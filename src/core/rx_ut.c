/*
 * Copyright (c) 2012, Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Network RX -- UDP transceiver layer (semi-reliable UDP)
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include <zlib.h>

#include "rx_ut.h"
#include "gnet_stats.h"
#include "rx.h"
#include "rxbuf.h"
#include "settings.h"			/* For settings_max_msg_size() */
#include "tx.h"
#include "tx_ut.h"
#include "udp_reliable.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/bit_array.h"
#include "lib/cq.h"
#include "lib/gnet_host.h"
#include "lib/hashing.h"
#include "lib/hevset.h"
#include "lib/iovec.h"
#include "lib/pmsg.h"
#include "lib/stringify.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * It is important to have the RX expiration time be a little bit larger than
 * the TX expiration time to account for transmission delays.
 *
 * The ACK delay time must be significantly smaller than the retransmission
 * timeout, to avoid undue TX activity because we're holding the ACK, yet it
 * must be large enough to make waiting worth it, i.e. get enough fragments
 * during the holding period.
 */

#define RX_UT_EXPIRE_MS	(70*1000)	/* Expiration time for RX messages, in ms */
#define RX_UT_ALMOST_MS	(40*1000)	/* Early expiration for RX messages (ms) */
#define RX_UT_DELAY_MS	500			/* ACK delay: 500 ms -- must be << 5 s */

#define RX_UT_DBG_MSG		(1U << 0)	/* Messages */
#define RX_UT_DBG_FRAG		(1U << 1)	/* Fragments */
#define RX_UT_DBG_ACK		(1U << 2)	/* Acknowledgments */
#define RX_UT_DBG_RECV		(1U << 3)	/* Reception to upper layer */
#define RX_UT_DBG_TIMEOUT	(1U << 4)	/* Timeouts */

#define rx_ut_debugging(mask, from) \
	G_UNLIKELY((GNET_PROPERTY(rx_ut_debug_flags) & (mask)) && \
		(NULL == (from) || rx_debug_host(from)))

enum rx_ut_attr_magic { RX_UT_ATTR_MAGIC = 0x118e9a01 };

/**
 * Private attributes for the decompressing layer.
 */
struct attr {
	enum rx_ut_attr_magic magic;
	txdrv_t *tx;				/* Sibling TX layer */
	rxdrv_t *rx;				/* Back pointer to this RX layer */
	const struct rx_ut_cb *cb;	/* Layer-specific callbacks */
	zlib_inflater_t *zi;		/* Inflating object */
	void *buffer;				/* Inflating buffer (fix-sized) */
	hevset_t *mseq;				/* Host + sequence ID -> received messsage */
	udp_tag_t tag;				/* Protocol tag (e.g. "GTA" or "GND") */
	unsigned if_enabled:1;		/* Reception enabled */
	unsigned improved_acks:1;	/* Whether we can blindly send improved ACKs */
};

static inline void
ut_attr_check(const struct attr * const attr)
{
	g_assert(attr != NULL);
	g_assert(RX_UT_ATTR_MAGIC == attr->magic);
}

/**
 * The ID of messages being received is composed of the origin of the message
 * plus the unique sequence ID allocated by the sender.
 */
struct ut_mid {
	const gnet_host_t *from;		/* Sending host (atom) */
	uint16 seqno;					/* Sequence number */
};

enum ut_rmsg_msgic { UT_RMSG_MAGIC = 0x75e48c06 };

/**
 * A message being received.
 */
struct ut_rmsg {
	enum ut_rmsg_msgic magic;
	struct ut_mid id;				/* Message ID (embedded key) */
	iovec_t *fragments;				/* Array of received fragments */
	bit_array_t *fbits;				/* Bitmap of received fragments */
	bit_array_t *facks;				/* Bitmap of fragments pending ACK */
	cevent_t *expire_ev;			/* Expire timer for the whole message */
	cevent_t *acks_ev;				/* Expire timer for delayed ACKs */
	struct attr *attr;				/* Layer attributes */
	uint8 fragcnt;					/* Amount of fragments in message */
	uint8 fragrecv;					/* Amount of fragments received */
	uint8 acks_pending;				/* Amount of delayed ACKs */
	unsigned reliable:1;			/* Whether fragments need ACKs */
	unsigned deflated:1;			/* Whether PDU is deflated */
	unsigned improved_acks:1;		/* Whether we can send improved ACKs */
	unsigned lingering:1;			/* Set when lingering after reception */
};

static inline void
ut_rmsg_check(const struct ut_rmsg * const um)
{
	g_assert(um != NULL);
	g_assert(UT_RMSG_MAGIC == um->magic);
}

static void ut_rmsg_reack(struct ut_rmsg *um);

/**
 * Primary hashing routine for ut_mid structs.
 */
static uint
ut_mid_hash(const void *key)
{
	const struct ut_mid *m = key;

	return gnet_host_hash(m->from) ^ u16_hash(m->seqno);
}

/**
 * Secondary hashing routine for ut_mid structs.
 */
static uint
ut_mid_hash2(const void *key)
{
	const struct ut_mid *m = key;

	return gnet_host_hash2(m->from) ^ u16_hash2(m->seqno);
}

/**
 * Equality routine for ut_mid structs;
 */
static bool
ut_mid_eq(const void *k1, const void *k2)
{
	const struct ut_mid *m1 = k1, *m2 = k2;

	return m1->seqno == m2->seqno && gnet_host_equal(m1->from, m2->from);
}

/**
 * Free message fragments.
 */
static void
ut_rmsg_fragments_free(const struct ut_rmsg *um)
{
	unsigned i;

	ut_rmsg_check(um);

	/*
	 * Free fragments collected in the I/O vector.
	 */

	for (i = 0; i < um->fragcnt; i++) {
		iovec_t *iov = &um->fragments[i];
		if (iovec_base(iov) != NULL)
			wfree(iovec_base(iov), iovec_len(iov));
		iovec_set(iov, NULL, 0);
	}
}

/**
 * Free message.
 */
static void
ut_rmsg_free(struct ut_rmsg *um, bool free_sequence)
{
	ut_rmsg_check(um);

	ut_rmsg_fragments_free(um);

	if (free_sequence) {
		struct attr *attr = um->attr;
		ut_attr_check(um->attr);
		hevset_remove(attr->mseq, &um->id);
	}

	iov_free(um->fragments);
	cq_cancel(&um->expire_ev);
	cq_cancel(&um->acks_ev);
	atom_host_free_null(&um->id.from);
	WFREE_NULL(um->fbits, BIT_ARRAY_BYTE_SIZE(um->fragcnt));
	WFREE_NULL(um->facks, BIT_ARRAY_BYTE_SIZE(um->fragcnt));

	um->magic = 0;
	WFREE(um);
}

/**
 * Callout queue callback invoked when the whole packet has expired.
 */
static void
ut_rmsg_expired(cqueue_t *cq, void *obj)
{
	struct ut_rmsg *um = obj;

	ut_rmsg_check(um);
	g_assert(um->expire_ev != NULL);

	cq_zero(cq, &um->expire_ev);	/* Callback has fired */

	if (rx_ut_debugging(RX_UT_DBG_TIMEOUT, um->id.from)) {
		g_debug("RX UT[%s]: %s: message from %s timed out "
			"(seq=0x%04x, got %u/%u fragment%s)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			gnet_host_to_string(um->id.from),
			um->id.seqno, um->fragrecv, um->fragcnt, plural(um->fragcnt));
	}

	/*
	 * We keep stats about how many fragments each message had.
	 *
	 * The expectation is that large messages are sent reliably, so we have
	 * more cases for reliable messages.
	 */

	g_assert(um->fragcnt > 1);	/* If it expired, it had more than 1 fragment */

	if (um->reliable) {
		gnr_stats_t s[] = {
			GNR_UDP_SR_RX_MSG_EXP_RELIABLE_2_FRAGS,
			GNR_UDP_SR_RX_MSG_EXP_RELIABLE_3_FRAGS,
			GNR_UDP_SR_RX_MSG_EXP_RELIABLE_4_FRAGS,
			GNR_UDP_SR_RX_MSG_EXP_RELIABLE_5_FRAGS,
			GNR_UDP_SR_RX_MSG_EXP_RELIABLE_6PLUS_FRAGS,
		};
		size_t n = um->fragcnt - 2;

		n = MIN(n, N_ITEMS(s) - 1);
		gnet_stats_inc_general(s[n]);
	} else {
		gnr_stats_t s[] = {
			GNR_UDP_SR_RX_MSG_EXP_UNRELIABLE_2_FRAGS,
			GNR_UDP_SR_RX_MSG_EXP_UNRELIABLE_3PLUS_FRAGS,
		};
		size_t n = um->fragcnt - 2;

		n = MIN(n, N_ITEMS(s) - 1);
		gnet_stats_inc_general(s[n]);
	}

	gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_EXPIRED);
	ut_rmsg_free(um, TRUE);
}

/**
 * Callout queue callback invoked when the whole packet is about to expire.
 */
static void
ut_rmsg_almost_expired(cqueue_t *cq, void *obj)
{
	struct ut_rmsg *um = obj;

	(void) cq;

	ut_rmsg_check(um);
	g_assert(um->expire_ev != NULL);

	cq_zero(cq, &um->expire_ev);	/* Callback has fired */

	/*
	 * This is an advance notice that the message could expire.  Probably our
	 * last acknowledgement was lost, so we resend it, hoping that the remote
	 * side will resume sending the missing parts.
	 *
	 * The rationale is that it is better to send an extra ACK (which the TX
	 * side will discard) than to let the remote side timeout because it is
	 * not getting any of our ACKs.  This early expiration notice is another
	 * chance to prevent reception timeout.  It is not necessary in the
	 * protocol and is just added for increased robustness.
	 *
	 * Then, if nothing happens within the remaining time window, the message
	 * will truly expire.
	 */

	um->expire_ev = cq_main_insert(RX_UT_EXPIRE_MS - RX_UT_ALMOST_MS,
		ut_rmsg_expired, um);

	if (rx_ut_debugging(RX_UT_DBG_TIMEOUT | RX_UT_DBG_ACK, um->id.from)) {
		g_debug("RX UT[%s]: %s: message from %s could timeout "
			"(seq=0x%04x, got %u/%u fragment%s so far)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			gnet_host_to_string(um->id.from),
			um->id.seqno, um->fragrecv, um->fragcnt, plural(um->fragcnt));
	}

	ut_rmsg_reack(um);
}

/**
 * Callout queue callback invoked when the packet has finished lingering.
 */
static void
ut_rmsg_lingered(cqueue_t *cq, void *obj)
{
	struct ut_rmsg *um = obj;

	ut_rmsg_check(um);
	g_assert(um->expire_ev != NULL);

	cq_zero(cq, &um->expire_ev);	/* Callback has fired */

	/*
	 * We delayed freeing to be able to re-ACK messages and avoid duplicate
	 * message reception.
	 */

	ut_rmsg_free(um, TRUE);
}

/**
 * Initiate lingering of the message, deferring its release from memory.
 *
 * The aim is to be able to avoid handling the retransmission of a fragment
 * as a new message if we already received it.  The other end can retransmit
 * in case the acknowledgment is lost or when the message reception was
 * delayed by some transmission queue and caused the other end to resend it.
 */
static void
ut_rmsg_linger(struct ut_rmsg *um)
{
	ut_rmsg_check(um);

	ut_rmsg_fragments_free(um);		/* No longer need collected message data */
	um->lingering = TRUE;
	cq_replace(um->expire_ev, ut_rmsg_lingered, um);
}

/**
 * Create a new message for reception.
 *
 * This records the tuple (sender's address, sequence ID) in a set, and it
 * will uniquely identify the message, letting us dispatch fragments to the
 * proper messages.
 *
 * @param attr		the layer's attributes
 * @param header	header information
 * @param from		sender's address
 */
static struct ut_rmsg *
ut_rmsg_create(struct attr *attr, const struct ut_header *header,
	const gnet_host_t *from)
{
	struct ut_rmsg *um;

	ut_attr_check(attr);
	g_assert(header->count != 0);

	WALLOC0(um);
	um->magic = UT_RMSG_MAGIC;
	um->id.from = atom_host_get(from);
	um->id.seqno = header->seqno;
	um->fragcnt = header->count;
	um->fragments = iov_alloc_n(um->fragcnt);
	um->reliable = booleanize(header->flags & UDP_RF_ACKME);
	um->deflated = booleanize(header->flags & UDP_RF_DEFLATED);
	um->improved_acks = attr->improved_acks ||
		booleanize(header->flags & UDP_RF_IMPROVED_ACKS);
	um->attr = attr;
	um->fbits = walloc0(BIT_ARRAY_BYTE_SIZE(um->fragcnt));
	um->facks = walloc0(BIT_ARRAY_BYTE_SIZE(um->fragcnt));

	g_assert(!hevset_contains(attr->mseq, &um->id));	/* New message! */

	hevset_insert_key(attr->mseq, &um->id);

	/*
	 * We must receive all the fragments for this message within the
	 * expiration period.
	 */

	um->expire_ev = cq_main_insert(RX_UT_ALMOST_MS, ut_rmsg_almost_expired, um);

	return um;
}

/**
 * Fill supplied header structure by reading the fields from the message.
 */
static void
ut_header_read(pmsg_t *mb, struct ut_header *header)
{
	const void *p;

	g_assert(pmsg_size(mb) >= UDP_RELIABLE_HEADER_SIZE);

	p = pmsg_start(mb);
	header->seqno = udp_reliable_header_get_seqno(p);
	header->flags = udp_reliable_header_get_flags(p);
	header->part  = udp_reliable_header_get_part(p) - 1;	/* Zero-based */
	header->count = udp_reliable_header_get_count(p);

	pmsg_discard(mb, UDP_RELIABLE_HEADER_SIZE);		/* Data has been read */
}

/**
 * Fill supplied acknowledgment structure by reading fields from the header.
 */
static void
ut_ack_read(const void *data, size_t len, struct ut_ack *ack)
{
	uint8 flags;
	uint8 fragno;

	g_assert(len >= UDP_RELIABLE_HEADER_SIZE);

	ZERO(ack);
	ack->seqno = udp_reliable_header_get_seqno(data);
	flags = udp_reliable_header_get_flags(data);
	ack->cumulative = booleanize(0 != (flags & UDP_RF_CUMULATIVE_ACK));

	/*
	 * Check for EARs (Extra Acknowledgment Requests).
	 */

	fragno = udp_reliable_header_get_part(data);

	if (0 == fragno) {
		ack->ear = TRUE;
		ack->ear_nack = booleanize(0 == (flags & UDP_RF_ACKME));
	} else {
		ack->fragno  = fragno - 1;	/* Zero-based */
	}

	if (flags & UDP_RF_EXTENDED_ACK) {
		g_assert(len >= UDP_RELIABLE_EXT_HEADER_SIZE);

		ack->received = udp_reliable_get_received(data);
		ack->missing = udp_reliable_get_missing(data);
	}
}

/**
 * Iterator callback to release all pending messages.
 */
static void
ut_destroy_rmsg(void *data, void *unused_arg)
{
	struct ut_rmsg *um = data;

	(void) unused_arg;

	ut_rmsg_free(um, FALSE);		/* Iterating from set */
}

/**
 * Reset the pending acknowledments.
 */
static void
ut_rmsg_clear_acks(struct ut_rmsg *um)
{
	if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
		g_debug("RX UT[%s]: %s: clearing %u delayed ACK%s to %s "
			"(seq=0x%04x, received %u/%u fragment%s)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			um->acks_pending, plural(um->acks_pending),
			gnet_host_to_string(um->id.from), um->id.seqno,
			um->fragrecv, um->fragcnt, plural(um->fragcnt));
	}

	gnet_stats_count_general(GNR_UDP_SR_RX_AVOIDED_ACKS, um->acks_pending);
	um->acks_pending = 0;
	bit_array_clear_range(um->facks, 0, um->fragcnt - 1);
}

/**
 * Signal reception of complete message.
 *
 * The message is expected to be freed at the end of processing by the
 * data-indication routine, because we cannot know whether the upper
 * layer will not buffer the message and delay its processing.
 */
static inline void
ut_received(const struct attr *attr, pmsg_t *mb, const gnet_host_t *from)
{
	if G_UNLIKELY(!attr->if_enabled) {
		pmsg_free(mb);
		return;
	}

	if (rx_ut_debugging(RX_UT_DBG_RECV, from)) {
		g_debug("RX UT[%s]: %s: giving %d-byte message from %s",
			udp_tag_to_string(attr->tag), G_STRFUNC,
			pmsg_size(mb), gnet_host_to_string(from));
	}

	rx_check(attr->rx);

	(void) (*attr->rx->data.from_ind)(attr->rx, mb, from);
}

/**
 * Update statistics on messages received.
 *
 * @param reliable		whether message was reliable
 * @param fragcnt		amount of fragments in message
 */
static void
ut_update_rx_messages_stats(bool reliable, uint8 fragcnt)
{
	g_assert(fragcnt != 0);

	gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_RECEIVED);
	if (!reliable)
		gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_UNRELIABLE);

	/*
	 * We keep stats about how many fragments each message had.
	 *
	 * The expectation is that large messages are sent reliably, so we have
	 * more cases for reliable messages.
	 */

	if (reliable) {
		gnr_stats_t s[] = {
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_1_FRAG,
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_2_FRAGS,
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_3_FRAGS,
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_4_FRAGS,
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_5_FRAGS,
			GNR_UDP_SR_RX_MSG_OK_RELIABLE_6PLUS_FRAGS,
		};
		size_t n = fragcnt - 1;

		n = MIN(n, N_ITEMS(s) - 1);
		gnet_stats_inc_general(s[n]);
	} else {
		gnr_stats_t s[] = {
			GNR_UDP_SR_RX_MSG_OK_UNRELIABLE_1_FRAG,
			GNR_UDP_SR_RX_MSG_OK_UNRELIABLE_2_FRAGS,
			GNR_UDP_SR_RX_MSG_OK_UNRELIABLE_3PLUS_FRAGS,
		};
		size_t n = fragcnt - 1;

		n = MIN(n, N_ITEMS(s) - 1);
		gnet_stats_inc_general(s[n]);
	}
}

/**
 * Assemble all the collected fragments into a single message and send it
 * to upper layers.
 */
static void
ut_assemble_message(struct ut_rmsg *um)
{
	pmsg_t *mb;

	ut_rmsg_check(um);
	ut_attr_check(um->attr);

	if (rx_ut_debugging(RX_UT_DBG_MSG, um->id.from)) {
		size_t len = iov_calculate_size(um->fragments, um->fragcnt);
		g_debug("RX UT[%s]: %s: re-assembling %s%smessage from %s "
			"(seq=0x%04x, %u fragment%s, %zu bytes)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			um->reliable ? "reliable " : "",
			um->deflated ? "deflated " : "",
			gnet_host_to_string(um->id.from),
			um->id.seqno, um->fragcnt, plural(um->fragcnt), len);
	}

	ut_update_rx_messages_stats(um->reliable, um->fragcnt);

	if (um->deflated) {
		zlib_inflater_t *zi = um->attr->zi;
		unsigned i;
		int ret = 0;

		zlib_inflater_reset(zi, NULL, 0);

		for (i = 0; i < um->fragcnt; i++) {
			iovec_t *iov = &um->fragments[i];
			if (NULL == iovec_base(iov))
				continue;		/* Fragment #i was empty (0-byte payload) */
			ret = zlib_inflate_data(zi, iovec_base(iov), iovec_len(iov));
			if (-1 == ret)
				goto drop;
			else if (0 == ret && i != um->fragcnt - 1U)
				goto drop;
		}

		if (0 != ret)
			goto drop;

		gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_INFLATED);
		mb = pmsg_new(PMSG_P_DATA,
				zlib_inflater_out(zi), zlib_inflater_outlen(zi));
	} else {
		size_t len;
		unsigned i;

		len = iov_calculate_size(um->fragments, um->fragcnt);
		if (0 == len)
			goto empty;
		mb = pmsg_new(PMSG_P_DATA, NULL, len);

		for (i = 0; i < um->fragcnt; i++) {
			iovec_t *iov = &um->fragments[i];
			if (NULL == iovec_base(iov))
				continue;		/* Fragment #i was empty (0-byte payload) */
			pmsg_write(mb, iovec_base(iov), iovec_len(iov));
		}
	}

	ut_received(um->attr, mb, um->id.from);
	return;

drop:
	if (
		GNET_PROPERTY(udp_debug) ||
		rx_ut_debugging(RX_UT_DBG_MSG, um->id.from)
	) {
		size_t len = iov_calculate_size(um->fragments, um->fragcnt);
		g_warning("RX UT[%s]: %s: inflation error for message from %s "
			"(seq=0x%04x, %u fragment%s, %zu byte%s)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			gnet_host_to_string(um->id.from),
			um->id.seqno, um->fragcnt, plural(um->fragcnt),
			len, plural(len));
	}

	gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_INFLATION_ERROR);
	return;

empty:
	if (rx_ut_debugging(RX_UT_DBG_MSG, um->id.from)) {
		g_warning("RX UT[%s]: %s: dropping empty message from %s "
			"(seq=0x%04x, %u fragment%s)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			gnet_host_to_string(um->id.from),
			um->id.seqno, um->fragcnt, plural(um->fragcnt));
	}

	gnet_stats_inc_general(GNR_UDP_SR_RX_MESSAGES_EMPTY);
}

/**
 * Handle reception of a new fragment for the message.
 */
static void
ut_handle_fragment(struct ut_rmsg *um, const struct ut_header *head, pmsg_t *mb)
{
	iovec_t *iov;
	size_t len;
	void *data;

	ut_rmsg_check(um);
	g_assert(head->part < um->fragcnt);

	if (rx_ut_debugging(RX_UT_DBG_FRAG, um->id.from)) {
		g_debug("RX UT[%s]: %s: handling %s%s%sfragment #%u/%u from %s "
			"(seq=0x%04x, %u pending ACK%s)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			um->lingering ? "lingering " :
			bit_array_get(um->fbits, head->part) ? "duplicate " : "",
			um->reliable ? "reliable " : "",
			um->deflated ? "deflated " : "",
			head->part + 1, um->fragcnt,
			gnet_host_to_string(um->id.from), head->seqno,
			um->acks_pending, plural(um->acks_pending));
	}

	if (um->lingering) {
		gnet_stats_inc_general(GNR_UDP_SR_RX_FRAGMENTS_LINGERING);
		return;			/* Message already fully received */
	}

	if (bit_array_get(um->fbits, head->part)) {
		gnet_stats_inc_general(GNR_UDP_SR_RX_FRAGMENTS_DUPLICATE);
		return;			/* Already got that fragment */
	}

	bit_array_set(um->fbits, head->part);	/* Got fragment */
	um->fragrecv++;

	/*
	 * We have no a priori knowledge about the total size of the message once
	 * re-assembled.  Therefore, we have no other option but to copy the data
	 * from the message into a newly allocated buffer.
	 */

	len = pmsg_size(mb);

	if (0 != len) {
		/* Payload not empty */
		data = walloc(len);
		pmsg_read(mb, data, len);

		iov = &um->fragments[head->part];
		g_assert(NULL == iovec_base(iov));	/* Not already received */

		iovec_set(iov, data, len);
	}

	/*
	 * If we got the last fragment, we can re-assemble the whole message.
	 */

	if (um->fragrecv == um->fragcnt) {
		ut_assemble_message(um);
		ut_rmsg_linger(um);
	}
}

/**
 * Upgrade improved acknowledgment, as appropriate.
 *
 * The acknowledgment has already been filled as either a regular or
 * cumulative acknowledgment, and we're looking at whether we should
 * transform it as an extended acknowledgment.
 *
 * @return TRUE if the generated ACK covers everything that was received.
 */
static bool
ut_upgrade_ack(const struct ut_rmsg *um, struct ut_ack *ack)
{
	unsigned i, mask, max, base;

	g_assert(ack->fragno < um->fragcnt);
	g_assert(um->improved_acks);

	/*
	 * See whether we should use an extended acknowledgment.
	 *
	 * If the total amount of fragments is 1 or 2, then a cumulative
	 * acknowledgment is enough anyway.
	 *
	 * If the total amount of fragments is 3 or more and we're sending
	 * a cumulative acknowledgment with no other fragments received past
	 * the one being acknowledged, then there is no need for an extended
	 * acknowledgment: the cumulative acknowledgment implicitly denies
	 * reception of other fragments.
	 *
	 * If there has been only one fragment received overall, then an extended
	 * acknowledgment does not add any value: the (only) fragment received so
	 * far can be simply acknoweldged.
	 */

	if (um->fragcnt <= 2)
		return ack->cumulative;

	if (
		ack->cumulative &&
		(
			ack->fragno + 1 == um->fragcnt ||
			(size_t) -1 == bit_array_last_set(um->fbits,
				ack->fragno + 1, um->fragcnt - 1)
		)
	)
		return TRUE;	/* Implicitly denies reception of upper fragments */

	if (1 == um->fragrecv)
		return TRUE;	/* One fragment received so far */

	/*
	 * Extended acknowledgment is worth sending.
	 *
	 * The bit 0 of the missing field is going to be corresponding to the
	 * first fragment after the acknoweldged one if we are sending a
	 * cumulative acknowledgment.  Otherwise, it corresponds to fragment 0,
	 * in our zero-based counting.
	 */

	g_assert(um->fragrecv != 0);

	ack->received = um->fragrecv;
	base = ack->cumulative ? ack->fragno + 1 : 0;
	max = base + 24;				/* Only 24 bits available in missing */
	max = MIN(max, um->fragcnt);
	mask = 1;

	g_assert(base < um->fragcnt);

	for (i = base; i < max; i++, mask <<= 1) {
		if (!bit_array_get(um->fbits, i))
			ack->missing |= mask;	/* Fragment still missing */
	}

	return max <= um->fragcnt;		/* Are we exhaustive in our ACK? */
}

/**
 * Build possibly cumulative ack for message.
 */
static  void
ut_cumulative_ack(const struct ut_rmsg *um, struct ut_ack *ack,
	size_t first_missing, size_t last_unacked)
{
	g_assert(um->improved_acks);

	if ((size_t) -1 == first_missing) {
		/* Everything was already received (for multi-fragment message) */
		g_assert(um->fragcnt == um->fragrecv);
		ack->cumulative = TRUE;
		ack->fragno = um->fragcnt - 1;
	} else if (first_missing > last_unacked) {
		ack->cumulative = booleanize(first_missing > 1U);
		ack->fragno = first_missing - 1;
	} else {
		g_assert((size_t) -1 != last_unacked);	/* One frag received at least */
		ack->fragno = last_unacked;
	}
}

/**
 * Build delayed improved acknowledgment, as appropriate.
 *
 * @return TRUE if the generated ACK covers everything that was received.
 */
static bool
ut_build_delayed_ack(struct ut_rmsg *um, struct ut_ack *ack)
{
	size_t first_missing, last_unacked;

	g_assert(um->acks_pending != 0);
	g_assert(um->fragcnt > 1U);		/* Delayed only if multiple fragments */
	g_assert(um->improved_acks);	/* Remote will understand improved ACKs */

	/*
	 * Start from the highest numbered un-acknoweledged fragment remaining.
	 */

	last_unacked = bit_array_last_set(um->facks, 0, um->fragcnt - 1);
	g_assert((size_t) -1 != last_unacked);	/* At least 1 un-ACKed fragment */

	bit_array_clear(um->facks, last_unacked);
	um->acks_pending--;

	/*
	 * See whether we can use a cumulative acknowledgment, then possibly
	 * upgrading it to an extended acknowledgment..
	 */

	first_missing = bit_array_first_clear(um->fbits, 0, um->fragcnt - 1);

	ZERO(ack);
	ack->seqno = um->id.seqno;
	ut_cumulative_ack(um, ack, first_missing, last_unacked);

	return ut_upgrade_ack(um, ack);
}

/**
 * Build an extra acknowledgment, as appropriate.
 */
static void
ut_build_extra_ack(const struct ut_rmsg *um, struct ut_ack *ack)
{
	size_t first_missing, last_unacked;

	/*
	 * Start from the highest numbered un-acknoweledged fragment remaining.
	 */

	last_unacked = bit_array_last_set(um->facks, 0, um->fragcnt - 1);
	first_missing = bit_array_first_clear(um->fbits, 0, um->fragcnt - 1);

	/*
	 * If we have no un-acked fragments, set the last un-acked fragment count
	 * to the last received fragment of the message.  This is the fragment we
	 * will then re-acknowledge.
	 */

	if ((size_t) -1 == last_unacked) {
		last_unacked = (size_t) -1 == first_missing
			? um->fragcnt - 1U
			: bit_array_last_set(um->fbits, 0, um->fragcnt - 1);

		g_assert((size_t) -1 != last_unacked);	/* One frag received at least */
	}

	ZERO(ack);
	ack->seqno = um->id.seqno;

	if (um->improved_acks) {
		ut_cumulative_ack(um, ack, first_missing, last_unacked);
		ut_upgrade_ack(um, ack);
	} else {
		size_t last_frag = bit_array_last_set(um->fbits, 0, um->fragcnt - 1);
		g_assert((size_t) -1 != last_frag);	/* One frag received at least */
		ack->fragno = last_frag;
	}
}

/**
 * Send back the acknowledgment.
 *
 * We have been building an acknowledgment structure, which is now going
 * to be handed over to the sibling TX layer.  That layer will do the
 * proper packet framing and send it with high priority.
 */
static void
ut_ack_sendback(const struct ut_rmsg *um, const struct ut_ack *ack)
{
	const struct attr *attr;

	ut_rmsg_check(um);
	ut_attr_check(um->attr);

	attr = um->attr;

	if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
		g_debug("RX UT[%s]: %s: sending %s%s%sACK to %s "
			"(seq=0x%04x, fragment #%u, missing=0x%x)",
			udp_tag_to_string(attr->tag), G_STRFUNC,
			um->improved_acks ? "" : "legacy ",
			ack->cumulative ? "cumulative " : "",
			ack->received != 0 ? "extended " : "",
			gnet_host_to_string(um->id.from),
			ack->seqno, ack->fragno + 1, ack->missing);
	}

	gnet_stats_inc_general(GNR_UDP_SR_RX_TOTAL_ACKS_SENT);
	if (ack->cumulative)
		gnet_stats_inc_general(GNR_UDP_SR_RX_CUMULATIVE_ACKS_SENT);
	if (ack->received != 0)
		gnet_stats_inc_general(GNR_UDP_SR_RX_EXTENDED_ACKS_SENT);

	ut_send_ack(attr->tx, um->id.from, ack);	/* Sent by the TX layer */
}

/**
 * Callout queue callback invoked when pending ACKs must be sent back.
 */
static void
ut_delayed_ack(cqueue_t *cq, void *obj)
{
	struct ut_rmsg *um = obj;
	struct ut_ack ack;

	ut_rmsg_check(um);
	g_assert(um->acks_ev != NULL);

	cq_zero(cq, &um->acks_ev);		/* Callback has fired */

	while (um->acks_pending) {
		bool exhausted = ut_build_delayed_ack(um, &ack);

		if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
			g_debug("RX UT[%s]: %s: %s delayed %s%sACK to %s "
				"(seq=0x%04x, fragment #%u, missing=0x%x)",
				udp_tag_to_string(um->attr->tag), G_STRFUNC,
				exhausted ? "flushing" : "sending",
				ack.cumulative ? "cumulative " : "",
				ack.received != 0 ? "extended " : "",
				gnet_host_to_string(um->id.from),
				ack.seqno, ack.fragno + 1, ack.missing);
		}

		ut_ack_sendback(um, &ack);
		if (exhausted)
			break;
	}

	ut_rmsg_clear_acks(um);
}

/**
 * Acknowledge reception of fragment.
 *
 * When this routine is called, the fragment has not been handled yet so its
 * proper reception may not be accounted for already.
 *
 * We're nonetheless sending the acknowledgment before processing the fragment
 * to let the message go back as quickly as possible.
 */
static void
ut_acknowledge_fragment(struct ut_rmsg *um, const struct ut_header *head)
{
	struct attr *attr;
	struct ut_ack ack;

	ut_rmsg_check(um);
	g_assert(head->count == um->fragcnt);
	g_assert(head->part < um->fragcnt);

	attr = um->attr;
	ut_attr_check(attr);

	ZERO(&ack);
	ack.seqno = head->seqno;
	ack.fragno = head->part;

	/*
	 * Improved acknowledgments are only interesting when there are multiple
	 * fragments in the message
	 */

	if (um->improved_acks && um->fragcnt > 1) {
		size_t fragrecv = um->fragrecv;

		/*
		 * Delaying acknowledgments allows the RX side to hopefully acknowledge
		 * more than one fragment at a time, thanks to cumulative or extended
		 * acknowledgment messages.
		 *
		 * We're dealing with an un-processed fragment here, so account for
		 * its reception if it's not a duplicate.
		 */

		if (!bit_array_get(um->fbits, head->part))
			fragrecv++;

		/*
		 * As soon as we have received all the fragments, immediately
		 * acknowledge everything through a single cumulative acknowledgment.
		 */

		if (fragrecv == um->fragcnt) {
			cq_cancel(&um->acks_ev);
			ack.cumulative = TRUE;
			ack.fragno = um->fragcnt - 1;
			ut_rmsg_clear_acks(um);
			goto send_ack;
		}

		/*
		 * We use a Nagle-like algorithm to defer the acknowledgment, but
		 * we don't wait more than RX_UT_DELAY_MS after the reception of the
		 * first fragment to acknowledge what we got in-between.
		 *
		 * The aim is to make the delaying almost invisible to the sender,
		 * yet give enough time to buffer fragments (and therefore pending
		 * acknowledgments) without running the risk of facing a retransmission
		 * due to lack of acknowledgment.
		 */

		if (NULL == um->acks_ev)
			um->acks_ev = cq_main_insert(RX_UT_DELAY_MS, ut_delayed_ack, um);

		/*
		 * If fragment was already pending ACK, then it's going to be
		 * acknowledged when we flush the pending ACKs, hence we can ignore it.
		 */

		if (bit_array_get(um->facks, head->part)) {
			if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
				g_debug("RX UT[%s]: %s: already delayed ACK to %s "
					"(seq=0x%04x, fragment #%u/%u, pending=%u)",
					udp_tag_to_string(um->attr->tag), G_STRFUNC,
					gnet_host_to_string(um->id.from),
					ack.seqno, ack.fragno + 1, um->fragcnt, um->acks_pending);
			}
			gnet_stats_inc_general(GNR_UDP_SR_RX_AVOIDED_ACKS);
			return;
		}

		bit_array_set(um->facks, head->part);	/* Fragment is pending ACK */
		um->acks_pending++;

		if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
			g_debug("RX UT[%s]: %s: delaying ACK to %s "
				"(seq=0x%04x, fragment #%u/%u, pending=%u)",
				udp_tag_to_string(um->attr->tag), G_STRFUNC,
				gnet_host_to_string(um->id.from),
				ack.seqno, ack.fragno + 1, um->fragcnt, um->acks_pending);
		}

		return;
	}

send_ack:
	ut_ack_sendback(um, &ack);
}

/**
 * Re-acknowledge the message completely, stating everything we got so far.
 *
 * @param um		the message being received
 */
static void
ut_rmsg_reack(struct ut_rmsg *um)
{
	struct ut_ack rack;

	ut_rmsg_check(um);

	/*
	 * If we had pending ACKs to send, cancel them as we're about to re-ack
	 * everything we got.
	 */

	cq_cancel(&um->acks_ev);
	ut_build_extra_ack(um, &rack);
	ut_rmsg_clear_acks(um);

	if (rx_ut_debugging(RX_UT_DBG_ACK, um->id.from)) {
		g_debug("RX UT[%s]: %s: sending extra %s%sACK back to %s "
			"(seq=0x%04x, fragment #%u, got %u/%u fragment%s, "
			"missing=0x%x)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			rack.cumulative ? "cumulative " : "",
			rack.missing != 0 ? "extended " : "",
			gnet_host_to_string(um->id.from), rack.seqno,
			rack.fragno + 1, um->fragrecv, um->fragcnt,
			plural(um->fragcnt), rack.missing);
	}

	ut_send_ack(um->attr->tx, um->id.from, &rack);	/* Sent by the TX layer */
}

/**
 * Handle reception of an EAR (Extra Acknowledgment Request).
 */
static void
ut_handle_ear(const struct attr *attr,
	const gnet_host_t *from, const struct ut_ack *ack)
{
	struct ut_mid key;
	struct ut_rmsg *um;
	struct ut_ack rack;

	if (rx_ut_debugging(RX_UT_DBG_ACK, from)) {
		g_debug("RX UT[%s]: %s: got EAR from %s (seq=0x%04x)",
			udp_tag_to_string(attr->tag), G_STRFUNC,
			gnet_host_to_string(from), ack->seqno);
	}

	gnet_stats_inc_general(GNR_UDP_SR_RX_EARS_RECEIVED);

	/*
	 * See whether this an EAR for a known message (being received with
	 * still missing fragments).
	 */

	key.from = from;
	key.seqno = ack->seqno;
	um = hevset_lookup(attr->mseq, &key);

	if (NULL == um) {
		/*
		 * We don't know anything about this sequence ID, so negatively ACK the
		 * EAR by sending back another EAR with the "negative ACK" indication.
		 */

		ZERO(&rack);
		rack.ear = TRUE;
		rack.ear_nack = TRUE;
		rack.seqno = ack->seqno;

		gnet_stats_inc_general(GNR_UDP_SR_RX_EARS_FOR_UNKNOWN_MESSAGE);

		if (rx_ut_debugging(RX_UT_DBG_ACK, from)) {
			g_debug("RX UT[%s]: %s: sending negative EAR back to %s "
				"(unknown seq=0x%04x)",
				udp_tag_to_string(attr->tag), G_STRFUNC,
				gnet_host_to_string(from), ack->seqno);
		}

		ut_send_ack(attr->tx, from, &rack);	/* Sent by the TX layer */
	} else {
		/*
		 * We know this sequence ID, hence the remote TX side probably did not
		 * get our last ACK, hence we're getting an EAR.  Cancel any pending
		 * delayed ACK and immediately resend an ACK for what we got so far.
		 */

		if (um->lingering)
			gnet_stats_inc_general(GNR_UDP_SR_RX_EARS_FOR_LINGERING_MESSAGE);

		ut_rmsg_reack(um);
	}
}

/***
 *** Routines exported to the core for direct access to the RX layer.
 ***/

/**
 * Check whether header / origin are for a valid message.
 *
 * This is only used on ambiguous messages to determine whether they can
 * be interpreted as a semi-reliable UDP message.
 *
 * @param rx		the RX driver
 * @param uth		the UDP semi-reliable header
 * @param from		host that sent us the message
 *
 * @return TRUE if this corresponds to a fragment for a message being received.
 */
bool
ut_valid_message(const rxdrv_t *rx, const struct ut_header *uth,
	const gnet_host_t *from)
{
	struct attr *attr;
	struct ut_mid key;
	const struct ut_rmsg *um;

	rx_check(rx);
	g_assert(uth != NULL);
	g_assert(from != NULL);

	attr = rx->opaque;

	ut_attr_check(attr);

	/*
	 * See whether this a fragment for a known message (being received with
	 * still missing fragments).
	 */

	key.from = from;
	key.seqno = uth->seqno;
	um = hevset_lookup(attr->mseq, &key);

	if (NULL == um)
		return FALSE;		/* Unknown message */

	/*
	 * Check against the fragment count.
	 */

	if (um->fragcnt != uth->count)
		return FALSE;

	/*
	 * If message was deflated, make sure the flags are for a deflated message.
	 * And conversely, if the message was not deflated.
	 *
	 * Then perform the same logical equivalence check for acknowledgments.
	 */

	if (!equiv(um->deflated, (uth->flags & UDP_RF_DEFLATED)))
		return FALSE;

	if (!equiv(um->reliable, (uth->flags & UDP_RF_ACKME)))
		return FALSE;

	return TRUE;		/* OK, consistent semi-reliable UDP fragment */
}

/**
 * Got incoming message (UDP datagram), i.e. a fragment / acknowledgment for us.
 *
 * @param rx		the RX driver
 * @param data		start of the data
 * @param len		amount of data available
 * @param from		host that sent us the message
 */
void
ut_got_message(const rxdrv_t *rx, const void *data, size_t len,
	const gnet_host_t *from)
{
	struct attr *attr;
	struct ut_mid key;
	struct ut_rmsg *um;
	pdata_t *db;
	pmsg_t *mb;
	struct ut_header head;

	rx_check(rx);
	g_assert(data != NULL);
	g_assert(size_is_non_negative(len));
	g_assert(len >= UDP_RELIABLE_HEADER_SIZE);
	g_assert(from != NULL);

	attr = rx->opaque;

	ut_attr_check(attr);

	/*
	 * Account for all the bytes we receive, including protocol overhead.
	 */

	if (attr->cb->add_rx_given != NULL)
		(*attr->cb->add_rx_given)(rx->owner, len);

	/*
	 * Handle acknowledgments (for packets sent by the TX side) and EARs.
	 *
	 * We can get special EAR packets (Extra Acknowledgment Request) which
	 * are either true requests (handled by the RX layer) or actually
	 * negative ACKs (handled by the TX layer, as it is a response to a
	 * previous EAR it sent).
	 *
	 * The lower layer which feeds us the received datagrams is carefully
	 * validating that the traffic we get is well-formed.  In particular,
	 * this means there is a valid header and that acknowledgments are
	 * properly sized: an extended acknowledgment has a longer header.
	 *
	 * Hence the code can assume that the sizes are correct.
	 */

	if (0 == udp_reliable_header_get_count(data)) {
		struct ut_ack ack;
		ut_ack_read(data, len, &ack);
		if (ack.ear && !ack.ear_nack)
			ut_handle_ear(attr, from, &ack);	/* EAR for the RX layer */
		else
			ut_got_ack(attr->tx, from, &ack);	/* Handle it in the TX layer */
		return;
	}

	/*
	 * Create the message buffer, referencing the data being received.
	 */

	db = pdata_allocb_ext(deconstify_pointer(data), len, pdata_free_nop, NULL);
	mb = pmsg_alloc(PMSG_P_DATA, db, 0, len);

	/*
	 * Read message header.
	 */

	ut_header_read(mb, &head);

	gnet_stats_inc_general(GNR_UDP_SR_RX_FRAGMENTS_RECEIVED);
	if (0 == (head.flags & UDP_RF_ACKME))
		gnet_stats_inc_general(GNR_UDP_SR_RX_FRAGMENTS_UNRELIABLE);

	/*
	 * See whether this a fragment for a known message (being received with
	 * some fragments still missing).
	 */

	key.from = from;
	key.seqno = head.seqno;
	um = hevset_lookup(attr->mseq, &key);

	if (NULL == um) {
		if (rx_ut_debugging(RX_UT_DBG_MSG, from)) {
			g_debug("RX UT[%s]: %s: start of new %s%smessage from %s "
				"(seq=0x%04x, %u fragment%s) -- already has %zu pending",
				udp_tag_to_string(attr->tag), G_STRFUNC,
				(head.flags & UDP_RF_ACKME) ? "reliable " : "",
				(head.flags & UDP_RF_DEFLATED) ? "deflated " : "",
				gnet_host_to_string(from),
				head.seqno, head.count, plural(head.count),
				hevset_count(attr->mseq));
		}

		/* Special-case non-ACKed single fragment messages */
		if (1 == head.count && !(head.flags & UDP_RF_ACKME)) {
			ut_update_rx_messages_stats(FALSE, 1);
			ut_received(attr, mb, from);
			return;		/* Message freed by data indication routine */
		}

		um = ut_rmsg_create(attr, &head, from);
	}

	/*
	 * Make sure fragment count is consistent, as well as acknowledgment
	 * and deflation flags.
	 *
	 * If an inconsistency is detected, the fragment is simply ignored,
	 * and not even acknowledged, even if this causes re-transmission on
	 * the other end.
	 */

	if (
		head.count != um->fragcnt ||
		head.part >= um->fragcnt ||
		um->deflated != booleanize(head.flags & UDP_RF_DEFLATED) ||
		um->reliable != booleanize(head.flags & UDP_RF_ACKME)
	) {
		if (rx_ut_debugging(RX_UT_DBG_FRAG, from)) {
			g_warning("RX UT[%s]: %s: dropping invalid %s%sfragment from %s "
				"(seq=0x%04x, fragment #%u/%u, "
				"message is %sreliable %swith %u fragment%s)",
				udp_tag_to_string(um->attr->tag), G_STRFUNC,
				(head.flags & UDP_RF_ACKME) ? "reliable " : "",
				(head.flags & UDP_RF_DEFLATED) ? "deflated " : "",
				gnet_host_to_string(from),
				head.seqno, head.part + 1, head.count,
				um->reliable ? "" : "un",
				um->deflated ? "and deflated " : "",
				um->fragcnt, plural(um->fragcnt));
		}

		gnet_stats_inc_general(GNR_UDP_SR_RX_FRAGMENTS_DROPPED);
		goto done;
	}

	/*
	 * Log fragment reception.
	 */

	if (rx_ut_debugging(RX_UT_DBG_FRAG, um->id.from)) {
		g_debug("RX UT[%s]: %s: got %s%s%sfragment #%u/%u from %s "
			"(seq=0x%04x, %d-byte payload)",
			udp_tag_to_string(um->attr->tag), G_STRFUNC,
			um->lingering ? "lingering " :
			bit_array_get(um->fbits, head.part) ? "duplicate " : "",
			um->reliable ? "reliable " : "",
			um->deflated ? "deflated " : "",
			head.part + 1, um->fragcnt,
			gnet_host_to_string(um->id.from),
			head.seqno, pmsg_size(mb));
	}

	/*
	 * If requested, acknowledge reception of fragment immediately, before
	 * processing it, to make sure we send it back as early as possible.
	 * Of course, the ACK message could be queued by the lower UDP TX scheduler
	 * but then we already have a clogged output stream.
	 */

	if (head.flags & UDP_RF_ACKME)
		ut_acknowledge_fragment(um, &head);

	ut_handle_fragment(um, &head, mb);

done:
 	pmsg_free(mb);
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 */
static void *
rx_ut_init(rxdrv_t *rx, const void *args)
{
	const struct rx_ut_args *rargs = args;
	struct attr *attr;

	rx_check(rx);
	tx_check(rargs->tx);
	g_assert(rargs->cb != NULL);

	WALLOC0(attr);
	attr->magic = RX_UT_ATTR_MAGIC;
	attr->tag = rargs->tag;
	attr->mseq = hevset_create_any(
		offsetof(struct ut_rmsg, id),
		ut_mid_hash, ut_mid_hash2, ut_mid_eq);
	attr->rx = rx;
	attr->tx = rargs->tx;
	attr->cb = rargs->cb;
	attr->improved_acks = booleanize(!rargs->advertised_improved_acks);
	attr->zi = zlib_inflater_make(NULL, 0);
	zlib_inflater_set_maxoutlen(attr->zi, settings_max_msg_size());

	rx->opaque = attr;

	return rx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
rx_ut_destroy(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	ut_attr_check(attr);

	hevset_foreach(attr->mseq, ut_destroy_rmsg, NULL);
	hevset_free_null(&attr->mseq);
	zlib_inflater_free(attr->zi, TRUE);

	attr->magic = 0;
	WFREE(attr);
	rx->opaque = NULL;
}

/**
 * Enable reception of data.
 */
static void
rx_ut_enable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	ut_attr_check(attr);

	attr->if_enabled = TRUE;
}

/**
 * Disable reception of data.
 */
static void
rx_ut_disable(rxdrv_t *rx)
{
	struct attr *attr = rx->opaque;

	ut_attr_check(attr);

	attr->if_enabled = FALSE;
}

static const struct rxdrv_ops rx_ut_ops = {
	rx_ut_init,		/**< init */
	rx_ut_destroy,	/**< destroy */
	NULL,			/**< recv */
	NULL,			/**< recvfrom */
	rx_ut_enable,	/**< enable */
	rx_ut_disable,	/**< disable */
	rx_no_source,	/**< bio_source */
};

const struct rxdrv_ops *
rx_ut_get_ops(void)
{
	return &rx_ut_ops;
}

/* vi: set ts=4 sw=4 cindent: */
