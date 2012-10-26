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
 * Network driver -- UDP transceiver layer (semi-reliable UDP)
 *
 * Initially designed for the G2 network, this semi-reliable UDP layer is
 * actually general enough to be useful for Gnutella as well. It is for
 * connection-less exchanges needing more reliability than what UDP/IP
 * natively provides.
 *
 * UDP datagrams of large sizes can be sent to other hosts with native
 * fragmentation into smaller packets and transparent compression of payloads.
 * The layer also enables optional acknowledgment of packets, with feedback
 * to the application layer when the packet has been sent, or failed its
 * transmission.
 *
 * FRAMING OF FRAGMENTS
 *
 * Each payload is optionally deflated (if it saves data) and then split
 * into many small fragments (typically of 476 bytes) that are then framed
 * and sent over the network.
 *
 *  0               1               2               3
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7| Byte
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      idTag                    |    nFlags     | 0-3
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           nSequence           |    nPart      |    nCount     | 4-7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * idTag is a 3-byte unique protocol identifier allowing multiplexing of
 * several protocols on the same socket.  For instance, "GND" for the G2
 * UDP protocol, "GTA" for Gnutella UDP traffic.
 *
 *
 * nFlags contains flags which modify the content of the packet. The
 * low-order nibble is reserved for critical flags: if one of these bits
 * is set but the decoding software does not understand the meaning, the
 * packet must be discarded. The high-order nibble is reserved for
 * non-critical flags: when set these bits may be interpreted, but an
 * inability to interpret a bit does not cause the packet to be discarded.
 *
 * Currently defined flags are:
 *
 * - 0x1: Deflate.  The whole payload was deflated with the additional zlib
 *   encapsulation (RFC 1950).
 * - 0x2: Acknowledge Request: reception of the fragment must be acknowledged
 *   to the sender (ignored in acknowlegement messages).
 *
 * nSequence is a temporally unique sequence number for the payload.
 *
 * nPart is the fragment part number. 1 <= nPart <= nCount
 *
 * nCount is the fragment number, 0 meaning acknowledgment of the packet
 * whose number is given in nPart.
 *
 * ACKNOWLEDGMENTS
 *
 * An acknowledgement is made of a single header with no application payload,
 * and is sent out with nCount = 0 to let the other end know that the fragment
 * number ``nPart'' of the sequence number ``nSequence'' has been received.
 *
 * Acknowledgments are sent out as highly prioritary messages, ahead of any
 * other pending traffic.  This is to avoid the other end from wasting bandwidth
 * to resend a fragment that has in fact already been received.
 *
 * The "Acknowledge Request" flag bit is ignored in acknowledgment packets.
 *
 * Because acknowledgment messages can be lost in the way or arrive out of
 * order, it is best to include as much of the reception state as possible
 * so that the sending party can optimize retransmissions.
 *
 * In order to do that, the following extensions to the original specifications
 * have been added by gtk-gnutella:
 *
 * - Cumulative Acknowledgements: when the flag 0x10 is set, it tells the other
 *   party that ALL the fragments up to ``nPart'' have been received.
 *
 * - Extended Acknowledgments: when the flag 0x20 is set, it tells the other
 *   party that an acknowledgment payload is present.  It immediately follows
 *   the header and is architected thusly:
 *
 *  0               1               2               3
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7| Byte
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   nReceived   |                  missingBits                  | 0-3
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * nReceived is the total amount of parts successfully received so far.
 *
 * missingBits is a bitfield that is read as a big-endian number and
 * which contains set bits for the parts still missing.  The base part number
 * is normally 0, unless flag 0x10 was set, in which case the ``nPart''
 * value indicates the base.  The rule is then that if bit ``b'' is set,
 * then the fragment number "b + base + 1" is still missing.
 *
 * In the unlikely case where missingBits is too small to hold all the
 * missing parts, only the ones that can be represented are included, the
 * ``nReceived'' field being there to provide additional information.
 *
 * Proper generation and parsing of the missingBits field is crucial, so to
 * remove any ambiguity, it is best to interpret missingBits as a number.
 * Then bit 0 is the bit corresponding to 2^0, bit ``n'' is the bit
 * corresponding to 2^n.
 *
 * Bit 0 corresponds to fragment #1, unless the 0x10 flag was set.  In that
 * case, if for instance ``nPart'' is 3, then it means fragments #1, #2 and
 * #3 were already received.  The base is therefore 3, and if bit 0 is set
 * in missingBits, it means fragment #4 (0 + 3 + 1) is still missing.
 *
 * This extended acknowledgment lets the sending party optimize its
 * retransmissions even when some acknowledgments are lost.
 *
 * Extended Acknowlegments are only useful when the total amount of fragments
 * is 3 or above.  Indeed, with only 2 fragments, the Cumulative Acknowledgment
 * lets the receiving party know about the whole reception state.
 *
 * When the amount of fragments is 3 or more and only a Cumulative
 * Acknowledgment is sent out, it implicitly denies reception of any other
 * fragments.  This optimizes bandwidth since the 4 extra bytes sent out will
 * only be required for large messages (more than 2 fragments) in case fragments
 * are received out-of-order.
 *
 * TRANSMISSION PARAMETERS
 *
 * Our maximum payload size is set to 476 bytes (to limit the total IP message
 * to 512 bytes, including our 8-byte header + 28 bytes of UDP/IP header).
 * The fragment transmission timeout (ACK not received) is set to 5 secs for
 * the first transmission, 10 secs for the second and 20 secs for the third
 * and last attempt (exponential retry delay).
 * The packet transmission timeout is set to 60 secs (larger than 5+10+20+20=55
 * in case each fragment is not immediately sent out), to leave about 20 seconds
 * to get the final acknowledgement back on the last re-transmission.
 *
 * LINK WITH THE RX SIDE
 *
 * Due to the reliability nature of the layer, the RX side must know the TX
 * side of this layer to be able to feed the TX layer with acknowledgments
 * to send back and acknowledgments received from remote peers.
 *
 * Because this is highly specific, the normal TX API is not suitable here.
 * Instead, we use globally visible routines: ut_got_ack() and ut_send_ack().
 *
 * When assembling the TX and RX stacks, the user code must therefore construct
 * the TX stack first and pass the address of the TX layer to the corresponding
 * RX layer.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include <zlib.h>				/* For Z_BEST_COMPRESSION */

#include "tx_ut.h"
#include "gnet_stats.h"
#include "udp_reliable.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/elist.h"
#include "lib/eslist.h"
#include "lib/gnet_host.h"
#include "lib/hevset.h"
#include "lib/idtable.h"
#include "lib/nid.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

#define TX_UT_MTU			476		/* Our MTU (max byes per fragment) */
#define TX_UT_FRAG_MAX		255		/* At most 255 fragments per message */
#define TX_UT_MSG_MAXSIZE	(TX_UT_MTU * TX_UT_FRAG_MAX)
#define TX_UT_SEND_MAX		4		/* Max amount of fragment transmissions */
#define TX_UT_EAR_SEND_MAX	3		/* Max amount of EAR transmissions */

#define TX_UT_EXPIRE_MS		(60*1000)	/* Expiration time for packets, in ms */
#define TX_UT_SEQNO_COUNT	(1U << 16)	/* Amount of 16-bit sequence IDs */
#define TX_UT_SEQNO_THRESH	1024		/* Sequence ID freeing threshold */

#define TX_UT_DBG_MSG		(1U << 0)	/* Messages */
#define TX_UT_DBG_FRAG		(1U << 1)	/* Fragments */
#define TX_UT_DBG_ACK		(1U << 2)	/* Acknowledgments */
#define TX_UT_DBG_SEND		(1U << 3)	/* Sending to lower layer */
#define TX_UT_DBG_TIMEOUT	(1U << 4)	/* Timeouts */

#define tx_ut_debugging(mask, to) \
	G_UNLIKELY((GNET_PROPERTY(tx_ut_debug_flags) & (mask)) && \
		(NULL == (to) || tx_debug_host(to)))

enum tx_ut_attr_magic { TX_UT_ATTR_MAGIC = 0x7d93d0a9 };

/**
 * Private attributes for the layer.
 */
struct attr {
	enum tx_ut_attr_magic magic;
	idtable_t *seq;			/* Messages to send indexed by sequence ID */
	txdrv_t *tx;			/* Back pointer to TX layer owning this struct */
	eslist_t pending[PMSG_P_COUNT];	/* Pending messages to service, by prio */
	size_t buffered;		/* Total size of enqueued messages */
	zlib_deflater_t *zd;	/* Deflating object */
	struct tx_ut_cb *cb;	/* Callbacks */
	udp_tag_t tag;			/* Protocol tag (e.g. "GTA" or "GND") */
	unsigned seqno_freed;	/* Sequence IDs freed, for hysteresis */
	unsigned improved_acks:1;	/* Advertise improved ACKs in TX fragments */
	unsigned ear_support:1;		/* Remote RX will understand EARs */
	unsigned out_of_seqno:1;	/* We ran out of sequence IDs */
	unsigned upper_flowc:1;		/* Upper layer was flow-controlled */
	unsigned lower_flowc:1;		/* Lower layer flow-controlled us */
};

static inline void
ut_attr_check(const struct attr * const attr)
{
	g_assert(attr != NULL);
	g_assert(TX_UT_ATTR_MAGIC == attr->magic);
}

/**
 * An enqueued message to process in the service routine.
 */
struct ut_queued {
	pmsg_t *mb;
	slink_t lk;
};

enum ut_frag_magic { UT_FRAG_MAGIC = 0x179a92a6 };

struct ut_msg;

/**
 * A fragment to send.
 */
struct ut_frag {
	enum ut_frag_magic magic;
	struct ut_msg *msg;				/* Message where fragment belongs */
	cevent_t *resend_ev;			/* Timer for fragment retransmission */
	pmsg_t *fb;						/* Fragment message block */
	link_t lk;						/* Link in "resend" queue */
	uint8 fragno;					/* Fragment number, zero-based */
	uint8 txcnt;					/* Amount of times fragment was sent */
	uint resend:1;					/* Enqueued for resending */
	uint pending:1;					/* Pending ACK on resending */
};

static void
ut_frag_check(const struct ut_frag * const uf)
{
	g_assert(uf != NULL);
	g_assert(UT_FRAG_MAGIC == uf->magic);
}

enum ut_msg_magic { UT_MSG_MAGIC = 0x4ee960c0 };

/**
 * A message to send.
 *
 * The original message is kept around to delay its freeing until we know
 * whether it has been successfully sent or not.
 *
 * Its payload is deflated (if the message is not already flagged as being
 * compressed) and transmitted as such provided the deflated payload is
 * smaller.
 *
 * The actual message PDU is broken down into fragments which are immediately
 * sent out if possible, or enqueued if the underlying layer flow-controls us,
 * that queue being flushed by our service routine.
 */
struct ut_msg {
	enum ut_msg_magic magic;
	struct nid mid;					/* Unique message ID */
	pmsg_t *mb;						/* Original user message to send */
	const gnet_host_t *to;			/* Destination address (atom) */
	cevent_t *expire_ev;			/* Expire timer for the whole message */
	cevent_t *iterate_ev;			/* Recorded iterate event */
	cevent_t *ear_ev;				/* Expire timer for EARs */
	struct ut_frag **fragments;		/* Fragments to send (NULL when ACK-ed) */
	struct attr *attr;				/* TX layer private attributes */
	elist_t resend;					/* Fragments to resend */
	uint16 seqno;					/* Sequence ID number */
	uint16 fragtx;					/* Fragments transmitted, total */
	uint16 fragtx2;					/* Fragments that were re-transmitted */
	uint8 fragcnt;					/* Amount of fragments */
	uint8 fragsent;					/* Fragments sent (and ACK-ed if needed) */
	uint8 pending;					/* Fragments pending ACK on resend */
	uint8 alpha;					/* Parallel factor for resending */
	uint8 ears;						/* Amount of EARs sent */
	unsigned reliable:1;			/* Whether each fragment needs ACKs */
	unsigned deflated:1;			/* Whether PDU was deflated */
	unsigned alive:1;				/* Got at least an ACK from host */
	unsigned expecting_ack:1;		/* Expecting ACK to continue */
	unsigned ear_pending:1;			/* Sent EAR to lower layer, waiting CONF */
};

static void
ut_msg_check(const struct ut_msg * const um)
{
	g_assert(um != NULL);
	g_assert(UT_MSG_MAGIC == um->magic);
}

enum ut_pmi_magic { UT_PMI_MAGIC = 0x1d282650 };

/**
 * Message block context for messages we are enqueuing to lower layers.
 *
 * This context is "metadata" for the message that can be used in pre-TX hooks
 * and is also passed as argument to the free routine.
 *
 * Since there is a life-cycle disconnect between the fragment message we're
 * enqueing to lower layers and the overall message we have to send (before
 * fragmentation) which can expire on its own, it is important to be able to
 * spot whether the association between the message and the fragment has been
 * broken.  This is the role of the MID field, which is a numerical message
 * ID that is ever-growing and never reused.
 */
struct ut_pmsg_info {
	enum ut_pmi_magic magic;
	struct nid mid;			/* Numerical message ID */
	struct ut_msg *um;		/* Message */
	const gnet_host_t *to;	/* Destination address, simple reference */
	struct attr *attr;		/* TX layer attributes */
	uint8 fragno;			/* Fragment number, 0-based, 1-based for ACKs */
};

static inline void
ut_pmsg_info_check(const struct ut_pmsg_info * const pmi)
{
	g_assert(pmi != NULL);
	g_assert(UT_PMI_MAGIC == pmi->magic);
}

static hevset_t *ut_mset;		/* Alive mesages */
static unsigned ut_mset_refcnt;

static bool ut_frag_free(struct ut_frag *uf, bool free_message);
static void ut_frag_send(const struct ut_frag *uf);
static void ut_ack_send(pmsg_t *mb);
static void ut_resend_async(struct ut_msg *um);

/**
 * Add a new reference to the message set.
 */
static void
tx_ut_mset_add_ref(void)
{
	if G_UNLIKELY(NULL == ut_mset) {
		g_assert(0 == ut_mset_refcnt);
		ut_mset = hevset_create_any(
			offsetof(struct ut_msg, mid), nid_hash, nid_hash2, nid_equal);
	}

	ut_mset_refcnt++;
}

/**
 * Remove a reference to the message set.
 */
static void
tx_ut_mset_unref(void)
{
	g_assert(ut_mset != NULL);

	if (0 == --ut_mset_refcnt)
		hevset_free_null(&ut_mset);
}

/**
 * Invoke service routine of the upper layer if it wants servicing.
 */
static void
tx_ut_upper_service(const txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	attr->upper_flowc = FALSE;

	if (tx_ut_debugging(TX_UT_DBG_SEND, NULL)) {
		g_debug("TX UT: %s: upper layer %s servicing (tag=\"%s\")",
			G_STRFUNC, (tx->flags & TX_SERVICE) ? "wants" : "doesn't want",
			udp_tag_to_string(attr->tag));
	}

	if (tx->flags & TX_SERVICE) {
		g_assert(tx->srv_routine != NULL);
		tx->srv_routine(tx->srv_arg);
	}
}

/**
 * Allocate a unique message ID, used to identify the message object.
 *
 * This ID is a key to look the object up since any reference to that object
 * directly could be broken asynchronously should the object be freed.
 */
static struct nid
ut_msg_id_create(void)
{
	static struct nid counter;

	return nid_new_counter_value(&counter);
}

/**
 * Check whether the message bearing the specified ID is still alive.
 *
 * @return NULL if the ID has expired, otherwise a pointer to the mesage.
 */
static struct ut_msg *
ut_msg_is_alive(struct nid mid)
{
	struct ut_msg *um;

	if G_UNLIKELY(NULL == ut_mset)
		return NULL;

	um = hevset_lookup(ut_mset, &mid);

	if (um != NULL)
		ut_msg_check(um);

	return um;
}

/**
 * Free message.
 */
static void
ut_msg_free(struct ut_msg *um, bool free_sequence)
{
	unsigned i;
	struct attr *attr;

	ut_msg_check(um);
	ut_attr_check(um->attr);

	attr = um->attr;

	if (tx_ut_debugging(TX_UT_DBG_MSG, um->to)) {
		g_debug("TX UT[%s]: %s: %s message "
			"(%d bytes, seq=0x%04x, %u/%u fragment%s %s) to %s",
			nid_to_string(&um->mid), G_STRFUNC,
			um->fragsent == um->fragcnt ? "sent" : "dropped",
			pmsg_size(um->mb), um->seqno, um->fragsent, um->fragcnt,
			1 == um->fragcnt ? "" : "s",
			um->reliable ? "ack'ed" : "sent", gnet_host_to_string(um->to));
	}

	/*
	 * If all the fragments were sent, mark the message as sent: should someone
	 * monitor the original PDU with a free routine, they will know the fate
	 * of the message that way.
	 */

	if (um->fragsent == um->fragcnt) {
		pmsg_mark_sent(um->mb);

		/* Message was fully sent out */
		if (attr->cb->msg_account != NULL)
			(*attr->cb->msg_account)(attr->tx->owner, um->mb, um->to);

		if (um->reliable)
			gnet_stats_inc_general(GNR_UDP_SR_TX_RELIABLE_MESSAGES_SENT);
		if (um->deflated)
			gnet_stats_inc_general(GNR_UDP_TX_COMPRESSED);
	} else {
		/* Message was dropped during TX */
		if (attr->cb->add_tx_dropped != NULL)
			(*attr->cb->add_tx_dropped)(attr->tx->owner, 1);

		gnet_stats_inc_general(GNR_UDP_SR_TX_MESSAGES_UNSENT);
		if (um->reliable)
			gnet_stats_inc_general(GNR_UDP_SR_TX_RELIABLE_MESSAGES_UNSENT);
	}

	/*
	 * Free any remaining fragments.
	 */

	for (i = 0; i < um->fragcnt; i++) {
		struct ut_frag *uf = um->fragments[i];

		if (uf != NULL)
			ut_frag_free(uf, FALSE);	/* Don't recurse to ut_msg_free() */
	}

	attr->buffered = size_saturate_sub(attr->buffered, pmsg_size(um->mb));

	cq_cancel(&um->expire_ev);
	cq_cancel(&um->iterate_ev);
	cq_cancel(&um->ear_ev);
	atom_host_free_null(&um->to);
	wfree(um->fragments, um->fragcnt * sizeof um->fragments[0]);
	hevset_remove(ut_mset, &um->mid);
	pmsg_free_null(&um->mb);

	if (free_sequence) {
		idtable_free_id(attr->seq, um->seqno);

		/*
		 * If we ran out of sequence IDs (and flow-controlled the upper layers),
		 * then we monitor the amount of sequence IDs freed and leave the
		 * flow-controlled state only after enough have been released.
		 *
		 * This creates hysteresis and avoids situations where we would quickly
		 * leave/re-enter flow-control, which is inefficient.
		 */

		if (attr->out_of_seqno) {
			if (++attr->seqno_freed >= TX_UT_SEQNO_THRESH) {
				/* We have enough free sequence IDs to resume */
				attr->seqno_freed = 0;
				attr->out_of_seqno = FALSE;
				tx_ut_upper_service(attr->tx);
			}
		}
	}

	um->magic = 0;
	WFREE(um);
}

/**
 * Free fragment.
 *
 * @param uf			fragment to free (acknoweldged or sent)
 * @param free_message	if TRUE, free up message if this is the last fragment
 *
 * @return TRUE if the fragment was the last one remaining.
 */
static bool
ut_frag_free(struct ut_frag *uf, bool free_message)
{
	struct ut_msg *um;
	bool is_last;

	ut_frag_check(uf);
	ut_msg_check(uf->msg);

	um = uf->msg;
	cq_cancel(&uf->resend_ev);
	pmsg_free_null(&uf->fb);

	g_assert(uf->fragno < um->fragcnt);
	g_assert(uf == um->fragments[uf->fragno]);

	um->fragments[uf->fragno] = NULL;
	um->fragsent++;

	if (uf->resend)
		elist_remove(&um->resend, uf);

	if (uf->pending) {
		um->pending--;
		ut_resend_async(um);
	}

	if (free_message && tx_ut_debugging(TX_UT_DBG_FRAG, um->to)) {
		g_debug("TX UT[%s]: %s: %s fragment #%u/%u seq=0x%04x (%d %s) to %s",
			nid_to_string(&um->mid), G_STRFUNC,
			um->reliable ? "acknowledged" : "sent",
			uf->fragno + 1, um->fragcnt, um->seqno,
			um->fragcnt - um->fragsent, um->reliable ? "un-ack'ed" : "unsent",
			gnet_host_to_string(um->to));
	}

	uf->magic = 0;
	WFREE(uf);

	/*
	 * When the last fragment is freed, we're done with the message.
	 */

	is_last = um->fragcnt == um->fragsent;

	if (is_last && free_message)
		ut_msg_free(um, TRUE);

	return is_last;
}

/**
 * Computes the delay (in ms) we have to wait at most to get an ACK back.
 *
 */
static int
ut_sending_delay(unsigned txcnt)
{
	switch (txcnt) {
	case 1:  return 5000;		/* 5 seconds */
	case 2:  return 7500;		/* 7.5 seconds */
	case 3:  return 11250;		/* 11.25 seconds */
	default: return 22500;		/* 22.5 seconds */
	}
}

/**
 * Computes the delay (in ms) before resending a fragment, depending on how
 * many times it was sent already.
 */
static int
ut_frag_delay(const struct ut_frag *uf)
{
	ut_frag_check(uf);
	g_assert(uf->txcnt != 0);

	return ut_sending_delay(uf->txcnt);
}

/**
 * Send an EAR (Extra ACK Request) to the remote end.
 */
static void
ut_ear_send(struct ut_msg *um)
{
	struct ut_ack ear;

	ut_msg_check(um);
	g_assert(NULL == um->ear_ev);

	if (tx_ut_debugging(TX_UT_DBG_ACK, um->to)) {
		g_debug("TX UT[%s]: %s: sending EAR to %s (seq=0x%04x, attempt #%u)",
			nid_to_string(&um->mid), G_STRFUNC,
			gnet_host_to_string(um->to), um->seqno, um->ears + 1);
	}

	ZERO(&ear);
	ear.seqno = um->seqno;
	ear.ear = TRUE;

	um->expecting_ack = TRUE;
	um->ear_pending = TRUE;
	ut_send_ack(um->attr->tx, um->to, &ear);
}

/**
 * Callout queue callback invoked to trigger fragment resending.
 */
static void
ut_resend_iterate(cqueue_t *unused_cq, void *obj)
{
	struct ut_msg *um = obj;

	(void) unused_cq;

	ut_msg_check(um);
	ut_attr_check(um->attr);
	g_assert(um->iterate_ev != NULL);

	um->iterate_ev = NULL;	/* Callback triggered */

	if (tx_ut_debugging(TX_UT_DBG_TIMEOUT, um->to)) {
		g_debug("TX UT[%s]: %s: alpha=%u, pending=%u, enqueued=%zu, alive=%c",
			nid_to_string(&um->mid), G_STRFUNC,
			um->alpha, um->pending, elist_count(&um->resend),
			um->alive ? 'y' : '?');
	}

	/*
	 * When we don't know whether the remote host is alive yet, don't resend
	 * fragments but rather send EARs (Extra ACK Requests) to check whether
	 * there is a remote stack listening to our traffic.
	 *
	 * This is only done when we know (by configuration made at creation time)
	 * that the remote RX side will properly understand EARs.
	 */

	if (!um->alive && um->attr->ear_support) {
		if (!um->ear_pending && NULL == um->ear_ev)
			ut_ear_send(um);
		return;
	}

	/*
	 * If we can't send a new batch, wait for more ACKs to come or for a
	 * resend timeout.
	 */

	if (um->pending != 0 && um->pending >= um->alpha)
		return;

	/*
	 * We're getting ACKs for our fragments, send more.
	 */

	um->alpha++;

	while (um->pending < um->alpha) {
		struct ut_frag *uf = elist_shift(&um->resend);

		if (NULL == uf)
			return;

		g_assert(uf->resend);
		g_assert(!uf->pending);

		uf->resend = FALSE;
		uf->pending = TRUE;
		ut_frag_send(uf);
		um->pending++;
	}
}

/**
 * Request asynchronous iteration to resend pending fragments, if needed.
 */
static void
ut_resend_async(struct ut_msg *um)
{
	ut_msg_check(um);

	if (NULL == um->iterate_ev && 0 != elist_count(&um->resend))
		um->iterate_ev = cq_main_insert(1, ut_resend_iterate, um);
}

/**
 * Callout queue callback invoked when no acknowledgment was received.
 */
static void
ut_ear_resend(cqueue_t *unused_cq, void *obj)
{
	struct ut_msg *um = obj;

	(void) unused_cq;

	ut_msg_check(um);
	g_assert(um->ear_ev != NULL);

	um->ear_ev = NULL;		/* Callback triggered */

	/*
	 * If we already sent too many EARs, give up on the whole message.
	 */

	if (um->ears >= TX_UT_EAR_SEND_MAX) {
		if (tx_ut_debugging(TX_UT_DBG_FRAG | TX_UT_DBG_TIMEOUT, um->to)) {
			g_debug("TX UT[%s]: %s: EAR for %s already sent %u times "
				"(tag=\"%s\", seq=0x%04x, %u/%u fragment%s sent) -- giving up",
				nid_to_string(&um->mid), G_STRFUNC,
				gnet_host_to_string(um->to), um->ears,
				udp_tag_to_string(um->attr->tag), um->seqno, um->fragsent,
				um->fragcnt, 1 == um->fragcnt ? "" : "s");
		}

		gnet_stats_inc_general(GNR_UDP_SR_TX_EARS_OVERSENT);
		ut_msg_free(um, TRUE);
		return;
	}

	if (tx_ut_debugging(TX_UT_DBG_FRAG | TX_UT_DBG_TIMEOUT, um->to)) {
		g_debug("TX UT[%s]: %s: will resend EAR seq=0x%04x to %s "
			"retransmit #%u",
			nid_to_string(&um->mid), G_STRFUNC,
			um->seqno, gnet_host_to_string(um->to), um->ears);
	}

	ut_resend_async(um);
}

/**
 * Callout queue callback invoked when no acknowledgment was received.
 */
static void
ut_frag_resend(cqueue_t *unused_cq, void *obj)
{
	struct ut_frag *uf = obj;
	struct ut_msg *um;

	(void) unused_cq;

	ut_frag_check(uf);
	ut_msg_check(uf->msg);
	g_assert(uf->resend_ev != NULL);

	uf->resend_ev = NULL;	/* Callback triggered */
	um = uf->msg;

	if (tx_ut_debugging(TX_UT_DBG_FRAG | TX_UT_DBG_TIMEOUT, uf->msg->to)) {
		g_debug("TX UT[%s]: %s: will resend fragment #%u/%u seq=0x%04x to %s "
			"retransmit #%u",
			nid_to_string(&um->mid), G_STRFUNC,
			uf->fragno + 1, um->fragcnt, um->seqno,
			gnet_host_to_string(um->to), uf->txcnt);
	}

	/*
	 * If fragment was marked as "pending ACK", then it was resent and the
	 * acknowledgment did not come in the allocated time.
	 *
	 * Decrease the amount of pending messages, but also decrease parallelism
	 * for the next batch.
	 */

	if (uf->pending) {				/* Was pending ACK */
		um->pending--;
		um->alpha /= 2;				/* Decrease sending parallelism */
	}

	/*
	 * If we sent the fragment too many times already, give up on the whole
	 * message.
	 */

	if (uf->txcnt >= TX_UT_SEND_MAX) {
		if (tx_ut_debugging(TX_UT_DBG_FRAG | TX_UT_DBG_TIMEOUT, um->to)) {
			g_debug("TX UT[%s]: %s: fragment #%u for %s already sent %u times "
				"(tag=\"%s\", seq=0x%04x, %u/%u fragment%s sent) -- giving up",
				nid_to_string(&um->mid), G_STRFUNC, uf->fragno + 1,
				gnet_host_to_string(um->to), uf->txcnt,
				udp_tag_to_string(um->attr->tag), um->seqno, um->fragsent,
				um->fragcnt, 1 == um->fragcnt ? "" : "s");
		}

		gnet_stats_inc_general(GNR_UDP_SR_TX_FRAGMENTS_OVERSENT);
		ut_msg_free(um, TRUE);
		return;
	}

	/*
	 * Enqueue for retransmission, done "alpha" fragments at a time to avoid
	 * wasting outgoing bandwidth.
	 */

	g_assert(!uf->resend);

	uf->resend = TRUE;
	uf->pending = FALSE;			/* No longer pending, awaiting retransmit */
	elist_append(&um->resend, uf);
	ut_resend_async(um);
}

/**
 * This TX hook is invoked by the UDP scheduler to make sure we still have
 * to send the message.  Indeed, an acknowledgment could have arrived while
 * it was delayed due to bandwidth shortage, or the message could have expired.
 *
 * @param mb		the fragment message
 *
 * @return TRUE if the message can still be sent.
 */
static bool
ut_frag_hook(const pmsg_t *mb)
{
	const struct ut_msg *um;
	const struct ut_pmsg_info *pmi;

	/*
	 * Messages sent have a free routine, their metadata being information
	 * about the message.
	 */

	pmi = pmsg_get_metadata(mb);
	um = ut_msg_is_alive(pmi->mid);

	if (NULL == um)
		goto do_not_send;	/* Message expired */

	g_assert(pmi->fragno < um->fragcnt);

	if (NULL == um->fragments[pmi->fragno])
		goto do_not_send;	/* Fragment already acknowledged */

	return TRUE;			/* OK, can send fragment */

do_not_send:
	if (tx_ut_debugging(TX_UT_DBG_FRAG, NULL == um ? NULL : um->to)) {
		const void *pdu = pmsg_start(mb);
		udp_tag_t tag = udp_reliable_header_get_tag(pdu);
		uint16 seqno = udp_reliable_header_get_seqno(pdu);

		g_debug("TX UT[%s]: %s: dropping fragment #%u to %s "
			"(tag=\"%s\", seq=0x%04x): %s",
			NULL == um ? "-" : nid_to_string(&um->mid),
			G_STRFUNC, pmi->fragno + 1,
			NULL == um ? "???" : gnet_host_to_string(um->to),
			udp_tag_to_string(tag), seqno,
			NULL == um ? "message expired" :
				um->reliable ? "fragment already ACK'ed" :
				"fragment already sent");
	}

	gnet_stats_inc_general(GNR_UDP_SR_TX_FRAGMENTS_SENDING_AVOIDED);
	return FALSE;
}

/**
 * Fragment message free routine, invoked when the message was released by
 * a lower layer.
 */
static void
ut_frag_pmsg_free(pmsg_t *mb, void *arg)
{
	struct ut_msg *um;
	struct ut_pmsg_info *pmi = arg;
	struct ut_frag *uf;

	g_assert(pmsg_is_extended(mb));
	g_assert(NULL == pmi->attr);		/* Signals info for a fragment */

	um = ut_msg_is_alive(pmi->mid);

	if (NULL == um)
		goto cleanup;		/* Message expired */

	g_assert(pmi->fragno < um->fragcnt);

	uf = um->fragments[pmi->fragno];

	if (tx_ut_debugging(TX_UT_DBG_FRAG, um->to)) {
		g_debug("TX UT[%s]: %s: %s%sfragment #%u/%u seq=0x%04x tx=%d to %s "
			"was %s",
			nid_to_string(&uf->msg->mid), G_STRFUNC,
			um->reliable ? "reliable " : "",
			NULL == uf ? "ACK'ed " : "",
			pmi->fragno + 1, um->fragcnt, um->seqno,
			NULL == uf ? -1 : uf->txcnt, gnet_host_to_string(um->to),
			pmsg_was_sent(mb) ? "sent" : "dropped");
	}

	if (NULL == uf)
		goto cleanup;		/* Fragment already acknowledged */

	ut_frag_check(uf);

	if (pmsg_was_sent(mb)) {
		/*
		 * Fragment was sent.
		 *
		 * If it requires an acknowledgment, arm a resend timer in case
		 * we do not receive it in the time frame we have (which depends
		 * on the number of transmissions already made).
		 *
		 * If no acknowledgment is required, we can free the fragment.
		 */

		uf->txcnt++;
		um->fragtx++;
		gnet_stats_inc_general(GNR_UDP_SR_TX_FRAGMENTS_SENT);
		if (uf->txcnt > 1) {
			um->fragtx2++;
			gnet_stats_inc_general(GNR_UDP_SR_TX_FRAGMENTS_RESENT);
		}

		if (um->reliable) {
			if (tx_ut_debugging(TX_UT_DBG_TIMEOUT, um->to)) {
				g_debug("TX UT[%s]: %s: fragment #%u/%u seq=0x%04x tx=%d to %s "
					"will be resent in %d ms",
					nid_to_string(&uf->msg->mid), G_STRFUNC,
					uf->fragno + 1, um->fragcnt, um->seqno, uf->txcnt,
					gnet_host_to_string(um->to), ut_frag_delay(uf));
			}
			g_assert(NULL == uf->resend_ev);
			uf->resend_ev = cq_main_insert(ut_frag_delay(uf),
				ut_frag_resend, uf);
		} else {
			ut_frag_free(uf, TRUE);
		}

		/*
		 * If this is the first fragment being sent, reschedule the expiration
		 * with the original time: as far as the recipient goes, this is when
		 * we started emitting the message.
		 *
		 * This is important when the UDP TX scheduler is clogged with unsent
		 * traffic, because it will then keep dropping our fragments and the
		 * message could globally expire before we even could send the first
		 * fragment!
		 */

		if (1 == um->fragtx)
			cq_resched(um->expire_ev, TX_UT_EXPIRE_MS);
	} else {
		/*
		 * Fragment was dropped by lower layer (expired, probably).
		 * Immediately requeue it.
		 */

		ut_frag_send(uf);
	}

	/* FALL THROUGH */

cleanup:
	pmi->magic = 0;
	WFREE(pmi);
}

/**
 * Acknowledge message free routine, invoked when the message was released by
 * a lower layer.
 */
static void
ut_ack_pmsg_free(pmsg_t *mb, void *arg)
{
	struct ut_pmsg_info *pmi = arg;

	g_assert(pmsg_is_extended(mb));
	ut_attr_check(pmi->attr);		/* Signals this is info for an ack */

	if (!pmsg_was_sent(mb)) {
		pmsg_t *amb;

		/*
		 * Acknowledgment was not sent, re-enqueue a clone.
		 *
		 * It is safe to call pmsg_clone_extend() on the message even though
		 * we're invoked here from pmsg_free() because it will be adding a
		 * reference to the PDU data, and this will prevent releasing the PDU
		 * at the end of pmsg_free().
		 */

		amb = pmsg_clone_extend(mb, ut_ack_pmsg_free, pmi);
		ut_ack_send(amb);
	} else {
		if (tx_ut_debugging(TX_UT_DBG_ACK, pmi->to)) {
			const void *pdu = pmsg_start(mb);
			udp_tag_t tag = udp_reliable_header_get_tag(pdu);
			uint16 seqno = udp_reliable_header_get_seqno(pdu);
			uint8 flags = udp_reliable_header_get_flags(pdu);

			g_debug("TX UT: %s: sent %s%s%s "
				"(tag=\"%s\", seq=0x%04x, fragment #%u) to %s",
				G_STRFUNC,
				(flags & UDP_RF_CUMULATIVE_ACK) ? "cumulative " : "",
				(flags & UDP_RF_EXTENDED_ACK) ? "extended " : "",
				0 == pmi->fragno ? "EAR" : "ACK", udp_tag_to_string(tag),
				seqno, pmi->fragno, gnet_host_to_string(pmi->to));
		}

		/*
		 * Handle sending of an EAR.
		 */

		if (0 == pmi->fragno) {
			struct ut_msg *um;
			uint16 seqno = udp_reliable_header_get_seqno(pmsg_start(mb));

			gnet_stats_inc_general(GNR_UDP_SR_TX_EARS_SENT);

			um = idtable_probe_value(pmi->attr->seq, seqno);
			if (um != NULL) {
				um->ears++;
				um->ear_pending = FALSE;		/* Got CONF that it was sent */
				g_assert(NULL == um->ear_ev);
				um->ear_ev = cq_main_insert(
					ut_sending_delay(um->ears), ut_ear_resend, um);

				if (tx_ut_debugging(TX_UT_DBG_TIMEOUT, um->to)) {
					g_debug("TX UT[%s]: %s: EAR seq=0x%04x tx=%d to %s "
						"will be resent in %d ms",
						nid_to_string(&um->mid), G_STRFUNC,
						um->seqno, um->ears, gnet_host_to_string(um->to),
						ut_sending_delay(um->ears));
				}
			}
		}

		pmi->magic = 0;
		atom_host_free_null(&pmi->to);	/* Reference taken on acks */
		WFREE(pmi);
	}
}

/**
 * Send fragment.
 *
 * Send the message to the lower layer and if we are flow-controlled then
 * enqueue the message for servicing.
 */
static void
ut_frag_send(const struct ut_frag *uf)
{
	const struct ut_msg *um;
	struct attr *attr;
	pmsg_t *mb;
	struct ut_pmsg_info *pmi;
	struct ut_queued *uq;
	uint8 prio;

	ut_frag_check(uf);
	ut_msg_check(uf->msg);
	g_assert(NULL == uf->resend_ev);

	um = uf->msg;
	attr = um->attr;

	ut_attr_check(attr);

	/*
	 * Construct the message block we're going to send, attaching the relevant
	 * metadata and free routine.
	 *
	 * It is safe to take a reference on the um->to atom because the message
	 * will not be freed before the fragment has been sent out.
	 */

	WALLOC0(pmi);
	pmi->magic = UT_PMI_MAGIC;
	pmi->mid = um->mid;				/* Struct copy */
	pmi->to = um->to;				/* Simple copy, no ref count increase */
	pmi->fragno = uf->fragno;

	/* pmi->attr is not used for fragments */

	mb = pmsg_clone_extend(uf->fb, ut_frag_pmsg_free, pmi);
	prio = pmsg_prio(mb);

	if (tx_ut_debugging(TX_UT_DBG_SEND, um->to)) {
		g_debug("TX UT[%s]: %s: %ssending fragment #%u (%d bytes, prio=%u) "
			"to %s (%u fragment%s, seq=0x%04x, tag=\"%s\")",
			nid_to_string(&um->mid), G_STRFUNC,
			0 == uf->txcnt ? "" : "re",
			uf->fragno + 1, pmsg_size(mb), prio,
			gnet_host_to_string(um->to),
			um->fragcnt, 1 == um->fragcnt ? "" : "s",
			um->seqno, udp_tag_to_string(attr->tag));
	}
	
	if (
		0 == eslist_count(&attr->pending[prio]) &&
		0 != tx_sendto(attr->tx->lower, mb, um->to)
	) {
		pmsg_free(mb);
		return;
	}

	/*
	 * Cannot send the message to the lower layer, enqueue it.
	 */

	if (tx_ut_debugging(TX_UT_DBG_SEND, um->to)) {
		g_debug("TX UT[%s]: %s: enqueuing fragment (%zu already pending)",
			nid_to_string(&um->mid), G_STRFUNC,
			eslist_count(&attr->pending[prio]));
	}

	WALLOC0(uq);
	uq->mb = mb;
	eslist_prepend(&attr->pending[prio], uq);
	attr->lower_flowc = TRUE;
	tx_srv_enable(attr->tx->lower);
}

/**
 * Send acknowledgement message, already set with metadata and free routine.
 */
static void
ut_ack_send(pmsg_t *mb)
{
	struct ut_pmsg_info *pmi = pmsg_get_metadata(mb);
	struct attr *attr;
	struct ut_queued *uq;
	uint8 prio;

	ut_pmsg_info_check(pmi);

	attr = pmi->attr;
	prio = pmsg_prio(mb);

	ut_attr_check(attr);

	if (tx_ut_debugging(TX_UT_DBG_SEND, pmi->to)) {
		const void *pdu = pmsg_start(mb);
		udp_tag_t tag = udp_reliable_header_get_tag(pdu);
		uint16 seqno = udp_reliable_header_get_seqno(pdu);
		uint8 fragno = udp_reliable_header_get_part(pdu);
		uint8 flags = udp_reliable_header_get_flags(pdu);

		g_debug("TX UT: %s: sending %s%s%s (%d bytes, prio=%u) "
			"to %s (fragment #%u, seq=0x%04x, tag=\"%s\")",
			G_STRFUNC,
			(flags & UDP_RF_CUMULATIVE_ACK) ? "cumulative " : "",
			(flags & UDP_RF_EXTENDED_ACK) ? "extended " : "",
			0 == fragno ? "EAR" : "ACK", pmsg_size(mb), prio,
			gnet_host_to_string(pmi->to), fragno, seqno,
			udp_tag_to_string(tag));
	}

	/*
	 * ACKs can be sent out of order, so don't check whether we have some
	 * in the queue, try to send this one regardless.
	 *
	 * Anyway, the UDP TX scheduler is now configured to always accept
	 * highest priority messages, which is what ACKs are, so we would not
	 * need enqueuing logic.  We're keeping it in case the policy changes
	 * one day.
	 *		--RAM, 2012-10-12
	 */

	if (0 != tx_sendto(attr->tx->lower, mb, pmi->to)) {
		pmsg_free(mb);
		return;
	}

	/*
	 * Cannot send the message to the lower layer, enqueue it.
	 */

	if (tx_ut_debugging(TX_UT_DBG_SEND, pmi->to)) {
		g_debug("TX UT: %s: enqueuing %s (%zu prio=%u already pending)",
			G_STRFUNC, 0 == pmi->fragno ? "EAR" : "ACK",
			eslist_count(&attr->pending[prio]), prio);
	}

	WALLOC0(uq);
	uq->mb = mb;
	eslist_prepend(&attr->pending[prio], uq);
	attr->lower_flowc = TRUE;
	tx_srv_enable(attr->tx->lower);
}

/**
 * Process enqueued messages, highest priorities first.
 *
 * @return TRUE if we were able to flush everything.
 */
static bool
ut_pending_send(struct attr *attr)
{
	unsigned i;

	ut_attr_check(attr);
	g_assert(attr->lower_flowc);	/* Lower layer flow-controlled us */

	for (i = G_N_ELEMENTS(attr->pending); i != 0; i--) {
		eslist_t *list = &attr->pending[i - 1];
		struct ut_queued *uq;

		while (NULL != (uq = eslist_shift(list))) {
			pmsg_t *mb = uq->mb;
			struct ut_pmsg_info *pmi = pmsg_get_metadata(mb);

			ut_pmsg_info_check(pmi);

			if (tx_ut_debugging(TX_UT_DBG_SEND, pmi->to)) {
				const void *pdu = pmsg_start(mb);
				udp_tag_t tag = udp_reliable_header_get_tag(pdu);
				uint16 seqno = udp_reliable_header_get_seqno(pdu);
				uint8 fragno = udp_reliable_header_get_part(pdu);
				uint8 flags = udp_reliable_header_get_flags(pdu);
				uint8 count = udp_reliable_header_get_count(pdu);

				if (0 == count) {
					g_debug("TX UT: %s: dequeuing %s%sACK (%d bytes, prio=%u) "
						"to %s (fragment #%u, seq=0x%04x, tag=\"%s\")",
						G_STRFUNC,
						(flags & UDP_RF_CUMULATIVE_ACK) ? "cumulative " : "",
						(flags & UDP_RF_EXTENDED_ACK) ? "extended " : "",
						pmsg_size(mb), pmsg_prio(mb),
						gnet_host_to_string(pmi->to), fragno, seqno,
						udp_tag_to_string(tag));
				} else {
					g_debug("TX UT: %s: dequeuing fragment #%u/%u "
						"(%d bytes, prio=%u) to %s (seq=0x%04x, tag=\"%s\")",
						G_STRFUNC, fragno, count,
						pmsg_size(mb), pmsg_prio(mb),
						gnet_host_to_string(pmi->to), seqno,
						udp_tag_to_string(attr->tag));
				}
			}

			if (0 == tx_sendto(attr->tx->lower, mb, pmi->to)) {
				eslist_prepend(list, uq);		/* Put it back */

				if (tx_ut_debugging(TX_UT_DBG_SEND, pmi->to))
					g_debug("TX UT: %s: flow-controlled", G_STRFUNC);

				return FALSE;				/* We're flow-controlled */
			}

			pmsg_free_null(&uq->mb);
			WFREE(uq);
		}
	}

	attr->lower_flowc = FALSE;	/* Flushed everything! */
	tx_srv_disable(attr->tx->lower);

	return TRUE;
}

/**
 * Discard enqueued messages.
 */
static void
ut_pending_discard(struct attr *attr)
{
	unsigned i;

	ut_attr_check(attr);

	for (i = 0; i < G_N_ELEMENTS(attr->pending); i++) {
		eslist_t *list = &attr->pending[i];
		struct ut_queued *uq;

		while (NULL != (uq = eslist_shift(list))) {
			pmsg_t *mb = uq->mb;

			/*
			 * Cancel free routine because message was not given to lower layer
			 * and we free the message here.
			 */

			(void) pmsg_replace_ext(mb, NULL, NULL, NULL);
			pmsg_free_null(&uq->mb);
			WFREE(uq);
		}
	}
}

/**
 * Create a new fragment for given message.
 *
 * The relevant parts of the PDU are copied over and the header is added to
 * ready the message for transmission.
 *
 * @param attr		attributes of this layer
 * @param fragno	fragment number (zero-based)
 * @param um		message to which fragment belongs to
 * @param pdu		PDU starting pointer
 * @param pdulen	PDU length
 *
 * @return created fragment.
 */
static struct ut_frag *
ut_frag_create(const struct attr *attr, unsigned fragno,
	struct ut_msg *um, const void *pdu, size_t pdulen)
{
	struct ut_frag *uf;
	pmsg_t *mb;
	uint8 flags;

	ut_attr_check(attr);
	ut_msg_check(um);
	g_assert(fragno < um->fragcnt);

	mb = pmsg_new(pmsg_prio(um->mb), NULL, pdulen + UDP_RELIABLE_HEADER_SIZE);

	WALLOC0(uf);
	uf->magic = UT_FRAG_MAGIC;
	uf->msg = um;
	uf->fragno = fragno;		/* Index base is 0 here, not 1 */
	uf->fb = mb;

	/*
	 * Generate the 8-byte fragment header.
	 *
	 *  0               1               2               3
	 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7| Byte
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                      idTag                    |    nFlags     | 0-3
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |           nSequence           |    nPart      |    nCount     | 4-7
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	flags = attr->improved_acks ? UDP_RF_IMPROVED_ACKS : 0;
	flags |= um->deflated ? UDP_RF_DEFLATED : 0;
	flags |= um->reliable ? UDP_RF_ACKME : 0;

	pmsg_write(mb, attr->tag.value, 3);
	pmsg_write_u8(mb, flags);
	pmsg_write_be16(mb, um->seqno);
	pmsg_write_u8(mb, fragno + 1);
	pmsg_write_u8(mb, um->fragcnt);

	/*
	 * If the PDU is compressed, it is held in an internal buffer of the
	 * deflating object, so we need to copy it anyhow.
	 *
	 * If the PDU is not compressed, we could avoid this copy but it would
	 * require the use of sendmsg() to be able to write an iovec, and this
	 * is not compatible with our giving a pmsg_t to the UDP TX scheduler.
	 *
	 * For now, live with this extra copy which buys us the simplicity of
	 * implementation.  If it becomes a performance bottleneck, we can always
	 * revisit the strategy.
	 *		--RAM, 2012-09-26
	 */

	pmsg_write(mb, pdu, pdulen);

	/*
	 * Install a pre-transmit hook on the message, which will be propagated
	 * when we pmsg_clone() it before sending.
	 */

	pmsg_set_hook(mb, ut_frag_hook);

	if (tx_ut_debugging(TX_UT_DBG_FRAG, um->to)) {
		g_debug("TX UT[%s]: %s: created %d-byte %s fragment (#%u/%u) to %s",
			nid_to_string(&um->mid), G_STRFUNC, pmsg_size(mb),
			um->reliable ? "reliable" : "unreliable",
			fragno + 1, um->fragcnt, gnet_host_to_string(um->to));
	}

	return uf;
}

/*
 * Attempt deflation of message.
 *
 * @param attr		attributes of this layer
 * @param pdu		points to the original PDU starting pointer
 * @param pdulen	points to the original PDU length
 *
 * @return FALSE if PDU could not be deflated, TRUE if it was deflated with
 * the ``pdu'' and ``pdulen'' parameters updated to the deflated PDU, which
 * is held insize the deflater and must be consumed before further usage.
 */
static bool
ut_deflate(const struct attr *attr, const void **pdu, size_t *pdulen)
{
	size_t len = *pdulen;
	void *buf;								/* Compression buffer */
	uint32 deflated_len;					/* Length of deflated data */
	zlib_deflater_t *zd = attr->zd;

	zlib_deflater_reset(zd, *pdu, len);

	if (-1 == zlib_deflate_all(zd)) {
		g_warning("%s(): cannot deflate payload", G_STRFUNC);
		return FALSE;
	}

	/*
	 * Check whether compressed data is smaller than the original payload.
	 */

	deflated_len = zlib_deflater_outlen(zd);
	buf = zlib_deflater_out(zd);

	g_assert(zlib_is_valid_header(buf, deflated_len));

	if (deflated_len >= len)
		return FALSE;

	/*
	 * This payload will be sent deflated.
	 */

	*pdu = buf;
	*pdulen = deflated_len;

	return TRUE;
}

/**
 * Callout queue callback invoked when the whole packet has expired.
 */
static void
ut_um_expired(cqueue_t *unused_cq, void *obj)
{
	struct ut_msg *um = obj;

	ut_msg_check(um);
	g_assert(um->expire_ev != NULL);

	(void) unused_cq;

	um->expire_ev = NULL;		/* Indicates that callback has fired */

	if (tx_ut_debugging(TX_UT_DBG_MSG | TX_UT_DBG_TIMEOUT, um->to)) {
		g_debug("TX UT[%s]: %s: message for %s expired "
			"(tag=\"%s\", seq=0x%04x, %u/%u fragment%s %s, "
			"%u transmitted with %u re-transmissions, %u pending ACK%s, "
			"%zu fragment%s pending TX)",
			nid_to_string(&um->mid), G_STRFUNC,
			gnet_host_to_string(um->to),
			udp_tag_to_string(um->attr->tag), um->seqno, um->fragsent,
			um->fragcnt, 1 == um->fragcnt ? "" : "s",
			um->reliable ? "ack-ed" : "sent",
			um->fragtx, um->fragtx2,
			um->pending, 1 == um->pending ? "" : "s",
			elist_count(&um->resend), 1 == elist_count(&um->resend) ? "" : "s");
	}

	/*
	 * If we were unable to transmit all the fragments of the message at
	 * least once, count it as a clogged UDP output queue.
	 */

	if (um->fragtx - um->fragtx2 < um->fragcnt)
		gnet_stats_inc_general(GNR_UDP_SR_TX_MESSAGES_CLOGGING);

	/*
	 * Because all the fragments we enqueue have a pre-TX hook, we can simply
	 * free up the message.  None of the pending fragments, if any, will be
	 * sent.
	 */

	ut_msg_free(um, TRUE);
}

/**
 * Create a new message structure to send specified message.
 *
 * @return NULL in the advent we cannot create the message (because it's too
 * large mostly) with errno set, otherwise return the message structure.
 */
static struct ut_msg *
ut_msg_create(struct attr *attr, pmsg_t *mb, const gnet_host_t *to)
{
	struct ut_msg *um;
	bool deflated = FALSE;
	const void *pdu;
	size_t pdulen;
	uint32 seqno;

	/*
	 * Allocate a new sequence ID, rejecting message if we're out of IDs.
	 */

	if (!idtable_try_new_id(attr->seq, &seqno, NULL)) {
		if (tx_ut_debugging(TX_UT_DBG_MSG, NULL))
			g_debug("TX UT: %s: out of sequence IDs", G_STRFUNC);
		errno = ENOBUFS;		/* Out of sequence IDs */
		return NULL;
	}

	g_assert(seqno < TX_UT_SEQNO_COUNT);	/* Is a 16-bit quantity */

	/*
	 * See whether we can compress the PDU.
	 *
	 * The zlib encapsulation will add a 2-byte header plus a trailing 16-bit
	 * checksum, hence it's useless to attempt deflation if the payload has
	 * less than 5 bytes.
	 *
	 * If the message is flagged as already being compressed or holding
	 * likely un-compressible data, also skip the compression stage.
	 */

	pdulen = pmsg_size(mb);
	pdu = pmsg_read_base(mb);

	if (pdulen > 5 && !pmsg_is_compressed(mb))
		deflated = ut_deflate(attr, &pdu, &pdulen);

	/*
	 * Split the PDU (possibly compressed) into the appropriate amount of
	 * fragments if it can fit our protocol.
	 */

	if G_UNLIKELY(pdulen > TX_UT_MSG_MAXSIZE) {
		if (tx_ut_debugging(TX_UT_DBG_MSG, NULL)) {
			g_debug("TX UT: %s: %s message for %s too large (%zu bytes)",
				G_STRFUNC, deflated ? "deflated" : "plain",
				gnet_host_to_string(to), pdulen);
		}
		errno = EMSGSIZE;
		return NULL;
	}

	WALLOC0(um);
	um->magic = UT_MSG_MAGIC;
	um->mb = pmsg_ref(mb);		/* Enqueued, not freeable by upper layer yet */
	um->reliable = booleanize(pmsg_is_reliable(mb));
	um->to = atom_host_get(to);
	um->seqno = seqno;
	um->mid = ut_msg_id_create();
	um->attr = attr;
	um->deflated = booleanize(deflated);
	elist_init(&um->resend, offsetof(struct ut_frag, lk));

	um->fragcnt = pdulen / TX_UT_MTU;
	if (pdulen != um->fragcnt * TX_UT_MTU)
		um->fragcnt++;
	um->fragments = walloc(um->fragcnt * sizeof um->fragments[0]);

	/*
	 * The sequence ID (seqno) is going to be echoed back by the receiving
	 * party during acknowledgements.
	 *
	 * The message ID (mid) is our internal ID that is used to create a "weak
	 * reference" to the message structure though the set.
	 * See ut_msg_is_alive(), which is the way we "dereference" the message ID.
	 */

	idtable_set_value(attr->seq, um->seqno, um);
	hevset_insert_key(ut_mset, &um->mid);

	/*
	 * Create the fragments.
	 */

	{
		unsigned i;
		const void *base = pdu;
		size_t remain = pdulen;

		for (i = 0; i < um->fragcnt; i++) {
			size_t len = MIN(remain, TX_UT_MTU);

			g_assert(ptr_diff(base, pdu) < pdulen);
			g_assert(size_is_positive(len));

			um->fragments[i] = ut_frag_create(attr, i, um, base, len);
			base = const_ptr_add_offset(base, len);
			remain = size_saturate_sub(remain, len);
		}

		g_assert(0 == remain);
	}

	/*
	 * Set global send-timer expiration: regardless of whether some fragments
	 * are still unsent, the whole packet will expire when this timer fires.
	 */

	um->expire_ev = cq_main_insert(TX_UT_EXPIRE_MS, ut_um_expired, um);

	/*
	 * The data buffered by this layer is the running count of original message
	 * sizes we have to transmit, not the compressed PDUs or pending acks or
	 * fragments.
	 */

	attr->buffered = size_saturate_add(attr->buffered, pmsg_size(mb));

	if (tx_ut_debugging(TX_UT_DBG_MSG, to)) {
		g_debug("TX UT[%s]: %s: created %zu-byte %s %s message (%d bytes) "
			"for %s (%u fragment%s, seq=0x%04x, tag=\"%s\", prio=%u)",
			nid_to_string(&um->mid), G_STRFUNC, pdulen,
			um->reliable ? "reliable" : "unreliable",
			deflated ? "deflated" : "plain", pmsg_size(mb),
			gnet_host_to_string(to), um->fragcnt, 1 == um->fragcnt ? "" : "s",
			um->seqno, udp_tag_to_string(attr->tag), pmsg_prio(mb));
	}

	return um;
}

/**
 * ID table iterator to release all pending messages.
 */
static void
ut_destroy_msg(void *data, void *unused_arg)
{
	struct ut_msg *um = data;

	(void) unused_arg;
	ut_msg_check(um);

	ut_msg_free(um, FALSE);		/* Iterating from sequence table */
}

/**
 * Service routine, invoked by lower layer when it's ready to consume more data.
 */
static void
tx_ut_service(void *data)
{
	const txdrv_t *tx = data;
	struct attr *attr = tx->opaque;

	ut_attr_check(attr);

	if (tx_ut_debugging(TX_UT_DBG_SEND, NULL)) {
		g_debug("TX UT: %s: servicing layer (tag=\"%s\", "
			"upper-flowc=%c, out-of-seqno=%c)",
			G_STRFUNC, udp_tag_to_string(attr->tag),
			attr->upper_flowc ? 'y' : 'n',
			attr->out_of_seqno ? 'y' : 'n');
	}

	if (!ut_pending_send(attr))
		return;

	/*
	 * We flushed everything we had.
	 * If upper layer wants servicing, do it.
	 */

	tx_ut_upper_service(tx);
}

/***
 *** Routines exported to the RX side of the semi-reliable UDP layer.
 ***/

/**
 * An acknowledgement was received.
 *
 * @param tx		the TX layer (sibling known to the RX layer)
 * @param from		host which sent the acknowledgment
 * @param ack		acknowledgment parameters
 */
void
ut_got_ack(txdrv_t *tx, const gnet_host_t *from, const struct ut_ack *ack)
{
	struct attr *attr = tx->opaque;
	struct ut_msg *um;
	struct ut_frag *uf;
	const char *reason;

	ut_attr_check(attr);

	um = idtable_probe_value(attr->seq, ack->seqno);

	/*
	 * An ACK can be an EAR negative acknowledgment.
	 */

	if (ack->ear) {
		g_assert(ack->ear_nack);

		gnet_stats_inc_general(GNR_UDP_SR_TX_EAR_NACKS_RECEIVED);

		if (tx_ut_debugging(TX_UT_DBG_ACK, from)) {
			g_debug("TX UT: %s: EAR NACK (seq=0x%04x) from %s",
				G_STRFUNC, ack->seqno, gnet_host_to_string(from));
		}
	} else {
		gnet_stats_inc_general(GNR_UDP_SR_TX_TOTAL_ACKS_RECEIVED);

		if (tx_ut_debugging(TX_UT_DBG_ACK, from)) {
			g_debug("TX UT: %s: %s%sACK (seq=0x%04x, fragment #%u) from %s",
				G_STRFUNC,
				ack->cumulative ? "cumulative " : "",
				0 != ack->received ? "extended " : "",
				ack->seqno, ack->fragno + 1, gnet_host_to_string(from));
		}
	}

	/*
	 * This ACK message is coming from the outside world and needs to be
	 * carefully validated before being processed: we only want to handle
	 * valid acks coming from the expected host, based on the sequence ID.
	 */

	if (NULL == um) {
		reason = "unknown sequence ID";
		goto spurious;		/* Probably an ACK for a message we just freed */
	}

	ut_msg_check(um);

	if (ack->fragno >= um->fragcnt) {
		reason = "invalid fragment number";
		goto rejected;
	}

	if (ack->received != 0 && ack->received > um->fragcnt) {
		reason = "received fragment count out of range";
		goto rejected;
	}

	if (!um->reliable) {
		reason = "was not expecting any ACK for message";
		goto rejected;
	}

	/* Compare IPs, not source ports, in case of NAT and different out port */

	if (!gnet_host_addr_eq(um->to, from)) {
		reason = "coming from alien host";
		goto rejected;
	}

	if (ack->ear && !um->expecting_ack) {
		reason = "no EAR sent";
		goto rejected;
	}

	if (ack->cumulative)
		gnet_stats_inc_general(GNR_UDP_SR_TX_CUMULATIVE_ACKS_RECEIVED);
	if (ack->received != 0)
		gnet_stats_inc_general(GNR_UDP_SR_TX_EXTENDED_ACKS_RECEIVED);

	/*
	 * If all the fragments were received, we're done with the whole message.
	 */

	if (
		ack->received == um->fragcnt ||
		(ack->cumulative && ack->fragno + 1 == um->fragcnt)
	) {
		um->fragsent = um->fragcnt;		/* Signals: all fragments received */
		ut_msg_free(um, TRUE);
		return;
	}

	/*
	 * Got something back, so remote host is alive.
	 */

	um->alive = TRUE;
	cq_cancel(&um->ear_ev);

	if (ack->ear)
		goto ear_nack;		/* Got an EAR NACK, not a fragment ACK */

	if (um->expecting_ack)
		gnet_stats_inc_general(GNR_UDP_SR_TX_EAR_FOLLOWED_BY_ACKS);

	/*
	 * OK, fragment was properly acknowledged.
	 *
	 * If this was the last fragment, we're done and the message was completly
	 * received by the other end.
	 */

	uf = um->fragments[ack->fragno];

	if (uf != NULL) {
		g_assert(ack->fragno == uf->fragno);

		if (ut_frag_free(uf, TRUE))
			return;		/* Was the last fragment */
	}

	/*
	 * If this is a cumulative acknowledge, make sure we free up earlier
	 * fragments.
	 */

	if (ack->cumulative) {
		unsigned i;

		for (i = 0; i < ack->fragno; i++) {
			uf = um->fragments[i];
			if (uf != NULL && ut_frag_free(uf, TRUE))
				return;		/* Was the last fragment */
		}
	}

	/*
	 * If the amount of fragments received is not zero, we have an extended
	 * acknowledge with a bitmap specifying which fragments are still missing,
	 * from which we can derive which have actually been received.
	 *
	 * The bit 0 is for fragment #0 (in our zero-based counting) unless
	 * we have a cumulative acknowledge, in which case the base is the
	 * fragment following the one being acknowledged.
	 */

	if (ack->received != 0) {
		unsigned base = ack->cumulative ? ack->fragno + 1 : 0;
		unsigned max = base + 24;	/* Only 24 significant bits */
		unsigned f;
		uint32 mask = 1;			/* bit 0 */
		unsigned frags = base;		/* Counts received fragments */

		max = MIN(max, um->fragcnt);

		for (f = base; f < max; f++, mask <<= 1) {
			if (0 == (ack->missing & mask)) {
				uf = um->fragments[f];		/* This fragment was received */
				frags++;
				if (uf != NULL && ut_frag_free(uf, TRUE))
					return;		/* Was the last fragment */
			}
		}

		/*
		 * In case there are more fragments in the message than can fit in the
		 * missing bits, and we know we have received all the other fragments
		 * based on the transmitted count, mark them received as well.
		 */

		if (max < um->fragcnt && ack->received == frags + um->fragcnt - max) {
			for (f = max; f < um->fragcnt; f++) {
				uf = um->fragments[f];
				if (uf != NULL && ut_frag_free(uf, TRUE))
					return;		/* Was the last fragment */
			}
		}
	}

	/* FALL THROUGH */

ear_nack:
	/*
	 * If we were expecting anything (ACK or EAR NACK) iterate to resend
	 * the pending fragments.
	 */

	if (um->expecting_ack)
		ut_resend_async(um);

	um->expecting_ack = FALSE;

	return;

spurious:
	gnet_stats_inc_general(GNR_UDP_SR_TX_SPURIOUS_ACKS_RECEIVED);
	goto log;

rejected:
	gnet_stats_inc_general(GNR_UDP_SR_TX_INVALID_ACKS_RECEIVED);
	/* FALL THROUGH */
log:
	if (tx_ut_debugging(TX_UT_DBG_ACK, NULL)) {
		g_debug("TX UT: %s: rejecting %s%s%sACK "
			"(seq=0x%04x, fragment #%u) from %s: %s (message to %s)",
			G_STRFUNC, ack->cumulative ? "cumulative " : "",
			0 != ack->received ? "extended " : "",
			ack->ear ? "EAR N" : "",
			ack->seqno, ack->ear ? 0 : ack->fragno + 1,
			gnet_host_to_string(from),
			reason, NULL == um ? "N/A" : gnet_host_to_string2(um->to));
	}
}

/**
 * Send back fragment acknowledgment or EAR to specified host.
 *
 * @param tx		the TX layer (sibling known to the RX layer)
 * @param to		destination address
 * @param ack		acknowledgment parameters
 */
void
ut_send_ack(txdrv_t *tx, const gnet_host_t *to, const struct ut_ack *ack)
{
	struct attr *attr = tx->opaque;
	struct ut_pmsg_info *pmi;
	pmsg_t *mb;
	uint8 flags;
	int length;

	ut_attr_check(attr);

	if (ack->received != 0) {
		flags = UDP_RF_EXTENDED_ACK;
		length = UDP_RELIABLE_EXT_HEADER_SIZE;
	} else {
		flags = 0;
		length = UDP_RELIABLE_HEADER_SIZE;
	}

	if (ack->cumulative)
		flags |= UDP_RF_CUMULATIVE_ACK;

	if (ack->ear && !ack->ear_nack)
		flags |= UDP_RF_ACKME;

	/*
	 * Allocate the message information, the argument to the free routine.
	 * We're using the same structure as for regular fragments but do not
	 * set all the fields in the same way: we add the TX attr structure, and
	 * the destination is an atom, not a mere pointer copy.
	 */

	WALLOC0(pmi);
	pmi->magic = UT_PMI_MAGIC;
	pmi->to = atom_host_get(to);		/* Reference count increased */
	pmi->attr = attr;
	pmi->fragno = ack->ear ? 0 : ack->fragno + 1;

	/*
	 * Acknowledgement messages are sent with the highest priority.
	 */

	mb = pmsg_new_extend(PMSG_P_HIGHEST, NULL, length, ut_ack_pmsg_free, pmi);

	pmsg_write(mb, attr->tag.value, 3);
	pmsg_write_u8(mb, flags);
	pmsg_write_be16(mb, ack->seqno);
	pmsg_write_u8(mb, ack->ear ? 0 : ack->fragno + 1);
	pmsg_write_u8(mb, 0);			/* Count = 0 indicates an acknowledgment */

	if (flags & UDP_RF_EXTENDED_ACK) {
		pmsg_write_u8(mb, ack->received);
		/* Write ``missing'' as a 24-bit big-endian number */
		pmsg_write_be16(mb, ack->missing >> 8);		/* Upper 16 bits */
		pmsg_write_u8(mb, ack->missing & 0xff);		/* Lower 8 bits */
	}

	ut_ack_send(mb);
}

/***
 *** Polymorphic routines.
 ***/

/**
 * Initialize the driver.
 *
 * Always succeeds, so never returns NULL.
 */
static void *
tx_ut_init(txdrv_t *tx, void *args)
{
	struct attr *attr;
	struct tx_ut_args *targs = args;
	unsigned i;

	g_assert(tx);
	g_assert(targs->cb != NULL);

	/*
	 * Create a global embedded-value set that will track the association
	 * between a message ID and a message structure, during the lifetime
	 * of these messages.
	 *
	 * This is a global variable and we track the amount of TX stacks that
	 * refer to it.  Once the number is 0, the set is destroyed.
	 */

	tx_ut_mset_add_ref();

	WALLOC0(attr);
	attr->magic = TX_UT_ATTR_MAGIC;
	attr->seq = idtable_new(16);		/* Sequence numbers are 16-bit wide */
	attr->tx = tx;
	attr->zd = zlib_deflater_make(NULL, 0, Z_BEST_COMPRESSION);
	attr->cb = targs->cb;
	attr->tag = targs->tag;				/* struct copy */
	attr->improved_acks = booleanize(targs->advertise_improved_acks);

	for (i = 0; i < G_N_ELEMENTS(attr->pending); i++) {
		eslist_init(&attr->pending[i], offsetof(struct ut_queued, lk));
	}

	/*
	 * We will be maintaining two flow-control statuses in the layer attributes:
	 *
	 * - upper_flowc will be set when we can no longer accept messages from
	 *   the upper layers because we ran out of sequence IDs or because we
	 *   have locally-enqueued messages that we cannot send.
	 *
	 * - lower_flowc is set when we are flow-controlled from the lower layer:
	 *   it is no longer accepting our messages.
	 *
	 * These flow-control situations are cleared thusly:
	 *
	 * - upper_flowc is cleared when we have new sequence IDs available or
	 *   when we are done flushing our enqueued packets.  This happens when
	 *   we are trying to service our upper layers, if they asked us to do so.
	 *
	 * - lower_flowc is cleared when we are able to flush all our packets.
	 *   This is done as the lower layer calls our service routine.
	 *
	 * The service routine is enabled when we have enqueued data to flush,
	 * and disabled when we are simply a pass-through (i.e. everything we get
	 * from above layers can be sent out to the lower layers).  The lower
	 * layer invokes our service routine when it can process more incoming data.
	 */

	tx->opaque = attr;
	tx_srv_register(tx->lower, tx_ut_service, tx);	/* Our service routine */

	return tx;		/* OK */
}

/**
 * Get rid of the driver's private data.
 */
static void
tx_ut_destroy(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	ut_attr_check(attr);

	zlib_deflater_free(attr->zd, TRUE);
	idtable_foreach(attr->seq, ut_destroy_msg, NULL);
	idtable_destroy(attr->seq);
	ut_pending_discard(attr);

	attr->magic = 0;
	WFREE(attr);

	tx_ut_mset_unref();
}

/**
 * Send buffer datagram to specified destination `to'.
 *
 * @returns amount of bytes written, 0 if flow-controlled, -1 on error
 * with errno set.
 */
static ssize_t
tx_ut_sendto(txdrv_t *tx, pmsg_t *mb, const gnet_host_t *to)
{
	struct attr *attr = tx->opaque;
	struct ut_msg *um;
	unsigned i;

	ut_attr_check(attr);

	/*
	 * If lower layer flow-controlled us, refuse to enqueue another message
	 * to create some hysteresis: we'll wait for the enqueued messages to
	 * drain first before accepting new messages.
	 */

	if (attr->lower_flowc) {
		if (tx_ut_debugging(TX_UT_DBG_MSG, NULL))
			g_debug("TX UT: %s: lower layer flow-controlled us", G_STRFUNC);
		goto flow_control;
	}

	/*
	 * Record the message to be sent, asynchronously.
	 *
	 * If we accept the message, it will be transmitted fragment by fragment,
	 * possibly reliably, but for upper layers we accept the whole message
	 * and will do whatever it takes to send it completly.
	 */

	um = ut_msg_create(attr, mb, to);

	if (NULL == um) {
		if (ENOBUFS == errno) {
			attr->out_of_seqno = TRUE;
			goto flow_control;
		}
		return -1;
	}

	/*
	 * Update statistics.
	 */

	gnet_stats_inc_general(GNR_UDP_SR_TX_MESSAGES_GIVEN);
	if (um->reliable)
		gnet_stats_inc_general(GNR_UDP_SR_TX_RELIABLE_MESSAGES_GIVEN);
	if (um->deflated)
		gnet_stats_inc_general(GNR_UDP_SR_TX_MESSAGES_DEFLATED);

	/*
	 * Send all the fragments immediately.
	 */

	for (i = 0; i < um->fragcnt; i++) {
		struct ut_frag *uf = um->fragments[i];

		ut_frag_send(uf);
	}

	return pmsg_size(mb);		/* "wrote" the whole message */

flow_control:
	attr->upper_flowc = TRUE;
	return 0;					/* Flow-controlling upper layer */
}

/**
 * Allow servicing of upper TX queue when output fd is ready.
 */
static void
tx_ut_enable(txdrv_t *unused_tx)
{
	/* Nothing specific for this layer */
	(void) unused_tx;
}

/**
 * Disable servicing of upper TX queue.
 */
static void
tx_ut_disable(txdrv_t *unused_tx)
{
	/* Nothing specific for this layer */
	(void) unused_tx;
}

/**
 * @return the amount of data buffered locally, awaiting full transmission.
 */
static size_t
tx_ut_pending(txdrv_t *tx)
{
	struct attr *attr = tx->opaque;

	ut_attr_check(attr);

	return attr->buffered;
}

/**
 * Nothing to do.
 */
static void
tx_ut_flush(txdrv_t *unused_tx)
{
	(void) unused_tx;
}

/**
 * Nothing to do.
 */
static void
tx_ut_shutdown(txdrv_t *unused_tx)
{
	(void) unused_tx;
}

static const struct txdrv_ops tx_ut_ops = {
	tx_ut_init,			/**< init */
	tx_ut_destroy,		/**< destroy */
	tx_no_write,		/**< write */
	tx_no_writev,		/**< writev */
	tx_ut_sendto,		/**< sendto */
	tx_ut_enable,		/**< enable */
	tx_ut_disable,		/**< disable */
	tx_ut_pending,		/**< pending */
	tx_ut_flush,		/**< flush */
	tx_ut_shutdown,		/**< shutdown */
	tx_close_noop,		/**< close */
	tx_no_source,		/**< bio_source */
};

const struct txdrv_ops *
tx_ut_get_ops(void)
{
	return &tx_ut_ops;
}

/* vi: set ts=4 sw=4 cindent: */
