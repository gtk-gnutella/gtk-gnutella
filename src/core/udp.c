/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * Handling UDP datagrams.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include <zlib.h>				/* For Z_OK */

#include "udp.h"
#include "bogons.h"
#include "bsched.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "gnutella.h"
#include "inet.h"
#include "mq_udp.h"
#include "nodes.h"
#include "pcache.h"
#include "routing.h"
#include "rx_ut.h"
#include "settings.h"
#include "sockets.h"
#include "udp_reliable.h"

#include "if/gnet_property_priv.h"
#include "if/dht/kmsg.h"		/* For kmsg_name() */

#include "lib/aging.h"
#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/gnet_host.h"
#include "lib/hashlist.h"
#include "lib/random.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"
#include "lib/zlib_util.h"

#include "lib/override.h"		/* Must be the last header included */

#define UDP_PING_FREQ	60		/**< At most 1 ping per minute to a given IP */

static aging_table_t *udp_aging_pings;

static rxdrv_t *rx_sr_gta[2];		/**< Semi-reliable RX layer for "GTA" */
static rxdrv_t *rx_sr_gnd[2];		/**< Semi-reliable RX layer for "GND" */

/**
 * Types of UDP traffic we multiplex on the same socket.
 */
enum udp_traffic {
	GNUTELLA,				/* Gnutella header recognized */
	DHT,					/* DHT header recognized */
	SEMI_RELIABLE_GTA,		/* Semi-reliable UDP, "GTA" tag (Gnutella) */
	SEMI_RELIABLE_GND,		/* Semi-reliable UDP, "GND" tag (G2) */
	UNKNOWN,				/* Unknown traffic */
};

/**
 * Records the RX layer to use for semi-reliable UDP traffic.
 */
void
udp_set_rx_semi_reliable(enum udp_sr_tag tag, rxdrv_t *rx, enum net_type net)
{
	unsigned i = 0;

	switch (net) {
	case NET_TYPE_IPV4:		i = 0; break;
	case NET_TYPE_IPV6:		i = 1; break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_carp("mis-configured network type %s for socket",
			net_type_to_string(net));
		return;		/* Ignore, indicates mis-configuration of bind address */
	}

	switch (tag) {
	case UDP_SR_GTA:
		rx_sr_gta[i] = rx;
		break;
	case UDP_SR_GND:
		rx_sr_gnd[i] = rx;
		break;
	}
}

/**
 * Select proper RX layer for semi-reliable UDP traffic.
 */
static rxdrv_t *
udp_get_rx_semi_reliable(enum udp_traffic utp, host_addr_t from)
{
	unsigned i = 0;

	switch (host_addr_net(from)) {
	case NET_TYPE_IPV4:		i = 0; break;
	case NET_TYPE_IPV6:		i = 1; break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		g_assert_not_reached();
	}

	return
		SEMI_RELIABLE_GTA == utp ? rx_sr_gta[i] :
		SEMI_RELIABLE_GND == utp ? rx_sr_gnd[i] :
		NULL;
}

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 *
 * The routine also handles traffic statistics (reception and dropping).
 *
 * If ``n'' is not NULL, then ``s'' may be NULL.  If ``n'' is NULL, then
 * ``s'' must not be NULL.
 *
 * @param n				the pseudo UDP reception node (NULL if invalid IP:port)
 * @param s				the socket on which we got the UDP datagram
 * @param truncated		whether datagram was truncated during reception
 * @param header		header of message
 * @param payload		payload of message (maybe not contiguous with header)
 * @param len			total length of message (header + payload)
 *
 * @return TRUE if valid, FALSE otherwise.
 */
bool
udp_is_valid_gnet_split(gnutella_node_t *n, const gnutella_socket_t *s,
	bool truncated, const void *header, const void *payload, size_t len)
{
	const char *msg;
	uint16 size;			/**< Payload size, from the Gnutella message */

	g_assert(s != NULL || n != NULL);

	/*
	 * If we can't get a proper UDP node for this address/port combination,
	 * ignore the message.
	 */

	if (NULL == n) {
		msg = "Invalid address/port combination";
		goto not;
	}

	if (len < GTA_HEADER_SIZE) {
		msg = "Too short";
		goto not;
	}

	/*
	 * We have enough to account for packet reception.
	 * Note that packet could be garbage at this point.
	 */

	memcpy(n->header, header, sizeof n->header);
	n->size = len - GTA_HEADER_SIZE;		/* Payload size if Gnutella msg */

	gnet_stats_count_received_header(n);
	gnet_stats_count_received_payload(n, payload);

	/*
	 * If the message was truncated, then there is also going to be a
	 * size mismatch, but we want to flag truncated messages as being
	 * "too large" because this is mainly why we reject them.  They may
	 * be legitimate Gnutella packets, too bad.
	 */

	if (truncated) {
		msg = "Truncated (too large?)";
		goto too_large;
	}

	/*
	 * Message sizes are architecturally limited to 64K bytes.
	 *
	 * We don't ensure the leading bits are zero in the size field because
	 * this constraint we put allows us to use those bits for flags in
	 * future extensions.
	 *
	 * The downside is that we have only 3 bytes (2 bytes for the size and
	 * 1 byte for the function type) to identify a valid Gnutella packet.
	 */

	switch (gmsg_size_valid(header, &size)) {
	case GMSG_VALID:
	case GMSG_VALID_MARKED:
		break;
	case GMSG_VALID_NO_PROCESS:
		msg = "Header flags undefined for now";
		goto drop;
	case GMSG_INVALID:
		msg = "Invalid size (greater than 64 KiB without flags)";
		goto not;		/* Probably just garbage */
	}

	if ((size_t) size + GTA_HEADER_SIZE != len) {
		msg = "Size mismatch";
		goto not;
	}

	/*
	 * We only support a subset of Gnutella message from UDP.  In particular,
	 * messages like HSEP data, BYE or QRP are not expected!
	 */

	switch (gnutella_header_get_function(header)) {
	case GTA_MSG_INIT:
	case GTA_MSG_INIT_RESPONSE:
	case GTA_MSG_VENDOR:
	case GTA_MSG_STANDARD:
	case GTA_MSG_PUSH_REQUEST:
	case GTA_MSG_SEARCH_RESULTS:
	case GTA_MSG_RUDP:
	case GTA_MSG_DHT:
		return TRUE;
	case GTA_MSG_SEARCH:
		if (settings_is_ultra() && GNET_PROPERTY(enable_guess)) {
			return TRUE;	/* GUESS query accepted */
		}
		msg = "Query from UDP refused";
		goto drop;
	}
	msg = "Gnutella message not processed from UDP";

drop:
	gnet_stats_count_dropped(n, MSG_DROP_UNEXPECTED);
	gnet_stats_inc_general(GNR_UDP_UNPROCESSED_MESSAGE);
	goto log;

too_large:
	gnet_stats_count_dropped(n, MSG_DROP_TOO_LARGE);
	gnet_stats_inc_general(GNR_UDP_UNPROCESSED_MESSAGE);
	goto log;

not:
	gnet_stats_inc_general(GNR_UDP_ALIEN_MESSAGE);
	/* FALL THROUGH */

log:
	if (GNET_PROPERTY(udp_debug)) {
		g_warning("got invalid Gnutella packet (%zu byte%s) "
			"\"%s\" %sfrom %s: %s",
			len, 1 == len ? "" : "s",
			len >= GTA_HEADER_SIZE ?
				gmsg_infostr_full_split(header, payload, len - GTA_HEADER_SIZE)
				: "<incomplete Gnutella header>",
			truncated ? "(truncated) " : "",
			NULL == n ?
				host_addr_port_to_string(s->addr, s->port) :
				node_infostr(n),
			msg);
		if (len != 0) {
			iovec_t iov[2];
			iovec_set(&iov[0], header, GTA_HEADER_SIZE);
			iovec_set(&iov[1], payload, len - GTA_HEADER_SIZE);
			dump_hex_vec(stderr, "UDP datagram", iov, G_N_ELEMENTS(iov));
		}
	}

	return FALSE;		/* Dropped */
}

/**
 * Look whether the datagram we received is a valid Gnutella packet.
 *
 * The routine also handles traffic statistics (reception and dropping).
 *
 * @param n				the pseudo UDP reception node (NULL if invalid IP:port)
 * @param s				the socket on which we got the UDP datagram
 * @param truncated		whether datagram was truncated during reception
 * @param start			start of message (header + payload following)
 * @param len			total length of message
 *
 * @return TRUE if valid, FALSE otherwise.
 */
static bool
udp_is_valid_gnet(gnutella_node_t *n, const gnutella_socket_t *s,
	bool truncated, const void *start, size_t len)
{
	return udp_is_valid_gnet_split(n, s, truncated, start,
		const_ptr_add_offset(start, GTA_HEADER_SIZE), len);
}

/**
 * Look whether semi-reliable UDP header corresponds to valid traffic.
 *
 * This routine is only used for ambiguous traffic that looks like both
 * Gnutella and semi-reliable UDP: we want to make sure we're not mistaking
 * a legitimate semi-reliable fragment / ACK for a Gnutella message.
 *
 * @param utp		already classified semi-reliable protocol
 * @param s			socket which received the message
 *
 * @return TRUE if message corresponds to valid semi-reliable UDP traffic.
 */
static bool
udp_is_valid_semi_reliable(enum udp_traffic utp, const gnutella_socket_t *s)
{
	struct ut_header uth;
	const void *head = cast_to_pointer(s->buf);
	void *message = NULL;
	size_t msglen;
	bool valid = TRUE;

	/*
	 * Since we're talking about an ambiguous message, it is highly unlikely
	 * we'll ever be called with an acknowledgement: they should have been
	 * ruled out earlier as improbable since ACKs are short message, much
	 * shorter than a Gnuella header typically.
	 *
	 * So we'll only handle fragments for now, assuming ACKs are legitimate.
	 */

	gnet_stats_inc_general(GNR_UDP_AMBIGUOUS_DEEPER_INSPECTION);

	uth.count = udp_reliable_header_get_count(head);
	if (0 == uth.count)
		return TRUE;		/* Acknoweldgments */

	uth.part = udp_reliable_header_get_part(head) - 1;	/* Zero-based */
	uth.flags = udp_reliable_header_get_flags(head);
	uth.seqno = udp_reliable_header_get_seqno(head);

	/*
	 * We're going to ask the RX layer about the message: is it a known
	 * sequence ID for this host?
	 *
	 * This works only for messages with more than one fragment, of course,
	 * but chances are that, for these, we would have possibly already
	 * received another fragment, not mistaken as a Gnutella message...
	 *
	 * This is OK for acknowledged fragments: we're not going to acknowledge
	 * the unprocessed fragment, but we'll receive other fragments of the
	 * message, and later on we'll get a retransmission of the unprocessed
	 * fragment, which this time will be validated since we have already
	 * partially received the message.
	 */

	if (uth.count > 1) {
		rxdrv_t *rx;
		gnet_host_t from;

		gnet_host_set(&from, s->addr, s->port);
		rx = udp_get_rx_semi_reliable(utp, s->addr);

		return NULL == rx ? FALSE : ut_valid_message(rx, &uth, &from);
	}

	/*
	 * We're facing a single-fragment message.
	 *
	 * We can trivially probe it and validate it to see whether it can still
	 * be interpreted as a valid Gnutella message on its own...  If the answer
	 * is yes, then we can assert we're facing a valid semi-reliable UDP
	 * message.
	 *
	 * For deflated payloads, we already validated that the start of the
	 * payload is a well-formed zlib header, but we'll attempt deflation anyway
	 * so we will know for sure whether it's a valid message!
	 *
	 * Of course we're doing here work that will have to be redone later when
	 * processing the message, but this is for proper classification and not
	 * happening very often: only on a very very small fraction of messages for
	 * which there is a high level of ambiguity.
	 */

	g_assert(0 == uth.part);	/* First (and only) fragment */

	if (uth.flags & UDP_RF_DEFLATED) {
		int outlen = settings_max_msg_size();
		int ret;

		message = xmalloc(outlen);
		
		ret = zlib_inflate_into(
			const_ptr_add_offset(head, UDP_RELIABLE_HEADER_SIZE),
			s->pos - UDP_RELIABLE_HEADER_SIZE,
			message, &outlen);

		if (ret != Z_OK) {
			valid = FALSE;		/* Does not inflate properly */
			goto done;
		}

		msglen = outlen;
	} else {
		message = ptr_add_offset(
			deconstify_pointer(head), UDP_RELIABLE_HEADER_SIZE);
		msglen = s->pos - UDP_RELIABLE_HEADER_SIZE;
	}

	switch (utp) {
	case SEMI_RELIABLE_GTA:
		/*
		 * Assume message is valid if the Gnutella size header is consistent
		 * with the length of the whole message.
		 */

		{
			uint16 size;

			switch (gmsg_size_valid(message, &size)) {
			case GMSG_VALID:
			case GMSG_VALID_MARKED:
				break;
			case GMSG_VALID_NO_PROCESS: /* Header flags undefined for now */
			case GMSG_INVALID:
				valid = FALSE;
				goto done;
			}

			valid = (size_t) size + GTA_HEADER_SIZE == msglen;
		}
		break;
	case SEMI_RELIABLE_GND:
		valid = TRUE;			/* For now */
		break;
	case GNUTELLA:
	case DHT:
	case UNKNOWN:
		g_assert_not_reached();
	}

done:
	if (uth.flags & UDP_RF_DEFLATED)
		xfree(message);

	return valid;
}

/**
 * Check message header for a valid semi-reliable UDP header.
 *
 * @param head		message header
 * @param len		message length
 *
 * @return intuited type
 */
static enum udp_traffic
udp_check_semi_reliable(const void *head, size_t len)
{
	uint8 flags, part, count;
	const unsigned char *tag;
	enum udp_traffic utp;

	if (len < UDP_RELIABLE_HEADER_SIZE)
		return UNKNOWN;

	/*
	 * We're only interested in "GTA" and "GND" traffic.
	 */

	tag = head;
	if (tag[0] != 'G')
		return UNKNOWN;

	if ('T' == tag[1] && 'A' == tag[2]) {
		utp = SEMI_RELIABLE_GTA;
		goto tag_known;
	}

	if ('N' == tag[1] && 'D' == tag[2]) {
		utp = SEMI_RELIABLE_GND;
		goto tag_known;
	}

	return UNKNOWN;		/* Not a tag we know about */

tag_known:

	/*
	 * Extract key fields from the header.
	 */

	flags = udp_reliable_header_get_flags(head);
	part = udp_reliable_header_get_part(head);
	count = udp_reliable_header_get_count(head);

	/*
	 * There are 2 bits that must be zero in the flags (critical bits that
	 * we don't know about if set and therefore would lead us to drop the
	 * fragment anyway).
	 *
	 * This will match 3 random bytes out of 4, or 75% of them.
	 */

	if (0 != (flags & UDP_RF_CRITICAL_MASK))
		return UNKNOWN;		/* Critical flags we don't know about */

	/*
	 * Normally the part is non-zero, unless we're facing an Extra
	 * Acknowledgment Request (EAR) in which case both part and count will
	 * be set to zero.
	 *
	 * Hence, 0 is an invalid part number for plain fragments only, when
	 * count is non-zero.
	 */

	if (0 == part && 0 != count)
		return UNKNOWN;		/* Invalid fragment number */

	/*
	 * Check acknowledgments for consistency.
	 */

	if (0 == count) {
		size_t nominal_size = UDP_RELIABLE_HEADER_SIZE;

		if (flags & UDP_RF_EXTENDED_ACK) {
			uint8 received;

			if (len < UDP_RELIABLE_EXT_HEADER_SIZE)
				return UNKNOWN;

			received = udp_reliable_get_received(head);
			nominal_size = UDP_RELIABLE_EXT_HEADER_SIZE;

			if (0 == received)
				return UNKNOWN;		/* At least one fragment received! */

			if (0 == part)
				return UNKNOWN;		/* EARs are not extended */

			if ((flags & UDP_RF_CUMULATIVE_ACK) && received < part)
				return UNKNOWN;		/* Receiver must have ``part'' fragments */
		}

		/*
		 * A valid acknowledgment should never claim to have a deflated payload.
		 * First, there is no payload expected, really, but second, in order
		 * to have deflation creating a saving over plain bytes, it would
		 * require to carry over a significant amount of data, something that
		 * is totally illogical in any foreseeable future.
		 */

		if (flags & UDP_RF_DEFLATED)
			return UNKNOWN;			/* Cannot be a legitimate acknowledgment */

		/*
		 * We don't check for the UDP_RF_ACKME flag.  No acknowledgment should
		 * specify this, but implementations should ignore that flag anyway for
		 * acknowledgments, so a broken implementation could have it set and
		 * it would go totally unnoticed during testing.
		 *
		 * Actually, EARs can have the UDP_RF_ACKME flag set, but we don't care
		 * at this point.
		 */

		/*
		 * There could be a (small) payload added one day to acknowledgments,
		 * but it should remain small otherwise the protocol will become
		 * inefficient.
		 *
		 * Therefore it is fair to assume that if the length of the fragment
		 * claiming to be an acknowledgement is more than twice as large as
		 * it should be, it most definitely isn't an acknowledgment.
		 */

		if (len > 2 * nominal_size)
			return UNKNOWN;			/* Was certainly a false positive! */

		return utp;			/* OK, seems valid as far as we can tell */
	}

	/*
	 * This has roughly a 50% chance of correctly ruling out a non-header.
	 */

	if (part > count)
		return UNKNOWN;		/* Invalid fragment number */

	/*
	 * If we are receiving fragment #1 of a message, we can further check
	 * the consistency of the "deflate" flag provided we have at least 2 bytes
	 * in the payload.
	 */

	if (
		1 == part && (flags & UDP_RF_DEFLATED) &&
		len >= UDP_RELIABLE_HEADER_SIZE + 2
	) {
		const void *payload =
			const_ptr_add_offset(head, UDP_RELIABLE_HEADER_SIZE);

		if (!zlib_is_valid_header(payload, len - UDP_RELIABLE_HEADER_SIZE))
			return UNKNOWN;	/* Supposedly deflated payload is not valid */
	}

	return utp;
}

/**
 * Identify the traffic type received on the UDP socket.
 *
 * This routine uses simple heuristics that ensure we're properly discriminating
 * incoming traffic on the UDP socket between regular Gnutella traffic and
 * semi-reliable UDP traffic (which adds a small header before its actual
 * payload).
 *
 * Most messages will be un-ambiguous, and the probabilty of misclassifying
 * an ambiguous message (one that look like valid for both types, based on
 * header inspections) is brought down to less than 1 in a billion, making
 * it perfectly safe in practice.
 *
 * @return intuited type
 */
static enum udp_traffic
udp_intuit_traffic_type(const gnutella_socket_t *s)
{
	enum udp_traffic utp;
	const void *head = cast_to_pointer(s->buf);

	utp = udp_check_semi_reliable(head, s->pos);

	if (s->pos >= GTA_HEADER_SIZE) {
		uint16 size;			/* Payload size, from the Gnutella message */
		gmsg_valid_t valid;

		valid = gmsg_size_valid(head, &size);

		switch (valid) {
		case GMSG_VALID:
		case GMSG_VALID_MARKED:
			if ((size_t) size + GTA_HEADER_SIZE == s->pos) {
				uint8 function, hops, ttl;

				function = gnutella_header_get_function(head);

				/*
				 * If the header cannot be that of a known semi-reliable
				 * UDP protocol, there is no ambiguity.
				 */

				if (UNKNOWN == utp)
					return GTA_MSG_DHT == function ? DHT : GNUTELLA;

				/*
				 * Message is ambiguous: its leading header appears to be
				 * both a legitimate Gnutella message and a semi-reliable UDP
				 * header.
				 *
				 * We have to apply some heuristics to decide whether to handle
				 * the message as a Gnutella one or as a semi-reliable UDP one,
				 * knowing that if we improperly classify it, the message will
				 * not be handled correctly.
				 *
				 * Note that this is highly unlikely.  There is about 1 chance
				 * in 10 millions (1 / 2^23 exactly) to mis-interpret a random
				 * Gnutella MUID as the start of one of the semi-reliable
				 * protocols we support.  Our discriminating logic probes a
				 * few more bytes (say 2 at least) which are going to let us
				 * decide with about 99% certainety.  So mis-classification
				 * will occur only once per billion -- a ratio which is OK.
				 *
				 * We could also mistakenely handle a semi-reliable UDP message
				 * as a Gnutella one.  For that to happen, the payload must
				 * contain a field that will be exactly the message size,
				 * a 1 / 2^32 event (since the size is 4 bytes in Gnutella).
				 * However, if message flags are put to use for Gnutella UDP,
				 * this ratio could lower to 1 / 2^16 and that is too large
				 * a chance (about 1.5 in 100,000).
				 *
				 * So when we think an ambiguous message could be a valid
				 * Gnutella message, we also check whether the message could
				 * not be interpreted as a valid semi-reliable UDP one, and
				 * we give priority to that classification if we have a match:
				 * correct sequence number, consistent count and emitting host.
				 * This checks roughly 3 more bytes in the message, yielding
				 * a misclassification for about 1 / 2^(16+24) random cases.
				 */

				hops = gnutella_header_get_hops(head);
				ttl = gnutella_header_get_ttl(head);

				gnet_stats_inc_general(GNR_UDP_AMBIGUOUS);

				if (GNET_PROPERTY(udp_debug)) {
					g_debug("UDP ambiguous datagram from %s: "
						"%zu bytes (%u-byte payload), "
						"function=%u, hops=%u, TTL=%u, size=%u",
						host_addr_port_to_string(s->addr, s->port),
						s->pos, size, function, hops, ttl,
						gnutella_header_get_size(head));
					dump_hex(stderr, "UDP ambiguous datagram", s->buf, s->pos);
				}

				switch (function) {
				case GTA_MSG_DHT:
					/*
					 * A DHT message must be larger than KDA_HEADER_SIZE bytes.
					 */

					if (s->pos < KDA_HEADER_SIZE)
						break;		/* Not a DHT message */

					/*
					 * DHT messages have no bits defined in the size field
					 * to mark them.
					 */

					if (valid != GMSG_VALID)
						break;		/* Higest bit set, not a DHT message */

					/*
					 * If it is a DHT message, it must have a valid opcode.
					 */

					function = kademlia_header_get_function(head);

					if (function > KDA_MSG_MAX_ID)
						break;		/* Not a valid DHT opcode */

					/*
					 * Check the contact address length: it must be 4 in the
					 * header, because there is only room for an IPv4 address.
					 */

					if (!kademlia_header_constants_ok(head))
						break;		/* Not a valid Kademlia header */

					/*
					 * Make sure we're not mistaking a valid semi-reliable UDP
					 * message as a DHT message.
					 */

					if (udp_is_valid_semi_reliable(utp, s))
						break;		/* Validated it as semi-reliable UDP */

					g_warning("UDP ambiguous message from %s (%zu bytes total),"
						" DHT function is %s",
						host_addr_port_to_string(s->addr, s->port),
						s->pos, kmsg_name(function));

					return DHT;

				case GTA_MSG_INIT:
				case GTA_MSG_PUSH_REQUEST:
				case GTA_MSG_SEARCH:
					/*
					 * No incoming messages of this type can have a TTL
					 * indicating a deflated payload, since there is no
					 * guarantee the host would be able to read it (deflated
					 * UDP is negotiated and can therefore only come from a
					 * response).
					 */

					if (ttl & GTA_UDP_DEFLATED)
						break;			/* Not Gnutella, we're positive */

					/* FALL THROUGH */

				case GTA_MSG_INIT_RESPONSE:
				case GTA_MSG_VENDOR:
				case GTA_MSG_SEARCH_RESULTS:
				case GTA_MSG_RUDP:
					/*
					 * To further discriminate, look at the hop count.
					 * Over UDP, the hop count will be low (0 or 1 mostly)
					 * and definitely less than 3 since the only UDP-relayed
					 * messages are from GUESS, and they can travel at most
					 * through a leaf and an ultra node before reaching us.
					 */

					if (hops >= 3U)
						break;			/* Gnutella is very unlikely */

					/*
					 * Check the TTL, cleared from bits that indicate
					 * support for deflated UDP or a deflated payload.
					 * No servent should send a TTL greater than 7, which
					 * was the de-facto limit in the early Gnutella days.
					 */

					if ((ttl & ~(GTA_UDP_CAN_INFLATE | GTA_UDP_DEFLATED)) > 7U)
						break;			/* Gnutella is very unlikely */

					/*
					 * Make sure we're not mistaking a valid semi-reliable UDP
					 * message as a Gnutella message.
					 */

					if (udp_is_valid_semi_reliable(utp, s))
						break;		/* Validated it as semi-reliable UDP */

					g_warning("UDP ambiguous message from %s (%zu bytes total),"
						" Gnutella function is %s, hops=%u, TTL=%u",
						host_addr_port_to_string(s->addr, s->port),
						s->pos, gmsg_name(function), hops, ttl);

					return GNUTELLA;

				case GTA_MSG_STANDARD:	/* Nobody is using this function code */
				default:
					break;				/* Not a function we expect over UDP */
				}

				/*
				 * Will be handled as semi-reliable UDP.
				 */

				gnet_stats_inc_general(GNR_UDP_AMBIGUOUS_AS_SEMI_RELIABLE);

				{
					udp_tag_t tag;

					memcpy(tag.value, head, sizeof tag.value);

					g_warning("UDP ambiguous message (%zu bytes total), "
						"not Gnutella (function is %d, hops=%u, TTL=%u) "
						"handling as semi-reliable UDP (tag=\"%s\")",
						s->pos, function, hops, ttl, udp_tag_to_string(tag));
				}
				return utp;
			}
			/* FALL THROUGH */
		case GMSG_VALID_NO_PROCESS:
		case GMSG_INVALID:
			break;
		}
	}

	return utp;
}

/**
 * Notification from the socket layer that we got a new datagram.
 *
 * If `truncated' is true, then the message was too large for the
 * socket buffer.
 */
void
udp_received(struct gnutella_socket *s, bool truncated)
{
	gnutella_node_t *n;
	bool bogus = FALSE;
	bool dht = FALSE;

	/*
	 * This must be regular Gnutella / DHT traffic.
	 */

	inet_udp_got_incoming(s->addr);

	/*
	 * We need to identify semi-reliable UDP traffic early, because that
	 * traffic needs to go through the RX stack to reassemble the final
	 * payload out of the many fragments, or to process the acknowledgments.
	 *
	 * We have to apply heuristics however because the leading 8 bytes could
	 * be just a part of gnutella message (the first 8 bytes of a GUID).
	 * One thing is certain though: if the size is less than that of a a
	 * Gnutella header, it has to be semi-reliable UDP traffic...
	 *
	 * Because semi-reliable UDP uses small payloads, much smaller than our
	 * socket buffer, the datagram cannot be truncated.
	 */

	if (!truncated) {
		enum udp_traffic utp;
		rxdrv_t *rx;

		utp = udp_intuit_traffic_type(s);

		switch (utp) {
		case GNUTELLA:
			dht = FALSE;
			goto unreliable;
		case DHT:
			dht = TRUE;
			goto unreliable;
		case UNKNOWN:
			goto unknown;
		case SEMI_RELIABLE_GTA:
		case SEMI_RELIABLE_GND:
			break;
		}

		/*
		 * We are going to treat this message a a semi-reliable UDP fragment.
		 *
		 * Account the size of the payload for traffic purposes, then redirect
		 * the message to the RX layer that reassembles and dispatches these
		 * messages.
		 */

		bws_udp_count_read(s->pos, FALSE);	/* We know it's not DHT traffic */

		rx = udp_get_rx_semi_reliable(utp, s->addr);

		if (rx != NULL) {
			gnet_host_t from;

			gnet_host_set(&from, s->addr, s->port);
			ut_got_message(rx, s->buf, s->pos, &from);
		}

		return;
	}

unknown:
	/*
	 * Discriminate between Gnutella UDP and DHT messages, so that we
	 * can account received data with the proper bandwidth scheduler.
	 */

	if (s->pos >= GTA_HEADER_SIZE)
		dht = GTA_MSG_DHT == gnutella_header_get_function(s->buf);

unreliable:

	bws_udp_count_read(s->pos, dht);

	/*
	 * If we get traffic from a bogus IP (unroutable), warn, for now.
	 */

	if (bogons_check(s->addr)) {
		bogus = TRUE;

		if (GNET_PROPERTY(udp_debug)) {
			g_warning("UDP %sdatagram (%d byte%s) received from bogus IP %s",
				truncated ? "truncated " : "",
				(int) s->pos, s->pos == 1 ? "" : "s",
				host_addr_to_string(s->addr));
		}
		gnet_stats_inc_general(GNR_UDP_BOGUS_SOURCE_IP);
	}

	/*
	 * Get proper pseudo-node.
	 *
	 * These routines can return NULL if the address/port combination is
	 * not correct, but this will be handled by udp_is_valid_gnet().
	 */

	n = dht ? node_dht_get_addr_port(s->addr, s->port) :
		node_udp_get_addr_port(s->addr, s->port);

	if (!udp_is_valid_gnet(n, s, truncated, s->buf, s->pos))
		return;

	/*
	 * Process message as if it had been received from regular Gnet by
	 * another node, only we'll use a special "pseudo UDP node" as origin.
	 */

	if (GNET_PROPERTY(udp_debug) > 19 || (bogus && GNET_PROPERTY(udp_debug)))
		g_debug("UDP got %s from %s%s", gmsg_infostr_full(s->buf, s->pos),
			bogus ? "BOGUS " : "", host_addr_port_to_string(s->addr, s->port));

	node_udp_process(n, s);
}

/**
 * Send a datagram to the specified node, made of `len' bytes from `buf',
 * forming a valid Gnutella message.
 */
void
udp_send_msg(const gnutella_node_t *n, const void *buf, int len)
{
	pmsg_t *mb;

	g_assert(NODE_IS_UDP(n));
	g_return_if_fail(n->outq);

	/*
	 * If message is directed to a UDP node that can do semi-reliable UDP,
	 * then turn on reliability on the message.
	 */

	mb = gmsg_to_pmsg(buf, len);
	if (NODE_CAN_SR_UDP(n))
		pmsg_mark_reliable(mb);
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a datagram to the specified node, made of `len' bytes from `buf',
 * forming a valid Gnutella message, with a "control" priority.
 */
void
udp_ctrl_send_msg(const gnutella_node_t *n, const void *buf, int len)
{
	pmsg_t *mb;

	g_assert(NODE_IS_UDP(n));
	g_return_if_fail(n->outq);

	mb = gmsg_to_ctrl_pmsg(buf, len);
	if (NODE_CAN_SR_UDP(n))
		pmsg_mark_reliable(mb);		/* Send reliably if node supports it */
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a message to specified UDP node.
 *
 * It is up to the caller to clone the message if needed, otherwise the
 * node's queue becomes the sole owner of the message and will pmsg_free() it.
 */
void
udp_send_mb(const gnutella_node_t *n, pmsg_t *mb)
{
	if (NULL == n || NULL == n->outq) {
		pmsg_free(mb);
		/* emit warnings */
		g_return_if_fail(n);
		g_return_if_fail(n->outq);
		g_assert_not_reached();
	}
	g_assert(NODE_IS_UDP(n));
	if (NODE_CAN_SR_UDP(n))
		pmsg_mark_reliable(mb);		/* Send reliably if node supports it */
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a message to the DHT node through UDP.
 *
 * It is up to the caller to clone the message if needed, otherwise the
 * node's queue becomes the sole owner of the message and will pmsg_free() it.
 */
void
udp_dht_send_mb(const gnutella_node_t *n, pmsg_t *mb)
{
	if (NULL == n || NULL == n->outq) {
		pmsg_free(mb);
		/* emit warnings */
		g_return_if_fail(n);
		g_return_if_fail(n->outq);
		g_assert_not_reached();
	}
	g_assert(NODE_IS_DHT(n));
	mq_udp_node_putq(n->outq, mb, n);
}

/**
 * Send a Gnutella ping to the specified host via UDP, using the
 * specified MUID.
 */
void
udp_connect_back(const host_addr_t addr, uint16 port, const struct guid *muid)
{
	if (udp_send_ping(muid, addr, port, FALSE)) {
		if (GNET_PROPERTY(udp_debug) > 19)
			g_debug("UDP queued connect-back PING %s to %s\n",
				guid_hex_str(muid), host_addr_port_to_string(addr, port));
	}
}

/***
 *** Management of "UDP ping RPCs", whereby we register a ping event and
 *** expect a pong back within a hardwired timeout.
 ***/

struct udp_ping_cb {
	udp_ping_cb_t cb;
	void *data;
	unsigned multiple:1;
	unsigned got_reply:1;
};

struct udp_ping {
	struct guid muid;	/* MUST be at offset zero (for hashing function) */
	time_t added;		/**< Timestamp of insertion */
	struct udp_ping_cb *callback;	/**< Optional: callback description */
};

static const time_delta_t UDP_PING_TIMEOUT	   = 30;	/**< seconds */
static const size_t		  UDP_PING_MAX 		   = 1024;	/**< amount to track */
static const int 		  UDP_PING_PERIODIC_MS = 10000;	/**< milliseconds */

static hash_list_t *udp_pings;	/**< Tracks send/forwarded UDP Pings */
static cevent_t *udp_ping_ev;	/**< Monitoring event */

static inline void
udp_ping_free(struct udp_ping *ping)
{
	WFREE_NULL(ping->callback, sizeof *ping->callback);
	WFREE(ping);
}

/**
 * Expire registered pings.
 *
 * @param forced	TRUE if we're shutdowning and want to cleanup
 */
static void
udp_ping_expire(bool forced)
{
	time_t now;

	g_return_if_fail(udp_pings);

	now = tm_time();
	for (;;) {
		struct udp_ping *ping;
		time_delta_t d;

		ping = hash_list_head(udp_pings);
		if (!ping) {
			break;
		}
		if (!forced) {
			d = delta_time(now, ping->added);
			if (d > 0 && d <= UDP_PING_TIMEOUT) {
				break;
			}
		}
		if (ping->callback) {
			(*ping->callback->cb)(
				ping->callback->got_reply ?
					UDP_PING_EXPIRED : UDP_PING_TIMEDOUT,
				NULL, ping->callback->data);
		}
		hash_list_remove(udp_pings, ping);
		udp_ping_free(ping);
	}
}

/**
 * Callout queue callback to perform periodic monitoring of the
 * registered pings.
 */
static void
udp_ping_timer(cqueue_t *cq, void *unused_udata)
{
	(void) unused_udata;

	/*
	 * Re-install timer for next time.
	 */

	udp_ping_ev = cq_insert(cq, UDP_PING_PERIODIC_MS, udp_ping_timer, NULL);
	udp_ping_expire(FALSE);
}

static bool
udp_ping_register(const struct guid *muid,
	udp_ping_cb_t cb, void *data, bool multiple)
{
	struct udp_ping *ping;
	uint length;

	g_assert(muid);
	g_return_val_if_fail(udp_pings, FALSE);

	if (hash_list_contains(udp_pings, muid)) {
		/* Probably a duplicate */
		return FALSE;
	}

	/* random early drop */
	length = hash_list_length(udp_pings);
	if (length >= UDP_PING_MAX) {
		return FALSE;
	} else if (length > (UDP_PING_MAX / 4) * 3) {
		if (random_value(UDP_PING_MAX - 1) < length)
			return FALSE;
	}

	WALLOC(ping);
	ping->muid = *muid;
	ping->added = tm_time();
	if (cb != NULL) {
		WALLOC0(ping->callback);
		ping->callback->cb = cb;
		ping->callback->data = data;
		ping->callback->multiple = booleanize(multiple);
	} else {
		ping->callback = NULL;
	}
	hash_list_append(udp_pings, ping);
	return TRUE;
}

/**
 * Upon reception of an UDP pong, check whether we had a matching registered
 * ping bearing the given MUID.
 *
 * If there was a callback atttached to the reception of a reply, invoke it
 * before returning.
 *
 * @return TRUE if indeed this was a reply for a ping we sent.
 */
enum udp_pong_status
udp_ping_is_registered(const struct gnutella_node *n)
{
	const struct guid *muid = gnutella_header_get_muid(&n->header);

	if (udp_pings) {
		struct udp_ping *ping;

		ping = hash_list_remove(udp_pings, muid);
		if (ping) {
			if (ping->callback) {
				(*ping->callback->cb)(UDP_PING_REPLY, n, ping->callback->data);
				if (ping->callback->multiple) {
					ping->callback->got_reply = TRUE;
					ping->added = tm_time();	/* Delay expiration */
					hash_list_append(udp_pings, ping);
				} else {
					udp_ping_free(ping);
				}
				return UDP_PONG_HANDLED;
			}
			udp_ping_free(ping);
			return UDP_PONG_SOLICITED;
		}
	}
	return UDP_PONG_UNSOLICITED;
}

/**
 * Send a Gnutella ping message to the specified host.
 *
 * @param m			the Ping message to send
 * @param size		size of the Ping message, in bytes
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param cb		if non-NULL, callback to invoke on reply or timeout
 * @param arg		additional callback argument
 * @param multiple	whether multiple replies (Pongs) are expected
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
static bool
udp_send_ping_with_callback(
	gnutella_msg_init_t *m, uint32 size,
	const host_addr_t addr, uint16 port,
	udp_ping_cb_t cb, void *arg, bool multiple)
{
	struct gnutella_node *n = node_udp_get_addr_port(addr, port);

	if (n != NULL) {
		if (udp_ping_register(gnutella_header_get_muid(m), cb, arg, multiple)) {
			aging_insert(udp_aging_pings,
				wcopy(&addr, sizeof addr), GUINT_TO_POINTER(1));
			udp_send_msg(n, m, size);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Send a new Gnutella ping message to the specified host.
 *
 * @param muid		the MUID to use (allocated randomly if NULL)
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param uhc_ping	if TRUE, include the "SCP" GGEP extension
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
bool
udp_send_ping(const struct guid *muid, const host_addr_t addr, uint16 port,
	bool uhc_ping)
{
	gnutella_msg_init_t *m;
	uint32 size;

	/*
	 * Don't send too frequent pings: they may throttle us anyway.
	 */

	if (aging_lookup(udp_aging_pings, &addr)) {
		if (GNET_PROPERTY(udp_debug) > 1) {
			g_warning("UDP throttling %sping to %s",
				uhc_ping ? "UHC " : "", host_addr_to_string(addr));
		}
		return FALSE;
	}

	m = build_ping_msg(muid, 1, uhc_ping, &size);
	return udp_send_ping_with_callback(m, size, addr, port, NULL, NULL, FALSE);
}

/**
 * Send given Gnutella ping message to the host, monitoring replies and
 * timeouts through specified callback.
 *
 * @param m			the Ping message to send
 * @param size		size of the Ping message, in bytes
 * @param addr		address to which ping should be sent
 * @param port		port number
 * @param cb		callback to invoke on reply or timeout
 * @param arg		additional callback argument
 * @param multiple	whether multiple replies (Pongs) are expected
 *
 * @return TRUE if we sent the ping, FALSE it we throttled it.
 */
bool
udp_send_ping_callback(
	gnutella_msg_init_t *m, uint32 size,
	const host_addr_t addr, uint16 port,
	udp_ping_cb_t cb, void *arg, bool multiple)
{
	g_assert(cb != NULL);
	g_assert(GTA_MSG_INIT == gnutella_header_get_function(m));

	return udp_send_ping_with_callback(m, size, addr, port, cb, arg, multiple);
}

/***
 *** Init / shutdown
 ***/

/**
 * UDP layer startup
 */
void
udp_init(void)
{
	/*
	 * Limit sending of UDP pings to 1 per UDP_PING_FREQ seconds.
	 */

	udp_aging_pings = aging_make(UDP_PING_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	udp_pings = hash_list_new(guid_hash, guid_eq);
	udp_ping_timer(cq_main(), NULL);
}

/**
 * Final cleanup when application terminates.
 */
void
udp_close(void)
{
	if (udp_pings) {
		udp_ping_expire(TRUE);
		hash_list_free(&udp_pings);
	}

	aging_destroy(&udp_aging_pings);
}

/* vi: set ts=4 sw=4 cindent: */
