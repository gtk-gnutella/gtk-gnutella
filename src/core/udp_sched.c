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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * UDP TX traffic scheduler.
 *
 * This layer schedules the sending of enqueued UDP datagrams in a LIFO
 * manner according to available bandwidth.  Packets are silently dropped
 * when they become too old.
 *
 * Packets in the LIFO stack are also processed by destination address to avoid
 * flooding the destination with too many packets: when an entry in the LIFO
 * is processed, its destination is remembered and we skip other items to the
 * same destination until we have processed all the queued items and bandwidth
 * remains, at which time we go back to the top of the stack and resume.
 *
 * This layer stops accepting packets (i.e. it returns 0 on send() operations)
 * when its amount buffered is 3 times the amount of data that can be sent per
 * second.
 *
 * Scheduling of UDP packets is normally done once per second but in the advent
 * all the bandwidth was not consumed, incoming packets are sent immediately
 * until no more bandwidth is available, at which point we start queuing again.
 *
 * A scheduling queue is maintained by priority to send traffic ahead of any
 * other less prioritary packets.  This is typically used for acknowledgments,
 * since delaying an ACK will likely cause retransmission on the other end.
 *
 * This layer is at the bottom of the TX stacks, but it can be used by several
 * TX stacks which happen to have the same shared bandwidth pool.  Therefore,
 * each packet to send also remembers its TX stack origin (for callback
 * processing, which need to get at the TX owner).
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "udp_sched.h"

#include "bsched.h"
#include "gnet_stats.h"
#include "inet.h"
#include "sockets.h"
#include "tx.h"
#include "tx_dgram.h"

#include "lib/atoms.h"
#include "lib/eslist.h"
#include "lib/host_addr.h"
#include "lib/gnet_host.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/hset.h"
#include "lib/log.h"
#include "lib/palloc.h"
#include "lib/pmsg.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

#define UDP_SCHED_EXPIRE	5	/**< Seconds before expiring unsent messages */
#define UDP_SCHED_FACTOR	3	/**< Stop when that many times the b/w queued */

#define udp_sched_log(lvl, fmt, ...)						\
G_STMT_START {												\
	if G_UNLIKELY(GNET_PROPERTY(udp_sched_debug) >= (lvl))	\
		s_debug("%s: " fmt, G_STRFUNC, __VA_ARGS__);		\
} G_STMT_END


enum udp_sched_magic { UDP_SCHED_MAGIC = 0x23e00967 };

enum udp_sched_net {
	UDP_SCHED_IPv4 = 0,
	UDP_SCHED_IPv6 = 1,

	UDP_SCHED_NET_CNT
};

static const enum net_type udp_sched_net_type[UDP_SCHED_NET_CNT] = {
	NET_TYPE_IPV4,			/* UDP_SCHED_IPv4 */
	NET_TYPE_IPV6,			/* UDP_SCHED_IPv6 */
};

/**
 * The UDP TX scheduler object.
 *
 * Buffers to send are represented by a TX descriptor which are linked into
 * the LIFO field.
 *
 * The TX stacks using us (i.e. the ones attaching us as the sending mechanism)
 * are tracked so that we can trigger upper-level servicing when bandwidth
 * becomes available again.
 *
 * Each time the UDP sockets (that the application makes available to actually
 * send UDP datagrams) change, a call to udp_sched_update_sockets() is required
 * to update the cached information.
 */
struct udp_sched {
	enum udp_sched_magic magic;		/**< Magic number */
	pool_t *txpool;					/**< TX descriptor pool */
	bio_source_t *bio[UDP_SCHED_NET_CNT];	/**< Bandwidth-limited I/O source */
	udp_sched_socket_cb_t get_socket;		/**< Get the UDP socket by net */
	eslist_t lifo[PMSG_P_COUNT];	/**< LIFO stacks of TX descriptors */
	eslist_t tx_released;			/**< Deferred TX descriptor freeing */
	bsched_bws_t bws;				/**< Bandwidth scheduler to use */
	hset_t *seen;					/**< Remembers destinations processed */
	hash_list_t *stacks;			/**< TX stacks using us */
	size_t buffered;				/**< Amount buffered (regular + urgent) */
	unsigned used_all:1;			/**< Set when all b/w was used */
	unsigned flow_controlled:1;		/**< Whether we flow-controlled */
};

static inline void
udp_sched_check(const struct udp_sched * const us)
{
	g_assert(us != NULL);
	g_assert(UDP_SCHED_MAGIC == us->magic);
}

enum udp_tx_desc_magic { UDP_TX_DESC_MAGIC = 0x66f40d1b };

/**
 * A TX descriptor.
 */
struct udp_tx_desc {
	enum udp_tx_desc_magic magic;	/**< Magic number */
	pmsg_t *mb;						/**< The message block to send */
	const gnet_host_t *to;			/**< Destination address (atom) */
	const txdrv_t *tx;				/**< TX stack origin */
	const struct tx_dgram_cb *cb;	/**< Callback actions on datagram */
	slink_t lnk;					/**< LIFO queue link */
	time_t expire;					/**< Expiration time */
};

static inline void
udp_tx_desc_check(const struct udp_tx_desc * const txd)
{
	g_assert(txd != NULL);
	g_assert(UDP_TX_DESC_MAGIC == txd->magic);
}

/**
 * The TX stacks using us are remembered along with their "is_writable"
 * callback routine so that we can trigger servicing.
 */
struct udp_tx_stack {
	const txdrv_t *tx;
	inputevt_handler_t writable;
};

static uint
udp_tx_stack_hash(const void *key)
{
	const struct udp_tx_stack *uts = key;

	return pointer_hash(uts->tx);
}

static bool
udp_tx_stack_eq(const void *a, const void *b)
{
	const struct udp_tx_stack *ua = a, *ub = b;

	return ua->tx == ub->tx;
}

/**
 * Wrapper used by palloc() to allocate a new UDP TX descriptor.
 */
static void *
udp_tx_desc_alloc(size_t size)
{
	struct udp_tx_desc *txd;

	g_assert(sizeof *txd == size);

	WALLOC0(txd);
	return txd;
}

/**
 * Wrapper used by pfree() to release a UDP TX descriptor.
 */
static void
udp_tx_desc_free(void *p, size_t size, bool fragment)
{
	struct udp_tx_desc *txd = p;

	g_assert(sizeof *txd == size);
	(void) fragment;

	WFREE(txd);
}

/**
 * Release user data from TX descriptor, then return it to the pool.
 */
static void
udp_tx_desc_release(struct udp_tx_desc *txd, udp_sched_t *us)
{
	udp_tx_desc_check(txd);
	udp_sched_check(us);

	pmsg_free_null(&txd->mb);
	atom_host_free_null(&txd->to);
	pfree(us->txpool, txd);
}

/**
 * Flag TX descriptor for release.
 *
 * During list iteration, one cannot free up the message block because the
 * free routine attached to the mesasge block could decide to re-enqueue
 * the unsent packet, which would modify the list we're iterating over.
 *
 * To avoid that problem, we link away the TX descriptor for later release.
 * This works because the eslist iterators are immune to item freeing, meaning
 * they don't re-inspect the link_t item after calling the callback.  Hence
 * we can safely update the link_t item.
 */
static void
udp_tx_desc_flag_release(struct udp_tx_desc *txd, udp_sched_t *us)
{
	udp_tx_desc_check(txd);
	udp_sched_check(us);

	eslist_mark_removed(&us->tx_released, txd);		/* For assertions */
	eslist_append(&us->tx_released, txd);
}

/**
 * Release message (eslist iterator).
 *
 * @return TRUE to force message to be removed from list.
 */
static bool
udp_tx_desc_reclaim(void *data, void *udata)
{
	struct udp_tx_desc *txd = data;
	udp_sched_t *us = udata;

	udp_sched_check(us);
	udp_tx_desc_check(txd);
	g_assert(1 == pmsg_refcnt(txd->mb));

	udp_tx_desc_release(txd, us);
	return TRUE;
}

/**
 * Drop message (eslist iterator).
 *
 * @return TRUE to force message to be removed from list.
 */
static bool
udp_tx_desc_drop(void *data, void *udata)
{
	struct udp_tx_desc *txd = data;
	udp_sched_t *us = udata;

	udp_sched_check(us);
	udp_tx_desc_check(txd);
	g_assert(1 == pmsg_refcnt(txd->mb));

	us->buffered = size_saturate_sub(us->buffered, pmsg_size(txd->mb));
	udp_tx_desc_flag_release(txd, us);
	return TRUE;
}

/**
 * Remove expired messages (eslist iterator).
 *
 * @return TRUE if message has expired and was freed up.
 */
static bool
udp_tx_desc_expired(void *data, void *udata)
{
	struct udp_tx_desc *txd = data;
	udp_sched_t *us = udata;

	udp_sched_check(us);
	udp_tx_desc_check(txd);

	if (delta_time(tm_time(), txd->expire) > 0) {
		static gnr_stats_t s[] = {
			GNR_UDP_SCHED_TIMED_OUT_PRIO_DATA,
			GNR_UDP_SCHED_TIMED_OUT_PRIO_CONTROL,
			GNR_UDP_SCHED_TIMED_OUT_PRIO_URGENT,
			GNR_UDP_SCHED_TIMED_OUT_PRIO_HIGHEST,
		};
		uint8 prio = pmsg_prio(txd->mb);

		STATIC_ASSERT(PMSG_P_COUNT == N_ITEMS(s));

		g_assert_log(prio < PMSG_P_COUNT,
			"%s(): prio=%u", G_STRFUNC, prio);

		udp_sched_log(1, "%p: expiring mb=%p (%d bytes) prio=%u",
			us, txd->mb, pmsg_size(txd->mb), prio);

		gnet_stats_inc_general(s[prio]);

		if (txd->cb->add_tx_dropped != NULL)
			(*txd->cb->add_tx_dropped)(txd->tx->owner, 1);	/* Dropped in TX */

		return udp_tx_desc_drop(data, udata);			/* Returns TRUE */
	}

	return FALSE;
}

/**
 * Forcefully drop all items in the specified list.
 */
static void
udp_sched_drop_all(udp_sched_t *us, eslist_t *list)
{
	eslist_foreach_remove(list, udp_tx_desc_drop, us);
}

/**
 * Log TX error if unusual.
 *
 * @return TRUE if the error was fatal, FALSE if it's a temporary error and
 * the message needs to be enqueued.
 */
static bool
udp_sched_write_error(const udp_sched_t *us, const gnet_host_t *to,
	const pmsg_t *mb, const char *func)
{
	(void) us;		/* FIXME -- no longer used */

	if (is_temporary_error(errno) || ENOBUFS == errno)
		return FALSE;

	switch (errno) {
	/*
	 * The following are probably due to bugs in the libc, but this is in
	 * the same vein as write() failing with -1 whereas errno == 0!  Be more
	 * robust against bugs in the components we rely on. --RAM, 09/10/2003
	 */
	case EINPROGRESS:		/* Weird, but seen it -- RAM, 07/10/2003 */
	{
		g_warning("%s(to=%s, len=%d) failed with weird errno = %m -- "
			"assuming EAGAIN", func, gnet_host_to_string(to), pmsg_size(mb));
	}
		break;
	case EPIPE:
	case ENOSPC:
	case ENOMEM:
	case EINVAL:			/* Seen this with "reserved" IP addresses */
#ifdef EDQUOT
	case EDQUOT:
#endif /* EDQUOT */
	case EMSGSIZE:			/* Message too large */
	case EFBIG:
	case EIO:
	case EADDRNOTAVAIL:
	case ECONNABORTED:
	case ECONNRESET:
	case ECONNREFUSED:
	case ENETRESET:
	case ENETDOWN:
	case ENETUNREACH:
	case EHOSTDOWN:
	case EHOSTUNREACH:
	case ENOPROTOOPT:
	case EPROTONOSUPPORT:
	case ETIMEDOUT:
	case EACCES:
	case EPERM:
		/*
		 * We don't care about lost packets.
		 */
		g_warning("%s(): UDP write of %d bytes to %s failed: %m",
			func, pmsg_size(mb), gnet_host_to_string(to));
		break;
	default:
		g_critical("%s(): UDP write of %d bytes to %s failed "
			"with unexpected errno %d: %m",
			func, pmsg_size(mb), gnet_host_to_string(to), errno);
		break;
	}

	return TRUE;	/* Fatal error */
}

/**
 * Drop message that could not be sent.
 *
 * @param tx		the TX stack sending the message
 * @param cb		callback actions on the datagram
 *
 * @return TRUE.
 */
static bool
udp_tx_drop(const txdrv_t *tx, const struct tx_dgram_cb *cb)
{
	if (cb->add_tx_dropped != NULL)
		(*cb->add_tx_dropped)(tx->owner, 1);	/* Dropped in TX */

	return TRUE;
}

/**
 * Send message block to IP:port.
 *
 * @param us		the UDP scheduler
 * @param mb		the message to send
 * @param to		the IP:port destination of the message
 * @param tx		the TX stack sending the message
 * @param cb		callback actions on the datagram
 *
 * @return TRUE if message was sent or dropped, FALSE if there is no more
 * bandwidth to send anything.
 */
static bool
udp_sched_mb_sendto(udp_sched_t *us, pmsg_t *mb, const gnet_host_t *to,
	const txdrv_t *tx, const struct tx_dgram_cb *cb)
{
	ssize_t r;
	int len = pmsg_size(mb);
	bio_source_t *bio = NULL;

	if (0 == gnet_host_get_port(to)) {
		gnet_stats_inc_general(GNR_UDP_SCHED_DROP_ZERO_PORT);
		return TRUE;
	}

	/*
	 * Check whether message still needs to be sent.
	 */

	if (!pmsg_can_transmit(mb)) {
		gnet_stats_inc_general(GNR_UDP_SCHED_DROP_NO_LONGER_NEEDED);
		return TRUE;			/* Dropped */
	}

	/*
	 * Select the proper I/O source depending on the network address type.
	 */

	switch (gnet_host_get_net(to)) {
	case NET_TYPE_IPV4:
		bio = us->bio[UDP_SCHED_IPv4];
		break;
	case NET_TYPE_IPV6:
		bio = us->bio[UDP_SCHED_IPv6];
		break;
	case NET_TYPE_NONE:
	case NET_TYPE_LOCAL:
		g_assert_not_reached();
	}

	/*
	 * If there is no I/O source, then the socket to send that type of traffic
	 * was cleared, hence we simply need to discard the message.
	 */

	if (NULL == bio) {
		udp_sched_log(4, "%p: discarding mb=%p (%d bytes) to %s",
			us, mb, pmsg_written_size(mb), gnet_host_to_string(to));
		gnet_stats_inc_general(GNR_UDP_SCHED_DROP_NO_SOCKET);
		return udp_tx_drop(tx, cb);		/* TRUE, for "sent" */
	}

	/*
	 * OK, proceed if we have bandwidth.
	 */

	r = bio_sendto(bio, to, pmsg_phys_base(mb), len);

	if (r < 0) {		/* Error, or no bandwidth */
		if (udp_sched_write_error(us, to, mb, G_STRFUNC)) {
			udp_sched_log(4, "%p: dropped mb=%p (%d bytes): %m",
				us, mb, pmsg_written_size(mb));
			gnet_stats_inc_general(GNR_UDP_SCHED_DROP_IO_ERROR);
			return udp_tx_drop(tx, cb);	/* TRUE, for "sent" */
		}
		udp_sched_log(3, "%p: no bandwidth for mb=%p (%d bytes)",
			us, mb, pmsg_written_size(mb));
		us->used_all = TRUE;
		return FALSE;
	}

	if (r != len) {
		/* This should never happen with UDP/IP since datagrams are atomic */
		g_warning("%s: partial UDP write (%zd bytes) to %s "
			"for %d-byte datagram",
			G_STRFUNC, r, gnet_host_to_string(to), len);
	} else {
		static gnr_stats_t s[] = {
			GNR_UDP_SCHED_FINALLY_SENT_PRIO_DATA,
			GNR_UDP_SCHED_FINALLY_SENT_PRIO_CONTROL,
			GNR_UDP_SCHED_FINALLY_SENT_PRIO_URGENT,
			GNR_UDP_SCHED_FINALLY_SENT_PRIO_HIGHEST,
		};
		uint prio = pmsg_prio(mb);

		STATIC_ASSERT(PMSG_P_COUNT == N_ITEMS(s));

		g_assert_log(prio < PMSG_P_COUNT,
			"%s(): prio=%u", G_STRFUNC, prio);

		udp_sched_log(5, "%p: sent mb=%p (%d bytes) prio=%u",
			us, mb, pmsg_size(mb), prio);

		pmsg_mark_sent(mb);
		gnet_stats_inc_general(s[prio]);

		if (cb->msg_account != NULL)
			(*cb->msg_account)(tx->owner, mb);

		inet_udp_record_sent(gnet_host_get_addr(to));
	}

	return TRUE;		/* Message sent */
}

/**
 * Send message (eslist iterator callback).
 *
 * @return TRUE if message was sent and freed up.
 */
static bool
udp_tx_desc_send(void *data, void *udata)
{
	struct udp_tx_desc *txd = data;
	udp_sched_t *us = udata;
	unsigned prio;

	udp_sched_check(us);
	udp_tx_desc_check(txd);

	if (us->used_all)
		return FALSE;

	/*
	 * Avoid flushing consecutive queued messages to the same destination,
	 * for regular (non-prioritary) messages.
	 *
	 * This serves two purposes:
	 *
	 * 1- It makes sure one single host does not capture all the available
	 *    outgoing bandwidth.
	 *
	 * 2- It somehow delays consecutive packets to a given host thereby reducing
	 *    flooding and hopefully avoiding saturation of its RX flow.
	 */

	prio = pmsg_prio(txd->mb);

	if (PMSG_P_DATA == prio && hset_contains(us->seen, txd->to)) {
		udp_sched_log(2, "%p: skipping mb=%p (%d bytes) to %s",
			us, txd->mb, pmsg_size(txd->mb), gnet_host_to_string(txd->to));
		return FALSE;
	}

	if (udp_sched_mb_sendto(us, txd->mb, txd->to, txd->tx, txd->cb)) {
		if (PMSG_P_DATA == prio && pmsg_was_sent(txd->mb))
			hset_insert(us->seen, atom_host_get(txd->to));
	} else {
		return FALSE;		/* Unsent, leave it in the queue */
	}

	us->buffered = size_saturate_sub(us->buffered, pmsg_size(txd->mb));
	udp_tx_desc_flag_release(txd, us);
	return TRUE;
}

/**
 * @return b/w per second configured for the attached b/w scheduler.
 */
static uint64
udp_sched_bw_per_second(const udp_sched_t *us)
{
	uint i;

	for (i = 0; i < N_ITEMS(us->bio); i++) {
		const bio_source_t *bio = us->bio[i];

		if (bio != NULL)
			return bio_bw_per_second(bio);
	}

	return 0;	/* No known I/O source, no bandwidth available */
}

/**
 * Send datagram.
 *
 * @param us		the UDP scheduler responsible for sending the datagram
 * @param mb		the message to send
 * @param to		the IP:port destination of the message
 * @param tx		the TX stack sending the message
 * @param cb		callback actions on the datagram
 *
 * @return 0 if message was unsent, length of message if sent, queued or
 * dropped.
 */
size_t
udp_sched_send(udp_sched_t *us, pmsg_t *mb, const gnet_host_t *to,
	const txdrv_t *tx, const struct tx_dgram_cb *cb)
{
	int len;
	struct udp_tx_desc *txd;
	uint prio;

	len = pmsg_size(mb);
	prio = pmsg_prio(mb);


	g_assert_log(prio < PMSG_P_COUNT,
		"%s(): prio=%u", G_STRFUNC, prio);

	/*
	 * Try to send immediately if we have bandwidth.
	 */

	if (!us->used_all && udp_sched_mb_sendto(us, mb, to, tx, cb)) {
		static gnr_stats_t s[] = {
			GNR_UDP_SCHED_DIRECTLY_SENT_PRIO_DATA,
			GNR_UDP_SCHED_DIRECTLY_SENT_PRIO_CONTROL,
			GNR_UDP_SCHED_DIRECTLY_SENT_PRIO_URGENT,
			GNR_UDP_SCHED_DIRECTLY_SENT_PRIO_HIGHEST,
		};

		STATIC_ASSERT(PMSG_P_COUNT == N_ITEMS(s));

		gnet_stats_inc_general(s[prio]);
		return len;		/*  Message "sent" */
	}

	/*
	 * If we already have enough data enqueued, flow-control the upper
	 * layer by acting as if we do not have enough bandwidth.
	 *
	 * However, we now always accept traffic sent with the highest priority
	 * since it is important to send those as soon as possible, i.e. ahead
	 * of any other pending data we would otherwise flush locally before
	 * servicing upper queues.
	 *		--RAM, 2012-10-12
	 */

	if (
		PMSG_P_HIGHEST != prio &&
		us->buffered >= UDP_SCHED_FACTOR * udp_sched_bw_per_second(us)
	) {
		static gnr_stats_t s[] = {
			GNR_UDP_SCHED_FLOW_CONTROLLED_PRIO_DATA,
			GNR_UDP_SCHED_FLOW_CONTROLLED_PRIO_CONTROL,
			GNR_UDP_SCHED_FLOW_CONTROLLED_PRIO_URGENT,
			GNR_UDP_SCHED_FLOW_CONTROLLED_PRIO_HIGHEST,	/* Cannot happen */
		};

		STATIC_ASSERT(PMSG_P_COUNT == N_ITEMS(s));

		gnet_stats_inc_general(s[prio]);
		udp_sched_log(1, "%p: flow-controlled", us);
		us->flow_controlled = TRUE;
		return 0;		/* Flow control upper layers */
	}

	/*
	 * Message is going to be enqueued.
	 *
	 * However, from the upper layers (the message queue in particular),
	 * the message is considered as being sent, and therefore these layers
	 * are going to call pmsg_free() on the message.
	 *
	 * We do not want to pmsg_clone() the message because that would render
	 * uses of pmsg_was_sent() useless in free routines, and upper layers
	 * would think the message was dropped if they installed a free routine
	 * on the message.
	 *
	 * Hence we use pmsg_ref().
	 */

	txd = palloc(us->txpool);
	ZERO(txd);
	txd->magic = UDP_TX_DESC_MAGIC;
	txd->mb = pmsg_ref(mb);		/* Take ownership of message */
	txd->to = atom_host_get(to);
	txd->tx = tx;
	txd->cb = cb;
	txd->expire = time_advance(tm_time(), UDP_SCHED_EXPIRE);

	udp_sched_log(4, "%p: queuing mb=%p (%d bytes) prio=%u",
		us, mb, pmsg_size(mb), pmsg_prio(mb));

	{
		static gnr_stats_t s[] = {
			GNR_UDP_SCHED_ENQUEUED_PRIO_DATA,
			GNR_UDP_SCHED_ENQUEUED_PRIO_CONTROL,
			GNR_UDP_SCHED_ENQUEUED_PRIO_URGENT,
			GNR_UDP_SCHED_ENQUEUED_PRIO_HIGHEST,
		};

		STATIC_ASSERT(PMSG_P_COUNT == N_ITEMS(s));

		gnet_stats_inc_general(s[prio]);
	}

	/*
	 * The queue used is a LIFO to avoid buffering delaying all the messages.
	 * Since UDP traffic is unordered, it's better to send the most recent
	 * datagrams first, to reduce the perceived average latency.
	 */

	g_assert(prio < N_ITEMS(us->lifo));
	eslist_prepend(&us->lifo[prio], txd);
	us->buffered = size_saturate_add(us->buffered, len);

	return len;		/* Message queued, but tell upper layers it's sent */
}

/**
 * Process LIFO queue, sending out messages until we have no more bandwidth.
 */
static void
udp_sched_process(udp_sched_t *us, eslist_t *list)
{
	udp_sched_check(us);

	eslist_foreach_remove(list, udp_tx_desc_send, us);
}

/**
 * Release host atom.
 */
static void
udp_seen_host_free(const void *data, void *udata)
{
	(void) udata;

	atom_host_free(data);
}

/**
 * Remove all entries in the "seen" hashed set.
 */
static void
udp_sched_seen_clear(udp_sched_t *us)
{
	udp_sched_check(us);

	hset_foreach(us->seen, udp_seen_host_free, NULL);
	hset_clear(us->seen);
}

/**
 * Reclaim all pending TX descriptors.
 */
static void
udp_sched_tx_release(udp_sched_t *us)
{
	udp_sched_check(us);

	/*
	 * During reclaiming of TX descriptors, unsent messages may be re-queued
	 * if upper layers see that an important message which has not been
	 * sent is being freed up.
	 *
	 * This is why this reclaiming must be done outside of the regular
	 * iterators that process the different LIFOs to avoid updating them
	 * whilst they are traversed.
	 */

	eslist_foreach_remove(&us->tx_released, udp_tx_desc_reclaim, us);
}

struct udp_service_ctx {
	int fd;
	inputevt_cond_t cond;
};

/**
 * Iterator callback to trigger TX stack servicing.
 */
static void
udp_sched_tx_service(void *data, void *udata)
{
	struct udp_tx_stack *uts = data;
	struct udp_service_ctx *ctx = udata;

	udp_sched_log(4, "servicing TX=%p", uts->tx);
	(*uts->writable)(deconstify_pointer(uts->tx), ctx->fd, ctx->cond);
	udp_sched_log(4, "done for TX=%p", uts->tx);
}

/**
 * @return amount of pending (buffered) data.
 */
size_t
udp_sched_pending(const udp_sched_t *us)
{
	udp_sched_check(us);

	return us->buffered;
}

/**
 * @return the I/O source used by the scheduler.
 */
bio_source_t *
udp_sched_bio_source(const udp_sched_t *us, enum net_type net)
{
	udp_sched_check(us);

	switch (net) {
	case NET_TYPE_IPV4:
		return us->bio[UDP_SCHED_IPv4];
	case NET_TYPE_IPV6:
		return us->bio[UDP_SCHED_IPv6];
	case NET_TYPE_NONE:
	case NET_TYPE_LOCAL:
		break;
	}

	g_assert_not_reached();
}

/**
 * Trigger TX stack servicing.
 */
static void
udp_sched_service(udp_sched_t *us, struct udp_service_ctx *ctx)
{
	udp_sched_check(us);

	udp_sched_log(4, "%p", us);

	/*
	 * We don't want to service the TX queues that attached to us in the same
	 * order to avoid nasty starving effects, hence rotate the list each time
	 * we service it.
	 */

	hash_list_rotate_left(us->stacks);
	hash_list_foreach(us->stacks, udp_sched_tx_service, ctx);
}

/**
 * Invoked each time a new bandwidth timeslice begins.
 */
static void
udp_sched_begin(void *data, int source, inputevt_cond_t cond)
{
	udp_sched_t *us = data;
	unsigned i;

	udp_sched_check(us);

	udp_sched_log(4, "%p: starting, %zu bytes buffered", us, us->buffered);
	udp_sched_log(5, "%p: messages queued: "
		"data=%zu, control=%zu, urgent=%zu, highest=%zu",
		us, eslist_count(&us->lifo[PMSG_P_DATA]),
		eslist_count(&us->lifo[PMSG_P_CONTROL]),
		eslist_count(&us->lifo[PMSG_P_URGENT]),
		eslist_count(&us->lifo[PMSG_P_HIGHEST]));

	/*
	 * Expire old traffic that we could not send.
	 */

	for (i = 0; i < N_ITEMS(us->lifo); i++) {
		eslist_foreach_remove(&us->lifo[i], udp_tx_desc_expired, us);
	}

	/*
	 * Schedule pending traffic in LIFO order (starting from head),
	 * processing the highest priority queue first.
	 */

	us->used_all = FALSE;

	do {
		udp_sched_seen_clear(us);
		for (i = N_ITEMS(us->lifo); i != 0 && !us->used_all; i--) {
			udp_sched_process(us, &us->lifo[i-1]);
		}
		udp_sched_tx_release(us);		/* May re-queue traffic */
		udp_sched_log(5, "%p: loop tail: %zu bytes buffered, b/w %s",
			us, us->buffered, us->used_all ? "gone" : "available");
	} while (!us->used_all && us->buffered != 0);

	/*
	 * If we did not use all the bandwidth yet and we flow-controlled
	 * upper layers, service them.
	 */

	if (!us->used_all && us->flow_controlled) {
		struct udp_service_ctx ctx;

		us->flow_controlled = FALSE;
		ctx.fd = source;
		ctx.cond = cond;
		udp_sched_service(us, &ctx);
	}

	udp_sched_log(4, "%p: done (b/w %s, %zu bytes buffered%s)",
		us, us->used_all ? "gone" : "available", us->buffered,
		us->flow_controlled ? ", flow-controlled" : "");
}

/**
 * Clear the socket-related information in the UDP scheduler.
 */
static void
udp_sched_clear_sockets(udp_sched_t *us)
{
	uint i;

	for (i = 0; i < N_ITEMS(us->bio); i++) {
		bio_source_t *bio = us->bio[i];

		if (bio != NULL) {
			bsched_source_remove(bio);
			us->bio[i] = NULL;
		}
	}
}

/**
 * Update the socket-related information in the UDP scheduler.
 */
void
udp_sched_update_sockets(udp_sched_t *us)
{
	uint i;
	bio_source_t *bio = NULL;

	udp_sched_clear_sockets(us);

	for (i = 0; i < N_ITEMS(us->bio); i++) {
		gnutella_socket_t *s = (*us->get_socket)(udp_sched_net_type[i]);

		if (s != NULL) {
			struct wrap_io *wio = &s->wio;

			wrap_io_check(wio);
			g_assert(wio->sendto != NULL);

			us->bio[i] = bsched_source_add(
				us->bws, wio, BIO_F_WRITE, NULL, NULL);

			if (NULL == bio)
				bio = us->bio[i];	/* Remember first I/O source seen */
		}
	}

	/*
	 * Make sure we are informed about the start of each bandwidth scheduling
	 * periods so that we may schedule data out and expire old data.
	 *
	 * We just need one of the IPv4 or IPv6 I/O source since they are linked
	 * to the same bandwidth scheduler.
	 */

	if (bio != NULL)
		bio_add_passive_callback(bio, udp_sched_begin, us);
}

/**
 * Creates a new UDP TX scheduling layer.
 *
 * The layer can be attached to multiple TX layers, which will then share
 * the same bandwidth limitation.  This is given by the "bws" parameter.
 *
 * The sockets are dynamically fetched, since the application can disable
 * them and recreate them depending on dynamic user reconfiguration.
 *
 * @param bws			the bandwidth scheduler used for output
 * @param get_socket	callback to get the UDP socket to write to
 *
 * @return a new scheduler.
 */
udp_sched_t *
udp_sched_make(
	bsched_bws_t bws, udp_sched_socket_cb_t get_socket)
{
	udp_sched_t *us;
	unsigned i;

	WALLOC0(us);
	us->magic = UDP_SCHED_MAGIC;
	us->txpool = pool_create("UDP TX descriptors", sizeof(struct udp_tx_desc),
		udp_tx_desc_alloc, udp_tx_desc_free, NULL);
	us->get_socket = get_socket;
	us->bws = bws;
	udp_sched_update_sockets(us);
	for (i = 0; i < N_ITEMS(us->lifo); i++) {
		eslist_init(&us->lifo[i], offsetof(struct udp_tx_desc, lnk));
	}
	eslist_init(&us->tx_released, offsetof(struct udp_tx_desc, lnk));
	us->seen =
		hset_create_any(gnet_host_hash, gnet_host_hash2, gnet_host_equal);
	us->stacks = hash_list_new(udp_tx_stack_hash, udp_tx_stack_eq);

	return us;
}

/**
 * Destroys the UDP TX scheduler, which must no longer be attached to anything.
 */
void
udp_sched_free(udp_sched_t *us)
{
	udp_sched_check(us);
	unsigned i;

	/*
	 * TX stacks are asynchronously collected, so we need to force collection
	 * now to make sure nobody references us any longer.
	 */

	tx_collect();

	g_assert(0 == hash_list_length(us->stacks));

	for (i = 0; i < N_ITEMS(us->lifo); i++) {
		udp_sched_drop_all(us, &us->lifo[i]);
	}
	udp_sched_tx_release(us);
	udp_sched_seen_clear(us);
	pool_free(us->txpool);
	hset_free_null(&us->seen);
	hash_list_free(&us->stacks);
	udp_sched_clear_sockets(us);

	us->magic = 0;
	WFREE(us);
}

/**
 * Attach a UDP TX scheduling layer to a TX stack.
 *
 * @param us			the UDP TX scheduler to use
 * @param tx			the TX driver attaching to the scheduler
 * @param writable		TX handler to invoke when we can write new data
 */
void
udp_sched_attach(udp_sched_t *us, const txdrv_t *tx,
	inputevt_handler_t writable)
{
	struct udp_tx_stack key, *uts;

	udp_sched_check(us);

	key.tx = tx;
	g_assert(!hash_list_contains(us->stacks, &key));

	WALLOC(uts);
	uts->tx = tx;
	uts->writable = writable;

	hash_list_append(us->stacks, uts);
}

/**
 * Detach a UDP TX scheduling layer from a TX stack.
 *
 * @param us			the UDP TX scheduler to detach from
 * @param tx			the TX driver detaching from the scheduler
 */
void
udp_sched_detach(udp_sched_t *us, const txdrv_t *tx)
{
	struct udp_tx_stack key, *uts;
	const void *oldkey;

	udp_sched_check(us);

	key.tx = tx;
	g_assert(hash_list_contains(us->stacks, &key));

	hash_list_find(us->stacks, &key, &oldkey);
	uts = deconstify_pointer(oldkey);
	hash_list_remove(us->stacks, uts);
	WFREE(uts);
}

/* vi: set ts=4 sw=4 cindent: */
