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
 * Out of band query hits.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "oob.h"
#include "ban.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hosts.h"
#include "mq.h"
#include "mq_udp.h"
#include "nodes.h"
#include "qhit.h"
#include "share.h"
#include "vmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fifo.h"
#include "lib/glib-missing.h"
#include "lib/hikset.h"
#include "lib/pmsg.h"
#include "lib/random.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define OOB_EXPIRE_MS		(2*60*1000)		/**< 2 minutes at most */
#define OOB_TIMEOUT_MS		(45*1000)		/**< 45 secs for them to reply */
#define OOB_DELIVER_BASE_MS	2500			/**< 1 msg queued every 2.5 secs */
#define OOB_DELIVER_RAND_MS	5000			/**< ... + up to 5 random secs */

#define OOB_MAX_QUEUED		50				/**< Max # of messages per host */
#define OOB_MAX_RETRY		3				/**< Retry # if LIME/12v2 dropped */

#define OOB_MAX_QHIT_SIZE	645			/**< Flush hits larger than this */
#define OOB_MAX_DQHIT_SIZE	1075		/**< Flush limit for deflated hits */
#define OOB_MAX_SRQHIT_SIZE	4096		/**< Flush limit for UDP SR hits */

typedef enum {
	OOB_RESULTS_MAGIC = 0x7ae5e685
} oob_results_magic_t;

/**
 * A set of hits awaiting delivery.
 */
struct oob_results {
	oob_results_magic_t	magic;
	int refcount;
	cevent_t *ev_expire;	/**< Global expiration event */
	cevent_t *ev_timeout;	/**< Reply waiting timeout */
	const struct guid *muid;/**< (atom) MUID of the query that generated hits */
	GSList *files;			/**< List of shared_file_t */
	gnet_host_t dest;		/**< The host to which we must deliver */
	int count;				/**< Amount of hits to deliver */
	int notify_requeued;	/**< Amount of LIME/12v2 requeued after dropping */
	unsigned flags;			/**< A combination of QHIT_F_* flags */
	unsigned secure:1;		/**< TRUE -> secure OOB, FALSE -> normal OOB */
	unsigned reliable:1;	/**< TRUE -> deliver through semi-reliable UDP */
};

/**
 * Indexes all OOB queries by MUID.
 * This hash table records MUID => "struct oob_results"
 */
static hikset_t *results_by_muid;

/**
 * Each servent, as identified by its IP:port, is given a FIFO for queuing
 * messages and sending them at a rate of 1 message every OOB_DELIVER_MS, to
 * avoid UDP flooding on the remote side.
 *
 * This hash table records gnet_host_t => "struct gservent"
 */
static hikset_t *servent_by_host = NULL;

/**
 * A servent entry, used as values in the `servent_by_host' table.
 */
struct gservent {
	cevent_t *ev_service; /**< Callout event for servicing FIFO */
	gnet_host_t *host;	  /**< The servent host (also used as key for table) */
	fifo_t *fifo;		  /**< The servent's FIFO, holding pmsg_t items */
	uint can_deflate:1;	  /**< Whether servent supports UDP compression */
	uint reliable:1;	  /**< Whether servent supports semi-reliable UDP */
};

/*
 * High-level description of what's happening here.
 *
 * When we get notified by share.c about a set of hits, we create the
 * struct oob_results, set the global expire to OOB_EXPIRE_MS and
 * send a LIME/12v2 to the querying, arming OOB_TIMEOUT_MS only AFTER
 * we get notified by the MQ that we sent the message.  If message was
 * dropped, requeue.  Do that OOB_MAX_RETRY times at most, then discard
 * the results.
 *
 * On reception of LIME/11v2, prepare all hits, put them in the FIFO
 * for this servent, then free the list.
 * Every OOB_DELIVER_MS, enqueue a hit to the UDP MQ for sending.
 */

static void results_destroy(cqueue_t *cq, void *obj);
static void servent_free(struct gservent *s);
static void oob_send_reply_ind(struct oob_results *r);

static int num_oob_records;	/**< Leak and duplicate free detector */
static bool oob_shutdowning;
static bool oob_shutdown_running;

static void
oob_results_check(const struct oob_results *r)
{
	g_assert(r);
	g_assert(OOB_RESULTS_MAGIC == r->magic);
	g_assert(r->refcount >= 0);
	g_assert(r->muid);
}

/**
 * Create new "struct oob_results" to handle the initial negotiation of
 * results delivery via the sent LIME/12v2 and the expected LIME/11v2 reply.
 */
static struct oob_results *
results_make(const struct guid *muid, GSList *files, int count,
	gnet_host_t *to, bool secure, bool reliable, unsigned flags)
{
	static const struct oob_results zero_results;
	struct oob_results *r;

	/*
	 * Check for duplicate queries bearing the same MUID.
	 *
	 * We used to soft-assert here, but since this condition actually triggers
	 * we explicitly check for it.
	 */

	if (hikset_contains(results_by_muid, muid))
		return NULL;

	/*
	 * First time we're seeing this query (normal case).
	 */

	WALLOC(r);
	*r = zero_results;
	r->magic = OOB_RESULTS_MAGIC;
	r->muid = atom_guid_get(muid);
	r->files = files;
	r->count = count;
	gnet_host_copy(&r->dest, to);
	r->secure = booleanize(secure);
	r->reliable = booleanize(reliable);
	r->flags = flags;

	r->ev_expire = cq_main_insert(OOB_EXPIRE_MS, results_destroy, r);
	r->refcount++;

	hikset_insert_key(results_by_muid, &r->muid);

	g_assert(num_oob_records >= 0);
	num_oob_records++;
	if (GNET_PROPERTY(query_debug) > 1)
		g_debug("%s(): num_oob_records=%d", G_STRFUNC, num_oob_records);

	return r;
}

/**
 * Dispose of results.
 */
static void
results_free_remove(struct oob_results *r)
{
	GSList *sl;

	oob_results_check(r);
	
	if (r->ev_expire) {
		cq_cancel(&r->ev_expire);
		g_assert(r->refcount > 0);
		r->refcount--;
	}
	if (r->ev_timeout) {
		cq_cancel(&r->ev_timeout);
		g_assert(r->refcount > 0);
		r->refcount--;
	}

	if (0 == r->refcount) {
		/* We must not modify the hash table whilst iterating over it */
		if (!oob_shutdown_running) {
			g_assert(r == hikset_lookup(results_by_muid, r->muid));
			hikset_remove(results_by_muid, r->muid);
		}
		atom_guid_free_null(&r->muid);

		for (sl = r->files; sl; sl = g_slist_next(sl)) {
			shared_file_t *sf = sl->data;
			shared_file_unref(&sf);
		}
		gm_slist_free_null(&r->files);

		g_assert(num_oob_records > 0);
		num_oob_records--;
		if (GNET_PROPERTY(query_debug) > 2)
			g_debug("results_free: num_oob_records=%d", num_oob_records);

		r->magic = 0;
		WFREE(r);
	}
}

/**
 * Callout queue callback to free the results when the time allocated for the
 * querying party to claim all the results has expired.
 */
static void
results_destroy(cqueue_t *unused_cq, void *obj)
{
	struct oob_results *r = obj;

	(void) unused_cq;
	oob_results_check(r);

	if (GNET_PROPERTY(query_debug))
		g_debug("OOB query #%s from %s expired with unclaimed %d hit%s",
			guid_hex_str(r->muid), gnet_host_to_string(&r->dest),
			r->count, r->count == 1 ? "" : "s");

	gnet_stats_inc_general(GNR_UNCLAIMED_OOB_HITS);

	r->ev_expire = NULL;		/* The timer which just triggered */
	r->refcount--;

	results_free_remove(r);
}

/**
 * Callout queue callback to free the results when our initial notification
 * was not acknowledged with claims.
 */
static void
results_timeout(cqueue_t *unused_cq, void *obj)
{
	struct oob_results *r = obj;
	host_addr_t addr;

	(void) unused_cq;
	oob_results_check(r);

	addr = gnet_host_get_addr(&r->dest);

	if (GNET_PROPERTY(query_debug)) {
		g_debug("OOB query #%s, no ACK from %s to claim %d hit%s",
			guid_hex_str(r->muid), gnet_host_to_string(&r->dest),
			r->count, r->count == 1 ? "" : "s");
	}

	gnet_stats_inc_general(GNR_UNCLAIMED_OOB_HITS);
	
	/*
	 * Record an "event" that the OOB results went unclaimed.
	 *
	 * After too many unclaimed results, the IP address will be banned
	 * for OOB query processing.
	 */

	if (BAN_OK != ban_allow(BAN_CAT_OOB_CLAIM, addr)) {
		if (GNET_PROPERTY(query_debug)) {
			int delay = ban_delay(BAN_CAT_OOB_CLAIM, addr);
			g_debug("OOB host %s will be banned for the next %d second%s",
				host_addr_to_string(addr), delay, 1 == delay ? "" : "s");
		}
	}

	r->ev_timeout = NULL;		/* The timer which just triggered */
	r->refcount--;

	results_free_remove(r);
}

/**
 * Dispose of servent, removing entry from the `servent_by_host' table.
 */
static void
servent_free_remove(struct gservent *s)
{
	hikset_remove(servent_by_host, s->host);
	servent_free(s);
}

/**
 * Computes the amount of milliseconds before the next OOB hit delivery,
 *
 * Per a suggestion of Daniel Stutzbach, we wait BASE + RAND*random secs,
 * where "random" is a real random number between 0 and 1.
 */
static int
deliver_delay(void)
{
	return OOB_DELIVER_BASE_MS + random_value(OOB_DELIVER_RAND_MS);
}

/**
 * Service servent's FIFO: send next packet, and re-arm servicing callback
 * if there are more data to send.
 */
static void
servent_service(cqueue_t *cq, void *obj)
{
	struct gservent *s = obj;
	pmsg_t *mb;
	mqueue_t *q;
	enum net_type nt;

	s->ev_service = NULL;		/* The callback that just triggered */

	mb = fifo_remove(s->fifo);
	if (mb == NULL)
		goto remove;

	nt = host_addr_net(gnet_host_get_addr(s->host));
	q = s->reliable ? node_udp_sr_get_outq(nt) : node_udp_get_outq(nt);
	if (q == NULL)
		goto udp_disabled;

	if (GNET_PROPERTY(udp_debug) > 19)
		g_debug("UDP queuing OOB %s to %s for #%s",
			gmsg_infostr_full(pmsg_start(mb), pmsg_written_size(mb)),
			gnet_host_to_string(s->host),
			guid_hex_str(cast_to_guid_ptr_const(pmsg_start(mb))));

	/*
	 * Count enqueued deflated payloads, only when server was marked as
	 * supporting compression anyway...
	 */

	if (s->can_deflate) {
		if (gnutella_header_get_ttl(pmsg_start(mb)) & GTA_UDP_DEFLATED)
			gnet_stats_inc_general(GNR_UDP_TX_COMPRESSED);
	}

	mq_udp_putq(q, mb, s->host);

	if (0 == fifo_count(s->fifo))
		goto remove;

	s->ev_service = cq_insert(cq, deliver_delay(), servent_service, s);

	return;

udp_disabled:
	pmsg_free(mb);
	/* FALL THROUGH */

remove:
	servent_free_remove(s);
}

/**
 * Create a new servent structure.
 *
 * @param host the servent's IP:port.  Caller may free it upon return.
 */
static struct gservent *
servent_make(gnet_host_t *host, bool can_deflate, bool reliable)
{
	struct gservent *s;

	WALLOC(s);
	s->host = gnet_host_dup(host);
	s->fifo = fifo_make();
	s->ev_service = NULL;
	s->can_deflate = booleanize(can_deflate);
	s->reliable = booleanize(reliable);

	return s;
}

/**
 * Cleanup items from FIFO.
 * -- fifo_free_all() callback.
 */
static void
free_pmsg(void *item, void *unused_udata)
{
	pmsg_t *mb = item;

	(void) unused_udata;
	pmsg_free(mb);
}

/**
 * Free servent structure.
 */
static void
servent_free(struct gservent *s)
{
	cq_cancel(&s->ev_service);
	gnet_host_free(s->host);
	fifo_free_all(s->fifo, free_pmsg, NULL);
	WFREE(s);
}

/**
 * Invoked via qhit_build_results() for each fully built query hit message.
 * Hit is enqueued in the FIFO, for slow delivery.
 */
static void
oob_record_hit(void *data, size_t len, void *udata)
{
	struct gservent *s = udata;
	pmsg_t *mb;

	g_assert(len <= INT_MAX);

	/*
	 * We don't deflate if sending the hits through the semi-reliable UDP
	 * layer since it will transparently compress for us.
	 */

	mb = (s->can_deflate && !s->reliable) ?
		gmsg_to_deflated_pmsg(data, len) : gmsg_to_pmsg(data, len);

	if (s->reliable)
		pmsg_mark_reliable(mb);

	fifo_put(s->fifo, mb);
}

/**
 * The remote host acknowledges that we have some hits for it and wishes
 * to get the specified amount.
 *
 * @param n			where we got the message from
 * @param muid		the query identifier
 * @param wanted	the amount of results they want delivered
 * @param token		the token for secure OOB
 */
void
oob_deliver_hits(struct gnutella_node *n, const struct guid *muid,
	uint8 wanted, const struct array *token)
{
	struct oob_results *r;
	struct gservent *s;
	int deliver_count;
	bool servent_created = FALSE;

	g_assert(NODE_IS_UDP(n));
	g_assert(token);

	if G_UNLIKELY(oob_shutdowning)
		return;

	r = hikset_lookup(results_by_muid, muid);

	if (r == NULL) {
		gnet_stats_inc_general(GNR_SPURIOUS_OOB_HIT_CLAIM);
		if (GNET_PROPERTY(query_debug))
			g_warning("OOB got spurious LIME/11 from %s for #%s, "
				"asking for %d hit%s",
				node_addr(n), guid_hex_str(muid),
				wanted, wanted == 1 ? "" : "s");
		return;
	}

	oob_results_check(r);

	/*
	 * Here's what could happen with proxied OOB queries:
	 *
	 *                 query               query
	 *      Queryier  ------> Proxying UP -------> Server
	 *               <--TCP--             <--UDP--
	 *               GTKG/12v2            LIME/12v2
	 *
	 *                        LIME/11v2
	 *      Queryier ------------UDP------------> Server
	 *               <-----------UDP-------------
	 *                        query hits
	 *
	 * The above forwarding by the Proxying UP can only be done when
	 * the server has mentionned that it could receive unsolicited UDP
	 * in its LIME/12v2 message.
	 *
	 * This means that we MUST not reply to the IP:port held in the
	 * GUID of the message, but really to the origin of the LIME/11v2
	 * message.
	 *
	 *		--RAM, 2004-09-10
	 */

	if (!host_addr_equal(n->addr, gnet_host_get_addr(&r->dest))) {
		/**
		 * The sender's IP address can of course change any time as
		 * dynamic IP addresses are very common. The sender might also
		 * have multiple network interfaces.
		 */
		
		g_warning("OOB query #%s might have been proxied: it had IP %s, "
			"but the LIME/11v2 ACK comes from %s", guid_hex_str(muid),
			gnet_host_to_string(&r->dest), node_addr(n));

		/*
		 * We'll send the hits to the host from where the ACK comes.
		 */

		gnet_host_set(&r->dest, n->addr, n->port);
	}

	/*
	 * Fetch the proper servent, create one if none exists yet.
	 *
	 * N.B: We assume that for a given host address, UDP deflation support
	 * will never change: if the host has marked support for deflation in
	 * the claim message once, we assume that it will always support it.
	 * Likewise, if it did not request it the first time, no matter what we
	 * get next, we will never deflate hits for this OOB delivery.
	 *		--RAM, 2006-08-13
	 *
	 * Likewise, we assume that semi-reliable UDP support will not vary
	 * over time for a given servent address, from query to query, during
	 * the lifetime of the server record here (kept around until we no longer
	 * have any pending hit to deliver, from any query).
	 *		--RAM, 2012-10-08
	 */

	s = hikset_lookup(servent_by_host, &r->dest);
	if (s == NULL) {
		bool can_deflate = NODE_CAN_INFLATE(n);	/* Can we deflate? */
		s = servent_make(&r->dest, can_deflate, r->reliable);
		hikset_insert_key(servent_by_host, &s->host);
		servent_created = TRUE;
	}

	g_assert(servent_created || s->ev_service != NULL);

	/*
	 * Build the query hits, enqueuing them to the servent's FIFO.
	 */

	deliver_count = (wanted == 255) ? r->count : MIN(wanted, r->count);

	if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(udp_debug)) {
		g_debug("OOB query #%s: host %s wants %d hit%s, delivering %d",
			guid_hex_str(r->muid), node_addr(n), wanted, wanted == 1 ? "" : "s",
			deliver_count);
	}

	if (deliver_count) {
		qhit_build_results(
			r->files, deliver_count,
			r->reliable ? OOB_MAX_SRQHIT_SIZE :
			s->can_deflate ? OOB_MAX_DQHIT_SIZE : OOB_MAX_QHIT_SIZE,
			oob_record_hit, s, r->muid, r->flags, token);
	}

	if (wanted < r->count)
		gnet_stats_inc_general(GNR_PARTIALLY_CLAIMED_OOB_HITS);

	/*
	 * We're now done with the "oob_results" structure, since all the
	 * to-be-delivered hits have been queued as Gnutella messages in
	 * the servent's FIFO.
	 */

	results_free_remove(r);

	/*
	 * If we just created a new servent entry, service it to send a
	 * first query hit.  Otherwise, we already have a callback installed
	 * for servicing it at regular interval.
	 */

	if (servent_created)
		servent_service(cq_main(), s);
}

/**
 * Callback invoked when the LIME/12v2 message we queued is freed.
 */
static void
oob_pmsg_free(pmsg_t *mb, void *arg)
{
	struct oob_results *r = arg;

	g_assert(pmsg_is_extended(mb));
	oob_results_check(r);
	r->refcount--;

	/*
	 * If we sent the message, great!  Arm a timer to ensure we get a
	 * reply within the next OOB_TIMEOUT_MS.
	 */

	if (pmsg_was_sent(mb)) {

		/* There may have been up to OOB_MAX_RETRY in the queue, ``r''
		 * is shared between all of them. So r->ev_timeout may have been
		 * set already.
		 */
		if (r->ev_timeout) {
			results_free_remove(r);
		} else {

			if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(udp_debug))
				g_debug("OOB query #%s, notified %s about %d hit%s",
					guid_hex_str(r->muid), gnet_host_to_string(&r->dest),
					r->count, r->count == 1 ? "" : "s");

			/*
			 * If we don't get any ACK back, we'll discard the results.
			 */

			r->ev_timeout = cq_main_insert(OOB_TIMEOUT_MS, results_timeout, r);
			r->refcount++;
		}
	} else {
		/*
		 * If we were not able to send the message: when we use plain UDP,
		 * we retry, but with semi-reliable UDP we trust the network layer to
		 * do the appropriate amount of retrying and a failure is definitive.
		 */

		if (GNET_PROPERTY(query_debug)) {
			g_debug("OOB query #%s, previous LIME12/v2 #%d was %s",
				guid_hex_str(r->muid), r->notify_requeued,
				r->reliable ? "unsent" : "dropped");
		}

		if (!r->reliable && ++r->notify_requeued < OOB_MAX_RETRY)
			oob_send_reply_ind(r);
		else
			results_free_remove(r);
	}
}

/**
 * Send them a LIME/12v2, monitoring progress in queue via a callback.
 */
static void
oob_send_reply_ind(struct oob_results *r)
{
	mqueue_t *q;
	pmsg_t *mb;
	pmsg_t *emb;
	enum net_type nt;

	oob_results_check(r);

	nt = host_addr_net(gnet_host_get_addr(&r->dest));
	q = r->reliable ? node_udp_sr_get_outq(nt) : node_udp_get_outq(nt);
	if (q == NULL)
		return;

	mb = vmsg_build_oob_reply_ind(r->muid, MIN(r->count, 255), r->secure);
	emb = pmsg_clone_extend(mb, oob_pmsg_free, r);
	if (r->reliable)
		pmsg_mark_reliable(emb);
	r->refcount++;
	pmsg_free(mb);

	if (GNET_PROPERTY(query_debug) || GNET_PROPERTY(udp_debug))
		g_debug("OOB query #%s, %snotifying %s about %d hit%s, try #%d",
			guid_hex_str(r->muid), r->reliable ? "reliably " : "",
			gnet_host_to_string(&r->dest),
			r->count, r->count == 1 ? "" : "s", r->notify_requeued);

	mq_udp_putq(q, emb, &r->dest);
}

/**
 * Notification that we got matches for a query from some node that needs
 * to be replied to using out-of-band delivery.
 *
 * @param n				the node from which we got the query
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results
 * @param addr			address where we must send the OOB result indication
 * @param port			port where we must send the OOB result indication
 * @param secure		whether secure OOB was requested
 * @param reliable		whether reliable UDP should be used
 * @param flags			a combination of QHIT_F_* flags
 */
void
oob_got_results(struct gnutella_node *n, GSList *files,
	int count, host_addr_t addr, uint16 port,
	bool secure, bool reliable, unsigned flags)
{
	struct oob_results *r;
	gnet_host_t to;
	const guid_t *muid;

	g_assert(count > 0);
	g_assert(files != NULL);

	gnet_host_set(&to, addr, port);
	muid = gnutella_header_get_muid(&n->header);
	r = results_make(muid, files, count, &to, secure, reliable, flags);
	if (r != NULL) {
		oob_send_reply_ind(r);
	} else {
		g_warning("%s(): ignoring duplicate %s%sOOB query %s from %s via %s",
			G_STRFUNC, secure ? "secure " : "", reliable ? "reliable " : "",
			guid_to_string(muid),
			gnet_host_to_string(&to), node_infostr(n));
	}
}

/**
 * Initialize out-of-band query hit delivery.
 */
G_GNUC_COLD void
oob_init(void)
{
	results_by_muid = hikset_create(
		offsetof(struct oob_results, muid), HASH_KEY_FIXED, GUID_RAW_SIZE);
	servent_by_host = hikset_create_any(
		offsetof(struct gservent, host), gnet_host_hash, gnet_host_eq);
}

/**
 * Cleanup oob_results -- hash table iterator callback
 */
G_GNUC_COLD static void
free_oob_kv(void *value, void *unused_udata)
{
	struct oob_results *r = value;

	(void) unused_udata;
	oob_results_check(r);

	r->refcount = 0; /* Enforce release */
	if (r->ev_timeout) {
		r->refcount++;
	}
	if (r->ev_expire) {
		r->refcount++;
	}
	results_free_remove(r);
}

/**
 * Cleanup servent -- hash table iterator callback
 */
static void
free_servent_kv(void *value, void *unused_udata)
{
	struct gservent *s = value;

	(void) unused_udata;

	servent_free(s);
}

/**
 * Cleanup at shutdown time.
 */
G_GNUC_COLD void
oob_shutdown(void)
{
	oob_shutdowning = TRUE;

	if (GNET_PROPERTY(search_debug)) {
		g_info("OOB %s: still has %zu entr%s by MUID, %zu host%s recorded",
			G_STRFUNC, hikset_count(results_by_muid),
			1 == hikset_count(results_by_muid) ? "y" : "ies",
			hikset_count(servent_by_host),
			1 == hikset_count(servent_by_host) ? "" : "s");
	}
}

/**
 * Final cleanup.
 */
G_GNUC_COLD void
oob_close(void)
{
	oob_shutdown_running = TRUE;

	hikset_foreach(results_by_muid, free_oob_kv, NULL);
	hikset_free_null(&results_by_muid);

	hikset_foreach(servent_by_host, free_servent_kv, NULL);
	hikset_free_null(&servent_by_host);

	g_assert(num_oob_records >= 0);
	if (num_oob_records > 0)
		g_warning("%d OOB reply records possibly leaked", num_oob_records);
}

/* vi: set ts=4 sw=4 cindent: */
