/*
 * $Id$
 *
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
 * @file
 *
 * Out of band query hits.
 */

#include "common.h"

RCSID("$Id$");

#include "oob.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h"
#include "guid.h"
#include "pmsg.h"
#include "mq.h"
#include "mq_udp.h"
#include "vmsg.h"
#include "qhit.h"
#include "gmsg.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/fifo.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define OOB_EXPIRE_MS		(2*60*1000)		/* 2 minutes at most */
#define OOB_TIMEOUT_MS		(45*1000)		/* 45 secs for them to reply */
#define OOB_DELIVER_MS		(5*1000)		/* 1 message queued every 5 secs */

#define OOB_MAX_QUEUED		50				/* Max # of messages per host */
#define OOB_MAX_RETRY		3				/* Retry # if LIME/12v2 dropped */

/*
 * A set of hits awaiting delivery.
 */
struct oob_results {
	gchar *muid;			/* (atom) MUID of the query that generated hits */
	GSList *files;			/* List of shared_file_t */
	gint count;				/* Amount of hits to deliver */
	gnet_host_t dest;		/* The host to which we must deliver */
	gint notify_requeued;	/* Amount of LIME/12v2 requeued after dropping */
	gpointer ev_expire;		/* Global expiration event */
	gpointer ev_timeout;	/* Reply waiting timeout */
	gboolean use_ggep_h;	/* Whether GGEP "H" can be used for SHA1 coding */
};

/*
 * Indexes all OOB queries by MUID.
 * This hash table records MUID => "struct oob_results"
 */
static GHashTable *results_by_muid = NULL;

/*
 * Each servent, as identified by its IP:port, is given a FIFO for queuing
 * messages and sending them at a rate of 1 message every OOB_DELIVER_MS, to
 * avoid UDP flooding on the remote side.
 *
 * This hash table records gnet_host_t => "struct servent"
 */
static GHashTable *servent_by_host = NULL;

/*
 * A servent entry, used as values in the `servent_by_host' table.
 */
struct servent {
	gpointer ev_service;	/* Callout event for servicing FIFO */
	gnet_host_t *host;		/* The servent host (also used as key for table) */
	fifo_t *fifo;			/* The servent's FIFO, holding pmsg_t items */
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

static void results_destroy(cqueue_t *cq, gpointer obj);
static void servent_free(struct servent *s);
static void oob_send_reply_ind(struct oob_results *r);

/**
 * Create new "struct oob_results" to handle the initial negotiation of
 * results delivery via the sent LIME/12v2 and the expected LIME/11v2 reply.
 */
static struct oob_results *
results_make(
	gchar *muid, GSList *files, gint count, gnet_host_t *to, gboolean ggep_h)
{
	struct oob_results *r;

	r = walloc0(sizeof(*r));
	r->muid = atom_guid_get(muid);
	r->files = files;
	r->count = count;
	r->dest = *to;			/* Struct copy */
	r->use_ggep_h = ggep_h;

	r->ev_expire = cq_insert(callout_queue, OOB_EXPIRE_MS, results_destroy, r);

	return r;
}

/**
 * Dispose of results.
 */
static void
results_free(struct oob_results *r)
{
	GSList *sl;

	atom_guid_free(r->muid);
	if (r->ev_expire)
		cq_cancel(callout_queue, r->ev_expire);
	if (r->ev_timeout)
		cq_cancel(callout_queue, r->ev_timeout);

	for (sl = r->files; sl; sl = g_slist_next(sl)) {
		shared_file_t *sf = (shared_file_t *) sl->data;
		shared_file_unref(sf);
	}
	g_slist_free(r->files);

	wfree(r, sizeof(*r));
}

/**
 * Dispose of results, removing entry from the `results_by_muid' table.
 */
static void
results_free_remove(struct oob_results *r)
{
	g_hash_table_remove(results_by_muid, r->muid);
	results_free(r);
}

/**
 * Callout queue callback to free the results.
 */
static void
results_destroy(cqueue_t *cq, gpointer obj)
{
	struct oob_results *r = (struct oob_results *) obj;

	if (query_debug)
		printf("OOB query %s from %s expired with unclaimed %d hit%s\n",
			guid_hex_str(r->muid), ip_port_to_gchar(r->dest.ip, r->dest.port),
			r->count, r->count == 1 ? "" : "s");

	r->ev_expire = NULL;		/* The timer which just triggered */
	results_free_remove(r);
}

/**
 * Callout queue callback to free the results.
 */
static void
results_timeout(cqueue_t *cq, gpointer obj)
{
	struct oob_results *r = (struct oob_results *) obj;

	if (query_debug)
		printf("OOB query %s, no ACK from %s to claim %d hit%s\n",
			guid_hex_str(r->muid), ip_port_to_gchar(r->dest.ip, r->dest.port),
			r->count, r->count == 1 ? "" : "s");

	r->ev_timeout = NULL;		/* The timer which just triggered */
	results_free_remove(r);
}

/**
 * Dispose of servent, removing entry from the `servent_by_host' table.
 */
static void
servent_free_remove(struct servent *s)
{
	g_hash_table_remove(servent_by_host, s->host);
	servent_free(s);
}

/**
 * Service servent's FIFO: send next packet, and re-arm servicing callback
 * if there are more data to send.
 */
static void
servent_service(cqueue_t *cq, gpointer obj)
{
	struct servent *s = (struct servent *) obj;
	pmsg_t *mb;
	mqueue_t *q;

	s->ev_service = NULL;		/* The callback that just triggered */

	mb = (pmsg_t *) fifo_remove(s->fifo);
	if (mb == NULL)
		goto remove;

	q = node_udp_get_outq();
	if (q == NULL)
		goto udp_disabled;

	if (udp_debug > 19)
		printf("UDP queuing OOB %s to %s for %s\n",
			gmsg_infostr_full(pmsg_start(mb)),
			ip_port_to_gchar(s->host->ip, s->host->port),
			guid_hex_str(pmsg_start(mb)));

	mq_udp_putq(q, mb, s->host);

	if (0 == fifo_count(s->fifo))
		goto remove;

	s->ev_service = cq_insert(cq, OOB_DELIVER_MS, servent_service, s);

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
static struct servent *
servent_make(gnet_host_t *host)
{
	struct servent *s;

	s = walloc(sizeof(*s));
	s->host = walloc(sizeof(gnet_host_t));
	*s->host = *host;		/* Struct copy */
	s->fifo = fifo_make();
	s->ev_service = NULL;

	return s;
}

/**
 * Cleanup items from FIFO.
 * -- fifo_free_all() callback.
 */
static void
free_pmsg(gpointer item, gpointer udata)
{
	pmsg_t *mb = (pmsg_t *) item;

	pmsg_free(mb);
}

/**
 * Free servent structure.
 */
static void
servent_free(struct servent *s)
{
	if (s->ev_service)
		cq_cancel(callout_queue, s->ev_service);
	wfree(s->host, sizeof(gnet_host_t));
	fifo_free_all(s->fifo, free_pmsg, NULL);
	wfree(s, sizeof(*s));
}

/**
 * Invoked via qhit_build_results() for each fully built query hit message.
 * Hit is enqueued in the FIFO, for slow delivery.
 */
static void
oob_record_hit(gpointer data, gint len, gpointer udata)
{
	struct servent *s = (struct servent *) udata;

	fifo_put(s->fifo, gmsg_to_pmsg(data, len));
}

/**
 * The remote host acknowledges that we have some hits for it and wishes
 * to get the specified amount.
 *
 * @param n			where we got the message from
 * @param muid		the query identifier
 * @param wanted	the amount of results they want delivered
 */
void
oob_deliver_hits(struct gnutella_node *n, gchar *muid, guint8 wanted)
{
	struct oob_results *r;
	struct servent *s;
	gint deliver_count;
	gboolean servent_created = FALSE;

	g_assert(NODE_IS_UDP(n));

	r = g_hash_table_lookup(results_by_muid, muid);

	if (r == NULL) {
		if (query_debug)
			printf("OOB got spurious LIME/11 from %s for %s, "
				"asking for %d hit%s\n",
				node_ip(n), guid_hex_str(muid), wanted, wanted == 1 ? "" : "s");
		return;
	}

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

	if (n->ip != r->dest.ip) {
		g_warning("OOB query %s must have been proxied: it had IP %s, "
			"but the LIME/11v2 ACK comes from %s",
			guid_hex_str(muid), ip_to_gchar(r->dest.ip), node_ip(n));

		/*
		 * We'll send the hits to the host from where the ACK comes.
		 */

		r->dest.ip = n->ip;
		r->dest.port = n->port;
	}

	/*
	 * Fetch the proper servent, create one if none exists yet.
	 */

	s = g_hash_table_lookup(servent_by_host, &r->dest);
	if (s == NULL) {
		s = servent_make(&r->dest);
		g_hash_table_insert(servent_by_host, s->host, s);
		servent_created = TRUE;
	}

	g_assert(servent_created || s->ev_service != NULL);

	/*
	 * Build the query hits, enqueuing them to the servent's FIFO.
	 */

	deliver_count = (wanted == 255) ? r->count : MIN(wanted, r->count);

	if (query_debug || udp_debug)
		printf("OOB query %s: host %s wants %d hit%s, delivering %d\n",
			guid_hex_str(r->muid), node_ip(n), wanted, wanted == 1 ? "" : "s",
			deliver_count);

	if (deliver_count)
		qhit_build_results(oob_record_hit, s,
			r->muid, r->files, deliver_count, r->use_ggep_h);

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
		servent_service(callout_queue, s);
}

/**
 * Callback invoked when the LIME/12v2 message we queued is freed.
 */
static void
oob_pmsg_free(pmsg_t *mb, gpointer arg)
{
	struct oob_results *r = (struct oob_results *) arg;

	g_assert(pmsg_is_extended(mb));

	/*
	 * If we sent the message, great!  Arm a timer to ensure we get a
	 * reply within the next OOB_TIMEOUT_MS.
	 */

	if (pmsg_was_sent(mb)) {
		g_assert(r->ev_timeout == NULL);

		if (query_debug || udp_debug)
			printf("OOB query %s, notified %s about %d hit%s\n",
				guid_hex_str(r->muid),
				ip_port_to_gchar(r->dest.ip, r->dest.port), r->count,
				r->count == 1 ? "" : "s");

		/*
		 * If we don't get any ACK back, we'll discard the results.
		 */

		r->ev_timeout = cq_insert(callout_queue, OOB_TIMEOUT_MS,
			results_timeout, r);

		return;
	}

	/*
	 * If we were not able to send the message,
	 */

	if (query_debug)
		printf("OOB query %s, previous LIME12/v2 #%d was dropped\n",
			guid_hex_str(r->muid), r->notify_requeued);

	if (++r->notify_requeued < OOB_MAX_RETRY)
		oob_send_reply_ind(r);
	else
		results_free_remove(r);
}

/**
 * Send them a LIME/12v2, monitoring progress in queue via a callback.
 */
static void
oob_send_reply_ind(struct oob_results *r)
{
	pmsg_t *mb;
	pmsg_t *emb;

	mb = vmsg_build_oob_reply_ind(r->muid, MIN(r->count, 255));
	emb = pmsg_clone_extend(mb, oob_pmsg_free, r);
	pmsg_free(mb);

	if (query_debug || udp_debug)
		printf("OOB query %s, notifying %s about %d hit%s, try #%d\n",
			guid_hex_str(r->muid), ip_port_to_gchar(r->dest.ip, r->dest.port),
			r->count, r->count == 1 ? "" : "s", r->notify_requeued);

	mq_udp_putq(node_udp_get_outq(), emb, &r->dest);
}

/**
 * Notification that we got matches for a query from some node that needs
 * to be replied to using out-of-band delivery.
 *
 * @param n				the node from which we got the query
 * @param files			the list of shared_file_t entries that make up results
 * @param count			the amount of results
 * @param use_ggep_h	whether GGEP "H" can be used to send the SHA1 of files
 */
void
oob_got_results(
	struct gnutella_node *n, GSList *files, gint count, gboolean use_ggep_h)
{
	struct oob_results *r;
	gnet_host_t to;
	guint32 ip;
	guint16 port;

	g_assert(count > 0);
	g_assert(files != NULL);

	guid_oob_get_ip_port(n->header.muid, &ip, &port);

	to.ip = ip;
	to.port = port;

	r = results_make(n->header.muid, files, count, &to, use_ggep_h);
	g_hash_table_insert(results_by_muid, r->muid, r);

	oob_send_reply_ind(r);
}

/**
 * Initialize out-of-band query hit delivery.
 */
void
oob_init(void)
{
	extern guint guid_hash(gconstpointer key);		/* from lib/atoms.c */
	extern gint guid_eq(gconstpointer a, gconstpointer b);

	results_by_muid = g_hash_table_new(guid_hash, guid_eq);
	servent_by_host = g_hash_table_new(host_hash, host_eq);
}

/**
 * Cleanup oob_results -- hash table iterator callback
 */
static void
free_oob_kv(gpointer key, gpointer value, gpointer udata)
{
	gchar *muid = (gchar *) key;
	struct oob_results *r = (struct oob_results *) value;

	g_assert(muid == r->muid);		/* Key is same as results's MUID */

	results_free(r);
}

/**
 * Cleanup servent -- hash table iterator callback
 */
static void
free_servent_kv(gpointer key, gpointer value, gpointer udata)
{
	gnet_host_t *host = (gnet_host_t *) key;
	struct servent *s = (struct servent *) value;

	g_assert(host == s->host);		/* Key is same as servent's host */

	servent_free(s);
}

/**
 * Cleanup at shutdown time.
 */
void
oob_close(void)
{
	g_hash_table_foreach(results_by_muid, free_oob_kv, NULL);
	g_hash_table_destroy(results_by_muid);

	g_hash_table_foreach(servent_by_host, free_servent_kv, NULL);
	g_hash_table_destroy(servent_by_host);
}

