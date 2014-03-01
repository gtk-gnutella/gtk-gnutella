/*
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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
 * Handles upload of our files to others users.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 */

#include "common.h"

#include "gtk-gnutella.h"

#include "ban.h"
#include "bh_upload.h"
#include "bsched.h"
#include "dmesh.h"
#include "features.h"
#include "geo_ip.h"
#include "ggep.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "hosts.h"		/* for check_valid_host() */
#include "http.h"
#include "huge.h"
#include "ignore.h"
#include "inet.h"		/* For INET_IP_V6READY */
#include "ioheader.h"
#include "nodes.h"
#include "parq.h"
#include "settings.h"
#include "search.h"		/* for QUERY_FW2FW_FILE_INDEX */
#include "share.h"
#include "sockets.h"
#include "spam.h"
#include "thex_upload.h"
#include "tth_cache.h"
#include "ipp_cache.h"
#include "tx_deflate.h"
#include "tx_link.h"		/* for callback structures */
#include "upload_stats.h"
#include "uploads.h"
#include "verify_tth.h"
#include "version.h"
#include "gnet_stats.h"
#include "ctl.h"

#include "g2/tree.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"
#include "if/dht/dht.h"		/* For dht_enabled() */

#include "lib/aging.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/crc.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/header.h"
#include "lib/htable.h"
#include "lib/http_range.h"
#include "lib/idtable.h"
#include "lib/iso3166.h"
#include "lib/listener.h"
#include "lib/parse.h"
#include "lib/product.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/vmm.h"
#include "lib/walloc.h"
#include "lib/wd.h"

#include "lib/override.h"	/* Must be the last header included */

#define READ_BUF_SIZE	(64 * 1024)	/**< Read buffer size, if no sendfile(2) */
#define BW_OUT_MIN		1024		/**< Minimum bandwidth to enable uploads */
#define IO_PRE_STALL	10			/**< Pre-stalling warning */
#define IO_RTT_STALL	15			/**< Watch for RTT larger than that */
#define IO_STALLED		30			/**< Stalling condition */
#define IO_STALL_WATCH	300			/**< Watchdog period for stall monitoring */
#define IO_LONG_TIMEOUT	160			/**< Longer timeouting condition */
#define STALL_CLEAR		600			/**< Decrease stall counter every 10 min */
#define MAX_ERRORS		10			/**< Max # of errors before we close */
#define PUSH_REPLY_MAX	5			/**< Answer to up to 5 pushes per IP... */
#define PUSH_REPLY_FREQ	30			/**< ...in an interval of 30 secs */
#define ALT_LOC_SIZE	160			/**< Size of X-Alt under b/w pressure */

static pslist_t *list_uploads;
static watchdog_t *early_stall_wd;	/**< Monitor early stalling events */
static watchdog_t *stall_wd;		/**< Monitor stalling events */

/** Used to fall back to write() if sendfile() failed */
static bool sendfile_failed = FALSE;

static idtable_t *upload_handle_map;

static const char no_reason[] = "<no reason>"; /* Don't translate this */

static inline struct upload *
cast_to_upload(void *p)
{
	struct upload *u = p;
	upload_check(u);
	return u;
}

static inline struct upload *
upload_find_by_handle(gnet_upload_t n)
{
	struct upload *u = idtable_get_value(upload_handle_map, n);
	return u ? cast_to_upload(u) : NULL;
}

static inline gnet_upload_t
upload_new_handle(struct upload *u)
{
    return idtable_new_id(upload_handle_map, u);
}

static inline void
upload_free_handle(gnet_upload_t n)
{
    idtable_free_id(upload_handle_map, n);
}

/**
 * This structure is the key used in the mesh_info hash table to record
 * when we last sent mesh information to some IP about a given file
 * (identified by its SHA1).
 */
struct mesh_info_key {
	host_addr_t addr;				/**< Remote host IP address */
	const struct sha1 *sha1;		/**< SHA1 atom */
};

struct mesh_info_val {
	uint32 stamp;					/**< When we last sent the mesh */
	cevent_t *cq_ev;				/**< Scheduled cleanup callout event */
};

/* Keep mesh info about uploaders for that long (unit: ms) */
#define MESH_INFO_TIMEOUT	((PARQ_MAX_UL_RETRY_DELAY + PARQ_GRACE_TIME)*1000)

static htable_t *mesh_info;
static aging_table_t *push_requests;	/**< Throttle push requests */

/* Remember IP address of stalling uploads for a while */
static aging_table_t *stalling_uploads;

static const char stall_first[] = "stall first";
static const char stall_again[] = "stall again";

#define STALL_FIRST (deconstify_pointer(stall_first))
#define STALL_AGAIN (deconstify_pointer(stall_again))

static void upload_request(struct upload *u, header_t *header);
static void upload_error_remove(struct upload *u,
		int code, const char *msg, ...) G_GNUC_PRINTF(3, 4);
static void upload_error_remove_ext(struct upload *u,
		const char *extended, int code,
		const char *msg, ...) G_GNUC_PRINTF(4, 5);
static void upload_writable(void *up, int source, inputevt_cond_t cond);
static void upload_special_writable(void *up);
static void send_upload_error(struct upload *u, int code,
			const char *msg, ...) G_GNUC_PRINTF(3, 4);
static void upload_connect_conf(struct upload *u);

/***
 *** Callbacks
 ***/

static listeners_t upload_added_listeners   = NULL;
static listeners_t upload_removed_listeners = NULL;
static listeners_t upload_info_changed_listeners = NULL;

void
upload_add_upload_added_listener(upload_added_listener_t l)
{
    LISTENER_ADD(upload_added, l);
}

void
upload_remove_upload_added_listener(upload_added_listener_t l)
{
    LISTENER_REMOVE(upload_added, l);
}

void
upload_add_upload_removed_listener(upload_removed_listener_t l)
{
    LISTENER_ADD(upload_removed, l);
}

void
upload_remove_upload_removed_listener(upload_removed_listener_t l)
{
    LISTENER_REMOVE(upload_removed, l);
}

void
upload_add_upload_info_changed_listener(upload_info_changed_listener_t l)
{
    LISTENER_ADD(upload_info_changed, l);
}

void
upload_remove_upload_info_changed_listener(upload_info_changed_listener_t l)
{
    LISTENER_REMOVE(upload_info_changed, l);
}

static void
upload_fire_upload_added(struct upload *u)
{
	gnet_prop_incr_guint32(PROP_UL_REGISTERED);
    LISTENER_EMIT(upload_added, (u->upload_handle));
}

static void
upload_fire_upload_removed(struct upload *u, const char *reason)
{
	gnet_prop_decr_guint32(PROP_UL_REGISTERED);
    LISTENER_EMIT(upload_removed, (u->upload_handle, reason));
}

void
upload_fire_upload_info_changed(struct upload *u)
{
    LISTENER_EMIT(upload_info_changed, (u->upload_handle));
}

/***
 *** Private functions
 ***/

/***
 *** Upload mesh info tracking.
 ***/

static struct mesh_info_key *
mi_key_make(const host_addr_t addr, const struct sha1 *sha1)
{
	struct mesh_info_key *mik;

	WALLOC(mik);
	mik->addr = addr;
	mik->sha1 = atom_sha1_get(sha1);

	return mik;
}

static void
mi_key_free(struct mesh_info_key *mik)
{
	g_assert(mik);

	atom_sha1_free(mik->sha1);
	WFREE(mik);
}

static uint
mi_key_hash(const void *key)
{
	const struct mesh_info_key *mik = key;

	return sha1_hash(mik->sha1) ^ host_addr_hash(mik->addr);
}

static uint
mi_key_hash2(const void *key)
{
	const struct mesh_info_key *mik = key;

	return binary_hash2(mik->sha1, SHA1_RAW_SIZE) ^ host_addr_hash2(mik->addr);
}

static int
mi_key_eq(const void *a, const void *b)
{
	const struct mesh_info_key *mika = a, *mikb = b;

	return host_addr_equal(mika->addr, mikb->addr) &&
		sha1_eq(mika->sha1, mikb->sha1);
}

static struct mesh_info_val *
mi_val_make(uint32 stamp)
{
	struct mesh_info_val *miv;

	WALLOC(miv);
	miv->stamp = stamp;
	miv->cq_ev = NULL;

	return miv;
}

static void
mi_val_free(struct mesh_info_val *miv)
{
	g_assert(miv);

	cq_cancel(&miv->cq_ev);
	WFREE(miv);
}

/**
 * Hash table iterator callback.
 */
static void
mi_free_kv(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;
	mi_key_free(deconstify_pointer(key));
	mi_val_free(value);
}

/**
 * Callout queue callback invoked to clear the entry.
 */
static void
mi_clean(cqueue_t *cq, void *obj)
{
	struct mesh_info_key *mik = obj;
	struct mesh_info_val *miv;
	const void *key;
	void *value;
	bool found;

	found = htable_lookup_extended(mesh_info, mik, &key, &value);
	miv = value;

	g_assert(found);
	g_assert(obj == key);
	g_assert(miv->cq_ev);

	if (GNET_PROPERTY(upload_debug) > 4)
		g_debug("upload MESH info (%s/%s) discarded",
			host_addr_to_string(mik->addr), sha1_base32(mik->sha1));

	htable_remove(mesh_info, mik);
	cq_zero(cq, &miv->cq_ev);
	mi_free_kv(key, value, NULL);
}

/**
 * Get timestamp at which we last sent download mesh information for (IP,SHA1).
 * If we don't remember sending it, return 0.
 * Always records `now' as the time we sent mesh information.
 */
static uint32
mi_get_stamp(const host_addr_t addr, const struct sha1 *sha1, time_t now)
{
	struct mesh_info_key mikey;
	struct mesh_info_val *miv;
	struct mesh_info_key *mik;

	mikey.addr = addr;
	mikey.sha1 = sha1;

	miv = htable_lookup(mesh_info, &mikey);

	/*
	 * If we have an entry, reschedule the cleanup in MESH_INFO_TIMEOUT.
	 * Then return the timestamp.
	 */

	if (miv) {
		uint32 oldstamp;

		g_assert(miv->cq_ev);
		cq_resched(miv->cq_ev, MESH_INFO_TIMEOUT);

		oldstamp = miv->stamp;
		miv->stamp = (uint32) now;

		if (GNET_PROPERTY(upload_debug) > 4)
			g_debug("upload MESH info (%s/%s) has stamp=%u",
				host_addr_to_string(addr), sha1_base32(sha1), oldstamp);

		return oldstamp;
	}

	/*
	 * Create new entry.
	 */

	mik = mi_key_make(addr, sha1);
	miv = mi_val_make((uint32) now);
	miv->cq_ev = cq_main_insert(MESH_INFO_TIMEOUT, mi_clean, mik);

	htable_insert(mesh_info, mik, miv);

	if (GNET_PROPERTY(upload_debug) > 4)
		g_debug("new upload MESH info (%s/%s) stamp=%u",
			host_addr_to_string(addr), sha1_base32(sha1), (uint32) now);

	return 0;			/* Don't remember sending info about this file */
}

/**
 * Can we use bio_sendfile()?
 */
static inline bool
use_sendfile(struct upload *u)
{
	upload_check(u);
#if defined(HAS_MMAP) || defined(HAS_SENDFILE)
	return !sendfile_failed && !socket_uses_tls(u->socket);
#else
	return FALSE;
#endif /* USE_MMAP || HAS_SENDFILE */
}

/**
 * Generate summary host information for uploading host.
 *
 * @return pointer to static buffer.
 */
const char *
upload_host_info(const struct upload *u)
{
	static char info[256];
	char host[128];

	upload_check(u);

	host_addr_to_string_buf(u->addr, host, sizeof host);
	concat_strings(info, sizeof info,
		"<", host, " \'", upload_vendor_str(u), "\'>",
		(void *) 0);
	return info;
}

/**
 * This is a watchdog callback invoked when no early stalling connection has
 * been seen for the configured amount of time.
 */
static bool
upload_no_more_early_stalling(watchdog_t *unused_wd, void *unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL end of upload early stalling condition");
	}

	/*
	 * Allow the HTTP outgoing scheduler to use the stolen bandwidth again,
	 * thereby being able to send more data.
	 */

	if (bws_ignore_stolen(BSCHED_BWS_OUT, FALSE)) {
		gnet_prop_set_boolean_val(PROP_UPLOADS_BW_IGNORE_STOLEN, FALSE);
		if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
			g_warning("UL re-enabled use of stolen bandwidth for HTTP out");
		}
	}

	/*
	 * Re-enable non-uniform bandwidth scheduling so that one source consuming
	 * less allows others to consume more.
	 */

	if (bws_uniform_allocation(BSCHED_BWS_OUT, FALSE)) {
		gnet_prop_set_boolean_val(PROP_UPLOADS_BW_UNIFORM, FALSE);
		if (GNET_PROPERTY(upload_debug)) {
			g_warning("UL switched back to non-uniform HTTP "
				"outgoing bandwidth");
		}
	}

	wd_expire(stall_wd);		/* No early stalling => no stalling as well */

	return FALSE;	/* Put watchdog to sleep */
}

/**
 * This is a watchdog callback invoked when no stalling connection has been
 * seen for the configured amount of time.
 */
static bool
upload_no_more_stalling(watchdog_t *unused_wd, void *unused_obj)
{
	(void) unused_wd;
	(void) unused_obj;

	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL end of upload stalling condition");
	}

	/*
	 * Allow unused bandwidth to be stolen from the HTTP outgoing scheduler
	 * since we are back to a healthy state.
	 */

	bws_allow_stealing(BSCHED_BWS_OUT, TRUE);
	gnet_prop_set_boolean_val(PROP_UPLOADS_BW_NO_STEALING, FALSE);

	if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
		g_warning("UL re-enabled stealing of unused HTTP outgoing bandwidth");
	}

	if (GNET_PROPERTY(uploads_stalling)) {
		if (GNET_PROPERTY(upload_debug)) {
			g_message("frequent stalling condition cleared");
		}
		gnet_prop_set_boolean_val(PROP_UPLOADS_STALLING, FALSE);
	}

	return FALSE;	/* Put watchdog to sleep */
}

/**
 * Activate early stalling measures.
 */
static void
upload_early_stall(void)
{
	/*
	 * Using more b/w would only help us feed clogged TCP queues, so use at
	 * most what we were configured to use.
	 */

	if (!bws_ignore_stolen(BSCHED_BWS_OUT, TRUE)) {
		gnet_prop_set_boolean_val(PROP_UPLOADS_BW_IGNORE_STOLEN, TRUE);
		if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
			g_warning("UL limiting HTTP outgoing bandwidth to %s/sec strictly",
				short_size(bsched_bw_per_second(BSCHED_BWS_OUT), FALSE));
		}
	}

	/*
	 * If we don't wake the watchdog up, it means we already came here for
	 * another early stalling condition, and apparently our initial adjustment
	 * was not enough.
	 *
	 * Enforce uniform bandwidth allocation so that sources which do not
	 * consume their allocated bandwidth do not cause others to get more
	 * bandwidth: stalling uploads are probably blocked by TCP, and we don't
	 * want to stuff too much data to the source as soon as we can write to
	 * it again.
	 */

	if (!wd_wakeup(early_stall_wd)) {
		if (!bws_uniform_allocation(BSCHED_BWS_OUT, TRUE)) {
			gnet_prop_set_boolean_val(PROP_UPLOADS_BW_UNIFORM, TRUE);
			if (GNET_PROPERTY(upload_debug)) {
				g_warning("UL switching to uniform HTTP outgoing bandwidth");
			}
		}
	}

	wd_kick(early_stall_wd);
}

/**
 * Another upload has an early-stalling condition.
 */
static void
upload_new_early_stalling(const struct upload *u)
{
	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL request #%u to %s (%s) in early-stalling phase "
			"after %s bytes sent",
			u->reqnum, host_addr_to_string(u->addr), upload_vendor_str(u),
			uint64_to_string(u->sent));
	}

	upload_early_stall();
}

/**
 * Activate stalling measures.
 */
static void
upload_stall(void)
{
	/*
	 * We're not using all our bandwidth because some uploads are
	 * stalling, and that may be due to TCP heavily retransmitting
	 * in the background.  Don't let other schedulers use this
	 * apparent available bandwidth.
	 */

	if (bws_allow_stealing(BSCHED_BWS_OUT, FALSE)) {
		gnet_prop_set_boolean_val(PROP_UPLOADS_BW_NO_STEALING, TRUE);
		if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
			g_warning("UL disabled stealing of unused HTTP outgoing bandwidth");
		}
	}

	/*
	 * Signal a definitive stalling condition the second time we see a stalling
	 * upload with the watchdog already active.
	 */

	if (!wd_wakeup(stall_wd)) {
		if (GNET_PROPERTY(upload_debug)) {
			g_warning("frequent stalling detected, using workarounds");
		}
		gnet_prop_set_boolean_val(PROP_UPLOADS_STALLING, TRUE);
	}

	wd_kick(stall_wd);
}

/**
 * Another upload is stalling.
 */
static void
upload_new_stalling(const struct upload *u)
{
	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL request #%u to %s (%s) stalled after %s bytes sent",
			u->reqnum, host_addr_to_string(u->addr), upload_vendor_str(u),
			uint64_to_string(u->sent));
	}

	upload_stall();
}

/**
 * Invoked when we spot a large round trip time between the end of the previous
 * request and the followup from the remote client.
 */
static void
upload_large_followup_rtt(const struct upload *u, time_delta_t d)
{
	bool ignore = FALSE;

	/*
	 * If IP has been stalling recently, then ignore.
	 */

	if (aging_lookup_revitalise(stalling_uploads, &u->addr))
		ignore = TRUE;

	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL host %s (%s) took %s to send follow-up after request #%u%s",
			host_addr_to_string(u->addr), upload_vendor_str(u),
			compact_time(d), u->reqnum, ignore ? " (IGNORED)" : "");
	}

	if (ignore)
		return;

	aging_insert(stalling_uploads,
		wcopy(&u->addr, sizeof u->addr), STALL_FIRST);

	if (d >= IO_STALLED) {
		upload_stall();
	} else {
		upload_early_stall();
	}
}

/**
 * Upload heartbeat timer.
 */
void
upload_timer(time_t now)
{
	pslist_t *sl, *to_remove = NULL;
	time_delta_t timeout;

	for (sl = list_uploads; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);
		bool is_connecting;

		if (UPLOAD_IS_COMPLETE(u))
			continue;					/* Complete, no timeout possible */

		/*
		 * Check for timeouts.
		 */

		is_connecting = UPLOAD_IS_CONNECTING(u);
		if (is_connecting) {
			timeout = GNET_PROPERTY(upload_connecting_timeout);
		} else if (UPLOAD_IS_QUEUED(u)) {
			timeout = delta_time(parq_upload_lifetime(u), u->last_update);
			timeout = MAX(0, timeout);
		} else {
			timeout = MAX(IO_STALLED, GNET_PROPERTY(upload_connected_timeout));
		}

		/*
		 * Detect frequent stalling conditions on sending.
		 */

		if (!UPLOAD_IS_SENDING(u))
			goto not_sending;		/* Avoid deep nesting level */

		if (delta_time(now, u->last_update) > IO_STALLED) {
			bool skip = FALSE;

			/*
			 * Check whether we know about this IP.  If we do, then it
			 * has been stalling recently, and it might be a problem on
			 * their end rather than ours, so don't increase the stalling
			 * counter.
			 */

			if (aging_lookup_revitalise(stalling_uploads, &u->addr))
				skip = TRUE;

			if (!(u->flags & UPLOAD_F_STALLED)) {
				u->flags |= UPLOAD_F_STALLED;
				if (!skip)
					upload_new_stalling(u);

				/*
				 * Record that this IP is stalling, but also record the fact
				 * that it's not the first time we're seeing it, if necessary.
				 */

				aging_insert(stalling_uploads, wcopy(&u->addr, sizeof u->addr),
					skip ? STALL_AGAIN : STALL_FIRST);
			} else if (!skip) {
				wd_kick(stall_wd);
			}
		} else {
			bool skip = FALSE;
			void *stall;

			stall = aging_lookup_revitalise(stalling_uploads, &u->addr);
			skip = (stall == STALL_AGAIN);

			if (u->flags & UPLOAD_F_STALLED) {
				if (GNET_PROPERTY(upload_debug)) g_warning(
					"connection to %s (%s) un-stalled, %s bytes sent%s",
					host_addr_to_string(u->addr), upload_vendor_str(u),
					uint64_to_string(u->sent),
					skip ? " (IGNORED)" : "");

				if (!skip && !socket_is_corked(u->socket)) {
					if (GNET_PROPERTY(upload_debug)) g_warning(
						"re-enabling TCP_CORK on connection to %s (%s)",
						host_addr_to_string(u->addr), upload_vendor_str(u));
					socket_cork(u->socket, TRUE);
					socket_tos_throughput(u->socket);
				}
			}
		}

		/* FALL THROUGH */

	not_sending:

		/*
		 * If they have experienced significant stalling conditions recently,
		 * be much more lenient about connection timeouts.
		 */

		if (!is_connecting && wd_is_awake(stall_wd)) {
			timeout = MAX(IO_LONG_TIMEOUT, timeout);
		}

		/*
		 * We can't call upload_remove() since it will remove the upload
		 * from the list we are traversing.
		 *
		 * Check pre-stalling condition and remove the CORK option
		 * if we are no longer transmitting.
		 */

		if (delta_time(now, u->last_update) > timeout) {
			to_remove = pslist_prepend(to_remove, u);
		} else if (UPLOAD_IS_SENDING(u)) {
			if (delta_time(now, u->last_update) > IO_PRE_STALL) {
				if (socket_is_corked(u->socket)) {
					if (GNET_PROPERTY(upload_debug)) g_warning(
						"connection to %s (%s) may be stalled, "
						"disabling TCP_CORK",
						host_addr_to_string(u->addr), upload_vendor_str(u));
					socket_cork(u->socket, FALSE);
					socket_tos_normal(u->socket); /* Have ACKs come faster */
				}
				if (!(u->flags & UPLOAD_F_EARLY_STALL)) {
					upload_new_early_stalling(u);
					u->flags |= UPLOAD_F_EARLY_STALL;
				} else {
					wd_kick(early_stall_wd);
				}
			} else
				u->flags &= ~UPLOAD_F_EARLY_STALL;
		}
	}

	for (sl = to_remove; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);

		if (UPLOAD_IS_CONNECTING(u)) {
			if (u->status == GTA_UL_PUSH_RECEIVED || u->status == GTA_UL_QUEUE)
				upload_remove(u, N_("Connect back timeout"));
			else if (UPLOAD_READING_HEADERS(u))
				upload_error_remove(u, 408, N_("Request timeout"));
			else
				upload_remove(u, N_("Timeout waiting for follow-up"));
		} else if (UPLOAD_IS_SENDING(u))
			/* Cannot use NG_ here because we can't pass a translated string */
			upload_remove(u, "Data timeout after %s byte%s",
				uint64_to_string(u->sent), plural(u->sent));
		else
			upload_remove(u, N_("Lifetime expired"));
	}
	pslist_free(to_remove);
}

struct upload *
upload_alloc(void)
{
	static const struct upload zero_upload;
	struct upload *u;

	WALLOC(u);
	*u = zero_upload;
	u->magic = UPLOAD_MAGIC;
	return u;
}

void
upload_free(struct upload **ptr)
{
	if (*ptr) {
		struct upload *u = *ptr;
		upload_check(u);
		u->magic = 0;
		WFREE(u);
		*ptr = NULL;
	}
}

/**
 * Callback invoked when socket is destroyed.
 */
static void
upload_socket_destroy(gnutella_socket_t *s, void *owner, const char *reason)
{
	struct upload *u = owner;

	upload_check(u);
	g_assert(s == u->socket);

	upload_remove(u, "%s", reason);
}

/**
 * Callback invoked when socket is connected.
 */
static void
upload_socket_connected(gnutella_socket_t *s, void *owner)
{
	struct upload *u = owner;

	upload_check(u);
	g_assert(s == u->socket);

	upload_connect_conf(u);
}

/**
 * Socket-layer callbacks for uploads.
 */
static struct socket_ops upload_socket_ops = {
	NULL,						/* connect_failed */
	upload_socket_connected,	/* connected */
	upload_socket_destroy,		/* destroy */
};

/**
 * Create a new upload structure, linked to a socket.
 */
struct upload *
upload_create(struct gnutella_socket *s, bool push)
{
	struct upload *u;

	u = upload_alloc();

    u->upload_handle = upload_new_handle(u);
	u->socket = s;
    u->addr = s->addr;
	u->country = gip_country(u->addr);
	u->push = push;
	u->status = push ? GTA_UL_PUSH_RECEIVED : GTA_UL_HEADERS;
	u->start_date = tm_time();
	u->last_update = u->start_date;
	u->parq_status = FALSE;

	socket_attach_ops(s, SOCK_TYPE_UPLOAD, &upload_socket_ops, u);

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	list_uploads = pslist_prepend(list_uploads, u);

	/*
	 * Add upload to the GUI
	 */

    upload_fire_upload_added(u);

	return u;
}

/**
 * Send a GIV string to the specified IP:port.
 *
 * `ip' and `port' is where we need to connect.
 * `hops' and `ttl' are the values from the PUSH message we received, just
 * for logging in case we cannot connect.
 * `file_index' and `file_name' are the values we determined from PUSH.
 * `banning' must be TRUE when we determined connections to the IP were
 * currently prohibited.
 */
void
upload_send_giv(const host_addr_t addr, uint16 port, uint8 hops, uint8 ttl,
	uint32 file_index, const char *file_name, uint32 flags)
{
	struct upload *u;
	struct gnutella_socket *s;

	flags |= GNET_PROPERTY(tls_enforce) ? SOCK_F_TLS : 0;
	s = socket_connect(addr, port, SOCK_TYPE_UPLOAD, flags);
	if (!s) {
		if (GNET_PROPERTY(upload_debug)) g_warning(
			"PUSH request (hops=%d, ttl=%d) dropped: can't connect to %s%s",
			hops, ttl, (flags & SOCK_F_G2) ? "G2 " : "",
			host_addr_port_to_string(addr, port));
		return;
	}

	u = upload_create(s, TRUE);
	u->g2 = booleanize(flags & SOCK_F_G2);
	u->file_index = file_index;
	u->name = atom_str_get(file_name);

	upload_fire_upload_info_changed(u);

	/* Now waiting for the connection CONF -- will call upload_connect_conf() */
}

/**
 * Called when we receive a Push request on Gnet or a /PUSH on G2.
 *
 * @param n		the receiving node
 * @param t		for G2, the parsed message tree
 *
 * If it is not for us, discard it.
 * If we are the target, then connect back to the remote servent.
 */
void
handle_push_request(struct gnutella_node *n, const g2_tree_t *t)
{
	host_addr_t ha;
	uint32 file_index, flags = 0;
	uint16 port;
	const char *info;
	const char *file_name = "<invalid file index>";
	int push_count;

	if (NODE_TALKS_G2(n)) {
		const char *payload;
		size_t plen;

		/*
		 * On G2, there is no Gnutella header, so zero it to make sure we
		 * can safely reuse the code below which is shared with Gnutella
		 * processing.
		 */

		ZERO(&n->header);

		/*
		 * Extract remote host information.
		 */

		payload = g2_tree_node_payload(t, &plen);

		if (NULL == payload || plen < 6)
			return;		/* Invalid /PUSH message */

		file_index = 0;

		if (plen >= 18) {
			ha = host_addr_peek_ipv6(&payload[0]);
			port = peek_le16(&payload[16]);
		} else {
			ha = host_addr_peek_ipv4(&payload[0]);
			port = peek_le16(&payload[4]);
		}

		/*
		 * Verify the packet was indeed targeted to us:
		 *
		 * If it has a /?/TO child, it must bear our GUID.
		 * Otherwise if it comes from UDP, it must have a matching address
		 * to connect back to.
		 */

		payload = g2_tree_payload(t, "TO", &plen);

		if (NULL == payload || plen < GUID_RAW_SIZE) {
			if (!NODE_IS_UDP(n))
				return;				/* No GUID, coming from TCP */
			if (!host_addr_equal(n->addr, ha))
				return;				/* Mismatching remote address */
		} else {
			if (!guid_eq(payload, GNET_PROPERTY(servent_guid)))
				return;				/* Mismatching GUID */
		}

		/*
		 * Setup G2 flags and see whether they support TLS connections.
		 */

		flags = SOCK_F_G2;

		if (NULL != g2_tree_lookup(t, "TLS"))
			flags |= SOCK_F_TLS;
	} else {
		/* Servent ID matches our GUID? */
		if (!guid_eq(n->data, GNET_PROPERTY(servent_guid)))
			return;								/* No: not for us */

		/*
		 * We are the target of the push.
		 */

		if (NODE_IS_UDP(n) && ctl_limit(n->addr, CTL_D_UDP | CTL_D_INCOMING)) {
			gnet_stats_count_dropped(n, MSG_DROP_LIMIT);
			return;
		}

		/*
		 * Decode the message.
		 */

		info = &n->data[GUID_RAW_SIZE];			/* Start of file information */

		file_index = peek_le32(&info[0]);
		ha = host_addr_peek_ipv4(&info[4]);
		port = peek_le16(&info[8]);
	}

	if (ctl_limit(ha, CTL_D_INCOMING)) {
		gnet_stats_count_dropped(n, MSG_DROP_LIMIT);
		return;
	}

	if (NODE_TALKS_G2(n))
		goto connect_to_host;

	/*
	 * Gnutella message, parse GGEP extensions if any.
	 */

	if (n->size > sizeof(gnutella_push_request_t)) {
		extvec_t exv[MAX_EXTVEC];
		int exvcnt;
		int i;

		ext_prepare(exv, MAX_EXTVEC);
		exvcnt = ext_parse(&n->data[sizeof(gnutella_push_request_t)],
					n->size - sizeof(gnutella_push_request_t),
					exv, MAX_EXTVEC);

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];

			switch (e->ext_token) {
			case EXT_T_GGEP_6:
			case EXT_T_GGEP_GTKG_IPV6:	/* Deprecated for 0.97 */
				if (settings_running_ipv6() && 0 != ext_paylen(e)) {
					host_addr_t addr;

					switch (ggept_gtkg_ipv6_extract(e, &addr)) {
					case GGEP_OK:
						/* XXX: Check validity, hostiles etc. */
						if (is_host_addr(addr)) {
							ha = addr;
						}
						break;
					case GGEP_INVALID:
					case GGEP_NOT_FOUND:
					case GGEP_BAD_SIZE:
					case GGEP_DUPLICATE:
						if (GNET_PROPERTY(ggep_debug) > 3) {
							g_warning("%s bad GGEP \"%s\" (dumping)",
									gmsg_node_infostr(n), ext_ggep_id_str(e));
							ext_dump(stderr, e, 1, "....", "\n", TRUE);
						}
						break;
					}
				}
				break;
			case EXT_T_GGEP_TLS:
			case EXT_T_GGEP_GTKG_TLS:	/* Deprecated for 0.97 */
				flags |= SOCK_F_TLS;
				break;
			default:
				if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
					size_t paylen = ext_paylen(e);
					g_warning("%s (PUSH): unhandled GGEP \"%s\" (%zu byte%s)",
						gmsg_node_infostr(n), ext_ggep_id_str(e),
						paylen, plural(paylen));
				}
				break;
			}
		}
		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);
	}

	/*
	 * Quick sanity check on file index.
	 *
	 * Note that even if the file index is wrong, we still open the
	 * connection.  After all, the PUSH message was bearing our GUID.
	 * We'll let the remote end figure out what to do.
	 *		--RAM. 18/07/2003
	 */

	if (file_index == QUERY_FW2FW_FILE_INDEX) {
		file_name = "<RUDP connection request>";
		if (GNET_PROPERTY(upload_debug))
			g_warning(
				"PUSH request (hops=%d, ttl=%d) for RUDP connection request",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header));
	} else {
		shared_file_t *req_file;

		req_file = shared_file(file_index);
		if (req_file == SHARE_REBUILDING) {
			file_name = "<rebuilding library>";
			if (GNET_PROPERTY(upload_debug))
				g_warning(
					"PUSH request (hops=%d, ttl=%d) whilst rebuilding library",
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header));
		} else if (req_file == NULL) {
			file_name = "<invalid file index>";
			if (GNET_PROPERTY(upload_debug))
				g_warning(
					"PUSH request (hops=%d, ttl=%d) for invalid file index %u",
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					file_index);
		} else {
			file_name = shared_file_name_nfc(req_file);
		}
		shared_file_unref(&req_file);
	}

connect_to_host:

	/*
	 * XXX might be run inside corporations (private IPs), must be smarter.
	 * XXX maybe a configuration variable? --RAM, 31/12/2001
	 *
	 * Don't waste time and resources connecting to something that will fail.
	 *
	 * NB: we allow the PUSH if we're already connected to that node.  This
	 * allows easy local testing. -- RAM, 11/11/2002
	 */

	if (!host_is_valid(ha, port) && !node_is_connected(ha, port, TRUE)) {
		if (GNET_PROPERTY(upload_debug)) g_warning(
			"PUSH request (hops=%d, ttl=%d) from invalid address %s",
			gnutella_header_get_hops(&n->header),
			gnutella_header_get_ttl(&n->header),
			host_addr_port_to_string(ha, port));
		return;
	}

	/*
	 * Protect from PUSH flood: since each push requires us to connect
	 * back, it uses resources and could be used to conduct a subtle denial
	 * of service attack.	-- RAM, 03/11/2002
	 */

	push_count = pointer_to_int(aging_lookup(push_requests, &ha));

	if (push_count >= PUSH_REPLY_MAX) {
		if (GNET_PROPERTY(upload_debug)) {
			g_warning("PUSH (hops=%d, ttl=%d) throttling callback to %s%s: %s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				NODE_TALKS_G2(n) ? "G2 " : "",
				host_addr_port_to_string(ha, port), file_name);
		}
		return;
	}

	aging_insert(push_requests, wcopy(&ha, sizeof ha),
		int_to_pointer(push_count + 1));

	/*
	 * OK, start the upload by opening a connection to the remote host.
	 */

	if (GNET_PROPERTY(upload_debug) > 3)
		g_debug("PUSH (hops=%d, ttl=%d) to %s%s: %s",
			gnutella_header_get_hops(&n->header),
			gnutella_header_get_ttl(&n->header),
			NODE_TALKS_G2(n) ? "G2 " : "",
			host_addr_port_to_string(ha, port),
			file_name);

	upload_send_giv(ha, port,
		gnutella_header_get_hops(&n->header),
		gnutella_header_get_ttl(&n->header),
		file_index, file_name, flags);
}

#if 0 /* UNUSED */
void
upload_real_remove(void)
{
	/* XXX UNUSED
	 * XXX Currently, we remove failed uploads from the list, but we should
	 * XXX do as we do for downloads, and have an extra option to remove
	 * XXX failed uploads immediately.	--RAM, 24/12/2001
	 */
}
#endif /* UNUSED */

static void
upload_free_resources(struct upload *u)
{
	upload_check(u);

	parq_upload_upload_got_freed(u);

	atom_str_free_null(&u->name);
	file_object_release(&u->file);

#ifdef HAS_MMAP
	if (u->sendfile_ctx.map) {
		size_t len = u->sendfile_ctx.map_end - u->sendfile_ctx.map_start;

		g_assert(len > 0 && len <= INT_MAX);
		vmm_munmap(u->sendfile_ctx.map, len);
		u->sendfile_ctx.map = NULL;
	}
#endif /* HAS_MMAP */

	HFREE_NULL(u->buffer);
	if (u->io_opaque) {				/* I/O data */
		io_free(u->io_opaque);
		g_assert(u->io_opaque == NULL);
	}
	if (u->bio != NULL) {
		bsched_source_remove(u->bio);
		u->bio = NULL;
	}
	atom_str_free_null(&u->user_agent);
	atom_sha1_free_null(&u->sha1);
	atom_guid_free_null(&u->guid);
	if (u->special) {
		(*u->special->close)(u->special, FALSE);
		u->special = NULL;
	}
	/*
	 * Close the socket at last because update_poll_event() needs a valid fd
	 * and some of the above may cause a close(u->socket->fd).
	 */
	socket_free_null(&u->socket);
	shared_file_unref(&u->sf);
	shared_file_unref(&u->thex);
	HFREE_NULL(u->request);

    upload_free_handle(u->upload_handle);
	list_uploads = pslist_remove(list_uploads, u);

	upload_free(&u);
}

/**
 * Clone upload, resetting all dynamically allocated structures in the
 * original, since they are shallow-copied to the new upload.
 *
 * (This routine is used because each different upload from the same host
 * will become a line in the GUI, and the GUI stores upload structures in
 * its row data, and will call upload_remove() to clear them.)
 */
static struct upload *
upload_clone(struct upload *u)
{
	struct upload *cu;
	bool within_error = FALSE;

	upload_check(u);

	if (u->io_opaque) {
		/* Was cloned after error sending, not during transfer */
		within_error = TRUE;
		io_free(u->io_opaque);
		u->io_opaque = NULL;
	}

	cu = wcopy(u, sizeof *cu);
	parq_upload_upload_got_cloned(u, cu);

	if (upload_is_special(u))
		cu->flags |= UPLOAD_F_WAS_PLAIN;
	else
		cu->flags &= ~UPLOAD_F_WAS_PLAIN;

    cu->upload_handle = upload_new_handle(cu); /* fetch new handle */
	cu->bio = NULL;						/* Recreated on each transfer */
	cu->sf = NULL;						/* File re-opened each time */
	cu->file = NULL;					/* File re-opened each time */
	cu->sendfile_ctx.map = NULL;		/* File re-opened each time */
	cu->accounted = FALSE;
	cu->browse_host = FALSE;
    cu->skip = 0;
    cu->end = 0;
	cu->sent = 0;
	cu->hevcnt = 0;

	socket_change_owner(cu->socket, cu);	/* Takes ownership of socket */

	/*
	 * This information is required to have proper GUI information displayed
	 * on the error line (when we get cloned after an error, the parent will
	 * be removed which will cause the line to be fully redisplayed).
	 */

	if (within_error) {
		if (u->name)
			u->name = atom_str_get(u->name);
		if (u->user_agent)
			u->user_agent = atom_str_get(u->user_agent);
	} else {
		/* When transferring, only the status changes: no full redisplay */
		u->name = NULL;
		u->user_agent = NULL;
	}
	u->was_running = FALSE;				/* Status transferred to clone */

	/*
	 * The following have been copied and appropriated by the cloned upload.
	 * Some are reset so that an upload_free_resource() on the original will
	 * not free them.
	 */

	u->socket = NULL;
	u->buffer = NULL;
	u->sha1 = NULL;
	u->guid = NULL;
	u->thex = NULL;
	u->request = NULL;

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	list_uploads = pslist_prepend(list_uploads, cu);

	/*
	 * Add upload to the GUI
	 */
    upload_fire_upload_added(cu);

	return cu;
}

/**
 * Check whether the request was likely made from a browser.
 */
static bool
upload_likely_from_browser(const header_t *header)
{
	char *buf;

	buf = header_get(header, "X-Queue");
	if (buf)
		return FALSE;

	buf = header_get(header, "X-Gnutella-Content-Urn");
	if (buf)
		return FALSE;

	buf = header_get(header, "X-Alt");
	if (buf)
		return FALSE;

	buf = header_get(header, "Accept");
	if (buf) {
		if (strtok_case_has(buf, ",;", "text/html"))
			return TRUE;
		if (strtok_case_has(buf, ",;", "text/*"))
			return TRUE;
	}

	buf = header_get(header, "Accept-Language");
	if (buf)
		return TRUE;

	buf = header_get(header, "Referer");
	if (buf)
		return TRUE;

	return FALSE;
}

/**
 * Wrapper to http_send_status() to disable TCP quick ACKs before sending
 * the actual status.
 *
 * @return TRUE if we were able to send everything, FALSE otherwise
 */
static bool 
upload_send_http_status(struct upload *u,
	bool keep_alive, int code, const char *msg)
{
	upload_check(u);
	g_assert(msg);

	if (u->keep_alive)
		socket_set_quickack(u->socket, FALSE);	/* Re-disable quick TCP ACKs */

	if (u->flags & UPLOAD_F_LIMITED) {
		send_upload_error(u, 403, N_("Unauthorized"));
		return TRUE;
	}

	return http_send_status(HTTP_UPLOAD, u->socket, code, keep_alive,
				u->hev, u->hevcnt, "%s", msg);
}

/**
 * This routine is called by http_send_status() to generate the
 * X-Host line (added to the HTTP status) into `buf'.
 */
static size_t
upload_http_xhost_add(char *buf, size_t size,
	void *unused_arg, uint32 unused_flags)
{
	host_addr_t addr;
	uint16 port;
	size_t len;

	(void) unused_arg;
	(void) unused_flags;
	g_return_val_if_fail(!GNET_PROPERTY(is_firewalled), 0);

	addr = listen_addr();
	port = socket_listen_port();

	if (host_is_valid(addr, port)) {
		len = concat_strings(buf, size,
				"X-Host: ", host_addr_port_to_string(addr, port), "\r\n",
				(void *) 0);
	} else {
		len = 0;
	}

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Host header back: only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

/**
 * Generates the X-Features line -- http_send_status() callback.
 *
 * @param buf		buffer where header must be written to
 * @param size		size of supplied buffer
 *
 * @return length of generated content
 */
static size_t
upload_xfeatures_add(char *buf, size_t size,
	void *unused_arg, uint32 unused_flags)
{
	size_t rw = 0;

	(void) unused_arg;
	(void) unused_flags;

	header_features_generate(FEATURES_UPLOADS, buf, size, &rw);
	return rw;
}

/**
 * Generates the X-GUID line -- http_send_status() callback.
 *
 * @param buf		buffer where header must be written to
 * @param size		size of supplied buffer
 * @param flags		set of HTTP_CBF_* flags
 *
 * @return length of generated content
 */
static size_t
upload_xguid_add(char *buf, size_t size, void *arg, uint32 flags)
{
	size_t rw;
	guid_t guid;

	/*
	 * If we are TCP-firewalled there's no need to generate the header
	 * (would be redundant with X-FW-Node-Info).
	 *
	 * IPv6-Ready: must generate X-GUID even if the DHT is disabled in order
	 * for downloaders to spot multiple downloading when we're running on
	 * both IPv4 and IPv6.
	 */

	if (
		GNET_PROPERTY(is_firewalled) ||
		!(dht_enabled() || settings_running_ipv4_and_ipv6())
	)
		return 0;

	/*
	 * Also if output bandwidth is saturated, save some bytes when sending
	 * a 503 "busy" signal, unless we're forced to by a non-null argument.
	 */

	if (
		(flags & (HTTP_CBF_BW_SATURATED|HTTP_CBF_BUSY_SIGNAL)) ==
			(HTTP_CBF_BW_SATURATED|HTTP_CBF_BUSY_SIGNAL) &&
		NULL == arg
	)
		return 0;

	gnet_prop_get_storage(PROP_SERVENT_GUID, &guid, sizeof guid);

	rw = concat_strings(buf, size,
			"X-GUID: ", guid_hex_str(&guid), "\r\n",
			(void *) 0);

	if (rw >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-GUID header back: only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return rw < size ? rw : 0;
}

/**
 * Generates the X-Gnutella-Content-URN line -- http_send_status() callback.
 *
 * @param buf		buffer where header must be written to
 * @param size		size of supplied buffer
 * @param arg		user-supplied argument
 * @param flags		set of HTTP_CBF_* flags
 *
 * @return length of generated content
 */
static size_t
upload_gnutella_content_urn_add(char *buf, size_t size, void *arg, uint32 flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	const struct sha1 *sha1;
	size_t len;

	upload_check(u);

	g_return_val_if_fail(u->sf, 0);
	shared_file_check(u->sf);

	sha1 = shared_file_sha1(u->sf);
	g_return_val_if_fail(sha1, 0);

	/*
	 * We don't send the SHA1 if we're short on bandwidth and they
	 * made a request via the N2R resolver.  This will leave more room
	 * for the mesh information.
	 * NB: we use HTTP_CBF_BW_SATURATED, not HTTP_CBF_SMALL_REPLY on purpose.
	 *
	 * Also, if we sent mesh information for THIS upload, it means we're
	 * facing a follow-up request and we don't need to send them the SHA1
	 * again.
	 *		--RAM, 18/10/2003
	 */

	if ((flags & HTTP_CBF_BW_SATURATED) && u->n2r)
		return 0;

	len = concat_strings(buf, size,
			"X-Gnutella-Content-URN: ", sha1_to_urn_string(sha1), "\r\n",
			(void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Gnutella-Content-URN header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

/**
 * Generates the X-Thex-URI line -- http_send_status() callback.
 *
 * @param buf		buffer where header must be written to
 * @param size		size of supplied buffer
 * @param arg		user-supplied argument
 * @param flags		set of HTTP_CBF_* flags
 *
 * @return length of generated content
 */
static size_t
upload_thex_uri_add(char *buf, size_t size, void *arg, uint32 flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	const struct sha1 *sha1;
	const struct tth *tth;
	size_t len = 0;

	upload_check(u);

	g_return_val_if_fail(u->sf, 0);
	shared_file_check(u->sf);

	sha1 = shared_file_sha1(u->sf);
	g_return_val_if_fail(sha1, 0);

	if ((flags & HTTP_CBF_BW_SATURATED) && u->n2r)
		return 0;

	tth = shared_file_tth(u->sf);
	if (!tth)
		return 0;
	
	len = concat_strings(buf, size,
			"X-Thex-URI: /uri-res/N2X?", sha1_to_urn_string(sha1),
			";", tth_base32(tth),
			"\r\n",
			(void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Thex-URI header back: only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

/**
 * This routine is called by http_send_status() to generate the
 * SHA1-specific headers (added to the HTTP status) into `buf'.
 */
static size_t
upload_http_content_urn_add(char *buf, size_t size, void *arg,
	uint32 flags)
{
	const struct sha1 *sha1;
	size_t rw = 0, mesh_len;
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	time_t last_sent;

	upload_check(u);

	g_return_val_if_fail(u->sf, 0);
	shared_file_check(u->sf);

	sha1 = shared_file_sha1(u->sf);
	g_return_val_if_fail(sha1, 0);

	/*
	 * Because of possible persistent uploads, we have to keep track on
	 * the last time we sent download mesh information within the upload
	 * itself: the time for them to download a range will be greater than
	 * our expiration timer on the external mesh information.
	 */

	if (u->last_dmesh) {
		last_sent = u->last_dmesh;
	} else {
		rw += upload_gnutella_content_urn_add(&buf[rw], size - rw, arg, flags);
		rw += upload_thex_uri_add(&buf[rw], size - rw, arg, flags);
		last_sent = mi_get_stamp(u->socket->addr, sha1, tm_time());
	} 

	/*
	 * Ranges are only emitted for partial files, so no pre-estimation of
	 * the size of the mesh entries is needed when replying for a full file.
	 *
	 * However, we're not going to include the available ranges when we
	 * are returning a 503 "busy" or "queued" indication, or any 4xx indication
	 * since the data will be stale by the time it is needed.  We only dump
	 * them when explicitly requested to do so.  Otherwise, we let them know
	 * about the amount of data we have for the file, so that they know we
	 * hold only a fraction of it.
	 */

	if (
		(
			GNET_PROPERTY(pfsp_server) ||
			(GNET_PROPERTY(pfsp_rare_server) && download_sha1_is_rare(sha1))
		) &&
		!shared_file_is_finished(u->sf) &&
		(flags & (HTTP_CBF_SHOW_RANGES|HTTP_CBF_BUSY_SIGNAL))
	) {
		char alt_locs[ALT_LOC_SIZE];

		/*
		 * PFSP-server: if they requested a partial file, let them know about
		 * the set of available ranges.
		 *
		 * To know how much room we can use for ranges, try to see how much
		 * locations we are going to fill.  In case we are under stringent
		 * size control, it would be a shame to not emit ranges because we
		 * want to leave size for alt-locs and yet there are none to emit!
		 */

		mesh_len = dmesh_alternate_location(sha1,
					alt_locs, sizeof alt_locs, u->socket->addr,
					last_sent, u->user_agent, NULL, FALSE,
					u->fwalt ? u->guid : NULL, u->net);

		if (size - rw > mesh_len) {
			size_t len;

			/*
			 * Emit the X-Available-Ranges: header if file is partial and we're
			 * not returning a busy signal.  Otherwise, just emit the
			 * X-Available header.
			 */

			if (flags & HTTP_CBF_BUSY_SIGNAL) {
				len = file_info_available(shared_file_fileinfo(u->sf),
						&buf[rw], size - rw - mesh_len);
			} else {
				len = file_info_available_ranges(shared_file_fileinfo(u->sf),
						&buf[rw], size - rw - mesh_len);
			}
			rw += len;
		}
	} else {
		mesh_len = 1;			/* Try to emit alt-locs later */
	}

	/*
	 * Emit alt-locs only if there is anything to emit, using all the
	 * remaining space, which may be larger than the room we tried to
	 * emit locations to in the above pre-check, in case there was only
	 * a little amount of ranges written!
	 */

	if (mesh_len > 0) {
		size_t len, avail;
		
		avail = size - rw;

		if (flags & HTTP_CBF_SMALL_REPLY) {
			/*
			 * If we're trying to limit the reply size, limit the size of the
			 * mesh. When we send X-Alt: locations, this leaves room for quite
			 * a few locations nonetheless!
			 *		--RAM, 18/10/2003
			 */

			avail = MIN(avail, ALT_LOC_SIZE);
		}

		len = dmesh_alternate_location(sha1,
					&buf[rw], avail, u->socket->addr,
					last_sent, u->user_agent, NULL, FALSE,
					u->fwalt ? u->guid : NULL, u->net);
		rw += len;
		u->last_dmesh = tm_time();
	}

	return rw;
}

/**
 * This routine is called by http_send_status() to generate the
 * additionnal headers on a "416 Request range not satisfiable" error.
 */
static size_t
upload_416_extra(char *buf, size_t size, void *arg, uint32 unused_flags)
{
	const struct upload_http_cb *a = arg;
	const struct upload *u = a->u;
	size_t len;
	char fsize[UINT64_DEC_BUFLEN];

	(void) unused_flags;
	upload_check(u);

	uint64_to_string_buf(u->file_size, fsize, sizeof fsize);
	len = concat_strings(buf, size,
			"Content-Range: bytes */", fsize, (void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Range header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	/* Don't emit a truncated header */
	return len < size ? len : 0;
}

static size_t
upload_http_content_length_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	len = concat_strings(buf, size,
			"Content-Length: ", uint64_to_string(u->end - u->skip + 1), "\r\n",
			(void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Length header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_content_type_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	if (!u->sf)
		return 0;

	shared_file_check(u->sf);
	len = concat_strings(buf, size,
			"Content-Type: ", shared_file_mime_type(u->sf), "\r\n",
			(void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Type header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_last_modified_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	struct upload_http_cb *a = arg;
	size_t len;

	(void) unused_flags;

	len = concat_strings(buf, size,
			"Last-Modified: ", timestamp_rfc1123_to_string(a->mtime), "\r\n",
			(void *) 0);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Last-Modified header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_content_range_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	if (u->skip || u->end != (u->file_size - 1)) {
		len = concat_strings(buf, size,
				"Content-Range: bytes ", 
				uint64_to_string(u->skip), "-", uint64_to_string2(u->end),
				"/", filesize_to_string(u->file_size),
				"\r\n",
				(void *) 0);
	} else {
		len = 0;
	}

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Range header back: "
			"only %u byte%s left",
			(unsigned) size, plural(size));
	}

	return len < size ? len : 0;
}


/**
 * This routine is called by http_send_status() to generate the
 * upload-specific headers into `buf'.
 */
static size_t
upload_http_status(char *buf, size_t size, void *arg, uint32 flags)
{
	size_t rw = 0;

	rw += upload_http_content_length_add(&buf[rw], size - rw, arg, flags);
	rw += upload_http_content_range_add(&buf[rw], size - rw, arg, flags);
	rw += upload_http_last_modified_add(&buf[rw], size - rw, arg, flags);
	rw += upload_http_content_type_add(&buf[rw], size - rw, arg, flags);
	return rw;
}

/**
 * Record additional header-generation callback to invoke when we generate
 * the HTTP status.
 */
static void
upload_http_extra_callback_add(struct upload *u,
	http_status_cb_t callback, void *user_arg)
{
	upload_check(u);
	g_return_if_fail(u->hevcnt < G_N_ELEMENTS(u->hev));

	http_extra_callback_set(&u->hev[u->hevcnt], callback, user_arg);
	u->hevcnt++;
}

/**
 * Remove all registered matching HTTP status callbacks.
 */
static void
upload_http_extra_callback_remove(struct upload *u, http_status_cb_t callback)
{
	uint i;

	upload_check(u);
	g_assert(u->hevcnt <= G_N_ELEMENTS(u->hev));

	for (i = 0; i < u->hevcnt; /* empty */) {
		if (http_extra_callback_matches(&u->hev[i], callback)) {
			if (i < u->hevcnt - 1) {
				memmove(&u->hev[i], &u->hev[i+1],
					sizeof(u->hev[0]) * (u->hevcnt - i - 1));
			}
			g_assert(u->hevcnt != 0);
			u->hevcnt--;
		} else {
			i++;
		}
	}
}

/**
 * Record additional header-generation callback to invoke when we generate
 * the HTTP status, provided that callback has not been recorded already.
 */
static void
upload_http_extra_callback_add_once(struct upload *u,
	http_status_cb_t callback, void *user_arg)
{
	uint i;

	upload_check(u);
	g_return_if_fail(u->hevcnt < G_N_ELEMENTS(u->hev));

	for (i = 0; i < u->hevcnt; i++) {
		if (http_extra_callback_matches(&u->hev[i], callback))
			return;
	}

	http_extra_callback_set(&u->hev[u->hevcnt], callback, user_arg);
	u->hevcnt++;
}

/**
 * Record additional header line (including trailing "\r\n") to add to the
 * generated HTTP status.
 */
static void
upload_http_extra_line_add(struct upload *u, const char *msg)
{
	upload_check(u);
	g_return_if_fail(u->hevcnt < G_N_ELEMENTS(u->hev));

	http_extra_line_set(&u->hev[u->hevcnt], msg);
	u->hevcnt++;
}

/**
 * Record extra body data to send along with the HTTP status.
 */
static void
upload_http_extra_body_add(struct upload *u, const char *body)
{
	upload_check(u);
	g_return_if_fail(u->hevcnt < G_N_ELEMENTS(u->hev));

	http_extra_body_set(&u->hev[u->hevcnt], body);
	u->hevcnt++;
}

/**
 * The vectorized (message-wise) version of send_upload_error().
 */
static void
send_upload_error_v(struct upload *u, const char *ext, int code,
	const char *msg, va_list ap)
{
	char reason[1024];
	char extra[1024];
	size_t slen = 0;

	upload_check(u);

	if (u->flags & UPLOAD_F_LIMITED) {
		if (GNET_PROPERTY(upload_debug)) {
			g_debug("upload request from %s [%s] limited for %s",
				host_addr_to_string(u->socket->addr),
				gip_country_name(u->socket->addr),
				u->name ? u->name : "<unkonwn resource>");
		}
		u->flags &= ~UPLOAD_F_LIMITED;		/* For recursion */
		u->keep_alive = FALSE;				/* Force disconnection */
		if (u->flags & UPLOAD_F_NORMAL_LIMIT) {
			send_upload_error(u, 403, N_("Unauthorized"));
		} else if (!(u->flags & UPLOAD_F_STEALTH_LIMIT)) {
			send_upload_error(u, 403, N_("Limiting connections from %s"),
				gip_country_name(u->socket->addr));
		}
		return;
	}

	if (msg && no_reason != msg) {
		str_vbprintf(reason, sizeof reason, msg, ap);
	} else
		reason[0] = '\0';

	if (u->error_sent) {
		if (GNET_PROPERTY(upload_debug)) g_warning(
			"already sent an error %d to %s, not sending %d (%s)",
			u->error_sent, host_addr_to_string(u->socket->addr), code, reason);
		return;
	}

	extra[0] = '\0';

	/*
	 * If `ext' is not null, we have extra header information to propagate.
	 */

	if (ext) {
		slen = g_strlcpy(extra, ext, sizeof(extra));

		if (slen < sizeof(extra)) {
			upload_http_extra_line_add(u, extra);
		} else {
			g_warning("%s: ignoring too large extra header (%zu bytes)",
				G_STRFUNC, slen);
		}
	}

	/*
	 * Send X-Features (the first time) and X-FW-Node-Info on errors as well.
	 *
	 * Since we don't really know the code path that led us here, we're
	 * careful not to add the same extra headers twice.
	 */

	if (!(u->is_followup || u->was_actively_queued)) {
		upload_http_extra_callback_add_once(u, upload_xfeatures_add, NULL);
	}

	upload_http_extra_callback_add_once(u, node_http_proxies_add, &u->net);

	/*
	 * If the download got queued, also add the queueing information
	 *		--JA, 07/02/2003
	 */

	if (parq_upload_queued(u)) {

		u->cb_parq_arg.u = u;
		upload_http_extra_callback_add(u,
			parq_upload_add_headers, &u->cb_parq_arg);

		/*
		 * If the request seems to come from a browser, send back a small
		 * piece of body to automatically restart the download when we
		 * want it to be re-emitted.
		 */

		if (503 == code && u->from_browser) {
			static char buf[2048];
			char href[1024];
			char index_href[32];
			long retry;

			retry = delta_time(parq_upload_retry(u), tm_time());
			retry = MAX(0, retry);

			{
				char *uri;

				uri = url_escape(u->name);
				if (html_escape(uri, href, sizeof href) >= sizeof href) {
					/* If the escaped href is too long, leave it out. They
				 	 * might get an ugly filename but at least the URI
				 	 * works. */
					href[0] = '\0';
				}
				if (uri != u->name)
					HFREE_NULL(uri);
			}

			str_bprintf(index_href, sizeof index_href,
				"/get/%lu/", (ulong) u->file_index);
			str_bprintf(buf, sizeof buf,
				"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\">"
				"<html>"
				"<head>"
				"<meta http-equiv=\"Refresh\" content=\"%ld; url=%s%s\">"
				"<title>Download</title>"
				"<script type=\"text/javascript\">"
				"var i=%ld;"
				"function main(){"
					"if (i>=0){"
						"document.getElementById('x').innerHTML=i--;"
						"setTimeout(\"main();\", 1000);"
					"}"
				"};"
				"</script>"
				"</head>"
				"<body onload=\"main();\">"
				"<h1>%s</h1>"
				"<p>The download starts in <em id=\"x\">%ld</em> seconds.</p>"
				"</body>"
				"</html>"
					"\r\n",
					retry, '\0' != href[0] ? index_href : "", href,
					retry, product_get_name(), retry);
			upload_http_extra_line_add(u,
				"Content-Type: text/html; charset=utf-8\r\n");
			upload_http_extra_body_add(u, buf);
		}

		/*
		 * Force sending of X-GUID if passively queued and the request
		 * does not come from a browser.
		 *
		 * We remove first instead of calling the "add_once" version in case
		 * the callback was registered already with a NULL argument: we want
		 * to force emission so we need a non-NULL one.
		 */

		if (u->from_browser) {
			upload_http_extra_callback_remove(u, upload_xguid_add);
		} else if (u->status != GTA_UL_QUEUED) {
			upload_http_extra_callback_remove(u, upload_xguid_add);
			upload_http_extra_callback_add(u, upload_xguid_add,
				GINT_TO_POINTER(1));
		}
	} else if (!(u->is_followup || u->was_actively_queued)) {
		upload_http_extra_callback_add_once(u, upload_xguid_add, NULL);
	}

	/*
	 * If this is a pushed upload, and we are not firewalled, then tell
	 * them they can reach us directly by outputting an X-Host line.
	 */

	if (u->push && !GNET_PROPERTY(is_firewalled)) {
		upload_http_extra_callback_add(u, upload_http_xhost_add, NULL);
	}

	/*
	 * If they chose to advertise a hostname, include it in our reply.
	 */

	if (
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		/*
		 * If they are not actively queued, we force the emission of the
		 * hostname even if bandwidth is tight.
		 */

		upload_http_extra_callback_add(u, http_hostname_add,
			u->status != GTA_UL_QUEUED ? GINT_TO_POINTER(1) : NULL);
	}

	/*
	 * If `sf' is not null, propagate the SHA1 for the file if we have it,
	 * as well as the download mesh.
	 */
	if (u->sf && sha1_hash_available(u->sf)) {
		u->cb_sha1_arg.u = u;
		upload_http_extra_callback_add(u,
			upload_http_content_urn_add, &u->cb_sha1_arg);
	}

	/*
	 * Keep connection alive when activly queued
	 * 		-- JA, 22/4/2003
	 */
	u->keep_alive = GTA_UL_QUEUED == u->status;

	if (GNET_PROPERTY(upload_debug) >= 4) {
		g_debug(
			"sending code=%d to %s (%s) [status=%d]: %s",
			code,
			u->socket
				? host_addr_to_string(u->socket->addr) : "<no socket>",
			upload_vendor_str(u),
			u->status, reason);
		
	}

	upload_send_http_status(u, u->keep_alive, code, reason);
	u->error_sent = code;
}

/**
 * Send error message to requestor.
 *
 * This can only be done once per connection.
 */
static void
send_upload_error(struct upload *u, int code, const char *msg, ...)
{
	va_list args;

	upload_check(u);

	va_start(args, msg);
	send_upload_error_v(u, NULL, code, msg, args);
	va_end(args);
}

static void
upload_aborted_file_stats(const struct upload *u)
{
	g_return_if_fail(u);
	upload_check(u);

	if (
		UPLOAD_IS_SENDING(u) &&
		!u->browse_host &&
		!u->thex &&
		!u->accounted &&
		u->sf &&
		u->pos > u->skip
	) {
		upload_stats_file_aborted(u->sf, u->pos - u->skip);
	}
}

/**
 * The vectorized (message-wise) version of upload_remove().
 */
static void
upload_remove_v(struct upload *u, const char *reason, va_list ap)
{
	const char *logreason;
	char errbuf[1024];
	bool was_sending;
	va_list apcopy;

	upload_check(u);

	was_sending = UPLOAD_IS_SENDING(u);
	VA_COPY(apcopy, ap);

	if (reason != NULL && no_reason != reason) {
		str_vbprintf(errbuf, sizeof errbuf, reason, ap);
		logreason = errbuf;
	} else {
		if (u->error_sent) {
			str_bprintf(errbuf, sizeof(errbuf), "HTTP %d", u->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = N_("No reason given");
		}
	}

	if (!UPLOAD_IS_COMPLETE(u) && GNET_PROPERTY(upload_debug) > 1) {
		if (u->name) {
			g_debug(
				"ending upload of \"%s\" [%s bytes out] from %s (%s): %s",
				u->name,
				uint64_to_string(u->sent),
				u->socket
					? host_addr_to_string(u->socket->addr) : "<no socket>",
				upload_vendor_str(u),
				logreason);
		} else {
			g_debug(
				"ending upload [%s bytes out] from %s (%s): %s",
				uint64_to_string(u->sent),
				u->socket
					? host_addr_to_string(u->socket->addr) : "<no socket>",
				upload_vendor_str(u),
				logreason);
		}
	}

	/*
	 * If the upload is still connecting, we have not started sending
	 * any data yet, so we send an HTTP error code before closing the
	 * connection.
	 *		--RAM, 24/12/2001
	 *
	 * Push requests still connecting don't have anything to send, hence
	 * we check explicitely for GTA_UL_PUSH_RECEIVED.
	 *		--RAM, 31/12/2001
	 * 	Same goes for a parq QUEUE 'push' send.
	 *		-- JA, 12/04/2003
	 */

	if (
		UPLOAD_IS_CONNECTING(u) &&
		!u->error_sent &&
		u->status != GTA_UL_PUSH_RECEIVED && u->status != GTA_UL_QUEUE
	) {
		if (reason == NULL)
			logreason = reason = N_("Bad Request");
		send_upload_error(u, 400, "%s", logreason);
	}

	/*
	 * If we were sending data, and we have not accounted the download yet,
	 * then update the stats, not marking the upload as completed.
	 */

	upload_aborted_file_stats(u);

    if (!UPLOAD_IS_COMPLETE(u)) {
        if (UPLOAD_WAITING_FOLLOWUP(u))
            u->status = GTA_UL_CLOSED;
        else
            u->status = GTA_UL_ABORTED;
        upload_fire_upload_info_changed(u);
    }

	parq_upload_remove(u, was_sending, u->was_running);
	if (u->was_running)
		gnet_prop_decr_guint32(PROP_UL_RUNNING);

	/*
	 * Translation for the GUI happens here.
	 */

	if (reason != NULL && no_reason != reason) {
		str_vbprintf(errbuf, sizeof errbuf, _(reason), apcopy);
		logreason = errbuf;
	} else {
		logreason = NULL;
	}
	va_end(apcopy);

	upload_fire_upload_removed(u, logreason);
	upload_free_resources(u);
}

/**
 * Remove upload entry, log reason.
 *
 * If no status has been sent back on the HTTP stream yet, give them
 * a 400 error with the reason.
 *
 * @note The parameter "reason" is passed to gettext(). Do not pass an already
 * translated string, use N_("string") as the argument.
 */
void
upload_remove(struct upload *u, const char *reason, ...)
{
	va_list args;

	upload_check(u);

	va_start(args, reason);
	upload_remove_v(u, reason, args);
	va_end(args);
}

/**
 * Same as upload_remove() but without any printf argument checking.
 */
static void
upload_remove_nowarn(struct upload *u, const char *reason, ...)
{
	va_list args;

	upload_check(u);

	va_start(args, reason);
	upload_remove_v(u, reason, args);
	va_end(args);
}

/**
 * Utility routine.  Cancel the upload, sending back the HTTP error message.
 *
 * @note The parameter "msg" is passed to gettext(). Do not pass an already
 *       translated strings because it's sent as an HTTP response message.
 */
static void
upload_error_remove(struct upload *u, int code, const char *msg, ...)
{
	va_list args, errargs;

	upload_check(u);

	va_start(args, msg);

	VA_COPY(errargs, args);
	send_upload_error_v(u, NULL, code, msg, errargs);
	va_end(errargs);

	upload_remove_v(u, msg, args);
	va_end(args);
}

/**
 * Utility routine.  Cancel the upload, sending back the HTTP error message.
 * `ext' contains additionnal header information to propagate back.
 */
static void
upload_error_remove_ext(struct upload *u, const char *ext, int code,
	const char *msg, ...)
{
	va_list args, errargs;

	upload_check(u);

	va_start(args, msg);

	VA_COPY(errargs, args);
	send_upload_error_v(u, ext, code, msg, errargs);
	va_end(errargs);

	upload_remove_v(u, msg, args);

	va_end(args);
}

/**
 * This is used for HTTP/1.1 persistent connections.
 *
 * Move the upload back to a waiting state, until a new HTTP request comes
 * on the socket.
 */
static void
upload_wait_new_request(struct upload *u)
{
	/*
	 * File will be re-opened each time a new request is made.
	 */

	file_object_release(&u->file);	/* expect_http_header() expects this */
 	socket_tos_normal(u->socket);
	expect_http_header(u, GTA_UL_EXPECTING);
}

/**
 * Report HTTP error to remote host, but keep the connection alive so
 * that they can send a new request, unless we have reached the maximum
 * amount of errors on that connection.
 *
 * @attention
 * The ``msg'' string must not be translated as it is send back in HTTP
 * headers.  We'll call gettext() on it to translate it for logging in the
 * GUI. Callers should use N_("string") to get the English version yet mark
 * "string" for translation.
 */
static void
upload_send_error(struct upload *u, int code, const char *msg)
{
	if (u->error_count++ < MAX_ERRORS && u->keep_alive) {
		if (upload_send_http_status(u, TRUE, code, msg)) {
			struct upload *cu;
			if (u->special) {
				(*u->special->close)(u->special, FALSE);
				u->special = NULL;
			}
			u->reqnum++;
			cu = upload_clone(u);
			cu->last_was_error = TRUE;
			upload_wait_new_request(cu);
		}
	} else {
		upload_send_http_status(u, FALSE, code, msg);
	}
	upload_remove_nowarn(u, _(msg));
}

/**
 * Stop all uploads dealing with partial file `fi'.
 */
void
upload_stop_all(struct dl_file_info *fi, const char *reason)
{
	pslist_t *sl, *to_stop = NULL;
	int count = 0;

	g_return_if_fail(fi);
	file_info_check(fi);

	for (sl = list_uploads; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);

		if (u->file_info == fi) {
			to_stop = pslist_prepend(to_stop, u);
			count++;
		}
	}

	if (to_stop == NULL)
		return;

	if (GNET_PROPERTY(upload_debug)) {
		g_warning("stopping %d uploads for \"%s\": %s",
			count, fi->pathname, reason);
	}

	for (sl = to_stop; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);
		upload_remove_nowarn(u, reason);
	}

	pslist_free(to_stop);
}

/**
 * Extract User-Agent information out of the HTTP headers.
 */
static void
upload_request_handle_user_agent(struct upload *u, const header_t *header)
{
	const char *user_agent;

	upload_check(u);
	g_assert(header);

	/*
	 * We remember the first User-Agent we see for a given upload, so
	 * follow-up requests simply ignore the field.
	 */

	if (u->user_agent != NULL)
		return;

	user_agent = header_get(header, "User-Agent");
	if (user_agent == NULL) {
		/* Maybe they sent a Server: line, thinking they're a server? */
		user_agent = header_get(header, "Server");
	}
	if (NULL == user_agent || !is_strprefix(user_agent, "gtk-gnutella/")) {
		socket_disable_token(u->socket);
	}

	if (user_agent != NULL) {
		const char *token;
		bool faked;

		/*
		 * Extract User-Agent.
		 *
		 * X-Token: GTKG token
		 * User-Agent: whatever
		 * Server: whatever (in case no User-Agent)
		 */

		token = header_get(header, "X-Token");
	   	faked = !version_check(user_agent, token, u->addr);
		if (faked) {
			char name[1024];

			concat_strings(name, sizeof name, "!", user_agent, (void *) 0);
			u->user_agent = atom_str_get(name);
		} else
			u->user_agent = atom_str_get(user_agent);

		upload_fire_upload_info_changed(u);
	}
}

/***
 *** I/O header parsing callbacks.
 ***/

static void
err_line_too_long(void *obj, header_t *head)
{
	struct upload *u = cast_to_upload(obj);

	upload_request_handle_user_agent(u, head);
	upload_error_remove(u, 413, N_("Header too large"));
}

static void
err_header_error_tell(void *obj, int error)
{
	send_upload_error(cast_to_upload(obj), 413, "%s", header_strerror(error));
}

static void
err_header_error(void *obj, int error)
{
	upload_remove(cast_to_upload(obj),
		N_("Failed (%s)"), header_strerror(error));
}

static void
err_input_exception(void *obj, header_t *head)
{
	struct upload *u = cast_to_upload(obj);

	upload_request_handle_user_agent(u, head);
	upload_remove(u, N_("Failed (Input Exception)"));
}

static void
err_input_buffer_full(void *obj)
{
	upload_error_remove(cast_to_upload(obj), 500, N_("Input buffer full"));
}

static void
err_header_read_error(void *obj, int error)
{
	upload_remove(cast_to_upload(obj),
		N_("Failed (Input error: %s)"), g_strerror(error));
}

static void
err_header_read_eof(void *obj, header_t *head)
{
	struct upload *u = cast_to_upload(obj);

	u->error_sent = 999;		/* No need to send anything on EOF condition */
	upload_request_handle_user_agent(u, head);
	upload_remove(u, N_("Failed (EOF)"));
}

static void
err_header_extra_data(void *obj, header_t *head)
{
	struct upload *u = cast_to_upload(obj);

	upload_request_handle_user_agent(u, head);
	upload_error_remove(u, 400, N_("Extra data after HTTP header"));
}

static const struct io_error upload_io_error = {
	err_line_too_long,
	err_header_error_tell,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	err_header_extra_data,
};

static void
call_upload_request(void *obj, header_t *header)
{
	struct upload *u = cast_to_upload(obj);

	/*
	 * These are kept for follow-up requests, so that the UI can show
	 * what the last request was.
	 */
	shared_file_unref(&u->sf);
	shared_file_unref(&u->thex);
	atom_str_free_null(&u->name);
	HFREE_NULL(u->request);
	u->hevcnt = 0;

	upload_request(u, header);
}


/**
 * Create a new upload request, and begin reading HTTP headers.
 */
void
upload_add(struct gnutella_socket *s)
{
	struct upload *u;

	u = upload_create(s, FALSE);

	/*
	 * Read HTTP headers fully, then call upload_request() when done.
	 */

	io_get_header(u, &u->io_opaque, bsched_in_select_by_addr(s->addr),
		s, IO_HEAD_ONLY, call_upload_request, NULL, &upload_io_error);
}

/**
 * Callback invoked when we start reading the follow-up HTTP request.
 */
static void
move_to_ul_waiting(void *obj)
{
	struct upload *u = cast_to_upload(obj);

	u->status = GTA_UL_WAITING;
	upload_fire_upload_info_changed(u);
}

/**
 * Prepare reception of a full HTTP header, including the leading request.
 * Will call upload_request() when everything has been parsed.
 */
void
expect_http_header(struct upload *u, upload_stage_t new_status)
{
	struct gnutella_socket *s = u->socket;
	io_start_cb_t start_cb = NULL;

	upload_check(u);
	g_assert(NULL == u->file);		/* File not opened */

	/*
	 * Cleanup data structures if not already done.
	 */

	if (u->io_opaque) {
		io_free(u->io_opaque);
		u->io_opaque = NULL;
	}
	if (s->getline) {
		getline_free(s->getline);
		s->getline = NULL;
	}
	if (u->sf) {
		shared_file_check(u->sf);
	}
	u->browse_host = FALSE;

	/*
	 * Change status, with immediate GUI feedback.
	 */

	u->status = new_status;
	upload_fire_upload_info_changed(u);

	/*
	 * If we're expecting a new HTTP header after a successfully completed
	 * one, in other words if we're going to deal with a follow-up request,
	 * then we must take care to wait for the start of the next request
	 * before we send them a 408 back, should we timeout reading the whole
	 * request.
	 */

	if (new_status == GTA_UL_EXPECTING)
		start_cb = move_to_ul_waiting;
	else if (new_status == GTA_UL_QUEUED) {
		if (u->was_running) {
			gnet_prop_decr_guint32(PROP_UL_RUNNING);
			u->was_running = FALSE;
		}
	}

	/*
	 * We're requesting the reading of a "status line", which will be the
	 * HTTP request.  It will be stored in a created s->getline entry.
	 * Once we're done, we'll end-up in upload_request(): the path joins
	 * with the one used for direct uploading.
	 */

	io_get_header(u, &u->io_opaque, bsched_in_select_by_addr(s->addr),
		s, IO_SAVE_FIRST, call_upload_request, start_cb, &upload_io_error);
}

/**
 * Got confirmation that the connection to the remote host was OK.
 * Send the GIV/QUEUE string, then prepare receiving back the HTTP request.
 */
static void
upload_connect_conf(struct upload *u)
{
	char giv[MAX_LINE_SIZE];
	struct gnutella_socket *s;
	size_t rw;
	ssize_t sent;
	const guid_t *guid;

	upload_check(u);

	/*
	 * PARQ should send QUEUE information header here.
	 *		-- JA, 13/04/2003
	 */

	if (u->status == GTA_UL_QUEUE) {
		parq_upload_send_queue_conf(u);
		return;
	}

	g_assert(u->name);

	/*
	 * Send the GIV or PUSH string, using our servent GUID.
	 */

	guid = cast_to_guid_ptr_const(GNET_PROPERTY(servent_guid));

	if (u->g2) {
		rw = str_bprintf(giv, sizeof giv, "PUSH guid:%s\r\n\r\n",
				guid_hex_str(guid));
	} else {
		rw = str_bprintf(giv, sizeof giv, "GIV %lu:%s/file\n\n",
				(ulong) u->file_index, guid_hex_str(guid));
	}

	s = u->socket;
	sent = bws_write(bsched_out_select_by_addr(s->addr), &s->wio, giv, rw);
	if ((ssize_t) -1 == sent) {
		if (GNET_PROPERTY(upload_debug) > 1) g_warning(
			"unable to send back GIV for \"%s\" to %s: %m",
			u->name, host_addr_to_string(s->addr));
	} else if ((size_t) sent < rw) {
		if (GNET_PROPERTY(upload_debug)) g_warning(
			"only sent %zu out of %zu bytes of GIV for \"%s\" to %s",
			sent, rw, u->name, host_addr_to_string(s->addr));
	} else if (GNET_PROPERTY(upload_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent GIV to %s:", host_addr_to_string(s->addr));
		dump_string(stderr, giv, rw, "----");
	}

	if ((size_t) sent != rw) {
		upload_remove(u, N_("Unable to send GIV"));
		return;
	}

	/*
	 * We're now expecting HTTP headers on the connection we've made.
	 */

	expect_http_header(u, GTA_UL_HEADERS);
}

/**
 * Send back an HTTP error 404: file not found,
 * We try to pretty-print SHA1 URNs for PFSP files we no longer share...
 */
static void
upload_error_not_found(struct upload *u, const char *request)
{
	if (request && GNET_PROPERTY(upload_debug)) {
		const char *filename;
		struct sha1 sha1;

		if (urn_get_sha1(request, &sha1)) {
			filename = ignore_sha1_filename(&sha1);
		} else {
			filename = NULL;
		}
		g_warning("returned 404 to %s <%s>: %s (%s)",
			host_addr_to_string(u->socket->addr),
			upload_vendor_str(u), filename ? filename : request,
			filename ? request : "verbatim");
	}

	upload_send_error(u, 404, N_("Not Found"));
}

/**
 * Check that we got an HTTP request, extracting the protocol version.
 *
 * @return TRUE if ok or FALSE otherwise (upload must then be aborted)
 */
static bool
upload_http_version(struct upload *u, const char *request, size_t len)
{
	uint http_major, http_minor;

	/*
	 * Check HTTP protocol version. --RAM, 11/04/2002
	 */

	if (!http_extract_version(request, len, &http_major, &http_minor)) {
		return FALSE;
	}

	u->http_major = http_major;
	u->http_minor = http_minor;

	return TRUE;
}

/**
 * Make sure file to upload is still present on disk.
 *
 * @return TRUE if OK, FALSE otherwise with the upload removed.
 */
static bool
upload_file_present(struct upload *u, shared_file_t *sf)
{
	fileinfo_t *fi;
	filestat_t sb;

	upload_check(u);

	/*
	 * If uploading is disabled, don't access the disk.
	 * Act as if the file was present, the upload will be refused anyway.
	 */

	if (!upload_is_enabled())
		return TRUE;

	fi = shared_file_fileinfo(sf);
	if (stat(shared_file_path(sf), &sb))
		goto failure;

	if (!S_ISREG(sb.st_mode))
		goto failure;
		
	if (delta_time(shared_file_modification_time(sf), sb.st_mtime)) {
		shared_file_set_modification_time(sf, sb.st_mtime);
		if (NULL == fi) {
			request_sha1(sf);
			goto failure;
		} else if (fi->flags & FI_F_SEEDING) {
			/*
			 * If the download is finished, we must stop seeding as soon
			 * as the file is modified.
			 */
			goto failure;
		}
	}
	return TRUE;

failure:
	/*
	 * Probably a file shared via PFS, or they changed their library
	 * and did not rescan yet.  It's important to detect this now in
	 * case they are queued: no need to wait for them to get their
	 * upload slot to discover the file is not there!
	 *		--RAM, 2005-08-04
	 */

	if (fi) {
		struct dl_file_info *current_fi = u->file_info;
		/*
		 * Ensure we do NOT kill the current upload through upload_stop_all().
		 * The current upload "u" will be stopped anyway after we return FALSE.
		 *		--RAM, 2007-08-31
		 */

		u->file_info = NULL;
		file_info_upload_stop(fi, N_("File was modified"));
		u->file_info = current_fi;
	}
	return FALSE;
}

/**
 * Collect alternate locations.
 */
static void
upload_collect_locations(struct upload *u,
	const struct sha1 *sha1, const header_t *header)
{
	shared_file_t *sf;

	g_return_if_fail(sha1);

	sf = shared_file_by_sha1(sha1);
	sf = SHARE_REBUILDING == sf ? NULL : sf;

	if (NULL != sf || file_info_by_sha1(sha1)) {
		char *buf;
		gnet_host_t host;
		gnet_host_t *origin = NULL;

		if (host_is_valid(u->gnet_addr, u->gnet_port)) {
			/*
			 * The downloader is only an alt-loc if it lists itself in the
			 * X-Alt: header.  To determine this, we propagate the origin
			 * of the X-Alt header and if we find that address listed, we'll
			 * be able to flag the alt-loc as good since we're talking
			 * to the server that can provide it.
			 *		--RAM, 2012-12-03
			 */

			gnet_host_set(&host, u->gnet_addr, u->gnet_port);
			origin = &host;
		}

		huge_collect_locations(sha1, header, origin);

		buf = header_get(header, "X-Nalt");
		if (buf)
			dmesh_collect_negative_locations(sha1, buf, u->addr);
	}

	shared_file_unref(&sf);
}

/**
 * Get the shared_file to upload. "/get/<index>/" has already been extracted,
 * ``uri'' points to the filename after this. The same holds for the
 * file index, which is passed as ``idx''.
 *
 * @return -1 on error, 0 on success.
 */
static int
get_file_to_upload_from_index(struct upload *u, const header_t *header,
	const char *uri, uint idx)
{
	shared_file_t *sf;
	bool sent_sha1 = FALSE;
	struct sha1 sha1;

	upload_check(u);
	g_assert(NULL == u->sf);

	/*
	 * We must be cautious about file index changing between two scans,
	 * which may happen when files are moved around on the local library.
	 * If we serve the wrong file, and it's a resuming request, this will
	 * result in a corrupted file!
	 *		--RAM, 26/09/2001
	 *
	 * We now support URL-escaped queries.
	 *		--RAM, 16/01/2002
	 */

	sf = shared_file(idx);		/* Reference-counted */

	if (SHARE_REBUILDING == sf)
		goto library_rebuilt;

    atom_str_change(&u->name, uri);

	/*
	 * If we have a X-Gnutella-Content-URN, check whether we got a valid
	 * SHA1 URN in there and extract it.
	 */
	{
		const char *urn = header_get(header, "X-Gnutella-Content-URN");

		if (NULL == urn)
			urn = header_get(header, "X-Content-URN");
		if (urn)
			sent_sha1 = dmesh_collect_sha1(urn, &sha1);
	}

	/*
	 * If they sent a SHA1, look whether we got a matching file.
	 * If we do, let them know the URL changed by returning a 301, otherwise
	 * it's a 404.
	 */

	if (sent_sha1) {
		shared_file_t *sfn;
		
		if (spam_sha1_check(&sha1)) {
			goto not_found;
		}

		/*
		 * If they sent a SHA1, maybe they have a download mesh as well?
		 *
		 * We ignore any mesh information when the SHA1 is not present
		 * because we cannot be sure that they are exact replicate of the
		 * file requested here.
		 *
		 *		--RAM, 19/06/2002
		 */

		upload_collect_locations(u, &sha1, header);

		/*
		 * They can share serveral clones of the same files, i.e. bearing
		 * distinct names yet having the same SHA1.  Therefore, check whether
		 * the SHA1 matches with what we found so far, and if it does,
		 * we found what they want.
		 */

		if (sf && sha1_hash_available(sf)) {
			if (!sha1_hash_is_uptodate(sf)) {
				shared_file_unref(&sf);
				goto sha1_recomputed;
			}
			if (sha1_eq(&sha1, shared_file_sha1(sf)))
				goto found;
		}

		/*
		 * Look whether we know this SHA1 at all, and compare the results
		 * with the file we found, if any.  Note that `sf' can be NULL at
		 * this point, in which case we'll redirect them with 301 if we
		 * know the hash.
		 */

		sfn = shared_file_by_sha1(&sha1);		/* Reference-counted */

		/*
		 * Since shared_file(idx) and shared_file_by_sha1(sha1) use different
		 * logics to determine whether the library is being rebuilt, we cannot
		 * blindly assert that shared_file_by_sha1() will not report a
		 * SHARE_REBUILDING condition when shared_file() did not above...
		 *		--RAM, 2012-11-12
		 */

		if (SHARE_REBUILDING == sfn)
			goto library_rebuilt;

		if (sfn && sf != sfn) {
			char location[1024];
			char *escaped;

			if (!sha1_hash_is_uptodate(sfn)) {
				shared_file_unref(&sfn);
				goto sha1_recomputed;
			}

			/*
			 * Be nice to pushed downloads: returning a 301 currently means
			 * a connection close, and they might not be able to reach us.
			 * Transparently remap their request.
			 *
			 * We don't do it for regular connections though, because servents
			 * MUST be prepared to deal with redirection requests.
			 *
			 *		--RAM, 14/10/2002
			 */

			if (u->push) {
				if (GNET_PROPERTY(upload_debug) > 1)
					g_debug("INDEX FIXED (push, SHA1 = %s): "
						"requested %u, serving %u: %s",
						sha1_base32(&sha1), idx,
						(uint) shared_file_index(sfn),
						shared_file_path(sfn));
				shared_file_unref(&sf);
				sf = sfn;
				goto found;
			}

			/*
			 * Be nice for PFSP as well.  They must have learned about
			 * this from an alt-loc, and alt-locs we emit for those partially
			 * shared files are URNs.  Why did they request it by name?
			 *		--RAM, 12/10/2003
			 */

			if (shared_file_is_partial(sfn)) {
				if (GNET_PROPERTY(upload_debug) > 1)
					g_debug("REQUEST FIXED (partial, SHA1 = %s): "
						"requested \"%s\", serving \"%s\"",
						sha1_base32(&sha1), u->name,
						shared_file_path(sfn));
				shared_file_unref(&sf);
				sf = sfn;
				goto found;
			}

			escaped = url_escape(shared_file_name_nfc(sfn));

			str_bprintf(location, sizeof(location),
				"Location: /get/%lu/%s\r\n",
				(ulong) shared_file_index(sfn), escaped);

			if (escaped != shared_file_name_nfc(sfn)) {
				HFREE_NULL(escaped);
			}

			shared_file_unref(&sf);
			u->sf = sfn;
			upload_error_remove_ext(u, location, 301, N_("Moved Permanently"));
			return -1;
		}

		shared_file_unref(&sfn);

		if (NULL == sf)
			goto urn_not_found;

		/* FALL THROUGH */
	}

	/*
	 * If `sf' is NULL, the index was incorrect.
	 *
	 * Maybe we have a unique file with the same basename.  If we do,
	 * transparently return it instead of what they requested.
	 *
	 * We don't return a 301 in that case because the user did not supply
	 * the X-Gnutella-Content-Urn.  Therefore it's an old servent, and it
	 * cannot know about the new 301 return I've introduced.
	 *
	 * (RAM notified the GDF about 301 handling on June 5th, 2002 only)
	 */

	if (sf == NULL) {
		sf = shared_file_by_name(u->name);	/* Reference counts ``sf'' */

		g_assert(sf != SHARE_REBUILDING);	/* Or we'd have trapped above */

		if (GNET_PROPERTY(upload_debug) > 1) {
			if (sf)
				g_debug("BAD INDEX FIXED: requested %u, serving %u: %s",
					idx, (uint) shared_file_index(sf), shared_file_path(sf));
			else
				g_debug("BAD INDEX NOT FIXED: requested %u: %s",
					idx, u->name);
		}

	} else if (0 != strcmp(u->name, shared_file_name_nfc(sf))) {
		shared_file_t *sfn = shared_file_by_name(u->name);

		g_assert(sfn != SHARE_REBUILDING);	/* Or we'd have trapped above */

		if (GNET_PROPERTY(upload_debug) > 1) {
			if (sfn)
				g_debug("INDEX FIXED: requested %u, serving %u: %s",
					idx, (uint) shared_file_index(sfn),
					shared_file_path(sfn));
			else
				g_debug("INDEX MISMATCH: requested %u: %s (has %s)",
					idx, u->name, shared_file_name_nfc(sf));
		}

		shared_file_unref(&sf);
		if (NULL == sfn) {
			upload_send_error(u, 404, N_("File index/name mismatch"));
			return -1;
		} else
			sf = sfn;			/* Ref-counted by shared_file_by_name() */
	}

	/*
	 * At this point, either ``sf'' is NULL or it has been ref-counted.
	 */

	if (NULL == sf || !upload_file_present(u, sf)) {
		shared_file_unref(&sf);
		goto not_found;
	}

found:
	g_assert(sf != NULL);
	u->sf = sf;				/* Already ref-counted */
	return 0;

urn_not_found:
	upload_send_error(u, 404, N_("URN Not Found (urn:sha1)"));
	return -1;

sha1_recomputed:
	upload_send_error(u, 503, N_("SHA1 is being recomputed"));
	return -1;

not_found:
	upload_error_not_found(u, uri);
	return -1;

library_rebuilt:
	/* Retry-able by user, hence 503 */
	upload_error_remove(u, 503, N_("Library being rebuilt"));
	return -1;
}

static void
upload_request_tth(shared_file_t *sf)
{
	if (!shared_file_is_partial(sf) && NULL == shared_file_tth(sf)) {
		request_tigertree(sf, TRUE);
	}
}

static bool
upload_request_tth_matches(shared_file_t *sf, const struct tth *tth)
{
	if (NULL == tth || NULL == shared_file_tth(sf)) {
		return TRUE;
	} else {
		return tth_eq(tth, shared_file_tth(sf));
	}
}

/**
 * Get the shared_file to upload from a given URN.
 * @return -1 on error, 0 on success.
 */
static int
get_file_to_upload_from_urn(struct upload *u, const header_t *header,
	const char *uri)
{
	struct tth tth_buf, *tth = NULL;
	struct sha1 sha1;
	shared_file_t *sf;

	upload_check(u);
	g_assert(NULL == u->sf);

	if (!uri)
		goto malformed;

	u->n2r = TRUE;		/* Remember we saw an N2R request */

	if (urn_get_bitprint(uri, strlen(uri), &sha1, &tth_buf)) {
		tth = &tth_buf;
	} else if (urn_get_sha1(uri, &sha1)) {
		tth = NULL;
	} else {
		goto malformed;
	}

	if (spam_sha1_check(&sha1))
		goto not_found;

	upload_collect_locations(u, &sha1, header);

	/*
	 * Note: if the file was fully completed and is being seeded, then
	 * "sf" will not be NULL and we'll get a proper filename in the traces
	 * and in the GUI.
	 *
	 * However, if the file is purged (i.e. no longer seeded), or if we
	 * restart GTKG, we won't be able to associate a filename with a SHA1
	 * N2R request.  We use the information stored in the "done.sha1" file
	 * to be able to map the SHA1 back to a filename.
	 *		--RAM, 2005-08-01, 2007-08-25
	 */

	sf = shared_file_by_sha1(&sha1);		/* Reference-counted */

	if (sf == NULL || sf == SHARE_REBUILDING) {
		const char *filename;

		filename = ignore_sha1_filename(&sha1);
 		atom_str_change(&u->name, filename ? filename : uri);
	} else {
 		atom_str_change(&u->name, shared_file_name_nfc(sf));
	}

	if (sf == SHARE_REBUILDING) {
		/* Retry-able by user, hence 503 */
		upload_error_remove(u, 503, N_("Library being rebuilt"));
		return -1;
	}

	if (sf == NULL) {
		upload_error_not_found(u, uri);
		return -1;
	} else if (!sha1_hash_is_uptodate(sf)) {
		upload_send_error(u, 503, N_("SHA1 is being recomputed"));
		shared_file_unref(&sf);
		return -1;
	} else if (!upload_file_present(u, sf)) {
		shared_file_unref(&sf);
		goto not_found;
	}

	if (!upload_request_tth_matches(sf, tth)) {
		shared_file_unref(&sf);
		goto not_found;
	}

	upload_request_tth(sf);
	u->sf = sf;
	return 0;

malformed:
	if (GNET_PROPERTY(upload_debug)) {
		g_warning("malformed URN \"%s\" in /uri-res/N2R request sent by %s",
			NULL_STRING(uri), upload_host_info(u));
	}
	upload_error_remove(u, 400, N_("Malformed URN in /uri-res/N2R request"));
	return -1;

not_found:
	upload_error_not_found(u, uri);			/* Unknown URN => not found */
	return -1;
}

/**
 * Get the shared_file to upload from a given URN.
 * @return -1 on error, 0 on success.
 */
static int
get_thex_file_to_upload_from_urn(struct upload *u, const char *uri)
{
	struct tth tth_buf, *tth = NULL;
	struct sha1 sha1;
	shared_file_t *sf;

	upload_check(u);
	g_assert(NULL == u->sf);

	if (!uri)
		goto malformed;

	u->n2r = TRUE;		/* Remember we saw an N2R request */

	if (urn_get_bitprint(uri, strlen(uri), &sha1, &tth_buf)) {
		tth = &tth_buf;
	} else if (urn_get_sha1(uri, &sha1)) {
		tth = NULL;
	} else {
		goto malformed;
	}

	if (spam_sha1_check(&sha1)) {
		goto not_found;
	}

	sf = shared_file_by_sha1(&sha1);
	if (SHARE_REBUILDING == sf) {
		/* Retry-able by user, hence 503 */
		atom_str_change(&u->name, bitprint_to_urn_string(&sha1, tth));
		upload_error_remove(u, 503, N_("Library being rebuilt"));
		return -1;
	}
	if (sf == NULL) {
		atom_str_change(&u->name, bitprint_to_urn_string(&sha1, tth));
		goto not_found;
	}
	atom_str_change(&u->name, shared_file_name_nfc(sf));

	if (shared_file_is_partial(sf)) {
		/*
		 * As long as we cannot verify the full TTH we should probably
		 * not pass it on even if we already fetched THEX data.
		 */
		shared_file_unref(&sf);
		goto not_found;
	}
	
	if (!sha1_hash_is_uptodate(sf)) {
		upload_send_error(u, 503, N_("SHA1 is being recomputed"));
		shared_file_unref(&sf);
		return -1;
	}

	if (!upload_request_tth_matches(sf, tth)) {
		shared_file_unref(&sf);
		goto not_found;
	}

	if (NULL == shared_file_tth(sf)) {
		upload_request_tth(sf);
		shared_file_unref(&sf);
		goto tth_recomputed;
	}

	if (0 == tth_cache_lookup(shared_file_tth(sf), shared_file_size(sf))) {
		shared_file_set_tth(sf, NULL);
		upload_request_tth(sf);
		shared_file_unref(&sf);
		goto tth_recomputed;
	}

	u->thex = sf;
	return 0;

not_found:
	upload_error_not_found(u, uri);			/* Unknown URN => not found */
	return -1;

malformed:
	if (GNET_PROPERTY(upload_debug)) {
		g_warning("malformed URN \"%s\" in /uri-res/N2X request sent by %s",
			NULL_STRING(uri), upload_host_info(u));
	}
	upload_error_remove(u, 400, N_("Malformed URN in /uri-res/N2X request"));
	return -1;

tth_recomputed:
	upload_send_error(u, 503, N_("TTH is being computed"));
	return -1;
}

/**
 * A dispatcher function to call either get_file_to_upload_from_index or
 * get_file_to_upload_from_sha1 depending on the syntax of the request.
 *
 * @param u a valid struct upload.
 * @param header a valid header_t.
 * @param uri the URI part of the HTTP request, URL-encoding has already
 *        been decoded.
 * @param search the search part of the HTTP request or NULL if none. This
 *        string is still URL-encoded to preserve the '&' boundaries.
 *
 * @return -1 on error, 0 on success. When -1 is returned, we have sent the
 * 			error back to the client.
 */
static int
get_file_to_upload(struct upload *u, const header_t *header,
	char *uri, char *search)
{
	const char *endptr;

	upload_check(u);
	g_assert(NULL == u->sf);

    if (u->name == NULL)
        u->name = atom_str_get(uri);

	if (NULL != (endptr = is_strprefix(uri, "/get/"))) {
		uint32 idx;
		int error;

		idx = parse_uint32(endptr, &endptr, 10, &error);
		if (
			!error &&
			'/' == endptr[0] &&
			'\0' != endptr[1] &&
			NULL == strchr(&endptr[1], '/')
		) {
			endptr = deconstify_char(&endptr[1]);
			return get_file_to_upload_from_index(u, header, endptr, idx);
		}
	} else if (NULL != (endptr = is_strprefix(uri, "/uri-res/"))) {
		if (0 == strcmp(endptr, "N2R")) {
			return get_file_to_upload_from_urn(u, header, search);
		} else if (0 == strcmp(endptr, "N2X")) {
			return get_thex_file_to_upload_from_urn(u, search);
		}
	} else {
		shared_file_t *sf = shared_special(uri);

		if (sf) {
			u->sf = shared_file_ref(sf);
			return 0;
		}
	}

	upload_error_not_found(u, uri);
	return -1;
}

/***
 *** TX deflate and link callbacks.
 ***/

static void
upload_tx_error(void *obj, const char *reason, ...)
{
	struct upload *u = cast_to_upload(obj);
	va_list args;

	va_start(args, reason);
	socket_eof(u->socket);
	upload_remove_v(u, reason, args);
	va_end(args);
}

static const struct tx_deflate_cb upload_tx_deflate_cb = {
	NULL,				/* add_tx_deflated */
	upload_tx_error,	/* shutdown */
	NULL,				/* flow_control */
};

static void
upload_tx_add_written(void *obj, int amount)
{
	struct upload *u = cast_to_upload(obj);

	if (u->browse_host) {
		u->file_size += amount;
		u->end = u->file_size;
	}
}

static const struct tx_link_cb upload_tx_link_cb = {
	upload_tx_add_written,	/* add_tx_written */
	upload_tx_error,		/* eof_remove */
	upload_tx_error,		/* eof_shutdown */
	NULL,					/* unflushq -- XXX rename it, it's node specific */
};

/**
 * Check whether remote end supports deflate or gzip, using a combination
 * of both HTTP headers and User-Agent to screen out known-to-be-broken agents.
 *
 * @return The chosen compression method.
 *         0: no compression,
 *         BH_F_GZIP: gzip,
 *         BH_F_DEFLATE: deflate
 */
static int
select_encoding(const header_t *header)
{
    const char *buf;

    buf = header_get(header, "Accept-Encoding");
	if (buf) {
		if (strtok_has(buf, ",", "deflate")) {
			const char *ua;
			
			ua = header_get(header, "User-Agent");
			if (NULL == ua || NULL == strstr(ua, "AppleWebKit"))
				return BH_F_DEFLATE;
		}

		if (strtok_has(buf, ",", "gzip"))
			return BH_F_GZIP;
	}

    return 0;
}

/**
 * Extract X-Downloaded from header, returning 0 if none.
 *
 * The X-Downloaded header lets us better estimate the time an upload request
 * can take if we are the only source for the file.
 */
static filesize_t
extract_downloaded(const struct upload *u, const header_t *header)
{
	const char *buf;
	filesize_t downloaded;
	int error;

	buf = header_get(header, "X-Downloaded");
	if (!buf)
		return 0;

	downloaded = parse_uint64(buf, NULL, 10, &error);
	if (error) {
		if (GNET_PROPERTY(upload_debug))
			g_warning("cannot parse X-Downloaded \"%s\" sent by %s",
				buf, upload_host_info(u));
		return 0;
	}

	return downloaded;
}

/**
 * Checks whether the HTTP client can handle the transfer-encoding "chunked".
 * @return TRUE if the client seems to support it and otherwise FALSE.
 */
static bool
supports_chunked(const struct upload *u, const header_t *header)
{
	bool chunked;

	upload_check(u);
	g_assert(header);

	if (u->http_major > 1 || (u->http_major == 1 && u->http_minor >= 1)) {
    	const char *buf;

		/*
		 * It's assumed that LimeWire-based clients cannot handle 
		 * "chunked" properly. This is at least true for their Browse Host
		 * support.
		 *
		 * BearShare apparently does not support it either, at least for
		 * THEX (N2X) transfers.
		 */
    	buf = header_get(header, "User-Agent");
		chunked = NULL == buf || (
			!is_strprefix(buf, "LimeWire") &&
			!is_strprefix(buf, "BearShare") &&
			!is_strprefix(buf, "FrostWire"));
	} else {
		/* HTTP/1.0 and older doesn't know about "chunked" */
		chunked = FALSE;
	}

	return chunked;
}

/**
 * Extract firewalled node information from the X-FW-Node-Info header string
 * and pass that information to the download side, in case they know about
 * that node.
 */
static void
extract_fw_node_info(struct upload *u, const header_t *header)
{
	struct guid guid;
	bool seen_port_ip = FALSE;
	bool seen_guid = FALSE;
	const char *tok;
	const char *msg = NULL;
	const char *buf;
	strtok_t *st;
	host_addr_t addr;
	uint16 port;

	buf = header_get(header, "X-FW-Node-Info");
	if (NULL == buf)
		return;

	/*
	 * An X-FW-Node-Info header looks like this:
	 *
	 *  X-FW-Node-Info: 9DBC52EEEBCA2C8A79036D626B959900;fwt/1;
	 *		26252:85.182.49.3;
	 *		pptls=E;69.12.88.95:1085;64.53.20.48:804;66.17.23.159:343
	 *
	 * We learn the GUID of the node, its address (in reversed port:IP format)
	 * and the push-proxies.
	 */

	st = strtok_make_strip(buf);

	while ((tok = strtok_next(st, ";"))) {

		/* GUID is the first item we expect */
		if (!seen_guid) {
			if (!hex_to_guid(tok, &guid)) {
				msg = "bad leading GUID";
				break;
			}
			if (guid_eq(&guid, GNET_PROPERTY(servent_guid))) {
				gnet_stats_inc_general(GNR_OWN_GUID_COLLISIONS);
				msg = "node bears our GUID";
				break;
			}
			seen_guid = TRUE;
			continue;
		}

		/* Skip "options", stated as "word/x.y" */
		if (strstr(tok, "/"))
			continue;

		/* End at first "pptsl=" indication (remaining are push-proxies) */
		if (is_strcaseprefix(tok, "pptls="))
			break;

		/*
		 * If we find a valid port:IP host, then these are the remote
		 * server address and port.
		 */

		if (string_to_port_host_addr(tok, NULL, &port, &addr)) {
			seen_port_ip = TRUE;
			break;
		}
	}

	strtok_free(st);

	if (!seen_guid && NULL == msg)
		msg = "missing GUID";

	if (msg != NULL) {
		if (GNET_PROPERTY(upload_debug))
			g_warning("could not parse 'X-FW-Node-Info: %s' from %s: %s",
				buf, upload_host_info(u), msg);

		return;
	}

	/*
	 * We got the GUID, but we may be missing the address and port.
	 */

	if (!seen_port_ip) {
		addr = u->socket->addr;
		port = 0;
	} else if (is_private_addr(addr)) {
		addr = u->socket->addr;
	}

	if (u->guid != NULL) {
		if (!guid_eq(u->guid, &guid)) {
			if (GNET_PROPERTY(upload_debug)) {
				g_warning("U/L spotted GUID change (%s => %s) from %s",
					guid_hex_str(u->guid), guid_to_string(&guid),
					upload_host_info(u));
			}
			atom_guid_free(u->guid);
			u->guid = atom_guid_get(&guid);
		}
	} else {
		u->guid = atom_guid_get(&guid);
	}

	/*
	 * Propagate information to the download layer so that we may further
	 * consolidate servers for which we do not have a GUID yet.
	 */

	download_got_fw_node_info(u->guid, addr, port, buf);
}

/**
 * Prepare the browse host request.
 *
 * @return 0 if we may go on, -1 if we've replied to the remote
 * host and either expect a new request now or terminated the connection.
 */
static int
prepare_browse_host_upload(struct upload *u, header_t *header,
	const char *host)
{
	char *buf;

	u->browse_host = TRUE;
	u->name = atom_str_get(_("<Browse Host Request>"));

	if (GNET_PROPERTY(upload_debug) > 1)
		g_debug("BROWSE request from %s (%s)",
			host_addr_to_string(u->socket->addr),
			upload_vendor_str(u));

	if (!GNET_PROPERTY(browse_host_enabled)) {
		if (ctl_limit(u->socket->addr, CTL_D_BROWSE | CTL_D_STEALTH)) {
			upload_remove(u, N_("Limited connection"));
		} else {
			upload_send_error(u, 403, N_("Browse Host Disabled"));
		}
		return -1;
	}

	if (ctl_limit(u->socket->addr, CTL_D_BROWSE)) {
		if (ctl_limit(u->socket->addr, CTL_D_NORMAL)) {
			send_upload_error(u, 403, N_("Browse Host Disabled"));
		} else if (!ctl_limit(u->socket->addr, CTL_D_STEALTH)) {
			send_upload_error(u, 404, N_("Limiting connections from %s"),
				gip_country_name(u->socket->addr));
		}
		upload_remove(u, N_("Limited connection"));
		return -1;
	}

	/*
	 * If we are advertising our hostname in query hits and they are not
	 * addressing our host directly, then redirect them to that.
	 */

	if (
		host &&
		GNET_PROPERTY(give_server_hostname) &&
		'\0' != GNET_PROPERTY(server_hostname)[0] &&
		!is_strprefix(host, GNET_PROPERTY(server_hostname)) &&
		upload_likely_from_browser(header)
	) {
		static const char fmt[] = "Location: http://%s:%u/\r\n";
		static char location[sizeof fmt + UINT16_DEC_BUFLEN + MAX_HOSTLEN];

		str_bprintf(location, sizeof location, fmt,
			GNET_PROPERTY(server_hostname), GNET_PROPERTY(listen_port));
		upload_http_extra_line_add(u, location);
		upload_send_http_status(u, FALSE, 301, "Redirecting");
		upload_remove(u, N_("Redirected to %s:%u"),
			GNET_PROPERTY(server_hostname), GNET_PROPERTY(listen_port));
		return -1;
	}

	buf = header_get(header, "If-Modified-Since");
	if (buf) {
		time_t t;

		t = date2time(buf, tm_time());
		if (
			(time_t) -1 != t &&
			delta_time((time_t) GNET_PROPERTY(library_rescan_finished), t) <= 0 
		) {
			upload_send_error(u, 304, N_("Not Modified"));
			return -1;
		}
	}

	/*
	 * Add a Last-Modified header containing the time of the last successful
	 * library scan.  This will allow browsers to issue conditional requests
	 * on "reload".
	 */

	{
		static char lm_buf[64];

		str_bprintf(lm_buf, sizeof lm_buf, "Last-Modified: %s\r\n",
		   timestamp_rfc1123_to_string(GNET_PROPERTY(library_rescan_finished)));
		upload_http_extra_line_add(u, lm_buf);
	}

	return 0;
}

/**
 * Check whether upload is already running.  If found but stalling, kick it
 * out as we have a replacement being asked by the remote end.
 *
 * @return TRUE if upload is a duplicate, FALSE if it isn't or if the old
 * duplicate was stalling and thus kicked out.
 */
static bool
upload_is_already_downloading(struct upload *upload)
{
	pslist_t *sl, *to_remove = NULL;
	bool result = FALSE;

	g_assert(upload);

	/*
	 * Ensure that noone tries to download the same file twice, and
	 * that they don't get beyond the max authorized downloads per IP.
	 * NB: SHA1 are atoms, so it's OK to compare their addresses.
	 *
	 * This needs to be done before the upload enters PARQ. PARQ doesn't
	 * handle multiple uploads for the same file very well as it tries to
	 * keep 1 pointer to the upload structure as long as that structure
	 * exists.
	 * 		-- JA 12/7/'03
	 */

	for (sl = list_uploads; sl; sl = pslist_next(sl)) {
		struct upload *up = cast_to_upload(sl->data);

		if (up == upload)
			continue;				/* Current upload is already in list */
		if (!UPLOAD_IS_SENDING(up) && up->status != GTA_UL_QUEUED)
			continue;
		if (
			host_addr_equal(up->socket->addr, upload->socket->addr) && (
				(up->file_index != URN_INDEX &&
				 up->file_index == upload->file_index) ||
				(upload->sha1 && up->sha1 == upload->sha1)
			)
		) {
			/*
			 * If the duplicate upload we have is stalled or showed signs
			 * of early stalling, the remote end might have seen no data
			 * and is trying to reconnect.  Kill that old upload.
			 *		--RAM, 07/12/2003
			 */

			if (0 == (up->flags & (UPLOAD_F_STALLED|UPLOAD_F_EARLY_STALL))) {
				result = TRUE;
				break;
			}
			to_remove = pslist_prepend(to_remove, up);
		}
	}

	if (!result) {
		/*
		 * Kill pre-stalling or stalling uploads we spotted as being
		 * identical to their current request.  There should be only one
		 * at most.
		 */

		for (sl = to_remove; sl; sl = pslist_next(sl)) {
			struct upload *up = cast_to_upload(sl->data);

			if (GNET_PROPERTY(upload_debug)) g_warning(
				"stalling connection to %s (%s) replaced after %s bytes sent",
				host_addr_to_string(up->addr), upload_vendor_str(up),
				uint64_to_string(up->sent));

			upload_remove(up, N_("Stalling upload replaced"));
		}
	}

	pslist_free(to_remove);
	return result;
}

/**
 * Handle request for a shared file.
 *
 * @return TRUE if we're going to actually serve the request.
 */
static bool
upload_request_for_shared_file(struct upload *u, const header_t *header)
{
	filesize_t range_skip = 0, range_end = 0;
	bool range_unavailable = FALSE;
	const struct sha1 *sha1 = NULL;
	const char *buf;
	time_t now = tm_time();
	bool parq_allows = FALSE;
    uint32 idx = 0;
	bool switched = FALSE;

	upload_check(u);
	g_assert(u->sf);

	upload_stats_file_requested(u->sf);

	idx = shared_file_index(u->sf);
	sha1 = sha1_hash_available(u->sf) ? shared_file_sha1(u->sf) : NULL;

	/*
	 * If we pushed this upload, and they are not requesting the same
	 * file, that's OK, but warn.
	 *		--RAM, 31/12/2001
	 */

	if (u->push && idx != u->file_index && GNET_PROPERTY(upload_debug)) {
		g_warning("host %s sent PUSH for %u (%s), now requesting %u (%s)",
				host_addr_to_string(u->addr), u->file_index, u->name, idx,
				shared_file_name_nfc(u->sf));
	}

	/*
	 * Detect resource switching among plain files.
	 */

	if (u->flags & UPLOAD_F_WAS_PLAIN) {
		if (u->sha1) {
			if (u->sha1 != sha1) {
				switched = TRUE;
				gnet_stats_inc_general(GNR_CLIENT_PLAIN_RESOURCE_SWITCHING);
				if (sha1)
					atom_sha1_change(&u->sha1, sha1);
				else
					atom_sha1_free_null(&u->sha1);
			}
		} else if (u->file_index != idx) {
			switched = TRUE;
			gnet_stats_inc_general(GNR_CLIENT_PLAIN_RESOURCE_SWITCHING);
		}
	}

	/*
	 * When changing resources, clear u->last_demsh since this relates
	 * to the previous resource.
	 */

	if (switched) {
		u->last_dmesh = 0;
	}

	/*
	 * We already have a non-NULL u->name in the structure, because we
	 * saved the uri there or the name from a push request.
	 * However, we want to display the actual name of the shared file.
	 *		--Richard, 20/11/2002
	 */

	u->file_index = idx;
	/* Identify file for follow-up reqs */
	if (!u->sha1 && sha1) {
		u->sha1 = atom_sha1_get(sha1);
	}
	atom_str_change(&u->name, shared_file_name_nfc(u->sf));
	/* NULL unless partially shared file */
	u->file_info = shared_file_fileinfo(u->sf);

	u->file_size = shared_file_size(u->sf);

	if (!u->head_only && upload_is_already_downloading(u)) {
		upload_send_error(u, 409, N_("Already downloading this file"));
		return FALSE;
	}

	/*
	 * Range: bytes=10453-23456
	 */

	buf = header_get(header, "Range");
	if (buf && shared_file_size(u->sf) > 0) {
		enum http_range_extract_status rs;

		rs = http_range_extract_first("Range", buf,
			shared_file_size(u->sf), u->user_agent,
			&range_skip, &range_end);

		if (HTTP_RANGE_NONE == rs) {
			if (GNET_PROPERTY(upload_debug)) {
				g_warning("cannot parse Range \"%s\" sent by %s",
					buf, upload_host_info(u));
			}
			upload_error_remove(u, 400, N_("Malformed Range request"));
			return FALSE;
		}

		/*
		 * We don't properly support multiple ranges yet.
		 * Just pick the first one, but warn so we know when people start
		 * requesting multiple ranges at once.
		 *		--RAM, 27/01/2003
		 */

		if (HTTP_RANGE_MULTI == rs) {
			if (GNET_PROPERTY(upload_debug)) {
				g_warning("%s requested several ranges for \"%s\": %s",
					upload_host_info(u), shared_file_name_nfc(u->sf), buf);
			}
		}

		g_assert(range_skip <= range_end);
		g_assert(range_end < shared_file_size(u->sf));
	} else {
		range_end = u->file_size - 1;
	}

	/*
	 * PFSP-server: restrict the end of the requested range if the file
	 * we're about to upload is only partially available.  If the range
	 * is not yet available, signal it but don't break the connection.
	 *		--RAM, 11/10/2003
	 */

	if (
		shared_file_is_partial(u->sf) &&
		!file_info_restrict_range(shared_file_fileinfo(u->sf),
				range_skip, &range_end)
	) {
		g_assert(GNET_PROPERTY(pfsp_server) || GNET_PROPERTY(pfsp_rare_server));
		range_unavailable = TRUE;
	}

	u->skip = range_skip;
	u->end = range_end;
	u->pos = range_skip;

	/*
	 * When requested range is invalid, the HTTP 416 reply should contain
	 * a Content-Range header giving the total file size, so that they
	 * know the limits of what they can request.
	 *
	 * XXX due to the use of http_range_parse() above, the following can
	 * XXX no longer trigger here.  However, http_range_parse() should be
	 * XXX able to report out-of-range errors so we can report a true 416
	 * XXX here.  Hence I'm not removing this code.  --RAM, 11/10/2003
	 */

	if (range_skip >= u->file_size || range_end >= u->file_size) {
		u->cb_416_arg.u = u;
		upload_http_extra_callback_add(u, upload_416_extra, &u->cb_416_arg);
		upload_send_error(u, 416, N_("Requested range not satisfiable"));
		return FALSE;
	}

	/*
	 * If the requested range was determined to be unavailable, signal it
	 * to them.  Break the connection if it was a HEAD request, but allow
	 * them an extra request if the last one was for a valid range.
	 *		--RAM, 11/10/2003
	 */

	if (range_unavailable) {
		g_assert(sha1_hash_available(u->sf));
		g_assert(GNET_PROPERTY(pfsp_server) || GNET_PROPERTY(pfsp_rare_server));

		u->cb_sha1_arg.u = u;
		upload_http_extra_callback_add(u,
			upload_http_content_urn_add, &u->cb_sha1_arg);

		/* Same for HEAD or GET */
		upload_send_error(u, 416, N_("Requested range not available yet"));
		return FALSE;
	}

	/*
	 * We let all HEAD request go through, whether we're busy or not, since
	 * we only send back the header.
	 *
	 * Follow-up requests already have their slots.
	 */

	if (!u->head_only) {
		if (u->is_followup && !parq_upload_queued(u)) {
			/*
			 * Although the request is a follow up request, the last time the
			 * upload didn't get a parq slot. There is probably a good reason
			 * for this. The most logical explantion is that the client did a
			 * HEAD only request with a keep-alive. However, no parq structure
			 * is set for such an upload. So we should treat as a new upload.
			 *		-- JA, 1/06/'03
			 */
			u->is_followup = FALSE;
		}

		u->parq_ul = parq_upload_get(u, header);
		if (u->parq_ul == NULL) {
			upload_error_remove(u, 503,
				parq_upload_queue_full(u) ? N_("Queue full") :
				N_("Another connection is still active"));
			return FALSE;
		}

		/*
		 * Check whether we can perform this upload.
		 *
		 * Note that we perform this check even for follow-up requests, as
		 * we can have allowed a quick upload to go through, but they
		 * start requesting too many small chunks..
		 */

		parq_allows = parq_upload_request(u);
	}

	/*
	 * Update downloaded amount in the PARQ entry.
	 */

	if (u->parq_ul != NULL)
		parq_upload_update_downloaded(u);

	if (!u->head_only && !parq_allows) {
		/*
		 * Even though this test is less costly than the previous ones, doing
		 * it afterwards allows them to be notified of a mismatch whilst they
		 * wait for a download slot.  It would be a pity for them to get
		 * a slot and be told about the mismatch only then.
		 *		--RAM, 15/12/2001
		 *
 		 * Althought the uploads slots are full, we could try to queue
		 * the download in PARQ. If this also fails, then the requesting client
		 * is out of luck.
		 *		--JA, 05/02/2003
		 *
		 */

		if (!parq_upload_queued(u)) {
			time_t expire = parq_banned_source_expire(u->addr);
			char retry_after[80];
			time_delta_t delay = delta_time(expire, now);

			if (delay <= 0)
				delay = 60;		/* Let them retry in a minute, only */


			str_bprintf(retry_after, sizeof(retry_after),
				"Retry-After: %u\r\n", (unsigned) delay);

			/*
			 * Looks like upload got removed from PARQ queue. For now this
			 * only happens when a client got banned. Bye bye!
			 *		-- JA, 19/05/'03
			 */
			upload_error_remove_ext(u, retry_after, 403,
				N_("%s not honoured; removed from PARQ queue"),
				u->was_actively_queued ?
					N_("Minimum retry delay") :
					"Retry-After" /* HTTP header name, don't translate */);
			return FALSE;
		}

		/*
		 * Support for bandwith-dependent number of upload slots.
		 * The upload bandwith limitation has to be enabled, otherwise
		 * we cannot be sure that we have reasonable values for the
		 * outgoing bandwith set.
		 *		--TF 30/05/2002
		 *
		 * NB: if max_uploads is 0, then we disable sharing, period.
		 *
		 * Require that BOTH the average and "instantaneous" usage be
		 * lower than the minimum to trigger the override.  This will
		 * make it more robust when bandwidth stealing is enabled.
		 *		--RAM, 27/01/2003
		 *
		 * Naturally, no new slot must be created when uploads are
		 * stalling, since then b/w usage will be abnormally low and
		 * creating new slots could make things worse.
		 *		--RAM, 2005-08-27
		 */

		if (
			!u->is_followup &&
			GNET_PROPERTY(bw_ul_usage_enabled) &&
			upload_is_enabled() &&
			GNET_PROPERTY(bws_out_enabled) &&
			!wd_is_awake(stall_wd) &&
			(ulong) bsched_pct(BSCHED_BWS_OUT)
				< GNET_PROPERTY(ul_usage_min_percentage) &&
			(ulong) bsched_avg_pct(BSCHED_BWS_OUT)
				< GNET_PROPERTY(ul_usage_min_percentage)
		) {
			if (parq_upload_request_force(u, u->parq_ul)) {
				parq_allows = TRUE;
				if (GNET_PROPERTY(upload_debug))
					g_debug(
						"overridden slot limit because u/l b/w used at "
						"%lu%% (minimum set to %d%%)",
						bsched_avg_pct(BSCHED_BWS_OUT),
						GNET_PROPERTY(ul_usage_min_percentage));
			}
		}

		if (!parq_allows) {
			if (u->status == GTA_UL_QUEUED) {
				send_upload_error(u, 503,
					  N_("Queued (slot %d, ETA: %s)"),
					  parq_upload_lookup_position(u),
					  short_time_ascii(parq_upload_lookup_eta(u)));

				u->error_sent = 0;	/* Any new request should be allowed
									   to retrieve an error code */

				/* Avoid data timeout */
				u->last_update = tm_time();
				expect_http_header(u, GTA_UL_QUEUED);
				return FALSE;
			} else if (parq_upload_queue_full(u)) {
				upload_error_remove(u, 503, N_("Queue full"));
			} else {
				upload_error_remove(u, 503,
					N_("Queued (slot %d, ETA: %s)"),
					parq_upload_lookup_position(u),
					short_time_ascii(parq_upload_lookup_eta(u)));
			}
			return FALSE;
		}
	}

	/*
	 * Keep track of the amount they requested, for possible greed limit
	 * someday.
	 */

	u->total_requested += range_end - range_skip + 1;

	g_assert(NULL == u->file);		/* File opened each time */

	/*
	 * Open the file for reading.
	 */

	u->file = file_object_open(shared_file_path(u->sf), O_RDONLY);

	if (NULL == u->file) {
		upload_error_not_found(u, NULL);
		return FALSE;
	}

	if (!u->head_only)
		parq_upload_busy(u, u->parq_ul);

	/*
	 * PARQ ID, emitted if needed.
	 *
	 * We do that before calling upload_http_status() to avoid lacking
	 * room in the headers, should there by any alternate location present.
	 *
	 * We never emit the queue ID for HEAD requests, nor during follow-ups
	 * (which always occur for the same slot, meaning the PARQ ID was already
	 * sent earlier).
	 */

	if (!u->head_only && !u->is_followup && !parq_ul_id_sent(u)) {
		u->cb_parq_arg.u = u;
		upload_http_extra_callback_add(u,
			parq_upload_add_header_id, &u->cb_parq_arg);
	}

	/*
	 * Content-Length, Last-Modified, etc...
	 */

	u->cb_status_arg.u = u;
	u->cb_status_arg.mtime = shared_file_modification_time(u->sf);
	upload_http_extra_callback_add(u,
		upload_http_status, &u->cb_status_arg);

	/*
	 * Content-Disposition
	 *
	 * This header tells the receiver our idea of the file's name.
	 * It's especially - but not only - useful when downloading by
	 * urn:sha1 or similar using a browser.
	 *
	 * See RFC 2183 and RFC 2184 for explanations. Basically,
	 * the filename is URL-encoded and set character set is
	 * declared as utf-8. The language is declared 'en' (English)
	 * which is bogus but it's required.
	 *
	 * This works with Mozilla.
	 * The header is sent once per file, or on HEAD requests.  It won't be
	 * sent for a follow-up GET after a HEAD for the same file.
	 */

	if (!u->is_followup || switched || u->head_only) {
		static char cd_buf[1024];
		size_t len, size = sizeof cd_buf;
		char *p = cd_buf;

		len = g_strlcpy(p,
				"Content-Disposition: inline; filename*=\"utf-8'en'", size);
		g_assert(len < sizeof cd_buf);

		p += len;
		size -= len;

		len = url_escape_into(shared_file_name_nfc(u->sf), p, size);
		if ((size_t) -1 != len) {
			static const char term[] = "\"\r\n";

			p += len;
			size -= len;
			if (size > CONST_STRLEN(term)) {
				(void) g_strlcpy(p, term, size);
				upload_http_extra_line_add(u, cd_buf);
			}
		}
	}

	/*
	 * Propagate the SHA1 information for the file, if we have it.
	 */

	if (sha1) {
		u->cb_sha1_arg.u = u;
		upload_http_extra_callback_add(u,
			upload_http_content_urn_add, &u->cb_sha1_arg);
	}

	/*
	 * Send back HTTP status.
	 */

	{
		
		const char *http_msg;
		int http_code;

		if ((u->skip || u->end != (u->file_size - 1))) {
			http_code = 206;
			http_msg = "Partial Content";
		} else {
			http_code = 200;
			http_msg = "OK";
		}

		if (!upload_send_http_status(u, u->keep_alive, http_code, http_msg)) {
			upload_remove(u, N_("Cannot send whole HTTP status"));
			return FALSE;
		}
	}

	/*
	 * If we need to send only the HEAD, we're done. --RAM, 26/12/2001
	 */

	if (u->head_only) {
		if (u->keep_alive) {
			u->reqnum++;
			upload_wait_new_request(u);
		} else {
			upload_remove(u, no_reason);	/* No message, everything was OK */
		}
		return FALSE;
	}

	io_free(u->io_opaque);
	u->io_opaque = NULL;

	/*
	 * Install the output I/O, which is via a bandwidth limited source.
	 */

	g_assert(u->socket->gdk_tag == 0);
	g_assert(u->bio == NULL);

	socket_send_buf(u->socket, GNET_PROPERTY(upload_tx_size) * 1024, FALSE);

	u->bio = bsched_source_add(bsched_out_select_by_addr(u->socket->addr),
				&u->socket->wio, BIO_F_WRITE, upload_writable, u);
	upload_stats_file_begin(u->sf);

	return TRUE;
}

static void
upload_determine_peer_address(struct upload *u, header_t *header)
{
	const char *buf;

	upload_check(u);
	g_assert(header);

	/*
	 * Look for X-Node or X-Listen-IP, which indicates the host's Gnutella
	 * address, should they want to browse the host.
	 */

	buf = header_get(header, "X-Node");
	if (buf == NULL)
		buf = header_get(header, "X-Node-IPv6");
	if (buf == NULL)
		buf = header_get(header, "X-Listen-Ip");	/* Case normalized */
	if (buf == NULL)
		buf = header_get(header, "Listen-Ip");		/* Gnucleus! */

	if (buf != NULL) {
		host_addr_t addr;
		uint16 port;
		if (string_to_host_addr_port(buf, NULL, &addr, &port)) {
			u->gnet_addr = addr;
			u->gnet_port = port;
			upload_fire_upload_info_changed(u);
		}
	}
}

static void
upload_set_tos(struct upload *u)
{
	bool known_for_stalling;

	upload_check(u);

	/*
	 * On linux, turn TCP_CORK on so that we only send out full TCP/IP
	 * frames.  The exact size depends on your LAN interface, but on
	 * Ethernet, it's about 1500 bytes.
	 *
	 * If they have some connections stalling recently, reduce the send buffer
	 * size.  This will lower TCP's throughput but will prevent us from
	 * writing too much before detecting the stall.
	 */

	known_for_stalling = NULL != aging_lookup(stalling_uploads, &u->addr);

	if (!wd_is_awake(stall_wd) && !known_for_stalling) {
		socket_cork(u->socket, TRUE);
		socket_tos_throughput(u->socket);
	} else {
		socket_tos_normal(u->socket);	/* Make sure ACKs come back faster */
	}
}

static char *
upload_parse_uri(header_t *header, const char *uri,
	char *host, size_t host_size)
{
	const char *ep;

	g_assert(uri);
	g_assert(host);
	g_assert(host_size > 0);

	host[0] = '\0';

	if (NULL != (ep = is_strcaseprefix(uri, "http://"))) {
		const char *h = ep;
		size_t len = ep - h;

		if (!string_to_host_or_addr(h, &ep, NULL)) {
			/* Unparsable Host */
			return NULL;
		}

		len = ep - h;
		if (len >= host_size) {
			/* Hostname Too Long */
			return NULL;
		}

		g_strlcpy(host, h, 1 + len);
		if (':' == *ep) {
			uint32 v;
			int error;

			ep++; /* Skip ':' */
			v = parse_uint32(ep, &ep, 10, &error);
			if (error || v < 1 || v > 65535) {
				/* Bad Port */
				return NULL;
			}
		}

		uri = ep;
	} else {
		const char *value;
		
		if (header && NULL != (value = header_get(header, "Host"))) {
			g_strlcpy(host, value, host_size);
		}
	}
	return deconstify_char(uri);
}

static void
remove_trailing_http_tag(char *request)
{
	char *endptr;

	endptr = strstr(request, " HTTP/");
	if (endptr) {
		while (request != endptr && is_ascii_blank(*(endptr - 1))) {
			endptr--;
		}
		*endptr = '\0';
	}
}

static uint64
get_content_length(header_t *header)
{
	const char *value;
	uint64 length = 0;
	
	value = header_get(header, "Content-Length");
	if (value) {
		int error;
		
		length = parse_uint64(value, NULL, 10, &error);
		if (error) {
			length = (filesize_t)-1;
		}
	}
	return length;
}

static void
upload_handle_connection_header(struct upload *u, header_t *header)
{
	const char *buf;
	
	/*
	 * Do we have to keep the connection after this request?
	 */

	buf = header_get(header, "Connection");

	if (u->http_major > 1 || (u->http_major == 1 && u->http_minor >= 1)) {
		/* HTTP/1.1 or greater -- defaults to persistent connections */
		u->keep_alive = TRUE;
		if (buf && 0 == ascii_strcasecmp(buf, "close"))
			u->keep_alive = FALSE;
	} else {
		/* HTTP/1.0 or lesser -- must request persistence */
		u->keep_alive = FALSE;
		if (buf && 0 == ascii_strcasecmp(buf, "keep-alive"))
			u->keep_alive = TRUE;
	}
}

/**
 * Handle request for special uploads.
 *
 * @return TRUE if we're going to actually serve the request.
 */
static bool
upload_request_special(struct upload *u, const header_t *header)
{
	int flags = 0;
	
	u->file_size = 0;
	if (u->browse_host) {
		const char *buf;
		char name[1024];

		if (supports_chunked(u, header)) {
			flags |= BH_F_CHUNKED;
			if (!u->head_only) {
				upload_http_extra_line_add(u,
					"Transfer-Encoding: chunked\r\n");
			}
		} else {
			/*
			 * If browsing our host with a client that cannot allow chunked
			 * transmission encoding, we have no choice but to indicate the
			 * end of the transmission with EOF since we don't want to
			 * compute the length of the data in advance.
			 */
			u->keep_alive = FALSE;
		}

		/*
		 * Look at an Accept: line with "application/x-gnutella-packets".
		 * If we get that, then we can send query hits backs.  Otherwise,
		 * we'll send HTML output.
		 */

		buf = header_get(header, "Accept");
		if (buf) {
			if (strtok_case_has(buf, ",", "application/x-gnutella-packets")) {
				flags |= BH_F_QHITS;
			} else if (strtok_case_has(buf, ",", "application/x-gnutella2")) {
				flags |= BH_F_QHITS | BH_F_G2;
			} else if (
				strtok_has(buf, ",;", "*/*") ||
				strtok_case_has(buf, ",;", "text/html") ||
				strtok_case_has(buf, ",;", "text/*")
			) {
				flags |= BH_F_HTML;	/* A browser probably */
			} else {
				upload_send_error(u, 406, N_("Not Acceptable"));
				return FALSE;
			}
		}
		if (!(BH_F_QHITS & flags)) {
			/* No Accept, default to HTML */
			flags |= BH_F_HTML;
		}

		if (flags & BH_F_HTML) {
			upload_http_extra_line_add(u,
					"Content-Type: text/html; charset=utf-8\r\n");
		} else {
			upload_http_extra_line_add(u,
				(flags & BH_F_G2) ?
					"Content-Type: application/x-gnutella2\r\n" :
					"Content-Type: application/x-gnutella-packets\r\n");
		}

		/*
		 * Accept-Encoding -- see whether they want compressed output.
		 */

		flags |= select_encoding(header);
		if (flags & (BH_F_DEFLATE | BH_F_GZIP)) {
			const char *content_encoding;

			if (flags & BH_F_GZIP) {
				content_encoding = "Content-Encoding: gzip\r\n";
			} else {
				content_encoding = "Content-Encoding: deflate\r\n";
			}
			upload_http_extra_line_add(u, content_encoding);
		}

		str_bprintf(name, sizeof name,
				_("<Browse Host %sRequest> [%s%s%s]"),
				(flags & BH_F_G2) ? "G2 " : "",
				(flags & BH_F_HTML) ? "HTML" : _("query hits"),
				(flags & BH_F_DEFLATE) ? _(", deflate") :
				(flags & BH_F_GZIP) ? _(", gzip") : "",
				(flags & BH_F_CHUNKED) ? _(", chunked") : "");

		atom_str_change(&u->name, name);
	} else if (u->thex) {
		char *name;
		
		name = str_cmsg(_("<THEX data for %s>"), u->name);
		atom_str_change(&u->name, name);
		HFREE_NULL(name);

		upload_http_extra_line_add(u, "Content-Type: application/dime\r\n");

		if (!(flags & THEX_UPLOAD_F_CHUNKED)) {
			
			u->file_size = thex_upload_get_content_length(u->thex);
			if (0 == u->file_size) {
				upload_send_error(u, 500, N_("THEX failure"));
				return FALSE;
			}
			u->pos = 0;
			u->skip = 0;
			u->end = u->file_size - 1;
			u->cb_length_arg.u = u;
			upload_http_extra_callback_add(u,
				upload_http_content_length_add, &u->cb_length_arg);
		}
	}

	if (!upload_send_http_status(u, u->keep_alive, 200, "OK")) {
		upload_remove(u, N_("Cannot send whole HTTP status"));
		return FALSE;
	}

	/*
	 * If we need to send only the HEAD, we're done. --RAM, 26/12/2001
	 */

	if (u->head_only) {
		if (u->keep_alive) {
			u->reqnum++;
			upload_wait_new_request(u);
		} else {
			/* No message, everything was OK */
			upload_remove(u, no_reason);
		}
		return FALSE;
	} else {
		gnet_host_t peer;

		io_free(u->io_opaque);
		u->io_opaque = NULL;

		socket_send_buf(u->socket, GNET_PROPERTY(upload_tx_size) * 1024,
			FALSE);

		gnet_host_set(&peer, u->socket->addr, u->socket->port);
		if (u->browse_host) {
			u->special = browse_host_open(u, &peer,
					upload_special_writable,
					&upload_tx_deflate_cb,
					&upload_tx_link_cb,
					&u->socket->wio,
					flags);
		} else if (u->thex) {
			u->special = thex_upload_open(u, &peer,
					u->thex,
					upload_special_writable,
					&upload_tx_link_cb,
					&u->socket->wio,
					flags);
			shared_file_unref(&u->thex);
		}
	}

	return TRUE;
}

/**
 * Called to initiate the upload once all the HTTP headers have been
 * read.  Validate the request, and begin processing it if all OK.
 * Otherwise cancel the upload.
 */
static void
upload_request(struct upload *u, header_t *header)
{
	char *search, *uri;
	time_t now = tm_time();
	char host[1 + MAX_HOSTLEN];
	bool first_request;
	uint32 entropy = 0;

	upload_check(u);

	/*
	 * The upload context is recycled for keep-alive connections but
	 * the following items are always released/cleared in advance.
	 */

	g_assert(NULL == u->request);
	g_assert(0 == u->hevcnt);
	g_assert(NULL == u->sf);
	g_assert(NULL == u->name);
	g_assert(NULL == u->thex);
	g_assert(!u->browse_host);
	g_assert(0 == u->socket->gdk_tag);
	g_assert(NULL == u->bio);

	u->was_actively_queued = FALSE;

	switch (u->status) {
	case GTA_UL_WAITING:
		u->is_followup = !u->last_was_error;
		break;
	case GTA_UL_QUEUED:
		u->was_actively_queued = TRUE;
		/* FALL THROUGH */
	default:
		u->is_followup = FALSE;
		break;
	}

	/*
	 * If we're dealing with a follow-up request, see how long it took them
	 * to get the last data we sent and the time we get the new request back.
	 * Sure, there is the round-trip time, but we must also account for the
	 * time it took TCP to flush all the pending buffers so that the remote
	 * host had a chance to see the end of its previous request.
	 */

	if (u->is_followup) {
		time_delta_t d = delta_time(now, u->last_update);
		entropy = d;
		if (d > IO_RTT_STALL) {
			upload_large_followup_rtt(u, d);
		}
	}

	/*
	 * Entropy harvesting...
	 */

	{
		host_addr_t addr = u->socket->addr;
		uint16 port = u->socket->port;

		entropy = crc32_update(entropy, &addr, sizeof addr);
		entropy = crc32_update(entropy, &port, sizeof port);
		entropy = crc32_update(entropy, &now, sizeof now);
		random_pool_append(&entropy, sizeof entropy);
	}

	/*
	 * Technically, we have not started sending anything yet, but this
	 * also serves as a marker in case we need to call upload_remove().
	 * It will not send an HTTP reply by itself.
	 */

	u->start_date = now;
	u->last_update = now;		/* Done reading headers */

	u->from_browser = upload_likely_from_browser(header);
	u->request = h_strdup(getline_str(u->socket->getline));
	u->downloaded = extract_downloaded(u, header);
	u->status = GTA_UL_SENDING;

	getline_free(u->socket->getline);
	u->socket->getline = NULL;

	if (GNET_PROPERTY(upload_trace) & SOCK_TRACE_IN) {
		g_debug("----%s HTTP Request%s #%u from %s%s%s:\n%s",
			u->is_followup ? "Follow-up" : "Incoming",
			u->last_was_error ? " (after error)" : "",
			u->reqnum,
			host_addr_to_string(u->socket->addr),
			u->from_browser ? " (via browser)" : "",
			u->was_actively_queued ? " (was queued)" : "",
			u->request);
		header_dump(stderr, header, "----");
	}

	if (u->last_was_error)
		gnet_stats_inc_general(GNR_CLIENT_FOLLOWUP_AFTER_ERROR);

	u->last_was_error = FALSE;

	/*
	 * Some headers are sent back only once on a given connection, the
	 * remote host being supposed to cache the values we provide.
	 * 
	 * If the request is a follow-up or a new request after being actively
	 * queued (the request is not a follow-up in that case, just a retry
	 * attempt of an initial request), then we consider it is not the first
	 * request ever made and will not send these headers.
	 */

	first_request = !(u->is_followup || u->was_actively_queued);

	/*
	 * Check limits.
	 */

	if (ctl_limit(u->socket->addr, CTL_D_INCOMING)) {
		u->flags |= UPLOAD_F_LIMITED;
		if (ctl_limit(u->socket->addr, CTL_D_NORMAL)) {
			u->flags |= UPLOAD_F_NORMAL_LIMIT;
		} else if (ctl_limit(u->socket->addr, CTL_D_STEALTH)) {
			u->flags |= UPLOAD_F_STEALTH_LIMIT;
		}
	}

	/* @todo TODO: Parse the HTTP request properly:
	 *		- Check for illegal characters (like NUL)
	 */

	upload_request_handle_user_agent(u, header);
	extract_fw_node_info(u, header);
	feed_host_cache_from_headers(header, HOST_ANY, FALSE, u->addr,
		upload_vendor_str(u));
	
	if (u->push && header_get_feature("tls", header, NULL, NULL)) {
		tls_cache_insert(u->addr, u->socket->port);
	}

	/*
	 * Cache whether remote host supports / wants firewalled locations.
	 */

	u->fwalt |= header_get_feature("fwalt", header, NULL, NULL);

	/*
	 * IPv6-Ready: check remote support of IPv6.
	 */

	u->net = HOST_NET_IPV4;

	{
		unsigned major, minor;

		if (header_get_feature("IP", header, &major, &minor)) {
			if (INET_IP_V6READY == major) {
				u->net = (INET_IP_NOV4 == minor) ?
					HOST_NET_IPV6 : HOST_NET_BOTH;
			}
		}
	}

	/*
	 * Make sure there is the HTTP/x.x tag at the end of the request,
	 * thereby ruling out the HTTP/0.9 requests.
	 *
	 * This has to be done early, and before calling get_file_to_upload()
	 * or the getline_length() call will no longer represent the length of
	 * the string, since URL-unescaping happens inplace and can "shrink"
	 * the request.
	 */

	if (upload_http_version(u, u->request, strlen(u->request))) {
		/* Get rid of the trailing HTTP/<whatever> */
		remove_trailing_http_tag(u->request);
	} else {
		upload_error_remove(u, 500, N_("Unknown/Missing Protocol Tag"));
		return;
	}

	upload_handle_connection_header(u, header);

	/*
	 * Check vendor-specific banning.
	 */

	if (u->user_agent) {
		const char *msg = ban_vendor(u->user_agent);

		if (msg != NULL) {
			ban_record(u->addr, msg);
			upload_error_remove(u, 403, "%s", msg);
			return;
		}
	}

	/* Separate the HTTP method (like GET or HEAD) */
	{
		const char *endptr;

		/*
		 * If `head_only' is true, the request was a HEAD and we're only going
		 * to send back the headers.
		 */
		
		if (NULL != (endptr = is_strprefix(u->request, "HEAD"))) {
			u->head_only = TRUE;
		} else if (NULL != (endptr = is_strprefix(u->request, "GET"))) {
			u->head_only = FALSE;
		}

		if (endptr && is_ascii_blank(endptr[0])) {
			uri = skip_ascii_blanks(endptr);
		} else {
			upload_send_error(u, 501, N_("Not Implemented"));
			return;
		}
	}

	upload_determine_peer_address(u, header);

	if (0 != get_content_length(header)) {
		/*
		 * Make sure there is no content sent along the request.
		 * We could sink it, but no Gnutella servent should ever need to
		 * send content along with GET/HEAD.
		 *		--RAM, 2006-08-15
		 */
		upload_error_remove(u, 403, N_("No Content Allowed"));
		return;
	}

	search = strchr(uri, '?');
	if (search) {
		*search++ = '\0';
		/*
		 * The search cannot be URL-decoded yet because that could
		 * destroy the '&' boundaries.
		 */
	}

	/* Extract the host and path from an absolute URI */
	uri = upload_parse_uri(header, uri, host, sizeof host);
	if (NULL == uri) {
		upload_send_error(u, 400, N_("Bad URI"));
		return;
	}

	if (
		'/' != uri[0] ||
		!url_unescape(uri, TRUE) ||
		0 != url_canonize_path(uri)
	) {
		upload_send_error(u, 400, N_("Bad Path"));
		return;
	}

	/*
	 * If HTTP/1.1 or above, check the Host header.
	 *
	 * We require it because HTTP does, but we don't really care for
	 * now.  Moreover, we might not know our external IP correctly,
	 * so we have little ways to check that the Host refers to us.
	 *
	 *		--RAM, 11/04/2002
	 */

	if ((u->http_major == 1 && u->http_minor >= 1) || u->http_major > 1) {
		if (NULL == header_get(header, "Host")) {
			upload_send_error(u, 400, N_("Missing Host Header"));
			return;
		}
	}

	/*
	 * Idea:
	 *
	 * To prevent people from hammering us, we should setup a priority queue
	 * coupled to a hash table for fast lookups, where we would record the
	 * last failed attempt and when it was.	As soon as there is a request,
	 * we would move the record for the IP address at the beginning of the
	 * queue, and drop the tail when we reach our size limit.
	 *
	 * Then, if we discover that a given IP re-issues too frequent requests,
	 * we would start differing our reply by not sending the error immediately
	 * but scheduling that some time in the future.	We would begin to use
	 * many file descriptors that way, so we trade CPU time for another scarce
	 * resource.  However, if someone is hammering us with connections,
	 * he would have to wait for our reply before knowing the failure, and
	 * it would slow him down, even if he retried immediately.
	 *
	 * Alternatively, instead of differing the 503 reply, we could send a
	 * "403 Forbidden to bad citizens" instead, and chances are that servents
	 * abort retries on failures other than 503...
	 *
	 *				--RAM, 09/09/2001
	 */

	if (0 == strcmp(uri, "/")) {
		if (0 != prepare_browse_host_upload(u, header, host)) {
			return;
		}
	} else if (0 != get_file_to_upload(u, header, uri, search)) {
		/* get_file_to_upload() has signaled the error already */
		return;
	}

	/*
	 * XXX We can't detect switching between two THEX or between THEX and
	 * XXX browse due to the fact that information from the previous request
	 * XXX was cleared.		--RAM, 2009-03-01
	 */

	if ((u->flags & UPLOAD_F_WAS_PLAIN) && upload_is_special(u))
		gnet_stats_inc_general(GNR_CLIENT_RESOURCE_SWITCHING);

	/* Pick up the X-Remote-IP or Remote-IP header */
	node_check_remote_ip_header(u->addr, header);

	/*
	 * X-Features is sent only once on a given connection.
	 */

	if (first_request)
		upload_http_extra_callback_add(u, upload_xfeatures_add, NULL);

	/*
	 * If this is a pushed upload, and we are not firewalled, then tell
	 * them they can reach us directly by outputting an X-Host line.
	 *
	 * Otherwise, if we are firewalled, tell them about possible push
	 * proxies we could have.
	 */

	if (u->push && !GNET_PROPERTY(is_firewalled)) {
		/* Only send X-Host the first time we reply */
		if (first_request) {
			upload_http_extra_callback_add(u, upload_http_xhost_add, NULL);
		}
	} else if (GNET_PROPERTY(is_firewalled)) {
		/* Send X-Push-Proxy each time: might have changed! */
		upload_http_extra_callback_add(u, node_http_proxies_add, &u->net);
	}
	
	/*
	 * Include X-Hostname the first time we reply and if we have a
	 * known hostname, for which the user gave permission to advertise.
	 */

	if (
		first_request &&
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		/* Force sending of X-Hostname even if bandwidth is tight */
		upload_http_extra_callback_add(u, http_hostname_add,
			GINT_TO_POINTER(1));
	}

	/*
	 * If we don't share, abort. --RAM, 11/01/2002
	 * Use 5xx error code, it's a server-side problem --RAM, 11/04/2002
	 *
	 * We do that quite late in the process to be able to gather as
	 * much as possible from the request for tracing in the GUI.
	 * Also, if they request something wrong, they ought to know it ASAP.
	 */

	if (!upload_is_enabled()) {
		upload_error_remove(u, 500, N_("Sharing currently disabled"));
		return;
	}

	/*
	 * We now have enough information to display the request in the GUI.
	 */

	upload_fire_upload_info_changed(u);

	if (u->flags & UPLOAD_F_LIMITED) {
		upload_error_remove(u, 403, N_("Limited connection"));
		return;
	}

	/*
	 * We will send back an X-GUID if necessary, provided that this is
	 * the first request on the connection.
	 */

	if (first_request)
		upload_http_extra_callback_add(u, upload_xguid_add, GINT_TO_POINTER(1));

	/*
	 * If we're not using sendfile() or if we don't have a requested file
	 * to serve (meaning we're dealing with a special upload), we're going
	 * to need a buffer.
	 */

	if (NULL == u->sf || !use_sendfile(u)) {
		u->bpos = 0;
		u->bsize = 0;

		if (u->buffer == NULL) {
			u->buf_size = READ_BUF_SIZE;
			u->buffer = halloc(u->buf_size);
		}
	}

	/*
	 * Set remaining upload information
	 */

	upload_set_tos(u);

	if (u->sf) {
		if (!upload_request_for_shared_file(u, header))
			return;
	} else {
		if (!upload_request_special(u, header))
			return;
	}

	u->reqnum++;
	upload_fire_upload_info_changed(u);

	if (!u->was_running) {
		gnet_prop_incr_guint32(PROP_UL_RUNNING);
		u->was_running = TRUE;
	}
}

static void
upload_completed(struct upload *u)
{
	/*
	 * We do the following before cloning, since this will reset most
	 * of the information, including the upload name.  If they chose
	 * to clear uploads immediately, they will incur a small overhead...
	 */
	u->status = GTA_UL_COMPLETE;

	socket_check(u->socket);

	gnet_prop_incr_guint32(PROP_TOTAL_UPLOADS);
	upload_fire_upload_info_changed(u); /* gui must update last state */

	/*
	 * If we're going to keep the connection, we must clone the upload
	 * structure, since it is associated to the GUI entry.
	 *
	 * When the upload is to be cloned, we need to collect stats before
	 * it is cloned, otherwise it will be performed by upload_remove().
	 * Indeed, once cloned, the PARQ opaque structure is attached to the
	 * child and no longer to the parent.
	 */

	if (u->keep_alive) {
		struct upload *cu;

		parq_upload_collect_stats(u);
		cu = upload_clone(u);
		upload_wait_new_request(cu);
	}
	upload_remove(u, no_reason);
}

/**
 * @return TRUE if an exception occured, the upload has been removed
 *         in this case. FALSE if everything is OK.
 */
static bool
upload_handle_exception(struct upload *u, inputevt_cond_t cond)
{
	if (cond & INPUT_EVENT_EXCEPTION) {
		/* If we can't write then we don't want it, kill the socket */
		socket_eof(u->socket);
		upload_remove(u, N_("Write exception"));
		return TRUE;
	}

	return FALSE;
}

/**
 * Called when output source can accept more data.
 */
static void
upload_writable(void *obj, int unused_source, inputevt_cond_t cond)
{
	struct upload *u = cast_to_upload(obj);
	ssize_t written;
	filesize_t amount;
	size_t available;
	bool using_sendfile;

	(void) unused_source;

	if (upload_handle_exception(u, cond))
		return;

	if (GTA_UL_COMPLETE == u->status) {
		upload_completed(u);
		return;
	}

   /*
 	* Compute the amount of bytes to send.
 	*/

	amount = u->end - u->pos + 1;
	g_assert(amount > 0);

	using_sendfile = use_sendfile(u);

	if (using_sendfile) {
		fileoffset_t pos, before;			/**< For sendfile() sanity checks */
		/*
	 	 * Compute the amount of bytes to send.
	 	 * Use the two variables to avoid warnings about unused vars by
		 * compiler.
	 	 */

		available = MIN(amount, READ_BUF_SIZE);
		before = pos = u->pos;
		written = bio_sendfile(&u->sendfile_ctx, u->bio,
					file_object_fd(u->file), &pos, available);

		g_assert((ssize_t) -1 == written ||
			(fileoffset_t) written == pos - before);
		u->pos = pos;

	} else {
		/*
		 * If sendfile() failed on a different connection meanwhile
		 * u->buffer is still NULL for this connection.
		 */
		if (sendfile_failed && NULL == u->buffer) {
			u->buf_size = READ_BUF_SIZE;
			u->buffer = halloc(u->buf_size);
		}

		/*
	 	 * If the buffer position reached the size, then we need to read
	 	 * more data from the file.
	 	 */

		if (u->bpos == u->bsize) {
			ssize_t ret;

			g_assert(u->buffer != NULL);
			g_assert(u->buf_size > 0);
			ret = file_object_pread(u->file, u->buffer, u->buf_size, u->pos);
			if ((ssize_t) -1 == ret) {
				upload_remove(u, N_("File read error: %s"), g_strerror(errno));
				return;
			}
			if (0 == ret) {
				upload_remove(u, N_("File EOF?"));
				return;
			}
			u->bsize = (size_t) ret;
			u->bpos = 0;
		}

		available = u->bsize - u->bpos;
		if (available > amount)
			available = amount;

		g_assert(available > 0 && available <= INT_MAX);

		written = bio_write(u->bio, &u->buffer[u->bpos], available);
	}

	if ((ssize_t) -1 == written) {
		int e = errno;

		if (
			using_sendfile &&
			!is_temporary_error(e) &&
			e != EPIPE &&
			e != ECONNRESET &&
			e != ENOTCONN &&
			e != ENOBUFS
		) {
			g_warning("sendfile() failed: \"%s\" -- "
				"disabling sendfile() for this session", g_strerror(e));
			sendfile_failed = TRUE;
		}
		if (!is_temporary_error(e)) {
			socket_eof(u->socket);
			upload_remove(u, N_("Data write error: %s"), g_strerror(e));
		}
		return;
	} else if (written == 0) {
		upload_remove(u, N_("No bytes written, source may be gone"));
		return;
	}

	if (!using_sendfile) {
		/*
	 	 * Only required when not using sendfile(), otherwise the u->pos field
	 	 * is directly updated by the kernel, and u->bpos is unused.
	 	 *		--RAM, 21/02/2002
	 	 */

		u->pos += written;
		u->bpos += written;
	}

	gnet_prop_set_guint64_val(PROP_UL_BYTE_COUNT,
		GNET_PROPERTY(ul_byte_count) + written);

	u->last_update = tm_time();
	u->sent += written;
	if (u->file_info) {
		fi_increase_uploaded(u->file_info, written);
	}

	/* This upload is complete */
	if (u->pos > u->end) {

		if (u->sf) {
			upload_stats_file_complete(u->sf, u->end - u->skip + 1);
			u->accounted = TRUE;	/* Called upload_stats_file_complete() */
		}
		upload_completed(u);
	}
}

static inline ssize_t
upload_special_read(struct upload *u)
{
	g_assert(NULL != u->special);
	g_assert(NULL != u->special->read);

	return u->special->read(u->special, u->buffer, u->buf_size);
}

static inline ssize_t
upload_special_write(struct upload *u, const void *data, size_t len)
{
	ssize_t r;

	g_assert(NULL != u->special);
	g_assert(NULL != u->special->write);

	r = u->special->write(u->special, data, len);
	if (r > 0)
		upload_fire_upload_info_changed(u);		/* Update size info */

	return r;
}

/**
 * Callback invoked when the special stack has been fully flushed.
 */
static void
upload_special_flushed(void *arg)
{
	struct upload *u = cast_to_upload(arg);

	g_assert(u->special);
	g_assert(u->special->close);

	/*
	 * Must get rid of the special reading hooks to reset the TX stack
	 * for the next request.
	 */

	(*u->special->close)(u->special, TRUE);
	u->special = NULL;

	if (GNET_PROPERTY(upload_debug))
		g_debug("%s from %s (%s) done: %s bytes, %s sent",
			u->name,
			host_addr_to_string(u->socket->addr),
			upload_vendor_str(u),
			uint64_to_string(u->sent),	/* Sent to TX stack = final RX size */
			uint64_to_string2(u->file_size));/* True amount sent on the wire */

	upload_fire_upload_info_changed(u);		/* Update size info */
	upload_completed(u);	/* We're done, wait for next request if any */
}

static inline void
upload_special_flush(struct upload *u)
{
	g_assert(NULL != u->special);
	g_assert(NULL != u->special->flush);

	u->special->flush(u->special, upload_special_flushed, u);
}

/**
 * Called when output source can accept more data.
 */
static void
upload_special_writable(void *obj)
{
	struct upload *u = cast_to_upload(obj);
	ssize_t written;
	size_t available;

	g_assert(NULL != u->special);

	/*
 	 * If the buffer position reached the size, then we need to read
 	 * more data from the file.
 	 */

	if (u->bpos == u->bsize) {
		ssize_t ret;

		g_assert(u->buffer != NULL);
		g_assert(u->buf_size > 0);
		ret = upload_special_read(u);
		if ((ssize_t) -1 == ret) {
			upload_remove(u, N_("Special read error: %s"), g_strerror(errno));
			return;
		}
		if (0 == ret) {
			/*
			 * We're done.  Flush the stack asynchronously.
			 */

			upload_special_flush(u);
			return;
		}
		u->bsize = (size_t) ret;
		u->bpos = 0;
	}

	available = u->bsize - u->bpos;
	g_assert(available > 0 && available <= INT_MAX);

	written = upload_special_write(u, &u->buffer[u->bpos], available);

	if ((ssize_t) -1 == written)
		return;		/* TX stack already removed the upload */

	u->pos += written;
	u->bpos += written;

	gnet_prop_set_guint64_val(PROP_UL_BYTE_COUNT,
		GNET_PROPERTY(ul_byte_count) + written);

	u->last_update = tm_time();
	u->sent += written;
}

/**
 * Kill a running upload.
 */
void
upload_kill(gnet_upload_t upload)
{
    struct upload *u = upload_find_by_handle(upload);

	g_return_if_fail(u);
    if (!UPLOAD_IS_COMPLETE(u)) {
		parq_upload_force_remove(u);
        upload_remove(u, N_("Explicitly killed"));
	}
}

/**
 * Kill all running uploads by IP.
 */
void
upload_kill_addr(const host_addr_t addr)
{
	pslist_t *sl, *to_remove = NULL;

	for (sl = list_uploads; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);

		if (host_addr_equal(u->addr, addr) && !UPLOAD_IS_COMPLETE(u))
			to_remove = pslist_prepend(to_remove, u);
	}

	for (sl = to_remove; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);

		parq_upload_force_remove(u);
		upload_remove(u, N_("IP denying uploads"));
	}
	pslist_free(to_remove);
}

/**
 * Check whether uploading is enabled: we have slots, and bandwidth.
 */
bool
upload_is_enabled(void)
{
	return GNET_PROPERTY(max_uploads) > 0 && (
		0 == GNET_PROPERTY(ul_running) + GNET_PROPERTY(ul_quick_running) ||
		bsched_bw_per_second(BSCHED_BWS_OUT) >= BW_OUT_MIN
	);
}

/**
 * Initialize uploads.
 */
G_GNUC_COLD void
upload_init(void)
{
	mesh_info = htable_create_any(mi_key_hash, mi_key_hash2, mi_key_eq);
	stalling_uploads = aging_make(STALL_CLEAR,
						host_addr_hash_func, host_addr_eq_func,
						wfree_host_addr);
	upload_handle_map = idtable_new(32);
	push_requests = aging_make(PUSH_REPLY_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);

	header_features_add_guarded(FEATURES_UPLOADS, "browse",
		BH_VERSION_MAJOR, BH_VERSION_MINOR,
		GNET_PROPERTY_PTR(browse_host_enabled));

	header_features_add(FEATURES_UPLOADS, "fwalt",
		FWALT_VERSION_MAJOR, FWALT_VERSION_MINOR);

	/*
	 * IPv6-Ready:
	 * - advertise "IP/6.4" if we don't run IPv4.
	 * - advertise "IP/6.0" if we run both IPv4 and IPv6.
	 * - advertise nothing otherwise (running IPv4 only)
	 */

	header_features_add_guarded_function(FEATURES_UPLOADS, "IP",
		INET_IP_V6READY, INET_IP_NOV4, settings_running_ipv6_only);
	header_features_add_guarded_function(FEATURES_UPLOADS, "IP",
		INET_IP_V6READY, INET_IP_V4V6, settings_running_ipv4_and_ipv6);

	early_stall_wd = wd_make("upload early stalling",
		IO_STALL_WATCH, upload_no_more_early_stalling, NULL, FALSE);

	stall_wd = wd_make("upload stalling",
		IO_STALL_WATCH, upload_no_more_stalling, NULL, FALSE);
}

/**
 * Final cleanup at shutdown time.
 */
G_GNUC_COLD void
upload_close(void)
{
	while (list_uploads) {
		struct upload *u = cast_to_upload(list_uploads->data);

		upload_aborted_file_stats(u);
		upload_free_resources(u);
	}

    idtable_destroy(upload_handle_map);
    upload_handle_map = NULL;

	htable_foreach(mesh_info, mi_free_kv, NULL);
	htable_free_null(&mesh_info);

	aging_destroy(&stalling_uploads);
	aging_destroy(&push_requests);
	wd_free_null(&early_stall_wd);
	wd_free_null(&stall_wd);
}

gnet_upload_info_t *
upload_get_info(gnet_upload_t uh)
{
    static const gnet_upload_info_t zero_info;
    gnet_upload_info_t *info;
    struct upload *u;

    u = upload_find_by_handle(uh);
	g_return_val_if_fail(u, NULL);

    WALLOC(info);
	*info = zero_info;

	if (u->sf) {
   		info->name = atom_str_get(shared_file_name_nfc(u->sf));
	} else if (u->name) {
   		info->name = atom_str_get(lazy_unknown_to_utf8_normalized(u->name,
						UNI_NORM_GUI, NULL));
	}
	if (u->user_agent) {
    	info->user_agent = atom_str_get(lazy_iso8859_1_to_utf8(u->user_agent));
	}
    info->addr          = u->addr;
    info->file_size     = u->file_size;
    info->range_start   = u->skip;
    info->range_end     = u->end;
    info->start_date    = u->start_date;
    info->last_update   = u->last_update;
    info->country       = u->country;
    info->upload_handle = u->upload_handle;
	info->push          = u->push;
	info->encrypted     = u->socket && socket_uses_tls(u->socket);
	info->partial       = u->file_info != NULL;
	info->gnet_addr     = u->gnet_addr;
	info->gnet_port     = u->gnet_port;

    return info;
}

void
upload_free_info(gnet_upload_info_t *info)
{
    g_assert(info != NULL);

	atom_str_free_null(&info->user_agent);
	atom_str_free_null(&info->name);

    WFREE(info);
}

void
upload_get_status(gnet_upload_t uh, gnet_upload_status_t *si)
{
    struct upload *u = upload_find_by_handle(uh);
	time_t now = tm_time();

    g_assert(si != NULL);

    si->status      = u->status;
    si->pos         = u->pos;
    si->bps         = 1;
    si->avg_bps     = 1;
    si->last_update = u->last_update;
	si->reqnum      = u->reqnum;
	si->error_count = u->error_count;

	si->parq_queue_no = parq_upload_lookup_queue_no(u);
	si->parq_position = parq_upload_lookup_position(u);
	si->parq_size = parq_upload_lookup_size(u);
	si->parq_lifetime = MAX(0, delta_time(parq_upload_lifetime(u), now));
	si->parq_retry = MAX(0, delta_time(parq_upload_retry(u), now));
	si->parq_quick = parq_upload_lookup_quick(u);
	si->parq_frozen = parq_upload_lookup_frozen(u);

    if (u->bio) {
        si->bps = bio_bps(u->bio);
		si->avg_bps = bio_avg_bps(u->bio);
	}

    if (si->avg_bps <= 10 && u->last_update != u->start_date)
        si->avg_bps = (u->pos - u->skip)
			/ delta_time(u->last_update, u->start_date);
	if (si->avg_bps == 0)
        si->avg_bps++;
}

pslist_t *
upload_get_info_list(void)
{
	pslist_t *sl, *sl_info = NULL;

	for (sl = list_uploads; sl; sl = pslist_next(sl)) {
		struct upload *u = cast_to_upload(sl->data);
		sl_info = pslist_prepend(sl_info, upload_get_info(u->upload_handle));
	}
	return pslist_reverse(sl_info);
}

void
upload_free_info_list(pslist_t **sl_ptr)
{
	g_assert(sl_ptr);
	if (*sl_ptr) {
		pslist_t *sl;

		for (sl = *sl_ptr; sl; sl = pslist_next(sl)) {
			upload_free_info(sl->data);
		}
		pslist_free(*sl_ptr);
		*sl_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
