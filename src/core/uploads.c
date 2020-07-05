/*
 * Copyright (c) 2001-2003, 2015 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "lib/array_util.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/cstr.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/header.h"
#include "lib/hstrfn.h"
#include "lib/http_range.h"
#include "lib/idtable.h"
#include "lib/iso3166.h"
#include "lib/listener.h"
#include "lib/misc.h"			/* For english_strerror() */
#include "lib/parse.h"
#include "lib/pow2.h"
#include "lib/product.h"
#include "lib/pslist.h"
#include "lib/ripening.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
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
#define IO_RTT_CAP		5			/**< Initiate b/w cap if RTT larger */
#define IO_STALLED		30			/**< Stalling condition */
#define IO_STALL_WATCH	300			/**< Watchdog period for stall monitoring */
#define IO_LONG_TIMEOUT	160			/**< Longer timeouting condition */
#define TX_DURATION		20			/**< Aimed max TX duration for request (s) */
#define TX_MIN_CHUNK	(16*1024)	/**< Min chunk size we wish to keep */
#define TX_FIRST_STALL	(128*1024)	/**< Capped first request for stalling hosts */
#define TX_FIRST_CHUNK	(512*1024)	/**< Capped first request for other hosts */
#define STALL_CLEAR		600			/**< Decrease stall counter every 10 min */
#define MAX_ERRORS		10			/**< Max # of errors before we close */
#define PUSH_REPLY_MAX	5			/**< Answer to up to 5 pushes per IP... */
#define PUSH_REPLY_FREQ	30			/**< ...in an interval of 30 secs */
#define PUSH_BAN_FREQ	500			/**< 5-minute ban if cannot reach host */
#define ALT_LOC_SIZE	160			/**< Size of X-Alt under b/w pressure */
#define RANGES_SIZE		120			/**< Minimal size of X-Available-Ranges */
#define UPLOAD_MAX_SINK (16 * 1024)	/**< Maximum length of data to sink */
#define BROWSING_THRESH	3600		/**< secs: at most once per hour! */
#define BROWSING_ABUSE	3			/**< More than that in an hour is abusing! */
#define ONE_DAY			(24*3600)	/**< Seconds in a day */

static pslist_t *list_uploads;
static watchdog_t *early_stall_wd;	/**< Monitor early stalling events */
static watchdog_t *stall_wd;		/**< Monitor stalling events */

/** Used to fall back to write() if sendfile() failed */
static bool sendfile_failed = FALSE;

static idtable_t *upload_handle_map;

static const char no_reason[] = "<no reason>"; /* Don't translate this */
static const char ALLOW[]     = "Allow: GET, HEAD\r\n";

static cpattern_t *pat_http;
static cpattern_t *pat_applewebkit;

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
 * Record association between a SHA1 and a remote IP address.
 *
 * This structure is the key used in the mesh_info aging table to record
 * when we last sent mesh information to some IP about a given file
 * (identified by its SHA1).
 *
 * It is also meant to be used to register Retry-After time, for insertion in
 * a ripening table (each item having a different expiration time, we cannot
 * use an aging table in that case).
 */
struct upload_tag_key {
	host_addr_t addr;				/**< Remote host IP address */
	const struct sha1 *sha1;		/**< SHA1 atom */
};

/* Keep mesh info about uploaders for that long (unit: s) */
#define MESH_INFO_TIMEOUT	(PARQ_MAX_UL_RETRY_DELAY + PARQ_GRACE_TIME)

static aging_table_t *mesh_info;		/**< Tracks when we last sent mesh info */
static aging_table_t *push_requests;	/**< Throttle push requests */
static aging_table_t *push_conn_failed;	/**< Throttle unreacheable hosts */

/* Remember IP address of stalling uploads for a while */
static aging_table_t *stalling_uploads;
static aging_table_t *early_stalling_uploads;

static aging_table_t *browsing_reqs;	/**< Throttle browsing requests */

/* Enfore Retry-After */
static ripening_table_t *retry_after;	/**< Tracks known delays per IP + SHA1 */

#define RETRY_AFTER_ENFORCE_MAX		3600	/* seconds */

static const char stall_first[] = "stall first";
static const char stall_again[] = "stall again";

#define STALL_FIRST (deconstify_pointer(stall_first))
#define STALL_AGAIN (deconstify_pointer(stall_again))

static void upload_request(struct upload *u, header_t *header);
static void upload_error_remove(struct upload *u,
		int code, const char *msg, ...) G_PRINTF(3, 4);
static void upload_error_remove_ext(struct upload *u,
		const char *extended, int code,
		const char *msg, ...) G_PRINTF(4, 5);
static void upload_writable(void *up, int source, inputevt_cond_t cond);
static void upload_special_writable(void *up);
static bool send_upload_error(struct upload *u, int code,
			const char *msg, ...) G_PRINTF(3, 4);
static void upload_connect_conf(struct upload *u);

static void upload_http_status_partially_sent(
	const char *data, size_t len, size_t sent, void *arg);
static void upload_http_status_sent(struct upload *u);

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
 *** Upload mesh information tracking.
 ***/

static struct upload_tag_key *
upload_tag_key_make(const host_addr_t addr, const struct sha1 *sha1)
{
	struct upload_tag_key *mik;

	WALLOC(mik);
	mik->addr = addr;
	mik->sha1 = atom_sha1_get(sha1);

	return mik;
}

static void
upload_tag_key_free(void *p)
{
	struct upload_tag_key *mik = p;

	g_assert(mik != NULL);

	atom_sha1_free(mik->sha1);
	WFREE(mik);
}

static void
upload_tag_key_free2(void *p, void *unused)
{
	struct upload_tag_key *mik = p;

	(void) unused;

	if (GNET_PROPERTY(upload_debug) > 4) {
		g_debug("upload MESH info (%s/%s) discarded",
			host_addr_to_string(mik->addr), sha1_base32(mik->sha1));
	}

	upload_tag_key_free(p);
}

static void
upload_tag_key_free2_silent(void *p, void *unused)
{
	(void) unused;
	upload_tag_key_free(p);
}

static uint
upload_tag_key_hash(const void *key)
{
	const struct upload_tag_key *mik = key;

	return sha1_hash(mik->sha1) ^ host_addr_hash(mik->addr);
}

static int
upload_tag_key_eq(const void *a, const void *b)
{
	const struct upload_tag_key *mika = a, *mikb = b;

	/* The SHA1 being an atom, we use == instead of sha1_eq() */

	return host_addr_equiv(mika->addr, mikb->addr) &&
		sha1_eq(mika->sha1, mikb->sha1);
}

/**
 * Get timestamp at which we last sent download mesh information for (IP,SHA1).
 * If we don't remember sending it, return 0.
 * Always records `now' as the time we sent mesh information.
 */
static uint
upload_mi_get_stamp(const host_addr_t addr, const struct sha1 *sha1, time_t now)
{
	struct upload_tag_key mikey, *mik;
	uint stamp;

	mikey.addr = addr;
	mikey.sha1 = sha1;

	/* Update stamp if key already exists */

	stamp = pointer_to_uint(
		aging_replace_revitalise(mesh_info, &mikey, uint_to_pointer(now)));

	if (stamp != 0) {
		if (GNET_PROPERTY(upload_debug) > 4) {
			g_debug("upload MESH info (%s/%s) has stamp=%u",
				host_addr_to_string(addr), sha1_base32(sha1), stamp);
		}
		return stamp;		/* Previously sent stamp */
	}

	/* Create new entry since key was missing */

	mik = upload_tag_key_make(addr, sha1);
	aging_insert(mesh_info, mik, uint_to_pointer(now));

	if (GNET_PROPERTY(upload_debug) > 4)
		g_debug("new upload MESH info (%s/%s) stamp=%u",
			host_addr_to_string(addr), sha1_base32(sha1), (uint32) now);

	return 0;			/* Don't remember sending info about this file yet */
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

	host_addr_to_string_buf(u->addr, ARYLEN(host));
	concat_strings(ARYLEN(info),
		"<", host, " \'", upload_vendor_str(u), "\'>",
		NULL_PTR);
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

	entropy_harvest_time();

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
	 * Allow unused bandwidth to be stolen from the HTTP outgoing scheduler
	 * since we are back to a healthy state.
	 */

	bws_allow_stealing(BSCHED_BWS_OUT, TRUE);
	gnet_prop_set_boolean_val(PROP_UPLOADS_BW_NO_STEALING, FALSE);

	if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
		g_warning("UL re-enabled stealing of unused HTTP outgoing bandwidth");
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

	entropy_harvest_time();

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
	 * We're not using all our bandwidth because some uploads are
	 * stalling, and that may be due to TCP heavily retransmitting
	 * in the background.  Don't let other schedulers use this
	 * apparent available bandwidth.
	 */

	if (!wd_wakeup(early_stall_wd)) {
		if (bws_allow_stealing(BSCHED_BWS_OUT, FALSE)) {
			gnet_prop_set_boolean_val(PROP_UPLOADS_BW_NO_STEALING, TRUE);
			if (GNET_PROPERTY(upload_debug) && GNET_PROPERTY(bw_allow_stealing)) {
				g_warning("UL disabled stealing unused HTTP outgoing bandwidth");
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

	entropy_harvest_small(VARLEN(u), VARLEN(u->addr), VARLEN(u->reqnum), NULL);

	/*
	 * We don't want the same IP address with a bad connection creating
	 * the false impression that we're struggling to send out data on every
	 * connection.
	 *
	 * Hence we remember the recent early stalling conditions we see for each
	 * IP and only accept an early stalling condition the very first time,
	 * until we forget about that IP.
	 * 		--RAM, 2017-08-03
	 */

	if (aging_lookup_revitalise(early_stalling_uploads, &u->addr))
		return;

	aging_record(early_stalling_uploads, WCOPY(&u->addr));

	/*
	 * We need to have at least two remote hosts early stallling at the same
	 * time to start counter-measures.  Otherwise, we rely on the new
	 * bandwidth decimation feature on early stalling conditions to hopefully
	 * take care of the problem.
	 * 		--RAM, 2020-05-26
	 */

	if (aging_count(early_stalling_uploads) > 1)
		upload_early_stall();
}

/**
 * Activate stalling measures.
 */
static void
upload_stall(void)
{
	/*
	 * Enforce uniform bandwidth allocation so that sources which do not
	 * consume their allocated bandwidth do not cause others to get more
	 * bandwidth: stalling uploads are probably blocked by TCP, and we don't
	 * want to stuff too much data to the source as soon as we can write to
	 * it again.
	 */

	if (!bws_uniform_allocation(BSCHED_BWS_OUT, TRUE)) {
		gnet_prop_set_boolean_val(PROP_UPLOADS_BW_UNIFORM, TRUE);
		if (GNET_PROPERTY(upload_debug)) {
			g_warning("UL switching to uniform HTTP outgoing bandwidth");
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
		entropy_harvest_time();
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

	entropy_harvest_small(VARLEN(u), VARLEN(u->addr), NULL);

	upload_stall();
}

/**
 * Bandwidth capping requests.
 *
 * The purpose of b/w capping is to prevent stalling conditions when
 * sending chunks to the remote host.  If we have a lot of bandwidth but
 * the remote host has less and has many connections, its bandwdith could
 * be saturating, slowing down our transmission.
 *
 * If we do nothing, what happens usually is that we fill the large TX
 * send buffer on our side and then, when we think we are done sending, we
 * wait for the follow-up request.  If the remote host does not do HTTP
 * request pipelining like gtk-gnutella does, then we will not get the
 * reply until the whole TX buffer is flushed.  That can take a while, and
 * during this time we have no feedback from the kernel because it has
 * space in the TX buffer so we are not flow-controlled.
 *
 * Eventually, this can lead to a follow-up request timeout and we will
 * close the connection, thinking the remote side is lost.
 *
 * Therefore, what we do is try to adapt to the actual transfer rate we
 * can witness between the two hosts (us and them).  This is the job of the
 * upload_update_bw_cap() routine, and it tries to cut down bandwidth, but
 * not too severely or we will converge to 1 KiB/s or less very quickly if
 * transfers start to stall.
 *
 * Hopefully this new adaptative strategy will allow us to serve more requests
 * when we have more bandwidth than they have.  If we have less bandwidth, then
 * we will be limited by the b/w scheduler normally.
 *
 * 		--RAM, 2020-05-27
 */
enum upload_bw_cap {
	UL_BW_CAP_CLEAR = 0,
	UL_BW_CAP_UP,
	UL_BW_CAP_DOWN,
};

/*
 * Recompute bandwidth cap for the follow-up request.
 *
 * @param u		the upload
 * @param cmd	requested b/w cap adjustment
 */
static void
upload_update_bw_cap(struct upload *u, enum upload_bw_cap cmd)
{
	const char *what = "reset";
	time_delta_t elapsed;
	filesize_t fspeed;
	uint32 speed;

	upload_check(u);

	elapsed = delta_time(tm_time(), u->last_start);
	if G_UNLIKELY(0 == u->last_start)
		elapsed = 0;		/* First time, no previous request */

	/*
	 * Compute speed of last request, overall, by using brute overall timing.
	 *
	 * We substract 1 second from the total elapsed time to get a more
	 * optimistic speed.
	 *
	 * If no elapsed time or it is too small, assume it was all sent instantly.
	 */

	if (elapsed > 2)
		fspeed = u->last_sent / (elapsed - 1);
	else
		fspeed = u->last_sent;

	if (fspeed > MAX_INT_VAL(uint32))
		fspeed = MAX_INT_VAL(uint32);

	/*
	 * We aim to remain at 12.5% above the measured speed otherwise we may
	 * be dragged down to lower and lower speeds, and due to the b/w scheduler
	 * doing its job, the measured speed will be always what we had set for,
	 * modulo the delays we get during follow-ups which may be due to us or
	 * to them, and that we do not know!
	 */

	speed = uint32_saturate_add(fspeed, fspeed / 8);

	if (UL_BW_CAP_CLEAR == cmd) {
		u->bw_cap = 0;
	} else if (0 != u->bw_cap) {
		if (UL_BW_CAP_DOWN == cmd) {
			uint32 pct = u->bw_cap / 5;		/* 20% decrement */
			uint32 ncap = u->bw_cap - pct;
			if (ncap >= speed) {
				if (ncap - speed > pct) {
					/* Large difference, better cut-down TX rate */
					u->bw_cap = speed;
					what = "cut-down";
				} else {
					u->bw_cap = ncap;
					what = "lowered";
				}
			} else if (u->bw_cap >= speed){
				u->bw_cap = speed;		/* Don't lower too much */
				what = "decreased";
			} else {
				u->bw_cap = speed;		/* Need to stay optimist */
				what = "increased";
			}
		} else if (UL_BW_CAP_UP == cmd) {
			uint32 pct = u->bw_cap / 4;		/* 25% increment */
			if (u->bw_cap >= u->last_sent) {
				/* Request was smaller than b/w, be careful! */
				if (u->bw_cap - pct < speed) {
					what = "kept";
				} else {
					/* This is actually a reduction! */
					u->bw_cap = speed;
					what = "forced";
				}
			} else {
				uint32 ncap = uint32_saturate_add(u->bw_cap, pct);
				u->bw_cap = ncap;
				what = "raised";
			}
		} else
			g_assert_not_reached();
	} else {
		/* First time, regardless of UL_BW_CAP_DOWN or UL_BW_CAP_UP */
		if (elapsed > 2) {
			u->bw_cap = speed;
			what = "set";
		} else {
			what = "kept";
		}
	}

	if (GNET_PROPERTY(upload_debug) > 1) {
		char buf[SIZE_FIELD_MAX];

		if (UL_BW_CAP_CLEAR == cmd)
			elapsed = 0;

		short_size_to_string_buf(speed, FALSE, ARYLEN(buf));

		g_debug(
			"UL b/w cap %s to %s/s%s for host %s (%s) request #%u, "
			"T=%s for %s, speed ~ %s/s",
			what, short_size(u->bw_cap, FALSE),
			0 == u->bw_cap ? " (none)" : "",
			host_addr_to_string(u->addr), upload_vendor_str(u), u->reqnum,
			short_time_ascii(elapsed), short_size2(u->last_sent, FALSE), buf);
	}
}

/**
 * Invoked when we spot a large round trip time between the end of the previous
 * request and the followup from the remote client.
 */
static void
upload_large_followup_rtt(const struct upload *u, time_delta_t d)
{
	bool ignore = FALSE;

	upload_check(u);

	/*
	 * If bandwidth capping was used or IP has been stalling recently,
	 * then ignore.
	 */

	if (0 != u->bw_cap || aging_lookup_revitalise(stalling_uploads, &u->addr))
		ignore = TRUE;

	if (GNET_PROPERTY(upload_debug)) {
		g_debug(
			"UL host %s (%s) took %s to send follow-up after request #%u (%s)%s",
			host_addr_to_string(u->addr), upload_vendor_str(u),
			compact_time(d), u->reqnum, short_size(u->last_sent, FALSE),
			ignore ? " (IGNORED)" : "");
	}

	entropy_harvest_small(VARLEN(u), VARLEN(u->addr), NULL);

	if (ignore)
		return;

	aging_insert(stalling_uploads, WCOPY(&u->addr), STALL_FIRST);

	/*
	 * We need to have at least two remote hosts stallling at the same
	 * time to start counter-measures.  Otherwise, we rely on the new
	 * bandwidth decimation feature on stalling conditions to hopefully
	 * take care of the problem.
	 * 		--RAM, 2020-05-26
	 */

	if (aging_count(stalling_uploads) > 1) {
		if (d >= IO_STALLED) {
			upload_stall();
		} else {
			upload_early_stall();
		}
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

	PSLIST_FOREACH(list_uploads, sl) {
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
		 *
		 * We not only want UPLOAD_IS_SENDING() but also u->bio != NULL
		 * otherwise we are facing a cloned upload whose HTTP status
		 * header has not been sent back yet, hence we are not within a
		 * data transfer!
		 * 		--RAM, 2020-05-26
		 */

		if (!UPLOAD_IS_SENDING(u) || NULL == u->bio)
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
				bio_add_penalty(u->bio, 1);		/* Reduce write bandwidth */

				if (!skip)
					upload_new_stalling(u);

				/*
				 * Record that this IP is stalling, but also record the fact
				 * that it's not the first time we're seeing it, if necessary.
				 */

				aging_insert(stalling_uploads, WCOPY(&u->addr),
					skip ? STALL_AGAIN : STALL_FIRST);
			} else if (!skip) {
				wd_kick(stall_wd);
			}
		} else {
			bool skip = FALSE;
			void *stall;

			stall = aging_lookup(stalling_uploads, &u->addr);
			skip = (stall == STALL_AGAIN);

			if (u->flags & UPLOAD_F_STALLED) {
				if (GNET_PROPERTY(upload_debug)) g_warning(
					"connection to %s (%s) un-stalled, %s bytes sent%s",
					host_addr_to_string(u->addr), upload_vendor_str(u),
					uint64_to_string(u->sent),
					skip ? " (IGNORED)" : "");

				u->flags &= ~UPLOAD_F_STALLED;	/* No more stalling */
			}

			if (!skip) {
				if (!socket_is_corked(u->socket)) {
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
				if (u->bio != NULL) {		/* Within chunk serving */
					if (!(u->flags & UPLOAD_F_EARLY_STALL)) {
						upload_new_early_stalling(u);
						/* Reduce write bandwidth by a factor of 2^2 = 4 */
						bio_add_penalty(u->bio, 2);
						u->flags |= UPLOAD_F_EARLY_STALL;
					} else {
						wd_kick(early_stall_wd);
					}
				}
			} else if (u->bio != NULL) {
				/*
				 * When clearing the early stalling condition, we re-increase
				 * the write bandwidth but less than what we had decreased
				 * before. The net effect is that bandwidth returns to half
				 * what it was before the early stalling condition, until this
				 * request is completed.  More stalling will continue to add
				 * some penalty until we can write less but more often to the
				 * remote host.  This should smooth out traffic by adapting
				 * to the available end-to-end bandwidth.
				 * 		--RAM, 2020-05-26
				 */

				if (u->flags & UPLOAD_F_EARLY_STALL) {
					/* Re-increase bandwidth by a factor of 2^1 = 2 */
					bio_remove_penalty(u->bio, 1);
					u->flags &= ~UPLOAD_F_EARLY_STALL;
				}
			}
		}
	}

	PSLIST_FOREACH(to_remove, sl) {
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
 * Callback invoked when the socket connection failed.
 */
static void
upload_socket_connect_failed(gnutella_socket_t *s, void *owner, const char *err)
{
	struct upload *u = owner;

	upload_check(u);
	g_assert(s == u->socket);

	/*
	 * Record the failing address so that we do not re-attempt to connect to
	 * that host for a while when we receive a PUSH request.
	 */

	{
		gnet_host_t to;

		gnet_host_set(&to, s->addr, s->port);
		aging_record(push_conn_failed, atom_host_get(&to));

		if (GNET_PROPERTY(upload_debug)) {
			g_warning("PUSH can't connect to %s", gnet_host_to_string(&to));
		}
	}

	/*
	 * The socket_connection_failed() routine invoked us, and expects that we
	 * destroy the socket ourselves.
	 */

	upload_remove(u, "%s", err);
}

/**
 * Socket-layer callbacks for uploads.
 */
static struct socket_ops upload_socket_ops = {
	upload_socket_connect_failed,	/* connect_failed */
	upload_socket_connected,		/* connected */
	upload_socket_destroy,			/* destroy */
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
    u->port = s->port;
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

	if (GNET_PROPERTY(net_buffer_shortage))
		return;

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
handle_push_request(gnutella_node_t *n, const g2_tree_t *t)
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
			if (!host_addr_equiv(n->addr, ha))
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
						PLURAL(paylen));
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
	 * Protect from incoming PUSH listng an IP:port that we cannot connect to.
	 */

	{
		gnet_host_t to;

		gnet_host_set(&to, ha, port);

		if (aging_lookup(push_conn_failed, &to)) {
			if (GNET_PROPERTY(upload_debug)) {
				time_delta_t age = aging_age(push_conn_failed, &to);
				g_warning("PUSH (hops=%d, ttl=%d) "
					"skipping %s%s (unreacheable, since %ld sec%s): %s",
					gnutella_header_get_hops(&n->header),
					gnutella_header_get_ttl(&n->header),
					NODE_TALKS_G2(n) ? "G2 " : "",
					host_addr_port_to_string(ha, port),
					(long) PLURAL(age), file_name);
			}
			return;
		}
	}

	/*
	 * Protect from PUSH flood: since each push requires us to connect
	 * back, it uses resources and could be used to conduct a subtle denial
	 * of service attack.	-- RAM, 03/11/2002
	 */

	push_count = aging_saw_another_revitalise(push_requests, &ha, host_addr_wcopy);

	if (push_count >= PUSH_REPLY_MAX) {
		if (GNET_PROPERTY(upload_debug)) {
			g_warning("PUSH (hops=%d, ttl=%d) throttling callback to %s%s: %s",
				gnutella_header_get_hops(&n->header),
				gnutella_header_get_ttl(&n->header),
				NODE_TALKS_G2(n) ? "G2 " : "",
				host_addr_port_to_string(ha, port), file_name);
		}
		gnet_stats_inc_general(GNR_REMOTE_PUSH_THROTTLED);
		return;
	}

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
	file_object_close(&u->file);

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
	if (u->special != NULL) {
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
	pmsg_free_null(&u->reply);
	HFREE_NULL(u->sending_error);

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
	g_assert(NULL == u->reply);

	entropy_harvest_time();

	if (u->io_opaque) {
		/* Was cloned after error sending, not during transfer */
		within_error = TRUE;
		io_free(u->io_opaque);
		u->io_opaque = NULL;
	}

	cu = WCOPY(u);
	parq_upload_upload_got_cloned(u, cu);

	if (upload_is_special(u))
		cu->flags |= UPLOAD_F_WAS_PLAIN;
	else
		cu->flags &= ~UPLOAD_F_WAS_PLAIN;

    cu->upload_handle = upload_new_handle(cu); /* fetch new handle */
	cu->last_sent = u->sent;			/* Bytes sent in previous request */
	cu->last_start = u->start_date;		/* Remember previous request start */
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
	cu->error_sent = 0;
	cu->http_status = 0;
	cu->http_status_sent = FALSE;
	cu->sending_error = NULL;			/* Freed by the parent upload */

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
	bool keep_alive, int code,
	http_send_status_cb_t unsent, void *unsent_arg,
	const char *msg)
{
	bool flushed;

	upload_check(u);
	g_assert(msg != NULL);

	if (u->keep_alive)
		socket_set_quickack(u->socket, FALSE);	/* Re-disable quick TCP ACKs */

	if (u->flags & UPLOAD_F_LIMITED) {
		send_upload_error(u, 403, "Unauthorized");
		return TRUE;
	}

	u->http_status = code;

	flushed = http_send_status(HTTP_UPLOAD,
		u->socket, code, keep_alive,
		u->hev, u->hevcnt, unsent, unsent_arg, "%s", msg);

	if (flushed)
		u->http_status_sent = TRUE;		/* For logging */

	return flushed;
}

/**
 * Record that we're sending a Retry-After for this resource (as identified
 * by u->sf), and penalize the remote host if another request comes before.
 */
static void
upload_enforce_retry_after(const struct upload *u, time_delta_t delay)
{
	const struct sha1 *sha1;
	struct upload_tag_key *tk;

	upload_check(u);
	g_assert(u->sf != NULL);

	delay -= 2;		/* Grace time for their computation errors, etc. */
	if (delay <= 0)
		return;

	sha1 = sha1_hash_available(u->sf) ? shared_file_sha1(u->sf) : NULL;
	if (NULL == sha1)
		return;		/* Not possible to enforce without a SHA1 */

	delay = MIN(RETRY_AFTER_ENFORCE_MAX, delay);

	tk = upload_tag_key_make(u->addr, sha1);
	ripening_insert_key(retry_after, delay, tk);
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
				NULL_PTR);
	} else {
		len = 0;
	}

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Host header back: only %u byte%s left",
			(unsigned) PLURAL(size));
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

	gnet_prop_get_storage(PROP_SERVENT_GUID, VARLEN(guid));

	rw = concat_strings(buf, size,
			"X-GUID: ", guid_hex_str(&guid), "\r\n",
			NULL_PTR);

	if (rw >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-GUID header back: only %u byte%s left",
			(unsigned) PLURAL(size));
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
	 */

	if ((flags & HTTP_CBF_BW_SATURATED) && u->n2r)
		return 0;

	len = concat_strings(buf, size,
			"X-Gnutella-Content-URN: ", sha1_to_urn_string(sha1), "\r\n",
			NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Gnutella-Content-URN header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
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
			NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send X-Thex-URI header back: only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	return len < size ? len : 0;
}

/**
 * This routine is called by http_send_status() on 416 errors to generate a
 * Retry-After header (added to the HTTP headers) into `buf'.
 *
 * @param buf		where the callback can generate extra data.
 * @param size		the size of buf in bytes.
 * @param arg		user-supplied data.
 * @param flags		extra flags passed by callback invoker
 *
 * @return the amount of bytes written to buf.
 */
static size_t
upload_retry_after(char *buf, size_t size, void *arg, uint32 flags)
{
	const struct upload_http_cb *a = arg;
	const struct upload *u = a->u;
	time_delta_t after;
	char ra[32];
	size_t len;

	upload_check(u);
	g_return_val_if_fail(u->sf != NULL, 0);
	(void) flags;

	/*
	 * The HTTP Retry-After is normally defined for 503 errors, but we also
	 * bend the protocol and return it as well for 416: partial files where
	 * the requested range is not available yet.
	 *
	 * Remote gtk-gnutella (and maybe other modern servents) will parse it
	 * and honour it for this particular file request, to avoid hammering.
	 * Of course, this is only to be used when there has been no updating
	 * on the file for some time.
	 *
	 * As a safety precaution, we compute the time since the last file
	 * modification and set a timeout to half that time, capped to 1 day.
	 * We do not send any Retry-After if there as been a recent modification
	 * on the file (i.e. the file is currently being downloaded).
	 */

	after = delta_time(tm_time(), shared_file_modification_time(u->sf)) / 2;
	after = MIN(after, ONE_DAY);

	if (after < 60)		/* Was updated this last minute */
		return 0;		/* No header generated */

	len = str_bprintf(ARYLEN(ra), "Retry-After: %s\r\n", int64_to_string(after));

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Retry-After header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	if (len >= size)
		return 0;

	upload_enforce_retry_after(u, after);
	cstr_bcpy(buf, size, ra);		/* Will loudly warn if failing */

	return len;
}

/**
 * This routine is called by http_send_status() to generate the
 * SHA1-specific headers (added to the HTTP status) into `buf'.
 *
 * @param buf		where the callback can generate extra data.
 * @param size		the size of buf in bytes.
 * @param arg		user-supplied data.
 * @param flags		extra flags passed by callback invoker
 *
 * @return the amount of bytes written to buf.
 */
static size_t
upload_http_content_urn_add(char *buf, size_t size, void *arg, uint32 flags)
{
	const struct sha1 *sha1;
	size_t rw = 0, mesh_len;
	const struct upload_http_cb *a = arg;
	struct upload *u = a->u;
	time_t last_sent;
	bool need_content_urn;
	uint32 urn_flags = flags;

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
		last_sent = upload_mi_get_stamp(u->addr, sha1, tm_time());
	}

	/*
	 * If we sent mesh information for THIS upload, it means we're facing
	 * a follow-up request and we don't need to send them the SHA1
	 * again.
	 *		--RAM, 18/10/2003
	 *
	 * However, legacy Phex servents (don't know exactly up to which version)
	 * do expect to see the X-Gnutella-Content-URN line regardless of whether
	 * it's a follow-up request.  Failing that, they will close the connection.
	 * This create a loose-loose situation: they can wait up in the PARQ queue
	 * and then when it's their turn, they cannot benefit. And we reserved
	 * the slot for them, denying it to another servent for nothing.  Given
	 * that Phex is no longer maintained, we have to work-around this here.
	 *		--RAM, 2015-08-18
	 */

	need_content_urn = !u->is_followup;		/* TRUE on first request */

	if (
		!need_content_urn &&
		u->user_agent != NULL &&
		is_strprefix(u->user_agent, "Phex ")
	) {
		need_content_urn = TRUE;				/* Workaround for Phex */
		urn_flags &= ~HTTP_CBF_BW_SATURATED;	/* Force generation of header */
	}

	if (need_content_urn) {
		rw += upload_gnutella_content_urn_add(&buf[rw], size - rw,
				arg, urn_flags);	/* urn_flags, not flags, for Phex */
	}

	/*
	 * The X-Thex-URI line is never sent on follow-up requests.
	 */

	if (!u->is_followup && !(flags & HTTP_CBF_SMALL_REPLY))
		rw += upload_thex_uri_add(&buf[rw], size - rw, arg, flags);

	/*
	 * Ranges are only emitted for partial files, so no pre-estimation of
	 * the size of the mesh entries is needed when replying for a full file.
	 *
	 * However, we're not going to include the available ranges when we
	 * are returning a 503 "busy" or "queued" indication, or any 4xx indication
	 * (but 416) since the data will be stale by the time it is needed.
	 *
	 * We only dump them when explicitly requested to do so.
	 * Otherwise, we let them know about the amount of data we have for the
	 * file, so that they know we hold only a fraction of it.
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

		if (flags & HTTP_CBF_SMALL_REPLY)
			mesh_len = 0;
		else {
			mesh_len = dmesh_alternate_location(sha1,
						ARYLEN(alt_locs), u->addr,
						last_sent, u->user_agent, NULL, FALSE,
						u->fwalt ? u->guid : NULL, u->net);
		}

		if (size - rw > mesh_len) {
			size_t len, avail;

			/*
			 * Emit the X-Available-Ranges: header if file is partial and we're
			 * not returning a busy signal.  Otherwise, just emit the
			 * X-Available header.
			 */

			avail = size - rw - mesh_len;

			if (flags & HTTP_CBF_RETRY_PRIO) {
				avail = MIN(avail, RANGES_SIZE);
			} else if (flags & HTTP_CBF_SMALL_REPLY) {
				avail /= 2;
				avail = MAX(avail, RANGES_SIZE);
			}

			if (flags & HTTP_CBF_BUSY_SIGNAL) {
				len = file_info_available(shared_file_fileinfo(u->sf),
						&buf[rw], avail);
			} else {
				len = file_info_available_ranges(shared_file_fileinfo(u->sf),
						&buf[rw], avail);
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
					&buf[rw], avail, u->addr,
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

	uint64_to_string_buf(u->file_size, ARYLEN(fsize));
	len = concat_strings(buf, size,
			"Content-Range: bytes */", fsize, "\r\n", NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Range header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	/* Don't emit a truncated header */
	return len < size ? len : 0;
}

static size_t
upload_http_content_length_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	const struct upload_http_cb *a = arg;
	const struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	len = concat_strings(buf, size,
			"Content-Length: ", uint64_to_string(u->end - u->skip + 1), "\r\n",
			NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Length header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_content_type_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	const struct upload_http_cb *a = arg;
	const struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	if (!u->sf)
		return 0;

	shared_file_check(u->sf);
	len = concat_strings(buf, size,
			"Content-Type: ", shared_file_mime_type(u->sf), "\r\n",
			NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Type header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_last_modified_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	const struct upload_http_cb *a = arg;
	size_t len;

	(void) unused_flags;

	len = concat_strings(buf, size,
			"Last-Modified: ", timestamp_rfc1123_to_string(a->mtime), "\r\n",
			NULL_PTR);

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Last-Modified header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
	}

	return len < size ? len : 0;
}

static size_t
upload_http_content_range_add(char *buf, size_t size,
	void *arg, uint32 unused_flags)
{
	const struct upload_http_cb *a = arg;
	const struct upload *u = a->u;
	size_t len;

	(void) unused_flags;
	upload_check(u);

	if (u->skip || u->end != (u->file_size - 1)) {
		len = concat_strings(buf, size,
				"Content-Range: bytes ",
				uint64_to_string(u->skip), "-", uint64_to_string2(u->end),
				"/", filesize_to_string(u->file_size),
				"\r\n",
				NULL_PTR);
	} else {
		len = 0;
	}

	if (len >= size && GNET_PROPERTY(upload_debug)) {
		g_warning("U/L cannot send Content-Range header back: "
			"only %u byte%s left",
			(unsigned) PLURAL(size));
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

	rw += upload_http_last_modified_add(&buf[rw], size - rw, arg, flags);
	rw += upload_http_content_type_add(&buf[rw], size - rw, arg, flags);
	return rw;
}

/**
 * This routine is called by http_send_status() to generate the
 * mandatory upload-specific headers into `buf'.
 *
 * This is for prioritary headers that must be generated or the downloading
 * host will not be able to process the incoming data properly.
 */
static size_t
upload_http_status_mandatory(char *buf, size_t size, void *arg, uint32 flags)
{
	size_t rw = 0;

	/*
	 * When there is not enough room in the header to include all the
	 * information added by the callbacks, a second pass is made with
	 * just the prioritary headers.  The http_send_status() routine
	 * indicates that with the HTTP_CBF_RETRY_PRIO flag set.
	 *
	 * In that case, we do not generate the Content-Length header if
	 * we managed (and required) a Content-Range header.  We'll know
	 * about that by monitring the returned value: a 0 indicates that
	 * the callback could not (or did not need to) generate the header.
	 *
	 * 		--RAM, 2020-06-03
	 */

	rw += upload_http_content_range_add(&buf[rw], size - rw, arg, flags);

	if (0 == (HTTP_CBF_RETRY_PRIO & flags) || 0 == rw)
		rw += upload_http_content_length_add(&buf[rw], size - rw, arg, flags);

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
	g_return_if_fail(u->hevcnt < N_ITEMS(u->hev));

	http_extra_callback_set(&u->hev[u->hevcnt], callback, user_arg);
	u->hevcnt++;
}

/**
 * Record additional header-generation prioritary callback to invoke when
 * we generate the HTTP status.
 *
 * A prioritary callback is noramlly always emitted in the HTTP status but
 * others can have their output dropped when the header size becomes too large.
 *
 * Use that for mandatory headers that need to be sent back or the remote host
 * will not be able to properly parse the reply (e.g. the Content-Range header
 * when a partial request is made).
 */
static void
upload_http_extra_prio_callback_add(struct upload *u,
	http_status_cb_t callback, void *user_arg)
{
	upload_check(u);
	g_return_if_fail(u->hevcnt < N_ITEMS(u->hev));

	http_extra_prio_callback_set(&u->hev[u->hevcnt], callback, user_arg);
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
	g_assert(u->hevcnt <= N_ITEMS(u->hev));

	for (i = 0; i < u->hevcnt; /* empty */) {
		if G_UNLIKELY(http_extra_callback_matches(&u->hev[i], callback)) {
			ARRAY_REMOVE_DEC(u->hev, i, u->hevcnt);
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
	g_return_if_fail(u->hevcnt < N_ITEMS(u->hev));

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
	g_return_if_fail(u->hevcnt < N_ITEMS(u->hev));

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
	g_return_if_fail(u->hevcnt < N_ITEMS(u->hev));

	http_extra_body_set(&u->hev[u->hevcnt], body);
	u->hevcnt++;
}

/**
 * The vectorized (message-wise) version of send_upload_error().
 */
static bool
send_upload_error_v(struct upload *u, const char *ext, int code,
	const char *msg, va_list ap)
{
	char reason[1024];
	char extra[1024];

	upload_check(u);

	if (u->flags & UPLOAD_F_LIMITED) {
		if (GNET_PROPERTY(upload_debug)) {
			g_debug("upload request from %s [%s] limited for %s",
				host_addr_to_string(u->addr),
				gip_country_name(u->addr),
				u->name ? u->name : "<unkonwn resource>");
		}
		u->flags &= ~UPLOAD_F_LIMITED;		/* For recursion */
		u->keep_alive = FALSE;				/* Force disconnection */
		if (u->flags & UPLOAD_F_NORMAL_LIMIT) {
			send_upload_error(u, 403, "Unauthorized");
		} else if (!(u->flags & UPLOAD_F_STEALTH_LIMIT)) {
			send_upload_error(u, 403, "Limiting connections from %s",
				gip_country_name(u->addr));
		}
		return TRUE;	/* Assume OK */
	}

	if (msg && no_reason != msg) {
		str_vbprintf(ARYLEN(reason), msg, ap);
	} else
		reason[0] = '\0';

	if (u->error_sent) {
		if (GNET_PROPERTY(upload_debug)) g_warning(
			"already sent an error %d to %s, not sending %d (%s)",
			u->error_sent, host_addr_to_string(u->addr), code, reason);
		return TRUE;	/* Assume OK */
	}

	extra[0] = '\0';

	/*
	 * If `ext' is not null, we have extra header information to propagate.
	 */

	if (ext) {
		if (cstr_fcpy(ARYLEN(extra), ext)) {
			upload_http_extra_line_add(u, extra);
		} else {
			g_warning("%s: ignoring too large extra header (%zu bytes)",
				G_STRFUNC, vstrlen(ext));
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
				if (html_escape(uri, ARYLEN(href)) >= sizeof href) {
					/* If the escaped href is too long, leave it out. They
				 	 * might get an ugly filename but at least the URI
				 	 * works. */
					href[0] = '\0';
				}
				if (uri != u->name)
					HFREE_NULL(uri);
			}

			str_bprintf(ARYLEN(index_href),
				"/get/%lu/", (ulong) u->file_index);
			str_bprintf(ARYLEN(buf),
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
					retry, product_name(), retry);
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
			host_addr_to_string(u->addr),
			upload_vendor_str(u),
			u->status, reason);

	}

	u->error_sent = code;

	/* We do not care about partially sent replies on errors */

	if (code != 503 || u->status != GTA_UL_QUEUED) {
		return upload_send_http_status(u, u->keep_alive, code,
					HTTP_ATOMIC_SEND, reason);
	}

	/*
	 * This is an active queueing operation, we need to send the whole header
	 * or we'll break things on the remote side.
	 * 		--RAM, 2017-08-09
	 */

	return upload_send_http_status(u, u->keep_alive, code,
				upload_http_status_partially_sent, u, reason);
}

/**
 * Send error message to requestor.
 *
 * This can only be done once per connection.
 *
 * @attention
 * The messsage is not meant to be user-visible and therefore needs to be
 * in plain English (must not be translated).
 *
 * @return TRUE if we were able to completely flush the status.
 */
static bool
send_upload_error(struct upload *u, int code, const char *msg, ...)
{
	va_list args;
	bool ret;

	upload_check(u);

	va_start(args, msg);
	ret = send_upload_error_v(u, NULL, code, msg, args);
	va_end(args);

	return ret;
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
		str_vbprintf(ARYLEN(errbuf), reason, ap);
		logreason = errbuf;
	} else {
		if (u->error_sent) {
			str_bprintf(ARYLEN(errbuf), "HTTP %d", u->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = N_("No reason given");
		}
	}

	if (!UPLOAD_IS_COMPLETE(u) && GNET_PROPERTY(upload_debug) > 1) {
		str_t *s = str_new(128);

		str_catf(s, "ending %supload ", u->push ? "pushed " : "");
		if (u->name != NULL)
			str_catf(s, "of %s \"%s\" ", u->head_only ? "HEAD" : "GET", u->name);
		str_catf(s, "[%s bytes out, %s total] request #%u [%sHTTP %03d] ",
			uint64_to_string(u->sent),
			uint64_to_string2(u->total_sent),
			u->reqnum, u->http_status_sent ? "" : "unsent ", u->http_status);
		if (u->push)
			str_catf(s, "to %s", host_addr_port_to_string(u->addr, u->port));
		else
			str_catf(s, "from %s", host_addr_to_string(u->addr));
		if (u->user_agent != NULL)
			str_catf(s, " (%s)", u->user_agent);
		str_catf(s, ": %s", logreason);
		g_debug("%s", str_2c(s));
		str_destroy(s);
	}

	/*
	 * Check for obvious abuse: a servent requesting some chunk and
	 * then not even bothering to get the output back.
	 * 		--RAM, 2020-06-06
	 */

	if (
		0 == u->sent &&				/* No payload sent back for this request */
		0 == u->total_sent &&		/* And never sent any payload yet */
		(u->http_status >= 200 && u->http_status < 300) &&	/* 2xx status code */
		!u->head_only &&			/* Not a HEAD request */
		u->http_status_sent			/* And header was sent back */
	) {
		ban_penalty(BAN_CAT_HTTP, u->addr, "Not reading HTTP payloads");
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
		if (reason == NULL) {
			reason = N_("Bad Request");		/* `reason' is untranslated */
			logreason = _(reason);			/* `logreason' is translated */
		}
		send_upload_error(u, 400, "%s", reason);
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
		str_vbprintf(ARYLEN(errbuf), _(reason), apcopy);
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
 * Signal that we cannot serve request because the library is being rebuilt.
 */
static void
upload_error_library_rebuilt(struct upload *u)
{
	upload_check(u);

	ban_legit(BAN_CAT_HTTP, u->addr);
	/* Retry-able by user, hence 503 */
	upload_error_remove(u, 503, N_("Library being rebuilt"));
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

	file_object_close(&u->file);	/* expect_http_header() expects this */
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
		bool flushed;

		u->sending_error = h_strdup(msg);	/* For upload_http_status_sent() */

		flushed = upload_send_http_status(u, TRUE, code,
					upload_http_status_partially_sent, u, msg);

		if (flushed)
			upload_http_status_sent(u);
	} else {
		/*
		 * About to remove upload and close connect: we don't care about
		 * a partially-sent HTTP status.
		 */

		upload_send_http_status(u, FALSE, code, HTTP_ATOMIC_SEND, msg);
		upload_remove_nowarn(u, _(msg));
	}
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

	PSLIST_FOREACH(list_uploads, sl) {
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

	PSLIST_FOREACH(to_stop, sl) {
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

			concat_strings(ARYLEN(name), "!", user_agent, NULL_PTR);
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
	getline_free_null(&s->getline);
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
		rw = str_bprintf(ARYLEN(giv), "PUSH guid:%s\r\n\r\n", guid_hex_str(guid));
	} else {
		rw = str_bprintf(ARYLEN(giv), "GIV %lu:%s/file\n\n",
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
			host_addr_to_string(u->addr),
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

	if (-1 == stat(shared_file_path(sf), &sb)) {
		g_warning("%s(): cannot stat() shared file \"%s\": %m",
			G_STRFUNC, shared_file_path(sf));
		goto failure;
	}

	if (!S_ISREG(sb.st_mode)) {
		g_warning("%s(): shared file \"%s\" is no longer a regular file",
			G_STRFUNC, shared_file_path(sf));
		goto failure;
	}

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
			g_warning("%s(): shared file \"%s\" was modified since completion",
				G_STRFUNC, shared_file_path(sf));
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

	if (fi != NULL) {
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
			dmesh_collect_negative_locations(sha1, buf, u->addr, u->user_agent);
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
			shared_file_unref(&sf);
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

		if (SHARE_REBUILDING == sfn) {
			shared_file_unref(&sf);
			goto library_rebuilt;
		}

		if (sfn && sf != sfn) {
			char location[1024];
			char *escaped;

			if (!sha1_hash_is_uptodate(sfn)) {
				shared_file_unref(&sfn);
				shared_file_unref(&sf);
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
			 * Be nice for PFSP as well.  They must have learnt about
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

			str_bprintf(ARYLEN(location),
				"Location: /get/%lu/%s\r\n",
				(ulong) shared_file_index(sfn), escaped);

			if (escaped != shared_file_name_nfc(sfn)) {
				HFREE_NULL(escaped);
			}

			/*
			 * By setting u->sf to the new location, we allow the HTTP
			 * reply to include the SHA1 of the file as well as some
			 * alternate locations. See send_upload_error_v().
			 */

			shared_file_unref(&sf);
			u->sf = sfn;
			upload_error_remove_ext(u, location, 301, "Moved Permanently");
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
	upload_error_library_rebuilt(u);
	return -1;
}

static void
upload_request_tth(shared_file_t *sf)
{
	if (shared_file_is_servable(sf) && NULL == shared_file_tth(sf)) {
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

	if (urn_get_bitprint(uri, vstrlen(uri), &sha1, &tth_buf)) {
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
		upload_error_library_rebuilt(u);
		return -1;
	}

	if (sf == NULL) {
		goto not_found;
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

	if (urn_get_bitprint(uri, vstrlen(uri), &sha1, &tth_buf)) {
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
		atom_str_change(&u->name, bitprint_to_urn_string(&sha1, tth));
		upload_error_library_rebuilt(u);
		return -1;
	}
	if (sf == NULL) {
		atom_str_change(&u->name, bitprint_to_urn_string(&sha1, tth));
		goto not_found;
	}
	atom_str_change(&u->name, shared_file_name_nfc(sf));

	if (shared_file_is_partial(sf) && !shared_file_is_finished(sf)) {
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
			NULL == vstrchr(&endptr[1], '/')
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
			size_t ulen;

			ua = header_get_extended(header, "User-Agent", &ulen);
			if (
				NULL == ua ||
				NULL == pattern_strstrlen(ua, ulen, pat_applewebkit)
			)
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
		if (vstrchr(tok, '/'))
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

	strtok_free_null(&st);

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
		addr = u->addr;
		port = 0;
	} else if (is_private_addr(addr)) {
		addr = u->addr;
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
	size_t count;

	u->browse_host = TRUE;
	u->name = atom_str_get(_("<Browse Host Request>"));

	if (GNET_PROPERTY(upload_debug) > 1)
		g_debug("BROWSE request from %s (%s)",
			host_addr_to_string(u->addr),
			upload_vendor_str(u));

	if (!GNET_PROPERTY(browse_host_enabled)) {
		if (ctl_limit(u->addr, CTL_D_BROWSE | CTL_D_STEALTH)) {
			upload_remove(u, N_("Limited connection"));
		} else {
			upload_send_error(u, 403, N_("Browse Host Disabled"));
		}
		return -1;
	}

	if (ctl_limit(u->addr, CTL_D_BROWSE)) {
		if (ctl_limit(u->addr, CTL_D_NORMAL)) {
			send_upload_error(u, 403, "Browse Host Disabled");
		} else if (!ctl_limit(u->addr, CTL_D_STEALTH)) {
			send_upload_error(u, 404, "Limiting connections from %s",
				gip_country_name(u->addr));
		}
		upload_remove(u, N_("Limited connection"));
		return -1;
	}

	/*
	 * Throttle browsing requests from indelicate clients...
	 *
	 * We limit such requests to one per BROWSING_THRESH seconds,
	 * which will also take care of broken servents sending several
	 * requests concurrently!
	 *
	 * If they send more than BROWSING_ABUSE requests, revitalise the key
	 * so that browsing will be throttled until they totally stop for
	 * BROWSING_THRESH seconds.
	 */

	count = aging_saw_another(browsing_reqs, &u->addr, host_addr_wcopy);

	if (count > 1) {
		send_upload_error(u, 429, "Cannot Browse Too Often");
		if (count >= BROWSING_ABUSE) {
			(void) aging_lookup_revitalise(browsing_reqs, &u->addr);
			upload_remove(u, N_("Browsing abuse detected"));
			ban_record(BAN_CAT_HTTP, u->addr, "Browsing abuse");
		} else {
			upload_remove(u, N_("Browsing throttled"));
		}
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

		str_bprintf(ARYLEN(location), fmt,
			GNET_PROPERTY(server_hostname), GNET_PROPERTY(listen_port));
		upload_http_extra_line_add(u, location);
		upload_send_http_status(u, FALSE, 301, HTTP_ATOMIC_SEND, "Redirecting");
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

		str_bprintf(ARYLEN(lm_buf), "Last-Modified: %s\r\n",
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

	PSLIST_FOREACH(list_uploads, sl) {
		struct upload *up = cast_to_upload(sl->data);

		if (up == upload)
			continue;				/* Current upload is already in list */
		if (!UPLOAD_IS_SENDING(up) && up->status != GTA_UL_QUEUED)
			continue;
		if (
			host_addr_equiv(up->socket->addr, upload->socket->addr) && (
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

		PSLIST_FOREACH(to_remove, sl) {
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
 * Called when the upload HTTP status has been fully sent out.
 *
 * This is only used when we monitor whether the HTTP status is fully sent,
 * not when we reasonably expect that it be atomically sent at the first
 * attempt, or when we simply do not care whether it will be sent at all
 * before closing the connection.
 *
 * Indeed, tracking whether the header has been completely sent out perturbs
 * the normal linear code flow, due the asynchronous nature of the flushing
 * that needs to take place before we continue, and this routine has to handle
 * all the cases where we are doing that, to be able to factorize the code
 * required to resume processing.  Since asynchronous flushing is a rare
 * event that can only happen when the socket on which we're sending back the
 * HTTP status is clogged by previously unsent data and therefore the kernel
 * needs to flow-control the user land, most partial sending will occur during
 * follow-up HTTP requests.  We therefore need to only be careful when we have
 * an interest in keeping the connection alive properly in order to be able to
 * receive another follow-up request.
 * 		--RAM, 2017-08-10
 */
static void
upload_http_status_sent(struct upload *u)
{
	u->last_update = tm_time();

	/*
	 * If we were sending an error back, with the connection kept alive
	 * so that they can try with a new request (e.g. on a 416 for an
	 * improper range), make sure we clone the upload before waiting for
	 * aother HTTP request.
	 */

	if (u->sending_error != NULL) {
		struct upload *cu;

		if (u->special != NULL) {
			(*u->special->close)(u->special, FALSE);
			u->special = NULL;
		}

		u->reqnum++;
		cu = upload_clone(u);
		cu->last_was_error = TRUE;
		upload_wait_new_request(cu);
		upload_remove_nowarn(u, _(u->sending_error));
		return;
	}

	/*
	 * If we were sending a queued status for an actively queued connection,
	 * we need to wait for the follow-up request now.
	 */

	if (GTA_UL_QUEUED == u->status) {
		u->error_sent = 0;	/* New request allowed to return an error code */
		expect_http_header(u, GTA_UL_QUEUED);
		return;
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
		return;
	}

	io_free(u->io_opaque);
	u->io_opaque = NULL;

	socket_send_buf(u->socket, GNET_PROPERTY(upload_tx_size) * 1024, FALSE);

	u->start_date = u->last_update;		/* We're really starting to send now */
	upload_fire_upload_info_changed(u);	/* Update GUI for the send starting time */

	if (upload_is_special(u)) {
		gnet_host_t peer;

		gnet_host_set(&peer, u->socket->addr, u->socket->port);

		if (u->browse_host) {
			u->special = browse_host_open(u, &peer,
					upload_special_writable,
					&upload_tx_deflate_cb,
					&upload_tx_link_cb,
					&u->socket->wio,
					u->special_flags);
		} else if (u->thex) {
			u->special = thex_upload_open(u, &peer,
					u->thex,
					upload_special_writable,
					&upload_tx_link_cb,
					&u->socket->wio,
					u->special_flags);
			shared_file_unref(&u->thex);
		} else {
			g_assert_not_reached();
		}
	} else {
		/*
		 * Install the output I/O, which is via a bandwidth limited source.
		 */

		g_assert(u->socket->gdk_tag == 0);
		g_assert(u->bio == NULL);

		u->bio = bsched_source_add(bsched_out_select_by_addr(u->addr),
					&u->socket->wio, BIO_F_WRITE, upload_writable, u);

		/*
		 * Decimate max bandwidth by additional amount of power of 2 in
		 * case the address is known to be stalling.
		 * 		--RAM, 2020-05-26
		 */

		if (u->flags & (UPLOAD_F_STALLED|UPLOAD_F_EARLY_STALL))
			bio_add_penalty(u->bio, 1);

		if (aging_lookup(early_stalling_uploads, &u->addr))
			bio_add_penalty(u->bio, 1);

		if (aging_lookup(stalling_uploads, &u->addr))
			bio_add_penalty(u->bio, 2);

		/*
		 * In addition to b/w penalty, set-up b/w capping: the maximum
		 * amount of data we shall write per second.  This is computed
		 * dynamically at each follow-up request and allows us to avoid
		 * overwhelming the remote host with more data it can consume.
		 * 		--RAM, 2020-05-27
		 */

		if (0 != u->bw_cap)
			u->bw_cap = bio_set_cap(u->bio, u->bw_cap);

		upload_stats_file_begin(u->sf);
	}
}

/**
 * I/O callback invoked when we can write more data to the server to finish
 * sending the HTTP status reply.
 */
static void
upload_write_status(void *data, int unused_source, inputevt_cond_t cond)
{
	struct upload *u = data;
	pmsg_t *r;
	gnutella_socket_t *s;
	int rw;
	const char *base;
	ssize_t sent;
	const char *msg = _("Could not send whole HTTP status");

	(void) unused_source;
	upload_check(u);

	s = u->socket;
	r = u->reply;

	g_assert(s->gdk_tag);		/* I/O callback is still registered */
	pmsg_check(r);

	if G_UNLIKELY(cond & INPUT_EVENT_EXCEPTION) {
		socket_eof(s);
		upload_remove(u, "%s", msg);
		return;
	}

	rw = pmsg_size(r);			/* Data we still have to send */
	base = pmsg_start(r);		/* And where unsent data start */

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, base, rw);
	if ((ssize_t) -1 == sent) {
		upload_remove(u, "%s: %s", msg, g_strerror(errno));
		return;
	} else if (sent < rw) {
		pmsg_discard(r, sent);	/* Move start past the data we sent */
		u->last_update = tm_time();
		return;
	} else {
		if (GNET_PROPERTY(upload_trace) & SOCK_TRACE_OUT) {
			g_debug("----Sent HTTP status completely to %s (%zu bytes):",
				host_addr_to_string(s->addr), pmsg_phys_len(r));
			dump_string(stderr, pmsg_phys_base(r), pmsg_phys_len(r), "----");
		}
	}

	/*
	 * HTTP status reply was completely sent.
	 */

	if (GNET_PROPERTY(upload_debug)) {
		int code =
			http_status_parse(pmsg_phys_base(r), "HTTP", NULL, NULL, NULL);

		g_debug("flushed partially written HTTP %d status to %s (%zu bytes)",
			code, host_addr_to_string(s->addr), pmsg_phys_len(r));
	}

	socket_evt_clear(s);
	pmsg_free_null(&u->reply);
	u->http_status_sent = TRUE;			/* For logging */

	upload_http_status_sent(u);
}

/**
 * Traps partially sent HTTP status headers.
 *
 * @param data		start of the header
 * @param len		total length of the header
 * @param sent		amount sent
 * @param arg		the upload request
 */
static void
upload_http_status_partially_sent(
	const char *data, size_t len, size_t sent, void *arg)
{
	struct upload *u = arg;

	upload_check(u);
	g_assert(NULL == u->reply);

	u->reply = http_pmsg_alloc(data, len, sent);
	u->last_update = tm_time();

	/*
	 * Do some logging if debugging.
	 */

	if (GNET_PROPERTY(upload_debug)) {
		int code = http_status_parse(data, "HTTP", NULL, NULL, NULL);;

		g_debug("partially sent %zu byte%s for HTTP %d status to %s (%zu bytes)",
			PLURAL(sent), code, host_addr_to_string(u->addr), len);
	}

	/*
	 * Install the writing callback.
	 */

	g_assert(u->socket->gdk_tag == 0);

	socket_evt_set(u->socket, INPUT_EVENT_WX, upload_write_status, u);
}

/**
 * Handle request for a shared file.
 *
 * @return TRUE if we're going to actually serve the request.
 */
static bool
upload_request_for_shared_file(struct upload *u, const header_t *header)
{
	filesize_t range_skip = 0, range_end = 0, max_chunk_size, requested;
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

	if (
		u->push && idx != u->file_index &&
		GNET_PROPERTY(upload_debug) &&
		0 != strcmp(u->name, shared_file_name_nfc(u->sf))
	) {
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
	 * Enforcing Retry-After, not applicable of course to follow-up requests,
	 * but applicable to HEAD requests!
	 */

	if (u->sha1 != NULL && !u->is_followup) {
		struct upload_tag_key key;

		key.addr = u->addr;
		key.sha1 = u->sha1;

		if (ripening_contains(retry_after, &key))
			ban_penalty(BAN_CAT_HTTP, u->addr, "Not honouring Retry-After");
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
		u->cb_416_arg.mtime = shared_file_modification_time(u->sf);
		upload_http_extra_callback_add(u, upload_416_extra, &u->cb_416_arg);
		upload_http_extra_callback_add(u, upload_retry_after, &u->cb_416_arg);
		upload_http_extra_callback_add(u,
			upload_http_last_modified_add, &u->cb_416_arg);
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
		u->cb_sha1_arg.mtime = shared_file_modification_time(u->sf);
		upload_http_extra_prio_callback_add(u,
			upload_http_content_urn_add, &u->cb_sha1_arg);
		upload_http_extra_callback_add(u, upload_retry_after, &u->cb_sha1_arg);
		upload_http_extra_callback_add(u,
			upload_http_last_modified_add, &u->cb_sha1_arg);

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
			char after[80];
			time_delta_t delay = delta_time(expire, now);

			if (delay <= 0)
				delay = 60;		/* Let them retry in a minute, only */

			upload_enforce_retry_after(u, delay);

			str_bprintf(ARYLEN(after), "Retry-After: %u\r\n", (unsigned) delay);

			/*
			 * Looks like upload got removed from PARQ queue. For now this
			 * only happens when a client got banned. Bye bye!
			 *		-- JA, 19/05/'03
			 */
			upload_error_remove_ext(u, after, 429,
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
				bool ok;

				ok = send_upload_error(u, 503, "Queued (slot %d, ETA: %s)",
					  parq_upload_lookup_position(u),
					  short_time_ascii(parq_upload_lookup_eta(u)));

				if (ok)
					upload_http_status_sent(u);
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
	 * Bandwidth capping:
	 *
	 * - if the remote host is known to have been stalling, then limit its
	 *   first chunk to a maximum of TX_FIRST_STALL bytes, so that we can measure
	 *   the apparent b/w we're getting.  For other hosts, limit to the
	 *   reasonable TX_FIRST_CHUNK to avoid them requesting the whole file
	 *   without us getting to measure the apparent bandwidth we have on that
	 *   connection.
	 *
	 * - otherwise, for follow-up requests, we have already computed the b/w
	 *   cap we're going to enforce in u->bw_cap.  Compute a suitable chunk
	 *   size so that the transfer takes about TX_DURATION seconds.
	 *
	 * The rationale is that we want to avoid stalling uploads, so we're
	 * monitoring the apparent bandwidth available with the remote host, whilst
	 * ensuring that we do rather frequent adjustments.  Should the b/w drop
	 * to a ridiculous level below 1 KiB/s and the remote end were to request
	 * a 1 MiB chunk, it would mean the next b/w adjustment would only occur
	 * in 1024 seconds, more than 17 minutes!  That is way too long to be able
	 * to react to b/w fluctuations.
	 *
	 * All chunk sizes are aligned to a power-of-two and we ensure a minimal
	 * size of TX_MIN_CHUNK to avoid the problem of getting so small a size that
	 * the HTTP header overhead associated with the response becomes bigger
	 * than the data we send back!
	 *
	 * 		--RAM, 2020-06-01
	 */

	if (u->head_only)		/* No capping for HEAD requests */
		goto head_request;	/* Avoid indenting too much code below */

	requested = range_end - range_skip + 1;
	max_chunk_size = 0;		/* Signals: no adjustment necessary */

	if (u->is_followup) {
		if (u->bw_cap != 0) {
			ulong maxsize = TX_DURATION * u->bw_cap;

			if (requested > maxsize) {
				max_chunk_size = next_pow2_64(maxsize);
				if (max_chunk_size > maxsize)		/* Not a power of 2 */
					max_chunk_size >>= 1;			/* Drop to previous power */
				if (max_chunk_size < TX_MIN_CHUNK)
					max_chunk_size = TX_MIN_CHUNK;	/* Our minimum */
			}
		}
	} else if (
		aging_lookup(stalling_uploads, &u->addr) ||
		aging_lookup(early_stalling_uploads, &u->addr)
	) {
		max_chunk_size = TX_FIRST_STALL;	/* First request on stalling host */
	} else {
		max_chunk_size = TX_FIRST_CHUNK;	/* First request for other hosts */
	}

	/*
	 * Adjust their request if they end-up asking for more than we are willing
	 * to serve them right now.
	 */

	if (max_chunk_size != 0 && max_chunk_size < requested) {
		if (GNET_PROPERTY(upload_debug) > 1) {
			g_debug(
				"UL b/w cap is %s/s for host %s (%s), %srequest #%u capped to %s",
				short_size(u->bw_cap, FALSE),
				host_addr_to_string(u->addr), upload_vendor_str(u),
				u->is_followup ? "" : "initial ",
				u->reqnum, short_size2(max_chunk_size, FALSE));
		}

		u->end = range_end = range_skip + max_chunk_size - 1;
		u->shrunk_chunk = TRUE;
		requested = max_chunk_size;
	} else {
		u->shrunk_chunk = FALSE;
	}

	/*
	 * Keep track of the amount they requested, for possible greed limit
	 * someday.
	 */

	u->total_requested += requested;

	/* FALL THROUGH */

head_request:
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
	 * If it's not a HEAD request but a new request, then mark the
	 * connection legitimate so that it does not count against the
	 * banning limits for that host.  This allows them to initiate
	 * several download requests, as long as they have the upload
	 * slots or the active queue slots.
	 * 		--RAM, 2020-06-03
	 */

	if (!u->head_only && !u->is_followup && !u->was_actively_queued)
		ban_legit(BAN_CAT_HTTP, u->addr);

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

	/* Necessary headers */
	upload_http_extra_prio_callback_add(u,
		upload_http_status_mandatory, &u->cb_status_arg);

	/* Send these headers provided everything fits in the reply */
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

		len = cstr_lcpy(p, size,
				"Content-Disposition: inline; filename*=\"utf-8'en'");
		g_assert(len < sizeof cd_buf);

		p += len;
		size -= len;

		len = url_escape_into(shared_file_name_nfc(u->sf), p, size);
		if ((size_t) -1 != len) {
			static const char term[] = "\"\r\n";

			p += len;
			size -= len;
			if (size > CONST_STRLEN(term)) {
				cstr_bcpy(p, size, term);
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

		if (
			upload_send_http_status(u, u->keep_alive, http_code,
				upload_http_status_partially_sent, u, http_msg)
		) {
			upload_http_status_sent(u);
		}
	}

	return !u->head_only;
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
upload_parse_uri(header_t *header, const char *uri, char *host, size_t host_size)
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

		clamp_strncpy(host, host_size, h, len + 1);
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
			cstr_bcpy(host, host_size, value);
		}
	}
	return deconstify_char(uri);
}

static void
remove_trailing_http_tag(char *request)
{
	char *endptr;

	endptr = pattern_strstr(request, pat_http);
	if (endptr) {
		while (request != endptr && is_ascii_blank(*(endptr - 1))) {
			endptr--;
		}
		*endptr = '\0';
	}
}

static uint64
get_content_length(const header_t *header)
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

	/*
	 * Use substraction to avoid compiler warning since we are comparing
	 * values from distinct enums.  We assert the two values must be identical.
	 */
	STATIC_ASSERT(0 == (THEX_UPLOAD_F_CHUNKED - BH_F_CHUNKED));

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

		str_bprintf(ARYLEN(name),
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
			upload_http_extra_prio_callback_add(u,
				upload_http_content_length_add, &u->cb_length_arg);
		}
	}

	u->special_flags = flags;

	if (
		upload_send_http_status(u, u->keep_alive, 200,
			upload_http_status_partially_sent, u, "OK")
	) {
		upload_http_status_sent(u);
	}

	return !u->head_only;
}

/**
 * Upgrade the upload socket to TLS, then invoke the specified callback with
 * the upload to terminate the action that was being processed before the
 * upgrade, in order to reply once the switch has been made.
 *
 * Note that the connection will be forcefully closed if the upgrade does
 * not succeed, i.e. TLS cannot handshake with the remote client.
 */
static void
upload_tls_upgrade(struct upload *u, notify_fn_t upgraded)
{
	gnutella_socket_t *s;
	char buf[80];

	upload_check(u);
	socket_check(u->socket);

	s = u->socket;

	g_assert(!socket_uses_tls(s));
	g_assert(0 == s->pos);			/* No unread data after request */

	if (GNET_PROPERTY(upload_debug)) {
		g_debug("UL request #%u from %s (%s): upgrading to TLS",
			u->reqnum, host_addr_to_string(u->addr), upload_vendor_str(u));
	}

	/*
	 * There is no Content-Length line to generate since this is a
	 * continuation header: the client must continue to read after
	 * upgrading the socket on its side.
	 */

	str_bprintf(ARYLEN(buf), "Upgrade: TLS/1.0, HTTP/%d.%d\r\n",
		u->http_major, u->http_minor);

	upload_http_extra_line_add(u, buf);
	upload_http_extra_line_add(u, "Connection: Upgrade\r\n");
	upload_send_http_status(u, TRUE, 101,
		HTTP_ATOMIC_SEND, "Switching Protocols");

	/*
	 * Because socket_tls_upgrade() guarantees that the socket will not be
	 * destroyed synchronously on error, we can access the upload structure
	 * upon return.
	 */

	socket_tls_upgrade(s, upgraded, u);
	u->tls_upgraded = TRUE;		/* In progress, will succeed hopefully */
}

/*
 * Perform necessary cleanup if we come from a TLS upgrade, since then we don't
 * clone the upload.  This is necessary before re-entering upload_request().
 */
static void
upload_request_cleanup(struct upload *u)
{
	u->hevcnt = 0;
}

/**
 * Finish the OPTIONS request (possibly after switching the socket TLS).
 */
static void
upload_options_finish(struct upload *u)
{
	bool ok;

	upload_check(u);

	upload_http_extra_line_add(u, "Content-Length: 0\r\n");

	ok = upload_send_http_status(u, u->keep_alive, 200, HTTP_ATOMIC_SEND, "OK");

	if (!ok) {
		upload_remove(u, N_("Cannot send whole HTTP status after OPTIONS"));
		return;
	}

	if (u->keep_alive) {
		HFREE_NULL(u->request);
		upload_request_cleanup(u);
		upload_wait_new_request(u);
	} else {
		upload_remove(u, no_reason);
	}
}

/**
 * Check whether upload wants to be upgraded to TLS.
 *
 * @return TRUE if remote host wants a TLS upgrade, and we can fullfil it.
 */
static bool
upload_wants_tls_upgrade(const struct upload *u, const header_t *header)
{
	const char *field;

	if (!tls_enabled() || socket_uses_tls(u->socket))
		return FALSE;

	field = header_get(header, "Upgrade");
	if (NULL == field || !strtok_case_has(field, ",", "TLS/1.0"))
		return FALSE;

	field = header_get(header, "Connection");
	if (NULL == field || 0 != ascii_strcasecmp(field, "upgrade"))
		return FALSE;

	return TRUE;
}

/**
 * Handle an OPTIONS request.
 */
static void
upload_options_handle(struct upload *u, const header_t *header, const char *uri)
{
	upload_check(u);

	if ((u->http_major == 1 && u->http_minor >= 1) || u->http_major > 1) {
		/*
		 * An "OPTIONS * HTTP/1.1" request is for requesting a mandatory
		 * upgrade to TLS -- see RFC-2817.
		 */

		if (0 == strcmp(uri, "*")) {
			if (!upload_wants_tls_upgrade(u, header))
				goto done;

			/*
			 * We have all the necessary headers to update the socket to TLS!
			 *
			 * After the upgrade,we'll call upload_options_finish() to respond
			 * to the original OPTIONS request, on top of TLS this time.
			 */

			g_assert(header == io_header(u->io_opaque));

			upload_tls_upgrade(u, (notify_fn_t) upload_options_finish);
			return;
		} else {
			goto ok;
		}
	} else {
		goto ok;
	}

ok:
	upload_http_extra_line_add(u, ALLOW);
	/* FALL THROUGH */

done:
	upload_options_finish(u);
}

struct upload_sink_ctx {
	struct upload *u;
	const header_t *header;
	const char *uri;
	size_t amount;
};

/**
 * Input callback to sink data.
 */
static void
upload_sink_data(void *data, int unused_source, inputevt_cond_t cond)
{
	struct upload_sink_ctx *ctx = data;
	struct upload *u = ctx->u;
	char buf[512];
	ssize_t r;

	(void) unused_source;
	g_assert(size_is_positive(ctx->amount));
	upload_check(u);

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_eof(u->socket);
		upload_remove(u, _("EOF while sinking"));
		return;
	}

	while (ctx->amount != 0) {
		size_t n = MIN(ctx->amount, N_ITEMS(buf));
		r = bws_read(BSCHED_BWS_IN, &u->socket->wio, buf, n);
		if (-1 == r) {
			upload_remove(u, _("Read error while sinking: %m"));
			return;
		}
		ctx->amount -= r;
		if (UNSIGNED(r) < n)
			break;
	}

	if (0 == ctx->amount) {
		/*
		 * Done with input sink, now process the request.
		 */

		socket_evt_clear(u->socket);
		upload_options_handle(u, ctx->header, ctx->uri);
		WFREE(ctx);
	}
}

/**
 * Got an OPTIONS request.
 */
static void
upload_options_request(struct upload *u,
	const header_t *header, const char *uri)
{
	uint64 len = get_content_length(header);

	if (len > UPLOAD_MAX_SINK) {
		upload_send_error(u, 400, N_("Content Too Large"));
		return;
	}

	/*
	 * Sink (ignore) any content in the OPTIONS request.
	 */

	if (len != 0) {
		struct upload_sink_ctx *ctx;

		WALLOC0(ctx);
		ctx->u = u;
		ctx->header = header;
		ctx->uri = uri;
		ctx->amount = len;
		socket_evt_set(u->socket, INPUT_EVENT_RX, upload_sink_data, ctx);
		return;
	}

	upload_options_handle(u, header, uri);
}

/**
 * Re-invoke upload_request() after a TLS connection upgrade.
 */
static void
upload_request_restart(void *arg)
{
	struct upload *u = arg;

	upload_check(u);
	socket_check(u->socket);
	g_assert(NULL == u->socket->getline);

	upload_request_cleanup(u);
	upload_request(u, io_header(u->io_opaque));
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
	bool first_request, options_req = FALSE;

	upload_check(u);

	/*
	 * The upload context is recycled for keep-alive connections but
	 * the following items are always released/cleared in advance.
	 */

	g_assert(NULL == u->request || NULL == u->socket->getline);
	g_assert(0 == u->hevcnt);
	g_assert(NULL == u->sf);
	g_assert(NULL == u->name);
	g_assert(NULL == u->thex);
	g_assert(!u->browse_host);
	g_assert(0 == u->socket->gdk_tag);
	g_assert(NULL == u->bio);

	u->was_actively_queued = FALSE;

	/*
	 * Have to save this early -- we can come back here during TLS upgrades.
	 */

	if (NULL == u->request) {
		u->request = h_strdup(getline_str(u->socket->getline));
		getline_free_null(&u->socket->getline);
	}

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

		if (d > IO_RTT_STALL)
			upload_large_followup_rtt(u, d);

		/*
		 * If the reply comes quickly, we are likely sending at the right
		 * rate (or the remote side is using HTTP request pipelining), so
		 * try to raise our b/w cap if possible.
		 *
		 * If we have to wait for the follow-up request, we're probably
		 * sending too much at a time and it takes time for TCP to flush
		 * its buffers.  Therefore, attempt to reduce our b/w cap.
		 */

		if (d > IO_RTT_CAP) {
			upload_update_bw_cap(u, UL_BW_CAP_DOWN);
		} else {
			upload_update_bw_cap(u, UL_BW_CAP_UP);
		}

		entropy_harvest_single(VARLEN(d));
	} else {
		/* Ensure no cap on first request */
		upload_update_bw_cap(u, UL_BW_CAP_CLEAR);
	}

	/*
	 * Entropy harvesting...
	 */

	{
		host_addr_t addr = u->socket->addr;
		uint16 port = u->socket->port;

		entropy_harvest_small(VARLEN(addr), VARLEN(port), NULL);
	}

	/*
	 * Technically, we have not started sending anything yet, but this
	 * also serves as a marker in case we need to call upload_remove().
	 * It will not send an HTTP reply by itself.
	 */

	u->start_date = now;
	u->last_update = now;		/* Done reading headers */

	u->from_browser = upload_likely_from_browser(header);
	u->downloaded = extract_downloaded(u, header);
	u->status = GTA_UL_SENDING;

	if (GNET_PROPERTY(upload_trace) & SOCK_TRACE_IN) {
		g_debug("----%s HTTP Request%s #%u from %s%s%s:\n%s",
			u->is_followup ? "Follow-up" : "Incoming",
			u->last_was_error ? " (after error)" : "",
			u->reqnum,
			host_addr_to_string(u->addr),
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

	if (ctl_limit(u->addr, CTL_D_INCOMING)) {
		u->flags |= UPLOAD_F_LIMITED;
		if (ctl_limit(u->addr, CTL_D_NORMAL)) {
			u->flags |= UPLOAD_F_NORMAL_LIMIT;
		} else if (ctl_limit(u->addr, CTL_D_STEALTH)) {
			u->flags |= UPLOAD_F_STEALTH_LIMIT;
		}
	}

	/* @todo TODO: Parse the HTTP request properly:
	 *		- Check for illegal characters (like NUL)
	 */

	upload_request_handle_user_agent(u, header);

	/*
	 * Make sure there is the HTTP/x.x tag at the end of the request,
	 * thereby ruling out the HTTP/0.9 requests.
	 */

	if (!upload_http_version(u, u->request, vstrlen(u->request))) {
		upload_error_remove(u, 500, N_("Unknown/Missing Protocol Tag"));
		return;
	}

	upload_handle_connection_header(u, header);

	/*
	 * Spot requests from G2 servents.
	 *
	 * The X-Features may not be present in every follow-up request, but
	 * that is OK since we merge the flag in and therefore it will be sticky.
	 */

	if (header_get_feature("g2", header, NULL, NULL))
		u->flags |= UPLOAD_F_G2;

	/*
	 * Check vendor-specific banning.
	 */

	if (u->user_agent) {
		const char *msg = ban_vendor(u->user_agent);

		if (msg != NULL) {
			ban_record(BAN_CAT_HTTP, u->addr, msg);
			upload_error_remove(u, 403, "%s", msg);
			return;
		}
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
		} else if (NULL != (endptr = is_strprefix(u->request, "OPTIONS"))) {
			options_req = TRUE;
		}

		if (endptr && is_ascii_blank(endptr[0])) {
			uri = skip_ascii_blanks(endptr);
		} else {
			upload_send_error(u, 501, N_("Not Implemented"));
			return;
		}
	}

	/*
	 * The OPTIONS request must be dealt with specially.
	 */

	if (options_req) {
		/* Get rid of the trailing HTTP/<whatever> at the end of the request */
		remove_trailing_http_tag(uri);

		upload_options_request(u, header, uri);
		return;
	}

	/*
	 * Check whether they want to upgrade the connection to TLS.
	 */

	if (upload_wants_tls_upgrade(u, header)) {
		/*
		 * We have all the necessary headers to update the socket to TLS!
		 *
		 * After the upgrade,we'll call upload_request() again to respond
		 * to the original request, on top of TLS this time: this is why
		 * we need to keep the header structure around (what the client
		 * sent us) to be able to resume processing after the upgrade.
		 */

		g_assert(header == io_header(u->io_opaque));	/* Needed to resume */

		upload_tls_upgrade(u, upload_request_restart);
		return;
	}

	/*
	 * Get rid of the trailing HTTP/<whatever> at the end of the request
	 *
	 * This must come after the TLS upgrade checks, because when we re-enter
	 * the routine, we still need to find the protocol tags at the end of
	 * the request line.
	 */

	remove_trailing_http_tag(uri);

	/* Extract the host and path from an absolute URI */

	uri = upload_parse_uri(header, uri, ARYLEN(host));
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
	 * We don't expect any content with GET or HEAD!
	 */

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

	/*
	 * Gnutella-specific HTTP header processing.
	 */

	upload_determine_peer_address(u, header);
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

	search = vstrchr(uri, '?');
	if (search) {
		*search++ = '\0';
		/*
		 * The search cannot be URL-decoded yet because that could
		 * destroy the '&' boundaries.
		 */
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

	entropy_harvest_time();
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
				"disabling sendfile() for this session", english_strerror(e));
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
	u->total_sent += written;
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

	g_assert(u->special != NULL);
	g_assert(u->special->close != NULL);

	/*
	 * Must get rid of the special reading hooks to reset the TX stack
	 * for the next request.
	 */

	(*u->special->close)(u->special, TRUE);
	u->special = NULL;

	if (GNET_PROPERTY(upload_debug)) {
		g_debug("%s from %s (%s) done: %s bytes, %s sent",
			u->name,
			host_addr_to_string(u->addr),
			upload_vendor_str(u),
			uint64_to_string(u->sent),	/* Sent to TX stack = final RX size */
			uint64_to_string2(u->file_size));/* True amount sent on the wire */
	}

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
	u->total_sent += written;
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

	PSLIST_FOREACH(list_uploads, sl) {
		struct upload *u = cast_to_upload(sl->data);

		if (host_addr_equiv(u->addr, addr) && !UPLOAD_IS_COMPLETE(u))
			to_remove = pslist_prepend(to_remove, u);
	}

	PSLIST_FOREACH(to_remove, sl) {
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
 * Computes the maximum amount of uploads per IP.
 *
 * This is dynamic in order to forcefully limit uploads to 1 when the IP
 * address is known to be causing stalls, recently.
 */
uint
upload_max_by_addr(host_addr_t addr)
{
	time_delta_t d = aging_age(stalling_uploads, &addr);

	if (d != (time_delta_t) -1 && d < STALL_CLEAR / 3)
		return 1;

	return GNET_PROPERTY(max_uploads_ip);
}

/**
 * Initialize uploads.
 */
void G_COLD
upload_init(void)
{
	pat_http        = PATTERN_COMPILE_CONST(" HTTP/");
	pat_applewebkit = PATTERN_COMPILE_CONST("AppleWebKit");

	mesh_info = aging_make(MESH_INFO_TIMEOUT,
						upload_tag_key_hash, upload_tag_key_eq,
						upload_tag_key_free2);
	stalling_uploads = aging_make(STALL_CLEAR,
						host_addr_hash_func, host_addr_eq_func,
						wfree_host_addr);
	early_stalling_uploads = aging_make(STALL_CLEAR,
						host_addr_hash_func, host_addr_eq_func,
						wfree_host_addr);
	upload_handle_map = idtable_new(32);
	browsing_reqs = aging_make(BROWSING_THRESH,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);
	push_requests = aging_make(PUSH_REPLY_FREQ,
		host_addr_hash_func, host_addr_eq_func, wfree_host_addr);
	push_conn_failed = aging_make(PUSH_BAN_FREQ,
		gnet_host_hash, gnet_host_equal, gnet_host_free_atom2);

	retry_after = ripening_make(FALSE,
		upload_tag_key_hash, upload_tag_key_eq, upload_tag_key_free2_silent);

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
void G_COLD
upload_close(void)
{
	while (list_uploads) {
		struct upload *u = cast_to_upload(list_uploads->data);

		upload_aborted_file_stats(u);
		upload_free_resources(u);
	}

    idtable_destroy(upload_handle_map);
    upload_handle_map = NULL;

	aging_destroy(&mesh_info);
	aging_destroy(&stalling_uploads);
	aging_destroy(&early_stalling_uploads);
	aging_destroy(&browsing_reqs);
	aging_destroy(&push_requests);
	aging_destroy(&push_conn_failed);
	ripening_destroy(&retry_after);
	wd_free_null(&early_stall_wd);
	wd_free_null(&stall_wd);
	pattern_free_null(&pat_http);
	pattern_free_null(&pat_applewebkit);
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
	info->g2            = booleanize(u->flags & UPLOAD_F_G2);
	info->tls_upgraded  = u->tls_upgraded;
	info->partial       = u->file_info != NULL;
	info->available     = info->partial ? u->file_info->done : u->file_size;
	info->gnet_addr     = u->gnet_addr;
	info->gnet_port     = u->gnet_port;
	info->shrunk_chunk  = u->shrunk_chunk;

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
	si->bw_cap      = u->bw_cap;

	si->parq_queue_no = parq_upload_lookup_queue_no(u);
	si->parq_position = parq_upload_lookup_position(u);
	si->parq_size     = parq_upload_lookup_size(u);
	si->parq_lifetime = MAX(0, delta_time(parq_upload_lifetime(u), now));
	si->parq_retry    = MAX(0, delta_time(parq_upload_retry(u), now));
	si->parq_quick    = parq_upload_lookup_quick(u);
	si->parq_frozen   = parq_upload_lookup_frozen(u);

    if (u->bio) {
        si->bps = bio_bps(u->bio);
		si->avg_bps = bio_avg_bps(u->bio);
		si->bw_penalty = bio_penalty(u->bio);
	} else
		si->bw_penalty = 0;

	if (u->last_update != u->start_date) {
		si->avg_bps = (u->pos - u->skip) /
			delta_time(u->last_update, u->start_date);
	}

	if (0 == si->avg_bps)
        si->avg_bps++;
}

pslist_t *
upload_get_info_list(void)
{
	pslist_t *sl, *sl_info = NULL;

	PSLIST_FOREACH(list_uploads, sl) {
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

		PSLIST_FOREACH(*sl_ptr, sl) {
			upload_free_info(sl->data);
		}
		pslist_free(*sl_ptr);
		*sl_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
