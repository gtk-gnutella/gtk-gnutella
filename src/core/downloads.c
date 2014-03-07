/*
 * Copyright (c) 2001-2011, Raphael Manfredi
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
 * Handle downloads.
 *
 * @author Raphael Manfredi
 * @date 2001-2011
 */

#include "common.h"

#include "gtk-gnutella.h"

#include "downloads.h"

#include "ban.h"
#include "bh_download.h"
#include "bh_upload.h"
#include "bsched.h"
#include "clock.h"
#include "ctl.h"
#include "dmesh.h"
#include "features.h"
#include "gdht.h"
#include "geo_ip.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hcache.h"		/* For HOST_NET_* flags */
#include "hostiles.h"
#include "hosts.h"
#include "http.h"
#include "huge.h"
#include "ignore.h"
#include "inet.h"		/* For INET_IP_V6READY */
#include "ioheader.h"
#include "ipp_cache.h"
#include "move.h"
#include "nodes.h"
#include "parq.h"
#include "pproxy.h"
#include "routing.h"
#include "rx_inflate.h"
#include "search.h"
#include "settings.h"
#include "sockets.h"
#include "thex_download.h"
#include "token.h"
#include "udp.h"
#include "uploads.h"
#include "verify_sha1.h"
#include "verify_tth.h"
#include "version.h"
#include "vmsg.h"

#include "g2/build.h"
#include "g2/node.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"
#include "if/core/main.h"
#include "if/dht/dht.h"

#include "lib/adns.h"
#include "lib/array.h"
#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/concat.h"
#include "lib/crc.h"
#include "lib/dbus_util.h"
#include "lib/dualhash.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/file_object.h"
#include "lib/filename.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/hikset.h"
#include "lib/htable.h"
#include "lib/http_range.h"
#include "lib/idtable.h"
#include "lib/iso3166.h"
#include "lib/magnet.h"
#include "lib/palloc.h"
#include "lib/parse.h"
#include "lib/plist.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/sequence.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/tigertree.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#if defined(S_IROTH)
#define DOWNLOAD_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) /* 0644 */
#else
#define DOWNLOAD_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP) /* 0640 */
#endif

#define DOWNLOAD_MIN_OVERLAP	64		/**< Minimum overlap for safety */
#define DOWNLOAD_SHORT_DELAY	2		/**< Shortest retry delay */
#define DOWNLOAD_MAX_SINK		16384	/**< Max amount of data to sink */
#define DOWNLOAD_MAX_IGN_DATA	2097152	/**< Max amount of data to ignore */
#define DOWNLOAD_MAX_IGN_TIME	300		/**< Max amount of secs we can ignore */
#define DOWNLOAD_MAX_IGN_REQS	3		/**< How many mismatches per source */
#define DOWNLOAD_SERVER_HOLD	15		/**< Space requests to same server */
#define DOWNLOAD_DNS_LOOKUP		1800	/**< Period of server DNS lookups */
#define DOWNLOAD_STALLED		60		/**< Consider stalled after 60 secs */
#define DOWNLOAD_PING_DELAY		300		/**< Minimum delay for 2 HEAD pings */
#define DOWNLOAD_MAX_HEADER_EOF	3		/**< Max # of EOF in headers we allow */
#define DOWNLOAD_DATA_TIMEOUT	5		/**< Max # of data timeouts we allow */
#define DOWNLOAD_ALT_LOC_SIZE	1024	/**< Max size for alt locs */
#define DOWNLOAD_BAN_DELAY		360		/**< Retry time when suspecting ban */
#define DOWNLOAD_MAX_PROXIES	8		/**< Keep that many recent proxies */
#define DOWNLOAD_MAX_UDP_PUSH	4		/**< Contact at most 4 hosts */
#define DOWNLOAD_CONNECT_DELAY	12		/**< Seconds between connections */
#define DOWNLOAD_PIPELINE_MSECS	10000	/**< Less than 10 secs away */
#define DOWNLOAD_FS_SPACE		16384	/**< Min filesystem free space */

#define IO_AVG_RATE		5		/**< Compute global recv rate every 5 secs */

static hash_list_t *sl_downloads;	/**< All downloads (queued + unqueued) */
static hash_list_t *sl_unqueued;	/**< Unqueued downloads only */
static pslist_t *sl_removed;		/**< Removed downloads only */
static pslist_t *sl_removed_servers;/**< Removed servers only */

static const char DL_OK_EXT[]	= ".OK";	/**< Extension to mark OK files */
static const char DL_BAD_EXT[]	= ".BAD";	/**< "Bad" files (SHA1 mismatch) */
static const char DL_UNKN_EXT[] = ".UNKN";	/**< For unchecked files */
static const char no_reason[]	= "<no reason>"; /**< Don't translate this */
static const char dev_null[]	= "/dev/null";
static const char APP_G2[]       = "application/x-gnutella2";
static const char APP_GNUTELLA[] = "application/x-gnutella-packets";

static void download_add_to_list(struct download *d, enum dl_list idx);
static bool download_send_push_request(
	struct download *d, bool, bool);
static bool download_read(struct download *d, pmsg_t *mb);
static bool download_ignore_data(struct download *d, pmsg_t *mb);
static void download_request(struct download *d, header_t *header, bool ok);
static void download_push_ready(struct download *d, getline_t *empty);
static void download_push(struct download *d, bool on_timeout);
static void download_resume_bg_tasks(void);
static void download_incomplete_header(struct download *d);
static bool has_blank_guid(const struct download *d);
static void download_verify_sha1(struct download *d);
static void download_verify_tigertree(struct download *d);
static bool download_get_server_name(struct download *d, header_t *header);
static bool use_push_proxy(struct download *d);
static void download_unavailable(struct download *d,
		download_status_t new_status,
		const char * reason, ...) G_GNUC_PRINTF(3, 4);
static void download_queue_delay(struct download *d, uint32 delay,
	const char *fmt, ...) G_GNUC_PRINTF(3, 4);
static void download_queue_hold(struct download *d, uint32 hold,
	const char *fmt, ...) G_GNUC_PRINTF(3, 4);
static void download_force_stop(struct download *d, const char * reason, ...);
static void download_reparent(struct download *d, struct dl_server *new_server);
static void download_silent_flush(struct download *d);
static void change_server_addr(struct dl_server *server,
	const host_addr_t new_addr, const uint16 new_port);
static struct download *download_pick_another(const struct download *d);
static void download_got_push_route(const guid_t *guid);

static bool download_dirty;
static bool download_shutdown;
static bool queue_frozen_on_write_error;

static void download_store(void);
static void download_retrieve(void);

bool
download_is_alive(const struct download *d)
{
	download_check(d);

	switch (d->status) {
	case GTA_DL_INVALID:
		/* This is the initial status... */
		return TRUE;
	case GTA_DL_ACTIVE_QUEUED:
	case GTA_DL_CONNECTING:
	case GTA_DL_CONNECTED:
	case GTA_DL_HEADERS:
	case GTA_DL_IGNORING:
	case GTA_DL_PASSIVE_QUEUED:
	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
	case GTA_DL_QUEUED:
	case GTA_DL_RECEIVING:
	case GTA_DL_REQ_SENDING:
	case GTA_DL_REQ_SENT:
	case GTA_DL_SINKING:
	case GTA_DL_TIMEOUT_WAIT:
		return TRUE;
	case GTA_DL_ABORTED:
	case GTA_DL_COMPLETED:
	case GTA_DL_DONE:
	case GTA_DL_ERROR:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_VERIFIED:
	case GTA_DL_VERIFYING:
	case GTA_DL_VERIFY_WAIT:
	case GTA_DL_REMOVED:
		return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

/**
 * Did we successfully connect to the server recently?
 */
bool
download_is_active(const struct download *d)
{
	download_check(d);

	switch (d->status) {
	case GTA_DL_CONNECTED:
	case GTA_DL_ACTIVE_QUEUED:
	case GTA_DL_HEADERS:
	case GTA_DL_IGNORING:
	case GTA_DL_PASSIVE_QUEUED:
	case GTA_DL_QUEUED:
	case GTA_DL_RECEIVING:
	case GTA_DL_REQ_SENDING:
	case GTA_DL_REQ_SENT:
	case GTA_DL_SINKING:
		return TRUE;
	case GTA_DL_CONNECTING:
	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
	case GTA_DL_TIMEOUT_WAIT:
	case GTA_DL_ABORTED:
	case GTA_DL_COMPLETED:
	case GTA_DL_DONE:
	case GTA_DL_ERROR:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_VERIFIED:
	case GTA_DL_VERIFYING:
	case GTA_DL_VERIFY_WAIT:
	case GTA_DL_REMOVED:
	case GTA_DL_INVALID:	/* This is the initial status... */
		return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

/**
 * Is download in a "running" list?
 */
static bool
download_is_running(const struct download *d)
{
	download_check(d);
	dl_server_valid(d->server);

	return DL_LIST_RUNNING == d->list_idx;
}

/**
 * Return download status string.
 */
const char *
download_status_to_string(const download_t *d)
{
	download_check(d);

	switch (d->status) {
	case GTA_DL_INVALID:			return "INVALID";
	case GTA_DL_ACTIVE_QUEUED:		return "ACTIVE_QUEUED";
	case GTA_DL_CONNECTING:			return "CONNECTING";
	case GTA_DL_CONNECTED:			return "CONNECTED";
	case GTA_DL_HEADERS:			return "HEADERS";
	case GTA_DL_IGNORING:			return "IGNORING";
	case GTA_DL_PASSIVE_QUEUED:		return "PASSIVE_QUEUED";
	case GTA_DL_PUSH_SENT:			return "PUSH_SENT";
	case GTA_DL_FALLBACK:			return "FALLBACK";
	case GTA_DL_QUEUED:				return "QUEUED";
	case GTA_DL_RECEIVING:			return "RECEIVING";
	case GTA_DL_REQ_SENDING:		return "REQ_SENDING";
	case GTA_DL_REQ_SENT:			return "REQ_SENT";
	case GTA_DL_SINKING:			return "SINKING";
	case GTA_DL_TIMEOUT_WAIT:		return "TIMEOUT_WAIT";
	case GTA_DL_ABORTED:			return "ABORTED";
	case GTA_DL_COMPLETED:			return "COMPLETED";
	case GTA_DL_DONE:				return "DONE";
	case GTA_DL_ERROR:				return "ERROR";
	case GTA_DL_MOVE_WAIT:			return "MOVE_WAIT";
	case GTA_DL_MOVING:				return "MOVING";
	case GTA_DL_VERIFIED:			return "VERIFIED";
	case GTA_DL_VERIFYING:			return "VERIFYING";
	case GTA_DL_VERIFY_WAIT:		return "VERIFY_WAIT";
	case GTA_DL_REMOVED:			return "REMOVED";
	}
	return "UNKNOWN";
}

static void
download_set_status(struct download *d, download_status_t status)
{
	bool was_alive, is_alive;

	download_check(d);

	if (status == d->status)
		return;

	was_alive = download_is_alive(d);
	d->status = status;

	g_return_if_fail(d->file_info);

	is_alive = download_is_alive(d);
	if (is_alive != was_alive) {
		fileinfo_t *fi = d->file_info;

		g_assert(fi->refcount >= fi->lifecount);
		fi->lifecount += is_alive ? 1 : -1;
		g_assert(fi->refcount >= fi->lifecount);
	}
	fi_src_status_changed(d);
}

const char *
download_pathname(const struct download *d)
{
	download_check(d);
	file_info_check(d->file_info);
	return d->file_info->pathname;
}

const char *
download_basename(const struct download *d)
{
	return filepath_basename(download_pathname(d));
}

const char *
server_host_info(const struct dl_server *server)
{
	static char info[256 + MAX_HOSTLEN];
	char host[128];
	char name[MAX_HOSTLEN + 8];

	g_assert(dl_server_valid(server));

	host_addr_port_to_string_buf(server->key->addr, server->key->port,
		host, sizeof host);

	name[0] = '\0';
	if (server->hostname) {
		concat_strings(name, sizeof name,
			" (", server->hostname, ") ",
			NULL);
	}

	concat_strings(info, sizeof info,
		"<",
		(server->attrs & DLS_A_G2_ONLY) ? "G2 " : "",
		host, name, " \'", server->vendor ? server->vendor : "", "\'>",
		NULL);

	return info;
}

/*
 * Download structures.
 *
 * This `dl_key' is inserted in the `dl_by_host' hash table were we find a
 * `dl_server' structure describing all the downloads for the given host.
 *
 * All `dl_server' structures are also inserted in the `dl_by_time' struct,
 * where hosts are sorted based on their retry time.
 */

static hikset_t *dl_by_host;

#define DHASH_SIZE	(1UL << 10)	/**< Hash list size, must be a power of 2 */
#define DHASH_MASK 	(DHASH_SIZE - 1)
#define DL_HASH(x)	((x) & DHASH_MASK)

static struct {
	plist_t *servers[DHASH_SIZE];	/**< Lists of servers, by retry time */
	int change[DHASH_SIZE];			/**< Counts changes to the list */
} dl_by_time;

/**
 * To handle download meshes, where we only know the IP/port of the host and
 * not its GUID, we need to be able to locate the server.  We know that the
 * IP will not be a private one.
 *
 * Therefore, for each (GUID, IP, port) tuple, where IP is NOT private, we
 * store the (IP, port) => server association as well.	There should be only
 * one such entry, ever.  If there is more, it means the server changed its
 * GUID, which is possible, in which case we simply supersede the old entry.
 */
static htable_t *dl_by_addr;

/**
 * To be able to handle push-proxy lookups from the DHT, we remember servers
 * by GUID as well.  In case there is a conflict (two hosts bearing the same
 * GUID), we keep only the first server we see with that GUID.
 */
static htable_t *dl_by_guid;

/**
 * Each source is given a random unique GUID so that we can easily associate
 * a download with its THEX download.  The dl_by_id hashtable maps a GUID
 * to its corresponding download.
 */
static hikset_t *dl_by_id;

/**
 * Associates a plain download with its corresponding THEX download in a
 * bijective way (key = plain download ID, value = THEX download ID).
 */
static dualhash_t *dl_thex;

/**
 * Keys in the `dl_by_addr' table.
 */
struct dl_addr {
	host_addr_t addr;		/**< IP address of server */
	uint16 port;			/**< Port of server */
};

static uint dl_establishing = 0;		/**< Establishing downloads */
static uint dl_active = 0;				/**< Active downloads */

/**
 * Keep track of downloads per SHA1.
 *
 * For each SHA1 we point to a hash_list_t containing all the known sources.
 * for that file.
 *
 * This is used to determine whether a SHA1 is rare on the network (has only
 * partial sources).
 */
static htable_t *dhl_by_sha1;

static inline uint
count_running_downloads(void)
{
	return dl_establishing + dl_active;
}

static inline uint
server_list_length(const struct dl_server *server, enum dl_list idx)
{
	g_assert(dl_server_valid(server));
	g_assert((uint) idx < DL_LIST_SZ);		
	return server->list[idx] ? list_length(server->list[idx]) : 0;
}

static inline uint
count_running_on_server(const struct dl_server *server)
{
	return server_list_length(server, DL_LIST_RUNNING);
}

static void
download_repair(struct download *d, const char *reason)
{
	download_check(d);

	/*
	 * Maybe we should try to initiate a TLS connection if we have not
	 * done so already?
	 */

	if (
		tls_enabled() &&
		!socket_with_tls(d->socket) && !(d->flags & DL_F_TRIED_TLS)
	) {
		d->flags |= DL_F_TRIED_TLS | DL_F_TRY_TLS;

		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(tls_debug))
			g_debug("will try to reach server %s with TLS",
					download_host_info(d));

		download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
				_("Stopped, will retry with TLS (%s)"), reason);

	} else if (d->retries < GNET_PROPERTY(download_max_retries)) {
		d->retries++;

		if (0 == d->served_reqs) {
			d->server->attrs |= DLS_A_FOOBAR;
		}
		download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
				_("Stopped (%s)"), reason);
	} else {
		download_unavailable(d, GTA_DL_ERROR,
			_("Too many attempts (%u times)"), d->retries);
	}
}

#define MAGIC_TIME	1		/**< For recreation upon startup */

/* ----------------------------------------- */

/***
 *** HTTP pipelining support.
 ***/

/**
 * Allocate a new pipelined request descriptor.
 *
 * @return allocated pipeline structure.
 */
static struct dl_pipeline *
download_pipeline_alloc(void)
{
	struct dl_pipeline *dp;

	WALLOC0(dp);
	dp->magic = DL_PIPELINE_MAGIC;
	dp->status = GTA_DL_PIPE_SELECTED;

	return dp;
}

/**
 * Free pipelined request descriptor and nullify holding pointer.
 */
static void
download_pipeline_free_null(struct dl_pipeline **dp_ptr)
{
	struct dl_pipeline *dp = *dp_ptr;

	if (dp != NULL) {
		dl_pipeline_check(dp);

		if (dp->req != NULL) {
			http_buffer_free(dp->req);
			dp->req = NULL;
		}
		pmsg_free_null(&dp->extra);
		dp->magic = 0;
		WFREE(dp);
		*dp_ptr = NULL;
	}
}

/**
 * Can we issue a pipelined request for a given download?
 */
static bool
download_pipeline_can_initiate(const struct download *d)
{
	fileinfo_t *fi;
	unsigned avg_bps, s;
	unsigned threshold;
	filesize_t downloaded, remain;

	download_check(d);
	g_assert(DOWNLOAD_IS_ACTIVE(d));
	g_assert(d->bio != NULL);

	fi = d->file_info;
	file_info_check(fi);

	if (download_pipelining(d))
		return FALSE;				/* Only one pipelined request at a time */

	if (!fi->file_size_known)
		return FALSE;				/* Must know upper boundary */

	if (!d->keep_alive)
		return FALSE;				/* Connection must be kept alive */

	if (download_is_stalled(d))
		return FALSE;				/* Stalling download */

	if (d->flags & (DL_F_MUST_IGNORE | DL_F_NO_PIPELINE | DL_F_PREFIX_HEAD))
		return FALSE;				/* No need to pipeline then */

	if ((DL_F_THEX | DL_F_BROWSE) & d->flags)
		return FALSE;				/* THEX and browsing use no chunking */

	if (FILE_INFO_COMPLETE(fi))
		return FALSE;

	if ((DLS_A_FOOBAR & d->server->attrs) && 0 == d->served_reqs)
		return FALSE;

	if (d->server->attrs & DLS_A_NO_PIPELINE)
		return FALSE;				/* Server seems to choke on pipelining */

	/*
	 * If we have a pending THEX download, do not use pipelining so that
	 * we can switch to the THEX download once the current chunk is done
	 * and then resume to the regular file downloading afterwards.
	 */

	if (dualhash_contains_key(dl_thex, d->id)) {
		struct guid *id = dualhash_lookup_key(dl_thex, d->id);
		struct download *dt = hikset_lookup(dl_by_id, id);

		download_check(dt);
		g_assert(dt->flags & DL_F_THEX);

		/*
		 * If they configured more than one download per server, then it's
		 * possible for the THEX download to be running already.  In which
		 * case there's no need to preserve the ability to switch.
		 */

		if (!DOWNLOAD_IS_ACTIVE(dt))
			return FALSE;			/* Not pipelining will allow switching */
	}

	/*
	 * We must be close to the end of the current request to not commit the
	 * next chunk too early.
	 */

	if (d->pos + download_buffered(d) > d->chunk.start) {
		downloaded = d->pos - d->chunk.start + download_buffered(d);
		remain = d->chunk.size - downloaded;
	} else {
		remain = d->chunk.size + d->chunk.overlap;
	}

	avg_bps = download_speed_avg(d);
	s = remain / (avg_bps ? avg_bps : 1);

	dl_server_valid(d->server);

	threshold = MAX(DOWNLOAD_PIPELINE_MSECS, GNET_PROPERTY(dl_http_latency));
	threshold = MAX(threshold, d->server->latency);

	return uint_saturate_mult(s, 1000) <= threshold;
}

/**
 * Take ownership of pipelined chunk after cloning.
 */
static void
download_pipeline_update_chunk(const struct download *d)
{
	struct dl_pipeline *dp;

	download_check(d);
	dp = d->pipeline;
	dl_pipeline_check(dp);
	g_assert(dp->status != GTA_DL_PIPE_SELECTED);

	/*
	 * With aggressive swarming, the pipelined chunk could be completed,
	 * in which case we shall ignore data later on when detecting we're
	 * bumping into a DONE chunk.
	 */

	file_info_new_chunk_owner(d, dp->chunk.start, dp->chunk.end);
}

/**
 * Copy message block data to the empty socket buffer.
 */
static void
download_pipeline_socket_feed(struct download *d, pmsg_t *mb)
{
	struct gnutella_socket *s;
	int r;

	download_check(d);
	pmsg_check_consistency(mb);

	s = d->socket;
	g_assert(s != NULL);
	g_assert(0 == s->pos);

	/* Assert we're dealing with a download having a simple RX stack */
	g_assert(d->rx != NULL);
	g_assert(rx_bottom(d->rx) == d->rx);	/* Only the RX link layer */

	r = pmsg_read(mb, s->buf, s->buf_size);
	g_assert(0 == pmsg_size(mb));	/* Did not truncate */
	pmsg_free(mb);
	s->pos = r;

	if (GNET_PROPERTY(download_debug) > 5) {
		g_debug("propagated %d pipelined bytes from %s for \"%s\"",
			r, download_host_info(d), download_pathname(d));
		if (GNET_PROPERTY(download_debug) > 8)
			dump_hex(stderr, "Propagated bytes", s->buf, r);
	}
}

/**
 * Move data pertaining to the server response for the pipelined request
 * back into the socket buffer where it belongs.
 *
 * Data will then be consumed by io_header_parse() to get the HTTP header,
 * and extra data (the reply payload) will be fed to the RX stack as usual.
 */
static void
download_pipeline_read(struct download *d)
{
	struct dl_pipeline *dp;
	struct gnutella_socket *s;

	download_check(d);
	dp = d->pipeline;
	s = d->socket;
	dl_pipeline_check(dp);
	g_assert(s != NULL);
	g_assert(0 == s->pos);

	if (dp->extra != NULL) {
		g_assert(GTA_DL_PIPE_SENT == dp->status);
		download_pipeline_socket_feed(d, dp->extra);
		dp->extra = NULL;
	}
}

/* ----------------------------------------- */

/**
 * Add download by SHA1.
 */
static void
download_by_sha1_add(const struct download *d)
{
	hash_list_t *hl;

	download_check(d);
	g_assert(d->file_info != NULL);
	g_assert(d->file_info->sha1 != NULL);

	hl = htable_lookup(dhl_by_sha1, d->file_info->sha1);
	if (NULL == hl) {
		hl = hash_list_new(pointer_hash, NULL);
		htable_insert(dhl_by_sha1, d->file_info->sha1, hl);
	}

	g_soft_assert(!hash_list_contains(hl, d));

	hash_list_append(hl, d);
}

/**
 * Remove download by SHA1.
 */
static void
download_by_sha1_remove(const struct download *d)
{
	hash_list_t *hl;

	download_check(d);
	g_assert(d->file_info != NULL);
	g_assert(d->file_info->sha1 != NULL);

	hl = htable_lookup(dhl_by_sha1, d->file_info->sha1);
	g_assert(hl != NULL);

	g_soft_assert(hash_list_contains(hl, d));

	hash_list_remove(hl, d);
	if (0 == hash_list_length(hl)) {
		htable_remove(dhl_by_sha1, d->file_info->sha1);
		hash_list_free(&hl);
	}
}

/**
 * Check whether all the active sources for a SHA1 are partial.
 */
bool
download_sha1_is_rare(const struct sha1 *sha1)
{
	hash_list_t *hl;
	hash_list_iter_t *iter;
	bool rare = TRUE;

	g_assert(sha1 != NULL);

	hl = htable_lookup(dhl_by_sha1, sha1);
	if (NULL == hl)
		return TRUE;	/* No source */

	iter = hash_list_iterator(hl);

	/*
	 * A download is rare when all the active sources are partial or when we
	 * have no active source.
	 */

	while (hash_list_iter_has_next(iter)) {
		const struct download *d = hash_list_iter_next(iter);

		download_check(d);

		if (d->flags & DL_F_CLONED)
			continue;		/* Cloned entries have d->ranges reset to NULL */

		if (download_is_active(d) && !(d->flags & DL_F_PARTIAL)) {
			rare = FALSE;
			break;
		}
	}

	hash_list_iter_release(&iter);

	return rare;
}

/* ----------------------------------------- */

/***
 *** RX link callbacks
 ***/

static G_GNUC_PRINTF(2, 3) void
download_rx_error(void *o, const char *reason, ...)
{
	struct download *d = o;
	char msg[1024];
	va_list args;

	download_check(d);

	/*
	 * If we sent a pipelined request and got an RX error with the server not
	 * known to support pipelining, them flag it as not supporting pipelining!
	 *		--RAM, 2012-12-09
	 */

	if (
		0 == (d->server->attrs & DLS_A_PIPELINING) &&
		d->pipeline != NULL &&
		GTA_DL_PIPE_SENT == d->pipeline->status
	) {
		d->server->attrs |= DLS_A_NO_PIPELINE;		/* Disable pipelining */

		if (GNET_PROPERTY(download_debug)) {
			g_message("disabled pipelining to %s on I/O error",
				download_host_info(d));
		}
	}

	va_start(args, reason);
	str_vbprintf(msg, sizeof msg, reason, args);
	download_repair(d, msg);
	va_end(args);
}

static void
download_rx_got_eof(void *o)
{
	struct download *d = o;

	download_check(d);
	download_got_eof(d);
}

/**
 * RX data indication callback used to give us some new download traffic in a
 * low-level message structure.
 *
 * @return FALSE if an error occurred.
 */
static bool
download_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct download *d = rx_owner(rx);

	/*
	 * For HTTP pipelining, we must be ready to process incoming network data
	 * from the RX layer even though we're not active yet, to be able to
	 * grab the HTTP reply that may already have been sent on the connection.
	 */

	if (GTA_DL_REQ_SENT == d->status || GTA_DL_HEADERS == d->status) {
		g_assert(d->io_opaque != NULL);

		download_pipeline_socket_feed(d, mb);
		io_add_header(d->io_opaque);
		return TRUE;
	} else {
		g_assert(DOWNLOAD_IS_ACTIVE(d));	/* No I/O via RX stack otherwise */
		g_assert(NULL == d->io_opaque);		/* Done with header parsing */

		return download_read(d, mb);
	}
}

/**
 * RX data indication callback used to give us some new download traffic in a
 * low-level message structure.
 *
 * @return FALSE if an error occurred.
 */
static bool
download_ignore_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct download *d = rx_owner(rx);

	/*
	 * For HTTP pipelining, we must be ready to process incoming network data
	 * from the RX layer even though we're not active yet, to be able to
	 * grab the HTTP reply that may already have been sent on the connection.
	 */

	if (GTA_DL_REQ_SENT == d->status || GTA_DL_HEADERS == d->status) {
		g_assert(d->io_opaque != NULL);

		download_pipeline_socket_feed(d, mb);
		io_add_header(d->io_opaque);
		return TRUE;
	} else {
		g_assert(DOWNLOAD_IS_ACTIVE(d));	/* No I/O via RX stack otherwise */
		g_assert(NULL == d->io_opaque);		/* Done with header parsing */

		return download_ignore_data(d, mb);
	}
}

static const struct rx_link_cb download_rx_link_cb = {
	NULL,					/* add_rx_given */
	download_rx_error,		/* read_error */
	download_rx_got_eof,	/* got_eof */
};

static void
download_chunk_rx_done(void *o)
{
	struct download *d = o;

	download_check(d);
	download_got_eof(d);
}

static const struct rx_chunk_cb download_rx_chunk_cb = {
	download_rx_error,		/* chunk_error */
	download_chunk_rx_done,	/* chunk_end */
};

static const struct rx_inflate_cb download_rx_inflate_cb = {
	NULL,					/* add_rx_inflated */
	download_rx_error,		/* inflate_error */
};

/**
 * Received data from outside the RX stack.
 */
static void
download_write(struct download *d, void *data, size_t len,
	bool pipelined_response)
{
	pdata_t *db;
	pmsg_t *mb;

	download_check(d);

	/*
	 * Prepare data buffer to feed the RX stack.
	 */

	db = pdata_allocb_ext(data, len, pdata_free_nop, NULL);
	mb = pmsg_alloc(PMSG_P_DATA, db, 0, len);

	/*
	 * The message is given to the RX stack, and it will be freed by
	 * the last function consuming it.
	 *
	 * When dealing with pipelined responses, the RX stack is kept from one
	 * request to another and therefore there could be pending data blocks
	 * in the RX stack.  However, we want to deliver this one ahead of all
	 * the others.
	 *
	 * Because we know the RX stack for pipelined requests is made of the
	 * single rx_link layer, we can call the data-ind callback ourselves
	 * directly in that case since it won't need processing.  That is the
	 * only way to put this message block ahead of the others.
	 */

	if (pipelined_response) {
		rx_data_t data_ind = rx_get_data_ind(d->rx);
		g_assert(d->rx == rx_bottom(d->rx));	/* Only the RX link layer */
		(*data_ind)(d->rx, mb);
	} else {
		rx_recv(rx_bottom(d->rx), mb);
	}
}


/**
 * The only place to allocate a struct download.
 */
static struct download *
download_alloc(void)
{
	struct download *d;
	
	WALLOC0(d);
	d->magic = DOWNLOAD_MAGIC;
	return d;
}

/**
 * The only place to release a struct download. The pointer will
 * be nullified to prevent further access of the memory chunk through
 * this pointer.
 *
 * @param d_ptr Pointer to a pointer holding a struct download.
 */
static void
download_free(struct download **d_ptr)
{
	struct download *d;
	
	g_assert(d_ptr);
	d = *d_ptr;
	download_check(d);

	hikset_remove(dl_by_id, d->id);
	dualhash_remove_key(dl_thex, d->id);
	atom_guid_free_null(&d->id);
	d->magic = 0;
	WFREE(d);
	*d_ptr = NULL;
}

/**
 * Hashing of a `dl_key' structure.
 */
static uint
dl_key_hash(const void *key)
{
	const struct dl_key *k = key;
	uint hash;

	hash = guid_hash(k->guid);
	hash ^= host_addr_hash(k->addr);
	hash ^= port_hash(k->port);

	return hash;
}

/**
 * Comparison of `dl_key' structures.
 */
static int
dl_key_eq(const void *a, const void *b)
{
	const struct dl_key *ak = a, *bk = b;

	return host_addr_equal(ak->addr, bk->addr) &&
		ak->port == bk->port &&
		guid_eq(ak->guid, bk->guid);
}

/**
 * Hashing of a `dl_addr' structure.
 */
static uint
dl_addr_hash(const void *key)
{
	const struct dl_addr *k = key;
	uint32 hash;

	hash = host_addr_hash(k->addr);
	hash ^= (k->port << 16) | k->port;

	return (uint) hash;
}

/**
 * Comparison of `dl_addr' structures.
 */
static int
dl_addr_eq(const void *a, const void *b)
{
	const struct dl_addr *ak = a, *bk = b;

	return host_addr_equal(ak->addr, bk->addr) && ak->port == bk->port;
}

/**
 * Compare two `download' structures based on the `retry_after' field.
 * The smaller that time, the smaller the structure is.
 */
static int
dl_retry_cmp(const void *p, const void *q)
{
	const struct download *a = p, *b = q;

	return CMP(a->retry_after, b->retry_after);
}

/**
 * Compare two `dl_server' structures based on the `retry_after' field.
 * The smaller that time, the smaller the structure is.
 */
static int
dl_server_retry_cmp(const void *p, const void *q)
{
	const struct dl_server *a = p, *b = q;

	return CMP(a->retry_after, b->retry_after);
}

/**
 * @returns whether download has a blank (fake) GUID.
 */
static bool
has_blank_guid(const struct download *d)
{
	return guid_is_blank(download_guid(d));
}

bool
download_has_blank_guid(const struct download *d)
{
	return d->server && has_blank_guid(d);
}
	
/**
 * @returns whether download was faked to reparent a complete orphaned file.
 */
bool
is_faked_download(const struct download *d)
{
	return !is_host_addr(download_addr(d)) &&
			download_port(d) == 0 &&
			has_blank_guid(d);
}

/**
 * Was downloaded file verified to have a SHA1 matching the advertised one?
 */
static bool
has_good_sha1(const struct download *d)
{
	fileinfo_t *fi = d->file_info;

	return fi->sha1 == NULL || (fi->cha1 && sha1_eq(fi->sha1, fi->cha1));
}

/**
 * Allocate random GUID to use as the download ID.
 *
 * @return a GUID atom, refcount incremented already.
 */
static const guid_t *
dl_random_guid_atom(void)
{
	struct guid id;
	size_t i;

	/*
	 * Paranoid, in case the random number generator is broken.
	 */

	for (i = 0; i < 100; i++) {
		guid_random_fill(&id);

		if (NULL == hikset_lookup(dl_by_id, &id))
			return atom_guid_get(&id);
	}

	g_error("no luck with random number generator");
	return NULL;
}

/**
 * Determine the set of networks we can return for alt-locs and push-proxies.
 */
static host_net_t
dl_server_net(const struct dl_server *server)
{
	host_net_t net;

	g_assert(dl_server_valid(server));

	net = HOST_NET_IPV4;
	if (server->attrs & DLS_A_IPV6_ONLY)
		net = HOST_NET_IPV6;
	else if (server->attrs & DLS_A_CAN_IPV6)
		net = HOST_NET_BOTH;

	return net;
}

/* ----------------------------------------- */

/**
 * Sets proper timeout delay, with exponential back-off and min/max enforcement.
 *
 * NB: This routine must be invoked before download_stop() is called because
 * it uses the d->start_date field which is reset there.
 */
static void
download_update_timeout_delay(struct download *d)
{
	download_check(d);

	/*
	 * The d->timeout_delay flag is reset to 0 each time we have a successful
	 * connection to the server.  So when we come here with a non-zero time,
	 * we make sure we increase the time we're going to spend waiting, until
	 * we finally get a successful connection.
	 */

	if (d->timeout_delay == 0) {
		/* If we come here from download_continue(), don't set the delay
		 * because the follow-up request may finish instantly and we would
		 * ignore this download on the same connection just because our
		 * careful timeout has not expired yet.
		 */
		if (d->keep_alive && DOWNLOAD_IS_RUNNING(d))
			return;

		d->timeout_delay = GNET_PROPERTY(download_retry_timeout_min);
	} else {
		d->timeout_delay *= 2;
		if (d->start_date) {
			/* We forgive a little while the download is working */
			d->timeout_delay -= delta_time(tm_time(), d->start_date) / 10;
		}
	}

	if (d->timeout_delay < GNET_PROPERTY(download_retry_timeout_min))
		d->timeout_delay = GNET_PROPERTY(download_retry_timeout_min);
	if (d->timeout_delay > GNET_PROPERTY(download_retry_timeout_max))
		d->timeout_delay = GNET_PROPERTY(download_retry_timeout_max);
}

/**
 * Called to request retry of a download after a timeout, with exponential
 * back-off timeout delay, up to a maximum.
 */
static void
download_retry(struct download *d)
{
	download_check(d);

	/*
	 * download_stop() sets the time, so all we need to do is set the delay.
	 */

	download_update_timeout_delay(d);
	download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);
}

/**
 * Return the total progress of a download.  The range
 * on the return value should be 0..1 but there is no
 * guarantee.
 *
 * @param d The download structure which we are interested
 * in knowing the progress of.
 *
 * @return The total percent completed for this file.
 */
double
download_total_progress(const struct download *d)
{
	return filesize_per_10000(download_filesize(d), download_filedone(d))
			/ 10000.0;
}

/**
 * Return the total progress of a download source.  The
 * range on the return value should be 0..1 but there is
 * no guarantee.
 *
 * Same as download_total_progress() if source is not receiving.
 *
 * @param d The download structure which we are interested
 * in knowing the progress of.
 *
 * @return  The percent completed for this source, or zero
 *			if the source is not receiving at the moment.
 */
double
download_source_progress(const struct download *d)
{
	if (DOWNLOAD_IS_ACTIVE(d)) {
		filesize_t done = d->pos - d->chunk.start + download_buffered(d);
		return filesize_per_10000(d->chunk.size, done) / 10000.0;
	} else {
		return 0.0;
	}
}

/**
 * Initialize downloading data structures.
 */
G_GNUC_COLD void
download_init(void)
{
	dl_by_host = hikset_create_any(
		offsetof(struct dl_server, key), dl_key_hash, dl_key_eq);
	dl_by_addr = htable_create_any(dl_addr_hash, NULL, dl_addr_eq);
	dl_by_guid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);
	dl_by_id = hikset_create(
		offsetof(struct download, id), HASH_KEY_FIXED, GUID_RAW_SIZE);
	dhl_by_sha1 = htable_create(HASH_KEY_FIXED, SHA1_RAW_SIZE);
	dl_thex = dualhash_new(guid_hash, guid_eq, guid_hash, guid_eq);

	header_features_add_guarded(FEATURES_DOWNLOADS, "browse",
		BH_VERSION_MAJOR, BH_VERSION_MINOR,
		GNET_PROPERTY_PTR(browse_host_enabled));

	header_features_add_guarded_function(FEATURES_DOWNLOADS,
		"fwalt", FWALT_VERSION_MAJOR, FWALT_VERSION_MINOR,
		dmesh_can_use_fwalt);

	/*
	 * IPv6-Ready:
	 * - advertise "IP/6.4" if we don't run IPv4.
	 * - advertise "IP/6.0" if we run both IPv4 and IPv6.
	 * - advertise nothing otherwise (running IPv4 only)
	 */

	header_features_add_guarded_function(FEATURES_DOWNLOADS, "IP",
		INET_IP_V6READY, INET_IP_NOV4, settings_running_ipv6_only);
	header_features_add_guarded_function(FEATURES_DOWNLOADS, "IP",
		INET_IP_V6READY, INET_IP_V4V6, settings_running_ipv4_and_ipv6);

	sl_downloads = hash_list_new(NULL, NULL);
	sl_unqueued = hash_list_new(NULL, NULL);
}

/**
 * Initialize downloading data structures.
 */
G_GNUC_COLD void
download_restore_state(void)
{
	/*
	 * The order of the following calls matters.
	 */

	gcu_download_gui_updates_freeze();
	download_freeze_queue();

	file_info_retrieve();					/* Get all fileinfos */
	/* Pick up orphaned files */
	file_info_scandir(GNET_PROPERTY(save_file_path));
	download_retrieve();					/* Restore downloads */
	file_info_spot_completed_orphans();		/* 100% done orphans => fake dl. */
	download_resume_bg_tasks();				/* Reschedule SHA1 and moving */
	file_info_store();

	download_thaw_queue();
	gcu_download_gui_updates_thaw();
}

/* ----------------------------------------- */

/**
 * Allocate a set of buffers for data reception.
 */
static void
buffers_alloc(struct download *d)
{
	static const struct dl_buffers zero_buffers;
	struct dl_buffers *b;

	download_check(d);
	socket_check(d->socket);
	g_assert(d->buffers == NULL);
	g_assert(DOWNLOAD_IS_ACTIVE(d));

	WALLOC(b);
	*b = zero_buffers;
	b->list = slist_new();
	b->amount = GNET_PROPERTY(download_buffer_size);

	d->buffers = b;
}

/**
 * Dispose of the buffers used for reading.
 */
static void
buffers_free(struct download *d)
{
	struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers != NULL);
	g_assert(d->buffers->held == 0);	/* No pending data */

	b = d->buffers;
	pmsg_slist_free_all(&b->list);
	WFREE(b);

	d->buffers = NULL;
}

/**
 * Reset the I/O vector for reading from the start.
 */
static void
buffers_reset_reading(struct download *d)
{
	struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers != NULL);
	g_assert(DOWNLOAD_IS_ACTIVE(d));
	g_assert(d->buffers->held == 0);

	b = d->buffers;
	pmsg_slist_discard_all(b->list);
	b->mode = DL_BUF_READING;
}

/**
 * Reset the I/O vector for writing the whole data held in the buffer.
 * The returned object must be freed via hfree().
 */
static iovec_t *
buffers_to_iovec(struct download *d, int *iov_cnt)
{
	struct dl_buffers *b;
	iovec_t *iov;
	size_t held;

	download_check(d);
	socket_check(d->socket);
	g_assert(iov_cnt);

	g_assert(d->buffers != NULL);
	g_assert(DOWNLOAD_IS_ACTIVE(d));

	b = d->buffers;
	g_assert(b->mode == DL_BUF_READING);
	g_assert(b->held > 0);
	g_assert(b->list);
	
	iov = pmsg_slist_to_iovec(b->list, iov_cnt, &held);
	g_assert(iov);
	g_assert(*iov_cnt > 0);
	g_assert(held == b->held);

	b->mode = DL_BUF_WRITING;

	return iov;
}

/**
 * Discard all read data from buffers.
 */
static inline void
buffers_discard(struct download *d)
{
	struct dl_buffers *b;
	fileinfo_t *fi;

	download_check(d);

	g_assert(d->buffers);
	b = d->buffers;
	fi = d->file_info;

	if (fi->buffered >= b->held)
		fi->buffered -= b->held;
	else
		fi->buffered = 0;		/* Be fault-tolerant, this is not critical */

	b->held = 0;
	buffers_reset_reading(d);
}

/**
 * Check whether reception buffers are full.
 */
static inline bool
buffers_full(const struct download *d)
{
	const struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers);

	b = d->buffers;

	return b->held >= GNET_PROPERTY(download_buffer_size);
}

/**
 * Update the buffer structure after having read "amount" more bytes:
 * prepare `iovcnt' for the next read and increase the amount of data held.
 */
static void
buffers_add_read(struct download *d, pmsg_t *mb)
{
	struct dl_buffers *b;
	fileinfo_t *fi;
	int size;
	int available;
	pmsg_t *prev_mb;

	download_check(d);
	socket_check(d->socket);
	g_assert(d->buffers != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = d->buffers;
	fi = d->file_info;

	g_assert(b->mode == DL_BUF_READING);

	/*
	 * Check for under-utilization of message buffers, breaking the zero-copy
	 * policy when the previous buffer has some room and could contain
	 * the totality of the current buffer.
	 *
	 * We don't perform any copy if the amount of data we add is sufficient
	 * to trigger a disk flush: why copy data we're about to write to disk?
	 */

	size = pmsg_size(mb);
	prev_mb = slist_tail(b->list);
	available = prev_mb != NULL ? pmsg_writable_length(prev_mb) : 0;

	if (b->held + size < b->amount && size <= available) {
		int written;

		g_assert(prev_mb != NULL);
		written = pmsg_write(prev_mb, pmsg_start(mb), size);
		g_assert(written == size);
		pmsg_free(mb);

		if (GNET_PROPERTY(download_debug) > 10)
			g_debug("%s(): copied %d bytes "
				"into %d-byte long previous #%d (had %d bytes free)",
				G_STRFUNC, written, pmsg_size(prev_mb) - written,
				slist_length(b->list), available);
	} else
		slist_append(b->list, mb);

	b->held += size;		/* Whether copied or not */

	/*
	 * Update read statistics.
	 */

	fi->buffered += size;
}

/**
 * Check whether we should request flushing of the buffered data.
 */
static inline bool
buffers_should_flush(const struct download *d)
{
	const struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers);

	b = d->buffers;

	/*
	 * Check against MAX_IOV_COUNT because if there are more buffers,
	 * this requires looping with [p]writev() - at least with the
	 * current download logic - which is inefficient.
	 */
	return b->held >= b->amount || slist_length(b->list) >= MAX_IOV_COUNT;
}

/**
 * Compare data held in the read buffers with the data chunk supplied.
 *
 * @return TRUE if data match.
 */
static bool
buffers_match(const struct download *d, const char *data, size_t len)
{
	const struct dl_buffers *b;
	slist_iter_t *iter;

	download_check(d);
	socket_check(d->socket);
	g_assert(d->buffers != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = d->buffers;
	g_assert(len <= b->held);

	iter = slist_iter_before_head(b->list);
	while (len > 0) {
		const pmsg_t *mb;
		size_t n;

		g_assert(slist_iter_has_next(iter));	
		mb = slist_iter_next(iter);
		g_assert(mb);

		n = pmsg_size(mb);
		n = MIN(n, len);
		if (0 != memcmp(pmsg_read_base(mb), data, n)) {
			break;
		}
		data += n;
		len -= n;
	}
	slist_iter_free(&iter);

	return 0 == len;
}

/**
 * Strip leading `amount' bytes from the read buffers.
 */
static void
buffers_strip_leading(struct download *d, size_t amount)
{
	struct dl_buffers *b;
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->buffers != NULL);

	b = d->buffers;
	fi = d->file_info;

	g_assert(b->mode == DL_BUF_READING);
	g_assert(amount <= b->held);

	if (b->held <= amount) {
		buffers_discard(d);
		return;
	}

	pmsg_slist_discard(b->list, amount);
	b->held -= amount;

	if (fi->buffered >= amount)
		fi->buffered -= amount;
	else
		fi->buffered = 0;		/* Not critical, be fault-tolerant */
}

/**
 * Assertion checking: b->held correctly represents the amount of buffered data.
 */
static void
buffers_check_held(const struct download *d)
{
	const struct dl_buffers *b;
	size_t held = 0;
	slist_iter_t *iter;

	download_check(d);

	b = d->buffers;
	g_assert(b);
	g_assert((0 == b->held) ^ (slist_length(b->list) > 0));

	iter = slist_iter_before_head(b->list);
	while (slist_iter_has_next(iter)) {
		const pmsg_t *mb;
		size_t size;

		mb = slist_iter_next(iter);
		g_assert(mb);

		size = pmsg_size(mb);
		g_assert(size > 0);

		g_assert(size <= ((size_t) -1) - held);
		held += size;
	}
	slist_iter_free(&iter);

	g_assert(held == b->held);
}

/**
 * Strip trailing `amount' bytes from the read buffers.
 */
static void
buffers_strip_trailing(struct download *d, size_t amount)
{
	struct dl_buffers *b;
	slist_iter_t *iter;
	fileinfo_t *fi;
	size_t n;

	download_check(d);
	g_assert(d->buffers != NULL);

	b = d->buffers;
	fi = d->file_info;

	g_assert(b->mode == DL_BUF_READING);
	g_assert(amount <= b->held);

	if (b->held <= amount) {
		buffers_discard(d);
		return;
	}
	n = b->held - amount;

	iter = slist_iter_removable_on_head(b->list);
	while (slist_iter_has_item(iter)) {
		pmsg_t *mb;
		size_t size;

		mb = slist_iter_current(iter);
		g_assert(mb);

		if (n > 0) {
			size = pmsg_size(mb);
			if (size < n) {
				n -= size;
			} else {
				if (size > n) {
					pmsg_discard_trailing(mb, size - n);
				}
				n = 0;
			}
			slist_iter_next(iter);
		} else {
			pmsg_free(mb);
			slist_iter_remove(iter);
		}
	}
	slist_iter_free(&iter);

	b->held -= amount;

	if (fi->buffered >= amount)
		fi->buffered -= amount;
	else
		fi->buffered = 0;		/* Not critical, be fault-tolerant */
}

/* ----------------------------------------- */

/**
 * Insert server by retry time into the `dl_by_time' structure.
 */
static void
dl_by_time_insert(struct dl_server *server)
{
	uint idx = DL_HASH(server->retry_after);

	g_assert(dl_server_valid(server));

	dl_by_time.change[idx]++;
	dl_by_time.servers[idx] = plist_insert_sorted(dl_by_time.servers[idx],
		server, dl_server_retry_cmp);
}

/**
 * Remove server from the `dl_by_time' structure.
 */
static void
dl_by_time_remove(struct dl_server *server)
{
	uint idx = DL_HASH(server->retry_after);

	g_assert(dl_server_valid(server));

	dl_by_time.change[idx]++;
	dl_by_time.servers[idx] = plist_remove(dl_by_time.servers[idx], server);
}

/**
 * Add hosts in the vector as push-proxies for the server, provided they
 * were not already known.
 */
static void
add_proxies_vec(struct dl_server *server, const gnet_host_vec_t *vec)
{
	g_assert(dl_server_valid(server));

	if (NULL == server->proxies)
		server->proxies = pproxy_set_allocate(DOWNLOAD_MAX_PROXIES);

	pproxy_set_add_vec(server->proxies, vec);
}

/**
 * Add host to the known push-proxies for the server, if not already known.
 *
 * @return TRUE if host was added, FALSE if we already knew it.
 */
static bool
add_proxy(struct dl_server *server, const host_addr_t addr, uint16 port)
{
	g_assert(dl_server_valid(server));

	if (NULL == server->proxies)
		server->proxies = pproxy_set_allocate(DOWNLOAD_MAX_PROXIES);

	return pproxy_set_add(server->proxies, addr, port);
}

/**
 * Remove push proxy from server.
 */
static void
remove_proxy(struct dl_server *server, const host_addr_t addr, uint16 port)
{
	g_assert(dl_server_valid(server));

	if (server->proxies != NULL)
		pproxy_set_remove(server->proxies, addr, port);
}

/**
 * Allocate new server structure.
 */
static struct dl_server *
allocate_server(const struct guid *guid, const host_addr_t addr, uint16 port)
{
	struct dl_key *key;
	struct dl_server *server;

	g_assert(host_addr_initialized(addr));

	WALLOC(key);
	key->addr = addr;
	key->port = port;
	key->guid = atom_guid_get(guid);

	WALLOC0(server);
	server->magic = DL_SERVER_MAGIC;
	server->key = key;
	server->retry_after = tm_time();
	server->country = gip_country(addr);
	server->sha1_counts = htable_create(HASH_KEY_FIXED, SHA1_RAW_SIZE);

	hikset_insert_key(dl_by_host, &server->key);
	dl_by_time_insert(server);

	/*
	 * If host is reacheable directly, its GUID does not matter much to
	 * identify the server as the (IP, port) should be unique.
	 */

	if (host_is_valid(addr, port)) {
		struct dl_addr *ipk;
		const void *ipkey;
		void *x;					/* Don't care about freeing values */
		bool existed;

		WALLOC(ipk);
		ipk->addr = addr;			/* Struct copy */
		ipk->port = port;

		existed = htable_lookup_extended(dl_by_addr, ipk, &ipkey, &x);

		/*
		 * For the rare cases where the key already existed, we "take
		 * ownership" of the old key by associating our server entry in it.
		 * We reuse the old key, and free the new one, otherwise we'd
		 * have a memory leak because noone would free the old key!
		 */

		if (existed) {
			const struct dl_addr *da = ipkey;
			g_assert(da != ipk);
			g_assert(host_addr_initialized(da->addr));
			WFREE(ipk);				/* Keep the old key */
			htable_insert(dl_by_addr, da, server);
		} else
			htable_insert(dl_by_addr, ipk, server);
	}

	/*
	 * If this is not a blank GUID and there is no such host bearing the
	 * same GUID already, record it.  Otherwise, warn about the conflicting
	 * GUID if they are debugging.
	 */

	if (!guid_is_blank(guid)) {
		bool existed;
		void *value;

		existed = htable_lookup_extended(dl_by_guid, guid, NULL, &value);

		if (existed) {
			struct dl_server *old = value;

			if (debugging(0))
				g_warning("GUID collision: %s is used by known %s and new %s",
					guid_to_string(guid),
					host_addr_port_to_string(old->key->addr, old->key->port),
					host_addr_port_to_string2(
						server->key->addr, server->key->port));
		} else {
			htable_insert(dl_by_guid, server->key->guid, server);
		}
	}

	return server;
}

static void
server_list_free_all(struct dl_server *server)
{
	uint i;

	g_assert(dl_server_valid(server));
	g_assert(0 == count_running_on_server(server));

	for (i = 0; i < DL_LIST_SZ; i++) {
		list_free(&server->list[i]);
	}
}

/**
 * Unregister server so that get_server() may no longer find it.
 */
static void
server_unregister(struct dl_server *server)
{
	g_assert(dl_server_valid(server));

	dl_by_time_remove(server);
	hikset_remove(dl_by_host, server->key);

	/*
	 * We only inserted the server in the `dl_addr' table if it was "reachable".
	 */

	{
		struct dl_addr ipk;
		const void *ipkey;
		void *x;

		ipk.addr = server->key->addr;
		ipk.port = server->key->port;

		/*
		 * Only remove server in the `dl_by_addr' table if it is the one
		 * for which the IP key is recored.  Otherwise, what can happen
		 * is that a server is detached from a download and marked for
		 * delayed removal.  Then a new one with same address is sprung
		 * to life, and inserted in `dl_by_addr'.  If we remove it now,
		 * we'll free the key of the new server.
		 */

		if (htable_lookup_extended(dl_by_addr, &ipk, &ipkey, &x)) {
			struct dl_addr *da = deconstify_pointer(ipkey);
			g_assert(host_addr_initialized(da->addr));
			if (x == server) {		/* We own the key */
				htable_remove(dl_by_addr, &ipk);
				WFREE(da);
			}
		}
	}

	/*
	 * Given there can be GUID collisions, make sure it is this entry which
	 * is listed in the `dl_by_guid' table.  Only non-blank GUIDs are stored.
	 */

	if (
		!guid_is_blank(server->key->guid) &&
		htable_lookup(dl_by_guid, server->key->guid) == server
	) {
		htable_remove(dl_by_guid, server->key->guid);
	}
}

/**
 * Free server structure.
 */
static void
free_server(struct dl_server *server)
{
	g_assert(dl_server_valid(server));
	g_assert(server->refcnt == 0);
	g_assert(server_list_length(server, DL_LIST_RUNNING) == 0);
	g_assert(server_list_length(server, DL_LIST_WAITING) == 0);
	g_assert(server_list_length(server, DL_LIST_STOPPED) == 0);
	g_assert(server->list[DL_LIST_RUNNING] == NULL);
	g_assert(server->list[DL_LIST_WAITING] == NULL);
	g_assert(server->list[DL_LIST_STOPPED] == NULL);

	server_unregister(server);
	pproxy_set_free_null(&server->proxies);
	atom_str_free_null(&server->hostname);
	server_list_free_all(server);
	route_starving_remove(server->key->guid);

	{
		uint n = htable_count(server->sha1_counts);
		if (0 != n) {
			g_warning("server->sha1_counts (%s) contains still %u items",
				host_addr_port_to_string(server->key->addr, server->key->port),
				n);
		}
	}

	htable_free_null(&server->sha1_counts);
	atom_str_free_null(&server->vendor);
	atom_guid_free_null(&server->key->guid);
	WFREE(server->key);
	server->magic = 0;
	WFREE(server);
}

/**
 * Marks server for delayed removal (via asynchronous timer).
 */
static void
server_delay_delete(struct dl_server *server)
{
	g_assert(dl_server_valid(server));
	g_assert(!(server->attrs & DLS_A_REMOVED));

	server->attrs |= DLS_A_REMOVED;		/* Insert once in list */
	sl_removed_servers = pslist_prepend(sl_removed_servers, server);
}

/**
 * Resurrect server pending deletion.
 */
static void
server_undelete(struct dl_server *server)
{
	g_assert(dl_server_valid(server));
	g_assert(server->attrs & DLS_A_REMOVED);

	server->attrs &= ~DLS_A_REMOVED;	/* Clear flag */
	sl_removed_servers = pslist_remove(sl_removed_servers, server);
}

/**
 * Found IP:port of firewalled source for which we knew only the GUID.
 * This happens when retrieving firewalled magnet sources for instance.
 *
 * Or we have found the GUID of a server which was only known by its IP:port.
 */
void
download_found_server(const struct guid *guid,
	const host_addr_t addr, uint16 port)
{
	struct dl_server *server;

	if (guid_is_blank(guid))
		return;

	/*
	 * XXX Unfortunately, this late discovery of the real IP:port can create
	 * XXX duplicate downloads.  Imagine we thought this was 0.0.0.0 for some
	 * XXX GUID and then we get a query hit for the same SHA1 but with a
	 * XXX proper IP.  Later on when we discover the real IP, we'll create
	 * XXX a duplicate download because we're changing the server from 0.0.0.0
	 * XXX to the same IP address.
	 * XXX		--RAM, 2008-09-01
	 */

	server = htable_lookup(dl_by_guid, guid);

	if (NULL == server) {
		/*
		 * Locate server by address/port to see whether we already knew about
		 * that host and whether it had a blank GUID, in which case we can
		 * now put the GUID we discovered.
		 */

		if (guid_eq(guid, GNET_PROPERTY(servent_guid))) {
			gnet_stats_inc_general(GNR_OWN_GUID_COLLISIONS);

			if (GNET_PROPERTY(download_debug)) {
				g_warning("discovered that host %s bears our GUID!",
					host_addr_port_to_string(addr, port));
			}

			return;
		}

		if (host_is_valid(addr, port)) {
			struct dl_addr ipk;

			ipk.addr = addr;
			ipk.port = port;

			server = htable_lookup(dl_by_addr, &ipk);

			if (server && guid_is_blank(server->key->guid)) {
				struct dl_key *key = server->key;

				if (GNET_PROPERTY(download_debug)) {
					g_debug("discovered GUID %s is for host %s "
						"which had a blank GUID", guid_to_string(guid),
						host_addr_port_to_string(addr, port));
				}

				hikset_remove(dl_by_host, key);
				gnet_stats_inc_general(GNR_DISCOVERED_SERVER_GUID);
				atom_guid_change(&key->guid, guid);
				htable_insert(dl_by_guid, key->guid, server);
				hikset_insert_key(dl_by_host, &server->key);
			}
		} else {
			if (GNET_PROPERTY(download_debug)) {
				g_debug("discovered GUID %s is for (firewalled) host %s, "
					"but server is gone!",
					guid_to_string(guid), host_addr_port_to_string(addr, port));
			}
		}

		return;
	}

	g_assert(dl_server_valid(server));

	/*
	 * Check whether something changed at all.
	 */

	if (host_addr_equal(addr, server->key->addr) && port == server->key->port)
		return;

	if (GNET_PROPERTY(download_debug))
		g_debug("discovered GUID %s is for host %s [%s] (was %s [%s])",
			guid_to_string(guid), host_addr_port_to_string(addr, port),
			iso3166_country_cc(gip_country(addr)),
			host_addr_port_to_string2(server->key->addr, server->key->port),
			iso3166_country_cc(server->country));

	change_server_addr(server, addr, port);
}

/**
 * Reparent (i.e. move) all downloads from server ``duplicate'' to ``server''.
 */
static void
download_reparent_all(struct dl_server *duplicate, struct dl_server *server)
{
	struct download *next;

	gnet_stats_inc_general(GNR_CONSOLIDATED_SERVERS);

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;

		download_check(d);
		next = hash_list_next(sl_downloads, next);

		if (d->status == GTA_DL_REMOVED)
			continue;

		if (d->server == duplicate)
			download_reparent(d, server);
	}

	/*
	 * Make sure get_server() no longer returns it
	 */

	server_unregister(duplicate);
}

/**
 * Notify all the downloads attached to a server that the address of the
 * server changed, so that the GUI can be refreshed.
 */
static void
download_server_info_changed(const struct dl_server *server)
{
	size_t i;
	enum dl_list listnum[] = { DL_LIST_RUNNING, DL_LIST_WAITING };

	g_assert(dl_server_valid(server));

	for (i = 0; i < G_N_ELEMENTS(listnum); i++) {
		enum dl_list idx = listnum[i];
		list_iter_t *iter;
		
		iter = list_iter_before_head(server->list[idx]);
		while (list_iter_has_next(iter)) {
			struct download *d;

			d = list_iter_next(iter);
			download_check(d);
			fi_src_info_changed(d);
		}
		list_iter_free(&iter);
	}
}

/**
 * Fetch server entry identified by IP:port first, then GUID+IP:port.
 *
 * @returns server, allocated if needed when allocate is TRUE.
 *
 * WARNING: may return a server instance whose address and port do not
 * match the initial arguments: when for instance the addr:port was a private
 * address but the non-blank GUID yields a proper server with a non-private
 * one.  If addr:port matter, the caller must use server->key->addr and
 * server->key->port after calling get_server().
 */
static struct dl_server *
get_server(const struct guid *guid, const host_addr_t addr, uint16 port,
	bool allocate)
{
	struct dl_addr ikey;
	struct dl_key key;
	struct dl_server *server;

	g_assert(guid);
	g_assert(host_addr_initialized(addr));

	ikey.addr = addr;
	ikey.port = port;

	/*
	 * A server can have its freeing "delayed".  If we are asked for a
	 * server that has been deleted, we need to "undelete" it.
	 */

	server = htable_lookup(dl_by_addr, &ikey);
	if (server) {
		if (server->attrs & DLS_A_REMOVED)
			server_undelete(server);
		goto allocated;
	}

	/*
	 * Only servers with a valid addr:port are inserted in dl_by_addr.
	 * So if we did not find it there, look in the table listing all servers.
	 */

	key.guid = deconstify_pointer(guid);
	key.addr = addr;
	key.port = port;

	server = hikset_lookup(dl_by_host, &key);
	g_assert(server == NULL || dl_server_valid(server));

	if (server) {
		if (server->attrs & DLS_A_REMOVED)
			server_undelete(server);
		goto allocated;
	}

	/*
	 * Last chance: if the GUID is non-blank, maybe we can find the server.
	 * Naturally, it will not bear the same addr:port or we would have found
	 * it in dl_by_host.
	 */

	if (!guid_is_blank(guid)) {
		server = htable_lookup(dl_by_guid, guid);

		if (server) {
			struct dl_key *skey = server->key;
			uint16 new_country = gip_country(addr);

			if (server->attrs & DLS_A_REMOVED)
				server_undelete(server);

			/*
			 * Equality is only possible when we're not asked to create a
			 * new server, because we're coming from change_server_addr()
			 * for instance and manipulating the data structures.
			 *
			 * If we're not allocating a new host. don't mess with the
			 * found server address.
			 */

			if (!allocate)
				goto allocated;

			g_assert(!host_addr_equal(skey->addr, addr) || skey->port != port);

			/*
			 * We knew this server, and it bears a new IP or port.
			 *
			 * If only the port changed, that's OK, but if the IP also
			 * changed, make sure it is in the same country or that the
			 * old address was not routable.
			 */

			if (
				host_addr_equal(skey->addr, addr) ||
				server->country == new_country ||
				(
					/* Address becomes routable */
					!host_addr_is_routable(skey->addr) &&
					host_addr_is_routable(addr)
				)
			) {
				if (GNET_PROPERTY(download_debug)) {
					g_debug("server GUID %s was at %s, now seen at %s [%s]",
						guid_to_string(guid),
						host_addr_port_to_string(skey->addr, skey->port),
						host_addr_port_to_string2(addr, port),
						iso3166_country_cc(new_country));
				}
				change_server_addr(server, addr, port);
			} else {
				if (GNET_PROPERTY(download_debug)) {
					g_debug(
						"not moving server GUID %s from %s [%s] to %s [%s]",
						guid_to_string(guid),
						host_addr_port_to_string(skey->addr, skey->port),
						iso3166_country_cc(server->country),
						host_addr_port_to_string2(addr, port),
						iso3166_country_cc(new_country));
				}
				/*
				 * The server we return should bear correct addr:port, but it
				 * won't match the supplied arguments.  See WARNING in
				 * function's leading comment.
				 */
			}
			g_assert(!guid_is_blank(server->key->guid));
		} else {
			/*
			 * Server not existing, make sure it does not bear our GUID
			 */

			if (guid_eq(guid, GNET_PROPERTY(servent_guid))) {
				/*
				 * Make sure the server address is not ours, otherwise we
				 * don't count that as a GUID collision.
				 */

				if (!is_my_address_and_port(addr, port)) {
					gnet_stats_inc_general(GNR_OWN_GUID_COLLISIONS);

					if (GNET_PROPERTY(download_debug)) {
						g_warning("host %s bears our GUID!",
							host_addr_port_to_string(addr, port));
					}
				} else {
					/*
					 * We're supposed to detect our IP:port earlier and avoid
					 * attempting to download from ourselves.  When debugging,
					 * trace the calling stack to see flaws in the logic.
					 *		--RAM, 2011-07-19
					 */

					if (GNET_PROPERTY(download_debug)) {
						g_carp("%s() called with our IP:port %s", G_STRFUNC,
							host_addr_port_to_string(addr, port));
					}
				}

				if (allocate)
					guid = &blank_guid;		/* Can't let them reuse it */
			}
		}
	}

	/*
	 * Allocate new server if it does not exist already.
	 */

	if (NULL == server) {
		if (!allocate)
			return NULL;
		server = allocate_server(guid, addr, port);
	}

allocated:
	if (g2_cache_lookup(addr, port)) {
		server->attrs |= DLS_A_G2_ONLY;
	}

	/*
	 * If we had a blank GUID in the server but we had a non-blank one
	 * supplied, we have found the missing piece to uniquely identify
	 * the server.
	 *
	 * Imagine the server's GUID was not yet known. For instance,
	 * we could have two entries for one host:
	 *
	 * #1	GUID 00000000000000000000000000000000 at 99.184.74.166:22459
	 * #2	GUID 018c33a4c292b2d2fc8c53dd28ba4d00 at 192.168.1.64:22459
	 *
	 * If we found the server by address, we got #1, but download_found_server()
	 * will locate by GUID and find #2.  It will then call
	 * change_server_addr() to change the address of #2 to that of #1,
	 * and the duplicate #1 will be picked and remaped to #2.
	 *
	 * Upon return, we must therefore not return the original server we
	 * had figured, but recompute the server by looking in the by_dl_guid hash.
	 */

	if (
		!guid_is_blank(guid) &&
		(
			guid_is_blank(server->key->guid) ||
			!host_is_valid(server->key->addr, server->key->port)
		)
	) {
		struct dl_server *correct;

		download_found_server(guid, addr, port);
		correct = htable_lookup(dl_by_guid, guid);

		if (correct != NULL && correct != server) {
			if (GNET_PROPERTY(download_debug)) {
				g_debug("had originally found GUID %s at %s, "
					"returning GUID %s at %s",
					guid_hex_str(server->key->guid),
					host_addr_port_to_string(
						server->key->addr, server->key->port),
					guid_to_string(correct->key->guid),
					host_addr_port_to_string2(
						correct->key->addr, correct->key->port));
			}
			server = correct;
		}
	}

	g_assert(dl_server_valid(server));

	/*
	 * Address, port or GUID of returned server may be different from arguments
	 */

	if (GNET_PROPERTY(download_debug) > 1) {
		if (
			!host_addr_equal(addr, server->key->addr) ||
			server->key->port != port ||
			!guid_eq(server->key->guid, guid)
		) {
			g_debug("called get_server() with GUID %s at %s, "
				"returning GUID %s at %s",
				guid_hex_str(guid), host_addr_port_to_string(addr, port),
				guid_to_string(server->key->guid),
				 host_addr_port_to_string2(
					server->key->addr, server->key->port));
		}
	}

	return server;
}

/**
 * The server address/port changed.
 */
static void
change_server_addr(struct dl_server *server,
	const host_addr_t new_addr, const uint16 new_port)
{
	struct dl_key *key = server->key;
	struct dl_server *duplicate;

	g_assert(dl_server_valid(server));
	g_assert(host_addr_initialized(new_addr));

	hikset_remove(dl_by_host, key);

	/*
	 * We only inserted the server in the `dl_addr' table if it was "reachable".
	 */

	if (host_is_valid(key->addr, key->port)) {
		struct dl_addr ipk;
		const void *ipkey;
		void *x;					/* Don't care about freeing values */

		ipk.addr = key->addr;
		ipk.port = key->port;

		if (htable_lookup_extended(dl_by_addr, &ipk, &ipkey, &x)) {
			struct dl_addr *da = deconstify_pointer(ipkey);
			g_assert(host_addr_initialized(da->addr));
			if (x == server) {		/* We "own" the key -- see free_server() */
				htable_remove(dl_by_addr, da);
				WFREE(da);
			}
		}
	}

	if (GNET_PROPERTY(download_debug)) {
		g_debug("server <%s> at %s:%u changed its IP from %s to %s",
			server->vendor == NULL ? "UNKNOWN" : server->vendor,
			server->hostname == NULL ? "NONAME" : server->hostname,
			key->port, host_addr_port_to_string(key->addr, key->port),
			host_addr_port_to_string2(new_addr, new_port));
    }

	/*
	 * If server is known to support TLS, remove the old address from the
	 * cache and insert the new one instead.
	 */

	if (server->attrs & DLS_A_TLS) {
		tls_cache_remove(key->addr, key->port);
		tls_cache_insert(new_addr, new_port);
	}

	/*
	 * Perform the IP change.
	 */

	key->addr = new_addr;
	key->port = new_port;
	server->country = gip_country(new_addr);

	g_assert(dl_server_valid(server));

	/*
	 * Look for a duplicate.  It's quite possible that we saw some IP
	 * address 1.2.3.4 and 5.6.7.8 without knowing that they both were
	 * for the foo.example.com host.  And now we learn that the name
	 * foo.example.com which we thought was 5.6.7.8 is at 1.2.3.4...
	 */

	duplicate = get_server(key->guid, new_addr, new_port, FALSE);

	if (duplicate != NULL && duplicate != server) {
		g_assert(dl_server_valid(duplicate));
		g_assert(host_addr_equal(duplicate->key->addr, key->addr));
		g_assert(duplicate->key->port == key->port);

		if (GNET_PROPERTY(download_debug)) {
            g_debug(
                "new IP %s for server <%s> GUID %s at %s:%u "
				"was used by <%s> GUID %s at %s:%u",
                host_addr_to_string(new_addr),
                server->vendor == NULL ? "UNKNOWN" : server->vendor,
				guid_hex_str(key->guid),
                server->hostname == NULL ? "NONAME" : server->hostname,
                key->port,
                duplicate->vendor == NULL ? "UNKNOWN" : duplicate->vendor,
				guid_to_string(duplicate->key->guid),
                duplicate->hostname == NULL ? "NONAME" : duplicate->hostname,
                duplicate->key->port);
        }

		/*
		 * If there was no GUID known for `server', copy the one
		 * from `duplicate'.
		 */

		if (
			guid_is_blank(key->guid) &&
			!guid_is_blank(duplicate->key->guid)
		) {
			struct dl_server *old;

			old = htable_lookup(dl_by_guid, duplicate->key->guid);
			atom_guid_change(&key->guid, duplicate->key->guid);
			if (duplicate == old)
				htable_insert(dl_by_guid, key->guid, server);
		} else if (
			!guid_eq(key->guid, duplicate->key->guid) &&
			!guid_is_blank(duplicate->key->guid)
		) {
			/* Remote node changed its GUID (after restart?) */
			gnet_stats_inc_general(GNR_CHANGED_SERVER_GUID);

			if (GNET_PROPERTY(download_debug)) g_warning(
				"found two distinct GUID for <%s> at %s:%u, keeping %s",
				server->vendor == NULL ? "UNKNOWN" : server->vendor,
				server->hostname == NULL ? "NONAME" : server->hostname,
				key->port, guid_hex_str(key->guid));
        }

		/*
		 * All the downloads attached to the `duplicate' server need to be
		 * reparented to `server' instead.
		 */

		download_reparent_all(duplicate, server);
	}

	/*
	 * We can now blindly insert `server' in the hash.  If there was a
	 * conflicting entry, all its downloads have been reparented and that
	 * server will be freed later, asynchronously.
	 */

	g_assert(server->key == key);

	hikset_insert_key(dl_by_host, &server->key);

	if (host_is_valid(key->addr, key->port)) {
		struct dl_addr *ipk;
		const void *ipkey;
		void *x;					/* Don't care about freeing values */
		bool existed;

		WALLOC(ipk);
		ipk->addr = new_addr;
		ipk->port = key->port;

		existed = htable_lookup_extended(dl_by_addr, ipk, &ipkey, &x);

		/*
		 * For the rare cases where the key already existed, we "take
		 * ownership" of the old key by associating our server entry in it.
		 * We reuse the old key, and free the new one, otherwise we'd
		 * have a memory leak because noone would free the old key!
		 */

		if (existed) {
			const struct dl_addr *da = ipkey;
			g_assert(host_addr_initialized(da->addr));
			g_assert(da != ipk);
			WFREE(ipk);				/* Keep the old key around */
			htable_insert(dl_by_addr, da, server);
		} else
			htable_insert(dl_by_addr, ipk, server);
	}

	/*
	 * Notify the source information change to all the downloads
	 * attached to that server so that the GUI can be refreshed to
	 * show the new address and port number.
	 */

	download_server_info_changed(server);
}

/**
 * Do we have more pending files to be retrieved on this server?
 * If ``retry_after'' is TRUE, also check the d->retry_after field to
 * make sure we can schedule this download.
 *
 * We're only interested in downloads to which we could switch an already
 * established connection.
 */
static bool
download_has_pending_on_server(const struct download *d, bool retry_after)
{
	list_iter_t *iter;
	bool result = FALSE;
	time_t now = tm_time();

	download_check(d);

	if (
		!GNET_PROPERTY(dl_resource_switching) ||
		0 == server_list_length(d->server, DL_LIST_WAITING)
	)
		return FALSE;

	iter = list_iter_before_head(d->server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter)) {
		struct download *cur;

		cur = list_iter_next(iter);
		download_check(cur);

		if (
			DOWNLOAD_IS_SWITCHABLE(cur) &&
			(!retry_after || delta_time(now, cur->retry_after) >= 0)
		) {
			result = TRUE;
			break;
		}
	}
	list_iter_free(&iter);

	return result;
}

/**
 * See whether we can ignore the data from now on, keeping the connection
 * open and sinking to /dev/null: the idea is that we keep the slot busy
 * to get a chance to re-issue another request later.
 *
 * @return TRUE if we successfully setup the downloaded data to be ignored.
 */
static bool
download_can_ignore(struct download *d)
{
	filesize_t remain;
	uint speed_avg;

	download_check(d);

	g_assert(d->chunk.end >= d->pos);
	g_assert(d->socket);
	g_assert(d->rx);
	g_assert(d->buffers);

	if (d->status == GTA_DL_IGNORING)
		return TRUE;

	remain = d->chunk.end - d->pos;

	/*
	 * If this is an incoming connection, keep it up provided we have
	 * something else to switch to later on for this server.
	 */

	if (
		SOCK_CONN_INCOMING == d->socket->direction &&
		download_has_pending_on_server(d, FALSE)
	) {
		if (GNET_PROPERTY(download_debug)) {
			uint count = server_list_length(d->server, DL_LIST_WAITING);
			g_debug("download \"%s\" has incoming connection from %s "
				"and %u waiting file%s on that server -- will sink %s bytes",
				download_basename(d), download_host_info(d),
				count, plural(count), uint64_to_string(remain));
		}

		goto sink_data;
	}

	/*
	 * Look at how many bytes we need to download still for this
	 * request.  If we have a known average download rate for the
	 * server, great, we'll use it to estimate the time we'll spend.
	 * Otherwise, use a size limit.
	 */

	speed_avg = download_speed_avg(d);

	if (speed_avg && remain / speed_avg > DOWNLOAD_MAX_IGN_TIME)
		goto refused;

	if (remain > DOWNLOAD_MAX_IGN_DATA)
		goto refused;

sink_data:

	/*
	 * We're going to purely ignore the data until we reach the end
	 * of this request, at which time we'll issue a new request,
	 * possibly somewhere else: we don't know for sure whether the
	 * source is bad or the data we had at the resuming point were
	 * faulty, hence we have to leave that to randomness -- we take
	 * our chances with the source..
	 */

	(void) rx_replace_data_ind(d->rx, download_ignore_data_ind);
	download_silent_flush(d);
	download_set_status(d, GTA_DL_IGNORING);

	if (GNET_PROPERTY(download_debug) > 1)
		g_debug("will be ignoring next %s bytes of data for \"%s\"",
			uint64_to_string(remain), download_basename(d));

	return TRUE;

refused:
	gnet_stats_inc_general(GNR_IGNORING_REFUSED);
	return FALSE;
}

/**
 * Signals that server seems to be publishing in the DHT.
 */
void
download_server_publishes_in_dht(const struct guid *guid)
{
	struct dl_server *server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	g_assert(dl_server_valid(server));

	if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(dht_debug)) {
		if (!(server->attrs & DLS_A_DHT_PUBLISH)) {
			g_debug("DL learnt that %s publishes in the DHT",
				server_host_info(server));
		}
	}

	server->attrs |= DLS_A_DHT_PUBLISH;
}

/**
 * Add a single push-proxy for server identified by its GUID.
 */
void
download_add_push_proxy(const struct guid *guid,
	host_addr_t addr, uint16 port)
{
	struct dl_server *server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	g_assert(dl_server_valid(server));

	add_proxy(server, addr, port);
}

/**
 * Add new push-proxies for server held in the `proxies' array.
 */
void
download_add_push_proxies(const struct guid *guid,
	gnet_host_t *proxies, int proxy_count)
{
	struct dl_server *server;

	g_assert(proxies);

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	g_assert(dl_server_valid(server));

	if (NULL == server->proxies)
		server->proxies = pproxy_set_allocate(DOWNLOAD_MAX_PROXIES);

	pproxy_set_add_array(server->proxies, proxies, proxy_count);
}

/**
 * Wakeup call when we get a fresh list of push-proxies for a server.
 * Re-send UDP push-requests to those expecting a GIV and those in a
 * "timeout wait" state if ``udp'' is TRUE.
 * If ``broadcast'' is TRUE, also try to broadcast the PUSH on Gnutella.
 */
static void
download_push_proxy_wakeup(struct dl_server *server,
	bool udp, bool broadcast)
{
	list_iter_t *iter;
	uint32 n = GNET_PROPERTY(max_host_downloads);
	time_t now;
	uint sent = 0;

	/*
	 * Send a UDP push request to the `n' first download we find waiting
	 * for a GIV from this server, with n = the max number of downloads
	 * we can request from a single server.
	 */

	iter = list_iter_before_head(server->list[DL_LIST_RUNNING]);
	while (list_iter_has_next(iter) && n != 0) {
		struct download *d = list_iter_next(iter);
		download_check(d);
		if (udp)
			d->flags &= ~DL_F_UDP_PUSH;
		if (DOWNLOAD_IS_EXPECTING_GIV(d)) {
			if (download_send_push_request(d, udp, broadcast)) {
				n--;
				sent++;
			}
		}
	}
	list_iter_free(&iter);

	/*
	 * If we still have some slots for this host, look at downloads
	 * in the "timeout" state which we can restart.
	 */

	if (n == 0)
		goto done;

	if (GNET_PROPERTY(max_host_downloads) <= count_running_on_server(server))
		goto done;

	n = GNET_PROPERTY(max_host_downloads) - count_running_on_server(server);
	now = tm_time();

	iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter) && n != 0) {
		struct download *d = list_iter_next(iter);
		download_check(d);
		d->flags &= ~DL_F_UDP_PUSH;
		if (d->flags & (DL_F_SUSPENDED | DL_F_PAUSED))
			continue;
		if (
			GTA_DL_TIMEOUT_WAIT == d->status ||
			delta_time(now, d->retry_after) >= 0
		) {
			if (download_send_push_request(d, udp, broadcast)) {
				n--;
				sent++;
			}
		}
	}
	list_iter_free(&iter);

done:
	if (GNET_PROPERTY(download_debug) > 1) {
		g_debug("PUSH %s %u message%s on wakeup for GUID %s at %s",
			broadcast ? "broadcasted" : "sent",
			sent, plural(sent),
			guid_hex_str(server->key->guid), server_host_info(server));
	}
}

/**
 * Sleep call when we get a notification from the DHT that there are no fresh
 * push-proxy available for a given server.  All the downloads awaiting
 * a push reply are put back to sleep.
 */
static void
download_push_proxy_sleep(struct dl_server *server)
{
	list_iter_t *iter;
	pslist_t *to_sleep = NULL;
	pslist_t *sl;

	iter = list_iter_before_head(server->list[DL_LIST_RUNNING]);
	while (list_iter_has_next(iter)) {
		struct download *d = list_iter_next(iter);
		download_check(d);
		if (DOWNLOAD_IS_EXPECTING_GIV(d)) {
			/* Not moving the download out of the list over which we iterate */
			to_sleep = pslist_prepend(to_sleep, d);
		}
	}
	list_iter_free(&iter);

	/*
	 * Process recorded downloads now that we finished iterating, since
	 * that will cause them to move to the waiting list.
	 */

	PSLIST_FOREACH(to_sleep, sl) {
		struct download *d = sl->data;
		uint32 delay = GNET_PROPERTY(download_retry_timeout_delay);
		if (d->retries < GNET_PROPERTY(download_max_retries) - 1) {
			d->retries++;
		} else if (d->server->attrs & DLS_A_DHT_PUBLISH) {
			/*
			 * If server is known to publish in the DHT, then it is safe
			 * to assume that it has a stable GUID and that we can find
			 * it as soon as it comes back up.  Hence do not bring the
			 * amount of retries above the maximum so that we can keep
			 * trying.  Just double the usual timeout.
			 *		--RAM, 2010-10-06
			 */

			delay = uint32_saturate_mult(delay, 2);
		} else {
			d->retries++;
		}
		download_retry(d);	/* Updates d->timeout_delay */
		download_queue_delay(d, MAX(delay, d->timeout_delay),
			_("Requeued due to no push-proxy"));
	}

	pslist_free(to_sleep);
}

/**
 * Lookup for push proxies is finished (successful or not).
 */
void
download_proxy_dht_lookup_done(const struct guid *guid)
{
	struct dl_server *server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	server->attrs &= ~DLS_A_DHT_PROX;

	if (NULL == server->proxies || 0 == pproxy_set_count(server->proxies)) {
		route_starving_add(guid, download_got_push_route);
		download_push_proxy_sleep(server);
	} else {
		route_starving_remove(guid);
		download_push_proxy_wakeup(server, TRUE, FALSE);
	}
}

/**
 * Look for more push-proxies in the DHT.
 *
 * @return TRUE if we are looking for proxies, FALSE if there is nothing
 * to query.
 */
static bool
server_dht_query(struct download *d)
{
	struct dl_server *server = d->server;
	struct dl_server *known;

	g_assert(dl_server_valid(server));

	if (!dht_enabled())
		return FALSE;						/* No DHT, cannot look */

	if (!dht_bootstrapped())
		return TRUE;						/* Wait until bootstrapped */

	known = htable_lookup(dl_by_guid, server->key->guid);

	/* XXX BUG: if two entries have the same GUID and we free the first server
	 * XXX which removes the entry from the dl_by_guid, then known can be NULL
	 * XXX when we handle the second server...
	 * XXX MUST re-attach everything with the same GUID under the same server.
	 */

	/* g_assert(known); XXX */
	g_return_val_if_fail(known, FALSE);		/* XXX temporary */

	if (known != server && GNET_PROPERTY(download_debug))
		g_warning("query in DHT for GUID %s (%s) done for colliding %s instead",
			guid_to_string(server->key->guid),
			host_addr_port_to_string(server->key->addr, server->key->port),
			host_addr_port_to_string2(known->key->addr, known->key->port));

	if (known->attrs & DLS_A_DHT_PROX)
		return TRUE;						/* Already querying */

	known->attrs |= DLS_A_DHT_PROX;
	if (server == known)
		fi_src_status_changed(d);
	gdht_find_guid(known->key->guid, known->key->addr, known->key->port);

	return TRUE;
}

/**
 * Set/change the server's hostname.
 *
 * @return TRUE if we changed the value, FALSE otherwise.
 */
static bool
set_server_hostname(struct dl_server *server, const char *hostname)
{
	g_assert(dl_server_valid(server));
	g_assert(hostname);

	if (
		NULL == server->hostname ||
		0 != ascii_strcasecmp(server->hostname, hostname)
	) {
		if (GNET_PROPERTY(download_debug))
			g_debug("setting hostname \"%s\" for server %s",
				hostname, server_host_info(server));

		atom_str_change(&server->hostname, hostname);
		return TRUE;
	}

	return FALSE;
}

/**
 * Check whether we can safely ignore Push indication for this server,
 * identified by its GUID, IP and port.
 */
bool
download_server_nopush(const struct guid *guid,
		const host_addr_t addr, uint16 port)
{
	struct dl_server *server = get_server(guid, addr, port, FALSE);

	if (server == NULL)
		return FALSE;

	g_assert(dl_server_valid(server));

	/*
	 * Rreturns true if we already made a direct connection to this server.
	 */

	return server->attrs & DLS_A_PUSH_IGN;
}

static inline const struct sha1 *
download_get_sha1(const struct download *d)
{
	download_check(d);

	if (d->sha1) {
		/* These are atoms */
		if (d->file_info && d->file_info->sha1) {
			g_assert(d->sha1 == d->file_info->sha1);
		}
		return d->sha1;
	} else if (d->file_info) {
		return d->file_info->sha1;
	} else {
		return NULL;
	}
}

static inline const struct tth *
download_get_tth(const struct download *d)
{
	download_check(d);
	return d->file_info->tth;
}

static inline void
server_sha1_count_inc(struct dl_server *server, struct download *d)
{
	const struct sha1 *sha1;

	download_check(d);
	g_assert(server == d->server);

	sha1 = download_get_sha1(d);
	if (sha1) {
		void *value;
		uint n;

		value = htable_lookup(server->sha1_counts, sha1);
		n = GPOINTER_TO_UINT(value);
		g_assert(n < (uint) -1);
		n++;
		value = GUINT_TO_POINTER(n);
		htable_insert(server->sha1_counts, sha1, value);
	}
}

static inline void
server_sha1_count_dec(struct dl_server *server, struct download *d)
{
	const struct sha1 *sha1;

	download_check(d);
	g_assert(server == d->server);

	sha1 = download_get_sha1(d);
	if (sha1) {
		void *value;
		uint n;

		value = htable_lookup(server->sha1_counts, sha1);
		n = GPOINTER_TO_UINT(value);

		/* Counter is sometimes off, make it non-fatal -- RAM, 2006-08-29 */
		if (n == 0) {
			g_carp("BUG: no SHA1 %s for server %s, ignoring decrement",
				sha1_base32(sha1),
				host_addr_port_to_string(server->key->addr, server->key->port));
			return;
		}

		n--;
		if (n > 0) {
			value = GUINT_TO_POINTER(n);
			htable_insert(server->sha1_counts, sha1, value);
		} else {
			htable_remove(server->sha1_counts, sha1);
		}
	}
}

/**
 * Are two downloads equivalent?
 *
 * If both have a SHA-1, then they must match, otherwise both the file
 * size and name must be identical.
 */
static bool
download_eq(const void *p, const void *q)
{
	const struct download *a = p, *b = q;
	const struct sha1 *a_sha1, *b_sha1;

	if (a == b)
		return TRUE;

	a_sha1 = download_get_sha1(a);
	b_sha1 = download_get_sha1(b);
	
	if (a_sha1 || b_sha1) {
		return a_sha1 == b_sha1; /* These are atoms! */
	} else if (
		a->file_size == b->file_size &&
		(
		 	a->file_name == b->file_name ||
		 	0 == strcmp(a->file_name, b->file_name)
		)
	) {
		return TRUE;
	}

	return FALSE;
}

/**
 * Lookup in the supplied server list whether we hold a matching file entry,
 * as identified by its file name, file size and SHA1.
 */
static struct download *
server_list_lookup(const struct dl_server *server, enum dl_list idx,
	const struct sha1 *sha1, const char *file, filesize_t size)
{
	struct download *d = NULL;

	g_assert(dl_server_valid(server));
	g_assert((uint) idx < DL_LIST_SZ);		

	if (server->list[idx]) {
		static const struct download zero_key;
		struct download key = zero_key;
		void *orig_key;

		key.magic = DOWNLOAD_MAGIC;
		key.sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
		key.file_name = deconstify_pointer(file);
		key.file_size = size;

		if (list_contains(server->list[idx], &key, download_eq, &orig_key)) {
			d = orig_key;
			download_check(d);
		}
		atom_sha1_free_null(&key.sha1);
	}
	return d;
}

static list_t *
server_list_by_index(struct dl_server *server, enum dl_list idx)
{
	g_assert(dl_server_valid(server));
	g_assert((uint) idx < DL_LIST_SZ);	

	if (!server->list[idx]) {
		server->list[idx] = list_new();
	}
	return server->list[idx];
}

static void
server_list_insert_download_sorted(struct dl_server *server, enum dl_list idx,
	struct download *d)
{
	g_assert(dl_server_valid(server));
	download_check(d);

	server_sha1_count_inc(server, d);
	list_insert_sorted(server_list_by_index(server, idx), d, dl_retry_cmp);
}

static void
server_list_append_download(struct dl_server *server, enum dl_list idx,
	struct download *d)
{
	g_assert(dl_server_valid(server));
	download_check(d);

	server_sha1_count_inc(server, d);
	list_append(server_list_by_index(server, idx), d);
}

static void
server_list_prepend_download(struct dl_server *server, enum dl_list idx,
	struct download *d)
{
	g_assert(dl_server_valid(server));
	download_check(d);

	server_sha1_count_inc(server, d);
	list_prepend(server_list_by_index(server, idx), d);
}

static struct download *
server_list_head(struct dl_server *server, enum dl_list idx)
{
	g_assert(dl_server_valid(server));

	return server_list_length(server, idx) > 0 
		? list_head(server_list_by_index(server, idx))
		: NULL;
}

static void
server_list_remove_download(struct dl_server *server, enum dl_list idx,
	struct download *d)
{
	g_assert(dl_server_valid(server));
	g_assert((uint) idx < DL_LIST_SZ);		
	g_assert(server->list[idx]);
	download_check(d);

	server_sha1_count_dec(server, d);
	list_remove(server->list[idx], d);
	if (0 == server_list_length(server, idx)) {
		list_free(&server->list[idx]);
	}
}

/**
 * Check whether we already have an identical (same file, same SHA1, same host)
 * running or queued download in the server.
 *
 * @return the found active download, or NULL if the server has no such
 * download yet.
 */
static struct download *
server_has_same_download(struct dl_server *server,
	const char *file, const struct sha1 *sha1, filesize_t size)
{
	static const enum dl_list listnum[] = { DL_LIST_WAITING, DL_LIST_RUNNING };
	struct download *d;
	uint i;

	g_assert(dl_server_valid(server));

	if (sha1 && !htable_contains(server->sha1_counts, sha1)) {
		return NULL;
	}

	/*
	 * Note that we scan the WAITING downloads first, and then only
	 * the RUNNING ones.  This is because that routine can now be called
	 * from download_convert_to_urires(), where the download is actually
	 * running!
	 */

	for (i = 0; i < G_N_ELEMENTS(listnum); i++) {
		d = server_list_lookup(server, i, sha1, file, size);
		if (d) {
			download_check(d);
			g_assert(!DOWNLOAD_IS_STOPPED(d));
			return d;
		}
	}

	return NULL;
}

/**
 * Check whether we already have an identical (same file, same SHA1, same host)
 * running or queued download.
 *
 * @returns found active download, or NULL if we have no such download yet.
 */
static struct download *
has_same_download(
	const char *file, const struct sha1 *sha1, filesize_t size,
	const struct guid *guid, const host_addr_t addr, uint16 port)
{
	struct dl_server *server = get_server(guid, addr, port, FALSE);

	return server ? server_has_same_download(server, file, sha1, size) : NULL;
}

static bool
download_has_enough_active_sources(struct download *d)
{
	fileinfo_t *fi;
	unsigned n;

	download_check(d);
	fi = d->file_info;

#if 0
	/*
	 * Disabled: this is broken logic.  Indeed, near the end, when only a
	 * few small holes remain, most of the source don't get scheduled, and
	 * the few partial ones that do get a slot may not have the chunks we
	 * need, resulting in an endless catch-22.
	 *		--RAM, 2007-05-17
	 */
	if (fi->use_swarming) {
		filesize_t m = download_filesize(d) - download_filedone(d);

		/*
		 * Don't use more than one source per 16 kB because the HTTP
		 * overhead becomes significant for small chunks.
		 */
		m /= 16000;
		m = MAX(m, 1);
		n = MIN(m, GNET_PROPERTY(max_simultaneous_downloads_per_file));
	} else {
		n = 1;
	}
#else
	if (fi->use_swarming) {
		n = GNET_PROPERTY(max_simultaneous_downloads_per_file);
	} else {
		n = 1;
	}
#endif
	return UNSIGNED(fi->recvcount + fi->active_queued) >= n;
}

/**
 * Mark a download as being actively queued.
 */
void
download_actively_queued(struct download *d, bool queued)
{
	download_check(d);

	if (queued) {
		download_set_status(d, GTA_DL_ACTIVE_QUEUED);

		if (d->flags & DL_F_ACTIVE_QUEUED)		/* Already accounted for */
			return;

		d->flags |= DL_F_ACTIVE_QUEUED;
        d->file_info->active_queued++;

		g_assert(GNET_PROPERTY(dl_aqueued_count) < INT_MAX);
		gnet_prop_incr_guint32(PROP_DL_AQUEUED_COUNT);
	} else {
		if (!(d->flags & DL_F_ACTIVE_QUEUED))	/* Already accounted for */
			return;

		g_assert(GNET_PROPERTY(dl_aqueued_count) > 0);
		gnet_prop_decr_guint32(PROP_DL_AQUEUED_COUNT);

		d->flags &= ~DL_F_ACTIVE_QUEUED;
		g_assert(d->file_info->active_queued > 0);
        d->file_info->active_queued--;
	}

	file_info_changed(d->file_info);
}

/**
 * Mark download as being passively queued.
 */
static void
download_passively_queued(struct download *d, bool queued)
{
	download_check(d);

	if (queued) {
		if (d->flags & DL_F_PASSIVE_QUEUED)		/* Already accounted for */
			return;

		d->flags |= DL_F_PASSIVE_QUEUED;
		d->file_info->passive_queued++;

		g_assert(GNET_PROPERTY(dl_pqueued_count) < INT_MAX);
		gnet_prop_incr_guint32(PROP_DL_PQUEUED_COUNT);
	} else {
		if (!(d->flags & DL_F_PASSIVE_QUEUED))	/* Already accounted for */
			return;

		g_assert(GNET_PROPERTY(dl_pqueued_count) > 0);
		gnet_prop_decr_guint32(PROP_DL_PQUEUED_COUNT);

		d->flags &= ~DL_F_PASSIVE_QUEUED;
		g_assert(d->file_info->passive_queued > 0);
		d->file_info->passive_queued--;
	}

	file_info_changed(d->file_info);
}

/**
 * @returns whether the download file exists in the temporary directory.
 */
bool
download_file_exists(const struct download *d)
{
	filestat_t sb;

	download_check(d);
	return -1 != stat(download_pathname(d), &sb) && S_ISREG(sb.st_mode);
}

static void
download_requeue_all_active(const fileinfo_t *fi)
{
	pslist_t *sources, *iter;

	file_info_check(fi);

	/*
	 * Requeue all the active downloads that were referencing that file.
	 */

	sources = file_info_get_sources(fi);
	PSLIST_FOREACH(sources, iter) {
		struct download *d = iter->data;

		download_check(d);
		g_assert(d->file_info == fi);

		/*
		 * An actively queued download is counted as running, but for our
		 * purposes here, it does not matter: we're not in the process of
		 * requesting the file.  Likewise for other special states that are
		 * counted as running but are harmless here.
		 *		--RAM, 17/05/2003
		 */

		switch (d->status) {
		case GTA_DL_REMOVED:
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:	/* Will only make one request afterwards */
		case GTA_DL_CONNECTING:
		case GTA_DL_CONNECTED:
			continue;
		default:
			break;		/* go on */
		}

		if (DOWNLOAD_IS_RUNNING(d)) {
			download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);
			download_queue(d, _("Requeued due to file removal"));
		}
	}
	pslist_free_null(&sources);
}

/**
 * Remove temporary download file.
 *
 * Optionally reset the fileinfo if unlinking is successful and `reset' is
 * TRUE.  The purpose of resetting on unlink is to prevent the fileinfo
 * from being discarded at the next relaunch (we discard non-reset fileinfos
 * when the file is missing).
 */
void
download_remove_file(struct download *d, bool reset)
{
	fileinfo_t *fi;

	download_check(d);

	if (download_shutdown)
		return;

	fi = d->file_info;
	file_info_unlink(fi);
	if (reset) {
		file_info_reset(fi);
	}
	download_requeue_all_active(fi);
}

/**
 * Change all the fileinfo of downloads from `old_fi' to `new_fi'.
 *
 * All running downloads are requeued immediately, since a change means
 * the underlying file we're writing to can change.
 */
void
download_info_change_all(fileinfo_t *old_fi, fileinfo_t *new_fi)
{
	pslist_t *sources, *iter;

	file_info_check(old_fi);
	file_info_check(new_fi);

	sources = file_info_get_sources(old_fi);
	PSLIST_FOREACH(sources, iter) {
		struct download *d = iter->data;
		bool is_running;

		download_check(d);
		g_assert(d->file_info == old_fi);

		if (d->status == GTA_DL_REMOVED)
			continue;

		is_running = DOWNLOAD_IS_RUNNING(d);

		/*
		 * The following states are marked as being running, but the
		 * fileinfo structure has not yet been used to request anything,
		 * so we don't need to stop.
		 */

		switch (d->status) {
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:
		case GTA_DL_CONNECTING:
		case GTA_DL_CONNECTED:
			is_running = FALSE;
			break;
		default:
			break;
		}

		if (is_running) {
			download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);
		}
		g_assert(old_fi->refcount > 0);
		file_info_remove_source(old_fi, d, FALSE); /* Keep it around */
		file_info_add_source(new_fi, d);

		d->flags &= ~DL_F_SUSPENDED;
		if (new_fi->flags & FI_F_SUSPEND)
			d->flags |= DL_F_SUSPENDED;

		if (is_running)
			download_queue(d, _("Requeued by file info change"));
	}
	pslist_free_null(&sources);
}

/**
 * Remove all downloads to a given peer from the download queue
 * and abort all connections to peer in the active download list.
 *
 * When `unavailable' is TRUE, the downloads are marked unavailable,
 * so that they can be cleared up differently by the GUI .
 *
 * @return the number of removed downloads.
 */
int
download_remove_all_from_peer(const struct guid *guid,
	const host_addr_t addr, uint16 port, bool unavailable)
{
	struct dl_server *server[2];
	int n = 0;
	enum dl_list listnum[] = { DL_LIST_RUNNING, DL_LIST_WAITING };
	pslist_t *to_remove = NULL;
	pslist_t *sl;
	int i;
	uint j;

	/*
	 * There can be two distinct server entries for a given IP:port.
	 * One with the GUID, and one with a blank GUID.  The latter is
	 * used when we enqueue entries from the download mesh: we don't
	 * have the GUID handy at that point.
	 *
	 * NB: It is conceivable that a server could change GUID between two
	 * sessions, and therefore we may miss to remove downloads from the
	 * same IP:port.  Apart from looping throughout the whole queue,
	 * there is nothing we can do.
	 *		--RAM, 15/10/2002.
	 */

	server[0] = get_server(guid, addr, port, FALSE);
	server[1] = get_server(&blank_guid, addr, port, FALSE);

	if (server[1] == server[0])
		server[1] = NULL;

	for (i = 0; i < 2; i++) {
		if (server[i] == NULL)
			continue;

		for (j = 0; j < G_N_ELEMENTS(listnum); j++) {
			enum dl_list idx = listnum[j];
			list_iter_t *iter;
			
			iter = list_iter_before_head(server[i]->list[idx]);
			while (list_iter_has_next(iter)) {
				struct download *d;

				d = list_iter_next(iter);
				download_check(d);
				g_assert(d->status != GTA_DL_REMOVED);

				n++;
				to_remove = pslist_prepend(to_remove, d);
			}
			list_iter_free(&iter);
		}
	}

	/*
	 * We "forget" instead of "aborting"  all requested downloads: we do
	 * not want to delete the file on the disk if they selected "delete on
	 * abort".
	 * Do NOT mark the fileinfo as "discard".
	 */

	PSLIST_FOREACH(to_remove, sl) {
		struct download *d = sl->data;
		download_forget(d, unavailable);
	}

	pslist_free(to_remove);

	return n;
}

/**
 * Remove all THEX downloads for a given sha1.
 *
 * @param sha1 The SHA-1 of the file to which this THEX download belongs.
 * @param skip If not NULL, the given download is skipped. Usually the
 *             THEX download which just finished and which we still need.
 */
static void
download_remove_all_thex(const struct sha1 *sha1, const struct download *skip)
{
	struct download *next;

	if (NULL == sha1)
		return;

	/*
	 * Abort THEX downloads aimed at the given sha1.
	 */

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;

		download_check(d);
		next = hash_list_next(sl_downloads, next);

		if (d == skip)
			continue;

		if (d->thex) {
			const struct sha1 *d_sha1 = thex_download_get_sha1(d->thex);

			if (sha1_eq(sha1, d_sha1)) {
				download_forget(d, FALSE);
			}
		}
	}
}

/**
 * Change the socket RX buffer size for all the currently connected
 * downloads.
 */
void
download_set_socket_rx_size(unsigned rx_size)
{
	hash_list_iter_t *iter;

	/* This is called from settings_init() before download_init() */
	if (NULL == sl_downloads)
		return;

	iter = hash_list_iterator(sl_downloads);

	while (hash_list_iter_has_next(iter)) {
		struct download *d = hash_list_iter_next(iter);

		download_check(d);

		if (d->socket != NULL)
			socket_recv_buf(d->socket, rx_size, TRUE);
	}

	hash_list_iter_release(&iter);
}

static void
download_set_sha1(struct download *d, const struct sha1 *sha1)
{
	download_check(d);

	if (DL_LIST_INVALID != d->list_idx) {
		g_assert(d->server);
		server_sha1_count_dec(d->server, d);
	}
	atom_sha1_change(&d->sha1, sha1);
	if (DL_LIST_INVALID != d->list_idx) {
		server_sha1_count_inc(d->server, d);
	}
}

/*
 * Downloads management
 */

static void
download_add_to_list(struct download *d, enum dl_list idx)
{
	struct dl_server *server;

	download_check(d);

	server = d->server;
	g_assert(dl_server_valid(server));
	g_assert(idx != DL_LIST_INVALID);
	g_assert(d->list_idx == DL_LIST_INVALID);			/* Not in any list */

	d->list_idx = idx;

	/*
	 * The DL_LIST_WAITING list is sorted by increasing retry after.
	 */

	if (idx == DL_LIST_WAITING) {
		server_list_insert_download_sorted(server, idx, d);
	} else {
		server_list_prepend_download(server, idx, d);
	}
}

/**
 * Move download from its current list to the `idx' one.
 */
static void
download_move_to_list(struct download *d, enum dl_list idx)
{
	struct dl_server *server = d->server;
	enum dl_list old_idx = d->list_idx;

	download_check(d);

	server = d->server;
	old_idx = d->list_idx;
	g_assert(dl_server_valid(server));
	g_assert(d->list_idx != DL_LIST_INVALID);			/* In some list */
	g_assert(d->list_idx != idx);			/* Not in the target list */

	/*
	 * Global counters update.
	 */

	if (old_idx == DL_LIST_RUNNING) {
		if (DOWNLOAD_IS_ACTIVE(d))
			dl_active--;
		else {
			/*
			 * Cannot assert DOWNLOAD_IS_ESTABLISHING(d) here because of
			 * download_force_stop() which can move things in the running
			 * list to be able to forcefully stop them later.  We could be
			 * dealing with a download that is in GTA_DL_TIMEOUT_WAIT for
			 * instance and which is being reparented and spot as a duplicate.
			 * What we DO know however is that the download was put in the
			 * running list so dl_establishing was incremented...
			 *		--RAM, 2009-04-02
			 */
			g_assert(dl_establishing > 0);
			dl_establishing--;
		}
	} else if (idx == DL_LIST_RUNNING) {
		dl_establishing++;
	}

	g_assert(dl_active <= INT_MAX && dl_establishing <= INT_MAX);

	/*
	 * Local counter and list update.
	 * The DL_LIST_WAITING list is sorted by increasing retry after.
	 */

	g_assert(server_list_length(server, old_idx) > 0);
	server_list_remove_download(server, old_idx, d);

	if (idx == DL_LIST_WAITING) {
		server_list_insert_download_sorted(server, idx, d);
	} else {
		server_list_append_download(server, idx, d);
	}

	d->list_idx = idx;
}

/**
 * Clone download, resetting most dynamically allocated structures in the
 * original since they are shallow-copied to the new download.
 *
 * (This routine is used because each different download from the same host
 * will become a line in the GUI, and the GUI stores download structures in
 * ts row data, expecting a one-to-one mapping between a download and the GUI).
 */
static struct download *
download_clone(struct download *d)
{
	struct download *cd;
	fileinfo_t *fi;
	struct gnutella_socket *s = d->socket;

	download_check(d);
	g_assert(!(d->flags & (DL_F_ACTIVE_QUEUED|DL_F_PASSIVE_QUEUED)));

	/* The socket can be NULL if we're acting on a queued source */

	if (s != NULL && s->getline != NULL) {
		getline_free(s->getline);	/* No longer need this */
		s->getline = NULL;
	}

	if (d->flags & (DL_F_BROWSE | DL_F_THEX)) {
		g_assert(NULL == d->buffers);
		if (d->io_opaque != NULL) {
			io_free(d->io_opaque);
			g_assert(NULL == d->io_opaque);
		}
	} else if (NULL == d->io_opaque) {
		g_assert(d->buffers != NULL);
		g_assert(d->buffers->held == 0);		/* All data flushed */
	} else {
		io_free(d->io_opaque);		/* Cloned after error, not when receiving */
		g_assert(NULL == d->buffers);
	}

	fi = d->file_info;

	cd = download_alloc();
	*cd = *d;							/* Struct copy */
	file_info_cloned_source(fi, d, cd);	/* Replace by cloned source */

	if (s != NULL)
		socket_change_owner(cd->socket, cd);	/* Takes ownership of socket */

	cd->list_idx = DL_LIST_INVALID;
	cd->sha1 = d->sha1 ? atom_sha1_get(d->sha1) : NULL;
	cd->file_name = atom_str_get(d->file_name);
	cd->id = atom_guid_get(d->id);
	cd->uri = d->uri ? atom_str_get(d->uri) : NULL;
	cd->flags &= ~(DL_F_MUST_IGNORE | DL_F_SWITCHED |
		DL_F_FROM_PLAIN | DL_F_FROM_ERROR | DL_F_CLONED | DL_F_NO_PIPELINE);
	cd->server->refcnt++;

	if (fi->sha1 != NULL)
		download_by_sha1_add(cd);

	download_add_to_list(cd, DL_LIST_WAITING);	/* Will add SHA1 to server */

	if (download_pipelining(cd)) {
		download_pipeline_update_chunk(cd);
		if (d->flags & DL_F_MUST_IGNORE) {
			cd->flags |= DL_F_MUST_IGNORE;	/* Propagates to pipelined result */
		}
		d->rx = NULL;		/* Keep RX stack to handle pipeline result */
		d->bio = NULL;		/* I/O source kept as well */
		d->out_file = NULL;	/* Keep file opened when pipelining */
		rx_change_owner(cd->rx, cd);
		switch (cd->pipeline->status) {
		case GTA_DL_PIPE_SENDING:
			download_set_status(cd, GTA_DL_REQ_SENDING);
			break;
		case GTA_DL_PIPE_SENT:
			download_set_status(cd, GTA_DL_REQ_SENT);
			break;
		case GTA_DL_PIPE_SELECTED:
			g_assert_not_reached();
		}
	} else {
		cd->rx = NULL;
		cd->bio = NULL;			/* Recreated on each transfer */
		cd->out_file = NULL;	/* File re-opened each time */
		download_set_status(cd, GTA_DL_CONNECTED);
	}

	download_set_sha1(d, NULL);

	/*
	 * NOTE: These are explicitely prepended to avoid inconsistencies if
	 *		 we just happen to iterate forwards over these lists.
	 */
	hash_list_prepend(sl_downloads, cd);
	hash_list_prepend(sl_unqueued, cd);

	if (d->parq_dl)
		parq_dl_reparent_id(d, cd);

	if (d->cproxy != NULL)
		cproxy_reparent(d, cd);

	g_assert(d->parq_dl == NULL);	/* Cleared by parq_dl_reparent_id() */

	/*
	 * The following copied data are cleared in the child.
	 */

	cd->buffers = NULL;		/* Allocated at each new request */
	cd->thex = NULL;
	cd->browse = NULL;

	/*
	 * The following have been copied and appropriated by the cloned download.
	 * They are reset so that a download_free() on the original will not
	 * free them.
	 */

	d->socket = NULL;
	d->ranges = NULL;
	d->pipeline = NULL;
	d->flags |= DL_F_CLONED;		/* Don't persist parent download */

	return cd;
}

/**
 * Change the `retry_after' field of the host where this download runs.
 * If a non-zero `hold' is specified, make sure nothing will be scheduled
 * from this server before the next `hold' seconds.
 */
static void
download_server_retry_after(struct dl_server *server, time_t now, int hold)
{
	struct download *d;
	time_t after;

	g_assert(dl_server_valid(server));

	/*
	 * Always consider the earliest time in the future for all the downloads
	 * enqueued in the server when updating its `retry_after' field.
	 *
	 * Indeed, we may have several downloads queued with PARQ, and each
	 * download bears its own retry_after time.  But we need to know the
	 * earliest time at which we should start browsing through the downloads
	 * for a given server.
	 *		--RAM, 16/07/2003
	 */

	d = server_list_head(server, DL_LIST_WAITING);

	/*
	 * We used to required that there be something waiting for this server,
	 * but this is way too strong.  If there is something, good, use its
	 * retry_after as a basis, otherwise use the current time.
	 *
	 * This avoids crashes when we get EOF conditions for downloads at the
	 * same time we've completed the whole file and wait to attempt file
	 * verification.
	 *		--RAM, 2012-12-25
	 */

	if (d != NULL) {
		download_check(d);
		after = d->retry_after;
	} else {
		after = now;	/* Nothing waiting on server, weird! */
	}

	/*
	 * We impose a minimum of DOWNLOAD_SERVER_HOLD seconds between retries.
	 * If we have some entries passively queued, well, we have some grace time
	 * before the entry expires.  And even if it expires, we won't lose the
	 * slot.  People having 100 entries passively queued on the same host with
	 * low retry rates will have problems, but if they requested too often,
	 * they would get banned anyway.  Let the system regulate itself via chaos.
	 *		--RAM, 17/07/2003
	 */

	if (delta_time(after, now) < DOWNLOAD_SERVER_HOLD)
		after = time_advance(now, DOWNLOAD_SERVER_HOLD);

	/*
	 * If server was given a "hold" period (e.g. requests to it were
	 * timeouting) then put it on hold now and reset the holding period.
	 */

	if (hold != 0)
		after = MAX(after, time_advance(now, hold));

	if (server->retry_after != after) {
		dl_by_time_remove(server);
		server->retry_after = after;
		dl_by_time_insert(server);
	}
}

/**
 * Reclaim download's server if it is no longer holding anything.
 * If `delayed' is true, we're performing a batch free of downloads.
 */
static void
download_reclaim_server(struct download *d, bool delayed)
{
	struct dl_server *server;

	download_check(d);
	g_assert(dl_server_valid(d->server));
	g_assert(d->list_idx == DL_LIST_INVALID);

	server = d->server;
	d->server = NULL;
	g_assert(server->refcnt > 0);
	server->refcnt--;

	/*
	 * We cannot reclaim the server structure immediately if `delayed' is set,
	 * because we can be removing physically several downloads that all
	 * pointed to the same server, and which have all been removed from it.
	 * Therefore, the server structure appears empty but is still referenced.
	 *
	 * Because we split the detaching of the download from the server and
	 * the actual reclaiming, the lists can be empty but still the server
	 * can have downloads referencing it, so we don't physically free it
	 * until all of them have been detached,
	 */

	if (
		server_list_length(server, DL_LIST_RUNNING) == 0 &&
		server_list_length(server, DL_LIST_WAITING) == 0 &&
		server_list_length(server, DL_LIST_STOPPED) == 0
	) {
		if (delayed) {
			if (!(server->attrs & DLS_A_REMOVED))
				server_delay_delete(server);
		} else if (server->refcnt == 0)
			free_server(server);
	}
}

/**
 * Remove download from server.
 * Reclaim server if this was the last download held and `reclaim' is true.
 */
static void
download_remove_from_server(struct download *d, bool reclaim)
{
	struct dl_server *server;
	enum dl_list idx;

	download_check(d);
	g_assert(dl_server_valid(d->server));
	g_assert(d->list_idx != DL_LIST_INVALID);

	idx = d->list_idx;
	server = d->server;
	d->list_idx = DL_LIST_INVALID;

	g_assert(server_list_length(server, idx) > 0);
	server_list_remove_download(server, idx, d);

	if (reclaim)
		download_reclaim_server(d, FALSE);
}

/**
 * Move download from a server to another one.
 */
static void
download_reparent(struct download *d, struct dl_server *new_server)
{
	enum dl_list list_idx;
	struct download *other;

	download_check(d);
	g_assert(dl_server_valid(d->server));
	g_assert(dl_server_valid(new_server));

	/*
	 * If not stopped, make sure we do not have a duplicate (same download
	 * attached originally to two different servers).
	 */

	switch (d->list_idx) {
	case DL_LIST_STOPPED:
		/* Does not matter, it's stopped -- we'll recheck on manual resume */
		break;
	case DL_LIST_RUNNING:
		other = server_has_same_download(new_server,
			d->file_name, d->sha1, d->file_size);

		/*
		 * If duplicate found, abort the duplicate unless it is active
		 * and we are not (the "running" list contains downloads which
		 * sent a PUSH, for instance, but which are not active yet).
		 */

		if (other != NULL) {
			if (DOWNLOAD_IS_ACTIVE(d)) {
				goto stop_other;
			} else if (DOWNLOAD_IS_PARQED(d)) {
				if (DOWNLOAD_IS_ACTIVE(other)) {
					goto stop_this;
				} else if (DOWNLOAD_IS_PARQED(other)) {
					if (get_parq_dl_position(d) > get_parq_dl_position(other))
						goto stop_this;
					else
						goto stop_other;
				} else {
					goto stop_other;
				}
			} else {
				goto stop_other;
			}
		}
		break;
	case DL_LIST_WAITING:
		other = server_has_same_download(new_server,
			d->file_name, d->sha1, d->file_size);

		/*
		 * If duplicate found, do not reparent this download, just stop it.
		 */

		if (other != NULL)
			goto stop_this;
		break;
	case DL_LIST_INVALID:
	case DL_LIST_SZ:
		g_assert_not_reached();
	}

reparent:

	if (GNET_PROPERTY(download_debug)) {
		g_debug("reparenting \"%s\", moving from %s/%s to %s/%s",
			download_basename(d), guid_hex_str(download_guid(d)),
			host_addr_port_to_string(download_addr(d), download_port(d)),
			guid_to_string(new_server->key->guid),
			host_addr_port_to_string2(
				new_server->key->addr, new_server->key->port));
	}

	/*
	 * Remove download from its current server.
	 */

	list_idx = d->list_idx;			/* Save index, before removal from server */

	download_remove_from_server(d, FALSE);	/* Server reclaimed later */
	download_reclaim_server(d, TRUE);		/* Delays free if empty */
	d->server = new_server;
	d->server->refcnt++;
	d->always_push = d->always_push && !has_blank_guid(d);

	/*
	 * Insert download in new server, in the same list.
	 */

	download_add_to_list(d, list_idx);
	return;

stop_this:

	if (GNET_PROPERTY(download_debug)) {
		g_debug("stopping \"%s\" from %s/%s: "
			"duplicate in %s/%s \"%s\"",
			download_basename(d), guid_hex_str(download_guid(d)),
			host_addr_port_to_string(download_addr(d), download_port(d)),
			guid_to_string(new_server->key->guid),
			host_addr_port_to_string2(
				new_server->key->addr, new_server->key->port),
			download_basename(other));
	}

	download_force_stop(d, _("Duplicate download"));
	goto dup_found;

stop_other:

	if (GNET_PROPERTY(download_debug)) {
		g_debug("duplicate \"%s\" stopped in %s/%s",
			download_basename(d), guid_to_string(new_server->key->guid),
			host_addr_port_to_string(
				new_server->key->addr, new_server->key->port));
	}

	download_force_stop(other, _("Duplicate download"));

	/* FALL THROUGH */

dup_found:
	gnet_stats_inc_general(GNR_DUP_DOWNLOADS_IN_CONSOLIDATION);
	goto reparent;
}

/**
 * Move download from a server to another when the IP:port changed due
 * to a Location: redirection for instance, or because of a QUEUE callback.
 */
void
download_redirect_to_server(struct download *d,
	const host_addr_t addr, uint16 port)
{
	struct dl_server *server;
	struct guid old_guid;
	enum dl_list list_idx;

	download_check(d);
	g_assert(dl_server_valid(d->server));

	/*
	 * If neither the IP nor the port changed, do nothing.
	 */

	server = d->server;
	if (host_addr_equal(server->key->addr, addr) && server->key->port == port)
		return;

	/*
	 * We have no way to know the GUID of the new IP:port server, so we
	 * reuse the old one.  We must save it before removing the download
	 * from the old server.
	 */

	list_idx = d->list_idx;			/* Save index, before removal from server */

	old_guid = *download_guid(d);
	download_remove_from_server(d, TRUE);

	/*
	 * Associate to server.
	 */

	server = get_server(&old_guid, addr, port, TRUE);
	d->server = server;
	d->server->refcnt++;
	d->always_push = d->always_push && !has_blank_guid(d);

	/*
	 * Insert download in new server, in the same list.
	 */

	download_add_to_list(d, list_idx);
}

/**
 * Can we organize a resource switching on this connection we have with
 * the remote server?
 *
 * @param d			the current download
 * @param header	the returned HTTP header from the server
 *
 * @return TRUE if we can consider switching to another resource.
 */
static bool
download_switchable(struct download *d, const header_t *header)
{
	uint64 len;
	const char *buf;
	int error;

	if (!GNET_PROPERTY(dl_resource_switching))
		return FALSE;

	if (!d->keep_alive)
		return FALSE;

	buf = header_get(header, "Content-Length");
	if (!buf)
		return FALSE;

	len = parse_uint64(buf, NULL, 10, &error);
	if (error || len != 0)
		return FALSE;			/* XXX would require we set sinking up */

	if (GNET_PROPERTY(download_debug)) {
		g_debug("download \"%s\" on %s could be switchable",
			download_basename(d), download_host_info(d));
	}

	if (!download_has_pending_on_server(d, TRUE))
		return FALSE;

	if (GNET_PROPERTY(download_debug)) {
		g_debug("pending downloads found on %s, \"%s\" is switchable",
			download_host_info(d), download_basename(d));
	}

	return TRUE;
}

/**
 * Is download special?
 */
static inline bool
download_is_special(const struct download *d)
{
	return 0 != (d->flags & (DL_F_THEX | DL_F_BROWSE));
}

/**
 * Callback invoked when socket is destroyed.
 */
static void
download_socket_destroy(gnutella_socket_t *s, void *owner, const char *reason)
{
	struct download *d = owner;

	download_check(d);
	g_assert(s == d->socket);

	download_queue(d, "%s", reason);
}

/**
 * Callback invoked when socket is connected.
 */
static void
download_socket_connected(gnutella_socket_t *s, void *owner)
{
	struct download *d = owner;

	download_check(d);
	g_assert(s == d->socket);

	download_connected(d);
}

/**
 * Callback invoked when connection failed.
 */
static void
download_socket_connect_failed(gnutella_socket_t *s, void *owner,
	const char *errmsg)
{
	struct download *d = owner;

	download_check(d);
	g_assert(s == d->socket);

	(void) errmsg;

	/*
	 * Socket will be closed by download_fallback_to_push().
	 *
	 * We need to call that routine regardless of whether we are
	 * firewalled or whether the user denied pushes: that will be
	 * checked in download_push(), and there is important processing
	 * that needs to be done by the download layer.
	 */

	download_fallback_to_push(d, FALSE, FALSE);
}

/**
 * Socket-layer callbacks for downloads.
 */
static struct socket_ops download_socket_ops = {
	download_socket_connect_failed,		/* connect_failed */
	download_socket_connected,			/* connected */
	download_socket_destroy,			/* destroy */
};

/**
 * Attach socket to download on remote connections (QUEUE or GIV callbacks).
 */
void
download_attach_socket(struct download *d, gnutella_socket_t *s)
{
	download_check(d);

	if (d->socket != NULL) {			/* Paranoid, defensive programming */
		g_carp("%s(): download had non-NULL %s socket already (%s)",
			G_STRFUNC, s == d->socket ? "identical" : "distinct",
			download_basename(d));
		if (d->socket != s) {
			socket_detach_ops(d->socket);
			socket_free_null(&d->socket);
		}
	}

	/*
	 * At this stage, we already parsed the "GIV" or "QUEUE" indication from
	 * the socket, so we no longer need its line parser
	 */

	if (s->getline != NULL) {
		getline_free(s->getline);
		s->getline = NULL;
	}

	d->socket = s;
	socket_attach_ops(s, SOCK_TYPE_DOWNLOAD, &download_socket_ops, d);
}

/**
 * Switch socket of old download to new one.
 *
 * Caller must then either stop or queue the old download, as appropriate.
 *
 * @param od		the old download we're switching from
 * @param nd		the new download we're switching to
 * @param on_error	was switching consecutive to an HTTP error?
 */
void
download_switch(struct download *od, struct download *nd, bool on_error)
{
	struct gnutella_socket *s;

	download_check(od);
	download_check(nd);
	g_assert(od != nd);

	if (GNET_PROPERTY(download_debug)) {
		g_debug("switching from \"%s\" %sto \"%s\" (%.2f%%) at %s",
			download_basename(od), on_error ? "(on error) " : "",
			download_basename(nd),
			100.0 * download_total_progress(nd), download_host_info(nd));
	}

	gnet_stats_inc_general(
		on_error ? GNR_ATTEMPTED_RESOURCE_SWITCHING_AFTER_ERROR :
			GNR_ATTEMPTED_RESOURCE_SWITCHING);

	g_assert(NULL == nd->socket);

	/* FIXME: there is a fair amount of code similarity with the trailing
	 * part of download_continue(). --RAM, 2009-03-08
	 */

	/* Steal the socket because download_stop() would free it. */
	s = od->socket;
	socket_detach_ops(s);
	od->socket = NULL;

	if (s->pos > 0) {
		g_carp("%s(): clearing socket buffer of %s",
			G_STRFUNC, download_host_info(od));
	}
	s->pos = 0;

	nd->socket = s;
	socket_attach_ops(s, SOCK_TYPE_DOWNLOAD, &download_socket_ops, nd);
	nd->flags |= DL_F_SWITCHED;
	if (on_error)
		nd->flags |= DL_F_FROM_ERROR;
	if (!download_is_special(od))
		nd->flags |= DL_F_FROM_PLAIN;
}

/**
 * Switch download to another resource on the same server if we can find one
 * and issue request immediately to the new download.
 *
 * @param d		the download we need to switch from
 */
static void
download_attempt_switch(struct download *d)
{
	struct download *next;

	if (GNET_PROPERTY(download_debug)) {
		g_debug("%s(): trying to reuse connection for \"%s\" on %s",
			G_STRFUNC, download_basename(d), download_host_info(d));
	}

	next = download_pick_another(d);

	if (NULL == next) {
		if (GNET_PROPERTY(download_debug)) {
			g_debug("%s(): closing connection to %s",
				G_STRFUNC, download_host_info(d));
		}
		download_stop(d, GTA_DL_COMPLETED, _("Nothing else to switch to"));
		return;
	}

	g_assert(next != d);

	download_switch(d, next, TRUE);		/* Switching after HTTP error */
	download_stop(d, GTA_DL_COMPLETED,
		_("Switching (after error) to \"%s\""), download_basename(d));

	if (download_start_prepare(next)) {
		next->keep_alive = TRUE;		/* Was reset by _prepare() */
		download_send_request(next);
	}
}

/**
 * Vectorized version common to download_stop() and download_unavailable().
 */
void
download_stop_v(struct download *d, download_status_t new_status,
    const char *reason, va_list ap)
{
	bool store_queue = FALSE;		/* Shall we call download_store()? */
	enum dl_list list_target;
	bool verify_sha1 = FALSE;
	bool was_active = FALSE;

	download_check(d);
	file_info_check(d->file_info);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(!DOWNLOAD_IS_STOPPED(d));
	g_assert(d->status != new_status);

	if (DOWNLOAD_IS_ACTIVE(d)) {
		g_assert(d->file_info->recvcount > 0);
		g_assert(d->file_info->recvcount <= d->file_info->refcount);
		g_assert(d->file_info->recvcount <= d->file_info->lifecount);

		was_active = TRUE;

		/*
		 * If there is unflushed downloaded data, try to flush it now,
		 * unless the file is already complete.
		 */

		if (d->buffers != NULL) {
			if (FILE_INFO_COMPLETE(d->file_info)) {
				buffers_discard(d);
			} else {
				download_silent_flush(d);
				if (FILE_INFO_COMPLETE(d->file_info)) {
					/*
					 * Flushing the data we held made the file complete.
					 * We were probably the last running source and did not
					 * complete our request, hence we did not go to
					 * download_write_data() to see that the file was now
					 * complete.
					 *
					 * We need to stop this donwload first, so defer
					 * launching verification until we've completed cleanup.
					 */
					verify_sha1 = TRUE;
					new_status = GTA_DL_COMPLETED;	/* Forced */
				}
			}
			buffers_free(d);
		}

		d->file_info->recvcount--;
		d->file_info->dirty_status = TRUE;
	}

	g_assert(d->buffers == NULL);

	switch (new_status) {
	case GTA_DL_COMPLETED:
	case GTA_DL_ABORTED:
		list_target = DL_LIST_STOPPED;
		store_queue = TRUE;
		break;
	case GTA_DL_ERROR:
		list_target = DL_LIST_STOPPED;
		break;
	case GTA_DL_TIMEOUT_WAIT:
		list_target = DL_LIST_WAITING;
		break;
	default:
		g_error("unexpected new status %u !", (uint) new_status);
		return;
	}

	if (GTA_DL_COMPLETED == new_status) {
		/*
		 * Update average download speed, computing a fast EMA on the
		 * last 3 terms.  Average is initialized with the actual download
		 * rate the first time we compute it.
		 */

		time_delta_t t = delta_time(d->last_update, d->start_date);
		struct dl_server *server = d->server;

		g_assert(server != NULL);

		if (t > 0) {
			filesize_t amount =
				d->chunk.end - d->chunk.start + d->chunk.overlap;
			uint avg = amount / t;

			if (server->speed_avg == 0)
				server->speed_avg = avg;	/* First time */
			else
				server->speed_avg += (avg >> 1) - (server->speed_avg >> 1);
		}
		d->data_timeouts = 0;	/* Got a full chunk all right */

		/*
		 * Do not reset the start_date field when the dowmload is completed.
		 * The GUI is going to use this field to compute the average download
		 * speed.  And it does not matter now for this request.
		 */
	} else {
		d->start_date = 0;		/* Download no longer running */
	}

	if (reason && no_reason != reason) {
		str_vbprintf(d->error_str, sizeof(d->error_str), reason, ap);
		d->remove_msg = d->error_str;
	} else
		d->remove_msg = NULL;

	/*
	 * Disable RX stacks to stop reception and clean up I/O structures.
	 */

	if (d->browse) {
		browse_host_dl_close(d->browse);
		d->bio = NULL;		/* Was a copy via browse_host_io_source() */
	}

	if (d->thex) {
		const struct sha1 *sha1;
		fileinfo_t *fi;

		sha1 = thex_download_get_sha1(d->thex);
		fi = file_info_by_sha1(sha1);
		if (fi) {
			fi->flags &= ~FI_F_FETCH_TTH;
		}
		thex_download_close(d->thex);
		d->bio = NULL;		/* Was a copy via thex_download_io_source() */
		dualhash_remove_value(dl_thex, d->id);
	}

	if (d->rx) {
		rx_free(d->rx);
		d->bio = NULL;		/* Was a copy via rx_bio_source() */
		d->rx = NULL;
	}

	if (d->bio) {
		bsched_source_remove(d->bio);
		d->bio = NULL;
	}
	socket_free_null(&d->socket);		/* Close socket */
	file_object_release(&d->out_file);	/* Close output file */
	if (d->io_opaque) {					/* I/O data */
		io_free(d->io_opaque);
		g_assert(d->io_opaque == NULL);
	}
	if (d->req) {
		http_buffer_free(d->req);
		d->req = NULL;
	}
	if (d->cproxy) {
		cproxy_free(d->cproxy);
		d->cproxy = NULL;
	}

	/* Don't clear ranges if simply queuing, or if completed */

	if (d->ranges) {
		switch (new_status) {
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			http_rangeset_free_null(&d->ranges);
			break;
		default:
			break;
		}
	}

	if (new_status == GTA_DL_COMPLETED) {
		browse_host_dl_free(&d->browse);
		thex_download_free(&d->thex);
	}

	if (d->list_idx != list_target)
		download_move_to_list(d, list_target);

	/* Register the new status, and update the GUI if needed */

	download_set_status(d, new_status);
	d->last_update = tm_time();

	if (store_queue) {
		download_dirty = TRUE;		/* Refresh list, in case we crash */
	}

	file_info_clear_download(d, FALSE);
	download_pipeline_free_null(&d->pipeline);
	file_info_changed(d->file_info);
	d->flags &= ~(DL_F_CHUNK_CHOSEN | DL_F_SWITCHED | DL_F_REPLIED |
		DL_F_FROM_PLAIN | DL_F_FROM_ERROR | DL_F_NO_PIPELINE);
	download_actively_queued(d, FALSE);

	gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT, count_running_downloads());
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);

	/*
	 * If the download was active and we have not completed the chunk, then
	 * we abruptly stopped and therefore we need to update the list of live
	 * chunks in the file.
	 *
	 * We cleared the DL_F_REPLIED flag above to make sure this source is no
	 * longer considered to determine the live chunks.
	 */

	if (was_active && new_status != GTA_DL_COMPLETED)
		fi_src_ranges_changed(d);

	/*
	 * If by stopping this download we completed the file, launch SHA1
	 * verification.
	 */

	if (verify_sha1) {
		download_verify_sha1(d);
	}
}

/**
 * Remove download from queue.
 * It is put in a state where it can be stopped if necessary.
 *
 * When ``removing'' is TRUE, we're called from download_remove() and
 * therefore know we're not unqueuing to schedule the download.
 */
static void
download_unqueue(struct download *d, bool removing)
{
	download_check(d);
	g_assert(DOWNLOAD_IS_QUEUED(d));
	g_assert(GNET_PROPERTY(dl_queue_count) > 0);

	gnet_prop_decr_guint32(PROP_DL_QUEUE_COUNT);

	if (d->flags & DL_F_REPLIED) {
		g_assert(GNET_PROPERTY(dl_qalive_count) > 0);
		gnet_prop_decr_guint32(PROP_DL_QALIVE_COUNT);
	}

	if (!removing) {
		hash_list_prepend(sl_unqueued, d);
		/* Allow download to be stopped, if necessary */
		download_set_status(d, GTA_DL_CONNECTING);
	}
}

/**
 * Stop an active download, close its socket and its data file descriptor.
 */
void
download_stop(struct download *d,
	download_status_t new_status, const char * reason, ...)
{
	va_list args;

	download_check(d);
	d->unavailable = FALSE;

	va_start(args, reason);
	download_stop_v(d, new_status, reason, args);
	va_end(args);
}

/**
 * Same as download_stop() but if the connection was kept alive,
 * consider whether we could not switch to another download on that server.
 *
 * @param d				the download (with d->keep_alive correctly set)
 * @param header		the reply headers, to get at the Content-Length
 * @param reason		the reason for stopping, followed by arguments
 */
static void
download_stop_switch(struct download *d, const header_t *header,
	const char * reason, ...)
{
	struct download *cd = NULL;
	va_list args;

	download_check(d);
	d->unavailable = FALSE;

	if (download_switchable(d, header)) {
		download_actively_queued(d, FALSE);
		cd = download_clone(d);
	}

	va_start(args, reason);
	download_stop_v(d, GTA_DL_ERROR, reason, args);
	va_end(args);

	if (cd != NULL)
		download_attempt_switch(cd);
}

/**
 * Forcefully stop a download, whether active or queued.
 */
static void
download_force_stop(struct download *d, const char * reason, ...)
{
	va_list args;

	download_check(d);

	g_return_if_fail(d->list_idx != DL_LIST_STOPPED);

	d->unavailable = TRUE;		/* Want it removed from the GUI */

	if (DOWNLOAD_IS_QUEUED(d))
		download_unqueue(d, FALSE);

	/* So we may safely call download_stop_v() */
	if (d->list_idx != DL_LIST_RUNNING)
		download_move_to_list(d, DL_LIST_RUNNING);

	va_start(args, reason);
	download_stop_v(d, GTA_DL_ERROR, reason, args);
	va_end(args);
}

/**
 * Like download_stop(), but flag the download as "unavailable".
 */
static void
download_unavailable(struct download *d, download_status_t new_status,
	const char * reason, ...)
{
	va_list args;

	download_check(d);
	d->unavailable = TRUE;

	va_start(args, reason);
	download_stop_v(d, new_status, reason, args);
	va_end(args);
}

/**
 * Update the status string of a queued download.
 *
 * We add the time at which the queuing occurred, plus PFS indication if
 * the source is a partial one.
 *
 * This string is meant to be displayed in the GUI, hence the care taken
 * to make sure the result is in the proper encoding.
 */
static void
download_queue_update_status(struct download *d)
{
	char event[80];
	size_t rw;

	/* Append times of event */
	time_locale_to_string_buf(tm_time(), event, sizeof event);
	rw = strlen(d->error_str);
	rw += str_bprintf(&d->error_str[rw], sizeof d->error_str - rw,
		_(" at %s"), lazy_locale_to_ui_string(event));

	/* Append PFS indication if needed */
	if (download_is_partial(d)) {
		str_bprintf(&d->error_str[rw], sizeof d->error_str - rw,
			" <PFS %4.02f%%>", d->ranges_size * 100.0 / download_filesize(d));
	}
}

/**
 * The vectorized (message-wise) version of download_queue().
 */
static void
download_queue_v(struct download *d, const char *fmt, va_list ap)
{
	download_check(d);
	file_info_check(d->file_info);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->file_info->refcount > 0);
	g_assert(d->file_info->lifecount <= d->file_info->refcount);
	g_assert(d->sha1 == NULL || d->file_info->sha1 == d->sha1);

	/* Non-fatal bugs if they occur -- simply ignore queuing request */
	g_return_if_fail(!DOWNLOAD_IS_VERIFYING(d));
	g_return_if_fail(!DOWNLOAD_IS_MOVING(d));

	/*
	 * We must use the arguments before possibly calling download_retry(),
	 * as the extracted HTTP status lies in the socket's buffer that will
	 * be freed then.
	 *
	 * But we'll only know the exact rescheduling information after
	 * download_retry() has been called, so we must split the work.
	 *		--RAM, 2007-09-09
	 */

	if (fmt) {
		str_vbprintf(d->error_str, sizeof d->error_str, fmt, ap);
	} else {
		g_strlcpy(d->error_str, "", sizeof d->error_str);
	}

	if (DOWNLOAD_IS_RUNNING(d)) {
		download_retry(d);					/* Will call download_stop() */

		/*
		 * When coming back from download_retry(), we are either in the
		 * GTA_DL_TIMEOUT_WAIT status or in the GTA_DL_VERIFY_WAIT status,
		 * the latter being caused by download_stop() noticing that the
		 * file is now complete.
		 */

		if (d->status != GTA_DL_TIMEOUT_WAIT) {
			g_soft_assert(GTA_DL_VERIFY_WAIT == d->status);
			goto not_running;
		}
	} else {
		file_info_clear_download(d, TRUE);	/* Also done by download_stop() */
	}

	download_queue_update_status(d);

	/*
	 * Since download_stop() can change "d->remove_msg", update it now.
	 */

	d->flags &= ~(DL_F_MUST_IGNORE | DL_F_SWITCHED |
		DL_F_FROM_PLAIN | DL_F_FROM_ERROR);
	d->remove_msg = fmt ? d->error_str: NULL;
	download_set_status(d, d->parq_dl ? GTA_DL_PASSIVE_QUEUED : GTA_DL_QUEUED);
	fi_src_status_changed(d);

	g_assert(d->socket == NULL);

	if (d->list_idx != DL_LIST_WAITING)		/* Timeout wait is in "waiting" */
		download_move_to_list(d, DL_LIST_WAITING);

	gnet_prop_incr_guint32(PROP_DL_QUEUE_COUNT);
	if (d->flags & DL_F_REPLIED) {
		gnet_prop_incr_guint32(PROP_DL_QALIVE_COUNT);
	}

	/*
	 * Removing the download from the sl_unqueued list since it is no
	 * longer in a "running" state.
	 */

not_running:
	hash_list_remove(sl_unqueued, d);

	if (GNET_PROPERTY(download_debug)) {
		g_debug("re-queued download \"%s\" (%s) at %s: %s",
			download_basename(d), download_status_to_string(d),
			download_host_info(d), fmt ? d->error_str : "<no reason>");
	}
}

/**
 * Put download into queue.
 */
void
download_queue(struct download *d, const char *fmt, ...)
{
	va_list args;

	download_check(d);

	va_start(args, fmt);
	download_queue_v(d, fmt, args);
	va_end(args);
}

/**
 * Freeze the scheduling queue. Multiple freezing requires
 * multiple thawing.
 */
void
download_freeze_queue(void)
{
	g_return_if_fail(GNET_PROPERTY(download_queue_frozen) < (uint32)-1);
	gnet_prop_incr_guint32(PROP_DOWNLOAD_QUEUE_FROZEN);
}

/**
 * Thaw the scheduling queue. Multiple freezing requires
 * multiple thawing.
 */
void
download_thaw_queue(void)
{
	g_return_if_fail(GNET_PROPERTY(download_queue_frozen) > 0);
	gnet_prop_decr_guint32(PROP_DOWNLOAD_QUEUE_FROZEN);
}

/**
 * Test whether download queue is frozen.
 */
bool
download_queue_is_frozen(void)
{
	return GNET_PROPERTY(download_queue_frozen) > 0;
}

/**
 * Common vectorized code for download_queue_delay() and download_queue_hold().
 */
static void
download_queue_hold_delay_v(struct download *d,
	int delay, time_t hold,
	const char *fmt, va_list ap)
{
	time_t now = tm_time();

	download_check(d);

	/*
	 * Must update `retry_after' before enqueuing, since the "waiting" list
	 * is sorted by increasing retry_after for a given server.
	 */

	d->last_update = now;
	d->retry_after = time_advance(now, delay);

	download_queue_v(d, fmt, ap);
	download_server_retry_after(d->server, now, hold);
}

/**
 * Put download back to queue, but don't reconsider it for starting
 * before the next `delay' seconds. -- RAM, 03/09/2001
 */
static void
download_queue_delay(struct download *d, uint32 delay, const char *fmt, ...)
{
	va_list args;

	download_check(d);

	va_start(args, fmt);
	download_queue_hold_delay_v(d, (time_t) delay, 0, fmt, args);
	va_end(args);
}

/**
 * Same as download_queue_delay() but if the connection was kept alive,
 * consider whether we could not switch to another download on that server.
 *
 * @param d			the download (with d->keep_alive correctly set)
 * @param header	the reply headers, to get at the Content-Length
 * @param delay		the delay in seconds we wish to impose to this download
 * @param fmt		message to display, followed by arguments
 */
static void
download_queue_delay_switch(struct download *d, const header_t *header,
	uint32 delay, const char *fmt, ...)
{
	struct download *cd = NULL;
	va_list args;

	download_check(d);

	if (download_switchable(d, header))
		cd = download_clone(d);

	va_start(args, fmt);
	download_queue_hold_delay_v(d, (time_t) delay, 0, fmt, args);
	va_end(args);

	if (cd)
		download_attempt_switch(cd);
}

/**
 * Same as download_queue_delay(), but make sure we don't consider
 * scheduling any currently queued download to this server before
 * the holding delay.
 */
static void
download_queue_hold(struct download *d, uint32 hold, const char *fmt, ...)
{
	va_list args;

	download_check(d);

	va_start(args, fmt);
	download_queue_hold_delay_v(d, (time_t) hold, (time_t) hold, fmt, args);
	va_end(args);
}

/**
 * Iterator callback to send a HEAD ping.
 */
static void
send_head_ping(void *key, void *data)
{
	gnet_host_t *host = key;
	struct download *d = data;

	download_check(d);

	vmsg_send_head_ping(d->file_info->sha1,
		gnet_host_get_addr(host), gnet_host_get_port(host),
		download_guid(d));

	d->head_ping_sent = tm_time();
}

/**
 * Send a HEAD Ping vendor message to node to get alternate sources via
 * UDP since we're not going to issue an HTTP request right now.
 */
static void
download_send_head_ping(struct download *d)
{
	time_t now = tm_time();
	time_delta_t delay;

	download_check(d);
	file_info_check(d->file_info);
	g_assert(d->server);

	if (download_queue_is_frozen())
		return;

	if (download_is_special(d))
		return;

	if (NULL == d->file_info->sha1 || !d->file_info->use_swarming)
		return;

	if (
		!udp_active() ||
		GNET_PROPERTY(is_firewalled) ||
		GNET_PROPERTY(is_udp_firewalled)
	)
		return;

	/*
	 * Increase the ping delay quadratically with the number of alive sources.
	 */
	delay = d->file_info->lifecount / 256;
	delay = MIN(delay, 512);
	delay *= delay;
	delay = MAX(DOWNLOAD_PING_DELAY, delay);

	if (delta_time(now, d->head_ping_sent) < delay)
		return;

	if (d->always_push) {
		/*
		 * Requires a PUSH: send the HEAD Ping to all the HTTP proxies.
		 */

		g_assert(!has_blank_guid(d));

		if (d->server->proxies != NULL) {
			pproxy_set_foreach(d->server->proxies, send_head_ping, d);
		}
	} else {
		/*
		 * Not firewalled, just send direct message to the server.
		 */

		vmsg_send_head_ping(d->file_info->sha1,
			download_addr(d), download_port(d), NULL);
		d->head_ping_sent = now;
	}
}

/**
 * Send a HEAD Ping to all the downloads in the list.
 */
static void
download_list_send_head_ping(list_t *list)
{
	list_iter_t *iter;

	if (
		!udp_active() ||
		GNET_PROPERTY(is_firewalled) ||
		GNET_PROPERTY(is_udp_firewalled)
	)
		return;

	iter = list_iter_before_head(list);
	while (list_iter_has_next(iter)) {
		struct download *d;

		d = list_iter_next(iter);
		download_send_head_ping(d);
	}
	list_iter_free(&iter);
}

/**
 * Invalidate improper fileinfo for the download, and get new one.
 *
 * This usually happens when we discover the SHA1 of the file on the remote
 * server, and see that it does not match the one for the associated file on
 * disk, as described in `file_info'.
 */
static void
download_info_reget(struct download *d)
{
	fileinfo_t *fi;
	bool file_size_known;

	download_check(d);
	
	fi = d->file_info;
	g_assert(fi);
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	if (fi->flags & FI_F_TRANSIENT)
		return;

	file_info_clear_download(d, TRUE);			/* `d' might be running */
	download_pipeline_free_null(&d->pipeline);
	file_size_known = fi->file_size_known;		/* This should not change */

	if (d->file_info->sha1 != NULL)
		download_by_sha1_remove(d);
	file_info_remove_source(fi, d, FALSE);		/* Keep it around for others */

	fi = file_info_get(d->file_name, GNET_PROPERTY(save_file_path),
			d->file_size, d->sha1, file_size_known);

	g_return_if_fail(fi);

	file_info_add_source(fi, d);
	if (d->file_info->sha1 != NULL)
		download_by_sha1_add(d);

	d->flags &= ~(DL_F_SUSPENDED | DL_F_PAUSED);
	if (fi->flags & FI_F_SUSPEND)
		d->flags |= DL_F_SUSPENDED;
	if (fi->flags & FI_F_PAUSED)
		d->flags |= DL_F_PAUSED;
}

/**
 * Mark all downloads that point to the file_info struct as "suspended" if
 * `suspend' is TRUE, or clear that mark if FALSE.
 */
static void
queue_suspend_downloads_with_file(fileinfo_t *fi, bool suspend)
{
	pslist_t *sources, *iter;

	file_info_check(fi);

	sources = file_info_get_sources(fi);
	PSLIST_FOREACH(sources, iter) {
		struct download *d = iter->data;

		download_check(d);
		g_assert(d->file_info == fi);

		switch (d->status) {
		case GTA_DL_REMOVED:
		case GTA_DL_COMPLETED:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_MOVING:
			continue;
		case GTA_DL_DONE:		/* We want to be able to "un-suspend" */
			break;
		default:
			break;
		}

		if (suspend) {
			if (DOWNLOAD_IS_RUNNING(d)) {
				/*
				 * Try to not lose a valid slot: if we can ignore the incoming
				 * data to later switch to another resource, let's do so instead
				 * of severing the connection.
				 */

				if (download_has_pending_on_server(d, FALSE)) {
					if (DOWNLOAD_IS_ESTABLISHING(d)) {
						d->flags |= DL_F_MUST_IGNORE;
					} else if (download_can_ignore(d)) {
						gnet_stats_inc_general(
							GNR_IGNORING_TO_PRESERVE_CONNECTION);
					} else {
						download_queue(d, _("Suspended (SHA1 checking)"));
					}
				} else
					download_queue(d, _("Suspended (SHA1 checking)"));
			}
			d->flags |= DL_F_SUSPENDED;		/* Can no longer be scheduled */
		} else {
			d->flags &= ~DL_F_SUSPENDED;
		}
	}
	pslist_free_null(&sources);

	if (suspend)
		fi->flags |= FI_F_SUSPEND;
	else
		fi->flags &= ~FI_F_SUSPEND;
}

/**
 * Freeing a download cannot be done simply, because it might happen when
 * we are traversing the `sl_downloads' or `sl_unqueued' lists.
 *
 * Therefore download_free() marks the download as "removed" and frees some
 * of the memory used, but does not reclaim the download structure yet, nor
 * does it remove it from the lists.
 *
 * The "freed" download is marked GTA_DL_REMOVED and is put into the
 * `sl_removed' list where it will be reclaimed later on via
 * download_free_removed().
 */
bool
download_remove(struct download *d)
{
	download_check(d);
	g_assert(d->status != GTA_DL_REMOVED);		/* Not already freed */

	/*
	 * Make sure download is not used by a background task
	 *		--JA 2003-10-25
	 */

	if (!download_shutdown) {
		switch (d->status) {
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_MOVING:
			if (GNET_PROPERTY(download_debug)) {
				g_carp("%s(): skipping \"%s\", status=%s",
					G_STRFUNC, download_basename(d),
					download_status_to_string(d));
			}
			return FALSE;
		default:
			break;
		}
	}

	if (DOWNLOAD_IS_QUEUED(d))
		download_unqueue(d, TRUE);

	/*
	 * Abort running download (which will decrement the lifecount), otherwise
	 * make sure we decrement it here (e.g. if the download was queued).
	 */

	if (DOWNLOAD_IS_RUNNING(d)) {
		download_stop(d, GTA_DL_ABORTED, no_reason);
	}	

	g_assert(d->io_opaque == NULL);
	g_assert(d->buffers == NULL);

	if (d->browse) {
		g_assert(d->flags & DL_F_BROWSE);
		browse_host_dl_free(&d->browse);
	}
	if (d->thex) {
		g_assert(d->flags & DL_F_THEX);
		/* In case download_stop() is not called, untie association */
		dualhash_remove_value(dl_thex, d->id);
		thex_download_free(&d->thex);
	}

	download_set_sha1(d, NULL);
	if (d->file_info->sha1 != NULL)
		download_by_sha1_remove(d);

	http_rangeset_free_null(&d->ranges);

	if (d->req) {
		http_buffer_free(d->req);
		d->req = NULL;
	}

	/*
	 * Let parq remove and free its allocated memory
	 *			-- JA, 18/4/2003
	 */
	parq_dl_remove(d);

	download_remove_from_server(d, FALSE);
	download_set_status(d, GTA_DL_REMOVED);

	atom_str_free_null(&d->file_name);
	atom_str_free_null(&d->uri);

	file_info_remove_source(d->file_info, d, FALSE); /* Keep fileinfo around */

	download_check(d);
	sl_removed = pslist_prepend(sl_removed, d);

	/* download structure will be freed in download_free_removed() */
	return TRUE;
}


/**
 * Removes all downloads that point to the file_info struct.
 * If `skip' is non-NULL, that download is skipped.
 */
static void
queue_remove_downloads_with_file(fileinfo_t *fi, struct download *skip)
{
	pslist_t *sources, *iter;

	file_info_check(fi);

	sources = file_info_get_sources(fi);
	PSLIST_FOREACH(sources, iter) {
		struct download *d = iter->data;

		download_check(d);
		g_assert(d->file_info == fi);

		if (d == skip)
			continue;

		switch (d->status) {
		case GTA_DL_REMOVED:
		case GTA_DL_COMPLETED:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_MOVING:
		case GTA_DL_DONE:
		case GTA_DL_IGNORING:
			continue;
		default:
			break;
		}

		download_remove(d);
	}
	pslist_free_null(&sources);
}


/**
 * Check whether download should be ignored, and stop it immediately if it is.
 *
 * @returns whether download was stopped (i.e. if it must be ignored).
 */
static bool
download_ignore_requested(struct download *d)
{
	enum ignore_val reason = IGNORE_FALSE;
	fileinfo_t *fi;

	download_check(d);
	fi = d->file_info;

	/*
	 * Reject if we're trying to download from ourselves (could happen
	 * if someone echoes back our own alt-locs to us with PFSP).
	 */

	if (!(SOCK_F_FORCE & d->cflags)) {
		if (is_my_address_and_port(download_addr(d), download_port(d))) {
			reason = IGNORE_OURSELVES;
		} else if (hostiles_is_bad(download_addr(d))) {
			reason = IGNORE_HOSTILE;
		} else if (ctl_limit(download_addr(d), CTL_D_OUTGOING)) {
			reason = IGNORE_LIMIT;
		}
	}

	if (reason == IGNORE_FALSE)
		reason = ignore_is_requested(download_basename(d), fi->size, fi->sha1);

	if (reason != IGNORE_FALSE) {
		const char *s_reason;
		
		s_reason = ignore_reason_to_string(reason);
		g_assert(s_reason);
		
		download_stop(d, GTA_DL_ERROR, _("Ignoring requested (%s)"), s_reason);

		/*
		 * If we're ignoring this file, make sure we don't keep any
		 * track of it on disk: dispose of the fileinfo when the last
		 * reference will be removed, remove all known downloads from the
		 * queue and delete the file (if not complete, or it could be in
		 * the process of being moved).
		 */

		switch (reason) {
		case IGNORE_HOSTILE:
		case IGNORE_OURSELVES:
		case IGNORE_LIMIT:
			break;
		case IGNORE_SHA1:
		case IGNORE_SPAM:
		case IGNORE_LIBRARY:
		case IGNORE_NAMESIZE:
			file_info_set_discard(d->file_info, TRUE);
			queue_remove_downloads_with_file(fi, d);
			if (!FILE_INFO_COMPLETE(fi)) {
				download_remove_file(d, FALSE);
			}
			break;
		case IGNORE_FALSE:
			g_assert_not_reached();
		}
		
		return TRUE;
	}

	return FALSE;
}

/**
 * Setup the download structure with proper range offset, and check that the
 * download is not otherwise completed.
 *
 * @returns TRUE if we may continue with the download, FALSE if it has been
 * stopped due to a problem.
 */
bool
download_start_prepare_running(struct download *d)
{
	fileinfo_t *fi;

	/*
	 * Do NOT use g_return_val_if_fail(blah, FALSE) in this routine.
	 * It MUST be g_assert() because before returning FALSE, some
	 * cleanup would be necessary to move back the download to the queue.
	 *
	 * Also if some of the assertions here are false, there is an important
	 * bug we need to tackle.
	 */

	download_check(d);
	file_info_check(d->file_info);
	fi = d->file_info;

	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->list_idx == DL_LIST_RUNNING);
	g_assert(fi->lifecount > 0);

	/* Most common state if we succeed */
	if (!download_pipelining(d)) {
		download_set_status(d, GTA_DL_CONNECTED);
	}

	/*
	 * If we were asked to ignore this download, abort now.
	 */

	if (download_ignore_requested(d))
		return FALSE;

	/*
	 * Even though we should not schedule a "suspended" download, we could
	 * be asked via a user-event to start such a download.
	 */

	if (d->flags & DL_F_SUSPENDED) {
		download_queue(d, _("Suspended (SHA1 checking)"));
		return FALSE;
	}

	if (d->flags & DL_F_PAUSED) {
		download_queue(d, _("Paused"));
		return FALSE;
	}

	/*
	 * If the file already exists, and has less than `download_overlap_range'
	 * bytes, we restart the download from scratch.	Otherwise, we request
	 * that amount before the resuming point.
	 * Later on, in download_write_data(), and as soon as we have read more
	 * than `download_overlap_range' bytes, we'll check for a match.
	 *		--RAM, 12/01/2002
	 */

	d->chunk.start = 0;		/* We're setting it here only if not swarming */
	d->keep_alive = FALSE;	/* Until proven otherwise by server's reply */
	d->got_giv = FALSE;		/* Don't know yet, assume no GIV */

	if (d->socket == NULL)
		d->served_reqs = 0;		/* No request served yet, since not connected */

	d->flags &= ~DL_F_OVERLAPPED;		/* Clear overlapping indication */
	d->flags &= ~DL_F_SHRUNK_REPLY;		/* Clear server shrinking indication */

	/*
	 * If this file is swarming, the overlapping size and skipping offset
	 * will be determined before making the requst, in download_pick_chunk().
	 *		--RAM, 22/08/2002.
	 *
	 * Don't use any overlap when we have the TTH for the file: if we already
	 * got bad data, resuming mismatch could kill a source whereas we can fix
	 * the bad areas later on anyway.
	 *		--RAM, 2010-11-04
	 */

	if (!fi->use_swarming) {
		if (fi->done > GNET_PROPERTY(download_overlap_range)) {
			d->chunk.start = fi->done;	/* Not swarming => file has no holes */
		}
		d->chunk.overlap =
			(d->chunk.start == 0 ||
				d->chunk.size <= d->chunk.start || download_get_tth(d))
			? 0
			: GNET_PROPERTY(download_overlap_range);

		g_assert(d->chunk.overlap == 0 || d->chunk.start > d->chunk.overlap);
	}

	d->last_update = tm_time();

	/*
	 * Is there anything to get at all?
	 */

	if (FILE_INFO_COMPLETE(fi)) {
		download_stop(d, GTA_DL_ERROR, _("Nothing more to get"));
		download_verify_sha1(d);
		return FALSE;
	}

	return TRUE;
}

/**
 * Make download a "running" one (in running list, unqueued), then call
 * download_start_prepare_running().
 *
 * @returns TRUE if we may continue with the download, FALSE if it has been
 * stopped due to a problem.
 */
bool
download_start_prepare(struct download *d)
{
	download_check(d);
	g_assert(d->list_idx != DL_LIST_RUNNING);	/* Not already running */

	/*
	 * Updata global accounting data.
	 */

	download_move_to_list(d, DL_LIST_RUNNING);

	/*
	 * If the download is in the queue, we remove it from there.
	 */

	if (DOWNLOAD_IS_QUEUED(d))
		download_unqueue(d, FALSE);

	/*
	 * Reset flags that must be cleared only once per session, i.e. when
	 * we start issuing requests for a queued download, or after we cloned
	 * a completed download.
	 *
	 * Since download_start_prepare_running() is called from download_request(),
	 * we must reset DL_F_SUNK_DATA here, since we want to sink only ONCE
	 * per session.
	 */

	d->flags &= ~DL_F_SUNK_DATA;		/* Restarting, nothing sunk yet */

	/*
	 * download_start_prepare_running() promises that it will dispose of
	 * the download properly if it returns FALSE (e.g. moving it back to
	 * the waiting list).
	 */

	return download_start_prepare_running(d);
}

/**
 * Pick a one random byte chunk within the file.
 *
 * @param d			the download source
 * @param chunk		where the selected chunk information is written to
 *
 * @returns TRUE (meaning we can continue with the download)
 */
static bool
download_pick_random_byte(struct download *d, struct dl_chunk *chunk)
{
	chunk->start = get_random_file_offset(download_filesize(d));
	chunk->size = 1;
	chunk->end = chunk->start + 1;
	chunk->overlap = 0;

	return TRUE;
}

/**
 * Called for swarming downloads when we are connected to the remote server,
 * but before making the request, to pick up a chunk for downloading.
 *
 * @param d			the download source
 * @param chunk		where the selected chunk information is written to
 * @param may_stop	TRUE if we may stop the download when no chunk available
 *
 * @returns TRUE if we can continue with the download, FALSE if no chunk
 * was selected and download was stopped (if allowed).
 */
static bool
download_pick_chunk(struct download *d,
	struct dl_chunk *chunk, bool may_stop)
{
	enum dl_chunk_status status;
	filesize_t from, to;

	download_check(d);
	g_assert(d->file_info->use_swarming);

	chunk->overlap = 0;
	d->last_update = tm_time();

	/*
	 * If we're going to ignore the data we read, just ask for 1 byte.
	 */

	if (d->flags & DL_F_MUST_IGNORE)
		return download_pick_random_byte(d, chunk);

	status = file_info_find_hole(d, &from, &to);

	switch (status) {
	case DL_CHUNK_EMPTY:
		chunk->start = from;
		chunk->end = to;
		chunk->size = to - from;

		/*
		 * Don't use overlaps if we got the TTH already.
		 *		--RAM, 2010-11-04
		 */

		if (
			NULL == download_get_tth(d) &&
			from > GNET_PROPERTY(download_overlap_range) &&
			file_info_chunk_status(d->file_info,
				from - GNET_PROPERTY(download_overlap_range),
				from) == DL_CHUNK_DONE
		)
			chunk->overlap = GNET_PROPERTY(download_overlap_range);
		break;
	case DL_CHUNK_BUSY:
		if (may_stop) {
			download_queue_delay(d, 10, _("Waiting for a free chunk"));
		}
		return FALSE;
	case DL_CHUNK_DONE:
		if (may_stop) {
			download_stop(d, GTA_DL_ERROR, _("No more gaps to fill"));
			queue_remove_downloads_with_file(d->file_info, d);
		}
		return FALSE;
	}

	g_assert(chunk->overlap == 0 || chunk->start > chunk->overlap);

	return TRUE;
}

/**
 * Pickup a range we don't have yet from the available ranges.
 *
 * @param d			the download source
 * @param chunk		where the selected chunk information is written to
 *
 * @returns TRUE if we selected a chunk, FALSE if we can't select a chunk
 * (e.g. we have everything the remote server makes available).
 */
static bool
download_pick_available(struct download *d, struct dl_chunk *chunk)
{
	filesize_t from, to;

	download_check(d);
	g_assert(d->ranges != NULL);

	chunk->overlap = 0;
	d->last_update = tm_time();

	/*
	 * If we're going to ignore the data we read, just ask for 1 byte.
	 */

	if (d->flags & DL_F_MUST_IGNORE)
		return download_pick_random_byte(d, chunk);

	if (!file_info_find_available_hole(d, d->ranges, &from, &to)) {
		if (GNET_PROPERTY(download_debug) > 3)
			g_debug("PFSP no interesting chunks from %s for \"%s\", "
				"available was: %s",
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_basename(d), http_rangeset_to_string(d->ranges));

		return FALSE;
	}

	/*
	 * We found a chunk that the remote end has and which we miss.
	 */

	chunk->start = from;
	chunk->end = to;
	chunk->size = to - from;

	/*
	 * Maybe we can do some overlapping check if the remote server has
	 * some data before that chunk and we also have the corresponding
	 * range.
	 *
	 * Don't use overlaps if we got the TTH already. --RAM, 2011-03-23
	 */

	if (
		NULL == download_get_tth(d) &&
		from > GNET_PROPERTY(download_overlap_range) &&
		file_info_chunk_status(d->file_info,
			from - GNET_PROPERTY(download_overlap_range),
			from) == DL_CHUNK_DONE &&
		http_rangeset_contains(d->ranges,
			from - GNET_PROPERTY(download_overlap_range),
			from - 1)
	)
		chunk->overlap = GNET_PROPERTY(download_overlap_range);

	if (GNET_PROPERTY(download_debug) > 3)
		g_debug("PFSP selected %s-%s (overlap=%u) "
			"from %s for \"%s\", available was: %s",
			uint64_to_string(from), uint64_to_string2(to - 1), chunk->overlap,
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_basename(d), http_rangeset_to_string(d->ranges));

	return TRUE;
}

/**
 * Indicates that this download source is not good enough for us: it is either
 * non-connectible, does not allow resuming, etc...  Remove it from the mesh.
 */
static void
download_bad_source(struct download *d)
{
	download_check(d);
	download_passively_queued(d, FALSE);

	if (!d->always_push && d->sha1 && !d->uri)
		dmesh_remove(d->sha1, download_addr(d), download_port(d),
			d->record_index, d->file_name);
}

/**
 * Establish asynchronous connection to remote server.
 *
 * @returns connecting socket.
 */
static struct gnutella_socket *
download_connect(struct download *d)
{
	struct dl_server *server;
	uint16 port;
	uint32 tls = GNET_PROPERTY(tls_enforce) ? SOCK_F_TLS : 0;
	gnutella_socket_t *s;

	download_check(d);

	server = d->server;
	g_assert(dl_server_valid(server));

	port = download_port(d);

	d->flags &= ~DL_F_DNS_LOOKUP;

	/*
	 * If they have requested that the next connection attempt be done
	 * via TLS, force a TLS connection.
	 */

	if (d->flags & DL_F_TRY_TLS) {
		d->flags &= ~DL_F_TRY_TLS;
		tls = SOCK_F_TLS;

		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(tls_debug))
			g_debug("forcing TLS connection for \"%s\" at %s",
				download_basename(d), download_host_info(d));
	}

	/*
	 * If server is known to support TLS, request a TLS connection, avoiding
	 * any cache lookup later.
	 */

	if (server->attrs & DLS_A_TLS)
		tls = SOCK_F_TLS;

	/*
	 * If there is a fully qualified domain name, look it up for possible
	 * change if either sufficient time passed since last lookup, or if the
	 * DLS_A_DNS_LOOKUP attribute was set because of a connection failure.
	 */

	if (
		(server->attrs & DLS_A_DNS_LOOKUP) ||
		(!is_null_or_empty(server->hostname) &&
			delta_time(tm_time(), server->dns_lookup) >= DOWNLOAD_DNS_LOOKUP)
	) {
		g_assert(server->hostname != NULL);

		d->flags |= DL_F_DNS_LOOKUP;
		server->attrs &= ~DLS_A_DNS_LOOKUP;
		server->dns_lookup = tm_time();
		s = socket_connect_by_name(
			server->hostname, port, SOCK_TYPE_DOWNLOAD, d->cflags | tls);
	} else {
		server->last_connect = tm_time();
		s = socket_connect(download_addr(d), port, SOCK_TYPE_DOWNLOAD,
				d->cflags | tls);
	}

	if (s != NULL)
		socket_attach_ops(s, SOCK_TYPE_DOWNLOAD, &download_socket_ops, d);

	return s;
}

/**
 * (Re)start a stopped or queued download.
 */
static void
download_start(struct download *d, bool check_allowed)
{
	download_check(d);
	file_info_check(d->file_info);

	g_return_if_fail(!DOWNLOAD_IS_MOVING(d));
	g_return_if_fail(!DOWNLOAD_IS_RUNNING(d));
	g_return_if_fail(!DOWNLOAD_IS_VERIFYING(d));
	
	g_return_if_fail(
		GTA_DL_INVALID == d->status ||
		DOWNLOAD_IS_QUEUED(d) ||
		DOWNLOAD_IS_WAITING(d));

	g_return_if_fail(d->list_idx != DL_LIST_RUNNING);	/* Waiting or stopped */
	g_return_if_fail(d->file_info->refcount > 0);
	g_return_if_fail(d->file_info->lifecount > 0);
	g_return_if_fail(d->file_info->lifecount <= d->file_info->refcount);
	g_return_if_fail(d->sha1 == NULL || d->file_info->sha1 == d->sha1);

	if (download_queue_is_frozen()) {
		if (!DOWNLOAD_IS_QUEUED(d)) {
			download_queue(d, _("Download queue is frozen"));
		}
		return;
	}

	/*
	 * If caller did not check whether we were allowed to start downloading
	 * this file, do it now. --RAM, 03/09/2001
	 */

	if (check_allowed && (
		download_has_enough_active_sources(d) ||
		count_running_downloads() >= GNET_PROPERTY(max_downloads) ||
		count_running_on_server(d->server) >= GNET_PROPERTY(max_host_downloads)
		)
	) {
		if (!DOWNLOAD_IS_QUEUED(d)) {
			download_send_head_ping(d);
			download_queue(d, _("No download slot (start)"));
		}
		return;
	}

	if (!download_start_prepare(d))
		return;

	/* Post-conditions when download_start_prepare() returns TRUE */

	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->list_idx == DL_LIST_RUNNING);	/* Moved to "running" list */
	g_assert(d->file_info->refcount > 0);		/* Still alive */
	g_assert(d->file_info->lifecount > 0);
	g_assert(d->file_info->lifecount <= d->file_info->refcount);

	/*
	 * If file is finished, we can stop immediately.
	 *
	 * NB: this check must be made after donwload_start_prepare() since
	 * one must not call download_stop() with a queued download, and the
	 * download is not flagged as running until download_start_prepare()
	 * was called and returned TRUE.
	 */

	if (FILE_INFO_FINISHED(d->file_info)) {
		download_stop(d, GTA_DL_COMPLETED, no_reason);
		return;
	}

	/*
	 * If server is known to be reachable without pushes, reset the flag.
	 */

	if (d->always_push && (d->server->attrs & DLS_A_PUSH_IGN)) {
		d->always_push = FALSE;
	}

	if (
		!DOWNLOAD_IS_IN_PUSH_MODE(d) &&
		(
		 	(SOCK_F_FORCE & d->cflags) ||
			host_is_valid(download_addr(d), download_port(d))
		)
	) {
		/* Direct download */
		download_set_status(d, GTA_DL_CONNECTING);
		d->socket = download_connect(d);

		if (!d->socket) {
			/*
			 * If we ran out of file descriptors, requeue this download.
			 * We don't want to lose the source.  We can't be sure, but
			 * if we see a banned_count of 0 and file_descriptor_runout set,
			 * then the lack of connection is probably due to a lack of
			 * descriptors.
			 *		--RAM, 2004-06-21
			 */

			if (
				GNET_PROPERTY(file_descriptor_runout) &&
				GNET_PROPERTY(banned_count) == 0
			) {
				download_queue_delay(d,
					GNET_PROPERTY(download_retry_busy_delay),
					_("Connection failed (Out of file descriptors?)"));
				return;
			}

			download_unavailable(d, GTA_DL_ERROR, _("Connection failed"));
			return;
		}

		d->socket->pos = 0;
	} else {					/* We have to send a push request */
		download_set_status(d, GTA_DL_PUSH_SENT);

		g_assert(d->socket == NULL);

		download_push(d, FALSE);
	}

	gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT, count_running_downloads());
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);
}

void
download_request_start(struct download *d)
{
	download_check(d);
	g_return_if_fail(d->file_info);
	file_info_check(d->file_info);

	d->flags &= ~DL_F_PAUSED;
	file_info_resume(d->file_info);

	download_start(d, TRUE);
}

/**
 * Restart a download after a failed SHA1 + TTH verification.
 */
static void
download_restart(struct download *d)
{
	g_assert(DL_LIST_STOPPED == d->list_idx);

	/* Reset status to "timeout wait" so that we can stop/start it again */

	download_set_status(d, GTA_DL_TIMEOUT_WAIT);
	download_move_to_list(d, DL_LIST_WAITING);

	/*
	 * If we already downloaded more than the file size from that source,
	 * stop using it.  This is only a crude check to avoid endless loops.
	 *		--RAM, 2012-05-17
	 */

	if (d->downloaded > d->file_size) {
		g_message("SHA1 mismatch for \"%s\", discarding source at %s",
			download_basename(d), download_host_info(d));
		download_stop(d, GTA_DL_ERROR, _("SHA1 mismatch detected"));
	} else {
		g_message("SHA1 mismatch for \"%s\", "
			"will be restarting download at %s",
			download_basename(d), download_host_info(d));
		download_start(d, TRUE);
	}
}

/**
 * Pause a download.
 */
static void
download_pause(struct download *d)
{
	download_check(d);
	file_info_check(d->file_info);

	if (FILE_INFO_FINISHED(d->file_info))
		return;

	if (DOWNLOAD_IS_VERIFYING(d))		/* Can't requeue: it's done */
		return;

	file_info_pause(d->file_info);
	d->flags |= DL_F_PAUSED;
	fi_src_status_changed(d);

	if (!DOWNLOAD_IS_QUEUED(d)) {
		download_queue(d, _("Paused"));
	}
}

void
download_request_pause(struct download *d)
{
	download_check(d);
	g_return_if_fail(d->file_info);
	file_info_check(d->file_info);

	if (!FILE_INFO_FINISHED(d->file_info)) {
		download_pause(d);
	}
}

/**
 * Helper for inner loops of download_pick_followup(), download_pick_another().
 *
 * Return FALSE if we must continue, TRUE if we can break out of the loop
 * because we found the proper target download.
 */
static bool
download_pick_process(
	struct download **dp, struct download *cur,
	bool was_plain_incomplete, const struct sha1 *sha1,
	bool retry_after)
{
	struct download *d;

	if (cur->flags & (DL_F_SUSPENDED | DL_F_PAUSED))
		return FALSE;

	if (download_has_enough_active_sources(cur))
		return FALSE;

	if (FILE_INFO_COMPLETE(cur->file_info))
		return FALSE;

	if (was_plain_incomplete && !download_is_special(cur))
		return FALSE;

	/*
	 * Can only switch to a download that is not actively / passively
	 * queued, as otherwise we could be violating the retry parameters
	 * assigned by the remote server for the resource we're about to ask.
	 */

	if (!DOWNLOAD_IS_SWITCHABLE(cur))
		return FALSE;		/* Can't switch to that download */

	/*
	 * Can't switch to a download that has already issued a pipelined request.
	 */

	if (download_pipelining(cur))
		return FALSE;

	/*
	 * Give priority to the file whose THEX we downloaded.
	 */

	if (
		sha1 && !download_is_special(cur) && cur->file_info->sha1 &&
		sha1_eq(sha1, cur->file_info->sha1)
	) {
		*dp = cur;		/* Found plain file download on this server */
		return TRUE;	/* Exit loop */
	}

	if (retry_after && delta_time(tm_time(), cur->retry_after) < 0)
		return FALSE;

	/*
	 * NOTE: we don't care about cur->timeout_delay and cur->retry_after
	 * because after this routine we are not going to be initiating a new
	 * connection: we're going to reuse the existing connection we have to
	 * the server already.
	 */

	d = *dp;

	if (d && !FILE_INFO_COMPLETE(d->file_info)) {
		if ((DL_F_THEX & d->flags) == (DL_F_THEX & cur->flags)) {
			/*
			 * Pick the download with the most progress. Otherwise
			 * we easily end up with dozens of partials from the
			 * the server.
			 */

			if (download_total_progress(d) >= download_total_progress(cur))
				return FALSE;

			/* Favor smaller file remains (completed sooner, hopefully) */
			if (download_fileremain(d) <= download_fileremain(cur))
				return FALSE;
		}

		/* Give priority to THEX downloads */
		if ((DL_F_THEX & d->flags) > (DL_F_THEX & cur->flags))
			return FALSE;
	}

	*dp = cur;		/* Have a new candidate for switching */

	return FALSE;
}

/**
 * Pick-up another source from this server, for the next HTTP request.
 * We may very well request another file we want on this server.
 *
 * If the download was a THEX download, try to switch back to the
 * download for the file whose THEX we downloaded.  Some servents only
 * allow switching between a THEX and the corresponding file.
 *
 * @param d		the download structure
 * @param sha1	if non-NULL, the SHA1 of the file we downloaded the THEX for
 */
static struct download *
download_pick_followup(struct download *d, const struct sha1 *sha1)
{
	list_iter_t *iter;
	bool was_plain_incomplete;
	bool found = FALSE;

	download_check(d);
	g_assert(d->list_idx == DL_LIST_WAITING);
	g_assert(!download_pipelining(d));

	if (!GNET_PROPERTY(dl_resource_switching))
		return d;

	/*
	 * Cannot enable this until GTKG can properly manage switching of
	 * resources as a server.  Also, how can we detect whether a server will
	 * support such a switching?  Some legacy servents may not, and legacy
	 * GTKG certainly won't.
	 *		--RAM, 2007-09-10
	 */

	if (is_strprefix(download_vendor_str(d), "gtk-gnutella/")) {
		version_t ver;

		if (!version_fill(download_vendor_str(d), &ver) || ver.build < 14884)
			return d;

		/* FALL-THROUGH: this version won't choke on resource switching. */
	}

	/*
	 * If we have a slot for a non-complete source file, then we will only
	 * allow switching to a special resource (either browse or THEX loads).
	 * Or the risk is that we lose the slot completely, or get requeued by
	 * the remote server.
	 *		--RAM, 2009-02-08
	 */

	was_plain_incomplete = !FILE_INFO_COMPLETE(d->file_info) &&
		!download_is_special(d);

	/*
	 * If this is a plain download and it has a pending THEX, switch to it.
	 */

	if (was_plain_incomplete) {
		struct guid *id = dualhash_lookup_key(dl_thex, d->id);

		/*
		 * The ID we find in the dl_thex dual hash is that of the associated
		 * THEX download for the plain file.
		 */

		if (id != NULL) {
			struct download *dt = hikset_lookup(dl_by_id, id);

			download_check(dt);
			g_assert(dt->flags & DL_F_THEX);
			
			if (DOWNLOAD_IS_SWITCHABLE(dt)) {
				if (GNET_PROPERTY(download_debug)) {
					g_debug("TTH requesting switching from "
						"plain \"%s\" to \"%s\" on %s",
						download_basename(d), download_basename(dt),
						download_host_info(d));
				}
				d = dt;
				goto done;
			}
		}
	}

	/*
	 * Elect a new download for the follow-up request.
	 */

	iter = list_iter_before_head(d->server->list[DL_LIST_RUNNING]);
	while (list_iter_has_next(iter)) {
		struct download *cur;

		cur = list_iter_next(iter);
		download_check(cur);

		if (download_pick_process(&d, cur, was_plain_incomplete, sha1, FALSE)) {
			found = TRUE;
			break;
		}
	}
	list_iter_free(&iter);

	if (found)
		goto done;

	iter = list_iter_before_head(d->server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter)) {
		struct download *cur;

		cur = list_iter_next(iter);
		download_check(cur);

		if (download_pick_process(&d, cur, was_plain_incomplete, sha1, FALSE))
			break;
	}
	list_iter_free(&iter);

done:
	/*
	 * If we have elected a "running" download (awaiting push results or
	 * connecting), then we need to move it back temporarily to the
	 * "waiting" list, as download_start_prepare() expects non-running
	 * downloads.  Calling download_stop() is a nice way to also cleanup
	 * the socket structure.
	 */

	if (d->list_idx == DL_LIST_RUNNING)
		download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);

	g_assert(d->list_idx == DL_LIST_WAITING);

	return d;
}

/**
 * Pick-up another waiting source from this server, for the next HTTP request
 * we're going to send.
 *
 * @param d		the current download
 *
 * @return the download we found, or NULL if none could be chosen.
 */
struct download *
download_pick_another_waiting(const struct download *d)
{
	list_iter_t *iter;
	struct download *other = NULL;

	download_check(d);

	iter = list_iter_before_head(d->server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter)) {
		struct download *cur;

		cur = list_iter_next(iter);
		download_check(cur);

		/* Make sure we're not targetting the same file */

		if (cur->file_info == d->file_info)
			continue;

		/* Pay attention to retry_after */

		if (download_pick_process(&other, cur, FALSE, NULL, TRUE))
			break;
	}
	list_iter_free(&iter);

	return other;
}

/**
 * Pick-up another source from this server, for the next HTTP request.
 * We must avoid the current download and its parent download, which has
 * just been stopped / requeued.
 *
 * We pay attention to the d->retry_after field because we're switching after
 * an error condition and we don't want to go back and forth between two
 * downloads on the same host without respecting the delays we have configured.
 *
 * @param d		the current download
 *
 * @return the download we found, or NULL if none could be chosen.
 */
static struct download *
download_pick_another(const struct download *d)
{
	list_iter_t *iter;
	struct download *other = NULL;

	download_check(d);
	g_assert(d->list_idx == DL_LIST_WAITING);

	iter = list_iter_before_head(d->server->list[DL_LIST_RUNNING]);
	while (list_iter_has_next(iter)) {
		struct download *cur;

		cur = list_iter_next(iter);
		download_check(cur);

		g_assert(cur != d);

		/* Make sure we're not targetting the same file */

		if (cur->file_info == d->file_info)
			continue;

		/* Pay attention to retry_after */

		if (download_pick_process(&other, cur, FALSE, NULL, TRUE))
			break;
	}
	list_iter_free(&iter);

	if (NULL == other)
		other = download_pick_another_waiting(d);

	if (NULL == other)
		return NULL;

	/*
	 * If we have elected a "running" download (awaiting push results or
	 * connecting), then we need to move it back temporarily to the
	 * "waiting" list, as download_start_prepare() expects non-running
	 * downloads.  Calling download_stop() is a nice way to also cleanup
	 * the socket structure.
	 */

	if (other->list_idx == DL_LIST_RUNNING) {
		if (GNET_PROPERTY(download_debug)) {
			g_debug("%s(): stopping %s \"%s\" on %s",
				G_STRFUNC, download_status_to_string(d),
				download_basename(other), download_host_info(other));
		}
		download_stop(other, GTA_DL_TIMEOUT_WAIT, no_reason);
	}

	g_assert(other->list_idx == DL_LIST_WAITING);

	return other;
}

/**
 * Pick up new downloads from the queue as needed.
 */
static void
download_pickup_queued(void)
{
	time_t now = tm_time();
	uint i;

	/*
	 * To select downloads, we iterate over the sorted `dl_by_time' list and
	 * look for something we could schedule.
	 *
	 * Note that we jump from one host to the other, even if we have multiple
	 * things to schedule on the same host: It's better to spread load among
	 * all hosts first.
	 */

	for (i = 0; i < DHASH_SIZE; i++) {
		plist_t *l;
		int last_change;

		if (download_queue_is_frozen())
			break;

		if (count_running_downloads() >= GNET_PROPERTY(max_downloads))
			break;

		if (!bws_can_connect(SOCK_TYPE_DOWNLOAD))
			break;
		
	retry:
		l = dl_by_time.servers[i];
		last_change = dl_by_time.change[i];

		for (/* NOTHING */; NULL != l; l = plist_next(l)) {
			struct dl_server *server = l->data;
			list_iter_t *iter;
			struct download *d;
			uint n;
			bool only_special = FALSE;

			g_assert(dl_server_valid(server));

			if (count_running_downloads() >= GNET_PROPERTY(max_downloads))
				break;

			/*
			 * List is sorted, so as soon as we go beyond the current time,
			 * we can stop.
			 */

			if (delta_time(now, server->retry_after) < 0)
				break;

			if (server_list_length(server, DL_LIST_WAITING) == 0)
				continue;

			if (
				count_running_on_server(server)
					>= GNET_PROPERTY(max_host_downloads)
			) {
				download_list_send_head_ping(server->list[DL_LIST_WAITING]);

				/*
				 * Normally, special downloads are served by remote servents
				 * regardless of the amount of upload slots or per host
				 * restrictions (since these downloads are small, usually).
				 *
				 * Hence, allow such special downloads to be scheduled even
				 * if we reached the configured local maximum.
				 */

				only_special = TRUE;
			}

			/*
			 * Avoid hammering servers.  In case we have multiple files queued
			 * on that server, we must not issue all the requests in a short
			 * period of time as this can be frowned upon.
			 */

			if (delta_time(now, server->last_connect) < DOWNLOAD_CONNECT_DELAY) 
				continue;

			/*
			 * OK, select a download within the waiting list, but do not
			 * remove it yet.  This will be done by download_start().
			 */

			g_assert(server->list[DL_LIST_WAITING]);	/* Since count != 0 */

			n = 0;
			d = NULL;
			iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
			while (list_iter_has_next(iter)) {
				struct download *cur;

				cur = list_iter_next(iter);
				download_check(cur);

				if (cur->flags & (DL_F_SUSPENDED | DL_F_PAUSED))
					continue;

				if (only_special && !download_is_special(cur))
					continue;

				if (download_has_enough_active_sources(cur)) {
					download_send_head_ping(cur);
					continue;
				}

				if (
					delta_time(now, cur->last_update) <=
						(time_delta_t) cur->timeout_delay
				) {
					download_send_head_ping(cur);
					continue;
				}

				/* Note that we skip over paused and suspended downloads */
				if (delta_time(now, cur->retry_after) < 0)
					break;	/* List is sorted */

				if (d) {
					if ((NULL != d->thex) == (NULL != cur->thex)) {
						/*
						 * Pick the download with the most progress. Otherwise
						 * we easily end up with dozens of partials from the
						 * the server.
						 */

						if (
							download_total_progress(d)
								>= download_total_progress(cur)
						) {
							download_send_head_ping(cur);
							continue;
						}
					}

					/* Give priority to THEX downloads */
					if (d->thex && NULL == cur->thex) {
						download_send_head_ping(cur);
						continue;
					}
				}

				if (d)
					download_send_head_ping(d);

				d = cur;

				/*
				 * If there are a lot of downloads queued at a single server we
				 * might spend a lot of time scanning the queue of a download
				 * to pick. Thus limit the amount of items we're going to take
				 * into account.
				 */

				if (n++ > 100)
					break;
			}
			list_iter_free(&iter);

			if (d) {
				download_start(d, FALSE);
			}


			/*
			 * It's possible that download_start() ended-up changing the
			 * dl_by_time list we're iterating over.  That's why all changes
			 * to that list update the dl_by_time_change variable, which we
			 * snapshot upon entry into the loop.
			 *		--RAM, 24/08/2002.
			 */

			if (last_change != dl_by_time.change[i])
				goto retry;
		}
	}
}

/**
 * Invoked by the query hit parsing layer when push-proxies are discovered
 * for some GUID.
 */
void
download_got_push_proxies(const struct guid *guid,
	const gnet_host_vec_t *proxies, bool g2)
{
	struct dl_server *server;
	int i;
	size_t added = 0;
	bool g2_server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	g_assert(dl_server_valid(server));

	/*
	 * We can only keep push-proxies that are compatible with the protocol
	 * supported by the server:
	 *
	 * - If we're handling proxies coming from a G2 query, and the server is
	 *   not flagged as being a G2 server, flag it as G2 and discard any
	 *   known push-proxies (which were necessarily Gnutella ultrapeers).
	 *
	 * - If we're handling proxies coming from a Gnutella query and the server
	 *   is already flagged as a G2 server, don't update anything.
	 */

	g2_server = booleanize(server->attrs & DLS_A_G2_ONLY);

	if (g2) {
		if (!g2_server) {
			if (GNET_PROPERTY(download_debug)) {
				g_debug("%s(): flagging %s as a G2 host%s",
					G_STRFUNC, server_host_info(server),
					server->proxies != NULL ?
						" and discarding known push-proxies" : "");
			}
			server->attrs |= DLS_A_G2_ONLY;
		}
	} else {
		if (g2_server)
			return;		/* Ignore Gnutella push-proxies for known G2 host */
	}

	/*
	 * Always supersede the previously known push-proxies with the newest ones.
	 */

	pproxy_set_free_null(&server->proxies);

	for (i = gnet_host_vec_count(proxies) - 1; i >= 0; i--) {
		struct gnutella_host host;
		host_addr_t addr;
		uint16 port;

		host = gnet_host_vec_get(proxies, i);
		addr = gnet_host_get_addr(&host);
		port = gnet_host_get_port(&host);

		if (
			host_addr_equal(addr, server->key->addr) &&
			port == server->key->port
		)
			continue;		/* We always try the server's own IP:port */

		if (add_proxy(server, addr, port))
			added++;
	}

	if (added > 0) {
		if (GNET_PROPERTY(download_debug)) {
			g_debug("PUSH found %zu new push prox%s in query hit "
				"for GUID %s at %s",
				added, plural_y(added),
				guid_hex_str(guid), server_host_info(server));
		}
		gnet_stats_inc_general(GNR_COLLECTED_PUSH_PROXIES);
		download_push_proxy_wakeup(server, TRUE, FALSE);
	}
}

/**
 * Invoked by routing layer when a PUSH route is available for the GUID.
 */
static void
download_got_push_route(const guid_t *guid)
{
	struct dl_server *server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return;

	/*
	 * We got a fresh route, so attempt to broadcast a PUSH on Gnutella.
	 * Once done, remove the starving condition unless we still have no
	 * push-proxies known.
	 */

	gnet_stats_inc_general(GNR_REVITALIZED_PUSH_ROUTES);
	download_push_proxy_wakeup(server, FALSE, TRUE);
	if (server->proxies != NULL && pproxy_set_count(server->proxies) > 0) {
		route_starving_remove(guid);
	}

	if (GNET_PROPERTY(download_debug)) {
		g_debug("PUSH revitalized route for GUID %s at %s",
			guid_hex_str(guid), server_host_info(server));
	}
}

/**
 * Attempt to get this download connected to the server through a PUSH request.
 */
static void
download_push(struct download *d, bool on_timeout)
{
	bool ignore_push = FALSE;
	bool udp_push;

	download_check(d);

	if (GNET_PROPERTY(download_debug) > 2)
		g_debug("%s(): timeout=%s for \"%s\" at %s",
			G_STRFUNC, on_timeout ? "y" : "n",
			download_basename(d), download_host_info(d));

	if (
		(d->flags & DL_F_PUSH_IGN) ||
		(d->server->attrs & DLS_A_PUSH_IGN) ||
		has_blank_guid(d)
	)
		ignore_push = TRUE;

	if (
		ignore_push || 
		GNET_PROPERTY(is_firewalled) ||
		!GNET_PROPERTY(send_pushes)
	)
		goto attempt_retry;

	/*
	 * The first time we come here, we simply record we did send PUSH via UDP
	 * and return.  Next time, we'll go on below.
	 *
	 * The rationale here is that UDP is a faster way to propagate PUSH
	 * requests, but we have to fallback in case it does not work.
	 *		--RAM, 2007-05-06
	 */

	udp_push = !booleanize(d->flags & DL_F_UDP_PUSH);

	/*
	 * Always attempt to broadcast through Gnutella if we have a route
	 */

	if (download_send_push_request(d, udp_push, TRUE)) {
		if (udp_push) {
			d->flags |= DL_F_UDP_PUSH;		/* For next time */
			return;
		}
		/* FALL THROUGH */
	}

	/*
	 * Contact push proxies via TCP, if we have any.
	 */

	if (use_push_proxy(d))
		return;

	/*
	 * No more push proxies: mark the GUID as starving so that we can be
	 * warned whenever the Gnutella routing layer discovers a new push route.
	 */

	route_starving_add(download_guid(d), download_got_push_route);

	/*
	 * Look for new push proxies through the DHT.
	 */

	if (server_dht_query(d))
		return;

	/*
	 * Nothing is working, we may be out of reach.  Try to ignore the PUSH
	 * flag if the address is deemed to be reacheable...
	 */

	if (d->always_push) {
		/*
		 * If the address is not a private IP, it is possible that the
		 * servent set the "Push" flag incorrectly.
		 *		-- RAM, 18/08/2002.
		 */

		if (!host_is_valid(download_addr(d), download_port(d))) {
			if (d->server->attrs & DLS_A_DHT_PUBLISH) {
				/*
				 * If server is known to publish in the DHT, then it is safe
				 * to assume that it has a stable GUID and that we can find
				 * it as soon as it comes back up.  Hence do not remove
				 * all the sources we have for that host.
				 *		--RAM, 2010-10-06
				 */
				if (d->retries < GNET_PROPERTY(download_max_retries) - 1) {
					d->retries++;
				}
				download_queue_hold(d,
					GNET_PROPERTY(download_retry_refused_delay),
					_("Waiting for server PROX publishing"));
			} else if (d->retries < GNET_PROPERTY(download_max_retries)) {
				d->retries++;
				download_queue_hold(d,
					GNET_PROPERTY(download_retry_refused_delay),
					_("Waiting for push route"));
			} else {
				/*
				 * Reached maximum amount of retries and server is not known
				 * for publishing PROX entries in the DHT.  Get rid of all
				 * the sources referring to that unreacheable server
				 */
				download_unavailable(d, GTA_DL_ERROR, _("Push route lost"));
				download_remove_all_from_peer(
					download_guid(d), download_addr(d), download_port(d), TRUE);
			}
		} else {
			/*
			 * Later on, if we manage to connect to the server, we'll
			 * make sure to mark it so that we ignore pushes to it, and
			 * we will clear the `always_push' indication.
			 * (see download_send_request() for more information)
			 */

			if (GNET_PROPERTY(download_debug) > 2)
				g_debug("PUSH trying to ignore them for %s",
					host_addr_port_to_string(download_addr(d),
					download_port(d)));

			d->flags |= DL_F_PUSH_IGN;
			download_queue(d, _("Ignoring Push flag"));
		}
		return;
	}

attempt_retry:
	/*
	 * If we're aborting a download flagged with "Push ignore" due to a
	 * timeout reason, chances are great that this host is indeed firewalled!
	 * Tell them so. -- RAM, 18/08/2002.
	 */

	if (
		d->always_push &&						/* Normally requires a push */
		(d->flags & DL_F_PUSH_IGN) &&			/* Started to ignore pushes */
		!(d->server->attrs & DLS_A_PUSH_IGN)	/* But never connected yet */
	) {
		d->retries++;

		if (on_timeout || d->retries >= 5) {
			/*
			 * Looks like we won't be able to ever reach this host directly.
			 * Reset the DL_F_PUSH_IGN flag.
			 */

			if (GNET_PROPERTY(download_debug) > 2) {
				g_debug("PUSH clearing the ignore PUSH condition for %s",
					host_addr_port_to_string(
						download_addr(d), download_port(d)));
			}
			d->flags &= ~DL_F_PUSH_IGN;
		}

		download_queue_hold(d, GNET_PROPERTY(download_retry_refused_delay),
			(d->flags & DL_F_PUSH_IGN) ?
				NG_("No direct connection yet (%u retry)",
					"No direct connection yet (%u retries)", d->retries) :
				NG_("Timeout (%u retry)", "Timeout (%u retries)", d->retries),
			d->retries);
	} else if (d->retries < GNET_PROPERTY(download_max_retries)) {
		d->retries++;
		if (on_timeout)
			download_queue_hold(d, GNET_PROPERTY(download_retry_timeout_delay),
				NG_("Timeout (%u retry)",
					"Timeout (%u retries)", d->retries), d->retries);
		else
			download_queue_hold(d, GNET_PROPERTY(download_retry_refused_delay),
				NG_("Connection refused (%u retry)",
					"Connection refused (%u retries)", d->retries),
					 d->retries);
	} else {
		/*
		 * Looks like this host is down.  Abort the download, and remove all
		 * the ones queued for the same host.
		 */

		download_unavailable(d, GTA_DL_ERROR,
				NG_("Timeout (%u retry)",
					"Timeout (%u retries)", d->retries), d->retries);

		download_remove_all_from_peer(
			download_guid(d), download_addr(d), download_port(d), TRUE);
	}

	/*
	 * Remove this source from mesh, since we don't seem to be able to
	 * connect to it properly.
	 */

	download_bad_source(d);
}

/**
 * Direct download failed, let's try it with a push request.
 *
 * @param d				the target download
 * @param on_timeout	TRUE when coming from download_timer()
 * @param user_request	TRUE if user explicitly requested a fallback
 */
void
download_fallback_to_push(struct download *d,
	bool on_timeout, bool user_request)
{
	g_return_if_fail(d);
	download_check(d);

	if (GNET_PROPERTY(download_debug) > 2)
		g_debug("%s(): timeout=%s, user=%s for \"%s\" at %s",
			G_STRFUNC, on_timeout ? "y" : "n", user_request ? "y" : "n",
			download_basename(d), download_host_info(d));

	/*
	 * On user requests, and provided we have a non-blank GUID for the
	 * download, reset the push-ignore flags.
	 */

	if (user_request && !has_blank_guid(d)) {
		d->always_push = TRUE;
		d->flags &= ~DL_F_PUSH_IGN;
		d->server->attrs &= ~DLS_A_PUSH_IGN;
	}

	if (DOWNLOAD_IS_QUEUED(d))
		return;

	/*
	 * If we're receiving data or already sent push, we're wrong
	 * here. Most likely it was unnecessarily requested by the user.
	 */

	if (DOWNLOAD_IS_ACTIVE(d))
		return;

	if (user_request && DOWNLOAD_IS_EXPECTING_GIV(d))
		return;

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	if (!d->socket) {
		g_warning("%s(): no socket for '%s'", G_STRFUNC, download_basename(d));
    } else {
		/*
		 * If a DNS lookup error occurred, discard the hostname we have.
		 * Due to the async nature of the DNS lookups, we must check for
		 * a non-NULL hostname, in case we already detected it earlier for
		 * this server, in another connection attempt.
		 *
		 * XXX we should allow for DNS failure and mark the hostname bad
		 * XXX for a while only, then re-attempt periodically, instead of
		 * XXX simply discarding it.
		 */

		if (
			socket_bad_hostname(d->socket) &&
			!is_null_or_empty(d->server->hostname)
		) {
			g_warning("hostname \"%s\" for %s could not resolve, discarding",
				d->server->hostname,
				host_addr_port_to_string(download_addr(d), download_port(d)));
			atom_str_free_null(&d->server->hostname);
			fi_src_info_changed(d);
		}

		/*
		 * If we could not connect to the host, but we have a hostname and
		 * we did not perform a DNS lookup this time, request one for the
		 * next attempt.
		 */

		if (
			!is_null_or_empty(d->server->hostname) &&
			!(d->flags & DL_F_DNS_LOOKUP)
		)
			d->server->attrs |= DLS_A_DNS_LOOKUP;

		socket_free_null(&d->socket);
	}

	file_object_release(&d->out_file);

	download_set_status(d, user_request ? GTA_DL_PUSH_SENT : GTA_DL_FALLBACK);
	d->last_update = tm_time();		/* Reset timeout if we send the push */
	download_push(d, on_timeout);

	fi_src_status_changed(d);
}

static uint32
get_index_from_uri(const char *uri)
{
	uint32 idx = 0;

	if (uri) {
		const char *endptr;

		endptr = is_strprefix(uri, "/get/");
		if (endptr) {
			int error;

			/*
			 * Only accept URIs of this form with a non-empty filename:
			 *
			 *	"/get/<32-bit integer>/<filename>"
			 */

			idx = parse_uint32(endptr, &endptr, 10, &error);
			if (
				error ||
				'/' != endptr[0] ||
				'\0' == endptr[1] ||
				NULL != strchr(&endptr[1], '/')
			) {
				idx = 0;
			}
		}
	}
	return idx;
}

/*
 * Downloads creation and destruction
 */

/**
 * Create a new download.
 *
 * @returns created download structure, or NULL if none.
 */
static struct download *
create_download(
	const char *file,
	const char *uri,
	filesize_t size,
	const host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *file_info,
	const gnet_host_vec_t *proxies,
	uint32 cflags,
	const char *parq_id)
{
	struct dl_server *server;
	struct download *d;
	const char *reason;
	fileinfo_t *fi;
	const char *msg = NULL;
	const char *file_name = NULL;
	bool use_mesh = FALSE;

	g_assert(host_addr_initialized(addr));

	if (file_info != NULL) {
		g_return_val_if_fail(!sha1 || sha1_eq(file_info->sha1, sha1), NULL);
		if (file_info->tth != NULL) {
			if (tth != NULL && !tth_eq(file_info->tth, tth)) {
				char buf[TTH_BASE32_SIZE + 1];

				tth_to_base32_buf(tth, buf, sizeof buf);
				g_warning("ignoring new source for %s at %s: its TTH %s "
					"differs from known %s (SHA1 is %s)",
					filepath_basename(file_info->pathname),
					host_addr_port_to_string(addr, port), buf,
					tth_base32(file_info->tth),
					NULL == file_info->sha1 ? "unknown" :
						sha1_base32(file_info->sha1));

				return NULL;
			}
		}
	}

#if 0 /* This is helpful when you have a transparent proxy running */
		/* XXX make that configurable from the GUI --RAM, 2005-08-15 */
    /*
     * Never try to download from ports 80 or 443.
     */
    if ((port == 80) || (port == 443)) {
        return NULL;
	}
#endif

	/*
	 * Reject if we're trying to download from ourselves (could happen
	 * if someone echoes back our own alt-locs to us with PFSP).
	 */

	if (0 != port) {
		if (is_my_address_and_port(addr, port)) {
			msg = "ignoring download from own address";
			goto fail;
		} else if (local_addr_cache_lookup(addr, port)) {
			msg = "ignoring download from own recent address";
			goto fail;
		}
	}

	{
		char *s;
		char *b;
		
		b = s = filename_sanitize(file, FALSE, FALSE);

		if (GNET_PROPERTY(beautify_filenames))
			b = filename_beautify(s);

		/* An empty filename would create a corrupted download entry */
    	file_name = atom_str_get('\0' != b[0] ? b : "noname");

		if (b != s)		HFREE_NULL(b);
		if (file != s)	HFREE_NULL(s);
	}

	/*
	 * Create server if none exists already.
	 */

	if (NULL == guid) {
		guid = &blank_guid;
	}
	server = get_server(guid, addr, port, TRUE);

	/*
	 * Set the G2 flag if needed, which will be sticky for the server.
	 */

	if (SOCK_F_G2 & cflags) {
		cflags &= ~SOCK_F_G2;		/* Don't propagate this further down */
		server->attrs &= ~DLS_A_FAKE_G2;
		server->attrs |= DLS_A_G2_ONLY;
	}

	g_assert(dl_server_valid(server));

	/*
	 * If some push proxies are given add the proxies coming from the
	 * query hit if we did not already know them and if the timestamp
	 * is more recent than the last addition to the push-proxy set.
	 */

	if (proxies != NULL && pproxy_set_older_than(server->proxies, stamp))
		add_proxies_vec(server, proxies);

	/*
	 * Record server's hostname if non-NULL and not empty.
	 *
	 * We need to do that before checking for duplicate downloads in case
	 * we already have the download for the IP address (through the download
	 * mesh entry) but we just resolved the hostname through the DNS and now
	 * attempt to create the download entry.  If we don't do that now, we'll
	 * lose the information about the server.
	 */

	if (!is_null_or_empty(hostname))
		set_server_hostname(server, hostname);

	/*
	 * Refuse to queue the same download twice. --RAM, 04/11/2001
	 */

	d = server_has_same_download(server, file_name, sha1, size);
	if (d) {
		download_check(d);
		msg = "has same download on server";
		goto fail;
	}

	fi = file_info == NULL
		? file_info_get(file_name, GNET_PROPERTY(save_file_path),
				size, sha1, 0 != size)
		: file_info;

	if (NULL == fi || (FI_F_SEEDING & fi->flags)) {
		msg = fi ? "fileinfo is NULL" : "file is seeding";
		goto fail;
	}

	/*
	 * Only attempt to collect information from the download mesh when this
	 * is the first source added.  Later additions to the mesh will try to
	 * add the source to the fileinfo.
	 *
	 * However, if the fileinfo did not have any SHA1 yet, and we supply one
	 * now, we have to look at the mesh because earlier entries could not.
	 */

	use_mesh = (NULL == fi->sha1 && sha1 != NULL) || 0 == fi->refcount;

	if (tth) {
		if (NULL == fi->tth) {
			file_info_got_tth(fi, tth);
		} else if (!tth_eq(tth, fi->tth)) {
			msg = "TTH mismatch between argument and fileinfo";
			goto fail;
		}
	}

	/*
	 * This usually happens when handling a magnet: with no source.
	 */

	if (!is_host_addr(addr) && guid_is_blank(guid) && !FILE_INFO_COMPLETE(fi)) {
		msg = "blank GUID and null IP address for non-orphan download";
		goto fail;
	}

	/*
	 * Initialize download.
	 */

	d = download_alloc();

	d->last_update = tm_time();
	d->server = server;
	d->server->refcnt++;
	d->id = dl_random_guid_atom();
	hikset_insert_key(dl_by_id, &d->id);

	/*
	 * If we know that this server can be directly connected to, ignore
	 * the push flag. --RAM, 18/08/2002.
	 */

	if ((d->server->attrs & DLS_A_PUSH_IGN) || has_blank_guid(d)) {
		cflags &= ~SOCK_F_PUSH;
	}
	d->cflags = cflags;
	d->always_push = 0 != (SOCK_F_PUSH & d->cflags);

	d->list_idx = DL_LIST_INVALID;
	d->file_name = file_name;
	d->uri = uri ? atom_str_get(uri) : NULL;
	d->file_size = size;

	/*
	 * Note: size and skip will be filled by download_pick_chunk() later
	 * if we use swarming.
	 */

	d->chunk.size = size;			/* Will be changed if range requested */
	d->record_stamp = stamp;
	download_set_sha1(d, sha1);
	download_add_to_list(d, DL_LIST_WAITING);

	/*
	 * If fileinfo is marked with FI_F_SUSPEND, it means we are in the process
	 * of verifying the SHA1 of the download.  If it matches with the SHA1
	 * we got initially, we'll remove the downloads, otherwise we will
	 * restart it.
	 *
	 * That's why we still accept downloads for that fileinfo, but do not
	 * schedule them: we wait for the outcome of the SHA1 verification process.
	 */

	if (fi->flags & FI_F_SUSPEND)
		d->flags |= DL_F_SUSPENDED;
	if (fi->flags & FI_F_PAUSED)
		d->flags |= DL_F_PAUSED;

	if (stamp == MAGIC_TIME)			/* Download recreated at startup */
		file_info_add_source(fi, d);	/* Preserve original "ntime" */
	else
		file_info_add_new_source(fi, d);

	g_assert(d->file_info != NULL);

	if (d->file_info->sha1 != NULL)
		download_by_sha1_add(d);

	/*
	 * NOTE: These are explicitely prepended to avoid inconsistencies if
	 *		 we just happen to iterate forwards over these lists.
	 */
	hash_list_prepend(sl_downloads, d);
	hash_list_prepend(sl_unqueued, d);

	download_dirty = TRUE;			/* Refresh list, in case we crash */

	/*
	 * Compute proper record_index.  Recall that URN_INDEX is our special mark
	 * to indicate that we can ask the resource on the server via a
	 * "/uri-res/N2R?urn:sha1:..." request.
	 *
	 * If we have no URI and a SHA1, chances are we can request via N2R...
	 */

	if (NULL == d->uri && d->sha1) {
		d->record_index = URN_INDEX;
	} else {
		d->record_index = get_index_from_uri(d->uri);
	}

	/*
	 * Insert in download mesh if it does not require a push and has a SHA1.
	 */

	if (!d->always_push && d->sha1 && (NULL == d->uri || 0 != d->record_index))
		dmesh_add(d->sha1, addr, port, d->record_index, d->file_name, stamp);

	/*
	 * When we know our SHA1, if we don't have a SHA1 in the `fi' and we
	 * looked for it, it means that they didn't have "strict_sha1_matching"
	 * at some point in time.
	 *
	 * If we have a SHA1, it must match.
	 */

	if (d->sha1 != NULL && fi->sha1 == NULL) {
		bool success = file_info_got_sha1(fi, d->sha1);
		if (success) {
            g_message("forced SHA1 %s after %s byte%s "
				"downloaded for %s",
				sha1_base32(d->sha1), uint64_to_string(fi->done),
				plural(fi->done), download_basename(d));
			download_by_sha1_add(d);
			if (DOWNLOAD_IS_QUEUED(d)) {	/* file_info_got_sha1() can queue */
				return d;
			}
		} else {
			download_info_reget(d);
			download_queue(d, _("Dup SHA1 during creation"));
			return d;
		}
	}

	g_assert(d->sha1 == NULL || d->file_info->sha1 == d->sha1);

	if (d->flags & DL_F_SUSPENDED) {
		reason = _("Suspended (SHA1 checking)");
	} else if (d->flags & DL_F_PAUSED) {
		reason = _("Paused");
	} else if (count_running_downloads() >= GNET_PROPERTY(max_downloads)) {
		reason = _("Max. number of downloads reached");
	} else if (
			count_running_on_server(d->server)
			>= GNET_PROPERTY(max_host_downloads)
			) {
		reason = _("Max. number of downloads for this host reached");
	} else if (download_has_enough_active_sources(d)) {
		reason = _("Has already enough active sources");
	} else {
		reason = _("download_start() failed");
		download_start(d, FALSE);		/* Start the download immediately */
	}

	if (GTA_DL_INVALID == d->status) {
		/* Ensure it has a time for status display */
		d->retry_after = time_advance(tm_time(), random_value(3) + 1);
		download_queue(d, "%s", reason);
	}

	/*
	 * Record PARQ id if present, so we may answer QUEUE callbacks.
	 */

	if (parq_id && !d->parq_dl) {
		d->parq_dl = parq_dl_create(d);
		parq_dl_add_id(d, parq_id);
	}

	/*
	 * Only attempt to collect information from the download mesh when this
	 * is the first source added.  Later additions to the mesh will try to
	 * add the source to the fileinfo, and further source additions will
	 * only re-process information that was already handled before.
	 */

	if (use_mesh && sha1 != NULL && size > 0)
		dmesh_multiple_downloads(sha1, size, d->file_info);

	return d;

fail:
	if (GNET_PROPERTY(download_debug)) {
		g_debug("%s(\"%s\", SHA1=%s): %s",
			G_STRFUNC, file, sha1 ? sha1_base32(sha1) : "none", msg);
	}
	atom_str_free_null(&file_name);
	return NULL;
}

/**
 * Common code for automatic download request.
 */
static void
download_auto_new_common(const char *file_name,
	filesize_t size,
	const host_addr_t addr,
   	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	gnet_host_vec_t *proxies,
	uint32 flags)
{
	const char *reason;
	enum ignore_val ign_reason;

	/*
	 * Make sure host is reacheable, especially if we come from the GUI,
	 * which cannot access the bogus IP database.
	 */

	if (0 == (SOCK_F_PUSH & flags) && !host_is_valid(addr, port)) {
		/* We cannot send a PUSH without a valid GUID */
		if (NULL == guid || guid_is_blank(guid))
			return;
		flags |= SOCK_F_PUSH;
	}

	/*
	 * Make sure we're not prevented from downloading that file.
	 */

	ign_reason = ignore_is_requested(
		fi ? filepath_basename(fi->pathname) : file_name,
		fi ? fi->size : size,
		fi ? fi->sha1 : sha1);

	if (IGNORE_FALSE != ign_reason) {
		reason = ignore_reason_to_string(ign_reason);
		if (!reason) {
			g_error("ignore_is_requested() returned unexpected %u",
					(uint) ign_reason);
		}
		goto abort_download;
	}

	/*
	 * Create download.
	 */

	create_download(file_name,
		NULL,	/* URI */
		size,
		addr,
		port,
		guid,
		hostname,
		sha1,
		tth,
		stamp,
		fi,
		proxies,
		flags,
		NULL); 	/* PARQ ID */

	return;

abort_download:
	if (GNET_PROPERTY(download_debug) > 4)
		g_debug("ignoring auto download for \"%s\": %s", file_name, reason);
	return;
}

/**
 * Automatic download request.
 */
void
download_auto_new(const char *file_name,
	filesize_t size,
	const host_addr_t addr,
   	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	gnet_host_vec_t *proxies,
	uint32 flags)
{
	bool was_orphan = fi && 0 == fi->refcount;

	/*
	 * Even though this routine can be called for sources collected out of
	 * the download mesh, we know we're seeding an orphan download out of
	 * query hits when there was no reference on the fileinfo.
	 */

	download_auto_new_common(
		file_name, size, addr, port, guid, hostname,
		sha1, tth, stamp, fi, proxies, flags);

	/*
	 * We can ignore sources: need to check for re-seeding upon return only.
	 */

	if (was_orphan && 0 != fi->refcount) {
		bool from_qhit;

		/*
		 * If the GUID is blank then we're most certainly not processing
		 * a query hit.  We were an orphan, meaning there was no download
		 * running, and this is not the path for DHT seeding, so it can only
		 * come from an upload, seeding us via an X-Alt line.
		 */

		from_qhit = !guid_is_blank(guid);
		gnet_stats_inc_general(from_qhit ?
			GNR_QHIT_SEEDING_OF_ORPHAN : GNR_UPLOAD_SEEDING_OF_ORPHAN);

		if (GNET_PROPERTY(download_debug))
			g_debug("%s seeding of orphan \"%s\" with %s:%u",
				from_qhit ? "QHIT" : "UPLOAD",
				filepath_basename(fi->pathname),
				hostname ? hostname : host_addr_to_string(addr), port);
	}
}

/**
 * Automatic download request triggered from DHT results.
 */
void
download_dht_auto_new(const char *file_name,
	filesize_t size,
	const char *hostname,
	const host_addr_t addr,
   	uint16 port,
	const struct guid *guid,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	uint32 flags)
{
	bool was_orphan = fi && 0 == fi->refcount;

	download_auto_new_common(
		file_name, size, addr, port, guid, hostname,
		sha1, tth, stamp, fi,
		NULL, /* proxies */
		flags);

	/*
	 * We can ignore sources: need to check for re-seeding upon return only.
	 */

	if (was_orphan && 0 != fi->refcount) {
		gnet_stats_inc_general(GNR_DHT_SEEDING_OF_ORPHAN);
		if (GNET_PROPERTY(dht_debug) || GNET_PROPERTY(download_debug))
			g_debug("DHT seeding of orphan \"%s\" with %s:%u", file_name,
				hostname ? hostname : host_addr_to_string(addr), port);
	}
}

/**
 * Search has detected index change in queued download.
 */
void
download_index_changed(const host_addr_t addr, uint16 port,
	const struct guid *guid, uint32 from, uint32 to)
{
	struct dl_server *server = get_server(guid, addr, port, FALSE);
	uint nfound = 0;
	pslist_t *to_stop = NULL;
	pslist_t *sl;
	uint n;
	enum dl_list listnum[] = { DL_LIST_RUNNING, DL_LIST_WAITING };

	if (!server)
		return;

	g_assert(dl_server_valid(server));

	for (n = 0; n < G_N_ELEMENTS(listnum); n++) {
		list_iter_t *iter;

		iter = list_iter_before_head(server->list[n]);
		while (list_iter_has_next(iter)) {
			struct download *d;

			d = list_iter_next(iter);
			download_check(d);
			if (d->record_index != from)
				continue;

			d->record_index = to;
			nfound++;

			switch (d->status) {
			case GTA_DL_REQ_SENT:
			case GTA_DL_HEADERS:
			case GTA_DL_PUSH_SENT:
				/*
				 * We've sent a request with possibly the wrong index.
				 * We can't know for sure, but it's safer to stop it, and
				 * restart it in a while.  Sure, we might lose the download
				 * slot, but we might as well have gotten a wrong file.
				 *
				 * NB: this can't happen when the remote peer is gtk-gnutella
				 * since we check the matching between the index and the file
				 * name, but some peers might not bother.
				 */
				g_message("stopping request for \"%s\": index changed",
					download_basename(d));
				to_stop = pslist_prepend(to_stop, d);
				break;
			case GTA_DL_RECEIVING:
				/*
				 * Ouch.  Pray and hope that the change occurred after we
				 * requested the file.	There's nothing we can do now.
				 */
				g_message("index of \"%s\" changed during reception",
					download_basename(d));
				break;
			default:
				/*
				 * Queued or other state not needing special notice
				 */
				if (GNET_PROPERTY(download_debug) > 3) {
					g_message("noted index change "
						"from %u to %u at %s for \"%s\"",
						from, to, guid_hex_str(guid), download_basename(d));
                }
				break;
			}
		}
		list_iter_free(&iter);
	}

	PSLIST_FOREACH(to_stop, sl) {
		struct download *d = sl->data;
		download_check(d);
		download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
			_("Stopped (Index changed)"));
	}
	pslist_free_null(&to_stop);

	/*
	 * This is a sanity check: we should not have any duplicate request
	 * in our download list.
	 */

	if (nfound > 1) {
		g_info("found %u requests for index %u (now %u) at %s",
			nfound, (uint) from, (uint) to,
			host_addr_port_to_string(addr, port));
    }
}

/**
 * Structure used to save download_new() parameters.
 */
struct download_request {
	host_addr_t addr;
	const struct guid *guid;
	const char *hostname;
	const char *filename;
	const struct sha1 *sha1;
	const struct tth *tth;
	const char *uri;
	const char *parq_id;
	gnet_host_vec_t *proxies;
	fileinfo_t *fi;
	filesize_t size;
	time_t stamp;
	uint32 flags;
	uint16 port;
};

/*
 * We create a download_request when a hostname is supplied for the server.
 * The name is first resolved asynchronously by the ADNS process, and then
 * we can call create_download().
 */
static struct download_request *
download_request_new(
	const char *filename,
	const char *uri,
	filesize_t size,
	host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	uint32 flags,
	const gnet_host_vec_t *proxies,
	const char *parq_id)
{
	static struct download_request zero_req;
	struct download_request *req;

	g_return_val_if_fail(filename, NULL);

	WALLOC(req);
	*req = zero_req;

	req->filename = atom_str_get(filename);
	req->uri = uri ? atom_str_get(uri) : NULL;
	req->size = size;
	req->addr = addr;
	req->port = port;
	req->guid = guid ? atom_guid_get(guid) : NULL;
	req->hostname = hostname ? atom_str_get(hostname) : NULL;
	req->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
	req->tth = tth ? atom_tth_get(tth) : NULL;
	req->stamp = stamp;
	if (fi) {
		req->fi = fi;
		g_assert(req->fi->refcount < INT_MAX);
		req->fi->refcount++;
	}
	req->flags = flags;
	req->proxies = proxies ? gnet_host_vec_copy(proxies) : NULL;
	req->parq_id = parq_id ? atom_str_get(parq_id) : NULL;
	return req;
}

static void
download_request_free(struct download_request **req_ptr)
{
	struct download_request *req;
	
	g_assert(req_ptr);

	req = *req_ptr;
	g_assert(req);

	*req_ptr = NULL;
	atom_str_free_null(&req->uri);
	atom_sha1_free_null(&req->sha1);
	atom_tth_free_null(&req->tth);
	atom_str_free_null(&req->hostname);
	atom_str_free_null(&req->filename);
	atom_str_free_null(&req->parq_id);
	atom_guid_free_null(&req->guid);
	gnet_host_vec_free(&req->proxies);
	if (req->fi) {
		g_assert(req->fi->refcount > 0);
		req->fi->refcount--;
	}
	WFREE(req);
}

/**
 * Called when we got a reply from the ADNS process.
 */
static void
download_new_by_hostname_helper(const host_addr_t *addrs, size_t n,
	void *user_data)
{
	struct download_request *req = user_data;

	g_assert(addrs);
	g_assert(req);

	if (n > 0) {
		size_t i = random_value(n - 1);

		/**
		 * @todo TODO: All resolved addresses should be attempted.
		 */
		create_download(req->filename,
			req->uri,
			req->size,
			addrs[i],
			req->port,
			req->guid,
			req->hostname,
			req->sha1,
			req->tth,
			req->stamp,
			req->fi,
			NULL,
			req->flags,
			req->parq_id);
	}
	download_request_free(&req);
}

/**
 * Resolve the hostname of the download request so that we can invoke
 * create_download() once we know the IP address.
 */
static void
download_new_by_hostname(struct download_request *req)
{
	g_assert(req);
	g_assert(req->hostname);

	adns_resolve(req->hostname, settings_dns_net(),
		download_new_by_hostname_helper, req);
}

/**
 * Create a new download, usually called from an interactive user action.
 *
 * @return whether download was created.
 */
bool
download_new(const char *filename,
	const char *uri,
	filesize_t size,
	const host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const char *hostname,
	const struct sha1 *sha1,
	const struct tth *tth,
	time_t stamp,
	fileinfo_t *fi,
	const gnet_host_vec_t *proxies,
	uint32 flags,
	const char *parq_id)
{
	if (hostname) {
		struct download_request *req;

		req = download_request_new(filename,
				uri,
				size,
				addr,
				port,
				guid,
				hostname,
				sha1,
				tth,
				stamp,
				fi,
				flags,
				proxies,
				parq_id);

		download_new_by_hostname(req);
		return TRUE;
	}
	return NULL != create_download(filename, uri, size, addr,
					port, guid, hostname, sha1, tth, stamp,
					fi, proxies, flags, parq_id);
}

/**
 * Fake a new download for an existing file that is marked complete in
 * its fileinfo trailer.
 */
void
download_orphan_new(const char *filename, filesize_t size,
	const struct sha1 *sha1, fileinfo_t *fi)
{
	time_t ntime;
	struct download *d;
   
	file_info_check(fi);

	ntime = fi->ntime;
	d = create_download(filename,
			NULL,	/* uri */
		   	size,
			ipv4_unspecified,	/* for host_addr_initialized() */
			0,		/* port */
			NULL,	/* GUID */
			NULL,	/* hostname*/
			sha1,
			NULL,	/* TTH */
			tm_time(),
			fi,
			NULL,	/* proxies */
			0,		/* cflags */
			NULL	/* PARQ ID */
	);
	fi->ntime = ntime;

	if (GNET_PROPERTY(download_debug)) {
		g_warning("%s orphan download for \"%s\"",
			d ? "created" : "could not create", filename);
	}
}

/**
 * Free all downloads listed in the `sl_removed' list.
 */
void
download_free_removed(void)
{
	pslist_t *sl;

	if (sl_removed == NULL)
		return;

	PSLIST_FOREACH(sl_removed, sl) {
		struct download *d = sl->data;

		download_check(d);
		g_assert(d->status == GTA_DL_REMOVED);

		download_reclaim_server(d, TRUE);	/* Delays freeing of server */

		hash_list_remove(sl_downloads, d);
		hash_list_remove(sl_unqueued, d);

		download_free(&d);
	}

	pslist_free_null(&sl_removed);

	PSLIST_FOREACH(sl_removed_servers, sl) {
		struct dl_server *s = sl->data;
		free_server(s);
	}

	pslist_free_null(&sl_removed_servers);
}

/* ----------------------------------------- */

/**
 * Does the download layer know information about a given GUID?
 *
 * If yes, return TRUE and fill in the ``addr'', ``port' and ``proxies''
 * argument.  If there are no push-proxies known, ``proxies'' is written
 * with a NULL pointer.
 *
 * @attention
 * It is up to the caller to release the memory allocated for the proxies
 * sequence through a call to sequence_release().
 */
bool
download_known_guid(const struct guid *guid,
	host_addr_t *addr, uint16 *port, sequence_t **proxies)
{
	struct dl_server *server;

	server = htable_lookup(dl_by_guid, guid);
	if (server == NULL)
		return FALSE;

	if (addr != NULL)
		*addr = server->key->addr;
	if (port != NULL)
		*port = server->key->port;
	if (proxies != NULL) {
		*proxies = server->proxies ?
			pproxy_set_sequence(server->proxies) : NULL;
	}

	return TRUE;
}

/**
 * Forget about download: stop it if running.
 * When `unavailable' is TRUE, mark the download as unavailable.
 */
void
download_forget(struct download *d, bool unavailable)
{
	download_check(d);

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	if (DOWNLOAD_IS_QUEUED(d))
		download_unqueue(d, FALSE);

	if (unavailable)
		download_unavailable(d, GTA_DL_ABORTED, no_reason);
	else
		download_stop(d, GTA_DL_ABORTED, no_reason);
}

/**
 * Abort download (forget about it) AND delete file if we removed the last
 * reference to it and they want to delete on abort.
 */
void
download_abort(struct download *d)
{
	download_check(d);
	file_info_check(d->file_info);

	if (d->file_info->lifecount > 0)
		download_forget(d, FALSE);

	/*
	 * The refcount isn't decreased until "Clear completed", so
	 * we may very well have a file with a high refcount and no active
	 * or queued downloads.  This is why we maintain a lifecount.
	 */

	if (d->file_info->lifecount == 0)
		if (GNET_PROPERTY(download_delete_aborted))
			download_remove_file(d, FALSE);
}

void
download_request_abort(struct download *d)
{
	download_check(d);
	g_return_if_fail(d->file_info);
	file_info_check(d->file_info);

	download_abort(d);
}

static void
download_resume(struct download *d)
{
	download_check(d);
	file_info_check(d->file_info);

	if (
		FILE_INFO_FINISHED(d->file_info) ||
		!DOWNLOAD_IS_STOPPED(d) ||
		!DOWNLOAD_IS_QUEUED(d) ||
		DOWNLOAD_IS_RUNNING(d) ||
		DOWNLOAD_IS_WAITING(d)
	) {
		return;
	}

	g_return_if_fail(d->list_idx == DL_LIST_STOPPED);

	if (
		server_has_same_download(d->server, d->file_name, d->sha1, d->file_size)
	) {
		download_force_stop(d, _("Duplicate download"));
		return;
	}

	download_start(d, TRUE);
}

void
download_request_resume(struct download *d)
{
	download_check(d);
	g_return_if_fail(d->file_info);
	file_info_check(d->file_info);

	if (!FILE_INFO_FINISHED(d->file_info)) {
		d->flags &= ~DL_F_PAUSED;
		file_info_resume(d->file_info);
		download_resume(d);
	}
}

/**
 * Explicitly re-enqueue potentially stopped download.
 */
static void
download_requeue(struct download *d)
{
	download_check(d);
	file_info_check(d->file_info);

	g_return_if_fail(!FILE_INFO_FINISHED(d->file_info));
	g_return_if_fail(!DOWNLOAD_IS_QUEUED(d));
	g_return_if_fail(!DOWNLOAD_IS_VERIFYING(d));

	g_return_if_fail(d->file_info->lifecount > 0);
	download_queue(d, _("Explicitly requeued"));
}

void
download_request_requeue(struct download *d)
{
	download_check(d);
	g_return_if_fail(d->file_info);
	file_info_check(d->file_info);

	if (FILE_INFO_FINISHED(d->file_info))
		return;
	if (DOWNLOAD_IS_QUEUED(d))
		return;
	if (DOWNLOAD_IS_VERIFYING(d))		/* Can't requeue: it's done */
		return;

	download_requeue(d);
}

/**
 * Do we have push-proxies to use for a download?
 */
static bool
has_push_proxies(const struct download *d)
{
	struct dl_server *server = d->server;

	download_check(d);
	g_assert(dl_server_valid(server));

	return server->proxies != NULL &&
		pproxy_set_count(server->proxies) > 0 && !has_blank_guid(d);
}

/**
 * Try to setup the download to use the push proxies available on the server.
 *
 * @returns TRUE is we can use a push proxy.
 */
static bool
use_push_proxy(struct download *d)
{
	struct dl_server *server = d->server;

	download_check(d);
	g_assert(!has_blank_guid(d));
	g_assert(dl_server_valid(server));

	if (d->cproxy != NULL) {
		struct cproxy *cp = d->cproxy;
		if (!cp->sent) {
			remove_proxy(d->server, cproxy_addr(cp), cproxy_port(cp));
		}
		cproxy_free(cp);
		d->cproxy = NULL;
	}

	if (server->proxies != NULL) {
		const gnet_host_t *host = pproxy_set_head(server->proxies);

		if (host != NULL) {
			d->cproxy = cproxy_create(d,
				gnet_host_get_addr(host), gnet_host_get_port(host),
				download_guid(d), d->record_index);

			/* Will read status in d->cproxy */
			fi_src_status_changed(d);
		}
	}

	if (d->cproxy != NULL && download_is_running(d)) {
		d->last_update = tm_time();
	}

	return d->cproxy != NULL;
}

/**
 * Attempt to move to the next push proxy if we were unable to send the
 * push message through the current one.
 *
 * @return TRUE if we selected a new push-proxy.
 */
static bool
next_push_proxy(struct download *d)
{
	download_check(d);
	g_assert(!has_blank_guid(d));

	if (d->cproxy != NULL) {
		struct cproxy *cp = d->cproxy;
		if (cp->sent)
			return FALSE;
		return use_push_proxy(d);
	}

	return FALSE;
}

/**
 * Called when the status of the HTTP request made by the client push-proxy
 * code changes.
 */
void
download_proxy_newstate(struct download *d)
{
	download_check(d);
	/* Will read status in d->cproxy */
	fi_src_status_changed(d);
}

/**
 * Called by client push-proxy side when we got indication that the PUSH
 * has been sent.
 */
void
download_proxy_sent(struct download *d)
{
	download_check(d);
	/* Will read status in d->cproxy */
	fi_src_status_changed(d);
}

/**
 * Called by client push-proxy side to indicate that it could not send a PUSH.
 */
void
download_proxy_failed(struct download *d)
{
	struct cproxy *cp;

	download_check(d);

	cp = d->cproxy;
	g_assert(cp != NULL);

	/* Will read status in d->cproxy */
	fi_src_status_changed(d);

	remove_proxy(d->server, cproxy_addr(cp), cproxy_port(cp));
	cproxy_free(d->cproxy);
	d->cproxy = NULL;

	if (!use_push_proxy(d))
		download_retry(d);
}

/*
 * IO functions
 */

/**
 * Send a UDP push packet to specified host.
 *
 * @return TRUE on success.
 */
bool
download_send_udp_push(
	const struct array packet, host_addr_t addr, uint16 port)
{
	bool success = FALSE;
	
	if (host_is_valid(addr, port)) {
		struct gnutella_node *n = node_udp_get_addr_port(addr, port);

		if (n != NULL) {
			success = TRUE;
			udp_send_msg(n, packet.data, packet.size);
		}
	}
	return success;
}

/**
 * Send a UDP push packet to specified G2 host.
 *
 * @return TRUE on success.
 */
static bool
download_g2_send_udp_push(const pmsg_t *mb, host_addr_t addr, uint16 port)
{
	bool success = FALSE;

	if (host_is_valid(addr, port)) {
		struct gnutella_node *n = node_udp_g2_get_addr_port(addr, port);

		if (n != NULL) {
			success = TRUE;
			g2_node_send(n, pmsg_clone(mb));
		}
	}
	return success;
}

/**
 * Send a push request to the target GUID, in order to request a remote
 * connection from the host.
 *
 * We're very aggressive: we can send a PUSH via UDP to the host itself,
 * as well as the 4 most recent push proxies when `udp' is set.
 * We can also broadcast to the G2 nodes if `broadcast' is set.
 *
 * @returns TRUE if the request could be sent, FALSE if we don't have the route.
 */
static bool
download_g2_send_push(struct download *d, const pmsg_t *mb,
	bool udp, bool broadcast)
{
	bool success = FALSE;

	download_check(d);

	/* Pure luck: try to reach the remote host directly via UDP... */
	if (udp) {
		download_g2_send_udp_push(mb, download_addr(d), download_port(d));
	}

	if (udp && has_push_proxies(d)) {
		sequence_t *seq = pproxy_set_sequence(d->server->proxies);
		sequence_iter_t *iter = sequence_forward_iterator(seq);
		int i = 0;

		while (i < DOWNLOAD_MAX_UDP_PUSH && sequence_iter_has_next(iter)) {
			gnet_host_t *host = sequence_iter_next(iter);

			if (
				download_g2_send_udp_push(mb,
					gnet_host_get_addr(host), gnet_host_get_port(host))
			) {
				i++;
			}
		}
		sequence_iterator_release(&iter);
		sequence_release(&seq);
		success = i > 0;
	}

	if (broadcast) {
		const pslist_t *sl;

		/*
		 * Send the message to all the hubs since on G2 we cannot track
		 * push routes at the leaf-node level.
		 */

		PSLIST_FOREACH(node_all_g2_nodes(), sl) {
			const gnutella_node_t *n = sl->data;

			g2_node_send(n, pmsg_clone(mb));
			success = TRUE;
		}
	}

	return success;
}

/**
 * Send a push request to the target GUID, in order to request a connection
 * from the remote host.
 *
 * We're very aggressive: we can send a PUSH via UDP to the host itself,
 * as well as the 4 most recent push proxies when `udp' is set.
 * We can also broadcast to the proper routes on Gnutella if `broadcast' is set.
 *
 * @returns TRUE if the request could be sent, FALSE if we don't have the route.
 */
static bool
download_send_push(struct download *d, const struct array packet,
	bool udp, bool broadcast)
{
	bool success = FALSE;

	download_check(d);

	/* Pure luck: try to reach the remote host directly via UDP... */
	if (udp) {
		download_send_udp_push(packet, download_addr(d), download_port(d));
	}

	if (udp && has_push_proxies(d)) {
		sequence_t *seq = pproxy_set_sequence(d->server->proxies);
		sequence_iter_t *iter = sequence_forward_iterator(seq);
		int i = 0;

		while (i < DOWNLOAD_MAX_UDP_PUSH && sequence_iter_has_next(iter)) {
			gnet_host_t *host = sequence_iter_next(iter);

			if (
				download_send_udp_push(packet,
					gnet_host_get_addr(host), gnet_host_get_port(host))
			) {
				i++;
			}
		}
		sequence_iterator_release(&iter);
		sequence_release(&seq);
		success = i > 0;
	}

	if (broadcast) {
		pslist_t *nodes = route_towards_guid(download_guid(d));

		if (nodes != NULL) {
			/*
			 * Send the message to all the nodes that can route our
			 * request back to the source of the query hit.
			 */

			gmsg_sendto_all(nodes, packet.data, packet.size);
			pslist_free(nodes);
			success = TRUE;
		}
	}

	return success;
}

/**
 * Send a push request to the target GUID, in order to request a remote
 * connection from the host.
 *
 * We're very aggressive: we can send a PUSH via UDP to the host itself,
 * as well as the 4 most recent push proxies when `udp' is set.
 * We can also broadcast to the proper routes if `broadcast' is set.
 *
 * @returns TRUE if the request could be sent, FALSE if we don't have the route.
 */
static bool
download_send_push_request(struct download *d, bool udp, bool broadcast)
{
	uint16 port;
	bool success = FALSE;

	download_check(d);

	if (!(udp || broadcast))
		return FALSE;

	port = socket_listen_port();
	if (0 == port)
		return FALSE;

	if (download_is_g2(d)) {
		pmsg_t *mb = g2_build_push(download_guid(d));

		if (NULL == mb)
			goto done;

		success = download_g2_send_push(d, mb, udp, broadcast);
		pmsg_free(mb);
	} else {
		const struct array packet =
			build_push(GNET_PROPERTY(max_ttl), 0 /* Hops */,
				download_guid(d), listen_addr(), listen_addr6(), port,
				d->record_index, tls_enabled());

		if (NULL == packet.data)
			goto done;

		success = download_send_push(d, packet, udp, broadcast);
	}

	if (success && download_is_running(d)) {
		d->last_update = tm_time();
	}

	/* FALL THROUGH */

done:
	if (!success && GNET_PROPERTY(download_debug)) {
		g_warning("failed to send %sPUSH (udp=%s, %s=%s) "
			"for %s (index=%lu)",
			download_is_g2(d) ? "G2 " : "",
			udp ? "y" : "n",
			download_is_g2(d) ? "g2" : "gnet", broadcast ? "y" : "n",
			host_addr_port_to_string(download_addr(d), download_port(d)),
				(ulong) d->record_index);
	}

	return success;
}

/**
 * Extract server name from headers.
 *
 * @returns whether new server name was found.
 */
static bool
download_get_server_name(struct download *d, header_t *header)
{
	const char *user_agent;
	bool got_new_server = FALSE;

	download_check(d);

	user_agent = header_get(header, "Server");			/* Mandatory */
	if (!user_agent)
		user_agent = header_get(header, "User-Agent"); /* Are they confused? */

	if (user_agent) {
		struct dl_server *server = d->server;
		const char *vendor;
		char *wbuf = NULL;
		size_t size = 0;
		bool faked;
	   
		g_assert(dl_server_valid(server));

		if (NULL == user_agent || !is_strprefix(user_agent, "gtk-gnutella/")) {
			socket_disable_token(d->socket);
		}

		/*
		 * Make sure the address is valid, because we may have to call
		 * clock_update() through version_check() when we have a gtk-gnutella
		 * host, and if the connection is pushed, the server address may
		 * bear an invalid address.
		 *
		 * Hence, do not use download_addr() but fetch the address from the
		 * socket, directly.
		 */

		faked = !version_check(user_agent, header_get(header, "X-Token"),
					d->socket->addr);

		if (server->vendor == NULL) {
			got_new_server = TRUE;
			if (faked)
				size = w_concat_strings(&wbuf, "!", user_agent, (void *) 0);
			vendor = wbuf ? wbuf : user_agent;
		} else if (!faked && 0 != strcmp(server->vendor, user_agent)) {
			/* Name changed? */
			got_new_server = TRUE;
			atom_str_free_null(&server->vendor);
			vendor = user_agent;
		} else {
			vendor = NULL;
		}
	
		if (vendor) {
			server->vendor = atom_str_get(lazy_iso8859_1_to_utf8(vendor));
			server->attrs &= ~DLS_A_FAKED_VENDOR;
		}
		if (wbuf) {
			wfree(wbuf, size);
			wbuf = NULL;
		}
	}

	return got_new_server;
}

/***
 *** I/O header parsing callbacks
 ***/

static inline struct download *
cast_to_download(void *p)
{
	struct download *d = p;
	download_check(d);
	return d;
}

static void
err_line_too_long(void *o, header_t *head)
{
	struct download *d = cast_to_download(o);

	download_get_server_name(d, head);
	download_stop(d, GTA_DL_ERROR, _("Failed (Header line too large)"));
}

static void
err_header_error(void *o, int error)
{
	download_stop(cast_to_download(o), GTA_DL_ERROR,
		_("Failed (%s)"), header_strerror(error));
}

static void
err_input_buffer_full(void *o)
{
	struct download *d = cast_to_download(o);
	download_stop(d, GTA_DL_ERROR, _("Failed (Input buffer full)"));
}

static void
err_header_read_error(void *o, int error)
{
	struct download *d = cast_to_download(o);

	download_check(d);
	download_repair(d, g_strerror(error));
}

static void
err_header_read_eof(void *o, header_t *header)
{
	struct download *d = cast_to_download(o);
	uint32 delay = GNET_PROPERTY(download_retry_stopped_delay);

	download_get_server_name(d, header);

	/*
	 * If we get no output at all from the remote peer (i.e. the connection
	 * is closed immediately), retry with TLS, if supported locally.
	 */

	if (tls_enabled() && io_get_read_bytes(d->io_opaque) == 0) {
		/*
		 * Maybe we should try to initiate a TLS connection if we have not
		 * done so already?
		 */

		if (
			!socket_with_tls(d->socket) && !(d->flags & DL_F_TRIED_TLS) &&
			!d->keep_alive
		) {
			d->flags |= DL_F_TRIED_TLS | DL_F_TRY_TLS;

			if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(tls_debug))
				g_debug("will try to reach server %s with TLS for \"%s\"",
					download_host_info(d), download_basename(d));
		}
	}

	/*
	 * Note: zero HTTP header line is different from zero output as we
	 * can get at least the HTTP status line.
	 */

	if (header_num_lines(header) == 0) {
		if (!(d->flags & DL_F_TRY_TLS)) {
			/*
			 * Maybe we sent HTTP header continuations and the server does not
			 * understand them, breaking the connection on "invalid" request.
			 * Use minimalist HTTP then when talking to this server!
			 */

			d->server->attrs |= DLS_A_MINIMAL_HTTP;
			d->header_read_eof++;		/* Will count twice: no header is bad */
		}
	} else {
		/*
		 * As some header lines were read, we could at least try to get the
		 * server's name so we can display it.
		 *		-- JA, 22/03/2003
		 */
		download_get_server_name(d, header);
	}

	if (++d->header_read_eof >= DOWNLOAD_MAX_HEADER_EOF) {
		/*
		 * Seen too many errors whilst connecting, probably because
		 * the remote end is closing the connection immediately when it
		 * sees our IP address.  Fair enough, but we can't allow that
		 * host from getting replies from us either, for some time.
		 *		--RAM, 2007-05-23
		 */

		d->server->attrs |= DLS_A_BANNING;		/* Probably... */
		ban_record(download_addr(d), "IP probably denying uploads");
		upload_kill_addr(download_addr(d));
		delay = MAX(delay, DOWNLOAD_BAN_DELAY);

		if (GNET_PROPERTY(download_debug))
			g_debug(
				"server %s might be banning us (too many EOF for \"%s\")",
				download_host_info(d), download_basename(d));

		/*
		 * This is a bet: the Shareaza folks changed their strategy.
		 */

		if (d->flags & DL_F_FAKE_G2) {
			delay += 120 * (d->header_read_eof - DOWNLOAD_MAX_HEADER_EOF);
			if (
				d->header_read_eof >= DOWNLOAD_MAX_HEADER_EOF + 5 &&
				!(d->server->attrs & DLS_A_G2_ONLY)
			) {
				if (GNET_PROPERTY(download_debug))
					g_debug(
						"server %s didn't respond to G2 faking for \"%s\"",
						download_host_info(d), download_basename(d));

				d->server->attrs &= ~DLS_A_FAKE_G2;
				d->flags &= ~DL_F_FAKE_G2;
				if (d->server->attrs & DLS_A_FAKED_VENDOR) {
					atom_str_free_null(&d->server->vendor);
					d->server->attrs &= ~DLS_A_FAKED_VENDOR;
				}
			}
		} else if (GNET_PROPERTY(enable_hackarounds)) {
			d->server->attrs |= DLS_A_FAKE_G2;
			d->flags |= DL_F_FAKE_G2;

			if (GNET_PROPERTY(download_debug))
				g_debug("will now attempt G2 faking at server %s for \"%s\"",
					download_host_info(d), download_basename(d));

			if (d->server->vendor == NULL) {
				d->server->attrs |= DLS_A_FAKED_VENDOR;
				d->server->vendor = atom_str_get("Shareaza?");
			}
		}
	}

	if (d->retries < GNET_PROPERTY(download_max_retries)) {
		d->retries++;
		download_queue_delay(d, delay,
			d->keep_alive ? _("Connection not kept-alive (EOF)") :
			_("Stopped (EOF) <err_header_read_eof>"));
	} else
		download_unavailable(d, GTA_DL_ERROR,
			_("Too many attempts (%u times)"), d->retries);
}

static struct io_error download_io_error = {
	err_line_too_long,
	NULL,
	err_header_error,
	err_header_read_eof,		/* Input exception, assume EOF */
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	NULL,
};

static void
download_start_reading(void *o)
{
	struct download *d = cast_to_download(o);
	tm_t now;
	uint32 latency;

	/*
	 * Compute the time it took since we sent the headers, and update
	 * the fast EMA (n=7 terms) storing the HTTP latency, in msecs.
	 *
	 * If the request was pipelined, we can't really compute the latency
	 * since it was sent before the previous request was completed.
	 */

	if (!(d->flags & DL_F_PIPELINED)) {
		time_delta_t elapsed;
		struct dl_server *server = d->server;

		tm_now(&now);
		elapsed = tm_elapsed_ms(&now, &d->header_sent);

		g_assert(dl_server_valid(server));

		gnet_prop_get_guint32_val(PROP_DL_HTTP_LATENCY, &latency);
		latency += (elapsed >> 2) - (latency >> 2);
		gnet_prop_set_guint32_val(PROP_DL_HTTP_LATENCY, latency);
		server->latency += (elapsed >> 2) - (server->latency >> 2);
	} else {
		d->flags &= ~DL_F_PIPELINED;
	}

	/*
	 * Update status and GUI, timestamp start of header reading.
	 */

	download_set_status(d, GTA_DL_HEADERS);
	d->last_update = tm_time();			/* Starting reading */
}

static void
call_download_request(void *o, header_t *header)
{
	download_request(cast_to_download(o), header, TRUE);
}

static void
call_download_push_ready(void *o, header_t *unused_header)
{
	struct download *d = cast_to_download(o);

	(void) unused_header;
	download_push_ready(d, io_getline(d->io_opaque));
}

/**
 * Forget that we ever downloaded some bytes when there was a resuming
 * mismatch at some point.
 */
static void
download_backout(struct download *d)
{
	filesize_t begin, end;
	uint32 backout;

	/*
	 * It is most likely that we have a mismatch because
	 * the other guy's data is not in order, but we could
	 * also have received bad data ourselves. Just to be
	 * sure we back out some of our data. Eventually we
	 * should find a host with good data, or we have
	 * backed out enough times for our data to be good
	 * again. This really is a stop-gap measure that TTH
	 * will fill in a more permanent way.
	 */

	end = d->chunk.start + 1;
	gnet_prop_get_guint32_val(PROP_DL_MISMATCH_BACKOUT, &backout);
	if (end >= backout)
		begin = end - backout;
	else
		begin = 0;
	file_info_update(d, begin, end, DL_CHUNK_EMPTY);
	g_message("resuming data mismatch on %s, backed out %u bytes block"
		" from %s to %s",
		 download_basename(d), (uint) backout,
		 uint64_to_string(begin), uint64_to_string2(end));
}

/**
 * Check that the leading overlapping data in the read buffers match with
 * the last ones in the downloaded file.  Then remove them.
 *
 * @returns TRUE if the data match, FALSE if they don't, in which case the
 * download is stopped.
 */
static bool
download_overlap_check(struct download *d)
{
	file_object_t *fo;
	fileinfo_t *fi;
	bool success = FALSE;
	char *data = NULL;

	download_check(d);
	fi = d->file_info;
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);
	g_assert(d->buffers->held >= d->chunk.overlap);

	fo = file_object_open(fi->pathname, O_RDONLY);
	if (NULL == fo) {
		const char *error = g_strerror(errno);
		g_warning("cannot check resuming for \"%s\": %m",
			filepath_basename(fi->pathname));
		download_stop(d, GTA_DL_ERROR, _("Can't check resume data: %s"), error);
		goto out;
	}

	{
		filestat_t sb;

		if (-1 == file_object_fstat(fo, &sb)) {
			/* Should never happen */
			const char *error = g_strerror(errno);
			g_warning("cannot stat opened \"%s\": %m", fi->pathname);
			download_stop(d, GTA_DL_ERROR, _("Can't stat opened file: %s"),
				error);
			goto out;
		}

		/*
		 * Sanity check: if the file is bigger than when we started, abort
		 * immediately.
		 */

		if (!fi->use_swarming && d->chunk.start != fi->done) {
			g_message("file '%s' changed size (now %s, but was %s)",
					fi->pathname, uint64_to_string(sb.st_size),
					uint64_to_string2(d->chunk.start));
			download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
					_("Stopped (Output file size changed)"));
			goto out;
		}
	}

	{
		ssize_t r;

		data = walloc(d->chunk.overlap);
		g_assert(d->chunk.start >= d->chunk.overlap);
		r = file_object_pread(fo, data, d->chunk.overlap,
				d->chunk.start - d->chunk.overlap);

		if ((ssize_t) -1 == r) {
			const char *error = g_strerror(errno);
			g_warning("cannot read resuming data for \"%s\": %m",
					fi->pathname);
			download_stop(d, GTA_DL_ERROR, _("Can't read resume data: %s"),
				error);
			goto out;
		} else if ((size_t) r != d->chunk.overlap) {
			g_warning(
				"short read (got %zu instead of %u bytes at offset %zu) "
				"on resuming data for \"%s\"",
				r, d->chunk.overlap, (size_t) d->chunk.start - d->chunk.overlap,
				fi->pathname);
			download_stop(d, GTA_DL_ERROR, _("Short read on resume data"));
			goto out;
		}
	}

	if (!buffers_match(d, data, d->chunk.overlap)) {
		/*
		 * Resuming data mismatch.
		 */

		if (GNET_PROPERTY(download_debug) > 1) {
			g_debug("%u overlapping bytes UNMATCHED at offset %s for \"%s\"",
				(uint) d->chunk.overlap,
				uint64_to_string(d->chunk.start - d->chunk.overlap),
				download_basename(d));
        }

		d->pos += d->buffers->held;	/* Keep track of what we read so far */
		d->pos -= d->chunk.overlap;	/* Overlap did not count as chunk data */
		d->mismatches++;
		buffers_discard(d);			/* Discard everything we read so far */

		if (GNET_PROPERTY(dl_remove_file_on_mismatch)) {
			download_bad_source(d);	/* Until proven otherwise if we resume it */
			download_queue(d, _("Resuming data mismatch @ %s"),
				uint64_to_string(d->chunk.start - d->chunk.overlap));
			download_remove_file(d, TRUE);
			goto out;
		}

		/*
		 * If we have not seen too many resuming mismatches from this source,
		 * maybe we got fooled earlier and downloaded some bad data.  Give
		 * this source a chance: if we don't have too much data requested,
		 * simply ignore them and get a chance to issue a new request later.
		 *		--RAM, 2007-05-05
		 */

		download_backout(d);	/* Forget some bytes at mismatch point */

		if (
			d->mismatches <= DOWNLOAD_MAX_IGN_REQS &&
			d->keep_alive &&
			download_can_ignore(d)
		) {
			success = TRUE;			/* Act as if overlapping was OK */
			gnet_stats_inc_general(GNR_IGNORING_AFTER_MISMATCH);
			goto out;
		}

		download_bad_source(d);	/* Until proven otherwise if we resume it */

		/*
		 * Don't always keep this source, and since there is doubt,
		 * leave it to randomness.
		 */

		if (random_value(99) >= 50)
			download_stop(d, GTA_DL_ERROR,
				_("Resuming data mismatch @ %s"),
				uint64_to_string(d->chunk.start - d->chunk.overlap));
		else
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				_("Resuming data mismatch @ %s"),
				uint64_to_string(d->chunk.start - d->chunk.overlap));
		goto out;
	}

	/*
	 * Great, resuming data matched!
	 * Remove the overlapping data from the read buffers.
	 */

	buffers_check_held(d);
	buffers_strip_leading(d, d->chunk.overlap);
	buffers_check_held(d);

	if (GNET_PROPERTY(download_debug) > 3)
		g_debug("%u overlapping bytes MATCHED "
			"at offset %s for \"%s\"",
			(uint) d->chunk.overlap,
			uint64_to_string(d->chunk.start - d->chunk.overlap),
			download_basename(d));

	success = TRUE;

out:
	WFREE_NULL(data, d->chunk.overlap);
	file_object_release(&fo);

	return success;
}

/**
 * Flush buffered data to disk.
 *
 * @param d			the download to flush
 * @param trimmed	if not NULL, filled with whether we trimmed data or not
 * @param may_stop	whether we can stop the download on errors
 *
 * @return TRUE if OK, FALSE on failure.
 */
static bool
download_flush(struct download *d, bool *trimmed, bool may_stop)
{
	struct dl_buffers *b;
	ssize_t written;
	filesize_t old_pos;		/* For assertion: original d->pos */
	filesize_t old_held;	/* For assertion: original buffered amount */

	download_check(d);
	b = d->buffers;
	g_assert(b != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	if (GNET_PROPERTY(download_debug) > 10)
		g_debug("flushing %lu bytes (%u buffers) for \"%s\"%s",
			(ulong) b->held, slist_length(b->list),
			download_basename(d), may_stop ? "" : " on stop");

	/*
	 * We can't have data going farther than what we requested from the
	 * server.  But if we do, trim and warn.  And mark the server as not
	 * being capable of handling keep-alive connections correctly!
	 */

	if (b->held > d->chunk.end - d->pos) {
		filesize_t extra = b->held - (d->chunk.end - d->pos);

		if (GNET_PROPERTY(download_debug)) g_debug(
			"server %s gave us %s more byte%s than requested for \"%s\"",
			download_host_info(d), uint64_to_string(extra),
			plural(extra), download_basename(d));

		buffers_check_held(d);
		buffers_strip_trailing(d, extra);
		buffers_check_held(d);

		if (trimmed)
			*trimmed = TRUE;

		g_assert(b->held > 0);	/* We had not reached end previously */
	} else if (trimmed) {
		*trimmed = FALSE;
	}


	/**
	 * writev() and others do not necessarily flush the complete buffer
	 * to disk, especially if the configured buffer size is large. As
	 * this is not handled gracefully i.e., the non-flushed buffer content
	 * would be discarded, we loop here until the complete buffer has
	 * been flushed or an error occurs. With large buffer sizes or a
	 * slow disk, this may of course increase the latency and cause some
	 * stalling. The right thing to do would be keeping the buffered
	 * data and attempting another flush next time.
	 */

	written = 0;
	old_held = download_buffered(d);
	old_pos = d->pos;

	do {
		iovec_t *iov;
		ssize_t ret;
		int n;

		buffers_check_held(d);

		/*
		 * Prepare I/O vector for writing.
		 */

		iov = buffers_to_iovec(d, &n); 
		ret = file_object_pwritev(d->out_file, iov, n, d->pos);
		HFREE_NULL(iov);

		b->mode = DL_BUF_READING;

		if ((ssize_t) -1 == ret || 0 == ret) {
			if (0 == written) {
				written = ret;
			}
			break;
		} else {
			size_t size = (size_t) ret;
			
			g_assert(size <= b->held);

			file_info_update(d, d->pos, d->pos + size, DL_CHUNK_DONE);
			gnet_prop_set_guint64_val(PROP_DL_BYTE_COUNT,
				GNET_PROPERTY(dl_byte_count) + size);

			d->pos += size;
			written += size;

			buffers_strip_leading(d, size);
		}
	} while (b->held > 0);

	if ((ssize_t) -1 == written) {
		const char *error;

		switch (errno) {
		case ENOSPC:	/* No space left */
			queue_frozen_on_write_error = TRUE;
			/* FALL THROUGH */
		case EDQUOT:	/* quota exceeded */
		case EROFS:		/* read-only filesystem */
		case EIO:		/* I/O error */
			if (!download_queue_is_frozen()) {
				download_freeze_queue();
				g_warning("freezing download queue due to write error: %m");
			}
			break;
		}
	
	   	error = g_strerror(errno);
		g_warning("write of %lu bytes to file \"%s\" failed: %m",
			(ulong) b->held, download_basename(d));

		/* FIXME: We should never discard downloaded data! This
		 * causes a re-download of the same data. Instead we should
		 * keep the buffered data around and periodically try to
		 * flush the buffers. At least in the case of ENOSPC or
		 * EDQUOT when the disk filled up and the condition can
		 * be solved by the user but may hold for a long duration.
		 */

		if (may_stop)
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				_("Can't save data: %s"), error);

		return FALSE;
	}

	if (b->held > 0) {
		g_warning("partial write (written=%lu, still held=%lu) to file \"%s\"",
			(ulong) written, (ulong) b->held, download_basename(d));

		if (may_stop)
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				_("Partial write to file"));

		return FALSE;
	}

	g_assert(0 == b->held);
	g_assert((size_t) written == old_held);
	g_assert(d->pos - old_pos == old_held);

	buffers_discard(d);			/* Since we wrote everything... */

	return TRUE;
}

/**
 * Issue download_flush() if needed, discarding silently anything we cannot
 * commit to disk.
 */
static void
download_silent_flush(struct download *d)
{
	download_check(d);
	g_assert(d->buffers != NULL);
	g_assert(d->status != GTA_DL_IGNORING || 0 == d->buffers->held);
	g_assert(d->status == GTA_DL_IGNORING || d->status == GTA_DL_RECEIVING);

	if (d->buffers->held > 0) {
		download_flush(d, NULL, FALSE);
		if (d->buffers->held > 0) {
			buffers_discard(d);
		}
	}
}

/**
 * Called when a chunk has been fully received but the file is still incomplete
 * and more data is to be fetched.
 *
 * Continue downloading from this source, now that the previous chunk was
 * fully received: if the connection was flagged "keep alive", go on with
 * the next request.
 *
 * @param d			the download source whose request has been completed
 * @param trimmed	whether we had to trim the tail of the received data
 */
static void
download_continue(struct download *d, bool trimmed)
{
	struct download *cd, *next = NULL;
	struct gnutella_socket *s;
	bool can_continue;
	const struct sha1 *sha1 = NULL;

	download_check(d);

	/*
	 * Determine whether we can use this download for a follow-up request if
	 * download_pick_followup() finds no better candidate.
	 */

	can_continue = DOWNLOAD_IS_ACTIVE(d) && !FILE_INFO_COMPLETE(d->file_info);

	/*
	 * Also for THEX downloads, we need to save the SHA1 from the THEX context
	 * before calling download_stop(), since that will free up that information
	 * and it is not propagated to the cloned structure.
	 */

	if (d->thex) {
		sha1 = thex_download_get_sha1(d->thex);
		if (sha1)
			sha1 = atom_sha1_get(sha1);
	}

	/*
	 * Since a download structure is associated with a GUI line entry, we
	 * must clone it to be able to display the chunk as completed, yet
	 * continue downloading.
	 */

	cd = download_clone(d);
	download_stop(d, GTA_DL_COMPLETED, no_reason);

	cd->served_reqs++;		/* We got one more served request */

	/*
	 * If we had to trim the data requested, it means the server did not
	 * understand our Range: request properly, and it's going to send us
	 * more data.  Something weird happened, and we can't even think
	 * continuing with this connection.
	 */

	if (trimmed) {
		if (GNET_PROPERTY(download_debug))
			g_debug("had to trim data for \"%s\" (%.2f%%), served by %s",
				download_basename(cd), 100.0 * download_total_progress(cd),
				download_host_info(cd));

		download_queue(cd, _("Requeued after trimmed data"));
		goto cleanup;
	}
	if (!cd->keep_alive) {
		if (GNET_PROPERTY(download_debug))
			g_debug("connection not kept alive for \"%s\" (%.2f%%) by %s",
				download_basename(cd), 100.0 * download_total_progress(cd),
				download_host_info(cd));

		download_queue(cd, _("Chunk done, connection closed"));
		goto cleanup;
	}

	/* Steal the socket because download_stop() would free it. */
	s = cd->socket;
	socket_detach_ops(s);
	cd->socket = NULL;

	/*
	 * NOTE: Resetting s->pos was missing in download_request() for THEX
	 *       and browse downloads causing a "Weird HTTP status". Keep this
	 *       a warning instead of an assertion for now until it has seen
	 *       some testing. 2007-09-12
	 */
	if (s->pos > 0) {
		/* This should have already been fed to the RX stack. */
		g_carp("%s(): clearing socket buffer of %s",
			G_STRFUNC, download_host_info(d));
	}
	s->pos = 0;

	/*
	 * If we pipelined a request, we have to grab its output before
	 * thinking about switching to another resource.
	 */

	if (download_pipelining(cd)) {
		next = cd;
	} else {
		next = download_pick_followup(cd, sha1);
	}

	if (cd != next) {
		if (GNET_PROPERTY(download_debug))
			g_debug("switching from \"%s\" (%.2f%%) to \"%s\" (%.2f%%) at %s",
				download_basename(cd), 100.0 * download_total_progress(cd),
				download_basename(next), 100.0 * download_total_progress(next),
				download_host_info(next));

		g_assert(NULL == next->socket);

		gnet_stats_inc_general(GNR_ATTEMPTED_RESOURCE_SWITCHING);

		next->socket = s;
		socket_attach_ops(s, SOCK_TYPE_DOWNLOAD, &download_socket_ops, next);
		next->flags |= DL_F_SWITCHED;
		if (!download_is_special(cd))
			next->flags |= DL_F_FROM_PLAIN;

		if (can_continue) {
			download_queue(cd, _("Switching to \"%s\""),
				download_basename(next));
		} else {
			download_stop(cd, GTA_DL_COMPLETED,
				_("Switching to \"%s\""), download_basename(next));
		}
	} else if (can_continue) {
		next = cd;
		next->socket = s;
		socket_attach_ops(s, SOCK_TYPE_DOWNLOAD, &download_socket_ops, next);
	} else {
		download_stop(cd, GTA_DL_COMPLETED, _("Nothing else to switch to"));
		socket_free_null(&s);
		next = NULL;
	}

	if (next && download_start_prepare(next)) {
		next->keep_alive = TRUE;			/* Was reset by _prepare() */
		download_send_request(next);		/* Will pick up new range */
	}

cleanup:
	atom_sha1_free_null(&sha1);
}

/**
 * Write data in socket buffer to file.
 *
 * @return FALSE if an error occurred.
 */
static bool
download_write_data(struct download *d)
{
	struct dl_buffers *b;
	fileinfo_t *fi;
	bool trimmed = FALSE;
	enum dl_chunk_status status = DL_CHUNK_BUSY;
	bool should_flush;

	download_check(d);

	b = d->buffers;
	fi = d->file_info;
	g_assert(b->held > 0);
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	/*
	 * If we have an overlapping window and DL_F_OVERLAPPED is not set yet,
	 * then the leading data we have in the buffer are overlapping data.
	 *		--RAM, 12/01/2002, revised 23/11/2002
	 */

	if (d->chunk.overlap && !(d->flags & DL_F_OVERLAPPED)) {
		g_assert(d->pos == d->chunk.start);
		if (b->held < d->chunk.overlap)		/* Not enough bytes yet */
			return TRUE;					/* Don't even write anything */
		if (!download_overlap_check(d))		/* Mismatch on overlapped bytes? */
			return FALSE;					/* Download was stopped */
		d->flags |= DL_F_OVERLAPPED;		/* Don't come here again */
		if (b->held == 0)					/* No bytes left to write */
			return TRUE;
		/* FALL THROUGH */
	}

	/*
	 * Determine whether we should flush the data we have in the file
	 * buffer.  We do so when we reach the configured buffering limit,
	 * or when we determine that we have enough data to complete the
	 * chunk or the file.
	 */

	g_assert(b->held > 0);

	should_flush = buffers_should_flush(d);		/* Enough buffered data? */

	if (!should_flush && b->held >= d->chunk.end - d->pos)
		should_flush = TRUE;		/* Moving past our range */

	/*
	 * When we are overcommitting by doing aggressive swarming (i.e. we
	 * have in our buffers more than the total file size), then we must
	 * revert to more frequent flushing to avoid long waiting time, if we
	 * are downloading from slow sources and can't flush to disk because
	 * we have incomplete buffers: the earlier we flush, the sooner the
	 * fileinfo's range will be updated and we will avoid spending our
	 * time requesting parts we already have in memory.
	 *		--RAM, 2006-03-11
	 */

	if (
		!should_flush &&
		download_filedone(d) >= download_filesize(d)
	) {
		should_flush = TRUE;
	}

	if (GNET_PROPERTY(download_debug) > 5) {
		g_debug(
			"%s: %sflushing pending %lu bytes for \"%s\", pos=%s, end=%s",
			download_host_info(d),
			should_flush ? "" : "NOT ",
			(ulong) b->held, download_basename(d),
			uint64_to_string(d->pos),
			uint64_to_string2(d->chunk.end));
	}

	if (!should_flush)
		return TRUE;

	if (!download_flush(d, &trimmed, TRUE))
		return FALSE;

	/*
	 * End download if we have completed it.
	 */

	if (fi->use_swarming) {
		status = file_info_pos_status(fi, d->pos);

		switch (status) {
		case DL_CHUNK_DONE:
			/*
			 * Reached a zone that is completed.  If the file is done,
			 * we can clear the download.
			 *
			 * Otherwise, if we have reached the end of our requested chunk,
			 * meaning we put an upper boundary to our request, we are probably
			 * on a persistent connection where we'll be able to request
			 * another chunk data of data.
			 *
			 * The only remaining possibility is that we have reached a zone
			 * where a competing download is busy (aggressive swarming on),
			 * and since we cannot tell the remote HTTP server that we wish
			 * to interrupt the current download, we have no choice but to
			 * requeue the download, thereby loosing the slot, unless there
			 * is little enough data to grab still and we can ignore them.
			 */
			if (fi->done >= fi->size) {
				if (d->pos >= d->chunk.end)
					goto done;
				if (
					!download_has_pending_on_server(d, FALSE) ||
					!download_can_ignore(d)
				)
					goto done;
				/* Will ignore data until we can switch to another file */
				gnet_stats_inc_general(GNR_IGNORING_TO_PRESERVE_CONNECTION);
			} else if (d->pos == d->chunk.end) {
				goto partial_done;
			} else if (download_can_ignore(d)) {
				gnet_stats_inc_general(GNR_IGNORING_DURING_AGGRESSIVE_SWARMING);
			} else
				download_queue(d, _("Requeued by competing download"));
			break;
		case DL_CHUNK_BUSY:
			if (d->pos < d->chunk.end) {	/* Still within requested chunk */
				g_assert(!trimmed);
				break;
			}
			/* FALL THROUGH -- going past our own busy-chunk and competing */
		case DL_CHUNK_EMPTY:
			/*
			 * We're done with our busy-chunk.
			 * We've reached a new virgin territory.
			 *
			 * If we are on a persistent connection AND we reached the
			 * end of our requested range, then the server is expecting
			 * a new request from us.
			 *
			 * Otherwise, go on.  We'll be stopped when we bump into another
			 * DONE chunk anyway.
			 *
			 * XXX It would be nice to extend the zone as much as possible to
			 * XXX avoid new downloads starting from here and competing too
			 * XXX soon with us. -- FIXME (original note from Vidar)
			 */

			if (d->pos == d->chunk.end)
				goto partial_done;

			if (d->pos > d->chunk.end)
				d->chunk.end = download_filesize(d);	/* New upper boundary */

			break;					/* Go on... */
		}
	} else if (FILE_INFO_COMPLETE(fi)) {
		goto done;
	} else {
		fi_src_status_changed(d);
	}

	return DOWNLOAD_IS_RUNNING(d);

	/*
	 * We have completed the download of the requested file.
	 */

done:
	/*
	 * If we were pipelining, we have to return TRUE to make it possible
	 * to switch to another download after processing the pipeline response
	 * since we could not know before issuing that request that the file would
	 * be completed.  The data sent back will simply be ignored until we can
	 * switch to another download on the host.
	 */

	{
		bool pipelining = download_pipelining(d);

		g_assert(FILE_INFO_COMPLETE(fi));

		download_continue(d, trimmed);
		download_verify_sha1(d);

		return pipelining;
	}

	/*
	 * Requested chunk is done.
	 */

partial_done:
	g_assert(d->pos == d->chunk.end);
	g_assert(fi->use_swarming);

	/*
	 * If we're pipelining, we have to return TRUE since the data flow to
	 * the RX stack will be propagated to the cloned download.
	 */

	{
		bool pipelining = download_pipelining(d);

		download_continue(d, trimmed);
		return pipelining;
	}
}

#if 0 /* UNUSED */
/**
 * Refresh IP:port, download index and name, by looking at the new location
 * in the header ("Location:").
 *
 * @returns TRUE if we managed to parse the new location.
 */
static bool
download_moved_permanently(struct download *d, header_t *header)
{
	const char *buf;
	dmesh_urlinfo_t info;
	host_addr_t addr;
	uint16 port;

	download_check(d);

	addr = download_addr(d);
	port = download_port(d);

	buf = header_get(header, "Location");
	if (buf == NULL)
		return FALSE;

	if (!dmesh_url_parse(buf, &info)) {
		if (GNET_PROPERTY(download_debug))
			g_debug("could not parse HTTP Location: %s", buf);
		return FALSE;
	}

	/*
	 * If ip/port changed, accept the new ones but warn.
	 */

	if (!host_addr_equal(info.addr, addr) || info.port != port) {
		g_warning("server %s (file \"%s\") redirecting us to alien %s",
			host_addr_port_to_string(addr, port), download_basename(d), buf);
    }

	if (!is_host_addr(info.addr)) {
		g_warning("server %s (file \"%s\") would redirect us to invalid %s",
			host_addr_port_to_string(addr, port), download_basename(d), buf);
		atom_str_free_null(&info.name);
		return FALSE;
	}

	/*
	 * Check filename.
	 *
	 * If it changed, we don't change the output_name, so we'll continue
	 * to write to the same file we previously started with.
	 *
	 * NB: idx = URN_INDEX is used to indicate a /uri-res/N2R? URL, which we
	 * don't really want here (if we have the SHA1, we already asked for it).
	 */

	if (URN_INDEX == info.idx) {
		g_message("server %s (file \"%s\") would redirect us to %s",
			host_addr_port_to_string(addr, port), download_basename(d), buf);
		atom_str_free_null(&info.name);
		return FALSE;
	}

	if (0 != strcmp(info.name, d->file_name)) {
		g_message("file \"%s\" was renamed \"%s\" on %s",
			d->file_name, info.name,
			host_addr_port_to_string(info.addr, info.port));

		/*
		 * If name changed, we must update the global hash counting downloads.
		 * We ensure the current download is in the running list, since only
		 * those can be stored in the hash.
		 */

		g_assert(d->list_idx == DL_LIST_RUNNING);

		atom_str_free_null(&d->file_name);

		d->file_name = deconstify_char(info.name);		/* Already an atom */
	} else
		atom_str_free_null(&info.name);

	/*
	 * Update download structure.
	 */

	d->record_index = info.idx;

	download_redirect_to_server(d, info.addr, info.port);

	return TRUE;
}
#endif /* UNUSED */

/**
 * Check status code from status line.
 *
 * @return TRUE if we can continue.
 */
static bool
download_check_status(struct download *d, header_t *header, int code)
{
	download_check(d);

	if (code < 0) {
		g_message("weird HTTP acknowledgment status line from %s",
			download_host_info(d));

		if (GNET_PROPERTY(download_debug)) {
			dump_hex(stderr, "Status Line", getline_str(d->socket->getline),
				MIN(getline_length(d->socket->getline), 80));
		}
		if (0 == d->served_reqs) {
			/*
			 * If this wasn't the initial request, it's probably an issue
			 * with keep-alive connections.
			 */
			download_bad_source(d);
		}
		download_stop(d, GTA_DL_ERROR, _("Weird HTTP status"));
		return FALSE;
	} else {
		/* Reset the retry counter only if we get a positive response code */
		switch (code) {
		case 503:	/* Busy */
			if (
				0 == d->served_reqs &&
				NULL == header_get(header, "X-Queue") &&
				extract_retry_after(d, header) <= 0
			) {
				break;
			}
		case 416:	/* Range not available */
		case 200:	/* Okay */
		case 206:	/* Partial Content */
			d->retries = 0;
			break;
		}
		return TRUE;
	}
}

/**
 * Convert download to /uri-res/N2R? request.
 *
 * This is called when we have a /get/index/name URL for the download, yet
 * we attempted a GET /uri-res/ and either got a 503, or a 2xx return code.
 * This means the remote server understands /uri-res/ with high probability.
 *
 * Converting the download to /uri-res/N2R? means that we get rid of the
 * old index/name information in the download structure and replace it
 * with URN_INDEX/URN.  Indeed, to access the download, we only need to issue
 * a /uri-res request from now on.
 *
 * As a side effect, we remove the old index/name information from the download
 * mesh as well.
 *
 * @returns TRUE if OK, FALSE if we stopped the download because we finally
 * spotted it as being a duplicate!
 */
static bool
download_convert_to_urires(struct download *d)
{
	struct download *xd;

	download_check(d);
	g_assert(d->uri == NULL);
	g_assert(d->record_index != URN_INDEX);
	g_assert(d->sha1 != NULL);
	g_assert(d->file_info->sha1 == d->sha1);

	/*
	 * In case it is still recorded under its now obsolete index/name...
	 */

	dmesh_remove(d->sha1, download_addr(d), download_port(d),
		d->record_index, d->file_name);

	if (GNET_PROPERTY(download_debug) > 1) {
		g_debug("download at %s \"%u/%s\" becomes "
			"\"/uri-res/N2R?urn:sha1:%s\"",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			d->record_index, d->file_name, sha1_base32(d->sha1));
    }

	d->record_index = URN_INDEX;

	/*
	 * Maybe it became a duplicate download, due to our lame detection?
	 */

	xd = has_same_download(d->file_name, d->sha1, d->file_size,
			download_guid(d), download_addr(d), download_port(d));

	if (xd != NULL && xd != d) {
		download_check(xd);
		download_stop(d, GTA_DL_ERROR, _("Download was a duplicate"));
		return FALSE;
	}

	return TRUE;
}

/**
 * Extract Retry-After delay from header, returning 0 if none.
 */
uint
extract_retry_after(struct download *d, const header_t *header)
{
	const char *buf;
	uint32 delay;
	int error;

	download_check(d);

	/*
	 * A Retry-After header is either a full HTTP date, such as
	 * "Fri, 31 Dec 1999 23:59:59 GMT", or an amount of seconds.
	 */

	buf = header_get(header, "Retry-After");
	if (!buf)
		return 0;

	delay = parse_uint32(buf, NULL, 10, &error);
	if (error || delay > INT_MAX) {
		time_t now = tm_time();
		time_t retry = date2time(buf, now);

		if ((time_t) -1 == retry) {
			g_warning("cannot parse Retry-After \"%s\" sent by %s",
				buf, download_host_info(d));
			return 0;
		}

		delay = delta_time(retry, now);
		if (delay > INT_MAX)
			return 0;
	}

	return delay;
}

/**
 * Extract urn:bitprint information (SHA-1 and TTH root) out of a X-Content-URN
 * header, which may contain several entries (separated with ",").
 *
 * @param buf		the X-Content-URN header string
 * @param sha1		where the SHA-1 gets written to
 * @param tth		where the TTH root gets written to
 *
 * @return TRUE if we found a valid urn:bitprint and filled the information.
 */
static bool
extract_bitprint(const char *buf, struct sha1 *sha1, struct tth *tth)
{
	strtok_t *st;
	const char *tok;
	size_t len;
	bool found = FALSE;

	st = strtok_make_strip(buf);

	while ((tok = strtok_next_length(st, ",", &len))) {
		if (urn_get_bitprint(tok, len, sha1, tth)) {
			found = TRUE;
			break;
		}
	}

	strtok_free(st);

	return found;
}


/*
 * A standard X-Thex-URI header has the following form:
 * X-Thex-URI: <relative URI with an absolute path>;<TTH without prefix>
 */
static void
download_handle_thex_uri_header(struct download *d, header_t *header)
{
	const char *uri_start, *endptr;
	size_t uri_length;
	struct tth tth;

	g_return_if_fail(d);
	g_return_if_fail(header);

	if ((DL_F_THEX | DL_F_BROWSE) & d->flags)
		return;

	uri_start = header_get(header, "X-Thex-URI");
	if (NULL == uri_start)
		return;
	
	if ('/' != uri_start[0]) {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("TTH X-Thex-URI header has no valid URI (%s): \"%s\"",
				download_host_info(d), uri_start);
		}
		return;
	}

	endptr = strchr(uri_start, ';');
	if (endptr) {
		const struct tth *tth_ptr;
		const char *urn;

		urn = skip_ascii_spaces(&endptr[1]);
		if (strlen(urn) < TTH_BASE32_SIZE) {
			if (GNET_PROPERTY(tigertree_debug)) {
				g_debug("TTH X-Thex-URI header has no root hash "
					"for %s from %s",
					download_basename(d), download_host_info(d));
			}
			return;
		}
		tth_ptr = base32_tth(urn);
		if (NULL == tth_ptr) {
			if (GNET_PROPERTY(tigertree_debug)) {
				g_debug("X-Thex-URI header has no root hash for %s from %s",
						download_basename(d), download_host_info(d));
			}
			return;
		}
		tth = *tth_ptr;

		while (endptr != uri_start) {
		   	if (!is_ascii_space(endptr[0]) && ';' != endptr[0])
				break;
			endptr--;	/* skip trailing spaces */
		}
		uri_length = &endptr[1] - uri_start;
	} else {
		const char *content_urn;
		struct sha1 sha1;

		uri_length = strlen(uri_start);

		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("TTH X-Thex-URI header has no root hash (%s): \"%s\"",
				download_host_info(d), uri_start);
		}
		/*
		 * Non-standard X-Thex-URI header; treat the URI as opaque and
		 * accept it as long as peer indicates a TTH
		 */
		content_urn = header_get(header, "X-Content-URN");
		if (!content_urn) {
			g_message("missing root hash and missing X-Content-URN (%s)",
				download_host_info(d));
			return;
		}
		if (!extract_bitprint(content_urn, &sha1, &tth)) {
			g_message("missing root hash and bad X-Content-URN (%s)",
				download_host_info(d));
			return;
		}
	}

	if (d->file_info->tth) {
		if (!tth_eq(&tth, d->file_info->tth)) {
			if (GNET_PROPERTY(tigertree_debug)) {
				g_warning("TTH X-Thex-URI causes TTH (%s) mismatch "
					"for %s from %s: \"%s\"",
					tth_base32(d->file_info->tth),
					download_basename(d), download_host_info(d), uri_start);
			}
			return;
		}
	} else if (GNET_PROPERTY(tth_auto_discovery)) {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("discovered TTH (%s) for %s from %s", tth_base32(&tth),
				download_basename(d), download_host_info(d));
		}
		file_info_got_tth(d->file_info, &tth);
	}

	if (
		d->file_info->tth &&
		!(DL_F_FETCH_TTH & d->flags) &&
		!(FI_F_FETCH_TTH & d->file_info->flags) &&
		tt_good_depth(download_filesize(d)) >
			tt_depth(d->file_info->tigertree.num_leaves)
	) {
		uint32 cflags = 0;
		gnet_host_vec_t *proxies;
		char *uri;
		struct download *dt;

		uri = h_strndup(uri_start, uri_length);

		/*
		 * Remember that we fetched tigertree data from this one, so
		 * that we don't retry frequently if they sent no or insufficient
		 * data.
		 */

		d->flags |= DL_F_FETCH_TTH;
		if (d->always_push) {
			cflags |= SOCK_F_PUSH;
		}
		proxies = pproxy_set_host_vec(d->server->proxies);

		dt = download_thex_start(uri, d->sha1, d->file_info->tth,
			download_filesize(d), NULL, download_addr(d), download_port(d),
			download_guid(d), proxies, cflags);

		if (dt != NULL) {
			/*
			 * Mark the fileinfo to avoid downloading the tigertree data from
			 * more than one source at a time.
			 */
			d->file_info->flags |= FI_F_FETCH_TTH;
			dualhash_insert_key(dl_thex, d->id, dt->id);	/* d has THEX */

			if (GNET_PROPERTY(tigertree_debug)) {
				g_debug("requesting TTH (%s) tree for %s from %s",
					tth_base32(&tth), download_basename(d),
					download_host_info(d));
			}
		}

		gnet_host_vec_free(&proxies);
		HFREE_NULL(uri);
	}
}

/**
 * Add download as a good alternate location in the mesh.
 */
static void
download_add_mesh(const struct download *d)
{
	download_check(d);

	if (d->uri != NULL)
		return;				/* Special download, no place in mesh */

	if (NULL == d->sha1)
		return;

	if (d->always_push) {
		struct dl_server *server = d->server;

		g_assert(dl_server_valid(server));

		/*
		 * If we have seen no sign in the replies from the server that the
		 * servent is recent enough to become a good firewalled source, then
		 * don't bother encumbering the mesh.
		 */

		if (!(d->server->attrs & DLS_A_FW_SOURCE))
			return;

		/*
		 * If we have no known push-proxies, then the firewalled alt-loc
		 * will be mostly useless.  It's also a probable sign that the
		 * remote host does not support either push-proxy advertising, or
		 * even lacks total DHT support, hence is not able to publish its
		 * push proxies.
		 */

		if (server->proxies != NULL && pproxy_set_count(server->proxies) > 0) {
			dmesh_add_good_firewalled(d->sha1, download_guid(d));
		}
	} else {
		dmesh_add_good_alternate(d->sha1, download_addr(d), download_port(d));
	}
}

/**
 * Look for a Date: header in the reply and use it to update our skew.
 */
static void
check_date(struct download *d, const header_t *header)
{
	const char *buf;

	download_check(d);
	g_assert(d->socket != NULL);

	buf = header_get(header, "Date");
	if (buf) {
		time_t their = date2time(buf, tm_time());

		if ((time_t) -1 == their)
			g_warning("cannot parse Date \"%s\" sent by %s",
				buf, download_host_info(d));
		else {
			tm_t delta;
			time_t correction;

			/*
			 * We can determine the elapsed time since we sent the headers.
			 * The half of that time should roughly be the trip time from
			 * the remote server to us, and hence we must correct their
			 * clock forwards.  Also, we use that amount as an indication
			 * of the precision of our measurement.  We make sure we don't
			 * supply a precision of 0, as this should be reserved to "Time
			 * Sync" via UDP from an NTP-synchronized host.
			 *		--RAM, 2004-10-03
			 */

			tm_now(&delta);
			tm_sub(&delta, &d->header_sent);
			correction = (time_t) (tm2f(&delta) / 2.0);

			clock_update(their + correction, correction + 1, d->socket->addr);
		}
	}
}

/**
 * Look for an X-Hostname header in the reply.  If we get one, then it means
 * the remote server is not firewalled and can be reached there, using
 * the symbolic hostname given.
 */
static void
check_xhostname(struct download *d, const header_t *header)
{
	struct dl_server *server;
	const char *buf;

	download_check(d);

	server = d->server;
	buf = header_get(header, "X-Hostname");
	if (buf == NULL)
		return;

	/*
	 * If we got a GIV, ignore all pushes to this server from now on.
	 * We'll mark the server as DLS_A_PUSH_IGN the first time we'll
	 * be able to connect to it.
	 */

	if (d->got_giv) {
		if (GNET_PROPERTY(download_debug) > 2)
			g_debug("PUSH got X-Hostname, trying to ignore them for %s (%s)",
				buf, host_addr_port_to_string(download_addr(d),
				download_port(d)));

		d->flags |= DL_F_PUSH_IGN;
	}

	if (set_server_hostname(server, buf))
		fi_src_info_changed(d);
}

/**
 * Look for an X-Host header in the reply.  If we get one, then it means
 * the remote server is not firewalled and can be reached there.
 *
 * We only pay attention to such headers for pushed downloads.
 */
static void
check_xhost(struct download *d, const header_t *header)
{
	const char *buf;
	host_addr_t addr;
	uint16 port;

	download_check(d);
	g_assert(d->got_giv);

	buf = header_get(header, "X-Host");

	if (buf == NULL)
		return;

	if (
		!string_to_host_addr_port(buf, NULL, &addr, &port) ||
		!host_is_valid(addr, port)
	)
		return;

	/*
	 * It is possible that the IP:port we already have for this server
	 * be wrong.  We may have gotten an IP:port from a query hit before
	 * the server knew its real IP address.
	 */

	if (!host_addr_equal(addr, download_addr(d)) || port != download_port(d))
		download_redirect_to_server(d, addr, port);

	/*
	 * Most importantly, ignore all pushes to this server from now on.
	 * We'll mark the server as DLS_A_PUSH_IGN the first time we'll
	 * be able to connect to it.
	 */

	if (GNET_PROPERTY(download_debug) > 2)
		g_debug("PUSH got X-Host, trying to ignore PUSH for %s",
			host_addr_port_to_string(download_addr(d), download_port(d)));

	d->flags |= DL_F_PUSH_IGN;
}

static bool
content_range_check(struct download *d, header_t *header)
{
	filesize_t start, end, total;
	fileinfo_t *fi;
	const char *buf;

	buf = header_get(header, "Content-Range");		/* Optional */
	if (NULL == buf)
		return TRUE;
	
	if (0 != http_content_range_parse(buf, &start, &end, &total))
		return TRUE;

	fi = d->file_info;
	file_info_check(fi);

	if (!fi->file_size_known)
		return TRUE;

	if (fi->size == total)
		return TRUE;
	
	download_bad_source(d);
	download_stop(d, GTA_DL_ERROR, _("Filesize mismatch"));
	return FALSE;
}

/**
 * Handle X-(Gnutella-)Content-URN header.
 *
 * @returns FALSE if we cannot continue with the download.
 */
static bool
handle_content_urn(struct download *d, header_t *header)
{
	bool found_sha1 = FALSE;
	struct sha1 sha1;
	struct tth tth;
	const char *buf;

	download_check(d);

	/**
	 * LimeWire emits a X-Gnutella-Content-Urn header with the SHA-1 of
	 * the file described by the THEX data. Thus the SHA-1 won't match
	 * the THEX data we are actually downloading. As there are many
	 * LimeWire clones we cannot just check the Server/User-Agent header.
	 */
	if ((DL_F_THEX | DL_F_BROWSE) & d->flags)
		return TRUE;

	if (!content_range_check(d, header))
		return FALSE;

	buf = header_get(header, "X-Gnutella-Content-URN");

	/*
	 * Shareaza chose to adhere to the Content-Addressable Web (CAW) specs
	 * instead of the HUGE specs.  However, we can get several comma-separated
	 * URNs in the header, not just one.
	 */

	if (buf == NULL)
		buf = header_get(header, "X-Content-URN");

	if (buf == NULL) {
		bool n2r = FALSE;

		/*
		 * We don't have any X-Gnutella-Content-URN header on this server.
		 * If fileinfo has a SHA1, we must be careful if we cannot be sure
		 * we're writing to the SAME file.
		 */

		if (d->record_index == URN_INDEX && d->sha1)
			n2r = TRUE;
		else if (d->flags & DL_F_URIRES)
			n2r = TRUE;

		/*
		 * If we sent an /uri-res/N2R?urn:sha1: request, the server might
		 * not necessarily send an X-Gnutella-Content-URN in the reply, since
		 * HUGE does not mandate it (it simply says the server "SHOULD" do it).
		 *		--RAM, 15/11/2002
		 */

		if (n2r)
			goto collect_locations;		/* Should be correct in reply */

		/*
		 * If "download_require_urn" is set, stop.
		 *
		 * If they have configured an overlapping range of at least
		 * DOWNLOAD_MIN_OVERLAP, we can requeue the download if we were not
		 * overlapping here, in the hope we'll (later on) request a chunk after
		 * something we have already downloaded.
		 *
		 * If not, stop definitively.
		 */

		if (d->file_info->sha1) {
			if (GNET_PROPERTY(download_require_urn)) {
				/* They want strictness */
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR,
					_("No URN on server (required)"));
				return FALSE;
			}
			if (GNET_PROPERTY(download_overlap_range) >= DOWNLOAD_MIN_OVERLAP) {
				if (GNET_PROPERTY(download_optimistic_start) && d->pos == 0)
					return TRUE;

				if (d->chunk.overlap == 0) {
					download_queue_delay(d,
						GNET_PROPERTY(download_retry_busy_delay),
						_("No URN on server, waiting for overlap"));
					return FALSE;
				}
			} else {
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR,
					_("No URN on server to validate"));
				return FALSE;
			}
		}

		return TRUE;		/* Nothing to check against, continue */
	}

	found_sha1 = extract_bitprint(buf, &sha1, &tth);
	if (found_sha1) {
		if (d->file_info->tth) {
			if (!tth_eq(&tth, d->file_info->tth)) {
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, _("TTH mismatch detected"));
				return FALSE;
			}
		} else if (GNET_PROPERTY(tth_auto_discovery)) {
			if (GNET_PROPERTY(tigertree_debug)) {
				g_debug("TTH discovered root hash (%s) for %s from %s",
					tth_base32(&tth),
					download_basename(d), download_host_info(d));
			}
			file_info_got_tth(d->file_info, &tth);
		}
	} else {
		found_sha1 = dmesh_collect_sha1(buf, &sha1);
		if (!found_sha1)
			return TRUE;
	}

	if (d->sha1 && !sha1_eq(&sha1, d->sha1)) {
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, _("SHA-1 mismatch detected"));
		return FALSE;
	}

	/*
	 * Record SHA1 if we did not know it yet.
	 */

	if (d->sha1 == NULL) {
		download_set_sha1(d, &sha1);

		/*
		 * The following test for equality works because both SHA1
		 * are atoms.
		 */

		if (d->file_info->sha1 != d->sha1) {
			g_message("discovered SHA1 %s on the fly for %s (fileinfo has %s)",
				sha1_base32(d->sha1), download_basename(d),
				d->file_info->sha1 ? "another" : "none");

			/*
			 * If the SHA1 does not match that of the fileinfo,
			 * abort the download.
			 */

			if (d->file_info->sha1) {
				g_assert(!sha1_eq(d->file_info->sha1, d->sha1));

				download_info_reget(d);
				download_queue(d, _("URN fileinfo mismatch"));

				g_assert(d->file_info->sha1 == d->sha1);

				return FALSE;
			}

			g_assert(d->file_info->sha1 == NULL);

			/*
			 * Record SHA1 in the fileinfo structure, and make sure
			 * we're not asked to ignore this download, now that we
			 * got the SHA1.
			 *
			 * WARNING: d->file_info can change underneath during
			 * this call, and the current download can be requeued!
			 */

			if (!file_info_got_sha1(d->file_info, d->sha1)) {
				download_info_reget(d);
				download_queue(d, _("Discovered dup SHA1"));
				return FALSE;
			}

			g_assert(d->file_info->sha1 == d->sha1);

			if (DOWNLOAD_IS_QUEUED(d))		/* Queued by call above */
				return FALSE;

			if (download_ignore_requested(d))
				return FALSE;
		}

		download_add_mesh(d);		/* Add as known good alt-loc */

		/*
		 * We discovered the SHA-1, thus refresh on next occasion.
		 */
		download_dirty = TRUE;
	}

	/*
	 * Check for possible download mesh headers.
	 */

collect_locations:
	file_info_check(d->file_info);
	g_assert(d->sha1 || d->file_info->sha1);

	{
		gnet_host_t host;
		const sha1_t *dsha1 = d->sha1 != NULL ? d->sha1 : d->file_info->sha1;

		gnet_host_set(&host, download_addr(d), download_port(d));
		huge_collect_locations(dsha1, header, &host);

		buf = header_get(header, "X-Nalt");
		if (buf != NULL)
			dmesh_collect_negative_locations(dsha1, buf, download_addr(d));

	}

	return TRUE;
}

/**
 * Extract GUID information out of X-GUID if present and update the server
 * information accordingly.
 */
static void
check_xguid(struct download *d, const header_t *header)
{
	const char *buf;

	buf = header_get(header, "X-GUID");
	if (buf) {
		guid_t guid;

		if (!hex_to_guid(buf, &guid))
			return;

		download_found_server(&guid, download_addr(d), download_port(d));
	}
}

/**
 * Extract firewalled node information and possibly push-proxies from
 * the X-FW-Node-Info header string.
 *
 * @return TRUE if we got push-proxies, FALSE if the header did not contain any
 * that we did not know about.
 */
static bool
check_fw_node_info(struct dl_server *server, const char *fwinfo)
{
	struct dl_key *key = server->key;
	struct guid guid;
	bool seen_proxy = FALSE;
	bool seen_guid = FALSE;
	bool seen_pptls = FALSE;
	const char *tok;
	const char *msg = NULL;
	size_t added = 0;
	strtok_t *st;

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

	st = strtok_make_strip(fwinfo);

	while ((tok = strtok_next(st, ";"))) {
		host_addr_t addr;
		uint16 port;

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

		/* Skip first "pptsl=" indication */
		if (!seen_pptls) {
			/* TODO: handle pptls=<hex> */
			if (is_strcaseprefix(tok, "pptls=")) {
				seen_pptls = TRUE;
				continue;
			}
		}

		/*
		 * If we find a valid port:IP host, then these are the remote
		 * server address and port.
		 */

		if (
			!seen_proxy &&
			string_to_port_host_addr(tok, NULL, &port, &addr)
		) {
			if (!is_private_addr(addr) && host_addr_is_routable(addr)) {
				if (!host_addr_equal(key->addr, addr) || key->port != port) {
					change_server_addr(server, addr, port);
				}
				download_found_server(&guid, addr, port);
			}
			continue;
		}

		if (!string_to_host_addr_port(tok, NULL, &addr, &port))
			continue;

		seen_proxy = TRUE;

		if (is_private_addr(addr) || !host_is_valid(addr, port)) {
			g_message(
				"host %s sent non-routable IP address %s as push-proxy",
				server_host_info(server), host_addr_port_to_string(addr, port));
		} else {
			if (add_proxy(server, addr, port))
				added++;
		}
	}

	strtok_free(st);

	if (!seen_guid && NULL == msg)
		msg = "missing GUID";

	if (msg != NULL) {
		if (GNET_PROPERTY(download_debug))
			g_warning("could not parse 'X-FW-Node-Info: %s' from %s: %s",
				fwinfo, server_host_info(server), msg);

		return FALSE;
	}

	if (added > 0)
		download_push_proxy_wakeup(server, TRUE, FALSE);

	return added > 0;
}

/**
 * A downloader (i.e. someone ww upload something to) sent us a X-FW-Node-Info
 * header in its request, along with its servent IP:port.  See whether we
 * know this GUID or host and if we do, collect push-proxies out of the header.
 *
 * @param guid		parsed GUID from X-FW-Node-Info line
 * @param addr		parsed address from X-FW-Node-Info line or socket address
 * @param port		parsed port from X-FW-Node-Info or 0
 * @param fwinfo	the raw X-FW-Node-Info line we got
 */
void
download_got_fw_node_info(const struct guid *guid,
	host_addr_t addr, uint16 port, const char *fwinfo)
{
	struct dl_server *server;

	/*
	 * See whether we know this server by GUID, then by addr+port.
	 */
	
	server = htable_lookup(dl_by_guid, guid);

	if (NULL == server && host_is_valid(addr, port)) {
		struct dl_addr ipk;

		ipk.addr = addr;
		ipk.port = port;
		
		server = htable_lookup(dl_by_addr, &ipk);
	}

	if (NULL == server)
		return;				/* Don't know this server, ignore */

	gnet_stats_inc_general(GNR_RECEIVED_KNOWN_FW_NODE_INFO);
	check_fw_node_info(server, fwinfo);
}

/**
 * Extract host:port information out of X-Push-Proxy if present and
 * update the server's list.
 */
static void
check_push_proxies(struct download *d, const header_t *header)
{
	const char *buf;
	const char *tok;
	size_t added = 0;
	strtok_t *st;

	download_check(d);

	/*
	 * When LW node supports firewalled-to-firewalled transfers, it sends
	 * its proxy information in a X-FW-Node-Info header, which encompasses
	 * the information one could find in X-Push-Proxies.
	 *
	 * However, gtk-gnutella currently sends both X-FW-Node-Info and
	 * X-Push-Proxies, only it does not integrate any push-proxy address in
	 * the first header.
	 *
	 * Therefore, our strategy is the following: we parse X-FW-Node-Info
	 * first, and if we got push-proxies out of it, then we stop, otherwise
	 * we look for X-Push-Proxy.
	 *		--RAM, 2009-03-02
	 */

	buf = header_get(header, "X-FW-Node-Info");
	if (buf && check_fw_node_info(d->server, buf)) {
		d->server->attrs |= DLS_A_FW_SOURCE;
		return;
	}

	/*
	 * The newest specifications say that the header to be used
	 * is X-Push-Proxy.  Continue to parse the older forms, but
	 * we'll emit the newest form now.
	 *		--RAM, 2004-09-28
	 */

	buf = header_get(header, "X-Push-Proxy");		/* Newest specs */
	if (buf == NULL)
		buf = header_get(header, "X-Push-Proxies");
	if (buf == NULL)
		buf = header_get(header, "X-Pushproxies");	/* Legacy */

	if (buf == NULL)
		return;

	d->server->attrs |= DLS_A_FW_SOURCE;
	st = strtok_make_strip(buf);

	while ((tok = strtok_next(st, ","))) {
		host_addr_t addr;
		uint16 port;

		/* TODO: handle pptls=<hex> */
		if (is_strcaseprefix(tok, "pptls="))
			continue;

		if (!string_to_host_addr_port(tok, NULL, &addr, &port))
			continue;

		if (is_private_addr(addr) || !host_is_valid(addr, port)) {
			g_message("host %s sent non-routable IP address %s as push-proxy",
				download_host_info(d), host_addr_port_to_string(addr, port));
		} else {
			if (add_proxy(d->server, addr, port))
				added++;
		}
	}

	strtok_free(st);

	if (added > 0)
		download_push_proxy_wakeup(d->server, TRUE, FALSE);
}

/**
 * Partial File Sharing Protocol (PFSP) -- client-side.
 *
 * If there is an X-Available-Range header, parse it to know
 * whether we can spot a range that is available and which we
 * do not have.
 *
 * @param[in,out] d  The download for which we update available ranges
 * @param[in] header  The HTTP header which contains ranges info
 *
 * @return TRUE if we have seen one of the X-Available headers, indicating
 * that the remote file is partial.
 */
static bool
update_available_ranges(struct download *d, const header_t *header)
{
	static const char available_ranges[] = "X-Available-Ranges";
	static const char available[] = "X-Available";
	const char *buf;
	filesize_t available_bytes = 0;
	bool seen_available = FALSE;
	bool has_new_ranges = FALSE;
	bool was_complete;

	download_check(d);

	was_complete = !(d->flags & DL_F_PARTIAL);
	d->flags &= ~DL_F_PARTIAL;		/* Assume file is complete now */

	if (!d->file_info->use_swarming)
		goto send_event;

	g_assert(header != NULL);

	/*
	 * Handle X-Available (indicates a partial file).
	 */

	buf = header_get(header, available);

	if (buf) {
		int error;
		char *p = is_strprefix(buf, "bytes");

		d->flags |= DL_F_PARTIAL;	/* Definitely a partial file */
		seen_available = TRUE;

		if (p) {
			uint64 v;

			p = skip_ascii_blanks(p);
			v = parse_uint64(p, NULL, 10, &error);

			if (!error)
				available_bytes = MIN(v, download_filesize(d));
		} else {
			error = EINVAL;
		}

		if (error && GNET_PROPERTY(download_debug)) {
			g_warning("malformed X-Available header from %s: \"%s\"",
				download_host_info(d), buf);
		}
	}

	/*
	 * Handle X-Available-Ranges.
	 */

	buf = header_get(header, available_ranges);

	if (NULL == buf || download_filesize(d) == 0)
		goto send_event;

	d->flags |= DL_F_PARTIAL;	/* Definitely a partial file */
	seen_available = TRUE;

	/*
	 * LimeWire seemingly sends this to imply that file is partial yet
	 * it has no available ranges.
	 */

	if (0 == strcmp(buf, "bytes"))
		goto send_event;
		
	/*
	 * Update available range list and total size available remotely.
	 *
	 * Since remote end can give us a random subset of ranges each time,
	 * we merge the new list we get with the old one we had.
	 */

	{
		filesize_t old_length, new_length;
		http_rangeset_t *new_ranges;

		old_length = NULL == d->ranges ? 0 : http_rangeset_length(d->ranges);

		new_ranges = http_rangeset_extract(available_ranges, buf,
			download_filesize(d), download_vendor_str(d));

		if (new_ranges != NULL) {
			if (d->ranges != NULL) {
				new_length = http_rangeset_merge(d->ranges, new_ranges);
			} else {
				new_length = http_rangeset_length(new_ranges);
				d->ranges = new_ranges;
			}
		} else {
			new_length = old_length;
		}
		
		d->ranges_size = new_length;
		has_new_ranges = old_length != new_length;

		if (d->ranges != new_ranges)
			http_rangeset_free_null(&new_ranges);
	}

	/* FALL THROUGH */

 send_event:
	/*
	 * If we have an X-Available header mentionning more data than we
	 * can see in X-Available-Ranges, use the former on the basis that
	 * the latter could have been truncated due to header size constraints.
	 */

	if (available_bytes > d->ranges_size) {
		d->ranges_size = available_bytes;
		has_new_ranges = TRUE;

		if (GNET_PROPERTY(download_debug)) {
			g_debug("X-Available header from %s: has %s bytes for \"%s\"",
				download_host_info(d), uint64_to_string(available_bytes),
				download_basename(d));
		}
	}

	/*
	 * If they have the whole file, we can discard the ranges.
	 */

	if (
		!was_complete &&
		download_filesize(d) != 0 &&
		d->ranges_size >= download_filesize(d)
	) {
		if (GNET_PROPERTY(download_debug)) {
			g_debug("server %s now has the whole file (%s bytes) for \"%s\"",
				download_host_info(d), uint64_to_string(available_bytes),
				download_basename(d));
		}

		http_rangeset_free_null(&d->ranges);
		d->flags &= ~DL_F_PARTIAL;
		has_new_ranges = TRUE;
	}

	/*
	 * For complete files, make sure ``ranges_size'' is set to the whole file.
	 */

	if (0 == (d->flags & DL_F_PARTIAL))
		d->ranges_size = download_filesize(d);

	/*
	 * Send an update event for the ranges when there is a change, or when
	 * we are processing the first request, to let listeners initialize the
	 * range list
	 */

	if (has_new_ranges || 0 == d->served_reqs)
		fi_src_ranges_changed(d);

	return seen_available;
}

/**
 * Sink read data.
 * Used when waiting for the end of the previous HTTP reply.
 *
 * When all the data has been sunk, issue the next HTTP request.
 */
static void
download_sink(struct download *d)
{
	struct gnutella_socket *s = d->socket;

	download_check(d);
	g_assert(UNSIGNED(s->pos) <= s->buf_size);
	g_assert(d->status == GTA_DL_SINKING);
	g_assert(d->flags & DL_F_CHUNK_CHOSEN);
	g_assert(d->flags & DL_F_SUNK_DATA);

	gnet_stats_count_general(GNR_SUNK_DATA, s->pos);

	if (s->pos > d->sinkleft) {
		g_message("got more data to sink than expected from %s",
			download_host_info(d));
		download_stop(d, GTA_DL_ERROR, _("More data to sink than expected"));
		return;
	}

	d->sinkleft -= s->pos;
	s->pos = 0;

	/*
	 * When we're done sinking everything, remove the read callback
	 * and send the pending request.
	 */

	if (d->sinkleft == 0) {
		bsched_source_remove(d->bio);
		d->bio = NULL;
		download_set_status(d, GTA_DL_CONNECTED);
		download_send_request(d);
	}
}

/**
 * Read callback for file data.
 */
static void
download_sink_read(void *data, int unused_source,
	inputevt_cond_t unused_cond)
{
	struct download *d = data;
	struct gnutella_socket *s;
	ssize_t r;

	(void) unused_source;
	(void) unused_cond;

	download_check(d);

	s = d->socket;
	g_assert(s);

	r = bio_read(d->bio, s->buf, s->buf_size);
	if (0 == r) {
		socket_eof(s);
		download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
			_("Stopped data (EOF)"));
	} else if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno)) {
			socket_eof(s);
			if (errno == ECONNRESET)
				download_queue_delay(d,
					GNET_PROPERTY(download_retry_busy_delay),
					_("Stopped data (%s)"), g_strerror(errno));
			else
				download_stop(d, GTA_DL_ERROR,
					_("Failed (Read error: %s)"), g_strerror(errno));
		}
	} else {
		s->pos = r;
		d->last_update = tm_time();

		download_sink(d);
	}
}

static const char *
lazy_ack_message_to_ui_string(const char *src)
{
	static char *prev;
	char *s;
	
	g_assert(src);
	g_assert(src != prev);

	G_FREE_NULL(prev);
	
	if (is_ascii_string(src))
		return src;

	s = iso8859_1_to_utf8(src);
	prev = utf8_to_ui_string(s);
	if (prev != s && src != s) {
		G_FREE_NULL(s);
	}
	return prev;
}

/**
 * Mark download as receiving data: download is becoming active.
 */
static void
download_mark_active(struct download *d, bool must_ignore, bool is_followup)
{
	fileinfo_t *fi;

	download_check(d);

	fi = d->file_info;
	d->start_date = tm_time();
	download_set_status(d, must_ignore ? GTA_DL_IGNORING : GTA_DL_RECEIVING);

	/*
	 * If we're a browse/THEX download, we're not really receiving data
	 * for the file so we don't need to increase fi->recvcount nor set the
	 * fileinfo as dirty.
	 */

	if (!download_is_special(d)) {
		/*
		 * If first source to begin receiving, reset receive rate.
		 *
		 * The fi->recvcount is not enough to determine whether we're the first
		 * source, since we download_clone() between each request and then stop
		 * the parent.  Therefore, we need to to look at whether is_followup
		 * is TRUE, meaning we're following-up on a request and fi->recvcount
		 * being 0 means we're the only source for the file...
		 *		--RAM, 2013-11-03
		 */

		if (
			!is_followup &&
			0 == fi->recvcount
		) {
			fi->recv_last_time = d->start_date;
			fi->recv_last_rate = 0;
		}

		/*
		 * Prepare reading buffers for regular download.
		 */

		buffers_alloc(d);
		buffers_reset_reading(d);
	}

	fi->recvcount++;
	fi->dirty_status = TRUE;

 	g_assert(dl_establishing > 0);
	dl_establishing--;
	dl_active++;
	g_assert(d->list_idx == DL_LIST_RUNNING);

	/*
	 * Update running count.
	 */

	gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT, count_running_downloads());
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);

	/*
	 * Set TOS to low-delay, so that ACKs flow back faster, and set the RX
	 * buffer according to their preference (large for better throughput,
	 * small for better control of the incoming rate).
	 */

	{
		struct gnutella_socket *s = d->socket;

		socket_tos_lowdelay(s);
		socket_recv_buf(s, GNET_PROPERTY(download_rx_size) * 1024, TRUE);
	}
}

/**
 * Checks whether the contents of a User-Agent or Server header match
 * the signature of a dumb spammer.
 *
 * @param user_agent Value of a User-Agent respectively Server header.
 * @returns TRUE if the given User-Agent string is known to be used by
 * 			spammers only, FALSE otherwise.
 */
static bool
is_dumb_spammer(const char *user_agent)
{
	const char *endptr;

	g_return_val_if_fail(user_agent, FALSE);
	
	endptr = is_strcaseprefix(user_agent, "LimeWire/");
	if (endptr) {
		if (is_strprefix(endptr, "3.6.") || is_strprefix(endptr, "4.8.10.")) {
			return TRUE;
		}
	} else {
		if (is_strcaseprefix(user_agent, "Morpheous/")) {
			return TRUE;
		}
	}
	return FALSE;
}

static bool
xalt_detect_tls_support(struct download *d, header_t *header)
{
	const char *tls_hex = NULL, *next;
	size_t host_index = 0;
	bool found = FALSE;

	download_check(d);

	next = header_get(header, "X-Alt");
	while (NULL != next) {
		const char *start, *endptr, *p;
		host_addr_t addr;
		uint16 port;
		bool ok;

		p = next;
		start = skip_ascii_blanks(p);
		if ('\0' == *start)
			break;

		next = strpbrk(start, ",;");
		if (next) {
			next++;
		}

		if (NULL == tls_hex && (tls_hex = is_strcaseprefix(start, "tls=")))
			continue;

		/*
		 * There could be a GUID here if the host is not directly connectible
		 * but we ignore this apparently.
		 */	
		ok = string_to_host_addr(start, &endptr, &addr);
		if (ok && ':' == *endptr) {
			int error;

			port = parse_uint16(&endptr[1], &endptr, 10, &error);
			ok = !error && port > 0;
		} else {
			port = GTA_PORT;
		}
		if (!ok)
			continue;

		if (
			port == download_port(d) &&
			host_addr_equal(addr, download_addr(d))
		) {
			found = TRUE;
			break;
		}
		host_index++;
	}

	if (found) {
		size_t i = 0;

		/*
		 * We parse something like "tls_hex=4cbd040533a2" whereas
		 * each nibble refers to the next 4 hosts in the list.
		 * The MSB refers to the first of these, the LSB to the last.
		 */
		while (tls_hex && is_ascii_xdigit(tls_hex[0])) {
			int nibble, mask;

			nibble = hex2int_inline(*tls_hex++);
			for (mask = 0x8; 0 != mask; mask >>= 1, i++) {
				if (i == host_index)
					return 0 != (nibble & mask);
			}
		}
	}
	
	return FALSE;
}

/**
 * Check whether the remote host supports TLS, and insert its addr:port in
 * the TLS cache if it does.
 */
static void
download_detect_tls_support(struct download *d, header_t *header)
{
	download_check(d);
	dl_server_valid(d->server);

	if (d->got_giv)
		return;

	if (
		header_get_feature("tls", header, NULL, NULL) ||
		xalt_detect_tls_support(d, header)
	) {
		tls_cache_insert(download_addr(d), download_port(d));
		d->server->attrs |= DLS_A_TLS;
	}
}

/**
 * Open the specified path for writing downloaded data.
 *
 * To avoid using too many file descriptors (each download source opening
 * the same file for writing its bits), we share file descriptors through
 * the file_object abstraction.
 *
 * @return the created file object, NULL if file could not be opened.
 */
#define download_open(p) \
	file_object_open((p), O_WRONLY)

/**
 * We discovered the total size of the resource.
 *
 * @param d		the download source telling us the total size
 * @param size	the advertized total size
 *
 * @return the length of the requested chunk (overlap included), bound by the
 * size of the resource.
 */
static filesize_t
download_discovered_size(struct download *d, filesize_t size)
{
	download_check(d);
	file_info_check(d->file_info);
	g_assert(!d->file_info->file_size_known);	/* Was unknown before */

	d->chunk.size = size;
	file_info_size_known(d, size);
	d->chunk.end = download_filesize(d);
	fi_src_info_changed(d);

	return d->chunk.end - d->chunk.start + d->chunk.overlap;
}

/**
 * Called to initiate the download once all the HTTP headers have been read.
 * If `ok' is false, we timed out reading the header, and have therefore
 * something incomplete.
 *
 * Validate the reply, and begin saving the incoming data if OK.
 * Otherwise, stop the download.
 */
static void
download_request(struct download *d, header_t *header, bool ok)
{
	struct gnutella_socket *s;
	const char *status;
	uint ack_code;
	const char *ack_message = "";
	const char *buf;
	bool got_content_length = FALSE;
	filesize_t content_length = 0;
	bool is_chunked;
	bool must_ignore;
	http_content_encoding_t content_encoding;
	filesize_t check_content_range = 0, requested_size;
	uint http_major = 0, http_minor = 0;
	bool is_followup;
	fileinfo_t *fi;
	char short_read[80];
	uint delay;
	uint hold = 0;
	uint fixed_ack_code;
	bool pipelined_response = FALSE;

	download_check(d);
	
	is_followup = d->keep_alive;
	s = d->socket;
	fi = d->file_info;

	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	/*
	 * If `ok' is FALSE, we might not even have fully read the status line,
	 * in which case `s->getline' will be null.
	 */

	if (!ok && s->getline == NULL) {
		download_queue_delay(d, GNET_PROPERTY(download_retry_refused_delay),
			_("Timeout reading HTTP status"));
		return;
	}

	g_assert(s->getline);				/* Being in the header reading phase */

	status = getline_str(s->getline);
	d->last_update = tm_time();			/* Done reading headers */

	if (GNET_PROPERTY(download_trace) & SOCK_TRACE_IN) {
		g_debug("----Got %sreply #%u from %s:\n%s",
			ok ? "" : "INCOMPLETE ", d->served_reqs,
			host_addr_to_string(s->addr), status);
		header_dump(stderr, header, "----");
	}

	/*
	 * If we did not get any status code at all, re-enqueue immediately.
	 */

	if (!ok && getline_length(s->getline) == 0) {
		download_queue_delay(d, GNET_PROPERTY(download_retry_refused_delay),
			_("Timeout reading headers"));
		return;
	}

	/*
	 * The DL_F_FAKE_G2 was set when we decided to attempt advertising as
	 * a G2 node.  Since GTKG supports both Gnutella and G2, we're not really
	 * faking anything, it's just that we decide to "appear" as a G2 node to
	 * be able to correctly download from another G2-only servent.
	 *
	 * (The Gnutella and G2 protocols are just "search engines", file exchange
	 * is HTTP, which could not care less about the way the resource location
	 * was obtained.)
	 *
	 * If we get here, it means advertising as G2 worked, hence the remote side
	 * must be flagged as a G2 host.  This information will be persisted in
	 * the download magnet, as well as in the G2 cache (to be able to handle
	 * other resources on the same server when this resource is fully fetched).
	 */

	if ((d->flags & DL_F_FAKE_G2) || (d->server->attrs & DLS_A_FAKE_G2)) {
		if (GNET_PROPERTY(download_debug))
			g_debug("server %s responded well to G2 faking for \"%s\"",
				download_host_info(d), download_basename(d));

		d->flags &= ~DL_F_FAKE_G2;
		d->server->attrs &= ~DLS_A_FAKE_G2;
		d->server->attrs |= DLS_A_G2_ONLY;

		if (download_port(d) != 0 && is_host_addr(download_addr(d))) {
			g2_cache_insert(download_addr(d), download_port(d));
		}
	}

	/*
	 * If we were pushing this download, check for an X-Host header in
	 * the reply: this will indicate that the remote host is not firewalled
	 * and will give us its IP:port.
	 *
	 * If not, look for a X-GUID header informing us about the server's GUID.
	 *
	 * NB: do this before extracting the server token, as it may redirect
	 * us to an alternate server, and we could therefore lose the server
	 * vendor string indication (attaching it to a discarded server object).
	 */

	if (d->got_giv) {
		if (!is_followup)
			check_xhost(d, header);
		check_push_proxies(d, header);
	} else {
		check_xguid(d, header);
	}

	/*
	 * Extract Server: header string, if present, and store it unless
	 * we already have it.
	 */

	if (download_get_server_name(d, header)) {
		fi_src_info_changed(d);
	}

	feed_host_cache_from_headers(header, HOST_ANY, FALSE, download_addr(d),
		download_vendor_str(d));

	/*
	 * If we get an X-Hostname header, we know the remote end is not
	 * firewalled, and we get its DNS name: even if its IP changes, we'll
	 * be able to recontact it.
	 */

	check_xhostname(d, header);
	node_check_remote_ip_header(download_addr(d), header);

	/*
	 * Cache whether remote host supports / wants firewalled locations.
	 */

	if (header_get_feature("fwalt", header, NULL, NULL))
		d->server->attrs |= DLS_A_FWALT;

	/*
	 * IPv6-Ready: check remote support of IPv6.
	 */

	{
		unsigned major, minor;

		if (header_get_feature("IP", header, &major, &minor)) {
			if (INET_IP_V6READY == major) {
				d->server->attrs |= DLS_A_CAN_IPV6;
				d->server->attrs |=
					(INET_IP_NOV4 == minor) ? DLS_A_IPV6_ONLY : 0;
			}
		}
	}

	/*
	 * Check status.
	 */

	ack_code = http_status_parse(status, "HTTP",
		&ack_message, &http_major, &http_minor);

	if (
		0 == d->served_reqs &&
		http_major < 1 &&
	    (ack_code < 200 || ack_code >= 400)
	) {
		d->server->attrs |= DLS_A_FOOBAR;
	}
	if (!download_check_status(d, header, ack_code))
		return;

	if (ack_message)
		ack_message = lazy_ack_message_to_ui_string(ack_message);

	if (ok) {
		d->header_read_eof = 0;	/* Reset counter: we got full headers */
	}
	d->flags |= DL_F_REPLIED;

	download_detect_tls_support(d, header);

	/* Update clock skew if we have a Date: */
	check_date(d, header);

	buf = header_get(header, "Transfer-Encoding");
	if (buf) {
		is_chunked = 0 == strcmp(buf, "chunked");
	} else {
		is_chunked = FALSE;
	}

	buf = header_get(header, "Content-Encoding");
	if (buf) {
		/* TODO: we don't support "gzip" encoding yet (and don't request it) */
		if (0 == strcmp(buf, "deflate")) {
			content_encoding = HTTP_CONTENT_ENCODING_DEFLATE;
		} else {
			download_bad_source(d);
			download_stop(d, GTA_DL_ERROR,
				_("No support for Content-Encoding (%s)"), buf);
			return;
		}
	} else {
		content_encoding = HTTP_CONTENT_ENCODING_IDENTITY;
	}

	/*
	 * Provision for broken HTTP engines, such as the one used by
	 * GnucDNA (morpheus, Gnucleus, etc..), which send replies such
	 * as "HTTP 503" without any version.
	 *
	 * We try to guess whether they're recent enough to be flagged as
	 * HTTP/1.1 or not, depending on the headers they sent.  What a shame.
	 *
	 *		--RAM, 2006-02-22
	 */

	if (http_major == 0) {
		buf = header_get(header, "X-Available-Ranges");
		if (buf != NULL)
			goto http_version_fix;	/* PFS implies HTTP/1.1 hopefully */

		buf = header_get(header, "X-Queue");
		if (buf != NULL)
			goto http_version_fix;	/* Active queuing -> HTTP/1.1 hopefully */

		buf = header_get(header, "Connection");
		if (buf && 0 == ascii_strcasecmp(buf, "close"))
			goto http_version_fix;	/* "Connection: close" is HTTP/1.1 */

		if (ack_code >= 200 && ack_code <= 299) {
			/* We're downloading */
			buf = header_get(header, "Content-Range");
			if (buf != NULL)
				goto http_version_fix;	/* HTTP/1.1 hopefully */
		}

		goto http_version_nofix;

	http_version_fix:
		/*
		 * If there's no Content-Length, HTTP/1.1 is no good to us anyway,
		 * since there cannot be any keep-alive performed.
		 */

		buf = header_get(header, "Content-Length");
		if (buf != NULL) {
			http_major = 1;
			http_minor = 1;
			if (GNET_PROPERTY(download_debug)) g_debug(
				"assuming \"HTTP/1.1 %d\" for %s", ack_code,
				download_host_info(d));
		} else if (GNET_PROPERTY(download_debug)) {
			g_debug(
				"no HTTP version nor Content-Length given by %s (status %d)",
				download_host_info(d), ack_code);
		}
		/* FALL THROUGH */
	}

http_version_nofix:

	/*
	 * Do we have to keep the connection after this request?
	 *
	 * If server supports HTTP/1.1, record it.  This will help us determine
	 * whether to send a Range: request during swarming, at the next
	 * connection attempt.
	 */

	buf = header_get(header, "Connection");

	if (http_major > 1 || (http_major == 1 && http_minor >= 1)) {
		/* HTTP/1.1 or greater -- defaults to persistent connections */
		d->keep_alive = TRUE;
		d->server->attrs &= ~DLS_A_NO_HTTP_1_1;
		if (buf && 0 == ascii_strcasecmp(buf, "close"))
			d->keep_alive = FALSE;
	} else {
		/* HTTP/1.0 or lesser -- must request persistence */
		d->server->attrs |= DLS_A_NO_HTTP_1_1;
		d->keep_alive = FALSE;
		if (buf && 0 == ascii_strcasecmp(buf, "keep-alive"))
			d->keep_alive = TRUE;
	}

	/*
	 * Now deal with the return code.
	 */

	if (ok)
		short_read[0] = '\0';
	else {
		uint count = header_num_lines(header);
		str_bprintf(short_read, sizeof short_read,
			"[short %u line%s header] ", count, plural(count));

		d->keep_alive = FALSE;			/* Got incomplete headers -> close */
	}

	if (is_dumb_spammer(download_vendor_str(d))) {	
		hostiles_dynamic_add(download_addr(d), "dumb spammer", HSTL_DUMB);
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "%s", _("Spammer detected"));
		return;
	}

	if (!handle_content_urn(d, header))
		return;

	download_handle_thex_uri_header(d, header);

	if (update_available_ranges(d, header)) {	/* Updates `d->ranges' */
		/*
		 * Some X-Availble or X-Available-Ranges header was present.
		 * Some broken servents return 503 when they meant 416, fix this.
		 */
		if (
			ack_code == 503 && d->ranges != NULL &&
			!http_rangeset_contains(d->ranges,
				d->chunk.start, d->chunk.end - 1) &&
			NULL == header_get(header, "X-Queue") &&
			NULL == header_get(header, "X-Queued")
		) {
			if (GNET_PROPERTY(download_debug)) {
				g_warning("fixing inappropriate status code 503 (%s) "
					"from %s to 416",
					ack_message, download_host_info(d));
			}
			ack_code = 416;
		}
	}

	if (ack_code == 503 || (ack_code >= 200 && ack_code <= 299)) {

		/*
		 * If we made a /uri-res/N2R? request, yet if the download still
		 * has the old index/name indication, convert it to a /uri-res/.
	 	 */
		if (
			!d->uri &&
			d->record_index != URN_INDEX &&
			d->sha1 && (d->flags & DL_F_URIRES) &&
			!download_convert_to_urires(d)
		) {
			return;
		}

		/*
		 * The download could be remotely queued. Check this now before
		 * continuing at all.
		 *   --JA, 31 jan 2003
		 */
		if (ack_code == 503) {			/* Check for queued status */

			if (parq_download_parse_queue_status(d, header, ack_code)) {
				/* If we are queued, there is nothing else we can do for now */
				if (parq_download_is_active_queued(d)) {
					download_passively_queued(d, FALSE);

					download_add_mesh(d);	/* Update mesh (good source) */

					/* Count partial success if we were switched */
					if (d->flags & DL_F_SWITCHED) {
						d->flags &= ~(DL_F_SWITCHED |
							DL_F_FROM_PLAIN | DL_F_FROM_ERROR);
						gnet_stats_inc_general(GNR_QUEUED_AFTER_SWITCHING);
					}

					return;

				} /* Download not active queued, continue as normal */
				download_set_status(d, GTA_DL_HEADERS);
			}
		} /* ack_code was not 503 */
	}

	delay = extract_retry_after(d, header);
	d->retry_after = time_advance(tm_time(), MAX(1, delay));
	d->timeout_delay = 0;			/* We managed to connect */

	/*
	 * Partial File Sharing Protocol (PFSP) -- client-side
	 *
	 * We can make another request with a range that the remote
	 * servent has if the reply was a keep-alive one.  Both 503 or 416
	 * replies are possible with PFSP.
	 */

	if (d->ranges != NULL && d->keep_alive && d->file_info->use_swarming) {
		switch (ack_code) {
		case 503:				/* Range not available, maybe */
		case 416:				/* Range not satisfiable */
			/*
			 * If we were requesting something that is already within the
			 * available ranges, then there is no need to go further.
			 */

			if (
				http_rangeset_contains(d->ranges,
					d->chunk.start, d->chunk.end - 1)
			) {
				if (GNET_PROPERTY(download_debug) > 3) {
					g_debug("PFSP currently requested chunk %s-%s from %s "
						"for \"%s\" already in the available ranges: %s",
						uint64_to_string(d->chunk.start),
						uint64_to_string2(d->chunk.end - 1),
						host_addr_port_to_string(download_addr(d),
								download_port(d)),
						download_basename(d),
						http_rangeset_to_string(d->ranges));
				}
				break;
			}

			/*
			 * Clear current request so we may pick whatever is available
			 * remotely by freeing the current chunk...
			 */

			file_info_clear_download(d, TRUE);		/* `d' is running */

			download_add_mesh(d);	/* Update mesh -- we're about to return */

			if (!download_start_prepare_running(d))
				return;

			/*
			 * If we can pick an available range, re-issue the request.
			 * Due to the above check for a request made for an already
			 * existing range, we won't loop re-requesting chunks forever
			 * if 503 meant "Busy" and not "Range not available".
			 *
			 * As a further precaution, to avoid hammering, we check
			 * whether there is a Retry-After header.  If there is,
			 * `delay' won't be 0 and we will not try to make the request.
			 */

			if (delay == 0 && download_pick_available(d, &d->chunk)) {
				uint64 v;
				int error;

				/*
				 * Sink the data that might have been returned with the
				 * HTTP status.  When it's done, we'll send the request
				 * with the chunk we have chosen.
				 */

				buf = header_get(header, "Content-Length");	/* Mandatory */

				if (buf == NULL) {
					g_message("no Content-Length with keep-alive reply "
						"%u \"%s\" from %s", ack_code, ack_message,
						download_host_info(d));
					download_queue_delay(d,
						MAX(delay, GNET_PROPERTY(download_retry_refused_delay)),
						_("Partial file, bad HTTP keep-alive support"));
					return;
				}

				v = parse_uint64(buf, NULL, 10, &error);
				if (error) {
					g_message("cannot parse Content-Length header from %s: "
						"\"%s\"",
						download_host_info(d), buf);
				}
				d->sinkleft = v;

				if (d->sinkleft > DOWNLOAD_MAX_SINK) {
					g_message("too much data to sink (%s bytes) on reply "
						"%u \"%s\" from %s",
						uint64_to_string(d->sinkleft), ack_code, ack_message,
						download_host_info(d));

					download_queue_delay(d,
						MAX(delay, GNET_PROPERTY(download_retry_refused_delay)),
						_("Partial file, too much data to sink (%s bytes)"),
						uint64_to_string(d->sinkleft));
					return;
				}

				/*
				 * Avoid endless request/sinking cycles.  If we already sunk
				 * data previously since we started the connection, requeue.
				 */

				if (d->flags & DL_F_SUNK_DATA) {
					g_message("would have to sink twice during session from %s",
						download_host_info(d));
					download_queue_delay(d,
						MAX(delay, GNET_PROPERTY(download_retry_refused_delay)),
						_("Partial file, no suitable range found yet"));
					return;
				}

				io_free(d->io_opaque);
				getline_free(s->getline);	/* No longer need this */
				s->getline = NULL;

				d->flags |= DL_F_CHUNK_CHOSEN;
				d->flags |= DL_F_SUNK_DATA;		/* Sink only once per session */

				if (d->sinkleft == 0 || d->sinkleft == s->pos) {
					s->pos = 0;
					download_send_request(d);
				} else {
					g_assert(s->gdk_tag == 0);
					g_assert(d->bio == NULL);

					download_set_status(d, GTA_DL_SINKING);

					d->bio = bsched_source_add(
						bsched_in_select_by_addr(s->addr), &s->wio,
						BIO_F_READ, download_sink_read, d);

					if (s->pos > 0) {
						download_sink(d);
					}
				}
			} else {
				/* Server has nothing for us yet, give it time */
				download_queue_delay_switch(d, header,
					MAX(delay, GNET_PROPERTY(download_retry_refused_delay)),
					_("Partial file on server, waiting"));
			}

			return;
		default:
			break;
		}
	}

	if (ack_code >= 200 && ack_code <= 299) {
		if (d->server->attrs & DLS_A_G2_ONLY) {
			if (download_port(d) != 0 && is_host_addr(download_addr(d))) {
				g2_cache_insert(download_addr(d), download_port(d));
			}
		}

		download_add_mesh(d);	/* OK -- mark as good source */
		download_passively_queued(d, FALSE);
		download_actively_queued(d, FALSE);

		if (!ok) {
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
		}
	} else {
		const char *vendor = download_vendor_str(d);

		if (ack_code == 403 && (*vendor == 'g' || *vendor == '!')) {
			/*
			 * GTKG is overzealous: it will send a 403 for PARQ banning
			 * if we retry too often, but this can happen when GTKG crashes
			 * and is restarted before the retry timeout expires.
			 *
			 * If we did not special case this reply, then someone who
			 * auto-cleans downloads from his queue on error would lose
			 * a source due to some error in GTKG, which is... embarrassing!
			 *
			 * NB: older GTKG before 2004-04-11 did not emit a Retry-After
			 * on such 403, so we hardcode a retry timer of 1200, which is
			 * the largest amount of time one can wait before retrying in
			 * a queue.
			 *
			 *		--RAM, 11/04/2004
			 */
			if (
				(
					is_strprefix(vendor, "gtk-gnutella/") ||
				 	is_strprefix(vendor, "!gtk-gnutella/")
				) &&
				NULL != strstr(ack_message, "removed from PARQ")
			) {
				download_queue_hold(d,
					delay == 0 ?  1200 : delay,
					"%sHTTP %u %s", short_read, ack_code, ack_message);
				return;
			}
		}
		switch (ack_code) {
		case 301:				/* Moved permanently */
		case 302:				/* Moved temporarily */
			/* FIXME: Disabled because we have no loop detection and
			 *		  send no Referer: header. This could be abused
			 *		  for DoS attacks.
			 */
#if 0
			if (!download_moved_permanently(d, header))
				break;
			download_passively_queued(d, FALSE);
			download_queue_delay(d,
				delay ? delay : GNET_PROPERTY(download_retry_busy_delay),
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
#else
			if (d->sha1 && NULL == d->uri) {
				dmesh_good_mark(d->sha1, download_addr(d), download_port(d),
					FALSE);
			}
			break;
#endif
		case 416:				/* Requested range not available */
			/*
			 * There was no ranges supplied (or we'd have gone through the
			 * PFSP code above), yet the server is sharing a partial file.
			 * Give it some time and retry.
			 */
			download_passively_queued(d, FALSE);
			download_queue_delay_switch(d, header,
				delay ? delay : GNET_PROPERTY(download_retry_timeout_delay),
				_("%sRequested range unavailable yet"), short_read);
			return;
		case 503:				/* Busy */
			/*
			 * These Shareaza morons started using 503 instead of 403.
			 * Now we need to handle that specially because it's not really
			 * a "busy" indication.
			 */
			if (
				is_strprefix(download_vendor_str(d), "Shareaza") &&
				is_strprefix(ack_message, "Service Unavailable")
			) {
				goto refused;	/* Sorry, contorted logic */
			}
			/* FALL THROUGH */
		case 408:				/* Request timeout */
			if (d->server->attrs & DLS_A_G2_ONLY) {
				if (download_port(d) != 0 && is_host_addr(download_addr(d))) {
					g2_cache_insert(download_addr(d), download_port(d));
				}
			}

			download_add_mesh(d);		/* Update mesh: source is good */

			/*
			 * We did a fall through on a 503, however, the download could be
			 * queued remotely. We might want to display this.
			 *		-- JA, 21/03/2003 (it is spring!)
			 */
			if (parq_download_is_passive_queued(d)) {
				char tmp[80];
				int pos = get_parq_dl_position(d);
				int length = get_parq_dl_queue_length(d);
				int eta = get_parq_dl_eta(d);
				size_t rw;

				download_passively_queued(d, TRUE);

				rw = str_bprintf(tmp, sizeof(tmp), "%s", _("Queued"));
				if (pos > 0) {
					rw += str_bprintf(&tmp[rw], sizeof(tmp)-rw,
						_(" (slot %d"), pos);		/* ) */

					if (length > 0)
						rw += str_bprintf(&tmp[rw], sizeof(tmp)-rw,
							"/%d", length);

					if (eta > 0)
						rw += str_bprintf(&tmp[rw], sizeof(tmp)-rw,
							_(", ETA: %s"), short_time(eta));

					rw += str_bprintf(&tmp[rw], sizeof(tmp)-rw, /* ( */ ")");
				}

				download_queue_delay(d,
					delay ? delay : GNET_PROPERTY(download_retry_busy_delay),
					"%s", tmp);
			} else {
				/* No hammering -- hold further requests on server */
				download_passively_queued(d, FALSE);

				download_queue_hold(d,
					delay ? delay : GNET_PROPERTY(download_retry_busy_delay),
					"%sHTTP %u %s", short_read, ack_code, ack_message);
			}
			return;
		case 550:				/* Banned */
			download_passively_queued(d, FALSE);
			download_queue_hold(d,
				delay ? delay : GNET_PROPERTY(download_retry_refused_delay),
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
		default:
			break;
		}

	refused:
		download_bad_source(d);
		fixed_ack_code = ack_code;

		/*
		 * Check whether server is banning us based on our user-agent.
		 *
		 * If server is a gtk-gnutella, it's not banning us based on that.
		 * Note that if the remote server is a fake GTKG, then its name
		 * will begin with a '!'.
		 *
		 * When remote host is a GTKG, it can't be banning us based on
		 * our user-agent.  So clear the DLS_A_BANNING flag, which could
		 * have been activated previously because the remote host was
		 * looking as a fake GTKG due to a de-synchronized clock.
		 */

		if (is_strprefix(download_vendor_str(d), "gtk-gnutella/")) {
			bool was_banning = d->server->attrs & DLS_A_BANNING;

			d->server->attrs &= ~DLS_A_BANNING;
			d->server->attrs &= ~DLS_A_MINIMAL_HTTP;
			d->server->attrs &= ~DLS_A_FAKE_G2;
			d->server->attrs &= ~DLS_A_G2_ONLY;

			if (was_banning) {
				fi_src_info_changed(d);
			}
		} else if (!(d->server->attrs & DLS_A_BANNING)) {
			switch (ack_code) {
			case 401:
				if (!is_strprefix(download_vendor_str(d), "BearShare"))
					d->server->attrs |= DLS_A_BANNING;	/* Probably */
				break;
			case 403:
				if (is_strprefix(ack_message, "Network Disabled")) {
					if (GNET_PROPERTY(enable_hackarounds)) {
						if (0 == (d->server->attrs & DLS_A_G2_ONLY))
							d->server->attrs |= DLS_A_FAKE_G2;
					}
					d->server->attrs |= DLS_A_G2_ONLY;
					hold = MAX(delay, 320);				/* To be safe */
					if (
						download_port(d) != 0 &&
						is_host_addr(download_addr(d))
					) {
						g2_cache_insert(download_addr(d), download_port(d));
					}
				}
				if (!(d->flags & DL_F_BROWSE)) {
					d->server->attrs |= DLS_A_BANNING;		/* Probably */
				}
				break;
			case 404:
				if (is_strprefix(ack_message, "Please Share")) {
					d->server->attrs |= DLS_A_BANNING;	/* Shareaza 1.8.0.0- */
					fixed_ack_code = 403;			/* Fix their error */
				}
				break;
			case 503:	/* Shareaza >= 2.2.3.0 misunderstands everything */
				fixed_ack_code = 403;				/* Fix their error */
				hold = MAX(delay, 7260);			/* To be safe */
				if (GNET_PROPERTY(enable_hackarounds)) {
					if (0 == (d->server->attrs & DLS_A_G2_ONLY))
						d->server->attrs |= DLS_A_FAKE_G2;
				}
				d->server->attrs |= DLS_A_G2_ONLY;
				if (download_port(d) != 0 && is_host_addr(download_addr(d))) {
					g2_cache_insert(download_addr(d), download_port(d));
				}
				d->server->attrs |= DLS_A_BANNING;	/* Surely if we came here */
				break;
			}

			/*
			 * If server might be banning us, use minimal HTTP headers
			 * in our requests from now on.
			 */

			if (d->server->attrs & DLS_A_BANNING) {
				d->server->attrs |= DLS_A_MINIMAL_HTTP;

				if (GNET_PROPERTY(download_debug)) {
					g_debug("server %s might be banning us with \"%d %s\"",
						download_host_info(d), ack_code, ack_message);
				}
			}
		}

		/*
		 * If they refuse our downloads, ban them in return for a limited
		 * amout of time and kill all their running uploads.
		 */

		switch (fixed_ack_code) {
		case 401:
		case 403:
			if (d->server->attrs & DLS_A_BANNING) {
				ban_record(download_addr(d), "IP denying uploads");
				upload_kill_addr(download_addr(d));
			}
			break;
		default:
			goto genuine_error;
		}

		if (d->server->attrs & DLS_A_BANNING) {
			if (hold)
				download_queue_hold(d, hold,
					"%sHTTP %u %s", short_read, ack_code, ack_message);
			else
				download_queue_delay(d,
					delay ? delay : GNET_PROPERTY(download_retry_busy_delay),
					"%sHTTP %u %s", short_read, ack_code, ack_message);

			return;
		}

	genuine_error:
		download_stop_switch(d, header, "%sHTTP %u %s",
			short_read, ack_code, ack_message);
		return;
	}

	/*
	 * We got a success status from the remote servent.	Parse header.
	 */

	g_assert(ok);

	/*
	 * Even upon a 2xx reply, a PARQ-compliant server may send us an ID.
	 * That ID will be used when the server sends us a QUEUE, so it's good
	 * to remember it.
	 *		--RAM, 17/05/2003
	 */

	(void) parq_download_parse_queue_status(d, header, ack_code);

	/*
	 * If they configured us to require a server name, and we have none
	 * at this stage, stop.
	 */

	if (
		!d->uri &&
		GNET_PROPERTY(download_require_server_name) &&
		download_vendor(d) == NULL
	) {
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR,
			_("Server did not supply identification"));
		return;
	}

	/*
	 * Normally, a Content-Length: header is mandatory.	However, if we
	 * get a valid Content-Range, relax that constraint a bit.
	 *		--RAM, 08/01/2002
	 *
	 * Ignore Content-Length completely if Content-Range is present to
	 * avoid issues with HTTP servers with hacked on resuming which send
	 * inconsistent headers.
	 *		--cbiere, 2007-11-29
	 */

	requested_size = d->chunk.end - d->chunk.start + d->chunk.overlap;

	buf = header_get(header, "Content-Length"); /* Mandatory */
	if (buf && NULL == header_get(header, "Content-Range")) {
		filesize_t content_size;
		int error;

		content_size = parse_uint64(buf, NULL, 10, &error);
		content_length = content_size;

		if (
			!error &&
			!fi->file_size_known &&
			HTTP_CONTENT_ENCODING_IDENTITY == content_encoding
		) {
			requested_size = download_discovered_size(d, content_size);
		}

		if (error) {
			download_bad_source(d);
			download_stop(d, GTA_DL_ERROR, _("Unparseable Content-Length"));
			return;
		} else if (
			HTTP_CONTENT_ENCODING_IDENTITY == content_encoding &&
			content_size != requested_size
		) {
			if (content_size == fi->size) {
				g_message("file \"%s\": server seems to have "
					"ignored our range request of %s-%s.",
					download_basename(d),
					uint64_to_string(d->chunk.start - d->chunk.overlap),
					uint64_to_string2(d->chunk.end - 1));
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR,
					"Server can't handle resume request");
				return;
			} else {
				check_content_range = content_size;	/* Need Content-Range */
			}
		}

		got_content_length = TRUE;
	}

	buf = header_get(header, "Content-Range");		/* Optional */
	if (buf) {
		filesize_t start, end, total;

		if (0 == http_content_range_parse(buf, &start, &end, &total)) {
			if (!fi->file_size_known) {
				requested_size = download_discovered_size(d, total);
			}

			if (check_content_range > total) {
                if (GNET_PROPERTY(download_debug))
                    g_debug(
						"file \"%s\" on %s: total size mismatch: got %s, "
						"for a served content of %s",
                        download_basename(d),
                        download_host_info(d),
                        uint64_to_string(check_content_range),
						uint64_to_string2(total));

				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR,
					_("Total/served sizes mismatch"));
				return;
			}

			if (start != d->chunk.start - d->chunk.overlap) {
                if (GNET_PROPERTY(download_debug))
                    g_debug("file \"%s\" on %s: start byte mismatch: "
						"wanted %s, got %s",
                        download_basename(d),
                        download_host_info(d),
                        uint64_to_string(d->chunk.start - d->chunk.overlap),
						uint64_to_string2(start));

				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, _("Range start mismatch"));
				return;
			}
			if (total != fi->size) {
                if (GNET_PROPERTY(download_debug)) {
                        g_debug("file \"%s\" on %s: file size mismatch:"
						" expected %s, got %s",
                        download_basename(d), download_host_info(d),
                        uint64_to_string(fi->size), uint64_to_string2(total));
                }
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, _("Filesize mismatch"));
				return;
			}
			if (end > d->chunk.end - 1) {
                if (GNET_PROPERTY(download_debug)) {
                    g_debug("file \"%s\" on %s: end byte too large: "
						"expected %s, got %s",
                        download_basename(d), download_host_info(d),
                        uint64_to_string(d->chunk.end - 1),
						uint64_to_string2(end));
                }
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, _("Range end too large"));
				return;
			}
			if (
				end < (d->chunk.start -
					(d->chunk.start < d->chunk.overlap ? 0 : d->chunk.overlap))
					||
				start >= d->chunk.end
			) {
				char got[64];

				str_bprintf(got, sizeof got, "got %s - %s",
					uint64_to_string(start), uint64_to_string2(end));

				/* XXX: Should we check whether we can use this range
				 *		nonetheless? This addresses the problem described
				 *		here:
				 *
				 * 		http://sf.net/mailarchive/message.php?msg_id=10454795
				 */

				g_message("file \"%s\" on %s: "
					"Range mismatch: wanted %s - %s, %s",
					download_basename(d),
					download_host_info(d),
					uint64_to_string(d->chunk.start),
					uint64_to_string2(d->chunk.end - 1),
					got);
				download_stop(d, GTA_DL_ERROR, _("Range mismatch"));
				return;
			}
			if (end < d->chunk.end - 1) {
                if (GNET_PROPERTY(download_debug))
                    g_debug(
						"file \"%s\" on %s: end byte short: wanted %s, "
						"got %s (continuing anyway)",
                        download_basename(d),
                        download_host_info(d),
                        uint64_to_string(d->chunk.end - 1),
						uint64_to_string2(end));

				/*
				 * Make sure there is something sensible served, i.e. the
				 * upper boundary must be greater than the lower (requested)
				 * one.		--RAM, 2006-01-13
				 *
				 * Note that this can happen and does not indicate a remote
				 * server-side bug: it's just that the real start of the
				 * request is d->chunk.start - d->chunk.overlap, and the server
				 * wants us to grab something that is only in the overlap
				 * section, because it is serving a partial file and has only
				 * that much to offer.
				 *			--RAM, 2010-10-18
				 *
				 * FIXME: shouldn't we sink that, and update our vision of
				 * the available ranges if we can determine that the remote
				 * file is indeed partial?
				 */

				if (d->chunk.start >= end + 1) {
					download_queue_delay_switch(d, header,
						MAX(delay, GNET_PROPERTY(download_retry_refused_delay)),
						_("Weird server-side chunk shrinking"));
					return;
				}

				/*
				 * Since we're getting less than we asked for, we need to
				 * update the end/size information and mark as DL_CHUNK_EMPTY
				 * the trailing part of the range we won't be getting.
				 *		-- RAM, 15/05/2003
				 */

				file_info_update(d,
					d->chunk.start, d->chunk.end, DL_CHUNK_EMPTY);
				if (d->chunk.start != end + 1)
					file_info_update(d, d->chunk.start, end + 1, DL_CHUNK_BUSY);

				d->chunk.end = end + 1;		/* The new end */
				/* Don't count overlap */
				d->chunk.size = d->chunk.end - d->chunk.start;
				d->flags |= DL_F_SHRUNK_REPLY;		/* Remember shrinking */

				fi_src_info_changed(d);
			}
			got_content_length = TRUE;
			check_content_range = 0;		/* We validated the served range */
		} else {
            if (GNET_PROPERTY(download_debug)) {
                g_debug("file \"%s\" on %s: malformed Content-Range: %s",
					download_basename(d), download_host_info(d), buf);
            }
        }
	}

	/*
	 * If we needed a Content-Range to validate the served range,
	 * but we didn't have any or could not parse it, abort!
	 */

	if (check_content_range != 0) {
		g_message("file \"%s\": expected content of %s, server %s said %s",
			download_basename(d), uint64_to_string(requested_size),
			download_host_info(d), uint64_to_string2(check_content_range));
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, _("Content-Length mismatch"));
		return;
	}

	/*
	 * If neither Content-Length nor Content-Range was seen, and they are
	 * not using "chunked" Transfer-Encoding, abort, unless the connection
	 * won't be kept alive (we'll read until EOF).
	 *		--RAM, 2007-05-05
	 */

	if (!got_content_length && d->keep_alive && !is_chunked) {
		const char *ua = header_get(header, "Server");
		ua = ua ? ua : header_get(header, "User-Agent");
		if (ua && GNET_PROPERTY(download_debug))
			g_debug("server \"%s\" did not send any length indication", ua);
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, _("No Content-Length header"));
		return;
	}

	/*
	 * If we reached that point, we can count a resource switching success.
	 */

	if (d->flags & DL_F_SWITCHED) {
		gnet_stats_inc_general(GNR_SUCCESSFUL_RESOURCE_SWITCHING);
		if (!download_is_special(d) && (d->flags & DL_F_FROM_PLAIN)) {
			gnet_stats_inc_general(GNR_SUCCESSFUL_PLAIN_RESOURCE_SWITCHING);
		} else if (d->flags & DL_F_FROM_ERROR) {
			gnet_stats_inc_general(
				GNR_SUCCESSFUL_RESOURCE_SWITCHING_AFTER_ERROR);
		}
		d->flags &= ~(DL_F_SWITCHED | DL_F_FROM_PLAIN | DL_F_FROM_ERROR);
	}

	/*
	 * Handle browse-host requests specially: there's no file to save to.
	 */

	if (d->flags & DL_F_PREFIX_HEAD) {
		/* Ignore the rest */	
	} else if (d->flags & DL_F_BROWSE) {
		gnet_host_t host;
		uint32 flags = 0;

		g_assert(d->browse != NULL);

		gnet_host_set(&host, download_addr(d), download_port(d));

		if (HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
			flags |= BH_DL_INFLATE;
		}
		if (is_chunked) {
			flags |= BH_DL_CHUNKED;
		}

		/*
		 * Are we getting proper query hits?
		 */

		buf = header_get(header, "Content-Type");		/* Mandatory */
		if (buf != NULL) {
			if (strtok_case_has(buf, ",", APP_GNUTELLA)) {
				/* OK, nothing to do */
			} else if (strtok_case_has(buf, ",", APP_G2)) {
				flags |= BH_DL_G2;
			} else {
				if (GNET_PROPERTY(download_debug)) {
					g_debug("unknown Content-Type \"%s\" from %s",
						buf, download_host_info(d));
				}
				download_stop(d, GTA_DL_ERROR, _("Unexpected Content-Type"));
				return;
			}
		} else {
			download_stop(d, GTA_DL_ERROR, _("No Content-Type"));
			return;
		}

		if (
			!browse_host_dl_receive(d->browse, &host, &d->socket->wio,
				download_vendor_str(d), flags)
		) {
			download_stop(d, GTA_DL_ERROR, _("Search already closed"));
			return;
		}

		d->bio = browse_host_io_source(d->browse);
	} else if (d->flags & DL_F_THEX) {
		gnet_host_t host;
		uint32 flags = 0;

		g_assert(d->thex != NULL);

		gnet_host_set(&host, download_addr(d), download_port(d));

		if (HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
			flags |= THEX_DOWNLOAD_F_INFLATE;
		}
		if (is_chunked) {
			flags |= THEX_DOWNLOAD_F_CHUNKED;
		}

		if (
			!thex_download_receive(d->thex, content_length,
				&host, &d->socket->wio, flags)
		) {
			download_stop(d, GTA_DL_ERROR, _("THEX download aborted"));
			return;
		}

		d->bio = thex_download_io_source(d->thex);
	} else if (d->chunk.size == 0 && fi->file_size_known) {
		g_assert(d->flags & DL_F_SHRUNK_REPLY);
		download_queue_delay(d,
			MAX(delay, GNET_PROPERTY(download_retry_busy_delay)),
			_("Partial file on server, waiting"));
		return;
	}

	/*
	 * Cleanup header-reading data structures.
	 */

	io_free(d->io_opaque);
	getline_free(s->getline);		/* No longer need this */
	s->getline = NULL;

	if (d->flags & DL_F_PREFIX_HEAD) {
		d->flags &= ~DL_F_PREFIX_HEAD;
		d->served_reqs++;
		download_set_status(d, GTA_DL_CONNECTED);
		file_info_clear_download(d, TRUE);
		s->pos = 0;
		download_send_request(d);
		return;
	}

	/*
	 * Done for a special request (e.g. THEX or browse downloads).
	 */

	if (download_is_special(d)) {
		download_mark_active(d, FALSE, is_followup);

		/*
		 * If we have something in the socket buffer, feed it to the RX stack.
	 	 */

		if (s->pos > 0) {
			size_t size = s->pos;

			s->pos = 0;
			fi->recv_amount += size;
			if (d->flags & DL_F_BROWSE) {
				browse_host_dl_write(d->browse, s->buf, size);
			} else if (d->flags & DL_F_THEX) {
				thex_download_write(d->thex, s->buf, size);
			}
		}
		return;
	}

	/*
	 * The RX stack from a previous request (if any) is normally recreated
	 * from scratch when dealing with a non-pipelined request / response
	 * stream.
	 *
	 * When pipelining requests, there is no stop in the flow of incoming
	 * data from the remote servent to mark the end of the previous request.
	 * Therefore, the RX stack is kept so that we may propagate received
	 * buffers which are meant to be data for the new request.
	 *
	 * Because we cannot use pipelining when there is chunking or deflation,
	 * we must make sure the server is not suddenly switching to that mode
	 * of operations.
	 */

	if (d->rx != NULL) {
		/* Handling a reply from a pipelined request */

		if (is_chunked || HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
			download_queue_delay(d, 10, _("Pipeline flow stopped"));
			return;
		}
		pipelined_response = TRUE;
		goto rx_stack_setup;	/* Avoid indenting following code */
	}

	{
		struct rx_link_args args;
		gnet_host_t host;

		args.cb = &download_rx_link_cb;
		args.bws = bsched_in_select_by_addr(s->addr);
		args.wio = &d->socket->wio;

		gnet_host_set(&host, download_addr(d), download_port(d));
		d->rx = rx_make(d, &host, rx_link_get_ops(), &args);
	}

	/*
	 * If data is chunked or compressed then we cannot use HTTP pipelining
	 * because the RX stack will not be able to process correctly the HTTP
	 * status for the pipelined request response if it comes together following
	 * data from the previous request: an inflating reception layer would
	 * choke on the plain non-deflated HTTP header!
	 */

	if (is_chunked) {
		struct rx_chunk_args args;

		args.cb = &download_rx_chunk_cb;
		d->rx = rx_make_above(d->rx, rx_chunk_get_ops(), &args);
		d->flags |= DL_F_NO_PIPELINE;	/* Pipelining disabled during request */
	}
	if (HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
		struct rx_inflate_args args;

		args.cb = &download_rx_inflate_cb;
		d->rx = rx_make_above(d->rx, rx_inflate_get_ops(), &args);
		d->flags |= DL_F_NO_PIPELINE;	/* Disabled for this request */
	}
	rx_enable(d->rx);

rx_stack_setup:
	if (d->flags & DL_F_MUST_IGNORE) {
		d->flags &= ~DL_F_MUST_IGNORE;
		must_ignore = TRUE;
		rx_set_data_ind(d->rx, download_ignore_data_ind);
		gnet_stats_inc_general(GNR_IGNORING_TO_PRESERVE_CONNECTION);
	} else {
		must_ignore = FALSE;
		rx_set_data_ind(d->rx, download_data_ind);
	}

	/*
	 * Open output file.
	 *
	 * When pieplining, we know that we'll stay on the same file so we keep
	 * the file opened between requests.
	 */

	if (pipelined_response) {
		g_assert(d->out_file != NULL);
		goto file_opened;
	}

	g_assert(NULL == d->out_file);

	if (must_ignore) {
		/*
		 * Ignoring can happen even when files are completely downloaded (and
		 * possibly SHA1-checked and moved away.  In order to avoid any
		 * accidental writing to the completed/verified file as well as provide
		 * a writable file descriptor (normally unused), we open /dev/null.
		 */

		d->out_file = download_open(dev_null);

		if (!d->out_file) {
			const char *error = g_strerror(errno);
			download_stop(d, GTA_DL_ERROR, _("Cannot open %s: %s"),
				dev_null, error);
			return;
		}

		goto file_opened;		/* Avoid too much indenting below */
	}

	d->out_file = download_open(fi->pathname);
	if (d->out_file != NULL) {
		/* File exists, we'll append the data to it */
		if (!fi->use_swarming && (fi->done != d->chunk.start)) {
			g_message("file '%s' changed size (now %s, but was %s)",
				fi->pathname, uint64_to_string(fi->done),
				uint64_to_string2(d->chunk.start));
			download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
				_("Stopped (Output file size changed)"));
			return;
		}
	} else if (!fi->use_swarming && d->chunk.start) {
		download_stop(d, GTA_DL_ERROR, _("Cannot resume: file gone"));
		return;
	} else {
		d->out_file =
			file_object_create(fi->pathname, O_WRONLY, DOWNLOAD_FILE_MODE);
		if (NULL == d->out_file) {
			const char *error = g_strerror(errno);
			download_stop(d, GTA_DL_ERROR, _("Cannot write into file: %s"),
				error);
			return;
		}
	}

file_opened:
	g_assert(d->out_file);

	/*
	 * We're ready to receive.
	 */

	download_mark_active(d, must_ignore, is_followup);

	g_assert(s->gdk_tag == 0);
	g_assert(d->bio == NULL || pipelined_response);

	d->pos = d->chunk.start;			/* Where we'll start writing to file */
	d->bio = rx_bio_source(d->rx);		/* Bandwidth-limited RX I/O source */

	g_assert(DOWNLOAD_IS_ACTIVE(d));	/* Ready to receive via RX stack */

	/*
	 * If we have something in the socket buffer, feed it to the RX stack.
	 */

	if (s->pos > 0) {
		size_t n = s->pos;
		
		s->pos = 0;
		download_write(d, s->buf, n, pipelined_response);
		fi->recv_amount += n;
	}
}

/**
 * Called when header reading times out.
 */
static void
download_incomplete_header(struct download *d)
{
	header_t *header;

	download_check(d);
	header = io_header(d->io_opaque);
	download_request(d, header, FALSE);
}

/**
 * Read callback for file data from the RX stack.
 */
static bool
download_read(struct download *d, pmsg_t *mb)
{
	fileinfo_t *fi;
	int received;

	download_check(d);
	socket_check(d->socket);
	file_info_check(d->file_info);
	g_assert(d->file_info->recvcount > 0);

	fi = d->file_info;

	if (buffers_full(d)) {
		download_queue_delay(d, GNET_PROPERTY(download_retry_stopped_delay),
			_("Stopped (Read buffer full)"));
		goto error;
	}

	if (fi->file_size_known) {
		g_assert(d->pos <= fi->size);

		if (d->pos == fi->size) {
			download_stop(d, GTA_DL_ERROR, _("Failed (Completed?)"));
			goto error;
		}
	}

	/*
	 * When pipelining requests, the server may have already read and processed
	 * the next request and begun sending its data along with data from
	 * the previous request (especially if there was TCP buffering due to
	 * the Nagle algorithm for the last few bytes of the previous request).
	 *
	 * Hence we need to process only what pertains to the current request and
	 * keep the extra data around to be able to feed them when we're processing
	 * the result from the next request (which will be a leading HTTP reply
	 * header pertaining to the pipelined HTTP request we sent followed by
	 * the requested data).
	 */

	if (d->pipeline != NULL && GTA_DL_PIPE_SENT == d->pipeline->status) {
		size_t buffered = download_buffered(d);
		filesize_t start = d->pos;

		/*
		 * If we have an overlapping window and DL_F_OVERLAPPED is not
		 * set yet, then we're still receiving overlapping data, which need
		 * to be accounted to determine whether the received data are going
		 * past the end of the current chunk.
		 */

		if (d->chunk.overlap && !(d->flags & DL_F_OVERLAPPED))
			start -= d->chunk.overlap;

		if (start + buffered + pmsg_size(mb) > d->chunk.end) {
			filesize_t offset = d->chunk.end - (start + buffered);

			g_assert(offset <= MAX_INT_VAL(int));
			g_assert(NULL == d->pipeline->extra);	/* Done once per request */

			d->pipeline->extra = pmsg_split(mb, offset);
		}
	}

	received = pmsg_size(mb);
	fi->recv_amount += received;
	d->downloaded += received;
	buffers_add_read(d, mb);	/* mb will be kept and freed as needed */

	d->last_update = tm_time();

	/*
	 * Possibly write data if we reached the end of the chunk we requested,
	 * or if the buffers hold enough data.
	 */

	return download_write_data(d);

error:
	pmsg_free(mb);
	return FALSE;
}

/**
 * Read callback for file data from the RX stack, used when we ignore those
 * data after a failed resuming check.
 */
static bool
download_ignore_data(struct download *d, pmsg_t *mb)
{
	download_check(d);
	socket_check(d->socket);
	file_info_check(d->file_info);
	g_assert(d->file_info->recvcount > 0);

	/*
	 * Same logic as download_read() when dealing with pipelined requests.
	 */

	if (d->pipeline != NULL && GTA_DL_PIPE_SENT == d->pipeline->status) {
		if (d->pos + pmsg_size(mb) > d->chunk.end) {
			filesize_t offset = d->chunk.end - d->pos;

			g_assert(offset <= MAX_INT_VAL(int));
			g_assert(NULL == d->pipeline->extra);	/* Done once per request */

			d->pipeline->extra = pmsg_split(mb, offset);
		}
	}

	d->last_update = tm_time();
	d->pos += pmsg_size(mb);

	gnet_stats_count_general(GNR_IGNORED_DATA, pmsg_size(mb));
	pmsg_free(mb);

	/*
	 * Do not increment fi->recv_amount here, because we're ignoring the
	 * data we're receiving: if we account it, it will lower the ETA for
	 * completion even more, wrongly.
	 *		--RAM, 2007-05-07
	 */

	fi_src_status_changed(d);

	if (d->pos >= d->chunk.end) {
		fileinfo_t *fi = d->file_info;
		bool pipelining = download_pipelining(d);

		/*
		 * We finished our request, go on with a new one, hoping it will
		 * match this time or give us good data if we request elsewhere
		 * with no resuming checking possibilities.
		 */

		download_continue(d, d->pos > d->chunk.end);

		/*
		 * Two sources could have competed one against another, forcing
		 * ignoring on each other. Yet the file is done and nobody spotted
		 * it because both went to "ignore mode" to preserve the connections
		 * and therefore the downloads were never stopped.
		 *
		 * Do the check now, but be extra careful since we can spend a long
		 * time in "ignore mode" and the file could alread have been checked
		 * and stripped of its fileinfo trailer by another source completing.
		 */

		if (
			FILE_INFO_COMPLETE(fi) && !FILE_INFO_FINISHED(fi) &&
			!(FI_F_VERIFYING & fi->flags) &&
			!(d->flags & DL_F_SUSPENDED)
		) {
			download_verify_sha1(d);
		}

		/*
		 * If we were pipelining, we have to return TRUE to make it possible
		 * to switch to another download after processing the pipeline response
		 * since we could not know before issuing that next request that the
		 * file would end up being completed sooner.
		 */

		return pipelining;
	}

	return TRUE;
}

/**
 * Called when the whole HTTP request has been sent out.
 */
static void
download_request_sent(struct download *d)
{
	/*
	 * Update status and GUI.
	 */

	download_check(d);

	d->last_update = tm_time();
	tm_now(&d->header_sent);

	if (download_pipelining(d)) {
		g_assert(DOWNLOAD_IS_ACTIVE(d));
		dl_pipeline_check(d->pipeline);
		d->pipeline->status = GTA_DL_PIPE_SENT;
		return;		/* We're still processing reception of previous request */
	} else {
		download_set_status(d, GTA_DL_REQ_SENT);
	}

	/*
	 * Now prepare to read the status line and the headers.
	 * XXX separate this to swallow 100 continuations?
	 */

	g_assert(d->io_opaque == NULL);

	io_get_header(d, &d->io_opaque,
		bsched_in_select_by_addr(d->socket->addr), d->socket, IO_SAVE_FIRST,
		call_download_request, download_start_reading, &download_io_error);
}

/**
 * I/O callback invoked when we can write more data to the server to finish
 * sending the HTTP request.
 */
static void
download_write_request(void *data, int unused_source, inputevt_cond_t cond)
{
	struct download *d = data;
	struct gnutella_socket *s;
	http_buffer_t *r;
	ssize_t sent;
	int rw;
	char *base;

	(void) unused_source;
	download_check(d);

	s = d->socket;
	r = download_pipelining(d) ? d->pipeline->req : d->req;

	g_assert(s->gdk_tag);		/* I/O callback still registered */
	http_buffer_check(r);
	g_assert(d->pipeline != NULL || GTA_DL_REQ_SENDING == d->status);
	g_assert(NULL == d->pipeline || GTA_DL_PIPE_SENDING == d->pipeline->status);

	if (cond & INPUT_EVENT_EXCEPTION) {
		const char *msg = _("Could not send whole HTTP request");

		/*
		 * If download is queued with PARQ, don't stop the download on a write
		 * error or we'd lose the PARQ ID, and the download entry.  If the
		 * server contacts us back with a QUEUE callback, we could be unable
		 * to resume!
		 *		--RAM, 14/07/2003
		 */

		socket_eof(s);

		if (d->parq_dl) {
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				"%s", msg);
		} else {
			download_stop(d, GTA_DL_ERROR, "%s", msg);
		}
		return;
	}

	rw = http_buffer_unread(r);			/* Data we still have to send */
	base = http_buffer_read_base(r);	/* And where unsent data start */

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, base, rw);
	if ((ssize_t) -1 == sent) {
		/*
		 * If download is queued with PARQ, etc...  [Same as above]
		 */

		if (d->parq_dl) {
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				_("Write failed: %s"), g_strerror(errno));
		} else {
			download_stop(d, GTA_DL_ERROR,
				_("Write failed: %s"), g_strerror(errno));
		}
		return;
	} else if (sent < rw) {
		http_buffer_add_read(r, sent);
		return;
	} else if (GNET_PROPERTY(download_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent Request (%s%s) completely to %s (%u bytes):",
			download_pipelining(d) ? "pipelined " : "",
			d->keep_alive ? "follow-up" : "initial",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			http_buffer_length(r));
		dump_string(stderr, http_buffer_base(r), http_buffer_length(r), "----");
	}

	/*
	 * HTTP request was completely sent.
	 */

	if (GNET_PROPERTY(download_debug)) {
		g_debug("flushed partially written %sHTTP request to %s (%u bytes)",
			download_pipelining(d) ? "pipelined " : "",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			http_buffer_length(r));
    }

	socket_evt_clear(s);

	http_buffer_free(r);
	if (download_pipelining(d)) {
		d->pipeline->req = NULL;
	} else {
		d->req = NULL;
	}

	download_request_sent(d);
}

/**
 * Send the HTTP request for a download, then prepare I/O reading callbacks
 * to read the incoming status line and following headers.
 *
 * @attention
 * NB: can stop the download, but does not return anything.
 */
void
download_send_request(struct download *d)
{
	struct gnutella_socket *s;
	const struct sha1 *sha1;
	const char *method;
	char request_buf[4096];
	fileinfo_t *fi;
	size_t rw;
	ssize_t sent;
	size_t maxsize = sizeof request_buf - 3;
	struct dl_chunk *req = NULL;

	download_check(d);

	s = d->socket;
	fi = d->file_info;

	socket_check(s);
	file_info_check(fi);
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	/*
	 * If we have a pipelined request, we're sending (or have already sent
	 * earlier) an HTTP request ahead of time.
	 *
	 * The first time we see a pipelined request, it must be in the
	 * GTA_DL_PIPE_SELECTED state and we're called to send it ahead of time,
	 * whilst another HTTP request is currently being processed (data received).
	 *
	 * The second time we're called, it would be to send a new request but
	 * the pipelined request may have been incompletely sent (in the
	 * GTA_DL_PIPE_SENDING state).  In that case, we act as if we had just
	 * selected a new request to send and move the download to the
	 * GTA_DL_REQ_SENDING state so that it continues to wait for the full 
	 * request flush to the server.
	 *
	 * Or the second time the request can be in the GTA_DL_PIPE_SENT state,
	 * meaning we already sent the pipelined request the first time and so the
	 * server should have got it right now: we can prepare for reception and
	 * we have nothing else to send right now.
	 *
	 * The second time we're called with a pipelined request we have to
	 * populate the download structure with the HTTP request information.
	 */

	if (download_pipelining(d)) {
		struct dl_pipeline *dp = d->pipeline;
		dl_pipeline_status_t status;

		dl_pipeline_check(dp);

		status = dp->status;

		switch (status) {
		case GTA_DL_PIPE_SELECTED:	/* Sending new pipelined request */
			req = &dp->chunk;
			d->flags |= DL_F_PIPELINED;	/* Suppress HTTP latency computation */
			goto picked;
		case GTA_DL_PIPE_SENDING:	/* Partially sent already */
			g_assert(dp->req != NULL);	/* Buffered request to flush */
			g_assert(NULL == d->req);	/* Was processing previous request */
			g_assert(s->gdk_tag != 0);	/* Event: download_write_request() */
			/* FALL THROUGH */
		case GTA_DL_PIPE_SENT:		/* Fully sent already */
			d->chunk = dp->chunk;	/* Struct copy */
			d->flags &= ~DL_F_REPLIED;	/* Will be set if we get a reply */
			fi_src_info_changed(d);
			if (GTA_DL_PIPE_SENDING == status) {
				download_set_status(d, GTA_DL_REQ_SENDING);
				d->req = dp->req;		/* Currently pending request */
				dp->req = NULL;			/* Transferred to the download now */
			}

			/*
			 * Since we went this far, assume the server supports pipelining.
			 *
			 * Some broken servers will close the connection as soon as they
			 * receive extra data on the HTTP socket (the pipelined request)
			 * and this is detected by download_rx_error() now.
			 *		--RAM, 2012-12-09
			 */

			d->server->attrs |= DLS_A_PIPELINING;

			/*
			 * Before discarding the pipeline structure (because we're now
			 * going to process the reply to the pipelined request soon),
			 * propagate back to the socket buffer any data that was sent by
			 * the remote server after it completed the sending of the previous
			 * chunk.
			 *
			 * A NULL pipeline structure will signal download_request_sent()
			 * that it can parse the HTTP reply.
			 */

			download_pipeline_read(d);
			download_pipeline_free_null(&d->pipeline);
			if (GTA_DL_PIPE_SENDING == status)
				return;
			else
				goto fully_sent;
		}

		g_error("%s(): impossible state %d of HTTP pipelined "
			"request for \"%s\"", G_STRFUNC, dp->status, download_basename(d));
	} else {
		req = &d->chunk;
	}

	fi_src_info_changed(d);

	/*
	 * If we have d->always_push set, yet we did not use a Push, it means we
	 * finally tried to connect directly to this server.  And we succeeded!
	 *		-- RAM, 18/08/2002.
	 */

	if (d->always_push && !DOWNLOAD_IS_IN_PUSH_MODE(d)) {
		if (GNET_PROPERTY(download_debug) > 2)
			g_debug("PUSH not necessary to reach %s",
				host_addr_port_to_string(download_addr(d), download_port(d)));
		d->server->attrs |= DLS_A_PUSH_IGN;
		d->always_push = FALSE;
	}

	/*
	 * If we're swarming, pick a free chunk.
	 * (will set d->chunk.start and d->chunk.overlap).
	 *
	 * We combine use_swarming + file_size_known because when the file size
	 * is not known, we only know to request the trailing part.  For the upper
	 * file part, we cannot swarm obviously since we do not know when the file
	 * will end.  For lower (inner) parts that could be missing or have been
	 * invalidated for some reason, we could one day support swarming, but
	 * it remains to be determined that this is useful and will happpen: we
	 * have no reason to invalidate inner parts (no TTH or the file size would
	 * necessarily be known).
	 */

	if (fi->use_swarming && fi->file_size_known) {
		/*
		 * PFSP -- client side
		 *
		 * If we're retrying after a 503/416 reply from a servent
		 * supporting PFSP, then the chunk is already chosen.
		 */

		if (d->flags & DL_F_CHUNK_CHOSEN)
			d->flags &= ~DL_F_CHUNK_CHOSEN;
		else {
			if (NULL == d->ranges || !download_pick_available(d, &d->chunk)) {
				/*
				 * Ranges may have changed on server, attempt to grab
				 * any chunk, regardless of what we can think is available.
				 */

				if (!download_pick_chunk(d, &d->chunk, TRUE))
					return;
			}
		}
	} else {
		/* XXX -- revisit this encapsulation violation after 0.96 -- RAM */
		/* XXX (when filesize is not known, fileinfo should handle this) */
		d->chunk.start = fi->done;		/* XXX no overlapping here */
		d->chunk.size = 0;
	}

	d->flags &= ~DL_F_REPLIED;			/* Will be set if we get a reply */

picked:

	g_assert(req != NULL);
	g_assert(req->overlap <= s->buf_size);

	/*
	 * We can have a SHA1 for this download (information gathered from
	 * the query hit, or from a previous interaction with the server),
	 * or from the fileinfo metadata (if we don't have d->sha1 yet, it means
	 * we assigned the fileinfo based on name only).
	 */

	sha1 = d->sha1 ? d->sha1 : fi->sha1;
	if (sha1)
		d->flags |= DL_F_URIRES;
	else
		d->flags &= ~DL_F_URIRES;

	/*
	 * Tell GUI about the selected range, and that we're sending.
	 */

	d->last_update = tm_time();

	if (download_pipelining(d)) {
		g_assert(DOWNLOAD_IS_ACTIVE(d));
		d->pipeline->status = GTA_DL_PIPE_SENDING;
		fi_src_status_changed(d);
	} else {
		download_set_status(d, GTA_DL_REQ_SENDING);
	}

	/*
	 * Build the HTTP request.
	 */

	if ((DLS_A_FOOBAR & d->server->attrs) && 0 == d->served_reqs) {
		g_assert(!download_pipelining(d));
		d->flags |= DL_F_PREFIX_HEAD;
		method = "HEAD";
	} else {
		method = "GET";
	}

	if (d->uri) {
		char *escaped_uri;

		escaped_uri = url_fix_escape(d->uri);
		rw = str_bprintf(request_buf, maxsize,
				"%s %s HTTP/1.1\r\n", method, escaped_uri);
		if (escaped_uri != d->uri) {
			HFREE_NULL(escaped_uri);
		}
	} else if (sha1) {
		rw = str_bprintf(request_buf, maxsize,
				"%s /uri-res/N2R?urn:sha1:%s HTTP/1.1\r\n",
				method, sha1_base32(sha1));
	} else {
		char *escaped = url_escape(d->file_name);

		rw = str_bprintf(request_buf, maxsize,
				"%s /get/%lu/%s HTTP/1.1\r\n",
				method, (ulong) d->record_index, escaped);

		if (escaped != d->file_name) {
			HFREE_NULL(escaped);
		}
	}

	/*
	 * If URL is too large, abort.
	 */

	if (rw >= MAX_LINE_SIZE) {
		g_assert(!download_pipelining(d));	/* Can't happen if we pipeline */
		download_stop(d, GTA_DL_ERROR, "URL too large");
		return;
	}

	/*
	 * When sending a follow-up request to a GTKG server, we do not need
	 * to include the User-Agent string again.  Other vendors do require
	 * the field, unfortunately.
	 *		--RAM, 2012-11-19
	 */

	if (
		!d->keep_alive ||
		!is_strprefix(download_vendor_str(d), "gtk-gnutella/")
	) {
		rw += str_bprintf(&request_buf[rw], maxsize - rw,
			"User-Agent: %s\r\n", version_string);
	}

	rw += str_bprintf(&request_buf[rw], maxsize - rw,
		"Host: %s\r\n",
		d->server->hostname
			? d->server->hostname
			: host_addr_port_to_string(download_addr(d), download_port(d)));

	if (d->server->attrs & (DLS_A_FAKE_G2 | DLS_A_G2_ONLY)) {
		rw += str_bprintf(&request_buf[rw], maxsize - rw,
			"X-Features: g2/1.0\r\n");
	} else if (!d->keep_alive) {		/* Not a follow-up HTTP request */
		/*
		 * We never send X-Features or X-Token on follow-up requests.
		 */

		header_features_generate(FEATURES_DOWNLOADS,
			request_buf, maxsize, &rw);

		/*
		 * If we request the file by a custom URI it's most likely
		 * not a Gnutella peer, unless it's a THEX or browse request.
		 */
		if (!d->uri || (d->flags & (DL_F_THEX | DL_F_BROWSE))) {
			rw += str_bprintf(&request_buf[rw], maxsize - rw,
					"X-Token: %s\r\n", tok_version());
		}
	}

	if (d->flags & DL_F_BROWSE) {
		rw += str_bprintf(&request_buf[rw], maxsize - rw,
			(d->server->attrs & (DLS_A_FAKE_G2 | DLS_A_G2_ONLY)) ?
				"Accept: application/x-gnutella2\r\n" :
				"Accept: application/x-gnutella-packets\r\n");
	}
	if (d->flags & DL_F_THEX) {
		rw += str_bprintf(&request_buf[rw], maxsize - rw,
				"Accept: application/dime\r\n");
	}

	rw += str_bprintf(&request_buf[rw], maxsize - rw,
			"Accept-Encoding: deflate\r\n");

	/*
	 * Add X-Queue / X-Queued information into the header
	 */
	parq_download_add_header(request_buf, maxsize, &rw, d);

	/*
	 * If server is known to NOT support keepalives, then request only
	 * a range starting from d->chunk.start.  Likewise if we know that the
	 * server does not support HTTP/1.1.
	 *
	 * Otherwise, we request a range and expect the server to keep the
	 * connection alive once the range has been fully served so that
	 * we may request the next chunk, if needed.
	 */

	g_assert(req->start >= req->overlap);

	if (fi->file_size_known && !(d->server->attrs & DLS_A_NO_HTTP_1_1)) {
		/*
		 * Request exact range, unless we're asking for the full file
		 */

		if (req->size != download_filesize(d)) {
			filesize_t start = req->start - req->overlap;

			rw += str_bprintf(&request_buf[rw], maxsize - rw,
				"Range: bytes=%s-%s\r\n",
				uint64_to_string(start), uint64_to_string2(req->end - 1));
		}
	} else {
		/* Request only a lower-bounded range, if needed */

		req->end = fi->file_size_known ? download_filesize(d) : (filesize_t) -1;

		if (req->start > req->overlap)
			rw += str_bprintf(&request_buf[rw], maxsize - rw,
				"Range: bytes=%s-\r\n",
				uint64_to_string(req->start - req->overlap));
	}

	if (!download_pipelining(d)) {
		fi_src_info_changed(d);		/* Now that we know d->chunk.end */
	}

	/*
	 * LimeWire hosts have started to emit an X-Downloaded: header stating
	 * the amount of bytes already downloaded by the requester.  This can
	 * be used to prioritize slots in a queue, or to prioritize requests
	 * when the remote host also has a partial file and wants to complete it.
	 *
	 * Let's emit the header for now, and we'll see whether we can peruse
	 * this information ourselves later.
	 *		--RAM, 2009-02-27
	 */

	if (!download_is_special(d) && !(d->server->attrs & DLS_A_FAKE_G2)) {
		rw += str_bprintf(&request_buf[rw], maxsize - rw,
			"X-Downloaded: %s\r\n", uint64_to_string(download_filedone(d)));
	}

	g_assert(rw + 3U < sizeof request_buf);	/* Should not have filled yet! */

	/*
	 * If we are firewalled, send X-FW-Node-Info with push-proxies.
	 */

	if (
		GNET_PROPERTY(is_firewalled) &&
		!(d->server->attrs &
			(DLS_A_MINIMAL_HTTP | DLS_A_G2_ONLY | DLS_A_FAKE_G2))
	) {

		rw += node_http_fw_node_info_add(
			&request_buf[rw], maxsize - rw, TRUE, dl_server_net(d->server));
	}

	/*
	 * In any case, if we know a SHA1, we need to send it over.  If the server
	 * sees a mismatch, it will abort.
	 */

	if (sha1 != NULL) {
		size_t sha1_room, wmesh;

		/*
		 * Leave room for the urn:sha1: possibly, plus final 2 * "\r\n".
		 */

		sha1_room = 33 + SHA1_BASE32_SIZE + 4;

		/*
		 * Send to the server any new alternate locations we may have
		 * learned about since the last time.
		 *
		 * Because the mesh header can be large, we use HTTP continuations
		 * to format it, but some broken servents do not know how to parse
		 * them.  Use minimal HTTP with those.
		 */

		if (d->server->attrs & DLS_A_MINIMAL_HTTP) {
			wmesh = 0;
		} else {
			fileinfo_t *file_info = d->file_info;
			size_t altloc_size;

			altloc_size = maxsize;
			altloc_size -= MIN(altloc_size, rw);
			altloc_size -= MIN(altloc_size, sha1_room);
			
			/*
			 * If we're short on HTTP output bandwidth, limit the size of
			 * the alt-locs we send and don't provide our fileinfo, so that
			 * we don't generate an URL for ourselves (if PFSP-server is on)
			 * which would attract even more HTTP traffic.
			 *		--RAM, 12/10/2003
			 *
			 * If there are only a few sources known for that file, we always
			 * propagate ourselves however (if PFSP is enabled) because we
			 * need to attract uploaders that will tell us about the locations
			 * they know.
			 *		--RAM, 2005-10-20
			 */

			if (bsched_saturated(BSCHED_BWS_OUT)) {
				altloc_size = MIN(altloc_size, 160);
				if (fi_alive_count(file_info) > FI_LOW_SRC_COUNT)
					file_info = NULL;
			}

			/*
			 * We have HEAD Pings and the alt-loc management isn't the
			 * greatest, thus keep the HTTP overhead at reasonable limit.
			 */
			altloc_size = MIN(altloc_size, DOWNLOAD_ALT_LOC_SIZE);

			/*
			 * Emit X-Alt: and possibly X-Nalt: headers.
			 */

			wmesh = dmesh_alternate_location(sha1,
				&request_buf[rw], altloc_size,
				download_addr(d), d->last_dmesh, download_vendor(d),
				file_info, TRUE,
				(d->server->attrs & DLS_A_FWALT) ?
					download_guid(d) : NULL,
				dl_server_net(d->server));
			rw += wmesh;

			if (wmesh > 0)
				d->last_dmesh = tm_time();
		}

		/*
		 * HUGE specs says that the alternate locations are only defined
		 * when there is an X-Gnutella-Content-URN present.	When we use
		 * the N2R form to retrieve a resource by SHA1, that line is
		 * redundant.  We only send it if we sent mesh information.
		 */

		if (wmesh) {
			g_assert(sha1);
			if (d->server->attrs & (DLS_A_FAKE_G2 | DLS_A_G2_ONLY)) {
				rw += str_bprintf(&request_buf[rw], maxsize - rw,
					"X-Content-URN: urn:sha1:%s\r\n",
					sha1_base32(sha1));
			} else {
				rw += str_bprintf(&request_buf[rw], maxsize - rw,
					"X-Gnutella-Content-URN: urn:sha1:%s\r\n",
					sha1_base32(sha1));
			}
		}
	}

	/*
	 * Finish headers.
	 */

	g_assert(rw + 3U <= sizeof request_buf);	/* Has room for final "\r\n" */

	rw += str_bprintf(&request_buf[rw], sizeof request_buf - rw, "\r\n");

	/*
	 * Send the HTTP Request
	 *
	 * We re-enable fast ACKs (if supported) each time we send a new request
	 * as the setting can be reverted internally by TCP on some platforms.
	 * As tcp(7) says on linux:
	 *
	 * "Subsequent operation of the TCP protocol will once again enter/leave
	 *  quickack mode depending on internal protocol processing and factors
	 *  such as delayed ack timeouts occurring and data transfer."
	 */

	socket_tos_normal(s);
	socket_set_quickack(s, TRUE);	/* Re-enable quick ACKs at the TCP level */

	sent = bws_write(BSCHED_BWS_OUT, &s->wio, request_buf, rw);
	if ((ssize_t) -1 == sent) {
		/*
		 * If download is queued with PARQ, don't stop the download on a write
		 * error or we'd lose the PARQ ID, and the download entry.  If the
		 * server contacts us back with a QUEUE callback, we could be unable
		 * to resume!
		 *		--RAM, 17/05/2003
		 */

		if (d->parq_dl) {
			download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
				_("Write failed: %s"), g_strerror(errno));
		} else {
			download_stop(d, GTA_DL_ERROR,
				_("Write failed: %s"), g_strerror(errno));
		}
		return;
	} else if ((size_t) sent < rw) {
		/*
		 * Could not send the whole request, probably because the TCP output
		 * path is clogged.
		 */

		g_message("partial HTTP %s write to %s: wrote %u out of %u bytes",
			download_pipelining(d) ? "pipelined request" : "request",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			(uint) sent, (uint) rw);

		if (download_pipelining(d)) {
			g_assert(NULL == d->pipeline->req);
			d->pipeline->req = http_buffer_alloc(request_buf, rw, sent);
		} else {
			g_assert(NULL == d->req);
			d->req = http_buffer_alloc(request_buf, rw, sent);
		}

		/*
		 * Install the writing callback.
		 */

		g_assert(s->gdk_tag == 0);

		socket_evt_set(s, INPUT_EVENT_WX, download_write_request, d);
		return;
	} else if (GNET_PROPERTY(download_trace) & SOCK_TRACE_OUT) {
		g_debug("----Sent Request (%s%s%s%s%s%s%s) to %s (%u bytes):",
			download_pipelining(d) ? "pipelined " : "",
			d->keep_alive ? "follow-up" : "initial",
			(d->server->attrs & DLS_A_NO_HTTP_1_1) ? "" : ", HTTP/1.1",
			(d->server->attrs & DLS_A_PUSH_IGN) ? ", ign-push" : "",
			(d->server->attrs & DLS_A_MINIMAL_HTTP) ? ", minimal" : "",
			DLS_A_G2_ONLY ==
				(d->server->attrs & (DLS_A_FAKE_G2 | DLS_A_G2_ONLY)) ?
					", g2" : "",
			(d->server->attrs & DLS_A_FAKE_G2) ? ", fake-g2" : "",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			(uint) rw);
		dump_string(stderr, request_buf, rw, "----");
	}

fully_sent:
	download_request_sent(d);
}

/**
 * This function is called once a connection has been established.
 */
void
download_connected(struct download *d)
{
	struct gnutella_socket *s;
	time_t now = tm_time();
	struct dl_server *server;

	download_check(d);
	dl_server_valid(d->server);
	socket_check(d->socket);
	g_assert(!download_pipelining(d));		/* Just got connected */

	/*
	 * Entropy harvesting...
	 */

	server = d->server;
	s = d->socket;

	{
		time_delta_t elapsed;
		uint32 entropy;
		host_addr_t addr = server->key->addr;

		elapsed = delta_time(now, server->last_connect);
		entropy = crc32_update(s->port, &addr, sizeof addr);
		entropy = crc32_update(entropy, &elapsed, sizeof elapsed);
		entropy = crc32_update(entropy, &now, sizeof now);
		random_pool_append(&entropy, sizeof entropy);
	}

	server->last_connect = now;
	socket_nodelay(s, TRUE);

	/*
	 * If we issued a DNS lookup, check whether the server address changed.
	 */

	if (d->flags & DL_F_DNS_LOOKUP) {
		if (!host_addr_equal(download_addr(d), s->addr)) {
			if (GNET_PROPERTY(download_debug)) {
				g_debug("DNS lookup revealed server %s moved to %s",
					server_host_info(server), host_addr_to_string(s->addr));
			}
			change_server_addr(server, s->addr, download_port(d));
		}
	}

	download_send_request(d);
}

/**
 * Send download request on the opened connection.
 *
 * Header processing callback, invoked when we have read the second "\n" at
 * the end of the GIV string.
 */
static void
download_push_ready(struct download *d, getline_t *empty)
{
	size_t len = getline_length(empty);

	download_check(d);

	if (len != 0) {
		g_debug("file \"%s\": push reply was not followed by an empty line",
			download_basename(d));
		dump_hex(stderr, "Extra GIV data", getline_str(empty), MIN(len, 80));
		download_stop(d, GTA_DL_ERROR, _("Malformed push reply"));
		return;
	}

	io_free(d->io_opaque);
	download_send_request(d);		/* Will install new I/O data */
}

/**
 * On reception of a "GIV index:GUID" string, select the appropriate download
 * to request, from the list of potential server targets.
 *
 * @returns the selected download, or NULL if we could not find one.
 */
static struct download *
select_push_download(pslist_t *servers)
{
	pslist_t *sl;
	time_t now = tm_time();
	struct download *d = NULL;
	int found = 0;		/* No a boolean to trace where it was found from */

	/*
	 * We do not limit by download slots for GIV... Indeed, pushes are
	 * precious little things.  We must peruse the connection we got
	 * because we don't know whether we'll be able to get another one.
	 * This is where it is nice that the remote end supports queuing... and
	 * PARQ will work either way (i.e. active or passive queuing, since
	 * then we'll get QUEUE callbacks).
	 *		--RAM, 19/07/2003
	 */

	PSLIST_FOREACH(servers, sl) {
		struct dl_server *server = sl->data;
		list_t *prepare;
		list_iter_t *iter;

		g_assert(dl_server_valid(server));

		/*
		 * Look for an active download for this host, expecting a GIV
		 * and not already gone through download_push_ack() i.e. not
		 * connected yet (downloads remain in the expecting state until
		 * they have read the trailing "\n" of the GIV, even though they
		 * are connected).
		 */

		iter = list_iter_before_head(server->list[DL_LIST_RUNNING]);
		while (!found && list_iter_has_next(iter)) {

			d = list_iter_next(iter);
			download_check(d);
			g_assert(DOWNLOAD_IS_RUNNING(d));

			if (!DOWNLOAD_IS_EXPECTING_GIV(d))
				continue;

			if (d->socket == NULL) {
				if (GNET_PROPERTY(download_debug) > 1) g_debug(
					"GIV: selected active download \"%s\" from %s at %s",
					download_basename(d), guid_hex_str(server->key->guid),
					download_host_info(d));
				found = 1;		/* Found in running list */
			}
		}
		list_iter_free(&iter);

		if (found)
			break;

		/*
		 * No luck so far.  Look for waiting downloads for this host.
		 *
		 * We don't check whether
		 *
		 *   count_running_on_server(server) >= max_host_downloads
		 *
		 * for the same reason we don't care about download slots: pushed
		 * downloads are precious.  Let the remote host decide whether
		 * he can accept us.
		 */

		prepare = list_new();
		iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
		while (list_iter_has_next(iter)) {
			d = list_iter_next(iter);

			download_check(d);
			file_info_check(d->file_info);
			g_assert(!DOWNLOAD_IS_RUNNING(d));

			if (download_has_enough_active_sources(d))
				continue;

			if (delta_time(now, d->retry_after) < 0)
				break;		/* List is sorted */

			if (d->flags & (DL_F_SUSPENDED | DL_F_PAUSED))
				continue;

			if (GNET_PROPERTY(download_debug) > 2) g_debug(
				"GIV: will try alternate download \"%s\" from %s at %s",
				download_basename(d), guid_hex_str(server->key->guid),
				download_host_info(d));

			g_assert(d->socket == NULL);

			/*
			 * Potential candidates are recorded into a new list because
			 * download_start_prepare() modifies the list which is just
			 * being traversed.
			 */
			list_append(prepare, d);
		}
		list_iter_free(&iter);

		iter = list_iter_before_head(prepare);
		while (!found && list_iter_has_next(iter)) {
			d = list_iter_next(iter);

			/*
			 * Only prepare the download, don't call download_start(): we
			 * already have the connection, and simply need to prepare the
			 * range offset.
			 */

			download_check(d);
			g_assert(d->socket == NULL);

			if (download_start_prepare(d)) {
				download_set_status(d, GTA_DL_CONNECTED);

				gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);
				gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT,
					count_running_downloads());

				if (GNET_PROPERTY(download_debug) > 1) g_debug("GIV: "
					"selected alternate download \"%s\" from %s at %s",
					download_basename(d), guid_hex_str(server->key->guid),
					download_host_info(d));

				found = 2;			/* Found in waiting list */
				break;
			}
		}
		list_iter_free(&iter);
		list_free(&prepare);

		if (found)
			break;
	}

	g_assert(!found || d->socket == NULL);

	return found ? d : NULL;
}

/*
 * Structure used to select servers matching the GUID / IP address criteria.
 */
struct server_select {
	const struct guid *guid;	/* The GUID that must match */
	host_addr_t addr;			/* The IP address that must match */
	pslist_t *servers;			/* List of servers matching criteria */
	int count;					/* Amount of servers inserted */
};

/**
 * If server is matching the selection criteria, insert it in the
 * result set.
 *
 * This routine is a hash table iterator callback.
 */
static void
select_matching_servers(void *value, void *user)
{
	const struct dl_key *skey;
	struct dl_server *server = value;
	struct server_select *ctx = user;

	g_assert(dl_server_valid(server));

	skey = server->key;

	if (
		guid_eq(skey->guid, ctx->guid) ||
		host_addr_equal(skey->addr, ctx->addr)
	) {
		ctx->servers = pslist_prepend(ctx->servers, server);
		ctx->count++;
	}
}

/**
 * Given a servent GUID and an IP address, build a list of all the servents
 * that bear either this GUID or that IP address.
 *
 * @return a list a servers matching, with `count' being updated with the
 * amount of matching servers we found.

 * @note	It is up to the caller to pslist_free() the returned list.
 */
static pslist_t *
select_servers(const struct guid *guid, const host_addr_t addr, int *count)
{
	struct server_select ctx;

	ctx.guid = guid;
	ctx.addr = addr;
	ctx.servers = NULL;
	ctx.count = 0;

	hikset_foreach(dl_by_host, select_matching_servers, &ctx);

	*count = ctx.count;
	return ctx.servers;
}

/**
 * We may find more that one suitable server when a GIV comes, because GUIDs
 * are not always known for servers and we may get for instance:
 *
 *  #1 is GUID d60159d9606be30beab0fd4242845200 at 24.86.132.181:21173
 *  #2 is GUID 00000000000000000000000000000000 at 24.86.132.181:21173
 *
 * Here we can merge the two servers into one because they have the same
 * address and one has a blank GUID whilst the other has a matching GUID,
 * most probably.
 *
 * This routine merges the two matching servers we found provided that
 * one has a matching non-blank GUID and the other has a blank one.  The
 * server kept is the one with the non-blank GUID and it is set with the
 * proper address (taken from the line with the blank GUID).
 *
 * @return a new pslist_t with the blank GUID removed, or the initial list
 * if we could not perform the merging.
 */
static pslist_t *
merge_push_servers(pslist_t *servers, const struct guid *guid)
{
	struct dl_server *serv[2];
	struct dl_server *duplicate;	/* blank GUID */
	struct dl_server *server;		/* non-blank GUID */
	host_addr_t addr;
	uint16 port;

	g_assert(2 == pslist_length(servers));

	serv[0] = pslist_nth_data(servers, 0);
	serv[1] = pslist_nth_data(servers, 1);

	if (serv[0] == NULL || serv[1] == NULL)
		return servers;

	if (guid_is_blank(serv[0]->key->guid)) {
		duplicate = serv[0];
		server = serv[1];
	} else {
		duplicate = serv[1];
		server = serv[0];
	}

	if (guid_is_blank(server->key->guid))
		return servers;		/* Both GUIDs are blank */

	if (!guid_is_blank(duplicate->key->guid))
		return servers;		/* Both GUIDs are non-blank */

	if (!guid_eq(server->key->guid, guid))
		return servers;		/*  Not a matching GUID */

	/*
	 * We can merge...
	 */

	addr = host_address_is_usable(duplicate->key->addr) ? 
		duplicate->key->addr : server->key->addr;

	port = port_is_valid(duplicate->key->port) ?
		duplicate->key->port : server->key->port;

	if (GNET_PROPERTY(download_debug)) {
		g_debug("%s(): GUID %s at %s into GUID %s at %s (using %s:%u)",
			G_STRFUNC, guid_hex_str(duplicate->key->guid),
			host_addr_port_to_string(
				duplicate->key->addr, duplicate->key->port),
			guid_to_string(server->key->guid),
			host_addr_port_to_string2(server->key->addr, server->key->port),
			host_addr_to_string(addr), port);
	}

	download_reparent_all(duplicate, server);
	change_server_addr(server, addr, port);
	pslist_free(servers);

	return pslist_prepend(NULL, server);
}

/**
 * Attempt to merge multiple servers as much as possible.
 *
 * @return new list of (hopefully merged) servers.
 */
static pslist_t *
merge_servers(pslist_t *servers, const struct guid *guid)
{
	pslist_t *sided = NULL;

	while (pslist_length(servers) >= 2) {
		pslist_t *sl;
		pslist_t *tuple = NULL;
		struct dl_server *non_blank = NULL;

		/*
		 * First we select a server with a non-blank GUID.  If there are none,
		 * then no further merging is possible.
		 */

		PSLIST_FOREACH(servers, sl) {
			struct dl_server *serv = sl->data;

			if (!guid_is_blank(serv->key->guid)) {
				non_blank = serv;
				servers = pslist_remove(servers, non_blank);
				break;
			}
		}

		if (NULL == non_blank)
			return servers;			/* No further merging possible */

		/*
		 * Construct a list with the head of the remaining servers and the
		 * non-blank one and attempt to merge the two.
		 */

		tuple = servers;
		servers = pslist_remove_link(servers, servers);
		tuple = pslist_prepend(tuple, non_blank);

		g_assert(2 == pslist_length(tuple));

		tuple = merge_push_servers(tuple, guid);

		if (1 == pslist_length(tuple)) {
			servers = pslist_prepend(servers, tuple->data);
			pslist_free(tuple);
			continue;
		}

		/*
		 * Could not merge the tuple into one single server.
		 *
		 * We keep the non-blank server to iterate, but we put aside
		 * the other one to re-inject it later.
		 */

		g_assert(2 == pslist_length(tuple));

		tuple = pslist_remove(tuple, non_blank);

		g_assert(1 == pslist_length(tuple));

		sided = pslist_prepend(sided, tuple->data);
		pslist_free(tuple);
		servers = pslist_prepend(servers, non_blank);
	}

	/*
	 * Bring back the un-mergeable servers we may have put aside.
	 */

	return pslist_concat(servers, sided);
}

/**
 * Parse a GIV (Gnutella push callback) or PUSH (G2 push callback) line.
 *
 * @param line		the GIV or PUSH line we got
 * @param hex_guid	array of 33 bytes where the hexadecimal GUID is extracted
 * @param size		the length of the hex_guid buffer
 *
 * @return FALSE on failure, TRUE if the GIV / PUSH was successfully parsed.
 */
static bool
parse_giv(const char *line, char *hex_guid, size_t size)
{
	static const uint hex_guid_len = 32;
	const char *endptr;
	uint i;
	int error;
	bool g2 = FALSE;			/* Assume it's a Gnutella GIV line */

	g_return_val_if_fail(line, FALSE);
	g_return_val_if_fail(hex_guid, FALSE);
	g_return_val_if_fail(size > hex_guid_len, FALSE);

	endptr = is_strprefix(line, "GIV ");
	if (NULL == endptr) {
		endptr = is_strprefix(line, "PUSH ");
		if (NULL == endptr)
			return FALSE;
		g2 = TRUE;				/* A G2 PUSH line */
	}

	/*
	 * A Gnutella GIV line has the following format:
	 *
	 *   GIV <index>:<hexadecimal GUID>/\n\n
	 *
	 * A G2 PUSH line has the following format:
	 *
	 *   PUSH guid:<hexadecimal GUID>\r\n\r\n
	 */

	if (g2) {
		/* Skip the guid: part */
		endptr = skip_ascii_spaces(endptr);
		endptr = is_strprefix(endptr, "guid:");
		if (NULL == endptr)
			return FALSE;
	} else {
		/* A file index must be given but we don't care about its value. */
		(void) parse_uint32(endptr, &endptr, 10, &error);
		if (error || ':' != *endptr)
			return FALSE;
		endptr++;			/* Skip the ':' separator */
	}

	/*
	 * Now extract the 32 bytes of the hexadecimal GUID.
	 */

	for (i = 0; i < hex_guid_len; i++) {
		char c = *endptr++;

		if (!is_ascii_xdigit(c))
			return FALSE;
		hex_guid[i] = c;
	}
	hex_guid[i] = '\0';

	return (g2 ? '\0' : '/') == *endptr;
}

/**
 * Initiate download on the remotely initiated connection.
 *
 * This is called when an incoming "GIV" or "PUSH" request is received in
 * answer to some of our pushes.
 */
void
download_push_ack(struct gnutella_socket *s)
{
	struct download *d = NULL;
	const char *giv;
	char hex_guid[33];			/* The hexadecimal GUID */
	struct guid guid;			/* The decoded (binary) GUID */
	pslist_t *servers;			/* Potential targets for the download */
	int count;					/* Amount of potential targets found */

	socket_check(s);
	g_assert(s->getline);
	giv = getline_str(s->getline);

	gnet_stats_inc_general(GNR_GIV_CALLBACKS);

	if (GNET_PROPERTY(download_trace) & SOCK_TRACE_IN) {
		g_debug("----Got GIV from %s:", host_addr_to_string(s->addr));
		dump_string(stderr, giv, getline_length(s->getline), "----");
	}

	/*
	 * Ensure we can accept the incoming connection to perform an outgoing
	 * HTTP request, eventually.
	 */

	if (hostiles_is_bad(s->addr)) {
		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(socket_debug)) {
			hostiles_flags_t flags = hostiles_check(s->addr);
			g_warning("discarding GIV string \"%s\" from hostile %s (%s)",
				giv, host_addr_to_string(s->addr),
				hostiles_flags_to_string(flags));
		}
		goto discard;
	}

	if (ctl_limit(s->addr, CTL_D_OUTGOING)) {
		if (GNET_PROPERTY(download_debug) || GNET_PROPERTY(ctl_debug)) {
			g_warning("CTL discarding GIV string \"%s\" from %s [%s]",
				giv, host_addr_to_string(s->addr), gip_country_cc(s->addr));
		}
		goto discard;
	}

	/*
	 * To find out which download this is, we have to parse the incoming
	 * GIV / PUSH request, which is stored in "s->getline".
	 */

	if (!parse_giv(giv, hex_guid, sizeof hex_guid)) {
		g_warning("malformed GIV string \"%s\" from %s",
			giv, host_addr_to_string(s->addr));
		goto discard;
	}

	/*
	 * Look for a recorded download.
	 */

	if (!hex_to_guid(hex_guid, &guid)) {
		g_warning("discarding GIV \"%s\" with malformed GUID %s from %s",
			giv, hex_guid, host_addr_to_string(s->addr));
		goto discard;
	}

	if (guid_is_blank(&guid)) {
		g_warning("discarding GIV since server %s supplied a blank GUID",
			host_addr_to_string(s->addr));
		goto discard;
	}

	/*
	 * Identify the targets for this download.
	 */

	servers = select_servers(&guid, s->addr, &count);

	switch (count) {
	case 0:
		if (GNET_PROPERTY(download_debug)) {
			g_warning("discarding GIV: found no host bearing GUID %s or at %s",
				hex_guid, host_addr_to_string(s->addr));
		}
		goto discard;
	case 1:
		break;
	default:
		if (GNET_PROPERTY(download_debug)) {
			pslist_t *sl;
			uint i;

			g_warning("found %d possible targets for GIV from GUID %s at %s",
				count, hex_guid, host_addr_to_string(s->addr));

			for (sl = servers, i = 0; sl; sl = pslist_next(sl), i++) {
				struct dl_server *serv = sl->data;
				g_debug("  #%u is GUID %s at %s <%s>",
					i + 1, guid_hex_str(serv->key->guid),
					host_addr_port_to_string(serv->key->addr, serv->key->port),
					serv->vendor ? serv->vendor : "");
			}

			if (count >= 2) {
				servers = merge_servers(servers, &guid);
			}
		}
		break;
	}

	d = select_push_download(servers);
	pslist_free(servers);

	if (d) {
		download_check(d);
	} else {
		if (GNET_PROPERTY(download_debug)) {
			g_warning("discarded GIV \"%s\" from %s",
				giv, host_addr_to_string(s->addr));
		}
		goto discard;
	}

	if (GNET_PROPERTY(download_debug))
		g_debug("mapped GIV \"%s\" to \"%s\" from %s",
			giv, download_basename(d), download_host_info(d));

	if (d->io_opaque) {
		g_carp("d->io_opaque is already set!");
		goto discard;
	}

	/*
	 * It could be that we were attempting to connect to a push-proxy and
	 * got a GIV whilst we were busy waiting.
	 */

	if (d->cproxy) {
		cproxy_free(d->cproxy);
		d->cproxy = NULL;
	}

	/*
	 * Install socket for the download.
	 */

	g_assert(d->socket == NULL);

	d->got_giv = TRUE;
	d->last_update = tm_time();

	download_attach_socket(d, s);

	/*
	 * Since we got a GIV, we now know the remote IP of the host and its GUID.
	 */

	g_assert(!host_addr_is_unspecified(s->addr));

	if (!host_addr_equal(download_addr(d), s->addr))
		change_server_addr(d->server, s->addr, download_port(d));

	download_found_server(&guid, s->addr, download_port(d));

	g_assert(host_addr_equal(download_addr(d), s->addr));

	fi_src_info_changed(d);

	/*
	 * Now we have to read that trailing "\n" (for Gnutella GIV) or "\r\n"
	 * (for G2 PUSH) which comes right afterwards.
	 *
	 * We can use the same code because getline_read() parses lines ending with
	 * a single '\n' and will swallow any preceding '\r' character.
	 */

	g_assert(NULL == d->io_opaque);
	io_get_header(d, &d->io_opaque, bsched_in_select_by_addr(s->addr),
		s, IO_SINGLE_LINE, call_download_push_ready, NULL, &download_io_error);

	return;

discard:
	gnet_stats_inc_general(GNR_GIV_DISCARDED);
	socket_free_null(&s);
}

/**
 * Find a waiting download on the specified server, identified by its IP:port
 * for which we have no PARQ information yet.
 *
 * @returns NULL if none, the download we found otherwise.
 */
struct download *
download_find_waiting_unparq(const host_addr_t addr, uint16 port)
{
	struct dl_server *server = get_server(&blank_guid, addr, port, FALSE);
	list_iter_t *iter;
	struct download *d = NULL;
	bool found = FALSE;

	if (server == NULL)
		return NULL;

	g_assert(dl_server_valid(server));

	iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter)) {

		d = list_iter_next(iter);
		download_check(d);
		g_assert(!DOWNLOAD_IS_RUNNING(d));

		if (d->flags & (DL_F_SUSPENDED | DL_F_PAUSED)) {
			/* Suspended, cannot pick */
			continue;
		}

		if (d->parq_dl == NULL) {		/* No PARQ information yet */
			found = TRUE;
			break;
		}
	}
	list_iter_free(&iter);

	return found ? d : NULL;
}

/***
 *** Queue persistency routines
 ***/

static const char download_file[] = "downloads";
static const char file_what[] = "downloads"; /**< What is persisted to file */
static bool retrieving = FALSE;

static char *
download_build_magnet(const struct download *d)
{
	const fileinfo_t *fi;
	char *url;
	char *dl_url;
   
	download_check(d);

	fi = d->file_info;
	g_return_val_if_fail(fi, NULL);
	file_info_check(fi);

	dl_url = download_build_url(d);
	if (dl_url) {
		struct magnet_resource *magnet;
		const struct sha1 *sha1;
		const struct tth *tth;
		const char *parq_id;
		const char *vendor;
	
		magnet = magnet_resource_new();

		/* The filename used for the magnet must be UTF-8 encoded */
		magnet_set_display_name(magnet,
			lazy_filename_to_utf8_normalized(filepath_basename(fi->pathname),
				UNI_NORM_NETWORK));

		sha1 = download_get_sha1(d);
		if (sha1 && d->uri) {
			/* Don't set for N2R URLs, the SHA-1 can be derived from it */
			magnet_set_sha1(magnet, sha1);
		}
		tth = download_get_tth(d);
		if (tth) {
			magnet_set_tth(magnet, tth);
		}
		if (fi->file_size_known && fi->size) {
			magnet_set_filesize(magnet, fi->size);
		}
		parq_id = get_parq_dl_id(d);
		if (parq_id) {
			magnet_set_parq_id(magnet, parq_id);
		}
		vendor = download_vendor(d);
		if (vendor) {
			magnet_set_vendor(magnet, vendor);
		}
		if (
			!guid_is_blank(download_guid(d)) &&
			!is_strprefix(dl_url, "push://")
		) {
			char guid_buf[GUID_HEX_SIZE + 1];
			guid_to_string_buf(download_guid(d), guid_buf, sizeof guid_buf);
			magnet_set_guid(magnet, guid_buf);
		}
		magnet_set_dht(magnet,
			booleanize(d->server->attrs & DLS_A_DHT_PUBLISH));
		magnet_set_g2(magnet, booleanize(d->server->attrs & DLS_A_G2_ONLY));
		magnet_add_source_by_url(magnet, dl_url);
		G_FREE_NULL(dl_url);
		url = magnet_to_string(magnet);
		magnet_resource_free(&magnet);
	} else {
		url = NULL;
	}
	return url;
}

static void
download_store_magnet(FILE *f, const struct download *d)
{
	char *url;

	g_return_if_fail(f);
	download_check(d);

	if (d->status == GTA_DL_DONE || d->status == GTA_DL_REMOVED)
		return;
	if (d->flags & (DL_F_TRANSIENT | DL_F_CLONED))
		return;

	url = download_build_magnet(d);
	if (url) {
		fprintf(f, "%s\n\n", url);
		HFREE_NULL(url);
	}
}

static void
download_store_magnets(void)
{
	file_path_t fp;
	FILE *f;

	g_return_if_fail(!retrieving);

	/*
	 * FIXME: it is wrong to store download sources as magnets only.
	 *
	 * Each record should be made of a magnet (standalone with sufficient
	 * information to be dropped to another servent to initiate a download)
	 * plus other meta information described separately.  When that is done,
	 * magnet extensions such as x.parq-id, x.vndr and x.guid can go: they
	 * are not pure as they apply to a single source only, but a general
	 * magnet could contain several source locations.
	 *
	 * Our extension trick works because we know that each magnet we persist
	 * is describing one source only.
	 *
	 *		--RAM, 2010-02-20
	 */

	file_path_set(&fp, settings_config_dir(), download_file);
	f = file_config_open_write(file_what, &fp);
	if (f) {
		hash_list_iter_t *iter;
		
		file_config_preamble(f, "Downloads");
		iter = hash_list_iterator(sl_downloads);

		while (hash_list_iter_has_next(iter)) {
			struct download *d = hash_list_iter_next(iter);

			download_check(d);
			download_store_magnet(f, d);
		}

		hash_list_iter_release(&iter);
		file_config_close(f, &fp);
	}
}

/**
 * Store all pending downloads.
 *
 * The downloads are normally stored in ~/.gtk-gnutella/downloads.
 */
static void
download_store(void)
{
	if (retrieving)
		return;

	if (download_shutdown)
		return;

	download_store_magnets();
}

/**
 * Store pending download if needed.
 *
 * The fileinfo database is also flushed if dirty, but only when the
 * downloads themselves are stored.  Since both are linked via SHA1 and name,
 * it's best to try to keep them in sync.
 */
void
download_store_if_dirty(void)
{
	if (download_shutdown)
		return;

	if (download_dirty) {
		download_store();
		file_info_store_if_dirty();
	}
}

/**
 * Retrieve stored downloads, saved as magnet URIs.
 */
static bool
download_retrieve_magnets(FILE *f)
{
	const size_t buffer_size = 64 * 1024;
	char *buffer = NULL;
	bool expect_old_format = TRUE;

	if (f) {
		bool truncated = FALSE;
		uint line = 0;

		buffer = halloc(buffer_size);
		while (fgets(buffer, buffer_size, f)) {

			if (!file_line_chomp_tail(buffer, buffer_size, NULL)) {
				g_warning("%s, line %u: line too long or unterminated",
					download_file, line);
				truncated = TRUE;
				continue;
			}
			line++; /* Increase line counter */
			if (truncated) {
				truncated = FALSE;
				continue;
			}

			if (file_line_is_skipable(buffer))
				continue;	/* Skip comments and empty lines */

			if (expect_old_format && is_strprefix(buffer, "RECLINES=")) {
				g_message("detected old downloads format");
				break;
			}

			if (is_strcaseprefix(buffer, "magnet:?")) {
				uint created;

				expect_old_format = FALSE;
				created = download_handle_magnet(buffer);

				if (GNET_PROPERTY(download_debug)) {
					g_debug("created %d download%s from %s",
						created, plural(created), buffer);
				}
			} else {
				g_warning("%s, line %u: Ignored unknown item",
					download_file, line);
			}
		}
	}
	HFREE_NULL(buffer);
	return !expect_old_format;
}

static void
download_retrieve_old(FILE *f)
{
	char dl_tmp[4096];
	filesize_t d_size = 0;	/* The d_ vars are what we deserialize */
	uint64 size64;
	int error;
	const char *d_name;
	host_addr_t d_addr;
	uint16 d_port;
	uint32 flags;
	char d_hexguid[33];
	char d_hostname[256];	/* Server hostname */
	int recline;			/* Record line number */
	unsigned line;			/* File line number */
	struct guid d_guid;
	struct sha1 sha1;
	bool has_sha1 = FALSE;
	int maxlines = -1;
	bool allow_comments = TRUE;
	char *parq_id = NULL;
	const char *endptr;
	struct download *d;

	g_return_if_fail(f);

	/*
	 * Retrieval algorithm:
	 *
	 * Lines starting with a # are skipped.
	 *
	 * We read the ines that make up each serialized record, and
	 * recreate the download.  We stop as soon as we encounter an
	 * error.
	 */

	line = recline = 0;
	d_name = NULL;
	flags = 0;

	while (fgets(dl_tmp, sizeof dl_tmp, f)) {
		line++;

		if (!file_line_chomp_tail(dl_tmp, sizeof dl_tmp, NULL)) {
			g_warning("%s(): line %u too long, aborting", G_STRFUNC, line);
			break;
		}

		if (allow_comments && file_line_is_comment(dl_tmp))
			continue;				/* Skip comments */

		/*
		 * We emitted a "RECLINES=x" at store time to indicate the amount of
		 * lines each record takes.  This also signals that we can no longer
		 * accept comments.
		 */

		if (maxlines < 0 && dl_tmp[0] == 'R') {
			if (1 == sscanf(dl_tmp, "RECLINES=%d", &maxlines)) {
				allow_comments = FALSE;
				continue;
			}
		}

		if (file_line_is_empty(dl_tmp)) {
			if (recline == 0)
				continue;			/* Allow arbitrary blank lines */

			g_warning("%s(): unexpected empty line #%u, aborting",
				G_STRFUNC, line);
			goto out;
		}

		recline++;					/* We're in a record */

		switch (recline) {
		case 1:						/* The file name */
			strchomp(dl_tmp, 0);
			/* Un-escape in place */
			if (!url_unescape(dl_tmp, TRUE)) {
				g_warning("%s(): invalid escaping in line #%u, aborting",
					G_STRFUNC, line);
				goto out;
			}
			d_name = atom_str_get(dl_tmp);

			/*
			 * Backward compatibility with 0.85, which did not have the
			 * "RECLINE=x" line.  If we reached the first record line, then
			 * either we saw that line in recent versions, or we did not and
			 * we know we had only 2 lines per record.
			 */

			if (maxlines < 0)
				maxlines = 2;

			continue;
		case 2:						/* Other information */
			g_assert(d_name);
			d_hostname[0] = '\0';

			size64 = parse_uint64(dl_tmp, &endptr, 10, &error);
			if (error || ',' != *endptr) {
				g_warning("%s(): cannot parse line #%u: %s",
					G_STRFUNC, line, dl_tmp);
				goto out;
			}

			d_size = size64;
			if ((uint64) d_size != size64) {
				g_warning("%s(): filesize is too large in line #%u: %s",
					G_STRFUNC, line, dl_tmp);
				goto out;
			}

			/* skip "<filesize>," for sscanf() */
			g_assert(endptr != dl_tmp);
			g_assert(*endptr == ',');
			endptr = skip_ascii_blanks(++endptr);

			parse_uint32(endptr, &endptr, 10, &error);
			if (error || NULL == strchr(":,", *endptr)) {
				g_warning("%s(): cannot parse index in line #%u: %s",
					G_STRFUNC, line, dl_tmp);
				goto out;
			}

			if (',' == *endptr) {
				memset(d_hexguid, '0', 32);		/* GUID missing -> blank */
				d_hexguid[32] = '\0';
			} else {
				g_assert(':' == *endptr);
				endptr++;

				endptr += clamp_strcpy(d_hexguid, sizeof d_hexguid, endptr);
			}

			if (',' != *endptr) {
				g_warning("%s(): expected ',' in line #%u: %s",
					G_STRFUNC, line, dl_tmp);
				goto out;
			}
			endptr = skip_ascii_blanks(++endptr);

			if (!string_to_host_addr_port(endptr, &endptr, &d_addr, &d_port)) {
				g_warning("%s(): bad IP:port at line #%u: %s",
					G_STRFUNC, line, dl_tmp);
				d_port = 0;
				d_addr = ipv4_unspecified;
				/* Will drop download when scheduling it */
				flags |= SOCK_F_PUSH;
			}

			if (',' == *endptr) {
				const char *end = &d_hostname[sizeof d_hostname - 1];
				char c, *s = d_hostname;

				endptr = skip_ascii_blanks(++endptr);
				while (end != s && '\0' != (c = *endptr++)) {
					if (!is_ascii_alnum(c) && '.' != c && '-' != c)
						break;
					*s++ = c;
				}
				*s = '\0';
			}

			if (maxlines == 2)
				break;
			continue;
		case 3:						/* SHA1 hash, or "*" if none */
			if (dl_tmp[0] == '*')
				goto no_sha1;
			if (
				strlen(dl_tmp) != (1+SHA1_BASE32_SIZE) ||	/* Final "\n" */
				SHA1_RAW_SIZE != base32_decode(sha1.data, sizeof sha1.data,
									dl_tmp, SHA1_BASE32_SIZE)
			) {
				g_warning("%s(): bad base32 SHA1 '%32s' at line #%u, ignoring",
					G_STRFUNC, dl_tmp, line);
			} else
				has_sha1 = TRUE;
		no_sha1:
			if (maxlines == 3)
				break;
			continue;
		case 4:						/* PARQ id, or "*" if none */
			if (maxlines != 4) {
				g_warning("%s(): can't handle %d lines in records, aborting",
					G_STRFUNC, maxlines);
				goto out;
			}
			if (dl_tmp[0] != '*') {
				strchomp(dl_tmp, 0);	/* Strip final "\n" */
				parq_id = g_strdup(dl_tmp);
			}
			break;
		default:
			g_warning("%s(): too many lines for record at line #%u, aborting",
				G_STRFUNC, line);
			goto out;
		}

		/*
		 * At the last line of the record.
		 */

		if (!hex_to_guid(d_hexguid, &d_guid)) {
			g_warning("%s(): malformed GUID %s near line #%u",
				G_STRFUNC, d_hexguid, line);
        }

		/*
		 * Download is created with a timestamp of `MAGIC_TIME' so that it is
		 * very old and the entry does not get added to the download mesh yet.
		 * Also, this is used as a signal to NOT update the "ntime" field
		 * in the fileinfo.
		 */

		if (GNET_PROPERTY(download_debug) > 5)
			g_debug("DOWNLOAD '%s' (%s bytes) from %s (%s) SHA1=%s",
				d_name, uint64_to_string(d_size), host_addr_to_string(d_addr),
				d_hostname, has_sha1 ? sha1_base32(&sha1) : "<none>");

		d = create_download(d_name, NULL, d_size, d_addr,
				d_port, &d_guid, d_hostname, has_sha1 ? &sha1 : NULL,
				NULL, 1, NULL, NULL, flags, parq_id);

		if (d == NULL) {
			if (GNET_PROPERTY(download_debug))
				g_debug("ignored dup download at line #%d (server %s)",
					line - maxlines + 1,
					host_addr_port_to_string(d_addr, d_port));
			goto next_entry;
		}

	next_entry:
		atom_str_free_null(&d_name);
		flags = 0;
		recline = 0;				/* Mark the end */
		has_sha1 = FALSE;
		G_FREE_NULL(parq_id);
	}

out:
	atom_str_free_null(&d_name);
}

/**
 * Retrieve download list and requeue each download.
 * The downloads are normally retrieved from ~/.gtk-gnutella/downloads.
 */
static void
download_retrieve(void)
{
	file_path_t fp[1];
	FILE *f;

	file_path_set(fp, settings_config_dir(), download_file);
	f = file_config_open_read(file_what, fp, G_N_ELEMENTS(fp));
	if (f) {
		retrieving = TRUE;			/* Prevent download_store() runs */

		if (!download_retrieve_magnets(f)) {
			clearerr(f);
			if (fseek(f, 0, SEEK_SET)) {
				g_carp("fseek(f, 0, SEEK_SET) failed: %m");
			} else {
				download_retrieve_old(f);
			}
		}

		retrieving = FALSE;			/* Re-enable download_store() runs */
		fclose(f);
		download_store();			/* Persist what we have retrieved */
	}
}

/**
 * Post renaming/moving routine called when download had a bad SHA1.
 */
static void
download_moved_with_bad_sha1(struct download *d)
{
	download_check(d);
	g_assert(d->status == GTA_DL_DONE);
	g_assert(!has_good_sha1(d));

	queue_suspend_downloads_with_file(d->file_info, FALSE);

	/*
	 * If it was a faked download or has a bad bitprint, we cannot resume.
	 */

	if (d->file_info && fi_has_bad_bitprint(d->file_info)) {
		g_warning("SHA1 mismatch for \"%s\" but TTH was good, cannot restart",
			download_basename(d));
		goto pause;
	} else if (is_faked_download(d)) {
		g_warning("SHA1 mismatch for \"%s\", and cannot restart download",
			download_basename(d));
		goto pause;
	} else {
		file_info_reset(d->file_info);
		download_restart(d);
	}

	return;

pause:
	/*
	 * FIXME: If the download is not paused, the file would be downloaded
	 *		  over and over again, even if there is just a single known
	 *		  source. For now there really isn't any better option to
	 *		  pause the download.
	 */

	download_pause(d);
}

/***
 *** Download moving routines.
 ***/

/**
 * Main entry point to move the completed file `d' to target directory `dir'.
 *
 * In case the target directory is the same as the source, the file is
 * simply renamed with the extension `ext' appended to it.
 */
static void
download_move(struct download *d, const char *dir, const char *ext)
{
	fileinfo_t *fi;
	char *dest = NULL;
	bool common_dir;
	const char *name;
	filesize_t free_space;

	download_check(d);
	g_assert(FILE_INFO_COMPLETE(d->file_info));
	g_assert(DOWNLOAD_IS_STOPPED(d));

	download_set_status(d, GTA_DL_MOVING);
	fi = d->file_info;

	/*
	 * Don't keep an URN-like name when the file is done, if possible.
	 */

	name = file_info_readable_filename(fi);

	/*
	 * If the target directory is the same as the source directory, we'll
	 * use the supplied extension and simply rename the file.
	 */
	{
		bool same_dir;
		char *path;

		/* FIXME: This could be done without copying. */
		path = filepath_directory(fi->pathname);
		same_dir = 0 == strcmp(dir, path);
		HFREE_NULL(path);

		if (same_dir) {
			dest = file_info_unique_filename(dir, name, ext);
			if (NULL == dest || !file_object_rename(fi->pathname, dest))
				goto error;
			goto renamed;
		}
	}

	/*
	 * Try to rename() the file, in case both the source and the target
	 * directory are on the same filesystem.  We usually ignore `ext' at
	 * this point since we know the target directory is distinct from the
	 * source, unless the good/bad directories are identical.
	 */

	common_dir = is_same_file(GNET_PROPERTY(move_file_path),
					GNET_PROPERTY(bad_file_path));

	dest = file_info_unique_filename(dir, name, common_dir ? ext : "");
	if (NULL == dest)
		goto error;

	if (file_object_rename(fi->pathname, dest))
		goto renamed;

	/*
	 * The only error we allow is EXDEV, meaning the source and the
	 * target are not on the same file system.
	 */

	if (errno != EXDEV)
		goto error;

	/*
	 * The file has to be moved across file systems.  Try to look whether
	 * we have enough space on the other filesystem before attempting a move.
	 *
	 * This is not bullet proof as there is obviously a huge race condition
	 * possible here, but it can prevent useless copying if we know for sure
	 * there is not enough free space currently.  Also, NFS in linux 2.6.x
	 * has a terrible bug that will slow down the NFS server needlessly if
	 * there is not enough free space to copy the file.  And whilst this
	 * happens, GTKG freezes which is bad.
	 *		--RAM, 2008-06-14
	 */

	free_space = fs_free_space(dir);
	if (download_filesize(d) > free_space) {
		g_message("not enough free space in %s (need %s, has %s): "
			"renaming \"%s\" locally with %s",
			dir,
			filesize_to_string(download_filesize(d)),
			filesize_to_string2(free_space),
			fi->pathname, ext);
		download_move_error(d);
		goto cleanup;
	}

	/*
	 * Have to move the file asynchronously.
	 */

	download_set_status(d, GTA_DL_MOVE_WAIT);
	move_queue(d, dir, common_dir ? ext : "");
	fi->flags |= FI_F_MOVING;

	goto cleanup;

error:
	g_warning("could not rename \"%s\" as \"%s\": %m", fi->pathname, dest);
	download_move_error(d);
	goto cleanup;

renamed:

	file_info_strip_binary_from_file(fi, dest);
	download_move_done(d, dest, 0);
	goto cleanup;

cleanup:

	HFREE_NULL(dest);
	return;
}

/**
 * Called when the moving daemon task starts processing a download.
 */
void
download_move_start(struct download *d)
{
	download_check(d);
	g_assert(d->status == GTA_DL_MOVE_WAIT);

	d->file_info->copied = 0;
	download_set_status(d, GTA_DL_MOVING);
}

/**
 * Called to register the current moving progress.
 */
void
download_move_progress(struct download *d, filesize_t copied)
{
	download_check(d);
	g_assert(d->status == GTA_DL_MOVING);

	d->file_info->copied = copied;
	file_info_changed(d->file_info);
}

/**
 * Called when file has been moved/renamed with its fileinfo trailer stripped.
 */
void
download_move_done(struct download *d, const char *pathname, uint elapsed)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->status == GTA_DL_MOVING);

	fi = d->file_info;
	fi->copy_elapsed = elapsed;
	fi->copied = fi->size;
	fi->flags &= ~FI_F_MOVING;

	d->last_update = tm_time();
	download_set_status(d, GTA_DL_DONE);

	/*
	 * File was unlinked by rename() if we were on the same filesystem,
	 * or by the moving daemon task upon success.
	 */

	if (has_good_sha1(d)) {
		file_info_moved(fi, pathname);

		if (
			fi->sha1 && GNET_PROPERTY(pfsp_server) &&
			!(FI_F_TRANSIENT & fi->flags)
			/* No size consideration here as the file is complete */
		) {
			fi->flags |= FI_F_SEEDING;
		}

		/* Send a notification */
		dbus_util_send_message(DBS_EVT_DOWNLOAD_DONE, download_pathname(d));
	} else {
		download_moved_with_bad_sha1(d);
	}
	file_info_changed(fi);
	fi_src_status_changed(d);	
}

/**
 * Called when we cannot move the file (I/O error, etc...).
 */
void
download_move_error(struct download *d)
{
	fileinfo_t *fi;
	const char *ext, *name;
	char *dest, *path;

	download_check(d);
	g_assert(d->status == GTA_DL_MOVING);

	/*
	 * If download is "good", rename it inplace as DL_OK_EXT, otherwise
	 * rename it as DL_BAD_EXT.
	 *
	 * Don't keep an URN-like name when the file is done, if possible.
	 */

	fi = d->file_info;
	fi->flags &= ~FI_F_MOVING;
	name = file_info_readable_filename(fi);

	ext = has_good_sha1(d) ? DL_OK_EXT : DL_BAD_EXT;
	path = filepath_directory(fi->pathname);
	dest = file_info_unique_filename(path, name, ext);
	HFREE_NULL(path);

	file_info_strip_binary(fi);

	if (NULL == dest || !file_object_rename(fi->pathname, dest)) {
		g_warning("could not rename completed file \"%s\" as \"%s\": %m",
			fi->pathname, dest);
		download_set_status(d, GTA_DL_DONE);
	} else {
		g_message("completed \"%s\" left at \"%s\"", name, dest);
		download_move_done(d, dest, 0);
	}
	HFREE_NULL(dest);
}

/***
 *** SHA1 verification routines.
 ***/

/**
 * Called when the verification daemon task starts processing a download.
 */
static void
download_verify_sha1_start(struct download *d)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFY_WAIT);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	download_set_status(d, GTA_DL_VERIFYING);
	gnet_stats_inc_general(GRN_SHA1_VERIFICATIONS);
}

/**
 * Called to register the current verification progress.
 */
static void
download_verify_sha1_progress(struct download *d, uint32 hashed)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	d->file_info->vrfy_hashed = hashed;
	file_info_changed(d->file_info);
}

static void
download_verifying_done(struct download *d)
{
	download_check(d);

	if (has_good_sha1(d)) {
		fileinfo_t *fi;

		fi = d->file_info;
		file_info_check(fi);

		if (fi->sha1 != NULL)
			search_dissociate_sha1(fi->sha1);

		download_remove_all_thex(download_get_sha1(d), NULL);
		ignore_add_filesize(file_info_readable_filename(fi),
			download_filesize(d));
		queue_remove_downloads_with_file(fi, d);
		download_move(d, GNET_PROPERTY(move_file_path), DL_OK_EXT);
	} else {
		download_move(d, GNET_PROPERTY(bad_file_path), DL_BAD_EXT);
		/* Will go to download_moved_with_bad_sha1() upon completion */
	}
}

/**
 * Called when download verification is finished and digest is known.
 */
static void
download_verify_sha1_done(struct download *d,
	const struct sha1 *sha1, uint elapsed)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	fi = d->file_info;
	file_info_check(fi);
	fi->cha1 = atom_sha1_get(sha1);
	fi->vrfy_elapsed = elapsed;
	fi->vrfy_hashed = fi->size;
	file_info_store_binary(fi, TRUE);		/* Resync with computed SHA1 */
	file_info_changed(fi);

	download_set_status(d, GTA_DL_VERIFIED);
	fi->flags &= ~FI_F_VERIFYING;

	ignore_add_sha1(file_info_readable_filename(fi), fi->cha1);

	if (fi->tth && (!has_good_sha1(d) || GNET_PROPERTY(tigertree_debug) > 1)) {
		download_verify_tigertree(d);
	} else {
		download_verifying_done(d);
	}
}

/**
 * When a SHA1 or TTH system error occurs during verification, we can't
 * determine whether the SHA1 or TTH is good or bad.
 */
static void
download_verify_status_unknown(struct download *d, const char *what)
{
	fileinfo_t *fi;
	const char *name;

	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);

	fi = d->file_info;
	file_info_check(fi);
	name = file_info_readable_filename(fi);

	if (0 == strcmp(filepath_basename(fi->pathname), name))
		g_warning("error while verifying %s for \"%s\"", what, fi->pathname);
	else {
		g_warning("error while verifying %s for \"%s\" (aka \"%s\")",
			what, fi->pathname, name);
    }

	download_set_status(d, GTA_DL_VERIFIED);
	fi->vrfy_hashed = fi->size;
	fi->tth_check = FALSE;
	fi->flags &= ~FI_F_VERIFYING;
	file_info_changed(fi);

	ignore_add_filesize(name, fi->size);
	queue_remove_downloads_with_file(fi, d);
	download_move(d, GNET_PROPERTY(move_file_path), DL_UNKN_EXT);
}

/**
 * Called when we cannot verify the SHA1 for the file (I/O error, etc...).
 */
static void
download_verify_sha1_error(struct download *d)
{
	download_verify_status_unknown(d, "SHA1");
}

static bool
download_verify_sha1_callback(const struct verify *ctx,
	enum verify_status status, void *user_data)
{
	struct download *d = user_data;

	download_check(d);
	g_assert(!FILE_INFO_FINISHED(d->file_info));

	switch (status) {
	case VERIFY_START:
		gnet_prop_set_boolean_val(PROP_SHA1_VERIFYING, TRUE);
		download_verify_sha1_start(d);
		return TRUE;
	case VERIFY_PROGRESS:
		download_verify_sha1_progress(d, verify_hashed(ctx));
		return TRUE;
	case VERIFY_DONE:
		gnet_prop_set_boolean_val(PROP_SHA1_VERIFYING, FALSE);
		download_verify_sha1_done(d,
			verify_sha1_digest(ctx), verify_elapsed(ctx));
		return TRUE;
	case VERIFY_ERROR:
		gnet_prop_set_boolean_val(PROP_SHA1_VERIFYING, FALSE);
		download_verify_sha1_error(d);
		return TRUE;
	case VERIFY_SHUTDOWN:
		return TRUE;
	case VERIFY_INVALID:
		break;
	}
	g_assert_not_reached();
	return FALSE;
}

/**
 * Main entry point for verifying the SHA1 of a completed download.
 */
static void
download_verify_sha1(struct download *d)
{
	bool inserted;
	fileinfo_t *fi;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(FILE_INFO_COMPLETE(fi));
	g_assert(DOWNLOAD_IS_STOPPED(d));
	g_assert(!DOWNLOAD_IS_VERIFYING(d));
	g_assert(!(d->flags & DL_F_SUSPENDED));
	g_assert(d->list_idx == DL_LIST_STOPPED);

	if (FI_F_VERIFYING & fi->flags)	/* Already verifying */
		return;

	/*
	 * We completed the file, accound as one more completed download.
	 */

	gnet_prop_incr_guint32(PROP_TOTAL_DOWNLOADS);

	if (DL_F_TRANSIENT & d->flags)	/* Nothing to verify */
		return;

	g_assert(!FILE_INFO_FINISHED(fi));

	if (GNET_PROPERTY(verify_debug) > 1) {
		g_debug("%s verifying SHA-1 of completed %s",
			(FI_F_VERIFYING & fi->flags) ?
				"already planned" : "will be",
			download_pathname(d));
	}

	/*
	 * Even if download was aborted or in error, we have a complete file
	 * anyway, so start verifying its SHA1.
	 */

	download_set_status(d, GTA_DL_VERIFY_WAIT);
	queue_suspend_downloads_with_file(fi, TRUE);
	d->flags &= ~DL_F_CLONED;		/* Has to be persisted until SHA-1 is OK */

	inserted = verify_sha1_enqueue(TRUE, download_pathname(d),
					download_filesize(d), download_verify_sha1_callback, d);

	g_assert(inserted); /* There cannot be duplicates */

	fi->flags |= FI_F_VERIFYING;
	fi->vrfy_hashed = 0;
	fi->tth_check = FALSE;
}

/***
 *** Tigertree verification routines.
 ***/

/**
 * Called when the verification daemon task starts processing a download.
 */
static void
download_verify_tigertree_start(struct download *d)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFY_WAIT);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	download_set_status(d, GTA_DL_VERIFYING);
	gnet_stats_inc_general(GRN_TTH_VERIFICATIONS);
}

/**
 * Called to register the current verification progress.
 */
static void
download_verify_tigertree_progress(struct download *d, uint32 hashed)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	d->file_info->vrfy_hashed = hashed;
	file_info_changed(d->file_info);
}

static void
download_tigertree_sweep(struct download *d,
	const struct tth *leaves, size_t num_leaves)
{
	filesize_t offset;
	struct tth *nodes;
	fileinfo_t *fi;
	size_t i, bad_slices;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);

	g_assert(leaves);
	g_return_if_fail(num_leaves > 0);
	g_return_if_fail(num_leaves >= fi->tigertree.num_leaves);
	g_return_if_fail(fi->tigertree.num_leaves > 0);
	g_return_if_fail(fi->tigertree.leaves);

	g_assert(fi->file_size_known);

	if (GNET_PROPERTY(tigertree_debug)) {
		g_debug("TTH tree sweep: file=\"%s\", filesize=%s, slice size=%s",
			download_basename(d),
			filesize_to_string(download_filesize(d)),
			uint64_to_string(fi->tigertree.slice_size));
	}

	if (num_leaves > fi->tigertree.num_leaves) {
		size_t dst;

		HALLOC0_ARRAY(nodes, num_leaves);
		dst = num_leaves;

		do {
			dst -= (num_leaves + 1) / 2;
			num_leaves = tt_compute_parents(&nodes[dst], leaves, num_leaves);
			leaves = &nodes[dst];
		} while (num_leaves > fi->tigertree.num_leaves);
	} else {
		nodes = NULL;
	}
	g_assert(num_leaves == fi->tigertree.num_leaves);

	bad_slices = 0;
	offset = 0;
	for (i = 0; i < num_leaves; i++) {
		filesize_t next, amount;

		/* The last slice is smaller than the slice size, if
		 * if the filesize isn't a multiple of the slice size.
		 */
		g_assert(download_filesize(d) > offset);
		amount = download_filesize(d) - offset;
		amount = MIN(amount, fi->tigertree.slice_size);
		next = offset + amount;

		if (!tth_eq(&leaves[i], &fi->tigertree.leaves[i])) {
			g_warning("TTH tree sweep: "
				"bad slice #%zu (%s-%s) in \"%s\" (%s bytes)",
				i, filesize_to_string(offset),
				uint64_to_string(next - 1),
				download_basename(d),
				filesize_to_string2(download_filesize(d)));

			bad_slices++;
			file_info_update(d, offset, next, DL_CHUNK_EMPTY);
		}
		offset = next;
	}
	if (bad_slices > 0) {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_warning("TTH tree sweep: %zu/%zu bad slice%s",
				bad_slices, num_leaves, plural(bad_slices));
		}
	} else {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("TTH tree sweep: all %zu slice%s okay",
				num_leaves, plural(num_leaves));
		}
	}
	HFREE_NULL(nodes);
}

/**
 * Called when download verification is finished and digest is known.
 */
static void
download_verify_tigertree_done(struct download *d,
	const struct tth *tth, uint elapsed,
	const struct tth *leaves, size_t num_leaves)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	fi = d->file_info;
	file_info_check(fi);
	fi->flags &= ~FI_F_VERIFYING;
	fi->vrfy_elapsed = elapsed;
	fi->vrfy_hashed = fi->size;

	if (tth_eq(tth, fi->tth)) {
		g_message("TTH matches (file=\"%s\")", download_basename(d));

		download_set_status(d, GTA_DL_VERIFIED);

		if (
			GNET_PROPERTY(tigertree_debug) > 1 &&
			fi->tigertree.num_leaves > 0
		) {
			/* NOTE: For testing only */
			download_tigertree_sweep(d, leaves, num_leaves); 
		}

		if (!has_good_sha1(d)) {
			/*
			 * FIXME:
			 * This is far from perfect: if we come here, the SHA1 checking
			 * was a mismatch, yet the TTH was good. We ought to flag this
			 * bitprint (combination of SHA1 and TTH) as invalid before retrying.
			 * But currently, what we do is move the download to the "bad" dir
			 * and we leave it there, stopping the download.
			 *		--RAM, 2007-08-25
			 */
			fi_mark_bad_bitprint(fi);
		}
		download_verifying_done(d);
	} else {
		download_set_status(d, GTA_DL_COMPLETED);

		if (fi->tigertree.num_leaves > 0) {
			g_message("TTH mismatch (file=\"%s\")", download_basename(d));
			/* Reset result of the SHA-1 calculation */
			atom_sha1_free_null(&fi->cha1);
			fi->vrfy_elapsed = 0;
			fi->vrfy_hashed = 0;

			download_tigertree_sweep(d, leaves, num_leaves);
			queue_suspend_downloads_with_file(fi, FALSE);
			download_restart(d);
		} else {
			g_message("TTH unavailable (file=\"%s\")", download_basename(d));
			download_verifying_done(d);
		}
	}
}

/**
 * Called when we cannot verify the TTH for the file (I/O error, etc...).
 */
static void
download_verify_tigertree_error(struct download *d)
{
	download_verify_status_unknown(d, "TTH");
}

static bool
download_verify_tigertree_callback(const struct verify *ctx,
	enum verify_status status, void *user_data)
{
	struct download *d = user_data;

	download_check(d);
	switch (status) {
	case VERIFY_START:
		gnet_prop_set_boolean_val(PROP_TTH_VERIFYING, TRUE);
		download_verify_tigertree_start(d);
		return TRUE;
	case VERIFY_PROGRESS:
		download_verify_tigertree_progress(d, verify_hashed(ctx));
		return TRUE;
	case VERIFY_DONE:
		gnet_prop_set_boolean_val(PROP_TTH_VERIFYING, FALSE);
		download_verify_tigertree_done(d,
			verify_tth_digest(ctx), verify_elapsed(ctx),
			verify_tth_leaves(ctx), verify_tth_leave_count(ctx));
		return TRUE;
	case VERIFY_ERROR:
		gnet_prop_set_boolean_val(PROP_TTH_VERIFYING, FALSE);
		download_verify_tigertree_error(d);
		return TRUE;
	case VERIFY_SHUTDOWN:
		return TRUE;
	case VERIFY_INVALID:
		break;
	}
	g_assert_not_reached();
	return FALSE;
}

/**
 * Initiate Tiger tree hash (TTH) verification of completed download.
 *
 * If verification is successful, the download will be considered OK provided
 * its SHA-1 verfication was also successful; otherwise we have a bad bitprint.
 *
 * If verification is unsuccessful, the Tiger tree is used to prune the parts
 * of the downloaded file which do not verify, and downloading will resume
 * to fetch the pruned parts again, hopefully correctly this time.
 */
static void
download_verify_tigertree(struct download *d)
{
	fileinfo_t *fi;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
	g_assert(FILE_INFO_COMPLETE(fi));
	g_assert(DOWNLOAD_IS_STOPPED(d));
	g_assert(d->list_idx == DL_LIST_STOPPED);
	g_return_if_fail(!(d->flags & DL_F_TRANSIENT));
	g_assert(!(fi->flags & FI_F_VERIFYING));

	if (GNET_PROPERTY(verify_debug) > 1) {
		g_debug("will be verifying TTH of completed %s",
			download_pathname(d));
	}

	/*
	 * Even if download was aborted or in error, we have a complete file
	 * anyway, so start verifying its TTH.
	 */

	download_set_status(d, GTA_DL_VERIFY_WAIT);
	queue_suspend_downloads_with_file(fi, TRUE);

	verify_tth_prepend(download_pathname(d), 0, download_filesize(d),
		download_verify_tigertree_callback, d);

	fi->flags |= FI_F_VERIFYING;
	fi->vrfy_hashed = 0;
	fi->tth_check = TRUE;
}

/**
 * Go through the downloads and check the completed ones that should
 * be either moved to the "done" directory, or which should have their
 * SHA1 computed/verified.
 */
static void
download_resume_bg_tasks(void)
{
	struct download *next;
	pslist_t *sl, *to_remove = NULL;

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;
		fileinfo_t *fi;

		download_check(d);
		next = hash_list_next(sl_downloads, next);

		download_check(d);

		if (d->status == GTA_DL_REMOVED)	/* Pending free, ignore it! */
			continue;

		fi = d->file_info;
		file_info_check(fi);

		if (fi->flags & FI_F_MARK)		/* Already processed */
			continue;

		fi->flags |= FI_F_MARK;

		if (!FILE_INFO_COMPLETE(fi))	/* Not complete */
			continue;

		/*
		 * Found a complete download.
		 *
		 * More than one download may reference this fileinfo if we crashed
		 * and many such downloads were in the queue at that time.
		 */

		g_assert(fi->refcount >= 1);

		/*
		 * It is possible that the faked download was scheduled to run, and
		 * the fact that it was complete was trapped, and the computing of
		 * its SHA1 started.
		 *
		 * In that case, the fileinfo of the file is marked as "suspended".
		 *
		 * It can also happen that the download has been scheduled for moving
		 * already, when the SHA1-computing step was already performed, i.e.
		 * we had a fi->cha1 in the record...
		 */

		if (fi->flags & (FI_F_VERIFYING | FI_F_PAUSED | FI_F_SEEDING)) {
			/* Already computing SHA1, moving or paused by user */
			continue;
		}

		if (DOWNLOAD_IS_QUEUED(d))
			download_unqueue(d, FALSE);

		if (!DOWNLOAD_IS_STOPPED(d))
			download_stop(d, GTA_DL_COMPLETED, no_reason);

		/*
		 * If we don't have the computed SHA1 yet, queue it for SHA1
		 * computation, and we'll proceed from there.
		 *
		 * If the file is still in the "tmp" directory, schedule its
		 * moving to the done/bad directory.
		 */

		if (fi->cha1 == NULL)
			download_verify_sha1(d);
		else {
			/*
			 * Bypassed SHA1 checking, so we must suspend explicitly here.
			 * Normally, this is done when we enter download_verify_sha1(),
			 * which happens before download_move() is called.
			 */

			/* GTA_DL_VERIFIED does NOT mean good SHA1 */
			download_set_status(d, GTA_DL_VERIFIED);
			queue_suspend_downloads_with_file(fi, TRUE);

			if (has_good_sha1(d))
				download_move(d, GNET_PROPERTY(move_file_path), DL_OK_EXT);
			else if (fi->tth != NULL)
				download_verify_tigertree(d);
			else 
				download_move(d, GNET_PROPERTY(bad_file_path), DL_BAD_EXT);
			
			if (!(fi->flags & FI_F_SEEDING))
				to_remove = pslist_prepend(to_remove, d->file_info);
		}
	}

	/*
	 * Remove queued downloads referencing a complete file.
	 */

	PSLIST_FOREACH(to_remove, sl) {
		fileinfo_t *fi = sl->data;
	
		file_info_check(fi);

		/*
		 * Recheck whether the file is complete as some of the
		 * above may cause the file to become incomplete again.
		 */
		if (FILE_INFO_COMPLETE(fi)) {
			queue_remove_downloads_with_file(fi, NULL);
		}
	}

	pslist_free_null(&to_remove);

	/*
	 * Clear the marks.
	 */

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;
		fileinfo_t *fi;

		download_check(d);
		next = hash_list_next(sl_downloads, next);

		if (d->status == GTA_DL_REMOVED)	/* Pending free, ignore it! */
			continue;

		fi = d->file_info;
		file_info_check(fi);

		fi->flags &= ~FI_F_MARK;
	}
}

static void
download_remove_all(void)
{
	struct download *next;

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;

		download_check(d);
		next = hash_list_next(sl_downloads, next);

		if (d->status == GTA_DL_REMOVED)
			continue;

		download_remove(d);
	}
}

/**
 * Terminating processing, cleanup data structures.
 */
G_GNUC_COLD void
download_close(void)
{
	gcu_download_gui_updates_freeze();

	download_store();			/* Save latest copy */
	download_freeze_queue();
	file_info_store();			/* Must do BEFORE we remove downloads */

	/*
	 * This flag is set because certain operations must be avoided from now on
	 * like storing the downloads or removing files. While we abort all
	 * downloads, nothing what we do from here on is meant to persist.
	 */
	download_shutdown = TRUE;

	download_clear_stopped(TRUE, TRUE, TRUE, TRUE, TRUE);
	download_remove_all();
	download_free_removed();

	hash_list_free(&sl_downloads);
	hash_list_free(&sl_unqueued);

	htable_free_null(&dl_by_guid);
	hikset_free_null(&dl_by_host);
	htable_free_null(&dl_by_addr);
	hikset_free_null(&dl_by_id);
	htable_free_null(&dhl_by_sha1);
	dualhash_destroy_null(&dl_thex);
}

static char *
download_url_for_uri(const struct download *d, const char *uri)
{
	const char *prefix;
	char prefix_buf[256];
	char *result;
	const char *host;
	char *hostp = NULL;
	host_addr_t addr;
	uint16 port;

	g_return_val_if_fail(d, NULL);
	g_return_val_if_fail(uri, NULL);
	download_check(d);
	g_assert(dl_server_valid(d->server));

	addr = download_addr(d);
	port = download_port(d);

	if (
		d->always_push ||
		(!host_is_valid(addr, port) && !guid_is_blank(download_guid(d)))
	) {
		char guid_buf[GUID_HEX_SIZE + 1];
		sequence_t *seq;

		seq = d->server->proxies != NULL ?
			pproxy_set_sequence(d->server->proxies) : NULL;
		host = hostp = magnet_proxies_to_string(seq);
		sequence_release(&seq);
		guid_to_string_buf(download_guid(d), guid_buf, sizeof guid_buf);
		concat_strings(prefix_buf, sizeof prefix_buf,
			"push://", guid_buf, (void *) 0);
		prefix = prefix_buf;
	} else if (0 != port && is_host_addr(addr)) {
		host = host_port_to_string(download_hostname(d), addr, port);
		prefix = "http://";		/* FIXME: "https:" when TLS is possible? */
	} else {
		return NULL;
	}

	if ('/' == uri[0])
		uri++;

	result = g_strconcat(prefix, host, "/", uri, (void *) 0);

	HFREE_NULL(hostp);

	return result;
}

/**
 * Creates a URL path which points to a download (e.g. you can copy and paste
 * this to a browser and download the file, provided it's a pure http:// URL
 * and not a push:// one).
 *
 * @return NULL on failure, or a newly allocated string holding the URL
 */
char *
download_build_url(const struct download *d)
{
	char *url;

	g_return_val_if_fail(d, NULL);
	download_check(d);

	if (d->browse) {
		url = download_url_for_uri(d, "/");
	} else if (d->uri) {
		url = download_url_for_uri(d, d->uri);
	} else if (download_get_sha1(d)) {
		char uri[128];

		concat_strings(uri, sizeof uri,
			"/uri-res/N2R?",
			bitprint_to_urn_string(download_get_sha1(d), download_get_tth(d)),
			(void *) 0);
		url = download_url_for_uri(d, uri);
	} else {
		char *escaped, *uri;
	   
		escaped = url_escape(d->file_name);
		uri = h_strdup_printf("/get/%u/%s", d->record_index, escaped);
		url = download_url_for_uri(d, uri);
		HFREE_NULL(uri);
		if (escaped != d->file_name) {
			HFREE_NULL(escaped);
		}
	}
	return url;
}

const char *
download_get_hostname(const struct download *d)
{
	static char buf[MAX_HOSTLEN + 1024];
	bool encrypted, inbound, outbound;
	host_addr_t addr;
	uint port;

	download_check(d);
	if (is_faked_download(d))
		return "";

	if (d->socket) {
		addr = d->socket->addr;
		port = d->socket->port;
		inbound = SOCK_CONN_INCOMING == d->socket->direction;
		outbound = SOCK_CONN_OUTGOING == d->socket->direction;
		encrypted = inbound
				? socket_uses_tls(d->socket)
				: socket_with_tls(d->socket);
	} else {
		addr = download_addr(d);
		port = download_port(d);
		encrypted = FALSE;
		inbound = FALSE;
		outbound = FALSE;
	}

	concat_strings(buf, sizeof buf,
		host_addr_port_to_string(addr, port),
		inbound ? _(", inbound") : "",
		outbound ? _(", outbound") : "",
		encrypted ? ", TLS" : "",
		(d->server->attrs & DLS_A_NO_PIPELINE) ? _(", no-pipeline") : "",
		(d->server->attrs & DLS_A_BANNING) ? _(", banning") : "",
		(d->server->attrs & (DLS_A_G2_ONLY | DLS_A_FAKE_G2)) == DLS_A_G2_ONLY ?
			_(", g2") : "",
		(d->server->attrs & DLS_A_FAKE_G2) ? _(", fake-g2") : "",
		(d->server->attrs & DLS_A_FAKED_VENDOR) ? _(", vendor?") : "",
		d->server->hostname ? ", (" : "",
		d->server->hostname ? d->server->hostname : "",
		d->server->hostname ? ")" : "",
		(void *) 0);
	
	return buf;
}

int
download_get_http_req_percent(const struct download *d)
{
	const http_buffer_t *r;

	download_check(d);
	r = d->req;
	return (http_buffer_read_base(r) - http_buffer_base(r))
				* 100 / http_buffer_length(r);
}

/**
 * Checks unqueued list to see if there are any downloads that are finished and
 * therefore ready to be cleared.
 */
bool
download_something_to_clear(void)
{
	hash_list_iter_t *iter;
	bool found = FALSE;

	iter = hash_list_iterator(sl_unqueued);

	while (hash_list_iter_has_next(iter)) {
		struct download *d = hash_list_iter_next(iter);

		download_check(d);

		switch (d->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
		case GTA_DL_DONE:
			found = TRUE;
			goto done;
		default:
			break;
		}
	}

done:
	hash_list_iter_release(&iter);
	return found;
}

/***
 *** Browse Host (client-side).
 ***/

/**
 * Create special non-persisted download that will request "/" on the
 * remote host and expect a stream of Gnutella query hits back.  Those
 * query hits will be feed back to the search given as parameter for
 * display.
 *
 * @param hostname	the DNS name of the host, or NULL if none known
 * @param addr		the IP address of the host to browse
 * @param port		the port to contact
 * @param guid		the GUID of the remote host
 * @param push		whether a PUSH request is neeed to reach remote host
 * @param proxies	vector holding known push-proxies
 * @param search	the search we have to send back query hits to.
 *
 * @return created download, or NULL on error.
 */
struct download *
download_browse_start(const char *hostname,
	host_addr_t addr, uint16 port, const struct guid *guid,
	const gnet_host_vec_t *proxies, gnet_search_t search, uint32 flags)
{
	struct download *d;
	fileinfo_t *fi;

	g_return_val_if_fail(host_addr_initialized(addr), NULL);

	{
		char *dname;

		if (SOCK_F_G2 & flags) {
			dname = str_cmsg(_("<Browse G2 Host %s>"),
				host_port_to_string(hostname, addr, port));
		} else {
			dname = str_cmsg(_("<Browse Host %s>"),
				host_port_to_string(hostname, addr, port));
		}

		fi = file_info_get_transient(dname);
		HFREE_NULL(dname);
	}

	d = create_download(filepath_basename(fi->pathname), "/",
			0,	/* filesize */
			addr, port, guid, hostname,
			NULL, /* SHA-1 */
			NULL, /* TTH */
			tm_time(),
			fi,
			proxies,
			flags,
			NULL);	/* PARQ ID */

	if (d) {
		gnet_host_t host;

		download_check(d);

		d->flags |= DL_F_TRANSIENT | DL_F_BROWSE;
		gnet_host_set(&host, addr, port);
		d->browse = browse_host_dl_create(d, &host, search);
		file_info_changed(fi);		/* Update status! */
	} else {
		file_info_remove(fi);
	}
	return d;
}

static void
download_thex_done(struct download *d)
{
	const struct sha1 *sha1;
	const struct tth *tth, *leaves;
	size_t num_leaves;
	fileinfo_t *fi;
	bool cancel_all = FALSE;

	download_check(d);
	g_return_if_fail(d->thex);
	g_return_if_fail(DL_F_THEX & d->flags);

	sha1 = thex_download_get_sha1(d->thex);
	g_return_if_fail(sha1);

	if (!thex_download_finished(d->thex)) {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("TTH discarding tigertree data from %s: Bad THEX data",
				download_host_info(d));
		}
		goto finish;
	}

	fi = file_info_by_sha1(sha1);
	if (NULL == fi) {
		if (GNET_PROPERTY(tigertree_debug)) {
			g_debug("TTH discarding tigertree data from %s: No more download",
				download_host_info(d));	
		}
		cancel_all = TRUE;
		goto finish;
	}

	tth = thex_download_get_tth(d->thex);
	num_leaves = thex_download_get_leaves(d->thex, &leaves);
	g_return_if_fail(tth);
	g_return_if_fail(leaves);
	g_return_if_fail(num_leaves > 0);

	if (NULL == fi->tth) {
		file_info_got_tth(fi, tth);
	}
	if (fi->tigertree.num_leaves >= num_leaves) {
		g_message("discarding tigertree data from %s: already known.",
			download_host_info(d));
		cancel_all = TRUE;
		goto finish;
	}
	file_info_got_tigertree(fi, leaves, num_leaves, TRUE);
	cancel_all = TRUE;

finish:
	if (cancel_all) {
		download_remove_all_thex(sha1, d);
	}
}
	
/**
 * Create special non-persisted download that will request THEX data from the
 * remote host.
 *
 * @param uri		the URI to request
 * @param hostname	the DNS name of the host, or NULL if none known
 * @param addr		the IP address of the host
 * @param port		the port to contact
 * @param guid		the GUID of the remote host
 * @param push		whether a PUSH request is neeed to reach remote host
 * @param proxies	vector holding known push-proxies
 *
 * @return created download, or NULL on error.
 */
struct download *
download_thex_start(const char *uri,
	const struct sha1 *sha1,
	const struct tth *tth,
	filesize_t filesize,
	const char *hostname,
	host_addr_t addr,
	uint16 port,
	const struct guid *guid,
	const gnet_host_vec_t *proxies,
	uint32 flags)
{
	struct download *d;
	fileinfo_t *fi;

	g_return_val_if_fail(host_addr_initialized(addr), NULL);
	g_return_val_if_fail(uri, NULL);
	g_return_val_if_fail(sha1, NULL);
	g_return_val_if_fail(tth, NULL);

	{
		char *dname;

		fi = file_info_by_sha1(sha1);
		
		dname = str_cmsg(_("<THEX data for %s>"),
					fi ? filepath_basename(fi->pathname)
					   : bitprint_to_urn_string(sha1, tth));

		fi = file_info_get_transient(dname);
		HFREE_NULL(dname);
	}

	d = create_download(filepath_basename(fi->pathname),
			uri,
			0,			/* filesize */
			addr,
			port,
			guid,
			hostname,
			NULL,		/* SHA-1 */
			NULL,		/* TTH */
			tm_time(),
			fi,
			proxies,
			flags,
			NULL);		/* PARQ ID */

	if (d) {
		gnet_host_t host;

		download_check(d);

		d->flags |= DL_F_TRANSIENT | DL_F_THEX;
		gnet_host_set(&host, addr, port);
		d->thex = thex_download_create(d, &host, sha1, tth, filesize);
		file_info_changed(fi);		/* Update status! */
	} else {
		file_info_remove(fi);
	}
	return d;
}

/**
 * Abort browse-host download when corresponding search is closed.
 */
void
download_abort_browse_host(struct download *d, gnet_search_t sh)
{
	download_check(d);
	g_assert(d->flags & DL_F_BROWSE);
	g_assert(browse_host_dl_for_search(d->browse, sh));

	browse_host_dl_search_closed(d->browse, sh);

	if (DOWNLOAD_IS_QUEUED(d))
		download_unqueue(d, FALSE);

	if (!DOWNLOAD_IS_STOPPED(d))
		download_stop(d, GTA_DL_ERROR, _("Browse search closed"));

	file_info_changed(d->file_info);		/* Update status! */
}

/**
 * Called when an EOF is received during data reception.
 */
void
download_got_eof(struct download *d)
{
	fileinfo_t *fi;

	download_check(d);

	fi = d->file_info;
	file_info_check(fi);

	/*
	 * If we don't know the file size, then consider EOF as an indication
	 * we got everything.  Flush buffers in that case because we're probably
	 * not swarming a file whose size is unknown...
	 */

	if (!fi->file_size_known) {
		if (d->buffers)
			download_silent_flush(d);
	}

	if (!fi->file_size_known || FILE_INFO_COMPLETE(fi)) {
		/*
		 * Any pending buffered data not flushed above (if the size is not
		 * known) should be discarded, because if the file is complete and
		 * we have pending buffered data, it means someone else completed
		 * the file and our data is now irrelevant.
		 */

		if (d->buffers && d->buffers->held > 0) {
			buffers_discard(d);
		}
		download_rx_done(d);
	} else {
		/*
		 * Buffers will be flushed by download_stop_v().
		 */

		download_queue_delay(d, GNET_PROPERTY(download_retry_busy_delay),
			_("Stopped data (EOF) <download_got_eof>"));
	}
}

/**
 * Called when all data has been received.
 */
void
download_rx_done(struct download *d)
{
	fileinfo_t *fi;
	bool was_receiving;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);

	/*
	 * We could have been receiving data, in which case we'll need to start
	 * checking the SHA1 of the file, or simply ignoring data, in which case
	 * we were actively transferring data that went to the bit bucket, and
	 * the file was already completed by another (receiving) source.
	 */

	was_receiving = GTA_DL_RECEIVING == d->status;

   	if (!fi->file_size_known) {
		file_info_size_known(d, fi->done);
		d->chunk.size = fi->size;
		d->chunk.end = download_filesize(d);	/* New upper boundary */
		fi_src_info_changed(d);
	}
	g_assert(FILE_INFO_COMPLETE(fi));

	if (d->thex) {
		download_thex_done(d);
		was_receiving = FALSE;		/* No need for SHA1 check */
	}
	download_continue(d, FALSE);

	/*
	 * Don't call download_verify_sha1() if we were not receiving: we were
	 * ignoring data and probably "suspended", i.e. with the DL_F_SUSPENDED
	 * activated to prevent scheduling of new requests.
	 */

	if (was_receiving) {
		download_verify_sha1(d);
	}
}

/**
 * Called when more data has been received on the RX stack, for non-file
 * downloads (e.g. when issuing a browse host request), so that we update
 * the download structure for accurate GUI feedback.
 */
void
download_data_received(struct download *d, ssize_t received)
{
	fileinfo_t *fi;
	filesize_t upper;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);

	upper = d->pos + received;

	/*
	 * If we're receiving "chunked" data, we do not know the size of what
	 * we'll be receiving in advance, so we need to dynamically extend
	 * the fileinfo.
	 */

	if (fi->size < upper) {
		if (fi->file_size_known) {
			file_info_size_unknown(fi);
			g_warning("%s(): receiving extra data for \"%s\" from %s: "
				"thought size was %s bytes, receiving %zu byte%s at %s -> %s",
				G_STRFUNC, fi->pathname, download_host_info(d),
				filesize_to_string(fi->size), received, plural(received),
				filesize_to_string2(d->pos),
				filesize_to_string3(upper));
		}
		file_info_resize(fi, upper);
	}

	file_info_update(d, d->pos, upper, DL_CHUNK_DONE);

	d->pos = upper;
	d->last_update = tm_time();
	fi->recv_amount += received;
}

/**
 * Called when all the received data so far have been processed to
 * check whether we are done.
 */
void
download_maybe_finished(struct download *d)
{
	fileinfo_t *fi = d->file_info;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);

	if (FILE_INFO_COMPLETE(fi))
		download_rx_done(d);
}

/**
 * Create a download based on the information from the magnet URI.
 */
uint
download_handle_magnet(const char *url)
{
	struct magnet_resource *res;
	uint n_downloads = 0;
	const char *error_str;

	res = magnet_parse(url, &error_str);
	if (res) {
		char *filename;	/* strdup */
		pslist_t *sl;

		filename = h_strdup(res->display_name);
		if (!filename) {
			PSLIST_FOREACH(res->sources, sl) {
				struct magnet_source *ms = sl->data;

				if (ms->path) {
					const char *endptr;
					
					/*
					 * If the path contains a '?', this is most-likely a
					 * `search' with parameters e.g., "/index.php?yadda=1",
					 * so we cut the search part off for the filename.
					 */
					endptr = strchr(ms->path, '?');
					if (!endptr) {
						endptr = strchr(ms->path, '\0');
					}

					{
						char *path, *unescaped;

						path = h_strndup(ms->path, endptr - ms->path);
						unescaped = url_unescape(path, FALSE);
						if (unescaped) {
							filename = g_strdup(filepath_basename(unescaped));
							if (unescaped != path) {
								HFREE_NULL(unescaped);
							}
						}
						HFREE_NULL(path);
					}

					if (filename && '\0' != filename[0]) {
						break;
					}
					HFREE_NULL(filename);
				}
			}
		}
		if (!filename) {
			if (res->sha1) {
				filename = h_strconcat("urn:sha1:",
								sha1_base32(res->sha1), (void *) 0);
			} else {
				filename = h_strdup("magnet-download");
			}
		}

		PSLIST_FOREACH(res->sources, sl) {
			struct magnet_source *ms = sl->data;
			gnet_host_vec_t *proxies;
			const struct guid *guid;
			const struct guid *guid_atom = NULL;
			host_addr_t addr;
			uint16 port;
			uint32 flags;

			if (
				(NULL == ms->path && NULL == res->sha1) ||
				(NULL == ms->guid &&
					(0 == ms->port ||
						(NULL == ms->hostname && !is_host_addr(ms->addr)))
				)
			) {
				char *s = magnet_source_to_string(ms);
				g_message("unusable magnet source \"%s\"", NULL_STRING(s));
				G_FREE_NULL(s);
				continue;
			}

			flags = SOCK_F_FORCE;

			/*
			 * Firewalled magnets have a push:// source pointing to a
			 * list of push-proxies.  When retrieving, we lost the
			 * original IP address of the server, so leave it unspecified.
			 */

			if (ms->guid) {
				addr = ipv4_unspecified;
				port = 0;
				flags |= SOCK_F_PUSH;
				guid = ms->guid;
				proxies = gnet_host_vec_from_pslist(ms->proxies);
			} else {
				addr = is_host_addr(ms->addr) ? ms->addr : ipv4_unspecified;
				port = ms->port;
				if (res->guid) {
					struct guid server_guid;
					if (hex_to_guid(res->guid, &server_guid)) {
						guid = guid_atom = atom_guid_get(&server_guid);
					} else {
						guid = &blank_guid;
					}
				} else {
					guid = &blank_guid;
				}
				proxies = NULL;
			}

			download_new(filename,
				ms->path,
				res->size,
				addr,
				port,
				guid,
				ms->hostname,
				res->sha1,
				res->tth,
				tm_time(),
				NULL,
				proxies,
				flags,
				res->parq_id);

			/*
			 * Propagate informations to server:
			 *    - vendor information if available.
			 *    - DHT support indication.
			 */

			if (res->vendor || res->dht || res->g2) {
				struct dl_server *server = get_server(guid, addr, port, FALSE);
				if (server && res->vendor != NULL && NULL == server->vendor) {
					server->vendor =
						atom_str_get(lazy_iso8859_1_to_utf8(res->vendor));
				}
				if (server && res->dht) {
					server->attrs |= DLS_A_DHT_PUBLISH;
				}
				if (server && res->g2) {
					server->attrs |= DLS_A_G2_ONLY;
				}
			}

			if (guid_atom != NULL)
				atom_guid_free_null(&guid_atom);

			gnet_host_vec_free(&proxies);
			n_downloads++;
		}

		if (!res->sources && res->sha1) {
			/*
			 * When we know the urn:sha1: we reserve a download immediately
			 * for the side effect of creating a proper fileinfo for this
			 * SHA1.  Then we immediately query the DHT for that SHA1 and
			 * the download will start as soon as we find a source.
			 */

			download_new(filename,
				NULL,	/* URI */
				res->size,
				ipv4_unspecified,
				0,		/* port */
				&blank_guid,
				NULL,	/* hostname */
				res->sha1,
				res->tth,
				tm_time(),
				NULL,	/* proxy */
				NULL,	/* fileinfo */
				0,		/* flags */
				NULL);	/* PARQ ID */

			n_downloads++;
			file_info_dht_query(res->sha1);
		}

		HFREE_NULL(filename);
		magnet_resource_free(&res);
	} else {
		if (GNET_PROPERTY(download_debug)) {
			g_warning("magnet_parse() failed: %s", NULL_STRING(error_str));
		}
	}
	return n_downloads;
}

/**
 * Create a download based on an HTTP URL.
 */
bool
download_handle_http(const char *url)
{
	char *magnet_url;
	bool success;

	g_return_val_if_fail(url, FALSE);
	g_return_val_if_fail(is_strcaseprefix(url, "http://"), FALSE);

	{
		struct magnet_resource *magnet;
		char *escaped_url;

		/* Assume the URL was entered by a human; humans don't escape
		 * URLs except on accident and probably incorrectly. Try to
		 * correct the escaping but don't touch '?', '&', '=', ':'.
		 */
		escaped_url = url_fix_escape(url);

		/* Magnet values are ALWAYS escaped. */
		magnet = magnet_resource_new();
		magnet_add_source_by_url(magnet, escaped_url);
		if (escaped_url != url) {
			HFREE_NULL(escaped_url);
		}
		magnet_url = magnet_to_string(magnet);
		magnet_resource_free(&magnet);
	}
	
	success = download_handle_magnet(magnet_url);
	HFREE_NULL(magnet_url);

	return success;
}

/**
 * @return average download speed overall for the server, and if not available
 * yet, for this particular source if it is active.
 */
uint
download_speed_avg(const struct download *d)
{
	uint speed_avg;
	uint source_avg = 0;

	download_check(d);
	g_assert(d->server);

	speed_avg = d->server->speed_avg;
	if (d->bio)
		source_avg = bio_avg_bps(d->bio);

	speed_avg = MAX(source_avg, speed_avg);

	/*
	 * If download is stalled, we arbitrarily decimate the average speed
	 * by an arbitrary factor instead of forcefully returning 0, as the
	 * stalling may be temporary.
	 */

	return download_is_stalled(d) ? speed_avg / 50 : speed_avg;
}

/**
 * @return whether download is stalled, not having received data for some
 * time now.
 */
bool
download_is_stalled(const struct download *d)
{
	return delta_time(tm_time(), d->last_update) > DOWNLOAD_STALLED;
}

/*
 * GUI operations
 */

/**
 * [GUI] Remove stopped downloads.
 * complete == TRUE:    removes DONE | COMPLETED
 * failed == TRUE:      removes ERROR | ABORTED without `unavailable' set
 * unavailable == TRUE: removes ERROR | ABORTED with `unavailable' set
 * now == TRUE:         remove immediately, else remove only downloads
 *                      idle since at least "entry_removal_timeout" seconds
 */
void
download_clear_stopped(bool complete,
	bool failed, bool unavailable, bool finished, bool now)
{
	struct download *next;

	next = hash_list_head(sl_unqueued);
	while (next) {
		struct download *d = next;

		download_check(d);
		next = hash_list_next(sl_unqueued, next);

		switch (d->status) {
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			if (
				!(failed && !d->unavailable) &&
				!(unavailable && d->unavailable)
			) {
				continue;
			}
			break;
		case GTA_DL_COMPLETED:
		case GTA_DL_DONE:
			if (!complete) {
				continue;
			}
			break;
		case GTA_DL_VERIFIED:
			if (!(now || finished)) {
				/* We don't want clear "finished" downloads automagically
				 * because it would make it difficult to notice them in the
				 * GUI. */
				continue;
			}
		default:
			continue;
		}

		if (
			!now &&
			delta_time(tm_time(), d->last_update) <
				(time_delta_t) GNET_PROPERTY(entry_removal_timeout)
		) {
			continue;
		}

		if (
			finished &&
			FILE_INFO_FINISHED(d->file_info) &&
			!(FI_F_SEEDING & d->file_info->flags)
		) {
			file_info_purge(d->file_info);
			continue;
		}
		
		if (d->flags & DL_F_TRANSIENT) {
			file_info_purge(d->file_info);
		} else {
			download_remove(d);
		}
	}
}


/**
 * Download heartbeat timer.
 */
void
download_timer(time_t now)
{
	struct download *next;

	next = hash_list_head(sl_unqueued);
	while (next) {
		struct download *d = next;

		download_check(d);
		g_assert(dl_server_valid(d->server));

		next = hash_list_next(sl_unqueued, next);

		switch (d->status) {
		time_delta_t timeout;
		case GTA_DL_RECEIVING:
		case GTA_DL_IGNORING:
			/*
			 * Update the global average reception rate periodically.
			 */

			if (!download_is_special(d)) {
				fileinfo_t *fi = d->file_info;
				time_delta_t delta = delta_time(now, fi->recv_last_time);

				g_assert(fi->recvcount > 0);

				if (delta > IO_AVG_RATE) {
					double rate = fi->recv_amount / (double) delta;

					fi->recv_last_rate = fi->recv_amount / delta;
					fi->recv_amount = 0;
					fi->recv_last_time = now;
					file_info_changed(fi);

					random_pool_append(&rate, sizeof rate);
				}
			}

			/*
			 * See whether it's not time to issue the next request ahead
			 * of time (HTTP pipelining) to reduce latency between chunk
			 * reception: no need to pay the penalty of the round-trip time.
			 */

			if (
				GNET_PROPERTY(enable_http_pipelining) &&
				download_pipeline_can_initiate(d)
			) {
				g_assert(!download_pipelining(d));
				g_assert(DOWNLOAD_IS_ACTIVE(d));

				d->pipeline = download_pipeline_alloc();

				if (
					NULL == d->ranges ||
					!download_pick_available(d, &d->pipeline->chunk)
				) {
					/*
					 * File info code may determine that a download file is
					 * suddenly gone and reset swarming, causing the
					 * download to be re-queued.  Hence we need to recheck
					 * that the download is still active.
					 */

					if (!DOWNLOAD_IS_ACTIVE(d)) {
						g_assert(!download_pipelining(d));
						continue;		/* Was requeued */
					}

					/*
					 * Ranges may have changed on server, pick a chunk without
					 * relying on what we think is available.  If that fails,
					 * we'll get an updated range list from the server.
					 */

					if (!download_pick_chunk(d, &d->pipeline->chunk, FALSE)) {
						d->flags |= DL_F_NO_PIPELINE;
						download_pipeline_free_null(&d->pipeline);
					}
				}

				if (DOWNLOAD_IS_ACTIVE(d)) {
					if (download_pipelining(d)) {
						download_send_request(d);
					}
				} else {
					g_assert(!download_pipelining(d));
					continue;		/* Was requeued */
				}

				g_assert(!download_pipelining(d) ||
					d->pipeline->status != GTA_DL_PIPE_SELECTED);
			}

			/* FALL THROUGH */

		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_HEADERS:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_CONNECTING:
		case GTA_DL_CONNECTED:
		case GTA_DL_REQ_SENDING:
		case GTA_DL_REQ_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:

			if (!GNET_PROPERTY(is_inet_connected)) {
				download_queue(d, _("No longer connected"));
				break;
			}

			switch (d->status) {
			case GTA_DL_ACTIVE_QUEUED:
 				timeout = get_parq_dl_retry_delay(d);
 				break;
			case GTA_DL_PUSH_SENT:
			case GTA_DL_FALLBACK:
				/*
				 * Do not timeout if we're searching for new push-proxies
				 * or if we're issuing an HTTP push-proxy request but
				 * got no reply from the other party yet.
				 */
				timeout = (d->server->attrs & DLS_A_DHT_PROX) ?
					MAX_INT_VAL(time_delta_t) :
					(d->cproxy != NULL && !d->cproxy->done) ?
						MAX_INT_VAL(time_delta_t) :
						GNET_PROPERTY(download_push_sent_timeout);
				break;
			case GTA_DL_CONNECTING:
				timeout = GNET_PROPERTY(download_connecting_timeout);
				break;
			case GTA_DL_REQ_SENT:
				/*
				 * For each second we spend in the "request sent" stage,
				 * add 0.5 secs to the latency so that we can better adjust
				 * the time at which we request the next pipelined chunk
				 * for this server.
				 */
				d->server->latency += 500;	/* Half a second */
				/* FALL THROUGH */
			default:
				timeout = GNET_PROPERTY(download_connected_timeout);
				break;
			}

			if (delta_time(now, d->last_update) > timeout) {
				if (DOWNLOAD_IS_ACTIVE(d))
					d->data_timeouts++;

				/*
				 * When the 'timeout' has expired, first check whether the
				 * download was activly queued. If so, tell parq to retry the
				 * download in which case the HTTP connection wasn't closed
				 *   --JA 31 jan 2003
				 */
				if (d->status == GTA_DL_ACTIVE_QUEUED)
					parq_download_retry_active_queued(d);
				else if (
					d->status == GTA_DL_CONNECTING &&
					!GNET_PROPERTY(is_firewalled) && GNET_PROPERTY(send_pushes)
				) {
					download_fallback_to_push(d, TRUE, FALSE);
				} else if (d->status == GTA_DL_HEADERS)
					download_incomplete_header(d);
				else {
					if (DOWNLOAD_IS_EXPECTING_GIV(d)) {
						if (!next_push_proxy(d))
							download_push(d, TRUE);
					} else if (
						d->retries++ < GNET_PROPERTY(download_max_retries)
					) {
						download_retry(d);
					} else if (d->data_timeouts > DOWNLOAD_DATA_TIMEOUT) {
						download_unavailable(d, GTA_DL_ERROR,
							_("Too many data timeouts"));
					} else {
						/*
						 * Host is down, probably.  Abort all other downloads
						 * queued for that host as well.
						 */

						download_unavailable(d, GTA_DL_ERROR, _("Timeout"));
						download_remove_all_from_peer(
							download_guid(d), download_addr(d),
							download_port(d), TRUE);
					}
				}
			} else if (now != d->last_gui_update) {
				fi_src_status_changed(d);
			}
			break;
		case GTA_DL_TIMEOUT_WAIT:
			if (!GNET_PROPERTY(is_inet_connected)) {
				download_queue(d, _("No longer connected"));
				break;
			}

			if (d->retries >= GNET_PROPERTY(download_max_retries)) {
				download_unavailable(d, GTA_DL_ERROR,
					_("Too many attempts (%u times)"), d->retries);
			} else if (
				delta_time(now, d->last_update) >
					(time_delta_t) d->timeout_delay
			) {
				download_start(d, TRUE);
			} else {
				/* Move the download back to the waiting queue.
				 * It will be rescheduled automatically later.
				 */
				download_queue_delay(d,
					GNET_PROPERTY(download_retry_timeout_delay),
				    _("Requeued due to timeout"));
			}
			break;
		case GTA_DL_VERIFYING:
		case GTA_DL_MOVING:
			fi_src_status_changed(d);
			break;
		case GTA_DL_COMPLETED:
		case GTA_DL_ABORTED:
		case GTA_DL_ERROR:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFIED:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_DONE:
		case GTA_DL_REMOVED:
			break;
		case GTA_DL_PASSIVE_QUEUED:
		case GTA_DL_QUEUED:
			g_error("found queued download in sl_unqueued list: \"%s\"",
				download_pathname(d));
			break;
		case GTA_DL_INVALID:
			g_assert_not_reached();
		}
	}

	download_clear_stopped(
		GNET_PROPERTY(clear_complete_downloads),
		GNET_PROPERTY(clear_failed_downloads),
		GNET_PROPERTY(clear_unavailable_downloads),
		GNET_PROPERTY(clear_finished_downloads),
		FALSE);

	download_free_removed();

	/*
	 * If we froze the queue due to a previous recoverable write error (such
	 * as a lack of free space on the filesystem), check whether we have
	 * room now and unfreeze the queue if we have.
	 */

	if (queue_frozen_on_write_error) {
		if (!download_queue_is_frozen())
			queue_frozen_on_write_error = FALSE;	/* They unfroze it! */
	}

	if (queue_frozen_on_write_error) {
		if (fs_free_space(GNET_PROPERTY(save_file_path)) >= DOWNLOAD_FS_SPACE) {
			g_info("space available again on %s, unfreezing download queue",
				GNET_PROPERTY(save_file_path));
			download_thaw_queue();
			queue_frozen_on_write_error = FALSE;
		}
	}

	/* Dequeuing */
	if (GNET_PROPERTY(is_inet_connected))
		download_pickup_queued();
}

/**
 * Download infrequent heartbeat timer.
 */
void
download_slow_timer(time_t now)
{
	struct download *next;

	next = hash_list_head(sl_downloads);
	while (next) {
		struct download *d = next;

		download_check(d);
		g_assert(dl_server_valid(d->server));

		next = hash_list_next(sl_downloads, next);

		switch (d->status) {
		case GTA_DL_QUEUED:
			/*
			 * If has a PARQ ID but the download is neither actively nor
			 * passively queued, then we may have gone through a queue
			 * freezing period, or we can't connect to the remote server.
			 */

			if (d->parq_dl && delta_time(now, d->retry_after) >= 0) {
				if (GNET_PROPERTY(parq_debug) || GNET_PROPERTY(download_debug))
					g_debug("restarting pending \"%s\" PARQ ID=%s",
						download_pathname(d), get_parq_dl_id(d));

				download_start(d, FALSE);
			}
			break;
		case GTA_DL_INVALID:
			g_assert_not_reached();
		default:
			break;
		}
	}
}

/*
 * Is the filename that of a completed download?
 */
bool
download_is_completed_filename(const char *name)
{
	static const char *ext[] = { DL_OK_EXT, DL_BAD_EXT, DL_UNKN_EXT };
	unsigned i;
	size_t namelen;

	g_assert(name != NULL);

	namelen = strlen(name);

	for (i = 0; i < G_N_ELEMENTS(ext); i++) {
		if (is_strsuffix(name, namelen, ext[i]))
			return TRUE;
	}

	return FALSE;
}

/*
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4 sw=4 cindent:
 */
