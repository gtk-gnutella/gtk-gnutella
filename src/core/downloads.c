/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @date 2001-2003
 */

#include "common.h"

#include "sockets.h"
#include "downloads.h"
#include "hosts.h"
#include "routing.h"
#include "gmsg.h"
#include "bsched.h"
#include "huge.h"
#include "dmesh.h"
#include "file_object.h"
#include "http.h"
#include "version.h"
#include "ignore.h"
#include "ioheader.h"
#include "verify.h"
#include "move.h"
#include "settings.h"
#include "nodes.h"
#include "parq.h"
#include "token.h"
#include "hostiles.h"
#include "clock.h"
#include "uploads.h"
#include "ban.h"
#include "guid.h"
#include "pproxy.h"
#include "features.h"
#include "gnet_stats.h"
#include "geo_ip.h"
#include "bh_download.h"
#include "tls_cache.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/adns.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/dbus_util.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/idtable.h"
#include "lib/palloc.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

#if defined(S_IROTH)
#define DOWNLOAD_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) /* 0644 */
#else
#define DOWNLOAD_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP) /* 0640 */
#endif

#define DOWNLOAD_MIN_OVERLAP	64		/**< Minimum overlap for safety */
#define DOWNLOAD_SHORT_DELAY	2		/**< Shortest retry delay */
#define DOWNLOAD_MAX_SINK		16384	/**< Max amount of data to sink */
#define DOWNLOAD_SERVER_HOLD	15		/**< Space requests to same server */
#define DOWNLOAD_DNS_LOOKUP		7200	/**< Period of server DNS lookups */

#define BUFFER_POOL_MAX			300		/**< Max amount of buffers to keep */

#define IO_AVG_RATE		5		/**< Compute global recv rate every 5 secs */

static GSList *sl_downloads = NULL;	/**< All downloads (queued + unqueued) */
GSList *sl_unqueued = NULL;			/**< Unqueued downloads only */
GSList *sl_removed = NULL;			/**< Removed downloads only */
GSList *sl_removed_servers = NULL;	/**< Removed servers only */
static gchar dl_tmp[4096];
static gint queue_frozen = 0;
static pool_t *buffer_pool;			/**< Memory pool for read buffers */

static const gchar DL_OK_EXT[] = ".OK";		/**< Extension to mark OK files */
static const gchar DL_BAD_EXT[] = ".BAD";	/**< "Bad" files (SHA1 mismatch) */
static const gchar DL_UNKN_EXT[] = ".UNKN";		/**< For unchecked files */
static const gchar file_what[] = "downloads"; /**< What is persisted to file */
static const gchar no_reason[] = "<no reason>"; /**< Don't translate this */

static void download_add_to_list(struct download *d, enum dl_list idx);
static gboolean send_push_request(const gchar *, guint32, guint16);
static gboolean download_read(struct download *d, pmsg_t *mb);
static void download_request(struct download *d, header_t *header, gboolean ok);
static void download_push_ready(struct download *d, getline_t *empty);
static void download_push_remove(struct download *d);
static void download_push(struct download *d, gboolean on_timeout);
static void download_resume_bg_tasks(void);
static void download_incomplete_header(struct download *d);
static gboolean has_blank_guid(const struct download *d);
static void download_verify_sha1(struct download *d);
static gboolean download_get_server_name(struct download *d, header_t *header);
static gboolean use_push_proxy(struct download *d);
static void download_unavailable(struct download *d,
		download_status_t new_status,
		const gchar * reason, ...) G_GNUC_PRINTF(3, 4);
static void download_queue_delay(struct download *d, guint32 delay,
	const gchar *fmt, ...) G_GNUC_PRINTF(3, 4);
static void download_queue_hold(struct download *d, guint32 hold,
	const gchar *fmt, ...) G_GNUC_PRINTF(3, 4);
static void download_reparent(struct download *d, struct dl_server *new_server);
static gboolean download_flush(
	struct download *d, gboolean *trimmed, gboolean may_stop);

static gboolean download_dirty = FALSE;
static void download_store(void);
static void download_retrieve(void);

/*
 * Download structures.
 *
 * This `dl_key' is inserted in the `dl_by_host' hash table were we find a
 * `dl_server' structure describing all the downloads for the given host.
 *
 * All `dl_server' structures are also inserted in the `dl_by_time' struct,
 * where hosts are sorted based on their retry time.
 *
 * The `dl_count_by_name' hash tables is indexed by name, and counts the
 * amount of downloads scheduled with that name.
 */

static GHashTable *dl_by_host = NULL;
static GHashTable *dl_count_by_name = NULL;

#define DHASH_SIZE	1024			/**< Hash list size, must be a power of 2 */
#define DHASH_MASK 	(DHASH_SIZE - 1)
#define DL_HASH(x)	((x) & DHASH_MASK)

static struct {
	GList *servers[DHASH_SIZE];		/**< Lists of servers, by retry time */
	gint change[DHASH_SIZE];		/**< Counts changes to the list */
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

static GHashTable *dl_by_addr = NULL;

/**
 * Keys in the `dl_by_addr' table.
 */
struct dl_addr {
	host_addr_t addr;		/**< IP address of server */
	guint16 port;			/**< Port of server */
};

static guint dl_establishing = 0;		/**< Establishing downloads */
static guint dl_active = 0;				/**< Active downloads */

#define count_running_downloads()	(dl_establishing + dl_active)
#define count_running_on_server(s)	(server_list_length(s, DL_LIST_RUNNING))

static inline guint
server_list_length(const struct dl_server *server, enum dl_list idx)
{
	g_assert(dl_server_valid(server));
	g_assert((guint) idx < DL_LIST_SZ);		
	return server->list[idx] ? list_length(server->list[idx]) : 0;
}

#define MAGIC_TIME	1		/**< For recreation upon starup */

/***
 *** Sources API
 ***/

static struct event *src_events[EV_SRC_EVENTS] = {
	NULL, NULL, NULL, NULL
};

static idtable_t *src_handle_map = NULL;

static void
src_init(void)
{
    src_handle_map = idtable_new(32, 32);

    src_events[EV_SRC_ADDED]          = event_new("src_added");
    src_events[EV_SRC_REMOVED]        = event_new("src_removed");
    src_events[EV_SRC_INFO_CHANGED]   = event_new("src_info_changed");
    src_events[EV_SRC_STATUS_CHANGED] = event_new("src_status_changed");
    src_events[EV_SRC_RANGES_CHANGED] = event_new("src_ranges_changed");
}

static void
src_close(void)
{
    guint n;

    /* See FIXME in download_close()!! */
#if 0
    g_assert(idtable_ids(src_handle_map) == 0);
#endif
    idtable_destroy(src_handle_map);

    for (n = 0; n < G_N_ELEMENTS(src_events); n ++)
        event_destroy(src_events[n]);
}

void
src_add_listener(src_listener_t cb, gnet_src_ev_t ev,
    frequency_t t, guint32 interval)
{
    g_assert(ev < EV_SRC_EVENTS);

    event_add_subscriber(src_events[ev], (GCallback) cb,
        t, interval);
}

void
src_remove_listener(src_listener_t cb, gnet_src_ev_t ev)
{
    g_assert(ev < EV_SRC_EVENTS);

    event_remove_subscriber(src_events[ev], (GCallback) cb);
}

struct download *
src_get_download(gnet_src_t src_handle)
{
	return idtable_get_value(src_handle_map, src_handle);
}

/***
 *** RX link callbacks
 ***/

static G_GNUC_PRINTF(2, 3) void
download_rx_error(gpointer o, const gchar *reason, ...)
{
	struct download *d = o;
	va_list args;

	download_check(d);
	va_start(args, reason);
	download_stop_v(d, GTA_DL_ERROR, reason, args);
	va_end(args);
}

static void
download_rx_got_eof(gpointer o)
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
static gboolean
download_data_ind(rxdrv_t *rx, pmsg_t *mb)
{
	struct download *d = rx_owner(rx);

	return download_read(d, mb);
}

static const struct rx_link_cb download_rx_link_cb = {
	NULL,					/* add_rx_given */
	download_rx_error,		/* read_error */
	download_rx_got_eof,	/* got_eof */
};

static void
download_chunk_rx_done(gpointer o)
{
	struct download *d = o;

	download_check(d);
	download_rx_done(d);
}

static const struct rx_chunk_cb download_rx_chunk_cb = {
	download_rx_error,		/* chunk_error */
	download_chunk_rx_done,			/* chunk_end */
};

static const struct rx_inflate_cb download_rx_inflate_cb = {
	NULL,					/* add_rx_inflated */
	download_rx_error,		/* inflate_error */
};

/**
 * Received data from outside the RX stack.
 */
static void
download_write(struct download *d, gpointer data, size_t len)
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
	 */

	rx_recv(rx_bottom(d->rx), mb);
}


/**
 * The only place to allocate a struct download.
 */
static struct download *
download_alloc(void)
{
	static const struct download zero_download;
	struct download *d;
	
	d = walloc(sizeof *d);
	*d = zero_download;
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

	d->magic = 0;
	wfree(d, sizeof *d);
	*d_ptr = NULL;
}

/**
 * Hashing of a `dl_key' structure.
 */
static guint
dl_key_hash(gconstpointer key)
{
	const struct dl_key *k = key;
	guint hash;

	hash = guid_hash(k->guid);
	hash ^= host_addr_hash(k->addr);
	hash ^= (k->port << 16) | k->port;

	return hash;
}

/**
 * Comparison of `dl_key' structures.
 */
static gint
dl_key_eq(gconstpointer a, gconstpointer b)
{
	const struct dl_key *ak = a, *bk = b;

	return host_addr_equal(ak->addr, bk->addr) &&
		ak->port == bk->port &&
		guid_eq(ak->guid, bk->guid);
}

/**
 * Hashing of a `dl_addr' structure.
 */
static guint
dl_addr_hash(gconstpointer key)
{
	const struct dl_addr *k = key;
	guint32 hash;

	hash = host_addr_hash(k->addr);
	hash ^= (k->port << 16) | k->port;

	return (guint) hash;
}

/**
 * Comparison of `dl_addr' structures.
 */
static gint
dl_addr_eq(gconstpointer a, gconstpointer b)
{
	const struct dl_addr *ak = a, *bk = b;

	return host_addr_equal(ak->addr, bk->addr) && ak->port == bk->port;
}

/**
 * Compare two `download' structures based on the `retry_after' field.
 * The smaller that time, the smaller the structure is.
 */
static gint
dl_retry_cmp(gconstpointer p, gconstpointer q)
{
	const struct download *a = p, *b = q;

	return CMP(a->retry_after, b->retry_after);
}

/**
 * Compare two `dl_server' structures based on the `retry_after' field.
 * The smaller that time, the smaller the structure is.
 */
static gint
dl_server_retry_cmp(gconstpointer p, gconstpointer q)
{
	const struct dl_server *a = p, *b = q;

	return CMP(a->retry_after, b->retry_after);
}

/**
 * @returns whether download has a blank (fake) GUID.
 */
static gboolean
has_blank_guid(const struct download *d)
{
	const gchar *g = download_guid(d);
	gint i;

	for (i = 0; i < 16; i++)
		if (*g++)
			return FALSE;

	return TRUE;
}

/**
 * @returns whether download was faked to reparent a complete orphaned file.
 */
gboolean
is_faked_download(const struct download *d)
{
	return !is_host_addr(download_addr(d)) &&
			download_port(d) == 0 &&
			has_blank_guid(d);
}

/**
 * Was downloaded file verified to have a SHA1 matching the advertised one?
 */
static gboolean
has_good_sha1(const struct download *d)
{
	fileinfo_t *fi = d->file_info;

	return fi->sha1 == NULL || (fi->cha1 && sha1_eq(fi->sha1, fi->cha1));
}

/* ----------------------------------------- */

/**
 * Return the total progress of a download.  The range
 * on the return value should be 0 -> 1 but there is no
 * guarantee.
 *
 * @param d The download structure which we are interested
 * in knowing the progress of.
 *
 * @return The total percent completed for this file.
 */
gdouble
download_total_progress(const struct download *d)
{
	filesize_t filesize = download_filesize(d);

	return filesize < 1 ? 0.0 : (gdouble) download_filedone(d) / filesize;
}

/**
 * Return the total progress of a download source.  The
 * range on the return value should be 0 -> 1 but there is
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
gdouble
download_source_progress(const struct download *d)
{
	return !DOWNLOAD_IS_ACTIVE(d) || d->size < 1
		? 0.0
		: (d->pos - d->skip + download_buffered(d)) / (gdouble) d->size;
}

/**
 * Initialize downloading data structures.
 */
void
download_init(void)
{
	dl_by_host = g_hash_table_new(dl_key_hash, dl_key_eq);
	dl_by_addr = g_hash_table_new(dl_addr_hash, dl_addr_eq);
	dl_count_by_name = g_hash_table_new(g_str_hash, g_str_equal);
	buffer_pool = pool_create(SOCK_BUFSZ, BUFFER_POOL_MAX);

	src_init();
}

/**
 * Initialize downloading data structures.
 */
void
download_restore_state(void)
{
	/*
	 * The order of the following calls matters.
	 */

	file_info_retrieve();					/* Get all fileinfos */
	file_info_scandir(save_file_path);		/* Pick up orphaned files */
	download_retrieve();					/* Restore downloads */
	file_info_spot_completed_orphans();		/* 100% done orphans => fake dl. */
	download_resume_bg_tasks();				/* Reschedule SHA1 and moving */
	file_info_store();
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
	g_assert(d->buffers == NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = walloc(sizeof *b);
	*b = zero_buffers;
	b->amount = download_buffer_size;

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

	G_SLIST_FOREACH(b->buffers, pmsg_free);
	g_slist_free(b->buffers);
	b->buffers = NULL;
	b->last = NULL;

	wfree(b, sizeof *b);

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
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);
	g_assert(d->buffers->held == 0);

	b = d->buffers;

	G_SLIST_FOREACH(b->buffers, pmsg_free);
	g_slist_free(b->buffers);
	b->buffers = NULL;
	b->last = NULL;

	b->count = 0;
	b->mode = DL_BUF_READING;
}

/**
 * Reset the I/O vector for writing the whole data held in the buffer.
 */
static struct iovec *
buffers_to_iovec(struct download *d)
{
	struct dl_buffers *b;
	struct iovec *iov;
	GSList *sl;
	size_t i;

	download_check(d);

	g_assert(d->buffers != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = d->buffers;

	g_assert(b->held > 0);
	g_assert(b->count > 0);
	g_assert(b->buffers);
	g_assert(b->last);
	g_assert(b->mode == DL_BUF_READING);

	iov = walloc(b->count * sizeof *iov);

	for (i = 0, sl = b->buffers; NULL != sl; sl = g_slist_next(sl), i++) {
		pmsg_t *mb;
	  
		mb = sl->data;
	   	g_assert(mb);
		g_assert(i < b->count);

		iov[i].iov_base = pmsg_read_base(mb);
		iov[i].iov_len = pmsg_size(mb);
	}

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
static inline gboolean
buffers_full(const struct download *d)
{
	const struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers);

	b = d->buffers;

	return b->held >= download_buffer_size;
}

/**
 * Check whether we should request flushing of the buffered data.
 */
static inline gboolean
buffers_should_flush(const struct download *d)
{
	const struct dl_buffers *b;

	download_check(d);
	g_assert(d->buffers);

	b = d->buffers;

	return b->held >= b->amount;
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
	size_t size;

	download_check(d);
	g_assert(d->buffers != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = d->buffers;
	fi = d->file_info;

	g_assert(b->mode == DL_BUF_READING);

	g_assert(NULL == g_slist_next(b->last));	
	b->last = g_slist_last(g_slist_append(b->last, mb));
	if (!b->buffers) {
		b->buffers = b->last;
	}
	b->count++;

	size = pmsg_size(mb);
	b->held += size;

	/*
	 * Update read statistics.
	 */

	fi->buffered += size;
}

/**
 * Compare data held in the read buffers with the data chunk supplied.
 *
 * @return TRUE if data match.
 */
static gboolean
buffers_match(const struct download *d, const gchar *data, size_t len)
{
	const struct dl_buffers *b;
	const GSList *sl;

	download_check(d);
	g_assert(d->buffers != NULL);
	g_assert(d->socket != NULL);
	g_assert(d->status == GTA_DL_RECEIVING);

	b = d->buffers;
	g_assert(len <= b->held);

	for (sl = b->buffers; len > 0 && NULL != sl; sl = g_slist_next(sl)) {
		const pmsg_t *mb;
		size_t n;
	
		mb = sl->data;
		g_assert(mb);

		n = pmsg_size(mb);
		n = MIN(n, len);
		if (0 != memcmp(pmsg_read_base(mb), data, n)) {
			return FALSE;
		}
		len -= n;
	}

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
	GSList *sl;
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

	n = amount;
	sl = b->buffers;
	while (n > 0) {
		pmsg_t *mb;
		size_t size;

		mb = sl->data;
		g_assert(mb);

		size = pmsg_size(mb);
		if (size > n) {
			pmsg_discard(mb, n);
			break;
		} else {
			pmsg_free(mb);
			n -= size;
			sl = g_slist_delete_link(sl, sl);
		}
	}

	b->buffers = sl;
	if (!b->buffers) 
		b->last = NULL;

	b->held -= amount;

	if (fi->buffered >= amount)
		fi->buffered -= amount;
	else
		fi->buffered = 0;		/* Not critical, be fault-tolerant */
}

/**
 * Strip trailing `amount' bytes from the read buffers.
 */
static void
buffers_strip_trailing(struct download *d, size_t amount)
{
	struct dl_buffers *b;
	fileinfo_t *fi;
	GSList *sl;
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
	b->last = b->buffers;

	for (sl = b->buffers; NULL != sl; /* NOTHING */) {
		pmsg_t *mb;
		size_t size;

		mb = sl->data;
		g_assert(mb);

		if (n > 0) {
			size = pmsg_size(mb);
			if (size < n) {
				n -= size;
			} else {
				b->last = sl;
				if (size > n) {
					pmsg_discard_trailing(mb, size - n);
				}
				n = 0;
			}
			sl = g_slist_next(sl);
		} else {
			pmsg_free(mb);
			sl = g_slist_delete_link(sl, sl);
		}
	}

	g_assert(NULL != b->last);
	b->last->next = NULL; /* Was already deleted if any */

	b->held -= amount;

	if (fi->buffered >= amount)
		fi->buffered -= amount;
	else
		fi->buffered = 0;		/* Not critical, be fault-tolerant */
}

/* ----------------------------------------- */

/**
 * Download heartbeat timer.
 */
void
download_timer(time_t now)
{
	GSList *sl = sl_unqueued;		/* Only downloads not in the queue */

	if (queue_frozen > 0) {
		gcu_gui_update_download_clear_now();
		return;
	}

	while (sl) {
		struct download *d = sl->data;
		guint32 t;

		download_check(d);
		g_assert(dl_server_valid(d->server));

		sl = g_slist_next(sl);

		switch (d->status) {
		case GTA_DL_RECEIVING:
			/*
			 * Update the global average reception rate periodically.
			 */

			{
				fileinfo_t *fi = d->file_info;
				gint delta = delta_time(now, fi->recv_last_time);

				g_assert(fi->recvcount > 0);

				if (delta > IO_AVG_RATE) {
					fi->recv_last_rate = fi->recv_amount / delta;
					fi->recv_amount = 0;
					fi->recv_last_time = now;
					file_info_changed(fi);
				}
			}
			/* FALL THROUGH */

		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_HEADERS:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_CONNECTING:
		case GTA_DL_REQ_SENDING:
		case GTA_DL_REQ_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:

			if (!is_inet_connected) {
				download_queue(d, _("No longer connected"));
				break;
			}

			switch (d->status) {
			case GTA_DL_ACTIVE_QUEUED:
 				t = get_parq_dl_retry_delay(d);
 				break;
			case GTA_DL_PUSH_SENT:
			case GTA_DL_FALLBACK:
				t = download_push_sent_timeout;
				break;
			case GTA_DL_CONNECTING:
			case GTA_DL_REQ_SENT:
			case GTA_DL_HEADERS:
				t = download_connecting_timeout;
				break;
			default:
				t = download_connected_timeout;
				break;
			}

			if (delta_time(now, d->last_update) > (time_delta_t) t) {
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
					!(is_firewalled || !send_pushes)
				) {
					download_fallback_to_push(d, TRUE, FALSE);
				} else if (d->status == GTA_DL_HEADERS)
					download_incomplete_header(d);
				else {
					if (d->retries++ < download_max_retries)
						download_retry(d);
					else {
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
			} else if (now != d->last_gui_update)
				gcu_gui_update_download(d, TRUE);
			break;
		case GTA_DL_TIMEOUT_WAIT:
			if (!is_inet_connected) {
				download_queue(d, _("No longer connected"));
				break;
			}

			if (
				delta_time(now, d->last_update) >
					(time_delta_t) d->timeout_delay
			)
				download_start(d, TRUE);
			else {
				/* Move the download back to the waiting queue.
				 * It will be rescheduled automatically later.
				 */
				download_queue_delay(d, download_retry_timeout_delay,
				    _("Requeued due to timeout"));
				gcu_gui_update_download(d, FALSE);
			}
			break;
		case GTA_DL_VERIFYING:
		case GTA_DL_MOVING:
			gcu_gui_update_download(d, FALSE);
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
				download_outname(d));
			break;
		}
	}

	download_clear_stopped(
		clear_complete_downloads,
		clear_failed_downloads,
		clear_unavailable_downloads,
		FALSE);

	download_free_removed();
	gcu_gui_update_download_clear_now();

	/* Dequeuing */
	if (is_inet_connected)
		download_pickup_queued();
}

/* ----------------------------------------- */

/**
 * Insert server by retry time into the `dl_by_time' structure.
 */
static void
dl_by_time_insert(struct dl_server *server)
{
	gint idx = DL_HASH(server->retry_after);

	g_assert(dl_server_valid(server));

	dl_by_time.change[idx]++;
	dl_by_time.servers[idx] = g_list_insert_sorted(dl_by_time.servers[idx],
		server, dl_server_retry_cmp);
}

/**
 * Remove server from the `dl_by_time' structure.
 */
static void
dl_by_time_remove(struct dl_server *server)
{
	gint idx = DL_HASH(server->retry_after);

	g_assert(dl_server_valid(server));

	dl_by_time.change[idx]++;
	dl_by_time.servers[idx] = g_list_remove(dl_by_time.servers[idx], server);
}

/**
 * Convert a vector of host to a single-linked list.
 *
 * @returns new list, with every item cloned.
 */
static GSList *
hostvec_to_slist(const gnet_host_vec_t *vec)
{
	GSList *sl = NULL;
	gint i;

	for (i = vec->hvcnt - 1; i >= 0; i--) {
		gnet_host_t *h = &vec->hvec[i];
		gnet_host_t *host = walloc(sizeof *host);

		host->addr = h->addr;
		host->port = h->port;

		sl = g_slist_prepend(sl, host);
	}

	return sl;
}

/**
 * Get rid of the list of push proxies held in the server.
 */
static void
free_proxies(struct dl_server *server)
{
	GSList *sl;

	g_assert(dl_server_valid(server));
	g_assert(server->proxies);

	for (sl = server->proxies; sl; sl = g_slist_next(sl)) {
		struct gnutella_host *h = sl->data;
		wfree(h, sizeof *h);
	}

	g_slist_free(server->proxies);
	server->proxies = NULL;
}

/**
 * Remove push proxy from server.
 */
static void
remove_proxy(struct dl_server *server, const host_addr_t addr, guint16 port)
{
	GSList *sl;

	g_assert(dl_server_valid(server));

	for (sl = server->proxies; sl; sl = g_slist_next(sl)) {
		struct gnutella_host *h = sl->data;
		g_assert(h != NULL);

		if (host_addr_equal(h->addr, addr) && h->port == port) {
			server->proxies = g_slist_remove_link(server->proxies, sl);
			g_slist_free_1(sl);
			wfree(h, sizeof *h);
			return;
		}
	}

	/*
	 * The following could happen when we reset the list of push-proxies
	 * for a host after having selected a push-proxy from the old stale list.
	 */

	if (download_debug) {
		g_message("did not find push-proxy %s in server %s",
			host_addr_port_to_string(addr, port),
			host_addr_to_string(server->key->addr));
    }
}

/**
 * Allocate new server structure.
 */
static struct dl_server *
allocate_server(const gchar *guid, const host_addr_t addr, guint16 port)
{
	struct dl_key *key;
	struct dl_server *server;

	g_assert(host_addr_initialized(addr));

	key = walloc(sizeof *key);
	key->addr = addr;
	key->port = port;
	key->guid = atom_guid_get(guid);

	server = walloc0(sizeof *server);
	server->magic = DL_SERVER_MAGIC;
	server->key = key;
	server->retry_after = tm_time();
	server->country = gip_country(addr);
	server->sha1_counts = g_hash_table_new(sha1_hash, sha1_eq);

	g_hash_table_insert(dl_by_host, key, server);
	dl_by_time_insert(server);

	/*
	 * If host is reacheable directly, its GUID does not matter much to
	 * identify the server as the (IP, port) should be unique.
	 */

	if (host_is_valid(addr, port)) {
		struct dl_addr *ipk;
		gpointer ipkey;
		gpointer x;					/* Don't care about freeing values */
		gboolean existed;

		ipk = walloc(sizeof *ipk);
		ipk->addr = addr;			/* Struct copy */
		ipk->port = port;

		existed = g_hash_table_lookup_extended(dl_by_addr, ipk, &ipkey, &x);

		/*
		 * For the rare cases where the key already existed, we "take
		 * ownership" of the old key by associating our server entry in it.
		 * We reuse the old key, and free the new one, otherwise we'd
		 * have a memory leak because noone would free the old key!
		 */

		if (existed) {
			struct dl_addr *da = ipkey;
			g_assert(da != ipk);
			g_assert(host_addr_initialized(da->addr));
			wfree(ipk, sizeof *ipk);	/* Keep the old key */
			g_hash_table_insert(dl_by_addr, da, server);
		} else
			g_hash_table_insert(dl_by_addr, ipk, server);
	}

	return server;
}

static void
server_list_free_all(struct dl_server *server)
{
	guint i;

	g_assert(dl_server_valid(server));
	g_assert(0 == count_running_on_server(server));

	for (i = 0; i < DL_LIST_SZ; i++) {
		list_free(&server->list[i]);
	}
}

/**
 * Free server structure.
 */
static void
free_server(struct dl_server *server)
{
	struct dl_addr ipk;

	g_assert(dl_server_valid(server));
	g_assert(server->refcnt == 0);
	g_assert(server_list_length(server, DL_LIST_RUNNING) == 0);
	g_assert(server_list_length(server, DL_LIST_WAITING) == 0);
	g_assert(server_list_length(server, DL_LIST_STOPPED) == 0);
	g_assert(server->list[DL_LIST_RUNNING] == NULL);
	g_assert(server->list[DL_LIST_WAITING] == NULL);
	g_assert(server->list[DL_LIST_STOPPED] == NULL);

	dl_by_time_remove(server);
	g_hash_table_remove(dl_by_host, server->key);

	atom_str_free_null(&server->vendor);
	atom_guid_free_null(&server->key->guid);

	/*
	 * We only inserted the server in the `dl_addr' table if it was "reachable".
	 */

	ipk.addr = server->key->addr;
	ipk.port = server->key->port;

	if (host_is_valid(ipk.addr, ipk.port)) {
		gpointer ipkey;
		gpointer x;					/* Don't care about freeing values */

		/*
		 * Only remove server in the `dl_by_addr' table if it is the one
		 * for which the IP key is recored.  Otherwise, what can happen
		 * is that a server is detached from a download and marked for
		 * delayed removal.  Then a new one with same address is sprung
		 * to life, and inserted in `dl_by_addr'.  If we remove it now,
		 * we'll free the key of the new server.
		 */

		if (g_hash_table_lookup_extended(dl_by_addr, &ipk, &ipkey, &x)) {
			struct dl_addr *da = ipkey;
			g_assert(host_addr_initialized(da->addr));
			if (x == server) {		/* We own the key */
				g_hash_table_remove(dl_by_addr, &ipk);
				wfree(da, sizeof *da);
			}
		}
	}

	/*
	 * Get rid of the known push proxies, if any.
	 */

	if (server->proxies)
		free_proxies(server);

	atom_str_free_null(&server->hostname);

	server_list_free_all(server);

	{
		guint n = g_hash_table_size(server->sha1_counts);
		if (0 != n) {
			g_warning("server->sha1_counts contains still %u items", n);
		}
	}
	g_hash_table_destroy(server->sha1_counts);
	server->sha1_counts = NULL;

	wfree(server->key, sizeof(struct dl_key));
	server->magic = 0;
	wfree(server, sizeof *server);
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
	sl_removed_servers = g_slist_prepend(sl_removed_servers, server);
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
	sl_removed_servers = g_slist_remove(sl_removed_servers, server);
}

/**
 * Fetch server entry identified by IP:port first, then GUID+IP:port.
 *
 * @returns server, allocated if needed when allocate is TRUE.
 */
static struct dl_server *
get_server(
	const gchar *guid, const host_addr_t addr, guint16 port, gboolean allocate)
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

	server = g_hash_table_lookup(dl_by_addr, &ikey);
	if (server) {
		if (server->attrs & DLS_A_REMOVED)
			server_undelete(server);
		goto done;
	}

	key.guid = deconstify_gchar(guid);
	key.addr = addr;
	key.port = port;

	server = g_hash_table_lookup(dl_by_host, &key);
	g_assert(server == NULL || dl_server_valid(server));

	if (server && (server->attrs & DLS_A_REMOVED))
		server_undelete(server);

	/*
	 * Allocate new server if it does not exist already.
	 */

	if (NULL == server) {
		if (!allocate)
			return NULL;
		server = allocate_server(guid, addr, port);
		/* FALL THROUGH */
	}

done:
	g_assert(dl_server_valid(server));
	return server;
}

/**
 * The server address changed.
 */
static void
change_server_addr(struct dl_server *server, const host_addr_t new_addr)
{
	struct dl_key *key = server->key;
	struct dl_server *duplicate;

	g_assert(dl_server_valid(server));
	g_assert(!host_addr_equal(key->addr, new_addr));
	g_assert(host_addr_initialized(new_addr));

	g_hash_table_remove(dl_by_host, key);

	/*
	 * We only inserted the server in the `dl_addr' table if it was "reachable".
	 */

	if (host_is_valid(key->addr, key->port)) {
		struct dl_addr ipk;
		gpointer ipkey;
		gpointer x;					/* Don't care about freeing values */

		ipk.addr = key->addr;
		ipk.port = key->port;

		if (g_hash_table_lookup_extended(dl_by_addr, &ipk, &ipkey, &x)) {
			struct dl_addr *da = ipkey;
			g_assert(host_addr_initialized(da->addr));
			if (x == server) {		/* We "own" the key -- see free_server() */
				g_hash_table_remove(dl_by_addr, da);
				wfree(da, sizeof *da);
			}
		}
	}

	/*
	 * Get rid of the known push proxies, if any.
	 */

	if (server->proxies)
		free_proxies(server);

	if (download_debug) {
		gchar buf[128];

		g_strlcpy(buf, host_addr_to_string(new_addr), sizeof buf);
		g_message("server <%s> at %s:%u changed its IP from %s to %s",
			server->vendor == NULL ? "UNKNOWN" : server->vendor,
			server->hostname == NULL ? "NONAME" : server->hostname,
			key->port, host_addr_to_string(key->addr), buf);
    }

	/*
	 * Perform the IP change.
	 */

	key->addr = new_addr;
	server->country = gip_country(new_addr);

	/*
	 * Look for a duplicate.  It's quite possible that we saw some IP
	 * address 1.2.3.4 and 5.6.7.8 without knowing that they both were
	 * for the foo.example.com host.  And now we learn that the name
	 * foo.example.com which we thought was 5.6.7.8 is at 1.2.3.4...
	 */

	duplicate = get_server(key->guid, new_addr, key->port, FALSE);

	if (duplicate != NULL) {
		GSList *sl;

		g_assert(host_addr_equal(duplicate->key->addr, key->addr));
		g_assert(duplicate->key->port == key->port);
		g_assert(duplicate != server);

		if (download_debug) {
            g_message(
                "new IP %s for server <%s> at %s:%u was used by <%s> at %s:%u",
                host_addr_to_string(new_addr),
                server->vendor == NULL ? "UNKNOWN" : server->vendor,
                server->hostname == NULL ? "NONAME" : server->hostname,
                key->port,
                duplicate->vendor == NULL ? "UNKNOWN" : duplicate->vendor,
                duplicate->hostname == NULL ? "NONAME" : duplicate->hostname,
                duplicate->key->port);
        }

		/*
		 * If there was no GUID known for `server', copy the one
		 * from `duplicate'.
		 */

		if (
			guid_eq(key->guid, blank_guid) &&
			!guid_eq(duplicate->key->guid, blank_guid)
		) {
			atom_guid_free(key->guid);
			key->guid = atom_guid_get(duplicate->key->guid);
		} else if (
			!guid_eq(key->guid, duplicate->key->guid) &&
			!guid_eq(duplicate->key->guid, blank_guid)
		) {
			if (download_debug) g_warning(
				"found two distinct GUID for <%s> at %s:%u, keeping %s",
				server->vendor == NULL ? "UNKNOWN" : server->vendor,
				server->hostname == NULL ? "NONAME" : server->hostname,
				key->port, guid_hex_str(key->guid));
        }

		/*
		 * All the downloads attached to the `duplicate' server need to be
		 * reparented to `server' instead.
		 */

		for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
			struct download *d = sl->data;

			download_check(d);
			if (d->status == GTA_DL_REMOVED)
				continue;

			if (d->server == duplicate)
				download_reparent(d, server);
		}
	}

	/*
	 * We can now blindly insert `server' in the hash.  If there was a
	 * conflicting entry, all its downloads have been reparented and that
	 * server will be freed later, asynchronously.
	 */

	g_assert(server->key == key);

	g_hash_table_insert(dl_by_host, key, server);

	if (host_is_valid(key->addr, key->port)) {
		struct dl_addr *ipk;
		gpointer ipkey;
		gpointer x;					/* Don't care about freeing values */
		gboolean existed;

		ipk = walloc(sizeof *ipk);
		ipk->addr = new_addr;
		ipk->port = key->port;

		existed = g_hash_table_lookup_extended(dl_by_addr, ipk, &ipkey, &x);

		/*
		 * For the rare cases where the key already existed, we "take
		 * ownership" of the old key by associating our server entry in it.
		 * We reuse the old key, and free the new one, otherwise we'd
		 * have a memory leak because noone would free the old key!
		 */

		if (existed) {
			struct dl_addr *da = ipkey;
			g_assert(host_addr_initialized(da->addr));
			g_assert(da != ipk);
			wfree(ipk, sizeof *ipk);	/* Keep the old key around */
			g_hash_table_insert(dl_by_addr, da, server);
		} else
			g_hash_table_insert(dl_by_addr, ipk, server);
	}
}

/**
 * Set/change the server's hostname.
 */
static void
set_server_hostname(struct dl_server *server, const gchar *hostname)
{
	g_assert(dl_server_valid(server));

	if (server->hostname != NULL) {
		atom_str_free(server->hostname);
		server->hostname = NULL;
	}

	if (hostname != NULL)
		server->hostname = atom_str_get(hostname);
}

/**
 * Check whether we can safely ignore Push indication for this server,
 * identified by its GUID, IP and port.
 */
gboolean
download_server_nopush(gchar *guid, const host_addr_t addr, guint16 port)
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

/**
 * How many downloads with same filename are running (active or establishing)?
 */
static guint
count_running_downloads_with_name(const char *name)
{
	return GPOINTER_TO_UINT(g_hash_table_lookup(dl_count_by_name, name));
}

/**
 * Add one to the amount of downloads running and bearing the filename.
 */
static void
downloads_with_name_inc(const gchar *name)
{
	guint val;

	val = GPOINTER_TO_UINT(g_hash_table_lookup(dl_count_by_name, name));
	g_hash_table_insert(dl_count_by_name, deconstify_gchar(name),
		GUINT_TO_POINTER(val + 1));
}

/**
 * Remove one from the amount of downloads running and bearing the filename.
 */
static void
downloads_with_name_dec(gchar *name)
{
	guint val;

	val = GPOINTER_TO_UINT(g_hash_table_lookup(dl_count_by_name, name));

	g_assert(val);		/* Cannot decrement something not present */

	if (val > 1)
		g_hash_table_insert(dl_count_by_name, name, GUINT_TO_POINTER(val - 1));
	else
		g_hash_table_remove(dl_count_by_name, name);
}

static inline gchar *
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

static inline void
server_sha1_count_inc(struct dl_server *server, struct download *d)
{
	gchar *sha1;

	download_check(d);
	g_assert(server == d->server);

	sha1 = download_get_sha1(d);
	if (sha1) {
		gpointer value;
		guint n;

		value = g_hash_table_lookup(server->sha1_counts, sha1);
		n = GPOINTER_TO_UINT(value);
		g_assert(n < (guint) -1);
		n++;
		value = GUINT_TO_POINTER(n);
		g_hash_table_insert(server->sha1_counts, sha1, value);
	}
}

static inline void
server_sha1_count_dec(struct dl_server *server, struct download *d)
{
	gchar *sha1;

	download_check(d);
	g_assert(server == d->server);

	sha1 = download_get_sha1(d);
	if (sha1) {
		gpointer value;
		guint n;

		value = g_hash_table_lookup(server->sha1_counts, sha1);
		n = GPOINTER_TO_UINT(value);
		g_assert(n > 0);
		n--;
		if (n > 0) {
			value = GUINT_TO_POINTER(n);
			g_hash_table_insert(server->sha1_counts, sha1, value);
		} else {
			g_hash_table_remove(server->sha1_counts, sha1);
		}
	}
}


static gboolean
download_eq(gconstpointer p, gconstpointer q)
{
	const struct download *a = p, *b = q;
	const char *a_sha1, *b_sha1;

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

static struct download *
server_list_lookup(const struct dl_server *server, enum dl_list idx,
	const gchar *sha1, const gchar *file, filesize_t size)
{
	struct download *d = NULL;

	g_assert(dl_server_valid(server));
	g_assert((guint) idx < DL_LIST_SZ);		

	if (server->list[idx]) {
		static const struct download zero_key;
		struct download key = zero_key;
		gpointer orig_key;

		key.magic = DOWNLOAD_MAGIC;
		key.sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
		key.file_name = deconstify_gpointer(file);
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
	g_assert((guint) idx < DL_LIST_SZ);	

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
	g_assert((guint) idx < DL_LIST_SZ);		
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
 * running or queued download.
 *
 * @returns found active download, or NULL if we have no such download yet.
 */
static struct download *
has_same_download(
	const gchar *file, const gchar *sha1, filesize_t size, const gchar *guid,
	const host_addr_t addr, guint16 port)
{
	static const enum dl_list listnum[] = { DL_LIST_WAITING, DL_LIST_RUNNING };
	struct dl_server *server = get_server(guid, addr, port, FALSE);
	struct download *d;
	guint i;

	if (server == NULL)
		return NULL;

	g_assert(dl_server_valid(server));

	if (sha1 && NULL == g_hash_table_lookup(server->sha1_counts, sha1)) {
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
 * Mark a download as being actively queued.
 */
void
download_actively_queued(struct download *d, gboolean queued)
{
	download_check(d);

	if (queued) {
		d->status = GTA_DL_ACTIVE_QUEUED;

		if (d->flags & DL_F_ACTIVE_QUEUED)		/* Already accounted for */
			return;

		d->flags |= DL_F_ACTIVE_QUEUED;
	        d->file_info->aqueued_count ++;
	        d->file_info->dirty = TRUE;
		gnet_prop_set_guint32_val(PROP_DL_AQUEUED_COUNT, dl_aqueued_count + 1);
	} else {
		if (!(d->flags & DL_F_ACTIVE_QUEUED))	/* Already accounted for */
			return;

		gnet_prop_set_guint32_val(PROP_DL_AQUEUED_COUNT, dl_aqueued_count - 1);
		g_assert((gint) dl_aqueued_count >= 0);
		d->flags &= ~DL_F_ACTIVE_QUEUED;
		g_assert(d->file_info->aqueued_count > 0);
	        d->file_info->aqueued_count --;
	        d->file_info->dirty = TRUE;
	}
}

/**
 * Mark download as being passively queued.
 */
static void
download_passively_queued(struct download *d, gboolean queued)
{
	download_check(d);

	if (queued) {
		if (d->flags & DL_F_PASSIVE_QUEUED)		/* Already accounted for */
			return;

		d->flags |= DL_F_PASSIVE_QUEUED;
	        d->file_info->pqueued_count ++;
	        d->file_info->dirty = TRUE;
		gnet_prop_set_guint32_val(PROP_DL_PQUEUED_COUNT, dl_pqueued_count + 1);
	} else {
		if (!(d->flags & DL_F_PASSIVE_QUEUED))	/* Already accounted for */
			return;

		gnet_prop_set_guint32_val(PROP_DL_PQUEUED_COUNT, dl_pqueued_count - 1);
		g_assert((gint) dl_pqueued_count >= 0);
		d->flags &= ~DL_F_PASSIVE_QUEUED;
		g_assert(d->file_info->pqueued_count > 0);
	        d->file_info->pqueued_count --;
	        d->file_info->dirty = TRUE;
	}
}

/**
 * @returns whether the download file exists in the temporary directory.
 */
gboolean
download_file_exists(const struct download *d)
{
	gboolean ret;
	gchar *path;
	struct stat buf;

	download_check(d);

	path = make_pathname(d->file_info->path, d->file_info->file_name);
	g_return_val_if_fail(NULL != path, FALSE);

	ret = -1 != stat(path, &buf);
	G_FREE_NULL(path);

	return ret;
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
download_remove_file(struct download *d, gboolean reset)
{
	fileinfo_t *fi;
	GSList *sl;

	download_check(d);

	fi = d->file_info;
	file_info_unlink(fi);
	if (reset)
		file_info_reset(fi);

	/*
	 * Requeue all the active downloads that were referencing that file.
	 */

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *dl = sl->data;

		download_check(dl);
		if (dl->status == GTA_DL_REMOVED)
			continue;

		if (dl->file_info != fi)
			continue;

		/*
		 * An actively queued download is counted as running, but for our
		 * purposes here, it does not matter: we're not in the process of
		 * requesting the file.  Likewise for other special states that are
		 * counted as running but are harmless here.
		 *		--RAM, 17/05/2003
		 */

		switch (dl->status) {
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:		/* Will only make a new request after */
		case GTA_DL_CONNECTING:
			continue;
		default:
			break;		/* go on */
		}

		if (DOWNLOAD_IS_RUNNING(dl)) {
			download_stop(dl, GTA_DL_TIMEOUT_WAIT, no_reason);
			download_queue(dl, "Requeued due to file removal");
		}
	}
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
	GSList *sl;

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		gboolean is_running;

		download_check(d);
		if (d->status == GTA_DL_REMOVED)
			continue;

		if (d->file_info != old_fi)
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
			is_running = FALSE;
			break;
		default:
			break;
		}

		if (is_running)
			download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);

		switch (d->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ABORTED:
		case GTA_DL_ERROR:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_MOVING:
		case GTA_DL_DONE:
			break;
		default:
			g_assert(old_fi->lifecount > 0);
			old_fi->lifecount--;
			new_fi->lifecount++;
			break;
		}

		/* Below file_info_add_source() changes d->file_info. Therefore, the
		 * download must be removed from the GUI right now. */
		if (DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_remove(d);

		g_assert(old_fi->refcount > 0);
		file_info_remove_source(old_fi, d, FALSE); /* Keep it around */
		file_info_add_source(new_fi, d);

		d->flags &= ~DL_F_SUSPENDED;
		if (new_fi->flags & FI_F_SUSPEND)
			d->flags |= DL_F_SUSPENDED;

		if (is_running)
			download_queue(d, _("Requeued by file info change"));
	}
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
	gboolean file_size_known;

	download_check(d);
	
	fi = d->file_info;
	g_assert(fi);
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	if (fi->flags & FI_F_TRANSIENT)
		return;

	/*
	 * The GUI uses d->file_info internally, so the download must be
	 * removed from it before changing the d->file_info.
	 */

	if (DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_remove(d);

	downloads_with_name_dec(fi->file_name);		/* File name can change! */
	file_info_clear_download(d, TRUE);			/* `d' might be running */
	file_size_known = fi->file_size_known;		/* This should not change */

	fi->lifecount--;
	file_info_remove_source(fi, d, FALSE);		/* Keep it around for others */

	fi = file_info_get(
		d->file_name, save_file_path, d->file_size, d->sha1,
		file_size_known);
	file_info_add_source(fi, d);
	fi->lifecount++;

	d->flags &= ~DL_F_SUSPENDED;
	if (fi->flags & FI_F_SUSPEND)
		d->flags |= DL_F_SUSPENDED;

	downloads_with_name_inc(fi->file_name);
}

/**
 * Mark all downloads that point to the file_info struct as "suspended" if
 * `suspend' is TRUE, or clear that mark if FALSE.
 */
static void
queue_suspend_downloads_with_file(fileinfo_t *fi, gboolean suspend)
{
	GSList *sl;

	for (sl = sl_downloads; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
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

		if (d->file_info != fi)
			continue;

		if (suspend) {
			if (DOWNLOAD_IS_RUNNING(d))
				download_queue(d, _("Suspended (SHA1 checking)"));
			d->flags |= DL_F_SUSPENDED;		/* Can no longer be scheduled */
		} else
			d->flags &= ~DL_F_SUSPENDED;
	}

	if (suspend)
		fi->flags |= FI_F_SUSPEND;
	else
		fi->flags &= ~FI_F_SUSPEND;
}

/**
 * Removes all downloads that point to the file_info struct.
 * If `skip' is non-NULL, that download is skipped.
 */
static void
queue_remove_downloads_with_file(fileinfo_t *fi, struct download *skip)
{
	GSList *sl;
	GSList *to_remove = NULL;

	for (sl = sl_downloads; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		switch (d->status) {
		case GTA_DL_REMOVED:
		case GTA_DL_COMPLETED:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
		case GTA_DL_MOVE_WAIT:
		case GTA_DL_MOVING:
		case GTA_DL_DONE:
			continue;
		default:
			break;
		}

		if (d->file_info != fi || d == skip)
			continue;

		to_remove = g_slist_prepend(to_remove, d);
	}

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		download_remove(d);
	}

	g_slist_free(to_remove);
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
gint
download_remove_all_from_peer(gchar *guid, const host_addr_t addr, guint16 port,
	gboolean unavailable)
{
	struct dl_server *server[2];
	gint n = 0;
	enum dl_list listnum[] = { DL_LIST_RUNNING, DL_LIST_WAITING };
	GSList *to_remove = NULL;
	GSList *sl;
	gint i;
	guint j;

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
	server[1] = get_server(blank_guid, addr, port, FALSE);

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
				to_remove = g_slist_prepend(to_remove, d);
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

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		download_forget(d, unavailable);
	}

	g_slist_free(to_remove);

	return n;
}

/**
 * Remove all downloads with a given name from the download queue
 * and abort all connections to peer in the active download list.
 *
 * @returns the number of removed downloads.
 */
gint
download_remove_all_named(const gchar *name)
{
	GSList *sl;
	GSList *to_remove = NULL;
	gint n = 0;

	g_return_val_if_fail(name, 0);

	for (sl = sl_downloads; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		if (GTA_DL_REMOVED == d->status || 0 != strcmp(name, d->file_name))
			continue;

		n++;
		to_remove = g_slist_prepend(to_remove, d);
	}

	/*
	 * Abort all requested downloads, and mark their fileinfo as "discard"
	 * so that we reclaim it when the last reference is gone: if we came
	 * here, it means they are no longer interested in that file, so it's
	 * no use to keep it around for "alternate" source location matching.
	 *		--RAM, 05/11/2002
	 */

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		file_info_set_discard(d->file_info, TRUE);
		download_abort(d);
	}

	g_slist_free(to_remove);

	return n;
}

/**
 * remove all downloads with a given sha1 hash from the download queue
 * and abort all conenctions to peer in the active download list.
 *
 * @returns the number of removed downloads.
 *
 * @note
 * If sha1 is NULL, we do not clear all download with sha1==NULL but
 * abort instead.
 */
gint
download_remove_all_with_sha1(const gchar *sha1)
{
	GSList *sl;
	GSList *to_remove = NULL;
	gint n = 0;

	g_return_val_if_fail(sha1 != NULL, 0);

	for (sl = sl_downloads; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);

		if (
			GTA_DL_REMOVED == d->status ||
			NULL == d->file_info->sha1 ||
			0 != memcmp(sha1, d->file_info->sha1, SHA1_RAW_SIZE)
		)
			continue;

		n++;
		to_remove = g_slist_prepend(to_remove, d);
	}

	/*
	 * Abort all requested downloads, and mark their fileinfo as "discard"
	 * so that we reclaim it when the last reference is gone: if we came
	 * here, it means they are no longer interested in that file, so it's
	 * no use to keep it around for "alternate" source location matching.
	 *		--RAM, 05/11/2002
	 */

	for (sl = to_remove; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		file_info_set_discard(d->file_info, TRUE);
		download_abort(d);
	}

	g_slist_free(to_remove);

	return n;
}

/**
 * Change the socket RX buffer size for all the currently connected
 * downloads.
 */
void
download_set_socket_rx_size(gint rx_size)
{
	GSList *sl;

	g_assert(rx_size > 0);

	for (sl = sl_downloads; sl != NULL; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		if (d->socket != NULL)
			sock_recv_buf(d->socket, rx_size, TRUE);
	}
}

static void
download_set_sha1(struct download *d, const gchar *sha1)
{
	gchar *old_atom;

	download_check(d);

	old_atom = d->sha1;
	if (DL_LIST_INVALID != d->list_idx) {
		g_assert(d->server);
		server_sha1_count_dec(d->server, d);
	}
	d->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
	if (DL_LIST_INVALID != d->list_idx) {
		server_sha1_count_inc(d->server, d);
	}
	atom_sha1_free_null(&old_atom);
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
download_clear_stopped(gboolean complete,
	gboolean failed, gboolean unavailable, gboolean now)
{
	GSList *sl;
	time_t current_time = 0;

	if (sl_unqueued == NULL)
		return;

	if (!now)
		current_time = tm_time();

	for (sl = sl_unqueued; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		if (d->status == GTA_DL_REMOVED)
			continue;

		switch (d->status) {
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
		case GTA_DL_COMPLETED:
		case GTA_DL_DONE:
			break;
		default:
			continue;
		}

		if (
			now ||
			delta_time(current_time, d->last_update) >
				(time_delta_t) entry_removal_timeout
		) {
			if (
				complete && (
					d->status == GTA_DL_DONE ||
					d->status == GTA_DL_COMPLETED)
			) {
				download_remove(d);
			}
			else if (
				d->status == GTA_DL_ERROR ||
				d->status == GTA_DL_ABORTED
			) {
				if (
					(failed && !d->unavailable) ||
					(unavailable && d->unavailable)
				)
					download_remove(d);
			}
		}
	}

	gcu_gui_update_download_abort_resume();
	gcu_gui_update_download_clear();
}

/*
 * Downloads management
 */

/**
 * download_add_to_list
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
			g_assert(DOWNLOAD_IS_ESTABLISHING(d));
			g_assert(dl_establishing > 0);
			dl_establishing--;
		}
		downloads_with_name_dec(download_outname(d));
	} else if (idx == DL_LIST_RUNNING) {
		dl_establishing++;
		downloads_with_name_inc(download_outname(d));
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
 * Change the `retry_after' field of the host where this download runs.
 * If a non-zero `hold' is specified, make sure nothing will be scheduled
 * from this server before the next `hold' seconds.
 */
static void
download_server_retry_after(struct dl_server *server, time_t now, gint hold)
{
	struct download *d;
	time_t after;

	g_assert(dl_server_valid(server));
	g_assert(server_list_length(server, DL_LIST_WAITING) > 0);

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
	download_check(d);
	after = d->retry_after;

	/*
	 * We impose a minimum of DOWNLOAD_SERVER_HOLD seconds between retries.
	 * If we have some entries passively queued, well, we have some grace time
	 * before the entry expires.  And even if it expires, we won't loose the
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
download_reclaim_server(struct download *d, gboolean delayed)
{
	struct dl_server *server;

	download_check(d);
	g_assert(dl_server_valid(d->server));
	g_assert(d->list_idx == DL_LIST_INVALID);

	server = d->server;
	d->server = NULL;
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
download_remove_from_server(struct download *d, gboolean reclaim)
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

	download_check(d);
	g_assert(dl_server_valid(d->server));

	list_idx = d->list_idx;			/* Save index, before removal from server */
	download_remove_from_server(d, FALSE);	/* Server reclaimed later */
	download_reclaim_server(d, TRUE);		/* Delays free if empty */
	d->server = new_server;
	new_server->refcnt++;

	/*
	 * Insert download in new server, in the same list.
	 */

	d->list_idx = DL_LIST_INVALID;	/* Pre-cond. for download_add_to_list() */

	download_add_to_list(d, list_idx);
}

/**
 * Move download from a server to another when the IP:port changed due
 * to a Location: redirection for instance, or because of a QUEUE callback.
 */
void
download_redirect_to_server(struct download *d,
	const host_addr_t addr, guint16 port)
{
	struct dl_server *server;
	gchar old_guid[GUID_RAW_SIZE];
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

	memcpy(old_guid, download_guid(d), 16);
	download_remove_from_server(d, TRUE);

	/*
	 * Associate to server.
	 */

	server = get_server(old_guid, addr, port, TRUE);
	d->server = server;
	server->refcnt++;

	/*
	 * Insert download in new server, in the same list.
	 */

	/* Pre-condition for download_add_to_list() */
	d->list_idx = DL_LIST_INVALID;

	download_add_to_list(d, list_idx);
}

/**
 * Vectorized version common to download_stop() and download_unavailable().
 */
void
download_stop_v(struct download *d, download_status_t new_status,
    const gchar *reason, va_list ap)
{
	gboolean store_queue = FALSE;		/* Shall we call download_store()? */
	enum dl_list list_target;

	download_check(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(!DOWNLOAD_IS_STOPPED(d));
	g_assert(d->status != new_status);
	g_assert(d->file_info);
	g_assert(d->file_info->refcount);

	if (d->status == GTA_DL_RECEIVING) {
		g_assert(d->file_info->recvcount > 0);
		g_assert(d->file_info->recvcount <= d->file_info->refcount);
		g_assert(d->file_info->recvcount <= d->file_info->lifecount);

		/*
		 * If there is unflushed downloaded data, try to flush it now.
		 */

		if (d->buffers != NULL) {
			if (d->buffers->held > 0)
				download_flush(d, NULL, FALSE);
			buffers_free(d);
		}

		d->file_info->recvcount--;
		d->file_info->dirty_status = TRUE;

		/*
		 * Dismantle RX stack for browse host.
		 */

		if (d->flags & DL_F_BROWSE) {
			browse_host_dl_close(d->browse);
			d->bio = NULL;		/* Was a copy via browse_host_io_source() */
		}

		/*
		 * Dismantle RX stack for normal downloads.
		 */
		if (d->rx) {
			rx_disable(d->rx);
			d->bio = NULL;		/* Was a copy via rx_bio_source() */
		}
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
		g_error("unexpected new status %u !", (guint) new_status);
		return;
	}

	switch (new_status) {
	case GTA_DL_COMPLETED:
	case GTA_DL_ABORTED:
	case GTA_DL_ERROR:
		g_assert(d->file_info->lifecount <= d->file_info->refcount);
		g_assert(d->file_info->lifecount > 0);
		d->file_info->lifecount--;
		break;
	default:
		break;
	}

	if (reason && no_reason != reason) {
		gm_vsnprintf(d->error_str, sizeof(d->error_str), reason, ap);
		d->remove_msg = d->error_str;
	} else
		d->remove_msg = NULL;

	if (d->rx) {
		rx_free(d->rx);
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
			http_range_free(d->ranges);
			d->ranges = NULL;
			break;
		default:
			break;
		}
	}

	if (d->browse && new_status == GTA_DL_COMPLETED) {
		browse_host_dl_free(d->browse);
		d->browse = NULL;
	}

	if (d->list_idx != list_target)
		download_move_to_list(d, list_target);

	/* Register the new status, and update the GUI if needed */

	d->status = new_status;
	d->last_update = tm_time();

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->retries = 0;		/* If they retry, go over whole cycle again */

	if (DOWNLOAD_IS_VISIBLE(d))
		gcu_gui_update_download(d, TRUE);

	if (store_queue)
		download_dirty = TRUE;		/* Refresh list, in case we crash */

	if (DOWNLOAD_IS_STOPPED(d) && DOWNLOAD_IS_IN_PUSH_MODE(d))
		download_push_remove(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		gcu_gui_update_download_abort_resume();
		gcu_gui_update_download_clear();
	}

	file_info_clear_download(d, FALSE);
	d->flags &= ~DL_F_CHUNK_CHOSEN;

	download_actively_queued(d, FALSE);

	gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT, count_running_downloads());
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);
}

/**
 * Stop an active download, close its socket and its data file descriptor.
 */
void
download_stop(struct download *d,
	download_status_t new_status, const gchar * reason, ...)
{
	va_list args;

	download_check(d);
	d->unavailable = FALSE;

	va_start(args, reason);
	download_stop_v(d, new_status, reason, args);
	va_end(args);
}

/**
 * Like download_stop(), but flag the download as "unavailable".
 */
static void
download_unavailable(struct download *d, download_status_t new_status,
	const gchar * reason, ...)
{
	va_list args;

	download_check(d);
	d->unavailable = TRUE;

	va_start(args, reason);
	download_stop_v(d, new_status, reason, args);
	va_end(args);
}

/**
 * The vectorized (message-wise) version of download_queue().
 */
static void
download_queue_v(struct download *d, const gchar *fmt, va_list ap)
{
	download_check(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->file_info);
	g_assert(d->file_info->refcount > 0);
	g_assert(d->file_info->lifecount > 0);
	g_assert(d->file_info->lifecount <= d->file_info->refcount);
	g_assert(d->sha1 == NULL || d->file_info->sha1 == d->sha1);

	/*
	 * Put a download in the queue :
	 * - it's a new download, but we have reached the max number of
	 *	running downloads
	 * - the user requested it with the popup menu "Move back to the queue"
	 */

	if (fmt) {
		size_t len;
		gchar event[80], resched[80];

		len = gm_vsnprintf(d->error_str, sizeof d->error_str, fmt, ap);
		/* d->remove_msg updated below */

		/* Append times of event/reschedule */
		time_locale_to_string_buf(tm_time(), event, sizeof event);
		time_locale_to_string_buf(d->retry_after, resched, sizeof resched);

		gm_snprintf(&d->error_str[len], sizeof d->error_str - len,
			_(" at %s - rescheduled for %s"),
			lazy_locale_to_ui_string(event),
			lazy_locale_to_ui_string2(resched));
	}

	if (DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_remove(d);

	if (DOWNLOAD_IS_RUNNING(d))
		download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);
	else
		file_info_clear_download(d, TRUE);	/* Also done by download_stop() */

	/*
	 * Since download stop can change "d->remove_msg", update it now.
	 */

	d->remove_msg = fmt ? d->error_str: NULL;
	d->status = GTA_DL_QUEUED;

	g_assert(d->socket == NULL);

	if (d->list_idx != DL_LIST_WAITING)		/* Timeout wait is in "waiting" */
		download_move_to_list(d, DL_LIST_WAITING);

	sl_unqueued = g_slist_remove(sl_unqueued, d);

	gnet_prop_set_guint32_val(PROP_DL_QUEUE_COUNT, dl_queue_count + 1);
	if (d->flags & DL_F_REPLIED)
		gnet_prop_set_guint32_val(PROP_DL_QALIVE_COUNT, dl_qalive_count + 1);

	gcu_download_gui_add(d);
	gcu_gui_update_download(d, TRUE);
}

/**
 * Put download into queue.
 */
void
download_queue(struct download *d, const gchar *fmt, ...)
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
	queue_frozen++;
	gcu_gui_update_queue_frozen();
}

/**
 * Thaw the scheduling queue. Multiple freezing requires
 * multiple thawing.
 */
void
download_thaw_queue(void)
{
	g_return_if_fail(queue_frozen > 0);

	queue_frozen--;
	gcu_gui_update_queue_frozen();
}

/**
 * Test whether download queue is frozen.
 */
gboolean
download_queue_is_frozen(void)
{
	g_return_val_if_fail(queue_frozen >= 0, FALSE);
	return queue_frozen > 0;
}

/**
 * Common vectorized code for download_queue_delay() and download_queue_hold().
 */
static void
download_queue_hold_delay_v(struct download *d,
	gint delay, time_t hold,
	const gchar *fmt, va_list ap)
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
download_queue_delay(struct download *d, guint32 delay, const gchar *fmt, ...)
{
	va_list args;

	download_check(d);

	va_start(args, fmt);
	download_queue_hold_delay_v(d, (time_t) delay, 0, fmt, args);
	va_end(args);
}

/**
 * Same as download_queue_delay(), but make sure we don't consider
 * scheduling any currently queued download to this server before
 * the holding delay.
 */
static void
download_queue_hold(struct download *d, guint32 hold, const gchar *fmt, ...)
{
	va_list args;

	download_check(d);

	va_start(args, fmt);
	download_queue_hold_delay_v(d, (time_t) hold, (time_t) hold, fmt, args);
	va_end(args);
}

/**
 * Record that we sent a push request for this download.
 */
static void
download_push_insert(struct download *d)
{
	download_check(d);
	g_assert(!d->push);

	d->push = TRUE;
}

/**
 * Forget that we sent a push request for this download.
 */
static void
download_push_remove(struct download *d)
{
	download_check(d);
	g_assert(d->push);

	d->push = FALSE;
}

/**
 * Check whether download should be ignored, and stop it immediately if it is.
 *
 * @returns whether download was stopped (i.e. if it must be ignored).
 */
static gboolean
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

	if (is_my_address(download_addr(d), download_port(d)))
		reason = IGNORE_OURSELVES;
	else if (hostiles_check(download_addr(d)))
		reason = IGNORE_HOSTILE;

	if (reason == IGNORE_FALSE)
		reason = ignore_is_requested(fi->file_name, fi->size, fi->sha1);

	if (reason != IGNORE_FALSE) {
		const gchar *s_reason;
		
		if (!DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_add(d);

		s_reason = ignore_reason_to_string(reason);
		g_assert(s_reason);
		
		download_stop(d, GTA_DL_ERROR, "Ignoring requested (%s)", s_reason);

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
 * Remove download from queue.
 * It is put in a state where it can be stopped if necessary.
 */
static void
download_unqueue(struct download *d)
{
	download_check(d);
	g_assert(DOWNLOAD_IS_QUEUED(d));
	g_assert(dl_queue_count > 0);

	if (DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_remove(d);

	sl_unqueued = g_slist_prepend(sl_unqueued, d);
	gnet_prop_set_guint32_val(PROP_DL_QUEUE_COUNT, dl_queue_count - 1);

	if (d->flags & DL_F_REPLIED)
		gnet_prop_set_guint32_val(PROP_DL_QALIVE_COUNT, dl_qalive_count - 1);

	g_assert((gint) dl_qalive_count >= 0);

	d->status = GTA_DL_CONNECTING;		/* Allow download to be stopped */
}

/**
 * Setup the download structure with proper range offset, and check that the
 * download is not otherwise completed.
 *
 * @returns TRUE if we may continue with the download, FALSE if it has been
 * stopped due to a problem.
 */
gboolean
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

	g_assert(d->file_info);
	fi = d->file_info;

	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->list_idx == DL_LIST_RUNNING);
	g_assert(fi->lifecount > 0);

	d->status = GTA_DL_CONNECTING;	/* Most common state if we succeed */

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

	/*
	 * If the file already exists, and has less than `download_overlap_range'
	 * bytes, we restart the download from scratch.	Otherwise, we request
	 * that amount before the resuming point.
	 * Later on, in download_write_data(), and as soon as we have read more
	 * than `download_overlap_range' bytes, we'll check for a match.
	 *		--RAM, 12/01/2002
	 */

	d->skip = 0;			/* We're setting it here only if not swarming */
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
	 */

	if (!fi->use_swarming) {
		if (fi->done > download_overlap_range)
			d->skip = fi->done;		/* Not swarming => file has no holes */
		d->pos = d->skip;
		d->overlap_size = (d->skip == 0 || d->size <= d->pos) ?
			0 : download_overlap_range;

		g_assert(d->overlap_size == 0 || d->skip > d->overlap_size);
	}

	d->last_update = tm_time();

	/*
	 * Is there anything to get at all?
	 */

	if (FILE_INFO_COMPLETE(fi)) {
		if (!DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_add(d);
		download_stop(d, GTA_DL_ERROR, "Nothing more to get");
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
gboolean
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
		download_unqueue(d);

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
 * Called for swarming downloads when we are connected to the remote server,
 * but before making the request, to pick up a chunk for downloading.
 *
 * @returns TRUE if we can continue with the download, FALSE if it has
 * been stopped.
 */
static gboolean
download_pick_chunk(struct download *d)
{
	enum dl_chunk_status status;
	filesize_t from, to;

	download_check(d);
	g_assert(d->file_info->use_swarming);

	d->overlap_size = 0;
	d->last_update = tm_time();

	status = file_info_find_hole(d, &from, &to);

	switch (status) {
	case DL_CHUNK_EMPTY:
		d->skip = d->pos = from;
		d->size = to - from;

		if (
			from > download_overlap_range &&
			file_info_chunk_status(d->file_info,
				from - download_overlap_range, from) == DL_CHUNK_DONE
		)
			d->overlap_size = download_overlap_range;
		break;
	case DL_CHUNK_BUSY:
		download_queue_delay(d, 10, _("Waiting for a free chunk"));
		return FALSE;
	case DL_CHUNK_DONE:
		if (!DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_add(d);

		download_stop(d, GTA_DL_ERROR, "No more gaps to fill");
		queue_remove_downloads_with_file(d->file_info, d);
		return FALSE;
	}

	g_assert(d->overlap_size == 0 || d->skip > d->overlap_size);

	return TRUE;
}

/**
 * Pickup a range we don't have yet from the available ranges.
 *
 * @returns TRUE if we selected a chunk, FALSE if we can't select a chunk
 * (e.g. we have everything the remote server makes available).
 */
static gboolean
download_pick_available(struct download *d)
{
	filesize_t from, to;

	download_check(d);
	g_assert(d->ranges != NULL);

	d->overlap_size = 0;
	d->last_update = tm_time();

	if (!file_info_find_available_hole(d, d->ranges, &from, &to)) {
		if (download_debug > 3)
			g_message("PFSP no interesting chunks from %s for \"%s\", "
				"available was: %s",
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_outname(d), http_range_to_string(d->ranges));

		return FALSE;
	}

	/*
	 * We found a chunk that the remote end has and which we miss.
	 */

	d->skip = d->pos = from;
	d->size = to - from;

	/*
	 * Maybe we can do some overlapping check if the remote server has
	 * some data before that chunk and we also have the corresponding
	 * range.
	 */

	if (
		from > download_overlap_range &&
		file_info_chunk_status(d->file_info,
			from - download_overlap_range, from) == DL_CHUNK_DONE &&
		http_range_contains(d->ranges, from - download_overlap_range, from - 1)
	)
		d->overlap_size = download_overlap_range;

	if (download_debug > 3)
		g_message("PFSP selected %s-%s (overlap=%u) "
			"from %s for \"%s\", available was: %s",
			uint64_to_string(from), uint64_to_string2(to - 1), d->overlap_size,
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_outname(d), http_range_to_string(d->ranges));

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
	guint16 port;

	download_check(d);

	server = d->server;
	g_assert(dl_server_valid(server));

	port = download_port(d);

	d->flags &= ~DL_F_DNS_LOOKUP;

	/*
	 * If there is a fully qualified domain name, look it up for possible
	 * change if either sufficient time passed since last lookup, or if the
	 * DLS_A_DNS_LOOKUP attribute was set because of a connection failure.
	 */

	if (
		(server->attrs & DLS_A_DNS_LOOKUP) ||
		(server->hostname != NULL &&
			delta_time(tm_time(), server->dns_lookup) > DOWNLOAD_DNS_LOOKUP)
	) {
		g_assert(server->hostname != NULL);

		d->flags |= DL_F_DNS_LOOKUP;
		server->attrs &= ~DLS_A_DNS_LOOKUP;
		server->dns_lookup = tm_time();
		return socket_connect_by_name(
			server->hostname, port, SOCK_TYPE_DOWNLOAD, d->cflags);
	} else
		return socket_connect(download_addr(d), port, SOCK_TYPE_DOWNLOAD,
				d->cflags);
}

/**
 * (Re)start a stopped or queued download.
 */
void
download_start(struct download *d, gboolean check_allowed)
{
	host_addr_t addr;
	guint16 port;

	download_check(d);
	g_return_if_fail(d->list_idx != DL_LIST_RUNNING);	/* Waiting or stopped */
	g_return_if_fail(d->file_info);
	g_return_if_fail(d->file_info->refcount > 0);
	g_return_if_fail(d->file_info->lifecount > 0);
	g_return_if_fail(d->file_info->lifecount <= d->file_info->refcount);
	g_return_if_fail(d->sha1 == NULL || d->file_info->sha1 == d->sha1);

	addr = download_addr(d);
	port = download_port(d);

	/*
	 * If caller did not check whether we were allowed to start downloading
	 * this file, do it now. --RAM, 03/09/2001
	 */

	if (check_allowed && (
		count_running_downloads() >= max_downloads ||
		count_running_on_server(d->server) >= max_host_downloads ||
		(!d->file_info->use_swarming &&
			count_running_downloads_with_name(download_outname(d)) != 0))
	) {
		if (!DOWNLOAD_IS_QUEUED(d))
			download_queue(d, _("No download slot (start)"));
		return;
	}

	if (!download_start_prepare(d))
		return;

	g_assert(d->list_idx == DL_LIST_RUNNING);	/* Moved to "running" list */
	g_assert(d->file_info->refcount > 0);		/* Still alive */
	g_assert(d->file_info->lifecount > 0);
	g_assert(d->file_info->lifecount <= d->file_info->refcount);

	if ((is_firewalled || !send_pushes) && d->push)
		download_push_remove(d);

	/*
	 * If server is known to be reachable without pushes, reset the flag.
	 */

	if (d->always_push && (d->server->attrs & DLS_A_PUSH_IGN)) {
		g_assert(host_is_valid(addr, port));	/* Or would not have set flag */
		if (d->push)
			download_push_remove(d);
		d->always_push = FALSE;
	}

	if (!DOWNLOAD_IS_IN_PUSH_MODE(d) && host_is_valid(addr, port)) {
		/* Direct download */
		d->status = GTA_DL_CONNECTING;
		d->socket = download_connect(d);

		if (!DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_add(d);

		if (!d->socket) {
			/*
			 * If we ran out of file descriptors, requeue this download.
			 * We don't want to loose the source.  We can't be sure, but
			 * if we see a banned_count of 0 and file_descriptor_runout set,
			 * then the lack of connection is probably due to a lack of
			 * descriptors.
			 *		--RAM, 2004-06-21
			 */

			if (file_descriptor_runout && banned_count == 0) {
				download_queue_delay(d, download_retry_busy_delay,
					_("Connection failed (Out of file descriptors?)"));
				return;
			}

			/*
			 * If DNS lookup was attempted, and we fail immediately, it
			 * means either the address returned by the DNS was invalid or
			 * there was no successful (synchronous) resolution for this
			 * host.
			 */

			if (d->flags & DL_F_DNS_LOOKUP) {
				atom_str_free(d->server->hostname);
				d->server->hostname = NULL;
				gcu_gui_update_download_host(d);
			}

			download_unavailable(d, GTA_DL_ERROR, "Connection failed");
			return;
		}

		d->socket->resource.download = d;
		d->socket->pos = 0;
	} else {					/* We have to send a push request */
		d->status = GTA_DL_PUSH_SENT;

		g_assert(d->socket == NULL);

		if (!DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_add(d);

		download_push(d, FALSE);
	}

	gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT, count_running_downloads());

	gcu_gui_update_download(d, TRUE);
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);
}

/**
 * Pick up new downloads from the queue as needed.
 */
void
download_pickup_queued(void)
{
	time_t now = tm_time();
	guint running = count_running_downloads();
	guint i;

	/*
	 * To select downloads, we iterate over the sorted `dl_by_time' list and
	 * look for something we could schedule.
	 *
	 * Note that we jump from one host to the other, even if we have multiple
	 * things to schedule on the same host: It's better to spread load among
	 * all hosts first.
	 */

	for (
		i = 0;
		i < DHASH_SIZE && running < max_downloads &&
			bws_can_connect(SOCK_TYPE_DOWNLOAD);
		i++
	) {
		GList *l;
		gint last_change;

	retry:
		l = dl_by_time.servers[i];
		last_change = dl_by_time.change[i];

		for (/* empty */; l && running < max_downloads; l = g_list_next(l)) {
			struct dl_server *server = l->data;
			list_iter_t *iter;
			struct download *d;
			gboolean found;

			g_assert(dl_server_valid(server));

			/*
			 * List is sorted, so as soon as we go beyond the current time,
			 * we can stop.
			 */

			if (delta_time(now, server->retry_after) < 0)
				break;

			if (
				server_list_length(server, DL_LIST_WAITING) == 0 ||
				count_running_on_server(server) >= max_host_downloads
			)
				continue;

			/*
			 * OK, pick the download at the start of the waiting list, but
			 * do not remove it yet.  This will be done by download_start().
			 */

			g_assert(server->list[DL_LIST_WAITING]);	/* Since count != 0 */

			found = FALSE;
			d = NULL;
			iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
			while (list_iter_has_next(iter)) {

				d = list_iter_next(iter);
				download_check(d);

				if (
					!d->file_info->use_swarming &&
					count_running_downloads_with_name(download_outname(d)) != 0
				)
					continue;

				if (
					delta_time(now, d->last_update) <=
						(time_delta_t) d->timeout_delay
				)
					continue;

				if (delta_time(now, d->retry_after) < 0)
					break;	/* List is sorted */

				if (d->flags & DL_F_SUSPENDED)
					continue;

				found = TRUE;
				break;		/* Don't schedule all files on same host at once */
			}
			list_iter_free(&iter);

			if (found) {
				download_start(d, FALSE);
				if (DOWNLOAD_IS_RUNNING(d))
					running++;
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

	gcu_download_enable_start_now(running, max_downloads);
}

static void
download_push(struct download *d, gboolean on_timeout)
{
	gboolean ignore_push = FALSE;

	download_check(d);

	if (
		(d->flags & DL_F_PUSH_IGN) ||
		(d->server->attrs & DLS_A_PUSH_IGN) ||
		has_blank_guid(d)
	)
		ignore_push = TRUE;

	if (is_firewalled || !send_pushes || ignore_push) {
		if (d->push)
			download_push_remove(d);
		goto attempt_retry;
	}

	/*
	 * The push request is sent with the listening port set to our Gnet port.
	 *
	 * To be able to later distinguish which download is referred to by each
	 * GIV we'll receive back, we record the association file_index/guid of
	 * the to-be-downloaded file with this download into a hash table.
	 * When stopping a download for which d->push is true, we'll have to
	 * remove the mapping.
	 *
	 *		--RAM, 30/12/2001
	 */

	if (!d->push)
		download_push_insert(d);

	g_assert(d->push);

	/*
	 * Before sending a push on Gnet, look whether we have some push-proxies
	 * available for the server.
	 *		--RAM, 18/07/2003
	 */

	if (use_push_proxy(d))
		return;

	if (0 == socket_listen_port())
		return;

	if (send_push_request(download_guid(d), d->record_index, listen_port))
		return;

	if (!d->always_push) {
		download_push_remove(d);
		goto attempt_retry;
	} else {
		/*
		 * If the address is not a private IP, it is possible that the
		 * servent set the "Push" flag incorrectly.
		 *		-- RAM, 18/08/2002.
		 */

		if (!host_is_valid(download_addr(d), download_port(d))) {
			download_unavailable(d, GTA_DL_ERROR, "Push route lost");
			download_remove_all_from_peer(
				download_guid(d), download_addr(d), download_port(d), TRUE);
		} else {
			/*
			 * Later on, if we manage to connect to the server, we'll
			 * make sure to mark it so that we ignore pushes to it, and
			 * we will clear the `always_push' indication.
			 * (see download_send_request() for more information)
			 */

			download_push_remove(d);

			if (download_debug > 2)
				g_message("PUSH trying to ignore them for %s",
					host_addr_port_to_string(download_addr(d),
					download_port(d)));

			d->flags |= DL_F_PUSH_IGN;
			download_queue(d, _("Ignoring Push flag"));
		}
	}

	return;

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
		if (on_timeout || d->retries > 5) {
			/*
			 * Looks like we won't be able to ever reach this host.
			 * Abort the download, and remove all the ones for the same host.
			 */

			download_unavailable(d, GTA_DL_ERROR,
				"Can't reach host (Push or Direct)");
			download_remove_all_from_peer(
				download_guid(d), download_addr(d), download_port(d), TRUE);
		} else
			download_queue_hold(d, download_retry_refused_delay,
				NG_("No direct connection yet (%u retry)",
					"No direct connection yet (%u retries)", d->retries),
					 d->retries);
	} else if (d->retries < download_max_retries) {
		d->retries++;
		if (on_timeout)
			download_queue_hold(d, download_retry_timeout_delay,
				NG_("Timeout (%u retry)",
					"Timeout (%u retries)", d->retries), d->retries);
		else
			download_queue_hold(d, download_retry_refused_delay,
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
 */
void
download_fallback_to_push(struct download *d,
	gboolean on_timeout, gboolean user_request)
{
	g_return_if_fail(d);
	download_check(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning(
			"BUG: download_fallback_to_push() called on a queued download!?!");
		return;
	}

	/* If we're receiving data or already sent push, we're wrong
	 * here. Most likely it was unnecessarily requested by the user.
	 */
	if (DOWNLOAD_IS_ACTIVE(d) || DOWNLOAD_IS_EXPECTING_GIV(d))
		return;

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	if (!d->socket) {
		g_warning("download_fallback_to_push(): no socket for '%s'",
			download_outname(d));
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

		if (socket_bad_hostname(d->socket) && d->server->hostname != NULL) {
			g_warning("hostname \"%s\" for %s could not resolve, discarding",
				d->server->hostname,
				host_addr_port_to_string(download_addr(d), download_port(d)));
			atom_str_free(d->server->hostname);
			d->server->hostname = NULL;
			gcu_gui_update_download_host(d);
		}

		/*
		 * If we could not connect to the host, but we have a hostname and
		 * we did not perform a DNS lookup this time, request one for the
		 * next attempt.
		 */

		if (d->server->hostname != NULL && !(d->flags & DL_F_DNS_LOOKUP))
			d->server->attrs |= DLS_A_DNS_LOOKUP;

		socket_free_null(&d->socket);
	}

	file_object_release(&d->out_file);

	if (user_request)
		d->status = GTA_DL_PUSH_SENT;
	else
		d->status = GTA_DL_FALLBACK;

	d->last_update = tm_time();		/* Reset timeout if we send the push */
	download_push(d, on_timeout);

	gcu_gui_update_download(d, TRUE);
}

static gchar *
download_escape_name(const gchar *name)
{
	gchar *escaped, *atom;
		
	escaped = url_escape_cntrl(deconstify_gchar(name));
	atom = atom_str_get(escaped);
	if (name != escaped) {
		G_FREE_NULL(escaped);
	}
	return atom;
}

/*
 * Downloads creation and destruction
 */

/**
 * Create a new download.
 *
 * When `interactive' is false, we assume that `file' was already duped,
 * and take ownership of the pointer.
 *
 * @attention
 * NB: If `record_index' == URN_INDEX, and a `sha1' is also supplied, then
 * this is our convention for expressing a /uri-res/N2R? download URL.
 * However, we don't forbid 0 as a valid record index if it does not
 * have a SHA1.
 *
 * @returns created download structure, or NULL if none.
 */
static struct download *
create_download(const gchar *file, const gchar *uri, filesize_t size,
	guint32 record_index,
	const host_addr_t addr, guint16 port, const gchar *guid,
	const gchar *hostname, const gchar *sha1, time_t stamp,
	gboolean interactive, gboolean file_size_known,
	fileinfo_t *file_info, const gnet_host_vec_t *proxies, guint32 cflags)
{
	struct dl_server *server;
	struct download *d;
	gchar *file_name;
	gchar *file_uri = NULL;
	fileinfo_t *fi;

	g_assert(size == 0 || file_size_known);
	g_assert(host_addr_initialized(addr));

	if (!file_size_known) {
		size = 0;
		/* Value should be updated later when known by HTTP headers */
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

	if (host_addr_equal(addr, listen_addr()) && port == listen_port) {
		if (download_debug)
			g_warning("create_download(): ignoring download from own address");

		return NULL;
	}

	if (interactive) {
		gchar *s;
		
		s = gm_sanitize_filename(file, FALSE, FALSE);
		
		/* An empty filename would create a corrupt download entry */
    	file_name = atom_str_get('\0' != s[0] ? s : "noname");

		if (file != s)
			G_FREE_NULL(s);
	} else {
    	file_name = deconstify_gchar(file);
	}


    if (uri) {
	    file_uri = atom_str_get(uri);
	}

	/*
	 * Create server if none exists already.
	 */

	server = get_server(guid, addr, port, TRUE);

	g_assert(dl_server_valid(server));

	/*
	 * If some push proxies are given, and provided the `stamp' argument
	 * is recent enough, drop the existing list and replace it with the
	 * one coming from the query hit.
	 */

	if (proxies != NULL && delta_time(stamp, server->proxies_stamp) > 0) {
		if (server->proxies)
			free_proxies(server);
		server->proxies = hostvec_to_slist(proxies);
		server->proxies_stamp = stamp;
	}

	/*
	 * Refuse to queue the same download twice. --RAM, 04/11/2001
	 */

	d = has_same_download(file_name, sha1, size, guid, addr, port);
	if (d) {
		download_check(d);
		if (interactive)
			g_message("rejecting duplicate download for %s", file_name);
		atom_str_free(file_name);
		return NULL;
	}

	/*
	 * Initialize download.
	 */

	d = download_alloc();

	d->src_handle = idtable_new_id(src_handle_map, d);
	d->server = server;
	server->refcnt++;
	d->list_idx = DL_LIST_INVALID;
	d->cflags = cflags;

	/*
	 * If we know that this server can be directly connected to, ignore
	 * the push flag. --RAM, 18/08/2002.
	 */

	if (d->server->attrs & DLS_A_PUSH_IGN) {
		cflags &= ~SOCK_F_PUSH;
	}

	d->file_name = file_name;
	d->escaped_name = download_escape_name(file_name);
	d->uri = file_uri;
	d->file_size = size;

	/*
	 * Note: size and skip will be filled by download_pick_chunk() later
	 * if we use swarming.
	 */
	d->size = size;					/* Will be changed if range requested */
	d->record_stamp = stamp;
	download_set_sha1(d, sha1);
	d->always_push = 0 != (SOCK_F_PUSH & cflags);
	if (d->always_push) {
		download_push_insert(d);
	} else {
		d->push = FALSE;
	}
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

	fi = file_info == NULL ?
		file_info_get(file_name, save_file_path, size, sha1, file_size_known)
		: file_info;

	if (fi->flags & FI_F_SUSPEND)
		d->flags |= DL_F_SUSPENDED;

	fi->lifecount++;
	if (stamp == MAGIC_TIME)			/* Download recreated at startup */
		file_info_add_source(fi, d);	/* Preserve original "ntime" */
	else
		file_info_add_new_source(fi, d);

	sl_downloads = g_slist_prepend(sl_downloads, d);
	sl_unqueued = g_slist_prepend(sl_unqueued, d);

	download_dirty = TRUE;			/* Refresh list, in case we crash */

	/*
	 * Record server's hostname if non-NULL and not empty.
	 */

	if (hostname != NULL && *hostname != '\0')
		set_server_hostname(d->server, hostname);

	/*
	 * Insert in download mesh if it does not require a push and has a SHA1.
	 */

	if (!d->always_push && d->sha1 && !d->uri)
		dmesh_add(d->sha1, addr, port, record_index, file_name, stamp);

	/*
	 * When we know our SHA1, if we don't have a SHA1 in the `fi' and we
	 * looked for it, it means that they didn't have "strict_sha1_matching"
	 * at some point in time.
	 *
	 * If we have a SHA1, it must match.
	 */

	if (d->sha1 != NULL && fi->sha1 == NULL) {
		gboolean success = file_info_got_sha1(fi, d->sha1);
		if (success) {
            g_message("forced SHA1 %s after %s byte%s "
				"downloaded for %s",
				sha1_base32(d->sha1), uint64_to_string(fi->done),
				fi->done == 1 ? "" : "s",
				download_outname(d));
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

	if (d->flags & DL_F_SUSPENDED)
		download_queue(d, _("Suspended (SHA1 checking)"));
	else if (
		count_running_downloads() < max_downloads &&
		count_running_on_server(d->server) < max_host_downloads &&
		(d->file_info->use_swarming ||
			count_running_downloads_with_name(download_outname(d)) == 0)
	) {
		download_start(d, FALSE);		/* Start the download immediately */
	} else {
		/* Max number of downloads reached, we have to queue it */
		/* Ensure it has a time for status display */
		d->retry_after = tm_time();
		download_queue(d, _("No download slot (create)"));
	}

	return d;
}

/**
 * Automatic download request.
 */
void
download_auto_new(const gchar *file, filesize_t size, guint32 record_index,
	const host_addr_t addr, guint16 port, const gchar *guid,
	const gchar *hostname, const gchar *sha1, time_t stamp,
	gboolean file_size_known, fileinfo_t *fi,
	gnet_host_vec_t *proxies, guint32 flags)
{
	gchar *file_name;
	const char *reason;
	enum ignore_val ign_reason;

	/*
	 * Make sure host is reacheable, especially if we come from the GUI,
	 * which cannot access the bogus IP database.
	 */

	if (0 == (SOCK_F_PUSH & flags) && !host_is_valid(addr, port)) {
		flags |= SOCK_F_PUSH;
		if (guid_eq(guid, blank_guid))
			return;
	}

	/*
	 * Make sure we're not prevented from downloading that file.
	 */

	ign_reason = ignore_is_requested(
		fi ? fi->file_name : file,
		fi ? fi->size : size,
		fi ? fi->sha1 : sha1);

	if (IGNORE_FALSE != ign_reason) {
		reason = ignore_reason_to_string(ign_reason);
		if (!reason) {
			g_error("ignore_is_requested() returned unexpected %u",
					(guint) ign_reason);
		}
		goto abort_download;
	}

	/*
	 * Create download.
	 */

	file_name = atom_str_get(file);

	create_download(file_name, NULL, size, record_index, addr, port,
		guid, hostname, sha1, stamp, FALSE, file_size_known, fi,
		proxies, flags);

	return;

abort_download:
	if (download_debug > 4)
		g_message("ignoring auto download for \"%s\": %s", file, reason);
	return;
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

	download_check(d);
	g_assert(!(d->flags & (DL_F_ACTIVE_QUEUED|DL_F_PASSIVE_QUEUED)));
	g_assert(d->buffers != NULL);
	g_assert(d->buffers->held == 0);		/* All data flushed */

	fi = d->file_info;

	cd = download_alloc();
	*cd = *d;						/* Struct copy */
	cd->src_handle = idtable_new_id(src_handle_map, cd); /* new handle */
	cd->file_info = NULL;			/* has not been added to fi sources list */
	cd->visible = FALSE;
	file_info_add_source(fi, cd);	/* add cloned source */

	g_assert(d->io_opaque == NULL);		/* If cloned, we were receiving! */

	cd->rx = NULL;
	cd->bio = NULL;						/* Recreated on each transfer */
	cd->out_file = NULL;				/* File re-opened each time */
	cd->socket->resource.download = cd;	/* Takes ownership of socket */
	cd->file_info->lifecount++;			/* Both are still "alive" for now */
	cd->list_idx = DL_LIST_INVALID;
	cd->file_name = atom_str_get(d->file_name);
	cd->escaped_name = atom_str_get(d->escaped_name);
	cd->push = FALSE;
	cd->status = GTA_DL_CONNECTING;
	cd->server->refcnt++;

	download_add_to_list(cd, DL_LIST_WAITING);

	sl_downloads = g_slist_prepend(sl_downloads, cd);
	sl_unqueued = g_slist_prepend(sl_unqueued, cd);

	if (d->push) {
		download_push_remove(d);
		download_push_insert(cd);
	}

	if (d->queue_status != NULL)
		parq_dl_reparent_id(d, cd);

	if (d->cproxy != NULL)
		cproxy_reparent(d, cd);

	g_assert(d->queue_status == NULL);	/* Cleared by parq_dl_reparent_id() */

	/*
	 * The following copied data are cleared in the child.
	 */

	cd->buffers = NULL;		/* Allocated at each new request */

	/*
	 * The following have been copied and appropriated by the cloned download.
	 * They are reset so that a download_free() on the original will not
	 * free them.
	 */

#if 0
	/* FIXME: This is probably incorrect because d->file_info still
	 * exists and download_get_sha1() looks at d->file_info->sha1 too.
	 * At least commenting this out fixed crash-on-purging-a-finished-file.
	 */
	if (DL_LIST_INVALID != d->list_idx) {
		server_sha1_count_dec(d->server, d);
	}
#endif

	d->sha1 = NULL;
	d->socket = NULL;
	d->ranges = NULL;

	return cd;
}

/**
 * Search has detected index change in queued download.
 */
void
download_index_changed(const host_addr_t addr, guint16 port, gchar *guid,
	guint32 from, guint32 to)
{
	struct dl_server *server = get_server(guid, addr, port, FALSE);
	guint nfound = 0;
	GSList *to_stop = NULL;
	GSList *sl;
	guint n;
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
				 * restart it in a while.  Sure, we might loose the download
				 * slot, but we might as well have gotten a wrong file.
				 *
				 * NB: this can't happen when the remote peer is gtk-gnutella
				 * since we check the matching between the index and the file
				 * name, but some peers might not bother.
				 */
				g_message("stopping request for \"%s\": index changed",
					download_outname(d));
				to_stop = g_slist_prepend(to_stop, d);
				break;
			case GTA_DL_RECEIVING:
				/*
				 * Ouch.  Pray and hope that the change occurred after we
				 * requested the file.	There's nothing we can do now.
				 */
				g_message("index of \"%s\" changed during reception",
					download_outname(d));
				break;
			default:
				/*
				 * Queued or other state not needing special notice
				 */
				if (download_debug > 3) {
					g_message("noted index change "
						"from %u to %u at %s for \"%s\"",
						from, to, guid_hex_str(guid), download_outname(d));
                }
				break;
			}
		}
		list_iter_free(&iter);
	}

	for (sl = to_stop; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		download_check(d);
		download_queue_delay(d, download_retry_stopped_delay,
			_("Stopped (Index changed)"));
	}
	g_slist_free(to_stop);
	to_stop = NULL;

	/*
	 * This is a sanity check: we should not have any duplicate request
	 * in our download list.
	 */

	if (nfound > 1) {
		g_message("found %u requests for index %u (now %u) at %s",
			nfound, (guint) from, (guint) to,
			host_addr_port_to_string(addr, port));
    }
}

struct download_request {
	host_addr_t addr;
	const gchar *guid;
	gchar *hostname;
	gchar *file;
	gchar *sha1;
	gchar *uri;
	fileinfo_t *fi;
	filesize_t size;
	time_t stamp;
	guint32 flags;
	guint32 record_index;
	guint16 port;
};

static void
download_request_free(struct download_request **req_ptr)
{
	struct download_request *req;
	
	g_assert(req_ptr);

	req = *req_ptr;
	g_assert(req);

	*req_ptr = NULL;
	if (req->uri) {
		atom_str_free(req->uri);
	}
	if (req->sha1) {
		atom_sha1_free(req->sha1);
	}
	atom_str_free(req->hostname);
	atom_str_free(req->file);
	atom_guid_free(req->guid);
	wfree(req, sizeof *req);
}

/**
 * Called when we got a reply from the ADNS process.
 */
static void
download_new_by_hostname_helper(const host_addr_t *addrs, size_t n,
	gpointer user_data)
{
	struct download_request *req = user_data;

	g_assert(addrs);
	g_assert(req);

	if (n > 0) {
		size_t i = random_raw() % n;

		/**
		 * @todo TODO: All resolved addresses should be attempted.
		 */
		create_download(req->file, req->uri, req->size,
			req->record_index, addrs[i],
			req->port, req->guid, req->hostname, req->sha1, req->stamp,
			TRUE, 0 != req->size, req->fi, NULL, req->flags);
	}
	download_request_free(&req);
}

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
gboolean
download_new(const gchar *file, filesize_t size, guint32 record_index,
	const host_addr_t addr, guint16 port, const gchar *guid,
	gchar *hostname, gchar *sha1, time_t stamp,
	fileinfo_t *fi, gnet_host_vec_t *proxies, guint32 flags)
{
	if (hostname) {
		static struct download_request zero_req;
		struct download_request *req;

		req = walloc(sizeof *req);
		*req = zero_req;

		req->file = atom_str_get(file);
		req->size = size;
		req->record_index = record_index;
		req->addr = addr;
		req->port = port;
		req->guid = atom_guid_get(guid);
		req->hostname = atom_str_get(hostname);
		req->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
		req->stamp = stamp;
		req->fi = fi;	/* XXX: Increase ref counter or what? */
		req->flags = flags;

		/*
		 * Ignore proxies because they might be freed before the hostname
		 * has been resolved.
		 */

		download_new_by_hostname(req);
		return TRUE;
	}
	return NULL != create_download(file, NULL, size, record_index, addr,
					port, guid, hostname, sha1, stamp, TRUE,
					0 != size, fi, proxies, flags);
}

/**
 * Create a new download whose total size is unknown.
 */
gboolean
download_new_unknown_size(const gchar *file, guint32 record_index,
	const host_addr_t addr, guint16 port, const gchar *guid, gchar *hostname,
	gchar *sha1, time_t stamp,
	fileinfo_t *fi, gnet_host_vec_t *proxies, guint32 flags)
{
	return NULL != create_download(file, NULL, 0, record_index, addr, port,
						guid, hostname, sha1, stamp, TRUE, FALSE, fi,
						proxies, flags);
}

gboolean
download_new_uri(const gchar *file, const gchar *uri, filesize_t size,
	  const host_addr_t addr, guint16 port, const gchar *guid, gchar *hostname,
	  gchar *sha1, time_t stamp,
	  fileinfo_t *fi, gnet_host_vec_t *proxies, guint32 flags)
{
	if (hostname) {
		static struct download_request zero_req;
		struct download_request *req;

		req = walloc(sizeof *req);
		*req = zero_req;

		req->file = atom_str_get(file);
		req->uri = atom_str_get(uri);
		req->size = size;
		req->addr = addr;
		req->port = port;
		req->guid = atom_guid_get(guid);
		req->hostname = atom_str_get(hostname);
		req->sha1 = sha1 ? atom_sha1_get(sha1) : NULL;
		req->stamp = stamp;
		req->fi = fi;	/* XXX: Increase ref counter or what? */
		req->flags = flags;

		/*
		 * Ignore proxies because they might be freed before the hostname
		 * has been resolved.
		 */

		download_new_by_hostname(req);
		return TRUE;
	}
	return NULL != create_download(file, uri, size, 0, addr, port,
						guid, hostname, sha1, stamp, TRUE,
						size != 0 ? TRUE : FALSE, fi, proxies, flags);
}

/**
 * Fake a new download for an existing file that is marked complete in
 * its fileinfo trailer.
 */
void
download_orphan_new(
	gchar *file, filesize_t size, gchar *sha1, fileinfo_t *fi)
{
	time_t ntime = fi->ntime;
	(void) create_download(file,
			NULL,	/* uri */
		   	size,
			0,		/* record_index */
			ipv4_unspecified,	/* for host_addr_initialized() */
			0,		/* port */
			blank_guid,
			NULL,	/* hostname*/
			sha1,
			tm_time(),
			TRUE,	/* interactive */
			TRUE,	/* file_size_known */
			fi,
			NULL,	/* proxies */
			0);		/* cflags */
	fi->ntime = ntime;
}

/**
 * Free all downloads listed in the `sl_removed' list.
 */
void
download_free_removed(void)
{
	GSList *sl;

	if (sl_removed == NULL)
		return;

	for (sl = sl_removed; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		g_assert(d->status == GTA_DL_REMOVED);

		download_reclaim_server(d, TRUE);	/* Delays freeing of server */

		sl_downloads = g_slist_remove(sl_downloads, d);
		sl_unqueued = g_slist_remove(sl_unqueued, d);

		download_free(&d);
	}

	g_slist_free(sl_removed);
	sl_removed = NULL;

	for (sl = sl_removed_servers; sl; sl = g_slist_next(sl)) {
		struct dl_server *s = sl->data;
		free_server(s);
	}

	g_slist_free(sl_removed_servers);
	sl_removed_servers = NULL;
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
gboolean
download_remove(struct download *d)
{
	download_check(d);
	g_assert(d->status != GTA_DL_REMOVED);		/* Not already freed */

	/*
	 * Make sure download is not used by a background task
	 * 		-- JA 25/10/2003
	 */
	if (d->status == GTA_DL_VERIFY_WAIT || d->status == GTA_DL_VERIFYING)
		return FALSE;

	if (DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_remove(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_assert(dl_queue_count > 0);

		gnet_prop_set_guint32_val(PROP_DL_QUEUE_COUNT, dl_queue_count - 1);
		if (d->flags & DL_F_REPLIED)
			gnet_prop_set_guint32_val(PROP_DL_QALIVE_COUNT, dl_qalive_count - 1);

		g_assert((gint) dl_qalive_count >= 0);
	}

	/*
	 * Abort running download (which will decrement the lifecount), otherwise
	 * make sure we decrement it here (e.g. if the download was queued).
	 */

	if (DOWNLOAD_IS_RUNNING(d))
		download_stop(d, GTA_DL_ABORTED, no_reason);
	else if (DOWNLOAD_IS_STOPPED(d))
		/* nothing, lifecount already decremented */;
	else {
		g_assert(d->file_info->lifecount > 0);
		d->file_info->lifecount--;
	}

	g_assert(d->io_opaque == NULL);
	g_assert(d->buffers == NULL);

	if (d->browse != NULL) {
		g_assert(d->flags & DL_F_BROWSE);
		browse_host_dl_free(d->browse);
		d->browse = NULL;
	}

	if (d->push)
		download_push_remove(d);

	download_set_sha1(d, NULL);
	atom_str_free_null(&d->uri);

	if (d->ranges) {
		http_range_free(d->ranges);
		d->ranges = NULL;
	}

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
	d->status = GTA_DL_REMOVED;

	atom_str_free(d->file_name);
	d->file_name = NULL;
	atom_str_free(d->escaped_name);
	d->escaped_name = NULL;

	file_info_remove_source(d->file_info, d, FALSE); /* Keep fileinfo around */
	d->file_info = NULL;

	idtable_free_id(src_handle_map, d->src_handle);

	download_check(d);
	sl_removed = g_slist_prepend(sl_removed, d);

	/* download structure will be freed in download_free_removed() */
	return TRUE;
}

/* ----------------------------------------- */

/**
 * Forget about download: stop it if running.
 * When `unavailable' is TRUE, mark the download as unavailable.
 */
void
download_forget(struct download *d, gboolean unavailable)
{
	download_check(d);

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	if (DOWNLOAD_IS_QUEUED(d)) {
		download_unqueue(d);
		gcu_download_gui_add(d);
	}

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

	download_forget(d, FALSE);

	/*
	 * The refcount isn't decreased until "Clear completed", so
	 * we may very well have a file with a high refcount and no active
	 * or queued downloads.  This is why we maintain a lifecount.
	 */

	if (d->file_info->lifecount == 0)
		if (download_delete_aborted)
			download_remove_file(d, FALSE);
}

void
download_resume(struct download *d)
{
	download_check(d);

	g_return_if_fail(!DOWNLOAD_IS_QUEUED(d));

	if (DOWNLOAD_IS_RUNNING(d) || DOWNLOAD_IS_WAITING(d))
		return;

	g_assert(d->list_idx == DL_LIST_STOPPED);

	switch (d->status) {
	case GTA_DL_COMPLETED:
	case GTA_DL_VERIFY_WAIT:
	case GTA_DL_VERIFYING:
	case GTA_DL_VERIFIED:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_DONE:
		return;
	default: ;
		/* FALL THROUGH */
	}

	d->file_info->lifecount++;

	if (
		NULL != has_same_download(d->file_name, d->sha1, d->file_size,
			download_guid(d), download_addr(d), download_port(d))
	) {
		d->status = GTA_DL_CONNECTING;		/* So we may call download_stop */
		download_move_to_list(d, DL_LIST_RUNNING);
		download_stop(d, GTA_DL_ERROR, "Duplicate");
		return;
	}

	download_start(d, TRUE);
}

/**
 * Explicitly re-enqueue potentially stopped download.
 */
void
download_requeue(struct download *d)
{
	download_check(d);
	g_return_if_fail(!DOWNLOAD_IS_QUEUED(d));

	if (DOWNLOAD_IS_VERIFYING(d))		/* Can't requeue: it's done */
		return;

	if (DOWNLOAD_IS_STOPPED(d))
		d->file_info->lifecount++;

	download_queue(d, _("Explicitly requeued"));
}

/**
 * Try to setup the download to use the push proxies available on the server.
 *
 * @returns TRUE is we can use a push proxy.
 */
static gboolean
use_push_proxy(struct download *d)
{
	struct dl_server *server = d->server;

	download_check(d);
	g_assert(d->push);
	g_assert(!has_blank_guid(d));
	g_assert(dl_server_valid(server));

	if (d->cproxy != NULL) {
		cproxy_free(d->cproxy);
		d->cproxy = NULL;
	}

	while (server->proxies != NULL) {
		gnet_host_t *host;

		host = (gnet_host_t *) server->proxies->data;	/* Pick the first */
		d->cproxy = cproxy_create(d, host->addr, host->port,
			download_guid(d), d->record_index);

		if (d->cproxy) {
			/* Will read status in d->cproxy */
			gcu_gui_update_download(d, TRUE);
			return TRUE;
		}

		remove_proxy(server, host->addr, host->port);
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
	gcu_gui_update_download(d, TRUE);
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
	gcu_gui_update_download(d, TRUE);
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
	gcu_gui_update_download(d, TRUE);

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
 * Send a push request to the target GUID, in order to request the push of
 * the file whose index is `file_id' there onto our local port `port'.
 *
 * @returns TRUE if the request could be sent, FALSE if we don't have the route.
 */
static gboolean
send_push_request(const gchar *guid, guint32 file_id, guint16 port)
{
	static const gboolean supports_tls =
#ifdef HAS_GNUTLS
		TRUE;
#else
		FALSE;
#endif /* HAS_GNUTLS */
	GSList *nodes;
	const gchar *packet;
	size_t size;

	if (0 == port)
		return FALSE;

	if (NULL == (nodes = route_towards_guid(guid)))
		return FALSE;

	/*
	 * NB: we send the PUSH message with hard_ttl_limit, not my_ttl, in case
	 * the message needs to be alternatively routed (the path the query hit
	 * used has been broken).
	 */

	
	packet = build_push(&size, hard_ttl_limit, 0, guid,
				listen_addr(), listen_addr6(), port, file_id, supports_tls);

	if (packet) {
		/*
		 * Send the message to all the nodes that can route our request back
		 * to the source of the query hit.
		 */
		gmsg_sendto_all(nodes, packet, size);
	} else {
		g_warning("Failed to send push to %s (index=%lu)",
			host_addr_port_to_string(listen_addr(), port), (gulong) file_id);
	}

	g_slist_free(nodes);
	nodes = NULL;

	return NULL != packet;
}

/***
 *** I/O header parsing callbacks
 ***/

static inline struct download *
cast_to_download(gpointer p)
{
	struct download *d = p;
	download_check(d);
	return d;
}

#define DOWNLOAD(x)	cast_to_download(x)

static void
err_line_too_long(gpointer o)
{
	download_stop(DOWNLOAD(o), GTA_DL_ERROR, "Failed (Header line too large)");
}

static void
err_header_error(gpointer o, gint error)
{
	download_stop(DOWNLOAD(o), GTA_DL_ERROR,
		"Failed (%s)", header_strerror(error));
}

static void
err_input_buffer_full(gpointer o)
{
	download_stop(DOWNLOAD(o), GTA_DL_ERROR, "Failed (Input buffer full)");
}

static void
err_header_read_error(gpointer o, gint error)
{
	struct download *d = DOWNLOAD(o);

	download_check(d);

	if (error == ECONNRESET) {
		if (d->retries++ < download_max_retries)
			download_queue_delay(d, download_retry_stopped_delay,
				_("Stopped (%s)"), g_strerror(error));
		else
			download_unavailable(d, GTA_DL_ERROR,
				_("Too many attempts (%u times)"), d->retries - 1);
	} else
		download_stop(d, GTA_DL_ERROR, _("Failed (Read error: %s)"),
			g_strerror(error));
}

static void
err_header_read_eof(gpointer o)
{
	struct download *d = DOWNLOAD(o);
	header_t *header = io_header(d->io_opaque);

	if (HEADER_LINES(header) == 0) {
		/*
		 * Maybe we sent HTTP header continuations and the server does not
		 * understand them, breaking the connection on "invalid" request.
		 * Use minimalist HTTP then when talking to this server!
		 */

		d->server->attrs |= DLS_A_MINIMAL_HTTP;
	} else {
		/*
		 * As some header lines were read, we could at least try to get the
		 * server's name so we can display it.
		 *		-- JA, 22/03/2003
		 */
		download_get_server_name(d, header);
	}

	if (d->retries++ < download_max_retries)
		download_queue_delay(d, download_retry_stopped_delay,
			d->keep_alive ? _("Connection not kept-alive (EOF)") :
			_("Stopped (EOF) <err_header_read_eof>"));
	else
		download_unavailable(d, GTA_DL_ERROR,
			_("Too many attempts (%u times)"), d->retries - 1);
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
download_start_reading(gpointer o)
{
	struct download *d = DOWNLOAD(o);
	tm_t now;
	tm_t elapsed;
	guint32 latency;

	/*
	 * Compute the time it took since we sent the headers, and update
	 * the fast EMA (n=7 terms) storing the HTTP latency, in msecs.
	 */

	tm_now(&now);
	tm_elapsed(&elapsed, &now, &d->header_sent);

	gnet_prop_get_guint32_val(PROP_DL_HTTP_LATENCY, &latency);
	latency += (tm2ms(&elapsed) >> 2) - (latency >> 2);
	gnet_prop_set_guint32_val(PROP_DL_HTTP_LATENCY, latency);

	/*
	 * Update status and GUI, timestamp start of header reading.
	 */

	d->status = GTA_DL_HEADERS;
	d->last_update = tm_time();			/* Starting reading */
	gcu_gui_update_download(d, TRUE);
}

static void
call_download_request(gpointer o, header_t *header)
{
	download_request(DOWNLOAD(o), header, TRUE);
}

static void
call_download_push_ready(gpointer o, header_t *unused_header)
{
	struct download *d = DOWNLOAD(o);

	(void) unused_header;
	download_push_ready(d, io_getline(d->io_opaque));
}

#undef DOWNLOAD

/**
 * Check that the leading overlapping data in the read buffers match with
 * the last ones in the downloaded file.  Then remove them.
 *
 * @returns TRUE if the data match, FALSE if they don't, in which case the
 * download is stopped.
 */
static gboolean
download_overlap_check(struct download *d)
{
	struct file_object *fo;
	fileinfo_t *fi;
	gboolean success = FALSE;
	gchar *data = NULL;

	download_check(d);
	fi = d->file_info;
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	{
		gchar *path = make_pathname(fi->path, fi->file_name);

		fo = file_object_open(path, O_RDONLY);
		if (!fo) {
			gint fd = file_open(path, O_RDONLY);
			if (fd >= 0) {
				fo = file_object_new(fd, path, O_RDONLY);
			} else {
				const gchar *error = g_strerror(errno);
				g_message("cannot check resuming for \"%s\": %s",
						fi->file_name, error);
				download_stop(d, GTA_DL_ERROR, "Can't check resume data: %s",
						error);
			}
		}
		G_FREE_NULL(path);
	}

	if (!fo) {
		goto out;
	}

	{
		struct stat sb;

		if (-1 == fstat(file_object_get_fd(fo), &sb)) {
			/* Should never happen */
			const gchar *error = g_strerror(errno);
			g_message("cannot stat opened \"%s\": %s", fi->file_name, error);
			download_stop(d, GTA_DL_ERROR, "Can't stat opened file: %s", error);
			goto out;
		}

		/*
		 * Sanity check: if the file is bigger than when we started, abort
		 * immediately.
		 */

		if (!fi->use_swarming && d->skip != fi->done) {
			g_message("file '%s' changed size (now %s, but was %s)",
					fi->file_name, uint64_to_string(sb.st_size),
					uint64_to_string2(d->skip));
			download_queue_delay(d, download_retry_stopped_delay,
					_("Stopped (Output file size changed)"));
			goto out;
		}
	}

	{
		ssize_t r;

		data = walloc(d->overlap_size);
		g_assert(d->skip >= d->overlap_size);
		r = file_object_pread(fo, data, d->overlap_size,
				d->skip - d->overlap_size);

		if ((ssize_t) -1 == r) {
			const gchar *error = g_strerror(errno);
			g_message("cannot read resuming data for \"%s\": %s",
					fi->file_name, error);
			download_stop(d, GTA_DL_ERROR, "Can't read resume data: %s", error);
			goto out;
		} else if ((size_t) r != d->overlap_size) {
			g_message(
				"short read (%u instead of %u bytes) on resuming data for "
				"\"%s\"", (guint) r, (guint) d->overlap_size, fi->file_name);
			download_stop(d, GTA_DL_ERROR, "Short read on resume data");
			goto out;
		}
	}

	if (!buffers_match(d, data, d->overlap_size)) {
		if (download_debug > 1) {
			g_message("%u overlapping bytes UNMATCHED at offset %s for \"%s\"",
				(guint) d->overlap_size,
				uint64_to_string(d->skip - d->overlap_size),
				download_outname(d));
        }

		buffers_discard(d);			/* Discard everything we read so far */
		download_bad_source(d);		/* Until proven otherwise if we resume it */

		if (dl_remove_file_on_mismatch) {
			download_queue(d, "Resuming data mismatch @ %s",
				uint64_to_string(d->skip - d->overlap_size));
			download_remove_file(d, TRUE);
		} else {
			filesize_t begin, end;
			guint32 backout;

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

			end = d->skip + 1;
			gnet_prop_get_guint32_val(PROP_DL_MISMATCH_BACKOUT, &backout);
			if (end >= backout)
				begin = end - backout;
			else
				begin = 0;
			file_info_update(d, begin, end, DL_CHUNK_EMPTY);
			g_message("resuming data mismatch on %s, backed out %u bytes block"
				" from %s to %s",
				 download_outname(d), (guint) backout,
				 uint64_to_string(begin), uint64_to_string2(end));

			/*
			 * Don't always keep this source, and since there is doubt,
			 * leave it to randomness.
			 */

			if (random_value(99) >= 50)
				download_stop(d, GTA_DL_ERROR,
					"Resuming data mismatch @ %s",
					uint64_to_string(d->skip - d->overlap_size));
			else
				download_queue_delay(d, download_retry_busy_delay,
					"Resuming data mismatch @ %s",
					uint64_to_string(d->skip - d->overlap_size));
		}
		goto out;
	}

	/*
	 * Remove the overlapping data from the read buffers.
	 */

	buffers_strip_leading(d, d->overlap_size);

	if (download_debug > 3)
		g_message("%u overlapping bytes MATCHED "
			"at offset %s for \"%s\"",
			(guint) d->overlap_size,
			uint64_to_string(d->skip - d->overlap_size), download_outname(d));

	success = TRUE;

out:
	WFREE_NULL(data, d->overlap_size);
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
static gboolean
download_flush(struct download *d, gboolean *trimmed, gboolean may_stop)
{
	struct dl_buffers *b;
	ssize_t written;

	download_check(d);
	b = d->buffers;
	g_assert(b != NULL);

	if (download_debug > 1)
		g_message("flushing %lu bytes for \"%s\"%s",
			(gulong) b->held, download_outname(d), may_stop ? "" : " on stop");

	/*
	 * We can't have data going farther than what we requested from the
	 * server.  But if we do, trim and warn.  And mark the server as not
	 * being capable of handling keep-alive connections correctly!
	 */

	if (b->held > d->range_end - d->pos) {
		filesize_t extra = b->held - (d->range_end - d->pos);

		if (download_debug) g_message(
			"server %s (%s) gave us %s more byte%s than requested for \"%s\"",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d), uint64_to_string(extra),
			extra == 1 ? "" : "s", download_outname(d));

		buffers_strip_trailing(d, extra);
		if (trimmed)
			*trimmed = TRUE;

		g_assert(b->held > 0);	/* We had not reached range_end previously */
	} else if (trimmed)
		*trimmed = FALSE;

	/*
	 * Prepare I/O vector for writing.
	 */
	
	{
		struct iovec *iov;

		iov = buffers_to_iovec(d); 
		written = file_object_pwritev(d->out_file, iov, b->count, d->pos);
		wfree(iov, b->count * sizeof *iov);
	}

	if ((ssize_t) -1 == written) {
		const char *error = g_strerror(errno);

		g_warning("write of %lu bytes to file \"%s\" failed: %s",
			(gulong) b->held, download_outname(d), error);

		/* FIXME: We should never discard downloaded data! This
		 * causes a re-download of the same data. Instead we should
		 * keep the buffered data around and periodically try to
		 * flush the buffers. At least in the case of ENOSPC or
		 * EDQUOT when the disk filled up and the condition can
		 * be solved by the user but may hold for a long duration.
		 */

		/* Prevent download_stop() from trying flushing again */
		buffers_discard(d);
		
		if (may_stop)
			download_queue_delay(d, download_retry_busy_delay,
				_("Can't save data: %s"), error);

		return FALSE;
	}

	g_assert((size_t) written <= b->held);

	file_info_update(d, d->pos, d->pos + written, DL_CHUNK_DONE);
	gnet_prop_set_guint64_val(PROP_DL_BYTE_COUNT, dl_byte_count + written);
	d->pos += written;

	if ((size_t) written < b->held) {
		g_warning("partial write of %lu out of %lu bytes to file \"%s\"",
			(gulong) written, (gulong) b->held, download_outname(d));

		/* Prevent download_stop() from trying flushing again */
		buffers_discard(d);

		if (may_stop)
			download_queue_delay(d, download_retry_busy_delay,
				"Partial write to file");

		return FALSE;
	}

	g_assert((size_t) written == b->held);

	buffers_discard(d);			/* Since we wrote everything... */

	return TRUE;
}

/**
 * Write data in socket buffer to file.
 *
 * @return FALSE if an error occurred.
 */
static gboolean
download_write_data(struct download *d)
{
	struct dl_buffers *b;
	fileinfo_t *fi;
	gboolean trimmed = FALSE;
	struct download *cd;					/* Cloned download, if completed */
	enum dl_chunk_status status = DL_CHUNK_BUSY;
	gboolean should_flush;

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

	if (d->overlap_size && !(d->flags & DL_F_OVERLAPPED)) {
		g_assert(d->pos == d->skip);
		if (b->held < d->overlap_size)		/* Not enough bytes yet */
			return TRUE;						/* Don't even write anything */
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

	if (!should_flush && b->held >= d->range_end - d->pos)
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

	if (download_debug > 5) {
		g_message(
			"%sflushing pending %lu bytes for \"%s\", pos=%s, range_end=%s",
			should_flush ? "" : "NOT ",
			(gulong) b->held, download_outname(d),
			uint64_to_string(d->pos),
			uint64_to_string2(d->range_end));
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
			 * requeue the download, thereby loosing the slot.
			 */
			if (fi->done >= fi->size)
				goto done;
			else if (d->pos == d->range_end)
				goto partial_done;
			else
				download_queue(d, _("Requeued by competing download"));
			break;
		case DL_CHUNK_BUSY:
			if (d->pos < d->range_end) {	/* Still within requested chunk */
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

			if (d->pos == d->range_end)
				goto partial_done;

			d->range_end = download_filesize(d);	/* New upper boundary */

			break;					/* Go on... */
		}
	} else if (FILE_INFO_COMPLETE(fi))
		goto done;
	else
		gcu_gui_update_download(d, FALSE);

	return DOWNLOAD_IS_RUNNING(d);

	/*
	 * Requested chunk is done.
	 */

partial_done:
	g_assert(d->pos == d->range_end);
	g_assert(fi->use_swarming);

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

	if (trimmed)
		download_queue(cd, _("Requeued after trimmed data"));
	else if (!cd->keep_alive)
		download_queue(cd, _("Chunk done, connection closed"));
	else {
		if (download_start_prepare(cd)) {
			cd->keep_alive = TRUE;			/* Was reset by _prepare() */
			gcu_download_gui_add(cd);
			download_send_request(cd);		/* Will pick up new range */
		}
	}

	return FALSE;

	/*
	 * We have completed the download of the requested file.
	 */

done:
	download_stop(d, GTA_DL_COMPLETED, no_reason);
	download_verify_sha1(d);

	gnet_prop_set_guint32_val(PROP_TOTAL_DOWNLOADS, total_downloads + 1);
	return FALSE;
}

/**
 * Refresh IP:port, download index and name, by looking at the new location
 * in the header ("Location:").
 *
 * @returns TRUE if we managed to parse the new location.
 */
gboolean
download_moved_permanently(struct download *d, header_t *header)
{
	gchar *buf;
	dmesh_urlinfo_t info;
	host_addr_t addr;
	guint16 port;

	download_check(d);

	addr = download_addr(d);
	port = download_port(d);

	buf = header_get(header, "Location");
	if (buf == NULL)
		return FALSE;

	if (!dmesh_url_parse(buf, &info)) {
		if (download_debug)
			g_message("could not parse HTTP Location: %s", buf);
		return FALSE;
	}

	/*
	 * If ip/port changed, accept the new ones but warn.
	 */

	if (!host_addr_equal(info.addr, addr) || info.port != port) {
		g_warning("server %s (file \"%s\") redirecting us to alien %s",
			host_addr_port_to_string(addr, port), download_outname(d), buf);
    }

	if (!is_host_addr(info.addr)) {
		g_warning("server %s (file \"%s\") would redirect us to invalid %s",
			host_addr_port_to_string(addr, port), download_outname(d), buf);
		atom_str_free(info.name);
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
			host_addr_port_to_string(addr, port), download_outname(d), buf);
		atom_str_free(info.name);
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

		atom_str_free(d->file_name);
		atom_str_free(d->escaped_name);

		d->file_name = deconstify_gchar(info.name);		/* Already an atom */
		d->escaped_name = download_escape_name(info.name);
	} else
		atom_str_free(info.name);

	/*
	 * Update download structure.
	 */

	d->record_index = info.idx;

	download_redirect_to_server(d, info.addr, info.port);

	return TRUE;
}

/**
 * Extract server name from headers.
 *
 * @returns whether new server name was found.
 */
static gboolean
download_get_server_name(struct download *d, header_t *header)
{
	const gchar *user_agent;
	gboolean got_new_server = FALSE;

	download_check(d);

	user_agent = header_get(header, "Server");			/* Mandatory */
	if (!user_agent)
		user_agent = header_get(header, "User-Agent"); /* Are they confused? */

	if (user_agent) {
		struct dl_server *server = d->server;
		const gchar *vendor;
		gchar *wbuf = NULL;
		size_t size = 0;
		gboolean faked;
	   
		g_assert(dl_server_valid(server));

		if (NULL == user_agent || !is_strprefix(user_agent, "gtk-gnutella/")) {
			socket_disable_token(d->socket);
		}
			
		faked = !version_check(user_agent, header_get(header, "X-Token"),
					download_addr(d));

		if (server->vendor == NULL) {
			got_new_server = TRUE;
			if (faked)
				size = w_concat_strings(&wbuf, "!", user_agent, (void *) 0);
			vendor = wbuf ? wbuf : user_agent;
		} else if (!faked && 0 != strcmp(server->vendor, user_agent)) {
			/* Name changed? */
			got_new_server = TRUE;
			atom_str_free(server->vendor);
			vendor = user_agent;
		} else {
			vendor = NULL;
		}
	
		if (vendor)	
			server->vendor = atom_str_get(lazy_iso8859_1_to_utf8(vendor));
		if (wbuf) {
			wfree(wbuf, size);
			wbuf = NULL;
		}
	}

	return got_new_server;
}

/**
 * Check status code from status line.
 *
 * @return TRUE if we can continue.
 */
static gboolean
download_check_status(struct download *d, getline_t *line, gint code)
{
	download_check(d);

	if (-1 == code) {
		g_message("weird HTTP acknowledgment status line from %s (%s)",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d));
		if (download_debug) {
			dump_hex(stderr, "Status Line", getline_str(line),
				MIN(getline_length(line), 80));
		}

		/*
		 * Don't abort the download if we're already on a persistent
		 * connection: the server might have goofed, or we have a bug.
		 * What we read was probably still data coming through.
		 */

		if (d->keep_alive) {
			download_queue(d, _("Weird HTTP status (protocol desync?)"));
		} else {
			download_bad_source(d);
			download_stop(d, GTA_DL_ERROR, "Weird HTTP status");
		}
		return FALSE;
	}

	return TRUE;
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
static gboolean
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

	if (download_debug > 1) {
		g_message("download at %s \"%u/%s\" becomes "
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
		download_stop(d, GTA_DL_ERROR, "Was a duplicate");
		return FALSE;
	}

	return TRUE;
}

/**
 * Extract Retry-After delay from header, returning 0 if none.
 */
guint
extract_retry_after(struct download *d, const header_t *header)
{
	const gchar *buf;
	guint32 delay;
	gint error;

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
			g_warning("cannot parse Retry-After \"%s\" sent by %s <%s>",
				buf,
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_vendor_str(d));
			return 0;
		}

		delay = delta_time(retry, now);
		if (delay > INT_MAX)
			return 0;
	}

	return delay;
}

/**
 * Look for a Date: header in the reply and use it to update our skew.
 */
static void
check_date(const header_t *header, const host_addr_t addr, struct download *d)
{
	const gchar *buf;

	download_check(d);

	buf = header_get(header, "Date");
	if (buf) {
		time_t their = date2time(buf, tm_time());

		if ((time_t) -1 == their)
			g_warning("cannot parse Date \"%s\" sent by %s <%s>",
				buf,
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_vendor_str(d));
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

			clock_update(their + correction, correction + 1, addr);
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
	gchar *buf;

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
		if (d->push)
			download_push_remove(d);

		if (download_debug > 2)
			g_message("PUSH got X-Hostname, trying to ignore them for %s (%s)",
				buf, host_addr_port_to_string(download_addr(d),
				download_port(d)));

		d->flags |= DL_F_PUSH_IGN;
	}

	/*
	 * If we had a hostname for this server, and it has not changed,
	 * then we're done.
	 */

	if (
		server->hostname != NULL &&
		0 == ascii_strcasecmp(server->hostname, buf)
	)
		return;

	set_server_hostname(server, buf);
	gcu_gui_update_download_host(d);
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
	const gchar *buf;
	host_addr_t addr;
	guint16 port;

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

	if (d->push)
		download_push_remove(d);

	if (download_debug > 2)
		g_message("PUSH got X-Host, trying to ignore them for %s",
			host_addr_port_to_string(download_addr(d), download_port(d)));

	d->flags |= DL_F_PUSH_IGN;
}

/**
 * Check for X-Gnutella-Content-URN.
 *
 * @returns FALSE if we cannot continue with the download.
 */
static gboolean
check_content_urn(struct download *d, header_t *header)
{
	gchar *buf;
	gchar digest[SHA1_RAW_SIZE];
	gboolean found_sha1 = FALSE;

	download_check(d);

	buf = header_get(header, "X-Gnutella-Content-Urn");

	/*
	 * Clueless Shareaza chose to blindly and secretly change the header
	 * into X-Content-Urn, which can also contain a list of URNs and not
	 * a single URN (the latter being a good thing actually).
	 *		--RAM, 16/06/2003
	 */

	if (buf == NULL)
		buf = header_get(header, "X-Content-Urn");

	if (buf == NULL) {
		gboolean n2r = FALSE;

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
			if (download_require_urn) {			/* They want strictness */
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, "No URN on server (required)");
				return FALSE;
			}
			if (download_overlap_range >= DOWNLOAD_MIN_OVERLAP) {
				if (download_optimistic_start && (d->pos == 0))
					return TRUE;

				if (d->overlap_size == 0) {
					download_queue_delay(d, download_retry_busy_delay,
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

	found_sha1 = dmesh_collect_sha1(buf, digest);

	if (!found_sha1)
		return TRUE;

	if (d->sha1 && 0 != memcmp(digest, d->sha1, SHA1_RAW_SIZE)) {
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "URN mismatch detected");
		return FALSE;
	}

	/*
	 * Record SHA1 if we did not know it yet.
	 */

	if (d->sha1 == NULL) {
		download_set_sha1(d, digest);

		/*
		 * The following test for equality works because both SHA1
		 * are atoms.
		 */

		if (d->file_info->sha1 != d->sha1) {
			g_message("discovered SHA1 %s on the fly for %s "
				"(fileinfo has %s)",
				sha1_base32(d->sha1), download_outname(d),
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

		/*
		 * Discovery of the SHA1 for a download should be infrequent enough,
		 * yet is very important.   This justifies immediately storing that
		 * new information without waiting for the "dirty timer" to trigger.
		 */

		download_store();				/* Save SHA1 */
		file_info_store_if_dirty();

		/*
		 * Insert record in download mesh if it does not require
		 * a push.	Since we just got a connection, we use "now"
		 * as the mesh timestamp.
		 */

		if (!d->always_push && !d->uri)
			dmesh_add(d->sha1,
				download_addr(d), download_port(d), d->record_index,
				d->file_name, 0);
	}

	/*
	 * Check for possible download mesh headers.
	 */

collect_locations:
	{
		const gchar *sha1;

		g_assert(d->file_info != NULL);
		g_assert(d->sha1 || d->file_info->sha1);

		sha1 = d->sha1 ? d->sha1 : d->file_info->sha1;

		huge_collect_locations(sha1, header);
	}

	return TRUE;
}

/**
 * Extract host:port information out of X-Push-Proxy if present and
 * update the server's list.
 */
static void
check_push_proxies(struct download *d, header_t *header)
{
	gchar *buf;
	const gchar *tok;
	GSList *sl = NULL;

	download_check(d);

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

	for (tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
		host_addr_t addr;
		guint16 port;

		if (!string_to_host_addr_port(tok, NULL, &addr, &port))
			continue;


		if (is_private_addr(addr)) {
			g_message("host %s [%s] sent a private IP address as Push-Proxy.",
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_vendor_str(d));
		} else {
			gnet_host_t *host = walloc(sizeof *host);
			host->addr = addr;
			host->port = port;

			sl = g_slist_prepend(sl, host);
		}
	}

	{
		struct dl_server *server = d->server;
		if (server->proxies)
			free_proxies(server);

		server->proxies = sl;
		server->proxies_stamp = tm_time();
	}
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
 */
static void
update_available_ranges(struct download *d, header_t *header)
{
	static const gchar available[] = "X-Available-Ranges";
	gchar *buf;

	download_check(d);

	if (d->ranges != NULL) {
		http_range_free(d->ranges);
		d->ranges = NULL;
	}

	if (!d->file_info->use_swarming)
		goto send_event;

	g_assert(header != NULL);

	buf = header_get(header, available);

	if (buf == NULL || download_filesize(d) == 0)
		goto send_event;

	/*
	 * LimeWire seemingly sends this to imply support for the feature
	 * when it has no availble ranges.
	 */
	if (0 == strcmp(buf, "bytes"))
		goto send_event;
		
	/*
	 * Update available range list and total size available remotely.
	 */

	d->ranges = http_range_parse(available, buf,
		download_filesize(d), download_vendor_str(d));

	d->ranges_size = http_range_size(d->ranges);

	/*
	 * We should always send an update event for the ranges, even when
	 * not using swarming or when there are no available ranges. That
	 * way the receiver of this event can still determine that the
	 * whole range for this file is available.
	 */
 send_event:
	event_trigger(src_events[EV_SRC_RANGES_CHANGED],
				  T_NORMAL(src_listener_t, (d->src_handle)));
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
	g_assert((gint) s->pos >= 0 && s->pos <= s->buf_size);
	g_assert(d->status == GTA_DL_SINKING);
	g_assert(d->flags & DL_F_CHUNK_CHOSEN);
	g_assert(d->flags & DL_F_SUNK_DATA);

	if (s->pos > d->sinkleft) {
		g_message("got more data to sink than expected from %s <%s>",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d));
		download_stop(d, GTA_DL_ERROR, "More data to sink than expected");
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
		d->status = GTA_DL_CONNECTING;
		download_send_request(d);
	}
}

/**
 * Read callback for file data.
 */
static void
download_sink_read(gpointer data, gint unused_source,
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
		download_queue_delay(d, download_retry_busy_delay,
			_("Stopped data (EOF) <download_sink_read>"));
	} else if ((ssize_t) -1 == r) {
		if (!is_temporary_error(errno)) {
			socket_eof(s);
			if (errno == ECONNRESET)
				download_queue_delay(d, download_retry_busy_delay,
					"Stopped data (%s)", g_strerror(errno));
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

static const gchar *
lazy_ack_message_to_ui_string(const gchar *src)
{
	static gchar *prev;
	gchar *s;
	
	g_assert(src);
	g_assert(src != prev);

	G_FREE_NULL(prev);
	
	if (is_ascii_string(src))
		return src;

	s = iso8859_1_to_utf8(src);
	prev = utf8_to_ui_string(s);
	if (prev != s && src != s)
		G_FREE_NULL(s);
	
	return prev;
}

/**
 * Mark download as receiving data: download is becoming active.
 */
static void
download_mark_active(struct download *d)
{
	fileinfo_t *fi;

	download_check(d);

	fi = d->file_info;
	d->start_date = tm_time();
	d->status = GTA_DL_RECEIVING;

	if (fi->recvcount == 0) {		/* First source to begin receiving */
		fi->recv_last_time = d->start_date;
		fi->recv_last_rate = 0;
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
	gcu_gui_update_download(d, TRUE);
	gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);

	/*
	 * Set TOS to low-delay, so that ACKs flow back faster, and set the RX
	 * buffer according to their preference (large for better throughput,
	 * small for better control of the incoming rate).
	 */

	{
		struct gnutella_socket *s = d->socket;

		socket_tos_lowdelay(s);
		sock_recv_buf(s, download_rx_size * 1024, TRUE);
	}

	/*
	 * If not a browse-host request, prepare reading buffers.
	 */

	if (!(d->flags & DL_F_BROWSE)) {
		buffers_alloc(d);
		buffers_reset_reading(d);
	}
}

/**
 * Checks whether the given vendor is evil.
 *
 * @param vendor Value of a User-Agent respectively Server header.
 * @returns TRUE if the given vendor string is known to be used by evil
 * 			guys only, FALSE otherwise.
 */
static gboolean
vendor_is_evil(const gchar *vendor)
{
	const gchar *endptr;

	g_return_val_if_fail(vendor, FALSE);
	
	endptr = is_strcaseprefix(vendor, "LimeWire/");
	if (endptr) {
		if (is_strprefix(endptr, "3.6.") || is_strprefix(endptr, "4.8.10.")) {
			return TRUE;
		}
	} else {
		if (is_strcaseprefix(vendor, "Morpheous/")) {
			return TRUE;
		}
	}
	return FALSE;
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
download_request(struct download *d, header_t *header, gboolean ok)
{
	struct gnutella_socket *s;
	const gchar *status;
	guint ack_code;
	const gchar *ack_message = "";
	gchar *buf;
	gboolean got_content_length = FALSE;
	gboolean is_chunked;
	http_content_encoding_t content_encoding;
	filesize_t check_content_range = 0, requested_size;
	host_addr_t addr;	
	guint16 port;
	guint http_major = 0, http_minor = 0;
	gboolean is_followup;
	fileinfo_t *fi;
	gchar short_read[80];
	guint delay;
	guint hold = 0;
	gchar *path = NULL;
	gboolean refusing;
	guint32 bh_flags = 0;

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
		download_queue_delay(d, download_retry_refused_delay,
			"Timeout reading HTTP status");
		return;
	}

	g_assert(s->getline);				/* Being in the header reading phase */

	status = getline_str(s->getline);
	d->last_update = tm_time();			/* Done reading headers */

	if (download_debug > 2) {
		const gchar *incomplete = ok ? "" : "INCOMPLETE ";
		g_message("----Got %sreply from %s:", incomplete,
			host_addr_to_string(s->addr));
		fprintf(stderr, "%s\n", status);
		header_dump(header, stderr);
		fprintf(stderr, "----\n");
		fflush(stderr);
	}

	/*
	 * If we did not get any status code at all, re-enqueue immediately.
	 */

	if (!ok && getline_length(s->getline) == 0) {
		download_queue_delay(d, download_retry_refused_delay,
			"Timeout reading headers");
		return;
	}

	/*
	 * If we were pushing this download, check for an X-Host header in
	 * the reply: this will indicate that the remote host is not firewalled
	 * and will give us its IP:port.
	 *
	 * NB: do this before extracting the server token, as it may redirect
	 * us to an alternate server, and we could therefore loose the server
	 * vendor string indication (attaching it to a discarded server object).
	 */

	if (d->got_giv) {
		if (!is_followup)
			check_xhost(d, header);
		check_push_proxies(d, header);
	}

	feed_host_cache_from_headers(header, HOST_ANY, FALSE, download_addr(d));

	/*
	 * If we get an X-Hostname header, we know the remote end is not
	 * firewalled, and we get its DNS name: even if its IP changes, we'll
	 * be able to recontact it.
	 */

	check_xhostname(d, header);

	/*
	 * Extract Server: header string, if present, and store it unless
	 * we already have it.
	 */

	if (download_get_server_name(d, header))
		gcu_gui_update_download_server(d);

	node_check_remote_ip_header(download_addr(d), header);

	/*
	 * Check status.
	 */

	ack_code = http_status_parse(status, "HTTP",
		&ack_message, &http_major, &http_minor);

	if (!download_check_status(d, s->getline, ack_code))
		return;

	if (ack_message)
		ack_message = lazy_ack_message_to_ui_string(ack_message);

	d->retries = 0;				/* Retry successful, we managed to connect */
	d->flags |= DL_F_REPLIED;

	addr = download_addr(d);
	port = download_port(d);

	if (!d->got_giv && header_get_feature("tls", header, NULL, NULL)) {
		tls_cache_insert(addr, port);
	}

	check_date(header, addr, d);	/* Update clock skew if we have a Date: */

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
			download_stop(d, GTA_DL_ERROR,
				"No support for Content-Encoding (%s)", buf);
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

	if (http_major == 0 && !ancient_version) {
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
			if (download_debug) g_message(
				"assuming \"HTTP/1.1 %d\" for %s <%s>", ack_code,
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_vendor_str(d));
		} else if (download_debug) {
			g_message(
				"no HTTP version nor Content-Length given by "
				"%s <%s> (status %d)",
				host_addr_port_to_string(download_addr(d), download_port(d)),
				download_vendor_str(d), ack_code);
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

	if (!ok)
		d->keep_alive = FALSE;			/* Got incomplete headers -> close */

	/*
	 * Now deal with the return code.
	 */

	if (ok)
		short_read[0] = '\0';
	else {
		guint count = HEADER_LINES(header);
		gm_snprintf(short_read, sizeof short_read,
			"[short %u line%s header] ", count, count == 1 ? "" : "s");
	}

	if (vendor_is_evil(download_vendor_str(d))) {	
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "%s", _("Spammer detected"));
		return;
	}

#ifdef TIGERTREE
	/* FIXME TIGERTREE:
	 * Temporary
	 */
	tt_parse_header(d, header);
#endif

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

			if (parq_download_parse_queue_status(d, header)) {
				/* If we are queued, there is nothing else we can do for now */
				if (parq_download_is_active_queued(d)) {
					download_passively_queued(d, FALSE);

					/* Make sure we're waiting for the right file,
					   collect alt-locs */
					if (check_content_urn(d, header)) {

						/* Update mesh */
						if (!d->always_push && d->sha1 && !d->uri)
							dmesh_add(d->sha1, addr, port, d->record_index,
								d->file_name, 0);

						return;

					} /* Check content urn failed */

					return;

				} /* Download not active queued, continue as normal */
				d->status = GTA_DL_HEADERS;
			}
		} /* ack_code was not 503 */
	}

	update_available_ranges(d, header);		/* Updates `d->ranges' */

	delay = extract_retry_after(d, header);
	d->retry_after = (delay > 0) ? time_advance(tm_time(), delay) : 0;

	/*
	 * Partial File Sharing Protocol (PFSP) -- client-side
	 *
	 * We can make another request with a range that the remote
	 * servent has if the reply was a keep-alive one.  Both 503 or 416
	 * replies are possible with PFSP.
	 */

	if (d->ranges && d->keep_alive && d->file_info->use_swarming) {
		switch (ack_code) {
		case 503:				/* Range not available, maybe */
		case 416:				/* Range not satisfiable */
			/*
			 * If we were requesting something that is already within the
			 * available ranges, then there is no need to go further.
			 */

			if (http_range_contains(d->ranges, d->skip, d->range_end - 1)) {
				if (download_debug > 3)
					g_message("PFSP currently requested chunk %s-%s from %s "
						"for \"%s\" already in the available ranges: %s",
						uint64_to_string(d->skip),
						uint64_to_string2(d->range_end - 1),
						host_addr_port_to_string(download_addr(d),
								download_port(d)),
						download_outname(d), http_range_to_string(d->ranges));

				break;
			}

			/*
			 * Clear current request so we may pick whatever is available
			 * remotely by freeing the current chunk...
			 */

			file_info_clear_download(d, TRUE);		/* `d' is running */

			/* Ensure we're waiting for the right file */
			if (!check_content_urn(d, header))
				return;

			/* Update mesh -- we're about to return */
			if (!d->always_push && d->sha1 && !d->uri)
				dmesh_add(d->sha1, addr, port,
					d->record_index, d->file_name, 0);

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

			if (delay == 0 && download_pick_available(d)) {
				guint64 v;
				gint error;

				/*
				 * Sink the data that might have been returned with the
				 * HTTP status.  When it's done, we'll send the request
				 * with the chunk we have chosen.
				 */

				buf = header_get(header, "Content-Length");	/* Mandatory */

				if (buf == NULL) {
					g_message("No Content-Length with keep-alive reply "
						"%u \"%s\" from %s <%s>", ack_code, ack_message,
						host_addr_port_to_string(download_addr(d),
							download_port(d)),
						download_vendor_str(d));
					download_queue_delay(d,
						MAX(delay, download_retry_refused_delay),
						"Partial file, bad HTTP keep-alive support");
					return;
				}

				v = parse_uint64(buf, NULL, 10, &error);
				if (error) {
					g_message( "Cannot parse Content-Length header from "
						"%s <%s>: \"%s\"",
						host_addr_port_to_string(download_addr(d),
							download_port(d)),
						download_vendor_str(d),
						buf);
				}
				d->sinkleft = v;

				if (d->sinkleft > DOWNLOAD_MAX_SINK) {
					g_message("Too much data to sink (%s bytes) on reply "
						"%u \"%s\" from %s <%s>",
						uint64_to_string(d->sinkleft), ack_code, ack_message,
						host_addr_port_to_string(download_addr(d),
							download_port(d)),
						download_vendor_str(d));

					download_queue_delay(d,
						MAX(delay, download_retry_refused_delay),
						"Partial file, too much data to sink (%s bytes)",
						uint64_to_string(d->sinkleft));
					return;
				}

				/*
				 * Avoid endless request/sinking cycles.  If we already sunk
				 * data previously since we started the connection, requeue.
				 */

				if (d->flags & DL_F_SUNK_DATA) {
					g_message("Would have to sink twice during session "
						"from %s <%s>",
						host_addr_port_to_string(download_addr(d),
							download_port(d)),
						download_vendor_str(d));
					download_queue_delay(d,
						MAX(delay, download_retry_refused_delay),
						"Partial file, no suitable range found yet");
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

					d->status = GTA_DL_SINKING;

					d->bio = bsched_source_add(bws.in, &s->wio,
						BIO_F_READ, download_sink_read, d);

					if (s->pos > 0)
						download_sink(d);

					gcu_gui_update_download(d, TRUE);
				}
			} else {
				/* Host might support queueing. If so, retrieve queue status */
				/* Server has nothing for us yet, give it time */
				download_queue_delay(d,
					MAX(delay, download_retry_refused_delay),
					_("Partial file on server, waiting"));
			}

			return;
		default:
			break;
		}
	}

	if (ack_code >= 200 && ack_code <= 299) {
		/* OK -- Update mesh */
		if (!d->always_push && d->sha1 && !d->uri)
			dmesh_add(d->sha1, addr, port, d->record_index, d->file_name, 0);

		download_passively_queued(d, FALSE);
		download_actively_queued(d, FALSE);

		if (!ok) {
			download_queue_delay(d, download_retry_busy_delay,
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
		}
	} else {
		const gchar *vendor = download_vendor_str(d);

		if (ack_code == 403 && (*vendor == 'g' || *vendor == '!')) {
			/*
			 * GTKG is overzealous: it will send a 403 for PARQ banning
			 * if we retry too often, but this can happen when GTKG crashes
			 * and is restarted before the retry timeout expires.
			 *
			 * If we did not special case this reply, then someone who
			 * auto-cleans downloads from his queue on error would loose
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
				delay ? delay : download_retry_busy_delay,
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
#else
			break;
#endif
		case 416:				/* Requested range not available */
			/*
			 * There was no ranges supplied (or we'd have gone through the
			 * PFSP code above), yet the server is sharing a partial file.
			 * Give it some time and retry.
			 */

			/* Make sure we're waiting for the right file, collect alt-locs */
			if (!check_content_urn(d, header))
				return;

			download_passively_queued(d, FALSE);
			download_queue_hold(d,
				delay ? delay : download_retry_timeout_delay,
				"%sRequested range unavailable yet", short_read);
			return;
		case 503:				/* Busy */
			/* Make sure we're waiting for the right file, collect alt-locs */
			if (!check_content_urn(d, header))
				return;

			/* FALL THROUGH */
		case 408:				/* Request timeout */
			/* Update mesh */
			if (!d->always_push && d->sha1 && !d->uri)
				dmesh_add(d->sha1, addr, port, d->record_index,
					d->file_name, 0);

			/*
			 * We did a fall through on a 503, however, the download could be
			 * queued remotely. We might want to display this.
			 *		-- JA, 21/03/2003 (it is spring!)
			 */
			if (parq_download_is_passive_queued(d)) {
				download_passively_queued(d, TRUE);
				download_queue_delay(d,
					delay ? delay : download_retry_busy_delay,
						_("Queued (slot %u/%u) ETA: %s"),
							get_parq_dl_position(d),
							get_parq_dl_queue_length(d),
							short_time_ascii(get_parq_dl_eta(d))
				);
			} else {
				/* No hammering -- hold further requests on server */
				download_passively_queued(d, FALSE);

#if 0
				if (d->sha1 && d->file_size) {
					dmesh_multiple_downloads(d->sha1,
							d->file_size, d->file_info);
				}
#endif
				download_queue_hold(d,
					delay ? delay : download_retry_busy_delay,
					"%sHTTP %u %s", short_read, ack_code, ack_message);
			}
			return;
		case 550:				/* Banned */
			download_passively_queued(d, FALSE);
			download_queue_hold(d,
				delay ? delay : download_retry_refused_delay,
				"%sHTTP %u %s", short_read, ack_code, ack_message);
			return;
		default:
			break;
		}

		download_bad_source(d);

		if (ancient_version)
			goto report_error;		/* Old versions don't circumvent banning */

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
			gboolean was_banning = d->server->attrs & DLS_A_BANNING;

			d->server->attrs &= ~DLS_A_BANNING;
			d->server->attrs &= ~DLS_A_MINIMAL_HTTP;

			if (was_banning)
				gcu_gui_update_download_server(d);

		} else if (!(d->server->attrs & DLS_A_BANNING)) {
			switch (ack_code) {
			case 401:
				if (!is_strprefix(download_vendor_str(d), "BearShare"))
					d->server->attrs |= DLS_A_BANNING;	/* Probably */
				break;
			case 403:
				if (is_strprefix(ack_message, "Network Disabled")) {
					hold = MAX(delay, 320);				/* To be safe */
				}
				d->server->attrs |= DLS_A_BANNING;		/* Probably */
				break;
			case 404:
				if (is_strprefix(ack_message, "Please Share"))
					d->server->attrs |= DLS_A_BANNING;	/* Shareaza 1.8.0.0- */
				break;
			}

			/*
			 * If server might be banning us, use minimal HTTP headers
			 * in our requests from now on.
			 */

			if (d->server->attrs & DLS_A_BANNING) {
				d->server->attrs |= DLS_A_MINIMAL_HTTP;

				if (download_debug) {
					g_message("server \"%s\" at %s might be banning us",
						download_vendor_str(d),
						host_addr_port_to_string(download_addr(d),
							download_port(d)));
				}

				if (hold)
					download_queue_hold(d, hold,
						"%sHTTP %u %s", short_read, ack_code, ack_message);
				else
					download_queue_delay(d,
						delay ? delay : download_retry_busy_delay,
						"%sHTTP %u %s", short_read, ack_code, ack_message);

				return;
			}
		}

		/*
		 * If they refuse our downloads, ban them in return for a limited
		 * amout of time and kill all their running uploads.
		 */

		refusing = FALSE;

		switch (ack_code) {
		case 401:
			refusing = TRUE;
			break;
		case 403:
		case 404:
			/*
			 * By only selecting servers that are banning us, we are not
			 * banning gtk-gnutella clients that could be refusing us because
			 * we're too old.  But this is fair, as the user is told about
			 * his revision being too old and decided not to act.
			 *		--RAM, 13/07/2003
			 */
			if (d->server->attrs & DLS_A_BANNING)
				refusing = TRUE;
			break;
		}

		if (refusing) {
			ban_record(download_addr(d), "IP denying uploads");
			upload_kill_addr(download_addr(d));
		}

	report_error:
		download_stop(d, GTA_DL_ERROR,
			"%sHTTP %u %s", short_read, ack_code, ack_message);
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

	(void) parq_download_parse_queue_status(d, header);

	/*
	 * If an URN is present, validate that we can continue this download.
 	 */

 	if (!check_content_urn(d, header))
 		return;


	/*
	 * If they configured us to require a server name, and we have none
	 * at this stage, stop.
	 */

	if (!d->uri && download_require_server_name && download_vendor(d) == NULL) {
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "Server did not supply identification");
		return;
	}

	/*
	 * Normally, a Content-Length: header is mandatory.	However, if we
	 * get a valid Content-Range, relax that constraint a bit.
	 *		--RAM, 08/01/2002
	 */

	requested_size = d->range_end - d->skip + d->overlap_size;

	buf = header_get(header, "Content-Length"); /* Mandatory */
	if (buf) {
		filesize_t content_size;
		gint error;

		content_size = parse_uint64(buf, NULL, 10, &error);

		if (
			!error &&
			!fi->file_size_known &&
			HTTP_CONTENT_ENCODING_IDENTITY == content_encoding
		) {
			/* XXX factor this code with the similar one below */
			d->size = content_size;
			file_info_size_known(d, content_size);
			d->range_end = download_filesize(d);
			requested_size = d->range_end - d->skip + d->overlap_size;
			gcu_gui_update_download_size(d);
		}

		if (error) {
			download_bad_source(d);
			download_stop(d, GTA_DL_ERROR, "Unparseable Content-Length");
			return;
		} else if (
			HTTP_CONTENT_ENCODING_IDENTITY == content_encoding &&
			content_size != requested_size
		) {
			if (content_size == fi->size) {
				g_message("file \"%s\": server seems to have "
					"ignored our range request of %s-%s.",
					download_outname(d),
					uint64_to_string(d->skip - d->overlap_size),
					uint64_to_string2(d->range_end - 1));
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
				/* XXX factor this code with the similar one above */
				d->size = total;
				file_info_size_known(d, total);
				d->range_end = download_filesize(d);
				requested_size = d->range_end - d->skip + d->overlap_size;
				gcu_gui_update_download_size(d);
			}

			if (check_content_range > total) {
                if (download_debug)
                    g_message(
						"file \"%s\" on %s (%s): total size mismatch: got %s, "
						"for a served content of %s",
                        download_outname(d),
                        host_addr_port_to_string(download_addr(d),
							download_port(d)),
                        download_vendor_str(d),
                        uint64_to_string(check_content_range),
						uint64_to_string2(total));

				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, "Total/served sizes mismatch");
				return;
			}

			if (start != d->skip - d->overlap_size) {
                if (download_debug)
                    g_message("file \"%s\" on %s (%s): start byte mismatch: "
						"wanted %s, got %s",
                        download_outname(d),
                        host_addr_port_to_string(download_addr(d),
							download_port(d)),
                        download_vendor_str(d),
                        uint64_to_string(d->skip - d->overlap_size),
						uint64_to_string2(start));

				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, "Range start mismatch");
				return;
			}
			if (total != fi->size) {
                if (download_debug) {
                        g_message("file \"%s\" on %s (%s): file size mismatch:"
						" expected %s, got %s",
                        download_outname(d),
                        host_addr_port_to_string(download_addr(d),
							download_port(d)),
                        download_vendor_str(d),
                        uint64_to_string(fi->size), uint64_to_string2(total));
                }
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, "File size mismatch");
				return;
			}
			if (end > d->range_end - 1) {
                if (download_debug) {
                    g_message("file \"%s\" on %s (%s): end byte too large: "
						"expected %s, got %s",
                        download_outname(d),
                        host_addr_port_to_string(download_addr(d),
							download_port(d)),
                        download_vendor_str(d),
                        uint64_to_string(d->range_end - 1),
						uint64_to_string2(end));
                }
				download_bad_source(d);
				download_stop(d, GTA_DL_ERROR, "Range end too large");
				return;
			}
			if (
				end < (d->skip -
					(d->skip < d->overlap_size ? 0 : d->overlap_size)) ||
				start >= d->range_end
			) {
				gchar got[64];

				gm_snprintf(got, sizeof got, "got %s - %s",
					uint64_to_string(start), uint64_to_string2(end));

				/* XXX: Should we check whether we can use this range
				 *		nonetheless? This addresses the problem described
				 *		here:
				 *
				 * 		http://sf.net/mailarchive/message.php?msg_id=10454795
				 */

				g_message("file \"%s\" on %s (%s): "
					"Range mismatch: wanted %s - %s, %s",
					download_outname(d),
					host_addr_port_to_string(download_addr(d),
						download_port(d)),
					download_vendor_str(d),
					uint64_to_string(d->skip),
					uint64_to_string2(d->range_end - 1),
					got);
				download_stop(d, GTA_DL_ERROR, "Range mismatch");
				return;
			}
			if (end < d->range_end - 1) {
                if (download_debug)
                    g_message(
						"file \"%s\" on %s (%s): end byte short: wanted %s, "
						"got %s (continuing anyway)",
                        download_outname(d),
                        host_addr_port_to_string(download_addr(d),
							download_port(d)),
                        download_vendor_str(d),
                        uint64_to_string(d->range_end - 1),
						uint64_to_string2(end));

				/*
				 * Make sure there is something sensible served, i.e. the
				 * upper boundary must be greater than the lower (requested)
				 * one.		--RAM, 2006-01-13
				 */

				if (d->skip >= end + 1) {
					download_stop(d, GTA_DL_ERROR,
						"Weird server-side chunk shrinking");
					return;
				}

				/*
				 * Since we're getting less than we asked for, we need to
				 * update the end/size information and mark as DL_CHUNK_EMPTY
				 * the trailing part of the range we won't be getting.
				 *		-- RAM, 15/05/2003
				 */

				file_info_clear_download(d, TRUE);
				if (d->skip != end + 1)
					file_info_update(d, d->skip, end + 1, DL_CHUNK_BUSY);

				d->range_end = end + 1;				/* The new end */
				d->size = d->range_end - d->skip;	/* Don't count overlap */
				d->flags |= DL_F_SHRUNK_REPLY;		/* Remember shrinking */

				gcu_gui_update_download_range(d);
			}
			got_content_length = TRUE;
			check_content_range = 0;		/* We validated the served range */
		} else {
            if (download_debug) {
                g_message("file \"%s\" on %s (%s): malformed Content-Range: %s",
					download_outname(d),
					host_addr_port_to_string(download_addr(d),
						download_port(d)),
					download_vendor_str(d), buf);
            }
        }
	}

	/*
	 * If we needed a Content-Range to validate the served range,
	 * but we didn't have any or could not parse it, abort!
	 */

	if (check_content_range != 0) {
		g_message("file \"%s\": expected content of %s, server %s (%s) said %s",
			download_outname(d), uint64_to_string(requested_size),
			host_addr_port_to_string(download_addr(d), download_port(d)),
			download_vendor_str(d),
			uint64_to_string2(check_content_range));
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "Content-Length mismatch");
		return;
	}

#if 0
	/*
	 * If neither Content-Length nor Content-Range was seen, abort!
	 *
	 * If we were talking to an official web-server, we'd assume the length
	 * to be correct and would be reading until EOF, but we're talking to
	 * an unknown party, that we cannot trust too much.
	 *		--RAM, 09/01/2002
	 */

	if (!got_content_length && !is_chunked) {
		const char *ua = header_get(header, "Server");
		ua = ua ? ua : header_get(header, "User-Agent");
		if (ua && download_debug)
			g_message("server \"%s\" did not send any length indication", ua);
		download_bad_source(d);
		download_stop(d, GTA_DL_ERROR, "No Content-Length header");
		return;
	}
#endif

	/*
	 * Since we may request some overlap, ensure that the server did not
	 * shrink our request to just the overlap range!
	 *		--RAM, 14/10/2003
	 */

#if 0
	/* XXX:
	 * d->size is of type guint32, and you can possibly request up to 4GB
	 */

	g_assert(d->size >= 0);
#endif

	/*
	 * Handle browse-host requests specially: there's no file to save to.
	 */

	if (d->flags & DL_F_BROWSE) {
		gnet_host_t host;

		g_assert(d->browse != NULL);

		host.addr = download_addr(d);
		host.port = download_port(d);

		if (HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
			bh_flags |= BH_DL_INFLATE;
		}
		if (is_chunked) {
			bh_flags |= BH_DL_CHUNKED;
		}

		if (
			!browse_host_dl_receive(d->browse, &host, &d->socket->wio,
				download_vendor_str(d), bh_flags)
		) {
			download_stop(d, GTA_DL_ERROR, "Search already closed");
			return;
		}

		d->bio = browse_host_io_source(d->browse);
	} else if (d->size == 0 && fi->file_size_known) {
		g_assert(d->flags & DL_F_SHRUNK_REPLY);
		download_queue_delay(d,
			MAX(delay, download_retry_busy_delay),
			_("Partial file on server, waiting"));
		return;
	}

	/*
	 * Cleanup header-reading data structures.
	 */

	io_free(d->io_opaque);
	getline_free(s->getline);		/* No longer need this */
	s->getline = NULL;

	/*
	 * Done for a browse-host request.
	 */

	if (d->flags & DL_F_BROWSE) {
		download_mark_active(d);

		/*
		 * If we have something in the socket buffer, feed it to the RX stack.
	 	 */

		if (s->pos > 0) {
			fi->recv_amount += s->pos;
			browse_host_dl_write(d->browse, s->buf, s->pos);
		}

		return;
	}

	/*
	 * Freeing of the RX stack must be asynchronous: each time we establish
	 * a new connection, dismantle the previous stack.  Otherwise the RX
	 * stack will be freed when the corresponding download structure is
	 * reclaimed.
	 */

	if (d->rx != NULL) {
		rx_free(d->rx);
		d->rx = NULL;
	}
	{
		struct rx_link_args args;
		gnet_host_t host;

		args.cb = &download_rx_link_cb;
		args.bs = bws.in;
		args.wio = &d->socket->wio;

		host.addr = download_addr(d); 
		host.port = download_port(d); 
		d->rx = rx_make(d, &host, rx_link_get_ops(), &args);
	}
	if (is_chunked) {
		struct rx_chunk_args args;

		args.cb = &download_rx_chunk_cb;
		d->rx = rx_make_above(d->rx, rx_chunk_get_ops(), &args);
	}
	if (HTTP_CONTENT_ENCODING_DEFLATE == content_encoding) {
		struct rx_inflate_args args;

		args.cb = &download_rx_inflate_cb;
		d->rx = rx_make_above(d->rx, rx_inflate_get_ops(), &args);
	}
	rx_set_data_ind(d->rx, download_data_ind);
	rx_enable(d->rx);

	/*
	 * Open output file.
	 */

	g_assert(NULL == d->out_file);

	path = make_pathname(fi->path, fi->file_name);

	d->out_file = file_object_open(path, O_WRONLY);
	if (!d->out_file) {
		gint fd = file_open_missing(path, O_RDWR);
		if (fd >= 0) {
			d->out_file = file_object_new(fd, path, O_RDWR);
		}
	}
	if (d->out_file) {

		/* File exists, we'll append the data to it */
		if (!fi->use_swarming && (fi->done != d->skip)) {
			g_message("File '%s' changed size (now %s, but was %s)",
				fi->file_name, uint64_to_string(fi->done),
				uint64_to_string2(d->skip));
			download_queue_delay(d, download_retry_stopped_delay,
				_("Stopped (Output file size changed)"));
			G_FREE_NULL(path);
			return;
		}
	} else if (!fi->use_swarming && d->skip) {
		download_stop(d, GTA_DL_ERROR, "Cannot resume: file gone");
		G_FREE_NULL(path);
		return;
	} else {
		gint fd = file_create(path, O_RDWR, DOWNLOAD_FILE_MODE);
		if (fd >= 0) {
			d->out_file = file_object_new(fd, path, O_RDWR);
		}
		if (!d->out_file) {
			const gchar *error = g_strerror(errno);
			download_stop(d, GTA_DL_ERROR, "Cannot write into file: %s", error);
			G_FREE_NULL(path);
			return;
		}
	}
	G_FREE_NULL(path);

	g_assert(d->out_file);

	/*
	 * We're ready to receive.
	 */

	download_mark_active(d);

	g_assert(s->gdk_tag == 0);
	g_assert(d->bio == NULL);

	d->bio = rx_bio_source(d->rx);

	/*
	 * If we have something in the socket buffer, feed it to the RX stack.
	 */

	if (s->pos > 0) {
		size_t n = s->pos;
		
		s->pos = 0;
		download_write(d, s->buf, n);
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
 * Read callback for file data.
 */
static gboolean
download_read(struct download *d, pmsg_t *mb)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->file_info->recvcount > 0);

	g_assert(d->socket);
	g_assert(d->file_info);

	fi = d->file_info;

	if (buffers_full(d)) {
		download_queue_delay(d, download_retry_stopped_delay,
			_("Stopped (Read buffer full)"));
		goto error;
	}

	if (fi->file_size_known) {
		g_assert(d->pos <= fi->size);

		if (d->pos == fi->size) {
			download_stop(d, GTA_DL_ERROR, "Failed (Completed?)");
			goto error;
		}
	}

	buffers_add_read(d, mb);

	d->last_update = tm_time();
	fi->recv_amount += pmsg_size(mb);

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
	d->status = GTA_DL_REQ_SENT;
	tm_now(&d->header_sent);

	gcu_gui_update_download(d, TRUE);

	/*
	 * Now prepare to read the status line and the headers.
	 * XXX separate this to swallow 100 continuations?
	 */

	g_assert(d->io_opaque == NULL);

	io_get_header(d, &d->io_opaque, bws.in, d->socket, IO_SAVE_FIRST,
		call_download_request, download_start_reading, &download_io_error);
}

/**
 * I/O callback invoked when we can write more data to the server to finish
 * sending the HTTP request.
 */
static void
download_write_request(gpointer data, gint unused_source, inputevt_cond_t cond)
{
	struct download *d = data;
	struct gnutella_socket *s;
	http_buffer_t *r;
	ssize_t sent;
	gint rw;
	gchar *base;

	(void) unused_source;
	download_check(d);

	s = d->socket;
	r = d->req;
	g_assert(s->gdk_tag);		/* I/O callback still registered */
	g_assert(r != NULL);
	g_assert(d->status == GTA_DL_REQ_SENDING);

	if (cond & INPUT_EVENT_EXCEPTION) {
		/*
		 * If download is queued with PARQ, don't stop the download on a write
		 * error or we'd loose the PARQ ID, and the download entry.  If the
		 * server contacts us back with a QUEUE callback, we could be unable
		 * to resume!
		 *		--RAM, 14/07/2003
		 */

		const gchar msg[] = "Could not send whole HTTP request";

		socket_eof(s);

		if (d->queue_status == NULL)
			download_stop(d, GTA_DL_ERROR, msg);
		else
			download_queue_delay(d, download_retry_busy_delay, msg);

		return;
	}

	rw = http_buffer_unread(r);			/* Data we still have to send */
	base = http_buffer_read_base(r);	/* And where unsent data start */

	sent = bws_write(bws.out, &s->wio, base, rw);
	if ((ssize_t) -1 == sent) {
		/*
		 * If download is queued with PARQ, etc...  [Same as above]
		 */

		static const gchar msg[] = "Write failed: %s";

		if (d->queue_status == NULL)
			download_stop(d, GTA_DL_ERROR, msg, g_strerror(errno));
		else
			download_queue_delay(d, download_retry_busy_delay,
				msg, g_strerror(errno));
		return;
	} else if (sent < rw) {
		http_buffer_add_read(r, sent);
		return;
	} else if (download_debug > 2) {
		g_message(
			"----Sent Request (%s) completely to %s (%u bytes):\n%.*s----\n",
			d->keep_alive ? "follow-up" : "initial",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			http_buffer_length(r), http_buffer_length(r), http_buffer_base(r));
	}

	/*
	 * HTTP request was completely sent.
	 */

	if (download_debug) {
		g_message("flushed partially written HTTP request to %s (%u bytes)",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			http_buffer_length(r));
    }

	socket_evt_clear(s);

	http_buffer_free(r);
	d->req = NULL;

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
	struct gnutella_socket *s = d->socket;
	fileinfo_t *fi;
	size_t rw;
	ssize_t sent;
	const gchar *sha1;

	download_check(d);

	fi = d->file_info;

	g_assert(fi);
	g_assert(fi->lifecount > 0);
	g_assert(fi->lifecount <= fi->refcount);

	if (!s)
		g_error("download_send_request(): no socket for \"%s\"",
			download_outname(d));

	/*
	 * If we have a hostname for this server, check the IP address of the
	 * socket with the one we have for this server: it may have changed if
	 * the remote server changed its IP address since last time we connected.
	 *		--RAM, 26/10/2003
	 */

	if (
		NULL != d->server->hostname &&
		!host_addr_equal(download_addr(d), s->addr)
	) {
		change_server_addr(d->server, s->addr);
		g_assert(host_addr_equal(download_addr(d), s->addr));
	}
	gcu_gui_update_download_host(d);

	/*
	 * If we have d->always_push set, yet we did not use a Push, it means we
	 * finally tried to connect directly to this server.  And we succeeded!
	 *		-- RAM, 18/08/2002.
	 */

	if (d->always_push && !DOWNLOAD_IS_IN_PUSH_MODE(d)) {
		if (download_debug > 2)
			g_message("PUSH not necessary to reach %s",
				host_addr_port_to_string(download_addr(d), download_port(d)));
		d->server->attrs |= DLS_A_PUSH_IGN;
		d->always_push = FALSE;
	}

	/*
	 * If we're swarming, pick a free chunk.
	 * (will set d->skip and d->overlap_size).
	 */

	if (fi->use_swarming) {
		g_assert(fi->file_size_known);

		/*
		 * PFSP -- client side
		 *
		 * If we're retrying after a 503/416 reply from a servent
		 * supporting PFSP, then the chunk is already chosen.
		 */

		if (d->flags & DL_F_CHUNK_CHOSEN)
			d->flags &= ~DL_F_CHUNK_CHOSEN;
		else {
			if (d->ranges != NULL && download_pick_available(d))
				goto picked;

			http_range_free(d->ranges);		/* May have changed on server */
			d->ranges = NULL;				/* Request normally */

			if (!download_pick_chunk(d))
				return;
		}
	} else if (!fi->file_size_known) {
		/* XXX -- revisit this encapsulation violation after 0.96 -- RAM */
		/* XXX (when filesize is not known, fileinfo should handle this) */
		d->skip = d->pos = fi->done;	/* XXX no overlapping here */
		d->size = 0;
	}

picked:

	g_assert(d->overlap_size <= s->buf_size);

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

	d->flags &= ~DL_F_REPLIED;			/* Will be set if we get a reply */

	/*
	 * Tell GUI about the selected range, and that we're sending.
	 */

	d->status = GTA_DL_REQ_SENDING;
	d->last_update = tm_time();

	if (!DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_add(d);
	gcu_gui_update_download(d, TRUE);

	/*
	 * Build the HTTP request.
	 */

	if (d->uri) {
		gchar *escaped_uri;

		escaped_uri = url_fix_escape(d->uri);
		rw = gm_snprintf(dl_tmp, sizeof(dl_tmp),
				"GET %s HTTP/1.1\r\n", escaped_uri);
		if (escaped_uri != d->uri) {
			G_FREE_NULL(escaped_uri);
		}
	} else if (sha1) {
		rw = gm_snprintf(dl_tmp, sizeof(dl_tmp),
			"GET /uri-res/N2R?urn:sha1:%s HTTP/1.1\r\n", sha1_base32(sha1));
	} else {
		gchar *escaped = url_escape(d->file_name);

		rw = gm_snprintf(dl_tmp, sizeof(dl_tmp),
			"GET /get/%u/%s HTTP/1.1\r\n",
			(guint) d->record_index, escaped);

		if (escaped != d->file_name)
			G_FREE_NULL(escaped);
	}

	/*
	 * If URL is too large, abort.
	 */

	if (rw >= MAX_LINE_SIZE) {
		download_stop(d, GTA_DL_ERROR, "URL too large");
		return;
	}

	rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
		"Host: %s\r\n"
		"User-Agent: %s\r\n",
		d->server->hostname
			? d->server->hostname
			: host_addr_port_to_string(download_addr(d), download_port(d)),
		(d->server->attrs & DLS_A_BANNING) ?
			download_vendor_str(d) : version_string);

	if (!(d->server->attrs & DLS_A_BANNING)) {
		header_features_generate(&xfeatures.downloads,
			dl_tmp, sizeof(dl_tmp), &rw);

		/* If we request the file by an custom URI it's most likely
		 * not a Gnutella peer.
		 */
		if (!d->uri) {
			rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
					"X-Token: %s\r\n", tok_version());
		}
	}

	if (d->flags & DL_F_BROWSE)
		rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
				"Accept: application/x-gnutella-packets\r\n");

	rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
			"Accept-Encoding: deflate\r\n");
	
	/*
	 * Add X-Queue / X-Queued information into the header
	 */
	parq_download_add_header(dl_tmp, sizeof(dl_tmp), &rw, d);

	/*
	 * If server is known to NOT support keepalives, then request only
	 * a range starting from d->skip.  Likewise if we know that the
	 * server does not support HTTP/1.1.
	 *
	 * Otherwise, we request a range and expect the server to keep the
	 * connection alive once the range has been fully served so that
	 * we may request the next chunk, if needed.
	 */

	g_assert(d->skip >= d->overlap_size);

	d->range_end = fi->file_size_known ? download_filesize(d) : (filesize_t) -1;

	if (fi->file_size_known && !(d->server->attrs & DLS_A_NO_HTTP_1_1)) {
		/*
		 * Request exact range, unless we're asking for the full file
		 */

		if (d->size != download_filesize(d)) {
			filesize_t start = d->skip - d->overlap_size;

			d->range_end = d->skip + d->size;

			rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
				"Range: bytes=%s-%s\r\n",
				uint64_to_string(start), uint64_to_string2(d->range_end - 1));
		}
	} else {
		/* Request only a lower-bounded range, if needed */

		if (d->skip > d->overlap_size)
			rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
				"Range: bytes=%s-\r\n",
				uint64_to_string(d->skip - d->overlap_size));
	}

	gcu_gui_update_download_range(d);		/* Now that we know d->range_end */

	g_assert(rw + 3U < sizeof(dl_tmp));		/* Should not have filled yet! */

	/*
	 * In any case, if we know a SHA1, we need to send it over.  If the server
	 * sees a mismatch, it will abort.
	 */

	if (sha1 != NULL) {
		gint wmesh;
		gint sha1_room;

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

		if (d->server->attrs & DLS_A_MINIMAL_HTTP)
			wmesh = 0;
		else {
			gint altloc_size = sizeof(dl_tmp) - (rw + sha1_room);
			fileinfo_t *file_info = d->file_info;

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

			if (bsched_saturated(bws.out)) {
				altloc_size = MIN(altloc_size, 160);
				if (fi_alive_count(file_info) > FI_LOW_SRC_COUNT)
					file_info = NULL;
			}

			wmesh = dmesh_alternate_location(sha1,
				&dl_tmp[rw], altloc_size,
				download_addr(d), d->last_dmesh, download_vendor(d),
				file_info, TRUE);
			rw += wmesh;

			d->last_dmesh = (guint32) tm_time();
		}

		/*
		 * HUGE specs says that the alternate locations are only defined
		 * when there is an X-Gnutella-Content-URN present.	When we use
		 * the N2R form to retrieve a resource by SHA1, that line is
		 * redundant.  We only send it if we sent mesh information.
		 */

		if (wmesh) {
			g_assert(sha1);
			rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw,
				"X-Gnutella-Content-URN: urn:sha1:%s\r\n",
				sha1_base32(sha1));
		}
	}

	rw += gm_snprintf(&dl_tmp[rw], sizeof(dl_tmp)-rw, "\r\n");

	/*
	 * Send the HTTP Request
	 */

	socket_tos_normal(s);

	if ((ssize_t) -1 == (sent = bws_write(bws.out, &s->wio, dl_tmp, rw))) {
		/*
		 * If download is queued with PARQ, don't stop the download on a write
		 * error or we'd loose the PARQ ID, and the download entry.  If the
		 * server contacts us back with a QUEUE callback, we could be unable
		 * to resume!
		 *		--RAM, 17/05/2003
		 */

		if (d->queue_status == NULL)
			download_stop(d, GTA_DL_ERROR,
				"Write failed: %s", g_strerror(errno));
		else
			download_queue_delay(d, download_retry_busy_delay,
				"Write failed: %s", g_strerror(errno));
		return;
	} else if ((size_t) sent < rw) {
		/*
		 * Could not send the whole request, probably because the TCP output
		 * path is clogged.
		 */

		g_message("Partial HTTP request write to %s: wrote %u out of %u bytes",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			(guint) sent, (guint) rw);

		g_assert(d->req == NULL);

		d->req = http_buffer_alloc(dl_tmp, rw, sent);

		/*
		 * Install the writing callback.
		 */

		g_assert(s->gdk_tag == 0);

		socket_evt_set(s, INPUT_EVENT_WX, download_write_request, d);
		return;
	} else if (download_debug > 2) {
		g_message("----Sent Request (%s%s%s%s) to %s (%u bytes):\n%.*s----\n",
			d->keep_alive ? "follow-up" : "initial",
			(d->server->attrs & DLS_A_NO_HTTP_1_1) ? "" : ", HTTP/1.1",
			(d->server->attrs & DLS_A_PUSH_IGN) ? ", ign-push" : "",
			(d->server->attrs & DLS_A_MINIMAL_HTTP) ? ", minimal" : "",
			host_addr_port_to_string(download_addr(d), download_port(d)),
			(guint) rw, (gint) rw, dl_tmp);
	}

	download_request_sent(d);
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
		g_message("file \"%s\": push reply was not followed by an empty line",
			download_outname(d));
		dump_hex(stderr, "Extra GIV data", getline_str(empty), MIN(len, 80));
		download_stop(d, GTA_DL_ERROR, "Malformed push reply");
		return;
	}

	/*
	 * Free up the s->getline structure which holds the GIV line.
	 */

	g_assert(d->socket->getline);
	getline_free(d->socket->getline);
	d->socket->getline = NULL;

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
select_push_download(GSList *servers)
{
	GSList *sl;
	time_t now = tm_time();
	struct download *d = NULL;
	gint found = 0;		/* No a boolean to trace where it was found from */

	/*
	 * We do not limit by download slots for GIV... Indeed, pushes are
	 * precious little things.  We must peruse the connection we got
	 * because we don't know whether we'll be able to get another one.
	 * This is where it is nice that the remote end supports queuing... and
	 * PARQ will work either way (i.e. active or passive queuing, since
	 * then we'll get QUEUE callbacks).
	 *		--RAM, 19/07/2003
	 */

	for (sl = servers; sl; sl = g_slist_next(sl)) {
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

			if (d->socket == NULL && DOWNLOAD_IS_EXPECTING_GIV(d)) {
				if (download_debug > 1) g_message(
					"GIV: selected active download \"%s\" from %s at %s <%s>",
					download_outname(d), guid_hex_str(server->key->guid),
					host_addr_port_to_string(download_addr(d),
						download_port(d)),
					download_vendor_str(d));
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
			g_assert(!DOWNLOAD_IS_RUNNING(d));
			g_assert(d->file_info);

			if (
				!d->file_info->use_swarming &&
				count_running_downloads_with_name(download_outname(d)) != 0
			)
				continue;

			if (delta_time(now, d->retry_after) < 0)
				break;		/* List is sorted */

			if (d->flags & DL_F_SUSPENDED)
				continue;

			if (download_debug > 2) g_message(
				"GIV: will try alternate download \"%s\" from %s at %s <%s>",
				download_outname(d), guid_hex_str(server->key->guid),
				host_addr_port_to_string(download_addr(d),
					download_port(d)),
				download_vendor_str(d));

			g_assert(d->socket == NULL);

			/* Potential candidates are recorded into a new list because
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
				d->status = GTA_DL_CONNECTING;
				if (!DOWNLOAD_IS_VISIBLE(d))
					gcu_download_gui_add(d);

				gcu_gui_update_download(d, TRUE);
				gnet_prop_set_guint32_val(PROP_DL_ACTIVE_COUNT, dl_active);
				gnet_prop_set_guint32_val(PROP_DL_RUNNING_COUNT,
					count_running_downloads());

				if (download_debug > 1) g_message("GIV: "
					"selected alternate download \"%s\" from %s at %s <%s>",
					download_outname(d), guid_hex_str(server->key->guid),
					host_addr_port_to_string(download_addr(d),
						download_port(d)),
					download_vendor_str(d));

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
	const gchar *guid;			/* The GUID that must match */
	host_addr_t addr;			/* The IP address that must match */
	GSList *servers;			/* List of servers matching criteria */
	gint count;					/* Amount of servers inserted */
};

/**
 * If server is matching the selection criteria, insert it in the
 * result set.
 *
 * This routine is a hash table iterator callback.
 */
static void
select_matching_servers(gpointer key, gpointer value, gpointer user)
{
	const struct dl_key *skey = key;
	struct dl_server *server = value;
	struct server_select *ctx = user;

	g_assert(server->key->guid == skey->guid);	/* They're atoms! */

	if (
		guid_eq(skey->guid, ctx->guid) ||
		host_addr_equal(skey->addr, ctx->addr)
	) {
		ctx->servers = g_slist_prepend(ctx->servers, server);
		ctx->count++;
	}
}

/**
 * Given a servent GUID and an IP address, build a list of all the servents
 * that bear either this GUID or that IP address.
 *
 * @return a list a servers matching, with `count' being updated with the
 * amount of matching servers we found.

 * @note	It is up to the caller to g_slist_free() the returned list.
 */
static GSList *
select_servers(const gchar *guid, const host_addr_t addr, gint *count)
{
	struct server_select ctx;

	ctx.guid = guid;
	ctx.addr = addr;
	ctx.servers = NULL;
	ctx.count = 0;

	g_hash_table_foreach(dl_by_host, select_matching_servers, &ctx);

	*count = ctx.count;
	return ctx.servers;
}

/**
 * @return FALSE on failure, TRUE if the GIV was successfully parsed.
 */
static gboolean
parse_giv(const gchar *line, gchar *hex_guid, size_t size)
{
	static const guint hex_guid_len = 32;
	const gchar *endptr;
	guint i;
	gint error;

	g_return_val_if_fail(line, FALSE);
	g_return_val_if_fail(hex_guid, FALSE);
	g_return_val_if_fail(size > hex_guid_len, FALSE);

	endptr = is_strprefix(line, "GIV ");
	if (!endptr)
		return FALSE;

	/* A file index must be given but we don't care about its value. */
	(void) parse_uint32(endptr, &endptr, 10, &error);
	if (error || ':' != *endptr)
		return FALSE;

	endptr++;
	for (i = 0; i < hex_guid_len; i++) {
		gchar c = *endptr++;

		if (!is_ascii_xdigit(c))
			return FALSE;
		hex_guid[i] = c;
	}
	hex_guid[i] = '\0';

	return '/' == *endptr;
}

/**
 * Initiate download on the remotely initiated connection.
 *
 * This is called when an incoming "GIV" request is received in answer to
 * some of our pushes.
 */
void
download_push_ack(struct gnutella_socket *s)
{
	struct download *d = NULL;
	const gchar *giv;
	gchar hex_guid[33];			/* The hexadecimal GUID */
	gchar guid[GUID_RAW_SIZE];	/* The decoded (binary) GUID */
	GSList *servers;			/* Potential targets for the download */
	gint count;					/* Amount of potential targets found */

	g_assert(s->getline);
	giv = getline_str(s->getline);

	gnet_stats_count_general(GNR_GIV_CALLBACKS, 1);

	if (download_debug > 2)
		g_message("----Got GIV from %s:\n%s\n----",
			host_addr_to_string(s->addr), giv);

	/*
	 * To find out which download this is, we have to parse the incoming
	 * GIV request, which is stored in "s->getline".
	 */
	if (!parse_giv(giv, hex_guid, sizeof hex_guid)) {
		g_warning("malformed GIV string \"%s\" from %s",
			giv, host_addr_to_string(s->addr));
		goto discard;
	}

	/*
	 * Look for a recorded download.
	 */

	if (!hex_to_guid(hex_guid, guid)) {
		g_warning("discarding GIV with malformed GUID %s from %s",
			hex_guid, host_addr_to_string(s->addr));
		goto discard;
	}

	/*
	 * Identify the targets for this download.
	 */

	servers = select_servers(guid, s->addr, &count);

	switch (count) {
	case 0:
		g_warning("discarding GIV: found no host bearing GUID %s or at %s",
			hex_guid, host_addr_to_string(s->addr));
		goto discard;
	case 1:
		break;
	default:
		g_warning("found %d possible targets for GIV from GUID %s at %s",
			count, hex_guid, host_addr_to_string(s->addr));
		if (download_debug) {
			GSList *sl;
			guint i;

			for (sl = servers, i = 0; sl; sl = g_slist_next(sl), i++) {
				struct dl_server *serv = sl->data;
				g_message("  #%u is GUID %s at %s <%s>",
					i + 1, guid_hex_str(serv->key->guid),
					host_addr_port_to_string(serv->key->addr, serv->key->port),
					serv->vendor ? serv->vendor : "");
			}
		}
		break;
	}

	d = select_push_download(servers);
	g_slist_free(servers);

	if (d) {
		download_check(d);
	} else {
		g_warning("discarded GIV \"%s\" from %s",
			giv, host_addr_to_string(s->addr));
		goto discard;
	}

	if (download_debug)
		g_message("mapped GIV \"%s\" to \"%s\" from %s <%s>",
			giv, download_outname(d), host_addr_to_string(s->addr),
			download_vendor_str(d));

	/*
	 * Install socket for the download.
	 */

	g_assert(d->socket == NULL);

	d->got_giv = TRUE;
	d->last_update = tm_time();
	d->socket = s;
	s->resource.download = d;

	/*
	 * Since we got a GIV, we now know the remote IP of the host.
	 */

	if (!host_addr_equal(download_addr(d), s->addr))
		change_server_addr(d->server, s->addr);

	g_assert(host_addr_equal(download_addr(d), s->addr));

	gcu_gui_update_download_host(d);

	/*
	 * Now we have to read that trailing "\n" which comes right afterwards.
	 */

	g_assert(NULL == d->io_opaque);
	io_get_header(d, &d->io_opaque, bws.in, s, IO_SINGLE_LINE,
		call_download_push_ready, NULL, &download_io_error);

	return;

discard:
	g_assert(s->resource.download == NULL);	/* Hence socket_free() below */
	socket_free_null(&s);
}

void
download_retry(struct download *d)
{
	download_check(d);

	/* download_stop() sets the time, so all we need to do is set the delay */

	if (d->timeout_delay == 0)
		d->timeout_delay = download_retry_timeout_min;
	else {
		d->timeout_delay *= 2;
		if (d->start_date) {
			/* We forgive a little while the download is working */
			d->timeout_delay -= delta_time(tm_time(), d->start_date) / 10;
		}
	}

	if (d->timeout_delay < download_retry_timeout_min)
		d->timeout_delay = download_retry_timeout_min;
	if (d->timeout_delay > download_retry_timeout_max)
		d->timeout_delay = download_retry_timeout_max;

	download_stop(d, GTA_DL_TIMEOUT_WAIT, no_reason);
}

/**
 * Find a waiting download on the specified server, identified by its IP:port
 * for which we have no PARQ information yet.
 *
 * @returns NULL if none, the download we found otherwise.
 */
struct download *
download_find_waiting_unparq(const host_addr_t addr, guint16 port)
{
	struct dl_server *server = get_server(blank_guid, addr, port, FALSE);
	list_iter_t *iter;
	struct download *d = NULL;
	gboolean found = FALSE;

	if (server == NULL)
		return NULL;

	g_assert(dl_server_valid(server));

	iter = list_iter_before_head(server->list[DL_LIST_WAITING]);
	while (list_iter_has_next(iter)) {

		d = list_iter_next(iter);
		download_check(d);
		g_assert(!DOWNLOAD_IS_RUNNING(d));

		if (d->flags & DL_F_SUSPENDED)		/* Suspended, cannot pick */
			continue;

		if (d->queue_status == NULL) {		/* No PARQ information yet */
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

static const gchar *download_file = "downloads";
static gboolean retrieving = FALSE;

/**
 * Store all pending downloads that are not in PUSH mode (since we'll loose
 * routing information when we quit).
 *
 * The downloads are normally stored in ~/.gtk-gnutella/downloads.
 */
static void
download_store(void)
{
	FILE *out;
	const GSList *sl;
	file_path_t fp;

	if (retrieving)
		return;

	file_path_set(&fp, settings_config_dir(), download_file);
	out = file_config_open_write(file_what, &fp);

	if (!out)
		return;

	file_config_preamble(out, "Downloads");

	fputs(	"#\n# Format is:\n"
			"#   File name\n"
			"#   size, index[:GUID], IP:port[, hostname]\n"
			"#   SHA1 or * if none\n"
			"#   PARQ id or * if none\n"
			"#   FILE_SIZE_KNOWN true or false \n"
			"#   <blank line>\n"
			"#\n\n"
			"RECLINES=4\n\n", out);

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		const gchar *id, *guid, *hostname;

		download_check(d);

		if (d->status == GTA_DL_DONE || d->status == GTA_DL_REMOVED)
			continue;
		if (d->always_push)
			continue;
		if (d->flags & DL_F_TRANSIENT)
			continue;
		if (d->uri) {
			/* XXX: If we have a custom URI, we have to store this URI
			 *		and load it on startup. Currently, the URI isn't
			 *		stored and we would create a bogus URI from the
			 *		SHA1 or the index. */
			continue;
		}

		id = get_parq_dl_id(d);
		guid = has_blank_guid(d) ? NULL : download_guid(d);
		hostname = d->server->hostname;

		/* XXX: TLS? */
		fprintf(out,
			"%s\n" /* File name */
			"%s, %u%s%s, %s%s%s\n" /* size,index,ip:port[,hostname] */
			"%s\n" /* SHA1 */
			"%s\n" /* PARQ id */
			"\n\n",
			d->escaped_name,
			uint64_to_string(d->file_info->size), d->record_index,
			guid == NULL ? "" : ":", guid == NULL ? "" : guid_hex_str(guid),
			host_addr_port_to_string(download_addr(d), download_port(d)),
			hostname == NULL ? "" : ", ", hostname == NULL ? "" : hostname,
			d->file_info->sha1 ? sha1_base32(d->file_info->sha1) : "*",
			id != NULL ? id : "*"
		);
	}

	file_config_close(out, &fp);
	download_dirty = FALSE;
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
	if (download_dirty) {
		download_store();
		file_info_store_if_dirty();
	}
}

/**
 * Retrieve download list and requeue each download.
 * The downloads are normally retrieved from ~/.gtk-gnutella/downloads.
 */
static void
download_retrieve(void)
{
	FILE *in;
	filesize_t d_size = 0;	/* The d_ vars are what we deserialize */
	guint64 size64;
	gint error;
	gchar *d_name;
	host_addr_t d_addr;
	guint16 d_port;
	guint32 d_index = 0;
	guint32 flags;
	gchar d_hexguid[33];
	gchar d_hostname[256];	/* Server hostname */
	gint recline;			/* Record line number */
	guint line;				/* File line number */
	gchar d_guid[GUID_RAW_SIZE];
	gchar sha1_digest[SHA1_RAW_SIZE];
	gboolean has_sha1 = FALSE;
	gint maxlines = -1;
	file_path_t fp;
	gboolean allow_comments = TRUE;
	gchar *parq_id = NULL;
	const gchar *endptr;
	struct download *d;

	file_path_set(&fp, settings_config_dir(), download_file);
	in = file_config_open_read(file_what, &fp, 1);

	if (!in)
		return;

	/*
	 * Retrieval algorithm:
	 *
	 * Lines starting with a # are skipped.
	 *
	 * We read the ines that make up each serialized record, and
	 * recreate the download.  We stop as soon as we encounter an
	 * error.
	 */

	retrieving = TRUE;			/* Prevent download_store() runs */

	line = recline = 0;
	d_name = NULL;
	flags = 0;

	while (fgets(dl_tmp, sizeof(dl_tmp) - 1, in)) { /* Room for trailing NUL */
		line++;

		if (dl_tmp[0] == '#' && allow_comments)
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

		if (dl_tmp[0] == '\n') {
			if (recline == 0)
				continue;			/* Allow arbitrary blank lines */

			g_message("download_retrieve(): "
				"Unexpected empty line #%u, aborting", line);
			goto out;
		}

		recline++;					/* We're in a record */

		switch (recline) {
		case 1:						/* The file name */
			(void) str_chomp(dl_tmp, 0);
			/* Un-escape in place */
			if (!url_unescape(dl_tmp, TRUE)) {
				g_message("download_retrieve(): "
					"Invalid escaping in line #%u, aborting", line);
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
				g_message("download_retrieve(): "
					"cannot parse line #%u: %s", line, dl_tmp);
				goto out;
			}

			d_size = size64;
			if ((guint64) d_size != size64) {
				g_message("download_retrieve(): "
					"filesize is too large in line #%u: %s", line, dl_tmp);
				goto out;
			}

			/* skip "<filesize>," for sscanf() */
			g_assert(endptr != dl_tmp);
			g_assert(*endptr == ',');
			endptr = skip_ascii_blanks(++endptr);

			d_index = parse_uint32(endptr, &endptr, 10, &error);
			if (error || NULL == strchr(":,", *endptr)) {
				g_message("download_retrieve(): "
					"cannot parse index in line #%u: %s", line, dl_tmp);
				goto out;
			}

			if (',' == *endptr) {
				memset(d_hexguid, '0', 32);		/* GUID missing -> blank */
				d_hexguid[32] = '\0';
			} else {
				g_assert(':' == *endptr);
				endptr++;

				strncpy(d_hexguid, endptr, sizeof d_hexguid);
				d_hexguid[32] = '\0';
				endptr += strlen(d_hexguid);
			}

			if (',' != *endptr) {
				g_message("download_retrieve(): "
					"expected ',' in line #%u: %s", line, dl_tmp);
				goto out;
			}
			endptr = skip_ascii_blanks(++endptr);

			if (!string_to_host_addr_port(endptr, &endptr, &d_addr, &d_port)) {
				g_message("download_retrieve(): "
					"bad IP:port at line #%u: %s", line, dl_tmp);
				d_port = 0;
				d_addr = ipv4_unspecified;
				/* Will drop download when scheduling it */
				flags |= SOCK_F_PUSH;
			}

			if (',' == *endptr) {
				const gchar *end = &d_hostname[sizeof d_hostname - 1];
				gchar c, *s = d_hostname;

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
				!base32_decode_into(dl_tmp, SHA1_BASE32_SIZE,
					sha1_digest, sizeof(sha1_digest))
			) {
				g_message("download_retrieve(): "
					"bad base32 SHA1 '%32s' at line #%u, ignoring",
					dl_tmp, line);
			} else
				has_sha1 = TRUE;
		no_sha1:
			if (maxlines == 3)
				break;
			continue;
		case 4:						/* PARQ id, or "*" if none */
			if (maxlines != 4) {
				g_message("download_retrieve(): "
					"Can't handle %d lines in records, aborting", maxlines);
				goto out;
			}
			if (dl_tmp[0] != '*') {
				(void) str_chomp(dl_tmp, 0);		/* Strip final "\n" */
				parq_id = g_strdup(dl_tmp);
			}
			break;
		default:
			g_message("download_retrieve(): "
				"Too many lines for record at line #%u, aborting", line);
			goto out;
		}

		/*
		 * At the last line of the record.
		 */

		if (!hex_to_guid(d_hexguid, d_guid)) {
			g_message("download_rerieve(): Malformed GUID %s near line #%u",
				d_hexguid, line);
        }

		/*
		 * Download is created with a timestamp of `MAGIC_TIME' so that it is
		 * very old and the entry does not get added to the download mesh yet.
		 * Also, this is used as a signal to NOT update the "ntime" field
		 * in the fileinfo.
		 */

		if (dbg)
			g_message("DOWNLOAD '%s' (%s bytes) from %s (%s) SHA1=%s",
				d_name, uint64_to_string(d_size), host_addr_to_string(d_addr),
				d_hostname, has_sha1 ? sha1_base32(sha1_digest) : "<none>");

		d = create_download(d_name, NULL, d_size, d_index, d_addr,
				d_port, d_guid, d_hostname, has_sha1 ? sha1_digest : NULL,
				1, FALSE, TRUE, NULL, NULL, flags);

		if (d == NULL) {
			if (download_debug)
				g_message("Ignored dup download at line #%d (server %s)",
					line - maxlines + 1,
					host_addr_port_to_string(d_addr, d_port));
			goto next_entry;
		}

		/*
		 * Record PARQ id if present, so we may answer QUEUE callbacks.
		 */

		if (parq_id != NULL) {
			d->queue_status = parq_dl_create(d);
			parq_dl_add_id(d, parq_id);
		}

		/*
		 * Don't free `d_name', we gave it to create_download()!
		 */

	next_entry:
		d_name = NULL;
		flags = 0;
		recline = 0;				/* Mark the end */
		has_sha1 = FALSE;
		G_FREE_NULL(parq_id);
	}

out:
	retrieving = FALSE;			/* Re-enable download_store() runs */

	if (d_name)
		atom_str_free(d_name);

	fclose(in);
	download_store();			/* Persist what we have retrieved */
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
	 * If it was a faked download, we cannot resume.
	 */

	if (is_faked_download(d)) {
		g_message("SHA1 mismatch for \"%s\", and cannot restart download",
			download_outname(d));
	} else {
		g_message("SHA1 mismatch for \"%s\", will be restarting download",
			download_outname(d));

		d->file_info->lifecount++;				/* Reactivate download */
		file_info_reset(d->file_info);
		download_queue(d, _("SHA1 mismatch detected"));
	}
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
download_move(struct download *d, const gchar *dir, const gchar *ext)
{
	fileinfo_t *fi;
	gchar *dest = NULL;
	gchar *src = NULL;
	gboolean common_dir;
	const gchar *name;

	download_check(d);
	g_assert(FILE_INFO_COMPLETE(d->file_info));
	g_assert(DOWNLOAD_IS_STOPPED(d));

	d->status = GTA_DL_MOVING;
	fi = d->file_info;

	src = make_pathname(fi->path, fi->file_name);
	if (NULL == src)
		goto error;

	/*
	 * Don't keep an URN-like name when the file is done, if possible.
	 */

	name = file_info_readable_filename(fi);

	/*
	 * If the target directory is the same as the source directory, we'll
	 * use the supplied extension and simply rename the file.
	 */

	if (0 == strcmp(dir, fi->path)) {
		dest = unique_filename(dir, name, ext, NULL);
		if (NULL == dest || -1 == rename(src, dest))
			goto error;
		goto renamed;
	}

	/*
	 * Try to rename() the file, in case both the source and the target
	 * directory are on the same filesystem.  We usually ignore `ext' at
	 * this point since we know the target directory is distinct from the
	 * source, unless the good/bad directories are identical.
	 */

	common_dir = (0 == strcmp(move_file_path, bad_file_path));

	dest = unique_filename(dir, name, common_dir ? ext : "", NULL);
	if (NULL == dest)
		goto error;

	if (-1 != rename(src, dest))
		goto renamed;

	/*
	 * The only error we allow is EXDEV, meaning the source and the
	 * target are not on the same file system.
	 */

	if (errno != EXDEV)
		goto error;

	/*
	 * Have to move the file asynchronously.
	 */

	d->status = GTA_DL_MOVE_WAIT;
	move_queue(d, dir, common_dir ? ext : "");

	if (!DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_add(d);

	gcu_gui_update_download(d, TRUE);

	goto cleanup;

error:
	g_message("Cannot rename %s as %s: %s", src, dest, g_strerror(errno));
	download_move_error(d);
	goto cleanup;

renamed:

	file_info_strip_binary_from_file(fi, dest);
	download_move_done(d, 0);
	goto cleanup;

cleanup:

	G_FREE_NULL(src);
	G_FREE_NULL(dest);
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

	d->status = GTA_DL_MOVING;
	d->file_info->copied = 0;

	gcu_gui_update_download(d, TRUE);
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
download_move_done(struct download *d, guint elapsed)
{
	fileinfo_t *fi;

	download_check(d);
	g_assert(d->status == GTA_DL_MOVING);

	d->status = GTA_DL_DONE;
	d->last_update = tm_time();
	fi = d->file_info;
	fi->copy_elapsed = elapsed;
	fi->copied = fi->size;
	file_info_changed(fi);
	gcu_gui_update_download(d, TRUE);

	/*
	 * File was unlinked by rename() if we were on the same filesystem,
	 * or by the moving daemon task upon success.
	 */

	if (!has_good_sha1(d))
		download_moved_with_bad_sha1(d);
}

/**
 * Called when we cannot move the file (I/O error, etc...).
 */
void
download_move_error(struct download *d)
{
	fileinfo_t *fi;
	const gchar *ext;
	gchar *src;
	gchar *dest;
	const gchar *name;

	download_check(d);
	g_assert(d->status == GTA_DL_MOVING);

	/*
	 * If download is "good", rename it inplace as DL_OK_EXT, otherwise
	 * rename it as DL_BAD_EXT.
	 *
	 * Don't keep an URN-like name when the file is done, if possible.
	 */

	fi = d->file_info;
	name = file_info_readable_filename(fi);

	src = make_pathname(fi->path, fi->file_name);
	ext = has_good_sha1(d) ? DL_OK_EXT : DL_BAD_EXT;
	dest = unique_filename(fi->path, name, ext, NULL);

	file_info_strip_binary(fi);

	if (NULL == src || NULL == dest || -1 == rename(src, dest)) {
		g_message("Could not rename \"%s\" as \"%s\": %s",
			src, dest, g_strerror(errno));
		d->status = GTA_DL_DONE;
	} else {
		g_message("Completed \"%s\" left at \"%s\"", name, dest);
		download_move_done(d, 0);
	}
	G_FREE_NULL(src);
	G_FREE_NULL(dest);
}

/***
 *** SHA1 verification routines.
 ***/

/**
 * Main entry point for verifying the SHA1 of a completed download.
 */
static void
download_verify_sha1(struct download *d)
{
	download_check(d);
	g_assert(FILE_INFO_COMPLETE(d->file_info));
	g_assert(DOWNLOAD_IS_STOPPED(d));
	g_assert(!DOWNLOAD_IS_VERIFYING(d));
	g_assert(!(d->flags & DL_F_SUSPENDED));
	g_assert(d->list_idx == DL_LIST_STOPPED);

	if (d->flags & DL_F_TRANSIENT) {
		file_info_changed(d->file_info);		/* Update status! */
		return;
	}

	/*
	 * Even if download was aborted or in error, we have a complete file
	 * anyway, so start verifying its SHA1.
	 */

	d->status = GTA_DL_VERIFY_WAIT;

	queue_suspend_downloads_with_file(d->file_info, TRUE);
	verify_queue(d);

	if (!DOWNLOAD_IS_VISIBLE(d))
		gcu_download_gui_add(d);

	gcu_gui_update_download(d, TRUE);
}

/**
 * Called when the verification daemon task starts processing a download.
 */
void
download_verify_start(struct download *d)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFY_WAIT);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	d->status = GTA_DL_VERIFYING;
	d->file_info->cha1_hashed = 0;

	gcu_gui_update_download(d, TRUE);
}

/**
 * Called to register the current verification progress.
 */
void
download_verify_progress(struct download *d, guint32 hashed)
{
	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	d->file_info->cha1_hashed = hashed;
	file_info_changed(d->file_info);
}

/**
 * Called when download verification is finished and digest is known.
 */
void
download_verify_done(struct download *d, gchar *digest, guint elapsed)
{
	fileinfo_t *fi;
	const gchar *name;
	gchar *src = NULL;

	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);
	g_assert(d->list_idx == DL_LIST_STOPPED);

	fi = d->file_info;
	name = file_info_readable_filename(fi);
	fi->cha1 = atom_sha1_get(digest);
	fi->cha1_elapsed = elapsed;
	fi->cha1_hashed = fi->size;
	file_info_store_binary(fi);		/* Resync with computed SHA1 */
	file_info_changed(fi);

	d->status = GTA_DL_VERIFIED;
	gcu_gui_update_download(d, TRUE);

	ignore_add_sha1(name, fi->cha1);

	if (has_good_sha1(d)) {
		ignore_add_filesize(name, d->file_info->size);
		queue_remove_downloads_with_file(d->file_info, d);
		download_move(d, move_file_path, DL_OK_EXT);

		/* Send a notification */
		src = make_pathname(move_file_path, d->file_info->file_name);
		dbus_util_send_message(DBS_EVT_DOWNLOAD_DONE, src);
		G_FREE_NULL(src);
	} else {
		download_move(d, bad_file_path, DL_BAD_EXT);
		/* Will go to download_moved_with_bad_sha1() upon completion */
	}
}

/**
 * Called when we cannot verify the SHA1 for the file (I/O error, etc...).
 */
void
download_verify_error(struct download *d)
{
	fileinfo_t *fi;
	const gchar *name;

	download_check(d);
	g_assert(d->status == GTA_DL_VERIFYING);

	fi = d->file_info;
	name = file_info_readable_filename(fi);

	if (0 == strcmp(fi->file_name, name))
		g_message("error while verifying SHA1 for \"%s\"", fi->file_name);
	else {
		g_message("error while verifying SHA1 for \"%s\" (aka \"%s\")",
			fi->file_name, name);
    }

	d->status = GTA_DL_VERIFIED;
	fi->cha1_hashed = fi->size;
	file_info_changed(fi);

	ignore_add_filesize(name, fi->size);
	queue_remove_downloads_with_file(fi, d);
	download_move(d, move_file_path, DL_UNKN_EXT);
	gcu_gui_update_download(d, TRUE);
}

/**
 * Go through the downloads and check the completed ones that should
 * be either moved to the "done" directory, or which should have their
 * SHA1 computed/verified.
 */
static void
download_resume_bg_tasks(void)
{
	GSList *sl;
	GSList *to_remove = NULL;			/* List of fileinfos to remove */

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		fileinfo_t *fi;

		download_check(d);
		fi = d->file_info;

		if (d->status == GTA_DL_REMOVED)	/* Pending free, ignore it! */
			continue;

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

		if (fi->flags & FI_F_SUSPEND)	/* Already computing SHA1 or moving */
			continue;

		if (DOWNLOAD_IS_QUEUED(d))
			download_unqueue(d);

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

			d->status = GTA_DL_VERIFIED;		/* Does not mean good SHA1 */
			queue_suspend_downloads_with_file(fi, TRUE);

			if (has_good_sha1(d))
				download_move(d, move_file_path, DL_OK_EXT);
			else
				download_move(d, bad_file_path, DL_BAD_EXT);
			to_remove = g_slist_prepend(to_remove, d->file_info);
		}

		gcu_gui_update_download(d, TRUE);
	}

	/*
	 * Remove queued downloads referencing a complete file.
	 */

	for (sl = to_remove; sl; sl = g_slist_next(sl)) {
		fileinfo_t *fi = sl->data;
		g_assert(FILE_INFO_COMPLETE(fi));
		queue_remove_downloads_with_file(fi, NULL);
	}

	g_slist_free(to_remove);
	to_remove = NULL;

	/*
	 * Clear the marks.
	 */

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		fileinfo_t *fi;

		download_check(d);
		fi = d->file_info;

		if (d->status == GTA_DL_REMOVED)	/* Pending free, ignore it! */
			continue;

		fi->flags &= ~FI_F_MARK;
	}
}

/**
 * Terminating processing, cleanup data structures.
 */
void
download_close(void)
{
	GSList *sl;

	download_store();			/* Save latest copy */
	download_freeze_queue();
	download_free_removed();

	for (sl = sl_downloads; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;

		download_check(d);
		if (DOWNLOAD_IS_VISIBLE(d))
			gcu_download_gui_remove(d);
		if (d->buffers) {
			if (d->buffers->held > 0)
				download_flush(d, NULL, FALSE);
			buffers_free(d);
		}
		if (d->push)
			download_push_remove(d);
		if (d->io_opaque)
			io_free(d->io_opaque);
		if (d->bio)
			bsched_source_remove(d->bio);
		socket_free_null(&d->socket);
		download_set_sha1(d, NULL);
		if (d->ranges)
			http_range_free(d->ranges);
		if (d->req)
			http_buffer_free(d->req);
		if (d->cproxy)
			cproxy_free(d->cproxy);
		if (d->browse != NULL)
			browse_host_dl_free(d->browse);

		file_info_remove_source(d->file_info, d, TRUE);
		parq_dl_remove(d);
		download_remove_from_server(d, TRUE);
		atom_str_free_null(&d->escaped_name);
		atom_str_free_null(&d->file_name);
		file_object_release(&d->out_file);	/* Close output file */

		download_free(&d);
	}

	file_info_store();		/* Now that pending data was flushed */

	/*
	 * FIXME:
	 * It would be much cleaner if all downloads would be properly freed
	 * by calling download_free because thier handles would then be
	 * freed and we can assert that the src_handle_map is empty when
	 * src_close is called. (see src_close)
	 * -- Richard, 24 Mar 2003
	 */

	src_close();

	g_slist_free(sl_downloads);
	sl_downloads = NULL;
	g_slist_free(sl_unqueued);
	sl_unqueued = NULL;

	pool_free(buffer_pool);
	buffer_pool = NULL;

	/* XXX free & check other hash tables as well.
	 * dl_by_addr, dl_by_host
	 */
}

/**
 * Creates a URL which points to a downloads (e.g. you can move this to a
 * browser and download the file there with this URL).
 * @return NULL on failure, an URL string which must be freed with g_free().
 */
gchar *
download_build_url(const struct download *d)
{
	const gchar *sha1;
	gchar *url;

	g_return_val_if_fail(d, NULL);
	download_check(d);

	sha1 = d->sha1 ? d->sha1 : d->file_info->sha1;

	if (!is_host_addr(download_addr(d)) || 0 == download_port(d))
		return NULL;

	/* XXX: "https:" when TLS is possible? */

	if (d->browse) {
		url = g_strdup_printf("http://%s/",
			host_addr_port_to_string(download_addr(d), download_port(d)));
	} else if (d->uri) {
		url = g_strdup(d->uri);
	} else if (sha1) {
		url = g_strdup_printf("http://%s/uri-res/N2R?urn:sha1:%s",
			 host_addr_port_to_string(download_addr(d), download_port(d)),
			 sha1_base32(sha1));
	} else {
		gchar *buf = url_escape(d->file_name);

		url = g_strdup_printf("http://%s/get/%u/%s",
		   		host_addr_port_to_string(download_addr(d), download_port(d)),
		   		d->record_index, buf);

		/*
	 	* Since url_escape() creates a new string ONLY if
	 	* escaping is necessary, we have to check this and
	 	* free memory accordingly.
	 	* -- Richard, 30 Apr 2002
	 	*/

		if (buf != d->file_name)
			G_FREE_NULL(buf);
	}

	return url;
}

const gchar *
download_get_hostname(const struct download *d)
{
	static gchar buf[MAX_HOSTLEN + UINT16_DEC_BUFLEN + sizeof ": (E)"];
	gboolean encrypted;
	host_addr_t addr;
	guint port;
	const gchar *enc;

	download_check(d);
	if (is_faked_download(d))
		return "";

	if (d->socket) {
		addr = d->socket->addr;
		port = d->socket->port;
		encrypted = 0 != SOCKET_USES_TLS(d->socket);
	} else {
		addr = download_addr(d);
		port = download_port(d);
		encrypted = 0 != (d->cflags & SOCK_F_TLS);
	}

	enc = encrypted ? " (E)" : "";
	if (d->server->hostname)
		gm_snprintf(buf, sizeof buf, "%s:%u%s", d->server->hostname, port, enc);
	else
		concat_strings(buf, sizeof buf,
			host_addr_port_to_string(addr, port), enc, (void *) 0);

	return buf;
}

gint
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
gboolean
download_something_to_clear(void)
{
	const GSList *sl;
	gboolean clear = FALSE;

	for (sl = sl_unqueued; !clear && sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;

		download_check(d);
		switch (d->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
		case GTA_DL_DONE:
			clear = TRUE;
			break;
		default:
			break;
		}
	}

	return clear;
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
 * @param name		the stringified "addr:port" of the host.
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
download_browse_start(const gchar *name, const gchar *hostname,
	host_addr_t addr, guint16 port, const gchar *guid,
	const gnet_host_vec_t *proxies, gnet_search_t search, guint32 flags)
{
	struct download *d;
	fileinfo_t *fi;
	gchar *dname;

	if (!host_addr_initialized(addr))
		return FALSE;

	gm_snprintf(dl_tmp, sizeof dl_tmp, _("<Browse Host %s>"), name);

	dname = atom_str_get(dl_tmp);
	fi = file_info_get_browse(dname);

	if (!guid)
		guid = blank_guid;

	d = create_download(dname, "/", 0, 0, addr, port, guid, hostname,
			NULL, tm_time(), TRUE, FALSE, fi, proxies, flags);

	atom_str_free(dname);

	if (d != NULL) {
		gnet_host_t host;

		download_check(d);

		d->flags |= DL_F_TRANSIENT | DL_F_BROWSE;
		host.addr = addr;
		host.port = port;

		d->browse = browse_host_dl_create(d, &host, search);
		file_info_changed(fi);		/* Update status! */
	} else
		file_info_remove(fi);

	return d;
}

/**
 * Abort browse-hosst download when corresponding search is closed.
 */
void
download_abort_browse_host(gpointer download, gnet_search_t sh)
{
	struct download *d = download;

	download_check(d);
	g_assert(d->flags & DL_F_BROWSE);
	g_assert(browse_host_dl_for_search(d->browse, sh));

	browse_host_dl_search_closed(d->browse, sh);

	if (DOWNLOAD_IS_QUEUED(d)) {
		download_unqueue(d);
		gcu_download_gui_add(d);
	}

	if (!DOWNLOAD_IS_STOPPED(d))
		download_stop(d, GTA_DL_ERROR, "Browse search closed");

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
	g_assert(d->file_info != NULL);

	/*
	 * If we don't know the file size, then consider EOF as an indication
	 * we got everything.
	 */

	fi = d->file_info;

	if (!fi->file_size_known)
		download_rx_done(d);
	else if (FILE_INFO_COMPLETE(fi))
		download_rx_done(d);
	else
		download_queue_delay(d, download_retry_busy_delay,
			_("Stopped data (EOF) <download_got_eof>"));
}

/**
 * Called when all data has been received.
 */
void
download_rx_done(struct download *d)
{
	fileinfo_t *fi;

	download_check(d);
	fi = d->file_info;
	g_assert(fi != NULL);

	if (!d->browse && !fi->file_size_known) {
		file_info_size_known(d, fi->done);
		d->size = fi->size;
		d->range_end = download_filesize(d);	/* New upper boundary */
		gcu_gui_update_download_size(d);
	}

	download_stop(d, GTA_DL_COMPLETED, no_reason);

	if (!d->browse && fi->file_size_known) {
		download_verify_sha1(d);
	}
}

/**
 * Called when more data has been received.
 */
void
download_browse_received(struct download *d, ssize_t received)
{
	fileinfo_t *fi;

	download_check(d);
	fi = d->file_info;
	g_assert(fi != NULL);

	file_info_update(d, d->pos, d->pos + received, DL_CHUNK_DONE);

	d->pos += received;
	d->last_update = tm_time();
	fi->recv_amount += received;
}

/**
 * Called when all the received data so far have been processed to
 * check whether we are done.
 */
void
download_browse_maybe_finished(struct download *d)
{
	fileinfo_t *fi = d->file_info;

	download_check(d);
	fi = d->file_info;
	g_assert(fi != NULL);

	if (FILE_INFO_COMPLETE(fi))
		download_rx_done(d);
}

/*
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4 sw=4 cindent:
 */
