/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _if_core_fileinfo_h_
#define _if_core_fileinfo_h_

#include "common.h"

#include "lib/eslist.h"
#include "lib/http_range.h"
#include "lib/path.h"
#include "lib/pslist.h"

#include "if/core/downloads.h"	/* For gnet_srt_t */

struct shared_file;
struct download;

/*
 * Operating flags.
 */

enum {
	FI_F_NOSHARE		= 1 << 14,	/**< Explicitly refuse any sharing of file */
	FI_F_DHT_LOOKING	= 1 << 13,	/**< Running DHT lookup for more sources */
	FI_F_DHT_LOOKUP		= 1 << 12,	/**< Pending DHT lookup for more sources */
	FI_F_MOVING			= 1 << 11,	/**< Moving file (or about to) */
	FI_F_VERIFYING		= 1 << 10,	/**< Verifying SHA1 or TTH */
	FI_F_BAD_BITPRINT	= 1 << 9,	/**< SHA1 + TTH combination is bad */
	FI_F_UNLINKED		= 1 << 8,	/**< Removed from disk */
	FI_F_FETCH_TTH		= 1 << 7,	/**< Tigertree data is being downloaded */
	FI_F_STRIPPED		= 1 << 6,	/**< Fileinfo trailler has been stripped */
	FI_F_SEEDING		= 1 << 5,	/**< Seeding after successful download */
	FI_F_PAUSED			= 1 << 4,	/**< Paused by user */
	FI_F_MARK			= 1 << 3,	/**< Marked during traversal */
	FI_F_TRANSIENT		= 1 << 2,	/**< Don't persist to disk */
	FI_F_DISCARD		= 1 << 1,	/**< Discard fileinfo if refcount = 0 */
	FI_F_SUSPEND		= 1 << 0	/**< Marked "suspended" new downloads */
};

/**
 * These used to be in fileinfo.h, but we need them now at several places.
 */
enum dl_chunk_status {
    DL_CHUNK_DONE  = 2,			/**< Downloaded */
    DL_CHUNK_BUSY  = 1,			/**< Being downloaded */
    DL_CHUNK_EMPTY = 0			/**< No data available yet */
};

typedef uint32 gnet_fi_t;

typedef struct gnet_fi_info {
	gnet_fi_t fi_handle;
	const struct guid *guid;	/**< Unique fileinfo ID */
	const char *filename;		/**< Name of the file on disk */
	const struct sha1 *sha1;	/**< SHA1 (binary) of the file or NULL */
	const struct tth *tth;		/**< TTH (binary) of the file or NULL */
	filesize_t size;
	filesize_t tth_slice_size;
	unsigned int tth_depth;
	size_t tth_num_leaves;
	time_t created;
} gnet_fi_info_t;

typedef struct gnet_fi_status {
	filesize_t size;
	filesize_t done;

	filesize_t uploaded;
	filesize_t vrfy_hashed;
	filesize_t copied;

	time_t modified;

	uint32 recvcount;
	uint32 refcount;
	uint32 lifecount;
	uint32 recv_last_rate;
	uint32 active_queued;
	uint32 passive_queued;
	unsigned dht_lookups;	/**< Amount of completed DHT lookups */
	unsigned dht_values;	/**< Amount of successful DHT lookups */

	unsigned paused:1;
	unsigned has_sha1:1;
	unsigned dht_lookup_pending:1;
	unsigned dht_lookup_running:1;

	/*
	 * The following are set only when file has been completely downloaded.
	 */

	unsigned complete:1;
	unsigned verifying:1;
	unsigned moving:1;
	unsigned sha1_matched:1;
	unsigned sha1_failed:1;
	unsigned finished:1;
	unsigned seeding:1;
	unsigned tth_check:1;
} gnet_fi_status_t;

typedef struct gnet_fi_chunks {
    filesize_t from;
    filesize_t to;
    enum dl_chunk_status status;
    bool old;
} gnet_fi_chunks_t;

enum fi_magic {
	FI_MAGIC = 0x599892e7
};

struct guid;

/**
 * File downloading information.
 *
 * This keeps essential information for all the individual files that are to be
 * downloaded.
 *
 * Each download source points to one dl_file_info structure.
 */
typedef struct dl_file_info {
	enum fi_magic magic;
    gnet_fi_t fi_handle;    /**< Handle */
	const struct guid *guid;/**< Unique fileinfo ID */
	uint32 flags;			/**< Operating flags */
	const char *pathname;	/**< Output pathname (atom) */
	pslist_t *alias;		/**< List of file name aliases (atoms) */
	filesize_t size;		/**< File size */
	const struct sha1 *sha1;/**< server SHA1 (atom) if known, NULL if not. */
	const struct tth  *tth; /**< server TTH (atom) if known, NULL if not. */
	const struct sha1 *cha1;/**< computed SHA1 (atom) if known, NULL if not. */
	struct {
		struct tth *leaves;	/**< Tigertree leaves */
		size_t num_leaves;	/**< Number of tigertree leaves */
		filesize_t slice_size;	/* Slice size (bytes covered by a leaf) */
	} tigertree;
	int32 refcount;			/**< Reference count of file (number of sources)*/
	pslist_t *sources;		/**< list of sources (struct download *) */
	int32 lifecount;		/**< Amount of "alive" downloads referencing us */
	time_t stamp;			/**< Time stamp */
	time_t created;			/**< Creation time stamp */
	time_t modified;		/**< Modification time stamp */
	time_t ntime;			/**< Last time a new source was added */
	time_t last_flush;		/**< When last flush to disk occurred */
	time_t last_dmesh;		/**< When last dmesh query was used */
	time_t last_dht_query;	/**< Last time when SHA1 DHT query was made */
	filesize_t done;		/**< Total number of bytes completed (flushed) */
	filesize_t buffered;	/**< Amount of buffered data (unflushed) */
	filesize_t uploaded;	/**< Amount of bytes uploaded */
	eslist_t chunklist;		/**< List of ranges within file */
	eslist_t available;		/**< List of ranges available, with source count */
	http_rangeset_t *seen_on_network;  /**< Ranges available on network */
	uint32 generation;		/**< Generation number, incremented on disk update */
	struct shared_file *sf;	/**< When PFSP-server is enabled, share this file */
	uint32 active_queued;	/**< Actively queued sources */
	uint32 passive_queued;	/**< Passively queued sources */
	unsigned dht_lookups;	/**< Amount of completed DHT lookups */
	unsigned dht_values;	/**< Amount of successful DHT lookups */

	/*
	 * The following group is used to compute the aggregated reception rate.
	 */

	int32 recvcount;		/**< Amount of "receiving" d/l referencing us */
	uint32 recv_last_rate;	/**< Last amount of bytes/sec received */
	uint32 recv_amount;		/**< Amount of bytes received this period */
	time_t recv_last_time;	/**< When did we last compute recv_last_rate? */

	/*
	 * This group of fields is used by the background SHA1 and moving daemons.
	 */

	filesize_t vrfy_hashed;	/**< Amount of bytes hashed so far during verify */
	filesize_t copied;		/**< Amount of bytes copied so far */
	unsigned vrfy_elapsed;	/**< Time spent to compute the hash */
	unsigned copy_elapsed;	/**< Time spent to copy the file */

	/*
	 * Booleans (bit fields used since bool uses too much space).
	 */

	unsigned file_size_known:1;	/**< File size known? */
	unsigned use_swarming:1;	/**< Use swarming? */
	unsigned dirty:1;			/**< Does it need saving? */
	unsigned dirty_status:1;  	/**< Notify status change on next interval */
	unsigned hashed:1;			/**< In hash tables? */
	unsigned tth_check:1;		/**< TTH checking performed? */
} fileinfo_t;

static inline void
file_info_check(const fileinfo_t *fi)
{
	g_assert(fi);
	g_assert(FI_MAGIC == fi->magic);
	g_assert(fi->refcount >= 0);
	g_assert(fi->pathname);
	g_assert(is_absolute_path(fi->pathname));
}

static inline void
fi_mark_bad_bitprint(fileinfo_t *fi)
{
	file_info_check(fi);
	fi->flags |= FI_F_BAD_BITPRINT;
}

static inline bool
fi_has_bad_bitprint(fileinfo_t *fi)
{
	file_info_check(fi);
	return (fi->flags & FI_F_BAD_BITPRINT) ? TRUE : FALSE;
}

static inline bool
FILE_INFO_COMPLETE(const fileinfo_t *fi)
{
	file_info_check(fi);
	return fi->file_size_known && fi->done == fi->size;
}

static inline bool
FILE_INFO_FINISHED(const fileinfo_t *fi)
{
	file_info_check(fi);
	return 0 != ((FI_F_STRIPPED | FI_F_TRANSIENT) & fi->flags)
		&& FILE_INFO_COMPLETE(fi);
}

typedef void (*fi_listener_t) (gnet_fi_t);
typedef void (*src_listener_t) (gnet_src_t);

typedef enum {
	EV_FI_ADDED = 0,       /**< fi_listener */
	EV_FI_REMOVED,         /**< fi_listener */
	EV_FI_INFO_CHANGED,    /**< fi_listener */
	EV_FI_RANGES_CHANGED,  /**< fi_listener */
	EV_FI_STATUS_CHANGED,  /**< fi_listener */
	EV_FI_STATUS_CHANGED_TRANSIENT, /**< fi_listener */

	EV_FI_EVENTS           /**< Number of events in this domain */
} gnet_fi_ev_t;

typedef enum {
	EV_SRC_ADDED,			/**< src_listener */
	EV_SRC_REMOVED,			/**< src_listener */
	EV_SRC_INFO_CHANGED,	/**< src_listener */
	EV_SRC_RANGES_CHANGED,	/**< src_listener */
	EV_SRC_STATUS_CHANGED,	/**< src_listener */

	EV_SRC_EVENTS           /**< Number of events in this domain */
} gnet_src_ev_t;

/*
 * Public interface, visible only from the bridge.
 */

#ifdef CORE_SOURCES

void fi_add_listener(fi_listener_t, gnet_fi_ev_t, frequency_t, uint32);
void fi_remove_listener(fi_listener_t, gnet_fi_ev_t);

void src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, uint32);
void src_remove_listener(src_listener_t, gnet_src_ev_t);

struct download *src_get_download(gnet_src_t);

gnet_fi_info_t *fi_get_info(gnet_fi_t);
void fi_free_info(gnet_fi_info_t *);
void fi_get_status(gnet_fi_t, gnet_fi_status_t *);
GSList *fi_get_chunks(gnet_fi_t);
void fi_free_chunks(GSList *chunks);
GSList *fi_get_ranges(gnet_fi_t);
void fi_free_ranges(GSList *ranges);
char **fi_get_aliases(gnet_fi_t fih);
bool fi_purge(gnet_fi_t fih);
void fi_pause(gnet_fi_t fih);
void fi_resume(gnet_fi_t fih);
bool fi_rename(gnet_fi_t fih, const char *);

const char *file_info_readable_filename(const struct dl_file_info *fi);
char *file_info_build_magnet(gnet_fi_t fih);
char *file_info_get_file_url(gnet_fi_t fih);
const char *file_info_status_to_string(const gnet_fi_status_t *status);

void fi_increase_uploaded(fileinfo_t *fi, size_t amount);
void file_info_clear_completed(void);

#endif /* CORE_SOURCES */
#endif /* _if_core_fileinfo_h_ */

/* vi: set ts=4 sw=4 cindent: */
