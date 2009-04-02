/*
 * $Id$
 *
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

#include "if/core/downloads.h"	/* For gnet_srt_t */

struct shared_file;
struct download;

/*
 * Operating flags.
 */

enum {
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

typedef guint32 gnet_fi_t;

typedef struct gnet_fi_info {
	gnet_fi_t fi_handle;
	const struct guid *guid;	/**< Unique fileinfo ID */
	const char *filename;		/**< Name of the file on disk */
	const struct sha1 *sha1;	/**< SHA1 (binary) of the file or NULL */
	const struct tth *tth;		/**< TTH (binary) of the file or NULL */
	filesize_t  size;
	filesize_t	tth_slice_size;
	unsigned int tth_depth;
	size_t 		tth_num_leaves;
	time_t		created;
} gnet_fi_info_t;

typedef struct gnet_fi_status {
	filesize_t  size;
	filesize_t  done;
	
	filesize_t  uploaded;
	filesize_t  sha1_hashed;
	filesize_t	copied;

	time_t		modified;

	guint32  	recvcount;
	guint32  	refcount;
	guint32  	lifecount;
	guint32  	recv_last_rate;
	guint32  	active_queued;
	guint32  	passive_queued;

	unsigned	paused:1;
	unsigned	has_sha1:1;

	/*
	 * The following are set only when file has been completely downloaded.
	 */

	unsigned	complete:1;
	unsigned	verifying:1;
	unsigned 	sha1_matched:1;
	unsigned	finished:1;
	unsigned	seeding:1;
} gnet_fi_status_t;

typedef struct gnet_fi_chunks {
    filesize_t  from;
    filesize_t  to;
    enum dl_chunk_status status;
    gboolean old;
} gnet_fi_chunks_t;

enum fi_magic {
	FI_MAGIC = 0x599892e7
};

struct guid;

typedef struct dl_file_info {
	enum fi_magic magic;	
    gnet_fi_t fi_handle;    /**< Handle */
	const struct guid *guid;/**< Unique fileinfo ID */
	guint32 flags;			/**< Operating flags */
	const char *pathname;	/**< Output pathname (atom) */
	GSList *alias;			/**< List of file name aliases (atoms) */
	filesize_t size;		/**< File size */
	const struct sha1 *sha1;/**< server SHA1 (atom) if known, NULL if not. */
	const struct tth  *tth; /**< server TTH (atom) if known, NULL if not. */
	const struct sha1 *cha1;/**< computed SHA1 (atom) if known, NULL if not. */
	struct {
		struct tth *leaves;	/**< Tigertree leaves */
		size_t num_leaves;	/**< Number of tigertree leaves */
		filesize_t slice_size;	/* Slice size (bytes covered by a leaf) */
	} tigertree;
	gint32 refcount;		/**< Reference count of file (number of sources)*/
	GSList *sources;        /**< list of sources (struct download *) */
	gint32 lifecount;		/**< Amount of "alive" downloads referencing us */
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
	GSList *chunklist;		/**< List of ranges within file */
	GSList *seen_on_network;  /**< List of ranges available on network */
	guint32 generation;		/**< Generation number, incremented on disk update */
	struct shared_file *sf;	/**< When PFSP-server is enabled, share this file */
	gboolean file_size_known; /**< File size known? */
	gboolean use_swarming;	/**< Use swarming? */
	gboolean dirty;			/**< Does it need saving? */
	gboolean dirty_status;  /**< Notify about status change on next interval */
	gboolean hashed;		/**< In hash tables? */
	guint32  active_queued; /**< Actively queued sources */
	guint32  passive_queued;/**< Passively queued sources */

	/*
	 * The following group is used to compute the aggregated reception rate.
	 */

	gint32 recvcount;		/**< Amount of "receiving" d/l referencing us */
	guint32 recv_last_rate;	/**< Last amount of bytes/sec received */
	guint32 recv_amount;	/**< Amount of bytes received this period */
	time_t recv_last_time;	/**< When did we last compute recv_last_rate? */

	/*
	 * This group of fields is used by the background SHA1 and moving daemons.
	 */

	filesize_t cha1_hashed;	/**< Amount of bytes hashed so far */
	filesize_t copied;		/**< Amount of bytes copied so far */
	unsigned cha1_elapsed;	/**< Time spent to compute the SHA1 */
	unsigned copy_elapsed;	/**< Time spent to copy the file */
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

static inline gboolean
fi_has_bad_bitprint(fileinfo_t *fi)
{
	file_info_check(fi);
	return (fi->flags & FI_F_BAD_BITPRINT) ? TRUE : FALSE;
}

static inline gboolean
FILE_INFO_COMPLETE(const fileinfo_t *fi)
{
	file_info_check(fi);
	return fi->file_size_known && fi->done == fi->size;
}

static inline gboolean
FILE_INFO_FINISHED(const fileinfo_t *fi)
{
	file_info_check(fi);
	return 0 != ((FI_F_STRIPPED | FI_F_TRANSIENT) & fi->flags)
		&& FILE_INFO_COMPLETE(fi);
}

static inline gboolean
FILE_INFO_COMPLETE_AFTER(const fileinfo_t *fi, filesize_t off)
{
	file_info_check(fi);
	return fi->file_size_known && off >= fi->size - fi->done;
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

void fi_add_listener(fi_listener_t, gnet_fi_ev_t, frequency_t, guint32);
void fi_remove_listener(fi_listener_t, gnet_fi_ev_t);

void src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, guint32);
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
gboolean fi_purge(gnet_fi_t fih);
void fi_pause(gnet_fi_t fih);
void fi_resume(gnet_fi_t fih);
gboolean fi_rename(gnet_fi_t fih, const char *);

const char *file_info_readable_filename(const struct dl_file_info *fi);
char *file_info_build_magnet(gnet_fi_t fih);
char *file_info_get_file_url(gnet_fi_t fih);
const char *file_info_status_to_string(const gnet_fi_status_t *status);

void fi_increase_uploaded(fileinfo_t *fi, size_t amount);

#endif /* CORE_SOURCES */
#endif /* _if_core_fileinfo_h_ */

/* vi: set ts=4 sw=4 cindent: */
