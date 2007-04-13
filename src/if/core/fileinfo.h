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

/**
 * These used to be in fileinfo.h, but we need them now at several places.
 */
enum dl_chunk_status {
    DL_CHUNK_EMPTY = 0,			/**< No data available yet */
    DL_CHUNK_BUSY  = 1,			/**< Being downloaded */
    DL_CHUNK_DONE  = 2,			/**< Downloaded */
};

typedef guint32 gnet_fi_t;

typedef struct gnet_fi_info {
	gnet_fi_t fi_handle;
	const gchar *path;		/**< Path of the directory of the file on disk */
	const gchar *file_name;	/**< Name of the file on disk */
	const struct sha1 *sha1;/**< SHA1 (binary) of the file or NULL */
	GSList *aliases;		/**< List of aliases (NULL if none) */
} gnet_fi_info_t;

typedef struct gnet_fi_status {
	guint32  	recvcount;
	guint32  	refcount;
	guint32  	lifecount;
	filesize_t  size;
	filesize_t  done;
	guint32  	recv_last_rate;
	guint32  	aqueued_count;
	guint32  	pqueued_count;

	/*
	 * The following are set only when file has been completely downloaded.
	 */

	filesize_t  sha1_hashed;
	filesize_t	copied;
	gboolean	has_sha1;
	gboolean	sha1_matched;
	gboolean	paused;
} gnet_fi_status_t;

typedef struct gnet_fi_chunks {
    filesize_t  from;
    filesize_t  to;
    enum dl_chunk_status status;
    gboolean old;
} gnet_fi_chunks_t;

enum fi_magic {
	FI_MAGIC = 0xd99892e7
};

typedef struct dl_file_info {
	enum fi_magic magic;	
    gnet_fi_t fi_handle;    /**< Handle */
	const gchar *guid;		/**< Unique fileinfo ID */
	guint32 flags;			/**< Operating flags */
	const gchar *file_name;	/**< Output file name (atom) */
	const gchar *path;		/**< Output file path (atom) */
	GSList *alias;			/**< List of file name aliases (atoms) */
	filesize_t size;		/**< File size */
	const filesize_t *size_atom;/**< File size (atom) */
	const struct sha1 *sha1;/**< server SHA1 (atom) if known, NULL if not. */
	const struct sha1 *cha1;/**< computed SHA1 (atom) if known, NULL if not. */
	gint32 refcount;		/**< Reference count of file (number of sources)*/
	GSList *sources;        /**< list of sources (struct download *) */
	gint32 lifecount;		/**< Amount of "alive" downloads referencing us */
	time_t stamp;			/**< Time stamp */
	time_t ctime;			/**< Creation time stamp */
	time_t ntime;			/**< Last time a new source was added */
	time_t last_flush;		/**< When last flush to disk occurred */
	time_t last_dmesh;		/**< When last dmesh query was used */
	filesize_t done;		/**< Total number of bytes completed (flushed) */
	filesize_t buffered;	/**< Amount of buffered data (unflushed) */
	GSList *chunklist;		/**< List of ranges within file */
	GSList *seen_on_network;  /**< List of ranges available on network */
	guint32 generation;		/**< Generation number, incremented on disk update */
	struct shared_file *sf;	/**< When PFSP-server is enabled, share this file */
	gboolean file_size_known; /**< File size known? */
	gboolean use_swarming;	/**< Use swarming? */
	gboolean dirty;			/**< Does it need saving? */
	gboolean dirty_status;  /**< Notify about status change on next interval */
	gboolean hashed;		/**< In hash tables? */
	guint32  aqueued_count; /**< Actively queued sources */
	guint32  pqueued_count; /**< Passively queued sources */

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

	guint cha1_elapsed;		/**< Time spent to compute the SHA1 */
	filesize_t cha1_hashed;	/**< Amount of bytes hashed so far */
	guint copy_elapsed;		/**< Time spent to copy the file */
	filesize_t copied;		/**< Amount of bytes copied so far */
} fileinfo_t;

static inline void
file_info_check(const fileinfo_t *fi)
{
	g_assert(fi);
	g_assert(FI_MAGIC == fi->magic);
	g_assert(fi->refcount >= 0);
}

static inline gboolean
FILE_INFO_COMPLETE(const fileinfo_t *fi)
{
	file_info_check(fi);
	return fi->file_size_known && fi->done == fi->size;
}

static inline gboolean
FILE_INFO_COMPLETE_AFTER(const fileinfo_t *fi, filesize_t off)
{
	file_info_check(fi);
	return fi->file_size_known && off >= fi->size - fi->done;
}

typedef void (*fi_listener_t) (gnet_fi_t);
typedef void (*fi_src_listener_t) (gnet_fi_t, gnet_src_t);

typedef enum {
	EV_FI_ADDED = 0,       /**< fi_listener */
	EV_FI_REMOVED,         /**< fi_listener */
	EV_FI_INFO_CHANGED,    /**< fi_listener */
	EV_FI_STATUS_CHANGED,  /**< fi_listener */
	EV_FI_STATUS_CHANGED_TRANSIENT, /**< fi_listener */
	EV_FI_SRC_ADDED,       /**< fi_src_listener */
	EV_FI_SRC_REMOVED,     /**< fi_src_listener */
	EV_FI_RANGES_CHANGED,  /**< fi_listener */

	EV_FI_EVENTS           /**< Number of events in this domain */
} gnet_fi_ev_t;

/*
 * Public interface, visible only from the bridge.
 */

#ifdef CORE_SOURCES

void fi_add_listener(fi_listener_t, gnet_fi_ev_t, frequency_t, guint32);
void fi_remove_listener(fi_listener_t, gnet_fi_ev_t);

gnet_fi_info_t *fi_get_info(gnet_fi_t);
void fi_free_info(gnet_fi_info_t *);
void fi_get_status(gnet_fi_t, gnet_fi_status_t *);
GSList *fi_get_chunks(gnet_fi_t);
void fi_free_chunks(GSList *chunks);
GSList *fi_get_ranges(gnet_fi_t);
void fi_free_ranges(GSList *ranges);
gchar **fi_get_aliases(gnet_fi_t fih);

void fi_purge_by_handle_list(const GSList *list);

const gchar *file_info_readable_filename(const struct dl_file_info *fi);
gchar *file_info_build_magnet(gnet_fi_t fih);

#endif /* CORE_SOURCES */
#endif /* _if_core_fileinfo_h_ */

/* vi: set ts=4 sw=4 cindent: */
