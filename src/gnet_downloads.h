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

#ifndef _gnet_downloads_h_
#define _gnet_downloads_h_


/***
 *** Downloads
 ***/
/* FIXME: dl_file_info must not be used here and download_index_changed
 *        actually needs to be in downloads.h and should be called from
 *       search.h and not from search_gui.h.
 */
struct dl_file_info;
gboolean download_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_auto_new(gchar *,
 	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_index_changed(guint32, guint16, gchar *, guint32, guint32);

#define URN_INDEX	0xffffffff		/* Marking index, indicates URN instead */


/***
 *** Sources (traditionally called "downloads")
 ***/

typedef guint32 gnet_src_t;

typedef void (*src_listener_t) (gnet_src_t);
typedef enum {
	EV_SRC_ADDED = 0,
	EV_SRC_REMOVED,
	EV_SRC_INFO_CHANGED,
	EV_SRC_STATUS_CHANGED,
	EV_SRC_RANGES_CHANGED,
	EV_SRC_EVENTS /* Number of events in this domain */
} gnet_src_ev_t;

void src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, guint32);
void src_remove_listener(src_listener_t, gnet_src_ev_t);

struct download *src_get_download(gnet_src_t src_handle);


/***
 *** Fileinfo
 ***/


/*
 * These used to be in fileinfo.h, but we need them now at several places.
 */
enum dl_chunk_status {
    DL_CHUNK_EMPTY = 0,
    DL_CHUNK_BUSY  = 1,
    DL_CHUNK_DONE  = 2
};


typedef guint32 gnet_fi_t;

typedef struct gnet_fi_info {
	gnet_fi_t fi_handle;
	gchar *file_name;			/* Name of the file on disk */
	GSList *aliases;			/* List of aliases (NULL if none) */
} gnet_fi_info_t;

typedef struct gnet_fi_status {
	guint32  recvcount;
	guint32  refcount;
	guint32  lifecount;
	guint32  size;
	guint32  done;
	guint32  recv_last_rate;
	guint32  aqueued_count;
	guint32  pqueued_count;
} gnet_fi_status_t;

typedef void (*fi_listener_t) (gnet_fi_t);
typedef void (*fi_src_listener_t) (gnet_fi_t, gnet_src_t);

typedef enum {
	EV_FI_ADDED = 0,       /* fi_listener */
	EV_FI_REMOVED,         /* fi_listener */
	EV_FI_INFO_CHANGED,    /* fi_listener */
	EV_FI_STATUS_CHANGED,  /* fi_listener */
	EV_FI_STATUS_CHANGED_TRANSIENT, /* fi_listener */
	EV_FI_SRC_ADDED,       /* fi_src_listener */
	EV_FI_SRC_REMOVED,     /* fi_src_listener */
	EV_FI_EVENTS           /* Number of events in this domain */
} gnet_fi_ev_t;

typedef struct gnet_fi_chunks {
    guint32  from;
    guint32  to;
    enum dl_chunk_status status;
    gboolean old;
} gnet_fi_chunks_t;

void fi_add_listener(GCallback, gnet_fi_ev_t, frequency_t, guint32);
void fi_remove_listener(GCallback, gnet_fi_ev_t);

gnet_fi_info_t *fi_get_info(gnet_fi_t);
void fi_free_info(gnet_fi_info_t *);
void fi_get_status(gnet_fi_t, gnet_fi_status_t *);
GSList *fi_get_chunks(gnet_fi_t);
void fi_free_chunks(GSList *chunks);
gchar **fi_get_aliases(gnet_fi_t fih);

void fi_purge_by_handle_list(GSList *list);
gboolean fi_purge(gnet_fi_t fih);


#endif /* _gnet_downloads_h_ */
