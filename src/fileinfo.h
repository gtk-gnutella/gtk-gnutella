/*
 * $Id$
 *
 * Copyright (c) 2002, Vidar Madsen
 *
 * Structure for storing meta-information about files being downloaded.
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

#ifndef __fileinfo_h__
#define __fileinfo_h__

enum dl_chunk_status {
	DL_CHUNK_EMPTY = 0,
	DL_CHUNK_BUSY = 1,
	DL_CHUNK_DONE = 2
};

struct dl_file_chunk {
	guint32 from;					/* Range offset start (byte included) */
	guint32 to;						/* Range offset end (byte EXCLUDED) */
	enum dl_chunk_status status;	/* Status of range */
	struct download *download;		/* Download that "reserved" the range */
};

struct dl_file_info {
	guint32 flags;			/* Operating flags */
	gchar *file_name;		/* Output file name (atom) */
	gchar *path;			/* Output file path (atom) */
	GSList *alias;			/* List of file name aliases (atoms) */
	guint32 size;			/* File size */
	gint *size_atom;		/* File size (atom -- points to value in memory) */
	guchar *sha1;			/* server SHA1 (atom) if known, NULL if not. */
	guchar *cha1;			/* computed SHA1 (atom) if known, NULL if not. */
	gint32 refcount;		/* Reference count of file */
	gint32 lifecount;		/* Amount of "alive" downloads referencing us */
	time_t stamp;			/* Time stamp */
	time_t last_flush;		/* When last flush to disk occurred */
	time_t last_dmesh;		/* When last dmesh query was used */
	guint32 done;			/* Total number of bytes completed */
	GSList *chunklist;		/* List of ranges within file */
	guint32 generation;		/* Generation number, incremented on disk update */
	time_t cha1_elapsed;	/* Time spent to compute the SHA1 */
	guint32 cha1_hashed;	/* Amount of bytes hashed so far */
	gboolean use_swarming;	/* Use swarming? */
	gboolean dirty;			/* Does it need saving? */
	gboolean hashed;		/* In hash tables? */
};

/*
 * Operating flags.
 */

#define FI_F_SUSPEND		0x00000001 	/* Marked "suspended" new downloads */
#define FI_F_DISCARD		0x00000002 	/* Discard fileinfo when refcount = 0 */
#define FI_F_MARK			0x80000000 	/* Marked during traversal */

#define FILE_INFO_COMPLETE(x)	((x)->done == (x)->size)

void file_info_init(void);
void file_info_scandir(gchar *dir);
off_t file_info_filesize(gchar *path);
void file_info_retrieve(void);
void file_info_store(void);
void file_info_store_binary(struct dl_file_info *fi);
void file_info_store_if_dirty(void);
void file_info_set_discard(struct dl_file_info *fi, gboolean state);
enum dl_chunk_status file_info_find_hole(
	struct download *d, guint32 *from, guint32 *to);
void file_info_merge_adjacent(struct dl_file_info *fi);
void file_info_clear_download(struct download *d);
enum dl_chunk_status file_info_chunk_status(
	struct dl_file_info *fi, guint32 from, guint32 to);
void file_info_recreate(struct download *d);
struct dl_file_info *file_info_get(
	gchar *file, gchar *path, guint32 size, gchar *sha1);
void file_info_free(struct dl_file_info *fi, gboolean discard);
void file_info_strip_binary(struct dl_file_info *fi);
gboolean file_info_got_sha1(struct dl_file_info *fi, guchar *sha1);
void file_info_update(
	struct download *d, guint32 from, guint32 to, enum dl_chunk_status status);
enum dl_chunk_status file_info_pos_status(struct dl_file_info *fi, guint32 pos);
void file_info_close(void);
void file_info_try_to_swarm_with(
	gchar *file_name, guint32 idx, guint32 ip, guint32 port, guchar *sha1);
void file_info_spot_completed_orphans(void);

#endif /* __fileinfo_h__ */

