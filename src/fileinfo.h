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

#ifndef _fileinfo_h_
#define _fileinfo_h_

struct shared_file;

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
    gnet_fi_t fi_handle;    /* Handle */

	guint32 flags;			/* Operating flags */
	gchar *file_name;		/* Output file name (atom) */
	gchar *path;			/* Output file path (atom) */
	GSList *alias;			/* List of file name aliases (atoms) */
	guint32 size;			/* File size */
	gint *size_atom;		/* File size (atom -- points to value in memory) */
	gchar *sha1;			/* server SHA1 (atom) if known, NULL if not. */
	gchar *cha1;			/* computed SHA1 (atom) if known, NULL if not. */
	gint32 refcount;		/* Reference count of file (number of sources)*/
    GSList *sources;        /* list of sources (struct download *)*/
	gint32 lifecount;		/* Amount of "alive" downloads referencing us */
	time_t stamp;			/* Time stamp */
	time_t last_flush;		/* When last flush to disk occurred */
	time_t last_dmesh;		/* When last dmesh query was used */
	guint32 done;			/* Total number of bytes completed */
	GSList *chunklist;		/* List of ranges within file */
	guint32 generation;		/* Generation number, incremented on disk update */
	struct shared_file *sf;	/* When PFSP-server is enabled, share this file */
	gboolean use_swarming;	/* Use swarming? */
	gboolean dirty;			/* Does it need saving? */
    gboolean dirty_status;  /* Notify about status change on next interval */
	gboolean hashed;		/* In hash tables? */

	/*
	 * The following group is used to compute the aggregated reception rate.
	 */

	gint32 recvcount;		/* Amount of "receiving" downloads referencing us */
	guint32 recv_last_rate;	/* Last amount of bytes/sec received */
	guint32 recv_amount;	/* Amount of bytes received this period */
	time_t recv_last_time;	/* When did we last compute recv_last_rate? */

	/*
	 * This group of fields is used by the background SHA1 and moving daemons.
	 */

	time_t cha1_elapsed;	/* Time spent to compute the SHA1 */
	guint32 cha1_hashed;	/* Amount of bytes hashed so far */
	time_t copy_elapsed;	/* Time spent to copy the file */
	guint32 copied;			/* Amount of bytes copied so far */
};

/*
 * Operating flags.
 */

#define FI_F_SUSPEND		0x00000001 	/* Marked "suspended" new downloads */
#define FI_F_DISCARD		0x00000002 	/* Discard fileinfo when refcount = 0 */
#define FI_F_MARK			0x80000000 	/* Marked during traversal */

#define FILE_INFO_COMPLETE(x)	((x)->done == (x)->size)

void file_info_init(void);
void file_info_scandir(const gchar *dir);
off_t file_info_filesize(const gchar *path);
void file_info_retrieve(void);
void file_info_store(void);
void file_info_store_binary(struct dl_file_info *fi);
void file_info_store_if_dirty(void);
void file_info_set_discard(struct dl_file_info *fi, gboolean state);
enum dl_chunk_status file_info_find_hole(
	struct download *d, guint32 *from, guint32 *to);
gboolean file_info_find_available_hole(struct download *d,
	GSList *ranges, guint32 *from, guint32 *to);
void file_info_merge_adjacent(struct dl_file_info *fi);
void file_info_clear_download(struct download *d, gboolean lifecount);
enum dl_chunk_status file_info_chunk_status(
	struct dl_file_info *fi, guint32 from, guint32 to);
void file_info_reset(struct dl_file_info *fi);
void file_info_recreate(struct download *d);
struct dl_file_info *file_info_get(
	gchar *file, const gchar *path, guint32 size, gchar *sha1);
void file_info_strip_binary(struct dl_file_info *fi);
void file_info_strip_binary_from_file(
	struct dl_file_info *fi, const gchar *file);
gboolean file_info_got_sha1(struct dl_file_info *fi, const gchar *sha1);
void file_info_update(
	struct download *d, guint32 from, guint32 to, enum dl_chunk_status status);
enum dl_chunk_status file_info_pos_status(struct dl_file_info *fi, guint32 pos);
void file_info_close(void);
void file_info_try_to_swarm_with(
	gchar *file_name, guint32 idx, guint32 ip, guint32 port, gchar *sha1);
void file_info_spot_completed_orphans(void);
void file_info_add_source(
    struct dl_file_info *fi, struct download *dl);
void file_info_remove_source(
    struct dl_file_info *fi, struct download *dl, gboolean discard);
void file_info_timer(void);

shared_file_t *file_info_shared_sha1(const gchar *sha1);
gint file_info_available_ranges(struct dl_file_info *fi, gchar *buf, gint size);
gboolean file_info_restrict_range(
	struct dl_file_info *fi, guint32 start, guint32 *end);

struct dl_file_info *file_info_has_identical(
	gchar *file, guint32 size, gchar *sha1);

#endif /* _fileinfo_h_ */

