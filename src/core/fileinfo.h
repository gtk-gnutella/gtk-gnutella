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

#ifndef _core_fileinfo_h_
#define _core_fileinfo_h_

#include "share.h"						/* For shared_file_t */
#include "if/core/fileinfo.h"

/*
 * Operating flags.
 */

#define FI_F_SUSPEND		0x00000001U	/* Marked "suspended" new downloads */
#define FI_F_DISCARD		0x00000002U	/* Discard fileinfo when refcount = 0 */
#define FI_F_MARK			0x80000000U	/* Marked during traversal */

/*
 * Public interface.
 */

void file_info_init(void);
void file_info_init_post(void);
void file_info_scandir(const gchar *dir);
gboolean file_info_has_trailer(const gchar *path);
void file_info_retrieve(void);
void file_info_store(void);
void file_info_store_binary(struct dl_file_info *fi);
void file_info_store_if_dirty(void);
void file_info_set_discard(struct dl_file_info *fi, gboolean state);
enum dl_chunk_status file_info_find_hole(
	struct download *d, filesize_t *from, filesize_t *to);
gboolean file_info_find_available_hole(struct download *d,
	GSList *ranges, filesize_t *from, filesize_t *to);
void file_info_merge_adjacent(struct dl_file_info *fi);
void file_info_clear_download(struct download *d, gboolean lifecount);
enum dl_chunk_status file_info_chunk_status(
	struct dl_file_info *fi, filesize_t from, filesize_t to);
void file_info_reset(struct dl_file_info *fi);
void file_info_recreate(struct download *d);
struct dl_file_info *file_info_get(
	gchar *file, const gchar *path, filesize_t size, gchar *sha1,
	gboolean file_size_known);
void file_info_strip_binary(struct dl_file_info *fi);
void file_info_strip_binary_from_file(
	struct dl_file_info *fi, const gchar *file);
gboolean file_info_got_sha1(struct dl_file_info *fi, const gchar *sha1);
void file_info_update(struct download *d, filesize_t from, filesize_t to,
	enum dl_chunk_status status);
enum dl_chunk_status file_info_pos_status(struct dl_file_info *fi,
	filesize_t pos);
void file_info_close(void);
void file_info_close_pre(void);
void file_info_try_to_swarm_with(
	gchar *file_name, guint32 idx, guint32 ip, guint32 port, gchar *sha1);
void file_info_spot_completed_orphans(void);
void file_info_add_source(struct dl_file_info *fi, struct download *dl);
void file_info_add_new_source(struct dl_file_info *fi, struct download *dl);
void file_info_remove_source(
    struct dl_file_info *fi, struct download *dl, gboolean discard);
void file_info_timer(void);
void file_info_unlink(struct dl_file_info *fi);
void file_info_upload_stop(struct dl_file_info *fi, const gchar *reason);

shared_file_t *file_info_shared_sha1(const gchar *sha1);
gint file_info_available_ranges(struct dl_file_info *fi, gchar *buf, gint size);
gboolean file_info_restrict_range(
	struct dl_file_info *fi, filesize_t start, filesize_t *end);

struct dl_file_info *file_info_has_identical(
	gchar *file, filesize_t size, gchar *sha1);

#endif /* _core_fileinfo_h_ */
/* vi: set ts=4 sw=4 cindent: */
