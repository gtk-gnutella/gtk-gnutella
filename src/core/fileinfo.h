/*
 * Copyright (c) 2002, Vidar Madsen
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
 * Structure for storing meta-information about files being downloaded.
 *
 * @author Vidar Madsen
 * @date 2002
 */

#ifndef _core_fileinfo_h_
#define _core_fileinfo_h_

#include "common.h"
#include "share.h"						/* For shared_file_t */
#include "if/core/fileinfo.h"

/*
 * Shared core constants
 */

#define FI_LOW_SRC_COUNT	5			/**< Few sources known if beneath */

struct guid;

/*
 * Public interface.
 */

void file_info_init(void);
void file_info_init_post(void);
void file_info_scandir(const char *dir);
int file_info_has_trailer(const char *path);
void file_info_retrieve(void);
void file_info_store(void);
void file_info_store_binary(fileinfo_t *fi, bool force);
void file_info_store_if_dirty(void);
void file_info_set_discard(fileinfo_t *fi, bool state);
enum dl_chunk_status file_info_find_hole(
	const struct download *d, filesize_t *from, filesize_t *to);
bool file_info_find_available_hole(const struct download *d,
	http_rangeset_t *ranges, filesize_t *from, filesize_t *to);
void file_info_merge_adjacent(fileinfo_t *fi);
void file_info_clear_download(struct download *d, bool lifecount);
enum dl_chunk_status file_info_chunk_status(
	fileinfo_t *fi, filesize_t from, filesize_t to);
void file_info_reset(fileinfo_t *fi);
void file_info_recreate(struct download *d);
fileinfo_t *file_info_get(
	const char *file, const char *path, filesize_t size,
	const struct sha1 *sha1, bool file_size_known);
void file_info_strip_binary(fileinfo_t *fi);
void file_info_strip_binary_from_file(fileinfo_t *fi, const char *file);
bool file_info_got_sha1(fileinfo_t *fi, const struct sha1 *sha1);
void file_info_got_tth(fileinfo_t *fi, const struct tth *tth);
void file_info_got_tigertree(fileinfo_t *fi,
		const struct tth *leaves, size_t num_leaves, bool mark_dirty);
void file_info_size_known(struct download *d, filesize_t size);
void file_info_size_unknown(fileinfo_t *fi);
void file_info_update(const struct download *d, filesize_t from, filesize_t to,
	enum dl_chunk_status status);
void file_info_new_chunk_owner(const struct download *d,
	filesize_t from, filesize_t to);
enum dl_chunk_status file_info_pos_status(fileinfo_t *fi,
	filesize_t pos /*, filesize_t *start, filesize_t *end */);
void file_info_close(void);
void file_info_close_pre(void);
void file_info_try_to_swarm_with(
	const char *file_name, const host_addr_t addr,
	uint16 port, const struct sha1 *sha1);
void file_info_try_to_swarm_with_firewalled(
	const guid_t *guid, hash_list_t *proxies, const struct sha1 *sha1);
void file_info_spot_completed_orphans(void);
void file_info_add_source(fileinfo_t *fi, struct download *dl);
void file_info_add_new_source(fileinfo_t *fi, struct download *dl);
void file_info_remove_source(
    fileinfo_t *fi, struct download *dl, bool discard);
void file_info_cloned_source(fileinfo_t *fi,
	struct download *d, struct download *cd);
void file_info_timer(void);
void file_info_slow_timer(void);
void file_info_unlink(fileinfo_t *fi);
void file_info_upload_stop(fileinfo_t *fi, const char *reason);
void file_info_pause(fileinfo_t *);
void file_info_resume(fileinfo_t *);
void file_info_changed(fileinfo_t *);
fileinfo_t *file_info_by_guid(const struct guid *guid);
void file_info_dht_query(const sha1_t *sha1);
void file_info_dht_query_queued(fileinfo_t *fi);
bool file_info_dht_query_starting(fileinfo_t *fi);
void file_info_dht_query_completed(fileinfo_t *fi, bool l, bool f);

shared_file_t *file_info_shared_sha1(const struct sha1 *sha1);
size_t file_info_available(const fileinfo_t *fi, char *buf, size_t size);
size_t file_info_available_ranges(const fileinfo_t *fi, char *buf, size_t size);
bool file_info_restrict_range(
	fileinfo_t *fi, filesize_t start, filesize_t *end);

fileinfo_t *file_info_has_identical(const struct sha1 *sha1, filesize_t size);
bool file_info_is_rare(const fileinfo_t *fi);
bool file_info_partial_shareable(const fileinfo_t *fi);

fileinfo_t *file_info_get_transient(const char *name);
fileinfo_t *file_info_by_sha1(const struct sha1 *sha1);
void file_info_remove(fileinfo_t *fi);
void file_info_moved(fileinfo_t *fi, const char *pathname);
void file_info_mark_stripped(fileinfo_t *fi);
bool file_info_rename(fileinfo_t *fi, const char *filename);
void file_info_resize(fileinfo_t *fi, filesize_t size);

typedef void (*file_info_foreach_cb)(gnet_fi_t fi_handle, void *udata);
void file_info_foreach(file_info_foreach_cb callback, void *udata);
bool file_info_purge(fileinfo_t *fi);

char *file_info_unique_filename(const char *path, const char *file,
	const char *ext);

void fi_src_info_changed(struct download *);
void fi_src_ranges_changed(struct download *);
void fi_src_status_changed(struct download *);

struct pslist *file_info_get_sources(const fileinfo_t *);

/***
 *** Inlined routines.
 ***/

/**
 * Return amount of currently active sources.
 */
static inline G_GNUC_PURE WARN_UNUSED_RESULT uint32
fi_alive_count(const fileinfo_t *fi)
{
	return fi->active_queued + fi->passive_queued + fi->recvcount;
}

#endif /* _core_fileinfo_h_ */

/* vi: set ts=4 sw=4 cindent: */
