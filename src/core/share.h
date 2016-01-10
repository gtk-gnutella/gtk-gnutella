/*
 * Copyright (c) 2001-2005, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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
 * Handle sharing of our own files and answers to remote queries.
 *
 * @author Raphael Manfredi
 * @date 2001-2005
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 */

#ifndef _core_share_h_
#define _core_share_h_

#include "common.h"

#include "matching.h"

#include "lib/mime_type.h"

#include "if/core/share.h"
#include "if/core/fileinfo.h"
#include "if/gnet_property_priv.h"

typedef struct shared_file shared_file_t;

/**
 * shared_file flags
 */

enum {
	SHARE_F_FILEINFO	=	(1 << 5),		/**< File referenced by fileinfo */
	SHARE_F_INDEXED		=	(1 << 4),		/**< File is in file_table index */
	SHARE_F_BASENAME	=	(1 << 3),		/**< File is in basename index */
	SHARE_F_SPECIAL		=	(1 << 2),		/**< Special (robots.txt, favicon)*/
	SHARE_F_RECOMPUTING	=	(1 << 1),		/**< Digest being recomputed */
	SHARE_F_HAS_DIGEST	=	(1 << 0)		/**< Digest is set */
};

static inline shared_file_t *
shared_file_dummy(void)
{
	static shared_file_t *dummy;
	if (!dummy) {
		dummy = deconstify_pointer(vmm_trap_page());
	}
	return dummy;
}

/**
 * Special return value from shared_file() during library rebuild time.
 * This is needed because we no longer block the GUI whilst scanning.
 */
#define SHARE_REBUILDING shared_file_dummy()

/**
 * Flags for shared_files_match().
 */
#define SHARE_FM_PARTIALS	(1 << 0)		/**< Can match partials */
#define SHARE_FM_G2			(1 << 1)		/**< G2 query */

struct gnutella_node;
struct query_hashvec;

/*
 * Global Functions
 */

void share_init(void);
void share_close(void);

shared_file_t *shared_file(uint idx);
shared_file_t *shared_file_sorted(uint idx);
shared_file_t *shared_file_by_name(const char *filename);
shared_file_t *shared_file_ref(const shared_file_t *sf);
shared_file_t *shared_file_by_sha1(const struct sha1 *sha1);
shared_file_t *shared_special(const char *path);
void shared_file_unref(shared_file_t **sf_ptr);
void shared_file_fileinfo_unref(shared_file_t **sf_ptr);
void shared_file_remove(shared_file_t *sf);

struct hset;
struct hset *share_tthset_get(void);
void share_tthset_free(struct hset *set);

void parse_extensions(const char *);
char *get_file_path(int);
void shared_dirs_update_prop(void);
bool shared_dirs_parse(const char *);

void shared_file_set_sha1(shared_file_t *, const struct sha1 *sha1);
void shared_file_set_tth(shared_file_t *, const struct tth *tth);
void shared_file_set_modification_time(shared_file_t *sf, time_t mtime);
void shared_file_set_path(shared_file_t *sf, const char *pathname);

void shared_file_check(const shared_file_t * const sf);
void shared_file_name_check(const shared_file_t * const sf);
bool sha1_hash_available(const shared_file_t *sf) G_PURE;
bool sha1_hash_is_uptodate(shared_file_t *sf);
bool shared_file_is_partial(const shared_file_t *sf) G_PURE;
bool shared_file_is_finished(const shared_file_t *sf) G_PURE;
bool shared_file_is_shareable(const shared_file_t *sf) G_PURE;
filesize_t shared_file_size(const shared_file_t *sf) G_PURE;
uint32 shared_file_index(const shared_file_t *sf) G_PURE;
time_t shared_file_modification_time(const shared_file_t *sf) G_PURE;
time_t shared_file_creation_time(const shared_file_t *sf) G_PURE;
filesize_t shared_file_available(const shared_file_t *sf) G_PURE;
const char *shared_file_path(const shared_file_t *sf) G_PURE;
const struct sha1 *shared_file_sha1(const shared_file_t *sf) G_PURE;
const struct tth *shared_file_tth(const shared_file_t *sf) G_PURE;
const char *shared_file_name_nfc(const shared_file_t *sf) G_PURE;
const char *shared_file_name_canonic(const shared_file_t *sf) G_PURE;
const char *shared_file_relative_path(const shared_file_t *sf) G_PURE;
size_t shared_file_name_nfc_len(const shared_file_t *sf) G_PURE;
size_t shared_file_name_canonic_len(const shared_file_t *sf) G_PURE;
uint32 shared_file_flags(const shared_file_t *sf) G_PURE;
fileinfo_t *shared_file_fileinfo(const shared_file_t *sf) G_PURE;
const char *shared_file_mime_type(const shared_file_t *sf) G_PURE;
bool shared_file_indexed(const shared_file_t *sf) G_PURE;
void shared_file_from_fileinfo(fileinfo_t *fi);
bool shared_file_has_media_type(const shared_file_t *sf, unsigned m)
	G_PURE;

struct pslist;

void shared_file_slist_free_null(struct pslist **l_ptr);

void share_add_partial(const shared_file_t *sf);
void share_remove_partial(const shared_file_t *sf);
void share_update_matching_information(void);

void shared_files_match(const char *query,
		st_search_callback callback, void *user_data,
		int max_res, uint32 partials, struct query_hashvec *qhv);

size_t share_fill_newest(shared_file_t **sfvec, size_t sfcount, unsigned mask,
	bool size_restrict, filesize_t minsize, filesize_t maxsize);

unsigned share_filename_media_mask(const char *filename);

static inline bool
share_can_answer_partials(void)
{
	return GNET_PROPERTY(pfsp_server) && GNET_PROPERTY(query_answer_partials);
}

#endif /* _core_share_h_ */

/* vi: set ts=4 sw=4 cindent: */
