/*
 * $Id$
 *
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
#include "if/core/share.h"
#include "if/core/fileinfo.h"

typedef struct shared_file shared_file_t;

/**
 * shared_file flags
 */

enum {
	SHARE_F_HAS_DIGEST	=	(1 << 0),		/**< Digest is set */
	SHARE_F_RECOMPUTING	=	(1 << 1),		/**< Digest being recomputed */
	SHARE_F_SPECIAL		=	(1 << 2),		/**< Special (robots.txt, favicon)*/
	SHARE_F_BASENAME	=	(1 << 3),		/**< File is in basename index */
	SHARE_F_INDEXED		=	(1 << 4),		/**< File is in file_table index */
};

/**
 * Known MIME content types
 */

enum share_mime_type {
	SHARE_M_APPLICATION_BINARY = 0,
	SHARE_M_IMAGE_PNG,
	SHARE_M_TEXT_PLAIN,
};

#define SHARE_REBUILDING shared_file_dummy()

static inline struct shared_file *
shared_file_dummy(void)
{
	static struct shared_file *dummy;
	if (!dummy) {
		dummy = deconstify_gpointer(vmm_trap_page());
	}
	return dummy;
}

struct gnutella_node;
struct query_hashvec;

/*
 * Special return value from shared_file() during library rebuild time.
 * This is needed because we no longer block the GUI whilst scanning.
 */

/*
 * Global Functions
 */

void share_init(void);
void share_close(void);

const gchar *share_mime_type(enum share_mime_type type);

shared_file_t *shared_file(guint idx);
shared_file_t *shared_file_by_name(const gchar *filename);
shared_file_t * shared_file_ref(shared_file_t *sf);
shared_file_t *shared_file_by_sha1(const gchar *sha1_digest);
shared_file_t *shared_special(const gchar *path);
void shared_file_unref(shared_file_t **sf_ptr);
void shared_file_remove(shared_file_t *sf);

gboolean search_request(struct gnutella_node *n, struct query_hashvec *qhv);
void parse_extensions(const gchar *);
gchar *get_file_path(gint);
void shared_dirs_update_prop(void);
gboolean shared_dirs_parse(const gchar *);

size_t compact_query(gchar *search);
void query_strip_oob_flag(const struct gnutella_node *n, gchar *data);
void query_set_oob_flag(const struct gnutella_node *n, gchar *data);

void shared_file_set_sha1(struct shared_file *, const gchar *sha1_digest);
void shared_file_set_modification_time(struct shared_file *sf, time_t mtime);

void shared_file_check(const struct shared_file *sf);
gboolean sha1_hash_available(const struct shared_file *sf);
gboolean sha1_hash_is_uptodate(struct shared_file *sf);
gboolean shared_file_is_partial(const struct shared_file *sf);
filesize_t shared_file_size(const shared_file_t *sf);
guint32 shared_file_index(const shared_file_t *sf);
time_t shared_file_modification_time(const struct shared_file *sf);
const gchar *shared_file_path(const shared_file_t *sf);
const gchar *shared_file_sha1(const shared_file_t *sf);
const gchar *shared_file_name_nfc(const shared_file_t *sf);
const gchar *shared_file_name_canonic(const shared_file_t *sf);
const gchar *shared_file_relative_path(const shared_file_t *sf);
size_t shared_file_name_nfc_len(const shared_file_t *sf);
size_t shared_file_name_canonic_len(const shared_file_t *sf);
guint32 shared_file_flags(const shared_file_t *sf);
fileinfo_t *shared_file_fileinfo(const shared_file_t *sf);
const gchar *shared_file_content_type(const shared_file_t *sf);
void shared_file_from_fileinfo(fileinfo_t *fi);

void record_query_string(const gchar muid[GUID_RAW_SIZE], const gchar *query);
const gchar *map_muid_to_query_string(const gchar muid[GUID_RAW_SIZE]);

#endif /* _core_share_h_ */

/* vi: set ts=4 sw=4 cindent: */
