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

struct extension {
	gchar *str;					/**< Extension string (e.g. "html") */
	size_t len;					/**< Extension length (e.g. 4) */
};

typedef struct shared_file {
	const gchar *file_path;		/**< The full path of the file (atom!) */
	const gchar *name_nfc;		/**< UTF-8 NFC version of filename (atom!) */
	const gchar *name_canonic;	/**< UTF-8 canonized ver. of filename (atom)! */
	const gchar *content_type;	/**< MIME content type (static string) */

	struct dl_file_info *fi;	/**< PFSP-server: the holding fileinfo */

	filesize_t file_size;		/**< File size in Bytes */
	guint32 file_index;			/**< the files index within our local DB */

	gint refcnt;				/**< Reference count */
	guint32 flags;				/**< See below for definition */

	size_t name_nfc_len;		/**< strlen(name_nfc) */
	size_t name_canonic_len;	/**< strlen(name_canonic) */

	time_t mtime;				/**< Last modif. time, for SHA1 computation */
	gchar sha1_digest[SHA1_RAW_SIZE];	/**< SHA1 digest, binary form */
} shared_file_t;

/**
 * shared_file flags
 */

#define SHARE_F_HAS_DIGEST	0x00000001		/**< Digest is set */
#define SHARE_F_RECOMPUTING	0x00000002		/**< Digest being recomputed */

/**
 * Known MIME content types
 */

enum share_mime_type {
	SHARE_M_APPLICATION_BINARY = 0,
	SHARE_M_IMAGE_PNG,
	SHARE_M_TEXT_PLAIN,
};

struct gnutella_search_results_out {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];

	/* record data follows */

	/* Last 16 bytes = client_id */
};

#define SHARE_REBUILDING	((struct shared_file *) 0x1)

struct gnutella_node;
struct query_hashvec;

/**
 * Global Data.
 */

extern GSList *extensions, *shared_dirs;

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
void shared_file_unref(shared_file_t *sf);
void shared_file_remove(shared_file_t *sf);

gboolean search_request(struct gnutella_node *n, struct query_hashvec *qhv);
void parse_extensions(const gchar *);
gchar *get_file_path(gint);
void shared_dirs_update_prop(void);
gboolean shared_dirs_parse(const gchar *);

size_t compact_query(gchar *search);
void query_strip_oob_flag(struct gnutella_node *n, gchar *data);
void query_set_oob_flag(struct gnutella_node *n, gchar *data);

void set_sha1(struct shared_file *, const gchar *sha1_digest);
gboolean sha1_hash_available(const struct shared_file *);
gboolean sha1_hash_is_uptodate(struct shared_file *sf);

const gchar *map_muid_to_query_string(const gchar muid[GUID_RAW_SIZE]);

#endif /* _core_share_h_ */

/* vi: set ts=4 sw=4 cindent: */
