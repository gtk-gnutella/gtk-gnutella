/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __share_h__
#define __share_h__

#include "huge.h"

struct gnutella_node;

/* A file extension we have to share */
struct extension {
	gchar *str;			/* Extension string (e.g. "html") */
	gint len;			/* Extension length (e.g. 4) */
};

typedef struct shared_file {
	gchar *file_path;		/* The full path of the file */
	gchar *file_name;		/* Pointer within file_path at start of filename */
	guint32 file_index;		/* the files index within our local DB */
	guint32 file_size;		/* File size in Bytes */
	gint file_name_len;
	time_t mtime;			/* Last modification time, for SHA1 computation */
	gchar sha1_digest[SHA1_RAW_SIZE];	/* SHA1 digest, binary form */
	gboolean has_sha1_digest;				/* True when digest is set */
} shared_file_t;

struct gnutella_search_results_out {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];

	/* Last 16 bytes = client_id */
};

/*
 * Global Data
 */

extern guint32 files_scanned, bytes_scanned, kbytes_scanned;
extern GSList *extensions, *shared_dirs;

/*
 * Special return value from shared_file() during library rebuild time.
 * This is needed because we no longer block the GUI whilst scanning.
 */

#define SHARE_REBUILDING	((struct shared_file *) 0x1)

/*
 * Global Functions
 */

void share_init(void);
struct shared_file *shared_file(guint idx);
struct shared_file *shared_file_by_name(gchar *basename);
void share_scan(void);
void share_close(void);
gboolean search_request(struct gnutella_node *n);
void parse_extensions(gchar *);
gchar *get_file_path(gint);
void shared_dirs_parse(gchar *);
void shared_dir_add(gchar *);
gint get_file_size(gint);

void set_sha1(struct shared_file *, const gchar *sha1_digest);
struct shared_file *shared_file_by_sha1(const gchar *sha1_digest);
gboolean sha1_hash_available(const struct shared_file *);

#endif /* __share_h__ */
