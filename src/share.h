/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _share_h_
#define _share_h_

#include "huge.h"

#include "ui_core_interface_share_defs.h"

struct gnutella_node;
struct query_hashvec;


/*
 * Global Data
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
struct shared_file *shared_file(guint idx);
struct shared_file *shared_file_by_name(const gchar *basename);
void share_scan(void);
void share_close(void);
guint64 shared_kbytes_scanned(void);
guint64 shared_files_scanned(void);
gboolean search_request(struct gnutella_node *n, struct query_hashvec *qhv);
void parse_extensions(const gchar *);
gchar *get_file_path(gint);
void shared_dirs_update_prop(void);
gboolean shared_dirs_parse(const gchar *);
void shared_dir_add(const gchar *);
gint get_file_size(gint);

void shared_file_free(shared_file_t *sf);

void set_sha1(struct shared_file *, const gchar *sha1_digest);
struct shared_file *shared_file_by_sha1(gchar *sha1_digest);
gboolean sha1_hash_available(const struct shared_file *);
gboolean sha1_hash_is_uptodate(struct shared_file *sf);
gboolean is_latin_locale(void);
void use_map_on_query(gchar *query, int len);

/* vi: set ts=4: */
#endif /* _share_h_ */
