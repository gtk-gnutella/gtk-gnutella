/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Download mesh.
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

#ifndef __dmesh_h__
#define __dmesh_h__

#include "downloads.h"

#include <glib.h>
#include <errno.h>

/*
 * A download mesh info (describes an URL).
 *
 * It can describe URLs like:
 *
 *   http://1.2.3.4:5678/get/1/name.txt
 *   http://1.2.3.4:5678/uri-res/N2R?urn:sha1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
 *
 * We use the `idx' to discriminate between the two forms, 0 meaning it's
 * an URN (since 0 cannot be a valid file index).
 */
typedef struct {
	guint32 ip;				/* Host IP */
	guint16 port;			/* Host port */
	guint idx;				/* File index (0 means URN access) */
	gchar *name;			/* File name or URN string (atom) */
} dmesh_urlinfo_t;

/*
 * Public interface
 */

void dmesh_init(void);
void dmesh_close(void);

gboolean dmesh_url_parse(gchar *url, dmesh_urlinfo_t *info);

gboolean dmesh_add(
	guchar *sha1, guint32 ip, guint16 port, guint idx, gchar *name,
	guint32 stamp);

void dmesh_remove(
	guchar *sha1, guint32 ip, guint16 port, guint idx, gchar *name);

void dmesh_collect_locations(guchar *sha1, guchar *value);

gint dmesh_alternate_location(
	guchar *sha1, gchar * buf, gint size, guint32 ip, guint32 last_sent);

void dmesh_multiple_downloads(
    guchar *sha1, guint32 size, struct dl_file_info *fi);

void dmesh_store(void);
void dmesh_ban_store(void);

#endif	/* __dmesh_h__ */

/* vi: set ts=4: */

