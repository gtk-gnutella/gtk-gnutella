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

#ifndef _dmesh_h_
#define _dmesh_h_

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
 * We use the `idx' to discriminate between the two forms, URN_INDEX meaning
 * it's an URN.
 */
typedef struct {
	guint32 ip;				/* Host IP */
	guint16 port;			/* Host port */
	guint idx;				/* File index (URN_INDEX means URN access) */
	gchar *name;			/* File name or URN string (atom) */
} dmesh_urlinfo_t;

#define URN_INDEX	0xffffffff		/* Marking index, indicates URN instead */

/*
 * Error codes from dmesh_url_parse().
 */

typedef enum {
	DMESH_URL_OK = 0,			/* All OK */
	DMESH_URL_HTTP_PARSER,		/* Error from http_url_parse() */
	DMESH_URL_BAD_FILE_PREFIX,	/* File prefix neither /uri-res nor /get */
	DMESH_URL_RESERVED_INDEX,	/* Index in /get/index is reserved */
	DMESH_URL_NO_FILENAME,		/* No filename after /get/index */
} dmesh_url_error_t;

extern dmesh_url_error_t dmesh_url_errno;

/*
 * Public interface
 */

void dmesh_init(void);
void dmesh_close(void);

const gchar *dmesh_url_strerror(dmesh_url_error_t errnum);
gboolean dmesh_url_parse(gchar *url, dmesh_urlinfo_t *info);

gboolean dmesh_add(
	guchar *sha1, guint32 ip, guint16 port, guint idx, gchar *name,
	guint32 stamp);

void dmesh_remove(
	const guchar *sha1, guint32 ip, guint16 port, guint idx, gchar *name);

void dmesh_collect_locations(guchar *sha1, guchar *value, gboolean defer);

gint dmesh_alternate_location(
	const guchar *sha1, gchar * buf, gint size, guint32 ip, guint32 last_sent);

void dmesh_multiple_downloads(
    guchar *sha1, guint32 size, struct dl_file_info *fi);

void dmesh_store(void);
void dmesh_ban_store(void);

#endif	/* _dmesh_h_ */

/* vi: set ts=4: */

