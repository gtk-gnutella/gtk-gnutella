/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Download mesh.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_dmesh_h_
#define _core_dmesh_h_

#include "common.h"
#include "downloads.h"

/**
 * A download mesh info (describes an URL).
 *
 * It can describe URLs like:
 *
 *  - http://1.2.3.4:5678/get/1/name.txt
 *  - http://1.2.3.4:5678/uri-res/N2R?urn:sha1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
 *
 * We use the `idx' to discriminate between the two forms, URN_INDEX meaning
 * it's an URN.
 */
typedef struct {
	const gchar *name;			/**< File name (atom) */
	guint idx;					/**< File index (URN_INDEX means URN access) */
	host_addr_t addr;			/**< Host address */
	guint16 port;				/**< Host port */
} dmesh_urlinfo_t;

/**
 * Error codes from dmesh_url_parse().
 */

typedef enum {
	DMESH_URL_OK = 0,			/**< All OK */
	DMESH_URL_HTTP_PARSER,		/**< Error from http_url_parse() */
	DMESH_URL_BAD_FILE_PREFIX,	/**< File prefix neither /uri-res nor /get */
	DMESH_URL_RESERVED_INDEX,	/**< Index in /get/index is reserved */
	DMESH_URL_NO_FILENAME,		/**< No filename after /get/index */
	DMESH_URL_BAD_ENCODING,		/**< Bad URL encoding */
	DMESH_URL_BAD_URI_RES		/**< Malformed /uri-res/N2R? */
} dmesh_url_error_t;

extern dmesh_url_error_t dmesh_url_errno;

/*
 * Public interface
 */

void dmesh_init(void);
void dmesh_close(void);

const gchar *dmesh_url_strerror(dmesh_url_error_t errnum);
gboolean dmesh_url_parse(const gchar *url, dmesh_urlinfo_t *info);

gboolean dmesh_add(
	const gchar *sha1, const host_addr_t addr, guint16 port, guint idx,
	const gchar *name, time_t stamp);

gboolean dmesh_remove(
	const gchar *sha1, const host_addr_t addr, guint16 port, guint idx,
	const gchar *name);

gint dmesh_count(const gchar *sha1);

gboolean dmesh_collect_sha1(const gchar *value, gchar *digest);
void dmesh_collect_locations(const gchar *sha1,
		const gchar *value, gboolean defer);
void dmesh_collect_compact_locations(const gchar *sha1, const gchar *value);
gint dmesh_fill_alternate(const gchar *sha1, gnet_host_t *hvec, gint hcnt);

gint dmesh_alternate_location(
	const gchar *sha1, gchar * buf, size_t size, const host_addr_t addr,
	time_t last_sent, const gchar *vendor, fileinfo_t *fi,
	gboolean request);

void dmesh_multiple_downloads(
	const gchar *sha1, filesize_t size, fileinfo_t *fi);

void dmesh_check_results_set(gnet_results_set_t *rs);

void dmesh_store(void);
void dmesh_ban_store(void);

#endif	/* _core_dmesh_h_ */

/* vi: set ts=4 sw=4 cindent: */
