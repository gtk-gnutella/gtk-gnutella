/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * @ingroup lib
 * @file
 *
 * Handling of magnet links.
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _magnet_h_
#define _magnet_h_

#include "common.h"

#include "lib/host_addr.h"
#include "lib/misc.h"

struct magnet_source {
	const gchar *url;			/* string atom */
	const gchar *hostname;		/* string atom */
	const gchar *path;			/* string atom */
	const struct sha1 *sha1;	/* SHA1 atom */
	const struct tth *tth;		/* TTH atom */
	const gchar *guid;			/* GUID atom */
	host_addr_t addr;
	guint16 port;
};

struct magnet_resource {
	const gchar *display_name;	/* string atom */
	const struct sha1 *sha1;	/* SHA1 atom */
	const struct tth *tth;		/* TTH atom */
	const gchar *parq_id;		/* string atom */
	GSList *sources;	/* List of walloc()ed (struct magnet_source *) */
	GSList *searches;	/* List of string atoms */
	filesize_t size;
};

struct magnet_resource *magnet_parse(const gchar *url, const gchar **error_str);
struct magnet_source *magnet_parse_exact_source(const gchar *uri,
							const gchar **error_str);

void magnet_source_free(struct magnet_source **ms_ptr);
void magnet_resource_free(struct magnet_resource **res_ptr);

struct magnet_resource *magnet_resource_new(void);
struct magnet_source *magnet_source_new(void);
gchar *magnet_to_string(struct magnet_resource *res);
void magnet_set_filesize(struct magnet_resource *res, filesize_t size);
void magnet_set_display_name(struct magnet_resource *res, const gchar *name);
gboolean magnet_set_exact_topic(struct magnet_resource *res,
			const gchar *topic);
void magnet_set_sha1(struct magnet_resource *res, const struct sha1 *sha1);
void magnet_set_tth(struct magnet_resource *res, const struct tth *tth);
void magnet_add_search(struct magnet_resource *res, const gchar *search);
void magnet_add_source_by_url(struct magnet_resource *res, const gchar *url);
void magnet_add_sha1_source(struct magnet_resource *res,
		const struct sha1 *sha1, const host_addr_t addr, const guint16 port,
		const gchar *guid);

/* Extensions */
void magnet_set_parq_id(struct magnet_resource *res, const gchar *parq_id);

#endif /* _magnet_h_ */
/* vi: set ts=4 sw=4 cindent: */
