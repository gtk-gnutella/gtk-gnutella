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
#include "host_addr.h"

struct magnet_source {
	gchar *hostname;	/* string atom */
	gchar *uri;			/* string atom */
	host_addr_t addr;
	guint16 port;
};

struct magnet_resource {
	gchar *display_name;	/* string atom */
	gchar *sha1;		/* sha1 atom */
	GSList *sources;	/* List of walloc()ed (struct magnet_source *) */
	GSList *searches;	/* List of string atoms */
	filesize_t size;
};

struct magnet_resource *magnet_parse(const gchar *url, const gchar **error_str);
void magnet_resource_free(struct magnet_resource *res);

#endif /* _magnet_h_ */
/* vi: set ts=4 sw=4 cindent: */
