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
 * @ingroup lib
 * @file
 *
 * URL handling of specific formats.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _url_h_
#define _url_h_

#include "common.h"

/**
 * Parsed URL parameters (from query string).
 */
typedef struct {
	GHashTable *params;		/**< parameter => value (malloc'ed) */
	gint count;				/**< Amount of parameters */
} url_params_t;

#define url_params_count(x)	((x)->count)

typedef enum {
	URL_POLICY_ALLOW_IP_AS_HOST		= (1 << 0),
	URL_POLICY_ALLOW_LOCAL_HOSTS	= (1 << 1),
	URL_POLICY_ALLOW_ANY_PORT		= (1 << 2),
	URL_POLICY_ALLOW_STATIC_FILES	= (1 << 3),
	URL_POLICY_ALLOW_ANY_CHAR		= (1 << 4),

	URL_POLICY_GWC_RULES			= 0 
} url_policy_t;

/*
 * Public interface.
 */

gchar *url_escape(const gchar *url);
gchar *url_escape_query(const gchar *url);
gchar *url_fix_escape(const gchar *url);
gint url_escape_into(const gchar *url, gchar *target, gint len);
gchar *url_escape_cntrl(const gchar *url);
gchar *url_unescape(gchar *url, gboolean inplace);

url_params_t *url_params_parse(gchar *query);
const gchar *url_params_get(url_params_t *up, const gchar *name);
void url_params_free(url_params_t *up);
gchar *url_normalize(gchar *url, url_policy_t pol);

#endif	/* _url_h_ */

/* vi: set ts=4 sw=4 cindent: */

