/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * Needs brief description here.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _iprange_h_
#define _iprange_h_

#include "common.h"

typedef void (*iprange_free_t)(gpointer value, gpointer udata);
typedef gpointer (*iprange_clone_t)(gpointer value);

/**
 * Statistics.
 */
typedef struct {
	gint count;					/**< Items held in database */
	gint level2;				/**< Level-2 pages used */
	gint heads;					/**< Lists of network ranges used */
	gint enlisted;				/**< Items held in lists */
} iprange_stats_t;

/**
 * Error codes.
 */

typedef enum {
	IPR_ERR_OK = 0,				/**< OK */
	IPR_ERR_BAD_PREFIX,			/**< Incorrect network prefix */
	IPR_ERR_RANGE_CLASH,		/**< CIDR range clash */
	IPR_ERR_RANGE_DUP,			/**< Duplicate range */
	IPR_ERR_RANGE_SUBNET,		/**< Range is subnet of existing range */
	IPR_ERR_RANGE_OVERLAP,		/**< Range is overlapping existing range */

	IPR_ERROR_COUNT				/**< Amount of error codes defined */
} iprange_err_t;

/*
 * Public interface.
 */

const gchar *iprange_strerror(iprange_err_t errnum);

gpointer iprange_make(iprange_free_t freecb, iprange_clone_t clonecb);
void iprange_free_each(gpointer db, gpointer udata);
iprange_err_t iprange_add_cidr(
	gpointer db, guint32 net, guint bits, gpointer udata);
iprange_err_t iprange_add_cidr_force(
	gpointer db, guint32 net, guint bits, gpointer udata, gpointer cdata);
gpointer iprange_get(gpointer db, guint32 ip);
void iprange_get_stats(gpointer db, iprange_stats_t *stats);

#endif	/* _iprange_h_ */

/* vi: set ts=4 sw=4 cindent: */
