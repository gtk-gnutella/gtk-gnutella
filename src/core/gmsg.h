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
 * Gnutella Messages.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_gmsg_h_
#define _core_gmsg_h_

#include "common.h"

#include "gnutella.h"

#include "if/core/search.h"

#include "lib/endian.h"
#include "lib/pmsg.h"

struct gnutella_node;
struct route_dest;
struct mqueue;

static inline guint8
gmsg_function(gconstpointer data)
{
	return gnutella_header_get_function(data);
}

static inline guint8
gmsg_hops(gconstpointer data)
{
	return gnutella_header_get_hops(data);
}

/**
 * Inline routines.
 */

/**
 * Returns the size (16-bit quantity) of a gnutella message.
 */
static inline guint16
gmsg_size(gconstpointer msg)
{
	return gnutella_header_get_size(msg) & GTA_SIZE_MASK;
}

/**
 * Returns the flags (16-bit quantity) of a gnutella message.
 */
static inline guint16
gmsg_flags(gconstpointer msg)
{
	guint32 size = gnutella_header_get_size(msg);

	return (size & GTA_SIZE_MARKED) ?
		(guint16) (size >> GTA_SIZE_FLAG_SHIFT) : 0;
}

typedef enum {
	GMSG_VALID = 0,				/* Payload <= 64KiB, no flags */
	GMSG_VALID_MARKED,			/* Payload <= 64KiB, marked but no flags */
	GMSG_INVALID,				/* Payload > 64KiB, no mark for flags */
	GMSG_VALID_NO_PROCESS		/* Marked for flags we do not know */
} gmsg_valid_t;

/*
 * Public interface
 */

void gmsg_init(void);
const char *gmsg_name(guint function);
gmsg_valid_t gmsg_size_valid(gconstpointer msg, guint16 *size);

pmsg_t *gmsg_to_pmsg(gconstpointer msg, guint32 size);
pmsg_t *gmsg_to_deflated_pmsg(gconstpointer msg, guint32 size);
pmsg_t *gmsg_to_ctrl_pmsg(gconstpointer msg, guint32 size);
pmsg_t * gmsg_to_ctrl_pmsg_extend(gconstpointer msg, guint32 size,
			pmsg_free_t free_cb, gpointer arg);
pmsg_t *gmsg_split_to_pmsg(gconstpointer head, gconstpointer data,
			guint32 size);
pmsg_t * gmsg_split_to_pmsg_extend(gconstpointer head, gconstpointer data,
			guint32 size, pmsg_free_t free_cb, gpointer arg);

void gmsg_mb_sendto_all(const GSList *sl, pmsg_t *mb);
void gmsg_mb_sendto_one(const struct gnutella_node *n, pmsg_t *mb);
void gmsg_mb_routeto_one(const struct gnutella_node *from,
	const struct gnutella_node *to, pmsg_t *mb);

void gmsg_sendto_one(struct gnutella_node *n, gconstpointer msg, guint32 size);
void gmsg_ctrl_sendto_one(struct gnutella_node *n,
		gconstpointer msg, guint32 size);
void gmsg_split_sendto_one(struct gnutella_node *n,
		gconstpointer head, gconstpointer data, guint32 size);
void gmsg_sendto_all(const GSList *l, gconstpointer msg, guint32 size);
void gmsg_split_routeto_all(const GSList *l,
		const struct gnutella_node *from,
		gconstpointer head, gconstpointer data, guint32 size);
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt);

gboolean gmsg_can_drop(gconstpointer pdu, int size);
gboolean gmsg_is_oob_query(gconstpointer msg);
gboolean gmsg_split_is_oob_query(gconstpointer head, gconstpointer data);
int gmsg_cmp(gconstpointer pdu1, gconstpointer pdu2, gboolean pdu2_complete);
const char *gmsg_infostr(gconstpointer msg);
char *gmsg_infostr_full(gconstpointer msg, size_t msg_len);
char *gmsg_infostr_full_split(gconstpointer head,
	gconstpointer data, size_t data_len);

void gmsg_install_presend(pmsg_t *mb);

void gmsg_log_bad(const struct gnutella_node *n,
	const char *reason, ...) G_GNUC_PRINTF(2, 3);
void gmsg_log_dropped_pmsg(pmsg_t *msg,
	const char *reason, ...) G_GNUC_PRINTF(2, 3);
void gmsg_log_split_dropped(
	gconstpointer head, gconstpointer data, size_t data_len,
	const char *reason, ...) G_GNUC_PRINTF(4, 5);

void gmsg_search_sendto_one(struct gnutella_node *n, gnet_search_t sh,
	gconstpointer msg, guint32 size);
void gmsg_search_sendto_all(const GSList *l, gnet_search_t sh,
	gconstpointer msg, guint32 size);

#endif	/* _core_gmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
