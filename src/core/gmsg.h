/*
 * Copyright (c) 2002-2003, 2014 Raphael Manfredi
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
 * @date 2002-2003, 2014
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

static inline uint8
gmsg_function(const void *data)
{
	return gnutella_header_get_function(data);
}

static inline uint8
gmsg_hops(const void *data)
{
	return gnutella_header_get_hops(data);
}

/**
 * Inline routines.
 */

/**
 * Returns the size (16-bit quantity) of a gnutella message.
 */
static inline uint16
gmsg_size(const void *msg)
{
	return gnutella_header_get_size(msg) & GTA_SIZE_MASK;
}

/**
 * Returns the flags (16-bit quantity) of a gnutella message.
 */
static inline uint16
gmsg_flags(const void *msg)
{
	uint32 size = gnutella_header_get_size(msg);

	return (size & GTA_SIZE_MARKED) ?
		(uint16) (size >> GTA_SIZE_FLAG_SHIFT) : 0;
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
void gmsg_close(void);
const char *gmsg_name(uint function);
gmsg_valid_t gmsg_size_valid(const void *msg, uint16 *size);

pmsg_t *gmsg_to_pmsg(const void *msg, uint32 size);
pmsg_t *gmsg_to_deflated_pmsg(const void *msg, uint32 size);
pmsg_t *gmsg_split_to_deflated_pmsg(const void *head,
			const void *data, uint32 size);
pmsg_t *gmsg_to_ctrl_pmsg(const void *msg, uint32 size);
pmsg_t * gmsg_to_ctrl_pmsg_extend(const void *msg, uint32 size,
			pmsg_free_t free_cb, void *arg);
pmsg_t *gmsg_split_to_pmsg(const void *head, const void *data,
			uint32 size);
pmsg_t * gmsg_split_to_pmsg_extend(const void *head, const void *data,
			uint32 size, pmsg_free_t free_cb, void *arg);

struct pslist;

void gmsg_mb_sendto_all(const struct pslist *sl, pmsg_t *mb);
void gmsg_mb_sendto_one(const struct gnutella_node *n, pmsg_t *mb);
void gmsg_mb_routeto_one(const struct gnutella_node *from,
	const struct gnutella_node *to, pmsg_t *mb);

void gmsg_sendto_one(struct gnutella_node *n, const void *msg, uint32 size);
void gmsg_ctrl_sendto_one(struct gnutella_node *n,
		const void *msg, uint32 size);
void gmsg_split_sendto_one(struct gnutella_node *n,
		const void *head, const void *data, uint32 size);
void gmsg_sendto_all(const struct pslist *l, const void *msg, uint32 size);
void gmsg_split_routeto_all(const struct pslist *l,
		const struct gnutella_node *from,
		const void *head, const void *data, uint32 size);
void gmsg_sendto_route(struct gnutella_node *n, struct route_dest *rt);

bool gmsg_can_drop(const void *pdu, int size);
bool gmsg_is_oob_query(const void *msg);
bool gmsg_split_is_oob_query(const void *head, const void *data);
int gmsg_cmp(const void *pdu1, const void *pdu2);
int gmsg_headcmp(const void *pdu1, const void *pdu2);
const char *gmsg_infostr(const void *msg);
const char *gmsg_node_infostr(const struct gnutella_node *n);
char *gmsg_infostr_full(const void *msg, size_t msg_len);
char *gmsg_infostr_full_split(const void *head,
	const void *data, size_t data_len);
size_t gmsg_infostr_full_split_to_buf(const void *head, const void *data,
	size_t data_len, char *buf, size_t buf_size);

iovec_t *gmsg_mq_templates(bool initial, size_t *vcnt);

void gmsg_install_presend(pmsg_t *mb);

void gmsg_log_bad(const struct gnutella_node *n,
	const char *reason, ...) G_PRINTF(2, 3);
void gmsg_log_dropped_pmsg(const pmsg_t *msg,
	const char *reason, ...) G_PRINTF(2, 3);
void gmsg_log_dropped(const struct gnutella_node *n,
	const char *reason, ...) G_PRINTF(2, 3);
void gmsg_log_split_dropped(
	const void *head, const void *data, size_t data_len,
	const char *reason, ...) G_PRINTF(4, 5);
void gmsg_log_duplicate(const struct gnutella_node *n,
	const char *reason, ...) G_PRINTF(2, 3);

void gmsg_search_sendto_one(struct gnutella_node *n, gnet_search_t sh,
	const void *msg, uint32 size);
void gmsg_search_sendto_all(const struct pslist *l, gnet_search_t sh,
	const void *msg, uint32 size);

#endif	/* _core_gmsg_h_ */

/* vi: set ts=4 sw=4 cindent: */
