/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 message factory.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _core_g2_build_h_
#define _core_g2_build_h_

#include "lib/pmsg.h"

typedef void (*g2_build_qh2_cb_t)(pmsg_t *mb, void *udata);

/*
 * Public interface.
 */

struct guid;

pmsg_t *g2_build_pong(void);
pmsg_t *g2_build_alive_ping(void);
pmsg_t *g2_build_qht_reset(int slots, int inf_val);
pmsg_t *g2_build_qht_patch(int seqno, int seqsize, bool compressed, int bits,
	char *buf, int len);
pmsg_t *g2_build_lni(void);
pmsg_t *g2_build_push(const struct guid *guid);
pmsg_t *g2_build_qkr(void);

struct gnutella_node;
struct pslist;

pmsg_t *g2_build_q2(const struct guid *muid, const char *query,
	unsigned mtype, const void *query_key, uint8 length);

void g2_build_send_qh2(const struct gnutella_node *h,
	struct gnutella_node *n, struct pslist *files,
	int count, const struct guid *muid, uint flags);

void g2_build_qh2_results(const struct pslist *files, int count,
	size_t max_msgsize, g2_build_qh2_cb_t cb, void *udata,
	const struct guid *muid, uint flags);

void g2_build_close(void);

#endif /* _core_g2_build_h_ */

/* vi: set ts=4 sw=4 cindent: */
