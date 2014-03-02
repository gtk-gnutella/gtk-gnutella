/*
 * Copyright (c) 2001-2004, Raphael Manfredi
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
 * Query hit management.
 *
 * @author Raphael Manfredi
 * @date 2001-2004
 */

#ifndef _core_qhit_h_
#define _core_qhit_h_

#include "common.h"

typedef void (*qhit_process_t)(void *data, size_t len, void *udata);

/**
 * Query hit generation flags.
 */
#define QHIT_F_GGEP_H		(1U << 0)	/**< Host supports GGEP "H" */
#define QHIT_F_IPV6			(1U << 1)	/**< Host accepts IPv6 addresses */
#define QHIT_F_IPV6_ONLY	(1U << 2)	/**< Host only wants IPv6 addresses */

/**
 * Query hit generation flags for G2 queries.
 */
#define QHIT_F_G2_URL		(1U << 31)	/**< Wants URL (stating we share it) */
#define QHIT_F_G2_DN		(1U << 30)	/**< Wants DN (distinguished name) */
#define QHIT_F_G2_ALT		(1U << 29)	/**< Wants ALT (alt-locs) */

/*
 * Public interface.
 */

struct gnutella_node;
struct array; 
struct guid;
struct pslist;

void qhit_init(void);
void qhit_close(void);

void qhit_send_results(struct gnutella_node *n, struct pslist *files, int count,
	const struct guid *muid, unsigned flags);
void qhit_build_results(const struct pslist *files,
	int count, size_t max_msgsize,
	qhit_process_t cb, void *udata, const struct guid *muid, unsigned flags,
	const struct array *token);

#endif /* _core_qhit_h_ */

/* vi: set ts=4 sw=4 cindent: */
