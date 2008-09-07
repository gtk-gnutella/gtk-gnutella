/*
 * $Id$
 *
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

typedef void (*qhit_process_t)(gpointer data, size_t len, gpointer udata);

/*
 * Public interface.
 */

struct gnutella_node;
struct array; 

void qhit_init(void);
void qhit_close(void);

void qhit_send_results(struct gnutella_node *n, GSList *files, gint count,
	const struct guid *muid, gboolean ggep_h);
void qhit_build_results(const GSList *files, gint count, size_t max_msgsize,
	qhit_process_t cb, gpointer udata, const struct guid *muid, gboolean ggep_h,
	const struct array *token);

#endif /* _core_qhit_h_ */

/* vi: set ts=4 sw=4 cindent: */
