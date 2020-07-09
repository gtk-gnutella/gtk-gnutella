/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Message queues with a TCP sending stack.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_mq_tcp_h_
#define _core_mq_tcp_h_

#include "common.h"

#include "mq.h"
#include "lib/pmsg.h"

struct txdriver;
struct gnutella_node;

void mq_tcp_putq(mqueue_t *q, pmsg_t *mb, const struct gnutella_node *from);
mqueue_t *mq_tcp_make(int maxsize,
	struct gnutella_node *n, struct txdriver *nd, const struct mq_uops *uops);

#endif	/* _core_mq_tcp_h_ */

/* vi: set ts=4 sw=4 cindent: */
