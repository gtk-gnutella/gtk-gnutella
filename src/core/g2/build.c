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

#include "common.h"

#include "build.h"

#include "frame.h"
#include "msg.h"
#include "tree.h"

#include "lib/once.h"
#include "lib/pmsg.h"

#include "lib/override.h"		/* Must be the last header included */

static pmsg_t *build_po;			/* Single pong */
static once_flag_t build_po_done;

/**
 * Create a pong message, once.
 */
static void
g2_build_pong_once(void)
{
	g2_tree_t *t;
	size_t len;

	t = g2_tree_alloc_empty("PO");
	len = g2_frame_serialize(t, NULL, 0);

	build_po = pmsg_new(PMSG_P_DATA, NULL, len);
	g2_frame_serialize(t, pmsg_start(build_po), len);
	pmsg_seek(build_po, len);

	g_assert(UNSIGNED(pmsg_size(build_po)) == len);
}

/**
 * Build a pong message.
 */
pmsg_t *
g2_build_pong(void)
{
	ONCE_FLAG_RUN(build_po_done, g2_build_pong_once);

	return pmsg_clone(build_po);
}

/* vi: set ts=4 sw=4 cindent: */
