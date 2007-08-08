/*
 * $Id$
 *
 * Copyright (c) 2007, Christian Biere
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
 */

#include "common.h"

RCSID("$Id$")

#include "topless.h"

#ifndef USE_TOPLESS
gboolean running_topless;
#endif	/* USE_TOPLESS */

void
topless_main_run(void)
{
	GMainLoop *ml;

#if GLIB_CHECK_VERSION(2,0,0)
	ml = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(ml);
#else
	ml = g_main_new(FALSE);
	g_main_run(ml);
#endif /* GLIB */
}

/* vi: set ts=4 sw=4 cindent: */
