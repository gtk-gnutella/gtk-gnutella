/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * @author Christian Biere
 * @date 2006
 */

#ifndef _fragcheck_h_
#define _fragcheck_h_

#include "common.h"

#if 1
#define FRAGCHECK
#endif

#if defined(FRAGCHECK) && GLIB_CHECK_VERSION(2,0,0)
void alloc_dump(FILE *f, gboolean unused_flag);
void alloc_dump2(FILE *unused_f, gboolean unused_flag);

#define alloc_reset(a, b) alloc_dump2((a), (b))

void fragcheck_init(void);
#endif	/* GLib >= 2.0 */

#endif /* _fragcheck_h_ */
/* vi: set ts=4 sw=4 cindent: */
