/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _if_core_main_h_
#define _if_core_main_h_

#include "common.h"

guint32 main_get_build(void);

#ifdef CORE_SOURCES

void gtk_gnutella_exit(gint n);
void gtk_gnutella_request_shutdown(void);
gboolean debugging(guint t);
const char *gtk_gnutella_interface(void);

#endif /* CORE_SOURCES */
#endif /* _if_core_main_h_ */

/* vi: set ts=4 sw=4 cindent: */
