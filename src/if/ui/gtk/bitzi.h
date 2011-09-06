/*
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
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

#ifndef _if_ui_gtk_bitzi_h_
#define _if_ui_gtk_bitzi_h_

#include "if/core/bitzi.h"		/* For bitzi types */

/*
 * Public interface, visible from the bridge.
 */

#ifdef GUI_SOURCES

void bitzi_gui_update(bitzi_data_t *bitzi_data);

#endif /* GUI_SOURCES */
#endif /* _gtk_bitzi_h_ */

/* vi: set ts=4 sw=4 cindent: */
