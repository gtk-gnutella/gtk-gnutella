/*
 * Copyright (c) 2002, Richard Eckart
 *
 * Functions that should be in gtk-1.2 but are not.
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

#include "gnutella.h"

#include "gtk-missing.h"

/*
 * gtk_paned_get_position:
 *
 * Get position of divider in a GtkPaned. (in GTK2)
 */
gint gtk_paned_get_position(GtkPaned *paned){
    g_return_val_if_fail(paned != NULL, -1);
    g_return_val_if_fail(GTK_IS_PANED (paned), -1);

    return paned->child1_size;
}
