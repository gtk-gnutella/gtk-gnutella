/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_inputevt_defs_h_
#define _ui_core_interface_inputevt_defs_h_

/*
 * This mimics the GDK input condition type.
 */
typedef enum {
	INPUT_EVENT_READ		= 1 << 0,
	INPUT_EVENT_WRITE		= 1 << 1,
	INPUT_EVENT_EXCEPTION	= 1 << 2,
} inputevt_cond_t;

/*
 * And the handler function type.
 */
typedef void (*inputevt_handler_t) (
	gpointer data,
	gint source,
	inputevt_cond_t condition
);


#endif
