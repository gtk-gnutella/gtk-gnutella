/*
 * Copyright (c) 2002, ko (ko-@wanadoo.fr)
 *
 * Input I/O notification.
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

#ifndef _inputevt_h_
#define _inputevt_h_

#include <glib.h>

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

/*
 * Module initialization and cleanup functions. 
 * These don't do anything and are not called (yet).
 */
void inputevt_init(void);
void inputevt_close(void);

/*
 * This emulates the GDK input interface.
 */
guint inputevt_add(gint source, inputevt_cond_t condition,
	inputevt_handler_t handler, gpointer data) ;

#define inputevt_remove(source) (g_source_remove(source))

#endif  /* _inputevt_h_ */

