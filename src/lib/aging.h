/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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

#ifndef _aging_h_
#define _aging_h_

#include "common.h"
#include "glib-missing.h"	/* For GEqualFunc in glib-1.x */

typedef void (*aging_free_t)(gpointer value, gpointer udata);

/*
 * Public interface.
 */

gpointer aging_make(
	gint delay, GHashFunc hash, GEqualFunc eq,
	aging_free_t kfree, gpointer kdata,
	aging_free_t vfree, gpointer vdata);

void aging_destroy(gpointer obj);

gpointer aging_lookup(gpointer obj, gpointer key);
void aging_insert(gpointer obj, gpointer key, gpointer value);
void aging_remove(gpointer obj, gpointer key);

#endif	/* _aging_h_ */

/* vi: set ts=4: sw=4 cindent: */

