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

#ifndef _ui_core_interface_common_defs_h_
#define _ui_core_interface_common_defs_h_

#include <glib.h>
#include "config.h"


/* The next two defines came from huge.h --- Emile */
#define SHA1_BASE32_SIZE 	32		/* 160 bits in base32 representation */
#define SHA1_RAW_SIZE		20		/* 160 bits in binary representation */


#ifdef USE_GTK2

#define G_DISABLE_DEPRECATED
#define GDK_DISABLE_DEPRECATED
#if 0
/* This isn't possible due to use of GtkCombo */
#define GTK_DISABLE_DEPRECATED

#endif
#endif

#ifndef USE_GTK2
typedef void (*GCallback) (void);
#else
#include <glib-object.h>
#endif

#endif
