/*
 * $Id$
 *
 * Copyright (c) 2008, Raphael Manfredi
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
 * Debug level configuration for library files.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "debug.h"
#include "override.h"			/* Must be the last header included */

guint32 common_dbg = 0;			/**< Common debug level for library files */
guint32 common_stats = 0;		/**< Common log level for library statistics */

/**
 * Set the debug level for library files.
 */
void
set_library_debug(guint32 level)
{
	common_dbg = level;
}

/**
 * Set the log level for library runtime statistics.
 */
void
set_library_stats(guint32 level)
{
	common_stats = level;
}

/* vi: set ts=4 sw=4 cindent: */
