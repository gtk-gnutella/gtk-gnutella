/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Version management.
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

#ifndef _version_h_
#define _version_h_

#include <glib.h>
#include "ui_core_interface_version_defs.h"

/*
 * Public interface.
 */

void version_init(void);
void version_close(void);
void version_ancient_warn(void);
gboolean version_check(const gchar *str, const gchar *token, guint32 ip);
gboolean version_is_too_old(const gchar *vendor);
gint version_cmp(const version_t *a, const version_t *b);
gboolean version_fill(const gchar *version, version_t *vs);
gboolean version_newer(const gchar *str, time_t stamp);

const gchar *version_str(const version_t *ver);

extern gchar *version_string;
extern gchar *version_short_string;

#endif	/* _version_h_ */

/* vi: set ts=4: */
