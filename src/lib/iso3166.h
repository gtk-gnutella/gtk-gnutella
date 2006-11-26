/*
 * $Id$
 *
 * Copyright (c) 2004, Christian Biere
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

#ifndef _lib_iso3166_h_
#define _lib_iso3166_h_

#include "common.h"

gint iso3166_encode_cc(const gchar *cc);
void iso3166_init(void);
void iso3166_close(void);
const gchar *iso3166_country_name(gint code);
const gchar *iso3166_country_cc(gint code);

#endif /* _lib_iso3166_h_ */
/* vi: set ts=4 sw=4 cindent: */
