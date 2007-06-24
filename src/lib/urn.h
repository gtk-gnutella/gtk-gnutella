/*
 * $Id$
 *
 * Copyright (c) 2002-2004, Raphael Manfredi
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
 * URN handling of specific formats.
 *
 * @author Raphael Manfredi
 * @date 2002-2004
 */

#ifndef _urn_h_
#define _urn_h_

#include "common.h" 

/*
 * Public interface.
 */

gboolean parse_base32_sha1(const gchar *buf, size_t size, struct sha1 *sha1);

gboolean urn_get_sha1(const gchar *buf, struct sha1 *sha1);
gboolean urn_get_sha1_no_prefix(const gchar *buf, struct sha1 *sha1);
gboolean urn_get_bitprint(const gchar *buf, size_t size,
	struct sha1 *sha1, struct tth *tth);
gboolean urn_get_tth(const gchar *buf, size_t size, struct tth *tth);

#endif	/* _urn_h_ */

/* vi: set ts=4 sw=4 cindent: */
