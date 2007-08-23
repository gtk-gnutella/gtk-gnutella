/*
 * $Id$
 *
 * Copyright (c) 2007, Raphael Manfredi
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
 * URL factory utilities.
 *
 * @author Raphael Manfredi
 * @date 2007
 */

#ifndef _url_factory_h_
#define _url_factory_h_

#include "common.h"

struct sha1;

const gchar * url_for_bitzi_lookup(const struct sha1 *k);
const gchar * url_for_sharemonkey_lookup(
	const struct sha1 *k, const gchar *filename, filesize_t size);

#endif	/* _url_factory_h_ */

/* vi: set ts=4 sw=4 cindent: */

