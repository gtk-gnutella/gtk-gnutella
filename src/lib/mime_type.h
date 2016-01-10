/*
 * Copyright (c) 2008, Christian Biere
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
 * Primitive MIME type handling.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#ifndef _lib_mime_h_
#define _lib_mime_h_

/**
 * Known MIME content types
 */

enum mime_type {
#define MIME_TYPE(id, name) MIME_TYPE_ ## id,
#include "lib/mime_types.h"
#undef MIME_TYPE

	MIME_TYPE_NUM
};

void mime_type_init(void);
enum mime_type mime_type_from_filename(const char *);
enum mime_type mime_type_from_extension(const char *);
const char *mime_type_to_string(enum mime_type) G_PURE;

#endif /* _lib_mime_h_ */
/* vi: set ts=4 sw=4 cindent: */


