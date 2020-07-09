/*
 * Copyright (c) 2010, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup xml
 * @file
 *
 * XML attributes.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _xml_xattr_h_
#define _xml_xattr_h_

#include "common.h"

struct xattr_table;
typedef struct xattr_table xattr_table_t;

/**
 * Traversal callback signature.
 *
 * @param uri		the URI prefix (NULL if attribute has no prefix)
 * @param local		the local attribute name
 * @param value		the attribute value
 * @param data		user-supplied callback
 */
typedef void (*xattr_table_cb_t)(const char *uri,
	const char *local, const char *value, void *data);

/*
 * Public interface.
 */

xattr_table_t *xattr_table_make(void);
void xattr_table_free_null(xattr_table_t **xat_ptr);

bool xattr_table_add(xattr_table_t *xat,
	const char *uri, const char *local, const char *value);
bool xattr_table_remove(xattr_table_t *xat,
	const char *uri, const char *local);
const char *xattr_table_lookup(const xattr_table_t *xat,
	const char *uri, const char *local);
size_t xattr_table_count(const xattr_table_t *xat);

void xattr_table_foreach(const xattr_table_t *xat,
	xattr_table_cb_t func, void *data);

#endif /* _xml_xattr_h_ */

/* vi: set ts=4 sw=4 cindent: */
