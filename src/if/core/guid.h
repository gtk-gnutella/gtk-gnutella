/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_guid_h_
#define _if_core_guid_h_

#include "common.h"

#include "lib/misc.h"		/* For GUID_RAW_SIZE */

typedef struct guid {
	char v[GUID_RAW_SIZE];
} guid_t;

/**
 * No alignment requirements but ptr must point to GUID_RAW_SIZE or more bytes.
 */
static inline guid_t *
cast_to_guid_ptr(char *ptr)
{
	return (guid_t *) ptr;
}

static inline const guid_t *
cast_to_guid_ptr_const(const char *ptr)
{
	return (const guid_t *) ptr;
}

extern const struct guid blank_guid;

bool guid_is_blank(const struct guid *);

#endif /* _if_core_guid_h_ */

/* vi: set ts=4 sw=4 cindent: */
