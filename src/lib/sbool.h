/*
 * Copyright (c) 2006 Christian Biere
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
 * @file
 *
 * Strict booleans.
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _sbool_h_
#define _sbool_h_

#include "common.h"

enum sbool {
	sbool_false = 0x59976b8fU,
	sbool_true	= 0x16459047U
};

typedef struct {
	enum sbool value;
} sbool;

static inline ALWAYS_INLINE int
sbool_get(sbool sb)
{
	switch (sb.value) {
	case sbool_false:	return 0;
	case sbool_true:	break;
	default:			g_assert_not_reached();
	}
	return 1;
}

static inline ALWAYS_INLINE sbool
sbool_set(int value)
{
	sbool sb;

	sb.value = value ? sbool_true : sbool_false;
	return sb;
}

#endif /* _sbool_h_ */

/* vi: set ts=4 sw=4 cindent: */
