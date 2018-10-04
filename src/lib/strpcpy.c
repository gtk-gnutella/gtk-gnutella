/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * A strpcpy() implementation.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#include "strpcpy.h"

/**
 * A strcpy() routine returning a pointer to the NUL byte in the destination.
 */
char * G_HOT
strpcpy(char *dest, const char *src)
{
	register const char *p = src;
	register char *q = dest;

	g_assert(dest != NULL);

	if G_UNLIKELY(NULL == src) {
		*q = '\0';
		return q;
	}

	do {
		*q++ = *p;
	} while (*p++ != '\0');

	return q - 1;
}

/* vi: set ts=4 sw=4 cindent: */
