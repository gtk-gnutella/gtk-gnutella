/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * This is like mempcpy(), but it returns a pointer to the last NUL byte copied
 * in the destination, allowing smoother code when concatening strings.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#ifndef _strpcpy_h_
#define _strpcpy_h_

char *strpcpy(char *dest, const char *src);

#endif /* _strpcpy_h_ */

/* vi: set ts=4 sw=4 cindent: */
