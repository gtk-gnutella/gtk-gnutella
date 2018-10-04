/*
 * Copyright (c) 2007 Christian Biere
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
 * @file
 *
 * Structure that defines a primitive array. This is almost the same
 * as struct iovec. However some systems have non-standard iovec with
 * iov_len being of type int instead of size_t. Also "char *" allows
 * pointer arithmetic whereas iov->iov_base requires a cast first.
 *
 * @author Christian Biere
 * @date 2007
 */

#ifndef _array_h_
#define _array_h_

#include "common.h"

struct array {
	const char *data;
	size_t size;
};

static const struct array zero_array;

static inline struct array
array_init(const void *data, size_t size)
{
	struct array array;
	array.data = data;
	array.size = size;
	return array;
}

static inline struct array
array_from_string(const char *str)
{
	return array_init(str, vstrlen(str));
}

#endif /* _array_h_ */

/* vi: set ts=4 sw=4 cindent: */
