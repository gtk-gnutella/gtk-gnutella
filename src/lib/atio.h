/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Atomic (respective to other threads) I/O operations.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _atio_h_
#define _atio_h_

#include "common.h"		/* For struct iovec */

/*
 * Public interface.
 */

ssize_t atio_write(int fd, const void *buf, size_t count);
ssize_t atio_writev(int fd, const iovec_t *iov, int iovcnt);
size_t atio_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f);

#endif /* _atio_h_ */

/* vi: set ts=4 sw=4 cindent: */
