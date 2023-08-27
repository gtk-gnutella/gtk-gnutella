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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Random value file persistency.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _frand_h_
#define _frand_h_

/*
 * Public interface.
 */

ssize_t frand_save(const char *path, randfill_fn_t rfn, size_t len);
ssize_t frand_merge(const char *path, randfill_fn_t rfn, size_t len);
ssize_t frand_restore(const char *path, feed_fn_t rfd, size_t len);
ssize_t frand_clear(const char *path, size_t len);

#endif /* _frand_h_ */

/* vi: set ts=4 sw=4 cindent: */
