/*
 * Copyright (c) 2004, Christian Biere
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
 * @ingroup ui
 * @file
 *
 * Wraping structures for I/O.
 *
 * @author Christian Biere
 * @date 2004
 */

#ifndef _if_core_wrap_h_
#define _if_core_wrap_h_

#include "sockets.h"		/* For enum socket_buftype */

#include "lib/gnet_host.h"

enum wrap_io_magic { WRAP_IO_MAGIC = 0x40b20646 };

typedef struct wrap_io {
	enum wrap_io_magic magic;
	void *ctx;
	ssize_t (*write)(struct wrap_io *, const void *, size_t);
	ssize_t (*read)(struct wrap_io *, void *, size_t);
	ssize_t (*writev)(struct wrap_io *, const iovec_t *, int);
	ssize_t (*readv)(struct wrap_io *, iovec_t *, int);
	ssize_t (*sendto)(struct wrap_io *, const gnet_host_t *,
						const void *, size_t);
	int (*flush)(struct wrap_io *);
	int (*fd)(struct wrap_io *);
	unsigned (*bufsize)(struct wrap_io *, enum socket_buftype);
} wrap_io_t;

static inline void
wrap_io_check(const struct wrap_io * const wio)
{
	g_assert(wio != NULL);
	g_assert(WRAP_IO_MAGIC == wio->magic);
}

typedef struct wrap_buf {
	size_t	pos;		/**< Current position in the buffer. */
	size_t	len;		/**< Amount of currently buffered bytes. */
	size_t	size;		/**< The size of the buffer. */
	char	*ptr;		/**< The walloc()ed buffer. */
} wrap_buf_t;

#endif /* _if_core_wrap_h_ */

/* vi: set ts=4 sw=4 cindent: */
