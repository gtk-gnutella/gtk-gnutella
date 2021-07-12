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
 * @ingroup lib
 * @file
 *
 * Output stream.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _ostream_h_
#define _ostream_h_

#include "common.h"

struct slist;
struct pmsg;
struct str;

struct ostream;
typedef struct ostream ostream_t;

/*
 * Public interface.
 */

bool ostream_is_file(const ostream_t *os);
bool ostream_is_memory(const ostream_t *os);
ostream_t *ostream_open_memory(void);
struct slist *ostream_close_memory(ostream_t *os);
ostream_t *ostream_open_fd(int fd);
ostream_t *ostream_open_file(FILE *f);
ostream_t *ostream_open_str(struct str *s);
ostream_t *ostream_open_pmsg(struct pmsg *mb);
int ostream_close_file(ostream_t *os);
bool ostream_has_ioerr(const ostream_t *os);
bool ostream_close(ostream_t *os);

ssize_t ostream_write(ostream_t *os, const void *data, size_t len);
ssize_t ostream_printf(ostream_t *os, const char *fmt, ...) G_PRINTF(2, 3);
ssize_t ostream_putc(ostream_t *os, int c);
ssize_t ostream_puts(ostream_t *os, const char *s);

#endif /* _ostream_h_ */

/* vi: set ts=4 sw=4 cindent: */
