/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Input stream.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _istream_h_
#define _istream_h_

#include "common.h"

#include "bstr.h"
#include "pmsg.h"

struct istream;
typedef struct istream istream_t;

/*
 * Public interface.
 */

bool istream_is_file(const istream_t *is) G_PURE;
bool istream_is_memory(const istream_t *is) G_PURE;
istream_t *istream_open_fd(int fd);
istream_t *istream_open_file(FILE *f);
int istream_close_file(istream_t *is);
bool istream_has_ioerr(const istream_t *is);
istream_t *istream_open_pmsg(pmsg_t *mb);
istream_t *istream_open_bstr(bstr_t *bs);
bool istream_close(istream_t *is);

size_t istream_bytes_read(const istream_t *is);

ssize_t istream_read(istream_t *is, void *data, size_t len);
int istream_getc(istream_t *is);
void istream_ungetc(istream_t *is, int c);

#endif /* _istream_h_ */

/* vi: set ts=4 sw=4 cindent: */
