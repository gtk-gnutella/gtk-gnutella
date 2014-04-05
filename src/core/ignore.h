/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Management of download ignoring list.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_ignore_h_
#define _core_ignore_h_

#include "common.h"

#include "if/gen/ignore.h"

void ignore_init(void);
void ignore_close(void);

struct sha1;

void ignore_timer(time_t now);
ignore_val_t ignore_is_requested(
	const char *file, filesize_t size, const struct sha1 *sha1);

void ignore_add_filesize(const char *file, filesize_t size);
void ignore_add_sha1(const char *file, const struct sha1 *sha1);
const char *ignore_sha1_filename(const struct sha1 *sha1);

#endif	/* _core_ignore_h_ */

/* vi: set ts=4 sw=4 cindent: */
