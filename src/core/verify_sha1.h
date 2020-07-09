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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Hash verification.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_verify_sha1_h_
#define _core_verify_sha1_h_

#include "common.h"

#include "verify.h"

int verify_sha1_enqueue(int high_priority,
	const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data);

const struct sha1 *verify_sha1_digest(const struct verify *);

void verify_sha1_init(void);
void verify_sha1_close(void);

#endif	/* _core_verify_sha1_h_ */

/* vi: set ts=4 sw=4 cindent: */

