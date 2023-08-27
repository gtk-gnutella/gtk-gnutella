/*
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Tigertree hash verification.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_verify_tth_h_
#define _core_verify_tth_h_

#include "common.h"
#include "verify.h"

struct tth;

bool verify_tth_append(const char *pathname,
		filesize_t offset, filesize_t amount,
		verify_callback callback, void *user_data);

bool verify_tth_prepend(const char *pathname,
		filesize_t offset, filesize_t amount,
		verify_callback callback, void *user_data);

const struct tth *verify_tth_digest(const struct verify *);
const struct tth *verify_tth_leaves(const struct verify *);
size_t verify_tth_leave_count(const struct verify *);

void verify_tth_init(void);
void verify_tth_shutdown(void);
void verify_tth_close(void);

void request_tigertree(struct shared_file *sf, bool high_priority);

#endif /* _core_verify_tth_h_ */

/* vi: set ts=4 sw=4 cindent: */
