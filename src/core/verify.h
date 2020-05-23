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

#ifndef _core_verify_h_
#define _core_verify_h_

#include "common.h"

/*
 * Public interface.
 */

enum verify_status {
	VERIFY_INVALID,		/**< Invalid context. */
	VERIFY_START,		/**< Hash calculation is about to start. */
	VERIFY_PROGRESS,	/**< Some chunk has been hashed. */
	VERIFY_DONE,		/**< Hash calculation is finished. */
	VERIFY_ERROR,		/**< Hash calculation failed (I/O error etc.). */
	VERIFY_SHUTDOWN		/**< Hash calculation aborted due to shutdown. */
};

struct verify;

typedef bool (*verify_callback)(const struct verify *,
										enum verify_status, void *user_data);

struct verify_hash {
	const char *	(*name)(void);
	void 			(*init)(filesize_t amount);
	int  			(*update)(const void *data, size_t size);
	int 			(*final)(void);
};

struct verify *verify_new(const struct verify_hash *);
void verify_free(struct verify **ptr);

bool verify_enqueue(struct verify *, int high_priority,
	const char *pathname, filesize_t offset, filesize_t filesize,
	verify_callback callback, void *user_data);

enum verify_status verify_status(const struct verify *);
filesize_t verify_hashed(const struct verify *);
uint verify_elapsed(const struct verify *);

#endif	/* _core_verify_h_ */

/* vi: set ts=4 sw=4 cindent: */

