/*
 * $Id$
 *
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
typedef gboolean (*verify_callback)(const struct verify *,
										enum verify_status, void *user_data);

void verify_init(void);
void verify_close(void);

void verify_append(const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data);
void verify_prepend(const char *pathname, filesize_t filesize,
	verify_callback callback, void *user_data);

const struct sha1 *verify_sha1(const struct verify *);
filesize_t verify_hashed(const struct verify *);
guint verify_elapsed(const struct verify *);
void verify_cancel(const struct verify *);

#endif	/* _core_verify_h_ */

/* vi: set ts=4: */

