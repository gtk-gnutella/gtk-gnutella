/*
 * Copyright (c) 2005, Christian Biere & Raphael Manfredi
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
 * For special uploads like data which is generated on the fly in contrast
 * to serving shared files.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_special_upload_h_
#define _core_special_upload_h_

#include "common.h"

typedef void (*special_upload_closed_t)(void *arg);
typedef void (*special_upload_writable_t)(void *arg);

#define SPECIAL_UPLOAD_MAGIC_VAL 	0x137b14e0
#define SPECIAL_UPLOAD_MAGIC_MASK 	0xfffffff0	/* Leading 28 bits set */

enum special_upload_magic {
	SPECIAL_UPLOAD_THEX_MAGIC   = SPECIAL_UPLOAD_MAGIC_VAL + 0x1,
	SPECIAL_UPLOAD_BROWSE_MAGIC = SPECIAL_UPLOAD_MAGIC_VAL + 0xc,
};

struct special_upload {
	enum special_upload_magic magic;
	struct txdriver *tx;
	ssize_t (*read)(struct special_upload *, void *dest, size_t size);
	ssize_t (*write)(struct special_upload *, const void *data, size_t size);
	void (*flush)(struct special_upload *,
					special_upload_closed_t cb, void *arg);
	void (*close)(struct special_upload *, bool fully_served);
};

static inline void
special_upload_check(const struct special_upload * const su)
{
	g_assert(su != NULL);
	g_assert(SPECIAL_UPLOAD_MAGIC_VAL ==
		(su->magic & SPECIAL_UPLOAD_MAGIC_MASK));
}

static inline void
special_upload_thex_check(const struct special_upload * const su)
{
	g_assert(su != NULL);
	g_assert(SPECIAL_UPLOAD_THEX_MAGIC == su->magic);
}

static inline void
special_upload_browse_check(const struct special_upload * const su)
{
	g_assert(su != NULL);
	g_assert(SPECIAL_UPLOAD_BROWSE_MAGIC == su->magic);
}

#endif /* _core_special_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
