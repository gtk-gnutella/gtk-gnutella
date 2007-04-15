/*
 * $Id$
 *
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
 * Handles the server-side of the Browse Host function.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2005
 */

#ifndef _core_special_upload_h_
#define _core_special_upload_h_

#include "common.h"

typedef void (*special_upload_closed_t)(gpointer arg);
typedef void (*special_upload_writable_t)(gpointer arg);

struct special_upload {
	struct txdriver *tx;
	ssize_t (*read)(struct special_upload *, gpointer dest, size_t size);
	ssize_t (*write)(struct special_upload *, gconstpointer data, size_t size);
	void (*flush)(struct special_upload *,
					special_upload_closed_t cb, gpointer arg);
	void (*close)(struct special_upload *, gboolean fully_served);
};

#endif /* _core_special_upload_h_ */

/* vi: set ts=4 sw=4 cindent: */
