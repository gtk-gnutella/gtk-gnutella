/*
 * Copyright (c) 2004, Raphael Manfredi
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
 * File watcher.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _watcher_h_
#define _watcher_h_

#include "common.h"

#include "file.h"

/**
 * The callback invoked when a monitored file changes.
 */
typedef void (*watcher_cb_t)(const char *filename, void *udata);

/*
 * Public interface.
 */

void watcher_init(void);
void watcher_close(void);
void watcher_register(const char *filename, watcher_cb_t cb, void *udata);
void watcher_unregister(const char *filename);
void watcher_register_path(
	const file_path_t *fp, watcher_cb_t cb, void *udata);
void watcher_unregister_path(const file_path_t *fp);

#endif /* _watcher_h_ */

/* vi: set ts=4 sw=4 cindent: */
