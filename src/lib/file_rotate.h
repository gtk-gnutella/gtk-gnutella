/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * File rotation.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _file_rotate_h_
#define _file_rotate_h_

/**
 * Operating flags for file_rotate().
 */

#define FILE_ROTATE_SILENT	(0)				/**< Be silent */
#define FILE_ROTATE_ERROR	(1U << 0)		/**< Report errors */
#define FILE_ROTATE_ACTION	(1U << 1)		/**< Report actions */

/*
 * Public interface.
 */

void file_rotate(const char *filename, size_t keep, uint flags);

#endif /* _file_rotate_h_ */

/* vi: set ts=4 sw=4 cindent: */
