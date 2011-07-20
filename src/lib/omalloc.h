/*
 * $Id$
 *
 * Copyright (c) 2010 Raphael Manfredi
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
 * Memory allocator for objects that are never resized nor freed.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _omalloc_h_
#define _omalloc_h_

void *omalloc(size_t size) G_GNUC_MALLOC;
void *omalloc0(size_t size) G_GNUC_MALLOC;
char *ostrdup(const char *str) G_GNUC_MALLOC;

size_t omalloc_page_count(void);
void set_omalloc_debug(guint32 level);
void omalloc_close(void);

#endif /* _omalloc_h_ */

/* vi: set ts=4 sw=4 cindent:  */
