/*
 * Copyright (c) 2012 Raphael Manfredi
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
 * Dynamic linker library wrapper functions.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _dl_util_h_
#define _dl_util_h_

/*
 * Public interface.
 */

void dl_util_done(void);
const void *dl_util_get_base(const void *addr);
const char *dl_util_get_path(const void *addr);
const char *dl_util_get_name(const void *addr);
const void *dl_util_get_start(const void *addr);

#endif	/* _dl_util_h_ */

/* vi: set ts=4 sw=4 cindent: */

