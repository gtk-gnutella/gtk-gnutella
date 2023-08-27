/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006-2008, Christian Biere
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
 * Miscellaneous compatibility routines.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#ifndef _compat_misc_h_
#define _compat_misc_h_

bool compat_is_superuser(void);
int compat_daemonize(const char *directory);
int compat_kill_zero(pid_t pid);
bool compat_process_exists(pid_t pid);

void compat_fadvise_sequential(int fd, fileoffset_t offset, fileoffset_t size);
void compat_fadvise_random(int fd, fileoffset_t offset, fileoffset_t size);
void compat_fadvise_noreuse(int fd, fileoffset_t offset, fileoffset_t size);
void compat_fadvise_dontneed(int fd, fileoffset_t offset, fileoffset_t size);
void *compat_memmem(const void *data, size_t data_size,
		const void *pattern, size_t pattern_size);


#endif /* _compat_misc_h_ */

/* vi: set ts=4 sw=4 cindent: */
