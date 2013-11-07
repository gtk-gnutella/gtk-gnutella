/*
 * Copyright (c) 2006 Christian Biere
 * Copyright (c) 2013 Raphael Manfredi
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
 * Sharing of file descriptors through file objects.
 *
 * @author Christian Biere
 * @date 2006
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _file_object_h_
#define _file_object_h_

#include "common.h"

void file_object_init(void);
void file_object_close(void);

struct file_object *file_object_new(int fd, const char *pathname, int accmode);
struct file_object *file_object_open(const char *pathname, int accmode);

ssize_t file_object_pwrite(const struct file_object *fo,
					const void *data, size_t buf, filesize_t offset);
ssize_t file_object_pwritev(const struct file_object *fo,
					const iovec_t *iov, int iov_cnt, filesize_t offset);
ssize_t file_object_pread(const struct file_object *fo,
					void *data, size_t size, filesize_t pos);
ssize_t file_object_preadv(const struct file_object *fo,
					iovec_t *iov, int iov_cnt, filesize_t offset);

int file_object_get_fd(const struct file_object *fo);
const char *file_object_get_pathname(const struct file_object *fo);

void file_object_release(struct file_object **fo_ptr);
bool file_object_rename(const char * const o, const char * const n);
bool file_object_unlink(const char * const path);
void file_object_moved(const char * const o, const char * const n);
int file_object_fstat(const struct file_object * const fo, filestat_t *b);

#endif /* _file_object_h_ */

/* vi: set ts=4 sw=4 cindent: */
