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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * File descriptor functions.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006-2008
 */

#ifndef _fd_h_
#define _fd_h_

void fd_close_from(const int first_fd);
void fd_close_unpreserved_from(const int first_fd);
int fd_first_available(void);
int reserve_standard_file_descriptors(void);
void fd_set_close_on_exec(int fd);
void fd_set_nonblocking(int fd);
int fd_fsync(int fd);
int fd_fdatasync(int fd);
int fd_forget_and_close(int *fd_ptr);
int fd_close(int *fd_ptr);
void fd_preserve(int fd);
void fd_notify_socket_closed(socket_fd_t fd);
int fd_get_non_stdio(int fd);
bool fd_need_non_stdio();
bool is_a_socket(int fd);
bool is_a_fifo(int fd);
bool is_open_fd(int fd);
bool fd_accmode_is_valid(const int fd, const int accmode);
bool fd_is_readable_and_writable(const int fd);
bool fd_is_readable(const int fd);
bool fd_is_writable(const int fd);

static inline int
is_valid_fd(int fd)
{
	return fd >= 0;
}

static inline int
cast_to_fd(unsigned int fd)
{
	return fd;
}

#endif /* _fd_h_ */

/* vi: set ts=4 sw=4 cindent: */
