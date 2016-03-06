/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Exit wrapper.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _exit_h_
#define _exit_h_

/**
 * Trap all calls to exit(), redirecting them to our own routine
 * transparently, so that we don't have to pollute all our code.
 */
#define exit(s)		do_exit(s)
#define _exit(s)	do__exit(s)

/*
 * Public interface.
 */

void exit_cleanup(void);
void do_exit(int status) G_NORETURN;
void do__exit(int status) G_NORETURN;

#endif /* _exit_h_ */

/* vi: set ts=4 sw=4 cindent: */
