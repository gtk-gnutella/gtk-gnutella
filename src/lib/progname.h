/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Program name management.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _progname_h_
#define _progname_h_

/*
 * Protected interface.
 */

#ifdef SETPROCTITLE_SOURCE
char *progname_args_start(void);
size_t progname_args_size(void);
#endif

/*
 * Public interface.
 */

struct tmval;

void progstart(int argc, char * const *argv);
bool progstart_was_called(void);
struct tmval progstart_time(void);
int progstart_dup(const char ***argv_ptr, const char ***envp_ptr);
const char *progstart_arg(int n);

#ifndef HAS_GETPROCNAME
const char *getprogname(void);
#endif

#ifndef HAS_SETPROCNAME
void setprogname(const char *name);
#endif

#endif	/* _progname_h_ */

/* vi: set ts=4 sw=4 cindent: */
