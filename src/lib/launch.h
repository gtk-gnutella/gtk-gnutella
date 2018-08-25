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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Process launcher.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _launch_h_
#define _launch_h_

/*
 * Public interface.
 */

pid_t launchve(const char *path, char *const argv[], char *const envp[]);

pid_t launchl(const char *path, const char *arg, ...) G_NULL_TERMINATED;
pid_t launchle(const char *path, const char *arg, ...);

pid_t launchl_v(const char *path, const char *arg, va_list ap);
pid_t launchle_v(const char *path,
	const char *arg, va_list ap, char *const envp[]);

#endif	/* _launch_h_ */

/* vi: set ts=4 sw=4 cindent: */
