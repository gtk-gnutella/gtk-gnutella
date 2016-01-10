/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Get user's home directory.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef I_PWD
#include <pwd.h>
#endif

#include "constants.h"
#include "gethomedir.h"
#include "misc.h"
#include "path.h"

#include "override.h"			/* Must be the last header included */

/**
 * Compute the user's home directory.
 *
 * Uses the HOME environment variable first, then the entry from /etc/passwd.
 *
 * @return read-only string constant.
 */
const char *
gethomedir(void)
{
	static const char *home;
	const char *dir;

	if G_LIKELY(home != NULL)
		return home;

#ifdef MINGW32
	dir = mingw_get_home_path();
#else
	dir = getenv("HOME");

	if (dir != NULL && !is_absolute_path(dir)) {
		/* Ignore $HOME if it's empty or a relative path */
		g_warning("ignoring environment HOME: not an absolute path");
		dir = NULL;
	}

	if (dir != NULL && !is_directory(dir)) {
		g_warning("ignoring environment HOME: not a directory");
		dir = NULL;
	}

	if (dir != NULL && -1 == access(dir, R_OK | W_OK | X_OK)) {
		g_warning("ignoring non-accessible environment HOME: %m");
		dir = NULL;
	}

#ifdef HAS_GETPWNAM
	if (!dir) {
		const char *name;

		name = getlogin();
		if (name) {
			const struct passwd *pp;

			pp = getpwnam(name);
			if (pp)
				dir = pp->pw_dir;
		}
	}
#endif	/* HAS_GETPWNAM */

#ifdef HAS_GETPWUID
	if (!dir) {
		const struct passwd *pp;

		pp = getpwuid(getuid());
		if (pp)
			dir = pp->pw_dir;
	}
#endif /* HAS_GETPWUID */

	if (NULL == dir) {
		g_warning("could not determine home directory");
		dir = "/";
	}
#endif	/* MINGW32 */

	return home = constant_str(dir);
}

/* vi: set ts=4 sw=4 cindent: */
