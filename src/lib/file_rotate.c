/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * File rotation, preserving trailing extensions when present.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "file_rotate.h"

#include "spinlock.h"
#include "str.h"
#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

/**
 * Rotate `filename', renaming existing files with a .0, .1, .2 extension
 * up to the maximum specified.
 *
 * If there ia a ".ext" extension to the filename, numbering is done before
 * that trailing extension.  Hence "x.stderr" becomes "x.0.stderr" for instance.
 *
 * If flags contains FILE_ROTATE_ERROR, errors are logged.
 * If flags contains FILE_ROTATE_ACTION, actions are logged.
 * Use FILE_ROTATE_SILENT to silently proceed.
 *
 * @param filename		the file to rotate
 * @param keep			how many old versions of the file to keep
 * @param flags			whether to report errors and actions
 */
void
file_rotate(const char *filename, size_t keep, uint flags)
{
	static char nfile[MAX_PATH_LEN];		/* Avoid using too much stack space */
	static spinlock_t lock = SPINLOCK_INIT;	/* Protects access to shared resource */
	size_t i;
	int len;
	const char *dot;

	g_assert(size_is_non_negative(keep));

	/*
	 * Figure out the extension of the given file, so that we can progate
	 * it during renaming.
	 *
	 * This allows Windows to properly open the log files once we
	 * have registered how such an extension should be opened.
	 */

	dot = vstrrchr(filename, '.');
	len = NULL == dot ? (int) vstrlen(filename) : dot - filename;
	g_assert(len >= 0);

	if (NULL == dot)
		dot = &filename[len];	/* Points to trailing NUL -> empty string */

	spinlock(&lock);			/* About to use global nfile[] */

	if (keep != 0) {
		str_bprintf(ARYLEN(nfile), "%.*s.%zu%s", len, filename, keep - 1, dot);

		if (-1 == unlink(nfile)) {
			if (flags & FILE_ROTATE_ERROR)
				s_warning("%s(): cannot unlink \"%s\": %m", G_STRFUNC, nfile);
		} else if (flags & FILE_ROTATE_ACTION) {
			s_message("%s(): removed \"%s\"", G_STRFUNC, nfile);
		}
	}

	for (i = keep - 1; i != 0; i--) {
		static char ofile[MAX_PATH_LEN];

		str_bprintf(ARYLEN(ofile), "%.*s.%zu%s", len, filename, i - 1, dot);
		str_bprintf(ARYLEN(nfile), "%.*s.%zu%s", len, filename, i, dot);

		if (-1 == rename(ofile, nfile)) {
			if (flags & FILE_ROTATE_ERROR) {
				s_warning("%s(): cannot rename \"%s\" as \"%s\": %m",
					G_STRFUNC, ofile, nfile);
			}
		} else if (flags & FILE_ROTATE_ACTION) {
			s_message("%s(): file \"%s\" renamed as \"%s\"",
				G_STRFUNC, ofile, nfile);
		}
	}

	str_bprintf(ARYLEN(nfile), "%.*s.0%s", len, filename, dot);

	if (-1 == rename(filename, nfile)) {
		if (flags & FILE_ROTATE_ERROR) {
			s_warning("%s(): cannot rename \"%s\" as \"%s\": %m",
				G_STRFUNC, filename, nfile);
		}
	} else if (flags & FILE_ROTATE_ACTION) {
		s_message("%s(): file \"%s\" renamed as \"%s\"",
			G_STRFUNC, filename, nfile);
	}

	spinunlock(&lock);
}

/* vi: set ts=4 sw=4 cindent: */
