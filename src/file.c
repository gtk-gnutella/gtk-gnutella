/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Miscellaneous common file routines.
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

#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

RCSID("$Id$");

static const gchar *orig_ext = ".orig";
static const gchar *new_ext = ".new";
static const gchar *instead_str = " instead";
static const gchar *empty_str = "";

/*
 * file_config_open_read
 *
 * Open configuration file, renaming it as ".orig".  If configuration file
 * cannot be found, try opening the ".orig" variant if already present.
 * If not found, try with successive alternatives, if supplied.
 *
 * NB: the supplied `fv' argument is a vector of `fvcnt' elements.
 *
 * Returns opened FILE, or NULL if we were unable to open any.
 */
FILE *file_config_open_read(
	const gchar *what, const file_path_t *fv, gint fvcnt)
{
	FILE *in = NULL;
	gchar *path;
	gchar *path_orig;
	const gchar *error;
	struct stat buf;
	const gchar *instead = empty_str;

	g_assert(fv != NULL);
	g_assert(fvcnt >= 1);
	
	path = g_strdup_printf("%s/%s", fv->dir, fv->name);
	g_return_val_if_fail(NULL != path, NULL);
	path_orig = g_strdup_printf("%s%s", path, orig_ext);
	if (NULL == path_orig)
		goto out;

	in = fopen(path, "r");

	if (in) {
		if (-1 == rename(path, path_orig))
			g_warning("[%s] could not rename \"%s\" as \"%s\": %s",
				what, path, path_orig, g_strerror(errno));
		goto out;
    } else {
		g_warning("[%s] failed to retrieve from \"%s\"", what, path);
        if (fvcnt > 1)
            g_warning("[%s] trying to load from alternate locations...", what);
    }

	error = g_strerror(errno);

	if (-1 != stat(path, &buf)) {
		instead = instead_str;			/* Regular file was present */
		g_warning("[%s] unable to open \"%s\": %s",
			what, path, error);
	}

	/*
	 * Maybe we crashed after having retrieved the file in a previous run
	 * but before being able to write it again correctly?  Try to open the
	 * ".orig" file instead.
	 */

	in = fopen(path_orig, "r");	/* The ".orig", in case of a crash */

	/*
	 * Try with alternatives, if supplied.
	 */

	if (in == NULL && fvcnt > 1) {
		const file_path_t *xfv;
		gint xfvcnt;

		instead = instead_str;

		for (xfv = fv + 1, xfvcnt = fvcnt - 1; xfvcnt; xfv++, xfvcnt--) {
			G_FREE_NULL(path);
			path = g_strdup_printf("%s/%s", xfv->dir, xfv->name);
			if (NULL != path && NULL != (in = fopen(path, "r")))
				break;
		}
	}

	if (in)
		g_warning("[%s] retrieving from \"%s\"%s", what, path, instead);
	else if (instead == instead_str)
		g_warning("[%s] unable to retrieve: tried %d alternate location%s",
			what, fvcnt, fvcnt == 1 ? "" : "s");
    else 
		g_warning("[%s] unable to retrieve: no alternate locations known",
			what);
    
out:

	if (NULL != path)
		G_FREE_NULL(path);
	if (NULL != path_orig)
		G_FREE_NULL(path_orig);
	return in;
}

/*
 * file_config_open_write
 *
 * Open configuration file for writing.  We don't clobber the existing file
 * yet and open a ".new" instead.  Renaming will occur afterwards, when
 * file_config_close() is called.
 *
 * Returns opened FILE if success, NULL on error.
 */
FILE *file_config_open_write(const gchar *what, const file_path_t *fv)
{
	FILE *out = NULL;
	char *path;

	path = g_strdup_printf("%s/%s%s", fv->dir, fv->name, new_ext);
	g_return_val_if_fail(NULL != path, NULL);

	out = fopen(path, "w");
	if (out == NULL)
		g_warning("unable to create \"%s\" to persist %s: %s",
			path, what, g_strerror(errno));
	G_FREE_NULL(path);
	return out;
}

/*
 * file_config_close
 *
 * Close configuration file opened for writing, and rename it.
 * Returns TRUE on success.
 */
gboolean file_config_close(FILE *out, const file_path_t *fv)
{
	char *path = NULL;
	char *path_new = NULL;

	if (0 != fclose(out)) {
		g_warning("could not flush \"%s\": %s", fv->name, g_strerror(errno));
		goto failed;
	}

	path = g_strdup_printf("%s/%s", fv->dir, fv->name);
	g_return_val_if_fail(NULL != path, FALSE);
	path_new = g_strdup_printf("%s%s", path, new_ext);
	if (NULL == path_new)
		goto failed;

	if (-1 == rename(path_new, path)) {
		g_warning("could not rename \"%s\" as \"%s\": %s",
			path_new, path, g_strerror(errno));
		goto failed;
	}

	G_FREE_NULL(path_new);
	G_FREE_NULL(path);
	return TRUE;

failed:

	if (NULL != path_new)
		G_FREE_NULL(path_new);
	if (NULL != path)
		G_FREE_NULL(path);
	return FALSE;
}

/*
 * file_config_preamble
 *
 * Emit the configuration preamble.
 */
void file_config_preamble(FILE *out, const gchar *what)
{
	time_t now = time((time_t *) NULL);

	g_assert(out);

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n", out);
	fprintf(out, "#\n# %s saved on %s#\n\n", what, ctime(&now));
}

