/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Miscellaneous common file routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "file.h"
#include "debug.h"
#include "halloc.h"
#include "misc.h"
#include "tm.h"
#include "override.h"		/* Must be the last header included */

static const char orig_ext[] = "orig";
static const char new_ext[] = "new";
static const char instead_str[] = " instead";
static const char empty_str[] = "";

/**
 * In order to avoid having a dependency between file.c and ban.c,
 * we have ban.c register a callback to reclaim file descriptors
 * at init time.
 *		--RAM, 2004-08-18
 */
static reclaim_fd_t reclaim_fd = NULL;

/**
 * Register fd reclaiming callback.
 * Use NULL to unregister it.
 */
void
file_register_fd_reclaimer(reclaim_fd_t callback)
{
	reclaim_fd = callback;
}

/**
 * Open configuration file, renaming it as ".orig" when `renaming' is TRUE.
 * If configuration file cannot be found, try opening the ".orig" variant
 * if already present and `renaming' is TRUE.
 * If not found, try with successive alternatives, if supplied.
 *
 * @attention
 * NB: the supplied `fv' argument is a vector of `fvcnt' elements.
 *
 * @param what is what is being opened, for logging purposes.
 * @param fv is a vector of files to try to open, in sequence
 * @param fvcnt is the size of the vector
 * @param renaming indicates whether the opened file should be renamed .orig.
 * @param chosen is filled with the index of the chosen path in the vector,
 * unless NULL is given.
 *
 * @return opened FILE, or NULL if we were unable to open any.  `chosen' is
 * only filled if the file is opened.
 */
static FILE *
open_read(
	const char *what, const file_path_t *fv, int fvcnt, gboolean renaming,
	int *chosen)
{
	FILE *in;
	char *path;
	char *path_orig;
	const char *instead = empty_str;
	int idx = 0;

	g_assert(fv != NULL);
	g_assert(fvcnt >= 1);

	path = make_pathname(fv->dir, fv->name);
	if (!is_absolute_path(path)) {
		HFREE_NULL(path);
		return NULL;
	}

	path_orig = h_strdup_printf("%s.%s", path, orig_ext);
	in = fopen(path, "r");
	if (in) {
		if (renaming && -1 == rename(path, path_orig))
			g_warning("[%s] could not rename \"%s\" as \"%s\": %s",
				what, path, path_orig, g_strerror(errno));
		goto out;
    } else {
		if (errno != ENOENT) {
			instead = instead_str;			/* Regular file was present */
			g_warning("[%s] failed to retrieve from \"%s\": %s", what, path,
				g_strerror(errno));
		}
        if (fvcnt > 1 && common_dbg > 0)
            g_message("[%s] trying to load from alternate locations...", what);
    }

	/*
	 * Maybe we crashed after having retrieved the file in a previous run
	 * but before being able to write it again correctly?  Try to open the
	 * ".orig" file instead.
	 */

	g_assert(in == NULL);

	if (renaming)
		in = fopen(path_orig, "r");		/* The ".orig", in case of a crash */

	if (in != NULL) {
		instead = instead_str;

		HFREE_NULL(path);
		path = path_orig;
		path_orig = NULL;
	}

	/*
	 * Try with alternatives, if supplied.
	 */

	if (in == NULL && fvcnt > 1) {
		const file_path_t *xfv;
		int xfvcnt;

		instead = instead_str;

		for (xfv = fv + 1, xfvcnt = fvcnt - 1; xfvcnt; xfv++, xfvcnt--) {
			HFREE_NULL(path);
			path = make_pathname(xfv->dir, xfv->name);
			idx++;
			if (NULL != path && NULL != (in = fopen(path, "r")))
				break;
		}
	}

	if (common_dbg > 0) {
		if (in) {
			g_message("[%s] retrieving from \"%s\"%s", what, path, instead);
		} else if (instead == instead_str) {
			g_message("[%s] unable to retrieve: tried %d alternate location%s",
				what, fvcnt, fvcnt == 1 ? "" : "s");
		} else {
			g_message("[%s] unable to retrieve: no alternate locations known",
				what);
		}
	}

out:

	HFREE_NULL(path);
	HFREE_NULL(path_orig);
	if (in != NULL && chosen != NULL)
		*chosen = idx;

	return in;
}

/**
 * Open configuration file, renaming it as ".orig".  If configuration file
 * cannot be found, try opening the ".orig" variant if already present.
 * If not found, try with successive alternatives, if supplied.
 *
 * @attention
 * NB: the supplied `fv' argument is a vector of `fvcnt' elements.
 *
 * @returns opened FILE, or NULL if we were unable to open any.
 */
FILE *
file_config_open_read(const char *what, const file_path_t *fv, int fvcnt)
{
	return open_read(what, fv, fvcnt, TRUE, NULL);
}

/**
 * Open configuration file, without renaming it.  If configuration file
 * cannot be found, try opening the ".orig" variant if already present.
 * If not found, try with successive alternatives, if supplied.
 *
 * @attention
 * NB: the supplied `fv' argument is a vector of `fvcnt' elements.
 *
 * @returns opened FILE, or NULL if we were unable to open any.
 */
FILE *
file_config_open_read_norename(
	const char *what, const file_path_t *fv, int fvcnt)
{
	return open_read(what, fv, fvcnt, FALSE, NULL);
}

/**
 * Same as file_config_open_read_norename(), but also returns the index
 * of the path chosen within the array, if a file was opened at all.
 */
FILE *
file_config_open_read_norename_chosen(
	const char *what, const file_path_t *fv, int fvcnt, int *chosen)
{
	return open_read(what, fv, fvcnt, FALSE, chosen);
}

/**
 * Open configuration file for writing.  We don't clobber the existing file
 * yet and open a ".new" instead.  Renaming will occur afterwards, when
 * file_config_close() is called.
 *
 * @returns opened FILE if success, NULL on error.
 */
static FILE *
file_config_open(const char *what, const file_path_t *fv)
{
	FILE *out = NULL;
	char *path;

	path = h_strconcat(fv->dir, G_DIR_SEPARATOR_S, fv->name, ".",
				new_ext, (void *) 0);
	g_return_val_if_fail(NULL != path, NULL);

	if (is_absolute_path(path)) {
		out = file_fopen(path, "w");
		if (out == NULL)
			g_warning("unable to persist %s", what);
		HFREE_NULL(path);
	}
	return out;
}

/**
 * Open configuration file for writing.
 */
FILE *
file_config_open_write(const char *what, const file_path_t *fv)
{
    return file_config_open(what, fv);
}

/**
 * Close configuration file opened for writing, and rename it.
 *
 * @returns TRUE on success.
 */
gboolean
file_config_close(FILE *out, const file_path_t *fv)
{
	char *path = NULL;
	char *path_new = NULL;
	gboolean success = FALSE;

	if (0 != fclose(out)) {
		g_warning("could not flush \"%s\": %s", fv->name, g_strerror(errno));
		goto failed;
	}

	path = make_pathname(fv->dir, fv->name);
	g_return_val_if_fail(NULL != path, FALSE);
	path_new = h_strdup_printf("%s.%s", path, new_ext);
	if (NULL == path_new)
		goto failed;

	if (-1 == rename(path_new, path)) {
		g_warning("could not rename \"%s\" as \"%s\": %s",
			path_new, path, g_strerror(errno));
		goto failed;
	}

	success = TRUE;

failed:

	HFREE_NULL(path_new);
	HFREE_NULL(path);
	return success;
}

/**
 * Emit the configuration preamble.
 */
void
file_config_preamble(FILE *out, const char *what)
{
	time_t now = tm_time();

	g_assert(out);

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n", out);
	fprintf(out, "#\n# %s saved on %s\n#\n\n", what, timestamp_to_string(now));
}

/**
 * Initializes `fp' with directory path `dir' and filename `name'.
 */
void
file_path_set(file_path_t *fp, const char *dir, const char *name)
{
	g_assert(fp);
	g_assert(dir);
	g_assert(name);
	g_assert(is_absolute_path(dir));

	fp->dir = dir;
	fp->name = name;
}

/**
 * Open file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless `missing' is true, in which
 * case no error is logged for ENOENT.
 */
static int
do_open(const char *path, int flags, int mode,
	gboolean missing, gboolean absolute)
{
	const char *what;
	int fd;

	if (absolute && !is_absolute_path(path)) {
		errno = EPERM;
		return -1;
	}

#ifdef O_NOCTTY
	flags |= O_NOCTTY;
#endif /* O_NOCTTY */

	fd = open(path, flags, mode);
	if (fd < 0) {
		if (flags & O_CREAT)
			what = "create";
		else if (flags & O_RDONLY)
			what = "read";
		else if (flags & O_WRONLY)
			what = "write into";
		else
			what = "open";

		/*
		 * If we ran out of file descriptors, try to reclaim one from the
		 * banning pool and retry.
		 */

		if (
			(errno == EMFILE || errno == ENFILE) &&
			reclaim_fd != NULL && (*reclaim_fd)()
		) {
			fd = open(path, flags, mode);
			if (fd >= 0) {
				g_warning("do_open(): had to close a banned fd to %s file",
					what);
			}
		}
	}

	if (fd >= 0) {
		fd = get_non_stdio_fd(fd);
		set_close_on_exec(fd);	/* Just in case */
		return fd;
	}

	/*
	 * Hack for broken libc, which can return -1 with errno = 0!
	 * This happens when compiling with gcc-3.x and linking with -lpthread
	 * on a Debian linux system.
	 *		--RAM, 15/02/2004
	 */

	if (errno == 0) {
		g_warning("do_open(): "
			"open() returned -1 with errno = 0, assuming ENOENT");
		errno = ENOENT;
	}

	if (!missing || errno != ENOENT) {
		g_warning("do_open(): can't %s file \"%s\": %s",
			what, path, g_strerror(errno));
	}

	return -1;
}

/**
 * Open file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning.
 *
 * This is a perfect replacement for the open() system call, with logging
 * on errors.
 */
int
file_open(const char *path, int flags, int mode)
{
	return do_open(path, flags, mode, FALSE, FALSE);
}

/**
 * Open file given with absolute pathname.
 * Returns file descriptor or -1 on error with errno set.
 * Errors are logged as a warning.
 */
int
file_absolute_open(const char *path, int flags, int mode)
{
	return do_open(path, flags, mode, FALSE, TRUE);
}

/**
 * Open absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless the file is missing, in which
 * case nothing is logged.
 */
int
file_open_missing(const char *path, int flags)
{
	return do_open(path, flags, 0, TRUE, TRUE);
}

/**
 * Create absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning.
 */
int
file_create(const char *path, int flags, int mode)
{
	return do_open(path, flags | O_CREAT, mode, FALSE, TRUE);
}

/**
 * Create absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless the error is ENOENT which means
 * the directory does not exist.
 */
int
file_create_missing(const char *path, int flags, int mode)
{
	return do_open(path, flags | O_CREAT, mode, TRUE, TRUE);
}

/**
 * Open file, returning FILE pointer if success or NULL on error.
 * Errors are logged as a warning, unless error is ENOENT and `missing'
 * is TRUE.
 */
static FILE *
do_fopen(const char *path, const char *mode, gboolean missing)
{
	char m;
	FILE *f;
	const char *what;

	if (!is_absolute_path(path)) {
		errno = EPERM;
		return NULL;
	}

	f = fopen(path, mode);
	if (f != NULL)
		return f;

	m = *mode;
	if (m == 'r')
		what = "read";
	else if (m == 'w')
		what = "write into";
	else if (m == 'a')
		what = "append to";
	else
		what = "open";

	/*
	 * If we ran out of file descriptors, try to reclaim one from the
	 * banning pool and retry.
	 */

	if (
		(errno == EMFILE || errno == ENFILE) &&
		reclaim_fd != NULL && (*reclaim_fd)()
	) {
		f = fopen(path, mode);
		if (f != NULL) {
			g_warning("had to close a banned fd to %s file", what);
			return f;
		}
	}

	if (!missing || errno != ENOENT)
		g_warning("can't %s file \"%s\": %s", what, path, g_strerror(errno));

	return NULL;
}

/**
 * Open file, returning FILE pointer if success or NULL on error.
 * Errors are logged as a warning.
 */
FILE *
file_fopen(const char *path, const char *mode)
{
	return do_fopen(path, mode, FALSE);
}

/**
 * Open file, returning FILE pointer if success or NULL on error.
 * Errors are logged as a warning, unless the file is missing, in which
 * case nothing is logged.
 */
FILE *
file_fopen_missing(const char *path, const char *mode)
{
	return do_fopen(path, mode, TRUE);
}

/* vi: set ts=4: */
