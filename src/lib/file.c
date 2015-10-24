/*
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

#include "ascii.h"
#include "concat.h"			/* For concat_strings() */
#include "debug.h"
#include "fd.h"
#include "file.h"
#include "halloc.h"
#include "log.h"			/* For s_carp() */
#include "misc.h"			/* For is_strsuffix() */
#include "path.h"
#include "str.h"
#include "stringify.h"		/* For plural() */
#include "timestamp.h"
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
 * Check for file existence.
 */
bool
file_exists(const char *pathname)
{
  	filestat_t st;

    g_assert(pathname != NULL);

    return 0 == stat(pathname, &st) && S_ISREG(st.st_mode);
}

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
 * Search executable within the user's PATH.
 *
 * @return full path if found, NULL otherwise.
 * The returned string is allocated with halloc().
 */
char *
file_locate_from_path(const char *argv0)
{
	static bool already_done;
	char *path;
	char *tok;
	char filepath[MAX_PATH_LEN + 1];
	char *result = NULL;
	char *ext = "";

	if (is_running_on_mingw() && !is_strsuffix(argv0, (size_t) -1, ".exe")) {
		ext = ".exe";
	}

	if (filepath_basename(argv0) != argv0) {
		if (!already_done) {
			s_warning("can't locate \"%s\" in PATH: name contains '%c' already",
				argv0,
				strchr(argv0, G_DIR_SEPARATOR) != NULL ? G_DIR_SEPARATOR : '/');
		}
		goto done;
	}

	path = getenv("PATH");
	if (NULL == path) {
		if (!already_done) {
			s_warning("can't locate \"%s\" in PATH: "
				"no such environment variable", argv0);
		}
		goto done;
	}

	path = h_strdup(path);

	tok = strtok(path, G_SEARCHPATH_SEPARATOR_S);
	while (NULL != tok) {
		const char *dir = tok;
		filestat_t buf;

		if ('\0' == *dir)
			dir = ".";
		concat_strings(filepath, sizeof filepath,
			dir, G_DIR_SEPARATOR_S, argv0, ext, NULL_PTR);

		if (-1 != stat(filepath, &buf)) {
			if (S_ISREG(buf.st_mode) && -1 != access(filepath, X_OK)) {
				result = h_strdup(filepath);
				break;
			}
		}
		tok = strtok(NULL, G_SEARCHPATH_SEPARATOR_S);
	}

	hfree(path);

done:
	already_done = TRUE;	/* No warning on subsequent invocation */
	return result;
}

/**
 * Open configuration file, renaming it as ".orig" when `renaming' is TRUE.
 * If configuration file cannot be found, try opening the ".orig" variant
 * if already present and `renaming' is TRUE.
 * If not found, try with successive alternatives, if supplied.
 *
 * @attention
 * NB: the supplied `fv' argument is a vector of `fvcnt' elements.  Items
 * with a NULL `dir' field are ignored, but fv[0].dir cannot be NULL.
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
	const char *what, const file_path_t *fv, int fvcnt, bool renaming,
	int *chosen)
{
	FILE *in;
	char *path;
	char *path_orig;
	const char *instead = empty_str;
	int idx = 0;

	g_assert(fv != NULL);
	g_assert(fvcnt >= 1);
	g_assert(fv->dir != NULL);

	path = make_pathname(fv->dir, fv->name);
	if (!is_absolute_path(path)) {
		HFREE_NULL(path);
		return NULL;
	}

	path_orig = h_strdup_printf("%s.%s", path, orig_ext);
	in = fopen(path, "r");
	if (in) {
		if (is_running_on_mingw()) {
			/* Windows can't rename an open file */
			fclose(in);
			in = NULL;
		}
		if (renaming && -1 == rename(path, path_orig)) {
			s_warning("[%s] could not rename \"%s\" as \"%s\": %m",
				what, path, path_orig);
		}
		if (NULL == in) {
			in = fopen(path_orig, "r");
		}
		goto out;
    } else {
		if (ENOENT == errno) {
			if (common_dbg > 0) {
				g_debug("[%s] cannot load non-existent \"%s\"", what, path);
			}
		} else {
			instead = instead_str;			/* Regular file was present */
			s_warning("[%s] failed to retrieve from \"%s\": %m", what, path);
		}
        if (fvcnt > 1 && common_dbg > 0)
            g_debug("[%s] trying to load from alternate locations...", what);
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
			if (NULL == xfv->dir)	/* In alternatives, dir may be NULL */
				continue;
			path = make_pathname(xfv->dir, xfv->name);
			idx++;
			if (NULL != path && NULL != (in = fopen(path, "r")))
				break;
			if (path != NULL && common_dbg > 0) {
				g_debug("[%s] cannot load non-existent \"%s\" either",
					what, path);
			}
		}
	}

	if (common_dbg > 0) {
		if (in) {
			g_debug("[%s] retrieving from \"%s\"%s", what, path, instead);
		} else if (instead == instead_str) {
			g_debug("[%s] unable to retrieve: tried %d alternate location%s",
				what, fvcnt, plural(fvcnt));
		} else {
			g_debug("[%s] unable to retrieve: no alternate locations known",
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
 * @note
 * Renaming only happens if the opened file is the first in the vector.
 * Other entries are expected to be fallbacks and are either non-writable
 * or should be left as-is.  Likewise, opening the ".orig" is only attempted
 * for the first entry.
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
 * Same as file_config_open_read(), but also returns the index
 * of the path chosen within the array, if a file was opened at all.
 */
FILE *
file_config_open_read_chosen(
	const char *what, const file_path_t *fv, int fvcnt, int *chosen)
{
	return open_read(what, fv, fvcnt, TRUE, chosen);
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

	path = h_strconcat(fv->dir, G_DIR_SEPARATOR_S, fv->name,
				".", new_ext, NULL_PTR);

	g_return_val_if_fail(NULL != path, NULL);

	if (is_absolute_path(path)) {
		out = file_fopen(path, "w");
		if (out == NULL)
			s_warning("unable to persist %s", what);
	}
	HFREE_NULL(path);
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
bool
file_config_close(FILE *out, const file_path_t *fv)
{
	char *path = NULL;
	char *path_new = NULL;
	bool success = FALSE;

	/*
	 * Be extra careful when operating on filesystems with delayed disk block
	 * allocation, such as "ext4".  If there is a crash and the data was not
	 * properly allocated to disk, we could lose both the old and new file data!
	 *
	 * To fight against that, make sure we sync the new data to disk before
	 * renaming the new file into the old, as the rename operation is likely
	 * to be stored on disk before allocation of the new data blocks is made.
	 *		--RAM, 2013-08-12
	 */

	if (0 != file_sync_fclose(out)) {
		s_warning("could not flush \"%s\": %m", fv->name);
		goto failed;
	}

	path = make_pathname(fv->dir, fv->name);
	g_return_val_if_fail(NULL != path, FALSE);
	path_new = h_strdup_printf("%s.%s", path, new_ext);
	if (NULL == path_new)
		goto failed;

	if (-1 == rename(path_new, path)) {
		s_warning("could not rename \"%s\" as \"%s\": %m", path_new, path);
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
 *
 * The directory must be an absolute path or the entry is initialized with NULL
 * values and a loud warning is emitted.
 */
void
file_path_set(file_path_t *fp, const char *dir, const char *name)
{
	g_assert(fp);
	g_assert(dir);
	g_assert(name);

	/*
	 * For robustness, we no longer assert that the path must be absolute.
	 *
	 * The open_read() routine will skip file_path_t entries in the vector
	 * that are NULL, the only requirement being that the first entry of the
	 * vector be non-NULL, i.e. an absolute path.
	 *
	 * Since this is an abnormal situation, loudly warn so that we may find
	 * out who the culprit is.
	 */

	if (!is_absolute_path(dir)) {
		s_carp("%s(): ignoring non-absolute path \"%s\" for \"%s\"",
			G_STRFUNC, dir, name);

		fp->dir = NULL;
		fp->name = NULL;
	} else {
		fp->dir = dir;
		fp->name = name;
	}
}

/**
 * Open file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless `missing' is TRUE, in which
 * case no error is logged for ENOENT.
 * No errors from open() due to invalid permission are logged when `silent'
 * is TRUE.
 */
static int
do_open(const char *path, int flags, int mode,
	bool missing, bool absolute, bool silent)
{
	const char *what;
	int fd;

	if (absolute && !is_absolute_path(path)) {
		s_warning("%s(): can't open absolute \"%s\": relative path",
			G_STRFUNC, path);
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
		else if (O_RDONLY == (flags & O_ACCMODE))
			what = "read";
		else if (O_WRONLY == (flags & O_ACCMODE))
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
				s_message("%s(): had to reclaim an unused to %s file",
					G_STRFUNC, what);
			}
		}
	}

	if (fd >= 0) {
		fd = get_non_stdio_fd(fd);
		fd_set_close_on_exec(fd);	/* Just in case */
		return fd;
	}

	/*
	 * Hack for broken libc, which can return -1 with errno = 0!
	 * This happens when compiling with gcc-3.x and linking with -lpthread
	 * on a Debian linux system.
	 *		--RAM, 15/02/2004
	 */

	if (errno == 0) {
		s_warning("%s(): open() returned -1 with errno = 0, assuming ENOENT",
			G_STRFUNC);
		errno = ENOENT;
	}

	if (!missing || errno != ENOENT) {
		if (!silent || errno != EACCES) {
			s_warning("%s(): can't %s file \"%s\": %m", G_STRFUNC, what, path);
		}
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
	return do_open(path, flags, mode, FALSE, FALSE, FALSE);
}

/**
 * Same as file_open(), no open() errors logged, but can reclaim fd on shortage.
 */
int
file_open_silent(const char *path, int flags, int mode)
{
	return do_open(path, flags, mode, FALSE, FALSE, TRUE);
}

/**
 * Open file given with absolute pathname.
 * Returns file descriptor or -1 on error with errno set.
 * Errors are logged as a warning.
 */
int
file_absolute_open(const char *path, int flags, int mode)
{
	return do_open(path, flags, mode, FALSE, TRUE, FALSE);
}

/*
 * Same as file_absolute_open(), no open() error logged.
 */
int
file_absolute_open_silent(const char *path, int flags, int mode)
{
	return do_open(path, flags, mode, FALSE, TRUE, TRUE);
}

/**
 * Open absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless the file is missing, in which
 * case nothing is logged.
 */
int
file_open_missing(const char *path, int flags)
{
	return do_open(path, flags, 0, TRUE, TRUE, FALSE);
}

/**
 * Same as file_open_missing(), no error logging.
 */
int
file_open_missing_silent(const char *path, int flags)
{
	return do_open(path, flags, 0, TRUE, TRUE, TRUE);
}

/**
 * Create absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning.
 */
int
file_create(const char *path, int flags, int mode)
{
	return do_open(path, flags | O_CREAT, mode, FALSE, TRUE, FALSE);
}

/**
 * Create absolute file, returning file descriptor or -1 on error with errno set.
 * Errors are logged as a warning, unless the error is ENOENT which means
 * the directory does not exist.
 */
int
file_create_missing(const char *path, int flags, int mode)
{
	return do_open(path, flags | O_CREAT, mode, TRUE, TRUE, FALSE);
}

/**
 * Open file, returning FILE pointer if success or NULL on error.
 * Errors are logged as a warning, unless error is ENOENT and `missing'
 * is TRUE.
 */
static FILE *
do_fopen(const char *path, const char *mode, bool missing)
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
			s_warning("had to close a banned fd to %s file", what);
			return f;
		}
	}

	if (!missing || errno != ENOENT)
		s_warning("can't %s file \"%s\": %m", what, path);

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

/**
 * Close a stream, flushing data to disk.
 *
 * This is needed on "ext4" filesystems or any other filesystem which delays
 * the allocation of data blocks, in case there is a crash between the close
 * and the moment the data is written physically to the disk.
 *
 * @return the fclose() status.
 */
int
file_sync_fclose(FILE *f)
{
	int fd, ret;

	g_assert(f != NULL);

	ret = fflush(f);			/* Send all buffered data to kernel first */
	fd = fileno(f);

	if (-1 == fd_fdatasync(fd))
		s_warning("cannot flush data blocks to disk for fd=%d: %m", fd);

	return fclose(f) | ret;		/* Report error if fflush() failed */
}

/**
 * Remove trailing white space from line held within buffer.
 *
 * This is meant to be used to validate the line returned by fgets() and to
 * remove final "\n", or "\r\n" markers as well as any other trailing white
 * space.
 *
 * @param line		buffer where line is held
 * @param size		buffer size
 * @paran lenptr	if non-NULL, the final string length is written there
 *
 * @return TRUE if we were facing a line terminated by "\n", FALSE otherwise.
 */
bool
file_line_chomp_tail(char *line, size_t size, size_t *lenptr)
{
	size_t len;
	char *p;

	len = clamp_strlen(line, size);

	if (size == len || 0 == len)
		return FALSE;		/* No NUL found or empty string */

	if ('\n' != line[len - 1])
		return FALSE;		/* Truncated line, reading buffer was too small */

	p = &line[len - 1];
	do {
		*p = '\0';
	} while (p != line && is_ascii_space(*--p));

	if (lenptr != NULL)
		*lenptr = p - line + ('\0' == *p ? 0 : 1);

	return TRUE;
}

/**
 * Convert open() flags to string, for debugging and logging purposes.
 *
 * @param flags		open() flags value
 *
 * @return pointer to static string.
 */
const char *
file_oflags_to_string(int flags)
{
	str_t *s = str_private(G_STRFUNC, 32);

	/* We assume there will be at least one of O_RDWR, O_RDONLY or O_WRONLY */

	str_printf(s, "%s%s%s%s%s",
		file_accmode_to_string(flags),
		(flags & O_APPEND)	? " | O_APPEND" : "",
		(flags & O_CREAT)	? " | O_CREAT" : "",
		(flags & O_TRUNC)	? " | O_TRUNC" : "",
		(flags & O_EXCL)	? " | O_EXCL" : "");

	return str_2c(s);
}

/**
 * Convert open() access mode to string, for debugging and logging purposes.
 *
 * @param accmode	open() access mode value (O_RDWR, O_RDONLY, O_WRONLY)
 *
 * @return pointer to static string.
 */
const char *
file_accmode_to_string(const int accmode)
{
	switch (accmode & O_ACCMODE) {
	case O_RDWR:	return "O_RDWR";
	case O_WRONLY:	return "O_WRONLY";
	case O_RDONLY:	return "O_RDONLY";
	default:		return "UNKNOWN_ACCMODE";
	}
}

/* vi: set ts=4: */
