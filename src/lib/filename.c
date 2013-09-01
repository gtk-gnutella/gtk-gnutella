/*
 * Copyright (c) 2001-2009, Raphael Manfredi
 * Copyright (c) 2003-2008, Christian Biere
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
 * Filename manipulation functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2009
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "filename.h"
#include "ascii.h"
#include "concat.h"
#include "glib-missing.h"	/* For g_strlcat() with glib 1.x */
#include "halloc.h"
#include "path.h"
#include "random.h"
#include "str.h"
#include "utf8.h"

#include "if/core/guid.h"

#include "override.h"			/* Must be the last header included */

/**
 * Shrinks a filename so that it fits into the given buffer. The function
 * tries to preserve the filename extension if there is any. The UTF-8
 * encoding is also preserved.
 *
 * @return The length of the resulting filename.
 */
size_t
filename_shrink(const char *filename, char *buf, size_t size)
{
	const char *ext;
	size_t ext_size = 0, ret;

	g_assert(filename);
	g_assert(buf);
	
	/* Try to preserve the filename extension */
	ext = strrchr(filename, '.');
	if (ext) {
		ext_size = strlen(ext) + 1;	/* Include NUL */
		if (ext_size >= size) {
			/*
			 * If it's too long, assume it's not extension at all.
			 * We must truncate the "extension" anyway and also
			 * preserve the UTF-8 encoding by all means.
			 */
			ext_size = 0;
			ext = NULL;
		}
	}

	g_assert(ext_size < size);
	utf8_strlcpy(buf, filename, size - ext_size);

	/* Append the filename extension */
	if (ext) {
		g_strlcat(buf, ext, size);
	}

	ret = strlen(buf);
	g_assert(ret < size);
	return ret;
}

static char *
unique_pathname(const char *path, const char *filename,
		bool (*name_is_uniq)(const char *pathname))
{
	char *pathname;
	
	if (!name_is_uniq) {
		name_is_uniq = path_does_not_exist;
	}
	pathname = make_pathname(path, filename);
	if (!(*name_is_uniq)(pathname)) {
		HFREE_NULL(pathname);
	}
	return pathname;
}

static inline bool
filename_is_evil_char(int c)
{
	/**
	 * NOTE: Parentheses "()" are not included because $ (dollar) and ` (tick)
	 *		 are considered evil. Applications and users failing to escape
	 *		 characters on the shell would still have trouble but it's not
	 *		 as serious and certainly not our fault.
	 */
	switch (c) {
	case '$':
	case '&':
	case '*':
	case '\\':
	case '`':
	case ':':
	case ';':
	case '\'':
	case '"':
	case '<':
	case '>':
	case '?':
	case '|':
	case '~':
	case '\177':
		return TRUE;
	}
	return FALSE;
}

static bool
filename_is_reserved(const char *filename)
{
	const char *endptr;

	if ('\0' == filename[0])
		return TRUE;

	/**
	 * FIXME: Doesn't this apply to CYGWIN, too?
	 */
	if (!is_running_on_mingw())
		return FALSE;

	/**
	 * The following may be a superset because PRN1 is (probably) not reserved.
	 */

	if (!(
	 	(endptr = is_strcaseprefix(filename, "aux")) ||
		(endptr = is_strcaseprefix(filename, "com")) ||
		(endptr = is_strcaseprefix(filename, "con")) ||
		(endptr = is_strcaseprefix(filename, "lpt")) ||
		(endptr = is_strcaseprefix(filename, "nul")) ||
		(endptr = is_strcaseprefix(filename, "prn"))
	))
		return FALSE;
	
	switch (*endptr) {
	case '\0':
		return TRUE;
	case '.':
		/* con.txt is reserved con.blah.txt isn't */
		return NULL == strchr(&endptr[1], '.');
	case '1': case '2': case '3': case '4': case '5': case '6': case '7':
	case '8': case '9': 
		/* lpt0, com0 are not reserved */
		endptr++;
		switch (*endptr) {
		case '\0':
			return TRUE;
		case '.':
			/* com1.txt is reserved com1.blah.txt isn't */
			return NULL == strchr(&endptr[1], '.');
		}
		break;
	}

	/* com1blah.txt is not reserved */
	return FALSE;
}

/**
 * Creates a valid and sanitized filename from the supplied string. For most
 * Unix-like platforms anything goes but for security reasons, shell meta
 * characters are replaced by harmless characters.
 *
 * @param filename the suggested filename.
 * @param no_spaces if TRUE, spaces are replaced with underscores.
 * @param no_evil if TRUE, "evil" characters are replaced with underscores.
 *
 * @returns a newly allocated string using halloc() or ``filename''
 *			if it was a valid filename already.
 */
char *
filename_sanitize(const char *filename, bool no_spaces, bool no_evil)
{
	const char *p;
	const char *s;
	char *q;

	g_assert(filename);

	/* Almost all evil characters are forbidden on Windows, anyway */
	no_evil |= is_running_on_mingw();

	/* Leading spaces are just confusing */
	p = skip_ascii_spaces(filename);

	/* Make sure the filename isn't too long */
	if (strlen(p) >= FILENAME_MAXBYTES) {
		q = halloc(FILENAME_MAXBYTES);
		filename_shrink(p, q, FILENAME_MAXBYTES);
		s = q;
	} else {
		s = p;
		q = NULL;
	}

	/* Replace shell meta characters and likely problematic characters */
	{
		size_t i;
		uchar c;
		
		for (i = 0; '\0' != (c = s[i]); i++) {
			if (
				c < 32
				|| is_ascii_cntrl(c)
				|| G_DIR_SEPARATOR == c
				|| '/' == c 
				|| (0 == i && ('.' == c || '-' == c))
				|| (no_spaces && is_ascii_space(c))
				|| (no_evil && filename_is_evil_char(c))
		   ) {
				if (!q)
					q = h_strdup(s);
				q[i] = '_';	/* replace undesired char with underscore */
			}
		}

		/**
		 * Windows does not like filenames ending with a space or period.
		 */
		while (i-- > 0 && (is_ascii_space(s[i]) || '.' == s[i])) {
			if (!q)
				q = h_strdup(s);
			q[i] = '\0';	/* truncate string */
		}
	}

	if (filename_is_reserved(q ? q : s)) {
		HFREE_NULL(q);
		q = h_strdup("noname");
	}

	if (NULL == q && s != filename)
		q = h_strdup(s);		/* Trimmed leading white space, must copy */

	return q ? q : deconstify_gchar(s);
}

/**
 * Make filename prettier, by removing leading "_", making sure the filename
 * does not start with "-" or ".", and stripping consecutive "_" or "_" that
 * surround a punctuation character.
 *
 * Finally, ensure the filename is not completely empty, as this is
 * awkward to manipulate from a shell.
 *
 * @param filename	the filename to beautify
 *
 * @returns a newly allocated string holding the beautified filename, even if
 * it is a mere copy of the original.
 */
char *
filename_beautify(const char *filename)
{
	const char *s;
	char *q;
	uchar c;
	size_t len;
	size_t j = 0;
	static const char punct[] = "_-+=.,<>{}[]";	/* 1st MUST be '_' */
	static const char strip[] = "_-.";
	static const char empty[] = "{empty}";

	g_assert(filename);

	s = filename;
	len = strlen(filename);
	q = halloc(len + 1);		/* Trailing NUL */

	while ((c = *s++)) {
		uchar d;

		/* Beautified filename cannot start with stripped characters */
		if (j == 0) {
			if (NULL == strchr(strip, c))
				q[j++] = c;
			continue;
		}

		g_assert(j > 0);

		d = q[j - 1];		/* Last char we've kept in beautified name */

		/* A "_" followed by a punctuation character, strip the "_" */
		if (d == '_' && NULL != strchr(punct, c)) {
			q[j - 1] = c;
			continue;
		}

		/* A punctuation character followed by "_", ignore that "_" */
		if (NULL != strchr(&punct[1], d) && c == '_')
			continue;

		q[j++] = c;
	}

	g_assert(j <= len);
	q[j] = '\0';

	/* Ensure we have no empty name */
	if (j == 0) {
		HFREE_NULL(q);
		return h_strdup(empty);
	}

	/*
	 * If there was an extension following stripped chars (e.g. "_.ext"),
	 * then the filename kept will become "ext" (we assume a valid extension
	 * cannot contain "escaped" chars).  In which case we will prepend the
	 * string "{empty}." to it.
	 */

	if (NULL == strchr(q, '.') && j < len && '.' == filename[len - j]) {
		char *r = h_strconcat(empty, ".", q, (void *) 0);
		HFREE_NULL(q);

		return r;
	}

	return q;
}

/**
 * Copies a string into a buffer whereas the string is potentially
 * truncated but the UTF-8 encoding is preserved.
 *
 * @param src The string to copy.
 * @param dst The destination buffer.
 * @param size The size of "dst" in bytes.
 * @return The length of the truncated string in bytes.
 */
static size_t
utf8_truncate(const char *src, char *dst, size_t size)
{
	g_assert(src);
	g_assert(0 == size || NULL != dst);

	if (size > 0) {
		utf8_strlcpy(dst, src, size);
		return strlen(dst);
	} else {
		return 0;
	}
}

/**
 * Determine unique filename for `file' in `path', with optional trailing
 * extension `ext'.  If no `ext' is wanted, one must supply an empty string.
 *
 * @param path A directory path.
 * @param file The basename for the resulting pathname.
 * @param ext An optional filename extension to be appended to the basename.
 * @param name_is_uniq An optional callback to decide whether a created
 *        pathname is uniq. If omitted, the default is file_does_not_exist().
 *
 * @returns the chosen unique complete filename as a pointer which must be
 * freed via hfree().
 */
char *
filename_unique(const char *path, const char *name, const char *ext,
		bool (*name_is_uniq)(const char *pathname))
{
	char filename_buf[FILENAME_MAXBYTES];
	char name_buf[FILENAME_MAXBYTES];
	char mid_buf[32];
	char ext_buf[32];
	const char *mid;
	char *pathname;
	size_t name_len, mid_len, ext_len;
	int i;

	g_assert(path);
	g_assert(name);
	g_assert(ext);
	g_assert(is_absolute_path(path));

	STATIC_ASSERT(sizeof filename_buf >
		sizeof mid_buf + sizeof ext_buf + GUID_HEX_SIZE);

	/**
	 * NOTE: The generated filename must not exceed FILENAME_MAXBYTES
	 *		 because such a file cannot be created. In reality, it depends
	 *		 on the filesystem as well and the limit might be even smaller.
	 *		 In any case, we don't want to cut-off arbitrary bytes but
	 *		 at least preserve the filename extension and the (potential)
	 *		 UTF-8 encoding.
	 */

	/* Because "ext" can be an additional extension like .BAD rather than
	 * one that indicates the filetype, try to preserve the next "extension"
	 * as well, if there's any. */
	mid = strrchr(name, '.');
	if (NULL == mid || mid == name || strlen(mid) >= sizeof mid_buf) {
		mid = strchr(name, '\0');
	}

	ext_len = strlen(ext);
	mid_len = strlen(mid);
	name_len = strlen(name) - mid_len;

	ext_len = MIN(ext_len, sizeof ext_buf - 1);
	mid_len = MIN(mid_len, sizeof mid_buf - 1);
	name_len = MIN(name_len, sizeof name_buf - 1);

	if (name_len + mid_len + ext_len >= sizeof filename_buf) {
		g_assert(name_len >= ext_len);
		name_len -= ext_len;
	}

	/* Truncate strings so that an UTF-8 encoding is preserved */
	ext_len = utf8_truncate(ext, ext_buf, ext_len + 1);
	mid_len = utf8_truncate(mid, mid_buf, mid_len + 1);
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	str_bprintf(filename_buf, sizeof filename_buf, "%s%s%s",
		name_buf, mid_buf, ext_buf);

	pathname = unique_pathname(path, filename_buf, name_is_uniq);
	if (pathname)
		goto finish;

	if (!is_directory(path))
		return NULL;

	/*
	 * Looks like we need to make the filename more unique.  Append .00, then
	 * .01, etc... until .99.
	 */

	while (name_len + mid_len + ext_len + 3 >= sizeof filename_buf) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	for (i = 0; i < 100; i++) {
		str_bprintf(filename_buf, sizeof filename_buf, "%s.%02u%s%s",
			name_buf, i, mid_buf, ext_buf);

		pathname = unique_pathname(path, filename_buf, name_is_uniq);
		if (pathname)
			goto finish;
	}

	/*
	 * OK, no luck.  Try with a few random numbers then.
	 */

	while (name_len + mid_len + ext_len + 9 >= sizeof filename_buf) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	for (i = 0; i < 100; i++) {
		str_bprintf(filename_buf, sizeof filename_buf, "%s.%x%s%s",
			name_buf, (unsigned) random_u32(), mid_buf, ext_buf);

		pathname = unique_pathname(path, filename_buf, name_is_uniq);
		if (pathname)
			goto finish;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	while (
		name_len + mid_len + ext_len + GUID_HEX_SIZE + 1 >= sizeof filename_buf
	) {
		g_assert(name_len > 0);
		name_len--;
	}
	name_len = utf8_truncate(name, name_buf, name_len + 1);

	{
		struct guid guid;

		guid_random_fill(&guid);
		str_bprintf(filename_buf, sizeof filename_buf, "%s.%s%s%s",
			name_buf, guid_hex_str(&guid), mid_buf, ext_buf);
	}

	pathname = unique_pathname(path, filename_buf, name_is_uniq);
	if (pathname)
		goto finish;

	/*
	 * This may also be the result of permission problems or inode
	 * exhaustion.
	 */
	g_warning("no luck with random number generator");

finish:
	return pathname;
}

/* vi: set ts=4 sw=4 cindent: */
