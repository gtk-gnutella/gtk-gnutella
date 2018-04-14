/*
 * Copyright (c) 2001-2008, 2013 Raphael Manfredi
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
 * Miscellaneous functions.
 *
 * @author Raphael Manfredi
 * @date 2001-2008, 2013
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

#include "misc.h"

#include "ascii.h"
#include "atomic.h"
#include "atoms.h"
#include "base16.h"
#include "base32.h"
#include "buf.h"
#include "compat_misc.h"
#include "concat.h"
#include "cstr.h"
#include "endian.h"
#include "entropy.h"
#include "halloc.h"
#include "hstrfn.h"
#include "htable.h"
#include "html_entities.h"
#include "log.h"				/* For log_file_printable() */
#include "mempcpy.h"
#include "once.h"
#include "parse.h"
#include "path.h"
#include "pow2.h"
#include "random.h"
#include "sha1.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"
#include "utf8.h"
#include "walloc.h"

#include "if/core/guid.h"

#include "override.h"			/* Must be the last header included */

/**
 * Checks whether ``prefix'' is a prefix of ``str''.
 * Maybe skip_prefix() would be a better name.
 *
 * @param str a NUL-terminated string
 * @param prefix a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``str''. Otherwise, a
 *			pointer to the first character in ``str'' after the prefix.
 */
char *
is_strprefix(const char *str, const char *prefix)
{
	const char *s, *p;
	int c;

	g_assert(NULL != str);
	g_assert(NULL != prefix);

	for (s = str, p = prefix; '\0' != (c = *p); p++) {
		if (c != *s++)
			return NULL;
	}

	return deconstify_gchar(s);
}

/**
 * Checks whether ``prefix'' is a prefix of ``str'' performing an
 * case-insensitive (ASCII only) check.
 * Maybe skip_caseprefix() would be a better name.
 *
 * @param str a NUL-terminated string
 * @param prefix a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``str''. Otherwise, a
 *			pointer to the first character in ``str'' after the prefix.
 */
char *
is_strcaseprefix(const char *str, const char *prefix)
{
	const char *s, *p;
	int a;

	g_assert(NULL != str);
	g_assert(NULL != prefix);

	for (s = str, p = prefix; '\0' != (a = *p); p++) {
		int b = *s++;

		/*
		 * Optimize a bit: if case matches, or we're dealing with a non-letter
		 * character, there's no need to invoke acscii_tolower().
		 */

		if (a != b && ascii_tolower(a) != ascii_tolower(b))
			return NULL;
	}

	return deconstify_gchar(s);
}

/**
 * Check whether ``suffix'' is the end of ``str''.
 *
 * @param str		a NUL-terminated string or array of "len" bytes.
 * @param len		length of ``str'', (size_t)-1 means compute it
 * @param suffix	the suffix to look for (NUL-terminated string)
 *
 * @return NULL if suffix is not found, a pointer to the start of it otherwise.
 */
char *
is_strsuffix(const char *str, size_t len, const char *suffix)
{
	size_t suffix_len;

	g_assert(NULL != str);
	g_assert(NULL != suffix);

	len = (size_t)-1 == len ? strlen(str) : len;
	suffix_len = strlen(suffix);

	if (suffix_len <= len) {
		const char *p = &str[len - suffix_len];
		if (0 == memcmp(p, suffix, suffix_len))
			return deconstify_char(p);
	}

	return NULL;
}

/**
 * Check whether ``suffix'' is the end of ``str'', using an ASCII
 * case-insensitive comparison.
 *
 * @param str		a NUL-terminated string or array of "len" bytes.
 * @param len		length of ``str'', (size_t)-1 means compute it
 * @param suffix	the suffix to look for (NUL-terminated string)
 *
 * @return NULL if suffix is not found, a pointer to the start of it otherwise.
 */
char *
is_strcasesuffix(const char *str, size_t len, const char *suffix)
{
	size_t suffix_len;

	g_assert(NULL != str);
	g_assert(NULL != suffix);

	len = (size_t)-1 == len ? strlen(str) : len;
	suffix_len = strlen(suffix);

	if (suffix_len <= len) {
		const char *p = &str[len - suffix_len];
		const char *q = suffix;
		size_t i;

		for (i = 0; i < suffix_len; i++) {
			int a = *p++, b = *q++;

			/*
			 * Optimize a bit: if case matches, or we're dealing with a
			 * non-letter character, there's no need to invoke acscii_tolower().
			 */

			if (a != b && ascii_tolower(a) != ascii_tolower(b))
				return NULL;
		}

		return deconstify_char(&str[len - suffix_len]);
	}

	return NULL;
}

/**
 * Checks whether ``prefix'' is a prefix of ``buf'' which may not be
 * NUL-terminated but whose size is known.
 *
 * @param buf		a buffer of size len (may not have a trailing NUL)
 * @param len 		length of buffer
 * @param prefix	a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``buf''. Otherwise, a
 *			pointer to the first character in ``buf'' after the prefix.
 */
char *
is_bufprefix(const char *buf, size_t len, const char *prefix)
{
	const char *s, *p, *end;
	int c;

	g_assert(NULL != buf);
	g_assert(NULL != prefix);
	g_assert(size_is_non_negative(len));

	for (
		s = buf, p = prefix, end = &buf[len];
		'\0' != (c = *p) && s < end;
		p++
	) {
		if (c != *s++)
			return NULL;
	}

	if ('\0' != *p)
		return NULL;			/* String was shorter than prefix */

	return deconstify_gchar(s);
}

/**
 * Checks whether ``prefix'' is a prefix of ``buf'' performing an
 * case-insensitive (ASCII only) check.  The buffer may not end with
 * a NUL but its size is known.
 *
 * @param buf		a buffer of size len (may not have a trailing NUL)
 * @param len 		length of buffer
 * @param prefix	a NUL-terminated string
 *
 * @return	NULL, if ``prefix'' is not a prefix of ``buf''. Otherwise, a
 *			pointer to the first character in ``buf'' after the prefix.
 */
char *
is_bufcaseprefix(const char *buf, size_t len, const char *prefix)
{
	const char *s, *p, *end;
	int a;

	g_assert(NULL != buf);
	g_assert(NULL != prefix);
	g_assert(size_is_non_negative(len));

	for (
		s = buf, p = prefix, end = &buf[len];
		'\0' != (a = *p) && s < end;
		p++
	) {
		int b = *s++;

		/*
		 * Optimize a bit: if case matches, or we're dealing with a non-letter
		 * character, there's no need to invoke acscii_tolower().
		 */

		if (a != b && ascii_tolower(a) != ascii_tolower(b))
			return NULL;
	}

	if ('\0' != *p)
		return NULL;			/* String was shorter than prefix */

	return deconstify_gchar(s);
}

/**
 * @returns local host name, as pointer to static data.
 */
const char *
local_hostname(void)
{
	buf_t *b = buf_private(G_STRFUNC, 256 + 1);
	char *name = buf_data(b);
	size_t size = buf_size(b);

	if (-1 == gethostname(name, size)) {
		g_warning("gethostname() failed: %m");
		name[0] = '\0';
	}

	name[size - 1] = '\0';
	return name;
}

#define ONEMASK ((size_t) (-1) / 0xff)	/* 0x01010101 on 32-bit machine */

/**
 * Determines the length of a NUL-terminated string looking only at the first
 * "src_size" bytes. If src[0..size] contains no NUL byte, "src_size" is
 * returned. Otherwise, the returned value is identical to strlen(str). Thus,
 * it is safe to pass a possibly non-terminated buffer.
 *
 * @param src An initialized buffer.
 * @param src_size The size of src in number of bytes. IF AND ONLY IF,
 *        src is NUL-terminated, src_size may exceed the actual buffer length.
 * @return The number of bytes in "src" before the first found NUL or src_size
 *		   if there is no NUL.
 */
size_t
clamp_strlen(const char *src, size_t src_size)
{
	const char * s;

	/*
	 * Handle any initial misaligned bytes.
	 */

	for (s = src; pointer_to_ulong(s) & (sizeof(size_t) - 1); s++) {
		if G_UNLIKELY(UNSIGNED(s - src) >= src_size)
			goto done;
		if G_UNLIKELY(*s == '\0')
			goto done;		/* Exit if we hit a zero byte. */
	}

	/*
	 * Handle complete blocks, using the same processing as utf8_strlen()
	 * to inspect a whole "size_t" word at a time.
	 *
	 * This may read more bytes than are present in the string, should the
	 * trailing NUL byte be in the middle of a block.
	 *
	 * However, this is safe because we cannot cross any page boundary
	 * by doing so, hence we cannot incur a memory fault as long as the first
	 * bytes we're reading falls within the given src_size boundaries.
	 */

	for (; UNSIGNED(s - src) < src_size; s += sizeof(size_t)) {
		size_t u = *(size_t *) s;	/* Grab 4 or 8 bytes of data */

		if ((u - ONEMASK) & (~u) & (ONEMASK * 0x80))
			break;				/* Exit loop if there are any zero bytes */
	}

	if G_UNLIKELY(UNSIGNED(s - src) > src_size)
		s = src + src_size;

	/*
	 * Take care of the left-over bytes (at most a "size_t" word) to find
	 * the exact NUL inside.
	 */

	for (; UNSIGNED(s - src) < src_size; s++) {
		if G_UNLIKELY(*s == '\0')
			break;			/* Exit if we hit a zero byte */
	}

done:
	return s - src;
}

/**
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a "\n" or "\r".
 * If len is 0, compute it.
 *
 * @returns new string length.
 */
size_t
strchomp(char *str, size_t len)
{
	if (len == 0) {
		len = strlen(str);
		if (len == 0)
			return 0;
	}

	if (len >= 2 && str[len-2] == '\r' && str[len-1] == '\n') {
		str[len-2] = '\0';
		return len - 2;
	}

	if (str[len-1] == '\n' || str[len-1] == '\r') {
		str[len-1] = '\0';
		return len - 1;
	} else
		return len;
}

/**
 * Check whether path is a directory.
 */
bool
is_directory(const char *pathname)
{
	filestat_t st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISDIR(st.st_mode);
}

/**
 * Check whether path points to a regular file.
 */
bool
is_regular(const char *pathname)
{
	filestat_t st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISREG(st.st_mode);
}

/**
 * Check whether path is a symbolic link.
 */
bool
is_symlink(const char *pathname)
#if defined(HAS_LSTAT)
{
	filestat_t st;

	g_assert(pathname);
	if (0 != lstat(pathname, &st))
		return FALSE;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}
#else /* !HAS_LSTAT */
{
	g_assert(pathname);
	return FALSE;
}
#endif /* HAS_LSTAT */

/**
 * Tests whether the two given pathnames point to same file using stat().
 * @param pathname_a A pathname.
 * @param pathname_b A pathname.
 * @return -1 on error, errno will be set by either stat() call.
 *          FALSE if the device number and file serial number are different.
 *          TRUE if the device number and file serial number are different.
 */
int
is_same_file(const char *pathname_a, const char *pathname_b)
{
	filestat_t sb_a, sb_b;

	g_assert(pathname_a);
	g_assert(pathname_b);

	/* May no exist but points clearly to the same file */
	if (0 == strcmp(pathname_a, pathname_b))
		return TRUE;

	if (stat(pathname_a, &sb_a))
		return -1;

	if (stat(pathname_b, &sb_b))
		return -1;

	/*
	 * On Windows there is no concept of inode number.
	 */

#ifdef MINGW32
	return sb_a.st_dev == sb_b.st_dev &&
		mingw_same_file_id(pathname_a, pathname_b);
#else
	return sb_a.st_dev == sb_b.st_dev && sb_a.st_ino == sb_b.st_ino;
#endif
}

/**
 * A wrapper around lseek() for handling filesize_t to fileoffset_t conversion.
 *
 * @param fd A valid file descriptor.
 * @param pos The position to seek to.
 * @return 0 on success and -1 on failure.
 */
int
seek_to_filepos(int fd, filesize_t pos)
{
	fileoffset_t offset;

	offset = filesize_to_fileoffset_t(pos);
	if ((fileoffset_t) -1 == offset) {
		errno = ERANGE;
		return -1;
	} else {
		int saved_errno = errno;
		fileoffset_t ret;

		/* Set errno to be sure we get no bogus errno code, if
		 * the system does not agree with us that the lseek()
		 * failed. */
		errno = EOVERFLOW;
		ret = lseek(fd, offset, SEEK_SET);
		if ((fileoffset_t) -1 == ret)
			return -1;

		if (ret != offset) {
			errno = EOVERFLOW;
			return -1;
		}
		errno = saved_errno;
	}
	return 0;
}

/**
 * Picks a random offset between 0 and (filesize - 1).
 * @param size The size of the file.
 * @return a random offset within the file.
 */
filesize_t
get_random_file_offset(const filesize_t size)
{
	if (sizeof(size) == sizeof(uint64)) {
		return random64_value(size - 1);
	} else {
		return random_value(size - 1);
	}
}

static inline uint
filesize_fraction(filesize_t size, filesize_t part, uint base)
{
	filesize_t x;

	/**
	 * Use integer arithmetic because float or double might be too small
	 * for 64-bit values.
	 */
	if (size == part) {
		return base;
	}
	if (size > base) {
		x = size / base;
		x = part / MAX(1, x);
	} else {
		x = (part * base) / MAX(1, size);
	}
	base--;
	return MIN(x, base);
}

#define GENERATE_FILESIZE_PER_X(base) \
uint \
filesize_per_ ## base (filesize_t size, filesize_t part) \
{ \
	return filesize_fraction(size, part, base); \
}

GENERATE_FILESIZE_PER_X(100)
GENERATE_FILESIZE_PER_X(1000)
GENERATE_FILESIZE_PER_X(10000)
#undef GENERATE_FILESIZE_PER_X

static inline uint
kilo(bool metric)
{
	return metric ? 1000 : 1024;
}

static inline const char *
byte_suffix(bool metric)
{
	static const char suffix[] = "iB";
	return &suffix[metric ? 1 : 0];
}

static inline const char *
scale_prefixes(bool metric)
{
	return metric ? "\0kMGTPEZ" : "\0KMGTPEZ";
}

/**
 * Scales v so that quotient and reminder are both in the range "0..1023".
 *
 * @param v no document.
 * @param q pointer to a uint; will hold the quotient.
 * @param r pointer to a uint; will hold the reminder.
 * @param s a string holding the scale prefixes; must be sufficiently long.
 *
 * @return the appropriate prefix character from "s".
 */
static inline char
size_scale(uint64 v, uint *q, uint *r, const char *s, bool metric)
{
	const uint base = kilo(metric);

	if (v < base) {
		*q = v;
		*r = 0;
	} else {
		const uint thresh = base * base;

		for (s++; v >= thresh; v /= base)
			s++;

		*q = (uint) v / base;
		*r = (uint) v % base;
	}
	return *s;
}

static inline char
norm_size_scale(uint64 v, uint *q, uint *r, bool metric)
{
	return size_scale(v, q, r, scale_prefixes(metric), metric);
}

/**
 * Same as norm_size_scale_base2() but assumes v is already divided
 * by 1024 (binary).
 */
static inline char
kib_size_scale(uint64 v, uint *q, uint *r, bool metric)
{
	if (metric && v < ((uint64) -1) / 1024) {
		v = (v * 1024) / 1000;
	}
	return size_scale(v, q, r, scale_prefixes(metric) + 1, metric);
}

/**
 * Prints the supplied size ``len'' to the ``dst'' buffer, whose is is ``len''
 * bytes.  If ``len'' is too small, the string is truncated but is always
 * NULL-terminated, unless ``len'' is 0.
 *
 * @param size		the size to print
 * @param metric	if TRUE, use the metric system, otherwise powers of 1024.
 * @param dst		where to write the string
 * @param len		the size of ``dst'' in bytes.
 *
 * @return The length of the resulting string.
 */
size_t
short_size_to_string_buf(uint64 size, bool metric, char *dst, size_t len)
{
	if (size < kilo(metric)) {
		uint n = size;
		return str_bprintf(dst, len, NG_("%u Byte", "%u Bytes", n), n);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		return
			str_bprintf(dst, len, "%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}
}

const char *
short_size(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_size_to_string_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

const char *
short_size2(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_size_to_string_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

const char *
short_frequency(uint64 freq)
{
	str_t *s = str_private(G_STRFUNC, SIZE_FIELD_MAX);

	if (freq < kilo(TRUE)) {
		uint n = freq;
		str_printf(s, "%u Hz", n);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(freq, &q, &r, TRUE);
		r = (r * 100) / kilo(TRUE);
		str_printf(s, "%u.%02u %cHz", q, r, c);
	}

	return str_2c(s);
}

/**
 * Like short_size() but with unbreakable space between the digits and unit.
 */
const char *
short_html_size(uint64 size, bool metric)
{
	str_t *s = str_private(G_STRFUNC, SIZE_FIELD_MAX);

	if (size < kilo(metric)) {
		uint n = size;
		str_printf(s, NG_("%u&nbsp;Byte", "%u&nbsp;Bytes", n), n);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		str_printf(s, "%u.%02u&nbsp;%c%s", q, r, c, byte_suffix(metric));
	}

	return str_2c(s);
}

size_t
short_byte_size_to_buf(uint64 size, bool metric, char *buf, size_t buflen)
{
	size_t w;

	if (size < kilo(metric)) {
		uint n = size;
		w = str_bprintf(buf, buflen, "%u B", n);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		w = str_bprintf(buf, buflen,
				"%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return w;
}

/**
 * Same as short_size() but displays "B" instead of Byte(s) when the value
 * is less than a kilo.
 */
const char *
short_byte_size(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_byte_size_to_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

const char *
short_byte_size2(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_byte_size_to_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

size_t
short_kb_size_to_buf(uint64 size, bool metric, char *buf, size_t buflen)
{
	size_t w;

	if (size < kilo(metric)) {
		w = str_bprintf(buf, buflen,
				"%u %s", (uint) size, metric ? "kB" : "KiB");
	} else {
		uint q, r;
		char c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		w = str_bprintf(buf, buflen,
				"%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return w;
}

/**
 * Same as short_size() or short_byte_size() but the argument is given in
 * kibibytes, not bytes.
 */
const char *
short_kb_size(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_kb_size_to_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

const char *
short_kb_size2(uint64 size, bool metric)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_FIELD_MAX);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = short_kb_size_to_buf(size, metric, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * @return a number of Kbytes in a compact readable form
 */
const char *
compact_kb_size(uint32 size, bool metric)
{
	str_t *s = str_private(G_STRFUNC, SIZE_FIELD_MAX);

	if (size < kilo(metric)) {
		str_printf(s, "%u%s", (uint) size, metric ? "kB" : "KiB");
	} else {
		uint q, r;
		char c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		str_printf(s, "%u.%u%c%s", q, r, c, byte_suffix(metric));
	}

	return str_2c(s);
}

const char *
nice_size(uint64 size, bool metric)
{
	str_t *s = str_private(G_STRFUNC, SIZE_FIELD_MAX);
	char bytes[UINT64_DEC_BUFLEN];

	uint64_to_string_buf(size, ARYLEN(bytes));
	str_printf(s, _("%s (%s bytes)"), short_size(size, metric), bytes);
	return str_2c(s);
}

char *
compact_value(char *buf, size_t size, uint64 v, bool metric)
{
	if (v < kilo(metric)) {
		str_bprintf(buf, size, "%u", (uint) v);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		str_bprintf(buf, size, "%u.%u%c%s", q, r, c, metric ? "" : "i");
	}

	return buf;
}

char *
short_value(char *buf, size_t size, uint64 v, bool metric)
{
	if (v < kilo(metric)) {
		str_bprintf(buf, size, "%u ", (uint) v);
	} else {
		uint q, r;
		char c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		str_bprintf(buf, size, "%u.%02u %c%s", q, r, c, metric ? "" : "i");
	}

	return buf;
}

const char *
compact_size(uint64 size, bool metric)
{
	char buf[SIZE_FIELD_MAX];
	str_t *s = str_private(G_STRFUNC, sizeof buf);

	compact_value(ARYLEN(buf), size, metric);
	str_printf(s, "%sB", buf);
	return str_2c(s);
}

const char *
compact_size2(uint64 size, bool metric)
{
	char buf[SIZE_FIELD_MAX];
	str_t *s = str_private(G_STRFUNC, sizeof buf);

	compact_value(ARYLEN(buf), size, metric);
	str_printf(s, "%sB", buf);
	return str_2c(s);
}

const char *
compact_rate(uint64 rate, bool metric)
{
	char buf[SIZE_FIELD_MAX];
	str_t *s = str_private(G_STRFUNC, sizeof buf);

	compact_value(ARYLEN(buf), rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	str_printf(s, "%s%s", buf, _("B/s"));
	return str_2c(s);
}

static size_t
short_rate_to_string_buf(uint64 rate, bool metric, char *dst, size_t size)
{
	short_value(dst, size, rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	return clamp_strcat(dst, size, _("B/s"));
}

short_string_t
short_rate_get_string(uint64 rate, bool metric)
{
	short_string_t buf;
	short_rate_to_string_buf(rate, metric, ARYLEN(buf.str));
	return buf;
}

const char *
short_rate(uint64 rate, bool metric)
{
	short_string_t buf;
	buf_t *b = buf_private(G_STRFUNC, sizeof buf);
	char *p = buf_data(b);
	size_t sz = buf_size(b);

	buf = short_rate_get_string(rate, metric);
	clamp_strcpy(p, sz, buf.str);
	return p;
}

/**
 * Convert binary data into a hexadecimal string.
 *
 * @param data		the data to convert
 * @paran len		length of the binary data supplied
 * @param dst		destination buffer, where to put the result
 * @param size		size of the destination buffer
 *
 * @return the length of the hexadecimal string generated.
 */
size_t
bin_to_hex_buf(const void *data, size_t len, char *dst, size_t size)
{
	size_t retval;

	if (size > 0) {
		retval = base16_encode(dst, size - 1, data, len);
		dst[retval] = '\0';
	} else {
		retval = 0;
	}
	return retval;
}

/**
 * Convert GUID to hexadecimal string in the supplied buffer.
 */
size_t
guid_to_string_buf(const guid_t *guid, char *dst, size_t size)
{
	if G_UNLIKELY(NULL == guid) {
		/* Our constant string is 32-byte long */
		return cstr_bcpy(dst, size, "<------ null GUID pointer ----->");
	}

	return bin_to_hex_buf(guid->v, GUID_RAW_SIZE, dst, size);
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const char *
guid_to_string(const guid_t *guid)
{
	buf_t *b = buf_private(G_STRFUNC, GUID_HEX_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = guid_to_string_buf(guid, p, sz);
	g_assert(GUID_HEX_SIZE == n);
	return p;
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const char *
guid_hex_str(const guid_t *guid)
{
	buf_t *b = buf_private(G_STRFUNC, GUID_HEX_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = guid_to_string_buf(guid, p, sz);
	g_assert(GUID_HEX_SIZE == n);
	return p;
}

static int8 char2int_tabs[3][(size_t) (uchar) -1 + 1];

const int8 *hex2int_tab = char2int_tabs[0];
const int8 *dec2int_tab = char2int_tabs[1];
const int8 *alnum2int_tab = char2int_tabs[2];

/**
 * Converts a hexadecimal char (0-9, A-F, a-f) to an integer.
 *
 * Passing a character which is not a hexadecimal ASCII character
 * causes an assertion failure.
 *
 * @param c the hexadecimal ASCII character to convert.
 * @return "0..15" for valid hexadecimal ASCII characters.
 */
int
hex2int(uchar c)
{
	int ret;

	if G_UNLIKELY(0 == hex2int_inline('a'))
		misc_init();	/* Auto-initialization of hex2int_inline() */

	ret = hex2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Converts a decimal char (0-9) to an integer.
 *
 * Passing a character which is not a decimal ASCII character causes
 * an assertion failure.
 *
 * @param c the decimal ASCII character to convert.
 * @return "0..9" for valid decimal ASCII characters.
 */
static int
dec2int(uchar c)
{
	int ret;

	if G_UNLIKELY(0 == dec2int_inline('1'))
		misc_init();		/* Auto-initialization of dec2int_inline() */

	ret = dec2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Converts an alphanumeric char (0-9, A-Z, a-z) to an integer.
 *
 * Passing a character which is not an alphanumeric ASCII character
 * causes an assertion failure.
 *
 * @param c the decimal ASCII character to convert.
 * @return "0..36" for valid decimal ASCII characters.
 */
static int
alnum2int(uchar c)
{
	int ret;

	if G_UNLIKELY(0 == alnum2int_inline('a'))
		misc_init();		/* Auto-initialization of alnum2int_inline() */

	ret = alnum2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Initializes the lookup table for hex2int().
 */
static void G_COLD
hex2int_init(void)
{
	size_t i;

	/* Initialize hex2int_tab */

	for (i = 0; i < N_ITEMS(char2int_tabs[0]); i++) {
		static const char hexa[] = "0123456789abcdef";
		const char *p = i ? strchr(hexa, ascii_tolower(i)): NULL;

		char2int_tabs[0][i] = p ? (p - hexa) : -1;
	}

	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (uchar) -1; i++)
		switch (i) {
		case '0': g_assert(0 == hex2int(i)); break;
		case '1': g_assert(1 == hex2int(i)); break;
		case '2': g_assert(2 == hex2int(i)); break;
		case '3': g_assert(3 == hex2int(i)); break;
		case '4': g_assert(4 == hex2int(i)); break;
		case '5': g_assert(5 == hex2int(i)); break;
		case '6': g_assert(6 == hex2int(i)); break;
		case '7': g_assert(7 == hex2int(i)); break;
		case '8': g_assert(8 == hex2int(i)); break;
		case '9': g_assert(9 == hex2int(i)); break;
		case 'A':
		case 'a': g_assert(10 == hex2int(i)); break;
		case 'B':
		case 'b': g_assert(11 == hex2int(i)); break;
		case 'C':
		case 'c': g_assert(12 == hex2int(i)); break;
		case 'D':
		case 'd': g_assert(13 == hex2int(i)); break;
		case 'E':
		case 'e': g_assert(14 == hex2int(i)); break;
		case 'F':
		case 'f': g_assert(15 == hex2int(i)); break;
		default:
				  g_assert(-1 == hex2int_inline(i));
		}
}

/**
 * Initializes the lookup table for dec2int().
 */
static void G_COLD
dec2int_init(void)
{
	size_t i;

	/* Initialize dec2int_tab */

	for (i = 0; i < N_ITEMS(char2int_tabs[1]); i++) {
		static const char deca[] = "0123456789";
		const char *p = i ? strchr(deca, i): NULL;

		char2int_tabs[1][i] = p ? (p - deca) : -1;
	}

	/* Check consistency of dec2int_tab */

	for (i = 0; i <= (uchar) -1; i++)
		switch (i) {
		case '0': g_assert(0 == dec2int(i)); break;
		case '1': g_assert(1 == dec2int(i)); break;
		case '2': g_assert(2 == dec2int(i)); break;
		case '3': g_assert(3 == dec2int(i)); break;
		case '4': g_assert(4 == dec2int(i)); break;
		case '5': g_assert(5 == dec2int(i)); break;
		case '6': g_assert(6 == dec2int(i)); break;
		case '7': g_assert(7 == dec2int(i)); break;
		case '8': g_assert(8 == dec2int(i)); break;
		case '9': g_assert(9 == dec2int(i)); break;
		default:
				  g_assert(-1 == dec2int_inline(i));
		}
}

/**
 * Initializes the lookup table for alnum2int().
 */
static void G_COLD
alnum2int_init(void)
{
	static const char abc[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	size_t i;

	/* Initialize alnum2int_tab */

	for (i = 0; i < N_ITEMS(char2int_tabs[2]); i++) {
		const char *p = i ? strchr(abc, ascii_tolower(i)): NULL;

		char2int_tabs[2][i] = p ? (p - abc) : -1;
	}

	/* Check consistency of alnum2int_tab */

	for (i = 0; i <= (uchar) -1; i++) {
		const char *p = i ? strchr(abc, ascii_tolower(i)): NULL;
		int v = p ? (p - abc) : -1;

		g_assert(alnum2int_inline(i) == v);
		g_assert(!p || alnum2int(i) >= 0);
	}
}


/**
 * Converts hexadecimal string into a GUID.
 *
 * @param hexguid	the hexadecimal representation to convert
 * @param guid		the 16-byte array into which the decoded GUID is written to
 *
 * @return TRUE if OK.
 */
bool
hex_to_guid(const char *hexguid, guid_t *guid)
{
	size_t ret;

	ret = base16_decode(PTRLEN(guid), hexguid, GUID_HEX_SIZE);
	return GUID_RAW_SIZE == ret;
}

/**
 * Converts GUID into its base32 representation, without the trailing padding.
 *
 * @return pointer to static data.
 */
const char *
guid_base32_str(const guid_t *guid)
{
	buf_t *b = buf_private(G_STRFUNC, GUID_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	n = base32_encode(p, sz, guid, GUID_RAW_SIZE);
	g_assert(GUID_BASE32_SIZE == n);
	return p;
}

/**
 * Decode the base32 representation of a GUID into supplied buffer.
 *
 * @return pointer to supplied buffer, NULL if the input was not valid base32.
 */
const guid_t *
base32_to_guid(const char *base32, guid_t *guid)
{
	size_t ret;

	g_assert(base32 != NULL);
	g_assert(guid != NULL);

	ret = base32_decode(PTRLEN(guid), base32, GUID_BASE32_SIZE);
	return (size_t) 0 + GUID_RAW_SIZE == ret ? guid : NULL;
}

/**
 * Convert binary SHA1 into a base32 string.
 *
 * @param dst The destination buffer for the string.
 * @param size The size of "dst" in bytes; should be larger than
 *             SHA1_BASE32_SIZE, otherwise the resulting string will be
 *             truncated.
 * @return dst.
 */
char *
sha1_to_base32_buf(const struct sha1 *sha1, char *dst, size_t size)
{
	g_assert(sha1);
	if (size > 0) {
		size_t len;
		size_t offset;

		len = base32_encode(dst, size, PTRLEN(sha1));
		g_assert(len <= size);
		offset = len < size ? len : size - 1;
		dst[offset] = '\0';
	}
	return dst;
}

/**
 * Convert binary SHA1 into a base32 string.
 *
 * @return pointer to static data.
 */
const char *
sha1_base32(const struct sha1 *sha1)
{
	buf_t *b = buf_private(G_STRFUNC, SHA1_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t sz = buf_size(b);

	g_assert(sha1 != NULL);

	sha1_to_base32_buf(sha1, p, sz);
	return p;
}

/**
 * Convert binary SHA1 into a base16 string.
 *
 * @param dst The destination buffer for the string.
 * @param size The size of "dst" in bytes; should be larger than
 *             SHA1_BASE16_SIZE, otherwise the resulting string will be
 *             truncated.
 * @return dst.
 */
char *
sha1_to_base16_buf(const struct sha1 *sha1, char *dst, size_t size)
{
	g_assert(sha1);
	if (size > 0) {
		size_t len;
		size_t offset;

		len = base16_encode(dst, size, PTRLEN(sha1));
		g_assert(len <= size);
		offset = len < size ? len : size - 1;
		dst[offset] = '\0';
	}
	return dst;
}

/**
 * Convert binary SHA1 into a base16 string.
 *
 * @return pointer to static data.
 */
const char *
sha1_base16(const struct sha1 *sha1)
{
	buf_t *b = buf_private(G_STRFUNC, SHA1_BASE16_SIZE + 1);
	char *p = buf_data(b);
	size_t sz = buf_size(b);

	g_assert(sha1 != NULL);

	sha1_to_base16_buf(sha1, p, sz);
	return p;
}

const char *
sha1_to_string(const struct sha1 *sha1)
{
	buf_t *b = buf_private(G_STRFUNC, SHA1_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t sz = buf_size(b);

	sha1_to_base32_buf(sha1, p, sz);
	return p;
}

/**
 * Convert binary SHA1 into a urn:sha1:<base32> string.
 *
 * @param sha1	a binary SHA-1.
 * @param dst	destination buffer
 * @param size	size of buffer
 *
 * @return The length of the SHA-1 converted to a URN string.
 */
size_t
sha1_to_urn_string_buf(const struct sha1 *sha1, char *dst, size_t size)
{
	static const char prefix[] = "urn:sha1:";
	size_t n;

	g_assert(sha1);

	n = MIN(size, CONST_STRLEN(prefix));
	memcpy(dst, prefix, n);
	size -= n;
	if (size > 0) {
		n = MIN(size, (SHA1_BASE32_SIZE + 1));
		sha1_to_base32_buf(sha1, &dst[CONST_STRLEN(prefix)], n);
	}
	return CONST_STRLEN(prefix) + SHA1_BASE32_SIZE;
}

/**
 * Generates an "urn:sha1:" URN pointing to the given SHA-1.
 * @return pointer to static data
 */
const char *
sha1_to_urn_string(const struct sha1 *sha1)
{
	buf_t *b = buf_private(G_STRFUNC,
		CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	g_assert(sha1 != NULL);
	n = sha1_to_urn_string_buf(sha1, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Generates an "urn:bitprint:" URN if both SHA-1 and TTH are supplied, or
 * an "urn:sha1" if the TTH is missing (NULL pointer).
 * @return pointer to static data
 */
const char *
bitprint_to_urn_string(const struct sha1 *sha1, const struct tth *tth)
{
	buf_t *b = buf_private(G_STRFUNC, BITPRINT_BASE32_SIZE + 14);

	g_assert(sha1 != NULL);

	if (tth) {
		static const char prefix[] = "urn:bitprint:";
		char buf[CONST_STRLEN(prefix) + BITPRINT_BASE32_SIZE + 1];
		const char * const end = &buf[sizeof buf];
		char *p = buf;

		p = mempcpy(p, prefix, CONST_STRLEN(prefix));
		base32_encode(p, end - p, PTRLEN(sha1));
		p += SHA1_BASE32_SIZE;

		*p++ = '.';

		base32_encode(p, end - p, PTRLEN(tth));
		p += TTH_BASE32_SIZE;
		*p = '\0';
		g_assert(ptr_diff(p, buf) <= sizeof buf);

		buf_copyin(b, ARYLEN(buf));
	} else {
		char buf[CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1];

		sha1_to_urn_string_buf(sha1, ARYLEN(buf));
		buf_copyin(b, ARYLEN(buf));
	}

	return buf_data(b);
}

/**
 * Convert base32 string into binary SHA1.
 *
 * @param base32 a buffer holding SHA1_BASE32_SIZE or more bytes.
 *
 * @return	Returns pointer to static data or NULL if the input wasn't a
 *			validly base32 encoded SHA1.
 */
const struct sha1 *
base32_sha1(const char *base32)
{
	static struct sha1 sha1[THREAD_MAX];
	uint stid = thread_small_id();
	struct sha1 *s = &sha1[stid];
	size_t len;

	g_assert(base32 != NULL);

	len = base32_decode(PTRLEN(s), base32, SHA1_BASE32_SIZE);
	return SHA1_RAW_SIZE == len ? s : NULL;
}

/**
 * Convert binary TTH into a base32 string.
 *
 * @return pointer to static data.
 */
const char *
tth_base32(const struct tth *tth)
{
	buf_t *b = buf_private(G_STRFUNC, TTH_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	g_assert(tth != NULL);

	n = 1 + base32_encode(p, sz, PTRLEN(tth));
	p[MAX(n, sz) - 1] = '\0';
	return p;
}

/**
 * Convert base32 string into a binary TTH.
 *
 * @param base32 a buffer holding TTH_BASE32_SIZE or more bytes.
 *
 * @return	Returns pointer to static data or NULL if the input wasn't a
 *			validly base32 encoded TTH.
 */
const struct tth *
base32_tth(const char *base32)
{
	static struct tth tth[THREAD_MAX];
	uint stid = thread_small_id();
	struct tth *t = &tth[stid];
	size_t len;

	g_assert(base32 != NULL);

	len = base32_decode(PTRLEN(t), base32, TTH_BASE32_SIZE);
	return TTH_RAW_SIZE == len ? t : NULL;
}

/**
 * Convert binary TTH into a base32 string.
 *
 * @param dst The destination buffer for the string.
 * @param size The size of "dst" in bytes; should be larger than
 *             TTH_BASE32_SIZE, otherwise the resulting string will be
 *             truncated.
 * @return dst.
 */
char *
tth_to_base32_buf(const struct tth *tth, char *dst, size_t size)
{
	g_assert(tth);
	if (size > 0) {
		size_t n = 1 + base32_encode(dst, size, PTRLEN(tth));
		dst[MIN(n, size) - 1] = '\0';
	}
	return dst;
}

/**
 * Convert binary TTH into a urn:ttroot:<base32> string.
 *
 * @param tth	a binary TTH.
 * @param dst	the destination buffer
 * @param size	the size of the destination buffer
 *
 * @return The length of the resulting URN string.
 */
size_t
tth_to_urn_string_buf(const struct tth *tth, char *dst, size_t size)
{
	static const char prefix[] = "urn:ttroot:";
	size_t n;

	g_assert(tth);

	n = MIN(size, CONST_STRLEN(prefix));
	memcpy(dst, prefix, n);
	size -= n;
	if (size > 0) {
		n = MIN(size, (TTH_BASE32_SIZE + 1));
		tth_to_base32_buf(tth, &dst[CONST_STRLEN(prefix)], n);
	}
	return CONST_STRLEN(prefix) + TTH_BASE32_SIZE;
}

const char *
tth_to_urn_string(const struct tth *tth)
{
	buf_t *b = buf_private(G_STRFUNC,
		CONST_STRLEN("urn:ttroot:") + TTH_BASE32_SIZE + 1);
	char *p = buf_data(b);
	size_t n, sz = buf_size(b);

	g_assert(tth != NULL);

	n = tth_to_urn_string_buf(tth, p, sz);
	g_assert(n < sz);
	return p;
}

/**
 * Determine how many leading bits the two keys have in common.
 *
 * @param k1		the first key
 * @param k1bits	size of the first key in bits
 * @param k2		the second key
 * @param k2bits	size of the second key in bits
 *
 * @return the number of common leading bits, which is at most
 * min(k1bits, k2bits) if everything matches.
 */
size_t G_HOT
common_leading_bits(
	const void *k1, size_t k1bits, const void *k2, size_t k2bits)
{
	const uint8 *p1 = k1;
	const uint8 *p2 = k2;
	size_t cbits;			/* Total amount of bits to compare */
	size_t bytes;			/* Amount of bytes to compare */
	size_t bits;			/* Remaining bits in last byte */
	size_t i;

	g_assert(k1);
	g_assert(k2);

	cbits = MIN(k1bits, k2bits);

	if (k1 == k2 || !cbits)
		return cbits;

	bytes = cbits >> 3;

	for (i = 0; i < bytes; i++) {
		uint8 diff = *p1++ ^ *p2++;
		if (diff)
			return i * 8 + 7 - highest_bit_set(diff);
	}

	bits = cbits & 0x7;

	if (bits != 0) {
		uint8 mask = ~((1 << (8 - bits)) - 1);
		uint8 diff = (*p1 & mask) ^ (*p2 & mask);
		if (diff)
			return bytes * 8 + 7 - highest_bit_set(diff);
	}

	return cbits;		/* All the bits we compared matched */
}

/**
 * Enforce range boundaries on a given floating point
 * number.
 *
 * @param val The value to force within the range.
 * @param min The minimum value which val can be.
 * @param max The maximum value with val can be.
 *
 * @return The new value of val which will be between
 *         min and max.
 */
float
force_range(float val, float min, float max)
{
	g_assert(min <= max);

	return
		val < min ? min :
		val > max ? max :
		val;
}

/**
 * Check whether buffer contains printable data, suitable for "%s" printing.
 * If not, consider dump_hex().
 */
bool
is_printable(const char *buf, int len)
{
	const char *p = buf;
	int l = len;

	while (l--) {
		char c = *p++;
		if (!is_ascii_print(c))
			return FALSE;
	}

	return TRUE;
}

/**
 * Prints a single "dump hex" line which consists of 16 bytes of data.
 *
 * @param out		the stream to print the string at.
 * @param data		a pointer to the first byte of the data to dump.
 * @param length	the length of data in bytes.
 * @param offset	the offset of the data being printed.
 */
static void
dump_hex_line(FILE *out, const char *data, size_t length, size_t offset)
{
	char char_buf[32], hex_buf[64];
	char *p = hex_buf, *q = char_buf;
	size_t j, i = 0;

	for (j = 0; j < 16; j++) {
		*p++ = ' ';
		if (8 == j) {
			*p++ = ' ';
		}
		if (i < length) {
			uchar c;

			c = data[i];
			i++;

			*p++ = hex_digit((c >> 4) & 0xf);
			*p++ = hex_digit(c & 0x0f);

			*q++ = is_ascii_print(c) ? c : '.';
		} else {
			*p++ = ' ';
			*p++ = ' ';

			*q++ = ' ';
		}
	}
	*p = '\0';
	*q = '\0';

	fprintf(out, "%5u %s  %s\n", (uint) (offset & 0xffff), hex_buf, char_buf);
}

#define DUMP_LINE_LENGTH	16		/* Amount of bytes per line */

/**
 * Dump scattered data.
 *
 * Displays hex & ascii lines to the specified file (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex_vec(FILE *out, const char *title, const iovec_t *iov, size_t iovcnt)
{
	unsigned i;
	char buf[DUMP_LINE_LENGTH];
	size_t length = 0;
	iovec_t *xiov;

	g_assert(iov != NULL);
	g_assert(iovcnt > 0);

	if (!log_file_printable(out))
		return;

	fprintf(out, "----------------- %s:\n", title);

	xiov = WCOPY_ARRAY(iov, iovcnt);	/* Don't modify argument */

	for (i = 0; i < iovcnt; /* empty */) {
		iovec_t *v = &xiov[i];
		const void *start = iovec_base(v);
		size_t len = iovec_len(v);
		size_t dumping;

		if (len < DUMP_LINE_LENGTH) {
			memcpy(buf, start, len);
			i++;
			while (i < iovcnt && len < DUMP_LINE_LENGTH) {
				size_t to_copy;
				size_t missing = DUMP_LINE_LENGTH - len;

				v = &xiov[i++];
				start = iovec_base(v);
				to_copy = MIN(missing, iovec_len(v));
				memcpy(&buf[len], start, to_copy);
				len += to_copy;
				iovec_set_base(v, const_ptr_add_offset(start, to_copy));
				iovec_set_len(v, iovec_len(v) - to_copy);
			}
			start = buf;
		} else {
			iovec_set_base(v, const_ptr_add_offset(start, DUMP_LINE_LENGTH));
			iovec_set_len(v, iovec_len(v) - DUMP_LINE_LENGTH);
		}

		if (0 == length % 256) {
			if (length != 0) {
				fputc('\n', out);	/* break after 256 byte chunk */
			}
			fputs("Offset  0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  "
				"0123456789abcdef\n", out);
		}

		dumping = MIN(len, DUMP_LINE_LENGTH);
		dump_hex_line(out, start, dumping, length);
		length += dumping;
	}

	WFREE_ARRAY(xiov, iovcnt);

	fprintf(out, "----------------- (%u byte%s).\n",
		(unsigned) length, plural(length));
	fflush(out);
}

/**
 * Dump contiguous data.
 *
 * Displays hex & ascii lines to the specified file (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex(FILE *out, const char *title, const void *data, int length)
{
	iovec_t iov;

	if (length < 0 || data == NULL) {
		g_critical("%s(): value out of range [data=%p, length=%d] for %s",
			G_STRFUNC, data, length, title);
		return;
	}

	iovec_set(&iov, data, length);
	dump_hex_vec(out, title, &iov, 1);
}

/**
 * Dump text string to the specified file, followed by trailer (if non-NULL).
 * A final "\n" is emitted at the end.
 */
void
dump_string(FILE *out, const char *str, size_t len, const char *trailer)
{
	g_return_if_fail(out);
	g_return_if_fail(str);
	g_return_if_fail(size_is_non_negative(len));

	if (!log_file_printable(out))
		return;

	if (len)
		fwrite(str, len, 1, out);
	if (trailer)
		fputs(trailer, out);
	fputc('\n', out);
}

/**
 * Is string made-up of printable ISO-8859 characters?
 * If not, consider dump_hex().
 */
bool
is_printable_iso8859_string(const char *s)
{
	int c;

	while ((c = *s++)) {
		if (
			!is_ascii_print(c) && c != '\r' && c != '\n' && c != '\t' &&
			!(c >= 160 && c <= 255)
		)
			return FALSE;
	}

	return TRUE;
}

/**
 * Copies ``src'' to ``dst'', converting all upper-case characters to
 * lower-case. ``dst'' and ``src'' may point to the same object. The
 * conversion depends on the current locale.
 */
void
locale_strlower(char *dst, const char *src)
{
	do {
		*dst++ = tolower((uchar) *src);
	} while (*src++);
}

/**
 * Generate a new random GUID within given `guid'.
 */
void
guid_random_fill(guid_t *guid)
{
	random_strong_bytes(guid, GUID_RAW_SIZE);
}

/**
 * Determine stripped down path, removing SRC_PREFIX if present.
 *
 * @returns pointer within supplied string.
 */
const char *
short_filename(const char *fullname)
{
	const char *s;

	s = is_strprefix(fullname, SRC_PREFIX);
	return s ? s : fullname;
}

/**
 * Creates the given directory including sub-directories if necessary. The
 * path must be absolute.
 *
 * @param dir the pathname of the directory to create.
 *
 * @return On success, zero is returned. On failure, -1 is returned and
 *         errno indicates the reason.
 */
int
create_directory(const char *dir, mode_t mode)
{
	int error = 0;

	if (NULL == dir) {
		error = EINVAL;
		goto failure;
	}
	if (!is_absolute_path(dir)) {
		error = EPERM;
		goto failure;
	}

	if (mkdir(dir, mode)) {
		error = errno;
		if (EEXIST == error) {
			goto finish;
		} else if (ENOENT == error) {
			char *upper = filepath_directory(dir);

			if (create_directory(upper, mode)) {
				error = errno;
		 	} else {
				if (mkdir(dir, mode)) {
					error = errno;
				} else {
					error = 0;
				}
			}
			HFREE_NULL(upper);
		} else {
			goto failure;
		}
	}
	if (error && EEXIST != error)
		goto failure;

finish:
	return is_directory(dir) ? 0 : -1;

failure:
	g_warning("mkdir(\"%s\") failed: %m", dir);
	errno = error;
	return -1;
}

/**
 * Find amount of common leading bits between two IP addresses.
 */
static uint8 G_HOT
find_common_leading(uint32 ip1, uint32 ip2)
{
	uint8 n;
	uint32 mask;

	for (n = 0, mask = 0x80000000; n < 32; n++, mask |= (mask >> 1)) {
		if ((ip1 & mask) != (ip2 & mask))
			return n;
	}

	return n;
}

/**
 * Computes the set of CIDR ranges that make up the set of IPs between
 * two boundary IPs, included.
 *
 * For instance, for the range 2.0.0.0 - 2.138.24.150, we have:
 *
 * 2.0.0.0/9, 2.128.0.0/13, 2.136.0.0/15, 2.138.0.0/20, 2.138.16.0/21,
 * 2.138.24.0/25, 2.138.24.128/28, 2.138.24.144/30, 2.138.24.148,
 * 2.138.24.149 and 2.138.24.150.
 *
 * For each identified CIDR range, invoke the supplied callback, along
 * with the trailing user-supplied `udata' pointer.
 *
 * @param lower_ip	the lower-bound IP
 * @param upper_ip	the upper-bound IP
 * @param cb		the callback, invoked as callback(ip, bits, udata)
 * @param udata		the trailing parameter passed as-is to the callbacks
 */
void
ip_range_split(
	uint32 lower_ip, uint32 upper_ip, cidr_split_t cb, void *udata)
{
	uint8 bits;
	uint32 mask;
	uint32 trailing;

	g_assert(lower_ip <= upper_ip);

	bits = find_common_leading(lower_ip, upper_ip);
	if G_UNLIKELY(0 == bits) {
		mask = 0;
		trailing = ~0;
	} else {
		mask = 1 << (32 - bits);
		trailing = mask - 1;
	}

	if (bits == 32) {
		g_assert(lower_ip == upper_ip);
		(*cb)(lower_ip, bits, udata);
	} else if (trailing == (upper_ip & trailing)) {
		/*
		 * All the trailing bits of upper_ip are 1s.
		 */

		if (0 == (lower_ip & trailing)) {
			/*
			 * All the trailing bits of lower_ip are 0s -- we're done
			 */

			(*cb)(lower_ip, bits, udata);
		} else {
			uint32 cut;

			/*
			 * Start filling after the first 1 bit in lower_ip.
			 */

			mask = 1;
			while (0 == (lower_ip & mask))
				mask <<= 1;
			cut = (mask - 1) | lower_ip;

			/*
			 * Recurse on sub-ranges [lower_ip, cut] and ]cut, upper_ip].
			 */

			ip_range_split(lower_ip, cut, cb, udata);
			ip_range_split(cut + 1, upper_ip, cb, udata);
		}
	} else {
		uint32 cut;

		/*
		 * We can't cover the full range.
		 *
		 * We know that bits #(32-bits) in lower_ip and upper_ip differ.
		 * Since lower_ip <= upper_ip, the bit is necessary 0 in lower_ip.
		 */

		mask >>= 1;					/* First bit that differs */

		g_assert(0 == (lower_ip & mask));
		g_assert(0 != (upper_ip & mask));

		cut = upper_ip & ~mask;		/* Reset that bit in upper_ip */
		cut |= mask - 1;			/* And set the trailing bits to 1s */

		/*
		 * Recurse on sub-ranges [lower_ip, cut] and ]cut, upper_ip].
		 */

		ip_range_split(lower_ip, cut, cb, udata);
		ip_range_split(cut + 1, upper_ip, cb, udata);
	}
}

static inline const char *
html_escape_replacement(char c, size_t *len)
{
	static char r[THREAD_MAX];
	uint stid;

#define REPLACE(x) { *len = CONST_STRLEN(x); return (x); }

	switch (c) {
	case '&':
		REPLACE("&amp;");
	case '<':
		REPLACE("&lt;");
	case '>':
		REPLACE("&gt;");
	case '"':
		REPLACE("&quot;");
	case '\'':
		REPLACE("&#39;");
	}
#undef REPLACE

	stid = thread_small_id();
	r[stid] = c;
	*len = 1;
	return &r[stid];
}

/**
 * Copies the NUL-terminated string ``src'' to ``dst'' replacing all
 * characters which are reserved in HTML with a replacement string.
 *
 * @param src a NUL-terminated string.
 * @param dst the destination buffer, may be NULL if ``size'' is zero.
 * @param dst_size the size in bytes of the destination buffer.
 * @return the length in bytes of resulting string assuming size was
 *         sufficiently large.
 */
size_t
html_escape(const char *src, char *dst, size_t dst_size)
{
	char *d = dst;
	const char *s = src;
	uchar c;

	g_assert(0 == dst_size || NULL != dst);
	g_assert(NULL != src);

	if (dst_size-- > 0) {
		for (/* NOTHING*/; '\0' != (c = *s); s++) {
			const char *r;
			size_t len;

			r = html_escape_replacement(c, &len);
			if (len > dst_size)
				break;

			dst_size -= len;
			while (len-- > 0)
				*d++ = *r++;
		}
		*d = '\0';
	}
	while ('\0' != (c = *s++)) {
		size_t len;

		html_escape_replacement(c, &len);
		d += len;
	}

	return d - dst;
}

static htable_t *html_entities_lut;

static void G_COLD
html_entities_init(void)
{
	size_t i;

	html_entities_lut = htable_create(HASH_KEY_STRING, 0);
	for (i = 0; i < N_ITEMS(html_entities); i++) {
		htable_insert(html_entities_lut, html_entities[i].name,
			uint_to_pointer(html_entities[i].uc));
	}
}

static void
html_entities_close(void)
{
	htable_free_null(&html_entities_lut);
}

/**
 * Maps an HTML entity to an Unicode codepoint.
 *
 * @param src    Should point to the start of an entity "&ENTITY;[...]"
 * @param endptr If not NULL, it will be set to point either to
 *		 		 the original string or the next character after
 *				 the entity.
 * @return		 On failure (uint32)-1 is returned, on success the
 *				 Unicode codepoint.
 */
uint32
html_decode_entity(const char * const src, const char **endptr)
{
	if ('&' != src[0])
		goto failure;

	if ('#' == src[1]) {
		const char *ep, *p;
		int base, error;
		uint32 v;

		switch (src[2]) {
		case 'x':
		case 'X':
			base = 16;
			p = &src[3];
			break;
		default:
			base = 10;
			p = &src[2];
		}

		v = parse_uint32(p, &ep, base, &error);
		if (error || 0x0000 == v || !utf32_is_valid(v) || ';' != *ep)
			goto failure;

		if (endptr) {
			*endptr = &ep[1];
		}
		return v;
	} else {
		char name[16];
		size_t name_len;
		const void *value;
		const char *p;

		/* Avoid strchr() because it would cause O(n^2) with unclosed entities */
		name_len = 0;
		for (p = &src[1]; ';' != *p; p++) {
			if ('\0' == *p)
				goto failure;
			name[name_len++] = *p;
			if (name_len >= sizeof name)
				goto failure;
		}
		name[name_len] = '\0';

		if (!html_entities_lut) {
			html_entities_init();
		}
		value = htable_lookup(html_entities_lut, name);
		if (NULL == value)
			goto failure;

		if (endptr) {
			*endptr = &p[1];
		}
		return pointer_to_uint(value);
	}

failure:
	if (endptr) {
		*endptr = src;
	}
	return (uint32) -1;
}

/**
 * Counts the number of bytes that differ between two chunks of memory.
 */
size_t
memcmp_diff(const void *a, const void *b, size_t size)
{
	const char *p = a, *q = b;
	size_t n = 0;

	while (size-- > 0) {
		if (*p++ != *q++)
			n++;
	}

	return n;
}

/**
 * Compare first n bits of the memory areas s1 and s2.
 *
 * @return 0 on equality, -1 if s1 < s2 and +1 if s1 > s2.
 */
int G_HOT
bitcmp(const void *s1, const void *s2, size_t n)
{
	int i, bytes, remain;
	const uint8 *p1 = s1, *p2 = s2;
	uint8 mask, c1, c2;

	bytes = n / 8;				/* First bytes to compare */

	for (i = 0; i < bytes; i++) {
		c1 = *p1++;
		c2 = *p2++;
		if (c1 != c2)
			return c1 < c2 ? -1 : +1;
	}

	remain = n - 8 * bytes;		/* Bits in next byte */

	if (0 == remain)
		return 0;

	mask = (uint8) -1 << (8 - remain);

	c1 = *p1 & mask;
	c2 = *p2 & mask;

	return CMP(c1, c2);
}

/**
 * Replaces all G_DIR_SEPARATOR characters with the canonic path component
 * separator '/' (a slash). The string is modified in-place.
 *
 * @param s a pathname.
 */
void
normalize_dir_separators(char *pathname)
{
   	g_assert(pathname);

	if (G_DIR_SEPARATOR != '/') {
		while (pathname) {
			pathname = strchr(pathname, G_DIR_SEPARATOR);
			if (pathname) {
				*pathname++ = '/';
			}
		}
	}
}

/**
 * Special-purpose function to create a string list of directories
 * seperated by G_SEARCHPATH_SEPARATOR which may also be part of
 * directory names.
 */
static void
dirlist_cat(str_t *str, const char *dir)
{
	str_check(str);

	if (str_len(str) > 0) {
		str_putc(str, G_SEARCHPATH_SEPARATOR);
	}
	if (strchr(dir, G_SEARCHPATH_SEPARATOR)) {
		const char *p;

		for (p = dir; '\0' != *p; p++) {
			str_putc(str, *p);
			if (G_SEARCHPATH_SEPARATOR == *p) {
				str_putc(str, G_SEARCHPATH_SEPARATOR);
			}
		}
	} else {
		str_cat(str, dir);
	}
}

/**
 * Creates a string from the given list of directory pathnames.
 *
 * @return a newly allocated string which must be freed via hfree().
 */
char *
dirlist_to_string(const pslist_t *pl_dirs)
{
	const pslist_t *sl;
	str_t *str = str_new(0);

	/**
	 * NB: The separator is escaped by appending another separator.
	 *     This is done because the separator may actually appear
	 *     in a pathname.
	 */

	PSLIST_FOREACH(pl_dirs, sl) {
		dirlist_cat(str, sl->data);
	}
	return str_s2c_null(&str);
}


/**
 * Parse a list of directory pathnames separated by G_SEARCHPATH_SEPARATOR.
 *
 * @return a list of newly allocated strings which must be freed via hfree().
 */
pslist_t *
dirlist_parse(const char *dirs)
{
	char *pathname, *s;
	const char *p;
	pslist_t *pl_dirs = NULL;

	/**
	 * The list of directories must be unescaped as follows:
	 * A separator followed by another separator means the pathname
	 * included the separator itself, so one character must be skipped.
	 */

	pathname = halloc(strsize(dirs));
	s = pathname;

	for (p = dirs; /* nothing */; p++) {
		int c = *p;

		if (G_SEARCHPATH_SEPARATOR == c) {
			if (G_SEARCHPATH_SEPARATOR == p[1]) {
				p++;
			} else {
				c = '\0';
			}
		}
		*s++ = c;
		if ('\0' == c) {
			s = pathname;
			if (is_absolute_path(pathname)) {
				pl_dirs = pslist_prepend(pl_dirs, h_strdup(pathname));
			}
		}
		if ('\0' == *p)
			break;
	}

	HFREE_NULL(pathname);
	return pslist_reverse(pl_dirs);
}

enum errno_map {
	ERRNO_SYM = 0,		/* Maps error number to symbolic value */
	ERRNO_STR = 1		/* Maps errno number to English message */
};

/**
 * Maps errno values to symbolic names or English messages for logging.
 *
 * @param errnum		the error number to map
 * @param which			whether to map for ERRNO_SYM or ERRNO_STR
 *
 * @return A const static string, or NULL if errno is unhandled.
 */
static const char *
symbolic_errno_map(int errnum, enum errno_map which)
{
#define CASE(x,s) case x: return ERRNO_SYM == which ? #x : s;

	switch (errnum) {
	case 0: return ERRNO_SYM == which ? "SUCCESS" : "OK";
	/* The following codes are defined by POSIX */
	CASE(E2BIG,			"Argument list too long");
	CASE(EACCES,		"Permission denied");
	CASE(EADDRINUSE,	"Address already in use");
	CASE(EADDRNOTAVAIL,	"Address not available");
	CASE(EAFNOSUPPORT,	"Address family not supported");
	CASE(EAGAIN,		"Resource  temporarily  unavailable");
	CASE(EALREADY,		"Connection already in progress");
	CASE(EBADF,			"Bad file descriptor");
#ifdef EBADMSG	/* MinGW */
	CASE(EBADMSG,		"Bad message");
#endif
	CASE(EBUSY,			"Device or resource busy");
	CASE(ECANCELED,		"Operation canceled");
	CASE(ECHILD,		"No child processes");
	CASE(ECONNABORTED,	"Connection aborted");
	CASE(ECONNREFUSED,	"Connection refused");
	CASE(ECONNRESET,	"Connection reset");
	CASE(EDEADLK,		"Resource deadlock avoided");
	CASE(EDESTADDRREQ,	"Destination address required");
	CASE(EDOM,			"Mathematics argument out of domain of function");
	CASE(EDQUOT,		"Disk quota exceeded");
	CASE(EEXIST,		"File exists");
	CASE(EFAULT,		"Bad address");
	CASE(EFBIG,			"File too large");
	CASE(EHOSTUNREACH,	"Host is unreachable");
	/* EIDRM is faked on MinGW */
	CASE(EIDRM,			"Identifier removed");
	CASE(EILSEQ,		"Illegal byte sequence");
	CASE(EINPROGRESS,	"Operation in progress");
	CASE(EINTR,			"Interrupted function call");
	CASE(EINVAL,		"Invalid argument");
	CASE(EIO,			"Input/output error");
	CASE(EISCONN,		"Socket is connected");
	CASE(EISDIR,		"Is a directory");
	CASE(ELOOP,			"Too many levels of symbolic links");
	CASE(EMFILE,		"Too many open files");
	CASE(EMLINK,		"Too many links");
	CASE(EMSGSIZE,		"Message too long");
#ifdef EMULTIHOP	/* MinGW */
	CASE(EMULTIHOP,		"Multihop attempted");
#endif
	CASE(ENAMETOOLONG,	"Filename too long");
	CASE(ENETDOWN,		"Network is down");
	CASE(ENETRESET,		"Connection aborted by network");
	CASE(ENETUNREACH,	"Network unreachable");
	CASE(ENFILE,		"Too many open files in system");
	CASE(ENOBUFS,		"No buffer space available");
#ifdef ENODATA	/* MinGW */
	CASE(ENODATA,		"No message available on the STREAM read queue");
#endif
	CASE(ENODEV,		"No such device");
	CASE(ENOENT,		"No such file or directory");
	CASE(ENOEXEC,		"Exec format error");
	CASE(ENOLCK,		"No locks available");
#ifdef ENOLINK	/* MinGW */
	CASE(ENOLINK,		"Link has been severed");
#endif
	CASE(ENOMEM,		"Not enough memory space");
#ifdef ENOMSG	/* MinGW */
	CASE(ENOMSG,		"No message of the desired type");
#endif
	CASE(ENOPROTOOPT,	"Protocol not available");
	CASE(ENOSPC,		"No space left on device");
#ifdef ENOSR	/* MinGW */
	CASE(ENOSR,			"No STREAM resources");
#endif
#ifdef ENOSTR	/* MinGW */
	CASE(ENOSTR,		"Not a STREAM");
#endif
	CASE(ENOSYS,		"Function not implemented");
	CASE(ENOTCONN,		"Socket is not connected");
	CASE(ENOTDIR,		"Not a directory");
	CASE(ENOTEMPTY,		"Directory not empty");
	CASE(ENOTSOCK,		"Not a socket");
	CASE(ENOTSUP,		"Operation not supported");
	CASE(ENOTTY,		"Inappropriate I/O control operation");
	CASE(ENXIO,			"No such device or address");
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP /* GLIBC and MinGW */
	CASE(EOPNOTSUPP,	"Operation not supported on socket");
#endif
#ifdef EOVERFLOW	/* MinGW */
	CASE(EOVERFLOW,		"Value too large to be stored in data type");
#endif
	CASE(EPERM,			"Operation not permitted");
	CASE(EPIPE,			"Broken pipe");
#if defined(EPROTO)	/* MinGW */
	CASE(EPROTO,		"Protocol error");
#endif
	CASE(EPROTONOSUPPORT,"Protocol not supported");
	CASE(EPROTOTYPE,	"Protocol wrong type for socket");
	CASE(ERANGE,		"Result too large");
	CASE(EROFS,			"Read-only file system");
	CASE(ESPIPE,		"Invalid seek");
	CASE(ESRCH,			"No such process");
	CASE(ESTALE,		"Stale file handle");
#ifdef ETIME	/* MinGW */
	CASE(ETIME,			"Timer expired");
#endif
	CASE(ETIMEDOUT,		"Connection timed out");
#ifdef ETXTBSY	/* MinGW */
	CASE(ETXTBSY,		"Text file busy");
#endif
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
	CASE(EWOULDBLOCK,	"Operation would block");
#endif
	CASE(EXDEV,			"Improper link");

	/* The following codes are non-standard extensions */
#ifdef EHOSTDOWN
	CASE(EHOSTDOWN,		"Host is down");
#endif
#ifdef ENOTBLK
	CASE(ENOTBLK,		"Block device required");
#endif
#ifdef ESHUTDOWN
	CASE(ESHUTDOWN,		"Cannot send after transport endpoint shutdown");
#endif
	}
#undef CASE

	return NULL;	/* Unknown error */
}

/**
 * Maps errno values to their symbolic names (e.g., EPERM to "EPERM").
 *
 * @return A const static string. If errno is unhandled, its stringified
 * integer value is returned.
 */
const char *
symbolic_errno(int errnum)
{
	const char *res = symbolic_errno_map(errnum, ERRNO_SYM);

	if G_LIKELY(res != NULL)
		return res;

	/*
	 * Use rotating static buffers to format the actual error value.
	 */

#define BUFCNT	8
	{
		static char buf[BUFCNT][UINT_DEC_BUFLEN];
		static unsigned n;
		char *p = &buf[atomic_uint_inc(&n) % BUFCNT][0];

		uint_to_string_buf(errno, p, sizeof buf[0]);
		return p; 	/* Unknown errno code */
	}
#undef BUFCNT
}

/**
 * Give English message from errno value.
 *
 * @return A const static string. If errno is unhandled, its stringified
 * integer value prefixed by "Error #" is returned.
 */
const char *
english_strerror(int errnum)
{
	const char *res = symbolic_errno_map(errnum, ERRNO_STR);

	if G_LIKELY(res != NULL)
		return res;

	/*
	 * Use rotating static buffers to format the actual error value.
	 */

#define BUFCNT	8
#define BUFPRE	CONST_STRLEN("Error #")
	{
		static char buf[BUFCNT][UINT_DEC_BUFLEN + BUFPRE];
		static unsigned n;
		char *p = &buf[atomic_uint_inc(&n) % BUFCNT][0];

		p = mempcpy(p, "Error #", BUFPRE);
		uint_to_string_buf(errno, p, sizeof buf[0] - BUFPRE);
		return p; 	/* Unknown errno code */
	}
#undef BUFCNT
#undef BUFPRE
}

/**
 * Adds some lexical indendation to XML-like text.
 *
 * The input text is assumed to be "flat" and well-formed. If these assumptions
 * fail, the output might look worse than the input.
 *
 * @param text		the string to format.
 *
 * @return a newly allocated string which must be freed via hfree().
 */
char *
xml_indent(const char *text)
{
	const char *p, *q;
	bool quoted, is_special, is_end, is_start, is_singleton, has_cdata;
	guint i, depth = 0;
	str_t *s;

	s = str_new(0);
	q = text;

	quoted = FALSE;
	is_special = FALSE;
	is_end = FALSE;
	is_start = FALSE;
	is_singleton = FALSE;
	has_cdata = FALSE;

	for (;;) {
		bool had_cdata;

		p = q;
		/*
		 * Find the start of the tag and append the text between the
		 * previous and the current tag.
		 */
		for (/* NOTHING */; '<' != *p && '\0' != *p; p++) {
			if (is_ascii_space(*p) && is_ascii_space(p[1]))
				continue;
			if (has_cdata && '&' == *p) {
				const char *endptr;
				guint32 uc;

				uc = html_decode_entity(p, &endptr);
				if (uc > 0x00 && uc <= 0xff && '<' != uc && '>' != uc) {
					str_putc(s, uc);
					p = endptr - 1;
					continue;
				}
			}
			str_putc(s, is_ascii_space(*p) ? ' ' : *p);
		}
		if ('\0' == *p)
			break;

		/* Find the end of the tag */
		q = strchr(p, '>');
		if (!q)
			q = strchr(p, '\0');

		is_special = '?' == p[1] || '!' == p[1];
		is_end = '/' == p[1];
		is_start = !(is_special || is_end);
		is_singleton = is_start && '>' == *q && '/' == q[-1];
		had_cdata = has_cdata;
		has_cdata = FALSE;

		if (is_end && depth > 0) {
			depth--;
		}
		if (p != text && !(is_end && had_cdata)) {
			str_putc(s, '\n');
			for (i = 0; i < depth; i++)
				str_putc(s, '\t');
		}

		quoted = FALSE;
		for (q = p; '\0' != *q; q++) {

			if (!quoted && is_ascii_space(*q) && is_ascii_space(q[1]))
				continue;

			if (is_ascii_space(*q)) {
				if (quoted || is_special) {
					str_putc(s, ' ');
				} else {
					str_putc(s, '\n');
					for (i = 0; i < depth + 1; i++)
						str_putc(s, '\t');
				}
				continue;
			}

			if (quoted && '&' == *q) {
				const char *endptr;
				guint32 uc;

				uc = html_decode_entity(q, &endptr);
				if (uc > 0x00 && uc <= 0xff && '"' != uc) {
					str_putc(s, uc);
					q = endptr - 1;
					continue;
				}
			}

			str_putc(s, *q);

			if ('"' == *q) {
				quoted ^= TRUE;
			} else if ('>' == *q) {
				q++;
				break;
			}
		}
		if (is_start && !is_singleton) {
			const char *next = strchr(q, '<');
			has_cdata = next && '/' == next[1];
			depth++;
		}
	}

	/* Ensure there is a final "\n" in the string */

	if ('\n' != str_at(s, -1))
		str_putc(s, '\n');

	return str_s2c_null(&s);
}

/**
 * Initialize miscellaneous data structures, once.
 */
static void G_COLD
misc_init_once(void)
{
	hex2int_init();
	dec2int_init();
	alnum2int_init();

	g_assert(is_ascii_blank(' '));
	g_assert(is_ascii_blank('\t'));
	g_assert(!is_ascii_blank('\v'));
	g_assert(is_ascii_space(' '));
	g_assert(is_ascii_space('\t'));
	g_assert(is_ascii_space('\v'));
	g_assert(!is_ascii_space('-'));
	g_assert(!is_ascii_space('a'));
	g_assert(is_ascii_lower('a'));
	g_assert(!is_ascii_upper('a'));
	g_assert(is_ascii_upper('A'));
	g_assert(!is_ascii_lower('A'));
	g_assert(is_ascii_xdigit('0'));
	g_assert(is_ascii_xdigit('9'));
	g_assert(is_ascii_xdigit('A'));
	g_assert(is_ascii_xdigit('F'));
	g_assert(is_ascii_xdigit('a'));
	g_assert(is_ascii_xdigit('f'));
	g_assert(!is_ascii_xdigit('H'));
	g_assert(is_ascii_alnum('0'));
	g_assert(is_ascii_alnum('a'));
	g_assert(is_ascii_alnum('z'));
	g_assert(is_ascii_alnum('A'));
	g_assert(is_ascii_alnum('Z'));
	g_assert(!is_ascii_alnum(' '));
	g_assert(!is_ascii_alnum('-'));
	g_assert(!is_ascii_punct('a'));
	g_assert(is_ascii_punct('-'));
	g_assert(is_ascii_graph('-'));

	{
		static const struct {
			const char *s;
			const uint64 v;
			const uint base;
			const int error;
		} tests[] = {
			{ "", 					0,				10, EINVAL },
			{ "1111",				1111,			10, 0 },
			{ "z",					35, 			36, 0 },
			{ "Z",					35,				36, 0 },
			{ "0ff",				0xff,			16, 0 },
			{ "-1",					0,				10, EINVAL },
			{ "aBcDE",				0xabcde,		16, 0 },
			{ "ffff",				0xffff,			16, 0 },
			{ "fffff",				0xfffff,		16, 0 },
			{ "ffffffff",			0xffffffffU,	16, 0 },
			{ "ffffffffffffffff",	(uint64) -1,	16, 0 },
			{ "1111111111111111",	0xffff,			2,  0 },
			{ "11111111111111111",	0x1ffff,		2,  0 },
			{ "111111111111111111",	0x3ffff,		2,  0 },
			{ "ZZZ0",				1679580,		36, 0 },
			{ "2",					0,				2, EINVAL },
			{ "3",					0,				3, EINVAL },
			{ "4",					0,				4, EINVAL },
			{ "5",					0,				5, EINVAL },
			{ "6",					0,				6, EINVAL },
			{ "7",					0,				7, EINVAL },
			{ "8",					0,				8, EINVAL },
			{ "9",					0,				9, EINVAL },
		};
		uint i;

		for (i = 0; i < N_ITEMS(tests); i++) {
			const char *endptr;
			int error;
			uint64 v;

			g_assert((0 == tests[i].v) ^ (0 == tests[i].error));

			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint64(tests[i].s, &endptr, tests[i].base, &error);
			g_assert(tests[i].v == v);
			g_assert(tests[i].error == error);

			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint32(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (uint32) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}

			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint16(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (uint16) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}
		}
	}

	{
		static const struct {
			const char *s;
			const uint src_len;
			const uint res;
		} t[] = {
			{ "",					1, 	0 },
			{ "ab",					3, 	2 },
			{ "ab",					2, 	2 },
			{ "ab",					1, 	1 },
			{ "abcdefghi",			10,	9 },
			{ "abcdefghi",			7,	7 },
			{ "abcdefgh",			9,	8 },
			{ "abcdefg",			8,	7 },
			{ "abcdef",				7,	6 },
			{ "abcdefghijklmnop",	17,	16 },
			{ "abcdefghijklmno\0p",	17,	15 },
			{ "abcdefghijklmn\0op",	17,	14 },
			{ "abcdefghijklm\0nop",	17,	13 },
			{ "abcdefghijkl\0mnop",	17,	12 },
			{ "abcdefghijk\0lmnop",	17,	11 },
			{ "abcdefghij\0klmnop",	17,	10 },
			{ "abcdefghi\0jklmnop",	17,	9 },
			{ "abcdefgh\0ijklmnop",	17,	8 },
			{ "abcdefg",			8,	7 },
			{ "abcdef\0g",			8,	6 },
			{ "abcde\0fg",			8,	5 },
			{ "abcd\0efg",			8,	4 },
			{ "abc\0defg",			8,	3 },
			{ "ab\0cdefg",			8,	2 },
			{ "a\0bcdefg",			8,	1 },
			{ "\0abcdefg",			8,	0 },
		};
		uint i;

		for (i = 0; i < N_ITEMS(t); i++) {
			const char *s = t[i].s;
			uint src_len = t[i].src_len;
			uint res = t[i].res;

			g_assert(res <= src_len);

			g_assert_log(res == clamp_strlen(s, src_len),
				"clamp_strlen(\"%s\", %d) = %zu, expected %u",
				s, src_len, clamp_strlen(s, src_len), res);

			while (res != 0) {
				s++;
				src_len--;
				res--;

				g_assert_log(res == clamp_strlen(s, src_len),
					"clamp_strlen(\"%s\", %d) = %zu, expected %u",
					s, src_len, clamp_strlen(s, src_len), res);
			}
		}
	}
}

/**
 * Initialize miscellaneous data structures.
 */
void G_COLD
misc_init(void)
{
	static once_flag_t done;

	once_flag_run(&done, misc_init_once);
}

/**
 * Final cleanup at shutdown time.
 */
void G_COLD
misc_close(void)
{
	html_entities_close();
}

/* vi: set ts=4 sw=4 cindent: */
