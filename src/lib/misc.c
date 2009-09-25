/*
 * $Id$
 *
 * Copyright (c) 2001-2008, Raphael Manfredi
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
 * @date 2001-2008
 * @author Christian Biere
 * @date 2003-2008
 */

#include "common.h"

RCSID("$Id$")

#include "ascii.h"
#include "atoms.h"
#include "base16.h"
#include "base32.h"
#include "compat_misc.h"
#include "concat.h"
#include "endian.h"
#include "entropy.h"
#include "halloc.h"
#include "html_entities.h"
#include "misc.h"
#include "glib-missing.h"
#include "sha1.h"
#include "parse.h"
#include "path.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "walloc.h"
#include "utf8.h"

#include "if/core/guid.h"

#include "override.h"			/* Must be the last header included */

#if !defined(HAS_ARC4RANDOM) && (!defined(HAS_SRANDOM) || !defined(HAS_RANDOM))
#error "No sufficient PRNG functions available."
/*
 * srandom() and random() are available as open-source implementations. Use
 * that or a stronger PRNG but do NOT use crappy toys like srand()/rand()!
 */
#endif	/* HAS_SRANDOM && HAS_RANDOM */

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
		if (a != b && ascii_tolower(a) != ascii_tolower(b))
			return NULL;
	}

	return deconstify_gchar(s);
}

/**
 * Check whether ``suffix'' is the end of ``str''.
 *
 * @param str		a NUL-terminated string
 * @param len		length of ``str'', 0 means compute it
 * @param suffix	the suffix to look for (NUL-terminated string)
 */
gboolean
is_strsuffix(const char *str, size_t len, const char *suffix)
{
	size_t slen;
	size_t flen;

	g_assert(NULL != str);
	g_assert(NULL != suffix);

	slen = 0 == len ? strlen(str) : len;
	flen = strlen(suffix);

	if (slen < flen) {
		return FALSE;
	} else {
		const char *p = str + (slen - flen);
		return 0 == strcmp(p, suffix);
	}
}

/**
 * Check for file existence.
 */
gboolean
file_exists(const char *pathname)
{
  	struct stat st;

    g_assert(pathname);
    return 0 == stat(pathname, &st);
}

/**
 * Check for file non-existence.
 */
gboolean
file_does_not_exist(const char *pathname)
{
  	struct stat st;

    g_assert(pathname);
	return stat(pathname, &st) && ENOENT == errno;
}

/**
 * @returns local host name, as pointer to static data.
 */
const char *
local_hostname(void)
{
	static char name[256 + 1];

	if (-1 == gethostname(name, sizeof name))
		g_warning("gethostname() failed: %s", g_strerror(errno));

	name[sizeof(name) - 1] = '\0';
	return name;
}

/**
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a "\n" or "\r".
 * If len is 0, compute it.
 *
 * @returns new string length.
 */
size_t
str_chomp(char *str, size_t len)
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
gboolean
is_directory(const char *pathname)
{
	struct stat st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISDIR(st.st_mode);
}

/**
 * Check whether path points to a regular file.
 */
gboolean
is_regular(const char *pathname)
{
	struct stat st;

	g_assert(pathname);
	return 0 == stat(pathname, &st) && S_ISREG(st.st_mode);
}

/**
 * Check whether path is a symbolic link.
 */
gboolean
is_symlink(const char *pathname)
#if defined(HAS_LSTAT)
{
	struct stat st;

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
	struct stat sb_a, sb_b;

	g_assert(pathname_a);
	g_assert(pathname_b);

	/* May no exist but points clearly to the same file */
	if (0 == strcmp(pathname_a, pathname_b))
		return TRUE;

	if (stat(pathname_a, &sb_a))
		return -1;

	if (stat(pathname_b, &sb_b))
		return -1;

	return sb_a.st_dev == sb_b.st_dev && sb_a.st_ino == sb_b.st_ino;
}

/**
 * A wrapper around lseek() for handling filesize_t to off_t conversion.
 *
 * @param fd A valid file descriptor.
 * @param pos The position to seek to.
 * @return 0 on success and -1 on failure.
 */
int
seek_to_filepos(int fd, filesize_t pos)
{
	off_t offset;

	offset = filesize_to_off_t(pos);
	if ((off_t) -1 == offset) {
		errno = ERANGE;
		return -1;
	} else {
		int saved_errno = errno;
		off_t ret;

		/* Clear errno to be sure we get no bogus errno code, if
		 * the system does not agree with us that the lseek()
		 * failed. */
		errno = 0;
		ret = lseek(fd, offset, SEEK_SET);
		if ((off_t) -1 == ret || ret != offset) {
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
	filesize_t offset;

	offset = 0;
	if (size > 1) {
		random_bytes(&offset, sizeof offset);
		offset %= size - 1;
	}
	return offset;
}

static inline guint
filesize_fraction(filesize_t size, filesize_t part, guint base)
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
guint \
filesize_per_ ## base (filesize_t size, filesize_t part) \
{ \
	return filesize_fraction(size, part, base); \
}

GENERATE_FILESIZE_PER_X(100)
GENERATE_FILESIZE_PER_X(1000)
GENERATE_FILESIZE_PER_X(10000)
#undef GENERATE_FILESIZE_PER_X

static inline guint
kilo(gboolean metric)
{
	return metric ? 1000 : 1024;
}

static inline const char *
byte_suffix(gboolean metric)
{
	static const char suffix[] = "iB";
	return &suffix[metric ? 1 : 0];
}

static inline const char *
scale_prefixes(gboolean metric)
{
	return metric ? "\0kMGTPEZ" : "\0KMGTPEZ";
}

/**
 * Scales v so that quotient and reminder are both in the range "0..1023".
 *
 * @param v no document.
 * @param q pointer to a guint; will hold the quotient.
 * @param r pointer to a guint; will hold the reminder.
 * @param s a string holding the scale prefixes; must be sufficiently long.
 *
 * @return the appropriate prefix character from "s".
 */
static inline char
size_scale(guint64 v, guint *q, guint *r, const char *s, gboolean metric)
{
	const guint base = kilo(metric);

	if (v < base) {
		*q = v;
		*r = 0;
	} else {
		const guint thresh = base * base;

		for (s++; v >= thresh; v /= base)
			s++;
	
		*q = (guint) v / base;
		*r = (guint) v % base;
	}
	return *s;
}

static inline char
norm_size_scale(guint64 v, guint *q, guint *r, gboolean metric)
{
	return size_scale(v, q, r, scale_prefixes(metric), metric);
}

/**
 * Same as norm_size_scale_base2() but assumes v is already divided
 * by 1024 (binary).
 */
static inline char
kib_size_scale(guint64 v, guint *q, guint *r, gboolean metric)
{
	if (metric && v < ((guint64) -1) / 1024) {
		v = (v * 1024) / 1000;
	}
	return size_scale(v, q, r, scale_prefixes(metric) + 1, metric);
}

const char *
short_size(guint64 size, gboolean metric)
{
	static char b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		guint n = size;
		gm_snprintf(b, sizeof b, NG_("%u Byte", "%u Bytes", n), n);
	} else {
		guint q, r;
		char c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

/**
 * Like short_size() but with unbreakable space between the digits and unit.
 */
const char *
short_html_size(guint64 size, gboolean metric)
{
	static char b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		guint n = size;
		gm_snprintf(b, sizeof b, NG_("%u&nbsp;Byte", "%u&nbsp;Bytes", n), n);
	} else {
		guint q, r;
		char c;

		c = norm_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u&nbsp;%c%s", q, r, c,
			byte_suffix(metric));
	}

	return b;
}

const char *
short_kb_size(guint64 size, gboolean metric)
{
	static char b[SIZE_FIELD_MAX];
	
	if (size < kilo(metric)) {
		gm_snprintf(b, sizeof b, "%u %s", (guint) size, metric ? "kB" : "KiB");
	} else {
		guint q, r;
		char c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%02u %c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

/**
 * @return a number of Kbytes in a compact readable form
 */
const char *
compact_kb_size(guint32 size, gboolean metric)
{
	static char b[SIZE_FIELD_MAX];

	if (size < kilo(metric)) {
		gm_snprintf(b, sizeof b, "%u%s", (guint) size, metric ? "kB" : "KiB");
	} else {
		guint q, r;
		char c;

		c = kib_size_scale(size, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		gm_snprintf(b, sizeof b, "%u.%u%c%s", q, r, c, byte_suffix(metric));
	}

	return b;
}

const char *
nice_size(guint64 size, gboolean metric)
{
	static char buf[256];
	char bytes[UINT64_DEC_BUFLEN];

	uint64_to_string_buf(size, bytes, sizeof bytes);
	gm_snprintf(buf, sizeof buf,
		_("%s (%s bytes)"), short_size(size, metric), bytes);
	return buf;
}

char *
compact_value(char *buf, size_t size, guint64 v, gboolean metric)
{
	if (v < kilo(metric)) {
		gm_snprintf(buf, size, "%u", (guint) v);
	} else {
		guint q, r;
		char c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 10) / kilo(metric);
		gm_snprintf(buf, size, "%u.%u%c%s", q, r, c, metric ? "" : "i");
	}

	return buf;
}

char *
short_value(char *buf, size_t size, guint64 v, gboolean metric)
{
	if (v < kilo(metric)) {
		gm_snprintf(buf, size, "%u ", (guint) v);
	} else {
		guint q, r;
		char c;

		c = norm_size_scale(v, &q, &r, metric);
		r = (r * 100) / kilo(metric);
		gm_snprintf(buf, size, "%u.%02u %c%s", q, r, c, metric ? "" : "i");
	}
	
	return buf;
}

const char *
compact_size(guint64 size, gboolean metric)
{
	static char buf[SIZE_FIELD_MAX];

	compact_value(buf, sizeof buf, size, metric);
	g_strlcat(buf, "B", sizeof buf);
	return buf;
}

const char *
compact_rate(guint64 rate, gboolean metric)
{
	static char buf[SIZE_FIELD_MAX];

	compact_value(buf, sizeof buf, rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	g_strlcat(buf, _("B/s"), sizeof buf);
	return buf;
}

static size_t
short_rate_to_string_buf(guint64 rate, gboolean metric, char *dst, size_t size)
{
	short_value(dst, size, rate, metric);
	/* TRANSLATORS: Don't translate 'B', just 's' is allowed. */
	return g_strlcat(dst, _("B/s"), size);
}

short_string_t
short_rate_get_string(guint64 rate, gboolean metric)
{
	short_string_t buf;
	short_rate_to_string_buf(rate, metric, buf.str, sizeof buf.str);
	return buf;
}

const char *
short_rate(guint64 rate, gboolean metric)
{
	static short_string_t buf;
	buf = short_rate_get_string(rate, metric);
	return buf.str;
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
guid_to_string_buf(const struct guid *guid, char *dst, size_t size)
{
	return bin_to_hex_buf(guid->v, GUID_RAW_SIZE, dst, size);
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const char *
guid_to_string(const struct guid *guid)
{
	static char buf[GUID_HEX_SIZE + 1];
	size_t ret;

	ret = guid_to_string_buf(guid, buf, sizeof buf);
	g_assert(GUID_HEX_SIZE == ret);
	return buf;
}

/**
 * @return hexadecimal string representing given GUID, in static buffer.
 */
const char *
guid_hex_str(const struct guid *guid)
{
	static char buf[GUID_HEX_SIZE + 1];
	size_t ret;

	ret = guid_to_string_buf(guid, buf, sizeof buf);
	g_assert(GUID_HEX_SIZE == ret);
	return buf;
}

static gint8 char2int_tabs[3][(size_t) (guchar) -1 + 1];

const gint8 *hex2int_tab = char2int_tabs[0];
const gint8 *dec2int_tab = char2int_tabs[1];
const gint8 *alnum2int_tab = char2int_tabs[2];

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
hex2int(guchar c)
{
	int ret;
	
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
dec2int(guchar c)
{
	int ret;
	
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
alnum2int(guchar c)
{
	int ret;
	
	ret = alnum2int_inline(c);
	g_assert(-1 != ret);
	return ret;
}

/**
 * Initializes the lookup table for hex2int().
 */
static void
hex2int_init(void)
{
	size_t i;

	/* Initialize hex2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[0]); i++) {
		static const char hexa[] = "0123456789abcdef";
		const char *p = i ? strchr(hexa, ascii_tolower(i)): NULL;
		
		char2int_tabs[0][i] = p ? (p - hexa) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++)
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
static void
dec2int_init(void)
{
	size_t i;

	/* Initialize dec2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[1]); i++) {
		static const char deca[] = "0123456789";
		const char *p = i ? strchr(deca, i): NULL;
		
		char2int_tabs[1][i] = p ? (p - deca) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++)
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
static void
alnum2int_init(void)
{
	static const char abc[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	size_t i;

	/* Initialize alnum2int_tab */
	
	for (i = 0; i < G_N_ELEMENTS(char2int_tabs[2]); i++) {
		const char *p = i ? strchr(abc, ascii_tolower(i)): NULL;
		
		char2int_tabs[2][i] = p ? (p - abc) : -1;
	}
	
	/* Check consistency of hex2int_tab */

	for (i = 0; i <= (guchar) -1; i++) {
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
gboolean
hex_to_guid(const char *hexguid, struct guid *guid)
{
	size_t ret;
		
	ret = base16_decode(guid->v, sizeof guid->v, hexguid, GUID_HEX_SIZE);
	return GUID_RAW_SIZE == ret;
}

/**
 * Converts GUID into its base32 representation, without the trailing padding.
 *
 * @return pointer to static data.
 */
const char *
guid_base32_str(const struct guid *guid)
{
	static char buf[GUID_BASE32_SIZE + 1];
	size_t len;

	len = base32_encode(buf, sizeof buf, guid, GUID_RAW_SIZE);
	g_assert(len == G_N_ELEMENTS(buf) - 1);
	buf[len] = '\0';
	return buf;
}

/**
 * Decode the base32 representation of a GUID.
 *
 * @return pointer to static data, or NULL if the input was not valid base32.
 */
const struct guid *
base32_to_guid(const char *base32)
{
	static struct guid guid;
	size_t ret;

	ret = base32_decode(guid.v, sizeof guid.v, base32, GUID_BASE32_SIZE);
	return (size_t)0 + GUID_RAW_SIZE == ret ? &guid : NULL;
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
		base32_encode(dst, size, sha1->data, sizeof sha1->data);
		dst[size - 1] = '\0';
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
	static char digest_b32[SHA1_BASE32_SIZE + 1];

	g_assert(sha1);
	return sha1_to_base32_buf(sha1, digest_b32, sizeof digest_b32);
}

const char *
sha1_to_string(const struct sha1 sha1)
{
	static char digest_b32[SHA1_BASE32_SIZE + 1];
	return sha1_to_base32_buf(&sha1, digest_b32, sizeof digest_b32);
}

/**
 * Convert binary SHA1 into a urn:sha1:<base32> string.
 *
 * @param sha1 A binary SHA-1.
 * @return The SHA-1 converted to an URN string.
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
	return CONST_STRLEN(prefix) + SHA1_BASE32_SIZE + 1;
}

const char *
sha1_to_urn_string(const struct sha1 *sha1)
{
	static char buf[CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1];

	g_assert(sha1);
	sha1_to_urn_string_buf(sha1, buf, sizeof buf);
	return buf;
}

const char *
bitprint_to_urn_string(const struct sha1 *sha1, const struct tth *tth)
{
	g_assert(sha1);

	if (tth) {
		static const char prefix[] = "urn:bitprint:";
		static char buf[CONST_STRLEN(prefix) + BITPRINT_BASE32_SIZE + 1];
		const char * const end = &buf[sizeof buf];
		char *p = buf;

		memcpy(p, prefix, CONST_STRLEN(prefix));
		p += CONST_STRLEN(prefix);
		
		base32_encode(p, end - p, sha1->data, sizeof sha1->data);
		p += SHA1_BASE32_SIZE;

		*p++ = '.';
		
		base32_encode(p, end - p, tth->data, sizeof tth->data);
		p += TTH_BASE32_SIZE;
		*p = '\0';
		
		return buf;
	} else {
		static char buf[CONST_STRLEN("urn:sha1:") + SHA1_BASE32_SIZE + 1];

		sha1_to_urn_string_buf(sha1, buf, sizeof buf);
		return buf;
	}
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
	static struct sha1 sha1;
	size_t len;

	g_assert(base32);
	len = base32_decode(sha1.data, sizeof sha1.data, base32, SHA1_BASE32_SIZE);
	return SHA1_RAW_SIZE == len ? &sha1 : NULL;
}

/**
 * Convert binary TTH into a base32 string.
 *
 * @return pointer to static data.
 */
const char *
tth_base32(const struct tth *tth)
{
	static char buf[TTH_BASE32_SIZE + 1];

	g_assert(tth);
	base32_encode(buf, sizeof buf, tth->data, sizeof tth->data);
	buf[sizeof buf - 1] = '\0';
	return buf;
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
	static struct tth tth;
	size_t len;

	g_assert(base32);
	len = base32_decode(tth.data, sizeof tth.data, base32, TTH_BASE32_SIZE);
	return TTH_RAW_SIZE == len ? &tth : NULL;
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
		base32_encode(dst, size, tth->data, sizeof tth->data);
		dst[size - 1] = '\0';
	}
	return dst;
}

/**
 * Convert binary TTH into a urn:ttroot:<base32> string.
 *
 * @param tth A binary TTH.
 * @return The TTH converted to an URN string.
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
	return CONST_STRLEN(prefix) + TTH_BASE32_SIZE + 1;
}

const char *
tth_to_urn_string(const struct tth *tth)
{
	static char buf[CONST_STRLEN("urn:ttroot:") + TTH_BASE32_SIZE + 1];

	g_assert(tth);
	tth_to_urn_string_buf(tth, buf, sizeof buf);
	return buf;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
int
highest_bit_set(guint32 n)
{
	int h = 0;
	guint32 r = n;

	if (r == 0)
		return -1;

	while (r >>= 1)			/* Will find largest bit set */
		h++;

	return h;
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
size_t
common_leading_bits(
	gconstpointer k1, size_t k1bits, gconstpointer k2, size_t k2bits)
{
	const guint8 *p1 = k1;
	const guint8 *p2 = k2;
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
		guint8 diff = *p1++ ^ *p2++;
		if (diff)
			return i * 8 + 7 - highest_bit_set(diff);
	}

	bits = cbits & 0x7;

	if (bits != 0) {
		guint8 mask = ~((1 << (8 - bits)) - 1);
		guint8 diff = (*p1 & mask) ^ (*p2 & mask);
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

#ifdef HAS_ARC4RANDOM
/**
 * @return random value between 0 and (2**32)-1. All 32 bit are random.
 */
guint32
random_u32(void)
{
	return arc4random();
}
#else	/* !HAS_ARC4RANDOM */
/* rotates a 32-bit value by 16 bit */
static inline guint32
uint32_rot16(guint32 value)
{
	return (value << 16) | (value >> 16);
}

/**
 * @return random value between 0 and (2**32)-1. All 32 bit are random.
 */
guint32
random_u32(void)
{
	/*
	 * random() returns only values between 0 and (2**31)-1, so the
	 * MSB is always zero. Therefore mix two random values to get
	 * full 32 random bits.
	 */
	return uint32_rot16(random()) ^ random();
}
#endif	/* HAS_ARC4RANDOM */

/**
 * @return random value between (0..max).
 */
guint32
random_value(guint32 max)
{
	return (guint32) ((max + 1.0) * random_u32() / ((guint32) -1 + 1.0));
}

/**
 * Fills buffer 'dst' with 'size' bytes of random data.
 */
void
random_bytes(void *dst, size_t size)
{
	char *p = dst;

	while (size > 4) {
		const guint32 value = random_u32();
		memcpy(p, &value, 4);
		p += 4;
		size -= 4;
	}
	if (size > 0) {
		const guint32 value = random_u32();
		memcpy(p, &value, size);
	}
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	guint32 seed;
	struct sha1 digest;

	entropy_collect(&digest);
	seed = sha1_hash(&digest);	/* Reduces 160 bits to 32 */

	srandom(seed);	/* Just in case initstate() enables the alarm device */

#if defined(HAS_INITSTATE)
	{
		static gulong state[256 / sizeof(gulong)];
		
		initstate(seed, cast_to_gchar_ptr(state), sizeof state);
	}
#endif /* HAS_INITSTATE */

	/*
	 * Randomly ask for a few random bytes so that even if the same seed
	 * is selected by two peers, the first random values they generate
	 * will differ.  This matters when the first thing they will do is
	 * generate a GUID or a KUID...
	 *
	 * This adds roughly 8 bits of additional salt to the 32-bit seed since
	 * it can compute at most 22*20 = 440 random numbers, that amount being
	 * random (based on the SHA1 noise we have already computed).
	 */

	{
		int i;
		guint32 count = 0;

		for (i = 0; i < SHA1_RAW_SIZE; i++) {
			int j = (guchar) digest.data[i] % 23;

			while (j-- > 0)
				count += random_u32();		/* Avoid compiler warnings */
		}
	}
}

/**
 * Check whether buffer contains printable data, suitable for "%s" printing.
 * If not, consider dump_hex().
 */
gboolean
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
 * Prints a single "dump hex" line which consists of 16 byte from data.
 *
 * @param out The stream to print the string at.
 * @param data A pointer to the first byte of the data to dump.
 * @param length The length of data in bytes.
 * @param offset The offset in data to start dumping at.
 */
static void
dump_hex_line(FILE *out, const char *data, size_t length, size_t offset)
{
	char char_buf[32], hex_buf[64];
	char *p = hex_buf, *q = char_buf;
	size_t j, i = offset;

	for (j = 0; j < 16; j++) {
		*p++ = ' ';
		if (8 == j) {
			*p++ = ' ';
		}
		if (i < length) {	
			guchar c;

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

	fprintf(out, "%5u %s  %s\n", (guint) (offset & 0xffff), hex_buf, char_buf);
}

/**
 * Displays hex & ascii lines to the specified file (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex(FILE *out, const char *title, gconstpointer data, int length)
{
	int i;

	if (length < 0 || data == NULL) {
		g_warning("dump_hex: value out of range [data=0x%lx, length=%d] for %s",
			(gulong) data, length, title);
		fflush(out);
		return;
	}

	fprintf(out, "----------------- %s:\n", title);

	for (i = 0; i < length; i += MIN(length - i, 16)) {
		if (i % 256 == 0) {
			if (i > 0) {
				fputc('\n', out);	/* break after 256 byte chunk */
			}
			fputs("Offset  0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  "
				"0123456789abcdef\n", out);
		}
		dump_hex_line(out, data, length, i);
	}

	fprintf(out, "----------------- (%d bytes).\n", length);
	fflush(out);
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
gboolean
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
		*dst++ = tolower((guchar) *src);
	} while (*src++);
}

/**
 * Generate a new random GUID within given `xuid'.
 */
void
guid_random_fill(struct guid *guid)
{
	random_bytes(guid, GUID_RAW_SIZE);
}

/**
 * Determine stripped down path, removing SRC_PREFIX if present.
 *
 * @returns pointer within supplied string.
 */
char *
short_filename(char *fullname)
{
	char *s;

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

	if (compat_mkdir(dir, mode)) {
		error = errno;
		if (EEXIST == error) {
			goto finish;
		} else if (ENOENT == error) {
			char *upper = filepath_directory(dir);

			if (create_directory(upper, mode)) {
				error = errno;
		 	} else {
				if (compat_mkdir(dir, mode)) {
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
	g_warning("mkdir(\"%s\") failed: %s", dir, g_strerror(error));
	errno = error;
	return -1;
}

int
parse_major_minor(const char *src, char const **endptr,
	guint *major, guint *minor)
{
	const char *ep;
	int error;
	guint32 maj, min;

	g_assert(src);

	maj = parse_uint32(src, &ep, 10, &error);
	if (error) {
		min = 0;	/* dumb compiler */
	} else if (*ep != '.') {
		error = EINVAL;
		min = 0;	/* dumb compiler */
	} else {
		ep++; /* Skip the '.' */
		min = parse_uint32(ep, &ep, 10, &error);
	}

	if (endptr)
		*endptr = ep;
	if (major)
		*major = error ? 0 : maj;
	if (minor)
		*minor = error ? 0 : min;

	return error;
}

/**
 * Find amount of common leading bits between two IP addresses.
 */
static guint8
find_common_leading(guint32 ip1, guint32 ip2)
{
	guint8 n;
	guint32 mask;

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
	guint32 lower_ip, guint32 upper_ip, cidr_split_t cb, gpointer udata)
{
	guint8 bits;
	guint32 mask;
	guint32 trailing;

	g_assert(lower_ip <= upper_ip);

	bits = find_common_leading(lower_ip, upper_ip);
	mask = 1 << (32 - bits);
	trailing = mask - 1;

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
			guint32 cut;

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
		guint32 cut;

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

/**
 * Installs a signal handler. The signal handler is not reset to the default
 * handler after delivery. If the signal is SIGALRM, the handler is installed
 * so that interrupted system calls fail with EINTR. Handlers for other all
 * signals are installed so that interrupted system calls are restarted
 * instead.
 *
 * @param signo the signal number.
 * @param handler the signal handler to install.
 *
 * @return the previous signal handler or SIG_ERR on failure.
 */
signal_handler_t
set_signal(int signo, signal_handler_t handler)
{
#ifdef HAS_SIGACTION
	static const struct sigaction zero_sa;
	struct sigaction sa, osa;
	
	g_assert(handler != SIG_ERR);

	sa = zero_sa;
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = signo != SIGALRM ? SA_RESTART
#ifdef HAS_SA_INTERRUPT
		: SA_INTERRUPT;
#else
		: 0;
#endif

	return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
#else
	/* FIXME WIN32, probably: We can't just ignore all signal logic */
	return NULL;
#endif
}

static inline const char *
html_escape_replacement(char c, size_t *len)
{
	static char r;

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

	r = c;
	*len = 1;
	return &r;
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
	guchar c;

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

static GHashTable *html_entities_lut;

static void
html_entities_init(void)
{
	size_t i;

	html_entities_lut = g_hash_table_new(g_str_hash, g_str_equal);
	for (i = 0; i < G_N_ELEMENTS(html_entities); i++) {
		gm_hash_table_insert_const(html_entities_lut, html_entities[i].name,
			uint_to_pointer(html_entities[i].uc));
	}
}

static void
html_entities_close(void)
{
	if (html_entities_lut) {
		g_hash_table_destroy(html_entities_lut);
		html_entities_lut = NULL;
	}
}

/**
 * Maps an HTML entity to an Unicode codepoint.
 *
 * @param src    Should point to the start of an entity "&ENTITY;[...]"
 * @param endptr If not NULL, it will be set to point either to
 *		 		 the original string or the next character after
 *				 the entity.
 * @return		 On failure (guint32)-1 is returned, on success the
 *				 Unicode codepoint.
 */
guint32
html_decode_entity(const char * const src, const char **endptr)
{
	if ('&' != src[0])
		goto failure;

	if ('#' == src[1]) {
		const char *ep, *p;
		int base, error;
		guint32 v;

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
		value = g_hash_table_lookup(html_entities_lut, name);
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
	return (guint32) -1;
}

/**
 * Creates the canonical representation of a path.
 *
 * ``dst'' and ``src'' may be identical but must not overlap otherwise.
 *
 * @param dst the destination, must be sufficiently long.
 * @param path a NUL-terminated string representing the input path.
 * @return zero on sucess, non-zero on failure.
 */
int
canonize_path(char *dst, const char *path)
{
  const char *p;
  char c, *q, *ep;

  g_assert(dst);
  g_assert(path);
  /** TODO: Add overlap check. */

  /* Scan path */
  for (p = path, q = dst; '\0' != (c = *p); q++, p++) {

    /* Handle relative paths i.e., /. and /.. */
    if ('/' != c) {
      *q = c;
      continue;
    }

    /* Special handling for '/' follows */

    do {

      *q = '/';

      while ('/' == p[1]) {
        p++;
      }

      if (0 == strcmp(p, "/.")) {
        p++;
        /* Ignoring trailing "/." in URI */
      } else if (0 == strcmp(p, "/..")) {
        return -1;
      } else if (NULL != (ep = is_strprefix(p, "/./"))) {
        p = ep - 1;
        /* Ignoring unnecessary "/./" in URI */
      } else if (NULL != (ep = is_strprefix(p, "/../"))) {
        p = ep - 1;

        /* Ascending one component in URI */
        do {
          if (q == dst)
            return -1; /* beyond root */
        } while ('/' != *--q);

      } else {
        break;
      }

    } while ('/' == p[0] && ('/' == p[1] || '.' == p[1]));

  }

  *q = '\0';

  return 0;
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

guint32
cpu_noise(void)
{
	static guchar data[512];
	struct sha1 digest;
	SHA1Context ctx;
	guint32 r, i;
	
	r = random_u32();
	i = r % G_N_ELEMENTS(data);
	data[i] = r;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, data, i);
	SHA1Result(&ctx, &digest);

	return peek_le32(digest.data);
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
 * Initialize miscellaneous data structures.
 */
void
misc_init(void)
{
	hex2int_init();
	dec2int_init();
	alnum2int_init();

	{
		static const struct {
			const char *s;
			const guint64 v;
			const guint base;
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
			{ "ffffffffffffffff",	(guint64) -1,	16, 0 },
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
		guint i;

		for (i = 0; i < G_N_ELEMENTS(tests); i++) {
			const char *endptr;
			int error;
			guint64 v;

			g_assert((0 == tests[i].v) ^ (0 == tests[i].error));
			
			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint64(tests[i].s, &endptr, tests[i].base, &error);
			g_assert(tests[i].v == v);
			g_assert(tests[i].error == error);
			
			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint32(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (guint32) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}

			error = EAGAIN;
			endptr = GINT_TO_POINTER(-1);
			v = parse_uint16(tests[i].s, &endptr, tests[i].base, &error);
			if (tests[i].v > (guint16) -1) {
				g_assert(0 == v);
				g_assert(ERANGE == error);
			} else {
				g_assert(tests[i].v == v);
				g_assert(tests[i].error == error);
			}
		}
	}

}

/**
 * Final cleanup at shutdown time.
 */
void
misc_close(void)
{
	html_entities_close();
}

/* vi: set ts=4 sw=4 cindent: */
