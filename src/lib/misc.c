/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @file
 *
 * Misc functions.
 */

#include "common.h"

RCSID("$Id$");

#include <netdb.h>			/* For gethostbyname() */
#include <sys/times.h>		/* For times() */

#include "base32.h"
#include "misc.h"
#include "glib-missing.h"
#include "sha1.h"
#include "override.h"			/* Must be the last header included */

#if !defined(HAS_SRANDOM) || !defined(HAS_RANDOM)
#define srandom(x)	srand(x)
#define random()	rand()
#define RANDOM_MASK				0xffffffff
#define RANDOM_MAXV				RAND_MAX
#else
#define RANDOM_MASK				0x7fffffff
#define RANDOM_MAXV				RANDOM_MASK
#endif

static const char hex_alphabet[] = "0123456789ABCDEF";
static const char hex_alphabet_lower[] = "0123456789abcdef";

#ifndef HAS_STRLCPY
size_t
strlcpy(gchar *dst, const gchar *src, size_t dst_size)
{
	gchar *d = dst;
	const gchar *s = src;

	g_assert(NULL != dst);
	g_assert(NULL != src);

	if (dst_size--) {
		size_t i = 0;

		while (i < dst_size) {
			if (!(*d++ = *s++))
				return i;
			i++;
		}
		dst[dst_size] = '\0';
	}
 	while (*s)
		s++;
	return s - src;
}
#endif /* HAS_STRLCPY */

/**
 * Checks whether the given string contains a valid IP address. If the
 * string is NULL returns FALSE.
 */
gboolean
is_string_ip(const gchar *s)
{
    if (s == NULL)
        return FALSE;

    return 0 != gchar_to_ip(s);
}

/**
 * Check for file existence.
 */
gboolean
file_exists(const gchar *f)
{
  	struct stat st;

    g_assert(f != NULL);
    return stat(f, &st) != -1;
}

gchar *
ip_to_gchar(guint32 ip)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = htonl(ip);
	g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	return a;
}

gchar *
ip2_to_gchar(guint32 ip)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = htonl(ip);
	g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	return a;
}

void
ip_to_string(guint32 ip, gchar *buf, size_t size)
{
	union {
		guint32 ip_be;
		guint8 p[4];
	} addr;

	g_assert(buf != NULL);
	g_assert(size <= INT_MAX);

	addr.ip_be = htonl(ip);
	gm_snprintf(buf, size, "%u.%u.%u.%u",
		addr.p[0], addr.p[1], addr.p[2], addr.p[3]);
}

gchar *
ip_port_to_gchar(guint32 ip, guint16 port)
{
	static gchar a[32];
	size_t len;
	struct in_addr ia;

	ia.s_addr = htonl(ip);
	len = g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	if (len < sizeof(a) - 1)
		gm_snprintf(a + len, sizeof(a) - len, ":%u", port);
	return a;
}

gchar *
hostname_port_to_gchar(const gchar *hostname, guint16 port)
{
	static gchar a[300];

	gm_snprintf(a, sizeof(a), "%.255s:%u", hostname, port);
	return a;
}

#ifndef HAS_INET_ATON
/**
 * Copied from icecast.
 * Fixed to returns 0 on failure, 1 on success --RAM, 12/01/2002.
 */
int
inet_aton(const char *s, struct in_addr *addr)
{
	int a, b, c, d;

	if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return 0;

#if G_BYTE_ORDER == G_BIG_ENDIAN
	addr->s_addr = d + (c << 8) + (b << 16) + (a << 24);
#elif G_BYTE_ORDER == G_LITTLE_ENDIAN
	addr->s_addr = a + (b << 8) + (c << 16) + (d << 24);
#else
#error Byteorder not supported!
#endif
	return 1;
}
#endif /* !HAS_INET_ATON */


guint32
gchar_to_ip(const gchar *str)
{
	/* Returns 0 if str is not a valid IP */

	struct in_addr ia;
	gint r;

	/* Skip leading spaces */
	while (isspace((guchar) *str))
		str++;

	r = inet_aton(str, &ia);
	if (r)
		return ntohl(ia.s_addr);
	return 0;
}

/**
 * A strict string to IP address conversion; when other stuff from misc.[ch]
 * is not sufficient.
 *
 * Returns TRUE if ``s'' pointed to a string representation of an IPv4
 * address, otherwise FALSE.
 * If successful, ``*addr'' will be set to the IPv4 address in NATIVE
 * byte order and ``*endptr'' will point to the character after the
 * IPv4 address. ``addr'' and ``endptr'' may be NULL.
 */
gboolean
gchar_to_ip_strict(const gchar *s, guint32 *addr, gchar const **endptr)
{
	const gchar *p = s;
	gboolean is_valid = TRUE;
	gint i, j, v;
	guint32 a = 0; /* 'pid compiler */

	g_assert(s);

	for (i = 0; i < 4; i++) {
		v = 0;
		for (j = 0; j < 3; j++) {
			if (*p < '0' || *p > '9') {
				is_valid = j > 0;
				break;
			}
			v *= 10;
			v += *p++ - '0';
		}
		if (!is_valid)
			break;
		if (i < 3) {
			if (*p != '.') {
				is_valid = FALSE;
				break; /* failure */
			}
			p++;
		}
		a = (a << 8) | v;
	}

	if (endptr)
		*endptr = p;

	if (addr)
		*addr = is_valid ? a : 0;

	return is_valid;
}

/**
 * Decompiles ip:port into ip and port.  Leading spaces are ignored.
 * Returns TRUE if it parsed correctly, FALSE otherwise.
 */
gboolean
gchar_to_ip_port(const gchar *str, guint32 *ip, guint16 *port)
{
	gint a, b, c, d;
	gint iport;

	/* Skip leading spaces */
	while (isspace((const guchar) *str))
		str++;

	/* IP addresses are always written in big-endian format */
	if (sscanf(str, "%d.%d.%d.%d:%d", &a, &b, &c, &d, &iport) < 5)
		return FALSE;

	if (iport < 0 || iport > 65535)
		return FALSE;

	*ip = d + (c << 8) + (b << 16) + (a << 24);
	*port = iport;

	return TRUE;
}

static void
gethostbyname_error(const gchar *host)
{
#if defined(HAS_HSTRERROR)
		g_warning("cannot resolve \"%s\": %s", host, hstrerror(h_errno));
#elif defined(HAS_HERROR)
		g_warning("cannot resolve \"%s\":", host);
		herror("gethostbyname()");
#else
		g_warning("cannot resolve \"%s\": gethostbyname() failed!", host);
#endif /* defined(HAS_HSTRERROR) */
}

const gchar *
ip_to_host(guint32 ip)
{
	static const struct in_addr zero_addr;
	struct in_addr addr;
	const struct hostent *he;

	addr = zero_addr;
	addr.s_addr = (guint32) htonl(ip);
	he = gethostbyaddr((gchar *) &addr, sizeof addr, AF_INET);
	if (!he) {
		gchar host[32];

		ip_to_string(ip, host, sizeof host);
		gethostbyname_error(host);
		return NULL;
	}

#if 0
	g_message("h_name=\"%s\"", NULL_STRING(he->h_name));
	if (he->h_aliases) {
		size_t i;

		for (i = 0; he->h_aliases[i]; i++)
			g_message("h_aliases[%u]=\"%s\"", (unsigned) i, he->h_aliases[i]);
	}
#endif

	return he->h_name;
}

guint32
host_to_ip(const gchar *host)
{
	const struct hostent *he = gethostbyname(host);

	if (!he) {
		gethostbyname_error(host);
		return 0;
	}

#if 0
	g_message("h_name=\"%s\"", NULL_STRING(he->h_name));
	if (he->h_aliases) {
		size_t i;

		for (i = 0; he->h_aliases[i]; i++)
			g_message("h_aliases[%u]=\"%s\"", (unsigned) i, he->h_aliases[i]);
	}
#endif

	if (AF_INET6 == he->h_addrtype && he->h_length == 16) {
		guint32 ip;
		memcpy(&ip, &he->h_addr_list[0][12], 4);
		return ip;
	}	
	if (AF_INET != he->h_addrtype) {
		g_warning("host_to_ip: Wrong address type %d (host=%s).",
			he->h_addrtype, host);
		return 0;
	}
	if (4 != he->h_length) {
		g_warning("host_to_ip: Wrong address length %d (host=%s).",
			he->h_length, host);
		return 0;
	}
	return ntohl(*(guint32 *) (he->h_addr_list[0]));
}

/**
 * Returns local host name, as pointer to static data.
 */
gchar *
host_name(void)
{
	static gchar name[256 + 1];

	if (-1 == gethostname(name, sizeof(name)))
		g_warning("gethostname() failed: %s", g_strerror(errno));

	name[sizeof(name) - 1] = '\0';
	return name;
}

/**
 * Check whether host can be reached from the Internet.
 * We rule out IPs of private networks, plus some other invalid combinations.
 */
gboolean
ip_is_valid(guint32 ip)
{
	if ((!ip) ||			/* IP == 0 */
		(is_private_ip(ip)) ||
		/* 0.0.0.0 / 7 */
		((ip & (guint32) 0xFE000000) == (guint32) 0x00000000) ||
		/* 224..239.0.0 / 8 (multicast) */
		((ip & (guint32) 0xF0000000) == (guint32) 0xE0000000) ||
		/* 127.0.0.0 / 8 */
		((ip & (guint32) 0xFF000000) == (guint32) 0x7F000000) ||
		/* 192.0.2.0 -- (192.0.2/24 prefix) TEST-NET [RFC 3330] */
		((ip & 0xFFFFFF00) == 0xC0000200) ||
		/* 255.0.0.0 / 8 */
		((ip & (guint32) 0xFF000000) == (guint32) 0xFF000000))
			return FALSE;

	return TRUE;
}

/**
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a "\n" or "\r".
 * If len is 0, compute it.
 *
 * Returns new string length.
 */
gint
str_chomp(gchar *str, gint len)
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
 * Checks for RFC1918 private addresses; returns TRUE if is a private address.
 */
gboolean
is_private_ip(guint32 ip)
{
	/* 10.0.0.0 -- (10/8 prefix) */
	if ((ip & 0xff000000) == 0xa000000)
		return TRUE;

	/* 172.16.0.0 -- (172.16/12 prefix) */
	if ((ip & 0xfff00000) == 0xac100000)
		return TRUE;

	/* 169.254.0.0 -- (169.254/16 prefix) -- since Jan 2001 */
	if ((ip & 0xffff0000) == 0xa9fe0000)
		return TRUE;

	/* 192.168.0.0 -- (192.168/16 prefix) */
	if ((ip & 0xffff0000) == 0xc0a80000)
		return TRUE;

	return FALSE;
}

/**
 * Check whether path is an absolute path
 */
gboolean
is_absolute_path(const char *path)
{
	g_assert(path != NULL);
	return '/' == path[0];
}

/**
 * Check whether path is a directory
 */
gboolean
is_directory(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1)
		return FALSE;
	return S_ISDIR(st.st_mode);
}

/**
 * Check whether path points to a regular file
 */
gboolean
is_regular(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1)
		return FALSE;
	return S_ISREG(st.st_mode);
}

/**
 * Check whether path is a symbolic link
 */
gboolean
is_symlink(const gchar *path)
{
	struct stat st;
	if (-1 == lstat(path, &st))
		return FALSE;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}

const gchar *
short_size(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024) {
		if (size == 1)
			gm_snprintf(b, sizeof(b), "1 Byte");
		else
			gm_snprintf(b, sizeof(b), "%u Bytes", (guint) size);
	} else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f KiB", (gfloat) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f MiB", (gfloat) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f GiB", (gfloat) size / 1073741824.0);
	else if ((size >> 20) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f TiB",
			(gfloat) (size >> 10) / 1073741824.0);
	else if ((size >> 30) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f PiB",
			(gfloat) (size >> 20) / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f EiB",
			(gfloat) (size >> 30) / 1073741824.0);

	return b;
}

const gchar *
short_kb_size(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%u KiB", (guint) size);
	else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f MiB", (gfloat) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f GiB", (gfloat) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f TiB", (gfloat) size / 1073741824.0);
	else if ((size >> 20) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f PiB",
			(gfloat) (size >> 10) / 1073741824.0);
	else if ((size >> 30) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f EiB",
			(gfloat) (size >> 20) / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f ZiB",
			(gfloat) (size >> 30) / 1073741824.0);

	return b;
}

gchar *
compact_value(gchar *buf, size_t size, guint64 v)
{
	if (v < 1024) {
		gm_snprintf(buf, size, "%u", (guint) v);
	} else if (v < 1048576) {
		if (v & 0x3ff)
			gm_snprintf(buf, size, "%.1fKi",
				(gfloat) (guint32) v / 1024.0);
		else
			gm_snprintf(buf, size, "%uKi", (guint32) v >> 10);
	} else if (v < 1073741824) {
		if (v & 0xfffff)
			gm_snprintf(buf, size, "%.1fMi",
				(gfloat) (guint32) v / 1048576.0);
		else
			gm_snprintf(buf, size, "%uMi", (guint32) v >> 20);
	} else if ((v >> 10) < 1073741824) {
		if (v & 0x3fffffff)
			gm_snprintf(buf, size, "%.1fGi", (gfloat) v / 1073741824.0);
		else
			gm_snprintf(buf, size, "%uGi", (guint32) (v >> 30));
	} else {
		gm_snprintf(buf, size, "%.1fTi", (gfloat) (v >> 10) / 1073741824.0);
	}

	return buf;
}

gchar *
short_value(gchar *buf, size_t size, guint64 v)
{
	if (v < 1024) {
		gm_snprintf(buf, size, "%u ", (guint) v);
	} else if (v < 1048576) {
		if (v & 0x3ff)
			gm_snprintf(buf, size, "%.2f Ki",
				(gfloat) (guint32) v / 1024.0);
		else
			gm_snprintf(buf, size, "%u Ki", (guint32) v >> 10);
	} else if (v < 1073741824) {
		if (v & 0xfffff)
			gm_snprintf(buf, size, "%.2f Mi",
				(gfloat) (guint32) v / 1048576.0);
		else
			gm_snprintf(buf, size, "%u Mi", (guint32) v >> 20);
	} else if ((v >> 10) < 1073741824) {
		if (v & 0x3fffffff)
			gm_snprintf(buf, size, "%.2f Gi", (gfloat) v / 1073741824.0);
		else
			gm_snprintf(buf, size, "%u Gi", (guint32) (v >> 30));
	} else {
		gm_snprintf(buf, size, "%.2f Ti", (gfloat) (v >> 10) / 1073741824.0);
	}

	return buf;
}

const gchar *
compact_size(guint64 size)
{
	static gchar buf[64];
	gchar sizebuf[48];

	gm_snprintf(buf, sizeof buf, "%sB",
		compact_value(sizebuf, sizeof sizebuf, size));
	return buf;
}

const gchar *
compact_rate(guint64 rate)
{
	static gchar buf[64];
	gchar ratebuf[48];

	gm_snprintf(buf, sizeof buf, "%sB/s",
		compact_value(ratebuf, sizeof ratebuf, rate));
	return buf;
}

const gchar *
short_rate(guint64 rate)
{
	static gchar buf[64];
	gchar ratebuf[48];

	gm_snprintf(buf, sizeof buf, "%sB/s",
		short_value(ratebuf, sizeof ratebuf, rate));
	return buf;
}

/**
 * @return a number of Kbytes in a compact readable form
 */
const gchar *
compact_kb_size(guint32 size)
{
	static gchar b[64];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%uKi", size);
	else if (size < 1048576) {
		if (size & 0x3ff)
			gm_snprintf(b, sizeof(b), "%.1fMi", (gfloat) size / 1024.0);
		else
			gm_snprintf(b, sizeof(b), "%dMi", size >> 10);
	} else if (size < 1073741824)
		if (size & 0xfffff)
			gm_snprintf(b, sizeof(b), "%.1fGi", (gfloat) size / 1048576.0);
		else
			gm_snprintf(b, sizeof(b), "%dGi", size >> 20);
	else {
		if (size & 0x3fffffff)
			gm_snprintf(b, sizeof(b), "%.1fTi", (gfloat) size / 1073741824.0);
		else
			gm_snprintf(b, sizeof(b), "%dTi", size >> 30);
	}

	return b;
}

/**
 * Return time spent in seconds in a consise short readable form
 */
gchar *
short_time(gint t)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = MAX(t, 0);

	if (s > 86400)
		gm_snprintf(b, sizeof(b), "%dd %dh", s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		gm_snprintf(b, sizeof(b), "%dh %dm", s / 3600, (s % 3600) / 60);
	else if (s > 60)
		gm_snprintf(b, sizeof(b), "%dm %ds", s / 60, s % 60);
	else
		gm_snprintf(b, sizeof(b), "%ds", s);

	return b;
}

/**
 * Alternate time formatter for uptime.
 */
gchar *
short_uptime(gint uptime)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = MAX(uptime, 0);

	if (s > 86400) {
		guint32 d = s % 86400;
		gm_snprintf(b, sizeof(b), "%dd %02d%c%02d",
			s / 86400, d / 3600, (s & 0x1) ? '.' : ':', (d % 3600) / 60);
	} else {
		guint32 h = s % 3600;
		gm_snprintf(b, sizeof(b), "%02d:%02d:%02d", s / 3600, h / 60, h % 60);
	}

	return b;
}

/**
 * Returns hexadecimal string representing given GUID.
 */
gchar *
guid_hex_str(const gchar *guid)
{
	static gchar buf[33];
	gulong i;
	const guchar *g = (guchar *) guid;

	for (i = 0; i < 32; g++) {
		buf[i++] = hex_alphabet_lower[*g >> 4];
		buf[i++] = hex_alphabet_lower[*g & 0x0f];
	}

	buf[32] = '\0';
	return buf;
}

/**
 * Returns hexadecimal string representation of "small" binary buffer.
 * Buffer must be less than 40 chars, or only the first 40 chars are
 * represented with a trailing "..." added to show it is incomplete.
 */
gchar *
data_hex_str(const gchar *data, size_t len)
{
	static gchar buf[84];
	static const size_t maxlen = sizeof(buf) - 4; /* 3 chars for "more" + NUL */
	const guchar *p = (guchar *) data;
	size_t hmax;
	size_t i;

	hmax = 2 * len;
	hmax = MIN(hmax, maxlen);

	for (i = 0; i < hmax; p++) {
		buf[i++] = hex_alphabet_lower[*p >> 4];
		buf[i++] = hex_alphabet_lower[*p & 0x0f];
	}

	if (2 * len > hmax) {
		buf[i++] = '.';
		buf[i++] = '.';
		buf[i++] = '.';
	}

	g_assert(i < sizeof(buf));

	buf[i] = '\0';
	return buf;
}

/**
 * Convert an hexadecimal char (0-9, A-F, a-f) into decimal.
 */
inline gint
hex2dec(guchar c)
{
	return c >= '0' && c <= '9' ? c - '0'
		 : c >= 'a' && c <= 'f' ? c - 'a' + 10
		 : c >= 'A' && c <= 'F' ? c - 'A' + 10
		 : (g_assert_not_reached(), -1);
}

/**
 * Converts hexadecimal string into a GUID.
 * Returns true if OK.
 */
gboolean
hex_to_guid(const gchar *hexguid, gchar *guid)
{
	gulong i;

	for (i = 0; i < 16; i++) {
 		gint a = (guchar) hexguid[i << 1];
 		gint b = (guchar) hexguid[(i << 1) + 1];

		if (!(is_ascii_xdigit(a) && is_ascii_xdigit(b)))
			return FALSE;

		guid[i] = (hex2dec(a) << 4) + hex2dec(b);
	}

	return TRUE;
}

/**
 * Converts GUID into its base32 representation, without the trailing padding.
 * Returns pointer to static data.
 */
gchar *
guid_base32_str(const gchar *guid)
{
	static gchar guid_b32[26 + 1];		/* 26 chars needed for a GUID */

	base32_encode_str_into(guid, 16, guid_b32, sizeof(guid_b32), FALSE);

	return guid_b32;
}

/**
 * Decode the base32 representation of a GUID.
 * Returns pointer to static data, or NULL if the input was not valid base32.
 */
gchar *
base32_to_guid(const gchar *base32)
{
	static gchar guid[20];	/* Needs 20 chars to decode, last 4 will be 0 */

	if (0 == base32_decode_into(base32, 26, guid, sizeof(guid)))
		return NULL;

	g_assert(guid[16] == '\0' && guid[17] == '\0' &&
		guid[18] == '\0' && guid[19] == '\0');

	return guid;
}

/**
 * Convert binary SHA1 into a base32 string.
 * Returns pointer to static data.
 */
gchar *
sha1_base32(const gchar *sha1)
{
	static gchar digest_b32[SHA1_BASE32_SIZE + 1];

	base32_encode_into(sha1, SHA1_RAW_SIZE, digest_b32, sizeof(digest_b32));
	digest_b32[SHA1_BASE32_SIZE] = '\0';

	return digest_b32;
}

/**
 * Convert base32 string into binary SHA1.
 * Returns pointer to static data.
 */
gchar *
base32_sha1(const gchar *base32)
{
	static gchar digest_sha1[SHA1_RAW_SIZE];

	base32_decode_into(base32, SHA1_BASE32_SIZE,
		digest_sha1, sizeof(digest_sha1));

	return digest_sha1;
}

/**
 * Convert time to ISO style date, e.g. "2002-06-09T14:54:42Z".
 * Returns pointer to static data.
 */
gchar *
date_to_iso_gchar(time_t date)
{
	static gchar buf[80];
	struct tm *tm;

	tm = gmtime(&date);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	buf[sizeof(buf)-1] = '\0';		/* Be really sure */

	return buf;
}


/**
 * Compute the difference in seconds between two tm structs (a - b).
 * Comes from glibc-2.2.5.
 */
static gint
tm_diff(const struct tm *a, const struct tm * b)
{
	/*
	 * Compute intervening leap days correctly even if year is negative.
	 * Take care to avoid int overflow in leap day calculations,
	 * but it's OK to assume that A and B are close to each other.
	 */

#define TM_YEAR_BASE 1900

	gint a4 = (a->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (a->tm_year & 3);
	gint b4 = (b->tm_year >> 2) + (TM_YEAR_BASE >> 2) - ! (b->tm_year & 3);
	gint a100 = a4 / 25 - (a4 % 25 < 0);
	gint b100 = b4 / 25 - (b4 % 25 < 0);
	gint a400 = a100 >> 2;
	gint b400 = b100 >> 2;
	gint intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
	gint years = a->tm_year - b->tm_year;
	gint days = (365 * years + intervening_leap_days
		+ (a->tm_yday - b->tm_yday));

	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		+ (a->tm_min - b->tm_min))
		+ (a->tm_sec - b->tm_sec));
}

static const gchar days[7][4] =
	{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static const gchar months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/**
 * Convert time to RFC-822 style date, into supplied string buffer.
 */
static void
date_to_rfc822(time_t date, gchar *buf, gint len)
{
	struct tm *tm;
	struct tm gmt_tm;
	gint gmt_off;
	gchar sign;

	g_assert(len > 0);
	tm = gmtime(&date);
	gmt_tm = *tm;					/* struct copy */
	tm = localtime(&date);

	/*
	 * We used to do:
	 *
	 *    strftime(buf, len, "%a, %d %b %Y %H:%M:%S %z", tm);
	 *
	 * but doing both:
	 *
	 *    putenv("LC_TIME=C");
	 *    setlocale(LC_TIME, "C");
	 *
	 * did not seem to force that routine to emit English.  Let's do it
	 * ourselves.
	 *
	 * We also used to reply on strftime()'s "%z" to compute the GMT offset,
	 * but this is GNU-specific.
	 */

	gmt_off = tm_diff(tm, &gmt_tm) / 60;	/* in minutes */

	if (gmt_off < 0) {
		sign = '-';
		gmt_off = -gmt_off;
	} else
		sign = '+';

	gm_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d %c%04d",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		sign, gmt_off / 60 * 100 + gmt_off % 60);

	buf[len - 1] = '\0';		/* Be really sure */
}

/**
 * Convert time to RFC-822 style date.
 * Returns pointer to static data.
 */
gchar *
date_to_rfc822_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/**
 * Same as date_to_rfc822_gchar(), to be able to use the two in the same
 * printf() line.
 */
gchar *
date_to_rfc822_gchar2(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/**
 * Convert time to RFC-1123 style date, into supplied string buffer.
 */
static void
date_to_rfc1123(time_t date, gchar *buf, gint len)
{
	const struct tm *tm;

	g_assert(len > 0);
	tm = gmtime(&date);
	gm_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/**
 * Convert time to RFC-1123 style date.
 * Returns pointer to static data.
 */
gchar *
date_to_rfc1123_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc1123(date, buf, sizeof(buf));
	return buf;
}

/**
 * Returns the closest power of two greater or equal to `n'.
 * next_pow2(0) and next_pow2(0x8.......) return 0.
 */
guint32
next_pow2(guint32 n)
{
	n--;

	n |= n >> 16;
	n |= n >> 8;
	n |= n >> 4;
	n |= n >> 2;
	n |= n >> 1;

	return n + 1;
}

/**
 * Determine the highest bit set in `n', -1 if value was 0.
 */
gint
highest_bit_set(guint32 n)
{
	gint h = 0;
	guint32 r = n;

	if (r == 0)
		return -1;

	while (r >>= 1)			/* Will find largest bit set */
		h++;

	return h;
}

/**
 * Enforce range boundaries on a given floating point
 * number.
 *
 * @param val The value to force within the range.
 * @param min The minimum value which val can be.
 * @param max The maximum value with val can be.
 * @return The new value of val which will be between
 *         min and max.
 */
gfloat
force_range(gfloat val, gfloat min, gfloat max)
{
	g_assert(min <= max);

	return
		val < min ? min :
		val > max ? max :
		val;
}

/**
 * Return random value between (0..max).
 */
guint32
random_value(guint32 max)
{
	return (guint32)
		((max + 1.0) * (random() & RANDOM_MASK) / (RANDOM_MAXV + 1.0));
}

/**
 * Initialize random number generator.
 */
void
random_init(void)
{
	FILE *f = NULL;
	SHA1Context ctx;
	struct stat buf;
	GTimeVal start, end;
	struct tms ticks;
	guint32 seed;
	guint8 digest[SHA1HashSize];
	guint32 sys[7];
	gint i;
	gint j;
	gboolean is_pipe = TRUE;

	/*
	 * Get random entropy from the system.
	 */

	g_get_current_time(&start);

	SHA1Reset(&ctx);

	/*
	 * If we have a /dev/urandom character device, use it.
	 * Otherwise, launch ps and grab its output.
	 */

	if (-1 != stat("/dev/urandom", &buf) && S_ISCHR(buf.st_mode)) {
		f = fopen("/dev/urandom", "r");
		is_pipe = FALSE;
	}
	else if (-1 != stat("/bin/ps", &buf))
		f = popen("/bin/ps -ef", "r");
	else if (-1 != stat("/usr/bin/ps", &buf))
		f = popen("/usr/bin/ps -ef", "r");
	else if (-1 != stat("/usr/ucb/ps", &buf))
		f = popen("/usr/ucb/ps aux", "r");

	if (f == NULL)
		g_warning("was unable to %s on your system",
			is_pipe ? "find the ps command" : "open /dev/urandom");
	else {
		/*
		 * Compute the SHA1 of the output (either ps or /dev/urandom).
		 */

		for (;;) {
			guint8 data[1024];
			gint r;
			gint len = is_pipe ? sizeof(data) : 128;

			r = fread(data, 1, len, f);
			if (r)
				SHA1Input(&ctx, data, r);
			if (r < len || !is_pipe)		/* Read once from /dev/urandom */
				break;
		}

		if (is_pipe)
			pclose(f);
		else
			fclose(f);
	}

	/*
	 * Add timing entropy.
	 */

	sys[0] = start.tv_sec;
	sys[1] = start.tv_usec;

	sys[2] = times(&ticks);
	sys[3] = ticks.tms_utime;
	sys[4] = ticks.tms_stime;

	g_get_current_time(&end);

	sys[5] = end.tv_sec - start.tv_sec;
	sys[6] = end.tv_usec - start.tv_usec;

	SHA1Input(&ctx, (guint8 *) sys, sizeof(sys));

	/*
	 * Reduce SHA1 to a single guint32.
	 */

	SHA1Result(&ctx, digest);

	for (seed = 0, i = j = 0; i < SHA1HashSize; i++) {
		guint32 b = digest[i];
		seed ^= b << (j << 3);
		j = (j + 1) & 0x3;
	}

	/*
	 * Finally, can initialize the random number generator.
	 */

	srandom(seed);
}

/**
 * Check whether buffer contains printable data, suitable for "%s" printing.
 * If not, consider dump_hex().
 */
gboolean is_printable(const gchar *buf, gint len)
{
	const guchar *p = (guchar *) buf;
	gint l = len;

	while (l--) {
		guchar c = *p++;
		if (!is_ascii_print(c))
			return FALSE;
	}

	return TRUE;
}

/**
 * Display header line for hex dumps
 */
inline static void
dump_hex_header(FILE *out)
{
	fprintf(out, "%s%s\n",
		"Offset  0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  ",
		"0123456789abcdef");
}

/**
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */
void
dump_hex(FILE *out, const gchar *title, gconstpointer data, gint b)
{
	int i, x, y, z, end;
	gchar *s = (gchar *) data;
	gchar temp[18];

	if ((b < 0) || (s == NULL)) {
		g_warning("dump_hex: value out of range [s=0x%lx, b=%d] for %s",
			(gulong) s, b, title);
		fflush(out);
		return;
	}

	fprintf(out, "----------------- %s:\n", title);

	if (b == 0)
		goto done;

	i = x = end = 0;
	for (;;) {
		if ((x & 0xff) == 0) {					/* x%256 == 0 */
			if (x > 0)
				fputc('\n', out);				/* break after 256 byte chunk */
			dump_hex_header(out);
		}
		if (i == 0)
			fprintf(out, "%5d  ", x & 0xffff);	/* offset, lowest 16 bits */
		if ((x & 0x07) == 0 && (x & 0x08))		/* x == 8 modulo 16 */
			fputc(' ', out);
		if (end) {
			fputs("   ", out);
			temp[i] = ' ';
		} else {
			z = s[x] & 0xff;
			fprintf(out, "%.2X ", z);
			if (!(isalnum(z) || ispunct(z)))
				z = '.';		/* no non printables */
			temp[i] = z;		/* save it for later ASCII print */
		}
		if (++i >= 16) {
			fputc(' ', out);
			for (y = 0; y < 16; y++) {	/* do 16 bytes ASCII */
				fputc(temp[y], out);
			}
			fputc('\n', out);
			if (end || ((x + 1) >= b))
				break;
			i = 0;
		}
		if (++x >= b)
			end = 1;
	}

done:
	fprintf(out, "----------------- (%d bytes).\n", b);
	fflush(out);
}

/**
 * Copies ``src'' to ``dst'', converting all upper-case characters to
 * lower-case. ``dst'' and ``src'' may point to the same object.
 *
 * NB: Bad name because it might clash with <string.h>.
 */
void
strlower(gchar *dst, const gchar *src)
{
	do {
		*dst++ = tolower((const guchar) *src);
	} while (*src++);
}

/**
 * ascii_strlower
 *
 * Copies ``src'' to ``dst'', converting all ASCII upper-case characters to
 * ASCII lower-case. ``dst'' and ``src'' may point to the same object.
 */
void
ascii_strlower(gchar *dst, const gchar *src)
{
	gint c;

	if (dst != src)
		do {
			c = (const guchar) *src++;
			*dst++ = is_ascii_upper(c) ? tolower(c) : c;
		} while (c != '\0');
	else
		do {
			c = (const guchar) *src++;
			if (is_ascii_upper(c))
				*dst = tolower(c);
			dst++;
		} while (c != '\0');
}


#ifndef HAS_STRCASESTR
/**
 * Same as strstr() but case-insensitive.
 */
gchar *
strcasestr(const gchar *haystack, const gchar *needle)
{
	guint32 delta[256];
	size_t nlen = strlen(needle);
	guint32 *pd = delta;
	size_t i;
	const gchar *n;
	guint32 haylen = strlen(haystack);
	const gchar *end = haystack + haylen;
	gchar *tp;

	/*
	 * Initialize Sunday's algorithm, lower-casing the needle.
	 */

	nlen++;		/* Avoid increasing within the loop */

	for (i = 0; i < 256; i++)
		*pd++ = nlen;

	nlen--;		/* Restore original pattern length */

	for (n = needle, i = 0; i < nlen; i++) {
		guchar c = *n++;
		delta[(guchar) tolower(c)] = nlen - i;
	}

	/*
	 * Now run Sunday's algorithm.
	 */

	for (tp = *(gchar **) &haystack; tp + nlen <= end; /* empty */) {
		const gchar *t;
		guchar c;

		for (n = needle, t = tp, i = 0; i < nlen; n++, t++, i++)
			if (tolower((guchar) *n) != tolower((guchar) *t))
				break;

		if (i == nlen)						/* Got a match! */
			return tp;

		c = *(tp + nlen);
		tp += delta[(guchar) tolower(c)];	/* Continue search there */
	}

	return NULL;		/* Not found */
}
#endif	/* HAS_STRCASESTR */

/**
 * Compare two strings up to the specified delimiters.
 */
static gint
strcmp_delimit_full(const gchar *a, const gchar *b,
	const gchar *delimit, gboolean case_sensitive)
{
	gboolean is_delimit[256];
	gint i;
	guchar *p;
	guchar *q;
	guchar c;
	guchar d;

	/*
	 * Initialize delimitors.
	 */

	is_delimit[0] = TRUE;
	for (i = 1; i < 256; i++)
		is_delimit[i] = FALSE;

	p = (guchar *) delimit;
	while ((c = *p++))
		is_delimit[case_sensitive ? c : tolower(c)] = TRUE;

	/*
	 * Compare strings up to the specified delimitors.
	 */

	p = (guchar *) a;
	q = (guchar *) b;

	for (;;) {
		c = *p++;
		d = *q++;
		if (case_sensitive) {
			c = tolower(c);
			d = tolower(d);
		}
		if (is_delimit[c])
			return is_delimit[d] ? 0 : -1;
		if (is_delimit[d])
			return +1;
		if (c != d)
			return c < d ? -1 : +1;
	}
}

/**
 * Compare two strings case-senstive up to the specified delimiters.
 */
gint
strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
{
	return strcmp_delimit_full(a, b, delimit, TRUE);
}

/**
 * Compare two strings case-insensitive up to the specified delimiters.
 */
gint
strcasecmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
{
	return strcmp_delimit_full(a, b, delimit, FALSE);
}

/**
 * Generate a new random GUID within given `xuid'.
 */
void
guid_random_fill(gchar *xuid)
{
	gint i;
	guint32 v;

	for (i = 0; i < 16; i++) {
		v =  random_value(~((guint32) 0U));
		xuid[i] = v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24);
	}
}


/**
 * Determine unique filename for `file' in `path', with optional trailing
 * extension `ext'.  If no `ext' is wanted, one must supply an empty string.
 *
 * Returns the chosen unique complete filename as a pointer which must be
 * freed.
 */
gchar *
unique_filename(const gchar *path, const gchar *file, const gchar *ext)
{
	static const gchar extra_bytes[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	const gchar *sep;
	gchar *filename;
	size_t size;
	size_t len;
	struct stat buf;
	gint i;
	gchar xuid[16];

	g_assert(path);
	g_assert(file);
	g_assert(ext);

	sep = strrchr(path, G_DIR_SEPARATOR);
	g_assert(sep);	/* This is supposed to an absolute path */
	/* Insert G_DIR_SEPARATOR_S only if necessary */
	sep = sep[1] != '\0' ? G_DIR_SEPARATOR_S : "";

	/* Use extra_bytes so we can easily append a few chars later */
	filename = GM_STRCONCAT_NULL(path, sep, file, ext, extra_bytes);
	size = strlen(filename);
	g_assert(size > sizeof extra_bytes);
	len = size - (sizeof extra_bytes - 1);
	g_assert(filename[len] == extra_bytes[0]);
	filename[len] = '\0';

	/*
	 * Append file and extension, then try to see whether this file exists.
	 */

	if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
		return filename;

	/*
	 * Looks like we need to make the filename more unique.  Append .00, then
	 * .01, etc... until .99.
	 */

	for (i = 0; i < 100; i++) {
		gm_snprintf(&filename[len], size - len, ".%02d%s", i, ext);
		if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
			return filename;
	}

	/*
	 * OK, no luck.  Try with a few random numbers then.
	 */

	for (i = 0; i < 100; i++) {
		guint32 rnum = random_value(~((guint32) 0));
		gm_snprintf(&filename[len], size - len, ".%x%s", rnum, ext);
		if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
			return filename;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	guid_random_fill(xuid);
	gm_snprintf(&filename[len], size - len, ".%s%s", guid_hex_str(xuid), ext);

	if (-1 == do_stat(filename, &buf))
		return filename;

	g_error("no luck with random number generator");	/* Should NOT happen */
	return NULL;
}

#define ESCAPE_CHAR		'\\'

/*
 * CHAR_IS_SAFE
 *
 * Nearly the same as isprint() but allows additional safe chars if !strict.
 */
#define CHAR_IS_SAFE(c, strict) \
	(isprint((c)) || (!(strict) && ((c) == ' ' || (c) == '\t' || (c) == '\n')))


/**
 * Escape all non-printable chars into the hexadecimal "\xhh" form.
 * Returns new escaped string, or the original string if no escaping occurred.
 */
gchar *
hex_escape(const gchar *name, gboolean strict)
{
	const gchar *p;
	gchar *q;
	guchar c;
	gint need_escape = 0;
	gchar *new;

	for (p = name, c = *p++; c; c = *p++)
		if (!CHAR_IS_SAFE(c, strict))
			need_escape++;

	if (need_escape == 0)
		return *(gchar **) &name; /* suppress compiler warning */

	new = g_malloc(p - name + 3 * need_escape);

	for (p = name, q = new, c = *p++; c; c = *p++) {
		if (CHAR_IS_SAFE(c, strict))
			*q++ = c;
		else {
			*q++ = ESCAPE_CHAR;
			*q++ = 'x';
			*q++ = hex_alphabet[c >> 4];
			*q++ = hex_alphabet[c & 0xf];
		}
	}
	*q = '\0';

	return new;
}

/**
 * Extracts the IP address into `ip' and the netmask into `netmask'.
 * Returns whether the supplied string represents a valid ip/mask combination.
 *
 * Accepted forms:
 * "a.b.c.d"			implies /32
 * "a.b.c.d/e"			whereas e [1..32]
 * "a.b.c.d/w.x.y.z"
 *
 * If the IP address or the netmask is zero, the function will return FALSE.
 */
gboolean
gchar_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask)
{
	const gchar *ep, *s = str;
	gint error;
	glong v;

	if (!gchar_to_ip_strict(s, ip, &ep))
		return FALSE;

	s = ep;

	if (*s == '\0') {
		*netmask = ~0;
		return TRUE;
	}

	if (*s++ != '/')
		return FALSE;

	if (!is_ascii_digit(*s))
		return FALSE;

	if (gchar_to_ip_strict(s, netmask, &ep))
		return 0 != *netmask;

	v = gm_atoul(s, (gchar **) &ep, &error);
	if (error || v < 1 || v > 32 || *ep != '\0')
		return FALSE;

	*netmask = ~0U << (32 - v);
	return TRUE;
}

/***
 *** System call wrapping with errno remapping.
 ***/

gint do_errno;

/**
 * Wrapper for the stat() system call.
 */
gint
do_stat(const gchar *path, struct stat *buf)
{
	gint ret;

	/*
	 * On my system, since I upgraded to libc6 2.3.2, I have system calls
	 * that fail with errno = 0.  I assume this is a multi-threading issue,
	 * since my kernel is SMP and gcc 3.3 requires a libpthread.  Or whatever,
	 * but it did not occur before with the same kernel and a previous libc6
	 * along with gcc 2.95.
	 *
	 * So... Assume that if stat() returns -1 and errno is 0, then it
	 * really means ENOENT.
	 *
	 *		--RAM, 27/10/2003
	 */

	ret = stat(path, buf);
	do_errno = errno;

	if (-1 == ret && 0 == do_errno) {
		g_warning("stat(\"%s\") returned -1 with errno = 0, assuming ENOENT",
			path);
		do_errno = errno = ENOENT;
	}

	/*
	 * Perform some remapping.  Stats through NFS may return EXDEV?
	 */

	switch (do_errno) {
	case EXDEV:
		g_warning("stat(\"%s\") failed with weird errno = %d (%s), "
			"assuming ENOENT", path, do_errno, g_strerror(do_errno));
		do_errno = errno = ENOENT;
		break;
	default:
		break;
	}

	if (-1 == ret && ENOENT != do_errno)
		g_warning("stat(\"%s\") returned -1 with errno = %d (%s)",
			path, do_errno, g_strerror(do_errno));

	return ret;
}

/**
 * Create new pathname from the concatenation of the dirname and the basename
 * of the file.  The resulting string can be freed when it is no longer needed.
 */
gchar *
make_pathname(const gchar *dir, const gchar *file)
{
	const gchar *sep;
	size_t l;

	g_assert(dir);
	g_assert(file);

	l = strlen(dir);
	if ((l > 0 && dir[l - 1] == G_DIR_SEPARATOR) || file[0] == G_DIR_SEPARATOR)
		 sep = "";
	else
		 sep = G_DIR_SEPARATOR_S;

	return GM_STRCONCAT_NULL(dir, sep, file);
}

/**
 * Determine stripped down path, removing SRC_PREFIX if present.
 * Returns pointer within supplied string.
 */
gchar *
short_filename(gchar *fullname)
{
	if (0 == strncmp(fullname, SRC_PREFIX, sizeof(SRC_PREFIX) - 1))
		return fullname + (sizeof(SRC_PREFIX) - 1);

	return fullname;
}

/**
 * Creates the given directory including sub-directories if necessary. The
 * path must be absolute.
 *
 * FIXME: This might fail with ``fancy'' file permissions. The directories
 *        should be created from leaf to root instead of vice-versa.
 *
 * @param dir the pathname of the directory to create.
 *
 * @return On success, zero is returned. On failure, -1 is returned and
 *         errno indicates the reason.
 */
gint
create_directory(const gchar *dir)
{
	static const mode_t mode =
		S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH; /* 0755 */
	gchar *path = NULL;
	size_t len, i;

	g_assert(dir != NULL);

	if (*dir != '/') {
		errno = EPERM;
		goto failure;
	}

	len = strlen(dir);
	path = g_malloc0(len + 1);
	memcpy(path, dir, len);
	path[len] = '\0';
	i = 0;

	do {
		const gchar *p;

		path[i++] = '/';
		p = strchr(&path[i], '/');
		if (p != NULL) {
			i = p - path;
			g_assert(i > 0 && i < len);
			g_assert(path[i] == '/');
			path[i] = '\0';
		} else {
			i = len;
			g_assert(path[i] == '\0');
		}

		g_message("stat(\"%s\")", path);
		if (!is_directory(path)) {
			g_message("stat() failed: %s", g_strerror(errno));
			if (errno != ENOENT)
				goto failure;

			g_message("mkdir(\"%s\")", path);
			if (mkdir(path, mode)) {
				g_message("mkdir() failed: %s", g_strerror(errno));
				goto failure;
			}
		}

	} while (i < len);

	G_FREE_NULL(path);
	return is_directory(dir) ? 0 : -1;

failure:

	G_FREE_NULL(path);
	return -1;
}

/**
 * Check whether file given by its dirname and its basename exists.
 */
gboolean
filepath_exists(const gchar *dir, const gchar *file)
{
	gchar *path;
	struct stat buf;
	gboolean exists = TRUE;

	path = make_pathname(dir, file);

	if (-1 == do_stat(path, &buf))
		exists = FALSE;

	G_FREE_NULL(path);

	return exists;
}

/**
 * Parses an unsigned 64-bit integer from an ASCII string.
 *
 * @param src
 *    The string to parse.
 * @param endptr
 *    May be NULL. Otherwise, it will be set to address of the first invalid
 *    character.
 * @param base
 *    The base system to be assumed e.g., 10 for decimal numbers 16 for
 *    hexadecimal numbers. The value MUST be 2..36.
 * @param errorptr
 *    Indicates a parse error if not zero. EINVAL means there was no
 *    number with respect to the used base at all. ERANGE means the
 *    number would exceed (2^64)-1.
 *
 * @return
 *    The parsed value or zero in case of an error. If zero is returned
 *    error must be checked to determine whether there was an error
 *    or whether the parsed value was zero.
 */
guint64
parse_uint64(const gchar *src, gchar **endptr, gint base, gint *errorptr)
{
	const gchar *p;
	guint64 v = 0;
	gint error = 0, c;

	g_assert(src != NULL);
	g_assert(errorptr != NULL);
	g_assert(base >= 2 && base <= 36);

	if (base < 2 || base > 36) {
		*errorptr = EINVAL;
		return 0;
	}

	for (p = src; (c = (guchar) *p) != '\0'; ++p) {
		guint64 d, w;

		if (!isascii(c))
			break;

		if (isdigit(c))
			d = c - '0';
		else if (isalpha(c)) {
			c = tolower(c);
			d = c - 'a' + 10;
		} else
			break;

		if (d >= (guint) base)
			break;

		w = v * base;
		if (w / base != v) {
			error = ERANGE;
			break;
		}
		v = w + d;
		if (v < w) {
			error = ERANGE;
			break;
		}
	}

	if (NULL != endptr)
		*endptr = (gchar *) p;

	if (!error && p == src)
		error = EINVAL;

	if (error)
		v = 0;
	*errorptr = error;

	return v;
}

/**
 * Find amount of common leading bits between two IP addresses
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
 * @return the previous signal handler or SIG_ERR on failure.
 *
 * TODO: Add Configure check for SA_INTERRUPT
 *
 */
signal_handler_t
set_signal(gint signo, signal_handler_t handler)
{
	struct sigaction sa, osa;

	g_assert(handler != SIG_ERR);

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = signo != SIGALRM ? SA_RESTART
#if defined(HAVE_SA_INTERRUPT) || defined(SA_INTERRUPT)
		: SA_INTERRUPT;
#else
		: 0;
#endif

	return sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
}

/* vi: set ts=4 sw=4 cindent: */
