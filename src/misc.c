/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Misc functions.
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


#include <sys/stat.h>

#include <stdlib.h>			/* For RAND_MAX */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>		/* For ntohl() */
#include <string.h>			/* For strlen() */
#include <ctype.h>			/* For isalnum() and isspace() */
#include <sys/times.h>		/* For times() */

#include "common.h"
#include "override.h"			/* Must be the last header included */

RCSID("$Id$");

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
const char hex_alphabet_lower[] = "0123456789abcdef";

#ifndef HAS_STRLCPY
size_t strlcpy(gchar *dst, const gchar *src, size_t dst_size)
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

/*
 * is_string_ip
 *
 * Checks whether the given string contains a valid IP address. If the
 * string is NULL returns FALSE.
 */
gboolean is_string_ip(const gchar *s)
{
    if (s == NULL)
        return FALSE;

    return 0 != gchar_to_ip(s);
}

gboolean file_exists(const gchar *f)
{
  	struct stat st;

    g_assert(f != NULL);
    return stat(f, &st) != -1;
}

gchar *ip_to_gchar(guint32 ip)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = htonl(ip);
	g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	return a;
}

gchar *ip2_to_gchar(guint32 ip)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = htonl(ip);
	g_strlcpy(a, inet_ntoa(ia), sizeof(a));
	return a;
}

gchar *ip_port_to_gchar(guint32 ip, guint16 port)
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

gchar *hostname_port_to_gchar(const gchar *hostname, guint16 port)
{
	static gchar a[300];

	gm_snprintf(a, sizeof(a), "%.255s:%u", hostname, port);
	return a;
}

#ifndef HAS_INET_ATON
/* 
 * Copied from icecast.
 * Fixed to returns 0 on failure, 1 on success --RAM, 12/01/2002.
 */
int inet_aton(const char *s, struct in_addr *addr)
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


guint32 gchar_to_ip(const gchar *str)
{
	/* Returns 0 if str is not a valid IP */

	struct in_addr ia;
	gint r;

	/* Skip leading spaces */
	while (isspace((const guchar) *str))
		str++;

	r = inet_aton(str, &ia);
	if (r)
		return ntohl(ia.s_addr);
	return 0;
}

/*
 * gchar_to_ip_port
 *
 * Decompiles ip:port into ip and port.  Leading spaces are ignored.
 * Returns TRUE if it parsed correctly, FALSE otherwise.
 */
gboolean gchar_to_ip_port(const gchar *str, guint32 *ip, guint16 *port)
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

guint32 host_to_ip(const gchar *host)
{
	struct hostent *he = gethostbyname(host);

	if (he) {
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
	} else {
#if defined(HAS_HSTRERROR)
		g_warning("cannot resolve \"%s\": %s", host, hstrerror(h_errno));
#elif defined(HAS_HERROR)
		g_warning("cannot resolve \"%s\":", host);
		herror("gethostbyname()");
#else
		g_warning("cannot resolve \"%s\": gethostbyname() failed!", host);
#endif /* defined(HAS_HSTRERROR) */
	}

	return 0;
}

/*
 * host_name
 *
 * Returns local host name, as pointer to static data.
 */
gchar *host_name(void)
{
	static gchar name[256 + 1];

	if (-1 == gethostname(name, sizeof(name)))
		g_warning("gethostname() failed: %s", g_strerror(errno));

	name[sizeof(name) - 1] = '\0';
	return name;
}

/*
 * host_is_valid
 *
 * Check whether host can be reached from the Internet.
 * We rule out IPs of private networks, plus some other invalid combinations.
 */
gboolean host_is_valid(guint32 ip, guint16 port)
{
	if ((!ip || !port) ||			/* IP == 0 || Port == 0 */
		(is_private_ip(ip)) ||
		/* 1.2.3.4 || 1.1.1.1 */
		(ip == (guint32) 0x01020304 || ip == (guint32) 0x01010101) ||
		/* 224..239.0.0 / 8 (multicast) */
		((ip & (guint32) 0xF0000000) == (guint32) 0xE0000000) ||
		/* 0.0.0.0 / 8 */
		((ip & (guint32) 0xFF000000) == (guint32) 0x00000000) ||
		/* 127.0.0.0 / 8 */
		((ip & (guint32) 0xFF000000) == (guint32) 0x7F000000) ||
		/* 192.0.2.0 -- (192.0.2/24 prefix) TEST-NET [RFC 3330] */
		((ip & 0xFFFFFF00) == 0xC0000200) ||
		/* 255.0.0.0 / 8 */
		((ip & (guint32) 0xFF000000) == (guint32) 0xFF000000))
			return FALSE;

	return TRUE;
}

/*
 * str_chomp
 *
 * Remove antepenultimate char of string if it is a "\r" followed by "\n".
 * Remove final char of string if it is a "\n" or "\r".
 * If len is 0, compute it.
 *
 * Returns new string length.
 */
gint str_chomp(gchar *str, gint len)
{
	if (len == 0)
		len = strlen(str);

	if (len == 0)
		return 0;

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

/*
 * Checks for RFC1918 private addresses; returns TRUE if is a private address.
 */
gboolean is_private_ip(guint32 ip)
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

/* Check whether path is a directory */
gboolean is_directory(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1)
		return FALSE;
	return S_ISDIR(st.st_mode);
}

/* Check whether path points to a regular file */
gboolean is_regular(const gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1) {
		return FALSE;
	}
	return S_ISREG(st.st_mode);
}

/* Check whether path is a symbolic link */
gboolean is_symlink(const gchar *path)
{
	struct stat st;
	if (-1 == lstat(path, &st))
		return FALSE;
	return (st.st_mode & S_IFMT) == S_IFLNK;
}

/* Returns a number of bytes in a more readable form */

gchar *short_size(guint32 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%u Bytes", size);
	else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.1f KB", (float) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.1f MB", (float) size / 1048576.0);
	else
		gm_snprintf(b, sizeof(b), "%.1f GB", (float) size / 1073741824.0);

	return b;
}

gchar *short_size64(guint64 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%u Bytes", (guint32) size);
	else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.1f KB", (float) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.1f MB", (float) size / 1048576.0);
	else if ((size >> 10) < 1073741824)
		gm_snprintf(b, sizeof(b), "%.1f GB", (float) size / 1073741824.0);
	else
		gm_snprintf(b, sizeof(b), "%.1f TB",
			(float) (size >> 10) / 1073741824.0);

	return b;
}

/* Returns a number of kbytes in a more readable form */

gchar *short_kb_size(guint32 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%u KB", size);
	else if (size < 1048576)
		gm_snprintf(b, sizeof(b), "%.2f MB", (float) size / 1024.0);
	else if (size < 1073741824)
		gm_snprintf(b, sizeof(b), "%.2f GB", (float) size / 1048576.0);
	else
		gm_snprintf(b, sizeof(b), "%.2f TB", (float) size / 1073741824.0);

	return b;
}

/* Returns a number of bytes in a compact readable form */

gchar *compact_size(guint32 size)
{
	static gchar b[64];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%uB", size);
	else if (size < 1048576) {
		if (size & 0x3ff)
			gm_snprintf(b, sizeof(b), "%.1fK", (float) size / 1024.0);
		else
			gm_snprintf(b, sizeof(b), "%dK", size >> 10);
	} else if (size < 1073741824)
		if (size & 0xfffff)
			gm_snprintf(b, sizeof(b), "%.1fM", (float) size / 1048576.0);
		else
			gm_snprintf(b, sizeof(b), "%dM", size >> 20);
	else {
		if (size & 0x3fffffff)
			gm_snprintf(b, sizeof(b), "%.1fG", (float) size / 1073741824.0);
		else
			gm_snprintf(b, sizeof(b), "%dG", size >> 30);
	}

	return b;
}

/* Returns a number of Kbytes in a compact readable form */

gchar *compact_kb_size(guint32 size)
{
	static gchar b[64];

	if (size < 1024)
		gm_snprintf(b, sizeof(b), "%uK", size);
	else if (size < 1048576) {
		if (size & 0x3ff)
			gm_snprintf(b, sizeof(b), "%.1fM", (float) size / 1024.0);
		else
			gm_snprintf(b, sizeof(b), "%dM", size >> 10);
	} else if (size < 1073741824)
		if (size & 0xfffff)
			gm_snprintf(b, sizeof(b), "%.1fG", (float) size / 1048576.0);
		else
			gm_snprintf(b, sizeof(b), "%dG", size >> 20);
	else {
		if (size & 0x3fffffff)
			gm_snprintf(b, sizeof(b), "%.1fT", (float) size / 1073741824.0);
		else
			gm_snprintf(b, sizeof(b), "%dT", size >> 30);
	}

	return b;
}

/* Return time spent in seconds in a consise short readable form */

gchar *short_time(time_t t)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = (gint) MAX(t, 0);

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

/* Alternate time formatter for uptime*/

gchar *short_uptime(time_t uptime)
{
	static gchar b[SIZE_FIELD_MAX];
	gint s = (gint) MAX(uptime, 0);

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

/*
 * guid_hex_str
 *
 * Returns hexadecimal string representing given GUID.
 */
gchar *guid_hex_str(const gchar *guid)
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

/*
 * hex2dec
 *
 * Convert an hexadecimal char (0-9, A-F, a-f) into decimal.
 */
inline gint hex2dec(guchar c)
{
	return c >= '0' && c <= '9' ? c - '0'
		 : c >= 'a' && c <= 'f' ? c - 'a' + 10
		 : c >= 'A' && c <= 'F' ? c - 'A' + 10
		 : -1;
}

/*
 * hex_to_guid
 *
 * Converts hexadecimal string into a GUID.
 * Returns true if OK.
 */
gboolean hex_to_guid(const gchar *hexguid, gchar *guid)
{
	gulong i;

	for (i = 0; i < 16; i++) {
		gint a = hex2dec((guchar) hexguid[i << 1]);
		gint b = hex2dec((guchar) hexguid[(i << 1) + 1]);

		if (a < 0 || b < 0)
			return FALSE;

		guid[i] = (a << 4) + b;
	}

	return TRUE;
}

/*
 * guid_base32_str
 *
 * Converts GUID into its base32 representation, without the trailing padding.
 * Returns pointer to static data.
 */
gchar *guid_base32_str(const gchar *guid)
{
	static gchar guid_b32[26 + 1];		/* 26 chars needed for a GUID */

	base32_encode_str_into(guid, 16, guid_b32, sizeof(guid_b32), FALSE);

	return guid_b32;
}

/*
 * base32_to_guid
 *
 * Decode the base32 representation of a GUID.
 * Returns pointer to static data, or NULL if the input was not valid base32.
 */
gchar *base32_to_guid(const gchar *base32)
{
	static gchar guid[20];	/* Needs 20 chars to decode, last 4 will be 0 */

	if (0 == base32_decode_into(base32, 26, guid, sizeof(guid)))
		return NULL;

	g_assert(guid[16] == '\0' && guid[17] == '\0' &&
		guid[18] == '\0' && guid[19] == '\0');

	return guid;
}

/*
 * sha1_base32
 *
 * Convert binary SHA1 into a base32 string.
 * Returns pointer to static data.
 */
gchar *sha1_base32(const gchar *sha1)
{
	static gchar digest_b32[SHA1_BASE32_SIZE + 1];

	base32_encode_into(sha1, SHA1_RAW_SIZE, digest_b32, sizeof(digest_b32));
	digest_b32[SHA1_BASE32_SIZE] = '\0';

	return digest_b32;
}

/*
 * base32_sha1
 *
 * Convert base32 string into binary SHA1.
 * Returns pointer to static data.
 */
gchar *base32_sha1(const gchar *base32)
{
	static gchar digest_sha1[SHA1_RAW_SIZE];

	base32_decode_into(base32, SHA1_BASE32_SIZE,
		digest_sha1, sizeof(digest_sha1));

	return digest_sha1;
}

/*
 * date_to_iso_gchar
 *
 * Convert time to ISO style date, e.g. "2002-06-09T14:54:42Z".
 * Returns pointer to static data.
 */
gchar *date_to_iso_gchar(time_t date)
{
	static gchar buf[80];
	struct tm *tm;

	tm = gmtime(&date);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	buf[sizeof(buf)-1] = '\0';		/* Be really sure */

	return buf;
}


/*
 * tm_diff
 *
 * Compute the difference in seconds between two tm structs (a - b).
 * Comes from glibc-2.2.5.
 */
static gint tm_diff(const struct tm *a, const struct tm * b)
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

/*
 * date_to_rfc822
 *
 * Convert time to RFC-822 style date, into supplied string buffer.
 */
static void date_to_rfc822(time_t date, gchar *buf, gint len)
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

/*
 * date_to_rfc822_gchar
 *
 * Convert time to RFC-822 style date.
 * Returns pointer to static data.
 */
gchar *date_to_rfc822_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/*
 * date_to_rfc822_gchar2
 *
 * Same as date_to_rfc822_gchar(), to be able to use the two in the same
 * printf() line.
 */
gchar *date_to_rfc822_gchar2(time_t date)
{
	static gchar buf[80];

	date_to_rfc822(date, buf, sizeof(buf));
	return buf;
}

/*
 * date_to_rfc1123
 *
 * Convert time to RFC-1123 style date, into supplied string buffer.
 */
static void date_to_rfc1123(time_t date, gchar *buf, gint len)
{
	const struct tm *tm;

	g_assert(len > 0);
	tm = gmtime(&date);
	gm_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d GMT",
		days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon], tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/*
 * date_to_rfc1123_gchar
 *
 * Convert time to RFC-1123 style date.
 * Returns pointer to static data.
 */
gchar *date_to_rfc1123_gchar(time_t date)
{
	static gchar buf[80];

	date_to_rfc1123(date, buf, sizeof(buf));
	return buf;
}


/*
 * is_pow2
 *
 * Determine whether value is a power of 2.
 */
gboolean is_pow2(guint32 value)
{
	guint32 mask;
	gint count;

	/*
	 * Make sure that binary representation contains only ONE single 1.
	 * We don't count 0 as being a power of 2.
	 */

	for (mask = 0x80000000, count = 0; mask && count <= 1; mask >>= 1) {
		if (value & mask)
			count++;
	}

	return 1 == count;
}

/*
 * next_pow2
 *
 * Returns the closest power of two greater or equal to `n'.
 */
guint32 next_pow2(guint32 n)
{
	guint p = 0;
	guint32 r = n;

	while (r >>= 1)			/* Will find largest bit set */
		p++;

	r = 1 << p;
	
	return r == n ? n : r << 1;
}

/*
 * highest_bit_set
 *
 * Determine the highest bit set in `n', -1 if value was 0.
 */
gint highest_bit_set(guint32 n)
{
	gint h = 0;
	guint32 r = n;

	if (r == 0)
		return -1;
	
	while (r >>= 1)			/* Will find largest bit set */
		h++;

	return h;
}

/*
 * random_value:
 *
 * Return random value between (0..max).
 */
guint32 random_value(guint32 max)
{
	return (guint32)
		((max + 1.0) * (random() & RANDOM_MASK) / (RANDOM_MAXV + 1.0));
}

/* Display header line for hex dumps */

inline static void dump_hex_header(FILE *out)
{
	fprintf(out, "%s%s\n",
		"Offset  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  ",
		hex_alphabet_lower);
}

/* 
 * dump_hex:
 *
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */

void dump_hex(FILE *out, const gchar *title, gconstpointer data, gint b)
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
		if ((x & 0xff) == 0) {					/* i%256 == 0 */
			if (x > 0)
				fputc('\n', out);				/* break after 256 byte chunk */
			dump_hex_header(out);
		}
		if (i == 0)
			fprintf(out, "%5d  ", x & 0xffff);	/* offset, lowest 16 bits */
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

/* copies str to dst, converting all upper-case characters to lower-case */
void strlower(gchar *dst, const gchar *src)
{
	do {
		*dst++ = tolower((const guchar) *src);
	} while (*src++);
}

#ifndef HAS_STRCASESTR
/*
 * strcasestr
 *
 * Same as strstr() but case-insensitive.
 */
gchar *strcasestr(const gchar *haystack, const gchar *needle)
{
	guint32 delta[256];
	guint32 nlen = strlen(needle);
	guint32 *pd = delta;
	gint i;
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

	for (n = needle, i =0; i < nlen; i++) {
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

/*
 * strcmp_delimit
 *
 * Compare two strings up to the specified delimiters.
 */
gint strcmp_delimit(const gchar *a, const gchar *b, const gchar *delimit)
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
		is_delimit[c] = TRUE;

	/*
	 * Compare strings up to the specified delimitors.
	 */

	p = (guchar *) a;
	q = (guchar *) b;

	for (;;) {
		c = *p++;
		d = *q++;
		if (is_delimit[c])
			return is_delimit[d] ? 0 : -1;
		if (is_delimit[d])
			return +1;
		if (c != d)
			return c < d ? -1 : +1;
	}
}

/*
 * random_init
 *
 * Initialize random number generator.
 */
void random_init(void)
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

/*
 * unique_filemame
 *
 * Determine unique filename for `file' in `path', with optional trailing
 * extension `ext'.  If no `ext' is wanted, one must supply an empty string.
 *
 * Returns the chosen unique complete filename as a pointer which must be
 * freed.
 */
gchar *unique_filename(const gchar *path, const gchar *file, const gchar *ext)
{
	gchar *filename;
	size_t size;
	size_t len;
	struct stat buf;
	gint i;
	gchar xuid[16];
	const gchar *extra_bytes = "0123456789abcdefghijklmnopqrstuvwxyz";

	/* Use extra_bytes so we can easily append a few chars later */
	filename = g_strdup_printf("%s/%s%s%s", path, file, ext, extra_bytes);
	size = strlen(filename);
	len = strlen(extra_bytes);
	filename[size - len] = '\0';
	len = size - len;

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
		guint32 rnum = random_value(RAND_MAX);
		gm_snprintf(&filename[len], size - len, ".%x%s", rnum, ext);
		if (-1 == do_stat(filename, &buf) && ENOENT == do_errno)
			return filename;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	guid_random_fill(xuid);
	gm_snprintf(&filename[len], size - len, ".%s%s",
		guid_hex_str(xuid), ext);

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


/*
 * hex_escape
 *
 * Escape all non-printable chars into the hexadecimal \xhh form.
 * Returns new escaped string, or the original string if no escaping occurred.
 */
gchar *hex_escape(const gchar *name, gboolean strict)
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

/*
 * gchar_to_ip_and_mask:
 *
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
gboolean gchar_to_ip_and_mask(const gchar *str, guint32 *ip, guint32 *netmask)
{
	const gchar *mask_str = NULL;
	gint error;
	gulong b;
	static gchar buf[64];

	if ((mask_str = strchr(str, '/')) != NULL) {
		size_t len = mask_str - str;

		if (len >= sizeof(buf))
			return FALSE;
		memcpy(buf, str, len);
		buf[len] = '\0';
		mask_str++;
		str = &buf[0];
	}

	*ip = gchar_to_ip(str);		/* Assume numeric IP */
	if (*ip == 0)				/* Bad luck */
		*ip = host_to_ip(str);
	if (!*ip)
		return FALSE;

	if (NULL == mask_str) {
		*netmask = ~0;
		return TRUE;
	}		

	if (strchr(mask_str, '.')) {
		*netmask = gchar_to_ip(mask_str);
		if (~0 != *netmask) {
			if (*netmask != ~((1 << (highest_bit_set(~*netmask) + 1)) - 1))
				return FALSE;
		}
		return 0 != *netmask;
	}

	b = gm_atoul(mask_str, NULL, &error);
	if (error || b == 0 || b > 32)
		return FALSE;
		
	if (32 == *netmask) {
		*netmask = ~0;
		return TRUE;
	}

	*netmask = ~(~0 >> b);
	return TRUE;
}

/***
 *** System call wrapping with errno remapping.
 ***/

gint do_errno;

/*
 * do_stat
 *
 * Wrapper for the stat() system call.
 */
gint do_stat(const gchar *path, struct stat *buf)
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

/* vi: set ts=4: */
