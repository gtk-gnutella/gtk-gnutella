/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#include "common.h"

#include <sys/stat.h>

#include <stdlib.h>			/* For RAND_MAX */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>			/* For strlen() */
#include <ctype.h>			/* For isalnum() and isspace() */
#include <sys/times.h>		/* For times() */

RCSID("$Id$");

#if !defined(HAVE_SRANDOM) || !defined(HAVE_RANDOM)
#define srandom(x)	srand(x)
#define random(x)	rand(x)
#define RANDOM_MASK				0xffffffff
#define RANDOM_MAXV				RAND_MAX
#else
#define RANDOM_MASK				2147483647
#define RANDOM_MAXV				RANDOM_MASK
#endif

/*
 * is_string_ip
 *
 * Checks wether the given string contains a valid IP address. If the
 * string is NULL returns FALSE.
 */
gboolean is_string_ip(const gchar *s)
{
    if (s == NULL)
        return FALSE;

    return (gboolean) gchar_to_ip(s);
}

gboolean file_exists(gchar *f)
{
  	struct stat st;

    g_assert(f != NULL);
    return stat(f, &st) != -1;
}

gchar *ip_to_gchar(guint32 ip)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = g_htonl(ip);
	g_snprintf(a, sizeof(a), "%s", inet_ntoa(ia));
	return a;
}


gchar *ip_port_to_gchar(guint32 ip, guint16 port)
{
	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = g_htonl(ip);
	g_snprintf(a, sizeof(a), "%s:%u", inet_ntoa(ia), port);
	return a;
}

#if defined(_WIN32) || !defined(HAVE_INET_ATON)
/* 
 * Copied from icecast.
 * Fixed to returns 0 on failure, 1 on success --RAM, 12/01/2002.
 */
int inet_aton(const char *s, struct in_addr *a)
{
	int lsb, b2, b3, msb;

	/* Assumes host byte ordering is little endian, which is OK on Wintel */
	if (sscanf(s, "%d.%d.%d.%d", &lsb, &b2, &b3, &msb) < 4)
		return 0;

	a->s_addr = lsb + (b2 << 8) + (b3 << 16) + (msb << 24);
	return 1;
}
#endif


guint32 gchar_to_ip(const gchar * str)
{
	/* Returns 0 if str is not a valid IP */

	struct in_addr ia;
	gint r;
	r = inet_aton(str, &ia);
	if (r)
		return g_ntohl(ia.s_addr);
	return 0;
}

/*
 * gchar_to_ip_port
 *
 * Decompiles ip:port into ip and port.  Leading spaces are ignored.
 * Returns TRUE if it parsed correctly, FALSE otherwise.
 */
gboolean gchar_to_ip_port(gchar *str, guint32 *ip, guint16 *port)
{
	gint c;
	gint lsb, b2, b3, msb;
	gint iport;

	while ((c = (guchar)*str)) {		/* Skip leading spaces */
		if (!isspace(c))
			break;
		str++;
	}

	/* IP addresses are always written in big-endian format */
	if (sscanf(str, "%d.%d.%d.%d:%d", &msb, &b3, &b2, &lsb, &iport) < 5)
		return FALSE;

	if (iport < 0 || iport > 65535)
		return FALSE;
	
	*ip = lsb + (b2 << 8) + (b3 << 16) + (msb << 24);
	*port = iport;

	return TRUE;
}

guint32 host_to_ip(gchar * host)
{
	struct hostent *he = gethostbyname(host);
	if (he)
		return g_ntohl(*(guint32 *) (he->h_addr_list[0]));
	else {
		g_warning("cannot resolve %s:", host);
#if defined(HAVE_HERROR)
		herror("gethostbyname()");
#else
		g_warning("gethostbyname() failed!");
#endif
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
	static gchar name[256];

	if (-1 == gethostname(name, sizeof(name)))
		g_warning("gethostname() failed: %s", g_strerror(errno));

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
		/* 255.255.255.0 / 24 */
		((ip & (guint32) 0xFFFFFF00) == (guint32) 0xFFFFFF00))
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

/* Returns a number of bytes in a more readable form */

gchar *short_size(guint32 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		g_snprintf(b, sizeof(b), "%u Bytes", size);
	else if (size < 1048576)
		g_snprintf(b, sizeof(b), "%.1f KB", (float) size / 1024.0);
	else if (size < 1073741824)
		g_snprintf(b, sizeof(b), "%.1f MB", (float) size / 1048576.0);
	else
		g_snprintf(b, sizeof(b), "%.1f GB", (float) size / 1073741824.0);

	return b;
}

/* Returns a number of kbytes in a more readable form */

gchar *short_kb_size(guint32 size)
{
	static gchar b[SIZE_FIELD_MAX];

	if (size < 1024)
		g_snprintf(b, sizeof(b), "%u KB", size);
	else if (size < 1048576)
		g_snprintf(b, sizeof(b), "%.2f MB", (float) size / 1024.0);
	else if (size < 1073741824)
		g_snprintf(b, sizeof(b), "%.2f GB", (float) size / 1048576.0);
	else
		g_snprintf(b, sizeof(b), "%.2f TB", (float) size / 1073741824.0);

	return b;
}

/* Returns a number of bytes in a compact readable form */

gchar *compact_size(guint32 size)
{
	static gchar b[64];

	if (size < 1024)
		g_snprintf(b, sizeof(b), "%uB", size);
	else if (size < 1048576)
		g_snprintf(b, sizeof(b), "%.1fK", (float) size / 1024.0);
	else if (size < 1073741824)
		g_snprintf(b, sizeof(b), "%.1fM", (float) size / 1048576.0);
	else
		g_snprintf(b, sizeof(b), "%.1fG", (float) size / 1073741824.0);

	return b;
}

/* Return time spent in seconds in a consise short readable form */

gchar *short_time(guint32 s)
{
	static gchar b[SIZE_FIELD_MAX];

	if (s > 86400)
		g_snprintf(b, sizeof(b), "%ud %uh", s / 86400, (s % 86400) / 3600);
	else if (s > 3600)
		g_snprintf(b, sizeof(b), "%uh %um", s / 3600, (s % 3600) / 60);
	else if (s > 60)
		g_snprintf(b, sizeof(b), "%um %us", s / 60, s % 60);
	else
		g_snprintf(b, sizeof(b), "%us", s);

	return b;
}

/* Alternate time formatter for uptime*/

gchar *short_uptime(guint32 s)
{
	static gchar b[SIZE_FIELD_MAX];

	if (s > 86400) {
		guint32 d = s % 86400;
		g_snprintf(b, sizeof(b), "%ud %02u%c%02u",
			s / 86400, d / 3600, (s & 0x1) ? '.' : ':', (d % 3600) / 60);
	} else {
		guint32 h = s % 3600;
		g_snprintf(b, sizeof(b), "%02u:%02u:%02u", s / 3600, h / 60, h % 60);
	}

	return b;
}

/*
 * guid_hex_str
 *
 * Returns hexadecimal string representing given GUID.
 */
gchar *guid_hex_str(guchar *guid)
{
	static gchar buf[33];
	gint i;

	for (i = 0; i < 16; i++)
		g_snprintf(&buf[i*2], 3, "%02x", guid[i]);

	buf[32] = '\0';		/* Should not be necessary, but... */

	return buf;
}

/*
 * hex2dec
 *
 * Convert an hexadecimal char (0-9, A-F, a-f) into decimal.
 */
gint hex2dec(gchar c)
{
	return c >= '0' && c <= '9' ? c - '0'
		 : c >= 'a' && c <= 'f' ? c - 'a' + 10
		 : c - 'A' + 10;
}

/*
 * hex_to_guid
 *
 * Converts hexadecimal string into a GUID.
 */
void hex_to_guid(gchar *hexguid, guchar *guid)
{
	gint i;

	for (i = 0; i < 16; i++)
		guid[i] = (hex2dec(hexguid[i*2]) << 4) + hex2dec(hexguid[i*2+1]);
}

/*
 * sha1_base32
 *
 * Convert binary SHA1 into a base32 string.
 * Returns pointer to static data.
 */
gchar *sha1_base32(const guchar *sha1)
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
guchar *base32_sha1(const gchar *base32)
{
	static guchar digest_sha1[SHA1_RAW_SIZE];

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

static gchar* days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

static gchar* months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/*
 * date_to_rfc822_gchar
 *
 * Convert time to RFC-822 style date, into supplied string buffer.
 */
static void date_to_rfc822(time_t date, gchar *buf, gint len)
{
	struct tm *tm;
	struct tm gmt_tm;
	gint gmt_off;
	gchar sign;

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

	g_snprintf(buf, len, "%s, %02d %s %04d %02d:%02d:%02d %c%04d",
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

static void dump_hex_header(FILE *out)
{
	int i;
	char *cols = "0123456789abcdef";

	fputs("Offset ", out);
	for (i = 0; i < 16; i++)
		fprintf(out, " %c ", cols[i]);
	fprintf(out, " %s\n", cols);
}

/* 
 * dump_hex:
 *
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */

void dump_hex(FILE *out, gchar *title, gchar *s, gint b)
{

	int i, x, y, z, end;
	guchar temp[18];

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
	while (1) {
		if ((x & 0xff) == 0) {					// i%256 == 0
			if (x > 0)
				fputc('\n', out);				// break after 256 byte chunk
			dump_hex_header(out);
		}
		if (i == 0)
			fprintf(out, "%5d  ", x & 0xffff);	// offset, lowest 16 bits
		if (end) {
			fputs("   ", out);
			temp[i] = ' ';
		} else {
			z = s[x] & 0xff;
			fprintf(out, "%.2X ", z);
			if (!(isalnum(z) || ispunct(z)))
				z = '.';		// no non printables
			temp[i] = z;		// save it for later ASCII print
		}
		if (++i >= 16) {
			fputc(' ', out);
			for (y = 0; y < 16; y++) {	//do 16 bytes ASCII
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
void strlower(gchar *dst, gchar *src)
{
	do {
		*dst++ = tolower((guchar) *src);
	} while (*src++);
}

#ifndef HAVE_STRCASESTR
/*
 * strcasestr
 *
 * Same as strstr() but case-insensitive.
 */
guchar *strcasestr(const guchar *haystack, const guchar *needle)
{
	guint32 delta[256];
	guint32 nlen = strlen(needle);
	guint32 *pd = delta;
	gint i;
	guchar *n;
	guint32 haylen = strlen(haystack);
	const guchar *end = haystack + haylen;
	guchar *tp;

	/*
	 * Initialize Sunday's algorithm, lower-casing the needle.
	 */

	nlen++;		/* Avoid increasing within the loop */

	for (i = 0; i < 256; i++)
		*pd++ = nlen;

	nlen--;		/* Restore original pattern length */

	for (n = (guchar *) needle, i =0; i < nlen; i++) {
		guchar c = *n++;
		delta[(guint) tolower(c)] = nlen - i;
	}
	
	/*
	 * Now run Sunday's algorithm.
	 */

	for (tp = (guchar *) haystack; tp + nlen <= end; /* empty */) {
		guchar *t;
		guchar c;

		for (n = (guchar *) needle, t = tp, i = 0; i < nlen; n++, t++, i++)
			if (tolower(*n) != tolower(*t))
				break;

		if (i == nlen)						/* Got a match! */
			return tp;

		c = *(tp + nlen);
		tp += delta[(guint) tolower(c)];	/* Continue search there */
	}

	return NULL;		/* Not found */
}
#endif	/* HAVE_STRCASESTR */

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
 * Returns the chosen unique complete filename as a pointer to static data.
 */
gchar *unique_filename(gchar *path, gchar *file, gchar *ext)
{
	static gchar filename[2048];
	gint rw;
	struct stat buf;
	gint i;
	guchar xuid[16];

	/*
	 * This is the basename.
	 */

	rw = g_snprintf(filename, sizeof(filename), "%s%s%s",
		path, path[strlen(path) - 1] == '/' ? "" : "/", file);

	/*
	 * Append the extension, then try to see whether this file exists.
	 */

	g_snprintf(&filename[rw], sizeof(filename)-rw, "%s", ext);

	if (-1 == stat(filename, &buf))
		return filename;

	/*
	 * Looks like we need to make the filename more unique.  Append .00, then
	 * .01, etc... until .99.
	 */

	for (i = 0; i < 100; i++) {
		g_snprintf(&filename[rw], sizeof(filename)-rw, ".%02d%s", i, ext);
		if (-1 == stat(filename, &buf))
			return filename;
	}

	/*
	 * OK, no luck.  Try with a few random numbers then.
	 */

	for (i = 0; i < 100; i++) {
		guint32 rnum = random_value(RAND_MAX);
		g_snprintf(&filename[rw], sizeof(filename)-rw, ".%x%s", rnum, ext);
		if (-1 == stat(filename, &buf))
			return filename;
	}

	/*
	 * Bad luck.  Allocate a random GUID then.
	 */

	guid_random_fill(xuid);
	g_snprintf(&filename[rw], sizeof(filename)-rw, ".%s%s",
		guid_hex_str(xuid), ext);

	if (-1 == stat(filename, &buf))
		return filename;

	g_error("no luck with random number generator");	/* Should NOT happen */
	return NULL;
}

#define ESCAPE_CHAR		'\\'

static char *hex_alphabet = "0123456789ABCDEF";

/*
 * hex_escape
 *
 * Escape all non-printable chars into the hexadecimal \xhh form.
 * Returns new escaped string, or the original string if no escaping occurred.
 */
guchar *hex_escape(guchar *name)
{
	guchar *p;
	guchar *q;
	guchar c;
	gint need_escape = 0;
	guchar *new;

	for (p = name, c = *p++; c; c = *p++)
		if (!isprint(c))
			need_escape++;

	if (need_escape == 0)
		return name;

	new = g_malloc(p - name + 3 * need_escape);

	for (p = name, q = new, c = *p++; c; c = *p++) {
		if (isprint(c))
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

#ifdef USE_GTK2
gchar *locale_to_utf8(const gchar *str, gssize len)
{
	GError *error = NULL;
	const gchar *local_charset = NULL;
	gchar *ret;
	
	g_get_charset(&local_charset);
	ret = g_convert_with_fallback(
		str, len, "UTF-8", local_charset, NULL, NULL, NULL, &error);
    if (NULL != error) {
        g_warning("locale_to_utf8 failed: %s", error->message);
        g_clear_error(&error);
	}
	if (NULL == ret)
		ret = g_strdup("<Cannot convert to UTF-8>");
	g_assert(NULL != ret);
	return ret;
}
#endif
