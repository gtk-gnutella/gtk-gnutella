/*
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

#include <sys/stat.h>

#include <stdlib.h>			/* For RAND_MAX */
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>			/* For strlen() */
#include <ctype.h>			/* For isalnum() and isspace() */

#include "gnutella.h"
#include "nodes.h"
#include "misc.h"
#include "url.h"
#include "huge.h"
#include "base32.h"

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


guint32 gchar_to_ip(gchar * str)
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

	while ((c = *str)) {		/* Skip leading spaces */
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
		g_warning("gethostbyname() failed!\n");
#endif
	}

	return 0;
}

/*
 * str_chomp
 *
 * Remove final char of string if it is a "\n".
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

	if (str[len-1] == '\n') {
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
gboolean is_directory(gchar * path)
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

/* Returns the ip:port of a node */

gchar *node_ip(struct gnutella_node * n)
{
	/* Same as ip_port_to_gchar(), but need another static buffer to be able
	   to use both in same printf() line */

	static gchar a[32];
	struct in_addr ia;
	ia.s_addr = g_htonl(n->ip);
	g_snprintf(a, sizeof(a), "%s:%u", inet_ntoa(ia), n->port);
	return a;
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
 * date_to_rfc822_gchar
 *
 * Convert time to RFC-822 style date.
 * Returns pointer to static data.
 */
gchar *date_to_rfc822_gchar(time_t date)
{
	static gchar buf[80];
	struct tm *tm;

	tm = localtime(&date);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", tm);
	buf[sizeof(buf)-1] = '\0';		/* Be really sure */

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
	struct tm *tm;

	tm = localtime(&date);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", tm);
	buf[sizeof(buf)-1] = '\0';		/* Be really sure */

	return buf;
}

/*
 * random_value:
 *
 * Return random value between (0..max).
 */
guint32 random_value(guint32 max)
{
	return (guint32) ((max + 1.0) * rand() / (RAND_MAX + 1.0));
}

/* Dumps a gnutella message (debug) */

void message_dump(struct gnutella_node *n)
{
	gint32 size, ip, index, count, total;
	gint16 port, speed;

	printf("Node %s: ", node_ip(n));
	printf("Func 0x%.2x ", n->header.function);
	printf("TTL = %d ", n->header.ttl);
	printf("hops = %d ", n->header.hops);

	READ_GUINT32_LE(n->header.size, size);

	printf(" data = %u", size);

	if (n->header.function == GTA_MSG_SEARCH) {
		READ_GUINT16_LE(n->data, speed);
		printf(" Speed = %d Query = '%s'", speed, n->data + 2);
	} else if (n->header.function == GTA_MSG_INIT_RESPONSE) {
		READ_GUINT16_LE(n->data, port);
		READ_GUINT32_BE(n->data + 2, ip);
		READ_GUINT32_LE(n->data + 6, count);
		READ_GUINT32_LE(n->data + 10, total);

		printf(" Host = %s Port = %d Count = %d Total = %d",
			   ip_to_gchar(ip), port, count, total);
	} else if (n->header.function == GTA_MSG_PUSH_REQUEST) {
		READ_GUINT32_BE(n->data + 20, ip);
		READ_GUINT32_LE(n->data + 16, index);
		READ_GUINT32_LE(n->data + 24, port);

		printf(" Index = %d Host = %s Port = %d ", index, ip_to_gchar(ip),
			   port);
	}

	printf("\n");
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
	char temp[18];

	if ((b < 1) || (s == NULL)) {		// check everything, this is for debug
		g_warning("dump_hex: value out of range");
		fflush(out);
		return;
	}

	fprintf(out, "----------------- %s:\n", title);

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
	fprintf(out, "----------------- (%d bytes).\n", b);
	fflush(out);
}

/* copies str to dst, converting all upper-case characters to lower-case */
void strlower(gchar *dst, gchar *src)
{
	do {
		*dst++ = tolower(*src);
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
 * build_url_from_download:
 *
 * creates a url which points to a downloads (e.g. you can move this to a
 * browser and download the file there with this url
 */
gchar *build_url_from_download(struct download *d) 
{
    static gchar url_tmp[1024];
    gchar *buf = NULL;

    if (d == NULL)
        return NULL;
   
    buf = url_escape(d->file_name);

    g_snprintf(url_tmp, sizeof(url_tmp),
               "http://%s/get/%u/%s",
               ip_port_to_gchar(d->ip, d->port),
			   d->record_index, buf);

    /*
     * Since url_escape() creates a new string ONLY if
     * escaping is necessary, we have to check this and
     * free memory accordingly.
     *     --BLUE, 30/04/2002
     */

    if (buf != d->file_name) {
        g_free(buf);
    }
    
    return url_tmp;
}

/* vi: set ts=4: */
