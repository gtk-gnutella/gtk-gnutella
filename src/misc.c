
/* Misc functions */

#include <sys/stat.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>			/* For isalnum() and isspace() */

#include "gnutella.h"
#include "nodes.h"

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
	if ((ip & 0xff000000) == 0xa000000) {
		return TRUE;
	}

	/* 172.16.0.0 -- (172.16/12 prefix) */
	if ((ip & 0xfff00000) == 0xac100000) {
		return TRUE;
	}

	/* 192.168.0.0 -- (192.168/16 prefix) */
	if ((ip & 0xffff0000) == 0xc0a80000) {
		return TRUE;
	}

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
	static gchar b[64];

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
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */

void dump_hex(FILE *out, gchar *title, gchar *s, gint b)
{

	int i, x, y, z, end;
	char temp[18];

	if ((b < 1) || (s == NULL)) {		// check everything, this is for debug
		g_warning("dump_hex: value out of range\n");
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


/* vi: set ts=4: */
