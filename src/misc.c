
/* Misc functions */

#include <sys/stat.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gnutella.h"

gchar *ip_to_gchar(guint32 ip)
{
	struct in_addr ia;
	ia.s_addr = g_htonl(ip);
	return inet_ntoa(ia);
}


gchar *ip_port_to_gchar(guint32 ip, guint16 port)
{
	static gchar a[128];
	struct in_addr ia;
	ia.s_addr = g_htonl(ip);
	g_snprintf(a, sizeof(a), "%s:%u", inet_ntoa(ia), port);
	return a;
}

#if defined(_WIN32) || !defined(HAVE_INET_ATON)
/* 
 * Copied from icecast
 */
int 
inet_aton(const char *s, struct in_addr *a)
{
    int lsb, b2, b3, msb;
    if (sscanf(s, "%d.%d.%d.%d", &lsb, &b2, &b3, &msb) < 4)
                return -1;

    a->s_addr = lsb + (b2 << 8) + (b3 << 16) + (msb << 24);
                return 0;
}
#endif


guint32 gchar_to_ip(gchar *str)
{
	/* Returns 0 if str is not a valid IP */

	struct in_addr ia;
	gint r;
	r = inet_aton(str, &ia);
	if (r) return g_ntohl(ia.s_addr);
	return 0;
}

guint32 host_to_ip(gchar *host)
{
	struct hostent *he = gethostbyname(host);
	if (he) return g_ntohl(*(guint32 *) (he->h_addr_list[0]));
#if defined(HAVE_HERROR)
	else herror("gethostbyname()");
#else
        else g_warning("gethostbyname('%s') failed!\n",host);
#endif
 
	return 0;
}

/* Checks for RFC1918 private addresses; returns TRUE if is a private address. */
gboolean is_private_ip(guint32 ip)
{
    /* 10.0.0.0 -- (10/8 prefix) */
    if ((ip & 0xff000000) == 0xa000000)
    {
        return TRUE;
    }

    /* 172.16.0.0 -- (172.16/12 prefix) */
    if ((ip & 0xfff00000) == 0xac100000)
    {
        return TRUE;
    }

    /* 192.168.0.0 -- (192.168/16 prefix) */
    if ((ip & 0xffff0000) == 0xc0a80000)
    {
        return TRUE;
    }

    return FALSE;
}


/* Check whether path is a directory */
gboolean is_directory(gchar *path)
{
	struct stat st;
	if (stat(path, &st) == -1) return FALSE;
	return S_ISDIR(st.st_mode);
}

/* Returns a number of bytes in a more readable form */

gchar *short_size(guint32 size)
{
	static gchar b[256];

	if (size < 1024) g_snprintf(b, sizeof(b), "%u Bytes", size);
	else if (size < 1048576) g_snprintf(b, sizeof(b), "%.1f KB", (float) size / 1024.0);
	else if (size < 1073741824) g_snprintf(b, sizeof(b), "%.1f MB", (float) size / 1048576.0);
	else g_snprintf(b, sizeof(b), "%.1f GB", (float) size / 1073741824.0);

	return b;
}

/* Returns the ip:port of a node */

gchar *node_ip(struct gnutella_node *n)
{
	return ip_port_to_gchar(n->ip, n->port);
}

/* Dumps a gnutella message (debug) */

void message_dump(struct gnutella_node *n)
{
	gint32 size, ip, index, count, total;
	gint16 port, speed;

	printf("Node %s: ",    node_ip(n));
	printf("Func 0x%.2x ", n->header.function);
	printf("TTL = %d ",    n->header.ttl);
	printf("hops = %d ",   n->header.hops);

	READ_GUINT32_LE(n->header.size, size);

	printf(" data = %u", size);

	if (n->header.function == GTA_MSG_SEARCH)
	{
		READ_GUINT16_LE(n->data, speed);
		printf(" Speed = %d Query = '%s'", speed, n->data + 2);
	}
	else if (n->header.function == GTA_MSG_INIT_RESPONSE)
	{
		READ_GUINT16_LE(n->data, port);
		READ_GUINT32_BE(n->data + 2, ip);
		READ_GUINT32_LE(n->data + 6, count);
		READ_GUINT32_LE(n->data + 10, total);

		printf(" Host = %s Port = %d Count = %d Total = %d", ip_to_gchar(ip), port, count, total);
	}
	else if (n->header.function == GTA_MSG_PUSH_REQUEST)
	{
		READ_GUINT32_BE(n->data + 20, ip);
		READ_GUINT32_LE(n->data + 16, index);
		READ_GUINT32_LE(n->data + 24, port);

		printf(" Index = %d Host = %s Port = %d ", index, ip_to_gchar(ip), port);
	}

	printf("\n");
}

/* 
 * Displays hex & ascii lines to the terminal (for debug)
 * Displays the "title" then the characters in "s", # of bytes to print in "b"
 */

void debug_show_hex(gchar *title, gchar *s, gint b){

	int i,x,y,z,end;
	char temp[18];

	printf ("----------------- %s\n",title);

	if ((b < 1) || (s == NULL)) { // check everything, this is for debug
		printf ("ERROR - debug_show_hex, value out of range\n");
		fflush(stdout);
		return;
		}

	i = x = end = 0;
	while (1) {
		if (end) {
			printf("   ");
			temp[i] = ' ';
			}
		else {
			z = s[x] & 0x000000FF;
			printf("%.2X ",z);
			z = z & 0x0000007F; // hack off bit 7 for ASCII
      	if (z < 0x20) z = '.'; // no non printables
			if (z == 0x7F) z = '.'; // no DEL
			temp[i] = z ; // save it for later ASCII print
			}
		if (++i >= 16) {
			printf(" ");
			for (y=0; y<16; y++){ //do 16 bytes ASCII
				printf("%c",temp[y]);
				}
    		printf("\n");
			if (end || ((x + 1) >= b)) break;
			i = 0;
			}
		if (++x >= b) end = 1;
		}
	printf ("----------------- Bytes = %d\n",b);
	fflush(stdout);
}

/* vi: set ts=3: */
