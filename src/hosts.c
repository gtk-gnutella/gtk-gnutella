
#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "interface.h"

GSList *sl_catched_hosts = (GSList *) NULL;
GHashTable *ht_catched_hosts = (GHashTable *) NULL;	/* Same, as H table */

GSList *ping_reqs = (GSList *) NULL;
guint32 n_ping_reqs = 0;
struct ping_req *pr_ref = (struct ping_req *) NULL;

gchar h_tmp[4096];

gint hosts_idle_func = 0;

#define MAX_PING_REQS 64	/* How many ping requests do we have to remember */

static void ping_reqs_clear(void);

/* Hosts ------------------------------------------------------------------------------------------ */

void host_init(void)
{
	ht_catched_hosts = g_hash_table_new(g_str_hash, g_str_equal);
}

#define BUILD_IP_PORT_KEY(b,i,p) do {          \
	g_snprintf(b, sizeof(b)-1, "%x:%x", i, p); \
} while (0)


static void host_ht_add(guint32 ip, guint16 port)
{
	/* Add (ip, port) tuple to the ht_catched_hosts table */

	char buf[64];
	
	BUILD_IP_PORT_KEY(buf, ip, port);
	if (g_hash_table_lookup(ht_catched_hosts, (gconstpointer) buf)) {
		g_warning("Attempt to add %s twice to caught host list",
			ip_port_to_gchar(ip, port));
		return;
	}

	g_hash_table_insert(ht_catched_hosts, g_strdup(buf), (gpointer) 1);
}

static void host_ht_remove(guint32 ip, guint16 port)
{
	/* Remove (ip, port) tuple from the ht_catched_hosts table */

	gpointer key, val;
	char buf[64];

	BUILD_IP_PORT_KEY(buf, ip, port);
	if (!g_hash_table_lookup_extended(ht_catched_hosts, buf, &key, &val)) {
		g_warning("Attempt to remove missing %s from caught host list",
			ip_port_to_gchar(ip, port));
		return;
	}

	g_hash_table_remove(ht_catched_hosts, buf);
	g_free(key);
}

gboolean find_host(guint32 ip, guint16 port)
{
	char buf[64];
	GSList *l;

	/* Check our local ip */

	if (ip == local_ip || (force_local_ip && ip == forced_local_ip)) return TRUE;

	/* Check the nodes -- this is a small list, OK to traverse */

	for (l = sl_nodes; l; l = l->next)
	{
		if (((struct gnutella_node *) l->data)->ip == ip)
		{
			if (((struct gnutella_node *) l->data)->socket->direction == GTA_CONNECTION_INCOMING) return TRUE;
			else if (((struct gnutella_node *) l->data)->port == port) return TRUE;
		}
	}

	/* Check the hosts -- large list, use hash table --RAM */

	BUILD_IP_PORT_KEY(buf, ip, port);
	return g_hash_table_lookup(ht_catched_hosts, buf) ? TRUE : FALSE;
}

void host_remove(struct gnutella_host *h, gboolean from_clist_too)
{
	gint row;

	if (from_clist_too)
	{
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_host_catcher), (gpointer) h);
		gtk_clist_remove(GTK_CLIST(clist_host_catcher), row);
	}

	sl_catched_hosts = g_slist_remove(sl_catched_hosts, h);
	host_ht_remove(h->ip, h->port);

	if (!sl_catched_hosts) gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);

	g_free(h);
}

static int host_ht_free(gpointer key, gpointer value, gpointer usr)
{
	g_free(key);
	return TRUE;		/* Remove the key */
}

gboolean check_valid_host(guint32 ip, guint16 port)
{
	if (!ip || !port) return FALSE;									/* IP == 0 || Port == 0					*/

	if (ip == (guint32) 0x01020304 || ip == (guint32) 0x01010101) return FALSE;	/* IP == 1.2.3.4 || IP == 1.1.1.1 	*/
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x00000000) return FALSE;			/* IP == 0.0.0.0 / 8					 	*/
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x7F000000) return FALSE;			/* IP == 127.0.0.0 / 8					*/
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x0A000000) return FALSE;			/* IP == 10.0.0.0 / 8					*/
	if ((ip & (guint32) 0xFFF00000) == (guint32) 0xAC100000) return FALSE; 		/* IP == 172.16.0.0 / 12				*/
	if ((ip & (guint32) 0xFFFF0000) == (guint32) 0xC0A80000) return FALSE;			/* IP == 192.168.0.0 / 16				*/

	return TRUE;
}

void host_add(struct gnutella_node *n, guint32 t_ip, guint16 t_port, gboolean connect)
{
	static time_t last_time = 0;

	struct gnutella_host *host;
	gchar *titles[2];
	gint row;
	guint32 ip;
	guint16 port;

	if (n)
	{
		READ_GUINT32_BE(n->data + 2, ip);
		READ_GUINT16_LE(n->data, port);
	}
	else
	{
		ip = t_ip;
		port = t_port;
	}

	if (!check_valid_host(ip, port)) return;	/* Is host valid? */

	if (find_host(ip, port)) return; 	/* Do we have this host? */

	/* Okay, we got a new host */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->port        = port;
	host->ip          = ip;

	if (n)
	{
		/* XXX These fields are unused, don't read them --RAM, 11/09/2001 */
		// READ_GUINT32_LE(n->data + 6,  host->files_count);
		// READ_GUINT32_LE(n->data + 10, host->kbytes_count);
	}

	titles[0] = ip_port_to_gchar(ip, port);

	/*
	 * If we are under the number of connections wanted, we add this host
	 * to the connection list.
	 *
	 * Note: we're not using `nodes_in_list' for the comparison with
	 * `up_connections' but connected_nodes().  The node_add() routine will
	 * compare `nodes_in_list' with `max_connections' to ensure we don't
	 * launch too many connections, that, if they all succeeded, would bring
	 * us above the configured maximum.  However, during bootstrap, this
	 * lets us issue connection requests faster.
	 *		--RAM, 08/09/2001
	 */

	if (
		connect &&
		connected_nodes() < up_connections &&
		(time((time_t *) NULL) - last_time) > 2
	) {
		node_add(NULL, host->ip, host->port);
		time(&last_time);
	}

	/* Add the host to the hosts catcher list */

	row = gtk_clist_append(GTK_CLIST(clist_host_catcher), titles);
	gtk_clist_set_row_data(GTK_CLIST(clist_host_catcher), row, (gpointer) host);

	if (!sl_catched_hosts) gtk_widget_set_sensitive(button_host_catcher_clear, TRUE);

	sl_catched_hosts = g_slist_prepend(sl_catched_hosts, host);
	host_ht_add(host->ip, host->port);
}

/* Hosts text files ------------------------------------------------------------------------------- */

FILE *hosts_r_file = (FILE *) NULL;

gint hosts_reading_func(gpointer data)
{
	gchar *s;
	guint16 port;

	if (fgets(h_tmp, sizeof(h_tmp)-1, hosts_r_file))	/* \0 appended */
	{
		s = h_tmp;
		while (*s && *s != ':') s++;
		port = (*s)? atoi(s + 1) : 6346;
		*s++ = 0;
		host_add(NULL, gchar_to_ip(h_tmp), port, FALSE);

		return TRUE;
	}

	fclose(hosts_r_file);

	hosts_r_file = (FILE *) NULL;

	hosts_idle_func = 0;

	gtk_clist_thaw(GTK_CLIST(clist_host_catcher));

	gui_set_status(NULL);

	return FALSE;
}

void hosts_read_from_file(gchar *path, gboolean quiet)
{
	/* Loads 'catched' hosts from a text file */

	hosts_r_file = fopen(path, "r");

	if (!hosts_r_file)
	{
		if (!quiet) g_warning("Unable to open file %s (%s)\n", path, g_strerror(errno));
		return;
	}

	gtk_clist_freeze(GTK_CLIST(clist_host_catcher));

	hosts_idle_func = gtk_idle_add(hosts_reading_func, (gpointer) NULL);

	gui_set_status("Reading catched hosts file...");
}

void hosts_write_to_file(gchar *path)
{
	/* Saves the currently catched hosts to a file */

	FILE *f;
	GSList *l;

	f = fopen(path, "w");

	if (!f)
	{
		g_warning("Unable to open output file %s (%s)\n", path, g_strerror(errno));
		return;
	}

	for (l = sl_catched_hosts; l; l = l->next)
		fprintf(f, "%s\n", ip_port_to_gchar(((struct gnutella_host *) l->data)->ip, ((struct gnutella_host *) l->data)->port));

	fclose(f);
}

/* gnutellaNet stats ------------------------------------------------------------------------------ */

/* Registers a new ping request */

void register_ping_req(guchar *muid)
{
	struct ping_req *p;

	if (n_ping_reqs >= MAX_PING_REQS)
	{
		GSList *l = g_slist_last(ping_reqs);
		p = (struct ping_req *) l->data;
		ping_reqs = g_slist_remove_link(ping_reqs, l);
		g_slist_free_1(l);
	}
	else
	{
		p = (struct ping_req *) g_malloc(sizeof(struct ping_req));
	}

	memcpy(p->muid, muid, 16);

	gettimeofday(&(p->tv), (struct timezone *) NULL);

	p->delay = p->hosts = p->files = p->kbytes = 0;

	ping_reqs = g_slist_prepend(ping_reqs, p);
}

/* Adds a reply to the stats */

void ping_stats_add(struct gnutella_node *n)
{
	GSList *l;
	struct gnutella_init_response *r;
	struct ping_req *p;
	struct timeval tv;
	guint32 v;

	/* First look for a matching req in the ping reqs list */

	for (l = ping_reqs; l; l = l->next)
		if (!memcmp(((struct ping_req *) l->data)->muid, n->header.muid, 16)) break;

	if (!l) return;	/* Found no request for this reply */

	r = (struct gnutella_init_response *) n->data;
	p = (struct ping_req *) l->data;

	p->hosts++;

	READ_GUINT32_LE(r->files_count, v); p->files += v;
	READ_GUINT32_LE(r->kbytes_count, v); p->kbytes += v;

	gettimeofday(&tv, (struct timezone *) NULL);

	p->delay += (tv.tv_sec - p->tv.tv_sec) * 1000 + (tv.tv_usec / 1000 - p->tv.tv_usec / 1000);

	if (!pr_ref || (p->hosts > pr_ref->hosts)) pr_ref = p;
}

/* Update the stats */

static void ping_reqs_clear(void)
{
	GSList *l;

	if ((l = ping_reqs)) {
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(ping_reqs);
		ping_reqs = NULL;
	}

	n_ping_reqs = 0;
}

void ping_stats_update(void)
{
	ping_reqs_clear();
	pr_ref = NULL;

	gui_update_stats();

	send_init(NULL);
}

/* Messages --------------------------------------------------------------------------------------- */

/* Sends an init request */

void send_init(struct gnutella_node *n)
{
	static struct gnutella_msg_init m;

	message_set_muid(&(m.header));

	m.header.function = GTA_MSG_INIT;
	m.header.ttl      = my_ttl;
	m.header.hops     = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	message_add(m.header.muid, GTA_MSG_INIT, NULL);

	if (n) sendto_one(n, (guchar *) &m, NULL, sizeof(struct gnutella_msg_init));
	else   sendto_all((guchar *) &m, NULL, sizeof(struct gnutella_msg_init));

	register_ping_req(m.header.muid);
}

/* Replies to an init request */

void reply_init(struct gnutella_node *n)
{	
	static struct gnutella_msg_init_response r;

	if (!force_local_ip && !local_ip) return; /* If we don't know yet your local IP, we can't reply */

	WRITE_GUINT16_LE(listen_port,   r.response.host_port);
	WRITE_GUINT32_BE((force_local_ip)? forced_local_ip : local_ip, r.response.host_ip);
	WRITE_GUINT32_LE(files_scanned, r.response.files_count);
	WRITE_GUINT32_LE(kbytes_scanned, r.response.kbytes_count);

	r.header.function = GTA_MSG_INIT_RESPONSE;
	r.header.ttl      = my_ttl;
	r.header.hops     = 0;

	memcpy(&r.header.muid, n->header.muid, 16);

	WRITE_GUINT32_LE(sizeof(struct gnutella_init_response), r.header.size);

	sendto_one(n, (guchar *) &r, NULL, sizeof(struct gnutella_msg_init_response));
}

void host_close(void)
{
	while (sl_catched_hosts)
		host_remove(
			(struct gnutella_host *) sl_catched_hosts->data, FALSE);

	g_hash_table_foreach_remove(ht_catched_hosts, host_ht_free, 0);
	g_hash_table_destroy(ht_catched_hosts);

	ping_reqs_clear();
	g_slist_free(sl_catched_hosts);
}

/* vi: set ts=3: */

