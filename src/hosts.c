
#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "interface.h"
#include "gui.h"
#include "misc.h"
#include "sockets.h"
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h" /* For files_scanned and kbytes_scanned. */

GList *sl_catched_hosts = NULL;
GHashTable *ht_catched_hosts = NULL;	/* Same, as H table */

GSList *ping_reqs = NULL;
guint32 n_ping_reqs = 0;
struct ping_req *pr_ref = (struct ping_req *) NULL;

gchar h_tmp[4096];

gint hosts_idle_func = 0;

#define MAX_PING_REQS 	64		/* How many ping requests we have to remember */
#define HOST_READ_CNT	20		/* Amount of hosts to read each idle tick */

static void ping_reqs_clear(void);

/*
 * Host hash table handing.
 */

static guint host_hash(gconstpointer key)
{
	struct gnutella_host *host = (struct gnutella_host *) key;

	return (guint) (host->ip ^ ((host->port << 16) | host->port));
}

static gint host_eq(gconstpointer v1, gconstpointer v2)
{
	struct gnutella_host *h1 = (struct gnutella_host *) v1;
	struct gnutella_host *h2 = (struct gnutella_host *) v2;

	return h1->ip == h2->ip && h1->port == h2->port;
}

static void host_ht_add(struct gnutella_host *host)
{
	/* Add host to the ht_catched_hosts table */

	if (g_hash_table_lookup(ht_catched_hosts, (gconstpointer) host)) {
		g_warning("Attempt to add %s twice to caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

	g_hash_table_insert(ht_catched_hosts, host, (gpointer) 1);
}

static void host_ht_remove(struct gnutella_host *host)
{
	/* Remove host from the ht_catched_hosts table */

	if (!g_hash_table_lookup(ht_catched_hosts, (gconstpointer) host)) {
		g_warning("Attempt to remove missing %s from caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

	g_hash_table_remove(ht_catched_hosts, host);
}

/*
 * Hosts
 */

void host_init(void)
{
	ht_catched_hosts = g_hash_table_new(host_hash, host_eq);
}

gboolean find_host(guint32 ip, guint16 port)
{
	GSList *l;
	struct gnutella_host lhost = { ip, port };

	/* Check our local ip */

	if (ip == local_ip || (force_local_ip && ip == forced_local_ip))
		return TRUE;

	/* Check the nodes -- this is a small list, OK to traverse */

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *node = (struct gnutella_node *) l->data;
		if (node->ip == ip) {
			if (node->socket &&
				node->socket->direction == GTA_CONNECTION_INCOMING)
				return TRUE;
			else if (node->port == port)
				return TRUE;
		}
	}

	/* Check the hosts -- large list, use hash table --RAM */

	return g_hash_table_lookup(ht_catched_hosts, &lhost) ? TRUE : FALSE;
}

void host_remove(struct gnutella_host *h, gboolean from_clist_too)
{
	gint row;

	if (from_clist_too) {
		row = gtk_clist_find_row_from_data(
			GTK_CLIST(clist_host_catcher), (gpointer) h);
		gtk_clist_remove(GTK_CLIST(clist_host_catcher), row);
	}

	sl_catched_hosts = g_list_remove(sl_catched_hosts, h);
	host_ht_remove(h);

	if (!sl_catched_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);

	g_free(h);
}

gboolean check_valid_host(guint32 ip, guint16 port)
{
	if (!ip || !port)
		return FALSE;			/* IP == 0 || Port == 0 */

	if (is_private_ip(ip)) 
		return FALSE;

	if (ip == (guint32) 0x01020304 || ip == (guint32) 0x01010101)
		return FALSE;			/* IP == 1.2.3.4 || IP == 1.1.1.1 */
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x00000000)
		return FALSE;			/* IP == 0.0.0.0 / 8 */
	if ((ip & (guint32) 0xFF000000) == (guint32) 0x7F000000)
		return FALSE;			/* IP == 127.0.0.0 / 8 */

	return TRUE;
}

void host_add(struct gnutella_node *n, guint32 t_ip, guint16 t_port,
			  gboolean connect)
{
	struct gnutella_host *host;
	gchar *titles[2];
	gint row;
	guint32 ip;
	guint16 port;
	gint extra;

	if (n) {
		READ_GUINT32_BE(n->data + 2, ip);
		READ_GUINT16_LE(n->data, port);
	} else {
		ip = t_ip;
		port = t_port;
	}

	if (!check_valid_host(ip, port))
		return;					/* Is host valid? */

	if (find_host(ip, port))
		return;					/* Do we have this host? */

	/* Okay, we got a new host */

	host =
		(struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->port = port;
	host->ip = ip;

	if (n) {
		/* XXX These fields are unused, don't read them --RAM, 11/09/2001 */
		// READ_GUINT32_LE(n->data + 6,	host->files_count);
		// READ_GUINT32_LE(n->data + 10, host->kbytes_count);
	}

	titles[0] = ip_port_to_gchar(ip, port);

	/*
	 * If we are under the number of connections wanted, we add this host
	 * to the connection list.
	 *
	 * Note: we're not using `nodes_in_list' for the comparison with
	 * `up_connections' but connected_nodes().	The node_add() routine also
	 * compare `nodes_in_list' with `max_connections' to ensure we don't
	 * launch too many connections, but comparing here as well may help
	 * avoid useless call to connected_nodes() and/or node_add().
	 *				--RAM, 20/09/2001
	 */

	if (connect && nodes_in_list < max_connections &&
			connected_nodes() < up_connections)
		node_add(NULL, host->ip, host->port);

	/* Add the host to the hosts catcher list */

	row = gtk_clist_append(GTK_CLIST(clist_host_catcher), titles);
	gtk_clist_set_row_data(GTK_CLIST(clist_host_catcher), row,
						   (gpointer) host);

	if (!sl_catched_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, TRUE);

	sl_catched_hosts = g_list_append(sl_catched_hosts, host);
	host_ht_add(host);

	/*
	 * Prune cache if we reached our limit.
	 */

	extra = g_hash_table_size(ht_catched_hosts) - max_hosts_cached;
	while (extra-- > 0)
		host_remove(g_list_first(sl_catched_hosts)->data, TRUE);
}

static FILE *hosts_r_file = (FILE *) NULL;

/*
 * host_get_caught
 *
 * Get a host from our caught host list.
 *
 * The returned host is removed from the list, but it is up to the caller
 * to free the host structure if it is no longer needed.
 */
struct gnutella_host *host_get_caught(void)
{
	struct gnutella_host *h;
	GList *link;
	gint row;

	g_assert(sl_catched_hosts);		/* Must not call if no host in list */

	/*
	 * If we're done reading from the host file, get latest host, at the
	 * tail of the list.  Otherwise, get the first host in that list.
	 */

	link = (hosts_r_file == NULL) ?
		g_list_last(sl_catched_hosts) : g_list_first(sl_catched_hosts);

	h = (struct gnutella_host *) link->data;
	sl_catched_hosts = g_list_remove_link(sl_catched_hosts, link);
	host_ht_remove(h);

	/*
	 * This is potentially inefficient if the find_row_from_data() does
	 * a sequential search.  They should be doing a hash lookup though.
	 * Well, I hope they do.
	 *
	 * Also, it is unfortunate, but we somehow duplicate the code from
	 * host_remove(), the difference being that we used g_list_remove_link()
	 * above to remove the element instead of giving the host and letting
	 * the list iterate to find it.
	 *
	 *		--RAM, 30/12/2001
	 */

	row = gtk_clist_find_row_from_data(
		GTK_CLIST(clist_host_catcher), (gpointer) h);
	gtk_clist_remove(GTK_CLIST(clist_host_catcher), row);

	if (!sl_catched_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);

	return h;
}

/*
 * Hosts text files
 */

gint hosts_reading_func(gpointer data)
{
	gchar *s;
	guint16 port;
	gint max_read = max_hosts_cached - g_hash_table_size(ht_catched_hosts);
	gint count = MIN(max_read, HOST_READ_CNT);
	gint i;

	for (i = 0; i < count; i++) {
		if (fgets(h_tmp, sizeof(h_tmp) - 1, hosts_r_file)) { /* NUL appended */
			s = h_tmp;
			while (*s && *s != ':')
				s++;
			port = (*s) ? atoi(s + 1) : 6346;
			*s++ = 0;
			host_add(NULL, gchar_to_ip(h_tmp), port, FALSE);
		} else
			goto done;
	}

	if (count < max_read)
		return TRUE;			/* Host cache not full, need to read more */

	/* Fall through */

done:
	fclose(hosts_r_file);

	hosts_r_file = (FILE *) NULL;
	hosts_idle_func = 0;

	gtk_clist_thaw(GTK_CLIST(clist_host_catcher));
	gui_set_status(NULL);

	return FALSE;
}

void hosts_read_from_file(gchar * path, gboolean quiet)
{
	/* Loads 'catched' hosts from a text file */

	hosts_r_file = fopen(path, "r");

	if (!hosts_r_file) {
		if (!quiet)
			g_warning("Unable to open file %s (%s)\n", path,
					  g_strerror(errno));
		return;
	}

	gtk_clist_freeze(GTK_CLIST(clist_host_catcher));

	hosts_idle_func = gtk_idle_add(hosts_reading_func, (gpointer) NULL);

	gui_set_status("Reading caught host file...");
}

void hosts_write_to_file(gchar * path)
{
	/* Saves the currently catched hosts to a file */

	FILE *f;
	GList *l;

	f = fopen(path, "w");

	if (!f) {
		g_warning("Unable to open output file %s (%s)\n", path,
				  g_strerror(errno));
		return;
	}

	for (l = sl_catched_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	fclose(f);
}

/*
 * gnutellaNet stats
 */

/* Registers a new ping request */

void register_ping_req(guchar * muid)
{
	struct ping_req *p;

	if (n_ping_reqs >= MAX_PING_REQS) {
		GSList *l = g_slist_last(ping_reqs);
		p = (struct ping_req *) l->data;
		ping_reqs = g_slist_remove_link(ping_reqs, l);
		g_slist_free_1(l);
	} else {
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
		if (!memcmp
			(((struct ping_req *) l->data)->muid, n->header.muid, 16))
			break;

	if (!l)
		return;					/* Found no request for this reply */

	r = (struct gnutella_init_response *) n->data;
	p = (struct ping_req *) l->data;

	p->hosts++;

	/*
	 * Both bits 31 and 30 must be clear, or either we have an improper
	 * little-endian encoding, or it's an obvious "fake" count.
	 *				--RAM, 14/09/2001
	 *
	 * We only account the kbytes value if the file count was correct.
	 *				--RAM, 15/09/2001
	 */

	READ_GUINT32_LE(r->files_count, v);
	if (0 == (v & 0xc0000000)) {
		p->files += v;
		READ_GUINT32_LE(r->kbytes_count, v);
		if (0 == (v & 0xc0000000))
			p->kbytes += v;
	}

	gettimeofday(&tv, (struct timezone *) NULL);

	p->delay +=
		(tv.tv_sec - p->tv.tv_sec) * 1000 + (tv.tv_usec / 1000 -
											 p->tv.tv_usec / 1000);

	if (!pr_ref || (p->hosts > pr_ref->hosts))
		pr_ref = p;
}

/* Update the stats */

static void ping_reqs_clear(void)
{
	GSList *l;

	if ((l = ping_reqs)) {
		while (l) {
			g_free(l->data);
			l = l->next;
		}
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

/*
 * Messages
 */

/* Sends an init request */

void send_init(struct gnutella_node *n)
{
	static struct gnutella_msg_init m;

	message_set_muid(&(m.header));

	m.header.function = GTA_MSG_INIT;
	m.header.ttl = my_ttl;
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	message_add(m.header.muid, GTA_MSG_INIT, NULL);

	if (n)
		sendto_one(n, (guchar *) & m, NULL,
				   sizeof(struct gnutella_msg_init));
	else
		sendto_all((guchar *) & m, NULL, sizeof(struct gnutella_msg_init));

	register_ping_req(m.header.muid);
}

/* Replies to an init request */

void reply_init(struct gnutella_node *n)
{
	static struct gnutella_msg_init_response r;

	if (!force_local_ip && !local_ip)
		return;		/* If we don't know yet your local IP, we can't reply */

	WRITE_GUINT16_LE(listen_port, r.response.host_port);
	WRITE_GUINT32_BE((force_local_ip) ? forced_local_ip : local_ip,
					 r.response.host_ip);
	WRITE_GUINT32_LE(files_scanned, r.response.files_count);
	WRITE_GUINT32_LE(kbytes_scanned, r.response.kbytes_count);

	/*
	 * Pongs are sent with a TTL just large enough to reach the pinging host,
	 * up to a maximum of max_ttl.	Note that we rely on the hop count being
	 * accurate.
	 *				--RAM, 15/09/2001
	 */

	if (n->header.hops == 0) {
		g_warning("reply_init(): hops=0, bug in route_message()?\n");
		n->header.hops++;		/* Can't send message with TTL=0 */
	}

	r.header.function = GTA_MSG_INIT_RESPONSE;
	r.header.ttl = MIN(n->header.hops, max_ttl);
	r.header.hops = 0;

	memcpy(&r.header.muid, n->header.muid, 16);

	WRITE_GUINT32_LE(sizeof(struct gnutella_init_response), r.header.size);

	sendto_one(n, (guchar *) & r, NULL,
			   sizeof(struct gnutella_msg_init_response));
}

void host_close(void)
{
	while (sl_catched_hosts)
		host_remove((struct gnutella_host *) sl_catched_hosts->data, FALSE);

	g_hash_table_destroy(ht_catched_hosts);

	ping_reqs_clear();
	g_list_free(sl_catched_hosts);
}

/* vi: set ts=4: */
