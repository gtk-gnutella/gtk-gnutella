
#include "gnutella.h"

#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "interface.h"
#include "gui.h"
#include "misc.h"
#include "sockets.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h" /* For files_scanned and kbytes_scanned. */
#include "routing.h"
#include "gmsg.h"

GList *sl_caught_hosts = NULL;				/* Reserve list */
static GList *sl_valid_hosts = NULL;		/* Validated hosts */
static GHashTable *ht_known_hosts = NULL;	/* All known hosts */
static GList *pcache_recent_pongs = NULL;	/* Recent pongs we got */

GSList *ping_reqs = NULL;
guint32 n_ping_reqs = 0;
struct ping_req *pr_ref = (struct ping_req *) NULL;
guint32 hosts_in_catcher = 0;
gboolean host_low_on_pongs = FALSE;			/* True when less than 12% full */

gchar h_tmp[4096];

gint hosts_idle_func = 0;

#define MAX_PING_REQS 		64	/* How many ping requests we have to remember */
#define HOST_READ_CNT		20	/* Amount of hosts to read each idle tick */
#define HOST_CATCHER_DELAY	10	/* Delay between connections to same host */

static void ping_reqs_clear(void);
static gboolean get_recent_pong(guint32 *ip, guint16 *port);

/***
 *** Host timer.
 ***/

/*
 * auto_connect
 *
 * Round-robin selection of a host catcher, and addition to the list of
 * nodes, if not already connected to it.
 */
static void auto_connect(void)
{
	static gchar *host_catcher[] = {
		"connect1.gnutellanet.com",
		"gnotella.fileflash.com",
		"connect2.gnutellanet.com",
		"public.bearshare.net",
		"connect3.gnutellanet.com",
		"gnet2.ath.cx",
		"connect1.bearshare.net",
		"gnutella-again.hostscache.com",	/* Multiple IPs, oh well */
	};
	static struct host_catcher {
		time_t tried;
		guint32 ip;
	} *host_tried = NULL;
	static guint host_idx = 0;
	guint32 ip = 0;
	guint16 port = 6346;
	gint host_count = sizeof(host_catcher) / sizeof(host_catcher[0]);
	gint i;
	time_t now = time((time_t *) NULL);
	extern gboolean node_connected(guint32, guint16, gboolean);

	/*
	 * To avoid hammering the host caches, we don't allow connections to
	 * each of them that are not at least HOST_CATCHER_DELAY seconds apart.
	 * The `host_tried' array keeps track of our last attempts.
	 *		--RAM, 30/12/2001
	 *
	 * To avoid continuous (blocking) DNS lookups when we are low on hosts,
	 * cache the IP of each host catcher.  We assume those are fairly stable
	 * hosts and that their IP will never change during the course of our
	 * running time.
	 *		--RAM, 14/01/2002
	 */

	if (host_tried == NULL)
		host_tried = g_malloc0(sizeof(struct host_catcher) * host_count);

	for (i = 0; i < host_count; i++, host_idx++) {
		if (host_idx >= host_count)
			host_idx = 0;

		ip = host_tried[host_idx].ip;
		if (ip == 0)
			ip = host_tried[host_idx].ip = host_to_ip(host_catcher[host_idx]);

		if (
			ip != 0 &&
			!node_connected(ip, port, FALSE) &&
			(now - host_tried[host_idx].tried) >= HOST_CATCHER_DELAY
		) {
			node_add(NULL, ip, port);
			host_tried[host_idx].tried = now;
			return;
		}
	}
}

/*
 * host_timer
 *
 * Periodic host heartbeat timer.
 */
void host_timer(void)
{
	int nodes_missing = up_connections - node_count();

	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	if (nodes_missing > 0 && !stop_host_get) {
		if (sl_caught_hosts != NULL) {
			while (nodes_missing-- > 0 && sl_caught_hosts) {
				guint32 ip;
				guint16 port;

				host_get_caught(&ip, &port);
				node_add(NULL, ip, port);
			}
		} else
			auto_connect();
	}
}

/***
 *** Host hash table handling.
 ***/

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

static gboolean host_ht_add(struct gnutella_host *host)
{
	/* Add host to the ht_known_hosts table */

	if (g_hash_table_lookup(ht_known_hosts, (gconstpointer) host)) {
		g_warning("Attempt to add %s twice to caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return FALSE;
	}

	hosts_in_catcher++;
	g_hash_table_insert(ht_known_hosts, host, (gpointer) 1);

	return TRUE;
}

static void host_ht_remove(struct gnutella_host *host)
{
	/* Remove host from the ht_known_hosts table */

	if (!g_hash_table_lookup(ht_known_hosts, (gconstpointer) host)) {
		g_warning("Attempt to remove missing %s from caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

	hosts_in_catcher--;
	g_hash_table_remove(ht_known_hosts, host);
}

/*
 * host_save_valid
 *
 * Save host to the validated server list
 *
 * We put in this list all the Gnet nodes to which we were able to connect
 * and transmit at list one packet (indicating a successful handshake).
 */
void host_save_valid(guint32 ip, guint16 port)
{
	struct gnutella_host *host;

	/*
	 * This routing must be called only when the node has been removed
	 * from `sl_nodes' or find_host() will report we have the node.
	 */

	if (!check_valid_host(ip, port))
		return;

	if (find_host(ip, port))
		return;						/* Already have it, from a pong? */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->ip = ip;
	host->port = port;

	/*
	 * We prepend to the list instead of appending because the day
	 * we switch it as `sl_caught_hosts', we'll start reading from there,
	 * in effect using the most recent hosts we know about.
	 */

	if (host_ht_add(host))
		sl_valid_hosts = g_list_prepend(sl_valid_hosts, host);
	else
		g_free(host);

	gtk_widget_set_sensitive(button_host_catcher_clear, sl_valid_hosts != NULL);
}

/***
 *** Hosts
 ***/

void host_init(void)
{
	static void pcache_init(void);

	ht_known_hosts = g_hash_table_new(host_hash, host_eq);
	pcache_init();
}

gboolean find_host(guint32 ip, guint16 port)
{
	GSList *l;
	struct gnutella_host lhost = { ip, port };

	/* Check our local ip */

	if (ip == listen_ip())
		return TRUE;

	/* Check the nodes -- this is a small list, OK to traverse */

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *node = (struct gnutella_node *) l->data;
		if (NODE_IS_REMOVING(node))
			continue;
		if (!node->gnet_ip)
			continue;
		if (node->gnet_ip == ip && node->gnet_port == port)
			return TRUE;
	}

	/* Check the hosts -- large list, use hash table --RAM */

	return g_hash_table_lookup(ht_known_hosts, &lhost) ? TRUE : FALSE;
}

void host_remove(struct gnutella_host *h)
{
	sl_caught_hosts = g_list_remove(sl_caught_hosts, h);
	host_ht_remove(h);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}

	if (!sl_caught_hosts)
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
	if ((ip & (guint32) 0xFFFFFF00) == (guint32) 0xFFFFFF00)
		return FALSE;			/* IP == 255.255.255.0 / 24 */

	return TRUE;
}

/*
 * add_host_to_cache
 *
 * Common processing for host_add() and host_add_semi_pong().
 * Returns true when IP/port passed sanity checks.
 */
static gboolean add_host_to_cache(guint32 ip, guint16 port, gchar *type)
{
	struct gnutella_host *host;

	if (!check_valid_host(ip, port))
		return FALSE;			/* Is host valid? */

	if (find_host(ip, port))
		return FALSE;			/* Do we have this host? */

	/* Okay, we got a new host */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->port = port;
	host->ip = ip;

	if (!sl_caught_hosts)		/* Assume addition below will be a success */
		gtk_widget_set_sensitive(button_host_catcher_clear, TRUE);

	if (host_ht_add(host))
		sl_caught_hosts = g_list_append(sl_caught_hosts, host);
	else
		g_free(host);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}

	if (!sl_caught_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);

	host_low_on_pongs = (hosts_in_catcher < (max_hosts_cached >> 3));

	if (dbg > 8)
		printf("added %s %s (%s)\n", type, ip_port_to_gchar(ip, port),
			host_low_on_pongs ? "LOW" : "OK");

	return TRUE;
}

/*
 * host_add
 *
 * Add a new host to our pong reserve.
 * When `connect' is true, attempt to connect if we are low in Gnet links.
 */
void host_add(guint32 ip, guint16 port, gboolean connect)
{
	gint extra;

	if (!add_host_to_cache(ip, port, "pong"))
		return;

	/*
	 * If we are under the number of connections wanted, we add this host
	 * to the connection list.
	 *
	 * Note: we're not using `node_count()' for the comparison with
	 * `up_connections' but connected_nodes().	The node_add() routine also
	 * compare `node_count' with `max_connections' to ensure we don't
	 * launch too many connections, but comparing here as well may help
	 * avoid useless call to connected_nodes() and/or node_add().
	 *				--RAM, 20/09/2001
	 */

	if (connect && node_count() < max_connections &&
			connected_nodes() < up_connections)
		node_add(NULL, ip, port);

	/*
	 * Prune cache if we reached our limit.
	 *
	 * Because the `ht_known_hosts' table records the hosts in the
	 * `sl_caught_hosts' list as well as those in the `sl_valid_hosts' list,
	 * it is possible that during the while loop, we reach the end of the
	 * `sl_valid_hosts'.  At that point, we switch.
	 */

	extra = g_hash_table_size(ht_known_hosts) - max_hosts_cached;
	while (extra-- > 0) {
		if (sl_caught_hosts == NULL) {
			sl_caught_hosts = sl_valid_hosts;
			sl_valid_hosts = NULL;
		}
		if (sl_caught_hosts == NULL) {
			g_warning("BUG: asked to remove hosts, but hostcache list empty");
			break;
		}
		host_remove(g_list_first(sl_caught_hosts)->data);
	}
}

/*
 * host_add_semi_pong
 *
 * Add a new host to our pong reserve, although the information here
 * does not come from a pong but from a Query Hit packet, hence the port
 * may be unsuitable for Gnet connections.
 */
void host_add_semi_pong(guint32 ip, guint16 port)
{
	g_assert(host_low_on_pongs);	/* Only used when low on pongs */

	(void) add_host_to_cache(ip, port, "semi-pong");

	/*
	 * Don't attempt to prune cache, we know we're below the limit.
	 */
}

static FILE *hosts_r_file = (FILE *) NULL;

/*
 * host_fill_caught_array
 *
 * Fill `hosts', an array of `hcount' hosts already allocated with at most
 * `hcount' hosts from out caught list, without removing those hosts from
 * the list.
 *
 * Returns the amount of hosts filled.
 */
gint host_fill_caught_array(struct gnutella_host *hosts, gint hcount)
{
	GList *l;
	gint i;

	/*
	 * First try to fill from our recent pongs, as they are more fresh
	 * and therefore more likely to be connectible.
	 */

	for (i = 0; i < hcount; i++) {
		guint32 ip;
		guint16 port;

		if (!get_recent_pong(&ip, &port))
			break;

		hosts[i].ip = ip;
		hosts[i].port = port;
	}

	if (i == hcount)
		return hcount;

	/*
	 * Not enough fresh pongs, get some from our reserve.
	 */

	for (l = g_list_last(sl_caught_hosts); i < hcount; i++, l = l->prev) {
		struct gnutella_host *h;

		if (!l)
			return i;			/* Amount of hosts we filled */
		
		h = (struct gnutella_host *) l->data;
		hosts[i] = *h;			/* struct copy */
	}

	return hcount;				/* We  filled all the slots */
}

/*
 * host_get_caught
 *
 * Get host IP/port information from our caught host list, or from the
 * recent pont cache, in alternance.
 */
void host_get_caught(guint32 *ip, guint16 *port)
{
	static guint alternate = 0;
	struct gnutella_host *h;
	GList *link;

	g_assert(sl_caught_hosts);		/* Must not call if no host in list */

	host_low_on_pongs = (hosts_in_catcher < (max_hosts_cached >> 3));

	/*
	 * Try the recent pong cache when `alternate' is odd.
	 */

	if (alternate++ & 0x1 && get_recent_pong(ip, port))
		return;

	/*
	 * If we're done reading from the host file, get latest host, at the
	 * tail of the list.  Otherwise, get the first host in that list.
	 */

	link = (hosts_r_file == NULL) ?
		g_list_last(sl_caught_hosts) : g_list_first(sl_caught_hosts);

	h = (struct gnutella_host *) link->data;
	sl_caught_hosts = g_list_remove_link(sl_caught_hosts, link);
	g_list_free_1(link);
	host_ht_remove(h);

	*ip = h->ip;
	*port = h->port;
	g_free(h);

	if (!sl_caught_hosts) {
		sl_caught_hosts = sl_valid_hosts;
		sl_valid_hosts = NULL;
	}

	if (!sl_caught_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);
}

/***
 *** Hosts text files
 ***/

gint hosts_reading_func(gpointer data)
{
	gint max_read = max_hosts_cached - g_hash_table_size(ht_known_hosts);
	gint count = MIN(max_read, HOST_READ_CNT);
	gint i;

	for (i = 0; i < count; i++) {
		if (fgets(h_tmp, sizeof(h_tmp) - 1, hosts_r_file)) { /* NUL appended */
			guint32 ip;
			gint16 port;

			if (gchar_to_ip_port(h_tmp, &ip, &port))
				host_add(ip, port, FALSE);
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

	/*
	 * Write "valid" hosts first.  Next time we are launched, we'll first
	 * start reading from the head first.  And once the whole cache has
	 * been read in memory, we'll begin using the tail of the list, i.e.
	 * possibly older hosts, which will help ensure we don't always connect
	 * to the same set of hosts.
	 */

	for (l = sl_valid_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	for (l = sl_caught_hosts; l; l = l->next)
		fprintf(f, "%s\n",
				ip_port_to_gchar(((struct gnutella_host *) l->data)->ip,
								 ((struct gnutella_host *) l->data)->port));

	fclose(f);
}

/***
 *** gnutellaNet stats
 ***/

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
		n_ping_reqs++;
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

	for (l = ping_reqs; l; l = l->next)
		g_free(l->data);
	g_slist_free(ping_reqs);

	ping_reqs = NULL;
	n_ping_reqs = 0;
}

void ping_stats_update(void)
{
	ping_reqs_clear();
	pr_ref = NULL;

	gui_update_stats();

	// No longer sends ping with the ping/pong reduction scheme
	//		--RAM, 02/01/2002
	// send_init(NULL);
}

/***
 *** Messages
 ***/

/*
 * send_ping
 *
 * Sends a ping to given node, or broadcast to everyone if `n' is NULL.
 */
static void send_ping(struct gnutella_node *n, guint8 ttl)
{
	struct gnutella_msg_init m;

	message_set_muid(&(m.header), TRUE);

	m.header.function = GTA_MSG_INIT;
	m.header.ttl = ttl;
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	if (n) {
		if (NODE_IS_WRITABLE(n)) {
			n->n_ping_sent++;
			gmsg_sendto_one(n, (guchar *) &m, sizeof(struct gnutella_msg_init));
		}
	} else {
		GSList *l;

		/*
		 * XXX Have to loop to count pings sent.
		 * XXX Need to do that more generically, to factorize code.
		 */

		for (l = sl_nodes; l; l = l->next) {
			n = (struct gnutella_node *) l->data;
			if (!NODE_IS_WRITABLE(n))
				continue;
			n->n_ping_sent++;
		}

		gmsg_sendto_all(sl_nodes, (guchar *) &m,
			sizeof(struct gnutella_msg_init));
	}

	register_ping_req(m.header.muid);
}

/*
 * send_alive_ping
 *
 * Send ping to immediate neighbour, to check its latency and the fact
 * that it is alive, or get its Gnet sharing information (ip, port).
 */
void send_alive_ping(struct gnutella_node *n)
{
	// XXX do that periodically to measure latency as well
	send_ping(n, 1);
}

/*
 * build_pong_msg
 *
 * Build pong message, returns pointer to static data.
 */
struct gnutella_msg_init_response *build_pong_msg(
	guint8 hops, guint8 ttl, guchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes)
{
	static struct gnutella_msg_init_response pong;

	pong.header.function = GTA_MSG_INIT_RESPONSE;
	pong.header.hops = hops;
	pong.header.ttl = ttl;
	memcpy(&pong.header.muid, muid, 16);

	WRITE_GUINT16_LE(port, pong.response.host_port);
	WRITE_GUINT32_BE(ip, pong.response.host_ip);
	WRITE_GUINT32_LE(files, pong.response.files_count);
	WRITE_GUINT32_LE(kbytes, pong.response.kbytes_count);
	WRITE_GUINT32_LE(sizeof(struct gnutella_init_response), pong.header.size);

	return &pong;
}

/*
 * send_pong
 *
 * Send pong message back to node.
 */
static void send_pong(struct gnutella_node *n,
	guint8 hops, guint8 ttl, guchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes)
{
	struct gnutella_msg_init_response *r;

	if (!NODE_IS_WRITABLE(n))
		return;

	r = build_pong_msg(hops, ttl, muid, ip, port, files, kbytes);
	n->n_pong_sent++;
	gmsg_sendto_one(n, (guchar *) r, sizeof(*r));
}

/*
 * send_personal_info
 *
 * Send info about us back to node, using the hopcount information present in
 * the header of the node structure to construct the TTL of the pong we
 * send.
 */
static void send_personal_info(struct gnutella_node *n)
{
	g_assert(n->header.function == GTA_MSG_INIT);	/* Replying to a ping */

	if (!force_local_ip && !local_ip)
		return;		/* If we don't know yet our local IP, we can't reply */

	/*
	 * Pongs are sent with a TTL just large enough to reach the pinging host,
	 * up to a maximum of max_ttl.	Note that we rely on the hop count being
	 * accurate.
	 *				--RAM, 15/09/2001
	 */

	send_pong(n, 0, MIN(n->header.hops + 1, max_ttl), n->header.muid,
		listen_ip(), listen_port, files_scanned, kbytes_scanned);
}

/*
 * send_neighbouring_info
 *
 * Send a pong for each of our connected neighbours to specified node.
 */
static void send_neighbouring_info(struct gnutella_node *n)
{
	GSList *l;

	g_assert(n->header.function == GTA_MSG_INIT);	/* Replying to a ping */
	g_assert(n->header.hops == 0);					/* Originates from node */
	g_assert(n->header.ttl == 2);					/* "Crawler" ping */

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *cn = (struct gnutella_node *) l->data;

		if (!NODE_IS_WRITABLE(cn))
			continue;

		/*
		 * If we have valid Gnet information for the node, build the pong
		 * as if it came from the neighbour, only we don't send the ping,
		 * and don't have to read back the pong and resent it.
		 *
		 * Otherwise, don't send anything back: we no longer keep routing
		 * information for pings.
		 */

		if (cn->gnet_ip == 0)
			continue;				/* No information yet */

		send_pong(n, 1, 1, n->header.muid,		/* hops = 1, TTL = 1 */
			cn->gnet_ip, cn->gnet_port,
			cn->gnet_files_count, cn->gnet_kbytes_count);

		/*
		 * Since we won't see the neighbour pong, we won't be able to store
		 * it in our reserve, so do it from here.
		 */

		host_add(cn->gnet_ip, cn->gnet_port, FALSE);

		/*
		 * Node can be removed should its send queue saturate.
		 */

		if (!NODE_IS_CONNECTED(n))
			return;
	}
}

/***
 *** Ping/pong reducing scheme.
 ***/

/*
 * Data structures used:
 *
 * `pong_cache' is an array of MAX_CACHE_HOPS+1 entries.
 * Each entry is a structure holding a one-way list and a traversal pointer
 * so we may iterate over the list of cached pongs at that hop level.
 *
 * `cache_expire_time' is the time after which we will expire the whole cache
 * and ping all our connections.
 */

static time_t pcache_expire_time = 0;

struct cached_pong {		/* A cached pong */
	gint refcount;			/* How many lists reference us? */
	guint32 node_id;		/* The node ID from which we got that pong */
	guint32 last_sent_id;	/* Node ID to which we last sent this pong */
	guint32 ip;				/* Values from the pong message */
	guint32 port;
	guint32 files_count;
	guint32 kbytes_count;
};

struct cache_line {			/* A cache line for a given hop value */
	gint hops;				/* Hop count of this cache line */
	GSList *pongs;			/* List of cached_pong */
	GSList *cursor;			/* Cursor within list: last item traversed */
};

static gint pcache_recent_pong_count = 0;	/* # of pongs in recent list */
static GHashTable *ht_recent_pongs;

#define PONG_CACHE_SIZE		(MAX_CACHE_HOPS+1)

static struct cache_line pong_cache[PONG_CACHE_SIZE];

#define CACHE_LIFESPAN		5		/* seconds */
#define PING_THROTTLE		3		/* seconds */
#define MAX_PONGS			10		/* Max pongs returned per ping */
#define OLD_PING_PERIOD		45		/* Pinging period for "old" clients */
#define OLD_CACHE_RATIO		20		/* % of pongs from "old" clients we cache */
#define MIN_RESERVE_SIZE	1024	/* we'd like that many pongs in reserve */
#define RECENT_PING_SIZE	50		/* remember last 50 pongs we saw */

/*
 * cached_pong_hash
 * cached_pong_eq
 *
 * Callbacks for the `ht_recent_pongs' hash table.
 */

static guint cached_pong_hash(gconstpointer key)
{
	struct cached_pong *cp = (struct cached_pong *) key;

	return (guint) (cp->ip ^ ((cp->port << 16) | cp->port));
}
static gint cached_pong_eq(gconstpointer v1, gconstpointer v2)
{
	struct cached_pong *h1 = (struct cached_pong *) v1;
	struct cached_pong *h2 = (struct cached_pong *) v2;

	return h1->ip == h2->ip && h1->port == h2->port;
}

/*
 * pcache_init
 */
static void pcache_init(void)
{
	gint h;

	memset(pong_cache, 0, sizeof(pong_cache));

	for (h = 0; h < PONG_CACHE_SIZE; h++)
		pong_cache[h].hops = h;

	ht_recent_pongs = g_hash_table_new(cached_pong_hash, cached_pong_eq);
}

/*
 * free_cached_pong
 *
 * Free cached pong when noone references it any more.
 */
static void free_cached_pong(struct cached_pong *cp)
{
	g_assert(cp->refcount > 0);		/* Someone was referencing it */

	if (--(cp->refcount) != 0)
		return;

	g_free(cp);
}

static GList *last_returned_pong = NULL;	/* Last returned from list */

/*
 * get_recent_pong
 *
 * Get a recent pong from the list, updating `last_returned_pong' as we
 * go along, so that we never return twice the same pong instance.
 *
 * Fills `ip' and `port' with the pong value and return TRUE if we
 * got a pong.  Otherwise return FALSE.
 */
static gboolean get_recent_pong(guint32 *ip, guint16 *port)
{
	static guint32 last_ip = 0;
	static guint16 last_port = 0;
	GList *l;
	struct cached_pong *cp;

	if (!pcache_recent_pongs)		/* List empty */
		return FALSE;

	/*
	 * If `last_returned_pong' is NULL, it means we reached the head
	 * of the list, so we traverse faster than we get pongs.
	 *
	 * Try with the head of the list, because maybe we have a recent pong
	 * there, but if it is the same as the last ip/port we returned, then
	 * go back to the tail of the list.
	 */

	if (last_returned_pong == NULL) {
		l = g_list_first(pcache_recent_pongs);
		cp = (struct cached_pong *) l->data;

		if (cp->ip != last_ip || cp->port != last_port)
			goto found;

		if (l->next == NULL)			/* Head is the only item in list */
			return FALSE;
	} else {
		/* Regular case */
		for (l = last_returned_pong->prev; l; l = l->prev) {
			cp = (struct cached_pong *) l->data;
			if (cp->ip != last_ip || cp->port != last_port)
				goto found;
		}
	}

	/*
	 * Still none found, go back to the end of the list.
	 */

	for (l = g_list_last(pcache_recent_pongs); l; l = l->prev) {
		cp = (struct cached_pong *) l->data;
		if (cp->ip != last_ip || cp->port != last_port)
			goto found;
	}

	return FALSE;

found:
	last_returned_pong = l;
	*ip = last_ip = cp->ip;
	*port = last_port = cp->port;

	if (dbg > 8)
		printf("returning recent PONG %s\n",
			ip_port_to_gchar(cp->ip, cp->port));

	return TRUE;
}

/*
 * add_recent_pong
 *
 * Add recent pong to the list, handled as a FIFO cache, if not already
 * present.
 */
static void add_recent_pong(struct cached_pong *cp)
{
	if (g_hash_table_lookup(ht_recent_pongs, (gconstpointer) cp))
		return;

	if (pcache_recent_pong_count == RECENT_PING_SIZE) {		/* Full */
		GList *link = g_list_last(pcache_recent_pongs);
		struct cached_pong *cp = (struct cached_pong *) link->data;

		pcache_recent_pongs = g_list_remove_link(pcache_recent_pongs, link);
		g_hash_table_remove(ht_recent_pongs, cp);

		if (link == last_returned_pong)
			last_returned_pong = last_returned_pong->prev;

		free_cached_pong(cp);
		g_list_free_1(link);
	} else
		pcache_recent_pong_count++;
	
	pcache_recent_pongs = g_list_prepend(pcache_recent_pongs, cp);
	g_hash_table_insert(ht_recent_pongs, cp, (gpointer) 1);
	cp->refcount++;		/* We don't refcount insertion in the hash table */
}

/*
 * clear_recent_pongs
 *
 * Clear the whole recent pong list.
 */
static void clear_recent_pongs(void)
{
	GList *l;

	for (l = pcache_recent_pongs; l; l = l->next) {
		struct cached_pong *cp = (struct cached_pong *) l->data;

		g_hash_table_remove(ht_recent_pongs, cp);
		free_cached_pong(cp);
	}

	g_list_free(pcache_recent_pongs);
	pcache_recent_pongs = NULL;
	last_returned_pong = NULL;
	pcache_recent_pong_count = 0;
}

/*
 * pcache_outgoing_connection
 *
 * Called when a new outgoing connection has been made.
 *
 * + If we need a connection, or have less than MAX_PONGS entries in our caught
 *   list, send a ping at normal TTL value.
 * + Otherwise, send a handshaking ping with TTL=1
 */
void pcache_outgoing_connection(struct gnutella_node *n)
{
	g_assert(NODE_IS_CONNECTED(n));

	if (
		connected_nodes() < up_connections ||
		g_hash_table_size(ht_known_hosts) < MIN_RESERVE_SIZE
	)
		send_ping(n, my_ttl);			/* Regular ping, get fresh pongs */
	else
		send_ping(n, 1);				/* Handshaking ping */
}

/*
 * pcache_expire
 *
 * Expire the whole cache.
 */
static void pcache_expire(void)
{
	gint i;
	gint entries = 0;

	for (i = 0; i < PONG_CACHE_SIZE; i++) {
		struct cache_line *cl = &pong_cache[i];
		GSList *l;

		for (l = cl->pongs; l; l = l->next) {
			entries++;
			free_cached_pong((struct cached_pong *) l->data);
		}
		g_slist_free(cl->pongs);

		cl->pongs = NULL;
		cl->cursor = NULL;
	}

	if (dbg > 4)
		printf("Pong CACHE expired (%d entr%s, %d in reserve)\n",
			entries, entries == 1 ? "y" : "ies",
			g_hash_table_size(ht_known_hosts));
}

/*
 * ping_all_neighbours
 *
 * Send a ping to all "new" clients to which we are connected, and one to
 * older client if and only if at least OLD_PING_PERIOD seconds have
 * elapsed since our last ping, as determined by `next_ping'.
 */
static void ping_all_neighbours(time_t now)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *n = (struct gnutella_node *) l->data;

		if (!NODE_IS_WRITABLE(n))
			continue;

		if (n->attrs & NODE_A_PONG_CACHING)
			send_ping(n, my_ttl);
		else if (now > n->next_ping) {
			send_ping(n, my_ttl);
			n->next_ping = now + OLD_PING_PERIOD;
		}
	}
}

/*
 * pcache_possibly_expired
 *
 * Check pong cache for expiration.
 * If expiration time is reached, flush it and ping all our neighbours.
 */
void pcache_possibly_expired(time_t now)
{
	if (now >= pcache_expire_time) {
		pcache_expire();
		pcache_expire_time = now + CACHE_LIFESPAN;
		ping_all_neighbours(now);
	}
}

/*
 * setup_pong_demultiplexing
 *
 * Fill ping_guid[] and pong_needed[] arrays in the node from which we just
 * accepted a ping.
 *
 * When we accept a ping from a connection, we don't really relay the ping.
 * Our cache is filled by the pongs we receive back from our periodic
 * pinging of the neighbours.
 *
 * However, when we get some pongs back, we forward them back to the nodes
 * for which we have accepted a ping and which still need results, as
 * determined by pong_needed[] (index by pong hop count).  The saved GUID
 * of the ping allows us to fake the pong reply, so the sending node recognizes
 * those as being "his" pongs.
 */
void setup_pong_demultiplexing(
	struct gnutella_node *n, guchar *muid, guint8 ttl)
{
	gint remains;
	gint h;

	g_assert(n->header.function == GTA_MSG_INIT);

	memcpy(n->ping_guid, n->header.muid, 16);
	memset(n->pong_needed, 0, sizeof(n->pong_needed));
	n->pong_missing = 0;

	/*
	 * `ttl' is currently the amount of hops the ping could travel.
	 * If it's 1, it means it would have travelled on host still, and we
	 * would have got a pong back with an hop count of 0.
	 *
	 * Since our pong_needed[] array is indexed by the hop count of pongs,
	 * we need to substract one from the ttl parameter.
	 */

	if (ttl-- == 0)
		return;

	ttl = MIN(ttl, MAX_CACHE_HOPS);		/* We limit the maximum hop count */

	/*
	 * Now we're going to distribute "evenly" the MAX_PONGS we can return
	 * to this ping accross the (0..ttl) range.  We start by the beginning
	 * of the array to give more weight to high-hops pongs.
	 */

	n->pong_missing = remains = MAX_PONGS;

	for (h = 0; h <= MAX_CACHE_HOPS; h++) {
		guchar amount = (guchar) (remains / (MAX_CACHE_HOPS + 1 - h));
		n->pong_needed[h] = amount;
		remains -= amount;
		if (dbg > 7)
			printf("pong_needed[%d] = %d, remains = %d\n", h, amount, remains);
	}

	g_assert(remains == 0);
}

/*
 * iterate_on_cached_line
 *
 * Internal routine for send_cached_pongs.
 *
 * Iterates on a list of cached pongs and send back any pong to node `n'
 * that did not originate from it.  Update `cursor' in the cached line
 * to be the address of the last traversed item.
 *
 * Return FALSE if we're definitely done, TRUE if we can still iterate.
 */
static gboolean iterate_on_cached_line(
	struct gnutella_node *n, struct cache_line *cl, guint8 ttl,
	GSList *start, GSList *end, gboolean strict)
{
	gint hops = cl->hops;
	GSList *l;

	for (l = start; l && l != end && n->pong_missing; l = l->next) {
		struct cached_pong *cp = (struct cached_pong *) l->data;

		cl->cursor = l;

		/*
		 * We never send a cached pong to the node from which it came along.
		 *
		 * The `last_sent_id' trick is used because we're going to iterate
		 * twice on the cache list: once to send pongs that strictly match
		 * the hop counts needed, and another time to send pongs as needed,
		 * more loosely.  The two runs are consecutive, so we're saving in
		 * each cached entry the node to which we sent it last, so we don't
		 * resend the same pong twice.
		 *
		 * We're only iterating upon reception of the intial ping from the
		 * node.  After that, we'll send pongs as we receive them, and
		 * only if they strictly match the needed TTL.
		 */

		if (n->id == cp->node_id)
			continue;
		if (n->id == cp->last_sent_id)
			continue;
		cp->last_sent_id = n->id;

		send_pong(n, hops, ttl, n->ping_guid,
			cp->ip, cp->port, cp->files_count, cp->kbytes_count);

		n->pong_missing--;

		if (dbg > 7)
			printf("iterate: sent cached pong %s (hops=%d, TTL=%d) to %s, "
				"missing=%d %s\n", ip_port_to_gchar(cp->ip, cp->port),
				hops, ttl, node_ip(n), n->pong_missing,
				strict ? "STRICT" : "loose");

		if (strict && --(n->pong_needed[hops]) == 0)
			return FALSE;

		/*
		 * Node can be removed should its send queue saturate.
		 */

		if (!NODE_IS_CONNECTED(n))
			return FALSE;
	}

	return n->pong_missing != 0;
}

/*
 * send_cached_pongs
 *
 * Send pongs from cache line back to node `n' if more are needed for this
 * hop count and they are not originating from the node.  When `strict'
 * is false, we send even if no pong at that hop level is needed.
 */
static void send_cached_pongs(struct gnutella_node *n,
	struct cache_line *cl, guint8 ttl, gboolean strict)
{
	gint hops = cl->hops;
	GSList *old = cl->cursor;

	if (strict && !n->pong_needed[hops])
		return;

	/*
	 * We start iterating after `cursor', until the end of the list, at which
	 * time we restart from the beginning until we reach `cursor', included.
	 * When we leave, `cursor' will point to the last traversed item.
	 */

	if (old) {
		if (!iterate_on_cached_line(n, cl, ttl, old->next, NULL, strict))
			return;
		(void) iterate_on_cached_line(n, cl, ttl, cl->pongs, old->next, strict);
	} else
		(void) iterate_on_cached_line(n, cl, ttl, cl->pongs, NULL, strict);
}

/*
 * pong_all_neighbours_but_one
 *
 * We received a pong we cached from `n'.  Send it to all other nodes if
 * they need one at this hop count.
 */
static void pong_all_neighbours_but_one(
	struct gnutella_node *n, struct cached_pong *cp, guint8 hops, guint8 ttl)
{
	GSList *l;

	for (l = sl_nodes; l; l = l->next) {
		struct gnutella_node *cn = (struct gnutella_node *) l->data;

		if (cn == n)
			continue;

		if (!NODE_IS_WRITABLE(cn))
			continue;

		/*
		 * Since we iterate twice initially at ping reception, once strictly
		 * and the other time loosly, `pong_missing' is always accurate but
		 * can be different from the sum of `pong_needed[i]', for all `i'.
		 */

		if (!cn->pong_missing)
			continue;

		if (!cn->pong_needed[hops])
			continue;

		cn->pong_missing--;
		cn->pong_needed[hops]--;

		send_pong(cn, hops, ttl, cn->ping_guid,
			cp->ip, cp->port, cp->files_count, cp->kbytes_count);

		if (dbg > 7)
			printf("pong_all: sent cached pong %s (hops=%d, TTL=%d) to %s "
				"missing=%d\n", ip_port_to_gchar(cp->ip, cp->port),
				hops, ttl, node_ip(cn), cn->pong_missing);
	}
}

/*
 * record_fresh_pong
 *
 * Add pong from node `n' to our cache of recent pongs.
 * Returns the cached pong object.
 */
static struct cached_pong *record_fresh_pong(struct gnutella_node *n,
	guint8 hops, guint32 ip, guint16 port,
	guint32 files_count, guint32 kbytes_count)
{
	struct cache_line *cl;
	struct cached_pong *cp;
	guint8 hop;

	cp = (struct cached_pong *) g_malloc(sizeof(struct cached_pong));

	cp->refcount = 1;
	cp->node_id = n->id;
	cp->last_sent_id = n->id;
	cp->ip = ip;
	cp->port = port;
	cp->files_count = files_count;
	cp->kbytes_count = kbytes_count;

	hop = CACHE_HOP_IDX(hops);
	cl = &pong_cache[hop];
	cl->pongs = g_slist_append(cl->pongs, cp);
	add_recent_pong(cp);

	return cp;
}

/*
 * pcache_ping_received
 *
 * Called when a ping is received from a node.
 *
 * + If current time is less than what `ping_accept' says, drop the ping.
 *   Otherwise, accept the ping and increment `ping_accept' by PING_THROTTLE.
 * + If cache expired, call pcache_expire() and broadcast a new ping to all
 *   the "new" clients (i.e. those flagged NODE_A_PONG_CACHING).  For "old"
 *   clients, do so only if "next_ping" time was reached.
 * + Handle "alive" pings (TTL=1) and "crawler" pings (TTL=2) immediately,
 *   then return.
 * + Setup pong demultiplexing tables, recording the fact that  the node needs
 *   to be sent pongs as we receive them.
 * + Return a pong for us if we accept incoming connections right now.
 * + Return cached pongs, avoiding to resend a pong coming from that node ID.
 */
void pcache_ping_received(struct gnutella_node *n)
{
	time_t now = time((time_t *) 0);
	gint h;
	guint8 ttl;

	g_assert(NODE_IS_CONNECTED(n));

	/*
	 * Handle "alive" pings and "crawler" pings specially.
	 * Besides, we always accept them.
	 */

	if (n->header.hops == 0 && n->header.ttl <= 2) {
		n->n_ping_special++;
		if (n->header.ttl == 1)
			send_personal_info(n);
		else if (n->header.ttl == 2)
			send_neighbouring_info(n);
		else
			node_sent_ttl0(n);
		return;
	}

	/*
	 * If we get a ping with hops != 0 from a host that claims to
	 * implement ping/pong reduction, then they are not playing
	 * by the same rules as we are.  Emit a warning.
	 *		--RAM, 03/03/2001
	 */

	if (
		n->header.hops &&
		(n->attrs & (NODE_A_PONG_CACHING|NODE_A_PONG_ALIEN)) ==
			NODE_A_PONG_CACHING
	) {
		g_warning("node %s [%d.%d] claimed ping reduction, "
			"got ping with hops=%d", node_ip(n),
			n->proto_major, n->proto_minor, n->header.hops);
		n->attrs |= NODE_A_PONG_ALIEN;		/* Warn only once */
	}

	/*
	 * Accept the ping?.
	 */

	if (now < n->ping_accept) {
		n->n_ping_throttle++;		/* Drop the ping */
		n->rx_dropped++;
		dropped_messages++;
		return;
	} else {
		n->n_ping_accepted++;
		n->ping_accept = now + PING_THROTTLE;	/* Drop more ones until then */
	}

	/*
	 * Purge cache if needed.
	 */

	pcache_possibly_expired(now);

	if (!NODE_IS_CONNECTED(n))		/* Can be removed if send queue is full */
		return;

	/*
	 * If TTL = 0, only us can reply, and we'll do that below in any case..
	 * We call setup_pong_demultiplexing() anyway to reset the pong_needed[]
	 * array.
	 */

	setup_pong_demultiplexing(n, n->header.muid, n->header.ttl);

	/*
	 * If we can accept an incoming connection, send a reply.
	 */

	if (node_count() < max_connections && !is_firewalled) {
		send_personal_info(n);
		if (!NODE_IS_CONNECTED(n))	/* Can be removed if send queue is full */
			return;
	}

	/*
	 * Return cached pongs if we have some and they are needed.
	 * We first try to send pongs on a per-hop basis, based on pong_needed[].
	 */

	ttl = MIN(n->header.hops + 1, max_ttl);

	for (h = 0; n->pong_missing && h < n->header.ttl; h++) {
		struct cache_line *cl = &pong_cache[CACHE_HOP_IDX(h)];

		if (cl->pongs) {
			send_cached_pongs(n, cl, ttl, TRUE);
			if (!NODE_IS_CONNECTED(n))
				return;
		}
	}

	/*
	 * We then re-iterate if some pongs are still needed, sending any we
	 * did not already send.
	 */

	for (h = 0; n->pong_missing && h < n->header.ttl; h++) {
		struct cache_line *cl = &pong_cache[CACHE_HOP_IDX(h)];

		if (cl->pongs) {
			send_cached_pongs(n, cl, ttl, FALSE);
			if (!NODE_IS_CONNECTED(n))
				return;
		}
	}
}

/*
 * pcache_pong_received
 *
 * Called when a pong is received from a node.
 *
 * + Record node in the main host catching list.
 * + If node is not a "new" client (i.e. flagged as NODE_A_PONG_CACHING),
 *   cache randomly OLD_CACHE_RATIO percent of those (older clients need
 *   to be able to get incoming connections as well).
 * + Cache pong in the pong.hops cache line, associated with the node ID (so we
 *   never send back this entry to the node).
 * + For all nodes but `n', propagate pong if neeed, with demultiplexing.
 */
void pcache_pong_received(struct gnutella_node *n)
{
	guint32 ip;
	guint16 port;
	guint32 files_count;
	guint32 kbytes_count;
	struct cached_pong *cp;

	n->n_pong_received++;

	/*
	 * Decompile the pong information.
	 */

	READ_GUINT16_LE(n->data, port);
	READ_GUINT32_BE(n->data + 2, ip);
	READ_GUINT32_LE(n->data + 6, files_count);
	READ_GUINT32_LE(n->data + 10, kbytes_count);

	ping_stats_add(n);		/* XXX keep this, stats are now meaningless? */

	/*
	 * Handle replies from our neighbours specially
	 */

	if (n->header.hops == 0) {
		if (!n->gnet_ip && (n->flags & NODE_F_INCOMING)) {
			if (ip == n->ip) {
				n->gnet_ip = ip;		/* Signals: we have figured it out */
				n->gnet_port = port;
			} else if (!(n->flags & NODE_F_ALIEN_IP)) {
				g_warning("node %s sent us a pong for itself with alien IP %s",
					node_ip(n), ip_to_gchar(ip));
				n->flags |= NODE_F_ALIEN_IP;	/* Probably firewalled */
			}
		}
		n->gnet_files_count = files_count;
		n->gnet_kbytes_count = kbytes_count;
	}

	/*
	 * If it's not a connectible pong, discard it.
	 */

	if (!check_valid_host(ip, port))
		return;

	/*
	 * Add pong to our reserve, and possibly try to connect.
	 */

	host_add(ip, port, TRUE);

	/*
	 * If we got a pong from an "old" client, cache OLD_CACHE_RATIO of
	 * its pongs, randomly.  Returning from this routine means we won't
	 * cache it.
	 */

	if (!(n->attrs & NODE_A_PONG_CACHING)) {
		gint ratio = (int) (100.0 * rand() / (RAND_MAX + 1.0));
		if (ratio >= OLD_CACHE_RATIO) {
			if (dbg > 7)
				printf("NOT CACHED pong %s (hops=%d, TTL=%d) from OLD %s\n",
					ip_port_to_gchar(ip, port), n->header.hops, n->header.ttl,
					node_ip(n));
			return;
		}
	}

	/*
	 * Insert pong within our cache.
	 */

	cp = record_fresh_pong(n, n->header.hops, ip, port,
		files_count, kbytes_count);

	if (dbg > 6)
		printf("CACHED pong %s (hops=%d, TTL=%d) from %s %s\n",
			ip_port_to_gchar(ip, port), n->header.hops, n->header.ttl,
			(n->attrs & NODE_A_PONG_CACHING) ? "NEW" : "OLD", node_ip(n));

	/*
	 * Demultiplex pong: send it to all the connections but the one we
	 * received it from, provided they need more pongs of this hop count.
	 */

	pong_all_neighbours_but_one(n,
		cp, CACHE_HOP_IDX(n->header.hops), MAX(1, n->header.ttl));
}

/*
 * pcache_pong_fake
 *
 * Fake a pong for a node from which we received an incoming connection,
 * using the supplied IP/port.
 *
 * This pong is not multiplexed to neighbours, but is used to populate our
 * cache, so we can return its address to others, assuming that if it is
 * making an incoming connection to us, it is really in need for other
 * connections as well.
 */
void pcache_pong_fake(struct gnutella_node *n, guint32 ip, guint16 port)
{
	if (!check_valid_host(ip, port))
		return;

	host_add(ip, port, FALSE);
	(void) record_fresh_pong(n, 1, ip, port, 0, 0);

	n->gnet_ip = ip;
	n->gnet_port = port;
}

/*
 * host_clear_cache
 *
 * Clear the whole host cache.
 */
void host_clear_cache(void)
{
	while (sl_caught_hosts)
		host_remove((struct gnutella_host *) sl_caught_hosts->data);
	g_list_free(sl_caught_hosts);

	sl_caught_hosts = sl_valid_hosts;	/* host_remove() uses that list */
	sl_valid_hosts = NULL;

	while (sl_caught_hosts)
		host_remove((struct gnutella_host *) sl_caught_hosts->data);
	g_list_free(sl_caught_hosts);

	clear_recent_pongs();

	gtk_widget_set_sensitive(button_host_catcher_clear, FALSE);
}

void host_close(void)
{
	pcache_expire();
	host_clear_cache();
	g_hash_table_destroy(ht_known_hosts);
	g_hash_table_destroy(ht_recent_pongs);
	ping_reqs_clear();
}

/* vi: set ts=4: */

