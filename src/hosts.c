
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
#include "routing.h"
#include "hosts.h"
#include "nodes.h"
#include "share.h" /* For files_scanned and kbytes_scanned. */

GList *sl_catched_hosts = NULL;
GHashTable *ht_catched_hosts = NULL;	/* Same, as H table */

GSList *ping_reqs = NULL;
guint32 n_ping_reqs = 0;
struct ping_req *pr_ref = (struct ping_req *) NULL;
guint32 hosts_in_catcher = 0;

gchar h_tmp[4096];

gint hosts_idle_func = 0;

#define MAX_PING_REQS 	64		/* How many ping requests we have to remember */
#define HOST_READ_CNT	20		/* Amount of hosts to read each idle tick */

static void ping_reqs_clear(void);

/*
 * Host hash table handling.
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

static gboolean host_ht_add(struct gnutella_host *host)
{
	/* Add host to the ht_catched_hosts table */

	if (g_hash_table_lookup(ht_catched_hosts, (gconstpointer) host)) {
		g_warning("Attempt to add %s twice to caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return FALSE;
	}

	hosts_in_catcher++;
	g_hash_table_insert(ht_catched_hosts, host, (gpointer) 1);

	return TRUE;
}

static void host_ht_remove(struct gnutella_host *host)
{
	/* Remove host from the ht_catched_hosts table */

	if (!g_hash_table_lookup(ht_catched_hosts, (gconstpointer) host)) {
		g_warning("Attempt to remove missing %s from caught host list",
				  ip_port_to_gchar(host->ip, host->port));
		return;
	}

	hosts_in_catcher--;
	g_hash_table_remove(ht_catched_hosts, host);
}

/*
 * Hosts
 */

void host_init(void)
{
	static void pcache_init(void);

	ht_catched_hosts = g_hash_table_new(host_hash, host_eq);
	pcache_init();
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

void host_remove(struct gnutella_host *h)
{
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

void host_add(guint32 ip, guint16 port, gboolean connect)
{
	struct gnutella_host *host;
	gchar *titles[2];
	gint extra;

	if (!check_valid_host(ip, port))
		return;					/* Is host valid? */

	if (find_host(ip, port))
		return;					/* Do we have this host? */

	/* Okay, we got a new host */

	host = (struct gnutella_host *) g_malloc0(sizeof(struct gnutella_host));

	host->port = port;
	host->ip = ip;

	titles[0] = ip_port_to_gchar(ip, port);

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
		node_add(NULL, host->ip, host->port);

	if (!sl_catched_hosts)
		gtk_widget_set_sensitive(button_host_catcher_clear, TRUE);

	if (host_ht_add(host))
		sl_catched_hosts = g_list_append(sl_catched_hosts, host);

	/*
	 * Prune cache if we reached our limit.
	 */

	extra = g_hash_table_size(ht_catched_hosts) - max_hosts_cached;
	while (extra-- > 0)
		host_remove(g_list_first(sl_catched_hosts)->data);
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
	GList *link = g_list_last(sl_catched_hosts);
	gint i;

	for (i = 0; i < hcount; i++, link = link->prev) {
		struct gnutella_host *h;

		if (!link)
			return i;			/* Amount of hosts we filled */
		
		h = (struct gnutella_host *) link->data;
		hosts[i] = *h;			/* struct copy */
	}

	return hcount;				/* We  filled all the slots */
}

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

	g_assert(sl_catched_hosts);		/* Must not call if no host in list */

	/*
	 * If we're done reading from the host file, get latest host, at the
	 * tail of the list.  Otherwise, get the first host in that list.
	 */

	link = (hosts_r_file == NULL) ?
		g_list_last(sl_catched_hosts) : g_list_first(sl_catched_hosts);

	h = (struct gnutella_host *) link->data;
	sl_catched_hosts = g_list_remove_link(sl_catched_hosts, link);
	g_list_free_1(link);
	host_ht_remove(h);

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
			host_add(gchar_to_ip(h_tmp), port, FALSE);
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

	// No longer sends ping with the ping/pong reduction scheme
	//		--RAM, 02/01/2002
	// send_init(NULL);
}

/*
 * Messages
 */

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
	m.header.ttl = MIN(1, ttl);
	m.header.hops = 0;

	WRITE_GUINT32_LE(0, m.header.size);

	if (n) {
		n->n_ping_sent++;
		sendto_one(n, (guchar *) & m, NULL, sizeof(struct gnutella_msg_init));
	} else {
		GSList *l;

		/*
		 * We don't call sendto_all() because we wish to count the amount
		 * of pings sent.
		 *
		 * XXX what we really need is a structure per node where we can
		 * XXX record the amount of valid messages sent and received.  Then
		 * XXX we'll be able to factorize counting in sendto_one().
		 *
		 *		--RAM, 02/01/2002
		 */

		for (l = sl_nodes; l; l = l->next) {
			n = (struct gnutella_node *) l->data;
			if (NODE_IS_PONGING_ONLY(n) || !NODE_IS_CONNECTED(n))
				continue;
			n->n_ping_sent++;
			sendto_one(n, (guchar *) & m, NULL,
				sizeof(struct gnutella_msg_init));
		}
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

	r = build_pong_msg(hops, ttl, muid, ip, port, files, kbytes);
	n->n_pong_sent++;
	sendto_one(n, (guchar *) r, NULL, sizeof(*r));
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
		force_local_ip ? forced_local_ip : local_ip, listen_port,
		files_scanned, kbytes_scanned);
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

		if (NODE_IS_PONGING_ONLY(cn) || !NODE_IS_CONNECTED(cn))
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

#define PONG_CACHE_SIZE		(MAX_CACHE_HOPS+1)

static struct cache_line pong_cache[PONG_CACHE_SIZE];

#define CACHE_LIFESPAN		5		/* seconds */
#define PING_THROTTLE		3		/* seconds */
#define MAX_PONGS			10		/* Max pongs returned per ping */
#define OLD_PING_PERIOD		45		/* Pinging period for "old" clients */
#define OLD_CACHE_RATIO		20		/* % of pongs from "old" clients we cache */
#define MIN_RESERVE_SIZE	512		/* we'd like that many pongs in reserve */

/*
 * pcache_init
 */
static void pcache_init(void)
{
	gint h;

	memset(pong_cache, 0, sizeof(pong_cache));

	for (h = 0; h < PONG_CACHE_SIZE; h++)
		pong_cache[h].hops = h;
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
	if (
		connected_nodes() < up_connections ||
		g_hash_table_size(ht_catched_hosts) < MIN_RESERVE_SIZE
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
			g_free(l->data);
		}
		g_slist_free(cl->pongs);

		cl->pongs = NULL;
		cl->cursor = NULL;
	}

	if (dbg > 4)
		printf("Pong CACHE expired (%d entr%s, %d in reserve)\n",
			entries, entries == 1 ? "y" : "ies",
			g_hash_table_size(ht_catched_hosts));
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

		if (NODE_IS_PONGING_ONLY(n) || !NODE_IS_CONNECTED(n))
			continue;

		if (n->flags & NODE_F_PING_LIMIT)
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

		if (NODE_IS_PONGING_ONLY(cn) || !NODE_IS_CONNECTED(cn))
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
 * pcache_ping_received
 *
 * Called when a ping is received from a node.
 *
 * + If current time is less than what `ping_accept' says, drop the ping.
 *   Otherwise, accept the ping and increment `ping_accept' by PING_THROTTLE.
 * + If cache expired, call pcache_expire() and broadcast a new ping to all
 *   the "new" clients (i.e. those flagged NODE_F_PING_LIMIT).  For "old"
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
		(n->flags & (NODE_F_PING_LIMIT|NODE_F_PING_ALIEN)) == NODE_F_PING_LIMIT
	) {
		g_warning("node %s [%d.%d] claimed ping reduction, "
			"got ping with hops=%d", node_ip(n),
			n->proto_major, n->proto_minor, n->header.hops);
		n->flags |= NODE_F_PING_ALIEN;		/* Warn only once */
	}

	/*
	 * Accept the ping?.
	 */

	if (now < n->ping_accept) {
		n->n_ping_throttle++;		/* Drop the ping */
		n->dropped++;
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

	/*
	 * If TTL = 0, only us can reply, and we'll do that below in any case..
	 * We call setup_pong_demultiplexing() anyway to reset the pong_needed[]
	 * array.
	 */

	setup_pong_demultiplexing(n, n->header.muid, n->header.ttl);

	/*
	 * If we can accept an incoming connection, send a reply.
	 */

	if (node_count() < max_connections) {
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
 * + If node is not a "new" client (i.e. flagged as NODE_F_PING_LIMIT),
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
	struct cache_line *cl;
	struct cached_pong *cp;
	guint8 hop;

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
			n->gnet_ip = ip;
			n->gnet_port = port;
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

	if (!(n->flags & NODE_F_PING_LIMIT)) {
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

	cp = (struct cached_pong *) g_malloc(sizeof(struct cached_pong));

	cp->node_id = n->id;
	cp->last_sent_id = n->id;
	cp->ip = ip;
	cp->port = port;
	cp->files_count = files_count;
	cp->kbytes_count = kbytes_count;

	hop = CACHE_HOP_IDX(n->header.hops);
	cl = &pong_cache[hop];
	cl->pongs = g_slist_append(cl->pongs, cp);

	if (dbg > 6)
		printf("CACHED pong %s (hops=%d, TTL=%d) from %s %s\n",
			ip_port_to_gchar(ip, port), n->header.hops, n->header.ttl,
			(n->flags & NODE_F_PING_LIMIT) ? "NEW" : "OLD", node_ip(n));

	/*
	 * Demultiplex pong: send it to all the connections but the one we
	 * received it from, provided they need more pongs of this hop count.
	 */

	pong_all_neighbours_but_one(n, cp, hop, n->header.ttl);
}

void host_close(void)
{
	pcache_expire();

	while (sl_catched_hosts)
		host_remove((struct gnutella_host *) sl_catched_hosts->data);

	g_hash_table_destroy(ht_catched_hosts);

	ping_reqs_clear();
	g_list_free(sl_catched_hosts);
}

/* vi: set ts=4: */

