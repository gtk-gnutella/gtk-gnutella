/*
 * $Id$
 *
 * Copyright (c) 2003, Christian Biere
 *
 * Asynchronous DNS lookup.
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

#include "gnutella.h" /* mainly for dbg */

RCSID("$Id$");

#include <fcntl.h> /* open(), O_RDONLY */
#include <signal.h> /* signal(), SIGCHLD, SIG_IGN */
#include "adns.h"
#include "http.h" /* MAX_HOSTLEN */

/* private data types */

struct adns_query_t {
	gchar hostname[MAX_HOSTLEN + 1];
	void (*user_callback)(guint32, gpointer);
	gpointer user_data;
};

struct adns_reply_t {
    void (*user_callback)(guint32, gpointer);
    gpointer user_data;
    guint32 ip;
};

struct adns_cache_entry_t {
	gchar hostname[MAX_HOSTLEN + 1];
    guint32 ip;
	time_t timestamp;
};

/* Cache entries will expire after ADNS_CACHE_TIMEOUT seconds */
#define ADNS_CACHE_TIMEOUT (5 * 60)
/* Cache max. ADNS_CACHED_NUM of (hostname,ip) entries*/
#define ADNS_CACHED_NUM (32)

struct adns_cache_t {
	guint size;
	guint oldest;
	time_t timeout;
	struct adns_cache_entry_t entry[ADNS_CACHED_NUM];
};

/* private variables */

static gint adns_query_fd = -1;
static guint adns_event_id = 0;

/* private functions */

static struct adns_cache_t *adns_cache_init(void)
{
	struct adns_cache_t *cache;
	
	cache = g_malloc0(sizeof(*cache));
	cache->size = ADNS_CACHED_NUM;
	cache->oldest = 0;
	cache->timeout = ADNS_CACHE_TIMEOUT;
	return cache;
}

/* these are not needed anywhere else so undefine them */
#undef ADNS_CACHED_NUM
#undef ADNS_CACHE_TIMEOUT

/*
 * adns_cache_add
 * 
 * Adds ``hostname'' and ``ip'' to the cache. The cache is implemented
 * as a wrap-around FIFO. In case it's full, the oldest entry will be
 * overwritten. 
 */
static void adns_cache_add(
	struct adns_cache_t *cache, time_t now, const gchar *hostname, guint32 ip)
{
	g_assert(NULL != cache);
	g_assert(NULL != hostname);
	
	g_strlcpy(cache->entry[cache->oldest].hostname, hostname,
		sizeof(cache->entry[0].hostname));
	cache->entry[cache->oldest].timestamp = now;
	cache->entry[cache->oldest].ip = ip;

	cache->oldest++;
	cache->oldest %= cache->size;
}

/*
 * adns_cache_lookup
 *
 * Looks for ``hostname'' in ``cache'' wrt to cache->timeout. If
 * ``hostname'' is not found or the entry is expired, FALSE will be
 * returned. Expired entries will be removed! ``ip'' is allowed to
 * be NULL, otherwise the cached IP will be stored into the variable
 * ``ip'' points to. 
 */
static gboolean adns_cache_lookup(
	struct adns_cache_t *cache, time_t now, const gchar *hostname, guint32 *ip)
{
	guint i;

	g_assert(NULL != cache);
	g_assert(NULL != hostname);

/* FIXME:	Take advantage of the order in which entries are added to
			the cache and the timestamps
*/
	for (i = 0; i < cache->size; i++) {
		struct adns_cache_entry_t *entry;

		entry = &cache->entry[i];
		if (0 != g_ascii_strcasecmp(entry->hostname, hostname))
			continue;

		if (now - entry->timestamp <= cache->timeout) {
			if (NULL != ip)
				*ip = entry->ip;
			if (dbg > 1)
				g_warning("adns_cache_lookup: \"%s\" cached (ip=%s)",
					entry->hostname, ip_to_gchar(entry->ip));
			return TRUE;
		}
		if (dbg > 1)
			g_warning("adns_cache_lookup: removing \"%s\" from cache",
				entry->hostname);
		entry->hostname[0] = '\0';
		entry->timestamp = 0;
		entry->ip = 0;
		break;
	}

	return FALSE;
}

G_INLINE_FUNC gboolean adns_do_transfer(
	gint fd, gpointer buf, size_t len, gboolean do_write)
{
	ssize_t ret;
	size_t transferred = 0;
	size_t n = len;

	while (n > 0) {
		if (dbg > 2)
			g_warning("adns_do_transfer: n=%lu", (gulong) n);

		if (do_write)
			ret = write(fd, buf, n);
		else 
			ret = read(fd, buf, n);
		
		if (-1 == ret && errno != EAGAIN && errno != EINTR) {
			g_warning("adns_do_transfer: %s (errno=%d, do_write=%d)",
				g_strerror(errno), errno, (gint) do_write);
			return FALSE;
		} else if (0 == ret) {
			g_warning("adns_do_transfer: EOF (%s)",
				do_write ? "write" : "read");
			return FALSE;
		} else {
			n -= ret;
			buf = (gchar *)buf + transferred;
		}
	}

	return TRUE;
}

/*
 * adns_do_read
 *
 * read the complete buffer ``buf'' of size ``len'' from file descriptor ``fd''
 * return TRUE on success, FALSE if the operation failed
 */
static gboolean adns_do_read(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, FALSE);
}

/*
 * adns_do_write
 *
 * write the complete buffer ``buf'' of size ``len'' to file descriptor ``fd''
 * return TRUE on success, FALSE if the operation failed
 */
static gboolean adns_do_write(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, TRUE);
}

/*
 * adns_gethostbyname
 *
 * copies user_callback and user_data from the query buffer to the
 * reply buffer. This function won't fail. However, if gethostbyname()
 * fails ``reply->ip'' will be set to zero.
 */
static void adns_gethostbyname(
	struct adns_cache_t *cache,
	const struct adns_query_t *query,
	struct adns_reply_t *reply)
{
	time_t now;

	g_assert(NULL != cache);
	g_assert(NULL != query);
	g_assert(NULL != reply);

	if (dbg > 1)
		g_warning("adns_gethostbyname: Resolving \"%s\" ...", query->hostname);
	reply->user_callback = query->user_callback;
	reply->user_data = query->user_data;
	now = time(NULL);
	if (!adns_cache_lookup(cache, now, query->hostname, &reply->ip)) {
		reply->ip = host_to_ip(query->hostname);
		adns_cache_add(cache, now, query->hostname, reply->ip);
	}
}

/*
 * adns_helper
 * 
 * The ``main'' function of the adns helper process (server).
 * Simply reads requests (queries) from fd_in, performs a DNS lookup for it
 * and writes the result to fd_out. All operations should be blocking. Exits
 * in case of non-recoverable error during read or write.  
 */
static void adns_helper(gint fd_in, gint fd_out)
{
	static struct adns_query_t query;
	static struct adns_reply_t reply;
	static struct adns_cache_t *cache; 

	g_set_prgname("DNS-helper for gtk-gnutella");
	cache = adns_cache_init();

	for (;;) {
		if (!adns_do_read(fd_in, &query, sizeof(query)))
			break;
		adns_gethostbyname(cache, &query, &reply);
		if (!adns_do_write(fd_out, &reply, sizeof(reply)))
			break;
	}

	close(fd_in);
	close(fd_out);
	_exit(EXIT_SUCCESS);
}

/*
 * adns_callback
 *
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., gtk-gnutella itself.
 */
static void adns_callback(
	gpointer data, gint source, inputevt_cond_t condition)
{
	static struct adns_reply_t reply;

	if (adns_do_read(source, &reply, sizeof(reply))) {
		if (dbg > 1)
			g_warning("adns_callback: resolved to \"%s\"",
				ip_to_gchar(reply.ip));
		g_assert(NULL != reply.user_callback);
		reply.user_callback(reply.ip, reply.user_data);
	} else {
		g_warning("adns_callback: removing myself");
		inputevt_remove(adns_event_id);
		close(source);
	}
}

#define CLOSE_IF_VALID(fd)	\
do {						\
	if (-1 != (fd))	{		\
		close(fd);			\
		fd = -1;			\
	} 						\
} while(0) 					

/* public functions */

/*
 * adns_init:
 *
 * Initializes the adns helper i.e., fork()s a child process which will
 * be used to resolve hostnames asynchronously.
 */
void adns_init(void)
{
	gint fd_query[2] = {-1, -1};
	gint fd_reply[2] = {-1, -1};
	pid_t pid;

	if (-1 == pipe(fd_query) || -1 == pipe(fd_reply)) {
		g_warning("adns_init: pipe() failed: %s", g_strerror(errno));
		goto prefork_failure;
	}
	signal(SIGCHLD, SIG_IGN); /* prevent a zombie */
	pid = fork();
	if ((pid_t) -1 == pid) {
		g_warning("adns_init: fork() failed: %s", g_strerror(errno));
		goto prefork_failure;
	}
	if (0 == pid) {
		/* child process */
		gint null;
	
		close(fd_query[1]);
		close(fd_reply[0]);
   		close(STDIN_FILENO);  /* Just in case */
		null = open("/dev/null", O_RDONLY);
		if (-1 == null)
			g_error("adns_init: Could not open() /dev/null");
		g_assert(STDIN_FILENO == null);
		adns_helper(fd_query[0], fd_reply[1]); 
		g_assert_not_reached();
		_exit(EXIT_SUCCESS);
	} 

	/* parent process */
	close(fd_query[0]);
	close(fd_reply[1]);
	adns_query_fd = fd_query[1];
	adns_event_id = inputevt_add(fd_reply[0], INPUT_EVENT_READ,
		(inputevt_handler_t) &adns_callback, NULL);
	return;

prefork_failure:

	CLOSE_IF_VALID(fd_query[0]);
	CLOSE_IF_VALID(fd_query[1]);
	CLOSE_IF_VALID(fd_reply[0]);
	CLOSE_IF_VALID(fd_reply[1]);
}

/*
 * adns_resolve
 *
 * Creates a DNS resolve query for ``hostname''. The given function
 * ``user_callback'' (which MUST NOT be NULL) will be invoked with
 * the resolved IP address and ``user_data'' as its parameters. The
 * IP address 0.0.0.0 i.e., ``(guint32) 0'' is used to indicate a
 * failure. In case the hostname is given as an IP string, it will
 * be directly converted and the callback immediately invoked. If
 * the adns helper process is ``out of service'' the query will be
 * resolved synchronously.
 */
 void adns_resolve(
	const gchar *hostname, gpointer user_callback, gpointer user_data)
{
	static gboolean helper_alive = TRUE;
	static struct adns_query_t query;
	static struct adns_reply_t reply;
	static struct adns_cache_t *cache = NULL; 

	g_assert(NULL != hostname);
	g_assert(NULL != user_callback);

	query.user_callback = user_callback;
	query.user_data = user_data;
	reply.ip = gchar_to_ip(hostname);
	if (0 != reply.ip) {
		query.user_callback(reply.ip, query.user_data);
		return;
	}

	g_strlcpy(query.hostname, hostname, sizeof(query.hostname));

	if (helper_alive) {	
		if (adns_do_write(adns_query_fd, &query, sizeof(query)))
			return;

		helper_alive = FALSE;
		CLOSE_IF_VALID(adns_query_fd);
		g_warning("adns_resolve: adns_do_write() failed using fall back");
		g_assert(NULL == cache);
		cache = adns_cache_init();
	}
	/* FALL THROUGH */
	adns_gethostbyname(cache, &query, &reply);
	g_assert(NULL != reply.user_callback);
	reply.user_callback(reply.ip, reply.user_data);
}

/*
 * adns_close
 *
 * Nothing for now  
 */
void adns_close(void)
{
	return;
}

