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
#include <errno.h>
#include "adns.h"
#include "http.h" /* MAX_HOSTLEN */

/* private data types */

typedef struct adns_query {
	gchar hostname[MAX_HOSTLEN + 1];
	adns_callback_t user_callback;
	gpointer user_data;
	gpointer data; 
} adns_query_t;

typedef struct adns_async_write {
	adns_query_t *query;	/* Original query */
	gchar *buf;				/* Remaining data to write */
	gint n;					/* Amount to write still */
} adns_async_write_t;


typedef struct adns_reply {
	adns_callback_t user_callback;
    gpointer user_data;
	gpointer data; 
    guint32 ip;
} adns_reply_t;

typedef struct adns_cache_entry {
	gchar *hostname; /* atom */
    guint32 ip;
	time_t timestamp;
} adns_cache_entry_t;

/* Cache entries will expire after ADNS_CACHE_TIMEOUT seconds */
#define ADNS_CACHE_TIMEOUT (5 * 60)
/* Cache max. ADNS_CACHED_NUM of adns_cache_entry_t entries */
#define ADNS_CACHED_NUM (1024)

#define ADNS_PROCESS_TITLE "DNS helper for gtk-gnutella"

typedef struct adns_cache_struct {
	guint size;
	guint oldest;
	time_t timeout;
	GHashTable *hashtab;
	adns_cache_entry_t entries[ADNS_CACHED_NUM];
} adns_cache_t;

static adns_cache_t *adns_cache = NULL;

/* private variables */

static gint adns_query_fd = -1;
static guint adns_query_event_id = 0;
static guint adns_reply_event_id = 0;
static gboolean is_helper = FALSE;		/* Are we the DNS helper process? */

static gboolean adns_helper_alive = TRUE;

/* private macros */

#define CLOSE_IF_VALID(fd)	\
do {						\
	if (-1 != (fd))	{		\
		close(fd);			\
		fd = -1;			\
	} 						\
} while(0) 					

/* private functions */

static adns_cache_t *adns_cache_init(void)
{
	adns_cache_t *cache;
	guint i;

	cache = g_malloc(sizeof(*cache)); 
	cache->size = G_N_ELEMENTS(cache->entries);
	cache->oldest = 0;
	cache->timeout = ADNS_CACHE_TIMEOUT;
	cache->hashtab = g_hash_table_new(NULL, NULL);
	for (i = 0; i < cache->size; i++)
		cache->entries[i].hostname = NULL;
	return cache;
}

/*
 *	adns_cache_free:
 *
 *	Frees all memory allocated by the cache and returns NULL. 
 */
adns_cache_t *adns_cache_free(adns_cache_t *cache)
{
	guint i;

	g_hash_table_destroy(cache->hashtab);
	cache->hashtab = NULL;
	for (i = 0; i < cache->size; i++)
		if (NULL != cache->entries[i].hostname)
			atom_str_free(cache->entries[i].hostname);
	cache->size = 0;
	return NULL;
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
	adns_cache_t *cache, time_t now, const gchar *hostname, guint32 ip)
{
	adns_cache_entry_t *entry;
	gchar *atom;
	g_assert(NULL != cache);
	g_assert(NULL != hostname);

	entry = &cache->entries[cache->oldest];
	atom = atom_str_get(hostname);
	g_assert(NULL == g_hash_table_lookup(cache->hashtab, hostname));
	if (NULL != entry->hostname) {
		g_hash_table_remove(cache->hashtab, entry->hostname);
		atom_str_free(entry->hostname);
	}
	entry->hostname = atom;
	entry->timestamp = now;
	entry->ip = ip;
	g_hash_table_insert(cache->hashtab, entry->hostname,
		GUINT_TO_POINTER(cache->oldest));

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
	adns_cache_t *cache, time_t now, const gchar *hostname, guint32 *ip)
{
	guint i;
	gpointer key;
	gpointer val;
	adns_cache_entry_t *entry;

	g_assert(NULL != cache);
	g_assert(NULL != hostname);

	if (!g_hash_table_lookup_extended(cache->hashtab, hostname, &key, &val))
		return FALSE;

	g_assert(hostname == key);
	i = GPOINTER_TO_UINT(val);
	g_assert(i < cache->size);
	entry = &cache->entries[i];
	g_assert(hostname == entry->hostname);

	if (entry->timestamp + cache->timeout > now) {
		if (NULL != ip)
			*ip = entry->ip;
		if (dbg > 0)
			g_warning("adns_cache_lookup: \"%s\" cached (ip=%s)",
				entry->hostname, ip_to_gchar(entry->ip));
		return TRUE;
	} else {
		if (dbg > 0)
			g_warning("adns_cache_lookup: removing \"%s\" from cache",
				entry->hostname);
		g_hash_table_remove(cache->hashtab, key);
		atom_str_free(key);
		entry->hostname = NULL;
		entry->timestamp = 0;
		entry->ip = 0;
	}

	return FALSE;
}

/*
 * adns_do_transfer
 *
 * Transfers the data in `buf' of size `len' through `fd'. If `do_write' is
 * FALSE the buffer will be filled from `fd'. Otherwise, the data from the
 * buffer will be written to `fd'. The function returns only if all data
 * has been transferred or if an unrecoverable error occurs. This function
 * should only be used with a blocking `fd'.
 */
static gboolean adns_do_transfer(
	gint fd, gpointer buf, size_t len, gboolean do_write)
{
	ssize_t ret;
	size_t n = len;

	while (n > 0) {
		if (dbg > 2)
			g_warning("adns_do_transfer: n=%lu", (gulong) n);

		if (do_write)
			ret = write(fd, buf, n);
		else 
			ret = read(fd, buf, n);
	
		if ((ssize_t) -1 == ret && errno != EAGAIN && errno != EINTR) {
            /* Ignore the failure, if the parent process is gone.
               This prevents an unnecessary warning when quitting. */
            if (!is_helper || getppid() != 1)
			    g_warning("adns_do_transfer: %s (errno=%d, do_write=%d)",
				    g_strerror(errno), errno, (gint) do_write);
			return FALSE;
		} else if (0 == ret) {
			/*
			 * Don't warn on EOF if we're the children process and our
			 * parent is gone.
			 */
			if (!do_write && !(is_helper && getppid() == 1))
				g_warning("adns_do_transfer: EOF (%s)",
					do_write ? "write" : "read");
			return FALSE;
		} else if (ret > 0) {
			n -= ret;
			buf = (gchar *) buf + ret;
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
static void adns_gethostbyname(const adns_query_t *query, adns_reply_t *reply)
{
	g_assert(NULL != query);
	g_assert(NULL != reply);

	if (dbg > 1)
		g_warning("adns_gethostbyname: Resolving \"%s\" ...", query->hostname);
	reply->user_callback = query->user_callback;
	reply->user_data = query->user_data;
	reply->data = query->data;
	reply->ip = host_to_ip(query->hostname);
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
	static adns_query_t query;
	static adns_reply_t reply;

	g_set_prgname(ADNS_PROCESS_TITLE);
	gm_setproctitle(g_get_prgname());

	signal(SIGQUIT, SIG_IGN);		/* Avoid core dumps on SIGQUIT */

	is_helper = TRUE;

	for (;;) {
		if (!adns_do_read(fd_in, &query, sizeof(query)))
			break;
		adns_gethostbyname(&query, &reply);
		if (!adns_do_write(fd_out, &reply, sizeof(reply)))
			break;
	}

	close(fd_in);
	close(fd_out);
	_exit(EXIT_SUCCESS);
}

/*
 * adns_fallback
 *
 * Handles the query in synchronous (blocking) mode and is used if the
 * dns helper is busy i.e., the pipe buffer is full or in case the dns
 * helper is dead.  
 */
static void adns_fallback(adns_query_t *query)
{
	adns_reply_t reply;

	g_assert(NULL != query);
	g_assert(NULL != query->data);

	atom_str_free(query->data);
	query->data = NULL;

	adns_gethostbyname(query, &reply);
	g_assert(NULL != reply.user_callback);
	reply.user_callback(reply.ip, reply.user_data);
}

/*
 * adns_reply_callback
 *
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., gtk-gnutella itself.
 * It handles partial reads if necessary. In case of an unrecoverable error
 * the reply pipe will be closed and the callback will be lost.
 */
static void adns_reply_callback(
	gpointer data, gint source, inputevt_cond_t condition)
{
	static size_t n = 0;
	static adns_reply_t reply;
	
	g_assert(sizeof(reply) >= n);

again:
	if (sizeof(reply) > n) {
		gpointer buf = (gchar *) &reply + n;
		ssize_t ret;

		ret = read(source, buf, sizeof(reply)-n);
		
		if (0 == ret) {
			errno = ECONNRESET;	
			ret = (ssize_t) -1;
		}
		/* FALL THROUGH */
		if ((ssize_t) -1 == ret) {
			if (errno != EAGAIN && errno != EINTR) {
				g_warning("adns_reply_callback: read() failed: %s",
					g_strerror(errno));
				inputevt_remove(adns_reply_event_id);
				g_warning("adns_reply_callback: removed myself");
				close(source);
				return;
			}
			goto again;
		}

		g_assert(ret > 0);
		n += (size_t) ret;
	}
	/* FALL THROUGH */
	if (sizeof(reply) == n) {
		time_t now = time(NULL);

		if (dbg > 1)
			g_warning("adns_reply_callback: Resolved \"%s\" to \"%s\".",
				(gchar *) reply.data, ip_to_gchar(reply.ip));
		g_assert(NULL != reply.user_callback);
		g_assert(NULL != reply.data);
		if (!adns_cache_lookup(adns_cache, now, reply.data, NULL))
			adns_cache_add(adns_cache, now, reply.data, reply.ip);
		atom_str_free(reply.data);
		reply.user_callback(reply.ip, reply.user_data);
		n = 0;
	}
}

/*
 * adns_query_write_alloc
 *
 * Allocate a the "spill" buffer for the query, with `n' bytes being already
 * written into the pipe.  The query is cloned.
 */
static adns_async_write_t *adns_async_write_alloc(adns_query_t *query, gint n)
{
	adns_async_write_t *remain;

	g_assert(n < sizeof(*query));

	remain = walloc(sizeof(*remain));
	remain->query = walloc(sizeof(*query));
	memcpy(remain->query, query, sizeof(*query));
	remain->buf = (gchar *) remain->query + n;
	remain->n = sizeof(*query) - n;

	return remain;
}

/*
 * adns_query_write_free
 *
 * Dispose of the "spill" buffer.
 */
static void adns_async_write_free(adns_async_write_t *remain)
{
	wfree(remain->query, sizeof(*remain->query));
	wfree(remain, sizeof(*remain));
}

/*
 * adns_query_callback
 *
 * Callback function for inputevt_add(). This function pipes the query to
 * the server using the pipe in non-blocking mode, partial writes are handled
 * appropriately. In case of an unrecoverable error the query pipe will be
 * closed and the blocking adns_fallback() will be invoked.
 */
static void adns_query_callback(
		gpointer data, gint dest, inputevt_cond_t condition)
{
	adns_async_write_t *remain = data;

	g_assert(NULL != remain);
	g_assert(dest == adns_query_fd);
	g_assert(0 != adns_query_event_id);

	if (condition & INPUT_EVENT_EXCEPTION) {
		g_warning("adns_query_callback: write exception");
		goto abort;
	}

	while (remain->n > 0) {
		ssize_t ret;

		ret = write(dest, remain->buf, remain->n);
		
		if (0 == ret) {
			errno = ECONNRESET;	
			ret = (ssize_t) -1;
		}
		/* FALL THROUGH */
		if ((ssize_t) -1 == ret) {
			if (errno != EAGAIN && errno != EINTR)
				goto error;
			return;
		}

		g_assert(ret > 0);	
		remain->n -= (size_t) ret;
		remain->buf += (size_t) ret;
		g_assert(remain->n >= 0);
	}

	inputevt_remove(adns_query_event_id);
	adns_query_event_id = 0;
	adns_async_write_free(remain);

	return;

error:
	g_warning("adns_query_callback: write() failed: %s", g_strerror(errno));
abort:
	inputevt_remove(adns_query_event_id);
	g_warning("adns_query_callback: removed myself");
	adns_helper_alive = FALSE;
	CLOSE_IF_VALID(adns_query_fd);
	g_warning("adns_query_callback: using fallback");
	adns_fallback(remain->query);
}

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
	fcntl(adns_query_fd, F_SETFL, O_NONBLOCK);
	fcntl(fd_reply[0], F_SETFL, O_NONBLOCK);
	adns_cache = adns_cache_init();
	adns_reply_event_id = inputevt_add(fd_reply[0],
		INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
		adns_reply_callback, NULL);
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
 *
 * Returns TRUE if the resolution is asynchronous i.e., the callback
 * will be called AFTER adns_resolve() returned. If the resolution is
 * synchronous i.e., the callback was called BEFORE adns_resolve()
 * returned, adns_resolve() returns FALSE.
 */
gboolean adns_resolve(
	const gchar *hostname, adns_callback_t user_callback, gpointer user_data)
{
	gsize hostname_len;
	static adns_query_t query;
	static adns_reply_t reply;

	g_assert(NULL != hostname);
	g_assert(NULL != user_callback);

	query.user_callback = user_callback;
	query.user_data = user_data;
	reply.ip = gchar_to_ip(hostname);
	if (0 != reply.ip) {
		query.user_callback(reply.ip, query.user_data);
		return FALSE; /* synchronous */
	}

	hostname_len = g_strlcpy(query.hostname, hostname, sizeof(query.hostname));
	if (hostname_len >= sizeof(query.hostname)) {
		/* truncation detected */
		query.user_callback(0, query.user_data);
		return FALSE; /* synchronous */
	}

	strlower(query.hostname, hostname);
	query.data = atom_str_get(query.hostname);
	if (adns_cache_lookup(adns_cache, time(NULL), query.data, &reply.ip)) {
		atom_str_free(query.data);
		query.user_callback(reply.ip, query.user_data);
		return FALSE; /* synchronous */
	}

	if (adns_helper_alive && 0 == adns_query_event_id) {
		adns_query_t q;
		gint written;

		g_assert(adns_query_fd >= 0);
		g_assert(hostname_len < sizeof(q.hostname));

		memcpy(q.hostname, query.data, hostname_len + 1);
		q.user_callback = user_callback;
		q.user_data = user_data;
		q.data = query.data;

		/*
		 * Try to write the query atomically into the pipe.
		 */

		written = write(adns_query_fd, &q, sizeof(q));

		if (written == -1) {
			if (errno != EINTR && errno != EAGAIN) {
				g_warning("adns_resolve: write() failed: %s",
					g_strerror(errno));
				adns_helper_alive = FALSE;
				CLOSE_IF_VALID(adns_query_fd);
				goto fallback;
			}
			written = 0;
		}

		g_assert(0 == adns_query_event_id);

		/*
		 * If not written fully, allocate a spill buffer and record
		 * callback that will write the remaining data when the pipe
		 * can absorb new data.
		 */

		if (written < sizeof(q)) {
			adns_async_write_t *aq = adns_async_write_alloc(&q, written);

			adns_query_event_id = inputevt_add(adns_query_fd,
				INPUT_EVENT_WRITE | INPUT_EVENT_EXCEPTION,
				adns_query_callback, aq);
		}

		return TRUE; /* asynchronous */ 
	}

fallback:
	g_warning("adns_resolve: using synchronous resolution for \"%s\"",
		(gchar *) query.data);

	adns_fallback(&query);

	return FALSE; /* synchronous */
}

/*
 * adns_close
 *
 * Removes the callback and frees the cache.
 */
void adns_close(void)
{
	inputevt_remove(adns_reply_event_id);
	adns_cache = adns_cache_free(adns_cache);
}
