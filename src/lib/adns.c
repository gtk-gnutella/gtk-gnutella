/*
 * $Id$
 *
 * Copyright (c) 2004, Christian Biere
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

/**
 * @ingroup lib
 * @file
 *
 * Asynchronous DNS lookup.
 *
 * @author Christian Biere
 * @date 2004
 */

#include "common.h"

RCSID("$Id$");

#include "adns.h"
#include "atoms.h"
#include "inputevt.h"
#include "misc.h"
#include "glib-missing.h"
#include "tm.h"
#include "walloc.h"
#include "socket.h"

#include "override.h"		/* Must be the last header included */

static guint32 common_dbg = 0;	/**< @bug XXX need to init lib's props --RAM */

/* private data types */

typedef struct adns_query {
	void (*user_callback)(void);
	gpointer user_data;
	host_addr_t addr;
	gboolean reverse;
	gchar hostname[MAX_HOSTLEN + 1];
} adns_query_t;

typedef struct adns_async_write {
	adns_query_t *query;	/**< Original query */
	gchar *buf;				/**< Remaining data to write */
	gint n;					/**< Amount to write still */
} adns_async_write_t;

typedef struct adns_cache_entry {
	gchar *hostname;		/**< atom */
	host_addr_t addr;
	time_t timestamp;
} adns_cache_entry_t;

/**
 * Cache entries will expire after ADNS_CACHE_TIMEOUT seconds.
 */
#define ADNS_CACHE_TIMEOUT (5 * 60)
/**
 * Cache max. ADNS_CACHED_NUM of adns_cache_entry_t entries.
 */
#define ADNS_CACHED_NUM (1024)

#define ADNS_PROCESS_TITLE "DNS helper for gtk-gnutella"

typedef struct adns_cache_struct {
	guint size;
	guint oldest;
	guint timeout;
	GHashTable *hashtab;
	adns_cache_entry_t entries[ADNS_CACHED_NUM];
} adns_cache_t;

static adns_cache_t *adns_cache = NULL;

/* private variables */

static gint adns_query_fd = -1;
static guint adns_query_event_id = 0;
static guint adns_reply_event_id = 0;
static gboolean is_helper = FALSE;		/**< Are we the DNS helper process? */

/**
 * Private macros.
 */

#define CLOSE_IF_VALID(fd)	\
do {						\
	if (-1 != (fd))	{		\
		close(fd);			\
		fd = -1;			\
	} 						\
} while(0)

/**
 * Private functions.
 */

static adns_cache_t *
adns_cache_init(void)
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

/**
 * Frees all memory allocated by the cache and returns NULL.
 */
void
adns_cache_free(adns_cache_t *cache)
{
	guint i;

	g_hash_table_destroy(cache->hashtab);
	cache->hashtab = NULL;
	for (i = 0; i < cache->size; i++)
		if (NULL != cache->entries[i].hostname)
			atom_str_free(cache->entries[i].hostname);
	cache->size = 0;
	G_FREE_NULL(cache);
}

/* these are not needed anywhere else so undefine them */
#undef ADNS_CACHED_NUM
#undef ADNS_CACHE_TIMEOUT

/**
 * Adds ``hostname'' and ``addr'' to the cache. The cache is implemented
 * as a wrap-around FIFO. In case it's full, the oldest entry will be
 * overwritten.
 */
static void
adns_cache_add(adns_cache_t *cache, time_t now,
	const gchar *hostname, const host_addr_t addr)
{
	adns_cache_entry_t *entry;
	gchar *atom;
	g_assert(NULL != cache);
	g_assert(NULL != hostname);

	entry = &cache->entries[cache->oldest];
	atom = atom_str_get(hostname);
	g_assert(NULL == g_hash_table_lookup(cache->hashtab, atom));
	if (NULL != entry->hostname) {
		g_hash_table_remove(cache->hashtab, entry->hostname);
		atom_str_free(entry->hostname);
	}
	entry->hostname = atom;
	entry->timestamp = now;
	entry->addr = addr;
	g_hash_table_insert(cache->hashtab, entry->hostname,
		GUINT_TO_POINTER(cache->oldest));

	cache->oldest++;
	cache->oldest %= cache->size;
}

/**
 * Looks for ``hostname'' in ``cache'' wrt to cache->timeout. If
 * ``hostname'' is not found or the entry is expired, FALSE will be
 * returned. Expired entries will be removed! ``addr'' is allowed to
 * be NULL, otherwise the cached IP will be stored into the variable
 * ``addr'' points to.
 */
static gboolean
adns_cache_lookup(adns_cache_t *cache, time_t now,
	const gchar *hostname, host_addr_t *addr)
{
	guint i;
	gpointer key;
	gpointer val;
	adns_cache_entry_t *entry;
	gpointer atom;
	gboolean found;

	g_assert(NULL != cache);
	g_assert(NULL != hostname);

	atom = atom_str_get(hostname);
	found = g_hash_table_lookup_extended(cache->hashtab, atom, &key, &val);
	g_assert(!found || atom == key);

	if (!found) {
		atom_str_free(atom);
		return FALSE;
	}

	i = GPOINTER_TO_UINT(val);
	g_assert(i < cache->size);
	entry = &cache->entries[i];
	g_assert(atom == entry->hostname);
	atom_str_free(atom);
	atom = NULL;

	if (delta_time(now, entry->timestamp) < cache->timeout) {
		if (NULL != addr)
			*addr = entry->addr;
		if (common_dbg > 0)
			g_warning("adns_cache_lookup: \"%s\" cached (addr=%s)",
				entry->hostname, host_addr_to_string(entry->addr));
		return TRUE;
	} else {
		if (common_dbg > 0)
			g_warning("adns_cache_lookup: removing \"%s\" from cache",
				entry->hostname);
		g_hash_table_remove(cache->hashtab, key);
		atom_str_free(key);
		entry->hostname = NULL;
		entry->timestamp = 0;
		entry->addr = zero_host_addr;
	}

	return FALSE;
}

/**
 * Transfers the data in `buf' of size `len' through `fd'. If `do_write' is
 * FALSE the buffer will be filled from `fd'. Otherwise, the data from the
 * buffer will be written to `fd'. The function returns only if all data
 * has been transferred or if an unrecoverable error occurs. This function
 * should only be used with a blocking `fd'.
 */
static gboolean
adns_do_transfer(gint fd, gpointer buf, size_t len, gboolean do_write)
{
	ssize_t ret;
	size_t n = len;

	while (n > 0) {
		if (common_dbg > 2)
			g_warning("adns_do_transfer: n=%lu", (gulong) n);

		if (do_write)
			ret = write(fd, buf, n);
		else
			ret = read(fd, buf, n);

		if ((ssize_t) -1 == ret && errno != VAL_EAGAIN && errno != EINTR) {
            /* Ignore the failure, if the parent process is gone.
               This prevents an unnecessary warning when quitting. */
            if (!is_helper || getppid() != 1)
			    g_warning("adns_do_transfer: %s (errno=%d, do_write=%d)",
				    g_strerror(errno), errno, (gint) do_write);
			return FALSE;
		} else if (0 == ret) {
			/*
			 * Don't warn on EOF if this is the child process and the
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

/**
 * Read the complete buffer ``buf'' of size ``len'' from file descriptor ``fd''
 *
 * @return TRUE on success, FALSE if the operation failed
 */
static gboolean
adns_do_read(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, FALSE);
}

/**
 * Write the complete buffer ``buf'' of size ``len'' to file descriptor ``fd''
 *
 * @return TRUE on success, FALSE if the operation failed
 */
static gboolean
adns_do_write(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, TRUE);
}

/**
 * Copies user_callback and user_data from the query buffer to the
 * reply buffer. This function won't fail. However, if gethostbyname()
 * fails ``reply->addr'' will be set to zero.
 */
static void
adns_gethostbyname(const adns_query_t *query, adns_query_t *reply)
{
	const gchar *host;

	g_assert(NULL != query);
	g_assert(NULL != reply);

	if (common_dbg > 1) {
		g_message("adns_gethostbyname: Resolving \"%s\" ...",
			query->reverse
				? host_addr_to_string(query->addr)
				: query->hostname);
	}

	reply->user_callback = query->user_callback;
	reply->user_data = query->user_data;
	reply->reverse = query->reverse;
	reply->addr = query->reverse
		? query->addr
		: name_to_host_addr(query->hostname);
	host = query->reverse
		? host_addr_to_name(query->addr)
		: query->hostname;
	g_strlcpy(reply->hostname, host ? host : "", sizeof reply->hostname);
}

/**
 * The ``main'' function of the adns helper process (server).
 *
 * Simply reads requests (queries) from fd_in, performs a DNS lookup for it
 * and writes the result to fd_out. All operations should be blocking. Exits
 * in case of non-recoverable error during read or write.
 */
static void
adns_helper(gint fd_in, gint fd_out)
{
	static adns_query_t query, reply;

	g_set_prgname(ADNS_PROCESS_TITLE);
	gm_setproctitle(g_get_prgname());

#ifdef SIGQUIT 
	set_signal(SIGQUIT, SIG_IGN);	/* Avoid core dumps on SIGQUIT */
#endif

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

static inline void
adns_invoke_user_callback(adns_query_t *reply)
{
	if (reply->reverse) {
		adns_reverse_callback_t func;

		func = (adns_reverse_callback_t) reply->user_callback;
		func(reply->hostname[0] != '\0' ? reply->hostname : NULL,
			reply->user_data);
	} else {
		adns_callback_t func;

		func = (adns_callback_t) reply->user_callback;
		func(is_host_addr(reply->addr) ? &reply->addr : NULL, reply->user_data);
	}
}

/**
 * Handles the query in synchronous (blocking) mode and is used if the
 * dns helper is busy i.e., the pipe buffer is full or in case the dns
 * helper is dead.
 */
static void
adns_fallback(const adns_query_t *query)
{
	adns_query_t reply;

	g_assert(NULL != query);
	adns_gethostbyname(query, &reply);
	g_assert(NULL != reply.user_callback);
	adns_invoke_user_callback(&reply);
}

/**
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., gtk-gnutella itself.
 * It handles partial reads if necessary. In case of an unrecoverable error
 * the reply pipe will be closed and the callback will be lost.
 */
static void
adns_reply_callback(gpointer data, gint source, inputevt_cond_t condition)
{
	static size_t n = 0;
	static adns_query_t reply;

	g_assert(NULL == data);
	g_assert(condition & INPUT_EVENT_RX);
	g_assert(sizeof reply >= n);

again:
	if (sizeof reply > n) {
		gpointer buf = cast_to_gchar_ptr(&reply) + n;
		ssize_t ret;

		ret = read(source, buf, sizeof reply - n);

		if (0 == ret) {
			errno = ECONNRESET;
			ret = (ssize_t) -1;
		}
		/* FALL THROUGH */
		if ((ssize_t) -1 == ret) {
			if (errno != VAL_EAGAIN && errno != EINTR) {
				g_warning("adns_reply_callback: read() failed: %s",
					g_strerror(errno));
				inputevt_remove(adns_reply_event_id);
				adns_reply_event_id = 0;
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
	if (sizeof reply == n) {
		time_t now = tm_time();

		if (common_dbg > 1) {
			const gchar *host, *addr;

			host = reply.hostname;
			addr = host_addr_to_string(reply.addr);
			g_warning("adns_reply_callback: Resolved \"%s\" to \"%s\".",
				reply.reverse ? addr : host, reply.reverse ? host : addr);
		}

		g_assert(NULL != reply.user_callback);
		if (
				!reply.reverse &&
				!adns_cache_lookup(adns_cache, now, reply.hostname, NULL)
		) {
			adns_cache_add(adns_cache, now, reply.hostname, reply.addr);
		}

		adns_invoke_user_callback(&reply);
		n = 0;
	}
}

/**
 * Allocate a the "spill" buffer for the query, with `n' bytes being already
 * written into the pipe.  The query is cloned.
 */
static adns_async_write_t *
adns_async_write_alloc(const adns_query_t *query, size_t n)
{
	adns_async_write_t *remain;

	g_assert(n < sizeof *query);

	remain = walloc(sizeof *remain);
	remain->query = walloc(sizeof *query);
	memcpy(remain->query, query, sizeof *query);
	remain->buf = cast_to_gchar_ptr(remain->query) + n;
	remain->n = sizeof *query - n;

	return remain;
}

/**
 * Dispose of the "spill" buffer.
 */
static void
adns_async_write_free(adns_async_write_t *remain)
{
	wfree(remain->query, sizeof *remain->query);
	wfree(remain, sizeof *remain);
}

/**
 * Callback function for inputevt_add(). This function pipes the query to
 * the server using the pipe in non-blocking mode, partial writes are handled
 * appropriately. In case of an unrecoverable error the query pipe will be
 * closed and the blocking adns_fallback() will be invoked.
 */
static void
adns_query_callback(gpointer data, gint dest, inputevt_cond_t condition)
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
			if (errno != VAL_EAGAIN && errno != EINTR)
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
	g_warning("adns_query_callback: removed myself");
	inputevt_remove(adns_query_event_id);
	adns_query_event_id = 0;
	CLOSE_IF_VALID(adns_query_fd);
	g_warning("adns_query_callback: using fallback");
	adns_fallback(remain->query);
}

/* public functions */

/**
 * Initializes the adns helper i.e., fork()s a child process which will
 * be used to resolve hostnames asynchronously.
 */
void
adns_init(void)
{
	gint fd_query[2] = {-1, -1};
	gint fd_reply[2] = {-1, -1};
	pid_t pid;

	if (-1 == pipe(fd_query) || -1 == pipe(fd_reply)) {
		g_warning("adns_init: pipe() failed: %s", g_strerror(errno));
		goto prefork_failure;
	}
	
#ifdef SIGCHLD 
	set_signal(SIGCHLD, SIG_IGN); /* prevent a zombie */
#endif

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
			g_error("adns_init: Could not open() /dev/null: %s",
				g_strerror(errno));
		g_assert(STDIN_FILENO == null);
		adns_helper(fd_query[0], fd_reply[1]);
		g_assert_not_reached();
		_exit(EXIT_SUCCESS);
	}

	/* parent process */
	close(fd_query[0]);
	close(fd_reply[1]);
	adns_query_fd = fd_query[1];

	socket_set_nonblocking(adns_query_fd);
	socket_set_nonblocking(fd_reply[0]);
	
	adns_reply_event_id = inputevt_add(fd_reply[0], INPUT_EVENT_RX,
							adns_reply_callback, NULL);
	/* FALL THROUGH */
prefork_failure:

	if (!adns_reply_event_id) {
		g_warning("Cannot use ADNS; DNS lookups may cause stalling");
		CLOSE_IF_VALID(fd_query[0]);
		CLOSE_IF_VALID(fd_query[1]);
		CLOSE_IF_VALID(fd_reply[0]);
		CLOSE_IF_VALID(fd_reply[1]);
	}

	adns_cache = adns_cache_init();
}

/**
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
adns_send_query(const adns_query_t *query)
{
	ssize_t written;
	adns_query_t q;

	if (!adns_reply_event_id || 0 != adns_query_event_id)
		return FALSE;

	g_assert(adns_query_fd >= 0);
	q = *query;

	/*
	 * Try to write the query atomically into the pipe.
	 */

	written = write(adns_query_fd, &q, sizeof q);
	if (written == (ssize_t) -1) {
		if (errno != EINTR && errno != VAL_EAGAIN) {
			g_warning("adns_resolve: write() failed: %s",
				g_strerror(errno));
			inputevt_remove(adns_reply_event_id);
			adns_reply_event_id = 0;
			CLOSE_IF_VALID(adns_query_fd);
			return FALSE;
		}
		written = 0;
	}

	g_assert(0 == adns_query_event_id);

	/*
	 * If not written fully, allocate a spill buffer and record
	 * callback that will write the remaining data when the pipe
	 * can absorb new data.
	 */

	if (written < (ssize_t) sizeof q) {
		adns_async_write_t *aq = adns_async_write_alloc(&q, written);

		adns_query_event_id = inputevt_add(adns_query_fd, INPUT_EVENT_WX,
								adns_query_callback, aq);
	}

	return TRUE;
}

/**
 * Creates a DNS resolve query for ``hostname''.
 *
 * The given function ``user_callback'' (which MUST NOT be NULL)
 * will be invoked with the resolved IP address and ``user_data''
 * as its parameters. The IP address 0.0.0.0 i.e., ``(guint32) 0''
 * is used to indicate a failure. In case the hostname is given as
 * an IP string, it will be directly converted and the callback
 * immediately invoked. If the adns helper process is ``out of service''
 * the query will be resolved synchronously.
 *
 * @return TRUE if the resolution is asynchronous i.e., the callback
 * will be called AFTER adns_resolve() returned. If the resolution is
 * synchronous i.e., the callback was called BEFORE adns_resolve()
 * returned, adns_resolve() returns FALSE.
 */
gboolean
adns_resolve(const gchar *hostname,
	adns_callback_t user_callback, gpointer user_data)
{
	static adns_query_t query, reply;
	size_t hostname_len;

	g_assert(NULL != hostname);
	g_assert(NULL != user_callback);

	query.user_callback = (void (*)(void)) user_callback;
	query.user_data = user_data;
	query.reverse = FALSE;
	query.addr = zero_host_addr;
	reply = query;

	if (string_to_host_addr(hostname, NULL, &reply.addr)) {
		adns_invoke_user_callback(&reply);
		return FALSE; /* synchronous */
	}

	hostname_len = g_strlcpy(query.hostname, hostname, sizeof(query.hostname));
	if (hostname_len >= sizeof(query.hostname)) {
		/* truncation detected */
		reply.addr = zero_host_addr;
		adns_invoke_user_callback(&reply);
		return FALSE; /* synchronous */
	}

	ascii_strlower(query.hostname, hostname);
	if (
		adns_cache_lookup(adns_cache, tm_time(), query.hostname, &reply.addr)
	) {
		adns_invoke_user_callback(&reply);
		return FALSE; /* synchronous */
	}

	if (adns_send_query(&query))
		return TRUE; /* asynchronous */

	if (adns_reply_event_id)
		g_warning("adns_resolve: using synchronous resolution for \"%s\"",
			query.hostname);

	adns_fallback(&query);

	return FALSE; /* synchronous */
}

/**
 * Creates a DNS reverse lookup query for ``addr''. The given function
 * ``user_callback'' (which MUST NOT be NULL) will be invoked with
 * the resolved hostname and ``user_data'' as its parameters. If the lookup
 * failed, the callback will be invoked with ``hostname'' NULL. If the adns
 * helper process is ``out of service'' the query will be processed
 * synchronously.
 *
 * @return TRUE if the resolution is asynchronous i.e., the callback
 * will be called AFTER adns_reverse_lookup() returned. If the resolution is
 * synchronous i.e., the callback was called BEFORE adns_reverse_lookup()
 * returned, adns_reverse_lookup() returns FALSE.
 */
gboolean
adns_reverse_lookup(const host_addr_t addr,
	adns_reverse_callback_t user_callback, gpointer user_data)
{
	static adns_query_t query;

	g_assert(user_callback);

	query.user_callback = (void (*)(void)) user_callback;
	query.user_data = user_data;
	query.addr = addr;
	query.reverse = TRUE;
	query.hostname[0] = '\0';

	if (adns_send_query(&query))
		return TRUE; /* asynchronous */

	g_warning("adns_reverse_lookup: using synchronous resolution for \"%s\"",
		host_addr_to_string(query.addr));

	adns_fallback(&query);

	return FALSE; /* synchronous */
}

/**
 * Removes the callback and frees the cache.
 */
void
adns_close(void)
{
	if (adns_reply_event_id) {
		inputevt_remove(adns_reply_event_id);
		adns_reply_event_id = 0;
	}
	if (adns_query_event_id) {
		inputevt_remove(adns_query_event_id);
		adns_query_event_id = 0;
	}
	
	adns_cache_free(adns_cache);
	adns_cache = NULL;
}

/* vi: set ts=4 sw=4 cindent: */
