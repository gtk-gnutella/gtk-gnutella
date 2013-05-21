/*
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

#include "adns.h"
#include "adns_msg.h"

#include "ascii.h"
#include "atoms.h"
#include "debug.h"
#include "fd.h"
#include "glib-missing.h"
#include "hikset.h"
#include "inputevt.h"
#include "signal.h"
#include "tm.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

/* private data types */

typedef struct adns_async_write {
	struct adns_request req;	/**< The original ADNS request */
	char *buf;					/**< Remaining data to write; walloc()ed */
	size_t pos;					/**< Read position */
	size_t size;				/**< Size of the buffer */
} adns_async_write_t;

typedef struct adns_cache_entry {
	const char *hostname;		/**< atom */
	time_t timestamp;
	size_t n;				/**< Number of addr items */
	unsigned id;
	host_addr_t addrs[1 /* pseudo-size */];
} adns_cache_entry_t;

static inline size_t
adns_cache_entry_size(size_t n)
{
	struct adns_cache_entry *entry;
	g_assert(n > 0);
	g_assert(((size_t) -1 - sizeof *entry) / sizeof entry->addrs[0] > n);

	return sizeof *entry + n * sizeof entry->addrs[0];
}

static inline size_t
count_addrs(const host_addr_t *addrs, size_t m)
{
	size_t n;

	for (n = 0; n < m; n++) {
		if (!is_host_addr(addrs[n]))
			break;
	}
	return n;
}
	
/**
 * Cache entries will expire after ADNS_CACHE_TIMEOUT seconds.
 */
#define ADNS_CACHE_TIMEOUT (60)
/**
 * Cache max. ADNS_CACHE_SIZE of adns_cache_entry_t entries.
 */
#define ADNS_CACHE_MAX_SIZE (1024)

static const char adns_process_title[] = "DNS helper for gtk-gnutella";

typedef struct adns_cache_struct {
	hikset_t *ht;
	unsigned pos;
	int timeout;
	adns_cache_entry_t *entries[ADNS_CACHE_MAX_SIZE];
} adns_cache_t;

static adns_cache_t *adns_cache = NULL;

/* private variables */

#ifndef MINGW32
static int adns_query_fd = -1;
static unsigned adns_query_event_id;
#endif	/* !MINGW32 */
static unsigned adns_reply_event_id;
static bool is_helper;		/**< Are we the DNS helper process? */

/**
 * Private functions.
 */

static adns_cache_t *
adns_cache_init(void)
{
	adns_cache_t *cache;
	size_t i;

	XMALLOC(cache);
	cache->timeout = ADNS_CACHE_TIMEOUT;
	cache->ht = hikset_create(
		offsetof(adns_cache_entry_t, hostname), HASH_KEY_STRING, 0);
	cache->pos = 0;
	for (i = 0; i < G_N_ELEMENTS(cache->entries); i++) {
		cache->entries[i] = NULL;
	}
	return cache;
}

/* these are not needed anywhere else so undefine them */
#undef ADNS_CACHE_MAX_SIZE
#undef ADNS_CACHE_TIMEOUT

static inline adns_cache_entry_t *
adns_cache_get_entry(adns_cache_t *cache, unsigned i)
{
	adns_cache_entry_t *entry;
	
	g_assert(cache);
	g_assert(i < G_N_ELEMENTS(cache->entries));

	entry = cache->entries[i];
	if (entry) {
		g_assert(i == entry->id);
		g_assert(entry->hostname);
		g_assert(entry->n > 0);
	}
	return entry;
}

static void
adns_cache_free_entry(adns_cache_t *cache, unsigned i)
{
	adns_cache_entry_t *entry;

	g_assert(cache);
	g_assert(i < G_N_ELEMENTS(cache->entries));

	entry = cache->entries[i];
	if (entry) {
		g_assert(i == entry->id);
		g_assert(entry->hostname);
		g_assert(entry->n > 0);

		atom_str_free_null(&entry->hostname);
		wfree(entry, adns_cache_entry_size(entry->n));
		cache->entries[i] = NULL;
	}
}

/**
 * Frees all memory allocated by the cache and returns NULL.
 */
static void
adns_cache_free(adns_cache_t **cache_ptr)
{
	adns_cache_t *cache = *cache_ptr;
	unsigned i;

	/* If adns is not used it will not be initialized */
	if (NULL == cache)
		return;

	g_assert(cache);
	g_assert(cache->ht);

	for (i = 0; i < G_N_ELEMENTS(cache->entries); i++) {
		adns_cache_free_entry(cache, i);
	}
	hikset_free_null(&cache->ht);
	XFREE_NULL(cache);
}

#ifndef MINGW32
/**
 * Adds ``hostname'' and ``addr'' to the cache. The cache is implemented
 * as a wrap-around FIFO. In case it's full, the oldest entry will be
 * overwritten.
 */
static void
adns_cache_add(adns_cache_t *cache, time_t now,
	const char *hostname, const host_addr_t *addrs, size_t n)
{
	adns_cache_entry_t *entry;
	size_t i;
	
	g_assert(NULL != addrs);
	g_assert(NULL != cache);
	g_assert(NULL != hostname);
	g_assert(n > 0);

	g_assert(!hikset_contains(cache->ht, hostname));
	g_assert(cache->pos < G_N_ELEMENTS(cache->entries));
	
	entry = adns_cache_get_entry(cache, cache->pos);
	if (entry) {
		g_assert(entry->hostname);
		g_assert(entry == hikset_lookup(cache->ht, entry->hostname));

		hikset_remove(cache->ht, entry->hostname);
		adns_cache_free_entry(cache, cache->pos);
		entry = NULL;
	}

	entry = walloc(adns_cache_entry_size(n));
	entry->n = n;
	entry->hostname = atom_str_get(hostname);
	entry->timestamp = now;
	entry->id = cache->pos;
	for (i = 0; i < entry->n; i++) {
		entry->addrs[i] = addrs[i];
	}
	hikset_insert_key(cache->ht, &entry->hostname);
	cache->entries[cache->pos++] = entry;
	cache->pos %= G_N_ELEMENTS(cache->entries);
}
#endif	/* !MINGW32 */

/**
 * Looks for ``hostname'' in ``cache'' wrt to cache->timeout. If
 * ``hostname'' is not found or the entry is expired, FALSE will be
 * returned. Expired entries will be removed! ``addr'' is allowed to
 * be NULL, otherwise the cached IP will be stored into the variable
 * ``addr'' points to.
 *
 * @param addrs An array of host_addr_t items. If not NULL, up to
 *              ``n'' items will be copied from the cache.
 * @param n The number of items "addrs" can hold.
 * @return The number of cached addresses for the given hostname.
 */
static size_t
adns_cache_lookup(adns_cache_t *cache, time_t now,
	const char *hostname, host_addr_t *addrs, size_t n)
{
	adns_cache_entry_t *entry;

	g_assert(NULL != cache);
	g_assert(NULL != hostname);
	g_assert(0 == n || NULL != addrs);

	entry = hikset_lookup(cache->ht, hostname);
	if (entry) {
		if (delta_time(now, entry->timestamp) < cache->timeout) {
			size_t i;

			for (i = 0; i < n; i++) {
				if (i < entry->n) {
					addrs[i] = entry->addrs[i];
					if (common_dbg > 0)
						g_debug("%s: \"%s\" cached (addr=%s)", G_STRFUNC,
							entry->hostname, host_addr_to_string(addrs[i]));
				} else {
					addrs[i] = zero_host_addr;
				}
			}
		} else {
			if (common_dbg > 0) {
				g_debug("%s: removing \"%s\" from cache",
					G_STRFUNC, entry->hostname);
			}

			hikset_remove(cache->ht, hostname);
			adns_cache_free_entry(cache, entry->id);
			entry = NULL;
		}
	}

	return entry ? entry->n : 0;
}

/**
 * Transfers the data in `buf' of size `len' through `fd'. If `do_write' is
 * FALSE the buffer will be filled from `fd'. Otherwise, the data from the
 * buffer will be written to `fd'. The function returns only if all data
 * has been transferred or if an unrecoverable error occurs. This function
 * should only be used with a blocking `fd'.
 */
static bool
adns_do_transfer(int fd, void *buf, size_t len, bool do_write)
{
	ssize_t ret;
	size_t n = len;

	while (n > 0) {
		if (common_dbg > 2)
			g_debug("%s (%s): n=%zu", G_STRFUNC,
				do_write ? "write" : "read", n);

		if (do_write)
			ret = write(fd, buf, n);
		else
			ret = read(fd, buf, n);

		if ((ssize_t) -1 == ret && !is_temporary_error(errno)) {
            /* Ignore the failure, if the parent process is gone.
               This prevents an unnecessary warning when quitting. */
            if (!is_helper || getppid() != 1)
			    g_warning("%s (%s): %m",
					G_STRFUNC, do_write ? "write" : "read");
			return FALSE;
		} else if (0 == ret) {
			/*
			 * Don't warn on EOF if this is the child process and the
			 * parent is gone.
			 */
			if (!do_write && !(is_helper && getppid() == 1))
				g_warning("%s (%s): EOF",
					G_STRFUNC, do_write ? "write" : "read");
			return FALSE;
		} else if (ret > 0) {
			n -= ret;
			buf = (char *) buf + ret;
		}
	}

	return TRUE;
}

/**
 * Read the complete buffer ``buf'' of size ``len'' from file descriptor ``fd''
 *
 * @return TRUE on success, FALSE if the operation failed
 */
static inline bool
adns_do_read(int fd, void *buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, FALSE);
}

/**
 * Write the complete buffer ``buf'' of size ``len'' to file descriptor ``fd''
 *
 * @return TRUE on success, FALSE if the operation failed
 */
static inline bool
adns_do_write(int fd, void *buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, TRUE);
}

/**
 * Copies user_callback and user_data from the query buffer to the
 * reply buffer. This function won't fail. However, if gethostbyname()
 * fails ``reply->addr'' will be set to zero.
 */
static void
adns_gethostbyname(const struct adns_request *req, struct adns_response *ans)
{
	g_assert(NULL != req);
	g_assert(NULL != ans);

	ans->common = req->common;

	if (req->common.reverse) {
		const struct adns_reverse_query *query = &req->query.reverse;
		struct adns_reverse_reply *reply = &ans->reply.reverse;
		const char *host;

		if (common_dbg > 1) {
			g_debug("%s: resolving \"%s\" ...",
					G_STRFUNC, host_addr_to_string(query->addr));
		}

		reply->addr = query->addr;
		host = host_addr_to_name(query->addr);
		clamp_strcpy(reply->hostname, sizeof reply->hostname, host ? host : "");
	} else {
		const struct adns_query *query = &req->query.by_addr;
		struct adns_reply *reply = &ans->reply.by_addr;
		GSList *sl_addr, *sl;
		size_t i = 0;

		if (common_dbg > 1) {
			g_debug("%s: resolving \"%s\" ...", G_STRFUNC, query->hostname);
		}
		clamp_strcpy(reply->hostname, sizeof reply->hostname, query->hostname);

		sl_addr = name_to_host_addr(query->hostname, query->net);
		for (sl = sl_addr; NULL != sl; sl = g_slist_next(sl)) {
			host_addr_t *addr = sl->data;
			g_assert(addr);
			if (i >= G_N_ELEMENTS(reply->addrs)) {
				break;
			}
			reply->addrs[i++] = *addr;
		}
		host_addr_free_list(&sl_addr);

		if (i < G_N_ELEMENTS(reply->addrs)) {
			reply->addrs[i] = zero_host_addr;
		}
	}
}

#ifndef MINGW32
/**
 * The ``main'' function of the adns helper process (server).
 *
 * Simply reads requests (queries) from fd_in, performs a DNS lookup for it
 * and writes the result to fd_out. All operations should be blocking. Exits
 * in case of non-recoverable error during read or write.
 */
static void
adns_helper(int fd_in, int fd_out)
{
	g_set_prgname(adns_process_title);
	gm_setproctitle(g_get_prgname());

#ifdef SIGQUIT 
	signal_set(SIGQUIT, SIG_IGN);	/* Avoid core dumps on SIGQUIT */
#endif

	is_helper = TRUE;

	for (;;) {
		struct adns_request req;
		struct adns_response ans;
		size_t size;
		void *buf;

		if (!adns_do_read(fd_in, &req.common, sizeof req.common))
			break;

		if (ADNS_COMMON_MAGIC != req.common.magic)
			break;
	
		if (req.common.reverse) {	
			size = sizeof req.query.reverse;
			buf = &req.query.reverse;
		} else {
			size = sizeof req.query.by_addr;
			buf = &req.query.by_addr;
		}

		if (!adns_do_read(fd_in, buf, size))
			break;

		adns_gethostbyname(&req, &ans);

		if (!adns_do_write(fd_out, &ans.common, sizeof ans.common))
			break;

		if (ans.common.reverse) {	
			size = sizeof ans.reply.reverse;
			buf = &ans.reply.reverse;
		} else {
			size = sizeof ans.reply.by_addr;
			buf = &ans.reply.by_addr;
		}

		if (!adns_do_write(fd_out, buf, size))
			break;
	}

	fd_close(&fd_in);
	fd_close(&fd_out);
	_exit(EXIT_SUCCESS);
}
#endif	/* !MINGW32 */

static inline void
adns_invoke_user_callback(const struct adns_response *ans)
{
	if (ans->common.reverse) {
		const struct adns_reverse_reply *reply = &ans->reply.reverse;
		adns_reverse_callback_t func;

		func = (adns_reverse_callback_t) ans->common.user_callback;
		func(reply->hostname[0] != '\0' ? reply->hostname : NULL,
			ans->common.user_data);
	} else {
		const struct adns_reply *reply = &ans->reply.by_addr;
		adns_callback_t func;
		size_t n;
	
		n = count_addrs(reply->addrs, G_N_ELEMENTS(reply->addrs));
		func = (adns_callback_t) ans->common.user_callback;
		func(reply->addrs, n, ans->common.user_data);
	}
}

/**
 * Handles the query in synchronous (blocking) mode and is used if the
 * dns helper is busy i.e., the pipe buffer is full or in case the dns
 * helper is dead.
 */
static void
adns_fallback(const struct adns_request *req)
{
	struct adns_response ans;

	g_assert(req);
	adns_gethostbyname(req, &ans);
	g_assert(ans.common.user_callback);
	adns_invoke_user_callback(&ans);
}

#ifndef MINGW32
static void
adns_reply_ready(const struct adns_response *ans)
{
	time_t now = tm_time();

	g_assert(ans != NULL);

	if (ans->common.reverse) {
		if (common_dbg > 1) {
			const struct adns_reverse_reply *reply = &ans->reply.reverse;
			
			g_debug("%s: resolved \"%s\" to \"%s\".",
				G_STRFUNC, host_addr_to_string(reply->addr), reply->hostname);
		}
	} else {
		const struct adns_reply *reply = &ans->reply.by_addr;
		size_t num;

		num = count_addrs(reply->addrs, G_N_ELEMENTS(reply->addrs));
		num = MAX(1, num); /* For negative caching */
		
		if (common_dbg > 1) {
			size_t i;
			
			for (i = 0; i < num; i++) {
				g_debug("%s: resolved \"%s\" to \"%s\".", G_STRFUNC,
					reply->hostname, host_addr_to_string(reply->addrs[i]));
			}
		}

		
		if (!adns_cache_lookup(adns_cache, now, reply->hostname, NULL, 0)) {
			adns_cache_add(adns_cache, now, reply->hostname, reply->addrs, num);
		}
	}

	g_assert(ans->common.user_callback);
	adns_invoke_user_callback(ans);
}

/**
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., gtk-gnutella itself.
 * It handles partial reads if necessary. In case of an unrecoverable error
 * the reply pipe will be closed and the callback will be lost.
 */
static void
adns_reply_callback(void *data, int source, inputevt_cond_t condition)
{
	static struct adns_response ans;
	static void *buf;
	static size_t size, pos;

	g_assert(NULL == data);
	g_assert(condition & INPUT_EVENT_RX);

	/*
	 * Consume all the data available in the pipe, potentially handling
	 * several pending replies.
	 */

	for (;;) {
		ssize_t ret;
		size_t n;

		if (pos == size) {

			pos = 0;
			if (cast_to_pointer(&ans.common) == buf) {
				/*
				 * Finished reading the generic reply header, now read
				 * the specific part.
				 */

				g_assert(ADNS_COMMON_MAGIC == ans.common.magic);

				if (ans.common.reverse) {
					buf = &ans.reply.reverse;
					size = sizeof ans.reply.reverse;
				} else {
					buf = &ans.reply.by_addr;
					size = sizeof ans.reply.by_addr;
				}
			} else {
				if (buf) {
					/*
					 * Completed reading the specific part of the reply.
					 * Inform issuer of request by invoking the user callback.
					 */

					adns_reply_ready(&ans);
				}

				/*
				 * Continue reading the next reply, if any, which will start
				 * by the generic header.
				 */

				buf = &ans.common;
				size = sizeof ans.common;
				ans.common.magic = 0;
			}
		}

		g_assert(buf);
		g_assert(size > 0);
		g_assert(pos < size);

		n = size - pos;
		ret = read(source, cast_to_gchar_ptr(buf) + pos, n);
		if ((ssize_t) -1 == ret) {
		   	if (!is_temporary_error(errno)) {
				g_warning("%s: read() failed: %m", G_STRFUNC);
				goto error;
			}
			break;
		} else if (0 == ret) {
			g_warning("%s: read() failed: EOF", G_STRFUNC);
			goto error;
		} else {
			g_assert(ret > 0);
			g_assert(UNSIGNED(ret) <= n);
			pos += (size_t) ret;
		}
	}
	return;
	
error:
	inputevt_remove(&adns_reply_event_id);
	g_warning("%s: removed myself", G_STRFUNC);
	fd_close(&source);
}

/**
 * Allocate a "spill" buffer of size `size'.
 */
static adns_async_write_t *
adns_async_write_alloc(const struct adns_request *req,
	const void *buf, size_t size)
{
	adns_async_write_t *remain;

	g_assert(req);
	g_assert(buf);
	g_assert(size > 0);
	
	WALLOC(remain);
	remain->req = *req;
	remain->size = size;
	remain->buf = wcopy(buf, remain->size);
	remain->pos = 0;

	return remain;
}

/**
 * Dispose of the "spill" buffer.
 */
static void
adns_async_write_free(adns_async_write_t *remain)
{
	g_assert(remain);
	g_assert(remain->buf);
	g_assert(remain->size > 0);
	
	wfree(remain->buf, remain->size);
	WFREE(remain);
}

/**
 * Callback function for inputevt_add(). This function pipes the query to
 * the server using the pipe in non-blocking mode, partial writes are handled
 * appropriately. In case of an unrecoverable error the query pipe will be
 * closed and the blocking adns_fallback() will be invoked.
 */
static void
adns_query_callback(void *data, int dest, inputevt_cond_t condition)
{
	adns_async_write_t *remain = data;

	g_assert(NULL != remain);
	g_assert(NULL != remain->buf);
	g_assert(remain->pos < remain->size);
	g_assert(dest == adns_query_fd);
	g_assert(0 != adns_query_event_id);

	if (condition & INPUT_EVENT_EXCEPTION) {
		g_warning("%s: write exception", G_STRFUNC);
		goto abort;
	}

	while (remain->pos < remain->size) {
		ssize_t ret;
		size_t n;

		n = remain->size - remain->pos;
		ret = write(dest, &remain->buf[remain->pos], n);

		if (0 == ret) {
			errno = ECONNRESET;
			ret = (ssize_t) -1;
		}
		/* FALL THROUGH */
		if ((ssize_t) -1 == ret) {
			if (!is_temporary_error(errno))
				goto error;
			return;
		}

		g_assert(ret > 0);
		g_assert(UNSIGNED(ret) <= n);
		remain->pos += (size_t) ret;
	}
	g_assert(remain->pos == remain->size);

	inputevt_remove(&adns_query_event_id);

	goto done;	


error:
	g_warning("%s: write() failed: %m", G_STRFUNC);
abort:
	g_warning("%s: removed myself", G_STRFUNC);
	inputevt_remove(&adns_query_event_id);
	fd_close(&adns_query_fd);
	g_warning("%s: using fallback", G_STRFUNC);
	adns_fallback(&remain->req);
done:
	adns_async_write_free(remain);
	return;
}
#endif	/* !MINGW32 */

static pid_t
adns_helper_init(void)
#ifdef MINGW32
{
	mingw_adns_init();
	return -1;
}
#else
{
	int fd_query[2] = {-1, -1};
	int fd_reply[2] = {-1, -1};
	pid_t pid;

	if (-1 == pipe(fd_query) || -1 == pipe(fd_reply)) {
		g_warning("%s: pipe() failed: %m", G_STRFUNC);
		goto prefork_failure;
	}
	
	pid = fork();
	if ((pid_t) -1 == pid) {
		g_warning("%s: fork() failed: %m", G_STRFUNC);
		goto prefork_failure;
	}
	if (0 == pid) {
		/* child process */

		/**
		 * Close all standard FILEs so that they don't keep a reference
		 * to the log files when they are reopened by the main process
		 * on SIGHUP. This means there will be no visible messages from
		 * ADNS at all.
		 */

		if (!freopen("/dev/null", "r", stdin))
			g_error("%s: freopen(\"/dev/null\", \"r\", stdin) failed: %m",
				G_STRFUNC);

		if (!freopen("/dev/null", "a", stdout))
			g_error("%s: freopen(\"/dev/null\", \"a\", stdout) failed: %m",
				G_STRFUNC);

		if (!freopen("/dev/null", "a", stderr))
			g_error("%s: freopen(\"/dev/null\", \"a\", stderr) failed: %m",
				G_STRFUNC);

		fd_close(&fd_query[1]);
		fd_close(&fd_reply[0]);

		set_close_on_exec(fd_query[0]);
		set_close_on_exec(fd_reply[1]);

		adns_helper(fd_query[0], fd_reply[1]);
		g_assert_not_reached();
		_exit(EXIT_SUCCESS);
	}

	/* parent process */
	fd_close(&fd_query[0]);
	fd_close(&fd_reply[1]);
	
	fd_query[1] = get_non_stdio_fd(fd_query[1]);
	fd_reply[0] = get_non_stdio_fd(fd_reply[0]);
	
	adns_query_fd = fd_query[1];

	set_close_on_exec(adns_query_fd);
	set_close_on_exec(fd_reply[0]);
	fd_set_nonblocking(adns_query_fd);
	fd_set_nonblocking(fd_reply[0]);
	
	adns_reply_event_id = inputevt_add(fd_reply[0], INPUT_EVENT_RX,
							adns_reply_callback, NULL);
	/* FALL THROUGH */
prefork_failure:

	if (!adns_reply_event_id) {
		g_warning("cannot use ADNS; DNS lookups may cause stalling");
		fd_close(&fd_query[0]);
		fd_close(&fd_query[1]);
		fd_close(&fd_reply[0]);
		fd_close(&fd_reply[1]);
	}
	
	return pid;
}
#endif	/* MINGW32 */

/* public functions */

/**
 * Initializes the adns helper i.e., fork()s a child process which will
 * be used to resolve hostnames asynchronously.
 */
pid_t
adns_init(void)
{
	adns_cache = adns_cache_init();
	return adns_helper_init();
}

/**
 * @return TRUE on success, FALSE on failure.
 */
static bool
adns_send_request(const struct adns_request *req)
#ifdef MINGW32
{
	return mingw_adns_send_request(req);
}
#else
{
	char buf[sizeof *req];
	size_t size;
	ssize_t written;

	g_assert(req);

	if (!adns_reply_event_id || 0 != adns_query_event_id)
		return FALSE;

	g_assert(adns_query_fd >= 0);
	
	memcpy(buf, &req->common, sizeof req->common);
	size = sizeof req->common;
	{
		const void *p;
		size_t n;
		
		if (req->common.reverse) {
			n = sizeof req->query.reverse;
			p = &req->query.reverse;
		} else {
			n = sizeof req->query.by_addr;
			p = &req->query.by_addr;
		}
		memcpy(&buf[size], p, n);
		size += n;
	}

	/*
	 * Try to write the query atomically into the pipe.
	 */

	written = write(adns_query_fd, buf, size);
	if (written == (ssize_t) -1) {
		if (!is_temporary_error(errno)) {
			g_warning("%s: write() failed: %m", G_STRFUNC);
			inputevt_remove(&adns_reply_event_id);
			fd_close(&adns_query_fd);
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

	if (UNSIGNED(written) < size) {
		adns_async_write_t *aq;
	   
		aq = adns_async_write_alloc(req, &buf[written], size - written);
		adns_query_event_id = inputevt_add(adns_query_fd, INPUT_EVENT_WX,
								adns_query_callback, aq);
	}

	return TRUE;
}
#endif	/* MINGW32 */

/**
 * Creates a DNS resolve query for ``hostname''.
 *
 * The given function ``user_callback'' (which MUST NOT be NULL)
 * will be invoked with the resolved IP address and ``user_data''
 * as its parameters. The IP address 0.0.0.0 i.e., ``(uint32) 0''
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
bool
adns_resolve(const char *hostname, enum net_type net,
	adns_callback_t user_callback, void *user_data)
{
	struct adns_request req;
	struct adns_response ans;
	struct adns_query *query = &req.query.by_addr;
	struct adns_reply *reply = &ans.reply.by_addr;
	size_t hostname_len;
	host_addr_t addr;

	g_assert(NULL != hostname);
	g_assert(NULL != user_callback);

	req.common.magic = ADNS_COMMON_MAGIC;
	req.common.user_callback = (void (*)(void)) user_callback;
	req.common.user_data = user_data;
	req.common.reverse = FALSE;
	ans.common = req.common;
	
	query->net = net;
	reply->hostname[0] = '\0';
	reply->addrs[0] = zero_host_addr;

	hostname_len = clamp_strcpy(query->hostname,
		sizeof query->hostname, hostname);

	if ('\0' != hostname[hostname_len]) {
		/* truncation detected */
		adns_invoke_user_callback(&ans);
		return FALSE; /* synchronous */
	}

	if (string_to_host_addr(hostname, NULL, &addr)) {
		reply->addrs[0] = addr;
		reply->addrs[1] = zero_host_addr;
		adns_invoke_user_callback(&ans);
		return FALSE; /* synchronous */
	}

	ascii_strlower(query->hostname, hostname);
	clamp_strcpy(reply->hostname, sizeof reply->hostname, query->hostname);
	
	if (
		adns_cache_lookup(adns_cache, tm_time(), query->hostname,
			reply->addrs, G_N_ELEMENTS(reply->addrs))
	) {
		adns_invoke_user_callback(&ans);
		return FALSE; /* synchronous */
	}

	if (adns_send_request(&req))
		return TRUE; /* asynchronous */

	if (adns_reply_event_id) {
		g_warning("%s: using synchronous resolution for \"%s\"",
			G_STRFUNC, query->hostname);
	}
	adns_fallback(&req);

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
bool
adns_reverse_lookup(const host_addr_t addr,
	adns_reverse_callback_t user_callback, void *user_data)
{
	struct adns_request req;
	struct adns_reverse_query *query = &req.query.reverse;

	g_assert(user_callback);

	req.common.user_callback = (void (*)(void)) user_callback;
	req.common.user_data = user_data;
	req.common.reverse = TRUE;
	query->addr = addr;

	if (adns_send_request(&req))
		return TRUE; /* asynchronous */

	g_warning("%s: using synchronous resolution for \"%s\"",
		G_STRFUNC, host_addr_to_string(query->addr));

	adns_fallback(&req);

	return FALSE; /* synchronous */
}

/**
 * Removes the callback and frees the cache.
 */
void
adns_close(void)
{
#ifdef MINGW32
	mingw_adns_close();
#else
	inputevt_remove(&adns_reply_event_id);
	inputevt_remove(&adns_query_event_id);
#endif	/* MINGW32 */

	adns_cache_free(&adns_cache);
}

/* vi: set ts=4 sw=4 cindent: */
