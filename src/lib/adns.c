/*
 * Copyright (c) 2004, Christian Biere
 * Copyright (c) 2013, 2015, 2020 Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2013, 2015, 2020
 */

#include "common.h"

#include "adns.h"

#include "aq.h"
#include "ascii.h"
#include "atoms.h"
#include "cq.h"
#include "debug.h"
#include "fd.h"
#include "glib-missing.h"
#include "hikset.h"
#include "host_addr.h"
#include "inputevt.h"
#include "mutex.h"
#include "once.h"
#include "pslist.h"
#include "shuffle.h"
#include "signal.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "waiter.h"
#include "walloc.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

/* private data types */

enum adns_magic { ADNS_COMMON_MAGIC = 0x05dc21cb };

struct adns_common {
	enum adns_magic magic;
	void (*user_callback)(void);
	void *user_data;
	bool reverse;
};

struct adns_reverse_query {
	host_addr_t addr;
};

struct adns_query {
	enum net_type net;
	char hostname[MAX_HOSTLEN + 1];
};

struct adns_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addrs[10];
};

struct adns_reverse_reply {
	char hostname[MAX_HOSTLEN + 1];
	host_addr_t addr;
};

struct adns_request {
	struct adns_common common;
	union {
		struct adns_query by_addr;
		struct adns_reverse_query reverse;
	} query;
};

struct adns_response {
	struct adns_common common;
	union {
		struct adns_reply by_addr;
		struct adns_reverse_reply reverse;
	} reply;
};

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
#define ADNS_CACHE_TIMEOUT 60

/**
 * Cache max. ADNS_CACHE_SIZE of adns_cache_entry_t entries.
 */
#define ADNS_CACHE_MAX_SIZE 1024

typedef struct adns_cache_struct {
	hikset_t *ht;
	unsigned pos;
	int timeout;
	adns_cache_entry_t *entries[ADNS_CACHE_MAX_SIZE];
	cperiodic_t *ev;
	mutex_t lock;
} adns_cache_t;

static adns_cache_t *adns_cache = NULL;

#define ADNS_CACHE_LOCK(ac)			mutex_lock(&(ac)->lock)
#define ADNS_CACHE_UNLOCK(ac)		mutex_unlock(&(ac)->lock)
#define ADNS_CACHE_IS_LOCKED(ac)	mutex_is_owned(&(ac)->lock)

/* private variables */

static unsigned adns_reply_event_id;
static aqueue_t *adns_req;
static aqueue_t *adns_ans;
static int adns_id = -1;

static uint32 adns_debug;	/**< Debug level */

#define adns_debugging(lvl)   G_UNLIKELY(adns_debug > (lvl))

/**
 * Set debug level.
 */
void
set_adns_debug(uint32 level)
{
	adns_debug = level;
}

/**
 * Private functions.
 */

static bool adns_cache_periodic(void *o);

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
	for (i = 0; i < N_ITEMS(cache->entries); i++) {
		cache->entries[i] = NULL;
	}
	mutex_init(&cache->lock);
	cache->ev = cq_periodic_main_add(
		1000 * ADNS_CACHE_TIMEOUT,		/* in ms for debug */
		adns_cache_periodic, cache);
	return cache;
}

/* these are not needed anywhere else so undefine them */
#undef ADNS_CACHE_MAX_SIZE
#undef ADNS_CACHE_TIMEOUT

static inline adns_cache_entry_t *
adns_cache_get_entry(const adns_cache_t *cache, unsigned i)
{
	const adns_cache_entry_t *entry;

	g_assert(cache);
	g_assert(i < N_ITEMS(cache->entries));

	entry = cache->entries[i];
	if (entry) {
		g_assert(i == entry->id);
		g_assert(entry->hostname);
		g_assert(entry->n > 0);
	}
	return deconstify_pointer(entry);
}

static void
adns_cache_free_item(adns_cache_entry_t *entry)
{
	g_assert(entry != NULL);
	g_assert(entry->hostname != NULL);
	g_assert(entry->n > 0);

	atom_str_free_null(&entry->hostname);
	wfree(entry, adns_cache_entry_size(entry->n));
}

static void
adns_cache_free_entry(adns_cache_t *cache, unsigned i)
{
	adns_cache_entry_t *entry;

	g_assert(cache);
	g_assert(i < N_ITEMS(cache->entries));
	g_assert(ADNS_CACHE_IS_LOCKED(cache));

	entry = cache->entries[i];
	if (entry != NULL) {
		g_assert(i == entry->id);
		adns_cache_free_item(entry);
		cache->entries[i] = NULL;
	}
}

/**
 * Drop entry from cache.
 *
 * The entry is freed and its cache slot cleared.
 */
static void
adns_cache_drop_entry(
	adns_cache_t *cache, adns_cache_entry_t *entry, const char *caller)
{
	g_assert(cache != NULL);
	g_assert(entry != NULL);
	g_assert(ADNS_CACHE_IS_LOCKED(cache));

	if (adns_debugging(1)) {
		s_debug("%s(): removing \"%s\" from cache (%zu entr%s) at slot #%u",
			caller, entry->hostname, PLURAL_Y(entry->n), entry->id);
	}

	hikset_remove(cache->ht, entry->hostname);
	adns_cache_free_entry(cache, entry->id);
}

/**
 * Clear entry from cache.
 *
 * The slot is cleared and the entry de-indexed but it is not freed.
 */
static void
adns_cache_clear_entry(adns_cache_t *cache, const adns_cache_entry_t *entry)
{
	g_assert(cache != NULL);
	g_assert(entry != NULL);
	g_assert(ADNS_CACHE_IS_LOCKED(cache));

	hikset_remove(cache->ht, entry->hostname);
	cache->entries[entry->id] = NULL;
}

/**
 * Has cache entry expired?
 */
static inline bool
adns_cache_expired_item(
	const adns_cache_t *cache, const adns_cache_entry_t *entry, time_t now)
{
	return delta_time(now, entry->timestamp) >= cache->timeout;
}

/**
 * Callout queue periodic event to prune expired cache entries.
 */
static bool
adns_cache_periodic(void *o)
{
	adns_cache_t *cache = o;
	time_t now = tm_time();
	pslist_t *to_free = NULL;
	size_t i, held = 0, expired = 0;

	ADNS_CACHE_LOCK(cache);

	for (i = 0; i < N_ITEMS(cache->entries); i++) {
		const adns_cache_entry_t *entry = cache->entries[i];

		if (NULL == entry)
			continue;

		g_assert(entry->id == i);

		if (adns_cache_expired_item(cache, entry, now)) {
			to_free = pslist_prepend_const(to_free, entry);
			expired++;

			if (adns_debugging(4)) {
				s_debug(
					"%s(): expiring \"%s\" from cache (%zu entr%s) at slot #%u",
					G_STRFUNC, entry->hostname, PLURAL_Y(entry->n), entry->id);
			}

			/* Not adns_cache_drop_entry(), we'll free entry later */
			adns_cache_clear_entry(cache, entry);
		} else {
			held++;
		}
	}

	ADNS_CACHE_UNLOCK(cache);

	/* Free items once the cache is no longer locked */

	PSLIST_FOREACH_CALL(to_free, adns_cache_free_item);
	pslist_free_null(&to_free);

	if (adns_debugging(3)) {
		s_debug("%s(): cache holds %zu entr%s (expired %zu this cycle)",
			G_STRFUNC, PLURAL_Y(held), expired);
	}

	return TRUE;		/* Keep calling */
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

	ADNS_CACHE_LOCK(cache);

	for (i = 0; i < N_ITEMS(cache->entries); i++) {
		adns_cache_free_entry(cache, i);
	}
	hikset_free_null(&cache->ht);
	cq_periodic_remove(&cache->ev);
	mutex_destroy(&cache->lock);
	XFREE_NULL(cache);
}

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
	g_assert(cache->pos < N_ITEMS(cache->entries));

	if (adns_debugging(0)) {
		s_debug("%s(): caching %zu entr%s for \"%s\" at slot #%u",
			G_STRFUNC, PLURAL_Y(n), hostname, cache->pos);
	}

	ADNS_CACHE_LOCK(cache);

	entry = adns_cache_get_entry(cache, cache->pos);

	if (entry != NULL) {
		g_assert(entry->hostname);
		g_assert(entry == hikset_lookup(cache->ht, entry->hostname));

		adns_cache_drop_entry(cache, entry, G_STRFUNC);
	}

	entry = walloc(adns_cache_entry_size(n));
	entry->n = n;
	entry->hostname = atom_str_get(hostname);
	entry->timestamp = now;
	entry->id = cache->pos;
	for (i = 0; i < entry->n; i++) {
		entry->addrs[i] = addrs[i];

		if (adns_debugging(1)) {
			s_debug("%s(): caching \"%s\" for \"%s\" (#%zu/%zu)",
				G_STRFUNC, host_addr_to_string(addrs[i]), hostname, i + 1, n);
		}
	}

	if (adns_debugging(3)) {
		s_debug("%s(): caching \"%s\" at slot #%u/%zu",
			G_STRFUNC, hostname, cache->pos, N_ITEMS(cache->entries));
	}

	hikset_insert_key(cache->ht, &entry->hostname);
	cache->entries[cache->pos++] = entry;
	cache->pos %= N_ITEMS(cache->entries);

	ADNS_CACHE_UNLOCK(cache);
}

/**
 * Looks for ``hostname'' in ``cache'' .
 *
 * If ``hostname'' is not found or the entry is expired, FALSE will be
 * returned. Expired entries will be removed! ``addr'' is allowed to
 * be NULL, otherwise the cached IP will be stored into the variable
 * ``addr'' points to.
 *
 * @param addrs		An array of host_addr_t items. If not NULL, up to
 *              	``n'' items will be copied from the cache.
 * @param n			The number of items "addrs" can hold.
 *
 * @return The number of cached addresses for the given hostname.
 */
static size_t
adns_cache_lookup(adns_cache_t *cache, time_t now,
	const char *hostname, host_addr_t *addrs, size_t n)
{
	adns_cache_entry_t *entry;
	size_t n_entry = 0;

	g_assert(NULL != cache);
	g_assert(NULL != hostname);
	g_assert(0 == n || NULL != addrs);

	ADNS_CACHE_LOCK(cache);

	entry = hikset_lookup(cache->ht, hostname);

	if (entry != NULL) {
		if (!adns_cache_expired_item(cache, entry, now)) {
			size_t i;

			if (adns_debugging(0)) {
				s_debug("%s(): \"%s\" is cached with %zu entr%s",
					G_STRFUNC, entry->hostname, PLURAL_Y(entry->n));
			}

			for (i = 0; i < n; i++) {
				if (i < entry->n) {
					addrs[i] = entry->addrs[i];

					if (adns_debugging(1)) {
						s_debug("%s(): \"%s\" returning cached addr=%s (#%zu/%zu)",
							G_STRFUNC, entry->hostname,
							host_addr_to_string(addrs[i]),
							i + 1, entry->n);
					}
				} else {
					addrs[i] = zero_host_addr;
				}
			}
			n_entry = MIN(entry->n, n);		/* Amount of addresses copied */
		} else {
			adns_cache_drop_entry(cache, entry, G_STRFUNC);
		}
	}

	ADNS_CACHE_UNLOCK(cache);

	/*
	 * If there are more than one address associated with the host, a
	 * real DNS would rotate the answer so that we do not hit the same
	 * IP address, ever.
	 *
	 * Here, we simply shuffle the results to ensure we do not hit the
	 * same IP address in the unlikely event a name resolves to a
	 * server pool and not to a load balancer or a single server.
	 *
	 * 		--RAM, 2020-04-06
	 */

	if (n_entry > 1)
		SHUFFLE_ARRAY_N(addrs, n_entry);

	return n_entry;
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

		if (adns_debugging(1)) {
			s_debug("%s(): reverse-resolving \"%s\" ...",
					G_STRFUNC, host_addr_to_string(query->addr));
		}

		reply->addr = query->addr;
		host = host_addr_to_name(query->addr);
		clamp_strcpy(ARYLEN(reply->hostname), host ? host : "");
	} else {
		const struct adns_query *query = &req->query.by_addr;
		struct adns_reply *reply = &ans->reply.by_addr;
		pslist_t *sl_addr, *sl;
		size_t i = 0;

		if (adns_debugging(1)) {
			s_debug("%s(): resolving \"%s\" ...", G_STRFUNC, query->hostname);
		}
		clamp_strcpy(ARYLEN(reply->hostname), query->hostname);

		sl_addr = name_to_host_addr(query->hostname, query->net);
		PSLIST_FOREACH(sl_addr, sl) {
			host_addr_t *addr = sl->data;
			g_assert(addr);
			if (i >= N_ITEMS(reply->addrs)) {
				break;
			}
			reply->addrs[i++] = *addr;
		}
		host_addr_free_list(&sl_addr);

		if (i < N_ITEMS(reply->addrs)) {
			reply->addrs[i] = zero_host_addr;
		}
	}
}

struct adns_helper_args {
	aqueue_t *requests;		/* Where helper receives requests from */
	aqueue_t *answers;		/* Where helper sends answers to */
};

#define ADNS_HELPER_STACK	THREAD_STACK_MIN

/**
 * The ``main'' function of the adns helper thread (server).
 *
 * Simply reads requests (queries) from the queue, performs a DNS lookup for it
 * and writes the result back to the output queue. All operations should be
 * blocking.
 */
static void *
adns_helper(void *p)
{
	struct adns_helper_args *args = p;
	aqueue_t *rq = aq_refcnt_inc(args->requests);
	aqueue_t *aq = aq_refcnt_inc(args->answers);

	thread_set_name("ADNS");
	WFREE(args);

	s_debug("ADNS thread started");

	for (;;) {
		struct adns_request *req;
		struct adns_response *ans;

		req = aq_remove(rq);
		if G_UNLIKELY(NULL == req)
			break;

		g_assert(ADNS_COMMON_MAGIC == req->common.magic);

		WALLOC(ans);
		adns_gethostbyname(req, ans);
		WFREE(req);
		aq_put(aq, ans);
	}

	if (adns_debugging(0))
		s_debug("ADNS thread exiting");

	aq_refcnt_dec(rq);
	aq_refcnt_dec(aq);

	return NULL;
}

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

		n = count_addrs(reply->addrs, N_ITEMS(reply->addrs));
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

static void
adns_reply_ready(const struct adns_response *ans)
{
	time_t now = tm_time();

	g_assert(ans != NULL);

	if (ans->common.reverse) {
		if (adns_debugging(1)) {
			const struct adns_reverse_reply *reply = &ans->reply.reverse;

			s_debug("%s(): resolved \"%s\" to \"%s\".",
				G_STRFUNC, host_addr_to_string(reply->addr), reply->hostname);
		}
	} else {
		const struct adns_reply *reply = &ans->reply.by_addr;
		size_t num;

		num = count_addrs(reply->addrs, N_ITEMS(reply->addrs));
		num = MAX(1, num); /* For negative caching */

		if (adns_debugging(1)) {
			size_t i;

			for (i = 0; i < num; i++) {
				s_debug("%s(): resolved \"%s\" to \"%s\".", G_STRFUNC,
					reply->hostname, host_addr_to_string(reply->addrs[i]));
			}
		}

		ADNS_CACHE_LOCK(adns_cache);

		if (!adns_cache_lookup(adns_cache, now, reply->hostname, NULL, 0)) {
			adns_cache_add(adns_cache, now, reply->hostname, reply->addrs, num);
		}

		ADNS_CACHE_UNLOCK(adns_cache);
	}

	g_assert(ans->common.user_callback);
	adns_invoke_user_callback(ans);
}

/**
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., the main thread itself.
 */
static void
adns_reply_callback(void *data, int source, inputevt_cond_t condition)
{
	struct adns_response *ans;
	waiter_t *w = data;

	g_assert(condition & INPUT_EVENT_RX);

	(void) source;

	waiter_ack(w);		/* Acknowledge reception of event */

	/*
	 * Consume all the data available in the queue, potentially handling
	 * several pending replies.
	 */

	while (NULL != (ans = aq_remove_try(adns_ans))) {
		/*
		 * Inform issuer of request by invoking the user callback.
		 */

		adns_reply_ready(ans);
		WFREE(ans);
	}
}

static void
adns_helper_init(void)
{
	waiter_t *waiter;
	struct adns_helper_args *args;
	int r;

	/*
	 * The ADNS thread talks to the main thread via a pair of asynchronous
	 * queues: requests are written to the adns_req queue and replies read
	 * from the adns_ans queue.
	 *
	 * Each side allocates the memory for the data structures put in the queue
	 * and the other side frees these data after processing them.
	 *
	 * In order for the main thread to know when there are data to read from
	 * the answer queue, we add a waiter object to the asynchronous queue,
	 * and insert its file descriptor to the main I/O event set.
	 */

	waiter = waiter_make(NULL);
	adns_req = aq_make();
	adns_ans = aq_make();
	aq_waiter_add(adns_ans, waiter);
	adns_reply_event_id = inputevt_add(waiter_fd(waiter), INPUT_EVENT_RX,
			adns_reply_callback, waiter);
	waiter_destroy_null(&waiter);	/* Is now referenced by the queue */

	WALLOC(args);
	args->requests = adns_req;
	args->answers = adns_ans;

	r = thread_create(adns_helper, args,
			THREAD_F_NO_POOL | THREAD_F_PANIC, ADNS_HELPER_STACK);

	adns_id = r;
}

/**
 * One-time initialization.
 */
static void
adns_init_once(void)
{
	adns_cache = adns_cache_init();
	adns_helper_init();
}

/* public functions */

/**
 * Initializes the adns helper running in a dedicated therad to resolve
 * hostnames asynchronously.
 */
void
adns_init(void)
{
	static once_flag_t inited;

	ONCE_FLAG_RUN(inited, adns_init_once);
}

/**
 * @return TRUE on success, FALSE if the ADNS queue is gone.
 */
static bool
adns_send_request(const struct adns_request *req)
{
	struct adns_request *r;

	g_assert(req != NULL);

	if (NULL == adns_req)
		return FALSE;			/* ADNS thread was shutdown */

	r = WCOPY(req);
	aq_put(adns_req, r);

	return TRUE;
}

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

	hostname_len = clamp_strcpy(ARYLEN(query->hostname), hostname);

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
	clamp_strcpy(ARYLEN(reply->hostname), query->hostname);

	if (
		adns_cache_lookup(adns_cache, tm_time(), query->hostname,
			reply->addrs, N_ITEMS(reply->addrs))
	) {
		adns_invoke_user_callback(&ans);
		return FALSE; /* synchronous */
	}

	if (adns_send_request(&req))
		return TRUE; /* asynchronous */

	if (adns_debugging(0)) {
		s_warning("%s(): falling back to synchronous resolution for \"%s\"",
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

	req.common.magic = ADNS_COMMON_MAGIC;
	req.common.user_callback = (void (*)(void)) user_callback;
	req.common.user_data = user_data;
	req.common.reverse = TRUE;
	query->addr = addr;

	if (adns_send_request(&req))
		return TRUE; /* asynchronous */

	s_warning("%s(): using synchronous resolution for \"%s\"",
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
	if (adns_debugging(0))
		s_debug("%s(): terminating ADNS, thread #%d", G_STRFUNC, adns_id);

	aq_put(adns_req, NULL);		/* Signals: end of processing */
	aq_destroy_null(&adns_req);
	aq_destroy_null(&adns_ans);
	inputevt_remove(&adns_reply_event_id);
	adns_cache_free(&adns_cache);

	/*
	 * Wait for the ADNS to exit before continuing since we're shutdowning
	 * and all the important subsystems on which the thread layer relies upon
	 * are also going to be shutdowned (e.g. the callout queue).
	 *
	 * Therefore, having a deterministic destruction is important.
	 */

	if (-1 != adns_id) {
		if (-1 == thread_join(adns_id, NULL)) {
			s_warning("%s(): cannot join with ADNS thread: %m", G_STRFUNC);
		} else {
			if (adns_debugging(0))
				s_debug("%s(): ADNS thread #%d terminated", G_STRFUNC, adns_id);
		}
		adns_id = -1;
	}
}

/* vi: set ts=4 sw=4 cindent: */
