/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Gnutella Web Cache.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#include "common.h"

RCSID("$Id$");

#include "gwcache.h"
#include "http.h"
#include "hosts.h"
#include "hcache.h"
#include "version.h"
#include "settings.h"
#include "sockets.h"		/* For socket_listen_addr() */

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/getline.h"
#include "lib/glib-missing.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"
#include "if/core/nodes.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static gchar gwc_tmp[1024];

/*
 * The web cache URLs are stored in a fixed-sized array: we remember only
 * a handful of URLs, and choose each time a random web cache among the
 * set for interaction.
 *
 * The array `gwc_url' is filled in a round-robin fashion, the last filled
 * position being `gwc_url_slot'.
 *
 * The `gwc_known_url' hash table is actually a search table indexed by an URL
 * to prevent insertion of duplicates in our cache.
 */

#define MAX_GWC_URLS	200		/**< Max URLs we store */
#define MAX_GWC_REUSE	1		/**< Max amount of uses for one URL */

struct gwc {
	gchar *url;					/**< atom */
	time_t stamp;				/**< time of last access */
} gwc_url[MAX_GWC_URLS];		/**< Holds string atoms */

static gint gwc_url_slot = -1;
static GHashTable *gwc_known_url = NULL;
static GHashTable *gwc_failed_url = NULL;

/*
 * Web cache update policy:
 *
 * . One random web cache is selected among the list of known caches,
 *   at startup.  This is known as the "current webcache", and it is
 *   stored in `current_url'.
 *
 * . As soon as a transaction to the "current webcache" fails, a new one
 *   is elected.
 *
 * . Every HOUR_MS milliseconds, a transaction updating ip (if connectible)
 *   and an url (chosen randomly among the known ones) is sent to
 *   the "current webcache".
 *
 * . Every 8 hours, an urlfile request is sent to the "current webcache",
 *   to get more webcache URLs to propagate.
 *
 * . After having used a cache for more than MAX_GWC_REUSE times, as
 *   tracked by `current_reused', a new "current webcache" is elected.
 *
 * . If an urlfile or an hostfile request return less than MIN_URL_LINES
 *   or MIN_IP_LINES respectively, we force an update on that cache to
 *   "seed" it with data.  We then elect another "current webcache".
 *
 * . All requests include "client=GTKG" and "version" information.
 */

static gchar *current_url = NULL;			/**< Cache we're currently using */
static gint current_reused = 0;				/**< Amount of times we reused it */

#define MAX_URL_LINES	50					/**< Max lines on a urlfile req */
#define MAX_IP_LINES	150					/**< Max lines on a hostfile req */
#define MAX_OK_LINES	3					/**< Max lines when expecting OK */
#define MIN_IP_LINES	5					/**< Min lines expected */
#define MIN_URL_LINES	5					/**< Min lines expected */
#define HOUR_MS			(3600 * 1000)		/**< Callout queue time in ms */
#define URL_RETRY_MS	(20 * 1000)			/**< Retry timer for urlfile, in ms */
#define REFRESH_MS		(8 * HOUR_MS)		/**< Refresh every 8 hours */
#define REUSE_PERIOD	3600				/**< Period between GET hostfile */

#define CLIENT_INFO "client=GTKG&version=" GTA_VERSION_NUMBER

static const gchar gwc_file[] = "gwcache";
static const gchar gwc_bootfile[] = "gwcache.boot";
static const gchar gwc_what[] = "web cache URLs";

static gpointer hourly_update_ev = NULL;
static gpointer periodic_refresh_ev = NULL;
static gpointer urlfile_retry_ev = NULL;
static gboolean gwc_file_dirty = FALSE;

static void gwc_get_urls(void);
static void gwc_update_ip_url(void);
static void gwc_seed_cache(gchar *cache_url);

/**
 * The following URLs are there for bootstrapping purposes only.
 */

static const gchar * const boot_url[] = {
	"http://cache.kicks-ass.net:8000/",
	"http://galvatron.dyndns.org:59009/gwcache",
	"http://krill.shacknet.nu:20095/gwc",
};

/**
 * Add new URL to cache, possibly pushing off an older one if cache is full.
 */
static void
gwc_add(const gchar *new_url)
{
	gchar *url_atom;
	gchar *url;
	gchar *old_url;

	url = g_strdup(new_url); /* url_normalize() can modify the URL */
	if (url) {
		gchar *ret;

		ret = url_normalize(url, URL_POLICY_GWC_RULES);
		if (!ret) {
			g_warning("ignoring bad web cache URL \"%s\"", new_url);
			G_FREE_NULL(url);
			return;
		}
		if (ret != url) {
			G_FREE_NULL(url);
			url = ret;
		}
	} else {
		/* This is superfluous with GLib but this way the above ``ret''
		 * is local and quitting isn't really appropriate anyway. */
		g_warning("Out of memory");
		return;
	}

	/*
	 * Don't add duplicates to the cache.
  	 */

	if (
		g_hash_table_lookup(gwc_known_url, url) ||
		g_hash_table_lookup(gwc_failed_url, url)
	) {
		G_FREE_NULL(url);
		return;
	}

	/*
	 * OK, record new entry at the `gwc_url_slot'.
	 */

	if (++gwc_url_slot >= MAX_GWC_URLS)
		gwc_url_slot = 0;

	g_assert(url != NULL);
	url_atom = atom_str_get(url);
	G_FREE_NULL(url);

	/*
	 * Expire any entry present at the slot we're about to write into.
	 */

	old_url = gwc_url[gwc_url_slot].url;

	if (old_url != NULL) {
		g_assert(g_hash_table_lookup(gwc_known_url, old_url));
		g_hash_table_remove(gwc_known_url, old_url);
		atom_str_free(old_url);
		gwc_url[gwc_url_slot].url = NULL;
	}

	g_hash_table_insert(gwc_known_url, url_atom, GUINT_TO_POINTER(1));

	gwc_url[gwc_url_slot].url = url_atom;
	gwc_url[gwc_url_slot].stamp = 0;
	gwc_file_dirty = TRUE;
}

/**
 * Pickup a cache randomly from the known set. If there's no URL used that
 * has not been used recently, NULL will be returned. The timestamp for
 * the picked URL is updated automatically.
 *
 * Try to avoid using default bootstrapping URLs if we have more than the
 * minimum set of caches in stock...
 *
 * @return a GWebCache URL or NULL on failure.
 */
static gchar *
gwc_pick(void)
{
	gint count = g_hash_table_size(gwc_known_url);
	gint idx, i;
	gchar *url = NULL;
	time_t now = tm_time();

	if (0 == count)
		return NULL;

	g_assert(count > 0);
	g_assert(count <= MAX_GWC_URLS);
	g_assert(count == MAX_GWC_URLS || gwc_url_slot < count);

	idx = random_value(count - 1);
	for (i = 0; i < count; i++) {
		time_t stamp = gwc_url[idx].stamp;

		if (0 == stamp || delta_time(now, stamp) > 3900) {
			url = gwc_url[idx].url;
			gwc_url[idx].stamp = now;
			break;
		}
	}

	if (gwc_debug && url)
		g_message("picked webcache \"%s\"", url);

	return url;
}

/**
 * Store known GWC URLs.
 * They are normally saved in ~/.gtk-gnutella/gwcache.
 */
static void
gwc_store(void)
{
	FILE *out;
	gint i;
	gint j;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), gwc_file);
	out = file_config_open_write(gwc_what, &fp);
	if (!out)
		return;

	file_config_preamble(out, "Gnutella web cache URLs");

	/*
	 * Start dumping with the next slot we'll supersede, so that the oldest
	 * entries are at the top: when the cache is full, we'll loop over at
	 * retrieve time and will start superseding the oldest entries.
	 */

	i = gwc_url_slot + 1;
	if (i >= MAX_GWC_URLS)
		i = 0;

	for (j = 0; j < MAX_GWC_URLS; j++) {
		gchar *url = gwc_url[i].url;

		i = (i + 1) % MAX_GWC_URLS;
		if (url == NULL)
			continue;
		fprintf(out, "%s\n", url);
	}

	if (file_config_close(out, &fp))
		gwc_file_dirty = FALSE;
}

/**
 * Store known GWC URLs if dirty.
 */
void
gwc_store_if_dirty(void)
{
	if (gwc_file_dirty)
		gwc_store();
}

/**
 * Retrieve known GWC URLs.
 * They are normally saved in ~/.gtk-gnutella/gwcache.
 */
static void
gwc_retrieve(void)
{
#ifndef OFFICIAL_BUILD
	static file_path_t fp[3];
#else
	static file_path_t fp[2];
#endif
	gint line;
	FILE *in;
	gchar tmp[1024];

	file_path_set(&fp[0], settings_config_dir(), gwc_file);
	file_path_set(&fp[1], PRIVLIB_EXP, gwc_bootfile);
#ifndef OFFICIAL_BUILD
	file_path_set(&fp[2], PACKAGE_SOURCE_DIR, gwc_bootfile);
#endif

	in = file_config_open_read(gwc_what, fp, G_N_ELEMENTS(fp));
	if (!in)
		return;

	/*
	 * Retrieve each line.
	 */

	line = 0;

	while (fgets(tmp, sizeof(tmp), in)) {
		line++;

		if (tmp[0] == '#')		/* Skip comments */
			continue;

		if (tmp[0] == '\n')		/* Allow empty lines */
			continue;

		(void) str_chomp(tmp, 0);
		gwc_add(tmp);
	}

	fclose(in);
}

/**
 * Hourly web cache update.
 * Scheduled as a callout queue event.
 */
static void
gwc_hourly_update(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (is_inet_connected)
		gwc_update_ip_url();

	hourly_update_ev = cq_insert(callout_queue,
		HOUR_MS, gwc_hourly_update, NULL);
}

/**
 * Hourly web cache refresh.
 * Scheduled as a callout queue event.
 */
static void
gwc_periodic_refresh(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	if (is_inet_connected) {
		/*
		 * Disable retry timer, since we are about to retry now based
		 * on our regular background periodic refreshing.
		 */

		if (urlfile_retry_ev) {
			cq_cancel(callout_queue, urlfile_retry_ev);
			urlfile_retry_ev = NULL;
		}

		gwc_get_urls();
	}

	periodic_refresh_ev = cq_insert(callout_queue,
		REFRESH_MS, gwc_periodic_refresh, NULL);
}

/**
 * Called when we failed last urlfile request, after some delay.
 * Scheduled as a callout queue event.
 */
static void
gwc_urlfile_retry(cqueue_t *unused_cq, gpointer unused_obj)
{
	(void) unused_cq;
	(void) unused_obj;

	urlfile_retry_ev = NULL;
	gwc_get_urls();
}

/**
 * Initialize web cache.
 */
void
gwc_init(void)
{
	guint i;

	gwc_known_url = g_hash_table_new(g_str_hash, g_str_equal);
	gwc_failed_url = g_hash_table_new(g_str_hash, g_str_equal);

	gwc_retrieve();
	if (0 == g_hash_table_size(gwc_known_url)) {
		for (i = 0; i < G_N_ELEMENTS(boot_url); i++)
			gwc_add(boot_url[i]);
	}

	if (ancient_version)
		return;				/* Older versions must have a harder time */

	/*
	 * Schedule hourly updates, starting our first in 10 minutes:
	 * It is hoped that by then, we'll have a stable IP and will know
	 * whether we're firewalled or not.
	 */

	hourly_update_ev = cq_insert(callout_queue,
		HOUR_MS / 6, gwc_hourly_update, NULL);

	periodic_refresh_ev = cq_insert(callout_queue,
		REFRESH_MS, gwc_periodic_refresh, NULL);
}

/**
 * Ensures that we have a valid `current_url' or pick a new one.
 * Also force change a the current URL after too many uses.
 *
 * @return TRUE if we got a valid URL.
 */
static gboolean
check_current_url(void)
{
	if (current_url == NULL || current_reused >= MAX_GWC_REUSE) {
		/*
		 * `current_url' must be an atom since we may replace the value
		 * in the cache at any time: we could be using a cache even after
		 * its entry has been superseded.
		 */
		gchar *ptr = gwc_pick();

		if (current_url != NULL)
			atom_str_free(current_url);

		current_url = ptr == NULL ? NULL : atom_str_get(ptr);
		current_reused = 0;
	} else
		current_reused++;

	return current_url != NULL;
}

/**
 * Removes the URL from the set of known URL, but do not free its memory
 * and keeps it in the set of failed URLs for the session.
 */
static void
forget_url(gchar *url)
{
	struct gwc url_tmp[MAX_GWC_URLS];			/* Temporary copy */
	gint count = g_hash_table_size(gwc_known_url);
	gint i;
	gint j = 0;

	g_assert(count > 0);
	g_assert(count <= MAX_GWC_URLS);
	g_assert(count == MAX_GWC_URLS || gwc_url_slot < count);
	g_assert(gwc_url_slot >= 0);
	STATIC_ASSERT(sizeof(url_tmp) == sizeof(gwc_url));

	if (gwc_debug)
		g_warning("forgetting GWC URL \"%s\"", url);

	/*
	 * It is possible that the URL we're trying to forget was
	 * already removed from the cache if it was at a slot overridden
	 * in the round-robin buffer, should we have got new GWC URL since
	 * it was selected.
	 */

	if (g_hash_table_lookup(gwc_known_url, url))
		g_hash_table_remove(gwc_known_url, url);
	else {
		if (gwc_debug)
			g_warning("URL was already gone from GWC");
		return;
	}
	g_hash_table_insert(gwc_failed_url, url, GUINT_TO_POINTER(1));

	/*
	 * Because we have a round-robin buffer, removing something in the
	 * middle of the buffer is not straightforward.  The `gwc_url_slot'
	 * variable points to the last filled value in the buffer.
	 *
	 * We're going to build a copy in url_tmp[], filled from 0 to "count - 1",
	 * and we'll move back that copy into the regular gwc_url[] cache.
	 * The reason is that since there will be less entries in the cache
	 * than the maximum amount, the round-robin buffer must be linearily
	 * filled from 0 and upwards.
	 */

	memset(url_tmp, 0, sizeof(url_tmp));

	if (count == MAX_GWC_URLS) {		/* Buffer was full */
		for (i = gwc_url_slot;;) {
			if (gwc_url[i].url != url)	/* Atoms: we can compare addresses */
				url_tmp[j++] = gwc_url[i];
			i++;
			if (i == MAX_GWC_URLS)
				i = 0;
			if (i == gwc_url_slot)		/* Back to where we started */
				break;
		}
	} else {							/* Buffer was partially filled */
		for (i = 0; i <= gwc_url_slot; i++) {
			if (gwc_url[i].url != url)	/* Atoms: we can compare addresses */
				url_tmp[j++] = gwc_url[i];
		}
	}

	count--;							/* New amount of data in cache */
	gwc_url_slot = j - 1;				/* Last position we filled */
	gwc_url_slot = MAX(0, gwc_url_slot);	/* If we removed ALL entries */
	g_assert(gwc_url_slot == MAX(0, count - 1));
	memcpy(gwc_url, url_tmp, sizeof(gwc_url));
	g_assert(gwc_url_slot >= 0 && gwc_url_slot < MAX_GWC_URLS);

	gwc_file_dirty = TRUE;
}

/**
 * Dispose of current URL atom, if defined.
 * When `discard' is set, we remove the current URL physically from our cache.
 */
static void
clear_current_url(gboolean discard)
{
	if (current_url == NULL)
		return;

	if (discard)
		forget_url(current_url);

	atom_str_free(current_url);
	current_url = NULL;
}

/**
 * Frees the atom used as hash table key 
 */
static void
free_failed_url(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	(void) unused_value;
	(void) unused_udata;
	atom_str_free(key);
}

/**
 * Called when servent shuts down.
 */
void
gwc_close(void)
{
	gint i;

	if (hourly_update_ev)
		cq_cancel(callout_queue, hourly_update_ev);
	if (periodic_refresh_ev)
		cq_cancel(callout_queue, periodic_refresh_ev);
	if (urlfile_retry_ev)
		cq_cancel(callout_queue, urlfile_retry_ev);

	gwc_store();
	g_hash_table_destroy(gwc_known_url);
	g_hash_table_foreach(gwc_failed_url, free_failed_url, NULL);
	g_hash_table_destroy(gwc_failed_url);

	for (i = 0; i < MAX_GWC_URLS; i++) {
		gchar *url = gwc_url[i].url;
		if (url == NULL)
			continue;
		atom_str_free(url);
	}

	clear_current_url(FALSE);
}

/***
 *** Line-by-line parsing context.
 ***/

struct parse_context {
	getline_t *getline;			/**< Used to hold partially read line */
	gpointer handle;			/**< Request handle */
	gint maxlines;				/**< Maximum number of lines we want to process */
	gint lines;					/**< Amount of lines so far */
	gint processed;				/**< User callback can count retained lines */
};

typedef gboolean (parse_dispatch_t)
	(struct parse_context *c, const gchar *buf, size_t len);
typedef void (parse_eof_t)(struct parse_context *c);

/**
 * Free parsing context.
 */
static void
parse_context_free(gpointer obj)
{
	struct parse_context *ctx = (struct parse_context *) obj;

	getline_free(ctx->getline);
	wfree(ctx, sizeof(*ctx));
}

/**
 * Allocate new parsing context for handle and record it.
 *
 * @param `handle'		the asynchronous HTTP request handle.
 * @param `maxlines'	the max number of lines we want to parse.
 */
static void
parse_context_set(gpointer handle, gint maxlines)
{
	struct parse_context *ctx;

	ctx = walloc(sizeof(*ctx));
	ctx->getline = getline_make(MAX_LINE_SIZE);
	ctx->maxlines = maxlines;
	ctx->handle = handle;
	ctx->lines = 0;
	ctx->processed = 0;

	http_async_set_opaque(handle, ctx, parse_context_free);
}


/**
 * Analyze the data we have received, and give each line to the supplied
 * dispatcher callback `cb', after having chomped it.  On EOF, call `eof'
 * to finalize parsing.
 */
static void
parse_dispatch_lines(gpointer handle, const gchar *buf, size_t len,
		parse_dispatch_t cb, parse_eof_t eof)
{
	struct parse_context *ctx;
	getline_t *getline;
	const gchar *p = buf;
	size_t remain = len;

	/*
	 * Retrieve parsing context, stored as an opaque attribute in the
	 * asynchronous HTTP request handle.
	 */

	ctx = http_async_get_opaque(handle);

	g_assert(ctx->handle == handle);	/* Make sure it's the right context */

	if (len == 0) {						/* Nothing to parse, got EOF */
		if (eof)
			(*eof)(ctx);
		return;
	}

	/*
	 * Read a line at a time.
	 */

	getline = ctx->getline;

	for (;;) {
		gchar *line;
		gboolean error;
		size_t line_len;
		size_t parsed;

		switch (getline_read(getline, p, remain, &parsed)) {
		case READ_OVERFLOW:
			http_async_cancel(handle);
			return;
		case READ_DONE:
			p += parsed;
			remain -= parsed;
			break;
		case READ_MORE:			/* ok, but needs more data */
			g_assert(parsed == remain);
			return;
		}

		/*
		 * We come here everytime we get a full line.
		 */

		line = g_strdup(getline_str(getline));
		line_len = getline_length(getline);
		line_len = str_chomp(line, line_len);

		error = !(*cb)(ctx, line, line_len); /* An ERROR was reported */
		G_FREE_NULL(line);

		if (error) {
	   		clear_current_url(FALSE);
			return;
		}

		/*
		 * Make sure we don't process lines ad infinitum.
		 */

		ctx->lines++;
		if (ctx->lines >= ctx->maxlines) {
			const gchar *req;
			const gchar *url = http_async_info(handle, &req, NULL, NULL, NULL);
			g_warning("got %d+ lines from \"%s %s\", stopping",
				ctx->lines, req, url);
			http_async_close(handle);
			return;
		}

		getline_reset(getline);
	}
}

/***
 *** GET ...?urlfile=1
 ***/

/**
 * Called from parse_dispatch_lines() for each complete line of output.
 *
 * @return FALSE to stop processing of any remaining data.
 */
static gboolean
gwc_url_line(struct parse_context *ctx, const gchar *buf, size_t len)
{
	if (gwc_debug > 3)
		g_message("GWC URL line (%lu bytes): %s", (gulong) len, buf);

	if (is_strprefix(buf, "ERROR")) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	/* XXX -- Ignore "chunked" output */
	if (len && !(*buf == 'h' || *buf == 'H'))
		return TRUE;

	if (len) {
		ctx->processed++;
		gwc_add(buf);		/* Add URL to cache */
	}

	return TRUE;
}

/**
 * Called from parse_dispatch_lines() on EOF.
 */
static void
gwc_url_eof(struct parse_context *ctx)
{
	if (gwc_debug > 2)
		g_message("GWC URL all done (%d/%d lines processed)",
			ctx->processed, ctx->lines);

	if (ctx->processed < MIN_URL_LINES) {
		gwc_seed_cache(current_url);
		clear_current_url(TRUE);	/* This webcache has nothing */

		/*
		 * Retry the urlfile request after some delay.
		 */

		g_assert(urlfile_retry_ev == NULL);

		urlfile_retry_ev = cq_insert(callout_queue,
			URL_RETRY_MS, gwc_urlfile_retry, NULL);
	}
}

/**
 * Populate callback: more data available.
 */
static void
gwc_url_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_url_line, gwc_url_eof);
}

/**
 * HTTP request is being stopped.
 */
static void
gwc_url_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error_dbg(handle, type, v, gwc_debug);

	clear_current_url(TRUE);		/* This webcache is not good */

	/*
	 * Retry the urlfile request after some delay.
	 */

	g_assert(urlfile_retry_ev == NULL);

	urlfile_retry_ev = cq_insert(callout_queue,
		URL_RETRY_MS, gwc_urlfile_retry, NULL);
}

/**
 * Retrieve more web caches, asynchronously.
 *
 * We'll try again and again, until we reach a good cache that answers
 * with at least one request.
 */
static void
gwc_get_urls(void)
{
	gpointer handle;

	g_assert(urlfile_retry_ev == NULL);

	if (!check_current_url())
		return;

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		"%s?urlfile=1&%s", current_url, CLIENT_INFO);

	if (gwc_debug > 2)
		g_message("GWC URL request: %s", gwc_tmp);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	handle = http_async_get(gwc_tmp,
		NULL, gwc_url_data_ind, gwc_url_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		clear_current_url(TRUE);
		return;
	}

	parse_context_set(handle, MAX_URL_LINES);
}

/***
 *** GET ...?hostfile=1
 ***/

static gboolean hostfile_running = FALSE;

/**
 * Check whether we're waiting for a hostfile request.
 */
gboolean
gwc_is_waiting(void)
{
	return hostfile_running;
}

/**
 * Called from parse_dispatch_lines() for each complete line of output.
 *
 * @return FALSE to stop processing of any remaining data.
 */
static gboolean
gwc_host_line(struct parse_context *ctx, const gchar *buf, size_t len)
{
	if (gwc_debug > 3 || bootstrap_debug > 2)
		g_message("BOOT GWC host line (%lu bytes): %s", (gulong) len, buf);

	if (is_strprefix(buf, "ERROR")) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	if (len) {
		host_addr_t addr;
		guint16 port;

		if (string_to_host_addr_port(buf, NULL, &addr, &port)) {
			ctx->processed++;
			hcache_add_caught(HOST_ULTRA, addr, port, "GWC");

			if (bootstrap_debug > 1)
				g_message("BOOT collected %s from GWC %s",
					host_addr_to_string(addr),
					http_async_info(ctx->handle, NULL, NULL, NULL, NULL));
		}
	}

	return TRUE;
}

/**
 * Called from parse_dispatch_lines() on EOF.
 */
static void
gwc_host_eof(struct parse_context *ctx)
{
	if (gwc_debug > 2)
		g_message("GWC host all done (%d/%d lines processed)",
			ctx->processed, ctx->lines);

	/*
	 * Provide GUI feedback.
	 */

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		NG_("Got %d host from %s", "Got %d hosts from %s", ctx->processed),
		ctx->processed, current_url);

	gcu_statusbar_message(gwc_tmp);

	if (bootstrap_debug)
		g_message("BOOT got %d host%s from GWC %s",
			ctx->processed, ctx->processed == 1 ? "" : "s", current_url);

	/*
	 * If we did not get enough addresses, try to feed the cache with ours.
	 */

	if (ctx->processed < MIN_IP_LINES) {
		gwc_seed_cache(current_url);
		clear_current_url(FALSE);			/* Move to another cache */
	}

	hostfile_running = FALSE;
}

/**
 * Populate callback: more data available.
 */
static void
gwc_host_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_host_line, gwc_host_eof);
}

/**
 * HTTP request is being stopped.
 */
static void
gwc_host_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error_dbg(handle, type, v, MAX(gwc_debug, bootstrap_debug));
	hostfile_running = FALSE;

	clear_current_url(TRUE);			/* This webcache is not good */
}

/**
 * Retrieve more hosts from web cache, asynchronously.
 */
void
gwc_get_hosts(void)
{
	gpointer handle;
	static time_t last_called = 0;
	time_t now = tm_time();

	/*
	 * Make sure we don't probe more than one webcache at a time.
	 * Ancient versions should rely on their hostcache to be connected.
	 */

	if (hostfile_running || ancient_version)
		return;

	/*
	 * This routine is called each time we run out of hosts to try in our
	 * cache, so we have absolutely no guarantee about the frequency at which
	 * it will be called.
	 *
	 * Force picking up a new cache (well, randomly) if we were called less
	 * than an hour ago.  Note that we don't remember whether it was THIS
	 * particular current cache that was accessed last time we were called.
	 * We only care about the calling frequency, and bet on the high number
	 * of available web caches and the random selection process to behave.
	 * properly.
	 *		--RAM, 24/11/2003
	 */

	if (delta_time(now, last_called) < REUSE_PERIOD)
		clear_current_url(FALSE);

	last_called = now;

	if (!check_current_url())
		return;

	/*
	 * Give some GUI feedback.
	 */

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		_("Connecting to web cache %s"), current_url);

	gcu_statusbar_message(gwc_tmp);

	if (bootstrap_debug)
		g_message("BOOT connecting to web cache %s", current_url);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		"%s?hostfile=1&%s", current_url, CLIENT_INFO);

	if (gwc_debug > 2)
		g_message("GWC host request: %s", gwc_tmp);

	handle = http_async_get(gwc_tmp,
		NULL, gwc_host_data_ind, gwc_host_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		clear_current_url(TRUE);
		return;
	}

	parse_context_set(handle, MAX_IP_LINES);
	hostfile_running = TRUE;
}

/***
 *** GET ...?ip=....
 ***/

/**
 * Called from parse_dispatch_lines() for each complete line of output.
 *
 * @return FALSE to stop processing of any remaining data.
 */
static gboolean
gwc_update_line(struct parse_context *ctx, const gchar *buf, size_t len)
{
	if (gwc_debug > 3)
		g_message("GWC update line (%lu bytes): %s", (gulong) len, buf);

	if (is_strprefix(buf, "OK")) {
		if (gwc_debug > 2)
			g_message("GWC update OK for \"%s\"",
				http_async_info(ctx->handle, NULL, NULL, NULL, NULL));
		http_async_close(ctx->handle);		/* OK, don't read more */
		return FALSE;
	} else if (is_strprefix(buf, "ERROR")) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	return TRUE;
}

/**
 * Populate callback: more data available.
 */
static void
gwc_update_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_update_line, NULL);
}

/**
 * HTTP request is being stopped.
 */
static void
gwc_update_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error_dbg(handle, type, v, gwc_debug);
	clear_current_url(TRUE);			/* This webcache is not good */
}

/**
 * Publish our IP to the named cache `cache_url' and propagate one random URL.
 */
static void
gwc_update_this(gchar *cache_url)
{
	gpointer handle;
	size_t rw;

	g_assert(cache_url != NULL);

	rw = concat_strings(gwc_tmp, sizeof gwc_tmp, cache_url, "?", (void *) 0);
	g_return_if_fail(rw < sizeof gwc_tmp);

	/*
	 * Send our IP:port information if we're connectible, we are
	 * not firewalled, and we're not in leaf mode.
	 */

	if (
		!is_firewalled &&
		current_peermode == NODE_P_ULTRA &&
		host_is_valid(listen_addr(), socket_listen_port())
	) {
		rw += gm_snprintf(&gwc_tmp[rw], sizeof(gwc_tmp)-rw, "ip=%s&",
			host_addr_port_to_string(listen_addr(), socket_listen_port()));
	} else {

		/*
		 * If we don't have anything to submit, we're done.
		 */

		if (gwc_debug > 2)
			g_message("GWC update has nothing to send");
		return;
	}

	/*
	 * Finally, append our client/version information.
	 */

	g_strlcpy(&gwc_tmp[rw], CLIENT_INFO, sizeof(gwc_tmp)-rw);

	if (gwc_debug > 2)
		g_message("GWC update request: %s", gwc_tmp);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	handle = http_async_get(gwc_tmp,
		NULL, gwc_update_data_ind, gwc_update_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		if (cache_url == current_url)
			clear_current_url(TRUE);
		return;
	}

	/*
	 * Provide GUI feedback in the statusbar.
	 */

	concat_strings(gwc_tmp, sizeof(gwc_tmp),
		_("Updated web cache "), cache_url, (void *) 0);
	gcu_statusbar_message(gwc_tmp);

	parse_context_set(handle, MAX_OK_LINES);
}

/**
 * Publish our IP to the named cache `cache_url' and propagate one random URL.
 *
 * We sometimes forcefully call this routine with a cache that does not return
 * anything to us, to try to "bootstrap" it by feeding some data.
 */
static void
gwc_seed_cache(gchar *cache_url)
{
	if (cache_url == NULL)
		return;

	if (gwc_debug > 2)
		g_message("GWC seeding cache \"%s\"", cache_url);

	gwc_update_this(cache_url);
}

/**
 * Publish our IP to the web cache and propagate one random URL.
 */
static void
gwc_update_ip_url(void)
{
	if (current_peermode == NODE_P_LEAF || !check_current_url())
		return;

	gwc_update_this(current_url);
}

/* vi: set ts=4 sw=4 cindent: */
