/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Gnutella Web Cache.
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

#include "gnutella.h"			/* For proper -DUSE_DMALLOC compiles */

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "gwcache.h"
#include "http.h"
#include "hosts.h"
#include "version.h"

#include "settings.h"

RCSID("$Id$");

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

#define MAX_GWC_URLS	200					/* Max URLs we store */
#define MAX_GWC_REUSE	8					/* Max amount of uses for one URL */

static gchar *gwc_url[MAX_GWC_URLS];		/* Holds string atoms */
static gint gwc_url_slot = -1;
static GHashTable *gwc_known_url = NULL;

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

static gchar *current_url = NULL;			/* Cache we're currently using */
static gint current_reused = 0;				/* Amount of times we reused it */

#define MAX_URL_LINES	50					/* Max lines on a urlfile req */
#define MAX_IP_LINES	50					/* Max lines on a hostfile req */
#define MAX_OK_LINES	3					/* Max lines when expecting OK */
#define MIN_IP_LINES	5					/* Min lines expected */
#define MIN_URL_LINES	5					/* Min lines expected */
#define HOUR_MS			(3600 * 1000)		/* Callout queue time in ms */
#define URL_RETRY_MS	(20 * 1000)			/* Retry timer for urlfile, in ms */
#define REFRESH_MS		(8 * HOUR_MS)		/* Refresh every 8 hours */

static gchar *gwc_file = "gwcache";
static gchar *gwc_bootfile = "gwcache.boot";
static gchar *gwc_what = "web cache URLs";

static gpointer hourly_update_ev = NULL;
static gpointer periodic_refresh_ev = NULL;
static gpointer urlfile_retry_ev = NULL;
static gchar *client_info;
static gboolean gwc_file_dirty = FALSE;

static void gwc_get_urls(void);
static void gwc_update_ip_url(void);
static void gwc_seed_cache(gchar *cache_url);

extern cqueue_t *callout_queue;

/*
 * gwc_add
 *
 * Add new URL to cache, possibly pushing off an older one if cache is full.
 */
static void gwc_add(gchar *url)
{
	gchar *url_atom;
	gchar *old_url;

	/*
	 * Don't add duplicates in the cache.
	 */

	if (g_hash_table_lookup(gwc_known_url, url))
		return;

	/*
	 * Make sure the entry is well-formed.
	 */

	if (!http_url_parse(url, NULL, NULL, NULL, NULL)) {
		g_warning("ignoring bad web cache URL \"%s\": %s",
			url, http_url_strerror(http_url_errno));
		return;
	}

	/*
	 * OK, record new entry at the `gwc_url_slot'.
	 */

	if (++gwc_url_slot >= MAX_GWC_URLS)
		gwc_url_slot = 0;

	g_assert(url != NULL);
	url_atom = atom_str_get(url);

	/*
	 * Expire any entry present at the slot we're about to write into.
	 */

	old_url = gwc_url[gwc_url_slot];

	if (old_url != NULL) {
		g_assert(g_hash_table_lookup(gwc_known_url, old_url));
		g_hash_table_remove(gwc_known_url, old_url);
		atom_str_free(old_url);
	}

	g_hash_table_insert(gwc_known_url, url_atom, (gpointer) 0x1);

	gwc_url[gwc_url_slot] = url_atom;
	gwc_file_dirty = TRUE;
}

/*
 * gwc_pick
 *
 * Pickup a cache randomly from the known set.
 */
static gchar *gwc_pick(void)
{
	gint count = g_hash_table_size(gwc_known_url);
	gint index;

	g_assert(count > 0);
	g_assert(count <= MAX_GWC_URLS);
	g_assert(count == MAX_GWC_URLS || gwc_url_slot < count);

	index = random_value(count - 1);

	if (dbg)
		g_warning("picked webcache %s", gwc_url[index]);

	return gwc_url[index];
}

/*
 * gwc_store
 *
 * Store known GWC URLs.
 * They are normally saved in ~/.gtk-gnutella/gwcache.
 */
static void gwc_store(void)
{
	FILE *out;
	gint i;
	gint j;
	file_path_t fp = { config_dir, gwc_file };

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
		gchar *url = gwc_url[i];
		i = (i == MAX_GWC_URLS - 1) ? 0 : (i + 1);
		if (url == NULL)
			continue;
		fprintf(out, "%s\n", url);
	}

	if (file_config_close(out, &fp))
		gwc_file_dirty = FALSE;
}

/*
 * gwc_store_if_dirty
 *
 * Store known GWC URLs if dirty.
 */
void gwc_store_if_dirty(void)
{
	if (gwc_file_dirty)
		gwc_store();
}

/*
 * gwc_retrieve
 *
 * Retrieve known GWC URLs.
 * They are normally saved in ~/.gtk-gnutella/gwcache.
 */
static void gwc_retrieve(void)
{
	gint line;
	FILE *in;
	file_path_t fpvec[] = {
		{ config_dir, gwc_file },
		{ PACKAGE_DATA_DIR, gwc_bootfile },
		{ PACKAGE_SOURCE_DIR, gwc_bootfile },
	};
	gchar tmp[1024];

	in = file_config_open_read(gwc_what, fpvec, G_N_ELEMENTS(fpvec));

	if (!in)
		return;

	/*
	 * Retrieve each line.
	 */

	line = 0;

	while (fgets(tmp, sizeof(tmp) - 1, in)) {	/* Room for trailing NUL */
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

/*
 * gwc_hourly_update
 *
 * Hourly web cache update.
 * Scheduled as a callout queue event.
 */
static void gwc_hourly_update(cqueue_t *cq, gpointer obj)
{
	gwc_update_ip_url();

	hourly_update_ev = cq_insert(callout_queue,
		HOUR_MS, gwc_hourly_update, NULL);
}

/*
 * gwc_periodic_refresh
 *
 * Hourly web cache refresh.
 * Scheduled as a callout queue event.
 */
static void gwc_periodic_refresh(cqueue_t *cq, gpointer obj)
{
	/*
	 * Disable retry timer, since we are about to retry now based on our
	 * regular background periodic refreshing.
	 */

	if (urlfile_retry_ev) {
		cq_cancel(callout_queue, urlfile_retry_ev);
		urlfile_retry_ev = NULL;
	}

	gwc_get_urls();

	periodic_refresh_ev = cq_insert(callout_queue,
		REFRESH_MS, gwc_periodic_refresh, NULL);
}

/*
 * gwc_urlfile_retry
 *
 * Called when we failed last urlfile request, after some delay.
 * Scheduled as a callout queue event.
 */
static void gwc_urlfile_retry(cqueue_t *cq, gpointer obj)
{
	urlfile_retry_ev = NULL;
	gwc_get_urls();
}

/*
 * gwc_init
 *
 * Initialize web cache.
 */
void gwc_init(void)
{
	gwc_known_url = g_hash_table_new(g_str_hash, g_str_equal);

	client_info = g_strdup_printf("client=GTKG&version=%s", version_number);

	/*
	 * The following URLs are there for bootstrapping purposes only.
	 */

	gwc_add("http://www.gnucleus.net/gcache/gcache.php");
	gwc_add("http://gwebcache.bearshare.net/gcache.php");
	gwc_add("http://raphael.manfredi.free.fr/gwc/gcache.php");

	gwc_retrieve();
	gwc_get_urls();

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

/*
 * check_current_url
 *
 * Ensures that we have a valid `current_url' or pick a new one.
 * Also force change a the current URL after too many uses.
 *
 * Returns TRUE if we got a valid URL.
 */
static gboolean check_current_url(void)
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

/*
 * clear_current_url
 *
 * Dispose of current URL atom, if defined.
 */
static void clear_current_url(void)
{
	if (current_url == NULL)
		return;

	atom_str_free(current_url);
	current_url = NULL;
}

/*
 * gwc_close
 *
 * Called when servent shuts down.
 */
void gwc_close(void)
{
	gint i;

	cq_cancel(callout_queue, hourly_update_ev);
	cq_cancel(callout_queue, periodic_refresh_ev);
	if (urlfile_retry_ev)
		cq_cancel(callout_queue, urlfile_retry_ev);
	g_free(client_info);

	gwc_store();
	g_hash_table_destroy(gwc_known_url);

	for (i = 0; i < MAX_GWC_URLS; i++) {
		gchar *url = gwc_url[i];
		if (url == NULL)
			continue;
		atom_str_free(url);
	}

	clear_current_url();
}

/***
 *** Line-by-line parsing context.
 ***/

struct parse_context {
	getline_t *getline;			/* Used to hold partially read line */
	gpointer handle;			/* Request handle */
	gint maxlines;				/* Maximum number of lines we want to process */
	gint lines;					/* Amount of lines so far */
	gint processed;				/* User callback can count retained lines */
};

typedef gboolean (parse_dispatch_t)
	(struct parse_context *c, gchar *buf, gint len);
typedef void (parse_eof_t)(struct parse_context *c);

/*
 * parse_context_free
 *
 * Free parsing context.
 */
static void parse_context_free(gpointer obj)
{
	struct parse_context *ctx = (struct parse_context *) obj;

	getline_free(ctx->getline);
	wfree(ctx, sizeof(*ctx));
}

/*
 * parse_context_set
 *
 * Allocate new parsing context for handle and record it.
 *
 * `handle' is the asynchronous HTTP request handle.
 * `maxlines' is the max number of lines we want to parse.
 */
static void parse_context_set(gpointer handle, gint maxlines)
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


/*
 * parse_dispatch_lines
 *
 * Analyze the data we have received, and give each line to the supplied
 * dispatcher callback `cb', after having chomped it.  On EOF, call `eof'
 * to finalize parsing.
 */
static void parse_dispatch_lines(
	gpointer handle, gchar *buf, gint len, parse_dispatch_t cb, parse_eof_t eof)
{
	struct parse_context *ctx;
	getline_t *getline;
	gchar *p = buf;
	gint remain = len;
	guint parsed;
	gint linelen;
	gchar *linep;

	/*
	 * Retrieve parsing context, stored as an opaque attribute in the
	 * asynchronous HTTP request handle.
	 */
	
	ctx = (struct parse_context *) http_async_get_opaque(handle);

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
		switch (getline_read(getline, p, remain, &parsed)) {
		case READ_OVERFLOW:
			http_async_cancel(handle);
			return;
		case READ_DONE:
			p += parsed;
			remain -= parsed;
			break;
		case READ_MORE:			/* ok, but needs more data */
		default:
			g_assert(parsed == remain);
			return;
		}

		/*
		 * We come here everytime we get a full line.
		 */

		linep = getline_str(getline);
		linelen = str_chomp(linep, getline_length(getline));
		if (!(*cb)(ctx, linep, linelen))
			return;

		/*
		 * Make sure we don't process lines ad infinitum.
		 */

		ctx->lines++;
		if (ctx->lines >= ctx->maxlines) {
			gchar *req;
			gchar *url = http_async_info(handle, &req, NULL, NULL, NULL);
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

/*
 * gwc_url_line
 *
 * Called from parse_dispatch_lines() for each complete line of output.
 * Returns FALSE to stop processing of any remaining data.
 */
static gboolean gwc_url_line(struct parse_context *ctx, gchar *buf, gint len)
{
	if (dbg > 3)
		printf("GWC URL line (%d bytes): %s\n", len, buf);

	if (0 == strncmp(buf, "ERROR", 5)) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	// XXX -- Ignore "chunked" output
	if (len && !(*buf == 'h' || *buf == 'H'))
		return TRUE;

	if (len) {
		ctx->processed++;
		gwc_add(buf);		/* Add URL to cache */
	}

	return TRUE;
}

/*
 * gwc_url_eof
 *
 * Called from parse_dispatch_lines() on EOF.
 */
static void gwc_url_eof(struct parse_context *ctx)
{
	if (dbg > 2)
		printf("GWC URL all done (%d/%d lines processed)\n",
			ctx->processed, ctx->lines);

	if (ctx->processed < MIN_URL_LINES) {
		gwc_seed_cache(current_url);
		clear_current_url();		/* This webcache has nothing */

		/*
		 * Retry the urlfile request after some delay.
		 */

		g_assert(urlfile_retry_ev == NULL);

		urlfile_retry_ev = cq_insert(callout_queue,
			URL_RETRY_MS, gwc_urlfile_retry, NULL);
	}
}

/*
 * gwc_url_data_ind
 *
 * Populate callback: more data available.
 */
static void gwc_url_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_url_line, gwc_url_eof);
}

/*
 * gwc_url_error_ind
 *
 * HTTP request is being stopped.
 */
static void gwc_url_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error(handle, type, v);

	clear_current_url();			/* This webcache is not good */

	/*
	 * Retry the urlfile request after some delay.
	 */

	g_assert(urlfile_retry_ev == NULL);

	urlfile_retry_ev = cq_insert(callout_queue,
		URL_RETRY_MS, gwc_urlfile_retry, NULL);
}

/*
 * gwc_get_urls
 *
 * Retrieve more web caches, asynchronously.
 *
 * We'll try again and again, until we reach a good cache that answers
 * with at least one request.
 */
static void gwc_get_urls(void)
{
	gpointer handle;

	g_assert(urlfile_retry_ev == NULL);

	if (!check_current_url())
		return;

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		"%s?urlfile=1&%s", current_url, client_info);

	if (dbg > 2)
		printf("GWC URL request: %s\n", gwc_tmp);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	handle = http_async_get(gwc_tmp,
		NULL, gwc_url_data_ind, gwc_url_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		clear_current_url();
		return;
	}

	parse_context_set(handle, MAX_URL_LINES);
}

/***
 *** GET ...?hostfile=1
 ***/

static gboolean hostfile_running = FALSE;

/*
 * gwc_host_line
 *
 * Called from parse_dispatch_lines() for each complete line of output.
 * Returns FALSE to stop processing of any remaining data.
 */
static gboolean gwc_host_line(struct parse_context *ctx, gchar *buf, gint len)
{
	if (dbg > 3)
		printf("GWC host line (%d bytes): %s\n", len, buf);

	if (0 == strncmp(buf, "ERROR", 5)) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	if (len) {
		guint32 ip;
		guint16 port;

		if (gchar_to_ip_port(buf, &ip, &port)) {
			ctx->processed++;
			host_add(ip, port, FALSE);
		}
	}

	return TRUE;
}

/*
 * gwc_host_eof
 *
 * Called from parse_dispatch_lines() on EOF.
 */
static void gwc_host_eof(struct parse_context *ctx)
{
	if (dbg > 2)
		printf("GWC host all done (%d/%d lines processed)\n",
			ctx->processed, ctx->lines);

	if (ctx->processed < MIN_IP_LINES) {
		gwc_seed_cache(current_url);
		clear_current_url();				/* Move to another cache */
	}

	hostfile_running = FALSE;
}

/*
 * gwc_host_data_ind
 *
 * Populate callback: more data available.
 */
static void gwc_host_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_host_line, gwc_host_eof);
}

/*
 * gwc_host_error_ind
 *
 * HTTP request is being stopped.
 */
static void gwc_host_error_ind(gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error(handle, type, v);
	hostfile_running = FALSE;
}

/*
 * gwc_get_hosts
 *
 * Retrieve more hosts from web cache, asynchronously.
 */
void gwc_get_hosts(void)
{
	gpointer handle;

	/*
	 * Make sure we don't probe more than one webcache at a time.
	 */

	if (hostfile_running)
		return;

	if (!check_current_url())
		return;

	gm_snprintf(gwc_tmp, sizeof(gwc_tmp),
		"%s?hostfile=1&%s", current_url, client_info);

	if (dbg > 2)
		printf("GWC host request: %s\n", gwc_tmp);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	handle = http_async_get(gwc_tmp,
		NULL, gwc_host_data_ind, gwc_host_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		clear_current_url();
		return;
	}

	parse_context_set(handle, MAX_IP_LINES);
	hostfile_running = TRUE;
}

/***
 *** GET ...?ip=....&url=....
 ***/

/*
 * gwc_update_line
 *
 * Called from parse_dispatch_lines() for each complete line of output.
 * Returns FALSE to stop processing of any remaining data.
 */
static gboolean gwc_update_line(struct parse_context *ctx, gchar *buf, gint len)
{
	if (dbg > 3)
		printf("GWC update line (%d bytes): %s\n", len, buf);

	if (0 == strncmp(buf, "OK", 2)) {
		if (dbg > 2)
			printf("GWC update OK for \"%s\"\n",
				http_async_info(ctx->handle, NULL, NULL, NULL, NULL));
		http_async_close(ctx->handle);		/* OK, don't read more */
		return FALSE;
	}
	else if (0 == strncmp(buf, "ERROR", 5)) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_info(ctx->handle, NULL, NULL, NULL, NULL), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	return TRUE;
}

/*
 * gwc_update_data_ind
 *
 * Populate callback: more data available.
 */
static void gwc_update_data_ind(gpointer handle, gchar *data, gint len)
{
	parse_dispatch_lines(handle, data, len, gwc_update_line, NULL);
}

/*
 * gwc_host_error_ind
 *
 * HTTP request is being stopped.
 */
static void gwc_update_error_ind(
	gpointer handle, http_errtype_t type, gpointer v)
{
	http_async_log_error(handle, type, v);
	clear_current_url();				/* This webcache is not good */
}

/*
 * gwc_update_this
 *
 * Publish our IP to the named cache `cache_url' and propagate one random URL.
 */
static void gwc_update_this(gchar *cache_url)
{
	gpointer handle;
	gchar *url = NULL;
	gboolean found_alternate = FALSE;
	gboolean has_data = FALSE;
	gint rw;
	gint i;

	g_assert(cache_url != NULL);

	rw = gm_snprintf(gwc_tmp, sizeof(gwc_tmp), "%s?", cache_url);

	/*
	 * Choose another URL randomly.
	 */

	for (i = 0; i < MAX_GWC_URLS; i++) {
		url = gwc_pick();
		if (0 != strcmp(url, cache_url)) {
			found_alternate = TRUE;
			break;
		}
	}

	/*
	 * If we found an URL different from the cache we're going to update,
	 * publish the escaped URL in the request.
	 */

	if (found_alternate) {
		gchar *escaped_url = url_escape_query(url);		/* For query string */

		rw += gm_snprintf(&gwc_tmp[rw], sizeof(gwc_tmp)-rw,
			"url=%s&", escaped_url);

		if (escaped_url != url)
			g_free(escaped_url);

		has_data = TRUE;		/* We have something to submit */
	}

	/*
	 * Send our IP:port information if we're connectible, we are
	 * not firewalled, and we're not in leaf mode.
	 */

	if (
		!is_firewalled &&
		current_peermode != NODE_P_LEAF &&
		host_is_valid(listen_ip(), listen_port)
	) {
		rw += gm_snprintf(&gwc_tmp[rw], sizeof(gwc_tmp)-rw,
			"ip=%s&", ip_port_to_gchar(listen_ip(), listen_port));
		has_data = TRUE;
	}

	/*
	 * If we don't have anything to submit, we're done.
	 */

	if (!has_data) {
		if (dbg > 2)
			printf("GWC update has nothing to send\n");
		return;
	}

	/*
	 * Finally, append our client/version information.
	 */

	rw += gm_snprintf(&gwc_tmp[rw], sizeof(gwc_tmp)-rw, "%s", client_info);
	

	if (dbg > 2)
		printf("GWC update request: %s\n", gwc_tmp);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	handle = http_async_get(gwc_tmp,
		NULL, gwc_update_data_ind, gwc_update_error_ind);

	if (!handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			gwc_tmp, http_async_strerror(http_async_errno));
		if (cache_url == current_url)
			clear_current_url();
		return;
	}

	parse_context_set(handle, MAX_OK_LINES);
}

/*
 * gwc_seed_cache
 *
 * Publish our IP to the named cache `cache_url' and propagate one random URL.
 *
 * We sometimes forcefully call this routine with a cache that does not return
 * anything to us, to try to "bootstrap" it by feeding some data.
 */
static void gwc_seed_cache(gchar *cache_url)
{
	if (cache_url == NULL)
		return;

	if (dbg > 2)
		printf("GWC seeding cache \"%s\"\n", cache_url);

	gwc_update_this(cache_url);
}

/*
 * gwc_update_ip_url
 *
 * Publish our IP to the web cache and propagate one random URL.
 */
static void gwc_update_ip_url(void)
{
	if (!check_current_url())
		return;
	gwc_update_this(current_url);
}

