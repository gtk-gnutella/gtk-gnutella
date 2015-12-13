/*
 * Copyright (c) 2001-2003, 2014 Raphael Manfredi
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
 * Gnutella Web Cache (version 2).
 *
 * This is used only for bootstrapping purposes on the G2 network.
 *
 * @author Raphael Manfredi
 * @date 2001-2003, 2014
 */

#include "common.h"

#include "gtk-gnutella.h"

#include "gwc.h"

#include "core/http.h"
#include "core/hosts.h"
#include "core/hcache.h"
#include "core/settings.h"
#include "core/sockets.h"		/* For socket_listen_addr() */

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/file.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/header.h"			/* For header_dump() */
#include "lib/hset.h"
#include "lib/log.h"			/* For log_printable() */
#include "lib/misc.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"
#include "if/core/nodes.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * The web cache URLs are stored in a fixed-sized array: we remember only
 * a handful of URLs, and choose each time a random web cache among the
 * set for interaction.
 *
 * The array `gwc_url' is filled in a round-robin fashion, the last filled
 * position being `gwc_url_slot'.
 *
 * The `gwc_known_url' is actually a search table indexed by an URL to
 * prevent insertion of duplicates in our cache.
 */

#define MAX_GWC_URLS	200		/**< Max URLs we store */
#define MAX_GWC_REUSE	1		/**< Max amount of uses for one URL */

struct gwc {
	const char *url;			/**< atom */
	time_t stamp;				/**< time of last access */
} gwc_url[MAX_GWC_URLS];		/**< Holds string atoms */

static int gwc_url_slot = -1;
static hset_t *gwc_known_url;
static hset_t *gwc_failed_url;

static const char *gwc_current_url = NULL;	/**< Cache we're currently using */
static int gwc_current_reused = 0;			/**< Amount of times we reused it */

#define MAX_IP_LINES	150				/**< Max lines on a host req */
#define MIN_IP_LINES	5				/**< Min lines expected */
#define REUSE_PERIOD	3600			/**< Period between GET hostfile */

/**
 * Client name sent in GWC requests -- vendor code and version are concatenated.
 */
#define CLIENT_INFO "client=" GTA_VENDOR_CODE GTA_VERSION_NUMBER

static const char gwc_file[] = "gwcache";
static const char gwc_what[] = "web cache URLs";

static bool gwc_file_dirty;

/**
 * The following URLs are there for bootstrapping purposes only.
 */

static const char * const boot_url[] = {
	"http://cache.trillinux.org/g2/bazooka.php",
	"http://cache.ce3c.be/",
};

/**
 * Add new URL to cache, possibly pushing off an older one if cache is full.
 *
 * @return TRUE if the URL was added, FALSE otherwise.
 */
static bool
gwc_add(const char *new_url)
{
	const char *url_atom;
	const char *old_url;
	char *url, *ret;

	url = h_strdup(new_url); /* url_normalize() can modify the URL */

	ret = url_normalize(url, URL_POLICY_GWC_RULES);
	if (!ret) {
		g_warning("%s(): ignoring bad web cache URL \"%s\"",
			G_STRFUNC, new_url);
		HFREE_NULL(url);
		return FALSE;
	}
	if (ret != url) {
		HFREE_NULL(url);
		url = ret;
	}

	/*
	 * Don't add duplicates to the cache.
	 */

	if (
		hset_contains(gwc_known_url, url) ||
		hset_contains(gwc_failed_url, url)
	) {
		HFREE_NULL(url);
		return FALSE;
	}

	/*
	 * OK, record new entry at the `gwc_url_slot'.
	 */

	if (++gwc_url_slot >= MAX_GWC_URLS)
		gwc_url_slot = 0;

	g_assert(url != NULL);
	url_atom = atom_str_get(url);
	HFREE_NULL(url);

	/*
	 * Expire any entry present at the slot we're about to write into.
	 */

	old_url = gwc_url[gwc_url_slot].url;

	if (old_url != NULL) {
		g_assert(hset_contains(gwc_known_url, old_url));
		hset_remove(gwc_known_url, old_url);
		atom_str_free_null(&old_url);
		gwc_url[gwc_url_slot].url = NULL;
	}

	hset_insert(gwc_known_url, url_atom);

	gwc_url[gwc_url_slot].url = url_atom;
	gwc_url[gwc_url_slot].stamp = 0;
	gwc_file_dirty = TRUE;

	if (GNET_PROPERTY(bootstrap_debug)) {
		g_debug("%s(): loaded GWC URL %s", G_STRFUNC, url_atom);
	}

	return TRUE;
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
static const char *
gwc_pick(void)
{
	int count = hset_count(gwc_known_url);
	int idx, i;
	const char *url = NULL;
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

	if (GNET_PROPERTY(bootstrap_debug) && url)
		g_message("GWC picked webcache \"%s\"", url);

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
	int i;
	int j;
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
		const char *url = gwc_url[i].url;

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
	file_path_t fp[4], *fpv;
	uint len, added;
	int line, idx;
	FILE *in;
	char tmp[1024];

	len = settings_file_path_load(fp, gwc_file, SFP_ALL);

	g_assert(len <= G_N_ELEMENTS(fp));

	fpv = &fp[0];

retry:
	g_assert(ptr_cmp(fpv, &fp[G_N_ELEMENTS(fp)]) < 0);

	if (&fp[0] == fpv)
		in = file_config_open_read_chosen(gwc_what, fpv, len, &idx);
	else
		in = file_config_open_read_norename_chosen(gwc_what, fpv, len, &idx);

	if (NULL == in)
		return;

	/*
	 * Retrieve each line, counting the amount of entries added.
	 */

	line = 0;
	added = 0;

	while (fgets(tmp, sizeof(tmp), in)) {
		line++;

		if (tmp[0] == '#')		/* Skip comments */
			continue;

		if (tmp[0] == '\n')		/* Allow empty lines */
			continue;

		(void) strchomp(tmp, 0);
		if (gwc_add(tmp))
			added++;
	}

	fclose(in);

	/*
	 * Now check whether we added anything from that file, and if we have not
	 * and there are more backup files to open, retry with these fallbacks
	 * instead.
	 */

	if (0 == added && UNSIGNED(idx) < len - 1) {
		g_warning("%s(): nothing loaded from \"%s/%s\", trying fallbacks",
			G_STRFUNC, fpv[idx].dir, fpv[idx].name);
		fpv += idx + 1;
		len -= idx + 1;
		g_assert(size_is_positive(len));
		goto retry;
	} else {
		if (GNET_PROPERTY(bootstrap_debug)) {
			g_debug("%s(): loaded %u URL%s from \"%s/%s\"",
				G_STRFUNC, added, plural(added), fpv[idx].dir, fpv[idx].name);
		}
	}
}

/**
 * Initialize web cache.
 */
void
gwc_init(void)
{
	uint i;

	gwc_known_url = hset_create(HASH_KEY_STRING, 0);
	gwc_failed_url = hset_create(HASH_KEY_STRING, 0);

	gwc_retrieve();
	if (0 == hset_count(gwc_known_url)) {
		for (i = 0; i < G_N_ELEMENTS(boot_url) && boot_url[i]; i++)
			gwc_add(boot_url[i]);
	}
}

/**
 * Ensures that we have a valid `gwc_current_url' or pick a new one.
 * Also force change a the current URL after too many uses.
 *
 * @return TRUE if we got a valid URL.
 */
static bool
gwc_check_current_url(void)
{
	if (gwc_current_url == NULL || gwc_current_reused >= MAX_GWC_REUSE) {
		/*
		 * `gwc_current_url' must be an atom since we may replace the value
		 * in the cache at any time: we could be using a cache even after
		 * its entry has been superseded.
		 */
		const char *ptr = gwc_pick();

		atom_str_free_null(&gwc_current_url);
		gwc_current_url = ptr == NULL ? NULL : atom_str_get(ptr);
		gwc_current_reused = 0;
	} else
		gwc_current_reused++;

	return gwc_current_url != NULL;
}

/**
 * Removes the URL from the set of known URL, but do not free its memory
 * and keeps it in the set of failed URLs for the session.
 */
static void
gwc_forget_url(const char *url)
{
	struct gwc url_tmp[MAX_GWC_URLS];			/* Temporary copy */
	int count = hset_count(gwc_known_url);
	int i;
	int j = 0;

	g_assert(count > 0);
	g_assert(count <= MAX_GWC_URLS);
	g_assert(count == MAX_GWC_URLS || gwc_url_slot < count);
	g_assert(gwc_url_slot >= 0);
	STATIC_ASSERT(sizeof(url_tmp) == sizeof(gwc_url));

	if (GNET_PROPERTY(bootstrap_debug))
		g_warning("forgetting GWC URL \"%s\"", url);

	/*
	 * It is possible that the URL we're trying to forget was
	 * already removed from the cache if it was at a slot overridden
	 * in the round-robin buffer, should we have got new GWC URL since
	 * it was selected.
	 */

	if (hset_contains(gwc_known_url, url))
		hset_remove(gwc_known_url, url);
	else {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("URL was already gone from GWC");
		return;
	}
	hset_insert(gwc_failed_url, url);

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
gwc_clear_current_url(bool discard)
{
	if (gwc_current_url == NULL)
		return;

	if (discard)
		gwc_forget_url(gwc_current_url);

	atom_str_free_null(&gwc_current_url);
}

/**
 * Frees the atom used as hash table key 
 */
static void
free_failed_url(const void *key, void *unused_udata)
{
	(void) unused_udata;
	atom_str_free(key);
}

/**
 * Called when servent shuts down.
 */
void
gwc_close(void)
{
	int i;

	gwc_store();
	hset_free_null(&gwc_known_url);
	hset_foreach(gwc_failed_url, free_failed_url, NULL);
	hset_free_null(&gwc_failed_url);

	for (i = 0; i < MAX_GWC_URLS; i++) {
		const char *url = gwc_url[i].url;
		if (url == NULL)
			continue;
		atom_str_free(url);
	}

	gwc_clear_current_url(FALSE);
}

/***
 *** Line-by-line parsing context.
 ***/

struct gwc_parse_context {
	getline_t *getline;		/**< Used to hold partially read line */
	void *handle;			/**< Request handle */
	int maxlines;			/**< Maximum number of lines we want to process */
	int lines;				/**< Amount of lines so far */
	int processed;			/**< User callback can count retained lines */
};

typedef bool (gwc_parse_dispatch_t)
	(struct gwc_parse_context *c, const char *buf, size_t len);
typedef void (gwc_parse_eof_t)(struct gwc_parse_context *c);

/**
 * Free parsing context.
 */
static void
gwc_parse_context_free(void *obj)
{
	struct gwc_parse_context *ctx = obj;

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
gwc_parse_context_set(void *handle, int maxlines)
{
	struct gwc_parse_context *ctx;

	ctx = walloc(sizeof(*ctx));
	ctx->getline = getline_make(MAX_LINE_SIZE);
	ctx->maxlines = maxlines;
	ctx->handle = handle;
	ctx->lines = 0;
	ctx->processed = 0;

	http_async_set_opaque(handle, ctx, gwc_parse_context_free);
}


/**
 * Analyze the data we have received, and give each line to the supplied
 * dispatcher callback `cb', after having chomped it.  On EOF, call `eof'
 * to finalize parsing.
 */
static void
gwc_parse_dispatch_lines(void *handle, const char *buf, size_t len,
		gwc_parse_dispatch_t cb, gwc_parse_eof_t eof_cb)
{
	struct gwc_parse_context *ctx;
	const char *p = buf;
	size_t remain = len;

	/*
	 * Retrieve parsing context, stored as an opaque attribute in the
	 * asynchronous HTTP request handle.
	 */

	ctx = http_async_get_opaque(handle);

	g_assert(ctx->handle == handle);	/* Make sure it's the right context */

	if (len == 0) {						/* Nothing to parse, got EOF */
		if (eof_cb != NULL)
			(*eof_cb)(ctx);
		return;
	}

	/*
	 * Read a line at a time.
	 */

	for (;;) {
		char *line;
		bool error;
		size_t line_len;
		size_t parsed;

		switch (getline_read(ctx->getline, p, remain, &parsed)) {
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

		line = h_strdup(getline_str(ctx->getline));
		line_len = getline_length(ctx->getline);
		line_len = strchomp(line, line_len);

		error = !(*cb)(ctx, line, line_len); /* An ERROR was reported */
		HFREE_NULL(line);

		if (error) {
	   		gwc_clear_current_url(FALSE);
			return;
		}

		/*
		 * Make sure we don't process lines ad infinitum.
		 */

		ctx->lines++;
		if (ctx->lines >= ctx->maxlines) {
			const char *req;
			const char *url = http_async_info(handle, &req, NULL, NULL, NULL);
			g_warning("GWC got %d+ lines from \"%s %s\", stopping",
				ctx->lines, req, url);
			http_async_close(handle);
			return;
		}

		getline_reset(ctx->getline);
	}
}

/***
 *** GET ...?get=1
 ***/

static bool gwc_get_running = FALSE;

/**
 * Check whether we're waiting for a host request.
 */
bool
gwc_is_waiting(void)
{
	return gwc_get_running;
}

/**
 * Called from gwc_parse_dispatch_lines() for each complete line of output.
 *
 * @return FALSE to stop processing of any remaining data.
 */
static bool
gwc_host_line(struct gwc_parse_context *ctx, const char *buf, size_t len)
{
	int c;

	if (GNET_PROPERTY(bootstrap_debug) > 3)
		g_message("BOOT GWC host line (%lu bytes): %s", (ulong) len, buf);

	if (is_strprefix(buf, "ERROR")) {
		g_warning("GWC cache \"%s\" returned %s",
			http_async_url(ctx->handle), buf);
		http_async_cancel(ctx->handle);
		return FALSE;
	}

	if (len <= 2)
		return TRUE;		/* Skip this line silently */

	/*
	 * A line starting with "H|" is a host, with "U|" a GWC URL.
	 * Letters are case-insensitive.
	 */

	if (buf[1] != '|')
		goto malformed;

	c = ascii_toupper(buf[0]);

	if ('H' == c) {
		host_addr_t addr;
		uint16 port;

		if (string_to_host_addr_port(&buf[2], NULL, &addr, &port)) {
			ctx->processed++;
			hcache_add_caught(HOST_G2HUB, addr, port, "GWC");
			if (GNET_PROPERTY(bootstrap_debug) > 1) {
				g_message("BOOT (G2) collected %s from GWC %s",
					host_addr_port_to_string(addr, port),
					http_async_url(ctx->handle));
			}
		}
		return TRUE;
	} else if ('U' == c) {
		char *end = strchr(&buf[2], '|');
		char *url;

		if (NULL == end)
			goto malformed;

		ctx->processed++;
		url = h_strndup(&buf[2], ptr_diff(end, &buf[2]));
		gwc_add(url);
		hfree(url);
		return TRUE;
	} else if ('I' == c) {
		return TRUE;		/* Ignore information line */
	}

	/*
	 * If we come here, we did not recognize the line properly.
	 */

	if (GNET_PROPERTY(bootstrap_debug) > 2) {
		g_warning("GWC ignoring unknown line \"%s\" from %s",
			buf, http_async_url(ctx->handle));
	}

	return TRUE;

malformed:
	if (GNET_PROPERTY(bootstrap_debug)) {
		g_warning("GWC ignoring malformed line \"%s\" from %s",
			buf, http_async_url(ctx->handle));
	}

	return TRUE;
}

/**
 * Called from gwc_parse_dispatch_lines() on EOF.
 */
static void
gwc_host_eof(struct gwc_parse_context *ctx)
{
	const char *msg;

	if (GNET_PROPERTY(bootstrap_debug) > 2)
		g_message("GWC host all done (%d/%d lines processed)",
			ctx->processed, ctx->lines);

	/*
	 * Provide GUI feedback.
	 */

	msg = str_smsg(
		NG_("Got %d host from %s", "Got %d hosts from %s", ctx->processed),
		ctx->processed, gwc_current_url);

	gcu_statusbar_message(msg);

	if (GNET_PROPERTY(bootstrap_debug))
		g_message("BOOT got %d host%s from GWC %s",
			ctx->processed, plural(ctx->processed), gwc_current_url);

	/*
	 * If we did not get enough addresses, try to feed the cache with ours.
	 */

	if (ctx->processed < MIN_IP_LINES) {
		gwc_clear_current_url(FALSE);		/* Move to another cache */
	}

	gwc_get_running = FALSE;
}

/**
 * Populate callback: more data available.
 */
static void
gwc_host_data_ind(http_async_t *ha, char *data, int len)
{
	gwc_parse_dispatch_lines(ha, data, len, gwc_host_line, gwc_host_eof);
}

/**
 * HTTP request is being stopped.
 */
static void
gwc_host_error_ind(http_async_t *ha, http_errtype_t type, void *v)
{
	http_async_log_error_dbg(ha,
		type, v, "GWC", GNET_PROPERTY(bootstrap_debug));

	gwc_get_running = FALSE;
	gwc_clear_current_url(TRUE);		/* This webcache is not good */
}

/**
 * Redefine callback invoked when we got the whole HTTP reply.
 *
 * @param ha		the HTTP async request descriptor
 * @param s			the socket on which we got the reply
 * @param status	the first HTTP status line
 * @param header	the parsed header structure
 */
static void
gwc_got_reply(const http_async_t *ha,
	const gnutella_socket_t *s, const char *status, const header_t *header)
{
	if (GNET_PROPERTY(bootstrap_debug) > 3)
		g_debug("GWC got reply from %s", http_async_url(ha));

	if (GNET_PROPERTY(bootstrap_debug) > 5) {
		g_debug("----Got GWC reply from %s:",
			host_addr_to_string(s->addr));
		if (log_printable(LOG_STDERR)) {
			fprintf(stderr, "%s\n", status);
			header_dump(stderr, header, "----");
		}
	}
}

/**
 * Retrieve more hosts from web cache, asynchronously.
 */
void
gwc_get_hosts(void)
{
	void *handle;
	char *url;
	const char *msg;
	static time_t last_called = 0;
	time_t now = tm_time();

	/*
	 * Make sure we don't probe more than one webcache at a time.
	 * Ancient versions should rely on their hostcache to be connected.
	 */

	if (gwc_get_running || GNET_PROPERTY(ancient_version))
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
		gwc_clear_current_url(FALSE);

	last_called = now;

	if (!gwc_check_current_url())
		return;

	/*
	 * Give some GUI feedback.
	 */

	msg = str_smsg(_("Connecting to web cache %s"), gwc_current_url);
	gcu_statusbar_message(msg);

	if (GNET_PROPERTY(bootstrap_debug))
		g_message("BOOT connecting to web cache %s", gwc_current_url);

	/*
	 * Launch the asynchronous request and attach parsing information.
	 */

	msg = str_smsg("%s?get=1&net=gnutella2&%s", gwc_current_url, CLIENT_INFO);
	url = h_strdup(msg);

	if (GNET_PROPERTY(bootstrap_debug) > 2)
		g_message("GWC host request: %s", url);

	handle = http_async_get(url, NULL, gwc_host_data_ind, gwc_host_error_ind);

	if (NULL == handle) {
		g_warning("could not launch a \"GET %s\" request: %s",
			url, http_async_strerror(http_async_errno));
		gwc_clear_current_url(TRUE);
	} else {
		http_async_set_op_gotreply(handle, gwc_got_reply);
		gwc_parse_context_set(handle, MAX_IP_LINES);
		gwc_get_running = TRUE;
	}

	hfree(url);
}

/* vi: set ts=4 sw=4 cindent: */
