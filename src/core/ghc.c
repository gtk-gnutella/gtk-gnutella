/*
 * Copyright (c) 2010, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Global Host Cache.
 *
 * This is used as a last-resort bootsrapping aid in case UDP bootstrapping
 * is not working for this node (UDP disabled or firewalled).
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "ghc.h"
#include "http.h"
#include "hcache.h"

#include "lib/atoms.h"
#include "lib/getline.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/list.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

#define GHC_MAX_ATTEMPTS 3		/**< Maximum connection / resolution attempts */
#define GHC_TIMEOUT		 20000	/**< Host cache timeout, milliseconds */
#define GHC_RETRY_AFTER	 3600	/**< Frequency of contacts for a GHC (secs) */
#define GHC_MAX_HOSTS	 500	/**< Amount of hosts we parse */
#define GHC_MAX_LINE_LEN 256	/**< Maximum expected line length in replies */

/**
 * List of URLs for last-resort bootstrapping purposes only.
 */
static const char * const boot_url[] = {
	/* Uses DNS round-robin and serves freshly crawled data */
	"http://ghc4.gtkgnutella.com/list4",
};

static bool ghc_connecting;
static list_t *ghc_list;		/**< List of ``struct ghc'' */

struct ghc {
	const char *url;		/**< The URL to request (atom) */
	time_t stamp;			/**< Timestamp of last request */
	unsigned used;			/**< How often we tried to contact it */
};

/**
 * Request context.
 */
static struct ghc_context {
	struct http_async *ha;		/**< Asynchronous HTTP request handle */
} ghc_ctx;

/***
 *** Line-by-line parsing context.
 ***/

struct parse_context {
	getline_t *getline;		/**< Used to hold partially read line */
	void *handle;			/**< Request handle */
	unsigned maxlines;		/**< Maximum amount of lines we wish to process */
	unsigned lines;			/**< Amount of lines so far */
	unsigned processed;		/**< User callback can count retained lines */
};

typedef bool (parse_dispatch_t)
	(struct parse_context *c, const char *buf, size_t len);
typedef void (parse_eof_t)(struct parse_context *c);

/**
 * Free parsing context.
 */
static void
parse_context_free(void *obj)
{
	struct parse_context *ctx = (struct parse_context *) obj;

	getline_free(ctx->getline);
	WFREE(ctx);
}

/**
 * Allocate new parsing context for handle and record it.
 *
 * @param `handle'		the asynchronous HTTP request handle.
 * @param `maxlines'	the max number of lines we want to parse.
 */
static void
parse_context_set(void *handle, int maxlines)
{
	struct parse_context *ctx;

	WALLOC(ctx);
	ctx->getline = getline_make(GHC_MAX_LINE_LEN);
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
parse_dispatch_lines(void *handle, const char *buf, size_t len,
		parse_dispatch_t cb, parse_eof_t eofile)
{
	struct parse_context *ctx;
	const char *p = buf;
	size_t remain = len;

	/*
	 * Retrieve parsing context, stored as an opaque attribute in the
	 * asynchronous HTTP request handle.
	 */

	ctx = http_async_get_opaque(handle);

	g_assert(ctx->handle == handle);	/* Make sure it's the right context */

	if (len == 0) {						/* Nothing to parse, got EOF */
		if (eofile != NULL)
			(*eofile)(ctx);
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
			ghc_connecting = FALSE;
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
			ghc_ctx.ha = NULL;
			ghc_connecting = FALSE;
			return;
		}

		/*
		 * Make sure we don't process lines ad infinitum.
		 */

		ctx->lines++;
		if (ctx->lines >= ctx->maxlines) {
			const char *req;
			const char *url = http_async_info(handle, &req, NULL, NULL, NULL);
			if (GNET_PROPERTY(bootstrap_debug))
				g_warning("BOOT GHC got %u+ lines from \"%s %s\", stopping",
					ctx->lines, req, url);
			http_async_close(handle);
			ghc_connecting = FALSE;
			return;
		}

		getline_reset(ctx->getline);
	}
}

/***
 *** Managing GHC requests.
 ***/

/**
 * Create a new GHC.
 */
static struct ghc *
ghc_new(const char *url)
{
	struct ghc *ghc;

	g_assert(url != NULL);

	WALLOC0(ghc);
	ghc->url = atom_str_get(url);
	ghc->stamp = 0;
	ghc->used = 0;

	return ghc;
}

/**
 * Destroy a GHC.
 */
static void
ghc_free(struct ghc *ghc)
{
	atom_str_free_null(&ghc->url);
	WFREE(ghc);
}

/**
 * Destroy a GHC.
 */
static void
ghc_free_null(struct ghc **ptr)
{
	if (*ptr) {
		ghc_free(*ptr);
		*ptr = NULL;
	}
}

/**
 * @return NULL on error, a newly allocated string via halloc() otherwise.
 */
static char *
ghc_get_next(void)
{
	struct ghc *ghc;
	char *url;
	time_t now;

	g_return_val_if_fail(ghc_list, NULL);

	now = tm_time();
	ghc = list_head(ghc_list);
	if (NULL == ghc)
		return NULL;

	/*
	 * Wait GHC_RETRY_AFTER secs before contacting the GHC again.
	 */

	if (ghc->stamp && delta_time(now, ghc->stamp) < GHC_RETRY_AFTER)
		return NULL;

	ghc->stamp = now;
	url = h_strdup(ghc->url);

	if (ghc->used < GHC_MAX_ATTEMPTS) {
		ghc->used++;
		list_moveto_tail(ghc_list, ghc);
	} else {
		list_remove(ghc_list, ghc);
		ghc_free_null(&ghc);
	}

	return url;
}

/**
 * Called from parse_dispatch_lines() for each complete line of output.
 *
 * @return FALSE to stop processing of any remaining data.
 */
static bool
ghc_host_line(struct parse_context *ctx, const char *buf, size_t len)
{
	if (GNET_PROPERTY(bootstrap_debug) > 2)
		g_debug("BOOT GHC host line #%u (%zu bytes): %s",
			ctx->processed + 1, len, buf);

	if (len) {
		host_addr_t addr;
		uint16 port;

		if (string_to_host_addr_port(buf, NULL, &addr, &port)) {
			ctx->processed++;
			hcache_add_caught(HOST_ULTRA, addr, port, "GHC");

			if (GNET_PROPERTY(bootstrap_debug) > 1)
				g_debug("BOOT collected %s from GHC %s",
					host_addr_to_string(addr), http_async_url(ctx->handle));
		}
	}

	return TRUE;
}

/**
 * Called from parse_dispatch_lines() on EOF.
 */
static void
ghc_host_eof(struct parse_context *ctx)
{
	char msg[256];

	if (GNET_PROPERTY(bootstrap_debug) > 2)
		g_debug("BOOT GHC all done (%u/%u lines processed)",
			ctx->processed, ctx->lines);

	/*
	 * Provide GUI feedback.
	 */

	str_bprintf(ARYLEN(msg),
		NG_("Got %d host from %s", "Got %d hosts from %s", ctx->processed),
		ctx->processed, http_async_url(ghc_ctx.ha));

	gcu_statusbar_message(msg);

	if (GNET_PROPERTY(bootstrap_debug))
		g_debug("BOOT GHC got %d host%s from %s",
			ctx->processed, plural(ctx->processed), http_async_url(ghc_ctx.ha));

	ghc_ctx.ha = NULL;
	ghc_connecting = FALSE;
}

/**
 * Populate callback: more data available.
 */
static void
ghc_data_ind(struct http_async *handle, const char *data, int len)
{
	parse_dispatch_lines(handle, data, len, ghc_host_line, ghc_host_eof);
}

/**
 * HTTP request is being stopped.
 */
static void
ghc_error_ind(struct http_async *handle, http_errtype_t type, void *v)
{
	http_async_log_error_dbg(handle, type, v, "BOOT GHC",
		GNET_PROPERTY(bootstrap_debug) > 1);
	ghc_ctx.ha = NULL;
	ghc_connecting = FALSE;
}

/**
 * Pick a random cache URL among the list we have.
 *
 * @return TRUE if OK.
 */
static bool
ghc_pick(void)
{
	bool success = FALSE;
	char *url;

	url = ghc_get_next();
	if (NULL == url) {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("BOOT ran out of GHCs");
		goto finish;
	}

	g_assert(NULL == ghc_ctx.ha);

	/*
	 * Give GUI feedback.
	 */

	{
		char msg[256];

		str_bprintf(ARYLEN(msg), _("Bootstrapping from %s"), url);
		gcu_statusbar_message(msg);
	}

	ghc_ctx.ha = http_async_get(url,  NULL, ghc_data_ind, ghc_error_ind);

	if (!ghc_ctx.ha) {
		if (GNET_PROPERTY(bootstrap_debug))
			g_warning("BOOT cannot launch a \"GET %s\" HTTP request: %s",
				url, http_async_strerror(http_async_errno));
		goto finish;
	}

	parse_context_set(ghc_ctx.ha, GHC_MAX_HOSTS);
	success = TRUE;

finish:
	HFREE_NULL(url);
	return success;
}

/**
 * Try a random cache URL.
 */
static void
ghc_try_random(void)
{
	g_assert(ghc_connecting);

	if (!ghc_pick()) {
		ghc_connecting = FALSE;
	}
}

/**
 * Get more hosts to connect to from one global host cache, asynchronously.
 */
void
ghc_get_hosts(void)
{
	/*
	 * Make sure we don't probe the global cache more than once at a time.
	 * Ancient versions are denied the right to contact host caches and
	 * must find out hosts another way.
	 */

	if (ghc_connecting || GNET_PROPERTY(ancient_version))
		return;

	g_message("BOOT will be contacting a GHC");

	ghc_connecting = TRUE;
	ghc_try_random();
}

/**
 * Add URL to the global list, randomly inserting at head or tail.
 */
static void
ghc_list_add(struct ghc *ghc)
{
	g_return_if_fail(ghc);

	if (random_value(100) < 50) {
		list_append(ghc_list, ghc);
	} else {
		list_prepend(ghc_list, ghc);
	}
}

/**
 * Check whether we're waiting for some GHC hosts.
 */
bool
ghc_is_waiting(void)
{
	return ghc_connecting;
}

/**
 * Initializations.
 */
void G_COLD
ghc_init(void)
{
	uint i;

	g_return_if_fail(NULL == ghc_list);
	ghc_list = list_new();

	for (i = 0; i < N_ITEMS(boot_url); i++) {
		struct ghc *ghc;
		ghc = ghc_new(boot_url[i]);
		ghc_list_add(ghc);
	}
}

/**
 * Final cleanup.
 */
void G_COLD
ghc_close(void)
{
	if (ghc_connecting) {
		if (ghc_ctx.ha != NULL) {
			http_async_cancel(ghc_ctx.ha);
			ghc_ctx.ha = NULL;
		}
	}

	ghc_connecting = FALSE;
	list_free_all(&ghc_list, cast_to_list_destroy(ghc_free));
}

/* vi: set ts=4 sw=4 cindent: */
