/*
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2002, Vidar Madsen
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
 * Needs brief description here.
 *
 * Functions for keeping a whitelist of nodes we always allow in,
 * and whom we try to keep a connection to.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Vidar Madsen
 * @date 2002
 */

#include "common.h"

#include "whitelist.h"
#include "settings.h"
#include "ipp_cache.h"
#include "nodes.h"

#include "if/gnet_property_priv.h"

#include "lib/adns.h"
#include "lib/ascii.h"
#include "lib/cq.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/pslist.h"
#include "lib/random.h"
#include "lib/stringify.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Number of seconds between each connection attempt to a whitelisted node.
 */
#define WHITELIST_RETRY_DELAY 30

/**
 * Number of seconds between DNS name resolutions and between periodic checks.
 */
#define WHITELIST_DNS_INTERVAL			600	/**< 10 minutes */
#define WHITELIST_DNS_RESOLVE_CHECK		120	/**< 2 minutes */

/**
 * A hostname entry.
 */
struct whitelist_hostname {
	char *name;					/**< halloc()-ed string */
	time_t last_resolved;		/**< Time of last DNS resolution attempt */
};

/**
 * A whitelist entry.
 */
struct whitelist {
	struct whitelist_hostname *host;	/**< If hostname is known */
    time_t last_try;
    host_addr_t addr;					/**< If name != NULL, last resolved */
    uint16 port;
    uint8 bits;							/**< For ranges (implies port == 0) */
	uint8 use_tls;						/**< Whether to use TLS */
};

static pslist_t *sl_whitelist;

static const char whitelist_file[] = "whitelist";

/**
 * To manage asynchronous DNS resolutions, keep track of the generation
 * number so that pending resolutions coming back after the whitelist
 * was reloaded are properly discarded.
 */
static unsigned whitelist_generation;

/**
 * A pending DNS resolution.
 */
struct whitelist_dns {
	struct whitelist *item;			/**< Item being resolved */
	unsigned generation;			/**< For which generation? */
	bool revalidate;				/**< Whether this is revalidation */
};

static uint
addr_default_mask(const host_addr_t addr)
{
	switch (host_addr_net(addr)) {
	case NET_TYPE_IPV4:
		return 32;
	case NET_TYPE_IPV6:
		return 128;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	g_assert_not_reached();
	return 0;
}

/**
 * Allocate a new whitelist entry containing an explicit address.
 */
static struct whitelist *
whitelist_addr_create(bool use_tls, host_addr_t addr, uint16 port, uint8 bits)
{
	struct whitelist *item;

	WALLOC0(item);
	item->use_tls = use_tls;
	item->addr = addr;
	item->port = port;
	item->bits = bits ? bits : addr_default_mask(addr);

	return item;
}

/**
 * Allocate a new whitelist entry containing a hostname.
 * The structure takes ownership of the supplied ``hname''.
 */
static struct whitelist *
whitelist_hostname_create(bool use_tls, char *hname, uint16 port)
{
	struct whitelist *item;
	struct whitelist_hostname *host;

	WALLOC0(item);
	WALLOC0(host);
	host->name = hname;
	item->use_tls = use_tls;
	item->host = host;
	item->port = port;

	return item;
}

/**
 * Free whitelist item.
 */
static void
whitelist_free(struct whitelist *item)
{
	g_assert(item != NULL);

	if (item->host != NULL) {
		HFREE_NULL(item->host->name);
		WFREE(item->host);
	}
	WFREE(item);
}

/**
 * Log whitelist item.
 */
static void
log_whitelist_item(const struct whitelist *item, const char *what)
{
	const char *host;
	uint8 bits;

	if (item->host != NULL) {
		host = 0 == item->port ? item->host->name :
			host_port_to_string(item->host->name, ipv4_unspecified, item->port);
	} else {
		host = 0 == item->port ? host_addr_to_string(item->addr) :
			host_addr_port_to_string(item->addr, item->port);
	}

	if (is_host_addr(item->addr)) {
		bits = item->bits == addr_default_mask(item->addr) ? 0 : item->bits;
	} else {
		bits = 0;
	}

	g_debug("WLIST %s %s%s%s%s", what,
		item->use_tls ? "tls:" : "", host,
		bits == 0 ? "" : "/",
		bits == 0 ? "" : uint32_to_string(bits));
}

/**
 * Add (address-resolved) item to the whitelist.
 */
static void
whitelist_add(struct whitelist *item)
{
	g_assert(item != NULL);
	g_assert(is_host_addr(item->addr));

	/*
	 * If TLS-usage was configured, re-add to the TLS cache so that
	 * connections to that host will use TLS.
	 */

	if (item->use_tls && item->port != 0)
		tls_cache_insert(item->addr, item->port);

	if (GNET_PROPERTY(whitelist_debug))
		log_whitelist_item(item, "adding");

	sl_whitelist = pslist_prepend(sl_whitelist, item);
}

/**
 * Called when we get a reply from the ADNS process.
 */
static void
whitelist_dns_cb(const host_addr_t *addrs, size_t n, void *udata)
{
	struct whitelist_dns *ctx = udata;
	struct whitelist *item = ctx->item;

	if (ctx->generation != whitelist_generation) {
		if (GNET_PROPERTY(whitelist_debug))
			log_whitelist_item(item, "late DNS resolution");
		if (!ctx->revalidate) {
			whitelist_free(item);
		}
	} else {
		item->host->last_resolved = tm_time();

		if (n < 1) {
			if (GNET_PROPERTY(whitelist_debug))
				log_whitelist_item(item, "could not DNS-resolve");
			if (ctx->revalidate) {
				item->addr = ipv4_unspecified;
				item->bits = 0;
			} else {
				whitelist_free(item);
			}
		} else {
			item->addr = addrs[random_value(n - 1)];	/* Pick one randomly */
			item->bits = addr_default_mask(item->addr);

			if (GNET_PROPERTY(whitelist_debug) > 1) {
				g_debug("WLIST DNS-resolved %s as %s (out of %zu result%s)",
					item->host->name, host_addr_to_string(item->addr),
					n, plural(n));
			}
			if (!ctx->revalidate) {
				whitelist_add(item);
			}
		}
	}

	WFREE(ctx);
}

/**
 * Request asynchronous DNS resolution for item, prior to inserting to
 * the whitelist or updating the existing host address (when revalidating).
 */
static void
whitelist_dns_resolve(struct whitelist *item, bool revalidate)
{
	struct whitelist_dns *ctx;
	char *host;

	g_assert(item != NULL);
	g_assert(revalidate || !is_host_addr(item->addr));
	g_assert(item->host != NULL);

	/*
	 * Since resolution is normally going to happen asynchronously, we must
	 * keep track of the generation at which the resolution was requested.
	 */

	WALLOC(ctx);
	ctx->item = item;
	ctx->generation = whitelist_generation;
	ctx->revalidate = revalidate;

	host = item->host->name;

	if (adns_resolve(host, settings_dns_net(), whitelist_dns_cb, ctx)) {
		/* Asynchronous resolution */
		if (GNET_PROPERTY(whitelist_debug) > 1)
			log_whitelist_item(item, "asynchronously resolving");
	} else {
		/* Synchronous resolution, whitelist_dns_cb() already called */
	}
}

/**
 * Loads the whitelist into memory.
 */
static void G_COLD
whitelist_retrieve(void)
{
	char line[1024];
	FILE *f;
	filestat_t st;
	unsigned linenum = 0;
	file_path_t fp[1];

	whitelist_generation++;

	file_path_set(fp, settings_config_dir(), whitelist_file);
	f = file_config_open_read_norename("Host Whitelist", fp, N_ITEMS(fp));
	if (!f)
		return;

	if (fstat(fileno(f), &st)) {
		g_warning("%s(): fstat() failed: %m", G_STRFUNC);
		fclose(f);
		return;
	}

    while (fgets(ARYLEN(line), f)) {
		pslist_t *sl_addr, *sl;
		const char *endptr, *start;
		host_addr_t addr;
    	uint16 port;
		uint8 bits;
		bool item_ok;
		bool use_tls;
		char *hname;

        linenum++;

		if (!file_line_chomp_tail(ARYLEN(line), NULL)) {
			g_warning("%s(): line %u too long, aborting", G_STRFUNC, linenum);
			break;
		}

        if (file_line_is_skipable(line))
			continue;

		sl_addr = NULL;
		addr = zero_host_addr;
		endptr = NULL;
		hname = NULL;

		endptr = is_strprefix(line, "tls:");
		if (endptr) {
			use_tls = TRUE;
			start = endptr;
		} else {
			use_tls = FALSE;
			start = line;
		}

		port = 0;
		if (string_to_host_addr_port(start, &endptr, &addr, &port)) {
       		sl_addr = name_to_host_addr(host_addr_to_string(addr),
							settings_dns_net());
		} else if (string_to_host_or_addr(start, &endptr, &addr)) {
			uchar c = *endptr;

			switch (c) {
			case '\0':
			case ':':
			case '/':
				break;
			default:
				if (!is_ascii_space(c))
					endptr = NULL;
			}

			if (!endptr) {
				g_warning("%s(): line %d: "
					"expected a hostname or IP address \"%s\"",
					G_STRFUNC, linenum, line);
				continue;
			}

			/* Terminate the string for name_to_host_addr() */
			hname = h_strndup(start, endptr - start);
		} else {
            g_warning("%s(): line %d: expected hostname or IP address \"%s\"",
				G_STRFUNC, linenum, line);
			continue;
		}

       	g_assert(sl_addr != NULL || hname != NULL);
		g_assert(NULL != endptr);
		bits = 0;
		item_ok = TRUE;

		/*
		 * When an explicit address is given (no hostname) and with no
		 * port, one can suffix the address with bits to indicate a CIDR
		 * range of whitelisted addresses.
		 */

		if (0 == port) {
			/* Ignore trailing items separated by a space */
			while ('\0' != *endptr && !is_ascii_space(*endptr)) {
				uchar c = *endptr++;

				if (':' == c) {
					int error;
					uint32 v;

					if (0 != port) {
						g_warning("%s(): line %d: multiple colons after host",
							G_STRFUNC, linenum);
						item_ok = FALSE;
						break;
					}

					v = parse_uint32(endptr, &endptr, 10, &error);
					port = (error || v > 0xffff) ? 0 : v;
					if (0 == port) {
						g_warning("%s(): line %d: "
							"invalid port value after host",
							G_STRFUNC, linenum);
						item_ok = FALSE;
						break;
					}
				} else if ('/' == c) {
					const char *ep;
					uint32 mask;

					if (0 != bits) {
						g_warning("%s(): line %d: "
							"multiple slashes after host", G_STRFUNC, linenum);
						item_ok = FALSE;
						break;
					}

					if (string_to_ip_strict(endptr, &mask, &ep)) {
						if (!host_addr_is_ipv4(addr)) {
							g_warning("%s(): line %d: "
								"IPv4 netmask after non-IPv4 address",
								G_STRFUNC, linenum);
							item_ok = FALSE;
							break;
						}
						endptr = ep;

						if (0 == (bits = netmask_to_cidr(mask))) {
							g_warning("%s(): line %d: "
								"IPv4 netmask after non-IPv4 address",
								G_STRFUNC, linenum);
							item_ok = FALSE;
							break;
						}

					} else {
						int error;
						uint32 v;

						v = parse_uint32(endptr, &endptr, 10, &error);
						if (
							error ||
							0 == v ||
							(v > 32 && host_addr_is_ipv4(addr)) ||
							(v > 128 && host_addr_is_ipv6(addr))
						) {
							g_warning("%s(): line %d: "
								"invalid numeric netmask after host",
								G_STRFUNC, linenum);
							item_ok = FALSE;
							break;
						}
						bits = v;
					}
				} else {
					g_warning("%s(): line %d: "
						"unexpected character after host", G_STRFUNC, linenum);
					item_ok = FALSE;
					break;
				}
			}
		}

		if (item_ok) {
			struct whitelist *item;
			if (hname) {
				item = whitelist_hostname_create(use_tls, hname, port);
				whitelist_dns_resolve(item, FALSE);
			} else {
				PSLIST_FOREACH(sl_addr, sl) {
					host_addr_t *aptr = sl->data;
					g_assert(aptr != NULL);
					item = whitelist_addr_create(use_tls, *aptr, port, bits);
					whitelist_add(item);
				}
			}
		} else {
			HFREE_NULL(hname);
		}

		host_addr_free_list(&sl_addr);
    }

    sl_whitelist = pslist_reverse(sl_whitelist);
	fclose(f);
}

/**
 * Attempts to connect to the nodes we have whitelisted.
 * Only entries with a specified port will be tried.
 *
 * @returns the number of new nodes that are connected to.
 */
uint
whitelist_connect(void)
{
	time_t now = tm_time();
	const pslist_t *sl;
	uint num = 0;

	PSLIST_FOREACH(sl_whitelist, sl) {
		struct whitelist *item;

		item = sl->data;

		if (0 == item->port || !is_host_addr(item->addr))
			continue;

		if (node_is_connected(item->addr, item->port, TRUE))
			continue;

		if (
			!item->last_try ||
			delta_time(now, item->last_try) > WHITELIST_RETRY_DELAY
		) {
			item->last_try = now;
			node_add(item->addr, item->port, item->use_tls ? SOCK_F_TLS : 0);
			num++;
		}
	}
	return num;
}

/**
 * Check the given IP against the entries in the whitelist.
 *
 * @param ha the host address to check.
 * @returns TRUE if found, and FALSE if not.
 */
bool
whitelist_check(const host_addr_t ha)
{
	const pslist_t *sl;

	PSLIST_FOREACH(sl_whitelist, sl) {
		const struct whitelist *item = sl->data;

		if (!is_host_addr(item->addr))
			continue;

		if (host_addr_matches(ha, item->addr, item->bits))
			return TRUE;
	}

	return FALSE;
}

/**
 * Reloads the whitelist.
 */
static void
whitelist_changed(const char *filename, void *unused_data)
{
	(void) unused_data;

	if (GNET_PROPERTY(whitelist_debug)) {
		g_debug("WLIST reloading from %s", filename);
	}

    whitelist_close();
    whitelist_retrieve();
}

/**
 * Callout queue periodic event to keep DNS-resolved addresses fresh.
 */
static bool
whitelist_periodic_dns(void *unused_obj)
{
	time_t now = tm_time();
	pslist_t *sl;

	(void) unused_obj;

	PSLIST_FOREACH(sl_whitelist, sl) {
    	struct whitelist *item = sl->data;

		/*
		 * Use this opportunity to refresh the TLS cache.
		 */

		if (item->use_tls && item->port != 0 && is_host_addr(item->addr))
			tls_cache_insert(item->addr, item->port);

		if (NULL == item->host)
			continue;

		if (delta_time(now, item->host->last_resolved) < WHITELIST_DNS_INTERVAL)
			continue;

		whitelist_dns_resolve(item, TRUE);
	}

	return TRUE;	/* Keep calling */
}

/**
 * Called on startup.
 *
 * Loads the whitelist into memory if it exists.
 *
 * Ensure we will monitor the file to reloead the whitelist soon after
 * the file is modified (or created if missing initially).
 */
void G_COLD
whitelist_init(void)
{
	char *path;

	/*
	 * Register monitoring of path.  It's OK if file does not exist yet.
	 */

	path = make_pathname(settings_config_dir(), whitelist_file);
	watcher_register(path, whitelist_changed, NULL);
	HFREE_NULL(path);

	/*
	 * Make sure we're re-resolving DNS names periodically.
	 */

	cq_periodic_main_add(WHITELIST_DNS_RESOLVE_CHECK * 1000,
		whitelist_periodic_dns, NULL);

    whitelist_retrieve();
}

/**
 * Frees all entries in the whitelist.
 */
void G_COLD
whitelist_close(void)
{
    pslist_t *sl;

	PSLIST_FOREACH(sl_whitelist, sl) {
		whitelist_free(sl->data);
	}

    pslist_free_null(&sl_whitelist);
}

/* vi: set ts=4 sw=4 cindent: */
