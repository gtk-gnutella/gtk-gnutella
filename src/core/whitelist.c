/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
 * @author Vidar Madsen
 * @date 2002
 */

#include "common.h"

RCSID("$Id$")

#include "whitelist.h"
#include "settings.h"
#include "ipp_cache.h"
#include "nodes.h"

#include "lib/ascii.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/**
 * Number of seconds between each connection attempt to a whitelisted node.
 */
#define WHITELIST_RETRY_DELAY 30

/**
 * Number of seconds between checking the whitelist file for updates.
 */
#define WHITELIST_CHECK_INTERVAL 60

struct whitelist {
    time_t last_try;
    host_addr_t addr;
    guint16 port;
    guint8 bits;
};

static GSList *sl_whitelist;

static const char whitelist_file[] = "whitelist";
static time_t whitelist_mtime, whitelist_checked;
static char *whitelist_path;

static guint
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
 * Loads the whitelist into memory.
 */
static void
whitelist_retrieve(void)
{
    char line[1024];
    FILE *f;
    struct stat st;
    int linenum = 0;
	file_path_t fp[1];

    whitelist_checked = tm_time();

	file_path_set(fp, settings_config_dir(), whitelist_file);
	f = file_config_open_read_norename("Host Whitelist", fp, G_N_ELEMENTS(fp));
	if (!f)
		return;

	if (fstat(fileno(f), &st)) {
		g_warning("whitelist_retrieve: fstat() failed: %s", g_strerror(errno));
		fclose(f);
		return;
	}
    whitelist_mtime = st.st_mtime;

    while (fgets(line, sizeof line, f)) {
		GSList *sl_addr, *sl;
		const char *endptr, *start;
		host_addr_t addr;
    	guint16 port;
		guint8 bits;
		char *p;
		gboolean item_ok;
		gboolean use_tls;

        linenum++;
        if ('#' == line[0]) continue;

		/* Remove trailing spaces so that lines that contain spaces only
		 * are ignored and cause no warnings. */
		for (p = strchr(line, '\0'); p != line; p--) {
			if (!is_ascii_space(*(p - 1)))
				break;
		}
		*p = '\0';

        if ('\0' == line[0])
            continue;

		sl_addr = NULL;
		addr = zero_host_addr;
		endptr = NULL;

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
			char *name;
			guchar c = *endptr;

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
           		g_warning("whitelist_retrieve(): "
					"Line %d: Expected a hostname or IP address \"%s\"",
						linenum, line);
				continue;
			}

			/* Terminate the string for name_to_host_addr() */
			name = g_strndup(start, endptr - start); 
			
			/* @todo TODO: This should use the ADNS resolver. */
       		sl_addr = name_to_host_addr(name, settings_dns_net());
       		if (!sl_addr) {
           		g_warning("whitelist_retrieve(): "
					"Line %d: Could not resolve hostname \"%s\"",
					linenum, line);
			}
			G_FREE_NULL(name);
       		if (!sl_addr)
				continue;
		} else {
            g_warning("whitelist_retrieve(): "
				"Line %d: Expected hostname or IP address \"%s\"",
				linenum, line);
			continue;
		}

       	g_assert(sl_addr);
		g_assert(NULL != endptr);
		bits = 0;
		item_ok = TRUE;

		if (0 == port) {
			/* Ignore trailing items separated by a space */
			while ('\0' != *endptr && !is_ascii_space(*endptr)) {
				guchar c = *endptr++;

				if (':' == c) {
					int error;
					guint32 v;

					if (0 != port) {
						g_warning("whitelist_retrieve(): Line %d:"
								"Multiple colons after host", linenum);
						item_ok = FALSE;
						break;
					}

					v = parse_uint32(endptr, &endptr, 10, &error);
					port = (error || v > 0xffff) ? 0 : v;
					if (0 == port) {
						g_warning("whitelist_retrieve(): Line %d: "
								"Invalid port value after host", linenum);
						item_ok = FALSE;
						break;
					}
				} else if ('/' == c) {
					const char *ep;
					guint32 mask;

					if (0 != bits) {
						g_warning("whitelist_retrieve(): Line %d:"
								"Multiple slashes after host", linenum);
						item_ok = FALSE;
						break;
					}

					if (string_to_ip_strict(endptr, &mask, &ep)) {
						if (NET_TYPE_IPV4 != host_addr_net(addr)) {
							g_warning("whitelist_retrieve(): Line %d: "
								"IPv4 netmask after non-IPv4 address", linenum);
							item_ok = FALSE;
							break;
						}
						endptr = ep;

						if (0 == (bits = netmask_to_cidr(mask))) {
							g_warning("whitelist_retrieve(): Line %d: "
								"IPv4 netmask after non-IPv4 address", linenum);
							item_ok = FALSE;
							break;
						}

					} else {
						int error;
						guint32 v;

						v = parse_uint32(endptr, &endptr, 10, &error);
						if (
							error ||
							0 == v ||
							(v > 32 && NET_TYPE_IPV4 == host_addr_net(addr)) ||
							(v > 128 && NET_TYPE_IPV6 == host_addr_net(addr))
						) {
							g_warning("whitelist_retrieve(): Line %d: "
								"Invalid numeric netmask after host", linenum);
							item_ok = FALSE;
							break;
						}
						bits = v;
					}
				} else {
					g_warning("whitelist_retrieve(): Line %d: "
							"Unexpected character after host", linenum);
					item_ok = FALSE;
					break;
				}
			}
		}

		if (item_ok) {
			for (sl = sl_addr; NULL != sl; sl = g_slist_next(sl)) {
				host_addr_t *addr_ptr = sl->data;
				struct whitelist *item;

				g_assert(addr_ptr);

				item = walloc0(sizeof *item);
				item->addr = *addr_ptr;
				item->port = port;
				item->bits = bits ? bits : addr_default_mask(item->addr);

				if (
					item->port > 0 &&
					addr_default_mask(item->addr) == item->bits
				) {
					tls_cache_insert(item->addr, item->port);
				}

				sl_whitelist = g_slist_prepend(sl_whitelist, item);
			}
		}

		host_addr_free_list(&sl_addr);
    }

    sl_whitelist = g_slist_reverse(sl_whitelist);
	fclose(f);
}

/**
 * Attempts to connect to the nodes we have whitelisted.
 * Only entries with a specified port will be tried.
 *
 * @returns the number of new nodes that are connected to.
 */
guint
whitelist_connect(void)
{
    time_t now = tm_time();
    const GSList *sl;
    guint num = 0;

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
    	struct whitelist *item;

        item = sl->data;

        if (!item->port)
            continue;

        if (node_is_connected(item->addr, item->port, TRUE))
            continue;

        if (
			!item->last_try ||
			delta_time(now, item->last_try) > WHITELIST_RETRY_DELAY
		) {
            item->last_try = now;
            node_add(item->addr, item->port, 0);
            num++;
        }
    }
    return num;
}

/**
 * Called on startup. Loads the whitelist into memory.
 */
void
whitelist_init(void)
{
	whitelist_path = make_pathname(settings_config_dir(), whitelist_file);
    whitelist_retrieve();
}

/**
 * Frees all entries in the whitelist.
 */
void
whitelist_close(void)
{
    GSList *sl;

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
		struct whitelist *item;

		item = sl->data;
        wfree(item, sizeof *item);
	}

    g_slist_free(sl_whitelist);
    sl_whitelist = NULL;
	HFREE_NULL(whitelist_path);
}

/**
 * Reloads the whitelist.
 */
void
whitelist_reload(void)
{
    whitelist_close();
    whitelist_retrieve();
}

/**
 * Check the given IP agains the entries in the whitelist.
 *
 * Also, it will periodically check the whitelist file for
 * updates, and reload it if it has changed.
 *
 * @param ha the host address to check.
 * @returns TRUE if found, and FALSE if not.
 */
gboolean
whitelist_check(const host_addr_t ha)
{
    time_t now = tm_time();
    const GSList *sl;

    /* Check if the file has changed on disk, and reload it if necessary. */
    if (delta_time(now, whitelist_checked) > WHITELIST_CHECK_INTERVAL) {
        struct stat st;

        whitelist_checked = now;

        if (NULL != whitelist_path && 0 == stat(whitelist_path, &st)) {
            if (st.st_mtime != whitelist_mtime) {
                g_message("whitelist_check(): "
					"Whitelist changed on disk. Reloading.");
                whitelist_reload();
            }
        }
    }

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
    	const struct whitelist *item = sl->data;

		if (host_addr_matches(ha, item->addr, item->bits))
            return TRUE;
    }

    return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
