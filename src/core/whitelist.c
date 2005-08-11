/*
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

RCSID("$Id$");

#include "whitelist.h"
#include "settings.h"
#include "nodes.h"

#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

static GSList *sl_whitelist = NULL;

static const gchar whitelist_file[] = "whitelist";
static time_t whitelist_mtime, whitelist_checked;
static gchar *whitelist_path = NULL;

/**
 * Loads the whitelist into memory.
 */
static void
whitelist_retrieve(void)
{
    gchar line[1024];
    FILE *f;
    struct stat st;
    int linenum = 0;
	file_path_t fp[1];

	file_path_set(fp, settings_config_dir(), whitelist_file);
	f = file_config_open_read_norename("Host Whitelist", fp, G_N_ELEMENTS(fp));
	if (!f)
		return;

	if (fstat(fileno(f), &st)) {
		g_warning("whitelist_retrieve: fstat() failed: %s", g_strerror(errno));
		fclose(f);
		return;
	}
    whitelist_checked = time(NULL);
    whitelist_mtime = st.st_mtime;

    while (fgets(line, sizeof line, f)) {
		const gchar *endptr;
		host_addr_t addr;
    	guint16 port;
		guint8 bits;
		gchar *p;

        linenum++;
        if ('#' == line[0]) continue;

		/* Remove trailing spaces so that lines that contain spaces only
		 * are ignored and cause no warnings. */
		p = strchr(line, '\0');
        while (p != line) {
			p--;
			if (!is_ascii_space((guchar) *p)) {
				*++p = '\0';
				break;
			}
		}

        if ('\0' == line[0])
            continue;

		addr = zero_host_addr;
		endptr = NULL;

		if (!string_to_host_or_addr(line, &endptr, &addr)) {
            g_warning("whitelist_retrieve(): "
				"Line %d: Expect hostname or IP address \"%s\"",
				linenum, line);
			continue;
		}

        if (!is_host_addr(addr)) {
			guchar c = *endptr;
			size_t len;
			
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

			len = endptr - line;
			line[len] = '\0'; /* Terminate the string for name_to_host_addr() */

			/* @todo TODO: This should use the ADNS resolver. */
        	addr = name_to_host_addr(line);

        	if (!is_host_addr(addr)) {
            	g_warning("whitelist_retrieve(): "
				"Line %d: Could not resolve hostname \"%s\"", linenum, line);
            	continue;
        	}
		}

       	g_assert(is_host_addr(addr));
		g_assert(NULL != endptr);
		port = bits = 0;

		/* Ignore trailing items separated by a space */
		while ('\0' != *endptr && !is_ascii_space(*endptr)) {
			guchar c = *endptr++;
			
			if (':' == c) {
				gint error;
				guint32 v;
		
				if (0 != port) {
					g_warning("whitelist_retrieve(): Line %d:"
						"Multiple colons after host", linenum);
					addr = zero_host_addr;
					break;
				}
					
            	v = parse_uint32(endptr, &endptr, 10, &error);
				port = (error || v > 0xffff) ? 0 : v;
				if (0 == port) {
					g_warning("whitelist_retrieve(): Line %d: "
						"Invalid port value after host", linenum);
					addr = zero_host_addr;
					break;
				}
			} else if ('/' == c) {
				const gchar *ep;
				guint32 mask;

				if (0 != bits) {
					g_warning("whitelist_retrieve(): Line %d:"
						"Multiple slashes after host", linenum);
					addr = zero_host_addr;
					break;
				}

				if (string_to_ip_strict(endptr, &mask, &ep)) {
					if (NET_TYPE_IP4 != host_addr_net(addr)) {
						g_warning("whitelist_retrieve(): Line %d: "
							"IPv4 netmask after non-IPv4 address", linenum);
						addr = zero_host_addr;
						break;
					}
					endptr = ep;

					if (0 == (bits = netmask_to_cidr(mask))) {
						g_warning("whitelist_retrieve(): Line %d: "
							"IPv4 netmask after non-IPv4 address", linenum);
						addr = zero_host_addr;
						break;
					}
						
				} else {
					gint error;
					guint32 v;
					
            		v = parse_uint32(endptr, &endptr, 10, &error);
					if (
						error ||
						0 == v ||
						(v > 32 && NET_TYPE_IP4 == host_addr_net(addr)) ||
						(v > 128 && NET_TYPE_IP6 == host_addr_net(addr))
					) {
						g_warning("whitelist_retrieve(): Line %d: "
							"Invalid numeric netmask after host", linenum);
						addr = zero_host_addr;
						break;
					}
					bits = v;
				}
			} else {
				g_warning("whitelist_retrieve(): Line %d: "
					"Unexpected character after host", linenum);
				addr = zero_host_addr;
				break;
			}
		}

        if (!is_host_addr(addr)) {
			continue;
		}
	
		if (0 == bits)	{
			/* Default mask */
			switch (host_addr_net(addr)) {
			case NET_TYPE_IP4:
        		bits = 32;
				break;
			case NET_TYPE_IP6:
        		bits = 128;
				break;
			case NET_TYPE_NONE:
				break;
			}
			g_assert(0 != bits);
		}

		{
    		struct whitelist *item;
			
        	item = walloc0(sizeof *item);
			item->addr = addr;
        	item->port = port;
        	item->bits = bits;

        	sl_whitelist = g_slist_prepend(sl_whitelist, item);
		}
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
    time_t now = time(NULL);
    const GSList *sl;
    guint num = 0;

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
    	struct whitelist *item;

        item = sl->data;

        if (!item->port)
            continue;

        if (node_is_connected(item->addr, item->port, TRUE))
            continue;

        if (delta_time(now, item->last_try) > WHITELIST_RETRY_DELAY) {
            item->last_try = now;
            node_add(item->addr, item->port);
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
	G_FREE_NULL(whitelist_path);
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
    time_t now = time(NULL);
    GSList *sl;

    /* Check if the file has changed on disk, and reload it if necessary. */
    if (delta_time(now, whitelist_checked) > WHITELIST_CHECK_INTERVAL) {
        struct stat st;

        whitelist_checked = now;

        if (NULL != whitelist_path && 0 == stat(whitelist_path, &st)) {
            if (st.st_mtime != whitelist_mtime) {
                g_warning("whitelist_check(): "
					"Whitelist changed on disk. Reloading.");
                whitelist_reload();
            }
        }
    }

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
    	struct whitelist *n;

        n = sl->data;
		if (host_addr_matches(ha, n->addr, n->bits))
            return TRUE;
    }

    return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
