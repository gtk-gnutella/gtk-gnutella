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
    gchar *p, *sport, *snetmask;
    guint32 port, netmask;
    struct whitelist *n;
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

    while (fgets(line, sizeof(line), f)) {
		host_addr_t addr;

        linenum++;
        if (*line == '#') continue;

		/* Remove trailing spaces so that lines that contain spaces only
		 * are ignored and cause no warnings. */
		p = strchr(line, '\0');
        while (--p >= line) {
			if (!is_ascii_space((guchar) *p))
				break;
           	*p = '\0';
		}

        if ('\0' == *line)
            continue;

        sport = snetmask = NULL;

        if ((p = strchr(line, '/')) != NULL) {
            *p = '\0';
            snetmask = ++p;
        }
        if ((p = strchr(line, ':')) != NULL) {
            *p = '\0';
            sport = ++p;
        }

        addr = name_to_host_addr(line);
        if (!is_host_addr(addr) || NET_TYPE_IP4 != host_addr_net(addr)) {
            g_warning("whitelist_retrieve(): "
				"Line %d: Invalid IP \"%s\"", linenum, line);
            continue;
        }

        if (sport)
            port = atol(sport);
        else
            port = 0;

        netmask = 0xffffffffU; /* Default mask */
        if (snetmask) {
            if (strchr(snetmask, '.')) {
                netmask = string_to_ip(snetmask);
            	if (!netmask) {
                	netmask = 0xffffffff;
                	g_warning("whitelist_retrieve(): "
						"Line %d: Invalid netmask \"%s\", "
						"using 255.255.255.255 instead.", linenum, snetmask);
            	}
            } else {
				gint error;
				gulong v;

				v = gm_atoul(snetmask, NULL, &error);
                if (!error && v > 0 && v <= 32) {
                	netmask = ~(0xffffffffU >> v);
				} else {
					g_warning("whitelist_retrieve(): "
						"Line %d: Invalid netmask \"%s\", "
						"using /32 instead.", linenum, snetmask);
				}
            }
		}

        n = g_malloc0(sizeof *n);
		n->ip = host_addr_ip4(addr);
        n->port = port;
        n->netmask = netmask;

        sl_whitelist = g_slist_prepend(sl_whitelist, n);
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
    GSList *sl;
    struct whitelist *n;
    time_t now = time(NULL);
    guint num = 0;

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl)) {
		host_addr_t ha;
		
        n = sl->data;
        if (!n->port)
            continue;

		ha = host_addr_set_ip4(n->ip);
        if (node_is_connected(ha, n->port, TRUE))
            continue;

        if (delta_time(now, n->last_try) > WHITELIST_RETRY_DELAY) {
            n->last_try = now;
            node_add(ha, n->port);
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

    for (sl = sl_whitelist; sl; sl = g_slist_next(sl))
        g_free(sl->data);

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
 * @returns TRUE if found, and FALSE if not.
 *
 * Also, it will peridically check the whitelist file for
 * updates, and reload it if it has changed.
 */
gboolean
whitelist_check(const host_addr_t addr)
{
    struct whitelist *n;
    time_t now = time(NULL);
    GSList *sl;
	guint32 ip;

	if (NET_TYPE_IP4 != host_addr_net(addr)) {
		/* XXX: Allow IPv6 addresses as well */
		return FALSE;
	}

	ip = host_addr_ip4(addr);

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
		guint32 mask;

        n = sl->data;
		mask = n->netmask;
        if ((n->ip & mask) == (ip & mask))
            return TRUE;
    }

    return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
