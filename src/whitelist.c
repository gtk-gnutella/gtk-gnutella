/*
 * Copyright (c) 2002, Vidar Madsen
 *
 * Functions for keeping a whitelist of nodes we always allow in,
 * and whom we try to keep a connection to.
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

#include "gnutella.h"

#include "whitelist.h"
#include "settings.h"
#include "nodes.h"

#include <sys/stat.h>
#include <unistd.h>

RCSID("$Id$");

GSList *sl_whitelist = NULL;

static const gchar *whitelist_file = "whitelist";
static time_t whitelist_mtime, whitelist_checked;

static gchar wl_tmp[1024];

/*
 * whitelist_retrieve
 *
 * Loads the whitelist into memory.
 */
static void whitelist_retrieve(void)
{
    gchar line[1024];
    gchar *p, *sport, *snetmask;
    guint32 ip, port, netmask;
    struct whitelist *n;
    FILE *f;
    struct stat st;
    int linenum = 0;

    gm_snprintf(wl_tmp, sizeof(wl_tmp), "%s/%s",
		settings_config_dir(), whitelist_file);

    if (stat(wl_tmp, &st) == -1) {
        if(dbg)
            printf("whitelist_retrieve(): error stat()ing whitelist file.\n");
        return;
    }

    whitelist_checked = time(NULL);
    whitelist_mtime = st.st_mtime;

    f = fopen(wl_tmp, "r");
    if (!f) {
        if(dbg)
            printf("whitelist_retrieve(): error opening whitelist file.");
        return;
    }

    while (fgets(line, sizeof(line), f)) {
        linenum++;
        if (*line == '#') continue;

        while (*line && line[strlen(line)-1] <= ' ')
            line[strlen(line)-1] = '\0';

        if (!*line)
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

        ip = host_to_ip(line);
        if (!ip) {
            g_warning("whitelist_retrieve(): "
				"Line %d: Invalid IP \"%s\"", linenum, line);
            continue;
        }
        
        if (sport) 
            port = atol(sport);
        else
            port = 0;

        if (snetmask) {
            if (strchr(snetmask, '.')) {
                netmask = gchar_to_ip(snetmask);
            } else {
                int n = atoi(snetmask);
                netmask = ~(0xffffffff >> n);
            }
            if(!netmask) {
                netmask = 0xffffffff;
                g_warning("whitelist_retrieve(): "
					"Line %d: Invalid netmask \"%s\", "
					"using 255.255.255.255 instead.", linenum, snetmask);
            }
        } else
            netmask = 0xffffffff;

        n = g_malloc0(sizeof(*n));
        n->ip = ip;
        n->port = port;
        n->netmask = netmask;

        sl_whitelist = g_slist_append(sl_whitelist, n);

    }
                                                
}

/*
 * whitelist_connect
 *
 * Attempts to connect to the nodes we have whitelisted.
 * Only entries with a specified port will be tried.
 * Returns the number of new nodes that are connected to.
 */
int whitelist_connect(void)
{
    GSList *l;
    struct whitelist *n;
    time_t now = time(NULL);
    int num = 0;

    for (l = sl_whitelist; l; l = l->next) {
        n = l->data;
        if (!n->port)
            continue;
        if (node_is_connected(n->ip, n->port, TRUE))
            continue;

        if ((now - n->last_try) > WHITELIST_RETRY_DELAY) {
            n->last_try = now;
            node_add(n->ip, n->port);
            num++;
        }
    }
    return num;
}

/*
 * whitelist_init
 *
 * Called on startup. Loads the whitelist into memory.
 */
void whitelist_init(void)
{
    whitelist_retrieve();
}

/*
 * whitelist_close
 *
 * Frees all entries in the whitelist.
 */
void whitelist_close(void)
{
    GSList *l;

    for (l = sl_whitelist; l; l = l->next) 
        g_free(l->data);

    g_slist_free(sl_whitelist);
    sl_whitelist = NULL;
}

/*
 * whitelist_reload
 *
 * Reloads the whitelist.
 */
void whitelist_reload(void)
{
    whitelist_close();
    whitelist_retrieve();
}

/*
 * whitelist_check
 *
 * Check the given IP agains the entries in the whitelist.
 * Returns TRUE if found, and FALSE if not.
 *
 * Also, it will peridically check the whitelist file for
 * updates, and reload it if it has changed.
 */
gboolean whitelist_check(guint32 ip)
{
    GSList *l;
    struct whitelist *n;
    time_t now = time(NULL);

    /* Check if the file has changed on disk, and reload it if necessary. */
    if ((now - whitelist_checked) > WHITELIST_CHECK_INTERVAL) {
        struct stat st;

        whitelist_checked = now;

        gm_snprintf(wl_tmp, sizeof(wl_tmp), "%s/%s",
			settings_config_dir(), whitelist_file);
        if (stat(wl_tmp, &st) != -1) {
            if (st.st_mtime != whitelist_mtime) {
                g_warning("whitelist_check(): "
					"Whitelist changed on disk. Reloading.");
                whitelist_reload();
            }
        }
    }
    
    for (l = sl_whitelist; l; l = l->next) {
        n = l->data;
        if ((ip & n->netmask) == (n->ip & n->netmask))
            return TRUE;
    }

    return FALSE;
}

