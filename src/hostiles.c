/*
 * Copyright (c) 2003, Markus Goetz
 *
 * Support for the hostiles.txt of bearshare
 * This file is based a lot on the whitelist stuff by vidar.
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

#include "hostiles.h"
#include "file.h"
#include "settings.h"
#include "nodes.h"
#include "misc.h"

#include <ctype.h>
#include <unistd.h>

RCSID("$Id$");

GSList *sl_hostiles = NULL;

static const gchar hostiles_file[] = "hostiles.txt";
static const gchar hostiles_what[] = "hostile IP addresses";

/*
 * Pre-sorted addresses to match against.
 */

static GSList *hostiles_exact[256];		/* Indexed by LAST byte */
static GSList *hostiles_wild = NULL;	/* Addresses with mask less than /8 */
static GSList *hostiles_narrow[256];	/* Indexed by FIRST byte */

/*
 * hostiles_retrieve
 *
 * Loads the hostiles.txt into memory.
 */
void hostiles_retrieve(void)
{
	gchar line[1024];
	gchar *p;
	guint32 ip, netmask;
	struct hostile *n;
	FILE *f;
	int linenum = 0;
	gint count = 0;
#ifdef USE_SOURCE_DIR_AS_FALLBACK 
	file_path_t fp[3];
#else
	file_path_t fp[2];
#endif

	file_path_set(&fp[0], settings_config_dir(), hostiles_file);
	file_path_set(&fp[1], PRIVLIB_EXP, hostiles_file);
#ifdef USE_SOURCE_DIR_AS_FALLBACK 
	file_path_set(&fp[2], PACKAGE_SOURCE_DIR, hostiles_file);
#endif
	f = file_config_open_read_norename(hostiles_what, fp, G_N_ELEMENTS(fp));
	if (!f)
	   return;

	while (fgets(line, sizeof(line), f)) {
		linenum++;
		if (*line == '\0' || *line == '#')
			continue;
	
		p = line + strlen(line);	
		while (isspace((guchar) *(--p)))
			*p = '\0';

		if ('\0' == *line)
			continue;

		if (!gchar_to_ip_and_mask(line, &ip, &netmask)) {
			g_warning("hostiles_retrieve(): "
				"line %d: invalid IP or netmask\"%s\"", linenum, line);
			continue;
		}

		n = walloc0(sizeof(*n));
		n->ip_masked = ip & netmask;
		n->netmask = netmask;

		sl_hostiles = g_slist_append(sl_hostiles, n);
		count++;
	}

	if (dbg)
		printf("Loaded %d hostile IP addresses/netmasks\n", count);
}

/*
 * hostiles_init
 *
 * Called on startup. Loads the hostiles.txt into memory.
 */
void hostiles_init(void)
{
	GSList *sl;
	gint i;

	hostiles_retrieve();

	/*
	 * Pre-compile addresses so that we don't have to check too many rules
	 * each time to see if an address is part of the hostile set:
	 *
	 * The addresses whose mask is /32 are put in a special array, indexed by
	 * the LAST byte of the address: `hostiles_exact'.
	 *
	 * The addresses with /8 or less are put in a special list that is
	 * parsed in the second place: `hostiles_wild'.  There should not be
	 * much in there.
	 *
	 * All remaining addresses are places in an array, indexed by the FIRST byte
	 * of the address: `hostiles_narrow'.
	 */

	for (i = 0; i < 256; i++)
		hostiles_exact[i] = hostiles_narrow[i] = NULL;

	for (sl = sl_hostiles; sl; sl = g_slist_next(sl)) {
		struct hostile *h = (struct hostile *) sl->data;
		if (h->netmask == 0xffffffff) {
			i = h->ip_masked & 0x000000ff;
			hostiles_exact[i] = g_slist_prepend(hostiles_exact[i], h);
		} else if (h->netmask < 0xff000000)
			hostiles_wild = g_slist_prepend(hostiles_wild, h);
		else {
			i = (h->ip_masked & 0xff000000) >> 24;
			hostiles_narrow[i] = g_slist_prepend(hostiles_narrow[i], h);
		}
	}
}

/*
 * hostiles_close
 *
 * Frees all entries in the hostiles
 */
void hostiles_close(void)
{
	GSList *sl;
	gint i;

	for (i = 0; i < 256; i++) {
		g_slist_free(hostiles_exact[i]);
		g_slist_free(hostiles_narrow[i]);
	}
	g_slist_free(hostiles_wild);

	for (sl = sl_hostiles; sl; sl = g_slist_next(sl)) 
		wfree(sl->data, sizeof(struct hostile));

	g_slist_free(sl_hostiles);
	sl_hostiles = NULL;
}

/*
 * hostiles_check
 *
 * Check the given IP agains the entries in the hostiles.
 * Returns TRUE if found, and FALSE if not.
 *
 */
gboolean hostiles_check(guint32 ip)
{
	GSList *sl;
	struct hostile *h;
	gint i;

	/*
	 * Look for an exact match.
	 */

	i = ip & 0x000000ff;

	for (sl = hostiles_exact[i]; sl; sl = g_slist_next(sl)) {
		h = (struct hostile *) sl->data;
		if (ip == h->ip_masked)
			return TRUE;
	}

	/*
	 * Look for a wild match.
	 */

	for (sl = hostiles_wild; sl; sl = g_slist_next(sl)) {
		h = (struct hostile *) sl->data;
		if ((ip & h->netmask) == h->ip_masked)
			return TRUE;
	}

	/*
	 * Look for a narrow match.
	 */

	i = (ip & 0xff000000) >> 24;

	for (sl = hostiles_narrow[i]; sl; sl = g_slist_next(sl)) {
		h = (struct hostile *) sl->data;
		if ((ip & h->netmask) == h->ip_masked)
			return TRUE;
	}

	return FALSE;
}

