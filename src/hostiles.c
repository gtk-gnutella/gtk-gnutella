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

#include <sys/stat.h>
#include <unistd.h>

RCSID("$Id$");

GSList *sl_hostiles = NULL;

static const gchar *hostiles_file = "hostiles.txt";
static const gchar *hostiles_what = "hostile IP addresses";

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
	gchar *p, *snetmask;
	guint32 ip, netmask;
	struct hostile *n;
	FILE *f;
	int linenum = 0;
	gint count = 0;
	file_path_t fp[] = {
		{ settings_config_dir(), hostiles_file },
		{ PACKAGE_DATA_DIR, hostiles_file },
#ifdef USE_SOURCE_DIR_AS_FALLBACK 
		{ PACKAGE_SOURCE_DIR, hostiles_file },
#endif
	};

	f = file_config_open_read_norename(hostiles_what, fp, G_N_ELEMENTS(fp));
	if (!f)
	   return;

	// XXX code parsing below is somehow a duplicate of that of whitelist.c,
	// XXX with some enhancements.  Needs to be factorized into misc.c.
	// XXX	--RAM, 08/05/2003

	while (fgets(line, sizeof(line), f)) {
		linenum++;
		if (*line == '#') continue;

		while (*line && line[strlen(line)-1] <= ' ')
			line[strlen(line)-1] = '\0';

		if (!*line)
			continue;

		snetmask = NULL;
		
		if ((p = strchr(line, '/')) != NULL) {
			*p = '\0';
			snetmask = ++p;
		}

		/*
		 * It should only contain IPs and netmasks, but well, we could
		 * have explict names in there some day...
		 */

		ip = host_to_ip(line);
		if (!ip) {
			g_warning("hostiles_retrieve(): "
				"line %d: invalid IP \"%s\"", linenum, line);
			continue;
		}
		
		if (snetmask) {
			gint i;

			if (strchr(snetmask, '.'))
				netmask = gchar_to_ip(snetmask);
			else {
				int n = atoi(snetmask);
				netmask = ~(0xffffffff >> n);
			}
			if (!netmask) {
				netmask = 0xffffffff;
				g_warning("hostiles_retrieve(): "
					"line %d: invalid netmask \"%s\", "
					"using 255.255.255.255 instead.", linenum, snetmask);
			}

			/*
			 * Ensure netmask has leading 1's and trailing 0's.
			 */

			i = highest_bit_set(~netmask);
			if (netmask != ~((1 << (i+1)) - 1)) {
				netmask = 0xffffffff;
				g_warning("hostiles_retrieve(): "
					"line %d: invalid netmask \"%s\" (bit #%d not 0), "
					"using 255.255.255.255 instead.", linenum, snetmask, i);
			}
		} else
			netmask = 0xffffffff;

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
	GSList *l;
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

	for (l = sl_hostiles; l; l = l->next) {
		struct hostile *h = (struct hostile *) l->data;
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
	GSList *l;
	gint i;

	for (i = 0; i < 256; i++) {
		g_slist_free(hostiles_exact[i]);
		g_slist_free(hostiles_narrow[i]);
	}
	g_slist_free(hostiles_wild);

	for (l = sl_hostiles; l; l = l->next) 
		wfree(l->data, sizeof(struct hostile));

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
	GSList *l;
	struct hostile *h;
	gint i;

	/*
	 * Look for an exact match.
	 */

	i = ip & 0x000000ff;

	for (l = hostiles_exact[i]; l; l = l->next) {
		h = (struct hostile *) l->data;
		if (ip == h->ip_masked)
			return TRUE;
	}

	/*
	 * Look for a wild match.
	 */

	for (l = hostiles_wild; l; l = l->next) {
		h = (struct hostile *) l->data;
		if ((ip & h->netmask) == h->ip_masked)
			return TRUE;
	}

	/*
	 * Look for a narrow match.
	 */

	i = (ip & 0xff000000) >> 24;

	for (l = hostiles_narrow[i]; l; l = l->next) {
		h = (struct hostile *) l->data;
		if ((ip & h->netmask) == h->ip_masked)
			return TRUE;
	}

	return FALSE;
}

