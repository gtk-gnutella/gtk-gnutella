/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
 * Copyright (c) 2003, Markus Goetz
 *
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

/**
 * @file
 *
 * Support for the hostiles.txt of BearShare
 */

#include "common.h"

RCSID("$Id$");

#include "hostiles.h"
#include "settings.h"
#include "nodes.h"

#include "lib/file.h"
#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/iprange.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

#define THERE	GUINT_TO_POINTER(0x2)

static const gchar hostiles_file[] = "hostiles.txt";
static const gchar hostiles_what[] = "hostile IP addresses";

static gpointer hostile_db;		/* The hostile database */

/**
 * Load hostile data from the supplied FILE.
 * Returns the amount of entries loaded.
 */
static gint
hostiles_load(FILE *f)
{
	gchar line[1024];
	gchar *p;
	guint32 ip, netmask;
	int linenum = 0;
	gint count = 0;
	gint bits;
	iprange_err_t error;

	hostile_db = iprange_make(NULL, NULL);

	while (fgets(line, sizeof(line), f)) {
		linenum++;
		if (*line == '\0' || *line == '#')
			continue;

		/*
		 * Remove all trailing spaces in string.
		 * Otherwise, lines which contain only spaces would cause a warning.
		 */
	
		p = strchr(line, '\0');	
		while (--p >= line) {
			guchar c = (guchar) *p;
			if (!is_ascii_space(c))
				break;
			*p = '\0';
		}
		if ('\0' == *line)
			continue;

		if (!gchar_to_ip_and_mask(line, &ip, &netmask)) {
			g_warning("%s, line %d: invalid IP or netmask \"%s\"",
				hostiles_file, linenum, line);
			continue;
		}

		bits = 32;
		while (0 == (netmask & 0x1)) {
			netmask >>= 1;
			bits--;
		}

		error = iprange_add_cidr(hostile_db, ip, bits, THERE);

		switch (error) {
		case IPR_ERR_OK:
			break;
		case IPR_ERR_RANGE_OVERLAP:
			error = iprange_add_cidr_force(hostile_db, ip, bits, THERE, NULL);
			if (error == IPR_ERR_OK) {
				g_warning("%s: line %d: "
					"entry \"%s\" (%s/%d) superseded earlier smaller range",
					hostiles_file, linenum, line, ip_to_gchar(ip), bits);
				break;
			}
			/* FALL THROUGH */
		default:
			g_warning("%s, line %d: rejected entry \"%s\" (%s/%d): %s",
				hostiles_file, linenum, line, ip_to_gchar(ip), bits,
				iprange_strerror(error));
			continue;
		}

		count++;
	}

	if (dbg) {
		iprange_stats_t stats;

		iprange_get_stats(hostile_db, &stats);

		g_message("loaded %d hostile IP addresses/netmasks", count);
		g_message("hostile stats: count=%d level2=%d heads=%d enlisted=%d",
			stats.count, stats.level2, stats.heads, stats.enlisted);
	}

	return count;
}

/**
 * Watcher callback, invoked when the file from which we read the hostile
 * addresses changed.
 */
static void
hostiles_changed(const gchar *filename, gpointer unused_udata)
{
	FILE *f;
	gchar buf[80];
	gint count;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f == NULL)
		return;

	hostiles_close();
	count = hostiles_load(f);

	gm_snprintf(buf, sizeof(buf), "Reloaded %d hostile IP addresses.", count);
	gcu_statusbar_message(buf);
}

/**
 * Loads the hostiles.txt into memory, choosing the first file we find
 * among the several places we look at, typically:
 *
 *    ~/.gtk-gnutella/hostiles.txt
 *    /usr/share/gtk-gnutella/hostiles.txt
 *    /home/src/gtk-gnutella/hostiles.txt
 *
 * The selected file will then be monitored and a reloading will occur
 * shortly after a modification.
 */
static void
hostiles_retrieve(void)
{
	FILE *f;
	gint idx;
	gchar *filename;
#ifndef OFFICIAL_BUILD 
	file_path_t fp[3];
#else
	file_path_t fp[2];
#endif

	file_path_set(&fp[0], settings_config_dir(), hostiles_file);
	file_path_set(&fp[1], PRIVLIB_EXP, hostiles_file);
#ifndef OFFICIAL_BUILD 
	file_path_set(&fp[2], PACKAGE_SOURCE_DIR, hostiles_file);
#endif

	f = file_config_open_read_norename_chosen(
			hostiles_what, fp, G_N_ELEMENTS(fp), &idx);

	if (!f)
	   return;

	filename = make_pathname(fp[idx].dir, fp[idx].name);
	watcher_register(filename, hostiles_changed, NULL);
	G_FREE_NULL(filename);

	hostiles_load(f);
}

/**
 * Called on startup. Loads the hostiles.txt into memory.
 */
void
hostiles_init(void)
{
	hostiles_retrieve();
}

/**
 * Frees all entries in the hostiles
 */
void
hostiles_close(void)
{
	iprange_free_each(hostile_db, NULL);
	hostile_db = NULL;
}

/**
 * Check the given IP agains the entries in the hostiles.
 * Returns TRUE if found, and FALSE if not.
 */
gboolean
hostiles_check(guint32 ip)
{
	return THERE == iprange_get(hostile_db, ip);
}

/* vi: set ts=4: */
