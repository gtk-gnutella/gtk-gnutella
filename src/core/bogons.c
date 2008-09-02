/*
 * $Id$
 *
 * Copyright (c) 2004, Raphael Manfredi
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
 * Support for IP bogons detection.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

RCSID("$Id$")

#include "bogons.h"
#include "settings.h"

#include "lib/ascii.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/iprange.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static const gchar bogon[] = "bogon";

static const gchar bogons_file[] = "bogons.txt";
static const gchar bogons_what[] = "Bogus IP addresses";

static struct iprange_db *bogons_db; /**< The database of bogus CIDR ranges */

/**
 * Load bogons data from the supplied FILE.
 *
 * @returns the amount of entries loaded.
 */
static gint
bogons_load(FILE *f)
{
	gchar line[1024];
	gchar *p;
	guint32 ip, netmask;
	int linenum = 0;
	gint bits;
	iprange_err_t error;

	bogons_db = iprange_new();

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

		if (!string_to_ip_and_mask(line, &ip, &netmask)) {
			g_warning("%s, line %d: invalid IP or netmask \"%s\"",
				bogons_file, linenum, line);
			continue;
		}

		bits = netmask_to_cidr(netmask);
		error = iprange_add_cidr(bogons_db, ip, bits,
					deconstify_gpointer(bogon));

		switch (error) {
		case IPR_ERR_OK:
			break;
			/* FALL THROUGH */
		default:
			g_warning("%s, line %d: rejected entry \"%s\" (%s/%d): %s",
				bogons_file, linenum, line, ip_to_string(ip), bits,
				iprange_strerror(error));
			continue;
		}
	}

	iprange_sync(bogons_db);

	if (GNET_PROPERTY(dbg)) {
		g_message("loaded %u bogus IP ranges (%u hosts)",
			iprange_get_item_count(bogons_db),
			iprange_get_host_count(bogons_db));
	}

	return iprange_get_item_count(bogons_db);
}

/**
 * Watcher callback, invoked when the file from which we read the bogus
 * addresses changed.
 */
static void
bogons_changed(const gchar *filename, gpointer unused_udata)
{
	FILE *f;
	gchar buf[80];
	gint count;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f == NULL)
		return;

	bogons_close();
	count = bogons_load(f);

	gm_snprintf(buf, sizeof(buf), "Reloaded %d bogus IP ranges.", count);
	gcu_statusbar_message(buf);
}

/**
 * Loads the bogons.txt into memory.
 *
 * Choosing the first file we find among the several places we look at,
 * typically:
 *
 *	-# ~/.gtk-gnutella/bogons.txt
 *	-# /usr/share/gtk-gnutella/bogons.txt
 *	-# PACKAGE_EXTRA_SOURCE_DIR/bogons.txt
 *
 * The selected file will then be monitored and a reloading will occur
 * shortly after a modification.
 */
static void
bogons_retrieve(void)
{
	FILE *f;
	gint idx;
	gchar *filename;
#ifndef OFFICIAL_BUILD
	static file_path_t fp[3];
#else
	static file_path_t fp[2];
#endif

	file_path_set(&fp[0], settings_config_dir(), bogons_file);
	file_path_set(&fp[1], PRIVLIB_EXP, bogons_file);
#ifndef OFFICIAL_BUILD
	file_path_set(&fp[2], PACKAGE_EXTRA_SOURCE_DIR, bogons_file);
#endif

	f = file_config_open_read_norename_chosen(
			bogons_what, fp, G_N_ELEMENTS(fp), &idx);

	if (!f)
	   return;

	filename = make_pathname(fp[idx].dir, fp[idx].name);
	watcher_register(filename, bogons_changed, NULL);
	G_FREE_NULL(filename);

	bogons_load(f);
	fclose(f);
}

/**
 * Called on startup. Loads the bogons.txt into memory.
 */
void
bogons_init(void)
{
	bogons_retrieve();
}

/**
 * Frees all entries in the hostiles.
 */
void
bogons_close(void)
{
	iprange_free(&bogons_db);
}

/**
 * Check the given IP against the entries in the bogus IP database.
 *
 * @returns TRUE if found, and FALSE if not.
 */
gboolean
bogons_check(const host_addr_t ha)
{
	if (NET_TYPE_IPV4 == host_addr_net(ha)) {
		guint32 ip = host_addr_ipv4(ha);
		return bogons_db && iprange_get(bogons_db, ip);
	} else if (NET_TYPE_IPV6 == host_addr_net(ha)) {
		host_addr_t to;

		if (host_addr_convert(ha, &to, NET_TYPE_IPV4))
			return bogons_check(to);
	}

	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: */
