/*
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

#include "bogons.h"
#include "settings.h"

#include "lib/ascii.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/host_addr.h"
#include "lib/iprange.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

static const char bogons_file[] = "bogons.txt";
static const char bogons_what[] = "Bogus IP addresses";

static struct iprange_db *bogons_db; /**< The database of bogus CIDR ranges */
static time_t bogons_mtime;			 /**< Modification time of loaded file */

/**
 * Load bogons data from the supplied FILE.
 *
 * @returns the amount of entries loaded.
 */
static G_GNUC_COLD int
bogons_load(FILE *f)
{
	char line[1024];
	uint32 ip, netmask;
	int linenum = 0;
	int bits;
	iprange_err_t error;
	filestat_t buf;

	bogons_db = iprange_new();
	if (-1 == fstat(fileno(f), &buf)) {
		g_warning("cannot stat %s: %m", bogons_file);
	} else {
		bogons_mtime = buf.st_mtime;
	}

	while (fgets(line, sizeof line, f)) {
		linenum++;

		/*
		 * Remove all trailing spaces in string.
		 * Otherwise, lines which contain only spaces would cause a warning.
		 */

		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
			g_warning("%s, line %d: too long a line", bogons_file, linenum);
			break;
		}

		if (file_line_is_skipable(line))
			continue;

		if (!string_to_ip_and_mask(line, &ip, &netmask)) {
			g_warning("%s, line %d: invalid IP or netmask \"%s\"",
				bogons_file, linenum, line);
			continue;
		}

		bits = netmask_to_cidr(netmask);
		error = iprange_add_cidr(bogons_db, ip, bits, 1);

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

	if (GNET_PROPERTY(reload_debug)) {
		g_debug("loaded %u bogus IP ranges (%u hosts)",
			iprange_get_item_count(bogons_db),
			iprange_get_host_count4(bogons_db));
	}

	return iprange_get_item_count(bogons_db);
}

/**
 * Watcher callback, invoked when the file from which we read the bogus
 * addresses changed.
 */
static void
bogons_changed(const char *filename, void *unused_udata)
{
	FILE *f;
	char buf[80];
	int count;

	(void) unused_udata;

	f = file_fopen(filename, "r");
	if (f == NULL)
		return;

	bogons_close();
	count = bogons_load(f);
	fclose(f);

	str_bprintf(buf, sizeof(buf), "Reloaded %d bogus IP ranges.", count);
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
static G_GNUC_COLD void
bogons_retrieve(void)
{
	FILE *f;
	int idx;
	char *filename;
	file_path_t fp[4];
	unsigned length;

	length = settings_file_path_load(fp, bogons_file, SFP_DFLT);

	g_assert(length <= G_N_ELEMENTS(fp));

	f = file_config_open_read_norename_chosen(bogons_what, fp, length, &idx);

	if (NULL == f)
	   return;

	filename = make_pathname(fp[idx].dir, fp[idx].name);
	watcher_register(filename, bogons_changed, NULL);
	HFREE_NULL(filename);

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
bool
bogons_check(const host_addr_t ha)
{
	if G_UNLIKELY(NULL == bogons_db)
		return FALSE;

	/*
	 * If the bogons file is too ancient, there is a risk it may flag an
	 * IP as bogus whereas it is no longer reserved.  IPv4 address shortage
	 * makes that likely.
	 *		--RAM, 2010-11-07
	 */

	if (delta_time(tm_time(), bogons_mtime) > 15552000)	/* ~6 months */
		return !host_addr_is_routable(ha);

	return 0 != iprange_get_addr(bogons_db, ha);
}

/* vi: set ts=4 sw=4 cindent: */
