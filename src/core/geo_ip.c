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
 * Support for geographic (country-level) IP mapping.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "geo_ip.h"
#include "settings.h"

#include "lib/ascii.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/host_addr.h"
#include "lib/iprange.h"
#include "lib/iso3166.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/str.h"
#include "lib/stringify.h"		/* For ipv6_to_string() */
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/watcher.h"

#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/override.h"		/* Must be the last header included */

#define GIP_IPV4	0
#define GIP_IPV6	1

struct gip_source {
	const char *file;		/**< Source file */
	const char *what;		/**< English description of file */
	time_t mtime;			/**< Modification time of loaded file */
};

static struct gip_source gip_source[] = {
	{ "geo-ip.txt",		"Geographic IPv4 mappings", 0 },
	{ "geo-ipv6.txt",	"Geographic IPv6 mappings", 0 },
};

static struct iprange_db *geo_db;	/**< The database of bogus CIDR ranges */

/**
 * Context used during ip_range_split() calls.
 */
struct range_context {
	const char *line;			/**< The line from the input file */
	int linenum;				/**< Line number in input file, for errors */
	uint32 ip1;					/**< Original lower IP in global range */
	uint32 ip2;					/**< Original upper IP in global range */
	uint16 country;				/**< Country code (numerical encoded) */
};

/**
 * ip_range_split() callback.
 *
 * Insert IP range in database, linking it to the proper country code.
 */
static void
gip_add_cidr(uint32 ip, uint bits, void *udata)
{
	struct range_context *ctx = udata;
	iprange_err_t error;
	uint16 cc;

	if (GNET_PROPERTY(reload_debug) > 4)
		printf("GEO adding %s/%d for \"%s\"\n",
			ip_to_string(ip), bits, ctx->line);

	cc = ctx->country;
	error = iprange_add_cidr(geo_db, ip, bits, cc);

	switch (error) {
	case IPR_ERR_OK:
		break;
		/* FALL THROUGH */
	default:
		g_warning("%s, line %d: rejected entry \"%s\" (%s/%d): %s",
			gip_source[GIP_IPV4].file, ctx->linenum,
			ctx->line, ip_to_string(ip), bits, iprange_strerror(error));
		return;
	}
}

/**
 * Parse an IPv4 Geo IP line and record the range in the database.
 */
static void
gip_parse_ipv4(const char *line, int linenum)
{
	const char *end;
	uint16 code;
	int c;
	struct range_context ctx;

	/*
	 * Each line looks like:
	 *
	 *    15.0.0.0 - 15.130.191.255 fr
	 *
	 * So we just have to parse the two IP addresses, then compute
	 * all the ranges they cover in order to insert them into
	 * the IP database.
	 */

	end = strchr(line, '-');
	if (end == NULL) {
		g_warning("%s, line %d: no IP address separator in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	if (!string_to_ip_strict(line, &ctx.ip1, NULL)) {
		g_warning("%s, line %d: invalid first IP in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	/*
	 * Skip spaces until the second IP.
	 */

	end++;			/* Go past the minus, parsing the second IP */

	while ((c = *end)) {
		if (!is_ascii_space(c))
			break;
		end++;
	}

	if (!string_to_ip_strict(end, &ctx.ip2, &end)) {
		g_warning("%s, line %d: invalid second IP in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	/*
	 * Make sure the IP addresses are ordered correctly
	 */

	if (ctx.ip1 > ctx.ip2) {
		g_warning("%s, line %d: invalid IP order in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	/*
	 * Skip spaces until the country code.
	 */

	while ((c = *end)) {
		if (!is_ascii_space(c))
			break;
		end++;
	}

	if (c == '\0') {
		g_warning("%s, line %d: missing country code in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	code = iso3166_encode_cc(end);
	if (ISO3166_INVALID == code) {
		g_warning("%s, line %d: bad country code in \"%s\"",
			gip_source[GIP_IPV4].file, linenum, line);
		return;
	}

	/* code must not be zero and the LSB must be zero due to using it as
	 * as key for ipranges */
	ctx.country = (code + 1) << 1;
	ctx.line = line;
	ctx.linenum = linenum;

	/*
	 * Now compute the CIDR ranges between the ip1 and ip2 addresses
	 * and insert each range into the database, linking it to the
	 * country code.
	 */

	ip_range_split(ctx.ip1, ctx.ip2, gip_add_cidr, &ctx);
}

/**
 * Parse an IPv6 Geo IP line and record the range in the database.
 */
static void
gip_parse_ipv6(const char *line, int linenum)
{
	const char *end;
	uint16 code;
	int error;
	uint8 ip[16];
	unsigned bits;

	/*
	 * Each line looks like:
	 *
	 *    2a03:be00::/32 nl
	 *
	 * The leading part up to the space is the IPv6 network in CIDR format.
	 * The trailing word is the 2-letter ISO country code.
	 */

	if (!parse_ipv6_addr(line, ip, &end)) {
		g_warning("%s, line %d: bad IPv6 network address \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	if ('/' != *end) {
		g_warning("%s, line %d: missing network separator in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	bits = parse_uint(end + 1, &end, 10, &error);

	if (error) {
		g_warning("%s, line %d: cannot parse network bit amount in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	if (bits > 128) {
		g_warning("%s, line %d: invalid bit amount %u in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, bits, line);
		return;
	}

	if (!is_ascii_space(*end)) {
		g_warning("%s, line %d: missing spaces after network in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	while (is_ascii_space(*end))
		end++;

	if ('\0' == *end) {
		g_warning("%s, line %d: missing country code in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	code = iso3166_encode_cc(end);
	if (ISO3166_INVALID == code) {
		g_warning("%s, line %d: bad country code in \"%s\"",
			gip_source[GIP_IPV6].file, linenum, line);
		return;
	}

	error = iprange_add_cidr6(geo_db, ip, bits, (code + 1) << 1);

	if (IPR_ERR_OK != error) {
		g_warning("%s, line %d: cannot insert %s/%u: %s",
			gip_source[GIP_IPV6].file, linenum, ipv6_to_string(ip),
			bits, iprange_strerror(error));
	}
}

/**
 * Load geographic IP data from the supplied FILE.
 *
 * @return The amount of entries loaded.
 */
static G_GNUC_COLD uint
gip_load(FILE *f, unsigned idx)
{
	char line[1024];
	int linenum = 0;
	filestat_t buf;

	g_assert(f != NULL);
	g_assert(uint_is_non_negative(idx));
	g_assert(idx < G_N_ELEMENTS(gip_source));

	switch (idx) {
	case GIP_IPV4:
		iprange_reset_ipv4(geo_db);
		break;
	case GIP_IPV6:
		iprange_reset_ipv6(geo_db);
		break;
	default:
		g_assert_not_reached();
	}

	if (-1 == fstat(fileno(f), &buf)) {
		g_warning("cannot stat %s: %m", gip_source[idx].file);
	} else {
		gip_source[idx].mtime = buf.st_mtime;
	}

	while (fgets(line, sizeof line, f)) {
		linenum++;

		/*
		 * Remove all trailing spaces in string.
		 * Otherwise, lines which contain only spaces would cause a warning.
		 */

		if (!file_line_chomp_tail(line, sizeof line, NULL)) {
			g_warning("%s: line %d too long, aborting",
				gip_source[idx].file, linenum);
			break;
		}

		if (file_line_is_skipable(line))
			continue;

		if (GIP_IPV4 == idx)
			gip_parse_ipv4(line, linenum);
		else
			gip_parse_ipv6(line, linenum);

	}

	iprange_sync(geo_db);

	if (GNET_PROPERTY(reload_debug)) {
		if (GIP_IPV4 == idx) {
			g_debug("loaded %u geographical IPv4 ranges (%u hosts)",
				iprange_get_item_count4(geo_db),
				iprange_get_host_count4(geo_db));
		} else {
			g_debug("loaded %u geographical IPv6 ranges",
				iprange_get_item_count6(geo_db));
		}
	}

	return GIP_IPV4 == idx ?
		iprange_get_item_count4(geo_db) : iprange_get_item_count6(geo_db);
}

/**
 * Watcher callback, invoked when the file from which we read the
 * geographic IP mappings changed.
 */
static void
gip_changed(const char *filename, void *idx_ptr)
{
	FILE *f;
	char buf[80];
	uint count;
	unsigned idx = pointer_to_uint(idx_ptr);

	f = file_fopen(filename, "r");
	if (f == NULL)
		return;

	count = gip_load(f, idx);
	fclose(f);

	str_bprintf(buf, sizeof buf, "Reloaded %u geographic IPv%c ranges.",
		count, GIP_IPV4 == idx ? '4' : '6');

	gcu_statusbar_message(buf);
}

/**
 * Loads the geo-ip.txt into memory.
 *
 * Choosing the first file we find among the several places we look at,
 * typically:
 *
 *		-# ~/.gtk-gnutella/geo-ip.txt
 *		-# /usr/share/gtk-gnutella/geo-ip.txt
 *		-# /home/src/gtk-gnutella/geo-ip.txt
 *
 * The selected file will then be monitored and a reloading will occur
 * shortly after a modification.
 */
static void
gip_retrieve(unsigned n)
{
	FILE *f;
	int idx;
	char *filename;
	file_path_t fp[4];
	unsigned length;

	length = settings_file_path_load(fp, gip_source[n].file, SFP_DFLT);

	g_assert(length <= G_N_ELEMENTS(fp));

	f = file_config_open_read_norename_chosen(
			gip_source[n].what, fp, length, &idx);

	if (NULL == f)
	   return;

	filename = make_pathname(fp[idx].dir, fp[idx].name);
	watcher_register(filename, gip_changed, uint_to_pointer(n));
	HFREE_NULL(filename);

	gip_load(f, n);
	fclose(f);
}

/**
 * Called on startup. Loads the geo-ip.txt file into memory.
 */
void
gip_init(void)
{
	geo_db = iprange_new();

	gip_retrieve(GIP_IPV4);
	gip_retrieve(GIP_IPV6);
}

/**
 * Frees all entries in the hostiles
 */
void
gip_close(void)
{
	iprange_free(&geo_db);
}

/**
 * Retrieves the country an address is assigned to.
 *
 * @param ha the host address to look up.
 * @return the country mapped to this IP address as a numerically-encoded
 *         country code, or ISO3166_INVALID when unknown.
 */
uint16
gip_country(const host_addr_t ha)
{
	uint16 code;

	if G_UNLIKELY(NULL == geo_db)
		return ISO3166_INVALID;
		
	code = iprange_get_addr(geo_db, ha);

	return 0 == code ? ISO3166_INVALID : (code >> 1) - 1;
}

/**
 * Same as gip_country() only returns ISO3166_INVALID if the geo_ip file
 * is too ancient: the risk of having a wrong mapping is too high.
 */
uint16
gip_country_safe(const host_addr_t ha)
{
	/* We allow them to be ~6 months behind */

	if (
		delta_time(tm_time(), gip_source[GIP_IPV4].mtime) > 15552000 ||
		delta_time(tm_time(), gip_source[GIP_IPV6].mtime) > 15552000
	)
		return ISO3166_INVALID;

	return gip_country(ha);
}

/**
 * Convenience routine to return the full contry name of an address.
 */
const char *
gip_country_name(const host_addr_t ha)
{
	return iso3166_country_name(gip_country(ha));
}

/**
 * Convenience routine to return the contry code of an address.
 */
const char *
gip_country_cc(const host_addr_t ha)
{
	return iso3166_country_cc(gip_country(ha));
}

/* vi: set ts=4 sw=4 cindent: */
