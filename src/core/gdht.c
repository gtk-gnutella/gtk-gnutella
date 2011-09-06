/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * Gnutella DHT "get" interface.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "gdht.h"
#include "fileinfo.h"
#include "extensions.h"
#include "ggep_type.h"
#include "hosts.h"
#include "hostiles.h"
#include "downloads.h"
#include "gnet_stats.h"
#include "settings.h"
#include "ipp_cache.h"

#include "if/core/guid.h"
#include "if/dht/lookup.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/bstr.h"
#include "lib/endian.h"
#include "lib/glib-missing.h"
#include "lib/sha1.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_PROXIES		32		/**< Max push-proxies we collect from a PROX */

/**
 * Hash table holding all the pending lookups by KUID.
 */
static GHashTable *sha1_lookups;	/* KUID -> struct sha1_lookup * */
static GHashTable *guid_lookups;	/* KUID -> struct guid_lookup * */

typedef enum {
	SHA1_LOOKUP_MAGIC = 0x5fd660bfU
} slk_magic_t;

/**
 * Context for SHA1 ALOC lookups.
 *
 * The fi_guid field is a unique fileinfo identifier from which we can
 * safely retrieve the fileinfo, if still present.
 */
struct sha1_lookup {
	slk_magic_t magic;
	const kuid_t *id;		/**< ID being looked for (atom) */
	const guid_t *fi_guid;	/**< GUID of the fileinfo being searched (atom) */
};

static inline void
sha1_lookup_check(const struct sha1_lookup *slk)
{
	g_assert(slk);
	g_assert(SHA1_LOOKUP_MAGIC == slk->magic);
}

typedef enum {
	GUID_LOOKUP_MAGIC = 0x465531c7U
} glk_magic_t;

/**
 * Context for PROX / NOPE lookups.
 */
struct guid_lookup {
	glk_magic_t magic;
	const kuid_t *id;		/**< ID being looked for (atom) */
	const guid_t *guid;		/**< Servent's GUID (atom) */
	host_addr_t addr;		/**< Servent's address */
	guint16 port;			/**< Servent's port */
	unsigned nope:1;		/**< Was looking for a NOPE instead of a PROX */
};

static inline void
guid_lookup_check(const struct guid_lookup *glk)
{
	g_assert(glk);
	g_assert(GUID_LOOKUP_MAGIC == glk->magic);
}

static void gdht_guid_found(const kuid_t *kuid,
	const lookup_val_rs_t *rs, gpointer arg);

/**
 * Convert a SHA1 to the proper Kademlia key for lookups.
 *
 * @return KUID atom for SHA1 lookup: KUID = SHA1.
 */
const kuid_t *
gdht_kuid_from_sha1(const sha1_t *sha1)
{
	return kuid_get_atom((const kuid_t *) sha1);	/* Identity */
}

/**
 * Convert a GUID to the proper Kademlia key for lookups.
 *
 * @return KUID atom for GUID lookup: KUID = SHA1(GUID).
 */
const kuid_t *
gdht_kuid_from_guid(const guid_t *guid)
{
	SHA1Context ctx;
	struct sha1 digest;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, guid->v, GUID_RAW_SIZE);
	SHA1Result(&ctx, &digest);

	return kuid_get_atom((const kuid_t *) &digest);
}

/**
 * Free SHA1 lookup context.
 */
static void
gdht_free_sha1_lookup(struct sha1_lookup *slk, gboolean do_remove)
{
	sha1_lookup_check(slk);

	if (do_remove)
		g_hash_table_remove(sha1_lookups, slk->id);

	kuid_atom_free(slk->id);
	atom_guid_free(slk->fi_guid);
	WFREE(slk);
}

/**
 * Free GUID lookup context.
 */
static void
gdht_free_guid_lookup(struct guid_lookup *glk, gboolean do_remove)
{
	guid_lookup_check(glk);

	if (do_remove) {
		download_proxy_dht_lookup_done(glk->guid);
		g_hash_table_remove(guid_lookups, glk->id);
	}

	kuid_atom_free(glk->id);
	atom_guid_free(glk->guid);
	WFREE(glk);
}

/*
 * Get human-readable DHT value type and version.
 * @return pointer to static data
 */
static const char *
value_infostr(const lookup_val_rc_t *rc)
{
	static char info[60];

	gm_snprintf(info, sizeof info, "DHT %s v%u.%u (%lu byte%s)",
		dht_value_type_to_string(rc->type), rc->major, rc->minor,
		(gulong) rc->length, 1 == rc->length ? "" : "s");

	return info;
}

/**
 * Callback when SHA1 lookup is initiated.
 *
 * @return TRUE if OK, FALSE if lookup must be aborted.
 */
static gboolean
gdht_sha1_looking(const kuid_t *kuid, gpointer arg)
{
	struct sha1_lookup *slk = arg;
	fileinfo_t *fi;

	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	fi = file_info_by_guid(slk->fi_guid);	/* NULL if fileinfo was removed */
	if (fi != NULL) {
		return file_info_dht_query_starting(fi);
	} else {
		return FALSE;		/* No need to query */
	}
}

/**
 * Callback when SHA1 lookup is unsuccessful.
 */
static void
gdht_sha1_not_found(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct sha1_lookup *slk = arg;
	fileinfo_t *fi;

	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	fi = file_info_by_guid(slk->fi_guid);	/* NULL if fileinfo was removed */
	if (fi != NULL) {
		gboolean launched;

		switch (error) {
		case LOOKUP_E_CANCELLED:
		case LOOKUP_E_EMPTY_ROUTE:
			launched = FALSE;
			break;
		default:
			launched = TRUE;
			break;
		}

		file_info_dht_query_completed(fi, launched, FALSE);
	}

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT ALOC lookup for %s failed: %s",
			kuid_to_string(kuid), lookup_strerror(error));

	gdht_free_sha1_lookup(slk, TRUE);
}

/**
 * Handle DHT ALOC value received to generate a new alt-loc source for
 * the file.
 */
static void
gdht_handle_aloc(const lookup_val_rc_t *rc, const fileinfo_t *fi)
{
	extvec_t exv[MAX_EXTVEC];
	int exvcnt;
	int i;
	gboolean firewalled = FALSE;
	struct tth tth;
	gboolean has_tth = FALSE;
	guid_t guid;
	guint16 port = 0;
	gboolean tls = FALSE;
	filesize_t filesize = 0;
	guint32 flags = 0;
	char host[MAX_HOSTLEN];
	const char *hostname = NULL;

	g_assert(DHT_VT_ALOC == rc->type);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		guint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_client_id:
			if (GUID_RAW_SIZE == ext_paylen(e))
				memcpy(guid.v, ext_payload(e), GUID_RAW_SIZE);
			break;
		case EXT_T_GGEP_firewalled:
			if (1 == ext_paylen(e)) {
				guint8 fw = peek_u8(ext_payload(e));
				firewalled = fw != 0;
			}
			break;
		case EXT_T_GGEP_length:
			{
				guint64 fs;
				ggept_status_t ret;

				ret = ggept_filesize_extract(e, &fs);
				if (GGEP_OK == ret)
					filesize = fs;
			}
			break;
		case EXT_T_GGEP_port:
			if (2 == ext_paylen(e))
				port = peek_be16(ext_payload(e));
			break;
		case EXT_T_GGEP_tls:
			tls = TRUE;
			break;
		case EXT_T_GGEP_ttroot:
			if (sizeof(tth.data) == ext_paylen(e)) {
				memcpy(tth.data, ext_payload(e), sizeof(tth.data));
				has_tth = TRUE;
			}
			break;
		case EXT_T_GGEP_HNAME:		/* GTKG-added key to ALOCs */
			{
				ggept_status_t ret;

				ret = ggept_hname_extract(e, host, sizeof host);
				if (GGEP_OK == ret)
					hostname = host;
			}
			break;
		case EXT_T_GGEP_avail:		/* Length available (for partial file) */
			/* FIXME - handle it */
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					value_infostr(rc),
					ext_ggep_id_str(e), paylen, paylen == 1 ? "" : "s");
			}
			break;
		}
	}

	/*
	 * Check servent's port, if specified.  It should match that of the
	 * creator.  If not, warn, but trust what is in the ALOC.
	 */

	if (port) {
		if (port != rc->port && GNET_PROPERTY(download_debug))
			g_warning("%s: port mismatch: creator's was %u, "
				"%sALOC is %u for %s",
				value_infostr(rc), rc->port,
				firewalled ? "firewalled " : "",
				port, fi->pathname);
	} else {
		port = rc->port;
	}

	/*
	 * Rule out invalid addresses if not firewalled.
	 */

	if (!firewalled && !host_is_valid(rc->addr, port)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s: invalid IP:port",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname);
		goto cleanup;
	}

	/*
	 * Discard hostile sources.
	 */

	if (hostiles_check(rc->addr)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s: hostile IP",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname);
		goto cleanup;
	}

	/*
	 * Check that filesize matches, if any supplied and if known.
	 */

	if (filesize != 0 && fi->size != 0 && fi->size != filesize) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s: "
				"we have size=%lu, ALOC says %lu",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname, (gulong) fi->size, (gulong) filesize);
		goto cleanup;
	}

	/**
	 * Check the TTH root if we have one.
	 */

	if (has_tth && fi->tth && !tth_eq(&tth, fi->tth)) {
		if (GNET_PROPERTY(download_debug)) {
			char buf[TTH_BASE32_SIZE + 1];

			base32_encode(buf, sizeof buf, tth.data, sizeof tth.data);

			g_warning("discarding %s from %s for %s: "
				"we have TTH root %s, ALOC says %s",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname, tth_base32(fi->tth), buf);
		}
		goto cleanup;
	}

	/*
	 * Create a new download.
	 */

	if (GNET_PROPERTY(download_debug) > 1)
		g_debug("adding %s%ssource %s (GUID %s) from DHT ALOC for %s",
			firewalled ? "firewalled " : "", tls ? "TLS " : "",
			host_addr_port_to_string(rc->addr, port),
			guid_to_string(&guid), fi->pathname);

	if (firewalled)
		flags |= SOCK_F_PUSH;
	else if (tls)
		flags |= SOCK_F_TLS;

	download_dht_auto_new(filepath_basename(fi->pathname),
		fi->size != 0 ? fi->size : filesize,
		hostname, rc->addr, port,
		&guid,
		fi->sha1,
		has_tth ? &tth : NULL,
		tm_time(),
		deconstify_gpointer(fi),
		flags);

	/* FALL THROUGH */

cleanup:
	/*
	 * Regardless of whether this ALOC matches the file we queried originally
	 * we can flag the server as publishing in the DHT.
	 */

	if (!guid_is_blank(&guid)) {
		download_server_publishes_in_dht(&guid);
	}
	if (exvcnt) {
		ext_reset(exv, MAX_EXTVEC);
	}
}

/**
 * Callback when SHA1 lookup is successful.
 */
static void
gdht_sha1_found(const kuid_t *kuid, const lookup_val_rs_t *rs, gpointer arg)
{
	struct sha1_lookup *slk = arg;
	fileinfo_t *fi;
	size_t i;
	gboolean seen_foreign = FALSE;

	g_assert(rs);
	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT ALOC lookup for %s returned %lu value%s",
			kuid_to_string(kuid), (gulong) rs->count,
			1 == rs->count ? "" : "s");

	fi = file_info_by_guid(slk->fi_guid);

	if (NULL == fi) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("fileinfo for %s was removed whilst looking for ALOC",
				kuid_to_string(kuid));
		goto cleanup;
	}

	/*
	 * Parse ALOC results.
	 *
	 * The lookup code is supposed to have filtered out non-ALOC results
	 * since we explicitly demanded this type of results.  Hence warn if
	 * we get something else.
	 */

	for (i = 0; i < rs->count; i++) {
		lookup_val_rc_t *rc = &rs->records[i];
		if (is_my_address_and_port(rc->addr, rc->port))
			continue;
		if (local_addr_cache_lookup(rc->addr, rc->port))
			continue;
		seen_foreign = TRUE;		/* ALOC not published by ourselves */
		gdht_handle_aloc(rc, fi);
	}

	/*
	 * Since we can publish partial SHA-1 ourselves, we can only count
	 * a success when we had one entry not published by ourselves.
	 */

	if (seen_foreign) {
		gnet_stats_count_general(GNR_DHT_SUCCESSFUL_ALT_LOC_LOOKUPS, 1);
	}

	file_info_dht_query_completed(fi, TRUE, seen_foreign);

cleanup:
	gdht_free_sha1_lookup(slk, TRUE);
}

/**
 * Launch a SHA1 lookup in the DHT to collect alternate locations.
 */
void
gdht_find_sha1(fileinfo_t *fi)
{
	struct sha1_lookup *slk;

	file_info_check(fi);
	g_assert(fi->sha1);

	WALLOC(slk);
	slk->magic = SHA1_LOOKUP_MAGIC;
	slk->id = gdht_kuid_from_sha1(fi->sha1);
	slk->fi_guid = atom_guid_get(fi->guid);

	/*
	 * If we have so many queued searches that we did not manage to get
	 * a previous one completed before it is re-attempted, ignore the new
	 * request.
	 */

	if (g_hash_table_lookup(sha1_lookups, slk->id)) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT already has pending search for %s (%s) for %s",
				kuid_to_hex_string(slk->id),
				kuid_to_string(slk->id), fi->pathname);

		gdht_free_sha1_lookup(slk, FALSE);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug))
		g_debug("DHT will be searching ALOC for %s (%s) for %s",
			kuid_to_hex_string(slk->id), kuid_to_string(slk->id), fi->pathname);

	gm_hash_table_insert_const(sha1_lookups, slk->id, slk);
	file_info_dht_query_queued(fi);

	ulq_find_value(slk->id, DHT_VT_ALOC, 
		gdht_sha1_found, gdht_sha1_looking, gdht_sha1_not_found, slk);
}

/**
 * Callback when GUID lookup is unsuccessful.
 */
static void
gdht_guid_not_found(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct guid_lookup *glk = arg;

	guid_lookup_check(glk);
	g_assert(glk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT PROX lookup for GUID %s failed: %s",
			guid_to_string(glk->guid), lookup_strerror(error));

	gdht_free_guid_lookup(glk, TRUE);
}

/**
 * Handle DHT PROX value received to generate a new push-proxy for the servent.
 */
static void
gdht_handle_prox(const lookup_val_rc_t *rc, struct guid_lookup *glk)
{
	extvec_t exv[MAX_EXTVEC];
	int exvcnt;
	int i;
	guid_t guid;
	guint16 port = 0;
	gnet_host_t proxies[MAX_PROXIES];
	int proxy_count = 0;

	g_assert(DHT_VT_PROX == rc->type);
	guid_lookup_check(glk);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		guint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_client_id:
			if (GUID_RAW_SIZE == ext_paylen(e))
				memcpy(guid.v, ext_payload(e), GUID_RAW_SIZE);
			break;
		case EXT_T_GGEP_features:
			/* Could not figure out the field's format -- RAM, 2008-09-01 */
			break;
		case EXT_T_GGEP_port:
			if (2 == ext_paylen(e))
				port = peek_be16(ext_payload(e));
			break;
		case EXT_T_GGEP_tls:
			/* Could not figure out the field's format -- RAM, 2008-09-01 */
			break;
		case EXT_T_GGEP_fwt_version:
			/* Not needed yet as we don't support RUDP -- RAM, 2008-09-01 */
			break;
		case EXT_T_GGEP_proxies:
			{
				bstr_t *bs = bstr_open(ext_payload(e), ext_paylen(e), 0);

				/*
				 * Reverse engineered host format is the following:
				 *
				 * . 1 byte gives the length of IP + port (6 or 18).
				 * . IP and port in big endian follow.
				 */

				while (
					bstr_unread_size(bs) > 0 &&
					UNSIGNED(proxy_count) < G_N_ELEMENTS(proxies)
				) {
					host_addr_t a;
					guint16 p;
					guint8 len;

					if (!bstr_read_u8(bs, &len))
						break;

					if (6 == len) {
						if (!bstr_read_ipv4_addr(bs, &a))
							break;
					} else if (18 == len) {
						if (!bstr_read_ipv6_addr(bs, &a))
							break;
					} else
						break;

					if (!bstr_read_be16(bs, &p))
						break;

					/*
					 * Discard hostile sources.
					 */

					if (hostiles_check(a)) {
						if (GNET_PROPERTY(download_debug))
							g_warning("discarding proxy %s in %s from %s "
								"for GUID %s: hostile IP",
								host_addr_port_to_string(a, p),
								value_infostr(rc),
								host_addr_port_to_string2(rc->addr, rc->port),
								guid_to_string(glk->guid));
						continue;
					} else {
						if (GNET_PROPERTY(download_debug))
							g_debug("new push-proxy for %s is at %s",
								guid_to_string(glk->guid),
								host_addr_port_to_string(a, p));
					}

					gnet_host_set(&proxies[proxy_count++], a, p);
				}

				bstr_free(&bs);
			}
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					value_infostr(rc),
					ext_ggep_id_str(e), paylen, paylen == 1 ? "" : "s");
			}
			break;
		}
	}

	/*
	 * If there is a SHA1 conflict, reject the PROX.
	 */

	if (!guid_eq(glk->guid, &guid)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for GUID %s: PROX was for GUID %s",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				guid_to_string(glk->guid), guid_hex_str(&guid));
		goto cleanup;
	}

	/*
	 * If we did not find any proxy, reject the PROX.
	 */

	if (0 == proxy_count) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for GUID %s: no proxies found",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				guid_to_string(glk->guid));
		goto cleanup;
	}

	/*
	 * Check servent's port, if specified.  It should match that of the
	 * creator.  If not, warn, but trust what is in the PROX.
	 */

	if (port) {
		if (port != rc->port && GNET_PROPERTY(download_debug))
			g_warning("%s: port mismatch: creator's was %u, "
				"PROX is %u for %s, known as %s here",
				value_infostr(rc), rc->port,
				port, host_addr_to_string(rc->addr),
				host_addr_port_to_string(glk->addr, glk->port));
	} else {
		port = rc->port;
	}

	/*
	 * If host address is not matching, we're getting push-proxy information
	 * for another host, which can mean the host has changed its address
	 * since we last heard about it.
	 */

	if (!host_addr_equal(glk->addr, rc->addr) || port != glk->port)
		download_found_server(glk->guid, rc->addr, port);

	/*
	 * Create new push-proxies.
	 */

	if (GNET_PROPERTY(download_debug) > 0)
		g_debug("adding %d push-prox%s (GUID %s) from DHT PROX for %s (%s)",
			proxy_count, 1 == proxy_count ? "y" : "ies",
			guid_to_string(glk->guid),
			host_addr_port_to_string(rc->addr, port),
			host_addr_port_to_string(glk->addr, glk->port));

	download_server_publishes_in_dht(glk->guid);
	download_add_push_proxies(glk->guid, proxies, proxy_count);

	/* FALL THROUGH */

cleanup:
	if (exvcnt)
		ext_reset(exv, MAX_EXTVEC);
}

/**
 * Handle DHT NOPE value received to generate a new push-proxy for the servent.
 */
static void
gdht_handle_nope(const lookup_val_rc_t *rc, struct guid_lookup *glk)
{
	extvec_t exv[MAX_EXTVEC];
	int exvcnt;
	int i;
	guid_t guid;
	guint16 port = 0;

	g_assert(DHT_VT_NOPE == rc->type);
	guid_lookup_check(glk);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		guint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_guid:
			if (GUID_RAW_SIZE == ext_paylen(e))
				memcpy(guid.v, ext_payload(e), GUID_RAW_SIZE);
			break;
		case EXT_T_GGEP_port:
			if (2 == ext_paylen(e))
				port = peek_be16(ext_payload(e));
			break;
		case EXT_T_GGEP_tls:
			/* We don't handle TLS support indication yet -- RAM, 2010-02-27 */
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					value_infostr(rc),
					ext_ggep_id_str(e), paylen, paylen == 1 ? "" : "s");
			}
			break;
		}
	}

	/*
	 * If there is a DHT key conflict, reject the NOPE.
	 */

	if (!guid_eq(glk->guid, &guid)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for GUID %s: NOPE was for GUID %s",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				guid_to_string(glk->guid), guid_hex_str(&guid));
		goto cleanup;
	}

	/*
	 * Check servent's port, if specified.  It should match that of the
	 * creator.  If not, warn, but trust what is in the NOPE.
	 */

	if (port) {
		if (port != rc->port && GNET_PROPERTY(download_debug))
			g_warning("%s: port mismatch: creator's was %u, "
				"NOPE is %u for %s, known as %s here",
				value_infostr(rc), rc->port,
				port, host_addr_to_string(rc->addr),
				host_addr_port_to_string(glk->addr, glk->port));
	} else {
		port = rc->port;
	}

	/*
	 * Create new push-proxies.
	 */

	if (GNET_PROPERTY(download_debug) > 0)
		g_debug("adding %s (NOPE creator) as push-proxy for %s (%s)",
			host_addr_port_to_string(rc->addr, port),
			guid_to_string(glk->guid),
			host_addr_port_to_string2(glk->addr, glk->port));

	download_add_push_proxy(glk->guid, rc->addr, port);

	/* FALL THROUGH */

cleanup:
	if (exvcnt)
		ext_reset(exv, MAX_EXTVEC);
}

/**
 * Callback when GUID lookup is successful (PROX or NOPE values).
 */
static void
gdht_guid_found(const kuid_t *kuid, const lookup_val_rs_t *rs, gpointer arg)
{
	struct guid_lookup *glk = arg;
	size_t i;
	gboolean prox = FALSE;
	gboolean nope = FALSE;
	size_t other = 0;

	g_assert(rs);
	guid_lookup_check(glk);
	g_assert(glk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT PROX lookup for GUID %s returned %lu value%s",
			guid_to_string(glk->guid), (gulong) rs->count,
			1 == rs->count ? "" : "s");
	}

	/*
	 * Parse PROX or NOPE results.
	 *
	 * We've been launching a generic lookup for any value.  If there is
	 * a SHA1 collision in the DHT, we may very well get ALOC results only,
	 * for instance.
	 */

	for (i = 0; i < rs->count; i++) {
		lookup_val_rc_t *rc = &rs->records[i];
		switch (rc->type) {
		case DHT_VT_PROX:
			prox = TRUE;
			gdht_handle_prox(rc, glk);
			break;
		case DHT_VT_NOPE:
			nope = TRUE;
			gdht_handle_nope(rc, glk);
			break;
		default:
			other++;
			break;
		}
	}

	if (GNET_PROPERTY(dht_lookup_debug)) {
		g_debug("DHT PROX %s lookup for GUID %s returned %lu other value%s",
			(prox || nope) ? "successful" : "failed",
			guid_to_string(glk->guid),
			(gulong) other, 1 == other ? "" : "s");
	}

	if (other > 0) {
		/* Was looking for SHA1(GUID), found some other SHA1 */
		gnet_stats_count_general(GNR_DHT_SHA1_DATA_TYPE_COLLISIONS, 1);
	}

	/*
	 * If we got only alien values (neither PROX nor NOPE), then act as if
	 * the lookup had failed, actually.
	 */

	if (!(prox || nope)) {
		gdht_guid_not_found(kuid, LOOKUP_E_NOT_FOUND, glk);
		return;
	}

	/* If we got at least one NOPE back, count a successful NOPE lookup */

	gnet_stats_count_general(
		nope ?
			GNR_DHT_SUCCESSFUL_NODE_PUSH_ENTRY_LOOKUPS :
			GNR_DHT_SUCCESSFUL_PUSH_PROXY_LOOKUPS,
		1);

	gdht_free_guid_lookup(glk, TRUE);
}

/**
 * Launch a GUID lookup in the DHT to collect push proxies for a server.
 */
void
gdht_find_guid(const guid_t *guid, const host_addr_t addr, guint16 port)
{
	struct guid_lookup *glk;

	g_assert(guid);
	g_assert(!guid_is_blank(guid));
	g_assert(host_addr_initialized(addr));

	WALLOC(glk);
	glk->magic = GUID_LOOKUP_MAGIC;
	glk->id = gdht_kuid_from_guid(guid);
	glk->guid = atom_guid_get(guid);
	glk->addr = addr;
	glk->port = port;

	/*
	 * If we have so many queued searches that we did not manage to get
	 * a previous one completed before it is re-attempted, ignore the new
	 * request.
	 */

	if (g_hash_table_lookup(guid_lookups, glk->id)) {
		if (GNET_PROPERTY(dht_lookup_debug))
			g_warning("DHT already has pending search for %s (GUID %s) for %s",
			kuid_to_hex_string(glk->id),
			guid_to_string(guid), host_addr_port_to_string(addr, port));

		gdht_free_guid_lookup(glk, FALSE);
		return;
	}

	if (GNET_PROPERTY(dht_lookup_debug))
		g_debug("DHT will be searching PROX for %s (GUID %s) for %s",
			kuid_to_hex_string(glk->id),
			guid_to_string(guid), host_addr_port_to_string(addr, port));

	gm_hash_table_insert_const(guid_lookups, glk->id, glk);

	/*
	 * We're looking for ANY value here, but we really expect PROX or NOPE
	 * values back.
	 *
	 * Compared to issuing a PROX lookup first followed by a NOPE lookup if
	 * we don't get result, we're more efficient but we run the risk of failing
	 * if, bad luck, the SHA1 of the GUID we're looking conflicts with the
	 * SHA1 of a shared file, and we'll be getting only ALOC values back.
	 *
	 * Still, the collision risk is low and lookups being rather costly,
	 * it's best to only issue one.  With time, NOPE publishing will become
	 * less frequent so we'll also better withstand evolution.
	 *		--RAM, 2010-02-28
	 */

	ulq_find_any_value(glk->id, DHT_VT_PROX,
		gdht_guid_found, gdht_guid_not_found, glk);
}

/**
 * Initialize the Gnutella DHT layer.
 */
void
gdht_init(void)
{
	sha1_lookups = g_hash_table_new(kuid_hash, kuid_eq);
	guid_lookups = g_hash_table_new(kuid_hash, kuid_eq);
}

/**
 * Hash table iterator to free a struct sha1_lookup
 */
static void
free_sha1_lookups_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	struct sha1_lookup *slk = val;

	(void) unused_key;
	(void) unused_x;

	gdht_free_sha1_lookup(slk, FALSE);
}

/**
 * Hash table iterator to free a struct guid_lookup
 */
static void
free_guid_lookups_kv(gpointer unused_key, gpointer val, gpointer unused_x)
{
	struct guid_lookup *glk = val;

	(void) unused_key;
	(void) unused_x;

	gdht_free_guid_lookup(glk, FALSE);
}

/**
 * Shutdown the Gnutella DHT layer.
 */
void
gdht_close(void)
{
	g_hash_table_foreach(sha1_lookups, free_sha1_lookups_kv, NULL);
	gm_hash_table_destroy_null(&sha1_lookups);

	g_hash_table_foreach(guid_lookups, free_guid_lookups_kv, NULL);
	gm_hash_table_destroy_null(&guid_lookups);
}

/* vi: set ts=4 sw=4 cindent: */
