/*
 * $Id$
 *
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
 * Gnutella DHT interface.
 *
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

RCSID("$Id$")

#include "gdht.h"
#include "fileinfo.h"
#include "extensions.h"
#include "ggep_type.h"
#include "hosts.h"
#include "hostiles.h"
#include "downloads.h"

#include "if/core/guid.h"
#include "if/dht/lookup.h"
#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/bstr.h"
#include "lib/endian.h"
#include "lib/sha1.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

#define MAX_PROXIES		8		/**< Max push-proxies we collect from a PROX */

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
	kuid_t *id;				/**< ID being looked for (atom) */
	guid_t *fi_guid;		/**< GUID of the fileinfo being searched (atom) */
};

static inline void
sha1_lookup_check(const struct sha1_lookup *slk)
{
	g_assert(slk);
	g_assert(SHA1_LOOKUP_MAGIC == slk->magic);
}

typedef enum {
	GUID_LOOKUP_MAGIC = 0xc65531c7U
} glk_magic_t;

/**
 * Context for PROX lookups.
 */
struct guid_lookup {
	glk_magic_t magic;
	kuid_t *id;				/**< ID being looked for (atom) */
	guid_t *guid;			/**< Servent's GUID (atom) */
	host_addr_t addr;		/**< Servent's address */
	guint16 port;			/**< Servent's port */
};

static inline void
guid_lookup_check(const struct guid_lookup *glk)
{
	g_assert(glk);
	g_assert(GUID_LOOKUP_MAGIC == glk->magic);
}

/**
 * Convert a SHA1 to the proper Kademlia key for lookups.
 *
 * @return KUID atom for SHA1 lookup: KUID = SHA1.
 */
static kuid_t *
kuid_from_sha1(const sha1_t *sha1)
{
	return kuid_get_atom((const kuid_t *) sha1);	/* Identity */
}

/**
 * Convert a GUID to the proper Kademlia key for lookups.
 *
 * @return KUID atom for GUID lookup: KUID = SHA1(GUID).
 */
static kuid_t *
kuid_from_guid(const char *guid)
{
	SHA1Context ctx;
	struct sha1 digest;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, guid, GUID_RAW_SIZE);
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
	atom_guid_free(slk->fi_guid->v);
	wfree(slk, sizeof *slk);
}

/**
 * Free GUID lookup context.
 */
static void
gdht_free_guid_lookup(struct guid_lookup *glk, gboolean do_remove)
{
	guid_lookup_check(glk);

	if (do_remove) {
		download_proxy_dht_lookup_done(glk->guid->v);
		g_hash_table_remove(guid_lookups, glk->id);
	}

	kuid_atom_free(glk->id);
	atom_guid_free(glk->guid->v);
	wfree(glk, sizeof *glk);
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
 * Callback when SHA1 lookup is unsuccessful.
 */
static void
gdht_sha1_not_found(const kuid_t *kuid, lookup_error_t error, gpointer arg)
{
	struct sha1_lookup *slk = arg;

	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT ALOC lookup for %s failed: %s",
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

	g_assert(DHT_VT_ALOC == rc->type);

	ext_prepare(exv, MAX_EXTVEC);
	memset(guid.v, 0, GUID_RAW_SIZE);

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
		return;
	}

	/*
	 * Discard hostile sources.
	 */

	if (hostiles_check(rc->addr)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s: hostile IP",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname);
		return;
	}

	/*
	 * Check that filesize matches.
	 */

	if (filesize && fi->size != filesize) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s: "
				"we have size=%lu, ALOC says %lu",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				fi->pathname, (gulong) fi->size, (gulong) filesize);
		return;
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
		return;
	}

	/*
	 * Create a new download.
	 */

	if (GNET_PROPERTY(download_debug) > 1)
		g_message("adding %s%ssource %s (GUID %s) from DHT ALOC for %s",
			firewalled ? "firewalled " : "", tls ? "TLS " : "",
			host_addr_port_to_string(rc->addr, port),
			guid_to_string(guid.v), fi->pathname);

	if (firewalled)
		flags |= SOCK_F_PUSH;
	else if (tls)
		flags |= SOCK_F_TLS;

	download_auto_new(filepath_basename(fi->pathname),
		fi->size,
		rc->addr, port,
		(char *) guid.v,
		NULL,					/* hostname */
		fi->sha1,
		has_tth ? &tth : NULL,
		tm_time(),
		deconstify_gpointer(fi),
		NULL,					/* proxies */
		flags);
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

	g_assert(rs);
	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT ALOC lookup for %s returned %lu value%s",
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
		gdht_handle_aloc(rc, fi);
	}

cleanup:
	lookup_free_value_results(rs);
	gdht_free_sha1_lookup(slk, TRUE);
}

/**
 * Launch a SHA1 lookup in the DHT to collect alternate locations.
 */
void
gdht_find_sha1(const fileinfo_t *fi)
{
	struct sha1_lookup *slk;

	file_info_check(fi);
	g_assert(fi->sha1);

	slk = walloc(sizeof *slk);
	slk->magic = SHA1_LOOKUP_MAGIC;
	slk->id = kuid_from_sha1(fi->sha1);
	slk->fi_guid = (guid_t *) atom_guid_get(fi->guid);

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
		g_message("DHT will be searching ALOC for %s (%s) for %s",
			kuid_to_hex_string(slk->id), kuid_to_string(slk->id), fi->pathname);

	g_hash_table_insert(sha1_lookups, slk->id, slk);
	ulq_find_value(slk->id, DHT_VT_ALOC, 
		gdht_sha1_found, gdht_sha1_not_found, slk);
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
		g_message("DHT PROX lookup for GUID %s failed: %s",
			guid_to_string(glk->guid->v), lookup_strerror(error));

	download_no_push_proxies(glk->guid->v);
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
	memset(guid.v, 0, GUID_RAW_SIZE);

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
								guid_to_string(glk->guid->v));
						continue;
					} else {
						if (GNET_PROPERTY(download_debug))
							g_message("new push-proxy for %s is at %s",
								guid_to_string(glk->guid->v),
								host_addr_port_to_string(a, p));
					}

					gnet_host_set(&proxies[proxy_count++], a, p);
				}

				bstr_close(bs);
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
	 * If we did not find any proxy, reject the PROX.
	 */

	if (0 == proxy_count) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for GUID %s: no proxies found",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				guid_to_string(glk->guid->v));
		return;
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
		download_found_server(glk->guid->v, rc->addr, port);

	/*
	 * Create new push-proxies.
	 */

	if (GNET_PROPERTY(download_debug) > 0)
		g_message("adding %d push-prox%s (GUID %s) from DHT PROX for %s (%s)",
			proxy_count, 1 == proxy_count ? "y" : "ies",
			guid_to_string(glk->guid->v),
			host_addr_port_to_string(rc->addr, port),
			host_addr_port_to_string(glk->addr, glk->port));

	download_add_push_proxies(glk->guid->v, proxies, proxy_count);
}

/**
 * Callback when GUID lookup is successful.
 */
static void
gdht_guid_found(const kuid_t *kuid, const lookup_val_rs_t *rs, gpointer arg)
{
	struct guid_lookup *glk = arg;
	size_t i;

	g_assert(rs);
	guid_lookup_check(glk);
	g_assert(glk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_message("DHT PROX lookup for GUID %s returned %lu value%s",
			guid_to_string(glk->guid->v), (gulong) rs->count,
			1 == rs->count ? "" : "s");

	/*
	 * Parse PROX results.
	 */

	for (i = 0; i < rs->count; i++) {
		lookup_val_rc_t *rc = &rs->records[i];
		gdht_handle_prox(rc, glk);
	}

	lookup_free_value_results(rs);
	gdht_free_guid_lookup(glk, TRUE);
}

/**
 * Launch a GUID lookup in the DHT to collect push proxies for a server.
 */
void
gdht_find_guid(const char *guid, const host_addr_t addr, guint16 port)
{
	struct guid_lookup *glk;

	g_assert(guid);
	g_assert(!guid_is_blank(guid));
	g_assert(host_addr_initialized(addr));

	glk = walloc(sizeof *glk);
	glk->magic = GUID_LOOKUP_MAGIC;
	glk->id = kuid_from_guid(guid);
	glk->guid = (guid_t *) atom_guid_get(guid);
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
		g_message("DHT will be searching PROX for %s (GUID %s) for %s",
			kuid_to_hex_string(glk->id),
			guid_to_string(guid), host_addr_port_to_string(addr, port));

	g_hash_table_insert(guid_lookups, glk->id, glk);
	ulq_find_value(glk->id, DHT_VT_PROX,
		gdht_guid_found, gdht_guid_not_found, glk);
}

/**
 * Initialize the Gnutella DHT layer.
 */
void
gdht_init(void)
{
	sha1_lookups = g_hash_table_new(sha1_hash, sha1_eq);
	guid_lookups = g_hash_table_new(sha1_hash, sha1_eq);
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
	g_hash_table_destroy(sha1_lookups);

	g_hash_table_foreach(guid_lookups, free_guid_lookups_kv, NULL);
	g_hash_table_destroy(guid_lookups);
}

/* vi: set ts=4 sw=4 cindent: */
