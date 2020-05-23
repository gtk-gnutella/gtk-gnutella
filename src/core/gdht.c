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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "lib/hikset.h"
#include "lib/sha1.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define MAX_PROXIES		32		/**< Max push-proxies we collect from a PROX */

/**
 * Hash table holding all the pending lookups by KUID.
 */
static hikset_t *sha1_lookups;	/* KUID -> struct sha1_lookup * */
static hikset_t *guid_lookups;	/* KUID -> struct guid_lookup * */

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
	uint16 port;			/**< Servent's port */
	unsigned nope:1;		/**< Was looking for a NOPE instead of a PROX */
};

static inline void
guid_lookup_check(const struct guid_lookup *glk)
{
	g_assert(glk);
	g_assert(GUID_LOOKUP_MAGIC == glk->magic);
}

static void gdht_guid_found(const kuid_t *kuid,
	const lookup_val_rs_t *rs, void *arg);

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
	struct sha1 digest;

	SHA1_COMPUTE(guid->v, &digest);

	return kuid_get_atom((const kuid_t *) &digest);
}

/**
 * Is IP:port pointing back at us?
 */
static bool
gdht_is_our_ip_port(const host_addr_t addr, uint16 port)
{
	return is_my_address_and_port(addr, port) ||
		local_addr_cache_lookup(addr, port);
}

/**
 * Was result published by ourselves
 */
static bool
gdht_published_by_ourselves(const lookup_val_rc_t *rc)
{
	return gdht_is_our_ip_port(rc->addr, rc->port);
}

/**
 * Free SHA1 lookup context.
 */
static void
gdht_free_sha1_lookup(struct sha1_lookup *slk, bool do_remove)
{
	sha1_lookup_check(slk);

	if (do_remove)
		hikset_remove(sha1_lookups, slk->id);

	kuid_atom_free(slk->id);
	atom_guid_free(slk->fi_guid);
	WFREE(slk);
}

/**
 * Free GUID lookup context.
 */
static void
gdht_free_guid_lookup(struct guid_lookup *glk, bool do_remove)
{
	guid_lookup_check(glk);

	if (do_remove) {
		download_proxy_dht_lookup_done(glk->guid);
		hikset_remove(guid_lookups, glk->id);
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
	static char info[64];

	str_bprintf(ARYLEN(info), "DHT %s v%u.%u (%lu byte%s) [%s]",
		dht_value_type_to_string(rc->type), rc->major, rc->minor,
		(ulong) rc->length, plural(rc->length), vendor_to_string(rc->vcode));

	return info;
}

/**
 * Callback when SHA1 lookup is initiated.
 *
 * @return TRUE if OK, FALSE if lookup must be aborted.
 */
static bool
gdht_sha1_looking(const kuid_t *kuid, void *arg)
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
gdht_sha1_not_found(const kuid_t *kuid, lookup_error_t error, void *arg)
{
	struct sha1_lookup *slk = arg;
	fileinfo_t *fi;

	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	fi = file_info_by_guid(slk->fi_guid);	/* NULL if fileinfo was removed */
	if (fi != NULL) {
		bool launched;

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
	bool firewalled = FALSE;
	struct tth tth;
	bool has_tth = FALSE;
	guid_t guid;
	uint16 port = 0;
	bool tls = FALSE;
	filesize_t filesize = 0;
	filesize_t available = 0;
	uint32 flags = 0;
	char host[MAX_HOSTLEN];
	const char *hostname = NULL;
	bool has_valid_guid = FALSE;

	g_assert(DHT_VT_ALOC == rc->type);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		uint16 paylen;

		switch (e->ext_token) {
		case EXT_T_GGEP_client_id:
			if (GUID_RAW_SIZE == ext_paylen(e)) {
				memcpy(guid.v, ext_payload(e), GUID_RAW_SIZE);
				has_valid_guid = TRUE;
			}
			break;
		case EXT_T_GGEP_firewalled:
			if (1 == ext_paylen(e)) {
				uint8 fw = peek_u8(ext_payload(e));
				firewalled = fw != 0;
			}
			break;
		case EXT_T_GGEP_length:
			{
				uint64 fs;
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

				ret = ggept_hname_extract(e, ARYLEN(host));
				if (GGEP_OK == ret)
					hostname = host;
			}
			break;
		case EXT_T_GGEP_avail:		/* Length available (for partial file) */
			{
				uint64 fs;
				ggept_status_t ret;

				ret = ggept_filesize_extract(e, &fs);
				if (GGEP_OK == ret)
					available = 0 == fs ? 1 : fs;
				else
					available = 1;		/* Force "partial" status */
			}
			break;
		default:
			if (GNET_PROPERTY(ggep_debug) > 1 && e->ext_type == EXT_GGEP) {
				paylen = ext_paylen(e);
				g_warning("%s: unhandled GGEP \"%s\" (%d byte%s)",
					value_infostr(rc),
					ext_ggep_id_str(e), paylen, plural(paylen));
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
				"%sALOC is %u for %s%s",
				value_infostr(rc), rc->port,
				firewalled ? "firewalled " : "",
				port, available != 0 ? "partial " : "", fi->pathname);
	} else {
		port = rc->port;
	}

	/*
	 * Rule out invalid addresses if not firewalled.
	 */

	if (!firewalled && !host_is_valid(rc->addr, port)) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s%s: invalid IP:port",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname);
		goto cleanup;
	}

	/*
	 * Make sure firewalled servents list their GUID.
	 */

	if (firewalled && !has_valid_guid) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s%s: "
				"firewalled host, no GUID",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname);
		goto cleanup;
	}

	/*
	 * Discard hostile sources.
	 */

	if (hostiles_is_bad(rc->addr)) {
		if (GNET_PROPERTY(download_debug)) {
			hostiles_flags_t hflags = hostiles_check(rc->addr);
			g_warning("discarding %s from %s for %s%s: hostile IP (%s)",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname,
				hostiles_flags_to_string(hflags));
		}
		goto cleanup;
	}

	/*
	 * Rule out on GUID collision: alt-loc cannot bear our own GUID.
	 *
	 * This is done after checking for hostile sources of course since
	 * anything can happen with hostiles
	 */

	if (has_valid_guid && guid_eq(&guid, GNET_PROPERTY(servent_guid))) {
		has_valid_guid = FALSE;

		/*
		 * Make sure the server address is not ours, otherwise we don't count
		 * that as a GUID collision.
		 */

		if (!gdht_is_our_ip_port(rc->addr, port))
			gnet_stats_inc_general(GNR_OWN_GUID_COLLISIONS);

		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s%s: host bears our GUID",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname);
		goto cleanup;
	}

	/*
	 * Check that filesize matches, if any supplied and if known.
	 */

	if (filesize != 0 && fi->size != 0 && fi->size != filesize) {
		if (GNET_PROPERTY(download_debug))
			g_warning("discarding %s from %s for %s%s: "
				"we have size=%s, ALOC says %s",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname,
				filesize_to_string(fi->size), filesize_to_string2(filesize));
		goto cleanup;
	}

	/**
	 * Check the TTH root if we have one.
	 */

	if (has_tth && fi->tth && !tth_eq(&tth, fi->tth)) {
		if (GNET_PROPERTY(download_debug)) {
			char buf[TTH_BASE32_SIZE + 1];

			base32_encode(ARYLEN(buf), ARYLEN(tth.data));

			g_warning("discarding %s from %s for %s%s: "
				"we have TTH root %s, ALOC says %s",
				value_infostr(rc), host_addr_port_to_string(rc->addr, port),
				available != 0 ? "partial " : "", fi->pathname,
				tth_base32(fi->tth), buf);
		}
		goto cleanup;
	}

	/*
	 * Create a new download.
	 */

	if (GNET_PROPERTY(download_debug) > 1)
		g_debug("adding %s%s%ssource %s (GUID %s) from DHT ALOC for %s",
			firewalled ? "firewalled " : "", tls ? "TLS " : "",
			available != 0 ? "partial " : "",
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
		deconstify_pointer(fi),
		flags);

	/* FALL THROUGH */

cleanup:
	/*
	 * Regardless of whether this ALOC matches the file we queried originally
	 * we can flag the server as publishing in the DHT.
	 */

	if (has_valid_guid) {
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
gdht_sha1_found(const kuid_t *kuid, const lookup_val_rs_t *rs, void *arg)
{
	struct sha1_lookup *slk = arg;
	fileinfo_t *fi;
	size_t i;
	bool seen_foreign = FALSE;

	g_assert(rs);
	sha1_lookup_check(slk);
	g_assert(slk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1)
		g_debug("DHT ALOC lookup for %s returned %zu value%s",
			kuid_to_string(kuid), rs->count, plural(rs->count));

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
		if (gdht_published_by_ourselves(rc))
			continue;
		seen_foreign = TRUE;		/* ALOC not published by ourselves */
		gdht_handle_aloc(rc, fi);
	}

	/*
	 * Since we can publish partial SHA-1 ourselves, we can only count
	 * a success when we had one entry not published by ourselves.
	 */

	if (seen_foreign) {
		gnet_stats_inc_general(GNR_DHT_SUCCESSFUL_ALT_LOC_LOOKUPS);
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

	if (hikset_contains(sha1_lookups, slk->id)) {
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

	hikset_insert_key(sha1_lookups, &slk->id);
	file_info_dht_query_queued(fi);

	ulq_find_value(slk->id, DHT_VT_ALOC,
		gdht_sha1_found, gdht_sha1_looking, gdht_sha1_not_found, slk);
}

/**
 * Callback when GUID lookup is unsuccessful.
 */
static void
gdht_guid_not_found(const kuid_t *kuid, lookup_error_t error, void *arg)
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
	uint16 port = 0;
	gnet_host_t proxies[MAX_PROXIES];
	int proxy_count = 0;

	g_assert(DHT_VT_PROX == rc->type);
	guid_lookup_check(glk);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		uint16 paylen;

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
					UNSIGNED(proxy_count) < N_ITEMS(proxies)
				) {
					host_addr_t a;
					uint16 p;
					uint8 len;

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

					if (hostiles_is_bad(a)) {
						if (GNET_PROPERTY(download_debug)) {
							hostiles_flags_t flags = hostiles_check(a);
							g_warning("discarding proxy %s in %s from %s "
								"for GUID %s: hostile IP (%s)",
								host_addr_port_to_string(a, p),
								value_infostr(rc),
								host_addr_port_to_string2(rc->addr, rc->port),
								guid_to_string(glk->guid),
								hostiles_flags_to_string(flags));
						}
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
					ext_ggep_id_str(e), paylen, plural(paylen));
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

	if (!host_addr_equiv(glk->addr, rc->addr) || port != glk->port)
		download_found_server(glk->guid, rc->addr, port);

	/*
	 * Create new push-proxies.
	 */

	if (GNET_PROPERTY(download_debug) > 0)
		g_debug("adding %d push-prox%s (GUID %s) from DHT PROX for %s (%s)",
			proxy_count, plural_y(proxy_count),
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
	uint16 port = 0;

	g_assert(DHT_VT_NOPE == rc->type);
	guid_lookup_check(glk);

	ext_prepare(exv, MAX_EXTVEC);
	ZERO(&guid.v);

	exvcnt = ext_parse(rc->data, rc->length, exv, MAX_EXTVEC);

	for (i = 0; i < exvcnt; i++) {
		extvec_t *e = &exv[i];
		uint16 paylen;

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
					ext_ggep_id_str(e), paylen, plural(paylen));
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
		g_debug("adding %s [%s] (NOPE creator) as push-proxy for %s (%s)",
			host_addr_port_to_string(rc->addr, port),
			vendor_to_string(rc->vcode), guid_to_string(glk->guid),
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
gdht_guid_found(const kuid_t *kuid, const lookup_val_rs_t *rs, void *arg)
{
	struct guid_lookup *glk = arg;
	size_t i;
	bool prox = FALSE;
	bool nope = FALSE;
	size_t other = 0;

	g_assert(rs);
	guid_lookup_check(glk);
	g_assert(glk->id == kuid);		/* They are atoms */

	if (GNET_PROPERTY(dht_lookup_debug) > 1) {
		g_debug("DHT PROX lookup for GUID %s returned %zu value%s",
			guid_to_string(glk->guid), rs->count, plural(rs->count));
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
		if (gdht_published_by_ourselves(rc))
			continue;
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
		g_debug("DHT PROX %s lookup for GUID %s returned %zu other value%s",
			(prox || nope) ? "successful" : "failed",
			guid_to_string(glk->guid), other, plural(other));
	}

	if (other > 0) {
		/* Was looking for SHA1(GUID), found some other SHA1 */
		gnet_stats_inc_general(GNR_DHT_SHA1_DATA_TYPE_COLLISIONS);
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

	gnet_stats_inc_general(nope ?
		GNR_DHT_SUCCESSFUL_NODE_PUSH_ENTRY_LOOKUPS :
		GNR_DHT_SUCCESSFUL_PUSH_PROXY_LOOKUPS);

	gdht_free_guid_lookup(glk, TRUE);
}

/**
 * Launch a GUID lookup in the DHT to collect push proxies for a server.
 */
void
gdht_find_guid(const guid_t *guid, const host_addr_t addr, uint16 port)
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

	if (hikset_contains(guid_lookups, glk->id)) {
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

	hikset_insert_key(guid_lookups, &glk->id);

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
	sha1_lookups = hikset_create(
		offsetof(struct sha1_lookup, id), HASH_KEY_FIXED, KUID_RAW_SIZE);
	guid_lookups = hikset_create(
		offsetof(struct guid_lookup, id), HASH_KEY_FIXED, KUID_RAW_SIZE);
}

/**
 * Hash table iterator to free a struct sha1_lookup
 */
static void
free_sha1_lookups_kv(void *val, void *unused_x)
{
	struct sha1_lookup *slk = val;

	(void) unused_x;

	gdht_free_sha1_lookup(slk, FALSE);
}

/**
 * Hash table iterator to free a struct guid_lookup
 */
static void
free_guid_lookups_kv(void *val, void *unused_x)
{
	struct guid_lookup *glk = val;

	(void) unused_x;

	gdht_free_guid_lookup(glk, FALSE);
}

/**
 * Shutdown the Gnutella DHT layer.
 */
void
gdht_close(void)
{
	hikset_foreach(sha1_lookups, free_sha1_lookups_kv, NULL);
	hikset_free_null(&sha1_lookups);

	hikset_foreach(guid_lookups, free_guid_lookups_kv, NULL);
	hikset_free_null(&guid_lookups);
}

/* vi: set ts=4 sw=4 cindent: */
