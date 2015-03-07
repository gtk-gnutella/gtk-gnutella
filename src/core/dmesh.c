/*
 * Copyright (c) 2002-2010, Raphael Manfredi
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
 * Download mesh.
 *
 * @author Raphael Manfredi
 * @date 2002-2010
 */

#include "common.h"

#include "gtk-gnutella.h"

#include "dmesh.h"
#include "ctl.h"
#include "downloads.h"
#include "fileinfo.h"
#include "gnutella.h"
#include "guid.h"
#include "hcache.h"
#include "hostiles.h"
#include "hosts.h"
#include "http.h"
#include "huge.h"
#include "ipp_cache.h"
#include "settings.h"
#include "share.h"
#include "tls_common.h"
#include "uploads.h"		/* For upload_is_enabled() */

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/concat.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/entropy.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/header.h"
#include "lib/hikset.h"
#include "lib/htable.h"
#include "lib/parse.h"
#include "lib/pslist.h"
#include "lib/shuffle.h"
#include "lib/str.h"
#include "lib/strtok.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/unsigned.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

dmesh_url_error_t dmesh_url_errno;	/**< Error from dmesh_url_parse() */

/**
 * The download mesh records all the known sources for a given SHA1.
 * It is implemented as a big hash table, where SHA1 are keys, each value
 * being a struct dmesh pointer.
 */
static hikset_t *mesh = NULL;

struct dmesh {				/**< A download mesh bucket */
	list_t *entries;		/**< The download mesh entries, dmesh_entry data */
	htable_t *by_host;		/**< Entries indexed by host (IP:port) */
	htable_t *by_guid;		/**< Entries indexed by GUID (firewalled entries) */
	time_t last_update;		/**< Timestamp of last insert/expire in the mesh */
	const sha1_t *sha1;		/**< The SHA1 of this mesh */
};

struct dmesh_entry {
	time_t inserted;		/**< When entry was inserted in mesh */
	time_t stamp;			/**< When entry was last seen */
	union {
		dmesh_urlinfo_t url;	/**< URL info */
		dmesh_fwinfo_t fwh;		/**< Firewalled host */
	} e;
	hash_list_t *bad;		/**< Keeps track of IPs reporting entry as bad */
	uint8 good;				/**< Whether marked as being a good entry */
	uint8 fw_entry;			/**< Whether entry is that of a firewalled host */
};

#define MAX_LIFETIME	43200		/**< half a day */
#define MAX_LIBLIFETIME	3600		/**< 1 hour for shared/seeded files */
#define MAX_ENTRIES		256			/**< Max amount of entries kept per SHA1 */

#define MIN_BAD_REPORT	3			/**< Don't ban before that many X-Nalt */
#define DMESH_CALLOUT	5000		/**< Callout heartbeat every 5 seconds */
#define DMESH_BAN_VETO	300			/**< 5 minutes, to keep banned entry */
#define EXPIRE_DELAY	600			/**< 10 minutes after last update */

#define FW_MAX_PROXIES	4			/**< At most 4 push-proxies */

static const char dmesh_file[] = "dmesh";
static cqueue_t *dmesh_cq;			/**< Download mesh callout queue */

/**
 * If we get a "bad" URL into the mesh ("bad" = gives 404 or other error when
 * trying to download it), we must remember it for some time and prevent it
 * from re-entering the mesh again within that period to prevent rescheduling
 * for download and a further failure: that would be hammering the poor host,
 * and we're wasting our time and bandwidth.
 *
 * Therefore, each time we get a "bad" URL, we insert it in a hash table.
 * The table entry is then scheduled to be removed after some grace period
 * occurs.  The table is keyed by the dmesh_urlinfo_t, and points to a
 * dmesh_banned structure.
 *
 * The table is persisted at regular intervals.
 */
static hikset_t *ban_mesh = NULL;

struct dmesh_banned {
	dmesh_urlinfo_t *info;	/**< The banned URL (same as key) */
	cevent_t *cq_ev;		/**< Scheduled callout event */
	const struct sha1 *sha1;/**< The SHA1, if any */
	time_t created;			/**< Last time we saw this banned URL */
};

typedef void (*dmesh_add_cb)(
	const struct sha1 *sha1, host_addr_t addr, uint16 port, void *udata);

/**
 * This table stores the banned entries by SHA1.
 */
static htable_t *ban_mesh_by_sha1 = NULL;

#define BAN_LIFETIME	7200		/**< 2 hours */

static const char dmesh_ban_file[] = "dmesh_ban";

static void dmesh_retrieve(void);
static void dmesh_ban_retrieve(void);
static char *dmesh_urlinfo_to_string(const dmesh_urlinfo_t *info);
static char *dmesh_fwinfo_to_string(const dmesh_fwinfo_t *info);

/**
 * Hash a URL info.
 */
static uint
urlinfo_hash(const void *key)
{
	const dmesh_urlinfo_t *info = key;
	uint hash;

	hash = host_addr_hash(info->addr);
	hash ^= port_hash(info->port);
	hash ^= integer_hash(info->idx);
	hash ^= string_mix_hash(info->name);

	return hash;
}

/**
 * Test equality of two URL infos.
 */
static int
urlinfo_eq(const void *a, const void *b)
{
	const dmesh_urlinfo_t *ia = a, *ib = b;

	return ia->port == ib->port &&
		ia->idx == ib->idx &&
		host_addr_equiv(ia->addr, ib->addr) &&
		(ia->name == ib->name || 0 == strcmp(ia->name, ib->name));
}

/**
 * Initialize the download mesh.
 */
G_GNUC_COLD void
dmesh_init(void)
{
	mesh = hikset_create(offsetof(struct dmesh, sha1),
		HASH_KEY_FIXED, SHA1_RAW_SIZE);
	ban_mesh = hikset_create_any(offsetof(struct dmesh_banned, info),
		urlinfo_hash, urlinfo_eq);
	ban_mesh_by_sha1 = htable_create(HASH_KEY_FIXED, SHA1_RAW_SIZE);
	dmesh_cq = cq_main_submake("dmesh", DMESH_CALLOUT);
	dmesh_retrieve();
	dmesh_ban_retrieve();
}

/**
 * Free download mesh entry.
 */
static void
dmesh_entry_free(struct dmesh_entry *dme)
{
	g_assert(dme);

	if (dme->fw_entry) {
		atom_guid_free_null(&dme->e.fwh.guid);
		hash_list_free_all(&dme->e.fwh.proxies, gnet_host_free);
	} else {
		if (dme->e.url.name)
			atom_str_free(dme->e.url.name);
	}
	hash_list_free_all(&dme->bad, wfree_host_addr1);
	WFREE(dme);
}

/**
 * Fill URL info from externally supplied sha1, addr, port, idx and name.
 * If sha1 is NULL, we use the name, otherwise the urn:sha1.
 *
 * WARNING: fills structure with pointers to static data.
 */
static void
dmesh_fill_info(dmesh_urlinfo_t *info,
	const struct sha1 *sha1, const host_addr_t addr,
	uint16 port, uint idx, const char *name)
{
	static const char urnsha1[] = "urn:sha1:";
	static char urn[SHA1_BASE32_SIZE + sizeof urnsha1];

	info->addr = addr;
	info->port = port;
	info->idx = idx;

	if (sha1) {
		concat_strings(urn, sizeof urn, urnsha1, sha1_base32(sha1), (void *) 0);
		info->name = urn;
	} else {
		info->name = name;
	}
}

/**
 * Free a dmesh_urlinfo_t structure.
 */
static void
dmesh_urlinfo_free(dmesh_urlinfo_t *info)
{
	g_assert(info);

	atom_str_free(info->name);
	WFREE(info);
}

/**
 * Remove entry from banned mesh.
 */
static void
dmesh_ban_remove_entry(struct dmesh_banned *dmb)
{
	g_assert(dmb);
	g_assert(dmb == hikset_lookup(ban_mesh, dmb->info));

	/*
	 * Also remove the banned entry from the IP list by SHA1 which is ussed
	 * by X-NAlt
	 *		-- JA 24/10/2003
	 */
	if (dmb->sha1 != NULL) {
		pslist_t *by_addr;
		pslist_t *head;
		const void *key;		/* The SHA1 atom used for key in table */
		void *x;
		bool found;

		found = htable_lookup_extended(ban_mesh_by_sha1, dmb->sha1, &key, &x);
		g_assert(found);
		head = by_addr = x;
		by_addr = pslist_remove(by_addr, dmb);

		if (by_addr == NULL) {
			htable_remove(ban_mesh_by_sha1, key);
			atom_sha1_free(key);
		} else if (by_addr != head)
			htable_insert(ban_mesh_by_sha1, key, by_addr);

		atom_sha1_free(dmb->sha1);
	}

	hikset_remove(ban_mesh, dmb->info);
	dmesh_urlinfo_free(dmb->info);
	WFREE(dmb);
}

/**
 * Called from callout queue when it's time to expire the URL ban.
 */
static void
dmesh_ban_expire(cqueue_t *unused_cq, void *obj)
{
	struct dmesh_banned *dmb = obj;

	(void) unused_cq;
	dmesh_ban_remove_entry(dmb);
}

/**
 * Add new URL to the banned hash.
 * If stamp is 0, the current timestamp is used.
 */
static void
dmesh_ban_add(const struct sha1 *sha1,
	const dmesh_urlinfo_t *info, time_t stamp)
{
	time_t now = tm_time();
	struct dmesh_banned *dmb;
	time_delta_t lifetime = BAN_LIFETIME;

	if (stamp == 0)
		stamp = now;

	/*
	 * If expired, don't insert.
	 */

	lifetime -= delta_time(now, stamp);
	lifetime = MIN(lifetime, INT_MAX / 1000);

	if (lifetime <= 0)
		return;

	/*
	 * Insert new entry, or update old entry if the new one is more recent.
	 */

	dmb = hikset_lookup(ban_mesh, info);

	if (dmb == NULL) {
		dmesh_urlinfo_t *ui;

		WALLOC(ui);
		ui->addr = info->addr;
		ui->port = info->port;
		ui->idx = info->idx;
		ui->name = atom_str_get(info->name);

		WALLOC(dmb);
		dmb->info = ui;
		dmb->created = stamp;
		dmb->cq_ev = cq_insert(dmesh_cq, lifetime*1000, dmesh_ban_expire, dmb);
		dmb->sha1 = NULL;

		hikset_insert(ban_mesh, dmb);

		entropy_harvest_many(VARLEN(ui), VARLEN(dmb),
			ui->name, strsize(ui->name), PTRLEN(sha1), NULL);

		/*
		 * Keep record of banned hosts by SHA1 Hash. We will use this to send
		 * out X-Nalt locations.
		 *		-- JA, 1/11/2003.
		 */

		if (sha1 != NULL) {
			pslist_t *by_addr;
			bool existed;

			dmb->sha1 = atom_sha1_get(sha1);

			/*
             * Don't fear for duplicates here. The dmb lookup above
             * makes sure that if a XNalt with the IP already exists,
             * the appropriate dmb will be updated (else-case below).
             *     -- BLUE 16/01/2004
             */
			by_addr = htable_lookup(ban_mesh_by_sha1, sha1);
			existed = by_addr != NULL;
			by_addr = pslist_append(by_addr, dmb);

			if (!existed) {
				htable_insert_const(ban_mesh_by_sha1,
					atom_sha1_get(sha1), by_addr);
			}
		}
	}
	else if (delta_time(dmb->created, stamp) < 0) {
		dmb->created = stamp;
		cq_resched(dmb->cq_ev, lifetime * 1000);
	}
}

/**
 * Conditionally remove an entry from the banned mesh provided it has not
 * been updated in the last DMESH_BAN_VETO seconds.
 *
 * @return TRUE if ban was lifted, FALSE otherwise.
 */
static bool
dmesh_ban_remove(const struct sha1 *sha1, host_addr_t addr, uint16 port)
{
	dmesh_urlinfo_t info;
	struct dmesh_banned *dmb;

	dmesh_fill_info(&info, sha1, addr, port, URN_INDEX, NULL);
	dmb = hikset_lookup(ban_mesh, &info);

	if (dmb != NULL && delta_time(tm_time(), dmb->created) > DMESH_BAN_VETO) {
		cq_cancel(&dmb->cq_ev);
		dmesh_ban_remove_entry(dmb);
		return TRUE;
	}

	return FALSE;
}

/**
 * Check whether URL is banned from the mesh.
 */
static bool
dmesh_is_banned(const dmesh_urlinfo_t *info)
{
	return hikset_contains(ban_mesh, info);
}

/**
 * Are we capable of using firewalled alternate locations?
 */
bool
dmesh_can_use_fwalt(void)
{
	return !GNET_PROPERTY(is_firewalled) && GNET_PROPERTY(send_pushes);
}

/***
 *** Mesh URL parsing.
 ***/

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const char *
dmesh_url_strerror(dmesh_url_error_t errnum)
{
	if (DMESH_URL_HTTP_PARSER == errnum) {
		str_t *s = str_private(G_STRFUNC, 80);

		str_printf(s, "%s: %s",
			dmesh_url_error_to_string(errnum),
			http_url_strerror(http_url_errno));

		return str_2c(s);
	}

	return dmesh_url_error_to_string(errnum);
}

/**
 * Parse URL `url', and fill a structure `info' representing this URL.
 *
 * @return TRUE if OK, FALSE if we could not parse it.
 * The variable `dmesh_url_errno' is set accordingly.
 */
bool
dmesh_url_parse(const char *url, dmesh_urlinfo_t *info)
{
	host_addr_t addr;
	uint16 port;
	uint idx;
	const char *endptr, *file, *host = NULL, *path = NULL;

	if (!http_url_parse(url, &port, &host, &path)) {
		dmesh_url_errno = DMESH_URL_HTTP_PARSER;
		return FALSE;
	}

	/* FIXME:	This can block; we should never keep resolved hostnames as IP
	 *			addresses around but always resolve hostnames just in time.
	 */
	addr = name_to_single_host_addr(host, settings_dns_net());
	if (!is_host_addr(addr))
		return FALSE;

	/*
	 * Test the first form of resource naming:
	 *
	 *    /get/1/name.txt
	 */

	if (NULL != (endptr = is_strprefix(path, "/get/"))) {
		int error;

		idx = parse_uint32(endptr, &endptr, 10, &error);
		if (!error && URN_INDEX == idx) {
			dmesh_url_errno = DMESH_URL_RESERVED_INDEX;
			return FALSE;				/* Index 0xffffffff is our mark */
		}

		if (error || *endptr != '/') {
			dmesh_url_errno = DMESH_URL_NO_FILENAME;
			return FALSE;				/* Did not have "/get/234/" */
		}

		/* Ok, `file' points after the "/", at beginning of filename */
		file = ++endptr;
	} else if (NULL != (endptr = is_strprefix(path, "/uri-res/N2R?"))) {

		/*
		 * Test the second form of resource naming:
		 *
		 *    /uri-res/N2R?urn:sha1:ABCDEFGHIJKLMN....
		 */

		idx = URN_INDEX;		/* Identifies second form */
		file = endptr;
	} else {
		dmesh_url_errno = DMESH_URL_BAD_FILE_PREFIX;
		return FALSE;
	}

	g_assert(file != NULL);

	info->addr = addr;
	info->port = port;
	info->idx = idx;

	/*
	 * If we have an URL with a filename, it is URL-escaped.
	 *
	 * We're unescaping it now, meaning there cannot be embedded '/' in the
	 * filename.  This is a reasonable assumption.
	 * NB: when most servents understand URL-escaped queries, we won't need
	 * to do this anymore and will keep the file URL-escaped.
	 */

	if (idx != URN_INDEX) {
		char *unescaped = url_unescape(deconstify_char(file), FALSE);
		if (!unescaped) {
			dmesh_url_errno = DMESH_URL_BAD_ENCODING;
			return FALSE;
		}
		info->name = atom_str_get(unescaped);
		if (unescaped != file) {
			HFREE_NULL(unescaped);
		}
	} else {
		struct sha1 sha1;
		
		if (!urn_get_sha1(file, &sha1)) {
			dmesh_url_errno = DMESH_URL_BAD_URI_RES;
			return FALSE;
		}
		info->name = atom_str_get(file);
	}


	dmesh_url_errno = DMESH_URL_OK;

	return TRUE;
}

/**
 * Allocate a new download mesh structure (there is one per SHA1).
 */
static struct dmesh *
dm_alloc(const struct sha1 *sha1)
{
	struct dmesh *dm;

	WALLOC(dm);
	dm->last_update = 0;
	dm->entries = list_new();
	dm->sha1 = atom_sha1_get(sha1);
	dm->by_host = htable_create_any(packed_host_hash_func,
		packed_host_hash_func2, packed_host_eq_func);
	dm->by_guid = htable_create(HASH_KEY_FIXED, GUID_RAW_SIZE);

	return dm;
}

/**
 * Free download mesh structure.
 */
static void
dm_free(struct dmesh *dm)
{
	list_free_all(&dm->entries,
		cast_to_list_destroy((func_ptr_t) dmesh_entry_free));

	/*
	 * Values in the dme->by_host table were the dmesh_entry structures
	 * we just disposed of above, so we only need to get rid of the keys.
	 */
	
	htable_foreach_key(dm->by_host, wfree_packed_host, NULL);
	htable_free_null(&dm->by_host);

	/* Keys were GUID in the dmesh_entry, no need to free them */
	htable_free_null(&dm->by_guid);

	atom_sha1_free_null(&dm->sha1);
	WFREE(dm);
}

/**
 * Remove specified entry from mesh bucket and reclaim it.
 */
static void
dm_remove_entry(struct dmesh *dm, struct dmesh_entry *dme)
{
	struct packed_host packed;
	const void *key;
	void *value;
	bool found;

	g_assert(dm);
	g_assert(list_length(dm->entries) > 0);

	if (GNET_PROPERTY(dmesh_debug)) {
		g_debug("dmesh %sentry removed for urn:sha1:%s at %s",
			dme->fw_entry ? "firewalled " : "", sha1_base32(dm->sha1),
			dme->fw_entry ?
				guid_hex_str(dme->e.fwh.guid) :
				host_addr_port_to_string(dme->e.url.addr, dme->e.url.port));
	}

	if (dme->fw_entry) {
		found = htable_lookup_extended(dm->by_guid,
					dme->e.fwh.guid, &key, &value);
	} else {
		packed = host_pack(dme->e.url.addr, dme->e.url.port);
		found = htable_lookup_extended(dm->by_host,
					&packed, &key, &value);
	}

	g_assert(found);
	g_assert(value == (void *) dme);

	found = list_remove(dm->entries, dme);		/* Remove from list... */

	g_assert(found);

	/* ...and from the proper hash table */

	if (dme->fw_entry) {
		htable_remove(dm->by_guid, dme->e.fwh.guid);
	} else {
		htable_remove(dm->by_host, &packed);
		wfree_packed_host(deconstify_pointer(key), NULL);
	}

	dmesh_entry_free(dme);
}

/**
 * Remove the addr:port entry from mesh bucket, if present.
 */
static void
dm_remove(struct dmesh *dm, const host_addr_t addr, uint16 port)
{
	struct packed_host packed;
	struct dmesh_entry *dme;
	const void *key;
	void *value;
	bool found;

	g_assert(dm);

	packed = host_pack(addr, port);
	found = htable_lookup_extended(dm->by_host, &packed, &key, &value);

	if (!found)
		return;

	if (GNET_PROPERTY(dmesh_debug)) {
		g_debug("dmesh entry removed for urn:sha1:%s at %s",
			sha1_base32(dm->sha1), host_addr_port_to_string(addr, port));
	}

	dme = value;
	found = list_remove(dm->entries, dme);		/* Remove from list */

	g_assert(found);
	g_assert(!dme->fw_entry);

	htable_remove(dm->by_host, &packed);	/* And from hash table */
	wfree_packed_host(deconstify_pointer(key), NULL);

	dmesh_entry_free(dme);
}

/**
 * Is the SHA1 that of a finished file (either shared in the library or
 * seeded after completion)?
 */
static bool
sha1_of_finished_file(const struct sha1 *sha1)
{
	shared_file_t *sf = shared_file_by_sha1(sha1);
	bool finished;

	finished = sf && sf != SHARE_REBUILDING && shared_file_is_finished(sf);
	shared_file_unref(&sf);

	return finished;
}

/**
 * Compute suitable life time for mesh entries.
 *
 * Complete files have no download HTTP transactions, hence the alt-locs
 * we get are only from uploaders.  To keep only the ones that are fresh-enough, 
 * reduce the lifetime of each entry.
 */
static long
dm_lifetime(const struct dmesh *dm)
{
	g_assert(dm);
	g_assert(dm->sha1);

	return sha1_of_finished_file(dm->sha1) ? MAX_LIBLIFETIME : MAX_LIFETIME;
}

/**
 * Expire entries deemed too old in a given mesh bucket `dm'.
 */
static void
dm_expire(struct dmesh *dm)
{
	pslist_t *expired = NULL;
	pslist_t *sl;
	time_t now = tm_time();
	long agemax;
	list_iter_t *iter;

	agemax = dm_lifetime(dm);

	iter = list_iter_before_head(dm->entries);

	while (list_iter_has_next(iter)) {
		struct dmesh_entry *dme = list_iter_next(iter);

		if (delta_time(now, dme->stamp) <= agemax)
			continue;

		/*
		 * Remove the entry.
		 *
		 * XXX instead of removing, maybe we can schedule a HEAD refresh
		 * XXX to see whether the entry is still valid?
		 */

		if (GNET_PROPERTY(dmesh_debug) > 4)
			g_debug("MESH %s: EXPIRED \"%s\", age=%u",
				sha1_base32(dm->sha1),
				dme->fw_entry ?
					dmesh_fwinfo_to_string(&dme->e.fwh) :
					dmesh_urlinfo_to_string(&dme->e.url),
				(unsigned) delta_time(now, dme->stamp));

		expired = pslist_prepend(expired, dme);
	}

	list_iter_free(&iter);

	PSLIST_FOREACH(expired, sl) {
		struct dmesh_entry *dme = sl->data;

		dm_remove_entry(dm, dme);
	}

	pslist_free(expired);

	dm->last_update = tm_time();
}

/**
 * Dispose of the entry slot, which must be empty.
 */
static void
dmesh_dispose(const struct sha1 *sha1)
{
	void *value;
	bool found;
	struct dmesh *dm;

	found = hikset_lookup_extended(mesh, sha1, &value);

	dm = value;
	g_assert(found);
	g_assert(list_length(dm->entries) == 0);

	hikset_remove(mesh, sha1);
	dm_free(dm);

	entropy_harvest_single(PTRLEN(sha1));
}

/**
 * Remove entry from mesh due to a failed download attempt.
 */
bool
dmesh_remove(const struct sha1 *sha1, const host_addr_t addr, uint16 port,
	uint idx, const char *name)
{
	struct dmesh *dm;
	dmesh_urlinfo_t info;

	/*
	 * We're called because the download failed, so we must ban the URL
	 * to prevent further insertion in the mesh.
	 */

	dmesh_fill_info(&info, sha1, addr, port, idx, name);
	dmesh_ban_add(sha1, &info, 0);

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 */

	dm = hikset_lookup(mesh, sha1);

	if (dm == NULL)				/* Nothing for this SHA1 key */
		return FALSE;

	dm_remove(dm, addr, port);

	/*
	 * If there is nothing left, clear the mesh entry.
	 */

	if (list_length(dm->entries) == 0)
		dmesh_dispose(sha1);

    return TRUE;
}

/**
 * Get the number of dmesh entries for a given SHA1.
 *
 * @return the number of dmesh entries
 */
int
dmesh_count(const struct sha1 *sha1)
{
	struct dmesh *dm;

	g_assert(sha1);

	dm = hikset_lookup(mesh, sha1);

	/*
	 * If we have an entry and the last update was done more than
	 * EXPIRE_DELAY seconds ago, attempt to expire old entries, and
	 * dispose of the record if none remain.
	 */

	if (NULL != dm && delta_time(tm_time(), dm->last_update) > EXPIRE_DELAY) {
		dm_expire(dm);

		if (list_length(dm->entries) == 0) {
			dmesh_dispose(sha1);
			dm = NULL;
		}
	}

	return dm ? list_length(dm->entries) : 0;
}

/**
 * Return download mesh for a given SHA1.
 */
static struct dmesh *
dmesh_get(const struct sha1 *sha1)
{
	struct dmesh *dm;

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 *
	 * If we don't, create a new structure and insert it in the table.
	 *
	 * If we have, make sure we remove any existing older entry first,
	 * to avoid storing duplicates (entry is removed only if found and older
	 * than the one we're trying to add).
	 */

	dm =  hikset_lookup(mesh, sha1);
	if (dm == NULL) {
		dm = dm_alloc(sha1);
		hikset_insert(mesh, dm);
	} else {
		dm_expire(dm);
	}

	return dm;
}

/**
 * Add entry to the download mesh, indexed by the binary `sha1' digest.
 * If `stamp' is 0, then the current time is used.
 *
 * If `idx' is URN_INDEX, then we can access this file only through an
 * /uri-res request, the URN being given as `name'.
 *
 * @return TRUE if the entry was added in the mesh, FALSE if it was discarded
 * because it was the oldest record and we have enough already.
 */
static bool
dmesh_raw_add(const struct sha1 *sha1, const dmesh_urlinfo_t *info,
	time_t stamp, bool swarm)
{
	struct dmesh_entry *dme;
	struct dmesh *dm;
	time_t now = tm_time();
	host_addr_t addr = info->addr;
	uint16 port = info->port;
	uint idx = info->idx;
	const char *name = info->name;
	struct packed_host packed;
	const char *reason = NULL;

	g_return_val_if_fail(sha1, FALSE);

	if (stamp == 0 || delta_time(stamp, now) > 0)
		stamp = now;

	if (delta_time(now, stamp) > MAX_LIFETIME) {
		reason = "expired";
		goto rejected;
	}

	/*
	 * Reject if this is for our host, or if the host is a private/hostile IP
	 * or if the IP:port point back to one of our recent addresses.
	 */

	if (is_my_address_and_port(addr, port)) {
		reason = "my own address and port";
		goto rejected;
	}

	if (local_addr_cache_lookup(addr, port)) {
		reason = "recent own address and port";
		goto rejected;
	}

	if (!host_is_valid(addr, port)) {
		reason = "address/port not valid";
		goto rejected;
	}

	if (hostiles_is_bad(addr)) {
		reason = "bad hostile address";
		goto rejected;
	}

	if (hostiles_spam_check(addr, port)) {
		reason = "caught spammer";
		goto rejected;
	}

	if (ctl_limit(addr, CTL_D_MESH)) {
		reason = "country limit";
		goto rejected;
	}

	/*
	 * See whether this URL is banned from the mesh.
	 */

	if (dmesh_is_banned(info)) {
		reason = "in banned mesh";
		goto rejected;
	}

	dm = dmesh_get(sha1);

	/*
	 * See whether we knew something about this host already.
	 */

	packed = host_pack(addr, port);
	dme = htable_lookup(dm->by_host, &packed);

	if (dme) {
		/*
		 * Entry for this host existed.
		 */

		g_assert(host_addr_equiv(dme->e.url.addr, addr));
		g_assert(dme->e.url.port == port);

		/*
		 * We favor URN_INDEX entries, if we can...
		 */

		if (dme->e.url.idx != idx && idx == URN_INDEX) {
			dme->e.url.idx = idx;
			atom_str_change(&dme->e.url.name, name);
		}

		if (stamp > dme->stamp)		/* Don't move stamp back in the past */
			dme->stamp = stamp;

		if (GNET_PROPERTY(dmesh_debug))
			g_debug("dmesh entry reused for urn:sha1:%s at %s",
				sha1_base32(sha1), host_addr_port_to_string(addr, port));
	} else {
		/*
		 * Allocate new entry.
		 */

		WALLOC(dme);

		dme->inserted = now;
		dme->stamp = stamp;
		dme->e.url.addr = addr;
		dme->e.url.port = port;
		dme->e.url.idx = idx;
		dme->e.url.name = atom_str_get(name);
		dme->bad = NULL;
		dme->good = FALSE;
		dme->fw_entry = FALSE;

		entropy_harvest_many(name, strlen(name),
			VARLEN(dme), PTRLEN(sha1), NULL);

		if (GNET_PROPERTY(dmesh_debug))
			g_debug("dmesh entry created for urn:sha1:%s at %s",
				sha1_base32(sha1), host_addr_port_to_string(addr, port));

		/*
		 * We insert new entries at the tail of the list, and record them
		 * into the hash table indexed by host.
		 */

		list_append(dm->entries, dme);
		dm->last_update = now;

		htable_insert(dm->by_host, walloc_packed_host(addr, port), dme);

		if (list_length(dm->entries) == MAX_ENTRIES) {
			struct dmesh_entry *oldest = list_head(dm->entries);
			dm_remove_entry(dm, oldest);
		}
	}

	/*
	 * We got a new entry that could be used for swarming if we are
	 * downloading that file.
	 *
	 * If this is from a uri-res URI, don't use the SHA1 as
	 * filename, so that the existing name is used instead.
	 */

	if (swarm) {
		file_info_try_to_swarm_with(URN_INDEX == idx && sha1 ? NULL : name,
			addr, port, sha1);
	}

	return TRUE;			/* We added the entry */

rejected:
	if (GNET_PROPERTY(dmesh_debug) > 4)
		g_debug("MESH %s: rejecting \"%s\", stamp=%u age=%u: %s",
			sha1_base32(sha1),
			dmesh_urlinfo_to_string(info), (uint) stamp,
			(unsigned) delta_time(now, stamp),
			reason);

	return FALSE;
}

/**
 * Add firewalled entry to the download mesh, indexed by the `sha1' digest.
 * If `stamp' is 0, then the current time is used.
 *
 * When entry is created, we become the owner of the proxies list.
 *
 * @return whether the entry was added in the mesh, or was discarded because
 * it was the oldest record and we have enough already.
 */
static bool
dmesh_raw_fw_add(const struct sha1 *sha1, const dmesh_fwinfo_t *info,
	time_t stamp, bool swarm)
{
	struct dmesh_entry *dme;
	struct dmesh *dm;
	time_t now = tm_time();
	const char *reason = NULL;

	g_return_val_if_fail(sha1, FALSE);

	if (stamp == 0 || delta_time(stamp, now) > 0)
		stamp = now;

	if (delta_time(now, stamp) > MAX_LIFETIME) {
		reason = "expired";
		goto rejected;
	}

	/*
	 * Reject if this is for our host.
	 */

	if (guid_eq(info->guid, GNET_PROPERTY(servent_guid))) {
		reason = "my own GUID";
		goto rejected;
	}

	dm = dmesh_get(sha1);

	/*
	 * See whether we knew something about this host already.
	 */

	dme = htable_lookup(dm->by_guid, info->guid);

	if (dme) {
		/*
		 * Entry for this host existed.
		 */

		g_assert(guid_eq(dme->e.fwh.guid, info->guid));

		if (stamp > dme->stamp)		/* Don't move stamp back in the past */
			dme->stamp = stamp;

		/*
		 * If we have new proxies, the new list supersedes the old one.
		 * Otherwise we keep the old list.
		 */

		if (info->proxies != NULL) {
			hash_list_free_all(&dme->e.fwh.proxies, gnet_host_free);
			dme->e.fwh.proxies = info->proxies;
			dme->inserted = now;	/* List of push-proxies changed */
		}

		if (GNET_PROPERTY(dmesh_debug))
			g_debug("dmesh entry reused for urn:sha1:%s for %s (%s proxies)",
				sha1_base32(sha1), guid_hex_str(info->guid),
				info->proxies ? "new" : "no new");
	} else {
		/*
		 * Allocate new entry.
		 */

		WALLOC(dme);

		dme->inserted = now;
		dme->stamp = stamp;
		dme->e.fwh.guid = atom_guid_get(info->guid);
		dme->e.fwh.proxies = info->proxies;
		dme->bad = NULL;
		dme->good = FALSE;
		dme->fw_entry = TRUE;

		entropy_harvest_many(PTRLEN(info->guid),
			VARLEN(dme), PTRLEN(sha1), NULL);

		if (GNET_PROPERTY(dmesh_debug))
			g_debug("dmesh entry created for urn:sha1:%s for %s",
				sha1_base32(sha1), guid_hex_str(info->guid));

		/*
		 * We insert new entries at the tail of the list, and record them
		 * into the hash table indexed by GUID.
		 */

		list_append(dm->entries, dme);
		dm->last_update = now;

		htable_insert(dm->by_guid, dme->e.fwh.guid, dme);

		if (list_length(dm->entries) == MAX_ENTRIES) {
			struct dmesh_entry *oldest = list_head(dm->entries);
			dm_remove_entry(dm, oldest);
		}
	}

	/*
	 * We got a new entry that could be used for swarming if we are
	 * downloading that file.
	 */

	if (swarm)
		file_info_try_to_swarm_with_firewalled(info->guid, info->proxies, sha1);

	return TRUE;			/* We added the entry */

rejected:
	if (GNET_PROPERTY(dmesh_debug) > 4)
		g_debug("MESH %s: rejecting \"%s\", stamp=%u age=%u: %s",
			sha1_base32(sha1),
			dmesh_fwinfo_to_string(info), (uint) stamp,
			(unsigned) delta_time(now, stamp),
			reason);

	return FALSE;
}

/**
 * Same as dmesh_raw_add(), but this is for public consumption.
 */
bool
dmesh_add(const struct sha1 *sha1, const host_addr_t addr,
	uint16 port, uint idx, const char *name, time_t stamp)
{
	dmesh_urlinfo_t info;

	/*
	 * Translate the supplied arguments: if idx is URN_INDEX, then `name'
	 * is the filename but we must use the urn:sha1 instead, as URN_INDEX
	 * is our mark to indicate an /uri-res/N2R? URL (with an urn:sha1).
	 */

	dmesh_fill_info(&info, sha1, addr, port, idx, name);
	return dmesh_raw_add(sha1, &info, stamp, TRUE);
}

/**
 * Add addr:port as a known alternate location for given sha1.
 */
void
dmesh_add_alternate(const struct sha1 *sha1, host_addr_t addr, uint16 port)
{
	dmesh_urlinfo_t info;

	dmesh_fill_info(&info, sha1, addr, port, URN_INDEX, NULL);
	(void) dmesh_raw_add(sha1, &info, tm_time(), TRUE);
}

/**
 * Add addr:port as a known good alternate location for given sha1.
 */
void
dmesh_add_good_alternate(const struct sha1 *sha1,
	host_addr_t addr, uint16 port)
{
	dmesh_urlinfo_t info;

	dmesh_fill_info(&info, sha1, addr, port, URN_INDEX, NULL);
	(void) dmesh_raw_add(sha1, &info, tm_time(), FALSE);
	dmesh_good_mark(sha1, addr, port, TRUE);
}

/**
 * Add a set of alternate locations (IP + port) to the mesh.
 */
void
dmesh_add_alternates(const struct sha1 *sha1, const gnet_host_vec_t *alt)
{
	int i;

	for (i = gnet_host_vec_count(alt) - 1; i >= 0; i--) {
		struct gnutella_host host;
		host_addr_t addr;
		uint16 port;

		host = gnet_host_vec_get(alt, i);
		addr = gnet_host_get_addr(&host);
		port = gnet_host_get_port(&host);

		dmesh_add_alternate(sha1, addr, port);
	}
}

/**
 * Remove addr:port as a known alternate location for given sha1.
 * This inserts the location into the banned mesh.
 */
void
dmesh_remove_alternate(const struct sha1 *sha1, host_addr_t addr, uint16 port)
{
	dmesh_remove(sha1, addr, port, URN_INDEX, NULL);
}

/**
 * Record that addr:port was signalled negatively as an alternate location
 * for given sha1.  The reporter's address is also given so that we can wait
 * until we have sufficient evidence from at least MIN_BAD_REPORT different
 * parties from different networks to mitigate local collusion.
 *
 * When there is sufficient evidence, the entry is evicted from the mesh
 * and placed into the banned mesh.
 */
void
dmesh_negative_alt(const struct sha1 *sha1, host_addr_t reporter,
	host_addr_t addr, uint16 port)
{
	struct dmesh *dm;
	struct packed_host packed;
	struct dmesh_entry *dme;
	host_addr_t net;

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 */

	dm = hikset_lookup(mesh, sha1);

	if (dm == NULL)				/* Nothing for this SHA1 key */
		return;

	packed = host_pack(addr, port);
	dme = htable_lookup(dm->by_host, &packed);

	if (dme == NULL)
		return;

	g_assert(dme->e.url.port == port);
	g_assert(host_addr_equiv(dme->e.url.addr, addr));

	if (dme->bad == NULL)
		dme->bad = hash_list_new(host_addr_hash_func, host_addr_eq_func);

	/*
	 * If this host already reported this network as being bad, ignore.
	 * We define "network" as CIDR/16 for IPv4 and CIDR/64 for IPv6.
	 */

	net = host_addr_mask_net(reporter, 16, 64);

	if (hash_list_contains(dme->bad, &net))
		return;

	/*
	 * Evict the entry only when there is enough evidence.
	 */

	if (hash_list_length(dme->bad) + 1 < MIN_BAD_REPORT) {
		hash_list_append(dme->bad, WCOPY(&net));
	} else {
		/* Add entry to the banned mesh if not a firewalled source */

		if (!dme->fw_entry)
			dmesh_ban_add(sha1, &dme->e.url, 0);

		dm_remove_entry(dm, dme);
	}
}

/**
 * Flag dmesh entry for this SHA1, address and port as good or bad.
 */
void
dmesh_good_mark(const struct sha1 *sha1,
	host_addr_t addr, uint16 port, bool good)
{
	struct dmesh *dm;
	struct packed_host packed;
	struct dmesh_entry *dme;
	bool retried = FALSE;

	dm = hikset_lookup(mesh, sha1);
	if (dm == NULL)
		return;			/* Weird, but it doesn't matter */

	packed = host_pack(addr, port);

retry:
	dme = htable_lookup(dm->by_host, &packed);

	if (dme == NULL) {
		/*
		 * Weird, we may have expired this entry.  Recreate it if it's good.
		 * If it still not appears, maybe it's rejected for some reason
		 * by the dmesh_raw_add() routine.  Warn and bail out.
		 */

		if (retried) {
			g_warning("cannot mark %s as being a good source for urn:sha1:%s",
				host_addr_port_to_string(addr, port), sha1_base32(sha1));
			return;
		}

		if (good) {
			if (!dmesh_ban_remove(sha1, addr, port))
				return;		/* Entry too recent to lift ban yet */
			dmesh_add_alternate(sha1, addr, port);
			retried = TRUE;
			goto retry;
		} else
			return;
	}

	g_assert(dme->e.url.port == port);
	g_assert(host_addr_equiv(dme->e.url.addr, addr));

	/*
	 * Get rid of the "bad" reporting if we're flagging it as good!
	 */

	if (good) {
		hash_list_free_all(&dme->bad, wfree_host_addr1);
	}

	/*
	 * If we're flagging the entry as good for the first time, then
	 * update the `inserted' field: indeed, we only send new entries
	 * to remote parties, so we must update this.
	 *
	 * As a side effect, we also update the stamp when the entry is
	 * flagged as good!
	 */

	if (good) {
		time_t now = tm_time();

		if (!dme->good)
			dme->inserted = now;	/* First time flagged as good */
		dme->stamp = now;			/* We know it's still alive */
	}

	dme->good = good;
}

/**
 * Flag firewalled dmesh entry for this SHA1 as good or bad.
 */
static void
dmesh_good_fw_mark(const struct sha1 *sha1,
	const struct guid *guid, bool good)
{
	struct dmesh *dm;
	struct dmesh_entry *dme;

	dm = hikset_lookup(mesh, sha1);
	if (dm == NULL)
		return;			/* Weird, but it doesn't matter */

	dme = htable_lookup(dm->by_guid, guid);

	if (dme == NULL)
		return;

	g_assert(guid_eq(dme->e.fwh.guid, guid));

/* XXX */
#if 0
	/*
	 * Get rid of the "bad" reporting if we're flagging it as good!
	 */

	if (good) {
		hash_list_free_all(&dme->bad, wfree_host_addr1);
	}
#endif

	/*
	 * If we're flagging the entry as good for the first time, then
	 * update the `inserted' field: indeed, we only send new entries
	 * to remote parties, so we must update this.
	 *
	 * As a side effect, we also update the stamp when the entry is
	 * flagged as good!
	 */

	if (good) {
		time_t now = tm_time();

		if (!dme->good)
			dme->inserted = now;	/* First time flagged as good */
		dme->stamp = now;			/* We know it's still alive */
	}

	dme->good = good;
}

/**
 * Add GUID as a known good firewalled location for given sha1.
 */
void
dmesh_add_good_firewalled(const struct sha1 *sha1, const struct guid *guid)
{
	dmesh_fwinfo_t info;

	/*
	 * Firewalled locations which we collect through downloading (i.e. ones
	 * we know as being good) are recorded without push-proxies.
	 *
	 * When we have to propagate these firewalled locations, we'll use the
	 * known push-proxies from the download server, if any.
	 */

	info.guid = guid;
	info.proxies = NULL;

	dmesh_raw_fw_add(sha1, &info, tm_time(), FALSE);
	dmesh_good_fw_mark(sha1, guid, TRUE);
}

/**
 * Format the URL described by `info' into the provided buffer `buf', which
 * can hold `len' bytes.
 *
 * @returns length of formatted entry, -1 if the URL would be larger than
 * the buffer.  If `quoting' is non-NULL, set it to indicate whether the
 * formatted URL should be quoted if emitted in a header, because it
 * contains a "," character.
 */
static size_t
dmesh_urlinfo_to_string_buf(const dmesh_urlinfo_t *info, char *buf,
	size_t len, bool *quoting)
{
	size_t rw;
	size_t maxslen = len - 1;			/* Account for trailing NUL */
	const char *host;

	g_assert(len > 0);
	g_assert(len <= INT_MAX);
	g_assert(info->name != NULL);

	host = info->port == HTTP_PORT
			? host_addr_to_string(info->addr)
			: host_addr_port_to_string(info->addr, info->port);
	rw = concat_strings(buf, len, "http://", host, (void *) 0);
	if (rw >= maxslen)
		return (size_t) -1;

	if (info->idx == URN_INDEX) {
		rw += str_bprintf(&buf[rw], len - rw, "/uri-res/N2R?%s", info->name);
		if (quoting != NULL)
			*quoting = FALSE;			/* No "," in the generated URL */
	} else {
		rw += str_bprintf(&buf[rw], len - rw, "/get/%u/", info->idx);

		/*
		 * Write filename, URL-escaping it directly into the buffer.
		 */

		if (rw < maxslen) {
			int re = url_escape_into(info->name, &buf[rw], len - rw);

			if (re < 0)
				return (size_t) -1;

			rw += re;
			if (rw < len)
				buf[rw] = '\0';
		}

		/*
		 * If `quoting' is non-NULL, look whether there is a "," in the
		 * filename.  Since "," is not URL-escaped, we look directly in
		 * the info->name field.
		 */

		if (quoting != NULL)
			*quoting = NULL != strchr(info->name, ',');
	}

	return rw < maxslen ? rw : (size_t) -1;
}

/**
 * Format the `info' URL and return pointer to static string.
 */
static char *
dmesh_urlinfo_to_string(const dmesh_urlinfo_t *info)
{
	static char urlstr[1024];

	(void) dmesh_urlinfo_to_string_buf(info, urlstr, sizeof urlstr, NULL);

	return urlstr;
}

/**
 * Format the firewalled host described by `info' into the provided buffer
 * `buf', which can hold `len' bytes.
 *
 * @returns length of formatted entry, -1 if the string would be larger than
 * the buffer.  The generated string does not contain any "," character.
 */
static size_t
dmesh_fwinfo_to_string_buf(const dmesh_fwinfo_t *info, char *buf, size_t len)
{
	size_t rw;
	size_t maxslen = len - 1;			/* Account for trailing NUL */
	hash_list_iter_t *iter;

	g_assert(len > 0);
	g_assert(len <= INT_MAX);
	g_assert(info->guid != NULL);

	rw = str_bprintf(buf, len, "%s", guid_hex_str(info->guid));
	if (rw >= maxslen)
		goto done;

	if (NULL == info->proxies)
		goto done;

	iter = hash_list_iterator(info->proxies);

	while (hash_list_iter_has_next(iter) && rw < maxslen) {
		gnet_host_t *host = hash_list_iter_next(iter);

		rw += str_bprintf(&buf[rw], len - rw, ";%s",
				host_addr_port_to_string(
					gnet_host_get_addr(host), gnet_host_get_port(host)));
	}

	hash_list_iter_release(&iter);

done:
	return rw < maxslen ? rw : (size_t) -1;
}

/**
 * Format the `info' firewalled host and return pointer to static string.
 */
static char *
dmesh_fwinfo_to_string(const dmesh_fwinfo_t *info)
{
	static char fwstr[1024];

	(void) dmesh_fwinfo_to_string_buf(info, fwstr, sizeof fwstr);

	return fwstr;
}

/**
 * Format mesh_entry in the provided buffer, as a compact addr:port address.
 * The port is even omitted if it is the standard Gnutella one.
 *
 * @returns length of formatted entry, -1 if the address would be larger than
 * the buffer, or if no compact form can be derived for this entry (not an
 * URN_INDEX kind).
 */
static size_t
dmesh_entry_compact(const struct dmesh_entry *dme, char *buf, size_t size)
{
	const dmesh_urlinfo_t *info = &dme->e.url;
	const char *host;
	size_t rw;

	g_assert(!dme->fw_entry);
	g_assert(size > 0);
	g_assert(size <= INT_MAX);

	if (info->idx != URN_INDEX)
		return (size_t) -1;

	host = info->port == GTA_PORT
		? host_addr_to_string(info->addr)
		: host_addr_port_to_string(info->addr, info->port);

	rw = g_strlcpy(buf, host, size);
	return rw < size ? rw : (size_t) -1;
}

/**
 * Format dmesh_entry in the provided buffer, as an URL with an appended
 * timestamp in ISO format, GMT time.
 *
 * @return length of formatted entry, -1 if the URL would be larger than
 * the buffer.
 */
static size_t
dmesh_entry_url_stamp(const struct dmesh_entry *dme, char *buf, size_t size)
{
	size_t rw;
	bool quoting;

	g_assert(!dme->fw_entry);
	g_assert(size > 0);
	g_assert(size <= INT_MAX);

	/*
	 * Format the URL info first.
	 */

	rw = dmesh_urlinfo_to_string_buf(&dme->e.url, buf, size, &quoting);
	if ((size_t) -1 == rw)
		return (size_t) -1;

	/*
	 * If quoting is required, we need to surround the already formatted
	 * string into "quotes".
	 */

	if (quoting) {
		if (rw + 2 >= size)		/* Not enough room for 2 quotes */
			return (size_t) -1;

		g_memmove(buf + 1, buf, rw);
		buf[0] = '"';
		buf[++rw] = '"';
		buf[++rw] = '\0';
	}

	/*
	 * Append timestamp.
	 */

	rw += concat_strings(&buf[rw], size - rw,
			" ", timestamp_utc_to_string(dme->stamp), (void *) 0);

	return rw < size ? rw : (size_t) -1;
}

/**
 * Format dmesh_entry in the provided buffer, as a firewalled location
 * with an appended timestamp in ISO format, GMT time.
 *
 * @return length of formatted entry, -1 if the entry would be larger than
 * the buffer.
 */
static size_t
dmesh_entry_fw_stamp(const struct dmesh_entry *dme, char *buf, size_t size)
{
	size_t rw;

	g_assert(dme->fw_entry);
	g_assert(size > 0);
	g_assert(size <= INT_MAX);

	/*
	 * Format the firewalled host info first.
	 */

	rw = dmesh_fwinfo_to_string_buf(&dme->e.fwh, buf, size);
	if ((size_t) -1 == rw)
		return (size_t) -1;

	/*
	 * Append timestamp.
	 */

	rw += concat_strings(&buf[rw], size - rw,
			";", timestamp_utc_to_string(dme->stamp), (void *) 0);

	return rw < size ? rw : (size_t) -1;
}

/**
 * Format the `dme' mesh entry as "URL timestamp" or as FW host info.
 *
 * @return pointer to static string.
 */
static const char *
dmesh_entry_to_string(const struct dmesh_entry *dme)
{
	static char str[1024];

	if (dme->fw_entry) {
		dmesh_entry_fw_stamp(dme, str, sizeof str);
	} else {
		dmesh_entry_url_stamp(dme, str, sizeof str);
	}

	return str;
}

/**
 * Fill supplied vector `hvec' whose size is `hcnt' with some alternate
 * locations for a given SHA1 key, that can be requested by hash directly.
 *
 * @return the amount of locations filled.
 */
int
dmesh_fill_alternate(const struct sha1 *sha1, gnet_host_t *hvec, int hcnt)
{
	struct dmesh *dm;
	struct dmesh_entry *selected[MAX_ENTRIES];
	int nselected;
	int i;
	int j;
	bool complete_file;
	list_iter_t *iter;

	/*
	 * Fetch the mesh entry for this SHA1.
	 */

	dm = hikset_lookup(mesh, sha1);
	if (dm == NULL)						/* SHA1 unknown */
		return 0;

	/*
	 * First pass: identify good entries that can be requested by hash only.
	 */

	i = 0;
	complete_file = sha1_of_finished_file(sha1);
	iter = list_iter_before_head(dm->entries);

	while (list_iter_has_next(iter)) {
		struct dmesh_entry *dme = list_iter_next(iter);

		if (dme->fw_entry || dme->e.url.idx != URN_INDEX)
			continue;

		/*
		 * When downloading (i.e. when the file is not complete), we have the
		 * neceesary feedback to spot good sources.  When sharing a complete
		 * file, all we can do is skip entries for which we got bad feedback.
		 */

		if (complete_file) {
			if (dme->bad)		/* Skip entries with negative feedback */
				continue;
		} else {
			if (!dme->good)
				continue;		/* Only propagate good alt locs */
		}

		if (!host_addr_is_ipv4(dme->e.url.addr))
			continue;

		if (g2_cache_lookup(dme->e.url.addr, dme->e.url.port))
			continue;			/* Don't pollute with G2-only entries */

		if (local_addr_cache_lookup(dme->e.url.addr, dme->e.url.port))
			continue;			/* Don't pollute with our recent addresses */

		g_assert(i < MAX_ENTRIES);
		selected[i++] = dme;
	}

	nselected = i;
	list_iter_free(&iter);

	if (nselected == 0)
		return 0;

	g_assert(UNSIGNED(nselected) <= list_length(dm->entries));

	/*
	 * Second pass: choose at most `hcnt' entries at random.
	 *
	 * We do this by randomly shuffling the whole array and then selecting
	 * the first `hcnt' entries.
	 */

	shuffle(selected, nselected, sizeof selected[0]);

	for (i = j = 0; i < nselected && j < hcnt; i++, j++) {
		struct dmesh_entry *dme;

		dme = selected[i];
		gnet_host_set(&hvec[j], dme->e.url.addr, dme->e.url.port);
	}

	return j;		/* Amount we filled in vector */
}

/**
 * Format firewalled location into supplied buffer.
 *
 * @param buf		the buffer where we have to format
 * @param size		the buffer size
 * @param guid		the GUID of the firewalled alt-loc
 * @param addr		the known address of the servent
 * @param port		the known listening port of the servent
 * @param proxies	sequence of known push-proxies (gnet_host_t *)
 * @param net		network type for proxies that we want to include
 *
 * @return the length of generated string.
 */
static size_t
dmesh_fwalt_string(char *buf, size_t size,
	const guid_t *guid, host_addr_t addr, uint16 port, sequence_t *proxies,
	host_net_t net)
{
	size_t rw;

	rw = str_bprintf(buf, size, "%s", guid_to_string(guid));

#if 0
	/* No FWT support yet */
	rw += str_bprintf(&buf[rw], size - rw, ";fwt/1");
#endif

	if (host_is_valid(addr, port)) {
		rw += str_bprintf(&buf[rw], size - rw, ";%s",
			port_host_addr_to_string(port, addr));
	}

	if (proxies != NULL) {
		sequence_iter_t *iter;
		size_t n = 0;

		iter = sequence_forward_iterator(proxies);
		while (sequence_iter_has_next(iter) && n++ < FW_MAX_PROXIES) {
			const gnet_host_t *host = sequence_iter_next(iter);
			const host_addr_t haddr = gnet_host_get_addr(host);

			if (!hcache_addr_within_net(haddr, net))
				continue;

			rw += str_bprintf(&buf[rw], size - rw, ";%s",
				host_addr_port_to_string(haddr, gnet_host_get_port(host)));
		}
		sequence_iterator_release(&iter);
	}

	return rw;
}

/**
 * Build alternate location headers for a given SHA1 key.  We generate at
 * most `size' bytes of data into `alt'.
 *
 * @param sha1	the SHA1 of the resource for which we're emitting alt-locs
 * @param buf	buffer where headers are generated
 * @param size	size of buffer
 *
 * @param addr is the host to which those alternate locations are meant:
 * we skip any data pertaining to that host.
 *
 * @param last_sent is the time at which we sent some previous alternate
 * locations. If there has been no change to the mesh since then, we'll
 * return an empty string.  Otherwise we return entries inserted after
 * `last_sent'.
 *
 * @param vendor is given to determine whether it is apt to read our
 * X-Alt and X-Nalt fields formatted with continuations or not.
 *
 * @param fi when it is non-NULL, it means we're sharing that file and
 * we're sending alternate locations to remote servers: include ourselves
 * in the list of alternate locations if PFSP-server is enabled.
 *
 * @param request if it is true, then the mesh entries are generated in
 * an HTTP request; otherwise it's for an HTTP reply.
 *
 * @param guid if non-NULL, then we can also include firewalled locations
 * and this is the GUID that we must not include.
 *
 * @param net specifies which networks are allowed for alt-locs: IPv4, IPv6
 * or both.
 *
 * unless the `vendor' is GTKG, don't use continuation: most
 * servent authors don't bother with a proper HTTP header parsing layer.
 *
 * @return amount of generated data.
 */
int
dmesh_alternate_location(const struct sha1 *sha1,
	char *buf, size_t size, const host_addr_t addr,
	time_t last_sent, const char *vendor,
	fileinfo_t *fi, bool request, const struct guid *guid,
	host_net_t net)
{
	char url[1024];
	struct dmesh *dm;
	size_t len = 0;
	pslist_t *l;
	int nselected = 0;
	struct dmesh_entry *selected[MAX_ENTRIES];
	int i;
	pslist_t *by_addr;
	size_t maxlinelen = 0;
	header_fmt_t *fmt;
	bool added;
	list_iter_t *iter;
	bool complete_file;
	bool can_share_partials;

	g_assert(sha1);
	g_assert(buf);
	g_assert(size_is_non_negative(size));
	g_assert(size <= INT_MAX);

	if (fi != NULL) {
		file_info_check(fi);
	}

	if (size <= 3)		/* Account for trailing NUL + "\r\n" */
		return 0;

	/*
	 * Shall we emit continuations?
	 *
	 * When sending a request, unless we know the vendor is GTKG, don't.
	 * When sending a reply, do so but be nice with older BearShare versions.
	 *		--RAM, 04/01/2004.
	 */

	if (request) {
		/* We're sending the request: assume they can't read continuations */
		if (vendor == NULL || !is_strprefix(vendor, "gtk-gnutella/"))
			maxlinelen = 100000;	/* In practice, no continuations! */
	} else {
		/* We're sending a reply: assume they can read continuations */
		if (vendor != NULL && is_strprefix(vendor, "BearShare ")) {
			/*
			 * Only versions newer than (included) BS 4.3.4 and BS 4.4b25
			 * will properly support continuations.
			 *
			 * Given that BearShare is almost extinct in the Gnutella world,
			 * no need to bother, just avoid continuations for all versions.
			 *		--RAM, 2011-06-21
			 */

			maxlinelen = 100000;	/* In practice, no continuations! */
		}
	}

	/*
	 * Get the X-Nalts and fill this header. Only fill up to a maximum of 33%
	 * of the total buffer size.
	 *		 -- JA, 1/11/2003
	 */

	by_addr = htable_lookup(ban_mesh_by_sha1, sha1);

	if (by_addr != NULL) {
		fmt = header_fmt_make("X-Nalt", ", ", size, size / 3);
		if (maxlinelen)
			header_fmt_set_line_length(fmt, maxlinelen);
		added = FALSE;

		/* Loop through the X-Nalts */
		PSLIST_FOREACH(by_addr, l) {
			struct dmesh_banned *banned = l->data;
			dmesh_urlinfo_t *info = banned->info;

			if (info->idx != URN_INDEX)
				continue;

			/*
			 * IPv6-Ready: only include IP addresses they want.
			 */

			if (!hcache_addr_within_net(info->addr, net))
				continue;

			if (delta_time(banned->created, last_sent) > 0) {
				const char *value;

				value = host_addr_port_to_string(info->addr, info->port);
				if (!header_fmt_append_value(fmt, value))
					break;
				added = TRUE;
			}
		}

		if (added) {
			size_t length;

			header_fmt_end(fmt);
			length = header_fmt_length(fmt);
			g_assert(length < size);
			len += clamp_strncpy(buf, size, header_fmt_string(fmt), length);
		}

		header_fmt_free(&fmt);
	}

	/* Find mesh entry for this SHA1 */
	dm = hikset_lookup(mesh, sha1);

	/*
	 * Start filling the buffer.
	 */

	/* `len' is non-zero if X-Nalt was generated */
	fmt = header_fmt_make("X-Alt", ", ", size - len, size - len);
	if (maxlinelen)
		header_fmt_set_line_length(fmt, maxlinelen);
	added = FALSE;

	/*
	 * PFSP-server: If we have to list ourselves in the mesh, do so
	 * at the first position.
	 */

	can_share_partials =
		fi != NULL && file_info_partial_shareable(fi) &&
		is_host_addr(listen_addr_primary_net(net)) && upload_is_enabled();

	/*
	 * For unfirewalled servers, the PFSP-server alt-loc is listed in X-Alt.
	 */

	if (can_share_partials && !GNET_PROPERTY(is_firewalled)) {
		static const char tls_hex[] = "tls=8";	/* Only us at index zero */
		size_t url_len;
		struct dmesh_entry ourselves;
		time_t now = tm_time();

		ourselves.inserted = now;
		ourselves.stamp = now;
		ourselves.e.url.addr = listen_addr_primary_net(net);
		ourselves.e.url.port = GNET_PROPERTY(listen_port);
		ourselves.e.url.idx = URN_INDEX;
		ourselves.e.url.name = NULL;
		ourselves.good = TRUE;
		ourselves.fw_entry = FALSE;

		url_len = dmesh_entry_compact(&ourselves, url, sizeof url);
		g_assert((size_t) -1 != url_len && url_len < sizeof url);

		if (!header_fmt_value_fits(fmt, url_len + strlen(tls_hex)))
			goto nomore;

		if (tls_enabled()) {
			/* FIXME: what's the semantic of a leading "tls=8"? */
			header_fmt_append_value(fmt, tls_hex);
		}
		if (header_fmt_append_value(fmt, url))
			added = TRUE;
	}

	/*
	 * Check whether we have anything (new).
	 */

	if (dm == NULL)						/* SHA1 unknown */
		goto nomore;

	if (delta_time(dm->last_update, last_sent) <= 0)	/* No change occurred */
		goto nomore;

	/*
	 * Expire old entries.  If none remain, free entry and return.
	 */

	dm_expire(dm);

	if (list_length(dm->entries) == 0) {
		dmesh_dispose(sha1);
		goto nomore;
	}

	/*
	 * Go through the list, selecting new entries that can fit.
	 * We'll do two passes.  The first pass identifies the candidates.
	 * The second pass randomly selects items until we fill the room
	 * allocated.
	 */

	ZERO(&selected);

	/*
	 * First pass.
	 */

	i = 0;
	iter = list_iter_before_head(dm->entries);
	complete_file = sha1_of_finished_file(sha1);

	while (list_iter_has_next(iter)) {
		struct dmesh_entry *dme = list_iter_next(iter);

		if (dme->fw_entry)
			continue;

		/*
		 * When downloading (i.e. when the file is not complete), we have the
		 * neceesary feedback to spot good sources.  When sharing a complete
		 * file, all we can do is skip entries for which we got bad feedback.
		 */

		if (complete_file) {
			if (dme->bad)		/* Skip entries with negative feedback */
				continue;
		} else {
			if (!dme->good)
				continue;		/* Only propagate good alt locs */
		}

		if (delta_time(dme->inserted, last_sent) <= 0)
			continue;

		if (host_addr_equiv(dme->e.url.addr, addr))
			continue;

		if (!hcache_addr_within_net(dme->e.url.addr, net))
			continue;

		if (dme->e.url.idx != URN_INDEX)
			continue;

		if (g2_cache_lookup(dme->e.url.addr, dme->e.url.port))
			continue;			/* Don't pollute with G2-only entries */

		if (local_addr_cache_lookup(dme->e.url.addr, dme->e.url.port))
			continue;			/* Don't pollute with our recent addresses */

		g_assert(i < MAX_ENTRIES);

		selected[i++] = dme;
	}

	nselected = i;
	list_iter_free(&iter);

	if (nselected == 0)
		goto nomore;

	g_assert(UNSIGNED(nselected) <= list_length(dm->entries));

	/*
	 * Second pass.
	 */

	shuffle(selected, nselected, sizeof selected[0]);

	for (i = 0; i < nselected; i++) {
		struct dmesh_entry *dme = selected[i];
		size_t url_len;

		g_assert(delta_time(dme->inserted, last_sent) > 0);

		url_len = dmesh_entry_compact(dme, url, sizeof url);

		/* Buffer was large enough */
		g_assert((size_t) -1 != url_len && url_len < sizeof url);

		if (header_fmt_append_value(fmt, url))
			added = TRUE;
	}

	if (NULL == guid)
		goto nomore;		/* No need to emit firewalled alt locs */

	/*
	 * Finish X-Alt header if we have emitted something.
	 */

	if (added) {
		size_t length;

		header_fmt_end(fmt);			/* Only report sources we've checked */
		length = header_fmt_length(fmt);
		g_assert(size >= len);
		g_assert(size > size_saturate_add(length, len));
		len += clamp_strncpy(&buf[len], size - len,
			header_fmt_string(fmt), length);
	}
	header_fmt_free(&fmt);

	fmt = header_fmt_make("X-Falt", ", ", size - len, size - len);
	if (maxlinelen)
		header_fmt_set_line_length(fmt, maxlinelen);
	added = FALSE;

	/*
	 * For firewalled servers, the PFSP-server alt-loc is listed in X-Falt.
	 */

	if (can_share_partials && GNET_PROPERTY(is_firewalled)) {
		size_t url_len;
		guid_t servent_guid;

		gnet_prop_get_storage(PROP_SERVENT_GUID,
			&servent_guid, sizeof servent_guid);

		/*
		 * Since we're firewalled, we necessarily emit X-FW-Node-Info and
		 * possibly some X-Push-Proxy header.  There's no need to repeat
		 * that information and we can simply emit our GUID.
		 */

		url_len = dmesh_fwalt_string(url, sizeof url,
			&servent_guid, ipv4_unspecified, 0, NULL, net);

		g_assert(url_len < sizeof url);

		if (header_fmt_append_value(fmt, url))
			added = TRUE;

		if (!added)
			goto nomore;
	}

	/*
	 * We do a single-pass over firewalled entries because they are more
	 * verbose and if we have non-firewalled alt-locs then it is less useful
	 * to have firewalled ones.
	 */

	iter = list_iter_before_head(dm->entries);

	while (list_iter_has_next(iter)) {
		struct dmesh_entry *dme = list_iter_next(iter);
		sequence_t *proxies;
		host_addr_t servent_addr;
		uint16 servent_port;

		if (!dme->fw_entry)
			continue;

		/*
		 * When downloading (i.e. when the file is not complete), we have the
		 * neceesary feedback to spot good sources.  When sharing a complete
		 * file, all we can do is skip entries for which we got bad feedback.
		 */

		if (complete_file) {
			if (dme->bad)		/* Skip entries with negative feedback */
				continue;
		} else {
			if (!dme->good)
				continue;		/* Only propagate good alt locs */
		}

		if (delta_time(dme->inserted, last_sent) <= 0)
			continue;

		if (guid_eq(dme->e.fwh.guid, guid))
			continue;

		/*
		 * Found a suitable firewalled alt-loc.
		 *
		 * See whether the download layer knows about this GUID and can
		 * supply us a list of proxies as well as the servent's IP:port.
		 */

		if (
			download_known_guid(dme->e.fwh.guid, &servent_addr, &servent_port,
				&proxies)
		) {
			size_t url_len;
			url_len = dmesh_fwalt_string(url, sizeof url,
				dme->e.fwh.guid, servent_addr, servent_port, proxies, net);
			sequence_release(&proxies);


			if (!hcache_addr_within_net(servent_addr, net))
				continue;

			g_assert(url_len < sizeof url);

			if (header_fmt_append_value(fmt, url))
				added = TRUE;
		} else {
			size_t url_len;

			if (dme->e.fwh.proxies != NULL) {
				proxies = sequence_create_from_hash_list(dme->e.fwh.proxies);
			} else {
				proxies = NULL;
			}

			url_len = dmesh_fwalt_string(url, sizeof url,
				dme->e.fwh.guid, ipv4_unspecified, 0, proxies, net);
			sequence_release(&proxies);

			g_assert(url_len < sizeof url);

			if (header_fmt_append_value(fmt, url))
				added = TRUE;
		}
	}

	list_iter_free(&iter);

	/* FALL THROUGH */

nomore:
	if (added) {
		size_t length;

		header_fmt_end(fmt);			/* Only report sources we've checked */
		length = header_fmt_length(fmt);
		g_assert(size >= len);
		g_assert(size > size_saturate_add(length, len));
		len += clamp_strncpy(&buf[len], size - len,
			header_fmt_string(fmt), length);
	}
	header_fmt_free(&fmt);

	return len;
}

/**
 * Parse the value of the X-(Gnutella-)Content-URN header in `value', looking
 * for a SHA1.  When found, the SHA1 is extracted and placed into the given
 * `digest' buffer.
 *
 * @return whether we successfully extracted the SHA1.
 */
bool
dmesh_collect_sha1(const char *value, struct sha1 *sha1)
{
	strtok_t *st;
	const char *tok;
	bool found = FALSE;

	st = strtok_make_strip(value);

	while ((tok = strtok_next(st, ","))) {
		if (urn_get_sha1(tok, sha1)) {
			found = TRUE;
			break;
		}
	}

	strtok_free(st);

	return found;
}

/**
 * Parse a list of addr:port, such as typically found in "X-Alt" or "X-Nalt"
 * headers to extract alternate sources.
 *
 * For each value found, invoke the supplied callback `func' as:
 *
 *		func(sha1, addr, port, udata);
 *
 * where udata is opaque user-supplied data.
 */
static void
dmesh_parse_addr_port_list(const struct sha1 *sha1, const char *value,
	dmesh_add_cb func, void *udata)
{
	const char *tls_hex, *p, *next;

	tls_hex = NULL;
	next = value;

	while (NULL != (p = next)) {
		const char *start, *endptr;
		host_addr_t addr;
		uint16 port;
		bool ok;

		start = skip_ascii_blanks(p);
		if ('\0' == *start)
			break;

		next = strpbrk(start, ",;");
		if (next) {
			next++;
		}

		/* TODO: Handle tls=<hex> */
		if (NULL == tls_hex && (tls_hex = is_strcaseprefix(start, "tls=")))
			continue;

		/*
		 * In the original X-Alt specs, there could be a GUID here if the host
		 * is not directly connectible but LimeWire chose to emit firewalled
		 * sources in a dedicated X-Falt header, and only if the "fwalt" feature
		 * was advertised in X-Features.
		 *
		 * Therefore, we only parse a list of IP:port in X-Alt and X-Nalt.
		 */	

		ok = string_to_host_addr(start, &endptr, &addr);
		if (ok && ':' == *endptr) {
			int error;
				
			port = parse_uint16(&endptr[1], &endptr, 10, &error);
			ok = !error && port > 0; 
		} else {
			port = GTA_PORT;
		}
		
		if (ok) {
			(*func)(sha1, addr, port, udata);
		} else if (GNET_PROPERTY(dmesh_debug)) {
			g_warning("ignoring invalid compact alt-loc \"%s\"", start);
		}
	}
}

static void
dmesh_collect_compact_locations_cback(
	const sha1_t *sha1, host_addr_t addr, uint16 port, void *udata)
{
	const gnet_host_t *origin = udata;

	dmesh_add_alternate(sha1, addr, port);

	/*
	 * If entering an alt-loc in the mesh for an URN located on the
	 * origin, then we know it is a good one since it is being advertised
	 * by the server itself.
	 *		--RAM, 2012-12-03
	 */

	if (
		origin != NULL &&
		port == gnet_host_get_port(origin) &&
		host_addr_equiv(addr, gnet_host_get_addr(origin))
	) {
		dmesh_good_mark(sha1, addr, port, TRUE);

		if (GNET_PROPERTY(dmesh_debug) > 3) {
			g_debug("MESH %s: good self alt-loc from %s",
				 sha1_base32(sha1), gnet_host_to_string(origin));
		}
	}
}

/**
 * Parse the value of the "X-Alt" header to extract alternate sources
 * for a given SHA1 key given in the new compact form.
 *
 * @param sha1		the SHA1 for which we're collecting alt-locs
 * @param value		the value of the header field we're parsing
 * @param origin	if not-NULL, the host supplying us with the alt-locs
 */
void
dmesh_collect_compact_locations(const sha1_t *sha1, const char *value,
	const gnet_host_t *origin)
{
	dmesh_parse_addr_port_list(sha1, value,
		dmesh_collect_compact_locations_cback, deconstify_pointer(origin));
}

static void
dmesh_collect_negative_locations_cback(
	const struct sha1 *sha1, host_addr_t addr, uint16 port,
	void *udata)
{
	host_addr_t *reporter = udata;

	dmesh_negative_alt(sha1, *reporter, addr, port);
}

/**
 * Parse the value of the "X-Nalt" header to extract bad sources
 * for a given SHA1 key, given in the new compact form.
 *
 * @param reporter	the address of the host supplying the X-Nalt header
 */
void
dmesh_collect_negative_locations(
	const sha1_t *sha1, const char *value, host_addr_t reporter)
{
	dmesh_parse_addr_port_list(sha1, value,
		dmesh_collect_negative_locations_cback, &reporter);
}

/**
 * Parse value of the "X-Gnutella-Alternate-Location" to extract alternate
 * sources for a given SHA1 key.
 *
 * @param sha1		the SHA1 for which we're collecting alt-locs
 * @param value		the value of the header field we're parsing
 * @param origin	if not-NULL, the host supplying us with the alt-locs
 */
void
dmesh_collect_locations(const sha1_t *sha1, const char *value,
	const gnet_host_t *origin)
{
	const char *p = value;
	uchar c;
	time_t now = tm_time();
	bool finished = FALSE;

	do {
		const char *date_start, *url_start;
		time_t stamp;
		bool ok;
		dmesh_urlinfo_t info;
		bool skip_date;
		bool in_quote;

		/*
		 * Find next space, colon or EOS (End of String).
		 * Everything from now to there will be an URL.
		 * All leading spaces are skipped.
		 */

		in_quote = FALSE;
		info.name = NULL;
		info.addr = zero_host_addr;

		p = skip_ascii_spaces(p);
		if ('\0' == *p) {				/* Only seen spaces */
			finished = TRUE;
			goto free_urlinfo;
		}

		url_start = p;
		for (/* NOTHING */; '\0' != (c = *p); p++) {
			/*
			 * Quoted identifiers are one big token.
			 */

			if (in_quote && c == '\\' && p[1] == '"')
				g_warning("unsupported \\\" escape sequence in quoted section "
					"for Alternate-Location: should use URL escaping instead!");

			if (c == '"') {
				in_quote = !in_quote;
				if (!in_quote)
					break;			/* Space MUST follow after end quote */
			}

			if (in_quote)
				continue;

			/*
			 * The "," may appear un-escaped in the URL.
			 *
			 * We know we're no longer in an URL if the character after is a
			 * space (should be escaped).  Our header parsing code will
			 * concatenate lines with a ", " separation.
			 *
			 * If the character after the "," is an 'h' and we're seeing
			 * the string "http://" coming, then we've reached the end
			 * of the current URL (all URLs were given on one big happy line).
			 */

			if (c == ',') {
				if (is_strcaseprefix(&p[1], "http://"))
					break;
				if (!is_ascii_space(p[1]))
					continue;
			}

			if (is_ascii_space(c) || c == ',')
				break;
		}

		/*
		 * Parse URL.
		 */

		g_assert((uchar) *p == c);

		if (*url_start == '"') {				/* URL enclosed in quotes? */
			url_start++;						/* Skip that needless quote */
			if (c != '"')
				g_warning("Alternate-Location URL \"%s\" started with leading "
					"quote, but did not end with one!", url_start);
		}

		/*
		 * Once dmesh_url_parse() has been called and returned `ok', we'll
		 * have a non-NULL `info.name' field.  This is an atom that must
		 * get freed: instead of saying `continue', we must `goto free_urlinfo'
		 * so that this atom can be freed.
		 */

		{
			char *url;

			url = h_strndup(url_start, p - url_start);
			ok = dmesh_url_parse(url, &info);

			if (GNET_PROPERTY(dmesh_debug) > 6)
				g_debug("MESH (parsed=%d): \"%s\"", ok, url);

			if (!ok &&
				(GNET_PROPERTY(dmesh_debug) > 1 ||
					!is_strprefix(url, "ed2kftp://"))
			) {
				g_warning("cannot parse Alternate-Location URL \"%s\": %s",
					url, dmesh_url_strerror(dmesh_url_errno));
			}
			HFREE_NULL(url);
		}

		if (c == '"')				/* URL ended with a quote, skip it */
			c = *(++p);

		/*
		 * Maybe there is no date following the URL?
		 */

		if (c == ',') {				/* There's no following date then */
			p++;					/* Skip separator */
			goto free_urlinfo;		/* continue */
		}

		skip_date = !ok;			/* Skip date if we did not parse the URL */

		/*
		 * Advance to next ',', expecting a date.
		 */

		if (c != '\0')
			p++;

		date_start = p;

	more_date:
		for (/* NOTHING */; '\0' != (c = *p); p++) {
            /*
             * Limewire has a bug not to use the ',' separator, so
             * we assume a new urn is starting with "http://"
             *      -Richard 23/11/2002
             */

            if (c == ',' || is_strcaseprefix(p, "http://"))
				break;
		}

		/*
		 * Disambiguate "Mon, 17 Jun 2002 07:53:14 +0200"
		 */

		if (c == ',' && p - date_start == 3) {
			p++;
			goto more_date;
		}

		if (skip_date) {				/* URL was not parsed, just skipping */
			if (c == '\0')				/* Reached end of string */
				finished = TRUE;
			else if (c == ',')
                p++;					/* Skip the "," separator */
			goto free_urlinfo;			/* continue */
		}

		/*
		 * Parse date, if present.
		 */

		if (p != date_start) {
			char *date;

			g_assert((uchar) *p == c);
			date = h_strndup(date_start, p - date_start);
			stamp = date2time(date, now);

			if ((time_t) -1 == stamp) {
				const char *d;

				/*
				 * Some broken servents propagate two ISO dates separated by
				 * a space, such as: "2015-03-06T16:00Z 2015-03-06T19:09Z".
				 * So try to skip past the first space, if any, to see whether
				 * we can be more successful.
				 *		--RAM, 2015-03-06
				 *
				 * Actually, there can be more than two ISO dates, so just
				 * keep the LAST one (since a valid ISO date does not contain
				 * any space), by looking at the last space in the string.
				 *		--RAM, 2015-03-07
				 */

				if (NULL != (d = strrchr(date, ' ')))
					stamp = date2time(++d, now);	/* Skip the space */

				if ((time_t) -1 == stamp) {
					g_warning("cannot parse Alternate-Location date: %s", date);
					stamp = 0;
				}
			}

			if (GNET_PROPERTY(dmesh_debug) > 6) {
				g_debug("MESH (stamp=%s): \"%s\"",
					timestamp_to_string(stamp), date);
			}

			HFREE_NULL(date);
		} else
			stamp = 0;

		/*
		 * If we have a /uri-res/N2R?urn:sha1, make sure it's matching
		 * the SHA1 of the entry for which we're keeping those alternate
		 * locations.
		 */

		if (info.idx == URN_INDEX) {
			struct sha1 digest;
		
			ok = urn_get_sha1(info.name, &digest);
			g_assert(ok);

			ok = sha1_eq(sha1, &digest);
			if (!ok) {
				g_assert(sha1);
				g_warning("mismatch in /uri-res/N2R? Alternate-Location "
					"for SHA1=%s: got %s", sha1_base32(sha1), info.name);
				goto skip_add;
			}

			/* FALL THROUGH */

			/*
			 * Enter URL into mesh - only if it's a URN_INDEX
			 * to avoid dmesh pollution.
			 */

		}
		ok = dmesh_raw_add(sha1, &info, stamp, TRUE);

		/*
		 * If entering an alt-loc in the mesh for an URN located on the
		 * origin, then we know it is a good one since it is being advertised
		 * by the server itself.
		 *		--RAM, 2012-12-03
		 */

		if (
			URN_INDEX == info.idx &&
			origin != NULL &&
			info.port == gnet_host_get_port(origin) &&
			host_addr_equiv(info.addr, gnet_host_get_addr(origin))
		) {
			dmesh_good_mark(sha1, info.addr, info.port, TRUE);

			if (GNET_PROPERTY(dmesh_debug) > 3) {
				g_debug("MESH %s: good self alt-loc from %s",
					 sha1_base32(sha1), gnet_host_to_string(origin));
			}
		}

	skip_add:
		if (GNET_PROPERTY(dmesh_debug) > 4)
			g_debug("MESH %s: %s \"%s\", stamp=%u age=%u",
				sha1_base32(sha1),
				ok ? "added" : "rejected",
				dmesh_urlinfo_to_string(&info), (uint) stamp,
				(unsigned) delta_time(now, stamp));

		if (c == '\0')				/* Reached end of string */
			finished = TRUE;
		else if (c == ',')
            p++;					/* Skip separator */

	free_urlinfo:
		if (info.name)
			atom_str_free(info.name);

	} while (!finished);
}

/**
 * Fill buffer with at most `count' un-firewalled alt-locations for sha1.
 *
 * @returns the amount of locations inserted.
 */
static int
dmesh_alt_loc_fill(const struct sha1 *sha1, dmesh_urlinfo_t *buf, int count)
{
	struct dmesh *dm;
	list_iter_t *iter;
	int i;

	g_assert(sha1);
	g_assert(buf);
	g_assert(count > 0);

	dm = hikset_lookup(mesh, sha1);
	if (dm == NULL)					/* SHA1 unknown */
		return 0;

	i = 0;
	iter = list_iter_before_head(dm->entries);

	while (list_iter_has_next(iter) && i < count) {
		struct dmesh_entry *dme = list_iter_next(iter);
		dmesh_urlinfo_t *from;

		if (dme->fw_entry)
			continue;

		g_assert(i < MAX_ENTRIES);

		from = &dme->e.url;
		buf[i++] = *from;
	}

	list_iter_free(&iter);

	return i;
}

/**
 * Parse a single firewalled location.
 */
void
dmesh_collect_fw_host(const struct sha1 *sha1, const char *value)
{
	struct guid guid;
	bool seen_proxy = FALSE;
	bool seen_guid = FALSE;
	bool seen_pptls = FALSE;
	time_t stamp = 0;
	const char *tok;
	strtok_t *st;
	dmesh_fwinfo_t info;

	/*
	 * An X-Falt header is formatted as:
	 *
	 *  X-Falt: 9DBC52EEEBCA2C8A79036D626B959900;fwt/1;
	 *		26252:85.182.49.3;
	 *		pptls=E;69.12.88.95:1085;64.53.20.48:804;66.17.23.159:343
	 *
	 * We learn the GUID of the node, its address (in reversed port:IP format)
	 * and the push-proxies.
	 *
	 * The "fwt/1", the host address, "pptls=" and push-proxies are all
	 * optional items, only the leading GUID is mandatory.
	 *
	 * When persisting a firewalled location, we append an ISO timestamp
	 * at the end (e.g "2010-02-23 16:06:55Z").
	 */

	st = strtok_make_strip(value);
	info.guid = NULL;
	info.proxies = NULL;

	while ((tok = strtok_next(st, ";"))) {
		host_addr_t addr;
		uint16 port;
		gnet_host_t host;

		/* GUID is the first item we expect */
		if (!seen_guid) {
			if (!hex_to_guid(tok, &guid))
				break;
			seen_guid = TRUE;
			info.guid = atom_guid_get(&guid);
			continue;
		}

		/* Skip "options", stated as "word/x.y" */
		if (strstr(tok, "/"))
			continue;

		/* Skip first "pptsl=" indication */
		if (!seen_pptls) {
			/* TODO: handle pptls=<hex> */
			if (is_strcaseprefix(tok, "pptls=")) {
				seen_pptls = TRUE;
				continue;
			}
		}

		/*
		 * If we find a valid port:IP host, then these are the remote
		 * server address and port.
		 */

		if (!seen_proxy && string_to_port_host_addr(tok, NULL, &port, &addr))
			continue;

		/*
		 * If we reach the timestamp, we're done.
		 */

		if (string_to_timestamp_utc(tok, NULL, &stamp))
			break;

		/*
		 * Ignore everything that is not an IP:port, describing a push-proxy.
		 */

		if (!string_to_host_addr_port(tok, NULL, &addr, &port))
			continue;

		seen_proxy = TRUE;	/* Entering the push-proxy list */

		if (is_private_addr(addr) || !host_is_valid(addr, port))
			continue;

		if (info.proxies == NULL)
			info.proxies = hash_list_new(gnet_host_hash, gnet_host_equal);

		gnet_host_set(&host, addr, port);
		if (!hash_list_contains(info.proxies, &host)) {
			hash_list_append(info.proxies, gnet_host_dup(&host));
		}
	}

	strtok_free(st);

	if (NULL == info.guid) {
		if (GNET_PROPERTY(dmesh_debug))
			g_warning("could not parse 'X-Falt: %s'", value);
	} else {
		if (!dmesh_raw_fw_add(sha1, &info, stamp, TRUE)) {
			hash_list_free_all(&info.proxies, gnet_host_free);
		}
		atom_guid_free_null(&info.guid);
	}
}

/**
 * Parse value of the "X-Falt" header to extract alternate firewalled sources
 * for a given SHA1 key.
 */
void
dmesh_collect_fw_hosts(const struct sha1 *sha1, const char *value)
{
	const char *tok;
	strtok_t *st;

	/*
	 * An X-Falt header can contain several items, separated by ",".
	 */

	st = strtok_make_strip(value);
	while ((tok = strtok_next(st, ","))) {
		dmesh_collect_fw_host(sha1, tok);
	}
	strtok_free(st);
}

/**
 * Parse query hit (result set) for entries whose SHA1 match something
 * we have into the mesh or share, and insert them if needed.
 */
void
dmesh_check_results_set(gnet_results_set_t *rs)
{
	pslist_t *sl;
	time_t now = tm_time();

	PSLIST_FOREACH(rs->records, sl) {
		gnet_record_t *rc = sl->data;
		dmesh_urlinfo_t info;
		bool has = FALSE;

		if (rc->sha1 == NULL)
			continue;

		/*
		 * If we have an entry for this SHA1 in the mesh already,
		 * then we can update it for that entry.
		 *
		 * If the entry is not in the mesh already, look whether we're
		 * sharing this SHA1.
		 */

		has = hikset_contains(mesh, rc->sha1);

		if (!has) {
			shared_file_t *sf = shared_file_by_sha1(rc->sha1);
			has =	sf != NULL &&
					sf != SHARE_REBUILDING &&
					!shared_file_is_partial(sf);
			shared_file_unref(&sf);
		}

		if (has) {
			dmesh_fill_info(&info, rc->sha1, rs->addr, rs->port,
				URN_INDEX, NULL);
			(void) dmesh_raw_add(rc->sha1, &info, now, TRUE);

			/*
			 * If we have further alt-locs specified in the query hit, add
			 * them to the mesh and dispose of them.
			 */

			if (rc->alt_locs != NULL) {
				gnet_host_vec_t *alt = rc->alt_locs;
				int i;

				for (i = gnet_host_vec_count(alt) - 1; i >= 0; i--) {
					struct gnutella_host host;
				   
					host = gnet_host_vec_get(alt, i);
					dmesh_fill_info(&info, rc->sha1,
						gnet_host_get_addr(&host), gnet_host_get_port(&host),
						URN_INDEX, NULL);
					(void) dmesh_raw_add(rc->sha1, &info, now, TRUE);
				}

				search_free_alt_locs(rc);		/* Read them, free them! */
			}

			g_assert(rc->alt_locs == NULL);
		}
	}
}

#define DMESH_MAX	MAX_ENTRIES

/**
 * This is called when swarming is first requested to get a list of all the
 * servers with the requested file known by dmesh.
 * It creates a new download for every server found.
 *
 * @param `sha1' (atom) the SHA1 of the file.
 * @param `size' the original file size.
 * @param `fi' no brief description.
 */
void
dmesh_multiple_downloads(const struct sha1 *sha1,
	filesize_t size, fileinfo_t *fi)
{
	dmesh_urlinfo_t buffer[DMESH_MAX], *p;
	int n;
	time_t now;

	n = dmesh_alt_loc_fill(sha1, buffer, DMESH_MAX);
	if (n == 0)
		return;

	now = tm_time();

	for (p = buffer; n > 0; n--, p++) {
		const char *filename;

		if (GNET_PROPERTY(dmesh_debug) > 2)
			g_debug("ALT-LOC queuing from MESH: %s",
				dmesh_urlinfo_to_string(p));

		filename = URN_INDEX == p->idx && fi
			? filepath_basename(fi->pathname) : p->name;
		download_auto_new(filename,
			size,
			p->addr,
			p->port,
			&blank_guid,
			NULL,	/* hostname */
			sha1,
			NULL,	/* TTH */
			now,
			fi,
			NULL,	/* proxies */
			0);		/* flags */
	}
}

/**
 * Store key/value pair in file.
 */
static void
dmesh_store_kv(void *value, void *udata)
{
	const struct dmesh *dm = value;
	FILE *out = udata;
	list_iter_t *iter;

	fprintf(out, "%s\n", sha1_base32(dm->sha1));

	iter = list_iter_before_head(dm->entries);

	while (list_iter_has_next(iter)) {
		const struct dmesh_entry *dme = list_iter_next(iter);
		fprintf(out, "%s\n", dmesh_entry_to_string(dme));
	}

	list_iter_free(&iter);

	fputs("\n", out);
}

/* XXX add dmesh_store_if_dirty() and export that only */

typedef void (*header_func_t)(FILE *out);

/**
 * Store hash table `hash' into `file'.
 * The file header is emitted by `header_cb'.
 * The storing callback for each item is `store_cb'.
 */
static void
dmesh_store_hikset(const char *what, hikset_t *hash, const char *file,
	header_func_t header_cb, data_fn_t store_cb)
{
	FILE *out;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), file);
	out = file_config_open_write(what, &fp);

	if (!out)
		return;

	header_cb(out);
	hikset_foreach(hash, store_cb, out);

	file_config_close(out, &fp);
}

/**
 * Prints header to dmesh store file.
 */
static void
dmesh_header_print(FILE *out)
{
	file_config_preamble(out, "Download mesh");

	fputs(	"#\n# Format is:\n"
			"#   SHA1\n"
			"#   URL1 timestamp1\n"
			"#   URL2 timestamp2\n"
			"#   FWALT timestamp\n"
			"#   <blank line>\n"
			"#\n\n",
			out);
}

/**
 * Store download mesh onto file.
 * The download mesh is normally stored in ~/.gtk-gnutella/dmesh.
 */
void
dmesh_store(void)
{
	dmesh_store_hikset("download mesh",
		mesh, dmesh_file, dmesh_header_print, dmesh_store_kv);
}

/**
 * Retrieve download mesh and add entries that have not expired yet.
 * The mesh is normally retrieved from ~/.gtk-gnutella/dmesh.
 */
static G_GNUC_COLD void
dmesh_retrieve(void)
{
	FILE *f;
	char tmp[4096];
	struct sha1 sha1;
	bool has_sha1 = FALSE;
	bool skip = FALSE, truncated = FALSE;
	int line = 0;
	file_path_t fp[1];

	file_path_set(fp, settings_config_dir(), dmesh_file);
	f = file_config_open_read("download mesh", fp, G_N_ELEMENTS(fp));
	if (!f)
		return;

	/*
	 * Retrieval algorithm:
	 *
	 * Lines starting with a # are skipped.
	 *
	 * We read the SHA1 first, validate it.  The remaining line up to a
	 * blank line are attached sources for this SHA1.
	 */

	while (fgets(tmp, sizeof tmp, f)) {
		if (!file_line_chomp_tail(tmp, sizeof tmp, NULL)) {
			truncated = TRUE;
			continue;
		}
		line++;
		if (truncated) {
			truncated = FALSE;
			continue;
		}

		if (file_line_is_comment(tmp))
			continue;			/* Skip comments */

		if (file_line_is_empty(tmp)) {
			if (has_sha1)
				has_sha1 = FALSE;
			skip = FALSE;		/* Synchronization point */
			continue;
		}

		if (skip)
			continue;

		if (has_sha1) {
			if (GNET_PROPERTY(dmesh_debug))
				g_debug("%s(): parsing %s", G_STRFUNC, tmp);
			if (is_strprefix(tmp, "http://")) {
				dmesh_collect_locations(&sha1, tmp, NULL);
			} else {
				dmesh_collect_fw_hosts(&sha1, tmp);
			}
		} else {
			if (
				strlen(tmp) < SHA1_BASE32_SIZE ||
				SHA1_RAW_SIZE != base32_decode(sha1.data, sizeof sha1.data,
									tmp, SHA1_BASE32_SIZE)
			) {
				g_warning("%s: bad base32 SHA1 '%.32s' at line #%d, ignoring",
					G_STRFUNC, tmp, line);
				skip = TRUE;
			} else
				has_sha1 = TRUE;
		}
	}

	fclose(f);
	dmesh_store();			/* Persist what we have retrieved */
}

/**
 * Store key/value pair in file.
 */
static void
dmesh_ban_store_kv(void *value, void *udata)
{
	const struct dmesh_banned *dmb = value;
	FILE *out = udata;

	fprintf(out, "%lu %s\n",
		(ulong) dmb->created, dmesh_urlinfo_to_string(dmb->info));
}

/**
 * Prints header to banned mesh store file.
 */
static void
dmesh_ban_header_print(FILE *out)
{
	file_config_preamble(out, "Banned mesh");

	fputs(	"#\n# Format is:\n"
			"#  timestamp URL\n"
			"#\n\n", out);
}

/**
 * Store banned mesh onto file.
 * The banned mesh is normally stored in ~/.gtk-gnutella/dmesh_ban.
 */
void
dmesh_ban_store(void)
{
	dmesh_store_hikset("banned mesh",
		ban_mesh, dmesh_ban_file, dmesh_ban_header_print, dmesh_ban_store_kv);
}

/**
 * Retrieve banned mesh and add entries that have not expired yet.
 * The mesh is normally retrieved from ~/.gtk-gnutella/dmesh_ban.
 */
static G_GNUC_COLD void
dmesh_ban_retrieve(void)
{
	FILE *in;
	char tmp[1024];
	unsigned line = 0;
	time_t stamp;
	const char *p;
	int error;
	dmesh_urlinfo_t info;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), dmesh_ban_file);
	in = file_config_open_read("banned mesh", &fp, 1);

	if (!in)
		return;

	/*
	 * Retrieval algorithm:
	 *
	 * Lines starting with a # are skipped.
	 */

	while (fgets(tmp, sizeof tmp, in)) {
		line++;

		if (!file_line_chomp_tail(tmp, sizeof tmp, NULL)) {
			g_warning("%s: line %u too long, aborting", G_STRFUNC, line);
			break;
		}

		if (file_line_is_skipable(tmp))
			continue;			/* Skip empty or comment lines */

		stamp = parse_uint64(tmp, &p, 10, &error);
		if (error || *p != ' ') {
			g_warning("malformed stamp at line #%d in banned mesh: %s",
				line, tmp);
			continue;
		}

		p++;					/* Now points at the start of the URL */
		if (!dmesh_url_parse(p, &info)) {
			g_warning("malformed URL at line #%d in banned mesh: %s",
				line, tmp);
			continue;
		}

		/* FIXME: Save SHA1 for banning */
		dmesh_ban_add(NULL, &info, stamp);
		atom_str_free(info.name);
	}

	fclose(in);
	dmesh_ban_store();			/* Persist what we have retrieved */
}

/**
 * Free key/value pair in download mesh hash.
 */
static void
dmesh_free_kv(void *value, void *unused_udata)
{
	struct dmesh *dm = value;

	(void) unused_udata;
	dm_free(dm);
}

/**
 * Prepend the value to the list, given by reference.
 */
static void
dmesh_ban_prepend_list(void *value, void *user)
{
	struct dmesh_banned *dmb = value;
	pslist_t **listref = user;

	*listref = pslist_prepend(*listref, dmb);
}

/**
 * Called at servent shutdown time.
 */
G_GNUC_COLD void
dmesh_close(void)
{
	pslist_t *banned = NULL;
	pslist_t *sl;

	dmesh_store();
	dmesh_ban_store();

	hikset_foreach(mesh, dmesh_free_kv, NULL);
	hikset_free_null(&mesh);

	/*
	 * Construct a list of banned mesh entries to remove, then manually
	 * expire all the entries, which will remove entries from `ban_mesh'
	 * and `ban_mesh_by_sha1' as well.
	 */

	hikset_foreach(ban_mesh, dmesh_ban_prepend_list, &banned);

	PSLIST_FOREACH(banned, sl) {
		struct dmesh_banned *dmb = sl->data;
		cq_cancel(&dmb->cq_ev);
		dmesh_ban_expire(dmesh_cq, dmb);
	}

	pslist_free_null(&banned);
	hikset_free_null(&ban_mesh);
	htable_free_null(&ban_mesh_by_sha1);

	cq_free_null(&dmesh_cq);
}

/* vi: set ts=4 sw=4 cindent: */
