/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Download mesh.
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include <time.h>
#include <sys/time.h>

#include "gnutella.h"

#include "downloads.h"
#include "dmesh.h"
#include "huge.h"
#include "http.h"
#include "hostiles.h"
#include "guid.h"

#include "settings.h"

RCSID("$Id$");

extern cqueue_t *callout_queue;

/* made visible for us by atoms.c */
extern guint sha1_hash(gconstpointer key);
extern gint sha1_eq(gconstpointer a, gconstpointer b);

dmesh_url_error_t dmesh_url_errno;		/* Error from dmesh_url_parse() */

/*
 * The download mesh records all the known sources for a given SHA1.
 * It is implemented as a big hash table, where SHA1 are keys, each value
 * being a struct dmesh pointer.
 */
static GHashTable *mesh = NULL;

struct dmesh {				/* A download mesh bucket */
	guint32 last_update;	/* Timestamp of last insertion in the mesh */
	gint count;				/* Amount of entries in list */
	GSList *entries;		/* The download mesh entries, dmesh_entry data */
};

struct dmesh_entry {
	guint32 inserted;		/* When entry was inserted in mesh */
	guint32 stamp;			/* When entry was last seen */
	dmesh_urlinfo_t url;	/* URL info */
};

#define MAX_LIFETIME	86400		/* 1 day */
#define MAX_ENTRIES		64			/* Max amount of entries kept in list */
#define MAX_STAMP		0xffffffff	/* Unsigned int, 32 bits */

/* If not at least 60% alike, dump! */
#define FUZZY_DROP		((60 / 100) << FUZZY_SHIFT)
/* If more than 80% alike, equal! */
#define FUZZY_MATCH		((80 / 100) << FUZZY_SHIFT)

static const gchar *dmesh_file = "dmesh";

/*
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
static GHashTable *ban_mesh = NULL;

struct dmesh_banned {
	dmesh_urlinfo_t *info;	/* The banned URL (same as key) */
	time_t ctime;			/* Last time we saw this banned URL */
	gpointer cq_ev;			/* Scheduled callout event */
};

#define BAN_LIFETIME	7200		/* 2 hours */

static const gchar *dmesh_ban_file = "dmesh_ban";

static void dmesh_retrieve(void);
static void dmesh_ban_retrieve(void);
static gchar *dmesh_urlinfo_to_gchar(const dmesh_urlinfo_t *info);

/*
 * urlinfo_hash
 *
 * Hash a URL info.
 */
static guint urlinfo_hash(gconstpointer key)
{
	const dmesh_urlinfo_t *info = (const dmesh_urlinfo_t *) key;
	guint hash = 0;

	WRITE_GUINT32_LE(info->ip, &hash);	/* Reverse IP, 192.x.y.z -> z.y.x.192 */
	hash ^= (info->port << 16) | info->port;
	hash ^= info->idx;
	hash ^= g_str_hash(info->name);

	return hash;
}

/*
 * urlinfo_eq
 *
 * Test equality of two URL infos.
 */
static gint urlinfo_eq(gconstpointer a, gconstpointer b)
{
	const dmesh_urlinfo_t *ia = (const dmesh_urlinfo_t *) a;
	const dmesh_urlinfo_t *ib = (const dmesh_urlinfo_t *) b;

	return ia->ip == ib->ip		&&
		ia->port == ib->port	&&
		ia->idx == ib->idx		&&
		0 == strcmp(ia->name, ib->name);
}

/*
 * dmesh_init
 *
 * Initialize the download mesh.
 */
void dmesh_init(void)
{
	mesh = g_hash_table_new(sha1_hash, sha1_eq);
	ban_mesh = g_hash_table_new(urlinfo_hash, urlinfo_eq);
	dmesh_retrieve();
	dmesh_ban_retrieve();
}

/*
 * dmesh_entry_cmp
 *
 * Compare two dmesh_entry, based on the timestamp.  The greater the time
 * stamp, the samller the entry (i.e. the more recent).
 */
static gint dmesh_entry_cmp(gconstpointer a, gconstpointer b)
{
	const struct dmesh_entry *ae = (const struct dmesh_entry *) a;
	const struct dmesh_entry *be = (const struct dmesh_entry *) b;

	if (ae->stamp == be->stamp)
		return 0;

	return ae->stamp > be->stamp ? -1 : +1;
}

/*
 * dmesh_entry_free
 *
 * Free download mesh entry.
 */
static void dmesh_entry_free(struct dmesh_entry *dme)
{
	g_assert(dme);

	if (dme->url.name)
		atom_str_free(dme->url.name);

	wfree(dme, sizeof(*dme));
}

/*
 * dmesh_urlinfo_free
 *
 * Free a dmesh_urlinfo_t structure.
 */
static void dmesh_urlinfo_free(dmesh_urlinfo_t *info)
{
	g_assert(info);

	atom_str_free(info->name);
	wfree(info, sizeof(*info));
}

/*
 * dmesh_ban_expire
 *
 * Called from callout queue when it's time to expire the URL ban.
 */
static void dmesh_ban_expire(cqueue_t *cq, gpointer obj)
{
	struct dmesh_banned *dmb = (struct dmesh_banned *) obj;

	g_assert(dmb);
	g_assert((gpointer) dmb == g_hash_table_lookup(ban_mesh, dmb->info));

	g_hash_table_remove(ban_mesh, dmb->info);
	dmesh_urlinfo_free(dmb->info);
	wfree(dmb, sizeof(*dmb));
}

/*
 * dmesh_ban_add
 *
 * Add new URL to the banned hash.
 * If stamp is 0, the current timestamp is used.
 */
static void dmesh_ban_add(dmesh_urlinfo_t *info, time_t stamp)
{
	time_t now = time(NULL);
	struct dmesh_banned *dmb;
	gint lifetime = BAN_LIFETIME;

	if (stamp == 0)
		stamp = now;

	/*
	 * If expired, don't insert.
	 */

	lifetime -= now - stamp;

	if (lifetime <= 0)
		return;

	/*
	 * Insert new entry, or update old entry if the new one is more recent.
	 */

	dmb = (struct dmesh_banned *) g_hash_table_lookup(ban_mesh, info);

	if (dmb == NULL) {
		dmesh_urlinfo_t *ui;

		ui = walloc(sizeof(*info));
		ui->ip = info->ip;
		ui->port = info->port;
		ui->idx = info->idx;
		ui->name = atom_str_get(info->name);

		dmb = walloc(sizeof(*dmb));
		dmb->info = ui;
		dmb->ctime = stamp;
		dmb->cq_ev = cq_insert(callout_queue,
			lifetime * 1000, dmesh_ban_expire, dmb);

		g_hash_table_insert(ban_mesh, dmb->info, dmb);
	}
	else if (dmb->ctime < stamp) {
		dmb->ctime = stamp;
		cq_resched(callout_queue, dmb->cq_ev, lifetime * 1000);
	}
}

/*
 * dmesh_is_banned
 *
 * Check whether URL is banned from the mesh.
 */
static gboolean dmesh_is_banned(dmesh_urlinfo_t *info)
{
	return NULL != g_hash_table_lookup(ban_mesh, info);
}

/***
 *** Mesh URL parsing.
 ***/

static const gchar *parse_errstr[] = {
	"OK",									/* DMESH_URL_OK */
	"HTTP parsing error",					/* DMESH_URL_HTTP_PARSER */
	"File prefix neither /uri-res nor /get",/* DMESH_URL_BAD_FILE_PREFIX */
	"Index in /get/index is reserved",		/* DMESH_URL_RESERVED_INDEX */
	"No filename after /get/index",			/* DMESH_URL_NO_FILENAME */
};

/*
 * dmesh_url_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
const gchar *dmesh_url_strerror(dmesh_url_error_t errnum)
{
	static gchar http_error_str[128];

	if (errnum < 0 || errnum >= G_N_ELEMENTS(parse_errstr))
		return "Invalid error code";

	if (errnum == DMESH_URL_HTTP_PARSER) {
		gm_snprintf(http_error_str, sizeof(http_error_str),
			"%s: %s", parse_errstr[errnum], http_url_strerror(http_url_errno));
		return http_error_str;
	}

	return parse_errstr[errnum];
}

/*
 * dmesh_url_parse
 *
 * Parse URL `url', and fill a structure `info' representing this URL.
 *
 * Returns TRUE if OK, FALSE if we could not parse it.
 * The variable `dmesh_url_errno' is set accordingly.
 */
gboolean dmesh_url_parse(gchar *url, dmesh_urlinfo_t *info)
{
	guint32 ip;
	guint16 port;
	guint idx;
	guchar q;
	gchar *file = NULL;
	gchar *host = NULL;

	if (!http_url_parse(url, &port, &host, &file)) {
		dmesh_url_errno = DMESH_URL_HTTP_PARSER;
		return FALSE;
	}

	ip = host_to_ip(host);

	/*
	 * Test the first form of resource naming:
	 *
	 *    /get/1/name.txt
	 */

	if (1 == sscanf(file, "/get/%u", &idx))
		goto ok;

	/*
	 * Test the second form of resource naming:
	 *
	 *    /uri-res/N2R?urn:sha1:ABCDEFGHIJKLMN....
	 *
	 * Because of a bug in sscanf(), we have to end with a %c, otherwise
	 * the trailing text after the last parameter is NOT tested.
	 */

	idx = URN_INDEX;		/* Identifies second form */

	if (1 == sscanf(file, "/uri-res/N2R%c", &q) && q == '?')
		goto ok;
	
	dmesh_url_errno = DMESH_URL_BAD_FILE_PREFIX;
	return FALSE;

ok:
	/*
	 * Now extract the filename or the URL.
	 */

	if (idx == URN_INDEX) {
		file = strrchr(url, '/');
		g_assert(file);					/* Or we'd have not parsed above */

		/*
		 * Verify we're right on the "/N2R?" part, i.e. that we're facing
		 * an URL with an urn query, and not a get with an index:
		 * Should they send us a "/get/4294967295/name.txt", we refuse it.
		 * (4294967295 is URN_INDEX in decimal).
		 */

		if (0 != strncmp(file, "/N2R?", 5)) {
			dmesh_url_errno = DMESH_URL_RESERVED_INDEX;;
			return FALSE;					/* Index 0xffffffff is our mark */
		}

		file += 5;							/* Skip "/N2R?" */
	} else {
		guchar c;

		file = strstr(url, "/get/");
		g_assert(file);					/* Or we'd have not parsed above */

		file += sizeof("/get/") - 1;	/* Go at first index char */

		/*
		 * We have to go past the index and make sure there's a "/" after it.
		 */

		while ((c = *file++) && isdigit(c))
			/* empty */;

		if (c != '/') {
			dmesh_url_errno = DMESH_URL_NO_FILENAME;
			return FALSE;				/* Did not have "/get/234/" */
		}

		/* Ok, `file' points after the "/", at beginning of filename */
	}

	info->ip = ip;
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
		gchar *unescaped = url_unescape(file, FALSE);
		info->name = atom_str_get(unescaped);
		if (unescaped != file)
			g_free(unescaped);
	} else
		info->name = atom_str_get(file);

	dmesh_url_errno = DMESH_URL_OK;

	return TRUE;
}

/*
 * dm_expire
 *
 * Expire entries older than `agemax' in a given mesh bucket `dm'.
 * `sha1' is only passed in case we want to log the removal.
 */
static void dm_expire(
	struct dmesh *dm, guint32 agemax, const gchar *sha1)
{
	GSList *l;
	GSList *prev;
	guint32 now = (guint32) time(NULL);

	for (prev = NULL, l = dm->entries; l; /* empty */) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;
		GSList *next;

		if (now - dme->stamp <= agemax) {
			prev = l;
			l = l->next;
			continue;
		}

		/*
		 * Remove the entry.
		 *
		 * XXX instead of removing, maybe we can schedule a HEAD refresh
		 * XXX to see whether the entry is still valid.
		 */

		g_assert(dm->count > 0);

		if (dbg > 4)
			printf("MESH %s: EXPIRED \"%s\", age=%u\n",
				sha1_base32(sha1),
				dmesh_urlinfo_to_gchar(&dme->url),
				(guint32) (now - dme->stamp));

		dmesh_entry_free(dme);
		dm->count--;

		next = l->next;
		l->next = NULL;
		g_slist_free_1(l);

		if (prev == NULL)				/* At the head of the list */
			dm->entries = next;
		else
			prev->next = next;

		l = next;
	}
}

/*
 * dm_remove
 *
 * Remove specified entry from mesh bucket, if it is older than `stamp'.
 * Returns TRUE if entry was removed or not found, FALSE otherwise.
 */
static gboolean dm_remove(struct dmesh *dm,
	guint32 ip, guint16 port, guint idx, const gchar *name, guint32 stamp)
{
	GSList *l;

	g_assert(dm);
	g_assert(dm->count > 0);

	for (l = dm->entries; l; l = l->next) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;

		if (
			dme->url.ip == ip		&&
			dme->url.port == port	&&
			dme->url.idx == idx		&&
			0 == strcmp(dme->url.name, name)
		) {
			/*
			 * Found entry, remove it if older than `stamp'.
			 *
			 * If it's equal, we don't remove it either, to prevent addition
			 * of an entry we already have.
			 */

			if (dme->stamp >= stamp)
				return FALSE;

			dm->entries = g_slist_remove(dm->entries, dme);
			dm->count--;
			dmesh_entry_free(dme);
			break;
		}
	}

	return TRUE;
}

/*
 * dmesh_dispose
 *
 * Dispose of the entry slot, which must be empty.
 */
static void dmesh_dispose(const gchar *sha1)
{
	gpointer key;
	gpointer value;
	gboolean found;

	found = g_hash_table_lookup_extended(mesh, sha1, &key, &value);

	g_assert(found);
	g_assert(((struct dmesh *) value)->count == 0);
	g_assert(((struct dmesh *) value)->entries == NULL);

	atom_sha1_free(key);
	wfree(value, sizeof(struct dmesh));

	g_hash_table_remove(mesh, sha1);
}

/*
 * dmesh_fill_info
 *
 * Fill URL info from externally supplied sha1, ip, port, idx and name.
 * When `idx' is 0, then `name' is ignored, and we use the stringified SHA1.
 */
static void dmesh_fill_info(dmesh_urlinfo_t *info,
	const gchar *sha1, guint32 ip, guint16 port, guint idx, gchar *name)
{
	static gchar sha1_urn[SHA1_BASE32_SIZE + sizeof("urn:sha1:")];

	info->ip = ip;
	info->port = port;
	info->idx = idx;

	if (idx == URN_INDEX) {
		gm_snprintf(sha1_urn, sizeof(sha1_urn),
			"urn:sha1:%s", sha1_base32(sha1));
		info->name = sha1_urn;
	} else
		info->name = name;
}

/*
 * dmesh_remove
 *
 * Remove entry from mesh due to a failed download attempt.
 */
void dmesh_remove(const gchar *sha1,
	guint32 ip, guint16 port, guint idx, gchar *name)
{
	struct dmesh *dm;
	dmesh_urlinfo_t info;

	/*
	 * We're called because the download failed, so we must ban the URL
	 * to prevent further insertion in the mesh.
	 */

	dmesh_fill_info(&info, sha1, ip, port, idx, name);
	dmesh_ban_add(&info, 0);

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 */

	dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

	if (dm == NULL)				/* Nothing for this SHA1 key */
		return;

	(void) dm_remove(dm, ip, port, idx, info.name, MAX_STAMP);

	/*
	 * If there is nothing left, clear the mesh entry.
	 */

	if (dm->count == 0) {
		g_assert(dm->entries == NULL);
		dmesh_dispose(sha1);
	}
}

/*
 * dmesh_raw_add
 *
 * Add entry to the download mesh, indexed by the binary `sha1' digest.
 * If `stamp' is 0, then the current time is used.
 *
 * If `idx' is URN_INDEX, then we can access this file only through an
 * /uri-res request, the URN being given as `name'.
 *
 * Returns whether the entry was added in the mesh, or was discarded because
 * it was the oldest record and we have enough already.
 */
static gboolean dmesh_raw_add(gchar *sha1, dmesh_urlinfo_t *info, guint32 stamp)
{
	struct dmesh_entry *dme;
	struct dmesh *dm;
	guint32 now = (guint32) time(NULL);
	guint32 ip = info->ip;
	guint16 port = info->port;
	guint idx = info->idx;
	gchar *name = info->name;

	if (stamp == 0 || stamp > now)
		stamp = now;

	if (now - stamp > MAX_LIFETIME)
		return FALSE;

	/*
	 * Reject if this is for our host, or if the host is a private/hostile IP.
	 */

	if (ip == listen_ip() && port == listen_port)
		return FALSE;

	if (!host_is_valid(ip, port))
		return FALSE;

	if (hostiles_check(ip))
		return FALSE;

	/*
	 * See whether this URL is banned from the mesh.
	 */

	if (dmesh_is_banned(info))
		return FALSE;

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 *
	 * If we don't, create a new structure and insert it in the table.
	 *
	 * If we have, make sure we remove any existing older entry first,
	 * to avoid storing duplicates (entry is removed only if found and older
	 * than the one we're trying to add).
	 */

	dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

	if (dm == NULL) {
		dm = walloc(sizeof(*dm));

		dm->count = 0;
		dm->entries = NULL;

		g_hash_table_insert(mesh, atom_sha1_get(sha1), dm);
	} else {
		g_assert(dm->count > 0);

		dm_expire(dm, MAX_LIFETIME, sha1);

		/*
		 * If dm_remove() returns FALSE, it means that we found the entry
		 * in the mesh, but it is not older than the supplied stamp.  So
		 * we have the entry already, and reject this duplicate.
		 */

		if (dm->count && !dm_remove(dm, ip, port, idx, name, stamp))
			return FALSE;
	}

	/*
	 * Allocate new entry.
	 */

	dme = (struct dmesh_entry *) walloc(sizeof(*dme));

	dme->inserted = now;
	dme->stamp = stamp;
	dme->url.ip = ip;
	dme->url.port = port;
	dme->url.idx = idx;
	dme->url.name = atom_str_get(name);

    if (dbg)
		printf("dmesh entry created, name %p: %s\n",
				dme->url.name, dme->url.name);

	/*
	 * The entries are sorted by time.  We're going to unconditionally add
	 * the new entry, and then we'll prune the last item (oldest) if we
	 * reached our maximum capacity.
	 */

	dm->entries = g_slist_insert_sorted(dm->entries, dme, dmesh_entry_cmp);
	dm->last_update = now;

	if (dm->count == MAX_ENTRIES) {
		struct dmesh_entry *last =
			(struct dmesh_entry *) g_slist_last(dm->entries)->data;

		dm->entries = g_slist_remove(dm->entries, last);

		dmesh_entry_free(last);

		if (last == dme)		/* New entry turned out to be the oldest */
			dme = NULL;
	} else
		dm->count++;

	/*
	 * We got a new entry that could be used for swarming if we are
	 * downloading that file.
	 */

	if (dme != NULL)
		file_info_try_to_swarm_with(name, idx, ip, port, sha1);

	return dme != NULL;			/* TRUE means we added the entry */
}

/*
 * dmesh_add
 *
 * Same as dmesh_raw_add(), but this is for public consumption.
 */
gboolean dmesh_add(gchar *sha1,
	guint32 ip, guint16 port, guint idx, gchar *name, guint32 stamp)
{
	dmesh_urlinfo_t info;

	/*
	 * Translate the supplied arguments: if idx is URN_INDEX, then `name'
	 * is the filename but we must use the urn:sha1 instead, as URN_INDEX
	 * is our mark to indicate an /uri-res/N2R? URL (with an urn:sha1).
	 */

	dmesh_fill_info(&info, sha1, ip, port, idx, name);
	return dmesh_raw_add(sha1, &info, stamp);
}

/*
 * dmesh_urlinfo
 *
 * Format the URL described by `info' into the provided buffer `buf', which
 * can hold `len' bytes.
 *
 * Returns length of formatted entry, -1 if the URL would be larger than
 * the buffer.  If `quoting' is non-NULL, set it to indicate whether the
 * formatted URL should be quoted if emitted in a header, because it
 * contains a "," character.
 */
static gint dmesh_urlinfo(
	const dmesh_urlinfo_t *info, gchar *buf, gint len, gboolean *quoting)
{
	gint rw;
	gint maxslen = len - 1;			/* Account for trailing NUL */

	g_assert(len > 0);
	g_assert(info->name != NULL);

	if (info->port == HTTP_PORT)
		rw = gm_snprintf(buf, len, "http://%s", ip_to_gchar(info->ip));
	else
		rw = gm_snprintf(buf, len, "http://%s",
			ip_port_to_gchar(info->ip, info->port));

	if (rw >= maxslen)
		return -1;

	if (info->idx == URN_INDEX) {
		rw += gm_snprintf(&buf[rw], len - rw, "/uri-res/N2R?%s", info->name);
		if (quoting != NULL)
			*quoting = FALSE;			/* No "," in the generated URL */
	} else {
		rw += gm_snprintf(&buf[rw], len - rw, "/get/%u/", info->idx);

		/*
		 * Write filename, URL-escaping it directly into the buffer.
		 */

		if (rw < maxslen) {
			gint re = url_escape_into(info->name, &buf[rw], len - rw);

			if (re < 0)
				return -1;

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

	return (rw >= maxslen) ? -1 : rw;
}

/*
 * dmesh_urlinfo_to_gchar
 *
 * Format the `info' URL and return pointer to static string.
 */
static gchar *dmesh_urlinfo_to_gchar(const dmesh_urlinfo_t *info)
{
	static gchar urlstr[1024];

	(void) dmesh_urlinfo(info, urlstr, sizeof(urlstr) - 1, NULL);
	urlstr[sizeof(urlstr) - 1] = '\0';

	return urlstr;
}

/*
 * dmesh_entry_url_stamp
 *
 * Format dmesh_entry in the provided buffer, as an URL with an appended
 * timestamp in ISO format, GMT time.
 *
 * Returns length of formatted entry, -1 if the URL would be larger than
 * the buffer.
 */
static gint dmesh_entry_url_stamp(
	const struct dmesh_entry *dme, gchar *buf, gint len)
{
	gint rw;
	gint maxslen = len - 1;			/* Account for trailing NUL */
	gboolean quoting;

	/*
	 * Format the URL info first.
	 */

	rw = dmesh_urlinfo((const dmesh_urlinfo_t *) &dme->url, buf, len, &quoting);

	if (rw < 0)
		return -1;

	/*
	 * If quoting is required, we need to surround the already formatted
	 * string into "quotes".
	 */

	if (quoting) {
		if (rw + 2 >= maxslen)		/* Not enough room for 2 quotes */
			return -1;

		g_memmove(buf + 1, buf, rw);
		buf[0] = '"';
		buf[++rw] = '"';
		buf[++rw] = '\0';
	}

	/*
	 * Append timestamp.
	 */

	rw += gm_snprintf(&buf[rw], len - rw,
		" %s", date_to_iso_gchar((time_t) dme->stamp));

	return (rw >= maxslen) ? -1 : rw;
}

/*
 * dmesh_entry_to_gchar
 *
 * Format the `dme' mesh entry as "URL timestamp" and return pointer to
 * static string.
 */
static const gchar *dmesh_entry_to_gchar(const struct dmesh_entry *dme)
{
	static gchar urlstr[1024];

	(void) dmesh_entry_url_stamp(dme, urlstr, sizeof(urlstr) - 1);
	urlstr[sizeof(urlstr) - 1] = '\0';

	return urlstr;
}

/*
 * dmesh_alternate_location
 *
 * Build alternate location header for a given SHA1 key.  We generate at
 * most `size' bytes of data into `alt'.
 *
 * `ip' is the host to which those alternate locations are meant: we skip
 * any data pertaining to that host.
 *
 * `last_sent' is the time at which we sent some previous alternate locations.
 * If there has been no change to the mesh since then, we'll return an empty
 * string.  Otherwise we return entries inserted after `last_sent'.
 *
 * Returns amount of generated data.
 */
gint dmesh_alternate_location(const gchar *sha1,
	gchar *buf, gint size, guint32 ip, guint32 last_sent)
{
	gchar url[1024];
	struct dmesh *dm;
	gint len;
	GSList *l;
	gint nurl = 0;
	gint nselected = 0;
	struct dmesh_entry *selected[MAX_ENTRIES];
	gint i;
	gint min_url_len;
	gint maxslen = size - 1;		/* Account for trailing NUL */

	g_assert(sha1);
	g_assert(buf);
	g_assert(size >= 0);
	
	/*
	 * Start filling the buffer.
	 */

	len = gm_snprintf(buf, size, "X-Gnutella-Alternate-Location:\r\n");
	if (len >= maxslen)
		return 0;

	/*
	 * Find mesh entry for this SHA1, and check whether we anything (new).
	 */

	dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

	if (dm == NULL)						/* SHA1 unknown */
		return 0;

	if (dm->last_update <= last_sent)	/* No new insertion */
		return 0;

	/*
	 * Expire old entries.  If none remain, free entry and return.
	 */

	dm_expire(dm, MAX_LIFETIME, sha1);

	if (dm->count == 0) {
		g_assert(dm->entries == NULL);
		dmesh_dispose(sha1);
		return 0;
	}

	/*
	 * Go through the list, selecting new entries that can fit.
	 * We'll do two passes.  The first pass identifies the candidates.
	 * The second pass randomly selects items until we fill the room
	 * allocated.
	 */

	memset(selected, 0, sizeof(selected));

	/*
	 * First pass.
	 */

	for (i = 0, l = dm->entries; l; l = l->next) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;

		if (dme->inserted <= last_sent)
			continue;

		if (dme->url.ip == ip)
			continue;

		g_assert(i < MAX_ENTRIES);

		selected[i++] = dme;
	}

	nselected = i;

	if (nselected == 0)
		return 0;

	g_assert(nselected <= dm->count);

	/*
	 * Second pass.
	 */

	min_url_len = sizeof("\thttp://1.2.3.4/get/1/x 2002-06-09T14:54:42Z\r\n");

	for (i = 0; i < nselected && (size - len) > min_url_len; i++) {
		struct dmesh_entry *dme;
		gint nleft = nselected - i;
		gint npick = random_value(nleft - 1);
		gint j;
		gint n;
		gint url_len;

		/*
		 * The `npick' variable is the index of the selected entry, all
		 * NULL pointers we can encounter on our path not-withstanding.
		 */

		for (j = 0, n = npick; n >= 0; /* empty */) {
			g_assert(j < nselected);
			if (selected[j] == NULL) {
				j++;
				continue;
			}
			n--;
		}

		g_assert(j < nselected);

		dme = selected[j];
		selected[j] = NULL;				/* Can't select same entry twice */

		g_assert(dme->inserted > last_sent);

		url_len = dmesh_entry_url_stamp(dme, url, sizeof(url));

		if (url_len < 0)				/* Too big for the buffer */
			continue;

		if (nurl) {
			/*
			 * We need to finish the existing URL with ",\r\n", then we
			 * need our own URL, i.e. a minimum of "\t" and "\r\n" to close
			 * the header if we don't append anything else, plus the trailing
			 * NUL.
			 */
			if (url_len + 6 >= size - len)	/* Needs "\t" and 2*"\r\n" + "," */
				continue;
			len += gm_snprintf(&buf[len], size - len, ",\r\n");
		} else {
			/*
			 * We just need to be able to emit our URL and close the header,
			 * i.e. we need "\t" and "\r\n" to end, plus the trailing NUL.
			 */
			if (url_len + 3 >= size - len)	/* Needs "\t" and "\r\n" */
				continue;
		}

		g_assert((url_len + 1 + len) < size);
		len += gm_snprintf(&buf[len], size - len, "\t%s", url);
		g_assert(len + 2 < size);

		nurl++;
	}

	g_assert(len < size);

	if (nurl)
		len += gm_snprintf(&buf[len], size - len, "\r\n");

#if 0
	g_assert(len < size);
#endif /* 0 */
	if (len >= size) {
		g_error("BUG: dmesh_alternate_location: filled buffer completely "
			"(size=%d, len=%d, nurl=%d)", size, len, nurl);
		return 0;
	}

	return (nurl > 0) ? len : 0;
}

/*
 * A simple container for the dmesh info that the deferred checking
 * code needs, although to be honest it may be worth refactoring the
 * dmesh code so it all works on dmesh_entries?
 */

typedef struct {
    dmesh_urlinfo_t *dmesh_url;	/* The URL details */
    guint32 stamp;				/* Timestamp */
} dmesh_deferred_url_t;

/*
 * dmesh_get_nonurn_altlocs
 *
 * Create a list of nonurn alternative locations for a given sha1.
 * This is used in preference to self-consitancy checking as these
 * urls are already "known" to be valid and hence we do not waste
 * potentially valid urls on a "all or nothing" approach.
 */
static GSList *dmesh_get_nonurn_altlocs(const gchar *sha1)
{
    struct dmesh *dm;
    GSList *l;
	GSList *nonurn_altlocs = NULL;

    g_assert(sha1);

    dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

    if (dm == NULL)				/* SHA1 unknown */
		return NULL;

	for (l = dm->entries; l ; l = l->next) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;
			
		if (dme->url.idx != URN_INDEX)
			nonurn_altlocs = g_slist_append(nonurn_altlocs, dme);
	}

    return nonurn_altlocs;
}

/*
 * dmesh_defer_nourn_altloc
 *
 * This function defers adding a proposed alternate location that has been
 * given as an old style string (i.e. not a URN). After
 * dmesh_collect_locations() has parsed all the alt locations another
 * function (dmesh_check_deferred_altlocs) will be called to make a
 * judgement on the quality of these results, and determine whether they
 * should be added to the dmesh.
 */

static GSList *dmesh_defer_nonurn_altloc(
	GSList *list, dmesh_urlinfo_t *url, guint32 stamp)
{
    dmesh_deferred_url_t *defer;

    /* Allocate a structure */
    defer = walloc0(sizeof(dmesh_deferred_url_t));

    /*
	 * Copy the structure, beware of atoms.
	 */

    defer->dmesh_url = walloc(sizeof(dmesh_urlinfo_t));
	*defer->dmesh_url = *url;		/* struct copy */
    defer->dmesh_url->name = atom_str_get(url->name);
    defer->stamp = stamp;

	if (dbg)
		printf("Defering nonurn altloc str=%px:%s\n",
			defer->dmesh_url->name, defer->dmesh_url->name);

    /* Add to list */
    return g_slist_append(list, defer);
}

/*
 * dmesh_free_deferred_altloc
 *
 * Called to deallocate the dmesh_urlinfo and de-reference names
 * from the GSList. Intended to be called from a g_slist_foreach. The
 * list itself needs to be freed afterwards
 */
static void dmesh_free_deferred_altloc(
    dmesh_deferred_url_t *info, gpointer user_data)
{
	atom_str_free(info->dmesh_url->name);
	wfree(info->dmesh_url, sizeof(dmesh_urlinfo_t));
	wfree(info, sizeof(*info));
}

/*
 * dmesh_check_deferred_against_existing
 *
 * This routine checks deferred dmesh entries against any existing
 * nonurn alternative locations. The two factors that control the
 * quality of hits queued are:
 *
 * a) Fuzzy factor of compares
 * b) Number of the altlocs they have to match (threshold)
 *
 * These factors are currently semi-empirical guesses and hardwired
 *
 * NOTE: this is an O(m*n) process, when `m' is the amount of new entries
 * and `n' the amount of existing entries.
 */
static void dmesh_check_deferred_against_existing(
    gchar *sha1, GSList *existing_urls, GSList *deferred_urls)
{
    GSList *ex, *def;
	GSList *adding = NULL;
    gulong score;
    gint matches;
    gint threshold = g_slist_length(existing_urls);
	time_t now = time(NULL);

    /* We want to match at least 2 or more entries, going for 50% */
    threshold = (threshold < 3) ? 2 : (threshold / 2);
    
	for (def = deferred_urls; def; def = def->next) {
		dmesh_deferred_url_t *d = def->data;
		matches = 0;

		if (dbg > 4)
			printf("Checking deferred url 0x%lx (str=0x%lx:%s)\n",
				(glong) d, (glong) d->dmesh_url->name, d->dmesh_url->name);

		for (ex = existing_urls; ex; ex = ex->next) {
			struct dmesh_entry *dme = ex->data;
			score = fuzzy_compare(dme->url.name, d->dmesh_url->name);
			if (score > FUZZY_MATCH)
				matches++;
		}

		/*
		 * We can't add the entry in the mesh in the middle of the
		 * traversal: if we reach the max amount of entries in the mesh,
		 * we'll free some of them, and since our `existing_urls' items
		 * directly refer the dmesh_entry structures, that would be horrible!
		 *		--RAM, 05/02/2003
		 */

		if (matches >= threshold)
			adding = g_slist_prepend(adding, d);
		else {
			dmesh_urlinfo_t *url = d->dmesh_url;
			if (dbg)
				g_warning("dumped potential dmesh entry:\n%s\n\t"
					"(only matched %d of the others, needed %d)",
					url->name, matches, threshold);
		}
	} /* for def */

	for (def = adding; def; def = def->next) {
		dmesh_deferred_url_t *d = def->data;
		dmesh_urlinfo_t *url = d->dmesh_url;
		gboolean ok;

		ok = dmesh_raw_add(sha1, url, d->stamp);

		if (dbg > 4) {
			printf("MESH %s: %s deferred \"%s\", stamp=%u age=%u\n",
				sha1_base32(sha1),
				ok ? "added" : "rejected",
				dmesh_urlinfo_to_gchar(url), (guint32) d->stamp,
				(guint32) (now - MIN(d->stamp, now)));
		}
	}

	g_slist_free(adding);
}

/*
 * dmesh_check_deferred_against_themselves
 *
 * This routine checks deferred dmesh entries against themselves. They
 * have to be 100% consistent with what was being passed otherwise we
 * are conservative a throw them away. The main factor is the fuzzy
 * factor of the compare.
 *
 * Apoligies for the returns but this function doesn't need to clean up
 * after itself yet.
 */
static void dmesh_check_deferred_against_themselves(
	gchar *sha1, GSList *deferred_urls)
{
    GSList *l = deferred_urls;
    gulong score;
    dmesh_deferred_url_t *first;
	dmesh_deferred_url_t *current;

    first = l->data;
    l = g_slist_next(l);

	if (NULL == l) { /* Its probably correct, should we bin it? */
		if (dbg > 4)
			printf("Only one altloc to check, currently dumping:\n%s\n",
				first->dmesh_url->name);
		return;
	}
    
	for (/*empty */; l; l = g_slist_next(l)) {
		current = l->data;
		score = fuzzy_compare(first->dmesh_url->name, current->dmesh_url->name);
		if (score < FUZZY_DROP) {
			/* When anything fails, it's all over */
			if (dbg > 4)
				printf("dmesh_check_deferred_against_themselves failed with:\n"
					"%s\n\t"
					"(only scoring %lu against:\n\t"
					"%s\n",
				current->dmesh_url->name, score, first->dmesh_url->name);
			return;
		}
	}

    /* We made it this far, they must all match, lets add them to the dmesh */
	for (l = deferred_urls; l; l = l->next) {
		dmesh_deferred_url_t *def = l->data;
		dmesh_urlinfo_t *url = def->dmesh_url;
		gboolean ok;

		ok = dmesh_raw_add(sha1, url, def->stamp);

		if (dbg > 4) {
			time_t now = time(NULL);
			printf("MESH %s: %s consistent deferred \"%s\", stamp=%u age=%u\n",
				sha1_base32(sha1),
				ok ? "added" : "rejected",
				dmesh_urlinfo_to_gchar(url), (guint32) def->stamp,
				(guint32) (now - MIN(def->stamp, now)));
		}
	}

    return;
}

/*
 * dmesh_check_deferred_altlocs
 *
 * This function is called once dmesh_collect_locations is done and
 * makes it then decides how its going to vet the quality of the
 * deferred nonurn altlocs before decing if they are going to be added
 * for the given sha1.
 *
 * A couple of approaches are taken:
 * a) if any non-urn urls already exist compare against them and add
 * the ones that match
 * a) otherwise only add urls if they are all the same(ish)
 *
 * Another possible algorithm (majority wins) has been tried but
 * empirically did allow the occasional dmesh pollution. As we are
 * going for  a non-polluted dmesh we shall be conservative. Besides
 * using urn's for files is generally a better idea.
 *
 */
static void dmesh_check_deferred_altlocs(
	gchar *sha1, GSList *deferred_urls)
{
    GSList *existing_urls;

    if (NULL == deferred_urls)		/* Nothing to do */
		return;
    
    existing_urls = dmesh_get_nonurn_altlocs(sha1);

    if (existing_urls) {
		dmesh_check_deferred_against_existing(sha1,
			existing_urls, deferred_urls);
		g_slist_free(existing_urls);
	} else
		dmesh_check_deferred_against_themselves(sha1, deferred_urls);

    g_slist_foreach(deferred_urls, (GFunc) dmesh_free_deferred_altloc, NULL);
    g_slist_free(deferred_urls);
}

/*
 * dmesh_collect_sha1
 *
 * Parse the value of the X-Gnutella-Content-URN header in `value', looking
 * for a SHA1.  When found, the SHA1 is extracted and placed into the given
 * `digest' buffer.
 *
 * Returns whether we successfully extracted the SHA1.
 */
gboolean dmesh_collect_sha1(gchar *value, gchar *digest)
{
	gchar *p = value;

	for (;;) {
		guchar c;

		/*
		 * Skip leading spaces, if any.
		 */

		while ((c = *p)) {
			if (!isspace(c))
				break;
			p++;
		}

		if (huge_extract_sha1(p, digest))
			return TRUE;

		/*
		 * Advance past the next ',', if any.
		 */

		while ((c = *p++)) {
			if (c == ',')
				break;
		}

		if (c == '\0')			/* Reached end of string w/o finding a SHA1 */
			break;
	}

	return FALSE;
}

/*
 * dmesh_collect_locations
 *
 * Parse value of the "X-Gnutella-Alternate-Location" to extract alternate
 * sources for a given SHA1 key.
 */
void dmesh_collect_locations(gchar *sha1, gchar *value, gboolean defer)
{
	gchar *p = value;
	guchar c;
	time_t now = time(NULL);
    GSList *nonurn_altlocs = NULL;

	for (;;) {
		gchar *url;
		gchar *date;
		time_t stamp;
		gboolean ok;
		dmesh_urlinfo_t info;
		gboolean non_space_seen;
		gboolean skip_date;
		gboolean in_quote;

		/*
		 * Find next space, colon or EOS (End of String).
		 * Everything from now to there will be an URL.
		 * All leading spaces are skipped.
		 */

		url = NULL;
		non_space_seen = FALSE;
		in_quote = FALSE;
		info.name = NULL;

		while ((c = *p)) {
			if (!non_space_seen) {
				if (isspace(c))
					goto next;
				non_space_seen = TRUE;
				url = p;
			}

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
				goto next;

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
				if (
					(p[1] == 'h' || p[1] == 'H') &&
					0 == g_ascii_strncasecmp(&p[1], "http://", 7)

				)
					break;
				if (p[1] != ' ')
					goto next;
			}

			if (c == ' ' || c == ',')
				break;
	
		next:
			p++;
		}

		if (url == NULL) {				/* Only seen spaces */
			if (c == '\0')
				goto finish;
			continue;
		}

		if (c == '\0' && p == url)		/* Empty string remained */
			goto finish;

		/*
		 * Parse URL.
		 */

		g_assert((guchar) *p == c);

		if (*url == '"') {				/* URL enclosed in quotes? */
			url++;						/* Skip that needless quote */
			if (c != '"')
				g_warning("Alternate-Location URL \"%s\" started with leading "
					"quote, but did not end with one!", url);
		}

		/*
		 * Once dmesh_url_parse() has been called and returned `ok', we'll
		 * have a non-NULL `info.name' field.  This is an atom that must
		 * get freed: instead of saying `continue', we must `goto free_urlinfo'
		 * so that this atom can be freed.
		 */

		*p = '\0';
		ok = dmesh_url_parse(url, &info);

		if (dbg > 6)
			printf("MESH (parsed=%d): \"%s\"\n", ok, url);

		if (!ok)
			g_warning("cannot parse Alternate-Location URL \"%s\": %s",
				url, dmesh_url_strerror(dmesh_url_errno));

		*p = c;

		if (c == '"')				/* URL ended with a quote, skip it */
			c = *(++p);

		/*
		 * Maybe there is no date following the URL?
		 */

		if (c == '\0')				/* Reached end of string */
			goto finish;
		if (c == ',') {				/* There's no following date then */
			p++;					/* Skip separator */
			goto free_urlinfo;		/* continue */
		}

		skip_date = !ok;			/* Skip date if we did not parse the URL */

		/*
		 * Advance to next ',', expecting a date.
		 */

		date = ++p;

	more_date:
		while ((c = *p)) {
            /*
             * Limewire has a bug not to use the ',' separator, so
             * we assume a new urn is starting with "http://"
             *      -Richard 23/11/2002
             */

            if (
				(c == 'h' || c == 'H') &&
				0 == g_ascii_strncasecmp(p, "http://", 7)
			)
				break;

            if (c == ',')
				break;
			p++;
		}

		/*
		 * Disambiguate "Mon, 17 Jun 2002 07:53:14 +0200"
		 */

		if (c == ',' && p - date == 3) {
			p++;
			goto more_date;
		}

		if (skip_date) {				/* URL was not parsed, just skipping */
			if (c == '\0')				/* Reached end of string */
				goto finish;
            if (c == ',')
                p++;					/* Skip the "," separator */
			goto free_urlinfo;			/* continue */
		}

		/*
		 * Parse date, if present.
		 */

		if (p != date) {
			g_assert((guchar) *p == c);

			*p = '\0';
			stamp = date2time(date, &now);

			if (dbg > 6)
				printf("MESH (stamp=%u): \"%s\"\n", (guint32) stamp, date);

			if (stamp == -1) {
				g_warning("cannot parse Alternate-Location date: %s", date);
				stamp = 0;
			}

			*p = c;
		} else
			stamp = 0;

		/*
		 * If we have a /uri-res/N2R?urn:sha1, make sure it's matching
		 * the SHA1 of the entry for which we're keeping those alternate
		 * locations.
		 */

		if (info.idx == URN_INDEX) {
			gchar digest[SHA1_RAW_SIZE];

			ok = huge_extract_sha1(info.name, digest);
			if (!ok) {
				g_warning("malformed /uri-res/N2R? Alternate-Location: %s",
					info.name);
				goto skip_add;
			}

			ok = sha1_eq(sha1, digest);
			if (!ok) {
				g_warning("mismatch in /uri-res/N2R? Alternate-Location "
					"for SHA1=%s: got %s", sha1_base32(sha1), info.name);
				goto skip_add;
			}

			/* FALL THROUGH */

			/*
			 * Enter URL into mesh - only if it's a URN_INDEX
			 * to avoid dmesh pollution.
			 */

			ok = dmesh_raw_add(sha1, &info, stamp);

		} else {
			if (fuzzy_filter_dmesh && defer) {
				/*
				 * For named altlocs, defer so we can check they are ok,
				 * all in one block.
				 */
				nonurn_altlocs = dmesh_defer_nonurn_altloc(nonurn_altlocs,
						&info, stamp);
				goto nolog;
			} else
				ok = dmesh_raw_add(sha1, &info, stamp);
		}

	skip_add:
		if (dbg > 4)
			printf("MESH %s: %s \"%s\", stamp=%u age=%u\n",
				sha1_base32(sha1),
				ok ? "added" : "rejected",
				dmesh_urlinfo_to_gchar(&info), (guint32) stamp,
				(guint32) (now - MIN(stamp, now)));

	nolog:
		if (c == '\0')				/* Reached end of string */
			goto finish;

        if (c == ',')
            p++;					/* Skip separator */

	free_urlinfo:
		if (info.name)
			atom_str_free(info.name);

		continue;

	finish:
		if (info.name)
			atom_str_free(info.name);

		break;
	}

	/*
	 * Once everyone is done we can sort out deferred urls, if any.
	 */

	if (fuzzy_filter_dmesh && defer) {
		/*
		 * We only defer when collection from live headers.
		 */

		dmesh_check_deferred_altlocs(sha1, nonurn_altlocs);
	}

    return;
}

/*
 * dmesh_alt_loc_fill
 *
 * Fill buffer with at most `count' alternative locations for sha1.
 * Returns the amount of locations inserted.
 */
static gint dmesh_alt_loc_fill(
	const gchar *sha1, dmesh_urlinfo_t *buf, gint count)
{
	struct dmesh *dm;
	GSList *l;
	gint i;

	g_assert(sha1);
	g_assert(buf);
	g_assert(count > 0);

	dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

	if (dm == NULL)					/* SHA1 unknown */
		return 0;

	for (i = 0, l = dm->entries; l && i < count; l = l->next) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;
		dmesh_urlinfo_t *from, *to;

		g_assert(i < MAX_ENTRIES);

		from = &dme->url;
		to = &buf[i++];

		to->ip = from->ip;
		to->port = from->port;
		to->idx = from->idx;
		to->name = from->name;
	}

	return i;
}

/*
 * dmesh_check_results_set
 *
 * Parse query hit (result set) for entries whose SHA1 match something
 * we have into the mesh or share, and insert them if needed.
 */
void dmesh_check_results_set(gnet_results_set_t *rs)
{
	GSList *l;
	time_t now = time(NULL);

	for (l = rs->records; l; l = l->next) {
		gnet_record_t *rc = (gnet_record_t *) l->data;
		dmesh_urlinfo_t info;
		gboolean has = FALSE;

		if (rc->sha1 == NULL)
			continue;

		/*
		 * If we have an entry for this SHA1 in the mesh already,
		 * then we can update it for that entry.
		 *
		 * If the entry is not in the mesh already, look whether we're
		 * sharing this SHA1.
		 */

		has = (NULL != g_hash_table_lookup(mesh, rc->sha1));

		if (!has) {
			struct shared_file *sf = shared_file_by_sha1(rc->sha1);
			if (sf != NULL && sf != SHARE_REBUILDING)
				has = TRUE;
		}

		if (has) {
			dmesh_fill_info(&info, rc->sha1, rs->ip, rs->port, URN_INDEX, NULL);
			(void) dmesh_raw_add(rc->sha1, &info, now);

			/*
			 * If we have further alt-locs specified in the query hit, add
			 * them to the mesh and dispose of them.
			 */

			if (rc->alt_locs != NULL) {
				gint i;
				gnet_host_vec_t *alt = rc->alt_locs;

				for (i = alt->hvcnt - 1; i >= 0; i--) {
					struct gnutella_host *h = &alt->hvec[i];

					dmesh_fill_info(&info, rc->sha1, h->ip, h->port,
						URN_INDEX, NULL);
					(void) dmesh_raw_add(rc->sha1, &info, now);
				}

				search_free_alt_locs(rc);		/* Read them, free them! */
			}

			g_assert(rc->alt_locs == NULL);
		}
	}
}

#define DMESH_MAX	MAX_ENTRIES

/*
 * dmesh_multiple_downloads
 *
 * This is called when swarming is first requested to get a list of all the
 * servers with the requested file known by dmesh.
 * It creates a new download for every server found.
 *
 * `sha1': (atom) the SHA1 of the file
 * `size': the original file size
 */
void dmesh_multiple_downloads(
	gchar *sha1, guint32 size, struct dl_file_info *fi)
{
	dmesh_urlinfo_t buffer[DMESH_MAX];
	dmesh_urlinfo_t *p;
	gint n;
	time_t now;

	n = dmesh_alt_loc_fill(sha1, buffer, DMESH_MAX);
	if (n == 0)
		return;

	now = time(NULL);

	for (p = buffer; n; n--, p++) {
		if (dbg > 2)
			printf("ALT-LOC queuing from MESH: %s\n",
				dmesh_urlinfo_to_gchar(p));

		download_auto_new(p->name, size, p->idx, p->ip, p->port,
			blank_guid, sha1, now, FALSE, fi);
	}
}

/*
 * dmesh_store_kv
 *
 * Store key/value pair in file.
 */
static void dmesh_store_kv(gpointer key, gpointer value, gpointer udata)
{
	const struct dmesh *dm = (const struct dmesh *) value;
	GSList *l;
	FILE *out = (FILE *) udata;

	fprintf(out, "%s\n", sha1_base32((const gchar *) key));

	for (l = dm->entries; l; l = l->next) {
		const struct dmesh_entry *dme = (struct dmesh_entry *) l->data;
		fprintf(out, "%s\n", dmesh_entry_to_gchar(dme));
	}

	fputs("\n", out);
}

/* XXX add dmesh_store_if_dirty() and export that only */

typedef void (*header_func_t)(FILE *out);

/*
 * dmesh_hash_store
 *
 * Store hash table `hash' into `file'.
 * The file header is emitted by `header_cb'.
 * The storing callback for each item is `store_cb'.
 */
static void dmesh_store_hash(
	const gchar *what, GHashTable *hash, const gchar *file,
	header_func_t header_cb, GHFunc store_cb)
{
	FILE *out;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), file);
	out = file_config_open_write(what, &fp);

	if (!out)
		return;

	(*header_cb)(out);
	g_hash_table_foreach(hash, store_cb, out);

	file_config_close(out, &fp);
}

/*
 * dmesh_header_print
 *
 * Prints header to dmesh store file.
 */
static void dmesh_header_print(FILE *out)
{
	file_config_preamble(out, "Download mesh");

	fputs(	"#\n# Format is:\n"
			"#   SHA1\n"
			"#   URL1 timestamp1\n"
			"#   URL2 timestamp2\n"
			"#   <blank line>\n"
			"#\n\n",
			out);
}

/*
 * dmesh_store
 *
 * Store download mesh onto file.
 * The download mesh is normally stored in ~/.gtk-gnutella/dmesh.
 */
void dmesh_store(void)
{
	dmesh_store_hash("download mesh",
		mesh, dmesh_file, dmesh_header_print, dmesh_store_kv);
}

/*
 * dmesh_retrieve
 *
 * Retrieve download mesh and add entries that have not expired yet.
 * The mesh is normally retrieved from ~/.gtk-gnutella/dmesh.
 */
static void dmesh_retrieve(void)
{
	FILE *in;
	gchar tmp[1024];
	gchar sha1[SHA1_RAW_SIZE];
	gboolean has_sha1 = FALSE;
	gboolean skip = FALSE;
	gint line = 0;
	file_path_t fp;

	file_path_set(&fp, settings_config_dir(), dmesh_file);
	in = file_config_open_read("download mesh", &fp, 1);

	if (!in)
		return;

	/*
	 * Retrieval algorithm:
	 *
	 * Lines starting with a # are skipped.
	 *
	 * We read the SHA1 first, validate it.  The remaining line up to a
	 * blank line are attached sources for this SHA1.
	 */

	while (fgets(tmp, sizeof(tmp) - 1, in)) {	/* Room for trailing NUL */
		line++;

		if (tmp[0] == '#')
			continue;			/* Skip comments */

		if (tmp[0] == '\n') {
			if (has_sha1)
				has_sha1 = FALSE;
			skip = FALSE;		/* Synchronization point */
			continue;
		}

		if (skip)
			continue;

		str_chomp(tmp, 0);		/* Remove final "\n" */

		if (has_sha1)
			dmesh_collect_locations(sha1, tmp, FALSE);
		else {
			if (
				strlen(tmp) != SHA1_BASE32_SIZE ||
				!base32_decode_into(tmp, SHA1_BASE32_SIZE, sha1, sizeof(sha1))
			) {
				g_warning("dmesh_retrieve: "
					"bad base32 SHA1 '%32s' at line #%d, ignoring", tmp, line);
				skip = TRUE;
			} else
				has_sha1 = TRUE;
		}
	}

	fclose(in);
	dmesh_store();			/* Persist what we have retrieved */
}

/*
 * dmesh_ban_store_kv
 *
 * Store key/value pair in file.
 */
static void dmesh_ban_store_kv(
	gpointer key, gpointer value, gpointer udata)
{
	const struct dmesh_banned *dmb = (const struct dmesh_banned *) value;
	FILE *out = (FILE *) udata;

	g_assert(key == (gpointer) dmb->info);

	fprintf(out, "%d %s\n",
		(gint) dmb->ctime, dmesh_urlinfo_to_gchar(dmb->info));
}

/*
 * dmesh_ban_header_print
 *
 * Prints header to banned mesh store file.
 */
static void dmesh_ban_header_print(FILE *out)
{
	file_config_preamble(out, "Banned mesh");

	fputs(	"#\n# Format is:\n"
			"#  timestamp URL\n"
			"#\n\n", out);
}

/*
 * dmesh_ban_store
 *
 * Store banned mesh onto file.
 * The banned mesh is normally stored in ~/.gtk-gnutella/dmesh_ban.
 */
void dmesh_ban_store(void)
{
	dmesh_store_hash("banned mesh",
		ban_mesh, dmesh_ban_file, dmesh_ban_header_print, dmesh_ban_store_kv);
}

/*
 * dmesh_ban_retrieve
 *
 * Retrieve banned mesh and add entries that have not expired yet.
 * The mesh is normally retrieved from ~/.gtk-gnutella/dmesh_ban.
 */
static void dmesh_ban_retrieve(void)
{
	FILE *in;
	gchar tmp[1024];
	gint line = 0;
	time_t stamp;
	gchar *p;
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

	while (fgets(tmp, sizeof(tmp) - 1, in)) {	/* Room for trailing NUL */
		line++;

		if (tmp[0] == '#')
			continue;			/* Skip comments */

		if (tmp[0] == '\n')
			continue;			/* Skip empty lines */

		str_chomp(tmp, 0);		/* Remove final "\n" */

		stamp = strtoul(tmp, &p, 10);
		if (p == tmp || *p != ' ') {
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

		dmesh_ban_add(&info, stamp);
		atom_str_free(info.name);
	}

	fclose(in);
	dmesh_ban_store();			/* Persist what we have retrieved */
}

/*
 * dmesh_free_kv
 *
 * Free key/value pair in download mesh hash.
 */
static gboolean dmesh_free_kv(gpointer key, gpointer value, gpointer udata)
{
	struct dmesh *dm = (struct dmesh *) value;
	GSList *l;

	atom_sha1_free(key);

	for (l = dm->entries; l; l = l->next)
		dmesh_entry_free((struct dmesh_entry *) l->data);

	g_slist_free(dm->entries);
	wfree(dm, sizeof(*dm));

	return TRUE;
}

/*
 * dmesh_ban_free_kv
 *
 * Free key/value pair in the ban_mesh hash.
 */
static gboolean dmesh_ban_free_kv(gpointer key, gpointer value, gpointer udata)
{
	struct dmesh_banned *dmb = (struct dmesh_banned *) value;

	g_assert(key == (gpointer) dmb->info);

	dmesh_urlinfo_free(dmb->info);
	cq_cancel(callout_queue, dmb->cq_ev);

	wfree(dmb, sizeof(*dmb));

	return TRUE;
}

/*
 * dmesh_close
 *
 * Called at servent shutdown time.
 */
void dmesh_close(void)
{
	dmesh_store();
	dmesh_ban_store();

	g_hash_table_foreach_remove(mesh, dmesh_free_kv, NULL);
	g_hash_table_destroy(mesh);

	g_hash_table_foreach_remove(ban_mesh, dmesh_ban_free_kv, NULL);
	g_hash_table_destroy(ban_mesh);
}

