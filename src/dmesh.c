/*
 * Copyright (c) 2002, Raphael Manfredi
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

#include "dmesh.h"
#include "atoms.h"
#include "url.h"
#include "misc.h"
#include "getdate.h"
#include "appconfig.h"
#include "huge.h"
#include "base32.h"

#define HTTP_PORT	80		/* Registered HTTP port */

/* made visible for us by atoms.c */
extern guint sha1_hash(gconstpointer key);
extern gint sha1_eq(gconstpointer a, gconstpointer b);

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

#define MAX_LIFETIME	172800		/* 2 days */
#define MAX_ENTRIES		32			/* Max amount of entries kept in list */
#define MAX_STAMP		0xffffffff	/* Unsigned int, 32 bits */

static gchar *dmesh_file = "dmesh";

static void dmesh_retrieve(void);
static gchar *dmesh_urlinfo_to_gchar(dmesh_urlinfo_t *info);

/*
 * dmesh_init
 *
 * Initialize the download mesh.
 */
void dmesh_init(void)
{
	mesh = g_hash_table_new(sha1_hash, sha1_eq);
	dmesh_retrieve();
}

/*
 * dmesh_entry_cmp
 *
 * Compare two dmesh_entry, based on the timestamp.  The greater the time
 * stamp, the samller the entry (i.e. the more recent).
 */
static gint dmesh_entry_cmp(gconstpointer a, gconstpointer b)
{
	struct dmesh_entry *ae = (struct dmesh_entry *) a;
	struct dmesh_entry *be = (struct dmesh_entry *) b;

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

	g_free(dme);
}

/*
 * dmesh_url_parse
 *
 * Parse URL `url', and fill a structure `info' representing this URL.
 *
 * Returns TRUE if OK, FALSE if we could not parse it.
 */
gboolean dmesh_url_parse(gchar *url, dmesh_urlinfo_t *info)
{
	guint32 ip;
	guint port;
	guint idx;
	guint lsb, b2, b3, msb;
	gchar *file;

	if (0 != strncasecmp(url, "http://", 7))
		return FALSE;

	url += 7;

	/*
	 * Test the first form of URL:
	 *
	 *    http://1.2.3.4:5678/get/1/name.txt
	 *
	 * If the port is missing, then HTTP_PORT is assumed.
	 */

	if (
		6 == sscanf(url, "%u.%u.%u.%u:%u/get/%u",
			&msb, &b3, &b2, &lsb, &port, &idx)
	)
		goto ok;

	if (5 == sscanf(url, "%u.%u.%u.%u/get/%u", &msb, &b3, &b2, &lsb, &idx)) {
		port = HTTP_PORT;
		goto ok;
	}

	/*
	 * Test the second form of URL:
	 *
	 *    http://1.2.3.4:5678/uri-res/N2R?urn:sha1:ABCDEFGHIJKLMN....
	 */

	idx = 0;			/* Identifies second form */

	if (
		5 == sscanf(url, "%u.%u.%u.%u:%u/uri-res/N2R?",
			&msb, &b3, &b2, &lsb, &port)
	)
		goto ok;
	
	if (4 == sscanf(url, "%u.%u.%u.%u/uri-res/N2R?", &msb, &b3, &b2, &lsb)) {
		port = HTTP_PORT;
		goto ok;
	}

	return FALSE;

ok:
	ip = lsb + (b2 << 8) + (b3 << 16) + (msb << 24);

	/*
	 * Now extract the filename or the URL.
	 */

	if (idx == 0) {
		file = strrchr(url, '/');
		g_assert(file);					/* Or we'd have not parsed above */

		/*
		 * Verify we're right on the "/N2R?" part, i.e. that we're facing
		 * an URL with an urn query, and not a get with an index.
		 * Should they send us a "/get/0/name.txt", we refuse it.
		 */

		if (0 != strncmp(file, "/N2R?", 5))
			return FALSE;					/* Index 0 is our mark */
		file += 5;							/* Skip "/N2R?" */
	} else {
		gchar c;

		file = strstr(url, "/get/");
		g_assert(file);					/* Or we'd have not parsed above */

		file += sizeof("/get/") - 1;	/* Go at first index char */

		/*
		 * We have to go past the index and make sure there's a "/" after it.
		 */

		while ((c = *file++) && isdigit(c))
			/* empty */;

		if (c != '/')
			return FALSE;				/* Did not have "/get/234/" */

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

	if (idx != 0) {
		gchar *unescaped = url_unescape(file, FALSE);
		info->name = atom_str_get(unescaped);
		if (unescaped != file)
			g_free(unescaped);
	} else
		info->name = atom_str_get(file);

	return TRUE;
}

/*
 * dm_expire
 *
 * Expire entries older than `agemax' in a given mesh bucket `dm'.
 * `sha1' is only passed in case we want to log the removal.
 */
static void dm_expire(struct dmesh *dm, guint32 agemax, guchar *sha1)
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
	guint32 ip, guint16 port, guint idx, gchar *name, guint32 stamp)
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
static void dmesh_dispose(guchar *sha1)
{
	gpointer key;
	gpointer value;
	gboolean found;

	found = g_hash_table_lookup_extended(mesh, sha1, &key, &value);

	g_assert(found);
	g_assert(((struct dmesh *) value)->count == 0);
	g_assert(((struct dmesh *) value)->entries == NULL);

	atom_sha1_free(key);
	g_free(value);

	g_hash_table_remove(mesh, sha1);
}

/*
 * dmesh_remove
 *
 * Remove entry from mesh.
 */
void dmesh_remove(guchar *sha1,
	guint32 ip, guint16 port, guint idx, gchar *name)
{
	struct dmesh *dm;

	/*
	 * Lookup SHA1 in the mesh to see if we already have entries for it.
	 */

	dm = (struct dmesh *) g_hash_table_lookup(mesh, sha1);

	if (dm == NULL)				/* Nothing for this SHA1 key */
		return;

	(void) dm_remove(dm, ip, port, idx, name, MAX_STAMP);

	/*
	 * If there is nothing left, clear the mesh entry.
	 */

	if (dm->count == 0) {
		g_assert(dm->entries == NULL);
		dmesh_dispose(sha1);
	}
}

/*
 * dmesh_add
 *
 * Add entry to the download mesh, indexed by the binary `sha1' digest.
 * If `stamp' is 0, then the current time is used.
 *
 * If `idx' is 0, then we can access this file only through an /uri-res
 * request, the URN being given as `name'.
 *
 * Returns whether the entry was added in the mesh, or was discarded because
 * it was the oldest record and we have enough already.
 */
gboolean dmesh_add(guchar *sha1,
	guint32 ip, guint16 port, guint idx, gchar *name, guint32 stamp)
{
	struct dmesh_entry *dme;
	struct dmesh *dm;
	guint32 now = (guint32) time(NULL);

	if (stamp == 0 || stamp > now)
		stamp = now;

	if (now - stamp > MAX_LIFETIME)
		return FALSE;

	/*
	 * Reject if this is for our host, or if the host is a private IP.
	 */

	if (ip == listen_ip() && port == listen_port)
		return FALSE;

	if (is_private_ip(ip))
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
		dm = g_malloc(sizeof(*dm));

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

	dme = (struct dmesh_entry *) g_malloc(sizeof(*dme));

	dme->inserted = now;
	dme->stamp = stamp;
	dme->url.ip = ip;
	dme->url.port = port;
	dme->url.idx = idx;
	dme->url.name = atom_str_get(name);

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

	return dme != NULL;			/* TRUE means we added the entry */
}

/*
 * dmesh_urlinfo
 *
 * Format the URL described by `info' into the provided buffer `buf', which
 * can hold `len' bytes.
 *
 * Returns length of formatted entry, -1 if the URL would be larger than
 * the buffer.
 */
static gint dmesh_urlinfo(dmesh_urlinfo_t *info, gchar *buf, gint len)
{
	gint rw;
	gint maxslen = len - 1;			/* Account for trailing NUL */

	g_assert(len > 0);
	g_assert(info->name != NULL);

	if (info->port == HTTP_PORT)
		rw = g_snprintf(buf, len, "http://%s", ip_to_gchar(info->ip));
	else
		rw = g_snprintf(buf, len, "http://%s",
			ip_port_to_gchar(info->ip, info->port));

	if (rw >= maxslen)
		return -1;

	if (info->idx == 0)
		rw += g_snprintf(&buf[rw], len - rw, "/uri-res/N2R?%s", info->name);
	else {
		rw += g_snprintf(&buf[rw], len - rw, "/get/%u/", info->idx);

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
	}

	return (rw >= maxslen) ? -1 : rw;
}

/*
 * dmesh_urlinfo_to_gchar
 *
 * Format the `info' URL and return pointer to static string.
 */
static gchar *dmesh_urlinfo_to_gchar(dmesh_urlinfo_t *info)
{
	static gchar urlstr[1024];

	(void) dmesh_urlinfo(info, urlstr, sizeof(urlstr) - 1);
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
static gint dmesh_entry_url_stamp(struct dmesh_entry *dme, gchar *buf, gint len)
{
	gint rw;
	gint maxslen = len - 1;			/* Account for trailing NUL */

	/*
	 * Format the URL info first.
	 */

	rw = dmesh_urlinfo(&dme->url, buf, len);

	if (rw < 0)
		return -1;

	/*
	 * Append timestamp.
	 */

	rw += g_snprintf(&buf[rw], len - rw,
		" %s", date_to_iso_gchar((time_t) dme->stamp));

	return (rw >= maxslen) ? -1 : rw;
}

/*
 * dmesh_entry_to_gchar
 *
 * Format the `dme' mesh entry as "URL timestamp" and return pointer to
 * static string.
 */
static gchar *dmesh_entry_to_gchar(struct dmesh_entry *dme)
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
gint dmesh_alternate_location(guchar *sha1,
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

	len = g_snprintf(buf, size, "X-Gnutella-Alternate-Location:\r\n");
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
			len += g_snprintf(&buf[len], size - len, ",\r\n");
		} else {
			/*
			 * We just need to be able to emit our URL and close the header,
			 * i.e. we need "\t" and "\r\n" to end, plus the trailing NUL.
			 */
			if (url_len + 3 >= size - len)	/* Needs "\t" and "\r\n" */
				continue;
		}

		g_assert((url_len + 1 + len) < size);
		len += g_snprintf(&buf[len], size - len, "\t%s", url);
		g_assert(len + 2 < size);

		nurl++;
	}

	g_assert(len < size);

	if (nurl)
		len += g_snprintf(&buf[len], size - len, "\r\n");

	// g_assert(len < size);
	if (len >= size) {
		g_error("BUG: dmesh_alternate_location: filled buffer completely "
			"(size=%d, len=%d, nurl=%d)", size, len, nurl);
		return 0;
	}

	return (nurl > 0) ? len : 0;
}

/*
 * dmesh_collect_locations
 *
 * Parse value of the "X-Gnutella-Content-URN" to extract alternate sources
 * for a given SHA1 key.
 */
void dmesh_collect_locations(guchar *sha1, guchar *value)
{
	guchar *p = value;
	guchar c;
	time_t now = time(NULL);

	for (;;) {
		guchar *url;
		guchar *date;
		time_t stamp;
		gboolean ok;
		dmesh_urlinfo_t info;
		gboolean non_space_seen;

		/*
		 * Find next space, colon or EOS (End of String).
		 * Everything from now to there will be an URL.
		 * All leading spaces are skipped.
		 */

		url = NULL;
		non_space_seen = FALSE;

		while ((c = *p)) {
			if (!non_space_seen) {
				if (isspace(c))
					goto next;
				non_space_seen = TRUE;
				url = p;
			}

			/*
			 * The "," may appear un-escaped in the URL.
			 *
			 * We know we're no longer in an URL if the character after is a
			 * space (should be escaped).  Our header parsing code will
			 * concatenate lines with a ", " separation.
			 */

			if (c == ',' && p[1] != ' ')
				goto next;

			if (c == ' ' || c == ',')
				break;
	
		next:
			p++;
		}

		if (url == NULL) {				/* Only seen spaces */
			if (c == '\0')
				return;
			continue;
		}

		if (c == '\0' && p == url)		/* Empty string remained */
			return;

		/*
		 * Parse URL.
		 */

		g_assert(*p == c);

		*p = '\0';
		ok = dmesh_url_parse(url, &info);

		if (dbg > 6)
			printf("MESH (parsed=%d): \"%s\"\n", ok, url);

		if (!ok)
			g_warning("cannot parse Alternate-Location URL: %s", url);

		*p = c;

		/*
		 * If URL cannot be parsed, resume processing after current point.
		 */

		if (!ok) {
			if (c == '\0')				/* Reached end of string */
				return;
			p++;						/* Skip separator */
			continue;
		}

		/*
		 * Advance to next ',', expecting a date.
		 */

		date = ++p;

	more_date:
		while ((c = *p)) {
			if (c == ',')
				break;
			p++;
		}

		/*
		 * Disambiguate "Mon, 17 Jun 2002 07:53:14 +0200"
		 */

		if (c != '\0' && p - date == 3) {
			p++;
			goto more_date;
		}

		/*
		 * Parse date, if present.
		 */

		if (p != date) {
			g_assert(*p == c);

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
		 * Enter URL into mesh.
		 */

		ok = dmesh_add(sha1, info.ip, info.port, info.idx, info.name, stamp);

		if (dbg > 4)
			printf("MESH %s: %s \"%s\", stamp=%u age=%u\n",
				sha1_base32(sha1),
				ok ? "added" : "rejected",
				dmesh_urlinfo_to_gchar(&info), (guint32) stamp,
				(guint32) (now - MIN(stamp, now)));

		atom_str_free(info.name);

		if (c == '\0')				/* Reached end of string */
			return;

		p++;						/* Skip separator */
	}
}

/*
 * dmesh_store_kv
 *
 * Store key/value pair in file.
 */
static void dmesh_store_kv(gpointer key, gpointer value, gpointer udata)
{
	struct dmesh *dm = (struct dmesh *) value;
	GSList *l;
	FILE *out = (FILE *) udata;

	fprintf(out, "%s\n", sha1_base32((guchar *) key));

	for (l = dm->entries; l; l = l->next) {
		struct dmesh_entry *dme = (struct dmesh_entry *) l->data;
		fprintf(out, "%s\n", dmesh_entry_to_gchar(dme));
	}

	fputs("\n", out);
}

// XXX add dmesh_store_if_dirty() and export that only

/*
 * dmesh_store
 *
 * Store download mesh onto file.
 *
 * The download mesh is normally stored in ~/.gtk-gnutella/dmesh.
 */
void dmesh_store(void)
{
	FILE *out;
	time_t now = time((time_t *) NULL);
	gchar tmp[1024];
	gchar filename[1024];

	g_snprintf(tmp, sizeof(tmp), "%s/%s.new", config_dir, dmesh_file);
	out = fopen(tmp, "w");

	if (!out) {
		g_warning("unable to create %s to persist download mesh: %s",
			tmp, g_strerror(errno));
		return;
	}

	fputs("# THIS FILE IS AUTOMATICALLY GENERATED -- DO NOT EDIT\n", out);
	fprintf(out, "#\n# Download mesh saved on %s#\n\n", ctime(&now));
	fputs("#\n# Format is:\n", out);
	fputs("#   SHA1\n", out);
	fputs("#   URL1 timestamp1\n", out);
	fputs("#   URL2 timestamp2\n", out);
	fputs("#   <blank line>\n", out);
	fputs("#\n\n", out);

	g_hash_table_foreach(mesh, dmesh_store_kv, out);

	if (0 == fclose(out)) {
		g_snprintf(filename, sizeof(filename), "%s/%s",
			config_dir, dmesh_file);

		if (-1 == rename(tmp, filename))
			g_warning("could not rename %s as %s: %s",
				tmp, filename, g_strerror(errno));
	} else
		g_warning("could not flush %s: %s", tmp, g_strerror(errno));
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
	guchar sha1[SHA1_RAW_SIZE];
	gboolean has_sha1 = FALSE;
	gboolean skip = FALSE;
	gchar tmp[1024];
	gchar filename[1024];
	gint line = 0;

	g_snprintf(tmp, sizeof(tmp), "%s/%s", config_dir, dmesh_file);

	in = fopen(tmp, "r");

	if (!in)
		return;

	/*
	 * Rename "dmesh" as "dmesh.orig", so that the original file is kept
	 * around some time for recovery purposes..
	 */

	g_snprintf(filename, sizeof(filename), "%s/%s.orig",
		config_dir, dmesh_file);

	if (-1 == rename(tmp, filename))
		g_warning("could not rename %s as %s: %s",
			tmp, filename, g_strerror(errno));

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

		str_chomp(tmp, 0);

		if (has_sha1)
			dmesh_collect_locations(sha1, tmp);
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
	g_free(dm);

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
	g_hash_table_foreach_remove(mesh, dmesh_free_kv, NULL);
}

