/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * Address caching of TLS-capable hosts.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#ifdef HAS_SQLITE
#include <sqlite3.h>
#else	/* !HAS_SQLITE */
#include "lib/bit_array.h"
#include "lib/file.h"
#include "lib/getdate.h"
#include "lib/hashlist.h"
#include "lib/walloc.h"
#endif	/* HAS_SQLITE */

#include "lib/endian.h"
#include "lib/host_addr.h"

#include "gdb.h"
#include "hosts.h"
#include "settings.h"
#include "tls_cache.h"

#include "if/gnet_property_priv.h"

static const size_t tls_cache_max_items = 10000;
static const size_t tls_cache_max_time = 12 * 3600;

#ifdef HAS_SQLITE

static struct gdb_stmt *select_stmt;
static struct gdb_stmt *insert_stmt;
static struct gdb_stmt *delete_stmt;

static int
tls_cache_db_open(void)
{
	{
		static const char cmd[] =
			"CREATE TABLE IF NOT EXISTS tls_hosts ("
			"host BLOB PRIMARY KEY, "
			"seen INTEGER"
			");";
		char *errmsg;
		int ret;

		ret = gdb_exec(cmd, &errmsg);
		if (0 != ret) {
			g_warning("gdb_exec() failed: %s", errmsg);
			gdb_free(errmsg);
			goto failure;
		}
		ret = gdb_declare_types("tls_hosts", "host", GDB_CT_HOST, (void *) 0);
		if (0 != ret) {
			g_warning("gdb_declare_types() failed: %s", gdb_error_message());
			goto failure;
		}
	}

	{
		static const char cmd[] =
			"INSERT OR REPLACE INTO tls_hosts VALUES(?1, ?2);";
		int ret;
	   
		ret = gdb_stmt_prepare(cmd, &insert_stmt);
		if (0 != ret) {
			g_warning("gdb_stmt_prepare() failed: %s", gdb_error_message());
			goto failure;
		}
	}

	{
		static const char cmd[] =
			"SELECT seen FROM tls_hosts WHERE host = ?1;";
		int ret;

		ret = gdb_stmt_prepare(cmd, &select_stmt);
		if (0 != ret) {
			g_warning("gdb_stmt_prepare() failed: %s", gdb_error_message());
			goto failure;
		}
	}

	{
		static const char cmd[] =
			"DELETE FROM tls_hosts WHERE host = ?1;";
		int ret;

		ret = gdb_stmt_prepare(cmd, &delete_stmt);
		if (0 != ret) {
			g_warning("gdb_stmt_prepare() failed: %s", gdb_error_message());
			goto failure;
		}
	}

	return 0;
	
failure:
	tls_cache_close();
	return -1;
}

static int
tls_cache_bind_key(struct gdb_stmt *stmt, const host_addr_t addr, guint16 port)
{
	static struct packed_host host;
	guint size;
	int ret;

	host = host_pack(addr, port);
	size = packed_host_size(host);
	ret = gdb_stmt_bind_static_blob(stmt, 1, &host, size);
	if (0 != ret) {
		g_warning("%s: gdb_stmt_bind_static_blob() failed: %s",
			"tls_cache_bind_key", gdb_error_message());
	}
	return ret;
}

void
tls_cache_insert(const host_addr_t addr, guint16 port)
{
	struct gdb_stmt *stmt = insert_stmt;
	enum gdb_step step;
	int ret;
		
	g_return_if_fail(stmt);

	if (tls_debug) {
		g_message("tls_cache_insert: %s", host_addr_port_to_string(addr, port));
	}

	if (0 != tls_cache_bind_key(stmt, addr, port)) {
		goto reset;
	}

	ret = gdb_stmt_bind_int64(stmt, 2, tm_time());
	if (0 != ret) {
		g_warning("%s: gdb_stmt_bind_int64() failed: %s",
			"tls_cache_insert", gdb_error_message());
		goto reset;
	}

	step = gdb_stmt_step(stmt);
	if (GDB_STEP_DONE != step) {
		g_warning("%s: gdb_stmt_step() failed: %s",
			"tls_cache_insert", gdb_error_message());
		goto reset;
	}

reset:
	ret = gdb_stmt_reset(stmt);
	if (0 != ret) {
		g_warning("%s: gdb_stmt_reset() failed: %s",
			"tls_cache_add", gdb_error_message());
	}
}

void
tls_cache_delete(const host_addr_t addr, guint16 port)
{
	struct gdb_stmt *stmt = delete_stmt;

	g_return_if_fail(stmt);

	if (tls_debug) {
		g_message("tls_cache_delete: %s", host_addr_port_to_string(addr, port));
	}

	if (0 == tls_cache_bind_key(stmt, addr, port)) {
		enum gdb_step step;

		step = gdb_stmt_step(stmt);
		if (GDB_STEP_DONE != step) {
			g_warning("%s: gdb_stmt_step() failed: %s",
				"tls_cache_delete", gdb_error_message());
		}
	}

	if (0 != gdb_stmt_reset(stmt)) {
		g_warning("%s: gdb_stmt_reset() failed: %s",
			"tls_cache_delete", gdb_error_message());
	}
}

gboolean
tls_cache_lookup(const host_addr_t addr, guint16 port)
{
	struct gdb_stmt *stmt = select_stmt;
	gboolean found = FALSE, delete = FALSE;

	g_return_val_if_fail(stmt, FALSE);
	g_return_val_if_fail(host_addr_initialized(addr), FALSE);
	g_return_val_if_fail(0 != port, FALSE);
	if (!is_host_addr(addr)) {
		return FALSE;
	}

	if (0 == tls_cache_bind_key(stmt, addr, port)) {
		enum gdb_step step;

		step = gdb_stmt_step(stmt);
		if (GDB_STEP_ROW == step) {
			const time_delta_t max_delta = tls_cache_max_time;
			time_t seen, now;
			time_delta_t delta;
			gint64 value;

			value = gdb_stmt_column_int64(stmt, 0);

			if (tls_debug) {
				g_message("tls_cache_lookup: found %s (%s)",
					host_addr_port_to_string(addr, port),
					timestamp_to_string(value));
			}

			if (value > TIME_T_MAX) {
				seen = TIME_T_MAX;
			} else {
				seen = value;
			}
			now = tm_time();
			delta = delta_time(now, seen);
			delete = delta < 0 || delta > max_delta;
			found = !delete;
		} else if (GDB_STEP_DONE != step) {
			g_warning("%s: gdb_stmt_step() failed: %s",
				"tls_cache_lookup", gdb_error_message());
		}
	}

	if (0 != gdb_stmt_reset(stmt)) {
		g_warning("%s: gdb_stmt_reset() failed: %s",
			"tls_cache_lookup", gdb_error_message());
	}

	if (delete) {
		tls_cache_delete(addr, port);
	}

	return found;
}

void
tls_cache_init(void)
{
	tls_cache_db_open();
}

void
tls_cache_close(void)
{
	gdb_stmt_finalize(&insert_stmt);
	gdb_stmt_finalize(&select_stmt);
	gdb_stmt_finalize(&delete_stmt);
}

#else	/* !HAS_SQLITE */

static hash_list_t *tls_hosts = NULL;

typedef enum {
	TLS_CACHE_TAG_UNKNOWN = 0,

	TLS_CACHE_TAG_END,
	TLS_CACHE_TAG_HOST,
	TLS_CACHE_TAG_SEEN,

	NUM_TLS_CACHE_TAGS
} tls_cache_tag_t;

static const struct tls_cache_tag {
	tls_cache_tag_t	tag;
	const char *str;
} tls_cache_tag_map[] = {
	/* Must be sorted alphabetically for dichotomic search */

#define TLS_CACHE_TAG(x) { CAT2(TLS_CACHE_TAG_,x), #x }
	TLS_CACHE_TAG(END),
	TLS_CACHE_TAG(HOST),
	TLS_CACHE_TAG(SEEN),

	/* Above line intentionally left blank (for "!}sort" on vi) */
#undef TLS_CACHE_TAG
};

static tls_cache_tag_t
tls_cache_string_to_tag(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(tls_cache_tag_map) == (NUM_TLS_CACHE_TAGS - 1));

#define GET_ITEM(i) (tls_cache_tag_map[(i)].str)
#define FOUND(i) G_STMT_START { \
	return tls_cache_tag_map[(i)].tag; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``s'' */
	BINARY_SEARCH(const char *, s, G_N_ELEMENTS(tls_cache_tag_map), strcmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return TLS_CACHE_TAG_UNKNOWN;
}

struct tls_cache_item {
	gnet_host_t host;
	time_t seen;
};

static void
tls_cache_remove_oldest(void)
{
	struct tls_cache_item *item;
	
	item = hash_list_head(tls_hosts);
	if (item) {
		hash_list_remove(tls_hosts, item);
		wfree(item, sizeof *item);
	}
}

void
tls_cache_insert_intern(const struct tls_cache_item *item)
{
	gconstpointer key;

	g_return_if_fail(item);

	key = hash_list_remove(tls_hosts, item);
	if (key) {
		struct tls_cache_item *item_ptr = deconstify_gpointer(key);

		/* We'll move the host to the end of the list */
		if (tls_debug) {
			g_message("Refreshing TLS host %s",
				gnet_host_to_string(&item->host));
		}
		item_ptr->seen = item->seen;
	} else {
		if (tls_debug) {
			g_message("Adding TLS host %s", gnet_host_to_string(&item->host));
		}
		key = wcopy(item, sizeof *item);
	}
	hash_list_append(tls_hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	if (hash_list_length(tls_hosts) > tls_cache_max_items) {
		tls_cache_remove_oldest();
	}
}

void
tls_cache_insert(const host_addr_t addr, guint16 port)
{
	struct tls_cache_item item;

	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);

	gnet_host_set(&item.host, addr, port);
	item.seen = tm_time();
	tls_cache_insert_intern(&item);
}

gboolean
tls_cache_lookup(const host_addr_t addr, guint16 port)
{
	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct tls_cache_item item;
		gconstpointer key;

		gnet_host_set(&item.host, addr, port);
		if (hash_list_contains(tls_hosts, &item, &key)) {
			struct tls_cache_item *item_ptr = deconstify_gpointer(key);
			time_t now = tm_time();
			time_delta_t upper_limit = tls_cache_max_time;
			
			if (
				delta_time(now, item_ptr->seen) >= 0 && 
				delta_time(now, item_ptr->seen) < upper_limit
			) {
				return TRUE;
			} else {
				hash_list_remove(tls_hosts, item_ptr);
				wfree(item_ptr, sizeof *item_ptr);
			}
		}
	}
	return FALSE;
}

static guint
tls_cache_item_hash(gconstpointer key)
{
	const struct tls_cache_item *item = key;
	return host_hash(&item->host);
}

static gint
tls_cache_item_eq(gconstpointer v1, gconstpointer v2)
{
	const struct tls_cache_item *a = v1, *b = v2;
	return host_eq(&a->host,& b->host);
}

static void
tls_cache_parse(FILE *f)
{
	bit_array_t tag_used[BIT_ARRAY_SIZE(NUM_TLS_CACHE_TAGS)];
	static const struct tls_cache_item zero_item;
	struct tls_cache_item item;
	char line[1024];
	guint line_no = 0;
	gboolean done = FALSE;

	g_return_if_fail(f);

	/* Reset state */
	done = FALSE;
	item = zero_item;
	bit_array_clear_range(tag_used, 0, (guint) NUM_TLS_CACHE_TAGS - 1);

	while (fgets(line, sizeof line, f)) {
		const char *tag_name, *value;
		gchar *sp, *nl;
		gboolean damaged;
		tls_cache_tag_t tag;

		line_no++;

		damaged = FALSE;
		nl = strchr(line, '\n');
		if (!nl) {
			/*
			 * If the line is too long or unterminated the file is either
			 * corrupt or was manually edited without respecting the
			 * exact format. If we continued, we would read from the
			 * middle of a line which could be the filename or ID.
			 */
			g_warning("tls_cache_parse(): "
				"line too long or missing newline in line %u",
				line_no);
			break;
		}
		*nl = '\0';

		/* Skip comments and empty lines */
		if (*line == '#' || *line == '\0')
			continue;

		sp = strchr(line, ' ');
		if (sp) {
			*sp = '\0';
			value = &sp[1];
		} else {
			value = strchr(line, '\0');
		}
		tag_name = line;

		tag = tls_cache_string_to_tag(tag_name);
		g_assert((gint) tag >= 0 && tag < NUM_TLS_CACHE_TAGS);
		if (TLS_CACHE_TAG_UNKNOWN != tag && !bit_array_flip(tag_used, tag)) {
			g_warning(
				"tls_cache_load(): duplicate tag \"%s\" in entry in line %u",
				tag_name, line_no);
			break;
		}
		
		switch (tag) {
		case TLS_CACHE_TAG_HOST:
			{
				host_addr_t addr;
				guint16 port;

				if (string_to_host_addr_port(value, NULL, &addr, &port)) {
					gnet_host_set(&item.host, addr, port);
				} else {
					damaged = TRUE;
				}
			}
			break;

		case TLS_CACHE_TAG_SEEN:
			item.seen = date2time(value, tm_time());
			if ((time_t) -1 == item.seen) {
				damaged = TRUE;
			}
			break;
			
		case TLS_CACHE_TAG_END:
			if (!bit_array_get(tag_used, TLS_CACHE_TAG_HOST)) {
				g_warning("tls_cache_load(): missing HOST tag");
				damaged = TRUE;
			}
			if (!bit_array_get(tag_used, TLS_CACHE_TAG_SEEN)) {
				g_warning("tls_cache_load(): missing SEEN tag");
				damaged = TRUE;
			}
			done = TRUE;
			break;

		case TLS_CACHE_TAG_UNKNOWN:
			/* Ignore */
			break;
			
		case NUM_TLS_CACHE_TAGS:
			g_assert_not_reached();
			break;
		}

		if (damaged) {
			g_warning("Damaged TLS cache entry in line %u: "
				"tag_name=\"%s\", value=\"%s\"",
				line_no, tag_name, value);
			break;
		}

		if (done) {
			if (
				tls_cache_lookup(gnet_host_get_addr(&item.host),
					gnet_host_get_port(&item.host))
			) {
				g_warning(
					"Ignoring duplicate TLS cache item around line %u (%s)",
				   	line_no, gnet_host_to_string(&item.host));
			} else {
				tls_cache_insert_intern(&item);
			}
			
			/* Reset state */
			done = FALSE;
			item = zero_item;
			bit_array_clear_range(tag_used, 0, (guint) NUM_TLS_CACHE_TAGS - 1);
		}
	}
}

static file_path_t *
tls_cache_file_path(void)
{
	static file_path_t fp;
	static gboolean initialized;

	if (!initialized) {
		initialized = TRUE;
		file_path_set(&fp, g_strdup(settings_config_dir()), "tls_cache");
	}
	return &fp;
}

static void
tls_cache_load(void)
{
	FILE *f;

	f = file_config_open_read("TLS cache", tls_cache_file_path(), 1);
	if (f) {
		guint n;
		
		tls_cache_parse(f);
		n = hash_list_length(tls_hosts);
		g_message("Loaded %u items from the TLS cache", n);
		fclose(f);
	}
}

static void
tls_cache_dump(FILE *f)
{
	hash_list_iter_t *iter;

	g_return_if_fail(f);
	g_return_if_fail(tls_hosts);

	iter = hash_list_iterator(tls_hosts);
	while (hash_list_iter_has_next(iter)) {
		const struct tls_cache_item *item;
		
		item = hash_list_iter_next(iter);
		fprintf(f, "HOST %s\nSEEN %s\nEND\n\n",
			gnet_host_to_string(&item->host), timestamp_to_string(item->seen));
	}
	hash_list_iter_release(&iter);
}

static void
tls_cache_store(void)
{
	FILE *f;

	f = file_config_open_write("TLS cache", tls_cache_file_path());
	if (f) {
		tls_cache_dump(f);
		file_config_close(f, tls_cache_file_path());
	}
}

void
tls_cache_init(void)
{
	g_return_if_fail(!tls_hosts);

	tls_hosts = hash_list_new(tls_cache_item_hash, tls_cache_item_eq);
	tls_cache_load();
}

void
tls_cache_close(void)
{
	if (tls_hosts) {
		tls_cache_store();
		while (hash_list_length(tls_hosts) > 0) {
			tls_cache_remove_oldest();
		}
		hash_list_free(&tls_hosts);
	}
}
#endif	/* HAS_SQLITE */

/* vi: set ts=4 sw=4 cindent: */
