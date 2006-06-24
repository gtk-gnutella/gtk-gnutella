/*
 * $Id: nodes.c 11140 2006-06-22 04:04:39Z cbiere $
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

RCSID("$Id: nodes.c 11140 2006-06-22 04:04:39Z cbiere $");

#ifdef HAS_SQLITE
#include <sqlite3.h>
#else	/* !HAS_SQLITE */
#include "lib/hashlist.h"
#include "lib/walloc.h"
#endif	/* HAS_SQLITE */

#include "lib/endian.h"

#include "hosts.h"
#include "settings.h"
#include "tls_cache.h"

#include "if/gnet_property_priv.h"

static const size_t tls_cache_max_items = 10000;
static const size_t tls_cache_max_time = 12 * 3600;

#ifdef HAS_SQLITE

static sqlite3 *db;
static sqlite3_stmt *select_stmt;
static sqlite3_stmt *insert_stmt;
static sqlite3_stmt *delete_stmt;

static const gchar tls_cache_db_file[] = "tls_cache.db";

static gint
tls_cache_db_open(void)
{
	gchar *pathname;
	gint error;

	pathname = make_pathname(settings_config_dir(), tls_cache_db_file);
	error = sqlite3_open(pathname, &db);
	G_FREE_NULL(pathname);
	
	if (error) {
		g_warning("Cannot open TLS cache database: %s", sqlite3_errmsg(db));
		goto failure;
	}

	{
		static const gchar cmd[] =
			"CREATE TABLE IF NOT EXISTS tls_hosts ("
			"host TEXT PRIMARY KEY,"
			"seen INTEGER"
			");";
		gchar *errmsg;
		gint ret;

		ret = sqlite3_exec(db, cmd, NULL, NULL, &errmsg);
		if (SQLITE_OK != ret) {
			g_warning("sqlite3_exec() failed: %s", errmsg);
			sqlite3_free(errmsg);
			goto failure;
		}
	}

	{
		static const gchar cmd[] =
			"INSERT OR REPLACE INTO tls_hosts VALUES(?1, ?2);";
		gint ret;
	   
		ret = sqlite3_prepare(db, cmd, (-1), &insert_stmt, NULL);
		if (SQLITE_OK != ret) {
			g_warning("sqlite3_prepare() failed: %s", sqlite3_errmsg(db));
			goto failure;
		}
	}

	{
		static const gchar cmd[] =
			"SELECT seen FROM tls_hosts WHERE host = ?1;";
		gint ret;

		ret = sqlite3_prepare(db, cmd, (-1), &select_stmt, NULL);
		if (SQLITE_OK != ret) {
			g_warning("sqlite3_prepare() failed: %s", sqlite3_errmsg(db));
			goto failure;
		}
	}

	{
		static const gchar cmd[] =
			"DELETE FROM tls_hosts WHERE host = ?1;";
		gint ret;

		ret = sqlite3_prepare(db, cmd, (-1), &delete_stmt, NULL);
		if (SQLITE_OK != ret) {
			g_warning("sqlite3_prepare() failed: %s", sqlite3_errmsg(db));
			goto failure;
		}
	}

	return 0;
	
failure:
	tls_cache_close();
	return -1;
}

static gint
tls_cache_bind_key(sqlite3_stmt *stmt, const host_addr_t addr, guint16 port)
{
	const gchar *key;
	gint ret;

	key = host_addr_port_to_string(addr, port);
	ret = sqlite3_bind_text(stmt, 1, &key, (-1), SQLITE_STATIC);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_bind_text() failed: %s",
			"tls_cache_bind_key", sqlite3_errmsg(db));
	}
	return ret;
}

void
tls_cache_add(const host_addr_t addr, guint16 port)
{
	sqlite3_stmt *stmt = insert_stmt;
	gint ret;
		
	g_return_if_fail(db);
	g_return_if_fail(stmt);

	if (tls_cache_bind_key(stmt, addr, port)) {
		goto reset;
	}

	ret = sqlite3_bind_int64(stmt, 2, tm_time());
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_bind_int64() failed: %s",
			"tls_cache_add", sqlite3_errmsg(db));
		goto reset;
	}

	ret = sqlite3_step(stmt);
	if (SQLITE_DONE != ret) {
		g_warning("%s: sqlite3_step() failed: %s",
			"tls_cache_add", sqlite3_errmsg(db));
		goto reset;
	}

reset:
	ret = sqlite3_reset(stmt);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_reset() failed: %s",
			"tls_cache_add", sqlite3_errmsg(db));
	}
}

void
tls_cache_delete(const host_addr_t addr, guint16 port)
{
	sqlite3_stmt *stmt = delete_stmt;

	g_return_if_fail(db);
	g_return_if_fail(stmt);

	if (SQLITE_OK == tls_cache_bind_key(stmt, addr, port)) {
		gint ret;

		ret = sqlite3_step(stmt);
		if (SQLITE_DONE != ret) {
			g_warning("%s: sqlite3_step() failed: %s",
					"tls_cache_delete", sqlite3_errmsg(db));
		}
	}

	if (SQLITE_OK != sqlite3_reset(stmt)) {
		g_warning("%s: sqlite3_reset() failed: %s",
			"tls_cache_delete", sqlite3_errmsg(db));
	}
}


gboolean
tls_cache_lookup(const host_addr_t addr, guint16 port)
{
	sqlite3_stmt *stmt = select_stmt;
	gboolean found = FALSE, delete = FALSE;

	g_return_val_if_fail(db, FALSE);
	g_return_val_if_fail(stmt, FALSE);
	g_return_val_if_fail(host_addr_initialized(addr), FALSE);
	g_return_val_if_fail(is_host_addr(addr), FALSE);
	g_return_val_if_fail(0 != port, FALSE);

	if (SQLITE_OK == tls_cache_bind_key(stmt, addr, port)) {
		gint ret;

		ret = sqlite3_step(stmt);
		if (SQLITE_ROW == ret) {
			time_t seen, now;
			gint64 value;

			value = sqlite3_column_int64(stmt, 1);
			if (value > TIME_T_MAX) {
				seen = TIME_T_MAX;
			} else {
				seen = value;
			}
			now = tm_time();
			
			if (
				delta_time(now, seen) >= 0 &&
				delta_time(now, seen) < tls_cache_max_time
			) {
				found = TRUE;
			} else {
				delete = TRUE;
			}
		} else if (SQLITE_DONE != ret) {
			g_warning("%s: sqlite3_step() failed: %s",
				"tls_cache_lookup", sqlite3_errmsg(db));
		}
	}

	if (SQLITE_OK != sqlite3_reset(stmt)) {
		g_warning("%s: sqlite3_reset() failed: %s",
			"tls_cache_lookup", sqlite3_errmsg(db));
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
	if (insert_stmt) {
		sqlite3_finalize(insert_stmt);
		insert_stmt = NULL;
	}
	if (select_stmt) {
		sqlite3_finalize(select_stmt);
		select_stmt = NULL;
	}
	if (delete_stmt) {
		sqlite3_finalize(delete_stmt);
		delete_stmt = NULL;
	}
	if (db) {
		gint ret;
		
		ret = sqlite3_close(db);
		if (SQLITE_OK != ret) {
			g_warning("sqlite3_close() failed: %s", sqlite3_errmsg(db));
		}
		db = NULL;
	}
}

#else	/* !HAS_SQLITE */

static hash_list_t *tls_hosts = NULL;

struct tls_cache_item {
	gnet_host_t host;
	time_t seen;
};

static void
tls_cache_remove_oldest(void)
{
	struct tls_cache_item *item;
	
	item = hash_list_first(tls_hosts);
	if (item) {
		hash_list_remove(tls_hosts, item);
		wfree(item, sizeof *item);
	}
}

void
tls_cache_add(const host_addr_t addr, guint16 port)
{
	struct tls_cache_item item;
	gpointer key;

	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);

	item.host.addr = addr;
	item.host.port = port;
	item.seen = tm_time();

	if (hash_list_contains(tls_hosts, &item, &key)) {
		struct tls_cache_item *item_ptr = key;

		/* We'll move the host to the end of the list */
		hash_list_remove(tls_hosts, item_ptr);
		if (tls_debug) {
			g_message("Refreshing TLS host %s",
				host_addr_port_to_string(addr, port));
		}
		item_ptr->seen = item.seen;
	} else {
		if (tls_debug) {
			g_message("Adding TLS host %s",
				host_addr_port_to_string(addr, port));
		}
		key = wcopy(&item, sizeof item);
	}
	hash_list_append(tls_hosts, key);

	/* Remove the oldest host once we hit a reasonable limit */
	if (hash_list_length(tls_hosts) > tls_cache_max_items) {
		tls_cache_remove_oldest();
	}
}

gboolean
tls_cache_lookup(const host_addr_t addr, guint16 port)
{
	if (host_addr_initialized(addr) && is_host_addr(addr) && 0 != port) {
		struct tls_cache_item item;
		gpointer key;

		item.host.addr = addr;
		item.host.port = port;
		if (hash_list_contains(tls_hosts, &item, &key)) {
			struct tls_cache_item *item_ptr = key;
			time_t now = tm_time();
			
			if (
				delta_time(now, item_ptr->seen) >= 0 && 
				delta_time(now, item_ptr->seen) < tls_cache_max_time
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

void
tls_cache_init(void)
{
	g_assert(!tls_hosts);

	tls_hosts = hash_list_new(tls_cache_item_hash, tls_cache_item_eq);
}

void
tls_cache_close(void)
{
	if (tls_hosts) {
		while (hash_list_length(tls_hosts) > 0) {
			tls_cache_remove_oldest();
		}
		hash_list_free(tls_hosts);
		tls_hosts = NULL;
	}
}
#endif	/* HAS_SQLITE */

/* vi: set ts=4 sw=4 cindent: */
