/*
 * $Id$
 *
 * Copyright (c) 2006, Jeroen Asselman
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
 
#include "storage_sqlite3.h"
#include "settings.h"

#ifdef HAS_SQLITE

#include <sqlite3.h>

struct database_stmt {
	sqlite3_stmt *stmt;
};

static sqlite3 *persistent_db;
static sqlite3_stmt *get_config_value_stmt;
static sqlite3_stmt *set_config_value_stmt;

static void database_create(void);

void
database_init(void)
{
	char *error_message, *db_pathname;
	int result;
	
	db_pathname = make_pathname(settings_config_dir(), "gtkg.db");
	sqlite3_open(db_pathname, &persistent_db);
	G_FREE_NULL(db_pathname);
	
	result = sqlite3_exec(persistent_db, 
		"SELECT count(*) FROM config", NULL, 0, &error_message);
  
	if (result == SQLITE_ERROR) {
		database_create();
		sqlite3_free(error_message);
	} else if (result != SQLITE_OK) {
		g_error("Error opening database (%d) %s", result, error_message);
		sqlite3_free(error_message);
	}
}

void
database_close(void)
{
	if (persistent_db) {
		if (SQLITE_OK != sqlite3_close(persistent_db)) {
			g_warning("%s: sqlite3_close() failed: %s",
				"database_close", sqlite3_errmsg(persistent_db));
		} else {
			persistent_db = NULL;
		}
	}
}

/**
 * Create an initial database.
 *
 * Creates an initial database creating a config table which can be used to
 * store the schema versions.
 */
void
database_create(void)
{
	int result;
	char *error_message;
	
	result = sqlite3_exec(persistent_db,
		"CREATE TABLE config ("
		" key   VARCHAR(255)    NOT NULL PRIMARY KEY,"
		" value VARCHAR(1024)   NOT NULL"
		");", NULL, 0, &error_message);
		
	g_assert(result == SQLITE_OK);
	
	g_message("[SQLITE3] Database created");
}

/**
 * Gets a config value from the database.
 */
const char *
database_get_config_value(const char *key)
{
	const unsigned char *value;
	
	if (get_config_value_stmt == NULL)
	{
		if ( sqlite3_prepare(
			persistent_db, 
			"SELECT value FROM config WHERE key = '?1';",  /* stmt */
			-1, /* If than zero, then stmt is read up to the first nul terminator */
			&get_config_value_stmt,
			0  /* Pointer to unused portion of stmt */
		) != SQLITE_OK) 
			g_error("Could not prepare statement.");
	}
	
	if (sqlite3_bind_text (
		get_config_value_stmt,
		1,  /* Parameter 0 */
        key, (-1),
		SQLITE_TRANSIENT
        ) != SQLITE_OK)
			g_error("Could not bind key to parameter.");
	
	value = sqlite3_column_text(
		get_config_value_stmt, 
		1 /* first column is our result */);

	return (const char *) value;
}

/**
 * Stores a config value in the database.
 */
void
database_set_config_value(const char *key, const char *value)
{
	if (set_config_value_stmt == NULL)
	{
		if ( sqlite3_prepare(
			persistent_db, 
			"INSERT OR REPLACE INTO config ('key', 'value') VALUES(?1, ?2);",
			-1, /* If than zero, then stmt is read up to the first nul terminator */
			&set_config_value_stmt,
			0  /* Pointer to unused portion of stmt */
		) != SQLITE_OK) 
			g_error("Could not prepare statement.");
	}
	
	if (sqlite3_bind_text (
		set_config_value_stmt,
		1,  /* Parameter key */
        key, (-1),
		SQLITE_TRANSIENT
        ) != SQLITE_OK)
			g_error("Could not bind key to parameter.");

	if (sqlite3_bind_text (
		set_config_value_stmt,
		2,  /* Parameter value */
        value, (-1),
		SQLITE_TRANSIENT
        ) != SQLITE_OK)
			g_error("Could not bind value to parameter.");
	
	if (sqlite3_step(set_config_value_stmt) != SQLITE_DONE) 
		g_warning("Could not store %s ", key);
		
	sqlite3_reset(get_config_value_stmt);
}

int
database_begin(void)
{
	char *errmsg;
	int ret;

	ret = sqlite3_exec(persistent_db, "BEGIN;", NULL, NULL, &errmsg);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_exec() failed: %s", "database_begin", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	return 0;
}

int
database_commit(void)
{
	char *errmsg;
	int ret;

	ret = sqlite3_exec(persistent_db, "COMMIT;", NULL, NULL, &errmsg);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_exec() failed: %s", "database_commit", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	return 0;
}

int
database_exec(const char *cmd, char **error_message)
{
	int result;
	
	result = sqlite3_exec(persistent_db, cmd, NULL, 0, error_message);
	return result;
}

void
database_free(char *error_message)
{
	sqlite3_free(error_message);
}

const char *
database_error_message(void)
{
	return sqlite3_errmsg(persistent_db);
}

int
database_stmt_prepare(const char *cmd, struct database_stmt **db_stmt)
{
	sqlite3_stmt *stmt;
	int ret;

	g_return_val_if_fail(db_stmt, -1);

	ret = sqlite3_prepare(persistent_db, cmd, (-1), &stmt, NULL);
	if (SQLITE_OK == ret) {
		*db_stmt = g_malloc0(sizeof **db_stmt);
		(*db_stmt)->stmt = stmt;
		return 0;
	} else {
		*db_stmt = NULL;
		return -1;
	}
}

enum database_step
database_stmt_step(struct database_stmt *db_stmt)
{
	if (db_stmt) {
		switch (sqlite3_step(db_stmt->stmt)) {
		case SQLITE_ROW:	return DATABASE_STEP_ROW;
		case SQLITE_DONE:	return DATABASE_STEP_DONE;
		}
	}
	return DATABASE_STEP_ERROR;
}

int
database_stmt_bind_static_blob(struct database_stmt *db_stmt,
	int parameter, const void *data, size_t size)
{
	int len, ret;
	
	g_return_val_if_fail(db_stmt, -1);
	g_return_val_if_fail(size <= INT_MAX, -1);
	
	len = size;
	ret = sqlite3_bind_blob(db_stmt->stmt, parameter, data, len, SQLITE_STATIC);

	return SQLITE_OK == ret ? 0 : -1;
}

int
database_stmt_reset(struct database_stmt *db_stmt)
{
	int ret;
	
	g_return_val_if_fail(db_stmt, -1);

	ret = sqlite3_reset(db_stmt->stmt);
	return SQLITE_OK == ret ? 0 : -1;
}

int
database_stmt_finalize(struct database_stmt **db_stmt)
{
	g_return_val_if_fail(db_stmt, -1);

	if ((*db_stmt)->stmt) {
		int ret;

		ret = sqlite3_finalize((*db_stmt)->stmt);
		G_FREE_NULL((*db_stmt));
		return SQLITE_OK == ret ? 0 : -1;
	}
	return 0;
}

#else	/* !HAS_SQLITE */

const char *
database_get_config_value(const char *key)
{
	(void) key;
	g_assert_not_reached();
	return NULL;
}

#endif	/* HAS_SQLITE */
/* vi: set ts=4 sw=4 cindent: */
