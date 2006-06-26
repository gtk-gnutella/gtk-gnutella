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
 
#include "gdb.h"
#include "settings.h"

#ifdef HAS_SQLITE

#include <sqlite3.h>

struct gdb_stmt {
	sqlite3_stmt *stmt;
};

static sqlite3 *persistent_db;
static struct gdb_stmt *get_config_value_stmt;
static struct gdb_stmt *set_config_value_stmt;

/**
 * Create an initial database.
 *
 * Creates an initial database creating a config table which can be used to
 * store the schema versions.
 */
static int
gdb_create(void)
{
	char *error_message;
	int ret;
	
	ret = sqlite3_exec(persistent_db,
		"CREATE TABLE config ("
		" key   VARCHAR(255)    NOT NULL PRIMARY KEY,"
		" value VARCHAR(1024)   NOT NULL"
		");", NULL, 0, &error_message);

	if (SQLITE_OK != ret) {
		g_warning("gdb_create() failed: %s", error_message);
		sqlite3_free(error_message);
		return -1;
	} else {
		g_message("[SQLITE3] Database created");
		return 0;
	}
}

/**
 * Initialize the "gtkg.db" database.
 */
void
gdb_init(void)
{
	char *error_message;
	int result;

	g_return_if_fail(!persistent_db);

	{	
		char *pathname;
		
		pathname = make_pathname(settings_config_dir(), "gtkg.db");
		if (SQLITE_OK != sqlite3_open(pathname, &persistent_db)) {
			g_warning("sqlite3_open(\"%s\") failed: %s",
				pathname, sqlite3_errmsg(persistent_db));
			goto error;
		}
		G_FREE_NULL(pathname);
	}

	result = sqlite3_exec(persistent_db, 
		"SELECT key,value FROM config LIMIT 1", NULL, 0, &error_message);

	if (SQLITE_OK != result) {
		if (result == SQLITE_ERROR) {
			g_message("gdb_init() failure: %s", error_message);
			sqlite3_free(error_message);
			if (0 != gdb_create()) {
				goto error;
			}
		} else {
			g_warning("Error opening database (%d) %s", result, error_message);
			sqlite3_free(error_message);
			goto error;
		}
	}
	return;

error:
	sqlite3_close(persistent_db);
	g_error("gdb_init() failed");
}

/**
 * Close the "gtkg.db" database.
 */
void
gdb_close(void)
{
	if (persistent_db) {

		if (0 != gdb_stmt_finalize(&get_config_value_stmt)) {
			g_warning("%s: gdb_stmt_finalize() failed: %s", "gdb_close",
				gdb_error_message());
		}
		if (0 != gdb_stmt_finalize(&set_config_value_stmt)) {
			g_warning("%s: gdb_stmt_finalize() failed: %s", "gdb_close",
				gdb_error_message());
		}

		if (SQLITE_OK != sqlite3_close(persistent_db)) {
			g_warning("%s: sqlite3_close() failed: %s", "gdb_close",
				sqlite3_errmsg(persistent_db));
		} else {
			persistent_db = NULL;
		}
	}
}

/**
 * Gets a config value from the database.
 */
const char *
gdb_get_config_value(const char *key)
{
	const unsigned char *value;
	int ret;

	if (get_config_value_stmt == NULL) {
		ret = gdb_stmt_prepare("SELECT value FROM config WHERE key = '?1';",
				&get_config_value_stmt);
		if (0 != ret) {
			g_error("Could not prepare \"get_config_value_stmt\".");
		}
	}

	ret = sqlite3_bind_text(get_config_value_stmt->stmt, 1,  /* Parameter 0 */
			key, (-1), SQLITE_TRANSIENT);
	if (SQLITE_OK != ret) {
		g_error("Could not bind key to parameter in SELECT.");
	}
	
	value = sqlite3_column_text(get_config_value_stmt->stmt,
				1 /* first column is our result */);

	sqlite3_reset(get_config_value_stmt->stmt);

	return (const char *) value;
}

/**
 * Stores a config value in the database.
 */
void
gdb_set_config_value(const char *key, const char *value)
{
	int ret;

	if (set_config_value_stmt == NULL) {
		ret = gdb_stmt_prepare(
			"INSERT OR REPLACE INTO config ('key', 'value') VALUES(?1, ?2);",
			&set_config_value_stmt);

		if (0 != ret) {
			g_error("Could not prepare `set_config_value_stmt'");
		}
	}
	
	ret = sqlite3_bind_text(set_config_value_stmt->stmt, 1, /* Parameter key */
			key, (-1), SQLITE_TRANSIENT);
	if (SQLITE_OK != ret) {
		g_error("Could not bind key to parameter in INSERT.");
	}

	ret = sqlite3_bind_text(set_config_value_stmt->stmt, 2,/* Parameter value */
			value, (-1), SQLITE_TRANSIENT);
	if (SQLITE_OK != ret) {
		g_error("Could not bind value to parameter in INSERT.");
	}

	if (GDB_STEP_DONE != gdb_stmt_step(set_config_value_stmt))  {
		g_warning("%s: Could not store %s", "gdb_set_config_value", key);
	}
		
	gdb_stmt_reset(set_config_value_stmt);
}

/**
 * Begin SQL transaction.
 */
int
gdb_begin(void)
{
	char *errmsg;
	int ret;

	ret = sqlite3_exec(persistent_db, "BEGIN;", NULL, NULL, &errmsg);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_exec() failed: %s", "gdb_begin", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	return 0;
}

/**
 * Commit SQL transaction.
 */
int
gdb_commit(void)
{
	char *errmsg;
	int ret;

	ret = sqlite3_exec(persistent_db, "COMMIT;", NULL, NULL, &errmsg);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_exec() failed: %s", "gdb_commit", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	return 0;
}

/**
 * Perform a SQL transaction rollback.
 */
int
gdb_rollback(void)
{
	char *errmsg;
	int ret;

	ret = sqlite3_exec(persistent_db, "ROLLBACK;", NULL, NULL, &errmsg);
	if (SQLITE_OK != ret) {
		g_warning("%s: sqlite3_exec() failed: %s", "gdb_rollback", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}
	return 0;
}


/**
 * Execute SQL statement, return error message in `error_message'.
 */
int
gdb_exec(const char *cmd, char **error_message)
{
	int result;
	
	result = sqlite3_exec(persistent_db, cmd, NULL, 0, error_message);
	return result;
}

/**
 * Free error message returned by gdb_exec().
 */
void
gdb_free(char *error_message)
{
	sqlite3_free(error_message);
}

/**
 * Return error message for the last error from the SQL backend.
 */
const char *
gdb_error_message(void)
{
	return sqlite3_errmsg(persistent_db);
}

/**
 * Prepare SQL statement.
 *
 * @param cmd An UTF-8 encoded C string holding a SQL statement.
 * @param db_stmt A pointer to variable for holding the prepared statement.
 * @return 0 on success, -1 on failure.
 */
int
gdb_stmt_prepare(const char *cmd, struct gdb_stmt **db_stmt)
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

/**
 * "Steps" a prepared statement.
 *
 * @return	GDB_STEP_ERROR on failure, GDB_STEP_DONE when the
 * 			statement has been finished, GDB_STEP_ROW when the
 *			next result row is available.
 */
enum gdb_step
gdb_stmt_step(struct gdb_stmt *db_stmt)
{
	if (db_stmt) {
		switch (sqlite3_step(db_stmt->stmt)) {
		case SQLITE_ROW:	return GDB_STEP_ROW;
		case SQLITE_DONE:	return GDB_STEP_DONE;
		}
	}
	return GDB_STEP_ERROR;
}

/**
 * Binds the value of the `n'-th parameter of the prepared SQL statement
 * `db_stmt' to the given binary data with the given size.
 *
 * @param db_stmt A prepared SQL statement.
 * @param n The parameter index of the statement to bind.
 * @param data A pointer to the data to be bound as parameter value.
 * @param size The number of bytes in data.
 *
 * @return 0 on success, -1 on failure.
 */
int
gdb_stmt_bind_static_blob(struct gdb_stmt *db_stmt,
	int n, const void *data, size_t size)
{
	int len, ret;
	
	g_return_val_if_fail(db_stmt, -1);
	g_return_val_if_fail(size <= INT_MAX, -1);
	
	len = size;
	ret = sqlite3_bind_blob(db_stmt->stmt, n, data, len, SQLITE_STATIC);

	return SQLITE_OK == ret ? 0 : -1;
}

/**
 * Reset a database SQL statement.
 *
 * @param db_stmt A prepared SQL statement.
 * @return 0 on success, -1 on failure.
 */
int
gdb_stmt_reset(struct gdb_stmt *db_stmt)
{
	int ret;
	
	g_return_val_if_fail(db_stmt, -1);

	ret = sqlite3_reset(db_stmt->stmt);
	return SQLITE_OK == ret ? 0 : -1;
}

/**
 * Finalize a prepared SQL statement and nullify the pointer.
 *
 * @param db_stmt A pointer to a variable holding a prepared SQL statement.
 * @return 0 on success, -1 on failure.
 */
int
gdb_stmt_finalize(struct gdb_stmt **db_stmt)
{
	g_return_val_if_fail(db_stmt, -1);

	if (*db_stmt) {
		int ret;

		ret = sqlite3_finalize((*db_stmt)->stmt);
		G_FREE_NULL((*db_stmt));
		return SQLITE_OK == ret ? 0 : -1;
	}
	return 0;
}

static const char *
gdb_type_to_string(enum gdb_type col_type)
{
	switch (col_type) {
#define CASE(x) case (GDB_CT_ ## x) : return #x;
	CASE(INTEGER)
	CASE(FLOAT)
	CASE(TEXT)
	
	CASE(SHA1)
	CASE(HOST)
#undef CASE
	}
	return NULL;
}

/**
 * Declares the extended types of the given columns in the given table.
 * The variable argument list must be terminated with (void *) 0.
 *
 * @param table The name of table in the database.
 * @param first_column The name of the first column.
 * @param ... An "enum gdb_type" declaring the type of the column.
 */
int
gdb_declare_types(const char *table, const char *first_column, ...)
{
	static const char create_meta_types[] =
		"CREATE TABLE IF NOT EXISTS meta_types ("
		" tab TEXT,"
		" col TEXT,"
		" type TEXT,"
		" PRIMARY KEY(tab, col)"
		");";
	va_list ap;
	const char *col_name;
	gchar *error_message;

	va_start(ap, first_column);
	gdb_begin();
	
	if (0 != gdb_exec(create_meta_types, &error_message)) {
		g_warning("%s: gdb_exec(create_meta_types, ...) failed: %s",
				"gdb_declare_types", error_message);
		gdb_free(error_message);
		goto rollback;
	}

	col_name = first_column;
	while (col_name) {
		static const char fmt[] =
			"INSERT OR REPLACE INTO meta_types (tab, col, type)"
			" VALUES('%q', '%q', '%q');";
		enum gdb_type col_type;
		char *cmd;

		col_type = va_arg(ap, enum gdb_type);
		cmd = sqlite3_mprintf(fmt,
				table, col_name, gdb_type_to_string(col_type));
		if (0 != gdb_exec(cmd, &error_message)) {
			g_warning("%s: gdb_exec() failed: %s",
				"gdb_declare_types", error_message);
			gdb_free(error_message);
			goto rollback;
		}
		sqlite3_free(cmd);
		col_name = va_arg(ap, const char *);
	}

	gdb_commit();
	va_end(ap);
	return 0;

rollback:
	gdb_rollback();
	va_end(ap);
	return -1;
}

#endif	/* HAS_SQLITE */
/* vi: set ts=4 sw=4 cindent: */
