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
 
#include "common.h"
#include "storage_sqlite3.h"
#include "settings.h"


#ifdef HAS_SQLITE

#include <sqlite3.h>

sqlite3_stmt *get_config_value_stmt;

static void database_create();

void database_init()
{
	int result;
	char *error_message;
	
	char *dbfilename = g_strconcat(
		settings_config_dir(), 
		G_DIR_SEPARATOR_S, 
		"gtkg.db", 
		(void *) 0);

	sqlite3_open(dbfilename, &persistent_db);
	g_free(dbfilename);
	
	
	result = sqlite3_exec(persistent_db, 
		"SELECT count(*) FROM config", NULL, 0, &error_message);
  
	if (result == SQLITE_ERROR) {
		database_create();
		sqlite3_free(error_message);
	} else if (result != SQLITE_OK) {
		g_error("Error opening databaset (%d) %s", result, error_message);
		sqlite3_free(error_message);
	}
}

void database_close()
{
	sqlite3_close(persistent_db);
}

/**
 * Create an initial database.
 *
 * Creates an initial database creating a config table which can be used to
 * store the schema versions.
 */
void database_create()
{
	int result;
	char *error_message;
	
	result = sqlite3_exec(persistent_db,
		"CREATE TABLE config ("
		"key   VARCHAR(255)    NOT NULL,"
		"value VARCHAR(1024)   NOT NULL"
		");", NULL, 0, &error_message);
		
	g_assert(result == SQLITE_OK);
	
	g_message("[SQLITE3] Database created");
}


char* database_get_config_value(char* key)
{
	char *result;
	
	if (get_config_value_stmt == NULL)
	{
		if ( sqlite3_prepare(
			persistent_db, 
			"select value from config where key = '?'",  // stmt
			-1, // If than zero, then stmt is read up to the first nul terminator
			&get_config_value_stmt,
			0  // Pointer to unused portion of stmt
		) != SQLITE_OK) 
			g_error("\nCould not prepare statement.");
	}
	
	if (sqlite3_bind_text (
		get_config_value_stmt,
		0,  // Parameter 0
        key, strlen(key),
		SQLITE_STATIC
        ) != SQLITE_OK)
			g_error("\nCould not bind key to parameter.\n");
	
	result = (char *) sqlite3_column_text(
		get_config_value_stmt, 
		0 /* first column is our result */);
	
	sqlite3_reset(get_config_value_stmt);
	
	return result;
}


#endif
