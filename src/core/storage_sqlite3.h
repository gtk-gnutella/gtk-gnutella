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


#ifndef _core_sqlite3_h_
#define _core_sqlite3_h_

#include "common.h"

#ifdef HAS_SQLITE

struct database_stmt;

enum database_step {
	DATABASE_STEP_ROW = 1,
	DATABASE_STEP_DONE = 2,
		
	DATABASE_STEP_ERROR
};

void database_init(void);
void database_close(void);

int database_exec(const char *cmd, char **error_message);
void database_set_config_value(const char *key, const char *value);
const char *database_get_config_value(const char *key);
void database_free(char *error_message);
const char *database_error_message(void);
int database_begin(void);
int database_commit(void);

int database_stmt_prepare(const char *cmd, struct database_stmt **db_stmt);
enum database_step database_stmt_step(struct database_stmt *db_stmt);
int database_stmt_reset(struct database_stmt *db_stmt);
int database_stmt_bind_static_blob(struct database_stmt *db_stmt,
	int parameter, const void *data, size_t size);
int database_stmt_finalize(struct database_stmt **db_stmt);

#else	/* !HAS_SQLITE */
#define database_init()
#define database_close()
#endif	/* HAS_SQLITE */

#endif	/* _core_sqlite3_h_ */
/* vi: set ts=4 sw=4 cindent: */
