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

struct gdb_stmt;

enum gdb_step {
	GDB_STEP_ROW = 1,
	GDB_STEP_DONE = 2,
		
	GDB_STEP_ERROR
};

void gdb_init(void);
void gdb_close(void);

int gdb_exec(const char *cmd, char **error_message);
void gdb_set_config_value(const char *key, const char *value);
const char *gdb_get_config_value(const char *key);
void gdb_free(char *error_message);
const char *gdb_error_message(void);
int gdb_begin(void);
int gdb_commit(void);

int gdb_stmt_prepare(const char *cmd, struct gdb_stmt **db_stmt);
enum gdb_step gdb_stmt_step(struct gdb_stmt *db_stmt);
int gdb_stmt_reset(struct gdb_stmt *db_stmt);
int gdb_stmt_bind_static_blob(struct gdb_stmt *db_stmt,
	int parameter, const void *data, size_t size);
int gdb_stmt_finalize(struct gdb_stmt **db_stmt);

#else	/* !HAS_SQLITE */
#define gdb_init()
#define gdb_close()
#define gdb_begin()
#define gdb_commit()
#endif	/* HAS_SQLITE */

#endif	/* _core_sqlite3_h_ */
/* vi: set ts=4 sw=4 cindent: */
