/*
 * Copyright (c) 2004, Jeroen Asselman
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
 * Dime parser / creator.
 *
 * @author Jeroen Asselman
 * @date 2004
 */

/* Dime message parsing. */

#ifndef _dime_h_
#define _dime_h_

#include "common.h"

struct dime_record;
struct pslist;

struct dime_record *dime_record_alloc(void);
void dime_record_free(struct dime_record **record_ptr);

size_t dime_create_record(const struct dime_record *record,
			char **data_ptr, bool first, bool last);

bool dime_record_set_data(struct dime_record *record,
			const void *data, size_t size);
bool dime_record_set_id(struct dime_record *record, const char *id);
bool dime_record_set_type_uri(struct dime_record *, const char *type);
bool dime_record_set_type_mime(struct dime_record *, const char *type);

void dime_list_free(struct pslist **list_ptr);
struct pslist *dime_parse_records(const char *data, size_t size);

const char *dime_record_type(const struct dime_record *record);
size_t dime_record_type_length(const struct dime_record *record);
const char *dime_record_id(const struct dime_record *record);
size_t dime_record_id_length(const struct dime_record *record);
const char *dime_record_data(const struct dime_record *record);
size_t dime_record_data_length(const struct dime_record *record);

#endif	/* _dime_h_ */

/* vi: set ts=4 sw=4 cindent: */
