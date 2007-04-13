/*
 * $Id$
 *
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

#include "common.h"

RCSID("$Id$")

#include "dime.h"

#include "lib/endian.h"
#include "lib/walloc.h"

#include "lib/override.h"

#define DIME_VERSION		0x01
#define DIME_HEADER_SIZE	12

enum {
	DIME_F_CF = 1 << 0,
	DIME_F_ME = 1 << 1,
	DIME_F_MB = 1 << 2
};

static struct dime_record *
dime_record_alloc(void)
{
	static const struct dime_record zero_record;
	struct dime_record *record;

	record = walloc(sizeof *record);
	*record = zero_record;
	return record;
}

static void
dime_record_free(struct dime_record **record_ptr)
{
	struct dime_record *record = *record_ptr;

	if (record) {
		wfree(record, sizeof *record);
		*record_ptr = NULL;
	}
}

void
dime_list_free(GSList **list_ptr)
{
	GSList *list = *list_ptr;

	if (list) {
		GSList *iter;

		for (iter = list; NULL != iter; iter = g_slist_next(iter)) {
			struct dime_record *record = iter->data;
			dime_record_free(&record);
		}
		g_slist_free(list);
		*list_ptr = NULL;
	}
}

/**
 * Makes a value a multiple of 4.
 */
static inline size_t
dime_ceil(size_t value)
{
	return (value + 3) & ~(size_t) 3;
}

/**
 * Create a dime record header.
 */
static void
dime_fill_record_header(const struct dime_record *record,
	char *data, size_t size, guint flags)
{
	unsigned char value;

	g_assert(record);
	g_assert(data);
	g_assert(size >= DIME_HEADER_SIZE);

	value = record->version << 3;
	value |= (DIME_F_MB & flags);
	value |= (DIME_F_ME & flags);
	value |= (DIME_F_CF & flags);

	poke_u8(&data[0], value);
	poke_u8(&data[1], (record->type_t << 4) | record->resrvd);
	poke_be16(&data[2], record->options_length);
	poke_be16(&data[4], record->id_length);
	poke_be16(&data[6], record->type_length);
	poke_be32(&data[8], record->data_length);
}

char *
dime_create_record(const struct dime_record *record,
	gboolean first, gboolean last)
{
	char *data0, *data;
	size_t size;
	guint flags;

	size = DIME_HEADER_SIZE +
		dime_ceil(record->options_length) +
		dime_ceil(record->id_length) +
		dime_ceil(record->type_length) +
		dime_ceil(record->data_length);

	data0 = g_malloc0(size);
	data = data0;

	flags = (first ? DIME_F_MB : 0) | (last ?  DIME_F_ME : 0);
	dime_fill_record_header(record, data, size, flags);
	data += DIME_HEADER_SIZE;

	memcpy(data, record->options, record->options_length);
	data += dime_ceil(record->options_length);

	memcpy(data, record->id, record->id_length);
	data += dime_ceil(record->id_length);

	memcpy(data, record->type, record->type_length);
	data += dime_ceil(record->type_length);

	memcpy(data, record->data, record->data_length);
	data += dime_ceil(record->data_length);

	return data0;
}

/***
 *** Parsing
 ***/
static size_t
dime_parse_record_header(const char *data, size_t size,
	struct dime_record *header)
{
	const char * const data0 = data;
	size_t n;
	
	g_assert(data);
	g_assert(header);

	n = DIME_HEADER_SIZE;
	if (size < n) {
		goto failure;
	}
	
	header->version = peek_u8(&data[0]) >> 3;

	if (DIME_VERSION != header->version) {
		g_warning("Cannot parse dime version %u, only version %u is supported",
			header->version, DIME_VERSION);
		goto failure;
	}

	header->flags = peek_u8(&data[0]) & (DIME_F_MB | DIME_F_ME | DIME_F_CF);
	header->type_t = peek_u8(&data[1]) >> 4;
	header->resrvd = peek_u8(&data[1]) & 0x0F;

	header->options_length	= peek_be16(&data[2]);
	header->id_length		= peek_be16(&data[4]);
	header->type_length		= peek_be16(&data[6]);
	header->data_length		= peek_be32(&data[8]);

	size -= n;
	data += n;
	header->options	= data;

	n = dime_ceil(header->options_length);
	if (size < n) {
		goto failure;
	}
	size -= n;
	data += n;
	header->id = data;

	n = dime_ceil(header->id_length);
	if (size < n) {
		goto failure;
	}
	size -= n;
	data += n;
	header->type = data;

	n = dime_ceil(header->type_length);
	if (size < n) {
		goto failure;
	}
	size -= n;
	data += n;
	header->data = data;

	n = dime_ceil(header->data_length);
	if (size < n) {
		goto failure;
	}
	size -= n;
	data += n;

	return data - data0;

failure:
	return 0;
}

GSList *
dime_parse_records(const gchar *data, size_t size)
{
	const gchar * const data0 = data;
	GSList *list = NULL;

	for (;;) {
		struct dime_record *record;
		size_t ret;
		
		record = dime_record_alloc();
		list = g_slist_prepend(list, record);
		
		ret = dime_parse_record_header(data, size, record);
		if (0 == ret) {
			goto error;
		}
		data += ret;
		size -= ret;

		if (data0 == data) {
			if (0 == (DIME_F_MB & record->flags)) {
				/* FIXME: Warning, no message begin flag */
				goto error;
			}
		}
		if (0 == (DIME_F_ME & record->flags)) {
			break;
		}
	}

	return g_slist_reverse(list);

error:

	dime_list_free(&list);
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
