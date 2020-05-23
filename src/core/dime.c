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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "dime.h"

#include "lib/endian.h"
#include "lib/mempcpy.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"

#define DIME_VERSION		0x01
#define DIME_HEADER_SIZE	12

enum {
	DIME_F_CF = 1 << 0,
	DIME_F_ME = 1 << 1,
	DIME_F_MB = 1 << 2
};

enum dime_type_t {
	DIME_T_UNCHANGED	= 0x00,
	DIME_T_MIME			= 0x01,
	DIME_T_URI			= 0x02,
	DIME_T_UNKNOWN		= 0x03,
	DIME_T_NONE			= 0x04
};


struct dime_record {
	const char	*data;
	const char	*options;
	const char	*type;
	const char	*id;
	uint32	 data_length;
	uint16	 options_length;
	uint16	 type_length;
	uint16	 id_length;

	unsigned char	flags;
	unsigned char	version;
	unsigned char	type_t;
	unsigned char	resrvd;
};

struct dime_record *
dime_record_alloc(void)
{
	static const struct dime_record zero_record;
	struct dime_record *record;

	WALLOC(record);
	*record = zero_record;
	return record;
}

void
dime_record_free(struct dime_record **record_ptr)
{
	struct dime_record *record = *record_ptr;

	if (record) {
		WFREE(record);
		*record_ptr = NULL;
	}
}

void
dime_list_free(pslist_t **list_ptr)
{
	pslist_t *list = *list_ptr;

	if (list) {
		pslist_t *iter;

		PSLIST_FOREACH(list, iter) {
			struct dime_record *record = iter->data;
			dime_record_free(&record);
		}
		pslist_free(list);
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
	char *data, size_t size, uint flags)
{
	unsigned char value;

	g_assert(record);
	g_assert(data);
	g_assert(size >= DIME_HEADER_SIZE);

	value = DIME_VERSION << 3;
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

static size_t
copy_and_pad(char *dst, const char *src, size_t size)
{
	size_t pad;

	g_assert(NULL != src || 0 == size);
	if (size > 0) {
		void *p;
		pad = dime_ceil(size) - size;
		p = mempcpy(dst, src, size);
		memset(p, 0, pad);
	} else {
		pad = 0;
	}
	return size + pad;
}

size_t
dime_create_record(const struct dime_record *record,
	char **data_ptr, bool first, bool last)
{
	size_t size;

	size = DIME_HEADER_SIZE +
		dime_ceil(record->options_length) +
		dime_ceil(record->id_length) +
		dime_ceil(record->type_length) +
		dime_ceil(record->data_length);

	if (data_ptr) {
		char *data0, *data;
		uint flags;

		data0 = g_malloc(size);
		data = data0;

		flags = (first ? DIME_F_MB : 0) | (last ?  DIME_F_ME : 0);
		dime_fill_record_header(record, data, size, flags);
		data += DIME_HEADER_SIZE;

		data += copy_and_pad(data, record->options, record->options_length);
		data += copy_and_pad(data, record->id, record->id_length);
		data += copy_and_pad(data, record->type, record->type_length);
		data += copy_and_pad(data, record->data, record->data_length);

		*data_ptr = data0;
	}
	return size;
}

/***
 *** Parsing
 ***/

/**
 * Report truncated record.
 */
static void
dime_log_truncated_record(const char *name, const struct dime_record *header,
	size_t announced, size_t real)
{
	const char *type;

	switch (header->type_t) {
	case 0x00:	type = "unchanged"; break;
	case 0x01:	type = "media-type"; break;
	case 0x02:	type = "absolute URI"; break;
	case 0x03:	type = "unknown"; break;
	case 0x04:	type = "none"; break;
	default:	type = "reserved"; break;
	}

	g_warning("dime_parse_record_header(): truncated %s "
		"in \"%s\" record%s%s%s: "
		"announced %zu (padded to %zu), got only %zu byte%s left",
		name, type,
		(header->flags & DIME_F_MB) ? " [MB]" : "",
		(header->flags & DIME_F_ME) ? " [ME]" : "",
		(header->flags & DIME_F_CF) ? " [CF]" : "",
		announced, dime_ceil(announced), real, plural(real));
}

/**
 * Parse ``size'' bytes starting at ``data''  and fill-in the information
 * about the next record in ``header''.
 *
 * @return the length of the record successfully parsed, 0 on error (since
 * the minimal amount of bytes for an empty record would be DIME_HEADER_SIZE).
 */
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
		g_warning("%s(): cannot parse dime version %u, "
			"only version %u is supported",
			G_STRFUNC, header->version, DIME_VERSION);
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
		dime_log_truncated_record("options",
			header, header->options_length, size);
		goto failure;
	}
	size -= n;
	data += n;
	header->id = data;

	n = dime_ceil(header->id_length);
	if (size < n) {
		dime_log_truncated_record("ID", header, header->id_length, size);
		goto failure;
	}
	size -= n;
	data += n;
	header->type = data;

	n = dime_ceil(header->type_length);
	if (size < n) {
		dime_log_truncated_record("type", header, header->type_length, size);
		goto failure;
	}
	size -= n;
	data += n;
	header->data = data;

	n = dime_ceil(header->data_length);
	if (size < n) {
		dime_log_truncated_record("data", header, header->data_length, size);
		goto failure;
	}
	size -= n;
	data += n;

	return data - data0;

failure:
	return 0;
}

pslist_t *
dime_parse_records(const char *data, size_t size)
{
	const char * const data0 = data;
	pslist_t *list = NULL;

	for (;;) {
		struct dime_record *record;
		size_t ret;

		record = dime_record_alloc();
		list = pslist_prepend(list, record);

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
		if (DIME_F_ME & record->flags) {
			break;
		}
	}

	return pslist_reverse(list);

error:

	dime_list_free(&list);
	return NULL;
}

bool
dime_record_set_data(struct dime_record *record, const void *data, size_t size)
{
	g_return_val_if_fail(record, FALSE);
#if 0
	/* Allow data == NULL with size > 0 so that we can create a fake record
	 * to determine its size without copying the data.
	 */
	g_return_val_if_fail(NULL != data || 0 == size, FALSE);
#endif
	g_return_val_if_fail(size < (uint32)-1, FALSE);

	record->data = data;
	record->data_length = size;
	return TRUE;
}

bool
dime_record_set_id(struct dime_record *record, const char *id)
{
	size_t length;

	g_return_val_if_fail(record, FALSE);

	length = id ? vstrlen(id) : 0;
	g_return_val_if_fail(length < (uint16)-1, FALSE);

	record->id = id;
	record->id_length = length;
	return TRUE;
}

static bool
dime_record_set_type(struct dime_record *record,
	enum dime_type_t type_t, const char *type)
{
	size_t length;

	g_return_val_if_fail(record, FALSE);

	length = type ? vstrlen(type) : 0;
	g_return_val_if_fail(length < (uint16)-1, FALSE);

	record->type = type;
	record->type_length = length;
	record->type_t = type_t;
	return TRUE;
}

bool
dime_record_set_type_uri(struct dime_record *record, const char *type)
{
	return dime_record_set_type(record, DIME_T_URI, type);
}

bool
dime_record_set_type_mime(struct dime_record *record, const char *type)
{
	return dime_record_set_type(record, DIME_T_MIME, type);
}

const char *
dime_record_type(const struct dime_record *record)
{
	return record->type;
}

size_t
dime_record_type_length(const struct dime_record *record)
{
	return record->type_length;
}

const char *
dime_record_data(const struct dime_record *record)
{
	return record->data;
}

size_t
dime_record_data_length(const struct dime_record *record)
{
	return record->data_length;
}

const char *
dime_record_id(const struct dime_record *record)
{
	return record->id;
}

size_t
dime_record_id_length(const struct dime_record *record)
{
	return record->id_length;
}

/* vi: set ts=4 sw=4 cindent: */
