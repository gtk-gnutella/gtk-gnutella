/*
 * Copyright (c) 2004, Jeroen Asselman
 *
 * Dime parser / creator
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
 * @file
 *
 * Dime message parsing.
 */

#include "common.h"

#define DIME_VERSION	0x01
#define HEADER_SIZE	12

typedef struct dime_record_s dime_record_t;
struct dime_record_s
{
	char	*options;
	guint16	 options_length;

	char	*id;
	guint16	 id_length;

	char	*type;
	guint16	 type_length;

	char	*data;
	guint32	 data_length;
};

typedef struct dime_record_header_s dime_record_header_t;
struct dime_record_header_s
{
	char	version;
	gboolean	MB;
	gboolean	ME;
	gboolean	CF;
	char	type_t;
	char	resrvd;
	guint16	options_length;
	guint16	id_length;
	guint16	type_length;
	guint32	data_length;

	char	*options;
	char	*id;
	char	*type;
	char	*data;
};

/**
 * Makes a value a multiple of 4.
 */
int dime_ceil(int value)
{
	if (value % 4 == 0)
		return value;
	else
		return value + (4 - value % 4);
}

/**
 * Create a dime record header.
 */
char *dime_create_record_header(dime_record_header_t * dime_record_header)
{
	char *header;

	header = (char *) malloc(HEADER_SIZE);	/* malloc0 */

	header[0] = dime_record_header->version << 3;

	if (dime_record_header->MB) {
		header[0] = header[0] | 0x04;
	}

	if (dime_record_header->ME) {
		header[0] = header[0] | 0x02;
	}

	if (dime_record_header->CF) {
		header[0] = header[0] | 0x01;
	}

	header[1] = dime_record_header->type_t << 4;
	header[1] = header[1] | dime_record_header->resrvd;

	/* BE first */
	/* GUINT16/32_TO_BE(dime_record_header->data_length); */

	*((guint16 *) &header[2]) = dime_record_header->options_length;
	*((guint16 *) &header[4]) = dime_record_header->id_length;
	*((guint16 *) &header[6]) = dime_record_header->type_length;
	*((guint32 *) &header[8]) = dime_record_header->data_length;

	return header;
}

char *dime_create_record(dime_record_t *dime_record, gboolean firstrecord,
						 gboolean lastrecord)
{
	dime_record_header_t dime_record_header;
	int recordlength = HEADER_SIZE;
	char *recordheader;

	char *record = (char *) malloc(HEADER_SIZE /* Header length */ +
		dime_ceil(dime_record->options_length) +
		dime_ceil(dime_record->id_length) +
		dime_ceil(dime_record->type_length) +
		dime_ceil(dime_record->data_length));

	dime_record_header.MB = firstrecord;
	dime_record_header.ME = lastrecord;
	dime_record_header.CF = FALSE;

	recordheader = dime_create_record_header(&dime_record_header);

	memcpy(record, recordheader, HEADER_SIZE);
	free(recordheader);

	memcpy(record + recordlength, dime_record->options, dime_record->options_length);
	recordlength += dime_ceil(dime_record->options_length);

	memcpy(record + recordlength, dime_record->id, dime_record->id_length);
	recordlength += dime_ceil(dime_record->id_length);

	memcpy(record + recordlength, dime_record->type, dime_record->type_length);
	recordlength += dime_ceil(dime_record->type_length);

	memcpy(record + recordlength, dime_record->data, dime_record->data_length);
	recordlength += dime_ceil(dime_record->data_length);

	return record;
}

/***
 *** Parsing
 ***/
gboolean dime_parse_record_header(char *dime_record,
								  dime_record_header_t *dime_record_header)
{
	dime_record_header->version = dime_record[0] >> 3;

	if (dime_record_header->version != DIME_VERSION) {
		printf("Can not parse dime version %d, only version %d is supported\n",
			  dime_record_header->version, DIME_VERSION);
		return FALSE;
	}

	dime_record_header->MB = (dime_record[0] & 0x04) == 1;
	dime_record_header->ME = (dime_record[0] & 0x02) == 1;
	dime_record_header->CF = (dime_record[0] & 0x01) == 1;

	dime_record_header->type_t = dime_record[1] >> 4;
	dime_record_header->resrvd = dime_record[1] & 0x0F;

	/* FIXME: GUINT16/32_FROM_BE() */
	dime_record_header->options_length	= *(guint16 *) &dime_record[2];
	dime_record_header->id_length		= *(guint16 *) &dime_record[4];
	dime_record_header->type_length		= *(guint16 *) &dime_record[6];

	dime_record_header->data_length		= *(guint32 *) &dime_record[8];

	dime_record_header->options	= &dime_record[8];
	dime_record_header->id		=  dime_record_header->options	+
		dime_record_header->options_length;	/* FIXME: Round to a multiple of 4 octets */
	dime_record_header->type	=  dime_record_header->id		+
		dime_record_header->id_length;		/* FIXME: Round to a multiple of 4 octets */
	dime_record_header->data	=  dime_record_header->type		+
		dime_record_header->type_length;	/* FIXME: Round to a multiple of 4 octets */

	return TRUE;
}

gboolean dime_parse_records(char *data)
{
	dime_record_header_t record_header;
	dime_record_t *dime_record = (dime_record_t *) malloc(sizeof(dime_record_t));

	dime_record->data = NULL;
	dime_record->data_length = 0;
	dime_record->id = NULL;
	dime_record->id_length = 0;
	dime_record->options = NULL;
	dime_record->options_length = 0;
	dime_record->type = NULL;
	dime_record->type_length = 0;

	gboolean start = TRUE;

	do {
		if (!dime_parse_record_header(data, &record_header))
			goto error;

		if (start) {
			if (record_header.MB != TRUE) {
				/* FIXME: Warning, no message begin flag */
				goto error;
			}
		}

		dime_record->data = (char *) realloc(dime_record->data,
			  dime_record->data_length + record_header.data_length);

		memcpy(&dime_record->data[dime_record->data_length], record_header.data, record_header.data_length);

		dime_record->data_length =
			  dime_record->data_length + record_header.data_length;


		if (!record_header.CF) {
			/* FIXME: Add to Glist */
			dime_record = (dime_record_t *) malloc(sizeof(dime_record_t));
		}

		start = FALSE;

		/* Need some protection to avoid corrupt DIME packets and
		 * start parsing memory which is not ours to parse */
	} while(record_header.ME == FALSE);

	return TRUE;

error:
	/* For each in the list */
	if (dime_record->data != NULL)
		free(dime_record->data);

	if (dime_record->id != NULL)
		free(dime_record->id);

	if (dime_record->options != NULL)
		free(dime_record->options);

	if (dime_record->type != NULL)
		free(dime_record->type);

	free(dime_record);

	return FALSE;
}

