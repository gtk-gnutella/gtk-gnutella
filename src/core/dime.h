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

#ifndef _dime_h_
#define _dime_h_

#include "common.h"

struct dime_record {
	const char	*data;
	const char	*options;
	const char	*type;
	const char	*id;
	guint32	 data_length;
	guint16	 options_length;
	guint16	 type_length;
	guint16	 id_length;

	unsigned char	flags;
	unsigned char	version;
	unsigned char	type_t;
	unsigned char	resrvd;
};

void dime_list_free(GSList **list_ptr);
GSList *dime_parse_records(const gchar *data, size_t size);

#endif	/* _dime_h_ */

/* vi: set ts=4 sw=4 cindent: */
