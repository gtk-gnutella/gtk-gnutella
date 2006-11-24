/*
 * $Id$
 *
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
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

#ifndef _if_core_bitzi_h_
#define _if_core_bitzi_h_

#include "common.h"

/**
 * Bitzi Meta-data structure
 *
 * Both Core and GUI have visibility of this data structure
 */

typedef enum {
	BITZI_FJ_UNKNOWN = 0,
	BITZI_FJ_DANGEROUS_MISLEADING,
	BITZI_FJ_INCOMPLETE_DAMAGED,
	BITZI_FJ_SUBSTANDARD,
	BITZI_FJ_OVERRATED,
	BITZI_FJ_NORMAL,
	BITZI_FJ_UNDERRATED,
	BITZI_FJ_COMPLETE,
	BITZI_FJ_RECOMMENDED,
	BITZI_FJ_BEST_VERSION,

	NUM_BITZI_FJ
} bitzi_fj_t;

/**
 * bitzi_data_t
 */
typedef struct {
	const gchar	*sha1;			/**< pointer to SHA-1 atom */
	gchar		*mime_type;		/**< mime type */
	gchar		*mime_desc;		/**< mime details (fps, bitrate etc) */
	filesize_t	size;			/**< size of file */
	bitzi_fj_t	judgement;
	gfloat		goodness;
	time_t		expiry;			/**< expiry date of meta-data */
} bitzi_data_t;

#ifdef CORE_SOURCES

/*
 * Bitzi Core API declarations
 *
 * bitzi_query_* are initiated via the gui and will generate
 * notification events
 *
 * bitzi_query_cache_* are used internally for gui querys as well as
 * from within the core. They do not generate notification events
 */

gpointer bitzi_query_by_sha1(const gchar *sha1);
bitzi_data_t *bitzi_query_cache_by_sha1(const gchar *sha1);

#endif /* CORE_SOURCES */

#endif /* _core_bitzi_h_ */
/* -*- mode: cc-mode; tab-width:4; -*- */
/* vi: set ts=4 sw=4 cindent: */
