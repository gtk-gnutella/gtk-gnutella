/* -*- mode: cc-mode; tab-width:4; -*-
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

#include <glib.h>


#include <time.h>		/* for time_t */

/*
 * Bitzi Meta-data structure
 *
 * Both Core and GUI have visability of this data structure
 */
typedef enum {
	UNKNOWN=0,
	DANGEROUS_MISLEADING,
	INCOMPLETE_DAMAGED,
	SUBSTANDARD,
	OVERRATED,
	NORMAL,
	UNDERRATED,
	COMPLETE,
	RECOMMENDED,
	BEST_VERSION,
	MAX_JUDGEMENT,
} bitzi_fj_t;

/**
 * @struct
 */
typedef struct {
	gchar		*urnsha1;		/* pointer to urnsha1 atom */
	gchar		*mime_type;		/* mime type */
	gchar		*mime_desc;		/* mime details (fps, bitrate etc) */
	guint32		size;			/* size of file */
    bitzi_fj_t	judgement;
	float		goodness;
	time_t		expiry;		/* expiry date of meta-data */
} bitzi_data_t;

#ifdef CORE_SOURCES

/*
 * Bitzi Core API declartions
 *
 * bitzi_query_* are initiated via the gui and will generate
 * notification events
 *
 * bitzi_querycache_* are used internally for gui querys as well as
 * from within the core. They do not generate notification events
 */

gpointer bitzi_query_byurnsha1(const gchar *urnsha1);
bitzi_data_t *bitzi_querycache_byurnsha1(const gchar *urnsha1);

#endif /* CORE_SOURCES */

#endif /* _core_bitzi_h_ */
