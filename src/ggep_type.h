/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * GGEP type-specific routines.
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

#ifndef _ggep_type_h_
#define _ggep_type_h_

#include <glib.h>

/*
 * Extraction interface return types.
 */

typedef enum ggept_status {
	GGEP_OK = 0,					/* OK, extracted what was asked */
	GGEP_NOT_FOUND = 1,				/* OK, but did not find it */
	GGEP_INVALID = 2,				/* Error, found something invalid */
	GGEP_BAD_SIZE = 3,				/* Error, buffer not correctly sized */
} ggept_status_t;

/*
 * Public interface.
 */

struct gnutella_host;

ggept_status_t ggept_h_sha1_extract(extvec_t *exv, gchar *buf, gint len);

struct ggep_gtkgv1 {				/* Decompiled payload of "GTKGV1" */
	guint8 major;
	guint8 minor;
	guint8 patch;
	guint8 revchar;
	guint32 release;
	guint32 start;
};

ggept_status_t ggept_gtkgv1_extract(extvec_t *exv, struct ggep_gtkgv1 *info);

ggept_status_t ggept_alt_extract(extvec_t *exv,
	struct gnutella_host **hvec, gint *hvcnt);

#endif	/* _ggep_type_h_ */

/* vi: set ts=4: */

