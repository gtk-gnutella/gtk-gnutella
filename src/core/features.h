/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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
 * Header parsing routines.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _core_features_h_
#define _core_features_h_

#include "common.h"

#include "lib/header.h"		/* For header_t */

typedef enum {
	FEATURES_DOWNLOADS,
	FEATURES_UPLOADS,
	FEATURES_CONNECTIONS,

	NUM_FEATURES
} xfeature_t;

/*
 * Public interface.
 */

gboolean header_get_feature(const gchar *feature_name, const header_t *header,
		guint *feature_version_major, guint *feature_version_minor);
void header_features_add(xfeature_t xf, const gchar *feature_name,
		int feature_version_major, int feature_version_minor);
void features_close(void);
void header_features_generate(xfeature_t xf,
		gchar *buf, size_t len, size_t *rw);

#endif	/* _core_features_h_ */

/* vi: set ts=4 sw=4 cindent: */
