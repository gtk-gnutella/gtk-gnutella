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

#include <glib.h>

#include "lib/header.h"		/* For header_t */

struct xfeature_t {
	GList *features;
};

typedef struct xfeatures_t {
	struct xfeature_t uploads;
	struct xfeature_t downloads;
	struct xfeature_t connections;
} xfeatures_t;

/*
 * Public interface.
 */

extern xfeatures_t xfeatures;

gboolean header_get_feature(const gchar *feature_name, const header_t *header,
	guint *feature_version_major, guint *feature_version_minor);
void header_features_add(struct xfeature_t *xfeatures,
	const gchar *feature_name,
	int feature_version_major,
	int feature_version_minor);
void features_close(void);
void header_features_generate(struct xfeature_t *xfeatures,
	gchar *buf, size_t len, size_t *rw);

#endif	/* _core_features_h_ */

/* vi: set ts=4 sw=4 cindent: */
