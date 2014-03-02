/*
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
	FEATURES_G2_CONNECTIONS,

	NUM_FEATURES
} xfeature_t;

/*
 * Public interface.
 */

bool header_get_feature(const char *name, const header_t *header,
		uint *major, uint *minor);
void header_features_add(xfeature_t xf, const char *name, int major, int minor);
void header_features_add_guarded(xfeature_t xf, const char *name,
	int major, int minor, const bool *guard);
void header_features_add_guarded_function(xfeature_t xf,
	const char *name, int major, int minor, bool (*guardfn)(void));
void header_features_generate(xfeature_t xf, char *buf, size_t len, size_t *rw);

void features_close(void);

#endif	/* _core_features_h_ */

/* vi: set ts=4 sw=4 cindent: */
