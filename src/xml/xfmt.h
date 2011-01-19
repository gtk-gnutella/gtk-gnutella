/*
 * $Id$
 *
 * Copyright (c) 2010, Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * XML tree formatter.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#ifndef _xfmt_h_
#define _xfmt_h_

#include "common.h"

#include "xnode.h"
#include "lib/ostream.h"

/**
 * Formatter options.
 */
#define XFMT_O_SKIP_BLANKS		(1 << 0)	/**< Strip pure blank text */
#define XFMT_O_COLLAPSE_BLANKS	(1 << 1)	/**< Collapse consecutive blanks */
#define XFMT_O_NO_INDENT		(1 << 2)	/**< Do not indent */
#define XFMT_O_PROLOGUE			(1 << 3)	/**< Include XML prologue */
#define XFMT_O_FORCE_10			(1 << 4)	/**< Force XML 1.0 */

/**
 * User-defined namespace prefix mappings.
 */
struct xfmt_prefix {
	const char *uri;			/**< The URI to map */
	const char *prefix;			/**< The prefix to use */
};

/*
 * Public interface.
 */

gboolean xfmt_tree(const xnode_t *root, ostream_t *os, guint32 options);
gboolean xfmt_tree_extended(const xnode_t *root, ostream_t *os,
	guint32 options,
	const struct xfmt_prefix *pvec, size_t pvcnt,
	const char *default_ns);

gboolean xfmt_tree_dump(const xnode_t *root, FILE *f);

#endif /* _xfmt_h_ */

/* vi: set ts=4 sw=4 cindent: */
