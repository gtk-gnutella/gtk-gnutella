/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * G2 tree formatting.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_g2_tfmt_h_
#define _core_g2_tfmt_h_

/**
 * Formatter options.
 */
#define G2FMT_O_PAYLOAD		(1 << 0)	/**< Dump payloads as well */
#define G2FMT_O_PAYLEN		(1 << 1)	/**< Show payload lengths */

/*
 * Public interface.
 */

struct ostream;
struct g2_tree;

bool g2_tfmt_tree(const struct g2_tree *root, struct ostream *os, uint32 opt);
bool g2_tfmt_tree_dump(const struct g2_tree *root, FILE *f, uint32 opt);

#endif /* _core_g2_tfmt_h_ */

/* vi: set ts=4 sw=4 cindent: */
