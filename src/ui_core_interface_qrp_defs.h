/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_qrp_defs_h_
#define _ui_core_interface_qrp_defs_h_

#define QRP_MIN_WORD_LENGTH		3		/* Minimal word length */

/*
 * Query routing: structures to keep track of all the query hashes,
 * and where they come from..
 */

enum query_hsrc {
	QUERY_H_WORD = 0,				/* Query word (AND-ed) */
	QUERY_H_URN,					/* URN (OR-ed) */
};

struct query_hash {
	guint32 hashcode;
	enum query_hsrc source;
};

typedef struct query_hashvec {
	gint count;				/* Amount of slots actually taken */
	gint size;				/* Amount of slots in vector */
	struct query_hash *vec;	/* Vector of at most `size' entries */
} query_hashvec_t;

typedef struct qrt_info {
	gint slots;				/* Amount of slots */
	gint generation;		/* Generation number */
	gint fill_ratio;		/* Percentage of slots used */
	gint pass_throw;		/* Passing throw, on a d100 */
} qrt_info_t;


typedef void (*qrp_callback_t)(gpointer arg, gboolean cancelled);

#endif
