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

#ifndef _ui_core_interface_hsep_defs_h_
#define _ui_core_interface_hsep_defs_h_

/* number of hops to consider */
#define HSEP_N_MAX 7

/* average time in seconds before resending a */
/* HSEP message to a node (can be increased to 60) */
/* TODO: make this configurable? */
#define HSEP_MSG_INTERVAL 30 

/* random skew in seconds for message interval */
/* time is in the interval msg_interval +/- msg_skew */
/* TODO: make this configurable? */
#define HSEP_MSG_SKEW 10

typedef guint64 hsep_triple[3];

enum {
	HSEP_IDX_NODES = 0,
	HSEP_IDX_FILES = 1,
	HSEP_IDX_KIB = 2
};

#endif
