/*
 * Copyright (c) 2004, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_hsep_h_
#define _if_core_hsep_h_

#include "common.h"

#include "lib/event.h"		/* For frequency_t */

typedef uint64 hsep_triple[3];

#define HSEP_N_MAX 7		/**< number of hops to consider */

enum {
	HSEP_IDX_NODES = 0,
	HSEP_IDX_FILES = 1,
	HSEP_IDX_KIB = 2
};

/*
 * Public interface, visible from the bridge.
 */

#ifdef CORE_SOURCES

typedef struct {
	hsep_triple table[HSEP_N_MAX + 1];      /**< Connection's HSEP table */
	hsep_triple sent_table[HSEP_N_MAX];     /**< Previous table sent */
	time_t last_sent;                       /**< When last msg was sent */
	time_t last_received;                   /**< When last msg was rcvd */
	uint32 msgs_received;                   /**< # of msgs received */
	uint32 triples_received;                /**< # of triples received */
	uint32 msgs_sent;                       /**< # of msgs sent */
	uint32 triples_sent;                    /**< # of triples sent */
	int random_skew;		/**< additonal random delay for next exchange */
	uint8 major;			/**< their major version */
	uint8 minor;			/**< their minor version */
} hsep_ctx_t;

const char *hsep_get_static_str(int row, int column);
int hsep_get_table_size(void);
void hsep_get_non_hsep_triple(hsep_triple *tripledest);
void hsep_add_global_table_listener(callback_fn_t cb,
	frequency_t type, uint32 interval);
void hsep_remove_global_table_listener(callback_fn_t cb);

#endif /* CORE_SOURCES */
#endif /* _if_core_hsep_h */

/* vi: set ts=4 sw=4 cindent: */
