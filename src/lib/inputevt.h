/*
 * Copyright (c) 2002, ko (ko-@wanadoo.fr)
 * Copyright (c) 2005, Christian Biere
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
 * Input I/O notification.
 *
 * @author ko (ko-@wanadoo.fr)
 * @date 2002
 * @author Christian Biere
 * @date 2005
 */

#ifndef _inputevt_h_
#define _inputevt_h_

#include "common.h" 

/**
 * This mimics the GDK input condition type.
 */
typedef enum {
	INPUT_EVENT_R			= 1 << 0,	/* poll for Read events */
	INPUT_EVENT_W			= 1 << 1,	/* poll for Write events */
	INPUT_EVENT_EXCEPTION	= 1 << 2,	/* poll for exceptions */

	INPUT_EVENT_NONE        = 0,

	INPUT_EVENT_RX  = ((uint) INPUT_EVENT_R  | (uint) INPUT_EVENT_EXCEPTION),
	INPUT_EVENT_WX  = ((uint) INPUT_EVENT_W  | (uint) INPUT_EVENT_EXCEPTION),
	
	INPUT_EVENT_RW  = ((uint) INPUT_EVENT_R  | (uint) INPUT_EVENT_W),
	INPUT_EVENT_RWX = ((uint) INPUT_EVENT_RW | (uint) INPUT_EVENT_EXCEPTION)
} inputevt_cond_t;

/**
 * And the handler function type.
 */
typedef void (*inputevt_handler_t) (
	void *data,
	int source,
	inputevt_cond_t condition
);

/*
 * Module initialization and cleanup functions.
 */

void inputevt_init(int use_poll);
void inputevt_close(void);
void inputevt_dispatch(void);

void inputevt_set_debug(unsigned level);
unsigned inputevt_thread_id(void);

/**
 * This emulates the GDK input interface.
 */
unsigned inputevt_add(int source, inputevt_cond_t condition,
	inputevt_handler_t handler, void *data);

const char *inputevt_cond_to_string(inputevt_cond_t cond);
size_t inputevt_data_available(void);
void inputevt_remove(unsigned *id_ptr);
void inputevt_set_readable(int fd);

#endif  /* _inputevt_h_ */

/* vi: set ts=4 sw=4 cindent: */
