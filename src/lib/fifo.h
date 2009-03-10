/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * A FIFO.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#ifndef _fifo_h_
#define _fifo_h_

#include "common.h" 

typedef struct fifo {
	gpointer data;
} fifo_t;

typedef void (*fifo_free_t)(gpointer item, gpointer udata);

fifo_t *fifo_make(void);
void fifo_free(fifo_t *f);
void fifo_free_all(fifo_t *f, fifo_free_t cb, gpointer udata);
int fifo_count(fifo_t *f);
void fifo_put(fifo_t *f, gconstpointer data);
gpointer fifo_remove(fifo_t *f);

#endif /* _fifo_h_ */

