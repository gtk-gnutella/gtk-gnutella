/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Callout queue.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _cq_h_
#define _cq_h_

#include "common.h" 

struct cqueue;
typedef struct cqueue cqueue_t;

struct cevent;
typedef struct cevent cevent_t;

typedef void (*cq_service_t)(struct cqueue *cq, gpointer udata);

typedef guint64 cq_time_t;		/**< Virtual time for callout queue */

/*
 * Interface routines.
 */

extern cqueue_t *callout_queue;	/* Single global instance */

double callout_queue_coverage(int old_ticks);

void cq_init(void);
void cq_close(void);

cqueue_t *cq_make(cq_time_t now);
void cq_free(cqueue_t *cq);
cevent_t *cq_insert(cqueue_t *cq, int delay, cq_service_t fn, gpointer arg);
void cq_expire(cqueue_t *cq, cevent_t *ev);
void cq_cancel(cqueue_t *cq, cevent_t **handle_ptr);
void cq_resched(cqueue_t *cq, cevent_t *handle, int delay);
void cq_clock(cqueue_t *cq, int elapsed);
int cq_ticks(cqueue_t *cq);
int cq_count(const cqueue_t *cq);

#endif	/* _cq_h_ */

/* vi: set ts=4: */
