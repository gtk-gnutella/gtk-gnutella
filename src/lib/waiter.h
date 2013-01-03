/*
 * Copyright (c) 2013, Raphael Manfredi
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
 * Asynchronous waiter.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _waiter_h_
#define _waiter_h_

struct waiter;
typedef struct waiter waiter_t;

/*
 * Public interface.
 */

waiter_t *waiter_make(void *data);
waiter_t *waiter_spawn(const waiter_t *wp, void *data);
waiter_t *waiter_refcnt_inc(waiter_t *w);
bool waiter_refcnt_dec(waiter_t *w);
void waiter_destroy_null(waiter_t **w_ptr) NON_NULL_PARAM((1));

void waiter_signal(waiter_t *w);
void waiter_ack(waiter_t *w);
bool waiter_notified(const waiter_t *w);
bool waiter_suspend(const waiter_t *w);

int waiter_fd(const waiter_t *w);
void waiter_close_fd(waiter_t *w);
int waiter_refcnt(const waiter_t *w);
int waiter_child_count(const waiter_t *w);
void *waiter_data(const waiter_t *w);
void *waiter_set_data(waiter_t *w, void *data);

#endif /* _waiter_h_ */

/* vi: set ts=4 sw=4 cindent: */
