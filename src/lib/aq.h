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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Asynchronous queue.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _aq_h_
#define _aq_h_

struct async_queue;
typedef struct async_queue aqueue_t;

/*
 * Public interface.
 */

struct tmval;

aqueue_t *aq_make(void);
aqueue_t *aq_make_full(bool signals);
aqueue_t *aq_refcnt_inc(aqueue_t *aq);
bool aq_refcnt_dec(aqueue_t *aq);
void aq_destroy_null(aqueue_t **aq_ptr) NON_NULL_PARAM((1));

struct waiter;

void aq_waiter_add(aqueue_t *aq, struct waiter *w);
bool aq_waiter_remove(aqueue_t *aq, struct waiter *w);

size_t aq_count(const aqueue_t *aq);

size_t aq_put(aqueue_t *aq, void *data);
void *aq_remove(aqueue_t *aq);
void *aq_timed_remove(aqueue_t *aq, const struct tmval *timeout);
void *aq_remove_try(aqueue_t *aq);

void aq_lock(aqueue_t *aq);
void aq_unlock(aqueue_t *aq);

#endif /* _aq_h_ */

/* vi: set ts=4 sw=4 cindent: */
