/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Semaphore management.
 *
 * A semaphore is a global token pool that anybody can attempt to grab from
 * and release to.  When attempting to grab more than the amount of tokens it
 * has available, the process blocks until the corresponding amount of tokens
 * is made available by somebody else.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _semaphore_h_
#define _semaphore_h_

#include "tm.h"

struct semaphore;
typedef struct semaphore semaphore_t;

/*
 * Public interface.
 */

semaphore_t *semaphore_create(int tokens);
semaphore_t *semaphore_create_full(int tokens, bool emulated);
int semaphore_value(const semaphore_t *s);
bool semaphore_acquire(semaphore_t *s, int amount, const tm_t *timeout);
bool semaphore_acquire_try(semaphore_t *s, int amount);
void semaphore_release(semaphore_t *s, int amount);
void semaphore_destroy(semaphore_t **s_ptr);

size_t semaphore_kernel_usage(size_t *inuse);

#endif /* _semaphore_h_ */

/* vi: set ts=4 sw=4 cindent: */
