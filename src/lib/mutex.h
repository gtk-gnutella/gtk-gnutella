/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Mutual thread exclusion locks.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _mutex_h_
#define _mutex_h_

#include "spinlock.h"
#include "thread.h"

enum mutex_magic {
	MUTEX_MAGIC = 0x1a35dfeb,
	MUTEX_DESTROYED = 0x24fd2039
};

/**
 * A mutex is just a memory location holding an integer value (the lock)
 * a thread owner and an ownership depth.
 *
 * When the integer is 0, the lock is available, when the integer is 1
 * the lock is busy.
 */
typedef struct mutex {
	enum mutex_magic magic;
	unsigned long owner;
	size_t depth;
	spinlock_t lock;
} mutex_t;

/**
 * Static initialization value for a mutex structure.
 */
#define MUTEX_INIT	{ MUTEX_MAGIC, 0L, 0L, SPINLOCK_INIT }

/*
 * These should not be called directly by user code to allow debugging.
 */

void mutex_grab(mutex_t *m);
bool mutex_grab_try(mutex_t *m);

/*
 * Public interface.
 */

#ifdef SPINLOCK_DEBUG
void mutex_grab_from(mutex_t *m, const char *file, unsigned line);
bool mutex_grab_try_from(mutex_t *m, const char *file, unsigned line);

#define mutex_get(x)		mutex_grab_from((x), _WHERE_, __LINE__)
#define mutex_get_try(x)	mutex_grab_try_from((x), _WHERE_, __LINE__)

#define mutex_get_const(x)	\
	mutex_grab_from(deconstify_pointer(x), _WHERE_, __LINE__)

#else
#define mutex_get(x)		mutex_grab((x))
#define mutex_get_try(x)	mutex_grab_try((x))
#define mutex_get_const(x)	mutex_grab(deconstify_pointer(x))
#endif	/* SPINLOCK_DEBUG */

void mutex_init(mutex_t *m);
void mutex_destroy(mutex_t *m);
void mutex_release(mutex_t *m);
void mutex_release_const(const mutex_t *m);
bool mutex_is_owned(const mutex_t *m);
bool mutex_is_owned_by(const mutex_t *m, const thread_t t);
size_t mutex_held_depth(const mutex_t *m);

#endif /* _mutex_h_ */

/* vi: set ts=4 sw=4 cindent: */
