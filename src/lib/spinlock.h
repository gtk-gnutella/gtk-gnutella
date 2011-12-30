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
 * Spinning locks.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _spinlock_h_
#define _spinlock_h_

#if 1
#define SPINLOCK_DEBUG
#endif

enum spinlock_magic {
	SPINLOCK_MAGIC = 0x3918493e,
	SPINLOCK_DESTROYED = 0x132842f9
};

/**
 * A spinlock is just a memory location holding an integer value.
 *
 * When the integer is 0, the lock is available, when the integer is 1
 * the lock is busy.
 */
typedef struct spinlock {
	enum spinlock_magic magic;
	int lock;
#ifdef SPINLOCK_DEBUG
	const char *file;
	unsigned line;
#endif
} spinlock_t;

/**
 * Static initialization value for a spinlock structure.
 */
#ifdef SPINLOCK_DEBUG
#define SPINLOCK_INIT	{ SPINLOCK_MAGIC, 0, NULL, 0 }
#else
#define SPINLOCK_INIT	{ SPINLOCK_MAGIC, 0 }
#endif

/*
 * These should not be called directly by user code to allow debugging.
 */

void spinlock_grab(spinlock_t *s);
gboolean spinlock_grab_try(spinlock_t *s);

/*
 * Public interface.
 */

#ifdef SPINLOCK_DEBUG
void spinlock_grab_from(spinlock_t *s, const char *file, unsigned line);
gboolean spinlock_grab_try_from(spinlock_t *s, const char *file, unsigned line);

#define spinlock(x)		spinlock_grab_from((x), _WHERE_, __LINE__)
#define spinlock_try(x)	spinlock_grab_try_from((x), _WHERE_, __LINE__)
#else
#define spinlock(x)		spinlock_grab((x))
#define spinlock_try(x)	spinlock_grab_try((x))
#endif	/* SPINLOCK_DEBUG */

void spinlock_init(spinlock_t *s);
void spinlock_destroy(spinlock_t *s);
void spinunlock(spinlock_t *s);
gboolean spinlock_is_held(const spinlock_t *s);

#endif /* _spinlock_h_ */

/* vi: set ts=4 sw=4 cindent: */
