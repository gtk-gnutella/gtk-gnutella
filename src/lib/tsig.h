/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * Thread signal set operations.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _tsig_h_
#define _tsig_h_

/**
 * Thread signals.
 *
 * These are not kernel signals, they are only known and handled by the
 * thread layer at specific moments.  The signal is delivered to the thread
 * when it enters the locking code or when it checks for suspension, and then
 * only when the thread does not hold any locks currently.
 */
#define TSIG_0		0			/**< Not a real signal, only checks */
#define TSIG_1		1
#define TSIG_2		2
#define TSIG_3		3
#define TSIG_4		4
#define TSIG_5		5
#define TSIG_6		6
#define TSIG_7		7
#define TSIG_8		8
#define TSIG_9		9

/**
 * Signals with a specific meaning, reserved for the library.
 */

#define TSIG_TEQ	10			/**< Something is in the Thread Event Queue */

#define TSIG_COUNT	11

#define tsig_mask(sig)	(1U << ((sig) - 1))		/* 0 is not a signal */

typedef unsigned int tsigset_t;
typedef void (*tsighandler_t)(int);

/**
 * Special signal handlers.
 */
#define TSIG_DFL		((tsighandler_t) 0)
#define TSIG_IGN		((tsighandler_t) 1)
#define TSIG_ERR		((tsighandler_t) -1)

/*
 * Public interface.
 */

int tsig_addset(tsigset_t *set, int signum);
int tsig_delset(tsigset_t *set, int signum);
bool tsig_ismember(const tsigset_t *set, int signum);

/**
 * Empty the signal set.
 */
static inline void
tsig_emptyset(tsigset_t *set)
{
	g_assert(set != NULL);

	ZERO(set);
}

/**
 * Fill the signal set with ones.
 */
static inline void
tsig_fillset(tsigset_t *set)
{
	g_assert(set != NULL);

	memset(set, 0xff, sizeof *set);
}

/**
 * Is set empty?
 *
 * @return TRUE if set contains no signals.
 */
static inline bool
tsig_isemptyset(const tsigset_t *set)
{
	g_assert(set != NULL);

	return 0 == *set;
}

/**
 * Put result of NOT ``set'' into ``dest''.
 */
static inline void
tsig_notset(tsigset_t *dest, const tsigset_t *set)
{
	g_assert(dest != NULL);
	g_assert(set != NULL);

	*dest = ~*set;
}

/**
 * Put result of ``left'' OR ``right'' into ``dest''.
 */
static inline void
tsig_orset(tsigset_t *dest, const tsigset_t *left, const tsigset_t *right)
{
	g_assert(dest != NULL);
	g_assert(left != NULL);
	g_assert(right != NULL);

	*dest = *left | *right;
}

/**
 * Put result of ``left'' AND ``right'' into ``dest''.
 */
static inline void
tsig_andset(tsigset_t *dest, const tsigset_t *left, const tsigset_t *right)
{
	g_assert(dest != NULL);
	g_assert(left != NULL);
	g_assert(right != NULL);

	*dest = *left & *right;
}

#endif /* _tsig_h_ */

/* vi: set ts=4 sw=4 cindent: */
