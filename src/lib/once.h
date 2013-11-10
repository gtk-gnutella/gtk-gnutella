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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Thread-safe once initialization support.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _once_h_
#define _once_h_

/**
 * Tri-state once initialization flag.
 */
typedef enum once_flag {
	ONCE_F_UNDONE = 0,
	ONCE_F_PROGRESS = 1,
	ONCE_F_DONE = 2
} once_flag_t;

/**
 * Once initialization routine.
 */
typedef void (*once_fn_t)(void);

/*
 * Public interface.
 */

bool once_flag_run(once_flag_t *flag, once_fn_t routine);
bool once_flag_runwait(once_flag_t *flag, once_fn_t routine);

#define ONCE_DONE(f)	(ONCE_F_DONE == (f))

#define ONCE_FLAG_RUN(f, r) G_STMT_START {	\
	if G_UNLIKELY(!ONCE_DONE((f)))			\
		once_flag_run(&(f), (r));			\
} G_STMT_END

#define ONCE_FLAG_RUNWAIT(f, r) G_STMT_START {	\
	if G_UNLIKELY(!ONCE_DONE((f)))				\
		once_flag_runwait(&(f), (r));			\
} G_STMT_END

#endif /* _once_h_ */

/* vi: set ts=4 sw=4 cindent: */
