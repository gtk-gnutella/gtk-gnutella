/*
 * Copyright (c) 2008 Christian Biere
 * Copyright (c) 2012 Raphael Manfredi
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
 * Process suspension until a signal is received.
 *
 * @author Raphael Manfredi
 * @date 2012
 * @author Chritian Biere
 * @date 2008
 */

#include "common.h"

#include "compat_pause.h"
#include "compat_sleep_ms.h"
#include "thread.h"

#include "override.h"		/* Must be the last header included */

/**
 * Suspend process until a signal is delivered.
 *
 * @note
 * This routine is a cancellation point.
 */
void
compat_pause(void)
{
	thread_cancel_test();

#if defined(HAS_SIGPROCMASK)
	{
		sigset_t oset;

		if (sigprocmask(SIG_BLOCK, NULL, &oset) != -1) {
			sigsuspend(&oset);
		}
	}
#elif defined(HAS_PAUSE)
	pause();
#else	/* !HAS_SIGPROCMASK && !HAS_PAUSE */
	{
		for (;;) {
			compat_sleep_ms(MAX_INT_VAL(unsigned));
		}
	}
#endif	/* HAS_SIGPROCMASK || HAS_PAUSE */

	thread_cancel_test();
}

/* vi: set ts=4 sw=4 cindent: */
