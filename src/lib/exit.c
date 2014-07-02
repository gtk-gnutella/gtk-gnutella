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
 * Exit wrapper.
 *
 * Our own exit() wrapper makes sure anything allocated by the libc startup
 * will not be freed, as it could not have proper block sizes when xmalloc()
 * supersedes malloc(): at startup time, we had no chance to initialize the
 * necessary constants to compute page size alignments.
 *
 * They suspend the other threads to avoid problems and parasite logging as
 * we reclaim important resources during signal_perform_cleanup().
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "exit.h"
#include "crash.h"
#include "signal.h"
#include "thread.h"
#include "xmalloc.h"

#include "override.h"			/* Must be the last header included */

#undef exit
#undef _exit

/**
 * Exit common cleanup.
 */
G_GNUC_COLD void
exit_cleanup(void)
{
	thread_exit_mode();
	xmalloc_stop_freeing();
	signal_perform_cleanup();
	crash_close();
}

/**
 * Exit with given status for the parent process.
 */
G_GNUC_COLD void
do_exit(int status)
{
	exit_cleanup();
	exit(status);
}

/**
 * Exit with given status for the parent process.
 *
 * Handlers registered with atexit() are not invoked.
 */
G_GNUC_COLD void
do__exit(int status)
{
	exit_cleanup();
	_exit(status);
}

/* vi: set ts=4 sw=4 cindent: */
