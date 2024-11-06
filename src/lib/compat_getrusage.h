/*
 * Copyright (c) 2024 Raphael Manfredi
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
 * Get process resource usage.
 *
 * @author Raphael Manfredi
 * @date 2024
 */

#ifndef _compat_getrusage_h_
#define _compat_getrusage_h_

#include "common.h"

#ifndef HAS_GETRUSAGE
#define RUSAGE_SELF		0
#define RUSAGE_CHILDREN (-1)

#define compat_rusage		rusage
#define getrusage(w,u)		compat_getrusage((w), (u))
#endif	/* !HAS_GETRUSAGE */

struct compat_rusage {
	struct timeval ru_utime; /* user CPU time used */
	struct timeval ru_stime; /* system CPU time used */
	long   ru_maxrss;        /* maximum resident set size */
	long   ru_ixrss;         /* integral shared memory size */
	long   ru_idrss;         /* integral unshared data size */
	long   ru_isrss;         /* integral unshared stack size */
	long   ru_minflt;        /* page reclaims (soft page faults) */
	long   ru_majflt;        /* page faults (hard page faults) */
	long   ru_nswap;         /* swaps */
	long   ru_inblock;       /* block input operations */
	long   ru_oublock;       /* block output operations */
	long   ru_msgsnd;        /* IPC messages sent */
	long   ru_msgrcv;        /* IPC messages received */
	long   ru_nsignals;      /* signals received */
	long   ru_nvcsw;         /* voluntary context switches */
	long   ru_nivcsw;        /* involuntary context switches */
};

int compat_getrusage(int who, struct compat_rusage *usage);

#endif /* _compat_getrusage_h_ */

/* vi: set ts=4 sw=4 cindent: */
