/*
 * Copyright (c) 2016 Raphael Manfredi
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
 * Portable system thread ID computation.
 *
 * @author Raphael Manfredi
 * @date 2016
 */

#include "common.h"

#ifdef HAS_SYSCALL
#include <sys/syscall.h>
#endif

#include "compat_gettid.h"

#define THREAD_SOURCE		/* For thread_self() */
#include "thread.h"

#include "override.h"		/* Must be the last header included */

/**
 * Get the system thread ID.
 *
 * This value is meant to be used by low-level system-specific calls.
 * It needs to be cast back to the proper type if the native type is not
 * an unsigned long.
 *
 * @note
 * The meaning of this ID is system-specific:
 * On UNIX, this can be the kernel thread ID, or the pthread_t value cast.
 * On Windows, this is a thread handle.
 */
systid_t
compat_gettid(void)
{
	systid_t id;

#if defined(HAS_SYSCALL) && defined(SYS_gettid)
	id = syscall(SYS_gettid);
	if ((systid_t) -1 != id)
		return id;
#endif	/* HAS_SYSCALL && SYS_gettid */

#ifdef MINGW32
	id = mingw_gettid();
#else
	id = (systid_t) thread_self();
#endif	/* MINGW32 */

	return id;
}

/* vi: set ts=4 sw=4 cindent: */
