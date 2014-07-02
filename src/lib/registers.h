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
 * Machine register access.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _registers_h_
#define _registers_h_

#include "config.h"

#ifdef I_UCONTEXT
#include <ucontext.h>
#endif
#ifdef I_SYS_UCONTEXT
#include <sys/ucontext.h>
#endif

#if defined(HAS_UCONTEXT_MCONTEXT_GREGS) || defined(HAS_UCONTEXT_MCONTEXT)
#define USE_UC_MCONTEXT
#endif

/*
 * Accessing the machine registers is inherently non-portable.
 *
 * The REGISTER_COUNT macro defines the amount of registers we see.
 * The REGISTER_BASE macro lets us access the registers as an array of ulongs.
 * The REGISTER_VALUE macro lets us access a register by index.
 *
 * When the gregs[] array is present in the uc_mcontext field, the access
 * is straightforward.
 *
 * When there is no gregs[] array, assume the uc_mcontext field is a structure
 * containing registers whose size will be that of the "unsigned long" type.
 * This is a reasonable assumption which should prove correct on many systems.
 *
 * The uc_mcontext field could also be a pointer as on OSX, which we'll detect
 * when REGISTER_COUNT ends up being 1, in which case we're hosed.
 */

#if defined(HAS_UCONTEXT_MCONTEXT_GREGS)

#define REGISTER_COUNT(u)	G_N_ELEMENTS((u)->uc_mcontext.gregs)
#define REGISTER_BASE(u)	((ulong *) (u)->uc_mcontext.gregs)
#define REGISTER_VALUE(u,x)	((ulong) (u)->uc_mcontext.gregs[x])

#elif defined(HAS_UCONTEXT_MCONTEXT)

#define REGISTER_COUNT(u)	(sizeof((u)->uc_mcontext) / sizeof(ulong))
#define REGISTER_BASE(u)	((ulong *) &(u)->uc_mcontext)
#define REGISTER_VALUE(u,x)	((ulong *) &(u)->uc_mcontext)[x]

#else	/* !HAS_UCONTEXT_MCONTEXT_GREGS && !HAS_UCONTEXT_MCONTEXT */

#include "log.h"			/* For s_error_expr() */
#define REGISTER_COUNT(u)	0
#define REGISTER_BASE(u)	NULL
#define REGISTER_VALUE(u,x)	\
	(s_error_expr("%s: cannot access machine registers", G_STRFUNC), (x))

#endif	/* HAS_UCONTEXT_MCONTEXT_GREGS || HAS_UCONTEXT_MCONTEXT */

#endif /* _registers_h_ */

/* vi: set ts=4 sw=4 cindent:  */
