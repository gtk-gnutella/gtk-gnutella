/*
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Dynamic linker library wrapper functions.
 *
 * This interface is a wrapping API on top of the dl library which allows
 * to conveniently perform operations without necessarily knowing whether
 * the dl library is there and supports the operation.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef I_DLFCN
#define _GNU_SOURCE			/* Needed on linux to get dladdr() and Dl_info */
#include <dlfcn.h>
#endif

#include "dl_util.h"
#include "signal.h"
#include "thread.h"			/* For THREAD_MAX */

#include "override.h"		/* Must be the last header included */

static bool dl_util_inited;

enum dl_addr_op {
	DL_ADDR_GET_BASE,
	DL_ADDR_GET_NAME,
	DL_ADDR_GET_PATH,
	DL_ADDR_GET_START
};

/**
 * Initialize dynamic linker operations.
 */
static void
dl_util_init(void)
{
	if (!dl_util_inited) {
		/* Nothing yet */
		dl_util_inited = TRUE;
	}
}

/**
 * Terminate dynamic linker operations, for now.
 */
void
dl_util_done(void)
{
	if (dl_util_inited) {
		/* Nothing yet */
		dl_util_inited = FALSE;
	}
}

static sigjmp_buf dl_util_env[THREAD_MAX];

/**
 * Invoked when a fatal signal is received during dladdr().
 */
static void G_COLD
dl_util_got_signal(int signo)
{
	int stid = thread_small_id();

	(void) signo;

	siglongjmp(dl_util_env[stid], signo);
}

/**
 * Perform specify operation on the address.
 *
 * @param addr		the address we're querying
 * @param op		the operation to perform
 *
 * @return NULL on failure, an address whose interpretation is op-specific
 * otherwise.
 */
static const void *
dl_util_query(const void *addr, enum dl_addr_op op)
{
	if G_UNLIKELY(!dl_util_inited)
		dl_util_init();

#ifdef HAS_DLADDR
	{
		static Dl_info info;
		static const void *last_addr;
		int stid = thread_small_id();

		/*
		 * Cache results for a given address.  This will help our stack
		 * pretty-printing code which is going to gather the various
		 * items at different times instead of doing one dladdr() call.
		 * For a given stack item, we may therefore face various calls
		 * for the same address.
		 *
		 * The rationale is that we may want to use different routines on
		 * another platform without dladdr() some days and therefore we wish
		 * to hide the existence of dladdr() and rather provide higher-level
		 * services like dl_util_get_base().
		 */

		if (addr != last_addr) {
			signal_handler_t old_sigsegv;
			int ret;

			ZERO(&info);

			/*
			 * Protect against segmentation faults in dladdr().
			 *
			 * We use signal_catch() instead of signal_set() because we
			 * don't need extra information about the fault context.
			 */

			old_sigsegv = signal_catch(SIGSEGV, dl_util_got_signal);

			if (Sigsetjmp(dl_util_env[stid], TRUE)) {
				ret = 0;		/* Signal failure */
				goto skip;		/* Skip call that triggered SIGSEGV */
			}

			ret = dladdr(deconstify_pointer(addr), &info);
			/* FALL THROUGH */

		skip:
			signal_set(SIGSEGV, old_sigsegv);
			if (0 == ret) {
				last_addr = NULL;
				return NULL;
			}
			last_addr = addr;
		}

		switch (op) {
		case DL_ADDR_GET_BASE:
			return info.dli_fbase;
		case DL_ADDR_GET_NAME:
			return info.dli_sname;
		case DL_ADDR_GET_PATH:
			return info.dli_fname;
		case DL_ADDR_GET_START:
			return info.dli_saddr;
		}
	}

	g_assert_not_reached();
#else	/* !HAS_DLADDR */
	(void) addr;
	(void) op;

	return NULL;
#endif	/* HAS_DLADDR */
}

/**
 * Fetch the base address of the shared object containing the address.
 *
 * @param addr		the address we're querying
 *
 * @return the base address at which the shared object is loaded, NULL if
 * not found.
 */
const void *
dl_util_get_base(const void *addr)
{
	return dl_util_query(addr, DL_ADDR_GET_BASE);
}

/**
 * Fetch the pathname of the shared object that contains the address.
 *
 * @param addr		the address we're querying
 *
 * @return the path name, NULL if not found.
 */
const char *
dl_util_get_path(const void *addr)
{
	const char *path;

	path = dl_util_query(addr, DL_ADDR_GET_PATH);

	if (path != NULL && '\0' == path[0])
		return NULL;

	return path;
}

/**
 * Fetch the symbolic name of the address.
 *
 * @param addr		the address we're querying
 *
 * @return the symbol name, NULL if not found or unknown.
 */
const char *
dl_util_get_name(const void *addr)
{
	const char *name;

	name = dl_util_query(addr, DL_ADDR_GET_NAME);

	if (name != NULL && '\0' == name[0])
		return NULL;

	return name;
}

/**
 * Fetch the routine starting address.
 *
 * @param addr		the address we're querying
 *
 * @return the starting address, NULL if not found or unknown.
 */
const void *
dl_util_get_start(const void *addr)
{
	return dl_util_query(addr, DL_ADDR_GET_START);
}

/* vi: set ts=4 sw=4 cindent: */
