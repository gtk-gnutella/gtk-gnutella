/*
 * $Id$
 *
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
 * Signal dispatching support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"		/* For RCSID */

RCSID("$Id$")

#include "signal.h"
#include "misc.h"
#include "crash.h"
#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

#ifndef SIG_ERR
#define SIG_ERR ((signal_handler_t) -1)
#endif

/**
 * Table mapping a signal number with a symbolic name.
 *
 * Contrary to the signal_names[] below, this is using compiled constants
 * and should therefore be more accurate.
 */
static const struct {
	const char name[16];
	int signo;
} signals[] = {
#define D(x) { #x, x }
#ifdef SIGBUS
	D(SIGBUS),
#endif
#ifdef SIGTRAP
	D(SIGTRAP),
#endif
	D(SIGABRT),
	D(SIGFPE),
	D(SIGILL),
	D(SIGSEGV)
#undef D
};

/**
 * Array mapping a signal number to a signal name (leading "SIG" ommitted).
 * This is used in case the signal is not found in the signals[] table.
 */
static char *signal_names[] = { SIG_NAME };	/* Computed by Configure */

/**
 * Array recording signal handlers for signals.
 */
static signal_handler_t signal_handler[SIG_COUNT];

static const char SIGNAL_NUM[] = "signal #";
static const char SIG_PREFIX[] = "SIG";

/**
 * Converts signal number to a name.
 *
 * This routine can safely be used in signal handlers and performs no
 * memory allocation at all.
 *
 * @return signal name, either in symbolic form (e.g. "SIGSEGV") or as
 * a numeric value (e.g. "signal #11") if no other symbolic form is known.
 */
const char *
signal_name(int signo)
{
	static char sig_buf[32];
	unsigned i;
	char *start;
	size_t offset;

	for (i = 0; i < G_N_ELEMENTS(signals); i++) {
		if (signals[i].signo == signo)
			return signals[i].name;
	}

	/*
	 * If there is a known symbolic form (not starting with "NUMxx"), use it.
	 * There is no "SIG" prefix in names from this array.
	 */

	if (signo < SIG_COUNT && !is_strprefix(signal_names[signo], "NUM")) {
		g_strlcpy(sig_buf, SIG_PREFIX, sizeof sig_buf);

		start = &sig_buf[CONST_STRLEN(SIG_PREFIX)];
		offset = start - sig_buf;

		g_assert(size_is_positive(offset));
		g_assert(CONST_STRLEN(SIG_PREFIX) == offset);

		g_strlcpy(start, signal_names[signo], sizeof sig_buf - offset);
		return sig_buf;
	}

	/*
	 * print_number() works backwards within the supplied buffer, so we
	 * need to construct the final string accordingly.
	 */

	start = deconstify_char(print_number(sig_buf, sizeof sig_buf, signo));
	offset = start - sig_buf;

	g_assert(size_is_positive(offset));
	g_assert(offset > CONST_STRLEN(SIGNAL_NUM));

	/*
	 * Prepend constant SIGNAL_NUM string right before the number, without
	 * the trailing NUL (hence the use of memcpy).
	 */

	memcpy(start - CONST_STRLEN(SIGNAL_NUM),
		SIGNAL_NUM, CONST_STRLEN(SIGNAL_NUM));

	return start - CONST_STRLEN(SIGNAL_NUM);
}

static volatile sig_atomic_t in_signal_handler;

/**
 * Are we in a signal handler?
 */
gboolean
signal_in_handler(void)
{
	return in_signal_handler != 0;
}

/**
 * Wrapper for signal delivery.
 */
static void
signal_trampoline(int signo)
{
	signal_handler_t handler;

	g_assert(signo > 0 && signo < SIG_COUNT);

	handler = signal_handler[signo];

	g_assert(handler != SIG_DFL && handler != SIG_IGN);

	/*
	 * Wrapping the signal handler allows us to know whether we are in
	 * a signal handler through signal_in_handler().
	 */

	in_signal_handler++;
	(*handler)(signo);
	in_signal_handler--;
}

/**
 * Installs a signal handler.
 *
 * The signal handler is not reset to the default handler after delivery unless
 * the signal is SIGSEGV or SIGBUS, in which case not only is the default 
 * handler reset but further occurrence of the signal will retrigger even
 * within signal delivery.
 *
 * If the signal is SIGALRM, the handler is installed so that interrupted
 * system calls fail with EINTR. Handlers for other all signals are installed
 * so that interrupted system calls are restarted instead.
 *
 * @param signo the signal number.
 * @param handler the signal handler to install.
 *
 * @return the previous signal handler or SIG_ERR on failure.
 */
signal_handler_t
signal_set(int signo, signal_handler_t handler)
{
	static gboolean inited;
	signal_handler_t ret, old_handler, trampoline;

	g_assert(handler != SIG_ERR);
	g_assert(signo > 0 && signo < SIG_COUNT);

	STATIC_ASSERT(SIG_COUNT == G_N_ELEMENTS(signal_handler));

	if (!inited) {
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(signal_handler); i++) {
			signal_handler[i] = SIG_DFL;	/* Can't assume it's NULL */
		}

		inited = TRUE;
	}

	old_handler = signal_handler[signo];

	trampoline = (SIG_DFL == handler || SIG_IGN == handler) ?
		handler : signal_trampoline;

#ifdef HAS_SIGACTION
	{
		static const struct sigaction zero_sa;
		struct sigaction sa, osa;
		
		sa = zero_sa;
		sa.sa_handler = trampoline;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = signo != SIGALRM ? SA_RESTART : 0;

		switch (signo) {
#ifdef SIGBUS
		case SIGBUS:
#endif
		case SIGSEGV:
#ifdef SA_NODEFER
			sa.sa_flags |= SA_NODEFER;
#endif
#ifdef SA_RESETHAND
			sa.sa_flags |= SA_RESETHAND;
#endif
			break;
		}

		ret = sigaction(signo, &sa, &osa) ? SIG_ERR : osa.sa_handler;
	}
#else
	/* FIXME WIN32, probably: We can't just ignore all signal logic */
	 ret = signal(signo, trampoline);
#endif	/* HAS_SIGACTION */

	if (SIG_ERR == ret)
		return ret;

	signal_handler[signo] = handler;

	return (SIG_DFL == ret || SIG_IGN == ret) ? ret : old_handler;
}

/**
 * Block all signals, for entering a critical section.
 *
 * @param oset		the old signal set, to be passed to signal_leave_critical()
 *
 * @return TRUE if OK, FALSE on error with errno set.
 */
gboolean
signal_enter_critical(sigset_t *oset)
{
	g_assert(oset != NULL);

	/*
	 * There are no signals on Windows, so there is no risk we can be
	 * interrupted by a signal on that platform.
	 */

	if (is_running_on_mingw()) {
		return TRUE;
	}

#ifdef HAS_SIGPROCMASK
	{
		sigset_t set;
		sigfillset(&set);		/* Block everything */
		return -1 != sigprocmask(SIG_SETMASK, &set, oset);
	}
#else
	(void) oset;
	return FALSE;
#endif
}

/**
 * Unblock signals that were blocked when we entered the critical section.
 *
 * @return TRUE if OK, FALSE on error with errno set.
 */
gboolean
signal_leave_critical(const sigset_t *oset)
{
	if (is_running_on_mingw())
		return TRUE;

#ifdef HAS_SIGPROCMASK
	return -1 != sigprocmask(SIG_SETMASK, oset, NULL);
#else
	(void) oset;
	return TRUE;	/* Does not matter, we were not in a critical section */
#endif
}

/* vi: set ts=4 sw=4 cindent:  */
