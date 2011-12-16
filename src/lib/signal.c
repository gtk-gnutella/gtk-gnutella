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
 * Signal dispatching support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"		/* For RCSID */

#include "signal.h"
#include "ckalloc.h"
#include "crash.h"
#include "glib-missing.h"       /* For g_strlcpy() */
#include "log.h"
#include "misc.h"
#include "str.h"
#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

#ifndef SIG_ERR
#define SIG_ERR ((signal_handler_t) -1)
#endif

#define SIGNAL_CHUNK_SIZE		4000	/**< Safety allocation pool */
#define SIGNAL_CHUNK_RESERVE	512		/**< Critical amount reserved */

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
 * There are SIG_COUNT entries in that array (also computed by Configure).
 */
static char *signal_names[] = { SIG_NAME };	/* Computed by Configure */

/**
 * Array recording signal handlers for signals.
 */
static signal_handler_t signal_handler[SIGNAL_COUNT];

/**
 * A chunk of memory that can be used to safely allocate data within a
 * signal handler.  Any allocated data is freed when the last signal handler
 * exits, so this is not a way to allocate data from a signal handler that
 * will be still accessible upon return.
 */
static ckhunk_t *sig_chunk;

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
	return in_signal_handler != 0 && !mingw_in_exception();
}

/**
 * Returns the pre-allocated safe chunk for allocating memory within
 * a signal handler.
 */
ckhunk_t *
signal_chunk(void)
{
	return sig_chunk;
}

/**
 * Wrapper for signal delivery.
 */
static void
signal_trampoline(int signo)
{
	signal_handler_t handler;

	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	handler = signal_handler[signo];

	g_assert(handler != SIG_DFL && handler != SIG_IGN);

	/*
	 * Wrapping the signal handler allows us to know whether we are in
	 * a signal handler through signal_in_handler().
	 */

	in_signal_handler++;
	(*handler)(signo);
	in_signal_handler--;

	/*
	 * When leaving the last signal handler, cleanup the emergency chunk.
	 *
	 * Before requesting a critical section, look whether something was
	 * allocated already in the emergency chunk.
	 */

	if (ck_used(sig_chunk)) {
		sigset_t set;

		if (signal_enter_critical(&set)) {
			if (0 == in_signal_handler)
				ck_free_all(sig_chunk);
			signal_leave_critical(&set);
		}
	}
}

#ifdef SA_SIGINFO
/**
 * Extended trapping for harmful signals for which we can gather extra
 * information from the siginfo_t structure.
 */
static void
signal_trampoline_extended(int signo, siginfo_t *si, void *u)
{
	(void) u;

	/*
	 * Log faulting address and propagate that information in the
	 * crash log as an error message.
	 */

	in_signal_handler++;
	{
		char data[80];

		str_bprintf(data, sizeof data, "got %s for VA=%p",
			signal_name(signo), si->si_addr);
		s_critical("%s", data);
		crash_set_error(data);
	}
	in_signal_handler--;

	signal_trampoline(signo);
}
#endif	/* SA_SIGINFO */

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
	signal_handler_t ret, old_handler, trampoline;

	g_assert(handler != SIG_ERR);
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	STATIC_ASSERT(SIGNAL_COUNT == G_N_ELEMENTS(signal_handler));

	if (G_UNLIKELY(NULL == sig_chunk))		/* No signal_init() yet */
		signal_init();

	old_handler = signal_handler[signo];

	g_assert(old_handler != SIG_ERR);

	trampoline = (SIG_DFL == handler || SIG_IGN == handler) ?
		handler : signal_trampoline;

#ifdef HAS_SIGACTION
	{
		static const struct sigaction zero_sa;
		struct sigaction sa, osa;
		
		sa = zero_sa;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = signo != SIGALRM ? SA_RESTART : 0;

		switch (signo) {
#ifdef SIGBUS
		case SIGBUS:
#endif
#ifdef SIGTRAP
		case SIGTRAP:
#endif
		case SIGSEGV:
		case SIGFPE:
		case SIGILL:
#ifdef SA_SIGINFO
			if (signal_trampoline == trampoline) {
				sa.sa_flags |= SA_SIGINFO;
				sa.sa_sigaction = signal_trampoline_extended;
			} else {
				sa.sa_handler = trampoline;
			}
#else
			sa.sa_handler = trampoline;
#endif
#ifdef SA_NODEFER
			sa.sa_flags |= SA_NODEFER;
#endif
#ifdef SA_RESETHAND
			sa.sa_flags |= SA_RESETHAND;
#endif
			break;
		default:
			sa.sa_handler = trampoline;
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
 * Unblock signal.
 */
void
signal_unblock(int signo)
{
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

#ifdef HAS_SIGPROCMASK
	{
		sigset_t set;

		sigemptyset(&set);
		sigaddset(&set, signo);
		sigprocmask(SIG_UNBLOCK, &set, NULL);
	}
#endif	/* HAS_SIGPROCMASK */
}

static volatile sig_atomic_t in_critical_section;

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

	if (is_running_on_mingw())
		goto ok;

#ifdef HAS_SIGPROCMASK
	{
		sigset_t set;

		/*
		 * If we are nesting critical sections, we have already blocked
		 * all the signals, so there's no need to do anything.  Just count
		 * the sections so that we restore the signal mask only when we
		 * leave the outermost one.
		 */

		if (in_critical_section)
			goto ok;

		sigfillset(&set);		/* Block everything */

		if (-1 == sigprocmask(SIG_SETMASK, &set, oset))
			return FALSE;
	}
#else
	(void) oset;
	return FALSE;
#endif

ok:
	in_critical_section++;

	return TRUE;
}

/**
 * Unblock signals that were blocked when we entered the critical section.
 */
void
signal_leave_critical(const sigset_t *oset)
{
	g_assert(in_critical_section > 0);

	in_critical_section--;

	if (is_running_on_mingw())
		return;

#ifdef HAS_SIGPROCMASK
	if (!in_critical_section) {
		if (-1 == sigprocmask(SIG_SETMASK, oset, NULL))
			s_error("cannot leave critical section: %m");
	}
#else
	(void) oset;
#endif
}

/**
 * Initialize the signal layer.
 */
void
signal_init(void)
{
	if (NULL == sig_chunk) {		/* Allow multiple calls */
		size_t i;

		for (i = 0; i < G_N_ELEMENTS(signal_handler); i++) {
			signal_handler[i] = SIG_DFL;	/* Can't assume it's NULL */
		}

		/* 
		 * Chunk allocated as non-leaking because the signal chunk must
		 * remain active up to the very end, way past the point where we're
		 * supposed to have freed everything and leak detection kicks in.
		 */

		sig_chunk =
			ck_init_not_leaking(SIGNAL_CHUNK_SIZE, SIGNAL_CHUNK_RESERVE);
	}

	g_assert(sig_chunk != NULL);	/* We're initialized now */
}

/**
 * Called at shutdown.
 */
void
signal_close(void)
{
	/* Nothing to do */
}

/* vi: set ts=4 sw=4 cindent:  */
