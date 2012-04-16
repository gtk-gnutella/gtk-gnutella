/*
 * Copyright (c) 2011-2012 Raphael Manfredi
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
 * Signal dispatching and logging support.
 *
 * @author Raphael Manfredi
 * @date 2011-2012
 */

#include "common.h"		/* For RCSID */

#ifdef I_UCONTEXT
#include <ucontext.h>
#endif
#ifdef I_SYS_UCONTEXT
#include <sys/ucontext.h>
#endif

#include "signal.h"
#include "ckalloc.h"
#include "crash.h"
#include "dl_util.h"
#include "glib-missing.h"       /* For g_strlcpy() */
#include "log.h"
#include "misc.h"
#include "once.h"
#include "str.h"
#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

#ifndef SIG_ERR
#define SIG_ERR ((signal_handler_t) -1)
#endif

#define SIGNAL_CHUNK_SIZE		4000	/**< Safety allocation pool */
#define SIGNAL_CHUNK_RESERVE	512		/**< Critical amount reserved */

#if defined(HAS_UCONTEXT_MCONTEXT_GREGS) || defined(HAS_UCONTEXT_MCONTEXT)
#define USE_UC_MCONTEXT
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

/**
 * Various "undefined" values for the PC register number.
 *
 * All strictly negative values indicate that the PC cannot be read from the
 * machine context, a zero or positive value indicates an offset in the
 * array of machine registers, wherever that is within the machine context.
 */
#define SIG_PC_UNKNOWN		(-1)	/* Unknown register offset */
#define SIG_PC_MULTIPLE		(-2)	/* Multiple registers could match */
#define SIG_PC_IMPOSSIBLE	(-3)	/* Impossible condition */
#define SIG_PC_UNAVAILABLE	(-4)	/* Unavailable, we can't access registers */
#define SIG_PC_HIDDEN		(-5)	/* PC hidden in opaque machine context */

/**
 * The index of the general register in the machine context that holds
 * the Program Counter, the PC.
 *
 * If the value is negative, the PC register number is unknown.
 */
static volatile sig_atomic_t sig_pc_regnum = SIG_PC_UNKNOWN;

static const char SIGNAL_NUM[] = "signal #";
static const char SIG_PREFIX[] = "SIG";

static volatile sig_atomic_t in_signal_handler;
static bool signal_inited;

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

#if defined(USE_UC_MCONTEXT) && defined(SA_SIGINFO)
/*
 * This section computes the register number in the ucontext_t general
 * registers that contains the PC.
 *
 * In order to do that, we install a POSIX signal handler with SA_SIGINFO,
 * then trigger a segmentation violation from a known routine and probe the
 * saved registers in the supplied machine context to spot one whose value
 * is close to the address of the routine.
 */

static Sigjmp_buf sig_pc_env;

/**
 * Compute the PC register index into ``sig_pc_regnum''.
 */
static NO_INLINE void
sig_compute_pc_index(void)
{
	int *p = (int *) 0x10;		/* Align, avoids possible SIGBUS below */

	/*
	 * The instruction causing the SIGSEGV should be near the top of the
	 * routine to make sure we can identify which register was holding
	 * the faulting PC.
	 */

	*p = 1;						/* We expect this to raise a SIGSEGV */
	g_assert_not_reached();
}

/*
 * Accessing the machine registers is inherently non-portable.
 *
 * The REGISTER_COUNT macro defines the amount of registers we see.
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
#define REGISTER_COUNT		G_N_ELEMENTS(uc->uc_mcontext.gregs)
#define REGISTER_VALUE(x)	((ulong) uc->uc_mcontext.gregs[x])
#elif defined(HAS_UCONTEXT_MCONTEXT)
#define REGISTER_COUNT		(sizeof(uc->uc_mcontext) / sizeof(ulong))
#define REGISTER_VALUE(x)	((ulong *) &uc->uc_mcontext)[x]
#else
#error "impossible situation here"
#endif

#define SIG_PC_OFFSET_MAX	100		/* Bytes after start of routine */

/**
 * Signal handler for the segmentation violation we're creating.
 */
static void
sig_get_pc_handler(int signo, siginfo_t *si, void *u)
{
	const ucontext_t *uc = u;
	unsigned i;
	bool found = FALSE;
	ulong caller;

	g_assert(SIGSEGV == signo);
	g_assert(si != NULL);

	if (1 == REGISTER_COUNT) {
		/*
		 * The uc_mcontext field is a pointer, sorry.
		 *
		 * This is probably OSX, but the exact field name varies depending
		 * on the OSX version, so the checks are more complex for this
		 * platform.  For now, OSX users will miss the PC in the crash logs.
		 */
		sig_pc_regnum = SIG_PC_HIDDEN;
		goto done;
	}

	sig_pc_regnum = SIG_PC_UNKNOWN;
	caller = pointer_to_ulong(cast_func_to_pointer(sig_compute_pc_index));

	for (i = 0; i < REGISTER_COUNT; i++) {
		size_t off = REGISTER_VALUE(i) - caller;
		if (off < SIG_PC_OFFSET_MAX) {
			if (found) {
				sig_pc_regnum = SIG_PC_MULTIPLE;
				break;
			}
			found = TRUE;
			sig_pc_regnum = i;
		}
	}

done:
	Siglongjmp(sig_pc_env, 1);
}

/**
 * Computes the PC register number in the user thread context.
 *
 * @return the index in the general register array, -1 if unknown.
 */
static int
sig_get_pc_index(void)
{
	struct sigaction sa, osa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sig_get_pc_handler;

	if (-1 == sigaction(SIGSEGV, &sa, &osa)) {
		s_warning("%s: sigaction() setup failed: %m", G_STRFUNC);
		return -1;
	}

	if (Sigsetjmp(sig_pc_env, TRUE)) {
		if (-1 == sigaction(SIGSEGV, &osa, &sa))
			s_critical("%s: sigaction() restore failed: %m", G_STRFUNC);
		return sig_pc_regnum;
	}

	sig_compute_pc_index();

	g_assert_not_reached();
	return SIG_PC_IMPOSSIBLE;
}

/**
 * Extract the value of the PC register from the user thread context.
 *
 * @return the PC value, NULL if unknown.
 */
static void *
sig_get_pc(const void *u)
{
	const ucontext_t *uc = u;

	if (sig_pc_regnum < 0)
		return NULL;

	return ulong_to_pointer(REGISTER_VALUE(sig_pc_regnum));
}
#else	/* !USE_UC_MCONTEXT || !SA_SIGINFO */
static int
sig_get_pc_index(void)
{
	return SIG_PC_UNAVAILABLE;
}

static inline void *
sig_get_pc(const void *u)
{
	(void) u;
	return NULL;
}
#endif	/* USE_UC_MCONTEXT && SA_SIGINFO */

static volatile sig_atomic_t in_signal_handler;
static volatile sig_atomic_t in_signal_abort;

/**
 * Are we in an asynchronous signal handler?
 */
bool
signal_in_handler(void)
{
	if (in_signal_abort && 1 == in_signal_handler)
		return FALSE;		/* Handle signal_abort() specially */

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

#if defined(HAS_SIGACTION) && defined(SA_SIGINFO)
/**
 * Decodes the si_code field depending on the signal received.
 *
 * @param signo		the signal received
 * @param code		the si_code field of the siginfo_t structure
 *
 * @return textual description, NULL if unknown.
 */
static const char *
signal_decode(int signo, int code)
{
	switch (signo) {
	case SIGFPE:
		switch (code) {
#ifdef FPE_INTDIV
		case FPE_INTDIV:	return "integer divide by zero";
#endif
#ifdef FPE_INTOVF
		case FPE_INTOVF:	return "integer overflow";
#endif
#ifdef FPE_FLTDIV
		case FPE_FLTDIV:	return "floating-point divide by zero";
#endif
#ifdef FPE_FLTOVF
		case FPE_FLTOVF:	return "floating-point overflow";
#endif
#ifdef FPE_FLTUND
		case FPE_FLTUND:	return "floating-point underflow";
#endif
#ifdef FPE_FLTRES
		case FPE_FLTRES:	return "floating-point inexact result";
#endif
#ifdef FPE_FLTINV
		case FPE_FLTINV:	return "floating-point invalid operation";
#endif
#ifdef FPE_FLTSUB
		case FPE_FLTSUB:	return "subscript out of range";
#endif
		}
		break;
	case SIGILL:
		switch (code) {
#ifdef ILL_ILLOPC
		case ILL_ILLOPC:	return "illegal opcode";
#endif
#ifdef ILL_ILLOPN
		case ILL_ILLOPN:	return "illegal operand";
#endif
#ifdef ILL_ILLADR
		case ILL_ILLADR:	return "illegal addressing mode";
#endif
#ifdef ILL_ILLTRP
		case ILL_ILLTRP:	return "illegal trap";
#endif
#ifdef ILL_PRVOPC
		case ILL_PRVOPC:	return "privileged opcode";
#endif
#ifdef ILL_PRVREG
		case ILL_PRVREG:	return "privileged register";
#endif
#ifdef ILL_COPROC
		case ILL_COPROC:	return "coprocessor error";
#endif
#ifdef ILL_BADSTK
		case ILL_BADSTK:	return "internal stack error";
#endif
		}
		break;
	case SIGSEGV:
		switch (code) {
#ifdef SEGV_MAPERR
		case SEGV_MAPERR:	return "address not mapped to object";
#endif
#ifdef SEGV_ACCERR
		case SEGV_ACCERR:	return "invalid permissions for mapped object";
#endif
		}
		break;
#ifdef SIGBUS
	case SIGBUS:
		switch (code) {
#ifdef BUS_ADRALN
		case BUS_ADRALN:	return "invalid address alignment";
#endif
#ifdef BUS_ADRERR
		case BUS_ADRERR:	return "nonexistent physical address";
#endif
#ifdef BUS_OBJERR
		case BUS_OBJERR:	return "object-specific hardware error";
#endif
#ifdef BUS_MCEERR_AR
		case BUS_MCEERR_AR:	return "h/w memory error consumed on machine check";
#endif
#ifdef BUS_MCEERR_AO
		case BUS_MCEERR_AO:	return "h/w memory error not consumed";
#endif
		}
		break;
#endif	/* SIGBUS */
#ifdef SIGTRAP
	case SIGTRAP:
		switch (code) {
#ifdef TRAP_BRKPT
		case TRAP_BRKPT:	return "process breakpoint";
#endif
#ifdef TRAP_TRACE
		case TRAP_TRACE:	return "process trace trap";
#endif
#ifdef TRAP_BRANCH
		case TRAP_BRANCH:	return "process taken branch trap";
#endif
#ifdef TRAP_HWBKPT
		case TRAP_HWBKPT:	return "hardware breakpoint/watchpoint";
#endif
		}
		break;
#endif	/* SIGTRAP */
	default:
		break;
	}

	return NULL;
}

/**
 * Format exception into supplied buffer.
 *
 * @param dest		destination buffer
 * @param size		size of buffer
 * @param signo		signal number
 * @param si		signal information
 * @param u			user context
 * @param recursive	whether signal was recursively received
 */
static void
sig_exception_format(char *dest, size_t size,
	int signo, siginfo_t *si, void *u, bool recursive)
{
	const char *reason;
	const void *pc;
	str_t s;

	reason = signal_decode(signo, si->si_code);
	str_new_buffer(&s, dest, 0, size);

	str_printf(&s, "got %s%s",
		recursive ? "recursive " : "", signal_name(signo));

	/*
	 * For SIGBUS and SIGSEGV, the si_addr field contains the faulting address.
	 * For SIGILL, SIGTRAP and SIGFPE signals, si_addr may be the address of the
	 * faulting instruction, i.e. the current PC.
	 */

	switch (signo) {
#ifdef SIGBUS
	case SIGBUS:
#endif
	case SIGSEGV:
		str_catf(&s, " for VA=%p", si->si_addr);
		pc = sig_get_pc(u);
		break;
#ifdef SIGTRAP
	case SIGTRAP:
#endif
	case SIGFPE:
	case SIGILL:
		pc = sig_get_pc(u);
		if (NULL == pc)
			pc = si->si_addr;		/* Maybe, so prefer sig_get_pc() */
		break;
	default:
		pc = NULL;
		break;
	}

	if (reason != NULL)
		str_catf(&s, " (%s)", reason);

	if (pc != NULL) {
		str_catf(&s, " at PC=%p", pc);

		if (!recursive) {
			const char *name = stacktrace_routine_name(pc, TRUE);

			if (!is_strprefix(name, "0x"))
				str_catf(&s, " (%s)", name);

			if (!stacktrace_pc_within_our_text(pc)) {
				const char *file = dl_util_get_path(pc);
				if (file != NULL)
					str_catf(&s, " from %s", file);
			}
		}
	}
}

/**
 * Extended trapping for harmful signals for which we can gather extra
 * information from the siginfo_t structure.
 */
static void
signal_trampoline_extended(int signo, siginfo_t *si, void *u)
{
	static volatile sig_atomic_t extended;
	sigset_t set;

	in_signal_handler++;
	extended++;

	/*
	 * Check whether signal is still pending.
	 *
	 * We assume that because sigaction() is available, sigpending() is
	 * also present.  We know we have sigaction() because this routine
	 * is only called  from a handler installed with SA_SIGINFO.
	 *
	 * If the same signal that is being delivered is still pending, then
	 * unblocking the signal will immediately recurse here.  Hence it is
	 * useful to detect that and avoid calling the signal handler.
	 */

	if (-1 == sigpending(&set)) {
		s_warning("%s: sigpending() failed: %m", G_STRFUNC);
	} else if (extended <= 2) {
		int i;

		for (i = 1; i < SIG_COUNT; i++) {
			if (sigismember(&set, i)) {
				s_warning("%s: signal %s still pending",
					G_STRFUNC, signal_name(i));
			}
		}
	}

	/*
	 * Log faulting address and propagate that information in the
	 * crash log as an error message.
	 */

	{
		static char data[512];

		/*
		 * This signal handler is handling highly harmful signals, which could
		 * recursively re-occur in our handling, so be extremely careful and
		 * gradually do less and less, until explicit immediate termination.
		 */

		if (extended > 1) {
			if (2 == extended) {
				sig_exception_format(data, sizeof data, signo, si, u, TRUE);
				s_minicrit("%s", data);
				crash_set_error(data);
				crash_abort();
			} else if (3 == extended) {
				abort();
			} else {
				_exit(EXIT_FAILURE);
			}
		} else {
			sig_exception_format(data, sizeof data, signo, si, u, FALSE);
			s_critical("%s", data);
			crash_set_error(data);
		}
	}

	in_signal_handler--;
	signal_trampoline(signo);
}
#endif	/* HAS_SIGACTION && SA_SIGINFO */

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
 * @param signo		the signal number.
 * @param handler	the signal handler to install.
 * @param extra		whether to grab extra signal context
 *
 * @return the previous signal handler or SIG_ERR on failure.
 */
static signal_handler_t
signal_trap_with(int signo, signal_handler_t handler, bool extra)
{
	signal_handler_t ret, old_handler, trampoline;

	g_assert(handler != SIG_ERR);
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	STATIC_ASSERT(SIGNAL_COUNT == G_N_ELEMENTS(signal_handler));

	if G_UNLIKELY(!signal_inited)
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
			if (extra && signal_trampoline == trampoline) {
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

		ret = sigaction(signo, &sa, &osa) ? SIG_ERR :
#ifdef SA_SIGINFO
			(osa.sa_flags & SA_SIGINFO) ?
				(signal_handler_t) osa.sa_sigaction : osa.sa_handler
#else
			osa.sa_handler
#endif
		;
	}
#else
	(void) extra;
	ret = signal(signo, trampoline);
#endif	/* HAS_SIGACTION */

	if (SIG_ERR == ret)
		return ret;

	signal_handler[signo] = handler;

	return (SIG_DFL == ret || SIG_IGN == ret) ? ret : old_handler;
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
	return signal_trap_with(signo, handler, TRUE);
}

/**
 * Installs a signal handler but without any special handling for harmful
 * signals to capture extra contextual information.
 */
signal_handler_t
signal_catch(int signo, signal_handler_t handler)
{
	return signal_trap_with(signo, handler, FALSE);
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
bool
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
 * Synchronously raise a fatal SIGBART signal.
 *
 * If we were not in a signal handler or in a critical section already, this
 * call ensures that signal_in_handler() will return FALSE, since everything
 * is happening synchronously and we cannot be interrupting a memory allocation
 * routine or be in the presence of dangling data structures.
 */
void
signal_abort(void)
{
	/*
	 * In case the error occurs within a critical section with all the
	 * signals blocked, make sure to unblock SIGABRT.  In that case, we
	 * are asynchronous with respect to the program, as we are interrupting
	 * a section that is supposed to be signal-safe, so don't set the
	 * ``in_signal_abort'' flag.
	 */

	if (in_critical_section)
		signal_unblock(SIGABRT);
	else
		in_signal_abort = TRUE;

	raise(SIGABRT);
	s_error("raise() failed: %m");
}

/**
 * Initialize the signal layer.
 */
static G_GNUC_COLD void
signal_init_once(void)
{
	int regnum;
	size_t i;

	for (i = 0; i < G_N_ELEMENTS(signal_handler); i++) {
		signal_handler[i] = SIG_DFL;	/* Can't assume it's NULL */
	}

	/* 
	 * Chunk allocated as non-leaking because the signal chunk must
	 * remain active up to the very end, way past the point where we're
	 * supposed to have freed everything and leak detection kicks in.
	 */

	sig_chunk = ck_init_not_leaking(SIGNAL_CHUNK_SIZE, SIGNAL_CHUNK_RESERVE);

	/*
	 * Compute the PC register index in the saved user machine context.
	 */

	regnum = sig_get_pc_index();

	switch (regnum) {
	case SIG_PC_UNAVAILABLE:
	case SIG_PC_HIDDEN:
		break;
	case SIG_PC_UNKNOWN:
		s_warning("%s: could not find PC in machine context", G_STRFUNC);
		break;
	case SIG_PC_MULTIPLE:
		s_warning("%s: many locations for PC in machine context", G_STRFUNC);
		break;
	case SIG_PC_IMPOSSIBLE:
		g_assert_not_reached();
	default:
		break;
	}
}

/**
 * Initialize the signal layer.
 */
void
signal_init(void)
{
	once_run(&signal_inited, signal_init_once);
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
