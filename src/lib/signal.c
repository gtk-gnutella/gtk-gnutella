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

#include "signal.h"

#include "atomic.h"
#include "buf.h"
#include "ckalloc.h"
#include "crash.h"
#include "dl_util.h"
#include "glib-missing.h"       /* For g_strlcpy() */
#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "once.h"
#include "registers.h"
#include "str.h"
#include "stringify.h"
#include "unsigned.h"

#include "override.h"	/* Must be the last header included */

#if 0
#define SIGNAL_HANDLER_TRACE		/* Trace install of signal handlers */
#endif

#ifndef SIG_ERR
#define SIG_ERR ((signal_handler_t) -1)
#endif

#define SIGNAL_CHUNK_SIZE		4000	/**< Safety allocation pool */
#define SIGNAL_CHUNK_RESERVE	512		/**< Critical amount reserved */

/**
 * A signal stack is configured for each thread to be able to process SIGSEGV
 * in order to detect stack overflows.
 *
 * This only works if the kernel supports sigaction() with the SA_ONSTACK flag.
 *
 * We need to leave enough room to be able to process, on that stack, the
 * execution of the crash handler, possibly with a stack backtrace (which needs
 * to allocate the backtracing buffer on the stack itself).
 *
 * Therefore, we need more stack requirements than the typical stack size
 * which is defined to SIGSTKSZ.  Experiments on a 64-bit linux kernel shows
 * that SIGSTKSZ is too small (i.e. the signal stack overflows during the
 * stack dump process, which corrupts memory since we don't trap signal stack
 * overflows).
 *
 * Adding two additional pages (8K) is enough to cover the current needs.
 *		--RAM, 2013-09-10
 */
#define SIGNAL_STACK_SIZE		(SIGSTKSZ + 8192)

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
	D(SIGPIPE),
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

/*
 * Cleanup routines to invoke when we receive uncaught fatal signals.
 */

#define SIGNAL_CLEANUP		32
static signal_cleanup_t sig_cleanup[SIGNAL_CLEANUP];
static unsigned sig_cleanup_count;
static spinlock_t sig_cleanup_slk = SPINLOCK_INIT;

static mutex_t signal_lock = MUTEX_INIT;

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

static volatile sig_atomic_t in_signal_handler;
static once_flag_t signal_inited;
static bool signal_catch_segv;

static void signal_uncaught(int signo);

/**
 * Is signal fatal if not trapped, according to traditional UNIX semantics?
 *
 * Fatal means that the process will not survive, whether it is simply
 * terminated (SIGINT for instance) or terminated with a core dump (SIGQUIT).
 */
static bool
signal_is_fatal(int signo)
{
	switch (signo) {
#ifdef SIGHUP
	case SIGHUP:	return TRUE;
#endif
	case SIGINT:	return TRUE;
#ifdef SIGQUIT
	case SIGQUIT:	return TRUE;
#endif
	case SIGILL:	return TRUE;
	case SIGABRT:	return TRUE;
	case SIGFPE:	return TRUE;
#ifdef SIGKILL
	case SIGKILL:	return TRUE;	/* But non-trappable */
#endif
#ifdef SIGBUS
	case SIGBUS:	return TRUE;
#endif
	case SIGSEGV:	return TRUE;
#ifdef SIGPIPE
	case SIGPIPE:	return TRUE;
#endif
#ifdef SIGALRM
	case SIGALRM:	return TRUE;
#endif
	case SIGTERM:	return TRUE;
#ifdef SIGUSR1
	case SIGUSR1:	return TRUE;
#endif
#ifdef SIGUSR2
	case SIGUSR2:	return TRUE;
#endif
#ifdef SIGIO
	case SIGIO:		return TRUE;
#endif
#ifdef SIGTRAP
	case SIGTRAP:	return TRUE;
#endif
#ifdef SIGSYS
	case SIGSYS:	return TRUE;
#endif
#ifdef SIGPROF
	/*
	 * SIGPROF needs special care: it is a harmful signal, if received and
	 * untrapped, but its trapping is done by the C startup when profiling
	 * is enabled and if we mark it harmful, we will immediately abort in
	 * signal_uncaught() when getting the first SIGPROF signal...
	 *
	 * Let's not mark it harmful, but the consequences are that if the user
	 * explicitly sends a SIGPROF to the process, emergency signal cleanup
	 * will not be performed.  Since a user could always send a SIGKILL
	 * anyway, this is not deemed as a problem.
	 */
	case SIGPROF:	return FALSE;
#endif
#ifdef SIGVTALRM
	case SIGVTALRM:	return TRUE;
#endif
#ifdef SIGXCPU
	case SIGXCPU:	return TRUE;
#endif
#ifdef SIGXFSZ
	case SIGXFSZ:	return TRUE;
#endif
#ifdef SIGLOST
	case SIGLOST:	return TRUE;
#endif
	}

	/*
	 * Real-time signals always terminate a process if unhandled.
	 */

#ifdef SIGRTMIN
	if (signo >= SIGRTMIN && signo <= SIGRTMAX)
		return TRUE;
#endif

	return FALSE;	/* Unknown signal, or known to not be harmful if ignored */
}

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
	buf_t *b, bs;
	unsigned i;

	for (i = 0; i < N_ITEMS(signals); i++) {
		if (signals[i].signo == signo)
			return signals[i].name;
	}

	/*
	 * If there is a known symbolic form (not starting with "NUMxx"), use it.
	 * There is no "SIG" prefix in names from this array.
	 */

	if (signal_in_handler()) {
		static char sig_buf[32];	/* Do not allocate memory in handler */
		b = buf_init(&bs, sig_buf, sizeof sig_buf);
	} else {
		b = buf_private(G_STRFUNC, 32);
	}

	if (signo < SIG_COUNT && !is_strprefix(signal_names[signo], "NUM")) {
		buf_printf(b, "SIG%s", signal_names[signo]);
	} else {
		buf_printf(b, "signal #%d", signo);
	}

	return buf_data(b);
}

/**
 * Add a cleanup handler in case we receive a harmful uncaught signal.
 *
 * This is meant to release precious system resources that the kernel
 * would not normally return when the process exits (e.g. all System V
 * IPC resources, even when grabbed with IPC_PRIVATE).
 */
void
signal_cleanup_add(signal_cleanup_t cleanup)
{
	unsigned i, idx;

	spinlock(&sig_cleanup_slk);

	/*
	 * Ignore duplicates, loudly.
	 */

	for (i = 0; i < sig_cleanup_count; i++) {
		if (cleanup == sig_cleanup[i]) {
			spinunlock(&sig_cleanup_slk);
			s_minicarp("%s(): ignoring attempt to add already registered %s()",
				G_STRFUNC, stacktrace_function_name(cleanup));
			return;
		}
	}

	if G_UNLIKELY(sig_cleanup_count >= SIGNAL_CLEANUP)
		s_minierror("%s(): too many cleanup routines defined", G_STRFUNC);

	idx = sig_cleanup_count++;
	sig_cleanup[idx] = cleanup;
	spinunlock(&sig_cleanup_slk);

	/*
	 * The first time we install a cleanup, we need to look at all the
	 * known signals and setup our signal_uncaught() handler if nothing
	 * was setup yet.
	 */

	if G_UNLIKELY(0 == idx) {
		signal_init();

		/* Skip SIGZERO, this is not a real signal */

		mutex_lock(&signal_lock);

		for (i = 1; i < SIGNAL_COUNT; i++) {
			if (SIG_DFL == signal_handler[i] && signal_is_fatal(i))
				signal_set(i, signal_uncaught);
		}

		mutex_unlock(&signal_lock);
	}
}

static Sigjmp_buf sig_cleanup_env;

static void
signal_cleanup_got_signal(int signo)
{
	s_rawwarn("%s(): %s received, continuing...",
		G_STRFUNC, signal_name(signo));

	Siglongjmp(sig_cleanup_env, signo);
}

/**
 * Run installed cleanup handlers, in the reverse order they were installed.
 */
void
signal_perform_cleanup(void)
{
	static spinlock_t cleanup_slk = SPINLOCK_INIT;
	bool locked;
	signal_handler_t old_sigsegv;
#ifdef SIGBUS
	signal_handler_t old_sigbus;
#endif

	/*
	 * Only one thread may run this safely.  Warn if concurrent threads
	 * attempt to run this.
	 */

	if (!spinlock_hidden_try(&cleanup_slk)) {
		s_miniwarn("%s(): concurrent attempt ignored", G_STRFUNC);
		return;
	}

	signal_crashing();		/* Avoid memory allocations in some places */

	old_sigsegv = signal_catch(SIGSEGV, signal_cleanup_got_signal);
#ifdef SIGBUS
	old_sigbus = signal_catch(SIGBUS, signal_cleanup_got_signal);
#endif

	locked = spinlock_hidden_try(&sig_cleanup_slk);

	if (!locked)
		s_miniwarn("%s(): running without lock protection", G_STRFUNC);

	while (sig_cleanup_count != 0) {
		if (Sigsetjmp(sig_cleanup_env, TRUE)) {
			s_rawwarn("%s(): handler #%u did not complete",
				G_STRFUNC, sig_cleanup_count + 1);
			continue;
		}
		(*sig_cleanup[--sig_cleanup_count])();
	}

	if (locked)
		spinunlock_hidden(&sig_cleanup_slk);

	signal_set(SIGSEGV, old_sigsegv);
#ifdef SIGBUS
	signal_set(SIGBUS, old_sigbus);
#endif

	signal_uncrashing();
	spinunlock_hidden(&cleanup_slk);
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

	g_assert(SIGSEGV == signo
#ifdef SIGBUS
		|| SIGBUS == signo
#endif
	);
	g_assert(si != NULL);

	if (1 == REGISTER_COUNT(uc)) {
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

	for (i = 0; i < REGISTER_COUNT(uc); i++) {
		size_t off = REGISTER_VALUE(uc, i) - caller;
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
		s_warning("%s(): sigaction() setup failed: %m", G_STRFUNC);
		return -1;
	}

	if (Sigsetjmp(sig_pc_env, TRUE)) {
		if (-1 == sigaction(SIGSEGV, &osa, &sa))
			s_critical("%s(): sigaction() restore failed: %m", G_STRFUNC);
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

	return ulong_to_pointer(REGISTER_VALUE(uc, sig_pc_regnum));
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

static volatile sig_atomic_t in_signal_abort;

/**
 * Are we in an asynchronous signal handler?
 */
bool
signal_in_handler(void)
{
	if (ATOMIC_GET(&in_signal_abort) && 1 == ATOMIC_GET(&in_signal_handler))
		return FALSE;		/* Handle signal_abort() specially */

	return 0 != ATOMIC_GET(&in_signal_handler) && !signal_in_exception();
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
 * Wrapper for delivery of an untrapped harmful signal.
 *
 * These are caught to be able to perform application-specific cleanup
 * before the application is terminated.
 */
static void
signal_uncaught(int signo)
{
	g_assert(signo > 0 && signo < SIGNAL_COUNT);

	/*
	 * Be silent if there is nothing to do.
	 */

	if (0 != atomic_uint_get(&sig_cleanup_count)) {
		s_miniwarn("%s(%s): running %u cleanup handler%s",
			G_STRFUNC, signal_name(signo), sig_cleanup_count,
			plural(sig_cleanup_count));

		signal_perform_cleanup();
	}

	/*
	 * Restore default signal handler, since it was originally uncaught,
	 * unblock it and raise it again to get the default behaviour.
	 *
	 * We must reset signal_catch_segv to FALSE otherwise signal_trap_with()
	 * will force signal_uncaught() as the handler for SIGSEGV.  To avoid
	 * race conditions with a concurrent thread creation that would reset
	 * the signal_catch_segv variable to TRUE, we take the mutex.
	 */

	if (
		SIGSEGV == signo
#ifdef SIGBUS
		|| SIGBUS == signo
#endif
	) {
		mutex_lock(&signal_lock);
		signal_catch_segv = FALSE;
	}

	signal_catch(signo, SIG_DFL);
	signal_unblock(signo);

	if (
		SIGSEGV == signo
#ifdef SIGBUS
		|| SIGBUS == signo
#endif
	)
		mutex_unlock(&signal_lock);

	raise(signo);
}

#ifdef HAS_SIGALTSTACK
/*
 * Ensure the SIGSEGV signal is minimally trapped to catch up thread stack
 * overflows and properly log them when they occur.
 *
 * Called the first time a new thread is created.
 */
static void
signal_thread_init(void)
{
	mutex_lock(&signal_lock);

	/*
	 * Going through signal_set() ensures we'll properly use sigaction()
	 * to setup the signal handler, and further make sure we are configuring
	 * an alternate stack to process SIGSEGV when they occur, provided the
	 * kernel supports these features.
	 *
	 * On OS/X, it seems that SIGBUS is delivered to the process instead of
	 * SIGSEGV when a stack boundary is reached, hense the additional code
	 * to handle SIGBUS in a similar way.
	 */

	if (SIG_DFL == signal_handler[SIGSEGV])
		signal_set(SIGSEGV, signal_uncaught);

#ifdef SIGBUS
	if (SIG_DFL == signal_handler[SIGBUS])
		signal_set(SIGBUS, signal_uncaught);
#endif

	signal_catch_segv = TRUE;
	mutex_unlock(&signal_lock);
}
#endif	/* HAS_SIGALTSTACK */

/**
 * Create the signal stack used for SIGSEGV handlers called by the thread,
 * if supported.
 *
 * The allocated stack must be freed with signal_stack_free() when the thread
 * is terminated.
 *
 * If the value in *base_ptr is not NULL, it is taken as the base of an
 * already allocated memory region, suitable to be used as the stack base.
 * This allows reuse of previously allocated stacks when signal_stack_free()
 * cannot remove the signal stack for the thread.
 *
 * @param base_ptr		written with base of allocated stack
 *
 * @return the length of the signal stack if OK, 0 otherwise.
 * The base of the allocated stack is written to ``base'' when successful.
 */
size_t
signal_stack_allocate(void **base_ptr)
{
#ifdef HAS_SIGALTSTACK
	stack_t ss;
	void *p = *base_ptr;
	size_t size;

	if (NULL == p)
		p = vmm_alloc(SIGNAL_STACK_SIZE);

	ss.ss_sp = p;
	ss.ss_size = size = round_pagesize(SIGNAL_STACK_SIZE);
	ss.ss_flags = 0;

	/*
	 * It is the job of sigaltstack() to configure the stack properly
	 * depending on the growth direction of stacks on the system, using
	 * the supplied buffer.
	 */

	if (-1 == sigaltstack(&ss, NULL)) {
		s_warning("%s(): unable to install signal stack of %zu bytes at %p: %m",
			G_STRFUNC, size, p);
	}

	signal_thread_init();

	*base_ptr = p;

	return size;
#else
	*base_ptr = NULL;
	return 0;
#endif
}

/**
 * Free the allocated signal stack, nullifying the pointer if we can disable
 * the signal stack.
 *
 * @param base_ptr		pointer to the base address of the stack
 *
 * @return TRUE if we successfully disabled the stack and freed the stack.
 */
bool
signal_stack_free(void **base_ptr)
{
#ifdef HAS_SIGALTSTACK
	void *p = *base_ptr;
	stack_t ss;
	bool success = TRUE;

	ss.ss_sp = NULL;
	ss.ss_size = round_pagesize(SIGNAL_STACK_SIZE);
	ss.ss_flags = SS_DISABLE;

	/*
	 * If we can't disable the signal stack, then leave it allocated: it will
	 * be kept in the thread element and reused the next time another thread
	 * is launched with the same thread ID (and by then hopefully the signal
	 * stack will have been released by the POSIX thread layer).
	 */

	if (-1 == sigaltstack(&ss, NULL)) {
		s_warning("%s(): unable to disable signal stack of %zu bytes at %p: %m",
			G_STRFUNC, round_pagesize(SIGNAL_STACK_SIZE), p);
		success = FALSE;
	} else {
		vmm_free(p, SIGNAL_STACK_SIZE);
		*base_ptr = NULL;
	}

	return success;
#else
	(void) base_ptr;
	g_assert_not_reached();		/* Can't be called! */
#endif
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

	g_soft_assert_log(handler != SIG_DFL && handler != SIG_IGN,
		"%s(): signo=%d (%s), handler=%s",
		G_STRFUNC, signo, signal_name(signo),
		SIG_DFL == handler ? "SIG_DFL" :
		SIG_IGN == handler ? "SIG_IGN" : "<BUG>");

	if G_UNLIKELY(SIG_DFL == handler || SIG_IGN == handler)
		return;

	/*
	 * Wrapping the signal handler allows us to know whether we are in
	 * a signal handler through signal_in_handler().
	 */

	ATOMIC_INC(&in_signal_handler);
	(*handler)(signo);
	ATOMIC_DEC(&in_signal_handler);

	/*
	 * When leaving the last signal handler, cleanup the emergency chunk.
	 *
	 * Before requesting a critical section, look whether something was
	 * allocated already in the emergency chunk.
	 */

	if (ck_used(sig_chunk)) {
		sigset_t set;

		if (signal_enter_critical(&set)) {
			if (0 == ATOMIC_GET(&in_signal_handler))
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

	/*
	 * First check whether we're getting a segmentation violation due to a
	 * stack overflow.  If we do, we won't be able to go very far anyway hence
	 * it's best to abort as early as possible.
	 */

	if (SIGSEGV == signo)
		thread_stack_check_overflow(si->si_addr);

#ifdef SIGBUS
	/* On OS/X, the kernel sends a SIGBUS on stack overflows */
	if (SIGBUS == signo)
		thread_stack_check_overflow(si->si_addr);
#endif

	ATOMIC_INC(&in_signal_handler);
	ATOMIC_INC(&extended);
	atomic_mb();

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
		s_miniwarn("%s: sigpending() failed: %m", G_STRFUNC);
	} else if (extended <= 2) {
		int i;

		for (i = 1; i < SIG_COUNT; i++) {
			if (sigismember(&set, i)) {
				s_miniwarn("%s: signal %s still pending",
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
				s_rawwarn("%s", data);
				crash_set_error(data);
				crash_abort();
			} else if (3 == extended) {
				abort();
			} else {
				_exit(EXIT_FAILURE);
			}
		} else {
			sig_exception_format(data, sizeof data, signo, si, u, FALSE);
			s_rawwarn("%s", data);
			crash_set_error(data);
		}
	}

	ATOMIC_DEC(&in_signal_handler);
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

	STATIC_ASSERT(SIGNAL_COUNT == N_ITEMS(signal_handler));

	if G_UNLIKELY(!ONCE_DONE(signal_inited))
		signal_init();

	mutex_lock(&signal_lock);
	old_handler = signal_handler[signo];

	g_assert(old_handler != SIG_ERR);

	/*
	 * If they restore the default handler for a signal and we have cleanup
	 * to perform, redirect them to signal_uncaught().
	 */

	atomic_mb();		/* Make sure we have an accurate sig_cleanup_count */

	if (sig_cleanup_count != 0 && SIG_DFL == handler && signal_is_fatal(signo))
		handler = signal_uncaught;

	/*
	 * Likewise, if we created a thread, we need to catch SIGSEGV to never let
	 * the default handler run, so that we can trap stack overflows.
	 */

	if (SIGSEGV == signo && SIG_DFL == handler && signal_catch_segv)
		handler = signal_uncaught;

#ifdef SIGBUS
	if (SIGBUS == signo && SIG_DFL == handler && signal_catch_segv)
		handler = signal_uncaught;
#endif

	/*
	 * When not using SIG_DFL or SIG_IGN, make sure we go through the
	 * signal trampoline to perform some checks before invoking the
	 * user handler.
	 */

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
#ifdef SA_ONSTACK
			if (
				SIGSEGV == signo
#ifdef SIGBUS
				|| SIGBUS == signo
#endif
			) {
				sa.sa_flags |= SA_ONSTACK;
			}
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

#ifdef SIGNAL_HANDLER_TRACE
		{
			buf_t *b = buf_private(G_STRFUNC, 1);
			char *p = buf_data(b);

			/*
			 * Avoid trace recursions, which can happen through
			 * stacktrace_function_name() when dl_util_query() is
			 * called, since that will attempt to ignore SIGSEGV.
			 *
			 * We rely on the fact that buf_private() initially
			 * allocates a buffer that is zeroed to detect that we
			 * are actually entering this tracing code for the first
			 * time in a given thread.
			 *		--RAM, 2015-02-05
			 */

			if ('\0' == *p) {
				str_t *s;

				*p = '\01';		/* Flag that we're now tracing */

				s = str_new(120);
				str_printf(s, "%s(): installing %s() trampoline ",
					G_STRFUNC, stacktrace_function_name(
					(sa.sa_flags & SA_SIGINFO) ?
						(signal_handler_t) sa.sa_sigaction : sa.sa_handler));
				str_catf(s, "going to %s() handler for %s",
					stacktrace_function_name(handler), signal_name(signo));
				str_catf(s, ": old handler was %s()",
					stacktrace_function_name(old_handler));
				s_debug("%s", str_2c(s));
				str_destroy_null(&s);

				*p = '\0';		/* Done with tracing */
			}
		}
#endif	/* SIGNAL_HANDLER_TRACE */

		ret = sigaction(signo, &sa, &osa) ? SIG_ERR :
#ifdef SA_SIGINFO
			(osa.sa_flags & SA_SIGINFO) ?
				(signal_handler_t) osa.sa_sigaction : osa.sa_handler
#else
			osa.sa_handler
#endif
		;
	}
#else	/* !HAS_SIGACTION */
	(void) extra;
	ret = signal(signo, trampoline);
#endif	/* HAS_SIGACTION */

	if (SIG_ERR == ret) {
		mutex_unlock(&signal_lock);
		return ret;
	}

	signal_handler[signo] = handler;
	mutex_unlock(&signal_lock);

	/*
	 * Hide our internal signal_uncaught() handler which is only installed
	 * to be able to trap otherwise harmful signals when we have cleanup
	 * to perform.
	 */

	if (signal_uncaught == old_handler)
		old_handler = SIG_DFL;

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
static volatile sig_atomic_t in_exception_handler;

/**
 * Are we in an exception?
 *
 * @return amount of times signal_crashing() was called.
 */
int
signal_in_exception(void)
{
	return ATOMIC_GET(&in_exception_handler);
}

/**
 * Mark that we are entering a fatal exception.
 */
void
signal_crashing(void)
{
	ATOMIC_INC(&in_exception_handler);
}

/**
 * Mark that we are leaving a fatal exception handler.
 */
void
signal_uncrashing(void)
{
	sig_atomic_t old = ATOMIC_DEC(&in_exception_handler);

	g_assert_log(size_is_non_negative(old),
		"%s(): old=%zu", G_STRFUNC, (size_t) old);
}

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

	if (is_running_on_mingw()) {
		ATOMIC_INC(&in_critical_section);
		goto ok;
	}

#ifdef HAS_SIGPROCMASK
	{
		sigset_t set;

		/*
		 * If we are nesting critical sections, we have already blocked
		 * all the signals, so there's no need to do anything.  Just count
		 * the sections so that we restore the signal mask only when we
		 * leave the outermost one.
		 */

		if (ATOMIC_INC(&in_critical_section))
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
	return TRUE;
}

/**
 * Unblock signals that were blocked when we entered the critical section.
 */
void
signal_leave_critical(const sigset_t *oset)
{
	g_assert(ATOMIC_GET(&in_critical_section) > 0);

	ATOMIC_DEC(&in_critical_section);

	if (is_running_on_mingw())
		return;

#ifdef HAS_SIGPROCMASK
	if (0 == ATOMIC_GET(&in_critical_section)) {
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

	if (0 != ATOMIC_GET(&in_critical_section))
		signal_unblock(SIGABRT);
	else
		ATOMIC_SET(&in_signal_abort, TRUE);

	raise(SIGABRT);
}

/**
 * Initialize the signal layer.
 */
static void G_COLD
signal_init_once(void)
{
	int regnum;
	size_t i;

	for (i = 0; i < N_ITEMS(signal_handler); i++) {
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
		s_warning("%s(): could not find PC in machine context", G_STRFUNC);
		break;
	case SIG_PC_MULTIPLE:
		s_warning("%s(): many locations for PC in machine context", G_STRFUNC);
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
	once_flag_run(&signal_inited, signal_init_once);
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
