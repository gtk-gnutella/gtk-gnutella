/*
 * Copyright (c) 2004, 2010-2012, 2016 Raphael Manfredi
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
 * Stack unwinding and printing support.
 *
 * @author Raphael Manfredi
 * @date 2004, 2010-2012, 2016
 */

#include "common.h"		/* For RCSID */

#include "stacktrace.h"

#include "atio.h"
#include "atomic.h"
#include "bfd_util.h"
#include "concat.h"
#include "constants.h"
#include "crash.h"		/* For print_str() and crash_signame() */
#include "dl_util.h"
#include "eslist.h"
#include "file.h"
#include "halloc.h"
#include "hashing.h"	/* For binary_hash() */
#include "log.h"
#include "mem.h"
#include "misc.h"		/* For is_strprefix() and is_strsuffix() */
#include "mutex.h"
#include "omalloc.h"
#include "once.h"
#include "path.h"
#include "signal.h"
#include "spinlock.h"
#include "str.h"
#include "stringify.h"
#include "symbols.h"
#include "thread.h"
#include "tm.h"
#include "unsigned.h"

/* We need hash_table_new_real() to avoid any call to g_malloc() */
#define MALLOC_SOURCE
#include "hashtable.h"
#undef MALLOC_SOURCE

#include "override.h"	/* Must be the last header included */

#ifdef I_EXECINFO
#include <execinfo.h>	/* For backtrace() */
#endif

#define STACKTRACE_DLFT_SYMBOLS	8192	/* Pre-sizing of symbol table */
#define STACKTRACE_BUFFER_SIZE	8192	/* Amount reserved for stack tracing */
#define STACKTRACE_BUFFER_COUNT	3		/* Amount of pre-allocated buffers */

/**
 * Default stacktrace decoration flags we're using here.
 */
#define STACKTRACE_DECORATION	\
	(STACKTRACE_F_ORIGIN | STACKTRACE_F_SOURCE | \
		STACKTRACE_F_MAIN_STOP | STACKTRACE_F_THREAD)

/**
 * Deferred loading support.
 */
static const char *local_path;		/**< Path before a chdir() (ro string) */
static const char *program_path;	/**< Absolute program path (ro string) */
static time_t program_mtime;		/**< Last modification time of executable */
static bool stacktrace_crashing;	/**< Use simple stack traces if set */
static bool symbols_loaded;
static symbols_t *symbols;
static bool stacktrace_inited;

static mutex_t stacktrace_sym_mtx  = MUTEX_INIT;
static once_flag_t stacktrace_atom_inited;

#define STACKTRACE_CIRCULAR_LEN		THREAD_MAX

static struct {
	struct stacktrace circular[STACKTRACE_CIRCULAR_LEN];
	unsigned idx;
	bool dirty;
} stacktrace_atom_buffer;

static hash_table_t *stack_atoms;

#define STACKTRACE_ATOM_LOCK		hash_table_lock(stack_atoms)
#define STACKTRACE_ATOM_UNLOCK		hash_table_unlock(stack_atoms)
#define STACKTRACE_ATOM_IS_LOCKED	hash_table_is_locked(stack_atoms)

#define assert_stacktrace_atom_locked() g_assert(STACKTRACE_ATOM_IS_LOCKED)

#define STACKTRACE_SYM_LOCK		mutex_lock(&stacktrace_sym_mtx)
#define STACKTRACE_SYM_UNLOCK	mutex_unlock(&stacktrace_sym_mtx)
#define STACKTRACE_SYM_TRYLOCK	mutex_trylock(&stacktrace_sym_mtx)

/**
 * Auto-tuning stack trace offset.
 *
 * On some platforms, the level of offsetting we have to do to the stack
 * varies.  This variable contains the additionnal stack offsetting we have
 * to do.
 */
static size_t stack_auto_offset;

#ifndef MINGW32
static void *getreturnaddr(size_t level);
static void *getframeaddr(size_t level);
#endif

/**
 * Limit stacktraces to simple stacks, avoiding the BFD library or the
 * dynamic linker to resolve symbols.
 */
void
stacktrace_crash_mode(void)
{
	stacktrace_crashing = TRUE;
}

/**
 * Is PC a valid routine address?
 */
static inline bool G_CONST
valid_ptr(const void *pc)
{
	ulong v = pointer_to_ulong(pc);

	return v >= 0x1000 &&
		v < MAX_INT_VAL(ulong) - 0x1000 &&
		mem_is_valid_ptr(pc);
}

/**
 * Is SP a valid stack address?
 */
static inline bool G_PURE
valid_stack_ptr(const void *sp)
{
	return vmm_is_stack_pointer(sp, NULL);
}

/**
 * Is PC a routine address for something within our code?
 */
static inline bool G_CONST
stack_is_our_text(const void *pc)
{
#if defined(HAS_ETEXT_SYMBOL)
	extern const int etext;		/* linker-defined symbol */

	/* The address of "etext" marks the end of the text segment */
	return ptr_cmp(pc, &etext) < 0;

#elif defined(HAS_END_SYMBOL)
	extern const int end;		/* linker-defined symbol */

	/* The address of "end" marks the end of the BSS segment */
	return ptr_cmp(pc, &end) < 0;

#else
	(void) pc;
	return TRUE;
#endif
}

#ifndef MINGW32
/**
 * Unwind current stack into supplied stacktrace array.
 *
 * This routine stops unwinding as soon as it reaches a non-text address.
 *
 * If possible, do not inline stacktrace_gcc_unwind() as this would perturb
 * offsetting of stack elements to ignore.
 *
 * @param stack		array where stack should be written
 * @param count		amount of items in stack[]
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 *
 * @return the amount of entries filled in stack[].
 */
static NO_INLINE size_t
stacktrace_gcc_unwind(void *stack[], size_t count, size_t offset)
{
    size_t i;
	void *frame;

	/*
	 * Adjust the offset according to the auto-tunings.
	 */

	offset = size_saturate_add(offset, stack_auto_offset);

	/*
	 * Go carefully to stack frame "offset", in case the stack is
	 * currently corrupted.
	 */

	frame = getframeaddr(0);
	if (!valid_stack_ptr(frame))
		return 0;

	for (i = 0; i < offset; i++) {
		frame = getframeaddr(i + 1);

		if (!valid_stack_ptr(frame))
			return 0;
	}

	/*
	 * At this point, i == offset and frame == getframeaddr(offset).
	 */

	for (;; i++) {
		frame = getframeaddr(i + 1);

		if (!valid_stack_ptr(frame) || i - offset >= count)
			break;

		if (!valid_ptr(stack[i - offset] = getreturnaddr(i)))
			break;
	}

	return i - offset;
}
#endif	/* !MINGW32 */

/**
 * Unwind current stack into supplied stacktrace array.
 *
 * This routine stops unwinding as soon as it reaches a non-text address.
 *
 * If possible, do not inline stacktrace_unwind() as this would perturb
 * offsetting of stack elements to ignore.
 *
 * @param stack		array where stack should be written
 * @param count		amount of items in stack[]
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 *
 * @return the amount of entries filled in stack[].
 */
NO_INLINE size_t
stacktrace_unwind(void *stack[], size_t count, size_t offset)
#ifdef HAS_BACKTRACE
{
	static uint8 in_unwind[THREAD_MAX];
	void *trace[STACKTRACE_DEPTH_MAX + 5];	/* +5 to leave room for offsets */
	int depth;
    size_t amount;		/* Amount of entries we can copy in result */
	size_t i, idx;
	int id = thread_safe_small_id();
	static bool called;

	g_assert(size_is_non_negative(offset));

	/*
	 * backtrace() can call malloc(), which can cause fatal recursion here when
	 * compiled with xmalloc() trapping malloc()...  This usually happens
	 * on i386 linux when dlopen() is used at init time, the first time the
	 * routine is called, to fetch symbols from libgcc_s.so.1.
	 *
	 * If we are in a signal handler, we cannot invoke backtrace if we are
	 * holding a lock from xmalloc.c, for fear of deadlocking or starting
	 * to corrupt data structures.  This is not race-safe though as there is
	 * some time between grabbing a lock and registering it in the thread,
	 * time during which we can be interrupted by a signal.  Fortunately, this
	 * check is only required when we never called backtrace() before, so the
	 * failing window is quite narrow.
	 *		--RAM, 2016-01-29
	 */

	if (
		(id >= 0 && in_unwind[id]) ||
		(!called &&
			signal_in_unsafe_handler() &&
			thread_lock_holds_from("lib/xmalloc.c"))
	) {
		/*
		 * Don't "return" here, to avoid tail recursion since we increase the
		 * stack offsetting.
		 *
		 * Since stacktrace_gcc_unwind() will stop at the first non-text
		 * address it reaches, there is no need to post-process the result.
		 */

		i = stacktrace_gcc_unwind(stack, count, offset + 1);
		goto done;
	}

	/*
	 * When the size of stack[] is greater than the size of trace[], we
	 * backtrace directly into stack[], then copy over the result to be
	 * able to perform the offsetting.
	 *
	 * This is required for "safe" partial unwinding if coming from
	 * stacktrace_where_cautious_print_offset(): if we get a signal, the
	 * backtrace() operation will be aborted the hard way but hopefully we
	 * will have already filled some items in stack[].
	 */

	if (id >= 0)
		in_unwind[id] = TRUE;

	if (count >= N_ITEMS(trace)) {
		depth = backtrace(stack, count);
		memcpy(trace, stack, depth * sizeof trace[0]);
	} else {
		depth = backtrace(trace, N_ITEMS(trace));
	}

	/*
	 * Flag that backtrace() was called once, meaning it has performed its
	 * internal one-time initialization.  Subsequent calls should not have
	 * to call malloc().
	 */

	called = TRUE;		/* backtrace() should no longer invoke malloc() */

	if (id >= 0)
		in_unwind[id] = FALSE;

	idx = size_saturate_add(offset, stack_auto_offset);

	g_assert(size_is_non_negative(idx));

	if (UNSIGNED(depth) <= idx)
		return 0;

	amount = idx - UNSIGNED(depth);
	amount = MIN(amount, count);

	/*
	 * Only copy entries that are likely to be "text" addresses.
	 */

	for (i = 0; i < amount && valid_ptr(trace[idx]); i++) {
		stack[i] = trace[idx++];
	}

done:
	return i;		/* Amount of copied entries */
}
#elif defined(MINGW32)
{
	return mingw_backtrace(stack, count, offset + stack_auto_offset);
}
#else	/* !HAS_BACKTRACE */
{
	/*
	 * Don't increase offset, this is tail recursion and it can be optimized
	 * away.  At worst we'll see this call in the stack.
	 */
	return stacktrace_gcc_unwind(stack, count, offset);
}
#endif	/* HAS_BACKTRACE */

static sigjmp_buf stacktrace_safe_env[THREAD_MAX];

/**
 * Invoked when a fatal signal is received during stack unwinding.
 */
static void G_COLD
stacktrace_safe_got_signal(int signo)
{
	int stid = thread_small_id();

	/*
	 * Big assumption here is that the harmful signal is delivered to the
	 * thread that caused it.
	 */

	siglongjmp(stacktrace_safe_env[stid], signo);
}

/**
 * Safely unwind current stack into supplied stacktrace array.
 *
 * This routine stops unwinding as soon as it reaches a non-text address.
 *
 * @param stack		array where stack should be written
 * @param count		amount of items in stack[]
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 *
 * @return the amount of entries filled in stack[].
 */
NO_INLINE size_t
stacktrace_safe_unwind(void *stack[], size_t count, size_t offset)
{
	volatile size_t n;
	int stid;
	signal_handler_t old_sigsegv;
#ifdef SIGBUS
	signal_handler_t old_sigbus;
#endif

	/*
	 * Install signal handlers for most of the harmful signals that
	 * could happen during stack unwinding in case the stack is corrupted
	 * and we start following wrong frame pointers.
	 *
	 * We use signal_catch() and not signal_set() to avoid extra information
	 * from being collected should these signals occur.
	 */

	old_sigsegv = signal_catch(SIGSEGV, stacktrace_safe_got_signal);
#ifdef SIGBUS
	old_sigbus = signal_catch(SIGBUS, stacktrace_safe_got_signal);
#endif

	stid = thread_small_id();

	if (Sigsetjmp(stacktrace_safe_env[stid], TRUE)) {
		/*
		 * Because we zeroed the stack[] array before attempting the
		 * unwinding we can now go back and count the amount of items that
		 * were put there in case we got interrupted by a signal, to be
		 * able to save the part of the stack we were able to unwind
		 * correctly.
		 */

		n = 0;
		while (n < count && stack[n] != NULL)
			n++;
	} else {
		/*
		 * Prepare for possible harmful signal during stack unwinding:
		 * we zero the stack to be able to determine the amount of filled
		 * items in case the operation is aborted and stacktrace_unwind()
		 * does not return normally.
		 */

		memset(stack, 0, count * sizeof stack[0]);
		n = stacktrace_unwind(stack, count, offset + 1);
	}

	signal_set(SIGSEGV, old_sigsegv);
#ifdef SIGBUS
	signal_set(SIGBUS, old_sigbus);
#endif

	return n;
}

/**
 * Return self-assessed symbol quality.
 */
enum stacktrace_sym_quality
stacktrace_quality(void)
{
	return NULL == symbols ? STACKTRACE_SYM_GOOD : symbols_quality(symbols);
}

/**
 * Return string version of the self-assessed symbol quality.
 */
const char *
stacktrace_quality_string(const enum stacktrace_sym_quality sq)
{
	switch (sq) {
	case STACKTRACE_SYM_GOOD:		return "good";
	case STACKTRACE_SYM_STALE:		return "stale";
	case STACKTRACE_SYM_MISMATCH:	return "mismatch";
	case STACKTRACE_SYM_GARBAGE:	return "garbage";
	case STACKTRACE_SYM_MAX:		break;
	}

	return "UNKNOWN";
}

/**
 * Tune the level of offsetting we have to do to get the current caller.
 */
static NO_INLINE void G_COLD
stacktrace_auto_tune(void)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;
	size_t i;

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), 0);

	/*
	 * Look at the first item in the stack that is after ourselves.
	 * and within close range (the unwinding is close to the start of
	 * the routine so the PC of the caller should be close).
	 */

	for (i = 0; i < count; i++) {
		size_t d = ptr_diff(stack[i], func_to_pointer(stacktrace_auto_tune));

		if (size_is_non_negative(d) && d < 72)	/* close enough */
			break;
	}

	/*
	 * If we did not find a suitable candidate, warn but that's OK.
	 */

	if (count == i) {
		s_warning("could not auto-tune stacktrace offsets, using defaults");
		stack_auto_offset = 1;
	} else {
		stack_auto_offset = i;
	}
}

/**
 * Get symbols from the executable.
 */
static void G_COLD
stacktrace_get_symbols(const char *path, const char *lpath, bool stale)
{
	static int done;

	/*
	 * Make sure we're only doing this once.
	 *
	 * This cuts down recursion when there are stack traces to emit during
	 * symbol loading (e.g. an assertion failure, or a critical message
	 * requiring a trace).
	 */

	if (0 != atomic_int_inc(&done))
		return;

	/*
	 * In case we're crashing so early that stacktrace_init() has not been
	 * called, initialize properly.
	 */

	STACKTRACE_SYM_LOCK;

	if (NULL == symbols)
		symbols = symbols_make(STACKTRACE_DLFT_SYMBOLS, TRUE);

	symbols_load_from(symbols, path, lpath != NULL ? lpath : path);

	if (stale)
		symbols_mark_stale(symbols);

	STACKTRACE_SYM_UNLOCK;
}

/**
 * Initialize stack tracing.
 *
 * This should be called from the main thread only, before anything interesting
 * is done. Hence there is no need to make the initialization thread-safe.
 *
 * @param argv0		the value of argv[0], from main(): the program's filename
 * @param deferred	if TRUE, do not load symbols until it's needed
 */
void G_COLD
stacktrace_init(const char *argv0, bool deferred)
{
	char *path, *apath;
	filestat_t buf;

	g_assert(argv0 != NULL);

	if G_UNLIKELY(stacktrace_inited)
		return;

	stacktrace_inited = TRUE;
	path = file_program_path(argv0);
	if (NULL == symbols)
		symbols = symbols_make(STACKTRACE_DLFT_SYMBOLS, TRUE);

	if (NULL == path) {
		s_warning("cannot find \"%s\" in PATH, not loading symbols", argv0);
		goto done;
	}

	if (-1 == stat(path, &buf)) {
		s_warning("%s(): cannot stat \"%s\": %m", G_STRFUNC, path);
		s_warning("will not be loading symbols for %s", argv0);
		goto done;
	}

	apath = absolute_pathname(path);
	program_path = ostrdup_readonly(apath);
	HFREE_NULL(apath);

	if (deferred) {
		program_mtime = buf.st_mtime;
		local_path = ostrdup_readonly(path);
		goto tune;
	}

	stacktrace_get_symbols(path, path, FALSE);

	/*
	 * If running on Windows, call dl_util_get_base() to indirectly call
	 * dladdr(), which will trigger the mingw_dladdr() code and cause
	 * initialization of the Windows symbols: when crashing it may be hard
	 * to have symbols properly loaded.
	 *		--RAM, 2015-11-26
	 */

	if (is_running_on_mingw())
		(void) dl_util_get_base(stacktrace_init);

	/* FALL THROUGH */

done:
	symbols_loaded = TRUE;		/* Don't attempt again */

	/* FALL THROUGH */

tune:
	HFREE_NULL(path);
	stacktrace_auto_tune();
}

/**
 * @return amount of large VMM memory used.
 */
size_t
stacktrace_memory_used(void)
{
	size_t res;

	res = NULL == symbols ? 0 : symbols_memory_size(symbols);
	if (stack_atoms != NULL) {
		res += hash_table_arena_memory(stack_atoms);
	}

	return res;
}

/**
 * Close stack tracing.
 */
void G_COLD
stacktrace_close(void)
{
	symbols_free_null(&symbols);
	if (stack_atoms != NULL) {
		hash_table_destroy_real(stack_atoms);	/* Does not free keys/values */
		stack_atoms = NULL;
	}
}

/**
 * Load symbols if not done already.
 */
void G_COLD
stacktrace_load_symbols(void)
{
	static spinlock_t sym_load_slk = SPINLOCK_INIT;
	bool stale = FALSE;

	/*
	 * Don't use the once_flag_run() mechanism here since this can be used
	 * on the assertion failure path, and maybe called recursively.
	 */

	spinlock_hidden(&sym_load_slk);
	if G_LIKELY(symbols_loaded) {
		spinunlock_hidden(&sym_load_slk);
		return;
	}
	symbols_loaded = TRUE;		/* Whatever happens, don't try again */
	spinunlock_hidden(&sym_load_slk);

	/*
	 * If we are being called before stacktrace_init(), then derive a proper
	 * path using the dynamic linker.  In case we only get a relative path
	 * that cannot be found from our current location, attempt to locate the
	 * program in the user's PATH environment variable.
	 */

	if G_UNLIKELY(NULL == program_path) {
		const char *path = dl_util_get_path(func_to_pointer(stacktrace_init));
		if (!file_exists(path)) {
			char *fpath = file_locate_from_path(filepath_basename(path));
			program_path = ostrdup_readonly(fpath != NULL ? fpath : path);
			HFREE_NULL(fpath);
		} else {
			program_path = ostrdup_readonly(path);
		}
	}

	/*
	 * Loading of symbols was deferred: make sure the executable is still
	 * there and has not been tampered with since we started.
	 */

	if (program_path != NULL) {
		filestat_t buf;

		if (-1 == stat(program_path, &buf)) {
			s_warning("%s(): cannot stat \"%s\": %m", G_STRFUNC, program_path);
			goto error;
		}

		/*
		 * Symbols are loaded if the program has been tampered with, but
		 * the symbols are marked as stale.
		 */

		if (program_mtime != 0 && buf.st_mtime != program_mtime) {
			s_warning("%s(): executable file \"%s\" has been tampered with",
				G_STRFUNC, program_path);

			stale = TRUE;

			/* FALL THROUGH */
		}

		stacktrace_get_symbols(program_path, local_path, stale);
	}

	return;

error:
	if (program_path != NULL) {
		s_warning("%s(): cannot load symbols for %s", G_STRFUNC, program_path);
	}
}

/**
 * Post-init operations.
 */
void
stacktrace_post_init(void)
{
#ifdef MALLOC_FRAMES
	/*
	 * When we keep around allocation frames (to be able to report memory
	 * leaks later), it is best to load symbols immediately in case the
	 * program is changed (moved around) during the execution and we find out
	 * we cannot load the symbols later at exit time, when we have leaks to
	 * report and cannot map the PC addresses to functions.
	 */

	stacktrace_load_symbols();
#endif
}

/**
 * Fill supplied stacktrace structure with the backtrace.
 * Trace will start with our caller.
 */
void NO_INLINE
stacktrace_get(struct stacktrace *st)
{
	st->len = stacktrace_unwind(st->stack, N_ITEMS(st->stack), 1);
}

/**
 * Fill supplied stacktrace structure with the backtrace, removing ``offset''
 * amount of immediate callers (0 will make our caller be the first item).
 */
void NO_INLINE
stacktrace_get_offset(struct stacktrace *st, size_t offset)
{
	st->len = stacktrace_unwind(st->stack, N_ITEMS(st->stack), offset + 1);
}

/**
 * Stop as soon as we reach main() before backtracing into libc.
 *
 * @param where		symbolic name of the current routine
 *
 * @return TRUE if we reached main().
 */
static bool
stack_reached_main(const char *where)
{
	/*
	 * Stop as soon as we reach main() before backtracing into libc
	 */

	return is_strprefix(where, "main+") != NULL;	/* HACK ALERT */
}

/**
 * Attempt to grab the symbol lock to dump a stack trace.
 *
 * If we cannot grab the lock and we are already holding locks, fail as this
 * could create deadlocks.
 *
 * @param caller	caller routine, for logging purposes
 *
 * @return TRUE if we got the lock, FALSE if we could not get it.
 */
static bool
stack_sym_trylock(const char *caller)
{
	if (!STACKTRACE_SYM_TRYLOCK) {
		size_t cnt = thread_lock_count();

		/*
		 * Do not sleep if we are holding any locks, this could create
		 * deadlocks.
		 *
		 * Dumping the lock stack could give away some precious information
		 * though, since we're not going to get any stack trace!
		 */

		if (0 != cnt) {
			static uint8 warning[THREAD_MAX];
			uint stid = thread_small_id();

			/*
			 * Avoid deadly recursion: since dumping locks can also cause
			 * the locking stack to be dumped, we can come back here.
			 * Hence the warning[] array to cut recursion immediately.
			 */

			if (!warning[stid]) {
				warning[stid] = TRUE;

				s_rawwarn("%s(): not waiting, %s holds %zu lock%s",
					caller, thread_safe_name(), cnt, plural(cnt));
				thread_lock_dump_if_any(STDERR_FILENO, stid);

				warning[stid] = FALSE;
			}

			return FALSE;
		}

		STACKTRACE_SYM_LOCK;
	}

	return TRUE;
}

/**
 * Print array of PCs, using symbolic names if possible.
 *
 * @param f			where to print the stack
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 */
static void
stack_print(FILE *f, void * const *stack, size_t count)
{
	size_t i;
	int stid = -1;
	bool locked = TRUE;

	stacktrace_load_symbols();

	/*
	 * This attempts to avoid concurrent stack traces from being emitted,
	 * as long as the calling thread holds no lock.  Otherwise make sure
	 * we display the thread STID.
	 */

	if (!stack_sym_trylock(G_STRFUNC)) {
		stid = thread_safe_small_id();
		locked = FALSE;
	}

	for (i = 0; i < count; i++) {
		const char *where = symbols_name(symbols, stack[i], TRUE);

		if (!valid_ptr(stack[i]))
			break;

		if (stid >= 0)
			fprintf(f, "\t[%d] %s\n", stid, where);
		else
			fprintf(f, "\t%s\n", where);

		if (stack_reached_main(where))
			break;
	}

	if (locked)
		STACKTRACE_SYM_UNLOCK;
}

/**
 * Log array of PCs to logging agent, using symbolic names if possible.
 *
 * @param la		where to print the stack
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 */
static void
stack_log(logagent_t *la, void * const *stack, size_t count)
{
	size_t i;
	int stid = -1;
	bool locked = TRUE;

	stacktrace_load_symbols();

	/*
	 * This attempts to avoid concurrent stack traces from being emitted,
	 * as long as the calling thread holds no lock.  Otherwise make sure
	 * we display the thread STID.
	 */

	if (!stack_sym_trylock(G_STRFUNC)) {
		stid = thread_safe_small_id();
		locked = FALSE;
	}

	for (i = 0; i < count; i++) {
		const char *where = symbols_name(symbols, stack[i], TRUE);

		if (!valid_ptr(stack[i]))
			break;

		if (stid >= 0)
			log_info(la, "\t[%d] %s", stid, where);
		else
			log_info(la, "\t%s", where);

		if (stack_reached_main(where))
			break;
	}

	if (locked)
		STACKTRACE_SYM_UNLOCK;
}

/**
 * Safely print array of PCs, using symbolic names if possible.
 *
 * @param fd		where to print the stack
 * @param stid		thread ID to which stack belongs to
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 */
static void
stack_safe_print(int fd, int stid, void * const *stack, size_t count)
{
	size_t i;
	bool locked = TRUE;

	/*
	 * This attempts to avoid concurrent stack traces from being emitted,
	 * as long as the calling thread holds no lock.  Otherwise make sure
	 * we display the thread STID.
	 */

	if (!stack_sym_trylock(G_STRFUNC))
		locked = FALSE;

	for (i = 0; i < count; i++) {
		const char *where = symbols_name(symbols, stack[i], TRUE);
		char sbuf[UINT_DEC_BUFLEN];
		const char *snum;
		DECLARE_STR(6);

		print_str("\t");		/* 0 */
		if (stid > 0 || !locked) {
			snum = PRINT_NUMBER(sbuf, stid);
			print_str("[");		/* 1 */
			print_str(snum);	/* 2 */
			print_str("] ");	/* 3 */
		}
		print_str(where);		/* 4 */
		print_str("\n");		/* 5 */
		flush_str(fd);

		if (!valid_ptr(stack[i]))
			break;

		if (stack_reached_main(where))
			break;
	}

	if (locked)
		STACKTRACE_SYM_UNLOCK;
}

/**
 * @return whether a PC is from our own executable.
 */
bool
stacktrace_pc_within_our_text(const void *pc)
{
	return stack_is_our_text(pc);
}

/*
 * Return pretty path from source path by using the fact that our sources
 * lie under the "src/" root.
 */
static const char *
stacktrace_pretty_filepath(const char *filepath)
{
	const char *p;
	const char *q;
	const char *start;

	p = strrchr(filepath, G_DIR_SEPARATOR);
	if (p != NULL)
		p++;
	else
		p = filepath;

	/*
	 * Under operating systems that don't use '/' as path separators, we can
	 * stop because we know our compilation process uses '/' as separators.
	 *
	 * For instance, on Windows, we could have "gtk-gnutella\src\lib/cq.c"
	 * as the initial filepath and we would return "lib/cq.c" at this point.
	 */

	if ('/' != G_DIR_SEPARATOR)
		return p;

	start = filepath;

	if (is_absolute_path(filepath)) {
		const char *src = vstrstr(filepath, "/" SRC_PREFIX);
		start = (NULL == src) ? p : &src[CONST_STRLEN("/" SRC_PREFIX)];
	}

	/*
	 * We're on an operating system using '/' in paths.
	 *
	 * We basically recognized the basename at this point.  Move backwards
	 * until we find a "src/" component or the head of the string.
	 */

	for (q = p - 1; q > start; q--) {
		if ('/' == *q) {
			if (is_strprefix(q, "/" SRC_PREFIX))
				return p;
			p = q + 1;
		}
	}

	return is_strprefix(start, SRC_PREFIX) ? p : start;
}

enum sxfiletype {
	SXFILE_STDIO,
	SXFILE_FD
};

struct sxfile {
	enum sxfiletype type;	/* Union discriminant */
	int stid;				/* Thread ID for which we're printing */
	union {
		FILE *f;
		int fd;
	} u;
};

/**
 * Print a simple stack trace.
 *
 * @param xf		where to print the stack
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 */
static void
stack_safe_print_to(struct sxfile *xf, void * const *stack, size_t count)
{
	static int stack_plain;

	if (0 == atomic_int_inc(&stack_plain))
		s_rawwarn("disabled fancy symbolic stack traces");

	switch (xf->type) {
	case SXFILE_STDIO:
		fflush(xf->u.f);
		stack_safe_print(fileno(xf->u.f), xf->stid, stack, count);
		return;
	case SXFILE_FD:
		stack_safe_print(xf->u.fd, xf->stid, stack, count);
		return;
	}

	g_assert_not_reached();
}

/**
 * Print a decorated stack trace.
 *
 * @param xf		where to print the stack
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 * @param flags		decoration flags
 *
 * The available decoration flags are:
 *
 * STACKTRACE_F_ORIGIN:
 *	Displays the shared object file name if known, at the far right.
 *
 * STACKTRACE_F_PATH:
 *	In combination with STACKTRACE_F_ORIGIN, display full object paths.
 *
 * STACKTRACE_F_SOURCE:
 *	Displays the source code location, if known, after the symbol name.
 *
 * STACKTRACE_F_ADDRESS:
 *  Always display the hexadecimal address, even if the symbolic name
 *	is known.
 *
 * STACKTRACE_F_NUMBER:
 *	Number the stack items from 0 (top) and downwards.
 *
 * STACKTRACE_F_NO_INDENT:
 *	Do not emit a leading tabulation when formatting.
 *
 * STACKTRACE_F_GDB:
 *	Use gdb-like words to link items, such as "from", "at", "in", put
 *  parenthesis after routine names, don't display offsets.
 *
 * STACKTRACE_F_MAIN_STOP:
 *	Stop printing as soon as we reach the main() symbol.
 *
 * STACKTRACE_F_THREAD:
 *	Print leading thread ID between brackets if it's not the main thread (#0).
 *
 * When no flags are specified, this is equivalent to a mere stack_print().
 */
static void
stack_print_decorated_to(struct sxfile *xf,
	void * const *stack, size_t count, int flags)
{
	static bfd_env_t *be;
	size_t i;
	static char buf[512];
	static char name[256];
	static char tid[32];
	str_t s;
	bool gdb_like = booleanize(flags & STACKTRACE_F_GDB);
	bool reached_main = FALSE, locked = TRUE;
	int saved_errno = errno;

	/*
	 * When crashing severely, either after a recursive crash or because
	 * we are out of memory, disable fancy symbolic stack traces, use the
	 * simplest form.
	 *		--RAM, 2015-12-12
	 */

	if G_UNLIKELY(stacktrace_crashing) {
		stack_safe_print_to(xf, stack, count);
		return;
	}

	/*
	 * We're using global variables, and we need to avoid concurrent updates
	 * if we want to have something that makes sense in the output.
	 *
	 * If we are not crashing, locks are still enabled so we can create
	 * a critical section here to avoid garbling output.
	 *
	 * If we are crashing, and other threads reach this point, they are
	 * going to be suspended if not already done when they attempt to grab
	 * the lock: only the crashing thread will get a lock pass-through.
	 *
	 * This critical section alone also ensures that we never mix the outputs
	 * of two threads attempting to dump a stack at the same time.
	 * Otherwise, force the thread small ID to be output.
	 */

	if (!stack_sym_trylock(G_STRFUNC)) {
		flags |= STACKTRACE_F_THREAD;
		locked = FALSE;
	}

	/*
	 * The BFD environment is only opened once.
	 * See rationale at the end of this routine.
	 */

	if (NULL == be)
		be = bfd_util_init();

	str_new_buffer(&s, ARYLEN(buf), 0);

	/*
	 * Compute leading thread ID, shown only when not in the main thread.
	 */

	if (flags & STACKTRACE_F_THREAD) {
		unsigned stid = thread_safe_small_id();
		if (stid != 0)
			str_bprintf(ARYLEN(tid), "[%u] ", stid);
		else
			tid[0] = 0;
	} else {
		tid[0] = 0;
	}

	/*
	 * Iterate over the call stack and try to decipher each address: which
	 * file it comes from (the program itself, or a shared library object
	 * that has been mapped dynamically), what is the symbol name, and even
	 * which source file location it maps to if the information is available.
	 */

	for (i = 0; i < count && !reached_main; i++) {
		const void *pc = stack[i];
		const char *sopath = "??";	/* Shared object path */
		const void *base;			/* Mapping base for the shared object */
		bfd_ctx_t *bc = NULL;
		struct symbol_loc loc;
		bool located = FALSE;
		bool located_via_bfd = FALSE;
		bool has_parens = FALSE;

		/*
		 * If we run out of memory during the stack tracing, switch to a
		 * lighter version.
		 */

		if G_UNLIKELY(stacktrace_crashing) {
			if (locked)
				STACKTRACE_SYM_UNLOCK;
			stack_safe_print_to(xf, &stack[i], count - i);
			return;
		}

		/*
		 * Locate where the PC is located: in our own executable (statically
		 * linked) or within a dynamically mapped shared library.
		 */

		base = dl_util_get_base(pc);
		if (base != NULL) {
			const char *pathname;

			pathname = dl_util_get_path(pc);

			/*
			 * If we have a pathname, try to open the file with the BFD
			 * library to be able to get at debugging information.
			 */

			if (pathname != NULL) {
				if (!is_absolute_path(pathname) && stack_is_our_text(pc)) {
					if (!file_exists(pathname))
						pathname = program_path;
				}
			}

			if (pathname != NULL) {
				bc = bfd_util_get_context(be, pathname);
				bfd_util_compute_offset(bc, pointer_to_ulong(base));
				sopath = pathname;
			}
		}

		/*
		 * If we have a BFD context, try to locate the symbol attached
		 * to the PC, along with its source file location.
		 */

		ZERO(&loc);

		if (bc != NULL && bfd_util_has_symbols(bc)) {
			const void *call;

			/*
			 * Always move back two bytes because the return address is
			 * what we have on the stack, and we want the place where
			 * the call was made from a source code location perspective.
			 *
			 * It is assumed that the instruction to call a routine takes
			 * at least 2 bytes (opcode + relative offset / register).
			 * On the x86 for instance, "CALL EAX", which is used for (*f)(),
			 * takes 2 bytes.
			 */

			call = const_ptr_add_offset(pc, -2);
			located = bfd_util_locate(bc, call, &loc);

			if (!located) {
				/* A "CALL <address>" instruction is PTRSIZE+1 byte long */
				call = const_ptr_add_offset(pc, -(PTRSIZE + 1));
				located = bfd_util_locate(bc, call, &loc);
			}

			located_via_bfd = located;
		}

		/*
		 * If symbol was not located yet, try from our local symbol table,
		 * which will work if we are facing a symbol in our text segment
		 * and there are symbols present in the executable that we could load.
		 */

		if (!located && symbols != NULL) {
			const char *sym = symbols_name_only(symbols, pc, !gdb_like);

			if (sym != NULL) {
				loc.function = sym;
				located = TRUE;
			}
		}

		/*
		 * If we were not able to open the shared library, or it had no
		 * symbol available, we can try with the dynamic loader.  However,
		 * this can only provide us information about publicly available
		 * symbols, i.e. the symbols the dynamic loader must know about to
		 * be able to dynamically link the routines.
		 */

		if (!located) {
			const char *sym = dl_util_get_name(pc);

			if (sym != NULL) {
				const void *start = dl_util_get_start(pc);
				long disp;

				disp = (NULL == start) ? 0 : ptr_diff(pc, start);

				if (flags & STACKTRACE_F_MAIN_STOP)
					reached_main = 0 == strcmp(sym, "main");

				/*
				 * When not displaying a gdb-like trace, visually distinguish
				 * the names we resolve through the dynamic loader and the
				 * ones we resolve through symbols: all names between <> come
				 * from the dynamic loader's tables.
				 */

				if (gdb_like)
					str_bprintf(ARYLEN(name), "%s", sym);
				else if (0 == disp)
					str_bprintf(ARYLEN(name), "<%s>", sym);
				else
					str_bprintf(ARYLEN(name), "<%s%+ld>", sym, disp);
				sym = name;
			} else {
				if (symbols != NULL) {
					sym = symbols_name(symbols, pc, !gdb_like);
					if (flags & STACKTRACE_F_MAIN_STOP) {
						reached_main = 0 == strcmp(sym, "main") ||
							(!gdb_like && is_strprefix(sym, "main+"));
					}
				}
			}
			loc.function = sym;
		} else if (located_via_bfd) {
			/*
			 * Flag the BFD-recognized symbols with trailing parentheses, since
			 * there will be no trailing offset in that case, ever.
			 */

			if (flags & STACKTRACE_F_MAIN_STOP)
				reached_main = 0 == strcmp(loc.function, "main");

			str_bprintf(ARYLEN(name), "%s()", loc.function);
			has_parens = TRUE;
			loc.function = name;
		}

		/*
		 * Now foramt the information we gathered.
		 */

		str_reset(&s);

		if (NULL == loc.function)
			loc.function = "??";

		if (NULL == loc.file)
			loc.file = "??";

		if (0 == (flags & STACKTRACE_F_NO_INDENT))
			str_putc(&s, '\t');

		if (tid[0] != '\0')
			str_catf(&s, "%s", tid);

		if (0 != (flags & STACKTRACE_F_NUMBER)) {
			if (count < 10)
				str_catf(&s, "#%-1zu ", i);
			else if (count < 100)
				str_catf(&s, "#%-2zu ", i);
			else
				str_catf(&s, "#%-3zu ", i);
		}

		if (0 != (flags & STACKTRACE_F_ADDRESS)) {
			str_catf(&s, "0x%0*lx ", PTRSIZE * 2, pointer_to_ulong(pc));

			if (gdb_like)
				STR_CAT(&s, "in ");
		}

		str_cat(&s, loc.function);
		if ('0' == loc.function[0])		/* No valid name starts with a digit */
			has_parens = TRUE;			/* Avoid "()" after 0x.... names */

		if ('?' != loc.function[0] && gdb_like && !has_parens)
			STR_CAT(&s, "()");

		if (0 != (flags & STACKTRACE_F_SOURCE) && '?' != loc.file[0]) {
			str_cat(&s, gdb_like ? " at " : " \"");
			str_cat(&s, stacktrace_pretty_filepath(loc.file));
			if (loc.line != 0)
				str_catf(&s, ":%u", loc.line);
			if (!gdb_like)
				str_putc(&s, '"');
		}

		if (0 != (flags & STACKTRACE_F_ORIGIN) && !stack_is_our_text(pc)) {
			const char *filename = (flags & STACKTRACE_F_PATH) ?
				sopath : filepath_basename(sopath);
			if (gdb_like)
				str_catf(&s, " from %s", filename);
			else if ('?' != sopath[0]) {
				str_catf(&s, " : %s", filename);
			}
		}

		str_putc(&s, '\n');

		switch (xf->type) {
		case SXFILE_STDIO:
			atio_fwrite(str_2c(&s), str_len(&s), 1, xf->u.f);
			break;
		case SXFILE_FD:
			atio_write(xf->u.fd, str_2c(&s), str_len(&s));
			break;
		}
	}

	/*
	 * Flush output if we were writing via stdio.
	 */

	if (SXFILE_STDIO == xf->type)
		fflush(xf->u.f);

	/*
	 * Don't call
	 *
	 * 		bfd_util_close_null(&be);
	 *
	 * because when we are called, we may be crashing and then we won't
	 * release any memory anyway.  But if we start dumping a lot of stacks
	 * (for instance dumping memory leaks), we'll be using a lot of memory!
	 *
	 * Hence the strategy is to keep the BFD environment opened.
	 */

	errno = saved_errno;

	if (locked)
		STACKTRACE_SYM_UNLOCK;
}

/**
 * Convenience wrapper to print a decorated stack to a file descriptor.
 */
static void
stack_safe_print_decorated(int fd, int stid,
	void * const *stack, size_t count, int flags)
{
	struct sxfile xf;

	xf.type = SXFILE_FD;
	xf.stid = stid;
	xf.u.fd = fd;

	stack_print_decorated_to(&xf, stack, count, flags);
}

/**
 * Convenience wrapper to print a decorated stack to a FILE.
 */
static void
stack_print_decorated(FILE *f, int stid,
	void * const *stack, size_t count, int flags)
{
	struct sxfile xf;

	xf.type = SXFILE_STDIO;
	xf.stid = stid;
	xf.u.f = f;

	stack_print_decorated_to(&xf, stack, count, flags);
}

/**
 * Print stack trace to specified file, using symbolic names if possible.
 */
void
stacktrace_print(FILE *f, const struct stacktrace *st)
{
	g_assert(st != NULL);

	stack_print(f, st->stack, st->len);
}

/**
 * Print stack trace atom to specified file, using symbolic names if possible.
 */
void
stacktrace_atom_print(FILE *f, const struct stackatom *st)
{
	g_assert(st != NULL);

	stack_print(f, st->stack, st->len);
}

/**
 * Print decorated stack trace atom to specified file, using symbolic names
 * if possible.
 */
void
stacktrace_atom_decorate(FILE *f, const struct stackatom *st, uint flags)
{
	g_assert(st != NULL);

	stack_print_decorated(f, thread_small_id(), st->stack, st->len, flags);
}

/**
 * Log stack trace atom to logging agent, using symbolic names if possible.
 */
void
stacktrace_atom_log(logagent_t *la, const struct stackatom *st)
{
	g_assert(st != NULL);

	stack_log(la, st->stack, st->len);
}

/**
 * Get address of the n-th caller in the stack.
 *
 * With n = 0, this should be the address of the current routine.
 *
 * @return program counter of the n-th caller, NULL if it cannot be determined.
 */
const void *
stacktrace_caller(size_t n)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	g_assert(size_is_non_negative(n));
	g_assert(n <= STACKTRACE_DEPTH_MAX);

	count = stacktrace_unwind(stack, N_ITEMS(stack), 1);

	return n < count ? stack[n] : NULL;
}

/**
 * Return symbolic name of the n-th caller in the stack, if possible.
 *
 * With n = 0, this should be the current routine name.
 *
 * @return pointer to static data.  An empty name means there are not enough
 * items in the stack, "??" means that no symbols could be loaded so the
 * symbolic name is not available.
 */
const char *
stacktrace_caller_name(size_t n)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;
	bool in_sigh = signal_in_unsafe_handler();
	const char *name;

	g_assert(size_is_non_negative(n));
	g_assert(n <= STACKTRACE_DEPTH_MAX);

	count = stacktrace_unwind(stack, N_ITEMS(stack), 1);
	if (n >= count)
		return "";

	if (!in_sigh)
		stacktrace_load_symbols();

	if (NULL == symbols)
		return "??";

	name = symbols_name(symbols, stack[n], FALSE);

	/*
	 * Avoid all memory allocation if we are in a signal handler or
	 * crashing (where normally we are supposed to be running mono-threaded).
	 */

	if (!in_sigh && !thread_in_crash_mode())
		name = constant_str(name);

	return name;
}

/**
 * Return symbolic name of the routine to which a PC belongs.
 *
 * @param pc		the PC we're looking for
 * @param offset	whether we want additional offset within routine
 *
 * @return pointer to static data.  If symbols were not loaded or no matching
 * routine was found (the PC belongs to a shared library for instance), then
 * a formatted hexadecimal value is returned.
 */
const char *
stacktrace_routine_name(const void *pc, bool offset)
{
	const char *name;
	bool in_sigh = signal_in_unsafe_handler();

	if (!in_sigh)
		stacktrace_load_symbols();

	name = NULL == symbols ? NULL : symbols_name_only(symbols, pc, offset);

	/*
	 * This routine can be called from a signal handler.  We assume it will
	 * be safe to call dladdr() because that routine should not allocate
	 * memory but rather inspect the dynamic loader's tables.
	 *
	 * However we forbid ourselves to call the BFD library to resolve the
	 * name because that would force us to request to enter "crash mode" and
	 * memory allocation may not be safe anyway.
	 */

	if (NULL == name) {
		static bool computing[THREAD_MAX];
		int id = thread_safe_small_id();

		/*
		 * Prevent recursion through dl_util_get_name() in case we're very
		 * early in the process and not all the routines that need to be
		 * initialized have been properly setup.
		 *		--RAM, 2016-02-09
		 */

		if (id >= 0 && !computing[id]) {
			computing[id] = TRUE;
			name = dl_util_get_name(pc);
			computing[id] = FALSE;
		}
	}

	if (NULL == name) {
		static char buf[POINTER_BUFLEN];
		str_bprintf(ARYLEN(buf), "%p", pc);
		name = (in_sigh || thread_in_crash_mode()) ? buf : constant_str(buf);
	}

	return name;
}

/**
 * Return start of routine.
 *
 * @param pc		the PC within the routine
 *
 * @return start of the routine, NULL if we cannot find it.
 */
const void *
stacktrace_routine_start(const void *pc)
{
	if (!signal_in_unsafe_handler())
		stacktrace_load_symbols();

	return symbols_addr(symbols, pc);
}

/**
 * Print current stack trace to specified file.
 */
void
stacktrace_where_print(FILE *f)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), 1);
	stack_print(f, stack, count);
}

/**
 * @return whether we got any symbols.
 */
static bool
stacktrace_got_symbols(void)
{
	stacktrace_load_symbols();
	return symbols != NULL && 0 != symbols_count(symbols);
}

/**
 * Print current stack trace to specified file if symbols where loaded.
 */
void
stacktrace_where_sym_print(FILE *f)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;
	int stid;

	if (!stacktrace_got_symbols())
		return;		/* No symbols loaded */

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), 1);
	stid = thread_small_id();
	stack_print_decorated(f, stid, stack, count, STACKTRACE_DECORATION);
}

/**
 * Print current stack trace to specified file, with specified offset,
 * provided symbols were loaded.
 *
 * @param f			file where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void
stacktrace_where_sym_print_offset(FILE *f, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;
	int stid;

	if (!stacktrace_got_symbols())
		return;		/* No symbols loaded */

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), offset + 1);
	stid = thread_small_id();
	stack_print_decorated(f, stid, stack, count, STACKTRACE_DECORATION);
}

/**
 * Print current stack trace to specified file, with specified offset,
 * regardless of whether symbols were loaded.
 *
 * The stack trace is NOT decorated with line numbers.
 *
 * @param fd		file descriptor where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void
stacktrace_where_plain_print_offset(int fd, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), offset + 1);
	stack_safe_print(fd, thread_small_id(), stack, count);
}

/**
 * Print supplied trace to specified file as a plain symbolic stack,
 * if possible.
 *
 * @param fd		file descriptor where stack should be printed
 * @param stack		the stack trace
 * @param count		amount of items in stack
 */
void
stacktrace_stack_plain_print(int fd, void * const *stack, size_t count)
{
	stack_safe_print(fd, thread_small_id(), stack, count);
}

/**
 * Print supplied trace to specified file in fully decorated mode
 * if possible.
 *
 * @param fd		file descriptor where stack should be printed
 * @param stack		the stack trace
 * @param count		amount of items in stack
 */
void
stacktrace_stack_fancy_print(int fd, void * const *stack, size_t count)
{
	int stid = thread_small_id();
	stack_safe_print_decorated(fd, stid, stack, count, STACKTRACE_DECORATION);
}

/**
 * Safely print supplied trace to specified file as a symbolic stack,
 * if possible.
 *
 * Safety comes from the fact that this routine may be safely called from
 * a signal handler. However, symbolic names will not be loaded from the
 * executable if they haven't already and we're in a signal handler.
 *
 * @param fd		file descriptor where stack should be printed
 * @param stid		the thread ID to which the thread stack belongs
 * @param stack		the stack trace
 * @param count		amount of items in stack[]
 */
void
stacktrace_stack_safe_print(int fd, int stid, void * const *stack, size_t count)
{
	if (!signal_in_unsafe_handler()) {
		stacktrace_load_symbols();
		stack_safe_print_decorated(fd, stid,
			stack, count, STACKTRACE_DECORATION);
	} else if (signal_in_exception() && crash_is_supervised()) {
		/*
		 * We're crashing in supervised mode, so even if we get a fatal error
		 * our parent will be able to relaunch us.  We may not be able to
		 * get a core dumped correctly, so gather as much information as
		 * possible.
		 *
		 * There's no need to load the symbols because, since we're marked as
		 * supervised, it means we went through crash_init() and therefore
		 * the symbols were already loaded.
		 */

		stack_safe_print_decorated(fd, stid,
			stack, count, STACKTRACE_DECORATION);
	} else {
		stack_safe_print(fd, stid, stack, count);
	}
}

/**
 * Safely print current stack trace to specified file, with specified offset.
 *
 * Safety comes from the fact that this routine may be safely called from
 * a signal handler.  However, symbolic names will not be loaded from the
 * executable if they haven't already and we're in a signal handler.
 *
 * @param fd		file descriptor where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void
stacktrace_where_safe_print_offset(int fd, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), offset + 1);
	stacktrace_stack_safe_print(fd, thread_safe_small_id(), stack, count);
}

/**
 * Print supplied trace to specified file as a symbolic decorated stack,
 * if possible.
 *
 * This routine is NOT safe and could crash if called from a signal handler.
 *
 * @param fd		file descriptor where stack should be printed
 * @param stid		the thread ID to which the stack belongs
 * @param stack		the stack trace
 * @param count		amount of items in stack
 * @param flags		decoration flags (STACKTRACE_F_* values)
 */
void
stacktrace_stack_print_decorated(int fd, int stid,
	void * const *stack, size_t count, uint flags)
{
	stacktrace_load_symbols();
	stack_safe_print_decorated(fd, stid, stack, count, flags);
}

/**
 * Print decorated current stack trace to specified file.
 */
void
stacktrace_where_print_decorated(FILE *f, uint flags)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), 1);
	stacktrace_load_symbols();
	stack_print_decorated(f, thread_small_id(), stack, count, flags);
}

/**
 * Context for cautious stack printing, used in desperate situations
 * when we're about to crash anyway.
 */
static struct {
	int fd;
	sigjmp_buf env;
	unsigned done:1;
} print_context[THREAD_MAX];

/*
 * Was a cautious stacktrace already logged?
 */
bool
stacktrace_cautious_was_logged(void)
{
	int stid = thread_small_id();

	return print_context[stid].done;
}

/**
 * Invoked when a fatal signal is received during stack unwinding.
 */
static void G_COLD
stacktrace_got_signal(int signo)
{
	char time_buf[CRASH_TIME_BUFLEN];
	int stid;
	DECLARE_STR(4);

	stid = thread_small_id();

	crash_time(ARYLEN(time_buf));
	print_str(time_buf);
	print_str(" WARNING: got ");
	print_str(signal_name(signo));
	print_str(" during stack printing\n");
	flush_str(print_context[stid].fd);

	Siglongjmp(print_context[stid].env, signo);
}

/**
 * Print given stacktrace.
 *
 * Caution comes from the fact that we trap all SIGSEGV and other harmful
 * signals that could result from improper memory access during stack
 * unwinding (due to a corrupted stack) and printing (due to possible bugs
 * in our symbol mapping logic).
 *
 * @param fd		file descriptor where stack should be printed
 * @param stid		the thread ID to which stack belongs
 * @param stack		the stack to print
 * @param count		amount of valid stack entries in stack[]
 */
void G_COLD
stacktrace_cautious_print(int fd, int stid, void *stack[], size_t count)
{
	static volatile sig_atomic_t printing[THREAD_MAX];
	signal_handler_t old_sigsegv;
#ifdef SIGBUS
	signal_handler_t old_sigbus;
#endif

	if (printing[stid]) {
		char time_buf[CRASH_TIME_BUFLEN];
		char sbuf[UINT_DEC_BUFLEN];
		DECLARE_STR(7);

		crash_time(ARYLEN(time_buf));
		print_str(time_buf);						/* 0 */
		print_str(" (WARNING");						/* 1 */
		if (stid != 0) {
			print_str("-");							/* 2 */
			print_str(PRINT_NUMBER(sbuf, stid));	/* 3 */
		}
		print_str("): ignoring recursive");			/* 4 */
		print_str(G_STRFUNC);						/* 5 */
		print_str("() call\n");						/* 6 */
		flush_str(fd);
		return;
	}

	printing[stid] = TRUE;
	print_context[stid].fd = fd;

	/*
	 * Protect stack printing.
	 *
	 * Using signal_catch() instead of signal_set() because we don't need
	 * extra information about the signal context.
	 */

	old_sigsegv = signal_catch(SIGSEGV, stacktrace_got_signal);
#ifdef SIGBUS
	old_sigbus = signal_catch(SIGBUS, stacktrace_got_signal);
#endif

	if (Sigsetjmp(print_context[stid].env, TRUE)) {
		char time_buf[CRASH_TIME_BUFLEN];
		DECLARE_STR(2);

		crash_time(ARYLEN(time_buf));
		print_str(time_buf);
		print_str(" WARNING: truncated stack printing\n");
		flush_str(fd);
		goto restore;
	}

	if (0 == count) {
		char time_buf[CRASH_TIME_BUFLEN];
		DECLARE_STR(2);

		crash_time(ARYLEN(time_buf));
		print_str(time_buf);
		print_str(" WARNING: corrupted stack\n");
		flush_str(fd);
	} else {
		stacktrace_stack_safe_print(fd, stid, stack, count);
	}

	print_context[stid].done = TRUE;

restore:
	printing[stid] = FALSE;

	signal_set(SIGSEGV, old_sigsegv);
#ifdef SIGBUS
	signal_set(SIGBUS, old_sigbus);
#endif
}

/**
 * Like stacktrace_where_safe_print_offset() but with extra caution.
 *
 * Caution comes from the fact that we trap all SIGSEGV and other harmful
 * signals that could result from improper memory access during stack
 * unwinding (due to a corrupted stack) and printing (due to possible bugs
 * in our symbol mapping logic).
 *
 * @param fd		file descriptor where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void G_COLD
stacktrace_where_cautious_print_offset(int fd, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX + 5];	/* See stacktrace_unwind() */
	size_t count;
	int stid = thread_small_id();

	count = stacktrace_safe_unwind(stack, N_ITEMS(stack), offset + 1);

	stacktrace_cautious_print(fd, stid, stack, count);
}

/**
 * Hashing routine for a "struct stacktrace".
 */
unsigned
stack_hash(const void *key)
{
	const struct stackatom *sa = key;

	if (0 == sa->len)
		return 0;

	return binary_hash(sa->stack, sa->len * sizeof sa->stack[0]);
}

/**
 * Comparison of two "struct stacktrace" structures.
 */
int
stack_eq(const void *a, const void *b)
{
	const struct stackatom *sa = a, *sb = b;

	return sa->len == sb->len &&
		0 == memcmp(sa->stack, sb->stack, sa->len * sizeof sa->stack[0]);
}

/*
 * Adjust the length of the stack: any trailing address not belonging
 * to our text segment is that of shared libraries, i.e. not code for
 * which we have symbols.
 *
 * By chopping these trailing addresses off, we keep only the relevant
 * parts and also considerably limit the amount of stack atoms we have
 * to keep around during a session (since this memory is never freed).
 *
 * @param st		full stacktrace
 *
 * @return amount of topmost items we should keep in the stack.
 */
static size_t
stacktrace_chop_length(const struct stacktrace *st)
{
	size_t i;

	/*
	 * Until they called stacktrace_init(), we don't know whether we're
	 * running as part of a statically linked program or whether the whole
	 * program is held in shared libraries, the main() entry point being
	 * just there to load the initial shared libraray.
	 *
	 * This means stack_is_our_text() is unsafe.
	 *
	 * NB: This is only really needed when this library is used outside
	 * of gtk-gnutella.  The whole gtk-gnutella code is statically linked,
	 * and we know it calls stacktrace_init().
	 *		--RAM, 2012-05-11
	 */

	if (!stacktrace_inited)
		return st->len;

	for (i = st->len; i != 0; i--) {
		if (stack_is_our_text(st->stack[i - 1])) {
			break;		/* Last addres is our text, keep it */
		}
	}

	return i;
}

/**
 * Initialize the stack atom table.
 */
static void
stacktrace_atom_init(void)
{
	g_assert(NULL == stack_atoms);

	stack_atoms = hash_table_new_full_real(stack_hash, stack_eq);
	hash_table_thread_safe(stack_atoms);
}

/**
 * Lookup stacktrace in our circular buffer to see whether we already
 * have it, and possibly store it there.
 *
 * @param st		full stacktrace
 * @param len		amount of topmost items to consider from stack
 *
 * @return TRUE if we had a match.
 */
static bool
stacktrace_atom_lookup_and_store(const struct stacktrace *st, size_t len)
{
	uint i;
	const struct stacktrace *ct = &stacktrace_atom_buffer.circular[0];

	/*
	 * If the buffer is not marked dirty, then there is nothing to look for.
	 */

	if (!stacktrace_atom_buffer.dirty)
		goto insert;

	for (i = 0; i < N_ITEMS(stacktrace_atom_buffer.circular); i++, ct++) {
		size_t n = MIN(ct->len, len);

		if (0 == n)
			continue;

		if (0 == memcmp(&ct->stack[0], &st->stack[0], n * sizeof st->stack[0]))
			return TRUE;
	}

insert:

	/*
	 * No match found, need to record new entry, possibly superseding an
	 * older one (we do not maintain the buffer in an LRU way) for simplicity.
	 *
	 * Indeed, we're managing the circular buffer without locking, counting
	 * on the atomicity of the index increment and the size of the buffer
	 * to avoid two threads filling up the same entry.
	 */

	i = atomic_uint_inc(&stacktrace_atom_buffer.idx);
	i %= STACKTRACE_CIRCULAR_LEN;

	stacktrace_atom_buffer.dirty = TRUE;
	stacktrace_atom_buffer.circular[i].len = 0;		/* Invalid */
	atomic_mb();

	memcpy(&stacktrace_atom_buffer.circular[i].stack,
		&st->stack, len * sizeof st->stack[0]);

	stacktrace_atom_buffer.circular[i].len = len;	/* Now valid */
	atomic_mb();

	return FALSE;
}

/**
 * Lookup stacktrace to see whether we already have an atom for it.
 *
 * @param st		full stacktrace
 * @param len		amount of topmost items to consider from stack
 *
 * @return stack atom if we have one, NULL if it is unknown.
 */
static struct stackatom *
stacktrace_atom_lookup(const struct stacktrace *st, size_t len)
{
	struct stackatom key;
	struct stackatom *result;

	STATIC_ASSERT(sizeof st->stack[0] == sizeof result->stack[0]);

	ONCE_FLAG_RUN(stacktrace_atom_inited, stacktrace_atom_init);

	key.stack = deconstify_pointer(st->stack);
	key.len = len;

	return hash_table_lookup(stack_atoms, &key);
}

/**
 * Allocate and record a new stack trace atom from given stacktrace.
 *
 * @return read-only atom object.
 */
static const struct stackatom *
stacktrace_atom_record(const struct stacktrace *st, size_t len)
{
	const struct stackatom *result;
	struct stackatom local;

	assert_stacktrace_atom_locked();

	/* These objects will be never freed */
	if (len != 0) {
		const void *p = ocopy_readonly(st->stack, len * sizeof st->stack[0]);
		local.stack = deconstify_pointer(p);
	} else {
		local.stack = NULL;
	}
	local.len = len;

	result = ocopy_readonly(VARLEN(local));

	if (!hash_table_insert(stack_atoms, result, result))
		g_error("cannot record stack trace atom");

	return result;
}

/**
 * Insert given stack trace as an atom into the stack_atoms table if it does
 * not already exist there.
 *
 * @return the stack atom.
 */
static const struct stackatom *
stacktrace_atom_insert(const struct stacktrace *t, size_t len)
{
	const struct stackatom *item;

	STACKTRACE_ATOM_LOCK;
	item = stacktrace_atom_lookup(t, len);
	if (NULL == item)
		item = stacktrace_atom_record(t, len);
	STACKTRACE_ATOM_UNLOCK;

	return item;
}

/**
 * Get a stack trace atom (read-only, never freed).
 */
const struct stackatom *
stacktrace_get_atom(const struct stacktrace *st)
{
	const struct stackatom *result;
	size_t len;

	len = stacktrace_chop_length(st);
	result = stacktrace_atom_lookup(st, len);

	if G_UNLIKELY(NULL == result)
		result = stacktrace_atom_insert(st, len);

	return result;
}

/**
 * Move stacktrace entries in the circular buffer back to the atom table.
 *
 * The circular buffer is filled when stacktrace atom lookups are performed
 * whilst running in a signal handler (for asynchronous signals received).
 *
 * Once the signal handler processing is completed, this routine can be
 * called to possibly record the items stored in the table, if any, since
 * memory allocation is mostly forbidden during signal processing.
 */
void
stacktrace_atom_circular_flush(void)
{
	uint original_idx, i, j;

	if (signal_in_unsafe_handler())
		return;

	if (!stacktrace_atom_buffer.dirty)
		return;

	ONCE_FLAG_RUN(stacktrace_atom_inited, stacktrace_atom_init);

	i = original_idx = atomic_uint_get(&stacktrace_atom_buffer.idx);

	for (j = 0; j < N_ITEMS(stacktrace_atom_buffer.circular); j++, i++) {
		uint old_idx, new_idx;
		struct stacktrace *st, cst;

		i %= STACKTRACE_CIRCULAR_LEN;
		st = &stacktrace_atom_buffer.circular[i];
		if (0 == st->len)
			continue;

		old_idx = atomic_uint_get(&stacktrace_atom_buffer.idx);
		cst = *st;		/* Struct copy */
		st->len = 0;	/* Invalidate entry */
		new_idx = atomic_uint_get(&stacktrace_atom_buffer.idx);

		if (0 == cst.len)
			continue;

		/*
		 * If the index changed, it means someone entered a new entry in
		 * the circular buffer.  Hence we need to check whether the copy
		 * we made is valid.
		 */

		if G_UNLIKELY(old_idx != new_idx) {
			uint d = new_idx - old_idx;
			uint oi, ni;

			if G_UNLIKELY(d >= N_ITEMS(stacktrace_atom_buffer.circular))
				continue;		/* We wrapped around, copy is probably bad */

			/*
			 * Does the change of index encompass the slot we copied above?
			 */

			oi = old_idx % STACKTRACE_CIRCULAR_LEN;
			ni = new_idx % STACKTRACE_CIRCULAR_LEN;

			if (ni < oi)
				ni += STACKTRACE_CIRCULAR_LEN;

			if (oi <= i && i <= ni)
				continue;		/* Unfortunately, it does, so skip slot */
		}

		/*
		 * Good, we have a new entry.
		 */

		stacktrace_atom_insert(&cst, cst.len);
	}

	if (atomic_uint_get(&stacktrace_atom_buffer.idx) == original_idx)
		stacktrace_atom_buffer.dirty = FALSE;	/* Flushed everything */
}

/**
 * Check whether current stack is known, recording it as a side effect.
 *
 * This can be used to emit warnings once for a given calling stack.
 * The allocated objects are never freed so this should rather be used
 * for uncommon paths, which warning paths are.
 *
 * @param offset		additional stackframes to skip
 *
 * @return whether calling stack was known
 */
bool
stacktrace_caller_known(size_t offset)
{
	struct stacktrace t;
	size_t len;
	struct stackatom *result;

	stacktrace_get_offset(&t, offset + 1);	/* Skip ourselves */
	len = stacktrace_chop_length(&t);

	if G_UNLIKELY(0 == len)
		return FALSE;

	if G_LIKELY(ONCE_DONE(stacktrace_atom_inited))
		result = stacktrace_atom_lookup(&t, len);
	else
		result = NULL;

	if G_UNLIKELY(NULL == result) {

		/*
		 * If we are running in a signal handler, we cannot allocate
		 * memory hence use a circular buffer to store the stacks until
		 * it is safe to re-insert them into the table.
		 */

		if (signal_in_unsafe_handler())
			return stacktrace_atom_lookup_and_store(&t, len);

		ONCE_FLAG_RUN(stacktrace_atom_inited, stacktrace_atom_init);

		stacktrace_atom_insert(&t, len);
		return FALSE;
	} else {
		return TRUE;
	}
}

/***
 *** Low-level stack unwinding routines.
 ***
 *** The following routines rely on GCC internal macros, which are expanded
 *** at compile-time (hence the parameter must be specified explicitly and
 *** cannot be a variable).
 ***
 *** The advantage is that this is portable accross all architectures where
 *** GCC is available.
 ***
 *** The disadvantage is that GCC is required and the stack trace maximum
 *** size is constrained by the number of cases handled.
 ***
 *** Note that each GCC macro expansion yields the necessary assembly code to
 *** reach the given stackframe preceding the current frame, and therefore
 *** the code growth is exponential.  Handling 128 stack frames at most
 *** should be sufficient for our needs here, since we never need to unwind
 *** the stack back to main().
 ***
 ***		--RAM, 2010-10-24
 ***/

/*
 * getreturnaddr() and getframeaddr() are:
 *
 * Copyright (c) 2003 Maxim Sobolev <sobomax@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $X-Id: execinfo.c,v 1.3 2004/07/19 05:21:09 sobomax Exp $
 *
 * Changes were made to make these routines work on Windows under MinGW:
 *
 * Instead of having getreturnaddr(0) return __builtin_return_address(1),
 * it now returns __builtin_return_address(0).  Similar changes were made
 * to getframeaddr().  Moreover, the maximum level handled in the switch
 * is now 132, to cope with necessary offsetting required by user code
 * which uses an extra layer of functions to access stacktrace_unwind().
 *
 * In order to work correctly, the proper stack offsetting must be computed
 * at run-time.  See stacktrace_auto_tune().
 */

#ifndef MINGW32

#if HAS_GCC(3, 0)
static void *
getreturnaddr(size_t level)
{
    switch (level) {
	case 0:		return __builtin_return_address(0);
	case 1:		return __builtin_return_address(1);
	case 2:		return __builtin_return_address(2);
	case 3:		return __builtin_return_address(3);
	case 4:		return __builtin_return_address(4);
	case 5:		return __builtin_return_address(5);
	case 6:		return __builtin_return_address(6);
	case 7:		return __builtin_return_address(7);
	case 8:		return __builtin_return_address(8);
	case 9:		return __builtin_return_address(9);
	case 10:	return __builtin_return_address(10);
	case 11:	return __builtin_return_address(11);
	case 12:	return __builtin_return_address(12);
	case 13:	return __builtin_return_address(13);
	case 14:	return __builtin_return_address(14);
	case 15:	return __builtin_return_address(15);
	case 16:	return __builtin_return_address(16);
	case 17:	return __builtin_return_address(17);
	case 18:	return __builtin_return_address(18);
	case 19:	return __builtin_return_address(19);
	case 20:	return __builtin_return_address(20);
	case 21:	return __builtin_return_address(21);
	case 22:	return __builtin_return_address(22);
	case 23:	return __builtin_return_address(23);
	case 24:	return __builtin_return_address(24);
	case 25:	return __builtin_return_address(25);
	case 26:	return __builtin_return_address(26);
	case 27:	return __builtin_return_address(27);
	case 28:	return __builtin_return_address(28);
	case 29:	return __builtin_return_address(29);
	case 30:	return __builtin_return_address(30);
	case 31:	return __builtin_return_address(31);
	case 32:	return __builtin_return_address(32);
	case 33:	return __builtin_return_address(33);
	case 34:	return __builtin_return_address(34);
	case 35:	return __builtin_return_address(35);
	case 36:	return __builtin_return_address(36);
	case 37:	return __builtin_return_address(37);
	case 38:	return __builtin_return_address(38);
	case 39:	return __builtin_return_address(39);
	case 40:	return __builtin_return_address(40);
	case 41:	return __builtin_return_address(41);
	case 42:	return __builtin_return_address(42);
	case 43:	return __builtin_return_address(43);
	case 44:	return __builtin_return_address(44);
	case 45:	return __builtin_return_address(45);
	case 46:	return __builtin_return_address(46);
	case 47:	return __builtin_return_address(47);
	case 48:	return __builtin_return_address(48);
	case 49:	return __builtin_return_address(49);
	case 50:	return __builtin_return_address(50);
	case 51:	return __builtin_return_address(51);
	case 52:	return __builtin_return_address(52);
	case 53:	return __builtin_return_address(53);
	case 54:	return __builtin_return_address(54);
	case 55:	return __builtin_return_address(55);
	case 56:	return __builtin_return_address(56);
	case 57:	return __builtin_return_address(57);
	case 58:	return __builtin_return_address(58);
	case 59:	return __builtin_return_address(59);
	case 60:	return __builtin_return_address(60);
	case 61:	return __builtin_return_address(61);
	case 62:	return __builtin_return_address(62);
	case 63:	return __builtin_return_address(63);
	case 64:	return __builtin_return_address(64);
	case 65:	return __builtin_return_address(65);
	case 66:	return __builtin_return_address(66);
	case 67:	return __builtin_return_address(67);
	case 68:	return __builtin_return_address(68);
	case 69:	return __builtin_return_address(69);
	case 70:	return __builtin_return_address(70);
	case 71:	return __builtin_return_address(71);
	case 72:	return __builtin_return_address(72);
	case 73:	return __builtin_return_address(73);
	case 74:	return __builtin_return_address(74);
	case 75:	return __builtin_return_address(75);
	case 76:	return __builtin_return_address(76);
	case 77:	return __builtin_return_address(77);
	case 78:	return __builtin_return_address(78);
	case 79:	return __builtin_return_address(79);
	case 80:	return __builtin_return_address(80);
	case 81:	return __builtin_return_address(81);
	case 82:	return __builtin_return_address(82);
	case 83:	return __builtin_return_address(83);
	case 84:	return __builtin_return_address(84);
	case 85:	return __builtin_return_address(85);
	case 86:	return __builtin_return_address(86);
	case 87:	return __builtin_return_address(87);
	case 88:	return __builtin_return_address(88);
	case 89:	return __builtin_return_address(89);
	case 90:	return __builtin_return_address(90);
	case 91:	return __builtin_return_address(91);
	case 92:	return __builtin_return_address(92);
	case 93:	return __builtin_return_address(93);
	case 94:	return __builtin_return_address(94);
	case 95:	return __builtin_return_address(95);
	case 96:	return __builtin_return_address(96);
	case 97:	return __builtin_return_address(97);
	case 98:	return __builtin_return_address(98);
	case 99:	return __builtin_return_address(99);
	case 100:	return __builtin_return_address(100);
	case 101:	return __builtin_return_address(101);
	case 102:	return __builtin_return_address(102);
	case 103:	return __builtin_return_address(103);
	case 104:	return __builtin_return_address(104);
	case 105:	return __builtin_return_address(105);
	case 106:	return __builtin_return_address(106);
	case 107:	return __builtin_return_address(107);
	case 108:	return __builtin_return_address(108);
	case 109:	return __builtin_return_address(109);
	case 110:	return __builtin_return_address(110);
	case 111:	return __builtin_return_address(111);
	case 112:	return __builtin_return_address(112);
	case 113:	return __builtin_return_address(113);
	case 114:	return __builtin_return_address(114);
	case 115:	return __builtin_return_address(115);
	case 116:	return __builtin_return_address(116);
	case 117:	return __builtin_return_address(117);
	case 118:	return __builtin_return_address(118);
	case 119:	return __builtin_return_address(119);
	case 120:	return __builtin_return_address(120);
	case 121:	return __builtin_return_address(121);
	case 122:	return __builtin_return_address(122);
	case 123:	return __builtin_return_address(123);
	case 124:	return __builtin_return_address(124);
	case 125:	return __builtin_return_address(125);
	case 126:	return __builtin_return_address(126);
	case 127:	return __builtin_return_address(127);
	case 128:	return __builtin_return_address(128);
	case 129:	return __builtin_return_address(129);
	case 130:	return __builtin_return_address(130);
	case 131:	return __builtin_return_address(131);
	case 132:	return __builtin_return_address(132);
    default:	return NULL;
    }
}

static void *
getframeaddr(size_t level)
{
    switch (level) {
	case 0:		return __builtin_frame_address(0);
	case 1:		return __builtin_frame_address(1);
	case 2:		return __builtin_frame_address(2);
	case 3:		return __builtin_frame_address(3);
	case 4:		return __builtin_frame_address(4);
	case 5:		return __builtin_frame_address(5);
	case 6:		return __builtin_frame_address(6);
	case 7:		return __builtin_frame_address(7);
	case 8:		return __builtin_frame_address(8);
	case 9:		return __builtin_frame_address(9);
	case 10:	return __builtin_frame_address(10);
	case 11:	return __builtin_frame_address(11);
	case 12:	return __builtin_frame_address(12);
	case 13:	return __builtin_frame_address(13);
	case 14:	return __builtin_frame_address(14);
	case 15:	return __builtin_frame_address(15);
	case 16:	return __builtin_frame_address(16);
	case 17:	return __builtin_frame_address(17);
	case 18:	return __builtin_frame_address(18);
	case 19:	return __builtin_frame_address(19);
	case 20:	return __builtin_frame_address(20);
	case 21:	return __builtin_frame_address(21);
	case 22:	return __builtin_frame_address(22);
	case 23:	return __builtin_frame_address(23);
	case 24:	return __builtin_frame_address(24);
	case 25:	return __builtin_frame_address(25);
	case 26:	return __builtin_frame_address(26);
	case 27:	return __builtin_frame_address(27);
	case 28:	return __builtin_frame_address(28);
	case 29:	return __builtin_frame_address(29);
	case 30:	return __builtin_frame_address(30);
	case 31:	return __builtin_frame_address(31);
	case 32:	return __builtin_frame_address(32);
	case 33:	return __builtin_frame_address(33);
	case 34:	return __builtin_frame_address(34);
	case 35:	return __builtin_frame_address(35);
	case 36:	return __builtin_frame_address(36);
	case 37:	return __builtin_frame_address(37);
	case 38:	return __builtin_frame_address(38);
	case 39:	return __builtin_frame_address(39);
	case 40:	return __builtin_frame_address(40);
	case 41:	return __builtin_frame_address(41);
	case 42:	return __builtin_frame_address(42);
	case 43:	return __builtin_frame_address(43);
	case 44:	return __builtin_frame_address(44);
	case 45:	return __builtin_frame_address(45);
	case 46:	return __builtin_frame_address(46);
	case 47:	return __builtin_frame_address(47);
	case 48:	return __builtin_frame_address(48);
	case 49:	return __builtin_frame_address(49);
	case 50:	return __builtin_frame_address(50);
	case 51:	return __builtin_frame_address(51);
	case 52:	return __builtin_frame_address(52);
	case 53:	return __builtin_frame_address(53);
	case 54:	return __builtin_frame_address(54);
	case 55:	return __builtin_frame_address(55);
	case 56:	return __builtin_frame_address(56);
	case 57:	return __builtin_frame_address(57);
	case 58:	return __builtin_frame_address(58);
	case 59:	return __builtin_frame_address(59);
	case 60:	return __builtin_frame_address(60);
	case 61:	return __builtin_frame_address(61);
	case 62:	return __builtin_frame_address(62);
	case 63:	return __builtin_frame_address(63);
	case 64:	return __builtin_frame_address(64);
	case 65:	return __builtin_frame_address(65);
	case 66:	return __builtin_frame_address(66);
	case 67:	return __builtin_frame_address(67);
	case 68:	return __builtin_frame_address(68);
	case 69:	return __builtin_frame_address(69);
	case 70:	return __builtin_frame_address(70);
	case 71:	return __builtin_frame_address(71);
	case 72:	return __builtin_frame_address(72);
	case 73:	return __builtin_frame_address(73);
	case 74:	return __builtin_frame_address(74);
	case 75:	return __builtin_frame_address(75);
	case 76:	return __builtin_frame_address(76);
	case 77:	return __builtin_frame_address(77);
	case 78:	return __builtin_frame_address(78);
	case 79:	return __builtin_frame_address(79);
	case 80:	return __builtin_frame_address(80);
	case 81:	return __builtin_frame_address(81);
	case 82:	return __builtin_frame_address(82);
	case 83:	return __builtin_frame_address(83);
	case 84:	return __builtin_frame_address(84);
	case 85:	return __builtin_frame_address(85);
	case 86:	return __builtin_frame_address(86);
	case 87:	return __builtin_frame_address(87);
	case 88:	return __builtin_frame_address(88);
	case 89:	return __builtin_frame_address(89);
	case 90:	return __builtin_frame_address(90);
	case 91:	return __builtin_frame_address(91);
	case 92:	return __builtin_frame_address(92);
	case 93:	return __builtin_frame_address(93);
	case 94:	return __builtin_frame_address(94);
	case 95:	return __builtin_frame_address(95);
	case 96:	return __builtin_frame_address(96);
	case 97:	return __builtin_frame_address(97);
	case 98:	return __builtin_frame_address(98);
	case 99:	return __builtin_frame_address(99);
	case 100:	return __builtin_frame_address(100);
	case 101:	return __builtin_frame_address(101);
	case 102:	return __builtin_frame_address(102);
	case 103:	return __builtin_frame_address(103);
	case 104:	return __builtin_frame_address(104);
	case 105:	return __builtin_frame_address(105);
	case 106:	return __builtin_frame_address(106);
	case 107:	return __builtin_frame_address(107);
	case 108:	return __builtin_frame_address(108);
	case 109:	return __builtin_frame_address(109);
	case 110:	return __builtin_frame_address(110);
	case 111:	return __builtin_frame_address(111);
	case 112:	return __builtin_frame_address(112);
	case 113:	return __builtin_frame_address(113);
	case 114:	return __builtin_frame_address(114);
	case 115:	return __builtin_frame_address(115);
	case 116:	return __builtin_frame_address(116);
	case 117:	return __builtin_frame_address(117);
	case 118:	return __builtin_frame_address(118);
	case 119:	return __builtin_frame_address(119);
	case 120:	return __builtin_frame_address(120);
	case 121:	return __builtin_frame_address(121);
	case 122:	return __builtin_frame_address(122);
	case 123:	return __builtin_frame_address(123);
	case 124:	return __builtin_frame_address(124);
	case 125:	return __builtin_frame_address(125);
	case 126:	return __builtin_frame_address(126);
	case 127:	return __builtin_frame_address(127);
	case 128:	return __builtin_frame_address(128);
	case 129:	return __builtin_frame_address(129);
	case 130:	return __builtin_frame_address(130);
	case 131:	return __builtin_frame_address(131);
	case 132:	return __builtin_frame_address(132);
    default:	return NULL;
    }
}
#else	/* !GCC >= 3.0 */
static void *
getreturnaddr(size_t level)
{
	(void) level;
	return NULL;
}

static void *
getframeaddr(size_t level)
{
	(void) level;
	return NULL;
}
#endif	/* GCC >= 3.0 */

#endif	/* !MINGW32 */

/* vi: set ts=4 sw=4 cindent:  */
