/*
 * Copyright (c) 2004, 2010, Raphael Manfredi
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
 * Stack unwinding support.
 *
 * This file is using raw malloc(), free(), strdup(), etc... because it can
 * be exercised by the debugging malloc layer, at a very low level and we
 * must not interfere.  Don't even think about using g_malloc() and friends or
 * any other glib memory-allocating routine here.
 *
 * This means this file cannot be the target of leak detection by our
 * debugging malloc layer.
 *
 * @author Raphael Manfredi
 * @date 2004, 2010
 */

#include "common.h"		/* For RCSID */

#include "stacktrace.h"
#include "atoms.h"		/* For binary_hash() */
#include "ascii.h"
#include "base16.h"
#include "crash.h"		/* For print_str() and crash_signame() */
#include "file.h"
#include "glib-missing.h"
#include "halloc.h"
#include "log.h"
#include "offtime.h"
#include "omalloc.h"
#include "parse.h"
#include "path.h"
#include "signal.h"
#include "stringify.h"
#include "tm.h"
#include "unsigned.h"
#include "vmm.h"

/* We need hash_table_new_real() to avoid any call to g_malloc() */
#define MALLOC_SOURCE
#include "hashtable.h"
#undef MALLOC_SOURCE

#include "override.h"	/* Must be the last header included */

#ifdef I_EXECINFO
#include <execinfo.h>	/* For backtrace() */
#endif

/**
 * A routine entry in the symbol table.
 */
struct trace {
	const void *start;			/**< Start PC address */
	const char *name;			/**< Routine name (omalloc() atom) */
};

/**
 * The array of trace entries.
 */
static struct {
	struct trace *base;			/**< Array base */
	size_t size;				/**< Amount of entries allocated */
	size_t count;				/**< Amount of entries held */
	size_t offset;				/**< Symbol offset to apply */
	unsigned fresh:1;			/**< Symbols loaded via nm parsing */
	unsigned indirect:1;		/**< Symbols loaded via nm pre-computed file */
	unsigned stale:1;			/**< Pre-computed nm file was stale */
	unsigned mismatch:1;		/**< Symbol mismatches were identified */
	unsigned garbage:1;			/**< Symbols are probably pure garbage */
	unsigned sorted:1;			/**< Symbols were sorted */
} trace_array;

/**
 * Deferred loading support.
 */
static char *local_path;		/**< Path before a chdir() */
static char *program_path;		/**< Absolute program path */
static time_t program_mtime;	/**< Last modification time of executable */
static gboolean symbols_loaded;

/**
 * "nm" output parsing context.
 */
struct nm_parser {
	hash_table_t *atoms;		/**< To create string "atoms" */
};

/**
 * Auto-tuning stack trace offset.
 *
 * On some platforms, the level of offsetting we have to do to the stack
 * varies.  This variable contains the additionnal stack offsetting we have
 * to do.
 */
static size_t stack_auto_offset;

static hash_table_t *stack_atoms;
static const char NM_FILE[] = "gtk-gnutella.nm";

#ifndef HAS_BACKTRACE
static void *getreturnaddr(size_t level);
static void *getframeaddr(size_t level);
#endif

/**
 * Unwind current stack into supplied stacktrace array.
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
	void *trace[STACKTRACE_DEPTH_MAX + 5];	/* +5 to leave room for offsets */
	int depth;
    size_t amount;		/* Amount of entries we can copy in result */
	size_t idx;

	g_assert(size_is_non_negative(offset));

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

	if (count >= G_N_ELEMENTS(trace)) {
		depth = backtrace(stack, G_N_ELEMENTS(trace));
		memcpy(trace, stack, depth * sizeof trace[0]);
	} else {
		depth = backtrace(trace, G_N_ELEMENTS(trace));
	}
	idx = size_saturate_add(offset, stack_auto_offset);

	g_assert(size_is_non_negative(idx));

	if (UNSIGNED(depth) <= idx)
		return 0;

	amount = idx - UNSIGNED(depth);
	amount = MIN(amount, count);
	memcpy(stack, &trace[idx], amount * sizeof trace[0]);

	return amount;
}
#else	/* !HAS_BACKTRACE */
{
    size_t i;
	void *frame;
	size_t d;
	gboolean increasing;

	/*
	 * Adjust the offset according to the auto-tunings.
	 */

	offset = size_saturate_add(offset, stack_auto_offset);

	/*
	 * Go carefully to stack frame "offset", in case the stack is
	 * currently corrupted.
	 */

	frame = getframeaddr(0);
	if (NULL == frame)
		return 0;

	d = ptr_diff(getframeaddr(1), frame);
	increasing = size_is_positive(d);

	for (i = 0; i < offset; i++) {
		void *nframe = getframeaddr(i + 1);

		if (NULL == nframe)
			return 0;

		d = increasing ? ptr_diff(nframe, frame) : ptr_diff(frame, nframe);
		if (d > 0x1000)		/* Arbitrary, large enough to be uncommon */
			return 0;

		frame = nframe;
	}

	/*
	 * At this point, i == offset and frame == getframeaddr(offset).
	 */

	for (;; i++) {
		void *nframe = getframeaddr(i + 1);

		if (NULL == nframe || i - offset >= count)
			break;

        if (NULL == (stack[i - offset] = getreturnaddr(i)))
			break;

		/*
		 * Safety precaution: if the distance between one frame and the
		 * next is too large, we're probably facing stack corruption and
		 * are beginning to hit random places in memory.  Break out.
		 */

		d = increasing ? ptr_diff(nframe, frame) : ptr_diff(frame, nframe);
		if (d > 0x1000)		/* Arbitrary, large enough to be uncommon */
			break;
		frame = nframe;
	}

	return i - offset;
}
#endif	/* HAS_BACKTRACE */

/**
 * Compare two trace entries -- qsort() callback.
 */
static int
trace_cmp(const void *p, const void *q)
{
	struct trace const *a = p;
	struct trace const *b = q;

	return a->start == b->start ? 0 :
		pointer_to_ulong(a->start) < pointer_to_ulong(b->start) ? -1 : +1;
}

/**
 * Remove duplicate entry in trace array at the specified index.
 */
static void
trace_remove(size_t i)
{
	struct trace *t;

	g_assert(size_is_non_negative(i));
	g_assert(i < trace_array.count);

	t = &trace_array.base[i];
	if (i < trace_array.count - 1)
		memmove(t, t + 1, (trace_array.count - i - 1) * sizeof *t);
	trace_array.count--;
}

/**
 * Sort trace array, remove duplicate entries.
 */
static G_GNUC_COLD void
trace_sort(void)
{
	size_t i = 0;
	size_t old_count = trace_array.count;
	const void *last = 0;

	qsort(trace_array.base, trace_array.count,
		sizeof trace_array.base[0], trace_cmp);

	while (i < trace_array.count) {
		struct trace *t = &trace_array.base[i];
		if (last && t->start == last) {
			trace_remove(i);
		} else {
			last = t->start;
			i++;
		}
	}

	if (old_count != trace_array.count) {
		size_t delta = old_count - trace_array.count;
		g_assert(size_is_non_negative(delta));
		s_warning("stripped %lu duplicate symbol%s",
			(unsigned long) delta, 1 == delta ? "" : "s");
	}

	trace_array.sorted = TRUE;
}

/**
 * Insert new trace symbol.
 */
static void
trace_insert(const void *start, const char *name)
{
	struct trace *t;

	if (trace_array.count >= trace_array.size) {
		size_t old_size, new_size;
		void *old_base;

		old_base = trace_array.base;
		old_size = trace_array.size * sizeof *t;
		trace_array.size += 1024;
		new_size = trace_array.size * sizeof *t;

		trace_array.base = vmm_alloc_not_leaking(new_size);
		if (old_base != NULL) {
			memcpy(trace_array.base, old_base, old_size);
			vmm_free(old_base, old_size);
		}
	}

	t = &trace_array.base[trace_array.count++];
	t->start = start;
	t->name = name;
}

/**
 * Lookup trace structure encompassing given program counter.
 *
 * @return trace structure if found, NULL otherwise.
 */
static struct trace *
trace_lookup(const void *pc)
{
	struct trace *low = trace_array.base,
				 *high = &trace_array.base[trace_array.count -1],
				 *mid;
	const void *lpc;

	lpc = const_ptr_add_offset(pc, trace_array.offset);

	while (low <= high) {
		mid = low + (high - low) / 2;
		if (lpc >= mid->start && (mid == high || lpc < (mid+1)->start))
			return mid;			/* Found it! */
		else if (lpc < mid->start)
			high = mid - 1;
		else
			low = mid + 1;
	}

	return NULL;				/* Not found */
}

/**
 * Format pointer into specified buffer.
 *
 * This is equivalent to saying:
 *
 *    gm_snprintf(buf, buflen, "0x%lx", pointer_to_ulong(pc));
 *
 * but is safe to use in a signal handler.
 */
static void
trace_fmt_pointer(char *buf, size_t buflen, const void *p)
{
	if (buflen < 4) {
		buf[0] = '\0';
		return;
	}

	buf[0] = '0';
	buf[1] = 'x';
	pointer_to_string_buf(p, &buf[2], buflen - 2);
}

/**
 * Format "name+offset" into specified buffer.
 *
 * This is equivalent to saying:
 *
 *    gm_snprintf(buf, buflen, "%s+%u", name, offset);
 *
 * but is safe to use in a signal handler.
 */
static void
trace_fmt_name(char *buf, size_t buflen, const char *name, size_t offset)
{
	size_t namelen;

	namelen = g_strlcpy(buf, name, buflen);
	if (namelen >= buflen - 2)
		return;

	if (offset != 0) {
		buf[namelen] = '+';
		size_t_to_string_buf(offset, &buf[namelen+1], buflen - (namelen + 1));
	}
}

/*
 * Attempt to transform a PC (Program Counter) address into a symbolic name,
 * showing the function name and the offset within that routine.
 *
 * When the symbols are probable garbage, the name has a leading '?', and
 * the hexadecimal address follows the name between parenthesis.
 *
 * When the symbols may be inaccurate, the name has a leading '!'.
 *
 * When the symbols were loaded from a stale source, the name has a leading '~'.
 *
 * The way formatting is done allows this routine to be used from a
 * signal handler.
 *
 * @param pc		the PC to translate into symbolic form
 * @param offset	whether decimal offset should be added, in symbolic form.
 *
 * @return symbolic name for given pc offset, if found, otherwise
 * the hexadecimal value.
 */
static G_GNUC_COLD const char *
trace_name(const void *pc, gboolean offset)
{
	static char buf[256];

	if (!trace_array.sorted) {
		trace_fmt_pointer(buf, sizeof buf, pc);
	} else {
		struct trace *t;

		t = trace_lookup(pc);

		if (NULL == t || &trace_array.base[trace_array.count - 1] == t) {
			trace_fmt_pointer(buf, sizeof buf, pc);
		} else {
			size_t off = 0;

			if (trace_array.garbage) {
				buf[0] = '?';
				off = 1;
			} else if (trace_array.mismatch) {
				buf[0] = '!';
				off = 1;
			} else if (trace_array.stale) {
				buf[0] = '~';
				off = 1;
			}

			trace_fmt_name(&buf[off], sizeof buf - off, t->name,
				offset ? ptr_diff(pc, t->start) : 0);

			/*
			 * If symbols are garbage, add the hexadecimal pointer to the
			 * name so that we have a little chance of figuring out what
			 * was the routine.
			 */

			if (trace_array.garbage) {
				char ptr[POINTER_BUFLEN + CONST_STRLEN(" (0x)")];

				g_strlcpy(ptr, " (0x", sizeof ptr);
				pointer_to_string_buf(pc, &ptr[4], sizeof ptr - 4);
				clamp_strcat(ptr, sizeof ptr, ")");
				clamp_strcat(buf, sizeof buf, ptr);
			}
		}
	}

	return buf;
}

/**
 * Return atom string for the trace name.
 * This memory will never be freed.
 */
static const char *
trace_atom(struct nm_parser *ctx, const char *name)
{
	const char *result;

	/*
	 * On Windows, there is an obnoxious '_' prepended to all routine names.
	 */

	if (is_running_on_mingw() && '_' == name[0])
		name++;

	result = hash_table_lookup(ctx->atoms, name);

	if (NULL == result) {
		result = ostrdup(name);		/* Never freed */
		hash_table_insert(ctx->atoms, result, result);
	}

	return result;
}

#define FN(x) \
	{ (func_ptr_t) x, STRINGIFY(x) }

static void stack_print(FILE *f, void * const *stack, size_t count);
extern int main(int argc, char **argv);

/**
 * Known symbols that we want to check.
 */
static struct {
	func_ptr_t fn;				/**< Function address */
	const char *name;			/**< Function name */
} trace_known_symbols[] = {
	FN(file_locate_from_path),
	FN(halloc_init),
	FN(hash_table_new_full_real),
	FN(is_strprefix),
	FN(main),
	FN(make_pathname),
	FN(omalloc0),
	FN(pointer_to_string_buf),
	FN(s_warning),
	FN(s_info),
	FN(signal_set),
	FN(stack_print),
	FN(trace_atom),
	FN(trace_remove),
	FN(vmm_init),
};

#undef FN

/**
 * Check whether symbols that need to be defined in the program (either because
 * they are well-known like main() or used within this file) are consistent
 * with the symbols we loaded.
 *
 * Sets trace_array.mismatch if we find at least 1 mismatch.
 * Sets trace_array.garbage if we find more than half mismatches.
 */
static void
trace_check(void)
{
	size_t matching = 0;
	size_t mismatches;
	size_t i;
	size_t offset = 0;
	GHashTable *sym_pc;
	const void *main_pc;

	if (0 == trace_array.count)
		return;

	/*
	 * On some systems, symbols are not mapped at absolute addresses but
	 * are relocated.
	 *
	 * To detect this: we locate the address of our probing routines and
	 * compare them with what we loaded from the symbols.  Of course,
	 * offsetting will only be working when the offset is the same for all
	 * the symbols.
	 */

	sym_pc = g_hash_table_new(g_str_hash, g_str_equal);

	for (i = 0; i < trace_array.count; i++) {
		struct trace *t = &trace_array.base[i];

		gm_hash_table_insert_const(sym_pc, t->name, t->start);
	}

	/*
	 * Compute the initial offset for main().
	 */

	main_pc = g_hash_table_lookup(sym_pc, "main");

	if (NULL == main_pc) {
		s_warning("cannot find main() in the loaded symbols");
		trace_array.garbage = TRUE;
		goto done;
	}

	offset = ptr_diff(main_pc, func_to_pointer(main));

	/*
	 * Make sure the offset is constant among all our probed symbols.
	 */

	for (i = 0; i < G_N_ELEMENTS(trace_known_symbols); i++) {
		const char *name = trace_known_symbols[i].name;
		const void *pc = cast_func_to_pointer(trace_known_symbols[i].fn);
		const void *loaded_pc = g_hash_table_lookup(sym_pc, name);
		size_t loaded_offset;

		if (NULL == loaded_pc) {
			s_warning("cannot find %s() in the loaded symbols", name);
			trace_array.garbage = TRUE;
			goto done;
		}

		loaded_offset = ptr_diff(loaded_pc, pc);

		if (loaded_offset != offset) {
			s_warning("will not offset symbol addresses (loaded garbage?)");
			offset = 0;
			break;
		}
	}

	if (offset != 0) {
		s_warning("will be offsetting symbol addresses by 0x%lx (%ld)",
			(unsigned long) offset, (unsigned long) offset);
		trace_array.offset = offset;
	}

	/*
	 * Now verify whether we can match symbols.
	 */

	for (i = 0; i < G_N_ELEMENTS(trace_known_symbols); i++) {
		struct trace *t;
		const void *pc = cast_func_to_pointer(trace_known_symbols[i].fn);

		t = trace_lookup(pc);

		if (t != NULL) {
			const char *name = trace_known_symbols[i].name;
			if (0 == strcmp(name, t->name))
				matching++;
		}
	}

	g_assert(size_is_non_negative(matching));
	g_assert(matching <= G_N_ELEMENTS(trace_known_symbols));

	mismatches = G_N_ELEMENTS(trace_known_symbols) - matching;

	if (mismatches != 0) {
		if (mismatches >= G_N_ELEMENTS(trace_known_symbols) / 2) {
			trace_array.garbage = TRUE;
			s_warning("loaded symbols are %s",
				G_N_ELEMENTS(trace_known_symbols) == mismatches ?
					"pure garbage" : "highly unreliable");
		} else {
			trace_array.mismatch = TRUE;
			s_warning("loaded symbols are partially inaccurate");
		}
	}

	/*
	 * Note that our algorithm cannot find any mismatch if we successfully
	 * computed a valid offset above since by construction this means we were
	 * able to find a common offset between the loaded symbol addresses and
	 * the actual ones, meaning the lookup algorithm of trace_lookup() will
	 * find the proper symbols.
	 */

	if (offset != 0 && mismatches != 0)
		s_warning("BUG in trace_check()");

done:
	gm_hash_table_destroy_null(&sym_pc);
}

/**
 * Parse the nm output line, recording symbol mapping for function entries.
 *
 * We're looking for lines like:
 *
 *	082bec77 T zget
 *	082be9d3 t zn_create
 */
static void
parse_nm(struct nm_parser *ctx, char *line)
{
	int error;
	const char *ep;
	char *p = line;
	const void *addr;

	addr = parse_pointer(p, &ep, &error);
	if (error || NULL == addr)
		return;

	p = skip_ascii_blanks(ep);

	if ('t' == ascii_tolower(*p)) {
		p = skip_ascii_blanks(&p[1]);
		strchomp(p, 0);
		trace_insert(addr, trace_atom(ctx, p));
	}
}

static size_t
str_hash(const void *p)
{
	return g_str_hash(p);
}

/**
 * Open specified file containing code symbols.
 *
 * @param exe	the executable path, to assess freshness of nm file
 * @param nm	the path to the nm file, symbols from the executable
 *
 * @return opened file if successfull, NULL on error with the error already
 * logged appropriately.
 */
static FILE *
stacktrace_open_symbols(const char *exe, const char *nm)
{
	filestat_t ebuf, nbuf;
	FILE *f;

	trace_array.stale = FALSE;

	if (-1 == stat(nm, &nbuf)) {
		s_warning("can't stat \"%s\": %s", nm, g_strerror(errno));
		return NULL;
	}

	if (-1 == stat(exe, &ebuf)) {
		s_warning("can't stat \"%s\": %s", exe, g_strerror(errno));
		trace_array.stale = TRUE;
		goto open_file;
	}

	if (delta_time(ebuf.st_mtime, nbuf.st_mtime) > 0) {
		s_warning("executable \"%s\" more recent than symbol file \"%s\"",
			exe, nm);
		trace_array.stale = TRUE;
		/* FALL THROUGH */
	}

open_file:
	f = fopen(nm, is_running_on_mingw() ? "rb" : "r");

	if (NULL == f)
		s_warning("can't open \"%s\": %s", nm, g_strerror(errno));

	return f;
}

/**
 * Load symbols from the executable we're running.
 *
 * Symbols are loaded even if the executable is not "fresh" or if the
 * "gtk-gnutella.nm" file is older than the executable.  The rationale is
 * that it is better to have some symbols than none, in the hope that the
 * ones we list will be roughly correct.
 *
 * In any case, stale or un-fresh symbols will be clearly marked in the
 * stack traces we emit, so that there cannot be any doubt later one when
 * we analyze stacks and they seem inconsistent or impossible.  The only
 * limitation is that we cannot know which symbols are correct, so all symbols
 * will be flagged as doubtful when we detect the slightest inconsistency.
 */
static G_GNUC_COLD void
load_symbols(const char *path, const  char *lpath)
{
	char tmp[MAX_PATH_LEN + 80];
	FILE *f;
	struct nm_parser nm_ctx;
	gboolean retried = FALSE;

#ifdef MINGW32
	/*
	 * Open the "gtk-gnutella.nm" file nearby the executable.
	 */

	{
		const char *nm;

		nm = mingw_filename_nearby(NM_FILE);
		f = stacktrace_open_symbols(path, nm);

		if (NULL == f)
			goto done;

		trace_array.indirect = TRUE;
	}
#else	/* !MINGW32 */
	/*
	 * Launch "nm -p" on our executable to grab the symbols.
	 */

	{
		size_t rw;

		rw = gm_snprintf(tmp, sizeof tmp, "nm -p %s", path);
		if (rw != strlen(path) + CONST_STRLEN("nm -p ")) {
			s_warning("full path \"%s\" too long, cannot load symbols", path);
			goto done;
		}

		f = popen(tmp, "r");

		if (NULL == f) {
			s_warning("can't run \"%s\": %s", tmp, g_strerror(errno));
			goto done;
		}

		trace_array.fresh = !trace_array.stale;
	}
#endif	/* MINGW32 */

	nm_ctx.atoms = hash_table_new_full_real(str_hash, g_str_equal);

retry:
	while (fgets(tmp, sizeof tmp, f)) {
		parse_nm(&nm_ctx, tmp);
	}

	if (retried || is_running_on_mingw())
		fclose(f);
	else
		pclose(f);

	/*
	 * If we did not load any symbol, maybe the executable was stripped?
	 * Try to open the symbols from the installed nm file.
	 */

	if (!retried && 0 == trace_array.count) {
		char *nm = make_pathname(ARCHLIB_EXP, NM_FILE);

		s_warning("no symbols loaded, trying with pre-computed \"%s\"", nm);
		trace_array.fresh = FALSE;
		f = stacktrace_open_symbols(path, nm);
		retried = TRUE;
		HFREE_NULL(nm);

		if (f != NULL) {
			trace_array.indirect = TRUE;
			goto retry;
		}

		/* FALL THROUGH */
	}

	hash_table_destroy_real(nm_ctx.atoms);

done:
	s_info("loaded %u symbols for \"%s\"", (unsigned) trace_array.count, lpath);

	trace_sort();
	trace_check();
}

/**
 * Get the full program path.
 *
 * @return a newly allocated string (through halloc()) that points to the
 * path of the program being run, NULL if we can't compute a suitable path.
 */
static G_GNUC_COLD char *
program_path_allocate(const char *argv0)
{
	filestat_t buf;
	const char *file = argv0;

	if (-1 == stat(argv0, &buf)) {
		int saved_errno = errno;
		file = file_locate_from_path(argv0);
		if (NULL == file) {
			s_warning("could not stat() \"%s\": %s",
				argv0, g_strerror(saved_errno));
			s_warning("cannot find \"%s\" in PATH, not loading symbols", argv0);
			goto error;
		}
	}

	/*
	 * Make sure there are no problematic shell meta-characters in the path.
	 */

	{
		const char meta[] = "$&`;()<>|";
		const char *p = file;
		int c;

		while ((c = *p++)) {
			if (strchr(meta, c)) {
				s_warning("found shell meta-character '%c' in path \"%s\", "
					"not loading symbols", c, file);
				goto error;
			}
		}
	}

	if (file != NULL && file != argv0)
		return deconstify_gpointer(file);

	return h_strdup(argv0);

error:
	if (file != NULL && file != argv0)
		hfree(deconstify_gpointer(file));

	return NULL;
}

/**
 * Tune the level of offsetting we have to do to get the current caller.
 */
static G_GNUC_COLD NO_INLINE void
stacktrace_auto_tune(void)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;
	size_t i;

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), 0);

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
 * Initialize stack tracing.
 *
 * @param argv0		the value of argv[0], from main(): the program's filename
 * @param deferred	if TRUE, do not load symbols until it's needed
 */
G_GNUC_COLD void
stacktrace_init(const char *argv0, gboolean deferred)
{
	char *path;

	g_assert(argv0 != NULL);

	path = program_path_allocate(argv0);

	if (NULL == path)
		goto done;

	if (deferred) {
		filestat_t buf;

		if (-1 == stat(path, &buf)) {
			s_warning("cannot stat \"%s\": %s", path, g_strerror(errno));
			s_warning("will not be loading symbols for %s", argv0);
			goto done;
		}

		program_mtime = buf.st_mtime;
		local_path = path;
		program_path = absolute_pathname(path);
		goto tune;
	}

	load_symbols(path, path);

	/* FALL THROUGH */

done:
	HFREE_NULL(path);
	symbols_loaded = TRUE;		/* Don't attempt again */

	/* FALL THROUGH */

tune:
	stacktrace_auto_tune();
}

/**
 * @return amount of large VMM memory used.
 */
size_t
stacktrace_memory_used(void)
{
	size_t res;

	res = trace_array.size * sizeof trace_array.base[0];
	if (stack_atoms != NULL) {
		res += hash_table_arena_memory(stack_atoms);
	}

	return res;
}

/**
 * Close stack tracing.
 */
G_GNUC_COLD void
stacktrace_close(void)
{
	HFREE_NULL(local_path);
	HFREE_NULL(program_path);
	if (trace_array.base != NULL) {
		vmm_free(trace_array.base,
			trace_array.size * sizeof trace_array.base[0]);
		trace_array.base = NULL;
	}
	if (stack_atoms != NULL) {
		hash_table_destroy_real(stack_atoms);	/* Does not free keys/values */
		stack_atoms = NULL;
	}
}

/**
 * Load symbols if not done already.
 */
G_GNUC_COLD void
stacktrace_load_symbols(void)
{
	if (symbols_loaded)
		return;

	symbols_loaded = TRUE;		/* Whatever happens, don't try again */

	/*
	 * Loading of symbols was deferred: make sure the executable is still
	 * there and has not been tampered with since we started.
	 */

	if (program_path != NULL) {
		filestat_t buf;

		if (-1 == stat(program_path, &buf)) {
			s_warning("cannot stat \"%s\": %s",
				program_path, g_strerror(errno));
			goto error;
		}

		/*
		 * Symbols are loaded if the program has been tampered with, but
		 * the symbols are marked as stale.
		 */

		if (buf.st_mtime != program_mtime) {
			s_warning("executable file \"%s\" has been tampered with",
				program_path);

			trace_array.stale = TRUE;

			/* FALL THROUGH */
		}

		load_symbols(program_path, local_path);
	}

	goto done;

error:
	if (program_path != NULL) {
		s_warning("cannot load symbols for %s", program_path);
	}

	/* FALL THROUGH */

done:
	HFREE_NULL(program_path);
	HFREE_NULL(local_path);
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
void
stacktrace_get(struct stacktrace *st)
{
	st->len = stacktrace_unwind(st->stack, G_N_ELEMENTS(st->stack), 1);
}

/**
 * Fill supplied stacktrace structure with the backtrace, removing ``offset''
 * amount of immediate callers (0 will make our caller be the first item).
 */
void
stacktrace_get_offset(struct stacktrace *st, size_t offset)
{
	st->len = stacktrace_unwind(st->stack, G_N_ELEMENTS(st->stack), offset + 1);
}

/**
 * Stop as soon as we reach main() before backtracing into libc.
 *
 * @param where		symbolic name of the current routine
 *
 * @return TRUE if we reached main().
 */
static gboolean
stack_reached_main(const char *where)
{
	/*
	 * Stop as soon as we reach main() before backtracing into libc
	 */

	return is_strprefix(where, "main+") != NULL;	/* HACK ALERT */
}

/**
 * Is PC a valid routine address?
 */
static inline gboolean
stack_is_text(const void *pc)
{
	return pointer_to_ulong(pc) >= 0x1000;
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

	stacktrace_load_symbols();

	for (i = 0; i < count; i++) {
		const char *where = trace_name(stack[i], TRUE);

		if (!stack_is_text(stack[i]))
			break;

		fprintf(f, "\t%s\n", where);
		if (stack_reached_main(where))
			break;
	}
}

/**
 * Safely print array of PCs, using symbolic names if possible.
 *
 * @param fd		where to print the stack
 * @param stack		array of Program Counters making up the stack
 * @param count		number of items in stack[] to print, at most.
 */
static void
stack_safe_print(int fd, void * const *stack, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		const char *where = trace_name(stack[i], TRUE);
		DECLARE_STR(3);

		print_str("\t");		/* 0 */
		print_str(where);		/* 1 */
		print_str("\n");		/* 2 */
		flush_str(fd);

		if (!stack_is_text(stack[i]))
			break;

		if (stack_reached_main(where))
			break;
	}
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
 * Return symbolic name of the n-th caller in the stack, if possible.
 *
 * With n = 0, this should be the current routine name.
 *
 * @return pointer to static data.  An empty name means there are not enough
 * items in the stack.
 */
const char *
stacktrace_caller_name(size_t n)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	g_assert(size_is_non_negative(n));
	g_assert(n <= STACKTRACE_DEPTH_MAX);

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), 1);
	if (n >= count)
		return "";

	if (!signal_in_handler())
		stacktrace_load_symbols();

	return trace_name(stack[n], FALSE);
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
stacktrace_routine_name(const void *pc, gboolean offset)
{
	return trace_name(pc, offset);
}

/**
 * Print current stack trace to specified file.
 */
void
stacktrace_where_print(FILE *f)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), 1);
	stack_print(f, stack, count);
}

/**
 * @return whether we got any symbols.
 */
static gboolean
stacktrace_got_symbols(void)
{
	stacktrace_load_symbols();
	return trace_array.sorted;
}

/**
 * Print current stack trace to specified file if symbols where loaded.
 */
void
stacktrace_where_sym_print(FILE *f)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	if (!stacktrace_got_symbols())
		return;		/* No symbols loaded */

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), 1);
	stack_print(f, stack, count);
}

/**
 * Print current stack trace to specified file, with specified offset.
 *
 * @param f			file where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void
stacktrace_where_print_offset(FILE *f, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX];
	size_t count;

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), offset + 1);
	stack_print(f, stack, count);
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

	if (!stacktrace_got_symbols())
		return;		/* No symbols loaded */

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), offset + 1);
	stack_print(f, stack, count);
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

	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), offset + 1);
	if (!signal_in_handler())
		stacktrace_load_symbols();
	stack_safe_print(fd, stack, count);
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
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
void
stacktrace_stack_safe_print(int fd, void * const *stack, size_t count)
{
	if (!signal_in_handler())
		stacktrace_load_symbols();

	stack_safe_print(fd, stack, count);
}

/**
 * Context for cautious stack printing, used in desperate situations
 * when we're about to crash anyway.
 */
static struct {
	int fd;
	Sigjmp_buf env;
	unsigned unwinded:1;
	unsigned done:1;
} print_context;

/*
 * Was a cautious stacktrace already logged?
 */
gboolean
stacktrace_cautious_was_logged(void)
{
	return print_context.done;
}

/**
 * Invoked when a fatal signal is received during stack unwinding.
 */
static G_GNUC_COLD void
stacktrace_got_signal(int signo)
{
	char time_buf[18];
	DECLARE_STR(5);

	crash_time(time_buf, sizeof time_buf);
	print_str(time_buf);
	print_str(" WARNING: got ");
	print_str(signal_name(signo));
	print_str(" during stack ");
	if (print_context.unwinded) {
		print_str("printing\n");
	} else {
		print_str("unwinding\n");
	}
	flush_str(print_context.fd);

	Siglongjmp(print_context.env, signo);
}

/**
 * Like stacktrace_where_safe_print_offset() but with extra caution.
 *
 * Caution comes from the fact that we trap all SIGSEGV and other harmful
 * signals that could result from improper memory access during stack
 * unwinding (due to a corrupted stack).
 *
 * @param fd		file descriptor where stack should be printed
 * @param offset	amount of immediate callers to remove (ourselves excluded)
 */
G_GNUC_COLD void
stacktrace_where_cautious_print_offset(int fd, size_t offset)
{
	void *stack[STACKTRACE_DEPTH_MAX + 5];	/* See stacktrace_unwind() */
	volatile size_t count;

	static volatile sig_atomic_t printing;
	signal_handler_t old_sigsegv;
#ifdef SIGBUS
	signal_handler_t old_sigbus;
#endif
#ifdef SIGTRAP
	signal_handler_t old_sigtrap;
#endif

	if (printing) {
		char time_buf[18];
		DECLARE_STR(5);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);
		print_str(" WARNING: ignoring ");
		print_str("recursive ");
		print_str(G_STRFUNC);
		print_str("() call\n");
		flush_str(fd);
		return;
	}

	/*
	 * Install signal handlers for most of the harmful signals that
	 * could happen during stack unwinding in case the stack is corrupted
	 * and we start following wrong frame pointers.
	 */

	old_sigsegv = signal_set(SIGSEGV, stacktrace_got_signal);

#ifdef SIGBUS
	old_sigbus = signal_set(SIGBUS, stacktrace_got_signal);
#endif
#ifdef SIGTRAP
	old_sigtrap = signal_set(SIGTRAP, stacktrace_got_signal);
#endif

	printing = TRUE;
	print_context.fd = fd;

	if (Sigsetjmp(print_context.env, TRUE)) {
		char time_buf[18];
		DECLARE_STR(2);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);
		print_str("WARNING: truncated stack unwinding\n");
		flush_str(fd);

		/*
		 * Becasue we zeroed the stack[] array before attempting the unwinding
		 * we can now go back and count the amount of items that were put
		 * there in case we got interrupted by a signal, to be able to dump
		 * the part of the stack we were able to unwind correctly.
		 */

		count = 0;
		while (count < G_N_ELEMENTS(stack) && stack[count] != NULL)
			count++;
		goto print_stack;
	}

	/*
	 * Prepare for possible harmful signal during stack unwinding: we zero
	 * the stack to be able to determine the amount of filled items in case
	 * the operation is aborted and stacktrace_unwind() does not return.
	 */

	ZERO(&stack);
	count = stacktrace_unwind(stack, G_N_ELEMENTS(stack), offset + 1);

print_stack:

	print_context.unwinded = TRUE;

	if (Sigsetjmp(print_context.env, TRUE)) {
		char time_buf[18];
		DECLARE_STR(2);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);
		print_str(" WARNING: truncated stack printing\n");
		flush_str(fd);
		goto restore;
	}

	if (0 == count) {
		char time_buf[18];
		DECLARE_STR(2);

		crash_time(time_buf, sizeof time_buf);
		print_str(time_buf);
		print_str(" WARNING: corrupted stack\n");
		flush_str(fd);
	} else {
		if (!signal_in_handler())
			stacktrace_load_symbols();
		stack_safe_print(fd, stack, count);
	}

	print_context.done = TRUE;

restore:
	printing = FALSE;

	signal_set(SIGSEGV, old_sigsegv);

#ifdef SIGBUS
	signal_set(SIGBUS, old_sigbus);
#endif
#ifdef SIGTRAP
	signal_set(SIGTRAP, old_sigtrap);
#endif
}

/**
 * Hashing routine for a "struct stacktracea".
 */
size_t
stack_hash(const void *key)
{
	const struct stackatom *sa = key;

	if (0 == sa->len)
		return 0;

	return binary_hash(sa->stack, sa->len * sizeof sa->stack[0]);
}

/**
 * Comparison of two "struct stacktracea" structures.
 */
int
stack_eq(const void *a, const void *b)
{
	const struct stackatom *sa = a, *sb = b;

	return sa->len == sb->len &&
		0 == memcmp(sa->stack, sb->stack, sa->len * sizeof sa->stack[0]);
}

/**
 * Get a stack trace atom (never freed).
 */
struct stackatom *
stacktrace_get_atom(const struct stacktrace *st)
{
	struct stackatom key;
	struct stackatom *result;

	STATIC_ASSERT(sizeof st->stack[0] == sizeof result->stack[0]);

	if (NULL == stack_atoms) {
		stack_atoms = hash_table_new_full_real(stack_hash, stack_eq);
	}

	key.stack = deconstify_gpointer(st->stack);
	key.len = st->len;

	result = hash_table_lookup(stack_atoms, &key);

	if (NULL == result) {
		/* These objects will be never freed */
		result = omalloc0(sizeof *result);
		if (st->len != 0) {
			result->stack = omalloc(st->len * sizeof st->stack[0]);
			memcpy(result->stack, st->stack, st->len * sizeof st->stack[0]);
		} else {
			result->stack = NULL;
		}
		result->len = st->len;

		if (!hash_table_insert(stack_atoms, result, result))
			g_error("cannot record stack trace atom");
	}

	return result;
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

#ifndef HAS_BACKTRACE

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

#endif	/* !HAS_BACKTRACE */

/* vi: set ts=4 sw=4 cindent:  */
