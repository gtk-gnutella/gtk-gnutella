/*
 * Copyright (c) 2004, 2010 Raphael Manfredi
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
 * Stack unwiding support.
 *
 * @author Raphael Manfredi
 * @date 2004, 2010
 */

#ifndef _stacktrace_h_
#define _stacktrace_h_

#define STACKTRACE_DEPTH_MAX	128		/**< Maximum depth we can handle */
#define STACKTRACE_DEPTH		10		/**< Typical fixed-size trace */

/**
 * A fixed stack trace.
 */
struct stacktrace {
	void *stack[STACKTRACE_DEPTH];	/**< PC of callers */
	size_t len;						/**< Number of valid entries in stack */
};

/**
 * An "atomic" stack trace (only one copy kept around for identical traces).
 * These objects are never freed once allocated.
 *
 * To obtain an atomic copy, call stacktrace_get_atom().
 */
struct stackatom {
	void **stack;				/**< Array of PC of callers */
	size_t len;					/**< Number of valid entries in stack */
};

/**
 * Self-assessed stacktrace symbol quality.
 */
enum stacktrace_sym_quality {
	STACKTRACE_SYM_GOOD = 0,
	STACKTRACE_SYM_STALE,
	STACKTRACE_SYM_MISMATCH,
	STACKTRACE_SYM_GARBAGE,

	STACKTRACE_SYM_MAX
};

/*
 * Decoration flags for stack traces.
 */
#define STACKTRACE_F_ORIGIN		(1U << 0)	/**< Show shared object names */
#define STACKTRACE_F_SOURCE		(1U << 1)	/**< Display source location */
#define STACKTRACE_F_NUMBER		(1U << 2)	/**< Number items */
#define STACKTRACE_F_NO_INDENT	(1U << 3)	/**< Turn off indentation */
#define STACKTRACE_F_GDB		(1U << 4)	/**< Show a gdb-like trace */
#define STACKTRACE_F_ADDRESS	(1U << 5)	/**< Display addresses */
#define STACKTRACE_F_MAIN_STOP	(1U << 6)	/**< Stop printing at main() */
#define STACKTRACE_F_THREAD		(1U << 7)	/**< Print thread small ID */
#define STACKTRACE_F_PATH		(1U << 8)	/**< Prints full path of objects */

/**
 * Hashing /equality functions for "struct stacktrace" atomic traces.
 */
unsigned stack_hash(const void *key) G_PURE;
int stack_eq(const void *a, const void *b) G_PURE;

struct logagent;

void stacktrace_get(struct stacktrace *st);
void stacktrace_get_offset(struct stacktrace *st, size_t offset);
void stacktrace_print(FILE *f, const struct stacktrace *st);
void stacktrace_atom_print(FILE *f, const struct stackatom *st);
void stacktrace_atom_decorate(FILE *f, const struct stackatom *st, uint flags);
void stacktrace_atom_log(struct logagent *la, const struct stackatom *st);

const char *stacktrace_caller_name(size_t n);
const char *stacktrace_routine_name(const void *pc, bool offset);
const char *stacktrace_routine_name_light(const void *pc, size_t *offset);
size_t stacktrace_unwind(void *stack[], size_t count, size_t offset);
size_t stacktrace_safe_unwind(void *stack[], size_t count, size_t offset);

void stacktrace_where_print(FILE *f);
void stacktrace_where_sym_print(FILE *f);
void stacktrace_where_sym_print_offset(FILE *f, size_t offset);
void stacktrace_where_plain_print_offset(int fd, size_t offset);
void stacktrace_where_safe_print_offset(int fd, size_t offset);
void stacktrace_where_cautious_print_offset(int fd, size_t offset);
void stacktrace_stack_safe_print(int fd, int stid, void * const *, size_t);
void stacktrace_stack_plain_print(int fd, void * const *stack, size_t count);
void stacktrace_stack_fancy_print(int fd, void * const *stack, size_t count);
void stacktrace_stack_print_decorated(int fd, int stid,
	void * const *stack, size_t count, uint flags);
void stacktrace_where_print_decorated(FILE *f, uint flags);
bool stacktrace_cautious_was_logged(void);
void stacktrace_cautious_print(int fd, int stid, void *stack[], size_t offset);

const struct stackatom *stacktrace_get_atom(const struct stacktrace *st);
const void *stacktrace_caller(size_t n);
bool stacktrace_caller_known(size_t offset);
const void *stacktrace_routine_start(const void *pc);
bool stacktrace_pc_within_our_text(const void *pc);

void stacktrace_atom_circular_flush(void);

void stacktrace_init(const char *argv0, bool deferred);
void stacktrace_load_symbols(void);
void stacktrace_post_init(void);
void stacktrace_close(void);
size_t stacktrace_memory_used(void);
void stacktrace_crash_mode(void);
enum stacktrace_sym_quality stacktrace_quality(void);
const char *stacktrace_quality_string(const enum stacktrace_sym_quality sq);

/**
 * @return function's name given a function pointer.
 */
#define stacktrace_function_name(fp) \
	stacktrace_routine_name(func_to_pointer(fp), FALSE)

#endif /* _stacktrace_h_ */

/* vi: set ts=4 sw=4 cindent:  */
