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

/**
 * Hashing /equality functions for "struct stacktracea" atomic traces.
 */
size_t stack_hash(const void *key) G_GNUC_PURE;
int stack_eq(const void *a, const void *b) G_GNUC_PURE;

struct logagent;

void stacktrace_get(struct stacktrace *st);
void stacktrace_get_offset(struct stacktrace *st, size_t offset);
void stacktrace_print(FILE *f, const struct stacktrace *st);
void stacktrace_atom_print(FILE *f, const struct stackatom *st);
void stacktrace_atom_log(struct logagent *la, const struct stackatom *st);

const char *stacktrace_caller_name(size_t n);
const char *stacktrace_routine_name(const void *pc, gboolean offset);
NO_INLINE size_t stacktrace_unwind(void *stack[], size_t count, size_t offset);

void stacktrace_where_print(FILE *f);
void stacktrace_where_sym_print(FILE *f);
void stacktrace_where_sym_print_offset(FILE *f, size_t offset);
void stacktrace_where_print_offset(FILE *f, size_t offset);
void stacktrace_where_safe_print_offset(int fd, size_t offset);
void stacktrace_where_cautious_print_offset(int fd, size_t offset);
void stacktrace_stack_safe_print(int fd, void * const *stack, size_t count);
gboolean stacktrace_cautious_was_logged(void);

struct stackatom *stacktrace_get_atom(const struct stacktrace *st);

void stacktrace_init(const char *argv0, gboolean deferred);
void stacktrace_load_symbols(void);
void stacktrace_post_init(void);
void stacktrace_close(void);
size_t stacktrace_memory_used(void);
enum stacktrace_sym_quality stacktrace_quality(void);
const char *stacktrace_quality_string(const enum stacktrace_sym_quality sq);

#endif /* _stacktrace_h_ */

/* vi: set ts=4 sw=4 cindent:  */
