/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * Minimal regular expression support.
 *
 * The logfilter code has stringent requirements: its execution must refrain
 * from using wide memory allocation, or running code that will take locks.
 * Why?  Because it can be invoked to process a log message from almost anywhere
 * in the application, and that may be from a memory allocation layer, which is
 * currently holding locks.
 *
 * It was therefore necessary to have a minimal (but expressive enough) regex
 * support whose compilation phase is free to allocate memory but whose actual
 * matching operation must not allocate any, nor require locking.  The only
 * memory space allowed is stack space.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _re_h_
#define _re_h_

#include "if/gen/re.h"

struct re_regex;
typedef struct re_regex re_regex_t;

/**
 * Regular expression parsing error.
 */
typedef struct re_error {
	re_error_code_t code;	/**< Error code */
	size_t pos;				/**< Position in regex where error was found */
} re_error_t;

/**
 * Regular expression matching point.
 */
typedef struct re_match {
	ssize_t re_start;		/**< Offset within string where match starts */
	ssize_t re_end;			/**< Offset right after the match ends */
} re_match_t;

/**
 * Regular expression matching statistics.
 */
typedef struct re_exec_stats {
	bool remi;				/**< Went through RE Matching Interpreter? */
	bool engine;			/**< Went through a RE engine (C or MI) */
	size_t elapsed;			/**< Elapsed execution time, in ns */
	size_t stack_max;		/**< Execution stack threshold */
	size_t stack_used;		/**< Actual maximum stack used */
} re_exec_stats_t;

/**
 * Compilation flags.
 */

#define RE_F_ICASE		(1U << 0)	/**< Ignore case */
#define RE_F_NOSUB		(1U << 1)	/**< No sub-expression captures */
#define RE_F_NEWLINE	(1U << 2)	/**< Match-any (.) now also matches \n */

/* For debugging and testing */
#define RE_F_NO_OPTIM	(1U << 29)	/**< Disable optimizations */
#define RE_F_NO_SIMPLE	(1U << 30)	/**< Disable "simple regex" recognition */

/**
 * Execution flags.
 */
#define RE_X_NOSUB		(1U << 0)	/**< Disable capturing in () groups */
#define RE_X_MULTI_LINE	(1U << 1)	/**< ^ and $ can match after / before \n */

/* For debugging and testing */
#define RE_X_NO_MUST	(1U << 29)	/**< Disable "must" string processing */
#define RE_X_DEBUG		(1U << 30)	/**< Enable debug mode (for byte-code) */
#define RE_X_USE_BC		(1U << 31)	/**< Force byte-code matching */

/**
 * Flags for `show'.
 */
#define RE_SHOW_DUMP	(1U << 0)	/**< Show the compiled dump */
#define RE_SHOW_TREE	(1U << 1)	/**< Show the compiled tree */
#define RE_SHOW_BC		(1U << 2)	/**< Show the compiled bytecode */
#define RE_SHOW_FCMAP	(1U << 3)	/**< Show the First Char Map */
#define RE_SHOW_CASE	(1U << 4)	/**< Show compilation case */
#define RE_SHOW_DEBUG	(1U << 31)	/**< Emit bytecode with debug  */

#define RE_SHOW_ALL	\
	(RE_SHOW_DUMP | RE_SHOW_TREE | RE_SHOW_BC | RE_SHOW_FCMAP | RE_SHOW_CASE)

#define RE_SHOW_DFLT \
	(RE_SHOW_DUMP | RE_SHOW_TREE | RE_SHOW_FCMAP)

/*
 * Public interface.
 */

re_regex_t *re_compile(const char *s, uint32 cflags, re_error_t *error);
void re_recompile(re_regex_t *re, uint32 cflags);
void re_free(re_regex_t *re);
void re_free_null(re_regex_t **re);
int re_execute(const re_regex_t *re, const char *string, uint eflags);
int re_execute_len(const re_regex_t *re,
	const char *string, size_t slen, uint eflags);
int re_execute_full(const re_regex_t *re, const char *string, size_t slen,
	re_match_t *mvec, size_t mcnt, uint eflags);
int re_execute_stats(const re_regex_t *re, const char *string, size_t slen,
	re_match_t *mvec, size_t mcnt, uint eflags, re_exec_stats_t *stats);
const char *re_execute_strerror(int error);

char *re_dump_as_string(const re_regex_t *re);
char *re_show_as_string(const re_regex_t *re);
char *re_show_as_string_ext(const re_regex_t *re, uint flags);
char *re_fcmap_dump_as_string(const re_regex_t *re);
char *re_bytecode_as_string(const re_regex_t *re, bool debug);

const char *re_pattern(const re_regex_t *re) G_PURE;
bool re_is_simple(const re_regex_t *re) G_PURE;
bool re_is_optimized(const re_regex_t *re) G_PURE;
size_t re_group_count(const re_regex_t *re) G_PURE;
size_t re_match_length_min(const re_regex_t *re);
size_t re_match_length_max(const re_regex_t *re);

#endif /* _re_h_ */

/* vi: set ts=4 sw=4 cindent: */
