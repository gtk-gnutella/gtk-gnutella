/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Versatile logging filtering support.
 *
 * The level of log filtering provided here allows one to turn on all the
 * logging within the application and then selectively determine which
 * information to log, and where to add a stacktrace, allowing to easily
 * pinpoint an error without having to recompile the application to turn
 * s_warning() calls into s_carp() for instance, or regroup in another
 * file all the logs matching a pattern.
 *
 * The configuration of the filtering is stored in a file that is monitored
 * by the application and will be reloaded and applied whenever it changes,
 * modulo the checking period (30 seconds by default), or via the shell command
 * "log filter reload".
 *
 * Filtering is applicable to all g_xxx() and s_xxx() calls, where xxx is one
 * of: carp, carp_once, critical, warning, message, info, debug.
 *
 * Here is an informal description of the directives that can be used to
 * configure the log filtering:
 *
 * Whitespace between tokens is insignificant, with the exception of regular
 * expressions (viewed as one single token, including the trailing matching
 * options).
 *
 * A '#' introduces a comment, and the remainder of the line is ignored.
 *
 * A '*' introduces constant tokens that are not otherwise a keyword and which
 * must not be parsed as a variable nor as a string.
 *
 * The following words are reserved (keywords):
 *
 * 		break
 * 		carp
 * 		color
 * 		copy
 * 		critical
 * 		debug
 * 		disable
 * 		enable
 * 		err
 * 		file
 * 		highlight
 * 		ignore
 * 		info
 * 		level
 * 		line
 * 		log
 * 		match
 * 		message
 * 		next
 * 		nobreak
 * 		nocarp
 * 		nolevel
 * 		nolog
 * 		nomatch
 * 		noroutine
 * 		nowhere
 * 		options
 * 		out
 * 		routine
 * 		stop
 * 		strip
 * 		tag
 * 		warning
 * 		where
 *
 * The configuration file introduces rules that are applied in sequence.  Usually
 * processing will stop at the first match for a given log message, unless one
 * specifies "break" as a directive to continue matching.
 *
 * A filtering rule has the following form, in this approximate grammar:
 *
 *		',' denotes a verbatim char
 *		'()' denotes a verbatim sequence of '(' and ')' with no allowed spaces
 *		<keyword> denotes a keyword
 *		() are used for grouping
 *		? specifies 0 or 1 instance
 *		* specifies 0 or many instances
 *		+ specifies 1 or more instances
 *		:: defines a gramatical rule
 *		| denotes an alternative
 * 		; denotes the end of the grammatical rule
 *
 *		rule:: (selector-list ':')? (action (',' action)*)? ';' ;
 *
 * The selector is optional, and it is followed by a comma-separated list of
 * actions, terminated by a semi-colon.  The list can be empty.
 *
 * Actions can also be put within blocks, in which case the variables and
 * superseded actions live only within the block:
 *
 *		rule-list::
 * 			  rule
 *			| rule rule-list
 * 			;
 *
 *		block:: (selector-list)? '{' (rule-list | block)* '}'	;
 *
 * The block may be empty and the selector is optional.  As shown by the
 * grammar, blocks can nest.
 *
 * A selector can take four forms:
 *
 * 		plain-selector::
 * 			  (<message>)? regex
 * 			| (<routine>)? routine-name
 * 			| (<routine>) regex
 * 			| (<file>)? quoted-string
 * 			| (<file>) regex
 * 			| <level> op log-level
 * 			| <line> op unsigned-integer
 * 			;
 *
 * The optional '!' in front of the plain-selector inverts the matching condition.
 *
 * 		selector:: '!'? plain-selector ;
 *
 * A selector list is made of 1 or more selectors, separated by commas:
 *
 * 		selector-list::
 * 			  selector
 *			| selector ',' selector-list
 *			;
 *
 * When a list is given, all selectors are AND-ed, i.e. they all must match
 * in order for the following action or block to be processed.
 *
 *		unsigned-integer:: digit+;
 * 		constant-token:: '*' (letter|digit)+
 *
 * 		regex::
 * 		      '/' regular-expression '/' re-options
 * 		 	| 'm' re-punct regular-expression re-punct re-options
 * 			;
 *
 * 		In the above regex definition, re-punct must be the SAME character.
 *
 * 		re-punct:: ',' | '!' | ':' | '%' | '|' | '/';
 * 		re-options:: 'i'? ;
 *
 * The 'i' re-option requests case-insensitive pattern matching.
 *
 * 		quoted-string:: '"' (letter|digit|punct)* '"' ;
 *
 * 		routine-name::
 * 			  letter (letter|digit)* '(' ')'
 * 			| '"' letter (letter|digit)* '()' '"'
 * 			;
 *
 * 		The second  form of routine-name is used when the routine-name before
 * 		the trailing '()' sequence would form a keyword.
 *
 * 		op:: '=' | '!=' | '>' | '<' | '<=' | '>=' ;
 * 		log-level:: <critical> | <warning> | <message> | <info> | <debug> ;
 *
 * A log message has four constituants that can be matched for separately:
 *
 * 		1- the message string itself
 * 		2- the logging level (critical, warning, message, info, debug)
 * 		3- the routine name where the message is emitted
 * 		4- the file where the message is emitted
 *
 * By default, an action applies to any message as a whole, unless one of the
 * constituants is specified as a filter.  Actions are:
 *
 * 		break		continue matching other rules, supersedes earlier "nobreak"
 * 		carp		add aditional stacktrace after the message
 * 		copy		copy message to an additional logfile name
 * 		color		turn text into specfied color (string / variable argument)
 * 		highlight	highlight captured group in regular expression
 * 		ignore		regardless of log/nolog/copy status, ignore log message
 * 		level		restore logging of message level
 * 		log			log message (usually implied, unless "nolog" was given)
 * 		match		highlight pattern match, see below
 * 		next		regardless of break/nobreak status, move to next rule
 * 		nobreak		supersedes any earlier "break": stop matching other rules
 * 		nocarp		suppress aditional stacktrace after the message
 * 		nomatch		suppress pattern highlighting
 * 		nolevel		suppress logging of message level
 * 		nolog		ignore message (will not log it to stderr)
 * 		noroutine	leave message as-is, do not add routine name if not present
 * 		nowhere		suppress source code location in log message
 * 		routine		request logging of routine in message if not already present
 * 		stop		regardless of break/nobreak status, stop matching rules
 * 		strip		strip leading tag string if present, or where/routine info
 * 		tag			prepend tag string to the log message
 * 		where		requests source code location "(file.c:13)" in log message
 *
 * If not preceded by a selector, the above actions define default behaviour
 * to apply when a rule will match.  The default initial state corresponds
 * to the following actions:
 *
 *		level, log, nobreak, nocarp, noroutine, nowhere;
 *
 * Which means that, by default, unless a rule matches, we will stop and log
 * the message as if no filtering had been done.  If a rule matches, these
 * actions are implicit but can be superseded by any other action specified
 * after the selection.
 *
 * The "strip" action can take a variable or string to strip that leading tag,
 * or be followed by on the "routine" and "where" keywords. In which case
 * "strip routine" removes any routine indication in the log and "strip where"
 * will remove any source file location:
 *
 * 		strip "tag";		# removes "tag" in front of message
 * 		strip where;		# removes souce:line indication in message
 * 		strip routine;		# removes routine name from message
 *
 * The "carp" action may optionally be followed by a qualification constant
 * token: *full for full stack (the default), *name for routine names,
 * *mini for internal symbols and *hexa for hexadecimal trace.
 *
 * One can therefore say:
 *
 * 		carp *mini;
 *		carp *name;		# as *mini but public library symbols are resolved
 *
 * to request that only minimal symbol resolution be used in case a stack
 * is dumped, to specifically minimize the resources mobilized to produce
 * that stack.
 *
 * For "critical" log levels, "carp" is turned on automatically initially,
 * but can be disabled by saying:
 *
 * 		level = critical: nocarp;
 *
 * Additional names are defined by the following directive:
 *
 *		name = "~/path/to/logfile";
 *
 * where "name" stands for any identifier that is not a keyword!
 *
 * This will define "name" as a variable replacing a string for "copy" or "tag".
 * directives.  The "out" and "err" names are pre-defined to refer to the outputs
 * going to stdout and stderr respectively.
 *
 * To select on a message string (#1), use a regular expression:
 *
 * 		/mesh/: nolog;
 * 		/is.*not/: copy out, carp, highlight 0;
 *
 * It is possible to use another separator than "/" to introduce regular
 * expressions and avoid having to escape the "/" with a preceding "\": using
 * the perl syntax, say "m" followed by a punctuation sign, for instance:
 *
 * 		m|has / inside|: nolog;
 *
 * Also, like perl, it is possible to request a case-insensitive matching
 * by appending a "i" after the regular expression:
 *
 * 		m|CASE insensitive|i: tag "foo: ";
 *
 * The "match" and "highlight" actions can be used to put visual emphasis
 * on matched parts.  The "match" action is general and turns on the
 * highlighting of the whole matched string for all the patterns that matched
 * on the log message.  The "highlight" action is only meaningful in a
 * log message selection and will cause parts of the matched text to be
 * highlighted.
 *
 * The "highlight" action must be followed by a digit indicating which
 * capturing group in the regular expression must be highlighted.  0 stands
 * for the whole matching string, 1 for the first capturing group, etc...
 * Unlike "match" which is a global state and will put emphasis over all
 * the patterns that matched on the log string, "highlight" only focuses on the
 * particular regular expression where it appears.
 *
 * Match highlighting will be surrounded by on-off escapes, among "underline",
 * "inverse", "blink".  The default is "underline" for the "match" action
 * and "inverse" for "highlight" but it can be changed via an options{} block
 * by saying:
 *
 *		options {
 *			match = "blink"
 *			highlight = "underline"
 *      }
 *
 * Unfortunately, "match" interacts with coloring of logs, so the chosen
 * option must never be specified to color log messages or, after a match,
 * the effect will be turned off.
 *
 * The options{} block is a list of
 *
 * 		key = "value";
 *
 * statements where `key' is merely a variable.  There are no reserved
 * words within an options{} block, and validation of the options is done
 * after parsing.  Unknown options are signaled, to prevent a typo from
 * remaining unnoticed!
 *
 * To select on a logging level (#2), use a log level comparison.
 * NOTA BENE: a selection on level only (without any other selection) does
 * not stop rule matching, i.e. there is an implicit "next" at the end.
 *
 * 		level > warning: nocarp;
 * 		level = critical: copy out, color "red; bold";
 * 		level <= warning: carp;
 * 		level = warning: color "red; faint"
 * 		level > message: nolog;
 * 		level = info: color "green; faint";
 * 		level = debug: color "bright black";
 *
 * The above sentences, when confronted with a logging level of "info" would
 * trigger the following:
 *
 * 		level > warning: nocarp;
 *
 * matches, hence we set the "no carp" attribute and continue matching (implicit
 * "next" since we are only selecting on level).  The next line that matches is:
 *
 * 		level > message: nolog;
 *
 * which therefore sets the "nolog" attribute.  If we stopped matching here,
 * the attributes we have so far are: "nocarp, nolog": we turn-off any carp-ing
 * and ignore (i.e drop and do not log anything).
 *
 * Selection against a source line number uses the same syntax overall as level
 * but the value against which comparison is made is an unsigned value:
 * Note the "next" here, since contrary to level selection, line selection is
 * final by default.
 *
 * 		line >= 6: carp, next;
 * 		line = 8: nocarp;
 *
 * To select on a routine name (#3), use a name followed by '()'.  In case the
 * routine name is a reserved word (e.g. disable), then it is necessary to
 * include the whole string within double quotes:
 *
 * 		handle_error(): carp, copy out, copy "path";
 * 		"disable()": nolog;
 *
 * If it also possible to use regular expressions on the routine name, but
 * the keyword "routine" must come before the regular expression:
 *
 * 		routine /_error/: carp;
 *
 * To select on a source file (#4), use the path within double quotes:
 *
 * 		"core/dht.c": copy dht, next;
 *
 * The string is parsed and if it ends with "()" it will be re-interpreted
 * as a routine name, as explained above.
 *
 * If it also possible to use regular expressions on the file name, but
 * the keyword "file" must come before the regular expression:
 *
 * 		file m|core/.*-gen.c|: nolog;
 *
 * Selections can be followed by a {} block instead of the ":" separator.
 * In that case they introduce nested selections.  For instance:
 *
 * 		foo() {
 * 			# These rules are only activated when logging comes from foo()
 * 			/mesh/: carp, break;
 * 			/bar/: nolog;			# If /bar/ matches, will stop here
 * 			# This directive without a selection indicates that we need to
 * 			# continue matching once we reach the end of the rules that
 * 			# follow in this block -- in effect, it factorizes a "break"
 * 			# in all the rules below, which can be superseded by explicitly
 * 			# saying "nobreak".
 * 			break;
 * 			# This directive indicates that we need to copy all messages
 * 			# to the "foo" log, in addition to other attributes that can be
 * 			# further set below.
 * 			# The "nolog" flag suppresses output to stderr, meaning messages,
 * 			# if not further ignored, will only end-up being logged into "foo".
 * 			copy foo, nolog;
 * 			# Nesting introduces another selection on the level, to carry on
 * 			# specific actions depending on the level of messages emitted
 * 			# from foo().
 * 			level = critical {
 * 				/has no/: log, nocarp;
 * 				/other/: ignore, nobreak;	# cancels earlier factorized "break"
 * 				# If /other/ matches above, we will stop matching here
 * 			}
 * 			level = info {
 * 				/found/: log;
 * 				ignore;			# ignores all other info messages
 * 			}
 * 			level > message: nolog;
 * 		}
 *
 * Any set of rules and definitions can be included in {}, in which case this
 * scopes any logfile definition and default rules.
 *
 * The keyword "enable" (syntactic sugar) before a block is ignored.
 * The keyword "disable" on the other hand is followed by a block where we
 * will parse and validate the rules, and then ignore them as if they had not
 * been specified at all.
 *
 * The disable {} construct is therefore an easy way to "comment out" a list
 * of rules and yet continue to parse and validate them.
 *
 * The "options" keyword opens the options block, which can only consist
 * of key="string" statements.  There can be multiple options{} blocks
 * defined, and those within disable {} are parsed but ignored.  However,
 * options {} are always global, not scoped to the block where they appear
 * and redefining an option simply overrides the previous value.
 *
 * Valid options are:
 *
 *		highlight	how should we highlight a sub-expression match?
 *					can be either "underline", "inverse" or "blink"
 * 					default is "inverse"
 *
 *		match		how should we highlight a match?
 *					can be either "underline", "inverse" or "blink"
 * 					default is "underline"
 *
 * 		where		where is the source tagging happening?
 * 					can be either "start" or "end"
 * 					default is "end"
 * 					"start" prepends the source information before
 * 					the routine name, if present.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#define LOGFILTER_SOURCE

#include "common.h"

#include "logfilter.h"

#include "ascii.h"
#include "atoms.h"
#include "balloc.h"
#include "color.h"
#include "eval.h"
#include "fd.h"
#include "file.h"
#include "halloc.h"
#include "hstrfn.h"
#include "htable.h"
#include "istream.h"
#include "log.h"
#include "misc.h"
#include "nv.h"
#include "once.h"
#include "ostream.h"
#include "pattern.h"
#include "pcell.h"
#include "re.h"
#include "rwlock.h"
#include "signal.h"
#include "spinlock.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"		/* For UINT_DEC_BUFLEN, bool_to_string() */
#include "symtab.h"
#include "thread.h"
#include "tokenizer.h"
#include "walloc.h"
#include "watcher.h"
#include "xslist.h"

#include "override.h"		/* Must be the last header included */

#define LOGFILTER_RELOAD	30		/**< Seconds between file checking */
#define LOGFILTER_RE_GROUPS	10		/**< Allow 9 capturing groups */

/**
 * Known logging levels.
 */
enum logfilter_log_level {
	LF_LOG_CRITICAL = 0,
	LF_LOG_WARNING,
	LF_LOG_MESSAGE,
	LF_LOG_INFO,
	LF_LOG_DEBUG
};

static const char *logfilter_log_level_str[] = {
	"critical",	/* LF_LOG_CRITICAL */
	"warning",	/* LF_LOG_WARNING */
	"message",	/* LF_LOG_MESSAGE */
	"info",		/* LF_LOG_INFO */
	"debug",	/* LF_LOG_DEBUG */
};

/**
 * Logging level or line comparison operators.
 */
enum logfilter_cmp {
	LF_LVL_EQ = 0,			/* '=' */
	LF_LVL_GT,				/* '>' */
	LF_LVL_GTE,				/* '>=' */
	LF_LVL_LT,				/* '<' */
	LF_LVL_LTE,				/* '<=' */
	LF_LVL_NE				/* '!=' */
};

static const char *logfilter_cmp_str[] = {
	"=",		/* LF_LVL_EQ */
	">",		/* LF_LVL_GT */
	">=",		/* LF_LVL_GTE */
	"<",		/* LF_LVL_LT */
	"<=",		/* LF_LVL_LTE */
	"!=",		/* LF_LVL_NE */
};

/**
 * Tokens for reserved words and other lexical entities.
 */
typedef enum logfilter_token {
	LF_TOK_NONE = 0,

	/* Keywords */
	LF_TOK_BREAK,
	LF_TOK_CARP,
	LF_TOK_COLOR,
	LF_TOK_COPY,
	LF_TOK_CRITICAL,
	LF_TOK_DEBUG,
	LF_TOK_DISABLE,
	LF_TOK_ENABLE,
	LF_TOK_ERR,
	LF_TOK_FILE,
	LF_TOK_HIGHLIGHT,
	LF_TOK_IGNORE,
	LF_TOK_INFO,
	LF_TOK_LEVEL,
	LF_TOK_LINE,
	LF_TOK_LOG,
	LF_TOK_MATCH,
	LF_TOK_MESSAGE,
	LF_TOK_NEXT,
	LF_TOK_NOBREAK,
	LF_TOK_NOCARP,
	LF_TOK_NOLEVEL,
	LF_TOK_NOLOG,
	LF_TOK_NOMATCH,
	LF_TOK_NOROUTINE,
	LF_TOK_NOWHERE,
	LF_TOK_OPTIONS,
	LF_TOK_OUT,
	LF_TOK_ROUTINE,
	LF_TOK_STOP,
	LF_TOK_STRIP,
	LF_TOK_TAG,
	LF_TOK_WARNING,
	LF_TOK_WHERE,

	LF_TOK_MAX_KEYWORD,

	/* Operators */
	LF_TOK_LBRACE,			/* '{' */
	LF_TOK_RBRACE,			/* '}' */
	LF_TOK_EQ,				/* '=' */
	LF_TOK_GT,				/* '>' */
	LF_TOK_GTE,				/* '>=' */
	LF_TOK_LT,				/* '<' */
	LF_TOK_LTE,				/* '<=' */
	LF_TOK_NE,				/* '!=' */
	LF_TOK_NOT,				/* '!' */
	LF_TOK_SC,				/* ';' */
	LF_TOK_COMMA,			/* ',' */
	LF_TOK_COLON,			/* ':' */
	LF_TOK_PARENS,			/* '()' */

	/* Higher-level lexical entities */
	LF_TOK_IDENT,			/* Any symbol that is not reserved: an identifier */
	LF_TOK_UV,				/* An unsigned integer value */
	LF_TOK_STR,				/* A double-quoted string */
	LF_TOK_REGEX,			/* A regular expression */
	LF_TOK_CONSTANT,		/* A constant token */
	LF_TOK_EOF,				/* End of input */

	LF_TOK_ERROR,			/* Syntax error */

	LF_TOK_MAX
} lf_token_id_t;

/**
 * Constant tokens.
 *
 * These are not keywords, they must be preceded by a '*' character
 * in the input to be recognized as such.  They are tokenized to avoid
 * string comparisons when processing them,
 */
typedef enum logfilter_constants {
	LF_CTOK_NONE = 0,

	LF_CTOK_HEXA,
	LF_CTOK_FULL,
	LF_CTOK_MINI,
	LF_CTOK_NAME,
} lf_constant_id_t;

/**
 * A parsed lexical symbol.
 */
typedef struct logfilter_sym {
	lf_token_id_t id;					/* Token ID */
	union {
		char c[3];						/* Lexical elements of 1 or 2 chars */
		const char *keyword;			/* The identified keyword */
		char *str;						/* A parsed symbol or string */
		re_regex_t *re;					/* Compiled regular expression */
		ulong uv;						/* Unsigned integer value */
		lf_constant_id_t cid;			/* ID of constant *token */
	} u;
	uint lineno;						/* Which line did this pattern start? */
	uint is_keyword:1;					/* Is string a keyword? */
	uint is_constant:1;					/* Is string a constant token? */
	uint is_case_insensitive:1;			/* Is pattern case-insensitive? */
} lf_sym_t;

enum lf_regex_magic { LF_REGEX_MAGIC = 0x7511c4e1 };

/**
 * A capturing regular expression needs to be able to save matching
 * positions for later highlighting in the log message.
 *
 * The `captured' list contains group # to capture for this particular
 * regular expression, on a successful match.
 */
typedef struct lf_regex {
	enum lf_regex_magic magic;			/* Magic number */
	re_regex_t *re;						/* Compiled expression */
	pslist_t *captured;					/* List of group # to extract */
} lf_regex_t;

static inline void
lf_regex_check(const lf_regex_t * const cre)
{
	g_assert(cre != NULL);
	g_assert(LF_REGEX_MAGIC == cre->magic);
}

/**
 * Attributes collected during parsing.
 */
typedef struct logfilter_attributes {
	uint record_matches:1;		/* They use "match", record match positions */
} lf_attributes_t;

enum lf_selector_magic {
	/* 2nd nybble varies */
	LOGFILTER_SELECTOR_BASE_MAGIC			= 0x4574bf09,
	LOGFILTER_SELECTOR_MASK_MAGIC			= 0xffffff0f,
	LOGFILTER_SELECTOR_MESSAGE_STR_MAGIC	= 0x4574bf19,
	LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC		= 0x4574bf29,
	LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC	= 0x4574bf49,
	LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC		= 0x4574bf59,
	LOGFILTER_SELECTOR_FILE_STR_MAGIC		= 0x4574bf79,
	LOGFILTER_SELECTOR_FILE_RE_MAGIC		= 0x4574bf89,
	LOGFILTER_SELECTOR_LEVEL_MAGIC			= 0x4574bfa9,
	LOGFILTER_SELECTOR_LINE_MAGIC			= 0x4574bfb9,
};

/**
 * A selector item.
 *
 * Selectors can be chained, via an embedded pointer to form a selector-list.
 */
typedef struct logfilter_selector {
	enum lf_selector_magic magic;		/* Magic number */
	struct logfilter_selector *next;	/* Next selector, NULL if none */
	uint8 negated:1;					/* Whether selection is negated */
	uint8 insensitive:1;				/* Whether matching is case-insensitive */
	uint8 capture:1;					/* Regex needs to capture matches */
	/* Following field is really a compressed enum logfilter_cmp */
	uint8 op;							/* Comparison operation for level/line */
	/* The magic number is used as union discriminant */
	union {
		const char *str;				/* Constant string (atom) */
		re_regex_t *re;					/* Non-capturing regular expression */
		lf_regex_t *cre;				/* Capturing regular expression */
		enum logfilter_log_level lvl;	/* Log level being compared against */
		ulong uv;						/* Value line being compared against */
	} u;
} lf_selector_t;

static inline void
lf_selector_check(const lf_selector_t * const ls)
{
	g_assert(ls != NULL);
	g_assert(LOGFILTER_SELECTOR_BASE_MAGIC ==
		(ls->magic & LOGFILTER_SELECTOR_MASK_MAGIC));
}

/**
 * Flag action, for instance "routine" or "noroutine".
 */
typedef struct lf_flags_op {
	uint32 set;						/* Set mask for operating flags */
	uint32 clear;					/* Clear mask for operating flags */
} lf_flags_op_t;

/**
 * Flag setting action, for instance set *mini for "carp".
 *
 * Executing this action alters the runstate by setting the args[idx]
 * element to the supplied constant token.
 */
typedef struct lf_flag_arg_op {
	uint idx;						/* Index within the args[] array */
	lf_constant_id_t arg;			/* Constant token value */
} lf_flag_arg_op_t;

enum lf_action_magic {
	/* 2nd nybble varies */
	LOGFILTER_ACTION_BASE_MAGIC				= 0x39dd5d0d,
	LOGFILTER_ACTION_MASK_MAGIC				= 0xffffff0f,
	LOGFILTER_ACTION_FLAGS_MAGIC			= 0x39dd5d1d,
	LOGFILTER_ACTION_FLAG_SET_ARG_MAGIC		= 0x39dd5d2d,
	LOGFILTER_ACTION_COPY_PATH_MAGIC		= 0x39dd5d3d,
	LOGFILTER_ACTION_COPY_OUT_MAGIC			= 0x39dd5d4d,
	LOGFILTER_ACTION_TAG_MAGIC				= 0x39dd5d5d,
	LOGFILTER_ACTION_STRIP_TAG_MAGIC		= 0x39dd5d6d,
	LOGFILTER_ACTION_STRIP_ROUTINE_MAGIC	= 0x39dd5d7d,
	LOGFILTER_ACTION_STRIP_WHERE_MAGIC		= 0x39dd5d8d,
	LOGFILTER_ACTION_COLOR_MAGIC			= 0x39dd5d9d,
	LOGFILTER_ACTION_HIGHLIGHT_MAGIC		= 0x39dd5dad
};

/**
 * A logfilter action.
 *
 * Actions can be chained via an embedded pointer.
 */
typedef struct logfilter_action {
	enum lf_action_magic magic;		/* Magic number */
	struct logfilter_action *next;	/* Next action, NULL if none */
	/* The magic number is used as union discriminant */
	union {
		lf_flags_op_t flags;		/* Change of operating flags */
		lf_flag_arg_op_t set;		/* Activate flag with argument */
		const char *value;			/* value for "tag" (atom) */
		size_t logidx;				/* Logfile index for "copy" */
		ulong gn;					/* Group number for "highlight" */
	} u;
} lf_action_t;

static inline void
lf_action_check(const lf_action_t * const la)
{
	g_assert(la != NULL);
	g_assert(LOGFILTER_ACTION_BASE_MAGIC ==
		(la->magic & LOGFILTER_ACTION_MASK_MAGIC));
}

enum lf_rule_magic { LOGFILTER_RULE_MAGIC = 0x57ea89f0 };

/**
 * A logfilter logical rule.
 *
 * It defines conditional processing instructions for a log message.
 */
typedef struct logfilter_rule {
	enum lf_rule_magic magic;		/* Magic number */
	lf_selector_t *selector_list;	/* Head of selector list, NULL if empty */
	lf_action_t *action_list;		/* Head of action list, cannot be NULL */
} lf_rule_t;

static inline void
lf_rule_check(const lf_rule_t * const lr)
{
	g_assert(lr != NULL);
	g_assert(LOGFILTER_RULE_MAGIC == lr->magic);
}

enum lf_block_magic { LOGFILTER_BLOCK_MAGIC = 0x61c88d90 };

/**
 * A logfilter block.
 *
 * After conditional selection, we have a polymorphic list of blocks or rules.
 * The magic number is used to discriminate items in the list.
 *
 * At the topmost level, all the rules are implicitly made part of an enclosing
 * block with an empty selector: the root block, from which runtime analysis of
 * filtering rules starts.
 */
typedef struct logfilter_block {
	enum lf_block_magic magic;		/* Magic number */
	lf_selector_t *selector_list;	/* Head of selector list, NULL if empty */
	pslist_t *list;					/* Polymorphic list of blocks or rules */
} lf_block_t;

static inline void
lf_block_check(const lf_block_t * const lb)
{
	g_assert(lb != NULL);
	g_assert(LOGFILTER_BLOCK_MAGIC == lb->magic);
}

/**
 * Pseudo structure to assist in rule-or-block polymorphism.
 */
typedef struct logfilter_rule_or_block {
	uint magic;		/* Magic number */
} lf_rule_or_block_t;

/**
 * Used to auto-number the argument index and compute the maximum amount
 * of tokens that can take an argument in LF_ARG_MAX.
 */
enum logfilter_argument_index {
	LF_ARG_CARP = 0,

	LF_ARG_MAX
};

/**
 * Which of the actions can take a constant argument to configure
 * their runtime behaviour?
 *
 * This maps a token taking an optional argument to configure its mode
 * of operation (e.g. "carp") with the index in the args[] arrray where
 * we store this information, dynamic since rules can and will alter the
 * default value depending on some selection.
 *
 * To avoid linear scanning of this table at parsing time, we setup
 * a hash table mapping the id to the idx,
 */
struct logfilter_action_args {
	const char *name;				/* Token name */
	uint idx;						/* Position in the argument array */
} logfilter_flag_arguments[LF_ARG_MAX] = {
	{ "carp",		LF_ARG_CARP },
};

/**
 * Used at parsing time to map an action token to the position of its
 * argument in the args[] array.
 */
static htable_t *logfilter_action_map;	/* Maps LF_TOK_CARP -> LF_ARG_CARP */

/**
 * Used at dumping time to map an action string to the position of its
 * argument in the args[] array.
 */
static htable_t *logfilter_flags_map;	/* Maps "carp" -> LF_ARG_CARP */

/**
 * Used at runtime to map an argument position to its token: that is the
 * reverse mapping of logfilter_action_map.
 */
static lf_token_id_t logfilter_arg2token_map[LF_ARG_MAX];

/**
 * Used at runtime to map a token with arguments to a string.
 */
static const char *logfilter_arg2token_string[LF_ARG_MAX];

enum logfile_runstate_magic { LOGFILTER_RUNSTATE_MAGIC = 0x7b73561a };

/**
 * Attribute runtime state.
 *
 * This records the operating flags, plus the additional logfiles we need
 * to copy log messages into.
 */
typedef struct logfile_runstate {
	enum logfile_runstate_magic magic;	/* Magic number */
	enum logfilter_log_level level;		/* Message log level */
	uint32 flags;					/* Operating flags */
	size_t loglen;					/* Length of log message */
	size_t filelen;					/* Length of file name */
	size_t routlen;					/* Length of routine name */
	pslist_t *copy;					/* List of logfiles to copy message to */
	pslist_t *tag;					/* List of tags to prepend to message */
	pslist_t *strip;				/* List of tags to strip from message */
	pslist_t *match;				/* List of match positions */
	pslist_t *highlight;			/* List of highlighted positions */
	const char *logmsg;				/* Initial log message */
	const char *file;				/* source file (SRC_PREFIX removed) */
	const char *color;				/* Escape sequence to color message */
	const logfilter_data_t *data;	/* Meta-data about message */
	re_match_t *mvec;				/* Captures matching positions */
	size_t mlen;					/* Capacity of mvec[] */
	lf_attributes_t attrs;			/* Attributes collected during parsing */
	lf_constant_id_t args[LF_ARG_MAX];	/* Action arguments */
} lf_runstate_t;

static inline void
lf_runstate_check(const lf_runstate_t * const lrs)
{
	g_assert(lrs != NULL);
	g_assert(LOGFILTER_RUNSTATE_MAGIC == lrs->magic);
}

/**
 * Operating flags.
 */

#define LF_FLG_BREAK	(1U << 0)	/* Continue matching rules */
#define LF_FLG_CARP		(1U << 1)	/* Add additional stacktrace */
#define LF_FLG_LEVEL	(1U << 2)	/* Log message level */
#define LF_FLG_STDERR	(1U << 3)	/* Log message to stderr */
#define LF_FLG_ROUTINE	(1U << 4)	/* Include routine name */
#define LF_FLG_WHERE	(1U << 5)	/* Include code location */
#define LF_FLG_IGNORE	(1U << 6)	/* Ignore message altogether */
#define LF_FLG_NEXT		(1U << 7)	/* Move to next rule, disregard break */
#define LF_FLG_STOP		(1U << 8)	/* Stop at this rule, disregard break */
#define LF_FLG_MATCH	(1U << 9)	/* Highlight matched string */

#define LF_FLG_NOROUTINE (1U << 28)	/* Remove routine name from message */
#define LF_FLG_NOWHERE	(1U << 29)	/* Remove code location from message */
#define LF_FLG_STDOUT	(1U << 30)	/* Copy log message to stdout */
#define LF_FLG_SELECTED	(1U << 31)	/* Selection on sth. other than "level" */

/*
 * The parser context.
 */

enum lf_parser_magic { LOGFILTER_PARSER_MAGIC = 0x53ec7f8d };

/**
 * The parsing context
 */
typedef struct logfilter_parser {
	enum lf_parser_magic magic;	/* Magic number */
	istream_t *is;				/* Input stream */
	symtab_t *variables;		/* Symbol table for variables */
	htable_t *logfiles;			/* Additional logfiles used for "copy" */
	htable_t *options;			/* Recorded options */
	lf_block_t *root;			/* Root block we parsed */
	lf_block_t *current_block;	/* Current block we are in */
	lf_sym_t token;				/* Parsed lexical symbol */
	lf_sym_t previous;			/* Previously parsed lexical symbol */
	lf_sym_t saved_token;		/* Unread previously parsed symbol */
	xslist_t selector_list;		/* Current selection */
	xslist_t action_list;		/* Current actions */
	lf_flags_op_t flags;		/* Flags to be modified by actions */
	lf_attributes_t attrs;		/* Static attributes gathered during parsing */
	lf_constant_id_t args[LF_ARG_MAX];	/* Action arguments */
	uint lineno;				/* Line number in input */
	uint depth;					/* Current block depth */
	uint disabled;				/* Parsing a disabled block (depth) */
	uint in_options;			/* Parsing an options block (depth) */
	uint unread:1;				/* Act as if `token' was unread */
	uint has_saved:1;			/* Has read-ahead token in "saved_token" */
} lf_parser_t;

static inline void
lf_parser_check(const lf_parser_t * const lp)
{
	g_assert(lp != NULL);
	g_assert(LOGFILTER_PARSER_MAGIC == lp->magic);
}

typedef enum logfilter_parse_status {
	LF_PARSE_EMPTY = 0,			/* OK, there was no element */
	LF_PARSE_OK,				/* OK, parsed correctly */
	LF_PARSE_ERROR,				/* Failed to parse element */
} lf_parse_status_t;

/**
 * Custom position for "where" source information in the log message.
 */
enum lf_where {
	LF_WHERE_START = 1,			/* Source information at the start of log */
	LF_WHERE_END				/* Source information at the end of log */
};

/**
 * Match highlighting styles.
 */
enum lf_match {
	LF_MATCH_UNDERLINE = 1,		/* Underline matched text */
	LF_MATCH_INVERSE,			/* Put matched text in reverse video */
	LF_MATCH_BLINK,				/* Blinking matched text */
};

/*
 * Known options.
 */
enum lf_option {
	LF_OPTION_HIGHLIGHT = 1,
	LF_OPTION_MATCH,
	LF_OPTION_WHERE,

	LF_OPTION_MAX
};

/**
 * User-defined options.
 */
typedef struct logfilter_options {
	enum lf_match highlight;
	enum lf_where where;
	enum lf_match match;
} lf_options_t;

/**
 * A user-defined logfile to which we may send log information via the
 * "copy" filtering directive.
 */
typedef struct logfilter_logfile {
	const char *path;			/* File path */
	int fd;						/* Opened file descriptor */
} lf_logfile_t;

static lf_block_t *logfilter_root_block;	/* Where filtering starts from */
static lf_logfile_t *logfilter_logs;		/* Array of additional logfiles */
static size_t logfilter_logs_cnt;			/* Amount of additional logfiles */
static lf_options_t logfilter_options; 		/* Changed via an options{} block */
static lf_attributes_t logfilter_attrs;		/* Computed during parsing */

/**
 * Option handler callback, during configuration.
 *
 * @param value		the option value, as supplied by user
 *
 * @return TRUE if option value was correctly processed.
 */
typedef bool (*lf_option_handler_t)(const char *value);

/**
 * The rwlock protecting the global data structures.
 *
 * Since we have many users concurrently reading, and, once in a while,
 * a thread updating the global data structures (when reloading the
 * filtering rules), we are exhibiting the textbook case for read-write locks!
 */
static rwlock_t logfilter_lck = RWLOCK_INIT;

#define LOGFILTER_READ_LOCK			rwlock_rlock(&logfilter_lck)
#define LOGFILTER_READ_UNLOCK		rwlock_runlock(&logfilter_lck)
#define LOGFILTER_IS_READ_LOCKED	rwlock_is_taken(&logfilter_lck)

#define LOGFILTER_WRITE_LOCK		rwlock_wlock(&logfilter_lck)
#define LOGFILTER_WRITE_UNLOCK		rwlock_wunlock(&logfilter_lck)
#define LOGFILTER_DOWNGRADE_LOCK	rwlock_downgrade(&logfilter_lck)
#define LOGFILTER_IS_WRITE_LOCKED	rwlock_is_owned(&logfilter_lck)

/**
 * Keywords and their associated token value.
 */
static const tokenizer_t logfilter_keywords[] = {
	/* Sorted array */
	{ "break",		LF_TOK_BREAK },
	{ "carp",		LF_TOK_CARP },
	{ "color",		LF_TOK_COLOR },
	{ "copy",		LF_TOK_COPY },
	{ "critical",	LF_TOK_CRITICAL },
	{ "debug",		LF_TOK_DEBUG },
	{ "disable",	LF_TOK_DISABLE },
	{ "enable",		LF_TOK_ENABLE },
	{ "err",		LF_TOK_ERR },
	{ "file",		LF_TOK_FILE },
	{ "highlight",	LF_TOK_HIGHLIGHT },
	{ "ignore",		LF_TOK_IGNORE },
	{ "info",		LF_TOK_INFO },
	{ "level",		LF_TOK_LEVEL },
	{ "line",		LF_TOK_LINE },
	{ "log",		LF_TOK_LOG },
	{ "match",		LF_TOK_MATCH },
	{ "message",	LF_TOK_MESSAGE },
	{ "next",		LF_TOK_NEXT },
	{ "nobreak",	LF_TOK_NOBREAK },
	{ "nocarp",		LF_TOK_NOCARP },
	{ "nolevel",	LF_TOK_NOLEVEL },
	{ "nolog",		LF_TOK_NOLOG },
	{ "nomatch",	LF_TOK_NOMATCH },
	{ "noroutine",	LF_TOK_NOROUTINE },
	{ "nowhere",	LF_TOK_NOWHERE },
	{ "options",	LF_TOK_OPTIONS },
	{ "out",		LF_TOK_OUT },
	{ "routine",	LF_TOK_ROUTINE },
	{ "stop",		LF_TOK_STOP },
	{ "strip",		LF_TOK_STRIP },
	{ "tag",		LF_TOK_TAG },
	{ "warning",	LF_TOK_WARNING },
	{ "where",		LF_TOK_WHERE },
};

/**
 * Keywords for options.
 */
static const tokenizer_t logfilter_option_names[] = {
	/* Sorted array */
	{ "highlight",	LF_OPTION_HIGHLIGHT },
	{ "match",		LF_OPTION_MATCH },
	{ "where",		LF_OPTION_WHERE },
};

/**
 * Possible values for the "match" and "highlight" options.
 */
static const tokenizer_t logfilter_match_option_values[] = {
	/* Sorted array */
	{ "blink",		LF_MATCH_BLINK },
	{ "inverse",	LF_MATCH_INVERSE },
	{ "underline",	LF_MATCH_UNDERLINE },
};

/**
 * Possible values for the "where" option.
 */
static const tokenizer_t logfilter_where_option_values[] = {
	/* Sorted array */
	{ "end",		LF_WHERE_END },
	{ "start",		LF_WHERE_START },
};

/**
 * Constant token strings, without leading '*' character.
 */
static const tokenizer_t logfilter_constant_tokens[] = {
	/* Sorted array */
	{ "full",		LF_CTOK_FULL },
	{ "hexa",		LF_CTOK_HEXA },
	{ "mini",		LF_CTOK_MINI },
	{ "name",		LF_CTOK_NAME },
};

/*
 * Punctuation that can define a regular expression after 'm'.
 */
static const char logfilter_re_punct[] = ",!:%|/";

static bool logfilter_crashing;		/* Set when crashing */
static uint32 logfilter_debug;		/* Debug level for logfilter */

/*
 * At runtime (during execution of log filtering actions), we must avoid
 * memory allocation if possible!
 *
 * Whenever we have to construct lists dynamically, we therefore use a
 * specific cell allocator that will grab the memory blocks from a
 * memory zone we initialize and that only the logfilter uses.
 *
 * Memory allocation and freeing from the user zone will be very fast,
 * and the zone is initially setup to be large enough.
 *
 * Reserving 24 cells per thread, knowing that not all the threads will
 * be logging all at the same time and require cell allocation, should be
 * enough for our purposes.
 *
 * Allocation within this global buffer is done via the balloc layer,
 * which is completely distinct from all the other allocators to make
 * it possible to log from other memory allocators, precisely.
 */
static char lf_pslist_cells[sizeof(pslist_t) * 24 * THREAD_MAX];

/*
 * Same logic for storing matching position of regular expression matches:
 * memory is pre-allocated and shared amongst all the threads.
 *
 * Here however memory is allocated using balloc_try_alloc(), which is allowed
 * to return NULL when there is no more room.  Hence we can limit the amount
 * of memory used because it is not so dramatic if we run out of memory: we
 * just stop recording match positions.
 */
static char lf_match_positions[sizeof(re_match_t) * 8 * THREAD_MAX];

/**
 * Notification that the process is crashing.
 */
void G_COLD
logfilter_crash_mode(void)
{
	logfilter_crashing = TRUE;
}

/**
 * Set the logfilter debug level.
 */
void
logfilter_set_debug(uint32 level)
{
	logfilter_debug = level;
}

/**
 * Are we debugging the logfilter level at or above the specified level?
 */
static inline bool
lf_debugging(uint32 level)
{
	return logfilter_debug >= level;
}

/**
 * Cell allocator callback for pslist_t.
 */
static void *
lf_pslist_cell_alloc(void)
{
	return balloc_alloc(lf_pslist_cells);
}

/**
 * Cell allocator callback for pslist_t.
 */
static void
lf_pslist_cell_free(void *cell)
{
	balloc_free(lf_pslist_cells, cell);
}

/**
 * Cell allocator callback for pslist_t.
 */
static void
lf_pslist_free_all(void *pl)
{
	balloc_free_pslist(lf_pslist_cells, pl);
}

static pcell_alloc_t lf_pslist_alloc = {
	lf_pslist_cell_alloc,		/* pcell_alloc */
	lf_pslist_cell_free,		/* pcell_free */
	lf_pslist_free_all,			/* pcell_listfree */
};

/**
 * Given pathname of new logfile, return its predicted index in the global
 * logfile array logfilter_logs[].
 */
static size_t
lf_logfile_get_index(lf_parser_t *lp, const char *path)
{
	const void *v;
	size_t idx;

	lf_parser_check(lp);
	g_assert(path != NULL);

	v = htable_lookup(lp->logfiles, path);
	if (v != NULL)
		return pointer_to_size(v) - 1;		/* Already known */

	/*
	 * We have never seen this logfile before, so allocate a new index for
	 * it.  To avoid storing 0 (which can appear as NULL), we store the
	 * index + 1 in the hash table.
	 */

	idx = htable_count(lp->logfiles) + 1;
	htable_insert(lp->logfiles, atom_str_get(path), size_to_pointer(idx));

	return idx - 1;		/* Actual index we have chosen */
}

/**
 * Allocates a block.
 */
static lf_block_t *
lf_block_alloc(void)
{
	lf_block_t *lb;

	WALLOC0(lb);
	lb->magic = LOGFILTER_BLOCK_MAGIC;

	return lb;
}

/**
 * Translate log level to string.
 */
static const char *
lf_log_level_string(uint lvl)
{
	if (lvl < N_ITEMS(logfilter_log_level_str))
		return logfilter_log_level_str[lvl];

	return "loglevel?";
}

/**
 * Translate level comparison operation to string.
 */
static const char *
lf_cmp_string(uint op)
{
	if (op < N_ITEMS(logfilter_cmp_str))
		return logfilter_cmp_str[op];

	return "cmp?";
}

/**
 * Given a known keyword, return the static keyword string.
 */
static const char *
lf_keytok_to_string(int tok)
{
	g_assert(tok >= 1 && tok < LF_TOK_MAX_KEYWORD);

	/*
	 * This assert makes sure that, given a token ID of x, the keyword
	 * is held as logfilter_keywords[x-1].token.
	 */

	STATIC_ASSERT(LF_TOK_MAX_KEYWORD - 1 == N_ITEMS(logfilter_keywords));

	return logfilter_keywords[tok - 1].token;
}

/**
 * Stringify regular expression.
 */
static const char *
lf_regex_as_string(const re_regex_t *re)
{
	str_t *s = str_private(G_STRFUNC, 0);
	char *dump = re_dump_as_string(re);

	str_cpy(s, dump);
	HFREE_NULL(dump);

	/*
	 * To differentiate a static pattern with a regular expression, we
	 * use the m!! form to display a regular expression.
	 */

	if (re_is_simple(re)) {
		str_escape(s, '/', '\\');	/* Our delimiter is /, so escape them */
		str_ichar(s, 0, '/');		/* Prepend the opening of the pattern */
		str_putc(s, '/');			/* Terminates the pattern */
	} else {
		str_escape(s, '!', '\\');	/* Our delimiter is !, so escape them */
		str_istr(s, 0, "m!");		/* Prepend the opening of the regex */
		str_putc(s, '!');			/* Terminates the regular expression */
	}

	return str_2c(s);
}

/**
 * Convernt constant token as string.
 */
static const char *
lf_constant_string(lf_constant_id_t cid)
{
	switch (cid) {
	case LF_CTOK_NONE: return "*INVALID";
	case LF_CTOK_HEXA: return "*hexa";
	case LF_CTOK_FULL: return "*full";
	case LF_CTOK_MINI: return "*mini";
	case LF_CTOK_NAME: return "*name";
	}

	return "*UNKNOWN";
}

/**
 * Stringify current lexical symbol, for error reporting and debugging.
 */
static const char *
lf_sym_as_string(const lf_sym_t *t)
{
	str_t *s = str_private(G_STRFUNC, 0);

	if (t->is_keyword)
		return t->u.keyword;

	if (t->is_constant)
		return lf_constant_string(t->u.cid);

	switch (t->id) {
	case LF_TOK_IDENT:		return t->u.str;
	case LF_TOK_EOF:		return "<EOF>";
	case LF_TOK_ERROR:		return "*ERROR*";
	case LF_TOK_STR:
		str_printf(s, "\"%s\"", t->u.str);
		return str_2c(s);
	case LF_TOK_REGEX:
		if (t->u.re != NULL) {
			str_cpy(s, lf_regex_as_string(t->u.re));
			if (t->is_case_insensitive)
				str_putc(s, 'i');
			return str_2c(s);
		} else
			return "regex";
	case LF_TOK_MAX:
	case LF_TOK_MAX_KEYWORD:
		g_assert_not_reached();
	default:
		break;
	}

	g_assert(clamp_strlen(ARYLEN(t->u.c)) < N_ITEMS(t->u.c));

	return t->u.c;
}

/**
 * @return string associated with given "where" option.
 */
static const char *
lf_option_where_as_string(enum lf_where v)
{
	switch (v) {
	case LF_WHERE_START: return "start";
	case LF_WHERE_END:   return "end";
	}

	return "UNKNOWN";
}

/**
 * @return string associated with given "match" option.
 */
static const char *
lf_option_match_as_string(enum lf_match v)
{
	switch (v) {
	case LF_MATCH_UNDERLINE: return "underline";
	case LF_MATCH_INVERSE:   return "inverse";
	case LF_MATCH_BLINK:     return "blink";
	}

	return "UNKNOWN";
}

/**
 * Is character a valid regular expression "punctuation"?
 */
static bool
lf_is_re_punct(int c)
{
	const char *s = logfilter_re_punct;
	int x;

	while ((x = *s++)) {
		if (x == c)
			return TRUE;
	}

	return FALSE;
}

/**
 * Is token ID a real value (or a special value like LF_TOK_ERROR)?
 */
static bool
lf_token_is_real(lf_token_id_t id)
{
	switch (id) {
	case LF_TOK_NONE:
	case LF_TOK_MAX_KEYWORD:
	case LF_TOK_ERROR:
	case LF_TOK_MAX:
		return FALSE;
	default:
		return TRUE;
	}
}

/**
 * @return printable version of input character code.
 */
static const char *
lf_print_char(int c)
{
	str_t *s = str_private(G_STRFUNC, 10);

	if (is_ascii_print(c))
		str_printf(s, "'%c'", c);
	else
		str_printf(s, "ASCII %d", c);

	return str_2c(s);
}

/**
 * Formats location in parser.
 *
 * This generates a string like: "near 'blah' at line 125" or simply
 * "at line 125" if we do not have a token parsed already.  If we have
 * a known previous token on the same line, prepend "after 'foo',".
 *
 * @return pointer to thread-private string.
 */
static const char *
lf_parser_where(const lf_parser_t *lp)
{
	str_t *s = str_private(G_STRFUNC, 0);
	const lf_sym_t *p = &lp->previous;
	const lf_sym_t *t = &lp->token;

	lf_parser_check(lp);

	str_reset(s);

	/*
	 * If we have a previous token at the same line where we are, then log
	 * that previous token.
	 */

	if (lf_token_is_real(p->id) && p->lineno == lp->lineno)
		str_printf(s, "after '%s'", lf_sym_as_string(p));

	/*
	 * If we have a current token, log it.
	 */

	if (lf_token_is_real(t->id)) {
		if (0 != str_len(s))
			str_putc(s, ' ');
		str_catf(s, "near '%s'", lf_sym_as_string(t));
	}

	/*
	 * Always terminate the message with the current line number.
	 */

	if (0 != str_len(s))
		str_putc(s, ' ');

	str_catf(s, "at line %u", lp->lineno);

	return str_2c(s);
}

/**
 * Emit a parsing warning.
 */
static void G_PRINTF(2, 3)
lf_parser_warn(const lf_parser_t *lp, const char *fmt, ...)
{
	va_list args;
	str_t *s = str_new(0);

	lf_parser_check(lp);

	va_start(args, fmt);
	str_vprintf(s, fmt, args);
	va_end(args);

	s_warning("LOGFILTER %s %s", str_2c(s), lf_parser_where(lp));

	str_destroy(s);
}

/**
 * Report a parsing error.
 *
 * @return LF_PARSE_ERROR as a convenience.
 */
static lf_parse_status_t G_PRINTF(2, 3)
lf_parser_error(const lf_parser_t *lp, const char *fmt, ...)
{
	va_list args;
	str_t *s = str_new(0);

	lf_parser_check(lp);

	va_start(args, fmt);
	str_vprintf(s, fmt, args);
	va_end(args);

	s_warning("LOGFILTER syntax error: %s %s", str_2c(s), lf_parser_where(lp));
	str_destroy(s);

	return LF_PARSE_ERROR;
}

/**
 * Emit debugging message if log level is above the one specified.
 */
static void G_PRINTF(3, 4)
lf_parser_debug_lvl(uint32 level, const lf_parser_t *lp, const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	if (!lf_debugging(level))
		return;

	va_start(args, fmt);
	str_vbprintf(ARYLEN(buf), fmt, args);
	va_end(args);

	s_debug("LOGFILTER %s: %s",	lf_parser_where(lp), buf);
}

/**
 * Grab and ignore everything until EOF or end-of-line.
 */
static void
lf_ignore_eol(const lf_parser_t *lp)
{
	int c;

	while (-1 != (c = istream_getc(lp->is))) {
		if ('\n' == c)
			return;
	}
}

/**
 * Grab quoted string.
 *
 * The intial opening quote has been read already.
 * A '\' is necessary to escape the '"' character, or a '\' itself.
 *
 * Since strings are only used to specify additional log files, there is no
 * need to allow control characters in strings like "\n" or "\t".
 *
 * If there is a syntax error, it is reported before return NULL.
 *
 * @return parsed string, without the final '"', or NULL in case of syntax error.
 */
static char *
lf_grab_quoted_string(const lf_parser_t *lp)
{
	str_t *s = str_new(128);
	int c;

	while (-1 != (c = istream_getc(lp->is))) {
		/*
		 * Handle supported escape sequences.
		 */

		if G_UNLIKELY ('\\' == c) {
			int x = istream_getc(lp->is);

			if (-1 == x)
				goto eof;

			switch (x) {
			case '\\':
				break;		/* c is still '\\' */
			case '"':
				c = x;
				break;
			default:
				if (is_ascii_cntrl(x))
					goto control;
				lf_parser_error(lp, "unsupported escape \\%c in string", x);
				goto error;
			}
		}

		if G_UNLIKELY(is_ascii_cntrl(c))
			goto control;

		if G_UNLIKELY('"' == c)
			return str_s2c_null(&s);	/* Got whole string successfully */

		str_putc(s, c);
	}

	/* FALL THROUGH */

eof:
	lf_parser_error(lp, "got EOF whilst parsing string");

	/* FALL THROUGH */

error:
	str_destroy(s);
	return NULL;

control:
	lf_parser_error(lp,
		"got control %s whilst parsing string", lf_print_char(c));
	goto error;
}

/**
 * Extract regular expression to match from a selector.
 *
 * @return NULL if this is not a regex selector, the regex pointer otherwise.
 */
static re_regex_t *
lf_selector_regex(const lf_selector_t *ls)
{
	lf_selector_check(ls);

	switch (ls->magic) {
	case LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC:
	case LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC:
	case LOGFILTER_SELECTOR_FILE_RE_MAGIC:
		break;
	default:
		return NULL;		/* Not a regex selector */
	}

	if (ls->capture) {
		lf_regex_t *cre = ls->u.cre;
		lf_regex_check(cre);
		return cre->re;
	} else {
		return ls->u.re;
	}
}

/**
 * Parse regular expression up-to the unescaped character 'e'.
 *
 * If the regular expression is valid, return LF_TOK_REGEX as appropriate,
 * and fill the corresponding current token with the compiled object.
 *
 * Otherwise return LF_TOK_ERROR after reporting the syntax error.
 */
static lf_token_id_t
lf_parse_regex(lf_parser_t *lp, const int e)
{
	static const char re_escape[] = "^.[$()|*+?{\\";
	str_t *s = str_new(0);
	int c;
	bool case_insensitive = FALSE;
	lf_sym_t *t = &lp->token;

	g_assert(e != -1);

	while (-1 != (c = istream_getc(lp->is))) {
		if (e == c)
			goto parsed;

		/*
		 * Handle escapes.  We only trap escapes of the ending character.
		 * Any other is let through as-is.
		 */

		if G_UNLIKELY('\\' == c) {
			int x = istream_getc(lp->is);

			if (-1 == x)
				break;

			if (x == e) {
				/* An escaped delimiter stands for itself (could be a meta) */
				if (NULL != vstrchr(re_escape, x))
					str_putc(s, c);	/* The '\\' */
			} else {
				str_putc(s, c);	/* The '\\' */
			}
			c = x;				/* The character following '\\' */
		}

		str_putc(s, c);
	}

	lf_parser_error(lp, "got EOF whilst parsing regular expression");
	goto error;

parsed:
	/*
	 * Look ahead the next character to check whether the regular expression
	 * should be applied case-insensitively.
	 */

	c = istream_getc(lp->is);

	if ('i' == c)
		case_insensitive = TRUE;
	else
		istream_ungetc(lp->is, c);

	/*
	 * The string holds the full regular expression we parsed.
	 */

	{
		re_error_t error;

		g_assert(NULL == t->u.re);

		t->u.re = re_compile(str_2c(s),
			(case_insensitive ? RE_F_ICASE : 0), &error);

		if (NULL == t->u.re) {
			lf_parser_error(lp, "invalid regex %s: %s at offset %zu",
				  str_2c(s), re_strerror(error.code), error.pos);
			goto error;
		}
	}

	t->is_case_insensitive = booleanize(case_insensitive);
	str_destroy(s);
	return LF_TOK_REGEX;

error:
	str_destroy(s);
	return LF_TOK_ERROR;
}

/**
 * Is the string made up of digits only (ignoring any '_')?
 *
 * @param s		the string to analyze
 *
 * @return TRUE if the string could be parsed as an integer
 */
static bool
lf_digits_only(const char *s)
{
	const char *p = s;
	int c;

	while ((c = *p++)) {
		if ('_' == c || is_ascii_digit(c))
			continue;
		return FALSE;
	}

	return TRUE;
}

/**
 * Parse string as an unsigned long, ignoring '_' in the string.
 *
 * If the integer cannot fit in the string, loudly warn and use
 * the maximum integer we can fit as the value.
 *
 * @param lp		the parser
 * @param s			the string to convert to ulong
 *
 * @return the parsed ulong value
 */
static ulong
lf_keytok_to_ulong(lf_parser_t *lp, const char *s)
{
	const char *p = s;
	int c;
	ulong v = 0, mm;

	mm = (ulong) -1 / 10;	/* Maximum multiplicand before overflowing */

	while ((c = *p++)) {
		int d;
		ulong w;

		/*
		 * Supporting '_' in integers is a "free feature" of our lexical
		 * parsing: we recognize identifiers first, and then look whether
		 * they are keywords or integers.  Because '_' is accepted in
		 * identifiers, we can get '_' here.
		 *
		 * This makes numbers easier to read: 1153846 versus 1_153_846.
		 */

		if ('_' == c)
			continue;

		d = alnum2int_inline(c);
		w = v * 10;

		if (v > mm || (ulong) -1 - w < (ulong) d) {
			lf_parser_warn(lp, "interger overflow, capping to maximum");
			return MAX_INT_VAL(ulong);
		}

		v = w + d;
	}

	return v;
}

/**
 * Cleanup token, freeing dynamically allocated strings.
 */
static void
lf_token_cleanup(lf_sym_t *t)
{
	switch (t->id) {
	case LF_TOK_IDENT:
	case LF_TOK_STR:
		HFREE_NULL(t->u.str);
		break;
	case LF_TOK_REGEX:
		re_free_null(&t->u.re);
		break;
	default:
		break;
	}
}

/*
 * Unread current lexical token.
 *
 * Next time lf_next_token() will be called, the current lexical token will
 * be returned again.
 */
static void
lf_unread_token(lf_parser_t *lp)
{
	lf_parser_check(lp);

	lp->unread = TRUE;
}

/**
 * Rewind to the previous token and unread it.
 *
 * @return the ID of the previous token, with further information in lp->token.
 */
static lf_token_id_t
lf_rewind_token(lf_parser_t *lp)
{
	/*
	 * The current token has already been read, we cannot lose it.
	 * Save it away.
	 *
	 * lf_next_token() will first return the previous token (which we are
	 * about to mark unread, then the saved token, preserving the reading
	 * order).
	 *
	 */

	/* Save current token in "saved_token" */
	g_assert(!lp->has_saved);
	lp->has_saved = TRUE;
	lp->saved_token = lp->token;	/* struct copy */
	ZERO(&lp->token);

	/* Restore "previous" as the current token, marked unread */
	lf_token_cleanup(&lp->token);
	lp->token = lp->previous;
	ZERO(&lp->previous);
	lp->unread = TRUE;

	return lp->token.id;
}

/**
 * Get the next lexical token.
 *
 * @param lp		the parsing context
 *
 * @return the ID of the recognized token, with further information in lp->token.
 */
static lf_token_id_t
lf_next_token(lf_parser_t *lp)
{
	lf_sym_t *t = &lp->token;
	int c, x;
	str_t *s = NULL;

	lf_parser_check(lp);

	/*
	 * If the token is marked unread, clear the unread status and return
	 * the current token.
	 */

	if G_UNLIKELY(lp->unread) {
		lp->unread = FALSE;
		goto done;
	}

	/*
	 * To be able to achieve a 2-token look-ahaed, we sometimes need to
	 * save the unread token, the one we want to return next time we
	 * call lf_next_token().
	 */

	if G_UNLIKELY(lp->has_saved) {
		lp->has_saved = FALSE;
		lf_token_cleanup(&lp->previous);
		lp->previous = lp->token;		/* struct copy */
		lp->token = lp->saved_token;	/* struct copy */
		ZERO(&lp->saved_token);
		goto done;
	}

	/*
	 * Save previous token, which is useful in case there is a syntax error,
	 * and also allows us to perform a look-ahead over the next 2 tokens.
	 */

	lf_token_cleanup(&lp->previous);
	lp->previous = lp->token;	/* struct copy */
	ZERO(t);

	/*
	 * Start parsing.
	 */

	t->lineno = lp->lineno;		/* Line where token starts */

restart:

	c = t->u.c[0] = istream_getc(lp->is);

	switch (c) {
	case -1:	goto eof;
	case ';':	return t->id = LF_TOK_SC;
	case ',':	return t->id = LF_TOK_COMMA;
	case ':':	return t->id = LF_TOK_COLON;
	case '{':	return t->id = LF_TOK_LBRACE;
	case '}':	return t->id = LF_TOK_RBRACE;
	case '=':	return t->id = LF_TOK_EQ;
	case '<':
	case '>':
	case '!':
		/* Must look-ahead to see whether we get an '=' or not */
		x = istream_getc(lp->is);
		if ('=' != x) {
			/* No '=' after the initial character */
			istream_ungetc(lp->is, x);
			switch (c) {
			case '<':	return t->id = LF_TOK_LT;
			case '>':	return t->id = LF_TOK_GT;
			case '!':	return t->id = LF_TOK_NOT;
			}
		} else {
			/* We read an '=' after the initial character */
			t->u.c[1] = x;
			switch (c) {
			case '<':	return t->id = LF_TOK_LTE;
			case '>':	return t->id = LF_TOK_GTE;
			case '!':	return t->id = LF_TOK_NE;
			}
		}
		g_assert_not_reached();
	case '"':
		t->u.str = lf_grab_quoted_string(lp);
		if (NULL == t->u.str)
			return LF_TOK_ERROR;	/* Syntax error already reported */
		return t->id = LF_TOK_STR;
	case '*':
		c = istream_getc(lp->is);
		if (is_ascii_alpha(c)) {
			t->is_constant = TRUE;
			goto id_or_keyword;
		}
		lf_parser_error(lp, "expected alphabetic character following *");
		return LF_TOK_ERROR;
	case '#':
		lf_ignore_eol(lp);
		lp->lineno++;
		goto restart;
	case '\r':
		x = istream_getc(lp->is);
		if (x != '\n')
			goto unexpected;
		/* Fall through */
	case '\n':
		lp->lineno++;
		/* FALL THROUGH */
	case ' ':
	case '\t':
		goto restart;		/* skip spaces and end-of-lines */
	case 'm':
		x = istream_getc(lp->is);
		/*
		 * This could be the start of a regular expression if we have a
		 * valid regular-expression punctuation character.
		 */
		if (!lf_is_re_punct(x)) {
			/* Not a regular expression start, unread character */
			istream_ungetc(lp->is, x);
			goto id_or_keyword;
		}
		c = x;		/* This will be the regular expression terminating char */
		/* FALL THROUGH */
	case '/':
		t->u.c[0] = '\0';	/* Ignore start of regex */
		return t->id = lf_parse_regex(lp, c);
	case '(':
		/* Must look-ahead to see whether we get an ')' or not */
		x = istream_getc(lp->is);
		if (')' == x) {
			t->u.c[1] = x;
			return t->id = LF_TOK_PARENS;
		}
		istream_ungetc(lp->is, x);
		/* FALL THROUGH */
	default:
		if (is_ascii_lower(c) || is_ascii_digit(c))
			goto id_or_keyword;

		goto unexpected;
	}

	g_assert_not_reached();

id_or_keyword:
	/*
	 * We are expecting an id or a keyword, so read alphanumeric characters.
	 */

	s = str_new(0);
	str_putc(s, c);

	while (-1 != (c = istream_getc(lp->is))) {
		if (!is_ascii_alnum(c) && c != '_') {
			istream_ungetc(lp->is, c);
			break;
		}
		str_putc(s, c);
	}

	/*
	 * If we already determined the coming word was a constant,
	 * tokenize it as such.
	 */

	if (t->is_constant) {
		const char *name = str_2c(s);
		t->id = LF_TOK_CONSTANT;
		t->u.cid = TOKENIZE(name, logfilter_constant_tokens);
		if (0 == t->u.cid) {
			/* Unrecognized constant */
			t->id = LF_TOK_NONE;
			lf_parser_error(lp, "unknown constant '*%s'", name);
			return LF_TOK_ERROR;
		}
		goto done;
	}

	/*
	 * We have an ID, try a keyword first.
	 */

	t->id = TOKENIZE(str_2c(s), logfilter_keywords);

	if (LF_TOK_NONE != t->id) {
		/* We have a known keyword */
		t->is_keyword = TRUE;
		t->u.keyword = lf_keytok_to_string(t->id);
		goto done;
	}

	/*
	 * If the identifier we have is made up of digits (ignoring '_'),
	 * then we have an unsigned integer value.
	 */

	if (lf_digits_only(str_2c(s))) {
		/* We have an integer */
		t->id = LF_TOK_UV;
		t->u.uv = lf_keytok_to_ulong(lp, str_2c(s));
		goto done;
	}

	/*
	 * We have our last option at this stage: an identifier.
	 */

	t->u.str = str_dup(s);
	t->id = LF_TOK_IDENT;

	/* FALL THROUGH */

done:
	str_destroy_null(&s);

	lf_parser_debug_lvl(10, lp, "%s(): got %s", G_STRFUNC, lf_sym_as_string(t));

	return t->id;

eof:
	return t->id = LF_TOK_EOF;

unexpected:
	/* Unexpected character in variable `c' */

	lf_parser_error(lp, "unexpected character %s", lf_print_char(c));
	return t->id = LF_TOK_ERROR;
}

/**
 * Look ahead for the next token.
 */
static lf_token_id_t
lf_look_ahead_token(lf_parser_t *lp)
{
	lf_token_id_t id;

	id = lf_next_token(lp);
	lf_unread_token(lp);

	return id;
}

/**
 * Allocate a new logfilter parser.
 *
 * @param is		the input stream from which we get the logfilter rules
 *
 * @return a new logfilter parser
 */
static lf_parser_t *
lf_parser_alloc(istream_t *is)
{
	lf_parser_t *lp;

	WALLOC0(lp);
	lp->magic = LOGFILTER_PARSER_MAGIC;
	lp->is = is;
	lp->lineno = 1;
	lp->variables = symtab_make();
	lp->logfiles = htable_create(HASH_KEY_STRING, 0);
	lp->options  = htable_create(HASH_KEY_STRING, 0);
	lp->root = lf_block_alloc();
	lp->current_block = lp->root;

	/*
	 * The "next" field is not an slink_t structure but is a pointer to the
	 * actual next strcuture, i.e. to the start of the next item, NOT to the
	 * next "next" field.
	 *
	 * This is a degenerated case of an expanded list, where the structure
	 * itself is doing the chaining, hence the offset of the chaining structure
	 * is 0.
	 */

	xslist_init(&lp->selector_list, 0, offsetof(lf_selector_t, next));
	xslist_init(&lp->action_list,   0, offsetof(lf_action_t, next));

	return lp;
}

static void lf_selector_free(lf_selector_t *ls);
static void lf_action_free(lf_action_t *la);
static void lf_recursive_block_free(lf_block_t *lb);

/**
 * XS list iterator item free callback.
 */
static bool
lf_selector_item_free(void *data, void *udata)
{
	lf_selector_t *ls = data;

	(void) udata;
	lf_selector_free(ls);
	return TRUE;
}

/**
 * XS list iterator item free callback.
 */
static bool
lf_action_item_free(void *data, void *udata)
{
	lf_action_t *la = data;

	(void) udata;
	lf_action_free(la);
	return TRUE;
}

static void
lf_key_free(const void *key, void *unused_value, void *unused_udata)
{
	(void) unused_value;
	(void) unused_udata;

	atom_str_free(key);
}

static void
lf_key_value_free(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;

	atom_str_free(key);
	atom_str_free(value);
}

static void
lf_htable_string_k_free_null(htable_t **ht)
{
	htable_foreach(*ht, lf_key_free, NULL);
	htable_free_null(ht);
}

static void
lf_htable_string_kv_free_null(htable_t **ht)
{
	htable_foreach(*ht, lf_key_value_free, NULL);
	htable_free_null(ht);
}


/**
 * Free logfilter parser.
 */
static void
lf_parser_free(lf_parser_t *lp)
{
	lf_parser_check(lp);

	lf_token_cleanup(&lp->previous);
	lf_token_cleanup(&lp->token);
	lf_token_cleanup(&lp->saved_token);
	symtab_free_null(&lp->variables);
	lf_htable_string_k_free_null(&lp->logfiles);
	lf_htable_string_kv_free_null(&lp->options);

	xslist_foreach_remove(&lp->selector_list, lf_selector_item_free, NULL);
	xslist_foreach_remove(&lp->action_list,   lf_action_item_free,   NULL);

	if (lp->root != NULL)
		lf_recursive_block_free(lp->root);

	lp->magic = 0;
	WFREE(lp);
}

/**
 * Free routine for the logfile name/value pairs (to release the value side).
 */
static void
lf_nv_free(void *p, size_t unused_len)
{
	(void) unused_len;

	atom_str_free(p);
}

/**
 * Parse a variable definition.
 *
 * The variable identifier was already parsed.
 *
 * @param lp		the parser
 * @param name		the name they want to define (atom)
 */
static lf_parse_status_t
lf_parse_variable_definition(lf_parser_t *lp, const char *name)
{
	lf_token_id_t id;
	const char *value = NULL;
	nv_pair_t *nv = NULL;

	lf_parser_check(lp);

	/*
	 * Get the '='
	 */

	id = lf_next_token(lp);

	if (LF_TOK_EQ != id) {
		lf_parser_error(lp, "expected '=' after variable name \"%s\"", name);
		goto error;
	}

	/*
	 * Get the file path.
	 */

	id = lf_next_token(lp);

	if (LF_TOK_STR != id) {
		lf_parser_error(lp, "expected string for the value of \"%s\"", name);
		goto error;
	}

	value = atom_str_get(lp->token.u.str);

	/*
	 * Record the symbol.
	 *
	 * The name atom is going to get ref-counted, but the value is copied as-is.
	 * We setup a dedicated free routine to properly dispose of the string
	 * when the name/value pair will get reclaimed.
	 */

	nv = nv_pair_make_nocopy(name, value, vstrlen(value) + 1);
	nv_pair_set_value_free(nv, lf_nv_free);

	if (!symtab_insert_pair(lp->variables, nv, lp->depth)) {
		lf_parser_error(lp, "duplicate variable definition for \"%s\"", name);
		goto error;
	}

	/*
	 * Read trailing ';'.
	 */

	id = lf_next_token(lp);

	if (LF_TOK_SC != id) {
		lf_parser_error(lp, "expected ';' to end definition of \"%s\"", name);
		goto error;
	}

	return LF_PARSE_OK;

error:
	atom_str_free_null(&value);
	if (nv != NULL)
		nv_pair_free(nv);
	return LF_PARSE_ERROR;
}

/**
 * Allocate a selector.
 *
 * @param magic		the magic number to use (governs its type)
 * @param negated	whether selection should be negated
 *
 * @return allocated selector object.
 */
static lf_selector_t *
lf_selector_alloc(enum lf_selector_magic magic, bool negated)
{
	lf_selector_t *ls;

	WALLOC0(ls);
	ls->magic = magic;
	ls->negated = booleanize(negated);

	return ls;
}

/*
 * Macro used to steal a pointer from the token: grab its value, then
 * nullify it so it does not get freed when the token is cleaned up.
 */
#define LF_STEAL(x)		x; x = NULL;

/**
 * Parse a "message" selector.
 *
 * If present, the "message" keyword has already been processed.
 *
 * @param lp		the parser
 * @param negated	whether selection needs to be negated
 */
static lf_parse_status_t
lf_parse_message_selector(lf_parser_t *lp, bool negated)
{
	lf_token_id_t id;
	lf_selector_t *ls;

	lf_parser_check(lp);

	id = lf_next_token(lp);

	switch (id) {
	case LF_TOK_REGEX:
		ls = lf_selector_alloc(LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC, negated);
		ls->u.re = LF_STEAL(lp->token.u.re);
		ls->insensitive = lp->token.is_case_insensitive;
		break;
	case LF_TOK_STR:
		ls = lf_selector_alloc(LOGFILTER_SELECTOR_MESSAGE_STR_MAGIC, negated);
		ls->u.str = atom_str_get(lp->token.u.str);
		break;
	default:
		return lf_parser_error(lp,
			"expected regex or constant string for message selection");
	}

	xslist_append(&lp->selector_list, ls);

	return LF_PARSE_OK;
}

/**
 * Parse a "routine" selector.
 *
 * If present, the "routine" keyword has already been processed.
 *
 * @param lp		the parser
 * @param negated	whether selection needs to be negated
 * @param name		if non-NULL, the name of the routine to select
 */
static lf_parse_status_t
lf_parse_routine_selector(lf_parser_t *lp, bool negated, const char *name)
{
	lf_selector_t *ls;

	lf_parser_check(lp);

	/*
	 * If we already know the routine name, we do not have to parse anything
	 * more as we have our constant-string matching criteria.
	 */

	if (name != NULL) {
		ls = lf_selector_alloc(LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC, negated);
		ls->u.str = atom_str_get(name);
	} else {
		lf_token_id_t id;

		id = lf_next_token(lp);
		switch (id) {
		case LF_TOK_REGEX:
			ls = lf_selector_alloc(LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC, negated);
			ls->u.re = LF_STEAL(lp->token.u.re);
			ls->insensitive = lp->token.is_case_insensitive;
			break;
		case LF_TOK_STR:
			ls = lf_selector_alloc(LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC, negated);
			ls->u.str = atom_str_get(lp->token.u.str);
			/* Make sure there is no '()' in the name or it would never match */
			if G_UNLIKELY(NULL != strstr(ls->u.str, "()")) {
				return lf_parser_error(lp,
					"routine name \"%s\" cannot contain '()' "
					"after \"routine\" keyword", ls->u.str);
			}
			break;
		default:
			return lf_parser_error(lp,
				"expected regex or constant string for routine selection");
		}
	}

	xslist_append(&lp->selector_list, ls);

	return LF_PARSE_OK;
}

/**
 * Parse a "file" selector.
 *
 * If present, the "file" keyword has already been processed.
 *
 * @param lp		the parser
 * @param negated	whether selection needs to be negated
 * @param name		if non-NULL, the name of the file to select
 */
static lf_parse_status_t
lf_parse_file_selector(lf_parser_t *lp, bool negated, const char *name)
{
	lf_selector_t *ls;

	lf_parser_check(lp);

	/*
	 * If we already know the file name, we do not have to parse anything
	 * more as we have our constant-string matching criteria.
	 */

	if (name != NULL) {
		ls = lf_selector_alloc(LOGFILTER_SELECTOR_FILE_STR_MAGIC, negated);
		ls->u.str = atom_str_get(name);
	} else {
		lf_token_id_t id;

		id = lf_next_token(lp);
		switch (id) {
		case LF_TOK_REGEX:
			ls = lf_selector_alloc(LOGFILTER_SELECTOR_FILE_RE_MAGIC, negated);
			ls->u.re = LF_STEAL(lp->token.u.re);
			ls->insensitive = lp->token.is_case_insensitive;
			break;
		case LF_TOK_STR:
			ls = lf_selector_alloc(LOGFILTER_SELECTOR_FILE_STR_MAGIC, negated);
			ls->u.str = atom_str_get(lp->token.u.str);
			break;
		default:
			return lf_parser_error(lp,
				"expected regex or constant string for file selection");
		}
	}

	xslist_append(&lp->selector_list, ls);

	return LF_PARSE_OK;
}

/**
 * Parse a "level" or "line" selector.
 *
 * The "level" or "line" keyword has already been processed.
 *
 * @param lp		the parser
 * @param which		the token for "level" or "line"
 * @param negated	whether selection needs to be negated
 */
static lf_parse_status_t
lf_parse_level_or_line_selector(
	lf_parser_t *lp, lf_token_id_t which, bool negated)
{
	lf_token_id_t id;
	lf_selector_t *ls;
	enum logfilter_cmp cmp;
	enum logfilter_log_level level;
	enum lf_selector_magic magic;

	/*
	 * Get the comparison operator.
	 */

	id = lf_next_token(lp);

	switch (id) {
	case LF_TOK_EQ:  cmp = LF_LVL_EQ;  break;
	case LF_TOK_GT:  cmp = LF_LVL_GT;  break;
	case LF_TOK_GTE: cmp = LF_LVL_GTE; break;
	case LF_TOK_LT:  cmp = LF_LVL_LT;  break;
	case LF_TOK_LTE: cmp = LF_LVL_LTE; break;
	case LF_TOK_NE:  cmp = LF_LVL_NE;  break;
	default:
		return lf_parser_error(lp, "expected comparison operator");
	}

	/*
	 * Get token following the comparison operator.
	 */

	id = lf_next_token(lp);

	/*
	 * Parsing is easy for line: we just expect an integer value.
	 */

	if (LF_TOK_LINE == which) {
		if (id != LF_TOK_UV) {
			return lf_parser_error(lp, "expected integer value");
		}
		magic = LOGFILTER_SELECTOR_LINE_MAGIC;
		goto allocate;
	}

	/*
	 * Get the logging level
	 */

	switch (id) {
	case LF_TOK_CRITICAL: level = LF_LOG_CRITICAL; break;
	case LF_TOK_WARNING:  level = LF_LOG_WARNING;  break;
	case LF_TOK_MESSAGE:  level = LF_LOG_MESSAGE;  break;
	case LF_TOK_INFO:     level = LF_LOG_INFO;     break;
	case LF_TOK_DEBUG:    level = LF_LOG_DEBUG;    break;
	default:
		return lf_parser_error(lp, "expected logging level");
	}

	magic = LOGFILTER_SELECTOR_LEVEL_MAGIC;

	/* FALL THROUGH */

allocate:
	ls = lf_selector_alloc(magic, negated);
	ls->op = cmp;

	switch (which) {
	case LF_TOK_LINE:  ls->u.uv  = lp->token.u.uv; break;
	case LF_TOK_LEVEL: ls->u.lvl = level;          break;
	default:
		g_assert_not_reached();
	}

	xslist_append(&lp->selector_list, ls);

	return LF_PARSE_OK;
}

/**
 * Parse a selector.
 */
static lf_parse_status_t
lf_parse_selector(lf_parser_t *lp)
{
	lf_token_id_t id;
	bool negated = FALSE;

	lf_parser_check(lp);

	/*
	 * Look ahead to see if we have a '!' in front, which negates the selection.
	 */

	id = lf_next_token(lp);

	if (LF_TOK_NOT == id)
		negated = TRUE;
	else
		lf_unread_token(lp);

	while (LF_TOK_EOF != (id = lf_next_token(lp))) {
		switch (id) {
		case LF_TOK_MESSAGE:
			return lf_parse_message_selector(lp, negated);
		case LF_TOK_REGEX:
			/*
			 * A regular expression alone implies a selection on
			 * the log message.
			 */
			lf_unread_token(lp);
			return lf_parse_message_selector(lp, negated);
		case LF_TOK_ROUTINE:
			return lf_parse_routine_selector(lp, negated, NULL);
		case LF_TOK_IDENT:
			/*
			 * An identifier followed by '()' will be a selection on the
			 * routine name.
			 */
			{
				const char *name = atom_str_get(lp->token.u.str);
				lf_parse_status_t status;

				id = lf_next_token(lp);
				if (LF_TOK_PARENS == id) {		/* Followed by '()' */
					status = lf_parse_routine_selector(lp, negated, name);
				} else {
					lf_unread_token(lp);
					status = lf_parser_error(lp,
						"unexpected standalone identifier \"%s\"", name);
				}
				atom_str_free_null(&name);
				return status;
			}
			g_assert_not_reached();
		case LF_TOK_FILE:
			return lf_parse_file_selector(lp, negated, NULL);
		case LF_TOK_STR:
			/*
			 * If the string ends with '()' then it is really a routine
			 * selection.  Otherwise, this is a file selection.
			 */
			{
				const char *str = atom_str_get(lp->token.u.str);
				const char *suffix;
				lf_parse_status_t status;

				suffix = is_strsuffix(str, vstrlen(str), "()");
				if (suffix != NULL) {
					char *routine = h_strndup(str, suffix - str);
					status = lf_parse_routine_selector(lp, negated, routine);
					HFREE_NULL(routine);
				} else {
					status = lf_parse_file_selector(lp, negated, str);
				}
				atom_str_free_null(&str);
				return status;
			}
			g_assert_not_reached();
		case LF_TOK_LEVEL:
			return lf_parse_level_or_line_selector(lp, id, negated);
		default:
			return lf_parser_error(lp,
				"unexpected token in selector definition");
		}
	}

	return lf_parser_error(lp,
		"got EOF in the middle of selector definition");
}

/**
 * Parse a selector list, which may be empty!
 */
static lf_parse_status_t
lf_parse_selector_list(lf_parser_t *lp)
{
	lf_token_id_t id;

	lf_parser_check(lp);
	g_assert(0 == xslist_count(&lp->selector_list));

	id = lf_look_ahead_token(lp);

	switch (id) {
	case LF_TOK_MESSAGE:
	case LF_TOK_ROUTINE:
	case LF_TOK_FILE:
	case LF_TOK_LEVEL:
	case LF_TOK_IDENT:
	case LF_TOK_STR:
	case LF_TOK_REGEX:
	case LF_TOK_NOT:
		break;
	default:
		/* Does not look like the beginning of a selector */
		return LF_PARSE_EMPTY;
	}

	for (;;) {
		size_t ns = xslist_count(&lp->selector_list);

		if (LF_PARSE_ERROR == lf_parse_selector(lp))
			return LF_PARSE_ERROR;

		g_assert(ns + 1 == xslist_count(&lp->selector_list));

		id = lf_next_token(lp);
		if (LF_TOK_COMMA == id)
			continue;			/* Another selector follows */

		lf_unread_token(lp);
		return LF_PARSE_OK;
	}

	g_assert_not_reached();
}

/**
 * Allocate a new rule.
 */
static lf_rule_t *
lf_rule_alloc(void)
{
	lf_rule_t *lr;

	WALLOC0(lr);
	lr->magic = LOGFILTER_RULE_MAGIC;

	return lr;
}

/**
 * Get head of XS list and clear it.
 *
 * @return NULL if list was empty, the list head otherwise.
 */
static void *
lf_xslist_grab(xslist_t *xs)
{
	if (0 != xslist_count(xs)) {
		void *head = xslist_head(xs);
		xslist_clear(xs);
		return head;
	}

	return NULL;
}

/**
 * Scan selector list for regular expressions applied to messages and identify
 * those which were not flagged as "capturing": it means they do not want to
 * highlight any sub-block of this regular expression and it can therefore
 * be recompiled with the RE_F_NOSUB flag to possibly simplify it further.
 */
static void
lf_selector_recompile_non_capturing(lf_parser_t *lp)
{
	lf_selector_t *ls;

	XSLIST_FOREACH_DATA(&lp->selector_list, ls) {
		lf_selector_check(ls);

		if (LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC != ls->magic)
			continue;

		if (!ls->capture) {
			uint32 flags = RE_F_NOSUB;
			flags |= ls->insensitive ? RE_F_ICASE : 0;
			re_recompile(ls->u.re, flags);
		}
	}
}

/**
 * Record new rule in the parser's current block.
 */
static void
lf_record_rule(lf_parser_t *lp)
{
	lf_block_t *lb;
	lf_rule_t *lr;

	lf_parser_check(lp);
	lf_block_check(lp->current_block);

	if (0 == xslist_count(&lp->action_list))
		lf_parser_warn(lp, "no action defined in rule");

	/*
	 * If we were parsing a disabled block, discard everything.
	 */

	if (lp->disabled) {
		xslist_foreach_remove(&lp->selector_list, lf_selector_item_free, NULL);
		xslist_foreach_remove(&lp->action_list,   lf_action_item_free,   NULL);
		return;
	}

	lb = lp->current_block;
	lr = lf_rule_alloc();

	lf_selector_recompile_non_capturing(lp);

	lr->selector_list = lf_xslist_grab(&lp->selector_list);
	lr->action_list   = lf_xslist_grab(&lp->action_list);

	/*
	 * The rule is prepended to the one-way list, which will get reversed
	 * when the parsing of the block is complete.
	 */

	lb->list = pslist_prepend(lb->list, lr);
}

/**
 * Allocate an action.
 */
static lf_action_t *
lf_action_alloc(enum lf_action_magic magic)
{
	lf_action_t *la;

	WALLOC0(la);
	la->magic = magic;

	return la;
}

/**
 * Complain of pre-defined variable name for something other than "copy".
 */
static lf_parse_status_t
lf_parser_for_copy_only(lf_parser_t *lp, const char *name)
{
	return lf_parser_error(lp,
		"pre-defined \"%s\" only applies to \"copy\"", name);
}

/**
 * Complain of used token as argument for something other than "strip".
 */
static lf_parse_status_t
lf_parser_for_strip_only(lf_parser_t *lp, const char *name)
{
	return lf_parser_error(lp,
		"argument \"%s\" only applies to \"strip\"", name);
}

/**
 * Parse the coming variable or string or token.
 *
 * This is for the "color", "copy", "tag" or "strip" actions, as indicated
 * by the given token we already parsed.
 *
 * @param lp		the parser
 * @param token		the token for which we are now parsing
 */
static lf_parse_status_t
lf_parse_var_or_string_action(lf_parser_t *lp, lf_token_id_t token)
{
	lf_token_id_t id;
	lf_action_t *la;
	enum lf_action_magic magic;
	const char *value = NULL;

	lf_parser_check(lp);

	id = lf_next_token(lp);

	switch (id) {
	case LF_TOK_ERR:
		if (LF_TOK_COPY != token)
			return lf_parser_for_copy_only(lp, "err");
		lp->flags.set |= LF_FLG_STDERR;
		return LF_PARSE_OK;
	case LF_TOK_OUT:
		if (LF_TOK_COPY != token)
			return lf_parser_for_copy_only(lp, "out");
		magic = LOGFILTER_ACTION_COPY_OUT_MAGIC;
		break;
	case LF_TOK_ROUTINE:
		if (LF_TOK_STRIP != token)
			return lf_parser_for_strip_only(lp, "routine");
		magic = LOGFILTER_ACTION_STRIP_ROUTINE_MAGIC;
		break;
	case LF_TOK_WHERE:
		if (LF_TOK_STRIP != token)
			return lf_parser_for_strip_only(lp, "where");
		magic = LOGFILTER_ACTION_STRIP_WHERE_MAGIC;
		break;
	case LF_TOK_IDENT:
	case LF_TOK_STR:
		if (LF_TOK_IDENT == id) {
			/* We have TOKEN variable */
			const char *name = lp->token.u.str;

			value = symtab_lookup(lp->variables, name);

			if (NULL == value) {
				return lf_parser_error(lp,
					"unknown variable name \"%s\"", name);
			}
		} else {
			/* We have TOKEN "string" */
			value = lp->token.u.str;
		}

		/*
		 * Validate color if we're parsing for a color.
		 *
		 * We choose to ignore the "color" action when the color specification
		 * is not valid, since this is not a syntax error at this level.
		 */

		if (LF_TOK_COLOR == token) {
			const char *esc = color_escape(value, TRUE);
			if (NULL == esc) {
				static bool warned;

				lf_parser_warn(lp,
					"invalid color specification \"%s\", ignoring", value);

				if (!warned) {
					warned = TRUE;
					color_manual();		/* Inform them about color specs */
				}
				return LF_PARSE_OK;
			}
			value = esc;	/* Constant string */
		}

		switch (token) {
		case LF_TOK_COPY:  magic = LOGFILTER_ACTION_COPY_PATH_MAGIC; break;
		case LF_TOK_TAG:   magic = LOGFILTER_ACTION_TAG_MAGIC;       break;
		case LF_TOK_STRIP: magic = LOGFILTER_ACTION_STRIP_TAG_MAGIC; break;
		case LF_TOK_COLOR: magic = LOGFILTER_ACTION_COLOR_MAGIC;     break;
		default: g_assert_not_reached();
		}
		break;
	default:
		return lf_parser_error(lp, "expected string or variable name");
	}

	la = lf_action_alloc(magic);

	switch (magic) {
	case LOGFILTER_ACTION_TAG_MAGIC:
		la->u.value = atom_str_get(value);
		break;
	case LOGFILTER_ACTION_COPY_PATH_MAGIC:
		la->u.logidx = lf_logfile_get_index(lp, value);
		break;
	case LOGFILTER_ACTION_COPY_OUT_MAGIC:
	case LOGFILTER_ACTION_STRIP_ROUTINE_MAGIC:
	case LOGFILTER_ACTION_STRIP_WHERE_MAGIC:
		break;
	case LOGFILTER_ACTION_STRIP_TAG_MAGIC:
	case LOGFILTER_ACTION_COLOR_MAGIC:
		la->u.value = value;	/* Already a constant string */
		break;
	default:
		g_assert_not_reached();
	}

	xslist_append(&lp->action_list, la);

	return LF_PARSE_OK;
}

/**
 * Configure the regular expression in the selector to capture the given
 * group number matching information at runtime.
 */
static void
lf_selector_regex_capture(lf_selector_t *ls, ulong gn)
{
	lf_regex_t *cre;

	lf_selector_check(ls);

	/*
	 * If the selector is not yet flagged as capturing, then we have a
	 * plain regex: we need to encapsulate it into a lf_regex_t structure.
	 */

	if (!ls->capture) {
		WALLOC0(cre);
		cre->magic = LF_REGEX_MAGIC;
		cre->re = ls->u.re;
		cre->captured = pslist_prepend(cre->captured, ulong_to_pointer(gn));
		ls->u.cre = cre;
		ls->capture = TRUE;
	} else {
		cre = ls->u.cre;
		lf_regex_check(cre);
		/* Avoid duplicates */
		if (NULL == pslist_find(cre->captured, ulong_to_pointer(gn))) {
			cre->captured =
				pslist_prepend(cre->captured, ulong_to_pointer(gn));
		}
	}
}

/**
 * Parse the coming number.
 *
 * The "highlight" action must be attached to a selector list that will match
 * on the log message.  Otherwise a warning is emitted and the action ignored.
 *
 * Furthermore, the highlight number (which is the number of the capturing
 * group to highlight after matching, 0 meaning the whole matching text)
 * must be referring to regular expressions that define this group (i.e. if
 * they say "highlight 3" then a capturing group #3 must be present in at
 * least one regular expression used for selection), or again the directive
 * will be ignored at runtime.
 *
 * Because we have stringent "avoid memory allocation" constraints during
 * logging, we limit the maximum number of groups that can be catpured to 9.
 * That is 9 in a single regular expression... should be sufficient.
 *
 * @param lp		the parser
 */
static lf_parse_status_t
lf_parse_highlight(lf_parser_t *lp)
{
	lf_token_id_t id;
	ulong gn;
	const xslist_t *xsl;
	lf_selector_t *ls;
	lf_action_t *la;
	size_t re_cnt = 0;			/* Amount of regex found in selectors */
	size_t re_capturing = 0;	/* Amount that will be capturing the group */

	lf_parser_check(lp);

	id = lf_next_token(lp);		/* Fetch group number */

	if (id != LF_TOK_UV)
		return lf_parser_error(lp, "expected regex group number, got %s",
			lf_sym_as_string(&lp->token));

	/* Validate group number */

	gn = lp->token.u.uv;
	if (gn >= LOGFILTER_RE_GROUPS) {
		lf_parser_warn(lp, "ignoring highlighting of group #%lu (max is %u)",
			gn, LOGFILTER_RE_GROUPS - 1);
		goto done;
	}

	/*
	 * Check that we have a message selector with a regex bearing at least
	 * this amount of capturing groups!
	 */

	xsl = &lp->selector_list;

	if (0 == xslist_count(xsl)) {
		lf_parser_warn(lp, "ignoring highlight: no selectors defined");
		goto done;
	}

	XSLIST_FOREACH_DATA(xsl, ls) {
		re_regex_t *re;

		lf_selector_check(ls);

		if (LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC != ls->magic)
			continue;

		re_cnt++;			/* One regular expression found */
		re = lf_selector_regex(ls);

		if (re_group_count(re) < gn)
			continue;		/* Not enough groups in this regular expression */

		/*
		 * We found a regular expression applied to the log message which
		 * contains enough capturing groups for highlighting a match.
		 *
		 * Register that this selector will have to capture the matching
		 * information at runtime.
		 */

		lf_selector_regex_capture(ls, gn);
		re_capturing++;
	}

	if (0 == re_cnt) {
		lf_parser_warn(lp, "ignoring highlight: no regex on log message");
		goto done;
	}

	if (0 == re_capturing) {
		lf_parser_warn(lp, "ignoring highlight: no regex has group #%lu", gn);
		goto done;
	}

	/*
	 * We have installed capture of the matching information right in the
	 * selector, but we also add an action entry for the highlighting
	 * that will appear when we dump the actions.  At runtime, it will
	 * be otherwise ignored.
	 */

	la = lf_action_alloc(LOGFILTER_ACTION_HIGHLIGHT_MAGIC);
	la->u.gn = gn;

	xslist_append(&lp->action_list, la);

	/* FALL THROUGH */

done:
	return LF_PARSE_OK;
}

static lf_parse_status_t
lf_parse_handle_carp_arg(lf_parser_t *lp)
{
	lf_token_id_t id = lf_next_token(lp);

	if (id != LF_TOK_CONSTANT) {
		lf_unread_token(lp);
		goto done;
	}

	switch (lp->token.u.cid) {
	case LF_CTOK_FULL:
	case LF_CTOK_HEXA:
	case LF_CTOK_MINI:
	case LF_CTOK_NAME:
		/*
		 * At this parsing stage, we simply record that there is an
		 * argument given to "carp".  We will create the necessary
		 * LOGFILTER_ACTION_FLAG_SET_ARG_MAGIC action when we are done
		 * with the rules, in case they say "carp *full" and then
		 * "carp *mini" in the same action list -- the latest instance
		 * will win.
		 *
		 * This will also allow us to put all the setting actions at
		 * the beginning of the action list, for better clarity when
		 * dumping the rules.
		 */
		{
			size_t idx;		/* Position of "carp" in the args[] array */

			g_assert(htable_contains(
				logfilter_action_map, uint_to_pointer(LF_TOK_CARP)));

			idx = pointer_to_uint(htable_lookup(
				logfilter_action_map, uint_to_pointer(LF_TOK_CARP)));

			g_assert(idx < LF_ARG_MAX);

			lp->args[idx] = lp->token.u.cid;	/* The constant token */
		}
		break;
	default:
		return lf_parser_error(lp,
			"constant token \"%s\" not applicable to \"carp\"",
			lf_constant_string(lp->token.u.cid));
	}

	/* FALL THROUGH */

done:
	return LF_PARSE_OK;
}

/**
 * Parse an action.
 */
static lf_parse_status_t
lf_parse_action(lf_parser_t *lp)
{
	lf_token_id_t id;

	lf_parser_check(lp);

	id = lf_next_token(lp);

	/*
	 * For most of the actions, we simply record the update in flags, and
	 * will create a flag-modification action at the end of the action list,
	 * if necessary.
	 */

	switch (id) {
	case LF_TOK_BREAK:     lp->flags.set   |= LF_FLG_BREAK;   break;
	case LF_TOK_CARP:      lp->flags.set   |= LF_FLG_CARP;    break;
	case LF_TOK_IGNORE:    lp->flags.set   |= LF_FLG_IGNORE;  break;
	case LF_TOK_LEVEL:     lp->flags.set   |= LF_FLG_LEVEL;   break;
	case LF_TOK_LOG:       lp->flags.set   |= LF_FLG_STDERR;  break;
	case LF_TOK_MATCH:     lp->flags.set   |= LF_FLG_MATCH;   break;
	case LF_TOK_NEXT:      lp->flags.set   |= LF_FLG_NEXT;    break;
	case LF_TOK_ROUTINE:   lp->flags.set   |= LF_FLG_ROUTINE; break;
	case LF_TOK_STOP:      lp->flags.set   |= LF_FLG_STOP;    break;
	case LF_TOK_WHERE:     lp->flags.set   |= LF_FLG_WHERE;   break;
	case LF_TOK_NOBREAK:   lp->flags.clear |= LF_FLG_BREAK;   break;
	case LF_TOK_NOCARP:    lp->flags.clear |= LF_FLG_CARP;    break;
	case LF_TOK_NOLEVEL:   lp->flags.clear |= LF_FLG_LEVEL;   break;
	case LF_TOK_NOLOG:     lp->flags.clear |= LF_FLG_STDERR;  break;
	case LF_TOK_NOMATCH:   lp->flags.clear |= LF_FLG_MATCH;   break;
	case LF_TOK_NOROUTINE: lp->flags.clear |= LF_FLG_ROUTINE; break;
	case LF_TOK_NOWHERE:   lp->flags.clear |= LF_FLG_WHERE;   break;
	case LF_TOK_COPY:
	case LF_TOK_TAG:
	case LF_TOK_STRIP:
	case LF_TOK_COLOR:
		return lf_parse_var_or_string_action(lp, id);
	case LF_TOK_HIGHLIGHT:
		return lf_parse_highlight(lp);
	case LF_TOK_SC:
		lf_unread_token(lp);
		return LF_PARSE_EMPTY;
	default:
		return lf_parser_error(lp,
			"unexpected token, wanted an action keyword");
	}

	/* Handle "carp" specially since it can be followed by a constant token */

	if (LF_TOK_CARP == id) {
		if (LF_PARSE_OK != lf_parse_handle_carp_arg(lp))
			return LF_PARSE_ERROR;
	}

	/* Remember if they used "match" */

	if (lp->flags.set & LF_FLG_MATCH)
		lp->attrs.record_matches = TRUE;

	return LF_PARSE_OK;
}

/**
 * Parse an action list, which ends with a ';'.
 */
static lf_parse_status_t
lf_parse_action_list(lf_parser_t *lp)
{
	uint i;

	lf_parser_check(lp);
	g_assert(0 == xslist_count(&lp->action_list));

	ZERO(&lp->flags);
	ZERO(&lp->args);

	for (;;) {
		lf_token_id_t id;

		if (LF_PARSE_ERROR == lf_parse_action(lp))
			return LF_PARSE_ERROR;

		id = lf_next_token(lp);
		if (LF_TOK_COMMA == id)
			continue;			/* Another action follows */
		else if (LF_TOK_SC != id) {
			return lf_parser_error(lp, "expected ',' or ';' after action");
		}

		break;	/* Got final ';', we are done with the actions */
	}

	/*
	 * Check whether we have anything to do with the flags.
	 */

	if (lp->flags.set & lp->flags.clear) {
		return lf_parser_error(lp,
			"cannot set and clear flags at the same time");
	}

	if (
		(LF_FLG_STOP|LF_FLG_NEXT) == (lp->flags.set & (LF_FLG_STOP|LF_FLG_NEXT))
	) {
		return lf_parser_error(lp,
			"cannot say \"stop\" and \"next\" at the same time");
	}

	if (lp->flags.set != 0 || lp->flags.clear != 0) {
		lf_action_t *la = lf_action_alloc(LOGFILTER_ACTION_FLAGS_MAGIC);
		la->u.flags = lp->flags;	/* struct copy */
		xslist_append(&lp->action_list, la);
	}

	/*
	 * If they have set any argument in the args[] array, generate the
	 * necessary actions for setting that argument at runtime.
	 *
	 * We put these at the head of the action list so that they are the
	 * first seen when dumping the rules (otherwise the execution order
	 * of the actions within the rules does not matter).
	 */

	for (i = 0; i < N_ITEMS(lp->args); i++) {
		/* 0 is not a valid constant token */
		if (0 != lp->args[i]) {
			lf_action_t *la =
				lf_action_alloc(LOGFILTER_ACTION_FLAG_SET_ARG_MAGIC);

			la->u.set.idx = i;
			la->u.set.arg = lp->args[i];

			xslist_prepend(&lp->action_list, la);
		}
	}

	/*
	 * Now that we have parsed the selector (which may be empty) and the
	 * actions, create a rule combining the two.
	 */

	lf_record_rule(lp);

	return LF_PARSE_OK;
}

/**
 * Record new block in parser.
 *
 * @return the new block
 */
static lf_block_t *
lf_record_new_block(lf_parser_t *lp)
{
	lf_block_t *lb;

	lf_parser_check(lp);

	lb = lp->current_block = lf_block_alloc();

	/*
	 * If we parsed a selector list before the block, install it to guard
	 * the descent within the block at runtime.
	 */

	lf_selector_recompile_non_capturing(lp);

	lb->selector_list = lf_xslist_grab(&lp->selector_list);

	return lb;
}

/**
 * Parse an options {} block.
 *
 * This is a list of
 *
 * 		key = "string value";
 * 
 * statements, with no variable support (the manifest string is expected)
 * and no keywords (keys are read as they are supplied).  The trailing ';'
 * is optional here.
 *
 * We loudly warn when we encounter an unknown option key but this does
 * not result in a parsing error.
 */
static lf_parse_status_t
lf_parse_options(lf_parser_t *lp)
{
	lf_token_id_t id;

	while (LF_TOK_EOF != (id = lf_next_token(lp))) {
		lf_sym_t *t = &lp->token;
		const char *key, *value;
		lf_token_id_t option_id;

		if (LF_TOK_RBRACE == id)
			return LF_PARSE_OK;

		/*
		 * There are no keywords within an options{} block so if
		 * we have one, then simply use the keyword as a variable name.
		 */

		if (t->is_keyword)
			key = atom_str_get(t->u.keyword);
		else if (LF_TOK_IDENT == id)
			key = atom_str_get(t->u.str);
		else {
			return lf_parser_error(lp,
				"expected identifier (keywords possible) as option name");
		}

		option_id = TOKENIZE(key, logfilter_option_names);

		if (0 == option_id)
			lf_parser_warn(lp, "unknown option name \"%s\"", key);

		if (LF_TOK_EQ != lf_next_token(lp)) {
			atom_str_free_null(&key);
			return lf_parser_error(lp, "expected '=' after option name");
		}

		if (LF_TOK_STR != lf_next_token(lp)) {
			atom_str_free_null(&key);
			return lf_parser_error(lp, "expected manifest string");
		}

		value = atom_str_get(t->u.str);

		/* Trailing ';' is optional, swallow it if present */

		if (LF_TOK_SC == lf_look_ahead_token(lp))
			(void) lf_next_token(lp);

		if (lp->disabled || 0 == option_id) {
			/*
			 * Ignore entry if in a disabled block or if we did not recognize
			 * the key as that of a valid option (already warned above).
			 */
			goto cleanup;
		} else {
			const void *okey;
			void *ovalue;

			/*
			 * Record the key/value pair, but value will be processed later,
			 * when we are sure all the rules are correct and we can install
			 * them to supersede the old ones.
			 */

			if (htable_lookup_extended(lp->options, key, &okey, &ovalue)) {
				lf_parser_warn(lp, "redefining option \"%s\"", key);
				atom_str_free(okey);
				atom_str_free(ovalue);
			}

			htable_insert(lp->options, key, deconstify_pointer(value));
		}

		continue;

	cleanup:
		atom_str_free_null(&key);
		atom_str_free_null(&value);
	}

	return lf_parser_error(lp, "unexpected EOF within options {} block");
}

static lf_parse_status_t lf_parse_items(lf_parser_t *lp);

/**
 * Parse a block, which is expected to start with an unread '{'.
 */
static lf_parse_status_t
lf_parse_block(lf_parser_t *lp)
{
	lf_token_id_t id;
	lf_parse_status_t status;
	lf_block_t *current_block, *lb;

	lf_parser_check(lp);
	lf_block_check(lp->current_block);

	id = lf_next_token(lp);

	if (LF_TOK_LBRACE != id)
		return lf_parser_error(lp, "expected block opening with '{'");

	/*
	 * options {} blocks are handled specially: their syntax is special
	 * and they are always global, regardless of where they appear and
	 * whether the location where they appear is guarded by a selection.
	 *
	 * In effect, it is as if options {} blocks were removed from the
	 * input and any selection preceding them will be actually applied
	 * to the next block or actions!
	 */

	if (lp->in_options)
		return lf_parse_options(lp);

	/*
	 * We are entering a new block.
	 *
	 * Any selection already parsed will be attached to the block selector
	 * list, which will be conditionally guarding the traversal of the
	 * rules in the block at runtine, based on the selections attached to it.
	 */

	current_block = lp->current_block;
	lp->depth++;
	lb = lf_record_new_block(lp);		/* New block we're parsing */

	/*
	 * Parse the block, recursively.
	 */

	status = lf_parse_items(lp);

	/*
	 * If we did not parse the block successfully, or we were in a disabled
	 * block, clean it up.
	 *
	 * Otherwise, prepend it to the list of its parent block, and make
	 * sure we also reverse the order of the list in the block we parsed.
	 *
	 * Indeed, since we manage a one-way list, we prepend new items, and
	 * then conclude by reversing the list, which is more efficient than
	 * always attempting to append to the list.
	 */

	if (LF_PARSE_ERROR == status || lp->disabled) {
		lf_recursive_block_free(lb);
		lb = NULL;
	} else {
		lf_block_check(current_block);		/* The parent block */
		g_assert(lb == lp->current_block);

		lb->list = pslist_reverse(lb->list);
		current_block->list = pslist_prepend(current_block->list, lb);
	}

	/*
	 * We are now exiting the block.
	 */

	lp->current_block = current_block;
	symtab_leave(lp->variables, lp->depth);
	lp->depth--;

	return status;
}

/**
 * Parse items.
 *
 * We are expecting either a rule-list, a block, or blocks preceded by either
 * of "enable", "disable" or "options".
 *
 * This routine is recursively called each time we enter a new block and therefore
 * it monitors the closing '}' block indicator, or complains if we are at a
 * parsing depth of 0 (outside any block).
 */
static lf_parse_status_t
lf_parse_items(lf_parser_t *lp)
{
	lf_token_id_t id;

	lf_parser_check(lp);

	while (LF_TOK_EOF != (id = lf_next_token(lp))) {
		lf_parse_status_t status;

		/*
		 * Look for start of a new block without a selector.
		 *
		 * This allows them saying "disable {}" to disable a set of rules
		 * whilst still parsing them for correctness.
		 */

		switch (id) {
		case LF_TOK_DISABLE:
			lp->disabled++;
			if (LF_PARSE_ERROR == lf_parse_block(lp))
				return LF_PARSE_ERROR;
			lp->disabled--;
			continue;
		case LF_TOK_OPTIONS:
			lp->in_options++;
			if (LF_PARSE_ERROR == lf_parse_block(lp))
				return LF_PARSE_ERROR;
			lp->in_options--;
			continue;
		case LF_TOK_LBRACE:			/* Implicit "enable" before '{' */
			lf_unread_token(lp);	/* Unread '{' for now */
			/* FALL THROUGH */
		case LF_TOK_ENABLE:
			if (LF_PARSE_ERROR == lf_parse_block(lp))
				return LF_PARSE_ERROR;
			continue;
		case LF_TOK_RBRACE:			/* Closing '}' */
			if (0 == lp->depth)
				return lf_parser_error(lp, "unexpected block closing");
			return LF_PARSE_OK;		/* Exiting block */
		case LF_TOK_IDENT:
			/*
			 * Look ahead to check we have an '=' sign.
			 */
			{
				const char *name = atom_str_get(lp->token.u.str);

				id = lf_look_ahead_token(lp);
				if (LF_TOK_EQ == id) {
					if (LF_PARSE_ERROR == lf_parse_variable_definition(lp, name))
						return LF_PARSE_ERROR;
					continue;
				} else {
					/*
					 * This is not a variable definition.
					 *
					 * Restore the identifier token as the current token,
					 * then unread it.
					 *
					 * In effect, we have achieved a double look-ahead: the next
					 * token returned by lf_next_token() will be the identifier,
					 * followed by the token we looked-ahead above but decided
					 * to not consume yet!
					 */

					atom_str_free_null(&name);
					id = lf_rewind_token(lp);
					g_assert(LF_TOK_IDENT == id);	/* Next token returned */
				}
			}
			break;
		default:
			lf_unread_token(lp);
			break;
		}

		/*
		 * At this stage we expect an optional selector list, followed
		 * by a rule or a block.
		 *
		 * If the selector list is empty, we know we have to get a rule,
		 * since by construction we cannot face a block (was already
		 * dealt with above).
		 */

		status = lf_parse_selector_list(lp);

		if (LF_PARSE_ERROR == status)
			return LF_PARSE_ERROR;

		/*
		 * Now parse the rule or block.
		 */

		if (status != LF_PARSE_EMPTY) {
			g_assert(0 != xslist_count(&lp->selector_list));

			id = lf_next_token(lp);
			switch (id) {
			case LF_TOK_EOF:
				return lf_parser_error(lp,
					"got EOF after selector list, but expected ':' or '{'");
			case LF_TOK_COLON:
				if (LF_PARSE_ERROR == lf_parse_action_list(lp))
					return LF_PARSE_ERROR;
				break;
			case LF_TOK_LBRACE:
				lf_unread_token(lp);		/* Unread opening '{' */
				if (LF_PARSE_ERROR == lf_parse_block(lp))
					return LF_PARSE_ERROR;
				break;
			default:
				return lf_parser_error(lp,
					"expected ':' or '{' after selector list");
			}
			continue;
		}

		/*
		 * No selector list, parse the rule then.
		 */

		g_assert(0 == xslist_count(&lp->selector_list));

		if (LF_PARSE_ERROR == lf_parse_action_list(lp))
			return LF_PARSE_ERROR;
	}

	if (0 != lp->depth) {
		return lf_parser_error(lp,
			"got EOF in the middle of block (depth=%u)", lp->depth);
	}

	return LF_PARSE_OK;
}

/**
 * Parse document from configured stream.
 *
 * @return TRUE on success, FALSE if there is an error (syntactic or semantic).
 */
static bool
lf_parse(lf_parser_t *lp)
{
	lf_parse_status_t status;

	lf_parser_check(lp);

	lf_parser_debug_lvl(10, lp, "%s(): starting", G_STRFUNC);
	status = lf_parse_items(lp);
	lf_parser_debug_lvl(10, lp, "%s(): done, status=%d", G_STRFUNC, status);

	g_assert(implies(LF_PARSE_OK == status, 0 == lp->depth));

	/*
	 * Reverse the order of the rules in the root block if parsing was OK.
	 */

	if (LF_PARSE_OK == status) {
		g_assert(lp->root == lp->current_block);
		lf_block_check(lp->root);

		lp->root->list = pslist_reverse(lp->root->list);
	}

	return LF_PARSE_OK == status;
}

static struct lf_regex_test {
	const char *input;				/* Input given to parser */
	bool simple;					/* Is expression simple? */
	bool insensitive;				/* Whether patter is case-insensitive */
	const char *pattern;			/* Expected pattern string */
} lf_regex_tests[] = {
	{ "/simple, no'@ meta!/i",	TRUE,	TRUE,	"simple, no'@ meta!" },
	{ "/ab.c* has meta!/",		FALSE,	FALSE,	"ab.c* has meta!" },
	{ "/has \\/ but no meta!/",	TRUE,	FALSE,	"has / but no meta!" },
	{ "m|unesc \\|delim|i",		TRUE,	TRUE,	"unesc |delim" },
	{ "m|esc \\\\\\|delim|",	TRUE,	FALSE,	"esc \\|delim" },
	{ "m|esc \\|pipe char!|",	TRUE,	FALSE,	"esc |pipe char!" },
	{ "m|esc \\|pipe regex?|",	FALSE,	FALSE,	"esc \\|pipe regex?" },
	{ "m|plain|i",				TRUE,	TRUE,	"plain" },
	{ "m,esc\\,but plain,i",	TRUE,	TRUE,	"esc,but plain" },
};

/**
 * Parsing tests for regular expressions.
 */
static void
lf_regex_parsing_test(void)
{
	size_t i;

	for (i = 0; i < N_ITEMS(lf_regex_tests); i++) {
		bstr_t *bs;
		istream_t *is;
		lf_parser_t *lp;
		struct lf_regex_test *t = &lf_regex_tests[i];
		lf_token_id_t id;
		lf_sym_t *sym;
		char *compiled;

		bs = bstr_open(t->input, vstrlen(t->input), BSTR_F_ERROR);
		is = istream_open_bstr(bs);
		lp = lf_parser_alloc(is);
		id = lf_next_token(lp);
		sym = &lp->token;

		g_assert(id == sym->id);

		g_assert_log(sym->is_case_insensitive == t->insensitive,
			"%s(): test #%zu failed: expected case-%ssensitive, "
				"got case-%ssensitive for \"%s\"",
			G_STRFUNC, i, t->insensitive ? "in" : "",
			sym->is_case_insensitive ? "in" : "",
			t->input);

		switch (id) {
		case LF_TOK_REGEX:
			compiled = re_dump_as_string(sym->u.re);
			break;
		case LF_TOK_ERROR:
			s_error("%s(): failed to compile test #%zu: \"%s\"",
				G_STRFUNC, i, t->pattern);
		default:
			g_assert_not_reached();
		}

		g_assert_log(0 == strcmp(compiled, t->pattern),
			"%s(): test #%zu failed: expected pattern \"%s\", "
				"got \"%s\" for \"%s\"",
			G_STRFUNC, i, t->pattern, compiled, t->input);

		g_assert_log(re_is_simple(sym->u.re) == t->simple,
			"%s(): test #%zu failed: expected simple=%d, got %d for \"%s\": %s",
			G_STRFUNC, i, t->simple, re_is_simple(sym->u.re), t->input,
			re_show_as_string(sym->u.re));

		HFREE_NULL(compiled);
		istream_close(is);
		bstr_free(&bs);
		lf_parser_free(lp);
	}
}

/**
 * Free a selector.
 */
static void
lf_selector_free(lf_selector_t *ls)
{
	lf_selector_check(ls);

	switch (ls->magic) {
	case LOGFILTER_SELECTOR_BASE_MAGIC:
	case LOGFILTER_SELECTOR_MASK_MAGIC:
		g_assert_not_reached();
	case LOGFILTER_SELECTOR_MESSAGE_STR_MAGIC:
	case LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC:
	case LOGFILTER_SELECTOR_FILE_STR_MAGIC:
		atom_str_free(ls->u.str);
		break;
	case LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC:
	case LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC:
	case LOGFILTER_SELECTOR_FILE_RE_MAGIC:
		if (ls->capture) {
			lf_regex_t *cre = ls->u.cre;

			lf_regex_check(cre);

			re_free_null(&cre->re);
			pslist_free_null(&cre->captured);
			cre->magic = 0;
			WFREE(cre);
		} else {
			re_free(ls->u.re);
		}
		break;
	case LOGFILTER_SELECTOR_LEVEL_MAGIC:
	case LOGFILTER_SELECTOR_LINE_MAGIC:
		break;
	}

	WFREE0(ls);
}

/**
 * Free a selector list.
 */
static void
lf_selector_list_free(lf_selector_t *head)
{
	lf_selector_t *ls, *next;

	for (ls = head; ls != NULL; ls = next) {
		lf_selector_check(ls);
		next = ls->next;
		lf_selector_free(ls);
	}
}

/**
 * Free an action.
 */
static void
lf_action_free(lf_action_t *la)
{
	lf_action_check(la);

	if (LOGFILTER_ACTION_TAG_MAGIC == la->magic) {
		atom_str_free(la->u.value);
	}

	WFREE0(la);
}

/**
 * Free a rule.
 */
static void
lf_rule_free(lf_rule_t *lr)
{
	lf_action_t *la, *next;

	lf_rule_check(lr);

	lf_selector_list_free(lr->selector_list);

	for (la = lr->action_list; la != NULL; la = next) {
		lf_action_check(la);
		next = la->next;
		lf_action_free(la);
	}
}

/**
 * List iterator to free data.
 */
static void
lf_rule_or_block_free(void *data, void *udata)
{
	lf_rule_or_block_t *rob = data;

	(void) udata;

	if (LOGFILTER_BLOCK_MAGIC == rob->magic) {
		lf_recursive_block_free((lf_block_t *) rob);
	} else if (LOGFILTER_RULE_MAGIC == rob->magic) {
		lf_rule_free((lf_rule_t *) rob);
	} else {
		g_assert_not_reached();		/* Must be either a rule or a block */
	}
}

/**
 * Recursively free block and all contained blocks and rules.
 */
static void
lf_recursive_block_free(lf_block_t *lb)
{
	lf_block_check(lb);

	lf_selector_list_free(lb->selector_list);

	pslist_foreach(lb->list, lf_rule_or_block_free, NULL);
	pslist_free(lb->list);

	WFREE0(lb);
}

/**
 * Reset options to default values.
 */
static void
lf_options_reset(void)
{
	logfilter_options.highlight = LF_MATCH_INVERSE;
	logfilter_options.match     = LF_MATCH_UNDERLINE;
	logfilter_options.where     = LF_WHERE_END;
}

/**
 * Free all rules.
 */
static void
lf_free_all_rules(void)
{
	if (logfilter_root_block != NULL) {
		lf_recursive_block_free(logfilter_root_block);
		logfilter_root_block = NULL;
	}
}

/**
 * Close all existing user-defined logfiles.
 */
static void
lf_close_all_logfiles(void)
{
	size_t i;

	g_assert(equiv(0 != logfilter_logs_cnt, NULL != logfilter_logs));

	for (i = 0; i < logfilter_logs_cnt; i++) {
		lf_logfile_t *lg = &logfilter_logs[i];

		atom_str_free_null(&lg->path);
		fd_close(&lg->fd);
	}

	HFREE_NULL(logfilter_logs);
	logfilter_logs_cnt = 0;
}

#if defined(S_IROTH)
#define LF_LOG_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* 0644 */
#else
#define LF_LOG_MODE	(S_IRUSR | S_IWUSR | S_IRGRP)			/* 0640 */
#endif

/**
 * Open user-defined logfile and register it in logfilter_logs[].
 */
static void
lf_open_log(const void *key, void *value, void *udata)
{
	size_t idx = pointer_to_size(value) - 1;	/* See lf_logfile_get_index() */
	lf_logfile_t *lg;

	g_assert(idx < logfilter_logs_cnt);
	(void) udata;

	lg = &logfilter_logs[idx];
	lg->path = eval_subst_atom(key);
	lg->fd = file_open(lg->path, O_CREAT | O_APPEND | O_WRONLY, LF_LOG_MODE);
}

/**
 * Open all the user-defined logfiles.
 */
static void
lf_open_all_logfiles(const lf_parser_t *lp)
{
	size_t cnt;

	g_assert(NULL == logfilter_logs);
	g_assert(0 == logfilter_logs_cnt);
	g_assert(LOGFILTER_IS_WRITE_LOCKED);

	cnt = htable_count(lp->logfiles);

	if (0 == cnt)
		return;

	HALLOC0_ARRAY(logfilter_logs, cnt);
	logfilter_logs_cnt = cnt;

	/* Mark all fds invalid in case we have to log something whilst opening */

	while (cnt--)
		logfilter_logs[cnt].fd = -1;

	htable_foreach(lp->logfiles, lf_open_log, NULL);
}

/**
 * Handle the "name" option.
 *
 * @return TRUE if option value was correctly processed.
 */
#define LF_HANDLE_OPTION_V(name,type)						\
static bool											\
lf_handle_option_ ## name(const char *value)		\
{													\
	enum lf_ ## type id;							\
	id = TOKENIZE(value,							\
		logfilter_ ## type ## _option_values);		\
	if G_UNLIKELY(0 == id)							\
		return FALSE;								\
	logfilter_options.name = id;					\
	return TRUE;									\
}

#define LF_HANDLE_OPTION(name) LF_HANDLE_OPTION_V(name, name)

LF_HANDLE_OPTION_V(highlight, match);
LF_HANDLE_OPTION(match);
LF_HANDLE_OPTION(where);

static struct lf_option_handler {
	const char *name;				/* Option name */
	lf_option_handler_t handler;	/* Handler routine to install option */
} logfilter_option_handlers[] = {
	/* Sorted array */
	{ "highlight",	lf_handle_option_highlight },
	{ "match",		lf_handle_option_match },
	{ "where",		lf_handle_option_where },
};

/**
 * Get the option handler for a given option name.
 *
 * @param option		the name of the option we want to handle
 *
 * @return the option handler if found, NULL if name is not a valid option.
 */
static lf_option_handler_t
lf_option_handler_lookup(const char *option)
{
	g_assert(option != NULL);

	STATIC_ASSERT(LF_OPTION_MAX - 1 == N_ITEMS(logfilter_option_handlers));

#define GET_KEY(i)	(logfilter_option_handlers[i].name)
#define FOUND(i)	return logfilter_option_handlers[i].handler

	BINARY_SEARCH(const char *, option,
		N_ITEMS(logfilter_option_handlers), strcmp, GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY

	return NULL;
}

/**
 * Hash table iterator to process an option.
 */
static void
lf_option_handle(const void *key, void *value, void *data)
{
	const char *name = key;
	const char *string = value;
	lf_option_handler_t h;

	(void) data;

	h = lf_option_handler_lookup(name);
	g_return_if_fail(h != NULL);	/* Name validated during parsing */

	if (!(*h)(value)) {
		s_warning("LOGFILTER ignoring invalid value \"%s\" for option \"%s\"",
			string, name);
	}
}

/**
 * Handle user-defined options.
 */
static void
lf_handle_options(const lf_parser_t *lp)
{
	lf_parser_check(lp);

	htable_foreach(lp->options, lf_option_handle, NULL);
}

/**
 * Rule dumping context.
 */
typedef struct logfilter_dump_ctx {
	ostream_t *os;
	uint depth;
	lf_constant_id_t args[LF_ARG_MAX];
} lf_dump_ctx_t;

/**
 * Emit leading indentation.
 */
static void
lf_indent_dump(const lf_dump_ctx_t *ctx)
{
	uint i;

	for (i = 0; i < ctx->depth; i++)
		ostream_putc(ctx->os, '\t');
}

static void lf_recursive_block_dump(const lf_block_t *lb, lf_dump_ctx_t *ctx);

static void
lf_selector_dump(const lf_selector_t *ls, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;

	lf_selector_check(ls);

	if (ls->negated)
		ostream_putc(os, '!');

	switch (ls->magic) {
	case LOGFILTER_SELECTOR_BASE_MAGIC:
	case LOGFILTER_SELECTOR_MASK_MAGIC:
		g_assert_not_reached();
	case LOGFILTER_SELECTOR_MESSAGE_STR_MAGIC:
		ostream_printf(os, "message \"%s\"", ls->u.str);
		break;
	case LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC:
		ostream_printf(os, "routine \"%s\"", ls->u.str);
		break;
	case LOGFILTER_SELECTOR_FILE_STR_MAGIC:
		ostream_printf(os, "file \"%s\"", ls->u.str);
		break;
	case LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC:
		{
			re_regex_t *re = lf_selector_regex(ls);
			ostream_printf(os, "message %s", lf_regex_as_string(re));
		}
		break;
	case LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC:
		ostream_printf(os, "routine %s", lf_regex_as_string(ls->u.re));
		break;
	case LOGFILTER_SELECTOR_FILE_RE_MAGIC:
		ostream_printf(os, "file %s", lf_regex_as_string(ls->u.re));
		break;
	case LOGFILTER_SELECTOR_LEVEL_MAGIC:
		ostream_printf(os, "level %s %s",
			lf_cmp_string(ls->op), lf_log_level_string(ls->u.lvl));
		break;
	case LOGFILTER_SELECTOR_LINE_MAGIC:
		ostream_printf(os, "line %s %lu", lf_cmp_string(ls->op), ls->u.uv);
		break;
	}

	if (ls->insensitive)
		ostream_putc(os, 'i');
}

/**
 * Dump action flags.
 *
 * @param flags		the flags
 * @param is_set	if TRUE, then these are flags to set (otherwise, clear them)
 * @param is_first	if TRUE, this is the first flags to be printed
 *
 * @return TRUE if we had an empty set of flags to print.
 */
static bool
lf_action_flags_dump(uint32 flags, bool is_set, bool is_first, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;
	uint i;
	uint32 m;
	bool first = is_first;
	static const char *names[] = {
		/* In LF_FLG_* order -- some cannot be negated, that's OK */
		"break",
		"carp",
		"level",
		"log",
		"routine",
		"where",
		"ignore",
		"next",
		"stop",
		"match",
	};

	for (i = 0, m = 1; i < N_ITEMS(names); i++, m <<= 1) {
		if (flags & m) {
			/*
			 * If flag is set and is subject to bearing an optional
			 * constant token to alter its runtime behaviour, and that
			 * token has been seen already, then it has already been dumped
			 * at the beginning of the action list and there is no need to
			 * re-dump it here.
			 */

			if (is_set && htable_contains(logfilter_flags_map, names[i])) {
				uint idx = pointer_to_uint(
					htable_lookup(logfilter_flags_map, names[i]));

				g_assert(idx < N_ITEMS(ctx->args));

				if (ctx->args[idx] != 0)
					continue;		/* Has been set already */
			}

			if (!first)
				ostream_puts(os, ", ");
			first = FALSE;
			ostream_printf(os, "%s%s", is_set ? "" : "no", names[i]);
		}
	}

	return first;
}

static void
lf_action_dump(const lf_action_t *la, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;
	bool empty;

	lf_action_check(la);

	switch (la->magic) {
	case LOGFILTER_ACTION_BASE_MAGIC:
	case LOGFILTER_ACTION_MASK_MAGIC:
		g_assert_not_reached();
	case LOGFILTER_ACTION_FLAGS_MAGIC:
		empty = lf_action_flags_dump(la->u.flags.set, TRUE, TRUE, ctx);
		lf_action_flags_dump(la->u.flags.clear, FALSE, empty, ctx);
		break;
	case LOGFILTER_ACTION_FLAG_SET_ARG_MAGIC:
		g_assert(la->u.set.idx < N_ITEMS(ctx->args));
		ostream_printf(os, "%s %s",
			logfilter_arg2token_string[la->u.set.idx],
			lf_constant_string(la->u.set.arg));
		/* Remember so that we do not dump this flag setting in the list */
		ctx->args[la->u.set.idx] = la->u.set.arg;
		break;
	case LOGFILTER_ACTION_COPY_OUT_MAGIC:
		ostream_puts(os, "copy out");
		break;
	case LOGFILTER_ACTION_COPY_PATH_MAGIC:
		g_assert(la->u.logidx < logfilter_logs_cnt);
		ostream_printf(os, "copy \"%s\"", logfilter_logs[la->u.logidx].path);
		break;
	case LOGFILTER_ACTION_TAG_MAGIC:
		ostream_printf(os, "tag \"%s\"", la->u.value);
		break;
	case LOGFILTER_ACTION_STRIP_TAG_MAGIC:
		ostream_printf(os, "strip \"%s\"", la->u.value);
		break;
	case LOGFILTER_ACTION_STRIP_ROUTINE_MAGIC:
		ostream_puts(os, "strip routine");
		break;
	case LOGFILTER_ACTION_STRIP_WHERE_MAGIC:
		ostream_puts(os, "strip where");
		break;
	case LOGFILTER_ACTION_COLOR_MAGIC:
		ostream_printf(os, "color \"%s\"", color_decompile(la->u.value));
		break;
	case LOGFILTER_ACTION_HIGHLIGHT_MAGIC:
		ostream_printf(os, "highlight %lu", la->u.gn);
		break;
	}
}

static void
lf_selector_list_dump(const lf_selector_t *head, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;
	const lf_selector_t *ls, *next;

	for (ls = head; ls != NULL; ls = next) {
		lf_selector_check(ls);
		next = ls->next;
		if (ls != head)
			ostream_puts(os, ", ");
		lf_selector_dump(ls, ctx);
	}
}

static void
lf_action_list_dump(const lf_action_t *head, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;
	const lf_action_t *la, *next;

	ZERO(&ctx->args);

	for (la = head; la != NULL; la = next) {
		lf_action_check(la);
		next = la->next;
		if (la != head)
			ostream_puts(os, ", ");
		lf_action_dump(la, ctx);
	}
}

static void
lf_rule_dump(const lf_rule_t *lr, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;

	lf_rule_check(lr);
	g_assert(LOGFILTER_IS_READ_LOCKED);

	lf_indent_dump(ctx);
	if (lr->selector_list != NULL) {
		lf_selector_list_dump(lr->selector_list, ctx);
		ostream_puts(os, ": ");
	}
	lf_action_list_dump(lr->action_list, ctx);
	ostream_puts(os, ";\n");
}

/**
 * List iterator to dump data.
 */
static void
lf_rule_or_block_dump(void *data, void *udata)
{
	const lf_rule_or_block_t *rob = data;

	if (LOGFILTER_BLOCK_MAGIC == rob->magic) {
		lf_recursive_block_dump((lf_block_t *) rob, udata);
	} else if (LOGFILTER_RULE_MAGIC == rob->magic) {
		lf_rule_dump((lf_rule_t *) rob, udata);
	} else {
		g_assert_not_reached();		/* Must be either a rule or a block */
	}
}

static void
lf_recursive_block_dump(const lf_block_t *lb, lf_dump_ctx_t *ctx)
{
	ostream_t *os = ctx->os;

	lf_block_check(lb);

	lf_indent_dump(ctx);

	if (lb->selector_list != NULL) {
		lf_selector_list_dump(lb->selector_list, ctx);
		ostream_puts(os, " {\n");
	} else if (0 != ctx->depth) {
		ostream_puts(os, "{\n");
	}

	ctx->depth++;
	pslist_foreach(lb->list, lf_rule_or_block_dump, ctx);
	ctx->depth--;

	if (0 != ctx->depth) {
		lf_indent_dump(ctx);
		ostream_puts(os, "}\n");
	}
}

/**
 * Dump logging options to speficied file, for debugging and education.
 *
 * Options are listed even if they were not superseded, to document the
 * available option keys and show defaults explicitly.
 */
static void
lf_options_dump_fd(int fd, const lf_options_t *options)
{
	str_t *s = str_new(0);
	ostream_t *os;

#define SHOW_V(x,y)												\
	ostream_printf(os, "\t\t%s = \"%s\"\n", #x,					\
		lf_option_ ## y ## _as_string(options->x))

#define SHOW(x) SHOW_V(x,x)

	os = ostream_open_str(s);
	ostream_puts(os, "\toptions {\n");

	SHOW_V(highlight,match);
	SHOW(match);
	SHOW(where);

	ostream_puts(os, "\t}\n");
	ostream_close(os);

#undef SHOW

	IGNORE_RESULT(write(fd, str_2c(s), str_len(s)));
	str_destroy_null(&s);
}

/**
 * Dump rules to specified file, for debugging.
 */
static void
lf_rules_dump_fd(int fd, const lf_block_t *root)
{
	lf_dump_ctx_t ctx;
	str_t *s = str_new(0);

	ZERO(&ctx);

	ctx.os = ostream_open_str(s);
	lf_recursive_block_dump(root, &ctx);
	ostream_close(ctx.os);

	IGNORE_RESULT(write(fd, str_2c(s), str_len(s)));

	str_destroy_null(&s);
}

/**
 * Cleanup all dynamic data structures.
 */
static void
lf_cleanup(void)
{
	g_assert(LOGFILTER_IS_WRITE_LOCKED);

	lf_free_all_rules();
	lf_options_reset();
	lf_close_all_logfiles();
	ZERO(&logfilter_attrs);
}

/**
 * Construct new dynamic data structures for runtime based on the parsed
 * information we gathered.
 */
static void
lf_install_rules(lf_parser_t *lp)
{
	LOGFILTER_WRITE_LOCK;
	lf_cleanup();

	logfilter_root_block = LF_STEAL(lp->root);
	logfilter_attrs = lp->attrs;		/* Struct copy */

	s_debug("%s(): record_matches = %s",
		G_STRFUNC, bool_to_string(logfilter_attrs.record_matches));

	/*
	 * If there are no rules, release the block and nullify pointer.
	 */

	if (NULL == logfilter_root_block->list) {
		lf_free_all_rules();
		s_warning("LOGFILTER no rules were defined");
		LOGFILTER_WRITE_UNLOCK;
	} else {
		lf_open_all_logfiles(lp);
		lf_handle_options(lp);

		/*
		 * Can now relinquish the write-lock.  We downgrade to a read-lock
		 * to be able to atomically log the rules we just installed.
		 */

		LOGFILTER_DOWNGRADE_LOCK;

		/*
		 * Always dump the installed rules, so that we know what happens
		 * should we get no logging at all.
		 */
		s_debug("LOGFILTER installed rules:");
		LOG_FOREACH(fd,
			lf_options_dump_fd(fd, &logfilter_options);
			lf_rules_dump_fd(fd, logfilter_root_block);
		);
		LOGFILTER_READ_UNLOCK;
	}
}

/**
 * Watcher callback, invoked when the file useed to install logfilter
 * rules is being changed on the disk.
 */
static void
logfilter_file_changed(const char *filename, void *unused_udata)
{
	(void) unused_udata;

	if (logfilter_crashing)
		return;				/* Ignore silently when crashing! */

	if (lf_debugging(1))
		s_info("LOGFILTER reloading %s", filename);

	if (!logfilter_install(filename))
		s_warning("LOGFILTER failed reloading from %s", filename);
}

/**
 * Compute (and cache) length of file name.
 */
static size_t
lf_file_len(lf_runstate_t *ctx)
{
	if G_UNLIKELY((size_t) -1 == ctx->filelen)
		ctx->filelen = vstrlen(ctx->file);

	return ctx->filelen;
}

/**
 * Compute (and cache) length of routine name.
 */
static size_t
lf_routine_len(lf_runstate_t *ctx)
{
	if G_UNLIKELY((size_t) -1 == ctx->routlen)
		ctx->routlen = vstrlen(ctx->data->routine);

	return ctx->routlen;
}

/**
 * Record highlighting position after a successful match.
 */
static void
lf_highlight_record(const lf_regex_t *cre, lf_runstate_t *ctx)
{
	const pslist_t *sl;

	lf_regex_check(cre);
	lf_runstate_check(ctx);

	PSLIST_FOREACH(cre->captured, sl) {
		re_match_t *m;
		ulong gn = pointer_to_ulong(sl->data);

		g_assert(gn < ctx->mlen);

		m = balloc_try_alloc(lf_match_positions);
		if (m != NULL) {
			*m = ctx->mvec[gn];		/* Struct copy */
			ctx->highlight =
				pslist_prepend_ext(ctx->highlight, m, &lf_pslist_alloc);
		}
	}
}

/**
 * Apply a selector.
 *
 * @return TRUE if the selector matches.
 */
static bool
lf_apply_selector(const lf_selector_t *ls, lf_runstate_t *ctx)
{
	bool v = TRUE;
	bool level_selection = FALSE;

	lf_selector_check(ls);
	lf_runstate_check(ctx);

	switch (ls->magic) {
	case LOGFILTER_SELECTOR_BASE_MAGIC:
	case LOGFILTER_SELECTOR_MASK_MAGIC:
		g_assert_not_reached();
	case LOGFILTER_SELECTOR_MESSAGE_STR_MAGIC:
		v = 0 == strcmp(ctx->logmsg, ls->u.str);
		break;
	case LOGFILTER_SELECTOR_MESSAGE_RE_MAGIC:
		{
			if (ls->capture) {
				const lf_regex_t *cre = ls->u.cre;

				lf_regex_check(cre);

				/* We need to record subgroup positions for highlighting */
				v = 1 == re_execute_full(cre->re, ctx->logmsg, ctx->loglen,
					ctx->mvec, ctx->mlen, 0);

				if (v)
					lf_highlight_record(cre, ctx);
			} else {
				/* We only need to capture the whole matching position */
				v = 1 == re_execute_full(ls->u.re, ctx->logmsg, ctx->loglen,
					ctx->mvec, ctx->mlen, RE_X_NOSUB);
			}

			/* Record match position if they use "match" somewhere */

			if (v && ctx->attrs.record_matches) {
				re_match_t *pos = balloc_try_alloc(lf_match_positions);

				if (pos != NULL) {
					*pos = ctx->mvec[0];	/* Struct copy */
					ctx->match =
						pslist_prepend_ext(ctx->match, pos, &lf_pslist_alloc);
				}
			}
		}
		break;
	case LOGFILTER_SELECTOR_ROUTINE_STR_MAGIC:
		v = 0 == strcmp(ctx->data->routine, ls->u.str);
		break;
	case LOGFILTER_SELECTOR_ROUTINE_RE_MAGIC:
		v = 1 == re_execute_len(ls->u.re,
					ctx->data->routine, lf_routine_len(ctx), 0);
		break;
	case LOGFILTER_SELECTOR_FILE_STR_MAGIC:
		v = NULL != is_strsuffix(ctx->file, lf_file_len(ctx), ls->u.str);
		break;
	case LOGFILTER_SELECTOR_FILE_RE_MAGIC:
		v = 1 == re_execute_len(ls->u.re, ctx->file, lf_file_len(ctx), 0);
		break;
	case LOGFILTER_SELECTOR_LEVEL_MAGIC:
		level_selection = TRUE;
		switch (ls->op) {
		case LF_LVL_EQ:  v = ctx->level == ls->u.lvl; break;
		case LF_LVL_GT:  v = ctx->level >  ls->u.lvl; break;
		case LF_LVL_GTE: v = ctx->level >= ls->u.lvl; break;
		case LF_LVL_LT:  v = ctx->level <  ls->u.lvl; break;
		case LF_LVL_LTE: v = ctx->level <= ls->u.lvl; break;
		case LF_LVL_NE:  v = ctx->level != ls->u.lvl; break;
		default: g_assert_not_reached();
		}
		break;
	case LOGFILTER_SELECTOR_LINE_MAGIC:
		switch (ls->op) {
		case LF_LVL_EQ:  v = ctx->data->line == ls->u.uv; break;
		case LF_LVL_GT:  v = ctx->data->line >  ls->u.uv; break;
		case LF_LVL_GTE: v = ctx->data->line >= ls->u.uv; break;
		case LF_LVL_LT:  v = ctx->data->line <  ls->u.uv; break;
		case LF_LVL_LTE: v = ctx->data->line <= ls->u.uv; break;
		case LF_LVL_NE:  v = ctx->data->line != ls->u.uv; break;
		default: g_assert_not_reached();
		}
		break;
	}

	if (ls->negated)
		v = !v;

	if (v && !level_selection)
		ctx->flags |= LF_FLG_SELECTED;	/* Matched something other than level */

	return v;
}

/**
 * Apply a selector list.
 *
 * @return TRUE if all the selectors match, or if the list is empty.
 */
static bool
lf_apply_selector_list(const lf_selector_t *head, lf_runstate_t *ctx)
{
	const lf_selector_t *ls, *next;

	lf_runstate_check(ctx);

	/*
	 * We want to know whether we selected successfully on something other
	 * than a logging level.
	 */

	ctx->flags &= ~LF_FLG_SELECTED;

	for (ls = head; ls != NULL; ls = next) {
		lf_selector_check(ls);
		next = ls->next;
		if (!lf_apply_selector(ls, ctx))
			return FALSE;
	}

	return TRUE;	/* All selectors matched, or list was empty */
}

/**
 * Determines whether we need to continue parsing other rules.
 */
static bool
lf_apply_can_continue(lf_runstate_t *ctx)
{
	bool cont;

	lf_runstate_check(ctx);

	/*
	 * If the selection was only made on the log level, we need
	 * to continue matching other rules.
	 *
	 * If the "break" flag is set, then we need to continue
	 * matching other rules.
	 *
	 * If they decided to ignore the log message, we can stop matching.
	 *
	 * If they said "next" we need to continue, after clearing that flag.
	 * If they said "stop" we need to stop, after clearing that flag.
	 */

	if (ctx->flags & LF_FLG_SELECTED) {
		cont = FALSE;
		/* Matched on something other than a log level */
		ctx->flags &= ~LF_FLG_SELECTED;
	} else {
		cont = TRUE;
	}

	if (ctx->flags & LF_FLG_BREAK)
		cont = TRUE;

	if (ctx->flags & LF_FLG_IGNORE)
		cont = FALSE;

	if (ctx->flags & LF_FLG_STOP) {
		/* Explicit "stop" request, we're done */
		ctx->flags &= ~LF_FLG_STOP;
		return FALSE;	/* That's final! */
	}

	if (ctx->flags & LF_FLG_NEXT) {
		/* Explicit "next" request, continue */
		ctx->flags &= ~LF_FLG_NEXT;
		return TRUE;	/* That's final! */
	}

	return cont;
}

/**
 * Process the action.
 */
static void
lf_apply_action(const lf_action_t *la, lf_runstate_t *ctx)
{
	lf_action_check(la);
	lf_runstate_check(ctx);

	switch (la->magic) {
	case LOGFILTER_ACTION_BASE_MAGIC:
	case LOGFILTER_ACTION_MASK_MAGIC:
		g_assert_not_reached();
	case LOGFILTER_ACTION_FLAGS_MAGIC:
		ctx->flags |= la->u.flags.set;
		ctx->flags &= ~la->u.flags.clear;
		break;
	case LOGFILTER_ACTION_FLAG_SET_ARG_MAGIC:
		g_assert(la->u.set.idx < N_ITEMS(ctx->args));
		ctx->args[la->u.set.idx] = la->u.set.arg;
		break;
	case LOGFILTER_ACTION_COPY_OUT_MAGIC:
		ctx->flags |= LF_FLG_STDOUT;
		break;
	case LOGFILTER_ACTION_COPY_PATH_MAGIC:
		g_assert(la->u.logidx < logfilter_logs_cnt);
		{
			int fd = logfilter_logs[la->u.logidx].fd;
			ctx->copy = pslist_prepend_ext(
				ctx->copy, int_to_pointer(fd), &lf_pslist_alloc);
		}
		break;
	case LOGFILTER_ACTION_TAG_MAGIC:
		ctx->tag = pslist_prepend_ext(
			ctx->tag, deconstify_char(la->u.value), &lf_pslist_alloc);
		break;
	case LOGFILTER_ACTION_STRIP_TAG_MAGIC:
		ctx->strip = pslist_prepend_ext(
			ctx->strip, deconstify_char(la->u.value), &lf_pslist_alloc);
		break;
	case LOGFILTER_ACTION_STRIP_ROUTINE_MAGIC:
		ctx->flags |= LF_FLG_NOROUTINE;
		break;
	case LOGFILTER_ACTION_STRIP_WHERE_MAGIC:
		ctx->flags |= LF_FLG_NOWHERE;
		break;
	case LOGFILTER_ACTION_COLOR_MAGIC:
		ctx->color = la->u.value;
		break;
	case LOGFILTER_ACTION_HIGHLIGHT_MAGIC:
		/* Nothing to do now */
		break;
	}
}

/**
 * Process the action list.
 */
static void
lf_apply_action_list(const lf_action_t *head, lf_runstate_t *ctx)
{
	const lf_action_t *la, *next;

	lf_runstate_check(ctx);

	for (la = head; la != NULL; la = next) {
		lf_action_check(la);
		next = la->next;
		lf_apply_action(la, ctx);
	}
}

/**
 * Process logfilter rule.
 *
 * @return TRUE if we need to continue filtering, FALSE if we have to stop.
 */
static bool
lf_apply_rule(const lf_rule_t *lr, lf_runstate_t *ctx)
{
	lf_rule_check(lr);
	lf_runstate_check(ctx);

	/*
	 * We need to process the rule if there are no selector,
	 * or when all the defined selectors match.
	 */

	if (lf_apply_selector_list(lr->selector_list, ctx)) {
		lf_apply_action_list(lr->action_list, ctx);
		return lf_apply_can_continue(ctx);
	}

	return TRUE;	/* Selector did not match, continue */
}

/**
 * Process logfilter block.
 *
 * @return TRUE if we need to continue filtering, FALSE if we have to stop.
 */
static bool
lf_apply_block(const lf_block_t *lb, lf_runstate_t *ctx)
{
	lf_block_check(lb);
	lf_runstate_check(ctx);

	/*
	 * We need to process the rules of the block if there are no selector,
	 * or all the defined selectors match.
	 */

	if (lf_apply_selector_list(lb->selector_list, ctx)) {
		pslist_t *sl;
		bool complex_selection = booleanize(ctx->flags & LF_FLG_SELECTED);

		PSLIST_FOREACH(lb->list, sl) {
			const lf_rule_or_block_t *rob = sl->data;

			if (LOGFILTER_BLOCK_MAGIC == rob->magic) {
				if (!lf_apply_block((lf_block_t *) rob, ctx))
					return FALSE;
			} else if (LOGFILTER_RULE_MAGIC == rob->magic) {
				if (!lf_apply_rule((lf_rule_t *) rob, ctx))
					return FALSE;
			} else {
				g_assert_not_reached();
			}
		}

		/*
		 * Restore complex selection status for the block, since this
		 * status is constantly reset by each selection.
		 */

		if (complex_selection)
			ctx->flags |= LF_FLG_SELECTED;
		else
			ctx->flags &= ~LF_FLG_SELECTED;

		return lf_apply_can_continue(ctx);
	}

	return TRUE;	/* Selector did not match, continue */
}

/**
 * Apply logfilter rules.
 *
 * There are three variables in the context that get changed through our
 * processing:
 *
 * 	ctx.flags		the operating flags get updated after each rule
 *  ctx.copy		is filled with paths of additional logfiles to write to
 *
 * @param root		the root block (can be NULL, which does nothing)
 * @param ctx		the processing runtime context
 */
static void
lf_apply(const lf_block_t *root, lf_runstate_t *ctx)
{
	lf_runstate_check(ctx);

	if (NULL == root)
		return;

	lf_block_check(root);

	(void) lf_apply_block(root, ctx);
}

/**
 * Parse new logfilter rules and install them.
 *
 * A non-existing file is dismissed silently.
 *
 * If the file parses correctly, then it becomes automatically monitored
 * and any changes to the file will be reloaded every 30 seconds or so.
 *
 * @param file	the file containing the rules
 *
 * @return TRUE if we successfully parsed and installed the rules.
 */
bool
logfilter_install(const char *file)
{
	FILE *f;
	istream_t *is;
	lf_parser_t *lp;
	bool ok = FALSE;
	static const char *monitored_file;

	logfilter_init();	/* Auto-initialization */

	/*
	 * Open the file first.  If we can't, then there is no need to
	 * remove existing rules.
	 */

	f = file_fopen_missing(file, "r");
	if (NULL == f)
		return FALSE;		/* Error already logged with stacktrace */

	is = istream_open_file(f);
	lp = lf_parser_alloc(is);

	/*
	 * If we parse the whole file successfully, remove previous rules
	 * and install the new ones from the information we gathered during
	 * parsing.
	 */

	if (lf_parse(lp)) {
		if (lf_debugging(2))
			s_info("LOGFILTER installing rules from %s", file);

		ok = TRUE;
		lf_install_rules(lp);
	} else if (NULL == monitored_file) {
		s_warning("LOGFILTER not loading rules from %s", file);
	}

	istream_close_file(is);
	lf_parser_free(lp);

	/*
	 * Monitor the file for changes to auto-reload it.
	 */

	if (monitored_file != NULL) {
		if (0 != strcmp(monitored_file, file)) {
			/* File name changed */
			watcher_unregister(monitored_file);
			atom_str_free_null(&monitored_file);
		}
	}

	if (NULL == monitored_file) {
		/* First time we encounter this file name */
		monitored_file = atom_str_get(file);
		watcher_register(monitored_file, logfilter_file_changed, NULL);
	}

	return ok;
}

const char logfilter_config_test[] = "enable {\n\
	# This is totally meaningless, just to exercise parsing\n\
	a = \"/foo/bar\";\n\
	nowhere, nobreak;\n\
	level != message: nolog;\n\
	level <= message: nobreak, where;\n\
	level > message: copy a, level;\n\
	message \"string\": ignore, nolevel, noroutine;\n\
	\"routine()\": carp, routine, nowhere; \n\
	routine \"blah\": carp; \n\
	routine /_error$/: carp *mini; \n\
	func(): carp; \n\
	long_routine_func() {\n\
		carp, break; \n\
		\"foo.c\": nolog, copy a;\n\
	}\n\
	\"static_string\": log; \n\
	/simple, regular with no'@ meta!/i: log; \n\
	/ab.c* has meta!/: ignore; \n\
	/has a \\/ but no meta!/: nolog; \n\
	m|with un-escaped \\|meta delimiter|i: nolog; \n\
	m|with escaped \\\\\\|meta delimiter|i: ignore; \n\
	m!with escaped \\| pipe char!: break; \n\
	m!with escaped \\| pipe char in .* regex!, \n\
	m|without meta|: nocarp, log, copy a, copy \"foo\";\n\
	m,with escaped\\, but no meta,,\n\
	m|constant string|: next;\n\
}";

/**
 * Parse test file to ensure we don't accidentally break something.
 */
static void
lf_config_parsing_test(void)
{
	bstr_t *bs;
	istream_t *is;
	lf_parser_t *lp;

	bs = bstr_open(ARYLEN(logfilter_config_test) - 1, BSTR_F_ERROR);
	is = istream_open_bstr(bs);
	lp = lf_parser_alloc(is);

	if (!lf_parse(lp))
		s_warning("%s(): problems with the parsing test", G_STRFUNC);

	istream_close(is);
	bstr_free(&bs);
	lf_parser_free(lp);
}

/**
 * Skip word within log message, starting from given offset.
 *
 * @param s		the log string
 * @param off	the offset where we start skipping
 *
 * @return the offset of the first letter of the second word.
 */
static size_t
lf_msg_skip_word(const str_t *s, size_t off)
{
	size_t i = off;
	char c;

	/*
	 * Advance non-word characters
	 */

	while (!is_ascii_ident((c = str_at(s, i))) && c != '\0')
		i++;

	/*
	 * Skip word (identifier).
	 */

	while (is_ascii_ident(str_at(s, i)))
		i++;

	/*
	 * Advance non-word characters until we reach beginning of next word.
	 */

	while (!is_ascii_ident((c = str_at(s, i))) && c != '\0')
		i++;

	return i;
}

/**
 * Check whether string starts with "routine" or "routine()", optionally
 * followed by ":".  We also skip the initial word of the message to look
 * whether the routine name is not following that tag.
 *
 * Therefore we trap things like:
 *
 * 		foo(): some message
 * 		foo: some message
 * 		TAG foo(): some message
 * 		TAG foo: some message
 *
 * @param s			the log string
 * @param routine	the routine name we're looking for
 * @param rlen		the length of the routine name
 * @param start		if non-NULL, filled with routine starting point
 *
 * @return the offset past the routine name, skipping spaces, hence 0 means
 * the string does not start with the routine name.
 */
static size_t
lf_msg_starts_with_routine(
	const str_t *s, const char *routine, size_t rlen, size_t *start)
{
	size_t pos = rlen;

	if (!str_has_prefix_len(s, 0, routine, rlen)) {
		size_t i = lf_msg_skip_word(s, 0);
		if (!str_has_prefix_len(s, i, routine, rlen))
			return 0;
		pos += i;
	}

	if (start != NULL)
		*start = pos - rlen;	/* Where routine name started */

	if (STR_HAS_PREFIX(s, pos, "()"))
		pos += 2;
	else if ('(' == str_at(s, pos)) {
		/*
		 * If start is NULL, we're just looking at whether routine name
		 * is mentionned.
		 *
		 * If start is not NULL, we want to strip the routine name, but if
		 * there are parameters listed after the opening '(', we don't really
		 * want to remove them from the logs, so act as if there was nothing
		 * to strip by returning 0.
		 */
		if (start != NULL)
			return 0;		/* Routine name followed by '(', then something */
		return pos;			/* Has routine name */
	}

	if (STR_HAS_PREFIX(s, pos, ":")) {
		pos++;
	} else {
		/* No ":", so check we have a word boundary here */
		if (is_ascii_ident(str_at(s, pos)))
			return 0;
	}

	/*
	 * Skip spaces.
	 */

	while (is_ascii_space(str_at(s, pos)))
		pos++;

	return pos;
}

/**
 * Attempt to strip message from log.
 *
 * @param msg		the log message
 * @param s			the string we want to strip
 * @param offset	possible additional offset to remove extra chars
 *
 * @return TRUE if we stripped the string.
 */
static bool
lf_strip_anywhere(str_t *msg, str_t *s, size_t offset)
{
	size_t start;

	if (str_lookup(msg, 0, str_2c(s), &start)) {
		/* +offset below is to remove extra characters following, if any */
		str_remove(msg, start, str_len(s) + offset);
		return TRUE;
	}

	return FALSE;
}

/**
 * Strip leading tag from the log message.
 */
static void
lf_tag_strip(void *data, void *udata)
{
	const char *tag = data;
	str_t *msg = udata;
	size_t taglen;

	str_check(msg);

	taglen = vstrlen(tag);

	if (
		str_has_prefix(msg, 0, tag) &&
		is_ascii_space(str_at(msg, taglen))
	) {
		/* +1 to remove space character following prefix */
		str_remove(msg, 0, taglen + 1);
	}
}

/**
 * Prepend a tag to the log message if there is enough room.
 */
static void
lf_tag_prepend(void *data, void *udata)
{
	const char *tag = data;
	str_t *msg = udata;
	size_t taglen;

	str_check(msg);

	taglen = vstrlen(tag);

	if (str_avail(msg) >= taglen + 1 /* space */) {
		str_ichar(msg, 0, ' ');
		str_instr(msg, 0, tag, taglen);
	}
}

/**
 * Convert log flags into a log level.
 */
static enum logfilter_log_level
logfilter_level(GLogLevelFlags flags)
{
	switch (flags & G_LOG_LEVEL_MASK) {
	case G_LOG_LEVEL_CRITICAL: return LF_LOG_CRITICAL;
	case G_LOG_LEVEL_ERROR:    return LF_LOG_CRITICAL;
	case G_LOG_LEVEL_WARNING:  return LF_LOG_WARNING;
	case G_LOG_LEVEL_MESSAGE:  return LF_LOG_MESSAGE;
	case G_LOG_LEVEL_INFO:     return LF_LOG_INFO;
	case G_LOG_LEVEL_DEBUG:    return LF_LOG_DEBUG;
	}

	return LF_LOG_DEBUG;	/* Unknown, assume debug */
}

/**
 * @return proper escape sequence to turn given style on/off
 */
static const char *
lf_color_style(enum lf_match style, bool on)
{
	switch (style) {
	case LF_MATCH_UNDERLINE: return color_underline(on); break;
	case LF_MATCH_INVERSE:   return color_inverse(on);   break;
	case LF_MATCH_BLINK:     return color_blink(on);     break;
	}

	return "";
}

/**
 * Adjust all the recorded matching positions after highlighting controls
 * have been inserted.
 *
 * @param list		the list of re_match_t items
 * @param start		starting offset where "on" controls have been inserted
 * @param end		ending offset where "off" controls have been inserted
 * @param on_len	length of the "on" control sequence
 * @param off_len	length of the "off" control sequence
 */
static void
lf_highlight_adjust(pslist_t *list,
	 ssize_t start, ssize_t end,
	 size_t on_len, size_t off_len)
{
	pslist_t *sl;

	PSLIST_FOREACH(list, sl) {
		re_match_t *m = sl->data;	/* Matching segment to adjust */

		if (m->re_start >= end) {
			/* Whole segment after highlighted part */
			m->re_start += on_len + off_len;
			m->re_end   += on_len + off_len;
		} else if (m->re_start >= start) {
			/* Segment starts within highlighted part */
			m->re_start += on_len;
			if (m->re_end >= end)
				m->re_end += on_len + off_len;
			else
				m->re_end += on_len;
		} else if (m->re_end >= end) {
			/* Segment starts before and ends after highlighted part */
			m->re_end += on_len + off_len;
		} else if (m->re_end >= start)
			/* Segment start before and ends within the highlighted part */
			m->re_end += on_len;
	}
}

static inline void
lf_highlight_configure(enum lf_match style,
	const char **on, const char **off,
	size_t *on_len, size_t *off_len)
{
	*on  = lf_color_style(style, TRUE);
	*off = lf_color_style(style, FALSE);
	*on_len = vstrlen(*on);
	*off_len = vstrlen(*off);
}

/*
 * Apply highlighting of match position to string.
 *
 * @param ctx		the runtime context
 * @param msg		the log message
 * @param m			the matching position to highlight
 * @param on		the control sequence to start highlighting
 * @param off		the control sequence to stop highlighting
 * @param on_len	the length of the "on" sequence
 * @param off_len	the length of the "off" sequence
 */
static void
lf_highlight_apply(lf_runstate_t *ctx, str_t *msg,
	const re_match_t *m,
	const char *on, const char *off,
	size_t on_len, size_t off_len)
{
	/* Ensure we have space since we cannot resize the message string */
	if (str_avail(msg) < on_len + off_len)
		return;

	/* Highlight matched string */
	str_instr(msg, m->re_start, on, on_len);
	str_instr(msg, m->re_end + on_len, off, off_len);

	/* Shift all the other positions impacted by above insertions */
	lf_highlight_adjust(ctx->match,
		m->re_start, m->re_end, on_len, off_len);
	lf_highlight_adjust(ctx->highlight,
		m->re_start, m->re_end, on_len, off_len);
}

/**
 * Highlight matches and subgroups in the log message.
 *
 * @param ctx		the runtime context
 * @param msg		the log message
 */
static void
lf_highlight(lf_runstate_t *ctx, str_t *msg)
{
	const char *on;
	const char *off;
	size_t on_len;
	size_t off_len;
	re_match_t *m;

	if (ctx->flags & LF_FLG_MATCH) {
		lf_highlight_configure(
			logfilter_options.match, &on, &off, &on_len, &off_len);

		while (
			NULL != (m = pslist_shift_ext(&ctx->match, &lf_pslist_alloc))
		) {
			lf_highlight_apply(ctx, msg, m, on, off, on_len, off_len);
			balloc_free(lf_match_positions, m);
		}
	}

	if (ctx->highlight != NULL) {
		lf_highlight_configure(
			logfilter_options.highlight, &on, &off, &on_len, &off_len);

		while (
			NULL != (m = pslist_shift_ext(&ctx->highlight, &lf_pslist_alloc))
		) {
			lf_highlight_apply(ctx, msg, m, on, off, on_len, off_len);
			balloc_free(lf_match_positions, m);
		}
	}
}

/**
 * Pslist iterator to free the allocated re_match_t data.
 */
static void
lf_match_free(void *data, void *udata)
{
	(void) udata;

	balloc_free(lf_match_positions, data);
}


/**
 * Cleanup dynamically allocated structures.
 */
static void
lf_runstate_cleanup(lf_runstate_t *ctx)
{
	lf_runstate_check(ctx);

	/*
	 * Free matching positions we may have recorded.
	 */

	pslist_foreach(ctx->match,     lf_match_free, NULL);
	pslist_foreach(ctx->highlight, lf_match_free, NULL);

	/*
	 * Run-time updates to these lists uses cells allocated through our
	 * own zone, to limit memory allocation risks during critical logging.
	 */

	pslist_free_ext(ctx->strip,     &lf_pslist_alloc);
	pslist_free_ext(ctx->tag,       &lf_pslist_alloc);
	pslist_free_ext(ctx->copy,      &lf_pslist_alloc);
	pslist_free_ext(ctx->match,     &lf_pslist_alloc);
	pslist_free_ext(ctx->highlight, &lf_pslist_alloc);
}

/**
 * Reserved space for logging strings, to avoid stealing too much on the
 * stack each time we have to log.
 *
 * Per thread, we remember the last level we logged: this is for the benefits
 * of LOG_FOREACH().
 */
struct lf_reserve {
	char logmsg[LOG_MSG_MAXLEN];
	/* Save space: matchvec[] is only used during lf_apply() */
	union {
		struct {
			struct logcolor color;
			/* 255 is probably sufficient for the relative source path */
			char locbuf[255 + 3 + UINT_DEC_BUFLEN];
		} s;
		re_match_t matchvec[LOGFILTER_RE_GROUPS];
	} u;
	bool logging;
	/* The following fields are meant to be used by LOG_FOREACH() */
	enum logfilter_log_level last_level;
	size_t log_foreach_depth;		/* Track improbable recursion */
	bool color_reset;				/* Whether to reset colors */
	const char *last_color;			/* Last color emitted via LOG_FOREACH() */
};

static struct lf_reserve logfilter_reserved[THREAD_MAX];

/**
 * This is the main entry point for logging when logfilter is enabled.
 *
 * @param flags		glib-compatible log-level flags
 * @param data		meta-information about origin of log
 * @param offset	additional stack offset
 * @param fmt		formatting strings
 * @param format	whether to format arguments (if FALSE, args is NULL)
 * @param args		argument list for formatting
 *
 * It supersedes the default log_handler() routine defined normally
 * for g_xxx() logging calls and the s_logv() call for s_xxx() logging.
 */
void
logfilter_logv(
	GLogLevelFlags flags, const logfilter_data_t * const data,
	size_t offset, const char *fmt, bool format, va_list args)
{
	int saved_errno = errno;
	thread_sigsets_t set;
	void *saved, *value;
	str_t *msg, smsg;
	lf_runstate_t ctx;
	const char *prefix;
	unsigned stid;
	bool stdout_copy;
	bool in_sigh, minilog, rawlog;
	struct lf_reserve *r;
	struct logcolor *color;

#define CALLER_STACKOFF	(offset + 2)	/* Caller of our caller */

	/*
	 * If they requested once-carping, and the caller is already known, ignore.
	 */

	if G_UNLIKELY(
		(data->flags & LF_USR_ONCE) &&
		stacktrace_caller_known(CALLER_STACKOFF)
	)
		return;		/* Ignore error message */

	/*
	 * Disable filtering when crashing.
	 */

	if G_UNLIKELY(logfilter_crashing) {
		s_rawlogv(flags, TRUE, TRUE, fmt, args);
		goto bypassed;
	}

	/*
	 * Check whether they want mini (minimal amount of resources used) and/or
	 * raw (avoid taking locks) processing.
	 */

	minilog = booleanize(data->flags & LF_USR_MINILOG);
	rawlog  = booleanize(data->flags & LF_USR_RAWLOG);

	/*
	 * OK, here we go...
	 */

	stid = thread_small_id();
	r    = &logfilter_reserved[stid];

	/*
	 * Detect recursion early.
	 */

	if (r->logging) {
		s_rawlogv(flags | G_LOG_FLAG_RECURSION, TRUE, FALSE, fmt, args);
		goto bypassed;
	}

	r->logging = TRUE;

	if (!minilog && !rawlog) {
		/*
		 * Block all signals, to preserve the ability to log from a
		 * signal handler without causing recursions.
		 */

		thread_enter_critical(&set);

		/*
		 * Ask the logging layer for a string to format the message into.
		 * This also allows us to detect recursion in logging, just as
		 * s_logv() would detect it.
		 *
		 * The string is non-resizable and capped to LOG_MSG_MAXLEN bytes.
		 * When we are done logging, we need to return it to the logging
		 * layer, along with the "saved" pointer (a NULL pointer indicates
		 * that recursion was detected).
		 *
		 * If the string returned is NULL, it means there is no memory in
		 * the thread-private chunk to allocate a new string.  That error
		 * was already logged by log_string_get(), and we just ignore
		 * the message.
		 */

		saved = log_string_get(data->routine, fmt, &msg);

		if G_UNLIKELY(NULL == saved) {
			s_rawlogv(flags | G_LOG_FLAG_RECURSION, TRUE, FALSE, fmt, args);
			goto done;
		}

		if G_UNLIKELY(NULL == msg) {
			s_rawlogv(flags, FALSE, FALSE, fmt, args);
			goto done;		/* No memory to process message, sorry */
		}
	} else {
		/*
		 * Use minimal resources!
		 */

		saved = NULL;
		str_new_buffer(&smsg, ARYLEN(r->logmsg), 0);
		msg = &smsg;
	}

	/*
	 * Format log message and flag truncation.
	 */

	str_set_silent_truncation(msg, TRUE);

	if (format)
		str_vprintf(msg, fmt, args);
	else
		str_cpy(msg, fmt);	/* Already supplied formatted string */

	log_check_truncated(msg);

	/*
	 * Sanitize message.
	 *
	 * This will not perform any memory allocation (escaping is done in-place),
	 * but it will only be done when there is enough room to efficiently do it.
	 *
	 * In all cases, we srip \r in \r\n sequences but we first start to escape
	 * all the unsafe characters.  If we can't because we do not have enough
	 * room, retry with only the control characters.
	 */

	if (!str_unsafe_escape(msg, TRUE))	/* Also strips \r in \r\n sequences */
		str_ctrl_escape(msg, TRUE);		/* At least the controls */

	ZERO(&ctx);
	ctx.magic = LOGFILTER_RUNSTATE_MAGIC;
	ctx.logmsg = str_2c(msg);
	ctx.loglen = str_len(msg);
	ctx.level = logfilter_level(flags);
	ctx.file = short_filename(data->file);
	ctx.filelen = (size_t) -1;		/* Will compute and cache on first use */
	ctx.routlen = (size_t) -1;		/* Will compute and cache on first use */
	ctx.data = data;
	ctx.flags = LF_FLG_LEVEL | LF_FLG_STDERR;
	ctx.mvec = r->u.matchvec;
	ctx.mlen = N_ITEMS(r->u.matchvec);
	ctx.attrs = logfilter_attrs;	/* Struct copy */

	/*
	 * Once processing was already handled at the top of the routine.
	 * If they specified LF_USR_CARP, we'll emit a stacktrace if we
	 * log this message, unless explicitly disabled by rules via "nocarp".
	 */

	if (data->flags & LF_USR_CARP)
		ctx.flags |= LF_FLG_CARP;

	/*
	 * Shall message be copied to stdout by default?
	 */

	stdout_copy = booleanize(
		flags & (G_LOG_FLAG_FATAL |G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR)
	) || booleanize(data->flags & LF_USR_CARP);

	if (stdout_copy)
		ctx.flags |= LF_FLG_STDOUT;

	/*
	 * Here we go.
	 *
	 * We grab the read lock whilst filtering to make sure we read and
	 * process consistent data structures.
	 */

	LOGFILTER_READ_LOCK;

	lf_apply(logfilter_root_block, &ctx);

	LOGFILTER_READ_UNLOCK;

	/*
	 * If we have to drop the message, we're done.
	 */

	if (ctx.flags & LF_FLG_IGNORE)
		goto cleanup;

	if (NULL == ctx.copy && 0 == (ctx.flags & (LF_FLG_STDERR | LF_FLG_STDOUT)))
		goto cleanup;

	/*
	 * If we have a match or group highlighting to do, perform it before
	 * changing the logged string, which would invalidate the start/end
	 * matching offsets we have gathered so far.
	 */

	if ((ctx.flags & LF_FLG_MATCH) || NULL != ctx.highlight)
		lf_highlight(&ctx, msg);

	/*
	 * Strip tags from message.
	 *
	 * This comes BEFORE the possible prepending of routine name to messages,
	 * and other tags that they would want to prepend via "tag".
	 */

	pslist_foreach(ctx.strip, lf_tag_strip, msg);

	/*
	 * If they said "strip routine", then remove the routine name if it is
	 * present in the log message.
	 *
	 * We do this before possibly adding it back, so that we can normalize
	 * the logs if the routine is already mentionned in the message but
	 * not at the proper position.
	 */

	if (ctx.flags & LF_FLG_NOROUTINE) {
		/* Remove routine name if present at the start of the log message */
		size_t start;
		size_t n = lf_msg_starts_with_routine(
					msg, data->routine, lf_routine_len(&ctx), &start);
		if (0 != n) {
			g_assert(start < n);
			str_remove(msg, start, n);
		}
	}

	/*
	 * If they want the routine name, check whether it is present already
	 * in the log message. If not, prepend it.
	 */

	if (ctx.flags & LF_FLG_ROUTINE) {
		static const char separator[] = "(): ";
		uint approx = (data->flags & LF_USR_COMPUTED) ? 1 : 0;
		/* Add routine name if not present in the log message */
		if (
			0 == lf_msg_starts_with_routine(
					msg, data->routine, lf_routine_len(&ctx), NULL) &&
			str_avail(msg) >=
				lf_routine_len(&ctx) + CONST_STRLEN(separator) + approx
		) {
			str_instr(msg, 0, separator, CONST_STRLEN(separator));
			str_istr(msg, 0, data->routine);
			if (approx != 0)
				str_ichar(msg, 0, '~');	/* Signals: computed routine name */
		}
	}

	/*
	 * If they explicitly said "strip where", then remove the location if it
	 * is present in the log message.
	 *
	 * We do this before possibly re-adding it below, so that we can normalize
	 * the way source code location is displayed and where it is inserted.
	 */

	if (ctx.flags & LF_FLG_NOWHERE) {
		/* Remove source code location if present in the log message */
		str_t loc;
		const char *shortname = short_filename(data->file);

		str_new_buffer(&loc, ARYLEN(r->u.s.locbuf), 0);

		/*
		 * FIXME: use regular expression to find/replace?
		 * This can become handy if we do not know the exact line,
		 * (we have 0) but we know the filename: we can just match
		 * a digit!
		 */ 

		/* First with short filename (e.g. "lib/logfilter.c") */
		str_printf(&loc, "[%s:%u]", shortname, data->line);
		if (lf_strip_anywhere(msg, &loc, 1))
			goto stripped;
		/* Again, with parentheses */
		str_printf(&loc, "(%s:%u)", shortname, data->line);
		if (lf_strip_anywhere(msg, &loc, 1))
			goto stripped;
		/* Retry with full filename (e.g. "src/lib/logfilter.c") */
		/* Full filename is expected when using G_STRLOC */
		str_printf(&loc, "[%s:%u]", data->file, data->line);
		if (lf_strip_anywhere(msg, &loc, 1))
			goto stripped;
		/* Again, with parentheses */
		str_printf(&loc, "(%s:%u)", data->file, data->line);
		if (lf_strip_anywhere(msg, &loc, 1))
			goto stripped;
		/* G_STRLOC is expected at the beginning of log lines, usually */
		str_printf(&loc, "%s:%u: ", data->file, data->line);
		if (lf_strip_anywhere(msg, &loc, 0))
			goto stripped;
		/* Variant is "at ..." at the tail of the log usually */
		str_printf(&loc, "at %s:%u", data->file, data->line);
		if (lf_strip_anywhere(msg, &loc, 0))
			goto stripped;
	}

	/*
	 * If they want the source code location, add it to the message
	 * if not present already, by pre-pending it.
	 */

	if (ctx.flags & LF_FLG_WHERE) {
		/* Add source code location if not present in the log message */
		str_t loc;

		str_new_buffer(&loc, ARYLEN(r->u.s.locbuf), 0);
		str_printf(&loc, "[%s:%u]", short_filename(data->file), data->line);
		if (data->flags & LF_USR_COMPUTED)
			str_ichar(&loc, 0, '~');	/* Signals: computed location */
		if (
			!str_lookup(msg, 0, str_2c(&loc), NULL) &&
			str_avail(msg) >= str_len(&loc) + 1	/* space */
		) {
			if (LF_WHERE_END == logfilter_options.where) {
				/* Put "where" at the end */
				str_putc(msg, ' ');
				str_cat_len(msg, str_2c(&loc), str_len(&loc));
			} else {
				/* Put "where" at the start */
				str_ichar(msg, 0, ' ');
				str_instr(msg, 0, str_2c(&loc), str_len(&loc));
			}
		}
	}

stripped:	/* Avoids nasty nesting sequences in stripping code above */

	/*
	 * Prepend tags to message.
	 *
	 * This comes AFTER the possible prepending of routine name to messages.
	 */

	pslist_foreach(ctx.tag, lf_tag_prepend, msg);

	/*
	 * If we need to color the log, prepare a logcolor structure.
	 *
	 * The "closing" color escape sequence is the last color we emitted
	 * through LOG_FOREACH(), or the reset sequence if we're not in a
	 * colored LOG_FOREACH() sequence.
	 */

	if (ctx.color != NULL) {
		const char *reset = color_reset();
		color = &r->u.s.color;
		color->leading = ctx.color;
		if (r->last_color != NULL) {
			/* We are in a LOG_FOREACH() sequence */
			color->initial = reset;	/* Reset before the timestamp */
			color->closing = r->last_color;
		} else {
			color->initial = "";	/* No need, we're already in default */
			color->closing = reset;	/* So reset to default after logging */
		}
	} else {
		color = NULL;
	}

	/*
	 * If they do not want the log level, request that it not be added.
	 * Instead, we will add [n] if the message is not from thread #0.
	 */

	prefix = log_prefix(flags);

	if (0 == (ctx.flags & LF_FLG_LEVEL))
		prefix = NULL;

	stdout_copy = booleanize(ctx.flags & LF_FLG_STDOUT);
	in_sigh = signal_in_handler();

	if (ctx.flags & LF_FLG_STDERR) {
		log_emit(flags, msg, color, prefix, stid, in_sigh, stdout_copy, rawlog);

		/*
		 * Emit stacktrace if they requested it.
		 */

		if (ctx.flags & LF_FLG_CARP) {
			if (stdout_copy)
				s_stacktrace(TRUE, CALLER_STACKOFF);	/* Avoid stdio */
			else
				s_where(CALLER_STACKOFF);
		}
	} else if (stdout_copy) {
		/* They disabled log to stderr but requested a copy to stdout */
		ctx.copy = pslist_prepend_ext(
			ctx.copy, int_to_pointer(STDOUT_FILENO), &lf_pslist_alloc);
	}

	/*
	 * Now handle "copy" instructions.
	 */

	while (pslist_shift_data_ext(&ctx.copy, &value, &lf_pslist_alloc)) {
		int fd = pointer_to_int(value);

		if (is_valid_fd(fd)) {
			log_emit_fd(fd, flags, msg, color, prefix, stid, in_sigh, rawlog);
			if (ctx.flags & LF_FLG_CARP)
				s_where_fd(fd, CALLER_STACKOFF);
		}
	}

	/* FALL THROUGH */
cleanup:
	lf_runstate_cleanup(&ctx);

	/* FALL THROUGH */
done:
	log_string_release(saved);

	if (!minilog && !rawlog)
		thread_leave_critical(&set);

	r->last_level = ctx.level;		/* For logfilter_fds() */
	r->logging = FALSE;

	/* FALL THROUGH */
bypassed:
	errno = saved_errno;
}

/**
 * This is the main entry point for logging when logfilter is enabled.
 *
 * @param flags		glib-compatible log-level flags
 * @param data		meta-information about origin of log
 * @param fmt		formatting strings
 * @param ...		argument list for formatting
 *
 * It supersedes the default log_handler() routine defined normally
 * for g_xxx() logging calls and the s_logv() call for s_xxx() logging.
 */
void
logfilter_log(
	GLogLevelFlags flags, const logfilter_data_t * const data,
	const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	logfilter_logv(flags, data, 0, fmt, TRUE, args);
	va_end(args);
}

/**
 * List iterator to emit color codes to each file descriptor.
 */
static void
lf_emit_color(void *data, void *udata)
{
	int fd = pointer_to_int(data);
	const char *str = udata;

	g_assert(is_valid_fd(fd));

	IGNORE_RESULT(write(fd, str, vstrlen(str)));
}

/**
 * Computes the list of file descriptors to which a message whose origin
 * is given by `data' would be sent to.
 *
 * This is meant to be used through the LOG_FOREACH() macro to emit
 * additional information to the same log files as the message that most
 * probably precedes.
 *
 * For instance, old code with no logfilter awareness that the message could
 * be dispatched to many logfiles, and even not stderr, would be written like
 * this:
 *
 * 		g_debug("here is the data:");
 *		data_dump(stderr, data, len);	// sample, not actual code
 *
 * That would need to now be wrriten like this:
 *
 * 		g_debug("here is the data:");
 *		LOG_FOREACH(fd,
 *			data_dump_fd(fd, data, len);	// note signature change
 *		);
 *
 * The two changes required are the need of the fd variable (no lambdas in C),
 * and the requirement that data dumping routines work with file descriptors
 * and not stdio -- that's better for atomicity of the logging anyway.
 *
 * If possible, within the dumping routines, use atio_write() to perform atomic
 * operations.
 *
 * @param data		log data stipulating origin
 *
 * @return a new list (which may be empty) of file descriptors to which the
 * message should be sent when coming from that place.
 *
 * @note
 * It is assumed most log filtering will redirect logs based on routine or
 * source file.  If redirection happens on log message, it will not be caught
 * by this routine.
 *
 * @note
 * This routine allocates memory, via walloc() / zalloc() and possibly VMM.
 * It should therefore not be using in memory allocation routines.
 */
pslist_t *
logfilter_fds(const logfilter_data_t *data)
{
	lf_runstate_t ctx;
	pslist_t *fdl = NULL;
	void *value;
	struct lf_reserve *r = &logfilter_reserved[thread_small_id()];

	ZERO(&ctx);
	ctx.magic = LOGFILTER_RUNSTATE_MAGIC;
	ctx.logmsg = "";
	ctx.loglen = 0;
	ctx.level = r->last_level;		/* Assumption: same level as previous log */
	ctx.file = short_filename(data->file);
	ctx.filelen = (size_t) -1;		/* Will compute and cache on first use */
	ctx.routlen = (size_t) -1;		/* Will compute and cache on first use */
	ctx.data = data;
	ctx.flags = LF_FLG_STDERR;

	LOGFILTER_READ_LOCK;

	lf_apply(logfilter_root_block, &ctx);

	LOGFILTER_READ_UNLOCK;

	/*
	 * Create list of file descriptors, for those we managed to open.
	 *
	 * Since the ctx.copy list has cells allocated via a special internal
	 * allocator, we need to recreate a list with regular allocators for
	 * external consumption by our caller.
	 */

	while (pslist_shift_data_ext(&ctx.copy, &value, &lf_pslist_alloc)) {
		int fd = pointer_to_int(value);

		if (is_valid_fd(fd))
			fdl = pslist_prepend(fdl, int_to_pointer(fd));
	}

	/*
	 * Copy to stdout and stderr (the default log destination) are handled
	 * specially, hence we need to add them to the list if needed.
	 */

	if (ctx.flags & LF_FLG_STDOUT)
		fdl = pslist_prepend(fdl, int_to_pointer(STDOUT_FILENO));

	if (ctx.flags & LF_FLG_STDERR)
		fdl = pslist_prepend(fdl, int_to_pointer(STDERR_FILENO));

	/*
	 * If we have a color sequence, emit it to all the file descriptors
	 * and remember that fact.  Later when they call logfilter_fds_cleanup()
	 * we will be able to reset the color.
	 *
	 * This makes data dumping following a log message appear in the same
	 * color as the log message, transparently.  The assumption being that
	 * the LOG_FOREACH() be used right after an initial log msssage
	 * introducing the data, which it should normally.
	 *
	 * For the peculiar case where routines called by LOG_FOREACH() would
	 * need to do some logging and call LOG_FOREACH() recursively, we maintain
	 * a depth and do not change the color if the depth is greater than 1.
	 */

	r->log_foreach_depth++;

	if (ctx.color != NULL && 1 == r->log_foreach_depth) {
		r->last_color = ctx.color;	/* Remember in case of recursive logging */
		pslist_foreach(fdl, lf_emit_color, (void *) ctx.color);
		r->color_reset = TRUE;		/* For logfilter_fds_cleanup() */
	}

	lf_runstate_cleanup(&ctx);

	return fdl;
}

/**
 * Cleanup the logfilter file descriptor list.
 */
void
logfilter_fds_cleanup(pslist_t *fdl)
{
	struct lf_reserve *r = &logfilter_reserved[thread_small_id()];

	r->log_foreach_depth--;

	/*
	 * If we emitted a leading color escape in logfilter_fds(), we must
	 * send a reset escape sequence to all the files.
	 */

	if (r->color_reset && 0 == r->log_foreach_depth) {
		pslist_foreach(fdl, lf_emit_color, (void *) color_reset());
		r->last_color = NULL;
		r->color_reset = FALSE;
	}

	pslist_free(fdl);
}

/**
 * Initialize the logfilter layer, once.
 */
static void
logfilter_init_once(void)
{
	uint i;

	TOKENIZE_CHECK_SORTED(logfilter_keywords);
	TOKENIZE_CHECK_SORTED(logfilter_option_names);
	TOKENIZE_CHECK_SORTED(logfilter_match_option_values);
	TOKENIZE_CHECK_SORTED(logfilter_where_option_values);
	TOKENIZE_CHECK_SORTED(logfilter_constant_tokens);

	/*
	 * Since we use logfilter_keywords[] for lf_keytok_to_string(),
	 * we need to make sure that token ID x is at the slot x-1.
	 */

	for (i = 0; i < N_ITEMS(logfilter_keywords); i++) {
		g_assert_log(logfilter_keywords[i].value == i + 1,
			"invalid position for \"%s\" in logfilter_keywords[%u]: "
			"expected to find token value %u at offset %u instead",
			logfilter_keywords[i].token, i, logfilter_keywords[i].value,
			logfilter_keywords[i].value - 1);
	}

	balloc_init(sizeof(pslist_t),   ARYLEN(lf_pslist_cells));
	balloc_init(sizeof(re_match_t), ARYLEN(lf_match_positions));

	/*
	 * Create the token -> argument index map to assist parsing for
	 * actions whose behaviour can be modified by a constant token.
	 *
	 * We also fill-in the reverse mappings arrays to map back the
	 * argument index to either a token ID or to the token name.
	 */

	logfilter_action_map = htable_create(HASH_KEY_SELF, 0);
	logfilter_flags_map  = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < N_ITEMS(logfilter_flag_arguments); i++) {
		struct logfilter_action_args *a = &logfilter_flag_arguments[i];
		lf_token_id_t id;

		g_assert(a->idx < LF_ARG_MAX);

		id = TOKENIZE(a->name, logfilter_keywords);

		g_assert_log(id != 0,
			"%s(): unknown token \"%s\" at index %u", G_STRFUNC, a->name, i);

		g_assert_log(!htable_contains(logfilter_flags_map, a->name),
			"%s(): duplicate \"%s\" at index %u", G_STRFUNC, a->name, i);

		htable_insert(logfilter_action_map,
			uint_to_pointer(id), uint_to_pointer(a->idx));

		htable_insert(logfilter_flags_map,
			a->name, uint_to_pointer(a->idx));

		logfilter_arg2token_map[a->idx] = id;
		logfilter_arg2token_string[a->idx] = a->name;
	}

	/*
	 * Perform quick sanity tests.
	 */

	lf_regex_parsing_test();
	lf_config_parsing_test();

	/*
	 * Warn loudly if logfilter is not supported!
	 */

	if (!logfilter_supported())
		s_warning("LOGFILTER no runtime support for logfilter");
}

/**
 * Is the logfilter active (with installed rules)?
 */
bool
logfilter_is_active(void)
{
	return logfilter_supported() && logfilter_root_block != NULL;
}

/**
 * Initialization.
 */
void G_COLD
logfilter_init(void)
{
	static once_flag_t logfilter_inited;

	ONCE_FLAG_RUN(logfilter_inited, logfilter_init_once);
}

/**
 * Shutdown.
 */
void G_COLD
logfilter_close(void)
{
	LOGFILTER_WRITE_LOCK;
	lf_cleanup();
	LOGFILTER_WRITE_UNLOCK;

	htable_free_null(&logfilter_action_map);
	htable_free_null(&logfilter_flags_map);
}

/* vi: set ts=4 sw=4 cindent: */
