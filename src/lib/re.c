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
 * This is minimal not in the feature set, which is quite extensive, but in
 * the requirements that:
 *
 *   - when searching, NO MEMORY BE ALLOCATED apart from stack space
 *   - NO LOCKS BE TAKEN (prohibiting strategies where we could pre-allocate
 *     runtime memory when compiling since locking would be required to
 *     execute the matching operations in a multi-threaded environment).
 *   - no shared internal data structure may be changed at runtime.
 *   - only ASCII (or any other 8-bit charset) be supported; that means
 *     each input character is assumed to be fully represented by one single
 *     byte). That is meant for efficient and ease of implementation of the
 *     wildcard '.', especially for backtracking purposes.
 *
 * This regex package supports:
 *
 * 	re_compile()	compiles the given pattern (regular expression)
 * 	re_recompile()	re-compiles the compiled pattern with different options
 * 	re_free()		frees the compiled pattern
 * 	re_execute()	searches text for the compiled pattern (many variants)
 *
 * META-CHARACTERS
 *
 * The following characters do not match themselves but have special meaning:
 *
 *  ^	anchors pattern start at the start of text
 *  $	anchors pattern end at the end of text
 *  .	matches any character (but may be told to avoid \n)
 *  ()	are used to group a sub-regex as one item such as (and|or) or (.*)
 *  []	define character classes such as [abc] or [a-z], leading ^ to invert
 *  |	denotes an alternative such as and|or or (a.*)|b+
 *
 * Each meta-character can be escaped by preceding it with a '\', at which time
 * it matches that escaped character: \* matches a star, \( a left parenthesis,
 * and \\ a backslash.
 *
 * REPETITIONS
 *
 * Repetition operators govern how many instances of the previous item we want
 * to match.  An item is either the previous character or character-class, or
 * a sub-regex:
 *
 *  ?   matches 0 or 1 instance
 *  *   matches 0 or more instances
 *  +   matches 1 or more instances
 *  {}  repetition range, such as {3} (exactly 3) or {2,5} (2 to 5 instances)
 *
 * All the repetition operators are "greedy" by default (matching as much as
 * possible without causing the rest of the pattern to fail).  To alter this
 * behaviour, the above repetition operators may be followed by one of:
 *
 *  ?   match as little as possible (lazy match)
 *  +   become possessive (atomic matches, never give-up matched text)
 *
 * GROUPS
 *
 * The basic form of a group is a capturing group (the string it matches
 * can be remembered and returned):
 *
 * 	(pattern)
 *
 * The matching engine offers a way to get start/end offsets of each
 * capturing group. It can also return the offsets of the whole regular
 * expression pattern, as if the whole expression was enclosed in ().
 * Furthermore, the text matched by the group may be used to match further
 * text, as explained in BACK-REFERENCES below.
 *
 * Capturing groups are numbered sequentially, as they are parsed, from
 * left to right.
 *
 * Since groups are also used to alter operator precedence, as in (a.+b|c)+,
 * but we may not wish to capture the matched part, we support non-capturing
 * groups:
 *
 * 	(?:pattern)
 *
 * Hence we can write (?:a.+b|c)+ to avoid saying a.+b|c+, which would be
 * understood as (?:a.+b)|(?:c+), adding non-capturing groups to highlight
 * the default parsing precedence.
 *
 * Atomic matching on a quantifier is a special case of declaring an atomic
 * group:
 *
 *  (?>pattern)
 *
 * which matches the regular expression pattern and then continues without
 * backtracking even if there were alternatives in the given pattern.
 *
 * The following equivalences hold:
 *
 *  pattern*+       (?>pattern*)
 *  pattern++       (?>pattern+)
 *  pattern?+       (?>pattern?)
 *  pattern{n,m}+   (?>pattern{n,m})
 *
 * Hence the '+' modifier is just a convenience (syntactic sugar). But the
 * (?>) construct is required in full for alternatives: (?>foobar|foo).
 *
 * Finally, we support look-ahead groups, which are a required match (for
 * positive look-ahead, the opposite for negative look-ahead: pattern that
 * must not match) and whose matching is not really part of the result.
 * They can be viewed as zero-width assertions, telling the matching engine
 * to backtrack if they are not successful.
 *
 * A positive look-ahead group looks like:
 *
 * 	(?=pattern)
 *
 * and a negative look-ahead group looks like:
 *
 * 	(?!pattern)
 *
 * For instance, the pattern a(?=,) would match the "a" character but
 * only if it is followed by a comma, and that comma would not become
 * part of the matched string.
 *
 * Conversely, the pattern a(?![,.;]) would match the "a" character but
 * only if it is not followed by a comma, point or semi-colon character.
 * Since this text is not matched, it is of course not part of the matched
 * string!
 *
 * Repetitions are forbidden on assertions, but inside the assertion one
 * may of course include groups, alternatives, etc. all with repetitions
 * if needed.
 *
 * BACK-REFERENCES
 *
 * A pattern may be willing to refer to previously captured matching text,
 * from a previous capturing () group.
 *
 * In order to tell the matching engine that it must match forthcoming
 * text identical to what was captured by group #n (with n a positive
 * integer giving the group number), one can say either:
 *
 * \n		n is a positive integer, so that would be \3, or \12
 * \gn		same as \n, with `n' a positive integer, such as \g3 or \g12
 * \g{n}	n is an integer, so that would be \g{3}, \g{12}, or \g{-1}
 *
 * For instance, a pattern could say ([a-z])\1 to match any lower-cased
 * letter followed by itself.
 *
 * Note that \12 is really going to mean a back-reference to group #12,
 * and not mean \1 followed by 2.  If one wants to match \1 followed by
 * 2, the alternative group specification \g{1}2 needs to be used.
 *
 * The \g{n} notation can also be used with negative numbers, to refer
 * to capturing groups relatively, -1 being the last seen group, -2
 * the group before the last seen, etc...  For instance, ([a-z])\1 and
 * ([a-z])\g{-1} both match the same thing, but if any capturing group
 * was to be added before the ([a-z]) part, the first specification would
 * fail, as \1 would now refer to that new group, but the second would
 * still be correct.
 *
 * POSIX CHARACTER CLASSES
 *
 * The following POSIX character classes, only valid within a [] character
 * class specification, are supported:
 *
 *     alnum    digit    punct
 *     alpha    graph    space
 *     blank    lower    upper
 *     cntrl    print    xdigit
 *
 * We limit ourselves to the ASCII subset of each POSIX character class here.
 * So for instance, one can say: "[<>[:upper:][:space:]=-]", which will match
 * the same text as "[\t-\r \-<=>A-Z]" would.
 *
 * SPECIAL CHARACTER CLASSES
 *
 * The following common character classes are supported:
 *
 * \d	matches a digit [0-9]
 * \w	matches a word [A-Za-z0-9_]
 * \s	matches a space (space, and ASCII chars from 9 to 13)
 * \D	not a \d
 * \W	not a \w
 * \S	not a \s
 *
 * In addition, these special meta characters perform anchoring (zero-width
 * matching assertions):
 *
 * \b	matches at the beginning / end of text, or a word boundary
 * \B	not at a \b
 *
 * A word boundary is defined as a frontier between \w and \W, in any order.
 *
 * The pattern string also supports these character escapes for convenience:
 *
 * \a		bell
 * \t		horizontal tab
 * \v		vertical tab
 * \n		newline
 * \r		carriage return
 * \f		form feed
 * \xHH		hexadecimal escape, 2 digits (H = hexa digit, case-insensitive)
 *
 * LIMITATIONS:
 *
 * There is no support for Unicode matching.  This package is meant to be
 * used for real-time filtering of log messages, which are expected to be
 * in English, so ASCII. There is support for matching 8-bit chars but no
 * Unicode.
 *
 * In particular, '.' is processed as matching one single 8-bit char, and
 * POSIX classes are interpolated on their ASCII sub-range only.
 *
 * NOTA BENE
 *
 * - in a character class, \b does not stand for "word boundary" but for the
 *   regular BS (backspace) ASCII character.
 *
 * - the [^] class matches any single char (unlike '.' which could be
 *   configured at runtime to not match a \n).
 *
 * - the [] class is a valid specification to match the empty string.  It
 *   always  matches but does not consume any character in the input.
 *
 * - the implementation uses recursive backtracking but monitors the stack
 *   space being used and will prefer to abort than risk a stack overflow.
 *   This is an heuristic only, and normally red-zone protection should help
 *   detect an actual stack overflow in threads (the main stack can grow as
 *   needed but we still limit stack usage in the main thread).
 *
 * - because of the requirement that stack space be our only memory, we
 *   have to use complex calling logic at times to avoid recursion or
 *   limit stack usage when recursion is inevitable: reduce the number of
 *   local variables to the strict minimum, use alternate calling path when
 *   possible.
 *
 * IMPLEMENTATION
 *
 * This is a fresh implementation, done from scratch, which may however
 * be borrowing ideas I learned as I was practicing regular expressions
 * in Perl.  The syntax I retained should be Perl compatible.
 *
 * The compilation phase performs a whole set of optimizations by default,
 * merely aimed at optimizing alternatives to avoid costly backtracking
 * and reduce stack space usage at matching time.  The optimizations are not
 * meant to speed-up execution, although they will usually do.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "re.h"

/*
 * Turning this on will generate a *.reexec.log file with a huge amount of
 * output.  It is meant to be practical only in conjunction with the re-test
 * program, when testing a particular execution (e.g.: ./re-test -M32 -S)
 * that is currently failing or misbehaving.
 *
 * The log files are rotated at each new execution.
 */
#if 0
#define PRIVLOG_ENABLED 1
#endif

/**
 * Debugging flags (need to be defined before including "privlog.h" below).
 */
#define RE_D_EXEC		(1U << 0)	/* Trace high-level execution */
#define RE_D_REPEAT		(1U << 1)	/* Trace repetition matching */
#define RE_D_MATCHER	(1U << 2)	/* Individual matching routines */
#define RE_D_MATCHPOS	(1U << 3)	/* Matching positions */
#define RE_D_CONSTANT	(1U << 4)	/* Constant lookups */
#define RE_D_WHERE		(1U << 5)	/* Current position in text */
#define RE_D_TRIE		(1U << 6)	/* Trie matching */

#define RE_D_ALL		((uint) -1)

#define PRIVLOG_PREFIX reexec
#define PRIVLOG_FLAGS	(RE_D_ALL)

#include "privlog.h"

#define REX_ENTRY		PRIVLOG_ENTRY		/* RE_ENTRY defined in <regex.h> */
#define REX_DEBUG		PRIVLOG_DEBUG
#define REX_RETURN		PRIVLOG_RETURN
#define REX_RETURN_VOID	PRIVLOG_RETURN_VOID

#include "alloca.h"
#include "array_util.h"
#include "ascii.h"
#include "bstr.h"
#include "bit_field.h"
#include "buf.h"
#include "compat_setjmp.h"
#include "eslist.h"
#include "halloc.h"
#include "hashing.h"
#include "hset.h"
#include "hstrfn.h"
#include "htable.h"
#include "istream.h"
#include "log.h"
#include "misc.h"
#include "ostream.h"
#include "parse.h"
#include "pattern.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"
#include "tokenizer.h"
#include "trie.h"
#include "trie_fmt.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"	/* Must be the last header included */

#define RE_ELEMVEC_CAP		8	/* Initial capacity */
#define RE_ELEMVEC_GROW		128	/* Past this size, additional increments */

#define RE_CHAR_COUNT_MAX	32	/* Max char repetition we merge */
#define RE_TEXT_LEN_MAX		64	/* Max text length for repetition expanse */
#define RE_ALPHABET			256	/* Alphabet size */

#define RE_CLASS_SIZE		BIT_FIELD_BYTE_SIZE(RE_ALPHABET)
#define RE_LEN_ESCAPE		((uint16) -1)
#define RE_STACK_MAX		THREAD_STACK_MIN

/**
 * Matching element types.
 */
typedef enum {
	RE_TYPE_START = 0,		/* Matches at the beginning of text */
	RE_TYPE_END,			/* Matches at the end of text */
	RE_TYPE_ANY,			/* Any character (.) but not '\n' usually */
	RE_TYPE_ALL,			/* All characters (not '.', includes '\n') */
	RE_TYPE_EMPTY,			/* Matches the empty string (always matches!) */
	RE_TYPE_TEXT,			/* Plain text -- matches as-is */
	RE_TYPE_CHAR,			/* Single letter -- matches as-is */
	RE_TYPE_SUB,			/* Sub-expression (matching NOT captured) */
	RE_TYPE_SUBN,			/* Sub-expression (matching captured) */
	RE_TYPE_GROUP,			/* Sub-expression (matching never captured) */
	RE_TYPE_ATOMIC,			/* Sub-expression (atomic match, captured) */
	RE_TYPE_AHEAD,			/* Positive look-ahead assertion */
	RE_TYPE_NOT_AHEAD,		/* Negative look-ahead assertion */
	RE_TYPE_CLASS,			/* Character class */
	RE_TYPE_INV_CLASS,		/* Inverted character class */
	RE_TYPE_CLASS_MM,		/* Character class, with min-max encoding */
	RE_TYPE_INV_CLASS_MM,	/* Inverted character class, with min-max encoding */
	RE_TYPE_D_CLASS,		/* A digit */
	RE_TYPE_W_CLASS,		/* An alphanumeric character plus _  */
	RE_TYPE_S_CLASS,		/* A white space */
	RE_TYPE_NOT_D_CLASS,	/* Not a digit */
	RE_TYPE_NOT_S_CLASS,	/* Not a white space */
	RE_TYPE_NOT_W_CLASS,	/* Not an alphanumeric character nor a _ */
	RE_TYPE_POSIX_CLASS,	/* A set of POSIX classes */
	RE_TYPE_NOT_POSIX_CLASS,/* Negation of a set of POSIX classes */
	RE_TYPE_IS_BOUNDARY,	/* Is at a word boundary */
	RE_TYPE_NOT_BOUNDARY,	/* Is not at a word boundary */
	RE_TYPE_BACKREF,		/* Back-reference to captured text */
	RE_TYPE_OR,				/* Alternative list of sub-regex */
	RE_TYPE_MATCH,			/* Matching via trie, partial match possible */
	RE_TYPE_MATCHX,			/* Matching via trie, full match only */
	RE_TYPE_ROUTE,			/* Alternative routing via trie, partial possible */
	RE_TYPE_ROUTEX,			/* Alternative routing via trie, full match only */
	RE_TYPE_NEXT,			/* Next item, for linear traversal */
	RE_TYPE_RETURN,			/* End of match, return success */

	RE_TYPE_MAX
} re_elem_type_t;

/**
 * Repetitions of matching text.
 */
typedef enum {
	RE_N_ONCE = 0,			/* once */
	RE_N_AT_MOST_ONE,		/* ? */
	RE_N_AT_LEAST_ONE,		/* + */
	RE_N_ANY,				/* * */
	RE_N_RANGE,				/* explicit {min,max} */
	RE_N_MIN,				/* explicit {min,} */
	RE_N_COUNT,				/* explicit {count} */

	RE_N_MAX
} re_repeat_type_t;

/**
 * Special character classes -- bits set MUST match re_hardwired[].
 */

#define RE_CLASS_D				(1U << 0)		/* digit */
#define RE_CLASS_W				(1U << 1)		/* word */
#define RE_CLASS_S				(1U << 2)		/* space */
#define RE_CLASS_NOT_D			(1U << 3)		/* not a digit */
#define RE_CLASS_NOT_W			(1U << 4)		/* not a word */
#define RE_CLASS_NOT_S			(1U << 5)		/* not a space */
#define RE_CLASS_POSIX_START	6
#define RE_CLASS_PX_ALNUM		(1U << 6)		/* [:alnum:] */
#define RE_CLASS_PX_ALPHA		(1U << 7)		/* [:alpha:] */
#define RE_CLASS_PX_BLANK		(1U << 8)		/* [:blank:] */
#define RE_CLASS_PX_CNTRL		(1U << 9)		/* [:cntrl:] */
#define RE_CLASS_PX_DIGIT		(1U << 10)		/* [:digit:] */
#define RE_CLASS_PX_GRAPH		(1U << 11)		/* [:graph:] */
#define RE_CLASS_PX_LOWER		(1U << 12)		/* [:lower:] */
#define RE_CLASS_PX_PRINT		(1U << 13)		/* [:print:] */
#define RE_CLASS_PX_PUNCT		(1U << 14)		/* [:punct:] */
#define RE_CLASS_PX_SPACE		(1U << 15)		/* [:space:] */
#define RE_CLASS_PX_UPPER		(1U << 16)		/* [:upper:] */
#define RE_CLASS_PX_XDIGIT		(1U << 17)		/* [:xdigit:] */
#define RE_CLASS_POSIX_END		17

static const tokenizer_t re_posix_classes[] = {
	/* Sorted array */
	{ "alnum",	RE_CLASS_PX_ALNUM },
	{ "alpha",	RE_CLASS_PX_ALPHA },
	{ "blank",	RE_CLASS_PX_BLANK },
	{ "cntrl",	RE_CLASS_PX_CNTRL },
	{ "digit",	RE_CLASS_PX_DIGIT },
	{ "graph",	RE_CLASS_PX_GRAPH },
	{ "lower",	RE_CLASS_PX_LOWER },
	{ "print",	RE_CLASS_PX_PRINT },
	{ "punct",	RE_CLASS_PX_PUNCT },
	{ "space",	RE_CLASS_PX_SPACE },
	{ "upper",	RE_CLASS_PX_UPPER },
	{ "xdigit",	RE_CLASS_PX_XDIGIT },
};

struct re_elemvec;
struct re_other;
struct re_class;

/**
 * Definition pertaining to the element where this union is held.
 * Interpretation of the fields in this union depends on the element type.
 */
typedef union re_element_arg {
	const char *text;		/* NUL-terminated text to match */
	const struct re_class *class;	/* RE_ALPHABET bits, one per char */
	pslist_t *alt;			/* List of alternative re_elemvec_t to match */
	struct re_elemvec *sub;	/* Sub regex */
	trie_t *trie;			/* For MATCH and ROUTE elements */
	uint16 minmax;			/* Class with min-max encoded (max << 8 | min) */
	int c;					/* Single character */
	struct re_other *other;	/* Additional information when minlen is -1 */
} re_element_arg_t;

/**
 * Additional information that do not necessarily fit in the small re_element
 * structure.
 *
 * The field `minlen' of the re_element is set to -1 to signal that u.other
 * needs to be followed to get this extra information.  The actual real `minlen'
 * is stored in this additional structure.
 *
 * Since the "escape sequence" consumes the only slot we have for the definition
 * of the element, the actual definition is also stored here.
 *
 * Since only a few re_element will use this "escape sequence", we do not impose
 * that the structure be compact: we can use full-sized fields.
 */
typedef struct re_other {
	size_t minlen;			/* Actual minimum matching length */
	size_t maxlen;			/* Actual maximum matching length */
	re_element_arg_t u;		/* Definition of the element, type-dependent */
	union {
		struct {
			size_t min;		/* Minimum repeat value in a {min, max} repetition */
			size_t max;		/* Maximum repeat value in a {min, max} repetition */
		} repeat;
		struct {
			struct re_elemvec *vec;	/* Element vector where next element is */
			size_t n;				/* Index within vector */
		} next;				/* Next element in the chain */
	} x;
	union {
		uint classes;		/* Special hardwired classes to match */
		uint subn;			/* Group number for SUBN elements */
	} v;
} re_other_t;

/**
 * Representation of a compiled matching element.
 * This structure needs to be as compact as possible: 12 bytes on 32-bit and
 * 16 bytes on 64-bit machines.
 *
 * When minlen (the minimum matching text length for the element) is set to -1,
 * it is an escape sequence signaling that the u.other needs to be read in order
 * to get additional information on the element.
 */
typedef struct re_element {
	uint16 minlen;			/* Minimum matching length, (-1) is escape sequence */
	uint16 maxlen;			/* Maximum matching length */
	uint8 type:7;			/* re_elem_type_t, compressed */
	uint8 icase:1;			/* Element is case-insensitive */
	uint8 repeat:3;			/* re_repeat_type_t, compressed */
	uint8 minimal:1;		/* non-greedy matching */
	uint8 atomic:1;			/* atomic matching, no backtracking once matched */
	uint8 extra:1;			/* Hidden additional node added by re_finalize() */
	uint8 inserted:1;		/* Visible additional node added by re_finalize() */
	uint8 extracted:1;		/* Node was extracted from its group */
	re_element_arg_t u;		/* Definition of the element, type-dependent */
} re_element_t;

enum re_elemvec_magic { RE_ELEMVEC_MAGIC = 0x7692f566 };

/**
 * An re_element_t vector (dynamically allocated array).
 *
 * This is the structure representing a compiled regular expression.
 *
 * A compiled regular expression can be viewed as a tree of re_elemvec_t,
 * but most of the time it is a flat array (i.e. the root element vector
 * bears no children).
 *
 * Children are created for sub-regex (groups) for alternatives (which
 * really creates an OR parent above the vector), and for trie matching
 * nodes (which are created during the OR optimization process).
 *
 * The tree can only be traversed from the root: nodes do not have pointers
 * to their parent.  Children are referenced by re_element_t within the
 * vector via the "u.sub" field (points to the parsed group, and groups may
 * be nested freely), or via the "u.alt" list for the OR node (the only
 * natural tree node that can have more than 1 element vector child).
 *
 * During the optimization process, OR nodes may be complemented or replaced
 * by various trie nodes which also can reference children vectors, adding
 * traversal points in the regex tree structure.
 *
 * Once the regular expression is fully compiled, each element vector sees
 * a trailing NEXT node added, which is used to allow linear traversal of
 * the tree by providing pointers to the next item that follows the parent
 * in the tree.  NEXT nodes also allow looping back into a repetition group
 * and are a synchronization point for delimiting group captures.
 */
typedef struct re_elemvec {
	enum re_elemvec_magic magic;
	re_element_t *elements;		/* Dynamic array of elements */
	size_t ecnt;				/* Number of items in elements[] */
	size_t ecap;				/* Capacity of the elements[] array */
	size_t minlen;				/* Consolidated minimal matching text length */
	size_t maxlen;				/* Consolidated maximal matching text length */
} re_elemvec_t;

enum re_class_magic { RE_CLASS_MAGIC = 0x576ed28c };

/**
 * A character class to match against.
 *
 * The bit_field_t field normally represents the whole alphabet, each character
 * being a bit index which is set if the character belongs to the class,
 * and cleared otherwise.
 *
 * Most of the time, the character class will only be representing a small
 * portion of the alphabet.  We can therefore trim the unused parts, at the
 * beginning and the end, to be able to keep only the interesting portion.
 *
 * The indexing of bits within the class must therefore never be done
 * directly on the bit array but only through the interface, like
 * re_class_belongs(), to avoid accessing outside the kept range.
 */
typedef struct re_class {
	enum re_class_magic magic;	/* Magic number */
	uint8 min, max;				/* Known range */
	uint8 offset;				/* Offset for bit indexing */
	uint8 bytes;				/* Amount of bytes used by the bit array */
	bit_field_t *b;				/* Bit field */
} re_class_t;

enum re_regex_magic { RE_REGEX_MAGIC = 0x28d1a858 };

/**
 * Internal representation of a compiled regular expression.
 *
 * Usually, this will be the root element vector, stored in `compiled'.
 *
 * However, when the pattern is simple enough, it can be optimized to
 * a constant-string lookup, in which case it will be stored in `cp'
 * and will be matched by the fixed-pattern logic, not by the regular
 * expression engine.
 *
 * If furthermore the pattern is anchored (to the start of the text, to
 * the end of the text or both), then we don't need a complex pattern
 * matching algorithm but a simple string comparison at the right place,
 * hence we simply store the string to match in `anchored'.
 *
 * The union discriminant between `compiled' and the other forms is done
 * via the `is_simple' field in the re_regex structure.  And the `anchored'
 * string will be used over `cp' when `at_start' or `at_end' is set.
 */
typedef union re_regex_intern {
	re_elemvec_t *compiled;	/* Compiled regular expression */
	cpattern_t *cp;			/* Simple text too look for */
	const char *anchored;	/* Anchored string to compare */
} re_regex_intern_t;

/**
 * Given an amount of back-references used in the pattern, determine whether
 * we can use the byte LUT or whether we need the size LUT.
 */
#define RE_USE_BYTE_LUT(n)	((n) <= MAX_INT_VAL(uint8))

/**
 * A regular expression.
 *
 * This is the structure given to user code, hence it is protected by
 * a magic number.
 *
 * It merely encapsulates the original pattern and its compiled form.
 */
struct re_regex {
	enum re_regex_magic magic;	/* Magic number */
	const char *pattern;		/* The pattern originally given */
	re_regex_intern_t u;		/* Internal representation */
	const re_element_t *end;	/* Element that must match at the end */
	cpattern_t *must;			/* If non NULL, string that must be present */
	/*
	 * The first-char map is a RE_ALPHABET array storing 1 for each
	 * character that can be a valid match starting point.
	 *
	 * If all the characters of the alphabet can match, or if the
	 * pattern can match the empty string, then this entry is NULL.
	 */
	uint8 *fcmap;				/* If non NULL, map of allowed first chars */
	union {
		/*
		 * LUT (Look-Up Table) mapping a group # to a smaller index within
		 * a re_match_t vector.
		 *
		 * When capturing group #n is later referenced via a \n or \g{n}
		 * back-reference, we shall need to know how much text the group
		 * match and see if we can match that text at the current location.
		 *
		 * In order to do that, we need to remember in an internal re_match_t
		 * slot where the start and the end of the matching text is.
		 *
		 * LUT[n-1] gives us the slot number, in our re_match_t vector.
		 * If LUT[n-1] is 0, then it means that `n' is not used for back-reference
		 * matching.  Otherwise, if LUT[n-1] is number k > 0, and v is the
		 * re_match_t internal vector, then v[k-1] will be used to store the
		 * matching of group #n.
		 *
		 * This LUT table has `group_count' slots and the vector v[] lies on
		 * the stack, allocated by re_execute().  The reduction function
		 * described by the LUT minimizes the amount of room we have to allocate
		 * on the stack, using just enough slots to remember all the references
		 * we need for the matching.
		 *
		 * Depending on the maximum value the indices can take (the amount of
		 * back-references used by the pattern), we can use a byte to store
		 * each slot, or a size_t value.
		 */
		size_t *size_lut;		/* Large values (very unlikely) */
		uint8 *byte_lut;		/* Small values (most likely), less than 255 */
	} backrefs;
	size_t group_count;			/* How many capturing groups are defined? */
	size_t backref_count;		/* Amount of back-refs used in pattern */
	uint is_empty:1;			/* Is pattern empty? */
	uint is_simple:1;			/* Pattern is simple */
	uint at_start:1;			/* Leading string at start */
	uint at_end:1;				/* Leading string finishes text */
	uint icase:1;				/* Compiled for case-insensitive match? */
	uint nosub:1;				/* Compiled with no sub-captures? */
	uint optimized:1;			/* Whether went through optimizer */
};

enum re_parser_magic { RE_PARSER_MAGIC = 0x69fbf55c };

/**
 * Nesting context, stacked into the `nesting' list within the parsing
 * context as we recurse.
 */
struct re_parser_nesting {
	re_elemvec_t *or;			/* Where the OR element is stored */
	re_elemvec_t *current;		/* The current branch in the `OR' */
};

/**
 * The regular expression parsing context.
 */
typedef struct re_parser {
	enum re_parser_magic magic;	/* Magic number */
	uint32 cflags;				/* User compilation flags */
	uint subn;					/* Sub group numbering */
	uint refn;					/* Back reference numbering */
	istream_t *is;				/* The input stream */
	re_elemvec_t *root;			/* Root element */
	re_elemvec_t *or;			/* Alternative "or" parent, NULL if none */
	re_elemvec_t *current;		/* Current element */
	str_t *text;				/* Current text characters */
	htable_t *backrefs;			/* Maps group # -> small ref index */
	hset_t *finished_subn;		/* Set of finished capturing group */
	size_t depth;				/* Recursive depth for sub-expressions */
	re_error_t error;			/* Set on error */
	pslist_t *nesting;			/* Saves OR and current vectors */
	pslist_t *closed_subn;		/* Closed capturing groups, in reverse order */
	uint seen_end:1;			/* Seen an END marker in this alternative */
	uint seen_char:1;			/* Seen matching char in this alternative */
} re_parser_t;

static inline void
re_class_check(const re_class_t * const c)
{
	g_assert(c != NULL);
	g_assert(RE_CLASS_MAGIC == c->magic);
}

static inline void
re_elemvec_check(const re_elemvec_t * const rev)
{
	g_assert(rev != NULL);
	g_assert(RE_ELEMVEC_MAGIC == rev->magic);
}

static inline void
re_regex_check(const re_regex_t * const re)
{
	g_assert(re != NULL);
	g_assert(RE_REGEX_MAGIC == re->magic);
}

static inline void
re_parser_check(const re_parser_t * const rp)
{
	g_assert(rp != NULL);
	g_assert(RE_PARSER_MAGIC == rp->magic);
}

static inline void
re_element_check(const re_element_t * const e)
{
	g_assert(e != NULL);
	g_assert(e->type < RE_TYPE_MAX);
	g_assert(e->repeat < RE_N_MAX);
}

/**
 * A character class matching callback for hardwired classes.
 *
 * We prevent NUL from matching the D, S or W classes.
 */
typedef bool (*re_class_check_t)(int c);

static bool re_match_class_d(int c) { return  is_ascii_digit(c); }
static bool re_match_class_s(int c) { return  is_ascii_space(c); }
static bool re_match_class_w(int c) { return  is_ascii_ident(c); }
static bool re_match_class_D(int c) { return c && !is_ascii_digit(c); }
static bool re_match_class_S(int c) { return c && !is_ascii_space(c); }
static bool re_match_class_W(int c) { return c && !is_ascii_ident(c); }

/**
 * Array of matchers indexed by mask bit in the RE_CLASS_* flags
 * for hardwired classes, followed by RE_CLASS_PX_* POSIX class
 * matchers.
 */
static re_class_check_t re_hardwired[] = {
	re_match_class_d,		/* bit 0:  RE_CLASS_D */
	re_match_class_w,		/* bit 1:  RE_CLASS_W */
	re_match_class_s,		/* bit 2:  RE_CLASS_S */
	re_match_class_D,		/* bit 3:  RE_CLASS_NOT_D */
	re_match_class_W,		/* bit 4:  RE_CLASS_NOT_W */
	re_match_class_S,		/* bit 5:  RE_CLASS_NOT_S */
	/*
	 * Class matching requires that POSIX classes be at the tail.
	 *
	 * The offset at which they start in this array is defined by
	 * RE_CLASS_POSIX_START and their last offset is defined by
	 * RE_CLASS_POSIX_END.
	 *
	 * A POSIX_CLASS matcher is defined by a list of POSIX character
	 * matchers, represented by bits in a bit field within the expanded
	 * re_element_t structure (in re_other_t).
	 */
	is_ascii_alnum,			/* bit 6:  RE_CLASS_PX_ALNUM */
	is_ascii_alpha,			/* bit 7:  RE_CLASS_PX_ALPHA */
	is_ascii_blank,			/* bit 8:  RE_CLASS_PX_BLANK */
	is_ascii_cntrl,			/* bit 9:  RE_CLASS_PX_CNTRL */
	is_ascii_digit,			/* bit 10: RE_CLASS_PX_DIGIT */
	is_ascii_graph,			/* bit 11: RE_CLASS_PX_GRAPH */
	is_ascii_lower,			/* bit 12: RE_CLASS_PX_LOWER */
	is_ascii_print,			/* bit 13: RE_CLASS_PX_PRINT */
	is_ascii_punct,			/* bit 14: RE_CLASS_PX_PUNCT */
	is_ascii_space,			/* bit 15: RE_CLASS_PX_SPACE */
	is_ascii_upper,			/* bit 16: RE_CLASS_PX_UPPER */
	is_ascii_xdigit,		/* bit 17: RE_CLASS_PX_XDIGIT */
};

static bool re_parse(re_parser_t *rp);
static void re_dump_elemvec(const re_elemvec_t *rev, ostream_t *os);
static void re_dump_element(const re_element_t *e, ostream_t *os);

/***
 *** ======================== Utilities ========================
 ***/

/**
 * @return matcher for hardwired character class
 */
static re_class_check_t
re_hard_class_matcher(re_elem_type_t type)
{
	switch (type) {
	case RE_TYPE_D_CLASS:     return re_match_class_d;
	case RE_TYPE_S_CLASS:     return re_match_class_s;
	case RE_TYPE_W_CLASS:     return re_match_class_w;
	case RE_TYPE_NOT_D_CLASS: return re_match_class_D;
	case RE_TYPE_NOT_S_CLASS: return re_match_class_S;
	case RE_TYPE_NOT_W_CLASS: return re_match_class_W;
	default:
		g_assert_not_reached();
	}
}

/**
 * Allocates a new class object for class matching.
 */
static re_class_t *
re_class_allocate(void)
{
	re_class_t *c;

	STATIC_ASSERT(MAX_INT_VAL(uint8) >= RE_ALPHABET - 1);

	WALLOC0(c);
	c->magic = RE_CLASS_MAGIC;
	c->min = c->offset = 0;
	c->max = RE_ALPHABET - 1;
	c->bytes = RE_CLASS_SIZE;
	c->b = walloc0(c->bytes);

	return c;
}

static inline size_t
re_class_bytelen(size_t min, size_t max)
{
	return (1 + (max >> BIT_FIELD_BITSHIFT) - (min >> BIT_FIELD_BITSHIFT)) *
		sizeof(bit_field_t);
}

/**
 * @return amount of bytes used by the bit_field_t object.
 */
static size_t
re_class_bit_field_size(const re_class_t *c)
{
	re_class_check(c);

	if (NULL == c->b)
		return 0;

	return re_class_bytelen(c->min, c->max);
}

/**
 * Duplicate class used for class matching, if not NULL.
 */
static re_class_t *
re_class_clone(const re_class_t *a)
{
	re_class_t *c;
	size_t blen;

	if (NULL == a)
		return NULL;

	re_class_check(a);

	blen = re_class_bit_field_size(a);
	g_assert(a->bytes == blen);

	WALLOC0(c);
	c->magic  = RE_CLASS_MAGIC;
	c->min    = a->min;
	c->max    = a->max;
	c->offset = a->offset;
	c->bytes  = a->bytes;

	if (blen != 0) {
		g_assert(a->b != NULL);
		c->b = walloc(blen);
		memcpy(c->b, a->b, blen);
	}

	return c;
}

/**
 * Free class matching object, if not NULL.
 */
static void
re_class_free(re_class_t *c)
{
	size_t blen;

	if (NULL == c)
		return;

	re_class_check(c);

	blen = re_class_bit_field_size(c);
	c->magic = 0;
	WFREE_NULL(c->b, blen);
	WFREE(c);
}

/**
 * Is character part of the bit field?
 */
static inline bool
re_class_char_in_field(int c,
	int min, int max, int offset, const bit_field_t *b)
{
	return c >= min && c <= max && bit_field_get(b, c - offset);
}

/**
 * Is character part of the class?
 */
static bool
re_class_belongs(const re_class_t *cl, int c)
{
	re_class_check(cl);

	if (NULL == cl->b)
		return FALSE;

	return re_class_char_in_field(c, cl->min, cl->max, cl->offset, cl->b);
}

/**
 * Compact character class.
 */
static void
re_class_compact(re_class_t *c)
{
	size_t first, last;		/* First and last bits set */
	size_t bmin, bmax;		/* Byte min and byte max */
	size_t blen, bf_len;	/* Bitmap length in bytes */
	bit_field_t *bf;		/* New bit field */

	re_class_check(c);

	if (c->min != 0 || c->max != RE_ALPHABET - 1)
		return;		/* Already compacted */

	blen = re_class_bit_field_size(c);

	g_assert(blen == (RE_ALPHABET >> BIT_FIELD_BITSHIFT));
	g_assert(blen == c->bytes);

	first = bit_field_first_set(c->b, 0, RE_ALPHABET - 1);

	if ((size_t) -1 == first) {
		/* Empty class, all zeroes! */
		c->min = c->max = 0;
		c->offset = c->bytes = 0;
		WFREE_NULL(c->b, blen);
		return;
	}

	last = first;

	if (RE_ALPHABET - 1 != first) {
		last = bit_field_last_set(c->b, first + 1, RE_ALPHABET - 1);
		if ((size_t) -1 == last)
			last = first;
	}

	bmin = first >> BIT_FIELD_BITSHIFT;
	bmax = last >> BIT_FIELD_BITSHIFT;

	bf_len = (bmax - bmin + 1) * sizeof(bit_field_t);

	c->min    = first;
	c->max    = last;
	c->offset = bmin * BIT_FIELD_BITSIZE;	/* Nothing before old byte bmin */
	c->bytes  = bf_len;

	bf = walloc0(bf_len);

	/* Move the old part we keep, from byte bmin to bmax */
	memcpy(bf, ptr_add_offset(c->b, bmin), bf_len);

	WFREE_NULL(c->b, blen);
	c->b = bf;

	/* Ensure we worked correctly */
	g_assert(bf_len == re_class_bit_field_size(c));
	g_assert(bf_len == c->bytes);
	g_assert(re_class_belongs(c, c->min));
	g_assert(re_class_belongs(c, c->max));
}

/**
 * @return static string representing all characters in a class.
 */
static const char *
re_class2str(const re_class_t *a)
{
	str_t *s = str_private(G_STRFUNC, RE_ALPHABET / 2);
	int c;

	re_class_check(a);

	str_reset(s);

	for (c = a->min; c <= a->max; c++) {
		if (re_class_belongs(a, c))
			str_putc(s, c);
	}

	return str_2c(s);
}

/**
 * @return static string representing all characters in the First Char map.
 */
static const char *
re_fcmap2str(const uint8 *m)
{
	str_t *s = str_private(G_STRFUNC, RE_ALPHABET / 2);
	int c;
	size_t set = 0, cleared = 0;
	size_t inverted = FALSE;

	str_reset(s);

	/* Count how many positions are set or cleared */

	for (c = 0; c < RE_ALPHABET; c++) {
		if (m[c]) set++;
		else      cleared++;
	}

	if (set > cleared) {
		inverted = TRUE;
		STR_CAT(s, "^");		/* Flags inverted class */
	}

	for (c = 0; c < RE_ALPHABET; c++) {
		bool ok = m[c];
		if (inverted) ok = !ok;
		if (ok) {
			if ('\0' == c)
				STR_CAT(s, "<NUL>");
			else
				str_putc(s, c);
		}
	}

	return str_2c(s);
}

/**
 * @return symbolic type description.
 */
static const char *
re_type2str(re_elem_type_t t)
{
#define CASE(x)	case RE_TYPE_ ## x: return #x;

	STATIC_ASSERT(RE_TYPE_MAX <= (1U << 7));	/* Only 7 bits */

	switch (t) {
	CASE(START)
	CASE(END)
	CASE(ANY)
	CASE(ALL)
	CASE(EMPTY)
	CASE(TEXT)
	CASE(CHAR)
	CASE(SUB)
	CASE(SUBN)
	CASE(GROUP)
	CASE(ATOMIC)
	CASE(AHEAD)
	CASE(NOT_AHEAD)
	CASE(CLASS)
	CASE(INV_CLASS)
	CASE(CLASS_MM)
	CASE(INV_CLASS_MM)
	CASE(D_CLASS)
	CASE(W_CLASS)
	CASE(S_CLASS)
	CASE(NOT_D_CLASS)
	CASE(NOT_S_CLASS)
	CASE(NOT_W_CLASS)
	CASE(POSIX_CLASS)
	CASE(NOT_POSIX_CLASS)
	CASE(IS_BOUNDARY)
	CASE(NOT_BOUNDARY)
	CASE(BACKREF)
	CASE(OR)
	CASE(MATCH)
	CASE(MATCHX)
	CASE(ROUTE)
	CASE(ROUTEX)
	CASE(NEXT)
	CASE(RETURN)
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * @return symbolic repeat description.
 */
static const char *
re_repeat2str(re_repeat_type_t t)
{
#define CASE(x)	case RE_N_ ## x: return #x;

	switch (t) {
	CASE(ONCE)
	CASE(AT_MOST_ONE)
	CASE(AT_LEAST_ONE)
	CASE(ANY)
	CASE(RANGE)
	CASE(MIN)
	CASE(COUNT)
	case RE_N_MAX:
		g_assert_not_reached();
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * Encode min and max as a 16-bit integer.
 */
static uint16
re_minmax_encode(int min, int max)
{
	g_assert(min >= 0 && min < RE_ALPHABET);
	g_assert(max >= 0 && max < RE_ALPHABET);
	g_assert(min <= max);	/* Although we don't depend on that here */

	return ((uint) max << 8) | (uint) min;
}

/**
 * Decode 16-bit integer as min and max.
 */
static void
re_minmax_decode(uint16 encoded, int *min, int *max)
{
	g_assert(min != NULL);
	g_assert(max != NULL);

	*min = encoded & 0xff;
	*max = encoded >> 8;
}

/***
 *** ======================== Predicates ========================
 ***/

/**
 * An element predicate.
 */
typedef bool (*re_element_predicate_fn_t)(const re_element_t *e);

/**
 * Is element a text?
 */
static bool
re_element_is_text(const re_element_t *e)
{
	re_element_check(e);

	return RE_TYPE_TEXT == e->type;
}

/**
 * Is element a single char?
 */
static bool
re_element_is_char(const re_element_t *e)
{
	re_element_check(e);

	return RE_TYPE_CHAR == e->type;
}

/**
 * Is element a (user-defined) character class?
 */
static bool
re_element_is_class(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element a hardwired character class?
 */
static bool
re_element_is_hardwired_class(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_D_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_NOT_W_CLASS:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element a set of POSIX character classes?
 */
static bool
re_element_is_posix_class(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element an inverted POSIX character class set?
 */
static bool
re_element_is_inverted_posix(const re_element_t *e)
{
	re_element_check(e);

	return RE_TYPE_NOT_POSIX_CLASS == e->type;
}

/**
 * Is element a back-reference?
 */
static bool
re_element_is_backref(const re_element_t *e)
{
	re_element_check(e);

	return RE_TYPE_BACKREF == e->type;
}

/**
 * Is element a sub-expression group?
 */
static bool
re_element_is_group(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		return TRUE;
	}

	return FALSE;
}

/*
 * Is element a look-around sub-expression?
 */
static bool
re_element_is_look_around(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		return TRUE;
	}

	return FALSE;
}

#if 0
/**
 * Is element a matching trie?
 */
static bool
re_element_is_matching_trie(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
		return TRUE;
	}

	return FALSE;
}
#endif

/**
 * Is element a routing trie?
 */
static bool
re_element_is_routing_trie(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element a traversable trie?
 *
 * A traversable trie is a trie whose values are element vectors
 * that need to also be traversed when the trie is traversed.
 */
static bool
re_element_is_traversable_trie(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
	/* Special for alternative handling */
	case RE_TYPE_MATCH:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element a matching or routing trie?
 */
static bool
re_element_is_trie(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		return TRUE;
	}

	return FALSE;
}

/**
 * Is element a case-insensitive trie?
 */
static bool
re_element_is_icase_trie(const re_element_t *e)
{
	re_element_check(e);

	return e->icase && re_element_is_trie(e);
}

/**
 * Is element simple enough that it is not requiring deep inspection to
 * determine whether two elements of the same type are equal but only a
 * shallow comparison.
 *
 * We cannot use the "atomic" adjective because that would be confusing with
 * atomic groups, so we use the "shallow" adjective.
 */
static bool
re_element_is_shallow(const re_element_t *e)
{
	re_element_check(e);

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_EMPTY:
	case RE_TYPE_TEXT:
	case RE_TYPE_CHAR:
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_BACKREF:
		return TRUE;
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
	case RE_TYPE_OR:
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Is element expanded?
 */
static bool
re_element_is_expanded(const re_element_t *e)
{
	re_element_check(e);

	return e->minlen == RE_LEN_ESCAPE;
}

/***
 *** ======================== Elements ========================
 ***/

/**
 * Expand element, preserving existing `minlen' and `u' fields by propagating
 * them to the expanded structure.
 *
 * Does nothing if the element is already expanded.
 */
static void
re_expand_element(re_element_t *e)
{
	re_other_t *eo;

	re_element_check(e);

	if (re_element_is_expanded(e))
		return;

	WALLOC0(eo);
	eo->minlen = e->minlen;
	eo->maxlen = RE_LEN_ESCAPE == e->maxlen ? MAX_INT_VAL(size_t) : e->maxlen;
	eo->u = e->u;					/* Struct copy */

	e->u.other = eo;
	e->minlen = RE_LEN_ESCAPE;		/* Mark element as expanded */
}

/*
 * Remove expansion from element.
 *
 * Does nothing if the element is not already expanded.
 */
static void
re_unexpand_element(re_element_t *e)
{
	re_other_t *eo;

	re_element_check(e);

	if (!re_element_is_expanded(e))
		return;

	eo = e->u.other;

	if (eo->minlen >= RE_LEN_ESCAPE) {
		s_carp("%s(): losing minlen information %zu", G_STRFUNC, eo->minlen);
		e->minlen = RE_LEN_ESCAPE - 1;
	} else {
		e->minlen = eo->minlen;
	}

	if (MAX_INT_VAL(size_t) == eo->maxlen) {
		e->maxlen = RE_LEN_ESCAPE;
	} else if (eo->maxlen >= RE_LEN_ESCAPE) {
		s_carp("%s(): losing maxlen information %zu", G_STRFUNC, eo->maxlen);
		e->maxlen = RE_LEN_ESCAPE - 1;
	}

	e->u = eo->u;					/* Struct copy */
	WFREE(eo);
}

/**
 * Is the element requiring specific tracking for matching multiple times?
 */
static bool
re_element_needs_tracking(const re_element_t *e)
{
	/*
	 * If the current element is not a group or an OR or a routing
	 * trie matcher, we do not need to install a tracker as it will
	 * not attempt to descend into another element vector.
	 *
	 * This ability to descend (recurse) into another element vector
	 * is what requires the tracking: if within that sub vector there
	 * is an element that requires multiple attempts to match, it will
	 * verify its choice by recursing to re_exec_match_here() and request
	 * that NEXT elements be followed.  And then we need to loop back
	 * into the tracked element if we haven't matched the minimum yet.
	 *
	 * A non-routing trie matcher for instance (MATCHX, say) can have
	 * multiple choices to make, but it will not descend into another
	 * vector for matching: its repetition count can therefore be controlled
	 * from the caller.  Its choices are deterministic, it has no choice
	 * to try and verify.
	 *
	 * A notable exception is the MATCH trie matcher: because it has
	 * possibly multiple choices to make (which alternative to select),
	 * it needs to execute the remaining of the regular expression to
	 * check for a match, so that it can correct and backtrack if it
	 * guesses wrong.
	 *
	 * Because a re_exec_match_fn_t matcher routine does not supply
	 * the element vector, we handle I(MATCH) elements specially by having
	 * their trie reference a pseudo element vector for each possible match.
	 */

	switch (e->type) {
	case RE_TYPE_SUBN:
	case RE_TYPE_SUB:
	case RE_TYPE_GROUP:
	case RE_TYPE_OR:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
	case RE_TYPE_MATCH:
		return TRUE;
	default:
		return FALSE;
	}
}

/***
 *** ======================== Element Vectors ========================
 ***/

/**
 * Allocates a new element vector.
 *
 * @param cap	desired capacity, 0 = default of RE_ELEMVEC_CAP items
 */
static re_elemvec_t *
re_elemvec_alloc(size_t cap)
{
	re_elemvec_t *rev;

	g_assert(size_is_non_negative(cap));

	WALLOC0(rev);
	rev->magic = RE_ELEMVEC_MAGIC;
	rev->ecap = 0 == cap ? RE_ELEMVEC_CAP : cap;
	HALLOC_ARRAY(rev->elements, rev->ecap);

	return rev;
}

/**
 * Free an element vector (non recursively).
 */
static void
re_elemvec_free(re_elemvec_t *rev)
{
	re_elemvec_check(rev);

	HFREE_NULL(rev->elements);
	rev->magic = 0;
	WFREE(rev);
}

static void re_element_cleanup(re_element_t *e);

/**
 * Free element vector (non-recursively), cleaning up all its elements.
 */
static void
re_elemvec_cleanup_free(re_elemvec_t *rev)
{
	size_t i;
	re_element_t *e;

	re_elemvec_check(rev);

	/*
	 * Free expanded structures referred by elements.
	 */

	for (i = 0, e = &rev->elements[0]; i < rev->ecnt; i++, e++) {
		re_element_cleanup(e);
	}

	re_elemvec_free(rev);
}

/**
 * Extend element vector.
 *
 * @param rev		the element vector to resize
 * @param capacity	the desired capacity
 */
static void
re_elemvec_extend(re_elemvec_t *rev, size_t capacity)
{
	re_elemvec_check(rev);

	if G_UNLIKELY(rev->ecap >= capacity)
		return;

	while (rev->ecap < capacity) {
		if (rev->ecap > RE_ELEMVEC_GROW / 2)
			rev->ecap += RE_ELEMVEC_GROW;
		else
			rev->ecap *= 2;
	}

	HREALLOC_ARRAY(rev->elements, rev->ecap);
}

/**
 * Shrink element vector to its exact count.
 */
static void
re_elemvec_shrink(re_elemvec_t *rev)
{
	re_elemvec_check(rev);
	g_assert(rev->ecnt <= rev->ecap);

	if (rev->ecnt < rev->ecap) {
		HREALLOC_ARRAY(rev->elements, rev->ecnt);
		rev->ecap = rev->ecnt;
	}
}

/**
 * Allocate a new element in the element vector.
 *
 * @param rev	the element vector from which we need a new element
 * @param type	element type
 *
 * @return address of the new element in the vector.
 */
static re_element_t *
re_elemvec_new_element(re_elemvec_t *rev, re_elem_type_t type, bool icase)
{
	re_element_t *e;

	re_elemvec_check(rev);

	if G_UNLIKELY(rev->ecnt == rev->ecap)
		re_elemvec_extend(rev, rev->ecnt + 1);

	g_assert(rev->ecnt < rev->ecap);

	e = &rev->elements[rev->ecnt++];
	ZERO(e);
	e->type  = type;
	e->icase = booleanize(icase);

	g_assert(e->type == type);		/* No truncation */

	return e;
}

/**
 * Insert a new element in the element vector.
 *
 * @param rev	the element vector in which we need a new element
 * @param n		the index at which the element must be inserted
 * @param type	element type
 * @param icase	whether element is matching case-insensitively
 *
 * @return address of the inserted element in the vector.
 */
static re_element_t *
re_elemvec_insert_element(re_elemvec_t *rev, size_t n,
	re_elem_type_t type, bool icase)
{
	re_element_t *e;

	re_elemvec_check(rev);
	g_assert(n <= rev->ecnt);		/* `n' could be a new slot at the end */

	re_elemvec_extend(rev, rev->ecnt + 1);
	ARRAY_MAKEROOM(rev->elements, n, rev->ecnt, rev->ecap);
	rev->ecnt++;

	e = &rev->elements[n];			/* The new element */
	ZERO(e);
	e->type  = type;
	e->icase = booleanize(icase);

	g_assert(e->type == type);		/* No truncation */

	return e;
}

/**
 * Strip element from the element vector (without cleaning it up).
 *
 * @param rev	the element vector in which we need to remove element
 * @param n		the index at which the element must be removed
 */
static void
re_elemvec_strip_element(re_elemvec_t *rev, size_t n)
{
	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);

	ARRAY_REMOVE_DEC(rev->elements, n, rev->ecnt);
}

/**
 * Remove element from the element vector, cleaning it up.
 *
 * @param rev	the element vector in which we need to remove element
 * @param n		the index at which the element must be removed
 */
static void
re_elemvec_remove_element(re_elemvec_t *rev, size_t n)
{
	re_element_t *e;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);

	e = &rev->elements[n];
	re_element_cleanup(e);

	re_elemvec_strip_element(rev, n);
}

/**
 * Fetch last element we allocated.
 *
 * @return address of element, NULL if none allocated.
 */
static re_element_t *
re_elemvec_last_element(const re_elemvec_t *rev)
{
	re_elemvec_check(rev);

	if G_UNLIKELY(0 == rev->ecnt)
		return NULL;

	return &rev->elements[rev->ecnt - 1];
}

/**
 * Return empty element to the pool of elements.
 * This must be the last element.
 */
static void
re_elemvec_return_element(re_elemvec_t *rev, re_element_t *e)
{
	size_t off;

	re_elemvec_check(rev);
	g_assert(e != NULL);
	g_assert(rev->ecnt != 0);	/* There must be an element allocated */

	off = e - rev->elements;
	g_assert_log(off == rev->ecnt - 1,
		"%s(): can only return last element, off=%zu, rev->ecnt=%zu",
		G_STRFUNC, off, rev->ecnt);

	rev->ecnt--;
}

/***
 *** ==================== Element Getters / Setters ====================
 ***/

/**
 * Get minlen field.
 */
static size_t
re_element_get_minlen(const re_element_t *e)
{
	re_element_check(e);

	if (re_element_is_expanded(e))
		return e->u.other->minlen;
	return e->minlen;
}

/**
 * Get maxlen field.
 */
static size_t
re_element_get_maxlen(const re_element_t *e)
{
	re_element_check(e);

	if (re_element_is_expanded(e))
		return e->u.other->maxlen;

	if (RE_LEN_ESCAPE == e->maxlen)
		return MAX_INT_VAL(size_t);

	return e->maxlen;
}

/**
 * Get minmax field (needs to be decoded to get at min/max values).
 */
static uint16
re_element_get_minmax(const re_element_t *e)
{
	re_element_check(e);

	if (re_element_is_expanded(e))
		return e->u.other->u.minmax;
	return e->u.minmax;
}

/**
 * Get repeat_min field.
 */
static size_t
re_element_get_repeat_min(const re_element_t *e)
{
	re_element_check(e);

	switch ((re_repeat_type_t) e->repeat) {
	case RE_N_ONCE:         return 1;
	case RE_N_AT_MOST_ONE:  return 0;
	case RE_N_AT_LEAST_ONE: return 1;
	case RE_N_ANY:          return 0;
	case RE_N_RANGE:
	case RE_N_MIN:
	case RE_N_COUNT:
	case RE_N_MAX:          break;
	}

	if (re_element_is_expanded(e))
		return e->u.other->x.repeat.min;

	s_error("%s(): non-expanded %s has repeat=%s",
		G_STRFUNC, re_type2str(e->type), re_repeat2str(e->repeat));
}

/**
 * Get repeat_max field.
 */
static size_t
re_element_get_repeat_max(const re_element_t *e)
{
	re_element_check(e);

	switch ((re_repeat_type_t) e->repeat) {
	case RE_N_ONCE:         return 1;
	case RE_N_AT_MOST_ONE:  return 1;
	case RE_N_AT_LEAST_ONE: return MAX_INT_VAL(size_t);
	case RE_N_ANY:          return MAX_INT_VAL(size_t);
	case RE_N_RANGE:
	case RE_N_MIN:
	case RE_N_COUNT:
	case RE_N_MAX:          break;
	}

	if (re_element_is_expanded(e))
		return e->u.other->x.repeat.max;

	s_error("%s(): non-expanded %s has repeat=%s",
		G_STRFUNC, re_type2str(e->type), re_repeat2str(e->repeat));
}

static const char *re_elem_info(const re_element_t *e);

#define ELEMENT_IS_TYPE(t)					\
	g_assert_log(RE_TYPE_ ## t == e->type,	\
		"%s(): %s", G_STRFUNC, 				\
		re_elem_info(e))

#define ELEMENT_PREDICATE(p)		\
	g_assert_log(p(e),				\
		"%s(): %s", G_STRFUNC, 		\
		re_elem_info(e))

/**
 * Get text field.
 */
static const char *
re_element_get_text(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_text);

	if (re_element_is_expanded(e))
		return e->u.other->u.text;
	return e->u.text;
}

/**
 * Get char field.
 */
static int
re_element_get_char(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_char);

	if (re_element_is_expanded(e))
		return e->u.other->u.c;
	return e->u.c;
}

/**
 * Get class field.
 */
static const re_class_t *
re_element_get_class(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_class);

	if (re_element_is_expanded(e))
		return e->u.other->u.class;
	return e->u.class;
}

/**
 * Get hardwired matching classes field.
 */
static uint
re_element_get_classes(const re_element_t *e)
{
	if (!re_element_is_expanded(e))
		return 0;

	return e->u.other->v.classes;
}

/**
 * Get the sub field.
 */
static re_elemvec_t *
re_element_get_sub(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_group);

	if (re_element_is_expanded(e))
		return e->u.other->u.sub;
	return e->u.sub;
}

/**
 * Get the sub number field.
 */
static uint
re_element_get_sub_number(const re_element_t *e)
{
	ELEMENT_IS_TYPE(SUBN);
	g_assert(re_element_is_expanded(e));

	return e->u.other->v.subn;
}

/**
 * Get the back-reference number field.
 */
static uint
re_element_get_ref_number(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_backref);
	g_assert(re_element_is_expanded(e));

	return e->u.other->v.subn;
}

/**
 * Get the alt field.
 */
static pslist_t *
re_element_get_alt(const re_element_t *e)
{
	ELEMENT_IS_TYPE(OR);

	if (re_element_is_expanded(e))
		return e->u.other->u.alt;
	return e->u.alt;
}

/**
 * Get the trie field.
 */
static trie_t *
re_element_get_trie(const re_element_t *e)
{
	ELEMENT_PREDICATE(re_element_is_trie);

	if (re_element_is_expanded(e))
		return e->u.other->u.trie;
	return e->u.trie;
}

/**
 * Set class field, compacting it on-the-fly.
 */
static void
re_element_set_class(re_element_t *e, re_class_t *c)
{
	ELEMENT_PREDICATE(re_element_is_class);

	if (re_element_is_expanded(e))
		e->u.other->u.class = c;
	else
		e->u.class = c;

	if (c != NULL) {
		re_class_check(c);
		re_class_compact(c);
	}
}

/**
 * Set classes field.
 */
static void
re_element_set_classes(re_element_t *e, uint v)
{
	ELEMENT_PREDICATE(re_element_is_expanded);

	e->u.other->v.classes = v;
}

/**
 * Set trie field.
 */
static void
re_element_set_trie(re_element_t *e, trie_t *t)
{
	ELEMENT_PREDICATE(re_element_is_trie);

	trie_collapse(t);			/* Memory efficient representation */

	if (re_element_is_expanded(e))
		e->u.other->u.trie = t;
	else
		e->u.trie = t;
}

/**
 * Set char field.
 */
static void
re_element_set_char(re_element_t *e, int c)
{
	ELEMENT_PREDICATE(re_element_is_char);

	if (re_element_is_expanded(e))
		e->u.other->u.c = c;
	else
		e->u.c = c;
}

/**
 * Set text field.
 */
static void
re_element_set_text(re_element_t *e, const char *s)
{
	char *old;

	ELEMENT_PREDICATE(re_element_is_text);
	g_assert(s != NULL);

	old = deconstify_char(re_element_get_text(e));
	HFREE_NULL(old);

	if (re_element_is_expanded(e))
		e->u.other->u.text = s;
	else
		e->u.text = s;
}

/**
 * Set the sub field.
 */
static void
re_element_set_sub(re_element_t *e, re_elemvec_t *rev)
{
	ELEMENT_PREDICATE(re_element_is_group);
	re_elemvec_check(rev);

	if (re_element_is_expanded(e))
		e->u.other->u.sub = rev;
	else
		e->u.sub = rev;
}

/**
 * Set the alt field.
 */
static void
re_element_set_alt(re_element_t *e, pslist_t *alt)
{
	ELEMENT_IS_TYPE(OR);

	if (re_element_is_expanded(e))
		e->u.other->u.alt = alt;
	else
		e->u.alt = alt;
}

/**
 * Set the minlen field.
 */
static void
re_element_set_minlen(re_element_t *e, size_t minlen)
{
	if (re_element_is_expanded(e)) {
		e->u.other->minlen = minlen;
	} else if (minlen < RE_LEN_ESCAPE) {
		e->minlen = minlen;
	} else {
		re_expand_element(e);
		e->u.other->minlen = minlen;
	}
}

/**
 * Set the maxlen field.
 */
static void
re_element_set_maxlen(re_element_t *e, size_t maxlen)
{
	if (re_element_is_expanded(e)) {
		e->u.other->maxlen = maxlen;
	} else if (maxlen >= RE_LEN_ESCAPE) {
		/*
		 * If maxlen is "infinite", then store it as RE_LEN_ESCAPE.
		 * This is the most common case, so we avoid expanding the
		 * element for this common case.
		 */
		if (MAX_INT_VAL(size_t) == maxlen)
			e->maxlen = RE_LEN_ESCAPE;
		else {
			re_expand_element(e);
			e->u.other->maxlen = maxlen;
		}
	} else {
		e->maxlen = maxlen;
	}
}

/**
 * Set repeat information for node.
 */
static void
re_element_set_repeat(re_element_t *e, size_t min, size_t max)
{
	re_element_check(e);

	/*
	 * To store the customized range, we need to expand the element
	 * unless the specified range falls back to a predefined range.
	 */

	if (0 == min && MAX_INT_VAL(size_t) == max) {
		e->repeat = RE_N_ANY;
		return;
	} else if (0 == min && 1 == max) {
		e->repeat = RE_N_AT_MOST_ONE;
		return;
	} else if (1 == min && MAX_INT_VAL(size_t) == max) {
		e->repeat = RE_N_AT_LEAST_ONE;
		return;
	} else if (1 == min && 1 == max) {
		e->repeat = RE_N_ONCE;
		return;
	} else if (min == max) {
		e->repeat = RE_N_COUNT;
	} else if (MAX_INT_VAL(size_t) == max) {
		e->repeat = RE_N_MIN;
	} else {
		e->repeat = RE_N_RANGE;
	}

	re_expand_element(e);
	e->u.other->x.repeat.min = min;
	e->u.other->x.repeat.max = max;
}

/***
 *** ======================== Element Utilities ========================
 ***/

/**
 * Get new halloc()'ed string from given CHAR/TEXT element.
 */
static char *
re_element_string_dup(const re_element_t *e)
{
	char buf[2];

	g_assert_log(re_element_is_text(e) || re_element_is_char(e),
		"%s(): %s", G_STRFUNC, re_elem_info(e));

	if (re_element_is_char(e)) {
		buf[0] = re_element_get_char(e);
		buf[1] = '\0';
		return h_strdup(buf);
	} else {
		return h_strdup(re_element_get_text(e));
	}
}

/**
 * Copy dynamically allocated data structures.
 *
 * This should be used when the element is copied over another one,
 * to make sure we can alter the copy without perturbing the old pointers.
 */
static void
re_element_copy(re_element_t *to, const re_element_t *from)
{
	re_element_check(from);

	*to = *from;	/* Struct copy */

	if (re_element_is_expanded(from)) {
		re_other_t *eo;

		WALLOC(eo);
		*eo = *from->u.other;	/* Struct copy */
		to->u.other = eo;

		g_assert(re_element_is_expanded(to));
	}

	switch (from->type) {
	case RE_TYPE_TEXT:
		if (re_element_is_expanded(to))
			to->u.other->u.text = NULL;
		else
			to->u.text = NULL;
		re_element_set_text(to, h_strdup(re_element_get_text(from)));
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
		if (re_element_is_expanded(to))
			to->u.other->u.class = NULL;
		else
			to->u.class = NULL;
		re_element_set_class(to, re_class_clone(re_element_get_class(from)));
		break;
	case RE_TYPE_OR:
		g_assert_not_reached();	/* Cannot mutate an OR element */
		break;
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		g_assert_not_reached();	/* Cannot mutate a trie element */
		break;
	}
}

/**
 * Free dynamically allocated data structures for the element.
 *
 * Note: this only frees local information, not element vectors that
 * could be referenced by the element.
 */
static void
re_element_cleanup(re_element_t *e)
{
	switch (e->type) {
	case RE_TYPE_TEXT:
		hfree(deconstify_char(re_element_get_text(e)));
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
		re_class_free(deconstify_pointer(re_element_get_class(e)));
		break;
	case RE_TYPE_OR:
		pslist_free(re_element_get_alt(e));
		break;
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		trie_free(re_element_get_trie(e));
		break;
	}
	if (re_element_is_expanded(e))
		WFREE(e->u.other);

	ZERO(e);
}

/***
 *** ======================= Matching Maps =======================
 ***/

/**
 * Fill character map for ANY.
 *
 * @param map	a map of RE_ALPHABET elements
 */
static void
re_elem_map_any(uint8 *map)
{
	memset(map, 1, RE_ALPHABET);
	map['\n'] = 0;
}

/**
 * Fill map with the first character held in the text.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		text element
 */
static void
re_elem_map_first_text(uint8 *map, const re_element_t *e)
{
	const char *text = re_element_get_text(e);
	int c = *text;

	if (e->icase) {
		map[ascii_tolower(c)] = 1;
		map[ascii_toupper(c)] = 1;
	} else {
		map[c] = 1;
	}
}

/**
 * Fill map with all the characters matched by char.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		char element
 */
static void
re_elem_map_char(uint8 *map, const re_element_t *e)
{
	int c = re_element_get_char(e);

	if (e->icase) {
		map[ascii_tolower(c)] = 1;
		map[ascii_toupper(c)] = 1;
	} else {
		map[c] = 1;
	}
}

/**
 * Fill map for min-max class.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		class element
 */
static void
re_elem_map_minmax(uint8 *map, const re_element_t *e)
{
	bool inverted = RE_TYPE_INV_CLASS_MM == e->type;
	int c;
	int min, max;

	re_minmax_decode(re_element_get_minmax(e), &min, &max);

	for (c = 0; c < RE_ALPHABET; c++) {
		bool ok = c >= min && c <= max;
		if (inverted) ok = !ok;
		if (ok) {
			if (e->icase) {
				map[ascii_tolower(c)] = 1;
				map[ascii_toupper(c)] = 1;
			} else {
				map[c] = 1;
			}
		}
	}
}

/**
 * Fill map for character class.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		class element
 */
static void
re_elem_map_class(uint8 *map, const re_element_t *e)
{
	bool inverted = RE_TYPE_INV_CLASS == e->type;
	const re_class_t *a = re_element_get_class(e);
	uint classes = re_element_get_classes(e);
	int c;

	g_assert(implies(NULL == a, re_element_is_expanded(e)));

	for (c = 0; c < RE_ALPHABET; c++) {
		bool ok = FALSE;

		if (classes != 0) {
			uint j;
			for (j = 0; j < RE_CLASS_POSIX_START && !ok; j++) {
				if (classes & (1U << j)) {
					ok = (*re_hardwired[j])(c);
				}
			}
		}

		if (a != NULL && !ok)
			ok = re_class_belongs(a, c);

		if (inverted) ok = !ok;
		if (ok) {
			if (e->icase) {
				map[ascii_tolower(c)] = 1;
				map[ascii_toupper(c)] = 1;
			} else {
				map[c] = 1;
			}
		}
	}
}

/**
 * Fill map for hardwired character class.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		hardwired class element
 */
static void
re_elem_map_hwclass(uint8 *map, const re_element_t *e)
{
	int c;
	re_class_check_t matcher = re_hard_class_matcher(e->type);

	for (c = 0; c < RE_ALPHABET; c++) {
		if ((*matcher)(c))
			map[c] = 1;
	}
}

/**
 * Fill map for POSIX class element.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		POSIX class element
 */
static void
re_elem_map_posix(uint8 *map, const re_element_t *e)
{
	bool inverted = RE_TYPE_NOT_POSIX_CLASS == e->type;
	int c;
	uint classes = re_element_get_classes(e);

	for (c = 0; c < RE_ALPHABET; c++) {
		size_t n;
		bool ok = FALSE;

		for (
			n = RE_CLASS_POSIX_START;
			n <= RE_CLASS_POSIX_END;
			n++)
		{
			if (0 == ((1U << n) & classes))
				continue;
			g_assert(n < N_ITEMS(re_hardwired));
			if ((*re_hardwired[n])(c)) {
				ok = TRUE;
				break;
			}
		}
		if (inverted) ok = !ok;
		if (ok)       map[c] = 1;
	}
}

/**
 * Fill map with the first character held in the trie.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		trie element
 */
static void
re_elem_map_first_trie(uint8 *map, const re_element_t *e)
{
	const trie_t *t = re_element_get_trie(e);
	const trie_node_t * const *nodes;
	size_t n, count;

	/* Get all root children, which is the first char matched */

	nodes = trie_node_children(trie_root(t), &count);
	for (n = 0; n < count; n++) {
		const trie_node_t *tn = nodes[n];
		int c = trie_node_arc(tn);

		if (e->icase) {
			map[ascii_tolower(c)] = 1;
			map[ascii_toupper(c)] = 1;
		} else {
			map[c] = 1;
		}
	}
}

/***
 *** ======================== Formatting ========================
 ***/

/**
 * Format element repetition.
 */
static const char *
re_elem_repeat_info(const re_element_t *e)
{
	str_t *s = str_private(G_STRFUNC, 80);
	size_t min, max;

	re_element_check(e);

	str_reset(s);

	switch ((re_repeat_type_t) e->repeat) {
	case RE_N_ONCE:                           break;
	case RE_N_AT_MOST_ONE:  str_putc(s, '?'); break;
	case RE_N_AT_LEAST_ONE: str_putc(s, '+'); break;
	case RE_N_ANY:          str_putc(s, '*'); break;
	case RE_N_RANGE:
		min = re_element_get_repeat_min(e);
		max = re_element_get_repeat_max(e);
		str_catf(s, "{%zu,%zu}", min, max);
		break;
	case RE_N_MIN:
		min = re_element_get_repeat_min(e);
		str_catf(s, "{%zu,}", min);
		break;
	case RE_N_COUNT:
		min = re_element_get_repeat_min(e);
		max = re_element_get_repeat_max(e);
		g_assert(min == max);
		str_catf(s, "{%zu}", min);
		break;
	case RE_N_MAX:
		g_assert_not_reached();
	}

	if (e->minimal) str_putc(s, '?');
	if (e->atomic)  str_putc(s, '+');

	return str_2c(s);
}

/**
 * Format element type summary.
 */
static const char *
re_elem_info_internal(const re_element_t *e, bool show_regex)
{
	str_t *s = str_private(G_STRFUNC, 80);
	ostream_t *os;

	re_element_check(e);

	str_reset(s);

	if (e->icase)
		STR_CAT(s, "i-");

	str_catf(s, "%s", re_type2str(e->type));


	if (e->repeat != RE_N_ONCE)
		str_catf(s, "%s", re_elem_repeat_info(e));

	/* Show regex fragment between <>  if requested */

	if (show_regex) {
		STR_CAT(s, " <");
		os = ostream_open_str(s);
		re_dump_element(e, os);
		ostream_close(os);
		str_putc(s, '>');
	}

	return str_2c(s);
}

/**
 * Format element type summary.
 */
static const char *
re_elem_info(const re_element_t *e)
{
	return re_elem_info_internal(e, TRUE);
}

/**
 * Format element type summary.
 */
static const char *
re_elem_info_short(const re_element_t *e)
{
	return re_elem_info_internal(e, FALSE);
}

/**
 * Format element type summary.
 *
 * @note
 * Routine is flagged inline because it is only used when debugging
 * hence we want to avoid warnings about it being unused.
 */
static inline const char *
re_elemvec_info(const re_elemvec_t *ev)
{
	str_t *s = str_private(G_STRFUNC, 80);
	ostream_t *os;

	re_elemvec_check(ev);

	/* Show regex fragment between <> */

	str_reset(s);

	str_putc(s, '<');
	os = ostream_open_str(s);
	re_dump_elemvec(ev, os);
	ostream_close(os);
	str_putc(s, '>');

	return str_2c(s);
}

/**
 * Format max repetition, outlining "infinite" explicitly.
 */
static const char *
re_max2str(size_t max)
{
	buf_t *b = buf_private(G_STRFUNC, SIZE_T_DEC_BUFLEN);

	if (MAX_INT_VAL(size_t) == max)
		return "inf";

	size_t_to_string_buf(max, buf_data(b),  buf_size(b));
	return buf_data(b);
}

/***
 *** ======================== Traversal ========================
 ***/

/**
 * Trie iterator to collect values into a list.
 */
static void
re_traverse_trie_value(const void *key, void *value, void *data)
{
	pslist_t **list = data;

	(void) key;

	if (value != NULL)
		*list = pslist_prepend(*list, value);
}

/**
 * Traversal parameters.
 *
 * The "visited" set is optional and only present when performing a "once"
 * traversal of the element vectors.  Since they can be shared, we do not
 * want to visit them more than once when freeing the data structure (since
 * they do not bear any reference count).
 */
struct re_traverse_ctx {
	hset_t *seen;		/* visited element vectors, for "once" traversals */
	bool pre_e;			/* if set, "action" done before acting on children */
	match_fn_t enter;	/* (optional) element selection callback upon entry */
	data_fn_t action;	/* (optional) action on the element */
	bool pre_v;			/* if set, "vaction" done before acting on children */
	match_fn_t venter;	/* (optional) vector selection callback upon entry */
	data_fn_t vaction;	/* (optional) action on the element vector */
	void *data;			/* user-defined argument passed to callbacks */
};

static size_t re_traverse_vector(re_elemvec_t *, struct re_traverse_ctx *);

/**
 * Traversal of an element.
 *
 * @param e			the element at which traversal starts
 * @param ctx		traversal contextual parameters
 *
 * @return amount of elements visited
 */
static size_t
re_traverse_element(re_element_t *e, struct re_traverse_ctx *ctx)
{
	size_t visited = 1;		/* at least this node */

	if (ctx->enter != NULL && !(*ctx->enter)(e, ctx->data))
		return 0;

	if (ctx->pre_e && ctx->action != NULL)
		(*ctx->action)(e, ctx->data);

	/*
	 * Do we have element vector children to process?
	 */

	if (e->type == RE_TYPE_OR) {
		pslist_t *sl;
		PSLIST_FOREACH(re_element_get_alt(e), sl) {
			re_elemvec_t *rev = sl->data;
			visited += re_traverse_vector(rev, ctx);
		}
	}
	else if (re_element_is_group(e)) {
		re_elemvec_t *rev = re_element_get_sub(e);
		visited += re_traverse_vector(rev, ctx);
	}
	else if (re_element_is_traversable_trie(e)) {
		pslist_t *values = NULL, *sl;
		trie_t *t = re_element_get_trie(e);

		trie_foreach_value(t, re_traverse_trie_value, &values);
		values = pslist_reverse(values);
		PSLIST_FOREACH(values, sl) {
			re_elemvec_t *rev = sl->data;
			visited += re_traverse_vector(rev, ctx);
		}
		pslist_free(values);
	}

	if (!ctx->pre_e && ctx->action != NULL)
		(*ctx->action)(e, ctx->data);

	return visited;
}

/**
 * Traversal of an element vector.
 *
 * @param ev		the element vector at which traversal starts
 * @param ctx		traversal contextual parameters
 *
 * @return amount of elements visited
 */
static size_t
re_traverse_vector(re_elemvec_t *ev, struct re_traverse_ctx *ctx)
{
	size_t visited = 0;
	size_t i;

	/*
	 * Enforce "once" traversal for element vector if requested.
	 *
	 * The element vector may be invalid at this stage, for
	 * instance during recursive freeing.
	 */

	if (ctx->seen != NULL) {
		if (hset_contains(ctx->seen, ev))
			return 0;
		hset_insert(ctx->seen, ev);
	}

	re_elemvec_check(ev);

	if (ctx->venter != NULL && !(*ctx->venter)(ev, ctx->data))
		return 0;

	if (ctx->pre_v && ctx->vaction != NULL)
		(*ctx->vaction)(ev, ctx->data);

	/*
	 * It is critical to not cache root->ecnt but always evaluate it since
	 * we want to allow callbacks to modify the tree.
	 */

	re_elemvec_check(ev);

	for (i = 0; i < ev->ecnt; i++) {
		re_element_t *e = &ev->elements[i];

		visited += re_traverse_element(e, ctx);
	}

	re_elemvec_check(ev);

	if (!ctx->pre_v && ctx->vaction != NULL)
		(*ctx->vaction)(ev, ctx->data);

	return visited;
}

/**
 * Fill traversal context.
 */
static void
re_traverse_fill_ctx(struct re_traverse_ctx *ctx,
	bool pre_e, match_fn_t enter,   data_fn_t action,
	bool pre_v, match_fn_t venter,  data_fn_t vaction,
	void *data)
{
#define SET(x)	ctx->x = x
	SET(pre_e);
	SET(enter);
	SET(action);
	SET(pre_v);
	SET(venter);
	SET(vaction);
	SET(data);
#undef SET
}

/**
 * Traverse the "forward" tree formed by the element vectors.
 *
 * The "enter" function is called when we enter an element and if it
 * returns FALSE, the element is skipped (along with its children).
 * When missing, it is as if it were always returning TRUE.
 *
 * The "action" callback is invoked on each element before or after
 * processing the children of that element, depending on the "pre" flag.
 *
 * The "venter" callback is optional and applies to the element vector.
 * It proceeds as "enter" for an element.
 *
 * The "vaction" callback is optional and applies to the element vector.
 * It is always executed once all the elements in the vector have been
 * processed, regardless of "pre".
 *
 * @param root		the item at which traversal starts
 * @param pre_e		if TRUE, "action" is done before acting on children
 * @param enter		(optional) element selection callback upon entry
 * @param action	(optional) action on the element
 * @param pre_v		if TRUE, "vaction" is done before acting on children
 * @param venter	(optional) element vector selection callback upon entry
 * @param vaction	(optional) action on the element vector, in "post" mode
 * @param data		user-defined argument passed to callbacks
 *
 * @return amount of elements visited
 */
static inline size_t	/* inline because UNUSED, to avoid compiler warnings */
re_traverse(
	re_elemvec_t *root,
	bool pre_e, match_fn_t enter,   data_fn_t action,
	bool pre_v, match_fn_t venter,  data_fn_t vaction,
	void *data)
{
	struct re_traverse_ctx ctx;

	ZERO(&ctx);
	re_traverse_fill_ctx(&ctx,
		pre_e, enter,  action,
		pre_v, venter, vaction,
		data);

	return re_traverse_vector(root, &ctx);
}

/**
 * Traverse the "forward" tree formed by the element vectors.
 *
 * Each element vector is traversed once only.  This matters solely
 * when we can have tries in the regular expression tree, since they
 * can share some element vectors.
 *
 * The "enter" function is called when we enter an element and if it
 * returns FALSE, the element is skipped (along with its children).
 * When missing, it is as if it were always returning TRUE.
 *
 * The "action" callback is invoked on each element before or after
 * processing the children of that element, depending on the "pre" flag.
 *
 * The "venter" callback is optional and applies to the element vector.
 * It proceeds as "enter" for an element.
 *
 * The "vaction" callback is optional and applies to the element vector.
 * It is always executed once all the elements in the vector have been
 * processed, regardless of "pre".
 *
 * @param root		the item at which traversal starts
 * @param pre_e		if TRUE, "action" is done before acting on children
 * @param enter		(optional) element selection callback upon entry
 * @param action	(optional) action on the element
 * @param pre_v		if TRUE, "vaction" is done before acting on children
 * @param venter	(optional) element vector selection callback upon entry
 * @param vaction	(optional) action on the element vector, in "post" mode
 * @param data		user-defined argument passed to callbacks
 *
 * @return amount of elements visited
 */
static size_t
re_traverse_once(
	re_elemvec_t *root,
	bool pre_e, match_fn_t enter,   data_fn_t action,
	bool pre_v, match_fn_t venter,  data_fn_t vaction,
	void *data)
{
	struct re_traverse_ctx ctx;
	size_t visited;

	ZERO(&ctx);
	ctx.seen = hset_create(HASH_KEY_SELF, 0);
	re_traverse_fill_ctx(&ctx,
		pre_e, enter,  action,
		pre_v, venter, vaction,
		data);

	visited = re_traverse_vector(root, &ctx);
	hset_free_null(&ctx.seen);

	return visited;
}

/**
 * A traversal of each element vector, once only.
 *
 * Each element vector is traversed once (for shared vectors), in post-order.
 *
 * @param root		the root element vector
 * @param vaction	the callback to invoke on each element vector
 * @param data		user-supplied argument
 */
static size_t
re_foreach_elemvec(re_elemvec_t *root, data_fn_t vaction, void *data)
{
	re_elemvec_check(root);

	return re_traverse_once(root,
		FALSE,				/* pre_e */
		NULL,				/* enter */
		NULL,				/* action */
		FALSE,				/* pre_v */
		NULL,				/* venter */
		vaction,			/* vaction */
		data);
}

/**
 * Traversal callback to free element vector.
 */
static void
re_elemvec_free_cb(void *data, void *udata)
{
	re_elemvec_t *rev = data;

	(void) udata;
	re_elemvec_cleanup_free(rev);
}

/**
 * Recursively free the tree starting at root.
 */
static void
re_elemvec_recursive_free(re_elemvec_t *root)
{
	re_foreach_elemvec(root, re_elemvec_free_cb, NULL);
}

/***
 *** ======================== Equality ========================
 ***/

/**
 * Are two classes equal?
 *
 * @note
 * This routine is also used as a hash table comparison, hence the signature.
 */
static bool
re_class_eq(const void *a, const void *b)
{
	const re_class_t *c1 = a, *c2 = b;
	size_t c1len, c2len;

	if G_UNLIKELY(NULL == a || NULL == b)
		return a == b;

	re_class_check(c1);
	re_class_check(c2);

	if (c1->offset != c2->offset)
		return FALSE;

	c1len = re_class_bit_field_size(c1);
	c2len = re_class_bit_field_size(c2);

	if (c1len != c2len)
		return FALSE;

	return 0 == memcmp(c1->b, c2->b, c1len);
}

static bool re_deep_equal(const re_elemvec_t *ev1, const re_elemvec_t *ev2);

/**
 * Are two OR alternatives deeply equal?
 */
static bool
re_or_deep_equal(const re_element_t *e1, const re_element_t *e2)
{
	pslist_t *alt1, *alt2;

	alt1 = re_element_get_alt(e1);
	alt2 = re_element_get_alt(e2);

	while (alt1 != NULL && alt2 != NULL) {
		const re_elemvec_t *ev1 = alt1->data, *ev2 = alt2->data;
		if (!re_deep_equal(ev1, ev2))
			return FALSE;
		alt1 = pslist_next(alt1);
		alt2 = pslist_next(alt2);
	}

	return NULL == alt1 && NULL == alt2;
}

struct re_trie_deep_equal_ctx {
	const trie_t *t2;				/**< The second trie */
	bool mismatch;					/**< Set to TRUE as soon we know */
};

/**
 * Trie comparison callback for trie_foreach_value(), with key and value.
 */
static void
re_trie_keyval_deep_equal(const void *key, void *value, void *udata)
{
	struct re_trie_deep_equal_ctx *ctx = udata;
	const re_elemvec_t *ev1 = value, *ev2;

	if (ctx->mismatch)
		return;		/* We already know it's not a match */

	ev2 = trie_lookup(ctx->t2, key);

	if (NULL == ev2)
		ctx->mismatch = TRUE;
	else
		ctx->mismatch = !re_deep_equal(ev1, ev2);
}

/**
 * Trie comparison callback for trie_foreach(), with only key.
 */
static void
re_trie_key_deep_equal(void *data, void *udata)
{
	const char *key = data;
	struct re_trie_deep_equal_ctx *ctx = udata;

	if (ctx->mismatch)
		return;		/* We already know it's not a match */

	if (!trie_contains(ctx->t2, key))
		ctx->mismatch = TRUE;
}

/**
 * Are two tries deeply equal?
 */
static bool
re_trie_deep_equal(const re_element_t *e1, const re_element_t *e2)
{
	const trie_t *t1, *t2;
	struct re_trie_deep_equal_ctx ctx;

	g_assert(re_element_is_trie(e1));
	g_assert(re_element_is_trie(e2));
	g_assert(e1->type == e2->type);

	t1 = re_element_get_trie(e1);
	t2 = re_element_get_trie(e2);

	if (trie_count(t1) != trie_count(t2))
		return FALSE;

	if (trie_node_count(t1) != trie_node_count(t2))
		return FALSE;

	/*
	 * The strategy to compare the tries is to traverse t1 and compare
	 * with t2.  We know the two tries have the same amount of items.
	 */

	ZERO(&ctx);
	ctx.t2 = t2;

	switch (e1->type) {
	case RE_TYPE_MATCHX:
	case RE_TYPE_MATCH:
		trie_foreach(t1, re_trie_key_deep_equal, &ctx);
		break;
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		trie_foreach_value(t1, re_trie_keyval_deep_equal, &ctx);
		break;
	default:
		g_assert_not_reached();
	}

	return !ctx.mismatch;
}

/**
 * Are two elements shallow equal?
 *
 * The difference between shallow and deep equality is that two non-shallow
 * items are never shallow-equal, and shallow-equality does not bother with
 * repetition or atomic status, just on the element type and shallow content
 * when it makes sense (equal classes, equal text or char).
 */
static bool
re_element_shallow_equal(const re_element_t *e1, const re_element_t *e2)
{
	re_element_check(e1);
	re_element_check(e2);

	if (e1->type   != e2->type)   return FALSE;
	if (e1->icase  != e2->icase)  return FALSE;

	switch ((re_elem_type_t) e1->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_EMPTY:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
		break;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		if (re_element_get_classes(e1) != re_element_get_classes(e2))
			return FALSE;
		break;
	case RE_TYPE_CHAR:
		if (re_element_get_char(e1) != re_element_get_char(e2))
			return FALSE;
		break;
	case RE_TYPE_TEXT:
		if (0 != strcmp(re_element_get_text(e1), re_element_get_text(e2)))
			return FALSE;
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
		if (!re_class_eq(re_element_get_class(e1), re_element_get_class(e2)))
			return FALSE;
		if (re_element_is_expanded(e1) != re_element_is_expanded(e2))
			return FALSE;
		if (
			re_element_is_expanded(e1) &&
			e1->u.other->v.classes != e2->u.other->v.classes
		)
			return FALSE;
		break;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		if (re_element_get_minmax(e1) != re_element_get_minmax(e2))
			return FALSE;
		break;
	case RE_TYPE_BACKREF:
		if (re_element_get_ref_number(e1) != re_element_get_ref_number(e2))
			return FALSE;
		break;
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
	case RE_TYPE_OR:
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTEX:
		/* Would require deep comparison, cannot be shallow-equal */
		return FALSE;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return TRUE;
}

/**
 * Are two elements deeply equal?
 */
static bool
re_element_deep_equal(const re_element_t *e1, const re_element_t *e2)
{
	re_element_check(e1);
	re_element_check(e2);

	if (e1->type    != e2->type)    return FALSE;
	if (e1->repeat  != e2->repeat)  return FALSE;
	if (e1->atomic  != e2->atomic)  return FALSE;
	if (e1->minimal != e2->minimal) return FALSE;

	switch ((re_repeat_type_t) e1->repeat) {
	case RE_N_ONCE:
	case RE_N_AT_MOST_ONE:
	case RE_N_AT_LEAST_ONE:
	case RE_N_ANY:
		break;
	case RE_N_RANGE:
	case RE_N_MIN:
	case RE_N_COUNT:
		if (re_element_get_repeat_min(e1) != re_element_get_repeat_min(e2))
			return FALSE;
		if (re_element_get_repeat_max(e1) != re_element_get_repeat_max(e2))
			return FALSE;
		break;
	case RE_N_MAX:
		g_assert_not_reached();
	}

	switch ((re_elem_type_t) e1->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_EMPTY:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
		break;
	case RE_TYPE_CHAR:
	case RE_TYPE_TEXT:
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
	case RE_TYPE_BACKREF:
		return re_element_shallow_equal(e1, e2);
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		return re_deep_equal(re_element_get_sub(e1), re_element_get_sub(e2));
	case RE_TYPE_OR:
		return re_or_deep_equal(e1, e2);
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTEX:
		return re_trie_deep_equal(e1, e2);
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return TRUE;
}

/**
 * Are two trees (as defined by their root element vector) deeply equal?
 *
 * @param ev1	the first element vector
 * @param ev2	the second element vector
 *
 * @return TRUE if the two vectors are deeply equal.
 */
static bool
re_deep_equal(const re_elemvec_t *ev1, const re_elemvec_t *ev2)
{
	size_t i;
	const re_element_t *e1, *e2;

	re_elemvec_check(ev1);
	re_elemvec_check(ev2);

	if (ev1->ecnt != ev2->ecnt)
		return FALSE;

	for (
		i = 0, e1 = ev1->elements, e2 = ev2->elements;
		i < ev1->ecnt;
		i++, e1++, e2++)
	{
		if (!re_element_deep_equal(e1, e2))
			return FALSE;
	}

	return TRUE;
}

/**
 * Generic element vector equality.
 */
static bool
re_deep_eq(const void *k1, const void *k2)
{
	return re_deep_equal(k1, k2);
}

/***
 *** ======================== Hashing ========================
 ***/

/**
 * Hashing of a re_class_t structure.
 */
static unsigned
re_class_hash(const void *key)
{
	const re_class_t *c = key;

	if G_UNLIKELY(NULL == c)
		return 0;

	re_class_check(c);

	return binary_hash(c->b, c->bytes) ^ integer_hash(c->offset);
}

static uint re_elemvec_hash(const re_elemvec_t *ev);

static uint
re_or_hash(const re_element_t *e)
{
	uint h = 0;
	pslist_t *alt;

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		h += re_elemvec_hash(alt->data);
	}

	return h;
}

/**
 * Trie hashing callback for trie_foreach(), with only key.
 */
static void
re_trie_key_hash(void *data, void *udata)
{
	const char *key = data;
	uint *h = udata;

	*h += string_hash(key);
}

/**
 * Trie hashing callback for trie_foreach_value(), with key and value.
 */
static void
re_trie_keyval_hash(const void *key, void *value, void *udata)
{
	const re_elemvec_t *ev = value;
	uint *h = udata;

	*h += string_hash(key) + re_elemvec_hash(ev);
}

static uint
re_trie_hash(const re_element_t *e)
{
	const trie_t *t;
	uint h = 0;

	t = re_element_get_trie(e);

	switch (e->type) {
	case RE_TYPE_MATCHX:
	case RE_TYPE_MATCH:
		trie_foreach(t, re_trie_key_hash, &h);
		break;
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		trie_foreach_value(t, re_trie_keyval_hash, &h);
		break;
	default:
		g_assert_not_reached();
	}

	return h;
}

/**
 * Hash function for element;
 */
static uint
re_element_hash(const re_element_t *e)
{
	uint h;

	h =  u16_hash(
			(e->type << 3) + (e->icase << 2) + (e->minimal << 1) + e->atomic);
	h += integer_hash_fast(re_element_get_repeat_min(e));
	h += integer_hash_fast(re_element_get_repeat_max(e));

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_EMPTY:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
		break;
	case RE_TYPE_CHAR:
		h += u16_hash(re_element_get_char(e));
		break;
	case RE_TYPE_TEXT:
		h += string_hash(re_element_get_text(e));
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
		h += re_class_hash(re_element_get_class(e));
		break;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		h += u16_hash(re_element_get_minmax(e));
		break;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		h += uint_hash(re_element_get_classes(e));
		break;
	case RE_TYPE_BACKREF:
		h += uint_hash(re_element_get_ref_number(e));
		break;
	case RE_TYPE_SUBN:
		h += uint_hash(re_element_get_sub_number(e));
		/* FALL THROUGH */
	case RE_TYPE_SUB:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		h += re_elemvec_hash(re_element_get_sub(e));
		break;
	case RE_TYPE_OR:
		h += re_or_hash(e);
		break;
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTEX:
		h += re_trie_hash(e);
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return h;
}

/**
 * Hash function for element vector.
 */
static uint
re_elemvec_hash(const re_elemvec_t *ev)
{
	const re_element_t *e;
	size_t i;
	uint h = 0;

	re_elemvec_check(ev);

	for (i = 0, e = ev->elements; i < ev->ecnt; i++, e++) {
		h += re_element_hash(e);
	}

	return h;
}

/**
 * Generic hash function for element vectors.
 */
static uint
re_elemvec_h(const void *key)
{
	return re_elemvec_hash(key);
}

/***
 *** ======================== Parsing Utilities ========================
 ***/

/**
 * Convert the class made out of the characters in `cs' into a
 * "class" string (containing all the characters of the defined class)
 * and assign it to the element.
 *
 * @note
 * The `cs' string may contain the NUL character.
 *
 * @param e		the character-class element
 * @param cs	the string containing all the characters in the class
 */
static void
re_install_class(re_element_t *e, str_t *cs)
{
	uint8 bytes[RE_ALPHABET];
	const char *s;
	uint8 c;
	size_t i;
	size_t class_count = 0, len;
	bool icase = e->icase;
	bool inverted;

	g_assert(re_element_is_class(e));

	ZERO(&bytes);
	len = str_len(cs);		/* Can contain embedded NUL */
	s = str_2c(cs);

	/*
	 * See which characters are set: we only want to keep them once in the
	 * string.
	 *
	 * When compiling a pattern for case-insensitive matches, we only put
	 * lower-cased values in the byte map: at execution time, we'll be given
	 * only lower-cased input anyway.
	 *
	 * In order to support possible regions of the regular expression being
	 * case-sensitive and others being case-insensitive, we have two versions
	 * of each element type, so that we know, at runtime, what to feed to
	 * the element based on how it was constructed!
	 */

	if (icase) {
		/*
		 * We include only lower-cased items, and at runtime input will be
		 * indeed lower-cased before attempting to look whether the character
		 * belongs to the map.  This helps keeping the class short, and
		 * increases the chances of us being able to further optimize it into
		 * a min-max range..
		 */
		for (i = 0; i < len; i++) {
			c = *s++;
			if (is_ascii_upper(c))
				bytes[ascii_tolower(c)] = 1;
			else
				bytes[c] = 1;
		}
	} else {
		for (i = 0; i < len; i++) {
			c = *s++;
			bytes[c] = 1;
		}
	}

	/*
	 * If they included hardwired classes (\d for instance), then remove
	 * their characters from the selected state by clearing their bytes.
	 * If they say [0-9\d] then clearly it is redundant.
	 */

	if (re_element_is_expanded(e)) {
		uint classes = re_element_get_classes(e);
		pslist_t *cmlist = NULL, *sl;

		g_assert(classes != 0);

		for (i = 0; i < N_ITEMS(re_hardwired); i++) {
			if (classes & (1U << i))
				cmlist = pslist_prepend(cmlist, re_hardwired[i]);
		}

		/*
		 * Clear only the set bytes[] entries which are already handled by
		 * the hardwired classes.
		 */

		PSLIST_FOREACH(cmlist, sl) {
			re_class_check_t cb = sl->data;

			/* Start at 1 to leave-out NUL */
			for (i = 1; i < N_ITEMS(bytes); i++) {
				if (0 == bytes[i])
					continue;
				if (icase && is_ascii_upper(i))
					continue;	/* lower-cased version of \w will be handled */
				if ((*cb)(i)) {
					bytes[i] = 0;
					if (icase && is_ascii_lower(i))
						bytes[ascii_toupper(i)] = 0;
				}
			}
		}

		pslist_free_null(&cmlist);
	}

	/*
	 * We can add the NUL byte in the string, because we know a class string
	 * cannot be empty so at runtime we'll be able to skip it properly.
	 *
	 * Indeed, the way the character class will be matched at runtime will
	 * be by looking whether a character is present in this string via vstrchr(),
	 * and it will be easy to special-case a leading NUL.
	 *
	 * However, for now we choose to leave out NUL bytes: the aim is not to
	 * match binary data and NUL will always be the end-of-string marker.
	 */

	str_reset(cs);
	for (i = 1; i < N_ITEMS(bytes); i++) {
		if (bytes[i])
			str_putc(cs, i);
	}

	/*
	 * If the element was expanded to include hardwired character classes,
	 * look whether adding them would make the resulting string much larger.
	 *
	 * Having everything in the same string will make runtime matching much
	 * faster than having to special-case through the hardwired classes and
	 * at the same time look through the string.
	 */

	if (re_element_is_expanded(e)) {
		uint classes = e->u.other->v.classes;
		str_t *fc = str_new(0);		/* Full class expansion */
		pslist_t *cmlist = NULL, *sl;
		bool has_posix = FALSE, only_posix = TRUE;

		g_assert(classes != 0);		/* At least some hardwired classes */

		for (i = 0; i < N_ITEMS(re_hardwired); i++) {
			if (classes & (1U << i)) {
				cmlist = pslist_prepend(cmlist, re_hardwired[i]);
				if (i >= RE_CLASS_POSIX_START)
					has_posix = TRUE;
				else
					only_posix = FALSE;
			}
		}

		PSLIST_FOREACH(cmlist, sl) {
			re_class_check_t cb = sl->data;

			class_count++;		/* Count how many classes they gave */

			for (i = 1; i < N_ITEMS(bytes); i++) {
				if (bytes[i])
					continue;
				if (icase && is_ascii_upper(i))
					continue;	/* lower-cased version of \w will be handled */
				if ((*cb)(i))
					bytes[i] = 1;
			}
		}

		pslist_free_null(&cmlist);

		for (i = 1; i < N_ITEMS(bytes); i++) {
			if (bytes[i])
				str_putc(fc, i);
		}

		if (str_len(fc) > N_ITEMS(bytes) / 2) {
			/*
			 * We're doing a match against more than half the alphabet size.
			 * It pays to invert the match.  Copy what we have with the
			 * merging of the classes and it will be dealt with later.
			 */

			str_cpy_len(cs, str_2c(fc), str_len(fc));
			class_count = 0;			/* We merged classes back */
			str_destroy_null(&fc);
			goto done;
		}
		else if (str_len(fc) <= 2 * str_len(cs)) {
			/*
			 * The length of the resulting string is less than twice that
			 * of the previous string we computed, keep the new and remove
			 * the expansion: we merged the additional hardwired classes with
			 * the explicit characters already listed in the class.
			 */

			str_cpy_len(cs, str_2c(fc), str_len(fc));
			str_destroy_null(&fc);
			class_count = 0;			/* We merged classes back */
			re_unexpand_element(e);
			goto done;
		}
		else if (0 == str_len(cs)) {
			bool inv = RE_TYPE_INV_CLASS == e->type;

			if (has_posix && only_posix) {
				e->type = inv ? RE_TYPE_NOT_POSIX_CLASS : RE_TYPE_POSIX_CLASS;
				str_destroy_null(&fc);
				return;
			}

			if (1 == class_count && !has_posix) {
				/*
				 * The original string was empty (no user explicitly listed
				 * characters) and we just have one class here in the range:
				 * we can turn the class into a hardwired one: [\D] is just \D
				 * and [^\D] is just \d.
				 */

				re_unexpand_element(e);
				str_destroy_null(&fc);

				/* We know we have only one class specified */

				if (classes & RE_CLASS_D)
					e->type = inv ? RE_TYPE_NOT_D_CLASS : RE_TYPE_D_CLASS;
				else if (classes & RE_CLASS_S)
					e->type = inv ? RE_TYPE_NOT_S_CLASS : RE_TYPE_S_CLASS;
				else if (classes & RE_CLASS_W)
					e->type = inv ? RE_TYPE_NOT_W_CLASS : RE_TYPE_W_CLASS;
				else if (classes & RE_CLASS_NOT_D)
					e->type = inv ? RE_TYPE_D_CLASS : RE_TYPE_NOT_D_CLASS;
				else if (classes & RE_CLASS_NOT_S)
					e->type = inv ? RE_TYPE_S_CLASS : RE_TYPE_NOT_S_CLASS;
				else if (classes & RE_CLASS_NOT_W)
					e->type = inv ? RE_TYPE_W_CLASS : RE_TYPE_NOT_W_CLASS;
				else
					g_assert_not_reached();

				e->icase = FALSE;	/* These are case-insensitive matchers */

				return;
			}
		}

		if (has_posix) {
			str_cpy_len(cs, str_2c(fc), str_len(fc));
			re_unexpand_element(e);
			class_count = 0;			/* We merged classes back */
		}
		str_destroy_null(&fc);
	}

done:
	inverted = booleanize(RE_TYPE_INV_CLASS == e->type);

	if (str_len(cs) > N_ITEMS(bytes) / 2) {
		/*
		 * Invert matching.
		 */

		str_reset(cs);
		for (i = 1; i < N_ITEMS(bytes); i++) {
			if (!bytes[i])
				str_putc(cs, i);
		}

		re_unexpand_element(e);

		/* We flipped the class content */

		e->type = inverted ? RE_TYPE_CLASS : RE_TYPE_INV_CLASS;
	}

	if (RE_TYPE_CLASS == e->type) {
		/*
		 * If we are left with a single char, convert the class to a
		 * simple character match.
		 */

		if (0 == class_count) {
			if (1 == str_len(cs))
				goto char_transform;
			else if (0 == str_len(cs))
				goto null_transform;
		}
	} else {
		/*
		 * If there are no character to exclude, this matches all characters.
		 */

		if (0 == str_len(cs) && 0 == class_count)
			goto match_all;
	}

	/*
	 * Recognize expanded \w and \d (\s is less-likely to be explicitly
	 * expanded, but we handle it as well).
	 *
	 * This allows us to simplify "[0-9]" as "\d" and "[^0-9]" as "\D",
	 * which is both easier to the eye and more efficient at runtime.
	 */

	{
		static re_class_check_t plain[] = {
			re_match_class_d,
			re_match_class_s,
			re_match_class_w,
		};
		static re_elem_type_t plain_class[N_ITEMS(plain)] = {
			RE_TYPE_D_CLASS,
			RE_TYPE_S_CLASS,
			RE_TYPE_W_CLASS,
		};
		static re_elem_type_t inverted_class[N_ITEMS(plain)] = {
			RE_TYPE_NOT_D_CLASS,
			RE_TYPE_NOT_S_CLASS,
			RE_TYPE_NOT_W_CLASS,
		};
		bool fail[N_ITEMS(plain)], inv_fail[N_ITEMS(plain)];
		size_t j;
		re_elem_type_t type = RE_TYPE_MAX;		/* Signals: no valid class */

		ZERO(&fail);
		ZERO(&inv_fail);

		/* Scan all classes and bytes to identify hardwired classes */

		for (j = 0; j < N_ITEMS(plain); j++) {
			for (i = 1; i < N_ITEMS(bytes); i++) {
				bool belongs = (*plain[j])(i);
				bool b = bytes[i];

				if (icase && is_ascii_upper(i))
					b |= bytes[ascii_tolower(i)];

				if (belongs != b)
					fail[j] = TRUE;
				if ((!belongs) != b)
					inv_fail[j] = TRUE;

				if (fail[j] && inv_fail[j])
					break;
			}
		}

		/* Can we summarize bytes[] with a single class? */

		for (j = 0; j < N_ITEMS(plain); j++) {
			if (!fail[j]) {
				type = inverted ? inverted_class[j] : plain_class[j];
				break;
			}
			if (!inv_fail[j]) {
				type = inverted ? plain_class[j] : inverted_class[j];
				break;
			}
		}

		/* If we found a class, transform element into class matcher */

		if (type != RE_TYPE_MAX) {
			re_unexpand_element(e);
			e->type  = type;
			e->icase = FALSE;	/* Hardwired classes are case-insensitive */
			return;
		}
	}

	/*
	 * Check whether class can be summarized as a min-max (inclusive)
	 * type of representation.
	 *
	 * Since we go back to the bytes[] array, we cannot trust e->type
	 * to tell us whether we're inverted, we need to look at the
	 * inverted variable.
	 */

	{
		int min = -1, max = -1, switched = FALSE;

		for (i = 1; i < N_ITEMS(bytes); i++) {
			bool b = bytes[i];
			if (icase && is_ascii_alpha(i))
				b = bytes[ascii_tolower(i)] | bytes[ascii_toupper(i)];
			if (b) {
				if (switched) {
					max = -1;
					break;
				}
				if (-1 == min) min = max = i;
				else           max = i;
			} else {
				if (-1 != min) switched = TRUE;
			}
		}

		if (min != -1 && max != -1)
			goto min_max;

		/* Try with inverted logic */

		for (i = 1; i < N_ITEMS(bytes); i++) {
			bool b = bytes[i];
			if (icase && is_ascii_alpha(i))
				b = bytes[ascii_tolower(i)] | bytes[ascii_toupper(i)];
			if (!b) {	/* This is the only line changing */
				if (switched) {
					max = -1;
					break;
				}
				if (-1 == min) min = max = i;
				else           max = i;
			} else {
				if (-1 != min) switched = TRUE;
			}
		}

		if (-1 == min || -1 == max)
			goto no_min_max;

		/* Invert class since we inverted logic */

		inverted = !inverted;

		/* FALL THROUGH */

	min_max:
		g_assert(min != -1 && max != -1);

		if (min == max && RE_TYPE_CLASS == e->type) {
			/* Is matching a single char! */
			str_reset(cs);
			str_putc(cs, min);
			goto char_transform;
		}

		/* <= 1 in case we have a NUL */
		if (min <= 1 && 255 == max) {
			/* Is matching everything or nothing */
			if (!inverted)
				goto match_all;
			else
				goto empty_transform;
		}

		/*
		 * Transform character class into min-max matching.
		 */

		e->type = inverted ? RE_TYPE_INV_CLASS_MM : RE_TYPE_CLASS_MM;
		re_unexpand_element(e);
		e->u.minmax = re_minmax_encode(min, max);

		/*
		 * When the [a-z] range is not included, we can clear the
		 * case-insensitive flag on the element.
		 *
		 * If the class is inverted as in [^0-9], then we can clear
		 * the case-insensitive flag when neither [A-Z] nor [a-z] is
		 * part of the range, or both are.
		 */

		if (e->icase) {
			if (inverted) {
				if (min <= 'A' && max >= 'z') e->icase = FALSE;
				else
				if (min > 'Z' && max < 'a')   e->icase = FALSE;
				else
				if (min > 'z' || max < 'A')   e->icase = FALSE;
			} else {
				if (min > 'z' || max < 'a')   e->icase = FALSE;
			}
		}

		return;
	}

no_min_max:

	/*
	 * Compress the string into a bit array for fast matching.
	 */

	if (str_len(cs) != 0) {
		size_t x, blen = str_len(cs);
		re_class_t *cl = re_class_allocate();

		for (x = 0; x < blen; x++) {
			c = str_at(cs, x);
			bit_field_set(cl->b, c);	/* Not compacted yet, it's OK */
		}
		re_element_set_class(e, cl);
	} else {
		re_element_set_class(e, NULL);
	}

	return;

char_transform:
	/*
	 * Transform character class into single-char matching.
	 */

	re_unexpand_element(e);
	e->u.c = str_at(cs, 0);
	if (is_ascii_alpha(e->u.c)) {
		e->type  = RE_TYPE_CHAR;
		e->icase = icase;
	} else {
		e->type  = RE_TYPE_CHAR;
		e->icase = FALSE;		/* Case does not matter if not alpha */
	}
	e->minlen = e->maxlen = 1;
	return;

empty_transform:
	/*
	 * Transform character class into an empty-string matching.
	 * That would be [].
	 */

	re_unexpand_element(e);
	e->type = RE_TYPE_EMPTY;
	e->icase = FALSE;
	return;

null_transform:
	/*
	 * Transform character class into the NUL character match.
	 */

	re_unexpand_element(e);
	e->type = RE_TYPE_CHAR;
	e->icase = FALSE;
	re_element_set_char(e, '\0');
	return;

match_all:
	re_unexpand_element(e);
	e->type = RE_TYPE_ALL;
}

/***
 *** ======================== Optimisations ========================
 ***/

/**
 * Context for the linearization traversal.
 *
 * During the linearization traversal, we maintain the tree relationship
 * via the "stack" and "element" fields so we use this traversal to handle
 * several actions:
 *
 * - the linearization itself (adding NEXT nodes in children vectors)
 * - the computation of the longest TEXT / CHAR constant that we need
 * - whether any unbound wild card matching is used (ANY* or ANY+)
 * - the minimum amount of text that must be present to match a vector.
 */
struct re_linearize_ctx {
	pslist_t *stack;			/* Head is the parent vector */
	pslist_t *element;			/* Head is the parent element */
	/* For back-reference detection */
	const re_regex_t *re;		/* The regular expression (for back-refs LUT) */
	pslist_t *capturing;		/* Head is current SUBN group used as back-ref */
	htable_t *subn;				/* Indexed by group #n, yields element */
	/* For minlen computations */
	pslist_t *repeat_min;		/* Repeat minimum for parent vector */
	size_t has_end;				/* Is match anchored at the end? */
	const re_element_t *longest;/* Longest constant TEXT / CHAR we need */
	const re_elemvec_t *end_ev;	/* First element vector with END anchor */
	uint wildcard:1;			/* Any unbound wild card matching? */
};

/**
 * Compute minimal and maximal matching lengths for vector.
 *
 * @param rev	the element vector
 * @param min	where minimum length is stored
 * @param max	where maximum length is stored
 */
static void
re_compute_vector_length(re_elemvec_t *rev, size_t *min, size_t *max)
{
	size_t n, minlen = 0, maxlen = 0;
	re_element_t *e;

	re_elemvec_check(rev);
	g_assert(min != NULL);
	g_assert(max != NULL);

	for (n = 0, e = &rev->elements[0]; n < rev->ecnt; n++, e++) {
		size_t len;

		/*
		 * We skip look-ahead assertions since they do not consume
		 * input when matching.
		 */

		if (RE_TYPE_AHEAD == e->type || RE_TYPE_NOT_AHEAD == e->type)
			continue;

		len = re_element_get_minlen(e);
		len = size_saturate_mult(re_element_get_repeat_min(e), len);
		minlen = size_saturate_add(minlen, len);

		len = re_element_get_maxlen(e);
		len = size_saturate_mult(re_element_get_repeat_max(e), len);
		maxlen = size_saturate_add(maxlen, len);
	}

	*min = minlen;
	*max = maxlen;
}

/**
 * Traversal action callback for element vector: pop vector from stack.
 */
static void
re_linearize_pop(void *data, void *udata)
{
	struct re_linearize_ctx *ctx = udata;
	re_elemvec_t *rev = data, *popped;

	re_elemvec_check(rev);

	popped = pslist_shift(&ctx->stack);
	g_assert(popped == rev);

	re_compute_vector_length(rev, &rev->minlen, &rev->maxlen);
}

/**
 * Traversal entry callback for linearization.
 */
static bool
re_linearize_entry(const void *data, void *udata)
{
	struct re_linearize_ctx *ctx = udata;
	const re_element_t *e = data;

	ctx->element = pslist_prepend_const(ctx->element, e);

	/*
	 * If the element is a SUBN used for back-reference later, push element
	 * to the capturing list and remember the element by its number.
	 *
	 * We only need to take care of that when there are back-references
	 * in the pattern, and in that case ctx->subn will not be NULL.
	 */

	if (ctx->subn != NULL && e->type == RE_TYPE_SUBN) {
		ctx->capturing = pslist_prepend_const(ctx->capturing, e);
		htable_insert_const(ctx->subn,
			uint_to_pointer(re_element_get_sub_number(e)), e);
	}

	return TRUE;
}

/**
 * Linearization processing.
 *
 * @param e		the current element
 * @param rev	the element vector to which element belongs
 * @param ctx	the context
 */
static void
re_linearize_process(const re_element_t *e, re_elemvec_t *rev,
		struct re_linearize_ctx *ctx)
{
	const re_element_t *pe;
	re_element_t *ne;
	re_elemvec_t *parent_vector;
	size_t n;

	re_elemvec_check(rev);

	/*
	 * If we are not the last element of our element vector, continue.
	 *
	 * Note that the vector may be empty (e.g. in "abc|", the  second
	 * part of the alternative is empty), in which case we need the
	 * NEXT anyway.
	 */

	if (NULL == e) {
		g_assert(0 == rev->ecnt);
		goto add_next;
	}

	re_element_check(e);

	g_assert_log(ptr_cmp(e, &rev->elements[0]) >= 0,
		"%s(): e=%s", G_STRFUNC, re_elem_info(e));

	g_assert_log(ptr_cmp(e, &rev->elements[rev->ecnt - 1]) <= 0,
		"%s(): e=%s", G_STRFUNC, re_elem_info(e));

	if (e != &rev->elements[rev->ecnt - 1])
		return;

	/*
	 * If we are already a NEXT node, we're on the element we just
	 * added, so do nothing.
	 */

	if (RE_TYPE_NEXT == e->type)
		return;

	/*
	 * No need to add a NEXT after a RETURN.
	 */

	if (RE_TYPE_RETURN == e->type)
		return;

add_next:

	/*
	 * If we are at the top level (root element vector), there's nothing
	 * to do as there are no parents to add.
	 */

	parent_vector = pslist_data(pslist_next(ctx->stack));
	if (NULL == parent_vector)
		return;

	re_elemvec_check(parent_vector);

	/*
	 * Figure out position of parent element in the parent vector.
	 */

	pe = pslist_data(ctx->element);
	g_assert(pe != NULL);		/* Must have a parent! */

	n = pe - parent_vector->elements;
	g_assert(n < parent_vector->ecnt);

	/*
	 * We're going to append a NEXT node pointing to the element that
	 * follows the parent element in the parent vector, so that we can
	 * always linearily traverse the regular expression, whatever our
	 * starting point.
	 */

	ne = re_elemvec_new_element(rev, RE_TYPE_NEXT, FALSE);
	re_expand_element(ne);
	ne->u.other->x.next.vec = parent_vector;
	ne->u.other->x.next.n = n + 1;	/* May be beyond parent vector count */
	ne->extra = TRUE;				/* Added during finalization */
}

/**
 * Traversal entry callback for element vector: push vector on stack.
 */
static bool
re_linearize_push(const void *data, void *udata)
{
	struct re_linearize_ctx *ctx = udata;
	re_elemvec_t *rev = deconstify_pointer(data);

	re_elemvec_check(rev);

	ctx->stack = pslist_prepend_const(ctx->stack, rev);

	/*
	 * Need to linearize now if the vector is empty, otherwise we would
	 * not even iterate on any element.
	 */

	if G_UNLIKELY(0 == rev->ecnt)
		re_linearize_process(NULL, rev, ctx);

	return TRUE;	/* Traverse element vector */
}

/**
 * Return whether given capturing group #n has its matching text perused
 * later as a back-reference to further match text.
 *
 * @param re	the compiled regular expression
 * @param n		the group number
 *
 * @return TRUE if capturing group is used as a back-reference later on.
 */
static bool
re_group_is_used_as_backref(const re_regex_t *re, size_t n)
{
	re_regex_check(re);

	if (0 == re->backref_count)
		return FALSE;

	if (RE_USE_BYTE_LUT(re->backref_count)) {
		g_assert(re->backrefs.byte_lut != NULL);
		return re->backrefs.byte_lut[n - 1] != 0;
	} else {
		g_assert(re->backrefs.size_lut != NULL);
		return re->backrefs.size_lut[n - 1] != 0;
	}
}

/**
 * If we have a wildcard matching node, flag it in the context.
 */
static void
re_detect_wildcards(const re_element_t *e, struct re_linearize_ctx *ctx)
{
	if (ctx->wildcard)
		return;				/* Already a known fact */

	/*
	 * We're looking for nodes that are going to swallow input
	 * in greedy mode, consuming input that would be needed to
	 * match another part of the text later, causing backtracking.
	 */

	if (RE_N_ONCE == e->repeat)
		return;		/* Non-greedy */

	if (re_element_get_repeat_max(e) <= 3)
		return;		/* Not greedy enough */

	/*
	 * If we are within a capturing group, used by a back-reference, it
	 * would help to also flag as "wildcard" an expression with much
	 * maximum repetition, since it involves a lot of backtracking.
	 */

	if (ctx->capturing != NULL) {
		size_t n = re_element_get_sub_number(ctx->capturing->data);
		if (re_group_is_used_as_backref(ctx->re, n)) {
			ctx->wildcard = TRUE;
			return;
		}
	}

	if (e->minimal)
		return;					/* Not greedy */

	switch (e->type) {
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_NOT_S_CLASS:	/* Considered wide enough! */
		ctx->wildcard = TRUE;
		return;
	}
}

/**
 * Compute the minimum matching length of the group, excluding the
 * repetitions on the group itself.  So for example "(abc)*" will have
 * a minlen of 3, and "(a.*bc){5}" also a minlen of 3.
 */
static void
re_compute_group_length(re_element_t *e)
{
	re_elemvec_t *rev = re_element_get_sub(e);
	size_t min, max;

	re_compute_vector_length(rev, &min, &max);

	re_element_set_minlen(e, min);
	re_element_set_maxlen(e, max);
}

/**
 * Compute the minimum and maximum matching length of OR alternative.
 */
static void
re_compute_or_length(re_element_t *e)
{
	pslist_t *sl;
	size_t min = MAX_INT_VAL(size_t);
	size_t max = 0;

	PSLIST_FOREACH(re_element_get_alt(e), sl) {
		re_elemvec_t *rev = sl->data;
		size_t vlen;

		re_elemvec_check(rev);

		vlen = rev->minlen;
		min = MIN(vlen, min);

		vlen = rev->maxlen;
		max = MAX(vlen, max);
	}

	if (MAX_INT_VAL(size_t) == min)
		min = 0;

	re_element_set_minlen(e, min);
	re_element_set_maxlen(e, max);
}

struct re_compute_trie_minmax_ctx {
	size_t min, max;
};

static void
re_compute_trie_minmax_length(const void *key, void *value, void *data)
{
	const char *string = key;
	const re_elemvec_t *ev = value;
	struct re_compute_trie_minmax_ctx *ctx = data;
	size_t len = vstrlen(string);
	size_t next_min = 0, next_max = 0;
	size_t x;

	if (ev != NULL) {
		/* Routing trie, we need to add the vector matching length */
		re_elemvec_check(ev);
		next_min = ev->minlen;
		next_max = ev->maxlen;
	}

	x = size_saturate_add(len, next_min);
	if (x < ctx->min)
		ctx->min = x;

	x = size_saturate_add(len, next_max);
	if (x > ctx->max)
		ctx->max = x;
}

/**
 * Compute the minimum matching length for a trie alternative.
 */
static void
re_compute_trie_length(re_element_t *e)
{
	trie_t *t = re_element_get_trie(e);
	struct re_compute_trie_minmax_ctx ctx;

	ZERO(&ctx);
	ctx.min = MAX_INT_VAL(size_t);

	trie_foreach_value(t, re_compute_trie_minmax_length, &ctx);

	re_element_set_minlen(e, ctx.min);
	re_element_set_maxlen(e, ctx.max);
}

/**
 * Update minimum length for element.
 */
static void
re_update_minlen(const struct re_linearize_ctx *ctx, re_element_t *e)
{
	re_element_check(e);

	/*
	 * Fix the minilen field that we normally do not set during parsing.
	 */

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_EMPTY:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
		g_assert(0 == re_element_get_minlen(e));
		break;
	case RE_TYPE_BACKREF:
		g_assert(0 == re_element_get_minlen(e));
		/*
		 * Look for the SUBN element this back-reference corresponds to, and
		 * updates its min/max matching values to that of the group.
		 */
		{
			re_element_t *subn = htable_lookup(
					ctx->subn, uint_to_pointer(re_element_get_ref_number(e)));
			size_t min, max;

			g_assert(subn != NULL);
			re_element_check(subn);
			g_assert(RE_TYPE_SUBN == subn->type);

			/* SUBN minlen and maxlen do not include repetitions */

			min = re_element_get_minlen(subn);
			min = size_saturate_mult(min, re_element_get_repeat_min(subn));

			max = re_element_get_maxlen(subn);
			max = size_saturate_mult(max, re_element_get_repeat_max(subn));

			re_element_set_minlen(e, min);
			re_element_set_maxlen(e, max);
		}
		break;
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		re_element_set_minlen(e, 1);
		re_element_set_maxlen(e, 1);
		break;
	case RE_TYPE_CHAR:
		/* CHAR could be NUL, hence minlen would be 0 */
		g_assert_log(1 >= re_element_get_minlen(e),
			"minlen=%zu", re_element_get_minlen(e));
		re_element_set_maxlen(e, re_element_get_minlen(e));
		break;
	case RE_TYPE_TEXT:
		{
			const char *text = re_element_get_text(e);
			size_t minlen = re_element_get_minlen(e);

			g_assert_log(vstrlen(text) == minlen,
				"e=%s vstrlen(text)=%zu, minlen=%zu",
				re_elem_info(e), vstrlen(text), minlen);

			re_element_set_maxlen(e, minlen);
		}
		break;
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
		re_compute_group_length(e);
		break;
	case RE_TYPE_OR:
		re_compute_or_length(e);
		break;
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		re_compute_trie_length(e);
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}
}

/**
 * Computes the minimum matching that is applicable to the current
 * depth in the tree, as represented by the ctx->element stack.
 *
 * This is for the context of determining the longest string that must
 * match, not for computing minimum matching length for vectors.
 */
static size_t
re_current_min_match(const struct re_linearize_ctx *ctx)
{
	pslist_t *sl;
	size_t min = 1;

	if (NULL == ctx->element)
		return 1;		/* At the root vector */

	PSLIST_FOREACH(ctx->element, sl) {
		const re_element_t *e = sl->data;

		/* Strings present in an OR tree must not be considered */

		if (RE_TYPE_OR == e->type)
			return 0;	/* Don't know which branch will be matching text */

		min = size_saturate_mult(min, re_element_get_repeat_min(e));
		if (0 == min)
			break;
	}

	return min;
}

/**
 * Check whether we have a pattern anchored at the end.
 */
static void
re_detect_end(
	const re_elemvec_t *rev, const re_element_t *e,
	struct re_linearize_ctx *ctx)
{
	if (e->type != RE_TYPE_END)
		return;			/* Not an end '$' anchor */

	if (0 == ctx->has_end++)
		ctx->end_ev = rev;		/* Record first element vector with END */
}

/**
 * Can we enter the element for longest string computation?
 */
static bool
re_find_longest_enter(const void *data, void *udata)
{
	const re_element_t *e = data;

	(void) udata;

	if (0 == re_element_get_repeat_min(e))
		return FALSE;

	/*
	 * Do not traverse alternatives or tries, since we cannot know
	 * which path will be taken.
	 */

	if (RE_TYPE_OR == e->type || re_element_is_trie(e))
		return FALSE;

	return TRUE;
}

/**
 * Find longest constant string that must match for the pattern to match.
 */
static void
re_find_longest(void *data, void *udata)
{
	const re_element_t *e = data;
	struct re_linearize_ctx *ctx = udata;

	if (!re_element_is_text(e) && !re_element_is_char(e))
		return;

	/*
	 * If we are within a group that can match 0 times, then the
	 * empty string can match and so we do not have any minimum
	 * length requirement.
	 */

	if (0 == re_current_min_match(ctx))
		return;

	if (NULL == ctx->longest)
		ctx->longest = e;
	else {
		if (re_element_get_minlen(ctx->longest) <= re_element_get_minlen(e))
			ctx->longest = e;	/* Prefer latest items, given same length */
	}
}

/**
 * Traversal action callback for element during linearization.
 */
static void
re_linearize_action(void *data, void *udata)
{
	struct re_linearize_ctx *ctx = udata;
	const re_element_t *e = data, *pe;
	re_elemvec_t *rev;

	rev = pslist_data(ctx->stack);		/* Current element vector */
	re_elemvec_check(rev);

	re_element_check(e);

	g_assert_log(ptr_cmp(e, &rev->elements[0]) >= 0,
		"%s(): e=%s", G_STRFUNC, re_elem_info(e));

	g_assert_log(ptr_cmp(e, &rev->elements[rev->ecnt - 1]) <= 0,
		"%s(): e=%s", G_STRFUNC, re_elem_info(e));

	/*
	 * We traversed the element, hence we pushed that element on the stack.
	 */

	pe = pslist_shift(&ctx->element);
	g_assert(pe == e);

	/* Dispatch the various processing on the node */

	re_detect_wildcards(e, ctx);
	re_detect_end(rev, e, ctx);
	re_update_minlen(ctx, deconstify_pointer(e));

	/*
	 * If element was the head of the `capturing' list, then we can pop
	 * it from the list now that we traversed it.
	 */

	if (ctx->capturing != NULL && pslist_data(ctx->capturing) == e)
		(void) pslist_shift(&ctx->capturing);

	/*
	 * Must come at the end since we're altering the tree by appending NEXT
	 * nodes, which can cause re-allocation of element vectors and therefore
	 * can change the address of the element we're iterating on here.
	 */

	re_linearize_process(e, rev, ctx);
}

/**
 * Traversal action callback for element vector: shrink it!
 */
static void
re_final_shrink(void *data, void *udata)
{
	re_elemvec_t *rev = data;

	re_elemvec_check(rev);
	(void) udata;

	re_elemvec_shrink(rev);
}

/**
 * Processing callback for element.
 */
typedef void (*re_process_elem_fn_t)(re_element_t *e);

/**
 * Processing callback for element range.
 */
typedef void (*re_process_elem_range_fn_t)(
	re_element_t *start, const re_element_t *end);

/**
 * Context for upgrading elements (e.g standalone CHAR to TEXT).
 */
struct re_upgrade_ctx {
	re_element_predicate_fn_t is_upgradable;
	re_element_predicate_fn_t is_proper;
	re_process_elem_fn_t      up_cb;
};

/**
 * Context for processing 1 element or a range of elements.
 */
struct re_process_ctx {
	re_element_predicate_fn_t  is_proper;
	re_element_predicate_fn_t  can_merge;
	re_process_elem_fn_t       one_cb;
	re_process_elem_range_fn_t range_cb;
	struct re_upgrade_ctx      *upgrade;	/* Optional upgrade */
};

/**
 * Callback signature for common element merging.
 *
 * Elements are processed from first (included) to end (excluded).
 *
 * @param rev		the element vector
 * @param first		first element to coalesce
 * @param end		upper limit element (may point right beyond vector)
 * @param process	element / range processing callbacks
 *
 * @return amount of nodes that disappeared from vector due to coalescing.
 */
typedef size_t (*re_merge_elem_fn_t)(
	re_elemvec_t *rev, re_element_t *first, re_element_t *end,
	const struct re_process_ctx *process);

/**
 * Mutate element to TEXT, with text being held in string `s'.
 * The TEXT element is repeated only once.
 */
static void
re_element_mutate_text(re_element_t *e, re_elem_type_t ntype, const str_t *s)
{
	g_assert(!re_element_is_text(e));

	re_unexpand_element(e);
	e->type = ntype;
	e->u.text = str_dup(s);
	re_element_set_minlen(e, str_len(s));
	re_element_set_maxlen(e, str_len(s));
	e->repeat = RE_N_ONCE;
}

/**
 * Is element of type char or text?
 */
static bool
re_element_is_char_or_text(const re_element_t *e)
{
	return re_element_is_char(e) || re_element_is_text(e);
}

/**
 * Is element a CHAR{1} item?
 */
static bool
re_element_is_single_char(const re_element_t *e)
{
	return re_element_is_char(e) && RE_N_ONCE == e->repeat;
}

/**
 * Change single CHAR{1} node to text.
 */
static void
re_element_char_change_to_text(re_element_t *e)
{
	char t[2];

	g_assert(re_element_is_single_char(e));
	g_assert(!re_element_is_expanded(e));

	t[0] = re_element_get_char(e);
	t[1] = '\0';
	e->type = RE_TYPE_TEXT;
	e->u.text = h_strdup(t);
	e->minlen = e->maxlen = 1;
}

/**
 * Replace text within TEXT element with text being held in string `s'.
 * The TEXT element is repeated only once.
 */
static void
re_element_replace_text(re_element_t *e, const str_t *s)
{
	g_assert(re_element_is_text(e));
	re_element_set_text(e, str_dup(s));
	e->repeat = RE_N_ONCE;
	re_unexpand_element(e);
	re_element_set_minlen(e, str_len(s));
	re_element_set_maxlen(e, str_len(s));
}

/**
 * Predicate checking whether we can expand a CHAR node.
 */
static bool
re_element_can_expand_char(const re_element_t *e)
{
	size_t min, max;

	g_assert(re_element_is_char(e));

	min = re_element_get_repeat_min(e);
	max = re_element_get_repeat_max(e);

	/*
	 * Validate that the CHAR nodes are all repeated with
	 * a constant count, and that count remains below the
	 * RE_CHAR_COUNT_MAX limit (arbitrary limit to avoid them
	 * saying a{342656} and us optimizing that with a 342656-byte
	 * long string!
	 */

	return min == max && min <= RE_CHAR_COUNT_MAX;
}

/**
 * Check whether CHAR node with a low amount of repetition can be replaced
 * with a TEXT node.
 */
static void
re_element_char_to_text(re_element_t *e)
{
	size_t min = re_element_get_repeat_min(e);

	if (min > 1 && re_element_can_expand_char(e)) {
		str_t *s = str_new(0);
		int c = re_element_get_char(e);

		do {
			str_putc(s, c);
		} while (--min);

		/* Mutate node into expanded TEXT with 1 repetition */
		re_element_mutate_text(e, RE_TYPE_TEXT, s);
		str_destroy_null(&s);
	}
}

/**
 * Predicate checking whether we can expand a TEXT node.
 */
static bool
re_element_can_expand_text(const re_element_t *e)
{
	size_t min, max, len;

	g_assert(re_element_is_text(e));

	min = re_element_get_repeat_min(e);
	max = re_element_get_repeat_max(e);
	len = re_element_get_minlen(e);

	return min == max && size_saturate_mult(len, min) <= RE_TEXT_LEN_MAX;
}

/**
 * Check whether TEXT node with a low amount of repetition can be replaced
 * with a TEXT node expanding the repetition.
 */
static void
re_element_text_expand(re_element_t *e)
{
	size_t min = re_element_get_repeat_min(e);

	if (min > 1 && re_element_can_expand_text(e)) {
		str_t *s = str_new(0);
		const char *text = re_element_get_text(e);
		size_t len = re_element_get_minlen(e);

		do {
			str_cat_len(s, text, len);
		} while (--min);

		/* Mutate node into expanded TEXT with 1 repetition */
		re_element_replace_text(e, s);
		str_destroy_null(&s);
	}
}

/**
 * Is element text with no repetition or one that can be expanded?
 */
static bool
re_element_is_expandable_text(const re_element_t *e)
{
	return re_element_is_text(e) && re_element_can_expand_text(e);
}

/**
 * Strip lead string from element, possibly removing it if it becomes empty.
 *
 * @param e		the TEXT/CHAR element we need to strip
 * @param lead	the leading string we need to remove
 * @param ev	the element vector where `e' resides
 * @param n		the position of `e' within `ev'
 */
static void
re_element_strip_lead(re_element_t *e, str_t *lead, re_elemvec_t *ev, size_t n)
{
	re_elemvec_check(ev);
	g_assert(0 != str_len(lead));
	g_assert_log(n < ev->ecnt,
		"n=%zu, ecnt=%zu, lead=\"%s\"", n, ev->ecnt, str_2c(lead));

	if (re_element_is_char(e)) {
		/* The lead is necessary that character, so remove element */
		g_assert(1 == str_len(lead));
		g_assert(str_at(lead, 0) == re_element_get_char(e));

		re_elemvec_remove_element(ev, n);
	} else if (re_element_is_text(e)) {
		const char *text = re_element_get_text(e);
		size_t len = re_element_get_minlen(e);
		size_t lead_len = str_len(lead);

		g_assert(vstrlen(text) == len);
		g_assert(len >= lead_len);

		if (lead_len == len) {
			/* Stripping the whole element, remove it */
			re_elemvec_remove_element(ev, n);
		}
		else if (1 == len - lead_len) {
			/* Leaving just one character, transform TEXT into CHAR */
			int c = text[lead_len];
			hfree(deconstify_char(text));
			if (is_ascii_alpha(c)) {
				e->type  = RE_TYPE_CHAR;
			} else {
				e->type  = RE_TYPE_CHAR;
				e->icase = FALSE;		/* Case irrelevant if not alpha */
			}
			re_element_set_minlen(e, 1);
			re_element_set_maxlen(e, 1);
			re_element_set_char(e, c);
		}
		else {
			/* Regular case */
			re_element_set_text(e, h_strdup(text + lead_len));
			re_element_set_minlen(e, len - lead_len);
			re_element_set_maxlen(e, len - lead_len);
		}
	} else {
		s_error("%s(): unexpected element %s", G_STRFUNC, re_elem_info(e));
	}
}

/**
 * Coalesce consecutive CHAR elements into a single TEXT element.
 *
 * The first node is replaced by a TEXT element but elements are not
 * removed from the vector: it is up to the caller to do that afterwards,
 * since that is a generic operation.
 *
 * @param first		the first element, that is going to be transformed
 * @param limit		upper node for transformation (first outside range)
 */
static void
re_coalesce_char_elements(re_element_t *first, const re_element_t *limit)
{
	re_element_t *e;
	str_t *s = str_new(0);

	for (e = first; e < limit; e++) {
		size_t cnt = re_element_get_repeat_min(e);
		int c = re_element_get_char(e);

		while (cnt--)  {
			str_putc(s, c);
		}
	}

	re_element_mutate_text(first, RE_TYPE_TEXT, s);
	str_destroy_null(&s);
}

/**
 * Coalesce consecutive TEXT elements into a single TEXT element.
 *
 * The first node is replaced by a TEXT element but elements are not
 * removed from the vector: it is up to the caller to do that afterwards,
 * since that is a generic operation.
 *
 * @param first		the first element, that is going to be transformed
 * @param limit		upper node for transformation (first outside range)
 */
static void
re_coalesce_text_elements(re_element_t *first, const re_element_t *limit)
{
	re_element_t *e;
	str_t *s = str_new(0);

	for (e = first; e < limit; e++) {
		size_t cnt = re_element_get_repeat_min(e);
		const char *text = re_element_get_text(e);
		size_t len = re_element_get_minlen(e);

		while (cnt--) {
			str_cat_len(s, text, len);
		}
	}

	re_element_replace_text(first, s);
	str_destroy_null(&s);
}

/**
 * "Merge" a single element, by expanding it if it makes sense.
 */
static void
re_merge_one(re_element_t *e, const struct re_process_ctx *process)
{
	/*
	 * If there is an "upgrade" set of callbacks, we are not processing
	 * a single-typed element but a set of types.  Do nothing for a
	 * single element.
	 */

	if G_UNLIKELY(process->upgrade != NULL)
		return;

	(*process->one_cb)(e);
}

/**
 * Merges consecutive type{n} nodes as one TEXT node, with n >= 1,
 * where "type" can be CHAR or TEXT.
 *
 * @param rev		the element vector
 * @param first     first "type" element
 * @param end		first non-"type" element (may point right beyond vector)
 * @param process	processing callbacks for element / range
 *
 * @return amount of nodes that disappeared from vector.
 */
static size_t
re_merge_range_elements(
	re_elemvec_t *rev, re_element_t *first, re_element_t *end,
	const struct re_process_ctx *process)
{
	size_t n = 0;
	re_element_t *e;

	re_elemvec_check(rev);
	g_assert_log(process->is_proper(first),
		"%s*(: is_proper=%s, first is %s",
		G_STRFUNC, stacktrace_function_name(process->is_proper),
		re_elem_info(first));
	g_assert(end != first);
	/* `first' must be held in vector */
	g_assert(UNSIGNED(first - rev->elements) < rev->ecnt);
	/* `end' is either held or the first element beyond vector */
	g_assert(UNSIGNED(end - rev->elements) <= rev->ecnt);

	/*
	 * Expand a{n} into "aaaa...aaa" if n is small enough.
	 */

	if (1 == end - first) {
		re_merge_one(first, process);
		return 0;
	}

#if 0
#define RE_DEBUG_MERGE_RANGE_ELEMENTS
#endif

#ifdef RE_DEBUG_MERGE_RANGE_ELEMENTS
#define re_debug(...)	s_debug(__VA_ARGS__);
#else
#define re_debug(...)	{}
#endif

	do {
		re_element_t *limit = end;

		for (e = first; e < end; e++) {
			struct re_upgrade_ctx *up = process->upgrade;

			re_debug("%s(): processing %s, up=%s",
				G_STRFUNC, re_elem_info(e), bool_to_string(up != NULL));

			/*
			 * If there is an upgrade routine defined (for instance we are
			 * processing CHAR or TEXT elements and we wish to convert
			 * a standalone CHAR into a TEXT), then look whether item is
			 * upgradable.  If it is, perform the upgrade.
			 *
			 * It is mandatory for an upgraded node to be merge-able,
			 * otherwise we would transform a node and then not process it!
			 */

			if (up != NULL) {
				bool can_upgrade = !up->is_proper(e) && up->is_upgradable(e);
				bool mergeable = process->can_merge(e);
				bool should_stop;

				if (e > first && process->is_proper(e - 1)) {
					should_stop = !mergeable && !can_upgrade;
				} else if (
					(e + 1) < end && (can_upgrade || mergeable) &&
					(up->is_proper(e + 1) || up->is_upgradable(e + 1))
				) {
					should_stop = FALSE;
				} else {
					should_stop = TRUE;
				}

				if (should_stop) {
					re_debug("%s(): stopping at %s", G_STRFUNC, re_elem_info(e));
					goto stop;
				}

				if (can_upgrade) {
					re_debug("%s(): upgrading %s", G_STRFUNC, re_elem_info(e));
					(*up->up_cb)(e);
					g_assert(process->can_merge(e));
					g_assert(process->is_proper(e));
				}
			}

			re_debug("%s(): at %s, can_merge=%s", G_STRFUNC,
				re_elem_info(e), bool_to_string(process->can_merge(e)));

			if (!process->can_merge(e))
				goto stop;

			continue;
		stop:

			limit = e;		/* Exclude this node from coalescing */
			break;
		}

		if (limit - first > 1) {
			size_t removed = limit - first - 1;
			size_t first_n = first - rev->elements;	/* Index within vector */
			size_t upper_n = limit - rev->elements - 1;

			/* Mutate first node */

			process->range_cb(first, limit);

			/* Physically remove the coalesced nodes */

			g_assert(upper_n > first_n);
			g_assert(upper_n < rev->ecnt);

			do {
				re_elemvec_remove_element(rev, upper_n--);
			} while (upper_n > first_n);

			n += removed;
			limit = first;
			end -= removed;		/* Removed elements, end shifts as well */
		} else if (1 == limit - first) {
			/* If transformation, it is in place: no removal of any node */
			re_merge_one(first, process);
		}

		first = limit + 1;
	} while (first < end);

#undef re_debug

	return n;		/* Amount of nodes removed */
}

/**
 * Traversal action callback for element vector to merge consecutive
 * similar nodes with a fixed repetition count n as one TEXT, when n >= 1.
 */
static void
re_merge_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	struct re_process_ctx *ctx = udata;
	size_t i;
	re_element_t *first = NULL;

	re_elemvec_check(rev);

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (!(*ctx->is_proper)(e)) {
			/* Not an element with proper type */
			if (first != NULL) {
				i -= re_merge_range_elements(rev, first, e, ctx) + 1;
				first = NULL;
			}
		} else {
			/* Reached element of the type we want */
			if (NULL == first)
				first = e;
		}
	}

	if (first != NULL) {
		re_element_t *end = &rev->elements[rev->ecnt];
		re_merge_range_elements(rev, first, end, ctx);
	}
}

/**
 * Traversal action callback for element vector to remove EMPTY elements.
 */
static void
re_strip_empty_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (RE_TYPE_EMPTY == e->type) {
			re_elemvec_remove_element(rev, i);
			i--;		/* Keep same index for next loop */
		}
	}
}

/**
 * Explode TEXT elements with a repetition count of 1 into CHAR elements.
 */
static void
re_explode_text_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];
		const char *p;
		char c;

		if (!re_element_is_text(e))
			continue;

		if (RE_N_ONCE != e->repeat)
			continue;

#if 0
		s_debug("%s(): exploding %s", G_STRFUNC, re_elem_info(e));
#endif

		p = re_element_get_text(e);
		while ((c = *p++)) {
			re_element_t *ne =
				re_elemvec_insert_element(rev, i++, RE_TYPE_CHAR, e->icase);
			ne->repeat   = RE_N_ONCE;
			ne->atomic   = e->atomic;
			ne->inserted = TRUE;
			re_element_set_char(ne, c);
			ne->minlen = ne->maxlen = 1;
		}

		re_elemvec_remove_element(rev, i);	/* Initial TEXT shifted there */
	}
}

/**
 * Traversal action callback for element vector to split shallow repetitions.
 */
static void
re_split_shallow_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];
		re_element_t *ne;
		size_t min = re_element_get_repeat_min(e);
		size_t max = re_element_get_repeat_max(e);

		if (0 == min || 1 == max)
			continue;

		if (!re_element_is_shallow(e))
			continue;

		/*
		 * The idea behind splitting is this:
		 *
		 * Instead of:     CHAR 'a'; CHAR+ 'b'
		 * we create a:	   CHAR 'a'; CHAR 'b'; CHAR* 'b'
		 * so we'll get a: TEXT "ab"; CHAR* 'b'
		 * once all the coalescing is done.
		 *
		 * But we split all shallow elements, which includes
		 * TEXT, BACKREF, ANY, etc...
		 */

#if 0
		s_debug("%s(): splitting %s, min/max=%zu/%zu",
				G_STRFUNC, re_elem_info(e), min, max);
#endif

		ne = re_elemvec_insert_element(rev, i, e->type, e->icase);
		e = &rev->elements[i + 1];				/* Old shifted here */
		re_element_copy(ne, e);
		ne->inserted = TRUE;
		e->extracted = TRUE;

		if (max != MAX_INT_VAL(size_t))
			max -= min;

		re_element_set_repeat(e, 0, max);		/* Old element */
		re_element_set_repeat(ne, min, min);	/* New element */

#if 0
		s_debug("%s(): new element %s, min/max=%zu/%zu",
				G_STRFUNC, re_elem_info(ne),
				re_element_get_repeat_min(ne),
				re_element_get_repeat_max(ne));

		s_debug("%s(): old element %s, min/max=%zu/%zu",
				G_STRFUNC, re_elem_info(e),
				re_element_get_repeat_min(e),
				re_element_get_repeat_max(e));
#endif

		i++;		/* Skip old element */
	}
}

/**
 * Traversal action callback for element vector to merge back shallow
 * repetitions.
 */
static void
re_merge_shallow_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	if (0 == rev->ecnt)
		return;

	/*
	 * First pass: mutate 1-char TEXT elements into CHAR ones.
	 */

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (re_element_is_text(e)) {
			const char *text = re_element_get_text(e);
			char c;
			if (1 != vstrlen(text))
				continue;
			/* Transform TEXT "x" into CHAR 'x' */
			c = *text;
			hfree(deconstify_char(text));
			e->type = RE_TYPE_CHAR;
			re_element_set_char(e, c);
		}
	}

	/*
	 * Second pass: coalesce identical shallow elements together.
	 */

	for (i = 0; i < rev->ecnt - 1; i++) {
		re_element_t *e = &rev->elements[i];
		re_element_t *ne = &rev->elements[i + 1];
		size_t min = re_element_get_repeat_min(ne);
		size_t max = re_element_get_repeat_max(ne);
		bool atomic, minimal;

		if (!re_element_is_shallow(e))
			continue;

		if (e->type != ne->type)
			continue;

		/* `ne' is necessarily shallow since `e' and `ne' have same type */

		if (!re_element_shallow_equal(e, ne))
			continue;

		/*
		 * If one element is atomic, the second should be or no merging!
		 * The only exception is if one has a fixed repetition count, in
		 * which case the result will be atomic.
		 */

		atomic = e->atomic;
		if (e->atomic != ne->atomic) {
			/* One is necessarily atomic then */
			if (
				min != max &&
				re_element_get_repeat_max(e) != re_element_get_repeat_min(e)
			)
				continue;
			atomic = TRUE;
		}

		/*
		 * If one element is minimal, the second should be or no merging!
		 * The only exception is if one has a fixed repetition count, in
		 * which case the result will be minimal.
		 */

		minimal = e->minimal;
		if (e->minimal != ne->minimal) {
			/* One is necessarily minimal then */
			if (
				min != max &&
				re_element_get_repeat_max(e) != re_element_get_repeat_min(e)
			)
				continue;
			minimal = TRUE;
		}

#if 0
		s_debug("%s(): merging %s with next min/max=%zu/%zu",
				G_STRFUNC, re_elem_info(e), min, max);
		s_debug("%s(): next is %s", G_STRFUNC, re_elem_info(ne));
#endif

		max = size_saturate_add(max, re_element_get_repeat_max(e));
		min += re_element_get_repeat_min(e);

		re_element_set_repeat(ne, min, max);	/* Next element */
		ne->extracted = FALSE;					/* Merged back! */
		ne->minimal   = minimal;
		ne->atomic    = atomic;

#if 0
		s_debug("%s(): new element %s, min/max=%zu/%zu",
				G_STRFUNC, re_elem_info(ne),
				re_element_get_repeat_min(ne),
				re_element_get_repeat_max(ne));
#endif

		re_elemvec_remove_element(rev, i);		/* Current element */
		i--;									/* Stay on altered element */
	}
}

/**
 * Traversal action callback for element vector to remove redundant
 * elements.
 *
 * Currently, a redundant element is a look-ahead assertion identical
 * to what follows.
 */
static void
re_strip_redundant_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		const re_element_t *e = &rev->elements[i];

		if (RE_TYPE_AHEAD == e->type) {
			re_elemvec_t *gev = re_element_get_sub(e);
			size_t j;

			for (j = 0; j < gev->ecnt; j++) {
				const re_element_t *ae = &gev->elements[j];
				size_t k = i + j + 1;	/* + 1 to skip AHEAD in `rev' */

				if (RE_TYPE_SUBN == ae->type)
					goto next_element;		/* Has capturing group */

				if (RE_TYPE_RETURN == ae->type)
					break;					/* Reached end of AHEAD */

				if (k >= rev->ecnt)
					goto next_element;

				if (!re_element_deep_equal(&rev->elements[k], ae))
					goto next_element;
			}

			/* We can remove this AHEAD element */

			re_elemvec_remove_element(rev, i);
			re_elemvec_recursive_free(gev);
			i--;	/* Stay at current element */
		}
		/* FALL THROUGH */
	next_element:
		continue;
	}
}

/**
 * Strip EMPTY elements from all the element vectors: these items always
 * match the empty string and therefore they do not bring anything at
 * runtime and can be safely removed, regardless of their repetition count.
 */
static void
re_strip_empty(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_strip_empty_elements, NULL);
}

/**
 * Explode TEXT elements with a repetition count of 1 into CHAR elements.
 */
static void
re_explode_text(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_explode_text_elements, NULL);
}

/**
 * Split CHAR repetitions with a minimum > 0 when they are preceded by
 * another CHAR or TEXT element in the vector.
 */
static void
re_split_shallow_repetitions(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_split_shallow_elements, NULL);
}

/**
 * Merge "shallow" elements together, factorizing repetitions.
 *
 * It merges consecutive CHAR repetitions split by re_split_shallow_repetitions()
 * and which were not otherwise perused for merging with a TEXT node.
 *
 * It also merges together initial CHAR repetition, turning "b*b+" into "b+".
 * But it also merges ".*.+" into ".+" for instance, and "..." into ".{3}".
 *
 * And it transforms back TEXT into CHAR if only one character is
 * to be matched.
 */
static void
re_merge_shallow_repetitions(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_merge_shallow_elements, NULL);
}

static void
re_strip_redundant(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_strip_redundant_elements, NULL);
}

/**
 * Coalesce constant TEXT/CHAR nodes, possibly expansing those that.bear a
 * small repetition count to make them constant.
 */
static void
re_coalesce_constants(re_regex_t *re)
{
	struct re_process_ctx process_ctx;
	struct re_upgrade_ctx upgrade_ctx;

	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	/*
	 * Compact consecutive CHAR{n} nodes as TEXT.
	 *
	 * This allows "a[b]c", which internally is compiled as 'a', 'b', 'c'
	 * with 3 consecutive CHAR items to become a TEXT node with "abc".
	 *
	 * Furthermore, small-enough repetitions (capped to RE_CHAR_COUNT_MAX)
	 * are inlined, "a{3}" being expanded to "aaa".
	 */

	ZERO(&process_ctx);
	process_ctx.is_proper  = re_element_is_char;
	process_ctx.can_merge  = re_element_can_expand_char;
	process_ctx.one_cb     = re_element_char_to_text;
	process_ctx.range_cb   = re_coalesce_char_elements;

	re_foreach_elemvec(re->u.compiled, re_merge_elements, &process_ctx);

	/*
	 * Coalesce consecutive TEXT elements, expanding those with a low
	 * constant repetition count.
	 */

	process_ctx.is_proper  = re_element_is_text;
	process_ctx.can_merge  = re_element_is_expandable_text;
	process_ctx.one_cb     = re_element_text_expand;
	process_ctx.range_cb   = re_coalesce_text_elements;

	re_foreach_elemvec(re->u.compiled, re_merge_elements, &process_ctx);

	/*
	 * Now coalesce TEXT elements with standalone CHAR items.
	 */

	ZERO(&upgrade_ctx);
	upgrade_ctx.is_upgradable = re_element_is_single_char;
	upgrade_ctx.is_proper     = re_element_is_text;
	upgrade_ctx.up_cb         = re_element_char_change_to_text;

	process_ctx.is_proper  = re_element_is_char_or_text;
	process_ctx.upgrade    = &upgrade_ctx;

	re_foreach_elemvec(re->u.compiled, re_merge_elements, &process_ctx);
}

/**
 * Identify the previous constant element that must match before the END
 * marker in the element vector.
 *
 * @return element that must match, or NULL if we cannot find a suitable
 * element to check for.
 */
static const re_element_t *
re_finalize_ending_element(const re_elemvec_t *ev)
{
	re_element_t *e;

	if (ev->ecnt <= 1)
		return NULL;

	if (RE_TYPE_END != ev->elements[ev->ecnt - 1].type)
		return NULL;

	e = &ev->elements[ev->ecnt - 2];

	if (0 == re_element_get_repeat_min(e))
		return NULL;

	switch (e->type) {
	case RE_TYPE_CHAR:
	case RE_TYPE_TEXT:
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		return e;
	}

	return NULL;
}

/**
 * Extract leading common string and character class from the trie.
 *
 * In the sequence "foobar|footar", "foo" is the leading string, then
 * "[bt] is the character class that must match the remaining of the
 * strings.
 *
 * @param t			the trie
 * @param lead		where the leading string is extracted into
 * @param class		where the characters that make-up the class are put to
 */
static void
re_simplify_extract_lead_class(const trie_t *t, str_t *lead, str_t *class)
{
	const trie_node_t *tn;

	/*
	 * Inspect the trie: if we have more than one child underneath the
	 * root, then the only lookahead possible is the set of first letters
	 * of every word, that is: the character class represented by the set
	 * of children of the root node.
	 */

	tn = trie_root(t);

#if 0
	{
		ostream_t *os = ostream_open_fd(2);
		s_debug("%s(): trie dump:", G_STRFUNC);
		trie_fmt(t, os);
		ostream_close(os);
	}
#endif

	for (;;) {
		size_t i, child_count;
		const trie_node_t * const *children;
		const trie_node_t *cn;

		if (trie_node_is_match(tn))
			break;

		children = trie_node_children(tn, &child_count);

		if (0 == child_count)
			break;

		if (1 == child_count) {
			const char *radix;

			/*
			 * Whilst we have one child, we are following the common leading
			 * string of the keys that are in the trie.
			 *
			 * The first char of this string is the arc, followed by the
			 * radix, if present (for collapsed tries).
			 *
			 * We continue to follow this path, collecting the lead string,
			 * until we no longer have a single child under the current node
			 * or we reach a matching point.
			 */

			cn = children[0];		/* The only child */

			str_putc(lead, trie_node_arc(cn));
			radix = trie_node_radix(cn);
			if (radix != NULL)
				str_cat(lead, radix);
		} else {
			/*
			 * When there are multiple children, we collect the arcs of all
			 * the children and make-up a character class for them.
			 *
			 * Then we stop traversing the trie as we cannot factorize
			 * anything else from the strings present in the trie.
			 */

			for (i = 0; i < child_count; i++) {
				cn = children[i];
				str_putc(class, trie_node_arc(cn));
			}
			break;
		}

		tn = cn;
	}
}

/**
 * Insert lookahead block for leading string and character class.
 *
 * @param rev		the element vector where the OR node resides
 * @param n			the index within `rev' for the OR node.
 * @param lead		where the leading string was extracted into
 * @param class		where the characters that make-up the class are listed
 *
 * @return TRUE if we inserted a new look-ahead element
 */
static bool
re_simplify_insert_lookahead(
	re_elemvec_t *rev, size_t n, str_t *lead, str_t *class)
{
	re_element_t *ela;	/* The new AHEAD group element */
	re_elemvec_t *lev;	/* The element vector for the AHEAD group */
	bool inserted = TRUE;
	bool icase;

	if (0 == str_len(lead) && 0 == str_len(class))
		return FALSE;

	/*
	 * Refuse to install the AHEAD class, it does not speed-up
	 * matching at all.
	 *
	 * FIXME: revisit this look-ahead strategy since we heavily optimize
	 * the OR blocks now, extracting all the common substrings we can,
	 * and we remove redundant AHEAD items (even user-added).
	 * Maybe we don't need to bother with this AHEAD "optimization"
	 * any more?
	 * 		--RAM, 2020-07-15
	 */

	if (0 == str_len(lead))
		return FALSE;

	icase = rev->elements[n].icase;	/* OR element's icase status */

	/*
	 * Allocate the AHEAD element and its element vector, then
	 * insert it before the OR element.
	 */

	if (
		n != 0 &&
		rev->elements[n - 1].extra &&
		RE_TYPE_AHEAD == rev->elements[n - 1].type
	) {
		ela = &rev->elements[n - 1];
		if (!ela->extra)
			goto insert;	/* This is a user-supplied AHEAD */

		/* This is a AHEAD we previously inserted */
		lev = re_element_get_sub(ela);
		re_elemvec_cleanup_free(lev);
		/* Replace look-ahead with newer version */
		inserted = FALSE;
		goto replace;
	}

insert:
	ela = re_elemvec_insert_element(rev, n, RE_TYPE_AHEAD, icase);
	ela->extra = TRUE;				/* Don't dump this node */

replace:
	re_element_check(ela);
	g_assert(RE_TYPE_AHEAD == ela->type);

	lev = re_elemvec_alloc(0);
	re_element_set_sub(ela, lev);

	/*
	 * If we have a "lead" string, emit a TEXT node as part of
	 * the look-ahead expression.
	 */

	if (str_len(lead) != 0) {
		re_element_t *e = re_elemvec_new_element(lev, RE_TYPE_TEXT, icase);
		re_element_replace_text(e, lead);
	}

	/*
	 * If we have a "class" string, emit a CLASS node as part of the
	 * look-ahead expression.
	 */

	if (str_len(class) != 0) {
		re_element_t *e = re_elemvec_new_element(lev, RE_TYPE_CLASS, icase);
		re_install_class(e, class);
	}

	return inserted;
}

/**
 * Encapsulate the OR element into a GROUP, which is here only to
 * preserve precedence, transferring any repetition on the OR to
 * the new GROUP.
 *
 * This is done to be able to factorize things before and after the
 * OR element.
 *
 * @param rev		the element vector where the OR node resides
 * @param n			the index within `rev' for the OR node.
 *
 * @return the new element vector for the GROUP, the OR element now
 * residing at its first slot.
 */
static re_elemvec_t *
re_encapsulate_or(re_elemvec_t *rev, size_t n)
{
	re_elemvec_t *oev;		/* Element vector for the new OR group */
	re_element_t *oe;		/* OR element in new vector */
	re_element_t *e;		/* The old OR we're mutating into GROUP */

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);

	e = &rev->elements[n];

	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	oev = re_elemvec_alloc(0);

	/* The new OR element following, no repetition */

	oe = re_elemvec_new_element(oev, RE_TYPE_OR, e->icase);
	oe->u.alt = re_element_get_alt(e);	/* Transfer alternatives */

	/* Mutate the old OR into GROUP, keeping repetitions */

	e->type = RE_TYPE_GROUP;
	e->inserted = TRUE;
	re_element_set_sub(e, oev);		/* The vector we created */

	return oev;
}

/**
 * Factorize lead string out of OR block.
 *
 * @param rev		the element vector where the OR node resides
 * @param n			the index within `rev' for the OR node.
 * @param lead		the identified lead string to factorize
 * @param icase		was regular expression compiled case-insensitively?
 */
static void
re_simplify_factorize_lead(
	re_elemvec_t *rev, size_t n, str_t *lead, bool icase)
{
	re_elemvec_t *oev;		/* Element vector for the new OR group */
	re_element_t *te;		/* TEXT/CHAR element in new vector */
	re_element_t *oe;		/* OR element in new vector */
	re_elem_type_t tetype;
	pslist_t *sl;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(str_len(lead) != 0);

	/*
	 * When we have a lead string, install a previous TEXT element
	 * in front of the OR.  This is an optimization that we want to
	 * appear when we dump the regular expression, hence the new element
	 * is not flagged as "extra" and we need to make sure the OR is
	 * put inside a non-capturing GROUP to preserve precedence, transferring
	 * the initial OR repetition information to the GROUP.
	 *
	 * Then we need to strip that common leading string from all the
	 * leading TEXT/CHAR elements of the OR.
	 *
	 * Because we install a GROUP, we preserve the precedence of the OR
	 * element, in case a look-ahead is installed before it later on.
	 */

	oev = re_encapsulate_or(rev, n);
	oe = &oev->elements[0];

	g_assert(RE_TYPE_OR == oe->type);

	/*
	 * Strip leading string from all the initial elements in
	 * the alternatives.
	 */

	PSLIST_FOREACH(re_element_get_alt(oe), sl) {
		re_elemvec_t *ev = sl->data;
		re_elemvec_check(ev);
		re_element_strip_lead(&ev->elements[0], lead, ev, 0);
	}

	/* The leading TEXT/CHAR element we extracted */

	if (1 == str_len(lead)) {
		if (is_ascii_alpha(str_at(lead, 0)))
			tetype = RE_TYPE_CHAR;
		else {
			tetype = RE_TYPE_CHAR;
			icase = FALSE;
		}
	} else
		tetype = RE_TYPE_TEXT;

	/* Insert lead before the OR in the new GROUP */

	te = re_elemvec_insert_element(oev, 0, tetype, icase);
	te->inserted = TRUE;
	if (1 == str_len(lead)) {
		te->u.c = str_at(lead, 0);
		te->minlen = te->maxlen = 1;
	} else {
		re_element_replace_text(te, lead);
	}
}

/**
 * Free up the element vectors for the OR alternatives.
 *
 * @return TRUE if an empty branch was listed before any other.
 */
static bool
re_simplify_free_alternatives(re_element_t *e)
{
	bool first_was_empty = FALSE;

	pslist_t *alt, *sl;

	g_assert(RE_TYPE_OR == e->type);

	alt = re_element_get_alt(e);

	/*
	 * Detecting whether the first branch was empty lets us optimize
	 * things like "|a" and "a|" differently: the first is generating
	 * a lazy alternative, whilst the second will be greedy.
	 */

	if (alt != NULL) {
		re_elemvec_t *aev = alt->data;
		if (0 == aev->ecnt)
			first_was_empty = TRUE;
	}

	PSLIST_FOREACH(alt, sl) {
		re_elemvec_t *aev = sl->data;
		re_elemvec_recursive_free(aev);
	}

	pslist_free(alt);

	return first_was_empty;
}

/**
 * Replace the whole OR block with a character class element.
 *
 * @param rev		the element vector where the OR node resides
 * @param n			the index within `rev' for the OR node.
 * @param class		where the characters that make-up the class are listed
 */
static void
re_simplify_with_class(re_elemvec_t *rev, size_t n, str_t *class)
{
	re_element_t *e = &rev->elements[n];
	size_t min, max;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(RE_TYPE_OR == rev->elements[n].type);

	re_simplify_free_alternatives(e);
	min = re_element_get_repeat_min(e);
	max = re_element_get_repeat_max(e);

	/*
	 * re_install_class() expects an unexpanded element unless there are
	 * special classes.  Which we don't have here.
	 *
	 * So we unexpand the element before re-instating the min/max repetition,
	 * which may expand it again if necessary.
	 */

	re_unexpand_element(e);
	e->type = RE_TYPE_CLASS;
	re_install_class(e, class);
	re_element_set_repeat(e, min, max);
}

/**
 * Add look-ahead assertion before the OR node.
 *
 * @param rev	the element vector where the OR node resides
 * @param n		the index within `rev' for the OR node.
 * @param t		the trie describing all the matching strings
 *
 * @return TRUE if we added a look-ahead.
 */
static bool
re_simplify_add_lookahead(re_elemvec_t *rev, size_t n, const trie_t *t)
{
	str_t *lead = str_new(0), *class = str_new(0);
	bool added;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(RE_TYPE_OR == rev->elements[n].type);

	re_simplify_extract_lead_class(t, lead, class);
	added = re_simplify_insert_lookahead(rev, n, lead, class);

	str_destroy_null(&lead);
	str_destroy_null(&class);

	return added;
}

/**
 * Attempt to factorize common leading string out of the OR node, or
 * reduce the OR node to a single character class.
 *
 * For instance, "a|b|c|d" can become "[a-d]" and "foobar|footar" can
 * become "foo(?:bar|tar)".
 *
 * @param rev		the element vector where the OR node resides
 * @param n			the index within `rev' for the OR node.
 * @param t			the trie describing all the matching strings
 * @param icase		was regular expression compiled case-insensitively?
 * @param single	were all the alternatives made of a single element?
 *
 * @return TRUE if we altered the regex tree.
 */
static bool
re_simplify_factorize(
	re_elemvec_t *rev, size_t n, trie_t *t, bool icase, bool single)
{
	str_t *lead = str_new(0), *class = str_new(0);
	bool factorized = FALSE;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(RE_TYPE_OR == rev->elements[n].type);

	re_simplify_extract_lead_class(t, lead, class);

	/*
	 * If we have a lead string, install a previous TEXT element
	 * in front of the OR.  This is an optimization that we want to
	 * appear when we dump the regular expression, hence the new element
	 * is not flagged as "extra" and we need to make sure the OR is
	 * put inside a non-capturing group to preserve precedence.
	 *
	 * Then we need to strip that common leading string from all the
	 * leading TEXT/CHAR elements of the OR.
	 */

	if (str_len(lead) != 0) {
		re_simplify_factorize_lead(rev, n, lead, icase);
		factorized = TRUE;
		goto done;
	}

	/*
	 * If we have a class, look whether we have an alternative made of single
	 * elements with the trie depth being 1 (its depth is the length of the
	 * longest string we inserted into it).  If it is, then we can replace
	 * the whole OR by a single character class element.
	 */

	if (str_len(class) != 0) {
		if (single && 1 == trie_depth(t)) {
			re_simplify_with_class(rev, n, class);
			factorized = TRUE;
		}
	}

	/* FALL THROUGH */

done:
	str_destroy_null(&lead);
	str_destroy_null(&class);

	return factorized;
}

struct re_simplify_insert_ctx {
	trie_t *t;			/* Trie into which insertion must happen */
	re_elemvec_t *aev;	/* Original element vector */
	bool duplicate;		/* Did we detect duplicates? */
};

static void
re_simplify_insert_kv(const void *key, void *value, void *data)
{
	const char *string = key;
	struct re_simplify_insert_ctx *ctx = data;
	re_elemvec_t *ev = value;

	re_elemvec_check(ev);

	if (!trie_insert_value(ctx->t, string, ev))
		ctx->duplicate = TRUE;
}

static void
re_simplify_insert_k(void *key, void *data)
{
	const char *string = key;
	struct re_simplify_insert_ctx *ctx = data;

	if (!trie_insert_value(ctx->t, string, ctx->aev))
		ctx->duplicate = TRUE;
}

/**
 * Add element char/text/class to the trie, associated with the element vector
 * to which the element belongs to.
 *
 * @param t		the trie to which we are inserting
 * @param ae	the alternative leading element char or text
 * @param aev	the vector to which `ae' belongs to
 *
 * @return TRUE if we were able to insert the value, FALSE if it superseded
 * another value already present for that key
 */
static bool
re_simplify_insert(trie_t *t, const re_element_t *ae, re_elemvec_t *aev)
{
	const char *key;
	char buf[2];
	bool inverted, duplicate;

	re_elemvec_check(aev);

	if (re_element_is_char(ae)) {
		buf[0] = re_element_get_char(ae);
		buf[1] = '\0';
		key = buf;		/* The trie does not store the string */
	} else if (re_element_is_text(ae)) {
		key = re_element_get_text(ae);
	} else if (re_element_is_class(ae)) {
		goto class_element;
	} else if (re_element_is_hardwired_class(ae)) {
		goto hardwired_class_element;
	} else if (re_element_is_posix_class(ae)) {
		goto posix_class_element;
	} else if (re_element_is_trie(ae)) {
		goto trie_element;
	} else if (RE_TYPE_EMPTY == ae->type) {
		buf[0] = '\0';
		key = buf;		/* The trie does not store the string */
	} else {
		s_error("%s(): unexpected element %s", G_STRFUNC, re_elem_info(ae));
	}

	return trie_insert_value(t, key, aev);

class_element:

	inverted = duplicate = FALSE;
	buf[1] = '\0';

	switch (ae->type) {
	case RE_TYPE_INV_CLASS:
		inverted = TRUE;
		/* FALL THROUGH */
	case RE_TYPE_CLASS:
		{
			int c;
			const re_class_t *b = re_element_get_class(ae);

			/* We skip the NUL byte */
			for (c = 1; c < RE_ALPHABET; c++) {
				bool ok = re_class_belongs(b, c);

				/*
				 * If no match, look at the additional hardwired classes
				 *
				 * FIXME: really need to expand these into the bit array!
				 */

				if (!ok && re_element_is_expanded(ae)) {
					uint i;

					for (i = 0; i < RE_CLASS_POSIX_START && !ok; i++) {
						if (ae->u.other->v.classes & (1U << i)) {
							ok = (*re_hardwired[i])(c);
						}
					}
				}
				if (inverted) ok = !ok;		/* Inverted class? */
				if (ok) {
					buf[0] = c;
					if (!trie_insert_value(t, buf, aev))
						duplicate = TRUE;
				}
			}
		}
		break;
	case RE_TYPE_INV_CLASS_MM:
		inverted = TRUE;
		/* FALL THROUGH */
	case RE_TYPE_CLASS_MM:
		{
			int c, min, max;

			re_minmax_decode(re_element_get_minmax(ae), &min, &max);

			/* We skip the NUL byte */
			for (c = 1; c < RE_ALPHABET; c++) {
				bool ok = c >= min && c <= max;
				if (inverted) ok = !ok;
				if (ok) {
					buf[0] = c;
					if (!trie_insert_value(t, buf, aev))
						duplicate = TRUE;
				}
			}
		}
		break;
	}

	return !duplicate;

hardwired_class_element:
	buf[1] = '\0';
	duplicate = FALSE;

	{
		int c;
		re_class_check_t matcher = re_hard_class_matcher(ae->type);

		for (c = 1; c < RE_ALPHABET; c++) {
			if ((*matcher)(c)) {
				buf[0] = c;
				if (!trie_insert_value(t, buf, aev))
					duplicate = TRUE;
			}
		}
	}

	return !duplicate;

posix_class_element:
	buf[1] = '\0';
	duplicate = FALSE;
	inverted = re_element_is_inverted_posix(ae);

	{
		int c;
		uint classes = re_element_get_classes(ae);

		for (c = 1; c < RE_ALPHABET; c++) {
			size_t i;
			bool ok = FALSE;

			for (i = RE_CLASS_POSIX_START; i <= RE_CLASS_POSIX_END; i++) {
				if (0 == ((1U < i) & classes))
					continue;
				g_assert(i < N_ITEMS(re_hardwired));
				if ((*re_hardwired[i])(c)) {
					ok = TRUE;
					break;
				}
			}
			if (inverted) ok = !ok;
			if (ok) {
				buf[0] = c;
				if (!trie_insert_value(t, buf, aev))
					duplicate = TRUE;
			}
		}
	}

	return !duplicate;

trie_element:
	/*
	 * MATCHX elements do not hold values.
	 * MATCH elements hold empty element vectors at this stage (no NEXT yet)
	 * that do not require to be preserved.
	 *
	 * ROUTE(X) elements hold element vector values that must be preserved.
	 */

	{
		trie_t *at = re_element_get_trie(ae);
		struct re_simplify_insert_ctx ctx;

		ZERO(&ctx);
		ctx.t = t;
		ctx.aev = aev;

		if (re_element_is_traversable_trie(ae)) {
			trie_foreach_value(at, re_simplify_insert_kv, &ctx);
		} else {
			trie_foreach(at, re_simplify_insert_k, &ctx);
		}

		duplicate = ctx.duplicate;
	}

	return !duplicate;
}

/**
 * Transform element into a character class, as defined by the set of
 * arcs that match on the trie root node.
 *
 * @param e			the element to mutate
 * @param t			the trie
 * @param lazy		whether to turn lazy matching on
 */
static void
re_simplify_mutate_class(re_element_t *e, trie_t *t, bool lazy)
{
	str_t *s = str_new(0);
	const trie_node_t *root = trie_root(t);
	int c;

	g_assert(trie_depth(t) <= 1);
	g_assert(RE_TYPE_OR == e->type);
	g_assert(!re_element_is_expanded(e));

	for (c = 0; c < RE_ALPHABET; c++) {
		if (NULL != trie_node_child(root, c))
			str_putc(s, c);
	}

	/*
	 * When the root node of the trie matches, then the class can match
	 * the empty string.  Just make it optional (at most one match) so
	 * that it can match that empty string.
	 *
	 * @note
	 * That optimization makes it more likely for the execution engine
	 * to match the class if it can, and therefore can lead patterns
	 * such as "ab|abc" to match "abc".
	 */

	if (trie_node_is_match(root))
		e->repeat = RE_N_AT_MOST_ONE;

	trie_free(t);

	e->type = RE_TYPE_CLASS;
	if (lazy) e->minimal = TRUE;
	re_install_class(e, s);
	str_destroy_null(&s);
}

/**
 * Entry traversal callback for trie to spot partial matches.
 */
static bool
re_simplify_trie_locate_partial(const trie_context_t *ctx, void *udata)
{
	bool *partial = udata;

	if (*partial)
		return FALSE;	/* Prune traversal as soon as we know */

	if (trie_node_is_match(ctx->node) && !trie_node_is_leaf(ctx->node)) {
		*partial = TRUE;
		return FALSE;
	}

	return TRUE;	/* Traverse further */
}

/**
 * Check whether trie has partial matches (matches before leaf nodes).
 *
 * @return TRUE if we have partial matches.
 */
static bool
re_simplify_trie_has_partial(const trie_t *t)
{
	bool partial = FALSE;

	trie_traverse(deconstify_pointer(t), TRIE_TRAVERSE_ALL,
		re_simplify_trie_locate_partial, NULL, &partial);

	return partial;
}

/**
 * Trie traversal callback to install a shared empty element vector as value
 * for each matching point in the trie.
 */
static void
re_simplify_trie_install_vector(const trie_context_t *ctx, void *udata)
{
	trie_node_t *tn = deconstify_pointer(ctx->node);
	re_elemvec_t *shared_ev = udata;

	g_assert(trie_node_is_match(tn));
	re_elemvec_check(shared_ev);

	/*
	 * Set our shared element vector for the matching point.
	 * This vector will only contain a NEXT element added
	 * during linearization.
	 */

	trie_node_set_value(tn, shared_ev);
}

/**
 * Mutate the OR element with one alternative as a GROUP group.
 */
static void
re_simplify_mutate_group(re_element_t *e)
{
	pslist_t *alt;

	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	alt = re_element_get_alt(e);

	g_assert(1 == pslist_length(alt));

	e->type = RE_TYPE_GROUP;
	re_element_set_sub(e, alt->data);	/* Fetch element vector */
	pslist_free(alt);
}

/**
 * Mutate OR element with just one alternative.
 */
static void
re_simplify_or_if_single(re_element_t *e)
{
	pslist_t *alt;

	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	alt = re_element_get_alt(e);
	g_assert(alt != NULL);

	if (NULL == pslist_next(alt))		/* Only one cell in list: the head */
		re_simplify_mutate_group(e);
}

/**
 * Prune empty OR branches if all other branches can match the empty string.
 */
static void
re_prune_empty_or_branches_maybe(re_element_t *e)
{
	pslist_t *alt;
	bool has_empty = FALSE;
	bool match_empty = TRUE;
	bool could_force_zero_min = TRUE;
	size_t alt_count = 0, non_empty_alt = 0;

	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	/*
	 * First pass: see whether we have an empty alternative and
	 * whether the other alternatives cannot match the empty string.
	 */

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		re_elemvec_t *aev = pslist_data(alt);
		bool all_match_empty = TRUE;
		size_t i;
		const re_element_t *ae = &aev->elements[0];

		alt_count++;

		if (0 == aev->ecnt) {
			has_empty = TRUE;
			continue;
		}

		non_empty_alt++;

		if (
			aev->ecnt > 1 ||
			re_element_get_repeat_min(ae) > 1 ||
			RE_TYPE_SUBN == ae->type	/* These are numbered! */
		)
			could_force_zero_min = FALSE;	/* See below! */

		/*
		 * If all the items in the alternative do not already match
		 * the empty string, then we will not be able to strip the
		 * empty branch, unless `could_force_zero_min' remains TRUE.
		 */

		for (i = 0; i < aev->ecnt; i++) {
			if (0 != re_element_get_repeat_min(&aev->elements[i])) {
				all_match_empty = FALSE;
				break;
			}
		}

		if (!all_match_empty)
			match_empty = FALSE;
	}

	/*
	 * If there is just a single alternative left, no worries, it will
	 * be pruned later.  However, we do not want to prune the only
	 * empty alternative at this stage.
	 */

	if (!has_empty || 1 == alt_count)
		return;

	/*
	 * There is no sense turning "ax|(?:bx|.)|" into ""(?:ax)?|(?:bx)?|.?"
	 * just to suppress the final empty branch!  This will be less
	 * efficient at runtime.
	 *
	 * So if we have more than one non-empty alternative where the
	 * element repeated is not identical (e.g. "a+|a*|"), then do not
	 * bother.
	 */

	if (non_empty_alt > 1 && could_force_zero_min) {
		const re_element_t *first = NULL;

		PSLIST_FOREACH(re_element_get_alt(e), alt) {
			re_elemvec_t *aev = pslist_data(alt);
			const re_element_t *ae = &aev->elements[0];

			if (0 == aev->ecnt)
				continue;

			if (NULL == first) {
				first = ae;
				continue;
			}

			/*
			 * Shallow comparison because we do not care about
			 * repetition counts here.
			 */

			if (!re_element_shallow_equal(ae, first)) {
				could_force_zero_min = FALSE;
				break;
			}
		}
	}

	/*
	 * If the other alternatives do not all match the empty string, but
	 * we still have could_force_zero_min set to TRUE, then we can set
	 * the minimum repetition to 0 to the elements in all the alternatives
	 * and then get rid of the empty alternative.
	 */

	if (!match_empty && !could_force_zero_min)
		return;

	if (could_force_zero_min) {
		PSLIST_FOREACH(re_element_get_alt(e), alt) {
			re_elemvec_t *aev = pslist_data(alt);
			re_element_t *ae;
			size_t min, max;

			if (0 == aev->ecnt)
				continue;

			/* By choice in first pass */
			g_assert_log(1 == aev->ecnt,
				"%s(): aev->ecnt=%zu, aev: %s in %s",
				G_STRFUNC, aev->ecnt, re_elemvec_info(aev), re_elem_info(e));

			ae = &aev->elements[0];
			min = re_element_get_repeat_min(ae);
			max = re_element_get_repeat_max(ae);

			g_assert(min <= 1);			/* By choice in first pass */

			/*
			 * We have a single element in all the alternatives that are
			 * not empty, and they can match at minimum zero time or once.
			 *
			 * If it can match once or more (+), then it can be
			 * safely set to match zero time or more (*) without changing
			 * the pattern matching set.
			 *
			 * Then we will be able to strip every empty alternatives
			 * from the OR.
			 */

			if (1 == min)
				re_element_set_repeat(ae, 0, max);
		}
	}

	/*
	 * Loop again to strip the empty alternative(s).
	 *
	 * @note
	 * There can be multiple empty alternatives because we have not
	 * stripped identical branches from the OR elements at this stage.
	 */

again:
	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		re_elemvec_t *aev = pslist_data(alt);

		if (0 == aev->ecnt) {
			alt = re_element_get_alt(e);
			alt = pslist_remove(alt, aev);
			re_elemvec_free(aev);			/* Was empty, no need to cleanup */

			if (alt != re_element_get_alt(e))
				re_element_set_alt(e, alt);	/* Removal changed the head */

			goto again;		/* We may have more empty branches to prune */
		}
	}
}

/**
 * Mutate the OR element into a MATCH/MATCHX node, as appropriate.
 *
 * This is only applicable to alternatives with simple text, such
 * as "ax|bc" and not expressions like "ax.*|bc+" (those require a
 * ROUTE/ROUTEX instead).
 *
 * @note
 * The given trie `t' is either discarded or captured as part of the
 * trie-matching node created.
 *
 * @param rev		element vector where OR element lies
 * @param n			position in the element vector
 * @param t			the trie of the various alternatives to match
 */
static void
re_simplify_mutate_match(re_elemvec_t *rev, size_t n, trie_t *t)
{
	bool partial = re_simplify_trie_has_partial(t);
	bool first_was_empty;
	re_element_t *e = &rev->elements[n];
	re_elem_type_t type;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(RE_TYPE_OR == e->type);

	first_was_empty = re_simplify_free_alternatives(e);

	/*
	 * Detect trie of depth <=1 that can be converted into a character class.
	 */

	if (trie_depth(t) <= 1) {
		re_simplify_mutate_class(e, t, first_was_empty);
		return;
	}

	/*
	 * Create a trie-matching node.
	 */

	type = partial ? RE_TYPE_MATCH : RE_TYPE_MATCHX;

	e->type  = type;
	re_element_set_trie(e, t);

	/*
	 * Partial-matching tries require traversal of the regular
	 * expression until the end, to be able to validate that an
	 * alternative choice is the right one causing the pattern
	 * to match against the text.
	 *
	 * If a particular choice does not cause the regex to match,
	 * we need to backtrack to another choice, and only then can
	 * we know that either no choice works, or that we select one
	 * of the choices we can make to cause a match.
	 *
	 * The MATCHX tries are fully deterministic, hence they do
	 * not require any element vector (populated by NEXT elements
	 * during linearization): either they match the input, or they
	 * don't, but there are no choice to make between alternatives
	 * because there is no valid match until we reach a leaf node.
	 */

	if (partial) {
		re_elemvec_t *shared_ev = re_elemvec_alloc(1);
		trie_traverse(t, TRIE_TRAVERSE_MATCHING,
			NULL, re_simplify_trie_install_vector, shared_ev);
	} else {
		trie_discard_values(t);		/* Don't need the values */
	}
}

struct re_simplify_trie_values_ctx {
	const trie_t *t;
	hset_t *seen;
	hset_t *identical;
};

/**
 * Trie iterator callback to share common element vectors.
 */
static void
re_simplify_trie_values(const void *key, void *value, void *data)
{
	struct re_simplify_trie_values_ctx *ctx = data;
	re_elemvec_t *ev;

	re_elemvec_check(value);

	/*
	 * We make sure the vector was not physically processed already.
	 *
	 * If it was, then we are physically sharing common vectors, and
	 * therefore we have nothing to do here since sharing is already
	 * done for that vector.
	 */

	if (hset_contains(ctx->identical, value))
		return;		/* Guards against physically shared vectors */

	hset_insert(ctx->identical, value);

	ev = hset_lookup(ctx->seen, value);
	if (NULL == ev) {
		hset_insert(ctx->seen, value);
	} else {
		const trie_node_t *tn = trie_node(ctx->t, key);

		g_assert(tn != NULL);
		g_assert(value == trie_node_value(tn));

		/* Share existing similar vector, discard current node value */
		trie_node_set_value(deconstify_pointer(tn), ev);
		re_elemvec_recursive_free(value);
	}
}

/**
 * Mutate the OR element into a ROUTE/ROUTEX node, as appropriate.
 *
 * This is applicable to alternatives with expressions like
 * "ax.*|bc+" where the trie will be used to match the leading
 * constants and then control will be passed to the remaining
 * element vector.
 *
 * @param rev		element vector where OR element lies
 * @param n			position in the element vector
 * @param t			the trie of the various alternatives to match
 */
static void
re_simplify_mutate_route(re_elemvec_t *rev, size_t n, trie_t *t)
{
	bool partial = re_simplify_trie_has_partial(t);
	re_element_t *e = &rev->elements[n];
	re_elem_type_t type;
	pslist_t *alt, *sl;
	struct re_simplify_trie_values_ctx ctx;

	re_elemvec_check(rev);
	g_assert(n < rev->ecnt);
	g_assert(RE_TYPE_OR == e->type);

	type = partial ? RE_TYPE_ROUTE : RE_TYPE_ROUTEX;

	/*
	 * The trie values refer to the remaining element vectors in
	 * the alternative, once the constant part has been matched.
	 *
	 * We simply need to remove the first element of each alternative,
	 * as it is already being matched by the trie.  Note that there may
	 * be no element in the vector when it was originally empty (i.e. the
	 * empty string matches the vector).
	 */

	alt = re_element_get_alt(e);

	PSLIST_FOREACH(alt, sl) {
		re_elemvec_t *aev = sl->data;
		re_elemvec_check(aev);
		if (aev->ecnt != 0)
			re_elemvec_remove_element(aev, 0);
	}

	pslist_free(alt);	/* Free the cells, vectors are now trie values */

	e->type = type;
	re_element_set_trie(e, t);

	/*
	 * See whether remaining OR vectors (now trie values) are identical, and
	 * share them in that case.
	 */

	ZERO(&ctx);
	ctx.t         = t;
	ctx.seen      = hset_create_any(re_elemvec_h, NULL, re_deep_eq);
	ctx.identical = hset_create(HASH_KEY_SELF, 0);

	trie_foreach_value(t, re_simplify_trie_values, &ctx);

	hset_free_null(&ctx.seen);
	hset_free_null(&ctx.identical);
}

/**
 * Cleanup an empty OR element and mutate it into an EMPTY one.
 *
 * @param rev	element vector where OR element lies
 * @param n		position in the element vector
 */
static void
re_empty_or(re_elemvec_t *rev, size_t n)
{
	re_element_t *e = &rev->elements[n];

	re_elemvec_check(rev);
	g_assert(RE_TYPE_OR == e->type);

	re_simplify_free_alternatives(e);
	e->type = RE_TYPE_EMPTY;
}

/**
 * Hash set foreach callback to remove element vector from the set of
 * alternatives in the OR element.
 */
static void
re_prune_identical_or(const void *data, void *udata)
{
	re_elemvec_t *rev = deconstify_pointer(data);
	re_element_t *e = udata;

	re_elemvec_check(rev);
	g_assert(RE_TYPE_OR == e->type);

	e->u.alt = pslist_remove(e->u.alt, rev);
	re_elemvec_recursive_free(rev);
}

/**
 * Prune identical branches out of OR element.
 */
static void
re_prune_identical_or_branches(re_elemvec_t *rev, size_t n)
{
	re_element_t *e = &rev->elements[n];
	hset_t *identical, *seen;
	pslist_t *alt;

	re_elemvec_check(rev);
	g_assert(RE_TYPE_OR == e->type);

	seen      = hset_create_any(re_elemvec_h, NULL, re_deep_eq);
	identical = hset_create(HASH_KEY_SELF, 0);

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		re_elemvec_t *aev = alt->data;
		if (hset_contains(seen, aev))
			hset_insert(identical, aev);
		else
			hset_insert(seen, aev);
	}

	hset_foreach(identical, re_prune_identical_or, e);
	hset_free_null(&identical);
	hset_free_null(&seen);
}

/**
 * Extract common items for OR alternatives to factorize them out.
 *
 * @param rev	element vector where OR element lies
 * @param n		position in the element vector
 */
static void
re_extract_common_or(re_elemvec_t *rev, size_t n)
{
	re_elemvec_t *oev = NULL;		/* Element vector for the new OR group */
	re_element_t *oe;				/* OR element in new vector */
	size_t on;						/* OR index in `oev' */
	re_element_t *e = &rev->elements[n];

	re_elemvec_check(rev);
	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	/*
	 * First pass -- deal with common elements at the head.
	 */

	for (oe = e, on = n; /* empty */; /* empty */) {
		pslist_t *alt;
		re_element_t *cae = NULL, *fe;
		bool is_first = TRUE;

		PSLIST_FOREACH(re_element_get_alt(oe), alt) {
			re_elemvec_t *aev = alt->data;
			re_element_t *ae;

			re_elemvec_check(aev);

			if (0 == aev->ecnt)
				goto head_done;		/* End of shortest vector */

			ae = &aev->elements[0];

			if (is_first) {
				cae = ae;
				is_first = FALSE;
				continue;
			}

			if (!re_element_deep_equal(ae, cae))
				goto head_done;
		}

		/*
		 * All items at position `0' in all alternatives are equal
		 *
		 * We can therefore factor this item out and remove it from all
		 * the alternatives.
		 */

		re_element_check(cae);

		if (NULL == oev) {
			/*
			 * Create encapsulating GROUP for the OR, transferring
			 * the repetition count of the OR to the GROUP.
			 *
			 * Items factored-out of the OR will lie in the GROUP,
			 * to retain proper precedence and overall matching repetition.
			 *
			 * Initially, the OR will be at slot 0 in the GROUP, but of
			 * course it will move as we prepend factored items in front of it.
			 */

			oev = re_encapsulate_or(rev, n);
			on = 0;
		}

		/* Factored element inserted before the OR */

		fe = re_elemvec_insert_element(oev, on++, cae->type, cae->icase);
		oe = &oev->elements[on];	/* New position for OR */
		is_first = TRUE;

		PSLIST_FOREACH(re_element_get_alt(oe), alt) {
			re_elemvec_t *aev = alt->data;
			re_element_t *ae;

			re_elemvec_check(aev);
			g_assert(aev->ecnt >= 1);

			ae = &aev->elements[0];

			if (is_first) {
				g_assert(ae == cae);
				*fe = *ae;	/* Struct copy */
				is_first = FALSE;
				re_elemvec_strip_element(aev, 0);	/* Was copied */
			} else {
				re_elemvec_remove_element(aev, 0);	/* Cleanup element */
			}
		}
	}

head_done:

	/*
	 * Second pass -- deal with common elements at the tail.
	 */

	for (;;) {
		pslist_t *alt;
		re_element_t *cae = NULL, *fe;
		bool is_first = TRUE;

		PSLIST_FOREACH(re_element_get_alt(oe), alt) {
			re_elemvec_t *aev = alt->data;
			re_element_t *ae;

			re_elemvec_check(aev);

			if (0 == aev->ecnt)
				goto tail_done;		/* End of shortest vector */

			ae = &aev->elements[aev->ecnt - 1];

			if (is_first) {
				cae = ae;
				is_first = FALSE;
				continue;
			}

			if (!re_element_deep_equal(ae, cae))
				goto tail_done;
		}

		/*
		 * All items at the final position in all alternatives are equal
		 *
		 * We can therefore factor this item out and remove it from all
		 * the alternatives.
		 */

		re_element_check(cae);

		if (NULL == oev) {
			/*
			 * Create encapsulating GROUP for the OR, transferring
			 * the repetition count of the OR to the GROUP.
			 *
			 * Items factored-out of the OR will lie in the GROUP,
			 * to retain proper precedence and overall matching repetition.
			 *
			 * Initially, the OR will be at slot 0 in the GROUP, but of
			 * course it will move as we prepend factored items in front of it.
			 */

			oev = re_encapsulate_or(rev, n);
			on = 0;
			oe = &oev->elements[on];	/* New position for OR */
		}

		/* Factored element inserted after the OR */

		fe = re_elemvec_insert_element(oev, on + 1, cae->type, cae->icase);
		is_first = TRUE;

		PSLIST_FOREACH(re_element_get_alt(oe), alt) {
			re_elemvec_t *aev = alt->data;
			re_element_t *ae;
			size_t idx;

			re_elemvec_check(aev);
			g_assert(aev->ecnt >= 1);

			idx = aev->ecnt - 1;
			ae = &aev->elements[idx];

			if (is_first) {
				g_assert(ae == cae);
				*fe = *ae;	/* Struct copy */
				is_first = FALSE;
				re_elemvec_strip_element(aev, idx);		/* Was copied */
			} else {
				re_elemvec_remove_element(aev, idx);	/* Cleanup element */
			}
		}
	}

tail_done:
	return;
}

/**
 * Absorb sub OR blocks into parent OR if possible.
 *
 * @param rev	element vector where OR element lies
 * @param n		position in the element vector
 */
static void
re_absorb_or_up(re_elemvec_t *rev, size_t n)
{
	re_element_t *e = &rev->elements[n];
	pslist_t *alt;

	re_elemvec_check(rev);
	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

#if 0
#define RE_DEBUG_ABSORB_OR_UP
#endif

#ifdef RE_DEBUG_ABSORB_OR_UP
#define re_debug(...)	s_debug(__VA_ARGS__);
#else
#define re_debug(...)	{}
#endif

	re_debug("%s(): processing %s", G_STRFUNC, re_elem_info(e));

again:
	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		re_elemvec_t *aev = alt->data;
		re_element_t *ae;

		re_elemvec_check(aev);

		re_debug("%s(): at ALT %s", G_STRFUNC, re_elemvec_info(aev));

		if (0 == aev->ecnt)
			continue;

		ae = &aev->elements[0];

		/*
		 * An alternative of our OR is another OR.
		 *
		 * If it is only a single item in its element vector and
		 * its repetition count is one, then we can include all
		 * its branches within the scope of the OR we are simplifying.
		 *
		 * This will allow more optimisations to be performed within
		 * the context of this parent.
		 */

		if (
				!ae->atomic &&
				RE_TYPE_OR == ae->type &&
				RE_N_ONCE == ae->repeat &&
				1 == aev->ecnt
		) {
			pslist_t *nalt;
			long pos;

			re_debug("%s(): extracting sub OR %s",
				G_STRFUNC, re_elemvec_info(aev));

			nalt = pslist_concat_after(
					re_element_get_alt(e), alt, re_element_get_alt(ae));
			pos = pslist_position(nalt, alt);
			g_assert(pos != -1L);			/* Current still in list */
			nalt = pslist_remove(nalt, aev);/* Removes current element */
			re_element_set_alt(ae, NULL);	/* Stole its list */
			re_elemvec_cleanup_free(aev);	/* Must cleanup OR element */
			re_element_set_alt(e, nalt);

			/*
			 * We added new items *after* the current element, but we
			 * have also *removed* the current element from the list.
			 * We have to start again if position was 0, but otherwise
			 * we just need to reposition `alt' one location before
			 * and then can simply continue looping.
			 */

			if G_UNLIKELY(0 == pos)
				goto again;
			else {
				alt = pslist_nth(nalt, pos - 1);
				continue;
			}
		}
	}

#undef re_debug
}

/**
 * Simplify OR element.
 *
 * @param rev	element vector where OR element lies
 * @param n		position in the element vector
 * @param icase	whether regular expression was compiled case-insensitively
 *
 * @return TRUE if we altered the OR statement.
 */
static bool
re_simplify_or(re_elemvec_t *rev, size_t n, bool icase)
{
	re_element_t *e = &rev->elements[n];
	size_t alt_count, selected_count, once_count, empty_count;
	pslist_t *alt;
	trie_t *t;
	bool duplicate = FALSE, single = TRUE, altered = FALSE;

	re_elemvec_check(rev);
	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

#if 0
#define RE_DEBUG_SIMPLIFY_OR
#endif

#ifdef RE_DEBUG_SIMPLIFY_OR
#define re_debug(...)	s_debug(__VA_ARGS__);
#else
#define re_debug(...)	{}
#endif

	re_debug("%s(): processing %s", G_STRFUNC, re_elem_info(e));

	/*
	 * Collect all the alternatives which start with a CHAR or TEXT element
	 * and insert that text in a trie.
	 */

	t = trie_create();
	alt_count = selected_count = once_count = empty_count = 0;

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		re_elemvec_t *aev = alt->data;

		re_elemvec_check(aev);

		re_debug("%s(): at ALT %s", G_STRFUNC, re_elemvec_info(aev));

		alt_count++;

		/*
		 * We must special-case routing tries, which appear as being
		 * one element but are really acting as the head of multiple
		 * element vectors.
		 *
		 * Empty element vectors are treated below as matching the empty
		 * string, and are assumed to be "once" matches, as well as being
		 * single elements (it is as if the EMPTY element was present).
		 */

		if (
			aev->ecnt > 1 ||
			(1 == aev->ecnt && re_element_is_routing_trie(&aev->elements[0]))
		)
			single = FALSE;

		if (aev->ecnt != 0) {
			re_element_t *ae = &aev->elements[0];
			bool selected = FALSE, is_group = FALSE;

			if (re_element_is_group(ae)) {
				re_elemvec_t *gev = re_element_get_sub(ae);

				if (ae->atomic)
					continue;		/* Must leave atomic groups alone */

				/*
				 * Probe first group element.
				 * This will be only used for creating a look-ahead assertion.
				 */

				if (gev->ecnt != 0) {
					is_group = TRUE;
					/* Descend in the group, fetching its first element */
					aev = re_element_get_sub(ae);
					ae = &aev->elements[0];
				}
			}

			/*
			 * If an item can be missing, it cannot be used to establish
			 * a look-ahead string.
			 */

			if (0 == re_element_get_repeat_min(ae))
				continue;

			/*
			 * FIXME:
			 * We can't include POSIX classes in our list here because
			 * we currently do not expand them to the RE_ALPHABET range.
			 * Need to change that and expand them.
			 */

			if (
				re_element_is_text(ae) ||
				re_element_is_char(ae) ||
				re_element_is_class(ae) ||
				re_element_is_hardwired_class(ae) ||
				RE_TYPE_EMPTY == ae->type
			) {
				selected = TRUE;
			} else if (re_element_is_trie(ae)) {
				if (ae->atomic)
					continue;	/* Must leave optimized atomic OR alone */
				selected = TRUE;
			}

			if (selected) {
				selected_count++;
				if (!re_simplify_insert(t, ae, aev))
					duplicate = TRUE;
				/*
				 * By not incrementing once_count for the group,
				 * we're forcing the creation of a look-ahead only.
				 */
				if (RE_N_ONCE == ae->repeat && !is_group)
					once_count++;
			}
		} else {
			/* Empty vector */
			selected_count++;
			once_count++;
			empty_count++;
			if (!trie_insert_value(t, "", aev))
				duplicate = TRUE;
		}
	}

	re_debug("%s(%p, %zu, %s):"
		"alt_count=%zu, selected_count=%zu, empty_count=%zu, "
		"once_count=%zu, duplicate=%d, single=%d",
		G_STRFUNC, rev, n, bool_to_string(icase),
		alt_count, selected_count, empty_count,
		once_count, duplicate, single);

	/*
	 * If all the vectors corresponding to each alternative are empty,
	 * then we can remove the OR element and free-up all these vectors.
	 */

	if (alt_count == empty_count) {
		re_empty_or(rev, n);
		altered = TRUE;
		goto done;
	}

	/*
	 * If only one alternative after pruning of identical paths,
	 * we can mutate the OR node into a GROUP node.
	 */

	if (1 == alt_count) {
		re_simplify_mutate_group(e);
		altered = TRUE;
		goto done;
	}

	/*
	 * No optimization possible if we did not find any text/char at the start
	 * of the alternatives.
	 */

	if (0 == selected_count)
		goto done;

	/*
	 * For now, if we did not select all the OR paths, do not optimize.
	 */

	if (selected_count != alt_count)
		goto done;

	/*
	 * If all the items in the OR were not with a repeat count of ONCE,
	 * then install a lookahead assertion.
	 */

	if (selected_count != once_count) {
		altered = re_simplify_add_lookahead(rev, n, t);

		re_debug("%s(): %s look-ahead (duplicate=%s)",
			G_STRFUNC, altered ? "added" : "could not add",
			bool_to_string(duplicate));

		if (altered)
			re_debug("%s(): new %s", G_STRFUNC, re_elem_info(&rev->elements[n]));

		goto done;
	}

	/*
	 * Factorize what we can.
	 *
	 * This may transform the compiled regex tree and if it does, then
	 * abort processing for now: the added children nodes will be processed
	 * later by the traversal to finish the job.
	 */

	if (re_simplify_factorize(rev, n, t, icase, single)) {
		altered = TRUE;
		goto done;
	}

	g_assert (RE_TYPE_OR == rev->elements[n].type);

	/*
	 * Nothing can be factorized in the alternatives.
	 *
	 * If we have single text, we can create a MATCH node to perform
	 * the match with the trie instead of with the classic alternative
	 * code. If there are no partial matches in the trie, this is even
	 * better: we can create a MATCHX (X for eXact) node that will not
	 * require any recursion at runtime.
	 *
	 * Note that for single text, we do not care about duplicates: they
	 * will simply match.  For instance, "ax|bc|ax|cd" will simply match
	 * for "ax" if present.
	 */

	if (single) {
		/* Will free-up trie or capture it */
		re_simplify_mutate_match(rev, n, t);
		goto simplified;
	}

	/*
	 * If we have no duplicates, we can simplify "[ab]2|[cd]3" with
	 * a ROUTEX node.  However if there are duplicates, limit to a
	 * look-ahead assertion.
	 */

	if (duplicate) {
		altered = re_simplify_add_lookahead(rev, n, t);

		re_debug("%s(): %s look-ahead (has duplicates)", G_STRFUNC,
			altered ? "added" : "could not add");
		if (altered)
			re_debug("%s():new %s", G_STRFUNC, re_elem_info(&rev->elements[n]));
		goto done;		/* Cannot optimize with trie matching */
	}

	re_simplify_mutate_route(rev, n, t);

	/* FALL THROUGH */

simplified:
	re_debug("%s(): simplified as %s", G_STRFUNC, re_elem_info(e));
	return TRUE;

done:
	re_debug("%s(): altered=%s", G_STRFUNC, bool_to_string(altered));
	trie_free_null(&t);
	return altered;


#undef re_debug
}

/**
 * Traversal action callback for element vector to spot OR elements and
 * attempt to prune identical alternatives out of them.
 */
static void
re_prune_or_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (RE_TYPE_OR == e->type) {
			re_prune_empty_or_branches_maybe(e);

			/*
			 * If there were only empty branches in the OR, and they
			 * were all removed, we can just discard this element.
			 */

			if (NULL == re_element_get_alt(e)) {
				re_elemvec_remove_element(rev, i);
				i--;		/* Stay at same index */
				continue;
			}

			re_prune_identical_or_branches(rev, i);
			re_simplify_or_if_single(e);
		}
	}
}

/**
 * Prune identical alternatives from OR blocks.
 */
static void
re_prune_or_branches(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_prune_or_elements, NULL);
}

/**
 * Traversal action callback for element vector to spot OR elements and
 * attempt to merge sub OR blocks back into the parent OR to then better
 * optimize them.
 */
static void
re_absorb_or_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (RE_TYPE_OR == e->type) {
			re_absorb_or_up(rev, i);
		}
	}
}

/**
 * Move sub-OR groups to parent OR if possible.
 */
static void
re_absorb_or(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	/*
	 * We set pre_v to TRUE to be able to process parent OR before their
	 * children, which allows us to merge up sub-OR expressions and
	 * maximize the opportunities for leading factorization.
	 */

	re_traverse_once(re->u.compiled,
		FALSE,					/* pre_e */
		NULL,					/* enter */
		NULL,					/* action */
		TRUE,					/* pre_v -- handle parents first! */
		NULL,					/* venter */
		re_absorb_or_elements,	/* vaction */
		NULL);
}

struct re_handle_or_ctx {
	bool icase;
	bool altered;
};

/**
 * Traversal action callback for element vector to spot OR elements and
 * attempt to optimize them.
 */
static void
re_handle_or_elements(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;
	struct re_handle_or_ctx *ctx = udata;

	re_elemvec_check(rev);

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (RE_TYPE_OR == e->type) {
			if (re_simplify_or(rev, i, ctx->icase))
				ctx->altered = TRUE;
		}
	}
}

/**
 * Optimize OR blocks.
 *
 * This involves:
 * - factorizing a common leading string outside of the alternatives
 * - merging character classes
 * - organizing leading text into a trie for faster parsing, possibly
 *   fully deterministic when there are no partial matching.
 *
 * @return TRUE if we altered the regex tree
 */
static bool
re_optimize_or(re_regex_t *re)
{
	struct re_handle_or_ctx ctx;

	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	ZERO(&ctx);
	ctx.icase = re->icase;

	re_foreach_elemvec(re->u.compiled, re_handle_or_elements, &ctx);

	return ctx.altered;
}

/**
 * Linearise the representation by adding NEXT nodes so that we can process
 * the elements linearly whatever the starting element (i.e.  there is no
 * requirement to start at the root element vector.
 *
 * We use the linearization traversal to collect useful information about
 * the regular expression: whether it has wildcard matching, whether we
 * can extract a string that must be present in the text to obtain a match,
 * and whether we have constant text anchored at the end that we can quickly
 * check for.
 *
 * The existing tree structure is kept during this traversal.
 */
static void
re_linearize(re_regex_t *re)
{
	struct re_linearize_ctx linearize_ctx;

	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	/*
	 * Make the representation linear so that the regular expression matching
	 * engine can, from any point in the compiled graph, reach the remaining
	 * nodes that follow it.
	 */

	ZERO(&linearize_ctx);

	linearize_ctx.re = re;

	/*
	 * When we have back-references, we can compute their min/max matching
	 * lengths by keeping track of the SUBN element to which a given
	 * back-reference refers.
	 */

	if (re->backref_count != 0)
		linearize_ctx.subn = htable_create(HASH_KEY_SELF, 0);

	re_traverse_once(re->u.compiled,
		FALSE,					/* pre_e */
		re_linearize_entry,		/* enter */
		re_linearize_action,	/* action */
		FALSE,					/* pre_v */
		re_linearize_push,		/* venter */
		re_linearize_pop,		/* vaction */
		&linearize_ctx);

	/* Ensure callbacks have cleaned-up properly */
	g_assert(NULL == linearize_ctx.stack);
	g_assert(NULL == linearize_ctx.element);
	g_assert(NULL == linearize_ctx.capturing);

	htable_free_null(&linearize_ctx.subn);

	/*
	 * If patten has wildcard matching, it can involve a lot of backtracking
	 * and effort... For nothing if the pattern does not match.
	 *
	 * If we can identify a fixed text string or character that must be
	 * present, then store it so that we can pre-check the text.
	 */

	if (linearize_ctx.wildcard) {
		re_traverse_once(re->u.compiled,
			FALSE,					/* pre_e */
			re_find_longest_enter,	/* enter */
			re_find_longest,		/* action */
			FALSE,					/* pre_v */
			NULL,					/* venter */
			NULL,					/* vaction */
			&linearize_ctx);

		if (linearize_ctx.longest != NULL) {
			char * must = re_element_string_dup(linearize_ctx.longest);
			re->must = pattern_compile(must, re->icase);
			hfree(must);
		}
	}

	/*
	 * Now that we're done, shrink the element vectors as necessary so
	 * that no extra space is lost.
	 */

	re_foreach_elemvec(re->u.compiled, re_final_shrink, NULL);

	/*
	 * If we have only one single END marker in the pattern, parse its
	 * element vector to locate what comes before the END, so that we
	 * can pre-check that the text ends with that element right at
	 * the beginning.
	 */

	if (1 == linearize_ctx.has_end)
		re->end = re_finalize_ending_element(linearize_ctx.end_ev);
}

/**
 * Inline group, replacing the current group element in the element vector.
 *
 * @param ev	the element vector where we're inlining group
 * @param n		position of the group element initially
 * @param gev	the group element vector to inline in `ev'
 */
static void
re_inline_group(re_elemvec_t *ev, size_t n, re_elemvec_t *gev)
{
	size_t extra;

	re_elemvec_check(ev);
	re_elemvec_check(gev);
	g_assert(n < ev->ecnt);
	g_assert(ev != gev);
	g_assert(gev->ecnt > 1);

	/* Make room for the new items from the group */

	extra = gev->ecnt - 1;		/* We're replacing the group element */
	re_elemvec_extend(ev, ev->ecnt + extra);

	/* Shift elements after the current position by `extra' slots */

	memmove(&ev->elements[n + 1 + extra], &ev->elements[n + 1],
			(ev->ecnt - n - 1) * sizeof ev->elements[0]);

	/* Now move the elements from gev into the slots n .. n + extra */

	ev->ecnt += extra;
	memcpy(&ev->elements[n], &gev->elements[0],
			gev->ecnt * sizeof ev->elements[0]);

	re_elemvec_free(gev);
}

/**
 * Detect "simple" enough groups to remove them.
 *
 * @param ev	the element vector to which the group belongs
 * @param n		position in the element vector
 * @param e		the group element
 */
static void
re_handle_group(re_elemvec_t *ev, size_t n, re_element_t *e)
{
	re_elemvec_t *gev;
	size_t min, max;
	re_element_t *ce;
	bool e_atomic, e_minimal;

	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	/*
	 * A "simple" group must be non-capturing, and not a look-ahead
	 * assertion.
	 */

	switch (e->type) {
	case RE_TYPE_SUBN:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		return;
	}

	gev = re_element_get_sub(e);
	re_elemvec_check(gev);

	/*
	 * If there is only one element in the group (there are no
	 * NEXT yet), then the group is useless and can be removed.
	 *
	 * We propagate repetitions to the single element, which means
	 * we can create TEXT elements with repetitions at this stage,
	 * something that cannot happen during parsing.
	 *
	 * If there are more than one element in the group, but there
	 * is no specific repetition attached to it, then it is also
	 * useless and can be inlined: "f(?:bv.*f+)g" -> "fbv.*f+g".
	 */

	if (gev->ecnt > 1) {
		if (RE_N_ONCE == e->repeat && RE_TYPE_ATOMIC != e->type) {
			re_unexpand_element(e);		/* The group element */
			re_inline_group(ev, n, gev);
		}
		return;
	}

	/*
	 * If both the group and the child element have repetition, we must
	 * be careful to combine them.  For instance "(d{3,5})+" is NOT "d{3,}".
	 */

	ce = &gev->elements[0];

	if (RE_N_ONCE == ce->repeat || RE_N_ONCE == e->repeat) {
		/* Because one is RE_N_ONCE at least, their min & max will be 1 */
		min = re_element_get_repeat_min(e) * re_element_get_repeat_min(ce);
		max = re_element_get_repeat_max(e) * re_element_get_repeat_max(ce);
	} else {
		size_t e_max  = re_element_get_repeat_max(e);	/* GROUP */
		size_t e_min  = re_element_get_repeat_min(e);
		size_t ce_min = re_element_get_repeat_min(ce);	/* contained element */
		size_t ce_max = re_element_get_repeat_max(ce);

		if (e_min == e_max)
			goto compute;		/* Group count is fixed */

		if (e_min == e_max && ce_min == ce_max)
			goto compute;		/* Both counts are fixed */

		if (e_max <= 1 || ce_max <= 1)
			goto compute;

		if (ce_min == ce_max && e_max <= 1)
			goto compute;

		if (ce_min > 1 && (e_min > 1 || e_max > 1))
			return;

		if (e_min <= 1 || ce_min <= 1)
			goto compute;

		return;

	compute:
		min = size_saturate_mult(e_min, ce_min);
		max = size_saturate_mult(e_max, ce_max);
	}

	if (RE_N_ONCE  == ce->repeat || RE_N_COUNT == ce->repeat)
		ce->minimal = TRUE;		/* No choice, count is fixed */

	e_minimal = e->minimal;
	re_unexpand_element(e);
	e_atomic  = e->atomic;
	*e = *ce;					/* Struct copy */
	e->minimal &= e_minimal;	/* Both need to be minimal */
	e->atomic  |= e_atomic;		/* Either needs to be atomic */
	e->extracted = TRUE;
	re_element_set_repeat(e, min, max);

	re_elemvec_free(gev);
}

/**
 * Traversal callback on vector to handle group elements.
 */
static void
re_process_group(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (re_element_is_group(e))
			re_handle_group(rev, i, e);
	}
}

/**
 * Initiate traversal to remove useless non-capturing groups.
 *
 * For instance, "a(.)*+w" is kept, although inefficient, but "a(?:.)*+w"
 * is transformed into "a.*+w".
 *
 * TODO: we could probably optimize "a(.)*?w" into "a(.*?)w" due to the way
 * our capturing works: both would capture the same thing, which is NOT the
 * same behaviour as Perl's one for instance where the former only captures
 * the last matching character in the repetition.
 */
static void
re_remove_plain_groups(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	re_foreach_elemvec(re->u.compiled, re_process_group, NULL);
}

/**
 * Traversal callback on vector to handle OR elements.
 */
static void
re_factorize_or_trees(void *data, void *udata)
{
	re_elemvec_t *rev = data;
	size_t i;

	re_elemvec_check(rev);
	(void) udata;

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		if (RE_TYPE_OR == e->type)
			re_extract_common_or(rev, i);
	}
}

/**
 * Initiate traversal to factorize common items out of OR alternatives.
 *
 * For instance, "^abc|^def" will become "^(?:abc|def") and "a.c|b.c"
 * can become "(?:a|b).c", which will turn out as "[ab].c", which only
 * requires a linear traversal to match or fail!
 */
static void
re_factorize_or(re_regex_t *re)
{
	re_regex_check(re);
	re_elemvec_check(re->u.compiled);

	/* It is important to do that in post-order, from bottom-up */

	re_foreach_elemvec(re->u.compiled, re_factorize_or_trees, NULL);
}

/**
 * Transform the regular expression into constant pattern matching when
 * we just have to match the constant string described by e.
 */
static void
re_mutate_into_pattern(re_regex_t *re, const re_element_t *e)
{
	char buf[2];
	const char *pattern;

	g_assert(RE_N_ONCE == e->repeat);
	g_assert(re_element_is_text(e) || re_element_is_char(e));

	if (re_element_is_char(e)) {
		buf[0] = re_element_get_char(e);
		buf[1] = '\0';
		pattern = buf;
	} else {
		pattern = re_element_get_text(e);
	}

	re->u.cp = pattern_compile(pattern, re->icase);
}

/**
 * Transform the regular expression into a plain string comparison
 * when we just have a single anchored string to match.
 */
static void
re_mutate_into_anchored(re_regex_t *re, const re_element_t *e,
	bool at_start, bool at_end)
{
	g_assert(RE_N_ONCE == e->repeat);
	g_assert(re_element_is_text(e) || re_element_is_char(e));
	g_assert(at_start || at_end);

	re->u.anchored = re_element_string_dup(e);
	re->at_start   = at_start;
	re->at_end     = at_end;
}

/**
 * Is regular expression simple enough that we can use simpler and
 * more efficient techniques to match it?
 *
 * @return TRUE if regular expression was transformed into a simpler form.
 */
static bool
re_compiled_is_simple(re_regex_t *re)
{
	re_elemvec_t *rev = re->u.compiled;
	const re_element_t *e;
	bool at_start = FALSE, at_end = FALSE;

	re_elemvec_check(rev);

	if (rev->ecnt > 3)
		return FALSE;

	e = &rev->elements[0];

	if (1 == rev->ecnt) {
		goto plain;			/* Look for single TEXT or CHAR */
	} else if (2 == rev->ecnt) {
		/* Look for START + TEXT/CHAR or TEXT/CHAR + END */
		if (RE_TYPE_START == e->type) {
			e++;
			at_start = TRUE;
			goto anchored;	/* Look for single TEXT or CHAR */
		} else if (RE_TYPE_END == (e + 1)->type) {
			at_end = TRUE;
			goto anchored;	/* Look for single TEXT or CHAR */
		}
	} else {
		/* Look for START + TEXT/CHAR + END */
		if (RE_TYPE_START != e->type)
			return FALSE;
		e++;
		if (RE_TYPE_END != (e + 1)->type)
			return FALSE;
		at_start = at_end = TRUE;
		goto anchored;
	}

	return FALSE;	/* Not simple */

anchored:
	/*
	 * If element `e' is a single TEXT or CHAR, mutate into a fixed string.
	 */

	if (e->repeat != RE_N_ONCE)
		return FALSE;			/* Was not expanded for a reason */

	if (!re_element_is_text(e) && !re_element_is_char(e))
		return FALSE;

	re_mutate_into_anchored(re, e, at_start, at_end);
	goto free_compiled;

plain:
	/*
	 * If element `e' is a single TEXT or CHAR, mutate into a fixed pattern.
	 */

	if (e->repeat != RE_N_ONCE)
		return FALSE;			/* Was not expanded for a reason */

	if (!re_element_is_text(e) && !re_element_is_char(e))
		return FALSE;

	re_mutate_into_pattern(re, e);

	/* FALL THROUGH */

free_compiled:
	re->is_simple = TRUE;
	re_elemvec_recursive_free(rev);
	return TRUE;
}

/**
 * Context used for re_compute_first_char_map() traversal.
 */
struct re_compute_fcmap_ctx {
	uint8 *map;			/* The map we're constructing */
	bool matches_all;	/* True as soon as we know it matches all chars */
	hset_t *seen;		/* To avoid traversing same vector twice */
};

/**
 * Is the First Char map containing all the alphabet characters?
 */
static bool
re_fcmap_matches_all(const uint8 *map)
{
	return NULL == vmemchr(map, 0, RE_ALPHABET);
}

/**
 * Is the First Char map matching nothing?
 */
static bool
re_fcmap_matches_nothing(const uint8 *map)
{
	return NULL == vmemchr(map, 1, RE_ALPHABET);
}

/**
 * First Char map element vector traversal.
 */
static void
re_fcmap_elemvec(struct re_compute_fcmap_ctx *ctx, const re_elemvec_t *ev)
{
	size_t i;

	re_elemvec_check(ev);

	/*
	 * We need to protect against shared element vectors that can be
	 * used by traversable tries.
	 */

	if (hset_contains(ctx->seen, ev))
		return;		/* Already traversed */

	hset_insert(ctx->seen, ev);

	for (i = 0; i < ev->ecnt && !ctx->matches_all; i++) {
		re_element_t *e = &ev->elements[i];
		bool inverted = FALSE;

		switch ((re_elem_type_t) e->type) {
		case RE_TYPE_START:
		case RE_TYPE_END:
		case RE_TYPE_EMPTY:
		case RE_TYPE_IS_BOUNDARY:
		case RE_TYPE_NOT_BOUNDARY:
		case RE_TYPE_RETURN:
		case RE_TYPE_NEXT:
			break;
		case RE_TYPE_BACKREF:
		case RE_TYPE_ALL:
			ctx->matches_all = TRUE;
			return;
		case RE_TYPE_ANY:
			if (ctx->map['\n']) {
				ctx->matches_all = TRUE;
				return;
			} else {
				re_elem_map_any(ctx->map);
			}
			break;
		case RE_TYPE_TEXT:
			re_elem_map_first_text(ctx->map, e);
			break;
		case RE_TYPE_CHAR:
			re_elem_map_char(ctx->map, e);
			break;
		case RE_TYPE_INV_CLASS:
		case RE_TYPE_CLASS:
			re_elem_map_class(ctx->map, e);
			break;
		case RE_TYPE_INV_CLASS_MM:
		case RE_TYPE_CLASS_MM:
			re_elem_map_minmax(ctx->map, e);
			break;
		case RE_TYPE_D_CLASS:
		case RE_TYPE_W_CLASS:
		case RE_TYPE_S_CLASS:
		case RE_TYPE_NOT_D_CLASS:
		case RE_TYPE_NOT_W_CLASS:
		case RE_TYPE_NOT_S_CLASS:
			re_elem_map_hwclass(ctx->map, e);
			break;
		case RE_TYPE_NOT_POSIX_CLASS:
		case RE_TYPE_POSIX_CLASS:
			re_elem_map_posix(ctx->map, e);
			break;
		case RE_TYPE_NOT_AHEAD:
			inverted = TRUE;
			/* FALL THROUGH */
		case RE_TYPE_AHEAD:
			{
				uint8 *amap, *saved_map;
				int c;

				WALLOC0_ARRAY(amap, RE_ALPHABET);

				/* Recurse with fresh map for look-ahead */

				saved_map = ctx->map;
				ctx->map = amap;
				re_fcmap_elemvec(ctx, re_element_get_sub(e));
				ctx->map = saved_map;

				if (inverted) {
					for (c = 0; c < RE_ALPHABET; c++)
						amap[c] = !amap[c];
				}

				/* Merge back look-ahead map into our map */

				for (c = 0; c < RE_ALPHABET; c++)
					ctx->map[c] |= amap[c];

				WFREE_ARRAY(amap, RE_ALPHABET);
			}
			break;
		case RE_TYPE_ATOMIC:
		case RE_TYPE_GROUP:
		case RE_TYPE_SUB:
		case RE_TYPE_SUBN:
			re_fcmap_elemvec(ctx, re_element_get_sub(e));
			break;
		case RE_TYPE_OR:
			{
				pslist_t *sl;

				PSLIST_FOREACH(re_element_get_alt(e), sl) {
					re_fcmap_elemvec(ctx, sl->data);
				}
			}
			break;
		case RE_TYPE_MATCH:
		case RE_TYPE_MATCHX:
		case RE_TYPE_ROUTE:
		case RE_TYPE_ROUTEX:
			re_elem_map_first_trie(ctx->map, e);
			break;
		case RE_TYPE_MAX:
			g_assert_not_reached();
		}

		/*
		 * If the element can match at least one character, we're done.
		 * Just check whether the map can match any character at that point.
		 */

		if (re_element_get_minlen(e) >= 1 && re_element_get_repeat_min(e) > 0) {
			ctx->matches_all = re_fcmap_matches_all(ctx->map);
			return;
		}
	}
}

/**
 * Compute the "First Char map", which a byte map of all the characters
 * that can be used successfully as the first one of a matching text.
 *
 * If we encounter an element that can match the empty string, then we
 * look at all the characters it can start with, and continue, until
 * the first of these events:
 *
 * - any character of the alphabet could be the beginning of a matching text
 * - we encounter an element which matches at least once a non-empty string.
 * - the whole pattern matches the empty string.
 *
 * The last one is easy, because at this point we have computed the minimum
 * and maximum matching lengths of all the elements and all the vectors.
 */
static void
re_compute_first_char_map(re_regex_t *re)
{
	struct re_compute_fcmap_ctx ctx;
	const re_elemvec_t *ev = re->u.compiled;	/* Root element vector */

	re_regex_check(re);
	g_assert(NULL == re->fcmap);

	re_elemvec_check(ev);

	/*
	 * If ev->minlen is zero, the pattern matches the empty string
	 * and therefore could match anywhere.
	 *
	 * However, if we have a look-around assertion somewhere in the top
	 * vector, then we could compute a useful FC map anyway.
	 */

	if (0 == ev->minlen) {
		size_t i;
		bool has_lookaround = FALSE;

		for (i = 0; i < ev->ecnt; i++) {
			const re_element_t *e = &ev->elements[i];
			if (re_element_is_look_around(e)) {
				has_lookaround = TRUE;
				break;
			}
		}

		if (!has_lookaround)
			return;		/* Matches the empty string, could match anywhere */
	}

	ZERO(&ctx);
	WALLOC0_ARRAY(ctx.map, RE_ALPHABET);
	ctx.seen = hset_create(HASH_KEY_SELF, 0);

	re_fcmap_elemvec(&ctx, ev);

	hset_free_null(&ctx.seen);

	if (ctx.matches_all || re_fcmap_matches_nothing(ctx.map))
		WFREE_ARRAY(ctx.map, RE_ALPHABET);
	else
		re->fcmap = ctx.map;
}

/**
 * Finalize the compiled regular expression.
 *
 * This is called right after a successful parsing of the regular expression.
 *
 * The RE_F_NO_OPTIM flag can be supplied to disable any optimization on
 * the regular expression: only the simple transformations of character
 * classes done during parsing will be kept.  This is mostly useful for
 * testing that the optimized and non-optimized versions of the regular
 * expression match identically.
 *
 * The RE_F_NO_SIMPLE flag can be supplied to disable the simplification
 * of the regular expression into fixed-pattern matching or anchored string
 * comparison.  This is mostly useful for testing.
 *
 * Note that with RE_F_NO_OPTIM, the chances of being able to simplify the
 * regular expression are much reduced.
 *
 * @param re		the regular expression
 * @param cflags	supplied flags during compilation
 */
static void
re_finalize(re_regex_t *re, uint32 cflags)
{
	bool altered;

	re_regex_check(re);

	if (NULL == re->u.compiled) {
		re->is_empty = TRUE;
		return;		/* Empty regular expression */
	}

	/*
	 * If they supplied RE_X_NO_OPTIM, then do not optimize
	 * and leave the regex in the state it was in after parsing.
	 */

	if (cflags & RE_F_NO_OPTIM)
		goto no_optimization;

	re->optimized = TRUE;		/* Flag it passed through the optimizer */

	re_strip_empty(re);			/* Remove EMPTY elements which always match */
	re_remove_plain_groups(re);	/* Remove groups serving no purpose */
	re_explode_text(re);		/* Explode TEXT into CHAR if appropriate */

	/*
	 * Split CHAR elements with minimal repetition so that we can better
	 * factorize them out of alternatives or coalesce them later to form
	 * larger TEXT elements.
	 *
	 * For instance, "ab+" becomes "abb*" and "ab{3,}" becomes "abbbb*".
	 */

	re_split_shallow_repetitions(re);

	re_absorb_or(re);			/* Move sub-OR groups to parent OR */
	re_factorize_or(re);		/* Factorize common items out of alternatives */
	re_strip_redundant(re);		/* Remove redundant items */

	/*
	 * Coalesce CHAR and TEXT items together, expanding small
	 * repetitions to make-up a larger constant string.
	 */

	re_coalesce_constants(re);

	/*
	 * Now optimize OR groups, factorizing constants, merging character
	 * classes in alternatives, etc...  This may create extra TEXT
	 * nodes that we can maybe coalesce further, as in "a(?:bcx|bdy)"
	 * becoming "ab(?:cx|dy)"..
	 */

	do {
		altered = re_optimize_or(re);
		re_strip_empty(re);			/* ORs could have been emptied */
		re_remove_plain_groups(re);	/* Remove groups serving no purpose */
		re_explode_text(re);		/* Explode TEXT into CHAR if appropriate */
		re_split_shallow_repetitions(re);
		re_coalesce_constants(re);	/* Groups may have been stripped */
	} while (altered);

	/*
	 * Factorize consecutive identical "shallow" elements.
	 *
	 * This would merge back standalone split CHAR but also coalesce more
	 * complex patterns into simpler ones, like ".*.+" into ".+".
	 */

	re_merge_shallow_repetitions(re);	/* Merge back remaining split CHAR */
	re_strip_redundant(re);				/* Remove redundant items */

	/*
	 * Remove identical branches from OR elements.
	 */

	re_prune_or_branches(re);
	re_remove_plain_groups(re);

	/*
	 * After this initial coalescing, look at the root vector: if it
	 * has a START + TEXT or a simple TEXT element, then we do not need
	 * a regular expression engine at all to match it...
	 */

	if (0 == (cflags & RE_F_NO_SIMPLE) && re_compiled_is_simple(re))
		return;

no_optimization:

	/*
	 * OK, we will look for this pattern via the execution engine.
	 *
	 * Gather useful information, make the tree traversable from anywhere
	 * and compact vectors.
	 */

	re_linearize(re);

	/*
	 * Find suitable matching first characters so that we can skip over
	 * places where there is no hope to have a proper match.
	 */

	re_compute_first_char_map(re);
}

/***
 *** ======================== Parsing ========================
 ***/

/**
 * Allocate a new regular expression parser.
 *
 * @param is		input stream from which the regular expression is read
 * @param cflags	compilation flags
 *
 * @return a new regular expression parser
 */
static re_parser_t *
re_parser_alloc(istream_t *is, uint32 cflags)
{
	re_parser_t *rp;

	WALLOC0(rp);
	rp->magic = RE_PARSER_MAGIC;
	rp->cflags = cflags;
	rp->is = is;
	rp->text = str_new(0);
	rp->root = rp->current = re_elemvec_alloc(0);

	return rp;
}

/**
 * Free regular expression parser.
 */
static void
re_parser_free(re_parser_t *rp)
{
	struct re_parser_nesting *ctx;

	re_parser_check(rp);

	str_destroy_null(&rp->text);
	htable_free_null(&rp->backrefs);
	hset_free_null(&rp->finished_subn);
	pslist_free_null(&rp->closed_subn);

	if (NULL != rp->root)
		re_elemvec_recursive_free(rp->root);

	while ((ctx = pslist_shift(&rp->nesting))) {
		WFREE(ctx);
	}

	rp->magic = 0;
	WFREE(rp);
}

/**
 * Record parsing error at current position.
 *
 * @param rp		the parser
 * @param offset	offset to apply to correct position in input stream
 * @param code		the error code
 *
 * @return FALSE to signal error.
 */
static bool
re_parse_error(re_parser_t *rp, int offset, re_error_code_t code)
{
	rp->error.code = code;
	rp->error.pos = istream_bytes_read(rp->is) + offset;

	return FALSE;
}

/**
 * Flush context held in the parser into the element.
 */
static void
re_parse_flush_element(re_parser_t *rp, re_element_t *e)
{
	re_parser_check(rp);
	g_assert(e != NULL);

	switch (e->type) {
	case RE_TYPE_TEXT:
		if (0 == str_len(rp->text)) {
			/* Emptied text, discard element */
			re_elemvec_return_element(rp->current, e);
		}
		else if (1 == str_len(rp->text)) {
			bool icase = booleanize(rp->cflags & RE_F_ICASE);

			/* Single-char text is transformed into a char element */

			e->u.c = str_at(rp->text, 0);
			if (is_ascii_alpha(e->u.c)) {
				e->type  = RE_TYPE_CHAR;
				e->icase = icase;
			} else {
				e->type  = RE_TYPE_CHAR;
				e->icase = FALSE;
			}
			e->minlen = 1;
		} else {
			/* We have a longer text, duplicate the string */

			e->u.text = str_dup(rp->text);
			if (str_len(rp->text) >= RE_LEN_ESCAPE) {
				re_expand_element(e);
				e->u.other->minlen = e->u.other->maxlen = str_len(rp->text);
			} else {
				e->minlen = e->maxlen = str_len(rp->text);
			}
		}
		str_reset(rp->text);
		break;
	default:
		break;
	}
}

/**
 * Add new element, after flushing current element.
 *
 * @return new element of given type.
 */
static re_element_t *
re_parse_add_element(re_parser_t *rp, re_elem_type_t type, bool icase)
{
	re_element_t *e;

	re_parser_check(rp);

	e = re_elemvec_last_element(rp->current);
	if (e != NULL)
		re_parse_flush_element(rp, e);

	e = re_elemvec_new_element(rp->current, type, icase);

	return e;
}

/**
 * Opens a parent node for a sub-expression parsing.
 *
 * @param rp	the parser
 * @param type	type for parent node
 * @param icase	whether we're case-insensitive here
 *
 * @return created parent element.
 */
static re_element_t *
re_parse_open_parent(re_parser_t *rp, re_elem_type_t type, bool icase)
{
	re_element_t *e;
	struct re_parser_nesting *ctx;

	re_parser_check(rp);

	/*
	 * The group is going to be referenced by the element we're creating here.
	 *
	 *         GROUP         <- belongs to the parent element vector
	 *           |
	 *        (pattern)      <- sub-regex compiled in a new element vector
	 *
	 * If repetition meta-characters follow the group, they will be applied
	 * to the GROUP element once we return from the recursive parsing.
	 *
	 * The "pattern" above may contain other sub-groups, as in the following
	 * regular expression: "((a*|b)|cd)+".
	 */

	e = re_parse_add_element(rp, type, icase);	/* Sub-expression parent */

	/* Save current element vector context */

	WALLOC0(ctx);
	ctx->current = rp->current;
	ctx->or = rp->or;
	rp->nesting = pslist_prepend(rp->nesting, ctx);

	/*
	 * Setup context for the sub-expression recursive parsing.
	 *
	 * At this stage, the element we created above is not expanded, so we
	 * can directly set the "sub" field without calling a setter routine
	 * that would abstract the operation.
	 */

	rp->current = re_elemvec_alloc(0);	/* Element vector for sub-expression */
	rp->or = NULL;						/* No alternatives yet */
	e->u.sub = rp->current;				/* Link parent to sub-expression */
	rp->depth++;

	return e;
}

/**
 * Closes sub-expression, restoring previous element vector.
 */
static void
re_parse_close_parent(re_parser_t *rp)
{
	struct re_parser_nesting *ctx;

	re_parser_check(rp);
	g_assert(rp->depth != 0);

	ctx = pslist_shift(&rp->nesting);
	g_assert(ctx != NULL);

	/* Restore context */

	rp->current = ctx->current;
	rp->or      = ctx->or;
	rp->depth--;

	WFREE(ctx);
}

/**
 * Add character to match.
 */
static void
re_parse_add_char(re_parser_t *rp, int c)
{
	re_element_t *e;
	bool icase = booleanize(rp->cflags & RE_F_ICASE);

	re_parser_check(rp);

	/*
	 * If we are already in a text element, append the character.
	 * Otherwise, open a new text element.
	 */

	e = re_elemvec_last_element(rp->current);

	if (NULL == e || !re_element_is_text(e))
		e = re_parse_add_element(rp, RE_TYPE_TEXT, icase);

	if (icase)
		c = ascii_tolower(c);

	str_putc(rp->text, c);	/* Characters buffered until element is flushed */
	rp->seen_char = TRUE;
}

/**
 * Parse hexadecimal character escape (\xHH).
 *
 * The leading '\x' sequence has already been read.
 *
 * @return the parsed character if OK, -1 on error with the parser error set.
 */
static int
re_parse_hexa(re_parser_t *rp)
{
	uchar hexa[2];
	int c;
	size_t i;

	re_parser_check(rp);

	hexa[0] = c = istream_getc(rp->is);
	if G_UNLIKELY(-1 == c) {
		re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
		return -1;
	}
	hexa[1] = c = istream_getc(rp->is);
	if G_UNLIKELY(-1 == c) {
		re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
		return -1;
	}

	for (i = 0; i < N_ITEMS(hexa); i++) {
		int v = hex2int(hexa[i]);
		if (v < 0) {
			re_parse_error(rp, i - 2, RE_E_INVALID_HEXA_DIGIT);
			return -1;
		}
	}

	return (hex2int(hexa[0]) << 4) + hex2int(hexa[1]);
}

/**
 * Add word boundary matching assertion.
 */
static void
re_parse_add_boundary(re_parser_t *rp, bool boundary)
{
	re_parser_check(rp);

	(void) re_parse_add_element(rp,
			boundary ? RE_TYPE_IS_BOUNDARY : RE_TYPE_NOT_BOUNDARY, FALSE);
}

/**
 * Add hardwired character class matching character.
 */
static void
re_parse_add_char_class(re_parser_t *rp, int c)
{
	re_elem_type_t t;

	re_parser_check(rp);

	switch (c) {
	case 'd': t = RE_TYPE_D_CLASS;     break;
	case 'w': t = RE_TYPE_W_CLASS;     break;
	case 's': t = RE_TYPE_S_CLASS;     break;
	case 'D': t = RE_TYPE_NOT_D_CLASS; break;
	case 'W': t = RE_TYPE_NOT_W_CLASS; break;
	case 'S': t = RE_TYPE_NOT_S_CLASS; break;
	default:
		g_assert_not_reached();
	}

	(void) re_parse_add_element(rp, t, FALSE);
	rp->seen_char = TRUE;
}

/**
 * Add hardwired character class to a character class element.
 */
static void
re_class_add_known(re_element_t *e, int c)
{
	uint mask;

	g_assert(re_element_is_class(e));

	switch (c) {
	case 'd': mask = RE_CLASS_D;     break;
	case 'w': mask = RE_CLASS_W;     break;
	case 's': mask = RE_CLASS_S;     break;
	case 'D': mask = RE_CLASS_NOT_D; break;
	case 'W': mask = RE_CLASS_NOT_W; break;
	case 'S': mask = RE_CLASS_NOT_S; break;
	default:
		g_assert_not_reached();
	}

	re_expand_element(e);
	e->u.other->v.classes |= mask;
}

/**
 * Parse a possible POSIX character class with leading "[:" already read.
 *
 * If the string does not end-up being a valid character class, the leading
 * chars plus the characters we parsed will be added to the character class
 * being filled, and the last char will be returned.
 *
 * If the string ends-up being a valid POSIX character class specification,
 * then either the character class is known and we add it to the element,
 * then return -1, or the class is invalid and an error message is returned.
 *
 * @param rp	the parsing context
 * @param e		the class element
 *
 * @return the last character of the read string, -1 if we managed to parse
 * a valid POSIX character class, -2 if the POSIX class name is unknown.
 */
static int
re_parse_posix_class(re_parser_t *rp, re_element_t *e)
{
	str_t *s = str_new(0);
	int c;

	re_parser_check(rp);
	g_assert(re_element_is_class(e));

	while (-1 != (c = istream_getc(rp->is))) {
		switch(c) {
		case ':':
			/* Could be the start of the closing sequence ":]" */
			c = istream_getc(rp->is);
			if (']' == c)
				goto posix;
			/*
			 * The ':' cannot be part of a POSIX class name, and since this
			 * is not a class, there is no need to add the ':' character to the
			 * `s' string: we're going to add "[:" to the class anyway below!
			 */
			break;
		default:
			if (!is_ascii_lower(c))
				break;	/* Only lower ASCII letters form a valid class name */
			str_putc(s, c);
			continue;
		}
		break;
	}

	/* Not a POSIX class finally */

	if (-1 != c)
		istream_ungetc(rp->is, c);

	str_istr(s, 0, "[:");
	c = str_at(s, -1);			/* Last character seen */

	/* rp->text is where we stuff characters belonging to the class */

	str_cat_len(rp->text, str_2c(s), str_len(s));
	str_destroy_null(&s);

	return c;	/* This char may be followed by '-' to form a range later */

posix:
	/*
	 * Found a POSIX class if the name held in `s' is that of a valid POSIX
	 * string.  If it is not, then emit an error.
	 */

	{
		uint bitmask = TOKENIZE(str_2c(s), re_posix_classes);

		if (0 == bitmask) {
			re_parse_error(rp, -str_len(s) - 2, RE_E_UNKNOWN_POSIX_CLASS);
			str_destroy_null(&s);
			return -2;		/* Signals parser error */
		}

		re_expand_element(e);
		e->u.other->v.classes |= bitmask;
	}

	str_destroy_null(&s);
	return -1;	/* Valid POSIX class */
}

/**
 * Parse character class, with leading '[' already swallowed.
 *
 * @return TRUE on success.
 */
static bool
re_parse_class(re_parser_t *rp)
{
	bool inverted = FALSE;
	int c, prev_char = -1;
	re_element_t *e;
	size_t pos = istream_bytes_read(rp->is);

	re_parser_check(rp);

	rp->seen_char = TRUE;	/* When class parsing is complete, it will... */

	/*
	 * Only if there is a leading ^ will the character class be inverted.
	 */

	c = istream_getc(rp->is);
	if G_UNLIKELY(-1 == c)
		goto incomplete;

	if ('^' == c) {
		c = istream_getc(rp->is);
		if G_UNLIKELY(-1 == c)
			goto incomplete;
		if (']' == c) {
			/* They said [^], this means it matches anything, all the chars! */
			re_parse_add_element(rp, RE_TYPE_ALL, FALSE);
			return TRUE;
		} else {
			inverted = TRUE;
			istream_ungetc(rp->is, c);
		}
	} else if (']' == c) {
		re_parse_add_element(rp, RE_TYPE_EMPTY, FALSE);	/* That's "[]" */
		return TRUE;
	} else {
		istream_ungetc(rp->is, c);
	}

	/*
	 * Get a new element for the character class we're parsing.
	 *
	 * As a side effect, this flushes any opened text element and will
	 * therefore free the rp->text string for stuffing characters that
	 * belong (possibly negatively) to the character class.
	 */

	e = re_parse_add_element(rp,
			inverted ? RE_TYPE_INV_CLASS : RE_TYPE_CLASS,
			rp->cflags & RE_F_ICASE);

	/*
	 * Now parse the characters in the class, adding each character to
	 * the rp->text string buffer.
	 */

	g_assert(0 == str_len(rp->text));	/* Cleared when flushing last element */

resume:
	while (-1 != (c = istream_getc(rp->is))) {
		switch (c) {
		case ']':
			/* Not closing if we haven't seen any character yet */
			if (0 != str_len(rp->text) || re_element_is_expanded(e))
				goto done;
			break;
		case '-':
			/*
			 * If we already have a character, then this defines a range,
			 * unless we are followed by a ']', meaning we're at the end
			 * of the character class.
			 */

			if (-1 == prev_char)
				break;					/* Stands for itself then */

			c = istream_getc(rp->is);	/* What follows the '-' */
			if G_UNLIKELY(-1 == c)
				goto incomplete;
			if (']' == c) {
				str_putc(rp->text, '-');
				goto done;
			} else if (0 == str_len(rp->text)) {
				istream_ungetc(rp->is, c);
				c = '-';
				break;
			}

			/*
			 * This is the start of a range only if the previous character
			 * we read was a plain char and not a hardwired class like \w.
			 */

			if (-1 == prev_char)
				return re_parse_error(rp, -2, RE_E_INVALID_CHAR_CLASS_RANGE);

			/*
			 * We already read the next character in `c' above.
			 * But it could be an escape for \n or \t.
			 */

			if ('\\' == c) {
				c = istream_getc(rp->is);
				if G_UNLIKELY(-1 == c)
					return re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
				switch (c) {
				default:            break;	/* Escaped char stands for itself */
				case 'a': c = '\a'; break;
				case 'b': c = '\b'; break;	/* Not a \b word-boundary here */
				case 't': c = '\t'; break;
				case 'n': c = '\n'; break;
				case 'v': c = '\v'; break;
				case 'f': c = '\f'; break;
				case 'r': c = '\r'; break;
				case 'd':
				case 's':
				case 'w':
				case 'D':
				case 'W':
				case 'S':
					return re_parse_error(rp, -3, RE_E_INVALID_CHAR_CLASS_RANGE);
				case 'x':
					c = re_parse_hexa(rp);
					if G_UNLIKELY(-1 == c)
						return FALSE;		/* Error set by re_parse_hexa() */
					break;
				}
			}

			/*
			 * Get last character from string and then expand the range
			 * up to the next character.
			 */

			{
				if (prev_char != c) {
					int x;
					if (prev_char > c)
						return re_parse_error(rp, -3, RE_E_BAD_CHAR_CLASS_RANGE);
					/* Expand range -- we already have lower bound in string */
					for (x = prev_char + 1; x <= c; x++) {
						str_putc(rp->text, x);
					}
				}
			}

			prev_char = -1;
			continue;
		case '[':
			c = istream_getc(rp->is);
			if (':' == c) {
				/* May be the start of a new POSIX character class */
				prev_char = re_parse_posix_class(rp, e);
				if (-2 == prev_char)
					return FALSE;	/* Unknown POSIX class name */
				goto resume;		/* Continue parsing */
			} else {
				istream_ungetc(rp->is, c);
				c = '[';
				break;
			}
		case '\\':
			c = istream_getc(rp->is);
			if G_UNLIKELY(-1 == c)
				return re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
			switch (c) {
			default:            break;	/* Escaped char stands for itself */
			case 'a': c = '\a'; break;
			case 'b': c = '\b'; break;	/* Does not mean "word boundary here */
			case 't': c = '\t'; break;
			case 'n': c = '\n'; break;
			case 'v': c = '\v'; break;
			case 'f': c = '\f'; break;
			case 'r': c = '\r'; break;
			case 'd':
			case 's':
			case 'w':
			case 'D':
			case 'W':
			case 'S':
				prev_char = -1;
				re_class_add_known(e, c);
				continue;	/* Not "break", we want to continue loop  */
			case 'x':
				c = re_parse_hexa(rp);
				if G_UNLIKELY(-1 == c)
					return FALSE;		/* Error set by re_parse_hexa() */
				break;
			}
			/* FALL THROUGH */
		default:
			break;
		}
		str_putc(rp->text, c);
		prev_char = c;
	}

	/*
	 * If we come here, the character class was not properly closed.
	 * Report the error at the beginning of the class definition.
	 */

incomplete:
	{
		int offset = pos - istream_bytes_read(rp->is);	/* <= 0 */
		return re_parse_error(rp, offset - 1, RE_E_INCOMPLETE_CHAR_CLASS);
	}

done:

	/*
	 * Now do some sanity checks:
	 *
	 * - if we have expanded the element, look whether we are matching
	 *   anything (all the chars as in [\d\D] or [\s\S]) or nothing
	 *   which would be an error (as in [^\d\D]).
	 *
	 * - if they specified all the characters in the set, this can be
	 *   optimized by an ALL element (not ANY which is '.' and its behaviour
	 *   could be changed by matching flags).
	 */

#define FLAG_MATCHES(x)		((x) == (classes & (x)))

	if (re_element_is_expanded(e)) {
		uint classes = re_element_get_classes(e);
		bool all = FALSE;

		/* If case-insensitive, turn [:lower:] and [:upper:] into [:alpha:] */
		if (rp->cflags & RE_F_ICASE) {
			if (classes & (RE_CLASS_PX_UPPER | RE_CLASS_PX_LOWER)) {
				classes &= ~RE_CLASS_PX_UPPER;
				classes &= ~RE_CLASS_PX_LOWER;
				classes |= RE_CLASS_PX_ALPHA;
			}
		}

		/* A \w means we can remove some POSIX classes */
		if (classes & RE_CLASS_W) {
			classes &= ~RE_CLASS_PX_DIGIT;
			classes &= ~RE_CLASS_PX_ALNUM;
			classes &= ~RE_CLASS_PX_XDIGIT;
			classes &= ~RE_CLASS_PX_ALPHA;
			classes &= ~RE_CLASS_PX_UPPER;
			classes &= ~RE_CLASS_PX_LOWER;
		}

		/* Classes [:upper:] and [:lower:] are [:alpha:] */
		if (FLAG_MATCHES(RE_CLASS_PX_UPPER | RE_CLASS_PX_LOWER)) {
			classes |= RE_CLASS_PX_ALPHA;
			classes &= ~RE_CLASS_PX_UPPER;
			classes &= ~RE_CLASS_PX_LOWER;
		}

		/* Classes [:alpha:] and [:digit:] are [:alnum:] */
		if (FLAG_MATCHES(RE_CLASS_PX_ALPHA | RE_CLASS_PX_DIGIT)) {
			classes |= RE_CLASS_PX_ALNUM;
			classes &= ~RE_CLASS_PX_DIGIT;
			classes &= ~RE_CLASS_PX_ALPHA;
		}

		/* Class [:xdigit:] is superfluous if [:digit:] and [:alpha:] present */
		if (classes & RE_CLASS_PX_ALNUM)
			classes &= ~RE_CLASS_PX_XDIGIT;

		/* Class [:digit:] is \d */
		if (classes & RE_CLASS_PX_DIGIT) {
			classes |= RE_CLASS_D;
			classes &= ~RE_CLASS_PX_DIGIT;
		}

		/* Class [:space:] is \s */
		if (classes & RE_CLASS_PX_SPACE) {
			classes |= RE_CLASS_S;
			classes &= ~RE_CLASS_PX_SPACE;
		}

		all  = FLAG_MATCHES(RE_CLASS_D | RE_CLASS_NOT_D);
		all |= FLAG_MATCHES(RE_CLASS_S | RE_CLASS_NOT_S);
		all |= FLAG_MATCHES(RE_CLASS_W | RE_CLASS_NOT_W);

		if (all && inverted)
			return re_parse_error(rp, -1, RE_E_CHAR_CLASS_CANNOT_MATCH);

		if (all)
			goto match_all;

		/* Class D is encompassed by class W */

		if (FLAG_MATCHES(RE_CLASS_D | RE_CLASS_W))
			classes &= ~RE_CLASS_D;

		/* Class not-W is encompassed by class not-D */

		if (FLAG_MATCHES(RE_CLASS_NOT_D | RE_CLASS_NOT_W))
			classes &= ~RE_CLASS_NOT_W;

		re_element_set_classes(e, classes);
	}

#undef FLAG_MATCHES

	re_install_class(e, rp->text);
	goto cleanup;

	/*
	 * Simplify character class when it matches all the characters.
	 */

match_all:
	re_unexpand_element(e);
	e->type = RE_TYPE_ALL;

	/* FALL THROUGH */

cleanup:
	str_reset(rp->text);
	return TRUE;
}

/**
 * Create a tree structure to manage alternatives.
 *
 * The '|' between the alternatives has already been swallowed.
 */
static void
re_parse_add_alternative(re_parser_t *rp)
{
	re_element_t *e;
	re_parser_check(rp);

	e = re_elemvec_last_element(rp->current);
	if (e != NULL)
		re_parse_flush_element(rp, e);

	/*
	 * An alternative matching is a list of patterns that can match,
	 * each being separated by '|'.
	 *
	 * When we encounter an alternative, we have to create a tree of
	 * regular expressions, so that "a|b|c" is really represented as:
	 *
	 *            OR
	 *          / |  \
	 *         a  b   c
	 *
	 * In order to achieve that, we have to create a new parent node above
	 * the current element vector, if it has none, with a single OR entry
	 * pointing to the alternatives.  If it already has an OR, we just
	 * append to it.
	 */

	if (NULL == rp->or) {
		rp->or = re_elemvec_alloc(1);	/* Room only for the OR node */
		e = re_elemvec_new_element(rp->or, RE_TYPE_OR, rp->cflags & RE_F_ICASE);

		if (rp->root == rp->current) {
			/* At topmost level, the new OR node becomes the root */
			g_assert(0 == rp->depth);
			rp->root = rp->or;
		} else {
			struct re_parser_nesting *ctx;
			re_element_t *pe;

			g_assert(0 != rp->depth);
			g_assert(rp->nesting != NULL);
			ctx = rp->nesting->data;		/* Parent context */

			/*
			 * We need to re-target our parent to the OR element vector.
			 * The aim is to keep all the element vectors reachable from
			 * the root in case we have to abort and need to cleanup.
			 *
			 * Note that our parent element MUST be a group. This is
			 * the only recursive structure in a regular expression.
			 *
			 * This parent group has now alternatives, for instance "(a|b*)",
			 * and initially when we started to parse the "a" part, the
			 * group was referring to an element vector that is now being
			 * encapsulated below an OR.
			 *
			 * Final note: we can only access our parent context whilst
			 * parsing.  The context stack is a parser data structure that
			 * will go away once the pattern is compiled.
			 */

			pe = re_elemvec_last_element(ctx->current);
			g_assert(re_element_is_group(pe));

			re_element_set_sub(pe, rp->or);
		}

		/*
		 * Put the first alternative we already parsed
		 *
		 * During compilation, we know the element cannot be expanded,
		 * hence there is no need to complicate code by calling the
		 * getter and setter routines for the "alt" field.
		 */

		e->u.alt = pslist_prepend(e->u.alt, rp->current);
	}

	e = re_elemvec_last_element(rp->or);

	g_assert(RE_TYPE_OR == e->type);

	/*
	 * Add what we have parsed so far to the list of alternatives
	 * in the OR node.
	 *
	 * Order will be reversed when we finalize the parsing of the expression
	 * in re_parse().
	 *
	 * We must make sure all the element vectors are always reachable from the
	 * rp->root, to be able to cleanup in case of a parsing error, so
	 * immediately append the new element vector to the OR node.
	 */

	rp->current = re_elemvec_alloc(0);	/* For new expression */
	e->u.alt = pslist_prepend(e->u.alt, rp->current);

	rp->seen_end  = FALSE;	/* Starting a new alternative */
	rp->seen_char = FALSE;	/* Starting a new alternative */
}

/**
 * Is capturing group #n finished, and therefore suitable for a back-reference?
 */
static bool
re_parse_finished_subn(re_parser_t *rp, uint n)
{
	if (NULL == rp->finished_subn)
		return FALSE;

	return hset_contains(rp->finished_subn, uint_to_pointer(n));
}

/**
 * Flag capturing group #n as finished (i.e. we saw its closing parenthesis)..
 */
static void
re_parse_flag_finished_subn(re_parser_t *rp, uint n)
{
	if (NULL == rp->finished_subn)
		rp->finished_subn = hset_create(HASH_KEY_SELF, 0);

	/*
	 * The rp->finished_subn set lets us know whether a numbered capturing
	 * group is completely parsed and can therefore become a valid target
	 * for a back-reference.
	 *
	 * The rp->closed_subn list holds the closed capturing groups in the
	 * reverse order they were closed, so that we can correctly handle
	 * \g-n type of back-references (i.e. reference to the nth preceding group).
	 */

	hset_insert(rp->finished_subn, uint_to_pointer(n));
	rp->closed_subn = pslist_prepend(rp->closed_subn, uint_to_pointer(n));
}

/**
 * Parse regular expression group, with leading '(' already swallowed.
 *
 * @return TRUE on success.
 */
static bool
re_parse_group(re_parser_t *rp)
{
	re_elem_type_t type =
		(rp->cflags & RE_F_NOSUB) ? RE_TYPE_SUB : RE_TYPE_SUBN;
	int c;
	re_element_t *e;
	size_t subn = 0;

	re_parser_check(rp);

	/*
	 * Grouped expressions can nest: we are constructing a "forward tree"
	 * of these (it is not a real tree because there is no parent pointer,
	 * but it can be traversed from the top).
	 *
	 * The group element can therefore be the target of repetitions.
	 *
	 * There are three kinds of groups:
	 *
	 * - plain groups, within (), such as "(foo|bar)", "(a.*c)". If asked
	 *   for matched text, these groups will capture the starting and ending
	 *   positions in the text being matched.  Note that capturing (and
	 *   therefore the difference with the next group) is only done when
	 *   runtime flags ask for such a capture.
	 *
	 * - non-capturing groups, introduced by "(?:" are groups that will
	 *   never capture position of matched text.  Their runtime gain is
	 *   only there when matching with capturing turned on.  Otherwise,
	 *   they behave like plain groups. Example: "(?:foo|bar.*)"
	 *
	 * - atomic groups, introduced by "(?>" are groups which will match
	 *   and never give back what was matched even if it could later help
	 *   the pattern to match. Atomic groups are capturing groups.
	 *
	 * There is no runtime difference between processing of a SUB or a GROUP:
	 * their matching is never captured.  We keep the difference to be able
	 * to distinguish them in the "show" output: SUB were () groups whose
	 * capture was disabled at compile time whereas GROUP were specified by
	 * the user as (?:).
	 */

	c = istream_getc(rp->is);
	if (-1 == c)
		return re_parse_error(rp, -1, RE_E_INCOMPLETE_GROUP);

	if ('?' != c) {
		istream_ungetc(rp->is, c);
	} else {
		c = istream_getc(rp->is);
		if (-1 == c)
			return re_parse_error(rp, -2, RE_E_INCOMPLETE_GROUP);

		switch (c) {
		case ':': type = RE_TYPE_GROUP;     break;
		case '>': type = RE_TYPE_ATOMIC;    break;
		case '=': type = RE_TYPE_AHEAD;     break;
		case '!': type = RE_TYPE_NOT_AHEAD; break;
		default:
			return re_parse_error(rp, -1, RE_E_UNKNOWN_GROUP_TYPE);
		}
	}

	/*
	 * The group is its own little regular expression which we
	 * are going to recursively parse.
	 *
	 * We create a parent node and link it to the start of the new
	 * sub-expression that we will then fill with our parsing.
	 */

	e = re_parse_open_parent(rp, type, rp->cflags & RE_F_ICASE);

	if (RE_TYPE_SUBN == e->type) {
		re_expand_element(e);
		subn = e->u.other->v.subn = ++rp->subn;
	}

	if (RE_TYPE_ATOMIC == e->type)
		e->atomic = TRUE;

	if (!re_parse(rp))
		return FALSE;

	re_parse_close_parent(rp);

	/* If we handled a capturing group, it can now be used as a back-ref */

	if (RE_TYPE_SUBN == e->type)
		re_parse_flag_finished_subn(rp, subn);

	/*
	 * If we parsed a look-around assertion, then we need to include
	 * a RETURN statement after it in its element vector.  Indeed, we
	 * want to cut traversal to limit matching to only what is in the
	 * assertion, regardless of whether the rest of the expression is
	 * going to match.
	 */

	switch (type) {
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		/* Append a RETURN at the end of the look-around element vector */
		{
			re_elemvec_t *ev = re_element_get_sub(e);
			re_elemvec_insert_element(ev, ev->ecnt, RE_TYPE_RETURN, FALSE);
		}
		break;
	default:
		break;
	}

	return TRUE;
}

/**
 * Install repetition.
 *
 * @param rp		the parser
 * @param type		repetition type
 * @param ...		for ranges, min and optionally max as size_t
 *
 * @return TRUE on success.
 */
static bool
re_install_repetition(re_parser_t *rp, re_repeat_type_t type, ...)
{
	va_list args;
	size_t min = 0, max = MAX_INT_VAL(size_t);
	re_element_t *e;
	int c;

	re_parser_check(rp);

	/*
	 * If there is no element, we have a meta-character that cannot apply.
	 */

	e = re_elemvec_last_element(rp->current);

	if (NULL == e)
		return re_parse_error(rp, -1, RE_E_ORPHAN_REPETITION);

	/*
	 * If the last element is a text element, we need to strip-off its last
	 * letter because it is the one going to bear the repetition.
	 *
	 * The only types that are not allowed to bear a repetition are
	 * "OR" (which are really a tree node holding leaves, so we cannot be
	 * in that situation), word boundaries (\b and \B) and start-end positional
	 * matching (^ and $), all of which are zero-width assertions.
	 */

	switch (e->type) {
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
		return re_parse_error(rp, -1, RE_E_ORPHAN_REPETITION);
	case RE_TYPE_TEXT:
		g_assert(0 != str_len(rp->text));	/* Or we would not have a text */
		c = str_chop(rp->text);
		{
			bool icase = booleanize(rp->cflags & RE_F_ICASE);
			/* Adding element flushes text */
			if (is_ascii_alpha(c)) {
				e = re_parse_add_element(rp, RE_TYPE_CHAR, icase);
			} else {
				e = re_parse_add_element(rp, RE_TYPE_CHAR, FALSE);
			}
			re_element_set_minlen(e, 1);
			re_element_set_maxlen(e, 1);
		}
		e->u.c = c;		/* We have our char node now */
		break;
	case RE_TYPE_OR:
		g_assert_not_reached();
	default:
		break;
	}

	/*
	 * Flag repetition in the node.
	 */

	e->repeat = type;

	g_assert(type == e->repeat);	/* No truncation (field is small)  */

	/*
	 * For range repetitions, we need to fetch extra arguments.
	 */

	va_start(args, type);

	switch (type) {
	case RE_N_AT_MOST_ONE:
	case RE_N_AT_LEAST_ONE:
	case RE_N_ANY:
		goto done;
	case RE_N_RANGE:
		min = va_arg(args, size_t);
		max = va_arg(args, size_t);
		break;
	case RE_N_MIN:
		min = va_arg(args, size_t);
		break;
	case RE_N_COUNT:
		min = max = va_arg(args, size_t);
		break;
	case RE_N_ONCE:
		min = max = 1;
		break;
	case RE_N_MAX:
		g_assert_not_reached();
	}

	/*
	 * Validate repeat range.
	 */

	if (min > max)
		return re_parse_error(rp, -1, RE_E_INCONSISTENT_RANGE);

	if (0 == max)
		return re_parse_error(rp, -1, RE_E_NULL_REPETITION);

	re_element_set_repeat(e, min, max);

	/* FALL THROUGH */

done:
	/*
	 * Do not allow repetitions on look-ahead assertions.
	 *
	 * FIXME: maybe we could allow a fixed-count repetition?
	 * We definitely do not want a variable repetition count because
	 * we do not want to backtrack on look-ahead assertions!
	 */

	if (RE_TYPE_AHEAD == e->type || RE_TYPE_NOT_AHEAD == e->type) {
		if (type != RE_N_ONCE)
			return re_parse_error(rp, -1, RE_E_NO_REPEAT_ON_LOOK_AHEAD);
	}

	va_end(args);
	return TRUE;
}


/**
 * Modify repetition matching type with trailing '?' or '+' modifier.
 *
 * @return TRUE as convenience
 */
static bool
re_parse_repetition_modifier(re_parser_t *rp)
{
	bool greedy = TRUE, atomic = FALSE;		/* Defaults */
	bool no_modifier = FALSE;
	re_element_t *e;
	int c;

	re_parser_check(rp);

	e = re_elemvec_last_element(rp->current);

	g_assert(e != NULL);

	/*
	 * By default, repetition is greedy (matches as much as possible first)
	 * and not atomic (what was matched can be backtracked into even if the
	 * remaining text cannot match the remaining of the regular expression).
	 *
	 * Following one of the above meta-characters with '?' turns greediness off,
	 * whilst a '+' will turn on atomic matching (with greediness on).
	 */

	c = istream_getc(rp->is);		/* Can be EOF without issues */
	if (-1 == c)
		goto done;

	switch (c) {
	case '?': greedy = FALSE; break;
	case '+': atomic = TRUE;  break;
	default:  istream_ungetc(rp->is, c); no_modifier = TRUE; break;
	}

	if (RE_N_ONCE == e->repeat && !no_modifier)
		return re_parse_error(rp, -1, RE_E_CANNOT_ALTER_ONCE_MATCH);

	/*
	 * Look ahead to make sure they are not starting another repetition
	 * after the repetition operators.
	 */

	c = istream_getc(rp->is);		/* Can be EOF without issues */
	if (c != -1)
		istream_ungetc(rp->is, c);

	switch (c) {
	case '?':
	case '+':
	case '*':
	case '{':
		return re_parse_error(rp, 0, RE_E_ORPHAN_REPETITION);
	default:
		break;
	}

	if (no_modifier)
		return TRUE;

	e->minimal = !greedy;
	e->atomic = atomic;

done:
	return TRUE;
}

/**
 * Parse repetition with '?, '*' or '+' already swallowed.
 *
 * @param rp		the parser
 * @param c			the repetition character already read
 *
 * @return TRUE on success.
 */
static bool
re_parse_add_repetition(re_parser_t *rp, int c)
{
	re_repeat_type_t rt;

	re_parser_check(rp);

	switch (c) {
	case '?': rt = RE_N_AT_MOST_ONE;  break;
	case '+': rt = RE_N_AT_LEAST_ONE; break;
	case '*': rt = RE_N_ANY;          break;
	default:  g_assert_not_reached();
	}

	if (!re_install_repetition(rp, rt))
		return FALSE;

	return re_parse_repetition_modifier(rp);
}

/**
 * Parse a number.
 *
 * @param rp		the parser
 * @param value		where read value is stored
 *
 * @return TRUE if OK, FALSE on error with the parser error set.
 */
static bool
re_parse_unsigned(re_parser_t *rp, size_t *value)
{
	int c;
	char buf[SIZE_T_DEC_BUFLEN + 1];	/* +1 just for convenience here */
	size_t n = 0;
	int error;
	size_t pos = istream_bytes_read(rp->is);

	re_parser_check(rp);
	g_assert(value != NULL);

	while (n < SIZE_T_DEC_BUFLEN && -1 != (c = istream_getc(rp->is))) {
		if (!is_ascii_digit(c)) {
			istream_ungetc(rp->is, c);
			break;
		}
		buf[n++] = c;
	}

	buf[n++] = '\0';
	g_assert(n <= N_ITEMS(buf));	/* No overflow */

	if (1 == n)		/* Empty number */
		return re_parse_error(rp, 0, RE_E_UNPARSEABLE_NUMBER);

	n = parse_size(buf, NULL, 10, &error);

	if (0 == n && error != 0) {
		c = pos - istream_bytes_read(rp->is);	/* Negative value */
		if (EINVAL == error) {
			re_parse_error(rp, c, RE_E_UNPARSEABLE_NUMBER);
		} else if (ERANGE == error) {
			re_parse_error(rp, c, RE_E_NUMBER_OUT_OF_RANGE);
		} else {
			re_parse_error(rp, c, RE_E_ERROR);	/* Should not happen */
		}
		return FALSE;
	}

	*value = n;
	return TRUE;
}

/**
 * Parse min-max repetition specification, with leading '{' already swallowed.
 *
 * @return TRUE on success.
 */
static bool
re_parse_add_min_max(re_parser_t *rp)
{
	size_t min;
	int c;

	re_parser_check(rp);

	if (!re_parse_unsigned(rp, &min))
		return FALSE;

	c = istream_getc(rp->is);
	if (-1 == c)
		return re_parse_error(rp, -1, RE_E_INCOMPLETE_REPEAT_RANGE);

	if ('}' == c) {
		re_repeat_type_t t;
		/* We got "{count}" */
		if (1 == min) t = RE_N_ONCE;
		else          t = RE_N_COUNT;
		if (!re_install_repetition(rp, t, min))
			return FALSE;
	}
	else if (',' == c) {
		c = istream_getc(rp->is);
		if (-1 == c)
			return re_parse_error(rp, -1, RE_E_INCOMPLETE_REPEAT_RANGE);
		if ('}' == c) {
			/* We got "{min,}" */
			if (!re_install_repetition(rp, RE_N_MIN, min))
				return FALSE;
		} else {
			/* Must be "{min,max}" then */
			size_t max;
			istream_ungetc(rp->is, c);

			if (!re_parse_unsigned(rp, &max))
				return FALSE;

			c = istream_getc(rp->is);
			if (-1 == c)
				return re_parse_error(rp, -1, RE_E_INCOMPLETE_REPEAT_RANGE);
			if ('}' == c) {
				/* We got "{min,max}" */
				if (!re_install_repetition(rp, RE_N_RANGE, min, max))
					return FALSE;
			} else {
				return re_parse_error(rp, -1, RE_E_EXPECTED_CLOSING_BRACE);
			}
		}
	} else {
		return re_parse_error(rp, -1, RE_E_EXPECTED_CLOSING_BRACE);
	}

	/* Range can be followed by '?' or '+' */

	return re_parse_repetition_modifier(rp);
}

/**
 * Add a START anchor (^).
 *
 * @return TRUE if OK.
 */
static bool
re_parse_add_start(re_parser_t *rp)
{
	re_parser_check(rp);

	/*
	 * No matching character can have been seen before '^' in this alternative.
	 */

	if (rp->seen_char)
		return re_parse_error(rp, -1, RE_E_LATE_START);

	re_parse_add_element(rp, RE_TYPE_START, FALSE);
	return TRUE;
}

/**
 * Add an END anchor ($).
 */
static void
re_parse_add_end(re_parser_t *rp)
{
	re_parser_check(rp);

	/*
	 * No character can follow '$' until next alternative!
	 */

	re_parse_add_element(rp, RE_TYPE_END, FALSE);
	rp->seen_end = TRUE;
}

/**
 * Add an ANY match (.).
 */
static void
re_parse_add_any(re_parser_t *rp)
{
	re_parser_check(rp);

	/*
	 * If they are compiling with RE_F_NEWLINE, then make ANY an ALL
	 * since we can match \n then.
	 */

	re_parse_add_element(rp,
		(rp->cflags & RE_F_NEWLINE) ? RE_TYPE_ALL : RE_TYPE_ANY, FALSE);
}

/**
 * Assign small index to new BACKREF element.
 */
static void
re_parse_assign_lut_index(re_parser_t *rp, const re_element_t *e)
{
	size_t n;

	re_parser_check(rp);
	g_assert(re_element_is_backref(e));

	n = re_element_get_ref_number(e);

	/*
	 * This table lets us record which group numbers we have already seen
	 * and assigned an index for the runtime LUT.
	 */

	if (NULL == rp->backrefs)
		rp->backrefs = htable_create(HASH_KEY_SELF, 0);

	if (htable_contains(rp->backrefs, size_to_pointer(n)))
		return;

	htable_insert(rp->backrefs, size_to_pointer(n), uint_to_pointer(++rp->refn));
}

/**
 * Parse coming back-reference number and add a BACKREF element to
 * request matching of text already matched by the given group number.
 *
 * If `relative' is TRUE, we can expect either positive numbers (absolute
 * reference to a capturing group) or negative ones (relative reference
 * to a capturing group, -1 being the last one, etc..).
 *
 * A value of 0 is never allowed, as is a reference to a group number that
 * has not yet been seen.
 *
 * @param rp		the parsing context
 * @param relative	whether to accept relative (negative) group numbers.
 *
 * @return TRUE if OK, FALSE on error, with the error code already registered.
 */
static bool
re_parse_add_backref_num(re_parser_t *rp, bool relative)
{
	int c;
	size_t n;
	bool negative = FALSE;
	bool icase = booleanize(rp->cflags & RE_F_ICASE);
	re_element_t *e;

	re_parser_check(rp);

	/*
	 * When back-references are given in the pattern, it is obviously
	 * required to ensure capturing groups will not be neutralized
	 * at compilation time!
	 */

	if (rp->cflags & RE_F_NOSUB)
		return re_parse_error(rp, -1, RE_E_GROUP_CAPTURE_NEEDED);

	c = istream_getc(rp->is);
	if (-1 == c)
		return re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);

	if ('-' == c) {
		if (!relative)
			return re_parse_error(rp, -1, RE_E_UNKNOWN_GROUP_REF);
		negative = TRUE;
	} else {
		istream_ungetc(rp->is, c);
	}

	if (!re_parse_unsigned(rp, &n))
		return FALSE;

	if (negative && n != 0) {
		pslist_t *sl = pslist_nth(rp->closed_subn, n - 1);	/* 0th is first */
		n = pointer_to_uint(pslist_data(sl));	/* n = 0 if sl == NULL */
	}

	if (0 == n || !re_parse_finished_subn(rp, n))
		return re_parse_error(rp, -1 - negative, RE_E_UNKNOWN_GROUP_REF);

	/*
	 * BACKREF elements reference (by absolute number) the capturing group
	 * number they need to match against, regardless of whether they were
	 * specified using a relative or absolute number.
	 *
	 * When we finalize the compiled form, we shall build a LUT (look-up
	 * table) indexed by group number and which will hold a unique internal
	 * reference number: a small index in a stack-allocated re_match_t vector
	 * where we will store the matching boundaries of the group at runtime,
	 * in case they execute the expression without supplying a capture array
	 * (re_match_t vector).
	 *
	 * See longer comment in the definition of the re_regex structure.
	 */

	e = re_parse_add_element(rp, RE_TYPE_BACKREF, icase);
	re_expand_element(e);
	e->u.other->v.subn = n;

	re_parse_assign_lut_index(rp, e);

	return TRUE;
}

/**
 * Parse coming back-reference number, as introduced by \g, which have
 * already been swallowed.  We expect an optional opening '{', a number, and
 * then a closing '}' (if there was an opening one) to declare success.
 *
 * @return TRUE on success, FALSE on error.
 */
static bool
re_parse_add_backref(re_parser_t *rp)
{
	int c;
	bool had_brace;

	re_parser_check(rp);

	c = istream_getc(rp->is);
	if (-1 == c)
		return re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);

	had_brace = '{' == c;

	if (!had_brace)
		istream_ungetc(rp->is, c);

	if (!re_parse_add_backref_num(rp, TRUE))
		return FALSE;

	if (had_brace && '}' != istream_getc(rp->is))
		return re_parse_error(rp, -1, RE_E_EXPECTED_CLOSING_BRACE);

	return TRUE;
}

/**
 * Parse regular expression from stream.
 *
 * @return TRUE on success, FALSE on error.
 */
static bool
re_parse(re_parser_t *rp)
{
	int c;

	re_parser_check(rp);

	while (-1 != (c = istream_getc(rp->is))) {
		bool ok = TRUE;

		/*
		 * Once END was seen, ')' to close a group and '|' to start
		 * a new alternative are the only characters allowed!
		 */

		switch (c) {
		case ')':
			/* This closes a sub-expression when not at the root level */
			if (rp->depth != 0)
				goto done;
			break;		/* Will be handled by below switch */
		case '|':
			re_parse_add_alternative(rp);
			continue;
		default:
			break;
		}

		if (rp->seen_end)
			return re_parse_error(rp, -1, RE_E_END_SEEN);

		switch (c) {
		case '\\':
			c = istream_getc(rp->is);
			if G_UNLIKELY(-1 == c)
				return re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
			switch (c) {
			default:
			case '\\': re_parse_add_char(rp, c);         break;
			case 'a':  re_parse_add_char(rp, '\a');      break;
			case 't':  re_parse_add_char(rp, '\t');      break;
			case 'n':  re_parse_add_char(rp, '\n');      break;
			case 'v':  re_parse_add_char(rp, '\v');      break;
			case 'f':  re_parse_add_char(rp, '\f');      break;
			case 'r':  re_parse_add_char(rp, '\r');      break;
			case 'b':  re_parse_add_boundary(rp, TRUE);  break;
			case 'B':  re_parse_add_boundary(rp, FALSE); break;
			case 'd':
			case 'w':
			case 's':
			case 'D':
			case 'W':
			case 'S':  re_parse_add_char_class(rp, c);   break;
			case 'g':  ok = re_parse_add_backref(rp);    break;
			case 'x':
				c = re_parse_hexa(rp);
				if (-1 == c)
					return FALSE;
				re_parse_add_char(rp, c);
				break;
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				istream_ungetc(rp->is, c);
				ok = re_parse_add_backref_num(rp, FALSE);
				break;
			}
			break;
		case '^': ok = re_parse_add_start(rp);           break;
		case '$': re_parse_add_end(rp);                  break;
		case '.': re_parse_add_any(rp);                  break;
		case '[': ok = re_parse_class(rp);               break;
		case '(': ok = re_parse_group(rp);               break;
		case '?':
		case '*':
		case '+': ok = re_parse_add_repetition(rp, c);   break;
		case '{': ok = re_parse_add_min_max(rp);         break;
		case ')':
			/* no sub-expression, ')' stands for itself then */
			/* FALL THROUGH */
		default:  re_parse_add_char(rp, c);              break;
		}

		if (!ok)
			return FALSE;
	}

	if (rp->depth != 0)
		return re_parse_error(rp, 0, RE_E_INCOMPLETE_GROUP);

	/* FALL THROUGH */

done:

	/*
	 * If we had alternatives, we need to reverse the list to restore
	 * the initial order they used when specifying the pattern, since
	 * we prepend new alternatives for efficiency.
	 */

	if (rp->or != NULL) {
		re_element_t *e = re_elemvec_last_element(rp->or);

		g_assert(e->type == RE_TYPE_OR);

		e->u.alt = pslist_reverse(e->u.alt);	/* Element not expanded */
	}

	/*
	 * Flush last element to propagate information still in the
	 * parser into the compiled structure.
	 */

	{
		re_element_t *e = re_elemvec_last_element(rp->current);
		if (e != NULL)
			re_parse_flush_element(rp, e);
	}

	return TRUE;
}

/**
 * Hashtable iterator to fill LUT.
 */
static void
re_fill_lut(const void *key, void *value, void *data)
{
	re_regex_t *re = data;
	size_t group_n = pointer_to_size(key);
	size_t ref_n = pointer_to_size(value);

	re_regex_check(re);
	g_assert(group_n > 0 && group_n <= re->group_count);
	g_assert(ref_n > 0 && ref_n <= re->backref_count);

	if (RE_USE_BYTE_LUT(re->backref_count))
		re->backrefs.byte_lut[group_n - 1] = ref_n;
	else
		re->backrefs.size_lut[group_n - 1] = ref_n;
}

/**
 * Install LUT for back-reference matching.
 */
static void
re_install_lut(re_regex_t *re, const re_parser_t *rp)
{
	re_regex_check(re);
	re_parser_check(rp);
	g_assert(rp->backrefs != NULL);
	g_assert(rp->subn > 0);
	g_assert(rp->refn > 0);

	/*
	 * Allocate the LUT with proper sizing.
	 *
	 * The size of each item in the LUT is conditioned by the amount
	 * of back-refs we have in the pattern.
	 */

	re->backref_count = rp->refn;
	if (RE_USE_BYTE_LUT(rp->refn)) {
		HALLOC0_ARRAY(re->backrefs.byte_lut, rp->subn);
	} else {
		HALLOC0_ARRAY(re->backrefs.size_lut, rp->subn);
	}

	htable_foreach(rp->backrefs, re_fill_lut, re);
}

/**
 * Discard LUT.
 */
static void
re_free_lut(re_regex_t *re)
{
	re_regex_check(re);

	if (0 == re->backref_count)
		return;

	if (RE_USE_BYTE_LUT(re->backref_count))
		HFREE_NULL(re->backrefs.byte_lut);
	else
		HFREE_NULL(re->backrefs.size_lut);
}

/*
 * Macro used to steal a pointer, nullifying it so it does not get freed.
 */
#define RE_STEAL(x)		x; x = NULL

/**
 * Invoked on parsing success to setup the internal regex fields
 * and finalize compilation with possible optimizations.
 *
 * @param re		the regular expression structure
 * @param rp		the parser (NULL if regex string was empty )
 * @param cflags	compilation flags
 */
static void
re_parsed_ok(re_regex_t *re, re_parser_t *rp, uint32 cflags)
{
	re_regex_check(re);
	g_assert(NULL == rp || RE_PARSER_MAGIC == rp->magic);

	re->icase = booleanize(cflags & RE_F_ICASE);
	re->nosub = booleanize(cflags & RE_F_NOSUB);
	if (NULL == rp) {
		re->u.compiled = NULL;
	} else {
		re->u.compiled = RE_STEAL(rp->root);
		re->group_count = rp->subn;
		if (rp->backrefs != NULL)
			re_install_lut(re, rp);
	}
	re_finalize(re, cflags);
}

/**
 * Compile regular expression.
 *
 * When no longer needed, the compiled form must be disposed of via re_free().
 *
 * @param s			the start of the regular expression
 * @param cflags	compilation flags
 * @param error		if non-NULL, where parsing errors are reported
 *
 * @return compiled regular expression, NULL on error.
 */
re_regex_t *
re_compile(const char *s, uint32 cflags, re_error_t *error)
{
	bstr_t *bs = NULL;
	istream_t *is = NULL;
	re_parser_t *rp = NULL;
	re_regex_t *re = NULL;
	size_t len;

	g_assert(s != NULL);

	len = vstrlen(s);

	if (0 == len)
		goto allocate;		/* Regex will always match */

	bs = bstr_open(s, len, BSTR_F_ERROR);
	is = istream_open_bstr(bs);
	rp = re_parser_alloc(is, cflags);

	if (re_parse(rp)) {
		goto allocate;
	} else if (error != NULL) {
		*error = rp->error;		/* Struct copy */
	}

cleanup:
	if (is != NULL) istream_close(is);
	if (rp != NULL) re_parser_free(rp);
	bstr_free(&bs);

	return re;

allocate:
	WALLOC0(re);
	re->magic = RE_REGEX_MAGIC;
	re->pattern = h_strdup(s);
	re_parsed_ok(re, rp, cflags);

	goto cleanup;
}

/***
 *** ======================== Dumping ========================
 ***/

/**
 * Format a single char with proper escaping for appearing in a string.
 *
 * @param c			the character to format
 *
 * @return pointer to static string
 */
static const char *
re_format_char(int c)
{
	str_t *s = str_private(G_STRFUNC, 4);

	if (is_ascii_cntrl(c)) {
		const char *x = NULL;
		switch (c) {
		case '\a': x = "\\a"; break;
		case '\t': x = "\\t"; break;
		case '\n': x = "\\n"; break;
		case '\v': x = "\\v"; break;
		case '\f': x = "\\f"; break;
		case '\r': x = "\\r"; break;
		case '\b': x = "\\b"; break;
			break;
		default:
			str_printf(s, "\\x%02x", c);
			break;
		}
		if (x != NULL)
			str_cpy(s, x);
	} else if (is_ascii_print(c)) {
		str_reset(s);
		switch (c) {
		case '\\':
			str_putc(s, '\\');
			str_putc(s, '\\');
			break;
		default:
			str_putc(s, c);
			break;
		}
	} else {
		str_printf(s, "\\x%02x", c);
	}

	return str_2c(s);
}

/**
 * Emit a single char with proper escaping.
 *
 * @param c			the character to format
 * @param in_class	whether we are emitting characters in a matching class []
 * @param os		the output stream where formatting is done
 */
static void
re_dump_one_char(int c, bool in_class, ostream_t *os)
{
	if (is_ascii_cntrl(c)) {
		const char *x = NULL;
		switch (c) {
		case '\a': x = "\\a"; break;
		case '\t': x = "\\t"; break;
		case '\n': x = "\\n"; break;
		case '\v': x = "\\v"; break;
		case '\f': x = "\\f"; break;
		case '\r': x = "\\r"; break;
		case '\b':
			/* \b does not mean "word boundary" in a class */
			if (in_class)
				ostream_puts(os, "\\b");
			else
				ostream_puts(os, "[\\b]");
			break;
		default:
			ostream_printf(os, "\\x%02x", c);
			break;
		}
		if (x != NULL)
			ostream_puts(os, x);
	} else if (is_ascii_print(c)) {
		switch (c) {
		case '\\':
			ostream_putc(os, '\\');
			ostream_putc(os, '\\');
			break;
		case '-':
		case ']':
			if (in_class)
				ostream_putc(os, '\\');
			ostream_putc(os, c);
			break;
		case '?':
		case '+':
		case '*':
		case '.':
		case '|':
		case '{':
		case '[':
		case '(':
		case '^':
		case '$':
			if (!in_class)
				ostream_putc(os, '\\');
			/* FALL THROUGH */
		default:
			ostream_putc(os, c);
			break;
		}
	} else {
		ostream_printf(os, "\\x%02x", c);
	}
}

/**
 * Format string with proper character escapes.
 *
 * @param text	the string to format
 *
 * @return pointer to static string.
 */
static const char *
re_format_string(const char *text)
{
	str_t *s = str_private(G_STRFUNC, 80);
	int c;

	str_reset(s);

	while ((c = *text++))
		str_cat(s, re_format_char(c));

	return str_2c(s);
}

/**
 * Dump string with proper character escapes.
 */
static void
re_dump_string(const char *s, bool in_class, ostream_t *os)
{
	int c;
	const uchar *p = (uchar *) s;

	g_assert(s != NULL);

	if (in_class) {
		int prev = -1, start = -1;

		/*
		 * Reconstruct ranges.
		 *
		 * We know the string has been computed in character order, so all
		 * we need to do is maintain a small state to rebuild ranges and
		 * reduce output clutter.
		 *
		 * To keep ranges readable, we reconstruct them only within similar
		 * character subclasses, such as letters, numbers and controls.
		 */

		if ('\0' == *p) {
			/*
			 * We also know that the string cannot be empty, or we would not
			 * be dumping a class but an optimized version (EMPTY or ALL types).
			 * Therefore, a leading NUL byte is not the end of the string!
			 */

			prev = start = 0;
			re_dump_one_char('\0', TRUE, os);
			p++;
		}

		while ((c = *p++)) {
			if (prev + 1 == c) {
				/* Keep going whilst we stay within similar nature */
				if (
					(is_ascii_cntrl(prev) && is_ascii_cntrl(c)) ||
					(is_ascii_digit(prev) && is_ascii_digit(c)) ||
					(is_ascii_alpha(prev) && is_ascii_alpha(c))
				) {
					prev = c;
					continue;
				}
			}
			if (start != prev) {
				/* Finish range we started */
				if (prev - start > 1)
					ostream_putc(os, '-');
				re_dump_one_char(prev, TRUE, os);
			}
			/* Starting new range, maybe? */
			prev = start = c;
			if ('-' == c && 1 == ptr_diff(p, s))
				re_dump_one_char(c, FALSE, os);	/* Don't escape first '-' */
			else
				re_dump_one_char(c, TRUE, os);
		}
		if (start != prev) {
			/* Finish range we started */
			if (prev - start > 1)
				ostream_putc(os, '-');
			re_dump_one_char(prev, TRUE, os);
		}
	} else {
		while ((c = *p++)) {
			re_dump_one_char(c, FALSE, os);
		}
	}
}

/**
 * Format text element to stream.
 */
static void
re_dump_text(const re_element_t *e, ostream_t *os)
{
	g_assert(re_element_is_text(e));

	/*
	 * If, due to group optimization, we have a TEXT element with repetition,
	 * we need to fake a non-capturing group surrounding the text.
	 */

	if (RE_N_ONCE != e->repeat)
		ostream_puts(os, "(?:");

	re_dump_string(re_element_get_text(e), FALSE, os);

	if (RE_N_ONCE != e->repeat)
		ostream_putc(os, ')');
}

/**
 * Format char element to stream.
 */
static void
re_dump_char(const re_element_t *e, ostream_t *os)
{
	int c;

	g_assert(re_element_is_char(e));

	c = re_element_get_char(e);
	re_dump_one_char(c, FALSE, os);
}

/**
 * Format POSIX class(es) to stream.
 */
static void
re_dump_posix_class(const re_element_t *e, ostream_t *os)
{
	uint classes;
	size_t i;

	g_assert(re_element_is_posix_class(e));

	ostream_putc(os, '[');
	if (re_element_is_inverted_posix(e))
		ostream_putc(os, '^');

	classes = re_element_get_classes(e);

	for (i = 0; i < N_ITEMS(re_posix_classes); i++) {
		const tokenizer_t *tok = &re_posix_classes[i];

		if (classes & tok->value)
			ostream_printf(os, "[:%s:]", tok->token);
	}

	ostream_putc(os, ']');
}

/**
 * Format min-max character class to stream.
 *
 * Enclosing [] and ^ for negated classes must be handled by the caller,
 * we are only generating the class boundaries.
 */
static void
re_dump_minmax(int min, int max, ostream_t *os)
{
	g_assert(min <= max);

	re_dump_one_char(min, TRUE, os);
	if (max > min + 1)
		ostream_putc(os, '-');
	if (max != min)
		re_dump_one_char(max, TRUE, os);
}

/**
 * Format character class to stream.
 */
static void
re_dump_class(const re_element_t *e, ostream_t *os)
{
	g_assert(re_element_is_class(e));

	ostream_putc(os, '[');
	if (RE_TYPE_INV_CLASS == e->type || RE_TYPE_INV_CLASS_MM == e->type)
		ostream_putc(os, '^');

	if (RE_TYPE_CLASS_MM == e->type || RE_TYPE_INV_CLASS_MM == e->type) {
		int min, max;

		/* The class is encoded as a set of min/max for faster matching */

		re_minmax_decode(re_element_get_minmax(e), &min, &max);
		g_assert(min <= max);
		re_dump_minmax(min, max, os);
		goto done;
	} else {
		const re_class_t *b = re_element_get_class(e);
		if (b != NULL)
			re_dump_string(re_class2str(b), TRUE, os);
	}

	if (re_element_is_expanded(e)) {
		uint classes = re_element_get_classes(e);

		if (classes & RE_CLASS_D)     ostream_puts(os, "\\d");
		if (classes & RE_CLASS_S)     ostream_puts(os, "\\s");
		if (classes & RE_CLASS_W)     ostream_puts(os, "\\w");
		if (classes & RE_CLASS_NOT_D) ostream_puts(os, "\\D");
		if (classes & RE_CLASS_NOT_S) ostream_puts(os, "\\S");
		if (classes & RE_CLASS_NOT_W) ostream_puts(os, "\\W");
	}

done:
	ostream_putc(os, ']');
}

/**
 * Format back-reference to stream.
 */
static void
re_dump_backref(const re_element_t *e, ostream_t *os)
{
	size_t n;

	g_assert(re_element_is_backref(e));

	n = re_element_get_ref_number(e);

	if (n < 10) {
		ostream_printf(os, "\\%zu", n);
	} else {
		ostream_printf(os, "\\g{%zu}", n);
	}
}

/**
 * Format sub-expression group to stream.
 */
static void
re_dump_group(const re_element_t *e, ostream_t *os)
{
	g_assert(re_element_is_group(e));

	ostream_putc(os, '(');
	if (e->type != RE_TYPE_SUB && e->type != RE_TYPE_SUBN) {
		ostream_putc(os, '?');
		if (RE_TYPE_ATOMIC    == e->type) ostream_putc(os, '>');
		if (RE_TYPE_GROUP     == e->type) ostream_putc(os, ':');
		if (RE_TYPE_AHEAD     == e->type) ostream_putc(os, '=');
		if (RE_TYPE_NOT_AHEAD == e->type) ostream_putc(os, '!');
	}

	re_dump_elemvec(re_element_get_sub(e), os);
	ostream_putc(os, ')');
}

/**
 * Context for the re_dump_trie() traversals.
 */
struct re_dump_trie_ctx {
	bool is_next;
	ostream_t *os;
	str_t *class;
	bool is_route;
};

/**
 * Iterator callback to dump an element in a matching trie MATCH(X).
 */
static void
re_dump_matching_trie(void *key, void *data)
{
	struct re_dump_trie_ctx *ctx = data;
	str_t *s = str_new_from(key);

	/* Dump the alternative or its starting text for ROUTE(X) */

	if (!ctx->is_route && 1 == str_len(s)) {
		/* Save characters for class matching, emitted at the end */
		str_cat_len(ctx->class, str_2c(s), 1);
	} else {
		if (ctx->is_next)
			ostream_putc(ctx->os, '|');
		ctx->is_next = TRUE;
		str_unprintable_escape(s, FALSE);
		ostream_puts(ctx->os, str_2c(s));
	}
	str_destroy_null(&s);
}

/**
 * Iterator callback to dump an element in a routine trie ROUTE(X).
 */
static void
re_dump_routing_trie(const void *key, void *value, void *data)
{
	struct re_dump_trie_ctx *ctx = data;
	re_elemvec_t *rev = value;

	re_elemvec_check(rev);

	/* Dump the starting text */
	re_dump_matching_trie(deconstify_pointer(key), data);

	/* Followed by the remaining of the alternative */
	re_dump_elemvec(rev, ctx->os);
}

/**
 * Dump trie node to the stream.
 */
static void
re_dump_trie(const re_element_t *e, ostream_t *os)
{
	bool is_route = re_element_is_routing_trie(e);
	const trie_t *t = re_element_get_trie(e);
	struct re_dump_trie_ctx ctx;

	ZERO(&ctx);
	ctx.os = os;
	ctx.class = str_new(0);
	ctx.is_route = is_route;

	if (is_route)
		trie_foreach_value(t, re_dump_routing_trie, &ctx);
	else
		trie_foreach(t, re_dump_matching_trie, &ctx);

	if (0 != str_len(ctx.class)) {
		if (ctx.is_next)
			ostream_putc(os, '|');
		if (1 == str_len(ctx.class)) {
			ostream_puts(os, re_format_char(str_at(ctx.class, 0)));
		} else {
			ostream_putc(os, '[');
			re_dump_string(str_2c(ctx.class), TRUE, os);
			ostream_putc(os, ']');
		}
	}

	str_destroy_null(&ctx.class);
}

/**
 * Dump alternatives to the stream.
 */
static void
re_dump_alternative(const re_element_t *e, bool is_alone, ostream_t *os)
{
	bool first = TRUE;

	g_assert(RE_TYPE_OR == e->type || re_element_is_trie(e));

	/*
	 * If the alternative item was extracted from its group, re-add one.
	 * Likewise if it is not the sole element of its vector (e.g.
	 * some look-ahead assertion was prepended to it).
	 */

	if (e->extracted || !is_alone) {
		ostream_puts(os, "(?");
		ostream_putc(os, e->atomic ? '>' : ':');
	}

	if (RE_TYPE_OR == e->type) {
		pslist_t *sl;

		PSLIST_FOREACH(re_element_get_alt(e), sl) {
			if (first)
				first = FALSE;
			else
				ostream_putc(os, '|');
			re_dump_elemvec(sl->data, os);
		}
	} else {
		re_dump_trie(e, os);
	}

	if (e->extracted || !is_alone)
		ostream_putc(os, ')');
}

/**
 * Format repetition of the element to stream.
 */
static void
re_dump_repetition(const re_element_t *e, ostream_t *os)
{
	const char *s;

	g_assert(e != NULL);
	g_assert(e->repeat != RE_N_ONCE);

	s = re_elem_repeat_info(e);
	ostream_puts(os, s);
}

/**
 * Format element to stream.
 *
 * When `rev' is NULL, we're just dumping a single element so we don't
 * need to care about parenthesizes around the initial OR-like expressions,
 * if the current element is an OR-like expression.  Children of that element
 * will be recursively dumped with proper parenthesis because they will get
 * passed a proper `rev'.
 *
 * @param e		the element to format
 * @param extra	whether to display extra elements
 * @parem rev	(optional) the element vector to which element belongs
 * @param n		position of the element in the element vector
 * @param os	output stream
 */
static void
re_dump_internal_element(
	const re_element_t *e, bool extra,
	const re_elemvec_t *rev, size_t n, ostream_t *os)
{
	int c = 0;
	const char *s = NULL;

	if (e->extra && !extra)
		return;			/* Skip extra internal nodes added during finalize */

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:	       c = '^';   goto dump_char;
	case RE_TYPE_END:	       c = '$';   goto dump_char;
	case RE_TYPE_ANY:	       c = '.';   goto dump_char;
	case RE_TYPE_ALL:	       s = "[^]"; goto dump_string;
	case RE_TYPE_EMPTY:	       s = "[]";  goto dump_string;
	case RE_TYPE_D_CLASS:      s = "\\d"; goto dump_string;
	case RE_TYPE_W_CLASS:      s = "\\w"; goto dump_string;
	case RE_TYPE_S_CLASS:      s = "\\s"; goto dump_string;
	case RE_TYPE_NOT_D_CLASS:  s = "\\D"; goto dump_string;
	case RE_TYPE_NOT_S_CLASS:  s = "\\S"; goto dump_string;
	case RE_TYPE_NOT_W_CLASS:  s = "\\W"; goto dump_string;
	case RE_TYPE_IS_BOUNDARY:  s = "\\b"; goto dump_string;
	case RE_TYPE_NOT_BOUNDARY: s = "\\B"; goto dump_string;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		re_dump_posix_class(e, os);
		break;
	case RE_TYPE_TEXT:
		re_dump_text(e, os);
		break;
	case RE_TYPE_CHAR:
		re_dump_char(e, os);
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		re_dump_class(e, os);
		break;
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		re_dump_group(e, os);
		break;
	case RE_TYPE_BACKREF:
		re_dump_backref(e, os);
		break;
	case RE_TYPE_OR:
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
	   /*
		* We need to special-case the dumping of OR elements since we may
		* prepend a look-ahead block in front of it.  This will be an
		* extra element, not dumped, so we can act as if the OR element
		* was alone in its block: no need to parenthesize it.
		*
		* However, if the OR block is explicitly preceded by a user-supplied
		* look-ahead assertion for instance, we need to parenthesize the OR
		* block explicitly, since OR has the lowest precedence.
		*/
		if (rev != NULL) {
			bool ecnt = rev->ecnt;
			bool is_alone;

			if (ecnt != 0 && RE_TYPE_NEXT == rev->elements[ecnt - 1].type)
				ecnt--;					/* NEXT elements do not count */
			is_alone = 1 == ecnt;
			if (!is_alone && n != 0 && rev->elements[n - 1].extra)
				is_alone = 2 == ecnt;	/* Extra elements are not dumped */
			re_dump_alternative(e, is_alone, os);
		} else {
			re_dump_alternative(e, TRUE, os);
		}
		break;
	case RE_TYPE_RETURN:
		break;
	case RE_TYPE_NEXT:
		if (extra) {
			size_t i = e->u.other->x.next.n - 1;
			re_elemvec_t *pev = e->u.other->x.next.vec;

			re_elemvec_check(pev);
			g_assert(i < pev->ecnt);

			ostream_puts(os, "closing of <");
			re_dump_element(&pev->elements[i], os);
			ostream_putc(os, '>');
		}
		break;
	case RE_TYPE_MAX:          g_assert_not_reached();
	}

	/* FALL THROUGH */

show_repetition:

	if (e->repeat != RE_N_ONCE)
		re_dump_repetition(e, os);

	return;

dump_char:
	ostream_putc(os, c);
	goto show_repetition;

dump_string:
	ostream_puts(os, s);
	goto show_repetition;
}

/**
 * Dump element recursively to output stream.
 */
static void
re_dump_element(const re_element_t *e, ostream_t *os)
{
	/*
	 * We explicitly request that extra elements be shown in case
	 * we are on a node added during re_finalize().  If we are called,
	 * it is precisely to be able to show the content of the element.
	 *
	 * This is just for this initial element: recursive calls through
	 * re_dump_elemvec() will not request the displaying of extra
	 * elements in the vectors.
	 */

	re_dump_internal_element(e, TRUE, NULL, 0, os);
}

/**
 * Format element vector to stream.
 */
static void
re_dump_elemvec(const re_elemvec_t *rev, ostream_t *os)
{
	size_t i;

	re_elemvec_check(rev);

	for (i = 0; i < rev->ecnt; i++) {
		re_element_t *e = &rev->elements[i];

		re_dump_internal_element(e, FALSE, rev, i, os);
	}
}

/**
 * A dump function to a stream for a regular expression.
 */
typedef void (*re_dump_fn_t)(const re_regex_t *re, ostream_t *os);

static char *
re_apply_as_string(const re_regex_t *re, re_dump_fn_t cb)
{
	str_t *s = str_new(0);

	re_regex_check(re);

	if (!re->is_empty) {
		ostream_t *os;

		os = ostream_open_str(s);
		(*cb)(re, os);
		ostream_close(os);
	}

	return str_s2c_null(&s);
}

/**
 * Format compiled regular expression to stream.
 *
 * The output is an equivalent regular expression, which may not be a
 * string identical to the pattern but which should match identically.
 */
static void
re_dump(const re_regex_t *re, ostream_t *os)
{
	if (re->is_simple) {
		if (re->at_start || re->at_end) {
			if (re->at_start)
				ostream_putc(os, '^');
			ostream_puts(os, re->u.anchored);
			if (re->at_end)
				ostream_putc(os, '$');
		} else {
			ostream_puts(os, pattern_string(re->u.cp));
		}
	} else {
		re_dump_elemvec(re->u.compiled, os);
	}
}

/**
 * Format compiled regular expression to halloc()'ed string.
 *
 * The output string is a reconstructed pattern that shows some of the
 * internal optimizations performed by the compiler.
 *
 * If that output string is re-compiled, its dump should produce an identical
 * string, meaning we reached a fixed point for the compilation function.
 *
 * @return halloc()'ed string representing the compiled regular expression.
 */
char *
re_dump_as_string(const re_regex_t *re)
{
	return re_apply_as_string(re, re_dump);
}

/**
 * Format compiled First Char map as a character class to stream.
 *
 * This is intended to be used in automated testing, since it is critical
 * that the first character map be accurate or we will miss some matching
 * positions!
 */
static void
re_fcmap_dump(const re_regex_t *re, ostream_t *os)
{
	if (NULL == re->fcmap)
		return;

	/*
	 * We do not include the leading and trailing '[]' here, since this
	 * is naturally implied.
	 */

	re_dump_string(re_fcmap2str(re->fcmap), TRUE, os);
}

/**
 * Format compiled First Char map to halloc()'ed string.
 *
 * This is formatted as a character class, i.e. "a-d" will stand for "abcd"
 * but without the implied opening '[' and closing ']'.
 *
 * @return halloc()'ed string representing the compiled regular expression.
 */
char *
re_fcmap_dump_as_string(const re_regex_t *re)
{
	return re_apply_as_string(re, re_fcmap_dump);
}

#define RE_SHOW_INDENT	2	/* chars per level of indentation */

/**
 * Context for the re_show() traversal.
 */
struct re_show_ctx {
	size_t depth;		/* Current vector depth */
	htable_t *vectors;	/* To number vectors */
	ostream_t *os;		/* Output stream */
	pslist_t *vecs;		/* Stack of vectors, latest at beginning */
};

/**
 * Emit indentation to stream.
 *
 * @param ctx		traversal context
 * @param n			amount of characters per indentation
 */
static void
re_show_indent(const struct re_show_ctx *ctx, size_t n)
{
	size_t m = ctx->depth * n;

	while (m--)
		ostream_putc(ctx->os, ' ');
}

/**
 * Number vectors we encounter during traversal.
 *
 * @param ctx		traversal context
 * @param ev		the vector we want to number
 *
 * @return the vector number associated with given element vector.
 */
static size_t
re_show_vector_number(struct re_show_ctx *ctx, const re_elemvec_t *ev)
{
	size_t n = pointer_to_size(htable_lookup(ctx->vectors, ev));

	if (0 == n) {
		/* First time, assign new number */
		n = 1 + htable_count(ctx->vectors);
		htable_insert(ctx->vectors, ev, size_to_pointer(n));
	}

	return n;
}

/**
 * Additional context for trie dumping.
 */
struct re_show_trie_ctx {
	struct re_show_ctx *ctx;		/* The show context */
	const re_elemvec_t *ev;			/* Element vector where trie is */
	size_t i;						/* Index of trie within vector */
};

/**
 * Trie iterator to display string keys and optionally the element vector to
 * which they refer.
 */
static void
re_show_trie(const void *key, void *value, void *data)
{
	const char *string = key;
	re_elemvec_t *ev = value;
	struct re_show_trie_ctx *tc = data;
	struct re_show_ctx *ctx = tc->ctx;
	str_t *s = str_new(0);

	re_show_indent(ctx, RE_SHOW_INDENT);
	str_cpy(s, string);
	str_unprintable_escape(s, FALSE);
	ostream_printf(ctx->os, "[%zu] %2zu:  \"%s\"",
		re_show_vector_number(ctx, tc->ev), 1 + tc->i, str_2c(s));

	if (value != NULL) {
		ostream_printf(ctx->os, " -> item 1@%zu",
			re_show_vector_number(ctx, ev));
	}

	ostream_putc(ctx->os, '\n');
	str_destroy_null(&s);
}

/**
 * Show element.
 */
static void
re_show_element(void *data, void *udata)
{
	re_element_t *e = data;
	struct re_show_ctx *ctx = udata;
	str_t *s = str_new(0);
	re_elemvec_t *ev = ctx->vecs->data;
	size_t i = e - &ev->elements[0];

	re_elemvec_check(ev);

	switch (e->type) {
	case RE_TYPE_TEXT:
		str_printf(s, " \"%s\"", re_format_string(re_element_get_text(e)));
		break;
	case RE_TYPE_CHAR:
		str_printf(s, " \'%s\'", re_format_char(re_element_get_char(e)));
		break;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
		{
			ostream_t *os;

			os = ostream_open_str(s);
			ostream_putc(os, ' ');
			re_dump_posix_class(e, os);
			ostream_close(os);
		}
		break;
	case RE_TYPE_SUBN:
		str_printf(s, " #%u", re_element_get_sub_number(e));
		break;
	case RE_TYPE_BACKREF:
		str_printf(s, " #%u", re_element_get_ref_number(e));
		break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		{
			ostream_t *os;
			int min, max;

			os = ostream_open_str(s);
			ostream_putc(os, ' ');
			re_dump_class(e, os);

			if (
				RE_TYPE_CLASS_MM == e->type ||
				RE_TYPE_INV_CLASS_MM == e->type
			) {
				re_minmax_decode(re_element_get_minmax(e), &min, &max);
				ostream_printf(os, " = [%d", min);
				if (min != max)
					ostream_printf(os, ", %d", max);
				ostream_putc(os, ']');
			}

			ostream_close(os);
		}
		break;
	case RE_TYPE_NEXT:
		{
			size_t n = e->u.other->x.next.n;
			re_elemvec_t *nev = e->u.other->x.next.vec;

			re_elemvec_check(nev);
			if (n >= nev->ecnt) {
				str_printf(s, " -> end @%zu",
					re_show_vector_number(ctx, nev));
			} else {
				/* Uses index base of 1 for display, hence the "1 + n" */
				str_printf(s, " -> item %zu@%zu",
					1 + n, re_show_vector_number(ctx, nev));
			}
		}
		break;
	}

	if (
		RE_TYPE_OR == e->type ||
		re_element_is_group(e) ||
		re_element_is_trie(e)
	) {
		str_catf(s, " minlen=%zu, maxlen=%s",
			re_element_get_minlen(e), re_max2str(re_element_get_maxlen(e)));
	}

	re_show_indent(ctx, RE_SHOW_INDENT);
	ostream_printf(ctx->os, "[%zu] %2zu: %s%s",
		re_show_vector_number(ctx, ev), 1 + i,
		re_elem_info_short(e), str_2c(s));

	if (
		e->extra ||
		e->extracted ||
		e->inserted ||
		e->atomic ||
		re_element_is_expanded(e) ||
		(
			re_element_get_minlen(e) != 0 &&
			re_element_get_minlen(e) == re_element_get_maxlen(e)
		)
	) {
		ostream_puts(ctx->os, " <");
		if (
				re_element_get_minlen(e) != 0 &&
				re_element_get_minlen(e) == re_element_get_maxlen(e)
		)
			ostream_putc(ctx->os, 'f');
		if (e->extra)                  ostream_putc(ctx->os, 'a');
		if (e->extracted)              ostream_putc(ctx->os, 'x');
		if (e->inserted)               ostream_putc(ctx->os, 'i');
		if (e->atomic)                 ostream_putc(ctx->os, '+');
		if (re_element_is_expanded(e)) ostream_putc(ctx->os, 'E');
		ostream_putc(ctx->os, '>');
	}
	ostream_putc(ctx->os, '\n');

	/*
	 * Additional information for MATCH / ROUTE elements.
	 */

	switch (e->type) {
	case RE_TYPE_MATCH:
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		{
			trie_t *t = re_element_get_trie(e);
			struct re_show_trie_ctx tc;

			ZERO(&tc);
			tc.ctx = ctx;
			tc.ev = ev;
			tc.i = i;

			trie_foreach_value(t, re_show_trie, &tc);
		}
		break;
	}
	str_destroy_null(&s);
}

/**
 * Entering vector.
 */
static bool
re_show_enter_vector(const void *data, void *udata)
{
	const re_elemvec_t *ev = data;
	struct re_show_ctx *ctx = udata;
	size_t n;

	re_elemvec_check(ev);

	ctx->depth++;
	ctx->vecs = pslist_prepend_const(ctx->vecs, ev);

	re_show_indent(ctx, RE_SHOW_INDENT);
	n = re_show_vector_number(ctx, ev);

	ostream_printf(ctx->os, "[%zu] (cap=%zu, cnt=%zu, minlen=%zu, maxlen=%s)\n",
		n, ev->ecap, ev->ecnt, ev->minlen, re_max2str(ev->maxlen));

	return TRUE;		/* Traverse it */
}

/**
 * Leaving vector.
 */
static void
re_show_leave_vector(void *data, void *udata)
{
	re_elemvec_t *ev = data;
	struct re_show_ctx *ctx = udata;

	re_elemvec_check(ev);
	g_assert(ctx->depth != 0);

	ctx->depth--;
	(void) pslist_shift(&ctx->vecs);
}

/**
 * Show internal structure of the compiled regular expression, for
 * debugging purposes.
 */
static void
re_show(const re_regex_t *re, ostream_t *os)
{
	size_t n;

	ostream_printf(os, "Pattern : %s\n", re->pattern);
	ostream_printf(os, "Case    : %ssensitive\n", re->icase ? "in" : "");

	if (re->is_simple) {
		if (re->at_start || re->at_end) {
			ostream_printf(os, "String  : %s\n",
				re_format_string(re->u.anchored));
			ostream_printf(os, "Anchored: %s%s\n",
				re->at_start ? "^" : "",
				re->at_end   ? "$" : "");
		} else {
			ostream_printf(os, "Search  : %s\n",
				re_format_string(pattern_string(re->u.cp)));
		}
	} else {
		char *dump;
		struct re_show_ctx ctx;

		dump = re_dump_as_string(re);

		if (re->must != NULL)
			ostream_printf(os, "Needed  : %s\n",
				re_format_string(pattern_string(re->must)));

		if (re->fcmap != NULL) {
			ostream_puts(os, "FC Map  : [");
			re_dump_string(re_fcmap2str(re->fcmap), TRUE, os);
			ostream_puts(os, "]\n");
		}

		ostream_printf(os, "Has END : %s\n", re->end != NULL ? "yes" : "no");
		ostream_printf(os, "Compiled: %s\n", dump);
		ostream_puts(os,   "Tree    :\n");

		HFREE_NULL(dump);

		ZERO(&ctx);
		ctx.os = os;
		ctx.vectors = htable_create(HASH_KEY_SELF, 0);

		n = re_traverse_once(re->u.compiled,
				TRUE,					/* pre_e */
				NULL,					/* enter */
				re_show_element,		/* action */
				FALSE,					/* pre_v */
				re_show_enter_vector,	/* venter */
				re_show_leave_vector,	/* vaction */
				&ctx);

		ostream_printf(os,  "Dumped %zu element%s in %zu vector%s\n",
			PLURAL(n), PLURAL(htable_count(ctx.vectors)));

		g_assert(NULL == ctx.vecs);
		htable_free_null(&ctx.vectors);
	}
}

/**
 * Show a representation of the internal tree of the compiled regular
 * expression, as well as extra information gathered during compilation
 * such as constant string that must be present, anchoring, etc...
 *
 * This is useful for debugging and to witness the transformations performed
 * by the regular-expression optimizer.  The companion "re-test" program can
 * be used to examine pattern compilation with and without optimizations.
 *
 * For instance, compare the outputs of these commands to witness samples
 * of the various transformations that result in more efficient execution:
 *
 * 		re-test -E "abc|def|hgi" -O
 * 		re-test -E "abc|def|hgi"
 *
 * 		re-test -E "ab|abx|abc" -O
 * 		re-test -E "ab|abx|abc"
 *
 * 		re-test -E "alpha|alphabet|alphonse" -O
 * 		re-test -E "alpha|alphabet|alphonse"
 *
 * 		re-test -E "albert|alpha|alphonse" -O
 * 		re-test -E "albert|alpha|alphonse"
 *
 * 		re-test -E "[a-z]|[0-9]|_" -i -O
 * 		re-test -E "[a-z]|[0-9]|_" -i
 *
 * 		re-test -E "[a-z]1+|[0-9]2+|_3+" -O
 * 		re-test -E "[a-z]1+|[0-9]2+|_3+"
 *
 * 		re-test -E "cd+|cg.*?|(?:d|c)+" -O
 * 		re-test -E "cd+|cg.*?|(?:d|c)+"
 *
 * (the -O switch disables the optimizations, -E examines the pattern
 * by compiling it and showing the tree, -i compiles case-insensitively).
 *
 * @return halloc()'ed string showing internal structure, for debugging.
 */
char *
re_show_as_string(const re_regex_t *re)
{
	return re_apply_as_string(re, re_show);
}

/***
 *** ======================== Cleaning ========================
 ***/

/**
 * Free items that cannot remain after a recompilation.
 */
static void
re_free_recompiled(re_regex_t *re)
{
	re_regex_check(re);

	if (re->is_simple) {
		if (re->at_start || re->at_end)
			hfree((char *) re->u.anchored);
		else
			pattern_free_null(&re->u.cp);
	} else if (!re->is_empty) {
		re_elemvec_recursive_free(re->u.compiled);
	}

	pattern_free_null(&re->must);
	re_free_lut(re);
	WFREE_ARRAY_NULL(re->fcmap, RE_ALPHABET);

	re->backref_count = re->group_count = 0;
}

/**
 * Free compiled regular expression.
 */
void
re_free(re_regex_t *re)
{
	re_regex_check(re);

	re_free_recompiled(re);
	hfree(deconstify_char(re->pattern));
	re->magic = 0;
	WFREE(re);
}

/***
 *** ======================== Matching ========================
 ***/

/**
 * Context on the stack that records how many times a given element
 * has been matched so far.
 *
 * This is used when handling patterns such as "(a.*b){3,}" and the parent
 * node has a repeat count of {3,} so it must be re-traversed by the sub
 * expression "(a.*b)" when it matches (to re-attempt the sub-expression
 * if we have not reached the minimum count yet).
 *
 * Since this is allocated on the stack, we store the smallest information
 * possible: the element at which we are in, and the amount of times it has
 * been matched so far, plus a pointer to any next item, so as to create
 * a list.
 *
 * And of course, most critical, the last text pointer before we got a
 * match: if we recurse back and are asked to iterate for another match,
 * and the text pointer has not moved, we know we are looping forever and
 * must not iterate again.  For instance, here is a pathological pattern:
 * ((?:..+|.*?|.{3})*)b on the following text "abb" which would cause an
 * endless loop if we were not protecting ourselves.
 *
 * The head of the list is kept in the execution context.
 */
typedef struct re_match_count {
	const re_element_t *e;			/* The element being matched */
	size_t n;						/* Amount of times it was matched so far */
	const uchar *tp;				/* Text position BEFORE we attempted match */
	slink_t link;					/* Pointer up the calling chain */
} re_match_count_t;


enum re_exec_ctx_magic { RE_EXEC_CTX_MAGIC = 0x23a49ac2 };

/**
 * Regular expression matching context.
 */
struct re_exec_ctx {
	enum re_exec_ctx_magic magic;
	const re_regex_t *re;		/* Regular expression */
	const uchar *text;			/* Text against which match is attempted */
	const uchar *tp;			/* Current text position */
	const uchar *tend;			/* If non-NULL, known first byte past text end */
	const uchar *tprobed;		/* If non-NULL, last limit probed for end */
	re_match_t *mvec;			/* Where matching positions are stored */
	re_match_t *bvec;			/* Back-refs match positions (on the stack) */
	size_t mcnt;				/* Amount of entries in mvec[] */
	ssize_t max_stack;			/* Maximum stack allowed */
	size_t max_stack_used;		/* Tracks maximum stack usage */
	const void *stack_top;		/* Stack top at beginning */
	jmp_buf matched;			/* Where to return on a successful match */
	eslist_t multi;				/* Multi-nodes being handled */
	re_match_count_t tkey;		/* Tracking key, structure used for lookups */
	uint eflags;				/* Matching flags */
	uint icase:1;				/* If TRUE, matching case-insensitively */
	struct {
		const re_element_t *e;	/* The element to look for */
		const uchar *tp;		/* The position when we computed it */
		const uchar *result;	/* The actual result */
		bool lazy;				/* Whether computation was lazy */
	} seen_element;				/* Cache for re_seeing_element() */
#ifdef PRIVLOG_ENABLED
	const uchar *match_start;	/* Match starting point */
	size_t match_calls;			/* Calls to re_exec_match_here() */
	size_t match_depth;			/* Recursion depth in re_exec_match_here() */
	size_t max_match_depth;		/* Tracks maximum recursion depth */
#endif
};

static inline void
re_exec_ctx_check(const struct re_exec_ctx * const rec)
{
	g_assert(rec != NULL);
	g_assert(RE_EXEC_CTX_MAGIC == rec->magic);
}

static bool re_exec_match_here(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n, bool next);

/**
 * Record match position if we can.
 *
 * The beginning of the match is indicated, the end of the match is the
 * current position in the execution context.
 *
 * Note that this is always recorded (if the mvec[] vector is not NULL)
 * regardless of whether the RE_X_NOSUB flag is given.
 *
 * @param rec	the execution context
 * @param n		the group number
 * @param start	where we started to match
 *
 * @return TRUE as convenience.
 */
static bool
re_exec_matched(struct re_exec_ctx *rec, size_t n, volatile const uchar *start)
{
	REX_ENTRY;

	REX_DEBUG(RE_D_MATCHPOS,
		"n=%zu, start=%zu, end=%zu, %zu position%s",
		n, start - rec->text, rec->tp - rec->text,
		PLURAL(rec->mcnt));

	if (rec->mvec != NULL && n < rec->mcnt) {
		rec->mvec[n].re_start = start - rec->text;
		rec->mvec[n].re_end = rec->tp - rec->text;	/* Byte past match */

		REX_DEBUG(RE_D_MATCHPOS, "match[%zu]: %zu byte%s at %zu",
			n, PLURAL(rec->mvec[n].re_end - rec->mvec[n].re_start),
			rec->mvec[n].re_start);
	}

	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Find place on the stack where we can register match for group #n,
 * so that back-refs can find the matched text.
 *
 * @param rec	the execution context
 * @param n		the group number
 *
 * @return the re_match_t structure were we shall store matching boundaries,
 * NULL if capturing group #n is not used as a back-reference.
 */
static re_match_t *
re_exec_match_backref_find(const struct re_exec_ctx *rec, size_t n)
{
	size_t i;
	const re_regex_t *re;

	re_exec_ctx_check(rec);

	re = rec->re;
	re_regex_check(re);
	g_assert(n <= re->group_count);

	if (0 == re->backref_count)
		return NULL;		/* No group is ever used as a back-reference */

	g_assert(rec->bvec != NULL);

	if (RE_USE_BYTE_LUT(re->backref_count)) {
		g_assert(re->backrefs.byte_lut != NULL);
		i = re->backrefs.byte_lut[n - 1];
	} else {
		g_assert(re->backrefs.size_lut != NULL);
		i = re->backrefs.size_lut[n - 1];
	}

	g_assert(i <= re->backref_count);

	if (0 == i)
		return NULL;		/* Group not used as a back-reference */

	return &rec->bvec[i - 1];
}

/**
 * Computes length of back-reference to match.
 */
static size_t NO_INLINE
re_exec_match_backref_length(
	const struct re_exec_ctx *rec, const re_element_t *e)
{
	re_match_t *m;

	m = re_exec_match_backref_find(rec, re_element_get_ref_number(e));

	g_assert(m != NULL);		/* If it fails, we have an RE compilation bug */

	return m->re_end - m->re_start;
}

/**
 * Mark current position as match start for group #n, if there is enough
 * space in the matching vector for group #n.
 *
 * @param rec	the execution context
 * @param n		the group number
 */
static void
re_exec_match_group_start(struct re_exec_ctx *rec, size_t n)
{
	re_exec_ctx_check(rec);
	g_assert(n != 0);

	REX_ENTRY;

	REX_DEBUG(RE_D_MATCHPOS,
		"n=%zu, start=%zu ('%c')%s",
		n, rec->tp - rec->text, *rec->tp,
		n >= rec->mcnt ? " unrecordable" : "");

	if (rec->mvec != NULL && n < rec->mcnt)
		rec->mvec[n].re_start = rec->tp - rec->text;

	if (rec->bvec != NULL) {
		re_match_t *m = re_exec_match_backref_find(rec, n);
		if (m != NULL)
			m->re_start = rec->tp - rec->text;
	}

	REX_RETURN_VOID;
}

/**
 * Mark current position as match end for group #n, if there is enough
 * space in the matching vector for group #n.
 *
 * @param rec	the execution context
 * @param n		the group number
 */
static void
re_exec_match_group_end(struct re_exec_ctx *rec, size_t n)
{
	re_exec_ctx_check(rec);
	g_assert(n != 0);

	REX_ENTRY;

	REX_DEBUG(RE_D_MATCHPOS,
		"n=%zu, end=%zu ('%c')%s",
		n, rec->tp - rec->text, *rec->tp,
		n >= rec->mcnt ? " unrecordable" : "");

	if (rec->mvec != NULL && n < rec->mcnt) {
		g_assert(rec->mvec[n].re_start != (ssize_t) -1);
		rec->mvec[n].re_end = rec->tp - rec->text;
	}

	if (rec->bvec != NULL) {
		re_match_t *m = re_exec_match_backref_find(rec, n);
		if (m != NULL) {
			m->re_end = rec->tp - rec->text;

			REX_DEBUG(RE_D_MATCHPOS, "backref #%zu captured: %.*s",
				m - rec->bvec + 1, (int) (m->re_end - m->re_start),
				rec->text + m->re_start);
		}
	}

	REX_RETURN_VOID;
}

/**
 * Computes text end and stores it in the execution context.
 *
 * @return end of text.
 */
static const uchar *
re_exec_find_end(struct re_exec_ctx *rec)
{
	const char *text = (char *) rec->text;

	if (NULL == rec->tend) {
		const char *end;

		/*
		 * When RE_X_MULTI_LINE is given, the first \n we see is the actual end
		 * that '$' will match, so we do not wish to go past this \n.
		 */

		if (rec->eflags & RE_X_MULTI_LINE) {
			end = vstrchr(text, '\n');
			if (NULL == end)
				end = vstrchr(text, '\0');	/* No '\n', compute physical end */
		} else {
			end = vstrchr(text, '\0');		/* Compute physical text end */
		}
		rec->tend = (uchar *) end;		/* And cache it */
	}

	return rec->tend;
}

#if PRIVLOG_ENABLED
/**
 * Logs current position when debugging.
 */
static void
re_exec_log_where_full(const struct re_exec_ctx *rec, const char *caller)
{
	char buf[80];
	size_t d = rec->tp - rec->text;
	size_t matched;

	g_assert(size_is_non_negative(d));

	if (rec->tend != NULL) {
		size_t n = ptr_diff(rec->tend, rec->tp);
		str_bprintf(ARYLEN(buf), "end in %zu byte%s", PLURAL(n));
	} else {
		str_bprintf(ARYLEN(buf), "end unknown");
	}

	/* No REX_ENTRY -- logging is done in the context of the caller */

	if (rec->icase && is_ascii_upper(*rec->tp)) {
		REX_DEBUG(RE_D_WHERE,
			"%s(): at pos=%zu, c='%c' -> '%c' (%s)",
			caller, ptr_diff(rec->tp, rec->text),
			*rec->tp, ascii_tolower(*rec->tp), buf);
	} else {
		REX_DEBUG(RE_D_WHERE,
			"%s(): at pos=%zu, c='%c' (%s)",
			caller, ptr_diff(rec->tp, rec->text), *rec->tp, buf);
	}

	REX_DEBUG(RE_D_WHERE, ">>%.10s<<", rec->tp - MIN(3, d));

	if (0 == d)
		REX_DEBUG(RE_D_WHERE, "  ^");
	else
		REX_DEBUG(RE_D_WHERE, "  %.*s^", (int) MIN(3, d), "    ");

	matched = rec->tp - rec->match_start;
	REX_DEBUG(RE_D_WHERE, "already matched: %.*s (%zu byte%s from pos=%zu)",
		(int) matched, rec->match_start, PLURAL(matched),
		rec->match_start - rec->text);
}
#define re_exec_log_where(x)	re_exec_log_where_full((x), G_STRFUNC)
#else	/* !PRIVLOG_ENABLED */
#define re_exec_log_where(x)
#endif	/* PRIVLOG_ENABLED */

/**
 * Are we seeing the text downstream in the yet-unmatched text?
 *
 * @return start of last possible match in text if not lazy, first one
 * otherwise, NULL if not found.
 */
static const uchar *
re_seeing_text(struct re_exec_ctx *rec, const re_element_t *e, bool lazy)
{
	bool icase = e->icase;
	const char *text = re_element_get_text(e);
	const char *p;
	const uchar *start = NULL, *next_start;
	size_t n, len;
	size_t min = re_element_get_repeat_min(e);

	re_exec_ctx_check(rec);
	g_assert(min != 0);

	REX_ENTRY;
	REX_DEBUG(RE_D_CONSTANT, "looking for \"%s\", min=%zu (%s mode)",
		text, min, lazy ? "lazy" : "greedy");

	/*
	 * Find the last possible matching start giving us the minimal amount
	 * of repetitions we want.
	 */

	len = vstrlen(text);
	p = (char *) rec->tp;

	for (;;) {
		p = icase ? vstrcasestr(p, text) : vstrstr(p, text);
		next_start = (uchar *) p;

		if (NULL == p)
			REX_RETURN(const uchar *, "[last match] %p", start);

		REX_DEBUG(RE_D_CONSTANT, "match at %p", p);

		p += len;		/* Move past first match in case we have repetitions */

		n = min;
		while (--n) {
			p = icase ? is_strcaseprefix(p, text) : is_strprefix(p, text);
			if (NULL == p) {
				REX_DEBUG(RE_D_CONSTANT, "failed repetition");
				goto next;
			}
		}

		start = next_start;		/* OK, got a new match! */

		if (lazy)
			REX_RETURN(const uchar *, "[first match] %p", start);

		/* FALL THROUGH */

	next:
		p = (char *) (start + 1);
	}
}

/**
 * Are we seeing the char downstream in the yet-unmatched text?
 *
 * @return start of last possible match in text if not lazy, first otherwise,
 * NULL if not found.
 */
static const uchar *
re_seeing_char(struct re_exec_ctx *rec, const re_element_t *e, bool lazy)
{
	bool icase = e->icase;
	int c = re_element_get_char(e);
	const char *p;
	const uchar *start = NULL, *next_start;
	size_t n;
	char buf[2];
	size_t min = re_element_get_repeat_min(e);

	re_exec_ctx_check(rec);
	g_assert(min != 0);

	REX_ENTRY;
	REX_DEBUG(RE_D_CONSTANT, "looking for \'%c\', min=%zu (%s mode)",
		c, min, lazy ? "lazy" : "greedy");

	if (lazy)
		goto lazy;

	/*
	 * Optimize for the likely case of min == 1.
	 */

	if (1 == min) {
		p = vmemrchr((char *) rec->tp, c, re_exec_find_end(rec) - rec->tp + 1);

		if (NULL == p && icase && is_ascii_alpha(c)) {
			c = ascii_toupper(c);
			p = vmemrchr((char *) rec->tp, c, rec->tend - rec->tp + 1);
		}

		REX_RETURN(const uchar *, "[min=1 last match] %p", (uchar *) p);
	}

	/*
	 * Find the last possible matching start giving us the minimal amount
	 * of repetitions we want.
	 */

	p = (char *) rec->tp;

	if (icase) {
		buf[0] = c;
		buf[1] = '\0';
	}

	for (;;) {
		p = icase ? vstrcasestr(p, buf) : vstrchr(p, c);
		next_start = (uchar *) p;

		if (NULL == p)
			REX_RETURN(const uchar *, "[last match] %p", start);

		REX_DEBUG(RE_D_CONSTANT, "match at %p", p);

		n = min;
		while (--n) {
			if (icase) {
				if (ascii_tolower(*++p) == c)
					continue;
			} else {
				if (*++p == c)
					continue;
			}
			REX_DEBUG(RE_D_CONSTANT, "failed repetition");
			goto next;
		}

		/* FALL THROUGH */

		start = next_start;		/* OK, got a new match! */
	next:
		p = (char *) (next_start + 1);
	}

lazy:
	/*
	 * Optimize for the likely case of min == 1.
	 */

	if (1 == min) {
		p = vstrchr((char *) rec->tp, c);

		if (NULL == p && icase && is_ascii_alpha(c)) {
			c = ascii_toupper(c);
			p = vstrchr((char *) rec->tp, c);
		}

		REX_RETURN(const uchar *, "[min=1 first match] %p", (uchar *) p);
	}

	/*
	 * Find the first possible matching start giving us the minimal amount
	 * of repetitions we want.
	 */

	p = (char *) rec->tp;

	if (icase) {
		buf[0] = c;
		buf[1] = '\0';
	}

	for (;;) {
		p = icase ? vstrcasestr(p, buf) : vstrchr(p, c);
		next_start = (uchar *) p;

		if (NULL == p)
			REX_RETURN(const uchar *, "[no match] %p", NULL);

		REX_DEBUG(RE_D_CONSTANT, "match at %p", p);

		n = min;
		while (--n) {
			if (icase) {
				if (ascii_tolower(*++p) == c)
					continue;
			} else {
				if (*++p == c)
					continue;
			}
			REX_DEBUG(RE_D_CONSTANT, "failed repetition");
			goto lazy_next;
		}

		REX_RETURN(const uchar *, "[first match] %p", next_start);

	lazy_next:
		p = (char *) (next_start + 1);
	}

}

/**
 * Caching wrapper over re_seeing_text() and re_seeing_char().
 */
static const uchar *
re_seeing_element(struct re_exec_ctx *rec, const re_element_t *e, bool lazy)
{
	const uchar *result;

	REX_ENTRY;

	/* Check cache first */

	if (rec->seen_element.e == e) {
		REX_DEBUG(RE_D_CONSTANT, "%s(): checking cached info for %s",
			G_STRFUNC, re_elem_info(e));
		if (lazy != rec->seen_element.lazy) {
			REX_DEBUG(RE_D_CONSTANT, "lazy value changed");
			goto ignore;
		}

		REX_DEBUG(RE_D_CONSTANT,
			"cached result at pos=%zu (now %zu) was also %s and gave %p pos=%s",
			rec->seen_element.tp - rec->text, rec->tp - rec->text,
			lazy ? "lazy" : "greedy", rec->seen_element.result,
			NULL == rec->seen_element.result ? "-" :
				size_t_to_string(rec->seen_element.result - rec->text));

		if (rec->tp > rec->seen_element.tp) {
			if (rec->tp <= rec->seen_element.result)
				goto use_cached;
			if (lazy) goto ignore;		/* Past previous result! */
			REX_RETURN(const uchar *, "[no further occurrence] %p", NULL);
		} else {
			if (lazy) goto ignore;		/* Could have earlier match */
			if (NULL == rec->seen_element.result)
				goto ignore;			/* Idem */
		}

		/* FALL THROUGH */

	use_cached:
		result = rec->seen_element.result;

		g_assert(NULL == result || result >= rec->tp);

		REX_RETURN(const uchar *, "[cached] %p", result);

	ignore:
		REX_DEBUG(RE_D_CONSTANT, "discarding cached info");

	}

	switch (e->type) {
	case RE_TYPE_TEXT: result = re_seeing_text(rec, e, lazy); break;
	case RE_TYPE_CHAR: result = re_seeing_char(rec, e, lazy); break;
	default:
		s_error("%s(): called with unexpected element %s",
			G_STRFUNC, re_elem_info(e));
	}

	/* Cache result */

	rec->seen_element.e      = e;
	rec->seen_element.tp     = rec->tp;
	rec->seen_element.result = result;
	rec->seen_element.lazy   = lazy;

	REX_RETURN(const uchar *, "%p", result);
}

/**
 * Computes matching length for given element.
 *
 * @return the fixed length of the element, 0 if unknown (variable).
 */
static size_t NO_INLINE
re_exec_element_length(const struct re_exec_ctx *rec, const re_element_t *e)
{
	size_t len;

	re_exec_ctx_check(rec);
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_BACKREF:
		len = re_exec_match_backref_length(rec, e);
		g_assert(len >= re_element_get_minlen(e));
		break;
	default:
		len = re_element_get_minlen(e);
		if (re_element_get_maxlen(e) != len)
			len = 0;		/* Signals unknown length */
		break;
	}

	return len;
}

/**
 * Look for a node containing a fixed constant we have to match, and look
 * at whether we can find it in the remaining text.
 *
 * If found, the `*constant' variable is set with the first/last match we
 * found, which can be used to set an upper-bound to the unbound repetitions.
 *
 * @param rec		the execution context
 * @param ev		current element vector we are in
 * @param n			position in `ev' where we need to start looking
 * @param lazy		whether element we set an upper-bound to is lazy
 * @param constant	where constant address is written, if found
 * @param offset	set with how many chars between constant and end of match
 *
 * @return TRUE if we found the constant, or could not find any constant to
 * match (constant to know), FALSE if we found a constant string to test but
 * it was missing in text.
 */
static bool NO_INLINE
re_find_constant(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	bool lazy, const uchar **constant, size_t *offset)
{
	re_element_t *e;
	size_t d = 0;

	g_assert(constant != NULL);
	g_assert(offset != NULL);

	REX_ENTRY;

	*constant = NULL;		/* Signals: no constant string to test for */

next:
	re_exec_ctx_check(rec);
	re_elemvec_check(ev);

	for (e = &ev->elements[n]; n < ev->ecnt; n++, e++) {
		size_t min = re_element_get_repeat_min(e);
		size_t max;

		REX_DEBUG(RE_D_CONSTANT, "%s(): processing %s, repeat min=%zu",
			G_STRFUNC, re_elem_info(e), min);

		/*
		 * When we reach an element whose minimum repetition is 0,
		 * it can match the empty string, but it could also match
		 * text that will be matched by following constants, and
		 * we cannot constrain greedy operators by an early match.
		 */

		if (0 == min)
			break;

		switch ((re_elem_type_t) e->type) {
		case RE_TYPE_NEXT:
			ev = e->u.other->x.next.vec;
			n = e->u.other->x.next.n;
			REX_DEBUG(RE_D_CONSTANT,
				"%s(): following %s", G_STRFUNC, re_elem_info(e));
			goto next;
		case RE_TYPE_EMPTY:
		case RE_TYPE_IS_BOUNDARY:
		case RE_TYPE_NOT_BOUNDARY:
			break;			/* Ignore */
		case RE_TYPE_ANY:
		case RE_TYPE_ALL:
		case RE_TYPE_CLASS:
		case RE_TYPE_INV_CLASS:
		case RE_TYPE_CLASS_MM:
		case RE_TYPE_INV_CLASS_MM:
		case RE_TYPE_D_CLASS:
		case RE_TYPE_W_CLASS:
		case RE_TYPE_S_CLASS:
		case RE_TYPE_NOT_D_CLASS:
		case RE_TYPE_NOT_W_CLASS:
		case RE_TYPE_NOT_S_CLASS:
		case RE_TYPE_POSIX_CLASS:
		case RE_TYPE_NOT_POSIX_CLASS:
			{
				/* Matching element = 1 character */
				max = re_element_get_repeat_max(e);
				if (min == max)
					d = size_saturate_add(d, min);
				else
					goto done;
			}
			break;
		case RE_TYPE_MATCHX:
			{
				size_t len = re_exec_element_length(rec, e);
				g_assert(0 != len);	/* This is an exact matching trie */

				max = re_element_get_repeat_max(e);
				if (min == max)
					d = size_saturate_add(d, size_saturate_mult(len, min));
				else
					goto done;
			}
			break;
		case RE_TYPE_TEXT:
		case RE_TYPE_CHAR:
			if (NULL == (*constant = re_seeing_element(rec, e, lazy)))
				REX_RETURN(bool, "%d", FALSE);
			goto done;
		case RE_TYPE_SUB:
		case RE_TYPE_SUBN:
		case RE_TYPE_GROUP:
		case RE_TYPE_ATOMIC:
			if (RE_N_ONCE != e->repeat)
				goto done;
			/* FALL THROUGH */
		case RE_TYPE_AHEAD:
			{
				/* We descend into look-ahead blocks (no repetition allowed) */
				ev = re_element_get_sub(e);
				n = 0;
				REX_DEBUG(RE_D_CONSTANT, "%s(): descending in %s",
					G_STRFUNC, re_elem_info(e));
				goto next;
			}
		case RE_TYPE_START:
		case RE_TYPE_END:
		case RE_TYPE_NOT_AHEAD:
		case RE_TYPE_BACKREF:
		case RE_TYPE_OR:
		case RE_TYPE_MATCH:
		case RE_TYPE_ROUTE:
		case RE_TYPE_ROUTEX:
		case RE_TYPE_RETURN:
		case RE_TYPE_MAX:
			goto done;
		}
	}

	/* FALL THROUGH */

done:
	if G_UNLIKELY(NULL == *constant) {
		REX_DEBUG(RE_D_CONSTANT, "%s(): no constant found", G_STRFUNC);
	} else {
		REX_DEBUG(RE_D_CONSTANT, "%s(): constant at pos=%zu starts with '%c'",
			G_STRFUNC, *constant - rec->text, **constant);
	}

	*offset = d;

	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Signature of routines that match one single element at the current position.
 */
typedef bool (*re_exec_match_fn_t)(
	struct re_exec_ctx *rec, const re_element_t *e);

/**
 * Invoked when success was reached during deep recursions.
 *
 * If the negation counter is not zero, return TRUE, otherwise we can
 * longjmp() out of the recursion to report success directly.
 */
static void G_NORETURN
re_exec_success(struct re_exec_ctx *rec)
{
	re_exec_ctx_check(rec);

	/* No REX_ENTRY -- logging done at depth of caller */

	REX_DEBUG(RE_D_EXEC, "reporting success via longjmp()");
	longjmp(rec->matched, TRUE);
}

/**
 * Monitor stack usage during recursions.
 */
static void
re_exec_check_stack(struct re_exec_ctx *rec)
{
	ssize_t used = thread_stack_diff(rec->stack_top);

	/* No REX_ENTRY -- logging done at depth of caller */

	if G_UNLIKELY(UNSIGNED(used) > rec->max_stack_used) {
		REX_DEBUG(RE_D_EXEC, "new max stack usage: ** %zd bytes **", used);
		rec->max_stack_used = used;
	} else {
		REX_DEBUG(RE_D_EXEC,
			"stack usage: %zd bytes / %zd", used, rec->max_stack_used);
	}

	if (used >= rec->max_stack) {
		REX_DEBUG(RE_D_EXEC,
			"ABORTING via longjmp() -- allowed stack was %zu", rec->max_stack);
		longjmp(rec->matched, -1);
	}
}

/*
 * Track recursion levels in re_exec_match_here() when debugging.
 */
#if PRIVLOG_ENABLED
static inline void
re_exec_match_depth_inc(struct re_exec_ctx *rec)
{
	if (++rec->match_depth > rec->max_match_depth)
		rec->max_match_depth = rec->match_depth;
	rec->match_calls++;
}
static inline void
re_exec_match_depth_dec(struct re_exec_ctx *rec)
{
	g_assert(rec->match_depth != 0);
	rec->match_depth--;
}
#else	/* !PRIVLOG_ENABLED */
#define re_exec_match_depth_inc(x)
#define re_exec_match_depth_dec(x)
#endif	/* PRIVLOG_ENABLED */

/**
 * Do we have at least `need' bytes ahead before the end of text?
 */
static bool
re_exec_has_enough_ahead(struct re_exec_ctx *rec, size_t need)
{
	size_t available, probe;
	void *p;

	REX_ENTRY;
	re_exec_log_where(rec);

	REX_DEBUG(RE_D_EXEC, "needs %zu byte%s of text", PLURAL(need));

	if (rec->tend != NULL) {
		available = rec->tend - rec->tp;
		REX_DEBUG(RE_D_EXEC, "has %zu byte%s available",
			PLURAL(available));
		REX_RETURN(bool, "[end known] %d", available >= need);
	}

	/*
	 * We cache the last probed location (before end) to avoid
	 * scanning too many times if we backtrack.
	 */

	probe = need + 1;	/* Want to see trailing NUL after last char */

	if (rec->tprobed > rec->tp) {
		available = rec->tprobed - rec->tp;
		REX_DEBUG(RE_D_EXEC, "has %zu byte%s known to be available",
			PLURAL(available));
		if (available >= need)
			REX_RETURN(bool, "%d", TRUE);
		probe -= available;
	} else {
		rec->tprobed = rec->tp;
	}

	REX_DEBUG(RE_D_EXEC, "probing %zu byte%s ahead", PLURAL(probe));

	p = vmemchr(rec->tprobed, '\0', probe);
	if (NULL == p) {
		rec->tprobed += probe;
	} else {
		rec->tprobed = rec->tend = p;
		REX_DEBUG(RE_D_EXEC, "end of text found");
	}

	REX_RETURN(bool, "%d", UNSIGNED(rec->tprobed - rec->tp) >= need);
}

/**
 * Do we have enough text left to match the element?
 *
 * @param rec		the execution context
 * @param e			the element we want to match
 * @param cnt		how much were matched already?
 *
 * @return TRUE if we have enough text left.
 */
static bool
re_exec_has_enough_text(
	struct re_exec_ctx *rec, const re_element_t *e, size_t cnt)
{
	size_t min = re_element_get_repeat_min(e);
	size_t minlen = re_element_get_minlen(e);
	size_t need;

	REX_ENTRY;

	if (0 == min)
		REX_RETURN(bool, "[min=0] %d", TRUE);

	if (cnt >= min)
		REX_RETURN(bool, "[min already matched] %d", TRUE);

	need = size_saturate_mult(minlen, min - cnt);

	REX_DEBUG(RE_D_EXEC, "need %zu byte%s for %zu %s",
		PLURAL(need), min - cnt, re_type2str(e->type));

	REX_RETURN(bool, "%d", re_exec_has_enough_ahead(rec, need));
}

/**
 * Generic wrapper for matching a single element possibly multiple times.
 *
 * The minimum amount of repetitions have already been handled, this
 * routine only handles the matching of optional parts, in minimal mode.
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 * @param count		if non-NULL, used to keep track of match counts
 *
 * @return TRUE on match.
 */
static bool G_FAST
re_exec_match_minimal(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher, re_match_count_t *count)
{
	size_t i;
	size_t len;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	g_assert(ev->elements[n].minimal);
	g_assert(ev->elements[n].repeat != RE_N_ONCE);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */

	len = re_exec_element_length(rec, &ev->elements[n]);

	REX_DEBUG(RE_D_REPEAT,
		"handling %s, len=%zu%s, with min=%zu already matched",
		re_elem_info(&ev->elements[n]), len,
		re_element_get_minlen(&ev->elements[n]) !=
			re_element_get_maxlen(&ev->elements[n]) ? " (unknown)" : "",
		NULL == count ? re_element_get_repeat_min(&ev->elements[n]): count->n);

	for (
		i = NULL == count ?
			re_element_get_repeat_min(&ev->elements[n]) : count->n;
		i < re_element_get_repeat_max(&ev->elements[n]);
		i++
	) {
		const uchar *tp = rec->tp;

		REX_DEBUG(RE_D_REPEAT, "attempting to match remaining, i=%zu", i);

		/*
		 * If we do not have at least one byte to consume, there is no
		 * need to continue.
		 */

		if (!re_exec_has_enough_ahead(rec, MAX(len, 1))) {
			REX_DEBUG(RE_D_REPEAT, "not enough text, declaring success");
			goto success;
		}

		if (re_exec_match_here(rec, ev, n + 1, TRUE)) {
			REX_DEBUG(RE_D_REPEAT, "minimal %s matched for i=%zu",
				re_elem_info(&ev->elements[n]), i);
			re_exec_success(rec);
		}

		rec->tp = tp;
		if (count != NULL)
			count->n++;			/* Assume it matches */

		REX_DEBUG(RE_D_REPEAT, "trying to match %s once more for i=%zu",
			re_elem_info(&ev->elements[n]), i);

		if (!(*matcher)(rec, &ev->elements[n])) {
			rec->tp = tp;
			if (count != NULL)
				count->n--;		/* Did not match */
			break;
		} else {
			if (count != NULL)
				count->tp = tp;	/* Pointer before last match */
		}

		if (rec->tp == tp) {
			REX_DEBUG(RE_D_REPEAT,
				"matching not advancing at i=%zu (min=%zu, max=%s)",
				i, re_element_get_repeat_min(&ev->elements[n]),
				re_max2str(re_element_get_repeat_max(&ev->elements[n])));
			break;
		}
	}

	/* FALL THROUGH */

success:

	/* We matched as much as we could */
	REX_DEBUG(RE_D_REPEAT,
		"%s matched as much as possible for minimal match (i=%zu/%s)",
		re_elem_info(&ev->elements[n]),
		i, re_max2str(re_element_get_repeat_max(&ev->elements[n])));

	re_exec_log_where(rec);
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Structure used to pass all the arguments for the deep recursion, so as
 * to minimize stack space usage.
 */
struct re_exec_match_maximal_ctx {
	struct re_exec_ctx *rec;		/* the execution context */
	const re_elemvec_t *ev;			/* the element vector we are in */
	size_t n;						/* position in the element vector */
	re_exec_match_fn_t matcher;		/* element matching routine */
	re_match_count_t *count;		/* if non-NULL, tracks match counts */
	int constant;					/* if not NUL, constant char we expect */
	size_t offset;					/* constant offset after upper match */
};

/**
 * Helper routine to check whether we have a known matching constant ahead
 * at some fixed offset in the text.
 *
 * @return FALSE if we cannot see the constant, TRUE if there are no known
 * constant to check or it is present.
 */
static bool
re_exec_match_maximal_deep_constant(const struct re_exec_match_maximal_ctx *ctx)
{
	if ('\0' != ctx->constant) {
		if (
			0 != ctx->offset &&
			!re_exec_has_enough_ahead(ctx->rec, ctx->offset + 1)
		) {
			REX_DEBUG(RE_D_REPEAT | RE_D_CONSTANT, "not enough text left");
			return FALSE;
		} else if (*(ctx->rec->tp + ctx->offset) != ctx->constant) {
			REX_DEBUG(RE_D_REPEAT | RE_D_CONSTANT,
				"not followed by '%c' at offset %zu, declaring failure",
				ctx->constant, ctx->offset);
			return FALSE;
		}

		REX_DEBUG(RE_D_REPEAT | RE_D_CONSTANT,
			"seeing coming '%c' at offset %zu", ctx->constant, ctx->offset);

		/* FALL THROUGH -- constant was present */
	}

	return TRUE;	/* Cannot tell */
}

/**
 * Deep recursion for maximal matching.
 *
 * @param ctx		the deep matching context
 * @param n			amount of items to match still
 */
static bool G_FAST NO_INLINE
re_exec_match_maximal_deep(const struct re_exec_match_maximal_ctx *ctx, size_t n)
{
	const uchar *tp = ctx->rec->tp;

	REX_ENTRY;

	re_exec_check_stack(ctx->rec);	/* Deeply recursive, monitor permanently */
	re_exec_log_where(ctx->rec);

	REX_DEBUG(RE_D_REPEAT, "n=%zu, matching with %s(), count=%s", n,
		stacktrace_function_name(ctx->matcher),
		NULL == ctx->count ? "none" : size_t_to_string(ctx->count->n));

	if G_UNLIKELY(0 == n) {
		if (!re_exec_match_maximal_deep_constant(ctx))
			REX_RETURN(bool, "[bottom constant failure] %d", FALSE);

		REX_RETURN(bool, "[bottom] %d",
			re_exec_match_here(ctx->rec, ctx->ev, ctx->n + 1, TRUE));
	}

	if ((*ctx->matcher)(ctx->rec, &ctx->ev->elements[ctx->n])) {
		if (ctx->count != NULL)
			ctx->count->n++;

		REX_DEBUG(RE_D_REPEAT, "another match, %zu more to try", n - 1);

		if (re_exec_match_maximal_deep(ctx, n - 1))
			REX_RETURN(bool, "[propagating success] %d", TRUE);

		if (ctx->count != NULL)
			ctx->count->n--;

		ctx->rec->tp = tp;
		REX_DEBUG(RE_D_REPEAT, "deep failure, back at n=%zu", n);

		if (!re_exec_match_maximal_deep_constant(ctx))
			REX_RETURN(bool, "[constant failure] %d", FALSE);

		if (re_exec_match_here(ctx->rec, ctx->ev, ctx->n + 1, TRUE)) {
			REX_DEBUG(RE_D_REPEAT, "matching at n=%zu", n);
			REX_RETURN(bool, "[success] %d", TRUE);
		}

		REX_RETURN(bool, "[failure] %d", FALSE);
	}

	/*
	 * Since we went through re_exec_match_maximal() already, we know
	 * very well that we matched all our attempts.  The only thing we
	 * do not know is how many such successful matches we can accept to
	 * lead to a global pattern match.
	 */

	g_assert_not_reached();
}

/**
 * This is the entry point we move to when re_exec_match_maximal() does not
 * have a fixed matching length and going to the maximum did not lead to
 * a match.
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 * @param count		if non-NULL, used to keep track of match counts
 * @param amount	maximum amount of matching we have to perform
 * @param constant	constant char that must follow, if not NUL
 * @param offset	constant offset after upper match
 *
 * @return TRUE on match, with rec->tp adjusted past the match.
 */
static bool NO_INLINE
re_exec_match_maximal_recursively(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher, re_match_count_t *count, size_t amount,
	int constant, size_t offset)
{
	struct re_exec_match_maximal_ctx ctx;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);
	g_assert(size_is_positive(amount));

	/*
	 * No REX_ENTRY here, we're continuing re_exec_match_maximal()
	 * through tail recursion.
	 */

	REX_DEBUG(RE_D_REPEAT, "attempting %zu match%s at most with %s()",
		PLURAL_ES(amount), stacktrace_function_name(matcher));

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */
	re_exec_log_where(rec);

	ZERO(&ctx);
	ctx.rec      = rec;
	ctx.ev       = ev;
	ctx.n        = n;
	ctx.matcher  = matcher;
	ctx.count    = count;
	ctx.constant = constant;
	ctx.offset   = offset;

	REX_RETURN(bool, "[exiting deep recursion] %d",
		re_exec_match_maximal_deep(&ctx, amount));
}

/**
 * Generic wrapper for matching a single element possibly multiple times.
 *
 * The minimum amount of repetitions have already been handled, this
 * routine only handles the matching of optional parts, in greedy mode.
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 * @param count		if non-NULL, used to keep track of match counts
 *
 * @return TRUE on match.
 */
static bool G_FAST
re_exec_match_maximal(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher, re_match_count_t *count)
{
	re_element_t *e;
	const uchar *tp;
	const uchar *upper = NULL;	/* Upper matching pointer */
	size_t i, min, max, len, offset;
	const uchar *initial_tp;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */
	e = &ev->elements[n];

	/*
	 * Do we know the exact length of the item we are matching?
	 */

	len = re_exec_element_length(rec, e);

	REX_DEBUG(RE_D_REPEAT | RE_D_EXEC,
		"length of the %s items we match is %zu%s",
		re_type2str(e->type), len,
		re_element_get_minlen(e) != re_element_get_maxlen(e) ?
			" (unknown)" : "");

	/*
	 * Beware when matching ANY or ALL, we want to set an upper limit
	 * to avoid costly back-tracking.  Likewise when the length of
	 * the items we match is not fixed (unknown because variable).
	 *
	 * Before we attempt to match the repetition, look for a known
	 * fixed string that we will have to match after this.  If we
	 * cannot find it in the string, then there is no hope and we
	 * can fail right away.
	 *
	 * We don't do that for atomic operators since they never give
	 * back what they match, so let them match (and cause possible
	 * failure due to lack of back-tracking)!
	 */

	if (
		!e->atomic &&
		(0 == len || RE_TYPE_ANY == e->type || RE_TYPE_ALL == e->type)
	) {
		if (!re_find_constant(rec, ev, n + 1, e->minimal, &upper, &offset))
			REX_RETURN(bool, "[early failure] %d", FALSE);

		REX_DEBUG(RE_D_CONSTANT,
			"upper match pointer at pos=%s, offset=%zu",
			NULL == upper ?
				"-" : size_t_to_string((upper - offset) - rec->text),
			offset);
	}

	min = NULL == count ? re_element_get_repeat_min(e) : count->n;
	max = re_element_get_repeat_max(e);
	initial_tp = NULL == count ? NULL : count->tp;

	REX_DEBUG(RE_D_REPEAT, "handling %s with %zu match%s already",
		re_elem_info(e), PLURAL_ES(min));

	REX_DEBUG(RE_D_MATCHER, "matching routine is %s()",
		stacktrace_function_name(matcher));

	if (len != 0) {
		/*
		 * If we do not have enough text, we're done (and successful, since
		 * our minimal count was already matched.
		 */

		if (!re_exec_has_enough_ahead(rec, len)) {
			REX_DEBUG(RE_D_REPEAT, "not enough text to go further");
			goto done;
		}
	}

	/*
	 * Match as much as we can, whilst retaining the ability of the
	 * remaining parts of the pattern to match as well.
	 */

	tp = rec->tp;		/* Save starting point for i=min */
	i = min;

	REX_DEBUG(RE_D_REPEAT, "%s(): trying max=%s for %s (%p)",
		G_STRFUNC, re_max2str(max), re_elem_info(e), e);

	while (i < max) {
		const uchar *old_tp = rec->tp;
		const uchar *old_count_tp;

		if G_UNLIKELY(upper != NULL && rec->tp >= upper - offset) {
			REX_DEBUG(RE_D_REPEAT,
				"reached upper limit at i=%zu", i);
			break;
		}

		re_exec_log_where(rec);
		if (count != NULL) {
			old_count_tp = count->tp;
			count->tp = rec->tp;
			count->n++;			/* Assume it will match */
		}

		if (!(*matcher)(rec, e)) {
			if (count != NULL) {
				count->tp = old_count_tp;
				count->n--;			/* Did not match, finally */
			}
			break;
		}

		if (old_tp == rec->tp) {
			REX_DEBUG(RE_D_REPEAT,
				"matching not advancing at i=%zu (max=%s)",
				i, re_max2str(max));
			break;
		}

		i++;		/* One more successful "matcher" invocation */

		REX_DEBUG(RE_D_REPEAT,
			"additional match for i=%zu advanced by %zu",
			i, rec->tp - old_tp);
	}

	REX_DEBUG(RE_D_REPEAT,
		"max=%s, i=%zu, advanced by %zu",
		re_max2str(max), i, rec->tp - tp);
	re_exec_log_where(rec);

	/*
	 * If we stopped matching, either it is now max or we
	 * have reached the maximum amount of times we can
	 * match this element.
	 */

	if (i < max) {
		max = i;		/* Stopped matching at i */
		REX_DEBUG(RE_D_REPEAT,
			"setting max=%s for %s (%p)",
			re_max2str(max), re_elem_info(e), e);
	}

	/*
	 * Cut down on recursion if we stayed at the "minimum", which
	 * is either the element minimum or the already matched count
	 * for the element we had upon entry.
	 */

	if (i == min) {
		REX_DEBUG(RE_D_REPEAT, "cannot match %s (%p) beyond %zu (min=%zu)",
			re_elem_info(e), e, min,
			re_element_get_repeat_min(e));
		goto done;
	}

	/*
	 * If it's atomic, we matched as much as we could, now we declare
	 * success and we do not backtrack!
	 *
	 * Hence no need to go through re_exec_match_here(), if backtracking
	 * is required, it will be done by earlier operators (for instance if
	 * we are matching inside a repeated group).
	 */

	if (e->atomic) {
		REX_DEBUG(RE_D_REPEAT,
			"atomic match for %s (%p) at max=%s",
			re_elem_info(e), e, re_max2str(max));
		goto done;
	}

	REX_DEBUG(RE_D_REPEAT, "attempting to match remaining");

	if (re_exec_match_here(rec, ev, n + 1, TRUE)) {
		REX_DEBUG(RE_D_REPEAT, "MATCHED, max=%s", re_max2str(max));
		re_exec_log_where(rec);
		re_exec_success(rec);
	}

	REX_DEBUG(RE_D_REPEAT,
		"max=%s did not match for %s (%p)",
		re_max2str(max), re_elem_info(e), e);

	/*
	 * If we don't have a fixed length, we have to go recursive to be
	 * able to save on the stack the different backtracking points
	 */

	if (0 == len) {
		rec->tp = tp;		/* Restore starting point for i=min */
		if (count != NULL) {
			count->n = min;
			count->tp = initial_tp;
		}
		if (--max == min) {
			REX_DEBUG(RE_D_REPEAT,
				"no hope for better match than min=%zu", min);
			goto done;
		}

		REX_DEBUG(RE_D_REPEAT, "no fixed length -- going recursive");

		return re_exec_match_maximal_recursively(
			rec, ev, n, matcher, count, max - min,
			NULL == upper ? '\0' : *upper, offset);
	}

	/*
	 * We now have a fixed length pattern to backtrack until the
	 * remaining matches or we are back to the minimum.
	 */

	for (;;) {
		i--;
		rec->tp = tp + (i - min) * len;
		if (count != NULL) {
			count->n--;
			count->tp = rec->tp - len;	/* Before last match */
		}

		REX_DEBUG(RE_D_REPEAT, "%s(): backtracked %zu byte%s for %s",
			G_STRFUNC, PLURAL(len), re_elem_info(e));

		re_exec_log_where(rec);

		if (i == min) {
			/* No further repetitions lead to a match, we can return */
			REX_DEBUG(RE_D_REPEAT, "back to minimum, declaring success");
			goto done;
		}

		g_assert(rec->tp > tp);

		REX_DEBUG(RE_D_REPEAT, "%s(): restored i=%zu (min=%zu)",
			G_STRFUNC, i, re_element_get_repeat_min(e));

		if (re_exec_match_here(rec, ev, n + 1, TRUE)) {
			REX_DEBUG(RE_D_REPEAT, "MATCHED, max=%s", re_max2str(max));
			re_exec_log_where(rec);
			re_exec_success(rec);
		}
	}

	/* FALL THROUGH */

done:
	re_exec_log_where(rec);
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Match the minimum required amount of items at the current position.
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 * @param count		if non-NULL, tracks amount of matches we performed
 *
 * @return +1 if we matched but there are still items to be matched possibly,
 * 0 if we did not match all the required items and -1 if we matched the minimum
 * but either it is the same as the maximum, or there is no hope matching more
 * since the current pointer is not advancing on subsequent matches.
 */
static int G_FAST
re_exec_match_required(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher, re_match_count_t *count)
{
	const uchar *tp;
	size_t i;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */
	re_exec_log_where(rec);

	REX_DEBUG(RE_D_REPEAT, "handling %s", re_elem_info(&ev->elements[n]));

	REX_DEBUG(RE_D_REPEAT,
		"min=%zu, max=%s, matcher=%s %s",
		re_element_get_repeat_min(&ev->elements[n]),
		re_max2str(re_element_get_repeat_max(&ev->elements[n])),
		stacktrace_function_name(matcher),
		ev->elements[n].minimal ? "lazy" :
		ev->elements[n].atomic ? "atomic" : "greedy");

	REX_DEBUG(RE_D_REPEAT, "count is %s",
		NULL == count ? NULL : size_t_to_string(count->n));

	/*
	 * If the end is known, check that we have enough characters left
	 * to match the minimum required.
	 */

	if (
		rec->tend != NULL &&
		!re_exec_has_enough_text(
			rec, &ev->elements[n], NULL == count ? 0 : count->n)
	)
		REX_RETURN(bool, "[early failure: not enough text] %d", FALSE);


	tp = rec->tp;

	for (
		i = NULL == count ? 0 :
		count->n; i < re_element_get_repeat_min(&ev->elements[n]);
		i++
	) {
		/*
		 * If there is a count, we need to track our matching attempts
		 * before recursing here, possibly, through the matcher routine
		 * (as it attempts to match the remaining of the pattern during
		 * greedy matches).
		 */

		if (count != NULL)
			count->n++;			/* We're trying, assume it will work */

		re_exec_log_where(rec);

		if (!(*matcher)(rec, &ev->elements[n])) {
			REX_DEBUG(RE_D_REPEAT, "matched only %zu / min %zu",
				i, re_element_get_repeat_min(&ev->elements[n]));

			rec->tp = tp;
			if (count != NULL)
				count->n--;		/* Did not match */

			REX_RETURN(int, "[incomplete] %d", 0);
		} else {
			if (count != NULL)
				count->tp = tp;	/* Flag start of minimal matches */
		}
	}

	REX_DEBUG(RE_D_REPEAT, "matched min=%zu, advanced %zu byte%s",
		re_element_get_repeat_min(&ev->elements[n]),
		PLURAL(rec->tp - tp));
	re_exec_log_where(rec);

	if (
			re_element_get_repeat_min(&ev->elements[n]) ==
			re_element_get_repeat_max(&ev->elements[n])
	)
		REX_RETURN(int, "[min == max, matched requested count] %+d", -1);

	if (re_element_get_repeat_min(&ev->elements[n]) >= 1 && rec->tp == tp)
		REX_RETURN(int, "[matching did not advance position] %+d", -1);

	REX_RETURN(int, "%+d", +1);
}

/**
 * Find callback for eslist_find().
 *
 * @return 0 if both items point to the same element.
 */
static int
re_exec_same_element(const void *a, const void *b)
{
	const re_match_count_t *ma = a, *mb = b;

	if (ma->e == mb->e)
		return 0;

	return 1;	/* Items do not match elements */
}

/**
 * When hitting a NEXT, was the enclosing element a SUBN, in which case
 * we need to track the matching for that group.
 */
static void NO_INLINE
re_exec_match_subn_handle(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	re_element_t *be;	/* Element before next */

	g_assert(n >= 1);	/* Ensures we have a previous */

	be = &ev->elements[n - 1];

	if G_UNLIKELY(RE_TYPE_SUBN == be->type) {
		uint m;

		/* Don't bother if they supplied RE_X_NOSUB and no back-refs */
		if G_UNLIKELY(0 != (rec->eflags & RE_X_NOSUB) && NULL == rec->bvec)
			return;

		m = re_element_get_sub_number(be);
		re_exec_match_group_end(rec, m);
	}
}

/**
 * Generic wrapper for matching a single element possibly multiple times
 * with a minimum amount of matches to guarantee, or when greedy maximal
 * matching is requested.
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 *
 * @return +1 on match, 0 on no-match, and -1 if we do not need to track.
 *
 * @note
 * This routine is flagged NO_INLINE because it is otherwise a likely expansion
 * candidate within its sole caller, re_exec_match_repeat().  But inlining
 * would completely defeat the great care we are taking to alter the execution
 * flow in case of heavy recursion in order to minimize the stack space used!
 */
static int G_FAST NO_INLINE
re_exec_match_track(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher)
{
	re_match_count_t count;
	/* Save stack space since we can */
	union {
		int r;
		re_match_count_t *latest;
		bool ok;
	} u;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */
	re_exec_log_where(rec);

	REX_DEBUG(RE_D_REPEAT, "handling %s", re_elem_info(&ev->elements[n]));

	REX_DEBUG(RE_D_REPEAT,
		"min=%zu, max=%s, matcher=%s %s",
		re_element_get_repeat_min(&ev->elements[n]),
		re_max2str(re_element_get_repeat_max(&ev->elements[n])),
		stacktrace_function_name(matcher),
		ev->elements[n].minimal ? "minimal" :
			ev->elements[n].atomic ? "atomic" : "greedy");

	/*
	 * Before calling the matching routine, we need to install the count
	 * tracker on the stack.
	 *
	 * The effect of doing so will alter the behaviour of NEXT nodes: when
	 * they are right after an element in the rec->multi list, it means the
	 * required count has not yet been reached for that element and we
	 * need to recurse back.
	 *
	 * Because of that recursion, when we arrive here we may already have
	 * an entry for that element in the rec->multi list.  We add a new one
	 * but we propagate the count for the first one we see in the list (i.e.
	 * the latest we traversed).
	 */

	ZERO(&count);
	count.e  = &ev->elements[n];
	count.tp = rec->tp;

	REX_DEBUG(RE_D_REPEAT,
		"current count of rec->multi: %zu", eslist_count(&rec->multi));

	u.latest = eslist_find(&rec->multi, &count, re_exec_same_element);

	if (u.latest != NULL) {
		REX_DEBUG(RE_D_REPEAT,
			"found entry for %s (%p) with n=%zu (min is %zu, max is %s)",
			re_elem_info(count.e), count.e, u.latest->n,
			re_element_get_repeat_min(count.e),
			re_max2str(re_element_get_repeat_max(count.e)));

		count.n  = u.latest->n;
		count.tp = u.latest->tp;

		if (count.n >= re_element_get_repeat_max(count.e))
			REX_RETURN(int, "[max count already matched] %+d", +1);
	}

	if (
		NULL == u.latest ||			/* At least one record for tracking */
		!count.e->minimal ||		/* Always process greedy matches */
		count.n < re_element_get_repeat_min(count.e)
	) {
		/*
		 * When minimum is already reached, we need to recurse anyway
		 * to ensure greediness if we haven't reached the maximum yet.
		 *
		 * However, to minimize the stack used, don't recurse from here:
		 * return -1 and recursion will be done in the caller.  Because
		 * we don't prepend a new record that would be removed below
		 * before returning, the caller will have to save and restore the
		 * value of count->n.
		 */

		if (
			u.latest != NULL &&
			count.n >= re_element_get_repeat_min(count.e)
		) {
			/* We already have a record, recurse using minimal stack */
			REX_DEBUG(RE_D_REPEAT, "recursing via alt path for greediness");
			REX_RETURN(int, "[request alternate path] %+d", -1);
		}

		REX_DEBUG(RE_D_REPEAT,
			"prepending new record for %s %s (%p) with n=%zu (min is %zu)",
			count.e->minimal ? "lazy" : "greedy",
			re_elem_info(count.e), count.e, count.n,
			re_element_get_repeat_min(count.e));

		eslist_prepend(&rec->multi, &count);
		u.latest = &count;
	} else {
		REX_DEBUG(RE_D_REPEAT,
			"using alternate path to save stack space");
		REX_RETURN(int, "[request alternate path] %+d", -1);
	}

	/*
	 * At this stage, we have prepended &count to the rec->multi list.
	 */

	u.r = re_exec_match_required(rec, ev, n, matcher, u.latest);

	/*
	 * Remove the record when there is no hope to match more.
	 *
	 * Otherwise, we leave the record around regardless of whether this is
	 * a minimal or greedy matching: just because we have matched the minimum
	 * amount required does not mean we cannot have to perform more matches
	 * on the element to get a final matching success.
	 */

	if (u.r <= 0) {
		REX_DEBUG(RE_D_REPEAT,
			"removing record for %s (%p) with n=%zu (min is %zu)",
			re_elem_info(count.e), count.e, count.n,
			re_element_get_repeat_min(count.e));
		eslist_remove(&rec->multi, &count);
		count.e = NULL;		/* Our signal that it was removed */
	} else {
		REX_DEBUG(RE_D_REPEAT,
			"leaving record for %s %s (%p) with n=%zu (min is %zu)",
			count.e->minimal ? "minimal" : "greedy",
			re_elem_info(count.e), count.e, count.n,
			re_element_get_repeat_min(count.e));
	}

	switch (u.r) {
	case -1: REX_RETURN(int, "%+d", +1);		/* No hope to match more */
	case 0:  REX_RETURN(int, "%+d", 0);
	default: break;
	}

	/* FALL THROUGH */

	/*
	 * If we removed the record from the list, request the alternate
	 * path to save stack space since now the minimal amount has been
	 * matched.
	 */

	if (NULL == count.e)
		REX_RETURN(int, "[request alternate path, min matched] %+d", -1);

	if (ev->elements[n].minimal)
		u.ok = re_exec_match_minimal(rec, ev, n, matcher, &count);
	else
		u.ok = re_exec_match_maximal(rec, ev, n, matcher, &count);

	REX_DEBUG(RE_D_REPEAT,
		"removing record for %s %s (%p) with n=%zu (min is %zu), ok=%d",
		count.e->minimal ? "lazy" : "greedy",
		re_elem_info(&ev->elements[n]), &ev->elements[n], count.n,
		re_element_get_repeat_min(&ev->elements[n]), u.ok);

	eslist_remove(&rec->multi, &count);

	/*
	 * If the element matched and was a capturing group at the end
	 * of the regular expression, handle the end of its capture.
	 *
	 * We supply `n + 1' here to move to the "next" element, as this is
	 * what the re_exec_match_subn_handle() expects, but that does not
	 * mean there is a NEXT item there (there is not actually, which is
	 * precisely why we need to call that routine now or we would never
	 * close this group capture).
	 */

	if (u.ok && n + 1 == ev->ecnt)
		re_exec_match_subn_handle(rec, ev, ev->ecnt);

	REX_RETURN(int, "%+d", u.ok);
}

/**
 * Generic wrapper for matching a single element possibly multiple times.
 *
 * Normally we should not me called for RE_N_ONCE matches, these are
 * optimized to directly call the matching routine in re_exec_match_here().
 *
 * @param rec		the execution context
 * @param ev		the element vector we are in
 * @param n			position in the element vector
 * @param matcher	the routine that can match one instance of the element
 *
 * @return TRUE on match.
 */
static bool G_FAST
re_exec_match_repeat(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher)
{
	re_match_count_t *count = NULL;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */
	re_exec_log_where(rec);

	REX_DEBUG(RE_D_REPEAT, "handling %s", re_elem_info(&ev->elements[n]));

	/*
	 * A recursive element needs tracking due to possible backtracking.
	 *
	 * Indeed, we will follow NEXT nodes, until we can declare a match.
	 * See re_exec_should_resume() and its caller re_exec_match_here().
	 */

	if (re_element_needs_tracking(&ev->elements[n])) {
		int r = re_exec_match_track(rec, ev, n, matcher);

		if (-1 == r)
			goto fetch_count;	/* Save stack space during recursions */

		REX_RETURN(bool, "%d", r != 0);
	}

	/*
	 * Handling a non-recursive element.
	 *
	 * First match the minimum we have to, before invoking
	 * re_exec_match_optional() to match the remaining variable
	 * parts.
	 */

	REX_DEBUG(RE_D_REPEAT, "non-recursive element %s",
		re_elem_info(&ev->elements[n]));

	switch (re_exec_match_required(rec, ev, n, matcher, NULL)) {
	case -1: REX_RETURN(bool, "%d", TRUE);	/* No hope to match more */
	case 0:  REX_RETURN(bool, "%d", FALSE);
	default: break;
	}

	/* FALL THROUGH */

no_track:
	REX_DEBUG(RE_D_REPEAT, "%s(): minimum (%zu) handled for %s, "
		"count is %sknown%s%s",
		G_STRFUNC,
		re_element_get_repeat_min(&ev->elements[n]),
		re_elem_info(&ev->elements[n]), NULL == count ? "un" : "",
		NULL == count ? "" : ": ",
		NULL == count ? "" : size_t_to_string(count->n));

	/*
	 * At this point, the minimum is already matched.  If the maximum is
	 * also equal to the minimum, we're done!
	 *
	 * @note
	 * re_exec_match_here() ensures we cannot have RE_N_ONCE items here,
	 * hence we're only testing for RE_N_COUNT.
	 */

	if (RE_N_COUNT == ev->elements[n].repeat)
		REX_RETURN(bool, "[min == max] %d", TRUE);
	else {
		/*
		 * If the current text pointer is the same as the one for the
		 * last match, it means we're matching the empty string, and since
		 * our minimum matching count has been reached, it is time to
		 * declare the match.
		 */

		if (count != NULL && count->tp == rec->tp)
			REX_RETURN(bool, "[matching the empty string] %d", TRUE);

		/*
		 * The "goto success" below is to factorize code a little bit
		 * and avoid using an extra boolean on the stack to track
		 * the matching status.
		 */

		if (ev->elements[n].minimal) {
			if (re_exec_match_minimal(rec, ev, n, matcher, count))
				goto success;
		} else {
			if (re_exec_match_maximal(rec, ev, n, matcher, count))
				goto success;
		}

		REX_RETURN(bool, "%d", FALSE);

	success:
		if (count != NULL) {
			REX_DEBUG(RE_D_REPEAT,
				"%s(): %s has count=%zu, tp=%p (%zd from current)",
				G_STRFUNC, re_elem_info(&ev->elements[n]),
				count->n, count->tp, count->tp - rec->tp);
		}

		REX_RETURN(bool, "%d", TRUE);
	}

fetch_count:
	/*
	 * We're dealing with an element whose matching count is tracked.
	 * Look for an already existing tracking record before attempting
	 * minimal or maximal matching.
	 */

	ZERO(&rec->tkey);
	rec->tkey.e = &ev->elements[n];
	count = eslist_find(&rec->multi, &rec->tkey, re_exec_same_element);

	goto no_track;
}

/**
 * Match alternative element at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_or_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	pslist_t *alt;

	g_assert(RE_TYPE_OR == e->type);

	REX_ENTRY;

	/*
	 * If we have a minlen, look-ahead to make sure we have enough
	 * characters ahead for a match.
	 */

	if (
		0 != re_element_get_minlen(e) &&
		!re_exec_has_enough_ahead(rec, re_element_get_minlen(e))
	) {
		REX_DEBUG(RE_D_EXEC, "not enough text left to match");
		REX_RETURN(bool, "[not enough text] %d", FALSE);
	}

	for (alt = re_element_get_alt(e); alt != NULL; alt = pslist_next(alt)) {
		const uchar *tp = rec->tp;

		REX_DEBUG(RE_D_EXEC,
			"trying alternative %s...", re_elemvec_info(alt->data));
		re_exec_log_where(rec);

		/*
		 * We need to make sure that choosing an alternative over another
		 * is not going to cause the pattern to fail matching.
		 *
		 * Consider "(?:a|alpha|alphabet)s" on the text "alphabets".
		 *
		 * The first branch matches all-right, but then the pattern fails
		 * and it is obvious that the longest alternative is the right
		 * choice here.
		 *
		 * That's why we need to call re_exec_match_here() with TRUE as
		 * the last parameter, so that we continue matching until the
		 * end of the regular expression to determine whether our alternative
		 * was the right one.
		 *
		 * Because this causes deeper recursion, we optimize slightly by
		 * looking at whether the alternative is the last one.  It if is,
		 * then no matter what, there is nothing else to try, hence we can
		 * supply FALSE and return success if the element vector matches
		 * by itself.
		 */

		if (NULL == pslist_next(alt)) {
			if (re_exec_match_here(rec, alt->data, 0, FALSE))
				REX_RETURN(bool, "[last alternative matched] %d", TRUE);
		} else {
			/* Deeper recursion needed */
			if (re_exec_match_here(rec, alt->data, 0, TRUE))
				re_exec_success(rec);
		}

		rec->tp = tp;	/* Backtracking, restore old pointer */
	}

	REX_DEBUG(RE_D_EXEC, "backtracking due to failed alternatives");
	re_exec_log_where(rec);

	REX_RETURN(bool, "[no match] %d", FALSE);
}

/**
 * Match non-capturing group element at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_group_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	bool ok;
	const uchar *tp;

	g_assert(re_element_is_group(e));

	REX_ENTRY;

	re_exec_log_where(rec);

	tp = rec->tp;
	ok = re_exec_match_here(rec, re_element_get_sub(e), 0, FALSE);

	if (!ok) {
		rec->tp = tp;		/* Backtracking, restore original position */
		re_exec_log_where(rec);
	}

	REX_RETURN(bool, "%d", ok);
}

/**
 * Match look-around group at current position.
 *
 * The current text pointer is NOT changed, this is an assertion!
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_lookaround(
	struct re_exec_ctx * volatile rec, const re_element_t *e)
{
	const uchar * volatile tp = rec->tp;
	bool ok;
	bool inverted = RE_TYPE_NOT_AHEAD == e->type;
	jmp_buf env;
	int ret;
	PRIVLOG_DECLARE_LEVEL(indent);

	g_assert(re_element_is_group(e));
	g_assert(RE_N_ONCE == e->repeat);	/* No repetition allowed on these! */

	REX_ENTRY;
	PRIVLOG_SAVE_LEVEL(indent);

	re_exec_check_stack(rec);

	/*
	 * Since we recurse through re_exec_match_here(), we will hit the
	 * RETURN statement (if the assertion matches), forcing that routine
	 * to report a success and not bother with matching the rest of the
	 * regular expression.
	 *
	 * We need to track longjmp() success reports so that, on success, we
	 * get back here,  or we can propagate stack overflow conditions that
	 * would arise later in the call chain
	 */

	ARRAY_COPY(env, rec->matched);

	if ((ret = Setjmp(rec->matched))) {
		PRIVLOG_RESTORE_LEVEL(indent);
		REX_DEBUG(RE_D_EXEC, "%s(): back through longjmp(), ret=%d",
			G_STRFUNC, ret);
		if (ret < 0) {
			REX_DEBUG(RE_D_EXEC, "propagating stack overflow");
			longjmp(env, ret);
		}
		ok = booleanize(ret);
		goto back;
	}

	ok = re_exec_match_here(rec, re_element_get_sub(e), 0, FALSE);

	/* FALL THROUGH */

back:
	ARRAY_COPY(rec->matched, env);
	rec->tp = tp;
	if (inverted) ok = !ok;

	re_exec_log_where(rec);
	REX_RETURN(bool, "%d", ok);
}

/**
 * Match given text at current position.
 *
 * @param rec		the execution context
 * @param text		start of text string to match
 * @paran len		how many bytes to match
 * @paran icase		whether to ignore case during matching
 *
 * @return TRUE on match.
 */
static bool
re_exec_match_text_here(
	struct re_exec_ctx *rec, const char *text, size_t len, bool icase)
{
	bool match;

	/* REX_ENTRY done in caller, this routine is invisible in the logs */

	re_exec_log_where(rec);
	REX_DEBUG(RE_D_MATCHER,
		"coming text=\"%.*s\", looking for \"%.*s\" (%zu byte%s)%s",
		(int) len, rec->tp, (int) len, text, PLURAL(len),
		icase ? " (ignore case)" : "");

	if (icase)
		match = 0 == strncasecmp((char *) rec->tp, text, len);
	else
		match = 0 == strncmp((char *) rec->tp, text, len);

	if (!match)
		REX_RETURN(bool, "%d", FALSE);

	rec->tp += len;
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Match back-reference element at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_backref_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	const char *text;
	size_t len;
	re_match_t *m;

	REX_ENTRY;

	m = re_exec_match_backref_find(rec, re_element_get_ref_number(e));

	g_assert(m != NULL);		/* If it fails, we have an RE compilation bug */

	/* Fetch the text matched by SUBN #n */

	len = m->re_end - m->re_start;
	text = const_ptr_add_offset(rec->text, m->re_start);

	g_assert(size_is_non_negative(len));

	/* Captured group text must be in the text before current position */
	g_assert(ptr_cmp(text, rec->text) >= 0);

	/*
	 * Note that we cannot assert that the end of the back-reference text
	 * is at or before the current point.  Indeed, a capturing group can
	 * be placed in a look-around assertion that has already matched.
	 *
	 * For instance, "(?=(\d+))\w+\1" being matched against "123_12".
	 *
	 * That is because \w also matches \d and, the look-ahead match being
	 * an assertion, it does not move the matching pointer.
	 */

	return re_exec_match_text_here(rec, text, len, e->icase);
}

/**
 * Match text element at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_text_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	REX_ENTRY;

	return
		re_exec_match_text_here(
			rec, re_element_get_text(e), re_element_get_minlen(e),
			e->icase);
}

/**
 * Is next character part of the minmax range defined in the element?
 */
static bool
re_exec_match_char_minmax(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;
	int min, max;
	bool ok;

	REX_ENTRY;
	re_exec_log_where(rec);

	if ('\0' == c)
		REX_RETURN(bool, "[reached end of text] %d", FALSE);

	re_minmax_decode(re_element_get_minmax(e), &min, &max);

	REX_DEBUG(RE_D_MATCHER,
		"c=%d, looking for %s[%u, %u]",
		c, RE_TYPE_INV_CLASS_MM == e->type ? "!" : "", min, max);

	if (e->icase)
		c = ascii_tolower(c);

	ok = c >= min && c <= max;
	if (RE_TYPE_INV_CLASS_MM == e->type)
		ok = !ok;

	if (ok)
		rec->tp++;

	REX_RETURN(bool, "%d", ok);
}

/**
 * Is next character part of the class range defined in the element?
 */
static bool
re_exec_match_char_class(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;
	const re_class_t *b = re_element_get_class(e);
	bool ok;

	REX_ENTRY;

	re_exec_log_where(rec);

	REX_DEBUG(RE_D_MATCHER,
		"looking for any %s \"%s\"",
		RE_TYPE_INV_CLASS == e->type ? "not in" : "of", re_class2str(b));

	if ('\0' == c)
		REX_RETURN(bool, "[reached end of text] %d", FALSE);

	if (e->icase)
		c = ascii_tolower(c);

	ok = re_class_belongs(b, c);

	/*
	 * If no match yet, look at the additional hardwired classes.
	 *
	 * FIXME: must expand the POSIX classes into the bit array!
	 */

	if (!ok && re_element_is_expanded(e)) {
		uint i;

		for (i = 0; i < RE_CLASS_POSIX_START && !ok; i++) {
			if (e->u.other->v.classes & (1U << i)) {
				ok = (*re_hardwired[i])(c);
				REX_DEBUG(RE_D_MATCHER, "bit %u, checking '%c' with %s: %s",
					i, c, stacktrace_function_name(re_hardwired[i]),
					ok ? "success!" : "failed");
			}
		}
	}

	/*
	 * If running with RE_X_MULTI_LINE, make inverted classes never match a \n.
	 * This behaviour prevents from accidentally moving to the next line.
	 */

	if G_UNLIKELY(c == '\n' && RE_TYPE_INV_CLASS == e->type) {
		if G_UNLIKELY(rec->eflags & RE_X_MULTI_LINE)
			REX_RETURN(bool, "[not matching \\n as told] %d", FALSE);
	}

	if (RE_TYPE_INV_CLASS == e->type)
		ok = !ok;

	if (ok)
		rec->tp++;

	REX_RETURN(bool, "%d", ok);
}

/**
 * Match one character at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_char_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;

	REX_ENTRY;

	re_exec_log_where(rec);
	REX_DEBUG(RE_D_MATCHER, "looking for '%c'", re_element_get_char(e));

	if G_UNLIKELY('\0' == c) {
		rec->tend = rec->tp;
		REX_RETURN(bool, "[text end] %d", FALSE);
	}

	if (e->icase)
		c = ascii_tolower(c);

	if (c == re_element_get_char(e)) {
		rec->tp++;
		REX_RETURN(bool, "%d", TRUE);
	}

	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Match all ([^]) character at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_char_all(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;

	REX_ENTRY;

	(void) e;

	re_exec_log_where(rec);

	if G_UNLIKELY('\0' == c) {
		rec->tend = rec->tp;
		REX_RETURN(bool, "[text end] %d", FALSE);
	}

	rec->tp++;
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Match any (.) character at beginning of text.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_char_any(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;

	REX_ENTRY;

	(void) e;

	re_exec_log_where(rec);

	if G_UNLIKELY('\0' == c) {
		rec->tend = rec->tp;
		REX_RETURN(bool, "[text end] %d", FALSE);
	}

	if G_UNLIKELY('\n' == c)
		REX_RETURN(bool, "[\\n not matched] %d", FALSE);

	rec->tp++;
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Check whether element is already registered for recursion.
 *
 * @return the item on the stack counting matches if we find it, NULL
 * if we're not recursing for the given element.
 */
static re_match_count_t *
re_exec_match_find_tracker(struct re_exec_ctx *rec, const re_element_t *e)
{
	re_match_count_t key;

	ZERO(&key);
	key.e = e;

	return eslist_find(&rec->multi, &key, re_exec_same_element);
}

static int re_asis(int c) { return c; }	/* For no case conversion */

/**
 * Check whether radix is also matching at the current node.
 *
 * @param rec		the execution context
 * @param e			the trie element we're matching against
 * @param tn		the trie node
 *
 * @return TRUE if there is a radix match, incrementing the current
 * location in the execution context, FALSE if there is no match, leaving
 * the current location intact.
 */
static bool
re_exec_match_trie_radix(
	struct re_exec_ctx *rec, const re_element_t *e, const trie_node_t *tn)
{
	const char *radix;

	REX_ENTRY;

	/*
	 * The trie is collapsed to save memory, so handle possible
	 * radix after the leading character.
	 *
	 * Note that if the trie is not collapsed, radix will always
	 * be NULL hence the code does not depend on the collapsing
	 * optimization.
	 *
	 * When the radix is long, this is more efficient than following
	 * children in the trie anyway, so collapsing the trie is a
	 * good idea as it saves a lot of memory and should not impact
	 * runtime performance during matching.
	 */

	radix = trie_node_radix(tn);

	if (radix != NULL) {
		size_t len = vstrlen(radix);
		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
			"looking for radix \"%s\", coming text \"%.*s\"",
			radix, (int) len, rec->tp);

		if (re_element_is_icase_trie(e)) {
			if (0 != strncasecmp((char *) rec->tp, radix, len))
				REX_RETURN(bool, "[radix mismatch] %d", FALSE);
		} else if (0 != strncmp((char *) rec->tp, radix, len)) {
			REX_RETURN(bool, "[radix mismatch] %d", FALSE);
		}

		rec->tp += len;
		REX_RETURN(bool, "[radix match] %d", TRUE);
	}

	REX_RETURN(bool, "[no radix] %d", TRUE);
}

/**
 * Compute trie node own matching length.
 *
 * This is the size of the text that would be matched by this particular
 * node if it were a matching node.
 */
static size_t
re_exec_trie_node_length(const trie_node_t *tn)
{
	const char *radix;

	if (trie_node_is_root(tn))
		return 0;		/* If root matches, it consumes the empty string */

	radix = trie_node_radix(tn);
	if (NULL == radix)
		return 1;		/* Only length is this node */

	return 1 + vstrlen(radix);
}

/**
 * Match trie with possible partial matches at beginning of text.
 *
 * This routine handles MATCH / ROUTE elements.
 */
static bool
re_exec_match_trie_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	const trie_node_t *fm = NULL;	/* First match position in trie */
	const trie_node_t *tn, *cn;
	int c;
	int (*convert)(int);			/* Input character case conversion */

	REX_ENTRY;
	REX_DEBUG(RE_D_MATCHER, "handling %s", re_elem_info(e));

	convert = re_element_is_icase_trie(e) ? ascii_tolower : re_asis;

	/*
	 * Matching happens to-down, not considering the possible root match
	 * until the end, at which time we start backtracking and considering
	 * earlier match positions, up to the root should no other match be
	 * successful.  Hence we skip the root node initially and go directly
	 * to the first child based on the coming text.
	 *
	 * We choose the longest-match first policy, since we lost the order
	 * by which the alternatives were listed in the original regular
	 * expression... This is a case of potential surprise when the trie
	 * optimization kicks in, but it is reasonable to expect the longest
	 * possible match.
	 *
	 * To avoid recursion, we maintain a "first_match" trie node position,
	 * which will be the first node down (including the root node) that
	 * ends up being a matching position.  That way, we can know whether,
	 * at a given depth, we have a possible shorter match or not.
	 *
	 * Since we do not recurse, we maintain the current text position
	 * dynamically and, should we have to "backtrack" (i.e. go back to
	 * an early position in the tree to attempt a shorter leading match),
	 * we simply subtract the length of the strings we matched in the trie.
	 *
	 * Finally, there are lots of goto statements in this routine since we
	 * want to avoid a recursive handling of partial matching alternatives.
	 *
	 * @note
	 * We rely the ability to move up to parent nodes in the trie, and
	 * therefore we make sure to not "compact" it (which could lead to
	 * shared nodes) but only "collapse" it (which should be sufficient
	 * to cut down on the overall memory used by the trie structure).
	 * Because the trie is collapsed, we have to pay attention to an
	 * optional radix attached to each node, since this is a string part
	 * which must count to obtain a match at a given trie node.
	 *
	 * Here is what a collapsed trie looks like, with '$' indicating a
	 * matching position if the node is not a leaf:
	 *
	 *     +
	 *     \-+ "foo"
	 *     . |-+ "bar"  = "foobar"
	 *     . |-+ "lap"$ = "foolap"       <- radix "ap" attached to 'l'
	 *     . | \-+ 's'  = "foolaps"      <- no radix attached to 's'
	 *     . \-+ "tar"  = "footar"
	 *
	 * At the "lap" node (we already matched "foo"), we follow the arc
	 * from "foo" to "lap" because we read 'l' in the text, but we still
	 * need to check that "ap" follows that initial 'l'.  We have a matching
	 * position at "foolap", but we will continue to see if an 's' comes,
	 * and whether choosing 's', matching "foolaps", leads to an overall
	 * matching success for the regular expression.
	 *
	 * If it does not, we'll backtrack, "unreading" the 's' and trying
	 * to match the regular expression with "foolap".  If it does not
	 * match either, then we can declare a failure since we have no
	 * other matching node up, and the root node (the empty string) is
	 * not a match.
	 */

	tn = trie_root(re_element_get_trie(e));

	if (trie_node_is_match(tn))
		fm = tn;		/* Root node is matching */

	/*
	 * Move down the trie, finding the longest possible match.
	 */

	while ('\0' != (c = (*convert)(*rec->tp))) {
		cn = trie_node_child(tn, c);

	looping:
		re_exec_log_where(rec);

		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "processing '%c' -> %s%s",
			c, NULL == cn ? "invalid" : "valid",
			NULL == cn ? "" :
				trie_node_is_match(cn) ? " (possible match)" : "");

		if (NULL == cn)
			break;			/* No child for `c', no match possible */

		rec->tp++;			/* The arc character we just consumed */

		if (!re_exec_match_trie_radix(rec, e, cn)) {
			rec->tp--;		/* Go back to end of `tn', the previous node */
			break;			/* Radix does not match, node is not a match */
		}

		/*
		 * `cn' is matching, update current node `tn'.
		 * This means the current text position is after `tn'.
		 */

		tn = cn;			/* We're now processing this node */

		/*
		 * Descend to handle match point if not already at a leaf node
		 * and if the next character is a valid child!
		 *
		 * Otherwise, handle the match here.
		 */

		if (trie_node_is_match(tn)) {
			REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "reached match at %s node",
				trie_node_is_leaf(tn) ? "a leaf" : "an internal");

			if (trie_node_is_leaf(tn))
				goto handle_match;

			if (NULL == fm) {
				fm = tn;
				REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "first partial match point");
			}

			c = (*convert)(*rec->tp);
			cn = trie_node_child(tn, c);

			/* If `c' is NUL, we know `cn' must be NULL */

			if (NULL == cn) {
				REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
					"looked-ahead char '%c' not a valid child", *rec->tp);
				REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
					"handling match now since no longer match possible");

				goto handle_match;
			}

			REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
				"looked-ahead char '%c' is a valid child", *rec->tp);
			REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "looping for longer match");

			goto looping;		/* Next character read, `cn' set correctly */
		}
	}

	REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
		"exit from loop at node '%c' + \"%s\"%s%s",
		trie_node_arc(tn),
		NULL == trie_node_radix(tn) ? "" : trie_node_radix(tn),
		fm == tn ? " first" : "", trie_node_is_match(tn) ? " match" : "");

	if (fm == tn)
		fm = NULL;

	if (trie_node_is_match(tn))
		goto handle_match;

	/* FALL THROUGH */

backtrack:
	if (NULL == fm)
		goto failed;

	/*
	 * Start backtracking from the latest node `tn' until we reach another
	 * possible match.  As we go up, we look for a node being `fm', our
	 * first possible earlier match to clear it up as we encounter it.
	 */

	REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "backtracking...");

	while (NULL != (cn = trie_node_parent(tn))) {
		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
			"backtracking from node '%c' + \"%s\"",
			trie_node_arc(tn),
			NULL == trie_node_radix(tn) ? "" : trie_node_radix(tn));

		rec->tp -= re_exec_trie_node_length(tn);
		re_exec_log_where(rec);

		tn = cn;

		if G_UNLIKELY(fm == tn) {
			fm = NULL;
			REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "reached first match");
		}
		if (trie_node_is_match(tn))
			goto handle_match;
	}

	/* FALL THROUGH */

failed:
	REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "resetting on match failure...");

	/*
	 * We have to backtrack the text position since we did not match.
	 *
	 * The latest node we traversed successfully is `tn' (which can be
	 * the trie root at this point).  We only need to restore the text
	 * position to what it was upon entry in this routine.
	 */

	while (NULL != (cn = trie_node_parent(tn))) {
		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
			"undoing match at node '%c' + \"%s\"",
			trie_node_arc(tn),
			NULL == trie_node_radix(tn) ? "" : trie_node_radix(tn));

		rec->tp -= re_exec_trie_node_length(tn);
		re_exec_log_where(rec);
		tn = cn;
	}

	g_assert(trie_node_is_root(tn));

	REX_RETURN(bool, "%d", FALSE);

handle_match:
	/*
	 * Handling match for `tn'.
	 */

	REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "handling match");
	re_exec_log_where(rec);

	/*
	 * ROUTE nodes have a value, but so do MATCH nodes to
	 * allow validation of the choice made.
	 */

	g_assert(trie_node_has_value(tn));

	/*
	 * Continue matching using recursion to validate choice.
	 *
	 * If the path we have followed since the root has involved
	 * a choice between a partial match or continuing to match
	 * a longer string (e.g. we have both "alpha" and "alphabet"
	 * in the trie and after "alpha" we read a 'b' and were able
	 * to match "alphabet"), then we need to request that we
	 * follow NEXT nodes to validate our choice and backtrack to
	 * the previous one ("alpha") if "alphabet" does not cause
	 * the rest of the regex to match.
	 *
	 * However, when we come back to "alpha", we know it's the last
	 * viable option to try and we will not require to follow NEXT
	 * nodes then: it's the last alternative to try.
	 */

	REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
		"got trie match, handling the rest, %s",
		fm != NULL ? "has prior match" : "no prior match");

	if (fm != NULL) {
		if (re_exec_match_here(rec, trie_node_value(tn), 0, TRUE))
			re_exec_success(rec);
		goto backtrack;
	} else {
		if (re_exec_match_here(rec, trie_node_value(tn), 0, FALSE))
			REX_RETURN(bool, "[vector match] %d", TRUE);

		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "no further match possible");
		goto failed;
	}

	g_assert_not_reached();
}

/**
 * Match trie with known exact matches at beginning of text.
 *
 * This routine handles MATCHX / ROUTEX elements.
 */
static bool
re_exec_match_trie_exact_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	const trie_node_t *tn;
	int c;
	int (*convert)(int);			/* Input character case conversion */
	const uchar *tp = rec->tp;

	REX_ENTRY;
	REX_DEBUG(RE_D_MATCHER, "handling %s", re_elem_info(e));

	convert = re_element_is_icase_trie(e) ? ascii_tolower : re_asis;

	/*
	 * No need to backtrack since the trie is known to have no partial
	 * matches. Simply follow it as a little Deterministic Finite Automaton.
	 */

	tn = trie_root(re_element_get_trie(e));

	while ('\0' != (c = (*convert)(*rec->tp++))) {
		re_exec_log_where(rec);
		tn = trie_node_child(tn, c);

		REX_DEBUG(RE_D_MATCHER | RE_D_TRIE, "processing '%c' -> %s%s",
			c, NULL == tn ? "invalid" : "valid",
			NULL == tn ? "" :
				trie_node_is_match(tn) ? " (possible match)" : "");

		if (NULL == tn)
			break;			/* No child for `c', no match possible */

		if (!re_exec_match_trie_radix(rec, e, tn))
			break;			/* Radix does not match, node is not a match */

		/*
		 * Handle match points: recall we know there cannot be any
		 * partial matching here, like having both strings "alpha" and
		 * "alphabet" in the trie and reaching "alpha".
		 */

		if (trie_node_is_match(tn)) {
			/* If no value, we are in a MATCHX node */

			if (!trie_node_has_value(tn))
				REX_RETURN(bool, "[full match] %d", TRUE);

			/*
			 * With a value, it's a ROUTEX node, continue matching
			 * using recursion.
			 *
			 * However, we don't need to follow NEXT nodes at this stage
			 * because the alternative path we have chosen is a perfect one:
			 * no other choice is possible for this alternative to match.
			 * That's what the X is for: it's an eXact match or no match.
			 *
			 * Hence we pass FALSE to re_exec_match_here().
			 */

			REX_DEBUG(RE_D_MATCHER | RE_D_TRIE,
				"got trie match, handling associated vector");

			if (re_exec_match_here(rec, trie_node_value(tn), 0, FALSE))
				REX_RETURN(bool, "[vector match] %d", TRUE);

			break;	/* No match: failure since it's a ROUTEX */
		}
	}

	rec->tp = tp;
	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Match a hardwired class character at current position.
 */
static bool
re_exec_match_hard_class_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;
	re_class_check_t matcher;

	REX_ENTRY;

	re_exec_log_where(rec);
	REX_DEBUG(RE_D_MATCHER, "matching for %s", re_elem_info(e));

	if ('\0' == c)
		REX_RETURN(bool, "[reached end of text] %d", FALSE);

	/*
	 * With RE_X_MULTI_LINE, make sure we never match a \n, to avoid
	 * accidentally moving to the next line of text.
	 */

	if G_UNLIKELY('\n' == c) {
		if (rec->eflags & RE_X_MULTI_LINE)
			REX_RETURN(bool, "[not matching \\n as told] %d", FALSE);
	}

	matcher = re_hard_class_matcher(e->type);

	if ((*matcher)(c)) {
		rec->tp++;
		REX_RETURN(bool, "%d", TRUE);
	}

	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Match a set of POSIX character classes at current position.
 */
static bool
re_exec_match_posix_class_one(struct re_exec_ctx *rec, const re_element_t *e)
{
	int c = *rec->tp;
	uint classes;
	size_t i;

	STATIC_ASSERT(N_ITEMS(re_hardwired) == RE_CLASS_POSIX_END + 1);

	REX_ENTRY;

	re_exec_log_where(rec);
	REX_DEBUG(RE_D_MATCHER, "matching for %s", re_elem_info(e));

	if ('\0' == c)
		REX_RETURN(bool, "[reached end of text] %d", FALSE);

	/*
	 * With RE_X_MULTI_LINE, make sure we never match a \n in an
	 * inverted class, to avoid accidentally moving to the next line of text.
	 */

	if G_UNLIKELY('\n' == c) {
		if (
			(rec->eflags & RE_X_MULTI_LINE) &&
			re_element_is_inverted_posix(e)
		)
			REX_RETURN(bool, "[not matching \\n as told] %d", FALSE);
	}

	/*
	 * Unlike hardwired character classes like \d or \W, a POSIX class matcher
	 * is actually composed of a "list" of matchers, each identified by a
	 * single bit in the classes bit field.
	 *
	 * For a normal (straight) class, any match among the specified classes
	 * is a success.  For an inverted class, none of the listed class can
	 * match, otherwise it is a failure.
	 */

	classes = re_element_get_classes(e);

	for (i = RE_CLASS_POSIX_START; i <= RE_CLASS_POSIX_END; i++) {
		if ((1U << i) & classes) {
			re_class_check_t matcher;

			g_assert(i < N_ITEMS(re_hardwired));
			matcher = re_hardwired[i];

			REX_DEBUG(RE_D_MATCHER, "attempting %s matching with %s()",
				re_element_is_inverted_posix(e) ? "inverted" : "straight",
				stacktrace_function_name(matcher));

			if (re_element_is_inverted_posix(e)) {
				/* None of the listed classes must match for success */
				if ((*matcher)(c))
					REX_RETURN(bool, "[FAILED inverted match] %d", FALSE);
			} else {
				/* Any listed class matching means success */
				if ((*matcher)(c)) {
					rec->tp++;
					REX_RETURN(bool, "[SUCCESS straight match] %d", TRUE);
				}
			}
		}
	}

	/* No match among listed classes */

	if (re_element_is_inverted_posix(e)) {
		rec->tp++;
		REX_RETURN(bool, "[SUCCESS (inverted match)] %d", TRUE);
	} else {
		REX_RETURN(bool, "[FAILED (straight match)] %d", FALSE);
	}
}

/**
 * Starting to match on a capturing group.
 */
static void NO_INLINE
re_exec_match_subn_start(struct re_exec_ctx *rec, const re_element_t *e)
{
	uint n = re_element_get_sub_number(e);
	void *entry;

	REX_ENTRY;

	/*
	 * If we have an element already registered in rec->multi, then this
	 * is a recursion into a group we already started matching, hence the
	 * initial starting point must not be changed.
	 */

	ZERO(&rec->tkey);
	rec->tkey.e = e;

	entry = eslist_find(&rec->multi, &rec->tkey, re_exec_same_element);

	REX_DEBUG(RE_D_MATCHPOS, "%s entry for %s (%p)",
		NULL == entry ? "no" : "found", re_elem_info(e), e);

	/*
	 * We capture matching text for the group based on the first position
	 * where we enter the group: we can only enter a group when there
	 * is no entry for the element in the rec->multi list.
	 *
	 * When they gave RE_X_NOSUB in the execution flags, we do not need
	 * to capture group matching.  We always keep track of matching for
	 * the groups that may later be perused in the pattern as a back-reference.
	 */

	if (NULL == entry) {
		if (0 == (rec->eflags & RE_X_NOSUB) || rec->bvec != NULL)
			re_exec_match_group_start(rec, n);
	}

	REX_RETURN_VOID;
}

/**
 * Match non-capturing group at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_group(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_group_one);
}

/**
 * Match alternative element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_or(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_or_one);
}

/**
 * Match back-reference element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_backref(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_backref_one);
}

/**
 * Match text element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_text(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_text_one);
}

/**
 * Match character element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_char(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_char_one);
}

/**
 * Match any (.) element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_any(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_char_any);
}

/**
 * Match all [^] element at beginning of text, with possible repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_all(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_char_all);
}

/**
 * Match coming text against trie, with no known partial matches.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_trie_exact(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_trie_exact_one);
}

/**
 * Match coming text against trie, with possible partial matches.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_trie(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_trie_one);
}

/**
 * Match character class at the current position, possibly with
 * repetitions.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_class(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_char_class);
}

/**
 * Match listed POSIX classes at the current position, possibly with
 * repetitions.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_posix_class(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_posix_class_one);
}

/**
 * Match character class defined as min/max character values at the current
 * position, possibly with repetitions.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_minmax(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_char_minmax);
}

/**
 * Match an hardwired class at the current position, possibly with repetition.
 *
 * @return TRUE if we matched
 */
static bool
re_exec_match_hardwired_class(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	return re_exec_match_repeat(rec, ev, n, re_exec_match_hard_class_one);
}

/**
 * Match start-of-text (^) at the current position.
 */
static bool
re_exec_match_start(const struct re_exec_ctx *rec)
{
	REX_ENTRY;

	re_exec_log_where(rec);

	if (rec->tp == rec->text)
		REX_RETURN(bool, "[text start] %d", TRUE);	/* At start of text */

	/*
	 * When running with RE_X_MULTI_LINE, \n is always considered to be
	 * the beginning of text.
	 */

	if G_UNLIKELY(rec->eflags & RE_X_MULTI_LINE) {
		if ('\n' == rec->tp[-1]) {
			REX_DEBUG(RE_D_EXEC, "after \\n with RE_X_MULTI_LINE");
			return TRUE;
		}
	}

	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Match end-of-text ($) at the current position.
 */
static bool
re_exec_match_end(const struct re_exec_ctx *rec)
{
	REX_ENTRY;

	re_exec_log_where(rec);

	if ('\0' == rec->tp[0])
		REX_RETURN(bool, "[text end] %d", TRUE);	/* At end of text */

	/*
	 * When running with RE_X_MULTI_LINE, \n is always considered to be
	 * the end of text.
	 */

	if G_UNLIKELY(rec->eflags & RE_X_MULTI_LINE) {
		if ('\n' == rec->tp[0]) {
			REX_DEBUG(RE_D_EXEC, "at \\n with RE_X_MULTI_LINE");
			return TRUE;
		}
	}

	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Match a word boundary (\b) at the current position.
 *
 * This does not change the current position, it is just an assertion.
 * No repetition needs to be handled as it is illegal to attach a repetition
 * count to an assertion.
 */
static bool
re_exec_match_word_boundary(const struct re_exec_ctx *rec)
{
	int c = *rec->tp;

	REX_ENTRY;

	re_exec_log_where(rec);

	/*
	 * Regardless of the current character, we are at a word boundary
	 * at the beginning or at the end of text.
	 */

	if (rec->tp == rec->text)
		REX_RETURN(bool, "[text start] %d", TRUE);	/* At start of text */

	if ('\0' == c)
		REX_RETURN(bool, "[text end] %d", TRUE);	/* At end of text */

	/*
	 * When running with RE_X_MULTI_LINE, a \n is always considered to be
	 * the beginning or end of text, hence we are at a word boundary.
	 */

	if G_UNLIKELY(rec->eflags & RE_X_MULTI_LINE) {
		if ('\n' == rec->tp[0])
			REX_RETURN(bool, "[at \\n with RE_X_NEWLINE] %d", TRUE);
	}

	if (is_ascii_ident(c)) {
		if (!is_ascii_ident(rec->tp[-1]))
			REX_RETURN(bool, "%d", TRUE);
	} else {
		if (is_ascii_ident(rec->tp[-1]))
			REX_RETURN(bool, "%d", TRUE);
	}

	REX_RETURN(bool, "%d", FALSE);
}

/**
 * Matcher routine with a re_exec_match_fn_t interface for ^, $, \b and \B.
 *
 * @return TRUE if element matches at the current position.
 */
static bool
re_exec_match_assertion(struct re_exec_ctx *rec, const re_element_t *e)
{
	switch (e->type) {
	case RE_TYPE_START:        return re_exec_match_start(rec);
	case RE_TYPE_END:          return re_exec_match_end(rec);
	case RE_TYPE_EMPTY:        return TRUE;	/* Always matches */
	case RE_TYPE_IS_BOUNDARY:  return re_exec_match_word_boundary(rec);
	case RE_TYPE_NOT_BOUNDARY: return !re_exec_match_word_boundary(rec);
	default:
		s_error("%s(): unsupported %s", G_STRFUNC, re_elem_info(e));
	}
}

/**
 * When hitting a NEXT, should we resume at the previous item in the
 * parent vector (re-entering the previous element recursively to grab
 * more input, thereby transforming NEXT into a virtual LOOPBACK
 * instruction) or should we follow it to return to the next entry in
 * the parent vector?
 *
 * @return TRUE if we need to resume at the previous entry.
 */
static bool NO_INLINE
re_exec_should_resume(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	re_element_t *be;	/* Element before next */
	re_match_count_t *latest;

	g_assert(n >= 1);	/* Ensures we have a previous */
	be = &ev->elements[n - 1];

	latest = re_exec_match_find_tracker(rec, be);

	if (latest != NULL) {
		g_assert(be == latest->e);	/* by virtue of find!*/

		REX_DEBUG(RE_D_EXEC,
			"%s(): found entry for %s (%p) n=%zu (min=%zu)",
			G_STRFUNC, re_elem_info(be), be,
			latest->n, re_element_get_repeat_min(be));

		return latest->n < re_element_get_repeat_max(be);
	}

	return FALSE;
}

/**
 * Wrapper on re_exec_match_group_one() to trap SUBN and remember current
 * position in text.
 */
static bool
re_exec_match_group_one_start(struct re_exec_ctx *rec, const re_element_t *e)
{
	if G_UNLIKELY(RE_TYPE_SUBN == e->type)
		re_exec_match_subn_start(rec, e);

	return re_exec_match_group_one(rec, e);
}

/**
 * Compute matching routine that can be used to match a given element.
 *
 * @param e		the element we attempt to match
 *
 * @return the matching routine to apply
 */
static re_exec_match_fn_t
re_exec_matcher_get(const re_element_t *e)
{
	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:        return re_exec_match_assertion;
	case RE_TYPE_END:          return re_exec_match_assertion;
	case RE_TYPE_EMPTY:        return re_exec_match_assertion;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:    return re_exec_match_char_class;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM: return re_exec_match_char_minmax;
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_S_CLASS:  return re_exec_match_hard_class_one;
	case RE_TYPE_NOT_POSIX_CLASS:
	case RE_TYPE_POSIX_CLASS:  return re_exec_match_posix_class_one;
	case RE_TYPE_CHAR:         return re_exec_match_char_one;
	case RE_TYPE_TEXT:         return re_exec_match_text_one;
	case RE_TYPE_BACKREF:      return re_exec_match_backref_one;
	case RE_TYPE_OR:           return re_exec_match_or_one;
	case RE_TYPE_ANY:          return re_exec_match_char_any;
	case RE_TYPE_ALL:          return re_exec_match_char_all;
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:    return re_exec_match_lookaround;
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTEX:       return re_exec_match_trie_exact_one;
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:        return re_exec_match_trie_one;
	case RE_TYPE_ATOMIC:
		/*
		 * FIXME:
		 * Will need to think about it, no correct support yet:
		 * atomic must never backtrack on failed greedy grabbing!
		 * Must probably propagate atomicity at compile time to all
		 * enclosed elements, because atomic matching is currently
		 * supported at the element level (i.e. "a++" works).
		 *
		 * That would mean "(?>ab|a)" does not backtrack when "ab" has
		 * matched but the rest of the pattern does not match.  This
		 * would impact trie-based matchers, because we lose the order
		 * of the alternatives in the trie.
		 *
		 * It's OK for now as this regex support is intended solely for
		 * usage in the logfilter, and I don't intend to rely on atomic
		 * matching in my patterns yet.
		 * 		--RAM, 2018-11-05
		 */
	case RE_TYPE_GROUP:
	case RE_TYPE_SUB:          return re_exec_match_group_one;
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY: return re_exec_match_assertion;
	case RE_TYPE_SUBN:
		/*
		 * If we're going to do a RE_N_ONCE match, we need to
		 * encapsulate the call to re_exec_match_group_one()
		 * so that proper group capturing is setup, since our
		 * caller will blindly call the matching routine without
		 * any further tests, for speed purposes..
		 */
		if (RE_N_ONCE == e->repeat)
			return re_exec_match_group_one_start;
		else
			return re_exec_match_group_one;
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
	case RE_TYPE_MAX:
		break;
	}

	g_assert_not_reached();
}

/**
 * Match element a fixed amount of time at current position.
 *
 * This is optimized because it requires no costly backtracking: either
 * we succeed matching all the elements, or we fail.
 *
 * @param rec	the execution context
 * @param e		the element to match.
 *
 * @return TRUE if success.
 *
 * @note
 * Needs to be NO_INLINE to avoid extra stack usage in its sole
 * caller re_exec_match_here(), which is highly recursive hence
 * must not be penalized!
 */
static bool NO_INLINE
re_exec_match_count(struct re_exec_ctx *rec, const re_element_t *e)
{
	const uchar *tp = rec->tp;
	size_t min = re_element_get_repeat_min(e);
	const re_exec_match_fn_t matcher = re_exec_matcher_get(e);

	g_assert(RE_N_COUNT == e->repeat);		/* min == max */
	g_assert(min != SIZE_MAX);
	g_assert(min != 0);

	REX_ENTRY;

	re_exec_log_where(rec);
	re_exec_check_stack(rec);

	REX_DEBUG(RE_D_MATCHER, "handling %s", re_elem_info(e));

	if G_UNLIKELY(RE_TYPE_SUBN == e->type)
		re_exec_match_subn_start(rec, e);

	while (min--) {
		if (!(*matcher)(rec, e)) {
			rec->tp = tp;
			REX_DEBUG(RE_D_MATCHER, "%zu match attempt%s still", PLURAL(min));
			REX_RETURN(bool, "%d", FALSE);
		}
	}

	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Match element vector at beginning of text.
 *
 * Normally NEXT pointers are not followed, since we recurse to match OR nodes
 * or groups.  However, when handling repetitions, we need to know whether a
 * particular choice we're making causes the regular expression to match, and
 * at that moment we need to linearly follow all the items. We will still
 * recurse into groups or other OR nodes we will encounter, but following
 * NEXT will cause us to "continue" to the next node that caused us to recurse
 * in the first place.
 *
 * NEXT nodes are also our hook to be able to iterate back to a former element
 * when its repetition count is not yet matched, by transferring the matching
 * control to that element instead of continuing along the chain.
 *
 * Finally NEXT nodes are strategically placed after SUBN nodes and therefore
 * allow us to update the current matching position at the end of the
 * repetitions, so that we may report the whole matching to users and use the
 * matching text for the capturing group in back-references.
 *
 * @note
 * Does not restore previous rec->tp on failure, this is up to the caller
 * to maintain (in order to save stack space, the information is only
 * maintained where it should be).
 *
 * @param rec		the execution context
 * @param ev		the element vector
 * @param n			starting position in vector
 * @param next		whether to follow NEXT pointers
 *
 * @return TRUE if we matched
 */
static bool G_FAST
re_exec_match_here(struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n,
	bool next)
{
	re_element_t *e;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);

	REX_ENTRY;

	re_exec_match_depth_inc(rec);
	re_exec_check_stack(rec);	/* Called recursively, monitor usage */

	/*
	 * Make sure we have enough text ahead when we start at the
	 * beginning of the vector.
	 */

	if (
		0 == n && ev->minlen != 0 &&
		!re_exec_has_enough_ahead(rec, ev->minlen)
	) {
		re_exec_match_depth_dec(rec);
		REX_RETURN(bool, "[not enough text] %d", FALSE);
	}

next:		/* Comes back here when we process NEXT nodes */

	re_elemvec_check(ev);

	for (e = &ev->elements[n]; n < ev->ecnt; n++, e++) {
		re_exec_log_where(rec);
		REX_DEBUG(RE_D_EXEC,
			"%s(): depth=%zu/%zu, n=%zu in ev=%p at %s%s",
			G_STRFUNC, rec->match_depth, rec->max_match_depth,
			n, ev, re_elem_info(e),
			next ? " -- with NEXT following" : "");

		if G_UNLIKELY(RE_TYPE_RETURN == e->type)
			goto success;

		if G_UNLIKELY(RE_TYPE_NEXT == e->type) {
			ev = e->u.other->x.next.vec;
			n =  e->u.other->x.next.n;

			REX_DEBUG(RE_D_EXEC,
				"%s(): NEXT pointing to ev=%p, n=%zu", G_STRFUNC, ev, n);

			/*
			 * If item before the NEXT was a SUBN (capturing group),
			 * the current position is the end of the matching string
			 * for that group.
			 */

			re_exec_match_subn_handle(rec, ev, n);

			if (next) {
				/*
				 * If there are entries in rec->multi for the
				 * element before NEXT, we need to recurse back
				 * to that element because it has not yet matched
				 * its minimum!
				 */

				REX_DEBUG(RE_D_EXEC,
					"%s(): multi list count is %zu",
					G_STRFUNC, eslist_count(&rec->multi));

				if (
					0 != eslist_count(&rec->multi) &&
					re_exec_should_resume(rec, ev, n)
				) {
					n--; /* Go to previous item, same element vector */

					REX_DEBUG(RE_D_EXEC,
						"%s(): resuming at ev=%p, n=%zu",
					G_STRFUNC, ev, n);

					goto next;
				}
				REX_DEBUG(RE_D_EXEC,
					"%s(): following NEXT at ev=%p, n=%zu", G_STRFUNC, ev, n);
				goto next;
			} else {
				REX_DEBUG(RE_D_EXEC,
					"%s(): handling NEXT as a RETURN", G_STRFUNC);
				goto success;		/* NEXT is the last item in the vector! */
			}
		}

		/*
		 * Optimize for the likely case of an item matching exactly once
		 * or non-recursive items with a fixed repetition count.
		 */

		if G_LIKELY(RE_N_ONCE == e->repeat) {
			re_exec_log_where(rec);
			if ((*re_exec_matcher_get(e))(rec, e))
				continue;
			goto failed;
		} else if G_UNLIKELY(
				RE_N_COUNT == e->repeat &&
				!re_element_needs_tracking(e)
		) {
			if (re_exec_match_count(rec, e))
				continue;
			goto failed;
		}

		/* Multiple or zero matches, possibly unbounded */

		switch ((re_elem_type_t) e->type) {
		case RE_TYPE_EMPTY:
			continue;		/* Always matches */
		case RE_TYPE_CLASS:
		case RE_TYPE_INV_CLASS:
			if (re_exec_match_class(rec, ev, n))
				continue;
			break;
		case RE_TYPE_CLASS_MM:
		case RE_TYPE_INV_CLASS_MM:
			if (re_exec_match_minmax(rec, ev, n))
				continue;
			break;
		case RE_TYPE_D_CLASS:
		case RE_TYPE_W_CLASS:
		case RE_TYPE_S_CLASS:
		case RE_TYPE_NOT_D_CLASS:
		case RE_TYPE_NOT_W_CLASS:
		case RE_TYPE_NOT_S_CLASS:
			if (re_exec_match_hardwired_class(rec, ev, n))
				continue;
			break;
		case RE_TYPE_POSIX_CLASS:
		case RE_TYPE_NOT_POSIX_CLASS:
			if (re_exec_match_posix_class(rec, ev, n))
				continue;
			break;
		case RE_TYPE_CHAR:
			if (re_exec_match_char(rec, ev, n))
				continue;
			break;
		case RE_TYPE_TEXT:
			if (re_exec_match_text(rec, ev, n))
				continue;
			break;
		case RE_TYPE_BACKREF:
			if (re_exec_match_backref(rec, ev, n))
				continue;
			break;
		case RE_TYPE_OR:
			if (re_exec_match_or(rec, ev, n))
				continue;
			break;
		case RE_TYPE_ANY:
			if (re_exec_match_any(rec, ev, n))
				continue;
			break;
		case RE_TYPE_ALL:
			if (re_exec_match_all(rec, ev, n))
				continue;
			break;
		case RE_TYPE_MATCHX:
		case RE_TYPE_ROUTEX:
			if (re_exec_match_trie_exact(rec, ev, n))
				continue;
			break;
		case RE_TYPE_MATCH:
		case RE_TYPE_ROUTE:
			if (re_exec_match_trie(rec, ev, n))
				continue;
			break;
		case RE_TYPE_SUBN:
			re_exec_match_subn_start(rec, e);
			/* FALL THROUGH */
		case RE_TYPE_ATOMIC:
			/*
			 * FIXME
			 * Will need to think about it, no correct support yet:
			 * 		--RAM, 2018-11-05
			 */
		case RE_TYPE_GROUP:
		case RE_TYPE_SUB:
			if (re_exec_match_group(rec, ev, n))
				continue;
			break;
		case RE_TYPE_START:		/* These cannot have a repetition! */
		case RE_TYPE_END:
		case RE_TYPE_IS_BOUNDARY:
		case RE_TYPE_NOT_BOUNDARY:
		case RE_TYPE_AHEAD:
		case RE_TYPE_NOT_AHEAD:
		case RE_TYPE_NEXT:
		case RE_TYPE_RETURN:
		case RE_TYPE_MAX:
			g_assert_not_reached();
		}

		/* FALL THROUGH */

failed:
		re_exec_log_where(rec);
		REX_DEBUG(RE_D_EXEC,
			"%s(): FAILED for %s, n=%zu/%zu",
			G_STRFUNC, re_elem_info(e), n, ev->ecnt);

		re_exec_match_depth_dec(rec);
		REX_RETURN(bool, "%d", FALSE);
	}

success:
	re_exec_match_depth_dec(rec);
	REX_RETURN(bool, "%d", TRUE);
}

/**
 * Computes suitable starting point, at of after current position.
 *
 * @return NULL if we can no longer match, the starting point otherwise.
 */
static const uchar * G_FAST
re_exec_start_point(const struct re_exec_ctx *rec)
{
	register const uchar *tp = rec->tp;
	const uint8 *fcmap = rec->re->fcmap;
	register int c;

	re_exec_ctx_check(rec);

	REX_ENTRY;
	re_exec_log_where(rec);

	if (NULL == fcmap)
		goto current;

	do {
		c = *tp++;
		if (fcmap[c])
			goto matched;
	} while (c != '\0');

	/* FALL THROUGH */

	REX_RETURN(const uchar *, "[no other suitable point] %p", NULL);

current:
	REX_RETURN(const uchar *, "[default: current position] %p", tp);

matched:
	REX_RETURN(const uchar *, "[first char match] %p", tp - 1);
}

/**
 * Attempt to match the given element at the end of the input text.
 *
 * This is used to quickly assess whether the pattern can match when it is
 * anchored at the end.
 *
 * @param rec		the execution context
 * @param e			the element we want to match once at the end
 *
 * @return TRUE if there is a match.
 *
 * @note
 * Function marked NO_INLINE since it is used only once by the routine
 * at the root of the matching, hence we do not want to keep the price
 * of the stack used by its local variables.
 */
static bool NO_INLINE
re_exec_end_match(struct re_exec_ctx *rec, const re_element_t *e)
{
	const uchar *tp;
	re_exec_match_fn_t matcher;
	bool match;
	size_t minlen;

	g_assert(rec->tp == rec->text);		/* At the beginning */

	REX_ENTRY;

	minlen = re_element_get_minlen(e);
	tp = re_exec_find_end(rec) - minlen;

	REX_DEBUG(RE_D_EXEC | RE_D_MATCHER,
		"trying to match %s at the end (minlen=%zu)%s",
		re_elem_info(e), minlen,
		(rec->eflags & RE_X_MULTI_LINE) ? " with RE_X_MULTI_LINE" : "");

	if (tp < rec->text)
		REX_RETURN(bool, "[not enough text] %d", FALSE);

	/*
	 * The switch below lists the same types as the ones selected
	 * by re_finalize_ending_element().
	 */

	switch (e->type) {
	case RE_TYPE_CHAR:         matcher = re_exec_match_char_one;        break;
	case RE_TYPE_TEXT:         matcher = re_exec_match_text_one;        break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:    matcher = re_exec_match_char_class;      break;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM: matcher = re_exec_match_char_minmax;     break;
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_S_CLASS:
	case RE_TYPE_NOT_W_CLASS:  matcher = re_exec_match_hard_class_one;  break;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS:
							   matcher = re_exec_match_posix_class_one; break;
	default:
		/* Fix re_finalize_ending_element() or this routine */
		s_carp_once("%s(): BUG: unhandled %s", G_STRFUNC, re_elem_info(e));
		REX_RETURN(bool, "[BUG unexpected element type] %d", FALSE);
	}

	/*
	 * Prepare context so that we can call the individual element
	 * matcher at the "end - minlen" position.
	 */

	rec->tp = tp;
	match = (*matcher)(rec, e);		/* Match once, disregarding repetitions */
	rec->tp = rec->text;

	REX_RETURN(bool, "%d", match);
}

/**
 * Match compiled pattern in whole text.
 *
 * @return the matching start point, NULL if not found.
 */
static const uchar *
re_exec_match_pattern(struct re_exec_ctx *rec, const cpattern_t *pat)
{
	const char *p;

	REX_ENTRY;

	REX_DEBUG(RE_D_CONSTANT | RE_D_EXEC,
		"looking for \"%s\"", pattern_string(pat));

	p = pattern_search(pat, (char *) rec->text,
			ptr_diff(re_exec_find_end(rec), rec->text), 0, qs_any);

	REX_RETURN(const uchar *, "%p", (uchar *) p);
}

/**
 * Check whether text exhibits the required string, to rule out possible
 * matches early in the process.
 *
 * @return TRUE if the required string is present.
 */
static bool
re_exec_has_must(struct re_exec_ctx *rec)
{
	const uchar *p;

	REX_ENTRY;

	/*
	 * If they specified RE_X_NO_MUST, then act as if it had been found.
	 */

	if (rec->eflags & RE_X_NO_MUST) {
		REX_DEBUG(RE_D_CONSTANT, "faking success");
		REX_RETURN(bool, "[faked due to RE_X_NO_MUST] %d", TRUE);
	}

	p = re_exec_match_pattern(rec, rec->re->must);

	if (p != NULL)
		REX_RETURN(bool, "%d", TRUE);

	REX_RETURN(bool, "[not found] %d", FALSE);
}

G_IGNORE_PUSH(-Wclobbered);			/* For `vtp' in function below */

/**
 * Match element vector against text, anywhere.
 *
 * @param rec		the execution context
 * @param ev		the element vector
 * @param n			starting position in vector
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int
re_exec_match_ev(struct re_exec_ctx *rec, const re_elemvec_t *ev)
{
	volatile const uchar *vtp;
	int ret;

	PRIVLOG_DECLARE_LEVEL(indent);

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);

	REX_ENTRY;
	PRIVLOG_SAVE_LEVEL(indent);

	re_exec_check_stack(rec);	/* Just starting, track minimal usage so far */

	/*
	 * If we have a "must" string, see whether it is present in the
	 * text being matched.
	 */

	if (rec->re->must != NULL && !re_exec_has_must(rec))
		REX_RETURN(int, "[lacks \"must\" string] %+d", FALSE);

	/*
	 * If we have a non-zero minimum length of text to match, make sure
	 * we have it before starting the engine!
	 */

	if (ev->minlen != 0 && !re_exec_has_enough_ahead(rec, ev->minlen))
		REX_RETURN(int, "[not enough text anyway] %+d", FALSE);

	/*
	 * Our protection against stack space abnormal usage, and the easy
	 * exit point from deep recursions when we figure out we have a match!
	 */

	vtp = re_exec_start_point(rec);

	if ((ret = Setjmp(rec->matched))) {
		PRIVLOG_RESTORE_LEVEL(indent);
		if (ret > 0)
			re_exec_matched(rec, 0, vtp);
		REX_RETURN(bool, "[after longjmp()] %d", ret);
	}

	/*
	 * If the end of text is known and the last element of the regular
	 * expression is an END and the item before that is a constant string
	 * that must match at least once, immediately check for it.
	 */

	if (NULL != rec->re->end) {
		REX_DEBUG(RE_D_EXEC, "pattern anchored at the end");

		if (!re_exec_end_match(rec, rec->re->end))
			REX_RETURN(bool,  "[end does not match] %d", FALSE);

		REX_DEBUG(RE_D_EXEC, "end would match, trying whole pattern");
	}

	/*
	 * Now attempt to match the whole pattern.
	 *
	 * If the pattern does not match at the current position, we
	 * quickly scan ahead for the next suitable starting point if we
	 * can, or move ahead by one single char and re-attempt matching.
	 */

	for (;;) {
		if (NULL == vtp)
			goto failed;

		rec->tp = (uchar *) vtp;

#ifdef PRIVLOG_ENABLED
		rec->match_start = (uchar *) vtp;
#endif

		REX_DEBUG(RE_D_EXEC, "%s(): starting", G_STRFUNC);
		re_exec_log_where(rec);

		if (re_exec_match_here(rec, ev, 0, FALSE))
			REX_RETURN(bool, "[matched] %d",  re_exec_matched(rec, 0, vtp));

		rec->tp = (uchar *) vtp;
		if ('\0' == *rec->tp++)		/* Move one position forward */
			break;

		vtp = re_exec_start_point(rec);
	}

	/* FALL THROUGH */

failed:
	REX_RETURN(bool,  "[no match] %d", FALSE);
}

G_IGNORE_POP;

/**
 * Match anchored string.
 *
 * @return 1 if OK, 0 if not matched.
 */
static int
re_exec_match_anchored(struct re_exec_ctx *rec)
{
	const char *p;

	REX_ENTRY;

	if (rec->re->at_start) {
		if (rec->icase)
			p = is_strcaseprefix((char *) rec->text, rec->re->u.anchored);
		else
			p = is_strprefix((char *) rec->text, rec->re->u.anchored);

		if (NULL == p)
			REX_RETURN(int, "[not prefix] %+d", 0);

		rec->tp = (uchar *) p;

		if (rec->re->at_end && !re_exec_match_end(rec))
			REX_RETURN(int, "[at start but not at end] %+d", 0);

		re_exec_matched(rec, 0, rec->text);
	}
	else if (rec->re->at_end) {
		const char *tend, *start;
		size_t len = vstrlen(rec->re->u.anchored);

		if (rec->eflags & RE_X_MULTI_LINE) {
			tend = vstrchr((char *) rec->text, '\n');
			if (NULL == tend)
				tend = vstrchr((char *) rec->text, '\0');
		} else {
			tend = vstrchr((char *) rec->text, '\0');
		}

		if (len >= ptr_diff(tend, rec->text))
			REX_RETURN(int, "[text too small] %+d", 0);

		start = tend - len;

		if (rec->icase)
			p = is_strcaseprefix(start, rec->re->u.anchored);
		else
			p = is_strprefix(start, rec->re->u.anchored);

		if (NULL == p)
			REX_RETURN(int, "[not suffix] %+d", 0);

		rec->tp = (uchar *) tend;
		re_exec_matched(rec, 0, (uchar *) start);
	}

	REX_RETURN(int, "[matched] %+d", 1);
}

/**
 * Match fixed pattern.
 *
 * @return 1 if OK, 0 if not matched.
 */
static int
re_exec_match_fixed(struct re_exec_ctx *rec)
{
	const uchar *p;

	REX_ENTRY;

	p = re_exec_match_pattern(rec, rec->re->u.cp);

	if (NULL == p)
		REX_RETURN(int, "[not found] %+d", FALSE);

	rec->tp = p + pattern_len(rec->re->u.cp);
	re_exec_matched(rec, 0, p);

	REX_RETURN(int, "[matched] %+d", TRUE);
}

/**
 * Main entry point for regular expression matching.
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int
re_exec_match(struct re_exec_ctx *rec)
{
	REX_ENTRY;

	re_exec_ctx_check(rec);

	/*
	 * An empty regular expression (NULL compiled pointer)
	 * is always matching at the start of the text.
	 */

	if G_UNLIKELY(rec->re->is_empty) {
		if (rec->mvec != NULL) {
			rec->mvec[0].re_start = rec->mvec[0].re_end = 0;
		}
		REX_RETURN(int, "[empty regex] %+d", TRUE);
	}

	if (rec->re->is_simple) {
		REX_DEBUG(RE_D_EXEC, "expression is simple (%s%s%s%s)",
			rec->re->at_start || rec->re->at_end ?
				"anchored string at" : "fixed pattern",
			rec->re->at_start ? " start" : "",
			rec->re->at_start && rec->re->at_end ? " +" : "",
			rec->re->at_end ? " end" : "");
		if (rec->re->at_start || rec->re->at_end) {
			REX_RETURN(int, "%+d", re_exec_match_anchored(rec));
		} else {
			REX_RETURN(int, "%+d", re_exec_match_fixed(rec));
		}
	}

	REX_RETURN(int, "%+d", re_exec_match_ev(rec, rec->re->u.compiled));
}

static void
re_execute_match_clear(struct re_exec_ctx *rec)
{
	/*
	 * If they want positions for matching text, initialize all
	 * the positions with -1 to mark them unused.
	 *
	 * When RE_X_NOSUB was specified, we only clear mvec[0], which is
	 * important if there is no match.
	 */

	if (rec->mvec != NULL) {
		size_t i;
		size_t upper = 0 == (rec->eflags & RE_X_NOSUB) ? rec->mcnt : 1;

		g_assert(rec->mcnt >= upper);

		for (i = upper; i != 0; i--) {
			re_match_t *m = &rec->mvec[i - 1];
			m->re_start = m->re_end = (ssize_t) -1;
		}
	}
}

/**
 * Setup execution context.
 *
 * @param rec		the regex execution context to setup
 * @param re		the compiled regular expression
 * @param string	the NUL-terminated string against which match is attempted
 * @param slen		size of string if known, -1 if unknown
 * @param mvec		array of re_match_t to get match positions
 * @param mcnt		amount of entries in mvec
 * @param eflags	execution flags
 */
static void
re_execute_setup_context(struct re_exec_ctx *rec,
	const re_regex_t *re, const char *string, size_t slen,
	re_match_t *mvec, size_t mcnt, uint eflags)
{
	size_t stack;

	/*
	 * We include the regular expression in the context just for the
	 * initial matching when we have simple regex (constant patterns
	 * or leading / trailing fixed).
	 */

	ZERO(rec);
	rec->magic     = RE_EXEC_CTX_MAGIC;
	rec->re        = re;
	rec->text      = rec->tp = (uchar *) string;
	rec->tend      = (size_t) -1 == slen ? NULL : (rec->text + slen);
	rec->mvec      = mvec;
	rec->mcnt      = mcnt;
	rec->stack_top = rec;
	rec->eflags    = eflags;
	rec->icase     = re->icase;

#ifdef PRIVLOG_ENABLED
	rec->match_start  = rec->text;
#endif

	eslist_init(&rec->multi, offsetof(re_match_count_t, link));

	/*
	 * Compute maximum stack we can devote to matching without
	 * causing a stack overflow.
	 *
	 * Created threads will have a known stack size and we can
	 * therefore figure out how much to devote.  Discovered threads
	 * have an unknown maximum size, we assume a safe minimal value.
	 */

	stack = thread_stack_size();
	if (0 == stack) {
		rec->max_stack = RE_STACK_MAX;	/* Unknown thread stack size */
	} else {
		size_t used = thread_stack_used();
		if (used >= stack || stack - used < THREAD_STACK_MIN)
			rec->max_stack = THREAD_STACK_MIN / 3;
		else
			rec->max_stack = stack - used - THREAD_STACK_MIN / 2;;
	}

	re_execute_match_clear(rec);
}

/***
 *** ======================== User API ========================
 ***/

/**
 * Execute regular expression.
 *
 * Same as re_execute_full() but collects and reports execution statistics
 * in the user-supplied `stats' structure.
 */
int
re_execute_stats(const re_regex_t *re, const char *string, size_t slen,
	re_match_t *mvec, size_t mcnt, uint eflags, re_exec_stats_t *stats)
{
	struct re_exec_ctx ctx;
	int r;
	tm_t start, end;

	REX_ENTRY;

	re_regex_check(re);
	g_assert(string != NULL);
	g_assert_log(
		(size_t) -1 == slen || size_is_non_negative(slen),
		"%s(): slen=%zd", G_STRFUNC, slen);
	g_assert_log(size_is_non_negative(mcnt),
		"%s(): mcnt=%zd", G_STRFUNC, mcnt);
	g_assert_log(equiv(mcnt != 0, mvec != NULL),
		"%s(): mcnt=%zu, mvec=%p", G_STRFUNC, mcnt, mvec);

	if (NULL == mvec || 1 == mcnt)
		eflags |= RE_X_NOSUB;	/* No need to capture, there is no room */

	re_execute_setup_context(&ctx, re, string, slen, mvec, mcnt, eflags);

	REX_DEBUG(RE_D_EXEC, "matching \"%s\"", re->pattern);

	/*
	 * When they have back-references in the pattern, we need to make sure
	 * we remember the matching text.  To make code simpler, we always
	 * create an internal capturing context for the back-references we need
	 * to refer-to.  Those are indexed in the LUT.
	 */

	if (re->backref_count != 0) {
		size_t bsize = re->backref_count * sizeof(re_match_t);

		REX_DEBUG(RE_D_EXEC, "uses %zu back-ref%s, reserving %zu bytes on stack",
			PLURAL(re->backref_count), bsize);

		ctx.bvec = alloca(bsize);
		memset(ctx.bvec, 0, bsize);		/* For sanity checks later on */
	}

	REX_DEBUG(RE_D_EXEC, "stack usage limit: %zd bytes", ctx.max_stack);

	if (stats != NULL)
		tm_now_exact(&start);

	r = re_exec_match(&ctx);

	if (stats != NULL) {
		tm_now_exact(&end);
		stats->elapsed    = (size_t) tm_elapsed_us(&end, &start);
		stats->stack_max  = ctx.max_stack;
		stats->stack_used = ctx.max_stack_used;
	}

	if (r != +1)				/* `r' is an int, can be -1 on overflow */
		re_execute_match_clear(&ctx);

	REX_DEBUG(RE_D_EXEC, "when matching \"%s\":", re->pattern);
	REX_DEBUG(RE_D_EXEC, "max stack used: %zu bytes", ctx.max_stack_used);

#if PRIVLOG_ENABLED
	REX_DEBUG(RE_D_EXEC, "max stack allowed: %zd bytes", ctx.max_stack);
	REX_DEBUG(RE_D_EXEC, "max recursion depth: %zu", ctx.max_match_depth);
	REX_DEBUG(RE_D_EXEC, "re_exec_match_here() calls: %zu", ctx.match_calls);
#endif	/* PRIVLOG_ENABLED */

	REX_RETURN(bool, "%d", r);
}

/**
 * Execute regular expression.
 *
 * If "slen" is -1, then the size of the string will be figured out as the
 * regex engine attempts the match.  If known beforehand, it can allow early
 * optimization for anchored matches at the end.
 *
 * If "mvec" is non-NULL, capturing groups will return match position.
 * The mvec[0] entry is storing the start/end position for the whole pattern,
 * then one entry is used per capturing group: mvec[1] is the first group, etc...
 *
 * If the mvec[] array is too small, the matching positions are no longer filled.
 * Use re_group_count() to determine how many capturing groups there are for
 * a given regular expression.
 *
 * Unused entries within the mvec[] array are set with -1 for start/end offsets.
 *
 * @param re		a compiled regular expression
 * @param string	the NUL-terminated string against which match is attempted
 * @param slen		size of string if known, -1 if unknown
 * @param mvec		array of re_match_t to get match positions
 * @param mcnt		amount of entries in mvec
 * @param eflags	execution flags
 *
 * @return +1 if match succeeds on string, 0 if it failed and -1 on error.
 */
int
re_execute_full(const re_regex_t *re, const char *string, size_t slen,
	re_match_t *mvec, size_t mcnt, uint eflags)
{
	return re_execute_stats(re, string, slen, mvec, mcnt, eflags, NULL);
}

/**
 * Execute regular expression.
 *
 * @param re		a compiled regular expression
 * @param string	the NUL-terminated string against which match is attempted
 * @param eflags	execution flags
 *
 * @return +1 if match succeeds on string, 0 if it failed and -1 on error.
 */
int
re_execute(const re_regex_t *re, const char *string, uint eflags)
{
	return re_execute_stats(re, string, (size_t) -1, NULL, 0, eflags, NULL);
}

/**
 * Execute regular expression.
 *
 * @param re		a compiled regular expression
 * @param string	the NUL-terminated string against which match is attempted
 * @param slen		known length of string
 * @param eflags	execution flags
 *
 * @return +1 if match succeeds on string, 0 if it failed and -1 on error.
 */
int
re_execute_len(const re_regex_t *re,
	const char *string, size_t slen, uint eflags)
{
	g_assert(size_is_non_negative(slen));

	return re_execute_stats(re, string, slen, NULL, 0, eflags, NULL);
}

/**
 * @return pattern string.
 */
const char *
re_pattern(const re_regex_t *re)
{
	re_regex_check(re);
	return re->pattern;
}

/**
 * @return whether regex is optimized as fixed-pattern or string comparison.
 */
bool
re_is_simple(const re_regex_t *re)
{
	re_regex_check(re);
	return re->is_simple;
}

/**
 * @return whether regex went through the optimizer.
 */
bool
re_is_optimized(const re_regex_t *re)
{
	re_regex_check(re);
	return re->optimized;
}

/**
 * @return minimum text length we can match.
 */
size_t
re_match_length_min(const re_regex_t *re)
{
	re_regex_check(re);

	if (re->is_empty)
		return 0;
	else if (re->is_simple) {
		if (re->at_start || re->at_end) {
			return vstrlen(re->u.anchored);
		} else
			return pattern_len(re->u.cp);
	} else {
		return re->u.compiled->minlen;
	}
}

/**
 * @return maximum text length we can match.
 */
size_t
re_match_length_max(const re_regex_t *re)
{
	re_regex_check(re);

	if (re->is_empty || re->is_simple) {
		return re_match_length_min(re);	/* Constant string, min == max  */
	} else {
		return re->u.compiled->maxlen;
	}
}

/**
 * How many capturing groups are defined in the regular expression?
 *
 * This information can be used to size the re_match_t vector when executing
 * a regular expression: index 0 in that array is reserved for the whole
 * matching (as if a pseudo capturing group #0 was enclosing the regular
 * expression) and then indices 1..n are for groups 1..n.
 *
 * The re_match_t vector size should therefore be 1 + re_group_count() to
 * be able to capture all the matching group positions.
 *
 * @return amount of capturing groups for this regular expression.
 */
size_t
re_group_count(const re_regex_t *re)
{
	re_regex_check(re);
	return re->group_count;
}

/**
 * Recompile regular expression with different flags.
 *
 * @param re		the already compiled regular expression
 * @param cflags	new compilation flags
 */
void
re_recompile(re_regex_t *re, uint32 cflags)
{
	bstr_t *bs = NULL;
	istream_t *is = NULL;
	re_parser_t *rp = NULL;
	size_t len;

	re_regex_check(re);

	len = vstrlen(re->pattern);

	if G_UNLIKELY(0 == len)
		return;

	bs = bstr_open(re->pattern, len, BSTR_F_ERROR);
	is = istream_open_bstr(bs);
	rp = re_parser_alloc(is, cflags);

	if (!re_parse(rp)) {
		/*
		 * Regular expression compiled initially, this should not happen
		 * hence loudly complain with details.
		 */
		s_carp("%s(): failed to recompile \"%s\": %s at offset %zu",
			G_STRFUNC, re->pattern,
			re_strerror(rp->error.code), rp->error.pos);
	} else {
		re_free_recompiled(re);
		re_parsed_ok(re, rp, cflags);
	}

	istream_close(is);
	re_parser_free(rp);
	bstr_free(&bs);
}

/**
 * Free regular expression and nullify its pointer.
 */
void
re_free_null(re_regex_t **re_ptr)
{
	re_regex_t *re = *re_ptr;

	if (re != NULL) {
		re_free(re);
		*re_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
