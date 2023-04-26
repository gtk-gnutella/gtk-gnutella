/*
 * Copyright (c) 2018, 2020, 2023, 2024 Raphael Manfredi
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
 * \0DD		octal escape, 2 digits (D = octal digit)
 *
 * LIMITATIONS
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
 * The first implementation of 2018 was fully functional with the C matching
 * engine (simpler to code for validating the matching logic).  It was merely
 * a dynamic interpretation of the compiled regular expression tree.
 *
 * The REMI (Regular Expression Matching Interpreter) part was implemented
 * during the COVID-19 confinement episode, in 2020.  It initially started
 * as an experiment, to see how much it could reduce the stack space usage
 * required during matching.  It turned out to outperform the C matching
 * engine by a factor of 2 on average, hence it was fully developed to match
 * the level of functionality done in the C engine.
 *
 * REMI generates bytecode which uses highly specialized instructions that
 * are interpreted at runtime to perform the actual matching of the regular
 * expression against the text.
 *
 * In general, REMI exhibits a more compact representation of the regex than
 * the one achieved by the regular expression tree (hierarchical elements).
 * Its byte code can benefit from low-level optimizations and can embed static
 * knowledge determined at compilation time, to form an efficient "program".
 *
 * @author Raphael Manfredi
 * @date 2018, 2020, 2023, 2024
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
#define RE_D_MI			(1U << 7)	/* Matching Interpreter */

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
#include "atomic.h"
#include "bit_array.h"
#include "bit_field.h"
#include "bstr.h"
#include "buf.h"
#include "compat_setjmp.h"
#include "dualhash.h"
#include "endian.h"
#include "eslist.h"
#include "halloc.h"
#include "hashing.h"
#include "hset.h"
#include "hstrfn.h"
#include "htable.h"
#include "istream.h"
#include "log.h"
#include "mempcpy.h"
#include "misc.h"
#include "ostream.h"
#include "parse.h"
#include "pattern.h"
#include "str.h"
#include "stringify.h"
#include "thread.h"
#include "tm.h"
#include "tokenizer.h"
#include "trie_fmt.h"
#include "trie.h"
#include "unsigned.h"
#include "vsort.h"
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
#define RE_MI_STACK			(16*1024)

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

enum re_mi_seg_magic {
	RE_MI_SEG_MAGIC     = 0x02c7160f,
	RE_MI_SEG_DYN_MAGIC = 0x5f1388ea
};

/**
 * A segment in our byte code (could be TEXT or DATA).
 */
typedef struct re_mi_seg {
	enum re_mi_seg_magic magic;
	uint8 *base;		/* Start of segment */
	uint8 *p;			/* Next byte to fill, or end of segment when frozen */
	size_t len;			/* Length of segment in bytes */
} re_mi_seg_t;

static inline void
re_mi_seg_check(const re_mi_seg_t * const s)
{
	g_assert(s != NULL);
	g_assert(RE_MI_SEG_MAGIC == s->magic || RE_MI_SEG_DYN_MAGIC == s->magic);
}

/* Amounts of bytes used by the segment (its length once segment is frozen) */
static inline size_t ALWAYS_INLINE
re_mi_seg_used(const re_mi_seg_t *ms)
{
	return ms->p - ms->base;
}

/**
 * Generated byte code information
 *
 * There is a "text" segment, which is the program text, the matching
 * instructions we will interpret to perform the actual pattern matching.
 * This segment has an upper size of 64K, hence all addressing is done
 * using 16-bit absolute offsets, or 8-bit (signed) relative offsets.
 *
 * There is also a "data" segment, which is used to store common data
 * that will be required by the matching instructions.  All data in this
 * segment are indexed by an absolute 32-bit offset.
 *
 * Finally there is an amount of TRACK stack space words to reserve
 * for loop instructions.
 */
typedef struct re_mi_code {
	re_mi_seg_t text;		/* Text (= program) segment */
	re_mi_seg_t data;		/* Data segment */
	uint tsp_words;			/* Words reserved for our variables */
} re_mi_code_t;

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
	re_mi_code_t *bytecode;		/* Generated byte-code */
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
	int fcmap_char;				/* Single fcmap_char, -1 if none */
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

static bool re_match_class2_ds(int c)
	{ return  is_ascii_digit(c) || is_ascii_space(c); }

static bool re_match_class2_ws(int c)
	{ return  is_ascii_ident(c) || is_ascii_space(c); }

static bool re_match_class2_not_ds(int c)
	{ return  !(is_ascii_digit(c) || is_ascii_space(c)); }

static bool re_match_class2_not_ws(int c)
	{ return  !(is_ascii_ident(c) || is_ascii_space(c)); }

/**
 * Array of valid 2-hardwired classes combinations that do not get
 * simplified into something else during compilation.
 */
static re_class_check_t re_hardwired_2[] = {
	re_match_class2_ds,		/* bit 0:  RE_MI_HWCLASS2_DS */
	re_match_class2_ws,		/* bit 1:  RE_MI_HWCLASS2_WS */
	re_match_class2_not_ds,
	re_match_class2_not_ws,
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
	return (1 + BIT_FIELD_IDX(max) - BIT_FIELD_IDX(min)) * sizeof(bit_field_t);
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
	g_assert(c->bytes == blen);

	WFREE_NULL(c->b, blen);
	c->magic = 0;
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

	g_assert(blen == BIT_FIELD_IDX(RE_ALPHABET));
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

	bmin = BIT_FIELD_IDX(first);
	bmax = BIT_FIELD_IDX(last);

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
 * @return static string representing all characters in a byte-class.
 */
static const char *
re_bclass2str(int min, int max, const uint8 *b)
{
	str_t *s = str_private(G_STRFUNC, RE_ALPHABET / 2);
	int c;

	g_assert(min >= 0);
	g_assert(max >= min);

	str_reset(s);

	for (c = min; c <= max; c++, b++) {
		if (*b != '\0')
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

struct re_rarest_char {
	uint32 count;		/* Number of occurrences */
	uint32 offset;		/* Offset of first position seen */
};

static int
re_rarest_char_cmp(const void *c1, const void *c2)
{
	const struct re_rarest_char *r1 = c1;
	const struct re_rarest_char *r2 = c2;

	if (r1->count == r2->count)
		return CMP(r1->offset, r2->offset);		/* Earliest char */

	return CMP(r1->count, r2->count);			/* Least frequent char first */
}

/**
 * Find offset in string of the rarest character.
 *
 * @return the first position of the rarest character.
 */
size_t
re_rarest_char_offset(const char *s)
{
	struct re_rarest_char map[RE_ALPHABET];
	int c;
	const char *p = s;


	if G_UNLIKELY('\0' == *s)
		return 0;		/* Empty string */

	for (c = 0; c < RE_ALPHABET; c++) {
		struct re_rarest_char *m = &map[c];
		m->count = MAX_INT_VAL(uint32);
		m->offset = MAX_INT_VAL(uint32);
	}

	while ((c = *p++)) {
		if (0 == ++(map[c].count))
			map[c].offset = ptr_diff(p, s) - 1;
	}

	vsort(map, N_ITEMS(map), sizeof(map[0]), re_rarest_char_cmp);

	return map[0].offset;
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
 * Is element an exact matching or routine trie?
 */
static bool
re_element_is_exact_trie(const re_element_t *e)
{
	re_element_check(e);

	switch (e->type) {
	case RE_TYPE_MATCHX:
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
 * Fill map with the all the characters held in the given C string.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param p		start of NUL-terminated string
 * @param icase	if TRUE, map characters case-insensitively
 */
static void
re_elem_map_string(uint8 *map, const char *p, bool icase)
{
	int c;

	while ('\0' != (c = *p++)) {
		if (icase) {
			map[ascii_tolower(c)] = 1;
			map[ascii_toupper(c)] = 1;
		} else {
			map[c] = 1;
		}
	}
}

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
 * Fill map with the all the characters held in the text.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		text element
 */
static void
re_elem_map_text(uint8 *map, const re_element_t *e)
{
	re_elem_map_string(map, re_element_get_text(e), e->icase);
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

struct re_elem_map_trie_string_ctx {
	uint8 *map;
	bool icase;
};

static void
re_elem_map_trie_string(void *data, void *udata)
{
	const char *key = data;
	struct re_elem_map_trie_string_ctx *ctx = udata;

	re_elem_map_string(ctx->map, key, ctx->icase);
}

/**
 * Fill map with the all characters held in the trie.
 *
 * @param map	a map of RE_ALPHABET elements
 * @param e		trie element
 */
static void
re_elem_map_trie(uint8 *map, const re_element_t *e)
{
	const trie_t *t = re_element_get_trie(e);
	struct re_elem_map_trie_string_ctx ctx;

	ctx.map   = map;
	ctx.icase = e->icase;

	trie_foreach(t, re_elem_map_trie_string, &ctx);
}

/**
 * Are two matching maps overlapping?
 */
static bool
re_elem_map_overlap(const uint8 *m1, const uint8 *m2)
{
	int c;

	for (c = 0; c < RE_ALPHABET; c++) {
		if (m1[c] && m2[c])
			return TRUE;
	}

	return FALSE;
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
 * Same as re_traverse_once() but the root is an element.
 */
static size_t
re_traverse_once_element(
	re_element_t *root,
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

	visited = re_traverse_element(root, &ctx);
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
 * A traversal of each element, recursively, starting from an element.
 *
 * Traversal is done in pre-order, i.e. the parent is processed before
 * its children.  If the callback returns FALSE, traversal stops.
 *
 * @param root		the root element
 * @param action	the callback to invoke on each element
 * @param data		user-supplied argument
 */
static size_t
re_foreach_element(re_element_t *e, match_fn_t action, void *data)
{
	re_element_check(e);

	return re_traverse_once_element(e,
		FALSE,				/* pre_e */
		action,				/* enter */
		NULL,				/* action */
		FALSE,				/* pre_v */
		NULL,				/* venter */
		NULL,				/* vaction */
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

/**
 * Alternative hashing of a re_class_t structure.
 */
static unsigned
re_class_hash2(const void *key)
{
	const re_class_t *c = key;

	if G_UNLIKELY(NULL == c)
		return 0;

	re_class_check(c);

	return binary_hash2(c->b, c->bytes) ^ integer_hash2(c->offset);
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
re_trie_check_partial(const trie_context_t *ctx, void *udata)
{
	size_t *partials = udata;

	if (trie_node_is_match(ctx->node) && !trie_node_is_leaf(ctx->node))
		(*partials)++;

	return TRUE;	/* Traverse further */
}

/**
 * Count amount of partial matches (matches before leaf nodes).
 */
static size_t
re_trie_count_partials(const trie_t *t)
{
	size_t partials = 0;

	trie_traverse(deconstify_pointer(t), TRIE_TRAVERSE_ALL,
		re_trie_check_partial, NULL, &partials);

	return partials;
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
	bool partial = 0 != re_trie_count_partials(t);
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
	bool partial = 0 != re_trie_count_partials(t);
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
		re_debug("%s(): single alternative -> GROUP", G_STRFUNC);
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

	/*
	 * Check whether fcmap[] holds one single char.
	 */

	re->fcmap_char = -1;

	if (re->fcmap != NULL) {
		uint8 *f;
		int c, n, x = -1;

		for (f = re->fcmap, n = c = 0; c < RE_ALPHABET; c++, f++) {
			if (*f) {
				if (++n > 1)
					break;
				x = c;
			}
		}

		if (1 == n) {
			g_assert(x >= 0);
			re->fcmap_char = x;
		}
	}
}

static void re_mi_generate(re_regex_t *re, bool debug);

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

	/*
	 * Generate byte-code.
	 */

	re_mi_generate(re, FALSE);
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
 * Parse octal character escape (\0DD).
 *
 * The leading '\0' sequence has already been read.
 *
 * @return the parsed character if OK, -1 on error with the parser error set.
 */
static int
re_parse_octal(re_parser_t *rp)
{
	int v = 0;
	size_t i;

	re_parser_check(rp);

	for (i = 0; i < 2; i++) {
		int c = istream_getc(rp->is);
		if G_UNLIKELY(-1 == c) {
			re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
			return -1;
		}
		if (c < '0' || c > '7') {
			re_parse_error(rp, -1, RE_E_INVALID_OCTAL_DIGIT);
			return -1;
		}
		v = (v << 3) + (c - '0');
	}

	return v;
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
	int v = 0;
	size_t i;

	re_parser_check(rp);

	for (i = 0; i < 2; i++) {
		int c = istream_getc(rp->is);
		int x;
		if G_UNLIKELY(-1 == c) {
			re_parse_error(rp, -1, RE_E_INCOMPLETE_ESCAPE);
			return -1;
		}
		x = hex2int(c);
		if (x < 0) {
			re_parse_error(rp, -1, RE_E_INVALID_HEXA_DIGIT);
			return -1;
		}
		v = (v << 4) + x;
	}

	return v;
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
				case '0':
					c = re_parse_octal(rp);
					if G_UNLIKELY(-1 == c)
						return FALSE;		/* Error set by re_parse_octal() */
					break;
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
			case '0':
				c = re_parse_octal(rp);
				if G_UNLIKELY(-1 == c)
					return FALSE;		/* Error set by re_parse_octal() */
				break;
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
			case '0':
				c = re_parse_octal(rp);
				if (-1 == c)
					return FALSE;
				re_parse_add_char(rp, c);
				break;
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
 * A dump function to a stream for a regular expression or a part
 * of a regular expression (like the generated byte code).
 *
 * In order to customize the output in some cases, we allow flags to
 * govern the kind of output we produce.
 */
typedef void (*re_dump_fn_t)(const re_regex_t *re, ostream_t *os, uint flags);

static char *
re_apply_as_string(const re_regex_t *re, re_dump_fn_t cb, uint flags)
{
	str_t *s = str_new(0);

	re_regex_check(re);

	if (!re->is_empty) {
		ostream_t *os;

		os = ostream_open_str(s);
		(*cb)(re, os, flags);
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
re_dump(const re_regex_t *re, ostream_t *os, uint flags)
{
	(void) flags;		/* Currently unused by dump */

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
	return re_apply_as_string(re, re_dump, 0);
}

/**
 * Format compiled First Char map as a character class to stream.
 *
 * This is intended to be used in automated testing, since it is critical
 * that the first character map be accurate or we will miss some matching
 * positions!
 */
static void
re_fcmap_dump(const re_regex_t *re, ostream_t *os, uint flags)
{
	(void) flags;		/* Current unused by First Char map dumps */

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
	return re_apply_as_string(re, re_fcmap_dump, 0);
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
re_show(const re_regex_t *re, ostream_t *os, uint flags)
{
	size_t n;

	ostream_printf(os, "Pattern : %s\n", re->pattern);
	if (flags & RE_SHOW_CASE)
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
		if (re->must != NULL)
			ostream_printf(os, "Needed  : %s\n",
				re_format_string(pattern_string(re->must)));

		if (flags & RE_SHOW_FCMAP) {
			if (re->fcmap != NULL) {
				ostream_puts(os, "FC Map  : [");
				re_dump_string(re_fcmap2str(re->fcmap), TRUE, os);
				ostream_printf(os, "]%s\n",
					re->fcmap_char >= 0 ? " single" : "");
			} else {
				ostream_puts(os, "FC Map  : none\n");
			}
		}

		ostream_printf(os, "Has END : %s\n", re->end != NULL ? "yes" : "no");

		if (flags & RE_SHOW_DUMP) {
			char *dump = re_dump_as_string(re);

			ostream_printf(os, "Compiled: %s\n", dump);
			HFREE_NULL(dump);
		}

		if (flags & RE_SHOW_TREE) {
			struct re_show_ctx ctx;

			ZERO(&ctx);
			ctx.os = os;
			ctx.vectors = htable_create(HASH_KEY_SELF, 0);

			ostream_puts(os,   "Tree    :\n");

			n = re_traverse_once(re->u.compiled,
					TRUE,					/* pre_e */
					NULL,					/* enter */
					re_show_element,		/* action */
					FALSE,					/* pre_v */
					re_show_enter_vector,	/* venter */
					re_show_leave_vector,	/* vaction */
					&ctx);

			ostream_printf(os, "Dumped %zu element%s in %zu vector%s\n",
				PLURAL(n), PLURAL(htable_count(ctx.vectors)));

			g_assert(NULL == ctx.vecs);
			htable_free_null(&ctx.vectors);
		}

		if (flags & RE_SHOW_BC) {
			char *dump =
				re_bytecode_as_string(re, booleanize(flags & RE_SHOW_DEBUG));

			ostream_puts(os,   "Bytecode:\n");
			ostream_puts(os, dump);
			HFREE_NULL(dump);

			ostream_printf(os,
				"Dumped TEXT: %zu byte%s, DATA: %zu byte%s -- %u stack word%s\n",
				PLURAL(re_mi_seg_used(&re->bytecode->text)),
				PLURAL(re_mi_seg_used(&re->bytecode->data)),
				PLURAL(re->bytecode->tsp_words)
			);
		}
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
	return re_apply_as_string(re, re_show, RE_SHOW_DFLT);
}

/**
 * Customized re_show_as_string(), showing only what is requested by flags.
 *
 * See RE_SHOW_ALL and all other RE_SHOW_* flags that can be used here.
 */
char *
re_show_as_string_ext(const re_regex_t *re, uint flags)
{
	return re_apply_as_string(re, re_show, flags);
}

/***
 *** ======================== Cleaning ========================
 ***/

static void re_mi_free_null(re_mi_code_t **code_ptr);

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
	re_mi_free_null(&re->bytecode);
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
 *** =================== C Matching Engine ====================
 ***/

#define RE_MATCH_COUNT_COMMON \
	const re_element_t *e;	/* The element being matched */					\
	size_t n;				/* Amount of times it was matched so far */		\
	const uchar *tp;		/* Text position BEFORE we attempted match */	\
	slink_t link;			/* Pointer up the calling chain */				\
	uint completed:1;		/* If TRUE, iterations were completed */		\
	uint extended:1;		/* If TRUE, element is extended */

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
	RE_MATCH_COUNT_COMMON
} re_match_count_t;

typedef struct re_match_count_ext {
	RE_MATCH_COUNT_COMMON
	jmp_buf env;			/* Jump back there to commit atomic match */
} re_match_count_ext_t;

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

/**
 * Runtime fatal execution errors.
 *
 * These are mostly used by the Matching Interpter, but the recursive
 * C engine also uses them for stack overflow.
 *
 * That is the reason why they are prefixed with RE_MI_ERR_.
 *
 * It's not important as these errors cannot be acted upon by the
 * users, they only see an error occurred during the matching process,
 * and can request a human translation of these error codes for logging.
 *
 * This is why there definitions are not public, only re_execute_strerror() is.
 */

#define RE_MI_ERR_OVFLOW	(-1)	/**< Stack overflow */
#define RE_MI_ERR_ILL		(-2)	/**< Illegal instruction */
#define RE_MI_ERR_TSEGV		(-3)	/**< TEXT-segment violation */
#define RE_MI_ERR_DSEGV		(-4)	/**< DATA-segment violation */
#define RE_MI_ERR_SSEGV		(-5)	/**< Stack segment violation */
#define RE_MI_ERR_STALE		(-6)	/**< RET leaving stale FAIL point */
#define RE_MI_ERR_MWORD		(-7)	/**< Invalid memory word number */
#define RE_MI_ERR_UDFLOW	(-8)	/**< Stack underflow */
#define RE_MI_ERR_RANGE		(-9)	/**< Argument out of range */
#define RE_MI_ERR_GROUP		(-10)	/**< Invalid group number */
#define RE_MI_ERR_ARANGE	(-11)	/**< Accumulator register out of range */
#define RE_MI_ERR_BACKTRACK	(-12)	/**< Backtracking threshold reached */

/**
 * Return textual desscripton of re_execute*() error codes.
 * It also includes TRUE and FALSE, in case they pass-in these valid
 * return codes to this routine.
 *
 * @param error		the error code returned by re_execute*() functions.
 *
 * @return pointer to a static string.
 */
const char *
re_execute_strerror(int error)
{
	switch (error) {
	case TRUE:         			return "Matching success";
	case FALSE:					return "No match";
	case RE_MI_ERR_ILL:			return "Illegal instruction";
	case RE_MI_ERR_TSEGV:		return "TEXT-segment violation";
	case RE_MI_ERR_DSEGV:		return "DATA-segment violation";
	case RE_MI_ERR_SSEGV:		return "Stack segment violation";
	case RE_MI_ERR_OVFLOW:		return "Stack overflow";
	case RE_MI_ERR_UDFLOW:		return "Stack underflow";
	case RE_MI_ERR_STALE:		return "RET leaving stale FAIL point";
	case RE_MI_ERR_MWORD:		return "Invalid memory word number";
	case RE_MI_ERR_RANGE:		return "Instruction argument out of range";
	case RE_MI_ERR_GROUP:		return "Invalid group number";
	case RE_MI_ERR_ARANGE:		return "Accumulator register out of range";
	case RE_MI_ERR_BACKTRACK:	return "Backtracking threshold reached";
	}

	return str_smsg("Unknown error: %d", error);
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
 * Finds LUT-converted index for capturing back-ref for group #n.
 *
 * This is the index of the place where, at runtime, we can store the
 * matched text for group #n, which is known to be used later as a
 * back-reference and, as such, always needs to be remembered, regardless
 * of how large the user-supplied matching vector is.
 *
 * @param rec	the execution context
 * @param n		the group number
 *
 * @return index in internal matching array + 1, 0 if none.
 */
static size_t
re_exec_match_backref_index(const re_regex_t *re, size_t n)
{
	size_t i;

	re_regex_check(re);
	g_assert(n <= re->group_count);

	if (0 == re->backref_count)
		return 0;		/* No group is ever used as a back-reference */

	if (RE_USE_BYTE_LUT(re->backref_count)) {
		g_assert(re->backrefs.byte_lut != NULL);
		i = re->backrefs.byte_lut[n - 1];
	} else {
		g_assert(re->backrefs.size_lut != NULL);
		i = re->backrefs.size_lut[n - 1];
	}

	g_assert(i <= re->backref_count);

	return i;
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

	re_exec_ctx_check(rec);

	i = re_exec_match_backref_index(rec->re, n);

	if (0 == i)
		return NULL;

	g_assert(rec->bvec != NULL);

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
 * @note
 * We pass the value of TP (normally held in the execution context) so that
 * the Matching Interpreter can use this routine for its CAPTURE instruction.
 *
 * @param rec	the execution context
 * @param tp	the current text pointer
 * @param n		the group number
 */
static void
re_exec_match_group_start(struct re_exec_ctx *rec, const uchar *tp, size_t n)
{
	re_exec_ctx_check(rec);
	g_assert(n != 0);

	REX_ENTRY;

	REX_DEBUG(RE_D_MATCHPOS,
		"group #%zu start=%zu ('%c')%s",
		n, tp - rec->text, *tp,
		n >= rec->mcnt ? " unrecordable" : "");

	if (rec->mvec != NULL && n < rec->mcnt)
		rec->mvec[n].re_start = tp - rec->text;

	if (rec->bvec != NULL) {
		re_match_t *m = re_exec_match_backref_find(rec, n);
		if (m != NULL)
			m->re_start = tp - rec->text;
	}

	REX_RETURN_VOID;
}

/**
 * Mark current position as match end for group #n, if there is enough
 * space in the matching vector for group #n.
 *
 * @note
 * We pass the value of TP (normally held in the execution context) so that
 * the Matching Interpreter can use this routine for its CAPTURE instruction.
 *
 * @param rec	the execution context
 * @param tp	the current text pointer
 * @param n		the group number
 */
static void
re_exec_match_group_end(struct re_exec_ctx *rec, const uchar *tp, size_t n)
{
	re_exec_ctx_check(rec);
	g_assert(n != 0);

	REX_ENTRY;

	REX_DEBUG(RE_D_MATCHPOS,
		"group #%zu end=%zu ('%c')%s",
		n, tp - rec->text, *tp,
		n >= rec->mcnt ? " unrecordable" : "");

	if (rec->mvec != NULL && n < rec->mcnt) {
		g_assert(rec->mvec[n].re_start != (ssize_t) -1);
		rec->mvec[n].re_end = tp - rec->text;
	}

	if (rec->bvec != NULL) {
		re_match_t *m = re_exec_match_backref_find(rec, n);
		if (m != NULL) {
			m->re_end = tp - rec->text;

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
re_exec_log_where_full(
	const struct re_exec_ctx *rec,
	const uchar *tp, const char *caller)
{
	char buf[80];
	size_t d = tp - rec->text;
	size_t matched;

	g_assert(size_is_non_negative(d));

	if (rec->tend != NULL) {
		size_t n = ptr_diff(rec->tend, tp);
		str_bprintf(ARYLEN(buf), "end in %zu byte%s", PLURAL(n));
	} else {
		str_bprintf(ARYLEN(buf), "end unknown");
	}

	/* No REX_ENTRY -- logging is done in the context of the caller */

	if (rec->icase && is_ascii_upper(*tp)) {
		REX_DEBUG(RE_D_WHERE,
			"%s(): at pos=%zu, c='%c' -> '%c' (%s)",
			caller, ptr_diff(tp, rec->text),
			*tp, ascii_tolower(*tp), buf);
	} else {
		REX_DEBUG(RE_D_WHERE,
			"%s(): at pos=%zu, c='%c' (%s)",
			caller, ptr_diff(tp, rec->text), *tp, buf);
	}

	REX_DEBUG(RE_D_WHERE, ">>%.10s<<", tp - MIN(3, d));

	if (0 == d)
		REX_DEBUG(RE_D_WHERE, "  ^");
	else
		REX_DEBUG(RE_D_WHERE, "  %.*s^", (int) MIN(3, d), "    ");

	matched = tp - rec->match_start;
	REX_DEBUG(RE_D_WHERE, "already matched: %.*s (%zu byte%s from pos=%zu)",
		(int) matched, rec->match_start, PLURAL(matched),
		rec->match_start - rec->text);
}
#define re_exec_log_where(x)      re_exec_log_where_full((x),(x)->tp,G_STRFUNC)
#define re_exec_log_where_tp(x,t) re_exec_log_where_full((x),(t),    G_STRFUNC)
#else	/* !PRIVLOG_ENABLED */
#define re_exec_log_where(x)
#define re_exec_log_where_tp(x,t)
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
static bool NO_INLINE G_UNUSED
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
		longjmp(rec->matched, RE_MI_ERR_OVFLOW);
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
 *
 * We pass-in the current text pointer so that this routine can also be
 * used by the Matching Interpreter, where the text pointer is only held in
 * a register and not updated in the `rec' structure.
 *
 * @param rec		the execution context
 * @param tp		the current text pointer
 * @param need		how many bytes we need ahead?
 */
static bool
re_exec_has_enough_ahead(struct re_exec_ctx *rec,
	register const uchar *tp, size_t need)
{
	size_t available, probe;
	void *p;

	REX_ENTRY;
	re_exec_log_where_tp(rec, tp);

	REX_DEBUG(RE_D_EXEC, "needs %zu byte%s of text", PLURAL(need));

	if (rec->tend != NULL) {
		available = rec->tend - tp;
		REX_DEBUG(RE_D_EXEC, "has %zu byte%s available",
			PLURAL(available));
		REX_RETURN(bool, "[end known] %d", available >= need);
	}

	/*
	 * We cache the last probed location (before end) to avoid
	 * scanning too many times if we backtrack.
	 */

	probe = need + 1;	/* Want to see trailing NUL after last char */

	if (rec->tprobed > tp) {
		available = rec->tprobed - tp;
		REX_DEBUG(RE_D_EXEC, "has %zu byte%s known to be available",
			PLURAL(available));
		if (available >= need)
			REX_RETURN(bool, "%d", TRUE);
		probe -= available;
	} else {
		rec->tprobed = tp;
	}

	REX_DEBUG(RE_D_EXEC, "probing %zu byte%s ahead", PLURAL(probe));

	p = vmemchr(rec->tprobed, '\0', probe);
	if (NULL == p) {
		rec->tprobed += probe;
	} else {
		rec->tprobed = rec->tend = p;
		REX_DEBUG(RE_D_EXEC, "end of text found");
	}

	REX_RETURN(bool, "%d", UNSIGNED(rec->tprobed - tp) >= need);
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

	REX_RETURN(bool, "%d", re_exec_has_enough_ahead(rec, rec->tp, need));
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
	size_t i, len, max;

	re_exec_ctx_check(rec);
	re_elemvec_check(ev);
	g_assert(n < ev->ecnt);

	g_assert(ev->elements[n].minimal);
	g_assert(ev->elements[n].repeat != RE_N_ONCE);

	REX_ENTRY;

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */

	len = re_exec_element_length(rec, &ev->elements[n]);
	max = re_element_get_repeat_max(&ev->elements[n]);

	REX_DEBUG(RE_D_REPEAT,
		"handling %s, len=%zu%s, with min=%zu already matched",
		re_elem_info(&ev->elements[n]), len,
		re_element_get_minlen(&ev->elements[n]) !=
			re_element_get_maxlen(&ev->elements[n]) ? " (unknown)" : "",
		NULL == count ? re_element_get_repeat_min(&ev->elements[n]): count->n);

	for (
		i = NULL == count ?
			re_element_get_repeat_min(&ev->elements[n]) : count->n;
		i < max;
		i++
	) {
		const uchar *tp = rec->tp;

		REX_DEBUG(RE_D_REPEAT, "attempting to match remaining, i=%zu", i);

		/*
		 * If we do not have at least one byte to consume, there is no
		 * need to continue.
		 */

		if (!re_exec_has_enough_ahead(rec, rec->tp, MAX(len, 1))) {
			REX_DEBUG(RE_D_REPEAT, "not enough text, declaring success");
			goto success;
		}

		if (re_exec_match_here(rec, ev, n + 1, TRUE)) {
			REX_DEBUG(RE_D_REPEAT, "minimal %s matched for i=%zu",
				re_elem_info(&ev->elements[n]), i);
			re_exec_success(rec);
		}

		rec->tp = tp;
		if (count != NULL) {
			count->n++;					/* Assume it matches */
			if (max == count->n)
				count->completed = TRUE;	/* No more repeats! */
		}

		REX_DEBUG(RE_D_REPEAT, "trying to match %s once more for i=%zu",
			re_elem_info(&ev->elements[n]), i);

		if (!(*matcher)(rec, &ev->elements[n])) {
			rec->tp = tp;
			if (count != NULL) {
				count->n--;		/* Did not match */
				count->completed = FALSE;
			}
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
			!re_exec_has_enough_ahead(ctx->rec, ctx->rec->tp, ctx->offset + 1)
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
		if (ctx->count != NULL) {
			ctx->count->n++;
			if (1 == n)
				ctx->count->completed = TRUE;
		}

		REX_DEBUG(RE_D_REPEAT, "another match, %zu more to try", n - 1);

		if (re_exec_match_maximal_deep(ctx, n - 1))
			REX_RETURN(bool, "[propagating success] %d", TRUE);

		if (ctx->count != NULL) {
			ctx->count->n--;
			ctx->count->completed = FALSE;
		}

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
	bool ok;

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

	ok = re_exec_match_maximal_deep(&ctx, amount);

	REX_RETURN(bool, "[exiting deep recursion] %d", ok);
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
	size_t i, min, max, len, offset = 0;
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
	 * Disabling because this causes wrong matching for:
	 *
	 * 	echo "abaaaaaabaa" | ./re-test -LBSC -cog "(a.*){2}b"
	 *
	 * The generated byte-code correctly finds the right match, but
	 * the C matcher will not due to this upper constraining.
	 * 		--RAM, 2020-08-24
	 */
#if 0
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
#endif

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

		if (!re_exec_has_enough_ahead(rec, rec->tp, len)) {
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
			if (max == count->n)
				count->completed = TRUE;
		}

		if (!(*matcher)(rec, e)) {
			if (count != NULL) {
				count->tp = old_count_tp;
				count->n--;			/* Did not match, finally */
				count->completed = FALSE;
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

	REX_DEBUG(RE_D_REPEAT, "%s(): attempting to match remaining", G_STRFUNC);

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
 * Capture matching end of a SUBN capturing group.
 */
static void
re_exec_match_subn_handle(struct re_exec_ctx *rec, const re_element_t *e)
{
	uint n;

	/* Don't bother if they supplied RE_X_NOSUB and no back-refs */
	if G_UNLIKELY(0 != (rec->eflags & RE_X_NOSUB) && NULL == rec->bvec)
		return;

	n = re_element_get_sub_number(e);	/* Capturing group number */
	re_exec_match_group_end(rec, rec->tp, n);
}

/**
 * When hitting a NEXT, was the enclosing element a SUBN, in which case
 * we need to track the matching for that group.
 */
static void NO_INLINE
re_exec_match_subn_next(
	struct re_exec_ctx *rec, const re_elemvec_t *ev, size_t n)
{
	const re_element_t *be;	/* Element before next */

	g_assert(n >= 1);		/* Ensures we have a previous */

	be = &ev->elements[n - 1];

	if (RE_TYPE_SUBN == be->type)
		re_exec_match_subn_handle(rec, be);
}

#define RE_EXEC_MATCH_LATEST_DONE	((re_match_count_t *) 0x1)

/**
 * Look for similar entry in rec->multi for the element described in `count'.
 *
 * @return
 * 	- NULL if we will have to prepend a new entry
 * 	- the special value RE_EXEC_MATCH_LATEST_DONE if the current entry is the
 * 	  head of rec->multi and is done with its maximum amount of repetitions
 * 	- the pointer to the latest entry for that element otherwise.
 */
static re_match_count_t *
re_exec_match_find_latest(struct re_exec_ctx *rec, re_match_count_t *count)
{
	const re_match_count_t *latest;

	REX_ENTRY;

	REX_DEBUG(RE_D_REPEAT,
		"current count of rec->multi: %zu", eslist_count(&rec->multi));

	latest = eslist_find(&rec->multi, count, re_exec_same_element);

	if (latest != NULL) {
		REX_DEBUG(RE_D_REPEAT,
			"found %s %s entry for %s (%p) with n=%zu (min is %zu, max is %s)",
			latest == eslist_head(&rec->multi) ? "head" : "inner",
			latest->completed ? "completed" : "incomplete",
			re_elem_info(count->e), count->e, latest->n,
			re_element_get_repeat_min(count->e),
			re_max2str(re_element_get_repeat_max(count->e)));

		/*
		 * If the entry we found in the &rec->multi list is not the head
		 * of that list and it is flagged as completed, then we're recursing
		 * from an outer group and we need to restart matching from the
		 * beginning...
		 */

		if (eslist_head(&rec->multi) == latest) {
			if (latest->n >= re_element_get_repeat_max(count->e))
				REX_RETURN(void *, "%p", RE_EXEC_MATCH_LATEST_DONE);
		} else {
			if (latest->completed) {
				REX_DEBUG(RE_D_REPEAT,
					"completed entry, will prepend new record");
				/* Force prepending of new entry */
				REX_RETURN(void *, "%p", NULL);
			}
		}

		count->n  = latest->n;
		count->tp = latest->tp;
	}

	REX_RETURN(void *, "%p", deconstify_pointer(latest));
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
re_exec_match_track(struct re_exec_ctx *rec,
	const re_elemvec_t *ev, size_t n,
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

	u.latest = re_exec_match_find_latest(rec, &count);

	if (RE_EXEC_MATCH_LATEST_DONE == u.latest)
		REX_RETURN(int, "[max count already matched] %+d", +1);

	if (u.latest != NULL && u.latest->extended) {
		REX_DEBUG(RE_D_REPEAT, "dealing with existing atomic record");
		count.extended = TRUE;
		/* Do nothing, see re_exec_match_track_atomic() */
	} else if (
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

	if (u.r <= 0 && !count.extended) {
		REX_DEBUG(RE_D_REPEAT,
			"removing %s record for %s (%p) with n=%zu (min is %zu)",
			count.completed ? "completed" : "incomplete",
			re_elem_info(count.e), count.e, count.n,
			re_element_get_repeat_min(count.e));
		eslist_remove(&rec->multi, &count);
		count.e = NULL;		/* Our signal that it was removed */
	} else {
		REX_DEBUG(RE_D_REPEAT,
			"leaving %s %s record for %s %s (%p) with n=%zu (min is %zu)",
			count.completed ? "completed" : "incomplete",
			count.extended ? "extended" : "regular",
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
		"%s %s %s record for %s %s (%p) with n=%zu (min is %zu), ok=%d",
		count.extended ? "leaving" : "removing",
		count.completed ? "completed" : "incomplete",
		count.extended ? "extended" : "regular",
		count.e->minimal ? "lazy" : "greedy",
		re_elem_info(&ev->elements[n]), &ev->elements[n], count.n,
		re_element_get_repeat_min(&ev->elements[n]), u.ok);

	/*
	 * We cannot remove an extended record because it is not in our
	 * stack frame: it belongs to re_exec_match_track_atomic() and
	 * will be handled there!
	 */

	if (!count.extended)
		eslist_remove(&rec->multi, &count);

	/*
	 * If the element matched and was a capturing group at the end
	 * of the regular expression, handle the end of its capture.
	 *
	 * We do this when there is no NEXT element after this group, because
	 * we are at the end of the regular expression tree in the first
	 * element vector.
	 */

	if (u.ok && n + 1 == ev->ecnt && RE_TYPE_SUBN == ev->elements[n].type)
		re_exec_match_subn_handle(rec, &ev->elements[n]);

	REX_RETURN(int, "%+d", u.ok);
}

/**
 * Generic wrapper for matching an atomic element possibly multiple times
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
re_exec_match_track_atomic(struct re_exec_ctx *rec,
	const re_elemvec_t *ev, size_t n,
	re_exec_match_fn_t matcher)
{
	re_match_count_ext_t count;
	re_match_count_t *latest;
	int ret;
	PRIVLOG_DECLARE_LEVEL(indent);

	REX_ENTRY;
	PRIVLOG_SAVE_LEVEL(indent);

	re_exec_check_stack(rec);	/* Highly recursive, monitor permanently */

	REX_DEBUG(RE_D_REPEAT, "handling atomic %s",
		re_elem_info(&ev->elements[n]));

	ZERO(&count);
	count.e  = &ev->elements[n];
	count.tp = rec->tp;
	count.extended = TRUE;

	g_assert(count.e->atomic);

	latest = re_exec_match_find_latest(rec, (re_match_count_t *) &count);

	if (RE_EXEC_MATCH_LATEST_DONE == latest)
		REX_RETURN(int, "[max count already matched] %+d", +1);

	REX_DEBUG(RE_D_REPEAT,
		"prepending new record for %s %s (%p) with n=%zu (min is %zu)",
		count.e->minimal ? "lazy???" : "greedy (atomic)",
		re_elem_info(count.e), count.e, count.n,
		re_element_get_repeat_min(count.e));

	/*
	 * The item we are prepending is flagged as being extended.
	 *
	 * That will be a signal for re_exec_match_track() to not further
	 * prepend any record to the list.
	 */

	eslist_prepend(&rec->multi, &count);

	/*
	 * We need to track longjmp() success reports so that, on success, we
	 * get back here,  or we can propagate stack overflow conditions that
	 * would arise later in the call chain
	 */

repeat:
	if ((ret = Setjmp(count.env))) {
		PRIVLOG_RESTORE_LEVEL(indent);
		REX_DEBUG(RE_D_EXEC, "%s(): back through longjmp(), ret=%d",
			G_STRFUNC, ret);
		if (ret < 0) {
			REX_DEBUG(RE_D_EXEC, "propagating error %d (%s)",
				ret, re_execute_strerror(ret));
			longjmp(rec->matched, ret);
		}
		goto back;
	}

	ret = re_exec_match_track(rec, ev, n, matcher);

	/* FALL THROUGH */

back:
	REX_DEBUG(RE_D_EXEC, "%s(): dealing with %s %s, match count is %zu",
		G_STRFUNC, count.completed ? "complete" : "incomplete",
		re_elem_info(count.e), count.n);

	if (ret) {
		if (count.n < re_element_get_repeat_min(count.e))
			goto repeat;	/* Atomic matching is greedy */

		/*
		 * We succeeded as soon as we matched the minimal amount we had to
		 * match.
		 *
		 * But since we are greedy, try to match as much as possibly now.
		 * There will be no backtracking done since we are atomic, but we
		 * will no longer need to longjmp(), hence we must flag the record
		 * as no longer being extended.
		 */

		count.extended = FALSE;		/* Will no longer longjmp() */

		(void) re_exec_match_maximal(rec,
					ev, n, matcher, (re_match_count_t *) &count);
	}

	eslist_remove(&rec->multi, &count);
	REX_RETURN(int, "%+d", ret);
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
		int r;

		/*
		 * We have a special path for atomic elements, so that, when we
		 * reach their NEXT and attempt to repeat, we will commit the
		 * text already matched through a longjmp(), so that no backtracking
		 * occurs on that text.
		 */

		if (ev->elements[n].atomic)
			r = re_exec_match_track_atomic(rec, ev, n, matcher);
		else
			r = re_exec_match_track(rec, ev, n, matcher);

		if (-1 == r)
			goto fetch_count;	/* Save stack space during recursions */

		REX_RETURN(bool, "%d", r != 0);
	}

	/*
	 * Handling a non-recursive element.
	 *
	 * First match the minimum we have to, before attempting
	 * to match the remaining variable parts.
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

		if (count != NULL && count->tp == rec->tp) {
			count->completed = TRUE;
			REX_RETURN(bool, "[matching the empty string] %d", TRUE);
		}

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

		if (count != NULL)
			count->completed = FALSE;

		REX_RETURN(bool, "%d", FALSE);

	success:
		if (count != NULL) {
			REX_DEBUG(RE_D_REPEAT,
				"%s(): %s has count=%zu, tp=%p (%zd from current)",
				G_STRFUNC, re_elem_info(&ev->elements[n]),
				count->n, count->tp, count->tp - rec->tp);

			if (re_element_get_repeat_max(&ev->elements[n]) == count->n)
				count->completed = TRUE;
		}

		REX_RETURN(bool, "%d", TRUE);
	}

	g_assert_not_reached();

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
		!re_exec_has_enough_ahead(rec, rec->tp, re_element_get_minlen(e))
	) {
		REX_DEBUG(RE_D_EXEC, "not enough text left to match");
		REX_RETURN(bool, "[not enough text] %d", FALSE);
	}

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
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
			REX_DEBUG(RE_D_EXEC, "propagating error %d (%s)",
				ret, re_execute_strerror(ret));
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
	const re_match_t *m;

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
		/* FALL THROUGH */
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
static int (*re_convert[2])(int) = { re_asis, ascii_tolower };

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

	convert = re_convert[re_element_is_icase_trie(e)];

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

	if G_UNLIKELY('\0' == c)
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

	if G_UNLIKELY('\0' == c)
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
	const re_match_count_t *entry;

	REX_ENTRY;

	/*
	 * If we have an element already registered in rec->multi, then this
	 * is a recursion into a group we already started matching, hence the
	 * initial starting point must not be changed.
	 */

	ZERO(&rec->tkey);
	rec->tkey.e = e;

	entry = eslist_find(&rec->multi, &rec->tkey, re_exec_same_element);

	REX_DEBUG(RE_D_MATCHPOS, "%s%s entry for %s (%p)",
		NULL == entry ? "no" : "found",
		entry != NULL && entry->completed ? " completed" : "",
		re_elem_info(e), e);

	/*
	 * We capture matching text for the group based on the first position
	 * where we enter the group: we can only enter a group when there
	 * is no entry for the element in the rec->multi list, or when that
	 * entry has already been completed.
	 *
	 * When they gave RE_X_NOSUB in the execution flags, we do not need
	 * to capture group matching.  We always keep track of matching for
	 * the groups that may later be perused in the pattern as a back-reference.
	 */

	if (NULL == entry || entry->completed) {
		if (0 == (rec->eflags & RE_X_NOSUB) || rec->bvec != NULL)
			re_exec_match_group_start(rec, rec->tp, n);
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
 *
 * This routine exists to be callable both from the C matching code
 * (the re_exec_match_*() routines) and the MI matching code interpreting
 * byte code.
 *
 * Hence it is passed the values it has to process directly.
 *
 * @param tp		current text pointer
 * @param tstart	start of text
 * @param eflags	execution flags, for checking RE_X_MULTI_LINE
 */
static inline bool ALWAYS_INLINE
re_exec_at_start(
	register const uchar *tp, const uchar *tstart, uint eflags)
{
	/* No REX_ENTRY here, done by our caller */

	if G_UNLIKELY(tp == tstart) {
		REX_DEBUG(RE_D_EXEC | RE_D_MI, "at text start");
		return TRUE;
	}

	/*
	 * When running with RE_X_MULTI_LINE, \n is always considered to be
	 * the beginning of text.
	 */

	if G_UNLIKELY(eflags & RE_X_MULTI_LINE) {
		if ('\n' == tp[-1]) {
			REX_DEBUG(RE_D_EXEC | RE_D_MI, "after \\n with RE_X_MULTI_LINE");
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Match start-of-text (^) at the current position.
 */
static bool
re_exec_match_start(const struct re_exec_ctx *rec)
{
	REX_ENTRY;

	re_exec_log_where(rec);

	REX_RETURN(bool, "%d", re_exec_at_start(rec->tp, rec->text, rec->eflags));
}

/**
 * Match end-of-text ($) at the current position.
 *
 * This routine exists to be callable both from the C matching code
 * (the re_exec_match_*() routines) and the MI matching code interpreting
 * byte code.
 *
 * Hence it is passed the values it has to process directly.
 *
 * @param tp		current text pointer
 * @param eflags	execution flags, for checking RE_X_MULTI_LINE
 */
static inline bool ALWAYS_INLINE
re_exec_at_end(register const uchar *tp, uint eflags)
{
	int c = *tp;

	/* No REX_ENTRY here, done by our caller */

	if G_UNLIKELY('\0' == c) {
		REX_DEBUG(RE_D_EXEC | RE_D_MI, "at text end");
		return TRUE;
	}

	/*
	 * When running with RE_X_MULTI_LINE, \n is always considered to be
	 * the end of text.
	 */

	if G_UNLIKELY(eflags & RE_X_MULTI_LINE) {
		if ('\n' == c) {
			REX_DEBUG(RE_D_EXEC | RE_D_MI, "at \\n with RE_X_MULTI_LINE");
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * Match end-of-text ($) at the current position.
 */
static bool
re_exec_match_end(const struct re_exec_ctx *rec)
{
	REX_ENTRY;

	re_exec_log_where(rec);

	REX_RETURN(bool, "%d", re_exec_at_end(rec->tp, rec->eflags));
}

/**
 * Match a word boundary (\b) at the current position.
 *
 * This routine exists to be callable both from the C matching code
 * (the re_exec_match_*() routines) and the MI matching code interpreting
 * byte code.
 *
 * Hence it is passed the values it has to process directly.
 *
 * @param tp		current text pointer
 * @param tstart	start of text
 * @param eflags	execution flags, for checking RE_X_MULTI_LINE
 */
static inline bool ALWAYS_INLINE
re_exec_at_word_boundary(
	register const uchar *tp, const uchar *tstart, uint eflags)
{
	int c = *tp;

	/* No REX_ENTRY here, done by our caller */

	/*
	 * Regardless of the current character, we are at a word boundary
	 * at the beginning or at the end of text.
	 */

	if G_UNLIKELY(tp == tstart) {
		REX_DEBUG(RE_D_EXEC | RE_D_MI, "at text start, hence boundary");
		return TRUE;		/* At start of text */
	}

	if G_UNLIKELY('\0' == c) {
		REX_DEBUG(RE_D_EXEC | RE_D_MI, "at text end, hence boundary");
		return TRUE;		/* At start of text */
	}

	/*
	 * When running with RE_X_MULTI_LINE, a \n is always considered to be
	 * the beginning or end of text, hence we are at a word boundary.
	 */

	if G_UNLIKELY('\n' == c) {
		if (eflags & RE_X_MULTI_LINE) {
			REX_DEBUG(RE_D_EXEC | RE_D_MI,
				"at \\n with RE_X_MULTI_LINE, hence boundary");
			return TRUE;
		}
	}

	if (is_ascii_ident(c))
		return !is_ascii_ident(tp[-1]);

	return is_ascii_ident(tp[-1]);
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
	REX_ENTRY;

	re_exec_log_where(rec);

	REX_RETURN(bool, "%d",
		re_exec_at_word_boundary(rec->tp, rec->text, rec->eflags));
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
			"%s(): found %s %s entry for %s (%p) n=%zu (min=%zu)",
			G_STRFUNC,
			latest->completed ? "completed" : "incomplete",
			latest->extended ? "extended" : "regular",
			re_elem_info(be), be,
			latest->n, re_element_get_repeat_min(be));

		/*
		 * If we have an extended entry, then it means we are dealing
		 * with an atomic group repetition.  Report matching success
		 * via longjmp() so that we do not backtrack on what we matched
		 * so far.
		 */

		if (latest->extended) {
			re_match_count_ext_t *extended = (re_match_count_ext_t *) latest;
			REX_DEBUG(RE_D_EXEC,
				"%s(): ATOMIC MATCH committed via longjmp()", G_STRFUNC);
			longjmp(extended->env, TRUE);
		}

		return !latest->completed;
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
		!re_exec_has_enough_ahead(rec, rec->tp, ev->minlen)
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

			re_exec_match_subn_next(rec, ev, n);

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
	register const uchar *tp;
	const re_regex_t *re = rec->re;
	const uint8 *fcmap = re->fcmap;

	REX_ENTRY;
	re_exec_log_where(rec);

	if (NULL == fcmap)
		goto current;

	if (re->fcmap_char >= 0) {
		tp = (const uchar *) vstrchr((const char *) rec->tp, re->fcmap_char);
		if (tp != NULL) {
			tp++;
			goto matched;
		}
	} else {
		register int c;
		tp = rec->tp;
		do {
			c = *tp++;
			if (fcmap[c])
				goto matched;
		} while (c != '\0');
	}

	/* FALL THROUGH */

	REX_RETURN(const uchar *, "[no other suitable point] %p", NULL);

current:
	REX_RETURN(const uchar *, "[default: current position] %p", rec->tp);

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
	 * If we have a non-zero minimum length of text to match, make sure
	 * we have it before starting the engine!
	 */

	if (ev->minlen != 0 && !re_exec_has_enough_ahead(rec, rec->tp, ev->minlen))
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
 * Execute the match without the engine.
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int
re_exec_match_directly(struct re_exec_ctx *rec)
{
	const re_regex_t *re = rec->re;

	REX_ENTRY;

	re_exec_ctx_check(rec);
	re_regex_check(re);

	/*
	 * An empty regular expression (NULL compiled pointer)
	 * is always matching at the start of the text.
	 */

	if G_UNLIKELY(re->is_empty) {
		if (rec->mvec != NULL) {
			rec->mvec[0].re_start = rec->mvec[0].re_end = 0;
		}
		REX_RETURN(int, "[empty regex] %+d", TRUE);
	}

	if (re->is_simple) {
		REX_DEBUG(RE_D_EXEC, "expression is simple (%s%s%s%s)",
			re->at_start || re->at_end ?
				"anchored string at" : "fixed pattern",
			re->at_start ? " start" : "",
			re->at_start && re->at_end ? " +" : "",
			re->at_end ? " end" : "");
		if (re->at_start || re->at_end) {
			REX_RETURN(int, "%+d", re_exec_match_anchored(rec));
		} else {
			REX_RETURN(int, "%+d", re_exec_match_fixed(rec));
		}
	}

	g_assert_not_reached();
}

/**
 * Determine whether we'll need a matching engine.
 */
static bool
re_exec_needs_engine(const re_regex_t *re)
{
	re_regex_check(re);

	return !(re->is_empty || re->is_simple);
}

/**
 * Main entry point for regular expression matching.
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int
re_exec_match(struct re_exec_ctx *rec)
{
	return re_exec_match_ev(rec, rec->re->u.compiled);
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
 *** ================== Bytecode Management ===================
 ***/

/**
 * CS field values for encoding of following immediate constants.
 *
 *   0b00 normal fixed standard constant, if any, follows.
 *   0b01 (signed) 8-bit operand instead of whatever else OP was expecting
 *   0b11 (signed) 16-bit operand instead of whatever else OP was expecting
 *   0b10 compact constant follows, read as signed 64-bit quantity.
 *
 * For 0b11 and 0b01, whether the constant is signed depends on whether the
 * OP expects a signed or an unsigned quantity.
 */
typedef enum {
	RE_OP_CS_EMPTY  = 0,	/* Normal fixed standard constant */
	RE_OP_CS_8BITS  = 1,	/* 8-bit constant */
	RE_OP_CS_16BITS = 3,	/* 16-bit constant */
	RE_OP_CS_CLE    = 2,	/* Compact Little-Endian 64-bit constant */
} re_op_cs_t;

/**
 * Hardwired character class for the HWCL instruction.
 * These are the allowed values of FLAGS when the CS bits are RE_OP_CS_EMPTY.
 *
 * This is the index of the matching routine in re_hardwired[].
 */
#define RE_MI_HWCLASS_D		0		/* \d */
#define RE_MI_HWCLASS_W		1		/* \w */
#define RE_MI_HWCLASS_S		2		/* \s */

/**
 * Hardwired combination of character classes for the HWCL2 instruction.
 *
 * This is the index of the matching routine in re_hardwired_2[].
 */
#define RE_MI_HWCLASS2_DS	0		/* [\d\s] */
#define RE_MI_HWCLASS2_WS	1		/* [\w\s] */

/**
 * Encoding of the item to push/pop for the FAIL_OP instruction.
 */
#define RE_MI_FAIL_OP_TRACK	0		/* A variable (word number) */
#define RE_MI_FAIL_OP_GROUP	1		/* A capturing group (group number) */
#define RE_MI_FAIL_OP_REF	2		/* A back-reference (internal LUT number) */

/**
 * Encoding of the leading byte for CLE (Compact Little-Endian) values.
 *
 * A Compacted Little Endian (CLE) constant is encoded thusly:
 *
 * Leading byte, followed by value:
 *
 *   +----------------+  +----------------+
 *   |U|N|00| LENGTH  |  |  Encoded value |
 *   +----------------+  +----------------+
 *   <- leading byte ->  <- LENGTH bytes ->
 *
 * LENGTH gives amount of following bytes containing little-endian value
 * with trailing zero bytes removed.
 *
 * The U bit is set to 1 if the value is unsigned.
 * The N bit is set to 1 if the value was negated before encoding.
 *
 * For instance, U=0 and N=1 enables encoding of -2 as "2".
 */
typedef union {
	uint8 value;
	struct {
		uint8 u:1;
		uint8 n:1;
		uint8 zero:2;
		uint8 length:4;
	} v;
} re_mi_cle_t;

/**
 * An instruction opcode, leading byte.
 *
 *   +---------+-+-+--+
 *   | OP code |X|Z|CS|   Common, when "OP code" is >= 2
 *   +---------+-+-+--+
 *   +-+-+-+-+--------+
 *   |0:0:0:0|  M Op  |   Minimal code
 *   +-+-+-+-+--------+
 *   +-+-+-+-+-+------+
 *   |0:0:0:1|S| I Op |   Indexed code
 *   +-+-+-+-+-+------+
 */
typedef union {
	uint8 code;
	union {
		/* Common architecture */
		struct {
			uint8 op:4;
			uint8 x:1;
			uint8 z:1;
			uint8 cs:2;
		} v;
		/* Minimal architecture */
		struct {
			uint8 zero:4;
			uint8 op:4;
		} m;
		/* Indexed architecture */
		struct {
			uint8 one:4;
			uint8 s:1;
			uint8 op:3;
		} i;
	} u;
} re_mi_opcode_t;

/**
 * Follow-up instruction opcode, after ESCAPE.
 *
 *   +----------+-+-+-+
 *   | OP cont. |F.L.G|
 *   +----------+-+-+-+
 */
typedef union {
	uint8 code;
	struct {
		uint8 op:5;
		uint8 flg:3;
	} v;
} re_mi_opfollow_t;

/**
 * Instructions.
 *
 * The instruction itself (not its possible arguments) is coded on two bytes
 * at most.
 *
 * The first byte has the following architecture:
 *
 *   +---------+-+-+-+-+
 *   | OP code |X|Z|C.S|
 *   +---------+-+-+-+-+
 *
 * The trailing 4 bits are flags:
 * - X: modifies the meaning of the instruction, see OP codes below.
 * - Z: only executes when the Z flag is TRUE (otherwise, is a NOP)
 * - C.S: constant scheme (encoding method and possible implied length)
 *
 * If the OP code is greater than 15 (maximum that can fit in 4 bits), then
 * the encoding of the instruction will need an extra byte, the first byte
 * encoding the pseudo-instruction ESCAPE.
 *
 *   +----------+-+-+-+
 *   | OP cont. |F.L.G|
 *   +----------+-+-+-+
 *
 * However, the X, Z and CS flags all apply to the 2-byte instruction, and
 * we have 3 more bits (FLG) that can be used for additional tailoring of
 * the instruction.  Their interpretation will be instruction-dependant.
 */
typedef enum {
	/**
	 ** Short instruction codes, on 1 byte (+ possible following operands)
	 **/

		/*
		 * ZERO -- special, encodes a minimal operation
		 *
		 * To optimize short opcodes for simple operations that can occur
		 * many times, we abuse the ZERO instruction (OP code = 0) to pack
		 * other useful 1-byte instructions by using its trailing bytes
		 * to code up to 16 1-byte simple instructions.
		 */
	RE_OP_ZERO = 0,		/* RE_OP_ZERO must be 0 (instruction architecture) */

		/**
		 * INDEX -- special, compact encoding for operations with
		 * an immediate value that can be encoded on 1 or 2 bytes.
		 *
		 * This is used for operations involving memory words (variables)
		 * identified by their address (i.e. their index).
		 */
	RE_OP_INDEX = 1,	/* RE_OP_INDEX must be 1 (instruction architecture) */

		/*
		 * JMP dest -- conditionally jump to destination.
		 *
		 * The rules for JMP apply to all the JMP-like operations.
		 *
		 * If CS = 0b00, this is an absolute jump, 16-bit destination PC follows.
		 * If CS = 0b11, this is a relative jump, signed 16-bit offset follows.
		 * If CS = 0b01, this is a relative jump, signed 8-bit offset follows.
		 *
		 * The X and Z bits encode the different conditions:
		 *
		 * 	  XZ  condition   mnemo
		 *    00  Z is clear  NZ
		 *    01  Z is set    Z
		 *    10  C is clear  NC
		 *    11  C is set    C
		 *
		 * When the condition is not met, the JMP is not taken.
		 */
	RE_OP_JMP = 2,

		/*
		 * FAIL_JMP dest -- leaves a FAIL record (on the fail stack) and then
		 * acts as a JMP to destination.
		 *
		 * When the FAIL record is handled, it will return back after the
		 * FAIL_JMP instruction and restore the TP and TSP registers to the
		 * value they had when FAIL_JMP was executed.
		 *
		 * Expects a JMP offset, just like the JMP instruction.
		 * Same usage of the CS bits as in the JMP instruction.
		 */
	RE_OP_FAIL_JMP = 3,

		/*
		 * HWCL -- matches a hardwired character class (e.g. \w).
		 *
		 * If the X bit is set, matching is inverted (\W)
		 *
		 * The CS bits supply the class to match:
		 *
		 * - CS = 0b00 -> \d
		 * - CS = 0b01 -> \w
		 * - CS = 0b10 -> \s
		 *
		 * These bits correspond to the index within re_hardwired[]
		 * for the matching callback.
		 */
	RE_OP_HWCL = 4,

		/*
		 * MATCH size bytes -- matches the given text (variable amount of bytes)
		 *
		 * If the X bit is set, the matching is case-insensitive and the
		 * characters must be given in lower-case.
		 *
		 * Expects a CS-encoded unsigned constant, a single byte when CS=0
		 * (at which time it just matches the single char this byte represents).
		 */
	RE_OP_MATCH = 5,

		/*
		 * CLASS data or MIN+MAX -- matches a character class ([a-x]).
		 *
		 * If the X bit is set, matching is inverted ([^a-x])
		 * If the Z bit is set, matching is done case-insensitively.
		 *
		 * If CS is 0b00, then the upcoming 16-byte operand is understood
		 * as MIN and MAX (first byte is MIN, second is MAX), indicating
		 * an inclusive matching range (negated when X is set).
		 *
		 * Otherwise, the argument is a CS-encoded address in the DATA
		 * segment containing the description of the class to be matched.
		 */
	RE_OP_CLASS = 6,

		/*
		 * UJMP dest -- unconditionally jump to destination
		 *
		 * This is an unconditional JMP, the Z and X bits are ignored.
		 *
		 * If CS = 0b00, this is an absolute jump, 16-bit destination PC follows.
		 * If CS = 0b11, this is a relative jump, signed 16-bit offset follows.
		 * If CS = 0b01, this is a relative jump, signed 8-bit offset follows.
		 */
	RE_OP_UJMP = 7,

		/*
		 * DJMP #n offset -- deccrement word #n and jump if condition
		 *
		 * If the X bit is set, the offset if on 16-bits, otherwise it is 8-bits
		 * If the Z bit is set, JMP occurs if the word is 0, otherwise if non-0.
		 *
		 * `n' is a CS-governed constant
		 * `dest' is a relative negative offset, coded on 8-bits usually,
		 * but using 16-bits if the X bit is set.
		 *
		 * This highly specialized instruction is used in repetition loops.
		 * The offset is interpreted as a relative signed quantity.
		 */
	RE_OP_DJMP = 8,

		/*
		 * REF num -- matches text matched by the given back-reference number.
		 *
		 * If the X bit is set, the matching is case-insensitive
		 *
		 * It expects a CS-governed unsigned number, the group `num' whose
		 * matching text we are referring to.
		 */
	RE_OP_REF = 9,

		/*
		 * LT_A c -- compares accumulator value A with immediate constant `c'
		 *
		 * If the Z bit is set this is turned into an equality test.
		 *
		 * If the X bit is set this is turned into a comparison test, which
		 * is more powerful because it will alter both C and Z flags: it
		 * computes the sign of A - c:
		 *
		 *    +1: Z=0, C=0
		 *     0: Z=1, C=0
		 *    -1: Z=0, C=1
		 *
		 * When the X bit is set, the Z bit of the instruction is ignored.
		 *
		 * Otherwise, this is a strict less-than comparison and only the
		 * Z flag is set.
		 *
		 * `c' is a CS-governed constant.
		 *
		 * The Z flag is set if A < c (or A == c if Z or X), cleared otherwise.
		 * The C flag is set if A < c (with X), cleared otherwise.
		 */
	RE_OP_LT_A = 10,

		/*
		 * CALL dest -- performs a subroutine call to dest
		 *
		 * Expects a JMP destination, just like the JMP instruction.
		 * Same usage of the CS bits as in the JMP instruction.
		 *
		 * Contrary to XCALL, this is a call at the machine interpreter
		 * level.
		 *
		 * The current PC is pushed on the TRACK stack, and control is
		 * transferred to the destination PC.
		 *
		 * The purpose of CALL is to factorize bytecode for non-backtracking
		 * trie matching (exact trie).
		 */
	RE_OP_CALL = 11,

		/*
		 * TRIE data -- match a trie node (like a character class) and set
		 * index (0-based) of matched character in the A register.
		 *
		 * If the Z bit is set, matching is done case-insensitively.
		 *
		 * If CS is 0b00, then the upcoming 16-byte operand is understood
		 * as MIN and MAX (first byte is MIN, second is MAX), indicating
		 * an inclusive matching range (negated when X is set).
		 *
		 * Like the CLASS opcode, the argument is a CS-encoded address
		 * in the DATA segment containing the description of the class to
		 * be matched.
		 *
		 * If the trie node is the class [abc] and we find `b' then since
		 * `b' is the second position, its 0-based index is 1.  If we read
		 * a character not in the class, it triggers failure.
		 */
	RE_OP_TRIE = 12,

		/*
		 * FAIL_OP n -- push/pop one value on/off the FAIL stack.
		 *
		 * If the X bit is set, this pops, otherwise it pushes.
		 * If the Z bit is set, the value `n' is encoded on 2 bytes, otherwise
		 * one single byte is used.
		 *
		 * The CS bits encode the nature of the item to push/pop:
		 *
		 * CS=00b for a track word (a variable / counter)
		 * CS=01b for a capture group number
		 * CS=10b for a back-reference number
		 *
		 * This instruction is used when there is one item to push/pop onto
		 * or from the FAIL stack.  If more than one item is used, then
		 * dedicated opcodes like F_PUSH_TRACK, F_PUSH_GROUP or F_PUSH_REF
		 * are used.  But they take up more bytes and are therefore longer
		 * to process, whereas here we optimize for space and speed, for
		 * the very common case of just one single value being pushed or popped.
		 */
	RE_OP_FAIL_OP = 13,

		/*
		 * XJMP n -- uses value from A (0 to n - 1) to index a jump table
		 *
		 * `n' is CS-encoded.
		 *
		 * If the Z bit is set, then value 0 is not part of the jump table:
		 * when A is 0, control is transferred to the instruction following
		 * the table, hence the first relative address given is for A = 1.
		 *
		 * This is a jump table to quickly route code to a given address
		 * depending on the value of A.
		 *
		 * If (unsigned) A is greater or equal than `n', an error is raised.
		 *
		 * All addresses are 16-bit long and relative from the place
		 * after `n' has been read.
		 */
	RE_OP_XJMP = 14,

		/*
		 * ESCAPE is not really an instruction, rather an escape sequence
		 * used to indicate that an additional byte follows to supply the
		 * real operation code.
		 *
		 * The continuation OP code is given by the five upper bits of the
		 * following byte.
		 *
		 * The lower 3 bits FLG are reserved for additional specification
		 * by the instruction.  If not used, they are set to 0.
		 *
		 *   +----------+-+-+-+
		 *   | OP cont. |F:L:G|
		 *   +----------+-+-+-+
		 *
		 * The final OP code of the instruction will be 16 + the value
		 * held in the "OP continuation" leading five bits.
		 *
		 * Note that the X, Z and CS flags given in the ESCAPE byte will
		 * apply to the extended instruction!
		 */
	RE_OP_ESCAPE = 15,

	/**
	 ** Long instruction codes, following a leading RE_OP_ESCAPE code
	 **/

		/*
		 * NEED n -- ensures we have at least `n' bytes of text ahead
		 *
		 * If we don't have enough text, then FAIL.
		 *
		 * Expect a CS-encoded unsigned constant.
		 *
		 * When CS is EMPTY (0b00), the constant is immediate and encoded as
		 * the X, Z and FLG bits as n - 1 (since n cannot be 0).  This provides
		 * immediate constants up to 32 bytes.
		 *
		 * For larger values, the X, Z and FLG encode the lowest 5 bits
		 * and the remaining CS-encoded constant supply the higher bits.
		 */
	RE_OP_NEED = 16,

		/*
		 * DEBUG length text -- logs comment string plus some state
		 * information if we are running in debug mode.  Otherwise ignored.
		 *
		 * It expects a CS-governed unsigned length, by default 1 byte,
		 * followed by the text to be logged as-is.
		 */
	RE_OP_DEBUG = 17,

		/*
		 * LOAD #n, count -- sets memory word `n' to `count'
		 *
		 * Both `n' and `count' are CS-governed constants.
		 * `n' uses the CS bits.
		 * `count' uses the low-order FLG bits for CS-encoding.
		 */
	RE_OP_LOAD = 18,

		/*
		 * XCALL dest -- performs a recursive match call (re-entrant call to
		 * the interpreter)
		 *
		 * The C call is made without re-initializing the stacks.
		 * We just mark the current FSP and TSP as being the "bottom".
		 *
		 * This is used for look-ahead (and look-behind) assertions, which
		 * follow their own little matching logic and which must not backtrack
		 * past the point where we attempt the matching.
		 *
		 * If the X bit is set, the final matching status is inverted.
		 *
		 * If the Z bit is clear, then failure of the XCALL triggers a FAIL.
		 * If the Z bit is set, the Z flag is set to TRUE on matching
		 * success, FALSE on failure.
		 *
		 * The Z bit can be used to implement "(?( pattern ) yes | no)" one day.
		 *
		 * Upon return after the XCALL instruction, we are in the same state
		 * as before (same TP, same fail and track stacks).
		 *
		 * Expects a JMP destination, just like the JMP instruction.
		 * Same usage of the CS bits as in the JMP instruction.
		 */
	RE_OP_XCALL = 19,

		/*
		 * HWCL2 -- matches a combination of hardwired character classes
		 *
		 * If the X bit is set, matching is inverted.
		 *
		 * We have only 2 valid combinations.
		 *
		 * - FLG=0b000 -> [\d\s]
		 * - FLG=0b001 -> [\w\s]
		 *
		 * All other combinations of two hardwired classes get simplified
		 * any way, either as a simple character class or as a simple hardwired
		 * class, or as ALL.  Some are invalid and get a compile-time error,
		 * like [^\W\w] which cannot match anything.
		 */
	RE_OP_HWCL2 = 20,

		/*
		 * F_PUSH_TRACK amount nums -- pushes the listed TRACK reserved
		 * word indices onto the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_PUSH_TRACK = 21,

		/*
		 * F_POP_TRACK amount nums -- pops the listed TRACK reserved
		 * word indices from the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_POP_TRACK = 22,

		/*
		 * F_PUSH_GROUP amount nums -- pushes the listed capturing group
		 * start/end of match on the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_PUSH_GROUP = 23,

		/*
		 * F_POP_GROUP amount nums -- pops the listed capturing group
		 * start/end of match from the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_POP_GROUP = 24,

		/*
		 * F_PUSH_REF amount nums -- pushes the listed internal references
		 * start/end of match on the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_PUSH_REF = 25,

		/*
		 * F_POP_REF amount nums -- pops the listed internal references
		 * start/end of match from the FAIL stack.
		 *
		 * All the numbers are listed in the same encoding (either all
		 * 1 byte or 2 bytes), as specified by the FLG value.
		 *
		 * The given amount is the amount of such entries that follow,
		 * as a CS-encoded constant.
		 */
	RE_OP_F_POP_REF = 26,

		/*
		 * F_DROP_WORD n -- drop `n' words from the FAIL stack
		 *
		 * Expect a CS-encoded unsigned constant with the same embedded
		 * encoding mechanism as NEED.
		 *
		 * The amount encoded is one less than the amount we need to drop
		 * (since dropping 0 words would not require any instruction).
		 */
	RE_OP_F_DROP_WORD = 27,

		/*
		 * SET_A n -- set (unsigned) value `n' into the A register
		 *
		 * Expect a CS-encoded unsigned constant.
		 *
		 * When CS is EMPTY (0b00), then the constant is immediate and
		 * encoded into the X, Z and FLG bits as n: we can thus encode,
		 * directly into the instruction, positive values from 0 to 31.
		 *
		 * For larger values, the X, Z and FLG encode the lowest 5 bits
		 * and the remaining CS-encoded constant supply the higher bits.
		 *
		 * This scheme allows to encode values from 0 to 31 in 2 bytes
		 * (the instruction itself) and only use 3 bytes for values up
		 * to (255 << 5) + 31 = 8191.
		 */
	RE_OP_SET_A = 28,

		/*
		 * XLOAD_A n -- updates A by reading value in following `n' entries.
		 *
		 * `n' is a CS-encoded unsigned constant.
		 *
		 * After the instruction, we expect `n' entries, and the current value
		 * of A is used to index this array and load A with the value at that
		 * index.  If A is out of range, it raises an exception.
		 *
		 * Each of the `n' entries is CS-encoded by the value of the FLG bits,
		 * either as 8-bit or 16-bit values.
		 *
		 * This is used to avoid an XJMP instruction dispatching code to various
		 * places that will all say "LD A, x" with a different x before jumping
		 * to a specific place or returning from a CALL.  It is more efficient
		 * in terms of speed of execution and bytecode space.
		 */
	RE_OP_XLOAD_A = 29,

		/*
		 * CAPTURE n -- marks current position as the start of capturing group n.
		 *
		 * If the X bit is set, then we're capturing the matching end.
		 * If the Z bit is set, then we're capturing for a REF.
		 *
		 * Expects a CS-governed unsigned quantity for `n', with the lowest
		 * 3 bits already encoded in FLG.
		 */
	RE_OP_CAPTURE = 30,

		/*
		 * REPEAT [n] -- repeats next matching instruction
		 *
		 * If the X bit is set, also implies CEX (conditional execution),
		 * meaning that it sets the C bit in the flags and matching failure
		 * will simply stop with the C bit cleared.
		 *
		 * Expects a CS-governed unsigned quantity for `n', with the lowest
		 * 3 bits already encoded in FLG.
		 *
		 * If n = 0, it stands for infinite repetitions.
		 *
		 * This highly specialized instruction allows for optimal repetitions
		 * of matching instruction since looping happens right at the
		 * instruction level, hence we do not have to repay the instruction
		 * decoding phase each time we want a match (or attempt a match when
		 * the X bit is set).
		 */
	RE_OP_REPEAT = 31,

		/*
		 * SUB_TP n -- decrease TP by n
		 *
		 * Expect a CS-encoded unsigned constant with the same embedded
		 * encoding mechanism as SET_A.
		 */
	RE_OP_SUB_TP = 32,

		/*
		 * ADD #n, value -- adds `value' to memory word `n'
		 *
		 * Both `n' and `value' are CS-governed constants.
		 * `n' uses the CS bits.
		 * `value' uses the low-order FLG bits for CS-encoding.
		 */
	RE_OP_ADD = 33,

		/*
		 * UPDATE_FPC n, dest -- updates PC in the FAIL record pointed at by
		 * word `n' to be `dest' now
		 *
		 * Both `n' and `dest' are CS-governed constants.
		 * `n' uses the CS bits.
		 * `dest' uses the low-order FLG bits for CS-encoding.
		 *
		 * Using the content of word `n' as the base for the FAIL point,
		 * the registered PC in that FAIL point (the place to jump to when
		 * the FAIL point is popped) is updated to be `dest'.
		 *
		 * The `dest' value is encoded as a JMP destination: it can be
		 * absolute or relative (to this instruction).  Naturally it is
		 * resolved to an absolute address for updating the PC.
		 */
	RE_OP_UPDATE_FPC = 34,

		/*
		 * RG_A n, m -- compares accumulator A with range [n, m[
		 *
		 * `n' is a CS-governed constant.
		 * `m' is a CS-governed constant using the FLG bits.
		 *
		 * Both Z and C bits are altered during the comparison:
		 *
		 *    A <  n	Z=1, C=0
		 *    A >= m	Z=0, C=0
		 *    in range	Z=0, C=1
		 *
		 * The Z bit is set only when A < n.
		 * The C bit is set only when A is within specified range
		 */
	RE_OP_RG_A = 35,

		/*
		 * RET_A n -- load A with value `n' then return from subroutine
		 *
		 * Uses the same value encoding as SET_A, embedding the low 5 bits
		 * of `n' directly into the instruction.
		 */
	RE_OP_RET_A = 36,

		/*
		 * REW_TP n char [off]	-- rewind TP up to word 'n' under constraint.
		 *
		 * The constraint is that the character (byte) at TP+off be "char".
		 *
		 * The optional offset "off" is 0 by default.  Its presence and encoding
		 * is given by the CS bits: 00b indicates no additionnal offset,
		 * hence there is nothing if "off" is 0.
		 *
		 * If the Z bit is set, then 'n' is given as 2 bytes, otherwise 1 byte.
		 * If the X bit is set, then matching is done case-insensitively and
		 * character must be given in lowercase.
		 *
		 * This highly specialized complex instruction is meant to optimize
		 * the matching of "a.*b" for instance, once ".*" starts to backtrack.
		 * It can only be used to backtrack from a greedy operator matching a
		 * single byte at a time.
		 *
		 * This limits the amount of FAIL_JMP we issue duing backtracking.
		 *
		 * Sets the Z bit if we find a matching constraint before the limit.
		 */
	RE_OP_REW_TP = 37,

	RE_OP_MAX		/* 48 opcodes max */
} re_mi_op_t;

/**
 * Minimal one-byte instructions.
 *
 * When the OP code is 0, we have another interpretation for the trailing
 * 4 bits:
 *
 *   +-+-+-+-+--------+
 *   |0:0:0:0| M code |
 *   +-+-+-+-+--------+
 *
 * The M code (M for Minimal) defines 16 sub-instructions that all fit in
 * 1 byte, reserving 2-byte opcodes for instructions which either need
 * the FLG additional bits, or simply do not fit in the general architecture.
 */
typedef enum {
		/*
		 * NOP -- does nothing
		 */
	RE_MOP_NOP = 0,

		/*
		 * DONE -- flags matching success
		 */
	RE_MOP_DONE = 1,

		/*
		 * FAIL -- triggers a failure
		 */
	RE_MOP_FAIL = 2,

		/*
		 * START -- match at the start of text (^)
		 */
	RE_MOP_START = 3,

		/*
		 * END -- match at the end of text ($)
		 */
	RE_MOP_END = 4,

		/*
		 * WB -- match at a word-boundary (\b)
		 */
	RE_MOP_WB = 5,

		/*
		 * NOT_WB -- match unless at a word-boundary (\B)
		 */
	RE_MOP_NOT_WB = 6,

		/*
		 * RET -- return from subroutine
		 *
		 * This is the companion instruction for CALL.
		 *
		 * It pops a PC from the TRACK stack and transfers control back
		 * to it, in effect coming back right after the initial CALL
		 * instruction.
		 *
		 * It also pops the FSP and makes sure its value is identical to the
		 * current FSP register.  If not, this is a fatal error for the machine,
		 * as it means the subroutine has registered, on the FAIL stack, a point
		 * to which we cannot return!
		 */
	RE_MOP_RET = 7,

		/*
		 * PUSH_FSP -- pushes current FAIL stack pointer to the TRACK stack.
		 */
	RE_MOP_PUSH_FSP = 8,

		/*
		 * POP_A -- pops top value from the TRACK stack into the A register.
		 */
	RE_MOP_POP_A = 9,

		/*
		 * ANY -- matches any character but \n (.).
		 */
	RE_MOP_ANY = 10,

		/*
		 * ALL -- matches all characters.
		 */
	RE_MOP_ALL = 11,

		/*
		 * UPDATE_TP -- updates top of FAIL stack with current TP
		 */
	RE_MOP_UPDATE_TP = 12,

		/*
		 * DROP_FAIL -- drops last FAIL point on the FAIL stack
		 */
	RE_MOP_DROP_FAIL = 13,

		/*
		 * POP_FSP -- pops value from the TRACK stack and assign it to
		 * the current FAIL stack pointer register (FSP).
		 */
	RE_MOP_POP_FSP = 14,

		/*
		 * CEX -- conditional instruction execution, clearing C if no match
		 *
		 * This sets the C flag and changes the behaviour of the next
		 * matching instruction: instead of raising a FAIL when it fails
		 * text matching, it clears the C flag.
		 *
		 * It is then up to the code to check the C flag to determine
		 * whether there was a match (C still set) or not (C was cleared).
		 *
		 * The purpose of this instruction is to prevent the creation of
		 * a FAIL point during atomic matches for plain elements.
		 *
		 * Note that the C flag is otherwise left untouched (set) when
		 * there is a match, meaning atomic (greedy) unbound matching can be
		 * made very efficient since looping does not need to re-execute CEX!
		 */
	RE_MOP_CEX = 15,

	RE_MOP_MAX		/* 16 opcodes max */
} re_mi_mop_t;

/**
 * Indexed one-byte instructions, followed by 1 or 2 bytes immediate operand.
 *
 *   +-+-+-+-+-+------+
 *   |0:0:0:1|S| I Op |
 *   +-+-+-+-+-+------+
 *
 * When the S (for Small) bit is set, the immediate constant follows in
 * the next byte.  Otherwise, the immediate constant comes in the next
 * two bytes.
 *
 * The I op (I for Index) defines 8 sub-instructions that all fit in
 * 1 byte.  All these operate on memory words (addressed by their index
 * within the reserved-word array, lying at the bottom of the TRACK stack).
 */
typedef enum {
		/*
		 * SAVE_TP n -- saves the current text pointer in reserved word `n'
		 *
		 * This is used in combination with the CMP_TP instruction to
		 * track progress of the text pointer (TP register) when matching
		 * a pattern that can be successful on the empty string, to avoid
		 * being stuck in endless matching loops.
		 */
	RE_IOP_SAVE_TP = 0,

		/*
		 * CMP_TP n -- compares current TP with the one in reserved word `n'
		 *
		 * This is used in conjunction with an earlier SAVE_TP instruction
		 * to monitor progress of matching, when we know we can be successful
		 * with an empty-string match.
		 *
		 * The Z bit is set if the current TP matches the one saved,
		 * it is cleared otherwise.
		 */
	RE_IOP_CMP_TP = 1,

		/*
		 * CLEAR n -- clear value in reserved word `n'
		 */
	RE_IOP_CLEAR = 2,

		/*
		 * INC_A n -- increments value in word `n', copy new value into A.
		 *
		 * The value at reserved word `n' is incremented and the new value
		 * copied into the accumulator register A.
		 */
	RE_IOP_INC_A = 3,

		/*
		 * LOAD_A n -- loads value of word `n' into the A register.
		 */
	RE_IOP_LOAD_A = 4,

		/*
		 * LT_TP n -- compares current TP with the one in reserved word `n'
		 *
		 * The Z bit is set if the current TP is strictly less than the
		 * value in word `n', it is cleared otherwise.
		 */
	RE_IOP_LT_TP = 5,

		/*
		 * SAVE_FSP n -- saves value of the FSP register to memory word `n'
		 */
	RE_IOP_SAVE_FSP = 6,

		/*
		 * UPDATE_FTP n -- updates TP in the FAIL record pointed at by word `n'
		 *
		 * This instructions performs the same work as UPDATE_TP, but instead
		 * of using the current value of the FSP register to access the FAIL
		 * record, it uses the word `n'.
		 *
		 * The current TP register is then used to replace the previous entry
		 * in the corresponding FAIL record.
		 */
	RE_IOP_UPDATE_FTP = 7,

	RE_IOP_MAX		/* 8 opcodes max */
} re_mi_iop_t;

/**
 * Structure representing a fully-decoded instruction.
 */
typedef struct re_mi_inst {
	/* Raw values read, used to do bits decoding as needed during execution */
	re_mi_opcode_t op;
	re_mi_opfollow_t of;
	const uint8 *pc;	/* For convenience, beginning of arguments */
	const uint8 *ip;	/* For convenience, instruction pointer */
	int opcode;			/* Operation code */
	/* Decoded values, computed by re_mi_decode_inst() only */
	uint8 x;			/* X bit */
	uint8 z;			/* Z bit */
	uint8 cs;			/* CS flags */
	uint8 flg;			/* Additional flags in the FLG bits */
	uint8 s;			/* S bit for indexed operations */
	int mop;			/* Minimal operation code */
	int iop;			/* Indexed operation code */
} re_mi_inst_t;

/**
 * @return symbolic string for CS values.
 */
static const char *
re_mi_cs2str(re_op_cs_t cs)
{
#define CASE(x)	case RE_OP_CS_ ## x: return #x;

	switch (cs) {
	CASE(EMPTY);
	CASE(CLE);
	CASE(8BITS);
	CASE(16BITS);
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * @return short string for CS values.
 */
static inline const char *	/* Used only by debugging code, hence inline */
re_mi_cs2str_short(re_op_cs_t cs)
{
#define CASE(x)	case RE_OP_CS_ ## x: return #x;

	switch (cs) {
	case RE_OP_CS_EMPTY:  return "0";
	case RE_OP_CS_CLE:    return "CLE";
	case RE_OP_CS_8BITS:  return "8";
	case RE_OP_CS_16BITS: return "16";
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * @return symbolic op code name.
 */
static const char *
re_mi_op2str(re_mi_op_t op)
{
#define CASE(x)	case RE_OP_ ## x: return #x;

	switch (op) {
	CASE(ZERO);
	CASE(INDEX);
	CASE(JMP);
	CASE(LOAD);
	CASE(FAIL_JMP);
	CASE(NEED);
	CASE(XJMP);
	CASE(UJMP);
	CASE(MATCH);
	CASE(CLASS);
	CASE(TRIE);
	CASE(HWCL);
	CASE(HWCL2);
	CASE(REF);
	CASE(CAPTURE);
	CASE(DJMP);
	CASE(XCALL);
	CASE(DEBUG);
	CASE(ESCAPE);
	CASE(CALL);
	CASE(LT_A);
	CASE(RG_A);
	CASE(FAIL_OP);
	CASE(F_PUSH_TRACK);
	CASE(F_PUSH_GROUP);
	CASE(F_PUSH_REF);
	CASE(F_POP_TRACK);
	CASE(F_POP_GROUP);
	CASE(F_POP_REF);
	CASE(F_DROP_WORD);
	CASE(SET_A);
	CASE(RET_A);
	CASE(XLOAD_A);
	CASE(REPEAT);
	CASE(SUB_TP);
	CASE(ADD);
	CASE(UPDATE_FPC);
	CASE(REW_TP);
	case RE_OP_MAX:
		g_assert_not_reached();
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * @return symbolic minimal op code name.
 */
static const char *
re_mi_mop2str(re_mi_mop_t op)
{
#define CASE(x)	case RE_MOP_ ## x: return #x;

	switch (op) {
	CASE(NOP);
	CASE(DONE);
	CASE(FAIL);
	CASE(START);
	CASE(END);
	CASE(WB);
	CASE(NOT_WB);
	CASE(RET);
	CASE(PUSH_FSP);
	CASE(POP_A);
	CASE(ANY);
	CASE(ALL);
	CASE(UPDATE_TP);
	CASE(DROP_FAIL);
	CASE(POP_FSP);
	CASE(CEX);
	case RE_MOP_MAX:
		g_assert_not_reached();
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * @return symbolic indexed op code name.
 */
static const char *
re_mi_iop2str(re_mi_iop_t op)
{
#define CASE(x)	case RE_IOP_ ## x: return #x;

	switch (op) {
	CASE(SAVE_TP);
	CASE(CMP_TP);
	CASE(CLEAR);
	CASE(INC_A);
	CASE(LOAD_A);
	CASE(LT_TP);
	CASE(SAVE_FSP);
	CASE(UPDATE_FTP);
	case RE_IOP_MAX:
		g_assert_not_reached();
	}

#undef CASE

	return "*UNKNOWN*";
}

/**
 * Get opcode name from instruction.
 *
 * The Instruction Register does not require to be fully decoded, it just
 * needs to have been loaded via RE_MI_LOAD_IR().
 *
 * @param ir		the Instruction Register
 *
 * @return symbolic op code name from instruction.
 */
static const char *
re_mi_inst_opname(const re_mi_inst_t *ir)
{
	str_t *s1 = str_private(G_STRFUNC, 16);
	str_t *s2 = str_private(G_STRFUNC, 16);
	static uint count;
	str_t *s;

#define Z(i)	(i)->op.u.v.z
#define X(i)	(i)->op.u.v.x

	switch (ir->opcode) {
		case RE_OP_ZERO:  return re_mi_mop2str(ir->op.u.m.op);
		case RE_OP_INDEX: return re_mi_iop2str(ir->op.u.i.op);
		default:
			/*
			 * This trick allows using re_mi_inst_opname() at most twice
			 * in a string formatting instruction.
			 */
			s = (0 == (atomic_uint_inc(&count) & 0x1)) ? s1 : s2;

			str_printf(s, "%s", re_mi_op2str(ir->opcode));
			if (Z(ir) || X(ir)) {
				str_putc(s, '.');
				if (Z(ir)) str_putc(s, 'Z');
				if (X(ir)) str_putc(s, 'X');
			}
			return str_2c(s);
	}
	g_assert_not_reached();

#undef Z
#undef X
}

/**
 * Returns the hardwired class character for the HWCL instruction.
 */
static int
re_mi_hwc2char(int n, bool negated)
{
	int c;

	switch (n) {
	case RE_MI_HWCLASS_D: c = 'd'; break;
	case RE_MI_HWCLASS_W: c = 'w'; break;
	case RE_MI_HWCLASS_S: c = 's'; break;
	default:              c = '?'; break;
	}

	return negated ? ascii_toupper(c) : c;
}

/**
 * Returns the hardwired class characters for the HWCL2 instruction.
 */
static const char *
re_mi_hwc2str(int n, bool negated)
{
	if (RE_MI_HWCLASS2_DS == n) {
		return negated ? "[^\\d\\s]" : "[\\d\\s]";
	} else if (RE_MI_HWCLASS2_WS == n) {
		return negated ? "[^\\w\\s]" : "[\\w\\s]";
	} else {
		return "??";
	}
}

/**
 * Initializes the magic number of a segment.
 *
 * At runtime, we rarely check this magic number, excepted at strategic
 * places where we need to make sure the memory is still allocated for
 * the segment (e.g. during the CALL generation and subsequent resolution).
 */
static void
re_mi_seg_init(re_mi_seg_t *ms)
{
	ms->magic = RE_MI_SEG_MAGIC;
}

/**
 * Free allocated segment and zero its structure.
 */
static void
re_mi_seg_free(re_mi_seg_t *ms)
{
	re_mi_seg_check(ms);

	HFREE_NULL(ms->base);
	ZERO(ms);
}

/**
 * Create a new segment.
 *
 * Normally, segments are expanded structure, but during code generation
 * of subroutines, we create new structures for holding the routine code.
 *
 * This segment must be destroyed with re_mi_seg_destroy().
 */
static re_mi_seg_t *
re_mi_seg_create(void)
{
	re_mi_seg_t *ms;

	WALLOC0(ms);
	ms->magic = RE_MI_SEG_DYN_MAGIC;	/* Can be destroyed */

	return ms;
}

/**
 * Destroy dynamically allocated structure along with its contained segment.
 */
static void
re_mi_seg_destroy(re_mi_seg_t *ms)
{
	g_assert(RE_MI_SEG_DYN_MAGIC == ms->magic);
	re_mi_seg_free(ms);
	WFREE(ms);
}

/* Computes position of address `p' relative to the segment base */
static inline uint ALWAYS_INLINE
re_mi_seg_offset(const re_mi_seg_t *ms, const uint8 *p)
{
	return p - ms->base;
}

static const uint8 *
re_mi_seg_base(const re_mi_seg_t *ms)
{
	return ms->base;
}

/* End position, when generation is completed */
static const uint8 *
re_mi_seg_end(const re_mi_seg_t *ms)
{
	return ms->p;
}

/* Compute segment address based on relative position from base */
static uint8 *
re_mi_seg_at(const re_mi_seg_t *ms, uint position)
{
	g_assert_log(position < re_mi_seg_used(ms),
		"%s(): position=%04X, used=%04X",
		G_STRFUNC, position, (uint) re_mi_seg_used(ms));

	return ptr_add_offset(ms->base, position);
}

/* Same as re_mi_seg_at() but allows `position' to be one-byte off end */
static uint8 *
re_mi_seg_at_1off(const re_mi_seg_t *ms, uint position)
{
	g_assert_log(position <= re_mi_seg_used(ms),
		"%s(): position=%04X, used=%04X",
		G_STRFUNC, position, (uint) re_mi_seg_used(ms));

	return ptr_add_offset(ms->base, position);
}

/* Is the segment large enough to hold `bytes' more bytes starting at `p'? */
static bool
re_mi_seg_has(const re_mi_seg_t *ms, const uint8 *p, size_t bytes)
{
	if G_UNLIKELY(p < ms->base)
		return FALSE;

	return p + bytes <= ms->p;
}

/* Hash a segment */
static unsigned
re_mi_seg_hash(const void *key)
{
	const re_mi_seg_t *ms = key;

	re_mi_seg_check(ms);

	return binary_hash(ms->base, re_mi_seg_used(ms));
}

/* Are two segments equal? */
static bool
re_mi_seg_eq(const void *a, const void *b)
{
	const re_mi_seg_t *ma = a, *mb = b;

	re_mi_seg_check(ma);
	re_mi_seg_check(mb);

	return
		re_mi_seg_used(ma) == re_mi_seg_used(mb) &&
		0 == memcmp(ma->base, mb->base, re_mi_seg_used(ma));
}

/**
 * Is pointer a valid one within the segment?
 */
static bool
re_mi_seg_is_valid(const re_mi_seg_t *ms, const void *p)
{
	if (ptr_cmp(p, ms->base) < 0) return FALSE;
	if (ptr_cmp(p, ms->p) >= 0)   return FALSE;

	return TRUE;
}

/**
 * Is position a valid one within the segment?
 */
static bool
re_mi_seg_is_valid_pos(const re_mi_seg_t *ms, uint position)
{
	return position < re_mi_seg_used(ms);
}

/**
 * Grow segment to be able to store `n' additional bytes.
 */
static void
re_mi_seg_grow(re_mi_seg_t *ms, size_t n)
{
	size_t used = re_mi_seg_used(ms);

	g_assert(used <= ms->len);

	if (ms->len - used < n) {
		size_t nlen = MAX(ms->len + n, ms->len * 2);
		ms->base = hrealloc(ms->base, nlen);
		ms->p = ptr_add_offset(ms->base, used);
		ms->len = nlen;
	}
}

/**
 * Shrink segment to its ideal size.
 *
 * @param ms		the segment to resize
 * @param margin	the trailing margin to leave
 */
static void
re_mi_seg_shrink(re_mi_seg_t *ms, size_t margin)
{
	g_assert(size_is_non_negative(margin));

	if (ms->base != NULL) {
		size_t used = re_mi_seg_used(ms);
		size_t len = used + margin;

		g_assert(used <= ms->len);

		ms->base = hrealloc(ms->base, len);
		ms->len = len;
		ms->p = ptr_add_offset(ms->base, used);

		/* Ensure the trailing margin we leave is zeroed */

		if (margin)
			memset(ms->p, 0, margin);
	}
}

/***
 *** ================== Bytecode Generation ===================
 ***/

#define RE_MI_UNROLL_MAX	32		/* MAX unrolling of simple matchers */
#define RE_MI_FAIL_MIN		4		/* Min repeats for greedy optimization */

#define RE_MI_FAIL_WORD_SZ	1		/* One word on FAIL stack per word */
#define RE_MI_FAIL_GROUP_SZ	2		/* Two words on FAIL stack per group */
#define RE_MI_FAIL_REF_SZ	2		/* Two words on FAIL stack per ref */

enum re_mi_call_magic { RE_MI_CALL_MAGIC = 0x0d1b76e8 };

/**
 * Call information.
 *
 * When we generate a CALL instruction, the code is buffered in a
 * separate segment, up to the final RET instruction. This creates
 * a subroutine.
 *
 * Within that subroutine, subsequent calls can be made to other
 * subroutines.  A first CALL to any subroutine has the `is_def'
 * field set, which means the `sub' part of the structure is also
 * filled.  Any subsequent CALL has is_def=FALSE and is merely
 * recording where the CALL is made, but there is no further
 * code generation happening.
 *
 * This structure tracks the relevant data for the subroutine:
 *
 * - the text segment where the CALL was done initially, so that we
 *   may resolve that address when the subroutine is finally committed
 *   to a location.
 * - the position within that text segment of the CALL instruction.
 * - the text segment of the subroutine itself.
 *
 * Because a subroutine may reference other segments that precede it
 * (the position where they are called from), they are inserted into
 * a stack and generation will happen from the deepest routine and up.
 *
 * Within a subroutine, all the JMP that can happen must be relative
 * so that we may locate the subroutine at any place in memory, without
 * having to remember all the absolute JMP positions to adjust them.
 */
typedef struct re_mi_call {
	enum re_mi_call_magic magic;
	bool is_def;				/* If TRUE, is a definition record */
	const void *id;				/* Unique ID */
	struct {
		re_mi_seg_t *routine;	/* The routine text */
		htable_t *fwd;			/* Unresolved JMP/CALL made by subroutine */
	} sub;
	re_mi_seg_t *parent;		/* Where CALL was made */
	htable_t *p_fwd;			/* Parent forward call table */
	uint position;				/* CALL position within parent */
} re_mi_call_t;

static inline void
re_mi_call_check(const struct re_mi_call * const c)
{
	g_assert(c != NULL);
	g_assert(RE_MI_CALL_MAGIC == c->magic);
}

enum re_mi_repeat_magic { RE_MI_REPEAT_MAGIC = 0x4fda9d64 };

/**
 * Management of the looping instructions.
 *
 * All the memory words currently allocated are kept in the `words' bit field.
 *
 * All the memory words that need to be preserved across a failure (i.e. whose
 * current value needs to be restored when popping a failure point) are tracked
 * in the `saved' bit field.
 *
 * See re_mi_generate_tracking_get() for additional comments on the management
 * of these memory words.
 */
typedef struct re_mi_repeat {
	enum re_mi_repeat_magic magic;
	size_t active;				/* # of active tracking (bits set in save) */
	size_t size;				/* Size of the bit array (in bits) */
	size_t length;				/* Length of the bit array (allocated bytes) */
	bit_array_t *words;			/* Tracks active words (bit set if allocated) */
	bit_array_t *saved;			/* Tracks words to save (bit set if saved) */
} re_mi_repeat_t;

static inline void
re_mi_repeat_check(const struct re_mi_repeat * const r)
{
	g_assert(r != NULL);
	g_assert(RE_MI_REPEAT_MAGIC == r->magic);
}

enum re_mi_element_info_magic { RE_MI_ELEMENT_INFO_MAGIC = 0x01f9839b };

/**
 * Element information gathered by re_mi_generate_analyze().
 *
 * We do not want to expand the element structure to only attach additional
 * information only relevant to code generation, so this extra information
 * is linked to each element through the eleminfo hash table in the generation
 * context.
 */
typedef struct re_mi_element_info {
	enum re_mi_element_info_magic magic;
	pslist_t *groups;		/* List of group numbers seen under element */
} re_mi_element_info_t;

static inline void
re_mi_element_info_check(const re_mi_element_info_t * const ei)
{
	g_assert(ei != NULL);
	g_assert(RE_MI_ELEMENT_INFO_MAGIC == ei->magic);
}

/**
 * Trie generation context.
 */
struct re_mi_gen_trie_ctx {
	struct re_mi_gen_ctx *mig;	/* The generation context */
	const re_element_t *e;		/* The trie element */
	int depth;					/* Trie depth */
	bool ret;					/* Whether to use RET at end of trie branches */
	dualhash_t *dt;				/* Maps id <=> element vector */
	pslist_t *jumps;			/* Jumps to the end for non-exact tries */
};

enum re_mi_gen_ctx_magic { RE_MI_GEN_CTX_MAGIC = 0x269540e3 };

/**
 * Matching Interpreter code generation context.
 */
struct re_mi_gen_ctx {
	enum re_mi_gen_ctx_magic magic;
	const re_regex_t *re;		/* The regular expression */
	re_mi_code_t *code;			/* Where to store TEXT and DATA segments */
	re_mi_seg_t *text;			/* Current TEXT segment to use */
	re_mi_repeat_t *repeats;	/* Repetition (loops) management */
	struct re_mi_gen_trie_ctx *mit;	/* Used by trie generation */
	size_t comments;			/* Total size of DEBUG statements added (info) */
	htable_t *subid;			/* Defined sub-routines ID -> call structure */
	htable_t *subtext;			/* Maps sub-routine TEXT -> call structure */
	htable_t *subpos;			/* Maps sub-routine TEXT -> resolved position */
	htable_t *classes;			/* Maps classes inserted in DATA -> offset */
	htable_t *tries;			/* Maps tries inserted in DATA -> offset */
	htable_t *fwd;				/* Maps position -> forward jump CS type */
	htable_t *resolved;			/* Maps position -> forward jump CS type */
	htable_t *eleminfo;			/* Maps element -> re_mi_element_info_t */
	htable_t *backrefs;			/* Maps group number -> last element seen */
	pslist_t *resolvable;		/* List positions of jumps we can resolve */
	pslist_t *calls;			/* Pending calls to generate and resolve */
	pslist_t *routines;			/* Pending routine calls to resolve */
	pslist_t *class_free;		/* Merged re_class_t structures to free */
	uint last_fail_jmp_words;	/* Additional words saved by last FAIL_JMP */
	uint debug:1;				/* If TRUE, in debug mode */
	uint need_emitted:1;		/* Was NEED already emitted in this branch? */
};

static inline void
re_mi_gen_ctx_check(const struct re_mi_gen_ctx * const mig)
{
	g_assert(mig != NULL);
	g_assert(RE_MI_GEN_CTX_MAGIC == mig->magic);
}

/**
 * Conditions for re_mi_generate_push_jmp().
 */
typedef enum {
	RE_MI_JMP_ALWAYS = 0,		/* Unconditional jump */
	RE_MI_JMP_Z,				/* Jump if Z bit set */
	RE_MI_JMP_NZ,				/* Jump if Z bit clear */
	RE_MI_JMP_C,				/* Jump if C bit set */
	RE_MI_JMP_NC,				/* Jump if C bit clear */
} re_mi_jmp_cond_t;

static void re_mi_generate_pop_jmp(struct re_mi_gen_ctx *mig, uint position);

/**
 * List iterator callback to resolve a pending jump.
 *
 * @return TRUE to remove the record from the list.
 */
static bool
re_mi_resolve_jmp(void *data, void *udata)
{
	uint origin = pointer_to_uint(data);
	struct re_mi_gen_ctx *mig = udata;

	re_mi_gen_ctx_check(mig);

	re_mi_generate_pop_jmp(mig, origin);
	return TRUE;
}

/**
 * Resolve all the pending jumps to the current TEXT position.
 */
static void
re_mi_resolve_here(struct re_mi_gen_ctx *mig)
{
	re_mi_gen_ctx_check(mig);

	/* Resolve listed pending jumps to the current position */

	mig->resolvable =
		pslist_foreach_remove(mig->resolvable, re_mi_resolve_jmp, mig);
}

/**
 * Add minimal instruction opcode to the TEXT segment.
 *
 * Minimal means these instructions are 1-byte long and do not have flags.
 * Specific behaviour is therefore achieved by having distinct operation codes.
 *
 * @param mig		instruction generation context
 * @param mop		minimal operation code
 *
 * @return the offset within the segment where we generated the instruction.
 */
static uint
re_mi_gen_mop(struct re_mi_gen_ctx *mig, re_mi_mop_t mop)
{
	re_mi_opcode_t b;
	re_mi_seg_t *text = mig->text;
	uint start = re_mi_seg_used(text);

	re_mi_gen_ctx_check(mig);

	re_mi_resolve_here(mig);
	re_mi_seg_grow(text, 1);

	b.u.m.zero = 0;
	b.u.m.op   = mop;

	*text->p++ = b.code;

	return start;
}

/**
 * Add indexed instruction opcode to the TEXT segment.
 *
 * Indexed means these instructions take a short immediate constant
 * as argument, one that can fit 1 or 2 bytes, and which therefore
 * does not require CS-encoding but can be described through 1 bit (S).
 *
 * @param mig		instruction generation context
 * @param iop		immediate operation code
 * @param arg		immediate operation argument
 *
 * @return the offset within the segment where we generated the instruction.
 */
static uint
re_mi_gen_iop(struct re_mi_gen_ctx *mig, re_mi_iop_t iop, uint arg)
{
	re_mi_opcode_t b;
	re_mi_seg_t *text = mig->text;
	uint start = re_mi_seg_used(text);

	re_mi_gen_ctx_check(mig);
	g_assert(arg < MAX_INT_VAL(uint16));
	g_assert(arg >= 1);

	arg--;		/* Move back to 0-based indexing */

	b.u.i.one = 1;
	b.u.i.op  = iop;
	b.u.i.s   = arg < MAX_INT_VAL(uint8);

	re_mi_resolve_here(mig);
	re_mi_seg_grow(text, 2 + !b.u.i.s);

	*text->p++ = b.code;

	if (b.u.i.s)
		*text->p++ = (uint8) arg;
	else
		text->p = poke_le16(text->p, arg);

	return start;
}

/**
 * Add instruction opcode to the TEXT segment.
 *
 * @param mig		instruction generation context
 * @param op		operation
 * @param x			X bit
 * @param z			Z bit
 * @param cs		CS bits
 * @param flg		FLG bits, must be 0 if small op code
 *
 * @return the offset within the segment where we generated the instruction.
 */
static uint
re_mi_gen_op(struct re_mi_gen_ctx *mig,
	re_mi_op_t op, bool x, bool z, re_op_cs_t cs, uint8 flg)
{
	size_t oplen = op > RE_OP_ESCAPE ? 2 : 1;
	re_mi_opcode_t b1;
	re_mi_seg_t *text = mig->text;
	uint start = re_mi_seg_used(text);

	re_mi_gen_ctx_check(mig);
	g_assert(op != RE_OP_ZERO);	/* Must use re_mi_gen_mop() for these */
	g_assert(implies(1 == oplen, 0 == flg));
	g_assert(cs <= 3);			/* 2 bits */
	g_assert(flg <= 7);			/* 3 bits */

	/*
	 * If OP code is smaller than RE_OP_ESCAPE, we just need one byte.
	 */

	re_mi_resolve_here(mig);
	re_mi_seg_grow(text, oplen);

	b1.u.v.op = op > RE_OP_ESCAPE ? RE_OP_ESCAPE : op;
	b1.u.v.x = booleanize(x);
	b1.u.v.z = booleanize(z);
	b1.u.v.cs = cs;

	*text->p++ = b1.code;

	/*
	 * We need two bytes for this OP code, but we gain extra customization
	 * of the operation through the additional FLG field in the second
	 * byte.
	 *
	 * The use of the FLG field (apart from the expected frequency of
	 * the instructions) is one reason to use a 2-byte code, leaving
	 * more space for simpler, more common and more straightforward
	 * 1-byte instructions.
	 * 		--RAM, 2020-08-03
	 */

	if (oplen > 1) {
		re_mi_opfollow_t b2;

		b2.v.op  = op - (RE_OP_ESCAPE + 1);
		b2.v.flg = flg;

		*text->p++ = b2.code;
	}

	return start;
}

/**
 * Select the proper CS value to optimally encode value.
 *
 * @param value			the value to encode
 * @param is_signed		whether the value will be signed
 *
 * @return proper CS bits to use in the instruction.
 */
static re_op_cs_t
re_mi_cs_select(size_t value, bool is_signed)
{
	if (value <= MAX_INT_VAL(uint8))
		return RE_OP_CS_8BITS;
	else if (value <= MAX_INT_VAL(uint16))
		return RE_OP_CS_16BITS;

	if (is_signed && !size_is_positive(value)) {
		size_t neg_value = (size_t) (-(ssize_t) value);

		if (neg_value <= MAX_INT_VAL(uint8))
			return RE_OP_CS_8BITS;
		else if (neg_value <= MAX_INT_VAL(uint16))
			return RE_OP_CS_16BITS;
	}

	return RE_OP_CS_CLE;
}

/**
 * Append 1 byte to the given segment.
 */
static void
re_mi_gen_append_byte(re_mi_seg_t *ms, uint8 value)
{
	re_mi_seg_grow(ms, 1);
	*ms->p++ = value;
}

/**
 * Append bytes to the given segment.
 */
static void
re_mi_gen_append_bytes(re_mi_seg_t *ms, const void *p, size_t len)
{
	re_mi_seg_grow(ms, len);
	ms->p = mempcpy(ms->p, p, len);
}

/**
 * Append CS-encoded value.
 *
 * @param mig		the generation context
 * @param cs		the CS encoding
 * @param bytes		amount of bytes to reserve for RE_OP_CS_EMPTY
 * @param value		the value to write
 * @param is_signed	whether value is absolute or signed
 */
static void
re_mi_gen_constant(struct re_mi_gen_ctx *mig,
	re_op_cs_t cs, size_t bytes, size_t value, bool is_signed)
{
	re_mi_seg_t *text = mig->text;

	re_mi_gen_ctx_check(mig);

	switch (cs) {
	case RE_OP_CS_EMPTY:
		re_mi_seg_grow(text, bytes);
		memset(text->p, 0, bytes);
		text->p += bytes;
		return;
	case RE_OP_CS_CLE:
		{
			re_mi_cle_t lead;
			char buf[8];

			if (!size_is_positive(value)) {
				size_t neg_value = (size_t) (-(ssize_t) value);

				/*
				 * Negating value is only interesting if it is smaller,
				 * meaning possibly more trailing zero bytes in the encoding.
				 */

				if (neg_value < value) {
					lead.v.u = booleanize(!is_signed);
					lead.v.n = TRUE;
					lead.v.zero = 0;
					lead.v.length = vlint_encode(neg_value, buf);
					goto generate;
				}
			}

			lead.v.u = booleanize(!is_signed);
			lead.v.n = FALSE;
			lead.v.zero = 0;
			lead.v.length = vlint_encode(value, buf);

			/* FALL THROUGH */

		generate:
			re_mi_seg_grow(text, 1);
			*text->p++ = lead.value;
			re_mi_gen_append_bytes(text, buf, lead.v.length);
		}
		return;
	case RE_OP_CS_8BITS:
		if (is_signed) {
			if (abs((int) value) > MAX_INT_VAL(int8)) goto error;
		} else {
			if (value > MAX_INT_VAL(uint8)) goto error;
		}
		re_mi_seg_grow(text, 1);
		text->p = poke_u8(text->p, value);
		return;
	case RE_OP_CS_16BITS:
		if (is_signed) {
			if (abs((int) value) > MAX_INT_VAL(int16)) goto error;
		} else {
			if (value > MAX_INT_VAL(uint16)) goto error;
		}
		re_mi_seg_grow(text, 2);
		text->p = poke_le16(text->p, value);
		return;
	}

	g_assert_not_reached();

error:
	if (is_signed)
		s_error("%s(): %s unsuitable for signed constant %zd",
			G_STRFUNC, re_mi_cs2str(cs), (ssize_t) value);
	else
		s_error("%s(): %s unsuitable for unsigned constant %zu",
			G_STRFUNC, re_mi_cs2str(cs), value);
}

/**
 * Return whether opcode is that of a JMP-like instruction.
 */
static bool
re_mi_op_is_jmp(re_mi_op_t op)
{
	switch (op) {
	case RE_OP_JMP:
	case RE_OP_UJMP:
	case RE_OP_FAIL_JMP:
	case RE_OP_CALL:
	case RE_OP_XCALL:
		return TRUE;
	default:
		return FALSE;
	}
}

/**
 * Return current offset within the TEXT segment for the instruction we
 * are about to generate.
 */
static uint
re_mi_generate_position(const struct re_mi_gen_ctx *mig)
{
	return re_mi_seg_used(mig->text);
}

/**
 ** All the routines generating an instruction have the same interface:
 **
 ** The first parameter is the code generation context.
 ** The following parameters, if any, are the instruction parameters.
 **
 ** Parameters will only be documented when not trivially readable as-is.
 **
 ** All the instruction-generation routines bear the same naming convention:
 **
 **		re_mi_gen_inst_NAME
 **
 ** where NAME is the instruction name.
 **
 ** Note that due to the X bit helping us refine the meaning of some opcodes,
 ** we may have artificial NAME entries here not corresponding to an actual
 ** instruction code.  For instance FAIL is really a DONE.X, i.e. the DONE
 ** instruction with the X bit set!
 **
 ** But it's more readable to say that than to specify the X bit as an argument!
 **/

/* To make it clear what the arguments of GEN_OP() stand for */
#define X(x)		x
#define Z(x)		x
#define CS(x)		x
#define FLG(x)		x

#define GEN_OP(op, x, z, cs, flg) \
	re_mi_gen_op(mig, RE_OP_ ## op, (x), (z), (cs), (flg))

#define GEN_MOP(op)		re_mi_gen_mop(mig, RE_MOP_ ## op)
#define GEN_IOP(op,n)	re_mi_gen_iop(mig, RE_IOP_ ## op, (n))

#define GEN(name) re_mi_gen_inst_ ## name (mig)
#define GENX(name, ...) re_mi_gen_inst_ ## name (mig, __VA_ARGS__)

/* DEBUG instruction */
static void
re_mi_gen_inst_debug(struct re_mi_gen_ctx *mig, const char *text)
{
	size_t len;
	re_op_cs_t cs;
	size_t old_used, new_used;

	re_mi_gen_ctx_check(mig);

	if (!mig->debug)
		return;			/* Ignore if not in debugging mode */

	len = vstrlen(text);
	cs = re_mi_cs_select(len, FALSE);

	old_used = re_mi_seg_used(mig->text);

	GEN_OP(DEBUG, X(0), Z(0), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, len, FALSE);
	re_mi_gen_append_bytes(mig->text, text, len);

	new_used = re_mi_seg_used(mig->text);
	mig->comments += new_used - old_used;
}

/* DONE minimal instruction */
static void
re_mi_gen_inst_done(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(DONE);
}

/* FAIL minimal instruction */
static void
re_mi_gen_inst_fail(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(FAIL);
}

/* START minimal instruction */
static void
re_mi_gen_inst_start(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(START);
}

/* END minimal instruction */
static void
re_mi_gen_inst_end(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(END);
}

/* WB minimal instruction */
static void
re_mi_gen_inst_wb(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(WB);
}

/* NOT_WB minimal instruction */
static void
re_mi_gen_inst_not_wb(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(NOT_WB);
}

/* RET minimal instruction */
static void
re_mi_gen_inst_ret(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(RET);
}

/* UPDATE_TP minimal instruction */
static void
re_mi_gen_inst_update_tp(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(UPDATE_TP);
}

/* CEX minimal instruction */
static void
re_mi_gen_inst_cex(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(CEX);
}

/*
 * Generate instruction where operand value is encoded into the FLG bits
 * of the instruction opcode, and higher bits as additional arguments
 * if needed.
 *
 * This is typically how we encode CAPTURE.
 *
 * @param mig		the generation context
 * @param op		the operation code
 * @param x			value of the X bit
 * @param z			value of the Z bit
 * @param n			the immediate constant, argument of `op'
 */
static void
re_mi_gen_flg_embedded(struct re_mi_gen_ctx *mig, re_mi_op_t op,
	bool x, bool z, size_t n)
{
	re_op_cs_t cs = RE_OP_CS_CLE;
	uint flg;
	size_t high;

	g_assert(op > RE_OP_ESCAPE);	/* Need 2-byte instruction to use FLG */

	/*
	 * The lowest 3 bits are always part of the instruction.
	 * The highest bits, if non-zero, are CS-encoded.
	 */

	high = n >> 3;
	flg  = n & 0x7;

	if (0 == high)
		cs = RE_OP_CS_EMPTY;
	else if (high < MAX_INT_VAL(uint8))
		cs = RE_OP_CS_8BITS;
	else if (high < MAX_INT_VAL(uint16))
		cs = RE_OP_CS_16BITS;

	x = booleanize(x);
	z = booleanize(z);

	re_mi_gen_op(mig, op, X(x), Z(z), CS(cs), FLG(flg));
	if (RE_OP_CS_EMPTY != cs)
		re_mi_gen_constant(mig, cs, 0, high, FALSE);	/* Unsigned */
}

/*
 * Generate instruction where operand value is encoded into the
 * X, Z and FLG bits of the instruction opcode, and higher bits as
 * additional arguments if needed.
 *
 * This is typically how we encode NEED and SET_A.
 *
 * @param mig		the generation context
 * @param op		the operation code
 * @param n			the immediate constant, argument of `op'
 */
static void
re_mi_gen_xzflg_embedded(struct re_mi_gen_ctx *mig, re_mi_op_t op, size_t n)
{
	re_op_cs_t cs = RE_OP_CS_CLE;
	uint flg;
	bool z, x;
	size_t high;

	g_assert(op > RE_OP_ESCAPE);	/* Need 2-byte instruction to use FLG */

	/*
	 * The lowest 5 bits are always part of the instruction.
	 * The highest bits, if non-zero, are CS-encoded.
	 */

	high = n >> 5;
	flg  = n & 0x7;
	z    = booleanize(n & 0x8);
	x    = booleanize(n & 0x10);

	if (0 == high)
		cs = RE_OP_CS_EMPTY;
	else if (high < MAX_INT_VAL(uint8))
		cs = RE_OP_CS_8BITS;
	else if (high < MAX_INT_VAL(uint16))
		cs = RE_OP_CS_16BITS;

	re_mi_gen_op(mig, op, X(x), Z(z), CS(cs), FLG(flg));
	if (RE_OP_CS_EMPTY != cs)
		re_mi_gen_constant(mig, cs, 0, high, FALSE);	/* Unsigned */
}

/* NEED instruction */
static void
re_mi_gen_inst_need(struct re_mi_gen_ctx *mig, size_t n)
{
	g_assert(n != 0);		/* Since values are encoded as n - 1 */

	/* We encode n - 1 since, by construction, `n' is necessarily >= 1 */
	re_mi_gen_xzflg_embedded(mig, RE_OP_NEED, n - 1);
}

/* SET_A instruction */
static void
re_mi_gen_inst_set_a(struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_gen_xzflg_embedded(mig, RE_OP_SET_A, n);
}

/* RET_A instruction */
static void
re_mi_gen_inst_ret_a(struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_gen_xzflg_embedded(mig, RE_OP_RET_A, n);
}

/* SUB_TP instruction */
static void
re_mi_gen_inst_sub_tp(struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_gen_xzflg_embedded(mig, RE_OP_SUB_TP, n);
}

/* DROP_FAIL minimal instruction (possibly followed by F_DROP_WORD) */
static void
re_mi_gen_inst_drop_fail(struct re_mi_gen_ctx *mig, size_t nwords)
{
	GEN_MOP(DROP_FAIL);

	if (nwords != 0)
		re_mi_gen_xzflg_embedded(mig, RE_OP_F_DROP_WORD, nwords - 1);
}

/* REF instruction */
static void
re_mi_gen_inst_ref(struct re_mi_gen_ctx *mig, size_t n, bool icase)
{
	re_op_cs_t cs = RE_OP_CS_16BITS;

	if (n < MAX_INT_VAL(uint8))
		cs = RE_OP_CS_8BITS;

	GEN_OP(REF, X(icase), Z(0), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);
}

/* REPEAT instruction */
static void
re_mi_gen_inst_repeat(struct re_mi_gen_ctx *mig, bool x, size_t n)
{
	/* 0 means SIZE_MAX (or infinite) */

	if (SIZE_MAX == n)
		n = 0;

	re_mi_gen_flg_embedded(mig, RE_OP_REPEAT, X(x), Z(0), n);
}

/* CAPTURE (group) instruction */
static void
re_mi_gen_inst_capture(struct re_mi_gen_ctx *mig, size_t n, bool start)
{
	const re_regex_t *re = mig->re;
	size_t i;

	g_assert(n != 0);		/* Since values are encoded as n - 1 */

	/* We encode n - 1 since, by construction, `n' is necessarily >= 1 */
	re_mi_gen_flg_embedded(mig, RE_OP_CAPTURE, X(!start), Z(0), n - 1);

	/*
	 * If the group #n is used as a back-reference, also generate an
	 * instruction to capture that internal ref, using the LUT to convert
	 * the group number into an internal ref number.
	 */

	i = re_exec_match_backref_index(re, n);
	if (i != 0)
		re_mi_gen_flg_embedded(mig, RE_OP_CAPTURE, X(!start), Z(1), i - 1);
}

/**
 * Common code for HWCL instruction (non-POSIX).
 */
static void
re_mi_gen_inst_hwcl(struct re_mi_gen_ctx *mig, int n, bool negated)
{
	GEN_OP(HWCL, X(negated), Z(0), CS(n), FLG(0));
}

#define RE_MI_GEN_HWCLASS(c, v, flag)							\
static void														\
re_mi_gen_inst_hwcl_ ## c(struct re_mi_gen_ctx *mig)			\
{																\
	return														\
		re_mi_gen_inst_hwcl(mig, RE_MI_HWCLASS_ ## v, flag);	\
}

RE_MI_GEN_HWCLASS(d, D, FALSE)
RE_MI_GEN_HWCLASS(D, D, TRUE)
RE_MI_GEN_HWCLASS(w, W, FALSE)
RE_MI_GEN_HWCLASS(W, W, TRUE)
RE_MI_GEN_HWCLASS(s, S, FALSE)
RE_MI_GEN_HWCLASS(S, S, TRUE)

/* HWCL2 instruction */
static void
re_mi_gen_inst_hwcl2(struct re_mi_gen_ctx *mig, int n, bool negated)
{
	GEN_OP(HWCL2, X(negated), Z(0), CS(0), FLG(n));
}

/**
 * Patch CS flags in instruction at given offset.
 */
static void
re_mi_patch_cs(struct re_mi_gen_ctx *mig, uint start, re_op_cs_t cs)
{
	uint8 *pc;
	re_mi_opcode_t lead;

	re_mi_gen_ctx_check(mig);

	pc = re_mi_seg_at(mig->text, start);
	g_assert(re_mi_seg_is_valid(mig->text, pc));

	lead.code = *pc;
	g_assert(lead.u.v.op != RE_OP_ZERO);	/* No CS bits if minimal op */
	lead.u.v.cs = cs;
	*pc = lead.code;
}

/**
 * Common code for JMP-type instructions.
 *
 * The `cs' parameter tells us how to interpret the offset, and can be used
 * to force an absolute or a relative jump.  If RE_OP_CS_CLE, then we compute
 * the optimal encoding based on the offset value, and if RE_OP_CS_EMPTY,
 * we assume an absolute jump.
 *
 * @param mig		the generation context
 * @param op		the JMP-type op code
 * @param cond		the JMP condition
 * @param cs		chosen CS-encoding, RE_OP_CS_CLE to select proper one
 * @param offset	the destination offset
 */
static void
re_mi_gen_jump(struct re_mi_gen_ctx *mig,
	re_mi_op_t op, re_mi_jmp_cond_t cond, re_op_cs_t cs, int offset)
{
	uint start;
	bool chosen = FALSE;
	bool x, z;

	re_mi_gen_ctx_check(mig);
	g_assert(re_mi_op_is_jmp(op));

	if G_UNLIKELY(RE_OP_CS_CLE == cs) {
		chosen = TRUE;
		cs = re_mi_cs_select((size_t) offset, TRUE);
	}

	/*
	 * Bits for conditional jumps were carefully designed to allow
	 * efficient runtime computations: X is the index in the flags
	 * register of the bit to test, and Z is the value to test for
	 * in order for the jump to succeed.
	 */

	switch (cond) {
	case RE_MI_JMP_ALWAYS: x = z = 0;    break;
	case RE_MI_JMP_NZ:     x = 0; z = 0; break;
	case RE_MI_JMP_Z:      x = 0; z = 1; break;
	case RE_MI_JMP_NC:     x = 1; z = 0; break;
	case RE_MI_JMP_C:      x = 1; z = 1; break;
	}

	/*
	 * When we generate a forward jump (necessarily to an unknown address)
	 * we use an offset of zero, pending later resolution.
	 *
	 * However, when the offset is not zero (it cannot be a valid offset
	 * because it would mean to stay where we are after the JMP instruction,
	 * so why bother generating such an operation?), we need to offset it
	 * by the size of the JMP instruction itself.
	 *
	 * This means we can get off the CS encoding we selected above.  It's
	 * not a problem if it was chosen here, but if it was imposed, then
	 * it's a fatal error condition.
	 */

	start = re_mi_gen_op(mig, op, X(x), Z(z), CS(cs), FLG(0));

	if (offset != 0 && RE_OP_CS_EMPTY != cs) {
		/* Relative offset required */
		uint current = re_mi_seg_used(mig->text);
		size_t len = current - start;	/* Opcode length */

		if (RE_OP_CS_8BITS == cs)
			len += 1;
		else if (RE_OP_CS_16BITS == cs)
			len += 2;
		else
			g_assert_not_reached();	/* No CLE format for JMP */

		offset -= len;

		if (RE_OP_CS_8BITS == cs) {
			if (abs(offset) > MAX_INT_VAL(int8)) {	/* -128 is OK */
				if (!chosen) goto fatal;
				cs = RE_OP_CS_16BITS;		/* Move to 16-bit offset */
				offset--;					/* Which uses one more byte */
				re_mi_patch_cs(mig, start, cs);
			}
		} else if (abs(offset) > MAX_INT_VAL(int16)) {
			goto fatal;
		}
	}

	/* Signed value must be in proper range */
	g_assert(RE_OP_CS_EMPTY != cs  || offset >= 0);
	g_assert(RE_OP_CS_EMPTY != cs  || offset <= MAX_INT_VAL(uint16));
	g_assert(RE_OP_CS_8BITS != cs  || abs(offset) <= MAX_INT_VAL(int8));
	g_assert(RE_OP_CS_16BITS != cs || abs(offset) <= MAX_INT_VAL(int16));

	re_mi_gen_constant(mig, cs, 2, (size_t) offset, TRUE);
	return;

fatal:
	s_error("%s(): cannot use %s %s encoding of offset %d for %s",
		G_STRFUNC, chosen ? "chosen" : "imposed",
		re_mi_cs2str(cs), offset, re_mi_op2str(op));

}

/* SAVE_TP indexed instruction */
static void
re_mi_gen_inst_save_tp(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(SAVE_TP, n);
}

/* CMP_TP indexed instruction */
static void
re_mi_gen_inst_cmp_tp(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(CMP_TP, n);
}

/* SAVE_FSP instruction */
static void
re_mi_gen_inst_save_fsp(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(SAVE_FSP, n);
}

/* UPDATE_FTP instruction */
static void
re_mi_gen_inst_update_ftp(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(UPDATE_FTP, n);
}

/* PUSH_FSP minimal instruction */
static uint
re_mi_gen_inst_push_fsp(struct re_mi_gen_ctx *mig)
{
	return GEN_MOP(PUSH_FSP);
}

/* POP_FSP minimal instruction */
static void
re_mi_gen_inst_pop_fsp(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(POP_FSP);
}

/* POP_A minimal instruction */
static void
re_mi_gen_inst_pop_a(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(POP_A);
}

/* RG_A instruction */
static void
re_mi_gen_inst_rg_a(struct re_mi_gen_ctx *mig, size_t n, size_t m)
{
	re_op_cs_t ncs = re_mi_cs_select(n, FALSE);		/* Unsigned value */
	re_op_cs_t mcs = re_mi_cs_select(m, FALSE);		/* Unsigned value */

	GEN_OP(RG_A, X(0), Z(0), CS(ncs), FLG(mcs));
	re_mi_gen_constant(mig, ncs, 0, n, FALSE);
	re_mi_gen_constant(mig, mcs, 0, m, FALSE);
}

/* LT_A instruction */
static void
re_mi_gen_inst_lt_a(struct re_mi_gen_ctx *mig, size_t n)
{
	re_op_cs_t cs = re_mi_cs_select(n, FALSE);		/* Unsigned value */

	GEN_OP(LT_A, X(0), Z(0), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);
}

/* EQ_A instruction (LT_A.Z) (UNUSED) */
static void G_UNUSED
re_mi_gen_inst_eq_a(struct re_mi_gen_ctx *mig, size_t n)
{
	re_op_cs_t cs = re_mi_cs_select(n, FALSE);		/* Unsigned value */

	GEN_OP(LT_A, X(0), Z(1), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);
}

/* CP_A instruction (LT_A.X) */
static void
re_mi_gen_inst_cp_a(struct re_mi_gen_ctx *mig, size_t n)
{
	re_op_cs_t cs = re_mi_cs_select(n, FALSE);		/* Unsigned value */

	GEN_OP(LT_A, X(1), Z(0), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);
}

/* LT_TP indexed instruction */
static void
re_mi_gen_inst_lt_tp(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(LT_TP, n);
}

static bool re_mi_generate_tracking_is_used(
	const struct re_mi_gen_ctx *mig, size_t n);

/* CLEAR indexed instruction */
static void
re_mi_gen_inst_clear(struct re_mi_gen_ctx *mig, size_t n)
{
	g_assert(re_mi_generate_tracking_is_used(mig, n));

	GEN_IOP(CLEAR, n);
}

/* INC_A indexed instruction */
static void
re_mi_gen_inst_inc_a(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(INC_A, n);
}

/* LOAD_A indexed instruction */
static void
re_mi_gen_inst_load_a(struct re_mi_gen_ctx *mig, size_t n)
{
	GEN_IOP(LOAD_A, n);
}

/* XLOAD_A instruction */
static void
re_mi_gen_inst_xload_a(struct re_mi_gen_ctx *mig, size_t n, size_t *values)
{
	re_op_cs_t cs = re_mi_cs_select(n, FALSE);	/* Unsigned value */
	re_op_cs_t vcs;
	size_t i, max_value = 0;
	bool all_equal = TRUE;

	for (i = 0; i < n; i++) {
		if (i != values[i])
			all_equal = FALSE;
		max_value = MAX(max_value, values[i]);
	}

	/*
	 * There is no need to generate the XLOAD_A instruction if it simply
	 * performs an identity mapping!
	 */

	if (all_equal) {
		GENX(debug,
			str_smsg("avoiding identity mapping of %zu value%s", PLURAL(n)));
		return;
	}

	vcs = re_mi_cs_select(max_value, FALSE);

	GEN_OP(XLOAD_A, X(0), Z(0), CS(cs), FLG(vcs));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);	/* The amount of values */

	for (i = 0; i < n; i++) {
		re_mi_gen_constant(mig, vcs, 0, values[i], FALSE);
	}
}

/*
 * XJMP instructions (with placeholder offsets)
 *
 * @param mig		the generation context
 * @param n			upper boundary for A (i.e. A must be < n at runtime)
 * @param zero		if TRUE, generates a XJMP_Z instruction
 *
 * @return starting position of the jump table
 */
static uint
re_mi_gen_xjmp(struct re_mi_gen_ctx *mig, size_t n, bool zero)
{
	re_op_cs_t cs = re_mi_cs_select(n, FALSE);	/* Unsigned value */
	size_t position;

	g_assert(n > 1);		/* At least 2 values, or we'd use JMP */

	GEN_OP(XJMP, X(0), Z(zero), CS(cs), FLG(0));
	re_mi_gen_constant(mig, cs, 0, n, FALSE);	/* The amount of offsets */
	position = re_mi_generate_position(mig);

	if (zero)
		n--;		/* With XJMP_Z, A == 0 does not get any offset */

	while (n--)
		re_mi_gen_constant(mig, RE_OP_CS_16BITS, 0, 0, FALSE);

	return position;	/* Start of jump table */
}

/*
 * XJMP instruction (with placeholder offsets)
 *
 * @param mig		the generation context
 * @param n			upper boundary for A (i.e. A must be < n at runtime)
 *
 * @return starting position of the jump table
 */
static uint
re_mi_gen_inst_xjmp(struct re_mi_gen_ctx *mig, size_t n)
{
	return re_mi_gen_xjmp(mig, n, FALSE);
}

/*
 * XJMP_Z instruction (with placeholder offsets)
 *
 * @param mig		the generation context
 * @param n			upper boundary for A (i.e. A must be < n at runtime)
 *
 * @return starting position of the jump table
 */
static uint
re_mi_gen_inst_xjmp_z(struct re_mi_gen_ctx *mig, size_t n)
{
	return re_mi_gen_xjmp(mig, n, TRUE);
}

/* DJMP instruction (with placeholder offset) */
static void
re_mi_gen_inst_djmp(struct re_mi_gen_ctx *mig, bool z, size_t n, re_op_cs_t cs)
{
	re_op_cs_t ncs;
	bool x;

	g_assert(n >= 1);

	n--;								/* Encode 0-based index */
	ncs = re_mi_cs_select(n, FALSE);	/* Unsigned value */

	if (RE_OP_CS_8BITS == cs)
		x = FALSE;
	else if (RE_OP_CS_16BITS == cs)
		x = TRUE;
	else
		g_assert_not_reached();

	GEN_OP(DJMP, X(x), Z(z), CS(ncs), FLG(0));
	re_mi_gen_constant(mig, ncs, 0, n, FALSE);	/* The memory word */
	re_mi_gen_constant(mig, cs, 0, 0, FALSE);	/* Placeholder for JMP offset */
}

/* LOAD instruction */
static void
re_mi_gen_inst_load(struct re_mi_gen_ctx *mig, size_t n, size_t max)
{
	re_op_cs_t cs, fcs;

	g_assert(n >= 1);
	n--;								/* Encode 0-based index */

	/* Unsigned values */
	cs  = re_mi_cs_select(n,   FALSE);
	fcs = re_mi_cs_select(max, FALSE);

	GEN_OP(LOAD, X(0), Z(0), CS(cs), FLG(fcs));

	/* n comes first, then max */

	re_mi_gen_constant(mig, cs,  0, n,   FALSE);
	re_mi_gen_constant(mig, fcs, 0, max, FALSE);
}

/* ADD_instruction */
static void
re_mi_gen_inst_add(struct re_mi_gen_ctx *mig, size_t n, size_t val)
{
	re_op_cs_t cs, fcs;

	g_assert(n >= 1);
	n--;								/* Encode 0-based index */

	/* Unsigned values */
	cs  = re_mi_cs_select(n,   FALSE);
	fcs = re_mi_cs_select(val, FALSE);

	GEN_OP(ADD, X(0), Z(0), CS(cs), FLG(fcs));

	/* n comes first, then val */

	re_mi_gen_constant(mig, cs,  0, n,   FALSE);
	re_mi_gen_constant(mig, fcs, 0, val, FALSE);
}

/* MATCH or CHAR instruction */
static void
re_mi_gen_matching(struct re_mi_gen_ctx *mig,
	const char *text, size_t len, bool icase)
{
	re_op_cs_t cs = re_mi_cs_select(len, FALSE);

	/*
	 * If case does not matter, generate a case-sensitive match because it
	 * is more efficient at runtime.
	 */

	if (icase) {
		size_t n = len;
		const char *p = text;
		bool matters = FALSE;

		while (n--) {
			int c = *p++;
			if (ascii_toupper(c) != ascii_tolower(c)) {
				matters = TRUE;
				break;
			}
		}

		if (!matters)
			icase = FALSE;
	}

	/* Timing shows that 1 CHAR is more efficient than a MATCH 1 instruction */

	if (1 == len) {
		GEN_OP(MATCH,  X(icase), Z(0), CS(RE_OP_CS_EMPTY),  FLG(0));
	} else {
		GEN_OP(MATCH, X(icase), Z(0), CS(cs), FLG(0));
		re_mi_gen_constant(mig, cs, 0, len, FALSE);
	}

	if (icase) {
		const uchar *p = (const uchar *) text;
		/*
		 * At runtime we'll lower-case input text, so we must lower-case
		 * the character to compare against here
		 * */
		re_mi_seg_grow(mig->text, len);
		while (len--) {
			*mig->text->p++ = ascii_tolower(*p++);
		}
	} else {
		re_mi_gen_append_bytes(mig->text, text, len);
	}
}

/* MATCH instruction */
static void
re_mi_gen_inst_match(struct re_mi_gen_ctx *mig, const char *text, bool icase)
{
	size_t len = vstrlen(text);

	/* Timing shows that replacing a MATCH 2 with 2 CHAR is not useful */

	re_mi_gen_matching(mig, text, len, icase);
}

/* CHAR instruction (MATCH opcode with CS=EMPTY) */
static void
re_mi_gen_inst_char(struct re_mi_gen_ctx *mig, int c, bool icase)
{
	char buf[1];

	buf[0] = c;
	re_mi_gen_matching(mig, buf, 1, icase);
}

/* ANY minimal instruction */
static void
re_mi_gen_inst_any(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(ANY);
}

/* ALL minimal instruction */
static void
re_mi_gen_inst_all(struct re_mi_gen_ctx *mig)
{
	GEN_MOP(ALL);
}

/*
 * Common code for the CLASS instruction.
 *
 * @return TRUE if we had a new class definition (hence class was inserted
 * in the tracking hash table), FALSE if we already knew that class.
 */
static bool
re_mi_gen_class(struct re_mi_gen_ctx *mig, const re_class_t *cl,
	bool is_trie, bool inverted, bool icase)
{
	re_op_cs_t cs;
	re_mi_seg_t *data = &mig->code->data;
	void *data_off;
	size_t arg;
	bool is_new = TRUE;
	htable_t *ht = is_trie ? mig->tries : mig->classes;

	/*
	 * Lookup in our dictionary to see whether we have not seen already
	 * an instance of such a class.  If we do, we can reuse the DATA
	 * pointer we had set for that class already.
	 */

	if (htable_contains(ht, cl)) {
		data_off = htable_lookup(ht, cl);
		is_new = FALSE;
	} else {
		data_off = ulong_to_pointer(re_mi_seg_used(data));
		htable_insert(ht, cl, data_off);

		if (is_trie) {
			int c, n;

			/*
			 * When we're generating a class for trie matching, what matters
			 * is the position of the matching letter, so instead we generate
			 * an array of bytes containing the indexed value, so that it can be
			 * read immediately at runtime.  A zero means no-match.
			 *
			 * We can therefore be more fine-grained for the min/max values
			 * and we do not need the offset, as it will be the same as the
			 * minimum.
			 *
			 * Serialized data will therefore be:
			 * <min>, <max>, <byte array>
			 */

			re_mi_gen_append_byte(data, cl->min);
			re_mi_gen_append_byte(data, cl->max);

			for (n = 0, c = cl->min; c <= cl->max; c++) {
				if (bit_field_get(cl->b, c - cl->offset))
					re_mi_gen_append_byte(data, ++n);	/* nth char present */
				else
					re_mi_gen_append_byte(data, 0);		/* char absent */
			}
		} else {
			/*
			 * Copy class info into the DATA segment.
			 * The representation of the serialized re_class_t is very naturally:
			 *	<min>, <max>, <offset>, <bitfield>
			 */

			re_mi_gen_append_byte(data, cl->min);
			re_mi_gen_append_byte(data, cl->max);
			re_mi_gen_append_byte(data, cl->offset);
			re_mi_gen_append_bytes(data, cl->b, cl->bytes);
		}
	}

	arg = pointer_to_size(data_off);
	cs = re_mi_cs_select(arg, FALSE);	/* Unsigned value */

	if (is_trie)
		GEN_OP(TRIE, X(0), Z(icase), CS(cs), FLG(0));
	else
		GEN_OP(CLASS, X(inverted), Z(icase), CS(cs), FLG(0));

	re_mi_gen_constant(mig, cs, 0, arg, FALSE);

	return is_new;
}

/*
 * TRIE instruction, given as a re_class_t bitmap.
 *
 * @return TRUE if we had a new class definition.
 */
static bool
re_mi_gen_inst_trie(struct re_mi_gen_ctx *mig,
	const re_class_t *cl, bool icase)
{
	/*
	 * If all the bits are set between min and max, then we can use
	 * a min-max instruction.
	 */

	if (
		UNSIGNED(cl->max - cl->min + 1) == bit_field_count_set(
			cl->b, cl->min - cl->offset, cl->max - cl->offset)
	) {
		GEN_OP(TRIE, X(0), Z(icase), CS(RE_OP_CS_EMPTY), FLG(0));
		re_mi_gen_append_byte(mig->text, cl->min);
		re_mi_gen_append_byte(mig->text, cl->max);
		return FALSE;
	} else {
		return re_mi_gen_class(mig, cl, TRUE, FALSE, icase);
	}
}

/*
 * CLASS instruction, given as a re_class_t bitmap.
 *
 * @return TRUE if we had a new class definition.
 */
static bool
re_mi_gen_inst_class(struct re_mi_gen_ctx *mig,
	const re_class_t *cl, bool icase)
{
	return re_mi_gen_class(mig, cl, FALSE, FALSE, icase);
}

/*
 * INV_CLASS instruction, given as an inverted re_class_t bitmap
 *
 * @return TRUE if we had a new class definition.
 */
static bool
re_mi_gen_inst_inv_class(struct re_mi_gen_ctx *mig,
	const re_class_t *cl, bool icase)
{
	return re_mi_gen_class(mig, cl, FALSE, TRUE, icase);
}

/* CLASS instruction, given as a min/max range */
static void
re_mi_gen_inst_class_mm(struct re_mi_gen_ctx *mig,
	uint8 min, uint8 max, bool icase)
{
	GEN_OP(CLASS, X(0), Z(icase), CS(RE_OP_CS_EMPTY), FLG(0));
	re_mi_gen_append_byte(mig->text, min);
	re_mi_gen_append_byte(mig->text, max);
}

/* CLASS instruction, given as an inverted min/max range */
static void
re_mi_gen_inst_inv_class_mm(struct re_mi_gen_ctx *mig,
	uint8 min, uint8 max, bool icase)
{
	GEN_OP(CLASS, X(1), Z(icase), CS(RE_OP_CS_EMPTY), FLG(0));
	re_mi_gen_append_byte(mig->text, min);
	re_mi_gen_append_byte(mig->text, max);
}

/**
 * Generate UPDATE_FPC for an earlier destination.
 *
 * @param mig		the generation context
 * @param n			the memory word we use to access the FAIL record
 * @param where		position where we want to jump within the same segment
 */
static void
re_mi_gen_inst_update_fpc(struct re_mi_gen_ctx *mig, size_t n, uint where)
{
	re_mi_seg_t *text = mig->text;
	re_op_cs_t ncs, fcs;
	uint current;
	int offset;
	uint len;

	g_assert(RE_OP_UPDATE_FPC > RE_OP_ESCAPE);	/* 2-byte instruction */

	n--;								/* Encode 0-based index */
	ncs = re_mi_cs_select(n, FALSE);	/* Unsigned value */

	g_assert(RE_OP_CS_8BITS == ncs || RE_OP_CS_16BITS == ncs);

	current = re_mi_seg_used(mig->text);

	g_assert(where < current);			/* Destination before instruction */

	offset = where - current - 1 - (RE_OP_CS_16BITS == ncs);
	offset -= 2;	/* 2-byte instruction */

	len = 1 + (abs(offset) > MAX_INT_VAL(int8));
	fcs = 1 == len ? RE_OP_CS_8BITS : RE_OP_CS_16BITS;

	GEN_OP(UPDATE_FPC, X(0), Z(0), CS(ncs), FLG(fcs));
	re_mi_gen_constant(mig, ncs, 0, n, FALSE);		/* The memory word */

	offset = where - re_mi_seg_used(mig->text);	/* Used so far */
	offset -= len;		/* Jump offset starts AFTER we read displacement */

	if (1 == len) {
		g_assert(abs(offset) <= MAX_INT_VAL(int8));
		re_mi_seg_grow(text, 1);
		text->p = poke_u8(text->p, (uint8) offset);
	} else {
		g_assert(abs(offset) <= MAX_INT_VAL(int16));
		re_mi_seg_grow(text, 2);
		text->p = poke_le16(text->p, (uint16) offset);
	}
}

/* F_PUSH_TRACK #n instruction (FAIL_OP with CS=RE_MI_FAIL_OP_TRACK) */
static void
re_mi_gen_inst_f_push_track(struct re_mi_gen_ctx *mig, size_t n)
{
	re_op_cs_t csw;
	bool z;

	g_assert(n != 0);

	n--;							/* We encode n - 1 */
	z = n > MAX_INT_VAL(uint8);
	csw = z ? RE_OP_CS_16BITS : RE_OP_CS_8BITS;

	GEN_OP(FAIL_OP, X(0), Z(z), CS(RE_MI_FAIL_OP_TRACK), FLG(0));
	re_mi_gen_constant(mig, csw, 2, n, FALSE);
}

/* F_POP_TRACK #n instruction (FAIL_OP with CS=RE_MI_FAIL_OP_TRACK) */
static void
re_mi_gen_inst_f_pop_track(struct re_mi_gen_ctx *mig, size_t n)
{
	re_op_cs_t csw;
	bool z;

	g_assert(n != 0);

	n--;							/* We encode n - 1 */
	z = n > MAX_INT_VAL(uint8);
	csw = z ? RE_OP_CS_16BITS : RE_OP_CS_8BITS;

	GEN_OP(FAIL_OP, X(1), Z(z), CS(RE_MI_FAIL_OP_TRACK), FLG(0));
	re_mi_gen_constant(mig, csw, 2, n, FALSE);
}

/* REW_TP #n 'c' instruction */
static void
re_mi_gen_inst_rew_tp(struct re_mi_gen_ctx *mig,
	size_t n, uint8 c, size_t offset, bool icase)
{
	re_mi_seg_t *text = mig->text;
	bool z;
	re_op_cs_t cso, csw;

	n--;							/* We encode n - 1 */
	z = n > MAX_INT_VAL(uint8);
	csw = z ? RE_OP_CS_16BITS : RE_OP_CS_8BITS;
	cso = 0 == offset ? RE_OP_CS_EMPTY : re_mi_cs_select(offset, FALSE);

	/* Only request case-insensitive match if it matters */

	if (icase) {
		int lower = ascii_tolower(c);
		int upper = ascii_toupper(c);

		if (lower != upper) {
			/* Case-insensitive */
			GEN_OP(REW_TP, X(1), Z(z), CS(cso), FLG(0));
			c = lower;				/* Character given in lowercase */
			goto remaining;
		}
		/* FALL THROUGH -- case does not matter */
	}

	/* Case-sensitive matching */
	GEN_OP(REW_TP, X(0), Z(z), CS(cso), FLG(0));

remaining:
	re_mi_gen_constant(mig, csw, 2, n, FALSE);
	re_mi_seg_grow(text, 1);
	text->p = poke_u8(text->p, c);
	if (cso != RE_OP_CS_EMPTY)
		re_mi_gen_constant(mig, cso, 0, offset, FALSE);
}

/**
 * Matching interpreter version of re_mi_decode_inst_fast(), directly
 * updating the PC and only updating the minimal amount of information
 * in IR (the instruction register).
 *
 * This is the version used by the Matching Interpreter to fetch opcodes
 * into its IR, knowing that it already validated that the PC lied in the
 * proper range.
 *
 * Both `ir' and `pc' are l-values.
 */
#define RE_MI_LOAD_IR(ir, pc)										\
G_STMT_START {														\
	ir.ip      = pc;												\
	ir.op.code = *pc++;												\
	ir.opcode  = ir.op.u.v.op;										\
																	\
	if G_UNLIKELY(RE_OP_ESCAPE == ir.opcode) {						\
		ir.of.code  = *pc++;										\
		ir.opcode   = 16 + ir.of.v.op;								\
	}																\
} G_STMT_END

/**
 * Fast version of re_mi_decode_inst(), avoiding assertions and decoding
 * of the Z, X, CS and FLG.
 */
static inline bool G_FAST ALWAYS_INLINE
re_mi_decode_inst_fast(
	re_mi_inst_t *dest, const uint8 *end, register const uint8 *pc)
{
	RE_MI_LOAD_IR((*dest), pc);
	dest->pc = pc;
	return pc <= end;	/* We rely on the trailing margin at end of TEXT */
}

/**
 * As a convenience, decode the X, Z, CS and FLG bits in the loaded instruction.
 *
 * @param dest	the loaded Instruction Register
 *
 * @return parameter as a convenience.
 */
static const re_mi_inst_t *
re_mi_decode_inst_full(const re_mi_inst_t *dest)
{
	re_mi_inst_t *ir = deconstify_pointer(dest);

	/* Further convenience decoding */

	ir->x  = ir->op.u.v.x;
	ir->z  = ir->op.u.v.z;
	ir->cs = ir->op.u.v.cs;

	if (RE_OP_ZERO == ir->opcode)
		ir->mop = ir->op.u.m.op;
	else
		ir->mop = 0;

	if (RE_OP_INDEX == ir->opcode) {
		ir->iop = ir->op.u.i.op;
		ir->s   = ir->op.u.i.s;
	} else {
		ir->iop = 0;
		ir->s   = 0;
	}

	if (ir->opcode > RE_OP_ESCAPE)
		ir->flg = ir->of.v.flg;
	else
		ir->flg = 0;

	return ir;
}

/**
 * Decode next instruction operation.
 *
 * @param dest		where we store decoded information
 * @param text		the TEXT segment where instructions lie
 * @param pc		program counter, where instruction to decode lies
 *
 * @return TRUE if OK, FALSE if we reach the end of the segment.
 *
 * @note
 * The routine does not validate that the opcode is within range or a known
 * one, or even that its flags are consistent.
 * It simply decodes the data representing what lies ahead.
 */
static bool
re_mi_decode_inst(re_mi_inst_t *dest, const re_mi_seg_t *text, const uint8 *pc)
{
	g_assert_log(re_mi_seg_is_valid(text, pc),
		"%s(): PC=%X (max=%X)", G_STRFUNC,
		re_mi_seg_offset(text, pc), (uint) re_mi_seg_used(text) - 1);

	if (!re_mi_decode_inst_fast(dest, text->p, pc))
		return FALSE;

	re_mi_decode_inst_full(dest);
	return TRUE;
}

/**
 * Read Compact Little-Endian (CLE) value.
 *
 * @param p		the starting address in the segment
 * @param value	where read value is stored
 *
 * @return updated address following value, NULL if a fault occurred.
 */
static const uint8 *
re_mi_peek_cle(const uint8 *p, uint64 *value)
{
	uint64 v;
	re_mi_cle_t lead;

	lead.value = peek_u8(p++);

	g_assert(lead.v.length <= 8);		/* Or we're reading garbage */

	v = vlint_decode(cast_to_constpointer(p), lead.v.length);
	p += lead.v.length;

	if (lead.v.n)
		v = (uint64) -((int64) v);

	*value = v;
	return p;
}

/*
 * Inline fast version of peek_le16().
 *
 * Timing shows that calling peek_le16() is slower than doing the little-endian
 * decompilation of the constant inline.
 */
#define PEEK_LE16(x)	((x)[0] + ((x)[1] << 8))

/**
 * Fetch and decompile CS-governed value as unsigned.
 *
 * We rely on the existence of a trailing margin at the end of the TEXT
 * segment to void checks against the end of the TEXT segment, in order
 * to speed-up execution.
 *
 * @param pc	the current PC, starting address of the value
 * @param cs	the CS bits describing what to expect
 * @param len	length of bytes to expect when CS=0b00 (read as little-endian)
 * @praam value where the decompiled value is stored (0 if len=0 and CS=0b00)
 *
 * @return the new PC after the value has been read, or NULL if a fault happens.
 */
static inline uint8 * G_FAST ALWAYS_INLINE
re_mi_decode_immediate(register const uint8 *pc,
	re_op_cs_t cs, size_t len, size_t *value)
{
	switch ((re_op_cs_t) cs) {
	case RE_OP_CS_8BITS:
		*value = *pc++;
		goto done;
	case RE_OP_CS_16BITS:
		*value = PEEK_LE16(pc);
		pc += 2;
		goto done;
	case RE_OP_CS_CLE:
		{
			if (sizeof(uint64) == sizeof(size_t))
				pc = re_mi_peek_cle(pc, (uint64 *) value);
			else {
				uint64 v;
				pc = re_mi_peek_cle(pc, &v);
				*value = (size_t) v;
			}
		}
		goto done;
	case RE_OP_CS_EMPTY:
		switch (len) {
		case 4: *value = peek_le32(pc); break;
		case 2: *value = PEEK_LE16(pc); break;
		case 1: *value = *pc;           break;
		case 0: *value = 0;             break;
		default:
			s_error("%s(): unexpected len=%zu", G_STRFUNC, len);
		}
		pc += len;
		goto done;
	}

	/* FALL THROUGH -- invalid CS value */

	s_error("%s(): invalid CS value %d", G_STRFUNC, cs);

done:
	return deconstify_pointer(pc);
}

/**
 * Fast version of re_mi_jmp_offset() for the Matching Interpreter,
 * avoids extra test for NULL PC afterwards, because we can directly
 * goto the proper places from here.
 *
 * offset and pc are l-values.
 *
 * Timing shows that calling peek_le16() is slower than doing the little-endian
 * decompilation of the constant inline.
 */
#define RE_MI_JMP_OFFSET(pc, cs, offset) 							\
G_STMT_START {														\
	switch (cs) {													\
	case RE_OP_CS_EMPTY:											\
		offset = PEEK_LE16(pc); pc += 2;							\
		break;														\
	case RE_OP_CS_8BITS:											\
		offset = (int8) *pc++;										\
		break;														\
	case RE_OP_CS_16BITS:											\
		offset = (int16) PEEK_LE16(pc); pc += 2;					\
		break;														\
	default:														\
		goto illegal;												\
	}																\
} G_STMT_END

/**
 * Fetch and decompile JMP offset.
 *
 * @param pc	the starting address, to read the offset from
 * @param cs	the CS bits describing what to expect
 * @param off	whether the offset is read
 *
 * @return the new PC after the offset, NULL if a fault occurred.
 */
static inline const uint8 * G_FAST ALWAYS_INLINE
re_mi_jmp_offset(register const uint8 *pc, re_op_cs_t cs, int *off)
{
	RE_MI_JMP_OFFSET(pc, cs, *off);
	return pc;

illegal:
	*off = 0;
	return NULL;
}

/**
 * Adjust destination address for a JMP/CALL target.
 *
 * Indeed, when jumping to an address where the first instruction is going
 * to be an unconditional JMP elsewhere, it is better to adjust the actual
 * destination to that final place: this avoids an extra PC hop at runtime.
 *
 * Note that the JMP instruction we're bypassing that way may end-up never
 * being executed at all but will nonetheless remain in the TEXT segment!
 *
 * @attention
 * This hop-optimization is not done in the presence of DEBUG instructions,
 * on purpose: when monitoring execution, we want the debugging lines to be
 * emitted, so we do not want to short-circuit them by resolving past them!
 *
 * @param text		TEXT segment where `dest' lies
 * @param dest		original target destination within TEXT segment
 *
 * @return possibly adjusted destination within that TEXT segment.
 */
static uint
re_mi_gen_adjust_destination(const re_mi_seg_t *text, uint dest)
{
	int offset;
	re_mi_inst_t inst;
	const uint8 *pc;

	g_assert(re_mi_seg_is_valid_pos(text, dest));

	/* Look at the instruction at the given destination */

	pc = re_mi_seg_at(text, dest);

	if (!re_mi_decode_inst(&inst, text, pc))
		s_error("%s(): cannot decode instruction at PC=%04X", G_STRFUNC, dest);

	if (RE_OP_UJMP == inst.opcode) {
		/* This target is an unconditional JMP, compute its destination */
		pc = re_mi_jmp_offset(inst.pc, inst.cs, &offset);

		/* The JMP offset must be resolved if not absolute! */
		g_assert(implies(RE_OP_CS_EMPTY != inst.cs, offset != 0));

		dest = (RE_OP_CS_EMPTY == inst.cs) ?
			(uint) offset :							/* Absolute */
			re_mi_seg_offset(text, pc + offset);	/* Relative */

		/* Destination must remain a valid position with the TEXT segment */
		g_assert(re_mi_seg_is_valid_pos(text, dest));
	}

	return dest;
}

/*
 * Patch the CS-encoding bits of the "common architecture" instructions.
 *
 * The instruction cannot be a minimal or index operation since these
 * instruction formats do not bear any CS bits.
 *
 * @param ir	the Instruction Register
 * @param cs	new CS-encoding to use
 */
static void
re_mi_patch_inst_cs(const re_mi_inst_t *ir, re_op_cs_t cs)
{
	re_mi_opcode_t lib;		/* Lead instruction byte */

	lib.code = *ir->ip;

	g_assert(lib.u.v.op > RE_OP_INDEX);	/* Common architecture */
	g_soft_assert_log(cs != lib.u.v.cs,
		"%s(): requested CS encoding %s, instruction already uses that",
		G_STRFUNC, re_mi_cs2str(cs));

	lib.u.v.cs = cs;
	*(uint8 *) ir->ip = lib.code;	/* Patched lead byte */
}

/*
 * Patch the X of the "common architecture" instructions.
 *
 * The instruction cannot be a minimal or index operation since these
 * instruction formats do not bear any X bit.
 *
 * @param ir	the Instruction Register
 * @param cs	new CS-encoding to use
 */
static void
re_mi_patch_inst_x(const re_mi_inst_t *ir, bool x)
{
	re_mi_opcode_t lib;		/* Lead instruction byte */

	lib.code = *ir->ip;

	g_assert(lib.u.v.op > RE_OP_INDEX);	/* Common architecture */
	g_soft_assert_log(booleanize(x) != lib.u.v.x,
		"%s(): requested X=%s, instruction already uses that",
		G_STRFUNC, bool_to_string(x));

	lib.u.v.x = booleanize(x);
	*(uint8 *) ir->ip = lib.code;	/* Patched lead byte */
}

/**
 * Patch the instruction `ir' with the minimal op `repl'.
 *
 * @param ir	the Instruction Register
 * @param repl	the new instruction that must supersede `ir'
 *
 * @return TRUE if we performed patching, FALSE otherwise.
 */
static bool
re_mi_patch_inst_mop(const re_mi_inst_t *ir, const re_mi_inst_t *repl)
{
	re_mi_opcode_t lib;		/* Lead instruction byte */
	size_t len;

	g_assert(ir->opcode > RE_OP_INDEX);		/* Common architecture */
	g_assert(RE_OP_ZERO == repl->opcode);	/* Minimal opcode */

	lib.code = *ir->ip;

	g_assert(ir->opcode == lib.u.v.op);

	/*
	 * We only support patching a limited set of instructions.
	 */

	switch (ir->opcode) {
	case RE_OP_DJMP:
	case RE_OP_JMP:
		return FALSE;	/* Cannot patch conditional JMP */
	case RE_OP_UJMP:
	case RE_OP_FAIL_JMP:
		g_assert(1 == ptr_diff(ir->pc, ir->ip));	/* 1-byte opcodes */
		lib.u.m.zero = 0;
		lib.u.m.op   = repl->mop;
		goto zero_constant;
	case RE_OP_CALL:
	case RE_OP_XCALL:
		return FALSE;		/* Not needed */
	}

	s_error("%s(): cannot patch %s", G_STRFUNC, re_mi_inst_opname(ir));

zero_constant:

	*(uint8 *) ir->ip = lib.code;	/* Patched lead byte */

	switch (ir->cs) {
	case RE_OP_CS_EMPTY:
	case RE_OP_CS_16BITS: len = 2; break;
	case RE_OP_CS_8BITS:  len = 1; break;
	default:              g_assert_not_reached();
	}

	/* The `pc' field points after the instruction opcode */

	memset(deconstify_pointer(ir->pc), 0, len);

#if 0
	s_debug("%s(): patched %s with %s",
		G_STRFUNC, re_mi_inst_opname(ir), re_mi_inst_opname(repl));
#endif

	return TRUE;
}

/**
 * Hash table iterator to optimize resolved JMPs to avoid runtime hops
 * when we can statically resolve them.
 */
static void
re_mi_adjust_jmp(const void *key, void *value, void *data)
{
	const re_mi_seg_t *text = data;
	uint position = pointer_to_uint(key);
	re_op_cs_t cs = pointer_to_int(value);
	const uint8 *pc = re_mi_seg_at(text, position);
	const uint8 *dest;
	re_mi_inst_t inst, target;
	int offset, new_offset;
	size_t hops;

	re_mi_seg_check(text);

	if (!re_mi_decode_inst(&inst, text, pc)) {
		s_error("%s(): cannot decode instruction at PC=%04X",
			G_STRFUNC, position);
	}

#if 0
#define RE_DEBUG_MI_ADJUST_JUMP
#endif

#define RE_MI_MAX_HOPS	100		/* Maximum amount of hops to follow */

#ifdef RE_DEBUG_MI_ADJUST_JUMP
#define re_debug(...)	s_debug(__VA_ARGS__);
#else
#define re_debug(...)	{}
#endif

	/*
	 * Decompile instruction to determine its jump destination.
	 */

	switch (inst.opcode) {
	case RE_OP_DJMP:
		{
			size_t n;
			pc = re_mi_decode_immediate(inst.pc, inst.cs, 1, &n);
			if (inst.x) {
				offset = (int16) peek_le16(pc);
				pc += 2;
			} else {
				offset = (int8) *pc++;
			}
			dest = pc + offset;
		}
		break;
	case RE_OP_JMP:
	case RE_OP_UJMP:
	case RE_OP_FAIL_JMP:
	case RE_OP_XCALL:
	case RE_OP_CALL:
		/* We don't remember location for absolute JMP */
		g_assert(RE_OP_CS_EMPTY != inst.cs);
		pc = re_mi_jmp_offset(inst.pc, inst.cs, &offset);
		dest = pc + offset;
		break;
	default:
		s_error("%s(): unexpected instruction %s at PC=%04X",
			G_STRFUNC, re_mi_inst_opname(&inst),
			re_mi_seg_offset(text, inst.ip));
	}

	g_assert(re_mi_seg_is_valid(text, dest));

	/*
	 * Resolve the hops, iteratively following unconditional jumps.
	 */

	new_offset = offset;

	for (hops = 0; hops < RE_MI_MAX_HOPS; hops++) {
		uint d, ad;

		d  = re_mi_seg_offset(text, dest);
		ad = re_mi_gen_adjust_destination(text, d);

		if (d == ad)
			break;

		new_offset += (int) (ad - d);
		dest       += (int) (ad - d);
	}

	if G_UNLIKELY(hops == RE_MI_MAX_HOPS) {
		s_warning("%s(): infinite JMP loop starting at PC=%04X with %s?",
			G_STRFUNC, re_mi_seg_offset(text, inst.ip),
			re_mi_inst_opname(&inst));
	}

	/*
	 * Look at the instruction we are landing to.
	 */

	if (!re_mi_decode_inst(&target, text, dest)) {
		s_error("%s(): cannot decode instruction at PC=%04X",
			G_STRFUNC, re_mi_seg_offset(text, dest));
	}

	/*
	 * Regardless of whether we could resolve hops, if the final destination
	 * is a FAIL or DONE instruction, make it replace the current JMP.
	 */

	if (RE_OP_ZERO == target.opcode) {
		switch (target.mop) {
		case RE_MOP_DONE:
			if (re_mi_patch_inst_mop(&inst, &target))
				return;
			break;;
		case RE_MOP_FAIL:
			/*
			 * For FAIL, we cannot replace a FAIL_JMP instruction, since
			 * the effect of doing a FAIL_JMP jumping to a FAIL is to trigger
			 * the code after the FAIL_JMP, so we just NOP it, in order to
			 * fall through.
			 */
			if (RE_OP_FAIL_JMP == inst.opcode)
				target.mop = RE_MOP_NOP;
			if (re_mi_patch_inst_mop(&inst, &target))
				return;
			break;
		}
	}

	if (offset == new_offset)
		return;		/* No hop detected */

	if (RE_OP_DJMP == inst.opcode) {
		/* Loudly warn, but normally this should not happen */
		s_carp("%s(): not patching DJMP at PC=%04X"
			" (offset %d -> %d in %zu hop%s)",
			G_STRFUNC, re_mi_seg_offset(text, inst.ip),
			offset, new_offset, PLURAL(hops));
		return;		/* Not patching DJMP */
	}

	/*
	 * Statically resolve the hops if we can, which means patching
	 * the already generated jump offset.
	 */

	if (RE_OP_CS_8BITS == cs) {
		/* Original instruction limited to 8-bit offset */

		if (abs(new_offset) > MAX_INT_VAL(int8)) {
			s_warning("%s(): cannot adjust %s offset (%d -> %d in %zu hop%s)"
				" at PC=%04X: instruction limited to 8-bit offset",
				G_STRFUNC, re_mi_inst_opname(&inst),
				offset, new_offset, PLURAL(hops),
				re_mi_seg_offset(text, inst.ip));
		} else {
			re_debug("%s(): patching 8-bit %s offset (%d -> %d in %zu hop%s)"
				" at PC=%04X",
				G_STRFUNC, re_mi_inst_opname(&inst),
				offset, new_offset, PLURAL(hops),
				re_mi_seg_offset(text, inst.ip));

			poke_u8(deconstify_pointer(inst.pc), (uint8) new_offset);
		}
		return;
	}

	/* Original instruction allowed 16-bit offset */

	if (abs(new_offset) <= MAX_INT_VAL(int8)) {
		if (RE_OP_CS_16BITS == inst.cs) {
			/*
			 * We seem to be able to fit the offset in 8-bit,
			 * however the current offset was encoded in 16-bit
			 * in the instruction.
			 *
			 * With an 8-bit encoding, we will need to add 1 to
			 * the offset, and we need to make sure it still fits
			 * in 8-bit (note that we do not allow -128 to be
			 * coded in 8-bit format here).
			 */

			if (abs(new_offset + 1) <= MAX_INT_VAL(int8)) {
				new_offset++;	/* 8-bit offset shorted by 1 byte */
				re_debug("%s(): converting %s offset from 16-bit to 8-bit"
					" at PC=%04X",
					G_STRFUNC, re_mi_inst_opname(&inst),
					re_mi_seg_offset(text, inst.ip));
				re_mi_patch_inst_cs(&inst, RE_OP_CS_8BITS);
				poke_u8(deconstify_pointer(inst.pc), (uint8) new_offset);
				return;
			} else
				goto patch_16bit;	/* Will keep a 16-bit offset */

			re_debug("%s(): patching existing 16-bit in %s with "
				"8-bit offset (%d -> %d in %zu hop%s) at PC=%04X",
				G_STRFUNC, re_mi_inst_opname(&inst), offset, new_offset,
				PLURAL(hops), re_mi_seg_offset(text, inst.ip));
		} else {
			re_debug("%s(): patching provisioned 16-bit in %s with "
				"8-bit offset (%d -> %d in %zu hop%s) at PC=%04X",
				G_STRFUNC, re_mi_inst_opname(&inst), offset, new_offset,
				PLURAL(hops), re_mi_seg_offset(text, inst.ip));
		}
		poke_u8(deconstify_pointer(inst.pc), (uint8) new_offset);
		return;
	}

	/* We need a 16-bit offset */

	if (RE_OP_CS_8BITS == inst.cs) {
		new_offset--;	/* 16-bit offset is longer by 1 byte */
		re_debug("%s(): converting %s offset from 8-bit to 16-bit at PC=%04X",
			G_STRFUNC, re_mi_inst_opname(&inst),
			re_mi_seg_offset(text, inst.ip));
		re_mi_patch_inst_cs(&inst, RE_OP_CS_16BITS);
	}

	/* FALL THROUGH */

patch_16bit:
	re_debug("%s(): patching existing 16-bit in %s with "
		"16-bit offset (%d -> %d in %zu hop%s) at PC=%04X",
		G_STRFUNC, re_mi_inst_opname(&inst), offset, new_offset,
		PLURAL(hops), re_mi_seg_offset(text, inst.ip));

	poke_le16(deconstify_pointer(inst.pc), (uint16) new_offset);

#undef re_debug
}

/**
 * Analyze the mig->resolved table to check whether we cannot further adjust
 * the JMP offsets in case the target of these JMP is an unconditional JMP!
 */
static void
re_mi_resolve_optimize(struct re_mi_gen_ctx *mig)
{
	htable_foreach(mig->resolved, re_mi_adjust_jmp, mig->text);
}

/**
 * An element being generated.
 *
 * This allows us to trace where the element lies in the regex tree.
 */
typedef struct re_mi_element {
	const re_element_t *e;		/* The element */
	const re_elemvec_t *ev;		/* The vector where the element lies */
	size_t n;					/* The index of `e' within `ev' */
} re_mi_element_t;

static uint re_mi_generate_elemvec(
	struct re_mi_gen_ctx *mig, const re_elemvec_t *ev);

static void re_mi_generate_element(
	struct re_mi_gen_ctx *mig, const re_elemvec_t *ev, size_t n);

static uint re_mi_generate_element_once(
	struct re_mi_gen_ctx *mig, const re_element_t *e);

static void re_mi_generate_element_sub(
	struct re_mi_gen_ctx *mig, const re_element_t *e);

/**
 * Record that we're generating a forward DJMP instruction at the current
 * text position, to a destination that we do not know yet.
 *
 * When we know the destination address, we'll go back and patch the
 * placeholder 0 value that we're going to insert.  We'll also make sure
 * the delta is compatible with the distance.
 * If not, it will be a fatal error.
 *
 * The key by which we refer to this jump is the current PC (offset into
 * the text segment, since the segment can be relocated into memory as we
 * keep expanding it), which we return to the caller.
 *
 * @param mig		the generation context
 * @param z			if TRUE, jump if Z
 * @param n			the memory word we're decrementing
 * @param cs		the type of JMP offset
 *
 * @return current offset within the TEXT segment where we generate the DJMP.
 */
static uint
re_mi_generate_forward_djmp(struct re_mi_gen_ctx *mig,
	bool z, size_t n, re_op_cs_t cs)
{
	uint position;

	re_mi_gen_ctx_check(mig);
	g_assert(cs != RE_OP_CS_CLE);	/* Need to commit to a size */
	g_assert(n != 0);

	/* We record these to make sure we're not going to forget resolving them! */

	position = re_mi_generate_position(mig);

	if G_UNLIKELY(htable_contains(mig->fwd, uint_to_pointer(position)))
		s_error("%s(): already has a jump at position %04X", G_STRFUNC, position);

	htable_insert(mig->fwd, uint_to_pointer(position), int_to_pointer(cs));
	GENX(djmp, z, n, cs);

	return position;
}

/**
 * Record that we're generating a forward jump instruction at the current
 * text position, to a destination that we do not know yet.
 *
 * When we know the destination address, we'll go back and patch the
 * placeholder 0 value that we're going to insert.  We'll also make sure
 * the delta (if not an absolute jump) is compatible with the distance.
 * If not, it will be a fatal error.
 *
 * The key by which we refer to this jump is the current PC (offset into
 * the text segment, since the segment can be relocated into memory as we
 * keep expanding it), which we return to the caller.
 *
 * @param mig		the generation context
 * @param op		the JMP operation
 * @param cond		the conditional jump setting
 * @param cs		the type of JMP offset
 *
 * @return current offset within the TEXT segment where we generate the jump.
 */
static uint
re_mi_generate_push_jmp(struct re_mi_gen_ctx *mig,
	re_mi_op_t op, re_mi_jmp_cond_t cond, re_op_cs_t cs)
{
	uint position;

	re_mi_gen_ctx_check(mig);
	g_assert(cs != RE_OP_CS_CLE);	/* Need to commit to a size */
	g_assert_log(re_mi_op_is_jmp(op),
		"%s(): op=%s is not a JMP", G_STRFUNC, re_mi_op2str(op));

	/* We record these to make sure we're not going to forget resolving them! */

	position = re_mi_generate_position(mig);

	if G_UNLIKELY(htable_contains(mig->fwd, uint_to_pointer(position)))
		s_error("%s(): already has a jump at position %04X", G_STRFUNC, position);

	htable_insert(mig->fwd, uint_to_pointer(position), int_to_pointer(cs));
	re_mi_gen_jump(mig, op, cond, cs, 0);

	return position;
}

/**
 * Resolve forward JMP.
 *
 * @param ir	the IR containing the instruction we are resolving
 * @param text	the TEXT segment of that code
 * @param pc	the location where we need to write the offset
 * @param n		the length of bytes to write the offset over to
 * @param off	the offset we need to write
 */
static void
re_mi_resolve_offset(const re_mi_inst_t *ir,
	const re_mi_seg_t *text, uint8 *pc, size_t n, int off)
{
	int dest;

	g_assert(size_is_non_negative(n));
	g_assert(n >= 1);
	g_assert(re_mi_seg_is_valid(text, pc));
	g_assert(re_mi_seg_is_valid(text, const_ptr_add_offset(pc, n - 1)));

	/*
	 * Ensure `n' next bytes starting at `pc' are still zero, meaning
	 * the jump was not already resolved.  If it was, then we have a
	 * generation bug because we cannot resolve a jump twice.
	 */

	switch (n) {
	case 1: dest = (int8) peek_u8(pc);   break;
	case 2: dest = (int16) peek_le16(pc); break;
	default: g_assert_not_reached();
	}

	if G_UNLIKELY(dest != 0) {
		s_error("%s(): expected %zu zero byte%s at %04X "
			"for %s at PC=%04X: got %+d, writing %+d",
			G_STRFUNC, PLURAL(n), re_mi_seg_offset(text, pc),
			re_mi_inst_opname(ir), re_mi_seg_offset(text, ir->ip),
			dest, off);
	}

	switch (n) {
	case 1: poke_u8(pc,   (uint8)  off); break;
	case 2: poke_le16(pc, (uint16) off); break;
	default: g_assert_not_reached();
	}
}

/**
 * Update forward JMP to given destination.
 *
 * This is the routine used to resolve forward JMP (normally absolute)
 * between TEXT segments.
 *
 * @param text		TEXT segment where the JMP operation lies (origin segment)
 * @param dest_text TEXT segment where the JMP target lies
 * @param fwd		Forward table recording registered JMP in the origin segment
 * @param resolved	Resolved forward JMP (can be NULL)
 * @param position	position in the origin of the JMP operation
 * @param dest		destination for resolution
 */
static void
re_mi_generate_cross_jmp(
	const re_mi_seg_t *text,
	const re_mi_seg_t *dest_text,
	htable_t *fwd, htable_t *resolved, uint position, uint dest)
{
	re_op_cs_t cs;
	uint8 *pc;
	re_mi_inst_t inst;
	int offset;
	size_t offset_len = 0;

	g_assert(dest <= re_mi_seg_used(dest_text));	/* Within range */

	if G_UNLIKELY(!htable_contains(fwd, uint_to_pointer(position))) {
		s_error("%s(): no pending forward jump at position %04X",
			G_STRFUNC, position);
	}

	cs = pointer_to_int(htable_lookup(fwd, uint_to_pointer(position)));
	pc = re_mi_seg_at(text, position);

	/*
	 * For a relative JMP instruction, the offset we specify is the quantity
	 * that the machine interpreter will add to the current PC, after
	 * decoding the JMP and its offset, to form the destination PC.
	 *
	 * The `position' parameter gives us the start of the JMP instruction.
	 * We need to add the known amount of bytes that the instruction has
	 * to be able to determine the actual offset to use, and make sure we
	 * can encode it in the space we have!
	 */

	if (!re_mi_decode_inst(&inst, text, pc)) {
		s_error("%s(): cannot decode instruction at PC=%04X",
			G_STRFUNC, position);
	}

	/*
	 * We special-case DJMP instructions since their offsetting is
	 * particular and we need to skip the CS-encoded #n constant.
	 */

	if G_UNLIKELY(RE_OP_DJMP == inst.opcode) {
		size_t value;

		g_assert(text == dest_text);	/* No DJMP across segments */
		g_assert(re_mi_seg_is_valid(dest_text, inst.pc));

		pc = re_mi_decode_immediate(inst.pc, inst.cs, 1, &value);
		offset_len = inst.x ? 2 : 1;
		offset = dest - (re_mi_seg_offset(dest_text, pc) + offset_len);
		g_assert_log(offset >= 0,
			"%s(): offset=%d must be positive for DJMP",
			G_STRFUNC, offset);

		/* For DJMP offsets are always unsigned quantities */

		if (1 == offset_len) {
			g_assert_log(offset <= MAX_INT_VAL(uint8),
				"%s(): offset=%d", G_STRFUNC, offset);
			re_mi_resolve_offset(&inst, text, pc, 1, offset);
		} else {
			g_assert_log(offset <= MAX_INT_VAL(uint16),
				"%s(): offset=%d", G_STRFUNC, offset);

			/*
			 * If an 8-bit offset would be enough, use that and zero
			 * the next byte.  This requires patching the opcode to
			 * change its X bit as well.
			 *
			 * Note that we need to add 1 to the offset in that case
			 * since the relative jump is computed on the PC after
			 * consuming the arguments, and we have 1 byte more to
			 * consume if we only have an 8-bit offset.
			 */

			if (offset + 1 <= MAX_INT_VAL(uint8)) {
				re_mi_patch_inst_x(&inst, FALSE);
				re_mi_resolve_offset(&inst, text, pc, 1, offset);
				pc[1] = 0;			/* Unwritten jump offset -> NOP */
			} else {
				re_mi_resolve_offset(&inst, text, pc, 2, offset);
			}
		}

		goto done;
	}

	if (!re_mi_op_is_jmp(inst.opcode)) {
		s_error("%s(): not a JMP instruction at position %04X, but a %s",
			G_STRFUNC, position, re_mi_inst_opname(&inst));
	}

	/* Require that JMP address be absolute if we're crossing segments */

	g_assert(cs == inst.cs);	/* At the right instruction, properly encoded */
	g_assert(implies(text != dest_text, RE_OP_CS_EMPTY == cs));

	switch (cs) {
	case RE_OP_CS_EMPTY:  /* abosolute */ break;
	case RE_OP_CS_8BITS:  offset_len = 1; break;
	case RE_OP_CS_16BITS: offset_len = 2; break;
	case RE_OP_CS_CLE:
		g_assert_not_reached();
	}

	pc = deconstify_pointer(inst.pc);	/* Position after opcode */

	if (RE_OP_CS_EMPTY == cs) {
		g_assert(dest <= MAX_INT_VAL(uint16));
		re_mi_resolve_offset(&inst, text, pc, 2, dest);
	} else {
		g_assert(re_mi_seg_is_valid(dest_text, inst.pc));
		offset = dest - (re_mi_seg_offset(dest_text, inst.pc) + offset_len);
		g_assert(offset >= 0);	/* Resolving a forward jump */
		if (1 == offset_len) {
			g_assert_log(offset <= MAX_INT_VAL(int8),
				"%s(): offset=%d", G_STRFUNC, offset);
			re_mi_resolve_offset(&inst, text, pc, 1, offset);
		} else {
			g_assert_log(offset <= MAX_INT_VAL(int16),
				"%s(): offset=%d", G_STRFUNC, offset);
			/*
			 * If an 8-bit offset would be enough, use that and zero
			 * the next byte.  This requires patching the opcode to
			 * change its CS-encoding as well.
			 *
			 * Note that we need to add 1 to the offset in that case
			 * since the relative jump is computed on the PC after
			 * consuming the arguments, and we have 1 byte more to
			 * consume if we only have an 8-bit offset.
			 */
			if (offset + 1 <= MAX_INT_VAL(int8)) {
				re_mi_patch_inst_cs(&inst, RE_OP_CS_8BITS);
				re_mi_resolve_offset(&inst, text, pc, 1, offset + 1);
				pc[1] = 0;				/* Unwritten jump offset -> NOP */
			} else {
				re_mi_resolve_offset(&inst, text, pc, 2, offset);
			}
		}
	}

	/* FALL THROUGH */

done:
	htable_remove(fwd, uint_to_pointer(position));

	/*
	 * When `resolved' is non-NULL, remember that we resolved a CALL / JMP
	 * at this position in the TEXT segment.
	 *
	 * This will allow us to perform an extra pass later on to detect JMP
	 * to a place that also performs a JMP, so that we avoid these extra
	 * hops at runtime.
	 *
	 * It cannot happen now because the destination to which we resolved
	 * the JMP may not exist yet (the code is not yet generated at the
	 * current location), which is why it must happen afterwards.
	 *
	 * We are not remembering jumps to absolute positions though, because when
	 * they get resolved (their TEXT being appended to the main TEXT segment),
	 * we will perform this ad-hoc check, looking at whether that TEXT starts
	 * with a leading JMP, and adjusting the CALL to it.
	 */

	if (resolved != NULL && RE_OP_CS_EMPTY != cs)
		htable_insert(resolved, uint_to_pointer(position), int_to_pointer(cs));
}

/**
 * Resolve forward jump to current text position.
 *
 * We retrieve the type of offset encoding associated with the already recorded
 * position, compute the offset, make sure it fits and patch in the zero bytes
 * in the TEXT after the JMP operation.
 *
 * This is only valid for forward jumps made within the same text segment, i.e.
 * both the JMP operation and the target destination lie in the same segment,
 * which is the case for relative jumps.
 *
 * @param mig			the generation context
 * @param position		absolute TEXT position where JMP is
 */
static void
re_mi_generate_pop_jmp(struct re_mi_gen_ctx *mig, uint position)
{
	re_mi_seg_t *text = mig->text;
	uint dest = re_mi_generate_position(mig);	/* Current position */

	g_assert(dest >= position);		/* Forward jump! */

	re_mi_generate_cross_jmp(
		text, text, mig->fwd, mig->resolved, position, dest);
}

/**
 * Add jump origin to the list of jumps we can now resolve at the
 * next opcode generation.
 *
 * @param mig		the generation context
 * @param origin	the position of the JMP operation we can now resolve
 */
static void
re_mi_generate_pending_jmp(struct re_mi_gen_ctx *mig, uint origin)
{
	/* There must be a pending jump recorded at the origin */
	g_assert(htable_contains(mig->fwd, uint_to_pointer(origin)));

	mig->resolvable = pslist_prepend(mig->resolvable, uint_to_pointer(origin));
}

/**
 * Generate jump backwards, which we can easily resolve, and chose the
 * appropriate size for the offset.
 *
 * @param mig		the generation context
 * @param op		the jump instruction
 * @param cond		the conditional settings
 * @param where		position where we want to jump within the same segment
 *
 * @return the position of the generated jump instruction.
 */
static uint
re_mi_generate_back_jmp(struct re_mi_gen_ctx *mig,
	re_mi_op_t op, re_mi_jmp_cond_t cond, uint where)
{
	uint current;

	re_mi_gen_ctx_check(mig);
	g_assert_log(re_mi_op_is_jmp(op),
		"%s(): op=%s is not a JMP", G_STRFUNC, re_mi_op2str(op));

	/* We record these to make sure we're not going to forget resolving them! */

	current = re_mi_generate_position(mig);
	g_assert(where <= current);		/* Jumping backwards */

	re_mi_gen_jump(mig, op, cond, RE_OP_CS_CLE, where - current);

	return current;
}

/**
 * Generate DJMP backward, which we can easily resolve, and chose the
 * appropriate size for the offset.
 *
 * @param mig		the generation context
 * @param z			if TRUE, jump if Z
 * @param n			the memory word we decrement
 * @param where		position where we want to jump within the same segment
 */
static void
re_mi_generate_back_djmp(struct re_mi_gen_ctx *mig, bool z, size_t n, uint where)
{
	re_mi_seg_t *text = mig->text;
	re_op_cs_t ncs;
	uint current;
	int offset;
	bool x;
	uint len;

	current = re_mi_seg_used(mig->text);

	/* DJMP is a 1-byte instruction */
	STATIC_ASSERT(RE_OP_DJMP < RE_OP_ESCAPE);

	n--;								/* Encode 0-based index */
	ncs = re_mi_cs_select(n, FALSE);	/* Unsigned value */

	offset = where - current;

	/* 3 = max length of `n' (word number -> less than 2 bytes) + DJMP itself */
	if (abs(offset) > MAX_INT_VAL(int8) - 3 * (offset < 0)) {
		x = TRUE;
		len = 2;
	} else {
		x = FALSE;
		len = 1;
	}

	offset -= len;			/* Jump offset starts AFTER we read displacement */

	GEN_OP(DJMP, X(x), Z(z), CS(ncs), FLG(0));
	re_mi_gen_constant(mig, ncs, 0, n, FALSE);		/* The memory word */
	offset -= re_mi_seg_used(mig->text) - current;	/* Used by `n' + DJMP */

	if (1 == len) {
		g_assert(abs(offset) <= MAX_INT_VAL(int8));
		re_mi_seg_grow(text, 1);
		text->p = poke_u8(text->p, (uint8) offset);
	} else {
		g_assert(abs(offset) <= MAX_INT_VAL(int16));
		re_mi_seg_grow(text, 2);
		text->p = poke_le16(text->p, (uint16) offset);
	}
}

/**
 * Allocate a new repeat structure.
 */
static re_mi_repeat_t *
re_mi_repeat_allocate(void)
{
	re_mi_repeat_t *r;

	WALLOC0(r);
	r->magic  = RE_MI_REPEAT_MAGIC;
	r->size   = 1;
	r->length = BIT_ARRAY_BYTE_SIZE(r->size);
	r->words  = halloc0(r->length);
	r->saved  = halloc0(r->length);

	return r;
}

/**
 * Extends the bit array by `n' bits.
 */
static void
re_mi_repeat_extend(re_mi_repeat_t *r, size_t n)
{
	size_t new_length;

	re_mi_repeat_check(r);
	g_assert(size_is_positive(n));

	r->size += n;
	new_length = BIT_ARRAY_BYTE_SIZE(r->size);

	if G_UNLIKELY(new_length != r->length) {
		r->words = hrealloc(r->words, new_length);
		r->saved = hrealloc(r->saved, new_length);
		/* Ensure new allocated bytes at the end are zero-ed */
		memset(ptr_add_offset(r->words, r->length), 0, new_length - r->length);
		memset(ptr_add_offset(r->saved, r->length), 0, new_length - r->length);
		r->length = new_length;
	}
}

/**
 * Free the repeat structure.
 */
static void
re_mi_repeat_free(re_mi_repeat_t *r)
{
	re_mi_repeat_check(r);

	HFREE_NULL(r->words);
	HFREE_NULL(r->saved);
	r->magic = 0;
	WFREE(r);
}

/**
 * Free the repeat structure and nullify its pointer.
 */
static void
re_mi_repeat_free_null(re_mi_repeat_t **r_ptr)
{
	if (*r_ptr != NULL) {
		re_mi_repeat_t *r = *r_ptr;
		re_mi_repeat_free(r);
		*r_ptr = NULL;
	}
}

/**
 * Is tracking number `n' currently used?
 */
static bool
re_mi_generate_tracking_is_used(const struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_repeat_t *r;

	re_mi_gen_ctx_check(mig);
	re_mi_repeat_check(mig->repeats);
	g_assert(size_is_positive(n));		/* Cannot be 0 */

	r = mig->repeats;
	n--;

	g_assert(n < r->size);

	return bit_array_get(r->words, n);
}

/**
 * Release tracking number `n', its slot can be reused now.
 */
static void
re_mi_generate_tracking_release(struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_repeat_t *r;

	re_mi_gen_ctx_check(mig);
	re_mi_repeat_check(mig->repeats);
	g_assert(size_is_positive(n));		/* Cannot be 0 */

	r = mig->repeats;
	n--;					/* Actual bit number */

	g_assert(n < r->size);
	g_assert(bit_array_get(r->words, n));

	bit_array_clear(r->words, n);

	/*
	 * This check allows us to be called after having gone through
	 * re_mi_generate_tracking_keep().
	 *
	 * Indeed, we may not want to save the value of the tracking word `n'
	 * on the fail stack, yet we may wish to keep the number reserved
	 * so that sub-parts of the pattern do not reuse it, and finally
	 * release it to make it reusable once we no longer care about the
	 * value saved.
	 */

	if (bit_array_get(r->saved, n)) {
		g_assert(size_is_positive(r->active));
		bit_array_clear(r->saved, n);
		r->active--;
	}
}

/**
 * Remove tracking number `n' from the saving set, but its slot
 * is kept and cannot be reused (yet).
 *
 * It is always possible to release tracking number `n' at a later
 * time, after this routine has been called.
 */
static void
re_mi_generate_tracking_keep(struct re_mi_gen_ctx *mig, size_t n)
{
	re_mi_repeat_t *r;

	re_mi_gen_ctx_check(mig);
	re_mi_repeat_check(mig->repeats);
	g_assert(size_is_positive(n));		/* Cannot be 0 */

	r = mig->repeats;
	n--;					/* Actual bit number */

	g_assert(size_is_positive(r->active));
	g_assert(n < r->size);
	g_assert(bit_array_get(r->words, n));
	g_assert(bit_array_get(r->saved, n));

	/*
	 * Do not clear r->words since word `n' cannot be reused for now.
	 * The value of word `n' no longer needs to be saved.
	 */

	bit_array_clear(r->saved, n);
	r->active--;
}

/**
 * Generate a new tracking number (i.e. a variable index).
 *
 * Tracking numbers start at 1, to be visually appealing in dumps,
 * but internally they are used to index a reserved word array, so
 * the actual item being accessed is one less.
 *
 * @return the tracking number to use for this variable.
 */
static uint
re_mi_generate_tracking_get(struct re_mi_gen_ctx *mig)
{
	re_mi_repeat_t *r;
	size_t n;

	re_mi_gen_ctx_check(mig);

	/*
	 * THE THEORY
	 *
	 * Understanding tracking number and how they are used is essential
	 * to grasp how the code works at runtime (when the byte code gets
	 * run by the Matching Interpreter) and why the assignment logic is
	 * done that way.
	 *
	 * Let us define "closed" versus "opened" tracking first:
	 *
	 * Closed tracking is scoped to a limited portion of the pattern,
	 * whils opened tracking potentially spans for the entire remaining
	 * portion of the pattern.
	 *
	 * A fixed-count repetition is trivially scoped and therefore closed.
	 * Schematically, the byte code for X{5} is going to look like, if
	 * we get a tracking number of 1:
	 *
	 *        LOAD #1, 5		; set tracking #1 to 5 in memory
	 *   <A>: X
	 *        DEC #1			; decrement tracking #1 by 1
	 *        JMP_NZ <A>		; continue if counter did not reach 0 yet
	 *      ; continue here once X matched 5 times
	 *        ...
	 *
	 * Regardless of how X is constructed, as soon as the JMP_NZ instruction
	 * above gets skipped because we reached the end of the tracked repeat,
	 * then we don't need to access the repeat count #1.  This ID can therefore
	 * be reused if we have a subsequent repetition afterwards.
	 *
	 * The same is true for greedy repetitions, like X{0,5}:
	 *
	 *      ; simple variant used when X cannot match the empty string
	 *        LOAD #1, 5		; set tracking #1 to 5 in memory
	 *   <A>: FAIL_JMP <B>		; initially jump to <B>
	 *      ; coming back here when we pop a FAIL record
	 *        JMP <C>			; try without this last X
	 *   <B>: X
	 *        DEC #1			; decrement tracking #1 by 1
	 *        JMP_NZ <A>		; continue if not reached 0 yet
	 *      ; backtracking, or maximum repetition reached
	 *   <C> : ...
	 *
	 * The FAIL_JMP instruction works a bit like setjmp() in C: it has
	 * two outcomes:
	 *
	 * - it pushes a FAIL record on the FAIL stack, remembering the
	 *   current text position, the current PC and the current TRACK stack top,
	 *   then jumps to the specified destination (here <B>)..
	 *
	 * - when we backtrack and we pop the FAIL record from the FAIL stack,
	 *   we get back after the FAIL_JMP instruction, with the text position
	 *   reset and the TRACK stack also reset to what it was initially when
	 *   we executed FAIL_JMP.
	 *
	 * However, despite the presence of the FAIL_JMP here, the loop defined
	 * above is "closed" in the sense that, once we get to <C>, we no longer
	 * care about the value of the repeat counter at position #1: either we
	 * reached the maximum, or we're backtracking, but the execution path
	 * does not need to access the tracking information any more.
	 *
	 * Now let us examine a lazy repetition, like X{0,5}?:
	 *
	 *      ; simple variant used when X cannot match the empty string
	 *        LOAD #1, 5		; set tracking #1 to 5 in memory
	 *   <A>: FAIL_JMP <B>		; initially jump to <B>
	 *      ; coming back here when we pop the FAIL record
	 *      ; we need to match one more instance of X
	 *        X
	 *        DEC #1			; decrement tracking #1 by 1
	 *        JMP_NZ <A>		; continue if not reached 0 yet
	 *      ; maximum repetition reached
	 *   <B>: ...				; matching remaining of pattern
	 *
	 * This is completely different!
	 *
	 * This time, the lazy operator completely skips X, and we will resort
	 * to matching X once only if the remaining of the pattern does not match
	 * and we need to see whether matching X would change that outcome.
	 *
	 * But after opening the repetition with the leading TRACK instruction,
	 * we immediately jump to inspect the remaining of the pattern.  Hence:
	 *
	 * - the ID #1 cannot be reused any more by the subsequent pattern, since
	 *   when we backtrack, we would not be able to correctly repeat the
	 *   sequence.
	 * - we cannot consider the defined loop as being scoped, hence we
	 *   call it an "opened" tracking.
	 *
	 * To summarize, greedy (and fixed-count repetition) operators imply
	 * a closed tracking, whilst lazy operators imply an opened tracking.
	 *
	 * THE ALLOCATION LOGIC
	 *
	 * Each tracking number we allocate will cause a word at the top of
	 * the TRACK stack to be reserved.  This can be viewed as a global
	 * variable and the tracking number is its address.
	 *
	 * To manage the variable space, we use a bit array, each set bit in
	 * the array corresponding to a used variable.  The array is statically
	 * sized as needed, but the expectation is that the amount of tracking
	 * variables required will stay low: we only need them when we are
	 * doing a non-trivial bounded repetitions, since {0,1} or ?, * {0,} or *,
	 * {1}, naturally!,  and {1,} aka + do not require any variable loop to
	 * be used!
	 */

	r = mig->repeats;

	if G_UNLIKELY(NULL == r)
		r = mig->repeats = re_mi_repeat_allocate();

	re_mi_repeat_check(r);

	n = bit_array_first_clear(r->words, 0, r->size - 1);

	if ((size_t) -1 == n) {
		re_mi_repeat_extend(r, 1);
		n = r->size - 1;				/* Last bit we just extended */
	}

	bit_array_set(r->words, n);
	bit_array_set(r->saved, n);
	r->active++;	/* One more word allocated and active */
	n++;			/* Our numbers start at 1 viewed from the outside */

	if G_UNLIKELY(n > mig->code->tsp_words)
		mig->code->tsp_words = n;

	return n;
}

static int
re_mi_list_by_number(const void *a, const void *b)
{
	return CMP(pointer_to_ulong(a), pointer_to_ulong(b));
}

/**
 * Generates list of reserved words to persist, and compute suitable
 * CS-encoding (necessarily the same for all the words).
 *
 * @param mig		the generation context
 * @param exclude	the set of word numbers to exclude
 * @param saved		where the amount of words to be saved is returned
 * @param fcs		where the CS-encoding for the amount of words is saved
 * @param csw		where the CS-encoding for the saved words is saved
 *
 * @return NULL if there is nothing to save, a list of words to save
 * with `csw' filled with the proper CS encoding.  The list will have to
 * be freed using pslist_free().
 */
static pslist_t *
re_mi_generate_saved_word_list(struct re_mi_gen_ctx *mig,
	hset_t *exclude, size_t *saved, re_op_cs_t *fcs, re_op_cs_t *csw)
{
	pslist_t *list = NULL;
	size_t i, amount = 0, max = 0;
	re_mi_repeat_t *r = mig->repeats;

	if (NULL == r)
		return NULL;

	re_mi_repeat_check(r);

	if (0 == r->active)
		return NULL;

	for (i = 0; i < r->size; i++) {
		if (
			bit_array_get(r->saved, i) &&
			(NULL == exclude || !hset_contains(exclude, size_to_pointer(i + 1)))
		) {
			list = pslist_prepend(list, size_to_pointer(i));
			max = MAX(max, i);
			amount++;
		}
	}

	if (0 == amount)
		return NULL;

	list = pslist_sort(list, re_mi_list_by_number);	/* Nicer */

	/*
	 * We need to save some words before FAIL_JMP, compute the
	 * CS-encoding to use for all the items in the list.
	 */

	*saved = amount;
	*fcs = re_mi_cs_select(amount, FALSE);	/* Unsigned value */
	if (max <= MAX_INT_VAL(uint8))
		*csw = RE_OP_CS_8BITS;
	else
		*csw = RE_OP_CS_16BITS;

	return list;
}

/**
 * Generate instruction to save all the items in the list on the FAIL stack.
 *
 * @param mig		the generation context
 * @param op		the PUSH opcode
 * @param list		the list of words to save
 * @param amount	amount of words to save
 * @param fcs		CS-encoding to use for the amount of words
 * @param csw		CS-encoding to use for each word number
 *
 * @return position of the push instruction.
 */
static uint
re_mi_generate_fail_push_items(struct re_mi_gen_ctx *mig,
	re_mi_op_t op,
	pslist_t *list, size_t amount, re_op_cs_t fcs, re_op_cs_t csw)
{
	uint position;
	pslist_t *sl;
	size_t nwords;

	g_assert(list != NULL);
	g_assert(amount != 0);

	switch (op) {
	case RE_OP_F_PUSH_TRACK: nwords = RE_MI_FAIL_WORD_SZ;  break;
	case RE_OP_F_PUSH_GROUP: nwords = RE_MI_FAIL_GROUP_SZ; break;
	case RE_OP_F_PUSH_REF:   nwords = RE_MI_FAIL_REF_SZ;   break;
	default:
		g_assert_not_reached();
	}

	/*
	 * This is the amount of FAIL stack words we are going to use
	 * at runtime when we execute the instructions.
	 */

	mig->last_fail_jmp_words += nwords * amount;

	/*
	 * Optimize if we have one single item to push, through the versatile
	 * FAIL_OP instruction which takes only 1 byte for its opcode and uses
	 * one single immediate byte for its argument.
	 */

	if (1 == amount) {
		int cs;
		bool z = RE_OP_CS_16BITS == csw ? TRUE : FALSE;
		switch (op) {
		case RE_OP_F_PUSH_TRACK: cs = RE_MI_FAIL_OP_TRACK; break;
		case RE_OP_F_PUSH_GROUP: cs = RE_MI_FAIL_OP_GROUP; break;
		case RE_OP_F_PUSH_REF:   cs = RE_MI_FAIL_OP_REF;   break;
		default:
			g_assert_not_reached();
		}
		position = re_mi_gen_op(mig, RE_OP_FAIL_OP, X(0), Z(z), CS(cs), FLG(0));
		re_mi_gen_constant(mig, csw, 2, pointer_to_size(list->data), FALSE);
		return position;
	}

	position = re_mi_gen_op(mig, op, X(0), Z(0), CS(fcs), FLG(csw));
	re_mi_gen_constant(mig, fcs, 2, amount, FALSE);

	/* Order will be reversed for POP */

	PSLIST_FOREACH(list, sl) {
		re_mi_gen_constant(mig, csw, 2, pointer_to_size(sl->data), FALSE);
	}

	return position;
}

/**
 * Generate instruction instruction to restore all the items in the list
 * from the FAIL stack.
 *
 * @note
 * The `list' argument is freed.
 *
 * @param mig		the generation context
 * @param op		the POP opcode
 * @param list		the list of words saved (will be reversed)
 * @param amount	amount of words saved
 * @param fcs		CS-encoding to use for the amount of words
 * @param csw		CS-encoding to use for each word number
 */
static void
re_mi_generate_fail_pop_items(struct re_mi_gen_ctx *mig,
	re_mi_op_t op,
	pslist_t *list, size_t amount, re_op_cs_t fcs, re_op_cs_t csw)
{
	pslist_t *sl;

	g_assert(list != NULL);
	g_assert(amount != 0);

	/*
	 * Optimize if we have one single item to push, through the versatile
	 * FAIL_OP instruction which takes only 1 byte for its opcode and uses
	 * one single immediate byte for its argument.
	 */

	if (1 == amount) {
		int cs;
		bool z = RE_OP_CS_16BITS == csw ? TRUE : FALSE;
		switch (op) {
		case RE_OP_F_POP_TRACK: cs = RE_MI_FAIL_OP_TRACK; break;
		case RE_OP_F_POP_GROUP: cs = RE_MI_FAIL_OP_GROUP; break;
		case RE_OP_F_POP_REF:   cs = RE_MI_FAIL_OP_REF;   break;
		default:
			g_assert_not_reached();
		}
		re_mi_gen_op(mig, RE_OP_FAIL_OP, X(1), Z(z), CS(cs), FLG(0));
		re_mi_gen_constant(mig, csw, 2, pointer_to_size(list->data), FALSE);
	} else {
		re_mi_gen_op(mig, op, X(0), Z(0), CS(fcs), FLG(csw));
		re_mi_gen_constant(mig, fcs, 2, amount, FALSE);

		/* Reverse order compared to PUSH */

		list = pslist_reverse(list);

		PSLIST_FOREACH(list, sl) {
			re_mi_gen_constant(mig, csw, 2, pointer_to_size(sl->data), FALSE);
		}
	}

	pslist_free(list);
}

/**
 * Generates list of captured group positions to persist, and compute suitable
 * CS-encoding (necessarily the same for all the groups).
 *
 * @param mig		the generation context
 * @param e			the element we are repeating
 * @param saved		where the amount of groups to be saved is returned
 * @param fcs		where the CS-encoding for the amount of groups is saved
 * @param csw		where the CS-encoding for the saved groups is saved
 *
 * @return NULL if there is nothing to save, a list of groups to save
 * with `csw' filled with the proper CS encoding.  The list will have to
 * be freed using pslist_free().
 */
static pslist_t *
re_mi_generate_saved_capture_list(struct re_mi_gen_ctx *mig,
	const re_element_t *e, size_t *saved, re_op_cs_t *fcs, re_op_cs_t *csw)
{
	pslist_t *list = NULL, *sl;
	const re_mi_element_info_t *ei;
	size_t amount = 0, max = 0;

	/*
	 * If the group is of a lazy repetition type, then backtracking
	 * means we're trying to match more, not undoing extra greedy
	 * matching.  Hence for lazy repetitions, we do not need to save
	 * any captured group information since the last ones we have are
	 * always up-to-date.
	 */

	if (e->minimal)
		return NULL;

	ei = htable_lookup(mig->eleminfo, e);
	if (NULL == ei)
		return NULL;

	re_mi_element_info_check(ei);

	if (NULL == ei->groups)
		return NULL;

	list = pslist_copy(ei->groups);
	list = pslist_sort(list, re_mi_list_by_number);	/* Nicer */

	PSLIST_FOREACH(ei->groups, sl) {
		uint n = pointer_to_uint(sl->data);
		max = MAX(max, n);
		amount++;
	}

	/*
	 * We need to save some group numbers before FAIL_JMP, compute the
	 * CS-encoding to use for all the items in the list.
	 */

	*saved = amount;
	*fcs = re_mi_cs_select(amount, FALSE);	/* Unsigned value */
	if (max <= MAX_INT_VAL(uint8))
		*csw = RE_OP_CS_8BITS;
	else
		*csw = RE_OP_CS_16BITS;

	return list;
}

/**
 * Generates list of back-reference positions to persist, and compute suitable
 * CS-encoding (necessarily the same for all the references).
 *
 * @param mig		the generation context
 * @param groups	the list of capture groups
 * @param fcs		where the CS-encoding for the amount of references is saved
 * @param csw		where the CS-encoding for the saved refs is saved
 *
 * @return NULL if there is nothing to save, a list of references to save
 * with `csw' filled with the proper CS encoding.  The list will have to
 * be freed using pslist_free().
 */
static pslist_t *
re_mi_generate_saved_ref_list(struct re_mi_gen_ctx *mig,
	const pslist_t *groups, size_t *saved, re_op_cs_t *fcs, re_op_cs_t *csw)
{
	pslist_t *list = NULL;
	const pslist_t *sl;
	size_t amount = 0, max = 0;

	PSLIST_FOREACH(groups, sl) {
		uint n = pointer_to_uint(sl->data);
		uint i = re_exec_match_backref_index(mig->re, n);
		if (0 == i)
			continue;		/* Group not used as a back-reference */
		if (!htable_contains(mig->backrefs, uint_to_pointer(n)))
			continue;		/* No more usage of this back-reference */
		list = pslist_prepend(list, uint_to_pointer(i) - 1);
		max = MAX(max, i);
		amount++;
	}

	list = pslist_reverse(list);	/* For consistency with groups only */

	/*
	 * We need to save some ref numbers before FAIL_JMP, compute the
	 * CS-encoding to use for all the items in the list.
	 */

	*saved = amount;
	*fcs = re_mi_cs_select(amount, FALSE);	/* Unsigned value */
	if (max <= MAX_INT_VAL(uint8))
		*csw = RE_OP_CS_8BITS;
	else
		*csw = RE_OP_CS_16BITS;

	return list;
}

/**
 * Is element simple enough that its matching does not require recursing
 * into sub-elements (and its matching cannot involve backtracking), plus
 * its generated code is compact?
 */
static bool
re_mi_element_is_simple(const re_element_t *e)
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
	/* There are never matched as such, hence yes as well! */
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
	/* Exact tries cannot backtrack and MATCHX generates a CALL */
	case RE_TYPE_MATCHX:
		return TRUE;
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
	case RE_TYPE_OR:
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
	/*
	 * ROUTEX also uses a CALL, but it can cause backtracking and its jump
	 * table can be large, hence it fails on both counts to be qualified
	 * as "simple" here.
	 */
	case RE_TYPE_ROUTEX:
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Is element consuming text atomically, so that it can be CEX-ed?
 */
static bool
re_mi_element_is_cexable(const re_element_t *e)
{
	re_element_check(e);

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_ANY:
	case RE_TYPE_ALL:
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
	case RE_TYPE_BACKREF:
		return TRUE;
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_EMPTY:
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:
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
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return FALSE;
}

/**
 * Description of the forward / backward FAIL_JMP instruction.
 */
struct re_mi_fail_jmp {
	bool forward;				/* Is it a forward JMP? */
	union {
		re_op_cs_t cs;			/* For forward JMP, the offset encoding */
		uint dest;				/* For backward JMP, the destination */
	} u;
	hset_t *exclude;			/* Set of memory words to exclude */
};

/**
 * Generate a FAIL_JMP instruction, taking care of the extra context we
 * need to persist across the failure point (tracking variables, group
 * positions).
 *
 * The `pos' argument, if non-NULL, will be filled with the position
 * where we can JMP back to: it will usually be the FAIL_JMP instruction
 * itself, or the leading F_PUSH_TRACK of F_PUSH_GROUP if we had to save
 * some additional context.  This only matters if we have to jump back to
 * the start of a loop.
 *
 * The returned value is the position of the forward JMP that FAIL_JMP
 * is doing.  This value needs to be given to the re_mi_generate_pending_jmp()
 * routine to resolve the address of the forward JMP.
 *
 * @note
 * As a SIDE EFFECT: we update the mig->last_fail_jmp_words value with the
 * amount of additional words we are saving on the FAIL stack.  This avoids
 * making the overall FAIL_JMP generation interface more complex than it
 * already is.
 *
 * The purpose of that SIDE EFFECT is to make it possible for the generated
 * code to possibly issue a DROP_WORD instruction after a DROP_FAIL, to
 * make sure we fully clean the information pushed on the FAIL stack when
 * we decide to remove a record.
 *
 * @param mig		the generation context
 * @param e			the element we're repeating
 * @param info		the FAIL_JMP information
 * @param pos		position in the TEXT segment if we have to JMP to here
 *
 * @return position in the TEXT segment of the FAIL_JMP instruction that
 * we need to resolve later.
 */
static uint
re_mi_generate_fail_jmp(struct re_mi_gen_ctx *mig, const re_element_t *e,
	struct re_mi_fail_jmp *info, uint *pos)
{
	size_t amount = 0, ngroups = 0, nrefs = 0;
	pslist_t *list, *groups = NULL, *refs = NULL;
	re_op_cs_t fcs  = RE_OP_CS_EMPTY, csw  = RE_OP_CS_EMPTY;
	re_op_cs_t gfcs = RE_OP_CS_EMPTY, gcsw = RE_OP_CS_EMPTY;
	re_op_cs_t rfcs = RE_OP_CS_EMPTY, rcsw = RE_OP_CS_EMPTY;
	uint position = MAX_INT_VAL(uint), fail_pos = 0;

	/*
	 * Additional context to persist before the failure point
	 *
	 * If the element being repeated is atomic, then it is greedy and
	 * cannot backtrack, by definition.  Hence, it is not necessary to
	 * save any variable.
	 */

	if (e->atomic) {
		list = NULL;
	} else {
		list = re_mi_generate_saved_word_list(
			mig, info->exclude, &amount, &fcs, &csw);
	}

	/*
	 * If the element for which we are generating a FAIL_JMP is simple
	 * then we do not need to save any additional context (captured groups
	 * and back-references) since that element cannot, by definition,
	 * perform any capturing of its own matching.
	 */

	if (re_mi_element_is_simple(e))
		goto no_groups;

	groups = re_mi_generate_saved_capture_list(mig, e, &ngroups, &gfcs, &gcsw);
	refs   = re_mi_generate_saved_ref_list(mig, groups, &nrefs, &rfcs, &rcsw);

no_groups:

	/*
	 * The mig->last_fail_jmp_words variable is reset each time we issue
	 * a FAIL_JMP and will contain the amount of additional words we will
	 * push on the FAIL stack every time we execute the code at runtime.
	 */

	mig->last_fail_jmp_words = 0;

	if (list != NULL) {
		position = re_mi_generate_fail_push_items(mig,
			RE_OP_F_PUSH_TRACK, list, amount, fcs, csw);
	}

	if (groups != NULL) {
		uint gpos = re_mi_generate_fail_push_items(mig,
			RE_OP_F_PUSH_GROUP, groups, ngroups, gfcs, gcsw);
		if (MAX_INT_VAL(uint) == position)
			position = gpos;
	}

	if (refs != NULL) {
		/*
		 * If we save refs, we necessarily saved groups earlier, hence
		 * no need to update the position.
		 */
		re_mi_generate_fail_push_items(mig,
			RE_OP_F_PUSH_REF, refs, nrefs, rfcs, rcsw);
	}

	/* The FAIL_JMP instruction itself */

	if (info->forward) {
		fail_pos = re_mi_generate_push_jmp(mig,
			RE_OP_FAIL_JMP, RE_MI_JMP_ALWAYS, info->u.cs);
	} else {
		re_mi_generate_back_jmp(mig,
			RE_OP_FAIL_JMP, RE_MI_JMP_ALWAYS, info->u.dest);
	}

	/*
	 * If we did not save any value before, then the position we can
	 * jump back to is that of the FAIL_JMP instruction.
	 */

	if (MAX_INT_VAL(uint) == position)
		position = fail_pos;

	/*
	 * Additional context to retrieve after the failure point, done in
	 * reverse order compared to the initial push above.
	 */

	if (refs != NULL) {
		re_mi_generate_fail_pop_items(mig,
			RE_OP_F_POP_REF, refs, nrefs, rfcs, rcsw);
	}

	if (groups != NULL) {
		re_mi_generate_fail_pop_items(mig,
			RE_OP_F_POP_GROUP, groups, ngroups, gfcs, gcsw);
	}

	if (list != NULL) {
		re_mi_generate_fail_pop_items(mig,
			RE_OP_F_POP_TRACK, list, amount, fcs, csw);
	}

	/* Lists are freed by re_mi_generate_fail_pop_items() */

	if (pos != NULL)
		*pos = position;

	return fail_pos;
}

/**
 * Configure FAIL context information to exclude word `n' from the list
 * of saved variables.
 *
 * The `n' parameter supplies the tracking number (numbered from 1 and up)
 * of the current repetition loop we are in.  If we are not in a repetition
 * loop or if we need to save/restore the word on the FAIL stack, then use 0.
 * If non-zero, then word `n' will be excluded from the saving set, even
 * though it may be listed as a saved register.
 *
 * In all the patterns we generate today, we do not need to restore our
 * own repetition counter in the initial FAIL_JMP we use.  What matters
 * is that other FAIL_JMP will save/restore that word for us, but within
 * our loop, we are in control.
 *
 * @param info		the FAIL_JMP context information
 * @param n			the variable to exclude (0 if none)
 */
static void
re_mi_fail_exclude_n(struct re_mi_fail_jmp *info, size_t n)
{
	if (0 != n) {
		info->exclude = hset_create(HASH_KEY_SELF, 0);
		hset_insert(info->exclude, size_to_pointer(n));
	}
}

/**
 * Configure FAIL context information to exclude supplied word numbers
 * from the list of saved variables.
 *
 * @param info		the FAIL_JMP context information
 * @param list		list of word numbers to exclude
 */
static void
re_mi_fail_exclude_list(struct re_mi_fail_jmp *info, pslist_t *list)
{
	if (list != NULL) {
		pslist_t *sl;

		info->exclude = hset_create(HASH_KEY_SELF, 0);
		PSLIST_FOREACH(list, sl) {
			void *word = sl->data;	/* Word number cast to pointer */
			hset_insert(info->exclude, word);
		}
	}
}

/**
 * Cleanup dynamically allocated structure in FAIL_JMP context info.
 */
static void
re_mi_fail_cleanup(struct re_mi_fail_jmp *info)
{
	hset_free_null(&info->exclude);
}

/**
 * Generate a forward FAIL_JMP instruction, taking care of the memory
 * words we need to persist across the failure point, i.e. whose current
 * value needs to be pushed as additional context and restored when we
 * pop the failure point.
 *
 * The `n' parameter supplies the tracking number (numbered from 1 and up)
 * of the current repetition loop we are in.  If we are not in a repetition
 * loop or if we need to save/restore the word on the FAIL stack, then use 0.
 * If non-zero, then word `n' will be excluded from the saving set, even
 * though it may be listed as a saved register.
 *
 * In all the patterns we generate today, we do not need to restore our
 * own repetition counter in the initial FAIL_JMP we use.  What matters
 * is that other FAIL_JMP will save/restore that word for us, but within
 * our loop, we are in control.
 *
 * The `pos' argument, if non-NULL, will be filled with the position
 * where we can JMP back to: it will usually be the FAIL_JMP instruction
 * itself, of the leading F_PUSH_TRACK if we had to save some contextual
 * words.
 *
 * The returned value is the position of the forward JMP that FAIL_JMP
 * is doing.  This value needs to be given to the re_mi_generate_pending_jmp()
 * routine to resolve the address of the forward JMP.
 *
 * @param mig		the generation context
 * @param e			the element we're repeating
 * @param n			the current loop variable index (1-based), 0 if none
 * @param cs		the CS-encoding of the JMP offset
 * @param pos		position in the TEXT segment if we have to JMP to here
 *
 * @return position in the TEXT segment of the FAIL_JMP instruction that
 * we need to resolve later.
 */
static uint
re_mi_generate_forward_fail_jmp(struct re_mi_gen_ctx *mig,
	const re_element_t *e, size_t n, re_op_cs_t cs, uint *pos)
{
	struct re_mi_fail_jmp info;
	uint pc;

	ZERO(&info);
	info.forward = TRUE;
	info.u.cs    = cs;

	re_mi_fail_exclude_n(&info, n);
	pc = re_mi_generate_fail_jmp(mig, e, &info, pos);
	re_mi_fail_cleanup(&info);

	return pc;
}

/**
 * Generate a backward FAIL_JMP instruction, taking care of the memory
 * words we need to persist across the failure point, i.e. whose current
 * value needs to be pushed as additional context and restored when we
 * pop the failure point.
 *
 * The `n' parameter supplies the tracking number (numbered from 1 and up)
 * of the current repetition loop we are in.  If we are not in a repetition
 * loop or if we need to save/restore the word on the FAIL stack, then use 0.
 * If non-zero, then word `n' will be excluded from the saving set, even
 * though it may be listed as a saved register.
 *
 * @param mig		the generation context
 * @param e			the element we're repeating
 * @param n			the current word tracking the loop we are in, 0 if none.
 * @param dest		position in the TEXT segment where we need to jump
 */
static void
re_mi_generate_backward_fail_jmp(struct re_mi_gen_ctx *mig,
	const re_element_t *e, size_t n, uint dest)
{
	struct re_mi_fail_jmp info;

	ZERO(&info);
	info.forward = FALSE;
	info.u.dest  = dest;

	re_mi_fail_exclude_n(&info, n);
	re_mi_generate_fail_jmp(mig, e, &info, NULL);
	re_mi_fail_cleanup(&info);
}

/**
 * Generate a forward FAIL_JMP instruction, but the set of variables
 * to exclude from the context is given as a list.
 *
 * The `pos' argument, if non-NULL, will be filled with the position
 * where we can JMP back to: it will usually be the FAIL_JMP instruction
 * itself, of the leading F_PUSH_TRACK if we had to save some contextual
 * words.
 *
 * The returned value is the position of the forward JMP that FAIL_JMP
 * is doing.  This value needs to be given to the re_mi_generate_pending_jmp()
 * routine to resolve the address of the forward JMP.
 *
 * @param mig		the generation context
 * @param e			the element we're repeating
 * @param list		the list of variables to exclude, NULL if none
 * @param cs		the CS-encoding of the JMP offset
 * @param pos		position in the TEXT segment if we have to JMP to here
 *
 * @return position in the TEXT segment of the FAIL_JMP instruction that
 * we need to resolve later.
 */
static uint
re_mi_generate_forward_fail_jmp_list(struct re_mi_gen_ctx *mig,
	const re_element_t *e, pslist_t *list, re_op_cs_t cs, uint *pos)
{
	struct re_mi_fail_jmp info;
	uint pc;

	ZERO(&info);
	info.forward = TRUE;
	info.u.cs    = cs;

	re_mi_fail_exclude_list(&info, list);
	pc = re_mi_generate_fail_jmp(mig, e, &info, pos);
	re_mi_fail_cleanup(&info);

	return pc;
}

#undef F
#undef Z
#undef X
#undef CS
#undef FLG
#undef GEN_OP

/**
 * Generate tracking number for element.
 */
#define GEN_TRACK_GET_NUM() 	re_mi_generate_tracking_get(mig)
#define TRACK_RELEASE(n)		re_mi_generate_tracking_release(mig, (n))
#define TRACK_KEEP(n)			re_mi_generate_tracking_keep(mig, (n))

/**
 * Get current position in the TEXT segment.
 */
#define GEN_TEXT_POS()			re_mi_seg_used(mig->text);

/**
 * Issue a plain forward FAIL_JMP.
 *
 * This returns the location of the FAIL_JMP instruction, so that we may
 * resolve it with a GEN_TARGET_HERE().
 */
#define GEN_FAIL_JMP(cs) \
	re_mi_generate_forward_fail_jmp(mig, e, 0, RE_OP_CS_ ## cs, NULL)

#define GEN_GET_FAIL_WORDS()	(mig)->last_fail_jmp_words

/**
 * Issue a forward FAIL_JMP whilst within a loop whose index is variable #n.
 *
 * The trailing `loop' argument must be either &var or NULL, where `var'
 * is of type uint.  This is the position where we can jump back to
 * restart the loop, which may be distinct from the position where the
 * FAIL_JMP instruction is generated in case of additional context saved by
 * the F_PUSH_TRACK instructions.
 *
 * This returns the location of the FAIL_JMP instruction, so that we may
 * resolve it with a GEN_TARGET_HERE().
 */
#define GEN_TRACK_FAIL_JMP(cs, n, loop) \
	re_mi_generate_forward_fail_jmp(mig, e, (n), RE_OP_CS_ ## cs, (loop))

/**
 * Issue a forward FAIL_JMP whilst within a loop, with a list of variables
 * to exclude from the saved context.
 *
 * The trailing `loop' argument must be either &var or NULL, where `var'
 * is of type uint.  This is the position where we can jump back to
 * restart the loop, which may be distinct from the position where the
 * FAIL_JMP instruction is generated in case of additional context saved by
 * the F_PUSH_TRACK instructions.
 *
 * This returns the location of the FAIL_JMP instruction, so that we may
 * resolve it with a GEN_TARGET_HERE().
 */
#define GEN_LIST_FAIL_JMP(cs, sl, loop) \
	re_mi_generate_forward_fail_jmp_list(mig, e, (sl), RE_OP_CS_ ## cs, (loop))

/**
 * Issue a backward FAIL_JMP whilst within a loop #n.
 */
#define GEN_TRACK_BACKWARD_FAIL_JMP(n, dest) \
	re_mi_generate_backward_fail_jmp(mig, e, (n), (dest))

/**
 * Issue a forward jump, location will be declared by GEN_TARGET_HERE().
 *
 * @returns position in the TEXT segment where the jump op is written.
 */
#define GEN_FORWARD_JMP(cs) \
	re_mi_generate_push_jmp(mig, RE_OP_UJMP, RE_MI_JMP_ALWAYS, RE_OP_CS_ ## cs)

/**
 * Issue a forward DJMP if Z, location will be declared by GEN_TARGET_HERE().
 *
 * @returns position in the TEXT segment where the DJMP op is written.
 */
#define GEN_FORWARD_DJMP_Z(n, cs) \
	re_mi_generate_forward_djmp(mig, TRUE, (n), RE_OP_CS_ ## cs)

/**
 * Issue a forward DJMP if NZ, location will be declared by GEN_TARGET_HERE().
 *
 * @returns position in the TEXT segment where the DJMP op is written.
 */
#define GEN_FORWARD_DJMP_NZ(n, cs) \
	re_mi_generate_forward_djmp(mig, FALSE, (n), RE_OP_CS_ ## cs)

/**
 * Backward DJMP if Z instruction.
 */
#define GEN_BACKWARD_DJMP_Z(n, pos) \
	re_mi_generate_back_djmp(mig, TRUE, (n), (pos))

/**
 * Backward DJMP if NZ instruction.
 */
#define GEN_BACKWARD_DJMP_NZ(n, pos) \
	re_mi_generate_back_djmp(mig, FALSE, (n), (pos))

/**
 * Issue a conditional forward jump, location will be declared by
 * GEN_TARGET_HERE() later.
 *
 * @returns position in the TEXT segment where the jump op is written.
 */
#define GEN_FORWARD_IF(t, cs) \
	re_mi_generate_push_jmp(mig, RE_OP_JMP, RE_MI_JMP_ ## t, RE_OP_CS_ ## cs)

/**
 * Resolve target of forward jump identified by `pos' to the current location.
 */
#define GEN_TARGET_HERE(pos) \
	re_mi_generate_pending_jmp(mig, pos)

/**
 * Generate a back jump to position `pos' in the same TEXT segment.
 */
#define GEN_BACKWARD_JMP(pos) \
	re_mi_generate_back_jmp(mig, RE_OP_UJMP, RE_MI_JMP_ALWAYS, pos)

/**
 * Generates a conditional back jump to position `pos' in the same TEXT segment.
 */
#define GEN_BACKWARD_IF(t, pos) \
	re_mi_generate_back_jmp(mig, RE_OP_JMP, RE_MI_JMP_ ## t, pos)

/**
 * Generate the element X.
 */
#define GEN_ELEMENT(x)		re_mi_generate_element_once(mig, (x))
#define GEN_ELEMENT_N(e,i)	re_mi_generate_element(mig, (e), (i))

/**
 * Generate the element vector X
 */
#define GEN_ELEMVEC(x)	re_mi_generate_elemvec(mig, (x))

struct re_mi_element_can_backtrack_ctx {
	bool can_backtrack;
	const re_element_t *root;
};

/**
 * Is the element capable of generating FAIL points?
 *
 * @return TRUE to continue, FALSE as soon as we know it can backtrack.
 */
static bool
re_mi_element_check_backtracking(const void *data, void *udata)
{
	struct re_mi_element_can_backtrack_ctx *ctx = udata;
	const re_element_t *e = data;
	size_t min, max;

	re_element_check(e);

	if (ctx->can_backtrack)
		return FALSE;	/* Already know, stop recursing */

	if (
		RE_TYPE_OR == e->type ||
		(re_element_is_trie(e) && !re_element_is_exact_trie(e))
	) {
		ctx->can_backtrack = TRUE;
		return FALSE;	/* We know it can backtrack, stop recursing */
	}

	if (e == ctx->root)
		return TRUE;	/* At root element, inspect underneath */

	if (e->atomic)
		return FALSE;	/* Atomic elements never backtrack */

	/*
	 * Not at the root element, we need to consider repetitions.
	 *
	 * We know we are not atomic at this stage, hence if our repetition
	 * count is not constant, we'll need to push FAIL points.
	 */

	min = re_element_get_repeat_min(e);
	max = re_element_get_repeat_max(e);

	if (min != max) {
		ctx->can_backtrack = TRUE;
		return FALSE;	/* We know it can backtrack, stop recursing */
	}

	return TRUE;
}

/**
 * Check whether matching of the element can cause FAIL points to be
 * recorded, i.e. possible back-tracking.
 *
 * @param me			the element
 *
 * @return TRUE if the element can cause backtracking.
 */
static bool
re_mi_element_can_backtrack(const re_element_t *e)
{
	struct re_mi_element_can_backtrack_ctx ctx;

	/* We do not consider repetitions on the root element */

	if (re_mi_element_is_simple(e))
		return FALSE;

	ZERO(&ctx);
	ctx.root = e;

	re_foreach_element(deconstify_pointer(e),
		re_mi_element_check_backtracking, &ctx);

	return ctx.can_backtrack;
}

/**
 * Ensure that the byte-code we generate for the element will be
 * sufficiently small to be able to support a signed 8-bit relative
 * jump over it.
 *
 * We pass the generation context to be able to check whether we are
 * generating debugging instruction.
 *
 * The only simple element that can be a problem is the TEXT element,
 * since it generates a large MATCH instruction (due to following
 * immediate text bytes).
 *
 * @param mig		the generation context
 * @param e			the element
 *
 * @return TRUE if the element is small-enough to be skip its generated
 * code with an offset fitting in 7 bits.
 */
static bool
re_mi_element_is_small(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	if (mig->debug)
		return FALSE;		/* Debugging statements can be large */

	if (re_element_is_text(e)) {
		size_t len = re_element_get_minlen(e);
		return len < MAX_INT_VAL(int8) - 32;	/* Arbitrary safety room */
	} else if (re_element_is_group(e)) {
		re_elemvec_t *gev = re_element_get_sub(e);
		size_t len = 0;
		size_t i;

		/*
		 * If the group is made up of elements that are all repeated once
		 * or a fixed amount of times (no backtracking code) and are all
		 * simple, then we can probably jump over this code with a
		 * relative 7-bit jump.
		 */

		for (i = 0; i < gev->ecnt; i++) {
			const re_element_t *ge = &gev->elements[i];
			if (
				(RE_N_ONCE != ge->repeat && RE_N_COUNT != ge->repeat) ||
				!re_mi_element_is_simple(ge)
			) {
				len = SIZE_MAX;
				break;
			}
			/* Count 1 bytes for each element, plus element matching length */
			len += (1 + re_element_get_minlen(e)) * re_element_get_repeat_min(e);
			/* Adjust for classes and trie, adding 3 bytes to be safe */
			if (re_element_is_trie(e) || re_element_is_class(e))
				len += 3;
		}

		return len < MAX_INT_VAL(int8) - 32;	/* Arbitrary safety room */
	} else {
		/* All other simple elements cannot generate a large byte-code */
		return re_mi_element_is_simple(e);
	}
}

/**
 * Find next element to be matched.
 *
 * @param me		the current element
 * @param mne		if non-NULL, where next element information is returned
 * @param next		whether to follow NEXT
 *
 * @return TRUE if we found a next element (information written in `mne').
 */
static bool
re_mi_find_next_element(
	const re_mi_element_t *me, re_mi_element_t *mne, bool next)
{
	const re_elemvec_t *ev = me->ev;
	const re_element_t *e;
	size_t n = me->n + 1;

	re_elemvec_check(ev);

next:
	for (e = &ev->elements[n]; n < ev->ecnt; n++, e++) {
		switch ((re_elem_type_t) e->type) {
		case RE_TYPE_EMPTY:
		case RE_TYPE_IS_BOUNDARY:
		case RE_TYPE_NOT_BOUNDARY:
		case RE_TYPE_START:
		case RE_TYPE_END:
			continue;			/* Ignore */
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
		case RE_TYPE_OR:
		case RE_TYPE_MATCHX:
		case RE_TYPE_MATCH:
		case RE_TYPE_ROUTE:
		case RE_TYPE_ROUTEX:
		case RE_TYPE_TEXT:
		case RE_TYPE_CHAR:
		case RE_TYPE_BACKREF:
		case RE_TYPE_NOT_AHEAD:
			goto found;
		case RE_TYPE_SUB:
		case RE_TYPE_SUBN:
		case RE_TYPE_GROUP:
		case RE_TYPE_ATOMIC:
		case RE_TYPE_AHEAD:
			if (next) {
				const re_elemvec_t *next_ev = re_element_get_sub(e);
				const re_element_t *ne;		/* Next element */

				re_elemvec_check(next_ev);

				ne = &next_ev->elements[0];

				/*
				 * If we need to follow NEXT, also enter groups: we are looking
				 * for the next item that can be matched.
				 *
				 * However, if the group does not have at least one repetition,
				 * then the elements we find inside could very well end-up not
				 * matching against the text, hence there is not one single
				 * solution for the next matching element and we have to stop.
				 */

				if (0 == re_element_get_repeat_min(ne))
					goto found;

				/* OK, enter the group and continue scanning */

				ev = next_ev;
				n  = 0;

				goto next;
			}
			goto found;
		case RE_TYPE_NEXT:
			/*
			 * At the end of an element vector, we need to find the parent.
			 * We know there is no NEXT at the end of the root element vector.
			 */
			if (next) {
				const re_element_t *pe;		/* Parent element */
				const re_elemvec_t *next_ev;
				size_t next_n;

				next_ev = e->u.other->x.next.vec;
				next_n  = e->u.other->x.next.n;

				re_elemvec_check(next_ev);
				g_assert(next_n > 0);

				if (next_n >= next_ev->ecnt)
					return FALSE;		/* Nothing, this is the end! */

				pe = &next_ev->elements[next_n - 1];

				/*
				 * Only follow the NEXT element if the parent has at most
				 * one repetition.  Otherwise, the NEXT element to match
				 * could be the start of the parent again, depending on the
				 * amount of repetitions already processed, so there is not
				 * one solution for the next element.
				 */

				if (re_element_get_repeat_max(pe) > 1)
					goto found;

				/* OK, follow the NEXT pointer and continue scanning */

				ev = next_ev;
				n  = next_n;

				goto next;
			}
			goto found;
		case RE_TYPE_RETURN:
			break;	/* End of look-around assertion -> end of sub-expression */
		case RE_TYPE_MAX:
			g_assert_not_reached();
		}
	}

	return FALSE;

found:
	if (mne != NULL) {
		mne->e  = e;
		mne->n  = n;
		mne->ev = ev;
	}

	return TRUE;
}

/**
 * Find parent element.
 *
 * @param me		the current element
 * @param pe		if non-NULL, where parent element information is returned
 *
 * @return TRUE if we found a parent element (information written in `pe').
 */
static bool
re_mi_find_parent_element(const re_mi_element_t *me, re_mi_element_t *pe)
{
	const re_elemvec_t *ev = me->ev;
	const re_element_t *e;
	size_t n;

	re_elemvec_check(ev);

	for (n = me->n + 1, e = &ev->elements[n]; n < ev->ecnt; n++, e++) {
		if (RE_TYPE_NEXT == e->type) {
			ev = e->u.other->x.next.vec;
			n =  e->u.other->x.next.n;
			re_elemvec_check(ev);
			/*
			 * A NEXT element necessarily points after the parent element,
			 * and therefore its index MUST be > 0.
			 */
			g_assert(n > 0);
			goto found;
		}
	}

	return FALSE;

found:
	if (pe != NULL) {
		pe->e  = &ev->elements[n - 1];
		pe->n  = n - 1;
		pe->ev = ev;
	}

	return TRUE;
}

/**
 * Is element part of a repetition, recursively up to the root of the RE?
 *
 * @param me		the current element
 *
 * @return TRUE if any parent of the element is repeated more than once.
 */
static bool
re_mi_element_is_within_repetition(const re_mi_element_t *me)
{
	re_mi_element_t pe;		/* Parent element */
	re_mi_element_t ie;		/* Iterated-over element */

	for (ie = *me; /* TRUE */; ie = pe) {
		if (!re_mi_find_parent_element(&ie, &pe))
			return FALSE;
		if (
			re_element_get_repeat_min(pe.e) > 1 ||
			re_element_get_repeat_max(pe.e) > 1
		)
			return TRUE;
		/* Continue with parent of `pe' */
	}

	g_assert_not_reached();
}

static bool re_mi_elem_map_group(uint8 *map, const re_element_t *e);
static bool re_mi_elem_map_or(uint8 *map, const re_element_t *e);

/**
 * Fill matching map for element.
 *
 * @param map		the map to fill-in
 * @param e			the element whose matching set is of interest
 * @param first		if TRUE, only first char is needed
 *
 * @return TRUE if we support map filling for that element.
 */
static bool
re_mi_elem_map(uint8 *map, const re_element_t *e, bool first)
{
	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_ALL:             memset(map, 1, RE_ALPHABET);    break;
	case RE_TYPE_ANY:             re_elem_map_any(map);           break;
	case RE_TYPE_CLASS:
	case RE_TYPE_INV_CLASS:       re_elem_map_class(map, e);      break;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:    re_elem_map_minmax(map, e);     break;
	case RE_TYPE_D_CLASS:
	case RE_TYPE_W_CLASS:
	case RE_TYPE_S_CLASS:
	case RE_TYPE_NOT_D_CLASS:
	case RE_TYPE_NOT_W_CLASS:
	case RE_TYPE_NOT_S_CLASS:     re_elem_map_hwclass(map, e);    break;
	case RE_TYPE_POSIX_CLASS:
	case RE_TYPE_NOT_POSIX_CLASS: re_elem_map_posix(map, e);      break;
	case RE_TYPE_CHAR:            re_elem_map_char(map, e);       break;
	case RE_TYPE_IS_BOUNDARY:
	case RE_TYPE_NOT_BOUNDARY:
	case RE_TYPE_START:
	case RE_TYPE_END:
	case RE_TYPE_BACKREF:
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:       return FALSE;
	case RE_TYPE_EMPTY:
	case RE_TYPE_NEXT:
	case RE_TYPE_RETURN:          /* nothing to fill-in */        break;
	case RE_TYPE_TEXT:
		if (first)
			re_elem_map_first_text(map, e);
		else
			re_elem_map_text(map, e);
		break;
	case RE_TYPE_MATCHX:
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
	case RE_TYPE_ROUTEX:
		if (first)
			re_elem_map_first_trie(map, e);
		else
			re_elem_map_trie(map, e);

		/*
		 * If the element is a routing trie, we need to check
		 * all routed elements.
		 */

		if (re_element_is_routing_trie(e)) {
			pslist_t *values = NULL, *sl;
			trie_t *t = re_element_get_trie(e);

			if (!re_element_is_exact_trie(e))
				return FALSE;		/* Non-exact trie needs to backtrack */

			trie_foreach_value(t, re_traverse_trie_value, &values);

			PSLIST_FOREACH(values, sl) {
				re_elemvec_t *rev = sl->data;
				size_t n;

				re_elemvec_check(rev);

				for (n = 0; n < rev->ecnt; n++) {
					const re_element_t *ve = &rev->elements[n];

					if (!re_mi_elem_map(map, ve, FALSE)) {
						pslist_free(values);
						return FALSE;
					}
				}
			}

			pslist_free(values);
		}
		break;
	case RE_TYPE_SUB:
	case RE_TYPE_SUBN:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
		if (!re_mi_elem_map_group(map, e))
			return FALSE;
		break;
	case RE_TYPE_OR:
		if (!re_mi_elem_map_or(map, e))
			return FALSE;
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return TRUE;
}

/**
 * Fill matching map for element vector;
 *
 * @return TRUE if we correctly filled the vector;
 */
static bool
re_mi_elemvec_map(uint8 *map, const re_elemvec_t *ev)
{
	size_t n;

	re_elemvec_check(ev);

	for (n = 0; n < ev->ecnt; n++) {
		if (!re_mi_elem_map(map, &ev->elements[n], FALSE))
			return FALSE;
	}

	return TRUE;
}

/**
 * Fill matching map for group element.
 *
 * @return TRUE if we correctly filled a group for that element.
 */
static bool
re_mi_elem_map_group(uint8 *map, const re_element_t *e)
{
	return re_mi_elemvec_map(map, re_element_get_sub(e));
}

/**
 * Fill matching map for an OR element.
 *
 * @return TRUE if we correctly filled a group for that element.
 */
static bool
re_mi_elem_map_or(uint8 *map, const re_element_t *e)
{
	pslist_t *alt;

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		if (!re_mi_elemvec_map(map, alt->data))
			return FALSE;
	}

	return TRUE;
}

/**
 * Is the matching of the two elements overlapping?
 */
static bool
re_mi_match_overlap(const re_element_t *e1, const re_element_t *e2)
{
	uint8 m1[RE_ALPHABET];		/* Map of matching chars for e1 */
	uint8 m2[RE_ALPHABET];		/* Map of matching chars for e2 */

#if 0
#define RE_MI_MATCH_OVERLAP_DEBUG
#endif

	/*
	 * Handle the trivial cases quickly.
	 */

	if (RE_TYPE_ALL == e1->type || RE_TYPE_ALL == e2->type)
		return TRUE;	/* One of them matches everything */

	if (RE_TYPE_BACKREF == e1->type || RE_TYPE_BACKREF == e2->type)
		return TRUE;	/* Assume overlap */

	if (RE_TYPE_ANY == e1->type && RE_TYPE_ANY == e2->type)
		return TRUE;	/* Both are matching the same strings */

	if (re_element_shallow_equal(e1, e2))
		return TRUE;

	ZERO(&m1);
	ZERO(&m2);

	if (!re_mi_elem_map(m1, e1, TRUE)) return TRUE;
	if (!re_mi_elem_map(m2, e2, TRUE)) return TRUE;

	if (re_elem_map_overlap(m1, m2))
		return TRUE;

#ifdef RE_MI_MATCH_OVERLAP_DEBUG
	{
		char *i1 = h_strdup(re_elem_info(e1));
		char *i2 = h_strdup(re_elem_info(e2));

		s_debug("%s(): no overlap between %s and %s", G_STRFUNC, i1, i2);

		HFREE_NULL(i1);
		HFREE_NULL(i2);
	}
#endif

	return FALSE;
}

/**
 * Check whether the matching set of the current element overlaps with
 * the ones that follows.
 *
 * @param mce		the current element
 * @param ev		element vector where next element to check lies
 * @param n			index within vector of next element
 * @param next		whether to follow NEXT elements
 *
 * @return TRUE if we have no matching overlap.
 */
static bool
re_mi_next_element_disjoint(const re_mi_element_t *mce,
	const re_elemvec_t *ev, size_t n, bool next)
{
	const re_element_t *ce = mce->e;
	const re_element_t *e;

#if 0
#define RE_MI_DISJOINT_DEBUG
#endif

#ifdef RE_MI_DISJOINT_DEBUG
#define re_debug(...)	s_debug(__VA_ARGS__);
#else
#define re_debug(...)	{}
#endif

	re_debug("%s(): checking %s", G_STRFUNC, re_elem_info(ce));

	re_elemvec_check(ev);

	/*
	 * FIXME: revisit this algorithm.
	 *
	 * Being able to detect disjoint matches is paramount for optimizing
	 * greedy matches so that they do not consume entries in the FAIL stack,
	 * by turning them into atomic matches.
	 *
	 * Although correct, this first implementation is probably too
	 * pessimistic: it identifies coarse grain cases of disjoint matches
	 * but could be tailored to be able to process more cases, in particular
	 * in the presence of groups and OR alternatives (including tries, which
	 * are merely another representation for OR).
	 *
	 * 		--RAM, 2020-10-06
	 */

	/*
	 * Always consider a non-exact trie to be overlapping, so that
	 * we do not make it atomic, which could prevent possible matches.
	 * This is a first approximation with this algorithm which is giving
	 * correct results but is far from being optimal.
	 */

	if (re_element_is_trie(ce) && !re_element_is_exact_trie(ce))
		return FALSE;

	for (e = &ev->elements[n]; n < ev->ecnt; n++, e++) {
	again:

	re_debug("%s(): at e=%s (n=%zu in ev=%p)",
		G_STRFUNC, re_elem_info(e), n, ev);

		/*
		 * If coming back to the original element through NEXT pointer
		 * following, then declare overlapping!
		 */

		if (ce == e)
			return FALSE;

		switch ((re_elem_type_t) e->type) {
		case RE_TYPE_EMPTY:
		case RE_TYPE_IS_BOUNDARY:
		case RE_TYPE_NOT_BOUNDARY:
		case RE_TYPE_START:
		case RE_TYPE_END:
			continue;			/* Ignore */
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
		case RE_TYPE_MATCHX:
		case RE_TYPE_MATCH:
		case RE_TYPE_ROUTE:
		case RE_TYPE_ROUTEX:
		case RE_TYPE_TEXT:
		case RE_TYPE_CHAR:
			break;
		case RE_TYPE_OR:
			{
				pslist_t *alt;
				bool disjoint = TRUE;

				PSLIST_FOREACH(re_element_get_alt(e), alt) {
					const re_elemvec_t *aev = alt->data;
					re_elemvec_check(aev);
					if (!re_mi_next_element_disjoint(mce, aev, 0, FALSE)) {
						disjoint = FALSE;
						break;
					}
				}
				if (disjoint)
					goto minlen;
			}
			return FALSE;		/* Overlapping! */
		case RE_TYPE_SUB:
		case RE_TYPE_SUBN:
		case RE_TYPE_GROUP:
		case RE_TYPE_ATOMIC:
			{
				re_elemvec_t *gev = re_element_get_sub(e);
				re_elemvec_check(gev);
				if (!re_mi_next_element_disjoint(mce, gev, 0, FALSE))
					return FALSE;
			}
			goto minlen;
		case RE_TYPE_BACKREF:
			return FALSE;		/* Have to assume overlap */
		case RE_TYPE_AHEAD:
		case RE_TYPE_NOT_AHEAD:
			return FALSE;		/* For now */
		case RE_TYPE_NEXT:
			/*
			 * We follow NEXT pointers when `next' is TRUE, or when the
			 * current element vector is not the same as the initial
			 * vector (in case we are recursively processing vectors).
			 */
			if (next || ev != mce->ev) {
				ev = e->u.other->x.next.vec;
				n  = e->u.other->x.next.n;
				re_elemvec_check(ev);
				/*
				 * If the item before NEXT is an item repeated more than
				 * once, we need to make sure the current element is
				 * not overlapping with it.  Because during execution,
				 * we are going to loop back to that element.
				 *
				 * For instance, in "([a-b]+c?){2,4}", we must not
				 * optimize the "[a-b]+" into "[a-b]++ just because
				 * the item afterwards is "c?".  Looping back, we'll
				 * see that we overlap with ourselves and not wrongly
				 * optimize that.
				 */
				if (n > 0) {
					const re_element_t *pe = &ev->elements[n - 1];
					re_elemvec_t *gev = NULL;

					if (re_element_is_group(pe))
						gev = re_element_get_sub(pe);

					if (
						re_element_get_repeat_max(pe) > 1 &&
						/*
						 * If the parent is a group and the current element
						 * is the sole item of that group, then obviously
						 * we do not want to check whether it overlaps with
						 * itself since it will, and it does not matter there,
						 * as in "(x+)+y".  The group ()+ is not overlapping
						 * with "y".
						 *
						 * We know it's in the group by comparing element
						 * vector addresses.
						 *
						 * Note the magic value 2 below, since we have to
						 * account for NEXT.
						 */
						!(gev != NULL && gev == mce->ev && 2 == gev->ecnt) &&
						TRUE
						/* !re_mi_next_element_disjoint(mce, ev, n - 1, FALSE) */
					) {
						re_debug("%s(): failed check for repetition", G_STRFUNC);
						return FALSE;
					}
				}
				if (n >= ev->ecnt)
					return TRUE;	/* End of regular expression */
				e = &ev->elements[n];
				goto again;
			} else
				return TRUE;
		case RE_TYPE_RETURN:
			return TRUE;	/* End of look-around assertion -> end expression */
		case RE_TYPE_MAX:
			g_assert_not_reached();
		}

		/*
		 * Check whether this element matching range overlaps with the one
		 * from the initial element.
		 */

		if (re_mi_match_overlap(ce, e)) {
			re_debug("%s(): overlap with e=%s", G_STRFUNC, re_elem_info(e));
			return FALSE;
		}

		/* FALL THROUGH */

	minlen:
		/*
		 * If this element can match the empty string, then we need to
		 * continue with the next one.
		 */

		if (re_element_get_repeat_min(e) != 0)
			return TRUE;	/* Yes, we found a disjoint match */

		re_debug("%s(): e=%s can match empty string", G_STRFUNC, re_elem_info(e));
	}

	/* Keeping re_debug() defined for re_mi_next_is_disjoint */

	return TRUE;	/* Have to be disjoint if no more elements to check */
}

/**
 * Check whether the matching set of the current element overlaps with
 * the one that follows.
 *
 * @param me		the current element
 *
 * @return TRUE if we have no matching overlap.
 */
static bool
re_mi_next_is_disjoint(const re_mi_element_t *me)
{
	/*
	 * When a group is repeated, we must make sure it is not going to
	 * overlap with itself.  Indeed, in that case, it cannot be made
	 * atomic regardless of whatever follows.
	 *
	 * For instance, the outer group in "((?:ab|cd)[ce]?)+" has a possible
	 * overlap of [ce] with "cd", and therefore could backtrack.  Its
	 * repetition cannot be made atomic!
	 *
	 * This is complex, so for now forbid atomic optimisation of groups
	 * which hold more than one item.  The '2' is to account for the
	 * "NEXT" element at the end of the vector.
	 */

	if (re_element_is_group(me->e)) {
		re_elemvec_t *rev = re_element_get_sub(me->e);

		if (rev->ecnt >= 2) {
			re_debug("%s(): non-disjoint %s: unhandled group with %zu items",
				G_STRFUNC, re_elem_info(me->e), rev->ecnt);
			return FALSE;
		}

		/* Group with one item, probably for capturing */
	}

	re_debug("%s(): checking %s for disjoint", G_STRFUNC, re_elem_info(me->e));

	if (re_mi_next_element_disjoint(me, me->ev, me->n + 1, TRUE)) {
		re_debug("%s(): disjoint %s", G_STRFUNC, re_elem_info(me->e));
		return TRUE;
	}

	re_debug("%s(): non-disjoint %s", G_STRFUNC, re_elem_info(me->e));
	return FALSE;

#undef re_debug		/* Was defined in re_mi_next_element_disjoint() */
}

/**
 * Generate byte code for up to one repetition of given element.
 *
 * This is special-cased because it does not require a variable for
 * the loop and can therefore be used to handle X?? but also X{2,3}?,
 * the latter being generated as X{2}X??.
 */
static void
re_mi_generate_upto_1(struct re_mi_gen_ctx *mig, const re_mi_element_t *me)
{
	const re_element_t *e = me->e;
	bool atomic = e->atomic;
	bool has_next = re_mi_find_next_element(me, NULL, FALSE);
	bool is_cexable = re_mi_element_is_cexable(e);
	bool is_disjoint = !has_next || re_mi_next_is_disjoint(me);

	GENX(debug,
		str_smsg("at most 1 (%s mode) for %s",
			e->minimal ? "lazy" :
			e->atomic ?  "atomic" : "greedy",
			re_elem_info(e))
	);

	if (e->minimal && !has_next) {
		/*
		 * If nothing follows and we have to minimally match, then there is
		 * no need to match anything in order to succeed!
		 *
		 * Likewise, if there is no commonality with the matching of this
		 * element and the next (disjoint matches), then if we match what
		 * follows, there will be no use backtracking to attempt to perform
		 * a lazy match.
		 */

		GENX(debug, "trailing lazy match dropped");
		return;
	}

	if (is_cexable && is_disjoint && !e->minimal) {
		/*
		 * It is efficient to turn a greedy match into an atomic one when
		 * the element is CEX-able!
		 */

		if (!atomic) {
			atomic = TRUE;
			GENX(debug, str_smsg("%s greedy match made atomic",
				has_next ? "disjoint" : "trailing"));
		}
	} else if (atomic && !has_next) {
		/*
		 * Contrary to unbound greedy matches, there is no particular
		 * advantage turning a trailing (non CEX-able) X optional match (X?)
		 * into an atomic one (X?+).
		 *
		 * Quite the contrary in fact, we are better off turning a trailing
		 * atomic match into a greedy one.  At worse this avoids extra PUSH_FSP
		 * and POP_FSP instructions, and at best it prevents the final DROP_FAIL.
		 */

		atomic = FALSE;
		GENX(debug, "trailing atomic match made greedy");
	} else if (!atomic && has_next && is_disjoint) {
		atomic = TRUE;
		GENX(debug, "internal disjoint greedy match made atomic");
	}

	if (e->minimal) {
		uint a;

		/*
		 * Lazy repetition: X??
		 *
		 *      FAIL_JMP <A>	; first attempt will try without X
		 *      X				; match X if we backtracked
		 * <A>: ...				; matching remaining
		 */

		/*
		 * We don't know the exact size of X, use a 2-byte relative offset.
		 * However, if X is simple, an 8-bit offset will be sufficient.
		 * If not sufficient, this will cause a crash when we resolve the
		 * jump.
		 */

		if (re_mi_element_is_small(mig, e))
			a = GEN_FAIL_JMP(8BITS);			/* FAIL_JMP <A> */
		else
			a = GEN_FAIL_JMP(16BITS);			/* FAIL_JMP <A> */
		GEN_ELEMENT(e);							/* X */
		GEN_TARGET_HERE(a);						/* <A>: */
	} else if (!atomic) {
		uint a, b;

		/*
		 * Greedy repetition: X?, non atomic (can backtrack)
		 *
		 *      FAIL_JMP <A>
		 *      JMP <B>			; backtracking, try without X
		 * <A>: X				; match X
		 * <B>:	...				; matching remaining
		 */

		a = GEN_FAIL_JMP(8BITS);				/* FAIL_JMP <A> */
		if (re_mi_element_is_small(mig, e))
			b = GEN_FORWARD_JMP(8BITS);			/* JMP <B> */
		else
			b = GEN_FORWARD_JMP(16BITS);		/* JMP <B> */
		GEN_TARGET_HERE(a);						/* <A>: */
		GEN_ELEMENT(e);							/* X */
		GEN_TARGET_HERE(b);						/* <B>: */
	} else {
		uint a, b, n;

		/*
		 * Greedy repetition: X?+, atomic (keep if matched).
		 *
		 *      FAIL_JMP <A>
		 *      JMP <B>			; X did not match!
		 * <A>:
		 *    [ PUSH_FSP ]		; if X can backtrack, remember current FSP
		 *      X				; match X
		 *    [ POP_FSP ]		; this suppresses all X's backtracking
		 *      DROP_FAIL		; we will not backtrack now that X matched
		 * <B>:	...				; matching remaining
		 *
		 * If X matches, we remove any fail point the code for X could have
		 * generated.  This is only done when the element can backtrack.
		 *
		 * When X is CEX-able, i.e. it is matching a plain text item,
		 * then it is a perfect candidate for a CEX protection, avoiding
		 * the need to register a FAIL point that we will probably drop:
		 *
		 *      CEX				; set C, guard execution of next instruction
		 *      X				; try matching X, do not fail if we cannot
		 *
		 * Very efficient and compact way to specify an atomic optional match!
		 */

		if (re_mi_element_is_cexable(e)) {
			GEN(cex);							/* CEX */
			GEN_ELEMENT(e);						/* X */
			return;
		}

		a = GEN_FAIL_JMP(8BITS);				/* FAIL_JMP <A> */
		n = GEN_GET_FAIL_WORDS();

		if (re_mi_element_is_small(mig, e))
			b = GEN_FORWARD_JMP(8BITS);			/* JMP <B> */
		else
			b = GEN_FORWARD_JMP(16BITS);		/* JMP <B> */
		GEN_TARGET_HERE(a);						/* <A>: */

		if (!re_mi_element_can_backtrack(e)) {
			GEN_ELEMENT(e);						/* X */
		} else {
			GEN(push_fsp);
			GEN_ELEMENT(e);						/* X */
			GEN(pop_fsp);
		}

		GENX(drop_fail, n);						/* DROP_FAIL */
		GEN_TARGET_HERE(b);						/* <B>: */
	}
}

/**
 * Generate byte code for the given element, with max amount of repetitions
 * (possibly unbounded), and an optional first mandatory repetition.
 *
 * If max is SIZE_MAX, then repetitions are unlimited.
 *
 * @param mig		the generation context
 * @param e			the element to generate
 * @param max		amount of repetitions to monitor
 * @param first		if TRUE, we need a first element match
 */
static void
re_mi_generate_upto(struct re_mi_gen_ctx *mig, const re_mi_element_t *me,
	size_t max, bool first)
{
	const re_element_t *e = me->e;
	size_t minlen = re_element_get_minlen(e);
	uint f = 0;
	bool atomic = e->atomic;
	bool has_next = re_mi_find_next_element(me, NULL, FALSE);
	bool is_disjoint = !has_next || re_mi_next_is_disjoint(me);

	if (1 == max && !first) {
		/* Since this does not require any loop, specialize it */
		re_mi_generate_upto_1(mig, me);
		return;
	}

	GENX(debug,
		str_smsg("%s%s matches (%s mode) for %s",
			SIZE_MAX == max ? "" : "up to ",
			SIZE_MAX == max ? "unlimited" : size_t_to_string(max),
			e->minimal ? "lazy" :
			e->atomic ?  "atomic" : "greedy",
			re_elem_info(e))
	);

	if (first) {
		if (max != SIZE_MAX) {
			max++;
			GENX(debug, str_smsg("max increased by one to %zu", max));
		} else {
			GENX(debug, "infinite repetition, no adjustment");
		}
	}

	/*
	 * If the element is not atomic, look whether we have something
	 * afterwards.
	 */

	if (!atomic && is_disjoint) {
		if (e->minimal) {
			re_mi_element_t mne;

			/*
			 * If nothing follows and we have to minimally match, then there is
			 * no need to match anything in order to succeed!
			 */

			if (!first && !has_next) {
				GENX(debug, "trailing lazy match dropped");
				return;
			}

			/*
			 * If disjoint, there is no harm attempting to match this
			 * atomically when it cannot prevent further matching
			 * by the next element.
			 *
			 * We use re_mi_find_next_element() to look at the next
			 * item in the same element vector as the current element.
			 */

			if (
				re_mi_find_next_element(me, &mne, FALSE) &&
				RE_TYPE_NEXT != mne.e->type &&
				!re_mi_match_overlap(me->e, mne.e)
			) {
				GENX(debug, "lazy disjoint match made atomic");
				atomic = TRUE;
			}
		} else if (has_next || re_mi_element_is_cexable(e)) {
			/*
			 * Must be greedy then, but we can turn the element into an
			 * atomic match since it is disjoint.
			 */

			atomic = TRUE;

			GENX(debug, str_smsg("%s greedy match made atomic",
				has_next ? "disjoint" : "trailing"));
		}
	}

	/*
	 * If we have to track the maximum amount of repetitions, we just
	 * need to add a leading LOAD instruction.
	 *
	 * If we have unbound repetition (no LOAD), then we do not need
	 * the DEC at the end and the final JMP_NZ becomes a plain JMP
	 * since we do not have to test for us having reached the maximum
	 * amount of repetitions.
	 *
	 * When X can match the empty string, we have to monitor text pointer
	 * progress.  So instead of just saying:
	 *
	 *      X				; match X once more
	 *
	 * we have to generate instead:
	 *
	 *      SAVE_TP	#n		; save the text pointer in word `n'
	 *      X				; match X once more
	 *      CMP_TP #n		; compare current TP with saved one, sets Z
	 *    ; stop if no progress by triggering failure so that
	 *    ; we come back to the previous FAIL point
	 *      JMP_Z <exit>	; stop repeating if no change
	 *
	 * To make comments below less verbose, this additional code is not
	 * mentioned in the templates.
	 */

	if (e->minimal && !atomic) {
		uint a, b, c, n = 0, t = 0;

		/*
		 * Lazy repetition: X*?, non atomic (can backtrack)
		 */

		if (0 == minlen) {
			GENX(debug, "lazy matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("lazy, min match: %zu byte%s", PLURAL(minlen)));
		}

		/*
		 * General code pattern for lazy matching is:
		 *
		 *    [ LOAD #n, max ]	; create tracking on the TRACK stack
		 * <A>: FAIL_JMP <B>	; try to not match since lazy
		 *    ; coming back here due to matching failure
		 *      X				; have to match once more then
		 *    [ DEC #n ]		; and hope it's the last time we loop
		 *    JMP_NZ <A>		; plain JMP if no DEC
		 *    ; continue if we repeated X the maximum amount of time
		 *    ; (this does not leave any backtracking point)
		 * <B>: ...				; matching remaining
		 */

		if (SIZE_MAX != max) {
			n = GEN_TRACK_GET_NUM();
			GENX(load, n, max);					/* [ LOAD #n, max ] */
		}

		if (first) {
			GENX(debug, "first repetition enforced here");
			f = GEN_FORWARD_JMP(8BITS);		/* We expect a small jump */
		}

		/*
		 * If X is shallow, then the leading FAIL_JMP offset can
		 * be safely limited to 8-bits.
		 *
		 * This voids executing a NOP when we backtrack (due to the
		 * reserved byte that never gets used by the resolved 8-bit
		 * jump when code is small-enough).
		 */

		if (re_mi_element_is_small(mig, e))		/* <A>: FAIL_JMP <B> */
			a = GEN_TRACK_FAIL_JMP(8BITS, n, &b);
		else
			a = GEN_TRACK_FAIL_JMP(16BITS, n, &b);
		if (first)
			GEN_TARGET_HERE(f);					/* Entry for 1st repetition */
		if (0 == minlen) {
			t = GEN_TRACK_GET_NUM();
			GENX(save_tp, t);					/* SAVE_TP #t */
			/*
			 * Because this is an open repeat, cannot release the word `t'
			 * (used for tracking text when minlen is 0) either.
			 */
			TRACK_KEEP(t);						/* (permanent variable) */
		}
		GEN_ELEMENT(e);							/* X */
		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			c = GEN_FORWARD_IF(Z, 8BITS);		/* JMP_Z <B> */
		}
		GENX(debug,
			str_smsg("looping for lazy %s", re_elem_info(e)));
		if (SIZE_MAX == max) {
			GEN_BACKWARD_JMP(b);				/* JMP <A> */
		} else {
			/* Instead of "DEC #n; JMP_NZ <A>", use "DJMP_NZ, #n, <A>" */
			GEN_BACKWARD_DJMP_NZ(n, b);			/* DJMP_NZ #n, <A> */
			/*
			 * Not releasing counter variable, only stopping its saving now
			 * that we're out of the loop.
			 */
			TRACK_KEEP(n);
		}
		GEN_TARGET_HERE(a);						/* <B>: */
		if (0 == minlen)
			GEN_TARGET_HERE(c);					/* <B>: */
	} else if (!atomic) {
		uint a, b, c, n = 0, t = 0;

		/*
		 * Greedy repetition: X*, non atomic (can backtrack)
		 */

		if (0 == minlen) {
			GENX(debug, "greedy matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("greedy, min match: %zu byte%s", PLURAL(minlen)));
		}

		/*
		 * General pattern for greedy matching is:
		 *
		 *    [ LOAD #n, max ]	; create tracking on the TRACK stack
		 *      JMP <B>
		 * <A>: X				; match X one more time
		 *    [ DEC #n ]		; loop while we match until maximum
		 *    [ JMP_Z <C> ]		; nothing if no repeat
		 * <B>: FAIL_JMP <A>	; try to match as much as possible
		 *    ; backtracking or maximum reached
		 * <C>: ...				; matching remaining
		 *
		 * The:
		 *      DEC #n
		 *      JMP_Z <C>
		 * sequence is always implemented as DJMP_Z #n <A>, because
		 * the DJMP instruction is more efficient: we need just one
		 * instruction decoding to perform all operations: the decrement,
		 * the test against the limit and the jump if needed.
		 *
		 * In case we need a first match, we just need to fall though:
		 * we simply skip the leading JMP <B>. Hence we special-case
		 * the + repetitions in re_mi_generate_repeated() when we have
		 * a greedy match.
		 *
		 * When repeating a simple element, the above pattern is pushing
		 * a FAIL point for every character we have to match, which is
		 * going to be inefficient at runtime and can cause a FAIL stack
		 * overflow if we have a long sequence to repeat and a long text
		 * to match against it.
		 *
		 * Therefore, an alternate pattern is used to match elements
		 * for which we have a non-zero fixed matching length 'L' (the
		 * element does not have to be simple) and for which repetition
		 * is potentially infinite (no stated maximum).
		 *
		 * 1- When X cannot backtrack, the code is straightforward:
		 *
		 *      F_PUSH_TRACK #t	; save previous value of word #t
		 *      SAVE_TP #t		; must remember where we start in text
		 *    ; if we have a first match then...
		 *      ADD #t, L		; update word #t by adding L to it
		 *    ; end if
		 *      FAIL_JMP <A>	; try to match as much as possible
		 *    ; comes here on first matching failure, TP points to last match
		 *    ; first check whether we have backtracked to origin
		 * <C>: LT_TP #t		; is TP < word #t?
		 *      JMP_NZ <D>		; continue if at or after initial TP
		 *      F_POP_TRACK #t	; restore previous value of word #t
		 *      FAIL			; trigger matching failure
		 * <D>: FAIL_JMP <B>	; and try to match remaining with one less X
		 *    ; comes here on subsequent matching failure
		 *      SUB_TP L		; decrease TP by L
		 *      JMP <C>
		 *    ; this matching loop does not push a FAIL point for every X
		 *    ; instead, it updates the only FAIL point after each match
		 * <A>: X				; match X one more time
		 *      UPDATE_TP		; update TP entry in the push FAIL context
		 *      JMP <A>			; match as much as possible
		 *    ; backtracking or maximum reached
		 * <B>: ...				; matching remaining
		 *
		 * When there is a repetition count, the final repetition loop
		 * at <A> becomes:
		 *
		 * <A>: X				; match X one more time
		 *      UPDATE_TP		; update TP entry in the push FAIL context
		 *      DJMP_NZ #n <A>	; match as much as possible
		 *      FAIL			; get rid of first FAIL point
		 *    ; backtracking or maximum reached
		 * <B>: ...				; matching remaining
		 *
		 * The last FAIL instruction can be surprising, but it is there
		 * to forcefully trigger the first FAIL point when the maximum
		 * is reached, so that we jump directly to the second FAIL point
		 * in case of further matching failure down the chain, where we
		 * will start backtracking by L characters in the text.
		 *
		 * The downside for having one single FAIL point there is that
		 * we must allocate the tracking word #t and never release it
		 * since we can come back to the FAIL point at any time!
		 *
		 * 2- When X can backtrack, the code becomes more complex but this
		 * is the price to pay for wishing to keep one single FAIL point
		 * for the repetition, regardless of how may times we match X.
		 *
		 * Indeed, if X can backtrack, we need to be able to do two things
		 * that were not required in 1- when X cannot backtrack:
		 *
		 * a- we need to access the FAIL record we installed, to update
		 *    the TP pointer held inside it.  Hence we cannot use UPDATE_TP
		 *    since that would only quickly update the latest fail point on
		 *    the fail stack.
		 *
		 * b- when there is a repetition count, we cannot use FAIL at the
		 *    end to trigger the first FAIL_JMP we installed and move to
		 *    the second, since X can have installed its own FAIL points.
		 *
		 * For (a), we'll need two special instructions: SAVE_FSP #f, which
		 * will save the FSP into a variable #f, and then we can use the
		 * UPDATE_FTP #f special instruction to use the content of #f as
		 * its base for accessing the TP record, not the FSP register.
		 * This will be slower at runtime.
		 *
		 * For (b), we'll need yet another instruction, UPDATE_FPC #f, in
		 * order to be able to change the return PC of the fail point
		 * to go to the place where we do SUB_TP (the second FAIL point).
		 * This will be used instead of the tailing FAIL.
		 *
		 *      F_PUSH_TRACK #t	; save previous value of word #t
		 *      SAVE_TP #t		; must remember where we start in text
		 *    ; if we have a first match then...
		 *      ADD #t, L		; update word #t by adding L to it
		 *    ; end if
		 *      FAIL_JMP <R>	; try to match as much as possible
		 *    ; comes here on first matching failure, TP points to last match
		 *    ; first check whether we have backtracked to origin
		 * <C>: LT_TP #t		; is TP < word #t?
		 *      JMP_NZ <D>		; continue if at or after initial TP
		 *      F_POP_TRACK #t	; restore previous value of word #t
		 *      FAIL			; trigger matching failure
		 * <D>: FAIL_JMP <B>	; and try to match remaining with one less X
		 *    ; comes here on subsequent matching failure
		 * <T>: SUB_TP L		; decrease TP by L
		 *      JMP <C>
		 *    ; the first FAIL point above comes here so that we can save
		 *    ; the current FSP register into (permanent) variable #f
		 * <R>: SAVE_FSP #f		; capture FSP value for the initial FAIL point
		 *    ; this matching loop does not push a FAIL point for every X
		 *    ; instead, it updates the only FAIL point after each match
		 * <A>: X				; match X one more time
		 *      UPDATE_FTP #f	; update TP entry in the push FAIL context
		 *      DJMP_NZ #n <A>	; match as much as possible
		 *    ; get rid of the first FAIL point now that we matched all we can
		 *      UPDATE_FPC #f, <T>
		 *    ; backtracking or maximum reached
		 * <B>: ...				; matching remaining
		 *
		 * Note that backtracking X of constant matching length L is rarely
		 * seen: it requires an alternative not optimized into a TRIE match,
		 * in other words a non-optimized regular expression.
		 */

		if (
			minlen > 0 &&
			minlen == re_element_get_maxlen(e) &&
			max >= RE_MI_FAIL_MIN	/* Minimum amount to amortize setup */
		) {
			uint r = 0;
			bool can_backtrack = re_mi_element_can_backtrack(e);
			bool is_simple = re_mi_element_is_simple(e);
			bool is_cexable = re_mi_element_is_cexable(e);
			bool within_repeat = re_mi_element_is_within_repetition(me);

			/* We are only using one single FAIL point at a time */
			GENX(debug,
				str_smsg("using single FAIL point%s",
					within_repeat ? " (with parent repetition)" : ""));
			GENX(debug,
				str_smsg("item can%s backtrack", can_backtrack ? "" : "not"));

			g_assert(implies(is_cexable, !can_backtrack && is_simple));

			if (SIZE_MAX != max && !is_cexable) {
				n = GEN_TRACK_GET_NUM();
				GENX(load, n, max);				/* [ LOAD #n, max ] */
			}

			t = GEN_TRACK_GET_NUM();
			TRACK_KEEP(t);		/* Not saved, but remains allocated */

			if (can_backtrack) {
				f = GEN_TRACK_GET_NUM();
				TRACK_KEEP(f);	/* Not saved, but remains allocated */
			}

			if (is_simple && first)
				GEN_ELEMENT(e);				/* X */

			/*
			 * We need to save the previous value of word #t, and it
			 * will be restored before the explicit FAIL below whenever
			 * we are enclosed in a repetition (since this code could
			 * be re-entered as part of our own backtracking).
			 */

			if (within_repeat)
				GENX(f_push_track, t);			/* F_PUSH_TRACK #t */
			GENX(save_tp, t);					/* SAVE_TP #t */

			if (!is_simple) {
				/*
				 * Adjusting the starting TP, by offsetting it ahead with
				 * L bytes, is what will allow us to make sure we have
				 * matched at least once (since matching length of X is L).
				 */
				if (first)
					GENX(add, t, minlen);		/* ADD #t, L */
			}

			/*
			 * First FAIL point is needed to launch the greedy
			 * match and it will be always triggered (either by a matching
			 * failure or by an explicit FAIL instruction).
			 */

			a = GEN_TRACK_FAIL_JMP(8BITS, n, NULL);	/* FAIL_JMP <A> */
			GENX(debug, "back after first FAIL point");

			GENX(lt_tp, t);						/* LT_TP #t */
			c = GEN_FORWARD_IF(NZ, 8BITS);		/* JMP_NZ <D>*/
			GEN(fail);							/* FAIL */

			GEN_TARGET_HERE(c);					/* <D>: */
			GENX(debug, "got at least one match");

			/*
			 * Second FAIL point, used to control backtracking.
			 * It is installed once we are done with our greedy
			 * match and start matching the remaining of the pattern.
			 *
			 * Subsequent matching failures will come back here
			 * to decrease the text pointer (TP) by L (the length of
			 * the item we are matching) and re-attempt matching
			 * the remaining, until we come back before the place we
			 * started at which point we will explicitly declare
			 * a failure since the pattern downstream does not lead
			 * to a match.
			 */

			/* This place only used when item can backtrack */
			r = GEN_TEXT_POS();					/* <T>: */

			if (re_mi_element_is_small(mig, e) && !mig->debug)
				b = GEN_FAIL_JMP(8BITS);		/* FAIL_JMP <B> */
			else
				b = GEN_FAIL_JMP(16BITS);		/* FAIL_JMP <B> */

			GENX(debug,
				str_smsg("backracking %zu byte%s", PLURAL(minlen))
			);

			/*
			 * If we are matching items whose minlen is 1, and we have a
			 * next element following immediately which is a text or a
			 * character with at least one repetition, then we can use
			 * the REW_TP instruction to backtrack efficiently.
			 */

			if (1 == minlen) {
				re_mi_element_t mne;

				if (re_mi_find_next_element(me, &mne, TRUE)) {
					const re_element_t *ne = mne.e;
					uchar constraint = '\0';
					size_t off = 0;

					if (
						re_element_get_repeat_min(ne) >= 1 &&
						re_element_is_text(ne)
					) {
						const char *text = re_element_get_text(ne);
						off = re_rarest_char_offset(text);
						constraint = text[off];
					} else if (
						re_element_get_repeat_min(ne) >= 1 &&
						re_element_is_char(ne)
					) {
						constraint = (uchar) re_element_get_char(ne);
					}

					if (constraint != '\0') {
						/* REW_TP #t */
						GENX(rew_tp, t, constraint, off, ne->icase);
						GEN_BACKWARD_IF(Z, r);	/* JMP_Z <T> */
						goto backtracking_failed;
					}
				}
			}

			/* Sub-optimal slow rewinding of TP */

			GENX(sub_tp, minlen);				/* SUB_TP L */
			GENX(lt_tp, t);						/* LT_TP #t */
			GEN_BACKWARD_IF(NZ, r);				/* JMP_NZ <T> */

		backtracking_failed:

			if (within_repeat)
				GENX(f_pop_track, t);			/* F_POP_TRACK #t */
			GENX(debug, "no match!");
			GEN(fail);							/* FAIL */

			/*
			 * From here on, execution path no longer uses `n'.
			 * Releasing it prevents FAIL_JMP below from saving it.
			 * It is used below, but the execution path jumps from
			 * above to the DJMP_NZ below.  One can check that when the
			 * PC reaches this current execution point, `n' will no
			 * longer be accessed.
			 */

			if (SIZE_MAX != max && !is_cexable)
				TRACK_RELEASE(n);

			GEN_TARGET_HERE(a);					/* <A>: */

			/*
			 * The repetition loop can be optimized for CEX-able elements
			 * by letting the Machine Interpreter loop on the instruction.
			 * We do not use CEX but REPEAT here though.
			 *
			 * Note that for infinite repeats, we can pass SIZE_MAX to
			 * the instruction and 0 will be generated.
			 */

			if (is_cexable) {
				GENX(repeat, /* CEX = */ TRUE, max);
				GEN_ELEMENT(e);						/* X */
				GENX(debug, "saving text pointer reached in FAIL point");
				GEN(update_tp);						/* UPDATE_TP */
				/* Get rid of the first FAIL point */
				GENX(debug, "get rid of first FAIL point");
				GEN(fail);							/* FAIL */
			} else {
				if (can_backtrack) {
					GENX(save_fsp, f);				/* <R>: SAVE_FSP #f */
					a = GEN_ELEMENT(e);				/* <A>: X */
					GENX(update_ftp, f);			/* UPDATE_FTP #f */
				} else {
					a = GEN_ELEMENT(e);				/* X */
					GEN(update_tp);					/* UPDATE_TP */
				}
				if (SIZE_MAX != max) {
					GEN_BACKWARD_DJMP_NZ(n, a);		/* DEC #n; JMP_NZ <A> */
					/* Get rid of the first FAIL point */
					GENX(debug, "get rid of first FAIL point");
					if (can_backtrack)
						GENX(update_fpc, f, r);		/* UPDATE_FPC, #f, <T> */
					else
						GEN(fail);					/* FAIL */
				} else {
					GEN_BACKWARD_JMP(a);			/* JMP <A> */
				}
			}
			GEN_TARGET_HERE(b);					/* <B>: */
			return;
		}

		/*
		 * Here we are generating one FAIL point per X matching,
		 * up to the point where a matching failure occurs and
		 * we start backtracking.
		 */

		if (SIZE_MAX != max) {
			n = GEN_TRACK_GET_NUM();
			GENX(load, n, max);					/* [ LOAD #n, max ] */
		}

		if (first)
			GENX(debug, "first repetition by falling through");
		else if (re_mi_element_is_small(mig, e))
			f = GEN_FORWARD_JMP(8BITS);			/* JMP <B> */
		else
			f = GEN_FORWARD_JMP(16BITS);		/* JMP <B> */

		a = GEN_TEXT_POS();						/* <A>: */

		if (0 == minlen) {
			t = GEN_TRACK_GET_NUM();
			GENX(save_tp, t);					/* SAVE_TP #t */
		}
		GEN_ELEMENT(e);							/* X */
		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			TRACK_RELEASE(t);					/* (element generated now) */
			c = GEN_FORWARD_IF(Z, 8BITS);		/* JMP_Z <C>*/
		}
		GENX(debug,
			str_smsg("looping for greedy %s", re_elem_info(e)));
		if (SIZE_MAX != max) {
			/* Instead of "DEC #n; JMP_Z <C>", use "DJMP_Z, #n, <C>" */
			b = GEN_FORWARD_DJMP_Z(n, 8BITS);	/* DEC #n; JMP_Z <C> */
			TRACK_RELEASE(n);
		}
		if (!first)
			GEN_TARGET_HERE(f);
		GEN_TRACK_BACKWARD_FAIL_JMP(n, a);		/* FAIL_JMP <A> */
		if (0 == minlen)
			GEN_TARGET_HERE(c);					/* <C>: */
		if (SIZE_MAX != max)
			GEN_TARGET_HERE(b);					/* <C>: */
	} else {
		uint a, b = 0, c = 0, n = 0, t = 0, nw = 0;
		bool can_backtrack = re_mi_element_can_backtrack(e);
		bool is_simple = re_mi_element_is_simple(e);
		bool is_cexable = re_mi_element_is_cexable(e);
		bool checking_tp = FALSE;
		pslist_t *exclude = NULL;

		/*
		 * Greedy repetition: X*+, atomic (will not give-up what was matched)
		 */

		g_assert(implies(is_cexable,
			!can_backtrack && is_simple && minlen != 0));

		/*
		 * We are very careful here to generate the most efficient possible
		 * code for atomic matches, because greedy matches can be optimized
		 * to atomic ones when we know backtracking will not help improve
		 * matching.
		 *
		 * General matching scheme, presented here when X can match
		 * the empty string.
		 *
		 *    [ LOAD #n, max ]	; create tracking on the TRACK stack
		 * either...
		 *      JMP <B>			; only if `first' is FALSE (i.e * and not +)
		 * or...
		 *      PUSH_FSP		; otherwise this prevents backtracking into X
		 * 						; for the first time around (`first' is TRUE)
		 * <A>: SAVE_TP #t		; save text pointer in memory word #t
		 *      X				; match X, one more time
		 *      POP_FSP			; discard FAIL points from X + our own below
		 *      CMP_TP #t		; compare TP, see whether it changed
		 *      JMP_Z <C>		; stop repeating if no move
		 *    [ DEC #n ] 		; loop while we match until maximum
		 *    [ JMP_Z <C> ] 	; stop if we reached the maximum
		 * <B>: PUSH_FSP
		 *      FAIL_JMP <A>	; will be forgotten if we do POP_FSP above
		 *      POP_A			; undo PUSH_FSP above, popping value into A
		 *    ; forget about failed X matching, keep what we matched already
		 * <C>: ...				; matching remaining
		 *
		 * When the element cannot backtrack, we can further optimize by
		 * avoiding the needless constant updating of the FAIL and TRACK stacks,
		 * pushing items to pop them afterwards or discard them...
		 *
		 * When `first' is FALSE (X*+ matching), we generate this:
		 *
		 *      FAIL_JMP <A>	; in case X stop matching, sole FAIL context
		 *      JMP <B>			; done (remember, X itself cannot backtrack)
		 * <A>: X				; match X
		 *    ; the top FAIL context is necessarily our FAIL context above
		 *    ; since X cannot backtrack, hence cannot push any FAIL records!
		 *      UPDATE_TP		; update the TP entry in the push FAIL context
		 *      JMP <A>			; endless loop will end when X fails matching
		 * <B>: ...
		 *
		 * Even better, when the X element is CEX-able, we can avoid the
		 * FAIL_JMP and the UPDATE_TP instructions:
		 *
		 *      CEX				; set C, guard next instruction
		 * <A>: X				; match X
		 *      JMP_C <A>		; endless loop will end when X fails matching
		 *      ...
		 *
		 * or even more efficient at runtime via REPEAT_X:
		 *
		 *      REPEAT_X [max]  ; repeat next instruction at most max times
		 *      X				; match X as much as possible
		 *
		 * When `first' is TRUE (X++ matching), we need to ensure there is
		 * at least one initial X match.  If X is simple, it is trivial since
		 * we can just expand it.  But when X is not simple (has subgroups,
		 * with possible captures for instance), we cannot expand it.
		 *
		 * If it matches the empty string, no problem, we have nothing to do!
		 * It is possible for a group to match the empty string and still not
		 * appear to be backtracking when that group is itself atomic (at the
		 * end of the matching process, the FSP register will hold the same
		 * value as it had when we started to match X).
		 *
		 * Otherwise, if there is not already a repetition counter (which will
		 * happen when the repetition is unbound), we save the initial text
		 * pointer and will check at the end that it progressed by at least one
		 * position, indicating that there was at least a match (since X does
		 * not match the empty string).
		 *
		 *      FAIL_JMP <A>	; in case X stop matching, sole FAIL context
		 *      JMP <C>			; done (remember, X itself cannot backtrack)
		 *    ; the counter is taken after the FAIL_JMP to make sure it is
		 *    ; not made part of the saved context!
		 * <A>: SAVE_TP #c		; save text pointer into #c
		 * <B>: X				; match X
		 *    ; the top FAIL context is necessarily our FAIL context above
		 *    ; since X cannot backtrack, hence cannot push any FAIL records!
		 *      UPDATE_TP		; update the TP entry in the push FAIL context
		 *      JMP <B>			; endless loop will end when X fails matching
		 *    ; we come here when the FAIL point above is triggered
		 * <C>: CMP_TP #c		; check whether text pointer progressed
		 *      JMP_NZ <D>		; OK if it progressed
		 *      FAIL			; otherwise we did not match once at least
		 * <D>: ...
		 *
		 * However, if we already have a repetition counter, we use it to check
		 * that it was decremented at least once, hence we do not need this
		 * extra SAVE_TP / CMP_TP sequence:
		 *
		 * <C>: LOAD_A #n		; load accumulator with TRACK counter #n
		 *      LT_A max		; did counter change since initial setup?
		 *      JMP_Z <D>		; yes it did, hence we matched X once at least!
		 *      FAIL			; otherwise we did not match once at least
		 * <D>: ...
		 */

		if (0 == minlen) {
			GENX(debug, "atomic matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("atomic, min match: %zu byte%s", PLURAL(minlen)));
		}

		if (!can_backtrack) {
			GENX(debug,
				str_smsg("%s element cannot backtrack", re_type2str(e->type)));
		}

		/*
		 * For a CEX-able element, we do not need any tracking variable,
		 * we can do everything via the REPEAT instruction which will cause
		 * internal repetitions directly within the matching engine.
		 */

		if (is_cexable) {
			if (first)
				GEN_ELEMENT(e);		/* X */
			/*
			 * The CEX part of the REPEAT_X will guard the element, not causing
			 * a failure if it does not match but simply clearing the C bit.
			 */

			GENX(repeat, /* CEX = */ TRUE, max);
			GEN_ELEMENT(e);			/* X */
			return;
		}

		if (SIZE_MAX != max) {
			n = GEN_TRACK_GET_NUM();
			exclude = pslist_prepend(exclude, uint_to_pointer(n));
			GENX(load, n, max);					/* [ LOAD #n, max ] */
		}

		if (first)
			GENX(debug, "first repetition enforced here");

		if (
			first && !can_backtrack && !is_simple &&
			SIZE_MAX == max && 0 != minlen
		)
			checking_tp = TRUE;	/* To be able to enforce first match */

		if (0 == minlen || checking_tp) {
			/*
			 * The `t' variable is also excluded from the list of saved
			 * variables: it is defined before the FAIL_JMP instruction,
			 * so if we did not exclude it, it would be saved.
			 * However, we must not save it because when we come back
			 * after the FAIL_JMP instruction, the last value of that
			 * variable must be the one last updated, not the value we
			 * had before the FAIL_JMP...
			 */
			t = GEN_TRACK_GET_NUM();
			exclude = pslist_prepend(exclude, uint_to_pointer(t));
		}

		if (can_backtrack) {
			/* Normal code */
			if (first) {
				GEN(push_fsp);					/* PUSH_FSP */
			} else if (re_mi_element_is_small(mig, e))
				f = GEN_FORWARD_JMP(8BITS);		/* JMP <B> */
			else
				f = GEN_FORWARD_JMP(16BITS);	/* JMP <B> */
		} else {
			/* Alternative code */
			uint d = 0;
			if (first) {
				if (is_simple) {
					GEN_ELEMENT(e);					/* X */
				} else if (SIZE_MAX == max && 0 != minlen) {
					/* To be able to enforce first match, check TP progress */
					checking_tp = TRUE;
				}
			}

			d = GEN_LIST_FAIL_JMP(8BITS, exclude, NULL);/* FAIL_JMP <A> */
			nw = GEN_GET_FAIL_WORDS();

			/* Final verification to ensure we matched once */

			if (checking_tp) {
				GENX(cmp_tp, t);					/* CMP_TP #t */
				if (re_mi_element_is_small(mig, e))
					f = GEN_FORWARD_IF(NZ, 8BITS);	/* JMP_NZ <C> */
				else
					f = GEN_FORWARD_IF(NZ, 16BITS);	/* JMP_NZ <C> */
				GEN(fail);							/* FAIL */
			} else if (first && !is_simple && SIZE_MAX != max) {
				GENX(load_a, n);					/* LOAD_A #n */
				GENX(lt_a, max);					/* LT_A max */
				if (re_mi_element_is_small(mig, e))
					f = GEN_FORWARD_IF(Z, 8BITS);	/* JMP_Z <C> */
				else
					f = GEN_FORWARD_IF(Z, 16BITS);	/* JMP_Z <C> */
				GEN(fail);							/* FAIL */
			} else {
				if (re_mi_element_is_small(mig, e))
					f = GEN_FORWARD_JMP(8BITS);		/* JMP <B> */
				else
					f = GEN_FORWARD_JMP(16BITS);	/* JMP <B> */
			}

			GEN_TARGET_HERE(d);						/* <A>: */
		}

		a = GEN_TEXT_POS();						/* <A>: */
		if (0 == minlen || checking_tp)
			GENX(save_tp, t);					/* SAVE_TP #t */
		if (checking_tp)						/* <B>: */
			a = GEN_TEXT_POS();					/* this is where we'll loop */

		GEN_ELEMENT(e);							/* X */

		if (can_backtrack)
			GEN(pop_fsp);						/* POP_FSP */
		else
			GEN(update_tp);						/* UPDATE_TP */

		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			TRACK_RELEASE(t);					/* (element generated now) */
			if (can_backtrack) {
				b = GEN_FORWARD_IF(Z, 8BITS);	/* JMP_Z <C> */
			} else {
				uint d;
				d = GEN_FORWARD_IF(NZ, 8BITS);	/* JMP_NZ <E> */
				GEN(fail);							/* FAIL */
				GEN_TARGET_HERE(d);					/* <E> */
			}
		}

		GENX(debug, str_smsg("looping for %satomic %s",
			can_backtrack ? "" : "non-backtracking ", re_elem_info(e)));

		if (SIZE_MAX != max) {
			TRACK_RELEASE(n);
			if (can_backtrack) {
				/* DEC #n; JMP_Z <C> */
				c = GEN_FORWARD_DJMP_Z(n , 8BITS);	/* DJMP_Z #n, <C> */
			} else {
				/* DEC #n; JMP_NZ <B> */
				GEN_BACKWARD_DJMP_NZ(n, a);			/* DJMP_NZ #n, <B> */

				/*
				 * At this stage we know we matched the pattern at least
				 * once, hence there is no need to trigger the failure to
				 * go to the code after the leading FAIL_JMP that will
				 * check for the progress of the counter!
				 *
				 * Since we are out of the repetition loop, we can simply
				 * drop the FAIL context as we're done.
				 */

				GENX(drop_fail, nw);				/* DROP_FAIL */
			}
		}

		if (can_backtrack) {
			if (!first)
				GEN_TARGET_HERE(f);				/* <B>: */
			GEN(push_fsp);						/* PUSH_FSP */
			GEN_TRACK_BACKWARD_FAIL_JMP(n, a);	/* FAIL_JMP <A> */
			GEN(pop_a);							/* POP_A */
		} else {
			/* If SIZE_MAX != max, we already generated a DJMP_NZ above */
			if (SIZE_MAX == max) {
				if (is_cexable)
					GEN_BACKWARD_IF(C, a);		/* JMP_C <A> */
				else
					GEN_BACKWARD_JMP(a);		/* JMP <B> */
			}
		}

		if (can_backtrack) {
			if (0 == minlen)
				GEN_TARGET_HERE(b);				/* <C>: */
			if (SIZE_MAX != max)
				GEN_TARGET_HERE(c);				/* <C>: */
		} else {
			GEN_TARGET_HERE(f);					/* <C>: */
		}

		pslist_free_null(&exclude);
	}
}

/**
 * Generate unrolled repetition of CHAR and TEXT elements.
 *
 * @param mig		the generation context
 * @param e			the element to generate
 * @param n			amount of repetitions
 */
static void
re_mi_generate_unrolled(struct re_mi_gen_ctx *mig,
	const re_element_t *e, size_t n)
{
	str_t *s = str_new(0);

	while (n--) {
		if (RE_TYPE_CHAR == e->type) {
			int c = re_element_get_char(e);
			str_putc(s, c);
		} else if (RE_TYPE_TEXT == e->type) {
			const char *t = re_element_get_text(e);
			str_cat(s, t);
		} else {
			g_assert_not_reached();
		}
	}

	if (str_len(s) != 0)
		GENX(match, str_2c(s), e->icase);

	str_destroy_null(&s);
}

/**
 * Generate byte code for the given element, with max amount of repetitions
 * (possibly unbounded), and an optional first mandatory repetition.
 *
 * @param mig		the generation context
 * @param e			the element to generate
 * @param min		minimum amount of repetitions to ensure
 * @param max		max amount of repetitions to monitor, SIZE_MAX => unlimited
 * @param first		if TRUE, we need a first element match
 */
static void
re_mi_generate_min_max(struct re_mi_gen_ctx *mig, const re_mi_element_t *me,
	size_t min, size_t max)
{
	const re_element_t *e = me->e;
	size_t minlen = re_element_get_minlen(e);
	bool atomic = e->atomic;
	bool has_next = re_mi_find_next_element(me, NULL, FALSE);
	bool is_disjoint = !has_next || re_mi_next_is_disjoint(me);

	g_assert(implies(SIZE_MAX == max, min > 1));	/* Or simpler code used! */

	/*
	 * We know the item is not simple: if it were, then it would
	 * also be simple and X{n.m} would have been optimized into the
	 * more efficient X{n} X{0,m-n} earlier by re_mi_generate_repeated().
	 *
	 * Indeed, the code we're generating here is much slower due to
	 * the fact we have to rely on more instructions to implement the
	 * matching logic, and the proportion of control flow and arithmetic
	 * instructions over matching instructions is much higher than the
	 * one we can achieve in the X{0,m} case.
	 */

	g_assert(!re_mi_element_is_simple(e));

	/*
	 * When min is 0 or 1, we're better off using LOAD / DJMP loop,
	 * since "DJMP" combines both a pseudo DEC_A and LT_A instruction,
	 * hence is more efficient at runtime.  We know max cannot be
	 * SIZE_MAX, because "{0,}" is actually "*" and "{1,}" is "+" so
	 * we would not be here generating code for a bounded loop
	 */

	if (min <= 1) {
		g_assert(SIZE_MAX != max);
		re_mi_generate_upto(mig, me, max - min, 1 == min);
		return;
	}

	GENX(debug,
		str_smsg("between %zu and %s%s matches (%s mode) for %s",
			min,
			SIZE_MAX == max ? "" : "up to ",
			SIZE_MAX == max ? "infinite" : size_t_to_string(max),
			e->minimal ? "lazy" :
			e->atomic ?  "atomic" : "greedy",
			re_elem_info(e))
	);

	g_assert(min > 1);	/* We must always match X at least once */

	/*
	 * If the element is not atomic, look whether we have something
	 * afterwards or whether matching is disjoint with what comes next.
	 */

	if (!e->minimal && !atomic && is_disjoint) {
		/*
		 * Given anything afterwards will not overlap with the matching of
		 * the current element, we can turn that element into an atomic match.
		 */

		if (has_next || re_mi_element_is_cexable(e)) {
			atomic = TRUE;

			GENX(debug, str_smsg("%s greedy match made atomic",
				has_next ? "disjoint" : "trailing"));
		}
	}

	if (e->minimal) {
		uint a, b, c, d, i = 0, t = 0;

		/*
		 * Lazy repetition: X{n,m}?, non atomic (can backtrack)
		 */

		if (0 == minlen) {
			GENX(debug, "lazy matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("lazy, min match: %zu byte%s", PLURAL(minlen)));
		}

		/*
		 * General code pattern for X{n,m}? lazy matching is:
		 *
		 *      CLEAR #i		; sets word #i to 0
		 * <A>: X				; match X
		 *      INC_A #i		; increments word at #i, copy into A
		 *      RG_A n, m		; sets Z if A < n, C if A in [n, m[
		 *      JMP_Z <A>		; loop while minimum `n' not reached
		 *      JMP_NC <B>		; reached maximum, we're done
		 *      FAIL_JMP <B>	; try to not match since lazy
		 *    ; coming back here due to matching failure
		 *      JMP <A>			; have to match once more then
		 *    ; continue if we repeated X the maximum amount of time
		 *    ; (this does not leave any backtracking point)
		 * <B>: ...				; matching remaining
		 *
		 * The usual safeguards apply when X can match the empty string.
		 */

		i = GEN_TRACK_GET_NUM();
		GENX(clear, i);							/* CLEAR #i */

		a = GEN_TEXT_POS();						/* <A>: */

		if (0 == minlen) {
			t = GEN_TRACK_GET_NUM();
			GENX(save_tp, t);					/* SAVE_TP #t */
			/*
			 * Because this is an open loop, we cannot release the word `t'
			 * (used for tracking text when minlen is 0) either.
			 */
			TRACK_KEEP(t);						/* (permanent variable) */
		}
		GEN_ELEMENT(e);							/* X */
		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			b = GEN_FORWARD_IF(Z, 8BITS);		/* JMP_Z <B> */
			/* Word #t not released */
		}

		GENX(inc_a, i);							/* INC_A #i */
		if (SIZE_MAX != max) {
			GENX(rg_a, min, max);				/* RG_A n, m */
			GEN_BACKWARD_IF(Z, a);				/* JMP_Z <A> */
			c = GEN_FORWARD_IF(NC, 8BITS);		/* JMP_NC <B> */
		} else {
			GENX(lt_a, min);					/* LT_A n */
			GEN_BACKWARD_IF(Z, a);				/* JMP_Z <A> */
		}

		d = GEN_TRACK_FAIL_JMP(8BITS, i, NULL);	/* FAIL_JMP <B> */
		GEN_BACKWARD_JMP(a);					/* JMP <A> */

		if (0 == minlen)
			GEN_TARGET_HERE(b);					/* <B>: */
		if (SIZE_MAX != max)
			GEN_TARGET_HERE(c);					/* <B>: */
		GEN_TARGET_HERE(d);						/* <B>: */

		/*
		 * Not releasing word #i, only stopping its saving now
		 * that we're out of the loop.
		 */
		TRACK_KEEP(i);
	} else if (!atomic) {
		uint a, b, c, i = 0, t = 0;

		/*
		 * Greedy repetition: X{n,m}, non atomic (can backtrack)
		 */

		if (0 == minlen) {
			GENX(debug, "greedy matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("greedy, min match: %zu byte%s", PLURAL(minlen)));
		}

		/*
		 * General pattern for greedy X{n,m} matching is:
		 *
		 *      CLEAR #i		; sets word #i to 0
		 * <A>: X				; match X
		 *      INC_A #i		; increments word at #i, copy into A
		 *      RG_A n			; sets Z if A < n, C if A in [n, m[
		 *      JMP_Z <A>		; loop while minimum `n' not reached
		 *      JMP_NC <B>		; reached maximum, we're done
		 *      FAIL_JMP <A>	; try to match as much as possible
		 *    ; coming back here due to matching failure
		 *    ; simply continue without this last X
		 * <B>: ...				; matching remaining
		 *
		 * The usual safeguards apply when X can match the empty string.
		 *
		 * When X has a fixed non-zero matching length 'L' (not necessarily
		 * a simple element), we can use an alternate generation pattern
		 * which avoids creating one FAIL point for every X we match:
		 *
		 *      CLEAR #i		; sets word #i to 0
		 * <A>: X				; match X
		 *      INC_A #i		; increments word at #i, copy into A
		 *      CP_A n			; sets Z if A == n, C if A >= n
		 *      JMP_C <A>		; loop while minimum `n' not reached
		 *      JMP_NZ <B>		; starting TP never saved if Z (i.e A == n)
		 *    ; we have just reached the n minimal matches
		 *      SAVE_TP #t		; must remember where we start in text
		 *      FAIL_JMP <D>	; creates initial FAIL point
		 *    ; comes here on first matching failure, TP points to last match
		 *    ; first check whether we have backtracked to origin
		 * <C>: CMP_TP #t		; is TP equal to word #t, where we started
		 *      JMP_Z <E>		; yes, we are done, no FAIL point left!
		 *      FAIL_JMP <E>	; continue with one less X
		 *    ; comes here on subsequent matching failure
		 *      SUB_TP L		; decrease TP by L
		 *      JMP <C>
		 * <B>: UPDATE_TP		; update TP entry in the push FAIL context
		 * <D>: LT_A m			; sets Z if A < m
		 *      JMP_Z <A>		; not reached maximum, continue matching
		 *    ; we reached the maximum amount of matches
		 *    ; backtracking or maximum reached
		 * <E>: ...				; matching remaining
		 *
		 * Just like we do in re_mi_generate_upto(), we need to take care
		 * of elements which can backtrack...  We need the SAVE_FSP and
		 * UPDATE_FTP instructions, but we do not need UPDATE_FPC here
		 * because we do not need to get rid of the first FAIL point once
		 * we have reached the maximum.
		 *
		 * The code looks like this:
		 *
		 *      CLEAR #i		; sets word #i to 0
		 * <A>: X				; match X
		 *      INC_A #i		; increments word at #i, copy into A
		 *      CP_A n			; sets Z if A == n, C if A >= n
		 *      JMP_C <A>		; loop while minimum `n' not reached
		 *      JMP_NZ <B>		; starting TP never saved if Z (i.e A == n)
		 *    ; we have just reached the n minimal matches
		 *      SAVE_TP #t		; must remember where we start in text
		 *      FAIL_JMP <R>	; creates initial FAIL point
		 *    ; comes here on first matching failure, TP points to last match
		 *    ; first check whether we have backtracked to origin
		 * <C>: CMP_TP #t		; is TP equal to word #t, where we started
		 *      JMP_Z <E>		; yes, we are done, no FAIL point left!
		 *      FAIL_JMP <E>	; continue with one less X
		 *    ; comes here on subsequent matching failure
		 *      SUB_TP L		; decrease TP by L
		 *      JMP <C>
		 * <R>: SAVE_FSP #f		; save top of FAIL stack for initial FAIL point
		 *      JMP <D>
		 * <B>: UPDATE_FTP #f	; update TP entry in the push FAIL context
		 * <D>: LT_A m			; sets Z if A < m
		 *      JMP_Z <A>		; not reached maximum, continue matching
		 *    ; we reached the maximum amount of matches
		 *    ; backtracking or maximum reached
		 * <E>: ...				; matching remaining
		 */

		i = GEN_TRACK_GET_NUM();
		GENX(clear, i);							/* CLEAR #i */

		a = GEN_TEXT_POS();						/* <A>: */

		if (
			minlen == re_element_get_maxlen(e) &&
			max >= RE_MI_FAIL_MIN	/* Minimum amount to amortize setup */
		) {
			uint d, f = 0, g, h, j;
			bool can_backtrack = re_mi_element_can_backtrack(e);
			bool within_repeat = re_mi_element_is_within_repetition(me);

			/* We are only using one single FAIL point at a time */
			GENX(debug,
				str_smsg("using at most 1 FAIL point%s",
					within_repeat ? " (with parent repetition)" : ""));
			GENX(debug,
				str_smsg("item can%s backtrack", can_backtrack ? "" : "not"));

			g_assert(minlen != 0);

			t = GEN_TRACK_GET_NUM();
			TRACK_KEEP(t);		/* Not saved, but will remain allocated */

			if (can_backtrack) {
				f = GEN_TRACK_GET_NUM();
				TRACK_KEEP(f);	/* Not saved, but will remain allocated */
			}

			GEN_ELEMENT(e);						/* X */
			GENX(inc_a, i);						/* INC_A #i */
			GENX(cp_a, min);					/* CP_A n */
			GEN_BACKWARD_IF(C, a);				/* JMP_C <A> */
			b = GEN_FORWARD_IF(NZ, 8BITS);		/* JMP_NZ <B> */

			/*
			 * We need to save the previous value of word #t, (it
			 * will be restored when we no longer have any FAIL point
			 * for this element) when, we are enclosed in a repetition:
			 * indeed, this code could be re-entered as part of our own
			 * backtracking.
			 */

			if (within_repeat)
				GENX(f_push_track, t);			/* F_PUSH_TRACK #t */
			GENX(save_tp, t);					/* SAVE_TP #t */

			d = GEN_TRACK_FAIL_JMP(8BITS, i, NULL);	/* FAIL_JMP <D> */
			c = GEN_TEXT_POS();					/* <C>: */
			GENX(cmp_tp, t);					/* CMP_TP #t */

			/*
			 * When Z is set, we came back to the TP we had after we
			 * matched the minimum amount of repetitions.  We are
			 * therefore done and are not going to leave any FAIL point.
			 *
			 * If we are within a repetition, now is the time to also
			 * pop the value of word #t from the FAIL stack.
			 */

			if (!within_repeat) {
				h = GEN_FORWARD_IF(Z, 8BITS);	/* JMP_Z <E> */
			} else {
				uint k;
				k = GEN_FORWARD_IF(NZ, 8BITS);	/* JMP_NZ <K> */
				GENX(f_pop_track, t);			/* F_POP_TRACK #t */
				/* Done, no more FAIL point here */
				h = GEN_FORWARD_JMP(8BITS);		/* JMP <E> */
				GEN_TARGET_HERE(k);				/* <K>: still backtracking */
			}

			TRACK_RELEASE(i);
			g = GEN_FAIL_JMP(8BITS);			/* FAIL_JMP <E> */
			GENX(sub_tp, minlen);				/* SUB_TP L */
			GEN_BACKWARD_JMP(c);				/* JMP <C> */
			if (can_backtrack) {
				GEN_TARGET_HERE(d);				/* <R>: really! */
				GENX(save_fsp, f);				/* SAVE_FSP #f */
				j = GEN_FORWARD_JMP(8BITS);		/* JMP <D> */
			}
			GEN_TARGET_HERE(b);					/* <B>: */
			if (can_backtrack) {
				GENX(update_ftp, f);			/* UPDATE_FTP #f */
			} else {
				GEN(update_tp);					/* UPDATE_TP */
				GEN_TARGET_HERE(d);				/* <D>: */
			}
			if (can_backtrack)
				GEN_TARGET_HERE(j);				/* <D>: */
			if (SIZE_MAX == max) {
				GEN_BACKWARD_JMP(a);			/* JMP <A> */
			} else {
				GENX(lt_a, max);				/* LT_A m */
				GEN_BACKWARD_IF(Z, a);			/* JMP_Z <A> */
			}
			GEN_TARGET_HERE(h);					/* <E>: */
			GEN_TARGET_HERE(g);					/* <E>: */
			return;
		}

		/*
		 * Regular case: matching length of X is not fixed (or can be 0).
		 */

		if (0 == minlen) {
			t = GEN_TRACK_GET_NUM();
			GENX(save_tp, t);					/* SAVE_TP #t */
		}
		GEN_ELEMENT(e);							/* X */
		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			TRACK_RELEASE(t);					/* (element generated now) */
			b = GEN_FORWARD_IF(Z, 8BITS);		/* JMP_Z <B> */
		}

		GENX(inc_a, i);							/* INC_A #i */
		if (SIZE_MAX != max) {
			GENX(rg_a, min, max);				/* RG_A n, m */
			GEN_BACKWARD_IF(Z, a);				/* JMP_Z <A> */
			c = GEN_FORWARD_IF(NC, 8BITS);		/* JMP_NC <B> */
		} else {
			GENX(lt_a, min);					/* LT_A n */
			GEN_BACKWARD_IF(Z, a);				/* JMP_Z <A> */
		}

		GEN_TRACK_BACKWARD_FAIL_JMP(i, a);		/* FAIL_JMP <A> */

		if (0 == minlen)
			GEN_TARGET_HERE(b);					/* <B>: */
		if (SIZE_MAX != max)
			GEN_TARGET_HERE(c);					/* <B>: */
		TRACK_RELEASE(i);
	} else {
		uint a, b = 0, c = 0, d, f = 0, i = 0, t = 0, nw;
		bool can_backtrack = re_mi_element_can_backtrack(e);

		/*
		 * Greedy repetition: X{n,m}+, atomic (no give-up of matched text)
		 */

		/*
		 * Matching scheme, presented here when X can match the empty string.
		 *
		 *      CLEAR #i		; sets word #i to 0
		 * <B>: PUSH_FSP		; no backtracking into X
		 * <A>: SAVE_TP #t		; save text pointer in memory word #t
		 *      X				; match X, one more time
		 *      POP_FSP			; no backtracking into X
		 *      CMP_TP #t		; compare TP, see whether it changed
		 *      JMP_Z <C>		; end if no move, despite minimum not reached
		 *      INC_A #i		; increments word at #i, copy into A
		 *      RG_A n, m		; sets Z if A < n, C if A in [n, m[
		 *      JMP_Z <B>		; minimum count not reached
		 *      JMP_NC <C>		; reached maximum amount of attempts
		 *    ; attempting one more matching if possible
		 *      PUSH_FSP		; no backtracking into X
		 *      FAIL_JMP <A>	; will be forgotten if we do POP_FSP above
		 *    ; if we cannot match X anymore, keep what we got so far
		 *      POP_A			; undo PUSH_FSP: pops pushed FSP value into A
		 * <C>: ...				; matching remaining
		 *
		 * When the element X cannot backtrack, we can generate more efficient
		 * matching code, which decreases the amount of testing done in the
		 * loop and avoids pushing fail points and playing with FSP every
		 * iteration (for simplicity, version below when X cannot match the
		 * empty string):
		 *
		 *      LOAD #i, m		; sets word #i to max
		 *      FAIL_JMP <A>	; go match X
		 *    ; comes back here on X matching failure
		 *      LOAD_A #i		; load matching counter into accumulator A
		 *      LT_A m-n+1		; sets Z if A < (m - n + 1)
		 *      JMP_Z <B>		; we already reached our minimum count
		 *      FAIL			; sorry, minimum not reached yet
		 * <A>: X				; match X, which cannot push any FAIL point
		 *      UPDATE_TP		; update text pointer in FAIL context
		 *      DJMP_NZ #i, <A>	; loop until max repetition count is reached
		 *      DROP_FAIL		; drop FAIL point since we know min was reached
		 * <B>: ...
		 */

		if (0 == minlen) {
			GENX(debug, "atomic matches, empty string possible");
		} else {
			GENX(debug,
				str_smsg("atomic, min match: %zu byte%s", PLURAL(minlen)));
		}

		i = GEN_TRACK_GET_NUM();
		if (can_backtrack) {
			GENX(clear, i);							/* CLEAR #i */
			b = GEN_TEXT_POS();						/* <B>: */
			GEN(push_fsp);							/* PUSH_FSP */
		} else {
			GENX(load, i, max);						/* LOAD #i, m */
		}

		if (!can_backtrack) {
			f = GEN_TRACK_FAIL_JMP(8BITS, i, NULL);	/* FAIL_JMP <A> */
			nw = GEN_GET_FAIL_WORDS();
			/* Ensure we matched at least the minimum required times */
			GENX(load_a, i);						/* LOAD_A #i */
			GENX(lt_a, max - min + 1);				/* LT_A m-n+1 */
			if (re_mi_element_is_small(mig, e))
				d = GEN_FORWARD_IF(Z, 8BITS);		/* JMP_Z <B> */
			else
				d = GEN_FORWARD_IF(Z, 16BITS);		/* JMP_Z <B> */
			/* Minimum was not matched, we need to backtrack */
			GEN(fail);								/* FAIL */
			GEN_TARGET_HERE(f);						/* <A>: */
		}

		a = GEN_TEXT_POS();						/* <A>: */

		if (0 == minlen) {
			t = GEN_TRACK_GET_NUM();
			GENX(save_tp, t);					/* SAVE_TP #t */
		}

		GEN_ELEMENT(e);							/* X */

		if (can_backtrack)
			GEN(pop_fsp);						/* POP_FSP */

		if (0 == minlen) {
			GENX(cmp_tp, t);					/* CMP_TP #t */
			TRACK_RELEASE(t);					/* (element generated now) */
			c = GEN_FORWARD_IF(Z, 8BITS);		/* JMP Z <C> */
		}

		if (can_backtrack) {
			GENX(inc_a, i);							/* INC_A #i */
			if (SIZE_MAX != max)
				GENX(rg_a, min, max);				/* RG_A n, m */
			else
				GENX(cp_a, min);					/* CP_A n */
			GEN_BACKWARD_IF(Z, b);					/* JMP_Z <B> */
			if (SIZE_MAX != max)
				d = GEN_FORWARD_IF(NC, 8BITS);		/* JMP_NC <C> */
		} else {
			if (0 == minlen) {
				GENX(cmp_tp, t);					/* CMP_TP #t */
				f = GEN_FORWARD_IF(NZ, 8BITS);		/* JMP_NZ <C> */
				GEN(fail);							/* FAIL */
				GEN_TARGET_HERE(f);					/* <C> */
			}
			GEN(update_tp);							/* UPDATE_TP */
			GEN_BACKWARD_DJMP_NZ(i, a);				/* DJMP_NZ #i, <A> */
			/* No need to issue DROP_FAIL if this is the tail of RE */
			if (SIZE_MAX != max && has_next)
				GENX(drop_fail, nw);				/* DROP_FAIL */
		}

		if (can_backtrack) {
			GEN(push_fsp);							/* PUSH_FSP */
			GEN_TRACK_BACKWARD_FAIL_JMP(i, a);		/* FAIL_JMP <A> */
			GEN(pop_a);								/* POP_A */

			if (SIZE_MAX != max)
				GEN_TARGET_HERE(d);					/* <C>: */
			if (0 == minlen)
				GEN_TARGET_HERE(c);					/* <C>: */
		} else {
			GEN_TARGET_HERE(d);						/* <C>: */
		}

		TRACK_RELEASE(i);
	}
}

/**
 * Generate byte code for the given element, with repetition.
 *
 * @param mig		the generation context
 * @param me		the element to generate
 */
static void
re_mi_generate_repeated(struct re_mi_gen_ctx *mig, const re_mi_element_t *me)
{
	const re_element_t *e = me->e;
	size_t min = re_element_get_repeat_min(e);
	size_t max = re_element_get_repeat_max(e);
	bool can_backtrack = re_mi_element_can_backtrack(e);

	switch (e->type) {
	case RE_TYPE_NEXT:;
	case RE_TYPE_RETURN:
		return;		/* Silently ignore these */
	}

	GENX(debug, re_elem_info(e));

	/*
	 * The Matching Interpreter is currently using a 32-bit architecture
	 * (on purpose, to limit stack size to a maximum) and will therefore
	 * not be able to track more than 2^32 repetitions...
	 */

	if G_UNLIKELY(min > MAX_INT_VAL(uint32)) {
		min = MAX_INT_VAL(uint32);
		s_carp("%s(): capping minimum repetitions to %zu for %s",
			G_STRFUNC, min, re_elem_info(e));
	}

	if G_UNLIKELY(max > MAX_INT_VAL(uint32) && MAX_INT_VAL(size_t) != max) {
		max = MAX_INT_VAL(uint32);
		s_carp("%s(): capping maximum repetitions to %zu for %s",
			G_STRFUNC, max, re_elem_info(e));
	}

	/*
	 * In all comments below, "X" stands for the code matching the element.
	 */

	switch ((re_repeat_type_t) e->repeat) {
	case RE_N_ONCE:
		/*
		 * If the repetition is atomic, we must make sure we are
		 * discarding any FAIL point installed by X when it can
		 * backtrack.
		 */

		if (can_backtrack && e->atomic)
			GEN(push_fsp);				/* PUSH_FSP */

		GEN_ELEMENT(e);					/* X */

		if (can_backtrack && e->atomic)
			GEN(pop_fsp);				/* POP_FSP */
		break;

	case RE_N_AT_MOST_ONE:
		re_mi_generate_upto_1(mig, me);
		break;

	case RE_N_AT_LEAST_ONE:
	case RE_N_ANY:
		{
			bool need_first_match = RE_N_AT_LEAST_ONE == e->repeat;

			/*
			 * We do not special case greedy (+) repetitions because our
			 * generated code allows for an efficient implementation
			 * already.  See re_mi_generate_upto() for the greedy (*)
			 * generation when a first match is required.
			 */

			if (need_first_match && (e->atomic | e->minimal)) {
				/*
				 * When X is simple, we can use the equivalence:
				 *
				 *		X+ <=> X X*
				 *
				 * to generate more efficient code.
				 *
				 * Otherwise, we'll need to go through a slightly different
				 * scheme in re_mi_generate_upto() involving an extra JMP.
				 *
				 * This is allows us to avoid expanding the byte-code for X
				 * twice at the cost of an extra leading JMP.
				 */

				if (!can_backtrack) {
					GENX(debug,
						str_smsg("first match required (%s mode) expanded",
							e->minimal ? "lazy" :
							e->atomic ?  "atomic" : "greedy"));

					GEN_ELEMENT(e);				/* X */
					need_first_match = FALSE;
				}
			}

			re_mi_generate_upto(mig, me, MAX_INT_VAL(size_t), need_first_match);
		}
		break;

	case RE_N_RANGE:
	case RE_N_MIN:
	case RE_N_COUNT:
		if (RE_N_COUNT == e->repeat || re_mi_element_is_simple(e)) {
			/*
			 * Greedy or lazy does not make any difference here since
			 * a fixed repeat count is required.  However if n > 1 and
			 * the repetition is atomic (X{4}+ for instance), we must
			 * make sure X is not leaving behind any FAIL points when
			 * it can backtrack.
			 *
			 * Code for X{n}:
			 *
			 *    [ PUSH_FSP ]		; if atomic and X can backtrack
			 *      LOAD #i, n		; prepare for `n' repetitions
			 * <A>: X				; match X
			 *    ; actually using DJMP_NZ, but that's the idea
			 *      DEC #i			; and repeat `n' times exactly
			 *      JMP_NZ <A>
			 *    [ POP_FSP ]		; if atomic and X can backtrack
			 *    ; continue once X matched `n' times
			 *
			 * However if `n' is small-enough and the element simple, we
			 * can safely expand its repetitions, or use REPEAT for even
			 * faster looping at the instruction level.
			 */

			/*
			 * If the repetition is atomic, we must make sure we are
			 * discarding any FAIL point installed by X when it can
			 * backtrack.
			 */

			if (can_backtrack && e->atomic)
				GEN(push_fsp);				/* PUSH_FSP */

			if (re_mi_element_is_cexable(e) && min > 1) {
				/*
				 * We use REPEAT to factorize matching right into
				 * the execution engine.
				 */

				GENX(repeat, /* CEX = */ FALSE, min);	/* REPEAT min */
				GEN_ELEMENT(e);				/* X */
			} else if (re_mi_element_is_simple(e) && min <= RE_MI_UNROLL_MAX) {
				if (min > 1)
					GENX(debug, str_smsg("unrolling %zu repetitions", min));

				/*
				 * We handle CHAR and TEXT elements separately to be able
				 * to factorize the MATCH instruction.
				 */

				switch (e->type) {
				case RE_TYPE_CHAR:
				case RE_TYPE_TEXT:
					re_mi_generate_unrolled(mig, e, min);
					break;
				default:
					{
						size_t i;
						for (i = 0; i < min; i++)
							GEN_ELEMENT(e);
					}
					break;
				}
			} else if (1 == min) {
				GEN_ELEMENT(e);				/* X, once! */
			} else {
				uint a, i;

				g_assert(min != 0);

				GENX(debug,
					str_smsg("%s %zu %s repetitions",
						RE_N_MIN == e->repeat ? "first" : "exactly", min,
						e->atomic ? "atomic" :
						e->minimal ? "lazy" : "greedy"));

				i = GEN_TRACK_GET_NUM();
				GENX(load, i, min);				/* [ LOAD #i, min ] */
				a = GEN_ELEMENT(e);				/* <A>: X */
				/* DEC #i; JMP_NZ <A> written as DJMP_NZ <A> */
				GEN_BACKWARD_DJMP_NZ(i, a);
				TRACK_RELEASE(i);
			}

			if (can_backtrack && e->atomic)
				GEN(pop_fsp);				/* POP_FSP */

			/*
			 * To handle X{n,m} and X{n,} and when X is simple, we can
			 * rely on the fact that:
			 *
			 * 		X{n,m} <=> X{n} X{0,m-n}
			 *
			 * But when X is not simple, that would duplicate possibly large
			 * code for X so we will use a different pattern.
			 */

			if (RE_N_MIN == e->repeat) {
				re_mi_generate_upto(mig, me, MAX_INT_VAL(size_t), FALSE);
			} else if (RE_N_RANGE == e->repeat) {
				re_mi_generate_upto(mig, me, max - min, FALSE);
			}
		} else {
			/*
			 * Handling X{n,m} or X{n,} with a non-simple X.
			 */

			re_mi_generate_min_max(mig, me, min, max);
		}
		break;

	case RE_N_MAX:
		g_assert_not_reached();
	}
}

/**
 * Check whether last generated instruction is the given minimal opcode.
 */
static bool
re_mi_gen_last_is_mop(struct re_mi_gen_ctx *mig, re_mi_mop_t mop)
{
	re_mi_opcode_t lastop;

	if (0 == re_mi_seg_used(mig->text))
		return FALSE;		/* No instructions yet */

	lastop.code = mig->text->p[-1];
	return 0 == lastop.u.m.zero && mop == lastop.u.m.op;
}

/**
 * Generate a subroutine call for handling the element vector or the element.
 *
 * This is the common code for re_mi_generate_call() and re_mi_generate_xcall().
 *
 * Either `ev' or `e' must be NULL;
 *
 * @param mig		the generation context
 * @param ev		the element vector to generate
 * @param e			the element to generate
 * @param op		the call OP to make (CALL or XCALL)
 *
 * @return the position at which the CALL is made.
 */
static uint
re_mi_generate_subcall(struct re_mi_gen_ctx *mig,
	const re_elemvec_t *ev, const re_element_t *e, re_mi_op_t op)
{
	const void *id;
	uint position;
	bool exists;
	re_mi_call_t *call;
	htable_t *resolved, *saved_resolved;

	re_mi_gen_ctx_check(mig);
	re_mi_seg_check(mig->text);
	g_assert(NULL == ev || NULL == e);

	id = NULL == ev ? cast_to_constpointer(e) : cast_to_constpointer(ev);

	if (htable_contains(mig->subid, id)) {
		exists = TRUE;
	} else {
		exists = FALSE;
		htable_insert(mig->subid, id, NULL);
	}

	/*
	 * In the end, the code is going to look like this:
	 *
	 *     (X)CALL <A>
	 *     ....
	 *
	 * <A>:
	 *     { element vector (or plain element) match }
	 *     RET
	 *
	 * We do not know yet at which address the matching code is going to
	 * be placed in the TEXT segment, so we're using an absolute address
	 * scheme for the CALL, but of course we cannot resolve it yet.
	 *
	 * Generation is going to be done in its own segment, and, at the end,
	 * we'll emit the code for these segments and resolve the CALL address.
	 *
	 * Note that for an XCALL, we don't need a trailing RET, but rather
	 * expect a DONE on success, and a failure otherwise because the call
	 * itself is not handled directly via the Matching Interpreter but
	 * through a C routine recursing back into the Matching Interpreter.
	 */

	/* Generation of CALL in parent TEXT segment, absolute addressing */

	position = re_mi_generate_push_jmp(mig,
		op, RE_MI_JMP_ALWAYS, RE_OP_CS_EMPTY);

	g_assert(NULL == mig->resolvable);

	WALLOC0(call);
	call->magic    = RE_MI_CALL_MAGIC;
	call->is_def   = !exists;
	call->id       = id;
	call->parent   = mig->text;
	call->position = position;
	call->p_fwd    = mig->fwd;
	saved_resolved = mig->resolved;

	if (exists) {
		/*
		 * This is just a symbol table entry for the existing routine.
		 * The `routines' list will be traversed to only resolve the CALL
		 * addresses.
		 */
		mig->routines = pslist_prepend(mig->routines, call);
		return position;
	}

	/*
	 * This is code for an ID we do not know about yet.
	 * Generate the code for it!
	 *
	 * Also the call structure will be put in the `calls' stack, which is
	 * the first being traversed in LIFO order to append the generated
	 * code to the main TEXT segment and resolve the initial CALL to the
	 * subroutine, inserting its actual final address.
	 */

	call->sub.routine  = re_mi_seg_create();
	call->sub.fwd      = htable_create(HASH_KEY_SELF, 0);
	resolved           = htable_create(HASH_KEY_SELF, 0);

	mig->calls    = pslist_prepend(mig->calls, call);
	mig->fwd      = call->sub.fwd;
	mig->resolved = resolved;
	mig->text     = call->sub.routine;

	/* Generation of subroutine in its own TEXT segment */

	if (ev != NULL) {
		GENX(debug, str_smsg("start of routine for %s", re_elemvec_info(ev)));
		re_mi_generate_elemvec(mig, ev);
		if (RE_OP_XCALL == op)
			GEN(done);
		else
			GEN(ret);
		GENX(debug, str_smsg("end of routine for %s", re_elemvec_info(ev)));
	} else if (e != NULL) {
		GENX(debug, str_smsg("start of routine for %s", re_elem_info(e)));
		g_assert_log(op != RE_OP_XCALL,
			"%s(): cannot use XCALL for element %s", G_STRFUNC, re_elem_info(e));
		re_mi_generate_element_sub(mig, e);
		if (!re_mi_gen_last_is_mop(mig, RE_MOP_RET) || mig->resolvable != NULL)
			GEN(ret);
		GENX(debug, str_smsg("end of routine for %s", re_elem_info(e)));
	} else {
		g_assert_not_reached();
	}

	g_assert(NULL == mig->resolvable);

	/*
	 * See whether internal JMP we resolved in the routine TEXT segment are
	 * not themselves jumping to another unconditional JMP, so that we avoid
	 * these extra hops at runtime.
	 */

	re_mi_resolve_optimize(mig);
	htable_free_null(&resolved);

	/* Moving back to the parent TEXT segment */

	mig->text     = call->parent;
	mig->fwd      = call->p_fwd;
	mig->resolved = saved_resolved;

	/*
	 * Remember the calling text segment association with this call, so
	 * that if other calls are made from this segment to other (existing)
	 * routines, we'll be able to go back and update their CALL operation
	 * with the proper destination address.
	 *
	 * The only text segment we'll miss in that table is the main TEXT segment,
	 * which is not associated with any call structure.
	 *
	 * See re_mi_generate_append_call().
	 */

	htable_insert(mig->subtext, call->sub.routine, call);

	return position;
}

/**
 * Generate a CALL for handling the element vector or the element.
 *
 * Either `ev' or `e' must be NULL;
 *
 * This will register a new routine ID (the opaque address of the vector
 * or its element), emit the code for that element to a new segment and
 * return the position at which the CALL to the routine is made.
 *
 * If the routine ID already exists, then we do not regenerate the code,
 * but rather emit a CALL to the routine ID.  The CALL record will have
 * its "is_def" flag cleared, to indicate that it is not bearing any code but
 * simply a reference to an existing routine.
 *
 * This allows us to blindly generate subroutines for vectors and elements,
 * and if one already exists, we'll just end-up calling that factorized code.
 *
 * @param mig		the generation context
 * @param ev		the element vector to generate
 * @param e			the element to generate
 *
 * @return the position at which the CALL is made.
 */
static uint
re_mi_generate_call(struct re_mi_gen_ctx *mig,
	const re_elemvec_t *ev, const re_element_t *e)
{
	return re_mi_generate_subcall(mig, ev, e, RE_OP_CALL);
}

/**
 * Generate external call (XCALL) to handle look-around assertion.
 *
 * @param mig		the generation context
 * @param ev		the element vector to generate
 * @param negated	whether return status should be negated
 *
 * @return the position at which the XCALL is made.
 */
static uint
re_mi_generate_xcall(struct re_mi_gen_ctx *mig,
	const re_elemvec_t *ev, bool negated)
{
	uint position;

	position = re_mi_generate_subcall(mig, ev, NULL, RE_OP_XCALL);

	if (negated) {
		re_mi_opcode_t op;
		uint8 *pc = re_mi_seg_at(&mig->code->text, position);

		/* Patch opcode lead byte to add the X bit */

		op.code = *pc;
		g_assert(!op.u.v.x);
		op.u.v.x = TRUE;
		*pc = op.code;
	}

	return position;
}

/**
 * Free call structure.
 */
static void
re_mi_generate_free_call(re_mi_call_t *call)
{
	re_mi_call_check(call);

	/* Cleanup call object */

	if (call->is_def) {
		g_assert_log(0 == htable_count(call->sub.fwd),
			"%s(): still has %zu forward JMP instruction%s to resolve",
			G_STRFUNC, PLURAL(htable_count(call->sub.fwd)));

		re_mi_seg_destroy(call->sub.routine);
		htable_free_null(&call->sub.fwd);
	}
	call->magic = 0;
	WFREE(call);
}

/**
 * Iterator on the list of calls to append them to the TEXT segment.
 *
 * This is for the CALL operations to a new routine, hence we do not know
 * its address yet: the code for it is going to be emitted at the current
 * position in the TEXT segment.
 */
static void
re_mi_generate_append_call(void *data, void *udata)
{
	re_mi_call_t *call = data;
	struct re_mi_gen_ctx *mig = udata;

	re_mi_call_check(call);
	re_mi_gen_ctx_check(mig);
	re_mi_seg_check(mig->text);
	re_mi_seg_check(call->parent);

	if (call->is_def) {
		size_t sublen;
		uint dest = re_mi_seg_used(mig->text);

		/*
		 * This is a definition entry, meaning it was the first time we
		 * ever saw that CALL.
		 */

		re_mi_seg_check(call->sub.routine);
		g_assert(mig->text != call->sub.routine);

		/*
		 * If we already have identical bytecode, share it.  That would be
		 * the case when common sub-patterns are re-used and are implemented
		 * via a CALL already (trie matching).
		 */

		if (htable_contains(mig->subpos, call->sub.routine)) {
			dest = pointer_to_uint(
				htable_lookup(mig->subpos, call->sub.routine));
			goto resolve;
		}

		/* Append the TEXT segment of the subroutine to the current segment */

		sublen = re_mi_seg_used(call->sub.routine);
		re_mi_seg_grow(mig->text, sublen);

		mig->text->p =
			mempcpy(mig->text->p, re_mi_seg_base(call->sub.routine), sublen);

		/* Maybe we CALL a routine starting with a JMP: avoid extra hop! */

		dest = re_mi_gen_adjust_destination(mig->text, dest);
		htable_insert(mig->subpos, call->sub.routine, uint_to_pointer(dest));

		/* FALL THROUGH */

	resolve:

		/* Resolve the CALL to this subroutine in our parent */

		re_mi_generate_cross_jmp(call->parent, mig->text,
			call->p_fwd, NULL, call->position, dest);

		/*
		 * Need to update mig->subid with the address of that routine
		 * so that subsequent calls to that routine can be properly
		 * resolved (all the entries in mig->routines).
		 *
		 * Its position field is updated to be the position of the subroutine
		 * we just generated, so that we can easily resolve other calls to it.
		 */

		call->position = dest;
		htable_insert(mig->subid, call->id, call);
	} else {
		re_mi_call_t *subroutine = htable_lookup(mig->subid, call->id);
		re_mi_call_t *parent;
		uint dest;

		re_mi_call_check(subroutine);
		g_assert(subroutine->is_def);	/* Defining structure */

		dest = subroutine->position;	/* Where we generated that routine */

		/*
		 * At the time the CALL to that subroutine (now located at `dest')
		 * was made, we recorded the parent TEXT segment, along with the
		 * position within that segment were the CALL instruction is located.
		 *
		 * If it was the main TEXT segment (i.e. we were not in a subroutine),
		 * then we will not find anything in the mig->subtext hash table,
		 * since that hash records the routine TEXT segments and maps them
		 * to their defining call structure (re_mi_call_t, with is_def=TRUE).
		 * In that case, all is well because the position within the main
		 * segment has not changed.
		 *
		 * However, if we find something in the hash table, then the position
		 * in the segment is still correct, only the code was now appended
		 * to the main TEXT segment (by code above, in the other if() branch).
		 *
		 * To make sure re_mi_seg_at(origin, position) is going to point to
		 * that main TEXT segment, we need to create a new `artefact' segment:
		 * one that seems to start at the current routine position, and not
		 * at the original segment base where we first generated its code!
		 */

		parent = htable_lookup(mig->subtext, call->parent);

		if (parent != NULL) {
			re_mi_seg_t artefact;	/* See comment above */

			re_mi_call_check(parent);
			g_assert(parent->is_def);	/* Defining structure */

			/*
			 * CALL to another subroutine from a subroutine, we need to
			 * fake a text segment for the origin.
			 *
			 * We cannot change the actual segment because it is dynamic
			 * and will be freed later, so we cannot mess with its base
			 * pointer.  Hence we just work on a copy.
			 */

			artefact      = *parent->sub.routine;	/* Struct copy */
			artefact.base = re_mi_seg_at(mig->text, dest);

			/* Resolve the CALL to this subroutine in our parent */

			re_mi_generate_cross_jmp(&artefact, mig->text,
				call->p_fwd, NULL, call->position, dest);
		} else {
			/* Resolve the CALL to this subroutine in our parent */

			g_assert(call->parent == mig->text);	/* Since not in segtext */

			re_mi_generate_cross_jmp(call->parent, mig->text,
				call->p_fwd, NULL, call->position, dest);
		}
	}
}

/**
 * Flag empty string matching.
 */
static void
re_mi_generate_flag_empty(struct re_mi_gen_ctx *mig, size_t minlen)
{
	if (0 == minlen) {
		GENX(debug, "empty string possible");
	} else {
		GENX(debug, str_smsg("min match: %zu byte%s", PLURAL(minlen)));
	}
}

/*
 * Generate byte code for the given OR element, repeated once.
 */
static void
re_mi_generate_or(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	size_t n = 0;
	pslist_t *alt, *final = NULL;
	uint next = 0;
	bool emitted = FALSE;
	size_t minlen = re_element_get_minlen(e);

	re_element_check(e);
	g_assert(RE_TYPE_OR == e->type);

	if (!mig->need_emitted) {
		if (minlen > 1) {
			GENX(need, minlen);
			mig->need_emitted = TRUE;	/* No further emission in this branch */
			emitted = TRUE;				/* Remember we emitted it here */
		}
	}

	/*
	 * The generated code is straightforward, so to speak (because
	 * it jumps around, but it's rather simple).
	 *
	 * For A|B|C, the code looks like:
	 *
	 *       FAIL_JMP <A>		; go match A
	 *       JMP <PA>			; but if it failed, go past A
	 *  <A>: A					; match A
	 *       JMP <PO>			; A matched, go past the OR
	 * <PA>: FAIL_JMP <B>		; A did not match, go match B
	 *       JMP <C>			; but if it failed, go to C
	 *  <B>: B					; match B
	 *       JMP <PO>			; B matched, go past the OR
	 *     ; last alternative, no leading FAIL_JMP
	 *  <C>: C					; match C
	 *     ; if C matched, continue (falling through)
	 * <PO>: ...				; continue matching past the OR
	 *
	 * Within an atomic context, when there is just one item matched in a
	 * branch and it is CEX-able, we can avoid to FAIL_JMP simply to trap
	 * its matching failure and generate more efficient code:
	 *
	 *       CEX				; set C, guard next instruction
	 *       A					; try to match A (plain, no repetitions)
	 *       JMP_C <PO>			; matched, go to end of alternatives
	 *       ...				; match other alternatives
	 * <PO>: ...				; past OR
	 */

	re_mi_generate_flag_empty(mig, minlen);

	PSLIST_FOREACH(re_element_get_alt(e), alt) {
		const re_elemvec_t *aev = alt->data;

		re_elemvec_check(aev);

		n++;

		if (n > 1 && next != 0)
			GEN_TARGET_HERE(next);

		if (NULL == pslist_next(alt)) {
			/* Last alternative */
			GENX(debug, str_smsg("last alternative of %s", re_elem_info(e)));
			re_mi_generate_flag_empty(mig, aev->minlen);
			GEN_ELEMVEC(aev);					/* X */
		} else {
			uint a, b;
			GENX(debug,
				str_smsg("%zu%s alternative of %s", n,
					1 == n ? "st" :
					2 == n ? "nd" :
					3 == n ? "rd" : "th",
					re_elem_info(e))
			);
			re_mi_generate_flag_empty(mig, aev->minlen);

			if (
				e->atomic &&
				2 == aev->ecnt &&	/* second item is NEXT at end of vector */
				RE_N_ONCE == aev->elements[0].repeat &&
				re_mi_element_is_cexable(&aev->elements[0])
			) {
				GEN(cex);							/* CEX */
				GEN_ELEMENT_N(aev, 0);				/* X */
				b = GEN_FORWARD_IF(C, 16BITS);		/* JMP_C <PO> */
				next = 0;							/* signal: no jump */
			} else {
				a = GEN_FAIL_JMP(8BITS);			/* FAIL_JMP <X> */
				next = GEN_FORWARD_JMP(16BITS);		/* JMP <PX> */
				GEN_TARGET_HERE(a);					/* <X>: */
				GEN_ELEMVEC(aev);					/* X */
				b = GEN_FORWARD_JMP(16BITS);		/* JMP <PO> */
			}

			final = pslist_prepend(final, uint_to_pointer(b));
		}
	}

	GENX(debug, str_smsg("end of %s", re_elem_info(e)));

	PSLIST_FOREACH(final, alt) {
		GEN_TARGET_HERE(pointer_to_uint(alt->data));
	}

	pslist_free_null(&final);

	if (emitted)
		mig->need_emitted = FALSE;	/* Reset for other branches */
}

/**
 * Generate byte code for the given expanded class element.
 */
static void
re_mi_generate_expanded_classes(struct re_mi_gen_ctx *mig,
	const re_element_t *e, bool inverted)
{
	const re_class_t *cl = NULL;
	uint classes;

	g_assert(re_element_is_class(e) || re_element_is_posix_class(e));
	g_assert(re_element_is_expanded(e));

	classes = re_element_get_classes(e);

	if (re_element_is_class(e))
		cl = re_element_get_class(e);

	if (NULL == cl) {
		/*
		 * There are only two possible combinations: \d\s and \w\s, when there
		 * are no POSIX classes listed.
		 *
		 * All others are either invalid or get simplified / transformed
		 * at compilation time.
		 */

		if ((RE_CLASS_D | RE_CLASS_S) == classes) {
			GENX(hwcl2, RE_MI_HWCLASS2_DS, inverted);
			return;
		} else if ((RE_CLASS_W | RE_CLASS_S) == classes) {
			GENX(hwcl2, RE_MI_HWCLASS2_WS, inverted);
			return;
		}
		/* There are necessarily some POSIX classes listed, handle them below */
	}
	if (classes != 0) {
		re_class_t *mcl;		/* Merged class */
		int c;
		bool is_new;

		/*
		 * We have both hardwired classes and a class bitmap.
		 * This was originally done so that, during dumping of the tree,
		 * we could present "[a-c\d]" as such.
		 *
		 * Anyway, for now we need to expand the hardwired classes.
		 */

		mcl = re_class_allocate();

		for (c = 0; c < RE_ALPHABET; c++) {
			bool ok = FALSE;

			if (cl != NULL)
				ok = re_class_belongs(cl, c);

			if (!ok) {
				uint i;

				/*
				 * POSIX classes listed, if any, are "ASCII-fied" here, i.e.
				 * limited to matching the ASCII characters they represent.
				 */

				for (i = 0; i <= RE_CLASS_POSIX_END && !ok; i++) {
					if (classes & (1U << i)) {
						ok = (*re_hardwired[i])(c);
					}
				}
			}

			if (ok)
				bit_field_set(mcl->b, c);
		}

		re_class_compact(mcl);

		if (inverted)
			is_new = GENX(inv_class, mcl, e->icase);
		else
			is_new = GENX(class, mcl, e->icase);

		/*
		 * If the merged class was new, it was recorded in a hash table
		 * to ensure we can reuse it later possibly if we see an identical
		 * class.  Hence we cannot free it yet.
		 */

		if (is_new)
			mig->class_free = pslist_prepend(mig->class_free, mcl);
		else
			re_class_free(mcl);
	} else {
		if (inverted)
			GENX(inv_class, cl, e->icase);
		else
			GENX(class, cl, e->icase);
	}
}

/**
 * Generate ID for element vector in routing trie.
 *
 * @return the generated ID.
 */
static size_t
re_mi_generate_trie_nid(struct re_mi_gen_trie_ctx *mit, const trie_node_t *tn)
{
	re_elemvec_t *ev;

	g_assert(trie_node_is_match(tn));

	ev = trie_node_value(tn);
	re_elemvec_check(ev);

	/*
	 * If the element vector contains only one NEXT item, use NULL
	 * as the element vector address: all these items necessarily
	 * point to the same entry after the ROUTE(X) trie.
	 */

	if (1 == ev->ecnt) {
		g_assert(RE_TYPE_NEXT == ev->elements[0].type);
		ev = NULL;
	}

	if (dualhash_contains_value(mit->dt, ev)) {
		const void *id = dualhash_lookup_value(mit->dt, ev);
		return pointer_to_size(id);
	} else {
		size_t id = dualhash_count(mit->dt);
		dualhash_insert_key(mit->dt, size_to_pointer(id), ev);
		return id;
	}
}

/**
 * Fill XJMP table with relative JMP to given offset.
 *
 * @param mig		the generation context
 * @param jtable	the start of the XJMP table
 * @param i			index to fill in the table.
 * @param dest		destination to jump to
 */
static void
re_mi_fill_xjmp(struct re_mi_gen_ctx *mig, uint jtable, size_t i, uint dest)
{
	int offset = dest - jtable;
	uint8 *jr = re_mi_seg_at(mig->text, jtable + 2 * i);

	g_assert(re_mi_seg_has(mig->text, jr, 2));

	poke_le16(jr, offset);
}

/**
 * Fill XJMP table with relative JMP to given offset, but be smart....
 *
 * How smart are we: we look at the destination we are told to jump to,
 * and if that destination is also an unconditional JMP, then we compute
 * its destination and write it directly into the table.
 *
 * This avoids XJMP-ing to a location where we will again unconditionally JMP!
 *
 * @param mig		the generation context
 * @param jtable	the start of the XJMP table
 * @param i			index to fill in the table.
 * @param dest		destination to jump to
 */
static void
re_mi_fill_xjmp_smart(struct re_mi_gen_ctx *mig,
	uint jtable, size_t i, uint dest)
{
	dest = re_mi_gen_adjust_destination(mig->text, dest);
	re_mi_fill_xjmp(mig, jtable, i, dest);
}

/**
 * Hash table iterator to free key strings.
 */
static void
re_mi_free_htkey(const void *key, void *unused_value, void *unused_data)
{
	char *s = deconstify_char(key);

	(void) unused_value;
	(void) unused_data;

	hfree(s);
}

/**
 * Generate byte code for matching a trie node.
 *
 * @param mit		the trie generation context
 * @param tn		the trie node to generate
 */
static void
re_mi_generate_trie_node(struct re_mi_gen_trie_ctx *mit, const trie_node_t *tn)
{
	struct re_mi_gen_ctx *mig = mit->mig;
	const trie_node_t * const *children;
	size_t nchild, i;
	uint jtable = UINT_MAX;		/* Jump table start */
	htable_t *radices = NULL;	/* Maps radix string -> position */
	bool simple_load = FALSE;

	children = trie_node_children(tn, &nchild);

	GENX(debug,
		str_smsg("depth %d, arc for '%s', %zu child%s",
			mit->depth,
			0 == mit->depth ? "root node" : re_format_char(trie_node_arc(tn)),
			PLURAL_CHILD(nchild)));

	if (NULL == children)
		return;

	if (nchild > 1) {
		/* Compute the class matching all the children arcs */
		re_class_t *mcl;		/* Merged class */
		bool is_new, same_route = TRUE;
		size_t id = SIZE_MAX;
		const char *radix = NULL;

		mcl = re_class_allocate();
		simple_load = TRUE;

		for (i = 0; i < nchild; i++) {
			const trie_node_t *cn = children[i];
			bit_field_set(mcl->b, trie_node_arc(cn));

			/*
			 * Check whether all nodes are match points and go to the
			 * same vector (if routing).  If they do, we will be able to
			 * avoid using a TRIE + XJMP combination and instead fallback
			 * to a simple CLASS matching.
			 */

			if (same_route) {
				if (!trie_node_is_match(cn))
					same_route = FALSE;
				else {
					uint d = 0;
					const char *r = trie_node_radix(cn);

					if (mit->dt != NULL)
						d = re_mi_generate_trie_nid(mit, cn);

					if (SIZE_MAX == id) {
						/* First entry we process */
						id = d;
						radix = r;
					} else {
						/* Subsequent entries */
						if (radix != NULL && r != NULL)
							same_route = 0 == strcmp(radix, r);
						else if (radix != NULL && NULL == r)
							same_route = FALSE;
						else if (NULL == radix && r != NULL)
							same_route = FALSE;

						same_route &= d == id;
					}
				}
			}

			/*
			 * Check whether all nodes are match points and have no trailing
			 * radix matching.  If they all do, then instead of using an
			 * XJMP instruction to dispatch a jump to a piece of code that
			 * is going to do a distinct "LD A, value", we can compute an
			 * array of all the possible values and use XLOAD_A to set the
			 * accumulator.
			 */

			if (simple_load) {
				if (!trie_node_is_leaf(cn) || NULL != trie_node_radix(cn))
					simple_load = FALSE;
			}
		}

		g_assert(nchild == bit_field_count_set(mcl->b, 0, RE_ALPHABET - 1));

		re_class_compact(mcl);

		/**
		 * The generated code is:
		 *
		 *      TRIE class			; match class, A set with matching bit index
		 *      XJMP_Z n			; `n' is the amount of children
		 *      <o 1>				; offset is A == 1
		 *      <o 2>				; offset is A == 2
		 *      ...
		 *      <o n-1>				; offset is A == n - 1
		 *    ; code for matching when A == 0
		 *      ...
		 * <o 1>:
		 *    ; code for matching when A == 1
		 *      ...
		 * <o 2>:
		 *    ; code for matching when A == 2
		 *      ...
		 * <o n-1>:
		 *    ; code for matching when A == n - 1
		 *      ...
		 * However when `same_route' is TRUE, it becomes:
		 *
		 *      CLASS class			; match class
		 *
		 * To see examples of code generation for various MATCH/ROUTE tries,
		 * run these:
		 *
		 *    ./re-test -B -E "b|cd.|d"			// ROUTEX (eXact ROUTE)
		 *    ./re-test -B -E "b|cd.|e"			// ROUTEX with DATA class
		 *    ./re-test -B -E "b|c.|d"			// ROUTEX using XLOAD_A
		 *    ./re-test -B -E "b|c.|d."			// ROUTEX using XLOAD_A
		 *    ./re-test -B -E "b|cd|d"			// MATXHX (eXact MATCH)
		 *    ./re-test -B -E "b|cd|cde|d"		// MATXH
		 *    ./re-test -B -E "b|cd|cde|d."		// ROUTE
		 *    ./re-test -B -E "b|cd.|cde|d."	// ROUTE (spot the difference?)
		 */

		if (same_route) {
			is_new = GENX(class, mcl, mit->e->icase);
		} else {
			is_new = GENX(trie, mcl, mit->e->icase);
			if (!simple_load) {
				jtable = GENX(xjmp_z, nchild);
			} else {
				size_t *values;

				/*
				 * We are necessarily a routing trie because if we were not,
				 * then we would have `same_route' set to TRUE when we have
				 * `simple_load' set to TRUE!
				 *
				 * This is more efficient than doing an XJMP_Z, with each
				 * different entry doing a RET_A, and yields more compact code.
				 */

				g_assert(mit->dt != NULL);

				HALLOC_ARRAY(values, nchild);

				for (i = 0; i < nchild; i++) {
					const trie_node_t *cn = children[i];
					values[i] = re_mi_generate_trie_nid(mit, cn);
				}

				GENX(xload_a, nchild, values);
				HFREE_NULL(values);
			}
		}

		/*
		 * If the merged class was recorded in a hash table, then we
		 * cannot free it yet.
		 */

		if (is_new)
			mit->mig->class_free = pslist_prepend(mit->mig->class_free, mcl);
		else
			re_class_free(mcl);

		/*
		 * Create hash table recording the concatenation of the routing ID
		 * (if a routing trie, otherwise empty) and the radix string.
		 *
		 * This allows us to share common code if possible to avoid inflating
		 * the TEXT segment for large tries.
		 */

		radices = htable_create(HASH_KEY_STRING, 0);
	}

	for (i = 0; i < nchild; i++) {
		const trie_node_t *cn = children[i];
		const char *radix = trie_node_radix(cn);
		size_t id = SIZE_MAX;		/* To help spot missed initializations */
		bool shared_leaf = FALSE;

		/* If in a routing trie, get the ID of the element vector */
		if (mit->dt != NULL && trie_node_is_match(cn))
			id = re_mi_generate_trie_nid(mit, cn);

		if (1 == nchild) {
			str_t *s = str_new(0);

			str_putc(s, trie_node_arc(cn));
			if (radix != NULL)
				str_cat(s, radix);

			GENX(debug,
				str_smsg("depth %d, arc for '%s'",
					mit->depth + 1, re_format_char(trie_node_arc(cn))));

			/* MATCH 'x' + "radix" */
			GENX(match, str_2c(s), mit->e->icase);
			str_destroy_null(&s);
		} else {
			/*
			 * Share common leaf code (matching node) if we can.
			 *
			 * This is only possible for leaf matches, when we are
			 * at the longest possible match (for non-exact tries).
			 *
			 * When jtable is UINT_MAX, we have no jump table because
			 * we used CLASS matching for this trie depth, hence sharing
			 * of code is automatic once we get past the CLASS instruction!
			 */

			if (trie_node_is_leaf(cn) && jtable != UINT_MAX) {
				uint here = re_mi_generate_position(mit->mig);
				char *key;

				key = str_cmsg("I=%zuR=%s", id, NULL == radix ? "" : radix);

				if (htable_contains(radices, key)) {
					here = pointer_to_uint(htable_lookup(radices, key));
					HFREE_NULL(key);
					g_assert(i != 0);	/* Because we're sharing code! */
					/* Needs "i - 1" because this is a XJMP_Z instruction */
					re_mi_fill_xjmp(mit->mig, jtable, i - 1, here);
					shared_leaf = TRUE;
				} else {
					/* Remember position for this ID and radix */
					htable_insert(radices, key, uint_to_pointer(here));
				}
			}

			if (!shared_leaf) {
				if (i != 0 && jtable != UINT_MAX) {
					uint here = re_mi_generate_position(mit->mig);
					/* Needs "i - 1" because this is a XJMP_Z instruction */
					re_mi_fill_xjmp(mit->mig, jtable, i - 1, here);
				}

				GENX(debug,
					str_smsg("depth %d, arc for '%s'",
						mit->depth + 1, re_format_char(trie_node_arc(cn))));

				if (radix != NULL) {
					/* MATCH "radix" */
					GENX(match, radix, mit->e->icase);
				}
			}
		}

		if (trie_node_is_match(cn)) {
			if (!shared_leaf) {
				/*
				 * If we are in a routing trie, load element vector ID
				 * into the accumulator via SET_A before returning or
				 * before jumping to the end of the trie if we have
				 * partial matches possible.
				 */

				if (mit->ret) {
					/*
					 * We are an exact trie (MATCHX or ROUTEX elements),
					 * hence we are in a subroutine and we can just return
					 * to either match or dispatch the element vector whose
					 * ID was placed in the A register above.
					 */

					if (mit->dt != NULL && !simple_load)
						GENX(ret_a, id);	/* RET_A id */
					else
						GEN(ret);			/* RET */
				} else {
					uint a = 0, b;

					if (!trie_node_is_leaf(cn)) {
						const re_element_t *e = mit->e;	/* For GEN_FAIL_JMP() */

						/*
						 * This is a partial match, for a non-exact trie.
						 *
						 * We need to record a FAIL point, continue matching
						 * the children node(s) and only if none of them creates
						 * a suitable match will we come back to the FAIL point
						 * and declare a matching for this middle node.
						 */

						a = GEN_FAIL_JMP(8BITS);			/* FAIL_JMP <A> */
					}

					if (mit->dt != NULL)
						GENX(set_a, id);	/* SET_A id */

					/*
					 * This is a potential match: go to the end or the trie
					 * matching code, with the accumulator loaded with the ID
					 * of the vector we still need to match for routing tries.
					 *
					 * We avoid the trailing JMP if this is the last alternative
					 * at the top level.
					 */

					if (0 != mit->depth || i + 1 != nchild || a != 0) {
						b = GEN_FORWARD_JMP(16BITS);		/* JMP <E> */
						mit->jumps =
							pslist_prepend(mit->jumps, uint_to_pointer(b));
					}

					if (!trie_node_is_leaf(cn))
						GEN_TARGET_HERE(a);					/* <A>: */
				}
			}
		}

		if (!trie_node_is_leaf(cn)) {
			mit->depth++;
			re_mi_generate_trie_node(mit, cn);
			mit->depth--;
		}

		if (UINT_MAX == jtable)
			break;		/* All children go to the same route */
	}

	if (radices != NULL) {
		htable_foreach(radices, re_mi_free_htkey, NULL);
		htable_free_null(&radices);
	}
}

/**
 * Generate byte code for matching a trie (either plain or routing).
 *
 * @param mig		the generation context
 * @param e			the element to generate
 */
static void
re_mi_generate_trie_element(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	const trie_node_t *tn;

	g_assert(mig->mit != NULL);
	g_assert(mig->mit->mig == mig);

	tn = trie_root(re_element_get_trie(e));
	re_mi_generate_trie_node(mig->mit, tn);
}

/**
 * Generate byte code for a dispatching after a routing trie.
 *
 * @param mig		the generation context
 * @param e			the element to generate
 */
static void
re_mi_generate_routing_trie(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	struct re_mi_gen_trie_ctx *mit;
	uint jtable;				/* Jump table start */
	size_t n, i, max = 0;
	pslist_t *jpos = NULL;		/* Positions to fill */
	pslist_t *jump = NULL;		/* Forward jumps to the end */
	pslist_t *sl;
	uint end;

	g_assert(re_element_is_routing_trie(e));
	g_assert(mig->mit != NULL);
	g_assert(mig->mit->mig == mig);

	/*
	 * For a routing trie, we need now to route execution to the places
	 * where we can match each of the referenced vectors.  And once
	 * all these vectors have matched, we have them jump past all
	 * the sub-vectors from the trie to continue matching the remaining
	 * of the regex after the trie element (same as for OR elements).
	 *
	 * The only exception is for the NULL vector, which means there is
	 * nothing more to match on this trie branch and we can directly
	 * jump past all the other sub-vectors.
	 *
	 * The trie matching code has loaded the A register with a unique
	 * ID corresponding to an element vector to jump to, hence we can now
	 * use an XJMP instruction to further dispatch each element vector.
	 *
	 * At the end of each element vector, we generate a forward JMP to move
	 * past all these sub-vectors, and we store their position in a list
	 * to be able to resolve them once we have generated all the vectors.
	 *
	 * The generated code is going to look like this:
	 *
	 *      CALL trie					; go match the trie, A loaded
	 *      XJMP A, n					; `n' is the amount of sub-vectors
	 *      <off 0>						; offset for A == 0
	 *      <E>							; offset for A == 1 if vector is NULL
	 *      ...
	 *      <off n-1>					; offset for A == n-1
	 * <off 0>:
	 *      ... Vector 0 ...
	 *      JMP <E>						; done for vector 0
	 *    ; no vector 1 since its value is NULL, it jumps directly to the end
	 * <off 2>:
	 *      ... Vector 2 ...
	 *      JMP <E>						; done for vector 2
	 *      etc.
	 * <off n-1>:
	 *      ... Vector n-1 ...
	 *    ; done for vector n-1
	 * <E>: ...							; match remaining
	 */

	mit = mig->mit;
	n = dualhash_count(mit->dt);
	if (n > 1)
		jtable = GENX(xjmp, n);
	else
		jtable = 0;		/* No need, just one single value */

	/* Locate the index of the last non-NULL element vector */

	for (i = 0; i < n; i++) {
		re_elemvec_t *ev = dualhash_lookup_key(mit->dt, size_to_pointer(i));

		if (ev != NULL)
			max = i;
	}

	/* Generate code for all the non-NULL element vectors */

	for (i = 0; i < n; i++) {
		re_elemvec_t *ev = dualhash_lookup_key(mit->dt, size_to_pointer(i));

		if (NULL == ev) {
			/* Nothing more to match, need to go to the end */
			jpos = pslist_prepend(jpos, NULL);
		} else {
			uint pos = re_mi_generate_elemvec(mig, ev);

			g_assert(pos != 0);	/* NULL is our marker for "goto end" */

			/*
			 * Have to check for the position having moved since we started,
			 * or else it means that nothing was generated for the vector:
			 * it was optimized away as not being able to match.
			 */

			if (re_mi_generate_position(mig) != pos) {
				jpos = pslist_prepend(jpos, uint_to_pointer(pos));

				if (i < max) {
					/* Not the last non-NULL alternative */
					uint a = GEN_FORWARD_JMP(16BITS);	/* JMP <E> */
					jump = pslist_prepend(jump, uint_to_pointer(a));
				}
			}
		}
	}

	/*
	 * We are now at the end of all the alternatives.
	 *
	 * Resolve all the jumps in the jump table and the forward jumps
	 * to here for all but the last alternative.
	 */

	if (n > 1) {
		jpos = pslist_reverse(jpos);		/* Back into increasing order */
		end  = re_mi_generate_position(mig);

		i = 0;
		PSLIST_FOREACH(jpos, sl) {
			uint pos = pointer_to_uint(sl->data);

			if (0 == pos)
				re_mi_fill_xjmp(mig, jtable, i, end);
			else
				re_mi_fill_xjmp_smart(mig, jtable, i, pos);

			i++;
		}

		PSLIST_FOREACH(jump, sl) {
			uint a = pointer_to_uint(sl->data);
			GEN_TARGET_HERE(a);
		}
	}

	pslist_free_null(&jump);
	pslist_free_null(&jpos);
}

/**
 * Generate byte code for a trie element.
 */
static void
re_mi_generate_trie(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	struct re_mi_gen_trie_ctx mit;
	struct re_mi_gen_trie_ctx *omit;
	bool exact, empty;
	const trie_t *t;
	const trie_node_t *rn;
	uint a = 0, b = 0;

	omit = mig->mit;
	mig->mit = &mit;

	ZERO(&mit);
	mit.mig = mig;
	mit.e   = e;

	if (re_element_is_routing_trie(e)) {
		mit.dt = dualhash_new(
			pointer_hash, pointer_eq,	/* keys are IDs */
			pointer_hash, pointer_eq	/* values are element vectors */
		);
	}

	t = re_element_get_trie(e);
	rn = trie_root(t);
	exact = re_element_is_exact_trie(e);
	empty = trie_node_is_match(rn);

	/*
	 * Special-case for a usual case where the empty string is
	 * matched by the trie and it is the only partial matching point.
	 */

	if (empty) {
		/*
		 * Because the trie can match the empty string, but it is otherwise
		 * an exact-matching trie (no other partial matches), the only FAIL
		 * point is going to be here at the top, before invoking the
		 * matching subroutine.
		 *
		 * We attempt to match the strings in the trie first, and only if
		 * it does not work will we resort to an empty match.
		 *
		 * The code is:
		 *
		 *      FAIL_JMP <A>			; start by matching the trie
		 *      JMP <E>					; match the empty string then
		 * <A>: CALL trie				; invoke exact trie subroutine
		 * <E>: ...
		 */

		a = GEN_FAIL_JMP(8BITS);				/* FAIL_JMP <A> */

		/* Act as if trie were exact if only the root node is a partial */
		exact = 1 == re_trie_count_partials(t);

		/*
		 * We can only assume it's a short jump if the trie has only 1
		 * partial match (the empty match at the root): otherwise, we're
		 * not going to issue a CALL instruction, hence we need to reserve
		 * a larger offset for the JMP.  In other words, `exact' was set to
		 * TRUE above.
		 *
		 * Routing trie have an XJMP table following the CALL, so we need to
		 * assume that an 8-bit offset (really 7-bit since it's a forward JMP)
		 * will not be sufficient!
		 */

		if (exact && re_element_is_matching_trie(e))
			b = GEN_FORWARD_JMP(8BITS);			/* JMP <E> */
		else
			b = GEN_FORWARD_JMP(16BITS);		/* JMP <E> */

		GEN_TARGET_HERE(a);						/* <A>: */
	}

	if (exact) {
		mit.ret = TRUE;		/* Use RET at the end of the trie generation */
		re_mi_generate_call(mig, NULL, e);
	} else {
		pslist_t *sl;

		re_mi_generate_trie_element(mig, e);

		/* At the end of the trie, resolve forward jumps to here */

		PSLIST_FOREACH(mit.jumps, sl) {
			uint x = pointer_to_uint(sl->data);
			GEN_TARGET_HERE(x);
		}

		pslist_free_null(&mit.jumps);
	}

	if (mit.dt != NULL && 0 != dualhash_count(mit.dt))
		re_mi_generate_routing_trie(mig, e);

	if (empty)
		GEN_TARGET_HERE(b);					/* <E>: */

	dualhash_destroy_null(&mit.dt);

	mig->mit = omit;
}

/**
 * Generate byte code for the given element, repeated once, in a subroutine.
 *
 * This can only be used for elements whose generation does not cause any
 * backtracking.  Since the calling stack is the TRACK stack and the TSP
 * register is part of the FAIL context we are recording: any backtracking
 * after we called RET from the subroutine would be fatal: when we restore
 * a TSP from which we already returned!  The calling stack would hence
 * be already totally corrupted and another RET would be unpredictable.
 *
 * So we cannot use a subroutine to generate an OR alternative matching.
 * We need something "closed", from which we return once to signify a
 * definitive matching success.  For instance for an exact matching or
 * routing trie!
 *
 * @param mig		the generation context
 * @param e			the element to generate
 */
static void
re_mi_generate_element_sub(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	if (re_element_is_trie(e)) {
		re_mi_generate_trie_element(mig, e);
		return;
	}

	s_error("%s(): cannot use subroutine for %s elements",
			G_STRFUNC, re_type2str(e->type));
}

/**
 * Generate byte code for the given element, repeated once.
 *
 * @param mig		the generation context
 * @param e			the element to generate
 *
 * @return offset within the TEXT segment where we started the element.
 */
static uint
re_mi_generate_element_once(struct re_mi_gen_ctx *mig, const re_element_t *e)
{
	uint start;

	if (RE_N_ONCE != e->repeat)
		GENX(debug, re_type2str(e->type));

	start = re_mi_seg_used(mig->text);

	switch ((re_elem_type_t) e->type) {
	case RE_TYPE_START:        GEN(start);  break;
	case RE_TYPE_END:          GEN(end);    break;
	case RE_TYPE_IS_BOUNDARY:  GEN(wb);     break;
	case RE_TYPE_NOT_BOUNDARY: GEN(not_wb); break;
	case RE_TYPE_ANY:          GEN(any);    break;
	case RE_TYPE_ALL:          GEN(all);    break;
	case RE_TYPE_EMPTY:        /* ignore */ break;
	case RE_TYPE_D_CLASS:      GEN(hwcl_d); break;
	case RE_TYPE_W_CLASS:      GEN(hwcl_w); break;
	case RE_TYPE_S_CLASS:      GEN(hwcl_s); break;
	case RE_TYPE_NOT_D_CLASS:  GEN(hwcl_D); break;
	case RE_TYPE_NOT_W_CLASS:  GEN(hwcl_W); break;
	case RE_TYPE_NOT_S_CLASS:  GEN(hwcl_S); break;
	case RE_TYPE_POSIX_CLASS:
		re_mi_generate_expanded_classes(mig, e, FALSE);
		break;
	case RE_TYPE_NOT_POSIX_CLASS:
		re_mi_generate_expanded_classes(mig, e, TRUE);
		break;
	case RE_TYPE_CHAR:
		GENX(char, re_element_get_char(e), e->icase);
		break;
	case RE_TYPE_TEXT:
		GENX(match, re_element_get_text(e), e->icase);
		break;
	case RE_TYPE_CLASS:
		if (re_element_is_expanded(e))
			re_mi_generate_expanded_classes(mig, e, FALSE);
		else
			GENX(class, re_element_get_class(e), e->icase);
		break;
	case RE_TYPE_INV_CLASS:
		if (re_element_is_expanded(e))
			re_mi_generate_expanded_classes(mig, e, TRUE);
		else
			GENX(inv_class, re_element_get_class(e), e->icase);
		break;
	case RE_TYPE_CLASS_MM:
	case RE_TYPE_INV_CLASS_MM:
		{
			int min, max;
			re_minmax_decode(re_element_get_minmax(e), &min, &max);

			if (RE_TYPE_CLASS_MM == e->type) {
				GENX(class_mm, min, max, e->icase);
			} else {
				GENX(inv_class_mm, min, max, e->icase);
			}
		}
		break;
	case RE_TYPE_BACKREF:
		{
			size_t n = re_element_get_ref_number(e);
			size_t i = re_exec_match_backref_index(mig->re, n);
			g_assert(i != 0);	/* Or it's a RE compilation bug! */
			GENX(debug,
				str_smsg("group #%zu, ref #%zu", n, i));
			GENX(ref, i, e->icase);
		}
		break;
	case RE_TYPE_SUBN:
	case RE_TYPE_SUB:
	case RE_TYPE_GROUP:
	case RE_TYPE_ATOMIC:
		{
			re_elemvec_t *gev = re_element_get_sub(e);

			re_elemvec_check(gev);
			re_mi_generate_elemvec(mig, gev);
		}
		break;
	case RE_TYPE_AHEAD:
	case RE_TYPE_NOT_AHEAD:
		{
			re_elemvec_t *gev = re_element_get_sub(e);

			re_elemvec_check(gev);
			re_mi_generate_xcall(mig, gev, RE_TYPE_NOT_AHEAD == e->type);
		}
		break;
	case RE_TYPE_OR:
		re_mi_generate_or(mig, e);
		break;
	case RE_TYPE_MATCHX:
	case RE_TYPE_ROUTEX:
	case RE_TYPE_MATCH:
	case RE_TYPE_ROUTE:
		re_mi_generate_trie(mig, e);
		break;
	case RE_TYPE_RETURN:
	case RE_TYPE_NEXT:
		/* Ignored, we don't need them */
		break;
	case RE_TYPE_MAX:
		g_assert_not_reached();
	}

	return start;
}

/**
 * Generate element with proper amount of repetitions.
 *
 * @param mig	the generation context
 * @param ev	the element vector containing the element
 * @param n		index of element within vector
 */
static void
re_mi_generate_element(struct re_mi_gen_ctx *mig,
	const re_elemvec_t *ev, size_t n)
{
	re_mi_element_t me;

	re_elemvec_check(ev);
	g_assert(size_is_non_negative(n));
	g_assert(n < ev->ecnt);

	ZERO(&me);
	me.e  = &ev->elements[n];
	me.ev = ev;
	me.n  = n;

	re_mi_generate_repeated(mig, &me);
}

/**
 * Is the element vector composed of elements that can backtrack?
 */
static bool
re_mi_elemvec_can_backtrack(const re_elemvec_t *ev)
{
	size_t i;

	re_elemvec_check(ev);

	for (i = 0; i < ev->ecnt; i++) {
		const re_element_t *e = &ev->elements[i];

		if (re_mi_element_can_backtrack(e))
			return TRUE;
	}

	return FALSE;
}

/**
 * Traversal callback to handle element vector.
 *
 * @return offset within the TEXT segment where we started the element.
 */
static uint
re_mi_generate_elemvec(struct re_mi_gen_ctx *mig, const re_elemvec_t *ev)
{
	size_t i;
	bool emitted = FALSE;
	uint position = re_mi_generate_position(mig);

	re_elemvec_check(ev);

	GENX(debug, str_smsg("start of vector: %s", re_elemvec_info(ev)));

	/*
	 * If we already emitted a NEED instruction before in the recursion,
	 * then it already encompasses this element, so it is useless to
	 * re-emit another NEED.
	 *
	 * Also, if the element vector is only made of non-backtracking elements,
	 * then they're going to match rather quickly and there is no need (aha!)
	 * to emit a NEED for that.
	 */

	if (
		!mig->need_emitted &&
		ev->minlen > 1 &&
		re_mi_elemvec_can_backtrack(ev)
	) {
		GENX(need, ev->minlen);
		mig->need_emitted = TRUE;	/* No further emission in this branch */
		emitted = TRUE;				/* Remember we emitted it here */
	}

	for (i = 0; i < ev->ecnt; i++) {
		const re_element_t *e = &ev->elements[i];

		/*
		 * If the element is a capturing group, we need to enclose its
		 * code between CAPTURE operations.
		 */

		if (RE_TYPE_SUBN == e->type) {
			size_t n = re_element_get_sub_number(e);
			GENX(capture, n, TRUE);		/* Capturing start */
		}

		re_mi_generate_element(mig, ev, i);

		if (RE_TYPE_SUBN == e->type) {
			size_t n = re_element_get_sub_number(e);
			GENX(capture, n, FALSE);	/* Capturing end */
		}

		/*
		 * If the element was a back-reference and we are at the last time
		 * it appears in the pattern, then we can remove it from the set of
		 * back-references, meaning we no longer have to save it in the FAIL
		 * context since it will not be needed anymore by further matching.
		 */

		else if (RE_TYPE_BACKREF == e->type) {
			uint n = re_element_get_ref_number(e);
			const re_element_t *le;		/* Last element where back-ref seen */

			le = htable_lookup(mig->backrefs, uint_to_pointer(n));
			if (le == e) {
				size_t r = re_exec_match_backref_index(mig->re, n);
				htable_remove(mig->backrefs, uint_to_pointer(n));
				GENX(debug, str_smsg("last occurrence of group #%u, ref #%zu",
					n, r));
			}
		}
	}

	if (emitted)
		mig->need_emitted = FALSE;	/* Reset for other branches */

	GENX(debug, str_smsg("end of vector: %s", re_elemvec_info(ev)));

	return position;
}

#undef GEN
#undef GENX

/**
 * Allocates a new re_mi_element_info object.
 */
static re_mi_element_info_t *
re_mi_element_info_allocate(void)
{
	re_mi_element_info_t *ei;

	WALLOC0(ei);
	ei->magic = RE_MI_ELEMENT_INFO_MAGIC;

	return ei;
}

/**
 * Free a re_mi_element_info object.
 */
static void
re_mi_element_info_free(re_mi_element_info_t *ei)
{
	re_mi_element_info_check(ei);

	pslist_free_null(&ei->groups);
	ei->magic = 0;
	WFREE(ei);
}

/**
 * htable iterator to free-up re_mi_element_info values.
 */
static void
re_mi_element_info_free_v(const void *key, void *value, void *data)
{
	re_mi_element_info_t *ei = value;

	re_element_check(key);
	re_mi_element_info_check(ei);

	(void) data;
	re_mi_element_info_free(ei);
}

struct re_mi_generate_analyze_ctx {
	struct re_mi_gen_ctx *mig;	/* Generation context */
	pslist_t *element;			/* Head is the parent element */
};

/**
 * Fetch element info for given element, creating a new one if none already.
 */
static re_mi_element_info_t *
re_mi_generate_analyze_get_eleminfo(
	struct re_mi_generate_analyze_ctx *ctx, const re_element_t *e)
{
	re_mi_element_info_t *ei = htable_lookup(ctx->mig->eleminfo, e);

	if (NULL == ei) {
		ei = re_mi_element_info_allocate();
		htable_insert(ctx->mig->eleminfo, e, ei);
	}

	return ei;
}

#if 0
#define RE_MI_ANALYZE_DEBUG
#endif

/**
 * Entry into an element.
 */
static bool
re_mi_generate_analyze_entry(const void *data, void *udata)
{
	const re_element_t *e = data;
	struct re_mi_generate_analyze_ctx *ctx = udata;

	re_element_check(e);

	/*
	 * We want to track which capturing groups are held under the element.
	 *
	 * When we reach such a capturing group, we associate extra information
	 * to its parent element (if it exists) to record that we saw a capturing
	 * group.
	 */

	if (e->type == RE_TYPE_SUBN) {
		uint n = re_element_get_sub_number(e);
		const re_element_t *pe;		/* Parent element */

		pe = pslist_data(ctx->element);
		if (NULL != pe) {
			re_mi_element_info_t *ei =
				re_mi_generate_analyze_get_eleminfo(ctx, pe);

			ei->groups = pslist_prepend(ei->groups, uint_to_pointer(n));

#ifdef RE_MI_ANALYZE_DEBUG
			s_debug("%s(): inserting group %u into %s",
				G_STRFUNC, n, re_elem_info(pe));
			s_debug("%s():     group %u is %s", G_STRFUNC, n, re_elem_info(e));
#endif
		}
	}

	/*
	 * Keep track of the last element where a given back-reference is used.
	 */

	else if (e->type == RE_TYPE_BACKREF) {
		uint n = re_element_get_ref_number(e);

		htable_insert(ctx->mig->backrefs,
			uint_to_pointer(n), deconstify_pointer(e));
	}

	/*
	 * Maintain a "stack" of elements traversed, so that items in sub vectors
	 * can determine their parent element.
	 */

	ctx->element = pslist_prepend_const(ctx->element, e);
	return TRUE;		/* Process the element */
}

/**
 * Traversal action callback for element during analysis.
 */
static void
re_mi_generate_analyze_action(void *data, void *udata)
{
	const re_element_t *e = data, *pe;
	struct re_mi_generate_analyze_ctx *ctx = udata;
	const re_mi_element_info_t *ei = htable_lookup(ctx->mig->eleminfo, e);

	re_element_check(e);

	pe = pslist_shift(&ctx->element);
	g_assert(pe == e);

	pe = pslist_data(ctx->element);		/* Parent element */

	/*
	 * When we have a parent element, and the current element has extra
	 * information attached to it, propagate its group information into
	 * the parent element, thereby consolidating the set of capturing groups
	 * recursively held under the parent element.
	 */

#ifdef RE_MI_ANALYZE_DEBUG
	if (NULL != pe && ei != NULL) {
		re_mi_element_info_t *pei = re_mi_generate_analyze_get_eleminfo(ctx, pe);
		pslist_t *sl;
		str_t *s = str_new(0);
		s_debug("%s(): CONSOLIDATING %zu groups into parent %s which had %zu",
			G_STRFUNC, pslist_length(ei->groups), re_elem_info(pe),
			pslist_length(pei->groups));
		PSLIST_FOREACH(ei->groups, sl) {
			if (0 != str_len(s))
				STR_CAT(s, ", ");
			str_catf(s, "#%u", pointer_to_uint(sl->data));
		}
		s_debug("%s():    (%s)", G_STRFUNC, str_2c(s));
		str_destroy_null(&s);
	}
#endif

	if (NULL != pe && ei != NULL) {
		re_mi_element_info_t *pei = re_mi_generate_analyze_get_eleminfo(ctx, pe);
		pei->groups = pslist_concat(pei->groups, pslist_copy(ei->groups));
	}
}

/**
 * Analyze the compiled regular expression to pre-compute information
 * that will be perused during code generation.
 *
 * @param mig		the generation context
 * @param ev		the root element vector
 */
static void
re_mi_generate_analyze(struct re_mi_gen_ctx *mig, const re_elemvec_t *ev)
{
	struct re_mi_generate_analyze_ctx ctx;

	ZERO(&ctx);
	ctx.mig = mig;

	re_traverse_once(deconstify_pointer(ev),
		FALSE,								/* pre_e */
		re_mi_generate_analyze_entry,		/* enter */
		re_mi_generate_analyze_action,		/* action */
		FALSE,								/* pre_v */
		NULL,								/* venter */
		NULL,								/* vaction */
		&ctx);

	g_assert(NULL == ctx.element);
}

/**
 * Trailing margin we leave at the end of the TEXT segment.
 *
 * This is large enough for two CLE constants at maximum length (9 bytes each)
 * plus a 2-byte instruction opcode.
 */
#define RE_MI_TEXT_MARGIN	20

/**
 * Generate byte code to match the regular expression, provided it is not a
 * simple one, not requiring a matching engine.
 */
static void
re_mi_generate(re_regex_t *re, bool debug)
{
	struct re_mi_gen_ctx ctx;

	STATIC_ASSERT(RE_OP_MAX  <= 48);	/* Due to chosen instruction format */
	STATIC_ASSERT(RE_MOP_MAX <= 16);	/* Due to chosen instruction format */
	STATIC_ASSERT(RE_IOP_MAX <= 8);		/* Due to chosen instruction format */

	re_regex_check(re);

	if (!re_exec_needs_engine(re))
		return;

	ZERO(&ctx);
	WALLOC0(ctx.code);
	re_mi_seg_init(&ctx.code->text);
	re_mi_seg_init(&ctx.code->data);
	ctx.magic    = RE_MI_GEN_CTX_MAGIC;
	ctx.text     = &ctx.code->text;
	ctx.re       = re;
	ctx.debug    = booleanize(debug);
	ctx.classes  = htable_create_any(re_class_hash, re_class_hash2, re_class_eq);
	ctx.tries    = htable_create_any(re_class_hash, re_class_hash2, re_class_eq);
	ctx.fwd      = htable_create(HASH_KEY_SELF, 0);
	ctx.resolved = htable_create(HASH_KEY_SELF, 0);
	ctx.subid    = htable_create(HASH_KEY_SELF, 0);
	ctx.subtext  = htable_create(HASH_KEY_SELF, 0);
	ctx.eleminfo = htable_create(HASH_KEY_SELF, 0);
	ctx.backrefs = htable_create(HASH_KEY_SELF, 0);
	ctx.subpos   = htable_create_any(re_mi_seg_hash, NULL, re_mi_seg_eq);

	re_mi_gen_inst_debug(&ctx, "start of bytecode");

	re_mi_generate_analyze(&ctx, re->u.compiled);
	re_mi_generate_elemvec(&ctx, re->u.compiled);

	/*
	 * If we have pending jumps to resolve, do it now by emitting a DONE
	 * instruction.  Otherwise, the DONE instruction is not necessary,
	 * as it is implied when we reach the end of the TEXT segment.
	 *
	 * Also if we have pending CALL(s), their code is going to follow
	 * so we need the trailing DONE instruction.
	 */

	if (ctx.resolvable != NULL || ctx.calls != NULL)
		re_mi_gen_inst_done(&ctx);

	/*
	 * If we made CALL(s), we need to resolve them all by appending their
	 * text and updating their jump address.
	 */

	if (ctx.calls != NULL) {
		/* Append routine text to main TEXT segment and resolve their CALL */
		pslist_foreach(ctx.calls,    re_mi_generate_append_call, &ctx);

		/* Resolve other CALL(s) made to these routines */
		pslist_foreach(ctx.routines, re_mi_generate_append_call, &ctx);

		/* Cleanup */
		PSLIST_FOREACH_CALL(ctx.calls,    re_mi_generate_free_call);
		PSLIST_FOREACH_CALL(ctx.routines, re_mi_generate_free_call);
		pslist_free_null(&ctx.calls);
		pslist_free_null(&ctx.routines);
	}

	re_mi_gen_inst_debug(&ctx, "end of bytecode");

	re_mi_gen_inst_debug(&ctx,
		str_smsg("TEXT : %zu byte%s%s",
			PLURAL(re_mi_seg_used(&ctx.code->text) - ctx.comments),
			ctx.comments ? " (without comments)" : "")
	);
	re_mi_gen_inst_debug(&ctx,
		str_smsg("DATA : %zu byte%s (%zu item%s)",
			PLURAL(re_mi_seg_used(&ctx.code->data)),
			PLURAL(htable_count(ctx.classes) + htable_count(ctx.tries)))
	);
	re_mi_gen_inst_debug(&ctx,
		str_smsg("TRACK: %zu byte%s (%u 32-bit word%s)",
			PLURAL(ctx.code->tsp_words * sizeof(uint32)),
			PLURAL(ctx.code->tsp_words))
	);
	if (debug) {
		ulong used = re_mi_seg_used(&ctx.code->text) + 3 /* DEBUG op */;
		str_t *s = str_msg("TEXT: %zu byte%s total with debug", PLURAL(used));

		re_mi_gen_inst_debug(&ctx,
			str_smsg("TEXT: %zu byte%s total with debug",
				PLURAL(used + str_len(s)))
		);
		str_destroy_null(&s);
	}

	g_assert_log(0 == htable_count(ctx.fwd),
		"%s(): still has %zu forward JMP instruction%s to resolve",
		G_STRFUNC, PLURAL(htable_count(ctx.fwd)));

	/*
	 * Final optimization of JMP within the segment to make sure we do not
	 * perform costly hops at runtime if we can avoid them by resolving their
	 * final destination at compile time!
	 */

	re_mi_resolve_optimize(&ctx);

	/*
	 * To speed up execution time, we're leaving a margin of 12 bytes
	 * at the end of the TEXT segment.  This is enough to let us
	 * process common instructions without having to check whether there
	 * is room for extra arguments before fetching them.
	 *
	 * Reducing the amount of tests we do at runtime to the bare minimum
	 * is helping overall matching speed.
	 *
	 * The DATA segment is more infrequently accessed, and we have to
	 * validate the data we read anyway, so we do not leave any trailing
	 * margin there.
	 */

	re_mi_seg_shrink(&ctx.code->text, RE_MI_TEXT_MARGIN);
	re_mi_seg_shrink(&ctx.code->data, 0);

	re->bytecode = ctx.code;

	htable_foreach(ctx.eleminfo, re_mi_element_info_free_v, NULL);
	htable_free_null(&ctx.eleminfo);
	htable_free_null(&ctx.backrefs);
	htable_free_null(&ctx.classes);
	htable_free_null(&ctx.tries);
	htable_free_null(&ctx.fwd);
	htable_free_null(&ctx.resolved);
	htable_free_null(&ctx.subid);
	htable_free_null(&ctx.subtext);
	htable_free_null(&ctx.subpos);
	re_mi_repeat_free_null(&ctx.repeats);
	PSLIST_FOREACH_CALL(ctx.class_free, re_class_free);
	pslist_free_null(&ctx.class_free);
}

/**
 * Free generated bytecode.
 */
static void
re_mi_free(re_mi_code_t *code)
{
	re_mi_seg_free(&code->text);
	re_mi_seg_free(&code->data);
	WFREE(code);
}

/**
 * Free bytecode and nullify its pointer.
 */
static void
re_mi_free_null(re_mi_code_t **code_ptr)
{
	if (*code_ptr != NULL) {
		re_mi_code_t *code = *code_ptr;
		re_mi_free(code);
		*code_ptr = NULL;
	}
}

/***
 *** ================== Bytecode Disassembly ===================
 ***/

/**
 * Internal operation names are summarized into 5-char long (at most)
 * mnemonics, so that we can nicely align the operations and the arguments.
 * This means we are not actually using the internal opcode names defined
 * in this file for long operations.  But disassembly is only used for
 * debugging and verification of correctness of the generated code, hence it
 * does not matter that much.  One gets used to short mnemonics.
 *
 * Some mnemonics (and the general formatting of the instructions) will be
 * reminiscent of the Z80 assembly.  This is no accident, as I have spent
 * countless hours writing code for the Z80. ;-)
 *
 * For loading instructions the convention is that the destination comes
 * first and the source last.  And () refers to a de-reference of a pointer
 * or of a register, so (1) refers to the value at memory 1 and (FSP) refers
 * to the value pointed-at by the FSP register, whilst n(FSP) refers to
 * the value of (FSP + n), which is actually different of what the Z80 used
 * (in the Z80, relative indexing was only possible through the IX and IY
 * registers).
 *
 * For instance,
 *
 * 		LD (1), 4
 *
 * loads the value 4 into the memory address 1.  And LD stands for LOAD, but
 * is abridged to the minimum, since assembly is fond of short mnemonics, to
 * add to the cryptic mythology.
 *
 * Within the context of the Matching Interpreter, memory addresses are
 * referring to 1-based indices into an array of 32-bit values.
 */

/**
 * Elaborate on JMP offset specification.
 *
 * @param cs	the CS bits on the JMP instruction, or similar
 *
 * @return comment explaining the type of offsetting the jump will do
 */
static const char *
re_mi_jmp_comment(uint8 cs)
{
	switch ((re_op_cs_t) cs) {
	case RE_OP_CS_EMPTY:  return "absolute";
	case RE_OP_CS_8BITS:  return "8-bit";
	case RE_OP_CS_16BITS: return "16-bit";
	case RE_OP_CS_CLE:    return "CLE, is not expected!";
	}

	return "invalid CS";
}

/**
 * Description of a minimal opcode for disassembly.
 *
 * These opcodes are either argument-less (e.g. NOP) or have at most one
 * implied argument (e.g. POP_A is operation "POP" with argument "A").
 */
static struct re_mi_mop_desc {
	const char *op;			/* Operation name */
	const char *arg;		/* Operation argument, NULL if none */
	int value;				/* For making sure the array is right */
} re_mi_mop_desc[RE_MOP_MAX] = {
#define MOP(x)		RE_MOP_ ## x

	{ "NOP",	NULL,			MOP(NOP)		},
	{ "DONE",	NULL,			MOP(DONE)		},
	{ "FAIL",	NULL,			MOP(FAIL)		},
	{ "START",	NULL,			MOP(START)		},
	{ "END",	NULL,			MOP(END)		},
	{ "ZWA",	"\\b",			MOP(WB)			},	/* Zero Width Assert */
	{ "ZWA",	"\\B",			MOP(NOT_WB)		},	/* Zero Width Assert */
	{ "RET",	NULL,			MOP(RET)		},
	{ "PUSH",	"FSP",			MOP(PUSH_FSP)	},
	{ "POP",	"A",			MOP(POP_A)		},
	{ "ANY",	NULL,			MOP(ANY)		},
	{ "ALL",	NULL,			MOP(ALL)		},
	{ "LD",		"-1(FSP), TP",	MOP(UPDATE_TP)	},
	{ "POFP",	NULL,			MOP(DROP_FAIL)	},
	{ "POP",	"FSP",			MOP(POP_FSP)	},
	{ "CEX",	NULL,			MOP(CEX)		},

#undef MOP
};

/**
 * Description of an indexed opcode for disassembly.
 *
 * These opcodes all have an index following their operand.  However, they
 * can also bear an implied operand as well (e.g. INC_A is shown as the
 * "INCLD" operation, with the "A" operand).
 */
static struct re_mi_iop_desc {
	const char *op;			/* Operation name */
	const char *arg;		/* Operation implied argument, NULL if none */
	int value;				/* For making sure the array is right */
} re_mi_iop_desc[RE_IOP_MAX] = {
#define IOP(x)		RE_IOP_ ## x

	{ "LD",		"(%u), TP",		IOP(SAVE_TP)	},
	{ "EQ",		"TP, (%u)",		IOP(CMP_TP)		},
	{ "LD",		"(%u), 0",		IOP(CLEAR)		},
	{ "INCLD",	"A, (%u)",		IOP(INC_A)		},
	{ "LD",		"A, (%u)",		IOP(LOAD_A)		},
	{ "LT",		"TP, (%u)",		IOP(LT_TP)		},
	{ "LD",		"(%u), FSP",	IOP(SAVE_FSP)	},
	{ "LD",		"-1(%u), TP",	IOP(UPDATE_FTP)	},

#undef IOP
};

static const char *
re_mi_op_jmp_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	re_op_cs_t cs = ir->cs;
	return (RE_OP_CS_8BITS == cs || RE_OP_CS_16BITS == cs) ? "JR" : "JP";
}

static const char *
re_mi_op_fail_jmp_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	re_op_cs_t cs = ir->cs;
	/* Fail Point Jump */
	return (RE_OP_CS_8BITS == cs || RE_OP_CS_16BITS == cs) ? "FPJR" : "FPJP";
}

static const char *
re_mi_op_call_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	re_op_cs_t cs = ir->cs;
	return (RE_OP_CS_8BITS == cs || RE_OP_CS_16BITS == cs) ? "CALLR" : "CALL";
}

static const char *
re_mi_op_capture_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	if (ir->z)
		return ir->x ? "RE" : "RS";		/* Ref End / Ref Start */
	else
		return ir->x ? "GE" : "GS";		/* Group End / Group Start */
}

static const char *
re_mi_op_repeat_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);

	return ir->x ? "REPC" : "REP";
}

static const char *
re_mi_op_fail_op_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	/* Fail In/Out Word/Group/Ref */
	switch (ir->cs) {
	case RE_OP_CS_EMPTY: return ir->x ? "POW" : "PUW";
	case RE_OP_CS_8BITS: return ir->x ? "POG" : "PUG";
	case RE_OP_CS_CLE:   return ir->x ? "POR" : "PUR";
	default:             return "??";
	}
}

static const char *
re_mi_op_djmp_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	return ir->z ? "DJZ" : "DJNZ";
}

static const char *
re_mi_op_lt_a_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	return ir->x ? "CP" : ir->z ? "EQ" : "LT";
}

static const char *
re_mi_op_match_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);

	return RE_OP_CS_EMPTY == ir->cs ? "CHAR" : "MATCH";
}

static const char *
re_mi_op_xjmp_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);

	return ir->z ? "ZXJR" : "XJR";
}

static const char *
re_mi_op_xcall_opname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);

	/* Look Around zero-width assertions / tests */

	if (ir->x)
		return ir->z ? "NLAZ" : "NLA";
	else
		return ir->z ? "LAZ" : "LA";
}

static const char *
re_mi_op_hwcl_argname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	str_t *s = str_private(G_STRFUNC, 4);

	str_printf(s, "\\%c", re_mi_hwc2char(ir->cs, ir->x));

	return str_2c(s);
}

static const char *
re_mi_op_hwcl2_argname(const void *p)
{
	const re_mi_inst_t *ir = re_mi_decode_inst_full(p);
	str_t *s = str_private(G_STRFUNC, 4);

	str_printf(s, "%s", re_mi_hwc2str(ir->flg, ir->x));

	return str_2c(s);
}

/**
 * Description of a general opcode.
 *
 * The meaning of the instruction is possibly affected by the presence of
 * the X and Z bits.  It can be spelled-out completely differently in the
 * presence of the X bit (e.g. CAPTURE).
 *
 * At some other time, the X and Z bits are used to express a combined
 * condition.  For instance, JMP.X_Z indicates a jump on the "NZ" condition,
 * which will then appear as an "argument" to the jump opcode.
 *
 * The CS bits can also influence the name, for instance JMP with CS=EMPTY
 * is an absolute jump, displayed as "JP", otherwise it is a relative jump
 * shown as "JR".
 *
 * Due to this complexity, the operation name is either static or computed
 * via a callback routine, given a pointer to a re_mi_inst_t object and
 * producing a static string.
 *
 * Likewise for the operands that cannot be statically computed, we have a
 * callback routine supplied.
 */
static struct re_mi_op_desc {
	int value;				/* For making sure the array is right */
	const char *op;			/* Operation name */
	stringify_fn_t cop;		/* Callback generating operation name if complex */
	const char *arg;		/* Argument name if X and Z bits clear */
	const char *argx;		/* Argument name if X bit set */
	const char *argz;		/* Argument name if Z bit set */
	const char *argzx;		/* Argument name if Z and X bits set */
	stringify_fn_t carg;	/* Callback generating argument name if complex */
} re_mi_op_desc[RE_OP_MAX] = {
#define OP(x)		RE_OP_ ## x

#define PLAIN()		NULL, NULL
#define ALIAS(x)	#x,   NULL
#define CNAME(x)	NULL, re_mi_op_ ## x ## _opname

#define NO_ARGS()	NULL,   NULL,   NULL,   NULL,   NULL
#define CARGS(x)	NULL,   NULL,   NULL,   NULL,   re_mi_op_ ## x ## _argname
#define X_ARGS(n,x)	#n,     #x,     NULL,   NULL,   NULL
#define SIX_ARGS()	"S",    "SX",   "I",    "IX",   NULL,
#define A_ARGS()	"A, ",  "A, ",  "A, ",  NULL,   NULL,
#define TP_ARGS()	"TP, ", "TP, ", "TP, ", "TP, ", NULL,
#define AA_ARGS()	"A, ",  "A, ",  "A, ",  "A, ",  NULL,
#define ZX_ARGS()	"NZ, ", "NC, ", "Z, ",  "C, ",  NULL

	{ OP(ZERO),			PLAIN(),			NO_ARGS() 		},
	{ OP(INDEX),		PLAIN(),			NO_ARGS() 		},
	{ OP(JMP),			CNAME(jmp),			ZX_ARGS() 		},
	{ OP(FAIL_JMP),		CNAME(fail_jmp),	NO_ARGS() 		},
	{ OP(HWCL),			ALIAS(CLA),			CARGS(hwcl)		},
	{ OP(MATCH),		CNAME(match),		X_ARGS(S,I)		},
	{ OP(CLASS),		ALIAS(CLA),			SIX_ARGS()		},
	{ OP(UJMP),			CNAME(jmp),			NO_ARGS()		},
	{ OP(DJMP),			CNAME(djmp),		NO_ARGS()		},
	{ OP(REF),			PLAIN(),			X_ARGS(S,I)		},
	{ OP(LT_A),			CNAME(lt_a),		A_ARGS()		},
	{ OP(CALL),			CNAME(call),		NO_ARGS()		},
	{ OP(TRIE),			ALIAS(CLB),			SIX_ARGS()		},
	{ OP(FAIL_OP),		CNAME(fail_op),		NO_ARGS()		},
	{ OP(XJMP),			CNAME(xjmp),		A_ARGS()		},
	{ OP(ESCAPE),		PLAIN(),			NO_ARGS()		},
	{ OP(NEED),			PLAIN(),			NO_ARGS()		},
	{ OP(DEBUG),		PLAIN(),			NO_ARGS()		},
	{ OP(LOAD),			ALIAS(LD),			NO_ARGS()		},
	{ OP(XCALL),		CNAME(xcall),		NO_ARGS()		},
	{ OP(HWCL2),		ALIAS(CLA),			CARGS(hwcl2)	},
	{ OP(F_PUSH_TRACK),	ALIAS(PUW),			NO_ARGS()		},
	{ OP(F_POP_TRACK),	ALIAS(POW),			NO_ARGS()		},
	{ OP(F_PUSH_GROUP),	ALIAS(PUG),			NO_ARGS()		},
	{ OP(F_POP_GROUP),	ALIAS(POG),			NO_ARGS()		},
	{ OP(F_PUSH_REF),	ALIAS(PUR),			NO_ARGS()		},
	{ OP(F_POP_REF),	ALIAS(POR),			NO_ARGS()		},
	{ OP(F_DROP_WORD),	ALIAS(POFW),		NO_ARGS()		},
	{ OP(SET_A),		ALIAS(LD),			AA_ARGS()		},
	{ OP(XLOAD_A),		ALIAS(XLD),			AA_ARGS()		},
	{ OP(CAPTURE),		CNAME(capture),		NO_ARGS()		},
	{ OP(REPEAT),		CNAME(repeat),		NO_ARGS()		},
	{ OP(SUB_TP),		ALIAS(SUB),			TP_ARGS()		},
	{ OP(ADD),			ALIAS(ADD),			NO_ARGS()		},
	{ OP(UPDATE_FPC),	ALIAS(LD),			NO_ARGS()		},
	{ OP(RG_A),			ALIAS(RG),			A_ARGS()		},
	{ OP(RET_A),		ALIAS(RET),			NO_ARGS()		},
	{ OP(REW_TP),		ALIAS(REW),			TP_ARGS()		},

#undef OP
#undef PLAIN
#undef ALIAS
#undef CNAME
#undef CARGS
#undef NO_ARGS
#undef X_ARGS
#undef SIX_ARGS
#undef A_ARGS
#undef TP_ARGS
#undef ZX_ARGS
};

/**
 * An first level instruction disassembly, where we store the instruction
 * mnemonic (up to 5 letters) and the argument(s), if any.
 *
 * These strings can be held in a static buffer.
 */
struct re_mi_inst_str {
	const char *mnemo;			/* Up to 5-letter mnemonic */
	const char *arg;			/* Argument (NULL if none) */
};

/**
 * Fill `out' with disassembled minimal instruction.
 */
static void
re_mi_inst_mop_disassemble(struct re_mi_inst_str *out, const re_mi_inst_t *ir)
{
	const struct re_mi_mop_desc *mop;

	re_mi_decode_inst_full(ir);

	g_assert(RE_OP_ZERO == ir->opcode);
	g_assert((uint) ir->mop < RE_MOP_MAX);

	mop = &re_mi_mop_desc[ir->mop];

	g_assert_log(mop->value == ir->mop,
		"%s(): expected %s at re_mi_mop_desc[%d], entry is actually for %s (%d)",
		G_STRFUNC,
		re_mi_mop2str(ir->mop), ir->mop,
		re_mi_mop2str(mop->value), mop->value);

	out->mnemo = mop->op;
	out->arg   = mop->arg;
}

/**
 * Fill `out' with disassembled indexed instruction.
 */
static void
re_mi_inst_iop_disassemble(struct re_mi_inst_str *out, const re_mi_inst_t *ir)
{
	const struct re_mi_iop_desc *iop;
	str_t *s = str_private(G_STRFUNC, 24);
	uint i;

	re_mi_decode_inst_full(ir);

	g_assert(RE_OP_INDEX == ir->opcode);
	g_assert((uint) ir->iop < RE_IOP_MAX);

	iop = &re_mi_iop_desc[ir->iop];

	g_assert_log(iop->value == ir->iop,
		"%s(): expected %s at re_mi_iop_desc[%d], entry is actually for %s (%d)",
		G_STRFUNC,
		re_mi_iop2str(ir->iop), ir->iop,
		re_mi_iop2str(iop->value), iop->value);

	/*
	 * All these instructions use the same argument encoding:
	 *
	 * If the S bit is set, the value comes after the 1-byte opcode and
	 * is held in 1 byte.
	 *
	 * If the S bit is clear, the value comes after the 1-byte opcode and
	 * is held in 2 bytes.
	 */

	if (ir->s)
		i = ir->ip[1];		/* [1] to skip the 1-byte opcode */
	else
		i = peek_le16(&ir->ip[1]);

	out->mnemo = iop->op;


	if (iop->arg != NULL) {
		G_IGNORE_PUSH(-Wformat-nonliteral)
		/* It's OK here to have a non-literal formatting argument iop->arg */
		str_printf(s, iop->arg, i + 1);	/* We encode i - 1 in instruction */
		G_IGNORE_POP
		out->arg = str_2c(s);
	} else {
		out->arg = NULL;
	}
}

/**
 * Fill `out' with disassembled general instruction.
 */
static void
re_mi_inst_op_disassemble(struct re_mi_inst_str *out, const re_mi_inst_t *ir)
{
	const struct re_mi_op_desc *op;

	re_mi_decode_inst_full(ir);

	g_assert(ir->opcode > RE_OP_INDEX);
	g_assert(ir->opcode < RE_OP_MAX);

	op = &re_mi_op_desc[ir->opcode];

	g_assert_log(op->value == ir->opcode,
		"%s(): expected %s at re_mi_op_desc[%d], entry is actually for %s (%d)",
		G_STRFUNC,
		re_mi_op2str(ir->opcode), ir->opcode,
		re_mi_op2str(op->value), op->value);

	out->mnemo =
		op->cop != NULL ? op->cop(ir) :
		op->op  != NULL ? op->op :
		re_mi_op2str(ir->opcode);

	out->arg =
		op->carg != NULL ? op->carg(ir) :
		!(ir->z | ir->x) ? op->arg :
		 (ir->z & ir->x) ? op->argzx :
		 (ir->z)         ? op->argz :
		 (ir->x)         ? op->argx :
		 "??";
}

/**
 * Disassemble instruction held in the given Instruction Register by
 * filling the supplied structure.
 *
 * @param out	where output is written to
 * @param ir	the instruction register (minimally filled, as during execution)
 */
static void
re_mi_inst_disassemble(struct re_mi_inst_str *out, const re_mi_inst_t *ir)
{
	if (RE_OP_ZERO == ir->opcode) {
		re_mi_inst_mop_disassemble(out, ir);
	} else if (RE_OP_INDEX == ir->opcode) {
		re_mi_inst_iop_disassemble(out, ir);
	} else {
		re_mi_inst_op_disassemble(out, ir);
	}
}

/**
 * Get text pointed at by given pointer, of length `len'.
 *
 * We only read the data that lie within the segment boundaries.
 *
 * @param seg	the segment where data lie
 * @param p		where we read from the segment
 * @param len	amount of data to read
 *
 * @return static buffer string whose content is the bytes read.
 */
static const char *
re_mi_get_text(const re_mi_seg_t *seg, const uint8 *p, size_t len)
{
	str_t *s = str_private(G_STRFUNC, 64);

	str_reset(s);

	if (re_mi_seg_has(seg, p, len)) {
		while (len--)
			str_putc(s, *p++);
	}

	return str_2c(s);
}

/**
 * Context used during disassembly.
 */
struct re_mi_dump_ctx {
	re_mi_code_t *bc;			/* Bytecode */
	htable_t *labels;			/* Maps PC to number */
	ostream_t *os;				/* Output stream */
	uint num;					/* Next label number */
	bool show;					/* If TRUE, we're the second pass */
};

#define RE_MI_BYTES	18		/* Space for displaying instruction bytes */

/*
 * If we are at a known label, display information before the instruction.
 *
 * @param dc		the dumping context
 * @param pc		the current instruction start
 */
static void
re_mi_dump_label(struct re_mi_dump_ctx *dc, const uint8 *pc)
{
	uint num = pointer_to_uint(htable_lookup(dc->labels, pc));

	/* Labels start from 1, so a 0 (NULL value) means not a label position */

	if (num != 0)
		ostream_printf(dc->os, "%-*s<L%d>:\n", RE_MI_BYTES - 2, "", num);
}

/**
 * Dump character class, returning static string.
 */
static const char *
re_mi_dump_bit_class(int min, int max, int offset, const bit_field_t *b,
	bool inverted)
{
	str_t *s = str_private(G_STRFUNC, RE_ALPHABET / 2);
	re_class_t cl;
	ostream_t *os;

	ZERO(&cl);
	cl.magic  = RE_CLASS_MAGIC;
	cl.min    = min;
	cl.max    = max;
	cl.offset = offset;
	cl.b      = deconstify_pointer(b);

	str_printf(s, "[%s", inverted ? "^" : "");

	os = ostream_open_str(s);
	re_dump_string(re_class2str(&cl), TRUE, os);
	ostream_close(os);

	str_putc(s, ']');

	return str_2c(s);
}

/**
 * Dump byte-array class, returning static string.
 */
static const char *
re_mi_dump_byte_class(int min, int max, const uint8 *b)
{
	str_t *s = str_private(G_STRFUNC, RE_ALPHABET / 2);
	ostream_t *os;

	str_reset(s);
	str_putc(s, '[');

	os = ostream_open_str(s);
	re_dump_string(re_bclass2str(min, max, b), TRUE, os);
	ostream_close(os);

	str_putc(s, ']');

	return str_2c(s);
}

/**
 * Dump min-max class, returning static string.
 */
static const char *
re_mi_dump_minmax(int min, int max, bool inverted)
{
	str_t *s = str_private(G_STRFUNC, 16);
	ostream_t *os;

	str_printf(s, "[%s", inverted ? "^" : "");

	os = ostream_open_str(s);
	re_dump_minmax(min, max, os);
	ostream_close(os);

	str_putc(s, ']');

	return str_2c(s);
}

/**
 * Register destination so that we can output a label for it.
 *
 * @param dc	the dumping context
 * @param dest	the jump destination address in the TEXT segment
 */
static void
re_mi_dump_record_dest(struct re_mi_dump_ctx *dc, const uint8 *dest)
{
	if (!htable_contains(dc->labels, dest))
		htable_insert(dc->labels, dest, uint_to_pointer(dc->num++));
}

/**
 * Compute nice formatting of jump destination, using a label if we can!
 *
 * @param dc		the dumping context
 * @param dis		the string used to disassemble the instruction
 * @param dest		the jump destination address in the TEXT segment
 * @param cs		CS encoding for the destination
 * @param offset	offset seen in instruction (for relative jumps)
 *
 * @return pointer to static string containing comment for formatted jump
 * destination.
 */
static const char *
re_mi_dump_jump_dest(const struct re_mi_dump_ctx *dc,
	str_t *dis, const uint8 *dest, re_op_cs_t cs, int offset)
{
	str_t *com = str_private(G_STRFUNC, 16);
	const re_mi_seg_t *text = &dc->bc->text;
	uint num = pointer_to_uint(htable_lookup(dc->labels, dest));
	const char *jc;

	if (num != 0) {
		str_catf(dis, "<L%d>:%04X", num, re_mi_seg_offset(text, dest));
	} else if (RE_OP_CS_EMPTY == cs)
		str_catf(dis, "%04X", re_mi_seg_offset(text, dest));
	else
		str_catf(dis, "%+d", offset);	/* pass #1 missed it? */

	jc = re_mi_jmp_comment(cs);

	if (RE_OP_CS_EMPTY == cs) {
		str_printf(com, "%04X (%s)", re_mi_seg_offset(text, dest), jc);
	} else if (num != 0) {
		str_printf(com, "%+d (%s)", offset, jc);
	} else {
		/* If this shows up, pass #1 missed this spot! */
		str_printf(com, "%+d (%s) = %04X",
			offset, jc, re_mi_seg_offset(text, dest));
	}

	return str_2c(com);
}

/*
 * Compute and validate jump destination.
 *
 * @param dc		the dumping context
 * @param dest		where to write final jump destination in TEXT
 * @param ir		instruction being processing, for logging purposes
 * @param pc		PC at the end of the instruction
 * @param cs		CS-encoding for the JMP offset
 * @param offset	read JMP offset argument for the instruction
 *
 * @return TRUE if jump destination is OK.
 */
static bool
re_mi_dump_valid_dest(const struct re_mi_dump_ctx *dc, const uint8 **dest,
	const re_mi_inst_t *ir, const uint8 *pc, re_op_cs_t cs, int offset)
{
	const re_mi_seg_t *text = &dc->bc->text;

	if (RE_OP_CS_EMPTY == cs) {
		if (!re_mi_seg_is_valid_pos(text, offset)) {
			if (dc->show) {
				ostream_printf(dc->os,
					"invalid absolute destination %04X "
					"for %s at %04X\n",
					offset, re_mi_inst_opname(ir),
					re_mi_seg_offset(text, ir->ip));
			}
			return FALSE;
		}
		*dest = re_mi_seg_at(text, offset);	/* Absolute */
	} else {
		*dest = pc + offset;				/* Relative */
		if (!re_mi_seg_is_valid(text, *dest)) {
			if (dc->show) {
				ostream_printf(dc->os,
					"invalid destination %04X for %s at %04X\n",
					re_mi_seg_offset(text, *dest),
					re_mi_inst_opname(ir), re_mi_seg_offset(text, ir->ip));
			}
			return FALSE;
		}
	}

	return TRUE;	/* OK, destination is valid */
}

/**
 * Generate disassembly of generated bytecode to given stream.
 *
 * There are two passes made on the code:
 *
 * - Pass 1 is done with show = FALSE, to spot positions that are the
 *   targets of JMP statements, so that we can then dispplay them
 *   symbolically to ease reading of the disassembled output.
 *
 * - Pass 2, done with show = TRUE, emits the actual dumping.
 *
 * @param dc		the dumping context
 * @param show		whether to show output or just spot labels
 */
static void
re_mi_dump(struct re_mi_dump_ctx *dc)
{
	const re_mi_seg_t *text = &dc->bc->text;
	const re_mi_seg_t *data = &dc->bc->data;
	bool show = dc->show;
	const uint8
		*p    = re_mi_seg_base(text),
		*pend = re_mi_seg_end(text);
	str_t *s = NULL, *b = NULL;

	if (show) {
		s = str_new(0);
		b = str_new(0);
	}

	while (p < pend) {
		re_mi_inst_t inst;
		size_t i;
		const char *comment = NULL;
		int offset;
		size_t value;
		size_t characters = 0, tracks = 0, xoffsets = 0, entries = 0;

		if (!re_mi_decode_inst(&inst, text, p))
			goto fault;

		p = inst.pc;

		/*
		 * The %*s below reserves room for dumping instruction bytes.
		 *
		 * With 2 hex digits plus 1 space, that is 3 chars per byte so we
		 * have room for 6 bytes total.  We will display a "+" at the end
		 * to flag that we're masking some bytes, if we have more for the
		 * instruction.
		 */

		if (show) {
			struct re_mi_inst_str is;

			re_mi_inst_disassemble(&is, &inst);
			str_printf(s, "%04X %*s%-5s ",
				re_mi_seg_offset(text, inst.ip), RE_MI_BYTES, "", is.mnemo);
			if (is.arg != NULL)
				str_cat(s, is.arg);
		}

		switch ((re_mi_op_t) inst.opcode) {
		case RE_OP_DEBUG:
			/* Special, don't show the DEBUG opcode, just print its comment */
			p = re_mi_decode_immediate(p, inst.cs, 1, &value);
			if G_UNLIKELY(p + value > pend) goto fault;
			if (show) {
				comment = re_mi_get_text(text, p, value);
				re_mi_dump_label(dc, inst.ip);
				ostream_printf(dc->os, "%-*s; %s",
					3 + RE_MI_BYTES, "", comment);
			}
			p += value;
			goto next;
		case RE_OP_ZERO:
			/* Special -- 1-byte minimal instruction */
			switch (inst.mop) {
			case RE_MOP_DROP_FAIL: comment = "drop FAIL point";    break;
			case RE_MOP_UPDATE_TP: comment = "FAIL update TP";     break;
			case RE_MOP_CEX:       comment = "C set, guards next"; break;
			}
			goto ok;
		case RE_OP_INDEX:
			/* Special -- 1-byte instruction + 1 or 2 bytes operand */
			if (inst.s) {
				if (pend - p < 1) goto fault;
				value = *p++;
			} else {
				if (pend - p < 2) goto fault;
				value = peek_le16(p);
				p += 2;
			}
			if (show) {
				const char *x = NULL;
				size_t n = value;
				const char *invalid = "";

				if (n >= dc->bc->tsp_words)
					invalid = "*** ";		/* Flag invalid word visually */

				n++;	/* Addresses we show start at 1 */

				switch ((re_mi_iop_t) inst.iop) {
				case RE_IOP_SAVE_TP: x = str_smsg("(%zu) <- TP", n);      break;
				case RE_IOP_CMP_TP:  x = str_smsg("Z <- TP == (%zu)", n); break;
				case RE_IOP_CLEAR:   x = str_smsg("(%zu) <- 0", n);       break;
				case RE_IOP_INC_A:   x = str_smsg("A <- ++(%zu)", n);     break;
				case RE_IOP_LOAD_A:  x = str_smsg("A <- (%zu)", n);       break;
				case RE_IOP_LT_TP:   x = str_smsg("Z <- TP < (%zu)", n);  break;
				case RE_IOP_SAVE_FSP:x = str_smsg("(%zu) <- FSP", n);     break;
				case RE_IOP_UPDATE_FTP:
					x = str_smsg("%supdate TP in FAIL at %zu",
						invalid, value);
					break;
				case RE_IOP_MAX:     g_assert_not_reached();
				}
				comment = str_smsg2("%s%s", invalid, x);
			}
			goto ok;
		case RE_OP_HWCL:
		case RE_OP_HWCL2:
			goto ok;
		case RE_OP_XJMP:
			{
				p = re_mi_decode_immediate(p, inst.cs, 0, &xoffsets);
				if (show) {
					str_catf(s, "%zu, ...", xoffsets);
					if (inst.z)
						xoffsets--;
					if (inst.z == xoffsets) {
						comment = str_smsg("JR if A == %u", inst.z);
					} else {
						comment = str_smsg("JR for A in [%u, %zu]%s",
							inst.z, xoffsets - !inst.z,
							inst.z ? ", skip if A == 0" : "");
					}
				} else {
					const uint8 *xend = p + (xoffsets - inst.z) * 2;
					const uint8 *q = p;
					const uint8 *dest;

					while (q < xend) {
						offset = (int16) peek_le16(q);
						q += 2;
						dest = p + offset;
						re_mi_dump_record_dest(dc, dest);
					}
					p = q;
				}
			}
			goto ok;
		case RE_OP_UPDATE_FPC:
			{
				const uint8 *dest;

				if (inst.flg & 0x100) goto illegal;
				p = re_mi_decode_immediate(p, inst.cs,  1, &value);
				p = re_mi_jmp_offset(p, inst.flg, &offset);

				/* Validate PC destination (absolute or relative) */

				if (
					!re_mi_dump_valid_dest(dc, &dest,
						&inst, p, inst.flg, offset)
				)
					goto done;

				/* Compute label to nicely display destination */

				if (!show)
					re_mi_dump_record_dest(dc, dest);

				if (show) {
					str_catf(s, "-2(%zu), ", value);
					comment = re_mi_dump_jump_dest(
						dc, s, dest, inst.flg, offset);
					comment = str_smsg("FAIL update PC to %s", comment);
				}
			}
			goto ok;
		case RE_OP_DJMP:
			{
				const uint8 *dest;

				p = re_mi_decode_immediate(p, inst.cs, 1, &value);
				if (inst.x) {
					offset = (int16) peek_le16(p);
					p += 2;
				} else {
					offset = (int8) *p++;
				}

				dest = p + offset;	/* Relative offset */

				/* Compute label to nicely display destination */
				if (!show)
					re_mi_dump_record_dest(dc, dest);

				if (show) {
					re_op_cs_t cs = inst.x ? RE_OP_CS_16BITS : RE_OP_CS_8BITS;
					const char *invalid = "";

					if (value >= dc->bc->tsp_words)
						invalid = "*** ";		/* Flag invalid word visually */
					value++;
					
					str_catf(s, "(%zu), ", value);
					comment = re_mi_dump_jump_dest(dc, s, dest, cs, offset);
					comment = str_smsg("%sif 0 %c= --(%zu) JR %s",
						invalid,
						inst.z ? '=' : '!', value, comment);
				}
			}
			goto ok;
		case RE_OP_JMP:
		case RE_OP_UJMP:
		case RE_OP_FAIL_JMP:
		case RE_OP_XCALL:
		case RE_OP_CALL:
			{
				const uint8 *dest;

				p = re_mi_jmp_offset(p, inst.cs, &offset);

				/* Validate PC destination (absolute or relative) */

				if (
					!re_mi_dump_valid_dest(dc, &dest,
						&inst, p, inst.cs, offset)
				)
					goto done;

				/* Compute label to nicely display destination */

				if (!show)
					re_mi_dump_record_dest(dc, dest);

				if (show) {
					const char *fail = "";
					char condition[16];

					if (RE_OP_JMP == inst.opcode) {
						char x = inst.x ? 'C' : 'Z';
						const char *z = inst.z ? "" : "N";
						str_bprintf(ARYLEN(condition), " if %s%c", z, x);
					} else {
						condition[0] = '\0';
					}

					if (RE_OP_FAIL_JMP == inst.opcode) {
						if (RE_OP_CS_EMPTY == inst.cs)
							fail = "FAIL point, JP ";
						else
							fail = "FAIL point, JR ";
					}

					comment = re_mi_dump_jump_dest(
						dc, s, dest, inst.cs, offset);
					comment = str_smsg("%s%s", fail, comment);
					if (RE_OP_XCALL == inst.opcode) {
						if (inst.x)
							comment = str_smsg2("%s%s, negated",
								comment, inst.z ? " ,test" : "");
						else
							comment = str_smsg2("%s%s",
								comment, inst.z ? " ,test" : "");
					} else {
						comment = str_smsg2("%s%s", comment, condition);
					}
				}
			}
			goto ok;
		case RE_OP_MATCH:
			p = re_mi_decode_immediate(p, inst.cs, 1, &characters);
			if (show) {
				comment = str_smsg("case-%ssensitive", inst.x ? "in": "");
				if (RE_OP_CS_EMPTY == inst.cs) {
					str_catf(s, ", '%s'", re_format_char(characters));
					characters = 0;
				} else {
					str_catf(s, ", %zu, ...", characters);
				}
			} else {
				if (RE_OP_CS_EMPTY != inst.cs)
					p += characters;
			}
			goto ok;
		case RE_OP_F_PUSH_TRACK:
		case RE_OP_F_POP_TRACK:
			comment = "word";
			goto fail_items;
		case RE_OP_F_PUSH_GROUP:
		case RE_OP_F_POP_GROUP:
			comment = "group";
			goto fail_items;
		case RE_OP_F_PUSH_REF:
		case RE_OP_F_POP_REF:
			comment = "ref";
			/* FALL THROUGH */
		fail_items:
			p = re_mi_decode_immediate(p, inst.cs, 1, &value);
			switch (inst.flg) {
			case RE_OP_CS_16BITS: tracks = 2 * value; break;
			case RE_OP_CS_8BITS:  tracks = value;     break;
			default: goto illegal;
			}
			if (show) {
				uint bits = (RE_OP_CS_16BITS == inst.flg) ? 16 : 8;
				comment = str_smsg("%zu %s%s, %u-bit number%s",
					value, comment, plural(value), bits, plural(value));
				str_catf(s, "%zu, ...", tracks);
			} else {
				p += tracks;
			}
			goto ok;
		case RE_OP_RG_A:
			{
				size_t n, m;
				if (inst.flg & 0x100) goto illegal;
				p = re_mi_decode_immediate(p, inst.cs, 0, &n);
				p = re_mi_decode_immediate(p, inst.flg, 0, &m);
				if (show) {
					str_catf(s, "%zd%s, %zd%s",
						n, !size_is_positive(n) ? "U" : "",
						m, !size_is_positive(m) ? "U" : ""
					);
					comment = str_smsg(
						"Z <- A < %zd%s, C <- A in [%zd%s, %zd%s[",
						n, !size_is_positive(n) ? "U" : "",
						n, !size_is_positive(n) ? "U" : "",
						m, !size_is_positive(m) ? "U" : ""
					);
				}
			}
			goto ok;
		case RE_OP_LOAD:
		case RE_OP_ADD:
			{
				size_t word;
				if (inst.flg & 0x100) goto illegal;
				p = re_mi_decode_immediate(p, inst.cs, 0, &word);
				p = re_mi_decode_immediate(p, inst.flg, 0, &value);
				if (show) {
					const char *invalid = "";
					const char *o;
					if (word >= dc->bc->tsp_words)
						invalid = "*** ";		/* Flag invalid word visually */
					word++;
					o = (RE_OP_ADD == inst.opcode) ? "+=" : "<-";
					str_catf(s, "(%zu), %zd%s",
						word, value, !size_is_positive(value) ? "U" : "");
					comment = str_smsg("%s(%zu) %s %zd%s",
						invalid,
						word, o, value, !size_is_positive(value) ? "U" : "");
				}
			}
			goto ok;
		case RE_OP_XLOAD_A:
			p = re_mi_decode_immediate(p, inst.cs, 0, &entries);
			if (RE_OP_CS_8BITS != inst.cs && RE_OP_CS_16BITS != inst.cs)
				goto illegal;
			if (show) {
				str_catf(s, "%zd, ...", entries);
				comment = str_smsg("alter A by indexing next %zu %s%s",
					entries, RE_OP_CS_8BITS == inst.cs ? "byte" : "word",
					1 == entries ? "" : "s");
			} else {
				switch (inst.flg) {
				case RE_OP_CS_8BITS:  p += entries;     break;
				case RE_OP_CS_16BITS: p += entries * 2; break;
				}
			}
			goto ok;
		case RE_OP_F_DROP_WORD:
		case RE_OP_NEED:
		case RE_OP_SET_A:
		case RE_OP_RET_A:
		case RE_OP_SUB_TP:
			p = re_mi_decode_immediate(p, inst.cs, 0, &value);
			if (show) {
				value =
					(value << 5) + inst.flg + (inst.z << 3) + (inst.x << 4);
				switch (inst.opcode) {
				case RE_OP_F_DROP_WORD:
				case RE_OP_NEED:
					value++;
					break;
				}
				str_catf(s, "%zd", value);
				if (RE_OP_F_DROP_WORD == inst.opcode)
					comment = str_smsg("FAIL drop %zu word%s", PLURAL(value));
				else if (RE_OP_RET_A == inst.opcode)
					comment = str_smsg("A <- %zd, RET", value);
				else if (RE_OP_NEED == inst.opcode)
					comment = str_smsg("needs %zu character%s", PLURAL(value));
			}
			goto ok;
		case RE_OP_REPEAT:
		case RE_OP_CAPTURE:
		case RE_OP_REF:
		case RE_OP_LT_A:
			p = re_mi_decode_immediate(p, inst.cs, 0, &value);
			if (show) {
				switch (inst.opcode) {
				case RE_OP_REPEAT:
					value = (value << 3) + inst.flg;
					break;
				case RE_OP_CAPTURE:
					value = (value << 3) + inst.flg + 1;
					break;
				case RE_OP_REF:
					STR_CAT(s, ", ");
					break;
				}
				str_catf(s, "%zd%s",
					value, size_is_non_negative(value) ? "" : "U");
				switch (inst.opcode) {
				case RE_OP_LT_A:
					if (inst.x) {
						comment = str_smsg("C <- A < %zd%s, Z set if equal",
							value, !size_is_positive(value) ? "U" : "");
					} else {
						comment = str_smsg("Z <- A %s %zd%s",
							inst.z ? "==" : "<",
							value, !size_is_positive(value) ? "U" : "");
					}
					break;
				case RE_OP_REF:
					comment = str_smsg("case-%ssensitive ref #%zu",
						inst.x ? "in" : "", value);
					break;
				case RE_OP_REPEAT:
					comment = str_smsg("%s repeat%s%s",
						0 == value ? "inf" : size_t_to_string(value),
						1 == value ? "" : "s",
						inst.x ? ", C <- 1, guards next" : " of next");
					break;
				case RE_OP_CAPTURE:
					comment = str_smsg("%s of %s #%zu",
						inst.x ? "end" : "start",
						inst.z ? "ref" : "group", value);
					break;
				}
			}
			goto ok;
		case RE_OP_TRIE:
		case RE_OP_CLASS:
			{
				const uint8 *dp;

				if (RE_OP_CS_EMPTY == inst.cs) {
					size_t min, max;
					min = *p++;
					max = *p++;
					if (show) {
						if (min != max) {
							str_catf(s, ", [%s%zu, %zu]",
								inst.x ? "^" : "", min, max);
						} else {
							str_catf(s, ", [%s%zu]", inst.x ? "^" : "", min);
						}
						comment = re_mi_dump_minmax(min, max, inst.x);
					}
				} else if (RE_OP_CLASS == inst.opcode) {
					p = re_mi_decode_immediate(p, inst.cs, 0, &value);
					dp = re_mi_seg_at(data, value);
					if G_UNLIKELY(!re_mi_seg_has(data, dp, 3)) goto data_fault;
					if (show) {
						int min, max;
						const bit_field_t *bf;
						size_t nb;
						min    = *dp++;
						max    = *dp++;
						offset = *dp++;
						bf     = (bit_field_t *) dp;
						nb     = re_class_bytelen(min, max);
						if (!re_mi_seg_has(data, dp, nb)) goto data_fault;
						str_catf(s, ", %08X", (uint) value);
						comment =
							re_mi_dump_bit_class(min, max, offset, bf, inst.x);
					}
				} else {
					p = re_mi_decode_immediate(p, inst.cs, 0, &value);
					dp = re_mi_seg_at(data, value);
					if G_UNLIKELY(!re_mi_seg_has(data, dp, 2)) goto data_fault;
					if (show) {
						int min, max;
						size_t nb;
						min    = *dp++;
						max    = *dp++;
						nb     = max - min + 1;
						if (!re_mi_seg_has(data, dp, nb)) goto data_fault;
						str_catf(s, ", %08X", (uint) value);
						comment = re_mi_dump_byte_class(min, max, dp);
					}
				}

				if (show) {
					comment = str_smsg("case-%ssensitive %s%s",
							inst.z ? "in": "", comment,
							RE_OP_TRIE == inst.opcode ? ", sets A" : "");
				}
			}
			goto ok;
		case RE_OP_FAIL_OP:
			if (show) {
				int base = (RE_MI_FAIL_OP_GROUP == inst.cs) ? 0 : 1;
				uint n   = inst.z ? peek_le16(p) : peek_u8(p);
				const char *what;
				str_catf(s, "%u", n + base);
				switch (inst.cs) {
				case RE_MI_FAIL_OP_TRACK: what = "word";  break;
				case RE_MI_FAIL_OP_GROUP: what = "group"; break;
				case RE_MI_FAIL_OP_REF:   what = "ref";   break;
				default:                                  goto illegal;
				}
				comment = str_smsg("FAIL %s %s #%u",
					inst.x ? "pop" : "push", what, n + base);
			}
			p += 1 + inst.z;
			goto ok;
		case RE_OP_REW_TP:
			{
				uint n   = inst.z ? peek_le16(p) : peek_u8(p);
				uint8 c;
				size_t off = 0;
				n++;
				p += 1 + inst.z;
				c = *p++;
				if (inst.cs != RE_OP_CS_EMPTY)
					p = re_mi_decode_immediate(p, inst.cs, 0, &off);
				if (show) {
					char tpreg[32];
					if (0 == off) {
						str_catf(s, "(%u), '%c'", n, c);
						str_bprintf(ARYLEN(tpreg), "(TP)");
					} else {
						str_catf(s, "(%u), '%c'@%zu", n, c, off);
						str_bprintf(ARYLEN(tpreg), "(TP+%zu)", off);
					}
					comment = str_smsg("TP-- upto (%u) until %s%s, Z <- OK",
						n, tpreg, inst.x ?
							str_smsg2(" in [%c%c]", c, ascii_toupper(c)) :
							str_smsg2("='%c'", c)
					);
				}
			}
			goto ok;
		case RE_OP_ESCAPE:
		case RE_OP_MAX:
			break;
		}

		if (show) {
			ostream_printf(dc->os, "invalid opcode %d at PC=%04X",
				inst.opcode, re_mi_seg_offset(text, inst.ip));
		}
		goto done;

	ok:
		/* We have a trailing margin at the end of TEXT, check boundary now */

		if (p > pend)
			goto fault;		/* Arguments read past the logical end */

		if (!show)
			goto next;

		/* Format the instruction bytes plus the arguments */

		str_reset(b);

		for (i = p - inst.ip; i != 0; i--) {
			/*
			 * Since it is exceptional to have more than 4 bytes displayed
			 * for instructions, including arguments, we make the first
			 * 4 bytes stand-out, and the remaining bytes will all be
			 * displayed without any interleaving space, to save screen
			 * estate.
			 */

			if (&p[-i] - inst.ip < 3)
				str_catf(b, "%02X ", p[-i]);
			else
				str_catf(b, "%02X", p[-i]);
		}

		if (str_len(b) > RE_MI_BYTES) {
			str_setlen(b, RE_MI_BYTES - 1);
			str_putc(b, '+');	/* Signal: truncated instruction bytes */
		}

		/* Replace the characters we had reserved above */

		str_replace(s, 5, str_len(b), str_2c(b));

		/* If we are at a known label, display information before */

		re_mi_dump_label(dc, inst.ip);

#define RE_MI_I_SPC	44					/* Instruction space, until comments */
#define RE_MI_C_OFF	(RE_MI_I_SPC - 29)	/* Constant comment offset */

		if (NULL == comment)
			ostream_puts(dc->os, str_2c(s));
		else
			ostream_printf(dc->os, "%-*s; %s", RE_MI_I_SPC, str_2c(s), comment);

		/* If there are XLOAD_A offset following, dump them */

		if (entries != 0) {
			size_t width = RE_OP_CS_8BITS == inst.cs ? 1 : 2;
			int j = 0;
			while (entries-- && p < pend) {
				size_t n = (1 == width) ? *p : peek_le16(p);
				ostream_printf(dc->os, "\n%04X %-*s..... %-*zu; %d",
					re_mi_seg_offset(text, p),
					RE_MI_BYTES,
					1 == width ?
						str_smsg("%02X", p[0]) :
						str_smsg("%02X %02X", p[0], p[1]),
					RE_MI_C_OFF, n, j);
				p += width;
				j++;
			}
		}

		/* If there are XJMP offset following, dump them */

		if (xoffsets != 0) {
			const uint8 *base = p;
			str_t *ds = str_new(0);
			int n = inst.z;
			while (xoffsets-- && p < pend) {
				const uint8 *dest;
				uint num, dpc;
				offset = peek_le16(p);
				dest = base + offset;
				num = pointer_to_uint(htable_lookup(dc->labels, dest));
				dpc = re_mi_seg_offset(text, dest);
				if (0 == num)
					str_printf(ds, "%+d = %04X", offset, dpc);
				else
					str_printf(ds, "<L%d>:%04X", num, dpc);
				ostream_printf(dc->os, "\n%04X %-*s..... %-*s; %d",
					re_mi_seg_offset(text, p),
					RE_MI_BYTES, str_smsg("%02X %02X", p[0], p[1]),
					RE_MI_C_OFF, str_2c(ds), n);
				p += 2;
				n++;
			}
			str_destroy_null(&ds);
		}

		/* If there are matching characters following, dump them one at a time */

		while (characters-- && p < pend) {
			ostream_printf(dc->os, "\n%04X %-*s..... '%s'",
				re_mi_seg_offset(text, p),
				RE_MI_BYTES, str_smsg("%02X", *p), re_format_char(*p));
			p++;
		}

		/* If there are tracks following, dump them 6 at a time */

		while (tracks && p < pend) {
			str_t *bs = str_new(0);
			str_t *ts = str_new(0);
			size_t n;
			int base = 1;
			switch (inst.opcode) {
			case RE_OP_F_PUSH_GROUP:
			case RE_OP_F_POP_GROUP:
				base = 0;
				break;
			}
			ostream_printf(dc->os, "\n%04X", re_mi_seg_offset(text, p));
			STR_CAT(ts, ".....");	/* Skip mnemonic (5 chars) */
			switch (inst.flg) {
			case RE_OP_CS_8BITS:
				for (n = 0; n < MIN(tracks, 6) && p < pend; n++, p++) {
					str_catf(bs, " %02X", *p);
					str_catf(ts, " %d%s", *p + base,
						n + 1 == MIN(tracks, 6) ? "" : ",");
				}
				tracks -= MIN(tracks, 6);
				break;
			case RE_OP_CS_16BITS:
				for (n = 0; n < MIN(tracks, 3) && p < pend; n++, p += 2) {
					uint16 j = peek_le16(p) + base;
					str_catf(bs, " %02X", p[0]);
					str_catf(bs, " %02X", p[1]);
					str_catf(ts, " %d%s", j,
						n + 1 == MIN(tracks, 3) ? "" : ",");
				}
				tracks -= MIN(tracks, 3);
				break;
			default:
				g_assert_not_reached();	/* Already checked earlier */
			}

			ostream_printf(dc->os, "%-*s %s", RE_MI_BYTES,
				str_2c(bs), str_2c(ts));
			str_destroy_null(&bs);
			str_destroy_null(&ts);
		}

		/* FALL THROUGH */

	next:
		if (show)
			ostream_putc(dc->os, '\n');
	}

	/* FALL THROUGH */

done:
	str_destroy_null(&s);
	str_destroy_null(&b);
	return;

illegal:
	if (show)
		ostream_puts(dc->os, "<illegal instruction>\n");
	goto done;

data_fault:
	if (show)
		ostream_puts(dc->os, "<data fault>\n");
	goto done;

fault:
	if (show)
		ostream_puts(dc->os, "<text fault>\n");
	goto done;
}

#undef RE_MI_BYTES
#undef RE_MI_I_SPC
#undef RE_MI_C_OFF

/**
 * Format regex bytecode as string, which can be freed by hfree().
 *
 * The output is the generated bytecode, as it is going to be executed
 * by the machine interpreter.
 *
 * @param re	the compiled regular expression
 * @param debug	if TRUE, regenerate a bytecode with debugging info
 *
 * @return halloc()'ed string listing the generated bytecode.
 */
char *
re_bytecode_as_string(const re_regex_t *re, bool debug)
{
	struct re_mi_dump_ctx ctx;
	str_t *s = str_new(0);

	re_regex_check(re);

	if (!re_exec_needs_engine(re))
		return h_strdup("<simple regex - no bytecode>\n");

	if (NULL == re->bytecode && !debug)
		return h_strdup("<no bytecode>\n");

	ZERO(&ctx);
	ctx.os     = ostream_open_str(s);
	ctx.labels = htable_create(HASH_KEY_SELF, 0);
	ctx.bc     = re->bytecode;
	ctx.num    = 1;

	if (debug) {
		re_regex_t recpy = *re;

		recpy.bytecode = NULL;
		re_mi_generate(&recpy, TRUE);
		ctx.bc = recpy.bytecode;
	}

	/* TEXT segment */

	re_mi_dump(&ctx);		/* First pass */
	ctx.show = TRUE;
	re_mi_dump(&ctx);		/* Second pass */

	/* Optional DATA segment */

	if (0 != re_mi_seg_used(&ctx.bc->data)) {
		const re_mi_seg_t *data = &ctx.bc->data;

		dump_hex_ostream(ctx.os, "DATA segment",
			re_mi_seg_base(data), re_mi_seg_used(data));
	}

	/* Cleanup */

	if (debug)
		re_mi_free(ctx.bc);

	ostream_close(ctx.os);
	htable_free_null(&ctx.labels);

	return str_s2c_null(&s);
}

/***
 *** ================== Matching Interpreter ==================
 ***/

/**
 * Interpreter Registers
 * ---------------------
 *
 * Our interpreter is a very specialized processing engine, which is capable
 * of performing operations involving registers and memory.
 *
 * The internal registers of the processor are subdivided into:
 *
 * Internal registers, not directly usable by the program:
 *
 *   PC      the Program Counter (16-bit offset within the program TEXT segment)
 *   FSP     the Fail Stack Pointer (16-bit)
 *   TSP     the Track Stack Pointer (16-bit)
 *   RP      the Reserved-word Pointer (array of 32-bit words: our variables)
 *   IR      the Instruction Register (16-bit, copy of current instruction)
 *   D       the Direction register (either +1 or -1), the matching direction
 *
 * Registers that can be loaded / tested by the program:
 *
 *   TP      the Text Position (32-bit offset within the text being matched)
 *   A       the Accumulator (32-bit value)
 *   F       the flags register, with testable Z and C bits.
 *
 * The flags register architecture is:
 *
 *      +--------+-+-+
 *      | unused |C|Z|
 *      +--------+-+-+
 *
 * Z = Zero bit, set during comparisons usually
 * C = Carry bit, used for conditional execution (CEX) and comparisons (LT_A.X)
 *
 * For efficiency reasons, the F register is not implemented as a bit field
 * but as an array of bytes.  This allows minimal overhead for accessing and
 * settings flags and optimizes conditional jump processing.
 *
 *
 * Memory Management
 * -----------------
 *
 * The interpreter uses three different segments, two read-only and another
 * being read-write.  All segments are fixed regions of memory that cannot
 * be extended:
 *
 *   TEXT    the segment containing the program (instructions + immediate data)
 *   DATA    the segment containing program data (for sharing within program)
 *   STACK   the segment holding stacks plus reserved locations (variables)
 *
 * Obviously, only the STACK is a read-write segment!
 *
 * During execution of the program, special instructions can also access other
 * memory regions:
 *
 *   mvec[]  the matching position vector (user-supplied) to track match groups
 *   bvec[]  the built-in vector (internal), tracking back-references boundaries
 *
 * And of course the text against which our program is attempting to find a
 * match, not to be confused with the TEXT segment defined above (unfortunate
 * jargon clash!).
 *
 *
 * Stack Management
 * ----------------
 *
 * The FSP and TSP stack pointers run towards each other because they
 * share the same stack segment.  FSP grows up, TSP grows down.
 *
 * - FSP points to the next word to write (post-incremented on writes).
 * - TSP points one word above the next word to write, or to the last word
 *   written if not at the top (pre-decremented on writes).
 *
 * Once they satisfy TSP <= FSP, we know we have overflowed our stack.
 * The stack is full when FSP = TSP - 1.
 *
 *     <.................  Total stack allocated ...............>
 *                                                  RP
 *                                                  v
 *     +--------------------------------------------+-----------+
 *     |   ===> FSP    stack buffer     TSP <====   | reserved  |
 *     +--------------------------------------------+-----------+
 *     ^                                             ^
 *   fsp_bot                                   tsp_top
 *
 * The Fail Stack records backtracking points to go back to when a match
 * has failed, plus additional context that needs to be preserved.  This
 * context includes: the PC register (program counter), the TP register
 * (text position) and the TSP register.
 *
 * The Track Stack is a normal stack, used to do subroutines or push
 * value to be preserved whilst doing something and that need to be retrieved
 * later, like the value of the FSP register when handling atomic groups,
 * or the PC when doing a subroutine call.
 *
 * The upper part of the allocated stack is a set of reserved words that are
 * used to track element repetitions or text positions.  This is a region
 * addressed by the RP base register, as an array of words.
 *
 *
 * Architectural Limits
 * --------------------
 *
 * The PC and TSP registers are architecturally limited to 16-bit values
 * in order to be able to save both as one 32-bit value on the FAIL stack.
 *
 * The stack used by the interpreter is therefore also limited to 64 KiB
 * maximum, due to the span of the TSP register.
 */
struct re_mi_regs {
	const uchar *tp;		/* Text pointer */
	const uint8 *pc;		/* Program counter */
	uint32 *rp;				/* Base reserved pointer */
	uint32 *fsp;			/* Fail stack pointer */
	uint32 *fsp_bot;		/* Fail stack pointer bottom */
	uint32 *fsp_max;		/* Max FSP value, to compute stack usage */
	uint32 *tsp;			/* Track stack pointer */
	uint32 *tsp_top;		/* Track stack pointer top */
	uint32 *tsp_min;		/* Min TSP value, to compute stack usage */
};

/**
 * Interpreter context.
 */
struct re_mi_ctx {
	struct re_exec_ctx *rec;	/* Execution context */
	struct re_mi_regs regs;		/* Registers */
	re_mi_code_t *code;			/* Code information (TEXT + DATA) */
	const uchar *start_tp;		/* Starting text pointer */
	uint8 *stack;				/* Allocated stack (on the real CPU stack) */
	size_t stacksz;				/* Length of allocated stack (informative) */
};

/**
 * Fail stack records.
 *
 * We push two kind of records on the FAIL stack:
 *
 * - text offsets (index of the current text position)
 * - MI registers: PC and TSP
 *
 * Both are pushed as 32-bit words, so that we always access the FAIL
 * stack using uint32 pointers.
 *
 * These macros extract the PC and TSP parts of the pushed 32-bit word.
 * See re_mi_exec_push_fail() for the construction of this combined word.
 */
#define FSP_PC(v)	(uint16) ((v) >> 16)		/* PC in a FAIL stack word */
#define FSP_TSP(v)	(uint16) ((v) & 0xffffU)	/* TSP in a FAIL stack word */

#define RE_D_MI_MATCH	(RE_D_MI | RE_D_MATCHER)

/**
 * Built-in backtracking threshold after which we are starting to
 * compare the amount of backtracking we are doing to the number of
 * characters we are matching so far, allowing only 65536 backtracks
 * per character matched so far.
 */
#define RE_MI_BACKTRACK_THRESH		1000000		/* 1 million */
#define RE_MI_BACKTRACK_SHIFT		16			/* 1 << 16 = 65536 */

/**
 * Macro tracking the max FAIL stack usage.
 */
#define FAIL_USAGE()													\
G_STMT_START {															\
	if G_UNLIKELY(fsp > regs->fsp_max) {								\
		regs->fsp_max = fsp;											\
		REX_DEBUG(RE_D_MI, "new FSP max: ** %zu bytes **",				\
			ptr_diff(regs->fsp_max, regs->fsp_bot));					\
	}																	\
} G_STMT_END

/**
 * Macro used in re_mi_execute() to push a new FAIL record on stack.
 *
 * It is a macro to be able to conveniently use local variables from the
 * main execution loop, and goto labels in case of error.
 */
#define PUSH_FAIL()														\
G_STMT_START {															\
	if G_UNLIKELY(ptr_diff(tsp, fsp) < 2 * sizeof(uint32))				\
		goto stack_overflow;											\
																		\
	REX_DEBUG(RE_D_MI,													\
		"pushed FAIL record @FSP=%04X: TP=%u, PC=%04X, TSP=%04X",		\
		FSP, TP, PC, TSP);												\
																		\
	fsp = re_mi_exec_push_fail(fsp, PC, TSP, TP);						\
	FAIL_USAGE();														\
} G_STMT_END

/* Ensure we have `n' words available on the FAIL stack */
#define FAIL_POPPING(n)													\
G_STMT_START {															\
	if G_UNLIKELY(ptr_diff(fsp, regs->fsp_bot) < (n) * sizeof(uint32))	\
		goto stack_underflow;											\
} G_STMT_END

/**
 * Macro used in re_mi_execute() to pop a FAIL record on the stack
 * if there is one, and resume execution there.
 */
#define POP_FAIL()														\
G_STMT_START {															\
	if (fsp != regs->fsp_bot) {											\
		uint32 t, r;													\
		uint32 *ntsp;													\
																		\
		FAIL_POPPING(2);												\
		t = *(--fsp);		/* Text Pointer */							\
		r = *(--fsp);		/* Registers: PC and TSP */					\
																		\
		REX_DEBUG(RE_D_MI,												\
			"popped FAIL record @FSP=%04X: TP=%u, PC=%04X, TSP=%04X",	\
			FSP, t, FSP_PC(r), FSP_TSP(r));								\
																		\
		tp   = const_ptr_add_offset(tp_start, t);						\
		pc   = re_mi_seg_at_1off(text, FSP_PC(r));						\
		ntsp = ptr_add_offset(regs->tsp_top, -FSP_TSP(r));				\
		g_assert(ntsp >= tsp);											\
		tsp  = ntsp;													\
																		\
		/* Detect catastrophic backtracking */							\
		if (															\
			++backtracks > RE_MI_BACKTRACK_THRESH &&					\
			backtracks > ((uint64) TP) << RE_MI_BACKTRACK_SHIFT			\
		)																\
			goto backtrack_limit;										\
																		\
		goto resume;													\
	} else																\
		goto no_backtracking;											\
} G_STMT_END

/**
 * Update top word on the FAIL stack with the current TP value.
 */
#define FAIL_UPDATE_TP()												\
G_STMT_START {															\
	if G_UNLIKELY(fsp == regs->fsp_bot)									\
		goto stack_underflow;											\
	REX_DEBUG(RE_D_MI, "updating TP=%u with current TP=%u",				\
		fsp[-1], TP);													\
	fsp[-1] = TP;														\
} G_STMT_END

/* Ensure we have room for `n' words on the FAIL stack */
#define FAIL_PUSHING(n)													\
G_STMT_START {															\
	if G_UNLIKELY(ptr_diff(tsp, fsp) < (n) * sizeof(uint32))			\
		goto stack_overflow;											\
} G_STMT_END

/* Pushes reserved word n from the TRACK stack onto the FAIL stack */
#define F_PUSH_TRACK(n)													\
G_STMT_START {															\
	*fsp++ = rp[n];														\
	REX_DEBUG(RE_D_MI, "saved rp[%zu] = %u", (n), rp[n]);				\
} G_STMT_END

/* Pushes capturing group n start/end onto the FAIL stack */
#define F_PUSH_GROUP(n, rec)											\
G_STMT_START {															\
	if ((rec)->mvec != NULL && (n) < (rec)->mcnt) {						\
		*fsp++ = (uint32) rec->mvec[n].re_start;						\
		*fsp++ = (uint32) rec->mvec[n].re_end;							\
		REX_DEBUG(RE_D_MI, "saved group[%zu] = [%d, %d]",				\
			(n), fsp[-2], fsp[-1]);										\
	} else {															\
		*fsp++ = 0;														\
		*fsp++ = 0;														\
	}																	\
} G_STMT_END

/* Pushes back-reference n start/end onto the FAIL stack */
#define F_PUSH_REF(n, rec)												\
G_STMT_START {															\
	*fsp++ = (uint32) rec->bvec[n].re_start;							\
	*fsp++ = (uint32) rec->bvec[n].re_end;								\
	REX_DEBUG(RE_D_MI, "saved ref[%zu] = [%d, %d]",						\
		(n) + 1, fsp[-2], fsp[-1]);										\
} G_STMT_END

/* Drop last FAIL record on the FAIL stack */
#define FAIL_DROP(n)													\
	FAIL_POPPING(2);													\
	{																	\
		uint32 t, r;													\
																		\
		FAIL_POPPING(2);												\
		t = *(--fsp);													\
		r = *(--fsp);													\
																		\
		(void) r, (void) t;												\
		REX_DEBUG(RE_D_MI,												\
			"dropped FAIL record @FSP=%04X: TP=%u, PC=%04X, TSP=%04X",	\
			FSP, t, FSP_PC(r), FSP_TSP(r));								\
	}																	\
G_STMT_START {															\
} G_STMT_END

/* Pops reserved word n from the FAIL stack */
#define F_POP_TRACK(n)													\
G_STMT_START {															\
	REX_DEBUG(RE_D_MI,													\
		"restoring rp[%zu]: %u -> %u", (n), rp[n], fsp[-1]);			\
	rp[n] = *(--fsp);													\
} G_STMT_END

/* Pops capturing group n start/end from the FAIL stack */
#define F_POP_GROUP(n, rec)												\
G_STMT_START {															\
	if ((rec)->mvec != NULL && (n) < (rec)->mcnt) {						\
		REX_DEBUG(RE_D_MI, "restoring group[%zu] = [%d, %d]",			\
			(n), fsp[-2], fsp[-1]);										\
		rec->mvec[n].re_end   = (int32) *(--fsp);						\
		rec->mvec[n].re_start = (int32) *(--fsp);						\
	} else {															\
		fsp -= 2;														\
	}																	\
} G_STMT_END

/* Pops back-reference n start/end from the FAIL stack */
#define F_POP_REF(n, rec)												\
G_STMT_START {															\
	REX_DEBUG(RE_D_MI, "restoring ref[%zu] = [%d, %d]",					\
		(n) + 1, fsp[-2], fsp[-1]);										\
	rec->bvec[n].re_end   = (int32) *(--fsp);							\
	rec->bvec[n].re_start = (int32) *(--fsp);							\
} G_STMT_END

/**
 * Push FAIL record on stack.
 *
 * This routine is never called directly, only through the PUSH_FAIL macro
 * to be able to conveniently use local variables from re_mi_execute().
 *
 * @param fsp		current FAIL stack top
 * @param pc		current PC offset in text
 * @param tsp		current TSP offset
 * @param tp_off	current text pointer offset
 *
 * @return new FSP top.
 */
static inline uint32 * G_FAST ALWAYS_INLINE
re_mi_exec_push_fail(uint32 *fsp, uint16 pc, uint16 tsp, uint32 tp_off)
{
	*fsp++ = ((uint32) pc << 16) + tsp;

	/*
	 * The last item pushed on the FAIL stack is the text offset.
	 *
	 * This is architecturally defined so that UPDATE_TP knows where
	 * to find the text pointer.
	 */

	*fsp++ = tp_off;

	return fsp;
}

/**
 * Macro tracking the max usage of the TRACK stack.
 */
#define TRACK_USAGE()													\
G_STMT_START {															\
	if G_UNLIKELY(tsp < regs->tsp_min) {								\
		regs->tsp_min = tsp;											\
		REX_DEBUG(RE_D_MI, "new TSP max: ** %zu bytes **",				\
			ptr_diff(regs->tsp_top, tsp));								\
	}																	\
} G_STMT_END

/**
 * Macro used to PUSH the current PC on the TRACK stack, before
 * jumping to a subroutine.
 */
#define PUSH_PC()														\
G_STMT_START {															\
	if G_UNLIKELY(ptr_diff(tsp, fsp) < sizeof(uint32))					\
		goto stack_overflow;											\
	*(--tsp) = (uint32) PC;												\
	TRACK_USAGE();														\
} G_STMT_END

/**
 * Macro used to PUSH the current FSP on the TRACK stack.
 */
#define PUSH_FSP()														\
G_STMT_START {															\
	if G_UNLIKELY(ptr_diff(tsp, fsp) < sizeof(uint32))					\
		goto stack_overflow;											\
	*(--tsp) = FSP;														\
	REX_DEBUG(RE_D_MI_MATCH, "pushed @TSP=%04X: FSP=%04X", TSP, FSP);	\
	TRACK_USAGE();														\
} G_STMT_END

/**
 * When executing RET, the subroutine we're leaving must not have left
 * any FAIL point on the fail stack, since then their context is becoming
 * stale!  Check the top FAIL record we have.
 */
#define POP_CHECK_FSP()													\
G_STMT_START {															\
	if (fsp != regs->fsp_bot) {											\
		/* Top record is TP, then PC + TSP */							\
		uint32 pc_tsp = fsp[-2];										\
		if (FSP_TSP(pc_tsp) > (uint16) ptr_diff(regs->tsp_top, tsp)) {	\
			s_warning("%s(): current TSP=%04X: "						\
				"has FAIL @FSP=%04X with TSP=%04X and PC=%04X",			\
				G_STRFUNC, TSP,											\
				(uint) ptr_diff(fsp - 2, regs->fsp_bot),				\
				FSP_TSP(pc_tsp), FSP_PC(pc_tsp));						\
			goto stale_fail;											\
		}																\
	}																	\
} G_STMT_END

/**
 * Macro used to POP the top record on the TRACK stack into the PC,
 * which is used to implement the RET instruction.
 */
#define POP_PC()														\
G_STMT_START {															\
	if G_UNLIKELY(tsp == regs->tsp_top)									\
		goto stack_underflow;											\
	pc = re_mi_seg_at(text, (uint16) *tsp++);							\
	if (!re_mi_seg_is_valid(text, pc))									\
		goto text_fault;												\
	POP_CHECK_FSP();													\
} G_STMT_END

/**
 * Macro used to POP the top record on the TRACK stack into the given variable.
 */
#define POP_TOP(var)													\
G_STMT_START {															\
	if G_UNLIKELY(tsp == regs->tsp_top)									\
		goto stack_underflow;											\
	var = *tsp++;														\
} G_STMT_END

/**
 * POP the top of the TRACK stack into the accumulator register.
 */
#define POP_A()															\
G_STMT_START {															\
	POP_TOP(ar);														\
	REX_DEBUG(RE_D_MI_MATCH, "popped %04X into A", ar);					\
} G_STMT_END

/**
 * Handle the Z and X instruction guard bits:
 *
 * The protection bits architecture is the following:
 *
 *    X  Z   condition
 *    0  0   NZ
 *    0  1   Z
 *    1  0   NC
 *    1  1   C
 *
 * This allows for efficient checking of the flags register:
 * - the X bit is the index of the flag to test within fr[]
 * - the Z bit is the value to test
 */
#define HANDLE_ZX_GUARD()												\
G_STMT_START {															\
	if (fr[X(inst)] != Z(inst)) {										\
		REX_DEBUG(RE_D_MI, "ignoring (Z=%d, C=%d)", ZF, CF);			\
		goto resume;													\
	}																	\
} G_STMT_END

/**
 * Compute PC destination for jump.
 */
#define SET_PC_DESTINATION(cs, offset)									\
G_STMT_START {															\
	if G_UNLIKELY(RE_OP_CS_EMPTY == (cs)) {								\
		pc = re_mi_seg_at(text, (offset));								\
		REX_DEBUG(RE_D_MI, "jumping to %04X (absolute)", PC);			\
	} else {															\
		pc += offset;													\
		REX_DEBUG(RE_D_MI, "jumping to %04X (%+d)",						\
			PC, (int16) (offset));										\
		if G_UNLIKELY(offset < 0 && ptr_cmp(pc, text->base) < 0)		\
			goto text_fault;											\
	}																	\
} G_STMT_END

/**
 * Compute relative forward PC destination for jump.
 * No need to check for the PC range since we're moving forward.
 */
#define SET_PC_FORWARD(offset)											\
G_STMT_START {															\
	pc += offset;														\
	REX_DEBUG(RE_D_MI, "jumping to %04X (%+d)",	PC, (int16) (offset));	\
} G_STMT_END

/**
 * Sync registers we cache as local variables: TP, FSP and TSP.
 */
#define SYNC_REGS()		\
G_STMT_START {			\
	regs->tp  = tp;		\
	regs->fsp = fsp;	\
	regs->tsp = tsp;	\
} G_STMT_END

/**
 * Decode FLG value in instruction plus the one in its following bytes.
 *
 * The embedded value uses the FLG bits to hold the lowest 3 bits,
 * and upper bits optionally follow when the CS-encoding is not empty.
 */
#define FLG_FOLLOWUP(v, cs)								\
G_STMT_START {											\
	if (RE_OP_CS_EMPTY != cs) {							\
		size_t m;										\
		pc = re_mi_decode_immediate(pc, cs, 0, &m);		\
		v += m << 3;									\
	}													\
} G_STMT_END

/**
 * Decode embedded value in instruction plus the one in its following bytes.
 *
 * The embedded value uses the X, Z and FLG bits to hold the lowest 5 bits,
 * and upper bits optionally follow when the CS-encoding is not empty.
 */
#define EMB_FOLLOWUP(v, cs)								\
G_STMT_START {											\
	if (RE_OP_CS_EMPTY != cs) {							\
		size_t m;										\
		pc = re_mi_decode_immediate(pc, cs, 0, &m);		\
		v += m << 5;									\
	}													\
} G_STMT_END

static int re_mi_xcall(struct re_mi_ctx *rmi, const uint8 *pc);

/* Shortcuts to allow nicer formatting in re_mi_execute() */
#define TP_AT_START() re_exec_at_start(tp, tp_start, eflags)
#define TP_AT_END()   re_exec_at_end(tp, eflags)
#define TP_AT_WB()    re_exec_at_word_boundary(tp, tp_start, eflags)

/**
 * Execute the byte-code, starting at the initialized PC register.
 *
 * The routine can also longjmp() when an error condition occurs.
 *
 * @param rmi		the Matching Interpreter context
 * @param next		whether to iterate over next starting point
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int G_FAST
re_mi_execute(struct re_mi_ctx *rmi, bool next)
{
	int error                 = 0;
	size_t backtracks         = 0;
	struct re_mi_regs *regs   = &rmi->regs;
	register const uint8 *pc  = regs->pc;
	register const uchar *tp  = regs->tp;
	uint32 *fsp               = regs->fsp;
	uint32 *tsp               = regs->tsp;
	uint32 *rp                = regs->rp;
	int32 ar                  = 0;			/* Accumulator register */
	int dr                    = +1;			/* Direction register */
	uint8 fr[2]               = { 0 };		/* Flags register */
	re_mi_inst_t inst;						/* Instruction register */
	const uint8 *cex          = NULL;
	const re_mi_code_t *code  = rmi->code;
	const re_mi_seg_t *text   = &code->text;
	const re_mi_seg_t *data   = &code->data;
	register const uint8 *end = re_mi_seg_end(text);
	const uchar *tp_start     = rmi->rec->text;
	uint eflags               = rmi->rec->eflags;
	struct {
		size_t n;				/* Amount of repetitions */
		const uint8 *rex;		/* Instruction to repeat */
	} repeat = { 0, NULL };
#ifdef PRIVLOG_ENABLED
	size_t instructions = 0;
#endif

	REX_ENTRY;

#define PC		(uint16) re_mi_seg_offset(text, pc)
#define TP		(uint32) ptr_diff(tp, tp_start)
#define FSP		(uint16) ptr_diff(fsp, regs->fsp_bot)
#define TSP		(uint16) ptr_diff(regs->tsp_top, tsp)

#define Z(ir)	(ir).op.u.v.z
#define X(ir)	(ir).op.u.v.x
#define CS(ir)	(ir).op.u.v.cs
#define FLG(ir)	(ir).of.v.flg
#define MOP(ir)	(ir).op.u.m.op
#define IOP(ir)	(ir).op.u.i.op
#define S(ir)	(ir).op.u.i.s
#define EMB(ir)	FLG(ir) + (Z(ir) << 3) + (X(ir) << 4)

#define ZF	fr[0]
#define CF	fr[1]

	re_exec_check_stack(rmi->rec);
	ZERO(&inst);

	REX_DEBUG(RE_D_MI, "PC=%04X, end=%04x (%zu byte%s)",
			PC, re_mi_seg_offset(text, end), PLURAL(end - pc));

	/*
	 * The main interpreter loop.
	 *
	 * We left a trailing margin in the TEXT segment at generation time,
	 * which lets us fetch arguments for common instructions without having
	 * to think about accessing past the end of the TEXT segments.
	 *
	 * The only instructions where we have to be careful are those where
	 * the number of arguments is variable (e.g. MATCH).
	 */

resume:
	while (pc < end) {
		int offset;

		/*
		 * Fast version, not decoding X, Z, CS and FLG, so that
		 * instructions not using any of these do not have to pay
		 * the price for computing them.
		 *
		 * Also the PC register is positioned past the leading
		 * opcode, ready to process operands, if any.
		 *
		 * To access the X instruction flag, the matching interpreter
		 * must therefore use X(inst) and not try to access inst.x
		 * which is not computed by RE_MI_LOAD_IR(), given that some
		 * instructions simply do not care about their X flag to execute!
		 */

		RE_MI_LOAD_IR(inst, pc);	/* Load the Instruction Register */

#ifdef PRIVLOG_ENABLED
		if (RE_OP_DEBUG != inst.opcode) {
			struct re_mi_inst_str is;
			re_mi_inst_disassemble(&is, &inst);
			REX_DEBUG(RE_D_MI, "PC=%04X %s%s%s%s%s, TP=%04X ('%c'): %s%s%s",
				re_mi_seg_offset(text, inst.ip),
				re_mi_inst_opname(&inst),
				inst.opcode > RE_OP_INDEX && X(inst) ? ".X" : "",
				inst.opcode > RE_OP_INDEX && Z(inst) ? "_Z" : "",
				inst.opcode <= RE_OP_INDEX || RE_OP_CS_EMPTY == CS(inst) ?
					"" : "/",
				inst.opcode <= RE_OP_INDEX || RE_OP_CS_EMPTY == CS(inst) ?
					"" : re_mi_cs2str_short(CS(inst)),
				TP, *tp,
				is.mnemo,
				NULL == is.arg ? "" : " ", NULL == is.arg ? "" : is.arg);
			instructions++;
		}
#endif

		/*
		 * Execute instruction.
		 *
		 * This involves fetching the arguments of the instruction,
		 * either following in the TEXT segment (e.g. JMP offsets, or
		 * bytes to match for MATCH), or also in the DATA segment.
		 *
		 * Then processing these arguments to fully execute the work
		 * required by the instruction semantics.
		 */

		switch ((re_mi_op_t) inst.opcode) {
		case RE_OP_DEBUG:
			{
				size_t v;

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &v);
				if G_UNLIKELY(pc + v > end)
					goto text_fault;
				REX_DEBUG(RE_D_MI, "(DEBUG): PC=%04X: %s",
					re_mi_seg_offset(text, inst.ip),
					re_mi_get_text(text, pc, v));
				pc += v;

				/*
				 * Must adjust for CEX: skip debugging instructions and
				 * move the pointer to the instruction after DEBUG.
				 * If more DEBUG follow, shifting will continue until
				 * we reach an executable instruction, the actual one
				 * that CEX is supposed to guard.
				 */

				if (cex == inst.ip) {
					cex = pc;
					REX_DEBUG(RE_D_MI, "shifting CEX to PC=%04X", PC);
				}

				/* Same deal for repeats */

				if (repeat.rex == inst.ip) {
					repeat.rex = pc;
					REX_DEBUG(RE_D_MI, "shifting repeated EX to PC=%04X", PC);
				}
			}
			continue;

		case RE_OP_ZERO:
			switch ((re_mi_mop_t) MOP(inst)) {
			case RE_MOP_MAX:                          break;	/* Not possible */
			case RE_MOP_NOP:                          continue;
			case RE_MOP_DONE:                         goto matched;
			case RE_MOP_FAIL:                         goto fail;
			case RE_MOP_RET:       POP_PC();          continue;
			case RE_MOP_PUSH_FSP:  PUSH_FSP();        continue;
			case RE_MOP_POP_A:     POP_A();           continue;
			case RE_MOP_UPDATE_TP: FAIL_UPDATE_TP();  continue;
			case RE_MOP_DROP_FAIL: FAIL_DROP();       continue;
			case RE_MOP_START:     if (TP_AT_START()) continue; else goto fail;
			case RE_MOP_END:       if (TP_AT_END())   continue; else goto fail;
			case RE_MOP_WB:        if (TP_AT_WB())    continue; else goto fail;
			case RE_MOP_NOT_WB:    if (!TP_AT_WB())   continue; else goto fail;
			case RE_MOP_ANY:
				/* REPEAT-able instruction */
				do {
					register int c = *tp;
					if G_UNLIKELY('\0' == c) goto eot;
					if G_UNLIKELY('\n' == c) goto fail;
					REX_DEBUG(RE_D_MI_MATCH, "matched any on '%c'", c);
					tp += dr;
				} while (repeat.rex == inst.ip && 0 != --repeat.n);
				continue;
			case RE_MOP_ALL:
				/* REPEAT-able instruction */
				do {
					register int c = *tp;
					if G_UNLIKELY('\0' == c) goto eot;
					REX_DEBUG(RE_D_MI_MATCH, "matched all on '%c'", c);
					tp += dr;
				} while (repeat.rex == inst.ip && 0 != --repeat.n);
				continue;
			case RE_MOP_POP_FSP:
				{
					uint32 sp;

					POP_TOP(sp);			/* The pushed FSP */
					fsp = ptr_add_offset(regs->fsp_bot, sp);
					if (ptr_cmp(fsp, regs->fsp_bot) < 0) goto stack_fault;
					if (ptr_cmp(fsp, tsp) > 0)           goto stack_fault;

					REX_DEBUG(RE_D_MI_MATCH, "popped FSP=%04X", FSP);
				}
				continue;
			case RE_MOP_CEX:
				cex = pc;		/* The PC of the next instruction to guard */
				CF  = TRUE;
				REX_DEBUG(RE_D_MI_MATCH, "C <- 1, guarding PC=%04X", PC);
				continue;
			}
			g_assert_not_reached();

		case RE_OP_INDEX:
			{
				register uint n;

				/* Decode the index argument */

				if (S(inst)) {
					n = (uint) *pc++;
				} else {
					n = (uint) PEEK_LE16(pc);
					pc += 2;
				}

				if G_UNLIKELY(n >= code->tsp_words) goto bad_mword;

				/* Execute the indexed instruction with its argument */

				switch ((re_mi_iop_t) IOP(inst)) {
				case RE_IOP_SAVE_TP:
					rp[n] = TP;
					REX_DEBUG(RE_D_MI_MATCH,
						"rp[%u] <- %u (TP=%04X)", n, rp[n], TP);
					continue;
				case RE_IOP_SAVE_FSP:
					rp[n] = FSP;
					REX_DEBUG(RE_D_MI_MATCH,
						"rp[%u] <- %u (FSP=%04X)", n, rp[n], FSP);
					continue;
				case RE_IOP_CMP_TP:
					ZF = TP == rp[n];
					REX_DEBUG(RE_D_MI_MATCH,
						"Z <- %s: has rp[%u] = %u (TP=%04X), current TP=%04X",
						bool_to_string(ZF), n, rp[n], rp[n], TP);
					continue;
				case RE_IOP_LT_TP:
					ZF = (int) TP < (int) rp[n];
					REX_DEBUG(RE_D_MI_MATCH, "Z <- %s (TP=%d, rp[%u]=%d)",
						bool_to_string(ZF), TP, n, rp[n]);
					continue;
				case RE_IOP_CLEAR:
					rp[n] = 0;
					REX_DEBUG(RE_D_MI_MATCH, "rp[%u] <- 0", n);
					continue;
				case RE_IOP_INC_A:
					ar = ++(rp[n]);
					REX_DEBUG(RE_D_MI_MATCH, "A <- ++(rp[%u])=%u", n, ar);
					continue;
				case RE_IOP_LOAD_A:
					ar = rp[n];
					REX_DEBUG(RE_D_MI_MATCH, "A <- rp[%u]=%u", n, ar);
					continue;
				case RE_IOP_UPDATE_FTP:
					{
						uint32 *fp = ptr_add_offset(regs->fsp_bot, rp[n]);

						REX_DEBUG(RE_D_MI,
							"rp[%u] is %u (@FSP=%04X)", n, rp[n], rp[n]);

						if G_UNLIKELY(fp - regs->fsp_bot < 2 || fp > tsp)
							goto stack_fault;

						REX_DEBUG(RE_D_MI,
							"updating TP=%u with current TP=%u "
							"@FSP=%04X (FSP=%04X)",
							fp[-1], TP,
							(uint) ptr_diff(fp, regs->fsp_bot), FSP);

						fp[-1] = TP;
					}
					continue;

				case RE_IOP_MAX:
					break;
				}
			}
			g_assert_not_reached();

		case RE_OP_NEED:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = 1 + EMB(inst);

				EMB_FOLLOWUP(n, cs);
				if (!re_exec_has_enough_ahead(rmi->rec, tp, n))
					goto fail;
			}
			continue;

		case RE_OP_SET_A:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = EMB(inst);

				EMB_FOLLOWUP(n, cs);
				ar = (int) n;

				REX_DEBUG(RE_D_MI_MATCH, "A <- %d", ar);
			}
			continue;

		case RE_OP_RET_A:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = EMB(inst);

				EMB_FOLLOWUP(n, cs);
				ar = (int) n;

				REX_DEBUG(RE_D_MI_MATCH, "A <- %d, RET", ar);
				POP_PC();
			}
			continue;

		case RE_OP_SUB_TP:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = EMB(inst);

				EMB_FOLLOWUP(n, cs);
				tp -= n * dr;

				REX_DEBUG(RE_D_MI_MATCH, "TP -= %zd, now TP=%u", n * dr, TP);
			}
			continue;

		case RE_OP_UPDATE_FPC:
			{
				size_t n;
				re_op_cs_t cs  = CS(inst);
				re_op_cs_t fcs = FLG(inst);
				uint32 *fp;
				const uint8 *npc;

				if G_UNLIKELY(fcs & 0x100) goto illegal;

				/*
				 * No need to check TEXT boundaries, we have extra room for
				 * two CLE-encoded constants, to limit checking here.
				 */
				pc = re_mi_decode_immediate(pc, cs, 1, &n);
				RE_MI_JMP_OFFSET(pc, fcs, offset);

				if G_UNLIKELY(n >= code->tsp_words) goto bad_mword;

				if (RE_OP_CS_EMPTY == cs) {
					npc = re_mi_seg_at(text, offset);

					REX_DEBUG(RE_D_MI, "new PC is %04X (absolute)",
						re_mi_seg_offset(text, npc));
				} else {
					npc = pc + offset;

					REX_DEBUG(RE_D_MI, "new PC is %04X (%+d)",
						re_mi_seg_offset(text, npc), offset);

					if G_UNLIKELY(offset < 0 && ptr_cmp(npc, text->base) < 0)
						goto text_fault;
				}

				fp = ptr_add_offset(regs->fsp_bot, rp[n]);

				REX_DEBUG(RE_D_MI, "rp[%zu] is @FSP=%04X", n, rp[n]);

				if G_UNLIKELY(fp - regs->fsp_bot < 2 || fp > tsp)
					goto stack_fault;

				REX_DEBUG(RE_D_MI,
					"updating PC=%04X with new PC=%04X @FSP=%04X (FSP=%04X)",
					FSP_PC(fp[-2]),
					re_mi_seg_offset(text, npc),
					(uint) ptr_diff(fp, regs->fsp_bot), FSP);

				/* Patch the PC part of the 32-bit record */

				fp[-2] = (re_mi_seg_offset(text, npc) << 16) + FSP_TSP(fp[-2]);
			}
			continue;

		case RE_OP_REPEAT:
			{
				re_op_cs_t cs = CS(inst);

				repeat.n = FLG(inst);
				FLG_FOLLOWUP(repeat.n, cs);
				repeat.rex = pc;
				if (X(inst)) {
					/* Issue a CEX as well */
					cex = pc;
					CF  = TRUE;
					REX_DEBUG(RE_D_MI_MATCH, "C <- 1, guarding PC=%04X", PC);
				}
			}
			REX_DEBUG(RE_D_MI_MATCH, "repeating PC=%04X %zu time%s%s",
				PC, PLURAL(repeat.n), 0 == repeat.n ? " (infinitely)" : "");
			continue;

		case RE_OP_CAPTURE:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = 1 + FLG(inst);
				struct re_exec_ctx *rec = rmi->rec;

				FLG_FOLLOWUP(n, cs);

				if G_UNLIKELY(Z(inst)) {
					/* Dealing with back-reference */
					n--;	/* Back to a zero-based indexing */
					if G_UNLIKELY(n >= rec->re->backref_count) goto bad_range;
					if G_UNLIKELY(NULL == rec->bvec)           goto illegal;
					if (X(inst)) {
						/* End of ref #n */
						rec->bvec[n].re_end = TP;
						REX_DEBUG(RE_D_MI_MATCH,
							"ref #%zu end: %u", n + 1, TP);
					} else {
						/* Start of ref #n */
						rec->bvec[n].re_start = TP;
						REX_DEBUG(RE_D_MI_MATCH,
							"ref #%zu start: %u", n + 1, TP);
					}
				} else if (0 == (eflags & RE_X_NOSUB)) {
					/* Dealing with capture group */
					if (X(inst)) {
						/* End of group #n */
						if (rec->mvec != NULL && n < rec->mcnt)
							rec->mvec[n].re_end = TP;
						REX_DEBUG(RE_D_MI_MATCH,
							"group #%zu end: %u", n, TP);
					} else {
						/* Start of group #n */
						if (rec->mvec != NULL && n < rec->mcnt)
							rec->mvec[n].re_start = TP;
						REX_DEBUG(RE_D_MI_MATCH,
							"group #%zu start: %u", n, TP);
					}
				}
			}
			continue;

		case RE_OP_XCALL:
			{
				re_op_cs_t cs = CS(inst);
				int r;

				RE_MI_JMP_OFFSET(pc, cs, offset);
				PUSH_PC();
				SET_PC_DESTINATION(cs, offset);
				SYNC_REGS();
				r = re_mi_xcall(rmi, pc);
				POP_PC();
				REX_DEBUG(RE_D_MI_MATCH, "XCALL returned %d, PC=%04X", r, PC);
				if (r < 0) {
					error = r;
					goto fatal;
				}
				if (X(inst)) r = !r;
				if (Z(inst)) {
					ZF = booleanize(r);
				} else if (!r) goto fail;
			}
			continue;


		case RE_OP_CALL:
			{
				re_op_cs_t cs = CS(inst);

				/* ZX guards not used for CALL */
				RE_MI_JMP_OFFSET(pc, cs, offset);
				PUSH_PC();
				SET_PC_DESTINATION(cs, offset);
			}
			continue;

		case RE_OP_JMP:
			{
				re_op_cs_t cs = CS(inst);

				RE_MI_JMP_OFFSET(pc, cs, offset);
				HANDLE_ZX_GUARD();
				SET_PC_DESTINATION(cs, offset);
			}
			continue;

		case RE_OP_UJMP:
			{
				re_op_cs_t cs = CS(inst);

				/* No ZX guards for unconditional JMP */
				RE_MI_JMP_OFFSET(pc, cs, offset);
				SET_PC_DESTINATION(cs, offset);
			}
			continue;

		case RE_OP_FAIL_JMP:
			{
				re_op_cs_t cs = CS(inst);

				RE_MI_JMP_OFFSET(pc, cs, offset);
				PUSH_FAIL();
				SET_PC_DESTINATION(cs, offset);
			}
			continue;

		case RE_OP_DJMP:
			{
				size_t n;

				/* Decode the index argument */

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);

				if G_UNLIKELY(n >= code->tsp_words) goto bad_mword;

				/* Decode the offset as unsigned 8-bit or 16-bit value */

				if G_UNLIKELY(X(inst)) {
					offset = (int16) PEEK_LE16(pc);
					pc += 2;
				} else {
					offset = (int8) *pc++;
				}

				/* Execution */

				REX_DEBUG(RE_D_MI, "rp[%zu] <- %u - 1 = %u",
					n, rp[n], rp[n] - 1);

				if (Z(inst)) {
					/* JMP if word is zero */
					if (0 == --(rp[n])) {
						pc += offset;
						REX_DEBUG(RE_D_MI, "Z, jumping to %04X (+%d)",
							PC, offset);
					}
				} else {
					/* JMP if word is non-zero */
					if (0 != --(rp[n])) {
						pc += offset;
						REX_DEBUG(RE_D_MI, "NZ, jumping to %04X (-%d)",
							PC, offset);
					}
				}
				if G_UNLIKELY(offset < 0 && ptr_cmp(pc, text->base) < 0)
					goto text_fault;
			}
			continue;

		case RE_OP_XJMP:
			{
				bool z = Z(inst);
				size_t n;

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);

				if G_UNLIKELY((uint) ar >= n)    goto bad_a_range;
				if G_UNLIKELY(pc + 2 * (n - z) > end) goto text_fault;

				if G_UNLIKELY(0 == ar)
					offset = z ? 2 * (int) (n - 1) : (int) PEEK_LE16(pc);
				else {
					const uint8 *p = pc + 2 * (ar - z);
					offset = PEEK_LE16(p);
				}

				SET_PC_FORWARD(offset);
			}
			continue;

		case RE_OP_XLOAD_A:
			{
				size_t n;

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);

				if G_UNLIKELY((uint) ar >= n) goto bad_a_range;

				if (RE_OP_CS_8BITS == FLG(inst)) {
					/* 8-bit values */
					if G_UNLIKELY(pc + n > end) goto text_fault;
					ar = pc[ar];
				} else {
					/* 16-bit values */
					const uint8 *p = pc + 2 * ar;
					n <<= 1;
					if G_UNLIKELY(pc + n > end) goto text_fault;
					ar = PEEK_LE16(p);
				}
				pc += n;
			}
			continue;

		case RE_OP_F_DROP_WORD:
			{
				re_op_cs_t cs = CS(inst);
				size_t n = 1 + EMB(inst);

				EMB_FOLLOWUP(n, cs);
				FAIL_POPPING(n);
				fsp -= n;

				REX_DEBUG(RE_D_MI,
					"dropped %zu word%s on FAIL stack, now @FSP=%04X",
					PLURAL(n), FSP);
			}
			continue;

		case RE_OP_F_PUSH_TRACK:
		case RE_OP_F_POP_TRACK:
			{
				re_op_cs_t fcs;
				size_t i, nr, nb;

				pc  = re_mi_decode_immediate(pc, CS(inst), 1, &nr);
				fcs = FLG(inst);

				switch (fcs) {
				case RE_OP_CS_8BITS:  nb = nr;     break;
				case RE_OP_CS_16BITS: nb = nr * 2; break;
				default: goto illegal;
				}

				/* See comment in RE_OP_MATCH below on comparison boundaries */

				if G_UNLIKELY(pc + nb > end) {
					REX_DEBUG(RE_D_MI_MATCH,
						"TEXT fault, nb=%zu, PC=%04X", nb, PC);
					goto text_fault;
				}

				/*
				 * We want this code to run as fast as possible, because
				 * it might be executed many times!
				 *
				 * We factor stack bondary checks outside the loop and
				 * we hardwire the constant decoding since all the word
				 * numbers are encoded the same way!  And since all PC
				 * boundary * checks were already done, the loop is simple.
				 */

				if (RE_OP_F_POP_TRACK == inst.opcode) {
					/* Running F_POP_TRACK */
					FAIL_POPPING(nr);
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i >= code->tsp_words) goto bad_mword;
							F_POP_TRACK(i);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i >= code->tsp_words) goto bad_mword;
							F_POP_TRACK(i);
						}
					}
				} else {
					/* Running F_PUSH_TRACK */
					FAIL_PUSHING(nr);
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i >= code->tsp_words) goto bad_mword;
							F_PUSH_TRACK(i);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i >= code->tsp_words) goto bad_mword;
							F_PUSH_TRACK(i);
						}
					}
				}
			}
			continue;

		case RE_OP_F_PUSH_GROUP:
		case RE_OP_F_POP_GROUP:
			{
				re_op_cs_t fcs;
				size_t i, nr, nb;
				struct re_exec_ctx *rec = rmi->rec;
				size_t ngroups = rec->re->group_count;

				pc  = re_mi_decode_immediate(pc, CS(inst), 1, &nr);
				fcs = FLG(inst);

				switch (fcs) {
				case RE_OP_CS_8BITS:  nb = nr;     break;
				case RE_OP_CS_16BITS: nb = nr * 2; break;
				default: goto illegal;
				}

				/* See comment in RE_OP_MATCH below on comparison boundaries */

				if G_UNLIKELY(pc + nb > end) {
					REX_DEBUG(RE_D_MI_MATCH,
						"TEXT fault, nb=%zu, PC=%04X", nb, PC);
					goto text_fault;
				}

				/*
				 * We want this code to run as fast as possible, because
				 * it might be executed many times!
				 *
				 * We factor stack bondary checks outside the loop and
				 * we hardwire the constant decoding since all the word
				 * numbers are encoded the same way!  And since all PC
				 * boundary * checks were already done, the loop is simple.
				 */

				if (RE_OP_F_POP_GROUP == inst.opcode) {
					/* Running F_POP_GROUP */
					FAIL_POPPING(nr * 2);	/* Popping start/end for each */
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i > ngroups) goto bad_group;
							F_POP_GROUP(i, rec);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i > ngroups) goto bad_group;
							F_POP_GROUP(i, rec);
						}
					}
				} else {
					/* Running F_PUSH_GROUP */
					FAIL_PUSHING(nr * 2);	/* Pushing start/end for each */
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i > ngroups) goto bad_group;
							F_PUSH_GROUP(i, rec);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i > ngroups) goto bad_group;
							F_PUSH_GROUP(i, rec);
						}
					}
				}
			}
			continue;

		case RE_OP_F_PUSH_REF:
		case RE_OP_F_POP_REF:
			{
				re_op_cs_t fcs;
				size_t i, nr, nb;
				struct re_exec_ctx *rec = rmi->rec;
				size_t nrefs = rec->re->backref_count;

				pc  = re_mi_decode_immediate(pc, CS(inst), 1, &nr);
				fcs = FLG(inst);

				switch (fcs) {
				case RE_OP_CS_8BITS:  nb = nr;     break;
				case RE_OP_CS_16BITS: nb = nr * 2; break;
				default: goto illegal;
				}

				/* See comment in RE_OP_MATCH below on comparison boundaries */

				if G_UNLIKELY(pc + nb > end) {
					REX_DEBUG(RE_D_MI_MATCH,
						"TEXT fault, nb=%zu, PC=%04X", nb, PC);
					goto text_fault;
				}

				/*
				 * We want this code to run as fast as possible, because
				 * it might be executed many times!
				 *
				 * We factor stack bondary checks outside the loop and
				 * we hardwire the constant decoding since all the word
				 * numbers are encoded the same way!  And since all PC
				 * boundary * checks were already done, the loop is simple.
				 */

				if (RE_OP_F_POP_REF == inst.opcode) {
					/* Running F_POP_REF */
					FAIL_POPPING(nr * 2);	/* Popping start/end for each */
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i >= nrefs) goto bad_group;
							F_POP_REF(i, rec);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i >= nrefs) goto bad_group;
							F_POP_REF(i, rec);
						}
					}
				} else {
					/* Running F_PUSH_REF */
					FAIL_PUSHING(nr * 2);	/* Pushing start/end for each */
					if (RE_OP_CS_8BITS == fcs) {
						while (nr--) {
							i = *pc++;
							if (i >= nrefs) goto bad_group;
							F_PUSH_REF(i, rec);
						}
					} else {
						while (nr--) {
							i = PEEK_LE16(pc);
							pc += 2;
							if (i >= nrefs) goto bad_group;
							F_PUSH_REF(i, rec);
						}
					}
				}
			}
			continue;

		case RE_OP_FAIL_OP:
			{
				size_t n;

				/* Decode immediate value */

				if (Z(inst)) {
					n = PEEK_LE16(pc);
					pc += 2;
				} else {
					n = *pc++;
				}

				/* Perform operation */

				if (X(inst)) {
					/* POP operation */
					FAIL_POPPING(1);
					switch (CS(inst)) {
					case RE_MI_FAIL_OP_TRACK:
						if (n >= code->tsp_words) goto bad_mword;
						F_POP_TRACK(n);
						break;
					case RE_MI_FAIL_OP_GROUP:
						{
							struct re_exec_ctx *rec = rmi->rec;
							size_t ngroups = rec->re->group_count;

							if (n > ngroups) goto bad_group;
							F_POP_GROUP(n, rec);
						}
						break;
					case RE_MI_FAIL_OP_REF:
						{
							struct re_exec_ctx *rec = rmi->rec;
							size_t nrefs = rec->re->backref_count;

							if (n >= nrefs) goto bad_group;	/* n is 0-based */
							F_POP_REF(n, rec);
						}
						break;
					default:
						goto illegal;
					}
				} else {
					/* PUSH operation */
					FAIL_PUSHING(1);
					switch (CS(inst)) {
					case RE_MI_FAIL_OP_TRACK:
						if (n >= code->tsp_words) goto bad_mword;
						F_PUSH_TRACK(n);
						break;
					case RE_MI_FAIL_OP_GROUP:
						{
							struct re_exec_ctx *rec = rmi->rec;
							size_t ngroups = rec->re->group_count;

							if (n > ngroups) goto bad_group;
							F_PUSH_GROUP(n, rec);
						}
						break;
					case RE_MI_FAIL_OP_REF:
						{
							struct re_exec_ctx *rec = rmi->rec;
							size_t nrefs = rec->re->backref_count;

							if (n >= nrefs) goto bad_group;	/* n is 0-based */
							F_PUSH_REF(n, rec);
						}
						break;
					default:
						goto illegal;
					}
				}
			}
			continue;

		case RE_OP_REF:
			{
				size_t nr;
				const re_match_t *m;
				const char *ref;
				size_t len;
				struct re_exec_ctx *rec = rmi->rec;

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &nr);
				if G_UNLIKELY(0 == nr)                      goto bad_range;
				nr--;	/* Back to 0-based indexing */
				if G_UNLIKELY(NULL == rec->bvec)            goto illegal;
				if G_UNLIKELY(nr >= rec->re->backref_count) goto bad_range;

				m = &rec->bvec[nr];
				len = m->re_end - m->re_start;
				ref = const_ptr_add_offset(tp_start, m->re_start);

				g_assert(size_is_non_negative(len));
				g_assert(ptr_cmp(ref, tp_start) >= 0);

				/* REPEAT-able instruction */
				do {
					REX_DEBUG(RE_D_MI_MATCH,
						"coming text=\"%.*s\", "
						"looking for \"%.*s\" (%zu byte%s)%s",
						(int) len, tp, (int) len, ref, PLURAL(len),
						X(inst) ? " (ignore case)" : "");

					if (X(inst)) {
						if (0 != strncasecmp((char *) tp, ref, len))
							goto fail;
					} else {
						if (0 != strncmp((char *) tp, ref, len))
							goto fail;
					}
					tp += dr * len;
				} while (repeat.rex == inst.ip && 0 != --repeat.n);
			}
			continue;

		case RE_OP_MATCH:
			{
				re_op_cs_t cs = CS(inst);

				/* This is a REPEAT-able instruction */

				if (RE_OP_CS_EMPTY == cs) {
					int (*conv)(int) = re_convert[X(inst)];

					do {
						int c = (*conv)(*tp);

						/* Matching an immediate single char */

						if G_UNLIKELY('\0' == c) {
							pc++;		/* Must skip argument in case of CEX */
							goto eot;
						}

						REX_DEBUG(RE_D_MI_MATCH, "%c-matching '%c' with '%c'",
							X(inst) ? 'i' : 's', *pc, c);

						if (c != *pc) {
							pc++;
							goto fail;
						}

						REX_DEBUG(RE_D_MI_MATCH, "%c-matched '%c'",
							X(inst) ? 'i' : 's', c);

						tp += dr;
					} while (repeat.rex == inst.ip && 0 != --repeat.n);
					pc++;		/* Skip matched character in TEXT segment */
					continue;
				} else {
					size_t nc, old_nc;
					const uchar *old_tp;

					/*
					 * Matching a sequence of characters.
					 *
					 * Note that pc already points at the fist byte of the
					 * constant we need to read here, hence to check that
					 * the whole matching bytes are held in the TEXT segment,
					 * we need to ensure that its last byte is.  In other
					 * words, we must satisfy:
					 *
					 * 		pc + (nc  -1) < end
					 *
					 * to be able to safely de-reference pc below.  Hence the
					 * failure check:
					 *
					 * 		pc + nc > end		// strict comparison
					 */

					pc = re_mi_decode_immediate(pc, cs, 1, &nc);

					if G_UNLIKELY(pc + nc > end) {
						REX_DEBUG(RE_D_MI_MATCH,
							"TEXT fault, nc=%zu, PC=%04X", nc, PC);
						goto text_fault;
					}

					old_nc = nc;

				repeat_match:		/* Avoid painful indentation if REPEAT */
					old_tp = tp;	/* Must restore TP if CEX */

					/*
					 * When moving to eot or fail labels, we need to ensure
					 * the PC is positioned at the end of the MATCH inlined
					 * data and that TP is properly restored, in case we are
					 * executing under CEX protection.
					 */

#if 0 				/* DISABLING -- Timing shows that this slows things down */

					/* We need `nc' characters ahead */

					if (!re_exec_has_enough_ahead(rmi->rec, tp, nc)) {
						REX_DEBUG(RE_D_MI_MATCH,
							"lacking required %zu character%s ahead", PLURAL(nc));
						pc += nc + 1;	/* Skip remaining if CEX */
						goto eot;		/* Like "fail" but logs "end of text" */
					}
#endif

					if (X(inst)) {
						while (nc--) {
							register int c = *tp;
							if G_UNLIKELY('\0' == c) {
								pc += nc + 1;	/* Skip remaining if CEX */
								tp = old_tp;
								goto eot;
							}
							REX_DEBUG(RE_D_MI_MATCH, "i-matching '%c' with '%c'",
								*pc, c);
							if (ascii_tolower(c) != *pc++) {
								pc += nc;		/* Skip remaining if CEX */
								tp = old_tp;
								goto fail;
							}
							REX_DEBUG(RE_D_MI_MATCH, "i-matched '%c'", c);
							tp += dr;
						}
					} else {
						while (nc--) {
							register int c = *tp;
							if G_UNLIKELY('\0' == c) {
								pc += nc + 1;	/* Skip remaining if CEX */
								tp = old_tp;
								goto eot;
							}
							REX_DEBUG(RE_D_MI_MATCH, "s-matching '%c' with '%c'",
								*pc, c);
							if (*pc++ != c) {
								pc += nc;		/* Skip remaining if CEX */
								tp = old_tp;
								goto fail;
							}
							REX_DEBUG(RE_D_MI_MATCH, "s-matched '%c'", c);
							tp += dr;
						}
					}

					/* Handle the REPEAT instruction */

					if (repeat.rex == inst.ip && 0 != --repeat.n) {
						nc = old_nc;
						pc -= nc;		/* Start of chars to match */
						goto repeat_match;
					}
				}
			}
			continue;

		case RE_OP_TRIE:
			{
				re_op_cs_t cs = CS(inst);
				int c = (*re_convert[Z(inst)])(*tp);
				size_t addr;
				const uint8 *dp;

				/* This instruction cannot be REPEAT-ed */

				if (RE_OP_CS_EMPTY == cs) {
					int min, max;

					/* Min and max arguments follow directly in the TEXT */
					min = *pc++;
					max = *pc++;

					if G_UNLIKELY('\0' == c) goto eot;

					REX_DEBUG(RE_D_MI_MATCH, "%c-matching '%c' with %s",
						Z(inst) ? 'i' : 's', c,
						re_mi_dump_minmax(min, max, FALSE));

					if (c < min || c > max) goto fail;

					ar = c - min;
					REX_DEBUG(RE_D_MI_MATCH, "A <- %d", ar);
				} else {
					size_t nb;
					uint8 pos;

					pc = re_mi_decode_immediate(pc, cs, 0, &addr);
					dp = re_mi_seg_at(data, addr);
					if G_UNLIKELY(!re_mi_seg_has(data, dp, 2)) goto data_fault;
					if G_UNLIKELY('\0' == c) goto eot;

					/*
					 * Deserializing leader:
					 *
					 * min    = dp[0]
					 * max    = dp[1]
					 *
					 * Timing shows that it is better to not create temporary
					 * variables for these values.
					 */

					nb = dp[1] - dp[0] + 1;
					if G_UNLIKELY(!re_mi_seg_has(data, dp, nb)) goto data_fault;

					REX_DEBUG(RE_D_MI_MATCH, "%c-matching '%c' with %s",
						Z(inst) ? 'i' : 's', c,
						re_mi_dump_byte_class(dp[0], dp[1], &dp[2]));

					if G_UNLIKELY(c < dp[0] || c > dp[1]) goto fail;
					if (0 == (pos = (&dp[2])[c - dp[0]])) goto fail;

					ar = pos - 1;
					REX_DEBUG(RE_D_MI_MATCH, "A <- %d", ar);
				}

				REX_DEBUG(RE_D_MI_MATCH, "matched '%c'", *tp);
				tp += dr;
			}
			continue;

		case RE_OP_CLASS:
			{
				re_op_cs_t cs = CS(inst);
				size_t addr;
				const uint8 *dp;
				bool ok;
				bool z = Z(inst);	/* Case insensitive? */
				bool x = X(inst);	/* Inverted */

				/* This is a REPEAT-able instruction */

				if (RE_OP_CS_EMPTY == cs) {
					int min, max;

					/* Min and max arguments follow directly in the TEXT */
					min = *pc++;
					max = *pc++;

					do {
						int c = (*re_convert[z])(*tp);

						if G_UNLIKELY('\0' == c) goto eot;

						REX_DEBUG(RE_D_MI_MATCH, "%c-matching '%c' with %s",
							z ? 'i' : 's', c,
							re_mi_dump_minmax(min, max, x));

						/*
						 * With an inverted class and RE_X_MULTI_LINE,
						 * we never match a \n to avoid accidentally moving
						 * to the next line of text.
						 */

						if (x) {
							ok = c < min || c > max;
							if (
								ok && '\n' == c &&
								(RE_X_MULTI_LINE & eflags)
							) {
								REX_DEBUG(RE_D_MI_MATCH,
									"not matching \\n with RE_X_MULTI_LINE");
								goto fail;
							}
						} else {
							ok = c >= min && c <= max;
						}

						if (!ok) goto fail;

						REX_DEBUG(RE_D_MI_MATCH, "matched '%c'", *tp);
						tp += dr;

					} while (repeat.rex == inst.ip && 0 != --repeat.n);
				} else {
					size_t nb;
					bit_field_t *b;
					int (*conv)(int) = re_convert[z];

					/*
					 * The information about what to match is held in
					 * the DATA segment, under the form of a serialized
					 * re_class_t structure.
					 *
					 * This scheme allows us to share the representation
					 * of classes, in case they are used more than once in
					 * the pattern.  Inlining them in the TEXT segment every
					 * time they occur would also increase the chance of
					 * having to process 16-bit relative jumps when repetitions
					 * are involved.
					 */

					pc = re_mi_decode_immediate(pc, cs, 0, &addr);
					dp = re_mi_seg_at(data, addr);
					if G_UNLIKELY(!re_mi_seg_has(data, dp, 3)) goto data_fault;

					/*
					 * Deserializing re_class_t:
					 *
					 * min    = dp[0]
					 * max    = dp[1]
					 * offset = dp[2]
					 *
					 * Timing shows that it is better to not create temporary
					 * variables for these values.
					 */

					nb = re_class_bytelen(dp[0], dp[1]);
					if G_UNLIKELY(!re_mi_seg_has(data, dp, nb)) goto data_fault;
					b = (bit_field_t *) &dp[3];

					do {
						int c = (*conv)(*tp);

						if G_UNLIKELY('\0' == c) goto eot;

						REX_DEBUG(RE_D_MI_MATCH, "%c-matching '%c' with %s",
							Z(inst) ? 'i' : 's', c,
							re_mi_dump_bit_class(
								dp[0], dp[1], dp[2], b, X(inst)));

						ok = re_class_char_in_field(c, dp[0], dp[1], dp[2], b);

						/*
						 * With an inverted class and RE_X_MULTI_LINE,
						 * we never match a \n to avoid accidentally moving
						 * to the next line of text.
						 */

						if (x) {
							ok = !ok;
							if (
								ok && '\n' == c &&
								(RE_X_MULTI_LINE & eflags)
							) {
								REX_DEBUG(RE_D_MI_MATCH,
									"not matching \\n with RE_X_MULTI_LINE");
								goto fail;
							}
						}

						if (!ok) goto fail;

						REX_DEBUG(RE_D_MI_MATCH, "matched '%c'", *tp);
						tp += dr;
					} while (repeat.rex == inst.ip && 0 != --repeat.n);
				}
			}
			continue;

		case RE_OP_HWCL:
			{
				re_class_check_t matcher;

				offset = CS(inst);
				if G_UNLIKELY(offset > RE_CLASS_POSIX_START / 2) goto illegal;

				/*
				 * The instruction architecture allows us to quickly
				 * compute the proper re_hardwired[] matcher.
				 */

				matcher = re_hardwired[offset + 3 * X(inst)];

				/* REPEAT-able instruction */
				do {
					int c = *tp;

					REX_DEBUG(RE_D_MI_MATCH, "hw-matching \\%c with '%c'",
						re_mi_hwc2char(FLG(inst), X(inst)), *tp);

					if G_UNLIKELY('\0' == c) goto eot;

					if (!(*matcher)(c))
						goto fail;

					REX_DEBUG(RE_D_MI_MATCH, "hw-matched '%c'", c);
					tp += dr;
				} while (repeat.rex == inst.ip && 0 != --repeat.n);
			}
			continue;

		case RE_OP_HWCL2:
			{
				re_class_check_t matcher;

				offset = FLG(inst);
				if ((uint) offset >= N_ITEMS(re_hardwired_2) / 2) goto illegal;

				/*
				 * The instruction architecture allows us to quickly
				 * compute the proper re_hardwired_2[] matcher.
				 */

				matcher = re_hardwired_2[offset + 2 * X(inst)];

				/* REPEAT-able instruction */
				do {
					int c = *tp;

					REX_DEBUG(RE_D_MI_MATCH, "hw-matching %s with '%c'",
						re_mi_hwc2str(offset, X(inst)), c);

					if G_UNLIKELY('\0' == c) goto eot;

					if (!(*matcher)(c))
						goto fail;

					REX_DEBUG(RE_D_MI_MATCH, "hw-matched '%c'", c);
					tp += dr;
				} while (repeat.rex == inst.ip && 0 != --repeat.n);
			}
			continue;

		case RE_OP_LT_A:
			{
				size_t n;

				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);

				/*
				 * Order of checks made by chance of occurring:
				 * we use CP_A when we can, hence tested first.
				 *
				 * @note
				 * Since EQ_A is not used, we assume Z is always 0
				 * below.  If used again, re-instantiate the code
				 * by removing the comment and the #if 0.
				 */

				if (X(inst)) {
					ZF = (uint) ar == (uint) n;
					CF = (uint) ar < (uint) n;

					REX_DEBUG(RE_D_MI_MATCH, "C <- (A=%u) < %u (%s)",
						ar, (uint) n, bool_to_string(CF));
				} else /* if (!Z(inst)) */
					ZF = (uint) ar <  (uint) n;

#if 0
				/* EQ_A is not used */
				else
					ZF = (uint) ar == (uint) n;
#endif

				REX_DEBUG(RE_D_MI_MATCH, "Z <- (A=%u) %s %u (%s)",
					ar, (Z(inst) || X(inst)) ? "==" : "<", (uint) n,
					bool_to_string(ZF));
			}
			continue;

		case RE_OP_RG_A:
			{
				size_t n, m;
				re_op_cs_t fcs = FLG(inst);

				if G_UNLIKELY(fcs & 0x100) goto illegal;

				/*
				 * No need to check TEXT boundaries, we have extra room for
				 * two CLE-encoded constants, to limit checking here.
				 */
				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);
				pc = re_mi_decode_immediate(pc, fcs,      1, &m);

				ZF = (uint) ar < (uint) n;
				CF = !ZF && (uint) ar < (uint) m;

				REX_DEBUG(RE_D_MI_MATCH, "Z <- (A=%u) < %u (%s)",
					ar, (uint) n, bool_to_string(ZF));
				REX_DEBUG(RE_D_MI_MATCH, "C <- (A=%u) >= %u && A < %u (%s)",
					ar, (uint) n, (uint) m, bool_to_string(CF));
			}
			continue;

		case RE_OP_LOAD:
			{
				size_t n, max;
				re_op_cs_t fcs = FLG(inst);

				if G_UNLIKELY(fcs & 0x100) goto illegal;

				/*
				 * No need to check TEXT boundaries, we have extra room for
				 * two CLE-encoded constants, to limit checking here.
				 */
				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);
				pc = re_mi_decode_immediate(pc, fcs,      1, &max);
				if G_UNLIKELY(n >= code->tsp_words) goto bad_mword;

				rp[n] = max;

				REX_DEBUG(RE_D_MI_MATCH, "rp[%zu] <- %u", n, rp[n]);
			}
			continue;

		case RE_OP_ADD:
			{
				size_t n, v;
				re_op_cs_t fcs = FLG(inst);

				if G_UNLIKELY(fcs & 0x100) goto illegal;

				/*
				 * No need to check TEXT boundaries, we have extra room for
				 * two CLE-encoded constants, to limit checking here.
				 */
				pc = re_mi_decode_immediate(pc, CS(inst), 1, &n);
				pc = re_mi_decode_immediate(pc, fcs,      1, &v);
				if G_UNLIKELY (n >= code->tsp_words) goto bad_mword;

				rp[n] += v;

				REX_DEBUG(RE_D_MI_MATCH, "rp[%zu] <- %u (%u + %u)",
					n, rp[n], rp[n] - (uint) v, (uint) v);
			}
			continue;

		case RE_OP_REW_TP:
			{
				register uint n;
				uchar constraint;
				const uchar *tp_min;
				size_t off = 0;

				/* Decode 'n', the reserved word number */

				if (Z(inst)) {
					n = (uint) PEEK_LE16(pc);
					pc += 2;
				} else {
					n = (uint) *pc++;
				}

				if G_UNLIKELY(n >= code->tsp_words) goto bad_mword;

				constraint = *pc++;

				if (CS(inst) != RE_OP_CS_EMPTY)
					pc = re_mi_decode_immediate(pc, CS(inst), 0, &off);

				tp_min = const_ptr_add_offset(tp_start, (int) rp[n]);
				tp--;

				if (0 == off) {
					/* Most common case, looking at first char */
					if (X(inst)) {
						/* Case insensitive matching */
						while (tp >= tp_min) {
							if (ascii_tolower(*tp) == constraint) {
								ZF = TRUE;
								goto resume;
							}
							tp--;
						}
					} else {
						/* Case sensitive matching */
						while (tp >= tp_min) {
							if (*tp == constraint) {
								ZF = TRUE;
								goto resume;
							}
							tp--;
						}
					}
				} else {
					/*
					 * Since we look ahead more than one character, we must
					 * first ensure we backtrack by offset characters.
					 */

					tp -= off;

					if (X(inst)) {
						/* Case insensitive matching */
						while (tp >= tp_min) {
							if (ascii_tolower(tp[off]) == constraint) {
								ZF = TRUE;
								goto resume;
							}
							tp--;
						}
					} else {
						/* Case sensitive matching */
						while (tp >= tp_min) {
							if (tp[off] == constraint) {
								ZF = TRUE;
								goto resume;
							}
							tp--;
						}
					}
				}
				ZF = FALSE;
			}
			continue;

		case RE_OP_ESCAPE:
		case RE_OP_MAX:
			break;
		}

		goto illegal;
	}

matched:
	error = +1;			/* Success! */

	/* FALL THROUGH */

done:
	SYNC_REGS();		/* Let them see registers we cached */

	REX_DEBUG(RE_D_MI, "executed %zu instruction%s", PLURAL(instructions));
	REX_RETURN(int, "%+d", error);

eot:
	REX_DEBUG(RE_D_MI_MATCH, "end of text");
	/* FALL THROUGH */
fail:
	/*
	 * The meaning of failure is changed when the previous instruction
	 * was a CEX: we do not backtrack, we simply clear the C flag.
	 *
	 * Note that the cex variable is kept intact, allowing one to perform
	 * efficient repetition loops without having to re-execute the CEX
	 * instruction, for instance with patterns like "a*+".
	 */

	if G_UNLIKELY(inst.ip == cex) {
		REX_DEBUG(RE_D_MI, "failure under CEX guard, clearing C");
		CF = FALSE;			/* Signals matching failure */
		goto resume;
	} else {
		REX_DEBUG(RE_D_MI, "attempting backtracking");
		POP_FAIL();
	}

	/* FALL THROUGH if no more entries on the FAIL stack */

no_backtracking:
	REX_DEBUG(RE_D_MI, "no backtracking left");

	/*
	 * No backtracking position, definitive failure then from the current
	 * starting point.
	 */

	if (next) {
		/*
		 * If we're allowed to look for the next starting point, find the
		 * suitable point in text to restart matching.
		 *
		 * This is faster than returning back to re_mi_match_here() and let
		 * it advance the text pointer to then call us again.  Yes, we are
		 * duplicating some of the code, but we save all the initial variable
		 * setup done at the top of this routine!
		 */

		if ('\0' == *rmi->rec->tp++)
			goto done;

		tp = re_exec_start_point(rmi->rec);

		if (tp != NULL) {
			rmi->rec->tp = tp;			/* Where we start from in text */
			rmi->start_tp = tp;			/* Starting match point */
			pc = re_mi_seg_base(text);	/* Reset PC to start of code */
			fsp = regs->fsp_bot;		/* Reset fail stack */
			tsp = regs->tsp_top;		/* Reset track stack */
#ifdef PRIVLOG_ENABLED
			rmi->rec->match_start = (uchar *) tp;
#endif
			REX_DEBUG(RE_D_MI, "%s(): restarting at TP=%u",
				G_STRFUNC, TP);
			re_exec_log_where(rmi->rec);
			goto resume;
		}

		tp = rmi->rec->tp;
	}

	goto done;

illegal:         error = RE_MI_ERR_ILL;       goto fatal;
stack_overflow:  error = RE_MI_ERR_OVFLOW;    goto fatal;
stack_underflow: error = RE_MI_ERR_UDFLOW;    goto fatal;
stack_fault:     error = RE_MI_ERR_SSEGV;     goto fatal;
text_fault:      error = RE_MI_ERR_TSEGV;     goto fatal;
data_fault:      error = RE_MI_ERR_DSEGV;     goto fatal;
stale_fail:      error = RE_MI_ERR_STALE;     goto fatal;
bad_mword:       error = RE_MI_ERR_MWORD;     goto fatal;
bad_range:       error = RE_MI_ERR_RANGE;     goto fatal;
bad_group:       error = RE_MI_ERR_GROUP;     goto fatal;
bad_a_range:     error = RE_MI_ERR_ARANGE;    goto fatal;
backtrack_limit: error = RE_MI_ERR_BACKTRACK; goto fatal;

	g_assert_not_reached();

fatal:
	REX_DEBUG(RE_D_MI, "error %d (%s)", error, re_execute_strerror(error));
	REX_DEBUG(RE_D_MI, "executed %zu instruction%s", PLURAL(instructions));
	REX_DEBUG(RE_D_MI, "PC  = %04X", (uint16) re_mi_seg_offset(text, inst.ip));
	REX_DEBUG(RE_D_MI, "TP  = %04X", TP);
	REX_DEBUG(RE_D_MI, "FSP = %04X", FSP);
	REX_DEBUG(RE_D_MI, "TSP = %04X", TSP);

	s_warning("%s(): "
		"%s at PC=%04X, TP=%04X, FSP=%04X, TSP=%04X, A=%d, Z=%s, C=%s",
		G_STRFUNC, re_execute_strerror(error),
		(uint16) re_mi_seg_offset(text, inst.ip), TP, FSP, TSP,
		ar, bool_to_string(ZF), bool_to_string(CF));

	longjmp(rmi->rec->matched, error);

#undef PC
#undef TP
#undef FSP
#undef TSP

#undef Z
#undef X
#undef CS
#undef FLG
#undef MOP
#undef IOP
#undef S
#undef EMB

#undef ZF
#undef CF
}

/**
 * Wrapper to recurse into re_mi_execute() when handling an XCALL instruction.
 *
 * @return +1 on success, 0 on failure and -1 on error.
 */
static int
re_mi_xcall(struct re_mi_ctx *rmi, const uint8 *pc)
{
	struct re_mi_regs *regs   = &rmi->regs;
	uint32 *tsp_top, *fsp_bot;
	int r;

	REX_ENTRY;

	/*
	 * Empty the current FAIL and TRACK stacks, so that already filled
	 * parts be invisible during the recursion.
	 */

	tsp_top = regs->tsp_top;
	fsp_bot = regs->fsp_bot;

	regs->fsp_bot = regs->fsp;
	regs->tsp_top = regs->tsp;

	REX_DEBUG(RE_D_MI, "%zu bytes available for stacks",
		ptr_diff(regs->tsp, regs->fsp));
	REX_DEBUG(RE_D_MI, "external re-entry at PC=%04X",
		re_mi_seg_offset(&rmi->code->text, pc));

	regs->pc = pc;

	/*
	 * Note that we do not let re_mi_execute() find a next starting point.
	 * If it does not match from the current position we are at, then it
	 * is a matching failure.
	 */

	r = re_mi_execute(rmi, FALSE);

	regs->fsp_bot = fsp_bot;
	regs->tsp_top = tsp_top;

	REX_RETURN(int, "[XCALL return] %d", r);
}

/**
 * Initiate byte-code matching starting at given text position.
 *
 * @return +1 if we matched, 0 if we did not match and -1 on error.
 */
static int
re_mi_match_here(struct re_mi_ctx *rmi)
{
	struct re_exec_ctx *rec = rmi->rec;
	int ret;

	re_exec_ctx_check(rec);

	REX_ENTRY;

	re_exec_check_stack(rec);
	re_exec_log_where(rec);

	rmi->regs.tp  = rec->tp;
	rmi->regs.pc  = re_mi_seg_base(&rmi->code->text);
	rmi->regs.fsp = rmi->regs.fsp_bot;
	rmi->regs.tsp = rmi->regs.tsp_top;

#ifdef PRIVLOG_ENABLED
	rmi->rec->match_start = rec->tp;
#endif

	/*
	 * We will let re_mi_execute() advance to the next suitable matching
	 * point if it does not match here, so that we can save on the setup
	 * time done at the beginning of re_mi_execute()!
	 */

	ret = re_mi_execute(rmi, TRUE);

	if (ret > 0)
		rec->tp = rmi->regs.tp;		/* Where we stopped match */

	REX_RETURN(int, "%+d", ret);
}

/**
 * Main entry point for regular expression matching using the byte-code
 * interpreter
 *
 * It has the exact same interface as re_exec_match() so that we can call
 * either independently.
 *
 * @return +1 if we matched, 0 if we did not match and negative code on error.
 */
static int
re_mi_match(struct re_exec_ctx *rec)
{
	struct re_mi_ctx ctx;
	const uchar *tp;
	int ret;

	PRIVLOG_DECLARE_LEVEL(indent);

	re_exec_ctx_check(rec);

	REX_ENTRY;
	PRIVLOG_SAVE_LEVEL(indent);

	re_exec_check_stack(rec);	/* Just starting, track minimal usage so far */

	ZERO(&ctx.regs);
	ctx.code    = rec->re->bytecode;
	ctx.stacksz = MIN(RE_MI_STACK, rec->max_stack);
	ctx.rec     = rec;
	ctx.stack   = alloca(ctx.stacksz);

	g_assert(ctx.stack != NULL);

	REX_DEBUG(RE_D_MI, "allocated fail/track stack of %zu byte%s",
		PLURAL(ctx.stacksz));

	ctx.regs.fsp_bot = cast_to_pointer(ctx.stack);
	ctx.regs.tsp_top = ptr_add_offset(ctx.stack, ctx.stacksz);
	ctx.regs.tsp_top -= ctx.code->tsp_words;		/* Reserved space */
	ctx.regs.rp      = ctx.regs.tsp_top;
	ctx.regs.fsp_max = ctx.regs.fsp_bot;
	ctx.regs.tsp_min = ctx.regs.tsp_top;

	re_exec_check_stack(rec);	/* Now that we ran alloca() */

	tp = re_exec_start_point(rec);
	if (NULL == tp) {
		ret = 0;
		goto failed;
	}

	if ((ret = Setjmp(rec->matched))) {
		PRIVLOG_RESTORE_LEVEL(indent);
		if (ret <= 0)
			REX_RETURN(bool, "[after longjmp()] %d", ret);
	}

	ctx.start_tp = rec->tp = tp;
	ret = re_mi_match_here(&ctx);

	if (ret) {
		REX_DEBUG(RE_D_MI, "MATCHED");
		re_exec_matched(rec, 0, ctx.start_tp);
	}

	/* FALL THROUGH */

failed:
	REX_DEBUG(RE_D_MI, "max fail stack usage: %zd byte%s",
		PLURAL(ptr_diff(ctx.regs.fsp_max, ctx.regs.fsp_bot)));

	REX_DEBUG(RE_D_MI, "max track stack usage: %zd byte%s",
		PLURAL(ptr_diff(ctx.regs.tsp_top, ctx.regs.tsp_min)));

	REX_DEBUG(RE_D_MI, "unused fail/track stack space: %zd byte%s",
		PLURAL(ptr_diff(ctx.regs.tsp_min, ctx.regs.fsp_max)));

	REX_DEBUG(RE_D_MI, "reserved stack space: %zu bytes",
		ctx.code->tsp_words * sizeof(uint32));

	/*
	 * Adjust stack statistics, amount perused by re_execute_stats(),
	 * to hide the large stack we pre-allocated and only account for
	 * what we really consumed out of it.
	 */

	rec->max_stack_used += - ctx.stacksz +
		ptr_diff(ctx.regs.fsp_max, ctx.regs.fsp_bot) +	/* FAIL stack */
		ptr_diff(ctx.regs.tsp_top, ctx.regs.tsp_min) +	/* TRACK stack */
		ctx.code->tsp_words * sizeof(uint32);			/* Reserved words */

	REX_RETURN(int, "%+d", ret);
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
	tm_nano_t start, end;
	bool needs_engine;

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

	needs_engine = re_exec_needs_engine(re);

	if (stats != NULL) {
		stats->engine = needs_engine;
		tm_precise_time(&start);
	}

	if (needs_engine) {
		/*
		 * If we have a "must" string, see whether it is present in the
		 * text being matched.
		 */

		if (re->must != NULL && !re_exec_has_must(&ctx)) {
			REX_DEBUG(RE_D_EXEC,
				"lacks \"%s\" string", pattern_string(re->must));
			r = 0;
			goto done;
		}

		if (eflags & RE_X_USE_BC) {
			if (eflags & RE_X_DEBUG) {
				re_regex_t recpy = *re;
				recpy.bytecode = NULL;
				re_mi_generate(&recpy, TRUE);
				ctx.re = &recpy;
				r = re_mi_match(&ctx);
				re_mi_free(recpy.bytecode);
			} else {
				r = re_mi_match(&ctx);
			}
		} else
			r = re_exec_match(&ctx);
	} else {
		r = re_exec_match_directly(&ctx);
	}

done:
	if (stats != NULL) {
		tm_precise_time(&end);
		stats->elapsed    = (size_t) tm_precise_elapsed_ns(&end, &start);
		stats->stack_max  = ctx.max_stack;
		stats->stack_used = ctx.max_stack_used;
		stats->remi = stats->engine && booleanize(eflags & RE_X_USE_BC);
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

	REX_RETURN(int, "%d", r);
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
