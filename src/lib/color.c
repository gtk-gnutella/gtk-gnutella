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
 * ANSI color support for terminals.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "color.h"

#include "ascii.h"
#include "bsearch.h"
#include "constants.h"
#include "log.h"
#include "misc.h"
#include "once.h"
#include "parse.h"
#include "pslist.h"
#include "str.h"
#include "strtok.h"
#include "tokenizer.h"

#include "override.h"			/* Must be the last header included */

#define COLOR_COUNT				8
#define COLOR_FG_BASE			30
#define COLOR_BG_OFFSET			10
#define COLOR_BRIGHT_OFFSET		60

#define COLOR_FG_BRIGHT_BASE	(COLOR_FG_BASE + COLOR_BRIGHT_OFFSET)

#define COLOR_BG_BASE			(COLOR_FG_BASE + COLOR_BG_OFFSET)
#define COLOR_BG_BRIGHT_BASE	(COLOR_BG_BASE + COLOR_BRIGHT_OFFSET)

#define COLOR_LAST_VALID		(COLOR_BG_BRIGHT_BASE + COLOR_COUNT - 1)

/*
 * Color tokens.
 *
 * The token value is their ANSI offset + 1 (0 forbidden for tokenizer).
 */
enum color {
	COLOR_BLACK		= 1,
	COLOR_RED		= 2,
	COLOR_GREEN		= 3,
	COLOR_YELLOW	= 4,
	COLOR_BLUE		= 5,
	COLOR_MAGENTA	= 6,
	COLOR_CYAN		= 7,
	COLOR_WHITE		= 8,

	COLOR_MAX,

	COLOR_NORMAL,
	COLOR_BOLD,
	COLOR_FAINT,
	COLOR_UNDERLINE,
	COLOR_BLINK,
	COLOR_INVERSE,

	COLOR_NONE		= 0
};

static bool
color_is_valid(const enum color c)
{
	return c > 0 && c < COLOR_MAX;
}

static inline void
color_check(const enum color c)
{
	g_assert(color_is_valid(c));
}

/*
 * Our internal text color representation.
 */
struct colortext {
	uint8 fg;			/* Foreground color (0 = unspecified) */
	uint8 bg;			/* Background color (0 = unspecified) */
	uint8 faint:1;		/* Whether text is in "faint" color */
	uint8 bold:1;		/* Whether text is with a "bold" (brighter) font */
	uint8 inverse:1;	/* Whether text is output in inverse video */
	uint8 underline:1;	/* Whether text is to be underlined */
	uint8 blink:1;		/* Whether text is to be slowly blinking */
};

/**
 * Known color names.
 */
static const tokenizer_t color_names[] = {
	/* sorted array */
	{ "black",		COLOR_BLACK },
	{ "blue",		COLOR_BLUE },
	{ "cyan",		COLOR_CYAN },
	{ "green",		COLOR_GREEN },
	{ "magenta",	COLOR_MAGENTA },
	{ "red",		COLOR_RED },
	{ "white",		COLOR_WHITE },
	{ "yellow",		COLOR_YELLOW },
};

/**
 * Known text attributes.
 */
static const tokenizer_t text_attributes[] = {
	/* sorted array */
	{ "blink",		COLOR_BLINK },
	{ "bold",		COLOR_BOLD },
	{ "faint",		COLOR_FAINT },
	{ "inverse",	COLOR_INVERSE },
	{ "normal",		COLOR_NORMAL },
	{ "underline",	COLOR_UNDERLINE },
};

/**
 * Escape color offset -> color name.
 */
static const char *color_to_text[] = {
	"black",
	"red",
	"green",
	"yellow",
	"blue",
	"magenta",
	"cyan",
	"white",
};

static const char *attributes_to_text[] = {
	"normal",
	"bold",
	"faint",
	"unsupported italic",
	"underline",
	"blink",
	"unsupported rapid blink",
	"inverse",
};

/**
 * Configures the color layer, once.
 */
static void
color_init_once(void)
{
	TOKENIZE_CHECK_SORTED(color_names);
	TOKENIZE_CHECK_SORTED(text_attributes);

	STATIC_ASSERT(N_ITEMS(color_names) == COLOR_MAX - 1);
	STATIC_ASSERT(N_ITEMS(color_to_text) == COLOR_COUNT);
}

/**
 * Initialization.
 */
void
color_init(void)
{
	static once_flag_t color_inited;

	ONCE_FLAG_RUN(color_inited, color_init_once);
}

/**
 * @return the ANSI color offset.
 */
static unsigned
color_offset(const enum color c)
{
	color_check(c);

	return (uint) c - 1;	/* By construction of the color value */
}

/**
 * @return the ANSI text escape.
 */
static unsigned
color_text_escape(const enum color c)
{
	switch (c) {
	case COLOR_NORMAL:		return 0;
	case COLOR_BOLD:		return 1;
	case COLOR_FAINT:		return 2;
	case COLOR_UNDERLINE:	return 4;
	case COLOR_BLINK:		return 5;
	case COLOR_INVERSE:		return 7;
	default:
		g_assert_not_reached();
	}
}

/**
 * @return the ANSI escape sequence to reset.
 */
const char *
color_reset(void)
{
	return "\033[m";		/* 0 is implied when missing */
}

/**
 * @return the ANSI escape sequence to turn inverse video on or off.
 */
const char *
color_inverse(bool on)
{
	return on ? "\033[7m" : "\033[27m";
}

/**
 * @return the ANSI escape sequence to turn underline on or off.
 */
const char *
color_underline(bool on)
{
	return on ? "\033[4m" : "\033[24m";
}

/**
 * @return the ANSI escape sequence to turn faint on or off.
 */
const char *
color_blink(bool on)
{
	return on ? "\033[5m" : "\033[25m";
}

/**
 * Set a text attribute.
 *
 * @param color		structure describing the text color
 * @param c			the text attribute to apply
 */
static void
color_set_text(struct colortext *color, enum color c)
{
	g_assert(color != NULL);
	g_assert(!color_is_valid(c));	/* Is not a color! */

#define SET(x)	color->x = TRUE; break;

	switch (c) {
	case COLOR_FAINT:     SET(faint);
	case COLOR_BOLD:      SET(bold);
	case COLOR_INVERSE:   SET(inverse);
	case COLOR_UNDERLINE: SET(underline);
	case COLOR_BLINK:     SET(blink);
	case COLOR_NORMAL:
		color->bold = color->inverse = color->underline =
			color->faint = color->blink = FALSE;
		break;
	default:
		g_assert_not_reached();
	}

#undef SET
}

/**
 * Set color value.
 *
 * @param color		structure describing the text color
 * @param c			the color attribute to apply
 * @param bright	whether to select a bright value
 * @param fg		whether to select a foreground text value
 */
static void
color_set_color(struct colortext *color, enum color c, bool bright, bool fg)
{
	uint8 base = COLOR_FG_BASE;

	g_assert(color != NULL);
	g_assert(color_is_valid(c));

	if (bright)
		base += COLOR_BRIGHT_OFFSET;
	if (!fg)
		base += COLOR_BG_OFFSET;

	base += color_offset(c);

	if (fg)	color->fg = base;
	else	color->bg = base;
}

/**
 * Add color to escape sequence.
 */
static void
color_add(str_t *s, enum color c)
{
	if (str_len(s) > 2)
		str_putc(s, ';');

	str_catf(s, "%u", color_text_escape(c));
}

/**
 * Generates color escape string from text color specification.
 *
 * @return a constant string that must not be freed.
 */
static const char *
color_to_escape(const struct colortext *color)
{
	str_t *s = str_new(0);
	const char *esc;

	g_assert(color != NULL);

	str_putc(s, '\033');	/* ESC */
	str_putc(s, '[');		/* Opens the escape sequence */

	if (color->fg != 0)
		str_catf(s, "%u", color->fg);

	if (color->bg != 0) {
		if (str_len(s) > 2)
			str_putc(s, ';');
		str_catf(s, "%u", color->bg);
	}

	if (color->bold)		color_add(s, COLOR_BOLD);
	if (color->faint)		color_add(s, COLOR_FAINT);
	if (color->underline)	color_add(s, COLOR_UNDERLINE);
	if (color->blink)		color_add(s, COLOR_BLINK);
	if (color->inverse)		color_add(s, COLOR_INVERSE);

	str_putc(s, 'm');		/* Closes the escape sequence */

	esc = constant_str(str_2c(s));
	str_destroy_null(&s);

	return esc;
}

/**
 * Report ambiguous token.
 *
 * @param name		the input token
 * @param matching	the list of matching entries
 */
static void
color_ambiguous(const char *name, pslist_t *matching)
{
	pslist_t *sl;
	str_t *s = str_new(0);


	PSLIST_FOREACH(matching, sl) {
		tokenizer_t *item = sl->data;
		if (sl != matching)
			STR_CAT(s, ", ");
		str_catf(s, "\"%s\"", item->token);
	}

	s_warning("ambiguous color token \"%s\" could mean either of: %s",
		name, str_2c(s));

	str_destroy_null(&s);
}

/**
 * Comparison routine for approximate (based on prefix) token matching.
 *
 * This is a bsearch_prefix() callback.
 */
static int
color_prefix_cmp(const void *key, const void *item)
{
	const char *name = key;
	const tokenizer_t *entry = item;

	if (is_strprefix(entry->token, name))
		return 0;

	return strcmp(name, entry->token);
}

/**
 * Lookup token in a sorted array of tokens by using prefix comparison.
 *
 * Only report successful tokenization if matching is non-ambiguous.
 *
 * @param s			the input string we are trying to tokenize
 * @param verbose	if TRUE, log ambiguous match
 * @param tvec		the vector of tokenizer_t items, defining the tokens
 * @param tcnt		the amount of items in the token vector
 */
static unsigned
color_prefix_tokenize(
	const char *s, bool verbose,
	const tokenizer_t *tvec, size_t tcnt)
{
	bsearch_status_t status;
	void *result;
	tokenizer_t *entry;

	status = bsearch_prefix(s, tvec, tcnt, sizeof tvec[0],
				color_prefix_cmp, &result);

	switch (status) {
	case BSEARCH_NONE:
		goto not_found;
	case BSEARCH_MULTI:
		goto ambiguous;
	case BSEARCH_SINGLE:
		entry = result;
		return entry->value;
	}

	g_assert_not_reached();

ambiguous:
	if (verbose) {
		pslist_t *match;

		match = bsearch_matching(s, tvec, tcnt, sizeof tvec[0],
					color_prefix_cmp, result);

		color_ambiguous(s, match);
		pslist_free(match);
	}

	/* FALL THROUGH */

not_found:
	return 0;		/* Tokenizer convention: 0 means not found */
}

#define COLOR_PREFIX_TOKENIZE(s, vec, verbose) \
	color_prefix_tokenize((s), (verbose), (vec), N_ITEMS(vec))

/**
 * Parse the color specification string and return the ANSI escape
 * sequence for it, or NULL if we cannot parse the string.
 *
 * The string is a semi-colon delimited set of specifications that can be:
 *
 * 	a color name, optionally preceded by "bright"
 *  one of the the words "inverse", "underline", "bold", "faint", "blink".
 *
 * The color name can start with "bg=" to specify background color, or
 * with "fg=" to specify foreground color.  If omitted, "fg=" is assumed.
 *
 * Examples of valid color specifications:
 *
 * 		"bright white; bg=bright blue"
 * 		"bold; white; bg=red; blink"
 *
 * @param spec		the color specification
 * @param silent	if TRUE, do not report error but return NULL
 *
 * @return a constant string that must not be freed, NULL on error if silent.
 */
const char *
color_escape(const char *spec, bool silent)
{
	strtok_t *st;
	const char *tok;
	struct colortext color;

	st = strtok_make_strip(spec);
	ZERO(&color);

	while ((tok = strtok_next(st, ";"))) {
		enum color c;
		bool fg = TRUE;		/* Assume foreground color */
		bool bright = FALSE;
		const char *original = tok;
		const char *name = tok;

		/* Is this a text property? */

		c = TOKENIZE(tok, text_attributes);

		/* Is this an abbreviated property? */

		if (COLOR_NONE == c)
			c = COLOR_PREFIX_TOKENIZE(tok, text_attributes, FALSE);

		if (c != COLOR_NONE) {
			color_set_text(&color, c);
			continue;
		}

		/* Has to be a color then */

		name = is_strprefix(tok, "fg=");
		if (NULL == name) {
			name = is_strprefix(tok, "bg=");
			if (name != NULL)
				fg = FALSE;
			else
				name = tok;
		}

		/* If color is bright, has to be specified now */

		tok = name;
		name = is_strprefix(tok, "bright");
		if (name != NULL) {
			bright = TRUE;
		} else if ('b' == tok[0]) {
			strtok_t *stb;
			const char *first;

			/* Check whether they abbreviated "bright" */

			stb = strtok_make_strip(tok);
			first = strtok_next(stb, " ");
			if (is_strprefix("bright", first)) {
				bright = TRUE;
				name = tok + vstrlen(first);	/* Move past abbreviation */
			}

			strtok_free_null(&stb);
		}

		if (bright)
			tok = skip_ascii_spaces(name);

		/* An empty string means nothing follows "bright" */

		if ('\0' == *tok) {
			if (!silent) {
				s_warning("%s(): color name must follow \"bright\"", G_STRFUNC);
				goto complain_tok;
			} else
				goto failed;
		}

		/* Remaining text must be a valid color name */

		c = TOKENIZE(tok, color_names);

		/* Is this an abbreviated color name? */

		if (COLOR_NONE == c)
			c = COLOR_PREFIX_TOKENIZE(tok, color_names, !silent);

		if (COLOR_NONE == c)
			goto complain;

		/* Good, we have a valid color specification */

		color_set_color(&color, c, bright, fg);
		continue;

	complain:
		if (silent)
			goto failed;
		/* Just to report ambiguous matches for text attributes */
		(void) COLOR_PREFIX_TOKENIZE(tok, text_attributes, TRUE);
		/* FALL THROUGH */
	complain_tok:
		s_carp("%s(): cannot find any valid color in \"%s\" from \"%s\"",
			G_STRFUNC, original, spec);
	}

	strtok_free_null(&st);
	return color_to_escape(&color);

failed:
	strtok_free_null(&st);
	return NULL;
}

/**
 * Append word to string.
 */
static void
color_add_str(str_t *s, const char *word)
{
	if (str_len(s) > 2)
		STR_CAT(s, "; ");

	str_cat(s, word);
}

/*
 * Append decompiled color to string.
 *
 * @param s			the string
 * @param prefix	prefix to add
 * @param v			the color code
 *
 * @return error status (TRUE means error)
 */
static bool
color_add_color(str_t *s, const char *prefix, uint v)
{
	if (v >= N_ITEMS(color_names))
		return TRUE;

	color_add_str(s, prefix);
	str_cat(s, color_to_text[v]);

	return FALSE;	/* OK */
}

/**
 * Decompile an escape sequence into text.
 *
 * @return pointer to static string.
 */
const char *
color_decompile(const char *esc)
{
	const char *p = esc;
	str_t *s = str_private(G_STRFUNC, 80);
	size_t len = vstrlen(esc);
	const char *tok;
	strtok_t *st;
	bool has_error = FALSE;

	str_reset(s);

	if ('\033' != *p++)
		return "not an escape sequence";

	if ('[' != *p++)
		return "unknown escape sequence";

	if ('m' != esc[len - 1])
		return "unterminated color escape sequence";

	st = strtok_make_nostrip(p);

	while ((tok = strtok_next(st, ";"))) {
		int error;
		uint v;

		if G_UNLIKELY('m' == *tok)
			break;

		v = parse_uint(tok, NULL, 10, &error);
		if (error != 0 || v > COLOR_LAST_VALID) {
			has_error = TRUE;
			errno = error;
			continue;
		}

		/* Our decompilation logic below depends on this ordering */
		STATIC_ASSERT(COLOR_BG_BRIGHT_BASE > COLOR_FG_BRIGHT_BASE);
		STATIC_ASSERT(COLOR_FG_BRIGHT_BASE > COLOR_BG_BASE);
		STATIC_ASSERT(COLOR_BG_BASE > COLOR_FG_BASE);
		STATIC_ASSERT(COLOR_FG_BASE >= N_ITEMS(attributes_to_text));

		if (v < N_ITEMS(attributes_to_text)) {
			color_add_str(s, attributes_to_text[v]);
		} else if (v >= COLOR_BG_BRIGHT_BASE) {
			v -= COLOR_BG_BRIGHT_BASE;
			has_error |= color_add_color(s, "bg=bright ", v);
		} else if (v >= COLOR_FG_BRIGHT_BASE) {
			v -= COLOR_FG_BRIGHT_BASE;
			has_error |= color_add_color(s, "bright ", v);
		} else if (v >= COLOR_BG_BASE) {
			v -= COLOR_BG_BASE;
			has_error |= color_add_color(s, "bg=", v);
		} else if (v >= COLOR_FG_BASE) {
			v -= COLOR_FG_BASE;
			has_error |= color_add_color(s, "", v);
		} else {
			has_error = TRUE;
		}
	}

	if (has_error)
		STR_CAT(s, " (invalid!)");

#if 0
	s_debug("%s(): decompiled \"%s\" into \"%s\"", G_STRFUNC, esc + 1, str_2c(s));
#endif

	strtok_free_null(&st);
	return str_2c(s);
}

/**
 * Emit a short manual about color specifications.
 */
void
color_manual(void)
{
	str_t *s = str_new(256);
	size_t i;

	s_info("color specification is a semi-colon separated set of keywords");
	s_info("there are color names and text attributes");
	s_info("color names may be preceded by the word \"bright\"");
	s_info("default is foreground text color; prefix by \"bg=\" for background");

	for (i = 0; i < N_ITEMS(color_names); i++) {
		if (i != 0)
			STR_CAT(s, ", ");
		str_catf(s, "\"%s\"", color_names[i].token);
	}

	s_info("colors are: %s", str_2c(s));

	str_reset(s);
	for (i = 0; i < N_ITEMS(text_attributes); i++) {
		if (i != 0)
			STR_CAT(s, ", ");
		str_catf(s, "\"%s\"", text_attributes[i].token);
	}

	s_info("text attributes are: %s", str_2c(s));
	str_destroy_null(&s);

	s_info("order does not matter, space between items is optional");
	s_info("examples: \"red\", \"red; bg=bright black; blink\", \"bold;green\"");
	s_info("names can be abbreviated as long as they are unique");
	s_info("tokens match text attributes first: \"bl\" is for \"blink\"");
	s_info("a leading \"fg=\" or \"bg=\" forces color context");
	s_info("\"fg=b\" stands for \"fg=bright\", not \"fg=black\"");
	s_info("examples: \"r\", \"r; bg=b blu; bla\"");
}

/* vi: set ts=4 sw=4 cindent: */
