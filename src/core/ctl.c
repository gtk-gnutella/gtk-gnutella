/*
 * Copyright (c) 2009, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Country limits.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "ctl.h"
#include "geo_ip.h"
#include "whitelist.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/iso3166.h"
#include "lib/misc.h"
#include "lib/pslist.h"
#include "lib/walloc.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Parsing token types.
 */
enum ctl_toktype {
	CTL_TOK_EOF = 0,		/**< End of file */
	CTL_TOK_ERROR,			/**< Error, unknown token */
	CTL_TOK_ID,				/**< Identifier */
	CTL_TOK_COLON,			/**< A ':' character */
	CTL_TOK_LBRACE,			/**< A '{' character */
	CTL_TOK_RBRACE,			/**< A '}' character */
	CTL_TOK_COMMA,			/**< A ',' character */
	CTL_TOK_MAX
};

/**
 * Attached token value.
 */
union ctl_tokval {
	char c;					/**< For single character tokens */
	char *s;				/**< Identifier string, halloc()-ed */
};

/**
 * A parsed token.
 */
struct ctl_tok {
	enum ctl_toktype type;	/**< Token type */
	union ctl_tokval val;	/**< Lexical value */
	const char *start;		/**< Start position */
};

/**
 * The parsed string.
 */
struct ctl_string {
	const char *str;		/**< The string, NUL-terminated */
	const char *p;			/**< Next char to parse */
	struct ctl_tok *unread;	/**< Unread token */
};

/**
 * Allocate a new token.
 */
static struct ctl_tok *
ctl_token_alloc(enum ctl_toktype type, const char *start)
{
	struct ctl_tok *tok;

	WALLOC(tok);
	tok->type = type;
	tok->val.s = NULL;
	tok->start = start;

	return tok;
}

/**
 * Free parsed token.
 */
static void
ctl_token_free(struct ctl_tok *tok)
{
	g_assert(tok != NULL);

	if (CTL_TOK_ID == tok->type) {
		HFREE_NULL(tok->val.s);
	}
	WFREE(tok);
}

/**
 * Free parsed token and nullify holding variable.
 */
static void
ctl_token_free_null(struct ctl_tok **tok_ptr)
{
	struct ctl_tok *tok = *tok_ptr;

	if (tok) {
		ctl_token_free(tok);
		*tok_ptr = NULL;
	}
}

/**
 * Fetch next token from input string.
 */
static struct ctl_tok *
ctl_next_token(struct ctl_string *s)
{
	/*
	 * If we have a read-ahead token, reuse it.
	 */

	if (s->unread != NULL) {
		struct ctl_tok *tok = s->unread;
		s->unread = NULL;
		return tok;
	}

	/*
	 * Read next token.
	 */

	s->p = skip_ascii_blanks(s->p);

	if ('\0' == *s->p)
		return ctl_token_alloc(CTL_TOK_EOF, s->p);

	switch (*s->p) {
	case '{':	s->p++; return ctl_token_alloc(CTL_TOK_LBRACE, s->p);
	case '}':	s->p++; return ctl_token_alloc(CTL_TOK_RBRACE, s->p);
	case ':':	s->p++; return ctl_token_alloc(CTL_TOK_COLON, s->p);
	case ',':	s->p++; return ctl_token_alloc(CTL_TOK_COMMA, s->p);
	default:	break;
	}

	if (is_ascii_alnum(*s->p)) {
		const char *start = s->p;
		struct ctl_tok *tok = ctl_token_alloc(CTL_TOK_ID, s->p);
		size_t len;

		s->p = skip_ascii_alnum(s->p);
		len = s->p - start;
		tok->val.s = halloc(len + 1);
		clamp_strncpy(tok->val.s, len + 1, start, len);
		return tok;
	} else {
		struct ctl_tok *tok = ctl_token_alloc(CTL_TOK_ERROR, s->p);
		tok->val.c = *s->p;
		return tok;
	}

	g_assert_not_reached();
	return NULL;
}

/**
 * Put back token into string, nullifying its pointer.
 */
static void
ctl_unread(struct ctl_string *s, struct ctl_tok **tok_ptr)
{
	struct ctl_tok *tok;

	g_assert(tok_ptr != NULL);
	g_assert(NULL == s->unread);		/* Can only unread one token */

	tok = *tok_ptr;
	s->unread = tok;
	*tok_ptr = NULL;
}

/**
 * Known options
 */
static struct {
	char c;
	enum ctld flag;
} ctl_options[] = {
	/* Sorted array */
	{ 'a',	CTL_D_INCOMING | CTL_D_OUTGOING | CTL_D_GNUTELLA |
				CTL_D_BROWSE | CTL_D_UDP | CTL_D_QUERY | CTL_D_QHITS },
	{ 'b',	CTL_D_BROWSE },
	{ 'c',	CTL_D_CACHE },
	{ 'd',	CTL_D_MESH },
	{ 'g',	CTL_D_GNUTELLA },
	{ 'i',	CTL_D_INCOMING },
	{ 'n',	CTL_D_NORMAL },
	{ 'o',	CTL_D_OUTGOING },
	{ 'q',	CTL_D_QUERY },
	{ 'r',	CTL_D_QHITS },
	{ 's',	CTL_D_STEALTH },
	{ 'u',	CTL_D_UDP },
	{ 'w',	CTL_D_WHITELIST },

	/* Above line intentionnaly left blank (for "!}sort" within vi) */
};

/**
 * Convert option flags to string.
 * @return pointer to static data
 */
static const char *
ctl_flags2str(unsigned flags)
{
	static char buf[33];
	char *p = buf;

	if (flags & CTL_D_INCOMING)		*p++ = 'i';
	if (flags & CTL_D_OUTGOING)		*p++ = 'o';
	if (flags & CTL_D_GNUTELLA)		*p++ = 'g';
	if (flags & CTL_D_BROWSE)		*p++ = 'b';
	if (flags & CTL_D_UDP)			*p++ = 'u';
	if (flags & CTL_D_QUERY)		*p++ = 'q';
	if (flags & CTL_D_STEALTH)		*p++ = 's';
	if (flags & CTL_D_NORMAL)		*p++ = 'n';
	if (flags & CTL_D_MESH)			*p++ = 'd';
	if (flags & CTL_D_CACHE)		*p++ = 'c';
	if (flags & CTL_D_WHITELIST)	*p++ = 'w';
	if (flags & CTL_D_QHITS)		*p++ = 'r';

	*p++ = '\0';
	return buf;
}

/**
 * Compare two characters.
 */
static int
charcmp(char a, char b)
{
	return
		a == b ? 0 :
		UNSIGNED(a) < UNSIGNED(b) ? -1 : +1;
}

/**
 * Extract option flags.
 * @return 0 if option was not found, the corresponding flags otherwise.
 */
static unsigned
ctl_get_flags(char opt)
{
#define GET(i)		(ctl_options[(i)].c)
#define FOUND(i)	return ctl_options[(i)].flag

	/* Perform a binary search to find ``opt'' */
	BINARY_SEARCH(char, opt, N_ITEMS(ctl_options), charcmp, GET, FOUND);

#undef FOUND
#undef GET

	return 0;		/* Not found */
}

/**
 * Stringify a token.
 */
static const char *
ctl_tok2str(const struct ctl_tok *tok)
{
	static char buf[2];

	switch (tok->type) {
	case CTL_TOK_EOF:		return "<eof>";
	case CTL_TOK_ID:		return tok->val.s;
	default:				break;
	}

	buf[0] = tok->val.c;
	buf[1] = '\0';
	return buf;
}

/**
 * Report a syntax error at specified token.
 */
static void
ctl_error(const struct ctl_string *s,
	const struct ctl_tok *at, const char *expected)
{
	if (GNET_PROPERTY(ctl_debug)) {
		g_warning("CTL syntax error (position %zu, near \"%s\") in \"%s\"",
			at->start - s->str, ctl_tok2str(at), s->str);
		if (expected != NULL) {
			g_warning("CTL expected %s", expected);
		}
	}
}

/**
 * Report a warning at specified token.
 */
static void
ctl_warn(const struct ctl_string *s, const struct ctl_tok *at, const char *msg)
{
	if (GNET_PROPERTY(ctl_debug)) {
		g_warning("CTL (position %zu, near \"%s\") in \"%s\": %s",
			at->start - s->str, ctl_tok2str(at), s->str, msg);
	}
}

static htable_t *ctl_by_country;		/**< Options per country */
static unsigned ctl_all_flags;			/**< Set of flags used */

/**
 * Parse a single country held in the token.
 * @return list containing the parsed country code, an empty list if invalid.
 */
static pslist_t *
ctl_parse_country(struct ctl_string *s, const struct ctl_tok *tok)
{
	uint16 code;

	g_assert(CTL_TOK_ID == tok->type);

	code = iso3166_encode_cc(tok->val.s);

	if (ISO3166_INVALID == code) {
		ctl_warn(s, tok, "ignoring invalid country");
		return NULL;
	}

	return pslist_append(NULL, uint_to_pointer(code));
}

/**
 * Parse a list of countries until closing brace.
 * @return list containing the parsed country code, an empty list if invalid.
 */
static pslist_t *
ctl_parse_countries(struct ctl_string *s)
{
	pslist_t *sl = NULL;

	for (;;) {
		struct ctl_tok *tok = ctl_next_token(s);

		switch (tok->type) {
		case CTL_TOK_COMMA:
			ctl_token_free_null(&tok);
			continue;
		case CTL_TOK_RBRACE:
			ctl_token_free_null(&tok);
			goto out;
		case CTL_TOK_ID:
			sl = pslist_concat(sl, ctl_parse_country(s, tok));
			ctl_token_free_null(&tok);
			break;
		case CTL_TOK_EOF:
		default:
			ctl_error(s, tok, "country or '}'");
			ctl_token_free_null(&tok);
			goto out;
		}
	}

out:
	return sl;
}

/**
 * Parse options.
 * @return halloc()-ed option string, or NULL on error.
 */
static char *
ctl_parse_options(struct ctl_string *s)
{
	struct ctl_tok *tok = ctl_next_token(s);
	char *opt = NULL;

	if (CTL_TOK_ID != tok->type) {
		ctl_error(s, tok, "country options");
	} else {
		opt = h_strdup(tok->val.s);
	}

	ctl_token_free_null(&tok);
	return opt;
}

/**
 * Parse a list entry.
 * @return TRUE when done with input.
 */
static bool
ctl_parse_list_entry(struct ctl_string *s)
{
	struct ctl_tok *tok = ctl_next_token(s);
	pslist_t *countries = NULL;
	pslist_t *sl;
	char *opt = NULL;
	unsigned flags;
	bool done = FALSE;

	switch (tok->type) {
	case CTL_TOK_EOF:		done = TRUE; goto out;
	case CTL_TOK_ID:		countries = ctl_parse_country(s, tok); break;
	case CTL_TOK_LBRACE:	countries = ctl_parse_countries(s); break;
	default:				ctl_error(s, tok, "'{' or country"); goto out;
	}

	if (NULL == countries)
		goto out;

	/*
	 * Check presence of options
	 */

	ctl_token_free_null(&tok);
	tok = ctl_next_token(s);

	switch (tok->type) {
	case CTL_TOK_EOF:
	case CTL_TOK_COMMA:
		ctl_unread(s, &tok);
		break;
	case CTL_TOK_COLON:
		opt = ctl_parse_options(s);
		break;
	default:
		ctl_error(s, tok, "',' or ':' or EOF");
		goto out;
	}

	/*
	 * Compute flags.
	 */

	if (NULL == opt) {
		flags = ctl_get_flags('a');
	} else {
		char *p = opt;
		char c;

		flags = 0;

		while ((c = *p++)) {
			unsigned f = ctl_get_flags(c);
			if (0 == f)
				g_warning("CTL ignoring unknown option '%c'", c);
			flags |= f;
		}
	}

	/*
	 * Handle the country list in countries with options in opt.
	 * Nevermind superseding, the latest parsed is the winner.
	 */

	PSLIST_FOREACH(countries, sl) {
		unsigned code = pointer_to_uint(sl->data);

		htable_insert(ctl_by_country,
			uint_to_pointer(code), uint_to_pointer(flags));
		ctl_all_flags |= flags;

		if (GNET_PROPERTY(ctl_debug)) {
			g_debug("CTL %s => '%s' (%s)",
				iso3166_country_cc(code), ctl_flags2str(flags),
				iso3166_country_name(code));
		}
	}

out:
	pslist_free(countries);
	HFREE_NULL(opt);
	ctl_token_free_null(&tok);

	return done;
}

/**
 * Parse a comma-separated list of countries.
 */
static void
ctl_parse_list(struct ctl_string *s)
{
	while (!ctl_parse_list_entry(s)) {
		struct ctl_tok *tok = ctl_next_token(s);
		bool done = TRUE;

		switch (tok->type) {
		case CTL_TOK_EOF:	break;
		case CTL_TOK_COMMA:	done = FALSE; break;
		default:			ctl_error(s, tok, ","); break;
		}

		ctl_token_free_null(&tok);
		if (done)
			break;
	}
}

/**
 * Reset limits.
 */
static void
ctl_reset(void)
{
	htable_clear(ctl_by_country);
	ctl_all_flags = 0;
}

/**
 * Parse string.
 */
void
ctl_parse(const char *s)
{
	ctl_reset();

	if (s != NULL) {
		struct ctl_string str;

		str.str = s;
		str.p = s;
		str.unread = NULL;

		/*
		 * Format is:
		 *    <country>, <country>:<options>, {<country>, <country>}:<options>
		 *
		 * <country> is 2-letter ISO-3166 country code.
		 *
		 * <options> can be any combination of:
		 * i = do not accept incoming HTTP connections (uploads)
		 * o = do not make outoing HTTP connections (downloads)
		 * g = do not allow any Gnutella connection
		 * b = deny browse-host requests [implicit if "i"]
		 * u = deny Gnutella UDP (not including DHT and routed PUSH)
		 * q = do not answer Gnutella queries (hop=1 or OOB)
		 * r = ignore replies (query hits)
		 * a = all of the above ("qiobrug")
		 * s = stealth mode -- never give any feedback, just close connections
		 * n = reject with "unauthorized" message instead of explicit error
		 * d = no insertion into download mesh
		 * c = do not cache valid/fresh hosts
		 * w = allow whitelist overrides
		 *
		 * Default is "a", any specified option superseding the default.
		 * Use carefully.
		 */

		ctl_parse_list(&str);
		ctl_token_free_null(&str.unread);
	}

	if (GNET_PROPERTY(ctl_debug)) {
		g_debug("CTL full option set is '%s'", ctl_flags2str(ctl_all_flags));
	}
}

/**
 * Are specified flags all set for the country to which the IP address belongs?
 */
bool
ctl_limit(const host_addr_t ha, unsigned flags)
{
	uint16 code;
	unsigned cflags;

	/*
	 * Early optimization to avoid paying the price of gip_country_safe():
	 * If no flags are given, or the set of flags requested is not a subset
	 * of all the flags ever specified for all countries, we can return.
	 */

	if (0 == flags)
		return FALSE;

	if ((flags & ctl_all_flags) != flags)
		return FALSE;

	code = gip_country_safe(ha);

	if (ISO3166_INVALID == code)
		return FALSE;

	if (GNET_PROPERTY(ancient_version))
		return FALSE;

	cflags = pointer_to_uint(
		htable_lookup(ctl_by_country, uint_to_pointer(code)));

	if ((cflags & flags) != flags)
		return FALSE;

	if ((cflags & CTL_D_WHITELIST) && whitelist_check(ha))
		return FALSE;

	return TRUE;
}

/**
 * Initialization.
 */
void
ctl_init(void)
{
	ctl_by_country = htable_create(HASH_KEY_SELF, 0);
}

/**
 * Shutdown.
 */
void
ctl_close(void)
{
	ctl_reset();
	htable_free_null(&ctl_by_country);
}

/* vi: set ts=4 sw=4 cindent: */
