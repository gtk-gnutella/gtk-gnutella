/*
 * $Id$
 *
 * Copyright (c) 2010, Raphael Manfredi
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
 * XML tree formatter.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

#include "xfmt.h"
#include "vxml.h"
#include "xnode.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/misc.h"		/* For CONST_STRLEN() */
#include "lib/nv.h"
#include "lib/ostream.h"
#include "lib/unsigned.h"
#include "lib/stacktrace.h"
#include "lib/symtab.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

static const char XFMT_CDATA_START[]	= "<![CDATA[";
static const char XFMT_CDATA_END[]		= "]]>";

#define XFMT_CDATA_OVERHEAD \
	(CONST_STRLEN(XFMT_CDATA_START) + CONST_STRLEN(XFMT_CDATA_END))

/**
 * First pass traversal context.
 *
 * During the first pass we look for namespaces to use and at which tree
 * depth they will be required so that we can declare them before.
 */
struct xfmt_pass1 {
	GHashTable *uri2depth;		/**< URI -> earliest depth seen */
	GHashTable *multiple;		/**< Records URIs seen in multiple siblings */
	GHashTable *attr_uris;		/**< URIs used by attributes */
	nv_table_t *uri2prefix;		/**< URI -> prefixes (declared in tree) */
	unsigned depth;				/**< Current tree depth */
};

/**
 * Second pass traversal context.
 */
struct xfmt_pass2 {
	GHashTable *depth2uri;		/**< declaration depth -> URI list */
	GHashTable *attr_uris;		/**< URIs used by attributes */
	ostream_t *os;				/**< Output stream */
	guint32 options;			/**< Formatter options */
	nv_table_t *uri2prefix;		/**< URI -> prefixes (user-supplied) */
	symtab_t *uris;				/**< URI -> prefixes symbol table */
	symtab_t *prefixes;			/**< prefixes -> URI symbol table */
	const char *default_ns;		/**< Default namespace (NULL if none) */
	unsigned depth;				/**< Current tree depth */
	unsigned pcount;			/**< Count of generated prefixes */
	unsigned last_was_nl:1;		/**< Emitted a "\n" previously */
	unsigned had_text:1;		/**< Whether we last emitted text */
};

static const char XFMT_DECL[]		= "<?xml version='1.1' standalone='yes'?>";
static const char XFMT_DECL_10[]	= "<?xml version=\"1.0\"?>";
static const char XFMT_EMPTY[]		= "/>\n";
static const char XFMT_GT[]			= ">";

/**
 * Record the need to declare URI at current depth.
 */
static void
xfmt_uri_declare(const char *uri, struct xfmt_pass1 *xp1, gboolean element)
{
	void *v = g_hash_table_lookup(xp1->uri2depth, uri);

	/*
	 * Since the hash table will not outlive the tree traversal,
	 * we can reference the strings within the tree freely without
	 * taking a copy.
	 */

	if (v == NULL) {
		gm_hash_table_insert_const(xp1->uri2depth, uri,
			uint_to_pointer(xp1->depth));
	} else {
		unsigned d = pointer_to_uint(v);
		if (xp1->depth < d) {
			gm_hash_table_insert_const(xp1->uri2depth, uri,
				uint_to_pointer(xp1->depth));
			g_hash_table_remove(xp1->multiple, uri);
		} else if (xp1->depth == d && element) {
			gm_hash_table_insert_const(xp1->multiple, uri, NULL);
		}
	}
}

/**
 * Record a tree-defined mapping between a prefix and a namespace URI.
 */
static void
xfmt_prefix_record(struct xfmt_pass1 *xp1, const char *prefix, const char *uri)
{
	nv_pair_t *nv;

	/*
	 * Our policy is to use one single prefix for a given namespace URI
	 * throughout the document.  Although several prefixes could be used.
	 * this is confusing to read and serves no value: a human will be mislead
	 * into thinking the two namespaces are different because they carry
	 * distinct prefixes, and a machine will not care about the prefix value.
	 */

	nv = nv_table_lookup(xp1->uri2prefix, uri);
	if (nv != NULL) {
		/*
		 * Silently ignore the mapping if we already have seen an identical one
		 * in the XML tree.
		 */

		if (strcmp(prefix, nv_pair_value_str(nv)) != 0) {
			g_warning("XFMT ignoring prefix '%s' for '%s': "
				"already saw '%s' earlier in the tree", prefix, uri,
				nv_pair_value_str(nv));
		}
	} else {
		/*
		 * New mapping.
		 */

		nv = nv_pair_make_static_str(uri, prefix);
		nv_table_insert_pair(xp1->uri2prefix, nv);
	}
}

/**
 * Process element-defined namespace/prefix associations.
 */
static void
xfmt_handle_pass1_ns(const char *prefix, const char *uri, void *data)
{
	struct xfmt_pass1 *xp1 = data;

	xfmt_prefix_record(xp1, prefix, uri);
}

/**
 * Check attributes for URI usage.
 */
static void
xfmt_handle_pass1_attr(const char *uri,
	const char *local, const char *value, void *data)
{
	struct xfmt_pass1 *xp1 = data;

	(void) local;
	(void) value;

	if (uri != NULL) {
		xfmt_uri_declare(uri, xp1, FALSE);

		if (xp1->attr_uris != NULL) {
			gm_hash_table_insert_const(xp1->attr_uris, uri, NULL);
		}
	}
}

/**
 * Pass 1 handler on each tree node entry.
 */
static gboolean
xfmt_handle_pass1_enter(xnode_t *xn, void *data)
{
	struct xfmt_pass1 *xp1 = data;

	xp1->depth++;

	if (xnode_is_element(xn)) {
		const char *uri = xnode_element_ns(xn);

		if (uri != NULL)
			xfmt_uri_declare(uri, xp1, TRUE);

		xnode_prop_foreach(xn, xfmt_handle_pass1_attr, xp1);
		xnode_ns_foreach(xn, xfmt_handle_pass1_ns, xp1);
	}

	return TRUE;
}

/**
 * Pass 1 handler on each tree node leave.
 */
static void
xfmt_handle_pass1_leave(xnode_t *xn, void *data)
{
	struct xfmt_pass1 *xp1 = data;

	g_assert(uint_is_positive(xp1->depth));
	(void) xn;

	xp1->depth--;
}

#define XFMT_M_SINGLE	(1 << 0)
#define XFMT_M_DOUBLE	(1 << 1)
#define XFMT_M_BOTH		(XFMT_M_SINGLE | XFMT_M_DOUBLE)

enum xfmt_quotes {
	XFMT_NO_QUOTES			= 0,
	XFMT_SINGLE_QUOTE		= XFMT_M_SINGLE,
	XFMT_DOUBLE_QUOTE		= XFMT_M_DOUBLE,
	XFMT_BOTH_QUOTES		= XFMT_M_BOTH
};

/**
 * Strip leading and trailing blanks in text string.
 *
 * @param text		start of text to strip (NUL-terminated)
 * @param len_ptr	updated with new length if non-NULL
 *
 * @returns start of new text, and adjusted length in case we stripped.
 */
static const char *
xfmt_strip_blanks(const char *text, size_t *len_ptr)
{
	const char *p = text;
	unsigned retlen;
	int c;
	gboolean seen_non_blank = FALSE;
	const char *last_non_blank;
	const char *first_non_blank;

	first_non_blank = last_non_blank = p = text;

	/*
	 * Text is NUL-terminated, so we can use utf8_decode_char_fast().
	 */

	while ('\0' != (c = utf8_decode_char_fast(p, &retlen))) {
		p += retlen;

		if (seen_non_blank) {
			if (is_ascii_space(c))
				last_non_blank = p;				/* next char */
		} else {
			if (!is_ascii_space(c)) {
				seen_non_blank = TRUE;
				last_non_blank = p;				/* next char */
				first_non_blank = p - retlen;	/* this char */
			}
		}
	}

	if (len_ptr != NULL)
		*len_ptr = last_non_blank - first_non_blank;

	return first_non_blank;
}

/**
 * Check text to see whether it contains a single quote, a double quote,
 * or both.
 */
static enum xfmt_quotes
xfmt_has_quotes(const char *text)
{
	const char *p = text;
	int c;
	int flags = 0;

	g_assert(text != NULL);

	/*
	 * Text is assumed to be valid UTF-8, and since we are looking for ASCII
	 * characters, there's no need to decode the UTF-8 encoding.
	 */

	while ('\0' != (c = *p++)) {
		if ('\'' == c) {
			flags |= XFMT_M_SINGLE;
			if (XFMT_M_BOTH == flags)
				break;
		} else if ('"' == c) {
			flags |= XFMT_M_DOUBLE;
			if (XFMT_M_BOTH == flags)
				break;
		}
	}

	return flags;
}

/**
 * Computes the escaping overhead on text.
 *
 * @param text		the text to scan (UTF-8)
 * @param amp		whether '&' also needs to be escaped
 * @param apos		whether signle quotes also need to be escaped
 * @param len		if non-NULL, filled with the input string length
 *
 * @return the overhead (additional characters) that will be required to
 * escape the text, 0 meaning there is no escaping required.
 */
static size_t
xfmt_text_escape_overhead(const char *text,
	gboolean amp, gboolean apos, size_t *len)
{
	const char *p = text;
	int c;
	size_t overhead = 0;

	g_assert(text != NULL);

	/*
	 * Text is assumed to be valid UTF-8, and since we are looking for ASCII
	 * characters, there's no need to decode the UTF-8 encoding.
	 */

	while ('\0' != (c = *p++)) {
		if (amp && '&' == c) {
			overhead += CONST_STRLEN("amp;");
		} else if (apos && '\'' == c) {
			overhead += CONST_STRLEN("apos;");
		} else if ('<' == c || '>' == c) {
			overhead += CONST_STRLEN("xt;");	/* "&lt;" or "&gt;" */
		}
	}

	if (len != NULL)
		*len = (p - text) - 1;

	return overhead;
}

/**
 * Escape text string, returning a newly allocated string.
 *
 * @param text		text with characters to escape (NUL-terminated)
 * @param amp		whether '&' also needs to be escaped
 * @param apos		whether single quotes also need to be escaped
 * @param newlen	computed length for the escaped string
 * 
 * @return escaped string, which must be freed via hfree().
 */
static char *
xfmt_text_escape(const char *text, gboolean amp, gboolean apos, size_t newlen)
{
	char *newtext;
	const char *p;
	char *q;
	char *end;
	int c;

	g_assert(text != 0);
	g_assert(size_is_positive(newlen));

	newtext = halloc(newlen + 1);		/* Trailing NUL */
	p = text;
	q = newtext;
	end = newtext + (newlen + 1);

	/*
	 * Text is assumed to be valid UTF-8, and since we are looking for ASCII
	 * characters, there's no need to decode the UTF-8 encoding.
	 */

	while ('\0' != (c = *p++)) {
		if (amp && '&' == c) {
			g_assert(q + CONST_STRLEN("&amp;") < end);
			*q++ = '&';
			*q++ = 'a';
			*q++ = 'm';
			*q++ = 'p';
			*q++ = ';';
		} else if (apos && '\'' == c) {
			g_assert(q + CONST_STRLEN("&apos;") < end);
			*q++ = '&';
			*q++ = 'a';
			*q++ = 'p';
			*q++ = 'o';
			*q++ = 's';
			*q++ = ';';
		} else if ('<' == c || '>' == c) {
			g_assert(q + CONST_STRLEN("&xt;") < end);
			*q++ = '&';
			*q++ = ('<' == c) ? 'l' : 'g';
			*q++ = 't';
			*q++ = ';';
		} else {
			*q++ = c;
		}
	}

	g_assert(q < end);
	g_assert(q + 1 == end);		/* Overhead was properly computed */

	*q++ = '\0';

	return newtext;
}

/**
 * @return suitable quoting char for text, or NUL if none is possible.
 */
static int
xfmt_quoting_char(const char *text)
{
	switch (xfmt_has_quotes(text)) {
	case XFMT_BOTH_QUOTES:		return '\0';
	case XFMT_NO_QUOTES:		return '"';
	case XFMT_SINGLE_QUOTE:		return '"';
	case XFMT_DOUBLE_QUOTE:		return '\'';
	}

	g_assert_not_reached();
}

/**
 * Free routine for namespace name/value pairs.
 */
static void
xfmt_nv_free(void *p, size_t unused_len)
{
	(void) unused_len;

	hfree(p);
}

/**
 * Declare user-defined mapping between a URI and a namespace.
 */
static void
xfmt_prefix_declare(struct xfmt_pass2 *xp2, const char *uri, const char *prefix)
{
	nv_pair_t *nv;

	nv = nv_table_lookup(xp2->uri2prefix, uri);
	if (nv != NULL) {
		/*
		 * Silently ignore the mapping if we already have seen an identical one
		 * in the XML tree during the first pass.
		 */

		if (strcmp(prefix, nv_pair_value_str(nv)) != 0) {
			g_warning("XFMT ignoring supplied prefix '%s' for '%s': "
				"already saw '%s' in the tree", prefix, uri,
				nv_pair_value_str(nv));
		}
	} else {
		/*
		 * New mapping.
		 */

		nv = nv_pair_make_static_str(uri, prefix);
		nv_table_insert_pair(xp2->uri2prefix, nv);
	}
}

/**
 * Declare association between a prefix and a namespace URI at
 * the current depth.
 *
 * @param xp2			the pass 2 context
 * @param prefix		declared prefix string
 * @param uri			namespace URI
 * @param free_prefix	whether the prefix string will have to be freed
 */
static void
xfmt_ns_declare(struct xfmt_pass2 *xp2,
	const char *prefix, const char *uri, gboolean free_prefix)
{
	nv_pair_t *nv;
	gboolean inserted;

	/*
	 * The prefix string is shared between the two symbol tables, and is
	 * optionally freed when the pair is removed from the uris table.
	 * Therefore, removal must be done on the prefixes symbol table first.
	 */

	nv = nv_pair_make_static_str(prefix, uri);
	inserted = symtab_insert_pair(xp2->prefixes, nv, xp2->depth);
	g_assert(inserted);

	nv = nv_pair_make_static_str(uri, prefix);
	if (free_prefix)
		nv_pair_set_value_free(nv, xfmt_nv_free);
	inserted = symtab_insert_pair(xp2->uris, nv, xp2->depth);
	g_assert(inserted);
}

/**
 * Allocate a prefix as a shorthand for the URI.
 *
 * @return prefix string to use, which will be freed by symbol tables
 * when leaving scope.
 */
static const char *
xfmt_new_prefix(struct xfmt_pass2 *xp2, const char *uri)
{
	const char *prefix = NULL;
	gboolean free_prefix = FALSE;

	/* The URI must not already exist in the symbol table */
	g_assert(NULL == symtab_lookup(xp2->uris, uri));

	/*
	 * Check whether user has a preference for the prefix to use.
	 *
	 * If there is a prefix, there must be no identical prefix in scope
	 * currently.
	 */

	if (xp2->uri2prefix != NULL)
		prefix = nv_table_lookup_str(xp2->uri2prefix, uri);

	if (prefix != NULL) {
		const char *used_uri = symtab_lookup(xp2->prefixes, prefix);

		if (used_uri != NULL) {
			g_warning("XFMT cannot use prefix '%s' for '%s': "
				"already used by '%s'", prefix, uri, used_uri);
			prefix = NULL;
		}
	}

	/*
	 * Allocate a new prefix if required.
	 */

	if (NULL == prefix) {
		prefix = h_strdup_printf("ns%u", xp2->pcount++);
		free_prefix = TRUE;
	}

	/*
	 * Record associations in the symbol tables.
	 */

	xfmt_ns_declare(xp2, prefix, uri, free_prefix);

	return prefix;
}

/**
 * Construct a list of prefixes to declare at this level.
 */
static GSList *
xfmt_ns_declarations(struct xfmt_pass2 *xp2)
{
	GSList *ns = NULL;
	GSList *sl, *uris;

	uris = g_hash_table_lookup(xp2->depth2uri, uint_to_pointer(xp2->depth));

	GM_SLIST_FOREACH(uris, sl) {
		const char *uri = sl->data;
		const char *prefix = xfmt_new_prefix(xp2, uri);

		ns = gm_slist_prepend_const(ns, prefix);
	}

	if (uris != NULL) {
		g_hash_table_remove(xp2->depth2uri, uint_to_pointer(xp2->depth));
		g_slist_free(uris);
	}

	return g_slist_reverse(ns);
}

/**
 * Transform a namespace URI into its prefix.
 */
static const char *
xfmt_uri_to_prefix(const struct xfmt_pass2 *xp2, const char *uri)
{
	const char *prefix;

	g_assert(uri != NULL);

	prefix = symtab_lookup(xp2->uris, uri);
	g_assert(prefix != NULL);

	return prefix;
}

/**
 * Emit namespace declarations.
 */
static void
xfmt_pass2_declare_ns(struct xfmt_pass2 *xp2, GSList *ns)
{
	GSList *sl;

	GM_SLIST_FOREACH(ns, sl) {
		const char *prefix = sl->data;
		const char *uri;
		int c;

		/*
		 * Do not declare the "xml" namespace.
		 * We can use '==' here because it's a constant string.
		 */

		if (prefix == VXS_XML)
			continue;

		/*
		 * We don't need to declare the default namespace though, unless
		 * it is used in attributes (since there is no default namespace
		 * for attributes).
		 */

		uri = symtab_lookup(xp2->prefixes, prefix);

		if (
			xp2->default_ns != NULL && 0 == strcmp(uri, xp2->default_ns) &&
			!gm_hash_table_contains(xp2->attr_uris, xp2->default_ns)
		)
			continue;

		c = xfmt_quoting_char(uri);
		g_assert(c != '\0');
		ostream_printf(xp2->os, " xmlns:%s=%c%s%c", prefix, c, uri, c);
	}
}

/**
 * Emit attributes.
 */
static void
xfmt_handle_pass2_attr(const char *uri,
	const char *local, const char *value, void *data)
{
	struct xfmt_pass2 *xp2 = data;
	int c;
	gboolean apos_escape = FALSE;
	size_t len;
	size_t overhead;

	if (uri != NULL) {
		ostream_printf(xp2->os, " %s:", xfmt_uri_to_prefix(xp2, uri));
	} else {
		ostream_putc(xp2->os, ' ');
	}

	/*
	 * Inspect value to select proper quoting.
	 */

	c = xfmt_quoting_char(value);

	if ('\0' == c) {
		apos_escape = TRUE;
		c = '\'';	/* We'll be quoting "'" so it's safe to use */
	}

	/*
	 * Now check for escaping of any '&', '<' or '>'.
	 */

	overhead = xfmt_text_escape_overhead(value, TRUE, apos_escape, &len);

	ostream_printf(xp2->os, "%s=%c", local, c);

	if (0 == overhead) {
		ostream_write(xp2->os, value, len);
	} else {
		char *escaped = xfmt_text_escape(value, TRUE, apos_escape,
			len + overhead);
		ostream_write(xp2->os, escaped, len + overhead);
		hfree(escaped);
	}

	ostream_putc(xp2->os, c);
}

/**
 * Indent if we just emitted a new-line.
 */
static void
xfmt_indent(const struct xfmt_pass2 *xp2)
{
	if (xp2->options & XFMT_O_NO_INDENT)
		return;

	if (xp2->last_was_nl) {
		unsigned i;

		for (i = 1; i < xp2->depth; i++) {
			ostream_putc(xp2->os, '\t');
		}
	}
}

/**
 * Leaving scope.
 */
static inline void
xfmt_pass2_leaving(struct xfmt_pass2 *xp2)
{
	g_assert(uint_is_positive(xp2->depth));

	/*
	 * Need to clear the prefixes table first: see xfmt_ns_declare().
	 */

	symtab_leave(xp2->prefixes, xp2->depth);
	symtab_leave(xp2->uris, xp2->depth);

	xp2->depth--;
}

/**
 * Pass 2 handler on each tree node entry.
 */
static gboolean
xfmt_handle_pass2_enter(xnode_t *xn, void *data)
{
	struct xfmt_pass2 *xp2 = data;

	xp2->depth++;

	if (xnode_is_element(xn)) {
		GSList *ns = xfmt_ns_declarations(xp2);
		const char *nsuri = xnode_element_ns(xn);

		if (!xp2->had_text && !xp2->last_was_nl) {
			ostream_putc(xp2->os, '\n');
			xp2->last_was_nl = TRUE;
		}

		xfmt_indent(xp2);

		/*
		 * Look for the namespace matching the default namespace, in which
		 * case we don't have to emit it.
		 */

		if (
			nsuri != NULL && xp2->default_ns != NULL &&
			0 == strcmp(nsuri, xp2->default_ns)
		) {
			nsuri = NULL;
		}

		if (nsuri != NULL) {
			const char *prefix = xfmt_uri_to_prefix(xp2, nsuri);
			ostream_printf(xp2->os, "<%s:%s", prefix, xnode_element_name(xn));
		} else {
			ostream_printf(xp2->os, "<%s", xnode_element_name(xn));
		}

		/*
		 * Install default namespace on the root element, if any.
		 */

		if (1 == xp2->depth && xp2->default_ns != NULL) {
			int c = xfmt_quoting_char(xp2->default_ns);
			g_assert(c != '\0');
			ostream_printf(xp2->os, " xmlns=%c%s%c", c, xp2->default_ns, c);
		}

		/*
		 * Declare namespaces for the element's scope.
		 */

		xfmt_pass2_declare_ns(xp2, ns);
		g_slist_free(ns);

		/*
		 * Emit attributes.
		 */

		xnode_prop_foreach(xn, xfmt_handle_pass2_attr, xp2);

		/*
		 * Handle content-less elements specially: we don't let the
		 * "leave" callback run.
		 */

		xp2->had_text = FALSE;

		if (!xnode_has_content(xn)) {
			ostream_write(xp2->os, XFMT_EMPTY, CONST_STRLEN(XFMT_EMPTY));
			xp2->last_was_nl = TRUE;
			xfmt_pass2_leaving(xp2);	/* No children, no "leave" callback */
			return FALSE;
		}

		ostream_write(xp2->os, XFMT_GT, CONST_STRLEN(XFMT_GT));
		xp2->last_was_nl = FALSE;

	} else if (xnode_is_text(xn)) {
		const char *text = xnode_text(xn);
		size_t len;
		size_t overhead;
		gboolean amp;

		if (xp2->options & XFMT_O_SKIP_BLANKS) {
			const char *start;
			size_t tlen;

			start = xfmt_strip_blanks(text, &tlen);
			if (0 == tlen)
				goto ignore;

			/* FIXME: handle blank collapsing */
		}

		/*
		 * If text is known to have entities, we must not escape the '&'.
		 * This means the generated XML must define that entity in the DTD
		 * part of the tree.
		 *
		 * Computes the required overhead to fully escape the text (0 meaning
		 * that no escaping is required).  If the overhead is larger than
		 * a leading "<![CDATA[" and a closing ""]]>", we can emit a CDATA
		 * section instead, provided the text does not contain "]]>".
		 */

		amp = !xnode_text_has_entities(xn);
		overhead = xfmt_text_escape_overhead(text, amp, FALSE, &len);

		if (0 == overhead) {
			ostream_write(xp2->os, text, len);
		} else if (
			overhead >= XFMT_CDATA_OVERHEAD &&
			NULL == strstr(text, XFMT_CDATA_END)
		) {
			ostream_write(xp2->os,
				XFMT_CDATA_START, CONST_STRLEN(XFMT_CDATA_START));
			ostream_write(xp2->os, text, len);
			ostream_write(xp2->os,
				XFMT_CDATA_END, CONST_STRLEN(XFMT_CDATA_END));
		} else {
			char *escaped = xfmt_text_escape(text, amp, FALSE, len + overhead);
			ostream_write(xp2->os, escaped, len + overhead);
			hfree(escaped);
		}

		xp2->last_was_nl = FALSE;
		xp2->had_text = TRUE;
	}

ignore:
	return TRUE;
}

/**
 * Pass 2 handler on each tree node leave.
 */
static void
xfmt_handle_pass2_leave(xnode_t *xn, void *data)
{
	struct xfmt_pass2 *xp2 = data;

	if (xnode_is_element(xn)) {
		const char *uri = xnode_element_ns(xn);

		xfmt_indent(xp2);

		if (uri != NULL) {
			const char *pre = xfmt_uri_to_prefix(xp2, uri);
			ostream_printf(xp2->os, "</%s:%s>\n", pre, xnode_element_name(xn));
		} else {
			ostream_printf(xp2->os, "</%s>\n", xnode_element_name(xn));
		}
		/* Reset for next element */
		xp2->had_text = FALSE;
		xp2->last_was_nl = TRUE;
	}

	xfmt_pass2_leaving(xp2);
}

struct xfmt_invert_ctx {
	GHashTable *depth2uri;
	GHashTable *multiple;
};

/**
 * Hash table iterator to invert the "uri -> depth" mapping to "depth -> uri".
 *
 * Since there are many URIs that can be associated to a given depth, the
 * values are actually lists of URIs.
 */
static void
xfmt_invert_uri_kv(void *key, void *value, void *data)
{
	struct xfmt_invert_ctx *ictx = data;
	unsigned depth = pointer_to_uint(value);
	char *uri = key;
	GSList *sl;

	g_assert(uint_is_positive(depth));

	/*
	 * If URI is used by more than one sibling at a given depth, the URI
	 * needs to be declared in the parent.
	 */

	if (gm_hash_table_contains(ictx->multiple, uri)) {
		g_assert(depth > 1);
		depth--;
	}

	sl = g_hash_table_lookup(ictx->depth2uri, uint_to_pointer(depth));
	sl = g_slist_prepend(sl, uri);
	g_hash_table_insert(ictx->depth2uri, uint_to_pointer(depth), sl);
}

/**
 * Extended XML formatting of a tree.
 *
 * Namespaces, if any, are automatically assigned a prefix, whose format
 * is "ns%u", the counter being incremented from 0.
 *
 * Users can supply a vector mapping namespaces to prefixes, so that they
 * can force specific prefixes for a given well-known namespace.
 *
 * If there is a default namespace, all the tags belonging to that namespace
 * are emitted without any prefix.
 *
 * The output stream must be explicitly closed by the user upon return.
 *
 * Options can be supplied to tune the output:
 *
 * - XFMT_O_SKIP_BLANKS will skip pure white space nodes.
 * - XFMT_O_COLLAPSE_BLANKS will replace consecutive blanks with 1 space
 * - XFMT_O_NO_INDENT requests that no indentation of the tree be made.
 * - XFMT_O_PROLOGUE emits a leading <?xml?> prologue.
 * - XFMT_O_FORCE_10 force generation of XML 1.0
 *
 * @return TRUE on success.
 */
gboolean
xfmt_tree_extended(const xnode_t *root, ostream_t *os, guint32 options,
	const struct xfmt_prefix *pvec, size_t pvcnt, const char *default_ns)
{
	struct xfmt_pass1 xp1;
	struct xfmt_pass2 xp2;
	struct xfmt_invert_ctx ictx;
	const char *dflt_ns = default_ns;

	g_assert(root != NULL);
	g_assert(os != NULL);

	if (options & XFMT_O_COLLAPSE_BLANKS) {
		/* FIXME */
		g_warning("XFMT_O_COLLAPSE_BLANKS not supported yet");
		stacktrace_where_print(stderr);
	}

	/*
	 * First pass: look at namespaces and construct a table recording the
	 * earliest tree depth at which a namespace is used.
	 */

	memset(&xp1, 0, sizeof xp1);
	xp1.uri2depth = g_hash_table_new(g_str_hash, g_str_equal);
	xp1.multiple = g_hash_table_new(g_str_hash, g_str_equal);
	xp1.uri2prefix = nv_table_make(FALSE);

	if (default_ns != NULL)
		xp1.attr_uris = g_hash_table_new(g_str_hash, g_str_equal);

	gm_hash_table_insert_const(xp1.uri2depth, VXS_XML_URI,
			uint_to_pointer(1));

	xnode_tree_enter_leave(deconstify_gpointer(root),
		xfmt_handle_pass1_enter, xfmt_handle_pass1_leave, &xp1);

	g_assert(0 == xp1.depth);		/* Sound traversal */

	/*
	 * If there was a default namespace, make sure it is used in the tree.
	 * Otherwise, discard it.
	 */

	if (dflt_ns != NULL) {
		if (NULL == g_hash_table_lookup(xp1.uri2depth, dflt_ns)) {
			g_warning("XFMT default namespace '%s' is not needed", dflt_ns);
			dflt_ns = NULL;
		}
	}

	/*
	 * Prepare context for second pass.
	 */

	memset(&xp2, 0, sizeof xp2);
	xp2.depth2uri = g_hash_table_new(NULL, NULL);
	xp2.os = os;
	xp2.options = options;
	xp2.default_ns = dflt_ns;
	xp2.attr_uris = xp1.attr_uris;
	xp2.uri2prefix = xp1.uri2prefix;
	xp2.uris = symtab_make();
	xp2.prefixes = symtab_make();
	xp2.depth = 0;
	xp2.pcount = 0;
	xp2.last_was_nl = TRUE;

	/*
	 * Iterate over the hash table we've built to create a table indexed
	 * by tree depth and listing the namespaces to declare.
	 */

	ictx.depth2uri = xp2.depth2uri;
	ictx.multiple = xp1.multiple;

	g_hash_table_foreach(xp1.uri2depth, xfmt_invert_uri_kv, &ictx);
	gm_hash_table_destroy_null(&xp1.uri2depth);
	gm_hash_table_destroy_null(&xp1.multiple);

	/*
	 * Emit prologue if requested.
	 */

	if (options & XFMT_O_PROLOGUE) {
		if (options & XFMT_O_FORCE_10) {
			ostream_write(os, XFMT_DECL_10, CONST_STRLEN(XFMT_DECL_10));
		} else {
			ostream_write(os, XFMT_DECL, CONST_STRLEN(XFMT_DECL));
		}
		ostream_putc(os, '\n');
	}

	xfmt_prefix_declare(&xp2, VXS_XML_URI, VXS_XML);

	/*
	 * Prepare user-defined URI -> prefix mappings.
	 */

	if (pvcnt != 0) {
		size_t i;

		for (i = 0; i < pvcnt; i++) {
			const struct xfmt_prefix *p = &pvec[i];

			xfmt_prefix_declare(&xp2, p->uri, p->prefix);
		}
	}

	/*
	 * Second pass: generation.
	 */

	xnode_tree_enter_leave(deconstify_gpointer(root),
		xfmt_handle_pass2_enter, xfmt_handle_pass2_leave, &xp2);

	g_assert(0 == xp2.depth);		/* Sound traversal */

	/*
	 * Done, cleanup.
	 */

	nv_table_free_null(&xp2.uri2prefix);
	symtab_free_null(&xp2.prefixes);
	symtab_free_null(&xp2.uris);
	gm_hash_table_destroy_null(&xp2.depth2uri);
	gm_hash_table_destroy_null(&xp2.attr_uris);

	return !ostream_has_ioerr(os);
}

/**
 * Simple XML formatting of a tree.
 *
 * Namespaces, if any, are automatically assigned a prefix, whose format
 * is "ns%u", the counter being incremented from 0.
 *
 * There is no default namespace, all the tags are prefixed if they belong
 * to a namespace.
 *
 * The output stream must be explicitly closed by the user upon return.
 *
 * Options can be supplied to tune the output:
 *
 * - XFMT_O_SKIP_BLANKS will skip pure white space nodes.
 * - XFMT_O_COLLAPSE_BLANKS will replace consecutive blanks with 1 space
 * - XFMT_O_NO_INDENT requests that no indentation of the tree be made.
 * - XFMT_O_PROLOGUE emits a leading <?xml?> prologue.
 * - XFMT_O_FORCE_10 force generation of XML 1.0
 *
 * @return TRUE on success.
 */
gboolean
xfmt_tree(const xnode_t *root, ostream_t *os, guint32 options)
{
	return xfmt_tree_extended(root, os, options, NULL, 0, NULL);
}

/**
 * Convenience routine: dump tree without prologue to specified file.
 *
 * @return TRUE on success.
 */
gboolean
xfmt_tree_dump(const xnode_t *root, FILE *f)
{
	ostream_t *os;

	os = ostream_open_file(f);
	xfmt_tree(root, os, XFMT_O_SKIP_BLANKS);
	return 0 == ostream_close(os);
}


/* vi: set ts=4 sw=4 cindent: */
