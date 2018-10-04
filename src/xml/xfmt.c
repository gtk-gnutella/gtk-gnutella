/*
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
 * @ingroup xml
 * @file
 *
 * XML tree formatter.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

#include "xfmt.h"
#include "vxml.h"
#include "xnode.h"

#include "lib/ascii.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/hstrfn.h"
#include "lib/htable.h"
#include "lib/log.h"		/* For log_file_printable() */
#include "lib/misc.h"		/* For CONST_STRLEN() */
#include "lib/nv.h"
#include "lib/ostream.h"
#include "lib/pslist.h"
#include "lib/stacktrace.h"
#include "lib/symtab.h"
#include "lib/unsigned.h"
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
	htable_t *uri2node;			/**< URI -> topmost node in scope */
	hset_t *attr_uris;			/**< URIs used by attributes */
	nv_table_t *uri2prefix;		/**< URI -> prefixes (declared in tree) */
	const xnode_t *node;		/**< Current element being traversed */
	unsigned depth;				/**< Current tree depth */
};

/**
 * Second pass traversal context.
 */
struct xfmt_pass2 {
	htable_t *node2uri;			/**< node -> URI list to declare */
	hset_t *attr_uris;			/**< URIs used by attributes */
	ostream_t *os;				/**< Output stream */
	uint32 options;				/**< Formatter options */
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
static const char XFMT_EMPTY[]		= "/>";
static const char XFMT_GT[]			= ">";

/**
 * Find common parent between two arbitrary XML nodes in the same tree.
 *
 * @return common parent node, NULL if we did not find any (meaning the
 * nodes are not part of the same tree).
 */
static const xnode_t *
xfmt_find_common_parent(const xnode_t *x1, const xnode_t *x2)
{
	const xnode_t *xn;

	if (NULL == x1)
		return NULL;

	/*
	 * Recursive algorithm: walk up to the root of the tree from x2 to see if
	 * we reach x1.  If we do, we found our common ancestor.
	 *
	 * Otherwise, recurse with the parent of x1.
	 *
	 * Because we have no depth information in nodes, we can't know which one
	 * is deeper in the tree and cannot optimize the lookup algorithm much.
	 *
	 * The worst case complexity is O(d1 * d2) where d1 and d2 are the depths
	 * of x1 and x2.  However, in practice x2 is going to be part of x1's
	 * subtree or of that of its parent node so we do not always fall into the
	 * worst case scenario where the common ancestor ends up being the root.
	 */

	for (xn = x2; xn != NULL; xn = xnode_parent(xn)) {
		if (x1 == xn)
			return x1;
	}

	return xfmt_find_common_parent(xnode_parent(x1), x2);
}

/**
 * Record the need to declare URI at current node.
 */
static void
xfmt_uri_declare(const char *uri, struct xfmt_pass1 *xp1)
{
	const xnode_t *xn = htable_lookup(xp1->uri2node, uri);

	/*
	 * Since the hash table will not outlive the tree traversal,
	 * we can reference the strings within the tree freely without
	 * taking a copy.
	 */

	if (NULL == xn) {
		/*
		 * First time we see this URI, record the node where it appears.
		 */
		htable_insert_const(xp1->uri2node, uri, xp1->node);
	} else {
		const xnode_t *common;

		/*
		 * We already saw this URI already.  Move the declaration to the
		 * node which is the common ancestor between the previous node and
		 * the current one.
		 */

		common = xfmt_find_common_parent(xn, xp1->node);
		g_assert(common != NULL);
		htable_insert_const(xp1->uri2node, uri, common);
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
			g_carp("XFMT ignoring prefix '%s' for '%s': "
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
		xfmt_uri_declare(uri, xp1);

		if (xp1->attr_uris != NULL) {
			hset_insert(xp1->attr_uris, uri);
		}
	}
}

/**
 * Pass 1 handler on each tree node entry.
 */
static bool
xfmt_handle_pass1_enter(const void *node, void *data)
{
	const xnode_t *xn = node;
	struct xfmt_pass1 *xp1 = data;

	xp1->depth++;

	if (xnode_is_element(xn)) {
		const char *uri = xnode_element_ns(xn);

		xp1->node = xn;

		if (uri != NULL)
			xfmt_uri_declare(uri, xp1);

		xnode_prop_foreach(xn, xfmt_handle_pass1_attr, xp1);
		xnode_ns_foreach(xn, xfmt_handle_pass1_ns, xp1);
	}

	return TRUE;
}

/**
 * Pass 1 handler on each tree node leave.
 */
static void
xfmt_handle_pass1_leave(void *node, void *data)
{
	xnode_t *xn = node;
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
	bool seen_non_blank = FALSE;
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
xfmt_text_escape_overhead(const char *text, bool amp, bool apos, size_t *len)
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
xfmt_text_escape(const char *text, bool amp, bool apos, size_t newlen)
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
			g_carp("XFMT ignoring supplied prefix '%s' for '%s': "
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
	const char *prefix, const char *uri, bool free_prefix)
{
	nv_pair_t *nv;
	bool inserted;

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
	bool free_prefix = FALSE;

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
			g_carp("XFMT cannot use prefix '%s' for '%s': "
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
 * Construct a list of prefixes to declare at this node.
 */
static pslist_t *
xfmt_ns_declarations(struct xfmt_pass2 *xp2, const xnode_t *xn)
{
	pslist_t *ns = NULL;
	pslist_t *sl, *uris;

	uris = htable_lookup(xp2->node2uri, xn);

	PSLIST_FOREACH(uris, sl) {
		const char *uri = sl->data;
		const char *prefix = xfmt_new_prefix(xp2, uri);

		ns = pslist_prepend_const(ns, prefix);
	}

	if (uris != NULL) {
		htable_remove(xp2->node2uri, xn);
		pslist_free(uris);
	}

	return pslist_reverse(ns);
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
xfmt_pass2_declare_ns(struct xfmt_pass2 *xp2, pslist_t *ns)
{
	pslist_t *sl;

	PSLIST_FOREACH(ns, sl) {
		const char *prefix = sl->data;
		const char *uri;
		int c;

		/*
		 * Do not declare the "xml" namespace.
		 */

		if (0 == strcmp(prefix, VXS_XML))
			continue;

		/*
		 * We don't need to declare the default namespace though, unless
		 * it is used in attributes (since there is no default namespace
		 * for attributes).
		 */

		uri = symtab_lookup(xp2->prefixes, prefix);

		g_assert(uri != NULL);

		if (
			xp2->default_ns != NULL && 0 == strcmp(uri, xp2->default_ns) &&
			!hset_contains(xp2->attr_uris, xp2->default_ns)
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
	bool apos_escape = FALSE;
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
static bool
xfmt_handle_pass2_enter(const void *node, void *data)
{
	const xnode_t *xn = node;
	struct xfmt_pass2 *xp2 = data;

	xp2->depth++;

	if (xnode_is_element(xn)) {
		pslist_t *ns = xfmt_ns_declarations(xp2, xn);
		const char *nsuri = xnode_element_ns(xn);

		if (!xp2->had_text && !xp2->last_was_nl) {
			if (!(xp2->options & XFMT_O_SINGLE_LINE))
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
		pslist_free(ns);

		/*
		 * Emit attributes.
		 */

		xnode_prop_foreach(xn, xfmt_handle_pass2_attr, xp2);

		/*
		 * Handle content-less elements specially: we don't let the
		 * "leave" callback run.
		 *
		 * We consider an element with a single empty text child as
		 * content-less, so we test with xnode_is_empty() instead of
		 * !xnode_has_content().
		 */

		xp2->had_text = FALSE;

		if (xnode_is_empty(xn)) {
			ostream_write(xp2->os, XFMT_EMPTY, CONST_STRLEN(XFMT_EMPTY));
			if (!(xp2->options & XFMT_O_SINGLE_LINE))
				ostream_putc(xp2->os, '\n');
			xp2->last_was_nl = TRUE;
			xfmt_pass2_leaving(xp2);	/* No children, no "leave" callback */
			return FALSE;
		}

		ostream_write(xp2->os, XFMT_GT, CONST_STRLEN(XFMT_GT));
		xp2->last_was_nl = FALSE;

	} else if (xnode_has_text(xn)) {
		const char *text = xnode_text(xn);
		size_t len;
		size_t overhead;
		bool amp;

		g_assert(text != NULL);		/* Since we checked xnode_has_text() */

		if (xnode_is_comment(xn)) {
			g_carp_once("%s(): comment nodes ignored for now", G_STRFUNC);
			goto ignore;
		}

		if (xp2->options & XFMT_O_SKIP_BLANKS) {
			const char *start;
			size_t tlen;

			start = xfmt_strip_blanks(text, &tlen);
			if (0 == tlen)
				goto ignore;

			/* FIXME: handle blank collapsing */
			if (xp2->options & XFMT_O_COLLAPSE_BLANKS) {
				(void) start;
				g_carp_once("%s(): XFMT_O_COLLAPSE_BLANKS not handled yet",
					G_STRFUNC);
			}
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
			NULL == vstrstr(text, XFMT_CDATA_END)
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
xfmt_handle_pass2_leave(void *node, void *data)
{
	xnode_t *xn = node;
	struct xfmt_pass2 *xp2 = data;

	if (xnode_is_element(xn)) {
		const char *uri = xnode_element_ns(xn);

		xfmt_indent(xp2);

		/*
		 * We don't emit the URI if it is that of the default namespace.
		 */

		if (
			uri != NULL && xp2->default_ns != NULL &&
			0 == strcmp(uri, xp2->default_ns)
		) {
			uri = NULL;
		}

		if (uri != NULL) {
			const char *pre = xfmt_uri_to_prefix(xp2, uri);
			ostream_printf(xp2->os, "</%s:%s>", pre, xnode_element_name(xn));
		} else {
			ostream_printf(xp2->os, "</%s>", xnode_element_name(xn));
		}
		if (!(xp2->options & XFMT_O_SINGLE_LINE)) {
			ostream_putc(xp2->os, '\n');
		}
		/* Reset for next element */
		xp2->had_text = FALSE;
		xp2->last_was_nl = TRUE;
	}

	xfmt_pass2_leaving(xp2);
}

struct xfmt_invert_ctx {
	htable_t *uri2node;
	htable_t *node2uri;
};

/**
 * Hash table iterator to invert the "uri -> node" mapping to "node -> uri".
 *
 * Since there are many URIs that can be associated to a given node, the
 * values are actually lists of URIs.
 */
static void
xfmt_invert_uri_kv(const void *key, void *value, void *data)
{
	struct xfmt_invert_ctx *ictx = data;
	const char *uri = key;
	const xnode_t *xn = value;
	pslist_t *sl;

	g_assert(xn != NULL);

	sl = htable_lookup(ictx->node2uri, xn);
	sl = pslist_prepend_const(sl, uri);
	htable_insert(ictx->node2uri, xn, sl);
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
 * - XFMT_O_SINGLE_LINE emits XML as one big line (implies XFMT_O_NO_INDENT).
 *
 * @param root			the root of the tree to dump
 * @param os			the output stream where tree is dumped
 * @param options		formatting options, as documented above
 * @param pvec			a vector of prefixes to be used for namespaces
 * @param pvcnt			amount of entries in vector
 * @param default_ns	default namespace to install at root element
 *
 * @return TRUE on success.
 */
bool
xfmt_tree_extended(const xnode_t *root, ostream_t *os, uint32 options,
	const struct xfmt_prefix *pvec, size_t pvcnt, const char *default_ns)
{
	struct xfmt_pass1 xp1;
	struct xfmt_pass2 xp2;
	struct xfmt_invert_ctx ictx;
	const char *dflt_ns;

	g_assert(root != NULL);
	g_assert(os != NULL);

	if (options & XFMT_O_COLLAPSE_BLANKS) {
		/* FIXME */
		g_carp_once("%s(): XFMT_O_COLLAPSE_BLANKS not supported yet",
			G_STRFUNC);
	}

	if (options & XFMT_O_SINGLE_LINE)
		options |= XFMT_O_NO_INDENT;

	/*
	 * First pass: look at namespaces and construct a table recording the
	 * earliest tree depth at which a namespace is used.
	 */

	ZERO(&xp1);
	xp1.uri2node = htable_create(HASH_KEY_STRING, 0);
	xp1.uri2prefix = nv_table_make(FALSE);

	if (default_ns != NULL)
		xp1.attr_uris = hset_create(HASH_KEY_STRING, 0);

	htable_insert_const(xp1.uri2node, VXS_XML_URI, root);

	xnode_tree_enter_leave(deconstify_pointer(root),
		xfmt_handle_pass1_enter, xfmt_handle_pass1_leave, &xp1);

	g_assert(0 == xp1.depth);		/* Sound traversal */

	/*
	 * If there was a default namespace, make sure it is used in the tree.
	 * Otherwise, discard it.
	 */

	if (default_ns != NULL) {
		if (NULL == htable_lookup(xp1.uri2node, default_ns)) {
			g_carp("XFMT default namespace '%s' is not needed", default_ns);
			dflt_ns = NULL;
		} else {
			dflt_ns = default_ns;
		}
	} else {
		dflt_ns = NULL;
	}

	/*
	 * Prepare context for second pass.
	 */

	ZERO(&xp2);
	xp2.node2uri = htable_create(HASH_KEY_SELF, 0);
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
	 * by tree node and listing the namespaces to declare for that node.
	 */

	ictx.uri2node = xp1.uri2node;
	ictx.node2uri = xp2.node2uri;

	htable_foreach(xp1.uri2node, xfmt_invert_uri_kv, &ictx);
	htable_free_null(&xp1.uri2node);

	/*
	 * Emit prologue if requested.
	 */

	if (options & XFMT_O_PROLOGUE) {
		if (options & XFMT_O_FORCE_10) {
			ostream_write(os, XFMT_DECL_10, CONST_STRLEN(XFMT_DECL_10));
		} else {
			ostream_write(os, XFMT_DECL, CONST_STRLEN(XFMT_DECL));
		}
		if (!(options & XFMT_O_SINGLE_LINE)) {
			ostream_putc(os, '\n');
		}
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

	xnode_tree_enter_leave(deconstify_pointer(root),
		xfmt_handle_pass2_enter, xfmt_handle_pass2_leave, &xp2);

	g_assert(0 == xp2.depth);		/* Sound traversal */

	/*
	 * Done, cleanup.
	 */

	nv_table_free_null(&xp2.uri2prefix);
	symtab_free_null(&xp2.prefixes);
	symtab_free_null(&xp2.uris);
	htable_free_null(&xp2.node2uri);
	hset_free_null(&xp2.attr_uris);

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
 * - XFMT_O_SINGLE_LINE emits XML as one big line (implies XFMT_O_NO_INDENT).
 *
 * @param root		the root of the tree to dump
 * @param os		the output stream where tree is dumped
 * @param options	formatting options, as documented above
 *
 * @return TRUE on success.
 */
bool
xfmt_tree(const xnode_t *root, ostream_t *os, uint32 options)
{
	return xfmt_tree_extended(root, os, options, NULL, 0, NULL);
}

/**
 * Convenience routine: dump tree without prologue to specified file, skipping
 * pure white space nodes.
 *
 * @param root		tree to dump
 * @param f			file where we should dump the tree
 *
 * @return TRUE on success.
 */
bool
xfmt_tree_dump(const xnode_t *root, FILE *f)
{
	ostream_t *os;

	if (!log_file_printable(f))
		return FALSE;

	os = ostream_open_file(f);
	xfmt_tree(root, os, XFMT_O_SKIP_BLANKS);
	return 0 == ostream_close(os);
}

/**
 * Convenience routine: dump tree with prologue to specified file, skipping
 * pure white space nodes.
 *
 * @param root		tree to dump
 * @param f			file where we should dump the tree
 *
 * @return TRUE on success.
 */
bool
xfmt_tree_prologue_dump(const xnode_t *root, FILE *f)
{
	ostream_t *os;

	if (!log_file_printable(f))
		return FALSE;

	os = ostream_open_file(f);
	xfmt_tree(root, os, XFMT_O_SKIP_BLANKS | XFMT_O_PROLOGUE);
	return 0 == ostream_close(os);
}

/**
 * Convenience routine: dump tree specified file.
 *
 * See xfmt_tree_extended() for a description of the available options.
 *
 * @param root			tree to dump
 * @param f				file where we should dump the tree
 * @param options		formatting options, as documented above
 * @param pvec			a vector of prefixes to be used for namespaces
 * @param pvcnt			amount of entries in vector
 * @param default_ns	default namespace to install at root element
 *
 * @return TRUE on success.
 */
bool
xfmt_tree_dump_extended(const xnode_t *root, FILE *f,
	uint32 options, const struct xfmt_prefix *pvec, size_t pvcnt,
	const char *default_ns)
{
	ostream_t *os;

	if (!log_file_printable(f))
		return FALSE;

	os = ostream_open_file(f);
	xfmt_tree_extended(root, os, options, pvec, pvcnt, default_ns);
	return ostream_close(os);
}

/**
 * Convenience routine: format tree to memory buffer.
 *
 * @param root		tree to dump
 * @param buf		buffer where formatting is done
 * @param len		buffer length
 * @param options	formatting options
 *
 * @return length of generated string, -1 on failure.
 */
size_t
xfmt_tree_to_buffer(const xnode_t *root, void *buf, size_t len, uint32 options)
{
	ostream_t *os;
	pdata_t *pd;
	pmsg_t *mb;
	bool ok;
	size_t written = (size_t) -1;

	g_assert(root != NULL);
	g_assert(buf != NULL);
	g_assert(size_is_non_negative(len));

	pd = pdata_allocb_ext(buf, len, pdata_free_nop, NULL);
	mb = pmsg_alloc(PMSG_P_DATA, pd, 0, 0);
	os = ostream_open_pmsg(mb);

	ok = xfmt_tree(root, os, options);
	ok = ostream_close(os) && ok;

	if (ok)
		written = pmsg_size(mb);

	pmsg_free(mb);

	g_assert((size_t) -1 == written || written <= len);

	return written;
}

/**
 * Convenience routine: format tree to new halloc()'ed string.
 *
 * See xfmt_tree_extended() for a description of the available options.
 *
 * @param root			tree to dump
 * @param f				file where we should dump the tree
 * @param options		formatting options, as documented above
 * @param pvec			a vector of prefixes to be used for namespaces
 * @param pvcnt			amount of entries in vector
 * @param default_ns	default namespace to install at root element
 *
 * @return newly allocated string, NULL on error.
 */
char *
xfmt_tree_to_string_extended(const xnode_t *root,
	uint32 options, const struct xfmt_prefix *pvec, size_t pvcnt,
	const char *default_ns)
{
	ostream_t *os;
	slist_t *ps;
	bool ok;
	char *str = NULL;

	g_assert(root != NULL);

	os = ostream_open_memory();
	ok = xfmt_tree_extended(root, os, options, pvec, pvcnt, default_ns);
	ps = ostream_close_memory(os);

	if (ok) {
		size_t len = pmsg_slist_size(ps);
		size_t copied;

		/*
		 * Copy XML tree from the pmsg list to a newly allocated
		 * NUL-terminated string.
		 */

		str = halloc(len + 1);		/* Trailing NUL */
		copied = pmsg_slist_read(ps, str, len);
		g_assert(copied == len);
		str[len] = '\0';
	}

	pmsg_slist_free_all(&ps);

	return str;
}

/**
 * Convenience routine: format tree to new halloc()'ed string.
 *
 * @param root		tree to dump
 * @param options	formatting options
 *
 * @return newly allocated string, NULL on error.
 */
char *
xfmt_tree_to_string(const xnode_t *root, uint32 options)
{
	return xfmt_tree_to_string_extended(root, options, NULL, 0, NULL);
}

/* vi: set ts=4 sw=4 cindent: */
