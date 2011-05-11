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
 * @ingroup xml
 * @file
 *
 * XML nodes, building up an XML tree and ultimately an XML document.
 *
 * @author Raphael Manfredi
 * @date 2010
 */

#include "common.h"

RCSID("$Id$")

#include "xnode.h"
#include "xattr.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashlist.h"
#include "lib/nv.h"
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

enum xnode_magic { XNODE_MAGIC = 0x28aa3166 };

/**
 * An XML node.
 *
 * To keep each node reasonably small, we limit the tree structure pointers
 * to the bare minimum: each parent points to its first and last children, and
 * then each child is pointing to its next sibling only.
 *
 * This optimizes the regular usage patterns: a mere traversal of the tree,
 * or creation of a tree by appending childrens in order.
 */
struct xnode {
	enum xnode_magic magic;
	xnode_type_t type;			/**< Type of node (union discriminant) */
	union {
		struct {				/**< Text nodes */
			char *text;			/**< Text string */
			unsigned asis:1;	/**< Whether '&' need to be left as-is */
		} t;
		struct {				/**< Comment nodes */
			char *text;			/**< Text string */
		} c;
		struct {				/**< Processing instruction */
			const char *name;	/**< Element's name (atom) */
			char *target;		/**< PI target string */
		} pi;
		struct {					/**< Elements */
			const char *name;		/**< Element's name (atom) */
			const char *ns_uri;		/**< Name space URI, NULL if none (atom) */
			xattr_table_t *attrs;	/**< Attributes (NULL if none) */
			nv_table_t *ns;			/**< Namespace declarations, NULL if none */
		} e;
	} u;
	/* Tree structure */
	struct xnode *parent;		/**< Parent node, NULL if root element */
	struct xnode *sibling;		/**< Next sibling, NULL if none */
	struct xnode *first_child;	/**< First child, NULL if none */
	struct xnode *last_child;	/**< Last child, NULL if none */
};

static inline void
xnode_check(const struct xnode * const xn)
{
	g_assert(xn != NULL);
	g_assert(XNODE_MAGIC == xn->magic);
}

/**
 * @return the node type
 */
xnode_type_t
xnode_type(const xnode_t *xn)
{
	xnode_check(xn);
	return xn->type;
}

/**
 * Short string description for XML node, for debugging purposes.
 *
 * This is not a serialization of the XML node for inclusion in a document.
 *
 * @param xn	node to inspect (may be NULL)
 * @param buf	buffer where value should be printed
 * @param len	buffer length
 *
 * @return the length of the resulting string
 */
size_t
xnode_to_string_buf(const xnode_t *xn, char *buf, size_t len)
{
	if (NULL == xn)
		return g_strlcpy(buf, "{null XML node pointer}", len);

	xnode_check(xn);

	switch (xn->type) {
	case XNODE_T_ELEMENT:
		if (xn->u.e.ns_uri != NULL) {
			return gm_snprintf(buf, len, "<%s:%s%s>",
				xn->u.e.ns_uri, xn->u.e.name,
				xn->u.e.attrs != NULL ? " ..." : "");
		} else {
			return gm_snprintf(buf, len, "<%s%s>",
				xn->u.e.name, xn->u.e.attrs != NULL ? " ..." : "");
		}
		break;
	case XNODE_T_COMMENT:
		return g_strlcpy(buf, "{XML comment node}", len);
	case XNODE_T_PI:
		return gm_snprintf(buf, len, "<?%s...?>", xn->u.pi.name);
	case XNODE_T_TEXT:
		return g_strlcpy(buf, "{XML text node}", len);
	case XNODE_T_MAX:
		g_assert_not_reached();
	}

	return 0;
}

/**
 * Short string description for XML node, for debugging purposes.
 *
 * This is not a serialization of the XML node for inclusion in a document.
 *
 * @param xn	node to inspect (may be NULL)
 *
 * @return short description of node (pointer to static buffer).
 */
const char *
xnode_to_string(const xnode_t *xn)
{
	static char buf[256];

	xnode_to_string_buf(xn, buf, sizeof buf);
	return buf;
}

/**
 * Same as xnode_to_string().
 */
const char *
xnode_to_string2(const xnode_t *xn)
{
	static char buf[256];

	xnode_to_string_buf(xn, buf, sizeof buf);
	return buf;
}

/**
 * @return parent node, or NULL if the node is the root node.
 */
xnode_t *
xnode_parent(const xnode_t *xn)
{
	xnode_check(xn);
	return xn->parent;
}

/**
 * @return first child node, or NULL if the node has no children (leaf node).
 */
xnode_t *
xnode_first_child(const xnode_t *xn)
{
	xnode_check(xn);
	return xn->first_child;
}

/**
 * @return last child node, or NULL if the node has no children (leaf node).
 */
xnode_t *
xnode_last_child(const xnode_t *xn)
{
	xnode_check(xn);
	return xn->last_child;
}

/**
 * @return next sibbling node, or NULL if the node has no more siblings.
 */
xnode_t *
xnode_next_sibling(const xnode_t *xn)
{
	xnode_check(xn);
	return xn->sibling;
}

/**
 * @return TRUE if node has a text value (text or comment nodes).
 */
gboolean
xnode_has_text(const xnode_t *xn)
{
	xnode_check(xn);
	return XNODE_T_COMMENT == xn->type || XNODE_T_TEXT == xn->type;
}

/**
 * @return whether node is a text node.
 */
gboolean
xnode_is_text(const xnode_t *xn)
{
	xnode_check(xn);
	return XNODE_T_TEXT == xn->type;
}

/**
 * @return whether node is a comment node.
 */
gboolean
xnode_is_comment(const xnode_t *xn)
{
	xnode_check(xn);
	return XNODE_T_COMMENT == xn->type;
}

/**
 * @return whether node is an element node.
 */
gboolean
xnode_is_element(const xnode_t *xn)
{
	xnode_check(xn);
	return XNODE_T_ELEMENT == xn->type;
}

/**
 * @return whether node is a processing instruction node.
 */
gboolean
xnode_is_processing_instruction(const xnode_t *xn)
{
	xnode_check(xn);
	return XNODE_T_PI == xn->type;
}

/**
 * @return whether node has content (children).
 */
gboolean
xnode_has_content(const xnode_t *xn)
{
	xnode_check(xn);

	return xn->first_child != NULL;
}

/**
 * @return whether node is empty (has either no children, or a single one
 * which is an empty text node).
 */
gboolean
xnode_is_empty(const xnode_t *xn)
{
	const xnode_t *xc;

	xnode_check(xn);

	if (NULL == xn->first_child)
		return TRUE;

	xc = xn->first_child;
	if (xc->sibling != NULL)
		return FALSE;

	return XNODE_T_TEXT == xc->type && '\0' == *xc->u.t.text;
}

/**
 * @return whether node is an element node of corresponding namespace and name.
 */
gboolean
xnode_is_element_named(const xnode_t *xn, const char *uri, const char *name)
{
	xnode_check(xn);
	g_assert(name != NULL);

	if (XNODE_T_ELEMENT == xn->type) {
		if (NULL == uri) {
			if (xn->u.e.ns_uri != NULL)
				return FALSE;
		} else {
			if (NULL == xn->u.e.ns_uri)
				return FALSE;
			if (0 != strcmp(uri, xn->u.e.ns_uri))
				return FALSE;
		}
		g_assert(xn->u.e.name != NULL);
		return 0 == strcmp(xn->u.e.name, name);
	} else {
		return FALSE;
	}
}

/**
 * @return whether (element) node is within a specific namespace.
 */
gboolean
xnode_within_namespace(const xnode_t *xn, const char *uri)
{
	xnode_check(xn);
	g_assert(uri != NULL);

	if (XNODE_T_ELEMENT == xn->type) {
		return xn->u.e.ns_uri != NULL && 0 == strcmp(xn->u.e.ns_uri, uri);
	} else {
		return FALSE;	/* Only elements or attributes have namespaces */
	}
}

/**
 * @return node's text, NULL if not a text node.
 */
const char *
xnode_text(const xnode_t *xn)
{
	xnode_check(xn);

	if (XNODE_T_COMMENT == xn->type)
		return xn->u.c.text;
	else if (XNODE_T_TEXT == xn->type)
		return xn->u.t.text;
	else
		return NULL;
}

/**
 * @return node's first child text, NULL if the first child is not a
 * text node, or an empty string if the node has no children.
 */
const char *
xnode_first_text(const xnode_t *xn)
{
	const xnode_t *child;

	xnode_check(xn);

	child = xn->first_child;
	if (NULL == child)
		return "";

	return xnode_text(child);
}

/**
 * @return whether node's text must be output verbatim (no escaping of '&'
 * done on output because text refers to entites).
 */
gboolean
xnode_text_has_entities(const xnode_t *xn)
{
	xnode_check(xn);

	if (xn->type != XNODE_T_TEXT)
		return FALSE;

	return xn->u.t.asis;
}

/**
 * @return node's element name, NULL if not an element node.
 */
const char *
xnode_element_name(const xnode_t *xn)
{
	xnode_check(xn);
	return (XNODE_T_ELEMENT == xn->type) ? xn->u.e.name : NULL;
}

/**
 * @return node's element namespace URI, NULL if not in a namespace.
 */
const char *
xnode_element_ns(const xnode_t *xn)
{
	xnode_check(xn);
	return (XNODE_T_ELEMENT == xn->type) ? xn->u.e.ns_uri : NULL;
}

/**
 * @return node's PI name, NULL if not a PI node.
 */
const char *
xnode_pi_name(const xnode_t *xn)
{
	xnode_check(xn);
	return (XNODE_T_PI == xn->type) ? xn->u.pi.name : NULL;
}

/**
 * @return node's PI target, NULL if not a PI node.
 */
const char *
xnode_pi_target(const xnode_t *xn)
{
	xnode_check(xn);
	return (XNODE_T_PI == xn->type) ? xn->u.pi.target : NULL;
}

/**
 * Allocate a new XML node.
 */
static xnode_t *
xnode_new(xnode_type_t type)
{
	xnode_t *xn;

	xn = walloc0(sizeof *xn);
	xn->magic = XNODE_MAGIC;
	xn->type = type;

	return xn;
}

/**
 * Free an XML node.
 *
 * This is the user-visible routine that can succeed only if the node is
 * not part of a tree structure.
 */
void
xnode_free(xnode_t *xn)
{
	xnode_check(xn);
	g_assert(NULL == xn->parent);
	g_assert(NULL == xn->first_child);
	g_assert(NULL == xn->last_child);
	g_assert(NULL == xn->sibling);

	switch (xn->type) {
	case XNODE_T_COMMENT:
		HFREE_NULL(xn->u.c.text);
		break;
	case XNODE_T_TEXT:
		HFREE_NULL(xn->u.t.text);
		break;
	case XNODE_T_PI:
		atom_str_free_null(&xn->u.pi.name);
		HFREE_NULL(xn->u.pi.target);
		break;
	case XNODE_T_ELEMENT:
		atom_str_free_null(&xn->u.e.name);
		atom_str_free_null(&xn->u.e.ns_uri);
		nv_table_free_null(&xn->u.e.ns);
		xattr_table_free_null(&xn->u.e.attrs);
		break;
	case XNODE_T_MAX:
		g_assert_not_reached();
	}

	xn->magic = 0;
	wfree(xn, sizeof *xn);
}

/**
 * Make sure node is orphan.
 */
static void
xnode_orphan_check(const xnode_t * const xn)
{
	xnode_check(xn);
	g_assert(NULL == xn->parent);
	g_assert(NULL == xn->sibling);
}

/**
 * Create a new element tag node, inserted under parent node as the last child.
 *
 * @param parent		the parent node (NULL creates a standalone node)
 * @param ns			the namespace URI (NULL if none)
 * @param name			the element's name (copied)
 */
xnode_t *
xnode_new_element(xnode_t *parent, const char *ns, const char *name)
{
	xnode_t *xn;

	g_assert(name != NULL);

	xn = xnode_new(XNODE_T_ELEMENT);
	xn->u.e.name = atom_str_get(name);
	xn->u.e.ns_uri = NULL == ns ? NULL : atom_str_get(ns);

	if (parent != NULL)
		xnode_add_child(parent, xn);

	return xn;
}

/**
 * Create a new comment node, inserted under parent node as the last child.
 *
 * @param parent		the parent node (NULL creates a standalone node
 * @param text			the comment text, copied ("--" will be emitted as "- -")
 */
xnode_t *
xnode_new_comment(xnode_t *parent, const char *text)
{
	xnode_t *xn;

	g_assert(text != NULL);

	xn = xnode_new(XNODE_T_COMMENT);
	xn->u.c.text = h_strdup(text);

	if (parent != NULL)
		xnode_add_child(parent, xn);

	return xn;
}

/**
 * Create a new text node, inserted under parent node as the last child..
 *
 * When created as verbatim, any '&' character is left as-is, otherwise they
 * are escaped.  All '<' and '>' are escaped regardless.
 *
 * @param parent		the parent node (NULL creates a standalone node
 * @param text			the text
 * @param verbatim		whether text is to be emitted verbatim or escaped
 */
xnode_t *
xnode_new_text(xnode_t *parent, const char *text, gboolean verbatim)
{
	xnode_t *xn;

	g_assert(text != NULL);

	xn = xnode_new(XNODE_T_TEXT);
	xn->u.t.text = h_strdup(text);
	xn->u.t.asis = booleanize(verbatim);

	if (parent != NULL)
		xnode_add_child(parent, xn);

	return xn;
}

/**
 * Add orphan node under parent as last child.
 */
void
xnode_add_child(xnode_t *parent, xnode_t *node)
{
	xnode_check(parent);
	xnode_orphan_check(node);

	if (parent->last_child != NULL) {
		xnode_t *lchild = parent->last_child;

		xnode_check(lchild);
		g_assert(lchild->parent == parent);
		g_assert(NULL == lchild->sibling);

		lchild->sibling = node;
	} else {
		g_assert(NULL == parent->first_child);

		parent->first_child = node;
	}

	node->parent = parent;
	parent->last_child = node;
}

/**
 * Add parentless node under parent as first child.
 */
void
xnode_add_first_child(xnode_t *parent, xnode_t *node)
{
	xnode_check(parent);
	xnode_orphan_check(node);

	node->sibling = parent->first_child;

	if (NULL == parent->last_child) {
		g_assert(NULL == node->sibling);

		parent->last_child = node;
	}

	node->parent = parent;
	parent->first_child = node;
}

/**
 * Add orphan node as right-sibling of previous node (cannot be the root node).
 */
void
xnode_add_sibling(xnode_t *previous, xnode_t *node)
{
	xnode_check(previous);
	xnode_orphan_check(node);
	g_assert(previous->parent != NULL);

	node->parent = previous->parent;
	node->sibling = previous->sibling;
	previous->sibling = node;

	if (NULL == node->sibling)
		previous->parent->last_child = node;
}

/**
 * Detach node and all its sub-tree from a tree, making it the new root of
 * a smaller tree.
 */
void
xnode_detach(xnode_t *xn)
{
	xnode_check(xn);

	if (NULL == xn->parent) {
		g_assert(NULL == xn->sibling);
	} else {
		xnode_t *parent = xn->parent;

		xn->parent = NULL;

		if (xn == parent->first_child) {
			if (xn == parent->last_child) {
				g_assert(NULL == xn->sibling);
				parent->first_child = parent->last_child = NULL;
			} else {
				g_assert(xn->sibling != NULL);
				parent->first_child = xn->sibling;
			}
		} else {
			xnode_t *ch;
			gboolean found = FALSE;

			for (ch = parent->first_child; ch != NULL; ch = ch->sibling) {
				if (ch->sibling == xn) {
					found = TRUE;
					break;
				}
			}
			g_assert(found);

			ch->sibling = xn->sibling;

			if (xn == parent->last_child) {
				g_assert(NULL == xn->sibling);
				parent->last_child = ch;
			}
		}

		xn->sibling = NULL;
	}
}

/**
 * Add namespace declaration to element.
 *
 * There must not be any ':' in the prefix string.
 * The prefix must not have been already declared locally.
 *
 * @param element		the element node
 * @param prefix		the shorthand prefix for the namespace
 * @param uri			the namespace URI
 */
void
xnode_add_namespace(xnode_t *element, const char *prefix, const char *uri)
{
	size_t uri_len;

	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(prefix != NULL);
	g_assert(uri != NULL);
	g_assert(NULL == strchr(prefix, ':'));

	if (NULL == element->u.e.ns)
		element->u.e.ns = nv_table_make(TRUE);

	/* Prefix must not be redeclared in the same element */
	g_assert(NULL == nv_table_lookup(element->u.e.ns, prefix));

	uri_len = strlen(uri);
	nv_table_insert(element->u.e.ns, prefix, uri, uri_len + 1);
}

struct xnode_ns_foreach_ctx {
	xnode_ns_cb_t func;
	void *data;
};

/**
 * Wrapper function for xnode_ns_foreach().
 */
static void
xnode_ns_foreach_wrap(nv_pair_t *nv, void *u)
{
	struct xnode_ns_foreach_ctx *ctx = u;

	(*ctx->func)(nv_pair_name(nv), nv_pair_value_str(nv), ctx->data);
}

/**
 * Apply function to each declared namespace, in the order they were defined.
 */
void
xnode_ns_foreach(const xnode_t *element, xnode_ns_cb_t func, void *data)
{
	struct xnode_ns_foreach_ctx ctx;

	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(func != NULL);

	if (NULL == element->u.e.ns)
		return;

	ctx.func = func;
	ctx.data = data;

	nv_table_foreach(element->u.e.ns, xnode_ns_foreach_wrap, &ctx);
}

/**
 * Get property from element node (with namespace).
 *
 * If there is no such property on the node, NULL is returned.
 * The string returned must be duplicated if it is meant to be used after
 * the node is reclaimed.
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 *
 * @return the property value, NULL if the property does not exist.
 */
const char *
xnode_prop_ns_get(const xnode_t *element, const char *uri, const char *name)
{
	xnode_check(element);
	g_assert(name != NULL);
	g_assert(XNODE_T_ELEMENT == element->type);

	if (NULL == element->u.e.attrs)
		return NULL;

	return xattr_table_lookup(element->u.e.attrs, uri, name);
}

/**
 * Get property from element node (no namespace).
 *
 * If there is no such property on the node, NULL is returned.
 * The string returned must be duplicated if it is meant to be used after
 * the node is reclaimed.
 *
 * @param element		the element node
 * @param name			the property name
 *
 * @return the property value, NULL if the property does not exist.
 */
const char *
xnode_prop_get(const xnode_t *element, const char *name)
{
	return xnode_prop_ns_get(element, NULL, name);
}

/**
 * Apply function to each property, in the order they were defined.
 */
void
xnode_prop_foreach(const xnode_t *element, xattr_table_cb_t func, void *data)
{
	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(func != NULL);

	if (NULL == element->u.e.attrs)
		return;

	xattr_table_foreach(element->u.e.attrs, func, data);
}

/**
 * Set property in element node (with namespace).
 *
 * If there is an existing property on the node, the previous content is
 * replaced by the new one.
 *
 * If called with a NULL uri parameter, this is equivalent to xnode_prop_set().
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 * @param value			the property value (copied)
 *
 * @return TRUE if this was a new property, FALSE if we replaced content.
 */
gboolean
xnode_prop_ns_set(xnode_t *element,
	const char *uri, const char *name, const char *value)
{
	xnode_check(element);
	g_assert(name != NULL);
	g_assert(value != NULL);
	g_assert(XNODE_T_ELEMENT == element->type);

	if (NULL == element->u.e.attrs)
		element->u.e.attrs = xattr_table_make();

	return xattr_table_add(element->u.e.attrs, uri, name, value);
}

/**
 * Set property in element node (no namespace).
 *
 * If there is an existing property on the node, the previous content is
 * replaced by the new one.
 *
 * @param element		the element node
 * @param name			the property name
 * @param value			the property value (copied)
 *
 * @return TRUE if this was a new property, FALSE if we replaced content.
 */
gboolean
xnode_prop_set(xnode_t *element, const char *name, const char *value)
{
	return xnode_prop_ns_set(element, NULL, name, value);
}

/**
 * Set property in element node by formatting the supplied arguments to
 * construct the string value.
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 * @param fmt			the formatting string (printf-like)
 * @param args			the varargs pointer list
 *
 * @return TRUE if this was a new property, FALSE if we replaced content.
 */
static gboolean
xnode_prop_ns_vprintf(xnode_t *element,
	const char *uri, const char *name, const char *fmt, va_list args)
{
	char buf[1024];
	va_list args2;
	char *value;
	gboolean result;

	VA_COPY(args2, args);
	if (gm_vsnprintf(buf, sizeof buf, fmt, args2) >= sizeof buf - 1) {
		value = h_strdup_vprintf(fmt, args);
	} else {
		value = buf;
	}
	va_end(args2);

	result = xnode_prop_ns_set(element, uri, name, value);

	if (value != buf)
		hfree(value);

	return result;
}

/**
 * Set property in element node by formatting the supplied arguments to
 * construct the string value.
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 * @param fmt			the formatting string (printf-like)
 * @param ...			the arguments to format
 *
 * @return TRUE if this was a new property, FALSE if we replaced content.
 */
gboolean
xnode_prop_ns_printf(xnode_t *element,
	const char *uri, const char *name, const char *fmt, ...)
{
	va_list args;
	gboolean result;

	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(name != NULL);
	g_assert(fmt != NULL);

	va_start(args, fmt);
	result = xnode_prop_ns_vprintf(element, uri, name, fmt, args);
	va_end(args);

	return result;
}

/**
 * Set property in element node by formatting the supplied arguments to
 * construct the string value.
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 * @param fmt			the formatting string (printf-like)
 * @param ...			the arguments to format
 *
 * @return TRUE if this was a new property, FALSE if we replaced content.
 */
gboolean
xnode_prop_printf(xnode_t *element, const char *name, const char *fmt, ...)
{
	va_list args;
	gboolean result;

	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(name != NULL);
	g_assert(fmt != NULL);

	va_start(args, fmt);
	result = xnode_prop_ns_vprintf(element, NULL, name, fmt, args);
	va_end(args);

	return result;
}

/**
 * Unset property in element.
 *
 * @param element		the element node
 * @param uri			the namespace URI for the property (can be NULL)
 * @param name			the property name
 *
 * @return TRUE if the property existed, FALSE otherwise.
 */
gboolean
xnode_prop_ns_unset(xnode_t *element, const char *uri, const char *name)
{
	xnode_check(element);
	g_assert(XNODE_T_ELEMENT == element->type);
	g_assert(name != NULL);

	if (NULL == element->u.e.attrs)
		return FALSE;

	return xattr_table_remove(element->u.e.attrs, uri, name);
}

/**
 * @return the amount of properties attached to the node.
 */
size_t
xnode_prop_count(const xnode_t *element)
{
	xnode_check(element);

	if (XNODE_T_ELEMENT != element->type)
		return 0;

	if (NULL == element->u.e.attrs)
		return 0;

	return xattr_table_count(element->u.e.attrs);
}

/**
 * Unset property in element.
 *
 * @param element		the element node
 * @param name			the property name
 *
 * @return TRUE if the property existed, FALSE otherwise.
 */
gboolean
xnode_prop_unset(xnode_t *element, const char *name)
{
	return xnode_prop_ns_unset(element, NULL, name);
}

/**
 * Recursively apply function on each node, in depth-first mode.
 *
 * Traversal is done in such a way that the applied function can safely
 * free up the local node.
 */
void
xnode_tree_foreach(xnode_t *root, xnode_cb_t func, void *data)
{
	xnode_t *xn, *next;

	xnode_check(root);

	for (xn = root->first_child; xn != NULL; xn = next) {
		next = xn->sibling;
		xnode_tree_foreach(xn, func, data);
	}

	(*func)(root, data);
}

/**
 * Recursively apply matching function on each node, in depth-first order,
 * until it returns TRUE, at which time we return the matching node.
 *
 * @return the first matching node in the traversal path, NULL if none matched.
 */
xnode_t *
xnode_tree_find(xnode_t *root, xnode_match_t func, void *data)
{
	xnode_t *xn, *next;

	xnode_check(root);

	if ((*func)(root, data))
		return root;

	for (xn = root->first_child; xn != NULL; xn = next) {
		xnode_t *found;
		next = xn->sibling;
		found = xnode_tree_find(xn, func, data);
		if (found != NULL)
			return found;
	}

	return NULL;
}

/**
 * Internal routine for xnode_tree_find_depth().
 *
 * @return the first matching node in the traversal path, NULL if none matched.
 */
static xnode_t *
xnode_tree_find_until_depth(xnode_t *root,
	unsigned curdepth, unsigned maxdepth,
	xnode_match_t func, void *data)
{
	xnode_t *xn, *next;

	xnode_check(root);

	if ((*func)(root, data))
		return root;

	if (maxdepth == curdepth)
		return NULL;

	for (xn = root->first_child; xn != NULL; xn = next) {
		xnode_t *found;
		next = xn->sibling;
		found = xnode_tree_find_until_depth(xn,
			curdepth + 1, maxdepth, func, data);
		if (found != NULL)
			return found;
	}

	return NULL;
}

/**
 * Same as xnode_tree_find() but limit search to specified depth: 0 means
 * the root node only, 1 corresponds to the immediate children of the root,
 * and so on.
 *
 * @return the first matching node in the traversal path, NULL if none matched.
 */
xnode_t *
xnode_tree_find_depth(xnode_t *root, unsigned depth,
	xnode_match_t func, void *data)
{
	g_assert(uint_is_non_negative(depth));

	return xnode_tree_find_until_depth(root, 0, depth, func, data);
}

/**
 * Recursively apply two functions on each node, in depth-first mode.
 *
 * The first function "enter" is called when we enter a node and the
 * second "leave" is called when all the children have been processed,
 * before returning.
 *
 * Traversal is done in such a way that the "leave" function can safely
 * free up the local node.
 *
 * Traversal of a branch is aborted when "enter" returns FALSE, i.e. the
 * children of the node are not traversed and the "leave" callback is not
 * called since we did not enter...
 */
void
xnode_tree_enter_leave(xnode_t *root,
	xnode_cbe_t enter, xnode_cb_t leave, void *data)
{
	xnode_t *xn, *next;

	xnode_check(root);

	if (!(*enter)(root, data))
		return;

	for (xn = root->first_child; xn != NULL; xn = next) {
		next = xn->sibling;
		xnode_tree_enter_leave(xn, enter, leave, data);
	}

	(*leave)(root, data);
}

/**
 * Traversal callback to free up the structure.
 */
static void
xnode_item_free(xnode_t *item, void *udata)
{
	xnode_check(item);

	(void) udata;

	item->parent = item->first_child = item->last_child = item->sibling = NULL;
	xnode_free(item);
}

/**
 * Free an XML tree, recursively.
 */
void
xnode_tree_free(xnode_t *root)
{
	xnode_tree_foreach(root, xnode_item_free, NULL);
}

/**
 * Free an XML tree, recursively, and nullify the root pointer.
 */
void
xnode_tree_free_null(xnode_t **root_ptr)
{
	xnode_t *root = *root_ptr;

	if (root != NULL) {
		xnode_tree_free(root);
		*root_ptr = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
