/*
 * Copyright (c) 2012, 2014 Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * G2 packet management.
 *
 * A G2 packet is represented as a tree, much alike an XML tree, hence the
 * "tree" name of its interface.
 *
 * Relevant documentation extracted from the g2.doxu.org website:
 *
 * INTRODUCTION
 *
 * All Gnutella2 communications are represented with Gnutella2 lightweight
 * tree packets. This applies everywhere from TCP stream communications to
 * reliable UDP transmissions to HTTP packet exchanges (where protocol data
 * has been negotiated). Each tree packet may contain meaningful payload data
 * and/or one or more child packets, allowing complex document structures
 * to be created and extended in a backward compatible manner.
 *
 * The concept can be compared to an XML document tree. The "packets"
 * are elements, which can in turn contain zero or more child elements
 * (packets). The payload of a packet is like the attributes of an XML
 * element. However, serializing XML has a lot of overhead due to all the
 * naming, even in a compact binary form. The Gnutella2 packet structure
 * makes a compromise: it names elements (packets), allowing them to be
 * globally recognized and understood, without knowledge of their format -
 * and stores attributes as binary payloads, requiring knowledge of their
 * content to parse them.
 *
 * Thus the element (packet or child packet) is the finite unit of
 * comprehension. This system provides an excellent trade-off between format
 * transparency and compactness.
 *
 * CONTENTS
 *
 * Each Gnutella2 packet contains:
 *
 * - Control flags
 * - A type name meaningful in the namespace of the packet's parent or context
 * - A length (or implied length)
 * - Payload data of a format specific to the packet type name and namespace
 * - Child packets existing in the namespace of this packet
 *
 * NAMESPACE CONSIDERATIONS
 *
 * Each packet contains a relative type name of up to 8 bytes in length,
 * which are case sensitive. The packet type name is meaningful only in
 * the namespace of the packet's parent, or in the absence of a parent,
 * the context of the packet (e.g. root level TCP stream).

 * This means that, for example a packet "A" inside packet "X" is different
 * to a packet "A" inside packet "Y". Packets are of the same type only if
 * their fully qualified absolute type names are equal.

 * As a convention, when discussing packet type names, they will be noted in
 * their absolute form with a URL style slash (/) separating each level. In
 * the above example, the first packet is "/X/A" while the second is
 * "/Y/A". It is clear now that the packets are of different types.

 * Packet type names can contain from 1 to 8 bytes inclusive, and none
 * of these bytes may be a null (0). Community approved packets are by
 * convention named with uppercase characters and digits, for example
 * "PUSH". Private packet types are by convention named with lowercase
 * characters and digits, prefixed with the vendor code of the owner,
 * for example "RAZAclr2".
 *
 * @author Raphael Manfredi
 * @date 2012, 2014
 */

#include "common.h"

#if 0
#define TREE_TESTING
#endif

#include "tree.h"

#include "lib/atoms.h"
#include "lib/etree.h"
#include "lib/halloc.h"
#include "lib/strtok.h"
#include "lib/walloc.h"

#ifdef TREE_TESTING
#include "tfmt.h"
#include "frame.h"
#endif

#include "lib/override.h"		/* Must be the last header included */

enum g2_tree_magic { G2_TREE_MAGIC = 0x67f8b9e7 };

/**
 * A G2 packet (tree structure).
 */
struct g2_tree {
	enum g2_tree_magic magic;		/**< Magic number */
	const char *name;				/**< Node name (atom) */
	void *payload;					/**< Payload buffer, NULL if none */
	size_t paylen;					/**< Payload length */
	node_t node;					/**< Embedded tree node */
	unsigned copied:1;				/**< Whether payload was copied */
};

static inline void
g2_tree_check(const struct g2_tree * const t)
{
	g_assert(t != NULL);
	g_assert(G2_TREE_MAGIC == t->magic);
}

/**
 * Assert that tree is a valid pointer.
 */
bool
g2_tree_is_valid(const struct g2_tree * const t)
{
	return t != NULL && G2_TREE_MAGIC == t->magic;
}

/**
 * Internal lookup of the tree root.
 *
 * @return the root of the tree.
 */
static g2_tree_t *
g2_tree_find_root(const g2_tree_t *root)
{
	etree_t t;

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	return etree_find_root(&t, root);
}

/**
 * Node matching function against name.
 *
 * @param item		the item to check
 * @param data		the name to match against
 */
static bool
g2_tree_has_name(const void *item, void *data)
{
	const g2_tree_t *root = item;
	const char *name = data;

	return 0 == strcmp(root->name, name);
}

/**
 * Internal lookup of a node sibling, starting at specified root.
 *
 * @return the first sibling bearing the specified name, NULL if none.
 */
static g2_tree_t *
g2_tree_find_sibling(const g2_tree_t *root, const char *name)
{
	etree_t t;

	g_assert(name != NULL);

	if (NULL == root)
		return NULL;

	g2_tree_check(root);
	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));

	return etree_find_sibling(&t, root,
		g2_tree_has_name, deconstify_char(name));
}

/**
 * Fetch the subtree identified by its path, "/" being the top root in any case.
 *
 * The lookup starts at the specified node, but if the specified root is part
 * of a larger tree, the search can be directed to that bigger tree root by
 * prefixing the search with "/".
 *
 * As usual in tree paths, "." is the current node and ".." its parent node,
 * the parent of the root being the root itself.
 *
 * The semantics of the root-anchored search are different than the ones of
 * a local search: if at the root of the /QH2 packet one looks for "/QH2/H"
 * it will bring back the "H" child node of the packet.  Therefore the leading
 * "/QH2/" is only there to make sure we're dealing with a /QH2 packet.
 *
 * @param root		the root of the G2 packet structure
 * @param path		the path to the tree to be retrieved (eg: "/QH2/H")
 *
 * @return the root of the tree if path was found, NULL otherwise.
 */
g2_tree_t *
g2_tree_lookup(const g2_tree_t *root, const char *path)
{
	const g2_tree_t *r;
	strtok_t *st;
	const char *tok;
	etree_t t;

	g2_tree_check(root);
	g_assert(path != NULL);

	st = strtok_make_nostrip(path);
	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));

	/*
	 * If path is anchored, make sure the root element bears the proper name.
	 */

	if ('/' == path[0]) {
		r = g2_tree_find_root(root);
		(void) strtok_next(st, "/");	/* Swallow leading '/' */
		for (;;) {
			tok = strtok_next(st, "/");
			if (NULL == tok)			/* Looking for "/", root of the tree */
				goto done;				/* We found it! */
			if G_UNLIKELY('.' == tok[0]) {
				if (0 == strcmp(tok, "."))		/* "." is the current node */
					continue;
				if (0 == strcmp(tok, ".."))		/* ".." is the current node */
					continue;					/* because we're at the root */
			}
			if (0 != strcmp(tok, r->name)) {
				r = NULL;
				goto done;
			}
			break;						/* Validated root is properly named */
		}
	} else {
		r = root;
	}

	/*
	 * We can now look for children that bear the proper names.
	 */

	while (NULL != (tok = strtok_next(st, "/"))) {
		if G_UNLIKELY('.' == tok[0]) {
			if (0 == strcmp(tok, "."))		/* "." is the current node */
				continue;
			if (0 == strcmp(tok, ".."))	{	/* ".." is the parent node */
				const g2_tree_t *parent = etree_parent(&t, r);
				if (parent != NULL)
					r = parent;			/* Not at the tree root */
				continue;
			}
		}
		r = etree_first_child(&t, r);
		if (NULL == r)					/* No children */
			goto done;
		r = g2_tree_find_sibling(r, tok);
		if (NULL == r)
			goto done;
	}

	/* FALL THROUGH */

done:
	strtok_free_null(&st);
	return deconstify_pointer(r);
}

/**
 * @return the name of the node.
 */
const char *
g2_tree_name(const g2_tree_t *node)
{
	g2_tree_check(node);

	return node->name;
}

/**
 * @return the root of the tree.
 */
g2_tree_t *
g2_tree_root(const g2_tree_t *node)
{
	g2_tree_check(node);

	return g2_tree_find_root(node);
}

/**
 * Fetch the payload of this node.
 *
 * @param node		the G2 node we're querying
 * @param paylen	if non-NULL, where the size of the payload is returned
 *
 * @return the start of the payload held in the node, NULL if none.
 */
const void *
g2_tree_node_payload(const g2_tree_t *node, size_t *paylen)
{
	g2_tree_check(node);

	if (NULL == node->payload) {
		if (paylen != NULL)
			*paylen = 0;
		return NULL;
	}

	if (paylen != NULL)
		*paylen = node->paylen;

	return node->payload;
}

/**
 * Fetch the payload of a tree item identified by its sub-path.
 *
 * See g2_tree_lookup() for the semantics of the supplied path.
 *
 * It is possible to request a payload in a sub-tree underneath the supplied
 * node, of course.
 *
 * @param root		the G2 root of the (sub)tree
 * @param path		the path to the item to be retrieved (eg: "URN")
 * @param paylen	if non-NULL, where the size of the payload is returned
 *
 * @return the start of the payload held in the tree, NULL if none or if the
 * item does not exist.
 */
const void *
g2_tree_payload(const g2_tree_t *root, const char *path, size_t *paylen)
{
	const g2_tree_t *n;

	n = g2_tree_lookup(root, path);
	if (NULL == n)
		return NULL;

	return g2_tree_node_payload(n, paylen);
}

/**
 * Iterator over the immediate children of a node.
 *
 * @param root		the G2 root of the tree
 * @param cb		callback to invoke on each immediate child of the root
 * @param data		user-supplied data passed to the callback
 */
void
g2_tree_child_foreach(const g2_tree_t *root, data_fn_t cb, void *data)
{
	etree_t t;

	g2_tree_check(root);
	g_assert(cb != NULL);

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	etree_foreach(&t, cb, data);
}

/**
 * @return the first child of the node, NULL if no child.
 */
g2_tree_t *
g2_tree_first_child(const g2_tree_t *root)
{
	etree_t t;

	g2_tree_check(root);

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	return etree_first_child(&t, root);
}

/**
 * @return the next sibling of a supplied node, NULL if no more siblings.
 */
g2_tree_t *
g2_tree_next_sibling(const g2_tree_t *child)
{
	etree_t t;

	g2_tree_check(child);

	etree_init_root(&t, child, FALSE, offsetof(g2_tree_t, node));
	return etree_next_sibling(&t, child);
}

/**
 * @return next sibling bearing the same name, NULL if none.
 */
g2_tree_t *
g2_tree_next_twin(const g2_tree_t *child)
{
	g2_tree_check(child);

	return g2_tree_find_sibling(child, child->name);
}

/**
 * Create a node without any payload.
 *
 * @param name		name of the node
 *
 * @return a new node with no payload.
 */
g2_tree_t *
g2_tree_alloc_empty(const char *name)
{
	g2_tree_t *n;

	WALLOC0(n);
	n->magic = G2_TREE_MAGIC;
	n->name = atom_str_get(name);

	return n;
}

/**
 * Release memory used by node.
 */
static void
g2_tree_free_node(void *data)
{
	g2_tree_t *n = data;

	g2_tree_check(n);

	if (n->payload != NULL && n->copied)
		hfree(n->payload);

	atom_str_free_null(&n->name);
	n->payload = NULL;
	n->magic = 0;
	WFREE(n);
}

/**
 * Create a node with associated payload.
 *
 * The payload data are NOT copied.
 *
 * @param name		name of the node
 * @param payload	the start of the payload
 * @param paylen	the length of the payload, in bytes
 *
 * @return a new node.
 */
g2_tree_t *
g2_tree_alloc(const char *name, const void *payload, size_t paylen)
{
	g2_tree_t *n;

	n = g2_tree_alloc_empty(name);
	n->payload = deconstify_pointer(payload);
	n->paylen = paylen;
	n->copied = FALSE;

	return n;
}

/**
 * Create a node with associated payload.
 *
 * The payload data are copied.
 *
 * @param name		name of the node
 * @param payload	the start of the payload
 * @param paylen	the length of the payload, in bytes
 * @param copy		whether payload data must be copied
 *
 * @return a new node.
 */
g2_tree_t *
g2_tree_alloc_copy(const char *name, const void *payload, size_t paylen)
{
	g2_tree_t *n;

	n = g2_tree_alloc_empty(name);
	n->payload = hcopy(payload, paylen);
	n->paylen = paylen;
	n->copied = TRUE;

	return n;
}

/**
 * Set payload for node, replacing any older payload.
 *
 * @param root		the node to which we're adding a payload
 * @param payload	the start of the payload
 * @param paylen	the length of the payload, in bytes
 * @param copy		whether payload data must be copied
 */
void
g2_tree_set_payload(g2_tree_t *root, const void *payload,
	size_t paylen, bool copy)
{
	g2_tree_check(root);

	if (root->payload != NULL && root->copied)
		hfree(root->payload);

	root->payload = copy ? hcopy(payload, paylen) :
		deconstify_gpointer(payload);
	root->paylen = paylen;
	root->copied = booleanize(copy);
}

/**
 * Append data to node's payload, copying data.
 *
 * If there was no payload yet, this becomes the new payload, otherwise it
 * is concatenated at the end.  The payload buffer is resized as needed to
 * make sure everything fits.
 *
 * @param root		the node to which we're adding a payload
 * @param payload	the start of the payload to concatenate at the end
 * @param paylen	the length of the payload, in bytes
 *
 * @return the new length of the payload.
 */
size_t
g2_tree_append_payload(g2_tree_t *root, const void *payload, size_t paylen)
{
	size_t newlen;

	g2_tree_check(root);

	newlen = root->paylen + paylen;

	if (0 == paylen)
		return newlen;		/* Nothing to do and no payload copying needed */

	g_assert(payload != NULL);

	/*
	 * If there was already a payload and it was not copied, we need to
	 * allocate new buffer and copy the old data to it.
	 *
	 * Otherwise, resize the old buffer so that it can hold the new data.
	 */

	if (root->payload != NULL) {
		if (!root->copied) {
			void *p = halloc(newlen);
			memcpy(p, root->payload, root->paylen);
			root->payload = p;
			root->copied = TRUE;
		} else {
			root->payload = hrealloc(root->payload, newlen);
		}
	} else {
		root->payload = halloc(newlen);
		root->copied = TRUE;
	}

	memcpy(ptr_add_offset(root->payload, root->paylen), payload, paylen);
	root->paylen = newlen;

	g_assert(root->copied);

	return newlen;
}

/**
 * Add node as an immediate child of the supplied node.
 */
void
g2_tree_add_child(g2_tree_t *parent, g2_tree_t *child)
{
	etree_t t;

	g2_tree_check(parent);
	g2_tree_check(child);

	etree_init_root(&t, parent, FALSE, offsetof(g2_tree_t, node));
	etree_prepend_child(&t, parent, child);
}

/**
 * Reverse the order of children in node.
 */
void
g2_tree_reverse_children(g2_tree_t *root)
{
	etree_t t;

	g2_tree_check(root);

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	etree_reverse_children(&t, root);
}

/**
 * Free sub-tree, destroying all its items and removing the reference in
 * the parent node, if any.
 */
static void
g2_tree_free(g2_tree_t *root)
{
	etree_t t;

	g2_tree_check(root);

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	etree_sub_free(&t, root, g2_tree_free_node);
}

/**
 * Free tree, nullify its pointer.
 */
void
g2_tree_free_null(g2_tree_t **root_ptr)
{
	g2_tree_t *root = *root_ptr;

	if (root != NULL) {
		g2_tree_free(root);
		*root_ptr = NULL;
	}
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
g2_tree_enter_leave(g2_tree_t *root,
	match_fn_t enter, data_fn_t leave, void *data)
{
	etree_t t;

	g2_tree_check(root);

	etree_init_root(&t, root, FALSE, offsetof(g2_tree_t, node));
	etree_traverse(&t, ETREE_TRAVERSE_ALL | ETREE_CALL_AFTER,
		0, ETREE_MAX_DEPTH, enter, leave, data);
}

#ifdef TREE_TESTING

#define LARGE_PAYLOAD	258		/* Force 2-byte payload length */

void G_COLD
g2_tree_test(void)
{
	g2_tree_t *root, *first, *node, *c2, *retrieved;
	const char root_payload[] = "root payload";
	const char second[] = "second payload";
	size_t needed, length, rlen;
	void *buffer, *large;
	bool ok;

	g_debug("%s() starting...", G_STRFUNC);

	/*
	 * Tree primitives testing.
	 */

	large = halloc(LARGE_PAYLOAD);

	root = g2_tree_alloc_copy("root", root_payload, vstrlen(root_payload));
	g2_tree_add_child(root,
		g2_tree_alloc_copy("schild", second, vstrlen(second)));
	first = g2_tree_alloc_empty("rchild");
	g2_tree_add_child(root, first);
	g2_tree_add_child(first, (c2 = g2_tree_alloc_empty("c2")));
	g2_tree_add_child(c2, g2_tree_alloc_empty("d2"));
	g2_tree_add_child(c2, g2_tree_alloc_empty("d1"));
	g2_tree_add_child(first, g2_tree_alloc_empty("c3"));
	g2_tree_add_child(first, g2_tree_alloc("c1", large, LARGE_PAYLOAD));

	ok = g2_tfmt_tree_dump(root, stderr, G2FMT_O_PAYLOAD | G2FMT_O_PAYLEN);
	g_assert(ok);

	node = g2_tree_lookup(first, "/root/rchild/c2");
	g_assert(node == c2);
	node = g2_tree_lookup(first, "/root/bar/c2");
	g_assert(node == NULL);
	node = g2_tree_lookup(first, "/root/rchild/c4");
	g_assert(node == NULL);
	node = g2_tree_lookup(root, "/root/rchild/c2");
	g_assert(node == c2);
	node = g2_tree_lookup(root, "/root/rchild/c1/../c2");
	g_assert(node == c2);
	node = g2_tree_lookup(root, "/root/rchild/c1/../c2/../c2");
	g_assert(node == c2);
	node = g2_tree_lookup(root, "/root/rchild/c4/../c2");
	g_assert(node == NULL);	/* Since there is no "c4" */
	node = g2_tree_lookup(root, "/root/rchild/././c2");
	g_assert(node == c2);
	node = g2_tree_lookup(first, "c4");
	g_assert(node == NULL);
	node = g2_tree_lookup(first, "c2");
	g_assert(node == c2);
	node = g2_tree_lookup(first, "./c2");
	g_assert(node == c2);

	/*
	 * Serialization testing.
	 */

	needed = g2_frame_serialize(root, NULL, 0);
	g_debug("%s(): need %zu bytes to serialize tree", G_STRFUNC, needed);

	buffer = halloc(needed);
	length = g2_frame_serialize(root, buffer, needed);
	g_assert(length == needed);

	retrieved = g2_frame_deserialize(buffer, length, &rlen, TRUE);
	g_assert(retrieved != NULL);
	g_assert(length == rlen);

	g_debug("%s(): deserialized tree:", G_STRFUNC);
	ok = g2_tfmt_tree_dump(retrieved, stderr, G2FMT_O_PAYLOAD | G2FMT_O_PAYLEN);
	g_assert(ok);

	node = g2_tree_lookup(retrieved, "/root/rchild/c2");
	g_assert(node != NULL);
	g_assert(node != c2);
	g_assert(0 == strcmp("c2", g2_tree_name(node)));

	HFREE_NULL(buffer);
	HFREE_NULL(large);
	g2_tree_free_null(&root);
	g2_tree_free_null(&retrieved);

	g_debug("%s() done.", G_STRFUNC);
}

#else	/* !TREE_TESTING */
void G_COLD
g2_tree_test(void)
{
	/* Nothing */
}
#endif	/* TREE_TESTING */

/* vi: set ts=4 sw=4 cindent: */
