/*
 * $Id$
 *
 * Copyright (c) 2003 - 2004 Jeroen Asselman.
 *
 *----------------------------------------------------------------------
 *   The contents of this file are subject to the Mozilla Public License
 *   Version 1.1 (the "License"); you may not use this file except in
 *   compliance with the License. You may obtain a copy of the License at
 *   http://www.mozilla.org/MPL/
 *
 *   Software distributed under the License is distributed on an "AS IS"
 *   basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *   License for the specific language governing rights and limitations
 *   under the License.
 *
 *   The Original Code is hashtree.c, released Sun, 07 Sep 2003.
 *
 *   The Initial Developer of the Original Code is Jeroen Asselman
 *   Portions created by the Initial Developer are Copyright (C) 2003
 *   the Initial Developer. All Rights Reserved.
 *
 *   Contributor(s):
 *
 *   Alternatively, the contents of this file may be used under the terms
 *   of the GNU General Public License Version 2 or later (the  "GPL"), in
 *   which case the provisions of GPL are applicable instead of those
 *   above.  If you wish to allow use of your version of this file only
 *   under the terms of the GPL and not to allow others to use
 *   your version of this file under the MPL, indicate your decision by
 *   deleting  the provisions above and replace  them with the notice and
 *   other provisions required by the GPL.  If you do not delete
 *   the provisions above, a recipient may use your version of this file
 *   under either the MPL or the GPL License.
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Merkle Hash tree implementation, not yet memory and speed optimized yet.
 *
 * Hashtree can be used to build any hashtree. This could be a SHA1 tree or a
 * tigertree for example.
 *
 * To create a new hash tree, use the function hash_tree_new, save the returned
 * pointer as the parent. Add new leaf nodes to the hash tree using
 * hash_tree_append_leaf_node, pass the parent as an argument, save the returned
 * pointer as parent again. When you are done adding leaf nodes, call
 * hash_tree_finish. After this you can read parent->hash to read the calculated
 * hash. If you are done with this tree, free the tree with hash_tree_destroy.
 * Look at the function header description for a more detailed information about
 * the arguments and the returned values.
 *
 * @author Jeroen Asselman <jeroen@asselman.com>
 * @version 1.5
 * @date 2003-2004
 */

#include "common.h"

RCSID("$Id$")

/*
 * TODO: Allow adding of a complete tree, including allready calculated
 *       hashes
 */

#include "hashtree.h"
#include "if/core/nodes.h"

#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

node_t *node_new();
void node_destroy(node_t *node);
node_t *find_free_leaf_node(node_t *node);
node_t *find_free_node(node_t *node);
void hashtree_create_tree(node_t *start_node);
void hashtree_increase_depth(hashtree *tree);
void build_hash(hashtree *tree, node_t *node);

gint blocks;

/*** Helper functions ***/

/**
 * Check wether node is a leaf node.
 *
 * @param node is a pointer to the node which should be checked.
 * @return a boolean which is true if the node is a leaf node, false otherwise.
 */
inline gboolean node_is_leaf_node(node_t *node)
{
	return node->left_node == NULL &&
		  node->right_node == NULL &&
		  node->level == 0;
}

/**
 * Check wether node is a free leaf node.
 *
 * @param node is a pointer to the node which should be checked.
 * @return a boolean which is true if the node is a free leaf node,
 *         false otherwise.
 */
inline gboolean node_is_free_leaf_node(node_t *node)
{
	return node->left_node == NULL &&
		  node->right_node == NULL &&
		  node->level == 0 &&
		  node->hash == NULL;
}

/**
 * Check wether node is a free node.
 *
 * @param node is a pointer to the node which should be checked.
 * @return a boolean which is true if the node is a free node or a free leaf
 *        node, false otherwise.
 */
inline gboolean node_is_free_node(node_t *node)
{
	return (node->left_node == NULL || node->right_node == NULL) &&
		  node->hash == NULL;
}


/* Public functions */

/**
 * Create a new hashtree.
 *
 * Initializes a new hashtree. Save the returned hashtree pointer which you need
 * to pass to the other hashtree functions.
 *
 * @param hash_func a hash function which should be used to calculate the
 *        internal hash. The signature of the hash_func must be:
 *        gpointer *hash_func(gpointer hash1, gpointer hash2)
 *        The returned hash must be allocated with g_malloc() as this hashtree
 *        implementation will free it later with g_free().
 * @return a pointer to the new created hashtree.
 */
hashtree	*hashtree_new(gpointer (*hash_func)(gpointer, gpointer))
{
	hashtree *tree = (hashtree *) malloc(sizeof(hashtree));

	tree->hash_func = hash_func;
	tree->depth = 0;
	tree->parent = node_new();

	return tree;
}

/**
 * Append leaf node to hash tree.
 *
 * Adds a new leaf node to the hashtree, if necesarry it will expand the
 * hashtree to include the new leaf node.
 *
 * @param tree is a pointer to the hashtree to perform this action on.
 * @param hash is a pointer to a hash which should be included with the leaf
 *        node. This hash must be a pointer allocated with g_malloc as this
 *        hashtree will free this pointer with g_free later when the hashtree
 *        is destroyed.
 */
void hashtree_append_leaf_node(hashtree *tree, gpointer hash)
{
	node_t *free_node = find_free_node(tree->parent);

	if (free_node == NULL) {
		hashtree_increase_depth(tree);
		free_node = find_free_leaf_node(tree->parent);
	} else {
		if (!node_is_leaf_node(free_node)) {
			free_node->right_node = node_new();
			free_node->right_node->level = free_node->left_node->level;
			hashtree_create_tree(free_node->right_node);
			free_node = find_free_leaf_node(free_node->right_node);
		}
	}

	free_node->hash = hash;

	g_assert(node_is_leaf_node(free_node));
}

/**
 * Finish the hashtree.
 *
 * Calculates all internal hashes in the hashtree. Call this function when you
 * are ready with adding leaf nodes to the hashtree.
 *
 * @param tree is a pointer to the hashtree to perform this action on.
 */
void hashtree_finish(hashtree *tree)
{
	blocks = 0;
	build_hash(tree, tree->parent);
}

/**
 * Destroy the hashtree.
 *
 * Destroys the hash tree and all its included node. This will free all memory
 * used by the hashtree, including all hashes assigned to a node which was
 * added with hashtree_append_leaf_node which will be freed using g_free
 *
 * @param tree is a pointer to the hashtree to perform this action on.
 */
void hashtree_destroy(hashtree *tree)
{
	node_destroy(tree->parent);

	tree->depth = 0;
	tree->parent = NULL;

	free(tree);
}

/* Private functions */

/**
 * Calculate hash.
 *
 * Calculates the hash for the current node and its child node by using this
 * function recursively.
 * If a node has only a node to the left and no nodes to the right it will
 * promote the to the left up one level without recalculating.
 *
 * @param tree is a pointer to the hashtree to perform this action on.
 * @param node is the node for which the hash should be calculated
 */
void build_hash(hashtree *tree, node_t *node)
{
	g_assert(node != NULL);

	if (node_is_leaf_node(node)) {
		blocks++;
		return;
	}

	g_assert(node->left_node != NULL);
	g_assert(node->hash == NULL);

	/* First build hash for child nodes */
	if (node->left_node != NULL)
		build_hash(tree, node->left_node);

	if (node->right_node != NULL)
		build_hash(tree, node->right_node);

	/* Now build our own hash */
	if (node->right_node != NULL) {
		g_assert(node->left_node->hash != NULL);
		g_assert(node->right_node->hash != NULL);

		node->hash =
			  tree->hash_func(node->left_node->hash, node->right_node->hash);
	} else {
		node->hash = node->left_node->hash;
	}

	g_assert(node->hash != NULL);
}

/**
 * Find a free leaf node.
 *
 * Searches the tree to find a free leaf node.
 *
 * @param node is a pointer to a node from which the search should be started.
 *        It will search all its childeren using recursion.
 * @return a pointer to the free leaf node that is found, if no free leaf node
 *         could be found NULL will be returned.
 */
node_t *find_free_leaf_node(node_t *node)
{
	node_t *result = NULL;

	if (node == NULL)
		return NULL;

	if (node_is_free_leaf_node(node))
		return node;

	if (node_is_leaf_node(node))
		return NULL;

	/* Not a leaf node, check left node for free leaf nodes */
	if ((result = find_free_leaf_node(node->left_node)) != NULL)
		return result;

	/* No success, check right node for free leaf nodes */
	if ((result = find_free_leaf_node(node->right_node)) != NULL)
		return result;

	/*
	 * Nothing free at the left, nothing free at the right. Only one
	 * conclusion remaing. Full!
	 */
	return NULL;
}

/**
 * Find a free node.
 *
 * Searches the tree to find a free node.
 *
 * @param node is a pointer to a node from which the search should be started.
 *        It will search all its children using recursion.
 * @return a pointer to the free node that is found, if no free node could be
 *         found NULL is returned. The returned node could also be a free leaf
 *         node.
 */
node_t *find_free_node(node_t *node)
{
	node_t *result = NULL;

	if (node == NULL)
		return NULL;

	/*
	 * If current node is a leaf node, then we are at the bottom of this tree,
	 * no need to recurse any further. If the node happens to be free we are
	 * also happy, because we found our free node
	 */
	if (node_is_free_leaf_node(node)) {
		return node;
	}

	if (node_is_leaf_node(node)) {
		return NULL;
	}


	/* Not a leaf node, check left node for free leaf nodes */
	if ((result = find_free_node(node->left_node)) != NULL)
		return result;

	/* No success, check right node for free leaf nodes */
	if ((result = find_free_node(node->right_node)) != NULL)
		return result;

	if (node_is_free_node(node)) {
		return node;
	}

	/*
	 * Nothing free at the left, nothing free at the right. Only one
	 * conclusion remaing. Full!
	 */
	return NULL;
}

/**
 * Build a new hashtree with only left nodes.
 *
 * Builds a new hashtree until node->depth == 0. Only the nodes at the left are
 * build, all right nodes are NULL.
 *
 * @param start_node is a pointer to the node to which the new tree should be build.
 *        this function will use node->depth to determine how deep the tree
 *        should be build.
 */
void hashtree_create_tree(node_t *start_node)
{
	int i;
	node_t *add_node = start_node;

	/* Now add new children */
	for (i = start_node->level; i > 0; i--) {
		add_node->left_node = node_new();
		add_node = add_node->left_node;
		add_node->level = i - 1;
	}
}

/**
 * Increases the depth of the hashtree.
 *
 * Increases the hash tree by adding a new parrent to the tree.
 *
 * @param tree is a pointer to the hashtree to perform this action on.
 */
void hashtree_increase_depth(hashtree *tree)
{
	node_t *new_parent;

	tree->depth++;

	/* Create new parent */
	new_parent = node_new();
	new_parent->left_node = tree->parent;
	new_parent->level = tree->depth;
	tree->parent = new_parent;

	tree->parent->right_node = node_new();
	tree->parent->right_node->level = tree->parent->level - 1;

	hashtree_create_tree(tree->parent->right_node);
}

/**
 * Create a new node.
 *
 * Creates a new node by allocating memory for it.
 *
 * @return a pointer to the newly created node.
 */
node_t *node_new()
{
	node_t *new_node;

	new_node = (node_t *) walloc0(sizeof(node_t));
	new_node->left_node = NULL;
	new_node->right_node = NULL;
	new_node->hash = NULL;
	new_node->level = 0;

	return new_node;
}

/**
 * Destory a node.
 *
 * Destorys a node and all its child nodes using recursing, all memory assinged
 * to this node will be freed, including an assigned hash.
 *
 * @param node is a pointer to the node that should be destroyed.
 */
void node_destroy(node_t *node)
{
	if (node->left_node != NULL) {
		if (node->hash == node->left_node->hash)
			node->hash = NULL;	/* avoid freeing twice */
		node_destroy(node->left_node);
	}

	if (node->right_node != NULL)
		node_destroy(node->right_node);

	if (node->hash != NULL)
		G_FREE_NULL(node->hash);

	wfree(node, sizeof(node_t));
}
