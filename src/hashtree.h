/*
 * $Id$
 *
 * Copyright (c) 2003 Jeroen Asselman.
 * 
 * Hash tree implementation, not yet memory and speed optimized yet.
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
 *   The Original Code is hashtree.h, released Sun, 07 Sep 2003.
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

#ifndef _hashtree_h_
#define _hashtree_h_

/*
 * Usage: Create a new hash tree with hash_tree_new, save the returned
 *        pointer as the parent. Add new leaf nodes to the hash tree using
 *        hash_tree_append_leaf_node, pass the parent as an argument, save
 *        the returned pointer as parent again. When you are done adding
 *        leaf nodes, call hash_tree_finish. After this you can read
 *        parent->hash to read the calculated hash. If you are done with
 *        this tree, free the tree with hash_tree_destroy. Look at the function
 *        header description for a more detailed information about the
 *        arguments and the returned values.
 *
 *			-- Jeroen Asselman <jeroen@asselman.com>
 */
 
typedef struct node_s node_t;
struct node_s {
	node_t	*left_node;
	node_t	*right_node;

	gpointer	hash;

	int level;
};

typedef struct hashtree_s hashtree;
struct hashtree_s {
	node_t	*parent;

	gint depth;
	
	gpointer	(* hash_func) (gpointer hash1, gpointer hash2);
};

hashtree	*hashtree_new(gpointer hash_func);
void		 hashtree_append_leaf_node(hashtree *parent, gpointer hash);
void		 hashtree_finish(hashtree *parent);
void		 hashtree_destroy(hashtree *tree);

#endif	/* _hashtree_h_ */
