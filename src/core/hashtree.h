/*
 * $Id$
 *
 * Copyright (c) 2003 Jeroen Asselman.
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

/**
 * @ingroup core
 * @file
 *
 * Hash tree implementation, not yet memory and speed optimized yet.
 *
 * @author Jeroen Asselman
 * @date 2003
 */

#ifndef _core_hashtree_h_
#define _core_hashtree_h_

#include "common.h"

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

hashtree	*hashtree_new(gpointer (*hash_func)(gpointer, gpointer));
void		 hashtree_append_leaf_node(hashtree *parent, gpointer hash);
void		 hashtree_finish(hashtree *parent);
void		 hashtree_destroy(hashtree *tree);

#endif	/* _core_hashtree_h_ */

/* vi: set ts=4 sw=4 cindent: */
