/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
 *
 * GUI filtering functions.
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
 * @ingroup gtk
 * @file
 *
 * GUI filtering functions.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2003
 */
#include "gtk/gui.h"

#include "search_cb.h"

#include "gtk/columns.h"
#include "gtk/drag.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/iso3166.h"
#include "lib/mime_type.h"
#include "lib/stringify.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

static gchar tmpstr[4096];

/**
 * Characteristics of data in search results columns, used for sorting.
 */
enum {
	SEARCH_COL_SORT_DATA_RANDOM = 0,	/**< Randomly distributed */
	SEARCH_COL_SORT_DATA_SORTED_ASC,	/**< Already sorted or almost sorted */
	SEARCH_COL_SORT_DATA_SORTED_DES,	/**< Same as above but descending */
	SEARCH_COL_SORT_DATA_COUNT,			/**< Sorting by "count" column */
	SEARCH_COL_SORT_DATA_INFO,			/**< Sorting by Info column */
	SEARCH_COL_SORT_DATA_DEFAULT		/**< Catch all case */
};

static GtkCList *
clist_search(void)
{
    static GtkWidget *clist;
	if (!clist) {
    	clist = gui_main_window_lookup("clist_search");
	}
	return GTK_CLIST(clist);
}

/**
 *	Add the given tree node to the hashtable.
 *
 *  The key is an atomized sha1 of the search result.
 *
 *  @bug
 *	FIXME: The "key" is an atom of the record's SHA1, why don't we
 *	create that atom here, as we free it in "remove_parent_with_sha1"?
 *	Emile 02/15/2004
 */
static inline void
add_parent_with_sha1(search_t *search, const char *sha1, GtkCTreeNode *data)
{
	htable_insert(search->parents, sha1, data);
}

/**
 *	Removes the tree node matching the given sha1 from the hash table.
 *  The atom used for the key is then freed
 */
static inline void
remove_parent_with_sha1(search_t *search, const struct sha1 *sha1)
{
	const void *key;
	const void *orig_key;

	key = atom_sha1_get(sha1);

	if (htable_lookup_extended(search->parents, key, &orig_key, NULL)) {
		/* Must first free memory used by the original key */
		atom_sha1_free(orig_key);

		/* Then remove the key */
		htable_remove(search->parents, key);
	} else
		g_warning("%s(): can't find sha1 in hash table!", G_STRFUNC);

	atom_sha1_free(key);
}


/**
 *	@returns the tree node corresponding to the given key, an atomized
 *	sha1.
 */
GtkCTreeNode *
find_parent_with_sha1(search_t *search, gconstpointer key)
{
	return htable_lookup(search->parents, key);
}

static bool
search_gui_free_parent(const void *key, void *unused_value, void *unused_x)
{
	(void) unused_value;
	(void) unused_x;
	atom_sha1_free(key);
	return TRUE;
}

void
search_gui_free_gui_record(gpointer gui_rc)
{
	wfree(gui_rc, sizeof(gui_record_t));
}

/**
 * Decrement refcount of hash table key entry.
 */
static gboolean
dec_records_refcount(const void *key, void *unused_x)
{
	(void) unused_x;
	search_gui_unref_record(deconstify_pointer(key));
	return TRUE;
}

/**
 *	Removes a reference to the record stored in the given tree node
 */
static void
search_gui_ctree_unref(GtkCTree *ctree, GtkCTreeNode *node,
		gpointer unused_data)
{
	gui_record_t *grc;

	(void) unused_data;
	grc = gtk_ctree_node_get_row_data(ctree, node);
	search_gui_unref_record(grc->shared_record);
}


/**
 *	Clears all nodes from given ctree and unreferences all records
 *	referenced by the nodes row data
 */
void
search_gui_clear_ctree(GtkCTree *ctree)
{
	/* Unreference all records */
	gtk_ctree_post_recursive(ctree, NULL, search_gui_ctree_unref, NULL);
	gtk_clist_clear(GTK_CLIST(ctree));
}


/**
 * Clear all results from search.
 */
void
search_gui_clear_search(search_t *sch)
{
	g_assert(sch);
	g_assert(sch->dups);

	search_gui_clear_ctree(GTK_CTREE(sch->tree));
	hset_foreach_remove(sch->dups, dec_records_refcount, NULL);
	htable_foreach_remove(sch->parents, search_gui_free_parent, NULL);
}

static gint search_gui_cursor_x, search_gui_cursor_y;

/**
 * Sets the last known position of the (mouse) cursor. This is necessary
 * to map the cursor coordinates to a row in the tree for DND. This
 * should be called from the "button-press-event" signal handler with
 * the event coordinates.
 */
void
search_gui_set_cursor_position(gint x, gint y)
{
	search_gui_cursor_x = x;
	search_gui_cursor_y = y;
}


char *
search_gui_get_local_file_url(GtkWidget *widget)
{
	GtkCTreeNode *node;
	gui_record_t *grc;
	record_t *record;
	int row = -1;

	if (
		!gtk_clist_get_selection_info(GTK_CLIST(widget),
			search_gui_cursor_x, search_gui_cursor_y, &row, NULL)
	) {
		return NULL;
	}

	if (row < 0)
		return NULL;

	node = gtk_ctree_node_nth(GTK_CTREE(widget), row);
	grc = gtk_ctree_node_get_row_data(GTK_CTREE(widget), node);
	record = grc->shared_record;
	if (!(ST_LOCAL & record->results_set->status))
		return NULL;

	if (!record->tag)
		return NULL;

	return url_from_absolute_path(record->tag);
}

void
search_gui_init_tree(search_t *search)
{
    const gchar *titles[c_sl_num];
    int row;

	g_assert(NULL == search->parents);
	search->parents = htable_create(HASH_KEY_SELF, 0);

    titles[c_sl_name] = lazy_utf8_to_ui_string(search_gui_query(search));
    titles[c_sl_hit] = "0";
    titles[c_sl_new] = "0";
    row = gtk_clist_append(GTK_CLIST(clist_search()), (gchar **) titles);
    gtk_clist_set_row_data(GTK_CLIST(clist_search()), row, search);

	search_gui_sort_column(search, search->sorting.s_column);
}


/* Searches results */


/**
 * If the value in sort_col for r1 is "greater than" r2 returns +1
 * 0 if they're equal, and -1 if r1 is "less than" r2
 */
static gint
search_gui_compare_records(gint sort_col,
	const gui_record_t *g1, const gui_record_t *g2)
{
	record_t *r1 = g1->shared_record;
	record_t *r2 = g2->shared_record;
    results_set_t *rs1;
	results_set_t *rs2;
    gint result = 0;

    if (r1 == r2)
        result = 0;
    else if (r1 == NULL)
        result = -1;
    else if (r2 == NULL)
        result = +1;
    else {
        rs1 = r1->results_set;
        rs2 = r2->results_set;

        g_assert(rs1 != NULL);
        g_assert(rs2 != NULL);

        switch ((enum c_sr_columns) sort_col) {
        case c_sr_address:
			result = host_addr_cmp(rs1->addr, rs2->addr);
			break;

        case c_sr_filename:
			if (GUI_PROPERTY(search_sort_casesense)) {
            	result = strcmp(r1->utf8_name, r2->utf8_name);
			} else {
            	result = ascii_strcasecmp(r1->utf8_name, r2->utf8_name);
			}
            break;

        case c_sr_ext:
            result = strcmp(EMPTY_STRING(r1->ext), EMPTY_STRING(r2->ext));
            break;


        case c_sr_mime:
			{
				enum mime_type mt1, mt2;

				mt1 = mime_type_from_extension(r1->ext);
				mt2 = mime_type_from_extension(r2->ext);
				result = CMP(mt1, mt2);
			}
			break;

        case c_sr_charset:
            result = strcmp(EMPTY_STRING(r1->charset),
						EMPTY_STRING(r2->charset));
            break;

        case c_sr_size:
			/*
			 * Sort by size, then by identical SHA1.
			 */
			if (r1->size == r2->size)
            	result = search_gui_cmp_sha1s(r1->sha1, r2->sha1);
			else
				result = CMP(r1->size, r2->size);
            break;

        case c_sr_vendor:
			result = CMP(rs1->vendor, rs2->vendor);
            break;

        case c_sr_info:
			result = strcmp(EMPTY_STRING(r1->info), EMPTY_STRING(r2->info));
            break;

        case c_sr_count:
			/*
			 * Sort by count (#), then by size.
			 */
			if (g1->num_children == g2->num_children)
				result = CMP(r1->size, r2->size);
			else
				result = CMP(g1->num_children, g2->num_children);
            break;

        case c_sr_loc:
            result = CMP(rs1->country, rs2->country);
            break;

        case c_sr_route:
			result = host_addr_cmp(rs1->last_hop, rs2->last_hop);
			break;

        case c_sr_hops:
			result = CMP(rs1->hops, rs2->hops);
			break;

        case c_sr_ttl:
			result = CMP(rs1->ttl, rs2->ttl);
			break;

        case c_sr_protocol:
			{
				const guint32 mask = ST_UDP;
				result = CMP(mask & rs1->status, mask & rs2->status);
			}
			break;

        case c_sr_hostile:
			{
				const guint32 mask = ST_HOSTILE;
				result = CMP(mask & rs1->status, mask & rs2->status);
			}
			break;

        case c_sr_owned:
			{
				const guint32 mask = SR_SHARED | SR_OWNED;
				result = CMP(mask & r1->flags, mask & r2->flags);
			}
			break;

        case c_sr_spam:
			{
				guint32 mask = SR_SPAM;
				result = CMP(mask & r1->flags, mask & r2->flags);
				if (0 == result) {
					mask = ST_SPAM;
					result = CMP(mask & rs1->status, mask & rs2->status);
				}
			}
			break;

        case c_sr_sha1:
           	result = search_gui_cmp_sha1s(r1->sha1, r2->sha1);
			break;

        case c_sr_ctime:
           	result = delta_time(r1->create_time, r2->create_time);
			break;

        case c_sr_num:
			g_assert_not_reached();
			break;
        }
    }

	return result;
}

/**
 * Inserts the given node into the given list in the proper position.  Assumes
 * list has at least one item already and is sorted.  Note: this is extremely
 * time critical code, some code duplication is intentional.
 */
GList *
search_gui_insert_with_sort(GList *list, GtkCTreeNode *node,
	GtkCTree *ctree, gboolean ascending, gint sort_col)
{
	GList *l;
	gint i;
	gint result;
	gui_record_t *rkey;
	gui_record_t *rlist;

	rkey = gtk_ctree_node_get_row_data(ctree, node);
    list = g_list_first(list);

	if (ascending) {

		for (i = 0, l=list;; l = g_list_next(l), i++) {

			rlist = gtk_ctree_node_get_row_data(ctree, l->data);
			result = search_gui_compare_records(sort_col, rkey, rlist);

			if (result <= 0) {
                /* Our entry is "less" than the current (l)*/

                /*
                 * FIXME? g_list_insert is O(n). It might be possible
                 * to speed this up using the GList internals and a
                 * proper insertion funtion in glib-missing.c
                 *    -- BLUE 17/01/2004
                 */

				/*
				 * The purpose of using this sort hinges upon the assumption
				 * that this insert will be O(1) if i == 0, ie. if we're working
				 * with already ordered data
				 * 	 -- Emile
				 */

                /* Prepends if i == 0 */
				list = g_list_insert(list, node, i);
                break;
			} else {
                /* Our entry is "greater" than the current (l).
                 *
                 * If we are the the end, then we append the node,
                 * otherwise we go on...
                 */
    			if (NULL == l->next) {
                    /*
                     * FIXME? g_list_append is also O(n). Since we are
                     * at the last listitem anyway, why not append a new
                     * item directly using a custom function from
                     * glib-missing.c?
                     *    -- BLUE 17/01/2004
                     */
                    list = g_list_append(list, node);
                    break;
                }
            }
		}
	} else { /* sort descending */

		for (i = 0, l=list;; l = g_list_next(l), i++) {

			rlist = gtk_ctree_node_get_row_data(ctree, l->data);
			result = search_gui_compare_records(sort_col, rkey, rlist);

			if (result >= 0) {
                /* Entry is "greater" than the current (l)*/

                /*
                 * FIXME? g_list_insert is O(n). It might be possible
                 * to speed this up using the GList internals and a
                 * proper insertion funtion in glib-missing.c
                 *    -- BLUE 17/01/2004
                 */

				/*
				 * The purpose of using this sort hinges upon the assumption
				 * that this insert will be O(1) if i == 0, ie. if we're working
				 * with already ordered data
				 * 	 -- Emile
				 */

                /* Prepends if i == 0 */
				list = g_list_insert(list, node, i);
                break;
			} else {
                /* Our entry is "less" than the current (l).
                 *
                 * If we are the the end, then we append the node,
                 * otherwise we go on...
                 */
                if (NULL == l->next) {
                    /*
                     * FIXME? g_list_append is also O(n). Since we are
                     * at the last listitem anyway, why not append a new
                     * item directly using a custom function from
                     * glib-missing.c?
                     *    -- BLUE 17/01/2004
                     */
                    list = g_list_append(list, node);
                    break;
                }
            }
		}
	}

	return list;
}


/**
 * Swaps the values in the given array for the given indicies
 */
void
search_gui_quick_sort_array_swap(GArray *array, gint i1, gint i2)
{
/*
 *  This is the old version by Emile. The one below seems to work fine
 *  and should be faster because it does not remove/insert. Just in case
 *  my version doesn't work I'll leave the old one in.
 *    -- Richard, 6/2/2004
 *
 *	GtkCTreeNode *n1;
 *
 *	n1 = g_array_index(array, GtkCTreeNode *, i1);
 *	g_array_remove_index(array, i1);
 *	g_array_insert_val(array, i1, g_array_index(array, GtkCTreeNode *, i2));
 *	g_array_remove_index(array, i2);
 *	g_array_insert_val(array, i2, n1);
*/
    GtkCTreeNode *buf;

    buf = g_array_index(array, GtkCTreeNode *, i1);
    g_array_index(array, GtkCTreeNode *, i1) =
		g_array_index(array, GtkCTreeNode *, i2);
    g_array_index(array, GtkCTreeNode *, i2) = buf;
}

/**
 * Performs a recursive quick sort on the given array between indicies
 * beg and end.
 *
 * @note
 * This is extremely time critical code, some code duplication is
 * intentional.
 */
void
search_gui_quick_sort(GArray *array, gint beg, gint end,
	GtkCTree *ctree, gboolean ascending, gint sort_col)
{
	gui_record_t *pivot_record;
    GtkCTreeNode *pivot_node;
    gint pivot_index;

    /* terminate recursion */
	if (beg >= end)
		return;

	/** Choose the item in the middle for the pivot, swap it to the end */
	search_gui_quick_sort_array_swap(array, end, (beg + end) / 2);

    /* Fetch the value of the pivot element for later comparison */
    pivot_node   = g_array_index(array, GtkCTreeNode *, end);
	pivot_record = gtk_ctree_node_get_row_data(ctree, pivot_node);

    pivot_index = beg;

	if (ascending) {
        gint i;
        gint result;
        gui_record_t *ri;

        /* only go up to the second last element as the last is the pivot */
	    for (i = beg; i < end; i++) {

			ri = gtk_ctree_node_get_row_data(ctree,
				g_array_index(array, GtkCTreeNode *, i));
			result = search_gui_compare_records(sort_col, pivot_record, ri);

            /* if current record value is greater then pivot value... */
			if (result > 0) {
				search_gui_quick_sort_array_swap(array, pivot_index, i);
                pivot_index ++;
            }
		}
	} else {
        gint i;
        gint result;
        gui_record_t *ri;

	    for (i = beg; i < end; i++) {

			ri = gtk_ctree_node_get_row_data(ctree,
				g_array_index(array, GtkCTreeNode *, i));
			result = search_gui_compare_records(sort_col, pivot_record, ri);

			if (result < 0) {
				search_gui_quick_sort_array_swap(array, pivot_index, i);
                pivot_index ++;
            }
		}
	}


	/** move pivot from end to its final place */
	search_gui_quick_sort_array_swap(array, end, pivot_index);

	search_gui_quick_sort(array, beg, pivot_index - 1, ctree,
		ascending, sort_col);
	search_gui_quick_sort(array, pivot_index + 1, end, ctree,
		ascending, sort_col);
}


/**
 * Analyze the data in the given column to decide what type of search should
 * be performed.  This function detects whether the data is alreadt sorted
 * ascending, descending, appears to be random, is sorting via tha count column,
 * or via the info column.
 */
gint
search_gui_analyze_col_data(GtkCTree *ctree, gint sort_col)
{
	GtkCTreeNode *cur_node;
	GtkCTreeNode *prev_node;
	gboolean ascending = TRUE;
	gboolean descending = TRUE;
	gboolean is_random = FALSE;
	gint i;
	gint result;
	gui_record_t *rcur;
	gui_record_t *rprev;

	if (c_sr_count == sort_col)
		return SEARCH_COL_SORT_DATA_COUNT;

	if (c_sr_info == sort_col)
		return SEARCH_COL_SORT_DATA_INFO;


	prev_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);
	rcur = gtk_ctree_node_get_row_data(ctree, prev_node);

	/* No point anaylzing without enough data */
    /* FIXME: this counts the number of rows, but not the number of top-level
     * nodes. The number can only be seen as an estimation.
     *     -- BLUE 17/01/2004
	 */
	if (50 > g_list_length((GList *) prev_node))
		return SEARCH_COL_SORT_DATA_DEFAULT;

    /*
     * Since the sorting later will also only take place on the top-level
     * nodes, we will only analyze them.
     *    -- BLUE 17/01/2004
     */
	for (
        cur_node = GTK_CTREE_NODE_SIBLING(prev_node), i = 0;
        i < 50 && NULL != cur_node;
        i++, prev_node = cur_node, cur_node = GTK_CTREE_NODE_SIBLING(cur_node)
    ) {

		rprev = rcur;
		rcur = gtk_ctree_node_get_row_data(ctree, cur_node);
		result = search_gui_compare_records(sort_col, rcur, rprev);

		if (0 < result)
			descending = FALSE;

		if (0 > result)
			ascending = FALSE;

		if (!ascending && !descending) {
			is_random = TRUE;
			break;
		}
	}

	if (is_random)
		return SEARCH_COL_SORT_DATA_RANDOM;

	if (ascending)
		return SEARCH_COL_SORT_DATA_SORTED_ASC;

	if (descending)
		return SEARCH_COL_SORT_DATA_SORTED_DES;

	return SEARCH_COL_SORT_DATA_DEFAULT;
}


/**
 *	Sorts the given ctree using a quicksort algorithm.
 *  Theoretically this should be O(nlogn)
 *
 *	The default GtkCTree sort is a mergesort which works fine for small data
 *	sets.  Due to the nature of GtkCTree's and the size of the structures being
 *	passed around, the speed is unacceptable for larger sets (>2000).
 *
 *	We therefore implement an analytical approach to minimize sort times.  We
 *	examine the first few elements of a list and try to determine the nature of
 *	the data set and then choose the best of the following algorithms.
 *
 *	1. Default Mergesort: The built-in merge sort works fine for random sets
 *	of varied data.  eg. Sorting by name after retreiving fresh results.  If the
 *	data seems random and we're not sorting by count or info, we use this
 *	algorithm.
 *
 *	2. Insertion Sort: Performs stunningly on ordered or almost ordered data
 *	with a complexity of about O(n).  Fortunately for us it is a common case.
 *	Users will often sort a column ascending and then resort it descending.
 *	Merge/quicksort do not to so well with ordered data (besides which most of
 *	the work is done already).
 *
 *	3. ??? sort.  The info and count columns contain very few different
 *	elements with a large amount of repetition.  Insertion sort seems to work
 *	acceptably for count, but marginly for the info column.  Quicksort performs
 *  dismally for both info and count.  Probably some sort of pseudeo intelligent
 *  insertion sort will be needed, ie. one that makes an almost ordered list
 *  followed by a cleanup algorithm.
 */
void
search_gui_perform_sort(GtkCTree *ctree, gboolean ascending, gint sort_col)
{
	GtkCTreeNode *cur_node;
	GtkCTreeNode *prev_node = NULL;
	gint n;
	gint col_data;

	/* Nothing to sort */
	if (NULL == GTK_CLIST(ctree)->row_list)
		return;

	col_data = search_gui_analyze_col_data(ctree, sort_col);

	switch (col_data) {

	case SEARCH_COL_SORT_DATA_SORTED_ASC:
	case SEARCH_COL_SORT_DATA_SORTED_DES:
	case SEARCH_COL_SORT_DATA_COUNT:
	case SEARCH_COL_SORT_DATA_INFO:
        /*
         * Use an insertion sort:
         *   O(n) for ordered data,
         *   <O(n*n) for unordered
         */

		cur_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);
        g_assert(NULL == GTK_CTREE_ROW(cur_node)->parent);

		if (NULL != cur_node) {
            GList *temp_list;
            GList *l;

            /*
             * We add 1st node outside of the loop to get rid of
             * N comparisons.
             */
			temp_list = g_list_append(NULL, cur_node);

			/*
			 * Sort into a glist:
			 *   O(n) for ordered data,
			 *  <O(n*n) for unordered data.
			 */

            /*
             * We fetch all the top-level nodes from the tree and using
             * insertion-sort add it to the temp_list.
             */

            /* It is  necessary to interate over the
             * GTK_CTREE_NODE_SIBLINGs here. Using GTK_CTREE_NODE_NEXT
             * doesn't work with fast_move because it also iterates
             * over expanded children.
             *    -- BLUE 17/01/2004
             */

            /* FIXME: It might be possible to use fast_mode only when
             * moving top-level nodes around and also sort the children,
             * or to simply iterate over all nodes (also children), purge
             * the tree content are create it from scratch. How fast would
             * that be? Should be like <O(n^2) for iteration and sorting and
             * O(n) for purging and rebuilding.
             * A couple of other places in the code would need to be changed
             * too (search for GTK_CTREE_NODE_SIBLING).
             *    -- BLUE 17/01/2004
			 */
			for (
				cur_node = GTK_CTREE_NODE_SIBLING(cur_node);
				(NULL != cur_node);
				cur_node = GTK_CTREE_NODE_SIBLING(cur_node)
			) {
				temp_list = search_gui_insert_with_sort(temp_list,
					cur_node, ctree, ascending, sort_col);
			}

			/* Now order the CTree using the list O(n) */
			gtk_clist_freeze(GTK_CLIST(ctree));

			/* We move everything to the top of the old tree, backwards.  This
			 * is because "move" has optimized this way.
			 */
			prev_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);
			for (
                l = g_list_last(temp_list); /* g_list_last is O(n) */
                NULL != l;
				l = g_list_previous(l)
            ) {
                cur_node = l->data;

				if (prev_node == cur_node)
					continue;

				gtk_ctree_fast_move(ctree, cur_node, prev_node);
				prev_node = cur_node;
			}

			gtk_clist_thaw(GTK_CLIST(ctree));

            g_list_free(g_list_first(temp_list)); temp_list = NULL;
		}
		break; /* End of all cases using insertion sort */
	case SEARCH_COL_SORT_DATA_RANDOM:
	case SEARCH_COL_SORT_DATA_DEFAULT: {

		GArray *array = g_array_new(FALSE, FALSE, sizeof(GtkCTreeNode *));

		/* Use a quick sort:  Average of O(nlogn) for random data */

		/*
         * Convert the search tree into an array O(n)... actually only
         * the top-level nodes, otherwise fast_move will fail.
         */
		for (
            cur_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);
			NULL != cur_node;
            cur_node = GTK_CTREE_NODE_SIBLING(cur_node)
        ) {
            g_array_append_val(array, cur_node);
        }

		/* Sort the array O(nlogn) */
		search_gui_quick_sort(
            array, 0, array->len - 1, ctree, ascending, sort_col);

		/* Use the sorted array to sort the ctree widget O(n) */
		gtk_clist_freeze(GTK_CLIST(ctree));
		prev_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);

		for (n = array->len - 1; n >= 0; n--) {
			cur_node = g_array_index(array, GtkCTreeNode *, n);
			gtk_ctree_fast_move(ctree, cur_node, prev_node);
			prev_node = cur_node;
		}
		gtk_clist_thaw(GTK_CLIST(ctree));

		g_array_free(array, TRUE);
		break; /* End of all cases using quicksort */
	}

#if 0
	/* Use GTK's default sort functionality (a merge sort I think) */

		/* set compare function */
		gtk_clist_set_compare_func(GTK_CLIST(ctree),
			search_results_compare_func);

		/* set sort type */
		switch (ascending) {
		case SORT_ASC:
    	   	gtk_clist_set_sort_type(GTK_CLIST(ctree), GTK_SORT_ASCENDING);
        	break;

		case SORT_DESC:
    	   	gtk_clist_set_sort_type(GTK_CLIST(ctree), GTK_SORT_DESCENDING);
        	break;
		}

		gtk_clist_set_sort_column(GTK_CLIST(ctree), sort_col);
	    gtk_ctree_sort_node(ctree, NULL);
		break;
#endif


	default:
        g_assert_not_reached();
	}
}


/**
 * Draws arrows for the given column of the GtkCTree and
 * sorts the contents of the GtkCTree according to the
 * sorting parameters set in search
 */
void
search_gui_sort_column(search_t *search, gint column)
{
    GtkWidget * cw = NULL;
	gboolean ascending = TRUE;

   /* destroy existing arrow */
    if (search->arrow != NULL) {
        gtk_widget_destroy(search->arrow);
        search->arrow = NULL;
    }

    /* create new arrow */
    switch (search->sorting.s_order) {
    case SORT_ASC:
        search->arrow = create_pixmap(gui_main_window(), "arrow_down.xpm");
		ascending = TRUE;
        break;
    case SORT_DESC:
        search->arrow = create_pixmap(gui_main_window(), "arrow_up.xpm");
		ascending = FALSE;
        break;
    case SORT_NONE:
        break;
    default:
        g_assert_not_reached();
    }

    /* display arrow if necessary and set sorting parameters*/
    if (search->sorting.s_order != SORT_NONE) {
        cw = gtk_clist_get_column_widget(GTK_CLIST(search->tree), column);
        if (cw != NULL) {
            gtk_box_pack_start(GTK_BOX(cw), search->arrow,
                               FALSE, FALSE, 0);
            gtk_box_reorder_child(GTK_BOX(cw), search->arrow, 0);
            gtk_widget_show(search->arrow);
        }
		search_gui_perform_sort(GTK_CTREE(search->tree), ascending, column);
        search->sort = TRUE;

	} else {
        search->sort = FALSE;
    }
}

/**
 *	Adds the record to gth GtkCTree for this search.
 *	This is where the search grouping (parenting) is done
 */
void
search_gui_add_record(search_t *sch, record_t *rc, enum gui_color color)
{
	static const gchar empty[] = "";
  	const gchar *titles[c_sr_num];
	gboolean is_parent = FALSE;
	gui_record_t *gui_rc;
	gui_record_t *parent_rc;
	gui_record_t *grc1;
	gui_record_t *grc2;
    struct results_set *rs = rc->results_set;
	GtkCTreeNode *parent;
	GtkCTreeNode *node;
	GtkCTreeNode *cur_node;
	GtkCTreeNode *sibling;
	GtkCTreeNode *auto_node;
	GtkCTreeRow *row;
	GtkCTreeRow	*parent_row;
	GtkCTree *ctree = GTK_CTREE(sch->tree);

	/* Setup text for node. Note only parent nodes will have # and size shown */
	{
		gint i;

		for (i = 0; i < c_sr_num; i++) {
			const gchar *text = empty;

			switch ((enum c_sr_columns) i) {
	 		case c_sr_address:
				text = search_gui_get_address(rs);
				break;
			case c_sr_filename:
				text = lazy_utf8_to_ui_string(rc->utf8_name);
				break;
	 		case c_sr_ext:
				text = rc->ext;
				break;
			case c_sr_mime:
				text = mime_type_to_string(mime_type_from_extension(rc->ext));
				break;
			case c_sr_charset:
				if (!(ST_LOCAL & rs->status))
					text = rc->charset;
				break;
	 		case c_sr_vendor:
				if (!(ST_LOCAL & rs->status))
					text = vendor_code_get_name(rs->vendor);
				break;
	 		case c_sr_info:
				text = rc->info;
				break;
	 		case c_sr_loc:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status))
					text = iso3166_country_cc(rs->country);
				break;
	 		case c_sr_route:
				text = search_gui_get_route(rs);
				break;
			case c_sr_protocol:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status))
					text = ST_UDP & rs->status ?
						(ST_SR_UDP & rs->status ? "UDP (semi-reliable)" : "UDP")
						: "TCP";
				break;
			case c_sr_hops:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status)) {
					static gchar buf[UINT32_DEC_BUFLEN];
					uint32_to_string_buf(rs->hops, buf, sizeof buf);
					text = buf;
				}
				break;
			case c_sr_ttl:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status)) {
					static gchar buf[UINT32_DEC_BUFLEN];
					uint32_to_string_buf(rs->ttl, buf, sizeof buf);
					text = buf;
				}
				break;
			case c_sr_spam:
				if (SR_SPAM & rc->flags) {
					text = "S";	/* Spam */
				} else if (ST_SPAM & rs->status) {
					text = "maybe";	/* maybe spam */
				}
				break;
			case c_sr_owned:
				if (SR_OWNED & rc->flags) {
					text = _("owned");
				} else if (SR_PARTIAL & rc->flags) {
					text = _("partial");
				} else if (SR_SHARED & rc->flags) {
					text = _("shared");
				}
				break;
			case c_sr_hostile:
				if (ST_HOSTILE & rs->status) {
					text = "H";
				}
				break;
			case c_sr_sha1:
				if (rc->sha1) {
					text = sha1_base32(rc->sha1);
				}
				break;
			case c_sr_ctime:
				if ((time_t) -1 != rc->create_time) {
					text = timestamp_to_string(rc->create_time);
				}
				break;
	 		case c_sr_size:
	 		case c_sr_count:
				break;
			case c_sr_num:
				g_assert_not_reached();
				break;
			}
			titles[i] = EMPTY_STRING(text);
		}
	}

	uint32_to_string_buf(rs->speed, tmpstr, sizeof tmpstr);

	/* Add the search result to the ctree */

	/*
	 * Record memory is freed automatically by function set later on using
	 * gtk_ctree_node_set_row_data_full
	 */

	WALLOC(gui_rc);
	gui_rc->shared_record = rc;

	if (NULL != rc->sha1) {

		/*
		 * We use the sch->parents hash table to store pointers to all the
		 * parent tree nodes referenced by their atomized sha1.
		 */
		parent = find_parent_with_sha1(sch, rc->sha1);

		if (NULL != parent) {
			guint count;

			/* A parent exists with that sha1, add as child to that parent */
			node = gtk_ctree_insert_node(ctree, parent, NULL,
						(gchar **) titles, /* override const */
						N_ITEMS(titles), NULL, NULL, NULL, NULL, 0, 0);

			/* Update the "#" column of the parent, +1 for parent */
			count = gtk_ctree_count_node_children(ctree, parent);
			uint32_to_string_buf(count + 1, tmpstr, sizeof tmpstr);
			gtk_ctree_node_set_text(ctree, parent, c_sr_count, tmpstr);

			/* Update count in the records (use for column sorting) */
			gui_rc->num_children = 0;
			parent_rc = gtk_ctree_node_get_row_data(ctree, parent);
			parent_rc->num_children = count;
			is_parent = FALSE;

		} else { /* Add as a parent */
			gconstpointer key;

			key = atom_sha1_get(rc->sha1);	/* New parent, need new atom ref */

			titles[c_sr_size] = short_size(rc->size, show_metric_units());

			/* Add node as a parent */
			node = gtk_ctree_insert_node(ctree, parent = NULL, NULL,
						(gchar **) titles, /* override const */
						N_ITEMS(titles), NULL, NULL, NULL, NULL, 0, 0);
			add_parent_with_sha1(sch, key, node);

			/* Update count in the records (use for column sorting) */
			gui_rc->num_children = 0;
			is_parent = TRUE;
		}

	} else { /* Add node as a parent with no SHA1 */
		titles[c_sr_size] = short_size(rc->size, show_metric_units());

		node = gtk_ctree_insert_node(ctree, parent = NULL, NULL,
					(gchar **) titles, /* override */
					N_ITEMS(titles), NULL, NULL, NULL, NULL, 0, 0);
		/* Update count in the records (use for column sorting) */
		gui_rc->num_children = 0;
		is_parent = TRUE;
	}

	search_gui_ref_record(rc);
    gtk_ctree_node_set_row_data_full(ctree, node, gui_rc,
		search_gui_free_gui_record);

    if (sch->sort) {
		/*
		 * gtk_clist_set_auto_sort() can't work for row data based sorts!
		 * Too bad. The problem is, that our compare callback wants to
         * extract the record from the row data. But since we have not
         * yet added neither the row nor the row data, this does not
         * work.
		 * So we need to find the place to put the result by ourselves.
		 */

		/* If the node added was a child and the column is sorted by count we
		 * have to re-sort the parent node (it's count was just updated)
		 * moving the parent will move the children too so we just pretend that
		 * the parent node was actually the node that was added, not the child.
		 */
		if (!is_parent && (c_sr_count == sch->sorting.s_column)) {
			is_parent = TRUE;
			parent_row = GTK_CTREE_ROW(node);
			auto_node = parent_row->parent;
			grc1 = gtk_ctree_node_get_row_data(GTK_CTREE(sch->tree), auto_node);
		} else {
			auto_node = node;
			grc1 = gui_rc;
		}

		if (is_parent) {
			parent = NULL;
			sibling = NULL;

			/* Traverse the entire search tree */
			for (
                cur_node = GTK_CTREE_NODE(GTK_CLIST(sch->tree)->row_list);
				(NULL != cur_node);
                cur_node = GTK_CTREE_NODE_NEXT (cur_node)
            ) {

				row = GTK_CTREE_ROW(cur_node);

				/* If node is a child node, we skip it */
				if (NULL != row->parent)
					continue;

				grc2 = gtk_ctree_node_get_row_data(ctree, cur_node);

				if (grc1 == grc2)
					continue;

				if (SORT_ASC == sch->sorting.s_order) {
					if (
						search_gui_compare_records(
							sch->sorting.s_column, grc1, grc2) < 0
					) {
						sibling = cur_node;
						break;
					}
				} else { /* SORT_DESC */
					if (
						search_gui_compare_records(
							sch->sorting.s_column, grc1, grc2) > 0
					){
						sibling = cur_node;
						break;
					}
				}
			}

		} else { /* Is a child node */
			row = GTK_CTREE_ROW(auto_node);
			parent = row->parent;
			g_assert(NULL != parent);
			sibling = NULL;

			parent_row = GTK_CTREE_ROW(parent);
			cur_node = parent_row->children; /* start looking at first child */

			for (; NULL != cur_node; row = GTK_CTREE_ROW(cur_node),
					cur_node = row->sibling) {

				grc2 = gtk_ctree_node_get_row_data(ctree, cur_node);

				if (SORT_ASC == sch->sorting.s_order) {
					if (
						search_gui_compare_records(
							sch->sorting.s_column, grc1, grc2) < 0
					){
						sibling = cur_node;
						break;
					}
				} else { /* SORT_DESC */
					if (
						search_gui_compare_records(
							sch->sorting.s_column, grc1, grc2) > 0
					){
						sibling = cur_node;
						break;
					}
				}
			}
		}

		gtk_ctree_move(ctree, auto_node, parent, sibling);
	}

	gtk_ctree_node_set_foreground(ctree, node, gui_color_get(color));
	gtk_ctree_node_set_background(ctree, node,
		gui_color_get(GUI_COLOR_BACKGROUND));
}

/**
 * Removes the given node from the ctree
 */
static void
search_gui_remove_result(struct search *search, GtkCTreeNode *node)
{
	gui_record_t *grc = NULL;
	gui_record_t *parent_grc;
	gui_record_t *child_grc;
	record_t *rc;
	GtkCTree *ctree;
	GtkCTreeRow *row;
	GtkCTreeRow *child_row;
	GtkCTreeNode *child_node;
	GtkCTreeNode *old_parent;
	GtkCTreeNode *old_parent_sibling;
	GtkCTreeNode *child_sibling;
	gint n;

	g_return_if_fail(search);
	g_return_if_fail(search->tree);

	ctree = GTK_CTREE(search->tree);
    g_assert(search->items > 0);
    search->items--;

	/* First get the record, it must be unreferenced at the end */
	grc = gtk_ctree_node_get_row_data(ctree, node);
	rc = grc->shared_record;
	record_check(rc);
	g_assert(rc->refcount > 1);

	row = GTK_CTREE_ROW(node);
	if (NULL == row->parent) {

		/*
         * It has no parents, therefore it must be a parent.
		 * If it has children, then we are removing the parent but not the
		 * children
		 */
		if (NULL != row->children) {
			gconstpointer key;

			/*
             * We move the first child into the position originally occupied
			 * by the parent, then we move all the children of the parent into
			 * that child node (making it a parent).  Finally we delete the
			 * old parent.
			 */

			old_parent = node;
			old_parent_sibling = row->sibling;

			child_node = row->children;	/* The first child of node */
			child_sibling = GTK_CTREE_NODE_SIBLING(child_node);

			gtk_ctree_move(ctree, child_node, NULL, old_parent_sibling);

			while (NULL != child_sibling) {
                GtkCTreeNode *temp_node = child_sibling;

				child_sibling = GTK_CTREE_NODE_SIBLING(child_sibling);
				gtk_ctree_move(ctree, temp_node, child_node, NULL);
			}

			gtk_ctree_remove_node(ctree, old_parent);

			/* Now update the new parent (just promoted from child) */
			child_grc = gtk_ctree_node_get_row_data(ctree, child_node);

			/* Calculate # column */
			n = gtk_ctree_count_node_children(ctree, child_node);
			if (0 < n) {
				uint32_to_string_buf(n + 1, tmpstr, sizeof tmpstr);
			} else {
				*tmpstr = '\0';
            }

			/* Update record count, child_rc will become the rc for the parent*/
			child_grc->num_children = n;

			/* Now actually modify the new parent node */
			gtk_ctree_node_set_text(ctree, child_node,
                c_sr_count, tmpstr);
			gtk_ctree_node_set_text(ctree, child_node,
                c_sr_size, short_size(rc->size, show_metric_units()));

			/* Our hashtable contains the hash for the original parent (which we
			 * just removed) so we must remove that hash entry and create one
			 * for the new parent.
			 */
			remove_parent_with_sha1(search, rc->sha1);
			key = atom_sha1_get(rc->sha1);
			add_parent_with_sha1(search, key, child_node);
		} else {
			/* The row has no children, remove it's sha1 and the row itself */
			if (NULL != rc->sha1)
				remove_parent_with_sha1(search, rc->sha1);

			gtk_ctree_remove_node(ctree, node);
		}
	} else {
		/* It has parents, therefore it's child node. */
		child_row = GTK_CTREE_ROW(node);
		old_parent = child_row->parent;

		/* Now remove the row */
		gtk_ctree_remove_node(ctree, node);


		/* Now update the "#" column of the parent */
		n = gtk_ctree_count_node_children(ctree, old_parent);
		if (0 < n) {
			uint32_to_string_buf(n + 1, tmpstr, sizeof tmpstr);
		} else {
			*tmpstr = '\0';
		}
		gtk_ctree_node_set_text(ctree, old_parent, c_sr_count, tmpstr);

		parent_grc = gtk_ctree_node_get_row_data(ctree, old_parent);
		parent_grc->num_children = n;
	}

	/*
	 * Remove two references to this record.
	 *
	 * One is a gui reference, the other is the dups hash table reference
	 * (Note that GTK2 hashtables allow us to define an auto remove function,
	 *  not so with GTK1, so we have to do it ourselves)
	 */
	hset_remove(search->dups, rc);
	search_gui_unref_record(rc);
	search_gui_unref_record(rc);
}

static gboolean
search_resort_required(struct search *search, GtkCTreeNode *node)
{
	GtkCTreeRow *row;

	/* Check if we should re-sort after we remove the download.
	 * Re-sorting for every remove is too laggy and unnecessary.  If the
	 * search is not sorted by count we don't re-sort.  If the
	 * node is a parent we re-sort if the next node to be removed is not
	 * it's first child.  If the node is a child, we re-sort if the next
	 * node to be removed is not the next sibling.  Finally, we re-sort
	 * if the last child of a tree is selected.
	 *
	 * This assumes that the selection list will be in order, otherwise
	 * it will re-sort on every remove in a tree (although it won't
	 * re-sort for parent nodes with no children).
	 *
	 * We need to check this before we actually remove the node.
	 *
	 * Finally it should only be necessary to determine once
	 * during the walk wether we need to resort and resort at the end.
	 *     -- Richard, 17/04/2004
	 */

	if (c_sr_count != search->sorting.s_column)
		return FALSE;

	row = GTK_CTREE_ROW(node);

#if 0
	if (NULL == row->parent) {
		/* If it's a parent and the first child is not selected */
		if (NULL != row->children) {
			return NULL == sel_list->next ||
				sel_list->next->data != row->children;
		}
	} else {
		/* If it's a child and the next sibling is not selected */
		if (NULL != row->sibling) {
			return NULL == sel_list->next ||
				sel_list->next->data != row->sibling;
		} else {
			/* If it's a child and it has no sibling */
			return TRUE;
		}
	}
	return FALSE;
#endif
	(void) row;		/* #if 0 above */

	return TRUE;
}

/*
 * Collects all selected nodes. If a selected node is a parent and not expanded,
 * all its children are included as well.
 */
static GSList *
selection_of_ctree(GtkCTree *ctree)
{
	GSList *nodes = NULL;
	GList *iter;

	iter = GTK_CLIST(ctree)->selection;
	for (/* NOTHING */; NULL != iter; iter = g_list_next(iter)) {
		GtkCTreeNode *node;

		node = iter->data;
		g_assert(node);

		nodes = g_slist_prepend(nodes, node);

		if (!GTK_CTREE_ROW(node)->expanded) {
			GtkCTreeNode *child;

			for (
				child = GTK_CTREE_ROW(node)->children;
				NULL != child;
				child = GTK_CTREE_NODE_SIBLING(child)
			) {
				nodes = g_slist_prepend(nodes, child);
			}
		}
	}

	return g_slist_reverse(nodes);
}

/**
 * Discard all the search results selected in the ctree.
 *
 * @returns the amount of discarded results.
 */
static guint
discard_selection_of_ctree(struct search *search)
{
	GSList *selection, *iter;
	GtkCTree *ctree;
	gboolean resort = FALSE;
	guint n = 0;

	g_return_val_if_fail(search, 0);
	g_return_val_if_fail(search->tree, 0);

	ctree = GTK_CTREE(search->tree);
	gtk_clist_freeze(GTK_CLIST(ctree));

	gtk_signal_handler_block_by_func(GTK_OBJECT(ctree),
		GTK_SIGNAL_FUNC(on_ctree_search_results_select_row), NULL);

	selection = selection_of_ctree(ctree);
	gtk_clist_unselect_all(GTK_CLIST(ctree));

	/* Normalize the selection by selecting all children of collapsed nodes. */
	for (iter = selection; NULL != iter; iter = g_slist_next(iter)) {
		GtkCTreeNode *node;

		node = iter->data;
		g_assert(node);
		gtk_ctree_select(ctree, node);
	}
	gm_slist_free_null(&selection);

	while (GTK_CLIST(ctree)->selection) {
		GtkCTreeNode *node;
		gui_record_t *grc;

		node = GTK_CLIST(ctree)->selection->data;
		g_assert(node);
		gtk_ctree_unselect(ctree, node);

		grc = gtk_ctree_node_get_row_data(ctree, node);
		g_assert(grc);

		resort = resort || search_resort_required(search, node);
		search_gui_remove_result(search, node);
		n++;
	}

	if (resort) {
		search_gui_sort_column(search, search->sorting.s_column);
	}

	gtk_signal_handler_unblock_by_func(GTK_OBJECT(ctree),
		GTK_SIGNAL_FUNC(on_ctree_search_results_select_row), NULL);

	gtk_clist_thaw(GTK_CLIST(ctree));
	return n;
}

/**
 * Create downloads for all the search results selected in the ctree.
 *
 * @returns the amount of downloads actually created, and the amount of
 * items in the selection within `selected'.
 */
static unsigned
download_selection_of_ctree(struct search *search)
{
	GSList *selection, *iter;
	GtkCTree *ctree;
    gboolean remove_downloaded;
	guint n = 0;

	g_return_val_if_fail(search, 0);
	g_return_val_if_fail(search->tree, 0);

    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED,
		&remove_downloaded);

	ctree = GTK_CTREE(search->tree);
	gtk_clist_freeze(GTK_CLIST(ctree));
	selection = selection_of_ctree(ctree);

	for (iter = selection; NULL != iter; iter = g_slist_next(iter)) {
		GtkCTreeNode *node;
		gui_record_t *grc;

		node = iter->data;
		g_assert(node);

		grc = gtk_ctree_node_get_row_data(ctree, node);
		g_assert(grc);

		search_gui_download(grc->shared_record, search->search_handle);
		n++;

        if (!remove_downloaded) {
            /* make it visibile that we already selected this for download */
            gtk_ctree_node_set_foreground(ctree, node,
				gui_color_get(GUI_COLOR_DOWNLOADING));
        }
	}
	gm_slist_free_null(&selection);

	if (remove_downloaded) {
		discard_selection_of_ctree(search);
	}
	gtk_clist_thaw(GTK_CLIST(ctree));

	return n;
}

/**
 *	Download selected files
 */
void
search_gui_download_files(struct search *search)
{
	unsigned created;

	g_return_if_fail(search);

	created = download_selection_of_ctree(search);
	gtk_clist_unselect_all(GTK_CLIST(search->tree));

	statusbar_gui_message(15,
		NG_("Created %u download", "Created %u downloads", created),
		created);
}

/**
 *	Discard selected files
 */
void
search_gui_discard_files(struct search *search)
{
	unsigned discarded;

	discarded = discard_selection_of_ctree(search);
	gtk_clist_unselect_all(GTK_CLIST(search->tree));

	statusbar_gui_message(15,
		NG_("Discarded %u result", "Discarded %u results", discarded),
		discarded);
}

struct synchronize_search_list {
	GtkCList *clist;
	int row;
};

static search_t *
synchronize_search_list_callback(void *user_data)
{
	struct synchronize_search_list *ctx = user_data;
	void *data;

	data = gtk_clist_get_row_data(ctx->clist, ctx->row);
	g_assert(data);
	ctx->row++;
	return data;
}

static void
search_gui_synchronize_list(GtkCList *clist)
{
	struct synchronize_search_list ctx;

	ctx.clist = clist;
	ctx.row = 0;
	search_gui_synchronize_search_list(synchronize_search_list_callback, &ctx);
}

static void
on_search_list_row_move_event(GtkCList *clist,
	gint unused_from, gint unused_to, gpointer unused_udata)
{
	(void) unused_udata;
	(void) unused_from;
	(void) unused_to;

	search_gui_synchronize_list(clist);
}

/***
 *** Public functions
 ***/

void G_COLD
search_gui_init(void)
{
	{
		GtkCList *clist = clist_search();

		gtk_clist_set_reorderable(clist, TRUE);
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		widget_add_popup_menu(GTK_WIDGET(clist),
			search_gui_get_search_list_popup_menu);
		gui_signal_connect_after(clist, "row-move",
			on_search_list_row_move_event, NULL);
		gui_signal_connect(clist,
			"button-release-event", on_search_list_button_release_event, NULL);
		gui_signal_connect(clist,
			"key-release-event", on_search_list_key_release_event, NULL);
		clist_restore_widths(clist, PROP_SEARCH_LIST_COL_WIDTHS);
	}

	{
		GtkCList *clist;

		clist = GTK_CLIST(gui_main_window_lookup("clist_search_details"));
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_SINGLE);
		gui_signal_connect(clist, "key-press-event",
			on_search_details_key_press_event, NULL);
		clipboard_attach(GTK_WIDGET(clist));
		drag_attach_text(GTK_WIDGET(clist), search_gui_details_get_text);
	}

	search_gui_common_init();
}

void G_COLD
search_gui_shutdown(void)
{
	GtkCList *clist = clist_search();

	clist_save_widths(clist, PROP_SEARCH_LIST_COL_WIDTHS);
	search_gui_common_shutdown();
}

/**
 * Remove the search from the gui and update all widgets accordingly.
 */
void
search_gui_remove_search(search_t *sch)
{
	g_return_if_fail(sch);

	if (search_gui_get_current_search() == sch) {
		GtkCList *clist = GTK_CLIST(sch->tree);

		clist_save_visibility(clist, PROP_SEARCH_RESULTS_COL_VISIBLE);
		clist_save_widths(clist, PROP_SEARCH_RESULTS_COL_WIDTHS);
	}

	gtk_clist_remove(clist_search(),
		gtk_clist_find_row_from_data(clist_search(), sch));

    /* remove column header arrow if it exists */
    if (sch->arrow) {
        gtk_widget_destroy(sch->arrow);
        sch->arrow = NULL;
    }
}

static void
search_gui_set_search_list_cursor(struct search *search)
{
	GtkCList *clist;
	int row;

	g_return_if_fail(search);

	clist = clist_search();
	row = gtk_clist_find_row_from_data(clist, search);
	if (GTK_VISIBILITY_FULL != gtk_clist_row_is_visible(clist, row)) {
		gtk_clist_moveto(clist, row, 0, 0.0, 0.0);
	}
}

void
search_gui_hide_search(struct search *search)
{
	GtkCList *clist;

	g_return_if_fail(search);

	clist = GTK_CLIST(search->tree);
	clist_save_visibility(clist, PROP_SEARCH_RESULTS_COL_VISIBLE);
	clist_save_widths(clist, PROP_SEARCH_RESULTS_COL_WIDTHS);
}

void
search_gui_show_search(struct search *search)
{
	GtkCList *clist;

	g_return_if_fail(search);

	clist = GTK_CLIST(search->tree);
	clist_restore_visibility(clist, PROP_SEARCH_RESULTS_COL_VISIBLE);
	clist_restore_widths(clist, PROP_SEARCH_RESULTS_COL_WIDTHS);
	gtk_widget_set_sensitive(gui_main_window_lookup("button_search_download"),
		NULL != clist->selection);
	search_gui_set_search_list_cursor(search);
}

/**
 *	Create a new GtkCTree for search results
 */
GtkWidget *
search_gui_create_tree(void)
{
    GtkCList *ctree;
	guint i;

	ctree = GTK_CLIST(gtk_ctree_new(c_sr_num, 0));

	gtk_clist_set_selection_mode(ctree, GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(ctree);

	for (i = 0; i < c_sr_num; i++) {
    	gtk_clist_set_column_justification(ctree, i,
			search_gui_column_justify_right(i)
				 ? GTK_JUSTIFY_RIGHT
				 : GTK_JUSTIFY_LEFT);
	}

	for (i = 0; i < c_sr_num; i++) {
		GtkWidget *label, *hbox;
		const gchar *title;

		title = search_gui_column_title(i);
		label = gtk_label_new(title);
    	gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    	hbox = gtk_hbox_new(FALSE, 4);
    	gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
		gtk_clist_set_column_widget(ctree, i, hbox);
    	gtk_widget_show_all(hbox);
    	gtk_clist_set_column_name(ctree, i, deconstify_gchar(title));
	}

	clist_restore_visibility(ctree, PROP_SEARCH_RESULTS_COL_VISIBLE);
	clist_restore_widths(ctree, PROP_SEARCH_RESULTS_COL_WIDTHS);

	gui_signal_connect(ctree,
		"tree_select_row", on_ctree_search_results_select_row, NULL);
	gui_signal_connect(ctree,
		"click_column", on_clist_search_results_click_column, NULL);

	return GTK_WIDGET(ctree);
}

/**
 * Set proper search color in list depending on whether it is enabled.
 */
static void
search_gui_set_search_list_color(const struct search *search, int row)
{
	GtkStyle *style;
	GdkColor *fg, *bg;

	style = gtk_widget_get_style(GTK_WIDGET(clist_search()));
	if (search->unseen_items > 0) {
		fg = &style->fg[GTK_STATE_ACTIVE];
		bg = &style->bg[GTK_STATE_ACTIVE];
	} else if (search_gui_is_enabled(search)) {
		fg = NULL;
		bg = NULL;
	} else {
		fg = &style->fg[GTK_STATE_INSENSITIVE];
		bg = &style->bg[GTK_STATE_INSENSITIVE];
	}

	gtk_clist_set_foreground(clist_search(), row, fg);
	gtk_clist_set_background(clist_search(), row, bg);
}

void
search_gui_update_list_label(const struct search *search)
{
	if (search) {
		int row;

		row = gtk_clist_find_row_from_data(clist_search(),
				deconstify_gpointer(search));
		gtk_clist_set_text(clist_search(), row, c_sl_hit,
				uint32_to_string(search->items));
		gtk_clist_set_text(clist_search(), row, c_sl_new,
				uint32_to_string(search->unseen_items));
		search_gui_set_search_list_color(search, row);
	}
}

/**
 *	Expand all nodes in tree for current search
 */
void
search_gui_expand_all(struct search *search)
{
	if (search) {
		gtk_ctree_expand_recursive(GTK_CTREE(search->tree), NULL);
	}
}


/**
 *	Expand all nodes in tree for current search
 */
void
search_gui_collapse_all(struct search *search)
{
	if (search) {
		gtk_ctree_collapse_recursive(GTK_CTREE(search->tree), NULL);
	}
}

bool
search_gui_start_massive_update(struct search *search)
{
	g_return_val_if_fail(search, FALSE);

	if (search->frozen)
		return FALSE;

	gtk_clist_freeze(GTK_CLIST(search->tree));
	search->frozen = TRUE;
	return TRUE;
}

void
search_gui_end_massive_update(struct search *search)
{
	g_return_if_fail(search);
	g_return_if_fail(search->frozen);

	search->frozen = FALSE;
	gtk_clist_thaw(GTK_CLIST(search->tree));
}

record_t *
search_gui_record_get_parent(search_t *search, record_t *record)
{
	g_return_val_if_fail(search, NULL);
	g_return_val_if_fail(record, NULL);
	record_check(record);

	if (record->sha1) {
		GtkCTreeNode *parent;
		gui_record_t *grc;

		parent = find_parent_with_sha1(search, record->sha1);
		if (parent) {
			grc = gtk_ctree_node_get_row_data(GTK_CTREE(search->tree), parent);
			return grc->shared_record;
		}
	}
	return record;
}

GSList *
search_gui_record_get_children(search_t *search, record_t *record)
{
	GtkCTreeNode *parent;
	GSList *children = NULL;

	g_return_val_if_fail(search, NULL);
	g_return_val_if_fail(record, NULL);
	record_check(record);

	parent = record->sha1 ? find_parent_with_sha1(search, record->sha1) : NULL;
	if (parent) {
		GtkCTreeNode *node;
		GtkCTreeRow *row;

		row = GTK_CTREE_ROW(parent);
		for (node = row->children; NULL != node; node = row->sibling) {
			gui_record_t *grc;

			row = GTK_CTREE_ROW(node);
			grc = gtk_ctree_node_get_row_data(GTK_CTREE(search->tree), node);
			children = g_slist_prepend(children, grc->shared_record);
		}
	}
	return g_slist_reverse(children);
}

GSList *
search_gui_get_selected_searches(void)
{
	GSList *sl = NULL;
    GtkCList *clist;
	GList *selection;

    clist = clist_search();
	selection = GTK_CLIST(clist)->selection;

	for (/* NOTHING */; selection; selection = g_list_next(selection)) {
    	search_t *search;
		gint row;

		row = GPOINTER_TO_UINT(selection->data);
		if (row < 0)
			break;

    	search = gtk_clist_get_row_data(clist, row);
		if (!search)
			break;

		sl = g_slist_prepend(sl, search);
	}
	return sl;
}

gboolean
search_gui_has_selected_item(search_t *search)
{
	g_return_val_if_fail(search, FALSE);
	return NULL != GTK_CLIST(search->tree)->selection;
}

void
search_gui_search_list_clicked(void)
{
	int row;

	row = clist_get_cursor_row(clist_search());
	if (row >= 0) {
		search_t *search;

		search = gtk_clist_get_row_data(clist_search(), row);
		g_return_if_fail(search);

		search_gui_set_current_search(search);
	}
}

void
search_gui_flush_queues(void)
{
		/* TODO: Implement this */
}

unsigned
search_gui_queue_length(const struct search *search)
{
	g_return_val_if_fail(search, 0);
	/* TODO: Implement this */
	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
