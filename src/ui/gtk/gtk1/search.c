/*
 * $Id$
 *
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
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "common.h"

#include "gtk/gui.h"
#include "gtk/bitzi.h"
#include "gtk/search.h"
#include "gtk/gtk-missing.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"
#include "gtk/columns.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "search_cb.h"

#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"
#include "if/core/sockets.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/glib-missing.h"
#include "lib/iso3166.h"
#include "lib/misc.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

RCSID("$Id$")

static gchar tmpstr[4096];

static GList *searches = NULL;		/* List of search structs */

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


/*
 * Private function prototypes
 */
#if 0
static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2);
#endif
static void set_search_color(struct search *sch);
static void gui_search_create_ctree(GtkWidget ** sw, GtkCTree ** ctree);
static void search_gui_init_dnd(GtkCTree *ctree);

/*
 * If no searches are currently allocated
 */
GtkCTree *default_search_ctree = NULL;
static GtkWidget *default_scrolled_window = NULL;


/* ----------------------------------------- */


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
add_parent_with_sha1(GHashTable *ht, const gchar *sha1,
	GtkCTreeNode *data)
{
	gm_hash_table_insert_const(ht, sha1, data);
}


/**
 *	Removes the tree node matching the given sha1 from the hash table.
 *  The atom used for the key is then freed
 */
static inline void
remove_parent_with_sha1(GHashTable *ht, const gchar *sha1)
{
	gconstpointer key;
	gpointer orig_key;

	key = atom_sha1_get(sha1);

	if (g_hash_table_lookup_extended(ht, key, &orig_key, NULL)) {
		/* Must first free memory used by the original key */
		atom_sha1_free(orig_key);

		/* Then remove the key */
		g_hash_table_remove(ht, key);
	} else
		g_warning("remove_parent_with_sha1: can't find sha1 in hash table!");

	atom_sha1_free(key);
}


/**
 *	@returns the tree node corresponding to the given key, an atomized
 *	sha1.
 */
GtkCTreeNode *
find_parent_with_sha1(GHashTable *ht, gconstpointer key)
{
	return g_hash_table_lookup(ht, key);
}

gboolean
search_gui_free_parent(gpointer key, gpointer unused_value, gpointer unused_x)
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
 * Reset the internal model of the search.
 * Called when a search is restarted, for example.
 */
void
search_gui_reset_search(search_t *sch)
{
	search_gui_clear_search(sch);
}

/**
 * Decrement refcount of hash table key entry.
 */
static gboolean
dec_records_refcount(gpointer key, gpointer unused_value, gpointer unused_x)
{
	struct record *rc = (struct record *) key;

	(void) unused_value;
	(void) unused_x;
	g_assert(rc->refcount > 0);

	rc->refcount--;
	return TRUE;
}

/**
 *	Removes a reference to the record stored in the given tree node
 */
void
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

	/*
	 * Before invoking search_free_r_sets(), we must iterate on the
	 * hash table where we store records and decrement the refcount of
	 * each record, and remove them from the hash table.
	 *
	 * Otherwise, we will violate the pre-condition of search_free_record(),
	 * which is there precisely for that reason!
	 */
	search_gui_clear_ctree(sch->tree);
	g_hash_table_foreach_remove(sch->dups, dec_records_refcount, NULL);
	g_hash_table_foreach_remove(sch->parents, search_gui_free_parent, NULL);
	search_gui_free_r_sets(sch);

	sch->items = sch->unseen_items = 0;
	guc_search_update_items(sch->search_handle, sch->items);
}


/**
 * Remove the search from the list of searches and free all
 * associated ressources (including filter and gui stuff).
 */
void
search_gui_close_search(search_t *sch)
{
    g_assert(sch != NULL);

    /*
     * We remove the search immeditaly from the list of searches,
     * because some of the following calls (may) depend on
     * "searches" holding only the remaining searches.
     * We may not free any ressources of "sch" yet, because
     * the same calls may still need them!.
     *      --BLUE 26/05/2002
     */
 	searches = g_list_remove(searches, sch);
	search_gui_option_menu_searches_update();

	search_gui_clear_search(sch);
    search_gui_remove_search(sch);
	filter_close_search(sch);

	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;
	g_hash_table_destroy(sch->parents);
	sch->parents = NULL;

    guc_search_close(sch->search_handle);
	atom_str_free(sch->query);

	g_free(sch);
}

/**
 * Create a new search and start it.
 *
 * @returns TRUE if search was sucessfully created and FALSE if an error
 * happened. If the "search" argument is not NULL a pointer to the new
 * search is stored there.
 */
gboolean
search_gui_new_search_full(const gchar *query_str,
	time_t create_time, guint lifetime, guint32 reissue_timeout,
	gint sort_col, gint sort_order, flag_t flags, search_t **search)
{
    GtkWidget *clist_search = gui_main_window_lookup("clist_search");
    GtkWidget *notebook_search_results =
        gui_main_window_lookup("notebook_search_results");
    GtkWidget *button_search_close =
        gui_main_window_lookup("button_search_close");
    const gchar *titles[c_sl_num];
    const gchar *error_str;
	struct query *query;
    search_t *sch;
	gnet_search_t sch_id;
    gint row;
	gboolean is_only_search = FALSE;

	query = search_gui_handle_query(query_str, flags, &error_str);
	if (query || !error_str) {
		gtk_entry_set_text(
				GTK_ENTRY(gui_main_window_lookup("entry_search")), "");
	}
	if (!query) {
		if (error_str) {
			statusbar_gui_warning(5, "%s", error_str);
		}
		return FALSE;
	}
	g_assert(query);
	g_assert(query->text);

    sch_id = guc_search_new(query->text, create_time, lifetime,
				reissue_timeout, flags);
	if ((gnet_search_t) -1 == sch_id) {
		statusbar_gui_warning(5, "%s", _("Failed to create the search"));
		return FALSE;
	}

	sch = g_malloc0(sizeof *sch);

	if (sort_col >= 0 && (guint) sort_col < SEARCH_RESULTS_VISIBLE_COLUMNS)
		sch->sort_col = sort_col;
	else
		sch->sort_col = SORT_NO_COL;

	switch (sort_order) {
	case SORT_ASC:
	case SORT_DESC:
		sch->sort_order = sort_order;
		break;
	default:
		sch->sort_order = SORT_NONE;
	}

	sch->query = atom_str_get(query->text);
	sch->enabled = (flags & SEARCH_F_ENABLED) ? TRUE : FALSE;
	sch->browse = (flags & SEARCH_F_BROWSE) ? TRUE : FALSE;
	sch->local = (flags & SEARCH_F_LOCAL) ? TRUE : FALSE;
    sch->search_handle = sch_id;
    sch->passive = (flags & SEARCH_F_PASSIVE) ? TRUE : FALSE;
	sch->dups = g_hash_table_new(search_gui_hash_func,
					search_gui_hash_key_compare);

	sch->parents = g_hash_table_new(NULL, NULL);

	search_gui_filter_new(sch, query->rules);

    titles[c_sl_name] = lazy_utf8_to_ui_string(sch->query);
    titles[c_sl_hit] = "0";
    titles[c_sl_new] = "0";
    row = gtk_clist_append(GTK_CLIST(clist_search), (gchar **) titles);
    gtk_clist_set_row_data(GTK_CLIST(clist_search), row, sch);

	/* Create a new ctree if needed, or use the default ctree */

	if (searches) {
		/* We have to create a new ctree for this search */
		gui_search_create_ctree(&sch->scrolled_window, &sch->tree);
		gtk_object_set_user_data(GTK_OBJECT(sch->scrolled_window), sch);
		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
								 sch->scrolled_window, NULL);
	} else {
		/* There are no searches currently, we can use the default ctree */
		if (default_scrolled_window && default_search_ctree) {
			sch->scrolled_window = default_scrolled_window;
			sch->tree = default_search_ctree;

			default_search_ctree = NULL;
			default_scrolled_window = NULL;
		} else
			g_warning("search_gui_new_search_full(): "
				"No current search but no default ctree !?");

		gtk_object_set_user_data(GTK_OBJECT(sch->scrolled_window), sch);
	}

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(TAB_UPDATE_TIME * 1000,
        (GtkFunction)gui_search_update_tab_label, sch);

    if (!searches) {
        GtkWidget *w;
	   
		w = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook_search_results), 0);
		gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook_search_results),
            w, _("(no search)"));
    }

	search_gui_sort_column(sch, sort_col);
	
	gtk_widget_set_sensitive(button_search_close, TRUE);
    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_search_expand_all"), TRUE);
    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_search_collapse_all"), TRUE);

	is_only_search = (searches == NULL);
	searches = g_list_append(searches, sch);
	search_gui_option_menu_searches_update();
	
	if (search_gui_update_expiry(sch))
		sch->enabled = FALSE;

	if (sch->enabled)
		guc_search_start(sch->search_handle);

	/*
	 * Make new search the current search, unless it's a browse-host search:
	 * we need to initiate the download and only if everything is OK will
	 * we move to the newly created search.
	 *
	 * If the browse host is the only search in the list, it must be made
	 * the current search though, since the code relies on one always being
	 * set when the list of searches is not empty.
	 */
	if (is_only_search || (!sch->browse && search_jump_to_created)) {
		search_gui_set_current_search(sch);
	} else {
		gui_search_force_update_tab_label(sch);
	}
	if (search) {
		*search = sch;
	}
	search_gui_query_free(&query);
	if (sch->local) {
		search_gui_init_dnd(GTK_CTREE(sch->tree));
	}
	set_search_color(sch);
	
	return TRUE;
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
        case c_sr_filename:
			if (search_sort_casesense) {
            	result = strcmp(r1->utf8_name, r2->utf8_name);
			} else {
            	result = ascii_strcasecmp(r1->utf8_name, r2->utf8_name);
			}
            break;

        case c_sr_ext:
            result = strcmp(EMPTY_STRING(r1->ext), EMPTY_STRING(r2->ext));
            break;

        case c_sr_charset:
            result = strcmp(r1->charset, r2->charset);
            break;

        case c_sr_size:
			/*
			 * Sort by size, then by identical SHA1.
			 */
			if (r1->size == r2->size)
            	result = search_gui_cmp_sha1s(r1->sha1, r2->sha1);
			else
				result = (r1->size > r2->size) ? +1 : -1;
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

        case c_sr_meta:
			break;				/* XXX Can't sort, metadata not in record! */
			
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
	gtk_clist_sort(GTK_CLIST(ctree));
#if 0	
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
#endif
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
    switch (search->sort_order) {
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
    if (search->sort_order != SORT_NONE) {
        cw = gtk_clist_get_column_widget(GTK_CLIST(search->tree), column);
        if (cw != NULL) {
            gtk_box_pack_start(GTK_BOX(cw), search->arrow,
                               FALSE, FALSE, 0);
            gtk_box_reorder_child(GTK_BOX(cw), search->arrow, 0);
            gtk_widget_show(search->arrow);
        }
		search_gui_perform_sort(search->tree, ascending, column);
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
			case c_sr_filename:
				text = lazy_utf8_to_ui_string(rc->utf8_name);
				break;
	 		case c_sr_ext:
				text = EMPTY_STRING(rc->ext);
				break;
			case c_sr_charset:
				if (!(ST_LOCAL & rs->status))
					text = rc->charset;
				break;
	 		case c_sr_info:
				text = EMPTY_STRING(rc->info);
				break;
	 		case c_sr_loc:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status))
					text = iso3166_country_cc(rs->country);
				break;
	 		case c_sr_route:
				text = EMPTY_STRING(search_gui_get_route(rc));
				break;
			case c_sr_protocol:
				if (!((ST_LOCAL | ST_BROWSE) & rs->status))
					text = ST_UDP & rs->status ? "UDP" : "TCP";
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
			case c_sr_meta:
	 		case c_sr_size:
	 		case c_sr_count:
				break;
			case c_sr_num:
				g_assert_not_reached();
				break;
			}
			titles[i] = text;
		}
	}

	uint32_to_string_buf(rs->speed, tmpstr, sizeof tmpstr);

	/* Add the search result to the ctree */

	/* Record memory is freed automatically by function set later on using
	 * gtk_ctree_node_set_row_data_full
	 */
	gui_rc = walloc(sizeof *gui_rc);
	gui_rc->shared_record = rc;

	if (NULL != rc->sha1) {

		/* We use the sch->parents hash table to store pointers to all the
		 * parent tree nodes referenced by their atomized sha1.
		 */
		parent = find_parent_with_sha1(sch->parents, rc->sha1);

		if (NULL != parent) {
			guint count;

			/* A parent exists with that sha1, add as child to that parent */
			node = gtk_ctree_insert_node(ctree, parent, NULL,
						(gchar **) titles, /* override const */
						G_N_ELEMENTS(titles), NULL, NULL, NULL, NULL, 0, 0);

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
						G_N_ELEMENTS(titles), NULL, NULL, NULL, NULL, 0, 0);
			add_parent_with_sha1(sch->parents, key, node);

			/* Update count in the records (use for column sorting) */
			gui_rc->num_children = 0;
			is_parent = TRUE;
		}

	} else { /* Add node as a parent with no SHA1 */
		titles[c_sr_size] = short_size(rc->size, show_metric_units());

		node = gtk_ctree_insert_node(ctree, parent = NULL, NULL,
					(gchar **) titles, /* override */
					G_N_ELEMENTS(titles), NULL, NULL, NULL, NULL, 0, 0);
		/* Update count in the records (use for column sorting) */
		gui_rc->num_children = 0;
		is_parent = TRUE;
	}

	search_gui_ref_record(rc);
    gtk_ctree_node_set_row_data_full(ctree, node, (gpointer) gui_rc,
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
		if (!is_parent && (c_sr_count == sch->sort_col)) {
			is_parent = TRUE;
			parent_row = GTK_CTREE_ROW(node);
			auto_node = parent_row->parent;
			grc1 = gtk_ctree_node_get_row_data(sch->tree, auto_node);
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

				if (SORT_ASC == sch->sort_order) {
 	            	if (search_gui_compare_records(sch->sort_col, grc1, grc2) < 0){
						sibling = cur_node;
						break;
					}
				} else { /* SORT_DESC */
					if (search_gui_compare_records(sch->sort_col, grc1, grc2) > 0){
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

				if (SORT_ASC == sch->sort_order) {
 	            	if (search_gui_compare_records(sch->sort_col, grc1, grc2) < 0){
						sibling = cur_node;
						break;
					}
				} else { /* SORT_DESC */
					if (search_gui_compare_records(sch->sort_col, grc1, grc2) > 0){
						sibling = cur_node;
						break;
					}
				}
			}
		}

		gtk_ctree_move(ctree, auto_node, parent, sibling);
	}

	gtk_ctree_node_set_foreground(ctree, node, gui_color_get(color));
}


void
search_gui_set_clear_button_sensitive(gboolean flag)
{
	gtk_widget_set_sensitive(gui_main_window_lookup("button_search_clear"),
		flag);
}


/* ----------------------------------------- */


/**
 * Removes the given node from the ctree
 */
static void
search_gui_remove_result(GtkCTree *ctree, GtkCTreeNode *node)
{
	gui_record_t *grc = NULL;
	gui_record_t *parent_grc;
	gui_record_t *child_grc;
	record_t *rc;
	GtkCTreeRow *row;
	GtkCTreeRow *child_row;
	GtkCTreeNode *child_node;
	GtkCTreeNode *old_parent;
	GtkCTreeNode *old_parent_sibling;
	GtkCTreeNode *child_sibling;
	gint n;

	search_t *current_search = search_gui_get_current_search();
    current_search->items--;

	/* First get the record, it must be unreferenced at the end */
	grc = gtk_ctree_node_get_row_data(ctree, node);
	rc = grc->shared_record;

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
			remove_parent_with_sha1(current_search->parents, rc->sha1);
			key = atom_sha1_get(rc->sha1);
			add_parent_with_sha1(current_search->parents, key, child_node);


		} else {
			/* The row has no children, remove it's sha1 and the row itself */
			if (NULL != rc->sha1)
				remove_parent_with_sha1(current_search->parents, rc->sha1);

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
	g_hash_table_remove(current_search->dups, rc);
	search_gui_unref_record(rc);
	search_gui_unref_record(rc);
}


/**
 * Create downloads for all the search results selected in the ctree.
 *
 * @returns the amount of downloads actually created, and the amount of
 * items in the selection within `selected'.
 */
static guint
download_selection_of_ctree(GtkCTree *ctree, guint *selected)
{
	struct results_set *rs;
	gui_record_t *grc;
	record_t *rc;
	GList *sel_list;
    gboolean remove_downloaded;
	gboolean resort = FALSE;
	guint created = 0;
	guint count = 0;
	GtkCTreeNode *node;
	GtkCTreeRow *row;
	search_t *current_search = search_gui_get_current_search();

    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED,
		&remove_downloaded);

	gtk_clist_freeze(GTK_CLIST(ctree));

	/* Selection list changes after we process each selected node, so we have to
	 * "re-get" it each iteration.
	 */
	for (
		sel_list = GTK_CLIST(ctree)->selection;
		sel_list != NULL;
		sel_list = GTK_CLIST(ctree)->selection
	) {
		guint32 flags = 0;

		node = sel_list->data;
		if (NULL == node)
			break;

		count++;

		grc = gtk_ctree_node_get_row_data(ctree, node);
		rc = grc->shared_record;

        if (!rc) {
			g_warning("download_selection_of_ctree(): row has NULL data");
			continue;
        }

		rs = rc->results_set;
		flags |= (rs->status & ST_FIREWALL) ? SOCK_F_PUSH : 0;
		flags |= (rs->status & ST_TLS) ? SOCK_F_TLS : 0;

		if (guc_download_new(rc->name, rc->size, rc->file_index,
				rs->addr, rs->port, rs->guid, rs->hostname,
				rc->sha1, rs->stamp, NULL, rs->proxies, flags)
		) {
			created++;
		}

		if (rs->proxies != NULL)
			search_gui_free_proxies(rs);

		if (rc->alt_locs != NULL)
			search_gui_check_alt_locs(rs, rc);

        if (remove_downloaded) {
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

			if (!resort && c_sr_count == current_search->sort_col) {
				row = GTK_CTREE_ROW(node);

				if (NULL == row->parent) {
					/* If it's a parent and the first child is not selected */
					if (NULL != row->children) {
						if (NULL == sel_list->next)
							resort = TRUE;
						else if (sel_list->next->data != row->children)
								resort = TRUE;
					}
				} else {
					/* If it's a child and the next sibling is not selected */
					if (NULL != row->sibling) {
						if (NULL == sel_list->next)
							resort = TRUE;
						else if (sel_list->next->data != row->sibling)
								resort = TRUE;
					}

					/* If it's a child and it has no sibling */
					if (NULL == row->sibling)
						resort = TRUE;
				}
			}

			search_gui_remove_result(ctree, node);
		} else {
            /* make it visibile that we already selected this for download */
            gtk_ctree_node_set_foreground(ctree, node,
                &gtk_widget_get_style(
                    GTK_WIDGET(ctree))->fg[GTK_STATE_ACTIVE]);
			gtk_ctree_unselect(ctree, node);
        }
	}

	if (resort) {
		search_gui_sort_column(current_search, current_search->sort_col);
	}

	gtk_clist_unselect_all(GTK_CLIST(ctree));
	gtk_clist_thaw(GTK_CLIST(ctree));

    gui_search_force_update_tab_label(current_search);
    search_gui_update_items(current_search);
    guc_search_update_items(current_search->search_handle,
		current_search->items);

	*selected = count;
	return created;
}

/**
 * Discard all the search results selected in the ctree.
 *
 * @returns the amount of discarded results.
 */
static guint
discard_selection_of_ctree(GtkCTree *ctree)
{
	gui_record_t *grc;
	record_t *rc;
	GList *sel_list;
	gboolean resort = FALSE;
	guint discarded = 0;
	GtkCTreeNode *node;
	GtkCTreeRow *row;
	search_t *current_search = search_gui_get_current_search();

	gtk_clist_freeze(GTK_CLIST(ctree));

	/* Selection list changes after we process each selected node, so we have to
	 * "re-get" it each iteration.
	 */
	for (
		sel_list = GTK_CLIST(ctree)->selection;
		sel_list != NULL;
		sel_list = GTK_CLIST(ctree)->selection
	) {
		node = sel_list->data;
		if (NULL == node)
			break;

		grc = gtk_ctree_node_get_row_data(ctree, node);
		rc = grc->shared_record;

        if (!rc) {
			g_warning("discard_selection_of_ctree(): row has NULL data");
			continue;
        }

		discarded++;

		/* Check if we should re-sort after we remove the entry.
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

		if (!resort && c_sr_count == current_search->sort_col) {
			row = GTK_CTREE_ROW(node);

			if (NULL == row->parent) {
				/* If it's a parent and the first child is not selected */
				if (NULL != row->children) {
					if (NULL == sel_list->next)
						resort = TRUE;
					else if (sel_list->next->data != row->children)
							resort = TRUE;
				}
			} else {
				/* If it's a child and the next sibling is not selected */
				if (NULL != row->sibling) {
					if (NULL == sel_list->next)
						resort = TRUE;
					else if (sel_list->next->data != row->sibling)
							resort = TRUE;
				}

				/* If it's a child and it has no sibling */
				if (NULL == row->sibling)
					resort = TRUE;
			}
		}

		search_gui_remove_result(ctree, node);
	}

	if (resort) {
		search_gui_sort_column(current_search, current_search->sort_col);
	}

	gtk_clist_unselect_all(GTK_CLIST(ctree));
	gtk_clist_thaw(GTK_CLIST(ctree));

    gui_search_force_update_tab_label(current_search);
    search_gui_update_items(current_search);
    guc_search_update_items(current_search->search_handle,
		current_search->items);

	return discarded;
}

/**
 *	Download selected files
 */
void
search_gui_download_files(void)
{
    search_t *current_search = search_gui_get_current_search();

	if (current_search) {
        guint selected;
        guint created;
		gchar buf[1024];

		created = download_selection_of_ctree(
			GTK_CTREE(current_search->tree), &selected);

        gtk_clist_unselect_all(GTK_CLIST(current_search->tree));

		gm_snprintf(buf, sizeof buf,
			NG_("Created %u download", "Created %u downloads", created),
			created);
		statusbar_gui_message(15,
			NG_("%s from the %u selected item", "%s from the %u selected items",
				selected),
			buf, selected);
	} else {
		g_warning("search_gui_download_files(): no possible search!\n");
	}
}

/**
 *	Discard selected files
 */
void
search_gui_discard_files(void)
{
    search_t *current_search = search_gui_get_current_search();

	if (current_search) {
        guint discarded;

		discarded = discard_selection_of_ctree(
			GTK_CTREE(current_search->tree));

        gtk_clist_unselect_all(GTK_CLIST(current_search->tree));

		statusbar_gui_message(15,
			NG_("Discarded %u result", "Discarded %u results", discarded),
			discarded);
	} else {
		g_warning("search_gui_discard_files(): no possible search!\n");
	}
}



/***
 *** Callbacks
 ***/

/**
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean
search_gui_search_results_col_widths_changed(property_t prop)
{
    guint32 *val;
    GtkCTree *ctree;
	gint i;
    search_t *current_search = search_gui_get_current_search();

	g_assert(prop == PROP_SEARCH_RESULTS_COL_WIDTHS);
    if ((current_search == NULL) && (default_search_ctree == NULL))
        return FALSE;

    val = gui_prop_get_guint32(prop, NULL, 0, 0);

    ctree = (current_search != NULL) ?
		GTK_CTREE(current_search->tree) : default_search_ctree;

    if (NULL != ctree)
        for (i = 0; i < GTK_CLIST(ctree)->columns; i ++)
            gtk_clist_set_column_width(GTK_CLIST(ctree), i, val[i]);

    g_free(val);
    return FALSE;
}


/**
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean
search_gui_search_results_col_visible_changed(property_t prop)
{
	gint i;
    gboolean *val;
 	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

	g_assert(prop == PROP_SEARCH_RESULTS_COL_VISIBLE);
    if ((current_search == NULL) && (default_search_ctree == NULL))
        return FALSE;

    val = gui_prop_get_boolean(prop, NULL, 0, 0);

    ctree = (current_search != NULL) ?
        GTK_CTREE(current_search->tree) : default_search_ctree;

    if (ctree != NULL)
        for (i = 0; i < GTK_CLIST(ctree)->columns; i++)
            gtk_clist_set_column_visibility(GTK_CLIST(ctree), i, val[i]);

    g_free(val);
    return FALSE;
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

static void
drag_begin(GtkWidget *widget, GdkDragContext *unused_drag_ctx, gpointer udata)
{
	GtkCTreeNode *node;
	gui_record_t *grc;
	record_t *record;
	gchar **url_ptr = udata;
	gint row = -1;

	(void) unused_drag_ctx;
	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);

	if (
		!gtk_clist_get_selection_info(GTK_CLIST(widget),
			search_gui_cursor_x, search_gui_cursor_y, &row, NULL)
	) {
		return;
	}

	if (row < 0)
		return;
	
	node = gtk_ctree_node_nth(GTK_CTREE(widget), row);
	grc = gtk_ctree_node_get_row_data(GTK_CTREE(widget), node);
	record = grc->shared_record;
	if (ST_LOCAL & record->results_set->status) {
		const gchar *pathname = record->tag;
		if (pathname) {
			gchar *escaped;

			escaped = url_escape(pathname);
			*url_ptr = g_strconcat("file://", escaped, (void *) 0);
			if (escaped != pathname) {
				G_FREE_NULL(escaped);
			}
		}
	}
}

static void
drag_data_get(GtkWidget *unused_widget, GdkDragContext *unused_drag_ctx,
	GtkSelectionData *data, guint unused_info, guint unused_stamp,
	gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_widget;
	(void) unused_drag_ctx;
	(void) unused_info;
	(void) unused_stamp;

	g_assert(url_ptr != NULL);
	if (*url_ptr) {
		const gchar *drag_data = *url_ptr;
		
    	gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
			8 /* CHAR_BIT */, cast_to_gconstpointer(drag_data),
			strlen(drag_data));
		G_FREE_NULL(*url_ptr);
	}
}

static void
drag_end(GtkWidget *unused_widget, GdkDragContext *unused_drag_ctx,
	gpointer udata)
{
	gchar **url_ptr = udata;

	(void) unused_widget;
	(void) unused_drag_ctx;

	g_assert(url_ptr != NULL);
	G_FREE_NULL(*url_ptr);
}

static void
search_gui_init_dnd(GtkCTree *ctree)
{
	static const GtkTargetEntry targets[] = {
        { "STRING", 0, 23 },
        { "text/plain", 0, 23 },
    };
	static gchar *dnd_url; /* Holds the URL to set the drag data */

	g_return_if_fail(ctree);

	/* Initialize drag support */
	gtk_drag_source_set(GTK_WIDGET(ctree),
		GDK_BUTTON1_MASK | GDK_BUTTON2_MASK, targets, G_N_ELEMENTS(targets),
		GDK_ACTION_DEFAULT | GDK_ACTION_COPY | GDK_ACTION_ASK);

	gtk_signal_connect(GTK_OBJECT(ctree), "drag-data-get",
		drag_data_get, &dnd_url);
	gtk_signal_connect(GTK_OBJECT(ctree), "drag-begin",
		drag_begin, &dnd_url);
	gtk_signal_connect(GTK_OBJECT(ctree), "drag-end",
		drag_end, &dnd_url);
}

/***
 *** Private functions
 ***/

#if 0
static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2)
{
    const gui_record_t *s1 = (const gui_record_t *) ((const GtkCListRow *) ptr1)->data;
	const gui_record_t *s2 = (const gui_record_t *) ((const GtkCListRow *) ptr2)->data;

    return search_gui_compare_records(clist->sort_column, s1, s2);
}
#endif

/***
 *** Public functions
 ***/

void
search_gui_init(void)
{
    GtkNotebook *notebook;

    notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_search_results"));
	search_gui_common_init();

	gui_search_create_ctree(&default_scrolled_window, &default_search_ctree);
    gtk_notebook_remove_page(notebook, 0);
	gtk_notebook_set_scrollable(notebook, TRUE);
	gtk_notebook_append_page(notebook, default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text(notebook,
		default_scrolled_window, _("(no search)"));

	gtk_signal_connect(GTK_OBJECT(notebook), "switch_page",
		GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);

    /*
     * Now we restore the column visibility
     */

	{
		search_t *search;
		GtkCTree *ctree;
	   
		search = search_gui_get_current_search();
		ctree = search ? GTK_CTREE(search->tree) : default_search_ctree;
		gtk_clist_restore_visibility(GTK_CLIST(ctree),
			PROP_SEARCH_RESULTS_COL_VISIBLE);
	}

	search_gui_retrieve_searches();
    search_add_got_results_listener(search_gui_got_results);

	{
		GtkCList *clist;
		
		clist = GTK_CLIST(gui_main_window_lookup("clist_search"));
		gtk_clist_set_selection_mode(clist, GTK_SELECTION_EXTENDED);
		gtk_signal_connect(GTK_OBJECT(clist), "button_press_event",
			GTK_SIGNAL_FUNC(on_search_list_button_press_event), NULL);
	}
}

void
search_gui_shutdown(void)
{
	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

    search_remove_got_results_listener(search_gui_got_results);
	search_gui_store_searches();

    ctree = (current_search != NULL) ?
		GTK_CTREE(current_search->tree) : default_search_ctree;

	gtk_clist_save_visibility(
		GTK_CLIST(ctree), PROP_SEARCH_RESULTS_COL_VISIBLE);

    while (searches != NULL)
        search_gui_close_search((search_t *) searches->data);

	search_gui_common_shutdown();
}

const GList *
search_gui_get_searches(void)
{
	return (const GList *) searches;
}

/**
 * Remove the search from the gui and update all widgets accordingly.
 */
void
search_gui_remove_search(search_t * sch)
{
    gint row;
    gboolean sensitive;
    search_t *current_search;
    GtkCList *clist_search;
    GtkNotebook *notebook;

    g_assert(sch != NULL);

    clist_search = GTK_CLIST(gui_main_window_lookup("clist_search"));
    notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_search_results"));

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gtk_clist_remove(clist_search, row);

    gtk_timeout_remove(sch->tab_updating);

    /* remove column header arrow if it exists */
    if (sch->arrow != NULL) {
        gtk_widget_destroy(sch->arrow);
        sch->arrow = NULL;
    }

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook,
				gtk_notebook_page_num(notebook, sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */
		gtk_clist_clear(GTK_CLIST(sch->tree));

		default_search_ctree = sch->tree;
		default_scrolled_window = sch->scrolled_window;

		search_gui_forget_current_search();

		search_gui_update_items(NULL);
    	search_gui_update_expiry(NULL);

        gtk_notebook_set_tab_label_text(notebook,
			default_scrolled_window, _("(no search)"));

		gtk_widget_set_sensitive(gui_main_window_lookup("button_search_clear"),
			FALSE);
	}

	gtk_widget_set_sensitive(
        gui_main_window_lookup("button_search_close"),
        searches != NULL);
    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_search_expand_all"),
        searches != NULL);
    gtk_widget_set_sensitive(
        gui_main_window_lookup("button_search_collapse_all"),
        searches != NULL);

    sensitive = searches != NULL;
    current_search = search_gui_get_current_search();

	if (current_search != NULL)
		sensitive = sensitive &&
			GTK_CLIST(current_search->tree)->selection;

    gtk_widget_set_sensitive(
		gui_main_window_lookup("button_search_download"), sensitive);
}


void
search_gui_set_current_search(search_t *sch)
{
    static gboolean locked = FALSE;
    search_t *old_sch = search_gui_get_current_search();
    GtkWidget *spinbutton_reissue_timeout;
   	GtkCList *clist;
    gboolean frozen;
    gboolean active;
    guint32 reissue_timeout;
	search_t *current_search = old_sch;
	gint i;

	g_assert(sch != NULL);

    if (locked)
        return;

    locked = TRUE;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);

    active = guc_search_is_active(sch->search_handle);
    frozen = guc_search_is_frozen(sch->search_handle);
    reissue_timeout = guc_search_get_reissue_timeout(sch->search_handle);

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */
    if (current_search != NULL) {
    	GtkCTree *ctree;

        ctree = GTK_CTREE(current_search->tree);

        for (i = 0; i < GTK_CLIST(ctree)->columns; i++) {
            gtk_clist_set_column_visibility
                (GTK_CLIST(sch->tree), i, GTK_CLIST(ctree)->column[i].visible);
            gtk_clist_set_column_width
                (GTK_CLIST(sch->tree), i, GTK_CLIST(ctree)->column[i].width);
        }
    }

	sch->unseen_items = 0;

	search_gui_forget_current_search();
    spinbutton_reissue_timeout =
		gui_main_window_lookup("spinbutton_search_reissue_timeout");
   	clist = GTK_CLIST(gui_main_window_lookup("clist_search"));

    if (sch != NULL) {
        gui_search_force_update_tab_label(sch);
        search_gui_update_items(sch);

		if (0) {
			gint row;	

			row = gtk_clist_find_row_from_data(clist, sch);
			gtk_clist_select_row(clist, row, 0);
			if (!GTK_WIDGET_HAS_FOCUS(GTK_WIDGET(clist)))
				gtk_clist_moveto(clist, row, 0, 0.0, 0.0);
		}

        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_reissue_timeout), reissue_timeout);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, active);
        gtk_widget_set_sensitive(
            gui_main_window_lookup("button_search_download"),
            GTK_CLIST(sch->tree)->selection != NULL);
        gtk_widget_set_sensitive(
            gui_main_window_lookup("button_search_clear"),
            sch->items != 0);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_restart"), active);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_duplicate"), active);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_stop"), !frozen);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_resume"),frozen);

    } else {
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, FALSE);
        gtk_widget_set_sensitive(
            gui_main_window_lookup("button_search_download"), FALSE);
        gtk_widget_set_sensitive(
            gui_main_window_lookup("button_search_clear"), FALSE);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_restart"), FALSE);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_duplicate"), FALSE);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_stop"), FALSE);
        gtk_widget_set_sensitive(
            gui_popup_search_lookup("popup_search_resume"), FALSE);
    }

	search_gui_current_search(sch);

    /*
     * Search results notebook
     */
    {
        GtkNotebook *notebook_search_results = GTK_NOTEBOOK
            (gui_main_window_lookup("notebook_search_results"));

        gtk_notebook_set_page(notebook_search_results,
  			  gtk_notebook_page_num(notebook_search_results,
                  sch->scrolled_window));
    }

    /*
     * Tree menu
     */
    {
        GtkCTree *ctree;
    	GtkCTreeNode *node;
	   
		ctree = GTK_CTREE(gui_main_window_lookup("ctree_menu"));

        node = gtk_ctree_find_by_row_data(ctree, gtk_ctree_node_nth(ctree, 0),
					GINT_TO_POINTER(nb_main_page_search));

        if (node != NULL) {
            gtk_ctree_select(ctree, node);
			if (!GTK_WIDGET_HAS_FOCUS(GTK_WIDGET(ctree)))
				gtk_ctree_node_moveto(ctree, node, 0, 0.0, 0.0);
		}
    }

	if (search_gui_update_expiry(sch))
		gui_search_set_enabled(sch, FALSE);

    locked = FALSE;
}


/**
 *	Create a new GtkCTree for search results
 */
static void
gui_search_create_ctree(GtkWidget ** sw, GtkCTree ** ctree)
{
    GtkWidget *ctree_widget;
	static const struct {
		const gchar *title;
		const gint id;
		const gboolean visible;
	} columns[] = {
		{ N_("File"), 		c_sr_filename,	TRUE },
		{ N_("Extension"),	c_sr_ext, 		TRUE },
		{ N_("Encoding"),	c_sr_charset,	FALSE },
		{ N_("Size"),		c_sr_size,		TRUE },
		{ N_("#"),			c_sr_count,		TRUE },
		{ N_("Loc"),		c_sr_loc,		FALSE },
		{ N_("Metadata"),	c_sr_meta,		TRUE },
		{ N_("Info"),		c_sr_info,		TRUE },
		{ N_("Route"),		c_sr_route,		FALSE },
		{ N_("Protocol"),	c_sr_protocol, 	FALSE },
		{ N_("Hops"),  	   	c_sr_hops,		FALSE },
		{ N_("TTL"),  	   	c_sr_ttl,		FALSE },
		{ N_("Owned"),     	c_sr_owned,		FALSE },
		{ N_("Spam"),      	c_sr_spam,		FALSE },
		{ N_("Hostile"),   	c_sr_hostile,	FALSE },
		{ N_("SHA-1"),     	c_sr_sha1,		FALSE },
	};
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(columns) == c_sr_num);

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

	ctree_widget = gtk_ctree_new(c_sr_num,0);
	*ctree = GTK_CTREE(ctree_widget);

	gtk_container_add(GTK_CONTAINER(*sw), ctree_widget);

	for (i = 0; i < c_sr_num; i++)
		gtk_clist_set_column_width(GTK_CLIST(*ctree), i,
			search_results_col_widths[i]);

	gtk_clist_set_selection_mode(GTK_CLIST(*ctree), GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(GTK_CLIST(*ctree));

	/* Right/Left justification of column text */
    gtk_clist_set_column_justification(GTK_CLIST(*ctree),
        c_sr_size, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(GTK_CLIST(*ctree),
        c_sr_count, GTK_JUSTIFY_RIGHT);

	for (i = 0; i < G_N_ELEMENTS(columns); i++) {
		GtkWidget *label, *hbox;
		const gchar *title;
		gint id;
	
		title = _(columns[i].title);
		id = columns[i].id;
		label = gtk_label_new(title);
    	gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    	hbox = gtk_hbox_new(FALSE, 4);
    	gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
		gtk_clist_set_column_widget(GTK_CLIST(*ctree), id, hbox);
    	gtk_widget_show_all(hbox);
    	gtk_clist_set_column_name(GTK_CLIST(*ctree), id,
			deconstify_gchar(title));
		if (!columns[i].visible)
			gtk_clist_set_column_visibility(GTK_CLIST(*ctree), id, FALSE);
	}

	gtk_widget_show_all(*sw);

	gtk_signal_connect(GTK_OBJECT(*ctree), "tree_select_row",
					   GTK_SIGNAL_FUNC(on_ctree_search_results_select_row),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(*ctree), "tree_unselect_row",
					   GTK_SIGNAL_FUNC
					   (on_ctree_search_results_unselect_row), NULL);
	gtk_signal_connect(GTK_OBJECT(*ctree), "click_column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_click_column), NULL);
	gtk_signal_connect(GTK_OBJECT(*ctree), "button_press_event",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_button_press_event), NULL);
	gtk_signal_connect(GTK_OBJECT(*ctree), "resize-column",
					   GTK_SIGNAL_FUNC
					   (on_ctree_search_results_resize_column), NULL);
    gtk_signal_connect(GTK_OBJECT(*ctree), "key_press_event",
                       GTK_SIGNAL_FUNC
                       (on_clist_search_results_key_press_event), NULL);
}


/**
 *	gui_search_force_update_tab_label
 *
 *	Like search_update_tab_label but always update the label
 *
 */
void
gui_search_force_update_tab_label(struct search *sch)
{
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (gui_main_window_lookup("notebook_search_results"));
    GtkCList *clist_search = GTK_CLIST
        (gui_main_window_lookup("clist_search"));
	search_t *current_search = search_gui_get_current_search();
    gint row;

	{
		const gchar *s;
		
		s = lazy_utf8_to_ui_string(sch->query);
		if (sch == current_search || sch->unseen_items == 0)
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d)",
				s, sch->items);
		else
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d, %d)",
				s, sch->items, sch->unseen_items);
	}
	
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text
        (notebook_search_results, sch->scrolled_window, tmpstr);

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gm_snprintf(tmpstr, sizeof(tmpstr), "%u", sch->items);
    gtk_clist_set_text(clist_search, row, c_sl_hit, tmpstr);
    gm_snprintf(tmpstr, sizeof(tmpstr), "%u", sch->unseen_items);
    gtk_clist_set_text(clist_search, row, c_sl_new, tmpstr);

    if (sch->unseen_items > 0) {
        gtk_clist_set_background(
            clist_search, row,
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->bg[GTK_STATE_ACTIVE]);
    } else {
        gtk_clist_set_background(clist_search, row, NULL);
    }

	sch->last_update_time = tm_time();
}


/**
 *  Update the label if nothing's changed or if the last update was
 *  recent.
 */
gboolean
gui_search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (tm_time() - sch->last_update_time < TAB_UPDATE_TIME)
		return TRUE;

	gui_search_force_update_tab_label(sch);

	return TRUE;
}


/**
 * Removes all search results from the current search.
 */
void
gui_search_clear_results(void)
{
	search_t *current_search = search_gui_get_current_search();

	search_gui_reset_search(current_search);
	gui_search_force_update_tab_label(current_search);
    search_gui_update_items(current_search);
}

/**
 * Set proper search color in list depending on whether it is enabled.
 */
static void
set_search_color(struct search *sch)
{
	GtkCList * clist_search;
	static GtkNotebook *notebook_search_results = NULL;

	clist_search = GTK_CLIST(gui_main_window_lookup("clist_search"));

	if (notebook_search_results == NULL)
		notebook_search_results =
			GTK_NOTEBOOK(gui_main_window_lookup("notebook_search_results"));

	if (sch->enabled) {
        gtk_clist_set_foreground(
            clist_search,
			gtk_notebook_page_num(notebook_search_results,
				sch->scrolled_window),
            NULL);
	} else {
        gtk_clist_set_foreground(
            clist_search,
			gtk_notebook_page_num(notebook_search_results,
				sch->scrolled_window),
            &gtk_widget_get_style(GTK_WIDGET(clist_search))
                ->fg[GTK_STATE_INSENSITIVE]);
	}
}


/**
 * Flag whether search is enabled.
 */
void
gui_search_set_enabled(struct search *sch, gboolean enabled)
{
	gboolean was_enabled = sch->enabled;

	if (was_enabled == enabled)
		return;

	sch->enabled = enabled;

	if (enabled)
		guc_search_start(sch->search_handle);
	else
		guc_search_stop(sch->search_handle);

	set_search_color(sch);
}


/**
 *	Expand all nodes in tree for current search
 */
void
search_gui_expand_all(void)
{
	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

	if (current_search == NULL)
        return;

    ctree = current_search->tree;

	gtk_ctree_expand_recursive(ctree, NULL);
}


/**
 *	Expand all nodes in tree for current search
 */
void
search_gui_collapse_all(void)
{
	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

	if (current_search == NULL)
        return;

    ctree = current_search->tree;

	gtk_ctree_collapse_recursive(ctree, NULL);
}

void
search_gui_start_massive_update(search_t *sch)
{
	g_assert(sch);
	gtk_clist_freeze(GTK_CLIST(sch->tree));
}

void
search_gui_end_massive_update(search_t *sch)
{
	GtkCList *ctree;

	g_assert(sch);
	ctree = GTK_CLIST(sch->tree);
	g_assert(ctree);

	while (ctree->freeze_count > 0)
		gtk_clist_thaw(ctree);
}

/**
 * Update the search displays with the correct meta-data
 *
 */
void
search_gui_metadata_update(const bitzi_data_t *data)
{
    GList *l;
    gchar *text;

	text = bitzi_gui_get_metadata(data);

	/*
	 * Fill in the columns in each search that contains a reference
	 */

	for (l = searches; l != NULL; l = g_list_next(l)) {
		search_t *search = l->data;
		GtkCTree *ctree = GTK_CTREE(search->tree);
    	GtkCTreeNode *parent;

		parent = find_parent_with_sha1(search->parents, data->sha1);
		if (parent)
			gtk_ctree_node_set_text(ctree, parent,
					c_sr_meta, text ? text : _("Not in database"));
	}

	/* free the string */
	g_free(text);
}

/**
 * Update the search displays with the correct meta-data.
 * (called from search_cb.c)
 */
void
search_gui_queue_bitzi_by_sha1(const record_t *rec)
{
	GList *l;
	GtkCTreeNode *parent;

	g_assert(rec != NULL);

	if (!rec->sha1)
		return;

	/*
	 * Add some feedback that a search has been kicked off.
	 */

	for (l = searches; l; l = g_list_next(l)) {
		search_t *search = l->data;
		GtkCTree *ctree = GTK_CTREE(search->tree);

		parent = find_parent_with_sha1(search->parents, rec->sha1);
		if (parent)
			gtk_ctree_node_set_text(ctree, parent, c_sr_meta,
					_("Query queued..."));
	}

	/* and then send the query... */
	guc_query_bitzi_by_sha1(rec->sha1);
}

GSList *
search_gui_get_selected_searches(void)
{
	GSList *sl = NULL;
    GtkCList *clist;
	GList *selection;

    clist = GTK_CLIST(gui_main_window_lookup("clist_search"));
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
search_gui_search_list_clicked(GtkWidget *widget, GdkEventButton *event)
{
	gint row, column;

	if (gtk_clist_get_selection_info(GTK_CLIST(widget), event->x,
			event->y, &row, &column)
	) {
		search_t *search;

		search = gtk_clist_get_row_data(GTK_CLIST(widget), row);
		if (search) {
			search_gui_set_current_search(search);
		}
	}
}

void
search_gui_flush_queues(void)
{
		/* TODO: Implement this */
}

/* vi: set ts=4 sw=4 cindent: */
