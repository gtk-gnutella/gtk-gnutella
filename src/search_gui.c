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

#include "gui.h"

#ifdef USE_GTK1

/* System includes */
#include <ctype.h>
#include <gtk/gtk.h>
#include <sys/stat.h>

#include "file.h"

/* GUI includes  */
#include "search_gui.h"
#include "search_cb.h"
#include "gtk-missing.h"
#include "gui_property.h"
#include "gui_property_priv.h"
#include "settings_gui.h"
#include "statusbar_gui.h"

/* Core includes */
#include "search.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

static gchar tmpstr[4096];

GList *searches = NULL;		/* List of search structs */
search_t *search_selected = NULL;
static GList *list_search_history = NULL;

/* Characteristics of data in search results columns, used for sorting */
enum {
	SEARCH_COL_SORT_DATA_RANDOM = 0,	/* Randomly distributed */
	SEARCH_COL_SORT_DATA_SORTED_ASC,	/* Already sorted or almost sorted */
	SEARCH_COL_SORT_DATA_SORTED_DES,	/* Same as above but descending */
	SEARCH_COL_SORT_DATA_COUNT,			/* Sorting by "count" column */
	SEARCH_COL_SORT_DATA_INFO,			/* Sorting by Info column */
	SEARCH_COL_SORT_DATA_DEFAULT		/* Catch all case */
};


/*
 * Private function prototypes
 */
#if 0
static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2);
#endif
static void set_search_color(struct search *sch);


/*
 * If no searches are currently allocated 
 */
GtkCTree *default_search_ctree = NULL;
static GtkWidget *default_scrolled_window = NULL;


/* ----------------------------------------- */


/*
 *	add_parent_with_sha1
 *
 *	Add the given tree node to the hashtable.
 *  The key is an atomized sha1 of the search result.
 *
 */
static inline void add_parent_with_sha1(GHashTable *ht, gpointer key, 
	GtkCTreeNode *data)
{
	g_hash_table_insert(ht, key, data);
}


/*
 *	remove_parent_with_sha1
 *
 *	Removes the tree node matching the given sha1 from the hash table.
 *  The atom used for the key is then freed
 *
 */
static inline void remove_parent_with_sha1(GHashTable *ht, const gchar *sha1)
{
	gpointer key;
	GtkCTreeNode *data = NULL;
	gpointer orig_key;
 
	key = atom_sha1_get(sha1);

	if (g_hash_table_lookup_extended(ht, key,
			(gpointer) &orig_key, (gpointer) &data)) {
		/* Must first free memory used by the original key */
		atom_sha1_free(orig_key);
	
		/* Then remove the key */
		g_hash_table_remove(ht, key);
	} else
		g_warning("remove_parent_with_sha1: can't find sha1 in hash table!");

	atom_sha1_free(key);
}


/*
 *	find_parent_with_sha1
 *
 *	Returns the tree node corresponding to the given key, an atomized
 *	sha1.
 *
 */
GtkCTreeNode *find_parent_with_sha1(GHashTable *ht, gpointer key)
{
	return(g_hash_table_lookup(ht, key));
}


/*
 *	search_gui_free_parent
 */
gboolean search_gui_free_parent(gpointer key, gpointer value, gpointer x)
{
	atom_sha1_free(key);
	return TRUE;
}


/*
 *	search_gui_free_gui_record
 */
void search_gui_free_gui_record(gpointer gui_rc)
{
	wfree(gui_rc, sizeof(gui_record_t));
}


/*
 *	count_node_children
 *
 *	Returns number of children under parent node in the given ctree
 */
static inline gint count_node_children(GtkCTree *ctree, GtkCTreeNode *parent)
{
	GtkCTreeRow *current_row;
	GtkCTreeNode *current_node;
	gint num_children = 0;
	
	current_row = GTK_CTREE_ROW(parent);
	current_node = current_row->children;
	
	for(;NULL != current_node; current_node = current_row->sibling){
		current_row = GTK_CTREE_ROW(current_node);
		num_children++;
	}	
	
	return num_children;	
}


/*
 *	search_gui_restart_search
 *
 */
void search_gui_restart_search(search_t *sch)
{
	if (!sch->enabled)
		gui_search_set_enabled(sch, TRUE);
	search_reissue(sch->search_handle);	
	search_gui_clear_search(sch);	
	sch->items = sch->unseen_items = 0;
	gui_search_update_items(sch);
	search_update_items(sch->search_handle, sch->items);
}


/*
 * dec_records_refcount
 *
 * Decrement refcount of hash table key entry.
 */
static gboolean dec_records_refcount(gpointer key, gpointer value, gpointer x)
{
	struct record *rc = (struct record *) key;

	g_assert(rc->refcount > 0);

	rc->refcount--;
	return TRUE;
}

/*
 *	search_gui_ctree_unref
 * 
 *	Removes a reference to the record stored in the given tree node
 */
void search_gui_ctree_unref(GtkCTree *ctree, GtkCTreeNode *node, gpointer data)
{
	gui_record_t *grc;

	grc = gtk_ctree_node_get_row_data(ctree, node);
	search_gui_unref_record(grc->shared_record);	
}


/*
 *	search_gui_clear_ctree
 *
 *	Clears all nodes from given ctree and unreferences all records
 *	referenced by the nodes row data
 */
void search_gui_clear_ctree(GtkCTree *ctree)
{
	/* Unreference all records */
	gtk_ctree_post_recursive(ctree, NULL, search_gui_ctree_unref, NULL);	
	gtk_clist_clear(GTK_CLIST(ctree));
}


/*
 * search_clear
 *
 * Clear all results from search.
 */
void search_gui_clear_search(search_t *sch)
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
	search_gui_clear_ctree(sch->ctree);
	g_hash_table_foreach_remove(sch->dups, dec_records_refcount, NULL);
	g_hash_table_foreach_remove(sch->parents, search_gui_free_parent, NULL);
	search_gui_free_r_sets(sch);

	sch->items = sch->unseen_items = 0;
	search_update_items(sch->search_handle, sch->items);
}


/* 
 * search_gui_close_search:
 *
 * Remove the search from the list of searches and free all 
 * associated ressources (including filter and gui stuff).
 */
void search_gui_close_search(search_t *sch)
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
 	searches = g_list_remove(searches, (gpointer) sch);

	search_gui_clear_search(sch);
    search_gui_remove_search(sch);
	filter_close_search(sch);
	
	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;
	g_hash_table_destroy(sch->parents);
	sch->parents = NULL;

    search_close(sch->search_handle);
	atom_str_free(sch->query);

	g_free(sch);
}


/*
 * search_gui_new_search:
 * 
 * Create a new search and start it. Use default reissue timeout.
 */
gboolean search_gui_new_search(
	const gchar *query, flag_t flags, search_t **search)
{
    guint32 timeout;
    gint sort_col = SORT_NO_COL;
	gint sort_order = SORT_NONE;
	
    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    return search_gui_new_search_full(query, 0, timeout,
		sort_col, sort_order, flags | SEARCH_ENABLED, search);
}


/* 
 * search_gui_new_search_full:
 *
 * Create a new search and start it.
 * Returns TRUE if search was sucessfully created and FALSE if an error
 * happened. If the "search" argument is not NULL a pointer to the new
 * search is stored there.
 */
gboolean search_gui_new_search_full(
	const gchar *querystr, guint16 speed,
	guint32 reissue_timeout, gint sort_col, 
	gint sort_order, flag_t flags, search_t **search)
{
    search_t *sch;
    GList *glist;
    gchar *titles[c_sl_num];
    gint row;
    gchar query[512];

    GtkWidget *combo_searches = lookup_widget(main_window, "combo_searches");
    GtkWidget *clist_search = lookup_widget(main_window, "clist_search");
    GtkWidget *notebook_search_results = 
        lookup_widget(main_window, "notebook_search_results");
    GtkWidget *button_search_close = 
        lookup_widget(main_window, "button_search_close");
    GtkWidget *entry_search = lookup_widget(main_window, "entry_search");


	g_strlcpy(query, querystr, sizeof(query));

	/*
	 * If the text is a magnet link we extract the SHA1 urn
	 * and put it back into the search field string so that the
	 * code for urn searches below can handle it.
	 *		--DBelius   11/11/2002
	 */

	if (0 == strncasecmp(query, "magnet:", 7)) {
		gchar raw[SHA1_RAW_SIZE];

		if (huge_extract_sha1(query, raw)) {
			gm_snprintf(query, sizeof(query), "urn:sha1:%s", sha1_base32(raw));
		} else {
			return FALSE;		/* Entry refused */
		}
	}

	/*
	 * If string begins with "urn:sha1:", then it's an URN search.
	 * Validate the base32 representation, and if not valid, beep
	 * and refuse the entry.
	 *		--RAM, 28/06/2002
	 */

	if (0 == strncasecmp(query, "urn:sha1:", 9)) {
		gchar raw[SHA1_RAW_SIZE];
		gchar *b = query + 9;

		if (strlen(b) < SHA1_BASE32_SIZE)
			goto refused;

		if (base32_decode_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw)))
			goto validated;

		/*
		 * If they gave us an old base32 representation, convert it to
		 * the new one on the fly.
		 */
		if (base32_decode_old_into(b, SHA1_BASE32_SIZE, raw, sizeof(raw))) {
			gchar b32[SHA1_BASE32_SIZE];
			base32_encode_into(raw, sizeof(raw), b32, sizeof(b32));
			memcpy(b, b32, SHA1_BASE32_SIZE);
			goto validated;
		}

		/*
		 * Entry refused.
		 */
	refused:
		return FALSE;

	validated:
		b[SHA1_BASE32_SIZE] = '\0';		/* Truncate to end of URN */

		/* FALL THROUGH */
	}

	sch = g_new0(search_t, 1);

	sch->sort_col = sort_col;
	sch->sort_order = sort_order;
	
	sch->query = atom_str_get(query);
	sch->enabled = (flags & SEARCH_ENABLED) ? TRUE : FALSE;
    sch->search_handle = search_new(query, speed, reissue_timeout, flags);
    sch->passive = (flags & SEARCH_PASSIVE) ? TRUE : FALSE;
	sch->dups = g_hash_table_new((GHashFunc) search_gui_hash_func,
					(GCompareFunc) search_gui_hash_key_compare);
	if (!sch->dups)
		g_error("new_search: unable to allocate hash table.\n");
    
	sch->parents = g_hash_table_new(NULL, NULL);	
  	filter_new_for_search(sch);

	/* Create the list item */

	sch->list_item = gtk_list_item_new_with_label(sch->query);
	gtk_widget_show(sch->list_item);
	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_prepend_items(GTK_LIST(GTK_COMBO(combo_searches)->list), glist);

    titles[c_sl_name] = sch->query;
    titles[c_sl_hit] = "0";
    titles[c_sl_new] = "0";
    row = gtk_clist_append(GTK_CLIST(clist_search), titles);
    gtk_clist_set_row_data(GTK_CLIST(clist_search), row, sch);

	/* Create a new ctree if needed, or use the default ctree */

	if (searches) {
		/* We have to create a new ctree for this search */
		gui_search_create_ctree(&sch->scrolled_window, &sch->ctree);

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);

		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
								 sch->scrolled_window, NULL);
	} else {
		/* There are no searches currently, we can use the default ctree */
		if (default_scrolled_window && default_search_ctree) {
			sch->scrolled_window = default_scrolled_window;
			sch->ctree = default_search_ctree;

			default_search_ctree = NULL;
			default_scrolled_window = NULL;
		} else
			g_warning
				("new_search(): No current search but no default ctree !?\n");

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);
	}

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(TAB_UPDATE_TIME * 1000,
        (GtkFunction)gui_search_update_tab_label, sch);

    if (!searches) {
        GtkWidget * w = gtk_notebook_get_nth_page( 
            GTK_NOTEBOOK(notebook_search_results), 0);
    
		gtk_notebook_set_tab_label_text(
            GTK_NOTEBOOK(notebook_search_results),
            w, _("(no search)"));
    }

	gtk_signal_connect(GTK_OBJECT(sch->list_item), "select",
					   GTK_SIGNAL_FUNC(on_search_selected),
					   (gpointer) sch);

	search_gui_sort_column(sch, sort_col);
	search_gui_set_current_search(sch);

	gtk_widget_set_sensitive(combo_searches, TRUE);
	gtk_widget_set_sensitive(button_search_close, TRUE);
    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_expand_all"), TRUE);
    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_collapse_all"), TRUE);

    gtk_entry_set_text(GTK_ENTRY(entry_search),"");

	searches = g_list_append(searches, (gpointer) sch);

/* FIXME:	This might be suboptimal but if search_start() isn't called
 *			"search_handle"->sent_nodes will not be initialized and
 *			the function in search.c accessing this hashtable, will warn
 *			it's NULL (or raise a SIGSEGV in case of NODEBUG).
 */
	search_start(sch->search_handle);
	if (!sch->enabled)
		search_stop(sch->search_handle);

	set_search_color(sch);

	if (search)
		*search = sch;
	return TRUE;
}


/* Searches results */


/* 
 * search_gui_compare_records:
 *
 * If the value in sort_col for r1 is "greater than" r2 returns +1
 * 0 if they're equal, and -1 if r1 is "less than" r2
 */
gint search_gui_compare_records(
	gint sort_col, const gui_record_t *g1, const gui_record_t *g2)
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

        switch (sort_col) {
        case c_sr_filename:
            result = strcmp(r1->name, r2->name);
            break;
		
        case c_sr_size:
			/*
			 * Sort by size, then by identical SHA1.
			 */
			if (r1->size == r2->size)
            	result = (r1->sha1 == r2->sha1) ? 0 :
              		(r1->sha1 == NULL) ? -1 :
              		(r2->sha1 == NULL) ? +1 :
					memcmp(r1->sha1, r2->sha1, SHA1_RAW_SIZE);
			else
				result = (r1->size > r2->size) ? +1 : -1;
            break;
			
        case c_sr_info:
			result = memcmp(rs1->vendor, rs2->vendor, sizeof(rs1->vendor));
			if (result)
				break;
            if (rs1->status == rs2->status)
                result = 0;
            else
                result = (rs1->status > rs2->status) ? +1 : -1;
            break;
			
        case c_sr_count:
				if (g1->num_children == g2->num_children)
					result = 0;
				else
					result = (g1->num_children > g2->num_children) ? +1 : -1;
            break;
				
        case c_sr_speed:
            result = (rs1->speed == rs2->speed) ? 0 :
                (rs1->speed > rs2->speed) ? +1 : -1;
            break;
		
        case c_sr_host:
			/*
			 * If both have a hostname, sort by name.  Otherwise
			 * any hostname is greater than any IP.
			 */
			if (rs1->hostname != NULL) {
				result = rs2->hostname == NULL ? -1 :
					strcmp(rs1->hostname, rs2->hostname);
				if (result == 0)
					result = rs1->port < rs2->port ? -1 : +1;
			} else if (rs2->hostname != NULL) {
				result = +1;		/* greater than any IP address */
			} else {
				result = (rs1->ip == rs2->ip) ?  
					(gint) rs1->port - (gint) rs2->port :
					(rs1->ip > rs2->ip) ? +1 : -1;
			}
            break;
			
        case c_sr_sha1:
            if (r1->sha1 == r2->sha1)
                result = 0;
            else if (r1->sha1 == NULL)
                result = -1;
            else if (r2->sha1 == NULL)
                result = +1;
            else
                result =  memcmp(r1->sha1, r2->sha1, SHA1_RAW_SIZE);  
            break;

        default:
            g_assert_not_reached();
        }
    }

	return result;
}

/* 
 * search_gui_insert_with_sort:
 *
 * Inserts the given node into the given list in the proper position.  Assumes
 * list has at least one item already and is sorted.  Note: this is extremely 
 * time critical code, some code duplication is intentional.
 */
GList *search_gui_insert_with_sort(GList *list, GtkCTreeNode *node,
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


/* 
 * search_gui_quick_sort_array_swap:
 *
 * Swaps the values in the given array for the given indicies
 */
void search_gui_quick_sort_array_swap(GArray *array, gint i1, gint i2)
{
/*
 *  This is the old version by Emile. I the one below seems to work fine
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
    g_array_index(array, GtkCTreeNode *, i1) = g_array_index(array, GtkCTreeNode *, i2);
    g_array_index(array, GtkCTreeNode *, i2) = buf;
}


/* 
 * search_gui_quick_sort:
 *
 * Performs a recursive quick sort on the given array between indicies beg and 
 * end.  Note: this is extremely time critical code, some code duplication is
 * intentional.
 */
void search_gui_quick_sort(GArray *array, gint beg, gint end, 
	GtkCTree *ctree, gboolean ascending, gint sort_col)
{
	gui_record_t *pivot_record;
    GtkCTreeNode *pivot_node;
    gint pivot_index;
	
    /* terminate recursion */
	if (beg >= end) 
		return;	

	/* Choose the item in the middle for the pivot, swap it to the end */
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

	
	/* move pivot from end to its final place */
	search_gui_quick_sort_array_swap(array, end, pivot_index);

	search_gui_quick_sort(array, beg, pivot_index - 1, ctree, 
		ascending, sort_col);
	search_gui_quick_sort(array, pivot_index + 1, end, ctree, 
		ascending, sort_col);
}


/* 
 * search_gui_analyze_col_data:
 *
 * Analyze the data in the given column to decide what type of search should
 * be performed.  This function detects whether the data is alreadt sorted 
 * ascending, descending, appears to be random, is sorting via tha count column,
 * or via the info column.  
 */
gint search_gui_analyze_col_data(GtkCTree *ctree, gint sort_col)
{
	GtkCTreeNode *cur_node;
	GtkCTreeNode *prev_node;
	gboolean ascending = TRUE;
	gboolean descending = TRUE;
	gboolean random = FALSE;
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
    // FIXME: this counts the number of rows, but not the number of top-level
    // nodes. The number can only be seen as an estimation.
    //     -- BLUE 17/01/2004
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
			random = TRUE;		
			break;
		}
	}
	
	if (random)	
		return SEARCH_COL_SORT_DATA_RANDOM;

	if (ascending)	
		return SEARCH_COL_SORT_DATA_SORTED_ASC;

	if (descending)	
		return SEARCH_COL_SORT_DATA_SORTED_DES;

	return SEARCH_COL_SORT_DATA_DEFAULT;	
}


/*
 * 	search_gui_perform_sort
 *
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
void search_gui_perform_sort(GtkCTree *ctree, gboolean ascending, gint sort_col)
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

            // FIXME: It might be possible to use fast_mode only when
            // moving top-level nodes around and also sort the children,
            // or to simply iterate over all nodes (also children), purge
            // the tree content are create it from scratch. How fast would
            // that be? Should be like <O(n^2) for iteration and sorting and
            // O(n) for purging and rebuilding.
            // A couple of other places in the code would need to be changed
            // too (search for GTK_CTREE_NODE_SIBLING).
            //    -- BLUE 17/01/2004
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


/*
 * search_gui_sort_column
 *
 * Draws arrows for the given column of the GtkCTree and 
 * sorts the contents of the GtkCTree according to the 
 * sorting parameters set in search
 */
void search_gui_sort_column(search_t *search, gint column)
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
        search->arrow = create_pixmap(main_window, "arrow_up.xpm");
		ascending = TRUE;
        break;  
    case SORT_DESC:
        search->arrow = create_pixmap(main_window, "arrow_down.xpm");
		ascending = FALSE;
        break;
    case SORT_NONE:
        break;
    default:
        g_assert_not_reached();
    }

    /* display arrow if necessary and set sorting parameters*/
    if (search->sort_order != SORT_NONE) {
        cw = gtk_clist_get_column_widget
                 (GTK_CLIST(search->ctree), column);
        if (cw != NULL) {
            gtk_box_pack_start(GTK_BOX(cw), search->arrow, 
                               FALSE, FALSE, 0);
            gtk_box_reorder_child(GTK_BOX(cw), search->arrow, 0);
            gtk_widget_show(search->arrow);
        }
		search_gui_perform_sort(search->ctree, ascending, column);
        search->sort = TRUE;

	} else {
        search->sort = FALSE;
    }
}


/*
 *	search_gui_add_record
 *
 *	Adds the record to gth GtkCTree for this search.
 *	This is where the search grouping (parenting) is done
 */
void search_gui_add_record(
	search_t *sch, record_t *rc, GString *vinfo, GdkColor *fg, GdkColor *bg)
{
  	GString *info = g_string_sized_new(80);
  	gchar *titles[c_sr_num];
	gint count;
	gpointer key = NULL;
	gboolean is_parent = FALSE;
	gui_record_t *gui_rc;
	gui_record_t *parent_rc;
	gui_record_t *grc1;
	gui_record_t *grc2;
    struct results_set *rs = rc->results_set;
	gchar *empty = "";

	GtkCTreeNode *parent;
	GtkCTreeNode *node;
	GtkCTreeNode *cur_node;
	GtkCTreeNode *sibling;
	GtkCTreeNode *auto_node;
	GtkCTreeRow *row;
	GtkCTreeRow	*parent_row;
	GtkCTree *ctree = GTK_CTREE(sch->ctree);
	
	info = g_string_assign(info, "");
	if (rc->tag) {
		guint len = strlen(rc->tag);

		/*
		 * We want to limit the length of the tag shown, but we don't
		 * want to loose that information.	I imagine to have a popup
		 * "show file info" one day that will give out all the
		 * information.
		 *				--RAM, 09/09/2001
		 */

		if (len > MAX_TAG_SHOWN) {
            gchar saved = rc->tag[MAX_TAG_SHOWN];
			rc->tag[MAX_TAG_SHOWN] = '\0';
			g_string_append(info, rc->tag);
			rc->tag[MAX_TAG_SHOWN] = saved;
		} else
			g_string_append(info, rc->tag);
	}

	if (vinfo->len) {
		if (info->len)
			g_string_append(info, "; ");
		g_string_append(info, vinfo->str);
	}
	
	if (NULL != rc->info)
		atom_str_free(rc->info);
	rc->info = atom_str_get(info->str);	
	
	g_string_free(info, TRUE);

	/* Setup text for node.  Note only parent nodes will have # and size shown*/
	titles[c_sr_filename] = (NULL != rc->name) ?  rc->name : empty;
	titles[c_sr_info] = (NULL != rc->info) ?  rc->info : empty;
	titles[c_sr_sha1] = (NULL != rc->sha1) ?  sha1_base32(rc->sha1) : empty;
	titles[c_sr_size] = empty;
	titles[c_sr_count] = empty;

	titles[c_sr_host] = (NULL == rs->hostname) ?
		ip_port_to_gchar(rs->ip, rs->port) :
		hostname_port_to_gchar(rs->hostname, rs->port);

	gm_snprintf(tmpstr, sizeof(tmpstr), "%u", rs->speed);
	titles[c_sr_speed] = atom_str_get(tmpstr);


	/* Add the search result to the ctree */
	
	/* Record memory is freed automatically by function set later on using
	 * gtk_ctree_node_set_row_data_full
	 */
	gui_rc = walloc(sizeof(gui_record_t));
	gui_rc->shared_record = rc;

	if (NULL != rc->sha1) {

		/* We use the sch->parents hash table to store pointers to all the
		 * parent tree nodes referenced by their atomized sha1.
		 */
		parent = find_parent_with_sha1(sch->parents, rc->sha1);

		if (NULL != parent) {
			/* A parent exists with that sha1, add as child to that parent */
			node = gtk_ctree_insert_node(ctree, parent, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
			
			/*Update the "#" column of the parent, +1 for parent */			
			count = count_node_children(ctree, parent) + 1;			
			gm_snprintf(tmpstr, sizeof(tmpstr), "%u", count); 
			gtk_ctree_node_set_text(ctree, parent, c_sr_count, tmpstr); 

			/* Update count in the records (use for column sorting) */
			gui_rc->num_children = 0;
			parent_rc = gtk_ctree_node_get_row_data(ctree, parent);
			parent_rc->num_children = count - 1;
			is_parent = FALSE;

		} else { /* Add as a parent */
			key = atom_sha1_get(rc->sha1);	/* New parent, need new atom ref */

			titles[c_sr_size] = short_size(rc->size);

			/* Add node as a parent */
			node = gtk_ctree_insert_node(ctree, parent = NULL, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
			add_parent_with_sha1(sch->parents, key, node);

			/* Update count in the records (use for column sorting) */
			gui_rc->num_children = 0;
			is_parent = TRUE;
		}
		
	} else { /* Add node as a parent with no SHA1 */ 
		titles[c_sr_size] = short_size(rc->size);

		node = gtk_ctree_insert_node(ctree, parent = NULL, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
		/* Update count in the records (use for column sorting) */
		gui_rc->num_children = 0;
		is_parent = TRUE;
	}
	
	atom_str_free(titles[c_sr_speed]);
	
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
			grc1 = gtk_ctree_node_get_row_data(sch->ctree, auto_node);
		} else {
			auto_node = node;
			grc1 = gui_rc;
		}
		
		if (is_parent) {
			parent = NULL;
			sibling = NULL;
			
			/* Traverse the entire search tree */
			for (
                cur_node = GTK_CTREE_NODE(GTK_CLIST(sch->ctree)->row_list);
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


    if (fg != NULL)
        gtk_ctree_node_set_foreground(ctree, node, fg);
    if (bg != NULL)
        gtk_ctree_node_set_background(ctree, node, bg);
}


/*
 *	search_gui_set_clear_button_sensitive
 */
void search_gui_set_clear_button_sensitive(gboolean flag)
{
	GtkWidget *button_search_clear =
		lookup_widget(main_window, "button_search_clear");

	gtk_widget_set_sensitive(button_search_clear, flag);
}


/* ----------------------------------------- */


/*
 *	search_gui_remove_result
 *
 *	Removes the given node from the ctree 
 *
 */
static void search_gui_remove_result(GtkCTree *ctree, GtkCTreeNode *node)
{
	gui_record_t *grc = NULL;	
	gui_record_t *parent_grc;
	gui_record_t *child_grc;
	record_t *rc;
	record_t *child_rc;
	GtkCTreeRow *row;
	GtkCTreeRow *child_row;
	GtkCTreeNode *child_node;
	GtkCTreeNode *old_parent;
	GtkCTreeNode *old_parent_sibling;
	GtkCTreeNode *child_sibling;
	GtkCTreeNode *temp_node;
	gint n;

	search_t *current_search = search_gui_get_current_search();
    current_search->items--;

	/* First get the record, it must be unreferenced at the end */
	grc = gtk_ctree_node_get_row_data(ctree, node);
	rc = grc->shared_record;

	g_assert(rc->refcount > 1);

	row = GTK_CTREE_ROW(node);
	if (NULL == row->parent) {

		/* It has no parents, therefore it must be a parent.
		 * If it has children, then we are removing the parent but not the
		 * children 
		 */		
		n = count_node_children(ctree, node);
		if (0 < n) {

			/* We move the first child into the position originally occupied
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
				temp_node = child_sibling;
				child_sibling = GTK_CTREE_NODE_SIBLING(child_sibling);
				gtk_ctree_move(ctree, temp_node, child_node, NULL);					
			}
			
			gtk_ctree_remove_node(ctree, old_parent);

			/* Now update the new parent (just promoted from child) */			
			child_grc = gtk_ctree_node_get_row_data(ctree, child_node);
			
			/* Calculate # column */
			n = count_node_children(ctree, child_node);
			if (1 < n)
				gm_snprintf(tmpstr, sizeof(tmpstr), "%u", n); 
			else
				*tmpstr = '\0';

			/* Update record count, child_rc will become the rc for the parent*/
			child_grc->num_children = n - 1; /* -1 because we're removing one */
			
			/* Now actually modify the old parent node */
			gtk_ctree_node_set_text(ctree, child_node, c_sr_count, tmpstr);		
			
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
		n = count_node_children(ctree, old_parent) + 1;
		if (1 < n)
			gm_snprintf(tmpstr, sizeof(tmpstr), "%u", n);
		else
			*tmpstr = '\0';
		gtk_ctree_node_set_text(ctree, old_parent, c_sr_count, tmpstr);
	
		parent_grc = gtk_ctree_node_get_row_data(ctree, old_parent);
		parent_grc->num_children = n - 1;
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


/*
 * download_selection_of_ctree
 *
 * Create downloads for all the search results selected in the ctree.
 * Returns the amount of downloads actually created, and the amount of
 * items in the selection within `selected'.
 */
static guint download_selection_of_ctree(GtkCTree * ctree, guint *selected)
{
	struct results_set *rs;
	gui_record_t *grc;
	record_t *rc;
	GList *sel_list;
	gboolean need_push;
    gboolean remove_downloaded;
	guint created = 0;
	guint count = 0;
	GtkCTreeNode *node;

	search_t *current_search = search_gui_get_current_search();

    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED,
		&remove_downloaded);


	gtk_clist_freeze(GTK_CLIST(ctree));

	/* Selection list changes after we process each selected node, so we have to 
	 * "re-get" it each iteration.
	 */
	for (sel_list = GTK_CLIST(ctree)->selection; sel_list != NULL;
		 sel_list = GTK_CLIST(ctree)->selection) {

		node = sel_list->data;
		if (NULL == node)
			break;
		
		count++;

		/* make it visibile that we already selected this for download */
		gtk_ctree_node_set_foreground(ctree, node,
			&gtk_widget_get_style(GTK_WIDGET(ctree))->fg[GTK_STATE_ACTIVE]);

		grc = gtk_ctree_node_get_row_data(ctree, node);		
		rc = grc->shared_record;
		
        if (!rc) {
			g_warning("download_selection_of_ctree(): row has NULL data");
			continue;
        }

		rs = rc->results_set;
		need_push =
			(rs->status & ST_FIREWALL) || !host_is_valid(rs->ip, rs->port);

		if (download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
				rs->guid, rs->hostname,
				rc->sha1, rs->stamp, need_push, NULL, rs->proxies))
			created++;

		if (rs->proxies != NULL)
			search_gui_free_proxies(rs);

		if (rc->alt_locs != NULL)
			search_gui_check_alt_locs(rs, rc);

        if (remove_downloaded)
			search_gui_remove_result(ctree, node);
		else
			gtk_ctree_unselect(ctree, node);
	}
	
	gtk_clist_unselect_all(GTK_CLIST(ctree));
	gtk_clist_thaw(GTK_CLIST(ctree));

    gui_search_force_update_tab_label(current_search);
    gui_search_update_items(current_search);
    search_update_items(current_search->search_handle, current_search->items);

	*selected = count;
	return created;
}


/*
 *	search_gui_download_files
 *
 *	Download selected files
 */
void search_gui_download_files(void)
{
    GtkWidget *notebook_main;
    GtkWidget *ctree_menu;
	GtkCTreeNode *ctree_node;
	guint selected;
	guint created;

    search_t *current_search = search_gui_get_current_search();
	
    notebook_main = lookup_widget(main_window, "notebook_main");
    ctree_menu = lookup_widget(main_window, "ctree_menu");

	/* This CTree in this following section is the CTree on the lefthand pane,
	 * not the one used to display search results
	 */
	if (jump_to_downloads) {
		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main),
            nb_main_page_downloads);

		/*
		 * Get ctree node for "downloads" row.
		 * Start searching from root node (0th)
		 */
		ctree_node = gtk_ctree_find_by_row_data(GTK_CTREE(ctree_menu), 
			gtk_ctree_node_nth(GTK_CTREE(ctree_menu), 0), 
			GINT_TO_POINTER(nb_main_page_downloads));

		/*
		 * Select "downloads" row.
		 * May need additional code in the future to expand node,
		 * if necessary -- emile
		 */		
		gtk_ctree_select(GTK_CTREE(ctree_menu), ctree_node);
	}

	if (current_search) {

		created = download_selection_of_ctree(
			GTK_CTREE(current_search->ctree), &selected);

		gtk_clist_unselect_all(GTK_CLIST(current_search->ctree));

		statusbar_gui_message(15,
			"Created %u download%s from the %u selected item%s",
			created, created == 1 ? "" : "s",
			selected, selected == 1 ? "" : "s");
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}	
}



/***
 *** Callbacks
 ***/

/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_widths_changed(property_t prop)
{
    guint32 *val;
    GtkCTree *ctree;
	gint i;
    search_t *current_search = search_gui_get_current_search();

    if ((current_search == NULL) && (default_search_ctree == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, NULL, 0, 0);

    ctree = (current_search != NULL) ? 
		GTK_CTREE(current_search->ctree) : default_search_ctree;

    if (NULL != ctree)
        for (i = 0; i < GTK_CLIST(ctree)->columns; i ++)
            gtk_clist_set_column_width(GTK_CLIST(ctree), i, val[i]);

    g_free(val);
    return FALSE;
}


/*
 * search_gui_search_results_col_widths_changed:
 *
 * Callback to update the columns withs in the currently visible search.
 * This is not in settings_gui because the current search should not be
 * known outside this file.
 */
gboolean search_gui_search_results_col_visible_changed(property_t prop)
{
	gint i;
    guint32 *val;
 	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

    if ((current_search == NULL) && (default_search_ctree == NULL))
        return FALSE;

    val = gui_prop_get_guint32(PROP_SEARCH_RESULTS_COL_VISIBLE, NULL, 0, 0);

    ctree = (current_search != NULL) ? 
        GTK_CTREE(current_search->ctree) : default_search_ctree;

    if (ctree != NULL)
        for (i = 0; i < GTK_CLIST(ctree)->columns; i++)
            gtk_clist_set_column_visibility(GTK_CLIST(ctree), i, val[i]);
 
    g_free(val);
    return FALSE;
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


/*
 *	search_gui_init
 */
void search_gui_init(void)
{
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
        (lookup_widget(main_window, "combo_searches"));

	gint i;
	GtkCTree *ctree;
	search_t *current_search;
	
	search_gui_common_init();

	gui_search_create_ctree(&default_scrolled_window, &default_search_ctree);
    gtk_notebook_remove_page(notebook_search_results, 0);
	gtk_notebook_set_scrollable(notebook_search_results, TRUE);
	gtk_notebook_append_page
        (notebook_search_results, default_scrolled_window, NULL);
  	gtk_notebook_set_tab_label_text
        (notebook_search_results, default_scrolled_window, _("(no search)"));
    
	gtk_signal_connect(GTK_OBJECT(combo_searches->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);

    /*
     * Now we restore the column visibility
     */
	current_search = search_gui_get_current_search();

    ctree = (current_search != NULL) ? 
		GTK_CTREE(current_search->ctree) : default_search_ctree;
        
    for (i = 0; i < GTK_CLIST(ctree)->columns; i ++)
    	gtk_clist_set_column_visibility
        (GTK_CLIST(ctree), i, (gboolean) search_results_col_visible[i]);

	search_gui_retrieve_searches();
    search_add_got_results_listener(search_gui_got_results);
}


/*
 *	search_gui_shutdown
 */
void search_gui_shutdown(void)
{
	GtkCTree *ctree;
	gint i;
    search_t *current_search = search_gui_get_current_search();

    search_remove_got_results_listener(search_gui_got_results);
	search_gui_store_searches();

    ctree = (current_search != NULL) ? 
		GTK_CTREE(current_search->ctree) : default_search_ctree;

    for (i = 0; i < GTK_CLIST(ctree)->columns; i ++)
        search_results_col_visible[i] = GTK_CLIST(ctree)->column[i].visible;

    while (searches != NULL)
        search_gui_close_search((search_t *) searches->data);

	search_gui_common_shutdown();

    g_list_free(list_search_history);
    list_search_history = NULL;
}


/*
 *	search_gui_get_searches
 */
const GList *search_gui_get_searches(void)
{
	return (const GList *) searches;
}


/*
 * search_gui_remove_search:
 *
 * Remove the search from the gui and update all widgets accordingly.
 */
void search_gui_remove_search(search_t * sch)
{
    gint row;
    GList *glist;
    gboolean sensitive;
    search_t *current_search;
    GtkCList *clist_search = GTK_CLIST
        (lookup_widget(main_window, "clist_search"));
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCombo *combo_searches = GTK_COMBO
         (lookup_widget(main_window, "combo_searches"));

    g_assert(sch != NULL);

   	glist = g_list_prepend(NULL, (gpointer) sch->list_item);
	gtk_list_remove_items(GTK_LIST(combo_searches->list), glist);
    g_list_free(glist); glist = NULL;

    row = gtk_clist_find_row_from_data(clist_search, sch);
    gtk_clist_remove(clist_search, row);

    gtk_timeout_remove(sch->tab_updating);

    /* remove column header arrow if it exists */
    if (sch->arrow != NULL) { 
        gtk_widget_destroy(sch->arrow);
        sch->arrow = NULL;
    }     

    if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(notebook_search_results,
			gtk_notebook_page_num(notebook_search_results, 
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */
		gtk_clist_clear(GTK_CLIST(sch->ctree));

		default_search_ctree = sch->ctree;
		default_scrolled_window = sch->scrolled_window;

        search_selected = NULL;
		search_gui_forget_current_search();

		gui_search_update_items(NULL);

		gtk_entry_set_text
            (GTK_ENTRY(lookup_widget(main_window, "combo_entry_searches")), "");

        gtk_notebook_set_tab_label_text
            (notebook_search_results, default_scrolled_window, _("(no search)"));

		gtk_widget_set_sensitive
            (lookup_widget(main_window, "button_search_clear"), FALSE);
	}
    
	gtk_widget_set_sensitive(
        GTK_WIDGET(combo_searches), 
        searches != NULL);
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_close"), 
        searches != NULL);
    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_expand_all"), 
        searches != NULL);
    gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_collapse_all"),
        searches != NULL);

    sensitive = searches != NULL;
    current_search = search_gui_get_current_search();

	if (current_search != NULL)
		sensitive = sensitive &&
			GTK_CLIST(current_search->ctree)->selection;

    gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
}


/*
 *	search_gui_set_current_search
 *
 *	
 *
 */
void search_gui_set_current_search(search_t *sch) 
{
    search_t *old_sch = search_gui_get_current_search();
    GtkCTree *ctree;
    GtkCTreeNode * node;
    GtkWidget *spinbutton_reissue_timeout;
    GtkCList *clist_search;
	gint i;
    static gboolean locked = FALSE;
    gboolean passive;
    gboolean frozen;
    guint32 reissue_timeout;
	search_t *current_search = old_sch;

	g_assert(sch != NULL);

    if (locked)
        return;

    locked = TRUE;

	if (old_sch)
		gui_search_force_update_tab_label(old_sch);

    passive = search_is_passive(sch->search_handle);
    frozen = search_is_frozen(sch->search_handle);
    reissue_timeout = search_get_reissue_timeout(sch->search_handle);

    /*
     * We now propagate the column visibility from the current_search
     * to the new current_search.
     */
    if (current_search != NULL) {
        
        ctree = GTK_CTREE(current_search->ctree);

        for (i = 0; i < GTK_CLIST(ctree)->columns; i++) {
            gtk_clist_set_column_visibility
                (GTK_CLIST(sch->ctree), i, GTK_CLIST(ctree)->column[i].visible);
            gtk_clist_set_column_width
                (GTK_CLIST(sch->ctree), i, GTK_CLIST(ctree)->column[i].width);
        }
    }

	search_gui_current_search(sch);
	sch->unseen_items = 0;

    spinbutton_reissue_timeout= lookup_widget
        (main_window, "spinbutton_search_reissue_timeout");
    clist_search = GTK_CLIST
            (lookup_widget(main_window, "clist_search"));

    if (sch != NULL) {
        gui_search_force_update_tab_label(sch);
        gui_search_update_items(sch);

        gtk_clist_select_row(
            clist_search, 
            gtk_clist_find_row_from_data(clist_search, sch), 
            0);
        gtk_spin_button_set_value
            (GTK_SPIN_BUTTON(spinbutton_reissue_timeout), reissue_timeout);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, !passive);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_download"), 
            GTK_CLIST(sch->ctree)->selection != NULL);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_clear"), 
            sch->items != 0);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_restart"), !passive);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_duplicate"), !passive);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), !frozen);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"),frozen);

        /*
         * Combo "Active searches"
         */
        gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));
    } else {
        gtk_clist_unselect_all(clist_search);
        gtk_widget_set_sensitive(spinbutton_reissue_timeout, FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_download"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(main_window, "button_search_clear"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_restart"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_duplicate"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), FALSE);
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"), FALSE);
    }

    /*
     * Search results notebook
     */
    {
        GtkNotebook *notebook_search_results = GTK_NOTEBOOK
            (lookup_widget(main_window, "notebook_search_results"));

        gtk_notebook_set_page(notebook_search_results,
  			  gtk_notebook_page_num(notebook_search_results,
                  sch->scrolled_window));
    }

    /*
     * Tree menu
     */
    {
        GtkCTree *ctree_menu = GTK_CTREE
            (lookup_widget(main_window, "ctree_menu"));

        node = gtk_ctree_find_by_row_data(
            ctree_menu,
            gtk_ctree_node_nth(ctree_menu,0),
            GINT_TO_POINTER(nb_main_page_search));
    
        if (node != NULL)
            gtk_ctree_select(ctree_menu,node);
    }

    locked = FALSE;
}


/*
 *	gui_search_create_ctree
 *
 * Create a new GtkCTree for search results 
 */
void gui_search_create_ctree(GtkWidget ** sw, GtkCTree ** ctree)
{
	GtkWidget *label;
    GtkWidget *hbox;
    GtkWidget *ctree_widget;

	gint i;

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

	label = gtk_label_new(_("File"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_filename, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_filename, _("File"));

	label = gtk_label_new(_("Size"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_size, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_size, _("Size"));

	label = gtk_label_new(_("#"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_count, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_count, _("#"));

	label = gtk_label_new(_("Speed"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_speed, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_speed, _("Speed"));
	gtk_clist_set_column_visibility(GTK_CLIST(*ctree), c_sr_speed, FALSE);

	label = gtk_label_new(_("Host"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_host, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_host, _("Host"));
	gtk_clist_set_column_visibility(GTK_CLIST(*ctree), c_sr_host, FALSE);

	label = gtk_label_new(_("urn:sha1"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_sha1, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_sha1, _("urn:sha1"));
	gtk_clist_set_column_visibility(GTK_CLIST(*ctree), c_sr_sha1, FALSE);

	label = gtk_label_new(_("Info"));
    gtk_misc_set_alignment(GTK_MISC(label),0,0.5);
    hbox = gtk_hbox_new(FALSE, 4);
    gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
	gtk_clist_set_column_widget(GTK_CLIST(*ctree), c_sr_info, hbox);
    gtk_widget_show_all(hbox);
    gtk_clist_set_column_name(GTK_CLIST(*ctree), c_sr_info, _("Info"));

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


/*
 *	gui_search_update_items
 *
 *	Updates the # of items found label
 */
void gui_search_update_items(struct search *sch)
{
    if (sch) {
        gchar *str = sch->passive ? "(passive search) " : "";
    
        if (sch->items)
            gm_snprintf(tmpstr, sizeof(tmpstr), _("%s%u item%s found"), 
                str, sch->items, (sch->items > 1) ? "s" : "");
        else
            gm_snprintf(tmpstr, sizeof(tmpstr), _("%sNo items found"), str);
    } else
        g_strlcpy(tmpstr, _("No search"), sizeof(tmpstr));

	gtk_label_set(GTK_LABEL(lookup_widget(main_window, "label_items_found")), 
        tmpstr);
}


/*
 *	gui_search_force_update_tab_label
 *
 *	Like search_update_tab_label but always update the label
 *
 */
void gui_search_force_update_tab_label(struct search *sch)
{
    gint row;
    GtkNotebook *notebook_search_results = GTK_NOTEBOOK
        (lookup_widget(main_window, "notebook_search_results"));
    GtkCList *clist_search = GTK_CLIST
        (lookup_widget(main_window, "clist_search"));
	search_t *current_search = search_gui_get_current_search();

	if (sch == current_search || sch->unseen_items == 0)
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d)", sch->query,
				   sch->items);
	else
		gm_snprintf(tmpstr, sizeof(tmpstr), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
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

	sch->last_update_time = time(NULL);
    
}


/*
 *	gui_search_update_tab_label
 *
 *  Update the label if nothing's changed or if the last update was
 *  recent.
 */
gboolean gui_search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (time(NULL) - sch->last_update_time < TAB_UPDATE_TIME)
		return TRUE;

	gui_search_force_update_tab_label(sch);

	return TRUE;
}


/*
 *	gui_search_clear_results
 *
 */
void gui_search_clear_results(void)
{
	search_t *current_search = search_gui_get_current_search();

	search_gui_clear_search(current_search);
	gui_search_force_update_tab_label(current_search);
    gui_search_update_items(current_search);
}


/*
 * gui_search_get_colors
 *
 * Extract the mark/ignore/download color.
 */
void gui_search_get_colors(
	search_t *sch,
	GdkColor **mark_color, GdkColor **ignore_color, GdkColor **download_color)
{
    *mark_color = &(gtk_widget_get_style(GTK_WIDGET(sch->ctree))
        ->bg[GTK_STATE_INSENSITIVE]);

    *ignore_color = &(gtk_widget_get_style(GTK_WIDGET(sch->ctree))
        ->fg[GTK_STATE_INSENSITIVE]);

    *download_color =  &(gtk_widget_get_style(GTK_WIDGET(sch->ctree))
        ->fg[GTK_STATE_ACTIVE]);
}


/*
 * gui_search_history_add:
 *
 * Adds a search string to the search history combo. Makes
 * sure we do not get more than 10 entries in the history.
 * Also makes sure we don't get duplicate history entries.
 * If a string is already in history and it's added again,
 * it's moved to the beginning of the history list.
 */
void gui_search_history_add(gchar *s)
{
    GList *new_hist = NULL;
    GList *cur_hist = list_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if (n < 9 && 0 != g_ascii_strcasecmp(s,cur_hist->data)) {
            /* copy up to the first 9 items */
            new_hist = g_list_append(new_hist, cur_hist->data);
            n ++;
        } else {
            /* and free the rest */
            g_free(cur_hist->data);
        }
        cur_hist = cur_hist->next;
    }
    /* put the new item on top */
    new_hist = g_list_prepend(new_hist, g_strdup(s));

    /* set new history */
    gtk_combo_set_popdown_strings(
        GTK_COMBO(lookup_widget(main_window, "combo_search")),
        new_hist);

    /* free old list structure */
    g_list_free(list_search_history);
    
    list_search_history = new_hist;
}


/*
 * set_search_color
 *
 * Set proper search color in list depending on whether it is enabled.
 */
static void set_search_color(struct search *sch)
{
	GtkCList * clist_search;
	static GtkNotebook *notebook_search_results = NULL;

	clist_search = GTK_CLIST(
		lookup_widget(main_window, "clist_search"));

	if (notebook_search_results == NULL)
		notebook_search_results =
			GTK_NOTEBOOK(lookup_widget(main_window, "notebook_search_results"));

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


/*
 * gui_search_set_enabled
 *
 * Flag whether search is enabled.
 */
void gui_search_set_enabled(struct search *sch, gboolean enabled)
{
	gboolean was_enabled = sch->enabled;

	if (was_enabled == enabled)
		return;

	sch->enabled = enabled;

	if (enabled)
		search_start(sch->search_handle);
	else
		search_stop(sch->search_handle);

	set_search_color(sch);
}


/*
 *	search_gui_expand_all
 *
 *	Expand all nodes in tree for current search
 */
void search_gui_expand_all()
{
	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

	if (current_search == NULL)
        return;

    ctree = current_search->ctree;

	gtk_ctree_expand_recursive(ctree, NULL);	
}


/*
 *	search_gui_expand_all
 *
 *	Expand all nodes in tree for current search
 */
void search_gui_collapse_all()
{
	GtkCTree *ctree;
    search_t *current_search = search_gui_get_current_search();

	if (current_search == NULL)
        return;

    ctree = current_search->ctree;

	gtk_ctree_collapse_recursive(ctree, NULL);		
}



#endif	/* USE_GTK1 */
