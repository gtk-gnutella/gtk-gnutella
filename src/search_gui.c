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

/* System includes */
#include <ctype.h>
#include <gtk/gtk.h>
#include <sys/stat.h>

RCSID("$Id$");

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

static gchar tmpstr[4096];

GList *searches = NULL;		/* List of search structs */
search_t *search_selected = NULL;
static GList *list_search_history = NULL;

/*
 * Private function prototypes
 */
static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2);
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
	record_t *rc;

	rc = gtk_ctree_node_get_row_data(ctree, node);
	search_gui_unref_record(rc);	
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
    gint sort_col = SORT_NO_COL, sort_order = SORT_NONE;
	
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
    gchar *titles[3];
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
gint search_gui_compare_records(
	gint sort_col, const record_t *r1, const record_t *r2)
{
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
				if (r1->count == r2->count)
					result = 0;
				else
					result = (r1->count > r2->count) ? +1 : -1;
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
 * search_gui_sort_column
 *
 * Draws arrows for the given column of the GtkCTree and 
 * sorts the contents of the GtkCTree according to the 
 * sorting parameters set in search
 */
void search_gui_sort_column(search_t *search, gint column)
{
    GtkWidget * cw = NULL;

    /* set compare function */
	gtk_clist_set_compare_func
        (GTK_CLIST(search->ctree), search_results_compare_func);

   /* destroy existing arrow */
    if (search->arrow != NULL) { 
        gtk_widget_destroy(search->arrow);
        search->arrow = NULL;
    }     

    /* set sort type and create arrow */
    switch (search->sort_order) {
    case SORT_ASC:
        search->arrow = create_pixmap(main_window, "arrow_up.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(search->ctree),
            GTK_SORT_ASCENDING);
        break;  
    case SORT_DESC:
        search->arrow = create_pixmap(main_window, "arrow_down.xpm");
        gtk_clist_set_sort_type(
            GTK_CLIST(search->ctree),
            GTK_SORT_DESCENDING);
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
        gtk_clist_set_sort_column(GTK_CLIST(search->ctree), column);


		/* FIXME 
		 * GTK uses a merge sort algorithm to sort the column items using our
		 * function (search_gui_compare_records) as the comparation function.
		 * this is too slow.  However, I tried writing a custom quicksort 
		 * algorithm and the results weren't much better.  It's possible to 
		 * cast the ctree as a clist and use the clist sort function but this
		 * is just about as slow, doing this just ignores child nodes.  We need 
		 * to fix this somehow. --- Emile Jan 03, 2004
		 */
        gtk_ctree_sort_node(search->ctree, NULL);
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
  	gchar *titles[5];
	gint count;
	gpointer key = NULL;
	gboolean is_parent = FALSE;
    struct results_set *rs = rc->results_set;
	record_t *parent_rc, *rc2;

	GtkCTreeNode *parent, *node, *cur_node, *sibling;
	GtkCTreeRow *row, *parent_row;
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
	titles[c_sr_filename] = (NULL != rc->name) ?
		atom_str_get(rc->name) : atom_str_get("");
	titles[c_sr_info] = (NULL != rc->info) ?
		atom_str_get(rc->info) : atom_str_get("");
	titles[c_sr_sha1] = (NULL != rc->sha1) ?
		atom_str_get(sha1_base32(rc->sha1)) : atom_str_get("");
	titles[c_sr_size] = atom_str_get("");
	titles[c_sr_count] = atom_str_get("");

	titles[c_sr_host] = (NULL == rs->hostname) ?
		atom_str_get(ip_port_to_gchar(rs->ip, rs->port)) :
		atom_str_get(hostname_port_to_gchar(rs->hostname, rs->port));

	gm_snprintf(tmpstr, sizeof(tmpstr), "%u", rs->speed);
	titles[c_sr_speed] = atom_str_get(tmpstr);


	
	/*Add the search result to the ctree */
	if (NULL != rc->sha1) {

		/* We use the sch->parents hash table to store pointers to all the
		 * parent tree nodes referenced by their atomized sha1.
		 */
		key = atom_sha1_get(rc->sha1);
		parent = find_parent_with_sha1(sch->parents, key);

		if (NULL != parent) {
			/* A parent exists with that sha1, add as child to that parent */
			node = gtk_ctree_insert_node(ctree, parent, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
			
			/*Update the "#" column of the parent, +1 for parent */			
			count = count_node_children(ctree, parent) + 1;			
			gm_snprintf(tmpstr, sizeof(tmpstr), "%u", count); 
			gtk_ctree_node_set_text(ctree, parent, c_sr_count, tmpstr); 

			/* Update count in the records (use for column sorting) */
			rc->count = count;
			parent_rc = gtk_ctree_node_get_row_data(ctree, parent);
			parent_rc->count = count;
			is_parent = FALSE;
			
 			/* we need only the reference for new parents */
			atom_sha1_free(key);

		} else { 

			atom_str_free(titles[c_sr_size]);		
			titles[c_sr_size] = atom_str_get(short_size(rc->size));

			/* Add node as a parent */
			node = gtk_ctree_insert_node(ctree, parent = NULL, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
			add_parent_with_sha1(sch->parents, key, node);

			/* Update count in the records (use for column sorting) */
			rc->count = 1;
			is_parent = TRUE;
		}
		
	} else { /* Add node as a parent with no SHA1 */ 
		atom_str_free(titles[c_sr_size]);		
		titles[c_sr_size] = atom_str_get(short_size(rc->size));

		node = gtk_ctree_insert_node(ctree, parent = NULL, NULL, titles, 5, 
				NULL, NULL, NULL, NULL, 0, 0);
		/* Update count in the records (use for column sorting) */
		rc->count = 1;
		is_parent = TRUE;
	}
	
	atom_str_free(titles[c_sr_filename]);
	atom_str_free(titles[c_sr_speed]);
	atom_str_free(titles[c_sr_host]);
	atom_str_free(titles[c_sr_sha1]);
	atom_str_free(titles[c_sr_info]);
	atom_str_free(titles[c_sr_count]);
	atom_str_free(titles[c_sr_size]);
	
	search_gui_ref_record(rc);

    gtk_ctree_node_set_row_data(ctree, node, (gpointer) rc);

    if (sch->sort) {
		/*
		 * gtk_clist_set_auto_sort() can't work for row data based sorts!
		 * Too bad. The problem is, that our compare callback wants to
         * extract the record from the row data. But since we have not
         * yet added neither the row nor the row data, this does not
         * work.
		 * So we need to find the place to put the result by ourselves.
		 */
		
		/* FIXME
		 * For some reason autosort is broken on the count column. --- Emile
		 */
		if (is_parent) {
			
			parent = NULL;
			sibling = NULL;
			
			/* Traverse the entire search tree */
			for (cur_node = GTK_CTREE_NODE(GTK_CLIST(sch->ctree)->row_list);
				(NULL != cur_node); cur_node = GTK_CTREE_NODE_NEXT (cur_node)) {			

				row = GTK_CTREE_ROW(cur_node);

				/* If node is a child node, we skip it */
				if (NULL != row->parent)
				continue; 			
		
				rc2 = (record_t *) gtk_ctree_node_get_row_data(ctree, cur_node);
	
				if (rc == rc2)
					continue;
				
				if(SORT_ASC == sch->sort_order) {
 	            	if (search_gui_compare_records(sch->sort_col, rc, rc2) < 0){
						sibling = cur_node;
						break;
					} 
				} else { /* SORT_DESC */
					if (search_gui_compare_records(sch->sort_col, rc, rc2) > 0){
						sibling = cur_node;
						break;
					}
				}
			}
		} else { /* Is a child node */
		
			row = GTK_CTREE_ROW(node);
			parent = row->parent;
			g_assert(NULL != parent);
			sibling = NULL;
			
			parent_row = GTK_CTREE_ROW(node);
			cur_node = parent_row->children; /* start looking at first child */

			for (; NULL != cur_node; row = GTK_CTREE_ROW(cur_node), 
					cur_node = row->sibling) {		

				rc2 = (record_t *) gtk_ctree_node_get_row_data(ctree, cur_node);
	
				if(SORT_ASC == sch->sort_order) {
 	            	if (search_gui_compare_records(sch->sort_col, rc, rc2) < 0){
						sibling = cur_node;
						break;
					}
				} else { /* SORT_DESC */
					if (search_gui_compare_records(sch->sort_col, rc, rc2) > 0){
						sibling = cur_node;
						break;
					}
				}
			}
		}

		gtk_ctree_move(ctree, node, parent, sibling);
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
	record_t *rc = NULL, *parent_rc, *child_rc;
	gint n;
	GtkCTreeRow *row, *child_row;
	GtkCTreeNode *child_node, *old_parent;
	gchar *filename, *info, *size, *sha1, *host, *speed;

	search_t *current_search = search_gui_get_current_search();
    current_search->items--;

	/* First get the record, it must be unreferenced at the end */
	rc = gtk_ctree_node_get_row_data(ctree, node);

	g_assert(rc->refcount > 1);

	row = GTK_CTREE_ROW(node);
	if (NULL == row->parent) {

		/* It has no parents, therefore it must be a parent.
		 * If it has children, then we are removing the parent but not the
		 * children 
		 */		
		n = count_node_children(ctree, node);
		if (0 < n) {

			/* Copy data from first child into the parent node */
			child_node = row->children;	/* The first child of node */

			child_rc = gtk_ctree_node_get_row_data(ctree, child_node);
			filename = (NULL != child_rc->name) ?
				atom_str_get(child_rc->name) : atom_str_get("");
			info = (NULL != child_rc->info) ?
				atom_str_get(child_rc->info) : atom_str_get("");
			sha1 = (NULL != child_rc->sha1) ?
				atom_str_get(sha1_base32(child_rc->sha1)) : atom_str_get("");
			size = atom_str_get(short_size(child_rc->size));

			host = (NULL == child_rc->results_set->hostname) ?
				atom_str_get(ip_port_to_gchar(child_rc->results_set->ip, 
					child_rc->results_set->port)) :
				atom_str_get(hostname_port_to_gchar(
				child_rc->results_set->hostname, child_rc->results_set->port));

			gm_snprintf(tmpstr, sizeof(tmpstr), "%u", 
				child_rc->results_set->speed);
			speed = atom_str_get(tmpstr);
			
			/* Calculate # column */
			n = count_node_children(ctree, node);
			if (1 < n)
				gm_snprintf(tmpstr, sizeof(tmpstr), "%u", n); 
			else
				*tmpstr = '\0';

			/* Update record count, child_rc will become the rc for the parent*/
			child_rc->count = n;
			
			/* Now actually modify the old parent node */
			gtk_ctree_node_set_text(ctree, node, c_sr_filename, filename);		
			gtk_ctree_node_set_text(ctree, node, c_sr_info, info);		
			gtk_ctree_node_set_text(ctree, node, c_sr_size, size);		
			gtk_ctree_node_set_text(ctree, node, c_sr_sha1, sha1);		
			gtk_ctree_node_set_text(ctree, node, c_sr_count, tmpstr);		
			gtk_ctree_node_set_text(ctree, node, c_sr_speed, speed);		
			gtk_ctree_node_set_text(ctree, node, c_sr_host, host);		
			gtk_ctree_node_set_row_data(ctree, node, (gpointer) child_rc);

			/* Delete the 1st child node, now that we've copied the data */
			gtk_ctree_remove_node(ctree, child_node);

			atom_str_free(sha1);
			atom_str_free(filename);
			atom_str_free(info);
			atom_str_free(size);
			atom_str_free(speed);
			atom_str_free(host);
			
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
	
		parent_rc = gtk_ctree_node_get_row_data(ctree, old_parent);
		parent_rc->count = n;
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
	struct record *rc;
	gboolean need_push;
	GList *sel_list;
    gboolean remove_downloaded;
	guint created = 0;
	guint count = 0;

	GtkCTreeNode *node;
	search_t *current_search = search_gui_get_current_search();

    gnet_prop_get_boolean_val(PROP_SEARCH_REMOVE_DOWNLOADED,
		&remove_downloaded);

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

		rc = (struct record *) gtk_ctree_node_get_row_data(ctree, node);		

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

static gint search_results_compare_func
    (GtkCList * clist, gconstpointer ptr1, gconstpointer ptr2)
{
    const record_t *s1 = (const record_t *) ((const GtkCListRow *) ptr1)->data;
	const record_t *s2 = (const record_t *) ((const GtkCListRow *) ptr2)->data;

    return search_gui_compare_records(clist->sort_column, s1, s2);
}

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
    
	gtk_widget_set_sensitive(GTK_WIDGET(combo_searches), searches != NULL);
	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_search_close"), searches != NULL);

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

    ctree = current_search->ctree;

	gtk_ctree_collapse_recursive(ctree, NULL);		
}



#endif	/* USE_GTK1 */
