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

#include <gdk/gdkkeysyms.h>

#include "gtkcolumnchooser.h"
#include "search_cb.h"
#include "search_gui.h"
#include "statusbar_gui.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

extern search_t *search_selected;

static gboolean in_autoselect = FALSE;
static gchar tmpstr[4096];

/***
 *** Private functions
 ***/


/* 
 * 	refresh_popup
 *
 *	Activates/deactivates buttons and popups based on what is selected
 *
 */
static void refresh_popup(void)
{
	gboolean sensitive;
    search_t *search;

    search = search_gui_get_current_search();

	sensitive = search && 
        (NULL != (GTK_CLIST(search->ctree))->selection);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_download"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_name"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_sha1"), sensitive);
    gtk_widget_set_sensitive
        (lookup_widget(popup_search, "popup_search_drop_host"), sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_name_global"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_sha1_global"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_drop_host_global"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_name"), 
        sensitive);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_autodownload_sha1"), 
        sensitive);   
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_new_from_selected"), 
        sensitive);   

    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_restart"), NULL != search);
    gtk_widget_set_sensitive(
        lookup_widget(popup_search, "popup_search_duplicate"), NULL != search);

    if (search) {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), 
			!search_is_frozen(search->search_handle));
		gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"),
			search_is_frozen(search->search_handle));
		if (search->passive)
            gtk_widget_set_sensitive(
                lookup_widget(popup_search, "popup_search_restart"), 
                FALSE);
    } else {
        gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_stop"), FALSE);
	    gtk_widget_set_sensitive(
            lookup_widget(popup_search, "popup_search_resume"), FALSE);
    }
}


/* 
 * 	search_cb_autoselect
 *
 *	Autoselects all searches matching given node in given tree
 *	Uses the in_autosearch flag to prevent recursive autoselecting
 */
gint search_cb_autoselect(GtkCTree *ctree, GtkCTreeNode *node, 
	gboolean search_autoselect_ident)
{
	GtkCTreeNode *auto_node;
	GtkCTreeNode *parent, *child;
	GtkCTreeRow *row;
	record_t *rc, *rc2;
    guint32 fuzzy_threshold;
	gboolean child_selected, node_expanded;
	gint x = 0;
	
	if (in_autoselect)
		return 0;	/* Prevent recursive autoselect */
	
	in_autoselect = TRUE;
	gnet_prop_get_guint32(PROP_FUZZY_THRESHOLD, &fuzzy_threshold, 0, 1);

	/* 
     * Rows with NULL data can appear when inserting new rows
     * because the selection is resynced and the row data cannot
     * be set until insertion (and therefore also selection syncing
     * is done.
     *      --BLUE, 20/06/2002
     */
	rc = (record_t *) gtk_ctree_node_get_row_data(ctree, node);
	gtk_clist_freeze(GTK_CLIST(ctree));
	
    /* Search whole ctree for nodes to autoselect 
     */			
	for (x = 1, auto_node = GTK_CTREE_NODE(GTK_CLIST(ctree)->row_list);
		(NULL != auto_node) && (NULL != rc);
		auto_node = GTK_CTREE_NODE_NEXT (auto_node)) {			
       
		if (NULL == auto_node)
			continue;
			
		rc2 = (record_t *) gtk_ctree_node_get_row_data(ctree, auto_node);

        /*
         * Skip the line we selected in the first place.
         */
        if (rc == rc2)
        	continue;

        if (rc2 == NULL) {
        	g_warning(" on_ctree_search_results_select_row: "
            			"detected row with NULL data, skipping.");
            continue;
		}

		parent = GTK_CTREE_NODE(auto_node);
		row = GTK_CTREE_ROW(parent);
		
		/* If auto_node is a child node, we skip it cause it will be handled 
		 * when we come to it's parent 
		 */
		if(NULL != row->parent)
			continue; 			
		
		child = row->children;
		if (NULL != child) /* If the node has children */
		{
			/* A header node.  We expand it and check all of the children 
			 * If one of the children get selected keep node expanded,
			 * if it was initially collapsed, collapse it again
			 */				
			child_selected = FALSE;
			node_expanded = FALSE;

			node_expanded = gtk_ctree_is_viewable(ctree, child);
			gtk_ctree_expand(ctree, parent);
			
			for (; NULL != child; row = GTK_CTREE_ROW(child), 
				child = row->sibling) {		

				rc2 = gtk_ctree_node_get_row_data (ctree, child);
		    
				if (rc == rc2)
	        		continue;
	
	            if (search_autoselect_ident) {
       		    	if ((rc->size == rc2->size && rc->sha1 != NULL && 
						rc2->sha1 != NULL &&
                        memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) 
						|| ((rc->sha1 == NULL) && (rc2->size == rc->size) && 
						((!search_autoselect_fuzzy && 
						!strcmp(rc2->name, rc->name)) || 
						(search_autoselect_fuzzy &&
(fuzzy_compare(rc2->name, rc->name) * 100 >= (fuzzy_threshold << FUZZY_SHIFT)))
                    	))) {
							gtk_ctree_select(ctree, child);
							child_selected = TRUE;	                      
							x++;
                    }
                } else {
                   	if (((rc->sha1 != NULL && rc2->sha1 != NULL &&
                	    memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) || 
                        (rc2 && !strcmp(rc2->name, rc->name))) &&
                        (rc2->size >= rc->size)) {
							
						gtk_ctree_select(ctree, child);
						child_selected = TRUE;	                      
   	                    x++;
                   	}
				}
			}         				
			if ((!child_selected) && (!node_expanded))
				gtk_ctree_collapse(ctree, parent);
		}

		/* Reget rc2 in case we overwrote it while parsing the children */
		rc2 = (record_t *) gtk_ctree_node_get_row_data(ctree, auto_node);

        if (search_autoselect_ident) {
			if ((
            	/*
				 * size check added to workaround buggy
                 * servents. -vidar, 2002-08-08
				 */
                rc->size == rc2->size && 
                rc->sha1 != NULL && rc2->sha1 != NULL &&
                memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0
			) || (
                (rc->sha1 == NULL) && 
                (rc2->size == rc->size) && (
                (!search_autoselect_fuzzy &&
				!strcmp(rc2->name, rc->name)) ||
                (search_autoselect_fuzzy &&
(fuzzy_compare(rc2->name, rc->name) * 100 >= (fuzzy_threshold << FUZZY_SHIFT)))
                )
                )) {
                
				gtk_ctree_select(ctree, auto_node);
              	x++;
			}
		} else {
            
			if (((rc->sha1 != NULL && rc2->sha1 != NULL &&
               	memcmp(rc->sha1, rc2->sha1, SHA1_RAW_SIZE) == 0) || 
                (rc2 && !strcmp(rc2->name, rc->name))) &&
                (rc2->size >= rc->size)) {
				
				gtk_ctree_select(ctree, auto_node);
                x++;
            }
		}	
	} /* for */
	
	gtk_clist_thaw(GTK_CLIST(ctree));
	
	gtk_widget_queue_draw((GtkWidget *) ctree); /* Force redraw */
	in_autoselect = FALSE;
	return x;
}




/***
 *** Glade callbacks
 ***/
void on_combo_entry_searches_activate
    (GtkEditable *editable, gpointer user_data)
{
    /* FIXME */
}


/* 
 * 	on_search_popdown_switch
 */
void on_search_popdown_switch(GtkWidget *w, gpointer data)
{
	if (search_selected != NULL)
        search_gui_set_current_search(search_selected);
}


/* 
 * 	on_search_notebook_switch
 *
 *	When the user switches notebook tabs, update the rest of GUI
 *
 *	This may be obsolete as we removed the tabbed interface --Emile 27/12/03
 */
void on_search_notebook_switch(GtkNotebook * notebook, GtkNotebookPage * page, 
	gint page_num, gpointer user_data)
{
	search_t *sch;

	sch = (search_t *) gtk_object_get_user_data(
		GTK_OBJECT(gtk_notebook_get_nth_page(notebook, page_num)));

	g_return_if_fail(sch);

    search_gui_set_current_search(sch);
}


/* 
 * 	on_clist_search_select_row
 *
 *	Changes current search and updates GUI
 */
void on_clist_search_select_row(GtkCList * clist, gint row, gint column, 
	GdkEvent * event, gpointer user_data)
{
    gpointer sch;

    g_assert(clist != NULL);

    sch = gtk_clist_get_row_data(clist, row);

    if (sch == NULL)
        return;

    search_gui_set_current_search((search_t *)sch);
}


/* 
 * 	on_search_selected
 */
void on_search_selected(GtkItem * i, gpointer data)
{
	search_selected = (search_t *) data;
}


/* 
 * 	on_button_search_clicked
 *
 *	Create a search based on query entered
 *
 */
void on_button_search_clicked(GtkButton *button, gpointer user_data)
{
	gchar *e = STRTRACK(gtk_editable_get_chars
        (GTK_EDITABLE(lookup_widget(main_window, "entry_search")), 0, -1));

	/*
	 * Even though we might not be on_the_net() yet, record the search.
	 * There is a callback mechanism when a new node is connected, which
	 * will launch the search there if it has not been sent already.
	 *		--patch from Mark Schreiber, 10/01/2002
	 */

    g_strstrip(e);
    if (*e) {
        filter_t *default_filter;
        search_t *search;
        gboolean res;

        /*
         * It's important gui_search_history_add is called before
         * new_search, otherwise the search entry will not be
         * cleared.
         *      --BLUE, 04/05/2002
         */
        gui_search_history_add(e);

        /*
         * We have to capture the selection here already, because
         * new_search will trigger a rebuild of the menu as a
         * side effect.
         */
        default_filter = (filter_t *)option_menu_get_selected_data
            (lookup_widget(main_window, "optionmenu_search_filter"));

		res = search_gui_new_search(e, 0, &search);

        /*
         * If we should set a default filter, we do that.
         */
        if (res && (default_filter != NULL)) {
            rule_t *rule = filter_new_jump_rule
                (default_filter, RULE_FLAG_ACTIVE);
            
            /*
             * Since we don't want to distrub the shadows and
             * do a "force commit" without the user having pressed
             * the "ok" button in the dialog, we add the rule
             * manually.
             */
            search->filter->ruleset = 
                g_list_append(search->filter->ruleset, rule);
            rule->target->refcount ++;
        }
        
        if (!res)
        	gdk_beep();
    }

	G_FREE_NULL(e);
}


/* 
 * 	on_entry_search_activate
 */
void on_entry_search_activate(GtkEditable * editable, gpointer user_data)
{
    /*
     * Delegate to: on_button_search_clicked.
     *      --BLUE, 30/04/2002
     */

	on_button_search_clicked(NULL, user_data);
}


/* 
 * 	on_entry_search_changed
 *
 *	When a search string is entered, activate the search button
 *
 */
void on_entry_search_changed(GtkEditable * editable, gpointer user_data)
{
	gchar *e = STRTRACK(gtk_editable_get_chars(editable, 0, -1));
	g_strstrip(e);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search"), *e != 0);
	G_FREE_NULL(e);
}


/* 
 * 	on_button_search_clear_clicked
 *
 *	Clear search results, de-activate clear search button
 *
 */
void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	gui_search_clear_results();

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_search_clear"), FALSE);
}


/* 
 * 	on_button_search_close_clicked
 */
void on_button_search_close_clicked(GtkButton * button, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();

    if (search != NULL)
        search_gui_close_search(search);
}


/* 
 * 	on_button_search_download_clicked
 */
void on_button_search_download_clicked(GtkButton * button, gpointer user_data)
{
    search_gui_download_files();
}


/* 
 * 	on_button_search_collapse_clicked
 */
void on_button_search_collapse_all_clicked(GtkButton *button, gpointer user_data)
{
    search_gui_collapse_all();
}


/* 
 * 	on_button_search_expand_clicked
 */
void on_button_search_expand_all_clicked(GtkButton *button, gpointer user_data)
{
    search_gui_expand_all();
}


/* 
 * 	on_clist_search_results_key_press_event
 */
gboolean on_clist_search_results_key_press_event
    (GtkWidget *widget, GdkEventKey * event, gpointer user_data)
{
    g_assert(event != NULL);

    switch(event->keyval) {
    case GDK_Return:
        search_gui_download_files();
        return TRUE;
    default:
        return FALSE;
    };
}


/* 
 * 	on_clist_search_results_button_press_event
 *
 *	Handles showing the popup in the event of right-clicks and downloading
 *	for double-clicks
 */
gboolean on_clist_search_results_button_press_event
    (GtkWidget *widget, GdkEventButton * event, gpointer user_data)
{
	gint row = 0;
	gint column = 0;
	static guint click_time = 0;
    search_t *search;

    search = search_gui_get_current_search();

	switch (event->button) {
	case 1:
        /* left click section */
		if (event->type == GDK_2BUTTON_PRESS) {
			gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
				"button_press_event");
			return FALSE;
		}
		if (event->type == GDK_BUTTON_PRESS) {
			if ((event->time - click_time) <= 250) {
				/*
				 * 2 clicks within 250 msec == doubleclick.
				 * Surpress further events
				 */
				gtk_signal_emit_stop_by_name(GTK_OBJECT(widget),
					"button_press_event");
					
				if (gtk_clist_get_selection_info(GTK_CLIST(widget), event->x,
					event->y, &row, &column)) {

					search_gui_download_files();
                    return TRUE;
				}
			} else {
				click_time = event->time;
				return FALSE;
			}
		}
		return FALSE;
   
	case 3:
        /* right click section (popup menu) */
        refresh_popup();
        {
            gboolean search_results_show_tabs;
    
            gui_prop_get_boolean(
                PROP_SEARCH_RESULTS_SHOW_TABS,
                &search_results_show_tabs, 0, 1);

            gm_snprintf(tmpstr, sizeof(tmpstr), (search_results_show_tabs) ? 
                "Show search list" : "Show tabs");
        }

        gtk_label_set(GTK_LABEL((GTK_MENU_ITEM
            (lookup_widget(popup_search, "popup_search_toggle_tabs"))
                ->item.bin.child)), tmpstr);
		gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL, 
                     event->button, event->time);
		return TRUE;

	default:
		break;
	}

	return FALSE;
}


/* 
 * 	on_button_search_filter_clicked
 */
void on_button_search_filter_clicked(
    GtkButton *button, gpointer user_data)
{
	filter_open_dialog();
}


/* 
 * 	on_clist_search_results_click_column
 *
 *	Sort search according to selected column 
 *
 */
void on_clist_search_results_click_column(
    GtkCList *clist, gint column, gpointer user_data)
{
    search_t *search;

    g_assert(clist != NULL);

    search = search_gui_get_current_search();

	if (search == NULL)
		return;

    /* rotate or initialize search order */
	if (column == search->sort_col) {
        switch (search->sort_order) {
        case SORT_ASC:
            search->sort_order = SORT_DESC;
           	break;
        case SORT_DESC:
            search->sort_order = SORT_NONE;
            break;
        case SORT_NONE:
            search->sort_order = SORT_ASC;
        }
	} else {
		search->sort_col = column;
		search->sort_order = SORT_ASC;
	}
	
	search_gui_sort_column(search, column); /* Sort column, draw arrow */
}


/*
 *	on_clist_search_results_select_row:
 *
 *	This function is called when the user selects a row in the
 *	search results pane. Autoselection takes place here.
 */
void on_ctree_search_results_select_row(GtkCTree *ctree,
	GList *node, gint column, gpointer user_data)
{
    gboolean search_autoselect;
    gboolean search_autoselect_ident;
    gboolean search_autoselect_fuzzy;
    search_t *sch;
    record_t *rc;
    gint x;
    static gboolean active = FALSE;

    if (in_autoselect || active)
	return;
	
    if (NULL == node)
	return;
	
    active = TRUE;
	
    sch = search_gui_get_current_search();
	rc = (record_t *) gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));
	
    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT, 
        &search_autoselect, 0, 1);

    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT_IDENT, 
        &search_autoselect_ident, 0, 1);

    gui_prop_get_boolean(
        PROP_SEARCH_AUTOSELECT_FUZZY, 
        &search_autoselect_fuzzy, 0, 1);


    refresh_popup();

    /* 
     * check if config setting select all is on and only autoselect if
     * only one item is selected (no way to merge two autoselections)
     */
	if (search_autoselect && 
        (GTK_CLIST(ctree)->selection != NULL) &&
        (GTK_CLIST(ctree)->selection->next == NULL)) {

		x =	search_cb_autoselect(ctree, GTK_CTREE_NODE(node), 
			search_autoselect_ident); 
   
        if (x > 1) {
            statusbar_gui_message(15, 
                "%d auto selected %s",
                x, (rc->sha1 != NULL) ? 
                    "by urn:sha1 and filename" : "by filename");
        } else if (x == 1) {
            statusbar_gui_message(15, "none auto selected");
        }
	} 


	/* The following code will select all the children of a parent, if that
	 * parent is selected. This isn't necessary because when a node is closed
	 * it's children are already selected.  This would only be useful if 
	 * someone opened a node and then clicked on the parent... in which case
	 * they likely wouldn't want to select all the children.  Regardless,
	 * we may want this later --- Emile
	 */

#if 0
	/* If a parent node is selected, select all children */
	if (GTK_CLIST(ctree)->selection != NULL) {

		rc = gtk_ctree_node_get_row_data(ctree, GTK_CTREE_NODE(node));
		if (NULL != rc->sha1) {

			key = atom_sha1_get(rc->sha1);
			parent = find_parent_with_sha1(sch->parents, key);
		
			if (NULL != parent) {
			
				parent_row = GTK_CTREE_ROW(parent);
								
				/* A parent exists with that sha1, is it the selected node? */
				if ((parent == GTK_CTREE_NODE(node)) 
					&& (NULL != parent_row->children)) {
					gtk_ctree_select_recursive(ctree, GTK_CTREE_NODE(node));				
				}
			}
			
			atom_sha1_free(key);
		}	
	}
#endif

    active = FALSE;
}


/* 
 * 	on_clist_search_results_unselect_row
 */
void on_ctree_search_results_unselect_row(
    GtkCTree *ctree, GList *node, gint column, gpointer user_data)
{
    refresh_popup();
}


/* 
 * 	on_ctree_search_results_resize_column
 */
void on_ctree_search_results_resize_column(
    GtkCList * clist, gint column, gint width, gpointer user_data)
{
    guint32 buf = width;

    /* remember the width for storing it to the config file later */
    gui_prop_set_guint32(PROP_SEARCH_RESULTS_COL_WIDTHS, &buf, column, 1);
}


/* 
 * 	on_button_search_passive_clicked
 *
 *	Please add comment
 *
 */
void on_button_search_passive_clicked(
    GtkButton *button, gpointer user_data)
{
    filter_t *default_filter;
	search_t *search;

    /*
     * We have to capture the selection here already, because
     * new_search will trigger a rebuild of the menu as a
     * side effect.
     */
    default_filter = (filter_t *)
        option_menu_get_selected_data
            (lookup_widget(main_window, "optionmenu_search_filter"));

	search_gui_new_search("Passive", SEARCH_PASSIVE, &search);

    /*
     * If we should set a default filter, we do that.
     */
    if (default_filter != NULL) {
        rule_t *rule = filter_new_jump_rule
            (default_filter, RULE_FLAG_ACTIVE);
            
        /*
         * Since we don't want to distrub the shadows and
         * do a "force commit" without the user having pressed
         * the "ok" button in the dialog, we add the rule
         * manually.
         */
        search->filter->ruleset = 
            g_list_append(search->filter->ruleset, rule);
        rule->target->refcount ++;
    }
}



/***
 *** Search results popup
 ***/


/* 
 * 	search_cb_collect_ctree_data
 *
 *	Given a GList of GtkCTreeNodes, return a new list pointing to the row data 
 *	List will have to be freed later on.
 */
GList *search_cb_collect_ctree_data(GtkCTree *ctree, GList *node_list)
{
	GList *data_list = NULL;
	record_t *rc;
	
	for(; node_list != NULL; node_list = g_list_next(node_list)) {
	
		if(node_list->data != NULL) {
			rc = gtk_ctree_node_get_row_data(ctree, node_list->data);
			data_list = g_list_append(data_list, rc);
		}
	}
	
	data_list = g_list_first(data_list);
	return data_list;
}



/* 
 * 	on_popup_search_drop_name_activate
 *
 *	For all selected results, create a filter based on name
 */
void on_popup_search_drop_name_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_name_rule, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_drop_sha1_activate
 *
 *	For all selected results, create a filter based on sha1
 */
void on_popup_search_drop_sha1_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_sha1_rule, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_drop_host_activate
 *
 *	For all selected results, create a filter based on host
 */
void on_popup_search_drop_host_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_host_rule, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_drop_name_global_activate
 *
 *	For all selected results, create a global filter based on name
 */
void on_popup_search_drop_name_global_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_name_rule, 
		filter_get_global_pre());

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_drop_sha1_global_activate
 *
 *	For all selected results, create a global filter based on sha1
 *
 */
void on_popup_search_drop_sha1_global_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_sha1_rule, 
		filter_get_global_pre());

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_drop_host_global_activate
 *
 *	For all selected results, create a global filter based on host
 *
 */
void on_popup_search_drop_host_global_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_drop_host_rule, 
		filter_get_global_pre());

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_autodownload_name_activate
 *
 *	Please add comment
 *
 */
void on_popup_search_autodownload_name_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_download_name_rule, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_autodownload_sha1_activate
 *
 *	Please add comment
 *
 */
void on_popup_search_autodownload_sha1_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) filter_add_download_sha1_rule, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_new_from_selected_activate
 *
 *	Please add comment
 *
 */
void on_popup_search_new_from_selected_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    GList *node_list, *data_list = NULL;
    search_t *search;

    search = search_gui_get_current_search();
    g_assert(search != NULL);

    gtk_clist_freeze(GTK_CLIST(search->ctree));
	
	node_list = g_list_copy(GTK_CLIST(search->ctree)->selection);
	data_list = search_cb_collect_ctree_data(search->ctree, node_list);
	
    g_list_foreach(data_list, (GFunc) gui_add_targetted_search, 
		search->filter);

    gtk_clist_thaw(GTK_CLIST(search->ctree));
	g_list_free(data_list);
	g_list_free(node_list);
}


/* 
 * 	on_popup_search_edit_filter_activate
 */
void on_popup_search_edit_filter_activate(GtkMenuItem * menuitem, 
	gpointer user_data)
{
    filter_open_dialog();
}


/* 
 * 	on_popup_search_duplicate_activate
 *
 *	Create a new search identical to the current search
 * 	Note: Doesn't duplicate filters or passive searches yet
 */
void on_popup_search_duplicate_activate(GtkMenuItem * menuitem,	
	gpointer user_data)
{
    search_t *search;
    guint32 timeout;

    gnet_prop_get_guint32_val(PROP_SEARCH_REISSUE_TIMEOUT, &timeout);

    search = search_gui_get_current_search();
    /* FIXME: should also duplicate filters! */
    /* FIXME: should call search_duplicate which has to be written. */
    /* FIXME: should properly duplicate passive searches. */
	if (search)
		search_gui_new_search_full(search->query, 0,
			timeout, search->sort_col, search->sort_order,
			search->enabled ? SEARCH_ENABLED : 0, NULL);
}


/* 
 * 	on_popup_search_restart_activate
 */
void on_popup_search_restart_activate(GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search)
		search_gui_restart_search(search);
}


/* 
 * 	on_popup_search_resume_activate
 */
void on_popup_search_resume_activate(GtkMenuItem * menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search)
		gui_search_set_enabled(search, TRUE);
}


/* 
 * 	on_popup_search_stop_activate
 *
 *	Stop current search
 */
void on_popup_search_stop_activate
    (GtkMenuItem *menuitem, gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
	if (search)
		gui_search_set_enabled(search, FALSE);
}


/* 
 * 	on_popup_search_config_cols_activate
 *
 *	Please add comment
 *
 */
void on_popup_search_config_cols_activate(GtkMenuItem * menuitem,
	gpointer user_data)
{
    search_t *search;

    search = search_gui_get_current_search();
    g_return_if_fail(search != NULL);
    g_assert(search->ctree != NULL);

    {
        GtkWidget * cc;

        /* FIXME: needs to work also in Gtk2 or be replaced. */
        cc = gtk_column_chooser_new(GTK_WIDGET(search->ctree));
        gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1, 0);

        /* GtkColumnChooser takes care of cleaning up itself */
    }
}


/* 
 * 	on_popup_search_expand_all_activate
 */
void on_popup_search_expand_all_activate(GtkMenuItem *menuitem, 
	gpointer user_data)
{
    search_gui_expand_all();

}


/* 
 * 	on_popup_search_collapse_all_activate
 */
void on_popup_search_collapse_all_activate(GtkMenuItem *menuitem,
	gpointer user_data)
{
    search_gui_collapse_all();

}

#endif	/* USE_GTK1 */
