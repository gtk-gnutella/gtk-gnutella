/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Richard Eckart
 *
 * Functions that should be in gtk+-1.2 or gtk+-2.x but are not.
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
#include "gtk-missing.h"
#include "override.h"		/* Must be the last header included */

RCSID("$Id$");

/*
 * gtk_paned_get_position:
 *
 * Get position of divider in a GtkPaned. (in GTK2)
 */
#ifndef USE_GTK2
gint gtk_paned_get_position(GtkPaned *paned) 
{
    g_return_val_if_fail(paned != NULL, -1);
    g_return_val_if_fail(GTK_IS_PANED (paned), -1);

    return paned->child1_size;
}
#endif

/*
 * gtk_clist_set_column_name:
 *
 * Set the internal name of the column without changing the
 * column header widget. (Copy paste internal column_title_new
 * from gtkclist.c)
 * BEWARE: EVIL HACK
 */
void gtk_clist_set_column_name(GtkCList * clist, gint col, gchar * t)
{
    if (col < 0 || col >= clist->columns)
        return;

    if (clist->column[col].title)
        G_FREE_NULL(clist->column[col].title);

    clist->column[col].title = g_strdup(t);
}


/*
 * gtk_main_flush:
 *
 * Process all pending gtk events (i.e. draw now!)
 * Returns TRUE if gtk_main_quit has been called 
 * for the innermost mainloop. Aborts flush if
 * gtk_main_quit has been called.
 */
gint gtk_main_flush(void) 
{
    gint val = FALSE;

    while (!val && gtk_events_pending())
        val = gtk_main_iteration_do(FALSE);

    return val;
}



/*
 * Select the menu item which has given data attached to it.
 */
void option_menu_select_item_by_data(GtkWidget *m, gpointer *d)
{
    GList *l;
    gint n = 0;
    GtkWidget *menu;

    g_assert(m != NULL);
    g_assert(GTK_IS_OPTION_MENU(m));

    menu = GTK_WIDGET(gtk_option_menu_get_menu(GTK_OPTION_MENU(m)));

    for (l = GTK_MENU_SHELL(menu)->children; l != NULL; l = g_list_next(l)) {
        if (l->data != NULL) {
            if (gtk_object_get_user_data((GtkObject *) l->data) == d) {
                gtk_option_menu_set_history(GTK_OPTION_MENU(m), n); 
                break;
            }
        }

        n ++;
    }

    if (l == NULL)
        g_warning("option_menu_select_item_by_data: no item with data %p", d);
}



/*
 * Add a new menu item to the GtkMenu m, with the label l and
 * the data d.
 */
GtkWidget *menu_new_item_with_data(GtkMenu * m, gchar * l, gpointer d )
{
    GtkWidget *w;                                                     
                         
    g_assert(l != NULL);
                                                 
    w = gtk_menu_item_new_with_label(l);                              
    gtk_object_set_user_data((GtkObject *)w, (gpointer)d);            
    gtk_widget_show(w);                                               
    gtk_menu_append(m, w);    
    return w;
}


/*
 * Fetches the data set associated with the selected menu item in 
 * the GtkOptionMenu m.
 */
gpointer option_menu_get_selected_data(GtkWidget *m)
{
    GtkWidget *menu;

    g_assert(GTK_IS_OPTION_MENU(m));

    menu = gtk_menu_get_active
        (GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(m))));

    return (menu != NULL) ? gtk_object_get_user_data(GTK_OBJECT(menu)) : NULL;
}


/*
 * radiobutton_get_active_in_group:
 * 
 * Given a radio button it returns a pointer to the active radio
 * button in the group the given button is in. 
 * Returns NULL if there is no active button.
 */
GtkWidget *radiobutton_get_active_in_group(GtkRadioButton *rb)
{
    GSList *i;

    g_assert(rb != NULL);

    for (i = gtk_radio_button_group(rb); i != NULL; i = g_slist_next(i)) {
        GtkToggleButton *tb = GTK_TOGGLE_BUTTON(i->data);

        if (gtk_toggle_button_get_active(tb))
            return GTK_WIDGET(tb);
    }

    return NULL;
}


/*
 * gtk_entry_printf:
 *
 * printf into a gtk_entry.
 */
void gtk_entry_printf(GtkEntry *entry, const gchar *format, ...)
{
    static gchar buf[1024];
    va_list args;

    g_assert(entry != NULL);

    va_start(args, format);

    if (format != NULL)
        gm_vsnprintf(buf, sizeof(buf), format, args);
    else
        buf[0] = '\0';

    gtk_entry_set_text(entry, buf);

    va_end(args);
}

/*
 * gtk_label_printf:
 *
 * printf into a GtkLabel.
 */
void gtk_label_printf(GtkLabel *label, const gchar *format, ...)
{
    static gchar buf[1024];
    va_list args;

    g_assert(label != NULL);

    va_start(args, format);
    
    if (format != NULL)
        gm_vsnprintf(buf, sizeof(buf), format, args);
    else
        buf[0] = '\0';

    gtk_label_set_text(label, buf);

    va_end(args);
}

/*
 * gtk_mass_widget_set_sensitive:
 *
 * Takes a NULL terminated array of strings which are supposed to
 * be widgets names found with the given top-level widget. Sets all
 * to the given sentitivity state.
 */
void gtk_mass_widget_set_sensitive
    (GtkWidget *toplevel, gchar *list[], gboolean b)
{
    guint n;
    GtkWidget *w;
    
    g_assert(toplevel != NULL);

    for (n = 0; list[n] != NULL; n ++) {
        w = lookup_widget(toplevel, list[n]);
        gtk_widget_set_sensitive(w, b);
    }
}

/*
 * clist_collect_data:
 *
 * Fetch data from the selection of a clist. Returns a GSList containing
 * the user_data pointers from the selected rows. If allow_null is TRUE,
 * the returned list may contain NULL pointers. If cfn != NULL, it will
 * be used to determine whether two entries are equal and drop all duplicate
 * items from the result list. Using cfn will significantly increase runtime.
 */
GSList *clist_collect_data(GtkCList *clist, gboolean allow_null, 
    GCompareFunc cfn)
{
    GSList *result_list = NULL;
    GList *l;
    GSList *sl;
    GSList *to_unselect = NULL;

    g_assert(clist != NULL);
    
    /*
     * Collect the data of the selected rows.
     */
    for (l = clist->selection; l != NULL; l = g_list_next(l)) {
        gpointer data;
        gint row;
         
        row = GPOINTER_TO_INT(l->data);
        data = gtk_clist_get_row_data(clist, row);
 
        if ((data != NULL) || allow_null) {
            if (cfn != NULL) {
                if (g_slist_find_custom(result_list, data, cfn) != NULL) {
                    if (gui_debug >= 3) {
                        const gchar *name = 
                            gtk_widget_get_name(GTK_WIDGET(clist));
                        printf("%s has duplicate data: %p\n",
                            (name != NULL) ? name : "<UNKNOWN>", data);
                    }
                    to_unselect =
						g_slist_prepend(to_unselect, GINT_TO_POINTER(row));
                    continue;
                }
            }
            result_list = g_slist_prepend(result_list, data);
            to_unselect = g_slist_prepend(to_unselect, GINT_TO_POINTER(row));
        } else {
            if (gui_debug >= 3) {
                const gchar *name = gtk_widget_get_name(GTK_WIDGET(clist));
                printf("%s contains NULL data in row %d\n",
                    (name != NULL) ? name : "<UNKNOWN>", row);
            }
        }
    }

    /*
     * Unselect the rows from which data has been sucessfully gathered.
     */
    for (sl = to_unselect; sl != NULL; sl = g_slist_next(sl))
        gtk_clist_unselect_row(clist, GPOINTER_TO_INT(sl->data), 0);

    g_slist_free(to_unselect);

    return result_list;
}


#ifdef USE_GTK2

/*
 * w_tree_iter_new:
 * 
 * Returns a pointer to a newly allocated GtkTreeIter. Must be freed
 * with w_tree_iter_free().  
 */
GtkTreeIter *w_tree_iter_new(void)
{
	return walloc(sizeof(GtkTreeIter));
}

/*
 * w_tree_iter_copy:
 *
 * Same as gtk_tree_iter_copy() but uses walloc(). Use w_tree_iter_free()
 * to free the returned GtkTreeIter.
 */
GtkTreeIter *w_tree_iter_copy(GtkTreeIter *iter)
{
	GtkTreeIter *copy;

	copy = walloc(sizeof(*copy));
	memcpy(copy, iter, sizeof(*copy));
	return copy;
}

/*
 * w_tree_iter_free:
 *
 * Use this to free a GtkTreeIter returned by w_tree_iter_copy().
 */
void w_tree_iter_free(GtkTreeIter *iter)
{
	wfree(iter, sizeof(*iter));
}

typedef struct collect_data_struct {
    GSList *results;
    GSList *to_unselect;
	GCompareFunc cfn;
	const gchar *name; /* name of the treeview widget (for debugging) */
} collect_data_struct_t;

static void tree_selection_collect_data_helper(GtkTreeModel *model,
	GtkTreePath *path, GtkTreeIter *iter, gpointer user_data)
{
	collect_data_struct_t *cdata = user_data;
	gpointer data = NULL;

	g_assert(NULL != cdata);
	gtk_tree_model_get(model, iter, c_sr_record, &data, (-1));
	g_assert(NULL != data);

	cdata->to_unselect = g_slist_prepend(cdata->to_unselect,
								w_tree_iter_copy(iter));
	if (NULL != cdata->cfn &&
		NULL != g_slist_find_custom(cdata->results, data, cdata->cfn)) {
		if (gui_debug >= 3)
			g_warning("%s has duplicate data: %p", cdata->name, data);
		return;
	}
	cdata->results = g_slist_prepend(cdata->results, data);
}

static void tree_selection_unselect_helper(gpointer data, gpointer user_data)
{
	gtk_tree_selection_unselect_iter((GtkTreeSelection *) user_data,
		(GtkTreeIter *) data);
	w_tree_iter_free((GtkTreeIter *) data);
}

/*
 * tree_selection_collect_data:
 *
 * Fetch data from the selection of a treeview. Returns a GSList containing
 * the user_data pointers from the selected rows. If cfn != NULL, it will
 * be used to determine whether two entries are equal and drop all duplicate
 * items from the result list. Using cfn will significantly increase runtime.
 */
GSList *tree_selection_collect_data(GtkTreeSelection *selection,
	GCompareFunc cfn)
{
	collect_data_struct_t cdata;

    g_assert(NULL != selection);

	cdata.results = NULL;
	cdata.to_unselect = NULL;
	cdata.cfn = cfn;
	if (gui_debug >= 3) {
		cdata.name = gtk_widget_get_name(
			GTK_WIDGET(gtk_tree_selection_get_tree_view(selection)));
		if (NULL == cdata.name)
			cdata.name = "<UNKNOWN>";
	} else
		cdata.name = NULL;

    /*
     * Browse selected rows and gather data.
     */
	gtk_tree_selection_selected_foreach(selection,
		tree_selection_collect_data_helper, (gpointer) &cdata);

    /*
     * Now unselect the rows from which we got data.
     */
	g_slist_foreach(cdata.to_unselect,
		tree_selection_unselect_helper, selection);

    /*
     * Cleanup before exit.
     */
    g_slist_free(cdata.to_unselect);

    return cdata.results;
}

void tree_view_save_widths(GtkTreeView *treeview, property_t prop)
{
	gint i;

	for (i = 0; /* empty */ ; i++) {
		GtkTreeViewColumn *column;
		guint32 width;

		column = gtk_tree_view_get_column(treeview, i);
		if (NULL == column)
			break;

		width = gtk_tree_view_column_get_width(column);
		gui_prop_set_guint32(prop, &width, i, 1);
	}
}

#endif /* USE_GTK2 */

gdouble _gtk_spin_button_get_value(GtkSpinButton *spinbutton)
{
    gchar *e;
    gdouble result;

    e = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(spinbutton), 0, -1));
    g_strstrip(e);
    result = g_strtod(e, NULL);
    G_FREE_NULL(e);
    return result;
}

guint32 gtk_editable_get_value_as_uint(GtkEditable *editable)
{
    gchar *e;
    guint32 result;

    e = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
    g_strstrip(e);
    result = strtol(e, NULL, 10);
    G_FREE_NULL(e);
    return result;
}

/*
 * gtk_combo_init_choices:
 *
 * Adds alist of GtkItems to the given GtkCombo. Each GtkItem has the
 * choice number set as user_data.
 */
void gtk_combo_init_choices(
    GtkCombo *combo, GtkSignalFunc func, prop_def_t *def, gpointer user_data)
{
    guint n;
    guint32 original;

    g_assert(def != NULL);
    g_assert(combo != NULL);
    g_assert(def->type == PROP_TYPE_MULTICHOICE);
    g_assert(def->data.guint32.choices != NULL);

    original = *def->data.guint32.value;

    n = 0;
    while (def->data.guint32.choices[n].title != NULL) {
        GtkWidget *list_item;
        GList *l;

        list_item = gtk_list_item_new_with_label(
            def->data.guint32.choices[n].title);

        gtk_object_set_user_data(GTK_OBJECT(list_item),
            GINT_TO_POINTER(def->data.guint32.choices[n].value));

        gtk_widget_show(list_item);
        
        gtk_signal_connect_after(
            GTK_OBJECT(list_item), "select", func, user_data);

        l = g_list_prepend(NULL, (gpointer) list_item);
        gtk_list_append_items(GTK_LIST(combo->list), l);

        if (def->data.guint32.choices[n].value == original)
            gtk_list_select_child(GTK_LIST(combo->list), list_item);
        n ++;
    }
}

#ifdef USE_GTK1
/*
 * gtk_ctree_fast_unlink
 *
 * Functions like gtk_ctree_unlink for *Top level parent nodes only*. O(1)  
 */
static void gtk_ctree_fast_unlink (GtkCTree *ctree, GtkCTreeNode *node)
{
	GtkCList *clist;
	gint rows;
	gint level;
	gint visible;
	GtkCTreeNode *work;
	GtkCTreeNode *prev;
	GtkCTreeRow *prev_row;
	GtkCTreeNode *sibling;
	GList *list;
	
	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */
	
	clist = GTK_CLIST(ctree);
 	visible = gtk_ctree_is_viewable(ctree, node);

	/* clist->row_list_end unlinked ? */
	if (visible && (
            GTK_CTREE_NODE_NEXT(node) == NULL || (
                GTK_CTREE_ROW(node)->children && 
                gtk_ctree_is_ancestor(
                    ctree, node, GTK_CTREE_NODE(clist->row_list_end))
            )
        ))
		clist->row_list_end = (GList *) (GTK_CTREE_NODE_PREV(node));

	/* update list */
	rows = 0;
	level = GTK_CTREE_ROW(node)->level;
	work = GTK_CTREE_NODE_NEXT(node);

	/* Counts children of node */
	while (work && GTK_CTREE_ROW(work)->level > level) {
		work = GTK_CTREE_NODE_NEXT(work);
		rows++;
    }
	
	/* Subtract removed node and children from row count */
	if (visible) {
		clist->rows -= (rows + 1);
	}

	if (work) {
		list = (GList *)GTK_CTREE_NODE_PREV(work);
		list->next = NULL;
		list = (GList *)work;
		list->prev = (GList *)GTK_CTREE_NODE_PREV(node);
	}

	prev = GTK_CTREE_NODE_PREV(node); 
	
	if (prev && GTK_CTREE_NODE_NEXT(prev) == node) {
		list = (GList *)GTK_CTREE_NODE_PREV(node);
		list->next = (GList *)work;
    }

	if (clist->row_list == (GList *)node)
		clist->row_list = (GList *) (GTK_CTREE_ROW(node)->sibling);
	else {
		/* We need to hook the previous node up to the node's sibling */	
		if (prev) {
	
			prev_row = GTK_CTREE_ROW(prev);
			while (NULL != prev_row->parent) {
				prev = GTK_CTREE_NODE_PREV(prev);
				prev_row = GTK_CTREE_ROW(prev);
			}
			sibling = prev;			
			g_assert(GTK_CTREE_ROW(sibling)->sibling == node);		
			
			GTK_CTREE_ROW(sibling)->sibling = GTK_CTREE_ROW(node)->sibling;
		}
	}
}


/*
 * gtk_ctree_fast_link
 *
 * Functions like gtk_ctree_link for *Top level parent nodes only*.  This is 
 * optimized for data being linked at the beginning of the tree.  
 * O(1) if linking to beginning, O(n) otherwise.
 */
static void gtk_ctree_fast_link(GtkCTree *ctree, GtkCTreeNode *node,	
	GtkCTreeNode *sibling)
{
	GtkCList *clist;
	GList *list_end;
	GList *list;
	GList *work;
	gboolean visible = FALSE;
	gint rows = 1;

	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */
	
	clist = GTK_CLIST (ctree);

	/* Counts node and children */
	for (list_end = (GList *)node; list_end->next; list_end = list_end->next)
    	rows++;
	
	GTK_CTREE_ROW(node)->parent = NULL;
	GTK_CTREE_ROW(node)->sibling = sibling;

	visible = TRUE;
	clist->rows += rows;
	work = clist->row_list;

	/* O(1) if adding to top of list */
	if (sibling) {
		if (work != (GList *)sibling) {
			/* Searches from beginning of list until it finds sibling */
			while (GTK_CTREE_ROW(work)->sibling != sibling) {
				work = (GList *)(GTK_CTREE_ROW(work)->sibling);
            }
			GTK_CTREE_ROW(work)->sibling = node;
		}

		if (sibling == GTK_CTREE_NODE(clist->row_list)) {
			clist->row_list = (GList *) node;
        }

		if (GTK_CTREE_NODE_PREV(sibling) &&
			GTK_CTREE_NODE_NEXT(GTK_CTREE_NODE_PREV(sibling)) == sibling) {
			list = (GList *)GTK_CTREE_NODE_PREV(sibling);
			list->next = (GList *)node;
		}
      
		list = (GList *)node;
		list->prev = (GList *)GTK_CTREE_NODE_PREV(sibling);
		list_end->next = (GList *)sibling;
		list = (GList *)sibling;
		list->prev = list_end;

	} else {
		
		if (work) {

			/* Look from beginning of list/parent all the way to the end. */
			while (GTK_CTREE_ROW(work)->sibling)
				work = (GList *)(GTK_CTREE_ROW(work)->sibling);
			GTK_CTREE_ROW(work)->sibling = node;
	  
			/* find last child of sibling */
			work = (GList *) gtk_ctree_last(ctree, GTK_CTREE_NODE(work));
	  
			list_end->next = work->next;
			
			if (work->next)
				list = work->next->prev = list_end;
			work->next = (GList *)node;
			list = (GList *)node;
			list->prev = work;

		} else {
			clist->row_list = (GList *)node;
			list = (GList *)node;
			list->prev = NULL;
			list_end->next = NULL;
		}
	}

	if (
		clist->row_list_end == NULL ||
		clist->row_list_end->next == (GList *) node
	) {
		clist->row_list_end = list_end;
    }
}


/*
 * gtk_ctree_fast_move
 *
 * Functions like gtk_ctree_move for *Top level parent nodes only*.  This is 
 * optimized for data being moved to the beginning of the tree and assumes 
 * ctree != NULL and node != NULL.  O(1) as opposed to gtk's which is O(n).
 */
void gtk_ctree_fast_move (GtkCTree *ctree, GtkCTreeNode *node,
	GtkCTreeNode *new_sibling)
{
	GtkCList *clist;
	GtkCTreeNode *work;
	gboolean visible = FALSE;
	
	g_assert(NULL == GTK_CTREE_ROW(node)->parent); /* Not a child node */
	
	clist = GTK_CLIST (ctree);
	visible = gtk_ctree_is_viewable (ctree, node);

	/* return if it's already the right place */
	if (new_sibling == GTK_CTREE_ROW(node)->sibling || new_sibling == node) {
		return;
	}
	
	work = NULL;
	if (gtk_ctree_is_viewable (ctree, node))
    	work = GTK_CTREE_NODE(g_list_nth (clist->row_list, clist->focus_row));
    
	gtk_ctree_fast_unlink(ctree, node);
	gtk_ctree_fast_link(ctree, node, new_sibling);
	
	if (!work) {
		return;
	}
	
	while (work && !gtk_ctree_is_viewable(ctree, work))
		work = GTK_CTREE_ROW(work)->parent;

	clist->focus_row = g_list_position(clist->row_list, (GList *)work);
	clist->undo_anchor = clist->focus_row;
}

/*
 *	gtk_ctree_count_node_children
 *
 *	Returns number of children under parent node in the given ctree
 */
inline gint gtk_ctree_count_node_children(GtkCTree *ctree, GtkCTreeNode *parent)
{
	GtkCTreeRow *current_row;
	GtkCTreeNode *current_node;
	gint num_children = 0;
	
	current_row = GTK_CTREE_ROW(parent);
	current_node = current_row->children;
	
	for(; NULL != current_node; current_node = current_row->sibling) {
		current_row = GTK_CTREE_ROW(current_node);
		num_children++;
	}	
	
	return num_children;	
}

#endif /* USE_GTK1 */

/* vi: set ts=4: */
