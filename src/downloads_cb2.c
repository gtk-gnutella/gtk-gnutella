/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Richard Eckart
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

#ifdef USE_GTK2

RCSID("$Id$");

#include "downloads_cb2.h"

#include "downloads_gui.h"
#include "downloads_gui_common.h"
#include "statusbar_gui.h"

#include "downloads.h" /* FIXME: remove this dependency */

static gchar *selected_url = NULL; 

/***
 *** Popup menu: downloads
 ***/
void on_popup_downloads_push_activate(GtkMenuItem * menuitem,
								      gpointer user_data)
{
    GList *l;
	struct download *d;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	

	if(model != NULL) {

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;
			
            if (!d) {
				g_warning(
        	        "on_popup_downloads_push_activate(): row %d has NULL data\n",
				    GPOINTER_TO_INT(l->data));
		    	continue;
	        }
    
			download_fallback_to_push(d, FALSE, TRUE);
		}
	}
}




void on_popup_downloads_abort_named_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;

	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	
			
			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

			if (!d) {
				g_warning(
        	        "on_popup_downloads_abort_named_activate():"
            	    " row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}
		
			removed += download_remove_all_named(d->file_name);
		}
	}
	
    statusbar_gui_message(15, "Removed %u downloads", removed);
}



void on_popup_downloads_abort_host_activate
    (GtkMenuItem *menuitem, gpointer user_data) 
{
	// XXX routing misnamed: we're "forgetting" here, not "aborting"
	GList *l;
	struct download *d;
    gint removed = 0;

	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;
			
			if (!d) {
				g_warning(
        	        "on_popup_downloads_abort_host_activate():" 
            	    " row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}
			
			removed += download_remove_all_from_peer(
				download_guid(d), download_ip(d), download_port(d), FALSE);
		}
	}
		
    statusbar_gui_message(15, "Forgot %u downloads", removed);
}



void on_popup_downloads_abort_sha1_activate
    (GtkMenuItem *menuitem, gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
	gchar *sha1;

	GtkTreeIter iter, parent;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {
	
			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if (!d) {
				g_warning(
   	    	         "on_popup_downloads_abort_sha1_activate():"
   	        	     " row %d has NULL data\n", GPOINTER_TO_INT(l->data));
				continue;
			}

			if(DL_GUI_IS_HEADER == (guint32)d) {
				/* This is a header. All children have the same SHA1 though
				 * so we just grab the next one.
				 */
				parent = iter;
				if (gtk_tree_model_iter_nth_child(
							(GtkTreeModel *)model, &iter, &parent, 0)) {

					struct download *drecord = NULL;
					gtk_tree_model_get((GtkTreeModel *)model, &iter,
      					c_dl_record, &drecord,
	        			(-1));
				
					sha1 = drecord->file_info->sha1;	
				}
			}
			else
				sha1 = d->file_info->sha1;
			
        	if (NULL != sha1)
            	removed += download_remove_all_with_sha1(sha1);
		}
	}

    statusbar_gui_message(15, "Removed %u downloads", removed);
}



void on_popup_downloads_remove_file_activate(GtkMenuItem * menuitem,
			 							     gpointer user_data) 
{
	GList *l;
	struct download *d;

	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	
	if(model != NULL) {		
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

			if (!d) {
				g_warning(
        	        "on_popup_downloads_remove_file_activate():" 
            	    " row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}

			/*
			 * We request a resetting of the fileinfo to prevent discarding
			 * should we relaunch: non-reset fileinfos are discarded if the file
			 * is missing.
			 *		--RAM, 04/01/2003.
			 */
    	    if ((d->status == GTA_DL_ERROR || d->status == GTA_DL_ABORTED) &&
       				download_file_exists(d))
            	download_remove_file(d, TRUE);
		}
	}	
}


void on_popup_downloads_queue_activate(GtkMenuItem * menuitem,
                                       gpointer user_data)
{
    GList *l;
	struct download *d;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	if(model != NULL) {
		
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;
			
			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	
	
			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

	        if (!d) {
    	        g_warning
       	        ("on_popup_downloads_queue_activate(): row %d has NULL data\n",
            	     GPOINTER_TO_INT(l->data));
	            continue;
    	    }
			
			download_requeue(d);
    	}
	}
}



void on_popup_downloads_copy_url_activate(GtkMenuItem * menuitem,
									      gpointer user_data) 
{
   	struct download * d = NULL;
	GList *l;

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){  

		GtkTreeIter iter;
		GtkTreeView *tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads"));
		GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
		GtkTreeModel **modelp = &model;
	
		if(model != NULL) {		

			GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
			l = gtk_tree_selection_get_selected_rows(selection, modelp);

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				return;	
		
			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

	        if (!d) {
   	   		   	g_warning("on_popup_downloads_copy_url(): row %d has NULL data\n",
			        GPOINTER_TO_INT(l->data));
			    return;
	        }

	        /* 
   			* if "copy url" is done repeatedly, we have to make sure the
       		* memory of the previous selection is freed, because we may not
       		* recieve a "selection_clear" signal.
       		*      --BLUE, 24/04/2002
       		*/
	       if (selected_url != NULL) {
       		    g_free(selected_url);
           		selected_url = NULL;
	        }

       		selected_url = g_strdup(build_url_from_download(d));
		}			
    } 
}


void on_popup_downloads_selection_get(GtkWidget * widget,
                                      GtkSelectionData * data, 
                                      guint info, guint eventtime,
                                      gpointer user_data) 
{
    g_return_if_fail(selected_url);

    gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING,
                           8, (guchar *) selected_url, strlen(selected_url));
}



gint on_popup_downloads_selection_clear_event(GtkWidget * widget,
                                              GdkEventSelection *event)
{
    if (selected_url != NULL) {
        g_free(selected_url);
        selected_url = NULL;
    }
    return TRUE;
}



void on_popup_downloads_connect_activate(GtkMenuItem * menuitem,
					 	                 gpointer user_data) 
{
    struct download * d = NULL;
	GList *l;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;

	
	if(model != NULL) {		
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get_iter(model, &iter, l->data);
			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);

			gtk_tree_selection_unselect_iter(selection, &iter);	

			if (!d) {
		    	g_warning("on_popup_downloads_connect_activate():" 
        	    	"row %d has NULL data\n",
            		GPOINTER_TO_INT(l->data));
		    	return;
    		}

	    	node_add(download_ip(d), download_port(d));
		}
	}
}



/***
 *** popup-queue
 ***/
void on_popup_queue_start_now_activate(GtkMenuItem * menuitem,
										   gpointer user_data) 
{
    GList *l;
	struct download *d;

	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	
	if(model != NULL) {
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	
	
			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;
			
            if (!d) {
				g_warning(
        	        "on_popup_queue_start_now_activate(): row %d has NULL data\n",
				    GPOINTER_TO_INT(l->data));
		    	continue;
	        }
    
			if (d->status == GTA_DL_QUEUED)
				download_start(d, TRUE);
		}
	}
}


void on_popup_queue_abort_activate(GtkMenuItem * menuitem,
  							       gpointer user_data)
{
	GList *l;
	struct download *d;
		
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;

	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {
			
			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

			if (!d) {
				g_warning(
					"on_downloads_queue_abort_clicked(): row %d has NULL data\n",
            	    GPOINTER_TO_INT(l->data));
				continue;
			}
			if (d->status == GTA_DL_QUEUED)
				download_remove(d);
		}
	}
}


void on_popup_queue_abort_named_activate(GtkMenuItem * menuitem,
										  gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	
	if(model != NULL) {		
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	
	
			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

			if (!d) {
				g_warning(
        	        "on_popup_queue_abort_named_activate():"
            	    " row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}
		
			removed += download_remove_all_named(d->file_name);
		}
	}	

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_abort_host_activate(GtkMenuItem * menuitem,
										    gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;

	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;

			if (!d) {
				g_warning(
        	        "on_popup_queue_abort_host_activate():" 
            	    " row %d has NULL data\n",
					GPOINTER_TO_INT(l->data));
				continue;
			}
			
			removed += download_remove_all_from_peer(
				download_guid(d), download_ip(d), download_port(d), FALSE);
		}
	}
	
    statusbar_gui_message(15, "Removed %u downloads", removed);
}



void on_popup_queue_abort_sha1_activate(GtkMenuItem * menuitem,
								        gpointer user_data) 
{
	GList *l;
	struct download *d;
    gint removed = 0;
	gchar *sha1;
	
	GtkTreeIter iter, parent;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	
	if(model != NULL) {		
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {
	
			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if (!d) {
				g_warning(
   	    	         "on_popup_queue_abort_sha1_activate():"
   	        	     " row %d has NULL data\n", GPOINTER_TO_INT(l->data));
				continue;
			}

			
			if(DL_GUI_IS_HEADER == (guint32)d) {
			/* This is a header. All children have the same SHA1 though
			 * so we just grab the next one.
			 */
				parent = iter;
				if (gtk_tree_model_iter_nth_child(
						(GtkTreeModel *)model, &iter, &parent, 0)) {
					
					struct download *drecord = NULL;
						
					gtk_tree_model_get((GtkTreeModel *)model, &iter,
    					c_queue_record, &drecord,
	       				(-1));
				
					sha1 = drecord->file_info->sha1;	
				}
			}
			else
				sha1 = d->file_info->sha1;
			
			   	if (NULL != sha1)
            		removed += download_remove_all_with_sha1(sha1);
		}
	}

    statusbar_gui_message(15, "Removed %u downloads", removed);
}

void on_popup_queue_copy_url_activate(GtkMenuItem * menuitem,
					 	              gpointer user_data) 
{
    /* FIXME: This is more or less copy/paste from the downloads_copy_url
     * handler. There should be a more general function to call which
     * takes the string to copy as an arguments and handles the rest.
     *      --BLUE, 24/05/2002
     */

   	struct download * d = NULL;
    GList *l;

    g_return_if_fail(l);

    /* 
     * note that we set the popup dialog as owner, because we can
     * connect the selection_* signals to that using glade.
     *      --BLUE, 24/04/2002
     */
    if (gtk_selection_owner_set(GTK_WIDGET(popup_downloads),
                                GDK_SELECTION_PRIMARY,
                                GDK_CURRENT_TIME)){  


		GtkTreeIter iter;
		GtkTreeView *tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
		GtkTreeModel **modelp = &model;
	
									
		if(model != NULL) {		

			GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
			l = gtk_tree_selection_get_selected_rows(selection, modelp);

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				return;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);

	        if (!d) {
   	   		   	g_warning("on_popup_queue_copy_url(): row %d has NULL data\n",
			        GPOINTER_TO_INT(l->data));
			    return;
	        }

	        /* 
   			* if "copy url" is done repeatedly, we have to make sure the
       		* memory of the previous selection is freed, because we may not
       		* recieve a "selection_clear" signal.
       		*      --BLUE, 24/04/2002
       		*/
	       if (selected_url != NULL) {
       		    g_free(selected_url);
           		selected_url = NULL;
	        }

       		selected_url = g_strdup(build_url_from_download(d));
		}			

        /* 
         * if "copy url" is done repeatedly, we have to make sure the
         * memory of the previous selection is freed, because we may not
         * recieve a "selection_clear" signal.
         *      --BLUE, 24/04/2002
         */
        if (selected_url != NULL) {
            g_free(selected_url);
            selected_url = NULL;
        }

        selected_url = g_strdup(build_url_from_download(d));
    } 
}

void on_popup_queue_connect_activate(GtkMenuItem * menuitem,
					 	             gpointer user_data) 
{
    struct download * d = NULL;
	GList *l;		
	
	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	

	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
				return;
			
			if (!d) {
		    	g_warning("on_popup_queue_connect_activate():" 
        	    	"row %d has NULL data\n",
            		GPOINTER_TO_INT(l->data));
		    	return;
    		}

	    	node_add(download_ip(d), download_port(d));
		}
	}
}
 
/***
 *** downloads pane
 ***/

void on_button_downloads_abort_clicked(GtkButton * button,
									  gpointer user_data)
{
	GList *l;
	struct download *d;

	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;

	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {
			
			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;	

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

			if (!d) {
				g_warning(
					"on_button_downloads_abort_clicked(): row %d has NULL data\n",
            	    GPOINTER_TO_INT(l->data));
				continue;
			}

			download_abort(d);
		}
	}
}



void on_button_downloads_resume_clicked(GtkButton * button,
									   gpointer user_data)
{
	GList *l;
	struct download *d;

	GtkTreeIter iter;
	GtkTreeView *tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
	GtkTreeModel **modelp = &model;
	
	
	if(model != NULL) {		
	
		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		for (; l; l = l->next) {

			if(!gtk_tree_model_get_iter(model, &iter, l->data))
				break;				

			gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
			gtk_tree_selection_unselect_iter(selection, &iter);	

	        if (!d) {
    	        g_warning
        	        ("on_button_downloads_resume_clicked(): row %d has NULL data\n",
            	     GPOINTER_TO_INT(l->data));
            	continue;
        	}
        	download_resume(d);	
		}
	}

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

void on_button_downloads_clear_stopped_clicked(
    GtkButton *button, gpointer user_data)
{
	download_clear_stopped(TRUE, TRUE, TRUE, TRUE);
}

/*** 
 *** Queued downloads
 ***/
void on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton, 
										  gpointer user_data) 
{
    if (gtk_toggle_button_get_active(togglebutton)) {
        download_freeze_queue();
    } else {
        download_thaw_queue();
    }
}




void on_entry_queue_regex_activate(GtkEditable *editable, gpointer user_data)
{
    gint i;
  	gint n;
    gint m = 0;
	gint total_nodes;
    gint  err;
    gchar * regex;
	struct download *d;
	regex_t re;

    regex = gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1);

	g_return_if_fail(regex != NULL);
	
    err = regcomp(&re, 
                  regex,
                  REG_EXTENDED|REG_NOSUB|(queue_regex_case ? 0 : REG_ICASE));

   	if (err) {
        char buf[1000];
		regerror(err, &re, buf, 1000);
        statusbar_gui_warning
            (15, "on_entry_queue_regex_activate: regex error %s",buf);
    } else {
  
		GtkTreeIter iter;
		GtkTreeView *tree_view = GTK_TREE_VIEW
			(lookup_widget(main_window, "treeview_downloads_queue"));
		GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
			

		if(model != NULL) {		

			GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
			gtk_tree_selection_unselect_all(selection);
			
			if(!gtk_tree_model_get_iter_first(model, &iter))
				return; /* tree is empty */
			
			for (total_nodes=0; gtk_tree_model_iter_next(model, &iter); 
					total_nodes++) {
				
				gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);

				if(DL_GUI_IS_HEADER == (guint32)d) /* is header */
					continue;				
				
				if (!d) {
	                g_warning("on_entry_queue_regex_activate:row has NULL data");
    	            continue;
        	    }

	            if (
					(n = regexec(&re, d->file_name, 0, NULL, 0)) == 0 ||
					(n = regexec(&re, download_outname(d), 0, NULL, 0)) == 0
				) {
					gtk_tree_selection_select_iter(selection, &iter);
					m ++;
				}

    	        if (n == REG_ESPACE)
        	        g_warning("on_entry_queue_regex_activate: "
						"regexp memory overflow");
        	}
        
			statusbar_gui_message(15, 
        	    "Selected %u of %u queued downloads matching \"%s\".", 
	           	 m, total_nodes, regex);

			regfree(&re);
	    }
	}
    
	g_free(regex);
    gtk_entry_set_text(GTK_ENTRY(editable), "");
}


gboolean on_treeview_downloads_button_press_event 
	(GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;

	if (event->button != 3)
		return FALSE;


	if (NULL == gtk_tree_view_get_selection(GTK_TREE_VIEW(widget)))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_downloads), NULL, NULL, NULL, NULL, 
        event->button, event->time);

	return TRUE;
}


gboolean on_treeview_downloads_queue_button_press_event 
	(GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row;
    gint col;

	if (event->button != 3)
		return FALSE;


	if (NULL == gtk_tree_view_get_selection(GTK_TREE_VIEW(widget)))
		return FALSE;

    gtk_menu_popup(
        GTK_MENU(popup_queue), NULL, NULL, NULL, NULL, 
        event->button, event->time);

	return TRUE;
}


void on_treeview_downloads_select_row(GtkTreeView * tree_view, 
	gpointer user_data)
{
    gboolean activate = FALSE;

	GList *l;	
	struct download *d;
	
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeModel **modelp;
	
	
	/* The user selects a row(s) in the downloads treeview
	 * we unselect all rows in the downloads_queue tree view
	 */
	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_unselect_all(selection);


		
	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	model = gtk_tree_view_get_model(tree_view);
	modelp = &model;
	
	if(model != NULL) {		

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		if(NULL != l) {
			if(gtk_tree_model_get_iter(model, &iter, l->data)) {

				gtk_tree_model_get(model, &iter, c_dl_record, &d, -1);
				activate = ((NULL == l->next) && (DL_GUI_IS_HEADER != (guint32)d));
	
			    gtk_widget_set_sensitive(lookup_widget(popup_downloads, 
					"popup_downloads_copy_url"), activate);
    			gtk_widget_set_sensitive(lookup_widget(popup_downloads, 
					"popup_downloads_connect"), activate);
	
				/*Takes care of other widgets*/
				gui_update_download_abort_resume();
			}
		}	
	}
}


void on_treeview_downloads_queue_select_row
	(GtkTreeView * tree_view, gpointer user_data)
{
    gboolean is_header = FALSE;
	gboolean only_one = FALSE;
	gboolean something = FALSE;	/* is something selected? */


	GList *l;	
	struct download *d;
	
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeModel **modelp;
	
	
	/* The user selects a row(s) in the downloads_queue treeview
	 * we unselect all rows in the downloads tree view
	 */
	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads"));
	GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
	gtk_tree_selection_unselect_all(selection);


		
	tree_view = GTK_TREE_VIEW
		(lookup_widget(main_window, "treeview_downloads_queue"));
	model = gtk_tree_view_get_model(tree_view);
	modelp = &model;

	if(model != NULL) {

		GtkTreeSelection *selection = gtk_tree_view_get_selection(tree_view);
		l = gtk_tree_selection_get_selected_rows(selection, modelp);

		if(NULL != l) {		
			if(gtk_tree_model_get_iter(model, &iter, l->data)) {

				gtk_tree_model_get(model, &iter, c_queue_record, &d, -1);				

				is_header = (DL_GUI_IS_HEADER == (guint32) d);
				only_one = (NULL == l->next);
				something = TRUE;
			}
		}	
	}
	
	
	gtk_widget_set_sensitive
		(lookup_widget(popup_queue, "popup_queue_copy_url"), only_one);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_connect"), only_one);
	gui_update_download_abort_resume();

	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort"), !is_header);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_named"), !is_header);
	gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_host"), !is_header);
    gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_abort_sha1"), something);	

	if(is_header)
		gtk_widget_set_sensitive
        (lookup_widget(popup_queue, "popup_queue_start_now"), FALSE);
	
}

#endif	/* USE_GTK2 */
