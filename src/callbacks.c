#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "gnutella.h"

#include "callbacks.h"
#include "interface.h"
#include "support.h"

gchar c_tmp[2048];

struct download *selected_queued_download = (struct download *) NULL;
struct download *selected_active_download = (struct download *) NULL;

/* Main window ------------------------------------------------------------------------------------ */

gboolean on_main_window_delete_event (GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_gnutella_exit(0);
	return TRUE;
}

/* Left part -------------------------------------------------------------------------------------- */

void on_clist_menu_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), row);
}

void on_button_stats_update_clicked (GtkButton *button, gpointer user_data)
{
	ping_stats_update();
}

/* gnutellaNet ------------------------------------------------------------------------------------ */

/* connections */

void cb_node_add(void)
{
	gchar *seek, *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_host)));
	guint32 port = 6346;

	g_strstrip(e);

	seek = e;

	while (*seek && *seek != ':' && *seek != ' ') seek++;

	if (*seek)
	{
		*seek++ = 0;
		while (*seek && (*seek == ':' || *seek == ' ')) seek++;
		if (*seek) port = atol(seek);
	}

	if (port < 1 || port > 65535) printf("Bad host !\n");
	else
	{
		guint32 ip = host_to_ip(e);
		if (ip)
		{
			node_add(NULL, ip, port);
			gtk_entry_set_text(GTK_ENTRY(entry_host), "");
		}
	}

	g_free(e);
}

void on_button_nodes_add_clicked (GtkButton *button, gpointer user_data)
{
	cb_node_add();
}

void on_entry_host_activate (GtkEditable *editable, gpointer user_data)
{
	cb_node_add();
}

void on_entry_host_changed (GtkEditable *editable, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(editable)));
	g_strstrip(e);
	if (*e) gtk_widget_set_sensitive(button_nodes_add, TRUE);
	else gtk_widget_set_sensitive(button_nodes_add, FALSE);
	g_free(e);
}

void on_button_nodes_remove_clicked(GtkButton *button, gpointer user_data)
{
	if (GTK_CLIST(clist_nodes)->selection)
	{
		struct gnutella_node *n;
		GList *l = GTK_CLIST(clist_nodes)->selection;

		while (l)
		{
			n = (struct gnutella_node *) gtk_clist_get_row_data(GTK_CLIST(clist_nodes), (gint) l->data);
			l = l->next;
			node_remove(n, NULL);
			node_real_remove(n);
		}
	}
}

void on_clist_nodes_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gtk_widget_set_sensitive(button_nodes_remove, TRUE);
}

void on_clist_nodes_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gtk_widget_set_sensitive(button_nodes_remove, (gboolean) GTK_CLIST(clist_nodes)->selection);
}

void on_clist_nodes_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data)
{
	nodes_col_widths[column] = width;
}

/* minimum connections up */

void on_entry_up_connections_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_up_connections_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_up_connections)));
	g_strstrip(e);
	v = atol(e);
	g_free(e);
	if (v > 0 && v < 512) { up_connections = v; }
	gui_update_up_connections();
	return TRUE;
}

/* nodes popup menu */

gboolean on_clist_nodes_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	if (event->button != 3) return FALSE;

	gtk_clist_unselect_all(GTK_CLIST(clist_nodes));

	gtk_menu_popup(GTK_MENU(popup_nodes), NULL, NULL, NULL, NULL, 3, 0);

	return TRUE;
}

void on_popup_nodes_title_activate (GtkMenuItem *menuitem, gpointer user_data)
{
}

/* host catcher */

void on_button_host_catcher_connect_clicked (GtkButton *button, gpointer user_data)
{
	if (GTK_CLIST(clist_host_catcher)->selection)
	{
		struct gnutella_host *h;
		GList *l = GTK_CLIST(clist_host_catcher)->selection;

		while (l)
		{
			h = (struct gnutella_host *) gtk_clist_get_row_data(GTK_CLIST(clist_host_catcher), (gint) l->data);
			l = l->next;

			node_add(NULL, h->ip, h->port);
			host_remove(h, TRUE);
		}

		gtk_entry_set_text(GTK_ENTRY(entry_host), "");
	}
}

void on_button_host_catcher_get_more_clicked (GtkButton *button, gpointer user_data)
{
	send_init(NULL);
}

void on_button_host_catcher_remove_clicked (GtkButton *button, gpointer user_data)
{
	if (GTK_CLIST(clist_host_catcher)->selection)
	{
		struct gnutella_host *h;
		GList *l = GTK_CLIST(clist_host_catcher)->selection;

		while (l)
		{
			h = (struct gnutella_host *) gtk_clist_get_row_data(GTK_CLIST(clist_host_catcher), (gint) l->data);
			l = l->next;

			host_remove(h, TRUE);
		}
	}
}

void on_button_host_catcher_clear_clicked (GtkButton *button, gpointer user_data)
{
	gtk_clist_clear(GTK_CLIST(clist_host_catcher));
	gtk_widget_set_sensitive(button_host_catcher_connect, FALSE);
	gtk_widget_set_sensitive(button_host_catcher_remove, FALSE);

	while (sl_catched_hosts) host_remove((struct gnutella_host *) sl_catched_hosts->data, FALSE);
}

void on_clist_host_catcher_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	struct gnutella_host *h;

	gtk_widget_set_sensitive(button_host_catcher_connect, TRUE);
	gtk_widget_set_sensitive(button_host_catcher_remove, TRUE);

	h = (struct gnutella_host *) gtk_clist_get_row_data(GTK_CLIST(clist_host_catcher), row);

	gtk_entry_set_text(GTK_ENTRY(entry_host), ip_port_to_gchar(h->ip, h->port));
}

void on_clist_host_catcher_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gboolean s = (gboolean) GTK_CLIST(clist_host_catcher)->selection;
	gtk_widget_set_sensitive(button_host_catcher_connect, s);
	gtk_widget_set_sensitive(button_host_catcher_remove, s);
}

gboolean on_clist_host_catcher_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row, col;
	struct gnutella_host *h;

	if (event->button == 3)
	{
		gtk_widget_set_sensitive(popup_hosts_export, (gboolean) sl_catched_hosts);
		gtk_clist_unselect_all(GTK_CLIST(clist_host_catcher));
		gtk_menu_popup(GTK_MENU(popup_hosts), NULL, NULL, NULL, NULL, 3, 0);
		return TRUE;
	}

	if (event->button != 1 || (event->type != GDK_2BUTTON_PRESS && event->type != GDK_3BUTTON_PRESS)) return FALSE;
	
	if (!gtk_clist_get_selection_info(GTK_CLIST(clist_host_catcher), event->x, event->y, &row, &col)) return FALSE;

	h = (struct gnutella_host *) gtk_clist_get_row_data(GTK_CLIST(clist_host_catcher), row);

	node_add(NULL, h->ip, h->port);
	host_remove(h, TRUE);

	return TRUE;
}

GtkWidget *hosts_write_filesel = (GtkWidget *) NULL;

gboolean fs_hosts_write_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_hosts_write_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data)
		hosts_write_to_file(gtk_file_selection_get_filename(GTK_FILE_SELECTION(hosts_write_filesel)));

	gtk_widget_destroy(hosts_write_filesel);
	hosts_write_filesel = (GtkWidget *) NULL;
}

void on_popup_hosts_export_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (!hosts_write_filesel)
	{
		hosts_write_filesel = gtk_file_selection_new("Please choose a file to save the catched hosts");

		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(hosts_write_filesel)->ok_button), "clicked", GTK_SIGNAL_FUNC (button_fs_hosts_write_clicked), (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(hosts_write_filesel)->cancel_button), "clicked", GTK_SIGNAL_FUNC (button_fs_hosts_write_clicked), NULL);
		gtk_signal_connect(GTK_OBJECT(hosts_write_filesel), "delete_event", GTK_SIGNAL_FUNC (fs_hosts_write_delete_event), NULL);

		gtk_widget_show(hosts_write_filesel);
	}
}

GtkWidget *hosts_read_filesel = (GtkWidget *) NULL;

gboolean fs_hosts_read_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(hosts_read_filesel);
	hosts_read_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_hosts_read_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data)
		hosts_read_from_file(gtk_file_selection_get_filename(GTK_FILE_SELECTION(hosts_read_filesel)), FALSE);

	gtk_widget_destroy(hosts_read_filesel);
	hosts_read_filesel = (GtkWidget *) NULL;
}

void on_popup_hosts_importe_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (!hosts_read_filesel)
	{
		hosts_read_filesel = gtk_file_selection_new("Please choose a text hosts file");

		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(hosts_read_filesel)->ok_button), "clicked", GTK_SIGNAL_FUNC (button_fs_hosts_read_clicked), (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(hosts_read_filesel)->cancel_button), "clicked", GTK_SIGNAL_FUNC (button_fs_hosts_read_clicked), NULL);
		gtk_signal_connect(GTK_OBJECT(hosts_read_filesel), "delete_event", GTK_SIGNAL_FUNC (fs_hosts_read_delete_event), NULL);

		gtk_widget_show(hosts_read_filesel);
	}
}

/* Uploads ---------------------------------------------------------------------------------------- */

void on_clist_uploads_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
}

void on_clist_uploads_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
}

void on_clist_uploads_click_column (GtkCList *clist, gint column, gpointer user_data)
{
}

void on_clist_uploads_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data)
{
	uploads_col_widths[column] = width;
}

void on_button_kill_upload_clicked (GtkButton *button, gpointer user_data)
{
}

void on_button_clear_uploads_clicked (GtkButton *button, gpointer user_data)
{
}

void on_checkbutton_clear_uploads_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	clear_uploads = gtk_toggle_button_get_active(togglebutton);
}

/* uploads popup menu */

gboolean on_clist_uploads_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	if (event->button != 3) return FALSE;

	gtk_clist_unselect_all(GTK_CLIST(clist_uploads));

	gtk_menu_popup(GTK_MENU(popup_uploads), NULL, NULL, NULL, NULL, 3, 0);

	return TRUE;
}

void on_popup_uploads_title_activate (GtkMenuItem *menuitem, gpointer user_data)
{

}

/* Downloads -------------------------------------------------------------------------------------- */

/* Active downloads clist */

void on_clist_downloads_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gui_update_download_abort_resume();
}

void on_clist_downloads_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gui_update_download_abort_resume();
}

void on_clist_downloads_click_column (GtkCList *clist, gint column, gpointer user_data)
{
}

void on_clist_downloads_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data)
{
	dl_active_col_widths[column] = width;
}

/* Active downloads popup menu */

gboolean on_clist_downloads_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row, col;
	struct download *d;

	if (event->button != 3) return FALSE;

	if (!gtk_clist_get_selection_info(GTK_CLIST(clist_downloads), event->x, event->y, &row, &col)) return FALSE;

	d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_downloads), row);

	strncpy(c_tmp + 24, "...", 4);
	strncpy(c_tmp, d->file_name, 24);

	gtk_label_set(GTK_LABEL((GTK_MENU_ITEM(popup_dl_active_title)->item.bin.child)), c_tmp);

	gtk_widget_set_sensitive(download_p_push, !d->push);
	gtk_widget_set_sensitive(download_p_queue, d->status != GTA_DL_COMPLETED);
	gtk_widget_set_sensitive(download_p_kill, d->status != GTA_DL_COMPLETED);

	gtk_clist_unselect_all(GTK_CLIST(clist_downloads));

	gtk_menu_popup(GTK_MENU(popup_dl_active), NULL, NULL, NULL, NULL, 3, 0);

	selected_active_download = d;

	return TRUE;
}

void on_download_p_push_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (selected_active_download) download_fallback_to_push(selected_active_download, TRUE);
	selected_active_download = (struct download *) NULL;
}

void on_download_p_queue_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (selected_active_download) download_queue(selected_active_download);
	selected_active_download = (struct download *) NULL;
}

void on_download_p_kill_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (selected_active_download) download_kill(selected_active_download);
	selected_active_download = (struct download *) NULL;
}

/* Active downloads buttons and entries */

void on_button_abort_download_clicked (GtkButton *button, gpointer user_data)
{
	GList *l;
	struct download *d;

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next)
	{
		d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_downloads), (gint) l->data);

		if (!d)
		{
			g_warning("on_button_abort_download_clicked(): row %d has NULL data\n", (gint) l->data);
			continue;
		}

		download_abort(d);
	}
}

void on_button_resume_download_clicked (GtkButton *button, gpointer user_data)
{
	GList *l;
	struct download *d;

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next)
	{
		d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_downloads), (gint) l->data);

		if (!d)
		{
			g_warning("on_button_abort_download_clicked(): row %d has NULL data\n", (gint) l->data);
			continue;
		}

		download_resume(d);
	}

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

void on_button_clear_download_clicked (GtkButton *button, gpointer user_data)
{
	downloads_clear_stopped(TRUE, TRUE);
}

void on_checkbutton_clear_downloads_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	clear_downloads = gtk_toggle_button_get_active(togglebutton);
	if (clear_downloads) downloads_clear_stopped(FALSE, TRUE);
}

void on_entry_max_downloads_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_max_downloads_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	gint v = atol(gtk_entry_get_text(GTK_ENTRY(entry_max_downloads)));
	if (v > 0 && v < 65536) max_downloads = v;

	/* XXX If the user modifies the max simulteneous download and click on a queued download, */
	/* XXX gtk-gnutella segfaults in some cases. */
	/* XXX This unselected_all() is a first attempt to work around the problem */

	gtk_clist_unselect_all(GTK_CLIST(clist_download_queue));

	gui_update_max_downloads();
	download_pickup_queued();

	return TRUE;
}

/* Queued downloads */

void on_clist_download_queue_select_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gtk_widget_set_sensitive(button_remove_download, TRUE);
}

void on_clist_download_queue_unselect_row (GtkCList *clist, gint row, gint column, GdkEvent *event, gpointer user_data)
{
	gtk_widget_set_sensitive(button_remove_download, (gboolean) GTK_CLIST(clist_download_queue)->selection);
}

void on_button_remove_download_clicked (GtkButton *button, gpointer user_data)
{
	if (GTK_CLIST(clist_download_queue)->selection)
	{
		struct download *d;
		GList *l = GTK_CLIST(clist_download_queue)->selection;

		while (l)
		{
			d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_download_queue), (gint) l->data);
			l = l->next;
			if (d->status == GTA_DL_QUEUED) download_free(d);
		}
	}
}

void on_clist_download_queue_click_column (GtkCList *clist, gint column, gpointer user_data)
{
}

void on_download_start_now_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	if (selected_queued_download) download_start(selected_queued_download);
}

gboolean on_clist_download_queue_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	gint row, col;
	struct download *d;

	if (event->button != 3) return FALSE;

	if (!gtk_clist_get_selection_info(GTK_CLIST(clist_download_queue), event->x, event->y, &row, &col)) return FALSE;

	d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_download_queue), row);

	strncpy(c_tmp + 24, "...", 4);
	strncpy(c_tmp, d->file_name, 24);

	gtk_label_set(GTK_LABEL((GTK_MENU_ITEM(popup_dl_queued_title)->item.bin.child)), c_tmp);

	gtk_clist_unselect_all(GTK_CLIST(clist_download_queue));

	gtk_menu_popup(GTK_MENU(popup_dl_queued), NULL, NULL, NULL, NULL, 3, 0);

	if (d->status == GTA_DL_QUEUED) selected_queued_download = d;
	else g_warning("popup_dl_queued(): Unexpected download status %d !\n", d->status);

	return TRUE;
}

void on_clist_download_queue_resize_column (GtkCList *clist, gint column, gint width, gpointer user_data)
{
	dl_queued_col_widths[column] = width;
}

/* Searches --------------------------------------------------------------------------------------- */

void on_entry_minimum_speed_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_minimum_speed_focus_out_event(GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	gint speed = atol(gtk_entry_get_text(GTK_ENTRY(entry_minimum_speed)));
	if (speed >= 0 && speed < 65536) minimum_speed = speed;
	gui_update_minimum_speed(minimum_speed); /* XXX The minimum speed is now on a per search basis */

	return TRUE;
}

void on_button_search_clicked (GtkButton *button, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_search)));
	if (on_the_net())
	{
		g_strstrip(e);
		if (*e) new_search(minimum_speed, e);
		gtk_widget_grab_focus(clist_menu);
	}
	g_free(e);
}

void on_entry_search_activate (GtkEditable *editable, gpointer user_data)
{
	on_button_search_clicked(NULL, user_data);
}

void on_entry_search_changed (GtkEditable *editable, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_search)));
	g_strstrip(e);
	gtk_widget_set_sensitive(button_search, (gboolean) (*e));
	g_free(e);
}

void on_button_search_filter_clicked (GtkButton *button, gpointer user_data)
{
	search_open_filters_dialog();
}

void on_button_search_close_clicked (GtkButton *button, gpointer user_data)
{
	search_close_current();
}

void on_button_search_download_clicked (GtkButton *button, gpointer user_data)
{
	search_download_files();
}

void on_button_search_stream_clicked (GtkButton *button, gpointer user_data)
{

}

/* Monitor ---------------------------------------------------------------------------------------- */

void on_checkbutton_monitor_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	monitor_enabled = gtk_toggle_button_get_active(togglebutton);
}

void on_entry_monitor_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_monitor_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_monitor)));
	g_strstrip(e);
	v = atol(e);
	if (v > 0 && v < 512)
	{
		if (v < monitor_max_items)
		{
			gtk_clist_clear(GTK_CLIST(clist_monitor));
			monitor_items = 0;
		}
		monitor_max_items = v;
	}
	gui_update_monitor_max_items();
	g_free(e);

	return TRUE;
}

/* Monitor popup menu */

void on_popup_monitor_title_activate (GtkMenuItem *menuitem, gpointer user_data)
{
}

gboolean on_clist_monitor_button_press_event (GtkWidget *widget, GdkEventButton *event, gpointer user_data)
{
	if (event->button != 3) return FALSE;

	gtk_clist_unselect_all(GTK_CLIST(clist_monitor));

	gtk_menu_popup(GTK_MENU(popup_monitor), NULL, NULL, NULL, NULL, 3, 0);

	return TRUE;
}

/* Config ----------------------------------------------------------------------------------------- */

/* While downloading, store files to */

GtkWidget *save_path_filesel = NULL;

gboolean fs_save_path_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(save_path_filesel);
	save_path_filesel = NULL;
	return TRUE;
}

void button_fs_save_path_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data)
	{
		gchar *name = gtk_file_selection_get_filename(GTK_FILE_SELECTION(save_path_filesel));

		if (is_directory(name))
		{
			g_free(save_file_path);
			save_file_path = g_strdup(name);
		}

		gui_update_save_file_path();
	}

	gtk_widget_destroy(save_path_filesel);
	save_path_filesel = NULL;
}

void on_button_config_save_path_clicked (GtkButton *button, gpointer user_data)
{
	if (!save_path_filesel)
	{
		save_path_filesel = gtk_file_selection_new("Please choose where to store files while downloading");

		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(save_path_filesel)->ok_button), "clicked", GTK_SIGNAL_FUNC (button_fs_save_path_clicked), (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(save_path_filesel)->cancel_button), "clicked", GTK_SIGNAL_FUNC (button_fs_save_path_clicked), NULL);
		gtk_signal_connect(GTK_OBJECT(save_path_filesel), "delete_event", GTK_SIGNAL_FUNC (fs_save_path_delete_event), NULL);

		gtk_widget_show(save_path_filesel);
	}
}

/* Move downloaded files to */

GtkWidget *move_path_filesel = (GtkWidget *) NULL;

gboolean fs_save_move_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(move_path_filesel);
	move_path_filesel = (GtkWidget *) NULL;
	return TRUE;
}

void button_fs_move_path_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data)
	{
		gchar *name = gtk_file_selection_get_filename(GTK_FILE_SELECTION(move_path_filesel));

		if (is_directory(name))
		{
			g_free(move_file_path);
			move_file_path = g_strdup(name);
		}

		gui_update_move_file_path();
	}

	gtk_widget_destroy(move_path_filesel);
	move_path_filesel = (GtkWidget *) NULL;
}

void on_button_config_move_path_clicked (GtkButton *button, gpointer user_data)
{
	if (!move_path_filesel)
	{
		move_path_filesel = gtk_file_selection_new("Please choose where to move files after download");

		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(move_path_filesel)->ok_button), "clicked", GTK_SIGNAL_FUNC (button_fs_move_path_clicked), (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(move_path_filesel)->cancel_button), "clicked", GTK_SIGNAL_FUNC (button_fs_move_path_clicked), NULL);
		gtk_signal_connect(GTK_OBJECT(move_path_filesel), "delete_event", GTK_SIGNAL_FUNC (fs_save_move_delete_event), NULL);

		gtk_widget_show(move_path_filesel);
	}
}

/* */

GtkWidget *add_dir_filesel = NULL;

gboolean fs_add_dir_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_destroy(add_dir_filesel);
	add_dir_filesel = NULL;
	return TRUE;
}

void button_fs_add_dir_clicked(GtkButton *button, gpointer user_data)
{
	if (user_data)
	{
		gchar *name = gtk_file_selection_get_filename(GTK_FILE_SELECTION(add_dir_filesel));

		if (is_directory(name)) shared_dir_add(name);

		gui_update_save_file_path();
	}

	gtk_widget_destroy(add_dir_filesel);
	add_dir_filesel = NULL;
}

void on_button_config_add_dir_clicked (GtkButton *button, gpointer user_data)
{
	if (!add_dir_filesel)
	{
		add_dir_filesel = gtk_file_selection_new("Please choose a directory to share");

		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(add_dir_filesel)->ok_button), "clicked", GTK_SIGNAL_FUNC (button_fs_add_dir_clicked), (gpointer) 1);
		gtk_signal_connect(GTK_OBJECT(GTK_FILE_SELECTION(add_dir_filesel)->cancel_button), "clicked", GTK_SIGNAL_FUNC (button_fs_add_dir_clicked), NULL);
		gtk_signal_connect(GTK_OBJECT(add_dir_filesel), "delete_event", GTK_SIGNAL_FUNC (fs_add_dir_delete_event), NULL);

		gtk_widget_show(add_dir_filesel);
	}
}

void on_button_config_rescan_dir_clicked (GtkButton *button, gpointer user_data)
{
}

void on_entry_config_path_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_path_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	shared_dirs_parse(gtk_entry_get_text(GTK_ENTRY(entry_config_path)));
	gui_update_shared_dirs();
	return TRUE;
}

void on_entry_config_extensions_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_extensions_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	parse_extensions(gtk_entry_get_text(GTK_ENTRY(entry_config_extensions)));
	gui_update_scan_extensions();
	return TRUE;
}

void on_checkbutton_config_force_ip_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
	force_local_ip = gtk_toggle_button_get_active(togglebutton);
}

void on_entry_config_force_ip_changed (GtkEditable *editable, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(editable)));
	guint32 ip;
	g_strstrip(e);
	ip = gchar_to_ip(e);
	gtk_widget_set_sensitive(checkbutton_config_force_ip, ip);
	g_free(e);
}

void on_entry_config_force_ip_activate(GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_force_ip_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	gchar *e;
	guint32 ip;
	e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_force_ip)));
	g_strstrip(e);
	ip = gchar_to_ip(e);
	if (ip != forced_local_ip) forced_local_ip = ip;
	gui_update_config_force_ip();
	g_free(e);
	return TRUE;
}

void config_port_update_request(void)
{
	guint16 p;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_port)));
	g_strstrip(e);
	p = atoi(e);
	if (listen_port != p)
	{
		if (s_listen) socket_destroy(s_listen);
		if (p) s_listen = socket_listen(0, p, GTA_TYPE_CONTROL);
		else s_listen = NULL;
		if (s_listen) listen_port = p;
		else listen_port = 0;
	
		gtk_widget_set_sensitive(button_config_update_port, FALSE);
		gtk_widget_grab_focus(clist_menu);
	}
	gui_update_config_port();
	g_free(e);
}

void on_entry_config_port_activate (GtkEditable *editable, gpointer user_data)
{
	config_port_update_request();
}

void on_entry_config_port_changed (GtkEditable *editable, gpointer user_data)
{
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_port)));
	g_strstrip(e);
	g_snprintf(c_tmp, sizeof(c_tmp), "%d", listen_port);
	gtk_widget_set_sensitive(button_config_update_port, (gboolean) g_strcasecmp(c_tmp, e));
	g_free(e);
}

void on_button_config_update_port_clicked (GtkButton *button, gpointer user_data)
{
	config_port_update_request();
}

void on_checkbutton_config_throttle_toggled (GtkToggleButton *togglebutton, gpointer user_data)
{
}

void on_entry_config_maxttl_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_maxttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_maxttl)));
	g_strstrip(e);
	v = atoi(e);
	if (v > 0 && v < 255) max_ttl = v;
	gui_update_max_ttl();
	g_free(e);
	return TRUE;
}

void on_entry_config_myttl_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_myttl_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_myttl)));
	g_strstrip(e);
	v = atoi(e);
	if (v > 0 && v < 255) my_ttl = v;
	gui_update_my_ttl();
	g_free(e);
	return TRUE;
}

void on_entry_config_speed_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_speed_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_speed)));
	g_strstrip(e);
	v = atol(e);
	if (v > 0 && v < 65535) connection_speed = v;
	gui_update_connection_speed();
	g_free(e);
	return TRUE;
}

void on_entry_config_search_items_activate (GtkEditable *editable, gpointer user_data)
{
	gtk_widget_grab_focus(clist_menu); /* This will generate a focus out event (next func) */
}

gboolean on_entry_config_search_items_focus_out_event (GtkWidget *widget, GdkEventFocus *event, gpointer user_data)
{
	guint32 v;
	gchar *e = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry_config_search_items)));
	g_strstrip(e);
	v = atol(e);
	if (v > 0 && v < 256) search_max_items = v;
	gui_update_search_max_items();
	g_free(e);
	return TRUE;
}

void on_button_extra_config_clicked (GtkButton *button, gpointer user_data)
{
	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), 6);
}

/* vi: set ts=3: */

