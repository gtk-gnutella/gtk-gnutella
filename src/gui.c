
/* gui functions */

#include "gnutella.h"
#include "interface.h"
#include "gui.h"
#include "sockets.h" /* For local_ip. (FIXME: move to config.h?) */
#include "search.h" /* For search_reissue_timeout. (FIXME: move to config.h?) */
#include "share.h" /* For stats globals. (FIXME: move to config.h?) */
#include "downloads.h" /* For stats globals. (FIXME: move to config.h?) */
#include "hosts.h" /* For pr_ref. (FIXME: ???) */
#include "misc.h"
#include "callbacks.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#define IO_STALLED		60		/* If nothing exchanged after that many secs */

static gchar gui_tmp[4096];

/* If no search are currently allocated */
GtkWidget *default_search_clist = NULL;
GtkWidget *default_scrolled_window = NULL;

/* statusbar context ids */
guint scid_bottom              = -1;
guint scid_hostsfile           = -1;
guint scid_search_autoselected = -1;
guint scid_queue_freezed       = -1;
guint scid_queue_remove_regex  = -1;

/* List with timeout entries for statusbar messages */
static GSList *sl_statusbar_timeouts = NULL;

static GList *sl_search_history = NULL;

void gui_init(void)
{
	/* popup menus */
	create_popup_nodes();
	create_popup_search();
	create_popup_monitor();
	create_popup_uploads();
	create_popup_dl_active();
	create_popup_dl_queued();	

	/* statusbar stuff */
	scid_bottom    = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "default");
	scid_hostsfile = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "reading hosts file");
	scid_search_autoselected = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "autoselected search items");
	scid_queue_freezed = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "queue freezed");	

   	scid_queue_remove_regex = 
		gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), 
                                     "queue remove regex");	

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", GTA_WEBSITE);
	gui_statusbar_push(scid_bottom, gui_tmp);

    /* search history combo stuff */
    gtk_combo_disable_activate(GTK_COMBO(combo_search));

    /* copy url selection stuff */
    gtk_selection_add_target(popup_dl_active, GDK_SELECTION_PRIMARY, 
                             GDK_SELECTION_TYPE_STRING, 1);

	// FIXME: all the widget from here to end have empty callback functions
	gtk_widget_set_sensitive(popup_queue_search_again, FALSE);
	gtk_widget_set_sensitive(popup_downloads_search_again, FALSE);
	// FIXME: end

	gtk_widget_set_sensitive(popup_downloads_remove_file, FALSE);
    gtk_widget_set_sensitive(popup_downloads_copy_url, FALSE);
    gtk_widget_set_sensitive(popup_nodes_remove, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort_named, FALSE);
	gtk_widget_set_sensitive(popup_queue_abort_host, FALSE);
    gtk_widget_set_sensitive(popup_downloads_push, 
                             !gtk_toggle_button_get_active(
								 GTK_TOGGLE_BUTTON(checkbutton_downloads_never_push)));


    gtk_clist_column_titles_passive(GTK_CLIST(clist_nodes));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_uploads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads_queue));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_monitor));

	gtk_clist_set_reorderable(GTK_CLIST(clist_downloads_queue), TRUE);

}

void gui_nodes_remove_selected(void)
{
	if (GTK_CLIST(clist_nodes)->selection) {
		struct gnutella_node *n;
		GList *l = GTK_CLIST(clist_nodes)->selection;

		while (l) {
			n = (struct gnutella_node *)
				gtk_clist_get_row_data(GTK_CLIST(clist_nodes),
                                   (gint) l->data);
        if (n) {
			if (NODE_IS_WRITABLE(n)) {
				node_bye(n, 201, "User manual removal");
				gtk_clist_unselect_row(GTK_CLIST(clist_nodes), 
                                       (gint) l->data, 0);
            } else {
				node_remove(n, NULL);
				node_real_remove(n);
            }
        } else 
			g_warning( "remove_selected_nodes(): row %d has NULL data\n",
                       (gint) l->data);
			l = GTK_CLIST(clist_nodes)->selection;
		}
	}
}

/* 
 * gui_statusbar_add_timeout:
 * 
 * Add a statusbar message id to the timeout list, so it will be removed
 * automatically after a number of seconds.
 */
void gui_statusbar_add_timeout(guint scid, guint msgid, guint timeout)
{
	struct statusbar_timeout * t = NULL;

    t = g_malloc0(sizeof(struct statusbar_timeout));
	
	t->scid    = scid;
	t->msgid   = msgid;
	t->timeout = time((time_t *) NULL) + timeout;

	sl_statusbar_timeouts = g_slist_prepend(sl_statusbar_timeouts, t);
}

/*
 * gui_statusbar_free_timeout:
 *
 * Remove the timeout from the timeout list and free allocated memory.
 */
static void gui_statusbar_free_timeout(struct statusbar_timeout * t)
{
	g_return_if_fail(t);

	gui_statusbar_remove(t->scid, t->msgid);

	sl_statusbar_timeouts = g_slist_remove(sl_statusbar_timeouts, t);
	
	g_free(t);
}

/*
 * gui_statusbar_clear_timeouts
 *
 * Check wether statusbar items have expired and remove them from the statusbar.
 */
void gui_statusbar_clear_timeouts(time_t now)
{
	GSList *to_remove = NULL;
	GSList *l;
	
	for (l = sl_statusbar_timeouts; l; l = l->next) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;

		if (now > t->timeout)  
			to_remove = g_slist_prepend(to_remove, t);
	}

	for (l = to_remove; l; l = l->next)
		gui_statusbar_free_timeout((struct statusbar_timeout *) l->data);

	g_slist_free(to_remove);
}

/*
 * gui_statusbar_free_timeout_list:
 *
 * Clear the whole timeout list and free allocated memory.
 */
static void gui_statusbar_free_timeout_list() 
{
	GSList *l;

	for (l = sl_statusbar_timeouts; l; l = sl_statusbar_timeouts) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;
		
		gui_statusbar_free_timeout(t);
	}
}

void gui_update_config_force_ip(void)
{
	gtk_entry_set_text(GTK_ENTRY(entry_config_force_ip),
					   ip_to_gchar(forced_local_ip));
}

void gui_update_config_port(void)
{
	gchar *iport;

    // FIXME: if port/ip have changed display this as a notice in
    // the statusbar
    //      --BLUE, 30/04/2002

	iport = ip_port_to_gchar(listen_ip(), listen_port);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", listen_port);
	gtk_entry_set_text(GTK_ENTRY(entry_config_port), gui_tmp);
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", iport);
	gtk_label_set(GTK_LABEL(label_current_port), gui_tmp);
}

void gui_update_max_ttl(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_ttl);
	gtk_entry_set_text(GTK_ENTRY(entry_config_maxttl), gui_tmp);
}

void gui_update_my_ttl(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", my_ttl);
	gtk_entry_set_text(GTK_ENTRY(entry_config_myttl), gui_tmp);
}

void gui_update_up_connections(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", up_connections);
	gtk_entry_set_text(GTK_ENTRY(entry_up_connections), gui_tmp);
}

void gui_update_max_connections(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_connections);
	gtk_entry_set_text(GTK_ENTRY(entry_max_connections), gui_tmp);
}

void gui_update_search_reissue_timeout()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_reissue_timeout);
	gtk_entry_set_text(GTK_ENTRY(entry_search_reissue_timeout), gui_tmp);
}

void gui_update_minimum_speed(guint32 s)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", s);
	gtk_entry_set_text(GTK_ENTRY(entry_minimum_speed), gui_tmp);
}

void gui_update_count_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", count_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_count_downloads), gui_tmp);
}

void gui_update_count_uploads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", count_uploads);
	gtk_entry_set_text(GTK_ENTRY(entry_count_uploads), gui_tmp);
}

void gui_update_save_file_path(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", save_file_path);
	gtk_label_set(GTK_LABEL(GTK_BIN(button_config_save_path)->child),
				  gui_tmp);
}

void gui_update_move_file_path(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", move_file_path);
	gtk_label_set(GTK_LABEL(GTK_BIN(button_config_move_path)->child),
				  gui_tmp);
}

void gui_update_monitor_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", monitor_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_monitor), gui_tmp);
}

/* --------- */

void gui_update_c_gnutellanet(void)
{
	gint nodes = node_count();

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u gnutellaNet",
		connected_nodes(), nodes);
    gtk_progress_configure(GTK_PROGRESS(progressbar_connections), 
                           connected_nodes(), 0, nodes);
}

void gui_update_c_uploads(void)
{
	gint i = running_uploads;
	gint t = registered_uploads;
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");
    gtk_progress_configure(GTK_PROGRESS(progressbar_uploads), 
                           i, 0, t);
}

void gui_update_c_downloads(gint c, gint ec)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u download%s", c, ec,
			   (c == 1 && ec == 1) ? "" : "s");
    gtk_progress_configure(GTK_PROGRESS(progressbar_downloads), 
                           c, 0, ec);
}

void gui_update_max_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_downloads), gui_tmp);
}

void gui_update_max_host_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_host_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_host_downloads), gui_tmp);
}

void gui_update_max_uploads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_uploads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_uploads), gui_tmp);
}

void gui_update_max_host_uploads(void)
{
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_uploads_max_ip),
                              max_uploads_ip);
}


void gui_update_files_scanned(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u file%s shared (%s)",
		files_scanned, files_scanned == 1 ? "" : "s",
		short_kb_size(kbytes_scanned));
	gtk_label_set(GTK_LABEL(label_files_scanned), gui_tmp);
}

void gui_update_connection_speed(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", connection_speed);
	gtk_entry_set_text(GTK_ENTRY(entry_config_speed), gui_tmp);
}

void gui_update_search_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d", search_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_config_search_items), gui_tmp);
}

#if 0
void gui_update_search_reissue_timeout(GtkEntry *
									   entry_search_reissue_timeout)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d", search_reissue_timeout);
	gtk_entry_set_text(entry_search_reissue_timeout, gui_tmp);
}
#endif

void gui_update_socks_host()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", proxy_ip);
	gtk_entry_set_text(GTK_ENTRY(entry_config_socks_host), gui_tmp);
}

void gui_update_socks_port()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", proxy_port);
	gtk_entry_set_text(GTK_ENTRY(entry_config_socks_port), gui_tmp);
}

void gui_update_socks_user()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", socksv5_user);
	gtk_entry_set_text(GTK_ENTRY(entry_config_socks_username), gui_tmp);
}

void gui_update_socks_pass()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", socksv5_pass);
	gtk_entry_set_text(GTK_ENTRY(entry_config_socks_password), gui_tmp);
}

void gui_update_bandwidth_input()
{
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_config_bps_in),
						      input_bandwidth);
}

void gui_update_bandwidth_output()
{
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(spinbutton_config_bps_out),
						      output_bandwidth);
}


/*
 * gui_update_config_netmasks
 *
 * Update the gui with info from the config file
 */
void gui_update_config_netmasks()
{
	gtk_toggle_button_set_active(
		GTK_TOGGLE_BUTTON(checkbutton_config_use_netmasks), use_netmasks);
	if (local_netmasks_string)
		gtk_entry_set_text(GTK_ENTRY(entry_config_netmasks),
			local_netmasks_string);
}

void gui_update_scan_extensions(void)
{
	GSList *l;

	g_free(scan_extensions);

	*gui_tmp = 0;

	for (l = extensions; l; l = l->next) {
		struct extension *e = (struct extension *) l->data;
		if (*gui_tmp)
			strcat(gui_tmp, ";");
		strcat(gui_tmp, (gchar *) e->str);
	}

	scan_extensions = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_extensions),
					   scan_extensions);
	gtk_entry_set_position(GTK_ENTRY(entry_config_extensions), 0);
}

void gui_update_shared_dirs(void)
{
	GSList *l;

	g_free(shared_dirs_paths);

	*gui_tmp = 0;

	for (l = shared_dirs; l; l = l->next) {
		if (*gui_tmp)
			strcat(gui_tmp, ":");
		strcat(gui_tmp, (gchar *) l->data);
	}

	shared_dirs_paths = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_path), shared_dirs_paths);
	gtk_entry_set_position(GTK_ENTRY(entry_config_path), 0);

#if 0
	gtk_widget_set_sensitive (button_config_rescan_dir,
		(gboolean) *shared_dirs_paths);

	gtk_widget_set_sensitive (button_config_rescan_dir, FALSE);
#endif

}

void gui_update_global(void)
{
	static gboolean startupset = FALSE;
	static time_t   startup;

	time_t now = time((time_t *) NULL);	

	if( !startupset ) {
		startup = time((time_t *) NULL);
		startupset = TRUE;
	}

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", global_messages);
	gtk_entry_set_text(GTK_ENTRY(entry_global_messages), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", global_searches);
	gtk_entry_set_text(GTK_ENTRY(entry_global_searches), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", routing_errors);
	gtk_entry_set_text(GTK_ENTRY(entry_routing_errors), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", dropped_messages);
	gtk_entry_set_text(GTK_ENTRY(entry_dropped_messages), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", hosts_in_catcher);
	gtk_entry_set_text(GTK_ENTRY(entry_hosts_in_catcher), gui_tmp);

	
    g_snprintf(gui_tmp, sizeof(gui_tmp),  "Uptime: %s", 
							   short_uptime((guint32) difftime(now,startup)));
	gtk_label_set_text(GTK_LABEL(label_statusbar_uptime), gui_tmp);

	/*
	 * Since gtk_progress does not give us enough control over the format
     * of the displayed values, we have regenerate the value string on each
     * update.
	 *      --BLUE, 21/04/2002
	 */
	
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s in %s", 
			   compact_size(progressbar_bps_in_avg ? bsched_avg_bps(bws_in) : 
										             bsched_bps(bws_in)),
			   progressbar_bps_in_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bps_in), gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s/s out %s", 
			   compact_size(progressbar_bps_out_avg ? bsched_avg_bps(bws_out) :
										              bsched_bps(bws_out)),
			   progressbar_bps_out_avg ? "(avg)" : "");
	gtk_progress_set_format_string(GTK_PROGRESS(progressbar_bps_out), gui_tmp);

	/*
	 * If the bandwidth usage peaks above the maximum, then GTK will not
	 * update the progress bar, so we have to cheat and limit the value
	 * displayed.
	 *		--RAM, 16/04/2002
	 */

	gtk_progress_configure(GTK_PROGRESS(progressbar_bps_in), 
    	MIN(progressbar_bps_in_avg ? bsched_avg_bps(bws_in) : 
									 bsched_bps(bws_in), 
			bws_in->bw_per_second),
		0, bws_in->bw_per_second);

	gtk_progress_configure(GTK_PROGRESS(progressbar_bps_out), 
    	MIN(progressbar_bps_out_avg ? bsched_avg_bps(bws_out) :
									  bsched_bps(bws_out), 
			bws_out->bw_per_second),
		0, bws_out->bw_per_second);
}

void gui_update_node_display(struct gnutella_node *n, time_t now)
{
	gchar *a = (gchar *) NULL;
	gint row;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_NODE_HELLO_SENT:
		a = "Hello sent";
		break;

	case GTA_NODE_WELCOME_SENT:
		a = "Welcome sent";
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received) {
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"TX=%d RX=%d Query(TX=%d, Q=%d) Drop(TX=%d, RX=%d) "
				"Dup=%d Bad=%d Q=%d,%d%% %s",
				n->sent, n->received,
				NODE_SQUEUE_SENT(n), NODE_SQUEUE_COUNT(n),
				n->tx_dropped, n->rx_dropped, n->n_dups, n->n_bad,
				NODE_MQUEUE_COUNT(n), NODE_MQUEUE_PERCENT_USED(n),
				NODE_IN_TX_FLOW_CONTROL(n) ? " [FC]" : "");
			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_NODE_SHUTDOWN:
		{
			gint spent = now - n->shutdown_date;
			gint remain = n->shutdown_delay - spent;
			if (remain < 0)
				remain = 0;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Closing: %s [Stop in %ds] RX=%d Q=%d,%d%%",
				n->error_str, remain, n->received,
				NODE_MQUEUE_COUNT(n), NODE_MQUEUE_PERCENT_USED(n));
			a = gui_tmp;
		}
		break;

	case GTA_NODE_REMOVING:
		a = (gchar *) ((n->remove_msg) ? n->remove_msg : "Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		a = "Receiving hello";
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_freeze(GTK_CLIST(clist_nodes));
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 4, a);
	gtk_clist_thaw(GTK_CLIST(clist_nodes));
}

void gui_update_node(struct gnutella_node *n, gboolean force)
{
	time_t now = time((time_t *) NULL);

	if (n->last_update == now && !force)
		return;
	n->last_update = now;

	gui_update_node_display(n, now);
}

void gui_update_node_proto(struct gnutella_node *n)
{
	gint row;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%d.%d",
		n->proto_major, n->proto_minor);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 3, gui_tmp);
}

void gui_update_node_vendor(struct gnutella_node *n)
{
	gint row;

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 2,
		n->vendor ? n->vendor : "");
}

/* */

void gui_update_download_abort_resume(void)
{
	struct download *d;
	GList *l;

	gboolean abort  = FALSE;
    gboolean resume = FALSE;
    gboolean remove = FALSE;
    gboolean queue  = FALSE;

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next) {
		d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);

        if (!d) {
			g_warning
				("gui_update_download_abort_resume(): row %d has NULL data\n",
				 (gint) l->data);
			continue;
		}

        if (d->status != GTA_DL_COMPLETED)
            queue = TRUE;

		switch (d->status) {
		case GTA_DL_QUEUED:
			fprintf(stderr, "gui_update_download_abort_resume(): "
				"found queued download '%s' in active download list !\n",
				d->file_name);
			continue;
		case GTA_DL_CONNECTING:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_REQ_SENT:
		case GTA_DL_HEADERS:
		case GTA_DL_RECEIVING:
			abort = TRUE;
			break;
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			resume = TRUE;
            /* only check if file exists if really necessary */
            if (!remove && download_file_exists(d))
                remove = TRUE;
			break;
		case GTA_DL_TIMEOUT_WAIT:
		case GTA_DL_STOPPED:
			abort = resume = TRUE;
			break;
		}

		if (abort & resume & remove)
			break;
	}

	gtk_widget_set_sensitive(button_downloads_abort, abort);
	gtk_widget_set_sensitive(popup_downloads_abort, abort);
    gtk_widget_set_sensitive(popup_downloads_abort_named, abort);
    gtk_widget_set_sensitive(popup_downloads_abort_host, abort);
	gtk_widget_set_sensitive(button_downloads_resume, resume);
	gtk_widget_set_sensitive(popup_downloads_resume, resume);
    gtk_widget_set_sensitive(popup_downloads_remove_file, remove);
    gtk_widget_set_sensitive(popup_downloads_queue, queue);
}

void gui_update_upload_kill(void)
{
	GList *l = NULL;
	struct upload *d = NULL;

	for (l = GTK_CLIST(clist_uploads)->selection; l; l = l->next) {
		d = (struct upload *)
			gtk_clist_get_row_data(GTK_CLIST(clist_uploads),
								   (gint) l->data);
		if (UPLOAD_IS_COMPLETE(d)) {
			d = NULL;
			break;
		}
	}

	gtk_widget_set_sensitive(button_uploads_kill, d ? 1 : 0);
}


void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

	for (l = sl_downloads; !clear && l; l = l->next) {
		switch (((struct download *) l->data)->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			clear = TRUE;
			break;
		default:
			break;
		}
	}

	gtk_widget_set_sensitive(button_downloads_clear_completed, clear);
}

void gui_update_download(struct download *d, gboolean force)
{
	gchar *a = NULL;
	gint row;
	time_t now = time((time_t *) NULL);

	if (d->last_gui_update == now && !force)
		return;

	d->last_gui_update = now;

	switch (d->status) {
	case GTA_DL_QUEUED:
		a = "QUEUED REQUEST ?!";
		break;

	case GTA_DL_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_DL_PUSH_SENT:
		a = "Push sent";
		break;

	case GTA_DL_REQ_SENT:
		a = "Request sent";
		break;

	case GTA_DL_HEADERS:
		a = "Receiving headers";
		break;

	case GTA_DL_ABORTED:
		a = "Aborted";
		break;

	case GTA_DL_FALLBACK:
		a = "Falling back to push";
		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 spent = d->last_update - d->start_date;

			gfloat rate = ((d->size - d->skip + d->overlap_size) /
				1024.0) / spent;
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (%.1f k/s) %s",
				rate, short_time(spent));
		} else {
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
		}
		a = gui_tmp;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos - d->skip > 0) {
			gfloat p = 0;
			gint bps;
			guint32 avg_bps;

			if (d->size)
				p = d->pos * 100.0 / d->size;

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = (d->pos - d->skip) / (d->last_update - d->start_date);

			if (avg_bps) {
				gint slen;
				guint32 s;
				gfloat bs;

				s = (d->size - d->pos) / avg_bps;
				bs = bps / 1024.0;

				slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%% ", p);

				if (now - d->last_update > IO_STALLED)
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(stalled) ");
				else
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(%.1f k/s) ", bs);

				g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
					"TR: %s", short_time(s));
			} else
				g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%%%s", p,
					(now - d->last_update > IO_STALLED) ? " (stalled)" : "");

			a = gui_tmp;
		} else
			a = "Connected";
		break;

	case GTA_DL_STOPPED:
	case GTA_DL_ERROR:
		a = (gchar *) ((d->remove_msg) ? d->remove_msg : "Unknown Error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "Retry in %lds",
				   d->timeout_delay - (now - d->last_update));
		a = gui_tmp;
		break;
	default:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "UNKNOWN STATUS %u",
				   d->status);
		a = gui_tmp;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (d->status != GTA_DL_QUEUED) {
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads),
			(gpointer) d);
		gtk_clist_set_text(GTK_CLIST(clist_downloads), row, 3, a);
	}
}

void gui_update_upload(struct upload *u)
{
	gfloat rate = 1, pc = 0;
	guint32 tr = 0;
	gint row;
	gchar gui_tmp[256];
	guint32 requested = u->end - u->skip + 1;

	if (u->pos < u->skip)
		return;					/* Never wrote anything yet */

	if (!UPLOAD_IS_COMPLETE(u)) {
		gint slen;
		guint32 bps = 1;
		guint32 avg_bps = 1;

		/*
		 * position divided by 1 percentage point, found by dividing
		 * the total size by 100
		 */
		pc = (u->pos - u->skip) * 100.0 / requested;

		if (u->bio) {
			bps = bio_bps(u->bio);
			avg_bps = bio_avg_bps(u->bio);
		}

		if (avg_bps <= 10 && u->last_update != u->start_date)
			avg_bps = (u->pos - u->skip) / (u->last_update - u->start_date);
		if (avg_bps == 0)
			avg_bps++;

		rate = bps / 1024.0;

		/* Time Remaining at the current rate, in seconds  */
		tr = (u->end + 1 - u->pos) / avg_bps;

		slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.02f%% ", pc);

		if (time((time_t *) 0) - u->last_update > IO_STALLED)
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(stalled) ");
		else
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(%.1f k/s) ", rate);

		g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
			"TR: %s", short_time(tr));
	} else {
		if (u->last_update != u->start_date) {
			guint32 spent = u->last_update - u->start_date;

			rate = (requested / 1024.0) / spent;
			g_snprintf(gui_tmp, sizeof(gui_tmp),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
	}

	row =
		gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads),
									 (gpointer) u);

	gtk_clist_set_text(GTK_CLIST(clist_uploads), row, 4, gui_tmp);
}

/* Create a new GtkCList for search results */

void gui_search_create_clist(GtkWidget ** sw, GtkWidget ** clist)
{
	GtkWidget *label;
	gint i;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
								   GTK_POLICY_AUTOMATIC,
								   GTK_POLICY_AUTOMATIC);

	*clist = gtk_clist_new(5);

	gtk_container_add(GTK_CONTAINER(*sw), *clist);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(*clist), i,
								   search_results_col_widths[i]);
	gtk_clist_set_selection_mode(GTK_CLIST(*clist),
								 GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(GTK_CLIST(*clist));

	label = gtk_label_new("File");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 0, label);

	label = gtk_label_new("Size");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 1, label);

	label = gtk_label_new("Speed");
	gtk_widget_show(label);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 2, label);

	label = gtk_label_new("Host");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 3, label);

	label = gtk_label_new("Info");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 4, label);

	gtk_widget_show_all(*sw);

	gtk_signal_connect(GTK_OBJECT(*clist), "select_row",
					   GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "unselect_row",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_unselect_row), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "click_column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_click_column), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "button_press_event",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_button_press_event), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "resize-column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_resize_column), NULL);
}

void gui_search_update_items(struct search *sch)
{
	if (sch && sch->items)
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%u item%s found", sch->items,
				   (sch->items > 1) ? "s" : "");
	else
		g_snprintf(gui_tmp, sizeof(gui_tmp), "No item found");
	gtk_label_set(GTK_LABEL(label_items_found), gui_tmp);
}

void gui_search_init(void)
{
	gui_search_create_clist(&default_scrolled_window, &default_search_clist);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_search_results), 0);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook_search_results),
								TRUE);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
							 default_scrolled_window, NULL);
	gtk_signal_connect(GTK_OBJECT(GTK_COMBO(combo_searches)->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);
	gtk_window_set_position(GTK_WINDOW(dialog_filters),
							GTK_WIN_POS_CENTER);
}

/* Like search_update_tab_label but always update the label */
void gui_search_force_update_tab_label(struct search *sch)
{
	if (sch == current_search || sch->unseen_items == 0)
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%s\n(%d)", sch->query,
				   sch->items);
	else
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook_search_results),
									sch->scrolled_window, gui_tmp);
	sch->last_update_time = time(NULL);
}

/* Doesn't update the label if nothing's changed or if the last update was
   recent. */
gboolean gui_search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (time(NULL) - sch->last_update_time < tab_update_time)
		return TRUE;

	gui_search_force_update_tab_label(sch);

	return TRUE;
}

void gui_search_clear_results(void)
{
	gtk_clist_clear(GTK_CLIST(current_search->clist));
	current_search->items = current_search->unseen_items = 0;
	gui_search_force_update_tab_label(current_search);
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
void gui_search_history_add(gchar * s)
{
    GList *new_hist = NULL;
    GList *cur_hist = sl_search_history;
    guint n = 0;

    g_return_if_fail(s);

    while (cur_hist != NULL) {
        if ((n < 9) && (g_strcasecmp(s,cur_hist->data) != 0)) {
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
    gtk_combo_set_popdown_strings(GTK_COMBO(combo_search),new_hist);

    /* free old list structure */
    g_list_free(sl_search_history);
    
    sl_search_history = new_hist;
}

void gui_close(void)
{
	gui_statusbar_free_timeout_list();
	if (scan_extensions)
		g_free(scan_extensions);
	if (shared_dirs_paths)
		g_free(shared_dirs_paths);
}

void gui_update_search_stats_update_interval(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_stats_update_interval);
	gtk_entry_set_text(GTK_ENTRY(entry_search_stats_update_interval), gui_tmp);
}

void gui_update_search_stats_delcoef(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_stats_delcoef);
	gtk_entry_set_text(GTK_ENTRY(entry_search_stats_delcoef), gui_tmp);
}

/* vi: set ts=4: */
