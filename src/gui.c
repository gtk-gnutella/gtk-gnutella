
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

gchar gui_tmp[4096];

/* If no search are currently allocated */
GtkWidget *default_search_clist = NULL;
GtkWidget *default_scrolled_window = NULL;

void gui_set_status(gchar * msg)
{
	if (msg) {
		gtk_label_set(GTK_LABEL(label_left), msg);
		gtk_label_set(GTK_LABEL(label_right), "");
	} else {
		gtk_label_set(GTK_LABEL(label_left), "");
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", GTA_WEBSITE);
		gtk_label_set(GTK_LABEL(label_right), gui_tmp);
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

	iport = ip_port_to_gchar(force_local_ip ? forced_local_ip : local_ip,
							 listen_port);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", listen_port);
	gtk_entry_set_text(GTK_ENTRY(entry_config_port), gui_tmp);
	g_snprintf(gui_tmp, sizeof(gui_tmp), "Current IP:port : %s", iport);
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
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u gnutellaNet",
		connected_nodes(), node_count());
	gtk_clist_set_text(GTK_CLIST(clist_connections), 0, 0, gui_tmp);
}

void gui_update_c_uploads(void)
{
	gint i = running_uploads;
	gint t = registered_uploads;
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");
	gtk_clist_set_text(GTK_CLIST(clist_connections), 1, 0, gui_tmp);
}

void gui_update_c_downloads(gint c, gint ec)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u/%u download%s", c, ec,
			   (c == 1 && ec == 1) ? "" : "s");
	gtk_clist_set_text(GTK_CLIST(clist_connections), 2, 0, gui_tmp);
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

void gui_update_files_scanned(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "Files scanned: %u",
			   files_scanned);
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
	gtk_entry_set_text(GTK_ENTRY(config_entry_socks_host), gui_tmp);
}

void gui_update_socks_port()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", proxy_port);
	gtk_entry_set_text(GTK_ENTRY(config_entry_socks_port), gui_tmp);
}

void gui_update_socks_user()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", socksv5_user);
	gtk_entry_set_text(GTK_ENTRY(config_entry_socks_username), gui_tmp);
}

void gui_update_socks_pass()
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", socksv5_pass);
	gtk_entry_set_text(GTK_ENTRY(config_entry_socks_password), gui_tmp);
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

void gui_update_stats(void)
{
	guint32 hosts, files, ping;
	guint64 kbytes;
	static gchar b[256];

	if (pr_ref) {
		hosts = pr_ref->hosts;
		files = pr_ref->files;
		kbytes = pr_ref->kbytes;
		ping = pr_ref->delay / pr_ref->hosts;
	} else
		hosts = files = kbytes = ping = 0;

	if (files_scanned > 0) {
		files += files_scanned;
		kbytes += kbytes_scanned;
	}

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u hosts", hosts);
	gtk_clist_set_text(GTK_CLIST(clist_stats), 0, 0, gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u files", files);
	gtk_clist_set_text(GTK_CLIST(clist_stats), 1, 0, gui_tmp);

	if (kbytes < 1024)
		g_snprintf(b, sizeof(b), "%u KB", (guint32) kbytes);
	else if (kbytes < 1048576)
		g_snprintf(b, sizeof(b), "%.1f MB", (double) kbytes / 1024.0);
	else if (kbytes < 1073741824)
		g_snprintf(b, sizeof(b), "%.1f GB", (double) kbytes / 1048576.0);
	else
		g_snprintf(b, sizeof(b), "%.2f TB",
				   (double) kbytes / 1073741824.0);

	gtk_clist_set_text(GTK_CLIST(clist_stats), 2, 0, b);

	if (ping < 1000)
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%u ms avg ping", ping);
	else
		g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f s avg ping",
				   ping / 1000.0);
	gtk_clist_set_text(GTK_CLIST(clist_stats), 3, 0, gui_tmp);
}

void gui_update_global(void)
{
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
}

void gui_update_node(struct gnutella_node *n, gboolean force)
{
	gchar *a = (gchar *) NULL;
	gint row;

	if (n->last_update == time((time_t *) NULL) && !force)
		return;

	switch (n->status) {
	case GTA_NODE_CONNECTING:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "[%d.%d] Connecting...",
			n->proto_major, n->proto_minor);
		a = gui_tmp;
		break;

	case GTA_NODE_HELLO_SENT:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "[%d.%d] Hello sent",
			n->proto_major, n->proto_minor);
		a = gui_tmp;
		break;

	case GTA_NODE_WELCOME_SENT:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "[%d.%d] Welcome sent",
			n->proto_major, n->proto_minor);
		a = gui_tmp;
		break;

	case GTA_NODE_CONNECTED:
		if (n->sent || n->received)
			g_snprintf(gui_tmp, sizeof(gui_tmp),
			   "[%d.%d] Connected: TX=%-8d\tRX=%-8d\tDrop=%-8d\tBad=%-8d",
			   n->proto_major, n->proto_minor,
			   n->sent, n->received, n->dropped, n->n_bad);
		else
			g_snprintf(gui_tmp, sizeof(gui_tmp), "[%d.%d] Connected",
			   n->proto_major, n->proto_minor);
		a = gui_tmp;
		break;

	case GTA_NODE_REMOVING:
		a = (gchar *) ((n->remove_msg) ? n->remove_msg : "Removing");
		break;

	case GTA_NODE_RECEIVING_HELLO:
		g_snprintf(gui_tmp, sizeof(gui_tmp), "[%d.%d] Receiving Hello",
			n->proto_major, n->proto_minor);
		a = gui_tmp;
		break;

	default:
		a = "UNKNOWN STATUS";
	}

	n->last_update = time((time_t *) NULL);

	row =
		gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
	gtk_clist_freeze(GTK_CLIST(clist_nodes));
	gtk_clist_set_text(GTK_CLIST(clist_nodes), row, 2, a);
	gtk_clist_thaw(GTK_CLIST(clist_nodes));
}

/* */

void gui_update_download_abort_resume(void)
{
	struct download *d;
	GList *l;

	gboolean abort = FALSE, resume = FALSE;

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next) {
		d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_downloads),
								   (gint) l->data);

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
			break;
		case GTA_DL_TIMEOUT_WAIT:
		case GTA_DL_STOPPED:
			abort = resume = TRUE;
			break;
		}

		if (abort & resume)
			break;
	}

	gtk_widget_set_sensitive(button_abort_download, abort);
	gtk_widget_set_sensitive(button_resume_download, resume);
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

	gtk_widget_set_sensitive(button_kill_upload, d ? 1 : 0);
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

	gtk_widget_set_sensitive(button_clear_download, clear);
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
			gfloat rate = ((d->size - d->skip) / 1024.0) /
				(d->last_update - d->start_date);
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (%.1f k/s)",
					   rate);
		} else {
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
		}
		a = gui_tmp;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos - d->skip > 0) {
			gfloat p = 0, bs = now - d->start_date;

			if (d->size)
				p = ((gfloat) d->pos / (gfloat) d->size) * 100.0;

			if (bs) {
				gint slen;
				guint32 s;

				bs = ((d->pos - d->skip) / bs);
				s = (d->size - d->pos) / bs;
				bs = bs / 1024.0;

				slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% ", p);

				if (now - d->last_update > IO_STALLED)
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(stalled) ");
				else
					slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"(%.1f k/s) ", bs);

				if (s > 86400)
					g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TR: %ud %uh", s / 86400, (s % 86400) / 3600);
				else if (s > 3600)
					g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TR: %uh %um", s / 3600, (s % 3600) / 60);
				else if (s > 60)
					g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TR: %um %us", s / 60, s % 60);
				else
					g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
						"TR: %us", s);
			} else
				g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%%", p);

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

	if (!UPLOAD_IS_COMPLETE(u)) {
		gint slen;

		/*
		 * position divided by 1 percentage point, found by dividing
		 * the total size by 100
		 */
		pc = (u->pos) / ((u->file_size / 100.0));

		/*
		 * Data rate KBytes/second, K transfered (subtract off 1k remainder)
		 * divided by total seconds running
		 */
		if (u->last_update != u->start_date)
			rate = ((u->pos - u->skip) / 1024.0) /
				(u->last_update - u->start_date);

		/* Time Remaining at the current rate, in seconds  */
		if (fabs(rate) < .02)
			rate = 1;
		tr = ((u->file_size - u->pos) -
			  ((u->file_size - u->pos) % 1024)) / 1024 / rate;

		slen = g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% ", pc);

		if (time((time_t *) 0) - u->last_update > IO_STALLED)
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(stalled) ");
		else
			slen += g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"(%.1f k/s) ", rate);

		if (tr > 86400)
			g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"TR: %ud %uh", tr / 86400, (tr % 86400) / 3600);
		else if (tr > 3600)
			g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"TR: %uh %um", tr / 3600, (tr % 3600) / 60);
		else if (tr > 60)
			g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"TR: %um %us", tr / 60, tr % 60);
		else
			g_snprintf(&gui_tmp[slen], sizeof(gui_tmp)-slen,
				"TR: %us", tr);

	} else {
		if (u->last_update != u->start_date) {
			rate = ((u->file_size - u->skip) / 1024.0) /
				(u->last_update - u->start_date);
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (%.1f k/s)",
					   rate);
		} else {
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Completed (< 1s)");
		}
	}

	row =
		gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads),
									 (gpointer) u);

	gtk_clist_set_text(GTK_CLIST(clist_uploads), row, 2, gui_tmp);

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

void gui_close(void)
{
	if (scan_extensions)
		g_free(scan_extensions);
	if (shared_dirs_paths)
		g_free(shared_dirs_paths);
}

/* vi: set ts=4: */
