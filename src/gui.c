
/* gui functions */

#include "gnutella.h"
#include "interface.h"

#include <netinet/in.h>
#include <arpa/inet.h>

gchar gui_tmp[4096];

void gui_set_status(gchar *msg)
{
	if (msg)
	{
		gtk_label_set(GTK_LABEL(label_left), msg);
		gtk_label_set(GTK_LABEL(label_right), "");
	}
	else
	{
		gtk_label_set(GTK_LABEL(label_left), "");
		g_snprintf(gui_tmp, sizeof(gui_tmp), "(c) Olrick - %s", GTA_WEBSITE);
		gtk_label_set(GTK_LABEL(label_right), gui_tmp);
	}
}

void gui_update_config_force_ip(void)
{
	gtk_entry_set_text(GTK_ENTRY(entry_config_force_ip), ip_to_gchar(forced_local_ip));
}
	
void gui_update_config_port(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", listen_port);
	gtk_entry_set_text(GTK_ENTRY(entry_config_port), gui_tmp);
	g_snprintf(gui_tmp, sizeof(gui_tmp), "Current port : %u", listen_port);
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
	gtk_label_set(GTK_LABEL(GTK_BIN(button_config_save_path)->child), gui_tmp);
}

void gui_update_move_file_path(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%s", move_file_path);
	gtk_label_set(GTK_LABEL(GTK_BIN(button_config_move_path)->child), gui_tmp);
}

void gui_update_monitor_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", monitor_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_monitor), gui_tmp);
}
 
/* --------- */

void gui_update_c_gnutellanet(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u gnutellaNet", nodes_in_list);
	gtk_clist_set_text(GTK_CLIST(clist_connections), 0, 0, gui_tmp);
}

void gui_update_c_uploads(void)
{
	gint i = g_slist_length(uploads);
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u upload%s", i, (i == 1)? "" : "s");
	gtk_clist_set_text(GTK_CLIST(clist_connections), 1, 0, gui_tmp);
}

void gui_update_c_downloads(gint c)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u download%s", c, (c == 1)? "" : "s");
	gtk_clist_set_text(GTK_CLIST(clist_connections), 2, 0, gui_tmp);
}

void gui_update_max_downloads(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", max_downloads);
	gtk_entry_set_text(GTK_ENTRY(entry_max_downloads), gui_tmp);
}


void gui_update_files_scanned(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "Files scanned: %u", files_scanned);
	gtk_label_set(GTK_LABEL(label_files_scanned), gui_tmp);
}

void gui_update_connection_speed(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", connection_speed);
	gtk_entry_set_text(GTK_ENTRY(entry_config_speed), gui_tmp);
}

void gui_update_search_max_items(void)
{
	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u", search_max_items);
	gtk_entry_set_text(GTK_ENTRY(entry_config_search_items), gui_tmp);
}

void gui_update_scan_extensions(void)
{
	GSList *l;

	g_free(scan_extensions);

	*gui_tmp = 0;

	for (l = extensions; l; l = l->next)
	{
		if (*gui_tmp) strcat(gui_tmp, ";");
		strcat(gui_tmp, (gchar *) l->data);
	}

	scan_extensions = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_extensions), scan_extensions);
	gtk_entry_set_position(GTK_ENTRY(entry_config_extensions), 0);
}

void gui_update_shared_dirs(void)
{
	GSList *l;

	g_free(shared_dirs_paths);

	*gui_tmp = 0;

	for (l = shared_dirs; l; l = l->next)
	{
		if (*gui_tmp) strcat(gui_tmp, ":");
		strcat(gui_tmp, (gchar *) l->data);
	}

	shared_dirs_paths = g_strdup(gui_tmp);

	gtk_entry_set_text(GTK_ENTRY(entry_config_path), shared_dirs_paths);
	gtk_entry_set_position(GTK_ENTRY(entry_config_path), 0);

/*	gtk_widget_set_sensitive (button_config_rescan_dir, (gboolean) *shared_dirs_paths); */
	gtk_widget_set_sensitive (button_config_rescan_dir, FALSE);
}

void gui_update_stats(void)
{
	guint32 hosts, files, ping;
	guint64 kbytes;
	static gchar b[256];

	if (pr_ref)
	{
		hosts  = pr_ref->hosts;
		files  = pr_ref->files;
		kbytes = pr_ref->kbytes;
		ping   = pr_ref->delay / pr_ref->hosts;
	}
	else hosts = files = kbytes = ping = 0;

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u hosts", hosts);
	gtk_clist_set_text(GTK_CLIST(clist_stats), 0, 0, gui_tmp);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%u files", files);
	gtk_clist_set_text(GTK_CLIST(clist_stats), 1, 0, gui_tmp);

	if (kbytes < 1024) g_snprintf(b, sizeof(b), "%qu KB", kbytes);
	else if (kbytes < 1048576) g_snprintf(b, sizeof(b), "%.1fMB", (double) kbytes / 1024.0);
	else if (kbytes < 1073741824) g_snprintf(b, sizeof(b), "%.1fGB", (double) kbytes / 1048576.0);
	else g_snprintf(b, sizeof(b), "%.2fTB", (double) kbytes / 1073741824.0);

	gtk_clist_set_text(GTK_CLIST(clist_stats), 2, 0, b);

	g_snprintf(gui_tmp, sizeof(gui_tmp), "%ums avg ping", ping);
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
}

void gui_update_node(struct gnutella_node *n, gboolean force)
{
	gchar *a = (gchar *) NULL;
	gint row;

	if (n->last_update == time((time_t *) NULL) && !force) return;

	switch(n->status)
	{
		case GTA_NODE_CONNECTING:
			a = "Connecting";
			break;

		case GTA_NODE_HELLO_SENT:
			a = "Hello sent";
			break;

		case GTA_NODE_WELCOME_SENT:
			a = "Welcome sent";
			break;

		case GTA_NODE_CONNECTED:

			if (n->sent || n->received)
			{
				g_snprintf(gui_tmp, sizeof(gui_tmp), "Connected: %d/%d/%d", n->sent, n->received, n->dropped);
				a = gui_tmp;
			}
			else a = "Connected";

			break;

		case GTA_NODE_REMOVING:

			a = (gchar *) ((n->remove_msg)? n->remove_msg : "Removing");
			break;

		default:
			a = "UNKNOWN STATUS";
	}

	n->last_update = time((time_t *) NULL);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_nodes), (gpointer) n);
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

	for (l = GTK_CLIST(clist_downloads)->selection; l; l = l->next)
	{
		d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_downloads), (gint) l->data);

		switch (d->status)
		{
			case GTA_DL_QUEUED:
			{
				fprintf(stderr, "gui_update_download_abort_resume(): found queued download '%s' in active download list !\n", d->file_name);
				continue;
			}

			case GTA_DL_CONNECTING:
			case GTA_DL_PUSH_SENT:
			case GTA_DL_FALLBACK:
			case GTA_DL_REQ_SENT:
			case GTA_DL_HEADERS	:
			case GTA_DL_RECEIVING:
			{
				abort = TRUE;
				break;
			}

			case GTA_DL_ERROR:
			case GTA_DL_ABORTED:
			{
				resume = TRUE;
				break;
			}
		}

		if (abort & resume) break;
	}

	gtk_widget_set_sensitive(button_abort_download, abort);
	gtk_widget_set_sensitive(button_resume_download, resume);
}

void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

	for (l = sl_downloads; l; l = l->next)
	{
		switch (((struct download *) l->data)->status)
		{
			case GTA_DL_COMPLETED:
			case GTA_DL_ERROR:
			case GTA_DL_ABORTED:
			{
				clear = TRUE;
				break;
			}
		}
	}

	gtk_widget_set_sensitive(button_clear_download, clear);
}

void gui_update_download(struct download *d, gboolean force)
{
	gchar *a = NULL;
	gint row;

	if (d->last_update == time((time_t *) NULL) && !force) return;

	switch(d->status)
	{
		case GTA_DL_QUEUED:
			a= "QUEUED REQUEST ?!";
			break;

		case GTA_DL_CONNECTING:
			a = "Connecting";
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
			a = "Completed";
			break;

		case GTA_DL_RECEIVING:

			if (d->pos - d->skip > 0)
			{
				gfloat p = 0, bs = time((time_t *) NULL) - d->start_date;

				if (d->size) p = ((gfloat) d->pos / (gfloat) d->size) * 100.0;

				if (bs)
				{
					guint32 s;
					bs = ((d->pos - d->skip) / bs);
					s = (d->size - d->pos) / bs;
					bs = bs / 1024.0;

					if (s > 86400) g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% (%.1f k/s) TR: %ud %uh", p, bs, s / 86400, (s % 86400) / 3600);
					else if (s > 3600) g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% (%.1f k/s) TR: %uh %um", p, bs, s / 3600, (s % 3600) / 60);
					else if (s > 60) g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% (%.1f k/s) TR: %um %us", p, bs, s / 60, s % 60);
					else g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%% (%.1f k/s) TR: %us", p, bs, s);
				}
				else g_snprintf(gui_tmp, sizeof(gui_tmp), "%.1f%%", p);

				a = gui_tmp;
			}
			else a = "Connected";

			break;

		case GTA_DL_ERROR:
			a = (gchar *) ((d->remove_msg)? d->remove_msg : "Unknown Error");
			break;

		case GTA_DL_TIMEOUT_WAIT:
			g_snprintf(gui_tmp, sizeof(gui_tmp), "Timeout -- Waiting to retry (%lds)",
				d->timeout_delay - (time((time_t *) NULL) - d->last_update) );
			a = gui_tmp;
			break;
		default:
			g_snprintf(gui_tmp, sizeof(gui_tmp), "UNKNOWN STATUS %u", d->status);
			a = gui_tmp;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_update = time((time_t *) NULL);

	if (d->status != GTA_DL_QUEUED)
	{
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads), (gpointer) d);
		gtk_clist_set_text(GTK_CLIST(clist_downloads), row, 2, a);
	}
}

/* vi: set ts=3: */

