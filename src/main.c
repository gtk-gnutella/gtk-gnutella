
#include "gnutella.h"

#include <signal.h>

#include "interface.h"
#include "support.h"

#include "search.h"
#include "filter.h"

/* */

GtkWidget *main_window;

struct gnutella_socket *s_listen = NULL;

/* */

void gtk_gnutella_exit(gint n)
{
	if (hosts_idle_func) gtk_idle_remove(hosts_idle_func);
	config_save();
	gtk_exit(n);
}

void SIG_Handler(int n)
{
	gtk_gnutella_exit(1);
}

gboolean main_timer(gpointer p)
{
	GSList *l;
	struct gnutella_node *n;
	struct download *d;
	guint32 t;

	/* The nodes */

	l = sl_nodes;

	while (l)
	{
		n = (struct gnutella_node *) l->data;
		l = l->next;

		if (n->status == GTA_NODE_REMOVING && time((time_t *) NULL) - n->last_update > 3) node_real_remove(n);
		else if (n->status == GTA_NODE_CONNECTING && time((time_t *) NULL) - n->last_update > node_connecting_timeout) node_remove(n, "Timeout");
		else if (time((time_t *) NULL) - n->last_update > node_connected_timeout) node_remove(n, "Timeout");
	}

	/* The downloads */

	l = sl_downloads;

	while (l)
	{
		d = (struct download *) l->data;
		l = l->next;

		switch (d->status)
		{
			case GTA_DL_RECEIVING:
			case GTA_DL_HEADERS:
			case GTA_DL_PUSH_SENT:
			case GTA_DL_CONNECTING:
			case GTA_DL_REQ_SENT:
			case GTA_DL_FALLBACK:
			{
				if (time((time_t *) NULL) - d->last_update < 10) break;
				
				switch (d->status)
				{
					case GTA_DL_PUSH_SENT:
					case GTA_DL_FALLBACK:
						t = download_push_sent_timeout; break;

					case GTA_DL_CONNECTING:
						t = download_connecting_timeout; break;

					default:
						t = download_connected_timeout;
				}

				if (time((time_t *) NULL) - d->last_update > t)
				{
					if (d->status == GTA_DL_CONNECTING)
						download_fallback_to_push(d, FALSE);
					else {
						if (++d->retries <= download_max_retries) download_retry(d);
						else download_stop(d, GTA_DL_ERROR, "Timeout");
					}
				}

				break;
		  }
		  case GTA_DL_TIMEOUT_WAIT:
		  {
				if (time((time_t *) NULL) - d->last_update > d->timeout_delay)
					 download_start(d);
				else gui_update_download(d,FALSE);
				break;
		  }
		}
	}

	if (clear_downloads) downloads_clear_stopped(FALSE, FALSE);

	/* GUI update */

	gui_update_global();
	gui_update_stats();

	return TRUE;
}

gint main(gint argc, gchar **argv)
{
	gint i;
	const gchar *menus[] = { "gnutellaNet" , "Uploads", "Downloads", "Search", "  Monitor", "Config", NULL };
	gchar *titles[5];
	gchar mtmp[1024];
	gint optimal_width;

	for (i = 3; i < 256; i++) close(i); /* Just in case */

	/* Glade inits */

	gtk_set_locale();

	gtk_init(&argc, &argv);

	add_pixmap_directory(PACKAGE_DATA_DIR "/pixmaps");
	add_pixmap_directory(PACKAGE_SOURCE_DIR "/pixmaps");

	main_window = create_main_window();

	create_popup_nodes();
	create_popup_hosts();
	create_popup_search();
	create_popup_monitor();
	create_popup_uploads();
	create_popup_dl_active();
	create_popup_dl_queued();

	gui_set_status(NULL);

	/* Our inits */

	config_init();
	network_init();
	routing_init();
	search_init();
	share_init();
	filters_init();

	/* Some signal handlers */

	signal(SIGTERM, SIG_Handler);
	signal(SIGINT,  SIG_Handler);
	signal(SIGPIPE, SIG_IGN);

	/* Create the main listening socket */

	if (listen_port) s_listen = socket_listen(0, listen_port, GTA_TYPE_CONTROL);

	/* Final interface setup */

	optimal_width = gtk_clist_optimal_column_width(GTK_CLIST(clist_stats), 0);

	for (i = 0; i < 6; i++) gtk_clist_insert(GTK_CLIST(clist_menu), i, (gchar **) &menus[i]);
	gtk_clist_select_row(GTK_CLIST(clist_menu), 0, 0);

	gtk_widget_set_usize(sw_menu, optimal_width, (clist_menu->style->font->ascent + clist_menu->style->font->descent + 4) * 6);

	gtk_clist_column_titles_passive(GTK_CLIST(clist_nodes));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_uploads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_download_queue));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_monitor));

	gtk_clist_set_reorderable(GTK_CLIST(clist_download_queue), TRUE);

	titles[0] = NULL;

	for (i = 0; i < 3; i++) gtk_clist_append(GTK_CLIST(clist_connections), titles);
	for (i = 0; i < 4; i++) gtk_clist_append(GTK_CLIST(clist_stats), titles);

	gtk_widget_set_usize(sw_connections, optimal_width, (clist_connections->style->font->ascent + clist_connections->style->font->descent + 4) * 3);
	gtk_widget_set_usize(sw_stats, optimal_width, (clist_stats->style->font->ascent + clist_stats->style->font->descent + 4) * 4);

	gui_update_stats();

	gui_update_c_gnutellanet();
	gui_update_c_uploads();
	gui_update_c_downloads(0);

	gui_update_global();

	#ifdef GTA_REVISION
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u %s", GTA_VERSION, GTA_SUBVERSION, GTA_REVISION);
	#else
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u", GTA_VERSION, GTA_SUBVERSION);
	#endif

	gtk_window_set_title(GTK_WINDOW(main_window), mtmp);

	gtk_widget_set_sensitive(popup_hosts_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_active_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_queued_title, FALSE);
	gtk_widget_set_sensitive(popup_monitor_title, FALSE);
	gtk_widget_set_sensitive(popup_nodes_title, FALSE);
	gtk_widget_set_sensitive(popup_uploads_title, FALSE);
	gtk_widget_set_sensitive(popup_search_title, FALSE);

	gtk_widget_show(main_window); /* Display the main window */

	/* Setup the main timer */

	gtk_timeout_add(1000, (GtkFunction) main_timer, NULL);

	/* Okay, here we go */

	gtk_main();

	return 0;
}

/* vi: set ts=3: */

