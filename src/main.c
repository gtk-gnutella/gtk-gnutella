
#include "gnutella.h"

#include <signal.h>

#include "interface.h"
#include "support.h"

#include "search.h"
#include "filter.h"

#define NODE_ERRMSG_TIMEOUT		5	/* Time to leave erorr messages displayed */
#define DL_UPDATE_DELAY			10	/* Don't update downloads too often */
#define SLOW_UPDATE_PERIOD		20	/* Updating period for `main_slow_update' */

/* */

GtkWidget *main_window;

struct gnutella_socket *s_listen = NULL;
static guint main_slow_update = 0;

/* */

void gtk_gnutella_exit(gint n)
{
	if (hosts_idle_func)
		gtk_idle_remove(hosts_idle_func);
	config_save();

	/* Shutdown systems, so we can track memory leaks */
	if (s_listen)
		socket_destroy(s_listen);
	socket_shutdown();
	search_shutdown();
	share_close();
	host_close();
	config_close();
	node_close();
	routing_close();
	download_close();
	upload_close();
	gui_close();

	gtk_exit(n);
}

static void SIG_Handler(int n)
{
	gtk_gnutella_exit(1);
}

static void SIG_Ignore(int n)
{
	return;
}

static void auto_connect(void)
{
	/*
	 * Round-robin selection of a host catcher, and addition to the list of
	 * nodes, if not already connected to it.
	 */

	static gchar *host_catcher[] = {
		"router.limewire.com",
		"connect1.gnutellanet.com",
		"connect2.gnutellanet.com",
		"connect3.gnutellanet.com",
	};
	static guint host_idx = 0;
	guint32 ip = 0;
	guint16 port = 6346;
	extern gboolean node_connected(guint32, guint16, gboolean);

	if (host_idx >= (sizeof(host_catcher) / sizeof(host_catcher[0])))
		host_idx = 0;

	ip = host_to_ip(host_catcher[host_idx++]);
	if (ip != 0 && !node_connected(ip, port, FALSE))
		node_add(NULL, ip, port);
}

gboolean main_timer(gpointer p)
{
	GSList *l;
	struct gnutella_node *n;
	struct download *d;
	guint32 t;
	time_t now = time((time_t *) NULL);

	/*
	 * If we are under the number of connections wanted, we add hosts
	 * to the connection list
	 */

	if (nodes_in_list < up_connections && !stop_host_get) {
		if (sl_catched_hosts != NULL) {
			struct gnutella_host *host;
			int missing = up_connections - nodes_in_list;

			while (missing-- > 0 && sl_catched_hosts) {
				host = (struct gnutella_host *) sl_catched_hosts->data;
				node_add(NULL, host->ip, host->port);
				host_remove(host, TRUE);
			}
		} else
			auto_connect();
	}

	/* The nodes */

	l = sl_nodes;

	while (l && !stop_host_get) {		/* No timeout if stop_host_get is set */
		n = (struct gnutella_node *) l->data;
		l = l->next;

		if (n->status == GTA_NODE_REMOVING &&
			now - n->last_update > NODE_ERRMSG_TIMEOUT)
			node_real_remove(n);
		else if (n->status == GTA_NODE_CONNECTING &&
				 now - n->last_update > node_connecting_timeout)
			node_remove(n, "Timeout");
		else if (now - n->last_update > node_connected_timeout)
			node_remove(n, "Activity Timeout");
	}

	/* The downloads */

	l = sl_downloads;
	while (l) {
		d = (struct download *) l->data;
		l = l->next;

		switch (d->status) {
		case GTA_DL_RECEIVING:
		case GTA_DL_HEADERS:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_CONNECTING:
		case GTA_DL_REQ_SENT:
		case GTA_DL_FALLBACK:
			{
				if (now - d->last_update < DL_UPDATE_DELAY)
					break;

				switch (d->status) {
				case GTA_DL_PUSH_SENT:
				case GTA_DL_FALLBACK:
					t = download_push_sent_timeout;
					break;

				case GTA_DL_CONNECTING:
					t = download_connecting_timeout;
					break;

				default:
					t = download_connected_timeout;
				}

				if (now - d->last_update > t) {
					if (d->status == GTA_DL_CONNECTING)
						download_fallback_to_push(d, FALSE);
					else {
						if (++d->retries <= download_max_retries)
							download_retry(d);
						else
							download_stop(d, GTA_DL_ERROR, "Timeout");
					}
				}

				break;
			}
		case GTA_DL_TIMEOUT_WAIT:
			{
				if (now - d->last_update > d->timeout_delay)
					download_start(d, TRUE);
				else
					gui_update_download(d, FALSE);
				break;
			}
		}
	}

	if (clear_downloads)
		downloads_clear_stopped(FALSE, FALSE);

	/* Dequeuing */
	download_pickup_queued();

	/* Uploads */

	for (l = uploads; l; l = l->next)
		gui_update_upload((struct upload *) l->data);

	/* Expire connecting sockets */
	socket_monitor_incoming();

	/* GUI update */

	gui_update_global();
	gui_update_stats();

	/* Update for things that change slowly */
	if (main_slow_update++ > SLOW_UPDATE_PERIOD) {
		main_slow_update = 0;
		gui_update_config_port();		/* Show current IP:port if dynamic IP */
	}

	return TRUE;
}

gint main(gint argc, gchar ** argv)
{
	gint i;
	const gchar *menus[] = {
		"gnutellaNet",
		"Uploads",
		"Downloads",
		"Search",
		"  Monitor",
		"Config",
		NULL
	};
	gchar *titles[5];
	gchar mtmp[1024];
	gint optimal_width;

	for (i = 3; i < 256; i++)
		close(i);				/* Just in case */

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
	host_init();
	network_init();
	routing_init();
	search_init();
	share_init();
	filters_init();

	/* Some signal handlers */

	signal(SIGTERM, SIG_Handler);
	signal(SIGINT, SIG_Handler);
	signal(SIGPIPE, SIG_Ignore);		/* SIG_IGN -- running under debugger */

	/* Create the main listening socket */

	if (listen_port)
		s_listen = socket_listen(0, listen_port, GTA_TYPE_CONTROL);

	/* Final interface setup */

	optimal_width =
		gtk_clist_optimal_column_width(GTK_CLIST(clist_stats), 0);

	for (i = 0; i < 6; i++)
		gtk_clist_insert(GTK_CLIST(clist_menu), i, (gchar **) & menus[i]);
	gtk_clist_select_row(GTK_CLIST(clist_menu), 0, 0);

	gtk_widget_set_usize(sw_menu, optimal_width,
						 (clist_menu->style->font->ascent +
						  clist_menu->style->font->descent + 4) * 6);

	gtk_clist_column_titles_passive(GTK_CLIST(clist_nodes));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_uploads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_downloads));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_download_queue));
	gtk_clist_column_titles_passive(GTK_CLIST(clist_monitor));

	gtk_clist_set_reorderable(GTK_CLIST(clist_download_queue), TRUE);

	titles[0] = NULL;

	for (i = 0; i < 3; i++)
		gtk_clist_append(GTK_CLIST(clist_connections), titles);
	for (i = 0; i < 4; i++)
		gtk_clist_append(GTK_CLIST(clist_stats), titles);

	gtk_widget_set_usize(sw_connections, optimal_width,
						 (clist_connections->style->font->ascent +
						  clist_connections->style->font->descent +
						  4) * 3);
	gtk_widget_set_usize(sw_stats, optimal_width,
						 (clist_stats->style->font->ascent +
						  clist_stats->style->font->descent + 4) * 4);

	gui_update_stats();

	gui_update_c_gnutellanet();
	gui_update_c_uploads();
	gui_update_c_downloads(0);

	gui_update_global();

#ifdef GTA_REVISION
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u %s", GTA_VERSION,
			   GTA_SUBVERSION, GTA_REVISION);
#else
	g_snprintf(mtmp, sizeof(mtmp), "gtk-gnutella %u.%u", GTA_VERSION,
			   GTA_SUBVERSION);
#endif

	gtk_window_set_title(GTK_WINDOW(main_window), mtmp);

	gtk_widget_set_sensitive(popup_hosts_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_active_title, FALSE);
	gtk_widget_set_sensitive(popup_dl_queued_title, FALSE);
	gtk_widget_set_sensitive(popup_monitor_title, FALSE);
	gtk_widget_set_sensitive(popup_nodes_title, FALSE);
	gtk_widget_set_sensitive(popup_uploads_title, FALSE);
	gtk_widget_set_sensitive(popup_search_title, FALSE);

	gtk_widget_show(main_window);		/* Display the main window */

	/* Setup the main timer */

	gtk_timeout_add(1000, (GtkFunction) main_timer, NULL);

	/* Okay, here we go */

	gtk_main();

	return 0;
}

/* vi: set ts=4: */
