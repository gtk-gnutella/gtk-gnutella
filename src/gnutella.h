
#ifndef __gnutella_h__
#define __gnutella_h__

/* Main includes ---------------------------------------------------------------------------------- */

#include <gtk/gtk.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>

/* Macros ----------------------------------------------------------------------------------------- */

#define READ_GUINT16_LE(a,v) { memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); }

#define WRITE_GUINT16_LE(v,a) { guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); }

#define READ_GUINT32_LE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); }
#define READ_GUINT32_BE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_BE(v); }

#define WRITE_GUINT32_LE(v,a) { guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); }
#define WRITE_GUINT32_BE(v,a) { guint32 _v = GUINT32_TO_BE(v); memcpy(a, &_v, 4); }

/* Constants -------------------------------------------------------------------------------------- */

#define GTA_VERSION 0
#define GTA_SUBVERSION 13
#define GTA_REVISION "pre-alpha"
#define GTA_RELEASE "07.05.2000"
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#define GTA_MSG_INIT					0x00
#define GTA_MSG_INIT_RESPONSE		0x01
#define GTA_MSG_PUSH_REQUEST		0x40
#define GTA_MSG_SEARCH				0x80
#define GTA_MSG_SEARCH_RESULTS	0x81

#define GTA_CONNECTION_INCOMING	1
#define GTA_CONNECTION_OUTGOING	2
#define GTA_CONNECTION_LISTENING	3

#define GTA_TYPE_UNKNOWN			0
#define GTA_TYPE_CONTROL			1
#define GTA_TYPE_DOWNLOAD			2
#define GTA_TYPE_UPLOAD				3

#define GTA_NODE_CONNECTING	1
#define GTA_NODE_HELLO_SENT	2
#define GTA_NODE_WELCOME_SENT	3
#define GTA_NODE_CONNECTED		4
#define GTA_NODE_REMOVING		5

#define GTA_DL_QUEUED		1			/* Download queued, will be started later */
#define GTA_DL_CONNECTING	2			/* We are connecting to the server */
#define GTA_DL_PUSH_SENT	3			/* We sent a push request and are waiting for connection */
#define GTA_DL_FALLBACK		4			/* Direct request failed, we are falling back to a push request */
#define GTA_DL_REQ_SENT		5			/* Request sent, we are waiting for the HTTP headers */
#define GTA_DL_HEADERS		6			/* We are receiving the HTTP headers */
#define GTA_DL_RECEIVING	7			/* We are receiving the data of the file */
#define GTA_DL_COMPLETED	8			/* Download is completed */
#define GTA_DL_ERROR			9			/* Download is stopped due to error */
#define GTA_DL_ABORTED		10			/* User clicked the 'Abort Download' button */

/* Structures ------------------------------------------------------------------------------------- */

/* Messages structures */

struct gnutella_header
{
	guchar muid[16];
	guchar function;
	guchar ttl;
	guchar hops;
	guchar size[4];
};

struct gnutella_msg_init
{
	struct gnutella_header header;
};

struct gnutella_init_response
{
	guchar host_port[2];
	guchar host_ip[4];
	guchar files_count[4];
	guchar kbytes_count[4];
};

struct gnutella_msg_init_response
{
	struct gnutella_header header;
	struct gnutella_init_response response;
};

struct gnutella_search
{
	guchar speed[2];
	guchar query[0];
};

struct gnutella_msg_search
{
	struct gnutella_header header;
	struct gnutella_search search;
};

struct gnutella_search_results
{
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];
	guchar records[0];

	/* Last 16 bytes = client_id */
};

struct gnutella_search_record
{
	guchar file_index[4];
	guchar file_size[4];
	guchar file_name;
};

struct gnutella_push_request
{
	guchar guid[16];
	guchar file_id[4];
	guchar host_ip[4];
	guchar host_port[2];
};

struct gnutella_msg_push_request
{
	struct gnutella_header header;
	struct gnutella_push_request request;
};

/* */

struct gnutella_socket
{
	gint file_desc;			/* file descriptor */

	gint gdk_tag;				/* gdk tag */

	guchar direction;			/* GNUTELLA_INCOMING | GNUTELLA_OUTGOING */
	guchar type;				/* GNUTELLA_CONTROL | GNUTELLA_DOWNLOAD | GNUTELLA_UPLOAD */

	guint32 ip;					/* IP	of our partner */
	guint16 port;				/* Port of our partner */

	guint16 local_port;		/* Port on our side */

	union
	{
		struct gnutella_node	*node;
		struct download      *download;
		struct upload        *upload;
	} resource;

	gchar buffer[4096];		/*	buffer to put in the data read */
	guint32 pos;				/* write position in the buffer */
};

struct gnutella_node
{
	struct gnutella_socket *socket;	/* Socket of the node */

	struct gnutella_header header;	/* Header of the current message */

	guint32 size;				/* How many bytes we need to read for the current message */

	gchar *data;				/* data of the current message */

	guint32 pos;				/* write position in data */

	guchar status;				/* GNUTELLA_HELLO_SENT | GNUTELLA_HELLO_RECEIVED | GNUTELLA_CONNECTED | GNUTELLA_ */

	guint32 sent;				/* Number of sent packets */
	guint32 received;			/* Number of received packets */
	guint32 dropped;			/* Number of packets dropped */
	guint32 n_bad;				/* Number of bad packets received */

	gboolean allocated;		/* TRUE if we have allocated extra memory for message data */
	gboolean have_header;	/* TRUE if we have got a full message header */

	time_t last_update;		/* Timestamp of last update of the node in the GUI */

	const gchar *remove_msg;/* Reason of removing */

	guint32 ip;					/* ip of the node */
	guint16 port;				/* port of the node */

	gint gdk_tag;				/* gdk tag for write status */
	gchar *sendq;				/* Output buffer */
	guint32 sq_pos;			/* write position in the sendq */
};

struct gnutella_host
{
	guint32 ip;
	guint16 port;
	guint32 files_count;
	guint32 kbytes_count;
};

struct ping_req
{
	struct timeval tv;		/* Date of the ping */
	guchar muid[16];			/* muid of the ping */
	guint32 hosts;				/* Number of hosts that replied */
	guint32 files;				/* Number of shared files of all the hosts */
	guint64 kbytes;			/* Number of K-bytes of all the files */

	guint64 delay;				/* Total of reply delay for this request */
};

struct download
{
	guint32 status;			/* Current status of the download */

	gchar *path;				/* Path of the created output file */
	gchar *file_name;			/*	Name of the created output file */

	gchar guid[16];			/* GUID of the Gnutella server from which we download the file */
	guint32 record_index;	/* Index of the file on the Gnutella server */

	guint32 size;				/* Total size of the file, in bytes */

	guint32 skip;				/* Number of bytes of the file we already had before starting */
	guint32 pos;				/* Number of bytes of the file we currently have */

	struct gnutella_socket *socket;
	gint file_desc;

	time_t start_date;
	time_t last_update;

	const gchar *remove_msg;

	guint32 ip;
	guint16 port;

	gboolean visible;			/* The download is visible in the GUI */

	gboolean push;				/* Always use the push method for this download */

	gboolean ok;				/* We have got 200 OK */
};

struct gnutella_upload
{
	struct gnutella_socket *socket;
};

/* Variables -------------------------------------------------------------------------------------- */

/* config.c */

extern guint8  my_ttl;
extern guint8  max_ttl;
extern guint16 listen_port;
extern guint32 minimum_speed;
extern guint32 up_connections;
extern guint32 max_downloads;
extern guint32 connection_speed;
extern guint32 search_max_items;
extern guint32 listen_ip;
extern guint32 download_connecting_timeout;
extern guint32 download_push_sent_timeout;
extern guint32 download_connected_timeout;
extern guint32 node_connected_timeout;
extern guint32 node_connecting_timeout;
extern guint32 node_sendqueue_size;
extern guint32 search_queries_forward_size;
extern guint32 search_queries_kick_size;
extern guint32 search_answers_forward_size;
extern guint32 search_answers_kick_size;
extern guint32 other_messages_kick_size;
extern gchar *save_file_path;
extern gchar *move_file_path;
extern gchar *scan_extensions;
extern gchar *shared_dirs_paths;
extern gchar *completed_file_path;

/* sockets.c */

extern guint32 local_ip;

/* nodes.c */

extern const gchar *gnutella_hello;

extern GSList *sl_nodes;
extern guint32 nodes_in_list;
extern guint32 global_messages, global_searches, routing_errors, dropped_messages;

/* hosts.c */

extern GSList *sl_catched_hosts;
extern struct ping_req *pr_ref;
extern gint hosts_idle_func;

/* search.c */

extern gboolean  clear_uploads, clear_downloads;
extern GtkWidget *dialog_filters;

/* downloads.c */

extern GSList *sl_downloads;
extern guint32 count_downloads;

/* share.c */

extern guint32 files_scanned, bytes_scanned;
extern gboolean monitor_enabled;
extern guint32 monitor_max_items, monitor_items;
extern GSList *extensions, *shared_dirs;

/* uploads.c */

extern GSList *uploads;
extern guint32 count_uploads;

/* callbacks.c */

extern gint search_results_sort_col;
extern gint search_results_sort_order;
extern gboolean search_results_sort;
extern struct download *selected_queued_download;
extern struct download *selected_active_download;

/* main.c */

extern struct gnutella_socket *s_listen;
extern GtkWidget *main_window;

/* Functions -------------------------------------------------------------------------------------- */

/* main.c */

void gtk_gnutella_exit(gint);

/* md5.c */

gchar *md5dump(guchar *);

/* misc.c */

gchar *ip_to_gchar(guint32);
gchar *ip_port_to_gchar(guint32, guint16);
guint32 gchar_to_ip(gchar *);
guint32 host_to_ip(gchar *);
gchar *node_ip(struct gnutella_node *);
void message_dump(struct gnutella_node *);
gboolean is_directory(gchar *);
gchar *short_size(guint32);

/* config.c */

void config_init(void);
void config_save();

/* gui.c */

void gui_set_status(gchar *);
void gui_update_minimum_speed(guint32);
void gui_update_up_connections(void);
void gui_update_config_port(void);
void gui_update_config_force_ip(void);
void gui_update_global(void);
void gui_update_count_downloads(void);
void gui_update_count_uploads(void);
void gui_update_save_file_path(void);
void gui_update_move_file_path(void);
void gui_update_node(struct gnutella_node *, gboolean);
void gui_update_download(struct download *, gboolean);
void gui_update_c_gnutellanet(void);
void gui_update_c_uploads(void);
void gui_update_c_downloads(gint);
void gui_update_stats(void);
void gui_update_monitor_max_items(void);
void gui_update_max_ttl(void);
void gui_update_my_ttl(void);
void gui_update_max_downloads(void);
void gui_update_files_scanned(void);
void gui_update_connection_speed(void);
void gui_update_search_max_items(void);
void gui_update_scan_extensions(void);
void gui_update_shared_dirs(void);
void gui_update_download_clear(void);
void gui_update_download_abort_resume(void);

/* sockets.c */

void socket_destroy(struct gnutella_socket *);
struct gnutella_socket *socket_connect(guint32, guint16, gint);
struct gnutella_socket *socket_listen(guint32, guint16, gint);

/* nodes.c */

void network_init(void);
gboolean on_the_net(void);
struct gnutella_node *node_add(struct gnutella_socket *, guint32, guint16);
void node_real_remove(struct gnutella_node *);
void node_remove(struct gnutella_node *, const gchar *reason);
void node_init_outgoing(struct gnutella_node *);
void node_read_connecting(gpointer, gint, GdkInputCondition);
void node_read(gpointer, gint, GdkInputCondition);
void node_write(gpointer, gint, GdkInputCondition);
gboolean node_enqueue(struct gnutella_node *, gchar *, guint32);

/* hosts.c */

gboolean find_host(guint32, guint16);
void host_remove(struct gnutella_host *, gboolean);
void host_add(struct gnutella_node *, guint32, guint16, gboolean);
void send_init(struct gnutella_node *);
void reply_init(struct gnutella_node *);
void ping_stats_add(struct gnutella_node *);
void ping_stats_update(void);
gboolean check_valid_host(guint32, guint16);
void hosts_read_from_file(gchar *, gboolean);
void hosts_write_to_file(gchar *);

/* routing.c */

void routing_init(void);
void message_set_muid(struct gnutella_header *);
gboolean route_message(struct gnutella_node **);
void routing_node_remove(struct gnutella_node *);
void sendto_one(struct gnutella_node *, guchar *, guchar *, guint32);
void sendto_all_but_one(struct gnutella_node *, guchar *, guchar *, guint32);
void sendto_all(guchar *, guchar *, guint32);
void message_add(guchar *, guint8, struct gnutella_node *);

/* downloads.c */

void download_new(gchar *, guint32, guint32, guint32, guint16, gchar *);
void download_queue(struct download *);
void download_stop(struct download *, guint32, const gchar *);
void download_free(struct download *);
void download_read(gpointer, gint, GdkInputCondition);
void download_push(struct download *);
void download_fallback_to_push(struct download *, gboolean);
void download_pickup_queued(void);
void downloads_clear_stopped(gboolean, gboolean);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *);
void download_kill(struct download *);
void download_queue_back(struct download *);
gboolean download_send_request(struct download *);

/* uploads.c */

void upload_remove(struct upload *, gchar *);
void handle_push_request(struct gnutella_node *);

/* share.c */

void share_init(void);
void share_scan(void);
void search_request(struct gnutella_node *n);
void parse_extensions(gchar *);
void shared_dirs_parse(gchar *);
void shared_dir_add(gchar *);

/* search.c */

void search_init(void);
void new_search(guint16, gchar *);
void search_results(struct gnutella_node *n);
void search_download_files(void);
void search_close_current(void);
gint search_results_compare_size(GtkCList *, gconstpointer, gconstpointer);
gint search_results_compare_speed(GtkCList *, gconstpointer, gconstpointer);
gint search_results_compare_ip(GtkCList *, gconstpointer, gconstpointer);

#endif	/* __gnutella_h__ */

/* vi: set ts=3: */

