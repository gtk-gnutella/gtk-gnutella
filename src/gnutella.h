
#ifndef __gnutella_h__
#define __gnutella_h__

/* Main includes ---------------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gtk/gtk.h>

#include "../config.h"

/* Macros ----------------------------------------------------------------------------------------- */

#define READ_GUINT16_LE(a,v) { memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); }

#define WRITE_GUINT16_LE(v,a) { guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); }

#define READ_GUINT32_LE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); }
#define READ_GUINT32_BE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_BE(v); }

#define WRITE_GUINT32_LE(v,a) { guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); }
#define WRITE_GUINT32_BE(v,a) { guint32 _v = GUINT32_TO_BE(v); memcpy(a, &_v, 4); }

/* Constants -------------------------------------------------------------------------------------- */

#define GTA_VERSION 0
#define GTA_SUBVERSION 14
#define GTA_REVISION "pre-alpha"
#define GTA_RELEASE "13.09.2001"
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#define GTA_MSG_INIT					0x00
#define GTA_MSG_INIT_RESPONSE		0x01
#define GTA_MSG_PUSH_REQUEST		0x40
#define GTA_MSG_SEARCH				0x80
#define GTA_MSG_SEARCH_RESULTS	0x81

#define GTA_CONNECTION_INCOMING	1
#define GTA_CONNECTION_OUTGOING	2
#define GTA_CONNECTION_LISTENING	3
#define GTA_CONNECTION_PROXY_OUTGOING  4

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
#define GTA_DL_TIMEOUT_WAIT 11		/* Waiting to try connecting again */

#define GTA_UL_CONNECTED	1			/* Someone has connected to us  */
#define GTA_UL_CONNECTING	2			/* We are connecting to someone to upload */
#define GTA_UL_PUSH_RECIEVED	3			/* We got a push request */
#define GTA_UL_COMPLETE		4			/* The file has been sent completely */
#define GTA_UL_SENDING          5                       /* We are sending data for */

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

struct gnutella_search_results_out
{
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];

  /* Last 16 bytes = client_id */
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

	guint16 local_port;			/* Port on our side */

	time_t last_update;			/* Timestamp of last activity on socket */

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
	gchar error_str[256];			/* To sprintf() error strings with vars */
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
	guint16 n_dups;				/* Number of dup messages received (bad) */
	guint16 n_hard_ttl;			/* Number of hard_ttl exceeded (bad) */

	guint32 allocated;			/* Size of allocated buffer data, 0 for none */
	gboolean have_header;	/* TRUE if we have got a full message header */

	time_t last_update;		/* Timestamp of last update of the node in the GUI */

	const gchar *remove_msg;/* Reason of removing */

	guint32 ip;					/* ip of the node */
	guint16 port;				/* port of the node */

	gint gdk_tag;				/* gdk tag for write status */
	gchar *sendq;				/* Output buffer */
	guint32 sq_pos;			/* write position in the sendq */
	GSList *end_of_packets;     /* list of ends of packets, so that sent may be kept up to date. */
  								/* The data "pointer" is actually a guint32. */
	guint32 end_of_last_packet; /* how many bytes need to be written to reach the end of the last enqueued end of packet */
};

struct gnutella_host
{
	guint32 ip;
	guint16 port;
	// guint32 files_count;		/* UNUSED --RAM */
	// guint32 kbytes_count;	/* UNUSED --RAM */
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
	gchar error_str[256];	/* Used to sprintf() error strings with vars */
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
	guint32 retries;
	guint32 timeout_delay;
	guint  restart_timer_id;

	const gchar *remove_msg;

	guint32 ip;
	guint16 port;

	gboolean visible;			/* The download is visible in the GUI */

	gboolean push;				/* Always use the push method for this download */

	gboolean ok;				/* We have got 200 OK */
};

struct upload
{
  guint32 status;

  struct gnutella_socket *socket;
  
  gint file_desc;

  gchar *buffer;
  gint bpos;
  gint bsize;
  gint buf_size;

  guint index;
  gchar *name;
  guint32 file_size;

  time_t start_date;
  time_t last_update;
  
  gint skip;
  gint pos;
  gboolean push;

};

/* XXX could be clever and share the file_directory's ... */
struct shared_file {
  gchar *file_name;
  gchar *file_name_lowercase;
  gchar *file_directory; /* The full path of the directory the file's in */
  gchar *file_directory_path; /* lowercase of the path from the share_dir entry to the file */
  guint32 file_index;                /* the files index withing out local DB */
  guint32 file_size;               /* File size in Bytes */
  gint file_name_len;
};

/* Structure for search results */
struct search
{
	GtkWidget *clist;						/* GtkCList for this search */
	GtkWidget *scrolled_window;		/* GtkScrolledWindow containing the GtkCList */
	GtkWidget *list_item;				/* The GtkListItem in the combo for this search */
	gchar 	*query;						/* The search query */
	guint16	speed;						/* Minimum speed for the results of this query */
	time_t	time;							/* Time when this search was started */
	GSList  *muids;						/* Message UID's of this search */
	GSList	*r_sets;						/* The results sets of this search */
	guint32	items;						/* Total number of items for this search */

	gint sort_col;							/* Column to sort */
	gint sort_order;						/* Ascending or descending */
	gboolean sort;							/* Do sorting or not */

	gpointer filter_page;				/* Page of filters in the filters notebook */

	time_t last_update_time;             /* the last time the notebook tab was updated. */
	guint32 last_update_items;           /* Number of items included in last update */
	gint tab_updating;                   /* token identifying timeout function to be canceled. */
	guint32 unseen_items;                /* How many items haven't been seen yet. */

	gboolean passive;                    /* Is this a passive search?  Maybe this would be better done with a magic muid. */
	GHashTable *dups; /* keep a record of dups. */
	GHashTable *sent_nodes; /* keep a record of nodes we've sent this search w/ this muid to. */

	GHook  *new_node_hook;
	guint   reissue_timeout_id;
	guint reissue_timeout;		/* timeout per search, 0 = search stopped */
	/* XXX Other fields for the filtering will be added here */
};

/* Variables -------------------------------------------------------------------------------------- */

guchar guid[16];				/* ID of our client for this session */


/* config.c */

extern gboolean force_local_ip;
extern gboolean monitor_enabled;
extern gboolean clear_uploads;
extern gboolean clear_downloads;

extern guint8  my_ttl;
extern guint8  max_ttl;
extern guint8  hard_ttl_limit;
extern guint16 listen_port;
extern guint32 minimum_speed;
extern guint32 up_connections;
extern guint32 max_connections;
extern guint32 max_downloads;
extern guint32 max_host_downloads;
extern guint32 max_uploads;
extern guint32 connection_speed;
extern gint32 search_max_items;
extern guint32 forced_local_ip;
extern guint32 download_connecting_timeout;
extern guint32 download_push_sent_timeout;
extern guint32 download_connected_timeout;
extern guint32 download_retry_timeout_min;
extern guint32 download_retry_timeout_max;
extern guint32 download_max_retries;
extern guint32 node_connected_timeout;
extern guint32 node_connecting_timeout;
extern guint32 node_sendqueue_size;
extern guint32 search_queries_forward_size;
extern guint32 search_queries_kick_size;
extern guint32 search_answers_forward_size;
extern guint32 search_answers_kick_size;
extern guint32 other_messages_kick_size;
extern time_t tab_update_time;

extern guint32 nodes_col_widths[];
extern guint32 dl_active_col_widths[];
extern guint32 dl_queued_col_widths[];
extern guint32 uploads_col_widths[];
extern guint32 search_results_col_widths[];
extern guint32 hops_random_factor;

extern gint dbg;
extern gint stop_host_get;
extern gint enable_err_log;
extern gint search_strict_and;
extern gint search_pick_all;
extern gint max_uploads_ip;

extern gchar *save_file_path;
extern gchar *move_file_path;
extern gchar *scan_extensions;
extern gchar *shared_dirs_paths;
extern gchar *completed_file_path;
extern gchar *global_spam_filter_file;
extern gchar *global_IP_filter_file;


extern gboolean jump_to_downloads;

extern gboolean proxy_connections;
extern gint socks_protocol;
extern gchar *proxy_ip;
extern gint proxy_port;

extern gchar *socksv5_user;
extern gchar *socksv5_pass;


/* sockets.c */

extern guint32 local_ip;

/* nodes.c */

extern const gchar *gnutella_hello;

extern GSList *sl_nodes;
extern guint32 nodes_in_list;
extern guint32 global_messages, global_searches, routing_errors, dropped_messages;

extern GHookList node_added_hook_list;
extern struct gnutella_node *node_added;

/* hosts.c */

extern GSList *sl_catched_hosts;
extern struct ping_req *pr_ref;
extern gint hosts_idle_func;

/* search.c */

extern GtkWidget *dialog_filters;
extern gboolean search_results_show_tabs;
extern guint32 search_passive;
extern guint32 search_reissue_timeout;

/* downloads.c */

extern GSList *sl_downloads;
extern guint32 count_downloads;
extern gboolean send_pushes;

/* share.c */

extern guint32 files_scanned, bytes_scanned, kbytes_scanned;
extern guint32 monitor_max_items, monitor_items;
extern GSList *extensions, *shared_dirs, *shared_files;

/* uploads.c */

extern GSList *uploads;
extern gint running_uploads;
extern guint32 count_uploads;

/* callbacks.c */

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
gboolean is_private_ip(guint32 ip);
gchar *node_ip(struct gnutella_node *);
void message_dump(struct gnutella_node *);
gboolean is_directory(gchar *);
void debug_show_hex(gchar *, gchar *, gint);
gchar *short_size(guint32);

/* config.c */

void config_init(void);
void config_save();
void config_close(void);

/* gui.c */

void gui_set_status(gchar *);
void gui_update_minimum_speed(guint32);
void gui_update_up_connections(void);
void gui_update_max_connections(void);
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
void gui_update_max_host_downloads(void);
void gui_update_max_uploads(void);
void gui_update_files_scanned(void);
void gui_update_connection_speed(void);
void gui_update_search_max_items(void);
void gui_update_search_reissue_timeout();
void gui_update_scan_extensions(void);
void gui_update_shared_dirs(void);
void gui_update_download_clear(void);
void gui_update_download_abort_resume(void);
void gui_update_upload(struct upload *);
void gui_update_upload_kill(void);
void gui_update_socks_host();
void gui_update_socks_port();
void gui_update_socks_user();
void gui_update_socks_pass();
void gui_close(void);

/* sockets.c */

void socket_destroy(struct gnutella_socket *);
void socket_free(struct gnutella_socket *);
struct gnutella_socket *socket_connect(guint32, guint16, gint);
struct gnutella_socket *socket_listen(guint32, guint16, gint);
int connect_socksv5(struct gnutella_socket*);
int proxy_connect (int, const struct sockaddr *, socklen_t);
int recv_socks(struct gnutella_socket*);
int send_socks(struct gnutella_socket*);
void socket_monitor_incoming(void);
void socket_shutdown(void);

/* nodes.c */

void network_init(void);
gboolean on_the_net(void);
gint32 connected_nodes(void);
struct gnutella_node *node_add(struct gnutella_socket *, guint32, guint16);
void node_real_remove(struct gnutella_node *);
void node_remove(struct gnutella_node *, const gchar *reason, ...);
void node_init_outgoing(struct gnutella_node *);
void node_read_connecting(gpointer, gint, GdkInputCondition);
void node_read(gpointer, gint, GdkInputCondition);
void node_write(gpointer, gint, GdkInputCondition);
gboolean node_enqueue(struct gnutella_node *, gchar *, guint32);
void node_enqueue_end_of_packet(struct gnutella_node *);
void node_close(void);

/* hosts.c */

void host_init(void);
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
void host_close(void);

/* routing.c */

void routing_init(void);
void routing_close(void);
void generate_new_muid(guchar *muid);
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
void download_stop(struct download *, guint32, const gchar *, ...);
void download_free(struct download *);
void download_read(gpointer, gint, GdkInputCondition);
void download_push(struct download *);
void download_fallback_to_push(struct download *, gboolean);
void download_pickup_queued(void);
void downloads_clear_stopped(gboolean, gboolean);
void download_abort(struct download *);
void download_resume(struct download *);
void download_start(struct download *, gboolean);
void download_kill(struct download *);
void download_queue_back(struct download *);
gboolean download_send_request(struct download *);
void download_retry(struct download *);
void download_close(void);

/* uploads.c */

void upload_remove(struct upload *, gchar *);
void handle_push_request(struct gnutella_node *);
struct upload* upload_add(struct gnutella_socket *s);
void upload_write(gpointer up, gint, GdkInputCondition);
void upload_close(void);


/* share.c */

void share_init(void);
void share_scan(void);
void share_close(void);
void search_request(struct gnutella_node *n);
void parse_extensions(gchar *);
gint file_exists(gint, gchar *);
gchar *get_file_path(gint);
void shared_dirs_parse(gchar *);
void shared_dir_add(gchar *);
gint get_file_size(gint);

/* search.c */

void search_init(void);
struct search *new_search(guint16, gchar *);
struct search *_new_search(guint16, gchar *, guint flags);
void search_stop(struct search *sch);
void search_resume(struct search *sch);
void search_results(struct gnutella_node *n);
void search_download_files(void);
void search_close_current(void);
gint search_results_compare_size(GtkCList *, gconstpointer, gconstpointer);
gint search_results_compare_speed(GtkCList *, gconstpointer, gconstpointer);
gint search_results_compare_ip(GtkCList *, gconstpointer, gconstpointer);
void search_clear_clicked(void);
void search_update_reissue_timeout(guint32);
void search_shutdown(void);

#endif	/* __gnutella_h__ */

/* vi: set ts=3: */
