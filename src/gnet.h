/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#ifndef _gnet_h_
#define _gnet_h_

#include "common.h"
#include "hcache.h"
#include "hosts.h"


/***
 *** Proxy protocols
 ***/
enum {
    PROXY_NONE = 0,
    PROXY_HTTP = 1,
    PROXY_SOCKSV4 = 4,
    PROXY_SOCKSV5 = 5
};

/***
 *** Properties
 ***/
#include "gnet_property.h"

/***
 *** Gnet nodes
 ***/

/*
 * Gnet node specific types
 */
typedef guint32 gnet_node_t;

/*
 * A gnutella host.
 */
typedef struct gnutella_host {
	guint32 ip;
	guint16 port;
} gnet_host_t;

typedef struct gnet_node_status {
	guchar status;			    /* See possible values below */

	/* FIXME: the two below should go to gnet_node_info since they
	 *        only change very seldom
     */
	time_t connect_date;		/* When we got connected (after handshake) */
	time_t up_date;				/* When remote server started (0 if unknown) */

	guint32  sent;				/* Number of sent packets */
	guint32  received;			/* Number of received packets */
	guint32  tx_dropped;		/* Number of packets dropped at TX time */
	guint32  rx_dropped;		/* Number of packets dropped at RX time */
	guint32  n_bad;				/* Number of bad packets received */
	guint16  n_dups;			/* Number of dup messages received (bad) */
	guint16  n_hard_ttl;		/* Number of hard_ttl exceeded (bad) */
	guint32  n_weird;			/* Number of weird messages from that node */

    gint     squeue_sent;
    gint     squeue_count;
    gint     mqueue_count;
    gint     mqueue_percent_used;
    gboolean in_tx_flow_control;

	/*
	 * Traffic statistics -- RAM, 13/05/2002.
	 */
	gint32   tx_given;			/* Bytes fed to the TX stack (from top) */
	gint32   tx_deflated;		/* Bytes deflated by the TX stack */
	gint32   tx_written;		/* Bytes written by the TX stack */
    gboolean tx_compressed;     /* Is TX traffic compressed */
    gfloat   tx_compression_ratio; /* TX compression ratio */
    gfloat   tx_bps;			/* TX traffic rate */
	
	gint32   rx_given;			/* Bytes fed to the RX stack (from bottom) */
	gint32   rx_inflated;		/* Bytes inflated by the RX stack */
	gint32   rx_read;			/* Bytes read from the RX stack */
    gboolean rx_compressed;     /* Is RX traffic compressed */
    gfloat   rx_compression_ratio;/* RX compression ratio */
    gfloat   rx_bps;			/* RX traffic rate */

	guint32  rt_avg;			/* Average ping/pong roundtrip time */
	guint32  rt_last;			/* Last ping/pong roundtrip time */

    gint     shutdown_remain;   /* Number of seconds before shutdown */
    gchar    message[128];       /* Additional information */
} gnet_node_status_t;

typedef struct gnet_node_info {
    gnet_node_t node_handle;    /* Internal node handle */

    gchar *error_str;           /* To sprintf() error strings with vars */
	gint proto_major;			/* Protocol major number */
	gint proto_minor;			/* Protocol minor number */
	gchar *vendor;				/* Vendor information */
	guchar vcode[4];			/* Vendor code (vcode[0] == NUL when unknown) */

	guint32 ip;					/* ip of the node */
	guint16 port;				/* port of the node */
} gnet_node_info_t;

/*
 * Peer modes.
 */

typedef enum {
	NODE_P_LEAF = 0,					/* Leaf node */
	NODE_P_NORMAL,						/* Normal legacy node */
	NODE_P_ULTRA,						/* Ultra node */
	NODE_P_AUTO,						/* Automatic mode */
	NODE_P_CRAWLER,						/* Crawler node */
	NODE_P_UNKNOWN,						/* Unknown mode yet */
} node_peer_t;

/*
 * QRT state.
 */

typedef enum {
	QRT_S_NONE = 0,						/* Nothing */
	QRT_S_SENDING,						/* Sending QRT to ultrapeer */
	QRT_S_SENT,							/* Sent QRT to ultrapeer */
	QRT_S_RECEIVING,					/* Receiving initial QRT from leaf */
	QRT_S_PATCHING,						/* Receiving QRT patch from leaf */
	QRT_S_RECEIVED,						/* Received QRT from leaf */
} qrt_state_t;

typedef struct gnet_node_flags {
	node_peer_t peermode;
	qrt_state_t qrt_state;
	guint8 hops_flow;
	gboolean incoming;
	gboolean writable;
	gboolean readable;
	gboolean tx_compressed;
	gboolean rx_compressed;
	gboolean mqueue_empty;
	gboolean in_tx_flow_control;
	gboolean is_push_proxied;
	gboolean is_proxying;
} gnet_node_flags_t;

/*
 * Node states.
 */
#define GTA_NODE_CONNECTING			1	/* Making outgoing connection */
#define GTA_NODE_HELLO_SENT			2	/* Sent 0.4 hello */
#define GTA_NODE_WELCOME_SENT		3	/* Hello accepted, remote welcomed */
#define GTA_NODE_CONNECTED			4	/* Connected at the Gnet level */
#define GTA_NODE_REMOVING			5	/* Removing node */
#define GTA_NODE_RECEIVING_HELLO	6	/* Receiving 0.6 headers */
#define GTA_NODE_SHUTDOWN			7	/* Connection being shutdown */

#define GTA_NORMAL_TTL				7	/* Regular TTL, for hops-flow */

/*
 * Nodes callback definitions
 */
typedef void (*node_added_listener_t) (gnet_node_t, const gchar *);
typedef void (*node_removed_listener_t) (gnet_node_t);
typedef void (*node_info_changed_listener_t) (gnet_node_t);
typedef void (*node_flags_changed_listener_t) (gnet_node_t);

#define node_add_listener(signal, callback) \
    node_add_##signal##_listener(callback);

#define node_remove_listener(signal, callback) \
    node_remove_##signal##_listener(callback);

void node_add_node_added_listener(node_added_listener_t);
void node_remove_node_added_listener(node_added_listener_t);
void node_add_node_removed_listener(node_removed_listener_t);
void node_remove_node_removed_listener(node_removed_listener_t);
void node_add_node_info_changed_listener(node_info_changed_listener_t);
void node_remove_node_info_changed_listener(node_info_changed_listener_t);
void node_add_node_flags_changed_listener(node_flags_changed_listener_t);
void node_remove_node_flags_changed_listener(node_flags_changed_listener_t);

/*
 * Nodes public interface
 */
void node_add(guint32, guint16);
void node_remove_by_handle(gnet_node_t n);
void node_remove_nodes_by_handle(GSList *node_list);
void node_get_status(const gnet_node_t n, gnet_node_status_t *s);
gnet_node_info_t *node_get_info(const gnet_node_t n);
void node_clear_info(gnet_node_info_t *info);
void node_free_info(gnet_node_info_t *info);
void node_fill_flags(gnet_node_t n, gnet_node_flags_t *flags);
void node_fill_info(const gnet_node_t n, gnet_node_info_t *info);

/***
 *** Sharing
 ***/

/*
 * Search query types
 */
typedef enum {
    QUERY_STRING,
    QUERY_SHA1
} query_type_t;

/*
 * Sharing callbacks
 */
typedef void (*search_request_listener_t) (
    query_type_t, const gchar *query, guint32, guint16);

void share_add_search_request_listener(search_request_listener_t l);
void share_remove_search_request_listener(search_request_listener_t l);


/***
 *** Searches
 ***/
typedef guint32 gnet_search_t;

/* 
 * Flags for search_new()
 */
#define SEARCH_PASSIVE	 0x01 /* start a passive ssearch */
#define SEARCH_ENABLED	 0x02 /* start an enabled search */

/*
 * Host vectors held in query hits.
 */
typedef struct gnet_host_vec {
	gnet_host_t *hvec;		/* Vector of alternate locations */
	gint hvcnt;				/* Amount of hosts in vector */
} gnet_host_vec_t;

/*
 * Result sets `status' flags.
 */
#define ST_KNOWN_VENDOR			0x8000		/* Found known vendor code */
#define ST_PARSED_TRAILER		0x4000		/* Was able to parse trailer */
#define ST_PUSH_PROXY			0x0010		/* Listed some push proxies */
#define ST_GGEP					0x0008		/* Trailer has a GGEP extension */
#define ST_UPLOADED				0x0004		/* Is "stable", people downloaded */
#define ST_BUSY					0x0002		/* Has currently no slots */
#define ST_FIREWALL				0x0001		/* Is behind a firewall */

/*
 * Processing of ignored files.
 */
#define SEARCH_IGN_DISPLAY_AS_IS	0		/* Display normally */
#define SEARCH_IGN_DISPLAY_MARKED	1		/* Display marked (lighter color) */
#define SEARCH_IGN_NO_DISPLAY		2		/* Don't display */

/*
 * A results_set structure factorizes the common information from a Query Hit
 * packet, and then has a list of individual records, one for each hit.
 *
 * A single structure is created for each Query Hit packet we receive, but
 * then it can be dispatched for displaying some of its records to the
 * various searches in presence.
 */
typedef struct gnet_results_set {
	gchar *guid;				/* Servent's GUID (atom) */
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint32 speed;
	time_t  stamp;				/* Reception time of the hit */
	guchar  vendor[4];			/* Vendor code */
	gchar *version;				/* Version information (atom) */
    flag_t  flags;
	gnet_host_vec_t *proxies;	/* Optional: known push proxies */
	gchar *hostname;			/* Optional: server's hostname */

	GSList *records;
	guint32 num_recs;
} gnet_results_set_t;

/*
 * Result record flags
 */
#define SR_DOWNLOADED	0x0001
#define SR_IGNORED		0x0002
#define SR_DONT_SHOW	0x0004

/*
 * An individual hit.  It referes to a file entry on the remote servent,
 * as identified by the parent results_set structure that contains this hit.
 */
typedef struct gnet_record {
	gchar  *name;				/* File name */
	guint32 size;				/* Size of file, in bytes */
	guint32 index;				/* Index for GET command */
	gchar  *sha1;				/* SHA1 URN (binary form, atom) */
	gchar  *tag;				/* Optional tag data string (atom) */
	gnet_host_vec_t *alt_locs;	/* Optional: known alternate locations */
    flag_t  flags;
} gnet_record_t;

/*
 * Search callbacks
 */
typedef void (*search_got_results_listener_t) 
    (GSList *, const gnet_results_set_t *);

void search_add_got_results_listener(search_got_results_listener_t l);
void search_remove_got_results_listener(search_got_results_listener_t l);

/*
 * Search public interface
 */
gnet_search_t search_new
    (const gchar *, guint16 min_speed, guint32 timeout, flag_t flags);
void search_close(gnet_search_t sh);

void search_start(gnet_search_t sh);
void search_stop(gnet_search_t sh);
gboolean search_is_stopped(gnet_search_t sh);
void search_reissue(gnet_search_t sh);

gboolean search_is_passive(gnet_search_t sh);
gboolean search_is_frozen(gnet_search_t sh);

void search_set_reissue_timeout(gnet_search_t sh, guint32 timeout);
guint32 search_get_reissue_timeout(gnet_search_t sh);

void search_free_alt_locs(gnet_record_t *rc);
void search_free_proxies(gnet_results_set_t *rs);

/***
 *** Filters
 ***/
enum rule_type {
    RULE_TEXT = 0,
    RULE_IP,
    RULE_SIZE,
    RULE_JUMP,
    RULE_SHA1,
    RULE_FLAG,
    RULE_STATE
};

enum rule_text_type {
    RULE_TEXT_PREFIX,
    RULE_TEXT_WORDS,
    RULE_TEXT_SUFFIX,
    RULE_TEXT_SUBSTR,
    RULE_TEXT_REGEXP,
    RULE_TEXT_EXACT
};

enum rule_flag_action {
    RULE_FLAG_SET = 0,
    RULE_FLAG_UNSET = 1,
    RULE_FLAG_IGNORE = 2
};

/*
 * MAX_FILTER_PROP is used to know how many FILTER_PROPS there are.
 */
typedef enum filter_prop {
    FILTER_PROP_DISPLAY = 0,
    FILTER_PROP_DOWNLOAD,
    MAX_FILTER_PROP
} filter_prop_t;

/*
 * The states a filter_property. I chose 0 for UNKNOWN because that
 * makes it easy to initialize the property array with g_new0 and
 * it's easy to check if the state is still unset by !.
 * FILTER_PROP_IGNORE is needed because we also want filter rules
 * that allow to act only on one property and ignores the other.
 */
typedef enum filter_prop_state {
    FILTER_PROP_STATE_UNKNOWN = 0,
    FILTER_PROP_STATE_DO,
    FILTER_PROP_STATE_DONT,
    MAX_FILTER_PROP_STATE,
    FILTER_PROP_STATE_IGNORE
} filter_prop_state_t;



/***
 *** General statistics
 ***/

enum {
    MSG_UNKNOWN = 0,
    MSG_INIT,
    MSG_INIT_RESPONSE,
    MSG_BYE,
    MSG_QRP,
    MSG_VENDOR,
    MSG_STANDARD,
    MSG_PUSH_REQUEST,
    MSG_SEARCH,
    MSG_SEARCH_RESULTS,
    MSG_TOTAL,     /* allways counted (for all the above types) */
    MSG_TYPE_COUNT /* number of known message types */
};

typedef enum msg_drop_reason {
    MSG_DROP_BAD_SIZE,
    MSG_DROP_TOO_SMALL,
    MSG_DROP_TOO_LARGE,
    MSG_DROP_WAY_TOO_LARGE,
    MSG_DROP_UNKNOWN_TYPE,
	MSG_DROP_UNEXPECTED,
    MSG_DROP_TTL0,
    MSG_DROP_MAX_TTL_EXCEEDED,
    MSG_DROP_THROTTLE,
	MSG_DROP_PONG_UNUSABLE,
    MSG_DROP_HARD_TTL_LIMIT,
    MSG_DROP_MAX_HOP_COUNT,
    MSG_DROP_UNREQUESTED_REPLY,
    MSG_DROP_ROUTE_LOST,
    MSG_DROP_NO_ROUTE,
    MSG_DROP_DUPLICATE,
    MSG_DROP_BANNED,
    MSG_DROP_SHUTDOWN,
    MSG_DROP_FLOW_CONTROL,
    MSG_DROP_QUERY_NO_NUL,
    MSG_DROP_QUERY_TOO_SHORT,
    MSG_DROP_QUERY_OVERHEAD,
    MSG_DROP_MALFORMED_SHA1,
    MSG_DROP_MALFORMED_UTF_8,
    MSG_DROP_BAD_RESULT,
	MSG_DROP_HOSTILE_IP,
    MSG_DROP_REASON_COUNT /* number of known reasons to drop a message */
} msg_drop_reason_t;

enum {
    GNR_ROUTING_ERRORS,
    GNR_LOCAL_SEARCHES,
    GNR_LOCAL_HITS,
    GNR_QUERY_COMPACT_COUNT,
    GNR_QUERY_COMPACT_SIZE,
    GNR_QUERY_UTF8,
    GNR_QUERY_SHA1,
	GNR_BROADCASTED_PUSHES,
    GNR_TYPE_COUNT /* number of general stats */
};

#define STATS_FLOWC_COLUMNS 10 /* Type, 0..7, 8+ */
#define STATS_RECV_COLUMNS 10 /* -"- */

typedef struct gnet_stat {
    guint32 drop_reason[MSG_DROP_REASON_COUNT][MSG_TYPE_COUNT];

    struct {
        guint32 received[MSG_TYPE_COUNT];
        guint32 generated[MSG_TYPE_COUNT];
        guint32 relayed[MSG_TYPE_COUNT];
        guint32 dropped[MSG_TYPE_COUNT];
        guint32 expired[MSG_TYPE_COUNT];
		guint32 received_hops[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint32 received_ttl[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint32 flowc_hops[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
		guint32 flowc_ttl[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
    } pkg;

    struct {
        guint32 received[MSG_TYPE_COUNT];
        guint32 generated[MSG_TYPE_COUNT];
        guint32 relayed[MSG_TYPE_COUNT];
        guint32 dropped[MSG_TYPE_COUNT];
        guint32 expired[MSG_TYPE_COUNT];
		guint32 received_hops[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint32 received_ttl[STATS_RECV_COLUMNS][MSG_TYPE_COUNT];
		guint32 flowc_hops[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
		guint32 flowc_ttl[STATS_FLOWC_COLUMNS][MSG_TYPE_COUNT];
    } byte;


    guint32 general[GNR_TYPE_COUNT];
} gnet_stats_t;

typedef enum {
    BW_GNET_IN,
    BW_GNET_OUT,
    BW_HTTP_IN,
    BW_HTTP_OUT,
    BW_LEAF_IN,
    BW_LEAF_OUT
} gnet_bw_source;

typedef struct gnet_bw_stats {
    gboolean enabled;
    guint32  current;
    guint32  average;
    guint32  limit;
} gnet_bw_stats_t;

void gnet_stats_get(gnet_stats_t *stats);
void gnet_get_bw_stats(gnet_bw_source type, gnet_bw_stats_t *stats);



/***
 *** Downloads
 ***/
/* FIXME: dl_file_info must not be used here and download_index_changed
 *        actually needs to be in downloads.h and should be called from
 *       search.h and not from search_gui.h.
 */
struct dl_file_info;
gboolean download_new(gchar *,
	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_auto_new(gchar *,
 	guint32, guint32, guint32, guint16, gchar *, gchar *, gchar *, time_t,
    gboolean, struct dl_file_info *, gnet_host_vec_t *);
void download_index_changed(guint32, guint16, gchar *, guint32, guint32);

#define URN_INDEX	0xffffffff		/* Marking index, indicates URN instead */

/***
 *** Uploads
 ***/

typedef guint32 gnet_upload_t;

/*
 * Upload states.
 */

typedef enum {
    GTA_UL_PUSH_RECEIVED    = 1,    /* We got a push request */
    GTA_UL_COMPLETE         = 2,    /* The file has been sent completely */
    GTA_UL_SENDING          = 3,    /* We are sending data */
    GTA_UL_HEADERS          = 4,    /* Receiving the HTTP request headers */
    GTA_UL_WAITING          = 5,    /* Waiting new HTTP request */
    GTA_UL_ABORTED          = 6,    /* Upload removed during operation */
    GTA_UL_CLOSED           = 7,    /* Upload removed while waiting */
    GTA_UL_QUEUED           = 8,    /* Upload is queued */
    GTA_UL_QUEUE            = 9,    /* Send a queue (Similar to push) */
    GTA_UL_QUEUE_WAITING    = 10,   /* Connect back with GTA_UL_QUEUE was
                                       success now waiting for a response */
    GTA_UL_PFSP_WAITING     = 11,   /* Requested range unavailable, retry... */
} upload_stage_t;

typedef struct gnet_upload_status {
    upload_stage_t status;
	off_t   pos;		 /* Read position in file we're sending */
    guint32 bps;         /* Current transfer rate */
    guint32 avg_bps;     /* Average transfer rate */
    time_t  last_update;
	
	guint	parq_position;
	guint	parq_size;
	guint32	parq_lifetime;
	guint32	parq_retry;
	guint	parq_queue_no;
} gnet_upload_status_t;

typedef struct gnet_upload_info {
    gnet_upload_t upload_handle;

    gchar  *name;        /* Name of requested file */

    guint32 ip;          /* remote IP address */

    guint32 file_size;   /* Size of requested file */
    guint32 range_start; /* First byte to send, inclusive */
    guint32 range_end;   /* Last byte to send, inclusive */

    time_t  start_date;

    gchar  *user_agent;  /* remote user agent */
	gboolean push;       /* Whether we're pushing or not */
	gboolean partial;    /* Whether it's a partial file */
} gnet_upload_info_t;

/*
 * State inspection macros.
 */

#define UPLOAD_IS_CONNECTING(u)						\
	(	(u)->status == GTA_UL_HEADERS				\
	||	(u)->status == GTA_UL_PUSH_RECEIVED			\
	||	(u)->status == GTA_UL_QUEUE					\
	||	(u)->status == GTA_UL_QUEUE_WAITING			\
	||	(u)->status == GTA_UL_PFSP_WAITING			\
	||	(u)->status == GTA_UL_WAITING	)

#define UPLOAD_IS_COMPLETE(u)	\
	((u)->status == GTA_UL_COMPLETE)

#define UPLOAD_IS_SENDING(u)	\
	((u)->status == GTA_UL_SENDING)

/*
 * Until we got all the HTTP headers, the entry does not appear
 * in the upload list on the GUI.
 */
/*
#define UPLOAD_IS_VISIBLE(u) \
	((u)->status != GTA_UL_HEADERS)
*/

/*
 * Uploads callback definitions
 */
typedef void (*upload_added_listener_t) (
    gnet_upload_t, guint32, guint32);
typedef void (*upload_removed_listener_t) (
    gnet_upload_t, const gchar *, guint32, guint32);
typedef void (*upload_info_changed_listener_t) (
    gnet_upload_t, guint32, guint32);

#define upload_add_listener(signal, callback) \
    upload_add_##signal##_listener(callback);

#define upload_remove_listener(signal, callback) \
    upload_remove_##signal##_listener(callback);

void upload_add_upload_added_listener(upload_added_listener_t);
void upload_remove_upload_added_listener(upload_added_listener_t);
void upload_add_upload_removed_listener(upload_removed_listener_t);
void upload_remove_upload_removed_listener(upload_removed_listener_t);
void upload_add_upload_info_changed_listener
    (upload_info_changed_listener_t);
void upload_remove_upload_info_changed_listener
    (upload_info_changed_listener_t);

/*
 * Uploads public interface
 */
gnet_upload_info_t *upload_get_info(gnet_upload_t);
void upload_free_info(gnet_upload_info_t *);
void upload_get_status(gnet_upload_t u, gnet_upload_status_t *s);
void upload_kill(gnet_upload_t);


/* FIXME: temporarily located here: */
struct ul_stats {
	gchar  *filename;
	guint32 size;
	guint32 attempts;
	guint32 complete;
	guint64 bytes_sent;
	gfloat  norm;		/* bytes sent / file size */
} ul_stats_t;


/***
 *** Sources (traditionally called "downloads")
 ***/

typedef guint32 gnet_src_t;

typedef void (*src_listener_t) (gnet_src_t);
typedef enum {
    EV_SRC_ADDED = 0,
    EV_SRC_REMOVED,
    EV_SRC_INFO_CHANGED,
    EV_SRC_STATUS_CHANGED,
    EV_SRC_EVENTS /* Number of events in this domain */
} gnet_src_ev_t;

void src_add_listener(src_listener_t, gnet_src_ev_t, frequency_t, guint32);
void src_remove_listener(src_listener_t, gnet_src_ev_t);



/***
 *** Fileinfo
 ***/

typedef guint32 gnet_fi_t;

typedef struct gnet_fi_info {
    gnet_fi_t fi_handle;

    gchar    *file_name;        /* Name of the file on disk */
} gnet_fi_info_t;

typedef struct gnet_fi_status {
    guint32  recvcount;
    guint32  refcount;
    guint32  lifecount;
    guint32  size;
    guint32  done;
    guint32  recv_last_rate;
} gnet_fi_status_t;

typedef void (*fi_listener_t) (gnet_fi_t);
typedef void (*fi_src_listener_t) (gnet_fi_t, gnet_src_t);

typedef enum {
    EV_FI_ADDED = 0,       /* fi_listener */
    EV_FI_REMOVED,         /* fi_listener */
    EV_FI_INFO_CHANGED,    /* fi_listener */
    EV_FI_STATUS_CHANGED,  /* fi_listener */
    EV_FI_SRC_ADDED,       /* fi_src_listener */
    EV_FI_SRC_REMOVED,     /* fi_src_listener */
    EV_FI_EVENTS           /* Number of events in this domain */
} gnet_fi_ev_t;

void fi_add_listener(GCallback, gnet_fi_ev_t, frequency_t, guint32);
void fi_remove_listener(GCallback, gnet_fi_ev_t);

gnet_fi_info_t *fi_get_info(gnet_fi_t);
void fi_free_info(gnet_fi_info_t *);
void fi_get_status(gnet_fi_t, gnet_fi_status_t *);
gchar **fi_get_aliases(gnet_fi_t fih);

gboolean fi_purge(gnet_fi_t fih);


#endif /* _gnet_h_ */
