
#ifndef __gnutella_h__
#define __gnutella_h__

/*
 * Main includes
 */

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
#include "appconfig.h"

/*
 * Macros
 */

#define READ_GUINT16_LE(a,v) { memcpy(&v, a, 2); v = GUINT16_FROM_LE(v); }

#define WRITE_GUINT16_LE(v,a) { guint16 _v = GUINT16_TO_LE(v); memcpy(a, &_v, 2); }

#define READ_GUINT32_LE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_LE(v); }
#define READ_GUINT32_BE(a,v) { memcpy(&v, a, 4); v = GUINT32_FROM_BE(v); }

#define WRITE_GUINT32_LE(v,a) { guint32 _v = GUINT32_TO_LE(v); memcpy(a, &_v, 4); }
#define WRITE_GUINT32_BE(v,a) { guint32 _v = GUINT32_TO_BE(v); memcpy(a, &_v, 4); }

/*
 * Constants
 */

#define GTA_VERSION 0
#define GTA_SUBVERSION 90
#define GTA_REVISION "unstable"
#define GTA_REVCHAR "u"
#define GTA_INTERFACE "X11"
#define GTA_RELEASE "12/05/2002"
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#define GTA_MSG_INIT					0x00
#define GTA_MSG_INIT_RESPONSE			0x01
#define GTA_MSG_BYE						0x02
#define GTA_MSG_PUSH_REQUEST			0x40
#define GTA_MSG_SEARCH					0x80
#define GTA_MSG_SEARCH_RESULTS			0x81

/*
 * Structures
 */

/* Messages structures */

struct gnutella_header {
	guchar muid[16];
	guchar function;
	guchar ttl;
	guchar hops;
	guchar size[4];
};

struct gnutella_msg_init {
	struct gnutella_header header;
};

struct gnutella_init_response {
	guchar host_port[2];
	guchar host_ip[4];
	guchar files_count[4];
	guchar kbytes_count[4];
};

struct gnutella_msg_init_response {
	struct gnutella_header header;
	struct gnutella_init_response response;
};

struct gnutella_push_request {
	guchar guid[16];
	guchar file_id[4];
	guchar host_ip[4];
	guchar host_port[2];
};

struct gnutella_msg_push_request {
	struct gnutella_header header;
	struct gnutella_push_request request;
};

struct gnutella_bye {
	guchar code[2];
	guchar message[0];
};

/* */

struct ping_req {
	struct timeval tv;			/* Date of the ping */
	guchar muid[16];			/* muid of the ping */
	guint32 hosts;				/* Number of hosts that replied */
	guint32 files;				/* Number of shared files of all the hosts */
	guint64 kbytes;				/* Number of K-bytes of all the files */

	guint64 delay;				/* Total of reply delay for this request */
};

/*
 * Variables
 */

guchar guid[16];				/* ID of our client for this session */


/* main.c */

extern struct gnutella_socket *s_listen;
extern GtkWidget *main_window;
extern gchar *version_string;
extern time_t start_time;
extern gchar *start_rfc822_date;

/*
 * Functions
 */

/* main.c */

void gtk_gnutella_exit(gint);

/* md5.c */

gchar *md5dump(guchar *);

#endif							/* __gnutella_h__ */

/* vi: set ts=4: */
