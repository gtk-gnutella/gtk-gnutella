/*
 * Copyright (c) 2001-2002, Raphael Manfredi
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
#define GTA_REVISION "beta"
#define GTA_REVCHAR "b"
#define GTA_INTERFACE "X11"
#define GTA_RELEASE "30/06/2002"
#define GTA_WEBSITE "http://gtk-gnutella.sourceforge.net/"

#define GTA_MSG_INIT					0x00
#define GTA_MSG_INIT_RESPONSE			0x01
#define GTA_MSG_BYE						0x02
#define GTA_MSG_QRP						0x30
#define GTA_MSG_VENDOR					0x31	/* Vendor-specific */
#define GTA_MSG_STANDARD				0x32	/* Standard vendor-specific */
#define GTA_MSG_PUSH_REQUEST			0x40
#define GTA_MSG_SEARCH					0x80
#define GTA_MSG_SEARCH_RESULTS			0x81

#define GTA_QRP_RESET					0x00
#define GTA_QRP_PATCH					0x01

/*
 * Structures
 */

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(p)
#endif

/* Messages structures */

struct gnutella_header {
	guchar muid[16];
	guchar function;
	guchar ttl;
	guchar hops;
	guchar size[4];
} __attribute__((__packed__));

struct gnutella_msg_init {
	struct gnutella_header header;
} __attribute__((__packed__));

struct gnutella_init_response {
	guchar host_port[2];
	guchar host_ip[4];
	guchar files_count[4];
	guchar kbytes_count[4];
} __attribute__((__packed__));

struct gnutella_msg_init_response {
	struct gnutella_header header;
	struct gnutella_init_response response;
} __attribute__((__packed__));

struct gnutella_search {
	guchar speed[2];
	guchar query[0];
} __attribute__((__packed__));

struct gnutella_search_results {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];
	guchar records[0];

	/* Last 16 bytes = client_id */
} __attribute__((__packed__));

struct gnutella_msg_search {
	struct gnutella_header header;
	struct gnutella_search search;
} __attribute__((__packed__));

struct gnutella_push_request {
	guchar guid[16];
	guchar file_id[4];
	guchar host_ip[4];
	guchar host_port[2];
} __attribute__((__packed__));

struct gnutella_msg_push_request {
	struct gnutella_header header;
	struct gnutella_push_request request;
} __attribute__((__packed__));

struct gnutella_bye {
	guchar code[2];
	guchar message[0];
} __attribute__((__packed__));

struct qrp_reset {
	guchar variant;			/* 0x00 */
	guchar table_length[4];	/* little endian */
	guchar infinity;
} __attribute__((__packed__));

struct qrp_patch {
	guchar variant;			/* 0x01 */
	guchar seq_no;
	guchar seq_size;
	guchar compressor;
	guchar entry_bits;
} __attribute__((__packed__));

struct msg_vendor {
	guchar vendor[4];		/* E.g. "GTKG" */
	guchar type[2];			/* Message type, little endian */
	guchar version[2];		/* Message version number, little endian */
	/* payload follows */
} __attribute__((__packed__));

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

#endif							/* __gnutella_h__ */

/* vi: set ts=4: */
