/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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

#ifndef __sockets_h__
#define __sockets_h__

#include <sys/time.h>		/* for time_t */
#include <glib.h>

struct sockaddr;

#define SOCK_BUFSZ	4096

/*
 * Connection directions.
 */

enum socket_direction {
	SOCK_CONN_INCOMING,
	SOCK_CONN_OUTGOING,
	SOCK_CONN_LISTENING,
	SOCK_CONN_PROXY_OUTGOING,
};

/*
 * Connection types.
 */

enum socket_type {
	SOCK_TYPE_UNKNOWN = 0,
	SOCK_TYPE_CONTROL,
	SOCK_TYPE_DOWNLOAD,
	SOCK_TYPE_UPLOAD,
	SOCK_TYPE_HTTP,
    SOCK_TYPE_SHELL
};

struct gnutella_socket {
	gint file_desc;			/* file descriptor */

	gint gdk_tag;			/* gdk tag */

	enum socket_direction direction;
	enum socket_type type;
	gboolean corked;

	guint32 ip;				/* IP	of our partner */
	guint16 port;			/* Port of our partner */

	guint16 local_port;		/* Port on our side */

	time_t last_update;		/* Timestamp of last activity on socket */

	union {
		struct gnutella_node *node;
		struct download *download;
		struct upload *upload;
		gpointer handle;
	} resource;

	struct getline *getline;	/* Line reader object */

	gchar buffer[SOCK_BUFSZ];	/* buffer to put in the data read */
	guint32 pos;				/* write position in the buffer */
};

/*
 * Global Data
 */

extern gboolean is_firewalled;

/*
 * Global Functions
 */

void socket_free(struct gnutella_socket *);
struct gnutella_socket *socket_connect(guint32, guint16, enum socket_type);
struct gnutella_socket *socket_listen(guint32, guint16, enum socket_type);

void sock_cork(struct gnutella_socket *s, gboolean on);
void sock_send_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_recv_buf(struct gnutella_socket *s, gint size, gboolean shrink);
void sock_nodelay(struct gnutella_socket *s, gboolean on);
void sock_tx_shutdown(struct gnutella_socket *s);

int connect_http(struct gnutella_socket *);
int connect_socksv5(struct gnutella_socket *);
int proxy_connect(int, const struct sockaddr *, guint);
int recv_socks(struct gnutella_socket *);
int send_socks(struct gnutella_socket *);

void socket_timer(time_t now);
void socket_shutdown(void);

#endif /* __sockets_h__ */
