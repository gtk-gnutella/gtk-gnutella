/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_socket_defs_h_
#define _ui_core_interface_socket_defs_h_

#include "common.h"

typedef struct wrap_io {
	gpointer ctx;
	ssize_t (*write)(struct wrap_io *, gconstpointer, size_t);
	ssize_t (*read)(struct wrap_io *, gpointer, size_t);
	ssize_t (*writev)(struct wrap_io *, const struct iovec *, int);
	ssize_t (*readv)(struct wrap_io *, struct iovec *, int);
	int (*fd)(struct wrap_io *);
} wrap_io_t;

typedef struct wrap_buf {
	size_t	pos;		/**< Current position in the buffer. */
	size_t	len;		/**< Amount of currently buffered bytes. */
	size_t	size;		/**< The size of the buffer. */
	gchar	*ptr;		/**< The walloc()ed buffer. */
} wrap_buf_t;

#ifdef USE_TLS
#include <gnutls/gnutls.h>

enum socket_tls_stage {
	SOCK_TLS_NONE			= 0,
	SOCK_TLS_INITIALIZED	= 1,
	SOCK_TLS_ESTABLISHED	= 2
};

struct socket_tls_ctx {
	gnutls_session		 	session;
	gboolean			 	enabled;
	enum socket_tls_stage	stage;
	size_t snarf;			/**< Pending bytes if write failed temporarily. */
};

#define SOCKET_USES_TLS(s) \
	((s)->tls.enabled && (s)->tls.stage >= SOCK_TLS_ESTABLISHED)
#else /* !USE_TLS */
#define SOCKET_USES_TLS(s) 0
#endif /* USE_TLS */

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
    SOCK_TYPE_SHELL,
    SOCK_TYPE_CONNBACK,
    SOCK_TYPE_PPROXY,
    SOCK_TYPE_DESTROYING,
	SOCK_TYPE_UDP,
};

struct gnutella_socket {
	gint file_desc;			/* file descriptor */
	guint32 flags;			/* operating flags */
	guint gdk_tag;			/* gdk tag */

	enum socket_direction direction;
	enum socket_type type;
	gboolean corked;
	gint adns;				/* status of ADNS resolution */
	gchar *adns_msg;		/* ADNS error message */

	guint32 ip;				/* IP	of our partner */
	guint16 port;			/* Port of our partner */

	guint16 local_port;		/* Port on our side */

	time_t last_update;		/* Timestamp of last activity on socket */
	
	struct wrap_io wio;		/**< Wrapped IO object */
	
#ifdef USE_TLS
	struct socket_tls_ctx tls;
#endif

	union {
		struct gnutella_node *node;
		struct download *download;
		struct upload *upload;
		struct pproxy *pproxy;
		struct cproxy *cproxy;
		gpointer handle;
	} resource;

	struct getline *getline;	/* Line reader object */

	gchar buffer[SOCK_BUFSZ];	/* buffer to put in the data read */
	size_t pos;			/* write position in the buffer */
};

/*
 * Operating flags
 */

#define SOCK_F_ESTABLISHED		0x00000001 /* Connection was established */
#define SOCK_F_EOF				0x00000002 /* Got an EOF condition */
#define SOCK_F_UDP				0x40000000 /* Is a UDP socket */
#define SOCK_F_TCP				0x80000000 /* Is a TCP socket */

/*
 * Access macros
 */

#define sock_is_corked(x)		((x)->corked)

#endif

/* vi: set ts=4 sw=4 cindent: */
