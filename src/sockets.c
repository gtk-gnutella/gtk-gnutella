/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Socket management.
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

#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <pwd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "sockets.h"
#include "downloads.h"
#include "uploads.h"
#include "nodes.h"
#include "header.h"
#include "getline.h"
#include "bsched.h"
#include "ban.h"
#include "http.h"
#include "settings.h"
#include "inet.h"

#if !defined(SOL_TCP) && defined(IPPROTO_TCP)
#define SOL_TCP IPPROTO_TCP
#endif

#ifndef SHUT_WR
#define SHUT_WR 1		/* Shutdown TX side */
#endif

#define RQST_LINE_LENGTH	256		/* Reasonable estimate for request line */

static gboolean ip_computed = FALSE;

static GSList *sl_incoming = (GSList *) NULL;	/* To spot inactive sockets */

static void guess_local_ip(int sd);

/*
 * socket_timer
 *
 * Called by main timer.
 * Expires inactive sockets.
 */
void socket_timer(time_t now)
{
	GSList *l;

  retry:
	for (l = sl_incoming; l; l = l->next) {
		struct gnutella_socket *s = (struct gnutella_socket *) l->data;
		g_assert(s->last_update);
		/* We reuse the `node_connecting_timeout' parameter, need a new one? */
		if (now - s->last_update > node_connecting_timeout) {
			if (dbg) {
				g_warning("connection from %s timed out (%d bytes read)",
						  ip_to_gchar(s->ip), s->pos);
				if (s->pos > 0)
					dump_hex(stderr, "Connection Header",
						s->buffer, MIN(s->pos, 80));
			}
			socket_destroy(s);
			goto retry;			/* Don't know the internals of lists, retry */
		}
	}
}

void socket_shutdown(void)
{
	while (sl_incoming)
		socket_destroy((struct gnutella_socket *) sl_incoming->data);
}

/* ----------------------------------------- */

/* Destroy a socket, and free its resource if needed */

void socket_destroy(struct gnutella_socket *s)
{
	g_assert(s);

	if (s->type == SOCK_TYPE_CONTROL && s->resource.node) {
		node_remove(s->resource.node, NULL);
		return;
	} else if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download) {
		download_stop(s->resource.download, GTA_DL_ERROR, NULL);
		return;

	} else if (s->type == SOCK_TYPE_UPLOAD && s->resource.upload) {
		upload_remove(s->resource.upload, NULL);
		return;
	} else if (s->type == SOCK_TYPE_HTTP && s->resource.handle) {
		http_async_cancel(s->resource.handle, HTTP_ASYNC_IO_ERROR);
		return;
	}

	socket_free(s);
}

void socket_free(struct gnutella_socket *s)
{
	g_assert(s);
	if (s->last_update) {
		g_assert(sl_incoming);
		sl_incoming = g_slist_remove(sl_incoming, s);
	}
	if (s->gdk_tag)
		gdk_input_remove(s->gdk_tag);
	if (s->getline)
		getline_free(s->getline);
	if (s->file_desc != -1) {
		if (s->corked)
			sock_cork(s, FALSE);
		close(s->file_desc);
	}
	g_free(s);
}

/* ----------------------------------------- */

/* Read bytes on an unknown incoming socket */

static void socket_read(gpointer data, gint source, GdkInputCondition cond)
{
	gint r;
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	guint count;
	guint parsed;
	guchar *first;

	//s->type = 0;

	if (cond & GDK_INPUT_EXCEPTION) {
		socket_destroy(s);
		return;
	}

	g_assert(s->pos == 0);		/* We read a line, then leave this callback */

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("socket_read(): incoming buffer full, disconnecting from %s",
			 ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		socket_destroy(s);
		return;
	}

	/*
	 * Don't read too much data.  We're solely interested in getting
	 * the leading line.  If we don't read the whole line, we'll come
	 * back later on to read the remaining data.
	 *		--RAM, 23/05/2002
	 */

	count = MIN(count, RQST_LINE_LENGTH);

	r = bws_read(bws.in, s->file_desc, s->buffer + s->pos, count);

	if (r == 0) {
		socket_destroy(s);
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		socket_destroy(s);
		return;
	}

	s->last_update = time((time_t *) 0);
	s->pos += r;

	/*
	 * Get first line.
	 */

	switch (getline_read(s->getline, s->buffer, s->pos, &parsed)) {
	case READ_OVERFLOW:
		g_warning("socket_read(): first line too long, disconnecting from %s",
			 ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data",
			getline_str(s->getline), MIN(getline_length(s->getline), 256));
		if (
			0 == strncmp(s->buffer, "GET ", 4) ||
			0 == strncmp(s->buffer, "HEAD ", 5)
		)
			http_send_status(s, 414, NULL, 0, "Requested URL Too Large");
		socket_destroy(s);
		return;
	case READ_DONE:
		if (s->pos != parsed)
			memmove(s->buffer, s->buffer + parsed, s->pos - parsed);
		s->pos -= parsed;
		break;
	case READ_MORE:		/* ok, but needs more data */
	default:
		g_assert(parsed == s->pos);
		s->pos = 0;
		return;
	}

	/*
	 * We come here only when we got the first line of data.
	 *
	 * Whatever happens now, we're not going to use the existing read
	 * callback, and we'll no longer monitor the socket via the `sl_incoming'
	 * list: if it's a node connection, we'll monitor the node, if it's
	 * an upload, we'll monitor the upload.
	 */

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;
	sl_incoming = g_slist_remove(sl_incoming, s);
	s->last_update = 0;

	first = getline_str(s->getline);

	/*
	 * Always authorize replies for our PUSH requests!
	 */

	if (0 == strncmp(first, "GIV ", 4)) {
		download_push_ack(s);
		return;
	}

	/*
	 * Check for banning.
	 */

	switch (ban_allow(s->ip)) {
	case BAN_OK:				/* Connection authorized */
		break;
	case BAN_FORCE:				/* Connection refused, no ack */
		ban_force(s);
		goto cleanup;
	case BAN_FIRST:				/* Connection refused, negative ack */
		if (0 == strncmp(first, gnutella_hello, gnutella_hello_length))
			send_node_error(s, 550, "Banned for %s",
				short_time(ban_delay(s->ip)));
		else {
			gint delay = ban_delay(s->ip);
			gchar msg[80];
			http_extra_desc_t hev;

			g_snprintf(msg, sizeof(msg)-1, "Retry-After: %d\r\n", delay);

			hev.he_type = HTTP_EXTRA_LINE;
			hev.he_msg = msg;

			http_send_status(s, 550, &hev, 1, "Banned for %s",
				short_time(delay));
		}
		goto cleanup;
	default:
		g_assert(0);			/* Not reached */
	}

	/*
	 * Dispatch request.
	 */

	if (0 == strncmp(first, gnutella_hello, gnutella_hello_length))
		node_add_socket(s, s->ip, s->port);	/* Incoming control connection */
	else if (0 == strncmp(first, "GET ", 4))
		upload_add(s);
	else if (0 == strncmp(first, "HEAD ", 5))
		upload_add(s);
	else
		goto unknown;

	return;

unknown:
	if (dbg) {
		gint len = getline_length(s->getline);
		g_warning("socket_read(): got unknown incoming connection, dropping!");
		dump_hex(stderr, "First Line", first, MIN(len, 160));
	}
	if (strstr(first, "HTTP"))
		http_send_status(s, 501, NULL, 0, "Method Not Implemented");
	/* FALL THROUGH */

cleanup:
	socket_destroy(s);
}

/*
 * Sockets connection
 */

static void socket_connected(gpointer data, gint source, GdkInputCondition cond)
{
	/* We are connected to somebody */

	struct gnutella_socket *s = (struct gnutella_socket *) data;

	if (cond & GDK_INPUT_EXCEPTION) {	/* Error while connecting */
		if (s->type == SOCK_TYPE_CONTROL && s->resource.node)
			node_remove(s->resource.node, "Connection failed");
		else if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download)
			download_fallback_to_push(s->resource.download, FALSE, FALSE);
		else if (s->type == SOCK_TYPE_UPLOAD && s->resource.upload)
			upload_remove(s->resource.upload, "Connection failed");
		else
			socket_destroy(s);
		return;
	}

	if (cond & GDK_INPUT_READ) {
		if (
			proxy_connections
			&& s->direction == SOCK_CONN_PROXY_OUTGOING
		) {
			gdk_input_remove(s->gdk_tag);
			s->gdk_tag = 0;

			if (proxy_protocol == 4) {
				if (recv_socks(s) != 0) {
					socket_destroy(s);
					return;
				}

				s->direction = SOCK_CONN_OUTGOING;

				s->gdk_tag =
					gdk_input_add(s->file_desc,
								  GDK_INPUT_READ | GDK_INPUT_WRITE |
								  GDK_INPUT_EXCEPTION, socket_connected,
								  (gpointer) s);
				return;
			} else if (proxy_protocol == 5) {
				if (connect_socksv5(s) != 0) {
					socket_destroy(s);
					return;
				}

				if (s->pos > 5) {
					s->direction = SOCK_CONN_OUTGOING;

					s->gdk_tag =
						gdk_input_add(s->file_desc,
									  GDK_INPUT_READ | GDK_INPUT_WRITE |
									  GDK_INPUT_EXCEPTION,
									  socket_connected, (gpointer) s);

					return;
				} else
					s->gdk_tag =
						gdk_input_add(s->file_desc,
									  GDK_INPUT_WRITE |
									  GDK_INPUT_EXCEPTION,
									  socket_connected, (gpointer) s);

				return;

			} else if (proxy_protocol == 1) {
				if (connect_http(s) != 0) {
					socket_destroy(s);
					return;
				}

				if (s->pos > 2) {
					s->direction = SOCK_CONN_OUTGOING;

					s->gdk_tag =
						gdk_input_add(s->file_desc,
									  GDK_INPUT_READ | GDK_INPUT_WRITE |
									  GDK_INPUT_EXCEPTION,
									  socket_connected, (gpointer) s);
					return;
				} else {
					s->gdk_tag =
						gdk_input_add(s->file_desc,
									  GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
									  socket_connected, (gpointer) s);
					return;
				}
			}
		}
	}

	if (cond & GDK_INPUT_WRITE) {
		/* We are just connected to our partner */
		gint res, option, size = sizeof(gint);

		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;

		/* Check wether the socket is really connected */

		res = getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR,
					   (void *) &option, &size);

		if (res == -1 || option) {
			if (s->type == SOCK_TYPE_CONTROL && s->resource.node)
				node_remove(s->resource.node, "Connection failed");
			else if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download)
				download_fallback_to_push(s->resource.download, FALSE, FALSE);
			else
				socket_destroy(s);
			return;
		}

		if (proxy_connections
			&& s->direction == SOCK_CONN_PROXY_OUTGOING) {
			if (proxy_protocol == 4) {

				if (send_socks(s) != 0) {
					socket_destroy(s);
					return;
				}
			} else if (proxy_protocol == 5) {
				if (connect_socksv5(s) != 0) {
					socket_destroy(s);
					return;
				}

			} else if (proxy_protocol == 1) {
				if (connect_http(s) != 0) {
					socket_destroy(s);
					return;
				}
			}

			s->gdk_tag =
				gdk_input_add(s->file_desc,
							  GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
							  socket_connected, (gpointer) s);
			return;
		}

		inet_connection_succeeded(s->ip);

		s->pos = 0;
		memset(s->buffer, 0, sizeof(s->buffer));

		g_assert(s->gdk_tag == 0);

		/*
		 * Even though local_ip is persistent, we refresh it after startup,
		 * in case the IP changed since last time.
		 *		--RAM, 07/05/2002
		 */

		guess_local_ip(s->file_desc);

		switch (s->type) {
		case SOCK_TYPE_CONTROL:
			{
				struct gnutella_node *n = s->resource.node;

				g_assert(n->socket == s);
				node_init_outgoing(n);
			}
			break;

		case SOCK_TYPE_DOWNLOAD:
			{
				struct download *d = s->resource.download;

				g_assert(d->socket == s);
				download_send_request(d);
			}
			break;

		case SOCK_TYPE_UPLOAD:
			{
				struct upload *u = s->resource.upload;

				g_assert(u->socket == s);
				upload_push_conf(u);
			}
			break;

		case SOCK_TYPE_HTTP:
			http_async_connected(s->resource.handle);
			break;

		default:
			g_warning("socket_connected(): Unknown socket type %d !", s->type);
			socket_destroy(s);		/* ? */
			break;
		}
	}
}

static void guess_local_ip(int sd)
{
	struct sockaddr_in addr;
	gint len = sizeof(struct sockaddr_in);
	guint32 ip;

	if (-1 != getsockname(sd, (struct sockaddr *) &addr, &len)) {
		gboolean can_supersede;
		ip = g_ntohl(addr.sin_addr.s_addr);

		/*
		 * If local IP was unknown, keep what we got here, even if it's a
		 * private IP. Otherwise, we discard private IPs unless the previous
		 * IP was private.
		 *		--RAM, 17/05/2002
		 */

		can_supersede = !is_private_ip(ip) || is_private_ip(local_ip);

		if (!ip_computed) {
			if (!local_ip || can_supersede)
				gnet_prop_set_guint32(PROP_LOCAL_IP, &ip, 0, 1);
			ip_computed = TRUE;
		} else if (can_supersede)
			gnet_prop_set_guint32(PROP_LOCAL_IP, &ip, 0, 1);
	}
}

/*
 * socket_port
 *
 * Return socket's local port, or -1 on error.
 */
static int socket_local_port(struct gnutella_socket *s)
{
	struct sockaddr_in addr;
	gint len = sizeof(struct sockaddr_in);

	if (getsockname(s->file_desc, (struct sockaddr *) &addr, &len) == -1)
		return -1;

	return g_ntohs(addr.sin_port);
}

static void socket_accept(gpointer data, gint source,
						  GdkInputCondition cond)
{
	/* Someone is connecting to us */

	struct sockaddr_in addr;
	gint sd, len = sizeof(struct sockaddr_in);
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	struct gnutella_socket *t = NULL;

	if (cond & GDK_INPUT_EXCEPTION) {
		g_warning("Input Exception for listening socket #%d !!!!\n",
				  s->file_desc);
		gtk_gnutella_exit(2);
		return;
	}

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		break;
	default:
		g_warning("socket_accept(): Unknown listning socket type %d !\n",
				  s->type);
		socket_destroy(s);
		return;
	}

	sd = accept(s->file_desc, (struct sockaddr *) &addr, &len);

	if (sd == -1) {
		g_warning("accept() failed (%s)", g_strerror(errno));
		return;
	}

	if (!local_ip)
		guess_local_ip(sd);

	/* Create a new struct socket for this incoming connection */

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	t = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	t->file_desc = sd;
	t->ip = g_ntohl(addr.sin_addr.s_addr);
	t->port = g_ntohs(addr.sin_port);
	t->direction = SOCK_CONN_INCOMING;
	t->type = s->type;
	t->local_port = s->local_port;
	t->getline = getline_make();

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		t->gdk_tag =
			gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
						  socket_read, t);
		/*
		 * Whilst the socket is attached to that callback, it has been
		 * freshly accepted and we don't know what we're going to do with
		 * it.	Is it an incoming node connection or an upload request?
		 * Can't tell until we have read enough bytes.
		 *
		 * However, we must guard against a subtle DOS attack whereby
		 * someone would connect to us and then send only one byte (say),
		 * then nothing.  The socket would remain connected, without
		 * being monitored for timeout by the node/upload code.
		 *
		 * Insert the socket to the `sl_incoming' list, and have it
		 * monitored periodically.	We know the socket is on the list
		 * as soon as it has a non-zero last_update field.
		 *				--RAM, 07/09/2001
		 */

		sl_incoming = g_slist_prepend(sl_incoming, t);
		t->last_update = time((time_t *) 0);
		break;

	default:
		g_assert(0);			/* Can't happen */
		break;
	}

	inet_got_incoming(t->ip);	/* Signal we got an incoming connection */
}

/*
 * Sockets creation
 */

/*
 * socket_connect
 *
 * Creates a connected socket with an attached resource of `type'.
 *
 * Connection happens in the background, the connection callback being
 * determined by the resource type.
 */
struct gnutella_socket *socket_connect(
	guint32 ip, guint16 port, enum socket_type type)
{
	/* Create a socket and try to connect it to ip:port */

	gint sd, option = 1, res = 0;
	struct sockaddr_in addr, lcladdr;
	struct gnutella_socket *s;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1) {
		g_warning("Unable to create a socket (%s)", g_strerror(errno));
		return NULL;
	}

	s = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	s->type = type;
	s->direction = SOCK_CONN_OUTGOING;
	s->file_desc = sd;
	s->ip = ip;
	s->port = port;

	setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &option,
			   sizeof(option));
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *) &option,
			   sizeof(option));

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = g_htonl(ip);
	addr.sin_port = g_htons(port);

	inet_connection_attempted(ip);

	/*
	 * Now we check if we're forcing a local IP, and make it happen if so.
	 *   --JSL
	 */
	if (force_local_ip) {
		lcladdr.sin_family = AF_INET;
		lcladdr.sin_addr.s_addr = g_htonl(forced_local_ip);
		lcladdr.sin_port = g_htons(0);

		/*
		 * Note: we ignore failures: it will be automatic at connect()
		 * It's useful only for people forcing the IP without being
		 * behind a masquerading firewall --RAM.
		 */
		(void) bind(sd, (struct sockaddr *) &lcladdr,
			sizeof(struct sockaddr_in));
	}

	if (proxy_connections) {
		lcladdr.sin_family = AF_INET;
		lcladdr.sin_port = INADDR_ANY;

		(void) bind(sd, (struct sockaddr *) &lcladdr,
			sizeof(struct sockaddr_in));

		res = proxy_connect(sd, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_in));

		s->direction = SOCK_CONN_PROXY_OUTGOING;
	} else
		res = connect(sd, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_in));

	if (res == -1 && errno != EINPROGRESS) {
		g_warning("Unable to connect to %s: (%s)",
			ip_port_to_gchar(s->ip, s->port), g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	s->local_port = socket_local_port(s);

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	g_assert(s->gdk_tag == 0);

	if (proxy_connections)
		s->gdk_tag = gdk_input_add(sd,
			GDK_INPUT_READ | GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION,
			socket_connected, s);
	else
		s->gdk_tag = gdk_input_add(sd,
			GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION,
			socket_connected, s);

	return s;
}

/*
 * socket_listen
 *
 * Creates a non-blocking listening socket with an attached resource of `type'.
 */
struct gnutella_socket *socket_listen(
	guint32 ip, guint16 port, enum socket_type type)
{
	/* Create a socket, then bind() and listen() it */

	int sd, option = 1;
	unsigned int l = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct gnutella_socket *s;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1) {
		g_warning("Unable to create a socket (%s)", g_strerror(errno));
		return NULL;
	}

	s = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	s->type = type;
	s->direction = SOCK_CONN_LISTENING;
	s->file_desc = sd;
	s->pos = 0;

	setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &option,
			   sizeof(option));
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *) &option,
			   sizeof(option));

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = g_htonl((ip) ? ip : INADDR_ANY);
	addr.sin_port = g_htons(port);

	/* bind() the socket */

	if (bind(sd, (struct sockaddr *) &addr, l) == -1) {
		g_warning("Unable to bind() the socket on port %u (%s)",
				  port, g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	/* listen() the socket */

	if (listen(sd, 5) == -1) {
		g_warning("Unable to listen() the socket (%s)", g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	/* Get the port of the socket, if needed */

	if (!port) {
		option = sizeof(struct sockaddr_in);

		if (getsockname(sd, (struct sockaddr *) &addr, &option) == -1) {
			g_warning("Unable to get the port of the socket: "
				"getsockname() failed (%s)", g_strerror(errno));
			socket_destroy(s);
			return NULL;
		}

		s->local_port = g_ntohs(addr.sin_port);
	} else
		s->local_port = port;

	s->gdk_tag =
		gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
					  socket_accept, s);

	return s;
}

/*
 * sock_cork
 *
 * Set/clear TCP_CORK on the socket.
 *
 * When set, TCP will only send out full TCP/IP frames.
 * The exact size depends on your LAN interface, but on Ethernet,
 * it's about 1500 bytes.
 */
void sock_cork(struct gnutella_socket *s, gboolean on)
{
#if !defined(TCP_CORK) && defined(TCP_NOPUSH)
#define TCP_CORK TCP_NOPUSH		/* FreeBSD names it TCP_NOPUSH */
#endif

#ifdef TCP_CORK
	gint arg = on ? 1 : 0;

	if (-1 == setsockopt(s->file_desc, SOL_TCP, TCP_CORK, &arg, sizeof(arg)))
		g_warning("unable to %s TCP_CORK on fd#%d: %s",
			on ? "set" : "clear", s->file_desc, g_strerror(errno));
	else
		s->corked = on;
#else
	static gboolean warned = FALSE;

	if (!warned)
		g_warning("TCP_CORK is not implemented on this system");

	warned = TRUE;
#endif /* TCP_CORK */
}

/*
 * _sock_set
 *
 * Internal routine for sock_send_buf() and sock_recv_buf().
 * Set send/receive buffer to specified size, and warn if it cannot be done.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
static void _sock_set(gint fd, gint option, gint size,
	gchar *type, gboolean shrink)
{
	gint old_len = 0;
	gint new_len = 0;
	gint len;

	size = (size + 1) & ~0x1;	/* Must be even, round to upper boundary */

	len = sizeof(old_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &old_len, &len))
		g_warning("cannot read old %s buffer length on fd #%d: %s",
			type, fd, g_strerror(errno));

// XXX needs to add metaconfig test
#if linux
	old_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (!shrink && old_len >= size) {
		if (dbg > 5)
			printf("SOCKET %s buffer on fd #%d NOT shrank to %d bytes (is %d)\n",
				type, fd, size, old_len);
		return;
	}

	if (-1 == setsockopt(fd, SOL_SOCKET, option, &size, sizeof(size)))
		g_warning("cannot set new %s buffer length to %d on fd #%d: %s",
			type, size, fd, g_strerror(errno));

	len = sizeof(new_len);
	if (-1 == getsockopt(fd, SOL_SOCKET, option, &new_len, &len))
		g_warning("cannot read new %s buffer length on fd #%d: %s",
			type, fd, g_strerror(errno));

#if linux
	new_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (dbg > 5)
		printf("SOCKET %s buffer on fd #%d: %d -> %d bytes (now %d) %s\n",
			type, fd, old_len, size, new_len,
			(new_len == size) ? "OK" : "FAILED");
}

/*
 * sock_send_buf
 *
 * Set socket's send buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void sock_send_buf(struct gnutella_socket *s, gint size, gboolean shrink)
{
	_sock_set(s->file_desc, SO_SNDBUF, size, "send", shrink);
}

/*
 * sock_recv_buf
 *
 * Set socket's receive buffer to specified size.
 * If `shrink' is false, refuse to shrink the buffer if its size is larger.
 */
void sock_recv_buf(struct gnutella_socket *s, gint size, gboolean shrink)
{
	_sock_set(s->file_desc, SO_RCVBUF, size, "receive", shrink);
}

/*
 * sock_nodelay
 *
 * Turn TCP_NODELAY on or off on the socket.
 */
void sock_nodelay(struct gnutella_socket *s, gboolean on)
{
	gint arg = on ? 1 : 0;

	if (-1 == setsockopt(s->file_desc, SOL_TCP, TCP_NODELAY, &arg, sizeof(arg)))
		g_warning("unable to %s TCP_NODELAY on fd#%d: %s",
			on ? "set" : "clear", s->file_desc, g_strerror(errno));
}

/*
 * sock_tx_shutdown
 *
 * Shutdown the TX side of the socket.
 */
void sock_tx_shutdown(struct gnutella_socket *s)
{
	if (-1 == shutdown(s->file_desc, SHUT_WR))
		g_warning("unable to shutdown TX on fd#%d: %s",
			s->file_desc, g_strerror(errno));
}

static void show_error(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

/*
 * The socks 4/5 code was taken from tsocks 1.16 Copyright (C) 2000 Shaun Clowes
 * It was modified to work with gtk_gnutella and non-blocking sockets. --DW
 */

int proxy_connect(int __fd, const struct sockaddr *__addr, guint __len)
{
	struct sockaddr_in *connaddr;
	void **kludge;
	struct sockaddr_in server;

	int rc = 0;


	if (!(inet_aton(ip_to_gchar(proxy_ip), &server.sin_addr))) {
		show_error("The SOCKS server (%s) in configuration "
				   "file is invalid\n", ip_to_gchar(proxy_ip));
	} else {
		/* Construct the addr for the socks server */
		server.sin_family = AF_INET;	/* host byte order */
		server.sin_port = htons(proxy_port);
		/* zero the rest of the struct */
		memset(&(server.sin_zero), 0, sizeof(server.sin_zero));
	}


	/* Ok, so this method sucks, but it's all I can think of */

	kludge = (void *) &__addr;
	connaddr = (struct sockaddr_in *) *kludge;

	rc = connect(__fd, (struct sockaddr *) &server,
				 sizeof(struct sockaddr));

	return rc;

}

struct socksent {
	struct in_addr localip;
	struct in_addr localnet;
	struct socksent *next;
} __attribute__((__packed__));

struct sockreq {
	int8_t version;
	int8_t command;
	int16_t dstport;
	int32_t dstip;
	/* A null terminated username goes here */
} __attribute__((__packed__));

struct sockrep {
	int8_t version;
	int8_t result;
	int16_t ignore1;
	int32_t ignore2;
} __attribute__((__packed__));

int send_socks(struct gnutella_socket *s)
{
	int rc = 0;
	int length = 0;
	char *realreq;
	struct passwd *user;
	struct sockreq *thisreq;


	/* Determine the current username */
	user = getpwuid(getuid());

	/* Allocate enough space for the request and the null */
	/* terminated username */
	length = sizeof(struct sockreq) +
		(user == NULL ? 1 : strlen(user->pw_name) + 1);
	if ((realreq = malloc(length)) == NULL) {
		/* Could not malloc, bail */
		exit(1);
	}
	thisreq = (struct sockreq *) realreq;

	/* Create the request */
	thisreq->version = 4;
	thisreq->command = 1;
	thisreq->dstport = htons(s->port);
	thisreq->dstip = htonl(s->ip);

	/* Copy the username */
	strcpy(realreq + sizeof(struct sockreq),
		   (user == NULL ? "" : user->pw_name));

	/* Send the socks header info */
	if ((rc = send(s->file_desc, (void *) thisreq, length, 0)) < 0) {
		show_error("Error attempting to send SOCKS request (%s)\n",
				   strerror(errno));
		rc = rc;
		return -1;
	}

	free(thisreq);

	return 0;

}

int recv_socks(struct gnutella_socket *s)
{
	int rc = 0;
	struct sockrep thisrep;

	if ((rc =
		 recv(s->file_desc, (void *) &thisrep, sizeof(struct sockrep),
			  0)) < 0) {
		show_error("Error attempting to receive SOCKS " "reply (%s)\n",
				   g_strerror(errno));
		rc = ECONNREFUSED;
	} else if (rc < sizeof(struct sockrep)) {
		show_error("Short reply from SOCKS server\n");
		/* Let the application try and see how they */
		/* go										*/
		rc = 0;
	} else if (thisrep.result == 91) {
		show_error("SOCKS server refused connection\n");
		rc = ECONNREFUSED;
	} else if (thisrep.result == 92) {
		show_error("SOCKS server refused connection "
				   "because of failed connect to identd "
				   "on this machine\n");
		rc = ECONNREFUSED;
	} else if (thisrep.result == 93) {
		show_error("SOCKS server refused connection "
				   "because identd and this library "
				   "reported different user-ids\n");
		rc = ECONNREFUSED;
	} else {
		rc = 0;
	}

	if (rc != 0) {
		errno = rc;
		return -1;
	}

	return 0;

}

int connect_http(struct gnutella_socket *s)
{
	int rc = 0;
	guint parsed;
	int status;
	guchar *str;

	switch (s->pos) {
	case 0:
		g_snprintf(s->buffer, sizeof(s->buffer),
			"CONNECT %s HTTP/1.0\r\n\r\n",
			ip_port_to_gchar(s->ip, s->port));
		if (
			(rc = send(s->file_desc, (void *)s->buffer,
				strlen(s->buffer), 0)) < 0
		) {
			show_error("Sending info to HTTP proxy failed: %s\n",
				g_strerror(errno));
			return -1;
		}
		s->pos++;
		break;
	case 1:
		rc = read(s->file_desc, s->buffer, sizeof(s->buffer)-1);
		if (rc < 0) {
			show_error("Receiving answer from HTTP proxy faild: %s\n",
				g_strerror(errno));
			return -1;
		}
		s->getline = getline_make();
		switch (getline_read(s->getline, s->buffer, rc, &parsed)) {
		case READ_OVERFLOW:
			show_error("Reading buffer overflow\n");
			return -1;
		case READ_DONE:
			if (rc != parsed)
				memmove(s->buffer, s->buffer+parsed, rc-parsed);
			rc -= parsed;
			break;
		case READ_MORE:
		default:
			g_assert(parsed == rc);
			return 0;
		}
		str = getline_str(s->getline);
		if ((status=http_status_parse(str, NULL, NULL, NULL, NULL)) < 0) {
			show_error("Bad status line\n");
			return -1;
		}
		if ((status/100) != 2) {
			show_error(str);
			return -1;
		}
		s->pos++;

		while (rc) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buffer, rc, &parsed)) {
			case READ_OVERFLOW:
				show_error("Reading buffer overflow\n");
				return -1;
			case READ_DONE:
				if (rc != parsed)
					memmove(s->buffer, s->buffer+parsed, rc-parsed);
				rc -= parsed;
				if (getline_length(s->getline) == 0) {
					s->pos++;
					getline_free(s->getline);
					s->getline = NULL;
					return 0;
				}
				break;
			case READ_MORE:
			default:
				g_assert(parsed == rc);
				return 0;
			}
		}
		break;
	case 2:
		rc = read(s->file_desc, s->buffer, sizeof(s->buffer)-1);
		if (rc < 0) {
			show_error("Receiving answer from HTTP proxy failed: %s\n",
				g_strerror(errno));
			return -1;
		}
		while (rc) {
			getline_reset(s->getline);
			switch (getline_read(s->getline, s->buffer, rc, &parsed)) {
			case READ_OVERFLOW:
				show_error("Reading buffer overflow\n");
				return -1;
			case READ_DONE:
				if (rc != parsed)
					memmove(s->buffer, s->buffer+parsed, rc-parsed);
				rc -= parsed;
				if (getline_length(s->getline) == 0) {
					s->pos++;
					getline_free(s->getline);
					s->getline = NULL;
					return 0;
				}
				break;
			case READ_MORE:
			default:
				g_assert(parsed == rc);
				return 0;
			}
		}
		break;
	}

	return 0;
}

/*
0: Send
1: Recv
.. 
4: Send
5: Recv

6: Done
*/

int connect_socksv5(struct gnutella_socket *s)
{
	int rc = 0;
	int offset = 0;
	char *verstring = "\x05\x02\x02\x00";
	char *uname, *upass;
	struct passwd *nixuser;
	char *buf;
	int sockid;

	sockid = s->file_desc;

	buf = (char *) s->buffer;

	switch (s->pos) {

	case 0:
		/* Now send the method negotiation */
		if ((rc = send(sockid, (void *) verstring, 4, 0)) < 0) {
			show_error("Sending SOCKS method negotiation failed: %s\n",
				g_strerror(errno));
			return (-1);
		}
		s->pos++;
		break;

	case 1:
		/* Now receive the reply as to which method we're using */
		if ((rc = recv(sockid, (void *) buf, 2, 0)) < 0) {
			show_error("Receiving SOCKS method negotiation reply failed: %s\n",
				g_strerror(errno));
			rc = ECONNREFUSED;
			return (rc);
		}

		if (rc < 2) {
			show_error("Short reply from SOCKS server\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		/* See if we offered an acceptable method */
		if (buf[1] == '\xff') {
			show_error("SOCKS server refused authentication methods\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		if (
			(unsigned short int) buf[1] == 2 &&
			socks_user && socks_user[0]		/* has provided user info */
		)
			s->pos++;
		else
			s->pos += 3;
		break;
	case 2:
		/* If the socks server chose username/password authentication */
		/* (method 2) then do that */


		/* Determine the current *nix username */
		nixuser = getpwuid(getuid());

		if (((uname = socks_user) == NULL) &&
			((uname =
			  (nixuser == NULL ? NULL : nixuser->pw_name)) == NULL)) {
			show_error("No Username to authenticate with.\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		if (((upass = socks_pass) == NULL)) {
			show_error("No Password to authenticate with.\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		offset = 0;
		buf[offset] = '\x01';
		offset++;
		buf[offset] = (int8_t) strlen(uname);
		offset++;
		memcpy(&buf[offset], uname, strlen(uname));
		offset = offset + strlen(uname);
		buf[offset] = (int8_t) strlen(upass);
		offset++;
		memcpy(&buf[offset], upass, strlen(upass));
		offset = offset + strlen(upass);

		/* Send out the authentication */
		if ((rc = send(sockid, (void *) buf, offset, 0)) < 0) {
			show_error("Sending SOCKS authentication failed: %s\n",
				g_strerror(errno));
			return (-1);
		}

		s->pos++;

		break;
	case 3:
		/* Receive the authentication response */
		if ((rc = recv(sockid, (void *) buf, 2, 0)) < 0) {
			show_error("Receiving SOCKS authentication reply failed: %s\n",
				g_strerror(errno));
			rc = ECONNREFUSED;
			return (rc);
		}

		if (rc < 2) {
			show_error("Short reply from SOCKS server\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		if (buf[1] != '\x00') {
			show_error("SOCKS authentication failed, "
					   "check username and password\n");
			rc = ECONNREFUSED;
			return (rc);
		}
		s->pos++;
		break;
	case 4:
		/* Now send the connect */
		buf[0] = '\x05';		/* Version 5 SOCKS */
		buf[1] = '\x01';		/* Connect request */
		buf[2] = '\x00';		/* Reserved		*/
		buf[3] = '\x01';		/* IP version 4	*/
		*(guint32 *)(buf + 4) = htonl(s->ip);
		*(guint16 *)(buf + 8) = htons(s->port);

		/* Now send the connection */
		if ((rc = send(sockid, (void *) buf, 10, 0)) <= 0) {
			show_error("Send SOCKS connect command failed: %s\n",
				g_strerror(errno));
			return (-1);
		}

		s->pos++;
		break;
	case 5:
		/* Now receive the reply to see if we connected */
		if ((rc = recv(sockid, (void *) buf, 10, 0)) < 0) {
			show_error("Receiving SOCKS connection reply failed: %s\n",
				g_strerror(errno));
			rc = ECONNREFUSED;
			return (rc);
		}
		if (dbg) printf("connect_socksv5: Step 5, bytes recv'd %i\n", rc);
		if (rc < 10) {
			show_error("Short reply from SOCKS server\n");
			rc = ECONNREFUSED;
			return (rc);
		}

		/* See the connection succeeded */
		if (buf[1] != '\x00') {
			show_error("SOCKS connect failed: ");
			switch ((int8_t) buf[1]) {
			case 1:
				show_error("General SOCKS server failure\n");
				return (ECONNABORTED);
			case 2:
				show_error("Connection denied by rule\n");
				return (ECONNABORTED);
			case 3:
				show_error("Network unreachable\n");
				return (ENETUNREACH);
			case 4:
				show_error("Host unreachable\n");
				return (EHOSTUNREACH);
			case 5:
				show_error("Connection refused\n");
				return (ECONNREFUSED);
			case 6:
				show_error("TTL Expired\n");
				return (ETIMEDOUT);
			case 7:
				show_error("Command not supported\n");
				return (ECONNABORTED);
			case 8:
				show_error("Address type not supported\n");
				return (ECONNABORTED);
			default:
				show_error("Unknown error\n");
				return (ECONNABORTED);
			}
		}

		s->pos++;

		break;
	}

	return (0);

}

/* vi: set ts=4: */
