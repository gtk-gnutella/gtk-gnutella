/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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

#if defined(USE_IP_TOS) && defined(I_NETINET_IP)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include "sockets.h"
#include "downloads.h"
#include "uploads.h"
#include "parq.h"
#include "nodes.h"
#include "header.h"
#include "bsched.h"
#include "ban.h"
#include "http.h"
#include "settings.h"
#include "inet.h"
#include "walloc.h"
#include "adns.h"
#include "hostiles.h"
#include "pproxy.h"

#ifdef USE_REMOTE_CTRL
#include "shell.h"
#endif

RCSID("$Id$");

#ifndef SHUT_WR
#define SHUT_WR 1		/* Shutdown TX side */
#endif

#define RQST_LINE_LENGTH	256		/* Reasonable estimate for request line */

#define SOCK_ADNS_PENDING	1	/* Prevents free()ing the socket too early */
#define SOCK_ADNS_FAILED	2	/* Indicates an error in the ADNS callback */

static gboolean ip_computed = FALSE;

static GSList *sl_incoming = (GSList *) NULL;	/* To spot inactive sockets */

static void guess_local_ip(int sd);
static void socket_destroy(struct gnutella_socket *s, gchar *reason);

/* 
 * SOL_TCP and SOL_IP aren't standards. Some platforms define them, on
 * some it's safe to assume they're the same as IPPROTO_*, but the
 * only way to be portably safe is to use protoent functions.
 *
 * If the user changes /etc/protocols while running gtkg, things may
 * go badly.
 */
static gboolean sol_got = FALSE;
static gint sol_tcp_cached = -1;
static gint sol_ip_cached = -1;

static void get_sol(void)
{
	struct protoent *pent;

	pent = getprotobyname("tcp");
	if (NULL != pent)
		sol_tcp_cached = pent->p_proto;
	pent = getprotobyname("ip");
	if (NULL != pent)
		sol_ip_cached = pent->p_proto;
	sol_got = TRUE;
}

static gint sol_tcp(void)
{
	if (!sol_got) /* FIXME: This should be done in socket_init() */
		get_sol();
	return sol_tcp_cached;
}

#ifdef USE_IP_TOS
  
static gint sol_ip(void)
{
	if (!sol_got) /* FIXME: This should be done in socket_init() */
		get_sol();
	return sol_ip_cached;
}

/*
 * socket_tos
 *
 * Set the TOS on the socket.  Routers can use this information to
 * better route the IP datagrams.
 */
static void socket_tos(struct gnutella_socket *s, gint tos)
{
	if (!use_ip_tos)
		return;
		
	if (
		-1 == setsockopt(s->file_desc, sol_ip(),
				IP_TOS, (gpointer) &tos, sizeof(tos))
	) {
		const gchar *tosname = "default";

		switch (tos) {
			case 0: break;
			case IPTOS_LOWDELAY: tosname = "low delay"; break;
			case IPTOS_THROUGHPUT: tosname = "throughput"; break;
			default:
				g_assert_not_reached();
		}
		g_warning("unable to set IP_TOS to %s (%d) on fd#%d: %s",
			tosname, tos, s->file_desc, g_strerror(errno));
	}
}

/*
 * socket_tos_normal
 * 
 * Set the Type of Service (TOS) field to "normal."
 */
static void socket_tos_normal(struct gnutella_socket *s)
{
	socket_tos(s, 0);
}

/*
 * socket_tos_lowdelay
 *
 * Set the Type of Service (TOS) field to "lowdelay." This may cause
 * your host and/or any routers along the path to put its packets in
 * a higher-priority queue, and/or to route them along the lowest-
 * latency path without regard for bandwidth.
 */
static void socket_tos_lowdelay(struct gnutella_socket *s)
{
	socket_tos(s, IPTOS_LOWDELAY);
}

/*
 * socket_tos_throughput
 *
 * Set the Type of Service (TOS) field to "throughput." This may cause
 * your host and/or any routers along the path to put its packets in
 * a lower-priority queue, and/or to route them along the highest-
 * bandwidth path without regard for latency.
 */
static void socket_tos_throughput(struct gnutella_socket *s)
{
	socket_tos(s, IPTOS_THROUGHPUT);
}

/*
 * socket_tos_default
 *
 * Pick an appropriate default TOS for packets on the socket, based
 * on the socket's type.
 */
void socket_tos_default(struct gnutella_socket *s)
{
	switch (s->type) {
	case SOCK_TYPE_CONTROL:
	case SOCK_TYPE_DOWNLOAD: /* ACKs w/ low latency => higher transfer rates */
	case SOCK_TYPE_HTTP:
	case SOCK_TYPE_PPROXY:
		socket_tos_lowdelay(s);
		break;
	case SOCK_TYPE_UPLOAD:
		socket_tos_throughput(s);
		break;
	default:
		socket_tos_normal(s);
	}
}
#else
void socket_tos_default(struct gnutella_socket *s)
{
	/* Empty */
}
#endif /* USE_IP_TOS */


/*
 * socket_timer
 *
 * Called by main timer.
 * Expires inactive sockets.
 */
void socket_timer(time_t now)
{
	GSList *l;
	GSList *to_remove = NULL;

	for (l = sl_incoming; l; l = g_slist_next(l)) {
		struct gnutella_socket *s = (struct gnutella_socket *) l->data;
		g_assert(s->last_update);
		/*
		 * Last_update can be in the feature due to parq. This is needed
		 * to avoid dropping the connection
		 */
		if (now - s->last_update > (gint32) incoming_connecting_timeout) {
			if (dbg) {
				g_warning("connection from %s timed out (%d bytes read)",
						  ip_to_gchar(s->ip), s->pos);
				if (s->pos > 0)
					dump_hex(stderr, "Connection Header",
						s->buffer, MIN(s->pos, 80));
			}
			to_remove = g_slist_prepend(to_remove, s);
		}
	}

	for (l = to_remove; l; l = g_slist_next(l)) {
		struct gnutella_socket *s = (struct gnutella_socket *) l->data;
		socket_destroy(s, "Connection timeout");
	}

	g_slist_free(to_remove);
}

void socket_shutdown(void)
{
	while (sl_incoming)
		socket_destroy((struct gnutella_socket *) sl_incoming->data, NULL);
}

/* ----------------------------------------- */

/*
 * socket_destroy
 *
 * Destroy a socket.
 *
 * If there is an attached resource, call the resource's termination routine
 * with the supplied reason.
 */
static void socket_destroy(struct gnutella_socket *s, gchar *reason)
{
	g_assert(s);

	/*
	 * If there is an attached resource, its removal routine is responsible
	 * for calling back socket_free().
	 */

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		if (s->resource.node) {
			node_remove(s->resource.node, reason);
			return;
		}
		break;
	case SOCK_TYPE_DOWNLOAD:
		if (s->resource.download) {
			download_stop(s->resource.download, GTA_DL_ERROR, reason);
			return;
		}
		break;
	case SOCK_TYPE_UPLOAD:
		if (s->resource.upload) {
			upload_remove(s->resource.upload, reason);
			return;
		}
		break;
	case SOCK_TYPE_PPROXY:
		if (s->resource.pproxy) {
			pproxy_remove(s->resource.pproxy, reason);
			return;
		}
		break;
	case SOCK_TYPE_HTTP:
		if (s->resource.handle) {
			http_async_error(s->resource.handle, HTTP_ASYNC_IO_ERROR);
			return;
		}
		break;
	default:
		break;
	}

	/*
	 * No attached resource, we can simply free this socket then.
	 */

	socket_free(s);
}

/*
 * socket_free
 *
 * Dispose of socket, closing connection, removing input callback, and
 * reclaiming attached getline buffer.
 */
void socket_free(struct gnutella_socket *s)
{
	g_assert(s);

	if (s->last_update) {
		g_assert(sl_incoming);
		sl_incoming = g_slist_remove(sl_incoming, s);
		s->last_update = 0;
	}
	if (s->gdk_tag) {
		g_source_remove(s->gdk_tag);
		s->gdk_tag = 0;
	}
	if (s->adns & SOCK_ADNS_PENDING) {
		s->type = SOCK_TYPE_DESTROYING;
		return;
	}
	if (s->getline) {
		getline_free(s->getline);
		s->getline = NULL;
	}
	if (s->file_desc != -1) {
		if (s->corked)
			sock_cork(s, FALSE);
		close(s->file_desc);
		s->file_desc = -1;
	}
	wfree(s, sizeof(*s));
}

/* ----------------------------------------- */

/* 
 * socket_read:
 *
 * Used for incoming connections, for outgoing too??
 * Read bytes on an unknown incoming socket. When the first line
 * has been read it's decided on what type cof connection this is.
 * If the first line is not complete on the first call, this function
 * will be called as often as necessary to fetch a full line.
 */

static void socket_read(gpointer data, gint source, inputevt_cond_t cond)
{
	gint r;
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	guint count;
	gint parsed;
	gchar *first;

	/* s->type = 0; */

	if (cond & INPUT_EVENT_EXCEPTION) {
		socket_destroy(s, "Input exception");
		return;
	}

	g_assert(s->pos == 0);		/* We read a line, then leave this callback */
	
	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("socket_read(): incoming buffer full, disconnecting from %s",
			 ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		socket_destroy(s, "Incoming buffer full");
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
		socket_destroy(s, "Got EOF");
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		socket_destroy(s, "Read error");
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
			http_send_status(s, 414, FALSE, NULL, 0, "Requested URL Too Large");
		socket_destroy(s, "Requested URL too large");
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

	g_source_remove(s->gdk_tag);
	s->gdk_tag = 0;
	sl_incoming = g_slist_remove(sl_incoming, s);
	s->last_update = 0;

	first = getline_str(s->getline);

	/*
	 * Always authorize replies for our PUSH requests.
	 * Likewise for PARQ download resuming.
	 */

	if (0 == strncmp(first, "GIV ", 4)) {
		download_push_ack(s);
		return;
	}

	if (0 == strncmp(first, "QUEUE ", 6)) {
		parq_download_queue_ack(s);
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
	case BAN_MSG:				/* Send specific 403 error message */
		{
			gchar *msg = ban_message(s->ip);

			g_warning("rejecting connection from banned %s (%s still): %s",
				ip_to_gchar(s->ip), short_time(ban_delay(s->ip)), msg);

			if (0 == strncmp(first, GNUTELLA_HELLO, GNUTELLA_HELLO_LENGTH))
				send_node_error(s, 403, msg);
			else
				http_send_status(s, 403, FALSE, NULL, 0, msg);
		}
		goto cleanup;
	case BAN_FIRST:				/* Connection refused, negative ack */
		if (0 == strncmp(first, GNUTELLA_HELLO, GNUTELLA_HELLO_LENGTH))
			send_node_error(s, 550, "Banned for %s",
				short_time(ban_delay(s->ip)));
		else {
			gint delay = ban_delay(s->ip);
			gchar msg[80];
			http_extra_desc_t hev;

			gm_snprintf(msg, sizeof(msg)-1, "Retry-After: %d\r\n", delay);

			hev.he_type = HTTP_EXTRA_LINE;
			hev.he_msg = msg;

			http_send_status(s, 550, FALSE, &hev, 1, "Banned for %s",
				short_time(delay));
		}
		goto cleanup;
	default:
		g_assert(0);			/* Not reached */
	}

	/*
	 * Check for PARQ banning.
	 * 		-- JA, 29/07/2003
	 */
	 
	if (parq_is_banned_source(s->ip)) {
		if (dbg)
			g_warning("[sockets] PARQ has banned ip %s", ip_to_gchar(s->ip));
		ban_force(s);
		goto cleanup;
	}

	/*
	 * Deny connections from hostile IP addresses.
	 *
	 * We do this after banning checks so that if they hammer us, they
	 * get banned silently.
	 */

	if (hostiles_check(s->ip)) {
		gchar *msg = "Hostile IP address banned";

		g_warning("denying connection from hostile %s: \"%s\"",
			ip_to_gchar(s->ip), first);
		if (0 == strncmp(first, GNUTELLA_HELLO, GNUTELLA_HELLO_LENGTH))
			send_node_error(s, 550, msg);
		else
			http_send_status(s, 550, FALSE, NULL, 0, msg);
		goto cleanup;
	}

	/*
	 * Dispatch request. Here we decide what kind of connection this is.
	 */

	if (0 == strncmp(first, GNUTELLA_HELLO, GNUTELLA_HELLO_LENGTH))
		node_add_socket(s, s->ip, s->port);	/* Incoming control connection */
	else if (
		0 == strncmp(first, "GET ", 4) ||
		0 == strncmp(first, "HEAD ", 5)
	) {
		gchar *uri;

		/*
		 * We have to decide whether this is an upload request or a
		 * push-proxyfication request.
		 *
		 * In the following code, since sizeof("GET") accounts for the
		 * trailing NUL, we will skip the space after the request type.
		 */

		uri = first + ((first[0] == 'G') ? sizeof("GET") : sizeof("HEAD"));
		while (*uri == ' ' || *uri == '\t')
			uri++;

		if (
			0 == strncmp(uri, "/gnutella/", 10) ||
			0 == strncmp(uri, "/gnet/", 6)
		)
			pproxy_add(s);
		else
			upload_add(s);
	}
#ifdef USE_REMOTE_CTRL
	else if (0 == strncmp(first, "HELO ", 5))
        shell_add(s);
#endif
    else
		goto unknown;

	/* Socket might be free'ed now */

	return;

unknown:
	if (dbg) {
		gint len = getline_length(s->getline);
		g_warning("socket_read(): got unknown incoming connection from %s, "
			"dropping!", ip_to_gchar(s->ip));
		if (len > 0)
			dump_hex(stderr, "First Line", first, MIN(len, 160));
	}
	if (strstr(first, "HTTP"))
		http_send_status(s, 501, FALSE, NULL, 0, "Method Not Implemented");
	/* FALL THROUGH */

cleanup:
	socket_destroy(s, NULL);
}

/*
 * socket_connected:
 *
 * Used for outgoing connections!
 * Called when a socket is connected. Checks type of connection and hands
 * control over the connetion over to more specialized handlers. If no
 * handler was found the connection is terminated.
 * This is the place to hook up handlers for new communication types.
 * So far there are CONTROL, UPLOAD, DOWNLOAD and HTTP handlers.
 */
static void socket_connected(gpointer data, gint source, inputevt_cond_t cond)
{
	/* We are connected to somebody */

	struct gnutella_socket *s = (struct gnutella_socket *) data;

	if (cond & INPUT_EVENT_EXCEPTION) {	/* Error while connecting */
		if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download)
			download_fallback_to_push(s->resource.download, FALSE, FALSE);
		else
			socket_destroy(s, "Connection failed");
		return;
	}

	if (cond & INPUT_EVENT_READ) {
		if (
			proxy_protocol != PROXY_NONE
			&& s->direction == SOCK_CONN_PROXY_OUTGOING
		) {
			g_source_remove(s->gdk_tag);
			s->gdk_tag = 0;

			if (proxy_protocol == PROXY_SOCKSV4) {
				if (recv_socks(s) != 0) {
					socket_destroy(s, "Error receiving from SOCKS 4 proxy");
					return;
				}

				s->direction = SOCK_CONN_OUTGOING;

				s->gdk_tag =
					inputevt_add(s->file_desc,
								  INPUT_EVENT_READ | INPUT_EVENT_WRITE |
								  INPUT_EVENT_EXCEPTION, socket_connected,
								  (gpointer) s);
				return;
			} else if (proxy_protocol == PROXY_SOCKSV5) {
				if (connect_socksv5(s) != 0) {
					socket_destroy(s, "Error conneting to SOCKS 5 proxy");
					return;
				}

				if (s->pos > 5) {
					s->direction = SOCK_CONN_OUTGOING;

					s->gdk_tag =
						inputevt_add(s->file_desc,
									  INPUT_EVENT_READ | INPUT_EVENT_WRITE |
									  INPUT_EVENT_EXCEPTION,
									  socket_connected, (gpointer) s);

					return;
				} else
					s->gdk_tag =
						inputevt_add(s->file_desc,
									  INPUT_EVENT_WRITE |
									  INPUT_EVENT_EXCEPTION,
									  socket_connected, (gpointer) s);

				return;

			} else if (proxy_protocol == PROXY_HTTP) {
				if (connect_http(s) != 0) {
					socket_destroy(s, "Unable to connect to HTTP proxy");
					return;
				}

				if (s->pos > 2) {
					s->direction = SOCK_CONN_OUTGOING;

					s->gdk_tag =
						inputevt_add(s->file_desc,
									  INPUT_EVENT_READ | INPUT_EVENT_WRITE |
									  INPUT_EVENT_EXCEPTION,
									  socket_connected, (gpointer) s);
					return;
				} else {
					s->gdk_tag =
						inputevt_add(s->file_desc,
									  INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
									  socket_connected, (gpointer) s);
					return;
				}
			}
		}
	}

	if (cond & INPUT_EVENT_WRITE) {
		/* We are just connected to our partner */
		gint res, option, size = sizeof(gint);

		g_source_remove(s->gdk_tag);
		s->gdk_tag = 0;

		/* Check whether the socket is really connected */

		res = getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR,
					   (void *) &option, &size);

		if (res == -1 || option) {
			if (s->type == SOCK_TYPE_DOWNLOAD && s->resource.download)
				download_fallback_to_push(s->resource.download, FALSE, FALSE);
			else
				socket_destroy(s, "Connection failed");
			return;
		}

		if (proxy_protocol != PROXY_NONE
			&& s->direction == SOCK_CONN_PROXY_OUTGOING) {
			if (proxy_protocol == PROXY_SOCKSV4) {

				if (send_socks(s) != 0) {
					socket_destroy(s, "Error sending to SOCKS 4 proxy");
					return;
				}
			} else if (proxy_protocol == PROXY_SOCKSV5) {
				if (connect_socksv5(s) != 0) {
					socket_destroy(s, "Error connecting to SOCKS 5 proxy");
					return;
				}

			} else if (proxy_protocol == PROXY_HTTP) {
				if (connect_http(s) != 0) {
					socket_destroy(s, "Error connecting to HTTP proxy");
					return;
				}
			}

			s->gdk_tag =
				inputevt_add(s->file_desc,
							  INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
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
				upload_connect_conf(u);
			}
			break;

		case SOCK_TYPE_HTTP:
			http_async_connected(s->resource.handle);
			break;

		case SOCK_TYPE_CONNBACK:
			node_connected_back(s);
			break;

#ifdef USE_REMOTE_CTRL
        case SOCK_TYPE_SHELL:
            g_assert_not_reached(); /* FIXME: add code here? */
            break;
#endif

		default:
			g_warning("socket_connected(): Unknown socket type %d !", s->type);
			socket_destroy(s, NULL);		/* ? */
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
		ip = ntohl(addr.sin_addr.s_addr);

		/*
		 * If local IP was unknown, keep what we got here, even if it's a
		 * private IP. Otherwise, we discard private IPs unless the previous
		 * IP was private.
		 *		--RAM, 17/05/2002
		 */

		can_supersede = !is_private_ip(ip) || is_private_ip(local_ip);

		if (!ip_computed) {
			if (!local_ip || can_supersede)
				gnet_prop_set_guint32_val(PROP_LOCAL_IP, ip);
			ip_computed = TRUE;
		} else if (can_supersede)
			gnet_prop_set_guint32_val(PROP_LOCAL_IP, ip);
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

	return ntohs(addr.sin_port);
}

/*
 * socket_accept
 *
 * Someone is connecting to us.
 */
static void socket_accept(gpointer data, gint source,
						  inputevt_cond_t cond)
{
	struct sockaddr_in addr;
	gint sd, len = sizeof(struct sockaddr_in);
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	struct gnutella_socket *t = NULL;

	if (cond & INPUT_EVENT_EXCEPTION) {
		g_warning("Input Exception for listening socket #%d !!!!\n",
				  s->file_desc);
		gtk_gnutella_exit(2);
		return;
	}

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		break;
	default:
		g_warning("socket_accept(): Unknown listening socket type %d !\n",
				  s->type);
		socket_destroy(s, NULL);
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

	t = (struct gnutella_socket *) walloc0(sizeof(struct gnutella_socket));

	t->file_desc = sd;
	t->ip = ntohl(addr.sin_addr.s_addr);
	t->port = ntohs(addr.sin_port);
	t->direction = SOCK_CONN_INCOMING;
	t->type = s->type;
	t->local_port = s->local_port;
	t->getline = getline_make(MAX_LINE_SIZE);

	switch (s->type) {
	case SOCK_TYPE_CONTROL:
		t->gdk_tag =
			inputevt_add(sd, INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
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
 * socket_connect_prepare
 *
 * Called to prepare the creation of the socket connection.
 * Returns NULL in case of failure.
 */
static struct gnutella_socket *socket_connect_prepare(
	guint16 port, enum socket_type type)
{	
	struct gnutella_socket *s;
	gint sd, option = 1;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1) {
		g_warning("Unable to create a socket (%s)", g_strerror(errno));
		return NULL;
	}

	s = (struct gnutella_socket *) walloc0(sizeof(struct gnutella_socket));

	s->type = type;
	s->direction = SOCK_CONN_OUTGOING;
	s->file_desc = sd;
	s->port = port;

	setsockopt(s->file_desc, SOL_SOCKET, SO_KEEPALIVE, (void *) &option,
			   sizeof(option));
	setsockopt(s->file_desc, SOL_SOCKET, SO_REUSEADDR, (void *) &option,
			   sizeof(option));

	/* Set the file descriptor non blocking */
	fcntl(s->file_desc, F_SETFL, O_NONBLOCK);

	socket_tos_default(s);
	return s;
}

/*
 * socket_connect_finalize
 *
 * Called to finalize the creation of the socket connection, which is done
 * in two steps since DNS resolving is asynchronous.
 */
static struct gnutella_socket *socket_connect_finalize(
	struct gnutella_socket *s, guint32 ip_addr)
{
	gint res = 0;
	struct sockaddr_in addr;

	g_assert(NULL != s);

	s->ip = ip_addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(s->ip);
	addr.sin_port = htons(s->port);

	inet_connection_attempted(s->ip);

	/*
	 * Now we check if we're forcing a local IP, and make it happen if so.
	 *   --JSL
	 */
	if (force_local_ip) {
		struct sockaddr_in lcladdr;

		memset(&lcladdr, 0, sizeof(lcladdr));
		lcladdr.sin_family = AF_INET;
		lcladdr.sin_addr.s_addr = htonl(forced_local_ip);
		lcladdr.sin_port = htons(0);

		/*
		 * Note: we ignore failures: it will be automatic at connect()
		 * It's useful only for people forcing the IP without being
		 * behind a masquerading firewall --RAM.
		 */
		(void) bind(s->file_desc, (struct sockaddr *) &lcladdr,
			sizeof(struct sockaddr_in));
	}

	if (proxy_protocol != PROXY_NONE) {
		struct sockaddr_in lcladdr;

		memset(&lcladdr, 0, sizeof(lcladdr));
		lcladdr.sin_family = AF_INET;
		lcladdr.sin_port = INADDR_ANY;

		(void) bind(s->file_desc, (struct sockaddr *) &lcladdr,
			sizeof(struct sockaddr_in));

		s->direction = SOCK_CONN_PROXY_OUTGOING;
		res = proxy_connect(s->file_desc, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_in));
	} else
		res = connect(s->file_desc, (struct sockaddr *) &addr,
			sizeof(struct sockaddr_in));

	if (res == -1 && errno != EINPROGRESS) {
		g_warning("Unable to connect to %s: (%s)",
			ip_port_to_gchar(s->ip, s->port), g_strerror(errno));
	
		if (s->adns & SOCK_ADNS_PENDING)
			s->adns_msg = "Connection failed";
		else
			socket_destroy(s, "Connection failed");
		return NULL;
	}

	s->local_port = socket_local_port(s);

	/* Set the file descriptor non blocking */
	fcntl(s->file_desc, F_SETFL, O_NONBLOCK);

	g_assert(0 == s->gdk_tag);

	if (proxy_protocol != PROXY_NONE)
		s->gdk_tag = inputevt_add(s->file_desc,
			INPUT_EVENT_READ | INPUT_EVENT_WRITE | INPUT_EVENT_EXCEPTION,
			socket_connected, s);
	else
		s->gdk_tag = inputevt_add(s->file_desc,
			INPUT_EVENT_WRITE | INPUT_EVENT_EXCEPTION,
			socket_connected, s);

	return s;
}

/*
 * socket_connect
 *
 * Creates a connected socket with an attached resource of `type'.
 *
 * Connection happens in the background, the connection callback being
 * determined by the resource type.
 */
struct gnutella_socket *socket_connect(
	guint32 ip_addr, guint16 port, enum socket_type type)
{
	/* Create a socket and try to connect it to ip:port */

	struct gnutella_socket *s;
	
	s = socket_connect_prepare(port, type);
	g_return_val_if_fail(NULL != s, NULL);
	return socket_connect_finalize(s, ip_addr);
}

/*
 * socket_connect_by_name_helper
 *
 * Called when we got a reply from the ADNS process.
 */
static void socket_connect_by_name_helper(guint32 ip_addr, gpointer user_data)
{
	struct gnutella_socket *s = user_data;

	g_assert(NULL != s);

	if (0 == ip_addr || s->type == SOCK_TYPE_DESTROYING) {
		s->adns &= ~SOCK_ADNS_PENDING;
		s->adns |= SOCK_ADNS_FAILED;
		s->adns_msg = "Could not resolve address";
		return; 
	}
	if (NULL == socket_connect_finalize(s, ip_addr)) {
		s->adns &= ~SOCK_ADNS_PENDING;
		s->adns |= SOCK_ADNS_FAILED;
		return;
	}
	s->adns &= ~SOCK_ADNS_PENDING;
}

/*
 * socket_connect_by_name
 *
 * Like socket_connect() but the remote address is not known and must be
 * resolved through async DNS calls.
 */
struct gnutella_socket *socket_connect_by_name(
	const gchar *host, guint16 port, enum socket_type type)
{
	/* Create a socket and try to connect it to host:port */

	struct gnutella_socket *s;

	g_assert(NULL != host);
	s = socket_connect_prepare(port, type);
	g_return_val_if_fail(NULL != s, NULL);
	s->adns |= SOCK_ADNS_PENDING;
	if (
		!adns_resolve(host, &socket_connect_by_name_helper, s)
		&& (s->adns & SOCK_ADNS_FAILED)
	) {
		/*	socket_connect_by_name_helper() was already invoked! */
		if (dbg > 0)
			g_warning("socket_connect_by_name: "
				"adns_resolve() failed in synchronous mode");
		socket_destroy(s, s->adns_msg);
		return NULL;
	}

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

	s = (struct gnutella_socket *) walloc0(sizeof(struct gnutella_socket));

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
	addr.sin_addr.s_addr = ip ? htonl(ip) : INADDR_ANY;
	addr.sin_port = htons(port);

	/* bind() the socket */

	if (bind(sd, (struct sockaddr *) &addr, l) == -1) {
		g_warning("Unable to bind() the socket on port %u (%s)",
				  port, g_strerror(errno));
		socket_destroy(s, "Unable to bind socket");
		return NULL;
	}

	/* listen() the socket */

	if (listen(sd, 5) == -1) {
		g_warning("Unable to listen() the socket (%s)", g_strerror(errno));
		socket_destroy(s, "Unable to listen on socket");
		return NULL;
	}

	/* Get the port of the socket, if needed */

	if (!port) {
		option = sizeof(struct sockaddr_in);

		if (getsockname(sd, (struct sockaddr *) &addr, &option) == -1) {
			g_warning("Unable to get the port of the socket: "
				"getsockname() failed (%s)", g_strerror(errno));
			socket_destroy(s, "Can't probe socket for port");
			return NULL;
		}

		s->local_port = ntohs(addr.sin_port);
	} else
		s->local_port = port;

	s->gdk_tag =
		inputevt_add(sd, INPUT_EVENT_READ | INPUT_EVENT_EXCEPTION,
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

	if (-1 == setsockopt(s->file_desc, sol_tcp(), TCP_CORK, &arg, sizeof(arg)))
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

/* XXX needs to add metaconfig test */
#if linux
	old_len >>= 1;		/* Linux returns twice the real amount */
#endif

	if (!shrink && old_len >= size) {
		if (dbg > 5)
			printf("socket %s buffer on fd #%d NOT shrank to %d bytes (is %d)\n",
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
		printf("socket %s buffer on fd #%d: %d -> %d bytes (now %d) %s\n",
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

	if (
		-1 == setsockopt(s->file_desc, sol_tcp(), TCP_NODELAY,
				&arg, sizeof(arg))
	) {
		g_warning("unable to %s TCP_NODELAY on fd#%d: %s",
			on ? "set" : "clear", s->file_desc, g_strerror(errno));
	}
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

int proxy_connect(int fd, const struct sockaddr *addr, guint len)
{
	struct sockaddr_in *connaddr;
	void **kludge;
	struct sockaddr_in server;

	int rc = 0;


	if (!inet_aton(ip_to_gchar(proxy_ip), &server.sin_addr)) {
		show_error("The SOCKS server (%s) in configuration "
				   "file is invalid\n", ip_to_gchar(proxy_ip));
	} else {
		/* Construct the addr for the socks server */
		server.sin_family = AF_INET;	/* host byte order */
		server.sin_port = htons(proxy_port);
		/* zero the rest of the struct */
		memset(&server.sin_zero, 0, sizeof(server.sin_zero));
	}


	/* Ok, so this method sucks, but it's all I can think of */

	kludge = (void *) &addr;
	connaddr = (struct sockaddr_in *) *kludge;

	rc = connect(fd, (struct sockaddr *) &server, sizeof(struct sockaddr));

	return rc;

}

struct socksent {
	struct in_addr localip;
	struct in_addr localnet;
	struct socksent *next;
} __attribute__((__packed__));

struct sockreq {
	gint8 version;
	gint8 command;
	gint16 dstport;
	gint32 dstip;
	/* A null terminated username goes here */
} __attribute__((__packed__));

struct sockrep {
	gint8 version;
	gint8 result;
	gint16 ignore1;
	gint32 ignore2;
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
	gint parsed;
	int status;
	gchar *str;

	switch (s->pos) {
	case 0:
		gm_snprintf(s->buffer, sizeof(s->buffer),
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
		s->getline = getline_make(HEAD_MAX_SIZE);
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
	const char *verstring = "\x05\x02\x02\x00";
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
		buf[offset] = (gint8) strlen(uname);
		offset++;
		memcpy(&buf[offset], uname, strlen(uname));
		offset = offset + strlen(uname);
		buf[offset] = (gint8) strlen(upass);
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
			switch ((gint8) buf[1]) {
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
