
/* Socket management */

#include "gnutella.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

guint32 local_ip = 0;

/* ------------------------------------------------------------------------------------------------ */

/* Destroy a socket, a free its resource if needed */

void socket_destroy(struct gnutella_socket *s)
{
	g_return_if_fail(s);

	if (s->type == GTA_TYPE_CONTROL && s->resource.node)
	{
		node_remove(s->resource.node, NULL);
		return;
	}
	else if (s->type == GTA_TYPE_DOWNLOAD && s->resource.download)
	{
/*		printf("socket_remove(): removing download %s first \n", s->resource.download->file_name); */
		download_stop(s->resource.download, GTA_DL_ERROR, NULL);
		return;
	}
	else if (s->type == GTA_TYPE_UPLOAD && s->resource.upload)
	{
		upload_remove(s->resource.upload, NULL);
		return;
	}

	if (s->gdk_tag)   gdk_input_remove(s->gdk_tag);
	if (s->file_desc) close(s->file_desc);

	g_free(s);
}

/* ------------------------------------------------------------------------------------------------ */

/* Read bytes on an unknown incoming socket */

void socket_read(gpointer data, gint source, GdkInputCondition cond)
{
	gint r;
	struct gnutella_socket *s = (struct gnutella_socket *) data;

	if (cond & GDK_INPUT_EXCEPTION) { socket_destroy(s); return; }

	r = read(s->file_desc, s->buffer + s->pos, sizeof(s->buffer) - s->pos);

	if (r == 0) { socket_destroy(s); return; }
	else if (r < 0 && errno == EAGAIN) return;
	else if (r < 0) { socket_destroy(s); return; }

	s->pos += r;

	if (strchr(s->buffer, '\n')) /* We have got at least a line */
	{

		if (!strncmp(s->buffer, gnutella_hello, 17)) /* This is an incoming control connection */
		{
			struct gnutella_node *n;

			gdk_input_remove(s->gdk_tag);
			s->gdk_tag = 0;
			s->pos = 0;

			n = node_add(s, s->ip, s->port);

			if (n) s->gdk_tag = gdk_input_add(s->file_desc, (GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION, node_read, (gpointer) n);
		}
		else
		{
			g_warning("socket_read(): Got an unknown incoming connection, dropping it.\n");

			socket_destroy(s);
		}
	}
}

/* ----- Sockets connection ----------------------------------------------------------------------- */

void socket_connected(gpointer data, gint source, GdkInputCondition cond)
{
	/* We are connected to somebody */

	struct gnutella_socket *s = (struct gnutella_socket *) data;

	if (cond & GDK_INPUT_EXCEPTION)	/* Error while connecting */
	{
		if (s->type == GTA_TYPE_CONTROL && s->resource.node) node_remove(s->resource.node, "Connection failed");
		else if (s->type == GTA_TYPE_DOWNLOAD && s->resource.download) download_fallback_to_push(s->resource.download, FALSE);
		else socket_destroy(s);
		return;
	}

	if (cond & GDK_INPUT_WRITE)	/* We are just connected to our partner */
	{
		gint res, option, size = sizeof(gint);

		gdk_input_remove(s->gdk_tag);

		/* Check wether the socket is really connected */

		res = getsockopt(s->file_desc, SOL_SOCKET, SO_ERROR, (void *) &option, &size);

		if (res == -1 || option)
		{
			if (s->type == GTA_TYPE_CONTROL && s->resource.node) node_remove(s->resource.node, "Connection failed");
			else if (s->type == GTA_TYPE_DOWNLOAD && s->resource.download) download_fallback_to_push(s->resource.download, FALSE);
			else socket_destroy(s);
			return;
		}

		switch (s->type)
		{
			case GTA_TYPE_CONTROL:
			{
				s->gdk_tag = gdk_input_add(s->file_desc, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, node_read_connecting, (gpointer) s);
				node_init_outgoing(s->resource.node);
				break;
			}

			case GTA_TYPE_DOWNLOAD:
			{
				s->gdk_tag = gdk_input_add(s->file_desc, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, download_read, (gpointer) s);
				download_send_request(s->resource.download);
				break;
			}

			case GTA_TYPE_UPLOAD:
			{
				g_warning("No handler for UPLOADS yet...");
				break;
			}

			default:
			{
				g_warning("socket_connected(): Unknown socket type %d !", s->type);
			}
		}
	}
}

void socket_accept(gpointer data, gint source, GdkInputCondition cond)
{
	/* Someone is connecting to us */

	struct sockaddr_in addr;
	gint sd, len = sizeof(struct sockaddr_in);
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	struct gnutella_socket *t = NULL;

	if (cond & GDK_INPUT_EXCEPTION)
	{
		g_warning("Input Exception for listening socket #%d !!!!\n", s->file_desc);
		gtk_gnutella_exit(2);
		return;
	}

	switch (s->type)
	{
		case GTA_TYPE_CONTROL:
		case GTA_TYPE_DOWNLOAD:
			break;

		default:

			g_warning("socket_accept(): Unknown socket type %d !\n", s->type);
			socket_destroy(s);
			return;
	}

	sd = accept(s->file_desc, (struct sockaddr *) &addr, &len);

	if (sd == -1) { g_warning("accept() failed (%s)", g_strerror(errno)); return; }

	/* Create a new struct socket for this incoming connection */

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	t = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	t->file_desc = sd;
	t->ip = g_ntohl(addr.sin_addr.s_addr);
	t->port = g_ntohs(addr.sin_port);
	t->direction = GTA_CONNECTION_INCOMING;
	t->type = s->type;
	t->local_port = s->local_port;

	switch (s->type)
	{
		case GTA_TYPE_CONTROL:
		{
			t->gdk_tag = gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, socket_read, t);
			break;
		}

		case GTA_TYPE_DOWNLOAD:
		{
/*			printf("Accepting INCOMING CONNECTION for %s\n", s->resource.download->file_name); */

			t->resource.download = s->resource.download;

			t->resource.download->socket = t;

			t->gdk_tag = gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, download_read, t);

			/* Close the listening socket */

			s->resource.download = NULL;
			socket_destroy(s);

			break;
		}

		case GTA_TYPE_UPLOAD:
		{
			/* TODO */

			break;
		}
	}
}

/* ------ Sockets creation ------------------------------------------------------------------------ */

struct gnutella_socket *socket_connect(guint32 ip, guint16 port, gint type)
{
	/* Create a socket and try to connect it to ip:port */

	gint sd, option = 1, res;
	struct sockaddr_in addr;
	struct gnutella_socket *s;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1)
	{
		g_warning("Unable to create a socket (%s)\n", g_strerror(errno));
		return NULL;
	}

	s = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	s->type = type;
	s->direction = GTA_CONNECTION_OUTGOING;
	s->file_desc = sd;

	setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &option, sizeof(option));
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *) &option, sizeof(option));

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = g_htonl(ip);
	addr.sin_port = g_htons(port);

	res = connect(sd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));

	if (res == -1 && errno != EINPROGRESS)
	{
		g_warning("Unable to connect (%s)\n", g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	if (!local_ip)	/* We need our local address */
	{
		gint len = sizeof(struct sockaddr_in);

		if (getsockname(sd, (struct sockaddr *) &addr, &len) == -1)
		{
			g_warning("Unable to guess our IP ! (%s)\n", g_strerror(errno));
			socket_destroy(s);
			return NULL;
		}
		else
		{
			local_ip = g_ntohl(addr.sin_addr.s_addr);
			s->local_port = g_ntohs(addr.sin_port);
		}
	}

	s->gdk_tag = gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION, socket_connected, s);

	return s;
}

struct gnutella_socket *socket_listen(guint32 ip, guint16 port, gint type)
{
	/* Create a socket, then bind() and listen() it */

	int sd, option = 1;
	unsigned int l = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct gnutella_socket *s;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1)
	{
		g_warning("Unable to create a socket (%s)\n", g_strerror(errno));
		return NULL;
	}

	s = (struct gnutella_socket *) g_malloc0(sizeof(struct gnutella_socket));

	s->type = type;
	s->direction = GTA_CONNECTION_LISTENING;
	s->file_desc = sd;

	setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void *) &option, sizeof(option));
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *) &option, sizeof(option));

	fcntl(sd, F_SETFL, O_NONBLOCK);	/* Set the file descriptor non blocking */

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = g_htonl((ip)? ip : INADDR_ANY);
	addr.sin_port = g_htons(port);

	/* bind() the socket */

	if (bind(sd, (struct sockaddr *) &addr, l) == -1)
	{
		g_warning("Unable to bind() the socket (%s)\n", g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	/* listen() the socket */

	if (listen(sd, 1) == -1)
	{
		g_warning("Unable to listen() the socket (%s)\n", g_strerror(errno));
		socket_destroy(s);
		return NULL;
	}

	/* Get the port of the socket, if needed */

	if (!port)
	{
		option = sizeof(struct sockaddr_in);

		if (getsockname(sd, (struct sockaddr *) &addr, &option) == -1)
		{
			g_warning("Unable to get the port of the socket: getsockname() failed (%s).", g_strerror(errno));
			socket_destroy(s);
			return NULL;
		}

		s->local_port = g_ntohs(addr.sin_port);
	}
	else s->local_port = port;

	s->gdk_tag = gdk_input_add(sd, GDK_INPUT_READ | GDK_INPUT_EXCEPTION, socket_accept, s);

	return s;
}

/* vi: set ts=3: */

