#ifndef __sockets_h__
#define __sockets_h__

struct gnutella_socket {
	gint file_desc;			/* file descriptor */

	gint gdk_tag;			/* gdk tag */

	guchar direction;	/* GNUTELLA_INCOMING | GNUTELLA_OUTGOING */
	guchar type;	/* GNUTELLA_CONTROL | GNUTELLA_DOWNLOAD | GNUTELLA_UPLOAD */

	guint32 ip;				/* IP	of our partner */
	guint16 port;			/* Port of our partner */

	guint16 local_port;		/* Port on our side */

	time_t last_update;		/* Timestamp of last activity on socket */

	union {
		struct gnutella_node *node;
		struct download *download;
		struct upload *upload;
	} resource;

	gchar buffer[4096];		/*		buffer to put in the data read */
	guint32 pos;			/* write position in the buffer */
};

/*
 * Global Data
 */

extern guint32 local_ip;

/*
 * Global Functions
 */

void socket_destroy(struct gnutella_socket *);
void socket_free(struct gnutella_socket *);
struct gnutella_socket *socket_connect(guint32, guint16, gint);
struct gnutella_socket *socket_listen(guint32, guint16, gint);
int connect_socksv5(struct gnutella_socket *);
int proxy_connect(int, const struct sockaddr *, socklen_t);
int recv_socks(struct gnutella_socket *);
int send_socks(struct gnutella_socket *);
void socket_monitor_incoming(void);
void socket_shutdown(void);

#endif /* __sockets_h__ */
