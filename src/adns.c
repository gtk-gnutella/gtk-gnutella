/*
 * $Id$
 *
 * Copyright (c) 2003, Christian Biere
 *
 * Asynchronous DNS lookup.
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

#include "gnutella.h" /* mainly for dbg */

RCSID("$Id$");

#include <netdb.h>
#include <signal.h>
#include "adns.h"
#include "http.h" /* MAX_HOSTLEN */

/* private data types */

struct adns_query_t {
	gchar hostname[MAX_HOSTLEN + 1];
	void (*user_callback)(guint32, gpointer);
	gpointer user_data;
} __attribute__((__packed__));

struct adns_reply_t {
    void (*user_callback)(guint32, gpointer);
    gpointer user_data;
    guint32 ip;
} __attribute__((__packed__));

/* private variables */

static gint adns_query_fd = -1;

/* private functions */

G_INLINE_FUNC gboolean adns_do_transfer(
	gint fd, gpointer buf, size_t len, gboolean do_write)
{
	ssize_t ret;
	size_t transferred = 0;
	size_t n = len;

	while (n > 0) {
		if (dbg > 2)
			g_warning("adns_do_transfer: n=%lu", (gulong) n);

		if (do_write)
			ret = write(fd, buf, n);
		else 
			ret = read(fd, buf, n);
		
		if (-1 == ret && errno != EAGAIN && errno != EINTR) {
			g_warning("adns_do_transfer: %s (errno=%d, do_write=%d)",
				g_strerror(errno), errno, (gint) do_write);
			return FALSE;
		} else if (0 == ret) {
			g_warning("adns_do_transfer: EOF (%s)", write ? "write" : "read");
			return FALSE;
		} else {
			n -= ret;
			buf = (gchar *)buf + transferred;
		}
	}

	return TRUE;
}

/*
 * adns_do_read
 *
 * read the complete buffer ``buf'' of size ``len'' from file descriptor ``fd''
 * return TRUE on success, FALSE if the operation failed
 */
static gboolean adns_do_read(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, FALSE);
}

/*
 * adns_do_write
 *
 * write the complete buffer ``buf'' of size ``len'' to file descriptor ``fd''
 * return TRUE on success, FALSE if the operation failed
 */
static gboolean adns_do_write(gint fd, gpointer buf, size_t len)
{
	return adns_do_transfer(fd, buf, len, TRUE);
}

/*
 * adns_gethostbyname
 *
 * copies user_callback and user_data from the query buffer to the
 * reply buffer. This function won't fail. However, if gethostbyname()
 * fails ``reply->ip'' will be set to zero.
 */
static void adns_gethostbyname(
	const struct adns_query_t *query, struct adns_reply_t *reply)
{
	struct hostent *he;

	g_assert(NULL != query);
	g_assert(NULL != reply);
	g_warning("adns_gethostbyname: Resolving \"%s\" ...", query->hostname);
	he = gethostbyname(query->hostname);
	reply->ip = NULL != he ? g_ntohl(*(guint32 *) (he->h_addr)) : 0;
	reply->user_callback = query->user_callback;
	reply->user_data = query->user_data;
}

/*
 * adns_helper
 * 
 * The ``main'' function of the adns helper process (server).
 * Simply reads requests (queries) from fd_in, performs a DNS lookup for it
 * and writes the result to fd_out. All operations should be blocking. Exits
 * in case of non-recoverable error during read or write.  
 */
static void adns_helper(gint fd_in, gint fd_out)
{
	struct adns_query_t query;
	struct adns_reply_t reply;

	g_set_prgname("DNS-helper for gtk-gnutella");

	for (;;) {
		if (!adns_do_read(fd_in, &query, sizeof(query)))
			break;
		adns_gethostbyname(&query, &reply);
		if (!adns_do_write(fd_out, &reply, sizeof(reply)))
			break;
	}

	close(fd_in);
	close(fd_out);
	exit(EXIT_SUCCESS);
}

/*
 * adns_callback
 *
 * Callback function for inputevt_add(). This function invokes the callback
 * function given in DNS query on the client-side i.e., gtk-nutella itself.
 */
static gboolean adns_callback(
	gpointer data, gint source, inputevt_cond_t condition)
{
	struct adns_reply_t reply;

	if (adns_do_read(source, &reply, sizeof(reply))) {
		g_warning("adns_callback: resolved to \"%s\"", ip_to_gchar(reply.ip));
		g_assert(NULL != reply.user_callback);
		reply.user_callback(reply.ip, reply.user_data);
		return TRUE;
	}
	return FALSE;
}

/* public functions */

/*
 * adns_init:
 *
 * Initializes the adns helper i.e., fork()s a children process which will
 * be used to resolve hostnames asynchronously.
 */
void adns_init(void)
{
	gint fd_query[2];
	gint fd_reply[2];
	pid_t pid;

	if (-1 == pipe(fd_query) || -1 == pipe(fd_reply)) {
		g_warning("adns_init: pipe() failed: %s", g_strerror(errno));
		return;
	}
	signal(SIGCHLD, SIG_IGN);
	pid = fork();
	if ((pid_t) -1 == pid) {
		g_warning("adns_init: fork() failed: %s", g_strerror(errno));
		close(fd_query[0]);
		close(fd_query[1]);
		close(fd_reply[0]);
		close(fd_reply[1]);
		return;
	}
	if (0 == pid) {
		/* child process */
	
		close(fd_query[1]);
		close(fd_reply[0]);
		adns_helper(fd_query[0], fd_reply[1]); 
		g_assert_not_reached();
		exit(EXIT_SUCCESS);
	} 

	/* parent process */
	close(fd_query[0]);
	close(fd_reply[1]);
	adns_query_fd = fd_query[1];
	inputevt_add(fd_reply[0], INPUT_EVENT_READ,
		(inputevt_handler_t) &adns_callback, NULL);
}

/*
 * adns_resolve
 *
 * Creates a DNS resolve query for ``hostname''. The given function
 * ``user_callback'' (which MUST NOT be NULL) will be invoked with
 * the resolved IP address and ``user_data'' as its parameters. The
 * IP address 0.0.0.0 i.e., ``(guint32) 0'' is used to indicate a
 * failure. In case the hostname is given as an IP string, it will
 * be directly converted and the callback immediately invoked. If
 * the adns helper process is ``out of service'' the query will be
 * resolved synchronously.
 */
 void adns_resolve(
	const gchar *hostname, gpointer user_callback, gpointer user_data)
{
	struct adns_query_t query;
	struct adns_reply_t reply;

	g_assert(NULL != hostname);
	g_assert(NULL != user_callback);

	query.user_callback = user_callback;
	query.user_data = user_data;
	reply.ip = gchar_to_ip(hostname);
	if (0 != reply.ip) {
		query.user_callback(reply.ip, query.user_data);
		return;
	}

	g_strlcpy(query.hostname, hostname, sizeof(query.hostname));
	
	if (!adns_do_write(adns_query_fd, &query, sizeof(query))) {
		g_warning("adns_resolve: adns_do_write failed using fall back");
		adns_gethostbyname(&query, &reply);
		g_assert(NULL != reply.user_callback);
		reply.user_callback(reply.ip, reply.user_data);
	}
}

/*
 * adns_close
 *
 * Nothing for now  
 */
void adns_close(void)
{
	return;
}

