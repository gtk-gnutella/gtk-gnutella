/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
 *
 * Handles upload of our files to others users.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#ifdef HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

#include "sockets.h"
#include "share.h"
#include "header.h"
#include "hosts.h"		/* for check_valid_host() */
#include "bsched.h"
#include "upload_stats.h"
#include "dmesh.h"
#include "http.h"
#include "version.h"
#include "nodes.h"
#include "ioheader.h"
#include "ban.h"
#include "parq.h"

#include "settings.h"

RCSID("$Id$");

#define READ_BUF_SIZE	4096		/* Read buffer size, if no sendfile(2) */
#define BW_OUT_MIN		256			/* Minimum bandwidth to enable uploads */

#define RQST_LINE_LENGTH	256		/* Reasonable estimate for request line */

GSList *uploads = NULL;

static idtable_t *upload_handle_map = NULL;

#define upload_find_by_handle(n) \
    (gnutella_upload_t *) idtable_get_value(upload_handle_map, n)

#define upload_new_handle(n) \
    idtable_new_id(upload_handle_map, n)

#define upload_free_handle(n) \
    idtable_free_id(upload_handle_map, n);

gint running_uploads = 0;
gint registered_uploads = 0;

guint32 count_uploads = 0;

/*
 * This structure is the key used in the mesh_info hash table to record
 * when we last sent mesh information to some IP about a given file
 * (identified by its SHA1).
 */
struct mesh_info_key {
	guint32 ip;						/* Remote host IP address */
	const guchar *sha1;				/* SHA1 atom */
};

struct mesh_info_val {
	guint32 stamp;					/* When we last sent the mesh */
	gpointer cq_ev;					/* Scheduled cleanup callout event */
};

#define MESH_INFO_TIMEOUT	(600*1000)	/* Keep info 10 minutes (unit: ms) */

extern cqueue_t *callout_queue;

static GHashTable *mesh_info = NULL;

static void upload_request(gnutella_upload_t *u, header_t *header);
static void upload_error_remove(gnutella_upload_t *u, struct shared_file *sf,
	int code, const guchar *msg, ...);
static void upload_error_remove_ext(gnutella_upload_t *u,
	struct shared_file *sf, const gchar *extended, int code,
	const guchar *msg, ...);
static void upload_http_sha1_add(gchar *buf, gint *retval, gpointer arg);
static void upload_http_xhost_add(gchar *buf, gint *retval, gpointer arg);
static void upload_write(gpointer up, gint source, inputevt_cond_t cond);


/***
 *** Callbacks
 ***/

static listeners_t upload_added_listeners   = NULL;
static listeners_t upload_removed_listeners = NULL;
static listeners_t upload_info_changed_listeners = NULL;

void upload_add_upload_added_listener(upload_added_listener_t l)
{
    LISTENER_ADD(upload_added, l);
}

void upload_remove_upload_added_listener(upload_added_listener_t l)
{
    LISTENER_REMOVE(upload_added, l);
}

void upload_add_upload_removed_listener(upload_removed_listener_t l)
{
    LISTENER_ADD(upload_removed, l);
}

void upload_remove_upload_removed_listener(upload_removed_listener_t l)
{
    LISTENER_REMOVE(upload_removed, l);
}

void upload_add_upload_info_changed_listener(
    upload_info_changed_listener_t l)
{
    LISTENER_ADD(upload_info_changed, l);
}

void upload_remove_upload_info_changed_listener(
    upload_info_changed_listener_t l)
{
    LISTENER_REMOVE(upload_info_changed, l);
}

static void upload_fire_upload_added(gnutella_upload_t *n)
{
    LISTENER_EMIT(upload_added, n->upload_handle, 
        running_uploads, registered_uploads);
	gnet_prop_set_guint32_val(PROP_UL_RUNNING, running_uploads);
	gnet_prop_set_guint32_val(PROP_UL_REGISTERED, registered_uploads);
}

static void upload_fire_upload_removed(
    gnutella_upload_t *n, const gchar *reason)
{
    LISTENER_EMIT(upload_removed, n->upload_handle, reason,
        running_uploads, registered_uploads);
	gnet_prop_set_guint32_val(PROP_UL_RUNNING, running_uploads);
	gnet_prop_set_guint32_val(PROP_UL_REGISTERED, registered_uploads);
}

void upload_fire_upload_info_changed
    (gnutella_upload_t *n)
{
    LISTENER_EMIT(upload_info_changed, n->upload_handle,
        running_uploads, registered_uploads);
}

/***
 *** Private functions
 ***/
/*
 * upload_timer
 *
 * Upload heartbeat timer.
 */
void upload_timer(time_t now)
{
	GSList *l;
	GSList *to_remove = NULL;
	time_t t;

	for (l = uploads; l; l = l->next) {
		gnutella_upload_t *u = (gnutella_upload_t *) l->data;

		if (UPLOAD_IS_COMPLETE(u))
			continue;					/* Complete, no timeout possible */

		/*
		 * Check for timeouts.
		 */

		t = UPLOAD_IS_CONNECTING(u) ?
            upload_connecting_timeout :	upload_connected_timeout;

		/*
		 * We can't call upload_remove() since it will remove the upload
		 * from the list we are traversing.
		 */

		if (now - u->last_update > t)
			to_remove = g_slist_prepend(to_remove, u);
	}

	for (l = to_remove; l; l = l->next) {
		gnutella_upload_t *u = (gnutella_upload_t *) l->data;
		if (UPLOAD_IS_CONNECTING(u)) {
			if (u->status == GTA_UL_PUSH_RECEIVED || u->status == GTA_UL_QUEUE)
				upload_remove(u, "Connect back timeout");
			else
				upload_error_remove(u, NULL, 408, "Request timeout");
		} else
			upload_remove(u, "Data timeout");
	}
	g_slist_free(to_remove);
}

/*
 * upload_create
 *
 * Create a new upload structure, linked to a socket.
 */
gnutella_upload_t *upload_create(struct gnutella_socket *s, gboolean push)
{
	gnutella_upload_t *u;

	u = (gnutella_upload_t *) walloc0(sizeof(gnutella_upload_t));
    u->upload_handle = upload_new_handle(u);

	u->socket = s;
    u->ip = s->ip;
	s->resource.upload = u;

	u->push = push;
	u->status = push ? GTA_UL_PUSH_RECEIVED : GTA_UL_HEADERS;
	u->last_update = time((time_t *) 0);
	u->file_desc = -1;
	
	/*
	 * Record pending upload in the GUI.
	 */

	registered_uploads++;

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	uploads = g_slist_append(uploads, u);

	/*
	 * Add upload to the GUI
	 */
    upload_fire_upload_added(u);
	
	u->parq_status = 0;

	return u;
}

/*
 * handle_push_request
 *
 * Called when we receive a Push request on Gnet.
 *
 * If it is not for us, discard it.
 * If we are the target, then connect back to the remote servent.
 */
void handle_push_request(struct gnutella_node *n)
{
	gnutella_upload_t *u;
	struct gnutella_socket *s;
	struct shared_file *req_file;
	guint32 file_index;
	guint32 ip;
	guint16 port;
	guchar *info;
	gboolean show_banning = FALSE;

	if (0 != memcmp(n->data, guid, 16))		/* Servent ID matches our GUID? */
		return;								/* No: not for us */

	/*
	 * We are the target of the push.
	 */

	info = n->data + 16;					/* Start of file information */

	READ_GUINT32_LE(info, file_index);
	READ_GUINT32_BE(info + 4, ip);
	READ_GUINT16_LE(info + 8, port);

	/*
	 * Quick sanity check on file index.
	 */

	req_file = shared_file(file_index);

	if (req_file == SHARE_REBUILDING) {
		g_warning("PUSH request (hops=%d, ttl=%d) whilst rebuilding library",
			n->header.hops, n->header.ttl);
		return;		/* Sorry, race not supported for now -- RAM, 12/03/2002 */
	}

	if (req_file == NULL) {
		g_warning("PUSH request (hops=%d, ttl=%d) for invalid file index %u",
			n->header.hops, n->header.ttl, file_index);
		return;
	}

	/*
	 * XXX might be run inside corporations (private IPs), must be smarter.
	 * XXX maybe a configuration variable? --RAM, 31/12/2001
	 *
	 * Don't waste time and resources connecting to something that will fail.
	 *
	 * NB: we allow the PUSH if we're already connected to that node.  This
	 * allows easy local testing. -- RAM, 11/11/2002
	 */

	if (!host_is_valid(ip, port) && !node_is_connected(ip, port, TRUE)) {
		g_warning("PUSH request (hops=%d, ttl=%d) from invalid address %s",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port));
		return;
	}

	/*
	 * Protect from PUSH flood: since each push requires us to connect
	 * back, it uses resources and could be used to conduct a subtle denial
	 * of service attack.	-- RAM, 03/11/2002
	 */

	switch (ban_allow(ip)) {
	case BAN_OK:				/* Connection authorized */
		break;
	case BAN_FIRST:				/* Refused, negative ack (can't do for PUSH) */
		show_banning = TRUE;
		/* FALL THROUGH */
	case BAN_FORCE:				/* Refused, no ack */
		if (dbg) g_warning("PUSH flood (hops=%d, ttl=%d) to %s [ban %s]: %s\n",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port),
			short_time(ban_delay(ip)), req_file->file_name);
		if (!show_banning)
			return;
		break;
	default:
		g_assert(0);
	}

	/*
	 * OK, start the upload by opening a connection to the remote host.
	 */

	if (dbg > 4)
		printf("PUSH (hops=%d, ttl=%d) to %s: %s\n",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port),
			req_file->file_name);

	s = socket_connect(ip, port, SOCK_TYPE_UPLOAD);
	if (!s) {
		g_warning("PUSH request (hops=%d, ttl=%d) dropped: can't connect to %s",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port));
		return;
	}

	u = upload_create(s, TRUE);
	u->index = file_index;
	u->name = atom_str_get(req_file->file_name);

	if (show_banning) {
		upload_remove(u, "Banned for %s", short_time(ban_delay(ip)));
		return;
	}

	upload_fire_upload_info_changed(u);

	/* Now waiting for the connection CONF -- will call upload_connect_conf() */
}

void upload_real_remove(void)
{
	/* XXX UNUSED
	 * XXX Currently, we remove failed uploads from the list, but we should
	 * XXX do as we do for downloads, and have an extra option to remove
	 * XXX failed uploads immediately.	--RAM, 24/12/2001
	 */
}

static void upload_free_resources(gnutella_upload_t *u)
{
	if (u->name != NULL) {
		atom_str_free(u->name);
		u->name = NULL;
	}
	if (u->file_desc != -1) {
		close(u->file_desc);
		u->file_desc = -1;
	}
	if (u->socket != NULL) {
		g_assert(u->socket->resource.upload == u);
		socket_free(u->socket);
		u->socket = NULL;
	}
	if (u->buffer != NULL) {
		g_free(u->buffer);
		u->buffer = NULL;
	}
	if (u->io_opaque) {				/* I/O data */
		io_free(u->io_opaque);
		g_assert(u->io_opaque == NULL);
	}
	if (u->bio != NULL) {
		bsched_source_remove(u->bio);
		u->bio = NULL;
	}
	if (u->user_agent) {
		atom_str_free(u->user_agent);
		u->user_agent = NULL;
	}
	if (u->sha1) {
		atom_sha1_free(u->sha1);
		u->sha1 = NULL;
	}

    upload_free_handle(u->upload_handle);
}

/*
 * upload_clone
 *
 * Clone upload, resetting all dynamically allocated structures in the
 * original, since they are shallow-copied to the new upload.
 *
 * (This routine is used because each different upload from the same host
 * will become a line in the GUI, and the GUI stores upload structures in
 * its row data, and will call upload_remove() to clear them.)
 */
static gnutella_upload_t *upload_clone(gnutella_upload_t *u)
{
	gnutella_upload_t *cu = walloc(sizeof(gnutella_upload_t));

	*cu = *u;		/* Struct copy */

	g_assert(u->io_opaque == NULL);		/* If cloned, we were transferrring! */

    cu->upload_handle = upload_new_handle(cu); /* fetch new handle */
	cu->bio = NULL;						/* Recreated on each transfer */
	cu->file_desc = -1;					/* File re-opened each time */
	cu->socket->resource.upload = cu;	/* Takes ownership of socket */
	cu->accounted = FALSE;
    cu->skip = 0;
    cu->end = 0;

	/*
	 * The following have been copied and appropriated by the cloned upload.
	 * They are reset so that an upload_free_resource() on the original will
	 * not free them.
	 */

	u->name = NULL;
	u->socket = NULL;
	u->buffer = NULL;
	u->user_agent = NULL;
	u->sha1 = NULL;

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	uploads = g_slist_append(uploads, cu);

	/*
	 * Add upload to the GUI
	 */
    upload_fire_upload_added(cu);

	return cu;
}

/*
 * send_upload_error_v
 *
 * The vectorized (message-wise) version of send_upload_error().
 */
static void send_upload_error_v(
	gnutella_upload_t *u,
	struct shared_file *sf,
	const gchar *ext,
	int code,
	const guchar *msg, va_list ap)
{
	gchar reason[1024];
	gchar extra[1024];
	gint slen = 0;
	http_extra_desc_t hev[3];
	gint hevcnt = 0;
	struct upload_http_cb cb_arg;

	if (msg) {
		gm_vsnprintf(reason, sizeof(reason), msg, ap);
		reason[sizeof(reason) - 1] = '\0';		/* May be truncated */
	} else
		reason[0] = '\0';

	if (u->error_sent) {
		g_warning("Already sent an error %d to %s, not sending %d (%s)",
			u->error_sent, ip_to_gchar(u->socket->ip), code, reason);
		return;
	}

	extra[0] = '\0';

	/*
	 * If `ext' is not null, we have extra header information to propagate.
	 */

	if (ext) {
		slen = gm_snprintf(extra, sizeof(extra), "%s", ext);
		
		if (slen < sizeof(extra)) {
			hev[hevcnt].he_type = HTTP_EXTRA_LINE;
			hev[hevcnt++].he_msg = extra;
		} else
			g_warning("send_upload_error_v: "
				"ignoring too large extra header (%d bytes)", slen);
	}

	/*
	 * If the download got queued, also add the queueing information
	 *		--JA, 07/02/2003
	 */
	if (parq_upload_queued(u)) {
		cb_arg.u = u;
		cb_arg.sf = sf;
		
		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = parq_upload_add_header;
		hev[hevcnt++].he_arg = &cb_arg;
	}	

	/*
	 * If this is a pushed upload, and we are not firewalled, then tell
	 * them they can reach us directly by outputting an X-Host line.
	 */

	if (u->push && !is_firewalled) {
		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = upload_http_xhost_add;
		hev[hevcnt++].he_arg = NULL;
	}

	/*
	 * If `sf' is not null, propagate the SHA1 for the file if we have it,
	 * as well as the download mesh.
	 */
	if (sf && sha1_hash_available(sf)) {
		cb_arg.u = u;
		cb_arg.sf = sf;

		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = upload_http_sha1_add;
		hev[hevcnt++].he_arg = &cb_arg;
	}
	
	/* 
	 * Keep connection alive when activly queued
	 * 		-- JA, 22/4/2003
	 */
	if (u->status == GTA_UL_QUEUED)
		http_send_status(u->socket, code, TRUE,
			hevcnt ? hev : NULL, hevcnt, reason);
	else
		http_send_status(u->socket, code, FALSE,
			hevcnt ? hev : NULL, hevcnt, reason);

	u->error_sent = code;
}

/*
 * send_upload_error
 *
 * Send error message to requestor.
 * This can only be done once per connection.
 */
static void send_upload_error(
	gnutella_upload_t *u,
	struct shared_file *sf,
	int code,
	const guchar *msg, ...)
{
	va_list args;

	va_start(args, msg);
	send_upload_error_v(u, sf, NULL, code, msg, args);
	va_end(args);
}

/*
 * upload_remove_v
 *
 * The vectorized (message-wise) version of upload_remove().
 */
static void upload_remove_v(
	gnutella_upload_t *u, const gchar *reason, va_list ap)
{
	const gchar *logreason;
	gchar errbuf[1024];

	g_assert(u != NULL);

	if (reason) {
		gm_vsnprintf(errbuf, sizeof(errbuf), reason, ap);
		errbuf[sizeof(errbuf) - 1] = '\0';		/* May be truncated */
		logreason = errbuf;
	} else {
		if (u->error_sent) {
			gm_snprintf(errbuf, sizeof(errbuf), "HTTP %d", u->error_sent);
			logreason = errbuf;
		} else {
			errbuf[0] = '\0';
			logreason = "No reason given";
		}
	}

	if (!UPLOAD_IS_COMPLETE(u) && dbg > 1) {
		if (u->name) {
			printf("Cancelling upload for %s from %s: %s\n",
				u->name,
				u->socket ? ip_to_gchar(u->socket->ip) : "<no socket>",
				logreason);
		} else {
			printf("Cancelling upload from %s: %s\n",
				u->socket ? ip_to_gchar(u->socket->ip) : "<no socket>",
				logreason);
		}
	}

	/*
	 * If the upload is still connecting, we have not started sending
	 * any data yet, so we send an HTTP error code before closing the
	 * connection.
	 *		--RAM, 24/12/2001
	 *
	 * Push requests still connecting don't have anything to send, hence
	 * we check explicitely for GTA_UL_PUSH_RECEIVED.
	 *		--RAM, 31/12/2001
	 * 	Same goes for a parq QUEUE 'push' send.
	 *		-- JA, 12/04/2003
	 */

	if (
		UPLOAD_IS_CONNECTING(u) &&
		!u->error_sent &&
		(u->status != GTA_UL_PUSH_RECEIVED || u->status != GTA_UL_QUEUE)
	) {
		if (reason == NULL)
			logreason = "Bad Request";
		send_upload_error(u, NULL, 400, logreason);
	}

	/*
	 * If COMPLETE, we've already decremented `running_uploads' and
	 * `registered_uploads'.
	 * Moreover, if it's still connecting, then we've not even
	 * incremented the `running_uploads' counter yet.
	 * For keep-alive uploads still in the GTA_UL_WAITING state, the upload
	 * slot is reserved so it must be decremented as well (we know it's a
	 * follow-up request since u->keep_alive is set).
	 */

	if (!UPLOAD_IS_COMPLETE(u))
		registered_uploads--;

	if (u->status != GTA_UL_QUEUED) {
		if (!UPLOAD_IS_COMPLETE(u) && !UPLOAD_IS_CONNECTING(u)) {
			running_uploads--;
		} else if (u->keep_alive && UPLOAD_IS_CONNECTING(u)) {
			running_uploads--;
		}
	}
	
	
	/*
	 * If we were sending data, and we have not accounted the download yet,
	 * then update the stats, not marking the upload as completed.
	 */

	if (UPLOAD_IS_SENDING(u) && !u->accounted)
		upload_stats_file_aborted(u);

    if (!UPLOAD_IS_COMPLETE(u)) {
        if (u->status == GTA_UL_WAITING)
            u->status = GTA_UL_CLOSED;
        else
            u->status = GTA_UL_ABORTED;
        upload_fire_upload_info_changed(u);
    }


	parq_upload_remove(u);
    upload_fire_upload_removed(u, reason ? errbuf : NULL);

	upload_free_resources(u);
	wfree(u, sizeof(*u));
	uploads = g_slist_remove(uploads, (gpointer) u);
}

/*
 * upload_remove
 *
 * Remove upload entry, log reason.
 *
 * If no status has been sent back on the HTTP stream yet, give them
 * a 400 error with the reason.
 */
void upload_remove(gnutella_upload_t *u, const gchar *reason, ...)
{
	va_list args;
	
	g_assert(u != NULL);
	
	va_start(args, reason);
	upload_remove_v(u, reason, args);
	va_end(args);
}

/*
 * upload_error_remove
 *
 * Utility routine.  Cancel the upload, sending back the HTTP error message.
 */
static void upload_error_remove(
	gnutella_upload_t *u,
	struct shared_file *sf,
	int code,
	const guchar *msg, ...)
{
	va_list args, errargs;

	g_assert(u != NULL);

	va_start(args, msg);

	VA_COPY(errargs, args);
	send_upload_error_v(u, sf, NULL, code, msg, errargs);
	va_end(errargs);

	upload_remove_v(u, msg, args);
	va_end(args);
}

/*
 * upload_error_remove_ext
 *
 * Utility routine.  Cancel the upload, sending back the HTTP error message.
 * `ext' contains additionnal header information to propagate back. 
 */
static void upload_error_remove_ext(
	gnutella_upload_t *u,
	struct shared_file *sf,
	const gchar *ext,
	int code,
	const guchar *msg, ...)
{
	va_list args, errargs;

	g_assert(u != NULL);

	va_start(args, msg);

	VA_COPY(errargs, args);
	send_upload_error_v(u, sf, ext, code, msg, errargs);
	va_end(errargs);

	upload_remove_v(u, msg, args);
	
	va_end(args);
}

/***
 *** I/O header parsing callbacks.
 ***/

#define UPLOAD(x)	((gnutella_upload_t *) (x))

static void err_line_too_long(gpointer obj)
{
	upload_error_remove(UPLOAD(obj), NULL, 413, "Header too large");
}

static void err_header_error_tell(gpointer obj, gint error)
{
	send_upload_error(UPLOAD(obj), NULL, 413, header_strerror(error));
}

static void err_header_error(gpointer obj, gint error)
{
	upload_remove(UPLOAD(obj), "Failed (%s)", header_strerror(error));
}

static void err_input_exception(gpointer obj)
{
	upload_remove(UPLOAD(obj), "Failed (Input Exception)");
}

static void err_input_buffer_full(gpointer obj)
{
	upload_error_remove(UPLOAD(obj), NULL, 500, "Input buffer full");
}

static void err_header_read_error(gpointer obj, gint error)
{
	upload_remove(UPLOAD(obj), "Failed (Input error: %s)", g_strerror(error));
}

static void err_header_read_eof(gpointer obj)
{
	upload_remove(UPLOAD(obj), "Failed (EOF)");
}

static void err_header_extra_data(gpointer obj)
{
	upload_error_remove(UPLOAD(obj), NULL, 400, "Extra data after HTTP header");
}

static struct io_error upload_io_error = {
	err_line_too_long,
	err_header_error_tell,
	err_header_error,
	err_input_exception,
	err_input_buffer_full,
	err_header_read_error,
	err_header_read_eof,
	err_header_extra_data,
};

static void call_upload_request(gpointer obj, header_t *header)
{
	upload_request(UPLOAD(obj), header);
}

#undef UPLOAD

/***
 *** Upload mesh info tracking.
 ***/

static struct mesh_info_key *mi_key_make(guint32 ip, const guchar *sha1)
{
	struct mesh_info_key *mik;

	mik = walloc(sizeof(*mik));
	mik->ip = ip;
	mik->sha1 = atom_sha1_get(sha1);

	return mik;
}

static void mi_key_free(struct mesh_info_key *mik)
{
	g_assert(mik);

	atom_sha1_free(mik->sha1);
	wfree(mik, sizeof(*mik));
}

static guint mi_key_hash(gconstpointer key)
{
	const struct mesh_info_key *mik = (const struct mesh_info_key *) key;
	extern guint sha1_hash(gconstpointer key);

	return sha1_hash((gconstpointer) mik->sha1) ^ mik->ip;
}

static gint mi_key_eq(gconstpointer a, gconstpointer b)
{
	const struct mesh_info_key *mika = (const struct mesh_info_key *) a;
	const struct mesh_info_key *mikb = (const struct mesh_info_key *) b;
	extern gint sha1_eq(gconstpointer a, gconstpointer b);

	return mika->ip == mikb->ip &&
		sha1_eq((gconstpointer) mika->sha1, (gconstpointer) mikb->sha1);
}

static struct mesh_info_val *mi_val_make(guint32 stamp)
{
	struct mesh_info_val *miv;

	miv = walloc(sizeof(*miv));
	miv->stamp = stamp;
	miv->cq_ev = NULL;

	return miv;
}

static void mi_val_free(struct mesh_info_val *miv)
{
	g_assert(miv);

	if (miv->cq_ev)
		cq_cancel(callout_queue, miv->cq_ev);

	wfree(miv, sizeof(*miv));
}

/*
 * mi_free_kv
 *
 * Hash table iterator callback.
 */
static void mi_free_kv(gpointer key, gpointer value, gpointer udata)
{
	mi_key_free((struct mesh_info_key *) key);
	mi_val_free((struct mesh_info_val *) value);
}

/*
 * mi_clean
 *
 * Callout queue callback invoked to clear the entry.
 */
static void mi_clean(cqueue_t *cq, gpointer obj)
{
	struct mesh_info_key *mik = (struct mesh_info_key *) obj;
	gpointer key;
	gpointer value;
	gboolean found;
	
	found = g_hash_table_lookup_extended(mesh_info, mik, &key, &value);

	g_assert(found);
	g_assert(obj == key);
	g_assert(((struct mesh_info_val *) value)->cq_ev);

	if (dbg > 4)
		printf("upload MESH info (%s/%s) discarded\n",
			ip_to_gchar(mik->ip), sha1_base32(mik->sha1));

	g_hash_table_remove(mesh_info, mik);
	((struct mesh_info_val *) value)->cq_ev = NULL;
	mi_free_kv(key, value, NULL);
}

/*
 * mi_get_stamp
 *
 * Get timestamp at which we last sent download mesh information for (IP,SHA1).
 * If we don't remember sending it, return 0.
 * Always records `now' as the time we sent mesh information.
 */
static guint32 mi_get_stamp(guint32 ip, const guchar *sha1, time_t now)
{
	struct mesh_info_key mikey;
	struct mesh_info_val *miv;
	struct mesh_info_key *mik;

	mikey.ip = ip;
	mikey.sha1 = sha1;
	
	miv = g_hash_table_lookup(mesh_info, &mikey);

	/*
	 * If we have an entry, reschedule the cleanup in MESH_INFO_TIMEOUT.
	 * Then return the timestamp.
	 */

	if (miv) {
		guint32 oldstamp;

		g_assert(miv->cq_ev);
		cq_resched(callout_queue, miv->cq_ev, MESH_INFO_TIMEOUT);

		oldstamp = miv->stamp;
		miv->stamp = (guint32) now;

		if (dbg > 4)
			printf("upload MESH info (%s/%s) has stamp=%u\n",
				ip_to_gchar(ip), sha1_base32(sha1), oldstamp);

		return oldstamp;
	}

	/*
	 * Create new entry.
	 */

	mik = mi_key_make(ip, sha1);
	miv = mi_val_make((guint32) now);
	miv->cq_ev = cq_insert(callout_queue, MESH_INFO_TIMEOUT, mi_clean, mik);

	g_hash_table_insert(mesh_info, mik, miv);

	if (dbg > 4)
		printf("new upload MESH info (%s/%s) stamp=%u\n",
			ip_to_gchar(ip), sha1_base32(sha1), (guint32) now);

	return 0;			/* Don't remember sending info about this file */
}


/*
 * upload_add
 *
 * Create a new upload request, and begin reading HTTP headers.
 */
void upload_add(struct gnutella_socket *s)
{
	gnutella_upload_t *u;

	s->type = SOCK_TYPE_UPLOAD;
	socket_tos_default(s);			/* Set proper Type of Service */

	u = upload_create(s, FALSE);
		
	/*
	 * Read HTTP headers fully, then call upload_request() when done.
	 */

	io_get_header(u, &u->io_opaque, bws.in, s, IO_HEAD_ONLY,
		call_upload_request, NULL, &upload_io_error);
}

/*
 * expect_http_header
 *
 * Prepare reception of a full HTTP header, including the leading request.
 * Will call upload_request() when everything has been parsed.
 */
void expect_http_header(gnutella_upload_t *u, upload_stage_t new_status)
{
	struct gnutella_socket *s = u->socket;

	g_assert(s->resource.upload == u);
	g_assert(s->getline == NULL);
	g_assert(u->io_opaque == NULL);

	u->status = new_status;
	upload_fire_upload_info_changed(u);

	/*
	 * We're requesting the reading of a "status line", which will be the
	 * HTTP request.  It will be stored in a created s->getline entry.
	 * Once we're done, we'll end-up in upload_request(): the path joins
	 * with the one used for direct uploading.
	 */

	io_get_header(u, &u->io_opaque, bws.in, s, IO_SAVE_FIRST,
		call_upload_request, NULL, &upload_io_error);
}

/*
 * upload_wait_new_request
 *
 * This is used for HTTP/1.1 persistent connections.
 *
 * Move the upload back to a waiting state, until a new HTTP request comes
 * on the socket.
 */
static void upload_wait_new_request(gnutella_upload_t *u)
{
	expect_http_header(u, GTA_UL_WAITING);
}

/*
 * upload_connect_conf
 *
 * Got confirmation that the connection to the remote host was OK.
 * Send the GIV/QUEUE string, then prepare receiving back the HTTP request.
 */
void upload_connect_conf(gnutella_upload_t *u)
{
	gchar giv[MAX_LINE_SIZE];
	struct gnutella_socket *s;
	gint rw;
	gint sent;

	g_assert(u);

	/*
	 * PARQ should send QUEUE information header here.
	 *		-- JA, 13/04/2003
	 */
	
	if (u->status == GTA_UL_QUEUE) {
		parq_upload_send_queue_conf(u);
		return;
	}
	
	g_assert(u->name);

	/*
	 * Send the GIV string, using our servent GUID.
	 */

	rw = gm_snprintf(giv, sizeof(giv), "GIV %u:%s/%s\n\n",
		u->index, guid_hex_str(guid), u->name);
	giv[sizeof(giv)-1] = '\0';			/* Might have been truncated */
	rw = MIN(sizeof(giv)-1, rw);
	
	s = u->socket;
	if (-1 == (sent = bws_write(bws.out, s->file_desc, giv, rw))) {
		g_warning("Unable to send back GIV for \"%s\" to %s: %s",
			u->name, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (sent < rw) {
		g_warning("Only sent %d out of %d bytes of GIV for \"%s\" to %s: %s",
			sent, rw, u->name, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (dbg > 2) {
		printf("----Sent GIV to %s:\n%.*s----\n", ip_to_gchar(s->ip), rw, giv);
		fflush(stdout);
	}

	if (sent != rw) {
		upload_remove(u, "Unable to send GIV");
		return;
	}

	/*
	 * We're now expecting HTTP headers on the connection we've made.
	 */

	expect_http_header(u, GTA_UL_HEADERS);
}

/*
 * upload_error_not_found
 * 
 * Send back an HTTP error 404: file not found,
 */
static void upload_error_not_found(gnutella_upload_t *u, const gchar *request)
{
	g_warning("bad request from %s: %s", ip_to_gchar(u->socket->ip), request);
	upload_error_remove(u, NULL, 404, "Not Found");
}

/* 
 * upload_http_version
 * 
 * Check that we got an HTTP request, extracting the protocol version.
 * Return TRUE if ok or FALSE otherwise (upload must then be aborted)
 */
static gboolean upload_http_version(
	gnutella_upload_t *u,
	header_t *header,
	gchar *request,
	gint len)
{
	gint http_major, http_minor;

	/*
	 * Check HTTP protocol version. --RAM, 11/04/2002
	 */

	if (!http_extract_version(request, len, &http_major, &http_minor)) {
		upload_error_remove(u, NULL, 500, "Unknown/Missing Protocol Tag");
		return FALSE;
	}

	u->http_major = http_major;
	u->http_minor = http_minor;

	return TRUE;
}

/* 
 * get_file_to_upload_from_index
 * 
 * Get the shared_file to upload. Request has been extracted already, and is
 * passed as request. The same holds for the file index, which is passed as
 * index.
 * Return the shared_file if found, NULL otherwise.
 */
static struct shared_file *get_file_to_upload_from_index(
	gnutella_upload_t *u,
	header_t *header,
	gchar *uri,
	guint idx)
{
	struct shared_file *sf;
	guchar c;
	gchar *buf;
	gchar *basename;
	gboolean sent_sha1 = FALSE;
	gchar digest[SHA1_RAW_SIZE];
	gchar *p;

	/*
	 * We must be cautious about file index changing between two scans,
	 * which may happen when files are moved around on the local library.
	 * If we serve the wrong file, and it's a resuming request, this will
	 * result in a corrupted file!
	 *		--RAM, 26/09/2001
	 *
	 * We now support URL-escaped queries.
	 *		--RAM, 16/01/2002
	 */

	sf = shared_file(idx);

	if (sf == SHARE_REBUILDING) {
		/* Retry-able by user, hence 503 */
		upload_error_remove(u, NULL, 503, "Library being rebuilt");
		return NULL;
	}

	/*
	 * Go to the basename of the file requested in the query.
	 * If we have one, `c' will point to '/' and `buf' to the start
	 * of the requested filename.
	 */

	buf = uri + sizeof("/get/");		/* Go after first index char */
	(void) url_unescape(buf, TRUE);		/* Index is escape-safe anyway */

	while ((c = *(guchar *) buf++) && c != '/')
		/* empty */;

	if (c != '/') {
		g_warning("malformed Gnutella HTTP URI: %s", uri);
		upload_error_remove(u, NULL, 400, "Malformed Gnutella HTTP request");
		return NULL;
	}

	/*
	 * Go patch the first space we encounter before HTTP to be a NUL.
	 * Indeed, the requesst shoud be "GET /get/12/foo.txt HTTP/1.0".
	 *
	 * Note that if we don't find HTTP/ after the space, it's not an
	 * error: they're just sending an HTTP/0.9 request, which is awkward
	 * but we accept it.
	 */

	p = strrchr(buf, ' ');
	if (p && p[1]=='H' && p[2]=='T' && p[3]=='T' && p[4]=='P' && p[5]=='/')
		*p = '\0';
	else
		p = NULL;

	basename = buf;

    if (u->name != NULL)
        atom_str_free(u->name);
    u->name = atom_str_get(basename);

	/*
	 * If we have a X-Gnutella-Content-Urn, check whether we got a valid
	 * SHA1 URN in there and extract it.
	 */

	if ((buf = header_get(header, "X-Gnutella-Content-Urn")))
		sent_sha1 = huge_extract_sha1(buf, digest);

	/*
	 * If they sent a SHA1, look whether we got a matching file.
	 * If we do, let them know the URL changed by returning a 301, otherwise
	 * it's a 404.
	 */

	if (sent_sha1) {
		struct shared_file *sfn;
		extern gint sha1_eq(gconstpointer a, gconstpointer b);

		/*
		 * If they sent a SHA1, maybe they have a download mesh as well?
		 *
		 * We ignore any mesh information when the SHA1 is not present
		 * because we cannot be sure that they are exact replicate of the
		 * file requested here.
		 *
		 *		--RAM, 19/06/2002
		 */

		huge_collect_locations(digest, header);

		/*
		 * They can share serveral clones of the same files, i.e. bearing
		 * distinct names yet having the same SHA1.  Therefore, check whether
		 * the SHA1 matches with what we found so far, and if it does,
		 * we found what they want.
		 */

		if (sf && sha1_hash_available(sf)) {
			if (!sha1_hash_is_uptodate(sf))
				goto sha1_recomputed;
			if (sha1_eq(digest, sf->sha1_digest))
				goto found;
		}

		/*
		 * Look whether we know this SHA1 at all, and compare the results
		 * with the file we found, if any.  Note that `sf' can be NULL at
		 * this point, in which case we'll redirect them with 301 if we
		 * know the hash.
		 */

		sfn = shared_file_by_sha1(digest);

		g_assert(sfn != SHARE_REBUILDING);	/* Or we'd have trapped above */

		if (sfn && sf != sfn) {
			gchar location[1024];
			gchar *escaped;

			if (!sha1_hash_is_uptodate(sfn))
				goto sha1_recomputed;

			/*
			 * Be nice to pushed downloads: returning a 301 currently means
			 * a connection close, and they might not be able to reach us.
			 * Transparently remap their request.
			 *
			 * We don't do it for regular connections though, because servents
			 * MUST be prepared to deal with redirection requests.
			 *
			 *		--RAM, 14/10/2002
			 */

			if (u->push) {
				if (dbg > 4) {
					printf("INDEX FIXED (push, SHA1 = %s): "
						"requested %u, serving %u: %s\n",
						sha1_base32(digest), idx,
						sfn->file_index, sfn->file_path);
				}
				sf = sfn;
				goto found;
			}

			escaped = url_escape(sfn->file_name);

			gm_snprintf(location, sizeof(location),
				"Location: http://%s/get/%d/%s\r\n",
				ip_port_to_gchar(listen_ip(), listen_port),
				sfn->file_index, escaped);

			upload_error_remove_ext(u, sfn, location,
				301, "Moved Permanently");

			if (escaped != sfn->file_name)
				g_free(escaped);
			return NULL;
		}
		else if (sf == NULL)
			goto urn_not_found;

		/* FALL THROUGH */
	}

	/*
	 * If `sf' is NULL, the index was incorrect.
	 *
	 * Maybe we have a unique file with the same basename.  If we do,
	 * transparently return it instead of what they requested.
	 *
	 * We don't return a 301 in that case because the user did not supply
	 * the X-Gnutella-Content-Urn.  Therefore it's an old servent, and it
	 * cannot know about the new 301 return I've introduced.
	 *
	 * (RAM notified the GDF about 301 handling on June 5th, 2002 only)
	 */

	if (sf == NULL) {
		sf = shared_file_by_name(basename);

		g_assert(sf != SHARE_REBUILDING);	/* Or we'd have trapped above */

		if (dbg > 4) {
			if (sf)
				printf("BAD INDEX FIXED: requested %u, serving %u: %s\n",
					idx, sf->file_index, sf->file_path);
			else
				printf("BAD INDEX NOT FIXED: requested %u: %s\n",
					idx, basename);
		}

	} else if (0 != strncmp(basename, sf->file_name, sf->file_name_len)) {
		struct shared_file *sfn = shared_file_by_name(basename);

		g_assert(sfn != SHARE_REBUILDING);	/* Or we'd have trapped above */

		if (dbg > 4) {
			if (sfn)
				printf("INDEX FIXED: requested %u, serving %u: %s\n",
					idx, sfn->file_index, sfn->file_path);
			else
				printf("INDEX MISMATCH: requested %u: %s (has %s)\n",
					idx, basename, sf->file_name);
		}

		if (sfn == NULL) {
			upload_error_remove(u, NULL, 409, "File index/name mismatch");
			return NULL;
		} else
			sf = sfn;
	}

	if (sf == NULL) {
		upload_error_not_found(u, uri);
		return NULL;
	}

found:
	g_assert(sf != NULL);

	if (p) *p = ' ';			/* Restore patched space */

	return sf;

urn_not_found:
	upload_error_remove(u, NULL, 404, "URN Not Found (urn:sha1)");
	return NULL;

sha1_recomputed:
	upload_error_remove(u, NULL, 503, "SHA1 is being recomputed");
	return NULL;
}

static const char n2r_query[] = "/uri-res/N2R?";

#define N2R_QUERY_LENGTH	(sizeof(n2r_query) - 1)

/* 
 * get_file_to_upload_from_urn
 * 
 * Get the shared_file to upload from a given URN.
 * Return the shared_file if we have it, NULL otherwise
 */
static struct shared_file *get_file_to_upload_from_urn(
	gnutella_upload_t *u,
	header_t *header,
	const gchar *uri)
{
	gchar hash[SHA1_BASE32_SIZE + 1];
	gchar digest[SHA1_RAW_SIZE];
	const gchar *urn = uri + N2R_QUERY_LENGTH;
	struct shared_file *sf;
	gint skip;

	/*
	 * We currently only support SHA1, but this allows us to process
	 * both "urn:sha1:" and "urn:bitprint:" URNs.
	 *		--RAM, 16/11/2002
	 */

	if (0 == strncasecmp(urn, "urn:sha1:", 9))
		skip = 9;
	else if (0 == strncasecmp(urn, "urn:bitprint:", 13))
		skip = 13;
	else {
		upload_error_not_found(u, uri);			/* Unknown URN => not found */
		return NULL;
	}

	if (1 != sscanf(urn + skip, "%32s", hash))
		goto malformed;

	hash[SHA1_BASE32_SIZE] = '\0';

	if (!huge_http_sha1_extract32(hash, digest))
		goto malformed;

	huge_collect_locations(digest, header);

	sf = shared_file_by_sha1(digest);

    if (u->name != NULL)
        atom_str_free(u->name);
    u->name = atom_str_get(urn);

	if (sf == SHARE_REBUILDING) {
		/* Retry-able by user, hence 503 */
		upload_error_remove(u, NULL, 503, "Library being rebuilt");
		return NULL;
	}

	if (sf == NULL)
		upload_error_not_found(u, uri);

	return sf;

malformed:
	upload_error_remove(u, NULL, 400, "Malformed URN in /uri-res request");
	return NULL;
}

/*
 * get_file_to_upload
 * 
 * A dispatcher function to call either get_file_to_upload_from_index or
 * get_file_to_upload_from_sha1 depending on the syntax of the request.
 *
 * Return the shared_file if we got it, or NULL otherwise.
 * When NULL is returned, we have sent the error back to the client.
 */
static struct shared_file *get_file_to_upload(
	gnutella_upload_t *u, header_t *header, gchar *request)
{
	guint idx = 0;
	gchar *uri;
	gchar s;

	/*
	 * We have either "GET uri" or "HEAD uri" at this point.  Since the
	 * value sizeof("GET") accounts for the trailing NUL as well, the
	 * following will skip the space as well and point to the beginning
	 * of the requested URI.
	 */

	uri = request + ((request[0] == 'G') ? sizeof("GET") : sizeof("HEAD"));

    if (u->name == NULL)
        u->name = atom_str_get(uri);

	/*
	 * Because of a bug in sscanf(), we must end the format with a parameter,
	 * since sscanf() will ignore whatever lies afterwards.
	 */

	if (2 == sscanf(uri, "/get/%u%c", &idx, &s) && s == '/')
		return get_file_to_upload_from_index(u, header, uri, idx);
	else if (0 == strncmp(uri, n2r_query, N2R_QUERY_LENGTH))
		return get_file_to_upload_from_urn(u, header, uri);

	upload_error_not_found(u, request);
	return NULL;
}

/*
 * upload_http_xhost_add
 *
 * This routine is called by http_send_status() to generate the
 * X-Host line (added to the HTTP status) into `buf'.
 */
static void upload_http_xhost_add(gchar *buf, gint *retval, gpointer arg)
{
	gint rw = 0;
	gint length = *retval;
	guint32 ip;
	guint16 port;

	g_assert(!is_firewalled);

	ip = listen_ip();
	port = listen_port;

	if (host_is_valid(ip, port)) {
		const gchar *xhost = ip_port_to_gchar(ip, port);
		gint needed_room = strlen(xhost) + sizeof("X-Host: \r\n") - 1;
		if (length > needed_room)
			rw = gm_snprintf(buf, length, "X-Host: %s\r\n", xhost);
	}

	g_assert(rw < length);

	*retval = rw;
}

/*
 * upload_http_sha1_add
 *
 * This routine is called by http_send_status() to generate the
 * SHA1-specific headers (added to the HTTP status) into `buf'.
 */
static void upload_http_sha1_add(gchar *buf, gint *retval, gpointer arg)
{
	gint rw = 0;
	gint length = *retval;
	struct upload_http_cb *a = (struct upload_http_cb *) arg;
	gint needed_room;

	/*
	 * Room for header + base32 SHA1 + crlf
	 */

	needed_room = 33 + SHA1_BASE32_SIZE + 2;

	if (length - rw > needed_room)
		rw += gm_snprintf(buf, length,
			"X-Gnutella-Content-URN: urn:sha1:%s\r\n",
			sha1_base32(a->sf->sha1_digest));

	if (rw < length) {
		time_t now = time(NULL);
		gnutella_upload_t *u = a->u;

		guint32 last_sent;

		/*
		 * Because of possible persistent uplaods, we have to keep track on
		 * the last time we sent download mesh information within the upload
		 * itself: the time for them to download a range will be greater than
		 * our expiration timer on the external mesh information.
		 */

		last_sent = u->last_dmesh ?
			u->last_dmesh :
			mi_get_stamp(u->socket->ip, a->sf->sha1_digest, now);

		rw += dmesh_alternate_location(a->sf->sha1_digest,
			&buf[rw], length - rw, u->socket->ip, last_sent);

		u->last_dmesh = now;
	}

	*retval = rw;
}

/*
 * upload_416_extra
 *
 * This routine is called by http_send_status() to generate the
 * additionnal headers on a "416 Request range not satisfiable" error.
 */
static void upload_416_extra(gchar *buf, gint *retval, gpointer arg)
{
	gint rw = 0;
	gint length = *retval;
	const struct upload_http_cb *a = (const struct upload_http_cb *) arg;
	const gnutella_upload_t *u = a->u;

	rw = gm_snprintf(buf, length,
		"Content-Range: bytes */%u\r\n", u->file_size);

	g_assert(rw < length);

	*retval = rw;
}

/*
 * upload_http_status
 *
 * This routine is called by http_send_status() to generate the
 * upload-specific headers into `buf'.
 */
static void upload_http_status(gchar *buf, gint *retval, gpointer arg)
{
	gint rw = 0;
	gint length = *retval;
	struct upload_http_cb *a = (struct upload_http_cb *) arg;
	gnutella_upload_t *u = a->u;

	if (!u->keep_alive)
		rw = gm_snprintf(buf, length, "Connection: close\r\n");

	rw += gm_snprintf(&buf[rw], length - rw,
		"Date: %s\r\n"
		"Last-Modified: %s\r\n"
		"Content-Type: application/binary\r\n"
		"Content-Length: %u\r\n",
			date_to_rfc822_gchar(a->now), date_to_rfc822_gchar2(a->mtime),
			u->end - u->skip + 1);

	g_assert(rw < length);

	if (u->skip || u->end != (u->file_size - 1))
	  rw += gm_snprintf(&buf[rw], length - rw,
		"Content-Range: bytes %u-%u/%u\r\n", u->skip, u->end, u->file_size);

	g_assert(rw < length);

	/*
	 * Propagate the SHA1 information for the file, if we have it.
	 */

	if (sha1_hash_is_uptodate(a->sf)) {
		gint remain = length - rw;

		if (remain > 0) {
			upload_http_sha1_add(&buf[rw], &remain, arg);
			rw += remain;
		}
	}

	*retval = rw;
}

/*
 * upload_request
 *
 * Called to initiate the upload once all the HTTP headers have been
 * read.  Validate the request, and begin processing it if all OK.
 * Otherwise cancel the upload.
 */
static void upload_request(gnutella_upload_t *u, header_t *header)
{
	struct gnutella_socket *s = u->socket;
	struct shared_file *reqfile = NULL;
    guint idx = 0, skip = 0, end = 0, upcount = 0;
	gchar *fpath = NULL;
	gchar *user_agent = 0;
	gchar *buf;
	gchar *request = getline_str(s->getline);
	GSList *l;
	gboolean head_only;
	gboolean has_end = FALSE;
	struct stat statbuf;
	time_t mtime, now = time((time_t *) NULL);
	struct upload_http_cb cb_arg;
	struct upload_http_cb cb_parq_arg;
	gint http_code;
	const gchar *http_msg;
	http_extra_desc_t hev[3];
	gint hevcnt = 0;
	guchar *sha1;
	gboolean is_followup = 
		u->status == GTA_UL_WAITING;
	gboolean faked = FALSE;
	gchar *token;
	gpointer parq_handle = NULL;
	extern gint sha1_eq(gconstpointer a, gconstpointer b);

	if (dbg > 2) {
		printf("----%s Request from %s:\n",
			is_followup ? "Follow-up" : "Incoming",
			ip_to_gchar(s->ip));
		printf("%s\n", request);
		header_dump(header, stdout);
		printf("----\n");
		fflush(stdout);
	}

	/*
	 * Technically, we have not started sending anything yet, but this
	 * also serves as a marker in case we need to call upload_remove().
	 * It will not send an HTTP reply by itself.
	 */

	u->status = GTA_UL_SENDING;
	u->last_update = time((time_t *) 0);	/* Done reading headers */

	/*
	 * If we remove the upload in upload_remove(), we'll decrement
	 * running_uploads.  However, for followup-requests, the upload slot
	 * is already accounted for.
	 */

	/* This is for the moment being done if the upload really seems to be 
	 * getting an upload slot. This is to avoid messing with active queuing
	 *		-- JA, 09/05/03
	 */
	if (!is_followup)
		running_uploads++;

	/*
	 * If `head_only' is true, the request was a HEAD and we're only going
	 * to send back the headers.
	 */

	head_only = (request[0] == 'H');

	/* 
	 * Extract User-Agent.
	 *
	 * X-Token: GTKG token
	 * User-Agent: whatever
	 * Server: whatever (in case no User-Agent)
	 */

	token = header_get(header, "X-Token");
	user_agent = header_get(header, "User-Agent");

	/* Maybe they sent a Server: line, thinking they're a server? */
	if (!user_agent)
		user_agent = header_get(header, "Server");

	if (user_agent)
		faked = !version_check(user_agent, token);

	if (!is_followup && user_agent) {
		if (faked) {
			gchar *name = g_strdup_printf("!%s", user_agent);
			u->user_agent = atom_str_get(name);
			g_free(name);
		} else
			u->user_agent = atom_str_get(user_agent);
	}

	/*
	 * Make sure there is the HTTP/x.x tag at the end of the request,
	 * thereby ruling out the HTTP/0.9 requests.
	 *
	 * This has to be done early, and before calling get_file_to_upload()
	 * or the getline_length() call will no longer represent the length of
	 * the string, since URL-unescaping happens inplace and can "shrink"
	 * the request.
	 */

	if (!upload_http_version(u, header, request, getline_length(s->getline)))
		return;

	/*
	 * IDEA
	 *
	 * To prevent people from hammering us, we should setup a priority queue
	 * coupled to a hash table for fast lookups, where we would record the
	 * last failed attempt and when it was.	As soon as there is a request,
	 * we would move the record for the IP address at the beginning of the
	 * queue, and drop the tail when we reach our size limit.
	 *
	 * Then, if we discover that a given IP re-issues too frequent requests,
	 * we would start differing our reply by not sending the error immediately
	 * but scheduling that some time in the future.	We would begin to use
	 * many file descriptors that way, so we trade CPU time for another scarce
	 * resource.  However, if someone is hammering us with connections,
	 * he would have to wait for our reply before knowing the failure, and
	 * it would slow him down, even if he retried immediately.
	 *
	 * Alternatively, instead of differing the 503 reply, we could send a
	 * "403 Forbidden to bad citizens" instead, and chances are that servents
	 * abort retries on failures other than 503...
	 *
	 *				--RAM, 09/09/2001
	 */

	reqfile = get_file_to_upload(u, header, request);

	if (!reqfile) {
		/* get_file_to_upload() has signaled the error already */
		return;
	}

	/*
	 * Check vendor-specific banning.
	 */

	if (user_agent) {
		const gchar *msg = ban_vendor(user_agent);

		if (msg != NULL) {
			upload_error_remove(u, NULL, 403, msg);
			return;
		}
	}

	idx = reqfile->file_index;
	sha1 = sha1_hash_available(reqfile) ? reqfile->sha1_digest : NULL;

	/*
	 * If we pushed this upload, and they are not requesting the same
	 * file, that's OK, but warn.
	 *		--RAM, 31/12/2001
	 */

	if (u->push && idx != u->index)
		g_warning("Host %s sent PUSH for %u (%s), now requesting %u (%s)",
			ip_to_gchar(u->ip), u->index, u->name, idx, reqfile->file_name);

	/*
	 * We already have a non-NULL u->name in the structure, because we
     * saved the uri there or the name from a push request.
     * However, we want to display the actual name of the shared file.
	 *		--Richard, 20/11/2002
	 */

	u->index = idx;
	if (!u->sha1 && sha1)
		u->sha1 = atom_sha1_get(sha1);	/* Identify file for followup reqs */

    if (u->name != NULL)
        atom_str_free(u->name);

    u->name = atom_str_get(reqfile->file_name);

	/*
	 * Range: bytes=10453-23456
	 */

	buf = header_get(header, "Range");
	if (buf && reqfile->file_size != 0) {
		http_range_t *r;
		GSList *ranges =
			http_range_parse("Range", buf,  reqfile->file_size, user_agent);

		if (ranges == NULL) {
			upload_error_remove(u, NULL, 400, "Malformed Range request");
			return;
		}

		/*
		 * We don't properly support multiple ranges yet.
		 * Just pick the first one, but warn so we know when people start
		 * requesting multiple ranges at once.
		 *		--RAM, 27/01/2003
		 */

		if (g_slist_next(ranges) != NULL) {
			if (dbg) g_warning("client %s <%s> requested several ranges "
				"for \"%s\": %s", ip_to_gchar(u->ip),
				u->user_agent ? u->user_agent : "", reqfile->file_name,
				http_range_to_gchar(ranges));
		}

		r = (http_range_t *) ranges->data;

		g_assert(r->start <= r->end);
		g_assert(r->end < reqfile->file_size);

		skip = r->start;
		end = r->end;
		has_end = TRUE;

		http_range_free(ranges);
	}

	/*
	 * Validate the requested range.
	 */

	fpath = reqfile->file_path;
	u->file_size = reqfile->file_size;

	if (!has_end)
		end = u->file_size - 1;

	u->skip = skip;
	u->end = end;
	u->pos = skip;

	/*
	 * If this is a pushed upload, and we are not firewalled, then tell
	 * them they can reach us directly by outputting an X-Host line.
	 */

	if (u->push && !is_firewalled) {
		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = upload_http_xhost_add;
		hev[hevcnt++].he_arg = NULL;
	}

	/*
	 * When requested range is invalid, the HTTP 416 reply should contain
	 * a Content-Range header giving the total file size, so that they
	 * know the limits of what they can request.
	 */

	if (skip >= u->file_size || end >= u->file_size) {
		const gchar *msg = "Requested range not satisfiable";

		cb_arg.u = u;
		cb_arg.sf = reqfile;

		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = upload_416_extra;
		hev[hevcnt++].he_arg = &cb_arg;

		(void) http_send_status(u->socket, 416, FALSE, hev, hevcnt, msg);
		upload_remove(u, msg);
		return;
	}

	/*
	 * If HTTP/1.1 or above, check the Host header.
	 *
	 * We require it because HTTP does, but we don't really care for
	 * now.  Moreover, we might not know our external IP correctly,
	 * so we have little ways to check that the Host refers to us.
	 *
	 *		--RAM, 11/04/2002
	 */

	if ((u->http_major == 1 && u->http_minor >= 1) || u->http_major > 1) {
		const gchar *host = header_get(header, "Host");

		if (host == NULL) {
			upload_error_remove(u, NULL, 400, "Missing Host Header");
			return;
		}
	}

	/*
	 * If we don't share, abort. --RAM, 11/01/2002
	 * Use 5xx error code, it's a server-side problem --RAM, 11/04/2002
	 *
	 * We do that quite late in the process to be able to gather as
	 * much as possible from the request for tracing in the GUI.
	 * Also, if they request something wrong, they ought to know it ASAP.
	 */

	if (!upload_is_enabled()) {
		upload_error_remove(u, NULL, 503, "Sharing currently disabled");
		return;
	}

	/*
	 * We now have enough information to display the request in the GUI.
	 */

	upload_fire_upload_info_changed(u);

	/*
	 * A follow-up request must be for the same file, since the slot is
	 * allocated on the basis of one file.  We compare SHA1s if available,
	 * otherwise indices, in case the library has been rebuilt.
	 */

	if (
		is_followup &&
		!(sha1 && u->sha1 && sha1_eq(sha1, u->sha1)) && idx != u->index
	) {
		g_warning("Host %s sent initial request for %u (%s), "
			"now requesting %u (%s)",
			ip_to_gchar(s->ip),
			u->index, u->name, idx, reqfile->file_name);
		upload_error_remove(u, NULL, 400, "Change of Resource Forbidden");
		return;
	}

	/*
	 * We let all HEAD request go through, whether we're busy or not, since
	 * we only send back the header.
	 *
	 * Follow-up requests already have their slots.
	 */

	if (!head_only) {
		parq_handle = parq_upload_get(u, header);

		if (parq_handle == NULL) {
			upload_error_remove(u, reqfile, 503, "Queue full");
			return;
		}
	}

	if (!(head_only || is_followup)) {
		/*
		 * Ensure that noone tries to download the same file twice, and
		 * that they don't get beyond the max authorized downloads per IP.
		 * NB: SHA1 are atoms, so it's OK to compare their addresses.
		 */

		for (l = uploads; l; l = l->next) {
			gnutella_upload_t *up = (gnutella_upload_t *) (l->data);
			g_assert(up);
			if (up == u)
				continue;				/* Current upload is already in list */
			if (!UPLOAD_IS_SENDING(up) && up->status != GTA_UL_QUEUED)
				continue;
			if (
				up->socket->ip == s->ip &&
				(up->index == idx || (u->sha1 && up->sha1 == u->sha1))
			) {
				upload_error_remove(u, NULL, 503,
					"Already downloading that file");
				return;
			}
			if (up->socket->ip == s->ip && ++upcount >= max_uploads_ip) {
				upload_error_remove(u, reqfile,
					503, "Only %u download%s per IP address",
					max_uploads_ip, max_uploads_ip == 1 ? "" : "s");
				return;
			}
		}

		/*
		 * Even though this test is less costly than the previous ones, doing
		 * it afterwards allows them to be notified of a mismatch whilst they
		 * wait for a download slot.  It would be a pity for them to get
		 * a slot and be told about the mismatch only then.
		 *		--RAM, 15/12/2001
		 *
 		 * Althought the uploads slots are full, we could try to queue
		 * the download in PARQ. If this also fails, than the requesting client
		 * is out of luck.
		 *		--JA, 05/02/2003
		 *
		 */		

		if (!parq_upload_request(u, parq_handle, running_uploads - 1)) {
			gboolean parq_allows = FALSE;
			
			if (parq_upload_lookup_position(u) == -1) {
				/*
				 * Looks like upload got removed from PARQ queue. For now this
				 * only happens when a client got banned. Bye bye!
			 	 *		-- JA, 19/05/'03
				 */
				upload_error_remove(u, reqfile, 403, 
					"Retry-After not honoured. Removed from PARQ queue");
				return;
			}

			/*
		 	* Support for bandwith-dependent number of upload slots.
		 	* The upload bandwith limitation has to be enabled, otherwise
		 	* we can not be sure that we have reasonable values for the
		 	* outgoing bandwith set.
		 	*		--TF 30/05/2002
		 	*
		 	* NB: if max_uploads is 0, then we disable sharing, period.
		 	*
		 	* Require that BOTH the average and "instantaneous" usage be
		 	* lower than the minimum to trigger the override.  This will
		 	* make it more robust when bandwidth stealing is enabled.
		 	*		--RAM, 27/01/2003
		 	*
		 	*/

			if (
				upload_is_enabled() &&
				bw_ul_usage_enabled &&
				bws_out_enabled &&
				bsched_pct(bws.out) < ul_usage_min_percentage &&
				bsched_avg_pct(bws.out) < ul_usage_min_percentage
			) {
				if (parq_upload_request_force(
						u, parq_handle, running_uploads - 1)) {
					parq_allows = TRUE;
					if (dbg > 4)
						printf("Overriden slot limit because u/l b/w used at "
							"%d%% (minimum set to %d%%)\n",
							bsched_avg_pct(bws.out), ul_usage_min_percentage);
				}
			}
			
			if (!parq_allows) {
				if (u->status == GTA_UL_QUEUED) {
					/*
					 * Cleanup data structures.
					 */

					io_free(u->io_opaque);
					g_assert(u->io_opaque == NULL);

					getline_free(s->getline);
					s->getline = NULL;

					send_upload_error(u, reqfile, 503, 
						  "Queued (slot %d, ETA: %s)", 
						  parq_upload_lookup_position(u), 
						  short_time(parq_upload_lookup_eta(u)));

					u->error_sent = 0;	/* Any new request should be allowed
										   to retreive an error code */
	
					/* Avoid data timeout */
					u->last_update = parq_upload_lookup_lifetime(u) -
						  upload_connected_timeout;

					running_uploads--;	/* will get increased next time
										   upload_request is called */

					expect_http_header(u, GTA_UL_QUEUED);
					return;
				} else
				if (parq_upload_queue_full(u)) {
					upload_error_remove(u, reqfile, 503, "Queue full");
				} else {
					upload_error_remove(u, reqfile,	503, 
						"Queued (slot %d, ETA: %s)", 
						parq_upload_lookup_position(u), 
						short_time(parq_upload_lookup_eta(u)));
				}
				return;
			}
		}
	}

	if (!head_only)
		parq_upload_busy(u, parq_handle);
	
	/*
	 * Do we have to keep the connection after this request?
	 */

	buf = header_get(header, "Connection");

	if (u->http_major > 1 || (u->http_major == 1 && u->http_minor >= 1)) {
		/* HTTP/1.1 or greater -- defaults to persistent connections */
		u->keep_alive = TRUE;
		if (buf && 0 == strcasecmp(buf, "close"))
			u->keep_alive = FALSE;
	} else {
		/* HTTP/1.0 or lesser -- must request persistence */
		u->keep_alive = FALSE;
		if (buf && 0 == strcasecmp(buf, "keep-alive"))
			u->keep_alive = TRUE;
	}

	if (-1 == stat(fpath, &statbuf)) {
		upload_error_not_found(u, request);
		return;
	}

	/*
	 * Ensure that a given persistent connection never requests more than
	 * the total file length.  Add 0.5% to account for partial overlapping
	 * ranges.
	 */

	u->total_requested += end - skip + 1;

	if (u->total_requested > u->file_size * 1.005) {
		g_warning("Host %s requesting more than there is to %u (%s)",
			ip_to_gchar(s->ip), u->index, u->name);
		upload_error_remove(u, NULL, 400, "Requesting Too Much");
		return;
	}

	/* Open the file for reading , READONLY just in case. */
	if ((u->file_desc = open(fpath, O_RDONLY)) < 0) {
		upload_error_not_found(u, request);
		return;
	}

#ifndef HAVE_SENDFILE
	/* If we got a valid skip amount then jump ahead to that position */
	if (u->skip > 0) {
		if (-1 == lseek(u->file_desc, u->skip, SEEK_SET)) {
			upload_error_remove(u, NULL,
				500, "File seek error: %s", g_strerror(errno));
			return;
		}
	}

	u->bpos = 0;
	u->bsize = 0;

	if (!is_followup) {
		u->buf_size = READ_BUF_SIZE * sizeof(gchar);
		u->buffer = (gchar *) g_malloc(u->buf_size);
	}
#endif	/* !HAVE_SENDFILE */

	/*
	 * Set remaining upload information
	 */

	u->start_date = time((time_t *) NULL);
	u->last_update = time((time_t *) 0);

	/*
	 * Prepare date and modification time of file.
	 */

	mtime = statbuf.st_mtime;
	if (mtime > now)
		mtime = now;			/* Clock skew on file server */

	/*
	 * On linux, turn TCP_CORK on so that we only send out full TCP/IP
	 * frames.  The exact size depends on your LAN interface, but on
	 * Ethernet, it's about 1500 bytes.
	 */

	sock_cork(s, TRUE);

	/*
	 * Send back HTTP status.
	 */

	if (u->skip || u->end != (u->file_size - 1)) {
		http_code = 206;
		http_msg = "Partial Content";
	} else {
		http_code = 200;
		http_msg = "OK";
	}

	/*
	 * PARQ ID, emitted if needed.
	 *
	 * We do that before calling upload_http_status() to avoid lacking
	 * room in the headers, should there by any alternate location present.
	 *
	 * We never emit the queue ID for HEAD requests, nor during follow-ups
	 * (which always occur for the same resource, meaning the PARQ ID was
	 * arlready sent for those).
	 */

	if (!head_only && !is_followup && !parq_ul_id_sent(u)) {
		cb_parq_arg.u = u;

		hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
		hev[hevcnt].he_cb = parq_upload_add_header_id;
		hev[hevcnt++].he_arg = &cb_parq_arg;
	}

	/*
	 * Date, Content-Length, etc...
	 */

	cb_arg.u = u;
	cb_arg.now = now;
	cb_arg.mtime = mtime;
	cb_arg.sf = reqfile;

	hev[hevcnt].he_type = HTTP_EXTRA_CALLBACK;
	hev[hevcnt].he_cb = upload_http_status;
	hev[hevcnt++].he_arg = &cb_arg;

	if (!http_send_status(u->socket, http_code, FALSE, hev, hevcnt, http_msg)) {
		upload_remove(u, "Cannot send whole HTTP status");
		return;
	}

	/*
	 * Cleanup data structures.
	 */

	io_free(u->io_opaque);
	u->io_opaque = NULL;

	getline_free(s->getline);
	s->getline = NULL;

	/*
	 * If we need to send only the HEAD, we're done. --RAM, 26/12/2001
	 */

	if (head_only) {
		if (u->keep_alive)
			upload_wait_new_request(u);
		else
			upload_remove(u, NULL);		/* No message, everything was OK */
		return;
	}

	/*
	 * Install the output I/O, which is via a bandwidth limited source.
	 */

	g_assert(s->gdk_tag == 0);
	g_assert(u->bio == NULL);
	
	u->bio = bsched_source_add(bws.out, s->file_desc,
		BIO_F_WRITE, upload_write, (gpointer) u);

	upload_stats_file_begin(u);
}

/*
 * upload_write
 *
 * Called when output source can accept more data.
 */
static void upload_write(gpointer up, gint source, inputevt_cond_t cond)
{
	gnutella_upload_t *u = (gnutella_upload_t *) up;
	gint written;
	guint32 amount;
	guint32 available;
#ifdef HAVE_SENDFILE
	off_t pos;				/* For sendfile() sanity checks */
#endif	/* !HAVE_SENDFILE */

	if (!(cond & INPUT_EVENT_WRITE)) {
		/* If we can't write then we don't want it, kill the socket */
		if (dbg)
			printf("upload_write(); Condition %i, Exception = %i\n",
				   cond, INPUT_EVENT_EXCEPTION);
		upload_remove(u, "Write exception");
		return;
	}

#ifdef HAVE_SENDFILE
	/*
	 * Compute the amount of bytes to send.
	 * Use the two variables to avoid warnings about unused vars by compiler.
	 */

	amount = u->end - u->pos + 1;
	available = amount > READ_BUF_SIZE ? READ_BUF_SIZE : amount;

	g_assert(amount > 0);

	pos = u->pos;
	written = bio_sendfile(u->bio, u->file_desc, &u->pos, available);

	g_assert(written == -1 || written == u->pos - pos);

#else	/* !HAVE_SENDFILE */

	/*
	 * Compute the amount of bytes to send.
	 */

	amount = u->end - u->pos + 1;

	g_assert(amount > 0);

	/*
	 * If the buffer position reached the size, then we need to read
	 * more data from the file.
	 */

	if (u->bpos == u->bsize) {
		if ((u->bsize = read(u->file_desc, u->buffer, u->buf_size)) == -1) {
			upload_remove(u, "File read error: %s", g_strerror(errno));
			return;
		}
		if (u->bsize == 0) {
			upload_remove(u, "File EOF?");
			return;
		}
		u->bpos = 0;
	}

	available = u->bsize - u->bpos;
	if (available > amount)
		available = amount;

	g_assert(available > 0);

	written = bio_write(u->bio, &u->buffer[u->bpos], available);

#endif	/* HAVE_SENDFILE */

	if (written ==  -1) {
		if (errno != EAGAIN)
			upload_remove(u, "Data write error: %s", g_strerror(errno));
		return;
	} else if (written == 0) {
		upload_remove(u, "No bytes written, source may be gone");
		return;
	}

#ifndef HAVE_SENDFILE
	/*
	 * Only required when not using sendfile(), otherwise the u->pos field
	 * is directly updated by the kernel, and u->bpos is unused.
	 *		--RAM, 21/02/2002
	 */

	u->pos += written;
	u->bpos += written;
#endif

	gnet_prop_set_guint32_val(PROP_UL_BYTE_COUNT, ul_byte_count + written);

	u->last_update = time((time_t *) NULL);

	/* This upload is complete */
	if (u->pos > u->end) {
		/*
		 * We do the following before cloning, since this will reset most
		 * of the information, including the upload name.  If they chose
		 * to clear uploads immediately, they will incur a small overhead...
		 */
		u->status = GTA_UL_COMPLETE;

        gnet_prop_set_guint32_val(PROP_TOTAL_UPLOADS, total_uploads + 1);
		upload_stats_file_complete(u);
        upload_fire_upload_info_changed(u); /* gui must update last state */
		u->accounted = TRUE;		/* Called upload_stats_file_complete() */

		/*
		 * If we're going to keep the connection, we must clone the upload
		 * structure, since it is associated to the GUI entry.
		 */

		if (u->keep_alive) {
			gnutella_upload_t *cu = upload_clone(u);
			upload_wait_new_request(cu);
			/*
			 * Don't decrement counters, we're still using the same slot.
			 */
		} else {
			registered_uploads--;
			running_uploads--;
			parq_upload_remove(u);
		}

		upload_remove(u, NULL);

		return;
	}
}

/*
 * upload_kill
 *
 * Kill a running upload.
 */
void upload_kill(gnet_upload_t upload)
{
    gnutella_upload_t *u = upload_find_by_handle(upload);

    g_assert(u != NULL);

    if (!UPLOAD_IS_COMPLETE(u)) {
		parq_upload_force_remove(u);
        upload_remove(u, "Explicitly killed");
	}
}

/*
 * upload_is_enabled
 *
 * Check whether uploading is enabled: we have slots, and bandwidth.
 */
gboolean upload_is_enabled(void)
{
	if (max_uploads == 0)
		return FALSE;

	if (bsched_bwps(bws.out) < BW_OUT_MIN)
		return FALSE;

	return TRUE;
}

/*
 * upload_init
 *
 * Initialize uploads.
 */
void upload_init(void)
{
	mesh_info = g_hash_table_new(mi_key_hash, mi_key_eq);
    upload_handle_map = idtable_new(32, 32);
}

void upload_close(void)
{
	GSList *l;

	for (l = uploads; l; l = l->next) {
		gnutella_upload_t *u = (gnutella_upload_t *) l->data;
		if (UPLOAD_IS_SENDING(u) && !u->accounted)
			upload_stats_file_aborted(u);
		upload_free_resources(u);
		wfree(u, sizeof(*u));
	}

    idtable_destroy(upload_handle_map);
    upload_handle_map = NULL;

	g_slist_free(uploads);

	g_hash_table_foreach(mesh_info, mi_free_kv, NULL);
	g_hash_table_destroy(mesh_info);
}

gnet_upload_info_t *upload_get_info(gnet_upload_t uh)
{
    gnutella_upload_t *u = upload_find_by_handle(uh); 
    gnet_upload_info_t *info;

    info = walloc(sizeof(*info));

    info->name          = u->name ? atom_str_get(u->name) : NULL;
    info->ip            = u->ip;
    info->file_size     = u->file_size;
    info->range_start   = u->skip;
    info->range_end     = u->end;
    info->start_date    = u->start_date;
    info->user_agent    = u->user_agent ? atom_str_get(u->user_agent) : NULL;
    info->upload_handle = u->upload_handle;
	info->push          = u->push;
	
    return info;
}

void upload_free_info(gnet_upload_info_t *info)
{
    g_assert(info != NULL);

	if (info->user_agent)
		atom_str_free(info->user_agent);
	if (info->name)
		atom_str_free(info->name);

    wfree(info, sizeof(*info));
}

void upload_get_status(gnet_upload_t uh, gnet_upload_status_t *si)
{
    gnutella_upload_t *u = upload_find_by_handle(uh); 
	time_t now = time((time_t *) NULL);
    g_assert(si != NULL); 

    si->status      = u->status;
    si->pos         = u->pos;
    si->bps         = 1;
    si->avg_bps     = 1;
    si->last_update = u->last_update;

	si->parq_queue_no = parq_upload_lookup_queue_no(u);
	si->parq_position = parq_upload_lookup_position(u);
	si->parq_size = parq_upload_lookup_size(u);
	si->parq_lifetime = MAX(0, (gint32) (parq_upload_lookup_lifetime(u) - now));
	si->parq_retry = MAX(0, (gint32) (parq_upload_lookup_retry(u) - now));

    if (u->bio) {
        si->bps = bio_bps(u->bio);
		si->avg_bps = bio_avg_bps(u->bio);
	}

    if (si->avg_bps <= 10 && u->last_update != u->start_date)
        si->avg_bps = (u->pos - u->skip) / (u->last_update - u->start_date);
	if (si->avg_bps == 0)
        si->avg_bps++;
	
	
	
}
