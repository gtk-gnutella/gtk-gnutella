
/* Handles upload of our files to others users */

#include "gnutella.h"
#include "interface.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "sockets.h"
#include "share.h"
#include "gui.h"
#include "misc.h"
#include "getline.h"
#include "header.h"
#include "hosts.h"		/* for check_valid_host() */
#include "url.h"
#include "bsched.h"

GSList *uploads = NULL;
gint running_uploads = 0;
gint registered_uploads = 0;

guint32 count_uploads = 0;

/*
 * This structure is used to encapsulate the various arguments required
 * by the header parsing I/O callback.
 */
struct io_header {
	struct upload *upload;
	header_t *header;
	getline_t *getline;
	void (*process_header)(struct io_header *);
	gint flags;
};

#define IO_STATUS_LINE		0x00000002	/* First line is a status line */

static void upload_request(struct upload *u, header_t *header);
static void send_upload_error(struct upload *u, int code, guchar *msg, ...);

/*
 * upload_timer
 *
 * Upload heartbeat timer.
 */
void upload_timer(time_t now)
{
	GSList *l;
	GSList *remove = NULL;
	guint32 t;

	for (l = uploads; l; l = l->next) {
		struct upload *u = (struct upload *) l->data;

		if (UPLOAD_IS_COMPLETE(u))
			continue;					/* Complete, no timeout possible */

		if (UPLOAD_IS_VISIBLE(u))
			gui_update_upload(u);

		/*
		 * Check for timeouts.
		 */

		t = UPLOAD_IS_CONNECTING(u) ?
				upload_connecting_timeout :
				upload_connected_timeout;

		/*
		 * We can't call upload_remove() since it will remove the upload
		 * from the list we are traversing.
		 */

		if (now - u->last_update > t)
			remove = g_slist_append(remove, u);
	}

	for (l = remove; l; l = l->next) {
		struct upload *u = (struct upload *) l->data;
		if (UPLOAD_IS_CONNECTING(u)) {
			gchar *msg = "Request timeout";
			send_upload_error(u, 408, msg);
			upload_remove(u, msg);
		} else
			upload_remove(u, "Data timeout");
	}
	g_slist_free(remove);
}

/*
 * io_free
 *
 * Free the opaque I/O data.
 */
static void io_free(gpointer opaque)
{
	struct io_header *ih = (struct io_header *) opaque;

	g_assert(ih);
	g_assert(ih->upload->io_opaque == opaque);

	ih->upload->io_opaque = NULL;

	if (ih->header)
		header_free(ih->header);
	if (ih->getline)
		getline_free(ih->getline);

	g_free(ih);
}

/*
 * upload_create
 *
 * Create a new upload structure, linked to a socket.
 */
static struct upload *upload_create(struct gnutella_socket *s, gboolean push)
{
	struct upload *u;

	u = (struct upload *) g_malloc0(sizeof(struct upload));

	u->socket = s;
	s->resource.upload = u;

	u->push = push;
	u->status = push ? GTA_UL_PUSH_RECIEVED : GTA_UL_HEADERS;
	u->last_update = time((time_t *) 0);
	u->file_desc = -1;

	/*
	 * Record pending upload in the GUI.
	 */

	registered_uploads++;
	gui_update_c_uploads();

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	uploads = g_slist_append(uploads, u);

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
	struct upload *u;
	struct gnutella_socket *s;
	struct shared_file *req_file;
	guint32 file_index;
	guint32 ip;
	guint16 port;
	guchar *info;

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
	 */

	if (!check_valid_host(ip, port)) {
		g_warning("PUSH request (hops=%d, ttl=%d) from invalid address %s",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port));
		return;
	}

	if (dbg > 4)
		printf("PUSH (hops=%d, ttl=%d) to %s: %s\n",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port),
			req_file->file_name);

	/*
	 * OK, start the upload by opening a connection to the remote host.
	 */

	s = socket_connect(ip, port, GTA_TYPE_UPLOAD);
	if (!s) {
		g_warning("PUSH request (hops=%d, ttl=%d) dropped: can't connect to %s",
			n->header.hops, n->header.ttl, ip_port_to_gchar(ip, port));
		return;
	}

	u = upload_create(s, TRUE);
	u->index = file_index;
	u->name = req_file->file_name;

	/* Now waiting for the connection CONF -- will call upload_push_conf() */
}

void upload_real_remove(void)
{
	// XXX UNUSED
	// XXX Currently, we remove failed uploads from the list, but we should
	// XXX do as we do for downloads, and have an extra option to remove
	// XXX failed uploads immediately.	--RAM, 24/12/2001
}

static void upload_free_resources(struct upload *u)
{
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
	if (u->io_opaque)				/* I/O data */
		io_free(u->io_opaque);
	if (u->bio != NULL) {
		bsched_source_remove(u->bio);
		u->bio = NULL;
	}
}

/*
 * send_upload_error
 *
 * Send error message to requestor.
 * This can only be done once per connection.
 */
static void send_upload_error(struct upload *u, int code, guchar *msg, ...)
{
	struct gnutella_socket *s = u->socket;
	gchar http_response[1024];
	gchar reason[1024];
	gint rw;
	gint sent;
	va_list args;

	va_start(args, msg);
	g_vsnprintf(reason, sizeof(reason), msg, args);
	reason[sizeof(reason) - 1] = '\0';		/* May be truncated */
	va_end(args);

	if (u->error_sent) {
		g_warning("Already sent an error %d to %s, not sending %d (%s)",
			u->error_sent, ip_to_gchar(s->ip), code, reason);
		return;
	}

	rw = g_snprintf(http_response, sizeof(http_response),
		"HTTP/1.0 %d %s\r\n"
		"Server: %s\r\n"
		"Connection: close\r\n"
		"X-Live-Since: %s\r\n"
		"\r\n",
		code, reason, version_string, start_rfc822_date);

	if (-1 == (sent = bws_write(bws_out, s->file_desc, http_response, rw)))
		g_warning("Unable to send back HTTP error %d (%s) to %s: %s",
			code, reason, ip_to_gchar(s->ip), g_strerror(errno));
	else if (sent < rw)
		g_warning("Only sent %d out of %d bytes of error %d (%s) to %s: %s",
			sent, rw, code, reason, ip_to_gchar(s->ip), g_strerror(errno));
	else if (dbg > 4) {
		printf("----Sent HTTP Error to %s:\n%.*s----\n",
			ip_to_gchar(s->ip), rw, http_response);
		fflush(stdout);
	}

	u->error_sent = code;
}

void upload_remove(struct upload *u, const gchar *reason, ...)
{
	gint row;
	gchar errbuf[1024];

	if (reason && dbg > 1) {
		va_list args;
		va_start(args, reason);
		g_vsnprintf(errbuf, sizeof(errbuf), reason, args);
		errbuf[sizeof(errbuf) - 1] = '\0';		/* May be truncated */
		va_end(args);

		if (u->name) {
			if (dbg) printf("Cancelling upload for %s from %s: %s\n",
				u->name, ip_to_gchar(u->socket->ip), errbuf);
		} else {
			if (dbg) printf("Cancelling upload from %s: %s\n",
				ip_to_gchar(u->socket->ip), errbuf);
		}
	}

	/*
	 * If the upload is still connecting, we have not started sending
	 * any data yet, so we send an HTTP error code before closing the
	 * connection.
	 *		--RAM, 24/12/2001
	 *
	 * Push requests still connecting don't have anything to send, hence
	 * we check explicitely for GTA_UL_PUSH_RECIEVED.
	 *		--RAM, 31/12/2001
	 */

	if (
		UPLOAD_IS_CONNECTING(u) &&
		!u->error_sent &&
		u->status != GTA_UL_PUSH_RECIEVED
	)
		send_upload_error(u, 400, reason ? errbuf : "Bad Request");

	/*
	 * If COMPLETE, we've already decremented `running_uploads' and
	 * `registered_uploads'.
	 * Moreover, if it's still connecting, then we've not even
	 * incremented the `running_uploads' counter yet.
	 */

	if (!UPLOAD_IS_COMPLETE(u))
		registered_uploads--;

	if (!UPLOAD_IS_COMPLETE(u) && !UPLOAD_IS_CONNECTING(u))
		running_uploads--;

	upload_free_resources(u);
	g_free(u);

	/*
	 * `registered_uploads', and possibly `running_uploads' may have changed
	 */
	gui_update_c_uploads();

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads), (gpointer) u);
	gtk_clist_remove(GTK_CLIST(clist_uploads), row);
	uploads = g_slist_remove(uploads, (gpointer) u);
}

/***
 *** Header parsing callbacks
 ***
 *** We could call those directly, but I'm thinking about factoring all
 *** that processing into a generic set of functions, and the processing
 *** callbacks will all have the same signature.  --RAM, 31/12/2001
 ***/

static void call_upload_request(struct io_header *ih)
{
	upload_request(ih->upload, ih->header);
}

/*
 * upload_header_parse
 *
 * This routine is called to parse the input buffer, a line at a time,
 * until EOH is reached.
 */
static void upload_header_parse(struct io_header *ih)
{
	struct upload *u = ih->upload;
	struct gnutella_socket *s = u->socket;
	getline_t *getline = ih->getline;
	header_t *header = ih->header;
	guint parsed;
	gint error;

	/*
	 * Read header a line at a time.  We have exacly s->pos chars to handle.
	 * NB: we're using a goto label to loop over.
	 */

nextline:
	switch (getline_read(getline, s->buffer, s->pos, &parsed)) {
	case READ_OVERFLOW:
		send_upload_error(u, 413, "Header too large");
		g_warning("upload_header_parse: line too long, disconnecting from %s",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		upload_remove(u, "Failed (Header too large)");
		return;
		/* NOTREACHED */
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
	 * We come here everytime we get a full header line.
	 */

	if (ih->flags & IO_STATUS_LINE) {
		/*
		 * Save status line away in socket's "getline" object, then clear
		 * the fact that we're expecting a status line and continue to get
		 * the following header lines.
		 *
		 * XXX Refactoring note: it's not a status line here, it's the HTTP
		 * XXX request, which we get from the remote servent through a
		 * XXX connection we initiated with the GIV string (PUSH reply).
		 * XXX The flag must be renamed, kept it as-is for now to not add
		 * XXX futher factoring difficulty.
		 */

		g_assert(s->getline == 0);
		s->getline = getline_make();

		getline_copy(getline, s->getline);
		getline_reset(getline);
		ih->flags &= ~IO_STATUS_LINE;
		goto nextline;
	}

	error = header_append(header,
		getline_str(getline), getline_length(getline));

	switch (error) {
	case HEAD_OK:
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
		/* NOTREACHED */
	case HEAD_EOH:				/* We reached the end of the header */
		break;
	case HEAD_TOO_LARGE:
	case HEAD_MANY_LINES:
		send_upload_error(u, 413, header_strerror(error));
		/* FALL THROUGH */
	case HEAD_EOH_REACHED:
		g_warning("upload_header_parse: %s, disconnecting from %s",
			header_strerror(error),  ip_to_gchar(s->ip));
		fprintf(stderr, "------ Header Dump:\n");
		header_dump(header, stderr);
		fprintf(stderr, "------\n");
		dump_hex(stderr, "Header Line", getline_str(getline),
			MIN(getline_length(getline), 128));
		upload_remove(u, "Failed (%s)", header_strerror(error));
		return;
		/* NOTREACHED */
	default:					/* Error, but try to continue */
		g_warning("upload_header_parse: %s, from %s",
			header_strerror(error), ip_to_gchar(s->ip));
		dump_hex(stderr, "Header Line",
			getline_str(getline), getline_length(getline));
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
	}

	/*
	 * We reached the end of headers.  Make sure there's no more data.
	 */

	if (s->pos) {
		g_warning("remote %s sent extra bytes after HTTP headers",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Extra Data", s->buffer, MIN(s->pos, 256));
		upload_remove(u, "Failed (Extra HTTP header data)");
		return;
	}

	/*
	 * OK, we got the whole headers.
	 *
	 * Free up the I/O callback structure, remove the input callback and
	 * initialize the upload.  NB: the initial HTTP request on the first
	 * line is still held in the s->getline structure.
	 */

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;

	ih->process_header(ih);
}

/*
 * upload_header_read
 *
 * This routine is installed as an input callback to read the HTTP headers
 * of the request.
 */
static void upload_header_read(
	gpointer data, gint source, GdkInputCondition cond)
{
	struct io_header *ih = (struct io_header *) data;
	struct upload *u = ih->upload;
	struct gnutella_socket *s = u->socket;
	guint count;
	gint r;

	if (cond & GDK_INPUT_EXCEPTION) {
		upload_remove(u, "Failed (Input Exception)");
		return;
	}

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("upload_header_read: incoming buffer full, "
			"disconnecting from %s", ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		upload_remove(u, "Failed (Input buffer full)");
		return;
	}

	r = read(s->file_desc, s->buffer + s->pos, count);
	if (r == 0) {
		upload_remove(u, "Failed (EOF)");
		return;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		upload_remove(u, "Failed (Input error: %s)", g_strerror(errno));
		return;
	}

	/*
	 * During the header reading phase, we don't update "u->last_update"
	 * on purpose.  The timeout is defined for the whole connection phase,
	 * i.e. until we read the end of the headers.
	 */

	s->pos += r;

	upload_header_parse(ih);
}

/*
 * upload_add
 *
 * Create a new upload request, and begin reading HTTP headers.
 */
void upload_add(struct gnutella_socket *s)
{
	struct upload *u;
	struct io_header *ih;

	u = upload_create(s, FALSE);

	s->type = GTA_TYPE_UPLOAD;

	/*
	 * Prepare callback argument used during the header reading phase.
	 */

	ih = (struct io_header *) g_malloc(sizeof(struct io_header));
	ih->upload = u;
	ih->header = header_make();
	ih->getline = getline_make();
	ih->flags = 0;
	ih->process_header = call_upload_request;
	u->io_opaque = (gpointer) ih;

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		upload_header_read, (gpointer) ih);

	/*
	 * There may be pending input in the socket buffer, so go handle
	 * it immediately.
	 */

	upload_header_parse(ih);
}

/*
 * upload_push_conf
 *
 * Got confirmation that the connection to the remote host was OK.
 * Send the GIV string, then prepare receiving back the HTTP request.
 */
void upload_push_conf(struct upload *u)
{
	gchar giv[MAX_LINE_SIZE];
	struct gnutella_socket *s;
	struct io_header *ih;
	gint rw;
	gint sent;

	g_assert(u);
	g_assert(u->name);

	/*
	 * Send the GIV string, using our servent GUID.
	 */

	rw = g_snprintf(giv, sizeof(giv), "GIV %u:%s/%s\n\n",
		u->index, guid_hex_str(guid), u->name);
	giv[sizeof(giv)-1] = '\0';			/* Might have been truncated */
	
	s = u->socket;
	if (-1 == (sent = bws_write(bws_out, s->file_desc, giv, rw))) {
		g_warning("Unable to send back GIV for \"%s\" to %s: %s",
			u->name, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (sent < rw) {
		g_warning("Only sent %d out of %d bytes of GIV for \"%s\" to %s: %s",
			sent, rw, u->name, ip_to_gchar(s->ip), g_strerror(errno));
	} else if (dbg > 4) {
		printf("----Sent GIV to %s:\n%.*s----\n", ip_to_gchar(s->ip), rw, giv);
		fflush(stdout);
	}

	if (sent != rw) {
		upload_remove(u, "Unable to send GIV");
		return;
	}

	/*
	 * Prepare callback argument used during the header reading phase.
	 *
	 * We're requesting the reading of a "status line", which will be the
	 * HTTP request.  It will be stored in a created s->getline entry.
	 * Once we're done, we'll end-up in upload_request(): the path joins
	 * with the one used for direct uploading.
	 */

	g_assert(s->getline == 0);

	ih = (struct io_header *) g_malloc(sizeof(struct io_header));
	ih->upload = u;
	ih->header = header_make();
	ih->getline = getline_make();
	ih->flags = IO_STATUS_LINE;		/* XXX will be really the HTTP request */
	ih->process_header = call_upload_request;
	u->io_opaque = (gpointer) ih;

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		upload_header_read, (gpointer) ih);
}

/*
 * upload_request
 *
 * Called to initiate the upload once all the HTTP headers have been
 * read.  Validate the request, and begin processing it if all OK.
 * Otherwise cancel the upload.
 */
static void upload_request(struct upload *u, header_t *header)
{
	struct gnutella_socket *s = u->socket;
	struct shared_file *requested_file = NULL;
	guint index = 0, skip = 0, end = 0, rw = 0, row = 0, upcount = 0;
	gchar http_response[1024], *fpath = NULL, sl[] = "/\0";
	gchar *user_agent = 0;
	gchar *buf;
	gchar *titles[3];
	gchar *request = getline_str(s->getline);
	GSList *l;
	gint sent;
	gboolean head_only;
	gboolean has_end = FALSE;

	titles[0] = titles[1] = titles[2] = NULL;

	if (dbg > 4) {
		printf("----Incoming Request from %s:\n", ip_to_gchar(s->ip));
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
	 * running_uploads.
	 */

	running_uploads++;

	/*
	 * If `head_only' is true, the request was a HEAD and we're only going
	 * to send back the headers.
	 */

	head_only = (request[0] == 'H');

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

	if (
		sscanf(request, "GET /get/%u/", &index) ||
		sscanf(request, "HEAD /get/%u/", &index)
	) {
		guchar c;

		/*
		 * If we don't share, abort immediately. --RAM, 11/01/2002
		 */

		if (max_uploads == 0) {
			gchar *error = "Sharing currently disabled";
			send_upload_error(u, 410, error);
			upload_remove(u, error);
			return;
		}

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

		requested_file = shared_file(index);
		if (requested_file == NULL)
			goto not_found;

		buf = request +
			((request[0] == 'G') ? sizeof("GET /get/") : sizeof("HEAD /get/"));

		(void) url_unescape(buf, TRUE);		/* Index is escape-safe anyway */

		while ((c = *(guchar *) buf++) && c != '/')
			/* empty */;
		if (c == '/' && 0 != strncmp(buf,
				requested_file->file_name, requested_file->file_name_len)
		) {
			gchar *error = "File index/name mismatch";
			send_upload_error(u, 409, error);
			g_warning("%s from %s for %d/%s", error,
				ip_to_gchar(s->ip), index, requested_file->file_name);
			upload_remove(u, error);
			return;
		}

		/*
		 * Even though this test is less costly than the previous, doing it
		 * afterwards allows them to be notified of a mismatch whilst they
		 * wait for a download slot.  It would be a pity for them to get
		 * a slot and be told about the mismatch only then.
		 *		--RAM, 15/12/2001
		 */

		if (running_uploads > max_uploads) {
			send_upload_error(u, 503, "Too many uploads; try again later");
			upload_remove(u, "All %d slots used", max_uploads);
			return;
		}

		/*
		 * Ensure that noone tries to download the same file twice, and
		 * that they don't get beyond the max authorized downloads per IP.
		 */

		for (l = uploads; l; l = l->next) {
			struct upload *up = (struct upload *) (l->data);
			g_assert(up);
			if (up == u)
				continue;				/* Current upload is already in list */
			if (up->status != GTA_UL_SENDING)
				continue;
			if (up->index == index && up->socket->ip == s->ip) {
				guchar *error = "Already downloading that file";
				send_upload_error(u, 409, error);
				upload_remove(u, error);
				return;
			}
			if (up->socket->ip == s->ip && ++upcount >= max_uploads_ip) {
				send_upload_error(u, 503,
					"Only %u download%s per IP address",
					max_uploads_ip, max_uploads_ip == 1 ? "" : "s");
				upload_remove(u, "All %u slot%s for that IP used",
					max_uploads_ip, max_uploads_ip == 1 ? "" : "s");
				return;
			}
		}

		/*
		 * Range: bytes=10453-23456
		 * User-Agent: whatever
		 * Server: whatever (in case no User-Agent)
		 */

		buf = header_get(header, "Range");
		if (buf) {
			if (2 == sscanf(buf, "bytes=%u-%u", &skip, &end)) {
				has_end = TRUE;
				if (skip > end) {
					char *msg = "Malformed Range request";
					send_upload_error(u, 400, msg);
					upload_remove(u, msg);
					return;
				}
			} else if (1 == sscanf(buf, "bytes=-%u", &end))
				has_end = TRUE;
			else
				(void) sscanf(buf, "bytes=%u-", &skip);
		}

		user_agent = header_get(header, "User-Agent");

		/* Maybe they sent a Server: line, thinking they're a server? */
		if (!user_agent)
			user_agent = header_get(header, "Server");

		if (user_agent) {
			/* XXX match against web user agents, possibly */
		}

		/*
		 * We're accepting the upload.  Setup accordingly.
		 */

		/* Set the full path to the file */
		if (requested_file->
			file_directory[strlen(requested_file->file_directory) - 1] == sl[0])
			fpath =
				g_strconcat(requested_file->file_directory,
							requested_file->file_name, NULL);
		else
			fpath =
				g_strconcat(requested_file->file_directory, &sl,
							requested_file->file_name, NULL);

		/*
		 * Validate the rquested range.
		 */

		if (!has_end)
			end = requested_file->file_size - 1;

		u->file_size = requested_file->file_size;

		if (skip >= u->file_size || end >= u->file_size) {
			char *msg = "Requested range not satisfiable";
			send_upload_error(u, 416, msg);
			upload_remove(u, msg);
			return;
		}

		/* Open the file for reading , READONLY just in case. */
		if ((u->file_desc = open(fpath, O_RDONLY)) < 0)
			goto not_found;

		g_free(fpath);

		/*
		 * If we pushed this upload, and they are not requesting the same
		 * file, that's OK, but warn.
		 *		--RAM, 31/12/2001
		 */

		if (u->push && index != u->index)
			g_warning("Host %s sent PUSH for %u but is now requesting %u (%s)",
				ip_to_gchar(s->ip),
				u->index, index, requested_file->file_name);

		/* Set all the upload information */
		u->index = index;
		u->name = requested_file->file_name;

		u->skip = skip;
		u->end = end;
		u->pos = 0;
		u->start_date = time((time_t *) NULL);
		u->last_update = time((time_t *) 0);

		u->buf_size = 4096 * sizeof(gchar);
		u->buffer = (gchar *) g_malloc(u->buf_size);
		u->bpos = 0;
		u->bsize = 0;

		/*
		 * Setup and write the HTTP 200 header , including the file size.
		 * If partial content (range request), emit a 206 reply.
		 */

		if (skip || end != (u->file_size - 1))
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 206 Partial Content\r\n"
				"Server: %s\r\n"
				"Connection: close\r\n"
				"X-Live-Since: %s\r\n"
				"Content-type: application/binary\r\n"
				"Content-length: %u\r\n"
				"Content-Range: bytes %u-%u/%u\r\n\r\n",
				version_string, start_rfc822_date,
				u->end - u->skip + 1,
				u->skip, u->end, u->file_size);
		else
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 200 OK\r\n"
				"Server: %s\r\n"
				"Connection: close\r\n"
				"X-Live-Since: %s\r\n"
				"Content-type: application/binary\r\n"
				"Content-length: %u\r\n\r\n",
				version_string, start_rfc822_date, u->file_size);

		sent = bws_write(bws_out, s->file_desc, http_response, rw);
		if (sent == -1) {
			gint errcode = errno;
			g_warning("Unable to send back HTTP OK reply to %s: %s",
				ip_to_gchar(s->ip), g_strerror(errcode));
			upload_remove(u, "Cannot send ACK: %s", g_strerror(errcode));
			return;
		} else if (sent < rw) {
			g_warning("Could only send %d out of %d HTTP OK bytes to %s",
				sent, rw, ip_to_gchar(s->ip));
			upload_remove(u, "Cannot send whole ACK");
			return;
		}

		if (dbg > 4) {
			printf("----Sent Reply to %s:\n%.*s----\n",
				ip_to_gchar(s->ip), (int) rw, http_response);
			fflush(stdout);
		}

		/*
		 * If we need to send only the HEAD, we're done. --RAM, 26/12/2001
		 */

		if (head_only) {
			upload_remove(u, NULL);		/* No message, everything was OK */
			return;
		}

		/*
		 * Install the output I/O, which is via a bandwidth limited source.
		 */

		io_free(u->io_opaque);

		g_assert(s->gdk_tag == 0);
		g_assert(u->bio == NULL);
		
		u->bio = bsched_source_add(bws_out, s->file_desc,
			BIO_F_WRITE, upload_write, (gpointer) u);

		/*
		 * Add upload to the GUI
		 */

		titles[0] = u->name;
		titles[1] = ip_to_gchar(s->ip);
		titles[2] = "";

		row = gtk_clist_append(GTK_CLIST(clist_uploads), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_uploads), row, (gpointer) u);

		gui_update_c_uploads();

		return;
	}

  not_found:

	/* What?  Either the sscanf() failed or we don't have the file. */

	send_upload_error(u, 404, "Not Found");
	g_warning("bad request from %s: %s\n", ip_to_gchar(s->ip), request);

	if (fpath)
		g_free(fpath);

	upload_remove(u, "File not found");
}

/* Uplaod Write
 * FIFO type action to deal with low baud rates. If we try to force
 * 4k then the lower speed downloads will be garbled.
 */
void upload_write(gpointer up, gint source, GdkInputCondition cond)
{
	struct upload *u = (struct upload *) up;
	guint32 write_bytes;
	guint32 amount;
	guint32 available;

	if (!(cond & GDK_INPUT_WRITE)) {
		/* If we can't write then we don't want it, kill the socket */
		if (dbg)
			printf("upload_write(); Condition %i, Exception = %i\n",
				   cond, GDK_INPUT_EXCEPTION);
		upload_remove(u, "Write exception");
		return;
	}

	/* If we got a valid skip amount then jump ahead to that position */
	if (u->pos == 0 && u->skip > 0) {
		if (lseek(u->file_desc, u->skip, SEEK_SET) == -1) {
			upload_remove(u, "File seek error: %s", g_strerror(errno));
			return;
		}
		u->pos = u->skip;
	}

	/*
	 * Compute the amount of bytes to send.
	 */

	amount = u->end - u->pos + 1;

	/*
	 * If the buffer position reached the size, then we need to read
	 * more data from the file. We read in under or equal to the buffer
	 * memory size
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

	write_bytes = bio_write(u->bio, &u->buffer[u->bpos], available);

	if (write_bytes == -1) {
		if (errno != EAGAIN)
			upload_remove(u, "Data write error: %s", g_strerror(errno));
		return;
	}

	u->pos += write_bytes;
	u->bpos += write_bytes;

	u->last_update = time((time_t *) NULL);

	if (u->pos > u->end) {
		count_uploads++;
		gui_update_count_uploads();
		gui_update_c_uploads();
		if (clear_uploads == TRUE)
			upload_remove(u, NULL);
		else {
			u->status = GTA_UL_COMPLETE;
			gui_update_upload(u);
			registered_uploads--;
			running_uploads--;
			gui_update_c_uploads();
			gtk_widget_set_sensitive(button_clear_uploads, 1);
			upload_free_resources(u);
		}
		return;
	}
}

void upload_close(void)
{
	GSList *l;

	for (l = uploads; l; l = l->next) {
		struct upload *u = (struct upload *) l->data;
		upload_free_resources(u);
		g_free(u);
	}

	g_slist_free(uploads);
}

/* vi: set ts=4: */
