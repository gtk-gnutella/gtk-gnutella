
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
};

static void upload_request(struct upload *u, header_t *header);

/*
 * TODO: Make sure we do all the following:
 *
 * Recieve HTTP get information , send headers 200(found) or 404(not found),
 * look at Range for skip amount and do a sanity check on the Range
 * "Range < File Size" and Index, Make Upload structure with socket
 * and file desc ,and file name and location.
 * Handle the PUSH request.
 */

void handle_push_request(struct gnutella_node *n)
{
	/* TODO:
	 * Deal with push request, just setup the upload structure but don't
	 * send anything?
	 */
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
		"Server: gtk-gnutella/%d.%d\r\n"
		"\r\n",
		code, reason, GTA_VERSION, GTA_SUBVERSION);

	if (-1 == (sent = write(s->file_desc, http_response, rw)))
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
	 */

	if (UPLOAD_IS_CONNECTING(u) && !u->error_sent)
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
		goto final_cleanup;
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
		goto final_cleanup;
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
		goto final_cleanup;
	}

	/*
	 * OK, we got the whole headers.
	 *
	 * Free up the I/O callback structure, remove the input callback and
	 * initialize the upload.  NB: the initial HTTP request on the first
	 * line is still held in the s->getline structure.
	 */

	getline_free(ih->getline);
	g_free(ih);

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;

	u->last_update = time((time_t *) 0);	/* Done reading headers */
	upload_request(u, header);

	header_free(header);
	return;

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
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
		goto final_cleanup;
	}

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("upload_header_read: incoming buffer full, "
			"disconnecting from %s", ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		upload_remove(u, "Failed (Input buffer full)");
		goto final_cleanup;
	}

	r = read(s->file_desc, s->buffer + s->pos, count);
	if (r == 0) {
		upload_remove(u, "Failed (EOF)");
		goto final_cleanup;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		upload_remove(u, "Failed (Input error: %s)", g_strerror(errno));
		goto final_cleanup;
	}

	/*
	 * During the header reading phase, we don't update "u->last_update"
	 * on purpose.  The timeout is defined for the whole connection phase,
	 * i.e. until we read the end of the headers.
	 */

	s->pos += r;

	upload_header_parse(ih);
	return;

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
}

/*
 * upload_add
 *
 * Create a new upload request, and begin reading HTTP headers.
 * If `head_only' is true, the request was a HEAD and we're only going
 * to send back the headers.
 */
void upload_add(struct gnutella_socket *s, gboolean head_only)
{
	struct upload *u;
	struct io_header *ih;

	u = (struct upload *) g_malloc0(sizeof(struct upload));

	s->type = GTA_TYPE_UPLOAD;

	u->socket = s;
	u->status = GTA_UL_HEADERS;
	u->push = FALSE;
	u->last_update = time((time_t *) 0);
	u->file_desc = -1;
	u->head_only = head_only;
	s->resource.upload = u;

	/*
	 * Record pending upload in the GUI.
	 */

	registered_uploads++;
	gui_update_c_uploads();

	/*
	 * Prepare callback argument used during the header reading phase.
	 */

	ih = (struct io_header *) g_malloc(sizeof(struct io_header));
	ih->upload = u;
	ih->header = header_make();
	ih->getline = getline_make();

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		(GdkInputCondition) GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		upload_header_read, (gpointer) ih);

	/*
	 * Add the upload structure to the upload slist, so it's monitored
	 * from now on within the main loop for timeouts.
	 */

	g_assert(u);
	uploads = g_slist_append(uploads, u);

	/*
	 * There may be pending input in the socket buffer, so go handle
	 * it immediately.
	 */

	upload_header_parse(ih);
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
	guint index = 0, skip = 0, rw = 0, row = 0, upcount = 0;
	gchar http_response[1024], *fpath = NULL, sl[] = "/\0";
	gchar *user_agent = 0;
	gchar *buf;
	gchar *titles[3];
	gchar *request = getline_str(s->getline);
	GSList *l;
	gint sent;

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

	/*
	 * If we remove the upload in upload_remove(), we'll decrement
	 * running_uploads.
	 */

	running_uploads++;

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
		 * We must be cautious about file index changing between two scans,
		 * which may happen when files are moved around on the local library.
		 * If we serve the wrong file, and it's a resuming request, this will
		 * result in a corrupted file!
		 *		--RAM, 26/09/2001
		 */

		requested_file = shared_file(index);
		if (requested_file == NULL)
			goto not_found;

		buf = request +
			((request[0] == 'G') ? sizeof("GET /get/") : sizeof("HEAD /get/"));

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
		 * Range: bytes=10453-
		 * User-Agent: whatever
		 * Server: whatever (in case no User-Agent)
		 */

		buf = header_get(header, "Range");
		if (buf)
			sscanf(buf, "bytes=%u-", &skip);

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

		/* Open the file for reading , READONLY just in case. */
		if ((u->file_desc = open(fpath, O_RDONLY)) < 0)
			goto not_found;

		g_free(fpath);

		/* Set all the upload information */
		u->index = index;
		u->name = requested_file->file_name;

		u->skip = skip;
		u->pos = 0;
		u->file_size = requested_file->file_size;
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

		if (skip)
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 206 Partial Content\r\n"
				"Server: gtk-gnutella/%d.%d\r\n"
				"Content-type: application/binary\r\n"
				"Content-length: %i\r\n"
				"Content-Range: bytes %u-%u/%u\r\n\r\n",
				GTA_VERSION, GTA_SUBVERSION,
				u->file_size - u->skip,
				u->skip, u->file_size - 1, u->file_size);
		else
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 200 OK\r\n"
				"Server: gtk-gnutella/%d.%d\r\n"
				"Content-type: application/binary\r\n"
				"Content-length: %i\r\n\r\n",
				GTA_VERSION, GTA_SUBVERSION, u->file_size);

		sent = write(s->file_desc, http_response, rw);
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

		if (u->head_only) {
			upload_remove(u, NULL);		/* No message, everything was OK */
			return;
		}

		/*
		 * Install the output callback.
		 */

		g_assert(s->gdk_tag == 0);
		s->gdk_tag = gdk_input_add(s->file_desc,
			(GdkInputCondition) GDK_INPUT_WRITE | GDK_INPUT_EXCEPTION,
			upload_write, (gpointer) u);

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
	struct upload *current_upload;
	guint32 write_bytes;
	current_upload = (struct upload *) up;


	if (!(cond & GDK_INPUT_WRITE)) {
		/* If we can't write then we don't want it, kill the socket */
		if (dbg)
			printf("upload_write(); Condition %i, Exception = %i\n",
				   cond, GDK_INPUT_EXCEPTION);
		upload_remove(current_upload, "Write exception");
		return;
	}

	/* If we got a valid skip amount then jump ahead to that position */
	if (current_upload->pos == 0 && current_upload->skip > 0) {
		if (lseek
			(current_upload->file_desc, current_upload->skip,
			 SEEK_SET) == -1) {
			upload_remove(current_upload,
				"File seek error: %s", g_strerror(errno));
			return;
		}
		current_upload->pos = current_upload->skip;
	}


	/*
	 * If the buffer position is equal to zero then we need to read
	 * more data from the file. We read in under or equal to the buffer
	 * memory size
	 */

	if (current_upload->bpos == 0)
		if ((current_upload->bsize =
			 read(current_upload->file_desc, current_upload->buffer,
				  current_upload->buf_size)) == -1) {
			upload_remove(current_upload,
				"File read error: %s", g_strerror(errno));
			return;
		}

	if ((write_bytes =
		 write(current_upload->socket->file_desc,
			   &current_upload->buffer[current_upload->bpos],
			   (current_upload->bsize - current_upload->bpos))) == -1) {
		upload_remove(current_upload,
			"Data write error: %s", g_strerror(errno));
		return;
	}

	current_upload->pos += write_bytes;

	if ((current_upload->bpos + write_bytes) < current_upload->bsize)
		current_upload->bpos += write_bytes;
	else
		current_upload->bpos = 0;

	current_upload->last_update = time((time_t *) NULL);


	if (current_upload->pos >= current_upload->file_size) {
		count_uploads++;
		gui_update_count_uploads();
		gui_update_c_uploads();
		if (clear_uploads == TRUE)
			upload_remove(current_upload, NULL);
		else {
			current_upload->status = GTA_UL_COMPLETE;
			gui_update_upload(current_upload);
			registered_uploads--;
			running_uploads--;
			gui_update_c_uploads();
			gtk_widget_set_sensitive(button_clear_uploads, 1);
			upload_free_resources(current_upload);
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
