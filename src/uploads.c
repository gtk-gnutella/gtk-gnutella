
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

GSList *uploads = NULL;
gint running_uploads = 0;

guint32 count_uploads = 0;

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
}

void upload_real_remove(void)
{
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

void upload_remove(struct upload *u, gchar * reason)
{
	gint row;

	if (u->status != GTA_UL_COMPLETE) {
		/* if UL_COMPLETE, we've already decremented it. */
		running_uploads--;
		gui_update_c_uploads();
	}

	upload_free_resources(u);
	g_free(u);

	row = gtk_clist_find_row_from_data(GTK_CLIST(clist_uploads), (gpointer) u);
	gtk_clist_remove(GTK_CLIST(clist_uploads), row);
	uploads = g_slist_remove(uploads, (gpointer) u);
}

struct upload *upload_add(struct gnutella_socket *s)
{

	/* TODO:
	 * Deal with push request, just setup the upload structure but don't
	 * send anything
	 */
	struct upload *new_upload = NULL;
	struct shared_file *requested_file = NULL;
	GSList *t_uploads = NULL;
	guint index = 0, skip = 0, rw = 0, row = 0, upcount = 0;
	gchar http_response[1024], *fpath = NULL, sl[] = "/\0";
	gchar *user_agent = 0;
	gchar *buf;
	gint rqst_len;
	gchar *titles[3];
	guchar c;

	titles[0] = titles[1] = titles[2] = NULL;

	/*
	 * In any case, we must ensure sscanf() and other strstr() are bound to
	 * the buffer.	Force latest byte to NULL. -- RAM
	 */

	s->buffer[sizeof(s->buffer) - 1] = '\0';	/* Should not override data */

	if (dbg > 4) {
		printf("---Incoming Request from %s:\n%s----\n",
			ip_to_gchar(s->ip), s->buffer);
		fflush(stdout);
	}

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
	 * it would slow him down, even if he retries immediately.
	 *
	 * Alternatively, instead of differing the 503 reply, we could send a
	 * "403 Forbidden to bad citizens" instead, and chances are that servents
	 * abort retries on failures other than 503...
	 *
	 *				--RAM, 09/09/2001
	 */

	rqst_len = strlen(s->buffer);
	if (rqst_len < 5
		|| 0 != strncmp(&s->buffer[rqst_len - 4], "\r\n\r\n", 4)) {
		rw = g_snprintf(http_response, sizeof(http_response),
						"HTTP/1.0 400 Bad Request\r\n"
						"Server: gtk-gnutella/%d.%d\r\n\r\n", GTA_VERSION,
						GTA_SUBVERSION);
		write(s->file_desc, http_response, rw);
		return NULL;
	}

	if (sscanf(s->buffer, "GET /get/%u/", &index)) {
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

		buf = s->buffer + sizeof("GET /get/");
		while ((c = *(guchar *) buf++) && c != '/')
			/* empty */;
		if (c == '/' && 0 != strncmp(buf,
				requested_file->file_name, requested_file->file_name_len)
		) {
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 409 File index/name mismatch\r\n"
				"Server: gtk-gnutella/%d.%d\r\n\r\n",
				GTA_VERSION, GTA_SUBVERSION);
			write(s->file_desc, http_response, rw);
			g_warning("file index/name mismatch from %s for %d/%s",
				ip_to_gchar(s->ip), index, requested_file->file_name);
			return NULL;
		}

		/*
		 * Even though this test is less costly than the previous, doing it
		 * afterwards allows them to be notified of a mismatch whilst they
		 * wait for a download slot.  It would be a pity for them to get
		 * a slot and be told about the mismatch only then.
		 *		--RAM, 15/12/2001
		 */

		if (running_uploads >= max_uploads) {
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 503 Too many uploads; try again later\r\n"
				"Server: gtk-gnutella/%d.%d\r\n\r\n",
				GTA_VERSION, GTA_SUBVERSION);
			write(s->file_desc, http_response, rw);

			return NULL;
		}

		/*
		 * Ensure that noone tries to download the same file twice, and
		 * that they don't get beyond the max authorized downloads per IP.
		 */

		for (t_uploads = uploads; t_uploads; t_uploads = t_uploads->next) {
			struct upload *u = (struct upload *) (t_uploads->data);
			if (u->status != GTA_UL_SENDING)
				continue;
			if (u->index == index && u->socket->ip == s->ip) {
				rw = g_snprintf(http_response, sizeof(http_response),
					"HTTP/1.0 409 Already downloading that file\r\n"
					"Server: gtk-gnutella/%d.%d\r\n\r\n",
					GTA_VERSION, GTA_SUBVERSION);
				write(s->file_desc, http_response, rw);
				return NULL;
			}
			if (u->socket->ip == s->ip && ++upcount >= max_uploads_ip) {
				rw = g_snprintf(http_response, sizeof(http_response),
					"HTTP/1.0 503 Only %u download%s per IP address\r\n"
					"Server: gtk-gnutella/%d.%d\r\n\r\n",
					max_uploads_ip,
					max_uploads_ip == 1 ? "" : "s",
					GTA_VERSION, GTA_SUBVERSION);
				write(s->file_desc, http_response, rw);
				return NULL;
			}
		}

		/*
		 * Range: bytes=10453-
		 * User-Agent: whatever
		 * Server: whatever (in case no User-Agent)
		 */

		buf = strstr(s->buffer, "\nRange:");	/* XXX could be range: */
		if (buf)
			sscanf(buf, "\nRange: bytes=%u-", &skip);

		buf = strstr(s->buffer, "\nUser-Agent:"); /* XXX could be user-agent: */

		/* Not portable */
		if (buf)
			sscanf(buf, "\nUser-Agent: %a[^\r]\r\n", &user_agent);

		/* Maybe they sent a Server: line, thinking they're a server? */
		if (!user_agent) {
			buf = strstr(s->buffer, "\nServer:");
			if (buf)
				sscanf(buf, "\nServer: %a[^\r]\r\n", &user_agent);
		}

		if (user_agent) {
			/* XXX match against web user agents, possibly */
			free(user_agent);
		}

		/*
		 * Build uploading reply...
		 */

		new_upload = (struct upload *) g_malloc0(sizeof(struct upload));

		/* Set the full path to the file */
		if (requested_file->
			file_directory[strlen(requested_file->file_directory) - 1] ==
			sl[0])
			fpath =
				g_strconcat(requested_file->file_directory,
							requested_file->file_name, NULL);
		else
			fpath =
				g_strconcat(requested_file->file_directory, &sl,
							requested_file->file_name, NULL);

		/* Open the file for reading , READONLY just in case. */
		if ((new_upload->file_desc = open(fpath, O_RDONLY)) < 0)
			goto not_found;

		/* Set all the upload information in our newly created upload struct */
		new_upload->index = index;
		new_upload->name = requested_file->file_name;

		s->type = GTA_TYPE_UPLOAD;

		new_upload->socket = s;
		new_upload->skip = skip;
		new_upload->pos = 0;
		new_upload->status = GTA_UL_SENDING;
		new_upload->push = FALSE;
		new_upload->file_size = requested_file->file_size;
		new_upload->start_date = time((time_t *) NULL);
		new_upload->last_update = 0;

		new_upload->buf_size = 4096 * sizeof(gchar);
		new_upload->buffer = (gchar *) g_malloc(new_upload->buf_size);
		new_upload->bpos = 0;
		new_upload->bsize = 0;

		titles[0] = new_upload->name;
		titles[1] = g_strdup(ip_to_gchar(s->ip));
		titles[2] = "";


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
				new_upload->file_size - new_upload->skip,
				new_upload->skip, new_upload->file_size - 1,
				new_upload->file_size);
		else
			rw = g_snprintf(http_response, sizeof(http_response),
				"HTTP/1.0 200 OK\r\n"
				"Server: gtk-gnutella/%d.%d\r\n"
				"Content-type: application/binary\r\n"
				"Content-length: %i\r\n\r\n",
				GTA_VERSION, GTA_SUBVERSION,
				new_upload->file_size);

		/* XXX must protect write against EAGAIN, partial write, etc... */
		write(new_upload->socket->file_desc, http_response, rw);

		if (dbg > 4) {
			printf("----Sent Reply to %s:\n%.*s----\n",
				ip_to_gchar(s->ip), (int) rw, http_response);
			fflush(stdout);
		}

		/* add the upload structure to the upload slist */
		uploads = g_slist_append(uploads, new_upload);


		/* add upload to the gui */
		row = gtk_clist_append(GTK_CLIST(clist_uploads), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_uploads), row,
							   (gpointer) new_upload);

		running_uploads++;
		gui_update_c_uploads();

		g_free(fpath);

		return new_upload;
	}

  not_found:

	/* What?  Either the sscanf() failed or we don't have the file. */
	rw = g_snprintf(http_response, sizeof(http_response),
		"HTTP/1.0 404 Not Found\r\n"
		"Server: gtk-gnutella/%d.%d\r\n\r\n",
		GTA_VERSION, GTA_SUBVERSION);

	write(s->file_desc, http_response, rw);

	g_warning("bad request from %s:\n---\n%s---\n",
			  ip_to_gchar(s->ip), s->buffer);

	if (new_upload)
		g_free(new_upload);
	if (fpath)
		g_free(fpath);

	return NULL;
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
		socket_destroy(current_upload->socket);
		return;
	}

	/* If we got a valid skip amount then jump ahead to that position */
	if (current_upload->pos == 0 && current_upload->skip > 0) {
		if (lseek
			(current_upload->file_desc, current_upload->skip,
			 SEEK_SET) == -1) {
			socket_destroy(current_upload->socket);
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
			socket_destroy(current_upload->socket);
			return;
		}

	if ((write_bytes =
		 write(current_upload->socket->file_desc,
			   &current_upload->buffer[current_upload->bpos],
			   (current_upload->bsize - current_upload->bpos))) == -1) {
		socket_destroy(current_upload->socket);
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
