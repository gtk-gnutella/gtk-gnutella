
/* Handle downloads */

#include "gnutella.h"

#include "interface.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

GSList *sl_downloads = NULL;

guint32 count_downloads  = 0;

gchar dl_tmp[4096];

void download_start(struct download *);
void send_push_request(gchar *, guint32, guint16);

#define IS_DOWNLOAD_QUEUED(d)  ((d)->status == GTA_DL_QUEUED)

#define IS_DOWNLOAD_STOPPED(d) \
		(  (d)->status == GTA_DL_ABORTED \
		|| (d)->status == GTA_DL_ERROR \
		|| (d)->status == GTA_DL_COMPLETED  )

#define IS_DOWNLOAD_RUNNING(d) \
		(  (d)->status == GTA_DL_CONNECTING \
		|| (d)->status == GTA_DL_PUSH_SENT \
		|| (d)->status == GTA_DL_FALLBACK \
		|| (d)->status == GTA_DL_REQ_SENT \
		|| (d)->status == GTA_DL_HEADERS \
		|| (d)->status == GTA_DL_RECEIVING \
	   || (d)->status == GTA_DL_TIMEOUT_WAIT  )

#define IS_DOWNLOAD_IN_PUSH_MODE(d) (d->push)

#define IS_DOWNLOAD_VISIBLE(d) (d->visible)

/* ------------------------------------------------------------------------------------------------ */

/* Return the current number of running downloads */

gint count_running_downloads(void)
{
	GSList *l;
	guint32 n = 0;

	for (l = sl_downloads; l; l = l->next)
		if (IS_DOWNLOAD_RUNNING((struct download *) l->data))
			n++;

	gui_update_c_downloads(n);

	return n;
}

gint count_running_downloads_with_guid(gchar *guid)
{
  GSList *l;
  guint32 n = 0;

	for (l = sl_downloads; l; l = l->next)
		if (IS_DOWNLOAD_RUNNING((struct download *) l->data))
		  if (!memcmp(((struct download *) l->data)->guid, guid, 16))
			 n++;

	return n;
}

/* GUI operations --------------------------------------------------------------------------------- */

/* Add a download to the GUI */

void download_gui_add(struct download *d)
{
	gchar *titles[3];
	gint row;

	g_return_if_fail(d);

	if (IS_DOWNLOAD_VISIBLE(d))
	{
		g_warning("download_gui_add() called on already visible download '%s' !\n", d->file_name);
		return;
	}

	titles[0] = d->file_name;
	titles[1] = short_size(d->size);
	titles[2] = "";

	if (IS_DOWNLOAD_QUEUED(d))	/* This is a queued download */
	{
		row = gtk_clist_append(GTK_CLIST(clist_download_queue), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_download_queue), row, (gpointer) d);
	}
	else								/* This is an active download */
	{
		row = gtk_clist_append(GTK_CLIST(clist_downloads), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_downloads), row, (gpointer) d);
	}

	d->visible = TRUE;
}

/* Remove a download from the GUI */

void download_gui_remove(struct download *d)
{
	gint row;

	g_return_if_fail(d);

	if (!IS_DOWNLOAD_VISIBLE(d))
	{
		g_warning("download_gui_remove() called on unvisible download '%s' !\n", d->file_name);
		return;
	}

	if (IS_DOWNLOAD_QUEUED(d))
	{
		if (selected_queued_download == d) selected_queued_download = (struct download *) NULL;
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_download_queue), (gpointer) d);
		if (row != -1) gtk_clist_remove(GTK_CLIST(clist_download_queue), row);
		else g_warning("download_gui_remove(): Queued download '%s' not found in clist !?\n", d->file_name);
	}
	else
	{
		if (selected_active_download == d) selected_active_download = (struct download *) NULL;
		row = gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads), (gpointer) d);
		if (row != -1) gtk_clist_remove(GTK_CLIST(clist_downloads), row);
		else g_warning("download_gui_remove(): Active download '%s' not found in clist !?\n", d->file_name);
	}

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

/* Remove stopped downloads */

void downloads_clear_stopped(gboolean all, gboolean now)
{
	GSList *l = sl_downloads;

	/* If all == TRUE: remove COMPLETED | ERROR | ABORTED, else remove only COMPLETED */
	/* If now == TRUE: remove immediately, else remove only downloads idle since at least 3 seconds */

	while (l)
	{
		struct download *d = (struct download *) l->data;
		l = l->next;

		if (!IS_DOWNLOAD_STOPPED(d)) continue;

		if (all)
		{
			if (now || (time((time_t *) NULL) - d->last_update) > 3) download_free(d);
		}
		else if (d->status == GTA_DL_COMPLETED)
		{
			if (now || (time((time_t *) NULL) - d->last_update) > 3) download_free(d);
		}
	}

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

/* Downloads management --------------------------------------------------------------------------- */

void download_stop(struct download *d, guint32 new_status, const gchar *reason)
{
	/* Stop an active download, close its socket and its data file descriptor */

	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_stop() called on queued download '%s'!\n", d->file_name);
		return;
	}

	if (IS_DOWNLOAD_STOPPED(d))
	{
		g_warning("download_stop() called on stopped download '%s'!\n", d->file_name);
		return;
	}

	if (new_status != GTA_DL_ERROR && new_status != GTA_DL_ABORTED && new_status != GTA_DL_COMPLETED && new_status != GTA_DL_TIMEOUT_WAIT)
	{
		g_warning("download_stop(): unexpected new status %d !\n", new_status);
		return;
	}

	if (d->status == new_status)
	{
		g_warning("download_stop(): download '%s' already in state %d\n", d->file_name, new_status);
		return;
	}

	/* Close output file */

	if (d->file_desc != -1) { close(d->file_desc); d->file_desc = -1; }

	/* Close socket */

	if (d->socket)
	{
		d->socket->resource.download = (struct download *) NULL;
		socket_destroy(d->socket);
		d->socket = (struct gnutella_socket *) NULL;
	}

	/* Register the new status, and update the GUI if needed */

	d->status = new_status;

	d->last_update = time((time_t *) NULL);

	d->remove_msg = reason;

	if (IS_DOWNLOAD_VISIBLE(d)) gui_update_download(d, TRUE);

	download_pickup_queued();

	if (IS_DOWNLOAD_VISIBLE(d))
	{
		gui_update_download_abort_resume();
		gui_update_download_clear();
	}

	count_running_downloads();
}

void download_kill(struct download *d)
{
	/* Kill a active download: remove it from the GUI, and unlink() the file */

	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_queue(): Download is already queued ?!\n");
		return;
	}

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);
	unlink(dl_tmp);

	download_free(d);
}

void download_queue(struct download *d)
{
	/* Put a download in the queue : */

	/* - it's a new download, but we have reached the max number of running downloads */
	/* - the user requested it with the popup menu "Move back to the queue" */

	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_queue(): Download is already queued ?!\n");
		return;
	}

	if (IS_DOWNLOAD_VISIBLE(d)) download_gui_remove(d);

	if (IS_DOWNLOAD_RUNNING(d)) download_stop(d, GTA_DL_ABORTED, NULL);

	d->status = GTA_DL_QUEUED;

	download_gui_add(d);

	gui_update_download(d, TRUE);
}

/* (Re)start a stopped or queued download */

void download_start(struct download *d)
{
	struct stat st;

	g_return_if_fail(d);

	/* If the download is in the queue, we remove it from there */

	if (IS_DOWNLOAD_QUEUED(d) && IS_DOWNLOAD_VISIBLE(d)) download_gui_remove(d);

	/* If the output file already exists, we have to send a partial request */

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);

	if (stat(dl_tmp, &st) != -1 && st.st_size < d->size)
		d->skip = st.st_size;
	else
		d->skip = 0;
	
	d->pos = d->skip;

	if (!IS_DOWNLOAD_IN_PUSH_MODE(d) && check_valid_host(d->ip, d->port))	/* Direct download */
	{
		d->status = GTA_DL_CONNECTING;
		d->socket = socket_connect(d->ip, d->port, GTA_TYPE_DOWNLOAD);

		if (!d->socket)
		{
			if (!IS_DOWNLOAD_VISIBLE(d)) download_gui_add(d);
			download_stop(d, GTA_DL_ERROR, "Connection failed");
			return;
		}

		d->socket->resource.download = d;
		d->socket->pos = 0;
	}
	else 													/* We have to send a push request */
	{
		d->status = GTA_DL_PUSH_SENT;
		download_push(d);
	}

	if (!IS_DOWNLOAD_VISIBLE(d)) download_gui_add(d);

	gui_update_download(d, TRUE);

	count_running_downloads();
}

/* pick up new downloads from the queue as needed */

void download_pickup_queued(void)
{
	guint row;
	
	gtk_clist_freeze(GTK_CLIST(clist_download_queue));
	row=0;
	while (row<GTK_CLIST(clist_download_queue)->rows && count_running_downloads() < max_downloads)
	{
		struct download *d = (struct download *) gtk_clist_get_row_data(GTK_CLIST(clist_download_queue), row);

		if (!IS_DOWNLOAD_QUEUED(d)) g_warning("download_pickup_queued(): Download '%s' is not in queued state ! (state = %d)\n", d->file_name, d->status);

		if (count_running_downloads_with_guid(d->guid) < max_host_downloads)
			download_start(d);
		else row++;
	}
	gtk_clist_thaw(GTK_CLIST(clist_download_queue));
}

void download_push(struct download *d)
{
	g_return_if_fail(d);

	d->push = TRUE;
	d->socket = socket_listen(0, 0, GTA_TYPE_DOWNLOAD);
	if (!d->socket) { download_stop(d, GTA_DL_ERROR, "Internal error"); return; }
	d->socket->resource.download = d;
	d->socket->pos = 0;
	send_push_request(d->guid, d->record_index, d->socket->local_port);
}

/* Direct download failed, let's try it with a push request */

void download_fallback_to_push(struct download *d, gboolean user_request)
{
	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_fallback_to_push() called on a queued download !?!\n");
		return;
	}

	if (IS_DOWNLOAD_STOPPED(d)) return;

	if (!d->socket) g_warning("download_fallback_to_push(): no socket for '%s'\n", d->file_name);
	else
	{
		d->socket->resource.download = NULL;
		socket_destroy(d->socket);
		d->socket = NULL;
	}

	if (d->file_desc != -1) { close(d->file_desc); d->file_desc = -1; }

	if (user_request) d->status = GTA_DL_PUSH_SENT; else d->status = GTA_DL_FALLBACK;

	download_push(d);

	gui_update_download(d, TRUE);
}

/* Downloads creation and destruction ------------------------------------------------------------- */

/* Create a new download */

void download_new(gchar *file, guint32 size, guint32 record_index, guint32 ip, guint16 port, gchar *guid)
{
	struct download *d;
	gchar *s;

	d = (struct download *) g_malloc0(sizeof(struct download));	

	d->path = g_strdup(save_file_path);
	d->file_name = g_strdup(file);
	d->size = size;
	d->record_index = record_index;
	d->ip = ip;
	d->port = port;
	d->file_desc = -1;
	memcpy(d->guid, guid, 16);

	sl_downloads = g_slist_prepend(sl_downloads, (gpointer) d);

	/* Replace all slashes by backslashes in the file name */

	s = d->file_name; while (*s) { if (*s == '/') *s = '\\'; s++; }

	if (count_running_downloads() < max_downloads && 
		 count_running_downloads_with_guid(d->guid) < max_host_downloads)
	{
		download_start(d);	/* Starts the download immediately */
	}
	else
	{
		download_queue(d); /* Max number of downloads reached, we have to queue it */
	}
}

/* Free a download. */

void download_free(struct download *d)
{
	g_return_if_fail(d);

	if (IS_DOWNLOAD_VISIBLE(d)) download_gui_remove(d);

	if (IS_DOWNLOAD_RUNNING(d)) download_stop(d, GTA_DL_ABORTED, NULL);

	sl_downloads = g_slist_remove(sl_downloads, (gpointer) d);

	g_free(d->path);
	g_free(d->file_name);
	g_free(d);
}

/* ------------------------------------------------------------------------------------------------ */

void download_abort(struct download *d)
{
	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_abort() called on queued download '%s'!\n", d->file_name);
		return;
	}

	if (IS_DOWNLOAD_STOPPED(d)) return;

	download_stop(d, GTA_DL_ABORTED, NULL);
}

void download_resume(struct download *d)
{
	g_return_if_fail(d);

	if (IS_DOWNLOAD_QUEUED(d))
	{
		g_warning("download_resume() called on queued download '%s'!\n", d->file_name);
		return;
	}

	if (IS_DOWNLOAD_RUNNING(d)) return;

	download_start(d);
}

/* IO functions ----------------------------------------------------------------------------------- */

/* Based on patch from Myers W. Carpenter <myers@fil.org> */

void download_move_to_completed_dir(struct download *d) 
{
	/* Move a complete file to move_file_path */

	gchar dl_src[4096];
	gchar dl_dest[4096];
	gint return_tmp, return_tmp2;

	if (!strcmp(d->path, move_file_path)) return;

	g_snprintf(dl_src, sizeof(dl_src), "%s/%s", d->path, d->file_name);
	g_snprintf(dl_dest, sizeof(dl_dest), "%s/%s", move_file_path, d->file_name);

	/* First try and link it to the new locatation */

	return_tmp = rename(dl_src, dl_dest);

	if (return_tmp == -1 && (errno == EXDEV || errno == EPERM))
	{
		/* link failed becase either the two paths aren't on the */
		/* same filesystem or the filesystem doesn't support hard */
	  	/* links, so we have to do a copy. */

		gint tmp_src, tmp_dest;
		gboolean ok = FALSE;

		if ((tmp_src  = open(dl_src, O_RDONLY)) < 0)
		{
			g_warning("Unable to open() file '%s' (%s) !\n", dl_src, g_strerror(errno));
			return;
		}

		if ((tmp_dest = open(dl_dest, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
		{
			close(tmp_src);
			g_warning("Unable to create file '%s' (%s) !\n", dl_src, g_strerror(errno));
			return;
		}

		for (;;) 
		{
			return_tmp = read(tmp_src, dl_tmp, sizeof(dl_tmp));

			if (!return_tmp) { ok = TRUE; break; }

			if (return_tmp < 0)
			{ 
				g_warning("download_move_to_completed_dir(): error reading while moving file to save directory (%s)\n", g_strerror(errno));
				break;
			}

			return_tmp2 = write(tmp_dest, dl_tmp, return_tmp);

			if (return_tmp2 < 0)
			{ 
				g_warning("download_move_to_completed_dir(): error writing while moving file to save directory (%s)\n", g_strerror(errno));
				break;
			}

			if (return_tmp < sizeof(dl_tmp)) { ok = TRUE; break; }
		}
	
		close(tmp_dest); close(tmp_src);
		if (ok) unlink(dl_src);
	}

	return;
}

/* Send a push request */

void send_push_request(gchar *guid, guint32 file_id, guint16 local_port)
{
	struct gnutella_msg_push_request m;

	message_set_muid(&(m.header));

	m.header.function = GTA_MSG_PUSH_REQUEST;
	m.header.ttl = my_ttl;
	m.header.hops = 0;

	WRITE_GUINT32_LE(sizeof(struct gnutella_push_request), m.header.size);

	memcpy(&(m.request.guid), guid, 16);

	WRITE_GUINT32_LE(file_id, m.request.file_id);
	WRITE_GUINT32_BE((force_local_ip)? forced_local_ip : local_ip, m.request.host_ip);
	WRITE_GUINT16_LE(local_port, m.request.host_port);

	message_add(m.header.muid, GTA_MSG_PUSH_REQUEST, NULL);

	sendto_all((guchar *) &m, NULL, sizeof(struct gnutella_msg_push_request));
}

/* Send the HTTP request for a download */

gboolean download_send_request(struct download *d)
{
	g_return_val_if_fail(d, FALSE);

	if (!d->socket)
	{
		g_warning("download_send_request(): No socket for '%s'\n", d->file_name);
		download_stop(d, GTA_DL_ERROR, "Internal Error");
		return FALSE;
	}

	/* Send the HTTP Request */

	if (d->skip) g_snprintf(dl_tmp, sizeof(dl_tmp), "GET /get/%i/%s HTTP/1.0\r\nConnection: Keep-Alive\r\nRange: bytes=%u-\r\n\r\n", d->record_index, d->file_name, d->skip);
	else g_snprintf(dl_tmp, sizeof(dl_tmp), "GET /get/%i/%s HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", d->record_index, d->file_name);

	if (write(d->socket->file_desc, dl_tmp, strlen(dl_tmp)) < 0)
	{
		download_stop(d, GTA_DL_ERROR, "Write failed");
		return FALSE;
	}

	/* Update the GUI */

	d->status = GTA_DL_REQ_SENT;

	gui_update_download(d, TRUE);

	return TRUE;
}

/* Read data on a download socket */

void download_read(gpointer data, gint source, GdkInputCondition cond)
{
	struct gnutella_socket *s = (struct gnutella_socket *) data;
	struct download *d;
	guint32 r;

	g_return_if_fail(s);

	d = s->resource.download;
	g_return_if_fail(d);

	if (cond & GDK_INPUT_EXCEPTION) { download_stop(d, GTA_DL_ERROR, "Failed (Input Exception)"); return; }

	r = read(s->file_desc, s->buffer + s->pos, MIN(sizeof(s->buffer) - s->pos, d->size - d->pos));

	if (!r) { download_stop(d, GTA_DL_ERROR, "Failed (EOF)"); return; }
	else if (r < 0 && errno == EAGAIN) return;
	else if (r < 0) { download_stop(d, GTA_DL_ERROR, "Failed (Read Error)"); return; }

	d->retries=0; /* successful read means our retry was successful */
	s->pos += r;

	switch (d->status)
	{
		case GTA_DL_REQ_SENT: case GTA_DL_PUSH_SENT: case GTA_DL_FALLBACK:
		case GTA_DL_RECEIVING: case GTA_DL_HEADERS:
			break;

		default:
			g_warning("download_read(): UNEXPECTED DOWNLOAD STATUS %d\n", d->status);
	}

	if (d->status == GTA_DL_REQ_SENT)
	{
		d->status = GTA_DL_HEADERS;
		gui_update_download(d, TRUE);
	}
	else if (d->status == GTA_DL_PUSH_SENT || d->status == GTA_DL_FALLBACK)
	{
		gboolean end = FALSE;
		gchar *seek;

		do
		{
			seek = (gchar *) memchr(s->buffer, '\n', s->pos);

			if (!seek) return;

			if (*(seek - 1) == '\r') *(seek - 1) = 0;
			*seek++ = 0;

			if (!*(s->buffer)) end = TRUE;	/* End of headers */
			else if (!g_strncasecmp(s->buffer, "GIV ", 4))
			{
/*				printf("Got GIV string : %s\n", s->buffer); */
			}
			else
			{
				g_warning("download_read(): Unknown header on incoming socket ('%s')\n", s->buffer);
				download_stop(d, GTA_DL_ERROR, "Unknown header");
				return;
			}

			memmove(s->buffer, seek, s->pos - (seek - s->buffer));
			s->pos -= (seek - s->buffer);

		} while (!end);

		/* We can now send the request */

		if (!download_send_request(d)) return;
	}

	if (d->status == GTA_DL_HEADERS)
	{
		gchar *seek;
		gboolean end = FALSE;

		do
		{
			seek = (gchar *) memchr(s->buffer, '\n', s->pos);

			if (!seek) return;

			if (*(seek - 1) == '\r') *(seek - 1) = 0;
			else { download_stop(d, GTA_DL_ERROR, "Malformed HTTP header !"); return; }
			*seek++ = 0;

			if (!*(s->buffer)) end = TRUE;	/* We have got all the headers */
			else if (!g_strncasecmp(s->buffer, "HTTP/1.0 200", 12) || !g_strncasecmp(s->buffer, "HTTP 200", 8))
			{
				d->ok = TRUE;
			}
			else if (!g_strncasecmp(s->buffer, "HTTP/1.0 404", 12) || !g_strncasecmp(s->buffer, "HTTP 404", 8))
			{
				download_stop(d, GTA_DL_ERROR, "404 Not found");
				return;
			}
			else if (!g_strncasecmp(s->buffer, "Content-length:", 15))
			{
				guint32 z = atol(s->buffer + 15);

				if (!z) { download_stop(d, GTA_DL_ERROR, "Bad length !?"); return; }
				else if (z != d->size)
				{
					g_warning("File '%s': expected size %u but server says %u, believing it...\n", d->file_name, d->size, z);
					d->size = z;
				}
			}

			memmove(s->buffer, seek, s->pos - (seek - s->buffer));
			s->pos -= (seek - s->buffer);

		} while (!end);

		d->start_date = time((time_t *) NULL);
		d->status = GTA_DL_RECEIVING;
		gui_update_download(d, TRUE);
	}
	else /* If we have data, write it to the output file */
	{
		if (d->file_desc == -1 && s->pos > 0) /* The output file is not yet open */
		{
			struct stat st;

			g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);

			if (stat(dl_tmp, &st) != -1) /* File exists, we'll append the data to it */
			{
				d->file_desc = open(dl_tmp, O_WRONLY);
				if (d->file_desc != -1) lseek(d->file_desc, 0, SEEK_END);
			}
			else d->file_desc = open(dl_tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (d->file_desc == -1)
			{
				g_warning("Unable to open() file '%s'! (%s)\n", dl_tmp, g_strerror(errno));
				download_stop(d, GTA_DL_ERROR, "Unable to open file !");
				return;
			}
		}

		if (s->pos > 0 && write(d->file_desc, s->buffer, s->pos) < 0)
		{
			g_warning("download_read(): write to file failed (%s) !\n", g_strerror(errno));
			download_stop(d, GTA_DL_ERROR, "Can't save data !");
			return;
		}
	
		d->pos += s->pos;
		s->pos = 0;

		if (d->pos >= d->size)
		{
			download_stop(d, GTA_DL_COMPLETED, NULL);
			download_move_to_completed_dir(d);
			count_downloads++;
			gui_update_count_downloads();
			return;
		}
	}

	gui_update_download(d, FALSE);
}

void download_retry(struct download *d)
{
	/* download_stop() sets the time, so all we need to do is set the delay */

	if (d->timeout_delay == 0) 
		d->timeout_delay = download_retry_timeout_min;
	else {
		d->timeout_delay *= 2;
		if (d->start_date) {
			/* We forgive a little while the download is working */
			d->timeout_delay -= (time((time_t *)NULL) - d->start_date) / 10;
			if (d->timeout_delay < download_retry_timeout_min)
				d->timeout_delay = download_retry_timeout_min;
			if (d->timeout_delay > download_retry_timeout_max)
				d->timeout_delay = download_retry_timeout_max;
		}
	}
	
	download_stop(d, GTA_DL_TIMEOUT_WAIT, NULL);
}
   
/* vi: set ts=3: */

