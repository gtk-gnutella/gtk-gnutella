
/* Handle downloads */

#include "gnutella.h"
#include "misc.h"
#include "interface.h"
#include "gui.h"
#include "sockets.h"
#include "routing.h"
#include "downloads.h"
#include "hosts.h"
#include "getline.h"
#include "header.h"
#include "routing.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DL_RUN_DELAY		5	/* To avoid hammering host --RAM */
#define DL_RETRY_TIMER		15	/* Seconds to wait after EOF or ECONNRESET */

struct download *selected_queued_download = (struct download *) NULL;
struct download *selected_active_download = (struct download *) NULL;

GSList *sl_downloads = NULL;
guint32 count_downloads = 0;
gboolean send_pushes = TRUE;
gchar dl_tmp[4096];

static GHashTable *pushed_downloads = 0;

static gboolean send_push_request(gchar *, guint32, guint16);
static void download_start_restart_timer(struct download *d);
static void download_read(gpointer data, gint source, GdkInputCondition cond);
static void download_request(struct download *d, header_t *header);
static void download_push_ready(struct download *d, getline_t *empty);
static void download_push_remove(struct download *d);

/*
 * This structure is used to encapsulate the various arguments required
 * by the header parsing I/O callback.
 */
struct io_header {
	struct download *download;
	header_t *header;
	getline_t *getline;
	void (*process_header)(struct io_header *);
	gint flags;
};

#define IO_STATUS_LINE		0x00000002	/* First line is a status line */
#define IO_ONE_LINE			0x00000004	/* Get one line only, then process */

/* ----------------------------------------- */

/*
 * download_init
 *
 * Initialize downloading data structures.
 */
void download_init(void)
{
	pushed_downloads = g_hash_table_new(g_str_hash, g_str_equal);
}

/* ----------------------------------------- */

/* Return the current number of running downloads */

static guint32 count_running_downloads(void)
{
	GSList *l;
	guint32 establishing = 0;
	guint32 active = 0;

	for (l = sl_downloads; l; l = l->next) {
		struct download *d = (struct download *) l->data;
		if (DOWNLOAD_IS_ESTABLISHING(d))
			establishing++;
		else if (DOWNLOAD_IS_ACTIVE(d))
			active++;
	}

	gui_update_c_downloads(active, establishing + active);

	return establishing + active;
}

static guint32 count_running_downloads_with_guid(gchar * guid)
{
	GSList *l;
	guint32 n = 0;

	for (l = sl_downloads; l; l = l->next)
		if (DOWNLOAD_IS_RUNNING((struct download *) l->data))
			if (!memcmp(((struct download *) l->data)->guid, guid, 16))
				n++;

	return n;
}

static guint32 count_running_downloads_with_name(const char *name)
{
	GSList *l;
	guint32 n = 0;

	for (l = sl_downloads; l; l = l->next)
		if (DOWNLOAD_IS_RUNNING((struct download *) l->data)
			&& 0 == strcmp(((struct download *) l->data)->file_name, name))
			n++;

	return n;
}

static gboolean has_same_active_download(gchar *file, gchar *guid)
{
	/*
	 * Check whether we already have an identical (same file, same GUID)
	 * active download as the specified one.
	 *		--RAM, 04/11/2001
	 */

	GSList *l;

	for (l = sl_downloads; l; l = l->next) {
		struct download *d = (struct download *) l->data;
		if (DOWNLOAD_IS_STOPPED(d) || DOWNLOAD_IS_WAITING(d))
			continue;
		if (0 == strcmp(file, d->file_name) && 0 == memcmp(guid, d->guid, 16))
			return TRUE;
	}

	return FALSE;
}

static void queue_remove_all_named(const gchar *name)
{
	/*
	 * Remove downloads from the queue bearing given name
	 *		--RAM, 26/09/2001
	 */

	guint row;
	GSList *to_remove = NULL;
	GSList *l;
	guint row_count = GTK_CLIST(clist_download_queue)->rows;

	gtk_clist_freeze(GTK_CLIST(clist_download_queue));
	for (row = 0; row < row_count; row++) {
		struct download *d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_download_queue), row);

		if (!DOWNLOAD_IS_QUEUED(d))
			g_warning("queue_remove_all_named(): "
				"Download '%s' is not in queued state ! (state = %d)",
				 d->file_name, d->status);

		if (0 == strcmp(name, d->file_name))
			to_remove = g_slist_prepend(to_remove, d);
	}
	gtk_clist_thaw(GTK_CLIST(clist_download_queue));

	for (l = to_remove; l; l = l->next)
		download_free((struct download *) l->data);

	g_slist_free(to_remove);
}

/*
 * GUI operations
 */

/* Add a download to the GUI */

void download_gui_add(struct download *d)
{
	gchar *titles[4];
	gint row;

	g_return_if_fail(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_add() called on already visible download '%s' !",
			 d->file_name);
		return;
	}

	titles[0] = d->file_name;
	titles[1] = ip_port_to_gchar(d->ip, d->port);
	titles[2] = short_size(d->size);
	titles[3] = "";

	if (DOWNLOAD_IS_QUEUED(d)) {		/* This is a queued download */
		row = gtk_clist_append(GTK_CLIST(clist_download_queue), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_download_queue), row,
							   (gpointer) d);
	} else {					/* This is an active download */

		row = gtk_clist_append(GTK_CLIST(clist_downloads), titles);
		gtk_clist_set_row_data(GTK_CLIST(clist_downloads), row,
							   (gpointer) d);
	}

	d->visible = TRUE;
}

/* Remove a download from the GUI */

void download_gui_remove(struct download *d)
{
	gint row;

	g_return_if_fail(d);

	if (!DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_remove() called on invisible download '%s' !",
			 d->file_name);
		return;
	}

	if (DOWNLOAD_IS_QUEUED(d)) {
		if (selected_queued_download == d)
			selected_queued_download = (struct download *) NULL;
		row =
			gtk_clist_find_row_from_data(GTK_CLIST(clist_download_queue),
										 (gpointer) d);
		if (row != -1)
			gtk_clist_remove(GTK_CLIST(clist_download_queue), row);
		else
			g_warning("download_gui_remove(): "
				"Queued download '%s' not found in clist !?", d->file_name);
	} else {
		if (selected_active_download == d)
			selected_active_download = (struct download *) NULL;
		row =
			gtk_clist_find_row_from_data(GTK_CLIST(clist_downloads),
										 (gpointer) d);
		if (row != -1)
			gtk_clist_remove(GTK_CLIST(clist_downloads), row);
		else
			g_warning("download_gui_remove(): "
				"Active download '%s' not found in clist !?", d->file_name);
	}

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

/* Remove stopped downloads */

void downloads_clear_stopped(gboolean all, gboolean now)
{
	GSList *l = sl_downloads;
	time_t current_time = 0;

	/*
	 * If all == TRUE: remove COMPLETED | ERROR | ABORTED,
	 * else remove only COMPLETED.
	 *
	 * If now == TRUE: remove immediately, else remove only downloads
	 * idle since at least 3 seconds
	 */

	if (l && !now)
		current_time = time(NULL);

	while (l) {
		struct download *d = (struct download *) l->data;
		l = l->next;

		if (!DOWNLOAD_IS_STOPPED(d))
			continue;

		if (all) {
			if (now || (current_time - d->last_update) > 3)
				download_free(d);
		} else if (d->status == GTA_DL_COMPLETED) {
			if (now || (current_time - d->last_update) > 3)
				download_free(d);
		}
	}

	gui_update_download_abort_resume();
	gui_update_download_clear();
}


/*
 * Downloads management
 */

void download_stop(struct download *d, guint32 new_status,
				   const gchar * reason, ...)
{
	/* Stop an active download, close its socket and its data file descriptor */

	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning("download_stop() called on queued download '%s'!",
				  d->file_name);
		return;
	}

	if (DOWNLOAD_IS_STOPPED(d)) {
		g_warning("download_stop() called on stopped download '%s'!",
				  d->file_name);
		return;
	}

	if (d->status == new_status) {
		g_warning("download_stop(): download '%s' already in state %d",
				  d->file_name, new_status);
		return;
	}

	if (d->restart_timer_id) {
		if (d->status != GTA_DL_STOPPED)
			g_warning("download_stop: download \"%s\" has a restart_timer_id.",
				  d->file_name);
		g_source_remove(d->restart_timer_id);
		d->restart_timer_id = 0;
	}

	switch (new_status) {
	case GTA_DL_ERROR:
	case GTA_DL_ABORTED:
	case GTA_DL_COMPLETED:
	case GTA_DL_TIMEOUT_WAIT:
		break;
	case GTA_DL_STOPPED:
		download_start_restart_timer(d);
		break;
	default:
		g_warning("download_stop(): unexpected new status %d !", new_status);
		return;
	}

	/* Close output file */

	if (d->file_desc != -1) {
		close(d->file_desc);
		d->file_desc = -1;
	}

	/* Close socket */

	if (d->socket) {
		socket_free(d->socket);
		d->socket = NULL;
	}

	/* Register the new status, and update the GUI if needed */

	d->status = new_status;
	d->last_update = time((time_t *) NULL);

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->retries = 0;		/* If they retry, go over whole cycle again */

	if (reason) {
		va_list args;
		va_start(args, reason);
		g_vsnprintf(d->error_str, sizeof(d->error_str), reason, args);
		d->error_str[sizeof(d->error_str) - 1] = '\0';	/* May be truncated */
		va_end(args);
		d->remove_msg = d->error_str;
	} else
		d->remove_msg = NULL;

	if (DOWNLOAD_IS_VISIBLE(d))
		gui_update_download(d, TRUE);

	if (new_status == GTA_DL_COMPLETED)
		queue_remove_all_named(d->file_name);

	if (DOWNLOAD_IS_STOPPED(d) && DOWNLOAD_IS_IN_PUSH_MODE(d))
		download_push_remove(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		gui_update_download_abort_resume();
		gui_update_download_clear();
	}

	download_pickup_queued();	/* Can recurse to here via download_stop() */
	count_running_downloads();
}

void download_kill(struct download *d)
{
	/* Kill a active download: remove it from the GUI, and unlink() the file */

	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning("download_kill(): Download is already queued ?!");
		return;
	}

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);
	unlink(dl_tmp);

	download_free(d);
}

void download_queue(struct download *d)
{
	/*
	 * Put a download in the queue :
	 * - it's a new download, but we have reached the max number of
	 *   running downloads
	 * - the user requested it with the popup menu "Move back to the queue"
	 */

	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning("download_queue(): Download is already queued ?!");
		return;
	}

	if (DOWNLOAD_IS_VISIBLE(d))
		download_gui_remove(d);

	if (DOWNLOAD_IS_RUNNING(d))
		download_stop(d, GTA_DL_ABORTED, NULL);

	d->status = GTA_DL_QUEUED;

	download_gui_add(d);
	gui_update_download(d, TRUE);

	if (d->restart_timer_id) {
		g_source_remove(d->restart_timer_id);
		d->restart_timer_id = 0;
	}
}

static void download_queue_delay(struct download *d, guint32 delay)
{
	/*
	 * Put download back to queue, but don't reconsider it for starting
	 * before the next `delay' seconds. -- RAM, 03/09/2001
	 */

	download_queue(d);
	d->last_update = time((time_t *) NULL);
	d->timeout_delay = delay;
}

/*
 * download_push_insert
 *
 * Record that we sent a push request for this download.
 */
static void download_push_insert(struct download *d)
{
	gchar *key;

	g_assert(!d->push);

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%u:%s",
		d->record_index, guid_hex_str(d->guid));
	key = g_strdup(dl_tmp);

	/*
	 * We should not have the download already in the table, since we take care
	 * when starting a download that there is no (active) duplicate.  We also
	 * perform the same check on resuming a stopped download, so the following
	 * warning should not happen.  It will indicate a bug. --RAM, 01/01/2002
	 */

	if (0 != g_hash_table_lookup(pushed_downloads, (gpointer) key)) {
		g_warning("BUG: duplicate push ignored for \"%s\"", d->file_name);
		d->push = FALSE;		/* Don't do it */
	} else {
		g_hash_table_insert(pushed_downloads, (gpointer) key, (gpointer) d);
		d->push = TRUE;
	}
}

/*
 * download_push_remove
 *
 * Forget that we sent a push request for this download.
 */
static void download_push_remove(struct download *d)
{
	gpointer key;
	gpointer value;

	g_assert(d->push);

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%u:%s",
		d->record_index, guid_hex_str(d->guid));

	if (
		g_hash_table_lookup_extended(pushed_downloads, (gpointer) dl_tmp,
			&key, &value)
	) {
		g_assert(value == d);
		g_hash_table_remove(pushed_downloads, (gpointer) dl_tmp);
		g_free(key);
	} else
		g_warning("Tried to remove missing push %s", dl_tmp);

	d->push = FALSE;
}

/* (Re)start a stopped or queued download */

void download_start(struct download *d, gboolean check_allowed)
{
	struct stat st;

	g_return_if_fail(d);

	/*
	 * If caller did not check whether we were allowed to start downloading
	 * this file, do it now. --RAM, 03/09/2001
	 */

	if (check_allowed && (
		count_running_downloads() >= max_downloads ||
		count_running_downloads_with_guid(d->guid) >= max_host_downloads ||
		count_running_downloads_with_name(d->file_name) != 0)
	) {
		if (!DOWNLOAD_IS_QUEUED(d))
			download_queue(d);
		return;
	}

	/*
	 * If the output file already exists, we have to send a partial request
	 * This is done here so multiple downloads of existing files drop out when
	 * they are smaller than the existing file.
	 *
	 * (This code was present in the Debian version 0.13, but moved things
	 * from the "done" dir back to the working dir if the downloaded file
	 * was bigger.	I think the "done" dir is sacred.  Let the user move back
	 * the file if he so wants --RAM, 03/09/2001)
	 */

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);

	if (stat(dl_tmp, &st) != -1)
		d->skip = st.st_size;
	else
		d->skip = 0;

	d->pos = d->skip;
	d->last_update = time((time_t *) NULL);

	/* If the download is in the queue, we remove it from there */
	if (DOWNLOAD_IS_QUEUED(d) && DOWNLOAD_IS_VISIBLE(d))
		download_gui_remove(d);

	/* Is there anything to get at all? */
	if (d->size <= d->pos) {
		d->status = GTA_DL_CONNECTING;
		if (!DOWNLOAD_IS_VISIBLE(d))
			download_gui_add(d);
		download_stop(d, GTA_DL_COMPLETED, "Nothing more to get");
		return;
	}

	if (!send_pushes && d->push)
		download_push_remove(d);

	if (!DOWNLOAD_IS_IN_PUSH_MODE(d) && check_valid_host(d->ip, d->port)) {
		/* Direct download */
		d->status = GTA_DL_CONNECTING;
		d->socket = socket_connect(d->ip, d->port, GTA_TYPE_DOWNLOAD);

		if (!d->socket) {
			if (!DOWNLOAD_IS_VISIBLE(d))
				download_gui_add(d);
			download_stop(d, GTA_DL_ERROR, "Connection failed");
			return;
		}

		d->socket->resource.download = d;
		d->socket->pos = 0;
	} else {					/* We have to send a push request */
		d->status = GTA_DL_PUSH_SENT;
		download_push(d);
	}

	if (!DOWNLOAD_IS_VISIBLE(d))
		download_gui_add(d);

	gui_update_download(d, TRUE);

	count_running_downloads();
}

/* pick up new downloads from the queue as needed */

void download_pickup_queued(void)
{
	guint row;
	time_t now = time((time_t *) NULL);
	gint running = count_running_downloads();

	gtk_clist_freeze(GTK_CLIST(clist_download_queue));
	row = 0;
	while (row < GTK_CLIST(clist_download_queue)->rows
		   && running < max_downloads) {
		struct download *d = (struct download *)
			gtk_clist_get_row_data(GTK_CLIST(clist_download_queue), row);

		if (!DOWNLOAD_IS_QUEUED(d))
			g_warning("download_pickup_queued(): "
				"Download '%s' is not in queued state ! (state = %d)",
				 d->file_name, d->status);

		if ((now - d->last_update) > d->timeout_delay &&
			count_running_downloads_with_guid(d->guid) < max_host_downloads
			&& count_running_downloads_with_name(d->file_name) == 0
		) {
			download_start(d, FALSE);
			if (!DOWNLOAD_IS_QUEUED(d))
				running++;
		} else
			row++;
	}
	gtk_clist_thaw(GTK_CLIST(clist_download_queue));
}

void download_push(struct download *d)
{
	g_return_if_fail(d);

	if (!send_pushes) {
		if (d->push)
			download_push_remove(d);
		goto attempt_retry;
	}

	/*
	 * The push request is sent with the listening port set to our Gnet port.
	 *
	 * To be able to later distinguish which download is referred to by each
	 * GIV we'll receive back, we record the association file_index/guid of
	 * the to-be-downloaded file with this download into a hash table.
	 * When stopping a download for which d->push is true, we'll have to
	 * remove the mapping.
	 *
	 *		--RAM, 30/12/2001
	 */

	if (!d->push)
		download_push_insert(d);

	g_assert(d->push);
	if (!send_push_request(d->guid, d->record_index, listen_port)) {
		if (d->status == GTA_DL_FALLBACK) {
			download_push_remove(d);
			goto attempt_retry;
		} else
			download_stop(d, GTA_DL_ERROR, "Route lost");
	}

	return;

attempt_retry:
	if (++d->retries <= download_max_retries)
		download_queue_delay(d, DL_RUN_DELAY);
	else
		download_stop(d, GTA_DL_ERROR, "Timeout");

}

/* Direct download failed, let's try it with a push request */

void download_fallback_to_push(struct download *d, gboolean user_request)
{
	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning
			("download_fallback_to_push() called on a queued download !?!");
		return;
	}

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	if (!d->socket)
		g_warning("download_fallback_to_push(): no socket for '%s'",
				  d->file_name);
	else {
		d->socket->resource.download = NULL;
		socket_destroy(d->socket);
		d->socket = NULL;
	}

	if (d->file_desc != -1) {
		close(d->file_desc);
		d->file_desc = -1;
	}

	if (user_request)
		d->status = GTA_DL_PUSH_SENT;
	else
		d->status = GTA_DL_FALLBACK;

	download_push(d);

	gui_update_download(d, TRUE);
}

static void escape_filename(gchar *file)
{
	/* Inline substitution of all "/" by "_" within file name */

	gchar *s;

	s = file;
	while (*s) {
		if (*s == '/')
			*s = '_';
		s++;
	}
}

/*
 * Downloads creation and destruction
 */

/* Create a new download */

static void create_download(
	gchar *file, guint32 size, guint32 record_index,
	guint32 ip, guint16 port, gchar *guid, gboolean push,
	gboolean interactive)
{
	struct download *d;
	gchar *file_name = interactive ? g_strdup(file) : file;

	/* Replace all slashes by underscores in the file name */

	if (interactive) 		/* Was already done in auto_download_new() */
		escape_filename(file_name);

	/*
	 * Refuse to queue the same download twice. --RAM, 04/11/2001
	 */

	if (has_same_active_download(file_name, guid)) {
		if (interactive)
			g_warning("rejecting duplicate download for %s", file_name);
		g_free(file_name);
		return;
	}

	d = (struct download *) g_malloc0(sizeof(struct download));

	d->path = g_strdup(save_file_path);
	d->file_name = file_name;
	d->size = size;
	d->record_index = record_index;
	d->ip = ip;
	d->port = port;
	d->file_desc = -1;
	memcpy(d->guid, guid, 16);
	d->restart_timer_id = 0;
	if (push)
		download_push_insert(d);
	else
		d->push = FALSE;

	sl_downloads = g_slist_prepend(sl_downloads, (gpointer) d);

	if (
		count_running_downloads() < max_downloads &&
		count_running_downloads_with_guid(d->guid) < max_host_downloads &&
		count_running_downloads_with_name(d->file_name) == 0
	) {
		download_start(d, FALSE);		/* Starts the download immediately */
	} else {
		/* Max number of downloads reached, we have to queue it */
		download_queue(d);
	}
}


/* Automatic download request */

void auto_download_new(gchar * file, guint32 size, guint32 record_index,
					   guint32 ip, guint16 port, gchar * guid, gboolean push)
{
	gchar dl_tmp[4096];
	gchar *file_name = g_strdup(file);
	struct stat buf;
	char *reason;
	int tmplen;

	escape_filename(file_name);

	/*
	 * Make sure we have not got a bigger file in the "download dir".
	 */

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", save_file_path, file_name);
	dl_tmp[sizeof(dl_tmp)-1] = '\0';

	if (-1 != stat(dl_tmp, &buf) && buf.st_size >= size) {
		reason = "downloaded file bigger";
		goto abort_download;
	}

	/*
	 * Make sure we have not got a bigger file in the "completed dir".
	 *
	 * We must also check for bigger files bearing our renaming exts,
	 * i.e. .01, .02, etc... and keep going while files exist.
	 */

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", move_file_path, file_name);
	dl_tmp[sizeof(dl_tmp)-1] = '\0';

	if (-1 != stat(dl_tmp, &buf) && buf.st_size >= size) {
		reason = "complete file bigger";
		goto abort_download;
	}

	tmplen = strlen(dl_tmp);
	if (tmplen >= sizeof(dl_tmp) - 4) {
		g_warning("'%s' in completed dir is too long for further checks",
			file_name);
	} else {
		int i;
		for (i = 1; i < 100; i++) {
			gchar ext[4];

			g_snprintf(ext, 4, ".%02d", i);
			dl_tmp[tmplen] = '\0';				/* Ignore prior attempt */
			strncat(dl_tmp+tmplen, ext, 3);		/* Append .01, .02, ...*/

			if (-1 == stat(dl_tmp, &buf))
				break;							/* No file, stop scanning */

			if (buf.st_size >= size) {
				g_snprintf(dl_tmp, sizeof(dl_tmp),
					"alternate complete file #%d bigger", i);
				reason = dl_tmp;
				goto abort_download;
			}
		}
	}

	create_download(file_name, size, record_index, ip, port, guid, push, FALSE);
	return;

abort_download:
	if (dbg > 4)
		printf("ignoring auto download for '%s': %s\n", file_name, reason);
	g_free(file_name);
	return;
}

/* search has detected index change in queued download --RAM, 18/12/2001 */

void download_index_changed(guint32 ip, guint16 port, guchar *guid,
	guint32 from, guint32 to)
{
	GSList *l;
	gint nfound = 0;

	for (l = sl_downloads; l; l = l->next) {
		struct download *d = (struct download *) l->data;

		if (
			d->ip == ip &&
			d->port == port &&
			d->record_index == from &&
			0 == memcmp(d->guid, guid, 16)
		) {
			gboolean push_mode = d->push;

			/*
			 * When in push mode, we've recorded the index in a hash table,
			 * associating the GIV string to the download structure.
			 * If that index changes, we need to remove the old mapping before
			 * operating the change, and re-install the new mapping after
			 * then change took place.
			 */

			if (push_mode)
				download_push_remove(d);

			d->record_index = to;
			nfound++;

			if (push_mode)
				download_push_insert(d);

			switch (d->status) {
			case GTA_DL_REQ_SENT:
			case GTA_DL_HEADERS:
			case GTA_DL_PUSH_SENT:
				/*
				 * We've sent a request with possibly the wrong index.
				 * We can't know for sure, but it's safer to stop it, and
				 * restart it in a while.  Sure, we might loose the download
				 * slot, but we might as well have gotten a wrong file.
				 *
				 * NB: this can't happen when the remote peer is gtk-gnutella
				 * since we check the matching between the index and the file
				 * name, but some peers might not bother.
				 */
				g_warning("Stopping request for '%s': index changed",
					d->file_name);
				download_stop(d, GTA_DL_STOPPED, "Stopped (Index changed)");
				break;
			case GTA_DL_RECEIVING:
				/*
				 * Ouch.  Pray and hope that the change occurred after we
				 * requested the file.  There's nothing we can do now.
				 */
				g_warning("Index of '%s' changed during reception",
					d->file_name);
				break;
			default:
				/*
				 * Queued or other state not needing special notice
				 */
				if (dbg > 3)
					printf("Noted index change from %u to %u at %s for %s",
						from, to, guid_hex_str(guid), d->file_name);
				break;
			}
		}
	}

	/*
	 * This is a sanity check: we should not have any duplicate request
	 * in our download list.
	 */

	if (nfound > 1)
		g_warning("Found %d requests for index %d (now %d) at %s",
			nfound, from, to, ip_port_to_gchar(ip, port));
}


/* Create a new download */

void download_new(gchar * file, guint32 size, guint32 record_index,
				  guint32 ip, guint16 port, gchar * guid, gboolean push)
{
	create_download(file, size, record_index, ip, port, guid, push, TRUE);
}


/* Free a download. */

void download_free(struct download *d)
{
	g_return_if_fail(d);

	if (DOWNLOAD_IS_VISIBLE(d))
		download_gui_remove(d);

	if (DOWNLOAD_IS_RUNNING(d))
		download_stop(d, GTA_DL_ABORTED, NULL);

	sl_downloads = g_slist_remove(sl_downloads, (gpointer) d);

	if (d->restart_timer_id)
		g_source_remove(d->restart_timer_id);

	if (d->push)
		download_push_remove(d);

	g_free(d->path);
	g_free(d->file_name);
	g_free(d);
}

/* ----------------------------------------- */

void download_abort(struct download *d)
{
	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning("download_abort() called on queued download '%s'!",
				  d->file_name);
		return;
	}

	if (DOWNLOAD_IS_STOPPED(d))
		return;

	download_stop(d, GTA_DL_ABORTED, NULL);
}

void download_resume(struct download *d)
{
	g_return_if_fail(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		g_warning("download_resume() called on queued download '%s'!",
				  d->file_name);
		return;
	}

	if (DOWNLOAD_IS_RUNNING(d))
		return;

	if (has_same_active_download(d->file_name, d->guid)) {
		d->status = GTA_DL_CONNECTING;		/* So we may call download_stop */
		download_stop(d, GTA_DL_ERROR, "Duplicate");
		return;
	}

	download_start(d, TRUE);
}

/*
 * IO functions
 */

/* Based on patch from Myers W. Carpenter <myers@fil.org> */

void download_move_to_completed_dir(struct download *d)
{
	/* Move a complete file to move_file_path */

	gchar dl_src[4096];
	gchar dl_dest[4096];
	gint return_tmp, return_tmp2;
	struct stat buf;

	if (0 == strcmp(d->path, move_file_path))
		return;			/* Already in "completed dir" */

	g_snprintf(dl_src, sizeof(dl_src), "%s/%s", d->path, d->file_name);
	g_snprintf(dl_dest, sizeof(dl_dest), "%s/%s", move_file_path,
			   d->file_name);

	dl_src[sizeof(dl_src)-1] = '\0';
	dl_dest[sizeof(dl_dest)-1] = '\0';

	/*
	 * If, by extraordinary, there is already a file in the "completed dir"
	 * with the same name, don't overwrite the existing file.
	 *
	 * NB: we assume either there is only one gnutella servent running, or if
	 * several ones are running, that they are configured to use different
	 * download and completed dirs.
	 *
	 *		--RAM, 03/11/2001
	 */

	if (-1 != stat(dl_dest, &buf)) {
		gchar dl_tmp[4096];
		int destlen = strlen(dl_dest);
		int i;

		/*
		 * There must be enough room for us to append the ".xx" extensions.
		 * That's 3 chars, plus the trailing NUL.
		 */

		if (destlen >= sizeof(dl_dest) - 4) {
			g_warning("Found '%s' in completed dir, and path already too long",
				d->file_name);
			return;
		}

		strncpy(dl_tmp, dl_dest, destlen);

		for (i = 1; i < 100; i++) {
			gchar ext[4];

			g_snprintf(ext, 4, ".%02d", i);
			dl_tmp[destlen] = '\0';				/* Ignore prior attempt */
			strncat(dl_tmp+destlen, ext, 3);	/* Append .01, .02, ...*/
			if (-1 == stat(dl_tmp, &buf))
				break;
		}

		if (i == 100) {
			g_warning("Found '%s' in completed dir, "
				"and was unable to find another unique name",
				d->file_name);
			return;
		}

		strncat(dl_dest+destlen, dl_tmp+destlen, 3);

		g_warning("Moving completed file as '%s'", dl_dest);
	}

	/* First try and link it to the new locatation */

	return_tmp = rename(dl_src, dl_dest);

	if (return_tmp == -1 && (errno == EXDEV || errno == EPERM)) {
		/* link failed becase either the two paths aren't on the */
		/* same filesystem or the filesystem doesn't support hard */
		/* links, so we have to do a copy. */

		gint tmp_src, tmp_dest;
		gboolean ok = FALSE;

		if ((tmp_src = open(dl_src, O_RDONLY)) < 0) {
			g_warning("Unable to open() file '%s' (%s) !", dl_src,
					  g_strerror(errno));
			return;
		}

		if ((tmp_dest =
			 open(dl_dest, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
			close(tmp_src);
			g_warning("Unable to create file '%s' (%s) !", dl_src,
					  g_strerror(errno));
			return;
		}

		for (;;) {
			return_tmp = read(tmp_src, dl_tmp, sizeof(dl_tmp));

			if (!return_tmp) {
				ok = TRUE;
				break;
			}

			if (return_tmp < 0) {
				g_warning("download_move_to_completed_dir(): "
					"error reading while moving file to save directory (%s)",
					 g_strerror(errno));
				break;
			}

			return_tmp2 = write(tmp_dest, dl_tmp, return_tmp);

			if (return_tmp2 < 0) {
				g_warning("download_move_to_completed_dir(): "
					"error writing while moving file to save directory (%s)",
					 g_strerror(errno));
				break;
			}

			if (return_tmp < sizeof(dl_tmp)) {
				ok = TRUE;
				break;
			}
		}

		close(tmp_dest);
		close(tmp_src);
		if (ok)
			unlink(dl_src);
	}

	return;
}

/*
 * send_push_request
 *
 * Send a push request to the target GUID, in order to request the push of
 * the file whose index is `file_id' there onto our local port `port'.
 *
 * Returns TRUE if the request could be sent, FALSE if we don't have the route.
 */
static gboolean send_push_request(gchar *guid, guint32 file_id, guint16 port)
{
	struct gnutella_msg_push_request m;
	struct gnutella_node *n;

	n = route_towards_guid(guid);
	if (!n)
		return FALSE;

	message_set_muid(&(m.header), FALSE);

	m.header.function = GTA_MSG_PUSH_REQUEST;
	m.header.ttl = my_ttl;
	m.header.hops = 0;

	WRITE_GUINT32_LE(sizeof(struct gnutella_push_request), m.header.size);

	memcpy(&(m.request.guid), guid, 16);

	WRITE_GUINT32_LE(file_id, m.request.file_id);
	WRITE_GUINT32_BE((force_local_ip) ? forced_local_ip : local_ip,
					 m.request.host_ip);
	WRITE_GUINT16_LE(port, m.request.host_port);

	message_add(m.header.muid, GTA_MSG_PUSH_REQUEST, NULL);
	sendto_one(n, (guchar *) & m, NULL,
			   sizeof(struct gnutella_msg_push_request));

	return TRUE;
}

static gboolean download_queue_w(gpointer dp)
{
	struct download *d = (struct download *) dp;
	download_queue(d);
	download_pickup_queued();
	return TRUE;
}

static void download_start_restart_timer(struct download *d)
{
	d->restart_timer_id = g_timeout_add(DL_RETRY_TIMER * 1000,
		download_queue_w, d);
}

/***
 *** Header parsing callbacks
 ***
 *** We could call those directly, but I'm thinking about factoring all
 *** that processing into a generic set of functions, and the processing
 *** callbacks will all have the same signature.  --RAM, 30/12/2001
 ***/

static void call_download_request(struct io_header *ih)
{
	download_request(ih->download, ih->header);
}

static void call_download_push_ready(struct io_header *ih)
{
	download_push_ready(ih->download, ih->getline);
}

/***
 *** Read data on a download socket
 ***/

/*
 * download_header_parse
 *
 * This routine is called to parse the input buffer, a line at a time,
 * until EOH is reached.
 */
static void download_header_parse(struct io_header *ih)
{
	struct download *d = ih->download;
	struct gnutella_socket *s = d->socket;
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
		g_warning("download_header_parse: line too long, disconnecting from %s",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		download_stop(d, GTA_DL_ERROR, "Failed (Header too large)");
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

	if (ih->flags & IO_STATUS_LINE) {
		/*
		 * Save status line away in socket's "getline" object, then clear
		 * the fact that we're expecting a status line and continue to get
		 * the following header lines.
		 */

		g_assert(s->getline == 0);
		s->getline = getline_make();

		getline_copy(getline, s->getline);
		getline_reset(getline);
		ih->flags &= ~IO_STATUS_LINE;
		goto nextline;
	}

	if (ih->flags & IO_ONE_LINE) {
		/*
		 * Call processing routine immediately, then terminate processing.
		 * Remove the I/O callback input before invoking the callback.
		 */

		gdk_input_remove(s->gdk_tag);
		s->gdk_tag = 0;

		ih->process_header(ih);
		goto final_cleanup;
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
	case HEAD_EOH_REACHED:
		g_warning("download_header_parse: %s, disconnecting from %s",
			header_strerror(error),  ip_to_gchar(s->ip));
		fprintf(stderr, "------ Header Dump:\n");
		header_dump(header, stderr);
		fprintf(stderr, "------\n");
		dump_hex(stderr, "Header Line", getline_str(getline),
			MIN(getline_length(getline), 128));
		download_stop(d, GTA_DL_ERROR, "Failed (%s)", header_strerror(error));
		goto final_cleanup;
		/* NOTREACHED */
	default:					/* Error, but try to continue */
		g_warning("download_header_parse: %s, from %s",
			header_strerror(error), ip_to_gchar(s->ip));
		dump_hex(stderr, "Header Line",
			getline_str(getline), getline_length(getline));
		getline_reset(getline);
		goto nextline;			/* Go process other lines we may have read */
	}

	/*
	 * We reached the end of headers.  Downloaded data should follow.
	 * Remove the I/O callback input before invoking the processing callback.
	 */

	gdk_input_remove(s->gdk_tag);
	s->gdk_tag = 0;

	ih->process_header(ih);

	/* FALL THROUGH */

	/*
	 * When we come here, we're done with the parsing structures, we can
	 * free them.
	 */

final_cleanup:
	if (ih->header)
		header_free(ih->header);
	getline_free(ih->getline);
	g_free(ih);
}

/*
 * download_header_read
 *
 * This routine is installed as an input callback to read the HTTP headers
 * of the request.
 */
static void download_header_read(
	gpointer data, gint source, GdkInputCondition cond)
{
	struct io_header *ih = (struct io_header *) data;
	struct download *d = ih->download;
	struct gnutella_socket *s = d->socket;
	guint count;
	gint r;

	if (cond & GDK_INPUT_EXCEPTION) {
		download_stop(d, GTA_DL_ERROR, "Failed (Input Exception)");
		goto final_cleanup;
	}

	/*
	 * Update status and GUI.
	 */

	if (d->status != GTA_DL_HEADERS) {
		d->status = GTA_DL_HEADERS;
		gui_update_download(d, TRUE);
	}

	count = sizeof(s->buffer) - s->pos - 1;		/* -1 to allow trailing NUL */
	if (count <= 0) {
		g_warning("download_header_read: incoming buffer full, "
			"disconnecting from %s", ip_to_gchar(s->ip));
		dump_hex(stderr, "Leading Data", s->buffer, MIN(s->pos, 256));
		download_stop(d, GTA_DL_ERROR, "Failed (Input buffer full)");
		goto final_cleanup;
	}

	r = read(s->file_desc, s->buffer + s->pos, count);
	if (r == 0) {
		download_stop(d, GTA_DL_STOPPED, "Stopped (EOF)");
		goto final_cleanup;
	} else if (r < 0 && errno == EAGAIN)
		return;
	else if (r < 0) {
		if (errno == ECONNRESET)
			download_stop(d, GTA_DL_STOPPED, "Stopped (%s)",
				g_strerror(errno));
		else
			download_stop(d, GTA_DL_ERROR, "Failed (Read error: %s)",
				g_strerror(errno));
		goto final_cleanup;
	}

	/*
	 * During the header reading phase, we do update "d->last_update".
	 */

	s->pos += r;
	d->last_update = time((time_t *) 0);
	d->retries = 0;		/* successful read means our retry was successful */

	download_header_parse(ih);
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
 * download_write_data
 *
 * Write data in socket buffer to file.
 */
static void download_write_data(struct download *d)
{
	struct gnutella_socket *s = d->socket;
	gint written;

	g_assert(s->pos > 0);

	if (-1 == (written = write(d->file_desc, s->buffer, s->pos))) {
		char *error = g_strerror(errno);
		g_warning("download_read(): write to file failed (%s) !", error);
		g_warning("download_read: tried to write(%d, %p, %d)",
			  d->file_desc, s->buffer, s->pos);
		download_stop(d, GTA_DL_ERROR, "Can't save data: %s", error);
		return;
	} else if (written < s->pos) {
		g_warning("download_read(): "
			"partial write of %d out of %d bytes to file '%s'",
			written, s->pos, d->file_name);
		download_stop(d, GTA_DL_ERROR, "Partial write to file");
		return;
	}

	d->pos += s->pos;
	s->pos = 0;

	/*
	 * End download if we have completed it.
	 */

	if (d->pos >= d->size) {
		download_stop(d, GTA_DL_COMPLETED, NULL);
		download_move_to_completed_dir(d);
		count_downloads++;
		gui_update_count_downloads();
	} else
		gui_update_download(d, FALSE);
}

/*
 * download_request
 *
 * Called to initiate the download once all the HTTP headers have been read.
 * Validate the reply, and begin saving the incoming data if OK.
 * Otherwise, stop the download.
 */
static void download_request(struct download *d, header_t *header)
{
	struct gnutella_socket *s = d->socket;
	gchar *status = getline_str(s->getline);
	gint ack_code;
	gchar *ack_message = "";
	gchar *buf;
	struct stat st;
	gboolean got_content_length = FALSE;

	d->last_update = time((time_t *) 0);	/* Done reading headers */

	if (dbg > 4) {
		printf("----Got reply from %s:\n", ip_to_gchar(s->ip));
		printf("%s\n", status);
		header_dump(header, stdout);
		printf("----\n");
		fflush(stdout);
	}

	ack_code = parse_status_line(status, "HTTP", &ack_message, NULL, NULL);

	if (ack_code == -1) {
		g_warning("weird HTTP acknowledgment status line from %s",
			ip_to_gchar(s->ip));
		dump_hex(stderr, "Status Line", status,
			MIN(getline_length(s->getline), 80));
		download_stop(d, GTA_DL_ERROR, "Weird HTTP status");
		return;
	}

	if (ack_code >= 200 && ack_code <= 299) {
		/* empty -- everything OK */
	} else if (ack_code >= 500 && ack_code <= 599) {
		/* No hammering */
		download_queue_delay(d, DL_RUN_DELAY);
		return;
	} else {
		download_stop(d, GTA_DL_ERROR, "HTTP %d %s", ack_code, ack_message);
		return;
	}

	/*
	 * We got a success status from the remote servent.  Parse header.
	 *
	 * Normally, a Content-Length: header is mandatory.  However, if we
	 * get a valid Content-Range, relax that constraint a bit.
	 *		--RAM, 08/01/2002
	 */

	buf = header_get(header, "Content-Length");		/* Mandatory */
	if (buf) {
		guint32 z = atol(buf);
		if (z == 0) {
			download_stop(d, GTA_DL_ERROR, "Bad length !?");
			return;
		} else if (z + d->skip != d->size) {
			if (z == d->size) {
				g_warning("File '%s': server seems to have "
					"ignored our range request of %u.",
					d->file_name, d->size);
				download_stop(d, GTA_DL_ERROR,
					"Server can't handle resume request");
				return;
			} else {
				g_warning("File '%s': expected size %u but server said %u",
					d->file_name, d->size, z + d->skip);
				download_stop(d, GTA_DL_ERROR, "File size mismatch");
				return;
			}
		}
		got_content_length = TRUE;
	}

	buf = header_get(header, "Content-Range");		/* Optional */
	if (buf) {
		guint32 start, end, total;
		if (
			sscanf(buf, "bytes %d-%d/%d", &start, &end, &total) ||	/* Good */
			sscanf(buf, "bytes=%d-%d/%d", &start, &end, &total)		/* Bad! */
		) {
			if (start != d->skip) {
				g_warning("File '%s': start byte mismatch: wanted %u, got %u",
					d->file_name, d->skip, start);
				download_stop(d, GTA_DL_ERROR, "Range start mismatch");
				return;
			}
			if (total != d->size) {
				g_warning("File '%s': file size mismatch: expected %u, got %u",
					d->file_name, d->size, total);
				download_stop(d, GTA_DL_ERROR, "File size mismatch");
				return;
			}
			got_content_length = TRUE;
		} else {
			g_warning("File '%s': malformed Content-Range: %s",
				d->file_name, buf);
		}
	}

	/*
	 * If neither Content-Length nor Content-Range was seen, abort!
	 *
	 * If we were talking to an official web-server, we'd assume the length
	 * to be correct and would be reading until EOF, but we're talking to
	 * an unknown party, that we cannot trust too much.
	 *		--RAM, 09/01/2002
	 */

	if (!got_content_length) {
		char *ua = header_get(header, "Server");
		ua = ua ? ua : header_get(header, "User-Agent");
		if (ua)
			g_warning("server \"%s\" did not send any length indication", ua);
		download_stop(d, GTA_DL_ERROR, "No Content-Length header");
		return;
	}

	/*
	 * Open output file.
	 */

	g_assert(d->file_desc == -1);

	g_snprintf(dl_tmp, sizeof(dl_tmp), "%s/%s", d->path, d->file_name);

	if (stat(dl_tmp, &st) != -1) {
		/* File exists, we'll append the data to it */
		if (st.st_size != d->skip) {
			g_warning("File '%s' changed size (now %ld, but was %d)",
				d->file_name, st.st_size, d->skip);
			download_stop(d, GTA_DL_ERROR, "File modified since start");
			return;
		}

		d->file_desc = open(dl_tmp, O_WRONLY);
	} else {
		if (d->skip) {
			download_stop(d, GTA_DL_ERROR, "Cannot resume: file gone");
			return;
		}
		d->file_desc = open(dl_tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	}

	if (d->file_desc == -1) {
		gchar *error = g_strerror(errno);
		g_warning("Unable to open file '%s' for writing! (%s)",
			dl_tmp, error);
		download_stop(d, GTA_DL_ERROR, "Cannot write into file: %s", error);
		return;
	}

	if (d->skip && -1 == lseek(d->file_desc, d->skip, SEEK_SET)) {
		download_stop(d, GTA_DL_ERROR, "Unable to seek: %s",
			g_strerror(errno));
		return;
	}

	/*
	 * We're ready to receive.
	 */

	d->start_date = time((time_t *) NULL);
	d->status = GTA_DL_RECEIVING;
	gui_update_download(d, TRUE);

	s->gdk_tag = gdk_input_add(s->file_desc,
		GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		download_read, (gpointer) d);

	/*
	 * If we have something in the input buffer, write the data to the
	 * file immediately.  Note that this may close the download immediately
	 * if the whole file was already read in the socket buffer.
	 */

	if (s->pos > 0)
		download_write_data(d);
}

/*
 * download_read
 *
 * Read callback for file data.
 */
static void download_read(gpointer data, gint source, GdkInputCondition cond)
{
	struct download *d = (struct download *) data;
	struct gnutella_socket *s;
	gint32 r;
	gint32 to_read, remains;

	g_return_if_fail(d);
	s = d->socket;
	g_return_if_fail(s);

	if (cond & GDK_INPUT_EXCEPTION) {
		download_stop(d, GTA_DL_ERROR, "Failed (Input Exception)");
		return;
	}

	g_assert(s->pos >= 0 && s->pos <= sizeof(s->buffer));

	if (s->pos == sizeof(s->buffer)) {
		download_stop(d, GTA_DL_STOPPED, "Stopped (Read buffer full)");
		return;
	}

	g_assert(d->pos <= d->size);

	if (d->pos == d->size) {
		download_stop(d, GTA_DL_ERROR, "Failed (Completed?)");
		return;
	}

	remains = sizeof(s->buffer) - s->pos;
	to_read = d->size - d->pos;
	if (remains < to_read)
		to_read = remains;			/* Only read to fill buffer */

	r = read(s->file_desc, s->buffer + s->pos, to_read);

	if (r <= 0) {
		if (r == 0) {
			download_stop(d, GTA_DL_STOPPED, "Stopped (EOF)");
		} else if (errno != EAGAIN) {
			if (errno == ECONNRESET)
				download_stop(d, GTA_DL_STOPPED,
					"Stopped (%s)", g_strerror(errno));
			else
				download_stop(d, GTA_DL_ERROR,
					"Failed (Read error: %s)", g_strerror(errno));
		}
		return;
	}

	s->pos += r;
	d->last_update = time((time_t *) 0);

	g_assert(s->pos > 0);

	download_write_data(d);
}

/*
 * Send the HTTP request for a download, then prepare I/O reading callbacks
 * to read the incoming status line and following headers.
 */
gboolean download_send_request(struct download *d)
{
	struct gnutella_socket *s = d->socket;
	struct io_header *ih;
	gint rw;
	gint sent;

	g_return_val_if_fail(d, FALSE);

	if (!s) {
		g_warning("download_send_request(): No socket for '%s'", d->file_name);
		download_stop(d, GTA_DL_ERROR, "Internal Error");
		return FALSE;
	}

	/* Send the HTTP Request */

	if (d->skip)
		rw = g_snprintf(dl_tmp, sizeof(dl_tmp),
			"GET /get/%u/%s HTTP/1.0\r\n"
			"Connection: Keep-Alive\r\n"
			"Range: bytes=%u-\r\n"
			"User-Agent: %s\r\n\r\n",
			d->record_index, d->file_name, d->skip,
			version_string);
	else
		rw = g_snprintf(dl_tmp, sizeof(dl_tmp),
			"GET /get/%u/%s HTTP/1.0\r\n"
			"Connection: Keep-Alive\r\n"
			"User-Agent: %s\r\n\r\n",
			d->record_index, d->file_name,
			version_string);

	if (-1 == (sent = write(d->socket->file_desc, dl_tmp, rw))) {
		download_stop(d, GTA_DL_ERROR, "Write failed: %s", g_strerror(errno));
		return FALSE;
	} else if (sent < rw) {
		download_stop(d, GTA_DL_ERROR, "Partial write: wrote %d of %d bytes",
			sent, rw);
		return FALSE;
	} else if (dbg > 4) {
		printf("----Sent Request to %s:\n%.*s----\n",
			ip_port_to_gchar(d->ip, d->port), (int) rw, dl_tmp);
		fflush(stdout);
	}

	/*
	 * Update status and GUI.
	 */

	d->last_update = time((time_t *) 0);
	d->status = GTA_DL_REQ_SENT;
	gui_update_download(d, TRUE);

	/*
	 * Now prepare to read the status line and the headers.
	 */

	ih = (struct io_header *) g_malloc(sizeof(struct io_header));
	ih->download = d;
	ih->header = header_make();
	ih->getline = getline_make();
	ih->flags = IO_STATUS_LINE;		/* First line will be a status line */
	ih->process_header = call_download_request;

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		download_header_read, (gpointer) ih);

	return TRUE;
}

/*
 * download_push_ready
 *
 * Send download request on the opened connection.
 *
 * Header processing callback, invoked when we have read the second "\n" at
 * the end of the GIV string.
 */
static void download_push_ready(struct download *d, getline_t *empty)
{
	gint len = getline_length(empty);

	if (len != 0) {
		g_warning("File '%s': push reply was not followed by an empty line",
			d->file_name);
		dump_hex(stderr, "Extra GIV data", getline_str(empty), MIN(len, 80));
		download_stop(d, GTA_DL_ERROR, "Malformed push reply");
		return;
	}

	/*
	 * Free up the s->getline structure which holds the GIV line.
	 */

	g_assert(d->socket->getline);
	getline_free(d->socket->getline);
	d->socket->getline = NULL;

	download_send_request(d);
}

/*
 * download_push_ack
 *
 * Initiate download on the remotely initiated connection.
 *
 * This is called when an incoming "GIV" request is received in answer to
 * some of our pushes.
 */
void download_push_ack(struct gnutella_socket *s)
{
	struct download *d;
	gchar *giv;
	guint file_index;		/* The requested file index */
	gchar hex_guid[33];		/* The hexadecimal GUID */
	struct io_header *ih;

	g_assert(s->getline);

	giv = getline_str(s->getline);

	if (dbg > 4) {
		printf("----Got GIV from %s:\n", ip_to_gchar(s->ip));
		printf("%s\n", giv);
		printf("----\n");
		fflush(stdout);
		
	}

	/*
	 * To find out which download this is, we have to parse the incoming
	 * GIV request, which is stored in "s->getline".
	 */

	if (sscanf(giv, "GIV %u:%32c/", &file_index, hex_guid)) {
		gpointer val;

		hex_guid[32] = '\0';
		g_strdown(hex_guid);
		g_snprintf(dl_tmp, sizeof(dl_tmp), "%u:%s",
			file_index, hex_guid);

		val = g_hash_table_lookup(pushed_downloads, (gpointer) dl_tmp);
		if (!val) {
			g_warning("got a GIV without matching download request");
			goto error;
		}
		d = (struct download *) val;
		g_assert(d->record_index == file_index);
	} else {
		g_warning("malformed GIV string");
		goto error;
	}

	/*
	 * We might get another GIV for the same download: we send two pushes
	 * in a row, and with the propagation delay, the first gets handled
	 * after we sent the second push.  We'll get a GIV for an already
	 * connected download.
	 *
	 * We check two things: that we're not already connected (has a socket)
	 * and that we're in a state where we can expect a GIV string.  Doing
	 * the two tests add robustness, since they are overlapping, but not
	 * completely equivalent (if we're in the queued state, for instance).
	 */

	if (d->socket) {
		g_warning("got spurious GIV string: download is connected, state %d",
			d->status);
		goto error;
	}

	if (!DOWNLOAD_IS_EXPECTING_GIV(d)) {
		g_warning("got GIV string in unexpected state (%d), ignoring",
			d->status);
		goto error;
	}

	/*
	 * Install socket for the download.
	 */

	g_assert(d->socket == NULL);

	d->socket = s;
	s->resource.download = d;
	d->last_update = time((time_t *) NULL);

	/*
	 * Now we have to read that trailing "\n" which comes right afterwards.
	 */

	ih = (struct io_header *) g_malloc(sizeof(struct io_header));
	ih->download = d;
	ih->header = NULL;				/* Won't be needed, we read one line */
	ih->getline = getline_make();
	ih->flags = IO_ONE_LINE;		/* Process one line (will be empty) */
	ih->process_header = call_download_push_ready;

	g_assert(s->gdk_tag == 0);

	s->gdk_tag = gdk_input_add(s->file_desc,
		GDK_INPUT_READ | GDK_INPUT_EXCEPTION,
		download_header_read, (gpointer) ih);

	download_header_parse(ih);		/* Data might already be there */
	return;

	/*
	 * We come here on error to log the "faulty" GIV string and close the
	 * connection.
	 */
error:
	dump_hex(stderr, "GIV string", giv,
		MIN(getline_length(s->getline), 128));
	socket_destroy(s);
	return;
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
			d->timeout_delay -=
				(time((time_t *) NULL) - d->start_date) / 10;
		}
	}

	if (d->timeout_delay < download_retry_timeout_min)
		d->timeout_delay = download_retry_timeout_min;
	if (d->timeout_delay > download_retry_timeout_max)
		d->timeout_delay = download_retry_timeout_max;

	download_stop(d, GTA_DL_TIMEOUT_WAIT, NULL);
}

void download_close(void)
{
	GSList *l;

	for (l = sl_downloads; l; l = l->next) {
		struct download *d = (struct download *) l->data;
		if (d->socket)
			g_free(d->socket);
		if (d->push)
			download_push_remove(d);
		g_free(d->path);
		g_free(d->file_name);
		g_free(d);
	}

	g_slist_free(sl_downloads);
	g_hash_table_destroy(pushed_downloads);
}

/* vi: set ts=4: */
