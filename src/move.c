/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Asychronous file moving operations.
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "downloads.h"
#include "move.h"

RCSID("$Id$");

#define COPY_BLOCK_SHIFT	12			/* Power of two of copy unit credit */
#define COPY_BUF_SIZE		65536		/* Size of the reading buffer */

static gpointer move_daemon = NULL;

#define MOVED_MAGIC	0x00c0b100

/*
 * Moving daemon context.
 */
struct moved {
	gint magic;				/* Magic number */
	struct download *d;		/* Download for which we're moving file */
	gint rd;				/* Opened file descriptor for read, -1 if none */
	gint wd;				/* Opened file descriptor for write, -1 if none */
	time_t start;			/* Start time, to determine copying rate */
	off_t size;				/* Size of file */
	off_t copied;			/* Amount of data copied so far */
	gchar *buffer;			/* Large buffer, where data is read */
	gint error;				/* Error code */
};

/*
 * Work queue entry.
 */
struct work {
	struct download *d;		/* Download to move */
	gchar *dest;			/* Target directory (atom) */
	gchar *ext;				/* Trailing extension (atom) */
};

/*
 * we_alloc
 *
 * Allocate work queue entry.
 */
static struct work *we_alloc(
	struct download *d, const gchar *dest, const gchar *ext)
{
	struct work *we;

	we = walloc(sizeof(*we));
	we->d = d;
	we->dest = atom_str_get(dest);
	we->ext = atom_str_get(ext);

	return we;
}

/*
 * we_free
 *
 * Freeing of work queue entry.
 */
static void we_free(gpointer data)
{
	struct work *we = (struct work *) data;

	atom_str_free(we->dest);
	atom_str_free(we->ext);
	wfree(we, sizeof(*we));
}

/*
 * d_free
 *
 * Freeing of computation context.
 */
static void d_free(gpointer ctx)
{
	struct moved *md = (struct moved *) ctx;

	g_assert(md->magic == MOVED_MAGIC);

	if (md->rd != -1)
		close(md->rd);

	if (md->wd != -1)
		close(md->wd);

	g_free(md->buffer);
	wfree(md, sizeof(*md));
}

/*
 * d_notify
 *
 * Daemon's notification of start/stop.
 */
static void d_notify(gpointer h, gboolean on)
{
	gnet_prop_set_boolean_val(PROP_FILE_MOVING, on);
}

/*
 * d_start
 *
 * Daemon's notification: starting to work on item.
 */
static void d_start(gpointer h, gpointer ctx, gpointer item)
{
	struct moved *md = (struct moved *) ctx;
	struct work *we = (struct work *) item;
	struct download *d = we->d;
	char *source = NULL;
	char *target = NULL;
	struct stat buf;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->rd == -1);
	g_assert(md->wd == -1);

	source = g_strdup_printf("%s/%s", download_path(d), download_outname(d));
	g_return_if_fail(NULL != source);

	md->d = we->d;
	md->rd = open(source, O_RDONLY);

	if (md->rd == -1) {
		g_warning("can't open \"%s\" for reading to copy it into %s: %s",
			source, we->dest, g_strerror(errno));
		G_FREE_NULL(source);
		return;
	}

	if (-1 == fstat(md->rd, &buf)) {
		g_warning("can't fstat \"%s\": %s", source, g_strerror(errno));
		goto abort_read;
	}

	if (!S_ISREG(buf.st_mode)) {
		g_warning("file \"%s\" is not a regular file", source);
		goto abort_read;
	}

	target = unique_filename(we->dest, download_outname(d), we->ext);
	if (NULL == target)
		goto abort_read;

	md->wd = open(target, O_WRONLY | O_CREAT | O_TRUNC, buf.st_mode);

	if (md->wd == -1) {
		g_warning("can't create \"%s\": %s", target, g_strerror(errno));
		goto abort_read;
	}

	md->start = time(NULL);
	md->size = (off_t) download_filesize(d);
	md->copied = 0;
	md->error = 0;

	if (dbg > 1)
		printf("Moving \"%s\" to %s\n", download_outname(d), target);

	G_FREE_NULL(source);
	G_FREE_NULL(target);
	download_move_start(d);

	return;

abort_read:
	md->error = errno;
	close(md->rd);
	md->rd = -1;
	if (NULL != source)
		G_FREE_NULL(source);
	if (NULL != target)
		G_FREE_NULL(target);
	return;
}

/*
 * d_end
 *
 * Daemon's notification: finished working on item.
 */
static void d_end(gpointer h, gpointer ctx, gpointer item)
{
	struct moved *md = (struct moved *) ctx;
	time_t elapsed;
	struct download *d = md->d;

	g_assert(md->magic == MOVED_MAGIC);
	g_assert(md->d == ((struct work *) item)->d);

	if (md->rd == -1)			/* Did not start properly */
		return;

	close(md->rd);
	md->rd = -1;

	close(md->wd);
	md->wd = -1;

	if (md->error == 0) {
		gchar *source;

		g_assert(md->copied == md->size);
		
		source = g_strdup_printf("%s/%s",
					download_path(md->d), download_outname(md->d));
		if (NULL == source || -1 == unlink(source))
			g_warning("cannot unlink \"%s\": %s",
				download_outname(md->d), g_strerror(errno));
		if (NULL != source)
			G_FREE_NULL(source);
	}

	elapsed = time(NULL) - md->start;
	elapsed = MAX(1, elapsed);

	if (dbg > 1)
		printf("Moved file \"%s\" at %lu bytes/sec [error=%d]\n",
			download_outname(md->d), (gulong) md->size / elapsed, md->error);

	if (md->error == 0)
		download_move_done(d, elapsed);
	else
		download_move_error(d);
}

/*
 * d_step_copy
 *
 * Copy file around, incrementally.
 */
static bgret_t d_step_copy(gpointer h, gpointer u, gint ticks)
{
	struct moved *md = (struct moved *) u;
	gint r;
	gint amount;
	guint32 remain;
	gint used;

	g_assert(md->magic == MOVED_MAGIC);

	if (md->rd == -1)			/* Could not open the file */
		return BGR_DONE;		/* Computation done */

	if (md->size == 0)			/* Empty file */
		return BGR_DONE;

	remain = md->size - md->copied;

	g_assert(remain > 0);

	/*
	 * Each tick we have can buy us 2^COPY_BLOCK_SHIFT bytes.
	 *
	 * We read into a COPY_BUF_SIZE bytes buffer, and at most md->size
	 * bytes total, to stop before the fileinfo trailer.
	 */

	amount = ticks << COPY_BLOCK_SHIFT;
	remain = MIN(remain, COPY_BUF_SIZE);
	amount = MIN(amount, remain);

	g_assert(amount > 0);

	r = read(md->rd, md->buffer, amount);

	if (r < 0) {
		md->error = errno;
		g_warning("error while reading \"%s\" for moving: %s",
			download_outname(md->d), g_strerror(errno));
		return BGR_DONE;
	}

	if (r == 0) {
		g_warning("EOF while reading \"%s\" for moving!",
			download_outname(md->d));
		md->error = -1;
		return BGR_DONE;
	}

	/*
	 * Any partially read block counts as one block, hence the second term.
	 */

	used = (r >> COPY_BLOCK_SHIFT) +
		((r & ((1 << COPY_BLOCK_SHIFT) - 1)) ? 1 : 0);

	if (used != ticks)
		bg_task_ticks_used(h, used);

	r = write(md->wd, md->buffer, amount);

	if (r < 0) {
		md->error = errno;
		g_warning("error while writing for moving \"%s\": %s",
			download_outname(md->d), g_strerror(errno));
		return BGR_DONE;
	} else if (r < amount) {
		md->error = -1;
		g_warning("short write whilst moving \"%s\"", download_outname(md->d));
		return BGR_DONE;
	}

	g_assert(r == amount);

	md->copied += r;
	download_move_progress(md->d, md->copied);

	return md->copied == md->size ? BGR_DONE : BGR_MORE;
}

/*
 * move_queue
 *
 * Enqueue completed download file for verification.
 */
void move_queue(struct download *d, const gchar *dest, const gchar *ext)
{
	struct work *we;

	we = we_alloc(d, dest, ext);
	bg_daemon_enqueue(move_daemon, we);
}

/*
 * move_init
 *
 * Initializes the background moving/copying task.
 */
void move_init(void)
{
	struct moved *md;
	bgstep_cb_t step = d_step_copy;

	md = walloc(sizeof(*md));
	md->magic = MOVED_MAGIC;
	md->rd = -1;
	md->wd = -1;
	md->buffer = g_malloc(COPY_BUF_SIZE);

	move_daemon = bg_daemon_create("file moving",
		&step, 1,
		md, d_free,
		d_start, d_end, we_free,
		d_notify);
}

/*
 * move_close
 *
 * Called at shutdown time.
 */
void move_close(void)
{
	bg_task_cancel(move_daemon);
}

