/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Hash verification.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "downloads.h"
#include "file_object.h"
#include "verify.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/bg.h"
#include "lib/sha1.h"
#include "lib/file.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

#define HASH_BLOCK_SHIFT	12			/**< Power of two of hash unit credit */
#define HASH_BUF_SIZE		65536		/**< Size of the reading buffer */

static struct bgtask *verify_daemon;

enum verifyd_magic { VERIFYD_MAGIC = 0x000e31f8 };

/**
 * Verification daemon context.
 */
struct verifyd {
	enum verifyd_magic magic;	/**< Magic number */
	struct download *d;			/**< Current download */
	struct file_object *file;	/**< Opened file descriptor, -1 if none */
	time_t start;			/**< Start time, to determine computation rate */
	filesize_t size;		/**< Size of file */
	filesize_t hashed;		/**< Amount of data hashed so far */
	SHA1Context context;	/**< SHA1 computation context */
	gpointer buffer;		/**< Large buffer, where data is read */
	gint error;				/**< Error code */
};

/**
 * Freeing of computation context.
 */
static void
d_free(gpointer ctx)
{
	struct verifyd *vd = ctx;

	g_assert(vd->magic == VERIFYD_MAGIC);

	file_object_release(&vd->file);
	G_FREE_NULL(vd->buffer);
	vd->magic = 0;
	wfree(vd, sizeof *vd);
}

/**
 * Daemon's notification of start/stop.
 */
static void
d_notify(struct bgtask *unused_h, gboolean on)
{
	(void) unused_h;
	gnet_prop_set_boolean_val(PROP_SHA1_VERIFYING, on);
}

/**
 * Daemon's notification: starting to work on item.
 */
static void
d_start(struct bgtask *unused_h, gpointer ctx, gpointer item)
{
	struct verifyd *vd = ctx;
	struct download *d = item;
	gchar *pathname;

	(void) unused_h;
	g_assert(vd->magic == VERIFYD_MAGIC);
	g_assert(NULL == vd->file);
	g_assert(NULL == vd->d);

	download_verify_start(d);

	pathname = make_pathname(download_path(d), download_outname(d));
	vd->file = file_object_open(pathname, O_RDONLY);
	if (NULL == vd->file) {
		int fd;

		fd = file_open(pathname, O_RDONLY);
		if (fd >= 0) {
			vd->file = file_object_new(fd, pathname, O_RDONLY);
		}
	}
	if (vd->file) {
		if (dbg > 1) {
			g_message("Verifying SHA1 digest for %s\n", pathname);
		}
		compat_fadvise_sequential(file_object_get_fd(vd->file), 0, 0);
		vd->d = d;
		vd->start = tm_time();
		vd->size = download_filesize(d);
		vd->hashed = 0;
		vd->error = 0;
		SHA1Reset(&vd->context);
	} else {
		vd->error = errno ? errno : EIO;
		g_warning("can't open %s to verify SHA1: %s",
			pathname, g_strerror(errno));
	}
	G_FREE_NULL(pathname);
}

/**
 * Daemon's notification: finished working on item.
 */
static void
d_end(struct bgtask *unused_h, gpointer ctx, gpointer item)
{
	struct verifyd *vd = ctx;
	struct download *d = item;
	time_delta_t elapsed = 0;
	struct sha1 digest;

	(void) unused_h;
	g_assert(vd->magic == VERIFYD_MAGIC);

	if (NULL == vd->file) {				/* Did not start properly */
		g_assert(vd->error);
		goto finish;
	}
	file_object_release(&vd->file);

	g_assert(vd->d == d);
	vd->d = NULL;

	if (vd->error == 0) {
		g_assert(vd->hashed == vd->size);
		SHA1Result(&vd->context, &digest);
	}

	elapsed = delta_time(tm_time(), vd->start);
	elapsed = MAX(1, elapsed);

	if (dbg > 1)
		printf("Computed SHA1 digest for %s at %lu bytes/sec [error=%d]\n",
			download_outname(d), (gulong) (vd->size / elapsed), vd->error);

finish:
	if (vd->error)
		download_verify_error(d);
	else
		download_verify_done(d, &digest, elapsed);
}

/**
 * Compute SHA1 of current file.
 */
static bgret_t
d_step_compute(struct bgtask *h, gpointer u, gint ticks)
{
	struct verifyd *vd = u;
	ssize_t r;
	size_t amount;
	gint res;
	filesize_t remain;
	gint used;

	g_assert(vd->magic == VERIFYD_MAGIC);

	if (NULL == vd->file)		/* Could not open the file */
		return BGR_DONE;		/* Computation done */

	if (vd->size == 0)			/* Empty file */
		return BGR_DONE;

	remain = vd->size - vd->hashed;

	g_assert(remain > 0);

	/*
	 * Each tick we have can buy us 2^HASH_BLOCK_SHIFT bytes.
	 *
	 * We read into a HASH_BUF_SIZE bytes buffer, and at most vd->size
	 * bytes total, to stop before the fileinfo trailer.
	 */

	amount = ticks << HASH_BLOCK_SHIFT;
	remain = MIN(remain, HASH_BUF_SIZE);
	amount = MIN(amount, remain);

	g_assert(amount > 0);

	r = file_object_pread(vd->file, vd->buffer, amount, vd->hashed);
	if ((ssize_t) -1 == r) {
		if (is_temporary_error(errno)) {
			return BGR_MORE;
		} else {
			vd->error = errno;
			g_warning("error while reading %s for computing SHA1: %s",
					download_outname(vd->d), g_strerror(errno));
			return BGR_DONE;
		}
	} else if (r == 0) {
		g_warning("EOF while reading %s for computing SHA1!",
			download_outname(vd->d));
		vd->error = -1;
		return BGR_DONE;
	}

	/*
	 * Any partially read block counts as one block, hence the second term.
	 */

	amount = (size_t) r;
	used = (amount >> HASH_BLOCK_SHIFT) +
		((amount & ((1 << HASH_BLOCK_SHIFT) - 1)) ? 1 : 0);

	if (used != ticks)
		bg_task_ticks_used(h, used);

	res = SHA1Input(&vd->context, cast_to_gconstpointer(vd->buffer), r);
	if (res != shaSuccess) {
		g_warning("SHA1 computation error for %s", download_outname(vd->d));
		vd->error = -1;
		return BGR_DONE;
	}

	vd->hashed += (size_t) r;
	download_verify_progress(vd->d, vd->hashed);

	return vd->hashed == vd->size ? BGR_DONE : BGR_MORE;
}

/**
 * Enqueue completed download file for verification.
 */
void
verify_queue(struct download *d)
{
	bg_daemon_enqueue(verify_daemon, d);
}

/**
 * Initializes the background verification task.
 */
void
verify_init(void)
{
	static const bgstep_cb_t step[] = { d_step_compute };
	static const struct verifyd zero_vd;
	struct verifyd *vd;

	vd = walloc(sizeof *vd);
	*vd = zero_vd;
	vd->magic = VERIFYD_MAGIC;
	vd->buffer = g_malloc(HASH_BUF_SIZE);

	verify_daemon = bg_daemon_create("SHA1 verification",
		step, G_N_ELEMENTS(step),
		vd, d_free,
		d_start, d_end, NULL,
		d_notify);
}

/**
 * Called at shutdown time.
 */
void
verify_close(void)
{
	bg_task_cancel(verify_daemon);
}

/* vi: set ts=4 sw=4 cindent: */
