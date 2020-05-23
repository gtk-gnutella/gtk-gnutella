/*
 * Copyright (c) 2004, Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * File watcher.
 *
 * Periodically monitors file and invoke processing callback
 * should the file change.
 *
 * @author Raphael Manfredi
 * @date 2004
 */

#include "common.h"

#include "watcher.h"

#include "atoms.h"
#include "cq.h"
#include "halloc.h"
#include "hikset.h"
#include "once.h"
#include "path.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

#define MONITOR_PERIOD_MS	(30*1000)	/**< 30 seconds */

/**
 * A monitored file.
 */
struct monitored {
	const char *filename;	/**< Filename to monitor */
	time_t mtime;			/**< Last known modified time */
	watcher_cb_t cb;		/**< Callback to invoke on change */
	void *udata;			/**< User supplied data to hand-out to callback */
};

static hikset_t *monitored;	/**< filename -> struct monitored */

/**
 * Compute the modified time of the file on disk.
 */
static time_t
watcher_mtime(const char *filename)
{
	filestat_t buf;

	if (-1 == stat(filename, &buf))
		return 0;

	return buf.st_mtime;
}

/**
 * Check each registered file for change -- hash table iterator callback.
 */
static void
watcher_check_mtime(void *value, void *unused_udata)
{
	struct monitored *m = value;
	time_t new_mtime;

	(void) unused_udata;

	new_mtime = watcher_mtime(m->filename);

	if (new_mtime > m->mtime) {
		m->mtime = new_mtime;
		(*m->cb)(m->filename, m->udata);
	}
}

/**
 * Callout queue periodic event to perform periodic monitoring of the
 * registered files.
 */
static bool
watcher_timer(void *unused_udata)
{
	(void) unused_udata;

	if G_UNLIKELY(NULL == monitored)
		return FALSE;	/* Stop calling, layer disabled */

	hikset_foreach(monitored, watcher_check_mtime, NULL);

	return TRUE;		/* Keep calling */
}

/**
 * Register new file to be monitored.
 *
 * If the file was already monitored, cancel the previous monitoring action
 * and replace it with this one.
 *
 * @param filename the file to monitor (string duplicated)
 * @param cb the callback to invoke when the file changes
 * @param udata extra data to pass to the callback, along with filename
 */
void
watcher_register(const char *filename, watcher_cb_t cb, void *udata)
{
	struct monitored *m;

	g_assert(filename != NULL);
	g_assert(cb != NULL);

	watcher_init();		/* Auto-initialization */

	WALLOC0(m);
	m->filename = atom_str_get(filename);
	m->cb = cb;
	m->udata = udata;
	m->mtime = watcher_mtime(filename);

	if (hikset_contains(monitored, filename))
		watcher_unregister(filename);

	hikset_insert_key(monitored, &m->filename);
}

/**
 * Same as watcher_register() but a path, i.e. a (dir, base) tuple is
 * given instead of a complete filename.
 */
void
watcher_register_path(const file_path_t *fp, watcher_cb_t cb, void *udata)
{
	char *path;

	g_assert(fp != NULL);
	g_assert(cb != NULL);

	path = make_pathname(fp->dir, fp->name);
	watcher_register(path, cb, udata);
	HFREE_NULL(path);
}

/**
 * Free monitoring structure.
 */
static void
watcher_free(struct monitored *m)
{
	atom_str_free(m->filename);
	WFREE(m);
}

/**
 * Cancel monitoring of specified file.
 */
void
watcher_unregister(const char *filename)
{
	struct monitored *m;

	g_return_unless(monitored != NULL);
	g_assert(filename != NULL);

	m = hikset_lookup(monitored, filename);

	g_assert(m != NULL);

	hikset_remove(monitored, m->filename);
	watcher_free(m);
}

/**
 * Same as watcher_unregister() but a path, i.e. a (dir, base) tuple is
 * given instead of a complete filename.
 */
void
watcher_unregister_path(const file_path_t *fp)
{
	char *path;

	g_assert(fp != NULL);

	path = make_pathname(fp->dir, fp->name);
	watcher_unregister(path);
	HFREE_NULL(path);
}

/**
 * Configure the watcher layer, once.
 */
static void
watcher_init_once(void)
{
	monitored = hikset_create(
		offsetof(struct monitored, filename), HASH_KEY_STRING, 0);
	cq_periodic_main_add(MONITOR_PERIOD_MS, watcher_timer, NULL);
}

/**
 * Initialization.
 */
void
watcher_init(void)
{
	static once_flag_t watcher_inited;

	ONCE_FLAG_RUN(watcher_inited, watcher_init_once);
}

/**
 * Free monitored structure -- hash table iterator callback.
 */
static void
free_monitored_kv(void *value, void *unused_udata)
{
	struct monitored *m = value;

	(void) unused_udata;
	watcher_free(m);
}

/**
 * Final cleanup.
 */
void
watcher_close(void)
{
	hikset_foreach(monitored, free_monitored_kv, NULL);
	hikset_free_null(&monitored);
}

/* vi: set ts=4 sw=4 cindent: */
