/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Management of download ignoring list.
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

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ignore.h"
#include "huge.h"
#include "share.h"

#include "settings.h"

RCSID("$Id$");

/*
 * Hash tables where we collect SHA1 we already own or wish to ignore and
 * filename/filesizes we likewise wish to ignore.
 */
static GHashTable *by_sha1;			/* SHA1s to ignore */
static GHashTable *by_namesize;		/* By filename + filesize */

/*
 * We expect the initial ignore_sha1 and ignore_namesize files to be in
 * the startup directory.  We'll monitor them and reload them should they
 * change during our runtime.
 *
 * We also create done_sha1 and done_namesize files which we don't monitor
 * since we're appending to them (we only read them on startup).
 */

static const gchar *ignore_sha1     = "ignore.sha1";
static const gchar *ignore_namesize = "ignore.namesize";
static const gchar *done_sha1       = "done.sha1";
static const gchar *done_namesize   = "done.namesize";

static time_t ignore_sha1_mtime;
static time_t ignore_namesize_mtime;

static FILE *sha1_out = NULL;
static FILE *namesize_out = NULL;

static guchar ign_tmp[1024];

static void ignore_sha1_load(const guchar *file, time_t *stamp);
static void ignore_namesize_load(const guchar *file, time_t *stamp);

/*
 * open_read_stamp
 *
 * Open `file' for reading if it exists.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 *
 * Returns file handle of the opened file on success, NULL on failure.
 */
static FILE *open_read_stamp(const guchar *file, time_t *stamp)
{
	FILE *f;
	struct stat buf;

	gm_snprintf(ign_tmp, sizeof(ign_tmp), "%s/%s",
		settings_config_dir(), file);
		
	if (-1 == stat(ign_tmp, &buf)) {
		if (stamp)
			*stamp = time(NULL);
		return NULL;
	}

	if (stamp)
		*stamp = buf.st_mtime;

	f = fopen(ign_tmp, "r");

	if (!f) {
		g_warning("unable to open \"%s\" for reading: %s",
			ign_tmp, g_strerror(errno));
	}

	return f;
}

/*
 * open_append
 *
 * Open `file' for appending.
 */
static FILE *open_append(const guchar *file)
{
	FILE *f;

	gm_snprintf(ign_tmp, sizeof(ign_tmp), "%s/%s", settings_config_dir(), file);

	f = fopen(ign_tmp, "a");

	if (!f) {
		g_warning("unable to open \"%s\" for appending: %s",
			ign_tmp, g_strerror(errno));
	}

	return f;
}

/*
 * ignore_init
 *
 * Initialize the ignore tables.
 */
void ignore_init(void)
{
	extern guint sha1_hash(gconstpointer key);
	extern gint sha1_eq(gconstpointer a, gconstpointer b);

	by_sha1 = g_hash_table_new(sha1_hash, sha1_eq);
	by_namesize = g_hash_table_new(namesize_hash, namesize_eq);

	ignore_sha1_load(ignore_sha1, &ignore_sha1_mtime);
	ignore_sha1_load(done_sha1, NULL);

	ignore_namesize_load(ignore_namesize, &ignore_namesize_mtime);
	ignore_namesize_load(done_namesize, NULL);

	sha1_out = open_append(done_sha1);
	namesize_out = open_append(done_namesize);
}

/*
 * sha1_parse
 *
 * Parse opened file `f' containing SHA1s to ignore.
 */
static void sha1_parse(FILE *f, const guchar *file)
{
	gint line = 0;
	guchar sha1_digest[SHA1_RAW_SIZE];
	guchar *sha1;

	g_assert(f);

	while (fgets(ign_tmp, sizeof(ign_tmp) - 1, f)) {
		line++;

		if (ign_tmp[0] == '#' || ign_tmp[0] == '\n')
			continue;			/* Skip comments and blank lines */

		/*
		 * We're only interested in the leading base32 encoded SHA1.
		 */

		if (
			strlen(ign_tmp) < SHA1_BASE32_SIZE ||
			!base32_decode_into(ign_tmp, SHA1_BASE32_SIZE,
				sha1_digest, sizeof(sha1_digest))
		) {
			g_warning("invalid SHA1 at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		if (g_hash_table_lookup(by_sha1, sha1_digest))
			continue;

		sha1 = atom_sha1_get(sha1_digest);
		g_hash_table_insert(by_sha1, sha1, (gpointer) 0x1);
	}
}

/*
 * ignore_sha1_load
 *
 * Load new SHA1 from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void ignore_sha1_load(const guchar *file, time_t *stamp)
{
	FILE *f;

	f = open_read_stamp(file, stamp);

	if (!f)
		return;

	sha1_parse(f, file);
	fclose(f);
}

/*
 * namesize_parse
 *
 * Parse opened `f' containing size/filenames to ignore.
 */
static void namesize_parse(FILE *f, const guchar *file)
{
	gint line = 0;
	guint32 size;
	guint8 c;
	guchar *p, *q;
	namesize_t *ns;
	namesize_t nsk;

	g_assert(f);

	while (fgets(ign_tmp, sizeof(ign_tmp) - 1, f)) {
		line++;

		if (ign_tmp[0] == '#' || ign_tmp[0] == '\n')
			continue;			/* Skip comments and blank lines */

		str_chomp(ign_tmp, 0);	/* Remove final "\n" */

		size = strtoul(ign_tmp, (gchar **)&p, 10);

		if (p == ign_tmp || !isspace(*(guchar *) p)) {
			g_warning("malformed size at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		while ((c = *p) && isspace(c))
			p++;

		/*
		 * Go past the last "/" if filename, if any.
		 */

		q = strrchr(p, '/');
		if (q == NULL)
			q = p;
		else
			q++;

		nsk.name = q;
		nsk.size = size;

		if (g_hash_table_lookup(by_namesize, &nsk))
			continue;

		ns = namesize_make(q, size);
		g_hash_table_insert(by_namesize, ns, (gpointer) 0x1);
	}
}

/*
 * ignore_namesize_load
 *
 * Load new name/size tuples from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void ignore_namesize_load(const guchar *file, time_t *stamp)
{
	FILE *f;

	f = open_read_stamp(file, stamp);

	if (!f)
		return;

	namesize_parse(f, file);
	fclose(f);
}

/*
 * ignore_is_requested
 *
 * Is ignoring requested for `file' of size `size' and SHA1 `sha1'?
 * Priority is given to the SHA1, if supplied.
 */
enum ignore_val ignore_is_requested(
	guchar *file, guint32 size, guchar *sha1)
{
	namesize_t ns;

	g_assert(file != NULL);

	if (sha1) {
		struct shared_file *sf;
		if (g_hash_table_lookup(by_sha1, sha1))
			return IGNORE_SHA1;
		sf = shared_file_by_sha1(sha1);
		if (sf && sf != SHARE_REBUILDING)
			return IGNORE_LIBRARY;
	}

	ns.name = file;			/* Must be a basename, without any "/" inside */
	ns.size = size;

	if (g_hash_table_lookup(by_namesize, &ns))
		return IGNORE_NAMESIZE;

	return IGNORE_FALSE;
}

/*
 * ignore_add_sha1
 *
 * Add `sha1' to the set of ignored entries.
 */
void ignore_add_sha1(const guchar *file, guchar *sha1)
{
	g_assert(sha1);

	if (!g_hash_table_lookup(by_sha1, sha1))
		g_hash_table_insert(by_sha1, atom_sha1_get(sha1), (gpointer) 0x1);

	/*
	 * Write to file even if duplicate SHA1, in order to help us
	 * diagnose possible problems.
	 */

	if (sha1_out) {
		fprintf(sha1_out, "%s  %s\n", sha1_base32(sha1), file);
		fflush(sha1_out);
	}
}

/*
 * ignore_add_filesize
 *
 * Add `file', `size' to the set of ignored entries.
 */
void ignore_add_filesize(guchar *file, guint32 size)
{
	namesize_t *ns;
	namesize_t nsk;

	nsk.name = file;
	nsk.size = size;

	if (!g_hash_table_lookup(by_namesize, &nsk)) {
		ns = namesize_make(file, size);
		g_hash_table_insert(by_namesize, ns, (gpointer) 0x1);
	}

	/*
	 * Write to file even if duplicate file/size, in order to help us
	 * diagnose possible problems.
	 */

	if (namesize_out) {
		fprintf(namesize_out, "%u %s\n", size, file);
		fflush(namesize_out);
	}
}

/*
 * ignore_timer
 *
 * Called periodically to check the file timestamps.
 *
 * If files are newer, they are reloaded, but the previously recorded
 * ignores are NOT forgotten.  Therefore, we can ONLY append new ignores.
 */
void ignore_timer(time_t now)
{
	FILE *f;
	time_t stamp;

	f = open_read_stamp(ignore_sha1, &stamp);
	if (f != NULL) {
		if (stamp > ignore_sha1_mtime) {
			ignore_sha1_mtime = stamp;
			if (dbg)
				printf("RELOAD %s\n", ignore_sha1);
			sha1_parse(f, ignore_sha1);
		}
		fclose(f);
	}

	f = open_read_stamp(ignore_namesize, &stamp);
	if (f != NULL) {
		if (stamp > ignore_namesize_mtime) {
			ignore_namesize_mtime = stamp;
			if (dbg)
				printf("RELOAD %s\n", ignore_namesize);
			namesize_parse(f, ignore_namesize);
		}
		fclose(f);
	}
}

/*
 * free_sha1_kv
 *
 * Remove iterator callback.
 * Free a key/value pair from the by_sha1 hash.
 */
static gboolean free_sha1_kv(gpointer key, gpointer value, gpointer udata)
{
	atom_sha1_free((guchar *) key);
	return TRUE;
}

/*
 * free_namesize_kv
 *
 * Remove iterator callback.
 * Free a key/value pair from the by_namesize hash.
 */
static gboolean free_namesize_kv(gpointer key, gpointer value, gpointer udata)
{
	namesize_free((namesize_t *) key);
	return TRUE;
}

/*
 * ignore_close
 *
 * Called during servent shutdown to free up resources.
 */
void ignore_close(void)
{
	g_hash_table_foreach_remove(by_sha1, free_sha1_kv, NULL);
	g_hash_table_foreach_remove(by_namesize, free_namesize_kv, NULL);

	if (sha1_out != NULL)
		fclose(sha1_out);

	if (namesize_out != NULL)
		fclose(namesize_out);
}

