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
 * Management of download ignoring list.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#include "ignore.h"
#include "huge.h"
#include "share.h"
#include "settings.h"
#include "namesize.h"
#include "spam.h"

#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/file.h"
#include "lib/misc.h"
#include "lib/tm.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Hash tables where we collect SHA1 we already own or wish to ignore and
 * filename/filesizes we likewise wish to ignore.
 */
static GHashTable *by_sha1;			/**< SHA1s to ignore */
static GHashTable *by_namesize;		/**< By filename + filesize */

/*
 * We expect the initial ignore_sha1 and ignore_namesize files to be in
 * the startup directory.  We'll monitor them and reload them should they
 * change during our runtime.
 *
 * We also create done_sha1 and done_namesize files which we don't monitor
 * since we're appending to them (we only read them on startup).
 */

static const gchar ignore_sha1[]     = "ignore.sha1";
static const gchar ignore_namesize[] = "ignore.namesize";
static const gchar done_sha1[]       = "done.sha1";
static const gchar done_namesize[]   = "done.namesize";

static time_t ignore_sha1_mtime;
static time_t ignore_namesize_mtime;

static FILE *sha1_out = NULL;
static FILE *namesize_out = NULL;

static gchar ign_tmp[1024];

static void ignore_sha1_load(const gchar *file, time_t *stamp);
static void ignore_namesize_load(const gchar *file, time_t *stamp);

/**
 * Open `file' for reading if it exists.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 *
 * @returns FILE* of the opened file on success, NULL on failure.
 */
static FILE *
open_read_stamp(const gchar *file, time_t *stamp)
{
	FILE *f;
	char *path;
	struct stat buf;

	path = make_pathname(settings_config_dir(), file);
	g_return_val_if_fail(NULL != path, NULL);

	if (-1 == stat(path, &buf)) {
		if (stamp)
			*stamp = tm_time();
		G_FREE_NULL(path);
		return NULL;
	}

	if (stamp)
		*stamp = buf.st_mtime;

	f = file_fopen(path, "r");

	G_FREE_NULL(path);
	return f;
}

/**
 * Open `file' for appending.
 */
static FILE *
open_append(const gchar *file)
{
	FILE *f;
	char *path;

	path = make_pathname(settings_config_dir(), file);
	g_return_val_if_fail(NULL != path, NULL);

	f = file_fopen(path, "a");

	G_FREE_NULL(path);
	return f;
}

/**
 * Initialize the ignore tables.
 */
void
ignore_init(void)
{
	by_sha1 = g_hash_table_new(sha1_hash, sha1_eq);
	by_namesize = g_hash_table_new(namesize_hash, namesize_eq);

	ignore_sha1_load(ignore_sha1, &ignore_sha1_mtime);
	ignore_sha1_load(done_sha1, NULL);

	ignore_namesize_load(ignore_namesize, &ignore_namesize_mtime);
	ignore_namesize_load(done_namesize, NULL);

	sha1_out = open_append(done_sha1);
	namesize_out = open_append(done_namesize);
}

/**
 * Parse opened file `f' containing SHA1s to ignore.
 */
static void
sha1_parse(FILE *f, const gchar *file)
{
	gint line = 0;
	struct sha1 sha1;
	gchar *p;
	gint len;

	g_assert(f);

	while (fgets(ign_tmp, sizeof(ign_tmp), f)) {
		line++;

		if (ign_tmp[0] == '#' || ign_tmp[0] == '\n')
			continue;			/* Skip comments and blank lines */

		len = str_chomp(ign_tmp, 0);		/* Remove final "\n" */

		/*
		 * Decode leading base32 encoded SHA1.
		 */

		if (
			len < SHA1_BASE32_SIZE ||
			SHA1_RAW_SIZE != base32_decode(sha1.data, sizeof sha1.data,
								ign_tmp, SHA1_BASE32_SIZE)
		) {
			g_warning("invalid SHA1 at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		if (g_hash_table_lookup(by_sha1, &sha1))
			continue;

		/*
		 * Skip the 2 blanks after the SHA1 to reach the filename
		 */

		if (len < SHA1_BASE32_SIZE + 2) {
			g_warning("no filename after SHA1 at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		p = &ign_tmp[SHA1_BASE32_SIZE + 2];
		gm_hash_table_insert_const(by_sha1,
			atom_sha1_get(&sha1), atom_str_get(p));
	}
}

/**
 * Load new SHA1 from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void
ignore_sha1_load(const gchar *file, time_t *stamp)
{
	FILE *f;

	f = open_read_stamp(file, stamp);

	if (!f)
		return;

	sha1_parse(f, file);
	fclose(f);
}

/**
 * Parse opened `f' containing size/filenames to ignore.
 */
static void
namesize_parse(FILE *f, const gchar *file)
{
	gint line = 0, error;
	filesize_t size;
	const gchar *p, *q;
	namesize_t *ns;
	namesize_t nsk;

	g_assert(f);

	while (fgets(ign_tmp, sizeof(ign_tmp), f)) {
		line++;

		if (ign_tmp[0] == '#' || ign_tmp[0] == '\n')
			continue;			/* Skip comments and blank lines */

		str_chomp(ign_tmp, 0);	/* Remove final "\n" */

		size = parse_uint64(ign_tmp, &p, 10, &error);
		if (error || !is_ascii_blank(*p)) {
			g_warning("malformed size at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		p++;	/* skip the blank */

		/*
		 * Go past the last directory separator if filename, if any.
		 */

		q = strrchr(p, G_DIR_SEPARATOR);
		if (q == NULL)
			q = p;
		else
			q++;

		nsk.name = deconstify_gchar(q);
		nsk.size = size;

		if (g_hash_table_lookup(by_namesize, &nsk))
			continue;

		ns = namesize_make(q, size);
		g_hash_table_insert(by_namesize, ns, GINT_TO_POINTER(1));
	}
}

/**
 * Load new name/size tuples from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void
ignore_namesize_load(const gchar *file, time_t *stamp)
{
	FILE *f;

	f = open_read_stamp(file, stamp);

	if (!f)
		return;

	namesize_parse(f, file);
	fclose(f);
}

/**
 * @return the filename associated with the digest if known, NULL otherwise.
 */
const gchar *
ignore_sha1_filename(const struct sha1 *sha1)
{
	return g_hash_table_lookup(by_sha1, sha1);
}


const gchar *
ignore_reason_to_string(enum ignore_val reason)
{
	switch (reason) {
	case IGNORE_OURSELVES:	return "Points to ourselves";
	case IGNORE_HOSTILE:	return "Hostile IP";
	case IGNORE_SHA1:		return "SHA1";
	case IGNORE_SPAM:		return "Known Spam";
	case IGNORE_LIBRARY:	return "Already Owned";
	case IGNORE_NAMESIZE:	return "Name & Size";
	case IGNORE_FALSE:		return "NOT ignored";
	}
	return NULL;
}

/**
 * Is ignoring requested for `filename' of size `size' and SHA1 `sha1'?
 * `filename' and `size' are only used if `sha1' is NULL.
 *
 * @param filename Must be a basename, without any directory separator
 * @param size the filesize
 * @param sha1 must point to a SHA1 (binary) or NULL
 */
enum ignore_val
ignore_is_requested(const gchar *filename, filesize_t size,
	const struct sha1 *sha1)
{
	g_assert(filename != NULL);

	if (sha1) {
		const struct shared_file *sf;
		if (g_hash_table_lookup(by_sha1, sha1))
			return IGNORE_SHA1;
		if (spam_sha1_check(sha1))
			return IGNORE_SPAM;
		sf = shared_file_by_sha1(sha1);
		if (sf && sf != SHARE_REBUILDING && !shared_file_is_partial(sf))
			return IGNORE_LIBRARY;
	} else {
		namesize_t ns;

		ns.name = deconstify_gchar(filename);
		ns.size = size;

		if (g_hash_table_lookup(by_namesize, &ns))
			return IGNORE_NAMESIZE;
	}

	return IGNORE_FALSE;
}

/**
 * Add `sha1' to the set of ignored entries.
 */
void
ignore_add_sha1(const gchar *file, const struct sha1 *sha1)
{
	g_assert(sha1);

	if (!g_hash_table_lookup(by_sha1, sha1)) {
		gm_hash_table_insert_const(by_sha1,
			atom_sha1_get(sha1), atom_str_get(file));
	}

	/*
	 * Write to file even if duplicate SHA1, in order to help us
	 * diagnose possible problems.
	 */

	if (sha1_out) {
		/*
		 * Note: _exactly_ two blanks; the filename might contain leading
		 * blanks too.
		 */
		fprintf(sha1_out, "%s  %s\n", sha1_base32(sha1), file);
		fflush(sha1_out);
	}
}

/**
 * Add `file', `size' to the set of ignored entries.
 */
void
ignore_add_filesize(const gchar *file, filesize_t size)
{
	namesize_t nsk;

	nsk.name = deconstify_gchar(file);
	nsk.size = size;

	if (!g_hash_table_lookup(by_namesize, &nsk)) {
		namesize_t *ns;

		ns = namesize_make(file, size);
		g_hash_table_insert(by_namesize, ns, GINT_TO_POINTER(1));
	}

	/*
	 * Write to file even if duplicate file/size, in order to help us
	 * diagnose possible problems.
	 */

	if (namesize_out) {
		/*
		 * Note: _exactly_ one blank; the filename might contain leading
		 * blanks too.
		 */
		fprintf(namesize_out, "%s %s\n", uint64_to_string(size), file);
		fflush(namesize_out);
	}
}

/**
 * Called periodically to check the file timestamps.
 *
 * If files are newer, they are reloaded, but the previously recorded
 * ignores are NOT forgotten.  Therefore, we can ONLY append new ignores.
 */
void
ignore_timer(time_t unused_now)
{
	FILE *f;
	time_t stamp;

	(void) unused_now;

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

/**
 * Remove iterator callback.
 *
 * Free a key/value pair from the by_sha1 hash.
 */
static gboolean
free_sha1_kv(gpointer key, gpointer value, gpointer unused_udata)
{
	(void) unused_udata;

	atom_sha1_free(key);
	atom_str_free(value);

	return TRUE;
}

/**
 * Remove iterator callback.
 *
 * Free a key/value pair from the by_namesize hash.
 */
static gboolean
free_namesize_kv(gpointer key, gpointer unused_value, gpointer unused_udata)
{
	(void) unused_value;
	(void) unused_udata;
	namesize_free(key);
	return TRUE;
}

/**
 * Called during servent shutdown to free up resources.
 */
void
ignore_close(void)
{
	g_hash_table_foreach_remove(by_sha1, free_sha1_kv, NULL);
	g_hash_table_foreach_remove(by_namesize, free_namesize_kv, NULL);

	if (sha1_out != NULL) {
		fclose(sha1_out);
		sha1_out = NULL;
	}

	if (namesize_out != NULL) {
		fclose(namesize_out);
		namesize_out = NULL;
	}
}

/* vi: set ts=4 sw=4 cindent: */
