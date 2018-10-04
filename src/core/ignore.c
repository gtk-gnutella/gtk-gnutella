/*
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

#include "ignore.h"
#include "huge.h"
#include "share.h"
#include "settings.h"
#include "namesize.h"
#include "spam.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/base32.h"
#include "lib/file.h"
#include "lib/halloc.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/parse.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Hash tables where we collect SHA1 we already own or wish to ignore and
 * filename/filesizes we likewise wish to ignore.
 */
static htable_t *by_sha1;		/**< SHA1s to ignore */
static hset_t *by_namesize;		/**< By filename + filesize */

/*
 * We expect the initial ignore_sha1 file to be in the startup directory.
 * We'll monitor it and reload it should it change during our runtime.
 *
 * We also create done_sha1 and done_namesize files which we don't monitor
 * since we're appending to them (we only read them on startup).
 */

static const char ignore_sha1[]     = "ignore.sha1";
static const char done_sha1[]       = "done.sha1";
static const char done_namesize[]   = "done.namesize";

static time_t ignore_sha1_mtime;

static FILE *sha1_out = NULL;
static FILE *namesize_out = NULL;

static char ign_tmp[1024];

static void ignore_sha1_load(const char *file, time_t *stamp);
static void ignore_namesize_load(const char *file, time_t *stamp);

/**
 * Open `file' for reading if it exists.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 *
 * @returns FILE* of the opened file on success, NULL on failure.
 */
static FILE *
open_read_stamp(const char *file, time_t *stamp)
{
	FILE *f;
	char *path;
	filestat_t buf;

	path = make_pathname(settings_config_dir(), file);
	if (-1 == stat(path, &buf)) {
		if (stamp) {
			*stamp = tm_time();
		}
		HFREE_NULL(path);
		return NULL;
	}

	if (stamp) {
		*stamp = buf.st_mtime;
	}
	f = file_fopen(path, "r");

	HFREE_NULL(path);
	return f;
}

/**
 * Open `file' for appending.
 */
static FILE *
open_append(const char *file)
{
	FILE *f;
	char *path;

	path = make_pathname(settings_config_dir(), file);

	f = file_fopen(path, "a");

	HFREE_NULL(path);
	return f;
}

/**
 * Initialize the ignore tables.
 */
void G_COLD
ignore_init(void)
{
	by_sha1 = htable_create(HASH_KEY_FIXED, SHA1_RAW_SIZE);
	by_namesize = hset_create_any(namesize_hash, NULL, namesize_eq);

	ignore_sha1_load(ignore_sha1, &ignore_sha1_mtime);
	ignore_sha1_load(done_sha1, NULL);

	ignore_namesize_load(done_namesize, NULL);

	sha1_out = open_append(done_sha1);
	namesize_out = open_append(done_namesize);
}

/**
 * Parse opened file `f' containing SHA1s to ignore.
 */
static void
sha1_parse(FILE *f, const char *file)
{
	int line = 0;
	struct sha1 sha1;
	char *p;
	size_t len;

	g_assert(f);

	while (fgets(ARYLEN(ign_tmp), f)) {
		line++;

		if (!file_line_chomp_tail(ARYLEN(ign_tmp), &len)) {
			g_warning("%s: line %d too long, aborting", G_STRFUNC, line);
			break;
		}

		if (file_line_is_skipable(ign_tmp))
			continue;			/* Skip comments and blank lines */

		/*
		 * Decode leading base32 encoded SHA1.
		 */

		if (
			len < SHA1_BASE32_SIZE ||
			SHA1_RAW_SIZE != base32_decode(VARLEN(sha1), ign_tmp, SHA1_BASE32_SIZE)
		) {
			g_warning("invalid SHA1 at \"%s\" line %d: %s",
				file, line, ign_tmp);
			continue;
		}

		if (htable_contains(by_sha1, &sha1))
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
		htable_insert_const(by_sha1, atom_sha1_get(&sha1), atom_str_get(p));
	}
}

/**
 * Load new SHA1 from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void
ignore_sha1_load(const char *file, time_t *stamp)
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
static void G_COLD
namesize_parse(FILE *f, const char *file)
{
	int line = 0, error;
	filesize_t size;
	const char *p, *q;
	namesize_t *ns;
	namesize_t nsk;

	g_assert(f);

	while (fgets(ARYLEN(ign_tmp), f)) {
		line++;

		if (!file_line_chomp_tail(ARYLEN(ign_tmp), NULL)) {
			g_warning("%s: line %d too long, aborting", G_STRFUNC, line);
			break;
		}

		if (file_line_is_skipable(ign_tmp))
			continue;			/* Skip comments and blank lines */

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

		nsk.name = deconstify_char(q);
		nsk.size = size;

		if (hset_contains(by_namesize, &nsk))
			continue;

		ns = namesize_make(q, size);
		hset_insert(by_namesize, ns);
	}
}

/**
 * Load new name/size tuples from `file'.
 *
 * If `stamp' is non-NULL, fill it with the mtime of the file, or the current
 * time if the file does not exist.
 */
static void
ignore_namesize_load(const char *file, time_t *stamp)
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
const char *
ignore_sha1_filename(const struct sha1 *sha1)
{
	return htable_lookup(by_sha1, sha1);
}


/**
 * Is ignoring requested for `filename' of size `size' and SHA1 `sha1'?
 * `filename' and `size' are only used if `sha1' is NULL.
 *
 * @param filename Must be a basename, without any directory separator
 * @param size the filesize
 * @param sha1 must point to a SHA1 (binary) or NULL
 */
ignore_val_t
ignore_is_requested(const char *filename, filesize_t size,
	const struct sha1 *sha1)
{
	g_assert(filename != NULL);

	if (sha1) {
		shared_file_t *sf;
		bool ignore;
		if (htable_contains(by_sha1, sha1))
			return IGNORE_SHA1;
		if (spam_sha1_check(sha1))
			return IGNORE_SPAM;
		sf = shared_file_by_sha1(sha1);
		ignore = sf && sf != SHARE_REBUILDING && !shared_file_is_partial(sf);
		shared_file_unref(&sf);
		if (ignore)
			return IGNORE_LIBRARY;
	} else {
		namesize_t ns;

		ns.name = deconstify_char(filename);
		ns.size = size;

		if (hset_contains(by_namesize, &ns))
			return IGNORE_NAMESIZE;
	}

	return IGNORE_FALSE;
}

/**
 * Add `sha1' to the set of ignored entries.
 */
void
ignore_add_sha1(const char *file, const struct sha1 *sha1)
{
	g_assert(sha1);

	if (!htable_contains(by_sha1, sha1))
		htable_insert_const(by_sha1, atom_sha1_get(sha1), atom_str_get(file));

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
ignore_add_filesize(const char *file, filesize_t size)
{
	namesize_t nsk;

	nsk.name = deconstify_char(file);
	nsk.size = size;

	if (!hset_contains(by_namesize, &nsk)) {
		namesize_t *ns;

		ns = namesize_make(file, size);
		hset_insert(by_namesize, ns);
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
			if (GNET_PROPERTY(dbg))
				printf("RELOAD %s\n", ignore_sha1);
			sha1_parse(f, ignore_sha1);
		}
		fclose(f);
	}
}

/**
 * Table iterator callback.
 *
 * Free a key/value pair from the by_sha1 table.
 */
static void
free_sha1_kv(const void *key, void *value, void *unused_udata)
{
	(void) unused_udata;

	atom_sha1_free(key);
	atom_str_free(value);
}

/**
 * Set iterator callback.
 *
 * Free an entry from the by_namesize set.
 */
static void
free_namesize_kv(const void *key, void *unused_udata)
{
	(void) unused_udata;
	namesize_free(deconstify_pointer(key));
}

/**
 * Called during servent shutdown to free up resources.
 */
void G_COLD
ignore_close(void)
{
	htable_foreach(by_sha1, free_sha1_kv, NULL);
	htable_free_null(&by_sha1);

	hset_foreach(by_namesize, free_namesize_kv, NULL);
	hset_free_null(&by_namesize);

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
