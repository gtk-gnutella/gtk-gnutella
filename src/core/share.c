/*
 * $Id$
 *
 * Copyright (c) 2001-2005, Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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
 * Handle sharing of our own files and answers to remote queries.
 *
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 * @author Raphael Manfredi
 * @date 2001-2005
 */

#include "common.h"

RCSID("$Id$")

#include "share.h"
#include "gmsg.h"
#include "huge.h"
#include "qrp.h"
#include "extensions.h"
#include "nodes.h"
#include "uploads.h"
#include "ggep_type.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hostiles.h"
#include "qhit.h"
#include "oob.h"
#include "oob_proxy.h"
#include "fileinfo.h"
#include "settings.h"
#include "hosts.h"
#include "upload_stats.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/atoms.h"
#include "lib/ascii.h"
#include "lib/bg.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/hashlist.h"
#include "lib/listener.h"
#include "lib/mime_type.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

enum shared_file_magic {
	SHARED_FILE_MAGIC = 0x3702b437U
};

struct shared_file {
	enum shared_file_magic magic;

	struct dl_file_info *fi;	/**< PFSP-server: the holding fileinfo */
	const struct sha1 *sha1;	/**< SHA1 digest, binary form, atom */
	const struct tth *tth;		/**< TTH digest, binary form, atom */

	const gchar *file_path;		/**< The full path of the file (atom!) */
	const gchar *name_nfc;		/**< UTF-8 NFC version of filename (atom!) */
	const gchar *name_canonic;	/**< UTF-8 canonized ver. of filename (atom)! */
	const gchar *relative_path;	/**< UTF-8 NFC string (atom) */

	size_t name_nfc_len;		/**< strlen(name_nfc) */
	size_t name_canonic_len;	/**< strlen(name_canonic) */

	time_t mtime;				/**< Last modif. time, for SHA1 computation */

	filesize_t file_size;		/**< File size in Bytes */
	guint32 file_index;			/**< the files index within our local DB */
	guint32 sort_index;			/**< the index for sorted listings */

	enum mime_type mime_type;	/* MIME type of the file */

	gint refcnt;				/**< Reference count */
	guint32 flags;				/**< See below for definition */
};

/**
 * Describes special files which are served by GTKG.
 */
struct special_file {
	const gchar *path;			/* URL path */
	const gchar *file;			/* File name to load from disk */
	enum mime_type type;	/* MIME type of the file */
	const gchar *what;			/* Description of the file for traces */
};

static const struct special_file specials[] = {
	{ "/favicon.ico",
			"favicon.png",	MIME_TYPE_IMAGE_PNG,	"Favorite web icon" },
	{ "/robots.txt",
			"robots.txt",	MIME_TYPE_TEXT_PLAIN,	"Robot exclusion" },
};

/**
 * Maps special names (e.g. "/favicon.ico") to the shared_file_t structure.
 */
static GHashTable *special_names;

static guint64 files_scanned;
static guint64 bytes_scanned;

static GHashTable *extensions;	/* Shared filename extensions */
static GSList *shared_dirs;
static GSList *shared_files;
static struct shared_file **file_table;
static struct shared_file **sorted_file_table;
static search_table_t *search_table;
static GHashTable *file_basenames;

static struct recursive_scan *recursive_scan_context;

/**
 * This tree maps a SHA1 hash (base-32 encoded) onto the corresponding
 * shared_file if we have one.
 */

static GTree *sha1_to_share;

/**
 * Compare binary SHA1 hashes.
 * @return 0 if they're the same, a negative or positive number if s1 if greater
 * than s2 or s1 greater than s2, respectively.
 * Used to search the sha1_to_share tree.
 */
static gint
compare_share_sha1(gconstpointer s1, gconstpointer s2)
{
	return memcmp(s1, s2, SHA1_RAW_SIZE);
}

/**
 * Reset sha1_to_share
 */
static void
reinit_sha1_table(void)
{
	if (sha1_to_share)
		g_tree_destroy(sha1_to_share);

	sha1_to_share = g_tree_new(compare_share_sha1);
}

void
shared_file_check(const struct shared_file *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	g_assert(SHARED_FILE_MAGIC == sf->magic);
	g_assert(sf->refcnt >= 0);
	g_assert((NULL != sf->name_nfc) ^ (0 == sf->name_nfc_len));
	g_assert((NULL != sf->name_canonic) ^ (0 == sf->name_canonic_len));
	g_assert(!(SHARE_F_INDEXED & sf->flags) ^ (0 != sf->file_index));
}

/**
 * Allocate a shared_file_t structure.
 */
static shared_file_t *
shared_file_alloc(void)
{
	static const shared_file_t zero_sf;
	shared_file_t *sf;

	sf = walloc(sizeof *sf);
	*sf = zero_sf;
	sf->magic = SHARED_FILE_MAGIC;
	return sf;
}

static void
shared_file_deindex(shared_file_t *sf)
{
	shared_file_check(sf);

	if (SHARE_F_BASENAME & sf->flags) {
		if (file_basenames) {
			g_hash_table_remove(file_basenames, sf->name_nfc);
		}
	}
	sf->flags &= ~SHARE_F_BASENAME;

	/**
	 * The shared file might not be referenced by the current file_table
	 * either because it hasn't been build yet or because of a rescan.
	 */

	if (
		file_table &&
		sf->file_index > 0 &&
		sf->file_index <= files_scanned &&
		sf == file_table[sf->file_index - 1]
   ) {
		g_assert(SHARE_F_INDEXED & sf->flags);
		file_table[sf->file_index - 1] = NULL;
	}
	if (
		sorted_file_table &&
		sf->sort_index > 0 &&
		sf->sort_index <= files_scanned &&
		sf == sorted_file_table[sf->sort_index - 1]
   ) {
		g_assert(SHARE_F_INDEXED & sf->flags);
		sorted_file_table[sf->sort_index - 1] = NULL;
	}
	sf->file_index = 0;
	sf->sort_index = 0;
	sf->flags &= ~SHARE_F_INDEXED;
}

/**
 * Dispose of a shared_file_t structure and nullify the pointer.
 */
static void
shared_file_free(shared_file_t **sf_ptr)
{
	g_assert(sf_ptr);
	if (*sf_ptr) {
		shared_file_t *sf = *sf_ptr;

		g_assert(sf->refcnt == 0);

		shared_file_deindex(sf);

		atom_sha1_free_null(&sf->sha1);
		atom_tth_free_null(&sf->tth);
		atom_str_free_null(&sf->relative_path);
		atom_str_free_null(&sf->file_path);
		atom_str_free_null(&sf->name_nfc);
		atom_str_free_null(&sf->name_canonic);
		sf->magic = 0;

		wfree(sf, sizeof *sf);
		*sf_ptr = NULL;
	}
}

static gboolean
shared_file_set_names(shared_file_t *sf, const gchar *filename)
{
  	shared_file_check(sf);	
   	g_assert(!sf->name_nfc);
   	g_assert(!sf->name_canonic);

	/* Set the NFC normalized name. */
	{	
		gchar *name;

		name = filename_to_utf8_normalized(filename, UNI_NORM_NETWORK);
		sf->name_nfc = atom_str_get(name);
		if (name != filename) {
			G_FREE_NULL(name);
		}
	}

	/*
	 * Set the NFKC normalized name. Also prepend the relative path
	 * if enabled. Queries will be matched against this string.
	 */
	{
		gchar *name, *name_canonic;

		if (
			GNET_PROPERTY(search_results_expose_relative_paths) &&
			sf->relative_path
		) {
			name = g_strconcat(sf->relative_path, " ", sf->name_nfc,
						(void *) 0);
		} else {
			name = deconstify_gchar(sf->name_nfc);
		}
		name_canonic = UNICODE_CANONIZE(name);
		sf->name_canonic = atom_str_get(name_canonic);
		if (name_canonic != name) {
			G_FREE_NULL(name_canonic);
		}
		if (name != sf->name_nfc) {
			G_FREE_NULL(name);
		}
	}

	sf->name_nfc_len = strlen(sf->name_nfc);
	sf->name_canonic_len = strlen(sf->name_canonic);

	if (0 == sf->name_nfc_len || 0 == sf->name_canonic_len) {
		g_warning("Normalized filename is an empty string \"%s\" "
			"(NFC=\"%s\", canonic=\"%s\")",
			filename, sf->name_nfc, sf->name_canonic);
		return TRUE;
	}
	return FALSE;
}


/* ----------------------------------------- */

static const guint FILENAME_CLASH = -1;		/**< Indicates basename clashes */

/* ----------------------------------------- */

/**
 * Initialize special file entry, returning shared_file_t structure if
 * the file exists, NULL otherwise.
 */
static shared_file_t *
share_special_load(const struct special_file *sp)
{
	FILE *f;
	gint idx;
	shared_file_t *sf;

#ifndef OFFICIAL_BUILD
	file_path_t fp[3];
#else
	file_path_t fp[2];
#endif

	file_path_set(&fp[0], settings_config_dir(), sp->file);
	file_path_set(&fp[1], PRIVLIB_EXP, sp->file);
#ifndef OFFICIAL_BUILD
	file_path_set(&fp[2], PACKAGE_EXTRA_SOURCE_DIR, sp->file);
#endif

	f = file_config_open_read_norename_chosen(
			sp->what, fp, G_N_ELEMENTS(fp), &idx);

	if (!f)
		return NULL;

	/*
	 * Create fake special file sharing structure, so that we can
	 * upload it if requested.
	 */

	sf = shared_file_alloc();
	sf->flags |= SHARE_F_SPECIAL;

	{
		gchar *filename = make_pathname(fp[idx].dir, fp[idx].name);
		sf->file_path = atom_str_get(filename);
		G_FREE_NULL(filename);
	}
	if (shared_file_set_names(sf, sp->file)) {
		shared_file_free(&sf);
		return NULL;
	}
	sf->mime_type = sp->type;

	fclose(f);

	return sf;
}

void
shared_files_match(const gchar *search_term,
	st_search_callback callback, gpointer user_data,
	gint max_res, query_hashvec_t *qhv)
{
	st_search(search_table, search_term, callback, user_data, max_res, qhv);
}

/**
 * Initialize the special files we're sharing.
 */
static void
share_special_init(void)
{
	guint i;

	special_names = g_hash_table_new(g_str_hash, g_str_equal);

	for (i = 0; i < G_N_ELEMENTS(specials); i++) {
		shared_file_t *sf = share_special_load(&specials[i]);
		if (sf != NULL)
			g_hash_table_insert(special_names,
				deconstify_gchar(specials[i].path), shared_file_ref(sf));
	}
}

/**
 * Look up a possibly shared special file, updating the entry with current
 * file size and modification time.
 *
 * @param path	the URL path on the server (case sensitive, of course)
 *
 * @return the shared file information if there is something shared at path,
 * or NULL if the path is invalid.
 */
shared_file_t *
shared_special(const gchar *path)
{
	shared_file_t *sf;
	struct stat file_stat;

	sf = g_hash_table_lookup(special_names, path);

	if (sf == NULL)
		return NULL;

	if (-1 == stat(sf->file_path, &file_stat)) {
		g_warning("can't stat %s: %s", sf->file_path, g_strerror(errno));
		return NULL;
	}

	if (!S_ISREG(file_stat.st_mode)) {
		g_warning("file %s is no longer a plain file", sf->file_path);
		return NULL;
	}

	/*
	 * Update information in case the file changed since the last time
	 * we served it.
	 */

	sf->file_size = file_stat.st_size;
	sf->mtime = file_stat.st_mtime;

	return sf;
}

/**
 * Given a valid index, returns the `struct shared_file' entry describing
 * the shared file bearing that index if found, NULL if not found (invalid
 * index) and SHARE_REBUILDING when we're rebuilding the library.
 */
shared_file_t *
shared_file(guint idx)
{
	/* @return shared file info for index `idx', or NULL if none */

	if (file_table == NULL)			/* Rebuilding the library! */
		return SHARE_REBUILDING;

	if (idx < 1 || idx > files_scanned)
		return NULL;

	return file_table[idx - 1];
}

/**
 * Given a valid index, returns the `struct shared_file' entry describing
 * the shared file bearing that index if found, NULL if not found (invalid
 * index) and SHARE_REBUILDING when we're rebuilding the library.
 */
shared_file_t *
shared_file_sorted(guint idx)
{
	/* @return shared file info for index `idx', or NULL if none */

	if (sorted_file_table == NULL)			/* Rebuilding the library! */
		return SHARE_REBUILDING;

	if (idx < 1 || idx > files_scanned)
		return NULL;

	return sorted_file_table[idx - 1];
}

/**
 * Get index of shared file identified by its name.
 * @return index > 0 if found, 0 if file is not known.
 */
static guint
shared_file_get_index(const gchar *filename)
{
	guint idx;

	idx = GPOINTER_TO_UINT(g_hash_table_lookup(file_basenames, filename));
	if (idx == 0 || idx == FILENAME_CLASH)
		return 0;

	g_assert(idx >= 1 && idx <= files_scanned);
	return idx;	
}

/**
 * Given a file basename, returns the `struct shared_file' entry describing
 * the shared file bearing that basename, provided it is unique, NULL if
 * we either don't have a unique filename or SHARE_REBUILDING if the library
 * is being rebuilt.
 */
shared_file_t *
shared_file_by_name(const gchar *filename)
{
	shared_file_t *sf;
	guint idx;

	if (file_table == NULL)
		return SHARE_REBUILDING;

	g_assert(file_basenames);
	idx = shared_file_get_index(filename);
	if (idx > 0) {
		sf = file_table[idx - 1];
		shared_file_check(sf);
		return sf;
	} else {
		return NULL;
	}
}

static void
free_extensions_helper(gpointer key,
	gpointer unused_value, gpointer unused_data)
{
	(void) unused_value;
	(void) unused_data;
	atom_str_free(key);
}
/**
 * Free existing extensions
 */
static void
free_extensions(void)
{
	if (extensions) {
		g_hash_table_foreach(extensions, free_extensions_helper, NULL);
		g_hash_table_destroy(extensions);
		extensions = NULL;
	}
}

/**
 * Get the file extensions to scan.
 */
void
parse_extensions(const gchar *str)
{
	gchar **exts = g_strsplit(str, ";", 0);
	gchar *x, *s;
	guint i;

	free_extensions();
	extensions = g_hash_table_new(ascii_strcase_hash, ascii_strcase_eq);

	for (i = 0; exts[i]; i++) {
		gchar c;

		s = exts[i];
		while ((c = *s) == '.' || c == '*' || c == '?' || is_ascii_blank(c))
			s++;

		if (c) {

			for (x = strchr(s, '\0'); x-- != s; /* NOTHING */) {
				if ((c = *x) == '*' || c == '?' || is_ascii_blank(c))
					*x = '\0';
				else
					break;
			}

			if (*s && NULL == g_hash_table_lookup(extensions, s)) {
				gconstpointer key = atom_str_get(s);
				gm_hash_table_insert_const(extensions, key, key);
			}
		}
	}

	g_strfreev(exts);
}

/**
 * Release shared dirs.
 */
static void
shared_dirs_free(void)
{
	GSList *sl;

	if (!shared_dirs)
		return;

	for (sl = shared_dirs; sl; sl = g_slist_next(sl)) {
		atom_str_free(sl->data);
	}
	g_slist_free(shared_dirs);
	shared_dirs = NULL;
}

/**
 * Update the property holding the shared directories.
 */
void
shared_dirs_update_prop(void)
{
    GSList *sl;
    GString *s;

    s = g_string_new("");

    for (sl = shared_dirs; sl != NULL; sl = g_slist_next(sl)) {
        g_string_append(s, sl->data);
        if (g_slist_next(sl) != NULL)
            g_string_append(s, ":");
    }

    gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, s->str);

    g_string_free(s, TRUE);
}

/**
 * Parses the given string and updated the internal list of shared dirs.
 * The given string was completely parsed, it returns TRUE, otherwise
 * it returns FALSE.
 */
gboolean
shared_dirs_parse(const gchar *str)
{
	gchar **dirs = g_strsplit(str, ":", 0);
    gboolean ret = TRUE;
	guint i;

	/* FIXME: ESCAPING! */

	shared_dirs_free();

	for (i = 0; dirs[i]; i++) {
		if (is_directory(dirs[i]))
			shared_dirs = g_slist_prepend(shared_dirs,
								deconstify_gchar(atom_str_get(dirs[i])));
        else
            ret = FALSE;
	}

	shared_dirs = g_slist_reverse(shared_dirs);
	g_strfreev(dirs);

    return ret;
}

/**
 * Add directory to the list of shared directories.
 */
void
shared_dir_add(const gchar *path)
{
	if (is_directory(path))
        shared_dirs = g_slist_append(shared_dirs,
						deconstify_gchar(atom_str_get(path)));

    shared_dirs_update_prop();
}

/**
 * Add one more reference to a shared_file_t.
 * @return its argument, for convenience.
 */
shared_file_t *
shared_file_ref(shared_file_t *sf)
{
	sf->refcnt++;
	return sf;
}

/**
 * Remove one reference to a shared_file_t, freeing entry if there are
 * no reference left. The pointer itself is nullified.
 */
void
shared_file_unref(shared_file_t **sf_ptr)
{
	g_assert(sf_ptr);

	if (*sf_ptr) {
		shared_file_t *sf = *sf_ptr;

		shared_file_check(sf);
		g_assert(sf->refcnt > 0);

		sf->refcnt--;
		if (0 == sf->refcnt) {
			shared_file_free(&sf);
		}
		*sf_ptr = NULL;
	}
}

/**
 * Is file too big to be shared on Gnutella?
 *
 * Note: The original purpose was to avoid files larger than 2^32-1 bytes.
 *		 Keep it just in case that a platform has an off_t with more than
 *		 64 bits.
 */
static inline gboolean
too_big_for_gnutella(off_t size)
{
	g_return_val_if_fail(size >= 0, TRUE);
	return size + (filesize_t)0 > (filesize_t)-1 + (off_t)0;
}

/**
 * Checks whether it's OK to share the pathname with respect to special
 * characters in the string. As the database stores records line-by-line,
 * newline characters in the filename are not acceptable.
 *
 * @return	If the pathname contains ASCII control characters, TRUE is
 *			returned. Otherwise, the pathname is considered OK and FALSE
 *			is returned.
 */
static gboolean
contains_control_chars(const gchar *pathname)
{
	const gchar *s;

	for (s = pathname; *s != '\0'; s++) {
		if (is_ascii_cntrl(*s))
			return TRUE;
	}
	return FALSE;
}

/**
 * Extracts the relative path from a pathname relative to base_dir. If
 * base_dir and pathname do not overlap, NULL is returned. The resulting
 * is converted to UTF-8 NFC and returned as an atom.
 *
 * @param base_dir The base directory.
 * @param pathname A pathname that is relative to "base_dir".
 * @return A string atom holding the relative path or NULL.
 */
static const gchar *
get_relative_path(const gchar *base_dir, const gchar *pathname)
{
	const gchar *s, *relative_path = NULL;

	s = is_strprefix(pathname, base_dir);
	if (s) {
		s = skip_dir_separators(s);
		if ('\0' != s[0]) {
			gchar *normalized, *nfc_str;

			normalized = normalize_dir_separators(s);
			nfc_str = filename_to_utf8_normalized(normalized, UNI_NORM_NETWORK);
			relative_path = atom_str_get(nfc_str);
			if (nfc_str != normalized) {
				G_FREE_NULL(nfc_str);
			}
			G_FREE_NULL(normalized);
		}
	}
	return relative_path;
}

/**
 * Verify that a file extension is valid for sharing
 *
 * @param filename  The name of the file to check.
 * @return TRUE if the file should be shared, FALSE if not.
 */
static gboolean
shared_file_valid_extension(const gchar *filename)
{
	const gchar *filename_ext;

	if (!extensions)
		return FALSE;

	if (
		1 == g_hash_table_size(extensions) &&
		g_hash_table_lookup(extensions, "--all--")
    ) {
		/*
		 * An extension "--all--" matches all files, even those that don't
		 * have any extension. [Original patch by Zygo Blaxell].
		 */
		return TRUE;
	}

	filename_ext = strrchr(filename, '.');
	if (filename_ext) {
		/*
		 * Filenames without any extension are not shared, unless
		 * "--all--" is used.
		 */	

		filename_ext++;	/* skip the dot */

		/* 
		 * Match the file extension (if any) against the extensions list.
		 * All valid extensions start with '.'.  Matching is case-insensitive
		 */

		if (g_hash_table_lookup(extensions, filename_ext)) {
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @param relative_path The relative path of the file or NULL.
 * @param pathname The absolute pathname of the file.
 * @param sb A "stat buffer" that was initialized with stat().
 *
 * return On success a shared_file_t for the file is returned. Otherwise,
 *		  NULL is returned.
 */
static shared_file_t * 
share_scan_add_file(const gchar *relative_path,
	const gchar *pathname, const struct stat *sb)
{
	shared_file_t *sf;
	const gchar *name;

	g_assert(is_absolute_path(pathname));
	g_assert(sb);
	g_return_val_if_fail(S_ISREG(sb->st_mode), NULL);

	if (0 == sb->st_size) {
		if (GNET_PROPERTY(share_debug) > 5)
			g_warning("Not sharing empty file: \"%s\"", pathname);
		return NULL;
	}

	if (too_big_for_gnutella(sb->st_size)) {
		g_warning("File is too big to be shared: \"%s\"", pathname);
		return NULL;
	}

	if (contains_control_chars(pathname)) {
		g_warning("Not sharing filename with control characters: "
				"\"%s\"", pathname);
		return NULL;
	}

	if (!shared_file_valid_extension(pathname))
		return NULL;

	/*
	 * In the "tmp" directory, don't share files that have a trailer.
	 * It's probably a file being downloaded, and which is not complete yet.
	 * This check is necessary in case they choose to share their
	 * downloading directory...
	 */

	name = strrchr(pathname, G_DIR_SEPARATOR);
	g_assert(name && G_DIR_SEPARATOR == name[0]);
	name++;						/* Start of file name */

	if (GNET_PROPERTY(share_debug) > 5) {
		g_message("share_scan_add_file: pathname=\"%s\"", pathname);
	}
	sf = shared_file_alloc();
	sf->file_path = atom_str_get(pathname);
	sf->relative_path = relative_path ? atom_str_get(relative_path) : NULL;
	sf->file_size = sb->st_size;
	sf->mtime = sb->st_mtime;

	if (shared_file_set_names(sf, name)) {
		shared_file_free(&sf);
		return NULL;
	}

	sf->mime_type = mime_type_from_filename(sf->name_nfc);

	if (!sha1_is_cached(sf)) {
		gint ret;

		ret = file_info_has_trailer(pathname);
		switch (ret) {
		case 1:
			/*
			 * It's probably a file being downloaded, and which
			 * is not complete yet. This check is necessary in
			 * case they choose to share their downloading
			 * directory...
			 */
			g_warning("will not share partial file \"%s\"", pathname);
			/* FALL THROUGH */
		case -1:
			shared_file_free(&sf);
			return NULL;
		}
	}
	
	/*
	 * NOTE: An `else'-clause here would be if the file WAS found in the
	 * sha1_cache.  Good place to set the SHA1 in "sf".
	 */

	return sf;
}

/**
 * Tries to extrace the file mode from a struct dirent. Not all systems
 * support this, in which case zero is returned. Types other than regular
 * files, directories and symlinks are ignored and gain a value of zero
 * as well.
 */
static mode_t
dir_entry_mode(const struct dirent *dir_entry)
{
	g_assert(dir_entry);
#ifdef HAS_DIRENT_D_TYPE
	switch (dir_entry->d_type) {
	case DT_DIR: return S_IFDIR;
	case DT_LNK: return S_IFLNK;
	case DT_REG: return S_IFREG;
	}
#endif	/* HAS_DIRENT_WITH_D_TYPE */
	return 0;
}

/**
 * Check whether the given directory is one which should never be shared.
 * This is not meant to be exhaustive but test for common configuration
 * mistakes.
 */
static gboolean
directory_is_unshareable(const char *dir)
{
	g_assert(dir);

	/* Explicitly checking is_same_file() for TRUE to ignore errors (-1)
	 * probably caused by non-existing files or missing permission.
	 */
	if (TRUE == is_same_file(dir, "/")) {
		g_warning("Refusing to share root directory: %s", dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, settings_home_dir())) {
		g_warning("Refusing to share home directory: %s", dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, settings_config_dir())) {
		g_warning("Refusing to share directory for configuration data: %s",
			dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, GNET_PROPERTY(save_file_path))) {
		g_warning("Refusing to share directory for incomplete files: %s",
			dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, GNET_PROPERTY(bad_file_path))) {
		g_warning("Refusing to share directory for corrupted files: %s",
			dir);
		return TRUE;
	}

	return FALSE;	/* No objection */
}

enum recursive_scan_magic { RECURSIVE_SCAN_MAGIC = 0x16926d87U };

struct recursive_scan {
	enum recursive_scan_magic magic;	/**< Magic number. */
	struct bgtask *task;
	DIR *directory;
	const char *base_dir;		/* string atom */
	const char *current_dir;	/* string atom */
	const char *relative_path;	/* string atom */
	slist_t *base_dirs;			/* list of string atoms */
	slist_t *sub_dirs;			/* list of g_malloc()ed strings */
	slist_t *shared_files;		/* list of struct shared_file */
};

static inline void
recursive_scan_check(const struct recursive_scan * const ctx)
{
	g_assert(ctx);
	g_assert(RECURSIVE_SCAN_MAGIC == ctx->magic);
	g_assert(ctx->base_dirs);
	g_assert(ctx->sub_dirs);
	g_assert(ctx->shared_files);
}

static struct recursive_scan *
recursive_scan_new(const GSList *base_dirs)
{
	static const struct recursive_scan zero_ctx;
	struct recursive_scan *ctx;
	const GSList *iter;

	ctx = walloc(sizeof *ctx);
	*ctx = zero_ctx;
	ctx->magic = RECURSIVE_SCAN_MAGIC;
	ctx->base_dirs = slist_new();
	ctx->sub_dirs = slist_new();
	ctx->shared_files = slist_new();
	for (iter = base_dirs; NULL != iter; iter = g_slist_next(iter)) {
		const char *dir = atom_str_get(iter->data);
		slist_append(ctx->base_dirs, deconstify_gchar(dir));
	}
	return ctx;
}

static void
recursive_scan_closedir(struct recursive_scan *ctx)
{
	recursive_scan_check(ctx);

	atom_str_free_null(&ctx->relative_path);
	atom_str_free_null(&ctx->current_dir);
	if (ctx->directory) {
		closedir(ctx->directory);
		ctx->directory = NULL;
	}
}

static void recursive_sf_unref(gpointer o)
{
	struct shared_file *sf = o;

	shared_file_check(sf);
	shared_file_unref(&sf);
}

static void
recursive_scan_free(struct recursive_scan **ctx_ptr)
{
	g_assert(ctx_ptr);

	if (*ctx_ptr) {
		struct recursive_scan *ctx = *ctx_ptr;

		recursive_scan_check(ctx);

		if (ctx->task) {
			bg_task_cancel(ctx->task);
			g_assert(NULL == ctx->task);
		}

		recursive_scan_closedir(ctx);

		slist_free_all(&ctx->base_dirs, (slist_destroy_cb) atom_str_free);
		slist_free_all(&ctx->sub_dirs, g_free);
		slist_free_all(&ctx->shared_files, recursive_sf_unref);

		atom_str_free_null(&ctx->base_dir);

		ctx->magic = 0;
		wfree(ctx, sizeof *ctx);
		*ctx_ptr = NULL;
	}
}

static void
recursive_scan_context_free(void *data)
{
	struct recursive_scan *ctx = data;
	
	recursive_scan_check(ctx);
	/* If we're called, the task is being terminated */

	/*
	 * There's nothing to free here.  We're managing the overall context
	 * ourselves and this overall context is given as the task's context.
	 * We just need to record the fact that the task has been terminated
	 * here so recursive_scan_free() does not try to cancel it.
	 */

	ctx->task = NULL;
}

/**
 * Free up memory used by the shared library.
 */
static void
share_free(void)
{
	GSList *sl;

	st_destroy(search_table);

	if (file_basenames) {
		g_hash_table_destroy(file_basenames);
		file_basenames = NULL;
	}

	for (sl = shared_files; sl; sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;

		shared_file_check(sf);
		shared_file_deindex(sf);
		shared_file_unref(&sf);
	}
	g_slist_free(shared_files);
	shared_files = NULL;

	G_FREE_NULL(file_table);
	G_FREE_NULL(sorted_file_table);
}

/**
 * Sort function - shared files by descending mtime. 
 */
static int
shared_file_sort_by_mtime(const void *f1, const void *f2)
{
	const shared_file_t * const *sf1 = f1, * const *sf2 = f2;
	time_t t1, t2;

	/* We don't use shared_file_check() here because it would be
	 * the dominating factor for the sorting time. */
	g_assert(SHARED_FILE_MAGIC == (*sf1)->magic);
	g_assert(SHARED_FILE_MAGIC == (*sf2)->magic);

	t1 = (*sf1)->mtime;
	t2 = (*sf2)->mtime;
	return CMP(t1, t2);
}

static inline int
cmp_strings(const char *a, const char *b)
{
	if (a && b) {
		return a == b ? 0 : strcmp(a, b);
	} else {
		return a ? 1 : (b ? -1 : 0);
	}
}

/**
 * Sort function - shared files by descending mtime. 
 */
static int
shared_file_sort_by_name(const void *f1, const void *f2)
{
	const shared_file_t * const *sf1 = f1, * const *sf2 = f2;
	int ret;

	/* We don't use shared_file_check() here because it would be
	 * the dominating factor for the sorting time. */
	g_assert(SHARED_FILE_MAGIC == (*sf1)->magic);
	g_assert(SHARED_FILE_MAGIC == (*sf2)->magic);

	if (GNET_PROPERTY(search_results_expose_relative_paths)) {
		ret = cmp_strings((*sf1)->relative_path, (*sf2)->relative_path);
	} else {
		ret = strcmp((*sf1)->file_path, (*sf2)->file_path);
	}
	return 0 != ret ? ret : strcmp((*sf1)->name_nfc, (*sf2)->name_nfc);
}

/**
 * NOTE: This step is a rather big atomic block. Ideally, it should be broken
 * down in smaller steps to avoid temporary unresponsiveness. However, compared
 * to the time it takes to scan files, especially on slower disks, this
 * finishing step is neglible even for thousands of shared files.
 */
static void
recursive_scan_finish(struct recursive_scan *ctx)
{
	GSList *sl;
	time_delta_t elapsed;
	size_t i;

	recursive_scan_check(ctx);

	/*
	 * Done scanning for the files. Now process them.
	 */

	elapsed = delta_time(tm_time_exact(),
				GNET_PROPERTY(library_rescan_started));
	elapsed = MAX(0, elapsed);
	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_FINISHED, tm_time());
	gnet_prop_set_guint32_val(PROP_LIBRARY_RESCAN_DURATION, elapsed);

	reinit_sha1_table();
	share_free();

	g_assert(file_basenames == NULL);
	file_basenames = g_hash_table_new(g_str_hash, g_str_equal);

	g_assert(search_table);
	st_create(search_table);

	files_scanned = slist_length(ctx->shared_files);
	bytes_scanned = 0;

	g_assert(shared_files == NULL);

	while (slist_length(ctx->shared_files) > 0) {
		struct shared_file *sf = slist_shift(ctx->shared_files);

		shared_file_check(sf);
		bytes_scanned += sf->file_size;
		st_insert_item(search_table, sf->name_canonic, sf);
		shared_files = g_slist_prepend(shared_files, sf);
		upload_stats_enforce_local_filename(sf);
	}

	/* Compact the search table */
	st_compact(search_table);

	file_table = g_malloc0((files_scanned + 1) * sizeof file_table[0]);

	/*
	 * We over-allocate the file_table by one entry so that even when they
	 * don't share anything, the `file_table' pointer is not NULL.
	 * This will prevent us giving back "rebuilding library" when we should
	 * actually return "not found" for user download requests.
	 *		--RAM, 23/10/2002
	 */
	
	i = 0;
	for (sl = shared_files; sl; sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;

		shared_file_check(sf);
		g_assert(!(SHARE_F_INDEXED & sf->flags));
		file_table[i++] = sf;
	}

	/* Sort file list by modification time to get a relatively stable index */
	qsort(file_table, files_scanned, sizeof file_table[0],
		shared_file_sort_by_mtime);

	/*
	 * In order to quickly locate files based on indicies, build a table
	 * of all shared files.  This table is only accessible via shared_file().
	 * NB: file indicies start at 1, but indexing in table start at 0.
	 *		--RAM, 08/10/2001
	 */

	for (i = 0; i < files_scanned; i++) {
		struct shared_file *sf;
		guint val;

		/* FIXME: Must be handled in the background */

	   	sf = file_table[i];
		if (!sf)
			continue;

		/* Set file_index based on new sort order */
		sf->file_index = i + 1;
		sf->flags |= SHARE_F_INDEXED;
		shared_file_check(sf);

		/* We must not change the file index after request_sha1() */
		if (!request_sha1(sf)) {
			file_table[i] = NULL;
			continue;
		}

		/*
		 * In order to transparently handle files requested with the wrong
		 * indices, for older servents that would not know how to handle a
		 * return code of "301 Moved" with a Location header, we keep track
		 * of individual basenames of files, recording the index of each file.
		 * As soon as there is a clash, we revoke the entry by storing
		 * FILENAME_CLASH instead, which cannot be a valid index.
		 *		--RAM, 06/06/2002
		 */

		val = GPOINTER_TO_UINT(
			g_hash_table_lookup(file_basenames, sf->name_nfc));

		/*
		 * The following works because 0 cannot be a valid file index.
		 */

		val = (val != 0) ? FILENAME_CLASH : sf->file_index;
		g_hash_table_insert(file_basenames, deconstify_gchar(sf->name_nfc),
			GUINT_TO_POINTER(val));
		sf->flags |= SHARE_F_BASENAME;
	}

	sorted_file_table = g_memdup(file_table,
							(files_scanned + 1) * sizeof file_table[0]);
	qsort(sorted_file_table, files_scanned, sizeof sorted_file_table[0],
		shared_file_sort_by_name);

	/* Set the sort index used for sorted file listings */
	for (i = 0; i < files_scanned; i++) {
		struct shared_file *sf;

	   	sf = sorted_file_table[i];
		if (!sf)
			continue;
		shared_file_check(sf);
		sf->sort_index = i + 1;
	}

	gcu_gui_update_files_scanned();		/* Final view */

	/*
	 * Query routing table update.
	 */

	gnet_prop_set_timestamp_val(PROP_QRP_INDEXING_STARTED, tm_time_exact());

	qrp_prepare_computation();

	i = 0;
	for (sl = shared_files; sl; sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;

		/* FIXME: Must be handled in the background */
		shared_file_check(sf);
		qrp_add_file(sf);
	}

	qrp_finalize_computation();

	elapsed = delta_time(tm_time(), GNET_PROPERTY(qrp_indexing_started));
	elapsed = MAX(0, elapsed);
	gnet_prop_set_guint32_val(PROP_QRP_INDEXING_DURATION, elapsed);

	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, FALSE);
}

static void
recursive_scan_opendir(struct recursive_scan *ctx, const char * const dir)
{
	recursive_scan_check(ctx);
	g_assert(NULL == ctx->directory);
	g_assert(NULL == ctx->relative_path);
	g_assert(NULL == ctx->current_dir);

	g_return_if_fail('\0' != dir[0]);
	g_return_if_fail(is_absolute_path(ctx->base_dir));
	g_return_if_fail(is_absolute_path(dir));

	if (directory_is_unshareable(dir))
		return;

	if (!(ctx->directory = opendir(dir))) {
		g_warning("can't open directory %s: %s", dir, g_strerror(errno));
		return;
	}

	/* Get relative path if required */
	if (GNET_PROPERTY(search_results_expose_relative_paths)) {
		ctx->relative_path = get_relative_path(ctx->base_dir, dir);
	} else {
		ctx->relative_path = NULL;
	}
	ctx->current_dir = atom_str_get(dir);
}

static void
recursive_scan_readdir(struct recursive_scan *ctx)
{
	char *fullpath = NULL;
	struct dirent *dir_entry;

	recursive_scan_check(ctx);
	g_assert(ctx->directory);

	dir_entry = readdir(ctx->directory);
	if (dir_entry) {
		struct stat sb;

		if (dir_entry->d_name[0] == '.') {
			/* Hidden file, or "." or ".." */
			goto finish;
		}

		sb.st_mode = dir_entry_mode(dir_entry);
		if (
			S_ISLNK(sb.st_mode) &&
			GNET_PROPERTY(scan_ignore_symlink_dirs) &&
			GNET_PROPERTY(scan_ignore_symlink_regfiles)
		) {
			goto finish;
		}

		if (
			S_ISREG(sb.st_mode) &&
			!shared_file_valid_extension(dir_entry->d_name)
		) {
			goto finish;
		}

		fullpath = make_pathname(ctx->current_dir, dir_entry->d_name);
		if (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode)) {
			if (stat(fullpath, &sb)) {
				g_warning("stat() failed %s: %s", fullpath, g_strerror(errno));
				goto finish;
			}
		} else if (!S_ISLNK(sb.st_mode)) {
			if (lstat(fullpath, &sb)) {
				g_warning("lstat() failed %s: %s", fullpath, g_strerror(errno));
				goto finish;
			}

			if (
				S_ISLNK(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_dirs) &&
				GNET_PROPERTY(scan_ignore_symlink_regfiles)
			) {
				/* We check this again because dir_entry_mode() does not
				 * work everywhere. */
				goto finish;
			}
		}

		/* Get info on the symlinked file */
		if (S_ISLNK(sb.st_mode)) {
			if (stat(fullpath, &sb)) {
				g_warning("Broken symlink %s: %s",
					fullpath, g_strerror(errno));
				goto finish;
			}
			
			/*
			 * For symlinks, we check whether we are supposed to process
			 * symlinks for that type of entry, then either proceed or skip the
			 * entry.
			 */

			if (
				S_ISDIR(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_dirs)
			)
				goto finish;
			if (
				S_ISREG(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_regfiles)
			)
				goto finish;
		}
		
		if (S_ISDIR(sb.st_mode)) {
			/* If a directory, add to list for later processing */
			slist_prepend(ctx->sub_dirs, fullpath);
			fullpath = NULL;
		} else if (S_ISREG(sb.st_mode)) {
			shared_file_t *sf;

			sf = share_scan_add_file(ctx->relative_path, fullpath, &sb);
			if (sf) {
				slist_append(ctx->shared_files, shared_file_ref(sf));
			}
		}
	} else {
		recursive_scan_closedir(ctx);
	}

finish:
	G_FREE_NULL(fullpath);
}

/**
 * @return TRUE if finished.
 */
static gboolean 
recursive_scan_next_dir(struct recursive_scan *ctx)
{
	recursive_scan_check(ctx);

	if (ctx->directory) {
		recursive_scan_readdir(ctx);
		return FALSE;
	} else if (slist_length(ctx->sub_dirs) > 0) {
		char *dir;
	   
		dir = slist_shift(ctx->sub_dirs);
		recursive_scan_opendir(ctx, dir);
		G_FREE_NULL(dir);
		return FALSE;
	} else if (slist_length(ctx->base_dirs) > 0) {
		atom_str_free_null(&ctx->base_dir);
		ctx->base_dir = slist_shift(ctx->base_dirs);
		recursive_scan_opendir(ctx, ctx->base_dir);
		return FALSE;
	} else {
		atom_str_free_null(&ctx->base_dir);
		return TRUE;
	}
}

static bgret_t
recursive_scan_step_compute(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	int i = 0;

	recursive_scan_check(ctx);
	(void) ticks;
	(void) bt;

	do {
		if (recursive_scan_next_dir(ctx)) {
			recursive_scan_finish(ctx);
			return BGR_DONE;
		}
	} while (++i < ticks);

	return BGR_MORE;
}

static void
recursive_scan_create_task(struct recursive_scan *ctx)
{
	recursive_scan_check(ctx);

	if (NULL == ctx->task) {
		static const bgstep_cb_t step[] = { recursive_scan_step_compute };

		ctx->task = bg_task_create("recursive scan",
							step, G_N_ELEMENTS(step),
			  				ctx, recursive_scan_context_free,
							NULL, NULL);
	}
}

/**
 * Perform scanning of the shared directories to build up the list of
 * shared files.
 */
void
share_scan(void)
{
	recursive_scan_free(&recursive_scan_context);
	recursive_scan_context = recursive_scan_new(shared_dirs);
	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, TRUE);
	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_STARTED, tm_time_exact());
	recursive_scan_create_task(recursive_scan_context);
}

/**
 * Hash table iterator callback to free the value.
 */
static void
special_free_kv(gpointer unused_key, gpointer val, gpointer unused_udata)
{
	shared_file_t *sf = val;

	(void) unused_key;
	(void) unused_udata;

	g_assert(SHARE_F_SPECIAL & sf->flags);
	shared_file_unref(&sf);
}

/**
 * Get rid of the special file descriptions, if any.
 */
static void
share_special_close(void)
{
	g_hash_table_foreach(special_names, special_free_kv, NULL);
	g_hash_table_destroy(special_names);
	special_names = NULL;
}

/**
 * Shutdown cleanup.
 */
void
share_close(void)
{
	recursive_scan_free(&recursive_scan_context);
	share_special_close();
	free_extensions();
	share_free();
	shared_dirs_free();
	huge_close();
	qrp_close();
	oob_proxy_close();
	oob_close();
	qhit_close();
	st_free(&search_table);
}

/*
 * SHA1 digest processing
 */

/**
 * Set the SHA1 hash of a given shared_file. Take care of updating the
 * sha1_to_share structure. This function is called from inside the bowels of
 * huge.c when it knows what the hash associated to a file is.
 */
void
shared_file_set_sha1(struct shared_file *sf, const struct sha1 *sha1)
{
	shared_file_check(sf);
	g_assert(!shared_file_is_partial(sf));	/* Cannot be a partial file */

	sf->flags &= ~(SHARE_F_RECOMPUTING | SHARE_F_HAS_DIGEST);
	sf->flags |= sha1 ? SHARE_F_HAS_DIGEST : 0;

	if (sf->sha1) {
		struct shared_file *current;
		gpointer key;

		key = deconstify_gpointer(sf->sha1);
		current = g_tree_lookup(sha1_to_share, key);
		if (current) {
			shared_file_check(current);
			g_assert(SHARE_F_INDEXED & current->flags);

			if (sf == current) {
				g_tree_remove(sha1_to_share, key);
			}
		}
	}

	atom_sha1_change(&sf->sha1, sha1);

	/*
	 * If the file is no longer in the index table, it must not be
	 * put into the tree again. This might happen if a SHA-1 calculation
	 * from a previous rescan finishes after newly initiated rescan.
	 */
	if ((SHARE_F_INDEXED & sf->flags) && sf->sha1) {
		struct shared_file *current;
		gpointer key;

		key = deconstify_gpointer(sf->sha1);
		current = g_tree_lookup(sha1_to_share, key);
		if (current) {
			shared_file_check(current);
			g_assert(SHARE_F_INDEXED & current->flags);
			
			/*
			 * There can be multiple shared files with the same SHA-1.
			 * Only the first found is inserted into the tree.
			 */
			if (GNET_PROPERTY(share_debug) > 0) {
				g_message("\"%s\" is a duplicate of \"%s\"",
					shared_file_path(sf),
					shared_file_path(current));
			}
		} else {
			g_tree_insert(sha1_to_share, deconstify_gpointer(sf->sha1), sf);
		}
	}
}

void
shared_file_set_tth(struct shared_file *sf, const struct tth *tth)
{
	shared_file_check(sf);

	g_assert(!shared_file_is_partial(sf));	/* Cannot be a partial file */

	atom_tth_change(&sf->tth, tth);
}

void
shared_file_set_modification_time(struct shared_file *sf, time_t mtime)
{
	shared_file_check(sf);
	sf->mtime = mtime;
}

/**
 * Predicate returning TRUE if the SHA1 hash is available for a given
 * shared_file, FALSE otherwise.
 *
 * Use sha1_hash_is_uptodate() to check for availability and accurateness.
 */
gboolean
sha1_hash_available(const struct shared_file *sf)
{
	shared_file_check(sf);
	return SHARE_F_HAS_DIGEST ==
		(sf->flags & (SHARE_F_HAS_DIGEST | SHARE_F_RECOMPUTING));
}

/**
 * Predicate returning TRUE if the SHA1 hash is available AND is up to date
 * for the shared file.
 *
 * NB: if the file is found to have changed, the background computation of
 * the SHA1 is requested.
 */
gboolean
sha1_hash_is_uptodate(struct shared_file *sf)
{
	struct stat buf;

	shared_file_check(sf);

	if (!(sf->flags & SHARE_F_HAS_DIGEST))
		return FALSE;

	if (sf->flags & SHARE_F_RECOMPUTING)
		return FALSE;

	/*
	 * If there is a non-NULL `fi' entry, then this is a partially
	 * downloaded file that we are sharing.  Don't try to update its
	 * SHA1 by recomputing it!
	 *
	 * If it's a partial file, don't bother checking whether it exists.
	 * (if gone, we won't be able to serve it, that's all).  But partial
	 * files we serve MUST have known SHA1.
	 */

	if (shared_file_is_partial(sf)) {
		g_assert(sf->fi->sha1 != NULL);
		return TRUE;
	}

	if (-1 == stat(sf->file_path, &buf)) {
		g_warning("can't stat shared file #%d \"%s\": %s",
			sf->file_index, sf->file_path, g_strerror(errno));
		shared_file_set_sha1(sf, NULL);
		return FALSE;
	}

	if (too_big_for_gnutella(buf.st_size)) {
		g_warning("File is too big to be shared: \"%s\"", sf->file_path);
		shared_file_set_sha1(sf, NULL);
		return FALSE;
	}

	/*
	 * If file was modified since the last time we computed the SHA1,
	 * recompute it and tell them that the SHA1 we have might not be
	 * accurate.
	 */

	if (
			sf->mtime != buf.st_mtime ||
			sf->file_size + (off_t) 0 != buf.st_size + (filesize_t) 0
	) {
		g_warning("shared file #%d \"%s\" changed, recomputing SHA1",
			sf->file_index, sf->file_path);
		sf->flags |= SHARE_F_RECOMPUTING;
		sf->mtime = buf.st_mtime;
		sf->file_size = buf.st_size;
		request_sha1(sf);
		return FALSE;
	}

	return TRUE;
}

/**
 * Whether file is finished (i.e. either shared from the library or seeded).
 */
gboolean
shared_file_is_finished(const struct shared_file *sf)
{
	shared_file_check(sf);
	return NULL == sf->fi || 0 != (sf->fi->flags & FI_F_SEEDING);
}

gboolean
shared_file_is_partial(const struct shared_file *sf)
{
	shared_file_check(sf);
	return NULL != sf->fi;
}

filesize_t
shared_file_size(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->file_size;
}

guint32
shared_file_index(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->file_index;
}

const struct sha1 *
shared_file_sha1(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->sha1;
}

const struct tth *
shared_file_tth(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->tth;
}

const gchar *
shared_file_name_nfc(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_nfc;
}

const gchar *
shared_file_name_canonic(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_canonic;
}

size_t
shared_file_name_nfc_len(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_nfc_len;
}

size_t
shared_file_name_canonic_len(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_canonic_len;
}

/**
 * Returns the relative path of the shared files unless there was none
 * or exposing relative paths is disabled.
 *
 * @return A string or NULL.
 */
const gchar *
shared_file_relative_path(const shared_file_t *sf)
{
	shared_file_check(sf);
	return GNET_PROPERTY(search_results_expose_relative_paths)
			? sf->relative_path
			: NULL;
}

/**
 * Get the pathname of a shared file.
 *
 * @param sf an initialized shared file.
 * @return	the full pathname of the shared file. The returned pointer is
 *			a string atom.
 */
const gchar *
shared_file_path(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->file_path;
}

time_t
shared_file_modification_time(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->mtime;
}

guint32
shared_file_flags(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->flags;
}

fileinfo_t *
shared_file_fileinfo(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->fi;
}

const gchar *
shared_file_mime_type(const shared_file_t *sf)
{
	shared_file_check(sf);
	return mime_type_to_string(sf->mime_type);
}

void
shared_file_remove(struct shared_file *sf)
{
	shared_file_check(sf);

	shared_file_deindex(sf);
	if (0 == sf->refcnt) {
		shared_file_free(&sf);
	}
}

void
shared_file_set_path(struct shared_file *sf, const gchar *pathname)
{
	shared_file_check(sf);
	atom_str_change(&sf->file_path, pathname);
}

void
shared_file_from_fileinfo(fileinfo_t *fi)
{
	shared_file_t *sf;

	file_info_check(fi);

	sf = shared_file_alloc();
	sf->flags = SHARE_F_HAS_DIGEST;
	sf->mtime = fi->last_flush;
	sf->sha1 = atom_sha1_get(fi->sha1);

	/* FIXME: DOWNLOAD_SIZE:
	 * Do we need to add anything here now that fileinfos can have an
	 *  unknown length? --- Emile
	 */

	sf->file_size = fi->size;
	
	/*
	 * Determine a proper human-readable name for the file.
	 * If it is an URN, look through the aliases.
	 */

	if (shared_file_set_names(sf, file_info_readable_filename(fi))) {
		shared_file_free(&sf);
		return;
	}
	sf->mime_type = mime_type_from_filename(sf->name_nfc);

	sf->file_path = atom_str_get(fi->pathname);

	sf->fi = fi;		/* Signals it's a partially downloaded file */
	fi->sf = shared_file_ref(sf);
}

/**
 * @returns the shared_file if we share a complete file bearing the given SHA1.
 * @returns NULL if we don't share a complete file, or SHARE_REBUILDING if the
 * set of shared file is being rebuilt.
 */
static struct shared_file *
shared_file_complete_by_sha1(const struct sha1 *sha1)
{
	struct shared_file *f;

	if (sha1_to_share == NULL)			/* Not even begun share_scan() yet */
		return SHARE_REBUILDING;

	f = g_tree_lookup(sha1_to_share, deconstify_gpointer(sha1));
	if (f) {
		shared_file_check(f);
	}

	if (!f || !sha1_hash_available(f)) {
		/*
		 * If we're rebuilding the library, we might not have parsed the
		 * file yet, so it's possible we have this URN but we don't know
		 * it yet.	--RAM, 12/10/2002.
		 */

		if (file_table == NULL)			/* Rebuilding the library! */
			return SHARE_REBUILDING;

		return NULL;
	}

	return f;
}

/**
 * Take a given binary SHA1 digest, and return the corresponding
 * shared_file if we have it.
 *
 * @attention
 * NB: if the returned "shared_file" structure holds a non-NULL `fi',
 * then it means it is a partially shared file.
 *
 * @returns NULL if we don't share a complete file, or SHARE_REBUILDING if the
 * set of shared file is being rebuilt.
 */
shared_file_t *
shared_file_by_sha1(const struct sha1 *sha1)
{
	struct shared_file *f;

	f = shared_file_complete_by_sha1(sha1);

	/*
	 * If we don't share this file, or if we're rebuilding, and provided
	 * PFSP-server is enabled, look whether we don't have a partially
	 * downloaded file with this SHA1.
	 */

	if (f == NULL || f == SHARE_REBUILDING) {
		if (GNET_PROPERTY(pfsp_server)) {
			struct shared_file *sf = file_info_shared_sha1(sha1);
			if (sf)
				f = sf;
		}
	}
	if (f && SHARE_REBUILDING != f) {
		shared_file_check(f);
	}
	return f;
}

/**
 * Get accessor for ``kbytes_scanned''
 */
guint64
shared_kbytes_scanned(void)
{
	return bytes_scanned / 1024;
}

/**
 * Get accessor for ``files_scanned''
 */
guint64
shared_files_scanned(void)
{
	return files_scanned;
}

/**
 * Initialization of the sharing library.
 */
void
share_init(void)
{
	huge_init();
	search_table = st_alloc();
	st_initialize(search_table);
	qrp_init();
	qhit_init();
	oob_init();
	oob_proxy_init();
	share_special_init();

	/**
	 * We allocate an empty search_table, which will be de-allocated when we
	 * call share_scan().  Why do we do this?  Because it ensures the table
	 * is correctly setup empty, until we do call share_scan() for the first
	 * time (the call is delayed until the GUI is up).
	 *
	 * Since we will start processing network packets, we will have a race
	 * condition window if we get a Query message before having started
	 * the share_scan().  Creating the table right now prevents adding an
	 * extra test at the top of st_search().
	 *		--RAM, 15/08/2002.
	 */

	st_create(search_table);
}

/* vi: set ts=4 sw=4 cindent: */
