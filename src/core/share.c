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
#include "gnet_stats.h"
#include "search.h"		/* For QUERY_SPEED_MARK */
#include "guid.h"
#include "hostiles.h"
#include "matching.h"
#include "qhit.h"
#include "oob.h"
#include "oob_proxy.h"
#include "fileinfo.h"
#include "settings.h"
#include "hosts.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/atoms.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/hashlist.h"
#include "lib/listener.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

struct shared_file {
	const gchar *file_path;		/**< The full path of the file (atom!) */
	const gchar *name_nfc;		/**< UTF-8 NFC version of filename (atom!) */
	const gchar *name_canonic;	/**< UTF-8 canonized ver. of filename (atom)! */
	const gchar *content_type;	/**< MIME content type (static string) */

	size_t name_nfc_len;		/**< strlen(name_nfc) */
	size_t name_canonic_len;	/**< strlen(name_canonic) */

	struct dl_file_info *fi;	/**< PFSP-server: the holding fileinfo */

	gchar *sha1;				/**< SHA1 digest, binary form, atom */

	time_t mtime;				/**< Last modif. time, for SHA1 computation */

	filesize_t file_size;		/**< File size in Bytes */
	guint32 file_index;			/**< the files index within our local DB */

	gint refcnt;				/**< Reference count */
	guint32 flags;				/**< See below for definition */
};

/**
 * Describes special files which are served by GTKG.
 */
struct special_file {
	const gchar *path;			/* URL path */
	const gchar *file;			/* File name to load from disk */
	enum share_mime_type type;	/* MIME type of the file */
	const gchar *what;			/* Description of the file for traces */
};

static struct special_file specials[] = {
	{ "/favicon.ico",
			"favicon.png",	SHARE_M_IMAGE_PNG,	"Favorite web icon" },
	{ "/robots.txt",
			"robots.txt",	SHARE_M_TEXT_PLAIN,	"Robot exclusion" },
};

/**
 * Maps special names (e.g. "/favicon.ico") to the shared_file_t structure.
 */
static GHashTable *special_names = NULL;

static guint64 files_scanned = 0;
static guint64 kbytes_scanned = 0;
static guint64 bytes_scanned = 0;

GSList *extensions = NULL;
GSList *shared_dirs = NULL;
static GSList *shared_files = NULL;
static struct shared_file **file_table = NULL;
static search_table_t *search_table;
static GHashTable *file_basenames = NULL;

static GHashTable *muid_to_query_map;
static hash_list_t *query_muids;

/***
 *** Callbacks
 ***/

static listeners_t search_request_listeners = NULL;

void
share_add_search_request_listener(search_request_listener_t l)
{
    LISTENER_ADD(search_request, l);
}

void
share_remove_search_request_listener(search_request_listener_t l)
{
    LISTENER_REMOVE(search_request, l);
}

static void
share_emit_search_request(
	query_type_t type, const gchar *query, const host_addr_t addr, guint16 port)
{
    LISTENER_EMIT(search_request, (type, query, addr, port));
}

/* ----------------------------------------- */

/**
 * A query context.
 *
 * We don't want to include the same file several times in a reply (for
 * example, once because it matches an URN query and once because the file name
 * matches). So we keep track of what has been added in `found_indices'.
 * The file index is used as the key.
 */
struct query_context {
	GHashTable *found_indices;
	GSList *files;				/**< List of shared_file_t that match */
	gint found;
};

/**
 * Create new query context.
 */
static struct query_context *
share_query_context_make(void)
{
	struct query_context *ctx;

	ctx = walloc(sizeof *ctx);
	ctx->found_indices = g_hash_table_new(NULL, NULL);	/**< direct hashing */
	ctx->files = NULL;
	ctx->found = 0;

	return ctx;
}

/**
 * Get rid of the query context.
 */
static void
share_query_context_free(struct query_context *ctx)
{
	/*
	 * Don't free the `files' list, as we passed it to the query hit builder.
	 */

	g_hash_table_destroy(ctx->found_indices);
	wfree(ctx, sizeof *ctx);
}

/**
 * Check if a given shared_file has been added to the QueryHit.
 *
 * @return TRUE if the shared_file is in the QueryHit already, FALSE otherwise
 */
static inline gboolean
shared_file_already_found(struct query_context *ctx, const shared_file_t *sf)
{
	return NULL != g_hash_table_lookup(ctx->found_indices,
		GUINT_TO_POINTER(sf->file_index));
}

/**
 * Add the shared_file to the set of files already added to the QueryHit.
 */
static inline void
shared_file_mark_found(struct query_context *ctx, const shared_file_t *sf)
{
	g_hash_table_insert(ctx->found_indices,
		GUINT_TO_POINTER(sf->file_index), GUINT_TO_POINTER(0x1));
}

/**
 * Invoked for each new match we get.
 */
static void
got_match(gpointer context, gpointer data)
{
	struct query_context *qctx = context;
	shared_file_t *sf = data;

	g_assert(sf);
	/* Cannot match partially downloaded files */
	g_assert(!shared_file_is_partial(sf));

	/*
	 * Don't insert duplicates (possible when matching both by SHA1 and name).
	 */

	if (shared_file_already_found(qctx, sf))
		return;

	shared_file_mark_found(qctx, sf);

	qctx->files = g_slist_prepend(qctx->files, shared_file_ref(sf));
	qctx->found++;
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
	return sf;
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

		atom_sha1_free_null(&sf->sha1);
		atom_str_free(sf->file_path);
		atom_str_free(sf->name_nfc);
		atom_str_free(sf->name_canonic);
		wfree(sf, sizeof *sf);
		*sf_ptr = NULL;
	}
}

static gboolean
shared_file_set_names(shared_file_t *sf, const gchar *filename)
{
	gchar *name;
  
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
   	g_assert(!sf->name_nfc);
   	g_assert(!sf->name_canonic);
	
	name = filename_to_utf8_normalized(filename, UNI_NORM_NETWORK);
	sf->name_nfc = atom_str_get(name);
	if (name != filename) {
		G_FREE_NULL(name);
	}
	name = UNICODE_CANONIZE(sf->name_nfc);
	sf->name_canonic = atom_str_get(name);
	if (name != sf->name_nfc) {
		G_FREE_NULL(name);
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

#define FILENAME_CLASH 0xffffffff			/**< Indicates basename clashes */

/* ----------------------------------------- */

/**
 * Initialize special file entry, returning shared_file_t structure if
 * the file exists, NULL otherwise.
 */
static shared_file_t *
share_special_load(struct special_file *sp)
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
	{
		gchar *filename = make_pathname(fp[idx].dir, fp[idx].name);
		sf->file_path = atom_str_get(filename);
		G_FREE_NULL(filename);
	}
	if (shared_file_set_names(sf, sp->file)) {
		shared_file_free(&sf);
		return NULL;
	}
	sf->content_type = share_mime_type(sp->type);

	fclose(f);

	return sf;
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
				deconstify_gchar(specials[i].path), sf);
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

static void
query_muid_map_init(void)
{
	muid_to_query_map = g_hash_table_new(NULL, NULL);
	query_muids = hash_list_new(guid_hash, guid_eq);
}

static gboolean
query_muid_map_remove_oldest(void)
{
	gchar *old_muid;

	old_muid = hash_list_first(query_muids);
	if (old_muid) {
		gchar *old_query;
		
		hash_list_remove(query_muids, old_muid);

		old_query = g_hash_table_lookup(muid_to_query_map, old_muid);
		g_hash_table_remove(muid_to_query_map, old_muid);

		atom_guid_free_null(&old_muid);
		atom_str_free_null(&old_query);
		return TRUE;
	} else {
		return FALSE;
	}
}

static void
query_muid_map_close(void)
{
	while (query_muid_map_remove_oldest())
		continue;

	g_hash_table_destroy(muid_to_query_map);
	muid_to_query_map = NULL;
	hash_list_free(query_muids);
	query_muids = NULL;
}

static void
query_muid_map_garbage_collect(void)
{
	guint removed = 0;
	
	while (hash_list_length(query_muids) > search_muid_track_amount) {

		if (!query_muid_map_remove_oldest())
			break;
		/* If search_muid_track_amount was lowered drastically, there might
		 * be thousands of items to remove. If there are too much to be
		 * removed, we abort and come back later to prevent stalling.
		 */
		if (++removed > 100)
			break;
	}
}

static void
record_query_string(const gchar muid[GUID_RAW_SIZE], const gchar *query)
{
	gpointer key;
	
	g_assert(muid);
	g_assert(query);

	if (search_muid_track_amount > 0) {
		if (hash_list_contains(query_muids, muid, &key)) {
			gchar *old_query;

			/* We'll append the new value to the list */
			hash_list_remove(query_muids, deconstify_gpointer(muid));
			old_query = g_hash_table_lookup(muid_to_query_map, key);
			atom_str_free_null(&old_query);
			g_hash_table_remove(muid_to_query_map, old_query);
		} else {
			key = atom_guid_get(muid);
		}

		g_hash_table_insert(muid_to_query_map, key, atom_str_get(query));
		hash_list_append(query_muids, key);
	}
	query_muid_map_garbage_collect();
}

const gchar *
map_muid_to_query_string(const gchar muid[GUID_RAW_SIZE])
{
	gpointer key;
	
	if (hash_list_contains(query_muids, muid, &key)) {
		return g_hash_table_lookup(muid_to_query_map, key);
	}
	return NULL;
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

	query_muid_map_init();	
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
	guint idx;

	if (file_table == NULL)
		return SHARE_REBUILDING;

	g_assert(file_basenames);
	idx = shared_file_get_index(filename);
	return idx == 0 ? NULL : file_table[idx - 1];
}

/**
 * Returns the MIME content type string.
 */
const gchar *
share_mime_type(enum share_mime_type type)
{
	switch (type) {
	case SHARE_M_APPLICATION_BINARY:	return "application/binary";
	case SHARE_M_IMAGE_PNG:				return "image/png";
	case SHARE_M_TEXT_PLAIN:			return "text/plain";
	}

	g_error("unknown MIME type %d", (gint) type);
	return NULL;
}

/* ----------------------------------------- */

/**
 * Free existing extensions
 */
static void
free_extensions(void)
{
	GSList *sl = extensions;

	if (!sl)
		return;

	for ( /*empty */ ; sl; sl = g_slist_next(sl)) {
		struct extension *e = (struct extension *) sl->data;
		atom_str_free(e->str);
		g_free(e);
	}
	g_slist_free(extensions);
	extensions = NULL;
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

			if (*s) {
				struct extension *e = g_malloc(sizeof *e);
				e->str = atom_str_get(s);
				e->len = strlen(e->str);
				extensions = g_slist_prepend(extensions, e);
			}
		}
	}

	extensions = g_slist_reverse(extensions);
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
	guint i = 0;
    gboolean ret = TRUE;

	shared_dirs_free();

	while (dirs[i]) {
		if (is_directory(dirs[i]))
			shared_dirs = g_slist_prepend(shared_dirs, atom_str_get(dirs[i]));
        else
            ret = FALSE;
		i++;
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
        shared_dirs = g_slist_append(shared_dirs, atom_str_get(path));

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
 * no reference left.
 */
void
shared_file_unref(shared_file_t *sf)
{
	g_assert(sf->refcnt > 0);

	if (--sf->refcnt == 0)
		shared_file_free(&sf);
}

static inline gint
off_t_cmp(off_t a, off_t b)
{
	return CMP(a, b);	
}

/**
 * Is file too big to be shared on Gnutella?
 */
static inline gboolean
too_big_for_gnutella(gint size)
{
	g_return_val_if_fail(size >= 0, TRUE);
	return size > MAX_INT_VAL(gint32) &&
		off_t_cmp(size, MAX_INT_VAL(gint64)) > 0;
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
 * The directories that are given as shared will be completly transversed
 * including all files and directories. An entry of "/" would search the
 * the whole file system.
 */
static void
recurse_scan(const gchar *dir, const gchar *basedir)
{
	GSList *exts = NULL;
	DIR *directory;			/* Dir stream used by opendir, readdir etc.. */
	struct dirent *dir_entry;
	GSList *files = NULL;
	GSList *directories = NULL;
	GSList *sl;
	guint i;
	struct stat file_stat;
	const gchar *entry_end;

	if (*dir == '\0')
		return;

	if (!(directory = opendir(dir))) {
		g_warning("can't open directory %s: %s", dir, g_strerror(errno));
		return;
	}

	while ((dir_entry = readdir(directory))) {
		gchar *full;

		if (dir_entry->d_name[0] == '.')	/* Hidden file, or "." or ".." */
			continue;

		full = make_pathname(dir, dir_entry->d_name);

		if (is_directory(full)) {
			if (scan_ignore_symlink_dirs && is_symlink(full)) {
				G_FREE_NULL(full);
				continue;
			}
			directories = g_slist_prepend(directories, full);
		} else {
			if (scan_ignore_symlink_regfiles && is_symlink(full)) {
				G_FREE_NULL(full);
				continue;
			}
			files = g_slist_prepend(files, full);
		}
	}

	for (i = 0, sl = files; sl; i++, sl = g_slist_next(sl)) {
		const gchar *full, *name;

		full = sl->data;

		/*
		 * In the "tmp" directory, don't share files that have a trailer.
		 * It's probably a file being downloaded, and which is not complete yet.
		 * This check is necessary in case they choose to share their
		 * downloading directory...
		 */

		name = strrchr(full, G_DIR_SEPARATOR);
		g_assert(name && G_DIR_SEPARATOR == name[0]);
		name++;						/* Start of file name */

		entry_end = strchr(name, '\0');

		for (exts = extensions; exts; exts = exts->next) {
			struct extension *e = exts->data;
			const gchar *start = entry_end - (e->len + 1);	/* +1 for "." */

			/*
			 * Look for the trailing chars (we're matching an extension).
			 * Matching is case-insensitive, and the extension opener is ".".
			 *
			 * An extension "--all--" matches all files, even if they
			 * don't have any extension. [Patch from Zygo Blaxell].
			 */

			if (
				0 == ascii_strcasecmp("--all--", e->str) ||	/* All files */
				(start >= name && *start == '.' &&
					0 == ascii_strcasecmp(start + 1, e->str))
			) {
				struct shared_file *found = NULL;

				if (share_debug > 5)
					g_message("recurse_scan: full=\"%s\"", full);

				if (contains_control_chars(full)) {
					g_warning("Not sharing filename with control characters: "
						"\"%s\"", full);
					break;
				}

				if (stat(full, &file_stat) == -1) {
					g_warning("can't stat %s: %s", full, g_strerror(errno));
					break;
				}

				if (0 == file_stat.st_size) {
					if (share_debug > 5)
						g_warning("Not sharing empty file: \"%s\"", full);
					break;
				}

				if (!S_ISREG(file_stat.st_mode)) {
					g_warning("Not sharing non-regular file: \"%s\"", full);
					break;
				}

				if (too_big_for_gnutella(file_stat.st_size)) {
					g_warning("File is too big to be shared: \"%s\"", full);
					break;
				}

				found = shared_file_alloc();
				found->file_path = atom_str_get(full);
				found->file_size = file_stat.st_size;
				found->mtime = file_stat.st_mtime;
				found->content_type =
					share_mime_type(SHARE_M_APPLICATION_BINARY);

				if (shared_file_set_names(found, name)) {
					shared_file_free(&found);
					break;
				}

				if (!sha1_is_cached(found) && file_info_has_trailer(full)) {
					/*
	 		 	 	 * It's probably a file being downloaded, and which is
					 * not complete yet. This check is necessary in case
					 * they choose to share their downloading directory...
	 		  	 	 */

					g_warning("will not share partial file \"%s\"", full);
					shared_file_free(&found);
					break;
				}

				found->file_index = ++files_scanned;

				if (request_sha1(found)) {
					st_insert_item(search_table, found->name_canonic, found);

					shared_files = g_slist_prepend(shared_files,
							shared_file_ref(found));

					bytes_scanned += file_stat.st_size;
					kbytes_scanned += bytes_scanned >> 10;
					bytes_scanned &= (1 << 10) - 1;
				} else {
					found = NULL;
				}
				break;			/* for loop */
			}
		}
		G_FREE_NULL(sl->data);

		if (!(i & 0x3f)) {
			gcu_gui_update_files_scanned();	/* Interim view */
			gcu_gtk_main_flush();
		}
	}

	closedir(directory);
	directory = NULL;
	g_slist_free(files);
	files = NULL;

	/*
	 * Now that we handled files at this level and freed all their memory,
	 * recurse on directories.
	 */

	for (sl = directories; sl; sl = g_slist_next(sl)) {
		gchar *path = sl->data;
		recurse_scan(path, basedir);
		G_FREE_NULL(path);
	}
	g_slist_free(directories);

	gcu_gui_update_files_scanned();		/* Interim view */
	gcu_gtk_main_flush();
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

	G_FREE_NULL(file_table);

	for (sl = shared_files; sl; sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;
		shared_file_unref(sf);
	}

	g_slist_free(shared_files);
	shared_files = NULL;
}

static void reinit_sha1_table(void);

/**
 * Perform scanning of the shared directories to build up the list of
 * shared files.
 */
void
share_scan(void)
{
	GSList *dirs;
	GSList *sl;
	gint i;
	static gboolean in_share_scan = FALSE;
	time_t now, started;
	glong elapsed;

	/*
	 * We normally disable the "Rescan" button, so we should not enter here
	 * twice.  Nonetheless, the events can be stacked, and since we call
	 * the main loop whilst scanning, we could re-enter here.
	 *
	 *		--RAM, 05/06/2002 (added after the above indeed happened)
	 */

	if (in_share_scan)
		return;
	else
		in_share_scan = TRUE;

	started = now = tm_time();

	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, TRUE);
	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_STARTED, now);

	files_scanned = 0;
	bytes_scanned = 0;
	kbytes_scanned = 0;

	reinit_sha1_table();
	share_free();

	g_assert(file_basenames == NULL);

	g_assert(search_table);
	st_create(search_table);
	file_basenames = g_hash_table_new(g_str_hash, g_str_equal);

	/*
	 * Clone the `shared_dirs' list so that we don't behave strangely
	 * should they update the list of shared directories in the GUI
	 * whilst we're recursing!
	 *		--RAM, 30/01/2003
	 */

	for (dirs = NULL, sl = shared_dirs; sl; sl = g_slist_next(sl))
		dirs = g_slist_prepend(dirs, atom_str_get(sl->data));

	dirs = g_slist_reverse(dirs);

	/* Recurse on the cloned list... */
	for (sl = dirs; sl; sl = g_slist_next(sl))
		recurse_scan(sl->data, sl->data);	/* ...since this updates the GUI! */

	for (sl = dirs; sl; sl = g_slist_next(sl))
		atom_str_free(sl->data);

	g_slist_free(dirs);
	dirs = NULL;

	/*
	 * Done scanning all the files.
	 */

	st_compact(search_table);

	/*
	 * In order to quickly locate files based on indicies, build a table
	 * of all shared files.  This table is only accessible via shared_file().
	 * NB: file indicies start at 1, but indexing in table start at 0.
	 *		--RAM, 08/10/2001
	 *
	 * We over-allocate the file_table by one entry so that even when they
	 * don't share anything, the `file_table' pointer is not NULL.
	 * This will prevent us giving back "rebuilding library" when we should
	 * actually return "not found" for user download requests.
	 *		--RAM, 23/10/2002
	 */

	file_table = g_malloc0((files_scanned + 1) * sizeof *file_table);

	for (i = 0, sl = shared_files; sl; i++, sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;
		guint val;

		g_assert(sf->file_index > 0 && sf->file_index <= files_scanned);
		file_table[sf->file_index - 1] = sf;

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

		if (0 == (i & 0x7ff))
			gcu_gtk_main_flush();
	}

	gcu_gui_update_files_scanned();		/* Final view */

	now = tm_time();
	elapsed = delta_time(now, started);
	elapsed = MAX(0, elapsed);
	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_FINISHED, now);
	gnet_prop_set_guint32_val(PROP_LIBRARY_RESCAN_DURATION, elapsed);

	/*
	 * Query routing table update.
	 */

	started = now;
	gnet_prop_set_timestamp_val(PROP_QRP_INDEXING_STARTED, now);

	qrp_prepare_computation();

	for (i = 0, sl = shared_files; sl; i++, sl = g_slist_next(sl)) {
		struct shared_file *sf = sl->data;
		qrp_add_file(sf);
		if (0 == (i & 0x7ff))
			gcu_gtk_main_flush();
	}

	qrp_finalize_computation();

	now = tm_time();
	elapsed = delta_time(now, started);
	elapsed = MAX(0, elapsed);
	gnet_prop_set_guint32_val(PROP_QRP_INDEXING_DURATION, elapsed);

	in_share_scan = FALSE;
	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, FALSE);
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

	shared_file_free(&sf);
}

/**
 * Get rid of the special file descriptions, if any.
 */
static void
share_special_close(void)
{
	g_hash_table_foreach(special_names, special_free_kv, NULL);
	g_hash_table_destroy(special_names);
}

/**
 * Shutdown cleanup.
 */
void
share_close(void)
{
	query_muid_map_close();
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

#define MIN_WORD_LENGTH 1		/**< For compaction */

/**
 * Remove unnecessary ballast from a query before processing it. Works in
 * place on the given string. Removed are all consecutive blocks of
 * whitespace and all words shorter then MIN_WORD_LENGTH.
 *
 * @param search	the search string to compact, modified in place.
 * @return			the length in bytes of the compacted search string.
 */
static size_t
compact_query_utf8(gchar *search)
{
	gchar *s;
	gchar *word = NULL, *p;
	size_t word_length = 0;	/* length in bytes, not characters */

#define APPEND_WORD()								\
do {												\
	/* Append a space unless it's the first word */	\
	if (p != search) {								\
		if (*p != ' ')								\
			*p = ' ';								\
		p++;										\
	}												\
	if (p != word)									\
		memmove(p, word, word_length);				\
	p += word_length;								\
} while (0)

	if (share_debug > 4)
		g_message("original: [%s]", search);

	word = is_ascii_blank(*search) ? NULL : search;
	p = s = search;
	while ('\0' != *s) {
		guint clen;

		clen = utf8_char_len(s);
		clen = MAX(1, clen);	/* In case of invalid UTF-8 */

		if (is_ascii_blank(*s)) {
			if (word_length >= MIN_WORD_LENGTH) {
				APPEND_WORD();
			}
			word_length = 0;

			s = skip_ascii_blanks(s);
			if ('\0' == *s) {
				word = NULL;
				break;
			}
			word = s;
		} else {
			word_length += clen;
			s += clen;
		}
	}

	if (word_length >= MIN_WORD_LENGTH) {
		APPEND_WORD();
	}

	if ('\0' != *p)
		*p = '\0'; /* terminate mangled query */

	if (share_debug > 4)
		g_message("mangled: [%s]", search);

	/* search does no longer contain unnecessary whitespace */
	return p - search;
}

/**
 * Determine whether the given string is UTF-8 encoded.
 * If query starts with a BOM mark, skip it and set `retoff' accordingly.
 *
 * @returns TRUE if the string is valid UTF-8, FALSE otherwise.
 */
static gboolean 
query_utf8_decode(const gchar *text, guint *retoff)
{
	const gchar *p;

	/*
	 * Look whether we're facing an UTF-8 query.
	 *
	 * If it starts with the sequence EF BB BF (BOM in UTF-8), then
	 * it is clearly UTF-8.  If we can't decode it, it is bad UTF-8.
	 */

	if (!(p = is_strprefix(text, "\xef\xbb\xbf")))
		p = text;
	
	if (retoff)
		*retoff = p - text;

	/* Disallow BOM followed by an empty string */	
	return (p == text || '\0' != p[0]) && utf8_is_valid_string(p);
}

/**
 * Remove unnecessary ballast from a query string, in-place.
 *
 * @returns new query string length.
 */
size_t
compact_query(gchar *search)
{
	size_t mangled_search_len, orig_len = strlen(search);
	guint offset;			/* Query string start offset */

	/*
	 * Look whether we're facing an UTF-8 query.
	 */

	if (!query_utf8_decode(search, &offset))
		g_error("found invalid UTF-8 after a leading BOM");

	/*
	 * Compact the query, offsetting from the start as needed in case
	 * there is a leading BOM (our UTF-8 decoder does not allow BOM
	 * within the UTF-8 string, and rightly I think: that would be pure
	 * gratuitous bloat).
	 */

	mangled_search_len = compact_query_utf8(&search[offset]);

	g_assert(mangled_search_len <= (size_t) orig_len - offset);

	/*
	 * Get rid of BOM, if any.
	 */

	if (offset > 0)
		memmove(search, &search[offset], mangled_search_len);

	return mangled_search_len;
}

/**
 * Remove the OOB delivery flag by patching the query message inplace.
 */
void
query_strip_oob_flag(const gnutella_node_t *n, gchar *data)
{
	guint16 speed;

	speed = peek_le16(data) & ~QUERY_SPEED_OOB_REPLY;
	poke_le16(data, speed);

	gnet_stats_count_general(GNR_OOB_QUERIES_STRIPPED, 1);

	if (query_debug > 2 || oob_proxy_debug > 2)
		g_message(
			"QUERY %s from node %s <%s>: removed OOB delivery (speed = 0x%x)",
			guid_hex_str(n->header.muid), node_addr(n), node_vendor(n), speed);
}

/**
 * Set the OOB delivery flag by patching the query message inplace.
 */
void
query_set_oob_flag(const gnutella_node_t *n, gchar *data)
{
	guint16 speed;

	speed = peek_le16(data) | QUERY_SPEED_OOB_REPLY | QUERY_SPEED_MARK;
	poke_le16(data, speed);

	if (query_debug)
		g_message(
			"QUERY %s from node %s <%s>: set OOB delivery (speed = 0x%x)",
			guid_hex_str(n->header.muid), node_addr(n), node_vendor(n), speed);
}

/**
 * Searches requests (from others nodes)
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the LL.
 *
 * If `qhv' is not NULL, it is filled with hashes of URN or query words,
 * so that we may later properly route the query among the leaf nodes.
 *
 * @returns TRUE if the message should be dropped and not propagated further.
 */
gboolean
search_request(struct gnutella_node *n, query_hashvec_t *qhv)
{
	static const gchar qtrax2_con[] = "QTRAX2_CONNECTION";
	static gchar stmp_1[4096];
	guint16 req_speed;
	gchar *search;
	size_t search_len, max_len;
	gboolean decoded = FALSE;
	guint32 max_replies;
	gboolean skip_file_search = FALSE;
	extvec_t exv[MAX_EXTVEC];
	gint exvcnt = 0;
	struct {
		gchar sha1_digest[SHA1_RAW_SIZE];
		gboolean matched;
	} exv_sha1[MAX_EXTVEC];
	gchar *last_sha1_digest = NULL;
	gint exv_sha1cnt = 0;
	guint offset = 0;			/**< Query string start offset */
	gboolean drop_it = FALSE;
	gboolean oob = FALSE;		/**< Wants out-of-band query hit delivery? */
	gboolean use_ggep_h = FALSE;
	struct query_context *qctx;
	gboolean tagged_speed = FALSE;
	gboolean should_oob = FALSE;
	gchar muid[GUID_RAW_SIZE];

	/*
	 * Make sure search request is NUL terminated... --RAM, 06/10/2001
	 *
	 * We can't simply check the last byte, because there can be extensions
	 * at the end of the query after the first NUL.  So we need to scan the
	 * string.  Note that we use this scanning opportunity to also compute
	 * the search string length.
	 *		--RAN, 21/12/2001
	 */

	search = n->data + 2;
	max_len = n->size > 2 ? (n->size - 3) : 0; /* Payload size - Speed - NUL */
	search_len = str_len_capped(search, max_len + 1);
	
	if (search_len > max_len) {
		g_assert(n->data[n->size - 1] != '\0');
		if (share_debug)
			g_warning("query (hops=%d, ttl=%d) had no NUL (%d byte%s)",
					n->header.hops, n->header.ttl, n->size - 2,
					n->size == 3 ? "" : "s");
		if (share_debug > 4)
			dump_hex(stderr, "Query Text", search, MIN(n->size - 2, 256));

		gnet_stats_count_dropped(n, MSG_DROP_QUERY_NO_NUL);
		return TRUE;		/* Drop the message! */
	}
	/* We can now use `search' safely as a C string: it embeds a NUL */

	/*
	 * Drop the "QTRAX2_CONNECTION" queries as being "overhead".
	 */
	if (
		search_len >= CONST_STRLEN(qtrax2_con) &&
		is_strprefix(search, qtrax2_con)
	) {
		gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
		return TRUE;		/* Drop the message! */
	}

	/*
	 * Compact query, if requested and we're going to relay that message.
	 */

	if (
		gnet_compact_query &&
		n->header.ttl &&
		current_peermode != NODE_P_LEAF
	) {
		size_t mangled_search_len;

		/*
		 * Look whether we're facing an UTF-8 query.
		 */

		if (!query_utf8_decode(search, &offset)) {
			gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
			return TRUE;					/* Drop message! */
		}
		decoded = TRUE;

		if (!is_ascii_string(search))
			gnet_stats_count_general(GNR_QUERY_UTF8, 1);

		/*
		 * Compact the query, offsetting from the start as needed in case
		 * there is a leading BOM (our UTF-8 decoder does not allow BOM
		 * within the UTF-8 string, and rightly I think: that would be pure
		 * gratuitous bloat).
		 */

		mangled_search_len = compact_query_utf8(&search[offset]);

		g_assert(mangled_search_len <= search_len - offset);

		if (mangled_search_len != search_len - offset) {
			gnet_stats_count_general(GNR_QUERY_COMPACT_COUNT, 1);
			gnet_stats_count_general(GNR_QUERY_COMPACT_SIZE,
				search_len - offset - mangled_search_len);
		}

		/*
		 * Need to move the trailing data forward and adjust the
		 * size of the packet.
		 */

		g_memmove(
			&search[offset + mangled_search_len], /* new end of query string */
			&search[search_len],                  /* old end of query string */
			n->size - (search - n->data) - search_len); /* trailer len */

		n->size -= search_len - offset - mangled_search_len;
		WRITE_GUINT32_LE(n->size, n->header.size);
		search_len = mangled_search_len + offset;

		g_assert('\0' == search[search_len]);
	}

	/*
	 * If there are extra data after the first NUL, fill the extension vector.
	 */

	if (search_len + 3 != n->size) {
		gint extra = n->size - 3 - search_len;		/* Amount of extra data */
		gint i;

		ext_prepare(exv, MAX_EXTVEC);
		exvcnt = ext_parse(search + search_len + 1, extra, exv, MAX_EXTVEC);

		if (exvcnt == MAX_EXTVEC) {
			g_warning("%s has %d extensions!",
				gmsg_infostr(&n->header), exvcnt);
			if (share_debug)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (share_debug > 1)
				dump_hex(stderr, "Query", search, n->size - 2);
		}

		if (exvcnt && share_debug > 3) {
			g_message("query with extensions: %s\n", search);
			ext_dump(stderr, exv, exvcnt, "> ", "\n", share_debug > 4);
		}

		/*
		 * If there is a SHA1 URN, validate it and extract the binary digest
		 * into sha1_digest[], and set `sha1_query' to the base32 value.
		 */

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];

			if (e->ext_token == EXT_T_OVERHEAD) {
				if (share_debug > 6)
					dump_hex(stderr, "Query Packet (BAD: has overhead)",
						search, MIN(n->size - 2, 256));
				gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
				ext_reset(exv, MAX_EXTVEC);
				return TRUE;			/* Drop message! */
			}

			if (e->ext_token == EXT_T_URN_SHA1) {
				gchar *sha1_digest = exv_sha1[exv_sha1cnt].sha1_digest;
				gint paylen = ext_paylen(e);

				if (paylen == 0)
					continue;				/* A simple "urn:sha1:" */

				if (
					!huge_sha1_extract32(ext_payload(e), paylen,
						sha1_digest, &n->header, FALSE)
                ) {
                    gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1);
					ext_reset(exv, MAX_EXTVEC);
					return TRUE;			/* Drop message! */
                }

				exv_sha1[exv_sha1cnt].matched = FALSE;
				exv_sha1cnt++;

				if (share_debug > 4)
					g_message("valid SHA1 #%d in query: %32s",
						exv_sha1cnt, ext_payload(e));

				/*
				 * Add valid URN query to the list of query hashes, if we
				 * are to fill any for query routing.
				 */

				if (qhv != NULL) {
					gm_snprintf(stmp_1, sizeof(stmp_1),
						"urn:sha1:%s", sha1_base32(sha1_digest));
					qhvec_add(qhv, stmp_1, QUERY_H_URN);
				}

				last_sha1_digest = sha1_digest;
			}
		}

		if (exv_sha1cnt)
			gnet_stats_count_general(GNR_QUERY_SHA1, 1);

		if (exvcnt)
			ext_reset(exv, MAX_EXTVEC);
	}

    /*
     * Reorderd the checks: if we drop the packet, we won't notify any
     * listeners. We first check whether we want to drop the packet and
     * later decide whether we are eligible for answering the query:
     * 1) try top drop
     * 2) notify listeners
     * 3) bail out if not eligible for a local search
     * 4) local search
     *      --Richard, 11/09/2002
     */

	/*
	 * When an URN search is present, there can be an empty search string.
	 *
	 * If requester if farther than half our TTL hops. save bandwidth when
	 * returning lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 */

	if (
		search_len <= 1 ||
		(search_len < 5 && n->header.hops > (max_ttl / 2))
	)
		skip_file_search = TRUE;

    if (0 == exv_sha1cnt && skip_file_search) {
        gnet_stats_count_dropped(n, MSG_DROP_QUERY_TOO_SHORT);
		return TRUE;					/* Drop this search message */
    }

	/*
	 * When we are not a leaf node, we do two sanity checks here:
	 *
	 * 1. We keep track of all the queries sent by the node (hops = 1)
	 *    and the time by which we saw them.  If they are sent too often,
	 *    just drop the duplicates.  Since an Ultranode will send queries
	 *    from its leaves with an adjusted hop, we only do that for leaf
	 *    nodes.
	 *
	 * 2. We keep track of all queries relayed by the node (hops >= 1)
	 *    by hops and by search text for a limited period of time.
	 *    The purpose is to sanitize the traffic if the node did not do
	 *    point #1 above for its own neighbours.  Naturally, we expire
	 *    this data more quickly.
	 *
	 * When there is a SHA1 in the query, it is the SHA1 itself that is
	 * being remembered.
	 *
	 *		--RAM, 09/12/2003
	 */

	if (n->header.hops == 1 && n->qseen != NULL) {
		time_t now = tm_time();
		time_t seen = 0;
		gboolean found;
		gpointer atom;
		gpointer seenp;
		gchar *query = search;
		time_delta_t threshold = node_requery_threshold;

		g_assert(NODE_IS_LEAF(n));

		if (last_sha1_digest != NULL) {
			gm_snprintf(stmp_1, sizeof(stmp_1),
				"urn:sha1:%s", sha1_base32(last_sha1_digest));
			query = stmp_1;
		}

		found = g_hash_table_lookup_extended(n->qseen, query, &atom, &seenp);
		if (found)
			seen = (time_t) GPOINTER_TO_INT(seenp);

		if (delta_time(now, (time_t) 0) - seen < threshold) {
			if (share_debug) g_warning(
				"node %s (%s) re-queried \"%s\" after %d secs",
				node_addr(n), node_vendor(n), query, (gint) (now - seen));
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			return TRUE;		/* Drop the message! */
		}

		if (!found)
			atom = atom_str_get(query);

		g_hash_table_insert(n->qseen, atom,
			GINT_TO_POINTER((gint) delta_time(now, (time_t) 0)));
	}
	record_query_string(n->header.muid, search);

	/*
	 * For point #2, there are two tables to consider: `qrelayed_old' and
	 * `qrelayed'.  Presence in any of the tables is sufficient, but we
	 * only insert in the "new" table `qrelayed'.
	 */

	if (n->qrelayed != NULL) {					/* Check #2 */
		gpointer found = NULL;

		g_assert(!NODE_IS_LEAF(n));

		/*
		 * Consider both hops and TTL for dynamic querying, whereby the
		 * same query can be repeated with an increased TTL.
		 */

		if (last_sha1_digest == NULL)
			gm_snprintf(stmp_1, sizeof(stmp_1),
				"%d/%d%s", n->header.hops, n->header.ttl, search);
		else
			gm_snprintf(stmp_1, sizeof(stmp_1),
				"%d/%durn:sha1:%s", n->header.hops, n->header.ttl,
				sha1_base32(last_sha1_digest));

		if (n->qrelayed_old != NULL)
			found = g_hash_table_lookup(n->qrelayed_old, stmp_1);

		if (found == NULL)
			found = g_hash_table_lookup(n->qrelayed, stmp_1);

		if (found != NULL) {
			if (share_debug) g_warning(
				"dropping query \"%s%s\" (hops=%d, TTL=%d) "
				"already seen recently from %s (%s)",
				last_sha1_digest == NULL ? "" : "urn:sha1:",
				last_sha1_digest == NULL ?
					search : sha1_base32(last_sha1_digest),
				n->header.hops, n->header.ttl,
				node_addr(n), node_vendor(n));
			gnet_stats_count_dropped(n, MSG_DROP_THROTTLE);
			return TRUE;		/* Drop the message! */
		}

		g_hash_table_insert(n->qrelayed,
			atom_str_get(stmp_1), GINT_TO_POINTER(1));
	}

    /*
     * Push the query string to interested ones (GUI tracing).
     */

    if (
		(search[0] == '\0' || (search[0] == '\\' && search[1] == '\0'))
		&& exv_sha1cnt
    ) {
		gint i;
		for (i = 0; i < exv_sha1cnt; i++)
			share_emit_search_request(QUERY_SHA1,
				sha1_base32(exv_sha1[i].sha1_digest), n->addr, n->port);
	} else
		share_emit_search_request(QUERY_STRING, search, n->addr, n->port);

	/*
	 * Special processing for the "connection speed" field of queries.
	 *
	 * Unless bit 15 is set, process as a speed.
	 * Otherwise if bit 15 is set:
	 *
	 * 1. If the firewall bit (bit 14) is set, the remote servent is firewalled.
	 *    Therefore, if we are also firewalled, don't reply.
	 *
	 * 2. If the XML bit (bit 13) is cleared and we support XML meta data, don't
	 *    include them in the result set [GTKG does not support XML meta data]
	 *
	 *		--RAM, 19/01/2003, updated 06/07/2003 (bit 14-13 instead of 8-9)
	 *
	 * 3. If the GGEP "H" bit (bit 11) is set, the issuer of the query will
	 *    understand the "H" extension in query hits.
	 *		--RAM, 16/07/2003
	 *
	 * Starting today (06/07/2003), we ignore the connection speed overall
	 * if it's not marked with the QUERY_SPEED_MARK flag to indicate new
	 * interpretation. --RAM
	 */

	READ_GUINT16_LE(n->data, req_speed);

	tagged_speed = (req_speed & QUERY_SPEED_MARK) ? TRUE : FALSE;
	oob = tagged_speed && (req_speed & QUERY_SPEED_OOB_REPLY);
	use_ggep_h = tagged_speed && (req_speed & QUERY_SPEED_GGEP_H);

	/*
	 * If query comes from GTKG 0.91 or later, it understands GGEP "H".
	 * Otherwise, it's an old servent or one unwilling to support this new
	 * extension, so it will get its SHA1 URNs in ASCII form.
	 *		--RAM, 17/11/2002
	 */

	{
		guint8 major, minor;
		gboolean release;

		if (
			guid_query_muid_is_gtkg(n->header.muid, oob,
				&major, &minor, &release)
		) {
			gboolean requery = guid_is_requery(n->header.muid);

			/* Only supersede `use_ggep_h' if not indicated in "min speed" */
			if (!use_ggep_h)
				use_ggep_h =
					major >= 1 || minor > 91 || (minor == 91 && release);

			gnet_stats_count_general(GNR_GTKG_TOTAL_QUERIES, 1);
			if (requery)
				gnet_stats_count_general(GNR_GTKG_REQUERIES, 1);

			if (query_debug > 3)
				g_message("GTKG %s%squery from %d.%d%s",
					oob ? "OOB " : "", requery ? "re-" : "",
					major, minor, release ? "" : "u");
		}
	}

	if (use_ggep_h)
		gnet_stats_count_general(GNR_QUERIES_WITH_GGEP_H, 1);

	/*
	 * If OOB reply is wanted, validate a few things.
	 *
	 * We may either drop the query, or reset the OOB flag if it's
	 * obviously misconfigured.  Then we can re-enable the OOB flag
	 * if we're allowed to perform OOB-proxying for leaf queries.
	 */

	if (oob) {
		host_addr_t addr;
		guint16 port;

		guid_oob_get_addr_port(n->header.muid, &addr, &port);

		/*
		 * Verify against the hostile IP addresses...
		 */

		if (hostiles_check(addr)) {
			gnet_stats_count_dropped(n, MSG_DROP_HOSTILE_IP);
			return TRUE;		/* Drop the message! */
		}

		/*
		 * If it's a neighbouring query, make sure the IP for results
		 * matches what we know about the listening IP for the node.
		 * The UDP port can be different from the TCP port, so we can't
		 * check that.
		 */

		if (
			n->header.hops == 1 &&
			is_host_addr(n->gnet_addr) &&
			!host_addr_equal(addr, n->gnet_addr)
		) {
			gnet_stats_count_dropped(n, MSG_DROP_BAD_RETURN_ADDRESS);

			if (query_debug || oob_proxy_debug)
				g_message("QUERY dropped from node %s <%s>: invalid OOB flag "
					"(return address mismatch: %s, node: %s)",
					node_addr(n), node_vendor(n),
					host_addr_port_to_string(addr, port), node_gnet_addr(n));

			return TRUE;		/* Drop the message! */
		}

		/*
		 * If the query contains an invalid IP:port, clear the OOB flag.
		 */

		if (!host_is_valid(addr, port)) {
			query_strip_oob_flag(n, n->data);
			oob = FALSE;

			if (query_debug || oob_proxy_debug)
				g_message("QUERY %s node %s <%s>: removed OOB flag "
					"(invalid return address: %s)",
					guid_hex_str(n->header.muid), node_addr(n), node_vendor(n),
					host_addr_port_to_string(addr, port));
		}

		/*
		 * If the query comes from a leaf node and has the "firewalled"
		 * bit set, chances are the leaf is UDP-firewalled as well.
		 * Clear the OOB flag.
		 */

		if (oob && NODE_IS_LEAF(n) && (req_speed & QUERY_SPEED_FIREWALLED)) {
			query_strip_oob_flag(n, n->data);
			oob = FALSE;

			if (query_debug || oob_proxy_debug)
				g_message("QUERY %s node %s <%s>: removed OOB flag "
					"(leaf node is TCP-firewalled)",
					guid_hex_str(n->header.muid), node_addr(n), node_vendor(n));
		}
	}

	/*
	 * If the query comes from a node farther than our TTL (i.e. the TTL we'll
	 * use to send our reply), don't bother processing it: the reply won't
	 * be able to reach the issuing node.
	 *
	 * However, note that for replies, we use our maximum configured TTL for
	 * relayed messages, so we compare to that, and not to my_ttl, which is
	 * the TTL used for "standard" packets.
	 *
	 *				--RAM, 12/09/2001
	 *
	 * Naturally, we don't do this check for OOB queries, since the reply
	 * won't be relayed but delivered directly via UDP.
	 *
	 *				--RAM, 2004-11-27
	 */

	should_oob = process_oob_queries && udp_active() &&
		recv_solicited_udp && n->header.hops > 1;

    if (n->header.hops > max_ttl && !(oob && should_oob)) {
        gnet_stats_count_dropped(n, MSG_DROP_MAX_TTL_EXCEEDED);
		return TRUE;					/* Drop this long-lived search */
    }

	/*
	 * If the query does not have an OOB mark, comes from a leaf node and
	 * they allow us to be an OOB-proxy, then replace the IP:port of the
	 * query with ours, so that we are the ones to get the UDP replies.
	 *
	 * Since calling oob_proxy_create() is going to mangle the query's
	 * MUID in place (alterting n->header.muid), we must save the MUID
	 * in case we have local hits to deliver: since we send those directly
	 *		--RAM, 2005-08-28
	 */

	memcpy(muid, n->header.muid, GUID_RAW_SIZE);

	if (
		!oob && udp_active() && proxy_oob_queries && !is_udp_firewalled &&
		NODE_IS_LEAF(n) && host_is_valid(listen_addr(), socket_listen_port())
	) {
		oob_proxy_create(n);
		oob = TRUE;
		gnet_stats_count_general(GNR_OOB_PROXIED_QUERIES, 1);
	}

	if (tagged_speed) {
		if ((req_speed & QUERY_SPEED_FIREWALLED) && is_firewalled)
			return FALSE;			/* Both servents are firewalled */
	}

	/*
	 * Perform search...
	 */

    gnet_stats_count_general(GNR_LOCAL_SEARCHES, 1);
	if (current_peermode == NODE_P_LEAF && node_ultra_received_qrp(n))
		node_inc_qrp_query(n);

	qctx = share_query_context_make();
	max_replies = (search_max_items == (guint32) -1) ? 255 : search_max_items;

	/*
	 * Search each SHA1.
	 */

	if (exv_sha1cnt) {
		gint i;

		for (i = 0; i < exv_sha1cnt && max_replies > 0; i++) {
			struct shared_file *sf;

			sf = shared_file_by_sha1(exv_sha1[i].sha1_digest);
			if (sf && sf != SHARE_REBUILDING && !shared_file_is_partial(sf)) {
				got_match(qctx, sf);
				max_replies--;
			}
		}
	}

	if (!skip_file_search) {

		/*
		 * Keep only UTF8 encoded queries (This includes ASCII)
		 */

		g_assert('\0' == search[search_len]);

		if (!decoded) {
		   	if (!query_utf8_decode(search, &offset)) {
				gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
				drop_it = TRUE;				/* Drop message! */
				goto finish;				/* Flush any SHA1 result we have */
			}
			decoded = TRUE;
		
			if (!is_ascii_string(search))
				gnet_stats_count_general(GNR_QUERY_UTF8, 1);
		}

		/*
		 * Because st_search() will apply a character map over the string,
		 * we always need to copy the query string to avoid changing the
		 * data inplace.
		 *
		 * `stmp_1' is a static buffer.  Note that we copy the trailing NUL
		 * into the buffer, hence the "+1" below.
		 */

		search_len -= offset;
		memcpy(stmp_1, &search[offset], search_len + 1);

		st_search(search_table, stmp_1, got_match, qctx, max_replies, qhv);
	}

finish:
	if (qctx->found > 0) {
        gnet_stats_count_general(GNR_LOCAL_HITS, qctx->found);
		if (current_peermode == NODE_P_LEAF && node_ultra_received_qrp(n))
			node_inc_qrp_match(n);

		if (share_debug > 3) {
			g_message("share HIT %u files '%s'%s ", qctx->found,
				search + offset,
				skip_file_search ? " (skipped)" : "");
			if (exv_sha1cnt) {
				gint i;
				for (i = 0; i < exv_sha1cnt; i++)
					g_message("\t%c(%32s)",
						exv_sha1[i].matched ? '+' : '-',
						sha1_base32(exv_sha1[i].sha1_digest));
			}
			g_message("\treq_speed=%u ttl=%d hops=%d", (guint) req_speed,
				(gint) n->header.ttl, (gint) n->header.hops);
		}
	}

	if (share_debug > 3)
		g_message("QUERY %s \"%s\" has %u hit%s",
			guid_hex_str(n->header.muid), search, qctx->found,
			qctx->found == 1 ? "" : "s");

	/*
	 * If we got a query marked for OOB results delivery, send them
	 * a reply out-of-band but only if the query's hops is > 1.  Otherwise,
	 * we have a direct link to the queryier.
	 */

	if (qctx->found) {
		if (oob && should_oob)
			oob_got_results(n, qctx->files, qctx->found, use_ggep_h);
		else
			qhit_send_results(n, qctx->files, qctx->found, muid, use_ggep_h);
	}

	share_query_context_free(qctx);

	return drop_it;
}

/*
 * SHA1 digest processing
 */

/**
 * This tree maps a SHA1 hash (base-32 encoded) onto the corresponding
 * shared_file if we have one.
 */

static GTree *sha1_to_share = NULL;

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

/**
 * Set the SHA1 hash of a given shared_file. Take care of updating the
 * sha1_to_share structure. This function is called from inside the bowels of
 * huge.c when it knows what the hash associated to a file is.
 */
void
shared_file_set_sha1(struct shared_file *sf, const char *sha1)
{
	g_assert(!shared_file_is_partial(sf));	/* Cannot be a partial file */

	/*
	 * If we were recomputing the SHA1, remove the old version.
	 */

	if (sf->flags & SHARE_F_RECOMPUTING) {
		sf->flags &= ~SHARE_F_RECOMPUTING;
		g_tree_remove(sha1_to_share, sf->sha1);
	}

	atom_sha1_free_null(&sf->sha1);
	sf->sha1 = atom_sha1_get(sha1);
	sf->flags |= SHARE_F_HAS_DIGEST;
	g_tree_insert(sha1_to_share, sf->sha1, sf);
}

void
shared_file_set_modification_time(struct shared_file *sf, time_t mtime)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
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
		g_tree_remove(sha1_to_share, sf->sha1);
		atom_sha1_free_null(&sf->sha1);
		sf->flags &= ~SHARE_F_HAS_DIGEST;
		return FALSE;
	}

	if (too_big_for_gnutella(buf.st_size)) {
		g_warning("File is too big to be shared: \"%s\"", sf->file_path);
		g_tree_remove(sha1_to_share, sf->sha1);
		atom_sha1_free_null(&sf->sha1);
		sf->flags &= ~SHARE_F_HAS_DIGEST;
		return FALSE;
	}

	/*
	 * If file was modified since the last time we computed the SHA1,
	 * recompute it and tell them that the SHA1 we have might not be
	 * accurate.
	 */

	if (
			sf->mtime != buf.st_mtime ||
			sf->file_size != (filesize_t) buf.st_size
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

gboolean
shared_file_is_partial(const struct shared_file *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return NULL != sf->fi;
}

filesize_t
shared_file_size(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->file_size;
}

guint32
shared_file_index(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->file_index;
}

const gchar *
shared_file_sha1(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->sha1;
}

const gchar *
shared_file_name_nfc(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->name_nfc;
}

const gchar *
shared_file_name_canonic(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->name_canonic;
}

size_t
shared_file_name_nfc_len(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->name_nfc_len;
}

size_t
shared_file_name_canonic_len(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->name_canonic_len;
}

const gchar *
shared_file_path(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->file_path;
}

time_t
shared_file_modification_time(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->mtime;
}

guint32
shared_file_flags(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->flags;
}

fileinfo_t *
shared_file_fileinfo(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->fi;
}

const gchar *
shared_file_content_type(const shared_file_t *sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	return sf->content_type;
}

void
shared_file_remove(struct shared_file *sf)
{
	const struct shared_file *sfc;
	
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);

	sfc = shared_file(sf->file_index);
	if (SHARE_REBUILDING != sfc) {
		g_assert(sfc == sf);
		file_table[sf->file_index - 1] = NULL;
	}
	g_hash_table_remove(file_basenames, sf->name_nfc);
	if (0 == sf->refcnt) {
		shared_file_free(&sf);
	}
}

void
shared_file_from_fileinfo(fileinfo_t *fi)
{
	shared_file_t *sf;

	file_info_check(fi);

	sf = shared_file_alloc();

	/*
	 * Determine a proper human-readable name for the file.
	 * If it is an URN, look through the aliases.
	 */

	if (shared_file_set_names(sf, file_info_readable_filename(fi))) {
		shared_file_free(&sf);
		return;
	}

	{
		gchar *path = make_pathname(fi->path, fi->file_name);
		sf->file_path = atom_str_get(path);
		G_FREE_NULL(path);
	}

	/* FIXME: DOWNLOAD_SIZE:
	 * Do we need to add anything here now that fileinfos can have an
	 *  unknown length? --- Emile
	 */
	sf->file_size = fi->size;
	sf->file_index = URN_INDEX;
	sf->mtime = fi->last_flush;
	sf->flags = SHARE_F_HAS_DIGEST;
	sf->content_type = share_mime_type(SHARE_M_APPLICATION_BINARY);
	sf->sha1 = atom_sha1_get(fi->sha1);
	sf->fi = fi;		/* Signals it's a partially downloaded file */

	fi->sf = shared_file_ref(sf);
}

/**
 * @returns the shared_file if we share a complete file bearing the given SHA1.
 * @returns NULL if we don't share a complete file, or SHARE_REBUILDING if the
 * set of shared file is being rebuilt.
 */
static struct shared_file *
shared_file_complete_by_sha1(const gchar *sha1_digest)
{
	struct shared_file *f;

	if (sha1_to_share == NULL)			/* Not even begun share_scan() yet */
		return SHARE_REBUILDING;

	f = g_tree_lookup(sha1_to_share, deconstify_gchar(sha1_digest));

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
shared_file_by_sha1(const gchar *sha1_digest)
{
	struct shared_file *f;

	f = shared_file_complete_by_sha1(sha1_digest);

	/*
	 * If we don't share this file, or if we're rebuilding, and provided
	 * PFSP-server is enabled, look whether we don't have a partially
	 * downloaded file with this SHA1.
	 */

	if ((f == NULL || f == SHARE_REBUILDING) && pfsp_server) {
		struct shared_file *pf = file_info_shared_sha1(sha1_digest);
		if (pf != NULL)
			f = pf;
	}

	return f;
}

/**
 * Get accessor for ``kbytes_scanned''
 */
guint64
shared_kbytes_scanned(void)
{
	return kbytes_scanned;
}

/**
 * Get accessor for ``files_scanned''
 */
guint64
shared_files_scanned(void)
{
	return files_scanned;
}

/* vi: set ts=4 sw=4 cindent: */
