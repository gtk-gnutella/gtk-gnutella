/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Handle sharing of our own files.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>		/* tolower() */

#include "share.h"
#include "gmsg.h"
#include "huge.h"
#include "gtk-missing.h" // FIXME: remove this dependency
#include "utf8.h"
#include "qrp.h"
#include "extensions.h"
#include "nodes.h"
#include "uploads.h"
#include "gnet_stats.h"
#include "settings.h"

#include "gnet_property.h"

#define QHIT_SIZE_THRESHOLD	2016	/* Flush query hits larger than this */

static guchar iso_8859_1[96] = {
	' ', 			/* 160 - NO-BREAK SPACE */
	' ', 			/* 161 - INVERTED EXCLAMATION MARK */
	' ', 			/* 162 - CENT SIGN */
	' ', 			/* 163 - POUND SIGN */
	' ', 			/* 164 - CURRENCY SIGN */
	' ', 			/* 165 - YEN SIGN */
	' ', 			/* 166 - BROKEN BAR */
	' ', 			/* 167 - SECTION SIGN */
	' ', 			/* 168 - DIAERESIS */
	' ', 			/* 169 - COPYRIGHT SIGN */
	' ', 			/* 170 - FEMININE ORDINAL INDICATOR */
	' ', 			/* 171 - LEFT-POINTING DOUBLE ANGLE QUOTATION MARK */
	' ', 			/* 172 - NOT SIGN */
	' ', 			/* 173 - SOFT HYPHEN */
	' ', 			/* 174 - REGISTERED SIGN */
	' ', 			/* 175 - MACRON */
	' ', 			/* 176 - DEGREE SIGN */
	' ', 			/* 177 - PLUS-MINUS SIGN */
	'2', 			/* 178 - SUPERSCRIPT TWO */
	'3', 			/* 179 - SUPERSCRIPT THREE */
	' ', 			/* 180 - ACUTE ACCENT */
	'u', 			/* 181 - MICRO SIGN */
	' ', 			/* 182 - PILCROW SIGN */
	' ', 			/* 183 - MIDDLE DOT */
	' ', 			/* 184 - CEDILLA */
	'1', 			/* 185 - SUPERSCRIPT ONE */
	' ', 			/* 186 - MASCULINE ORDINAL INDICATOR */
	' ', 			/* 187 - RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK */
	' ', 			/* 188 - VULGAR FRACTION ONE QUARTER */
	' ', 			/* 189 - VULGAR FRACTION ONE HALF */
	' ', 			/* 190 - VULGAR FRACTION THREE QUARTERS */
	' ', 			/* 191 - INVERTED QUESTION MARK */
	'a', 			/* 192 - LATIN CAPITAL LETTER A WITH GRAVE */
	'a', 			/* 193 - LATIN CAPITAL LETTER A WITH ACUTE */
	'a', 			/* 194 - LATIN CAPITAL LETTER A WITH CIRCUMFLEX */
	'a', 			/* 195 - LATIN CAPITAL LETTER A WITH TILDE */
	'a', 			/* 196 - LATIN CAPITAL LETTER A WITH DIAERESIS */
	'a', 			/* 197 - LATIN CAPITAL LETTER A WITH RING ABOVE */
	' ', 			/* 198 - LATIN CAPITAL LETTER AE */
	'c', 			/* 199 - LATIN CAPITAL LETTER C WITH CEDILLA */
	'e', 			/* 200 - LATIN CAPITAL LETTER E WITH GRAVE */
	'e', 			/* 201 - LATIN CAPITAL LETTER E WITH ACUTE */
	'e', 			/* 202 - LATIN CAPITAL LETTER E WITH CIRCUMFLEX */
	'e', 			/* 203 - LATIN CAPITAL LETTER E WITH DIAERESIS */
	'i', 			/* 204 - LATIN CAPITAL LETTER I WITH GRAVE */
	'i', 			/* 205 - LATIN CAPITAL LETTER I WITH ACUTE */
	'i',			/* 206 - LATIN CAPITAL LETTER I WITH CIRCUMFLEX */
	'i',			/* 207 - LATIN CAPITAL LETTER I WITH DIAERESIS */
	' ',			/* 208 - LATIN CAPITAL LETTER ETH */
	'n',			/* 209 - LATIN CAPITAL LETTER N WITH TILDE */
	'o',			/* 210 - LATIN CAPITAL LETTER O WITH GRAVE */
	'o',			/* 211 - LATIN CAPITAL LETTER O WITH ACUTE */
	'o',			/* 212 - LATIN CAPITAL LETTER O WITH CIRCUMFLEX */
	'o',			/* 213 - LATIN CAPITAL LETTER O WITH TILDE */
	'o',			/* 214 - LATIN CAPITAL LETTER O WITH DIAERESIS */
	' ',			/* 215 - MULTIPLICATION SIGN */
	'o',			/* 216 - LATIN CAPITAL LETTER O WITH STROKE */
	'u',			/* 217 - LATIN CAPITAL LETTER U WITH GRAVE */
	'u',			/* 218 - LATIN CAPITAL LETTER U WITH ACUTE */
	'u',			/* 219 - LATIN CAPITAL LETTER U WITH CIRCUMFLEX */
	'u',			/* 220 - LATIN CAPITAL LETTER U WITH DIAERESIS */
	'y',			/* 221 - LATIN CAPITAL LETTER Y WITH ACUTE */
	' ',			/* 222 - LATIN CAPITAL LETTER THORN */
	's',			/* 223 - LATIN SMALL LETTER SHARP S */
	'a',			/* 224 - LATIN SMALL LETTER A WITH GRAVE */
	'a',			/* 225 - LATIN SMALL LETTER A WITH ACUTE */
	'a',			/* 226 - LATIN SMALL LETTER A WITH CIRCUMFLEX */
	'a',			/* 227 - LATIN SMALL LETTER A WITH TILDE */
	'a',			/* 228 - LATIN SMALL LETTER A WITH DIAERESIS */
	'a',			/* 229 - LATIN SMALL LETTER A WITH RING ABOVE */
	' ',			/* 230 - LATIN SMALL LETTER AE */
	'c',			/* 231 - LATIN SMALL LETTER C WITH CEDILLA */
	'e',			/* 232 - LATIN SMALL LETTER E WITH GRAVE */
	'e',			/* 233 - LATIN SMALL LETTER E WITH ACUTE */
	'e',			/* 234 - LATIN SMALL LETTER E WITH CIRCUMFLEX */
	'e',			/* 235 - LATIN SMALL LETTER E WITH DIAERESIS */
	'i',			/* 236 - LATIN SMALL LETTER I WITH GRAVE */
	'i',			/* 237 - LATIN SMALL LETTER I WITH ACUTE */
	'i',			/* 238 - LATIN SMALL LETTER I WITH CIRCUMFLEX */
	'i',			/* 239 - LATIN SMALL LETTER I WITH DIAERESIS */
	' ',			/* 240 - LATIN SMALL LETTER ETH */
	'n',			/* 241 - LATIN SMALL LETTER N WITH TILDE */
	'o',			/* 242 - LATIN SMALL LETTER O WITH GRAVE */
	'o',			/* 243 - LATIN SMALL LETTER O WITH ACUTE */
	'o',			/* 244 - LATIN SMALL LETTER O WITH CIRCUMFLEX */
	'o',			/* 245 - LATIN SMALL LETTER O WITH TILDE */
	'o',			/* 246 - LATIN SMALL LETTER O WITH DIAERESIS */
	' ',			/* 247 - DIVISION SIGN */
	'o',			/* 248 - LATIN SMALL LETTER O WITH STROKE */
	'u',			/* 249 - LATIN SMALL LETTER U WITH GRAVE */
	'u',			/* 250 - LATIN SMALL LETTER U WITH ACUTE */
	'u',			/* 251 - LATIN SMALL LETTER U WITH CIRCUMFLEX */
	'u',			/* 252 - LATIN SMALL LETTER U WITH DIAERESIS */
	'y',			/* 253 - LATIN SMALL LETTER Y WITH ACUTE */
	' ',			/* 254 - LATIN SMALL LETTER THORN */
	'y',			/* 255 - LATIN SMALL LETTER Y WITH DIAERESIS */
};

guint32 files_scanned = 0;
guint32 kbytes_scanned = 0;
guint32 bytes_scanned = 0;

GSList *extensions = NULL;
GSList *shared_dirs = NULL;
static GSList *shared_files = NULL;
static struct shared_file **file_table = NULL;
static search_table_t search_table;
static GHashTable *file_basenames = NULL;

gchar stmp_1[4096];
gchar stmp_2[4096];

/***
 *** Callbacks
 ***/

static listeners_t search_request_listeners = NULL;

void share_add_search_request_listener(search_request_listener_t l)
{
    LISTENER_ADD(search_request, l);
}

void share_remove_search_request_listener(search_request_listener_t l)
{
    LISTENER_REMOVE(search_request, l);
}

static void share_emit_search_request(
    query_type_t type, const gchar *query, guint32 ip, guint16 port)
{
    LISTENER_EMIT(search_request, type, query, ip, port);
}

/*
 * Buffer where query hit packet is built.
 *
 * There is only one such packet, never freed.  At the beginning, one founds
 * the gnutella header, followed by the query hit header: initial offsetting
 * set by FOUND_RESET().
 *
 * The bufffer is logically (and possibly physically) extended via FOUND_GROW()
 * FOUND_BUF and FOUND_SIZE are used within the building code to access the
 * beginning of the query hit packet and the logical size of the packet.
 *
 *		--RAM, 25/09/2001
 */

struct {
	guchar *d;					/* data */
	guint32 l;					/* data length */
	guint32 s;					/* size used by current search hit */
	guint files;				/* amount of file entries */
} found_data;

#define FOUND_CHUNK		1024	/* Minimal growing memory amount unit */

#define FOUND_GROW(len) do {						\
	gint missing;									\
	found_data.s += (len);							\
	missing = found_data.s - found_data.l;			\
	if (missing > 0) {								\
		missing = MAX(missing, FOUND_CHUNK);		\
		found_data.l += missing;					\
		found_data.d = (guchar *) g_realloc(found_data.d,	\
			found_data.l * sizeof(guchar));			\
	}												\
} while (0)

#define FOUND_RESET() do {							\
	found_data.s = sizeof(struct gnutella_header) +	\
		sizeof(struct gnutella_search_results_out);	\
	found_data.files = 0;							\
} while (0)

#define FOUND_BUF	found_data.d
#define FOUND_SIZE	found_data.s
#define FOUND_FILES	found_data.files

/* 
 * We don't want to include the same file several times in a reply (for
 * example, once because it matches an URN query and once because the file name
 * matches). So we keep track of what has been added in this tree. The file
 * index is used as the key.
 */

static GTree *index_of_found_files = NULL;
static gint index_of_found_files_count = 0;
static struct gnutella_node *issuing_node;

/* 
 * compare_indexes
 * 
 * Compare 2 indexes for use as the GCompareFunc for the index_of_found_files
 * GTree.
 * Return 0 if indexes are the same, a negative value if i1 is bigger
 * than i2 and a positive value otherwise.
 */
static int compare_indexes(guint32 i1, guint32 i2)
{
	return i2 - i1;
}

/* 
 * shared_file_already_in_found_set
 * 
 * Check if a given shared_file has been added to the QueryHit.
 * Return TRUE if the shared_file is in the QueryHit already, FALSE otherwise
 */
static gboolean shared_file_already_in_found_set(struct shared_file *sf)
{
	return NULL != g_tree_lookup(index_of_found_files,
		GUINT_TO_POINTER(sf->file_index));
}

/*
 * put_shared_file_into_found_set
 * 
 * Add the shared_file to the set of files already added to the QueryHit.
 */

static void put_shared_file_into_found_set(struct shared_file *sf)
{
	index_of_found_files_count++;
	g_tree_insert(index_of_found_files, 
				  GUINT_TO_POINTER(sf->file_index), 
				  GUINT_TO_POINTER(!NULL));
}

/* 
 * found_reset
 * 
 * Reset the QueryHit, that is, the "data found" pointer is at the beginning of
 * the data found section in the query hit packet and the index_of_found_files
 * GTree is reset.
 */
static void found_reset(struct gnutella_node *n)
{
	FOUND_RESET();
	issuing_node = n;

	/*
	 * We only destroy and recreate a new tree if we inserted something
	 * in the previous search.
	 */

	if (index_of_found_files && index_of_found_files_count) {
		g_tree_destroy(index_of_found_files);
		index_of_found_files_count = 0;
		index_of_found_files = NULL;
	}

	if (index_of_found_files == NULL)
		index_of_found_files = g_tree_new((GCompareFunc) compare_indexes);
}

/*
 * Minimal trailer length is our code NAME, the open flags, and the GUID.
 */
#define QHIT_MIN_TRAILER_LEN	(4+3+16)	/* NAME + open flags + GUID */

#define FILENAME_CLASH 0xffffffff			/* Indicates basename clashes */



/* ----------------------------------------- */

static char_map_t query_map;


/*
 * setup_char_map
 *
 * Set up keymapping table for Gnutella.
 *
 * The most common encoding of searches are ASCII, then ISO-8859-1.
 * Unicode is marginal for now, and we restrict it to the ISO-8859-1 subset.
 */
static void setup_char_map(char_map_t map)
{
	gint c;	

	for (c = 0; c < 256; c++)	{
		if (islower(c)) {
			map[c] = c;
			map[toupper(c)] = c;
		}
		else if (isupper(c))
			; /* handled by previous case */
		else if (ispunct(c) || isspace(c))
			map[c] = ' ';
		else if (isdigit(c))
			map[c] = c;
		else if (isalnum(c))
			map[c] = c;
		else
			map[c] = ' ';			/* unknown in our locale */
	}

	for (c = 160; c < 256; c++)
		map[c] = iso_8859_1[c - 160];
}

/* ----------------------------------------- */

void share_init(void)
{
	setup_char_map(query_map);
	huge_init();
	st_initialize(&search_table, query_map);
	qrp_init(query_map);

	found_data.l = FOUND_CHUNK;		/* must be > size after found_reset */
	found_data.d = (guchar *) g_malloc(found_data.l * sizeof(guchar));

	/*
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

	st_create(&search_table);
}

/*
 * shared_file
 *
 * Given a valid index, returns the `struct shared_file' entry describing
 * the shared file bearing that index if found, NULL if not found (invalid
 * index) and SHARE_REBUILDING when we're rebuilding the library.
 */
struct shared_file *shared_file(guint idx)
{
	/* Return shared file info for index `idx', or NULL if none */

	if (file_table == NULL)			/* Rebuilding the library! */
		return SHARE_REBUILDING;

	if (idx < 1 || idx > files_scanned)
		return NULL;

	return file_table[idx - 1];
}

/*
 * shared_file_by_name
 *
 * Given a file basename, returns the `struct shared_file' entry describing
 * the shared file bearing that basename, provided it is unique, NULL if
 * we either don't have a unique filename or SHARE_REBUILDING if the library
 * is being rebuilt.
 */
struct shared_file *shared_file_by_name(gchar *basename)
{
	guint idx;

	if (file_table == NULL)
		return SHARE_REBUILDING;

	g_assert(file_basenames);

	idx = (guint) g_hash_table_lookup(file_basenames, basename);

	if (idx == 0 || idx == FILENAME_CLASH)
		return NULL;

	g_assert(idx >= 1 && idx <= files_scanned);

	return file_table[idx - 1];
}

/* ----------------------------------------- */

/* Free existing extensions */

static void free_extensions(void)
{
	GSList *l = extensions;

	if (!l)
		return;

	while (l) {
		struct extension *e = (struct extension *) l->data;
		atom_str_free(e->str);
		g_free(e);
		l = l->next;
	}
	g_slist_free(extensions);
	extensions = NULL;
}

/* Get the file extensions to scan */

void parse_extensions(gchar * str)
{
	gchar **exts = g_strsplit(str, ";", 0);
	gchar *x, *s;
	guint i, e;

	free_extensions();

	e = i = 0;

	while (exts[i]) {
		s = exts[i];
		while (*s == ' ' || *s == '\t' || *s == '.' || *s == '*'
			   || *s == '?')
			s++;
		if (*s) {
			x = s + strlen(s);
			while (--x > s
				   && (*x == ' ' || *x == '\t' || *x == '*' || *x == '?'))
				*x = 0;
			if (*s) {
				struct extension *e = (struct extension *) g_malloc(sizeof(*e));
				e->str = atom_str_get(s);
				e->len = strlen(s);
				extensions = g_slist_append(extensions, e);
			}
		}
		i++;
	}

	g_strfreev(exts);
}

/* Shared dirs */

static void shared_dirs_free(void)
{
	if (shared_dirs) {
		GSList *l = shared_dirs;
		while (l) {
			atom_str_free(l->data);
			l = l->next;
		}
		g_slist_free(shared_dirs);
		shared_dirs = NULL;
	}
}

void shared_dirs_update_prop(void)
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

/*
 * shared_dirs_parse:
 *
 * Parses the given string and updated the internal list of shared dirs.
 * The given string was completely parsed, it returns TRUE, otherwise
 * it returns FALSE.
 */
gboolean shared_dirs_parse(gchar *str)
{
	gchar **dirs = g_strsplit(str, ":", 0);
	guint i = 0;
    gboolean ret = TRUE;

	shared_dirs_free();

	while (dirs[i]) {
		if (is_directory(dirs[i]))
			shared_dirs = g_slist_append(shared_dirs, atom_str_get(dirs[i]));
        else 
            ret = FALSE;
		i++;
	}

	g_strfreev(dirs);

    return ret;
}

void shared_dir_add(gchar * path)
{
	if (is_directory(path))
        shared_dirs = g_slist_append(shared_dirs, atom_str_get(path));

    shared_dirs_update_prop();
}

/*
 * recurse_scan
 *
 * The directories that are given as shared will be completly transversed
 * including all files and directories. An entry of "/" would search the
 * the whole file system.
 */
static void recurse_scan(gchar *dir, gchar *basedir)
{
	GSList *exts = NULL;
	DIR *directory;			/* Dir stream used by opendir, readdir etc.. */
	struct dirent *dir_entry;
	gchar *full = NULL, *sl = "/";
	GSList *files = NULL;
	GSList *directories = NULL;
	gchar *dir_slash = NULL;
	GSList *l;
	gint i;

	struct shared_file *found = NULL;
	struct stat file_stat;
	gchar *entry_end;

	if (*dir == '\0')
		return;

	if (!(directory = opendir(dir))) {
		g_warning("can't open directory %s: %s", dir, g_strerror(errno));
		return;
	}
	
	if (dir[strlen(dir) - 1] == '/')
		dir_slash = dir;
	else
		dir_slash = g_strconcat(dir, sl, NULL);

	while ((dir_entry = readdir(directory))) {

		if (dir_entry->d_name[0] == '.')	/* Hidden file, or "." or ".." */
			continue;

		full = g_strconcat(dir_slash, dir_entry->d_name, NULL);

		if (!is_directory(full))
			files = g_slist_prepend(files, full);
		else
			directories = g_slist_prepend(directories, full);
	}

	for (i = 0, l = files; l; i++, l = l->next) {
		gchar *name;
		gint name_len;

		full = (gchar *) l->data;

		name = strrchr(full, '/');
		g_assert(name);
		name++;						/* Start of file name */

		name_len = strlen(name);
		entry_end = name + name_len;

		for (exts = extensions; exts; exts = exts->next) {
			struct extension *e = (struct extension *) exts->data;
			gchar *start = entry_end - (e->len + 1);	/* +1 for "." */

			/*
			 * Look for the trailing chars (we're matching an extension).
			 * Matching is case-insensitive, and the extension opener is ".".
			 *
			 * An extension "--all--" matches all files, even if they
			 * don't have any extension. [Patch from Zygo Blaxell].
			 */

			if (
				0 == g_strcasecmp("--all--", e->str) ||		/* All files */
				(start >= name && *start == '.' &&
					0 == g_strcasecmp(start+1, e->str))
			) {
				if (stat(full, &file_stat) == -1) {
					g_warning("can't stat %s: %s", full, g_strerror(errno));
					break;
				}

				found = (struct shared_file *)
					g_malloc0(sizeof(struct shared_file));

				found->file_path = atom_str_get(full);
				found->file_name = found->file_path + (name - full);
				found->file_name_len = name_len;
				found->file_size = file_stat.st_size;
				found->file_index = ++files_scanned;
				found->mtime = file_stat.st_mtime;
				found->has_sha1_digest = FALSE;
				request_sha1(found);

				st_insert_item(&search_table, found->file_name, found);
				shared_files = g_slist_append(shared_files, found);

				bytes_scanned += file_stat.st_size;
				kbytes_scanned += bytes_scanned >> 10;
				bytes_scanned &= (1 << 10) - 1;
				break;			/* for loop */
			}
		}
		g_free(full);

		if (!(i & 0x3f)) {
			gui_update_files_scanned();		/* Interim view */
			gtk_main_flush();
		}
	}

	closedir(directory);
	g_slist_free(files);

	/*
	 * Now that we handled files at this level and freed all their memory,
	 * recurse on directories.
	 */

	for (l = directories; l; l = l->next) {
		gchar *path = (gchar *) l->data;
		recurse_scan(path, basedir);
		g_free(path);
	}
	g_slist_free(directories);

	if (dir_slash != dir)
		g_free(dir_slash);

	gui_update_files_scanned();		/* Interim view */
	gtk_main_iteration_do(FALSE);
}

static void share_free(void)
{
	GSList *l;

	st_destroy(&search_table);

	if (file_basenames)
		g_hash_table_destroy(file_basenames);
	file_basenames = NULL;

	if (file_table) {
		g_free(file_table);
		file_table = NULL;
	}

	for (l = shared_files; l; l = l->next) {
		struct shared_file *sf = l->data;
		atom_str_free(sf->file_path);
		g_free(sf);
	}

	g_slist_free(shared_files);
	shared_files = NULL;
}

static void reinit_sha1_table();

void share_scan(void)
{
	GSList *l;
	gint i;
	static gboolean in_share_scan = FALSE;

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

	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, TRUE);

	files_scanned = 0;
	bytes_scanned = 0;
	kbytes_scanned = 0;

	reinit_sha1_table();
	share_free();

	g_assert(file_basenames == NULL);

	st_create(&search_table);
	file_basenames = g_hash_table_new(g_str_hash, g_str_equal);

	for (l = shared_dirs; l; l = l->next)
		recurse_scan(l->data, l->data);

	st_compact(&search_table);

	/*
	 * In order to quickly locate files based on indicies, build a table
	 * of all shared files.  This table is only accessible via shared_file().
	 * NB: file indicies start at 1, but indexing in table start at 0.
	 *		--RAM, 08/10/2001
	 */

	file_table = g_malloc0(files_scanned * sizeof(struct shared_file *));

	for (i = 0, l = shared_files; l; i++, l = l->next) {
		struct shared_file *sf = l->data;
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

		val = (guint) g_hash_table_lookup(file_basenames, sf->file_name);

		/*
		 * The following works because 0 cannot be a valid file index.
		 */

		val = (val != 0) ? FILENAME_CLASH : sf->file_index;
		g_hash_table_insert(file_basenames, sf->file_name, (gpointer) val);

		if (0 == (i & 0x7ff))
			gtk_main_flush();
	}

	gui_update_files_scanned();		/* Final view */

#if 0
	/*
	 * Query routing table update.  XXX DISABLED: not ready.
	 */

	qrp_prepare_computation();

	for (i = 0, l = shared_files; l; i++, l = l->next) {
		struct shared_file *sf = l->data;
		qrp_add_file(sf);
		if (0 == (i & 0x7ff))
			gtk_main_flush();
	}

	qrp_finalize_computation();
#endif

	in_share_scan = FALSE;
	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, FALSE);
}

void share_close(void)
{
	g_free(found_data.d);
	free_extensions();
	share_free();
	shared_dirs_free();
	huge_close();
	qrp_close();
}

/*
 * flush_match
 *
 * Flush pending search request to the network.
 */
static void flush_match(void)
{
	struct gnutella_node *n = issuing_node;		/* XXX -- global! */
	gchar trailer[10];
	guint32 pos, pl;
	struct gnutella_header *packet_head;
	struct gnutella_search_results_out *search_head;

	if (dbg > 3)
		printf("flushing query hit (%d entr%s, %d bytes sofar)\n",
			FOUND_FILES, FOUND_FILES == 1 ? "y" : "ies", FOUND_SIZE);

	/*
	 * Build Gtk-gnutella trailer.
	 * It is compatible with BearShare's one in the "open data" section.
	 */

	strncpy(trailer, "GTKG", 4);	/* Vendor code */
	trailer[4] = 2;					/* Open data size */
	trailer[5] = 0x04 | 0x08;		/* Valid flags we set */
	trailer[6] = 0x01;				/* Our flags (valid firewall bit) */

	if (running_uploads >= max_uploads)
		trailer[6] |= 0x04;			/* Busy flag */
	if (count_uploads > 0)
		trailer[6] |= 0x08;			/* One file uploaded, at least */
	if (is_firewalled)
		trailer[5] |= 0x01;			/* Firewall bit set in enabling byte */

	pos = FOUND_SIZE;
	FOUND_GROW(16 + 7);
	memcpy(&FOUND_BUF[pos], trailer, 7);	/* Store trailer */
	memcpy(&FOUND_BUF[pos+7], guid, 16);	/* Store the GUID */

	/* Payload size including the search results header, actual results */
	pl = FOUND_SIZE - sizeof(struct gnutella_header);

	packet_head = (struct gnutella_header *) FOUND_BUF;
	memcpy(&packet_head->muid, &n->header.muid, 16);

	/*
	 * We limit the TTL to the minimal possible value, then add a margin
	 * of 5 to account for re-routing abilities some day.  We then trim
	 * at our configured hard TTL limit.  Replies are precious packets,
	 * it would be a pity if they did not make it back to their source.
	 *
	 *			 --RAM, 02/02/2001
	 */

	if (n->header.hops == 0) {
		g_warning
			("search_request(): hops=0, bug in route_message()?\n");
		n->header.hops++;	/* Can't send message with TTL=0 */
	}

	packet_head->function = GTA_MSG_SEARCH_RESULTS;
	packet_head->ttl = MIN(n->header.hops + 5, hard_ttl_limit);
	packet_head->hops = 0;
	WRITE_GUINT32_LE(pl, packet_head->size);

	search_head = (struct gnutella_search_results_out *)
		&FOUND_BUF[sizeof(struct gnutella_header)];

	search_head->num_recs = FOUND_FILES;	/* One byte, little endian! */

	WRITE_GUINT16_LE(listen_port, search_head->host_port);
	WRITE_GUINT32_BE(listen_ip(), search_head->host_ip);
	WRITE_GUINT32_LE(connection_speed, search_head->host_speed);

	gmsg_sendto_one(n, FOUND_BUF, FOUND_SIZE);
}

/*
 * Callback from st_search(), for each matching file.	--RAM, 06/10/2001
 *
 * Returns TRUE if we inserted the record, FALSE if we refused it due to
 * lack of space.
 */
static gboolean got_match(struct shared_file *sf)
{
	guint32 pos = FOUND_SIZE;
	guint32 needed = 8 + 2 + sf->file_name_len;		/* size of hit entry */
	gboolean sha1_available = sf->has_sha1_digest;
	
	/*
	 * We don't stop adding records if we refused this one, hence the TRUE
	 * returned.
	 */

	if (shared_file_already_in_found_set(sf))
		return TRUE;

	put_shared_file_into_found_set(sf);

	if (sha1_available)
		needed += 9 + SHA1_BASE32_SIZE;

	/*
	 * Refuse entry if we don't have enough room.	-- RAM, 22/01/2002
	 */

	if (pos + needed + QHIT_MIN_TRAILER_LEN > search_answers_forward_size)
		return FALSE;

	/*
	 * Grow buffer by the size of the search results header 8 bytes,
	 * plus the string length - NULL, plus two NULL's
	 */

	FOUND_GROW(needed);

	WRITE_GUINT32_LE(sf->file_index, &FOUND_BUF[pos]); pos += 4;
	WRITE_GUINT32_LE(sf->file_size, &FOUND_BUF[pos]);  pos += 4;

	memcpy(&FOUND_BUF[pos], sf->file_name, sf->file_name_len);
	pos += sf->file_name_len;

	/* Position equals the next byte to be writen to */

	FOUND_BUF[pos++] = '\0';

	if (sha1_available) {
		gchar *b32 = sha1_base32(sf->sha1_digest);
		memcpy(&FOUND_BUF[pos], "urn:sha1:", 9);
		pos += 9;
		memcpy(&FOUND_BUF[pos], b32, SHA1_BASE32_SIZE);
		pos += SHA1_BASE32_SIZE;
	}

	FOUND_BUF[pos++] = '\0';
	FOUND_FILES++;

	/*
	 * If we have reached our size limit for query hits, flush what
	 * we have so far.
	 */

	if (FOUND_SIZE >= QHIT_SIZE_THRESHOLD) {
		flush_match();
		FOUND_RESET();
	}

	return TRUE;		/* Hit entry accepted */
}

#define MIN_WORD_LENGTH 1		/* For compaction */

/*
 * compact_query:
 *
 * Remove unnecessary ballast from a query before processing it. Works in
 * place on the given string. Removed are all consecutive blocks of
 * whitespace and all word shorter then MIN_WORD_LENGTH.
 *
 * If `utf8_len' is non-zero, then we're facing an UTF-8 string.
 */
guint compact_query(gchar *search, gint utf8_len)
{
	gchar *s;
	gchar *w;
	gboolean skip_space = TRUE;
	gint word_length = 0;
	guint32 c;
	gint clen;
	gboolean is_utf8 = utf8_len != 0;

	if (dbg > 4)
		printf("original (%s): [%s]\n", is_utf8 ? "UTF-8" : "ASCII", search);

	w = s = search;
	while (
		(c = utf8_len ?
			utf8_decode_char(s, utf8_len, &clen, FALSE) :
			(guint32) *(guchar *) s)
	) {
		if (c == ' ') {
			/*
			 * Reduce consecutive spaces to a single space.
			 */
			if (!skip_space) {
				if (word_length < MIN_WORD_LENGTH) {
					/* 
					 * reached end of very short word in query. drop
					 * that word by rewinding write position
					 */
					if (dbg > 4)
						printf("w");
					w -= word_length;
				} else {
					/* copy space to final position, reset word length */
					*w++ = ' ';
				}
				skip_space = TRUE;
				word_length = 0; /* count this space to the next word */
			} else if (dbg > 4)
				printf("s");
		} else {
			/*
			 * Within a word now, copy character.
			 */
			skip_space = FALSE;
			if (utf8_len) {
				gint i;
				for (i = 0; i < clen; i++)
					*w++ = s[i];
				word_length += clen;	/* Yes, count 3-wide char as 3 */
			} else {
				*w++ = c;
				word_length++;
			}
		}
	
		/* count the length of the original search string */
		if (utf8_len) {
			s += clen;
			utf8_len -= clen;
			g_assert(utf8_len >= 0);
		} else
			s++;
	}

	/* maybe very short word at end of query, then drop */
	if ((word_length > 0) && (word_length < MIN_WORD_LENGTH)) {
		if (dbg > 4)
			printf("e");
		w -= word_length;
		skip_space = TRUE;
	}
	
	/* space left at end of query but query not empty, drop */
	if (skip_space && (w != search)) {
		if (dbg > 4)
			printf("t");
		w--;
	}

	*w = '\0'; /* terminate mangled query */

	if (dbg > 4 && w != s)
		printf("\nmangled (%s): [%s]\n", is_utf8 ? "UTF-8" : "ASCII", search);

	/* search does no longer contain unnecessary whitespace */
	return w - search;
}

/*
 * query_utf8_decode
 *
 * Given a query `text' of `len' bytes:
 *
 * If query is UTF8, compute its length and store it in `retlen'.
 * If query starts with a BOM mark, skip it and set `retoff' accordingly.
 *
 * Returns FALSE on bad UTF-8, TRUE otherwise.
 */
static gboolean query_utf8_decode(
	gchar *text, guint32 len, guint32 *retlen, guint *retoff)
{
	guint offset = 0;
	guint32 utf8_len = -1;

	/*
	 * Look whether we're facing an UTF-8 query.
	 *
	 * If it starts with the sequence EF BB BF (BOM in UTF-8), then
	 * it is clearly UTF-8.  If we can't decode it, it is bad UTF-8.
	 */

	if (len >= 3) {
		guchar *p = (guchar *) text;
		if (p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf) {
			offset = 3;				/* Is UTF-8, skip BOM */
			if (
				len == offset ||
				!(utf8_len = utf8_is_valid_string(text + offset, len - offset))
			)
				return FALSE;		/* Bad UTF-8 encoding */
		}
	}

	if (utf8_len == -1) {
		utf8_len = utf8_is_valid_string(text, len);
		if (utf8_len && utf8_len == len)			/* Is pure ASCII */
			utf8_len = 0;							/* Not fully UTF-8 */
	}

	*retlen = utf8_len;
	*retoff = offset;

	return TRUE;
}

/*
 * Searches requests (from others nodes) 
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the LL.
 *
 * Returns TRUE if the message should be dropped and not propagated further.
 */
gboolean search_request(struct gnutella_node *n)
{
	guchar found_files = 0;
	guint16 req_speed;
	gchar *search;
	guint32 search_len;
	guint32 max_replies;
	gboolean skip_file_search = FALSE;
	extvec_t exv[MAX_EXTVEC];
	gint exvcnt = 0;
	struct {
		gchar sha1_digest[SHA1_RAW_SIZE];
		gboolean matched;
	} exv_sha1[MAX_EXTVEC];
	gint exv_sha1cnt = 0;
	gint utf8_len = -1;
	guint offset = 0;			/* Query string start offset */
	gboolean drop_it = FALSE;

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
	search_len = 0;

	/* open a block, since C doesn't allow variables to be declared anywhere */
	{
		gchar *s = search;
		guint32 max_len = n->size - 3;		/* Payload size - Speed - NUL */

        while (search_len <= max_len && *s++)
            search_len ++;

		if (search_len > max_len) {
			g_assert(n->data[n->size - 1] != '\0');
			if (dbg)
				g_warning("query (hops=%d, ttl=%d) had no NUL (%d byte%s)",
					n->header.hops, n->header.ttl, n->size - 2,
					n->size == 3 ? "" : "s");
			if (dbg > 4)
				dump_hex(stderr, "Query Text", search, MIN(n->size - 2, 256));

            gnet_stats_count_dropped(n, MSG_DROP_QUERY_NO_NUL);
			return TRUE;		/* Drop the message! */
		}
		/* We can now use `search' safely as a C string: it embeds a NUL */

		/*
		 * Drop the "QTRAX2_CONNECTION" queries as being "overhead".
		 */

#define QTRAX_STRLEN	(sizeof("QTRAX2_CONNECTION")-1)

		if (
			search_len >= QTRAX_STRLEN &&
			search[0] == 'Q' &&
			search[1] == 'T' &&
			0 == strncmp(search, "QTRAX2_CONNECTION", QTRAX_STRLEN)
		) {
            gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
			return TRUE;		/* Drop the message! */
		}

#undef QTRAX_STRLEN

    }


	/*
	 * Compact query, if requested and we're going to relay that message.
	 */

	if (gnet_compact_query && n->header.ttl) {
		guint32 mangled_search_len;

		/*
		 * Look whether we're facing an UTF-8 query.
		 */

		if (!query_utf8_decode(search, search_len, &utf8_len, &offset)) {
			gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
			return TRUE;					/* Drop message! */
		} else if (utf8_len)
			gnet_stats_count_general(n, GNR_QUERY_UTF8, 1);

		/*
		 * Compact the query, offsetting from the start as needed in case
		 * there is a leading BOM (our UTF-8 decoder does not allow BOM
		 * within the UTF-8 string, and rightly I think: that would be pure
		 * gratuitous bloat).
		 */

		mangled_search_len = compact_query(search + offset, utf8_len);

		g_assert(mangled_search_len <= search_len - offset);
	
		if (mangled_search_len != search_len - offset) {
			gnet_stats_count_general(n, GNR_QUERY_COMPACT_COUNT, 1);
			gnet_stats_count_general(n, GNR_QUERY_COMPACT_SIZE,
				search_len - offset - mangled_search_len);
		}

		/*
		 * Need to move the trailing data forward and adjust the
		 * size of the packet.
		 */

		g_memmove(
			search+offset+mangled_search_len, /* new end of query string */
			search+search_len,                /* old end of query string */
			n->size - (search - n->data) - search_len); /* trailer len */

		n->size -= search_len - offset - mangled_search_len;
		WRITE_GUINT32_LE(n->size, n->header.size);
		search_len = mangled_search_len + offset;

		g_assert(search[search_len] == '\0');
	} 

	/*
	 * If there are extra data after the first NUL, fill the extension vector.
	 */

	if (search_len + 3 != n->size) {
		gint extra = n->size - 3 - search_len;		/* Amount of extra data */
		gint i;

		exvcnt = ext_parse(search + search_len + 1, extra, exv, MAX_EXTVEC);

		if (exvcnt == MAX_EXTVEC) {
			g_warning("%s has %d extensions!",
				gmsg_infostr(&n->header), exvcnt);
			if (dbg)
				ext_dump(stderr, exv, exvcnt, "> ", "\n", TRUE);
			if (dbg > 1)
				dump_hex(stderr, "Query", search, n->size - 2);
		}

		if (exvcnt && dbg > 3) {
			printf("Query with extensions: %s\n", search);
			ext_dump(stdout, exv, exvcnt, "> ", "\n", dbg > 4);
		}

		/*
		 * If there is a SHA1 URN, validate it and extract the binary digest
		 * into sha1_digest[], and set `sha1_query' to the base32 value.
		 */

		for (i = 0; i < exvcnt; i++) {
			extvec_t *e = &exv[i];

			if (e->ext_token == EXT_T_OVERHEAD) {
				if (dbg > 6)
					dump_hex(stderr, "Query Packet (BAD: has overhead)",
						search, MIN(n->size - 2, 256));
				gnet_stats_count_dropped(n, MSG_DROP_QUERY_OVERHEAD);
				return TRUE;			/* Drop message! */
			}

			if (e->ext_token == EXT_T_URN_SHA1) {
				gchar *sha1_digest = exv_sha1[exv_sha1cnt].sha1_digest;

				if (e->ext_paylen == 0)
					continue;				/* A simple "urn:sha1:" */

				if (
					!huge_sha1_extract32(e->ext_payload, e->ext_paylen,
						sha1_digest, &n->header, FALSE)
                ) {
                    gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_SHA1_QUERY);
					return TRUE;			/* Drop message! */
                }

				exv_sha1[exv_sha1cnt].matched = FALSE;
				exv_sha1cnt++;

				if (dbg > 4)
					printf("Valid SHA1 #%d in query: %32s\n",
						exv_sha1cnt, e->ext_payload);
			}
		}

		if (exv_sha1cnt)
			gnet_stats_count_general(n, GNR_QUERY_SHA1, 1);
	}

    /*
     * Reorderd the checks: if we drop the packet, we won't notify any
     * listeners. We first check wether we want to drop the packet and
     * later decide wether we are eligible for answering the query:
     * 1) try top drop
     * 2) notify listeners
     * 3) bail out if not eligible for a local search
     * 4) local search
     *      --Richard, 11/09/2002
     */

	/*
	 * If the query comes from a node farther than our TTL (i.e. the TTL we'll
	 * use to send our reply), don't bother processing it: the reply won't
	 * be able to reach the issuing node.
	 *
	 * However, note that for replies, we use our maximum configured TTL, so
	 * we compare to that, and not to my_ttl, which is the TTL used for
	 * "standard" packets.
	 *
	 *				--RAM, 12/09/2001
	 */

    if (n->header.hops > max_ttl) {
        gnet_stats_count_dropped(n, MSG_DROP_MAX_TTL_EXCEEDED);
		return TRUE;					/* Drop this long-lived search */
    }

	/*
	 * When an URN search is present, there can be an empty search string.
	 *
	 * If requester if farther than 3 hops. save bandwidth when returning
	 * lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 *
	 * Notes from RAM, 09/09/2001:
	 * 1) The hop amount must be made configurable.
	 * 2) We can add a config option to forbid forwarding of such queries.
	 */

	if (
		search_len <= 1 ||
		(search_len < 5 && n->header.hops > 3)
	)
		skip_file_search = TRUE;

    if (0 == exv_sha1cnt && skip_file_search) {
        gnet_stats_count_dropped(n, MSG_DROP_QUERY_TOO_SHORT);
		return TRUE;					/* Drop this search message */
    }

    /*
     * Push the query string to interested ones.
     */

	if (!*search && exv_sha1cnt) {
		gint i;
		for (i = 0; i < exv_sha1cnt; i++)
			share_emit_search_request(QUERY_SHA1,
				sha1_base32(exv_sha1[i].sha1_digest), n->ip, n->port);
	} else
		share_emit_search_request(QUERY_STRING, search, n->ip, n->port);

	READ_GUINT16_LE(n->data, req_speed);
	if (connection_speed < req_speed)
		return FALSE;				/* We're not fast enough */

	/*
	 * If we aren't going to let the searcher download anything, then
	 * don't waste bandwidth and his time by giving him search results.
	 *		--Mark Schreiber, 11/01/2002
     *
     * Also don't waste any time if we don't share a file.
     *      -- Richard, 9/9/2002
	 */

	if ((max_uploads == 0) || (files_scanned == 0))
		return FALSE;

	/*
	 * Perform search...
	 */

    gnet_stats_count_general(n, GNR_LOCAL_SEARCHES, 1);
	found_reset(n);

	max_replies = (search_max_items == -1) ? 255 : search_max_items;

	/*
	 * Search each SHA1.
	 */

	if (exv_sha1cnt) {
		gint i;

		for (i = 0; i < exv_sha1cnt && max_replies > 0; i++) {
			struct shared_file *sf;

			sf = shared_file_by_sha1(exv_sha1[i].sha1_digest);
			if (sf && sf != SHARE_REBUILDING) {
				got_match(sf);
				max_replies--;
				found_files++;
			}
		}
	}

	if (!skip_file_search) {
		gboolean is_utf8 = FALSE;
		gboolean ignore = FALSE;

		/*
		 * If the query string is UTF-8 encoded, decode it and keep only
		 * the characters in the ISO-8859-1 charset.
		 *		--RAM, 21/05/2002
		 */

		g_assert(search[search_len] == '\0');

		if (
			utf8_len == -1 &&
			!query_utf8_decode(search, search_len, &utf8_len, &offset)
		) {
			gnet_stats_count_dropped(n, MSG_DROP_MALFORMED_UTF_8);
			drop_it = TRUE;					/* Drop message! */
			goto finish;					/* Flush any SHA1 result we have */
		} else if (utf8_len)
			gnet_stats_count_general(n, GNR_QUERY_UTF8, 1);

		is_utf8 = utf8_len > 0;

		/*
		 * Because st_search() will apply a character map over the string,
		 * we always need to copy the query string to avoid changing the
		 * data inplace.
		 *
		 * `stmp_1' is a static buffer.  Note that we copy the trailing NUL
		 * into the buffer, hence the "+1" below.
		 */

		search_len -= offset;
		memcpy(stmp_1, search + offset, search_len + 1);

		if (is_utf8) {
			gint isochars;

			isochars = utf8_to_iso8859(stmp_1, search_len, TRUE);

			if (isochars != utf8_len)		/* Not fully ISO-8859-1 */
				ignore = TRUE;

			if (dbg > 4)
				printf("UTF-8 query, len=%d, utf8-len=%d, iso-len=%d: \"%s\"\n",
					search_len, utf8_len, isochars, stmp_1);
		}

		if (!ignore)
			found_files +=
				st_search(&search_table, stmp_1, got_match, max_replies);
	}

finish:
	if (found_files > 0) {
        gnet_stats_count_general(n, GNR_LOCAL_HITS, found_files);

		if (FOUND_FILES)			/* Still some unflushed results */
			flush_match();			/* Send last packet */

		if (dbg > 3) {
			printf("Share HIT %u files '%s'%s ", (gint) found_files,
				search + offset,
				skip_file_search ? " (skipped)" : "");
			if (exv_sha1cnt) {
				gint i;
				for (i = 0; i < exv_sha1cnt; i++)
					printf("\n\t%c(%32s)",
						exv_sha1[i].matched ? '+' : '-',
						sha1_base32(exv_sha1[i].sha1_digest));
				printf("\n\t");
			}
			printf("req_speed=%u ttl=%u hops=%u\n",
				   req_speed, (gint) n->header.ttl, (gint) n->header.hops);
			fflush(stdout);
		}
	}

	return drop_it;
}

/*
 * SHA1 digest processing
 */

/* 
 * This tree maps a SHA1 hash (base-32 encoded) onto the corresponding
 * shared_file if we have one.
 */

static GTree *sha1_to_share = NULL;

/* 
 * compare_share_sha1
 * 
 * Compare binary SHA1 hashes.
 * Return 0 if they're the same, a negative or positive number if s1 if greater
 * than s2 or s1 greater than s2, respectively.
 * Used to search the sha1_to_share tree.
 */

static int compare_share_sha1(const gchar *s1, const gchar *s2)
{
	return memcmp(s1, s2, SHA1_RAW_SIZE);
}

/* 
 * reinit_sha1_table
 * 
 * Reset sha1_to_share
 */

static void reinit_sha1_table()
{
	if (sha1_to_share)
		g_tree_destroy(sha1_to_share);

	sha1_to_share = g_tree_new((GCompareFunc) compare_share_sha1);
}

/* 
 * set_sha1
 * 
 * Set the SHA1 hash of a given shared_file. Take care of updating the
 * sha1_to_share structure. This function is called from inside the bowels of
 * sha1_server.c when it knows what the hash associated to a file is.
 */

void set_sha1(struct shared_file *f, const char *sha1)
{
	memcpy(f->sha1_digest, sha1, SHA1_RAW_SIZE);
	f->has_sha1_digest = TRUE;
	g_tree_insert(sha1_to_share, f->sha1_digest, f);
}

/*
 * sha1_hash_available
 * 
 * Predicate returning TRUE if the SHA1 hash is available for a given
 * shared_file, FALSE otherwise.
 */

gboolean sha1_hash_available(const struct shared_file *sf)
{
	return sf->has_sha1_digest;
}

/* 
 * shared_file_by_sha1
 * 
 * Take a given binary SHA1 digest, and return the corresponding
 * shared_file if we have it.
 */
struct shared_file *shared_file_by_sha1(const gchar *sha1_digest)
{
	struct shared_file *f;

	if (sha1_to_share == NULL)			/* Not even began share_scan() yet */
		return SHARE_REBUILDING;

	f = g_tree_lookup(sha1_to_share, (gpointer) sha1_digest);

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

