/*
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>		/* tolower() */

#include "gnutella.h"
#include "interface.h"
#include "gui.h"
#include "matching.h"
#include "share.h"
#include "sockets.h" /* For local_ip. (FIXME: move local_ip to config.h.) */
#include "misc.h"
#include "gmsg.h"
#include "huge.h"
#include "gtk-missing.h"
#include "utf8.h"
#include "qrp.h"

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

gchar stmp_1[4096];
gchar stmp_2[4096];

guint32 monitor_items = 0;

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
	guchar *d;		/* data */
	guint32 l;		/* data length */
	guint32 s;		/* size used by current search hit */
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

/* 
 * We don't want to include the same file several times in a reply (for
 * example, once because it matches an URN query and once because the file name
 * matches). So we keep track of what has been added in this tree. The file
 * index is used as the key.
 */

static GTree *index_of_found_files = NULL;
static gint index_of_found_files_count = 0;

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
static void found_reset()
{
	found_data.s = sizeof(struct gnutella_header) +	
		sizeof(struct gnutella_search_results_out);

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

#define FOUND_BUF	found_data.d
#define FOUND_SIZE	found_data.s

/*
 * Minimal trailer length is our code NAME, the open flags, and the GUID.
 */
#define QHIT_MIN_TRAILER_LEN	(4+3+16)	/* NAME + open flags + GUID */

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
}

struct shared_file *shared_file(guint idx)
{
	/* Return shared file info for index `idx', or NULL if none */

	if (file_table == NULL)			/* Rebuilding the library! */
		return SHARE_REBUILDING;

	if (idx < 1 || idx > files_scanned)
		return NULL;

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
		g_free(e->str);
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
				e->str = g_strdup(s);
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
			g_free(l->data);
			l = l->next;
		}
		g_slist_free(shared_dirs);
		shared_dirs = NULL;
	}
}

void shared_dirs_parse(gchar * str)
{
	gchar **dirs = g_strsplit(str, ":", 0);
	guint i;

	shared_dirs_free();

	i = 0;

	while (dirs[i]) {
		if (is_directory(dirs[i]))
			shared_dirs = g_slist_append(shared_dirs, g_strdup(dirs[i]));
		i++;
	}

	g_strfreev(dirs);
}

void shared_dir_add(gchar * path)
{
	if (!is_directory(path))
		return;

	shared_dirs = g_slist_append(shared_dirs, g_strdup(path));

	gui_update_shared_dirs();
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
	gchar *file_directory = NULL;
	GSList *files = NULL;
	gchar *dir_slash = NULL;
	GSList *l;

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

	/*
	 * Because we wish to optimize memory and only allocate the directory
	 * name once for all the files in the directory, we also need to have
	 * all the files for that same directory consecutively listed in the
	 * `shared_files' list, so that we can properly free the string in
	 * share_free() later on.
	 *
	 * In other words, we must process the sub-directories first, and then
	 * only the files.  To avoid traversing the directory twice and build
	 * all those full-name strings twice, we put files away in the `files'
	 * list and traverse directories first.
	 *
	 *		--RAM, 12/03/2002, with the help of Michael Tesch
	 */

	while ((dir_entry = readdir(directory))) {

		if (dir_entry->d_name[0] == '.')
			continue;

		full = g_strconcat(dir_slash, dir_entry->d_name, NULL);

		if (!is_directory(full)) {
			files = g_slist_prepend(files, full);
			continue;
		}

		/*
		 * Depth first traversal of directories.
		 */

		recurse_scan(full, basedir);
		g_free(full);
	}

	for (l = files; l; l = l->next) {
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
			 */

			if (*start == '.' && 0 == g_strcasecmp(start+1, e->str)) {

				if (stat(full, &file_stat) == -1) {
					g_warning("can't stat %s: %s", full, g_strerror(errno));
					break;
				}

				found = (struct shared_file *)
					g_malloc0(sizeof(struct shared_file));

				/*
				 * As long as we've got one file in this directory (so it'll be
				 * freed in share_free()), allocate these strings.
				 */

				if (!file_directory)
					file_directory = g_strdup(dir);

				found->file_name = g_strdup(name);
				found->file_name_len = name_len;
				found->file_directory = file_directory;
				found->file_size = file_stat.st_size;
				found->file_index = ++files_scanned;
				found->mtime = file_stat.st_mtime;
				found->sha1_digest[0] = '\0';
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

		if (!(files_scanned & 0x3f)) {
			gui_update_files_scanned();		/* Interim view */
			gtk_main_flush();
		}
	}

	closedir(directory);
	g_slist_free(files);

	if (dir_slash != dir)
		g_free(dir_slash);

	gui_update_files_scanned();		/* Interim view */
	gtk_main_iteration_do(FALSE);
}

static void share_free(void)
{
	GSList *l;
	gchar *last_dir = NULL;

	st_destroy(&search_table);

	if (file_table) {
		g_free(file_table);
		file_table = NULL;
	}

	if (shared_files) {
		struct shared_file *sf = shared_files->data;
		last_dir = sf->file_directory;
	}

	for (l = shared_files; l; l = l->next) {
		struct shared_file *sf = l->data;
		g_free(sf->file_name);
		if (last_dir && last_dir != sf->file_directory) {
			g_free(last_dir);
			last_dir = sf->file_directory;
		}
		g_free(sf);
	}
	if (last_dir)				/* free the last one */
		g_free(last_dir);

	g_slist_free(shared_files);
	shared_files = NULL;
}

static void reinit_sha1_table();

void share_scan(void)
{
	GSList *l;

	files_scanned = 0;
	bytes_scanned = 0;
	kbytes_scanned = 0;

	reinit_sha1_table();
	share_free();

	st_create(&search_table);

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

	for (l = shared_files; l; l = l->next) {
		struct shared_file *sf = l->data;
		g_assert(sf->file_index > 0 && sf->file_index <= files_scanned);
		file_table[sf->file_index - 1] = sf;
	}

	gui_update_files_scanned();		/* Final view */

/// XXX
	{
		struct timeval start, end;

		gettimeofday(&start, NULL);
		qrp_prepare_computation();

		for (l = shared_files; l; l = l->next) {
			struct shared_file *sf = l->data;
			qrp_add_file(sf);
		}

		qrp_finalize_computation();
		gettimeofday(&end, NULL);

		if (dbg)
			printf("QRP computation took: %d msec\n",
				(gint) ((end.tv_sec - start.tv_sec) * 1000 +
					(end.tv_usec - start.tv_usec) / 1000));
	}
}

void share_close(void)
{
	g_free(found_data.d);
	free_extensions();
	share_free();
	shared_dirs_free();
	huge_close();
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
	gboolean sha1_available = *sf->sha1_digest;
	
	/*
	 * We don't stop adding records if we refused this one, hence the TRUE
	 * returned.
	 */

	if (shared_file_already_in_found_set(sf))
		return TRUE;

	put_shared_file_into_found_set(sf);

	if (sha1_available)
		needed += 8 + SHA1_BASE32_SIZE;

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
		memcpy(&FOUND_BUF[pos], "urn:sha1:", 8);
		pos += 8;
		memcpy(&FOUND_BUF[pos], sf->sha1_digest, SHA1_BASE32_SIZE);
		pos += SHA1_BASE32_SIZE;
	}

	FOUND_BUF[pos++] = '\0';

	return TRUE;		/* Hit entry accepted */
}

#define FS (0x1c) /* Field separator (used to separate query extensions) */

/* A structure describing the extensions found in the query */

struct query_extensions {
	int unknown;       /* Number of unknown extensions   */
	const gchar *urn;  /* Query by urn, only one for now */
};

/*
 * initialize_query_extension
 * 
 * Initialize a struct query_extension
 */
static void initialize_query_extension(struct query_extensions *e)
{
	e->unknown = 0;
	e->urn = NULL; 
}

/*
 * extension_embeds_binary
 * 
 * Return TRUE if string extension of length extension_length embeds a
 * non-printable char, FALSE otherwise
 */
static gboolean extension_embeds_binary(
	const unsigned char *extension, int extension_length)
{
	for(; extension_length; extension_length--, extension++)
		if (!isprint(*extension)) return TRUE;
	return FALSE;
}

/* 
 * check_query_extension
 * 
 * Take the extension extension of length extension_length, and update the
 * struct query_extensions with recognized extensions.
 */
static void check_query_extension(
	const char *extension, int extension_length, struct query_extensions *qe)
{
	if (extension_length == 9 + SHA1_BASE32_SIZE
		&& !strncmp(extension, "urn:sha1:", 9)) {

		qe->urn = extension + 9;
		if (dbg > 4) {
			fprintf(stdout, "\tQuery by URN\t");
			fwrite(extension, extension_length, 1, stdout);
			fprintf(stdout, "\n");
		}

	} else if (extension_length == 4 && !strncmp(extension, "urn:", 4)) {
		; /* We always send URN for now */
	} else {
		qe->unknown++;
		if (dbg > 4) {
			if (!extension_embeds_binary(extension, extension_length)) {
				fprintf(stdout, "<%d:", extension_length);
				fwrite(extension, extension_length, 1, stdout);
				fprintf(stdout, ">\n");
			} else 
				dump_hex(stdout, "Binary extension",
					(char *)extension, extension_length);
		}
	}
}

/* 
 * scan_query_extensions
 * 
 * Scan extensions one by one (they're pointed to by extra and NUL-terminated)
 * and update the struct query_extensions with recognized extensions.
 */

static void scan_query_extensions(
	const char *extra,
	struct query_extensions *extension)
{
	for(;;) {
		const char *last_ext = extra;
		while(*extra && *extra != FS) extra++;
		check_query_extension(last_ext, extra - last_ext, extension);
		if (!*extra)
			break;
		extra++;
	}

	return;
}

/*
 * Searches requests (from others nodes) 
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the LL.
 */
void search_request(struct gnutella_node *n)
{
	guchar found_files = 0;
	guint32 pos, pl;
	guint16 req_speed;
	gchar *search;
	struct gnutella_header *packet_head;
	struct gnutella_search_results_out *search_head;
	guint32 search_len;
	gchar trailer[10];
	struct query_extensions query_extension;
	guint32 max_replies;
	gint urn_match = 0;
	gboolean skip_file_search = FALSE;

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
			search_len++;

		if (search_len > max_len) {
			g_warning("search request (hops=%d, ttl=%d) had no NUL (%d byte%s)",
				n->header.hops, n->header.ttl, n->size - 2,
				n->size == 3 ? "" : "s");
			g_assert(n->data[n->size - 1] != '\0');
			if (dbg > 4)
				dump_hex(stderr, "Search Text", search, MIN(n->size - 2, 256));
			n->data[n->size - 1] = '\0';	/* Force a NUL */
			search_len = max_len;			/* And we truncated it */
		}

		/* We can now use `search' safely as a C string: it embeds a NUL */
	}

	/*
	 * We don't handle extra search data yet, but trace them.
	 *
	 * We ignore double-NULs on search (i.e. one extra byte and it's NUL).
	 * This is not needed, but some servent do so.
	 */

	initialize_query_extension(&query_extension);

	if (search_len + 3 != n->size) {
		gint extra = n->size - 3 - search_len;		/* Amount of extra data */
		if (extra != 1 && search[search_len+1] != '\0') {
			/* Not a double NUL */
			scan_query_extensions(search + search_len + 1, &query_extension);

			if (query_extension.unknown) {
				g_warning("search request (hops=%d, ttl=%d) "
					"has %d extra byte%s after NUL",
					n->header.hops, n->header.ttl, extra,
					extra == 1 ? "" : "s");
				if (dbg > 4) {
					dump_hex(stdout, "Extra Query Data", &search[search_len+1],
						MIN(extra, 256));
					printf("Search was: %s\n", search);
				}
			}

			if (dbg > 3 && query_extension.urn && !query_extension.unknown)
				printf("URN search was: %s\n", search);
		}
	}

	if (monitor_enabled) {		/* Update the search monitor */
		gchar *titles[1];

		gtk_clist_freeze(GTK_CLIST(clist_monitor));

		if (monitor_items < monitor_max_items)
			monitor_items++;
		else
			gtk_clist_remove(GTK_CLIST(clist_monitor),
							 GTK_CLIST(clist_monitor)->rows - 1);

		titles[0] = n->data + 2;

		gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);

		gtk_clist_thaw(GTK_CLIST(clist_monitor));
	}

	READ_GUINT16_LE(n->data, req_speed);

	if (connection_speed < req_speed)
		return;					/* We're not fast enough */

	/*
	 * If we aren't going to let the searcher download anything, then
	 * don't waste bandwidth and his time by giving him search results.
	 *		--Mark Schreiber, 11/01/2002
	 */

	if (max_uploads == 0)
		return;

	/*
	 * If the query comes from a node farther than our TTL (i.e. the TTL we'll
	 * use to send our reply), don't bother processing it: the reply won't
	 * be able to reach the issuing node.
	 *
	 * However, not that for replies, we use our maximum configured TTL, so
	 * we compare to that, and not to my_ttl, which is the TTL used for
	 * "standard" packets.
	 *
	 *				--RAM, 12/09/2001
	 */

	if (n->header.hops > max_ttl)
		return;

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

	if (!query_extension.urn && skip_file_search)
		return;

	/*
	 * Perform search...
	 */

	global_searches++;
	found_reset();

	max_replies = (search_max_items == -1) ? 255 : search_max_items;

	if (query_extension.urn) {
		struct shared_file *sf =
			shared_file_from_sha1_hash(query_extension.urn);

		if (sf) {
			got_match(sf);
			if (dbg)
				printf("********* YYYYEEEESSSS !!!! AN URN MATCH !!!! (%s)\n",
					query_extension.urn);
			max_replies--;
			urn_match++;
		}
	}

	if (skip_file_search)
		found_files = urn_match;
	else {
		gint clen;
		gboolean ignore = FALSE;

		/*
		 * If the query string is UTF-8 encoded, decode it and keep only
		 * the characters in the ISO-8859-1 charset.
		 * NB: we use `search_len+1' chars to include the trailing NUL.
		 *		--RAM, 21/05/2002
		 */

		g_assert(search[search_len] == '\0');

		clen = utf8_is_valid_string(search, search_len+1);

		if (clen && clen != (search_len+1)) {		/* Not pure ASCII */
			gint isochars = utf8_to_iso8859(search, search_len+1, TRUE);

			if (isochars != clen)		/* Not fully ISO-8859-1 */
				ignore = TRUE;

			if (dbg > 4)
				printf("UTF-8 query, len=%d, chars=%d, iso=%d: \"%s\"\n",
					search_len, clen, isochars, search);
		}

		found_files = urn_match +
			st_search(&search_table, search, got_match, max_replies);
	}

	if (found_files > 0) {

		if (dbg > 3) {
			printf("Share HIT %u files '%s'%s ", (gint) found_files, search,
				skip_file_search ? " (skipped)" : "");
			if (query_extension.urn)
				printf("%c(%s) ", urn_match ? '+' : '-', query_extension.urn);
			printf("req_speed=%u ttl=%u hops=%u\n",
				   req_speed, (gint) n->header.ttl, (gint) n->header.hops);
			fflush(stdout);
		}

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

		search_head->num_recs = found_files;	/* One byte, little endian! */

		WRITE_GUINT16_LE(listen_port, search_head->host_port);
		WRITE_GUINT32_BE(listen_ip(), search_head->host_ip);
		WRITE_GUINT32_LE(connection_speed, search_head->host_speed);

		gmsg_sendto_one(n, FOUND_BUF, FOUND_SIZE);
	}

	return;
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
 * Compare to base-32 encoded SHA1 hashes.
 * Return 0 if they're the same, a negative or positive number if s1 if greater
 * than s2 or s1 greater than s2, respectively.
 * Used to search the sha1_to_share tree.
 */

static int compare_share_sha1(const gchar *s1, const gchar *s2)
{
	return memcmp(s1, s2, SHA1_BASE32_SIZE);
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

	sha1_to_share = g_tree_new((GCompareFunc)compare_share_sha1);
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
	memcpy(f->sha1_digest, sha1, SHA1_BASE32_SIZE);
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
	return *sf->sha1_digest;
}

/* 
 * shared_file_from_sha1_hash
 * 
 * Take a given base-32 encoded SHA1 hash, and return the corresponding
 * shared_file if we have it.
 */
struct shared_file *shared_file_from_sha1_hash(const gchar *sha1_digest)
{
	struct shared_file *f = g_tree_lookup(sha1_to_share,(gpointer)sha1_digest);

	if (!f)
		return NULL;

	if (!sha1_hash_available(f))
		return NULL;

	return f;
}

/* 
 * Emacs stuff:
 * Local Variables: ***
 * c-indentation-style: "bsd" ***
 * fill-column: 80 ***
 * tab-width: 4 ***
 * indent-tabs-mode: nil ***
 * End: ***
 */

/* vi: set ts=4: */
