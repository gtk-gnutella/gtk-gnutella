
/* Handle sharing of our own files */

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

#define FOUND_RESET() do {							\
	found_data.s = sizeof(struct gnutella_header) +	\
		 sizeof(struct gnutella_search_results_out);\
} while (0)

#define FOUND_BUF	found_data.d
#define FOUND_SIZE	found_data.s

/*
 * Minimal trailer length is our code NAME, the open flags, and the GUID.
 */
#define QHIT_MIN_TRAILER_LEN	(4+3+16)	/* NAME + open flags + GUID */

/* ----------------------------------------- */

static void setup_char_map(char_map_t map)
{
	/* set up keymapping table for Gnutella */

	gint cur_char;	

	for (cur_char = 0; cur_char < 256; cur_char++)
		map[cur_char] = '\0';
	
	for (cur_char = 0; cur_char < 256; cur_char++)	{
		if (islower(cur_char)) {
			map[cur_char] = cur_char;
			map[toupper(cur_char)] = cur_char;
		}
		else if (isupper(cur_char))
			; /* handled by previous case */
		else if (ispunct(cur_char) || isspace(cur_char))
			map[cur_char] = ' ';
		else if (isdigit(cur_char))
			map[cur_char] = cur_char;
		else if (isalnum(cur_char))
			map[cur_char] = cur_char;
		else
			map[cur_char] = ' ';	/* unknown in our locale */
	}
}

static void search_table_init(void)
{
	char_map_t map;

	setup_char_map(map);
	st_initialize(&search_table, map);
}

/* ----------------------------------------- */

void share_init(void)
{
	search_table_init();
	share_scan();
	found_data.l = FOUND_CHUNK;		/* must be > size after FOUND_RESET */
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

				st_insert_item(&search_table, found->file_name, found);
				shared_files = g_slist_append(shared_files, found);

				bytes_scanned += file_stat.st_size;
				kbytes_scanned += bytes_scanned >> 10;
				bytes_scanned &= (1 << 10) - 1;
				break;			/* for loop */
			}
		}
		g_free(full);

		if (!(files_scanned & 0x1f)) {
			gui_update_files_scanned();		/* Interim view */
			gtk_main_iteration_do(FALSE);
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

void share_scan(void)
{
	GSList *l;

	files_scanned = 0;
	bytes_scanned = 0;
	kbytes_scanned = 0;

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
}

void share_close(void)
{
	g_free(found_data.d);
	free_extensions();
	share_free();
	shared_dirs_free();
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

	WRITE_GUINT32_LE(sf->file_index, &FOUND_BUF[pos]);
	WRITE_GUINT32_LE(sf->file_size, &FOUND_BUF[pos + 4]);

	memcpy(&FOUND_BUF[pos + 8], sf->file_name, sf->file_name_len);

	/* Position equals the next byte to be writen to */
	pos = FOUND_SIZE - 2;

	FOUND_BUF[pos++] = '\0';
	FOUND_BUF[pos++] = '\0';

	return TRUE;		/* Hit entry accepted */
}

/* Searches requests (from others nodes) 
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

	if (search_len + 3 != n->size) {
		gint extra = n->size - 3 - search_len;		/* Amount of extra data */
		if (extra != 1 && search[search_len+1] != '\0') {
			/* Not a double NUL */
			g_warning("search request (hops=%d, ttl=%d) "
				"has %d extra byte%s after NUL",
				n->header.hops, n->header.ttl, extra, extra == 1 ? "" : "s");
			if (dbg > 4)
				dump_hex(stderr, "Extra Query Data", &search[search_len+1],
					MIN(extra, 256));
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

	if (search_len <= 1)
		return;

	/*
	 * If requester if farther than 3 hops. save bandwidth when returning
	 * lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 *
	 * Notes from RAM, 09/09/2001:
	 * 1) The hop amount must be made configurable.
	 * 2) We can add a config option to forbid forwarding of such queries.
	 */

	if (search_len < 5 && n->header.hops > 3)
		return;

	/*
	 * Perform search...
	 */

	global_searches++;
	FOUND_RESET();

	found_files = st_search(&search_table, search, got_match,
		(search_max_items == -1) ? 255 : search_max_items);

	if (found_files > 0) {

		if (dbg > 3) {
			printf("Share HIT %u files '%s' req_speed=%u ttl=%u hops=%u\n",
				   (gint) found_files, search, req_speed,
				   (gint) n->header.ttl, (gint) n->header.hops);
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

/* vi: set ts=4: */

