
/* Handle sharing of our own files */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>

#include "gnutella.h"
#include "interface.h"
#include "matching.h"

guint32 files_scanned = 0;
guint32 kbytes_scanned = 0;
guint32 bytes_scanned = 0;


GSList *extensions = NULL;
GSList *shared_dirs = NULL;
GSList *shared_files = NULL;


gchar stmp_1[4096];
gchar stmp_2[4096];

guint32 monitor_items = 0;

/* ------------------------------------------------------------------------------------------------ */

void share_init(void)
{
	share_scan();
}

/* Get the file extensions to scan */

void parse_extensions(gchar *str)
{
	gchar ** exts = g_strsplit(str, ";", 0);
	gchar *x, *s;
	guint i, e;
	GSList *l;

	if (extensions)
	{
		l = extensions;
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(extensions);
		extensions = NULL;
	}

	e = i = 0;

	while (exts[i])
	{
		s = exts[i];
		while (*s == ' ' || *s == '\t' || *s == '.' || *s == '*' || *s == '?') s++;
		if (*s)
		{
			x = s + strlen(s);
			while (--x > s && (*x == ' ' || *x == '\t' || *x == '*' || *x == '?')) *x = 0;
			if (*s) extensions = g_slist_append(extensions, g_strdup(s));
		}
		i++;
	}

	g_strfreev(exts);
}

/* Shared dirs */

static void shared_dirs_free(void)
{
	if (shared_dirs)
	{
		GSList *l = shared_dirs;
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(shared_dirs);
		shared_dirs = NULL;
	}
}

void shared_dirs_parse(gchar *str)
{
	gchar ** dirs = g_strsplit(str, ":", 0);
	guint i;

	shared_dirs_free();

	i = 0;

	while (dirs[i])
	{
		if (is_directory(dirs[i])) shared_dirs = g_slist_append(shared_dirs, g_strdup(dirs[i]));
		i++;
	}

	g_strfreev(dirs);
}

void shared_dir_add(gchar *path)
{
	if (!is_directory(path)) return;

	shared_dirs = g_slist_append(shared_dirs, g_strdup(path));

	gui_update_shared_dirs();
}

/* recurse_scan();
 *The directories that are given as shared will be completly transversed
 *including all files and directories. An entry of "/" would search the
 *the whole file system.
 */
 
void recurse_scan(gchar *dir, gchar *basedir)
{ 
 GSList *exts = NULL;
  DIR *directory;                                  /* Directory stream used by opendir, readdir etc.. */
  struct dirent *dir_entry;
  gchar *full = NULL , *sl = "/";
  gchar *file_directory = NULL;
  gchar *file_directory_path = NULL;

  struct shared_file *found = NULL;
  struct stat file_stat;

  if (!(directory = opendir(dir))) return;

  while ((dir_entry = readdir(directory))) {

	if (dir_entry->d_name[0] == '.') continue;

    if (dir[strlen(dir)-1] ==  '/')
      full = g_strconcat(dir,  dir_entry->d_name, NULL);
    else
      full = g_strconcat(dir, sl, dir_entry->d_name, NULL);

	if (is_directory(full)) {
	  g_free(full);
	  if (dir[strlen(dir)-1] ==  '/')
		full = g_strconcat(dir, dir_entry->d_name, sl, NULL);
	  else
		full = g_strconcat(dir, sl, dir_entry->d_name, sl, NULL);

	  recurse_scan(full, basedir);
	  g_free(full);
	  continue;
	}

	/* XXX Could make use of pattern matching, would speed up scanning */

	for (exts = extensions; exts; exts = exts->next) 
	  if (strstr(dir_entry->d_name, exts->data)) {

		if (stat(full, &file_stat) == -1) {
		  g_warning("Can't stat %s: %s", full, g_strerror(errno));
		  break;
		}

		found = (struct shared_file *)g_malloc0(sizeof(struct shared_file));

		/* As long as we've got one file in this directory (so it'll be
		 * freed in share_free()), allocate these strings.
		 */
		if(!file_directory)
		  file_directory = g_strdup(dir);
		if(!file_directory_path) {
		  file_directory_path = g_strdup(dir + strlen(basedir));
		  g_strdown(file_directory_path);
		}

		found->file_name = g_strdup(dir_entry->d_name);
		found->file_name_lowercase = g_strdup(found->file_name);
		g_strdown(found->file_name_lowercase);
		found->file_name_len = strlen(dir_entry->d_name);
		found->file_directory = file_directory;
		found->file_directory_path = file_directory_path;
		found->file_size = file_stat.st_size;
		found->file_index = ++files_scanned;

		shared_files = g_slist_append(shared_files, found);

		bytes_scanned += file_stat.st_size;
		kbytes_scanned += bytes_scanned/1024;
		bytes_scanned %= 1024;
		break; /* for loop */
	  }
	g_free(full);
  }
  closedir(directory);
  gui_update_files_scanned();		/* Avoid frozen GUI, update often -- RAM */
}  

static void share_free(void)
{
	GSList *l;
	gchar *last_dir = NULL, *last_lower_dir = NULL;

	for (l = shared_files; l; l = l->next) {
	  struct shared_file *sf = l->data;
	  g_free(sf->file_name);
	  g_free(sf->file_name_lowercase);
	  if(last_dir && strcmp(last_dir, sf->file_directory)) {
		g_free(last_dir);
		last_dir = sf->file_directory;
	  }
	  if(last_lower_dir && strcmp(last_lower_dir, sf->file_directory_path)) {
		g_free(last_lower_dir);
		last_lower_dir = sf->file_directory_path;
	  }
	  g_free(sf);
	}
	if(last_lower_dir) /* free the last one */
	  g_free(last_lower_dir);
	if(last_dir)
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

	for (l = shared_dirs; l; l = l->next)
	  recurse_scan(l->data, l->data);
}

void share_close(void)
{
	share_free();
	shared_dirs_free();
}

/*
 * dejunk
 *
 * Remove non-ascii characters (replacing them with spaces) inplace.
 * Returns string length.
 */
static guint32 dejunk(guchar *str)
{
	guchar *s = str;
	guint32 len = 0;
	guchar c;

	/*
	 * XXX I believe we should remove accents, assuming iso-latin-1.
	 * XXX And we should also remove them from lowercases file names, on
	 * XXX which we conduct searches -- RAM, 11/09/2001.
	 */

	while ((c = *s++)) {
		len++;
		if (c < 34 || c > 125) *(s-1) = ' ';
	}

	return len;
}


/*
 * Apply pattern matching on text, matching at the *beginning* of words.
 */

static gboolean share_match(
	gchar *text, gint tlen, cpattern_t **pw, word_vec_t *wovec, gint wn)
{
	gint i;

	for (i = 0; i < wn; i++) {
		gint amount = wovec[i].amount;
		gint j;
		guint32 offset = 0;
		for (j = 0; j < amount; j++) {
			char *pos = pattern_qsearch(pw[i], text, tlen, offset, qs_begin);
			if (pos)
				offset = (pos - text) + pw[i]->len;
			else
				break;
		}
		if (j != amount)	/* Word does not occur as many time as we want */
			return FALSE;
	}

	return TRUE;
}

/* Searches requests (from others nodes) 
 * Basic matching. The search request is made lowercase and
 * is matched to the filenames in the LL.
*/

void search_request(struct gnutella_node *n)
{

  GSList *files = NULL;
  guchar found_files = 0;
  guint32 size = 0, pos = 0, pl = 0;
  guint16 req_speed;
  gchar *search;
  guchar *found_data = NULL, *final = NULL;
  struct gnutella_header packet_head;
  struct gnutella_search_results_out search_head; 
  gchar *last_dir = NULL;
  guint32 search_len;
  gchar trailer[10];

  /* pattern matching */
  gint i;
  word_vec_t *wovec;
  guint wocnt;
  cpattern_t **pattern;

	global_searches++;

	if (monitor_enabled)	/* Update the search monitor */
	{
		gchar *titles[1];

		gtk_clist_freeze(GTK_CLIST(clist_monitor));

		if (monitor_items < monitor_max_items) monitor_items++;
		else gtk_clist_remove(GTK_CLIST(clist_monitor), GTK_CLIST(clist_monitor)->rows - 1);

		titles[0] = n->data + 2;

		gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);

		gtk_clist_set_selectable (GTK_CLIST(clist_monitor), 0, FALSE);

		gtk_clist_thaw(GTK_CLIST(clist_monitor));
	}

	READ_GUINT16_LE(n->data, req_speed);

	if (connection_speed < req_speed) return;	/* We're not fast enough */

	/*
	 * If the query comes from a node farther than our TTL (i.e. the TTL we'll
	 * use to send our reply), don't bother processing it: the reply won't
	 * be able to reach the issuing node.
	 *
	 * However, not that for replies, we use our maximum configured TTL, so
	 * we compare to that, and not to my_ttl, which is the TTL used for
	 * "standard" packets.
	 *
	 *		--RAM, 12/09/2001
	 */

	if (n->header.hops > max_ttl)
		return;

	search = n->data+2;
	search_len = dejunk(search);

	if (search_len <= 1) return;

	/*
	 * If requester if farther than 3 hops. save bandwidth when returning
	 * lots of hits from short queries, which are not specific enough.
	 * The idea here is to give some response, but not too many.
	 *
	 * Notes from RAM, 09/09/2001:
	 * 1) The hop amount must be made configurable.
	 * 2) We can add a config option to forbid forwarding of such queries.
	 */

	if (search_len < 5 && n->header.hops > 3) return;

	/*
	 * Prepare matching patterns --RAM, 11/09/2001
	 *
	 * When query_make_word_vec() returns no word, we can return immediately
	 * as no memory has been allocated.
	 */

	g_strdown(search);
	wocnt = query_make_word_vec(search, &wovec);
	if (wocnt == 0) return;
	pattern = (cpattern_t **) g_malloc(wocnt * sizeof(cpattern_t *));

	for (i = 0; i < wocnt; i++)
		pattern[i] = pattern_compile(wovec[i].word);

	found_data = (guchar *)g_malloc0(1*sizeof(guchar));

	for (files = shared_files; files; files = files->next) {
	    struct shared_file *sf = (struct shared_file *)files->data;
	    
		if (dbg > 7) printf("search %s, directory %s\n",
			search, ((struct shared_file *)(*files).data)->file_directory);

		/*
		 * Old code used to attempt matches on directory names, not only on
		 * files.  That makes sense when you store your files by directory,
		 * and don't repeat the directory name in the files, to keep them
		 * shorter.
		 *
		 * But Gnutella does not specifies that, so let's not do it.  Besides,
		 * it could send back irrelevant files.
		 *
		 *	--RAM, 09/09/2001
		 */

		if(last_dir != sf->file_directory_path)
		  last_dir = sf->file_directory_path;

		/*
		 * Apply pattern matching --RAM, 11/09/2001
		 */

		if (
			share_match(
				sf->file_name_lowercase, sf->file_name_len,
				pattern, wovec, wocnt)
		) {

	      /* Add to calling nodes found list. */
	      found_data = 
			g_realloc(found_data, (size + 8 + sf->file_name_len + 2)*sizeof(guchar));

	      WRITE_GUINT32_LE( sf->file_index, &found_data[pos]);
	      
	      WRITE_GUINT32_LE( sf->file_size, &found_data[pos+4]);
	      
	      memcpy(&found_data[pos + 8], sf->file_name, sf->file_name_len);

		/* the size of the search results header 8 bytes, plus the string length - NULL, plus two NULL's */ 
	      
		size += 8 + sf->file_name_len + 2;

		/* Position equals the next byte to be writen to */
		pos = size - 2;

		found_data[pos++] = '\0'; found_data[pos++] = '\0';
		found_files++; 
		
		/* Allow -1 to mean unlimited, and 0 to avoid returning any results
		 * (but not now, since this check happens after one has been found
		 * one.)
		 *
		 * XXX longer term, just use a checkbox: "[] limit searches to ______ results"
		 */

		/* Also, can't fit more than 255 results into a response packet.
		 * This can go away when we can send more than one packet per
		 * search. 
		 */
		if (((search_max_items != -1) && (found_files >= search_max_items)) ||
			(found_files == 255)) {
			break;
		  }
	    }
  	  }

	if (found_files > 0) {

		if (dbg > 3) {
			printf("Share HIT %u files '%s' words=%d "
				"req_speed=%u ttl=%u hops=%u\n",
				(gint)found_files, search, wocnt, req_speed,
				(gint)n->header.ttl, (gint)n->header.hops);
			fflush(stdout);
		}

		/*
		 * Build Gtk-gnutella trailer.
		 * It is compatible with BearShare's one in the "open data" section.
		 */

		strncpy(trailer, "GTKG", 4);		/* Vendor code */
		trailer[4] = 2;						/* Open data size */
		trailer[5] = 0x04|0x08;				/* Valid flags we set */
		trailer[6] = 0;						/* Our flags */

		if (running_uploads >= max_uploads)
			trailer[6] |= 0x04;				/* Busy flag */
		if (count_uploads > 0)
			trailer[6] |= 0x08;				/* One file uploaded, at least */

		found_data = g_realloc(found_data, size+16+6);
		memcpy(&found_data[pos], &trailer, 6);		/* Store trailer */
		pos += 6;
		memcpy(&found_data[pos], &guid, 16);		/* Store the GUID */
		pos += 16;
		size += 22;							/* Trailer + GUID */

	  /* Payload size including the search results header, actual results */
	  pl = size+sizeof(struct gnutella_search_results_out);

	  memcpy(&packet_head.muid, &(*n).header.muid, 16);

	 /*
	  * We apply the same logic here as in reply_init(): we limit the TTL
	  * to the minimal possible value.
	  *		--RAM, 15/09/2001
	  */

	  if (n->header.hops == 0) {
	  	  g_warning("search_request(): hops=0, bug in route_message()?\n");
		  n->header.hops++;		/* Can't send message with TTL=0 */
	  }

	  packet_head.function = GTA_MSG_SEARCH_RESULTS;
	  packet_head.ttl = MIN(n->header.hops, max_ttl);
	  packet_head.hops = 0;
	  memcpy(&packet_head.size, &pl, 4);
    

	  memcpy(&search_head.num_recs, &found_files , 1);

	  WRITE_GUINT16_LE(listen_port, search_head.host_port);

	  WRITE_GUINT32_BE(force_local_ip ? forced_local_ip : local_ip, search_head.host_ip);

	  WRITE_GUINT32_LE(connection_speed, search_head.host_speed);

 	  final = (guchar *)g_malloc0(size+sizeof(struct gnutella_header)+sizeof(struct gnutella_search_results_out));

	  memcpy(final, &packet_head , sizeof(struct gnutella_header));

	  memcpy(&final[sizeof(struct gnutella_header)], &search_head , sizeof(struct gnutella_search_results_out));

	  memcpy(&final[sizeof(struct gnutella_header)+sizeof(struct gnutella_search_results_out)], found_data , size); 

	  sendto_one(n, (guchar *)final, NULL, size+sizeof(struct gnutella_header)+sizeof(struct gnutella_search_results_out));
	  
	  g_free(final);
  	}

	g_free(found_data);
	for (i = 0; i < wocnt; i++)
		pattern_free(pattern[i]);
	g_free(pattern);
	query_word_vec_free(wovec, wocnt);

	return;
}

/* vi: set ts=3: */
