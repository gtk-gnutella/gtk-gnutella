
/* Handle sharing of our own files */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <glib.h>

#include "gnutella.h"
#include "interface.h"

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

void shared_dirs_parse(gchar *str)
{
	gchar ** dirs = g_strsplit(str, ":", 0);
	guint i;

	GSList *l;

	if (shared_dirs)
	{
		l = shared_dirs;
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(shared_dirs);
		shared_dirs = NULL;
	}

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
 
void recurse_scan(gchar *dir)
{ 
 GSList *exts = NULL;
  DIR *directory;                                  /* Directory stream used by opendir, readdir etc.. */
  struct dirent *dir_entry;
  gchar *full = NULL , *sl = "/";

  struct shared_file *found = NULL;
  struct stat file_stat;

   if (!(directory = opendir(dir))) return;

  while ((dir_entry = readdir(directory))) {

    if (*dir+(strlen(dir)-1) ==  '/')
      full = g_strconcat(dir,  dir_entry->d_name, NULL);
    else
      full = g_strconcat(dir, sl, dir_entry->d_name, NULL);

  if (dir_entry->d_name[0] == '.') continue;

  if (is_directory(full)) { 

    if (*dir+(strlen(dir)-1) ==  '/')
      full = g_strconcat(dir, &dir_entry->d_name[1], sl, NULL);
    else
      full = g_strconcat(dir, dir_entry->d_name, sl, NULL);

    recurse_scan(full);}

    for (exts = extensions; exts; exts = exts->next) 
      if (strstr(dir_entry->d_name, exts->data)) {
	
	while (stat(full, &file_stat) == -1) {
	  printf("GTK_GNUTELLA: Can't stat."); continue; }

	found = (struct shared_file *)g_malloc0(sizeof(struct shared_file));

	found->file_name = strdup(dir_entry->d_name);
	found->file_directory = strdup(dir);
	found->file_size = file_stat.st_size;
	found->file_index = ++files_scanned;

	shared_files = g_slist_append(shared_files, found);

	bytes_scanned += file_stat.st_size;
	kbytes_scanned += bytes_scanned/1024;
	bytes_scanned %= 1024;

      }


  }
  closedir(directory);
}  



void share_scan(void)
{
	GSList *l;

	files_scanned = 0;
	bytes_scanned = 0;
	kbytes_scanned = 0;

	g_slist_free(shared_files); shared_files = NULL;

       	for (l = shared_dirs; l; l = l->next) recurse_scan((gchar *) l->data);
	gui_update_files_scanned();

}

void dejunk(char *str)
{
  
  int c = 0, x = 0;
  
  c = strlen(str);

  for (;x<c;x++)
    if (str[x] < 34 || str[x] > 125) str[x] = ' ';
 
  return;
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
  gchar *search, *search2 = NULL;
  guchar *found_data = NULL, *final = NULL;
  struct gnutella_header packet_head;
  struct gnutella_search_results_out search_head; 

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

	/* TODO find all our files that match the request, and send the list to the requester */

	search = n->data+2;
	
	if ((strlen(search) < 1)) return;

	dejunk(search);

	found_data = (guchar *)g_malloc0(1*sizeof(guchar));
	
	/* So far, searches just search for a string match, nothing fancy.. */

	for (files = shared_files; files; files = files->next)
	  {
	    
	    g_strdown(search);
	    
	    search2 = g_strdup( ((struct shared_file *)(*files).data)->file_name );
	    
	    g_strdown(search2);

	    if (strstr(search2, search)) {


	      /* Add to calling nodes found list. */
	      found_data = 
		g_realloc(found_data, (size+8+strlen(((struct shared_file *)(*files).data)->file_name)+2)*sizeof(guchar));

	      WRITE_GUINT32_LE( ((struct shared_file *)(*files).data)->file_index, &found_data[pos]);
	      
	      WRITE_GUINT32_LE( ((struct shared_file *)(*files).data)->file_size, &found_data[pos+4]);
	      
	      memcpy(&found_data[pos+8],((struct shared_file *)(*files).data)->file_name, 
		       strlen(((struct shared_file *)(*files).data)->file_name));

		/* the size of the search results header 8 bytes, plus the string length - NULL, plus two NULL's */ 
	      
		size += 8+strlen(((struct shared_file *)(*files).data)->file_name)+2;
	       

		pos = size-2;

		found_data[pos] = '\0'; found_data[pos+1] = '\0';
		
		/* Position equals the next byte to be writen to */
		pos += 2;

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
		if (((search_max_items != -1) && (found_files > search_max_items)) ||
			(found_files == 255)) 
		  {
			g_free(search2);
			break;
		  }

	    }
	    g_free(search2);

  	  }


	if (found_files > 0) {

	  found_data = g_realloc(found_data, size+16);
	  memcpy(&found_data[pos], &guid, 16);

	  /* the GUID size */
	  size += 16;
	  pos += 16;

	  /* Payload size including the search results header, actual results */
	  pl = size+sizeof(struct gnutella_search_results_out);

	  memcpy(&packet_head.muid, &(*n).header.muid, 16);

	  packet_head.function = GTA_MSG_SEARCH_RESULTS;
	  packet_head.ttl = my_ttl;
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
	  
	  g_free(final); g_free(found_data);
  	}
	return;
}

  


/* vi: set ts=3: */
