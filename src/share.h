#ifndef __share_h__
#define __share_h__

#include "nodes.h"

/* A file extension we have to share */
struct extension {
	gchar *str;			/* Extension string (e.g. "divx") */
	gint len;			/* Extension length (e.g. 4) */
};

/* XXX could be clever and share the file_directory's ... */
struct shared_file {
	gchar *file_name;
	gchar *file_directory;	/* The full path of the directory the file's in */
	/* lowercased path from the share_dir entry to the file */
	gchar *file_directory_path;
	guint32 file_index;			/* the files index withing out local DB */
	guint32 file_size;			/* File size in Bytes */
	gint file_name_len;
};

struct gnutella_search_results_out {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];

	/* Last 16 bytes = client_id */
};

/*
 * Global Data
 */

extern guint32 files_scanned, bytes_scanned, kbytes_scanned;
extern guint32 monitor_max_items, monitor_items;
extern GSList *extensions, *shared_dirs;

/*
 * Global Functions
 */

void share_init(void);
struct shared_file *shared_file(guint idx);
void share_scan(void);
void share_close(void);
void search_request(struct gnutella_node *n);
void parse_extensions(gchar *);
gint file_exists(gint, gchar *);
gchar *get_file_path(gint);
void shared_dirs_parse(gchar *);
void shared_dir_add(gchar *);
gint get_file_size(gint);

#endif /* __share_h__ */
