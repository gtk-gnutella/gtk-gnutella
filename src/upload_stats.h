#ifndef __upload_stats_h__
#define __upload_stats_h__

#include <glib.h>

#include "uploads.h"

gint compare_ul_size(GtkCList *, gconstpointer, gconstpointer);
gint compare_ul_attempts(GtkCList *, gconstpointer, gconstpointer);
gint compare_ul_complete(GtkCList *, gconstpointer, gconstpointer);
void ul_stats_load_history(const gchar *);
void ul_stats_dump_history(const gchar *filename, gboolean cleanup);
void ul_flush_stats_if_dirty(void);
void ul_stats_file_begin(const struct upload *);
void ul_stats_file_complete(const struct upload *);
void ul_stats_prune_nonexistant();
void ul_stats_clear_all();

/*
 * GUI column indices.
 */

#define UL_STATS_FILE_IDX		0
#define UL_STATS_SIZE_IDX		1
#define UL_STATS_ATTEMPTS_IDX	2
#define UL_STATS_COMPLETE_IDX	3

#endif
