#ifndef _autodownload_h_
#define _autodownload_h_

extern int use_autodownload;
extern gchar *auto_download_file;

extern void autodownload_init();
extern void autodownload_notify(gchar * file, guint32 size,
                                guint32 record_index, guint32 ip,
                                guint16 port, gchar * guid, gboolean);

#endif /* _autodownload_h_ */

