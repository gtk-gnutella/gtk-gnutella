#ifndef __hosts_h__
#define __hosts_h__

struct gnutella_host {
	guint32 ip;
	guint16 port;
	// guint32 files_count;			/* UNUSED --RAM */
	// guint32 kbytes_count;		/* UNUSED --RAM */
};

/*
 * Global Data
 */

extern GList *sl_catched_hosts;
extern struct ping_req *pr_ref;
extern gint hosts_idle_func;

/*
 * Global Functions
 */

void host_init(void);
gboolean find_host(guint32, guint16);
void host_remove(struct gnutella_host *, gboolean);
void host_add(struct gnutella_node *, guint32, guint16, gboolean);
void send_init(struct gnutella_node *);
void reply_init(struct gnutella_node *);
void ping_stats_add(struct gnutella_node *);
void ping_stats_update(void);
gboolean check_valid_host(guint32, guint16);
void hosts_read_from_file(gchar *, gboolean);
void hosts_write_to_file(gchar *);
void host_close(void);

#endif /* __hosts_h__ */
