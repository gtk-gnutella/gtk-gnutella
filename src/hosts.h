#ifndef __hosts_h__
#define __hosts_h__

struct gnutella_host {
	guint32 ip;
	guint16 port;
};

/*
 * Global Data
 */

extern GList *sl_caught_hosts;
extern struct ping_req *pr_ref;
extern gint hosts_idle_func;
extern guint32 hosts_in_catcher;
extern gboolean host_low_on_pongs;

/*
 * Global Functions
 */

void host_init(void);
void host_timer(void);
gboolean find_host(guint32, guint16);
void host_remove(struct gnutella_host *);
void host_save_valid(guint32 ip, guint16 port);
void host_add(guint32, guint16, gboolean);
void host_add_semi_pong(guint32 ip, guint16 port);
gint host_fill_caught_array(struct gnutella_host *hosts, gint hcount);
void host_get_caught(guint32 *ip, guint16 *port);
void ping_stats_add(struct gnutella_node *);
void ping_stats_update(void);
gboolean check_valid_host(guint32, guint16);
void hosts_read_from_file(gchar *, gboolean);
void hosts_write_to_file(gchar *);
void host_clear_cache(void);
void host_close(void);
struct gnutella_msg_init_response *build_pong_msg(
	guint8 hops, guint8 ttl, guchar *muid,
	guint32 ip, guint16 port, guint32 files, guint32 kbytes);
void send_alive_ping(struct gnutella_node *n);

void pcache_possibly_expired(time_t now);
void pcache_outgoing_connection(struct gnutella_node *n);
void pcache_ping_received(struct gnutella_node *n);
void pcache_pong_received(struct gnutella_node *n);
void pcache_pong_fake(struct gnutella_node *n, guint32 ip, guint16 port);

#endif /* __hosts_h__ */
