/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
 *
 * GUI stuff used by share.c
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

#include "gui.h"
#include "statusbar_gui.h"

RCSID("$Id$");

/*
 * Timeout entry for statusbar messages.
 */
typedef struct statusbar_timeout {
    statusbar_msgid_t id; /* message id of the message */
	time_t timeout; /* time after which the message should be removed */
} statusbar_timeout_t;

/*
 * statusbar context ids 
 */
guint scid_bottom              = (guint) -1;
guint scid_hostsfile           = (guint) -1;
guint scid_search_autoselected = (guint) -1;
guint scid_queue_freezed       = (guint) -1;
guint scid_info                = (guint) -1;
guint scid_ip_changed          = (guint) -1;
guint scid_warn                = (guint) -1;

/* 
 * List with timeout entries for statusbar messages 
 */
static GSList *sl_statusbar_timeouts = NULL;

/*
 * Status bar
 */
static gchar *statbar_botstr = NULL;
static gchar *statbar_botstr_new = NULL;

static void statusbar_gui_free_timeout(struct statusbar_timeout * t);
static void statusbar_gui_free_timeout_list(void);
static void statusbar_gui_add_timeout(statusbar_msgid_t, guint timeout);

void statusbar_gui_init(void)
{
    GtkStatusbar *statusbar;

    statusbar = GTK_STATUSBAR
        (lookup_widget(main_window, "statusbar"));

    /* statusbar stuff */
	scid_bottom    = 
		gtk_statusbar_get_context_id(statusbar, "default");
	scid_hostsfile = 
		gtk_statusbar_get_context_id(statusbar, "reading hosts file");
	scid_search_autoselected = 
		gtk_statusbar_get_context_id(statusbar, "autoselected search items");
	scid_queue_freezed = 
		gtk_statusbar_get_context_id(statusbar, "queue freezed");	

   	scid_info = 
		gtk_statusbar_get_context_id(statusbar, "information");	

    scid_ip_changed =
        gtk_statusbar_get_context_id(statusbar, "ip changed");

    scid_warn =
        gtk_statusbar_get_context_id(statusbar, "warning");

   	/*
	 * This message lies at the bottom of the statusbar, and is never removed,
	 * but to be replaced by an updated message.
	 *
	 * The current string held at the bottom is stored in `statbar_botstr'.
	 * If a new string is pending replacement in `statbar_botstr_new', then
	 * it will replace the current one when the last timeout for pushed
	 * messages expires, at which time we'll know the bottom message is shown.
	 *		--RAM, 27/06/2002
	 */

	statbar_botstr = g_strdup(GTA_WEBSITE);
	statusbar_gui_push(SB_MESSAGE, scid_bottom, 0, statbar_botstr);
}

void statusbar_gui_shutdown(void)
{
    statusbar_gui_free_timeout_list();

	if (statbar_botstr_new)
		g_free(statbar_botstr_new);
	if (statbar_botstr)
		g_free(statbar_botstr);

}

void statusbar_gui_set_default(const char *format, ...)
{
    static gchar buf[1024];
    va_list args;

    va_start(args, format);

    if (statbar_botstr_new != NULL)
        g_free(statbar_botstr_new);

    if (format != NULL) {
        gm_vsnprintf(buf, sizeof(buf), format, args);
        statbar_botstr_new = g_strdup(buf);
    } else {
        statbar_botstr_new = g_strdup(GTA_WEBSITE);
    }

    va_end(args);
}

/*
 * statusbar_gui_message:
 *
 * Put a message on the statusbar. The message will by displayed for
 * a number of seconds given by timeout. If timeout is 0 the message
 * will not be automatically removed.
 *
 * Returns: message id of the added message
 */
statusbar_msgid_t statusbar_gui_push
    (sb_types_t type, guint scid, guint timeout, const gchar *format , ...)
{
    static gchar buf[1024];
    va_list args;
    statusbar_msgid_t id = {0, 0};
    GtkStatusbar *statusbar;

    va_start(args, format);
    
    if (format != NULL) {
        switch (type) {
        case SB_MESSAGE:
            gm_vsnprintf(buf, sizeof(buf), format, args);
            break;
        case SB_WARNING:
            gm_vsnprintf(buf, sizeof(buf), format, args);
            gdk_beep();
            break;
        }
    } else {
        buf[0] = '\0';
    }

    statusbar = GTK_STATUSBAR
        (lookup_widget(main_window, "statusbar"));

    id.scid = scid;
    id.msgid = gtk_statusbar_push(GTK_STATUSBAR(statusbar), scid, buf);
    
    if (timeout != 0)
        statusbar_gui_add_timeout(id, timeout);    

    va_end(args);

    return id;
}

static void statusbar_gui_pop(guint scid)
{
    GtkStatusbar *statusbar;

    statusbar = GTK_STATUSBAR
        (lookup_widget(main_window, "statusbar"));

    gtk_statusbar_pop(GTK_STATUSBAR(statusbar), scid);
}

void statusbar_gui_remove(statusbar_msgid_t id)
{
    GtkStatusbar *statusbar;

    statusbar = GTK_STATUSBAR
        (lookup_widget(main_window, "statusbar"));

    gtk_statusbar_remove(GTK_STATUSBAR(statusbar), id.scid, id.msgid);
}

/* 
 * statusbar_gui_add_timeout:
 * 
 * Add a statusbar message id to the timeout list, so it will be removed
 * automatically after a number of seconds.
 */
static void statusbar_gui_add_timeout(statusbar_msgid_t id, guint timeout)
{
	struct statusbar_timeout * t = NULL;

    t = g_malloc0(sizeof(struct statusbar_timeout));
	
	t->id = id;
	t->timeout = time((time_t *) NULL) + timeout;

	sl_statusbar_timeouts = g_slist_prepend(sl_statusbar_timeouts, t);
}

/*
 * statusbar_gui_free_timeout:
 *
 * Remove the timeout from the timeout list and free allocated memory.
 */
static void statusbar_gui_free_timeout(struct statusbar_timeout * t)
{
	g_return_if_fail(t);

	statusbar_gui_remove(t->id);

	sl_statusbar_timeouts = g_slist_remove(sl_statusbar_timeouts, t);
	
	g_free(t);
}

/*
 * statusbar_gui_clear_timeouts
 *
 * Check whether statusbar items have expired and remove them from the
 * statusbar.
 */
void statusbar_gui_clear_timeouts(time_t now)
{
	GSList *to_remove = NULL;
	GSList *l;
	
	for (l = sl_statusbar_timeouts; l; l = l->next) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;

		if (now > t->timeout)  
			to_remove = g_slist_prepend(to_remove, t);
	}

	for (l = to_remove; l; l = l->next)
		statusbar_gui_free_timeout((struct statusbar_timeout *) l->data);

	g_slist_free(to_remove);

	/*
	 * When there are no more timeouts left, and there's a pending
	 * new statusbar string to display, pop the old one and add the new.
	 *		--RAM, 27/06/2002
	 */

	if (sl_statusbar_timeouts == NULL && statbar_botstr_new) {
		statusbar_gui_pop(scid_bottom);
		g_free(statbar_botstr);
		statbar_botstr = statbar_botstr_new;
		statbar_botstr_new = NULL;
		statusbar_gui_push(SB_MESSAGE, scid_bottom, 0, statbar_botstr);
	}
}

/*
 * statusbar_gui_free_timeout_list:
 *
 * Clear the whole timeout list and free allocated memory.
 */
static void statusbar_gui_free_timeout_list(void) 
{
	GSList *l;

	for (l = sl_statusbar_timeouts; l; l = sl_statusbar_timeouts) {
		struct statusbar_timeout *t = (struct statusbar_timeout *) l->data;
		
		statusbar_gui_free_timeout(t);
	}
}
