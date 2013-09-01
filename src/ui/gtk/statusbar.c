/*
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

/**
 * @ingroup gtk
 * @file
 *
 * GUI stuff used by 'share.c'.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 *
 * @date 2001-2003
 */

#include "gui.h"

#include "gtk-gnutella.h"
#include "statusbar.h"

#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/misc.h"
#include "lib/product.h"
#include "lib/str.h"
#include "lib/tm.h"

#include "lib/override.h"	/* Must be the last header included */

static const statusbar_msgid_t zero_msgid;

/**
 * Timeout entry for statusbar messages.
 */
typedef struct statusbar_timeout {
    statusbar_msgid_t id;	/**< message id of the message */
	time_t stamp;			/**< time at which the message was added */
	guint timeout;			/**< # of seconds after which the message
								 should be removed */
} statusbar_timeout_t;

/*
 * statusbar context ids
 */
static guint scid_bottom              = (guint) -1;
static guint scid_hostsfile           = (guint) -1;
static guint scid_queue_freezed       = (guint) -1;
static guint scid_info                = (guint) -1;
static guint scid_ip_changed          = (guint) -1;
static guint scid_warn                = (guint) -1;

/**
 * List with timeout entries for statusbar messages.
 */
static GSList *sl_statusbar_timeouts;

/*
 * Status bar
 */
static char *statbar_botstr;
static char *statbar_botstr_new;

static void statusbar_gui_free_timeout(struct statusbar_timeout * t);
static void statusbar_gui_free_timeout_list(void);
static void statusbar_gui_add_timeout(statusbar_msgid_t, guint timeout);

static GtkStatusbar *
statusbar_get(void)
{
    static GtkStatusbar *sb;

	if (!sb) {
		sb = GTK_STATUSBAR(gui_main_window_lookup("statusbar"));
	}
	return sb;
}

/**
 * Put a message on the statusbar. The message will be displayed for
 * the number of seconds given by timeout. If timeout is 0 the message
 * will not be automatically removed.
 *
 * @returns message id of the added message
 */
statusbar_msgid_t
statusbar_gui_push_v(sb_types_t type, guint scid, guint timeout,
	const gchar *format, va_list args)
{
    static gchar buf[1024];
    statusbar_msgid_t id = zero_msgid;

    if (format != NULL) {
        switch (type) {
        case SB_WARNING:
            gdk_beep();
			/* FALL THRU */
        case SB_MESSAGE:
            str_vbprintf(buf, sizeof(buf), format, args);
            break;
        }
    } else {
        buf[0] = '\0';
    }

    id.scid = scid;
    id.msgid = gtk_statusbar_push(statusbar_get(), scid, buf);

    if (timeout != 0)
        statusbar_gui_add_timeout(id, timeout);

    return id;
}

/**
 * Put a message on the statusbar. The message will be displayed for
 * the number of seconds given by timeout. If timeout is 0 the message
 * will not be automatically removed.
 *
 * @returns message id of the added message
 */
static statusbar_msgid_t
statusbar_gui_push(sb_types_t type, guint scid, guint timeout,
	const gchar *format, ...)
{
    va_list args;
    statusbar_msgid_t id;

	va_start(args, format);
	id = statusbar_gui_push_v(type, scid, timeout, format, args);
    va_end(args);

    return id;
}

/**
 * Put an informational message on the statusbar. The message will be 
 * displayed for the number of seconds given by timeout. If timeout is 0
 * the message will not be automatically removed.
 *
 * @returns message id of the added message
 */
statusbar_msgid_t
statusbar_gui_message(guint timeout, const gchar *format, ...)
{
    va_list args;
    statusbar_msgid_t id;

	va_start(args, format);
	id = statusbar_gui_push_v(SB_MESSAGE, scid_info, timeout, format, args);
    va_end(args);

    return id;
}

/**
 * Put a warning message on the statusbar. The message will be displayed for
 * the number of seconds given by timeout. If timeout is 0 the message
 * will not be automatically removed.
 *
 * @returns message id of the added message
 */
statusbar_msgid_t
statusbar_gui_warning(guint timeout, const gchar *format, ...)
{
    va_list args;
    statusbar_msgid_t id;

	va_start(args, format);
	id = statusbar_gui_push_v(SB_WARNING, scid_warn, timeout, format, args);
    va_end(args);

    return id;
}

void
statusbar_gui_set_default(const char *format, ...)
{
    static gchar buf[1024];
    va_list args;

    va_start(args, format);

    HFREE_NULL(statbar_botstr_new);

    if (format != NULL) {
        str_vbprintf(buf, sizeof(buf), format, args);
        statbar_botstr_new = h_strdup(buf);
    } else {
        statbar_botstr_new = h_strdup(product_get_website());
    }

    va_end(args);
}

void
statusbar_gui_remove(statusbar_msgid_t id)
{
    gtk_statusbar_remove(statusbar_get(), id.scid, id.msgid);
}

/**
 * Add a statusbar message id to the timeout list, so it will be removed
 * automatically after a number of seconds.
 */
static void
statusbar_gui_add_timeout(statusbar_msgid_t id, guint timeout)
{
	struct statusbar_timeout *t;

    t = g_malloc0(sizeof *t);

	t->id = id;
	t->stamp = tm_time();
	t->timeout = timeout;

	sl_statusbar_timeouts = g_slist_prepend(sl_statusbar_timeouts, t);
}

/**
 * Remove the timeout from the timeout list and free allocated memory.
 */
static void
statusbar_gui_free_timeout(struct statusbar_timeout *t)
{
	g_return_if_fail(t);

	statusbar_gui_remove(t->id);
	sl_statusbar_timeouts = g_slist_remove(sl_statusbar_timeouts, t);
	G_FREE_NULL(t);
}

/**
 * Check whether statusbar items have expired and remove them from the
 * statusbar.
 */
static void
statusbar_gui_clear_timeouts(time_t now)
{
	GSList *sl, *to_remove = NULL;

	for (sl = sl_statusbar_timeouts; sl; sl = g_slist_next(sl)) {
		struct statusbar_timeout *t = sl->data;
		const time_delta_t timeout = t->timeout;

		if (delta_time(now, t->stamp) > timeout)
			to_remove = g_slist_prepend(to_remove, t);
	}

	for (sl = to_remove; sl; sl = g_slist_next(sl)) {
		statusbar_gui_free_timeout(sl->data);
	}
	g_slist_free(to_remove);

	/*
	 * When there are no more timeouts left, and there's a pending
	 * new statusbar string to display, pop the old one and add the new.
	 *		--RAM, 27/06/2002
	 */

	if (sl_statusbar_timeouts == NULL && statbar_botstr_new) {
    	gtk_statusbar_pop(statusbar_get(), scid_bottom);
		HFREE_NULL(statbar_botstr);
		statbar_botstr = statbar_botstr_new;
		statbar_botstr_new = NULL;
		statusbar_gui_push(SB_MESSAGE, scid_bottom, 0, "%s", statbar_botstr);
	}
}

/**
 * Clear the whole timeout list and free allocated memory.
 */
static void
statusbar_gui_free_timeout_list(void)
{
	while (NULL != sl_statusbar_timeouts) {
		struct statusbar_timeout *t = sl_statusbar_timeouts->data;

		statusbar_gui_free_timeout(t);
	}
}

G_GNUC_COLD void
statusbar_gui_init(void)
{
    GtkStatusbar *sb;

    sb = statusbar_get();
	statusbar_set_shadow_type(GTK_STATUSBAR(sb), GTK_SHADOW_ETCHED_IN);

	scid_bottom = gtk_statusbar_get_context_id(sb, "default");
	scid_hostsfile = gtk_statusbar_get_context_id(sb, "reading hosts file");
	scid_queue_freezed = gtk_statusbar_get_context_id(sb, "queue freezed");
   	scid_info = gtk_statusbar_get_context_id(sb, "information");
    scid_ip_changed = gtk_statusbar_get_context_id(sb, "ip changed");
    scid_warn = gtk_statusbar_get_context_id(sb, "warning");

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

	statbar_botstr = h_strdup(product_get_website());
	statusbar_gui_push(SB_MESSAGE, scid_bottom, 0, "%s", statbar_botstr);

	main_gui_add_timer(statusbar_gui_clear_timeouts);
}

void
statusbar_gui_shutdown(void)
{
    statusbar_gui_free_timeout_list();
	HFREE_NULL(statbar_botstr_new);
	HFREE_NULL(statbar_botstr);
}

/* vi: set ts=4 sw=4 cindent: */
