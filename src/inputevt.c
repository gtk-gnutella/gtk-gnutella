/*
 * Copyright (c) 2002, ko (ko-@wanadoo.fr)
 *
 * Input I/O notification.
 *
 * Basically this is a duplicate of the GDK input facilities,
 * without the features gtkg does not use.
 *
 * The intent here is to break the GDK dependency but retain
 * the same behavior, to avoid disturbing too much of the existing code.
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

#include <common.h>

RCSID("$Id$");

/*
 * The following defines map the GDK-compatible input condition flags
 * to those used by GLIB.
 *
 * Interesting remark found in gdkevents.c :
 * What do we do with G_IO_NVAL ?
 */
#define READ_CONDITION		(G_IO_IN | G_IO_HUP | G_IO_ERR)
#define WRITE_CONDITION		(G_IO_OUT | G_IO_ERR)
#define EXCEPTION_CONDITION	(G_IO_PRI)

/*
 * The relay structure is used as a bridge to provide GDK-compatible
 * input condition flags.
 */
typedef struct {
	inputevt_cond_t condition;
	inputevt_handler_t handler;
	gpointer data;
} inputevt_relay_t;

/*
 * inputevt_relay_destroy
 *
 * Frees the relay structure when its time comes.
 */
static void inputevt_relay_destroy(gpointer data)
{
	wfree(data, sizeof(inputevt_relay_t));
}

/*
 * inputevt_dispatch
 *
 * Relays the event to the registered handler function.
 * The input condition flags are properly mapped before being passed on.
 */
static gboolean inputevt_dispatch(GIOChannel *source,
								  GIOCondition condition,
								  gpointer data)
{
	inputevt_cond_t cond = 0;
	inputevt_relay_t *relay = (inputevt_relay_t *) data;

	if (condition & READ_CONDITION)
		cond |= INPUT_EVENT_READ;
	if (condition & WRITE_CONDITION)
		cond |= INPUT_EVENT_WRITE;
	if (condition & EXCEPTION_CONDITION)
		cond |= INPUT_EVENT_EXCEPTION;

	if (relay->condition & cond)
		relay->handler(relay->data, g_io_channel_unix_get_fd(source), cond);

	return TRUE;
}

/*
 * inputevt_add
 *
 * Adds an event source to the main GLIB monitor queue.
 *
 * A replacement for gdk_input_add().
 * Behaves exactly the same, except destroy notification has
 * been removed (since gtkg does not use it).
 */
guint inputevt_add(gint source, inputevt_cond_t condition,
	inputevt_handler_t handler, gpointer data)
{
	guint result;
	GIOChannel *chan;
	GIOCondition cond = 0;

	inputevt_relay_t *relay = walloc(sizeof(inputevt_relay_t));

	relay->condition = condition;
	relay->handler = handler;
	relay->data = data;

	if (condition & INPUT_EVENT_READ)
		cond |= READ_CONDITION;
	if (condition & INPUT_EVENT_WRITE)
		cond |= WRITE_CONDITION;
	if (condition & INPUT_EVENT_EXCEPTION)
		cond |= EXCEPTION_CONDITION;

	chan = g_io_channel_unix_new(source);
#ifdef USE_GTK2	
	g_io_channel_set_encoding(chan, NULL, NULL); /* binary data */
#endif
	result = g_io_add_watch_full(chan, G_PRIORITY_DEFAULT, cond,
				 inputevt_dispatch, relay, inputevt_relay_destroy);
	g_io_channel_unref(chan);

	return result;
}

/*
 * inputevt_init
 *
 * Performs module initialization.
 */
void inputevt_init(void)
{
	/* no initialization required */
}

/*
 * inputevt_close
 *
 * Performs module cleanup.
 */
void inputevt_cleanup(void)
{
	/* no cleanup required */
}

