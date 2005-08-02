/*
 * $Id$
 *
 * Copyright (c) 2005, Hans de Graaff
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
 * @ingroup lib
 * @file
 *
 * Interface to dbus messaging bus
 *
 * @author Hans de Graaff
 * @date 2005
 */

#include "common.h"

RCSID("$Id$");

#include "dbus_util.h"

#ifdef HAS_DBUS
/** @todo DBus API is not stable yet, may need changes once 1.0 is released */
#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

#define DBUS_PATH "/net/gtkg/events"
#define DBUS_INTERFACE "net.gtkg.Events"

static DBusConnection *bus = NULL; /**< DBus connection to the bus */

/** 
 * Initialize the bus connection
 */

void dbus_util_init () {

	DBusError error;

	dbus_error_init(&error);
	bus = dbus_bus_get(DBUS_BUS_SESSION, &error);

	if (bus == NULL) {
		g_message("Could not open connection to DBus bus: %s\n", error.message);
		dbus_error_free(&error);
	} else {

		/* Set up this connection to work in a GLib event loop */

		/** @todo Integrating the D-BUS connection in the GLib main
		loop causes crashes for ADNS. I'm assuming that this is some
		kind of signal or thread issue, but I'm not sure. Needs more
		investigation, but for now I'll just try to use D-BUS without
		doing this. It could also be a bug in D-BUS that may be fixed
		in 1.0, so revisit then. */

		/* dbus_connection_setup_with_g_main(bus, NULL); */

	}

	g_message("D-BUS set up and ready for use.\n");
	dbus_util_send_message("started");
}

/** 
 * Close down the D-BUS connection and send final event.
 */
void dbus_util_close () {
	
	dbus_util_send_message("stopped");
	
	/**
	 * @todo It's not really clear to me how I can free the bus that
	 * we have, but since we are shutting down now anyway it does not
	 * matter much except for the spotless record of memory
	 * reclaiming.
	*/
}



/** 
 * Send a notification string. I'm not sure if this is the practical
 * way to go about things, but this will be ok for testing.
 * @return void because this is a fire-and-forget interface
 */
void dbus_util_send_message (const char *text) {

	DBusMessage *message;

	if (bus) {
		/* Create a new message on the DBUS_INTERFACE */
		message = dbus_message_new_signal(DBUS_PATH, DBUS_INTERFACE, "Events");

		if (message == NULL) {
			g_message("Could not create D-BUS message!\n");
		} else {
			
			/* Add the message to the Events signal */
			dbus_message_append_args(message, DBUS_TYPE_STRING, &text, 
									 DBUS_TYPE_INVALID);

			/* Send the message */
			dbus_connection_send(bus, message, NULL);
		
			g_message("Sent D-BUS message %s\n", text);
		
			/* Free the message */
			dbus_message_unref(message);
		}
    }

}

#endif

/* vi: set ts=4: */
