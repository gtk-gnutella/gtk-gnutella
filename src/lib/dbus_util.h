/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#ifndef _dbus_h_
#define _dbus_h_

#include "common.h"

/**
 * Notification events. These should not be translated, they are part
 * of the machine protocol on dbus.
 */

#define DBS_EVT "Events"
#define DBS_EVT_DOWNLOAD_DONE "DownloadDone"
#define DBS_EVT_PEERMODE_CHANGE "PeermodeChange"

#ifdef HAS_DBUS

void dbus_util_init(bool disabled);
void dbus_util_close(void);
void dbus_util_send_message(const char *, const char *);

#else /* !HAS_DBUS */

#define dbus_util_init(d) G_STMT_START { (void) (d); } G_STMT_END
#define dbus_util_close() G_STMT_START { } G_STMT_END
#define dbus_util_send_message(signal, txt) \
	G_STMT_START { (void) (signal); (void) (txt); } G_STMT_END

#endif /* HAS_DBUS */

#endif /* _dbus_h_ */

/* vi: set ts=4 sw=4 cindent: */
