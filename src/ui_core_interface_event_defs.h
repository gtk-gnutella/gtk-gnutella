/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_event_defs_h_
#define _ui_core_interface_event_defs_h_

#include <time.h>
#include "ui_core_interface_common_defs.h"

typedef enum frequency_type {
    FREQ_SECS,
    FREQ_UPDATES
} frequency_t;

struct subscriber {
    GCallback           cb;
    enum frequency_type f_type;
    guint32             f_interval;
    time_t              last_call;
};

typedef struct event {
    const gchar *name;
    guint32      triggered_count;
    GSList      *subscribers;
} event_t;

struct event *event_new(const gchar *name);

#define event_destroy(evt) G_STMT_START {                          \
    real_event_destroy(evt);                                       \
    G_FREE_NULL(evt);                                              \
} G_STMT_END



#endif
