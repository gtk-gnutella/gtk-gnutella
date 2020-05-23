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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_gnet_stats_common_h_
#define _gtk_gnet_stats_common_h_

#include "gui.h"
#include "columns.h"

#include "if/core/hsep.h"
#include "if/core/net_stats.h"
#include "if/ui/gtk/gnet_stats.h"

const gchar *msg_type_str(gint msg_type);
const gchar *msg_drop_str(gint msg_drop_reason);
const gchar *general_type_str(gint gnr_type);
const gchar *horizon_stat_str(gint row,	c_horizon_t column);

gint msg_type_str_size(void);
void gnet_stats_gui_horizon_update(hsep_triple *table, guint32 triples);

void gnet_stats_gui_general_to_string_buf(char *dst, size_t size,
	const gnet_stats_t *stats, int idx);

void gnet_stats_gui_timer(time_t now);
void gnet_stats_gui_update_display(time_t now);

#endif /* _gtk_gnet_stats_common_h_ */

/* vi: set ts=4 sw=4 cindent: */
