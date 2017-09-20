/*
 * Copyright (c) 2007, Christian Biere
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

#ifndef _gtk_html_view_h_
#define _gtk_html_view_h_

#include "common.h"

#include "gui.h"
#include "lib/array.h"

struct html_view;

struct html_view *html_view_load_file(GtkWidget *textview, int fd);
struct html_view *html_view_load_memory(GtkWidget *textview,
			const struct array memory);
void html_view_clear(struct html_view *html_view);
void html_view_free(struct html_view **html_view_ptr);

#endif /* _gtk_html_view_h_ */

/* vi: set ts=4 sw=4 cindent: */
