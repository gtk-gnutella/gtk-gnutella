/*
 * $Id$
 *
 * Copyright (c) 2004, Russell Francis
 *
 * GTK cell renderer.
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

/* cellrenderer.h
 * Copyright (C) 2002 Naba Kumar <kh_naba@users.sourceforge.net>
 * modified by Jörgen Scheibengruber <mfcn@gmx.de>
 * modified more by Russell Francis <rf358197@ohio.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _pbarcellrenderer_gui2_h_
#define _pbarcellrenderer_gui2_h_

#include <gtk/gtkcellrenderer.h>

G_BEGIN_DECLS

#define GTK_TYPE_CELL_RENDERER_PROGRESS (gtk_cell_renderer_get_type ())
#define GTK_CELL_RENDERER_PROGRESS(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST ((obj), \
	GTK_TYPE_CELL_RENDERER_PROGRESS, GtkCellRendererProgress))

typedef struct _GtkCellRendererProgress      GtkCellRendererProgress;
typedef struct _GtkCellRendererProgressClass GtkCellRendererProgressClass;
typedef struct _GtkCellRendererProgressPriv  GtkCellRendererProgressPriv;

struct _GtkCellRendererProgress {
	GtkCellRenderer parent_instance;
	GtkCellRendererProgressPriv* priv;
};

struct _GtkCellRendererProgressClass{
	GtkCellRendererClass parent_class;
};

GtkType gtk_cell_renderer_progress_get_type (void) G_GNUC_CONST;
GtkCellRenderer* gtk_cell_renderer_progress_new(void);

G_END_DECLS

#endif	/* _pbarcellrenderer_gui2_h_ */
