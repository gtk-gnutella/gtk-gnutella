/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 * Header parsing routines.
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

#ifndef _header_h_
#define _header_h_

#include <stdio.h>
#include <glib.h>

#include "ui_core_interface_header_defs.h"

/*
 * Public interface.
 */

header_t *header_make(void);
void header_free(header_t *o);
void header_reset(header_t *o);
gint header_append(header_t *o, const gchar *text, gint len);
void header_dump(const header_t *o, FILE *out);
const gchar *header_strerror(guint errnum);
gchar *header_get(const header_t *o, const gchar *field);
gchar *header_getdup(const header_t *o, const gchar *field);

gpointer header_fmt_make(const gchar *field, const gchar *separator,
	gint len_hint);
void header_fmt_free(gpointer o);
void header_fmt_set_line_length(gpointer o, gint maxlen);
gboolean header_fmt_value_fits(gpointer o, gint len, gint maxlen);
void header_fmt_append(gpointer o, const gchar *str, const gchar *separator);
void header_fmt_append_value(gpointer o, const gchar *str);
gint header_fmt_length(gpointer o);
void header_fmt_end(gpointer o);
gchar *header_fmt_string(gpointer o);
gchar *header_fmt_to_gchar(gpointer o);

struct xfeature_t
{
	GList *features;
};

struct xfeatures_t
{
	struct xfeature_t uploads;
	struct xfeature_t downloads;
	struct xfeature_t connections;
} xfeatures;

void header_get_feature(const gchar *feature_name, const header_t *header,
	int *feature_version_major, int *feature_version_minor);
void header_features_add(struct xfeature_t *xfeatures,
	gchar *feature_name, 
	int feature_version_major,
	int feature_version_minor);
void header_features_cleanup(struct xfeature_t *xfeatures);
void header_features_close();
void header_features_generate(struct xfeature_t *xfeatures, 
	gchar *buf, gint len, gint *rw);

#endif	/* _header_h_ */

/* vi: set ts=4: */
