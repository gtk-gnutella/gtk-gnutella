/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * HTTP routines.
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

#ifndef _http_h_
#define _http_h_

#include "ui_core_interface_http_defs.h"
#include "ui_core_interface_socket_defs.h"

/*
 * Public interface
 */

void http_timer(time_t now);

gboolean http_send_status(struct gnutella_socket *s,
	gint code, gboolean keep_alive, http_extra_desc_t *hev, gint hevcnt, 
	const gchar *reason, ...) G_GNUC_PRINTF(6, 7);

void http_hostname_add(
	gchar *buf, gint *retval, gpointer arg, guint32 flags);

gint http_status_parse(const gchar *line,
	const gchar *proto, const gchar **msg, gint *major, gint *minor);

gboolean http_extract_version(
	gchar *request, gint len, gint *major, gint *minor);

http_buffer_t *http_buffer_alloc(gchar *buf, gint len, gint written);
void http_buffer_free(http_buffer_t *b);

guint32 http_range_size(const GSList *list);
const gchar *http_range_to_gchar(const GSList *list);
void http_range_free(GSList *list);
GSList *http_range_parse(
	const gchar *field, gchar *value, guint32 size, const gchar *vendor);
gboolean http_range_contains(GSList *ranges, guint32 from, guint32 to);
GSList *http_range_merge(GSList *list1, GSList *list2);

const gchar *http_url_strerror(http_url_error_t errnum);
gboolean http_url_parse(
	gchar *url, guint16 *port, gchar **host, gchar **path);

gpointer http_async_get(
	gchar *url,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

gpointer http_async_get_ip(
	gchar *path,
	guint32 ip,
	guint16 port,
	http_header_cb_t header_ind,
	http_data_cb_t data_ind,
	http_error_cb_t error_ind);

const gchar *http_async_strerror(guint errnum);
const gchar *http_async_info(
	gpointer handle, const gchar **req, gchar **path,
	guint32 *ip, guint16 *port);
void http_async_connected(gpointer handle);
void http_async_close(gpointer handle);
void http_async_cancel(gpointer handle);
void http_async_error(gpointer handle, gint code);
http_state_t http_async_state(gpointer handle);

void http_async_set_opaque(gpointer handle, gpointer data, http_user_free_t fn);
gpointer http_async_get_opaque(gpointer handle);
void http_async_log_error(gpointer handle, http_errtype_t type, gpointer v);

void http_async_on_state_change(gpointer handle, http_state_change_t fn);
void http_async_allow_redirects(gpointer handle, gboolean allow);
void http_async_set_op_request(gpointer handle, http_op_request_t op);

void http_close(void);

#endif	/* _http_h_ */

/* vi: set ts=4: */
