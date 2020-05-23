/*
 * Copyright (c) 2002-2003, Richard Eckart
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
 * @ingroup gtk
 * @file
 *
 * Persistance for searches and filters in XML format.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#ifndef _gtk_search_xml_h_
#define _gtk_search_xml_h_

#include "if/core/search.h"

void search_store_xml(void);
gboolean search_retrieve_xml(void);
gnet_search_t search_gui_get_handle(const struct search *);

#endif	/* _gtk_search_xml_h_ */

/* vi: set ts=4 sw=4 cindent: */
