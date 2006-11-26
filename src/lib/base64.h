/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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
 * Base64 encoding/decoding.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _base64_h_
#define _base64_h_

#include "common.h"

/*
 * Public interface.
 */

gchar *base64_encode(const gchar *buf, guint len, guint *retpad);
void base64_encode_into(const gchar *buf, guint len,
	gchar *encbuf, guint enclen);

gchar *base64_decode(const gchar *buf, guint len, guint *outlen);
guint base64_decode_into(const gchar *buf, guint len,
	gchar *decbuf, guint declen);

#endif	/* _base64_h_ */

/* vi: set ts=4: */

