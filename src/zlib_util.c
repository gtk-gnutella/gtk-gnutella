/*
 * Copyright (c) 2002, Raphael Manfredi
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

#include <zlib.h>
#include <glib.h>

/*
 * zlib_strerror
 *
 * Return human-readable error string corresponding to error code `errnum'.
 */
gchar *zlib_strerror(gint errnum)
{
	switch (errnum) {
	case Z_OK:				return "OK";
	case Z_STREAM_END:		return "End of stream";
	case Z_NEED_DICT:		return "Decompressing dictionary needed";
	case Z_ERRNO:			return "Generic zlib error";
	case Z_STREAM_ERROR:	return "Stream error";
	case Z_DATA_ERROR:		return "Data error";
	case Z_MEM_ERROR:		return "Memory error";
	case Z_BUF_ERROR:		return "Buffer error";
	case Z_VERSION_ERROR:	return "Incompatible runtime zlib library";
	default:				break;
	}

	return "Invalid error code";
}

