/*
 * Copyright (c) 2002, Raphael Manfredi
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

