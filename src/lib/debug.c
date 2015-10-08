/*
 * Copyright (c) 2008, 2012 Raphael Manfredi
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
 * Debug level configuration for library files.
 *
 * @author Raphael Manfredi
 * @date 2008, 2012
 */

#include "common.h"

#include "debug.h"

#include "buf.h"
#include "misc.h"
#include "stringify.h"

#include "override.h"			/* Must be the last header included */

uint32 common_dbg = 0;			/**< Common debug level for library files */
uint32 common_stats = 0;		/**< Common log level for library statistics */

/**
 * Set the debug level for library files.
 */
void
set_library_debug(uint32 level)
{
	common_dbg = level;
}

/**
 * Set the log level for library runtime statistics.
 */
void
set_library_stats(uint32 level)
{
	common_stats = level;
}

/**
 * Stringify the object name of a data structure.
 *
 * @param dc		the debug config
 * @param o			the object being debugged
 *
 * @return pointer to (possibly static) name.
 */
const char *
dbg_ds_name(const dbg_config_t *dc, const void *o)
{
	if (NULL == dc->o2str) {
		buf_t *b = buf_private(G_STRFUNC, POINTER_BUFLEN + CONST_STRLEN("0x"));
		buf_printf(b, "%p", o);
		return buf_data(b);
	} else {
		return (*dc->o2str)(o);
	}
}

/**
 * Stringify the keys in a data structure.
 *
 * @param dc		the debug config
 * @param key		the key to stringify
 * @param len		size of key (-1 if unknown)
 *
 * @return pointer to (possibly static) stringified key.
 */
const char *
dbg_ds_keystr(const dbg_config_t *dc, const void *key, size_t len)
{
	buf_t *b = buf_private(G_STRFUNC,
		POINTER_BUFLEN + SIZE_T_DEC_BUFLEN + CONST_STRLEN("<key@0x,len=>"));

	if (NULL == key)
		return "<null key>";

	if ((size_t) -1 == len) {
		if (NULL == dc->k2str) {
			buf_printf(b, "<key@%p>", key);
			return buf_data(b);
		} else {
			return (*dc->k2str)(key);
		}
	} else {
		if (NULL == dc->klen2str) {
			if (NULL == dc->k2str) {
				buf_printf(b, "<key@%p,len=%zu>", key, len);
				return buf_data(b);
			} else {
				return (*dc->k2str)(key);
			}
		} else {
			return (*dc->klen2str)(key, len);
		}
	}
}

/**
 * Stringify the values in a data structure.
 *
 * @param dc		the debug config
 * @param value		the value to stringify
 * @param len		size of value (-1 if unknown)
 *
 * @return pointer to (possibly static) stringified value.
 */
const char *
dbg_ds_valstr(const dbg_config_t *dc, const void *value, size_t len)
{
	buf_t *b = buf_private(G_STRFUNC,
		POINTER_BUFLEN + SIZE_T_DEC_BUFLEN + CONST_STRLEN("<value@0x,len=>"));

	if (NULL == value)
		return "<null value>";

	if ((size_t) -1 == len) {
		if (NULL == dc->v2str) {
			buf_printf(b, "<value@%p>", value);
			return buf_data(b);
		} else {
			return (*dc->v2str)(value);
		}
	} else {
		if (NULL == dc->vlen2str) {
			if (NULL == dc->v2str) {
				buf_printf(b, "<value@%p,len=%zu>", value, len);
				return buf_data(b);
			} else {
				return (*dc->v2str)(value);
			}
		} else {
			return (*dc->vlen2str)(value, len);
		}
	}
}

/**
 * Logging wrapper for debugged data structures.
 *
 * @param dc		the debug config
 * @param o			the debugged object
 * @param fmt		formatting string
 * @param args		points to additional format arguments
 */
void
dbg_ds_logv(const dbg_config_t *dc, const void *o,
	const char *fmt, va_list args)
{
	buf_t *b = buf_private(G_STRFUNC, 512);
	size_t len;

	len = buf_vprintf(b, fmt, args);
	g_debug("%s%s \"%s\" %s%s",
		dc->prefix, dc->type, dbg_ds_name(dc, o), buf_data(b),
		len == buf_size(b) - 1 ? "...more..." : "");
}

/**
 * Logging wrapper for debugged data structures.
 *
 * @param dc		the debug config
 * @param o			the debugged object
 * @param fmt		formatting string
 * @param ...		additional format arguments
 */
void
dbg_ds_log(const dbg_config_t *dc, const void *o, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	dbg_ds_logv(dc, o, fmt, args);
	va_end(args);
}

/* vi: set ts=4 sw=4 cindent: */
