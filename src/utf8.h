/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Unicode Transformation Format 8 bits.
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

#ifndef _utf8_h_
#define _utf8_h_

#include <glib.h>


#ifdef USE_ICU
#include "unicode/uchar.h"
#include "unicode/ustring.h"
#include "unicode/utypes.h"
#include "unicode/ustdio.h"
#include "unicode/unorm.h"
#endif

void locale_init(void);
void locale_close(void);
const gchar *locale_get_charset(void);
gint utf8_is_valid_char(const gchar *s);
gint utf8_is_valid_string(const gchar *s, gint len);
guint32 utf8_decode_char(gchar *s, gint len, gint *retlen, gboolean warn);
gint utf8_to_iso8859(gchar *s, gint len, gboolean space);

/* 
 * Necessary for GTK+ 2.x version because it expects almost any string
 * to be encoded as UTF-8.
 */
gchar *iso_8859_1_to_utf8(gchar *fromstr);
gchar *locale_to_utf8(gchar *str, size_t len);
gchar *lazy_locale_to_utf8(gchar *str, size_t len);


/* 
 * Necessary for GTK+ 1.2 version because it expects almost any string
 * to be in locale, but xml is stored in utf-8
 */

gboolean is_ascii_string(const gchar *str);
gchar *utf8_to_locale(gchar *str, size_t len);
gchar *lazy_utf8_to_locale(gchar *str, size_t len);

#ifdef USE_ICU

int to_icu_conv(const gchar *in, int lenin, UChar *out, int lenout);
int icu_to_utf8_conv(const UChar *in, int lenin, gchar *out, int lenout);

int unicode_NFC(const UChar *source, gint32 len, UChar *result, gint32 rlen);
int unicode_NFKD(const UChar *source, gint32 len, UChar *result, gint32 rlen);
int unicode_lower(const UChar *source, gint32 len, UChar *result, gint32 rlen);
int unicode_upper(const UChar *source, gint32 len, UChar *result, gint32 rlen);
int unicode_filters(const UChar *source, gint32 len, UChar *result);

#endif	/* USE_ICU */

#endif	/* _utf8_h_ */

/* vi: set ts=4: */

