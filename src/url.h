/*
 * Copyright (c) 2002, Raphael Manfredi
 */

#ifndef __url_h__
#define __utl_h__

#include <glib.h>

/*
 * Public interaface.
 */

guchar *url_escape(guchar *url);
guchar *url_escape_cntrl(guchar *url);
guchar *url_unescape(guchar *url, gboolean inplace);

#endif	/* __url_h__ */

/* vi: set ts=4: */

