/*
 * Copyright (c) 2002, Raphael Manfredi
 */

#ifndef __url_h__
#define __utl_h__

#include <glib.h>

/*
 * Public interaface.
 */

gchar *url_escape(gchar *url);
gchar *url_escape_cntrl(gchar *url);
gchar *url_unescape(gchar *url, gboolean inplace);

#endif	/* __url_h__ */

/* vi: set ts=4: */

