/*
 * Copyright (c) 2003, 2015 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Default setproctitle() for systems lacking it.
 *
 * @author Raphael Manfredi
 * @date 2003, 2015
 */

#include "common.h"

#ifndef HAS_SETPROCTITLE

#include "setproctitle.h"

#define SETPROCTITLE_SOURCE		/* For progname_arg_*() to be visible */

#include "buf.h"
#include "progname.h"

#include "override.h"			/* Must be the last header included */

/**
 * Set process title, for the ps(1) command to report an updated title.
 *
 * The title is set from the executable's name, followed by the result of a
 * printf(3) style expansion of the arguments as specified by the fmt argument.
 *
 * If the fmt argument begins with a ``-'' character, the executable's name
 * is skipped.
 *
 * If fmt is NULL, the original process title is restored.
 */
void
setproctitle(const char *fmt, ...)
{
	va_list args;
	char *start;
	size_t len;
	buf_t *b, bs;

	start = progname_args_start();
	len = progname_args_size();

	if (0 == len)
		return;

	b = buf_init(&bs, start, len);
	memset(start, 0, len);

	va_start(args, fmt);

	if (NULL == fmt) {
		buf_printf(b, "%s", progstart_arg(0));
	} else if ('-' == *fmt) {
		buf_vprintf(b, fmt + 1, args);
	} else {
		buf_printf(b, "%s ", getprogname());
		buf_vcatf(b, fmt, args);
	}

	va_end(args);
}
#endif	/* !HAS_SETPROCTITLE */

/* vi: set ts=4 sw=4 cindent: */
