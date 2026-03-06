/*
 * Copyright (c) 2018, Raphael Manfredi
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
 * Private logging support for verbosely tracing and debugging code sections.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#include "common.h"

#include "privlog.h"

#include "crash.h"
#include "file_rotate.h"
#include "log.h"
#include "misc.h"
#include "mutex.h"
#include "product.h"
#include "str.h"
#include "thread.h"

#include "override.h"	/* Must be the last header included */

#define PRIVLOG_MAX_LOGMSG	256	/* Maximum log length */
#define PRIVLOG_FILE_KEEP	3	/* Ancient logs we keep via rotation */

#define PRIVLOG_LOG_LOCK(pld)	mutex_lock(&pld->lock)
#define PRIVLOG_LOG_UNLOCK(pld)	mutex_unlock(&pld->lock)

/**
 * Create a unique logfile name.
 */
static const char *
privlog_make_path(const char *base)
{
	static char pathname[MAX_PATH_LEN];

	str_bprintf(ARYLEN(pathname), "%s.%s.log", product_nickname(), base);

	return pathname;
}

/**
 * Private logging main entry point.
 *
 * @param pld		private logging information
 * @param fmt		formatting string
 * @param args		arguments to format
 */
void
privlog_logv(privlog_logdef_t *pld, const char *fmt, va_list args)
{
	char time_buf[CRASH_TIME_BUFLEN];
	char logstr[PRIVLOG_MAX_LOGMSG];
	int i;
	unsigned stid = thread_small_id();

	/*
	 * If we haven't rotated logs yet, do it now that we have to emit
	 * something.
	 */

	if G_UNLIKELY(!pld->rotated) {
		PRIVLOG_LOG_LOCK(pld);
		if (!pld->rotated) {
			const char *path = privlog_make_path(pld->name);
			if (pld->lf != NULL)
				fclose(pld->lf);
			pld->rotated = TRUE;
			file_rotate(path, PRIVLOG_FILE_KEEP, FILE_ROTATE_ERROR);
		}
		PRIVLOG_LOG_UNLOCK(pld);
	}

	/*
	 * Open logfile the first time.
	 */

	if G_UNLIKELY(NULL == pld->lf) {
		bool warn = FALSE;
		const char *path = NULL;
		PRIVLOG_LOG_LOCK(pld);
		if (NULL == pld->lf) {
			path = privlog_make_path(pld->name);
			pld->lf = fopen(path, "a");
			if (NULL == pld->lf)
				warn = TRUE;
		}
		PRIVLOG_LOG_UNLOCK(pld);
		if (warn) {
			s_warning("%s(): cannot open %s: %m", G_STRFUNC, path);
			return;
		}
	}

	{
		str_t s;
		size_t len;

		crash_time_raw(ARYLEN(time_buf));
		len = log_vbprintf(ARYLEN(logstr), fmt, args);

		/* Sanitize message, in-place, and transform CRLF -> LF  */

		str_new_buffer(&s, ARYLEN(logstr), len);
		if (!str_unsafe_escape(&s, TRUE))
			str_ctrl_escape(&s, TRUE);		/* At least the controls */
	}

	PRIVLOG_LOG_LOCK(pld);

	fprintf(pld->lf, "%s: [%d] ", time_buf, stid);

	for (i = 0; i < pld->level[stid]; i++) {
		fputs("| ", pld->lf);
	}

	fputs(logstr, pld->lf);
	fputc('\n', pld->lf);
	fflush(pld->lf);

	PRIVLOG_LOG_UNLOCK(pld);
}

/**
 * Emit formatted log.
 *
 * @param pld		private logging information
 * @param fmt		formatting string
 * @param ...		arguments to format
 */
static void G_PRINTF(2, 3)
privlog_log(privlog_logdef_t *pld, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	privlog_logv(pld, fmt, args);
	va_end(args);
}

/**
 * Log routine entry.
 */
void
privlog_enter(privlog_logdef_t *pld, const char *routine)
{
	uint stid = thread_small_id();

	privlog_log(pld, "+> %s()", routine);
	pld->level[stid]++;
}

/**
 * Log routine exit.
 */
void privlog_leavev(privlog_logdef_t *pld,
	const char *routine, const char *loc, const char *fmt, va_list args)
{
	char result[128];
	uint stid = thread_small_id();

	if (pld->level[stid] > 0) {
		pld->level[stid]--;
	} else {
		privlog_log(pld,
			"WARNING: indent level was 0 when leaving %s()", routine);
	}

	log_vbprintf(ARYLEN(result), fmt, args);

	if (result[0] != '\0')
		privlog_log(pld, "+< %s() = %s at %s", routine, result, loc);
	else
		privlog_log(pld, "+< %s() at %s", routine, loc);
}

/* vi: set ts=4 sw=4 cindent: */
