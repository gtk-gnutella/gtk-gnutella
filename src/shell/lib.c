/*
 * Copyright (c) 2013 Raphael Manfredi
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
 * @ingroup shell
 * @file
 *
 * The "lib" command.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/cq.h"
#include "lib/file_object.h"
#include "lib/hset.h"
#include "lib/misc.h"
#include "lib/pow2.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_lib_show_callout(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	pslist_t *info, *sl;
	str_t *s;
	size_t maxlen = 0;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	shell_write(sh, "100~\n");
	shell_write(sh,
		"T  Events Per. Idle Last  Period  Heartbeat  Triggered Name (Parent)"
		"\n");

	info = cq_info_list();
	s = str_new(80);

	PSLIST_FOREACH(info, sl) {
		cq_info_t *cqi = sl->data;
		size_t len;

		cq_info_check(cqi);

		len = vstrlen(cqi->name);
		maxlen = MAX(len, maxlen);
	}

	PSLIST_FOREACH(info, sl) {
		cq_info_t *cqi = sl->data;

		cq_info_check(cqi);

		if (THREAD_INVALID_ID == cqi->stid)
			str_printf(s, "%-2s ", "-");
		else
			str_printf(s, "%-2d ", cqi->stid);
		str_catf(s, "%-6zu ", cqi->event_count);
		str_catf(s, "%-4zu ", cqi->periodic_count);
		str_catf(s, "%-4zu ", cqi->idle_count);
		str_catf(s, "%-5s ",
			0 == cqi->last_idle ?
				"-" : compact_time(delta_time(tm_time(), cqi->last_idle)));
		str_catf(s, "%'6d ", cqi->period);
		str_catf(s, "%10zu ", cqi->heartbeat_count);
		str_catf(s, "%10zu ", cqi->triggered_count);
		str_catf(s, "\"%s\"%*s", cqi->name,
			(int) (maxlen - vstrlen(cqi->name)), "");
		if (cqi->parent != NULL)
			str_catf(s, " (%s)", cqi->parent);
		str_putc(s, '\n');
		shell_write(sh, str_2c(s));
	}

	str_destroy_null(&s);
	cq_info_list_free_null(&info);
	shell_write(sh, ".\n");

	return REPLY_READY;
}

static int
file_object_descriptor_by_refcnt(const void *a, const void *b)
{
	const file_object_descriptor_info_t *fda = a, *fdb = b;

	file_object_descriptor_info_check(fda);
	file_object_descriptor_info_check(fdb);

	if (fda->refcnt != fdb->refcnt)
		return fda->refcnt < fdb->refcnt ? -1 : +1;

	return CMP(fda->linger, fdb->linger);
}

static enum shell_reply
shell_exec_lib_show_files(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *opt_d, *opt_w, *opt_u;
	const option_t options[] = {
		{ "d", &opt_d },
		{ "u", &opt_u },
		{ "w", &opt_w },
	};
	int parsed;
	pslist_t *info, *sl;
	str_t *s, *f;
	size_t maxlen = 0;
	hset_t *seen = NULL;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, N_ITEMS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	if (opt_d) {
		opt_u = opt_w = NULL;		/* -d is exclusive, disables all others */
		info = file_object_descriptor_info_list();
		info = pslist_sort(info, file_object_descriptor_by_refcnt);
	} else {
		info = file_object_info_list();
	}

	s = str_new(80);

	/*
	 * When they supply -u, we remove the display of the file mode (since
	 * we could have several entries for the same file) and the location,
	 * to only print the reference count and the pathname.
	 */

	if (opt_u != NULL) {
		opt_w = NULL;		/* -u disables -w */
		seen = hset_create(HASH_KEY_STRING, 0);
	}

	/*
	 * Compute how much room we need to display the opening locations.
	 */

	if (opt_d != NULL) {
		STR_CPY(s, "Refs How  Keep Path\n");
	} else if (opt_w != NULL) {
		PSLIST_FOREACH(info, sl) {
			file_object_info_t *foi = sl->data;
			size_t len;
			const char *p;

			file_object_info_check(foi);

			p = is_strprefix(foi->file, "src/");
			if (NULL == p)
				p = foi->file;

			/*
			 * We want to estimate how many characters will be used to display
			 * the "file:line" number when they use -w.
			 *
			 * The amount of digits needed to print the number can roughly be
			 * estimated by BIT_DEC_BUFLEN(), excepted it accounts for 1 more
			 * character (the trailing NUL byte) which is actually the ':' we
			 * add between the file name and the line number.  Hence there is
			 * no need to adjust that amount.
			 */

			len = vstrlen(p) + BIT_DEC_BUFLEN(1 + highest_bit_set(foi->line));
			maxlen = MAX(len, maxlen);
		}

		maxlen = MAX(maxlen, CONST_STRLEN("Where"));

		str_printf(s, "Refs How %*s Path\n", (int) -maxlen, "Where");
	} else if (NULL == opt_u) {
		STR_CPY(s, "Refs How Path\n");
	} else {
		STR_CPY(s, "Refs Path\n");
	}

	shell_write(sh, "100~\n");
	shell_write(sh, str_2c(s));

	f = str_new(80);

	PSLIST_FOREACH(info, sl) {
		if (opt_d) {
			file_object_descriptor_info_t *fdi = sl->data;

			file_object_descriptor_info_check(fdi);

			str_printf(s, "%4d ", fdi->refcnt);
			str_catf(s, "%3s", O_RDONLY == fdi->mode ? "RO" :
				O_WRONLY == fdi->mode ? "WO" :
				O_RDWR == fdi->mode ? "RW" : "??");
			/*
			 * fdi->linger is expected to be 0 if fdi->refcnt != 0 but
			 * trace the former anyway if it's not 0, to spot possible
			 * inconsistency.
			 */
			if (0 != fdi->refcnt && 0 == fdi->linger)
				STR_CAT(s, "       ");
			else
				str_catf(s, "%6s ", compact_time(fdi->linger));
			str_cat(s, fdi->path);
		} else {
			file_object_info_t *foi = sl->data;

			file_object_info_check(foi);

			str_printf(s, "%4d ", foi->refcnt);
			if (NULL == opt_u) {
				str_catf(s, "%3s ", O_RDONLY == foi->mode ? "RO" :
					O_WRONLY == foi->mode ? "WO" :
					O_RDWR == foi->mode ? "RW" : "??");
			} else {
				if (hset_contains(seen, foi->path))
					continue;
				hset_insert(seen, foi->path);
			}
			if (opt_w != NULL) {
				const char *p;
				p = is_strprefix(foi->file, "src/");
				if (NULL == p)
					p = foi->file;
				str_printf(f, "%s:%d", p, foi->line);
				str_catf(s, "%*s ", (int) -maxlen, str_2c(f));
			}
			str_cat(s, foi->path);
		}
		str_putc(s, '\n');
		shell_write(sh, str_2c(s));
	}

	hset_free_null(&seen);
	str_destroy_null(&f);
	str_destroy_null(&s);
	if (opt_d)
		file_object_descriptor_info_list_free_null(&info);
	else
		file_object_info_list_free_null(&info);
	shell_write(sh, ".\n");

	return REPLY_READY;
}

static enum shell_reply
shell_exec_lib_show(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_lib_show_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(callout);
	CMD(files);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"show %s\""), argv[1]);
	return REPLY_ERROR;
}

/**
 * Handles the lib command.
 */
enum shell_reply
shell_exec_lib(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_lib_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(show);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_lib(void)
{
	return "Library monitoring interface";
}

const char *
shell_help_lib(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "show")) {
			if (2 == argc) {
				return
					"lib show callout      # display callout queues\n"
					"lib show files [-duw] # display open files\n";
			} else {
				if (0 == ascii_strcasecmp(argv[2], "callout")) {
					return "lib show callout\n"
						"display information about all the callout queues\n";
				} else
				if (0 == ascii_strcasecmp(argv[2], "files")) {
					return "lib show files [-uw]\n"
						"display open files\n"
						"-d: show cached file descriptors (exclusive option)\n"
						"-u: show one entry per file path "
							"(ignoring -w if supplied)\n"
						"-w: show where files were opened\n";
				}
			}
		}
	} else {
		return "lib show callout|files\n";
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
