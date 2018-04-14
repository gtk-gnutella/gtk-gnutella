/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * @ingroup shell
 * @file
 *
 * The "log" command.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

enum shell_logtoken {
	SHELL_LOG_UNKNOWN = 0,
	SHELL_LOG_ALL,
	SHELL_LOG_OUT,
	SHELL_LOG_ERR
};

static enum shell_reply
shell_exec_log_cwd(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	char path[MAX_PATH_LEN];

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc != 1)
		return REPLY_ERROR;

	if (NULL == getcwd(ARYLEN(path))) {
		shell_set_msg(sh, _("Cannot determine current working directory"));
		return REPLY_ERROR;
	}

	shell_write(sh, str_smsg("%s\n", path));

	return REPLY_READY;
}

/**
 * Tokenize log name token.
 */
static enum shell_logtoken
shell_log_tokenize(const char *str)
{
	int c = ascii_tolower(str[0]);

	if ('a' == c) {
		if (0 == ascii_strcasecmp(str, "all"))
			return SHELL_LOG_ALL;
	} else if ('o' == c) {
		if (0 == ascii_strcasecmp(str, "out"))
			return SHELL_LOG_OUT;
	} else if ('e' == c) {
		if (0 == ascii_strcasecmp(str, "err"))
			return SHELL_LOG_ERR;
	}

	return SHELL_LOG_UNKNOWN;
}

/**
 * Translate a log name token into a log file enum.
 */
static inline enum log_file
token_to_logfile(const enum shell_logtoken tok)
{
	return SHELL_LOG_ERR == tok ? LOG_STDERR : LOG_STDOUT;
}

/**
 * Report unknown logfile name and return REPLY_ERROR.
 */
static enum shell_reply
shell_unknown_logfile(struct gnutella_shell *sh, const char *name)
{
	shell_set_msg(sh, str_smsg(_("Unknown logfile name \"%s\""), name));
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_log_reopen(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	enum shell_logtoken which = SHELL_LOG_ALL;
	bool ok = FALSE;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 3)
		goto done;

	if (2 == argc) {
		which = shell_log_tokenize(argv[1]);
		if (SHELL_LOG_UNKNOWN == which)
			return shell_unknown_logfile(sh, argv[1]);
	}

	if (SHELL_LOG_ALL == which)
		ok = log_reopen_all(FALSE);
	else
		ok = log_reopen_if_managed(token_to_logfile(which));

	if (!ok)
		shell_set_msg(sh, _("Unable to reopen"));

done:
	return ok ? REPLY_READY : REPLY_ERROR;
}

static enum shell_reply
shell_exec_log_set(struct gnutella_shell *sh, int argc, const char *argv[])
{
	enum shell_logtoken which;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc != 3)
		return REPLY_ERROR;

	which = shell_log_tokenize(argv[1]);
	if (SHELL_LOG_UNKNOWN == which || SHELL_LOG_ALL == which)
		return shell_unknown_logfile(sh, argv[1]);

	log_set(token_to_logfile(which), argv[2]);
	return REPLY_READY;
}

static enum shell_reply
shell_exec_log_rename(struct gnutella_shell *sh, int argc, const char *argv[])
{
	enum shell_logtoken which;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc != 3)
		return REPLY_ERROR;

	which = shell_log_tokenize(argv[1]);
	if (SHELL_LOG_UNKNOWN == which || SHELL_LOG_ALL == which)
		return shell_unknown_logfile(sh, argv[1]);

	if (!log_rename(token_to_logfile(which), argv[2])) {
		shell_set_msg(sh,
			str_smsg(_("Could not rename logfile as \"%s\": %m"), argv[2]));
		return REPLY_ERROR;
	}

	return REPLY_READY;
}

/**
 * Print logfile statistics.
 */
static void
shell_log_stats(struct gnutella_shell *sh, enum log_file which)
{
	struct logstat buf;
	time_delta_t d;

	log_stat(which, &buf);
	d = buf.otime != 0 ? delta_time(tm_time(), buf.otime) : 0;

	shell_write(sh, str_smsg("%4s %c%c%c %9s %11s %s\n",
		buf.name, NULL == buf.path ? 'U' : ' ',
		buf.disabled ? 'D' : 'E',
		buf.need_reopen ? 'R' : 'O',
		compact_time(d), short_byte_size(buf.size, FALSE),
		NULL == buf.path ? "-" : buf.path));
}

static enum shell_reply
shell_exec_log_status(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	enum shell_logtoken which = SHELL_LOG_ALL;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 3)
		return REPLY_ERROR;

	if (2 == argc) {
		which = shell_log_tokenize(argv[1]);
		if (SHELL_LOG_UNKNOWN == which)
			return shell_unknown_logfile(sh, argv[1]);
	}

	shell_write(sh, "NAME FLG    OPENED        SIZE PATH\n");

	if (SHELL_LOG_ALL == which || SHELL_LOG_OUT == which)
		shell_log_stats(sh, LOG_STDOUT);

	if (SHELL_LOG_ALL == which || SHELL_LOG_ERR == which)
		shell_log_stats(sh, LOG_STDERR);

	return REPLY_READY;
}

/**
 * Handle the "LOG" command.
 */
enum shell_reply
shell_exec_log(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_log_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(cwd);
	CMD(rename);
	CMD(reopen);
	CMD(set);
	CMD(status);

	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
	return REPLY_ERROR;
}

const char *
shell_summary_log(void)
{
	return "Manage log files";
}

const char *
shell_help_log(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "reopen")) {
			return "log reopen [out|err|all]\n"
				"re-opens specified log file (all by default)\n";
		} else if (0 == ascii_strcasecmp(argv[1], "rename")) {
			return "log rename out|err newname\n"
				"renames specified current log file, then reopens it\n";
		} else if (0 == ascii_strcasecmp(argv[1], "set")) {
			return "log set out|err path\n"
				"specifies new path for log file (needs reopen)\n";
		} else if (0 == ascii_strcasecmp(argv[1], "status")) {
			return "log status [out|err|all]\n"
				"display logfile status (all by default)\n";
		} else if (0 == ascii_strcasecmp(argv[1], "cwd")) {
			return "log cwd\n"
				"display current working directory\n";
		}
	} else {
		return
			"log cwd\n"
			"log rename\n"
			"log reopen\n"
			"log set\n"
			"log status\n"
			"Use \"help log <cmd>\" for additional information\n";
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
