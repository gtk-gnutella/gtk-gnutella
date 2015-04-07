/*
 * Copyright (c) 2002-2003, Richard Eckart
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
 * The "shutdown" command.
 *
 * @author Richard Eckart
 * @date 2002-2003
 */

#include "common.h"

#include "cmd.h"

#include "if/core/main.h"

#include "lib/crash.h"
#include "lib/str.h"
#include "lib/product.h"

#include "lib/override.h"		/* Must be the last header included */

static const char *
shutdown_mode_string(enum shutdown_mode mode)
{
	switch (mode) {
	case GTKG_SHUTDOWN_NORMAL:	break;
	case GTKG_SHUTDOWN_ASSERT:	return " (followed by assertion failure)";
	case GTKG_SHUTDOWN_ERROR:	return " (followed by forced error)";
	case GTKG_SHUTDOWN_MEMORY:	return " (followed by memory error)";
	case GTKG_SHUTDOWN_SIGNAL:	return " (followed by harmful signal)";
	}

	return "";
}

enum shell_reply
shell_exec_shutdown(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *opt_a, *opt_c, *opt_e, *opt_f, *opt_m, *opt_r, *opt_s;
	const option_t options[] = {
		{ "a", &opt_a },
		{ "c", &opt_c },
		{ "e", &opt_e },
		{ "f", &opt_f },
		{ "m", &opt_m },
		{ "r", &opt_r },
		{ "s", &opt_s },
	};
	int parsed;
	enum shutdown_mode mode;
	unsigned flags = 0;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	if (opt_a != NULL) {
		mode = GTKG_SHUTDOWN_ASSERT;
	} else if (opt_e != NULL) {
		mode = GTKG_SHUTDOWN_ERROR;
	} else if (opt_m != NULL) {
		mode = GTKG_SHUTDOWN_MEMORY;
	} else if (opt_s != NULL) {
		mode = GTKG_SHUTDOWN_SIGNAL;
	} else {
		mode = GTKG_SHUTDOWN_NORMAL;
	}

	if (opt_c != NULL)
		flags |= GTKG_SHUTDOWN_OCRASH;
	if (opt_f != NULL)
		flags |= GTKG_SHUTDOWN_OFAST;
	if (opt_r != NULL)
		flags |= GTKG_SHUTDOWN_ORESTART;

	if ((flags & GTKG_SHUTDOWN_ORESTART) && mode != GTKG_SHUTDOWN_NORMAL) {
		shell_set_msg(sh,
			"The -a, -e, -m and -s options are incompatible with -r.");
		return REPLY_ERROR;
	}

	/*
	 * Turn auto-restart on or off in case we crash from now on.
	 */

	crash_ctl(NULL == opt_r ? CRASH_FLAG_CLEAR : CRASH_FLAG_SET,
		CRASH_F_RESTART);

	gtk_gnutella_request_shutdown(mode, flags);

	shell_write_linef(sh, REPLY_READY, "%s %s%ssequence initiated%s.",
		(flags & GTKG_SHUTDOWN_ORESTART) ? "Restart" : "Shutdown",
		(flags & GTKG_SHUTDOWN_OFAST) ? "fast " : "",
		(flags & GTKG_SHUTDOWN_OCRASH) ? "(as if crashing) " : "",
		shutdown_mode_string(mode));

	shell_exit(sh);
	return REPLY_NONE;
}

const char *
shell_summary_shutdown(void)
{
	return str_smsg("Terminate %s", product_get_name());
}

const char *
shell_help_shutdown(int argc, const char *argv[])
{
	(void) argc;
	(void) argv;
	return str_smsg("shutdown [-fr] [-acems]\n"
		"Initiates a shutdown/restart of %s.\n"
		"As a side effect the shell connection is closed as well.\n"
		"-f: request fast shutdown, sending BYE only to nodes supporting it\n"
		"-r: request immediate restart after shutdown\n"
		"The following help trigger a crash after shutdown has completed\n"
		"to exercise the crash handler and make sure everything works:\n"
		"-a: finish with assertion failure\n"
		"-c: simulate a crashing condition\n"
		"-e: finish with forced error\n"
		"-m: finish with memory error\n"
		"-s: finish with harmful signal\n",
		product_get_name());
}

/* vi: set ts=4 sw=4 cindent: */
