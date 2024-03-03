/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * The "random" command.
 *
 * This cheaply turns gtk-gnutella into a random number server.
 *
 * The random numbers generated come from the AJE layer, i.e. are perfectly
 * random and the sequence is totally unpredictable.  The AJE layer is fed
 * some entropy on a regular basis and the output is cryptographically strong,
 * meaning these random numbers can be used to generate certificates or keys.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "cmd.h"

#include "lib/aje.h"
#include "lib/ascii.h"
#include "lib/base16.h"
#include "lib/dump_options.h"
#include "lib/log.h"
#include "lib/options.h"
#include "lib/parse.h"
#include "lib/random.h"
#include "lib/str.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define RANDOM_BYTES_MAX	4096	/* Max amount of random bytes we generate */
#define RANDOM_NUM_MAX		1024	/* Max amount of entries we generate */

/**
 * Parse value as an unsigned 32-bit integer.
 *
 * @param sh		the shell for which we're processing the command
 * @param what		the item being parsed
 * @param value		the option value
 * @param result	where the parsed value is returned
 *
 * @return TRUE if OK, FALSE on error with an error message emitted.
 */
static bool
shell_parse_uint32(struct gnutella_shell *sh,
	const char *what, const char *value, uint32 *result)
{
	int error;
	uint base;
	const char *start;

	base = parse_base(value, &start);
	if (0 == base) {
		error = EINVAL;
		goto failed;
	}

	*result = parse_uint32(start, NULL, base, &error);
	if (error != 0)
		goto failed;

	return TRUE;

failed:
	shell_write_linef(sh, REPLY_ERROR, "cannot parse %s: %s",
		what, g_strerror(error));

	return FALSE;
}

/**
 * Show random number stats.
 */
static enum shell_reply
shell_exec_random_stats(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *pretty;
	const option_t options[] = {
		{ "p", &pretty },			/* pretty-print */
	};
	int parsed;
	unsigned opt = 0;
	logagent_t *la = log_agent_string_make(0, "RANDOM ");

	shell_check(sh);

	parsed = shell_options_parse(sh, argv, options, N_ITEMS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;		/* args[0] is first command argument */
	argc -= parsed;		/* counts only command arguments now */

	if (pretty != NULL)
		opt |= DUMP_OPT_PRETTY;

	random_dump_stats_log(la, opt);

	shell_write(sh, "100~\n");
	shell_write(sh, log_agent_string_get(la));
	shell_write(sh, ".\n");

	log_agent_free_null(&la);

	return REPLY_READY;
}

/**
 * Generate random numbers.
 */
static enum shell_reply
shell_exec_random_val(struct gnutella_shell *sh, int argc, const char *argv[])
{
	const char *opt_x, *opt_b, *opt_n, *opt_s;
	const option_t options[] = {
		{ "b:", &opt_b },			/* how many bytes to generate */
		{ "n:", &opt_n },			/* how many numbers to generate */
		{ "s",  &opt_s },			/* use "random_strong" instead of AJE */
		{ "x",  &opt_x },			/* display in hexadecimal */
	};
	uint32 upper = 255, lower = 0;
	uint32 bytes = 1, amount = 1;
	int parsed;
	char *buf = NULL, *hexbuf = NULL;
	enum shell_reply result = REPLY_ERROR;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	parsed = shell_options_parse(sh, argv, options, N_ITEMS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;		/* argv[0] is now the first command argument */
	argc -= parsed;		/* Only counts remaining arguments */

	if (argc >= 1) {
		if (!shell_parse_uint32(sh, "upper", argv[0], &upper))
			goto failed;
	}

	if (argc >= 2) {
		if (!shell_parse_uint32(sh, "lower", argv[1], &lower))
			goto failed;
	}

	if (upper < lower) {
		shell_write_line(sh, REPLY_ERROR,
			"upper boundary smaller than the lower one");
		goto failed;
	}

	if (opt_b != NULL) {
		if (argc >= 1) {
			shell_write_line(sh, REPLY_ERROR,
				"cannot specify upper or lower boundaries with -b");
			goto failed;
		}

		if (!shell_parse_uint32(sh, "-b", opt_b, &bytes))
			goto failed;

		bytes = MIN(bytes, RANDOM_BYTES_MAX);
		buf = xmalloc(bytes);
		hexbuf = xmalloc(2 * bytes + 1);	/* Hexa format + trailing NUL */
		hexbuf[2 * bytes] = '\0';
	}

	if (opt_n != NULL) {
		if (!shell_parse_uint32(sh, "-n", opt_n, &amount))
			goto failed;

		amount = MIN(amount, RANDOM_NUM_MAX);
	}

	while (amount-- != 0) {
		if (buf != NULL) {
			if (opt_s != NULL) {
				random_strong_bytes(buf, bytes);
			} else {
				aje_random_bytes(buf, bytes);
			}
			base16_encode(hexbuf, 2 * bytes, buf, bytes);
			shell_write_line(sh, REPLY_READY, hexbuf);
		} else {
			int32 r;
			random_fn_t rf = opt_s != NULL ? random_strong : aje_rand_strong;

			r = lower + random_upto(rf, upper - lower);
			shell_write_line(sh, REPLY_READY,
				str_smsg(opt_x != NULL ? "%x" : "%d", r));
		}
	}

	result = REPLY_READY;
	goto done;

failed:
	shell_set_msg(sh, _("Invalid command syntax"));

	/* FALL THROUGH */

done:
	XFREE_NULL(buf);
	XFREE_NULL(hexbuf);
	return result;
}

enum shell_reply
shell_exec_random(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_random_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(stats);

#undef CMD

	return shell_exec_random_val(sh, argc, argv);

}

const char *
shell_summary_random(void)
{
	return "Generate random numbers";
}

const char *
shell_help_random(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		if (0 == ascii_strcasecmp(argv[1], "stats")) {
			return "random stats [-p]\n"
				"show statistics about random numbers\n"
				"-p: pretty-print numbers with thousands separators\n";
		}
	}

	return "random [-b bytes] [-n amount] [-sx] [upper [lower]]\n"
		"Generate uniformly distributed random numbers.\n"
		"By default: upper=255, lower=0\n"
		"Values given as decimal, hexadecimal (0x), octal (0) or binary (0b)\n"
		"-b : amount of random bytes to generate (implies -x), max 4096.\n"
		"-n : amount of numbers or sequences of random bytes (1024 max).\n"
		"-s : use RC4-encrypted WELL instead of AJE randomness.\n"
		"-x : display numbers in hexadecimal.\n"
		"(see also 'help random stats')\n";
}

/* vi: set ts=4 sw=4 cindent: */
