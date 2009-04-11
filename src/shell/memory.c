/*
 * $Id$
 *
 * Copyright (c) 2009, Christian Biere
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

#include "common.h"

RCSID("$Id$")

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/misc.h"
#include "lib/file.h"

#include "lib/override.h"		/* Must be the last header included */

static enum shell_reply
shell_exec_memory_dump(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const unsigned char *addr;
	const char *endptr;
	size_t length;
	int error, fd[2];

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (4 != argc) {
		shell_set_msg(sh, "Invalid parameter count");
		goto failure;
	}
	addr = parse_pointer(argv[2], &endptr, &error);
	if (error || NULL == addr || '\0' != *endptr) {
		shell_set_msg(sh, "Bad address");
		goto failure;
	}
	length = parse_size(argv[3], &endptr, 10, &error);
	if (error || '\0' != *endptr) {
		shell_set_msg(sh, "Bad length");
		goto failure;
	}

	if (pipe(fd) < 0) {
		shell_set_msg(sh, "pipe() failed");
		goto failure;
	}

	while (length > 0) {
		char buf[128], data[16], valid[G_N_ELEMENTS(data)], *p;
		size_t i;

		memset(data, 0, sizeof data);
		memset(valid, 0, sizeof valid);
		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			ssize_t ret;

			ret = write(fd[1], &addr[i], 1);
			if (1 != ret)
				continue;

			read(fd[0], &data[i], 1);
			if (1 != ret)
				continue;
			valid[i] = 1;
		}

		p = buf + pointer_to_string_buf(addr, buf, sizeof buf);
		*p++ = ' ';
		*p++ = ' ';

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];

				if (valid[i]) {
					*p++ = hex_digit((c >> 4) & 0xf);
					*p++ = hex_digit(c & 0x0f);
				} else {
					*p++ = 'X';
					*p++ = 'X';
				}
			} else {
				*p++ = ' ';
				*p++ = ' ';
			}
			*p++ = ' ';
		}
		*p++ = ' ';
		*p++ = '|';

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];
				*p++ = is_ascii_print(c) ? c : '.';
			} else {
				*p++ = ' ';
			}
		}
		*p++ = '|';
		*p++ = '\n';
		*p = '\0';
		shell_write(sh, buf);

		if (length < G_N_ELEMENTS(data))
			break;

		length -= G_N_ELEMENTS(data);
		addr += G_N_ELEMENTS(data);
	}
	close(fd[0]);
	close(fd[1]);
	return REPLY_READY;

failure:
	return REPLY_ERROR;
}

/**
 * Handles the download command.
 */
enum shell_reply
shell_exec_memory(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		goto error;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_memory_ ## name(sh, argc, argv); \
} G_STMT_END

	CMD(dump);
#undef CMD
	
	shell_set_msg(sh, _("Unknown operation"));
	goto error;

error:
	return REPLY_ERROR;
}

const char *
shell_summary_memory(void)
{
	return "Memory access interface";
}

const char *
shell_help_memory(int argc, const char *argv[])
{
	g_assert(argv);
	g_assert(argc > 0);

	if (argc > 1) {
		/* FIXME */
		return NULL;
	} else {
		return "memory dump ADDRESS LENGTH\n";
	}
}

/* vi: set ts=4 sw=4 cindent: */
