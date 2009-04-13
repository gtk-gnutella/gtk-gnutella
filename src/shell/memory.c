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

/**
 * Reads a piece of memory from the process address space using a pipe. As
 * write() fails with EFAULT for unreadable bytes, accessing such memory
 * doesn't raise a signal. The array "valid" is used to record which bytes in
 * "dst" are successfully copied from "addr".
 *
 * @param fd Array of 2 filescriptors initialized by pipe().
 * @param addr The source address to read from.
 * @param length The maximum number of bytes to read.
 * @param dst The destination buffer.
 * @param size The size of destination buffer.
 * @param valid The buffer to record validity of bytes in "dst". MUST be
 *        as large as "dst". If valid[i] is not zero, dst[i] is valid,
 *        otherwise addr[i] could not be read and dst[i] is zero.
 */
static inline void
read_memory(int fd[2], const unsigned char *addr, size_t length,
	char *dst, size_t size, char *valid)
{
	size_t i;

	memset(dst, 0, size);
	memset(valid, 0, size);

	size = MIN(length, size);
	for (i = 0; i < size; i++) {
		if (1 != write(fd[1], &addr[i], 1))
			continue;
		if (1 != read(fd[0], &dst[i], 1))
			break;
		valid[i] = 1;
	}
}

static enum shell_reply
shell_exec_memory_dump(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const unsigned char *addr;
	const char *endptr;
	size_t length;
	int error, fd[2];
	GString *gs;

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

	gs = g_string_sized_new(128);
	while (length > 0) {
		char data[16], valid[sizeof data];
		size_t i;

		STATIC_ASSERT(sizeof data == sizeof valid);
		read_memory(fd, addr, length, data, sizeof data, valid);

		gs = g_string_assign(gs, pointer_to_string(addr));
		gs = g_string_append(gs, "  ");

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];

				if (valid[i]) {
					gs = g_string_append_c(gs, hex_digit((c >> 4) & 0xf));
					gs = g_string_append_c(gs, hex_digit(c & 0x0f));
					gs = g_string_append_c(gs, ' ');
				} else {
					gs = g_string_append(gs, "XX ");
				}
			} else {
				gs = g_string_append(gs, "   ");
			}
		}
		gs = g_string_append(gs, " |");

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];
				c = is_ascii_print(c) ? c : '.';
				gs = g_string_append_c(gs, c);
			} else {
				gs = g_string_append_c(gs, ' ');
			}
		}
		gs = g_string_append(gs, "|\n");
		shell_write(sh, gs->str);

		if (length < G_N_ELEMENTS(data))
			break;

		length -= G_N_ELEMENTS(data);
		addr += G_N_ELEMENTS(data);
	}
	g_string_free(gs, TRUE);
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
