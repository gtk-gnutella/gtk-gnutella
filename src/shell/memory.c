/*
 * Copyright (c) 2009, Christian Biere
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
 * The "memory" command.
 *
 * @author Christian Biere
 * @date 2009
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "cmd.h"

#include "lib/ascii.h"
#include "lib/dump_options.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/omalloc.h"
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/vmm.h"
#include "lib/xmalloc.h"
#include "lib/zalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#if defined(MALLOC_STATS) || defined(MALLOC_FRAMES) || \
	defined(TRACK_MALLOC) || defined(TRACK_ZALLOC)
#define ALLOW_DUMP
#endif

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

static inline enum shell_reply	/* "inline" to avoid warning if unused */
shell_exec_memory_dump(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const unsigned char *addr;
	const char *endptr;
	size_t length;
	int error, fd[2];
	str_t *s;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (2 != argc) {
		shell_set_formatted(sh, "Invalid parameter count (%d)", argc);
		goto failure;
	}
	addr = parse_pointer(argv[0], &endptr, &error);
	if (error || NULL == addr || '\0' != *endptr) {
		shell_set_msg(sh, "Bad address");
		goto failure;
	}
	length = parse_size(argv[1], &endptr, 10, &error);
	if (error || '\0' != *endptr) {
		shell_set_msg(sh, "Bad length");
		goto failure;
	}

	if (pipe(fd) < 0) {
		shell_set_msg(sh, "pipe() failed");
		goto failure;
	}

	s = str_new(128);

	while (length > 0) {
		char data[16], valid[sizeof data];
		size_t i;

		STATIC_ASSERT(sizeof data == sizeof valid);
		read_memory(fd, addr, length, data, sizeof data, valid);

		str_cpy(s, pointer_to_string(addr));
		STR_CAT(s, "  ");

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];

				if (valid[i]) {
					str_putc(s, hex_digit((c >> 4) & 0xf));
					str_putc(s, hex_digit(c & 0x0f));
					str_putc(s, ' ');
				} else {
					STR_CAT(s, "XX ");
				}
			} else {
				STR_CAT(s, "   ");
			}
		}
		STR_CAT(s, " |");

		for (i = 0; i < G_N_ELEMENTS(data); i++) {
			if (length > i) {
				unsigned char c = data[i];
				c = is_ascii_print(c) ? c : '.';
				str_putc(s, c);
			} else {
				str_putc(s, ' ');
			}
		}
		STR_CAT(s, "|\n");
		shell_write(sh, str_2c(s));

		if (length < G_N_ELEMENTS(data))
			break;

		length -= G_N_ELEMENTS(data);
		addr += G_N_ELEMENTS(data);
	}
	str_destroy(s);
	fd_close(&fd[0]);
	fd_close(&fd[1]);
	return REPLY_READY;

failure:
	return REPLY_ERROR;
}

static void
shell_vtable_settings_log(logagent_t *la)
{
	log_info(la, "glib's g_malloc() is %s the system's malloc()",
		g_mem_is_system_malloc() ? "using" : "distinct from");
}

typedef void (*shower_cb_t)(logagent_t *la);
typedef void (*shower_opt_cb_t)(logagent_t *la, unsigned options);

typedef struct show_vec {
	shower_cb_t cb;
	const char *prefix;
} show_vec_t;

typedef struct show_opt_vec {
	shower_opt_cb_t cb;
	const char *prefix;
	unsigned options;
} show_opt_vec_t;

static enum shell_reply
memory_run_showerv(struct gnutella_shell *sh, show_vec_t *sv, unsigned sv_cnt)
{
	unsigned i;

	shell_check(sh);

	shell_write(sh, "100~\n");

	for (i = 0; i < sv_cnt; i++) {
		show_vec_t *v = &sv[i];
		logagent_t *la = log_agent_string_make(0, v->prefix);
		(*v->cb)(la);
		shell_write(sh, log_agent_string_get(la));
		log_agent_free_null(&la);
	}

	shell_write(sh, ".\n");

	return REPLY_READY;
}

static enum shell_reply
memory_run_opt_showerv(struct gnutella_shell *sh,
	show_opt_vec_t *sv, unsigned sv_cnt)
{
	unsigned i;

	shell_check(sh);

	shell_write(sh, "100~\n");

	for (i = 0; i < sv_cnt; i++) {
		show_opt_vec_t *v = &sv[i];
		logagent_t *la = log_agent_string_make(0, v->prefix);
		(*v->cb)(la, v->options);
		shell_write(sh, log_agent_string_get(la));
		log_agent_free_null(&la);
	}

	shell_write(sh, ".\n");

	return REPLY_READY;
}

static enum shell_reply
memory_run_shower(struct gnutella_shell *sh,
	shower_cb_t cb, const char *prefix)
{
	show_vec_t v;

	shell_check(sh);

	v.cb = cb;
	v.prefix = prefix;

	return memory_run_showerv(sh, &v, 1);
}

static enum shell_reply
memory_run_opt_shower(struct gnutella_shell *sh,
	shower_opt_cb_t cb, const char *prefix, bool options)
{
	show_opt_vec_t v;

	shell_check(sh);

	v.cb = cb;
	v.prefix = prefix;
	v.options = options;
 
	return memory_run_opt_showerv(sh, &v, 1);
}

static enum shell_reply
shell_exec_memory_show_options(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	show_vec_t v[3];

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	v[0].cb = xmalloc_show_settings_log;
	v[0].prefix = NULL;
	v[1].cb = malloc_show_settings_log;
	v[1].prefix = "malloc ";
	v[2].cb = shell_vtable_settings_log;
	v[2].prefix = NULL;

	return memory_run_showerv(sh, v, G_N_ELEMENTS(v));
}

static enum shell_reply
shell_exec_memory_show_hole(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, vmm_dump_hole_log, "VMM ");
}

static enum shell_reply
shell_exec_memory_show_pcache(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, vmm_dump_pcache_log, "VMM ");
}

static enum shell_reply
shell_exec_memory_show_pmap(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, vmm_dump_pmap_log, "VMM ");
}

static enum shell_reply
shell_exec_memory_show_xmalloc(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, xmalloc_dump_freelist_log, "XM ");
}

static enum shell_reply
shell_exec_memory_show_zones(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, zalloc_dump_zones_log, "ZALLOC ");
}

static enum shell_reply
shell_exec_memory_show(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_memory_show_## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(hole);
	CMD(options);
	CMD(pcache);
	CMD(pmap);
	CMD(xmalloc);
	CMD(zones);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"show %s\""), argv[1]);
	return REPLY_ERROR;
}

#define STATS_USAGE		(1 << 0)

static const char STATS_USAGE_STR[] = "usage";

static enum shell_reply
memory_stats_unsupported(struct gnutella_shell *sh,
	const char *layer, const char *which)
{
	shell_set_formatted(sh, "The %s layer is not offering %s statistics",
		layer, which);
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_memory_stats_halloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_stats_unsupported(sh, "halloc", STATS_USAGE_STR);

	return memory_run_opt_shower(sh, halloc_dump_stats_log, "HALLOC ", opt);
}

static enum shell_reply
shell_exec_memory_stats_vmm(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_run_opt_shower(sh, vmm_dump_usage_log, "VMM ", opt);

	return memory_run_opt_shower(sh, vmm_dump_stats_log, "VMM ", opt);
}

static enum shell_reply
shell_exec_memory_stats_xmalloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_run_opt_shower(sh, xmalloc_dump_usage_log, "XM ", opt);

	return memory_run_opt_shower(sh, xmalloc_dump_stats_log, "XM ", opt);
}

static enum shell_reply
shell_exec_memory_stats_zalloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_run_opt_shower(sh, zalloc_dump_usage_log, NULL, opt);

	return memory_run_opt_shower(sh, zalloc_dump_stats_log, "ZALLOC ", opt);
}

static enum shell_reply
shell_exec_memory_stats_omalloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_stats_unsupported(sh, "omalloc", STATS_USAGE_STR);

	return memory_run_opt_shower(sh, omalloc_dump_stats_log, "OMALLOC ", opt);
}

static enum shell_reply
shell_exec_memory_stats(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *pretty, *usage;
	const option_t options[] = {
		{ "p", &pretty },		/* pretty-print */
		{ "u", &usage },		/* usage stats, if available */
	};
	int parsed;
	unsigned opt = 0;
	unsigned which = 0;

	shell_check(sh);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;	/* args[0] is first command argument */
	argc -= parsed;	/* counts only command arguments now */

	if (argc < 1)
		return REPLY_ERROR;

	if (pretty != NULL)
		opt |= DUMP_OPT_PRETTY;
	if (usage != NULL)
		which |= STATS_USAGE;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[0], #name)) \
		return shell_exec_memory_stats_## name(sh, opt, which); \
} G_STMT_END

	CMD(halloc);
	CMD(vmm);
	CMD(xmalloc);
	CMD(zalloc);
	CMD(omalloc);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"stats %s\""), argv[0]);
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_memory_check_xmalloc(struct gnutella_shell *sh,
	bool verbose, bool summary)
{
	size_t errors;
	logagent_t *la = log_agent_string_make(0, "XM ");
	unsigned vflags = XMALLOC_FLCF_LOCK;

	vflags |= verbose ? XMALLOC_FLCF_STATUS : 0;
	vflags |= summary ? 0 : XMALLOC_FLCF_VERBOSE;

	if (vflags != XMALLOC_FLCF_LOCK)
		shell_write(sh, "100~\n");

	errors = xmalloc_freelist_check(la, vflags);
	shell_write(sh, log_agent_string_get(la));
	log_agent_free_null(&la);

	if (vflags != XMALLOC_FLCF_LOCK)
		shell_write(sh, ".\n");

	shell_write_linef(sh, REPLY_READY, "Found %zu freelist%s in error",
		errors, plural(errors));

	return REPLY_READY;
}

static enum shell_reply
shell_exec_memory_check(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	const char *verbose, *summary;
	const option_t options[] = {
		{ "v", &verbose },		/* verbosely report */
		{ "s", &summary },		/* silent report, only show summary status */
	};
	int parsed;

	shell_check(sh);

	parsed = shell_options_parse(sh, argv, options, G_N_ELEMENTS(options));
	if (parsed < 0)
		return REPLY_ERROR;

	argv += parsed;	/* args[0] is first command argument */
	argc -= parsed;	/* counts only command arguments now */

	if (argc < 1)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[0], #name)) \
		return shell_exec_memory_check_## name(sh, \
			verbose != NULL, summary != NULL); \
} G_STMT_END

	CMD(xmalloc);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"check %s\""), argv[0]);
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_memory_usage_zone(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	size_t size;
	const char *endptr;
	int error;
	bool ok;

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 3)
		return REPLY_ERROR;

	/*
	 * Parse the zone size.
	 */

	size = parse_size(argv[1], &endptr, 10, &error);
	if (error || '\0' != *endptr) {
		shell_set_formatted(sh, "Cannot parse zone size \"%s\"", argv[1]);
		goto failed;
	}

	/*
	 * Action: on, off or show.
	 */

	if (0 == ascii_strcasecmp(argv[2], "on")) {
		ok = zalloc_stack_accounting_ctrl(size, ZALLOC_SA_SET, TRUE);
	} else if (0 == ascii_strcasecmp(argv[2], "off")) {
		ok = zalloc_stack_accounting_ctrl(size, ZALLOC_SA_SET, FALSE);
	} else if (0 == ascii_strcasecmp(argv[2], "show")) {
		logagent_t *la = log_agent_string_make(65536, NULL);
		ok = zalloc_stack_accounting_ctrl(size, ZALLOC_SA_SHOW, la);
		if (ok)
			shell_write(sh, log_agent_string_get(la));
		log_agent_free_null(&la);
	} else {
		shell_set_formatted(sh, "Unknown action \"%s\" on zone %zu",
			argv[2], size);
		goto failed;
	}

	if (!ok) {
		shell_set_formatted(sh, "Operation failed");
		return REPLY_ERROR;
	}

	return REPLY_READY;

failed:
	return REPLY_ERROR;
}

static enum shell_reply
shell_exec_memory_usage(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_memory_usage_## name(sh, argc - 1, argv + 1); \
} G_STMT_END

	CMD(zone);

#undef CMD

	shell_set_formatted(sh, _("Unknown operation \"usage %s\""), argv[1]);
	return REPLY_ERROR;
}

/**
 * Handles the memory command.
 */
enum shell_reply
shell_exec_memory(struct gnutella_shell *sh, int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	if (argc < 2)
		return REPLY_ERROR;

#define CMD(name) G_STMT_START { \
	if (0 == ascii_strcasecmp(argv[1], #name)) \
		return shell_exec_memory_ ## name(sh, argc - 1, argv + 1); \
} G_STMT_END

#ifdef ALLOW_DUMP
	CMD(dump);
#endif
	CMD(check);
	CMD(show);
	CMD(stats);
	CMD(usage);

#undef CMD
	
	shell_set_formatted(sh, _("Unknown operation \"%s\""), argv[1]);
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
#ifdef ALLOW_DUMP
		if (0 == ascii_strcasecmp(argv[1], "dump")) {
			return "memory dump ADDRESS LENGTH\n"
				"dumps LENGTH bytes of memory starting at ADDRESS\n";
		} else
#endif
		if (0 == ascii_strcasecmp(argv[1], "check")) {
			return "memory check [-sv] xmalloc\n"
				"run consistency checks on freelists\n"
				"-s : silent mode, only display summary at the end\n"
				"-v : verbosely report for each freelist\n";
		}
		else if (0 == ascii_strcasecmp(argv[1], "show")) {
			return
				"memory show hole      # display VMM first known hole\n"
				"memory show options   # display memory options\n"
				"memory show pcache    # display VMM page cache\n"
				"memory show pmap      # display VMM pmap\n"
				"memory show xmalloc   # display xmalloc() freelist info\n"
				"memory show zones     # display zone usage\n";
		} else if (0 == ascii_strcasecmp(argv[1], "stats")) {
			return "memory stats [-pu] halloc|omalloc|vmm|xmalloc|zalloc\n"
				"show statistics about specified memory sub-system\n"
				"-p : pretty-print numbers with thousands separators\n"
				"-u : show allocation usage statistics, if available\n";
		} else if (0 == ascii_strcasecmp(argv[1], "usage")) {
			return "memory usage zone <size> on|off|show\n"
				"show or turn on/off usage statistics for given zone\n";
		}
	} else {
		return
#ifdef ALLOW_DUMP
		"memory dump ADDRESS LENGTH\n"
#endif
		"memory check xmalloc\n"
		"memory show hole|options|pmap|xmalloc|zones\n"
		"memory stats [-pu] omalloc|vmm|xmalloc|zalloc\n"
		"memory usage zone <size> on|off|show\n"
		;
	}
	return NULL;
}

/* vi: set ts=4 sw=4 cindent: */
