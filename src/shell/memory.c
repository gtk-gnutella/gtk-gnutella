/*
 * Copyright (c) 2009, Christian Biere
 * Copyright (c) 2011, 2026 Raphael Manfredi
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
 * The "memory" command.
 *
 * This module declares its complete grammar in shell_grammar_memory(),
 * adjacent to the leaf handlers.  The shell's syntax engine builds a
 * read-only parser only when the first actual shell command is received.
 * It expands unique prefixes and parses node-specific options, SIZE and
 * ADDRESS arguments in the main thread before scheduling a memory worker.
 *
 * The show handlers use the pre-resolved argc/argv adapter; stats, check,
 * usage and dump consume an immutable parsed invocation.  Other shell
 * commands remain on the original dispatch path until converted.
 *
 * To extend this command, update the declarative grammar below, not the
 * central parser.  Keyword ambiguity and option validity are automatic.
 *
 * @author Christian Biere
 * @date 2009
 * @author Raphael Manfredi
 * @date 2011, 2026
 */

#include "common.h"

#include "cmd.h"
#include "syntax.h"

#include "lib/ascii.h"
#include "lib/dump_options.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/omalloc.h"
#include "lib/palloc.h"
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tmalloc.h"
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

static enum shell_reply	G_UNUSED	/* May be unused */
shell_exec_memory_dump(struct gnutella_shell *sh,
	const shell_invocation_t *inv)
{
	const unsigned char *addr = shell_invocation_pointer(inv, 2);;
	size_t length = shell_invocation_size(inv, 3);;
	int fd[2];
	str_t *s;

	shell_check(sh);

	if (pipe(fd) < 0) {
		shell_set_msg(sh, str_smsg("pipe() failed: %m"));
		goto failure;
	}

	s = str_new(128);

	while (length > 0) {
		char data[16], valid[sizeof data];
		size_t i;

		STATIC_ASSERT(sizeof data == sizeof valid);
		read_memory(fd, addr, length, ARYLEN(data), valid);

		str_cpy(s, pointer_to_string(addr));
		STR_CAT(s, "  ");

		for (i = 0; i < N_ITEMS(data); i++) {
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

		for (i = 0; i < N_ITEMS(data); i++) {
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

		if (length < N_ITEMS(data))
			break;

		length -= N_ITEMS(data);
		addr += N_ITEMS(data);
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
	/*
	 * Since g_mem_is_system_malloc() is deprecated, use pragmas to shut down
	 * the warning for now.
	 *		--RAM, 2016-02-22
	 */

	G_IGNORE_PUSH(-Wdeprecated-declarations);

	log_info(la, "glib's g_malloc() is %s the system's malloc()",
		g_mem_is_system_malloc() ? "using" : "distinct from");

	G_IGNORE_POP;
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
	show_vec_t v[4];

	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	v[0].cb = xmalloc_show_settings_log;
	v[0].prefix = NULL;
	v[1].cb = malloc_show_settings_log;
	v[1].prefix = "malloc ";
	v[2].cb = zalloc_show_settings_log;
	v[2].prefix = "zalloc ";
	v[3].cb = shell_vtable_settings_log;
	v[3].prefix = NULL;

	return memory_run_showerv(sh, v, N_ITEMS(v));
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
shell_exec_memory_show_magazines(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, tmalloc_dump_magazines_log, "TMALLOC ");
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
shell_exec_memory_show_pools(struct gnutella_shell *sh,
	int argc, const char *argv[])
{
	shell_check(sh);
	g_assert(argv);
	g_assert(argc > 0);

	return memory_run_shower(sh, palloc_dump_pool_log, "PALLOC ");
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
shell_exec_memory_stats_palloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_stats_unsupported(sh, "palloc", STATS_USAGE_STR);

	return memory_run_opt_shower(sh, palloc_dump_stats_log, "PALLOC ", opt);
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
shell_exec_memory_stats_tmalloc(struct gnutella_shell *sh,
	unsigned opt, unsigned which)
{
	if (which & STATS_USAGE)
		return memory_stats_unsupported(sh, "tmalloc", STATS_USAGE_STR);

	return memory_run_opt_shower(sh, tmalloc_dump_stats_log, "TMALLOC ", opt);
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
		PLURAL(errors));

	return REPLY_READY;
}

/*
 * Common option parsing for "memory stats" commands: -p and -u
 *
 * Options are parsed once by syntax.c, before the worker starts. */
#define MEMORY_STATS_HANDLER(name) \
static enum shell_reply \
memory_stats_ ## name (struct gnutella_shell *sh, \
	const shell_invocation_t *inv) \
{ \
	unsigned opt = shell_invocation_option(inv, "stats", 'p') ?  \
		DUMP_OPT_PRETTY : 0; \
	unsigned which = shell_invocation_option(inv, "stats", 'u') ? \
		STATS_USAGE : 0; \
	return shell_exec_memory_stats_ ## name(sh, opt, which); \
}

MEMORY_STATS_HANDLER(halloc)
MEMORY_STATS_HANDLER(omalloc)
MEMORY_STATS_HANDLER(palloc)
MEMORY_STATS_HANDLER(tmalloc)
MEMORY_STATS_HANDLER(vmm)
MEMORY_STATS_HANDLER(xmalloc)
MEMORY_STATS_HANDLER(zalloc)
#undef MEMORY_STATS_HANDLER

static enum shell_reply
memory_check_xmalloc(struct gnutella_shell *sh, const shell_invocation_t *inv)
{
	return shell_exec_memory_check_xmalloc(sh,
		shell_invocation_option(inv, "check", 'v'),
		shell_invocation_option(inv, "check", 's')
	);
}

/* The SIZE argument has already been validated in the main thread. */
static enum shell_reply
memory_usage_zone_set(struct gnutella_shell *sh,
	const shell_invocation_t *inv, bool enable)
{
	size_t size = shell_invocation_size(inv, 3);

	shell_check(sh);

	if (!zalloc_stack_accounting_ctrl(size, ZALLOC_SA_SET, enable)) {
		shell_set_msg(sh, "Operation failed");
		return REPLY_ERROR;
	}
	return REPLY_READY;
}

static enum shell_reply
memory_usage_zone_on(struct gnutella_shell *sh, const shell_invocation_t *inv)
{
	return memory_usage_zone_set(sh, inv, TRUE);
}

static enum shell_reply
memory_usage_zone_off(struct gnutella_shell *sh, const shell_invocation_t *inv)
{
	return memory_usage_zone_set(sh, inv, FALSE);
}

static enum shell_reply
memory_usage_zone_show(struct gnutella_shell *sh,
	const shell_invocation_t *inv)
{
	size_t size = shell_invocation_size(inv, 3);
	logagent_t *la = log_agent_string_make(65536, NULL);
	bool ok = zalloc_stack_accounting_ctrl(size, ZALLOC_SA_SHOW, la);

	if (ok)
		shell_write(sh, log_agent_string_get(la));
	else
		shell_set_msg(sh, "Operation failed");
	log_agent_free_null(&la);
	return ok ? REPLY_READY : REPLY_ERROR;
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
				"memory show magazines # display thread magazine information\n"
				"memory show options   # display memory options\n"
				"memory show pcache    # display VMM page cache\n"
				"memory show pmap      # display VMM pmap\n"
				"memory show pools     # display allocation pools\n"
				"memory show xmalloc   # display xmalloc() freelist info\n"
				"memory show zones     # display zone usage\n";
		} else if (0 == ascii_strcasecmp(argv[1], "stats")) {
			return "memory stats [-pu] "
				"halloc|omalloc|palloc|tmalloc|vmm|xmalloc|zalloc\n"
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
		"memory show hole|magazines|options|pmap|pools|xmalloc|zones\n"
		"memory stats [-pu] omalloc|palloc|tmalloc|vmm|xmalloc|zalloc\n"
		"memory usage zone <size> on|off|show\n"
		;
	}
	return NULL;
}


/*
 * All syntax is declared here, near the implementing handlers.  The callback
 * merely exposes immutable data and is called once at parser construction.
 * No options or keywords are parsed in any of the migrated handlers.
 */

static const shell_option_desc_t memory_stats_options[] = {
    { "p" },		/* pretty-print by groupping thousands */
	{ "u" }			/* show usage stats, if available */
};
static const shell_option_desc_t memory_check_options[] = {
    { "s" },		/* silent report, only show summary status */
	{ "v" }			/* verbosely report */
};
static const shell_grammar_t memory_show[] = {
    SHELL_LEGACY_LEAF("hole", shell_exec_memory_show_hole),
    SHELL_LEGACY_LEAF("magazines", shell_exec_memory_show_magazines),
    SHELL_LEGACY_LEAF("options", shell_exec_memory_show_options),
    SHELL_LEGACY_LEAF("pcache", shell_exec_memory_show_pcache),
    SHELL_LEGACY_LEAF("pmap", shell_exec_memory_show_pmap),
    SHELL_LEGACY_LEAF("pools", shell_exec_memory_show_pools),
    SHELL_LEGACY_LEAF("xmalloc", shell_exec_memory_show_xmalloc),
    SHELL_LEGACY_LEAF("zones", shell_exec_memory_show_zones)
};
static const shell_grammar_t memory_stats[] = {
    SHELL_LEAF("halloc", memory_stats_halloc),
    SHELL_LEAF("omalloc", memory_stats_omalloc),
    SHELL_LEAF("palloc", memory_stats_palloc),
    SHELL_LEAF("tmalloc", memory_stats_tmalloc),
    SHELL_LEAF("vmm", memory_stats_vmm),
    SHELL_LEAF("xmalloc", memory_stats_xmalloc),
    SHELL_LEAF("zalloc", memory_stats_zalloc)
};
static const shell_grammar_t memory_check[] = {
    SHELL_LEAF("xmalloc", memory_check_xmalloc)
};
static const shell_grammar_t memory_zone_actions[] = {
    SHELL_LEAF("on", memory_usage_zone_on),
    SHELL_LEAF("off", memory_usage_zone_off),
    SHELL_LEAF("show", memory_usage_zone_show)
};
static const shell_grammar_t memory_zone_sizes[] = {
    SHELL_VALUE_BRANCH("zone size", SHELL_SYNTAX_SIZE, memory_zone_actions)
};
static const shell_grammar_t memory_usage[] = {
    SHELL_BRANCH("zone", memory_zone_sizes)
};
#ifdef ALLOW_DUMP
static const shell_grammar_t memory_dump_length[] = {
    SHELL_VALUE_LEAF("length", SHELL_SYNTAX_SIZE, shell_exec_memory_dump)
};
static const shell_grammar_t memory_dump_address[] = {
    SHELL_VALUE_BRANCH("address", SHELL_SYNTAX_POINTER, memory_dump_length)
};
#endif
static const shell_grammar_t memory_commands[] = {
#ifdef ALLOW_DUMP
    SHELL_BRANCH("dump", memory_dump_address),
#endif
    SHELL_BRANCH_OPTS("check", memory_check_options, memory_check),
    SHELL_BRANCH("show", memory_show),
    SHELL_BRANCH_OPTS("stats", memory_stats_options, memory_stats),
    SHELL_BRANCH("usage", memory_usage)
};

const shell_grammar_t *
shell_grammar_memory(void)
{
    static const shell_grammar_t grammar =
        SHELL_BRANCH("memory", memory_commands);

    return &grammar;
}

/* vi: set ts=4 sw=4 cindent: */
