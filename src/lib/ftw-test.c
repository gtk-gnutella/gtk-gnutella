/*
 * ftw-test -- file tree walker unit tests.
 *
 * Copyright (c) 2015 Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"

#include "etree.h"
#include "ftw.h"
#include "halloc.h"
#include "hset.h"
#include "hstrfn.h"
#include "misc.h"
#include "progname.h"
#include "stacktrace.h"
#include "str.h"
#include "stringify.h"
#include "strtok.h"
#include "walloc.h"

#include "override.h"

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-hls] rootdir\n"
		"       [-z fn1,fn2...]\n"
		"  -h : prints this help message\n"
		"  -l : show file length (size)\n"
		"  -s : dumps sorted file tree\n"
		"  -z : zap (suppress) messages from listed routines\n"
		, getprogname());
	exit(EXIT_FAILURE);
}

static hset_t *zap;
static bool show_length = FALSE;

static void
zap_record(const char *value)
{
	strtok_t *s;
	const char *tok;

	zap = hset_create(HASH_KEY_STRING, 0);
	s = strtok_make_strip(value);

	while ((tok = strtok_next(s, ","))) {
		hset_insert(zap, h_strdup(tok));
	}

	strtok_free_null(&s);
}

static void
emitv(bool nl, const char *fmt, va_list args)
{
	str_t *s = str_new(512);

	str_vprintf(s, fmt, args);
	fputs(str_2c(s), stdout);
	if (nl)
		fputc('\n', stdout);
	fflush(stdout);

	str_destroy_null(&s);
}

static void G_PRINTF(1, 2)
emit(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

static void G_PRINTF(2, 3)
emit_zap(const char *caller, const char *fmt, ...)
{
	va_list args;

	if (zap != NULL && hset_contains(zap, caller))
		return;		/* Zap messages from this caller */

	va_start(args, fmt);
	emitv(TRUE, fmt, args);
	va_end(args);
}

#define emitz(fmt, ...) emit_zap(G_STRFUNC, (fmt), __VA_ARGS__)

struct flags {
	const char *name;
	uint32 value;
};

#define FLAG(x)		{ #x, x }

struct flags ftwflagv[] = {
	FLAG(FTW_O_CHDIR),
	FLAG(FTW_O_DEPTH),
	FLAG(FTW_O_ENTRY),
	FLAG(FTW_O_MOUNT),
	FLAG(FTW_O_PHYS),
	FLAG(FTW_O_ALL),
	FLAG(FTW_O_SILENT),
};

struct flags cbflagv[] = {
	FLAG(FTW_F_FILE),
	FLAG(FTW_F_DIR),
	FLAG(FTW_F_OTHER),
	FLAG(FTW_F_NOREAD),
	FLAG(FTW_F_NOSTAT),
	FLAG(FTW_F_DONE),
	FLAG(FTW_F_SYMLINK),
	FLAG(FTW_F_DANGLING),
};

#undef FLAG

static void
strflags(str_t *s, uint32 flags, struct flags *descv, size_t nv)
{
	size_t i;

	str_reset(s);

	for (i = 0; i < nv; i++) {
		if (flags & descv[i].value) {
			if (0 != str_len(s))
				STR_CAT(s, " | ");
			str_cat(s, descv[i].name);
		}
	}
}

static const char *
ftwflags(uint32 flags)
{
	static str_t *s;

	if (NULL == s)
		s = str_new(0);

	strflags(s, flags, ftwflagv, N_ITEMS(ftwflagv));
	return str_2c(s);
}

static const char *
cbflags(uint32 flags)
{
	static str_t *s;

	if (NULL == s)
		s = str_new(0);

	strflags(s, flags, cbflagv, N_ITEMS(cbflagv));
	return str_2c(s);
}

static ftw_status_t
printpath(const ftw_info_t *info, const filestat_t *sb, void *data)
{
	(void) data;

	emitz("%s(): level=%d, fbase = %s [%d]", G_STRFUNC, info->level,
		info->fbase, info->fbase_len);
	emitz("\tflags = %s", cbflags(info->flags));
	emitz("\tfpath = %s [%d]", info->fpath, info->fpath_len);
	emitz("\trpath = %s [%d]", info->rpath, info->rpath_len);
	if (show_length)
		emitz("\tsize  = %zu", (size_t) sb->st_size);

	return FTW_STATUS_OK;
}

static void
launch(const char *rootdir, uint32 flags, ftw_fn_t cb, void *data)
{
	ftw_status_t res;

	emit("%s(): starting traversal of \"%s\"", G_STRFUNC, rootdir);
	emitz("\tcalling %s(%s)",
		stacktrace_function_name(cb), NULL == data ? "NULL" : "data");
	emitz("\tflags %s", ftwflags(flags));

	res = ftw_foreach(rootdir, flags, 0, cb, data);

	emitz("%s(): traversal of \"%s\" done, result=%d", G_STRFUNC, rootdir, res);
}

enum filenode_magic { FILENODE_MAGIC = 0x75c1aadb };

typedef struct filenode {
	enum filenode_magic magic;
	ftw_info_t info;
	filestat_t sb;
	node_t node;
} filenode_t;

static inline void
filenode_check(const struct filenode * const fn)
{
	g_assert(fn != NULL);
	g_assert(FILENODE_MAGIC == fn->magic);
}

static int
filenode_cmp(const void *a, const void *b)
{
	const filenode_t *fa = a, *fb = b;

	filenode_check(fa);
	filenode_check(fb);

	return strcmp(fa->info.fbase, fb->info.fbase);
}

static filenode_t *
filenode_alloc(const ftw_info_t *info, const filestat_t *sb)
{
	filenode_t *fn;

	WALLOC0(fn);
	fn->magic = FILENODE_MAGIC;
	fn->info = *info;
	fn->sb = *sb;

	fn->info.fpath = h_strdup(info->fpath);
	fn->info.fbase = fn->info.fpath + info->base;
	fn->info.rpath = fn->info.fpath + info->root;

	return fn;
}

static void
filenode_free(void *data)
{
	filenode_t *fn = data;

	filenode_check(fn);

	hfree((void *) fn->info.fpath);
	fn->magic = 0;
	WFREE(fn);
}

static void
filenode_print(void *data, void *udata)
{
	filenode_t *fn = data;
	const ftw_info_t *info = &fn->info;
	const filestat_t *sb = &fn->sb;

	filenode_check(fn);

	printpath(info, sb, udata);
}

struct sorted_context {
	etree_t *tree;
	filenode_t *cur;
};

static ftw_status_t
sortpath(const ftw_info_t *info, const filestat_t *sb, void *data)
{
	struct sorted_context *ctx = data;

	if (0 == info->level) {
		if (0 == (FTW_F_DONE & info->flags)) {
			g_assert(NULL == ctx->cur);
			ctx->cur = filenode_alloc(info, sb);
			etree_set_root(ctx->tree, ctx->cur);
		}
	} else {
		if (FTW_F_DONE & info->flags) {
			ctx->cur = etree_parent(ctx->tree, ctx->cur);
			if (NULL != ctx->cur)
				filenode_check(ctx->cur);
		} else {
			filenode_t *fn = filenode_alloc(info, sb);
			filenode_check(ctx->cur);
			etree_prepend_child(ctx->tree, ctx->cur, fn);
			if (FTW_F_DIR == (info->flags & (FTW_F_DIR | FTW_F_NOREAD)))
				ctx->cur = fn;		/* Will only process readable directory */
		}
	}

	return FTW_STATUS_OK;
}

static void
sorted_tree(const char *rootdir, uint32 flags)
{
	struct sorted_context ctx;
	etree_t tree;

	ZERO(&ctx);
	ctx.tree = &tree;

	etree_init(&tree, FALSE, offsetof(filenode_t, node));
	launch(rootdir, flags, sortpath, &ctx);

	emitz("%s(): tree has %zu item%s",
		G_STRFUNC, etree_count(&tree), plural(etree_count(&tree)));

	etree_sort(&tree, filenode_cmp);
	etree_foreach(&tree, filenode_print, NULL);
	etree_free(&tree, filenode_free);
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	const char options[] = "hlsz:";
	bool sorted = FALSE;
	const char *rootdir;
	int c;
	const uint32 ftw_flags =
			FTW_O_PHYS | FTW_O_ALL | FTW_O_MOUNT | FTW_O_DEPTH | FTW_O_ENTRY;

	progstart(argc, argv);
	thread_set_main(TRUE);		/* We're the main thread, we can block */
	stacktrace_init(argv[0], FALSE);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'l':			/* show file length */
			show_length = TRUE;
			break;
		case 's':			/* sort the filesystem tree before dumping */
			sorted = TRUE;
			break;
		case 'z':			/* zap message from routines using emitz() */
			zap_record(optarg);
			break;
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 1)
		usage();

	argv += optind;
	rootdir = argv[0];

	if (sorted) {
		sorted_tree(rootdir, ftw_flags);
	} else {
		launch(rootdir, ftw_flags, printpath, NULL);
	}

	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
