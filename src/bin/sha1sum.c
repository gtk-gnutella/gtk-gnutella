/*
 * sha1sum -- computes the SHA1 of a single file.
 *
 * Copyright (c) 2013 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

#include "lib/base16.h"
#include "lib/file.h"
#include "lib/log.h"
#include "lib/misc.h"
#include "lib/path.h"
#include "lib/progname.h"
#include "lib/sha1.h"

#include "lib/override.h"

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-h] filename\n"
		"  -h : prints this help message\n"
		, getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int c;
	int fd;
	SHA1_context ctx;
	struct sha1 digest;
	bool done;
	/* getopt() variables: */
	extern int optind;

	progstart(argc, argv);

	while ((c = getopt(argc, argv, "h")) != EOF) {
		switch (c) {
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if ((argc -= optind) != 1)
		usage();

	argv += optind;

	fd = file_open(argv[0], O_RDONLY, 0);
	if (-1 == fd)
		exit(EXIT_FAILURE);

	SHA1_reset(&ctx);

	for (done = FALSE; !done; /* empty */) {
		static char buf[128 * 1024];
		int r;

		r = read(fd, ARYLEN(buf));

		if (-1 == r)
			s_fatal_exit(EXIT_FAILURE, "read() error: %m");

		done = r != sizeof buf;
		SHA1_input(&ctx, buf, r);
	}

	SHA1_result(&ctx, &digest);
	close(fd);

	printf("%s\n", sha1_base16(&digest));
	return 0;
}

/* vi: set ts=4 sw=4 cindent: */
