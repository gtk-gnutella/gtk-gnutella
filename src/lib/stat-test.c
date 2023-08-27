/*
 * stat-test -- tests the stat() and fstat() functions on Windows.
 *
 * Copyright (c) 2018 Raphael Manfredi <Raphael_Manfredi@pobox.com>
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

#include "fd.h"
#include "log.h"
#include "progname.h"
#include "str.h"
#include "stringify.h"
#include "timestamp.h"

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
			"Usage: %s [-h] path1 [path2 ... pathn]\n"
			"  -h : prints this help message\n"
			, getprogname());
	exit(EXIT_FAILURE);
}

static const char *
stat_mode_str(const mode_t m)
{
	str_t *s = str_private(G_STRFUNC, 20);

	str_reset(s);

	if (S_ISREG(m))
		str_putc(s, '-');
	else if (S_ISDIR(m))
		str_putc(s, 'd');
	else if (S_ISCHR(m))
		str_putc(s, 'c');
	else if (S_ISFIFO(m))
		str_putc(s, 'p');
	else if (S_ISLNK(m))	/* Not using lstat(), cannot happen! */
		str_putc(s, 'l');
	else
		str_putc(s, '?');	/* Remember, this is for Windows... */

#define MATCH(m,b)	((b) == ((m) & (b)))

	str_putc(s, (m & S_IRUSR) ? 'r' : '-');
	str_putc(s, (m & S_IWUSR) ? 'w' : '-');
	str_putc(s,
		MATCH(m, S_IXUSR | S_ISUID) ? 's' :
		(m & S_ISUID) ? ('S') :
		(m & S_IXUSR) ? ('x') :
		'-');
	str_putc(s, (m & S_IRGRP) ? 'r' : '-');
	str_putc(s, (m & S_IWGRP) ? 'w' : '-');
	str_putc(s,
		MATCH(m, S_IXGRP | S_ISGID) ? 's' :
		(m & S_ISGID) ? ('S') :
		(m & S_IXGRP) ? ('x') :
		'-');
	str_putc(s, (m & S_IROTH) ? 'r' : '-');
	str_putc(s, (m & S_IWOTH) ? 'w' : '-');
	str_putc(s,
		MATCH(m, S_IXOTH | S_ISVTX) ? 't' :
		(m & S_ISVTX) ? ('T') :
		(m & S_IXOTH) ? ('x') :
		'-');

#undef MATCH

	return str_2c(s);
}

static void
stat_dump(const filestat_t *buf, bool full)
{
	s_info("\tst_dev     = %lu", (ulong) buf->st_dev);
	s_info("\tst_ino     = %s",  uint64_to_string(buf->st_ino));
	s_info("\tst_mode    = %s (0x%x)", stat_mode_str(buf->st_mode), buf->st_mode);
	s_info("\tst_size    = %s", uint64_to_string(buf->st_size));
	s_info("\tst_mtime   = %lu (%s)",
		buf->st_mtime, timestamp_to_string(buf->st_mtime));

	if (!full)
		return;

	s_info("\tst_nlink   = %u",  (uint) buf->st_nlink);
	s_info("\tst_uid     = %lu", (ulong) buf->st_uid);
	s_info("\tst_gid     = %lu", (ulong) buf->st_gid);
	s_info("\tst_rdev    = %lu", (ulong) buf->st_rdev);
	s_info("\tst_blksize = %lu", (ulong) buf->st_blksize);
	s_info("\tst_blocks  = %s",  uint64_to_string(buf->st_blocks));
	s_info("\tst_atime   = %lu (%s)",
		buf->st_atime, timestamp_to_string(buf->st_atime));
	s_info("\tst_ctime   = %lu (%s)",
		buf->st_ctime, timestamp_to_string(buf->st_ctime));
}

static bool
stat_test(const char *path)
{
	filestat_t buf, buf2;
	int fd = -1;
	bool ok = TRUE;

	s_info("testing \"%s\"", path);

	if (-1 == stat(path, &buf))
		s_critical("stat() failed for \"%s\": %m", path);
	else {
		s_info("stat() results:");
		stat_dump(&buf, TRUE);

		if (S_ISDIR(buf.st_mode)) {
			s_warning("skipping fstat() check on a directory");
			goto skip_fstat;
		}
	}

	fd = open(path, O_RDONLY, 0);
	if (-1 == fd)
		s_critical("open() failed for \"%s\": %m", path);
	else {
		if (-1 == fstat(fd, &buf2))
			s_critical("fstat() failed for \"%s\" on fd #%d : %m", path, fd);
		else {
			if (buf2.st_dev != buf.st_dev) {
				s_warning("st_dev is different with stat() and fstat()!");
				ok = FALSE;
			}
			if (buf2.st_ino != buf.st_ino) {
				s_warning("st_ino is different with stat() and fstat()!");
				ok = FALSE;
			}
			if (buf2.st_mtime != buf.st_mtime) {
				s_warning("st_mtime is different with stat() and fstat()!");
				ok = FALSE;
			}
			if (buf2.st_size != buf.st_size) {
				s_warning("st_size is different with stat() and fstat()!");
				ok = FALSE;
			}
			if (buf2.st_mode != buf.st_mode) {
				s_warning("st_mode diffrent: stat() and fstat()!");
				ok = FALSE;
			}
			if (buf2.st_nlink != buf.st_nlink) {
				s_warning("st_nlink diffrent: stat() and fstat()");
				ok = FALSE;
			}
			if (!ok) {
				s_info("fstat() results:");
				stat_dump(&buf2, TRUE);
			}
		}
	}

skip_fstat:

	if (-1 == stat(path, &buf2))
		s_critical("second stat() failed for \"%s\": %m", path);
	else {
		bool sok = TRUE;

		if (buf2.st_dev != buf.st_dev) {
			s_warning("st_dev is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_ino != buf.st_ino) {
			s_warning("st_ino is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_mtime != buf.st_mtime) {
			s_warning("st_mtime is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_size != buf.st_size) {
			s_warning("st_size is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_mode != buf.st_mode) {
			s_warning("st_mode is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_nlink != buf.st_nlink) {
			s_warning("st_nlink is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (!sok) {
			ok = FALSE;
			s_info("second stat() results:");
			stat_dump(&buf2, TRUE);
		}
	}

	fd_close(&fd);

	/* Ensure stat() is consistent, even after fd was closed! */

	if (-1 == stat(path, &buf2))
		s_critical("final stat() failed for \"%s\": %m", path);
	else {
		bool sok = TRUE;

		if (buf2.st_dev != buf.st_dev) {
			s_warning("st_dev is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_ino != buf.st_ino) {
			s_warning("st_ino is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_mtime != buf.st_mtime) {
			s_warning("st_mtime is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_size != buf.st_size) {
			s_warning("st_size is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_mode != buf.st_mode) {
			s_warning("st_mode is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (buf2.st_nlink != buf.st_nlink) {
			s_warning("st_nlink is different between 2 stat() calls!");
			sok = FALSE;
		}
		if (!sok) {
			ok = FALSE;
			s_info("final stat() results:");
			stat_dump(&buf2, TRUE);
		}
	}

	return ok;
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int c, i;
	int retval = 0;
	const char options[] = "h";

	progstart(argc, argv);

	while ((c = getopt(argc, argv, options)) != EOF) {
		switch (c) {
		case 'h':			/* show help */
		default:
			usage();
			break;
		}
	}

	if (0 == (argc -= optind))
		usage();

	for (i = 0; i < argc; i++) {
		if (!stat_test(argv[i+1]))
			retval = 1;
	}

	if (0 == retval)
		printf("All OK!\n");

	return retval;
}

/* vi: set ts=4 sw=4 cindent: */
