#include <stdio.h>
#include <errno.h>
#include "common.h"
#ifdef SDBM
#include "sdbm.h"
#else
#include "ndbm.h"
#endif

void
oops(register char *s1, register char *s2)
{
	extern char *progname;

	if (progname)
		fprintf(stderr, "%s: ", progname);
	fprintf(stderr, s1, s2);
	fprintf(stderr, " (%s)", strerror(errno));
	fprintf(stderr, "\n");
	exit(1);
}

int
okpage(char *pag)
{
	register unsigned n;
	register unsigned off;
	register unsigned short *ino = (unsigned short *) pag;
	int ino_end;

	if ((n = ino[0]) > DBM_PBLKSIZ / sizeof(unsigned short))
		return 0;

	if (!n)
		return 1;

	if (n & 0x1)
		return 0;

	ino_end = (n + 1) * sizeof(short);

	off = DBM_PBLKSIZ;
	for (ino++; n; ino += 2) {
		unsigned short koff = ino[0] & 0x7fff;
		unsigned short voff = ino[1] & 0x7fff;
		if (koff > off || voff > off || voff > koff)
			return 0;
		if (koff < ino_end || voff < ino_end)
			return 0;
		off = voff;
		n -= 2;
	}

	return 1;
}
