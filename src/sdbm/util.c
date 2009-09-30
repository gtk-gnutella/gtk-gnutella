#include "common.h"
#ifdef SDBM
#include "sdbm.h"
#else
#include "ndbm.h"
#endif

G_GNUC_PRINTF(1, 2) void
oops(char *fmt, ...)
{
	va_list args;
	extern char *progname;

	if (progname)
		fprintf(stderr, "%s: ", progname);

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
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
