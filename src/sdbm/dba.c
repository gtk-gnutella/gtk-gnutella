/*
 * dba	dbm analysis/recovery
 */

#include "common.h"
#include "casts.h"

#include "sdbm.h"

char *progname;
extern void oops();
void sdump(int);

int
main(int argc, char **argv)
{
	int n;
	char *p;
	char *name;
	int pagf;

	progname = argv[0];
	(void) argc;

	if ((p = argv[1])) {
		name = (char *) malloc((n = strlen(p)) + 5);
		if (!name)
		    oops("cannot get memory");

		strcpy(name, p);
		strcpy(name + n, DBM_PAGFEXT);

		if ((pagf = open(name, O_RDONLY)) < 0)
			oops("cannot open %s.", name);

		sdump(pagf);
	}
	else
		oops("usage: %s dbname", progname);

	return 0;
}

extern int okpage(char *pag);

static inline unsigned short
offset(unsigned short off)
{
	return off & 0x7fff;
}

static inline gboolean
is_big(unsigned short off)
{
	return booleanize(off & 0x8000);
}

int
pagestat(char *pag)
{
	register unsigned n;
	register int pfree;
	register unsigned short *ino = (unsigned short *) pag;

	if (!(n = ino[0]))
		printf("no entries.\n");
	else {
		unsigned i;
		int keysize = 0, valsize = 0;
		unsigned off = DBM_PBLKSIZ;
		gboolean has_big_value = FALSE;
		gboolean has_big_key = FALSE;

		for (i = 1; i < n; i+= 2) {
			unsigned short koff = offset(ino[i]);
			unsigned short voff = offset(ino[i+1]);
			keysize += off - koff;
			valsize += koff - voff;
			off = voff;

			if (is_big(ino[i]))
				has_big_key = TRUE;
			if (is_big(ino[i+1]))
				has_big_value = TRUE;
		}

		pfree = offset(ino[n]) - (n + 1) * sizeof(short);

		printf(
			"%3d entries, %2d%% used, keys %3d, values %3d, free %3d%s%s%s\n",
		       n / 2, ((DBM_PBLKSIZ - pfree) * 100) / DBM_PBLKSIZ,
			   keysize, valsize, pfree,
			   (DBM_PBLKSIZ - pfree) / (n/2) * (1+n/2) > DBM_PBLKSIZ ?
					" (LOW)" : "",
				has_big_key ? " (LKEY)" : "",
				has_big_value ? " (LVAL)" : "");
	}
	return n / 2;
}

void
sdump(int pagf)
{
	int b;
	int n = 0;
	int t = 0;
	int o = 0;
	int e;
	char pag[DBM_PBLKSIZ];

	while ((b = read(pagf, pag, DBM_PBLKSIZ)) > 0) {
		printf("#%d: ", n);
		if (!okpage(pag))
			printf("bad\n");
		else {
			printf("ok. ");
			if (!(e = pagestat(pag)))
			    o++;
			else
			    t += e;
		}
		n++;
	}

	if (b == 0)
		printf("%d pages (%d holes):  %d entries\n", n, o, t);
	else
		oops("read failed: block %d", n);
}

