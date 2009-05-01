/*
 * dba	dbm analysis/recovery
 */

#include <stdio.h>
#include <sys/file.h>
#include "common.h"
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

	if (p = argv[1]) {
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

void
sdump(int pagf)
{
	register b;
	register n = 0;
	register t = 0;
	register o = 0;
	register e;
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

int
pagestat(char *pag)
{
	register n;
	register free;
	register short *ino = (short *) pag;

	if (!(n = ino[0]))
		printf("no entries.\n");
	else {
		int i;
		int keysize = 0, valsize = 0;
		int off = DBM_PBLKSIZ;

		for (i = 1; i < n; i+= 2) {
			keysize += off - ino[i];
			valsize += ino[i] - ino[i+1];
			off = ino[i+1];
		}

		free = ino[n] - (n + 1) * sizeof(short);

		printf("%3d entries, %2d%% used, keys %3d, values %3d, free %3d%s\n",
		       n / 2, ((DBM_PBLKSIZ - free) * 100) / DBM_PBLKSIZ,
			   keysize, valsize, free,
			   (DBM_PBLKSIZ - free) / (n/2) * (1+n/2) > DBM_PBLKSIZ ?
					" (LOW)" : "");
	}
	return n / 2;
}
