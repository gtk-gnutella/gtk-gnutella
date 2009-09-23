/*
 * dba	dbm analysis/recovery
 */

#include "common.h"
#include "casts.h"

#include "sdbm.h"

char *progname;
extern void oops();
void sdump(int);
void bdump(int);

int
main(int argc, char **argv)
{
	char *p;

	progname = argv[0];
	(void) argc;

	if ((p = argv[1])) {
		int pagf;
		int datf;
		char *name;
		int n;

		name = (char *) malloc((n = strlen(p)) + sizeof(DBM_PAGFEXT));
		if (!name)
		    oops("cannot get memory");

		strcpy(name, p);
		strcpy(name + n, DBM_PAGFEXT);

		if ((pagf = open(name, O_RDONLY)) < 0)
			oops("cannot open %s.", name);

		sdump(pagf);
		free(name);

		name = (char *) malloc(n + sizeof(DBM_DATFEXT));
		if (!name)
		    oops("cannot get memory");

		strcpy(name, p);
		strcpy(name + n, DBM_DATFEXT);

		if ((datf = open(name, O_RDONLY)) >= 0)
			bdump(datf);
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
pagestat(char *pag, int *large_keys, int *large_values)
{
	register unsigned n;
	register int pfree;
	register unsigned short *ino = (unsigned short *) pag;
	int lk = 0, lv = 0;

	if (!(n = ino[0]))
		printf("no entries.\n");
	else {
		unsigned i;
		int keysize = 0, valsize = 0;
		unsigned off = DBM_PBLKSIZ;

		for (i = 1; i < n; i+= 2) {
			unsigned short koff = offset(ino[i]);
			unsigned short voff = offset(ino[i+1]);
			keysize += off - koff;
			valsize += koff - voff;
			off = voff;

			if (is_big(ino[i]))		lk++;
			if (is_big(ino[i+1]))	lv++;
		}

		pfree = offset(ino[n]) - (n + 1) * sizeof(short);

		printf(
			"%3d entries, %2d%% used, keys %3d, values %3d, free %3d%s%s%s\n",
		       n / 2, ((DBM_PBLKSIZ - pfree) * 100) / DBM_PBLKSIZ,
			   keysize, valsize, pfree,
			   (DBM_PBLKSIZ - pfree) / (n/2) * (1+n/2) > DBM_PBLKSIZ ?
					" (LOW)" : "",
				lk ? " (LKEY)" : "",
				lv ? " (LVAL)" : "");
	}
	if (large_keys)
		*large_keys = lk;
	if (large_values)
		*large_values = lv;
	return n / 2;
}

void
sdump(int pagf)
{
	int b;
	int n = 0;
	int t = 0;
	int o = 0;
	int tlk = 0;
	int tlv = 0;
	int e;
	char pag[DBM_PBLKSIZ];

	while ((b = read(pagf, pag, DBM_PBLKSIZ)) > 0) {
		int lk, lv;
		printf("#%d: ", n);
		if (!okpage(pag))
			printf("bad\n");
		else {
			printf("ok. ");
			if (!(e = pagestat(pag, &lk, &lv))) {
			    o++;
			} else {
			    t += e;
				tlk += lk;
				tlv += lv;
			}
		}
		n++;
	}

	if (b == 0) {
		printf("%d pages (%d holes):  %d entries\n", n, o, t);
		if (tlk || tlv)
			printf("%d large key%s, %d large value%s\n",
				tlk, 1 == tlk ? "" : "s",
				tlv, 1 == tlv ? "" : "s");
	} else
		oops("read failed: block %d", n);
}

int
bits_set(int v)
{
	int count = 0;

	while (v != 0) {
		if (v & 0x1)
			count++;
		v >>= 1;
	}

	return count;
}

void
bdump(int datf)
{
	int i;
	unsigned char dat[DBM_BBLKSIZ];
	int set[256];
	struct stat buf;
	unsigned long b;
	unsigned long used = 0;
	unsigned long total;

	for (i = 0; i < 256; i++)
		set[i] = bits_set(i);

	if (-1 == fstat(datf, &buf))
		return;

	for (b = 0; b < buf.st_size; b += DBM_BBLKSIZ * DBM_BBLKSIZ * 8) {
		if ((off_t) -1 == lseek(datf, b, SEEK_SET))
			oops("seek failed: offset %lu", b);
		if (-1 == read(datf, dat, sizeof dat))
			oops("read failed: offset %lu", b);
		for (i = 0; i < DBM_BBLKSIZ; i++)
			used += set[dat[i]];
	}

	total = buf.st_size / DBM_BBLKSIZ;
	if (buf.st_size % DBM_BBLKSIZ)
		total++;

	printf("%lu blocks used / %lu total (%.2f%% used)\n",
		used, total, used * 100.0 / total);
}

