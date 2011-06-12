/*
 * dba	dbm analysis/recovery
 */

#include "common.h"
#include "casts.h"

#include "lib/pow2.h"		/* For bits_set() */

#include "sdbm.h"

char *progname;
extern G_GNUC_PRINTF(1, 2) void oops(char *fmt, ...);
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

		free(name);
	}
	else
		oops("usage: %s dbname", progname);

	return 0;
}

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
pagestat(char *pag,
	unsigned *ksize, unsigned *vsize, int *large_keys, int *large_values)
{
	register unsigned n;
	register int pfree;
	register unsigned short *ino = (unsigned short *) pag;
	int lk = 0, lv = 0;
	int keysize = 0, valsize = 0;

	if (!(n = ino[0]))
		printf("no entries.\n");
	else {
		unsigned i;
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

		printf("%3d entries, %2d%% used, keys %3d, values %3d, free %3d%s",
			n / 2, ((DBM_PBLKSIZ - pfree) * 100) / DBM_PBLKSIZ,
			keysize, valsize, pfree,
			(DBM_PBLKSIZ - pfree) / (n/2) * (1+n/2) > DBM_PBLKSIZ ?
				" (LOW)" : "");

		if (lk != 0)
			printf(" (LKEY %d)", lk);
		if (lv != 0)
			printf(" (LVAL %d)", lv);

		putc('\n', stdout);
	}
	if (large_keys)		*large_keys = lk;
	if (large_values)	*large_values = lv;
	if (ksize)			*ksize = keysize;
	if (vsize)			*vsize = valsize;
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
	unsigned ksize = 0, vsize = 0;
	char pag[DBM_PBLKSIZ];

	while ((b = read(pagf, pag, DBM_PBLKSIZ)) > 0) {
		int lk, lv;
		unsigned ks, vs;
		printf("#%d: ", n);
		if (!sdbm_internal_chkpage(pag))
			printf("bad\n");
		else {
			printf("ok. ");
			if (!(e = pagestat(pag, &ks, &vs, &lk, &lv))) {
			    o++;
			} else {
			    t += e;
				tlk += lk;
				tlv += lv;
				ksize += ks;
				vsize += vs;
			}
		}
		n++;
	}

	if (b == 0) {
		printf("%d pages (%d holes):  %d entries\n", n, o, t);
		printf("keys: %u bytes, values: %u bytes\n", ksize, vsize);
		if (tlk || tlv)
			printf("%d large key%s, %d large value%s\n",
				tlk, 1 == tlk ? "" : "s",
				tlv, 1 == tlv ? "" : "s");
	} else
		oops("read failed: block %d", n);
}

void
bdump(int datf)
{
	int i;
	unsigned char dat[DBM_BBLKSIZ];
	filestat_t buf;
	unsigned long b;
	unsigned long used = 0;
	unsigned long total;

	if (-1 == fstat(datf, &buf))
		return;

	for (b = 0; b < UNSIGNED(buf.st_size); b += DBM_BBLKSIZ * DBM_BBLKSIZ * 8) {
		if ((fileoffset_t) -1 == lseek(datf, b, SEEK_SET))
			oops("seek failed: offset %lu", b);
		if (-1 == read(datf, dat, sizeof dat))
			oops("read failed: offset %lu", b);
		for (i = 0; i < DBM_BBLKSIZ; i++)
			used += bits_set(dat[i]);
	}

	total = buf.st_size / DBM_BBLKSIZ;
	if (buf.st_size % DBM_BBLKSIZ)
		total++;

	printf("%lu blocks used / %lu total (%.2f%% used)\n",
		used, total, used * 100.0 / (total ? total : 1));
}

