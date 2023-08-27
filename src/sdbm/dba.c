/*
 * dba	dbm analysis/recovery
 */

#include "common.h"
#include "casts.h"

#include "lib/progname.h"
#include "lib/pow2.h"		/* For bits_set() */
#include "lib/stringify.h"	/* For plural() */

#include "sdbm.h"

extern void oops(char *fmt, ...) G_PRINTF(1, 2);
void sdump(int, long);
void bdump(int);

static bool summary_only;
static bool filled_only;
static bool on_tty;

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s [-fs] dbname\n"
		"  -f : only print filled pages, skip empty ones\n"
		"  -s : display summary info only\n"
		, getprogname()
	);
	exit(EXIT_FAILURE);
}

static void
show_progress(long n, long count)
{
	if (on_tty) {
		static int c = 0;

		printf("%c (%02ld%%)\r", "-\\|/"[c++ % 4], n * 100 / count);
		fflush(stdout);
	}
}

int
main(int argc, char **argv)
{
	extern int optind;
	char *p;
	int c;

	progstart(argc, argv);

	on_tty = isatty(STDOUT_FILENO);

	while ((c = getopt(argc, argv, "fs")) != EOF) {
		switch (c) {
		case 'f':			/* show filled pages only */
			filled_only++;
			break;
		case 's':			/* summary info only */
			summary_only++;
			break;
		default:
			usage();
			break;
		}
	}

	if ((p = argv[optind])) {
		int pagf;
		int datf;
		char *name;
		int n;
		long npag;
		filestat_t buf;

		name = (char *) malloc((n = strlen(p)) + sizeof(DBM_PAGFEXT));
		if (!name)
		    oops("cannot get memory");

		strcpy(name, p);
		strcpy(name + n, DBM_PAGFEXT);

		if ((pagf = open(name, O_RDONLY)) < 0)
			oops("cannot open %s.", name);

		if (-1 == fstat(pagf, &buf))
			oops("cannot fstat opened %s", name);

		npag = buf.st_size / DBM_PBLKSIZ;
		sdump(pagf, npag);
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
		usage();

	return 0;
}

static inline unsigned short
offset(unsigned short off)
{
	return off & 0x7fff;
}

static inline bool
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

	if (!(n = ino[0])) {
		if (!summary_only && !filled_only)
			printf("no entries.\n");
	} else {
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

		if (!summary_only) {
			printf("%3d entr%-3s, %2d%% used, keys %3d, values %3d, free %3d%s",
				PLURAL_Y(n / 2),
				((DBM_PBLKSIZ - pfree) * 100) / DBM_PBLKSIZ,
				keysize, valsize, pfree,
				(DBM_PBLKSIZ - pfree) / (n/2) * (1+n/2) > DBM_PBLKSIZ ?
					" (LOW)" : "");

			if (lk != 0) printf(" (LKEY %d)", lk);
			if (lv != 0) printf(" (LVAL %d)", lv);
			putc('\n', stdout);
		}
	}
	if (large_keys)		*large_keys = lk;
	if (large_values)	*large_values = lv;
	if (ksize)			*ksize = keysize;
	if (vsize)			*vsize = valsize;
	return n / 2;
}

static inline bool
page_is_empty(const char *pag)
{
	register unsigned short *ino = (unsigned short *) pag;
	return 0 == ino[0];
}

void
sdump(int pagf, long npag)
{
	int b;
	int n = 0;
	int t = 0;
	int o = 0;
	int tlk = 0;
	int tlv = 0;
	int e;
	int bad = 0;
	unsigned ksize = 0, vsize = 0;
	char pag[DBM_PBLKSIZ];

	while ((b = read(pagf, pag, DBM_PBLKSIZ)) > 0) {
		int lk, lv;
		unsigned ks, vs;
		bool is_bad = !sdbm_chkpage(pag);
		bool is_empty = page_is_empty(pag);

		if (summary_only && 0 == n % 1000) show_progress(n, npag);
		if (
			!summary_only &&
			(is_bad || !filled_only || (filled_only && !is_empty))
		)
			printf("#%d: ", n);
		if (is_bad) {
			/* Bad pages are displayed when -f is given */
			bad++;
			if (!summary_only) printf("bad\n");
		} else {
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
		printf("%d page%s (%d hole%s):  %d entr%s\n",
			PLURAL(n), PLURAL(o), PLURAL(t));
		if (bad != 0) printf("%d bad page%s\n", PLURAL(bad));
		printf("keys: %u byte%s, values: %u byte%s\n",
			PLURAL(ksize), PLURAL(vsize));
		if (tlk || tlv)
			printf("%d large key%s, %d large value%s\n",
				PLURAL(tlk), PLURAL(tlv));
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
		if (-1 == read(datf, ARYLEN(dat)))
			oops("read failed: offset %lu", b);
		for (i = 0; i < DBM_BBLKSIZ; i++)
			used += bits_set(dat[i]);
	}

	total = buf.st_size / DBM_BBLKSIZ;
	if (buf.st_size % DBM_BBLKSIZ)
		total++;

	printf("%lu block%s used / %lu total (%.2f%% used)\n",
		PLURAL(used), total, used * 100.0 / (total ? total : 1));
}

/* vi: set ts=4 sw=4 cindent: */
