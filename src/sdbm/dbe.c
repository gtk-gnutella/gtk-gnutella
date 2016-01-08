#include "common.h"
#include "sdbm.h"
#include "lib/base16.h"
#include "lib/progname.h"

extern G_GNUC_PRINTF(1, 2) void oops(char *fmt, ...);

/***************************************************************************\
**                                                                         **
**   Function name: getopt()                                               **
**   Author:        Henry Spencer, UofT                                    **
**   Coding date:   84/04/28                                               **
**                                                                         **
**   Description:                                                          **
**                                                                         **
**   Parses argv[] for arguments.                                          **
**   Works with Whitesmith's C compiler.                                   **
**                                                                         **
**   Inputs   - The number of arguments                                    **
**            - The base address of the array of arguments                 **
**            - A string listing the valid options (':' indicates an       **
**              argument to the preceding option is required, a ';'        **
**              indicates an argument to the preceding option is optional) **
**                                                                         **
**   Outputs  - Returns the next option character,                         **
**              '?' for non '-' arguments                                  **
**              or ':' when there is no more arguments.                    **
**                                                                         **
**   Side Effects + The argument to an option is pointed to by 'optarg'    **
**                                                                         **
*****************************************************************************
**                                                                         **
**   REVISION HISTORY:                                                     **
**                                                                         **
**     DATE           NAME                        DESCRIPTION              **
**   YY/MM/DD  ------------------   ------------------------------------   **
**   88/10/20  Janick Bergeron      Returns '?' on unamed arguments        **
**                                  returns '!' on unknown options         **
**                                  and 'EOF' only when exhausted.         **
**   88/11/18  Janick Bergeron      Return ':' when no more arguments      **
**   89/08/11  Janick Bergeron      Optional optarg when ';' in optstring  **
**                                                                         **
\***************************************************************************/

#ifndef HAS_INDEX
#ifndef index
#define index	strchr
#endif
#endif	/* HAS_INDEX */

static char *my_optarg;			/* Global argument pointer. */

static char
my_getopt(int argc, char **argv, char *optstring)
{
	register int c;
	register char *place;
	static int my_optind = 0;
	static char *scan = NULL;

	my_optarg = NULL;

	if (scan == NULL || *scan == '\0') {

		if (my_optind == 0)
			my_optind++;
		if (my_optind >= argc)
			return ':';

		my_optarg = place = argv[my_optind++];
		if (place[0] != '-' || place[1] == '\0')
			return '?';
		if (place[1] == '-' && place[2] == '\0')
			return '?';
		scan = place + 1;
	}

	c = *scan++;
	place = index(optstring, c);
	if (place == NULL || c == ':' || c == ';') {

		(void) fprintf(stderr, "%s: unknown option %c\n", argv[0], c);
		scan = NULL;
		return '!';
	}
	if (*++place == ':') {

		if (*scan != '\0') {

			my_optarg = scan;
			scan = NULL;

		}
		else {

			if (my_optind >= argc) {

				(void) fprintf(stderr, "%s: option %c requires an argument\n",
					       argv[0], c);
				return '!';
			}
			my_optarg = argv[my_optind];
			my_optind++;
		}
	}
	else if (*place == ';') {

		if (*scan != '\0') {

			my_optarg = scan;
			scan = NULL;

		}
		else {

			if (my_optind >= argc || *argv[my_optind] == '-')
				my_optarg = NULL;
			else {
				my_optarg = argv[my_optind];
				my_optind++;
			}
		}
	}
	return c;
}


void
print_datum(FILE *f, datum db, int hexa)
{
	size_t i;

	if (hexa > 0) {
		const char *hex = "0123456789abcdef";
		for (i = 0; i < db.dsize; i++) {
			unsigned v = (unsigned char) db.dptr[i];
			fputc(hex[v >> 4], f);
			fputc(hex[v & 0xf], f);
		}
	} else if (hexa < 0) {
		for (i = 0; i < db.dsize; i++) {
			fputc(db.dptr[i], f);
		}
	} else {
		fputc('"', f);
		for (i = 0; i < db.dsize; i++) {
			if (isprint((unsigned char)db.dptr[i]))
				fputc(db.dptr[i], f);
			else {
				fputc('\\', f);
				fputc('0' + ((db.dptr[i] >> 6) & 0x07), f);
				fputc('0' + ((db.dptr[i] >> 3) & 0x07), f);
				fputc('0' + (db.dptr[i] & 0x07), f);
			}
		}
		fputc('"', f);
	}
}


datum
read_datum(char *s, int hexa, const char *what)
{
	datum db;
	size_t len, dest;

	dest = len = strlen(s);
	if (hexa > 0)
		dest /= 2;
	db.dsize = 0;
	db.dptr = malloc(dest);
	if (!db.dptr)
	    oops("cannot get memory");

	if (hexa > 0) {
		size_t decoded;

		if (len != (len & ~0x1)) {
			fprintf(stderr, "Hexadecimal for %s not even\n", what);
			exit(-1);
		}

		decoded = base16_decode(db.dptr, dest, s, len);
		if ((size_t) -1 == decoded) {
			fprintf(stderr, "Invalid hexadecimal %s\n", what);
			exit(-1);
		}
		db.dsize = decoded;
		return db;
	} else if (hexa < 0) {
		memcpy(db.dptr, s, dest);
	} else {
		char *p;
		int i;

		for (p = db.dptr; *s != '\0'; p++, db.dsize++, s++) {
			if (*s == '\\') {
				if (*++s == 'n')
					*p = '\n';
				else if (*s == 'r')
					*p = '\r';
				else if (*s == 'f')
					*p = '\f';
				else if (*s == 't')
					*p = '\t';
				else if (isdigit((unsigned char)*s)
					 && isdigit((unsigned char)*(s + 1))
					 && isdigit((unsigned char)*(s + 2)))
				{
					i = (*s++ - '0') << 6;
					i |= (*s++ - '0') << 3;
					i |= *s - '0';
					*p = i;
				}
				else if (*s == '0')
					*p = '\0';
				else
					*p = *s;
			}
			else
				*p = *s;
		}
	}

	return db;
}


datum
fread_datum(FILE *f, int hexa, const char *what)
{
	filestat_t buf;
	datum db;
	size_t len, dest;

	if (-1 == fstat(fileno(f), &buf)) {
		fprintf(stderr, "Cannot get %s length: %s\n", what, g_strerror(errno));
		exit(-1);
	}

	dest = len = buf.st_size;
	if (hexa)
		dest /= 2;
	db.dsize = 0;
	db.dptr = malloc(dest);
	if (!db.dptr)
	    oops("cannot get memory");

	if (hexa <= 0) {
		db.dsize = fread(db.dptr, 1, len, f);
	} else {
		void *data = malloc(len);
		size_t decoded;
		if (!data)
			oops("cannot get memory");

		if (len != (len & ~0x1)) {
			fprintf(stderr, "Hexadecimal for %s not even\n", what);
			exit(-1);
		}

		len = fread(data, 1, len, f);
		decoded = base16_decode(db.dptr, dest, data, len & ~0x1);
		if ((size_t) -1 == decoded) {
			fprintf(stderr, "Invalid hexadecimal %s\n", what);
			exit(-1);
		}
		db.dsize = decoded;
		free(data);
	}

	return db;
}

char *
key2s(datum db)
{
	char *buf;
	char *p1, *p2;

	buf = (char *) malloc((db.dsize + 1) * sizeof(char));
	if (!buf)
	    oops("cannot get memory");
	for (p1 = buf, p2 = db.dptr; *p2 != '\0'; *p1++ = *p2++);
	*p1 = '\0';
	return buf;
}

static void
log_keyerr(datum key, int key_hexa, const char *what)
{
	int saved = errno;

	fprintf(stderr, "Error when %s ", what);
	print_datum(stderr, key, key_hexa);
	fprintf(stderr, ": %s\n", g_strerror(saved));
}

static void G_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s -a|-c|-d|-f|-F|-s database "
		"[-m r|w|rw] [-bikortxXy] [key [content]]\n", getprogname());
	fprintf(stderr,
		"  -a : list all entries (as \"key: value\") in the database.\n"
		"  -b : content given / output as binary.\n"
		"  -c : create the database if it does not exist.\n"
		"  -d : delete the entry associated with key.\n"
		"  -f : fetch and display the entry associated with key.\n"
		"  -F : fetch and display all the entries whose key "
				"matches regular expression.\n"
		"  -i : input comes from content, interpreted as a filename.\n"
		"  -k : list all keys in the database.\n"
		"  -m : specifies database opening mode: "
				"read-only, write-only, read-write.\n");
	fprintf(stderr,
		"  -o : output sent to content, interpreted as a filename.\n"
		"  -r : replace the entry at key if it already exists (see -s).\n"
		"  -s : store entry under key provided it does not already exist.\n"
		"  -t : re-initialize the database before executing the command.\n"
		"  -v : verbose mode: logs stores and deletions.\n"
		"  -x : keys interpreted / shown as hexadecimal.\n"
		"  -X : create database with O_EXCL to abort if it already exists.\n"
		"  -y : content interpreted / shown as hexadecimal.\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	typedef enum {
		CMD_HELP, CMD_FETCH, CMD_STORE, CMD_DELETE, CMD_SCAN, CMD_REGEXP
	} commands;
	char opt;
	int flags;
	int giveusage = 0;
	int verbose = 0;
	int key_hexa = 0;
	int content_hexa = 0;
	int content_is_file = 0;
	int key_only = 0;
	commands what = CMD_HELP;
	char *comarg[3];
	int st_flag = DBM_INSERT;
	int argn;
	DBM *db;
	datum key;
	datum content;
	regex_t re;
	char *mode = NULL;
	FILE *f = stdout;

	progstart(argc, argv);
	flags = O_RDWR;
	argn = 0;

	while ((opt = my_getopt(argc, argv, "abcdfFikm:orstvxXy")) != ':') {
		switch (opt) {
		case 'k':
			key_only = 1;
			break;
		case 'a':
			what = CMD_SCAN;
			break;
		case 'b':
			content_hexa = -1;
			break;
		case 'c':
			flags |= O_CREAT;
			break;
		case 'd':
			what = CMD_DELETE;
			break;
		case 'f':
			what = CMD_FETCH;
			break;
		case 'F':
			what = CMD_REGEXP;
			break;
		case 'i':
			mode = "rb";
			content_is_file = 1;
			break;
		case 'm':
			flags &= ~(000007);
			if (strcmp(my_optarg, "r") == 0)
				flags |= O_RDONLY;
			else if (strcmp(my_optarg, "w") == 0)
				flags |= O_WRONLY;
			else if (strcmp(my_optarg, "rw") == 0)
				flags |= O_RDWR;
			else {
				fprintf(stderr, "Invalid mode: \"%s\"\n", my_optarg);
				giveusage = 1;
			}
			break;
		case 'o':
			mode = "wb";
			content_is_file = 1;
			break;
		case 'r':
			st_flag = DBM_REPLACE;
			/* FALL THROUGH */
		case 's':
			what = CMD_STORE;
			break;
		case 't':
			flags |= O_TRUNC;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'x':
			key_hexa = 1;
			break;
		case 'X':
			flags |= O_EXCL;
			break;
		case 'y':
			content_hexa = 1;
			break;
		case '!':
			giveusage = 1;
			break;
		case '?':
			if (argn < 3)
				comarg[argn++] = my_optarg;
			else {
				fprintf(stderr, "Too many arguments.\n");
				giveusage = 1;
			}
			break;
		}
	}

	if (key_only && CMD_HELP == what)
		what = CMD_SCAN;

	if (giveusage || what == CMD_HELP || argn < 1)
		usage();

	if ((db = sdbm_open(comarg[0], flags, 0777)) == NULL) {
		fprintf(stderr, "Error opening database \"%s\": %s\n", comarg[0],
			g_strerror(errno));
		exit(-1);
	}

	if (argn > 1)
		key = read_datum(comarg[1], key_hexa, "key");

	if (argn > 2) {
		if (content_is_file) {
			f = fopen(comarg[2], mode);
			if (NULL == f) {
				fprintf(stderr, "Cannot open \"%s\" for %s: %s\n",
					comarg[2], 'r' == *mode ? "reading" : "writing",
					g_strerror(errno));
				exit(-1);
			}
			if ('r' == *mode) {
				content = fread_datum(f, content_hexa, "content");
				fclose(f);
				f = stdout;
			}
		} else {
			content = read_datum(comarg[2], content_hexa, "content");
		}
	} else if (content_is_file) {
		fprintf(stderr, "WARNING: ignoring spurious -%c option\n",
			'r' == *mode ? 'i' : 'o');
	}

	switch (what) {
	case CMD_HELP:
		g_assert_not_reached();		/* Already handled above */
	case CMD_SCAN:
		key = sdbm_firstkey(db);
		if (sdbm_error(db)) {
			fprintf(stderr, "Error when fetching first key: %s\n",
				g_strerror(errno));
			goto db_exit;
		}
		while (key.dptr != NULL) {
			content = sdbm_value(db);
			if (sdbm_error(db)) {
				log_keyerr(key, key_hexa, "fetching value");
				goto db_exit;
			}
			print_datum(f, key, key_hexa);
			if (!key_only) {
				fprintf(f, ": ");
				print_datum(f, content, content_hexa);
			}
			fprintf(f, "\n");
			if (sdbm_error(db)) {
				fprintf(stderr, "Error when fetching next key: %s\n",
					g_strerror(errno));
				goto db_exit;
			}
			key = sdbm_nextkey(db);
		}
		break;

	case CMD_REGEXP:
		if (argn < 2) {
			fprintf(stderr, "Missing regular expression.\n");
			goto db_exit;
		}
		if (regcomp(&re, comarg[1], REG_EXTENDED)) {
			fprintf(stderr, "Invalid regular expression\n");
			goto db_exit;
		}
		key = sdbm_firstkey(db);
		if (sdbm_error(db)) {
			fprintf(stderr, "Error when fetching first key: %s\n",
				g_strerror(errno));
			goto db_exit;
		}
		while (key.dptr != NULL) {
			char *str = key2s(key);
			if (0 == regexec(&re, str, 0, NULL, 0)) {
				content = sdbm_value(db);
				if (sdbm_error(db)) {
					fprintf(stderr, "Error when fetching ");
					print_datum(stderr, key, key_hexa);
					fprintf(stderr, ": %s\n", g_strerror(errno));
					goto db_exit;
				}
				print_datum(f, key, key_hexa);
				if (!key_only) {
					fprintf(f, ": ");
					print_datum(f, content, content_hexa);
				}
				fprintf(f, "\n");
				if (sdbm_error(db)) {
					fprintf(stderr, "Error when fetching next key\n");
					goto db_exit;
				}
			}
			free(str);
			key = sdbm_nextkey(db);
		}
		break;

	case CMD_FETCH:
		if (argn < 2) {
			fprintf(stderr, "Missing fetch key.\n");
			goto db_exit;
		}
		content = sdbm_fetch(db, key);
		if (sdbm_error(db)) {
			log_keyerr(key, key_hexa, "fetching");
			goto db_exit;
		}
		if (content.dptr == NULL) {
			fprintf(stderr, "Cannot find ");
			print_datum(stderr, key, key_hexa);
			fprintf(stderr, "\n");
			goto db_exit;
		}
		if (content_is_file) {
			print_datum(f, content, content_hexa);
		} else {
			print_datum(f, key, key_hexa);
			fprintf(f, ": ");
			print_datum(f, content, content_hexa);
			fprintf(f, "\n");
		}
		break;

	case CMD_DELETE:
		if (argn < 2) {
			fprintf(stderr, "Missing delete key.\n");
			goto db_exit;
		}
		if (sdbm_delete(db, key) || sdbm_error(db)) {
			log_keyerr(key, key_hexa, "deleting");
			goto db_exit;
		}
		if (verbose) {
			print_datum(f, key, key_hexa);
			fprintf(f, ": DELETED\n");
		}
		break;

	case CMD_STORE:
		if (argn < 3) {
			fprintf(stderr, "Missing key and/or content.\n");
			goto db_exit;
		}
		if (sdbm_store(db, key, content, st_flag) || sdbm_error(db)) {
			log_keyerr(key, key_hexa, "storing");
			goto db_exit;
		}
		if (verbose) {
			print_datum(f, key, key_hexa);
			fprintf(f,": ");
			print_datum(f, content, content_hexa);
			fprintf(f, " STORED\n");
		}
		break;
	}

db_exit:
	if (content_is_file)
		fclose(f);

	sdbm_clearerr(db);
	sdbm_close(db);
	if (sdbm_error(db)) {
		fprintf(stderr, "Error closing database \"%s\": %s\n", comarg[0],
			g_strerror(errno));
		exit(-1);
	}

	return 0;
}
