#include "common.h"
#include "sdbm.h"

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

static char *my_optarg;			/* Global argument pointer. */

#ifdef VMS
#define index  strchr
#endif

static char
my_getopt(int argc, char **argv, char *optstring)
{
	register int c;
	register char *place;
	extern char *index();
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
print_datum(datum db)
{
	size_t i;

	putchar('"');
	for (i = 0; i < db.dsize; i++) {
		if (isprint((unsigned char)db.dptr[i]))
			putchar(db.dptr[i]);
		else {
			putchar('\\');
			putchar('0' + ((db.dptr[i] >> 6) & 0x07));
			putchar('0' + ((db.dptr[i] >> 3) & 0x07));
			putchar('0' + (db.dptr[i] & 0x07));
		}
	}
	putchar('"');
}


datum
read_datum(char *s)
{
	datum db;
	char *p;
	int i;

	db.dsize = 0;
	db.dptr = (char *) malloc(strlen(s) * sizeof(char));
	if (!db.dptr)
	    oops("cannot get memory");

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

char *progname;

static void G_GNUC_NORETURN
usage(void)
{
	fprintf(stderr,
		"Usage: %s database "
		"[-m r|w|rw] [-crtX] -a|-d|-f|-F|-s [key [content]]\n", progname);
	fprintf(stderr,
		"  -a : list all entries in the database.\n"
		"  -c : create the database if it does not exist.\n"
		"  -d : delete the entry associated with key.\n"
		"  -f : fetch and display the entry associated with key.\n"
		"  -F : fetch and display all the entries whose key "
				"matches regular expression.\n"
		"  -m : specifies database opening mode: "
				"read-only, write-only, read-write.\n");
	fprintf(stderr,
		"  -r : replace the entry at key if it already exists (see -s).\n"
		"  -s : store entry under key provided it does not already exist.\n"
		"  -t : re-initialize the database before executing the command.\n"
		"  -v : verbose mode: logs stores and deletions.\n"
		"  -X : create database with O_EXCL to abort if it already exists.\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	typedef enum {
		HELP, FETCH, STORE, DELETE, SCAN, REGEXP
	} commands;
	char opt;
	int flags;
	int giveusage = 0;
	int verbose = 0;
	commands what = HELP;
	char *comarg[3];
	int st_flag = DBM_INSERT;
	int argn;
	DBM *db;
	datum key;
	datum content;
	regex_t re;

	progname = argv[0];
	flags = O_RDWR;
	argn = 0;

	while ((opt = my_getopt(argc, argv, "acdfFm:rstvX")) != ':') {
		switch (opt) {
		case 'a':
			what = SCAN;
			break;
		case 'c':
			flags |= O_CREAT;
			break;
		case 'd':
			what = DELETE;
			break;
		case 'f':
			what = FETCH;
			break;
		case 'F':
			what = REGEXP;
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
		case 'r':
			st_flag = DBM_REPLACE;
			break;
		case 's':
			what = STORE;
			break;
		case 't':
			flags |= O_TRUNC;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'X':
			flags |= O_EXCL;
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

	if (giveusage || what == HELP || argn < 1) {
		usage();
	}

	if ((db = sdbm_open(comarg[0], flags, 0777)) == NULL) {
		fprintf(stderr, "Error opening database \"%s\"\n", comarg[0]);
		exit(-1);
	}

	if (argn > 1)
		key = read_datum(comarg[1]);
	if (argn > 2)
		content = read_datum(comarg[2]);

	switch (what) {
	case HELP:
		g_assert_not_reached();		/* Already handled above */
	case SCAN:
		key = sdbm_firstkey(db);
		if (sdbm_error(db)) {
			fprintf(stderr, "Error when fetching first key\n");
			goto db_exit;
		}
		while (key.dptr != NULL) {
			content = sdbm_fetch(db, key);
			if (sdbm_error(db)) {
				fprintf(stderr, "Error when fetching ");
				print_datum(key);
				printf("\n");
				goto db_exit;
			}
			print_datum(key);
			printf(": ");
			print_datum(content);
			printf("\n");
			if (sdbm_error(db)) {
				fprintf(stderr, "Error when fetching next key\n");
				goto db_exit;
			}
			key = sdbm_nextkey(db);
		}
		break;

	case REGEXP:
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
			fprintf(stderr, "Error when fetching first key\n");
			goto db_exit;
		}
		while (key.dptr != NULL) {
			char *str = key2s(key);
			if (regexec(&re, str, 0, NULL, 0)) {
				content = sdbm_fetch(db, key);
				if (sdbm_error(db)) {
					fprintf(stderr, "Error when fetching ");
					print_datum(key);
					printf("\n");
					goto db_exit;
				}
				print_datum(key);
				printf(": ");
				print_datum(content);
				printf("\n");
				if (sdbm_error(db)) {
					fprintf(stderr, "Error when fetching next key\n");
					goto db_exit;
				}
			}
			free(str);
			key = sdbm_nextkey(db);
		}
		break;

	case FETCH:
		if (argn < 2) {
			fprintf(stderr, "Missing fetch key.\n");
			goto db_exit;
		}
		content = sdbm_fetch(db, key);
		if (sdbm_error(db)) {
			fprintf(stderr, "Error when fetching ");
			print_datum(key);
			printf("\n");
			goto db_exit;
		}
		if (content.dptr == NULL) {
			fprintf(stderr, "Cannot find ");
			print_datum(key);
			printf("\n");
			goto db_exit;
		}
		print_datum(key);
		printf(": ");
		print_datum(content);
		printf("\n");
		break;

	case DELETE:
		if (argn < 2) {
			fprintf(stderr, "Missing delete key.\n");
			goto db_exit;
		}
		if (sdbm_delete(db, key) || sdbm_error(db)) {
			fprintf(stderr, "Error when deleting ");
			print_datum(key);
			printf("\n");
			goto db_exit;
		}
		if (verbose) {
			print_datum(key);
			printf(": DELETED\n");
		}
		break;

	case STORE:
		if (argn < 3) {
			fprintf(stderr, "Missing key and/or content.\n");
			goto db_exit;
		}
		if (sdbm_store(db, key, content, st_flag) || sdbm_error(db)) {
			fprintf(stderr, "Error when storing ");
			print_datum(key);
			printf("\n");
			goto db_exit;
		}
		if (verbose) {
			print_datum(key);
			printf(": ");
			print_datum(content);
			printf(" STORED\n");
		}
		break;
	}

db_exit:
	sdbm_clearerr(db);
	sdbm_close(db);
	if (sdbm_error(db)) {
		fprintf(stderr, "Error closing database \"%s\"\n", comarg[0]);
		exit(-1);
	}

	return 0;
}
