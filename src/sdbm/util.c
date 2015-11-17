#include "common.h"

#include "lib/progname.h"

G_GNUC_PRINTF(1, 2) void
oops(char *fmt, ...)
{
	va_list args;

	fprintf(stderr, "%s: ", getprogname());

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	if (errno != 0)
		fprintf(stderr, " (%s)", strerror(errno));
	fprintf(stderr, "\n");
	exit(1);
}

