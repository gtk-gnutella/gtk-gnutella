#include <sys/types.h>
#include <sys/stat.h>

#include "gnutella.h"
#include "matching.h"
#include "downloads.h"

#define MAX_STRINGS 1024
#define LINELEN 256

static time_t auto_last_mtime = 0;
static GSList *auto_strings = NULL;

int use_autodownload = 0;
gchar *auto_download_file = "auto-downloads.txt";

void autodownload_init()
{
	cpattern_t *pattern;
	char buf[LINELEN];
	FILE *f;
	int i;
	struct stat sbuf;

	if (!use_autodownload)
		return;

	/*
	 * Check whether file has changed since last initialization.
	 */

	if (-1 == stat(auto_download_file, &sbuf))
		return;

	if (auto_last_mtime && auto_last_mtime >= sbuf.st_mtime)
		return;
	auto_last_mtime = sbuf.st_mtime;

	while(auto_strings != NULL) {
		pattern = auto_strings->data;
		auto_strings = g_slist_remove(auto_strings, pattern);
		pattern_free(pattern);
	}

	f = fopen(auto_download_file, "r");
	if (f == NULL) {
		g_warning("could not open %s: %s",
			auto_download_file, g_strerror(errno));
		auto_last_mtime = 0;
		return;
	}

	if (dbg)
		printf("*** reloading %s\n", auto_download_file);

	i = 0;
	while(fgets(buf, LINELEN, f) != NULL) {
		buf[strlen(buf)-1] = 0;			/* Zap the trailing newline */
		if (buf[0] == '#')				/* Comment, ignore line */
			continue;
		pattern = pattern_compile(buf);
		auto_strings = g_slist_append(auto_strings, pattern);
	}

	fclose(f);
}

void autodownload_notify(gchar* file, guint32 size,
						 guint32 record_index, guint32 ip,
						 guint16 port, gchar* guid)
{
	GSList* cur_pattern;

	g_assert(use_autodownload);

	cur_pattern = auto_strings;
	while (cur_pattern != NULL) {
		cpattern_t *pattern;
		gchar *result;

		pattern = cur_pattern->data;
		result = pattern_qsearch(pattern, file, 0, 0, qs_any);

		if (result != NULL) {
			download_new(file, size, record_index, ip, port, guid);
			return;
		}

		cur_pattern = g_slist_next(cur_pattern);
	}

	return;
}

