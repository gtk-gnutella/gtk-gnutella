
#ifndef __filter_h__
#define __filter_h__

#include <arpa/inet.h>
#include <regex.h>

#include "matching.h"

enum filter_type {
  FILTER_TEXT,
  FILTER_IP,
  FILTER_SIZE
};

enum filter_text_type {
  FILTER_PREFIX,
  FILTER_WORDS,
  FILTER_SUFFIX,
  FILTER_SUBSTR,
  FILTER_REGEXP
};

struct filter {
  enum filter_type type;	/* type of filter, see above */
  int positive:1;		/* true: display matches; false: hide matches */
  union {
    struct _f_text {
      int case_sensitive:1;	/* case sensitive (true) or not (false) */
      enum filter_text_type type; /* type of match, see above */
      union {
	char *match;		/* match string */
	cpattern_t *pattern;	/* substring pattern */
	GList *words;		/* a list of substring patterns */
	regex_t *re;		/* regular expression match */
      } u;
    } text;
    struct _f_ip {
      guint32 addr;		/* IP address */
      guint32 mask;		/* netmask */
    } ip;
    struct _f_size {
      size_t lower;		/* lower limit or 0 */
      size_t upper;		/* upper limit or ~0 */
    } size;
  } u;
};

extern GList *global_filters;

/* ---- Functions ---- */

void filters_init(void);
void filters_open_dialog(void);

gboolean filter_record(struct search *, struct record *);

#endif							/* __filter_h__ */

/* vi: set ts=4: */
