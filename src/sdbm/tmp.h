/* Mini EMBED (tmp.c) */
#define tmp_add sdbm__tmp_add
#define tmp_remove sdbm__tmp_remove
#define tmp_clean sdbm__tmp_clean

void tmp_add(const DBM *, const char *);
void tmp_remove(const DBM *, const char *);
void tmp_clean(const DBM *);
