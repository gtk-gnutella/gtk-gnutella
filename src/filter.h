
#ifndef __filter_h__
#define __filter_h__

/* ---- Functions ---- */

void filters_init(void);
void filters_open_dialog(void);

gboolean filter_record(struct search *, struct record *);

#endif							/* __filter_h__ */

/* vi: set ts=4: */
