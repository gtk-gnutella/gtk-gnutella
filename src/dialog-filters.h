
#ifndef __dialog_filters_h__
#define __dialog_filters_h__

GtkWidget *create_dialog_filters(void);

void filters_open_dialog(void);
void filters_new_search(struct search *);
void filters_close_search(struct search *);
void filters_shutdown(void);

#endif /* __dialog_filters_h__ */

