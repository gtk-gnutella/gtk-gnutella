/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Network RX buffer allocator.
 */

#ifndef __rxbuf_h__
#define __rxbuf_h__

#include "pmsg.h"

/*
 * Public interface
 */

pdata_t *rxbuf_new(void);
void rxbuf_free(gpointer p, gpointer unused);

void rxbuf_init(void);
void rxbuf_close(void);

#endif	/* __rxbuf_h__ */

/* vi: set ts=4: */

