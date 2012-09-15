/*
 * Copyright (c) 2001-2003, Raphael Manfredi
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_bsched_h_
#define _if_core_bsched_h_

#include "if/core/wrap.h"	/* For wrap_io_t */
#include "lib/inputevt.h"	/* For inputevt_handler_t */

#define BS_BW_MAX	(2*1024*1024)

typedef struct bsched bsched_t;

typedef enum {
	BSCHED_BWS_IN,
	BSCHED_BWS_OUT,
	BSCHED_BWS_GIN,
	BSCHED_BWS_GOUT,
	BSCHED_BWS_GLIN,
	BSCHED_BWS_GLOUT,
	BSCHED_BWS_GIN_UDP,
	BSCHED_BWS_GOUT_UDP,
	BSCHED_BWS_LOOPBACK_IN,
	BSCHED_BWS_LOOPBACK_OUT,
	BSCHED_BWS_PRIVATE_IN,
	BSCHED_BWS_PRIVATE_OUT,
	BSCHED_BWS_DHT_IN,
	BSCHED_BWS_DHT_OUT,

	NUM_BSCHED_BWS,
	BSCHED_BWS_INVALID = NUM_BSCHED_BWS
} bsched_bws_t;

/**
 * Source under bandwidth control.
 */

enum bio_source_magic { BIO_SOURCE_MAGIC = 0x7fb3bf07U };

typedef struct bio_source {
	enum bio_source_magic magic;	/**< magic for consistency checks */
	bsched_bws_t bws;				/**< B/w scheduler for this source */
	wrap_io_t *wio;					/**< Wrapped I/O object */
	unsigned io_tag;				/**< Recorded I/O callback tag */
	uint io_flags;					/**< Flags for I/O callback */
	inputevt_handler_t io_callback;		/**< I/O callback routine */
	void *io_arg;					/**< I/O callback argument */
	uint32 flags;					/**< Source flags */
	unsigned bw_allocated;			/**< Allocated bandwidth credit */
	uint bw_actual;					/**< Actual bandwidth used in period */
	uint bw_last_bps;				/**< B/w used last period (bps) */
	uint bw_fast_ema;				/**< Fast EMA of actual bandwidth used */
	uint bw_slow_ema;				/**< Slow EMA of actual bandwidth used */
} bio_source_t;

/*
 * Source flags.
 */

#define BIO_F_READ			(1 << 0)	/**< Reading source */
#define BIO_F_WRITE			(1 << 1)	/**< Writing source */
#define BIO_F_ACTIVE		(1 << 2)	/**< Source active since b/w scheduled */
#define BIO_F_USED			(1 << 3)	/**< Source used this period */
#define BIO_F_FAVOUR		(1 << 4)	/**< Try to favour source this period */
#define BIO_F_PASSIVE		(1 << 5)	/**< Don't insert source for events */

#define BIO_F_RW			(BIO_F_READ|BIO_F_WRITE)

#define BIO_EMA_SHIFT	7

#define bio_bps(b)		((b)->bw_last_bps)
#define bio_avg_bps(b)	((b)->bw_slow_ema >> BIO_EMA_SHIFT)

#endif /* _if_core_bsched_h_ */

/* vi: set ts=4: */
