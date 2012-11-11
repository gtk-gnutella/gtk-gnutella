/*
 * Copyright (c) 2012, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Network RX -- UDP transceiver layer (semi-reliable UDP)
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_rx_ut_h_
#define _core_rx_ut_h_

#include "common.h"

#include "rx.h"
#include "udp_reliable.h"		/* For udp_tag_t */

const struct rxdrv_ops* rx_ut_get_ops(void);

struct txdriver;

/**
 * Callbacks used by the semi-reliable RX layer.
 */
struct rx_ut_cb {
	void (*add_rx_given)(void *owner, ssize_t amount);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct rx_ut_args {
	udp_tag_t tag;					/**< Protocol tag (for logging mostly) */
	struct txdriver *tx;			/**< Sibling TX side for ACKs processing */
	struct rx_ut_cb *cb;			/**< Callbacks */
	bool advertised_improved_acks;	/**< Remote must advertise support first */
};

/**
 * Fields of the semi-reliable UDP header.
 *
 * We don't include the leading tag because messages are routed to the
 * the proper RX layer based on the tag so there's no need to analyze it
 * further.
 *
 * Also note that the order in the structure is not identical to the
 * physical framing order.
 */
struct ut_header {
	uint16 seqno;
	uint8 flags;
	uint8 part;			/* Zero-based */
	uint8 count;
};

/*
 * Public interface.
 */

bool ut_valid_message(const rxdrv_t *rx, const struct ut_header *uth,
	const gnet_host_t *from);
void ut_got_message(const rxdrv_t *rx, const void *data, size_t len,
	const gnet_host_t *from);

#endif	/* _core_rx_ut_h_ */

/* vi: set ts=4 sw=4 cindent: */

