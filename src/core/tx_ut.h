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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup core
 * @file
 *
 * Network driver -- UDP transceiver layer (semi-reliable UDP)
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_tx_ut_h_
#define _core_tx_ut_h_

#include "common.h"
#include "tx.h"
#include "udp_reliable.h"			/* For udp_tag_t */

#include "if/core/bsched.h"

const struct txdrv_ops *tx_ut_get_ops(void);

struct gnutella_host;

/**
 * Callbacks used by the semi-reliable UDP layer.
 */
struct tx_ut_cb {
	void (*msg_account)(void *owner, const pmsg_t *mb,
		const struct gnutella_host *to);
	void (*add_tx_dropped)(void *owner, int amount);
};

/**
 * Arguments to be passed when the layer is instantiated.
 */
struct tx_ut_args {
	udp_tag_t tag;					/**< Protocol tag */
	struct tx_ut_cb *cb;			/**< Callbacks */
	bool advertise_improved_acks;	/**< Improved acks needs flagging in TX */
	bool ear_support;				/**< Will the RX side understand EARs? */
};

/**
 * Acknowledgment parameters.
 */
struct ut_ack {
	uint cumulative:1;		/* Cumulative: 0 .. fragno-1 received */
	uint ear:1;				/* Whether this was an EAR */
	uint ear_nack:1;		/* Whether this was a negative EAR ACK */
	uint16 seqno;			/* Sequence ID */
	uint8 fragno;			/* Fragment number being acknowledged, zero-based */
	uint8 received;			/* If non-zero, amount of fragments received */
	uint32 missing;			/* If received != 0, missing fragment bitmap */
};

/*
 * Public interface.
 */

struct pmsg;
struct gnutella_host;

void ut_got_ack(txdrv_t *tx,
	const struct gnutella_host *from, const struct ut_ack *ack);
void ut_send_ack(txdrv_t *tx,
	const struct gnutella_host *to, const struct ut_ack *ack);

#endif	/* _core_tx_ut_h_ */

/* vi: set ts=4 sw=4 cindent: */

