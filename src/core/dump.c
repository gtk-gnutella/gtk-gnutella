/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
 * Copyright (c) 2006, Christian Biere
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
 * Traffic dumping, for later analysis with barracuda.
 *
 * @author Raphael Manfredi
 * @date 2009
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

RCSID("$Id$")

#include "nodes.h"
#include "settings.h"

#include "lib/file.h"
#include "lib/slist.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Barracuda header flags.
 */
enum dump_header_flags {                                                        
	DH_F_UDP  = (1 << 0),
	DH_F_TCP  = (1 << 1),
	DH_F_IPV4 = (1 << 2),
	DH_F_IPV6 = (1 << 3),

	NUM_DH_F
};

/**
 * Barracuda dump header.
 */
struct dump_header {
/*
 * This is the logic layout:
 *
 *	uint8_t flags;
 *	uint8_t addr[16];
 *	uint8_t port[2];
 */
	guchar data[19];
};

/**
 * Dumping context.
 */
struct dump {
	const char * const filename;
	slist_t *slist;
	size_t fill;
	int fd;
	int initialized;
};

static struct dump dump_rx = {
	"packets_rx.dump",		/* filename */
	NULL,					/* slist */
	0,						/* fill */
	-1,						/* fd */
	FALSE					/* initialized */
};

/**
 * Fill dump header with node address information.
 */
static void
dump_header_set(struct dump_header *dh, const struct gnutella_node *node)
{
	memset(dh, 0, sizeof dh);

	dh->data[0] = NODE_IS_UDP(node) ? DH_F_UDP : DH_F_TCP;
	switch (host_addr_net(node->addr)) {
	case NET_TYPE_IPV4:
		{
			guint32 ip;
			
			dh->data[0] |= DH_F_IPV4;
			ip = host_addr_ipv4(node->addr);
			poke_be32(&dh->data[1], ip);
		}
		break;
	case NET_TYPE_IPV6:
		dh->data[0] |= DH_F_IPV6;
		memcpy(&dh->data[1], host_addr_ipv6(&node->addr), 16);
		break;
	case NET_TYPE_LOCAL:
	case NET_TYPE_NONE:
		break;
	}
	poke_be16(&dh->data[17], node->port);
}

/**
 * Disable RX dumps.
 */
static void
dump_rx_disable(void)
{
	pmsg_slist_free(&dump_rx.slist);
	dump_rx.fill = 0;

	if (dump_rx.fd >= 0) {
		close(dump_rx.fd);
		dump_rx.fd = -1;
	}
	dump_rx.initialized = FALSE;
	if (GNET_PROPERTY(dump_received_gnutella_packets)) {
		gnet_prop_set_boolean_val(PROP_DUMP_RECEIVED_GNUTELLA_PACKETS, FALSE);
	}
}

/**
 * Initialize RX dumping.
 *
 * @return TRUE if initialized.
 */
static gboolean
dump_rx_init(void)
{
	char *pathname;

	if (dump_rx.initialized)
		return TRUE;

	pathname = make_pathname(settings_config_dir(), dump_rx.filename);
	dump_rx.fd = file_open_missing(pathname, O_WRONLY | O_APPEND | O_NONBLOCK);
	G_FREE_NULL(pathname);

	/*
	 * If the dump "file" is actually a named pipe, we'd block quickly
	 * if there was no reader.  So set the file as non-blocking and
	 * we'll disable dumping as soon as we can't write all the data
	 * we want.
	 */

	if (dump_rx.fd < 0) {
		g_warning("can't open %s -- disabling dumping", dump_rx.filename);
		dump_rx_disable();
		return FALSE;
	}

	file_set_nonblocking(dump_rx.fd);

	dump_rx.slist = slist_new();
	dump_rx.fill = 0;
	dump_rx.initialized = TRUE;
	return TRUE;
}

/**
 * Append data to the dump buffer.
 */
static void
dump_rx_append(const void *data, size_t size)
{
	g_return_if_fail(dump_rx.slist);

	pmsg_slist_append(dump_rx.slist, data, size);
	dump_rx.fill += size;
}

/**
 * Dump packet received from node.
 */
void
dump_rx_packet(const struct gnutella_node *node)
{
	struct dump_header dh;	

	if (!GNET_PROPERTY(dump_received_gnutella_packets)) {
		if (dump_rx.initialized) {
			dump_rx_disable();
		}
		return;
	}

	if (!dump_rx.initialized && !dump_rx_init())
		return;

	dump_header_set(&dh, node);
	dump_rx_append(dh.data, sizeof dh.data);
	dump_rx_append(node->header, sizeof node->header);
	dump_rx_append(node->data, node->size);

	while (dump_rx.fill > 0) {
		ssize_t written;
		struct iovec *iov;
		int iov_cnt;

		iov = pmsg_slist_to_iovec(dump_rx.slist, &iov_cnt, NULL);
		written = writev(dump_rx.fd, iov, iov_cnt);
		G_FREE_NULL(iov);

		if ((ssize_t)-1 == written) {
			if (!is_temporary_error(errno)) {
				g_warning("error writing to %s: %s -- disabling dumping",
					dump_rx.filename, g_strerror(errno));
				dump_rx_disable();
			}
			if (dump_rx.fill >= 256 * 1024UL) {
				g_warning(
					"queue is full: %s -- disabling dumping", dump_rx.filename);
				dump_rx_disable();
			}
			break;
		} else if (0 == written) {
			g_warning("error writing to %s: hang up -- disabling dumping",
				dump_rx.filename);
			dump_rx_disable();
			break;
		} else {
			g_assert(dump_rx.fill >= (size_t) written);
			dump_rx.fill -= written;
			pmsg_slist_discard(dump_rx.slist, written);
		}
	}
}

/**
 * Initialize traffic dumping.
 */
void dump_init(void)
{
	/* Nothing to do, initialized on the fly */
}

/**
 * Close traffic dumping.
 */
void dump_close(void)
{
	if (dump_rx.initialized)
		dump_rx_disable();
}

/* vi: set ts=4 sw=4 cindent: */
