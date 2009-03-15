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
#include "lib/pmsg.h"
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
	DH_F_TO   = (1 << 4),
	DH_F_CTRL = (1 << 5),

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
	const gboolean *dump_var;
	size_t fill;
	int fd;
	int initialized;
	gnet_property_t dump_property;
};

static struct dump dump_rx = {
	"packets_rx.dump",		/* filename in ~/.gtk-gnutella */
	NULL,					/* slist */
	GNET_PROPERTY_PTR(dump_received_gnutella_packets),	/* dump_var */
	0,						/* fill */
	-1,						/* fd */
	FALSE,					/* initialized */
	PROP_DUMP_RECEIVED_GNUTELLA_PACKETS,	/* dump_property */
};

static struct dump dump_tx = {
	"packets_tx.dump",		/* filename in ~/.gtk-gnutella */
	NULL,					/* slist */
	GNET_PROPERTY_PTR(dump_transmitted_gnutella_packets),	/* dump_var */
	0,						/* fill */
	-1,						/* fd */
	FALSE,					/* initialized */
	PROP_DUMP_TRANSMITTED_GNUTELLA_PACKETS,	/* dump_property */
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
 * Disable dumps.
 */
static void
dump_disable(struct dump *dump)
{
	pmsg_slist_free(&dump->slist);
	dump->fill = 0;

	if (dump->fd >= 0) {
		close(dump->fd);
		dump->fd = -1;
	}
	dump->initialized = FALSE;
	if (*dump->dump_var) {
		gnet_prop_set_boolean_val(dump->dump_property, FALSE);
	}
}

/**
 * Initialize RX dumping.
 *
 * @return TRUE if initialized.
 */
static gboolean
dump_initialize(struct dump *dump)
{
	char *pathname;

	if (dump->initialized)
		return TRUE;

	pathname = make_pathname(settings_config_dir(), dump->filename);
	dump->fd = file_open_missing(pathname, O_WRONLY | O_APPEND | O_NONBLOCK);
	G_FREE_NULL(pathname);

	/*
	 * If the dump "file" is actually a named pipe, we'd block quickly
	 * if there was no reader.  So set the file as non-blocking and
	 * we'll disable dumping as soon as we can't write all the data
	 * we want.
	 */

	if (dump->fd < 0) {
		g_warning("can't open %s -- disabling dumping", dump->filename);
		dump_disable(dump);
		return FALSE;
	}

	file_set_nonblocking(dump->fd);

	dump->slist = slist_new();
	dump->fill = 0;
	dump->initialized = TRUE;

	return TRUE;
}

/**
 * Append data to the dump buffer.
 */
static void
dump_append(struct dump *dump, const void *data, size_t size)
{
	g_return_if_fail(dump->slist);

	pmsg_slist_append(dump->slist, data, size);
	dump->fill += size;
}

/**
 * Flush buffered data.
 */
static void
dump_flush(struct dump *dump)
{
	while (dump->fill > 0) {
		ssize_t written;
		struct iovec *iov;
		int iov_cnt;

		iov = pmsg_slist_to_iovec(dump->slist, &iov_cnt, NULL);
		written = writev(dump->fd, iov, iov_cnt);
		G_FREE_NULL(iov);

		if ((ssize_t)-1 == written) {
			if (!is_temporary_error(errno)) {
				g_warning("error writing to %s: %s -- disabling dumping",
					dump->filename, g_strerror(errno));
				dump_disable(dump);
			}
			if (dump->fill >= 256 * 1024UL) {
				g_warning(
					"queue is full: %s -- disabling dumping", dump->filename);
				dump_disable(dump);
			}
			break;
		} else if (0 == written) {
			g_warning("error writing to %s: hang up -- disabling dumping",
				dump->filename);
			dump_disable(dump);
			break;
		} else {
			g_assert(dump->fill >= (size_t) written);
			dump->fill -= written;
			pmsg_slist_discard(dump->slist, written);
		}
	}
}

/**
 * Dump packet received from node.
 */
static void
dump_packet_from(struct dump *dump, const struct gnutella_node *node)
{
	struct dump_header dh;	

	dump_header_set(&dh, node);
	dump_append(dump, dh.data, sizeof dh.data);
	dump_append(dump, node->header, sizeof node->header);
	dump_append(dump, node->data, node->size);
	dump_flush(dump);
}

/**
 * Dump relayed or locally-emitted packet.
 * If ``from'' is NULL, packet was emitted locally.
 */
static void
dump_packet_from_to(struct dump *dump,
	const struct gnutella_node *from, const struct gnutella_node *to,
	const pmsg_t *mb)
{
	struct dump_header dh_to;	
	struct dump_header dh_from;	

	g_assert(to != NULL);
	g_assert(mb != NULL);
	g_assert(pmsg_read_base(mb) == pmsg_start(mb));

	/*
	 * This is only for Gnutella packets, leave DHT messages out.
	 */

	if (GTA_MSG_DHT == gnutella_header_get_function(pmsg_start(mb)))
		return;

	if (NULL == from) {
		struct gnutella_node local;
		local.peermode = NODE_IS_UDP(to) ? NODE_P_UDP : NODE_P_NORMAL;
		local.addr = listen_addr();
		local.port = GNET_PROPERTY(listen_port);
		dump_header_set(&dh_from, &local);
	} else {
		dump_header_set(&dh_from, from);
	}

	dump_header_set(&dh_to, to);
	dh_to.data[0] |= DH_F_TO;
	if (pmsg_prio(mb) != PMSG_P_DATA)
		dh_to.data[0] |= DH_F_CTRL;
		
	dump_append(dump, dh_to.data, sizeof dh_to.data);
	dump_append(dump, dh_from.data, sizeof dh_from.data);
	dump_append(dump, pmsg_read_base(mb), pmsg_size(mb));
	dump_flush(dump);
}

/**
 * Dump packet received from node.
 */
void
dump_rx_packet(const struct gnutella_node *node)
{
	if (!GNET_PROPERTY(dump_received_gnutella_packets)) {
		if (dump_rx.initialized) {
			dump_disable(&dump_rx);
		}
		return;
	}

	if (!dump_rx.initialized && !dump_initialize(&dump_rx))
		return;

	dump_packet_from(&dump_rx, node);
}

/**
 * Dump transmitted message block via TCP.
 * If ``from'' is NULL, packet was emitted locally.
 */
void
dump_tx_tcp_packet(
	const struct gnutella_node *from, const struct gnutella_node *to,
	const pmsg_t *mb)
{
	if (!GNET_PROPERTY(dump_transmitted_gnutella_packets)) {
		if (dump_tx.initialized) {
			dump_disable(&dump_tx);
		}
		return;
	}

	if (!dump_tx.initialized && !dump_initialize(&dump_tx))
		return;

	g_assert(to != NULL);
	g_assert(mb != NULL);
	g_assert(!NODE_IS_UDP(to));

	dump_packet_from_to(&dump_tx, from, to, mb);
}

/**
 * Dump locally-emitted message block sent via UDP.
 */
void
dump_tx_udp_packet(const gnet_host_t *to, const pmsg_t *mb)
{
	struct gnutella_node udp;

	if (!GNET_PROPERTY(dump_transmitted_gnutella_packets)) {
		if (dump_tx.initialized) {
			dump_disable(&dump_tx);
		}
		return;
	}

	if (!dump_tx.initialized && !dump_initialize(&dump_tx))
		return;

	g_assert(to != NULL);
	g_assert(mb != NULL);

	/*
	 * Fill only the fields which will be perused by dump_packet_from_to().
	 */

	udp.peermode = NODE_P_UDP;
	udp.addr = gnet_host_get_addr(to);
	udp.port = gnet_host_get_port(to);

	dump_packet_from_to(&dump_tx, NULL, &udp, mb);
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
		dump_disable(&dump_rx);
}

/* vi: set ts=4 sw=4 cindent: */
