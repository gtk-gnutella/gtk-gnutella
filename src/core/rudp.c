/*
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
 * "Reliable" UDP connections.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "gnutella.h"
#include "nodes.h"
#include "udp.h"
#include "sockets.h"

#include "if/core/gnutella.h"
#include "if/gnet_property_priv.h"

#include "lib/endian.h"
#include "lib/hashing.h"
#include "lib/hashlist.h"
#include "lib/host_addr.h"
#include "lib/hset.h"
#include "lib/inputevt.h"
#include "lib/pmsg.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

/* The currently support protocol version. */
static const uint16 RUDP_PROTO_VERSION = 0;

static const uint16 RUDP_WINDOW = 20;

/* Standardized RUDP packet opcodes */
enum rudp_op {
	RUDP_OP_SYN        = 0x00,
	RUDP_OP_ACK        = 0x01,
	RUDP_OP_KEEP_ALIVE = 0x02,
	RUDP_OP_DATA       = 0x03,
	RUDP_OP_FIN        = 0x04
};

/* Standardized RUDP FIN codes */
enum rudp_fin_reason {
	RUDP_FIN_CLOSE     = 0x00,
	RUDP_FIN_ACK       = 0x01,
	RUDP_FIN_TIMEOUT   = 0x02,
	RUDP_FIN_TOO_BIG   = 0x03,
	RUDP_FIN_TOO_BAD   = 0x04
};

/*
 * Raw layout of a RUDP packet header. This overlays/replaces the GUID area of
 * a Gnutella packet. Thus the "GUID" of these is meaningless.
 */
struct rudp_header {
	uint8 peer_conn_id;
	uint8 op_and_len;
	uint8 seq_no[2];
};

/* Raw layout of a RUDP SYN packet */
struct rudp_syn {
	struct rudp_header common;

	uint8 conn_id;
	uint8 proto_ver[2];
};

/* Raw layout of a RUDP ACK packet */
struct rudp_ack {
	struct rudp_header common;

	uint8 window_start[2];
	uint8 window_space[2];
};

/* Raw layout of a RUDP DATA packet */
struct rudp_data {
	struct rudp_header common;

	uint8 data1[12];
};

/* Raw layout of a RUDP FIN packet */
struct rudp_fin {
	struct rudp_header common;

	uint8 reason;
};

/*
 * Implementation-specific structures and definitons
 */

enum rudp_status {
	RUDP_ST_ALLOCED = 0,	/* Freshly allocated, nothing has been sent */
	RUDP_ST_SYN_SENT,		/* Sent one or SYNs but not ACKed yet */
	RUDP_ST_ESTABLISHED,	/* Our SYN was ACKed */
	RUDP_ST_CLOSED			/* The connection was closed; FIN sent */
};

enum rudp_list {
	RUDP_LIST_INCOMING,	/* Incoming connection requests */
	RUDP_LIST_READABLE,	/* Connections with available buffered input */
	RUDP_LIST_WRITABLE,	/* Connections with available buffered output */
	RUDP_LIST_PENDING,	/* Connections with pending output data */
	RUDP_LIST_CLOSED,	/* Closed connections */

	RUDP_NUM_LISTS
};

static hash_list_t *rudp_list[RUDP_NUM_LISTS];

struct rudp_window {
	pmsg_t *buffers[32];
  	uint64 seq_no;		/* The current sequence number */
  	uint rd;			/* Read position; wrapping index into `buffers' */
  	uint wr;			/* Write position; wrapping index into `buffers' */
  	uint64 start;		/* The first sequence number in this window */
	uint16 space;		/* The size of the window */
	tm_t last_event;	/* Timestamp of the last I/O event */
};

struct rudp_con {
	inputevt_handler_t event_handler;
	inputevt_cond_t event_cond;
	void *event_data;

	host_addr_t addr;
	uint16 port;
	uint8 conn_id;
	struct rudp_window in;
	struct rudp_window out;
	enum rudp_status status;
};

static hset_t *connections;

#define RUDP_DEBUG(x) \
G_STMT_START { \
	if (rudp_debug) { \
		g_debug x; \
	} \
} G_STMT_END

static const char *
rudp_op_to_string(uint8 op)
{
	if (op <= 0x04) {
		enum rudp_op v = op;

		switch (v) {
#define CASE(x) case ( RUDP_OP_ ##x ) : return #x;
		CASE(SYN)
		CASE(ACK)
		CASE(KEEP_ALIVE)
		CASE(DATA)
		CASE(FIN)
#undef CASE
		}
	}
	return NULL;
}

static const char *
rudp_fin_reason_to_string(uint8 reason)
{
	if (reason <= 0x04) {
		enum rudp_fin_reason v = reason;

		switch (v) {
#define CASE(x) case ( RUDP_FIN_ ##x ) : return #x;
		CASE(CLOSE)
		CASE(ACK)
		CASE(TIMEOUT)
		CASE(TOO_BIG)
		CASE(TOO_BAD)
#undef CASE
		}
	}
	return "<Unknown>";
}

/**
 * Hash function for use in hash tables.
 */
static uint
rudp_con_hash(const void *key)
{
	const struct rudp_con *c = key;

	return host_addr_port_hash(c->addr, c->port) ^
		integer_hash_fast(c->conn_id);
}

/**
 * Compare function which returns TRUE if the connections are equal.
 *
 * @note For use in hash tables.
 */
int
rudp_con_eq(const void *v1, const void *v2)
{
	const struct rudp_con *c1 = v1, *c2 = v2;

	return c1->conn_id == c2->conn_id &&
		c1->port == c2->port && host_addr_equiv(c1->addr, c2->addr);
}

static void
rudp_list_add(enum rudp_list i, struct rudp_con *con, bool ready)
{
	g_return_if_fail(con);

	hash_list_remove(rudp_list[i], con);
	if (ready) {
		hash_list_prepend(rudp_list[i], con);
	}
}

static void
rudp_set_readable(struct rudp_con *con, bool ready)
{
	rudp_list_add(RUDP_LIST_READABLE, con, ready);
}

static void
rudp_set_writable(struct rudp_con *con, bool ready)
{
	rudp_list_add(RUDP_LIST_WRITABLE, con, ready);
}

static void
rudp_set_closed(struct rudp_con *con)
{
	rudp_list_add(RUDP_LIST_CLOSED, con, TRUE);
}

static void
rudp_set_incoming(struct rudp_con *con, bool ready)
{
	rudp_list_add(RUDP_LIST_INCOMING, con, ready);
}

static void
rudp_set_pending(struct rudp_con *con, bool ready)
{
	rudp_list_add(RUDP_LIST_PENDING, con, ready);
}

static inline bool
rudp_seq_number_in_recv_window(const struct rudp_con *con, uint16 seq_no)
{
	/* TODO: Overflow handling */
	return seq_no >= con->in.start &&
		seq_no <= (uint32) con->in.start + con->in.space;
}

static inline bool
rudp_seq_number_in_send_window(const struct rudp_con *con, uint16 seq_no)
{
	/* TODO: Overflow handling */
	return seq_no >= con->out.start &&
		seq_no <= (uint32) con->out.start + con->out.space;
}

struct rudp_con *
rudp_find(const host_addr_t addr, uint16 port, uint8 conn_id)
{
	static const struct rudp_con zero_con;
	struct rudp_con key;

	key = zero_con;
	key.addr = addr;
	key.port = port;
	key.conn_id = conn_id;
	return hset_lookup(connections, &key);
}

struct rudp_con *
rudp_alloc(const host_addr_t addr, uint16 port, uint8 conn_id)
{
	g_return_val_if_fail(is_host_addr(addr), NULL);
	g_return_val_if_fail(0 != port, NULL);

	if (!rudp_find(addr, port, conn_id)) {
		static const struct rudp_con zero_con;
		struct rudp_con *con;

		WALLOC(con);
		*con = zero_con;
		con->addr = addr;
		con->port = port;
		con->conn_id = conn_id;
		con->in.space = RUDP_WINDOW;
		con->out.space = RUDP_WINDOW;
		hset_insert(connections, con);
		return con;
	}
	return NULL;
}

static void
rudp_set_gnet_header(gnutella_header_t *header, uint32 size)
{
	g_assert(size < 0xffff);

	ZERO(&header->muid);
	header->function = GTA_MSG_RUDP;
	header->ttl = 1;
	header->hops = 0;
	poke_le32(header->size, size);
}

static void
rudp_set_header(struct rudp_header *header, enum rudp_op op, uint8 conn_id,
    uint8 data1_len, uint16 seq_no)
{ 
	g_assert(op < 16);  
	g_assert(data1_len <= 12);

	header->op_and_len = (op << 4) | (data1_len & 0x0f);
	header->peer_conn_id = conn_id;
	poke_be16(header->seq_no, seq_no);
} 

static void
rudp_send_packet(struct rudp_con *con, const void *data, size_t size)
{
	const gnutella_node_t *n;

	RUDP_DEBUG(
		("SENDING TO %s", host_addr_port_to_string(con->addr, con->port)));

	{
		gnutella_header_t *header = data;

		g_return_if_fail(GTA_MSG_RUDP == header->function);
		g_return_if_fail(1 == header->ttl);
		g_return_if_fail(0 == header->hops);
		g_return_if_fail(size - 23 == peek_le32(header->size));

		RUDP_DEBUG(("TYPE=0x%02x TTL=%u HOPS=%u SIZE=%lu",
			header->function, header->ttl, header->hops,
			(ulong) peek_le32(header->size)));
	}

	{
		const struct rudp_header *header = data;

		g_return_if_fail((header->op_and_len & 0x0f) <= 12);
		g_return_if_fail(((header->op_and_len >> 4) & 0x0f) <= 0x04);
		g_return_if_fail(header->peer_conn_id == con->conn_id);

		RUDP_DEBUG(("OP=%s DATA1_LEN=%u CONN_ID=%u SEQ_NO=%u\n",
			rudp_op_to_string((header->op_and_len >> 4) & 0x0f),
			header->op_and_len & 0x0f, header->peer_conn_id,
			peek_be16(header->seq_no)));
	}

	n = node_udp_get_addr_port(con->addr, con->port);
	if (n) {
		udp_send_msg(n, data, size);
		tm_now(&con->out.last_event);
	}
}

static inline bool
rudp_may_send_syn(const struct rudp_con *con)
{
	switch (con->status) {
	case RUDP_ST_ALLOCED:
	case RUDP_ST_SYN_SENT:
		return TRUE;
	case RUDP_ST_ESTABLISHED:
	case RUDP_ST_CLOSED:
		break;
	}
	return FALSE;
}

static void
rudp_send_syn(struct rudp_con *con)
{ 
	g_return_if_fail(con);
	g_return_if_fail(0 == con->out.start);
	g_return_if_fail(rudp_may_send_syn(con));

	switch (con->status) {
	case RUDP_ST_ALLOCED:
		{
			 gnutella_header_t *gnet;
			 struct rudp_syn *syn;
			 char packet[MAX(sizeof *gnet, sizeof *syn)];
			 pmsg_t *mb;

			 STATIC_ASSERT(23 == sizeof packet);

			 gnet = cast_to_pointer(&packet);
			 syn = cast_to_pointer(&packet);

			 rudp_set_gnet_header(gnet, 0);
			 rudp_set_header(&syn->common, RUDP_OP_SYN, con->conn_id, 0,
				con->out.seq_no++);

			 syn->conn_id = con->conn_id;
			 poke_be16(syn->proto_ver, RUDP_PROTO_VERSION);

			 RUDP_DEBUG(("RUDP: Sending SYN to %s (proto_ver=%u, conn_id=%u)",
				 host_addr_port_to_string(con->addr, con->port),
				 peek_be16(syn->proto_ver), syn->conn_id));

			 mb = pmsg_new(PMSG_P_DATA, &packet, sizeof packet);

			 g_return_if_fail(0 == con->out.wr);
			 con->out.buffers[con->out.wr++] = mb;
			 con->status = RUDP_ST_SYN_SENT;
		}
	 /* FALL THROUGH */
	case RUDP_ST_SYN_SENT:
		{
			 pmsg_t *mb;
			 
			 g_return_if_fail(0 == con->out.rd);
			 mb = con->out.buffers[con->out.rd];
			 g_return_if_fail(mb);

			 rudp_send_packet(con, pmsg_read_base(mb), pmsg_size(mb));
		}
		break;
	case RUDP_ST_ESTABLISHED:
	case RUDP_ST_CLOSED:
		break;
  }
}

static void
rudp_send_ack(struct rudp_con *con, uint16 seq_no)
{ 
	gnutella_header_t *gnet;
	struct rudp_ack *ack;
	char packet[MAX(sizeof *ack, sizeof *gnet)];

	STATIC_ASSERT(sizeof packet == 23);

	g_return_if_fail(con);

	if (seq_no >= con->in.start) {
		con->in.start = seq_no + 1;
	}

	gnet = cast_to_pointer(&packet);
	ack = cast_to_pointer(&packet);

	rudp_set_gnet_header(gnet, 0);
	rudp_set_header(&ack->common, RUDP_OP_ACK, con->conn_id, 0, seq_no);

	poke_be16(ack->window_start, con->in.start);
	poke_be16(ack->window_space, con->in.space);

	RUDP_DEBUG(("RUDP: Sending ACK to %s (seq_no=%u, start=%s, space=%u)",
	host_addr_port_to_string(con->addr, con->port), seq_no,
	uint64_to_string(con->in.start), con->in.space));

	rudp_send_packet(con, &packet, sizeof packet);
}

static void
rudp_send_fin(struct rudp_con *con, uint16 seq_no, enum rudp_fin_reason reason)
{ 
	gnutella_header_t *gnet;
	struct rudp_fin *fin;
	char packet[MAX(sizeof *fin, sizeof *gnet)];

	STATIC_ASSERT(sizeof packet == 23);

	g_return_if_fail(con);

	gnet = cast_to_pointer(&packet);
	fin = cast_to_pointer(&packet);

	rudp_set_gnet_header(gnet, 0);
	rudp_set_header(&fin->common, RUDP_OP_FIN, con->conn_id, 0, seq_no);
	fin->reason = reason; 

	con->status = RUDP_ST_CLOSED;
	con->in.space = 1;

	rudp_set_writable(con, FALSE);
	rudp_set_closed(con);

	RUDP_DEBUG(("RUDP: Sending FIN to %s (seq_no=%u, reason=%s)",
		host_addr_port_to_string(con->addr, con->port),
		seq_no, rudp_fin_reason_to_string(fin->reason)));

	rudp_send_packet(con, &packet, sizeof packet);
}

/**
 * Allocates a new RUDP connection and sends a RUDP SYN to the given
 * host.
 *
 * @param addr	The address of the host to connect to.
 * @param port	The port of the host to connect to.
 * @return	On failure -1 is returned. Otherwise a non-negative connection ID
 *			is returned.
 */
int
rudp_connect(const host_addr_t addr, uint16 port)
{
	struct rudp_con *con;
	uint i;

	g_return_val_if_fail(is_host_addr(addr), -1);
	g_return_val_if_fail(0 != port, -1);

	/*
	 * The connection ID is an 8-bit field. Thus there can be at most
	 * 256 connections between (a.address, a.port) and (b.address, b.port).
	 */	
	for (i = 0; i < 256; i++) {
		/* TODO: The connection ID should be randomized. Also consider
		 * to not recycle IDs to frequently because we might receive
		 * fall out from the previous connection (``TIME_WAIT'').
		 */
		con = rudp_alloc(addr, port, i);
		if (con)
			break;
	}

	if (con) {
		rudp_send_syn(con);
		return i;
	} else {
		return -1;
	}
}

/**
 * Handler for received RUDP SYN packets.
 *
 * @param con The RUDP connection; may be NULL for incoming connections.
 * @param addr The source address of the packet.
 * @param port The source port of the packet.
 * @param data A pointer to the first byte of the received packet.
 */
static void
rudp_handle_syn(struct rudp_con *con, const host_addr_t addr, uint16 port,
	const void *data)
{
	const struct rudp_syn *syn = data;
	uint16 proto_ver;
	uint16 seq_no;

	g_return_if_fail(syn);

   	seq_no = peek_be16(syn->common.seq_no);
	proto_ver = peek_be16(syn->proto_ver);

	RUDP_DEBUG(("RUDP SYN: conn_id=%u proto_ver=%u",
		(uint) syn->conn_id, (uint) proto_ver));
    
	if (RUDP_PROTO_VERSION != proto_ver) {
		RUDP_DEBUG(("RUDP SYN: Unsupported protocol version"));
		return;
	}

	if (0 != seq_no) {
		RUDP_DEBUG(("RUDP SYN: Non-zero sequence number"));
		return;
	}
	if (!con) {
		con = rudp_find(addr, port, syn->conn_id);
		if (!con) {
			/* This seems to be an incoming connection. */
			con = rudp_alloc(addr, port, syn->conn_id);
			if (!con) {
				RUDP_DEBUG(("RUDP SYN: Dropping incoming SYN, out-of-IDs"));
				return;
			}
		}
	}

	switch (con->status) {
	case RUDP_ST_ALLOCED:
	case RUDP_ST_SYN_SENT:
		rudp_send_syn(con);
		rudp_send_ack(con, seq_no);
		con->in.seq_no = 1;
		rudp_set_incoming(con, TRUE);
		break;
	case RUDP_ST_ESTABLISHED:
	case RUDP_ST_CLOSED:
		break;
	}
}

/**
 * Handler for received RUDP ACK packets.
 *
 * @param con The RUDP connection; may be NULL for incoming connections.
 * @param data A pointer to the first byte of the received packet.
 */
static void
rudp_handle_ack(struct rudp_con *con, const void *data)
{
	const struct rudp_ack *ack = data;
    uint16 space, start, seq_no;

	g_return_if_fail(con);
	g_return_if_fail(data);

	seq_no = peek_be16(ack->common.seq_no);
	start = peek_be16(ack->window_start);
	space = peek_be16(ack->window_space);	

	RUDP_DEBUG(("RUDP ACK: seq_no=%u, window_start=%u, window_space=%u",
		seq_no, start, space));

#if 0	
	if (!rudp_seq_number_in_send_window(con, seq_no)) {
		RUDP_DEBUG(("RUDP: Out of window (%u..%u)",
			con->out.start,
			con->out.start + con->out.space));
		return;
	}
#endif

	switch (con->status) {
	case RUDP_ST_ALLOCED:
		RUDP_DEBUG(("RUDP: SYN not sent yet!?!"));
		return;
	case RUDP_ST_CLOSED:
		break;
	case RUDP_ST_SYN_SENT:
		con->status = RUDP_ST_ESTABLISHED;
		rudp_set_readable(con, TRUE);
		/* FALL THROUGH */
	case RUDP_ST_ESTABLISHED:
		rudp_set_writable(con, TRUE);
		break;
	}
	
	{
		bool pending;
		uint i;

		/*
		 * Remove all ACKed messages from the outbuf buffers. The 
		 * ACK qualifies for `seq_no' and all up to `start - 1'.
		 */
		for (i = 0; i < G_N_ELEMENTS(con->out.buffers); i++) {
			pmsg_t *mb;

			mb = con->out.buffers[i];
			if (mb) {
				const struct rudp_header *header;
				uint16 s;

				header = cast_to_constpointer(pmsg_read_base(mb));
				s = peek_be16(header->seq_no);
				if (s == seq_no || s < start) {
					pmsg_free(mb);
					con->out.buffers[i] = NULL;
				}
			} 
		}

		pending = FALSE;
		for (i = 0; i < G_N_ELEMENTS(con->out.buffers); i++) {
			if (con->out.buffers[con->out.rd]) {
				pending = TRUE;
				break;
			}
			if (con->out.wr == con->out.rd) {
				break;
			}
			con->out.rd++;
			con->out.rd %= G_N_ELEMENTS(con->out.buffers);
		}
		rudp_set_pending(con, pending);
	}

	if (start > con->out.start + con->out.space) {
		/* Prevent ACKs beyond the current window. */
		start = con->out.start + con->out.space;
	} else {
		con->out.start = MAX(start, con->out.start);
	}
	con->out.space = MIN(space, G_N_ELEMENTS(con->out.buffers));
}

static void
rudp_handle_keep_alive(struct rudp_con *con, const void *data)
{
	const struct rudp_ack *keep_alive = data;
	uint16 seq_no;

	g_return_if_fail(con);
	g_return_if_fail(data);

	seq_no = peek_be16(keep_alive->common.seq_no);
	rudp_send_ack(con, seq_no);
}

static void
rudp_handle_fin(struct rudp_con *con, const void *data)
{
	const struct rudp_fin *fin = data;
	uint16 seq_no;

	g_return_if_fail(con);
	g_return_if_fail(data);

	seq_no = peek_be16(fin->common.seq_no);

	RUDP_DEBUG(("RUDP FIN: reason=%s", rudp_fin_reason_to_string(fin->reason)));

	switch (con->status) {
	case RUDP_ST_ESTABLISHED:
	case RUDP_ST_SYN_SENT:
		rudp_send_fin(con, seq_no, RUDP_FIN_ACK);
		break;
	case RUDP_ST_CLOSED:
	case RUDP_ST_ALLOCED:
		break;
	}
}

static void
rudp_handle_data(struct rudp_con *con, const void *data)
{
	const struct rudp_data *dat = data;
	uint16 seq_no, i;
	
	g_return_if_fail(con);
	g_return_if_fail(data);

	seq_no = peek_be16(dat->common.seq_no);

	RUDP_DEBUG(("RUDP DATA: seq_no=%u", seq_no));

	i = seq_no - con->in.seq_no;
	g_return_if_fail(i < G_N_ELEMENTS(con->in.buffers));

	i = ((uint32) i + con->in.rd) % G_N_ELEMENTS(con->in.buffers);
	
	if (con->in.buffers[i]) {
		RUDP_DEBUG(("RUDP DATA: Received duplicate"));
	} else {
    	gnutella_header_t *gnet_header = data;
		size_t data1_len, data_len, size;
		
		data1_len = dat->common.op_and_len & 0x0f;
		data_len = peek_le32(gnet_header->size) & 0xffff;
		size = data1_len + data_len;

		if (size > 0) {
			pmsg_t *mb;

			mb = pmsg_new(PMSG_P_DATA, NULL, data1_len + data_len);
			pmsg_write(mb, dat->data1, data1_len);
			pmsg_write(mb, &gnet_header[1], data_len);
			con->in.buffers[i] = mb;

			rudp_set_readable(con, TRUE);
		}
	}
	
	rudp_send_ack(con, seq_no);
}

static bool
rudp_send_data(struct rudp_con *con, const void *data, size_t size)
{
	const char *p = data;
	uint data_len;
	pmsg_t *mb;

	if (con->out.buffers[con->out.wr]) {
		return FALSE;
	}
	
	data_len = size < 12 ? 0 : (size - 12);
	mb = pmsg_new(PMSG_P_DATA, NULL, 23 + data_len);
	{
		union {
			gnutella_header_t gnet;
			struct rudp_data data;
		} header;
		uint data1_len, j;

		data1_len = size < 12 ? size : 12;
		rudp_set_gnet_header(&header.gnet, data_len);
		rudp_set_header(&header.data.common, RUDP_OP_DATA, con->conn_id,
				data1_len, con->out.seq_no++);

		for (j = 0; j < 12; j++) {
			header.data.data1[j] = j < data1_len ? *p++ : 0;
		}
		pmsg_write(mb, &header, sizeof header);
	}
	pmsg_write(mb, p, data_len);

	con->out.buffers[con->out.wr] = mb;
	con->out.wr++;
	con->out.wr %= G_N_ELEMENTS(con->out.buffers);

	return TRUE;
}

void
rudp_handle_packet(const host_addr_t addr, uint16 port,
	const void *data, size_t size)
{
	const struct rudp_header *rudp_header;
    gnutella_header_t *gnet_header;
	const char *op_str;
	uint16 seq_no;
	uint8 data1_len;
	uint8 op;
	uint8 conn_id;
	struct rudp_con *con;

	g_return_if_fail(is_host_addr(addr));
	g_return_if_fail(0 != port);
	g_return_if_fail(data);
	g_return_if_fail(size >= sizeof *gnet_header);
	g_return_if_fail(size >= sizeof *rudp_header);

	gnet_header = data;
	g_return_if_fail(GTA_MSG_RUDP == gnet_header->function);
	g_return_if_fail(size - sizeof *gnet_header == peek_le32(gnet_header->size));

	rudp_header = data;
	op = (rudp_header->op_and_len >> 4) & 0x0f;
	op_str = rudp_op_to_string(op);
	seq_no = peek_be16(rudp_header->seq_no);
	data1_len = rudp_header->op_and_len & 0x0f;
	conn_id = rudp_header->peer_conn_id;

	RUDP_DEBUG(("RUDP: sender=%s op=%s peer_conn_id=%u data_len=%u seq_no=%u",
		host_addr_port_to_string(addr, port), op_str ? op_str : "",
		(uint) conn_id, (uint) data1_len, (uint) seq_no));

	if (!op_str) {
		RUDP_DEBUG(("RUDP: Unknown op (0x%02x)", op));
		return;
	}

	if (data1_len > 12) {
		RUDP_DEBUG(("RUDP: Bad data_1 length (%u)", data1_len));
		return;
	}

	con = rudp_find(addr, port, rudp_header->peer_conn_id);
	if (con) {
		g_assert(port == con->port);
		g_assert(host_addr_equiv(addr, con->addr));
		g_assert(rudp_header->peer_conn_id == con->conn_id);

		if (RUDP_OP_ACK != op) {
			
			if (!rudp_seq_number_in_recv_window(con, seq_no)) {
				char start_buf[UINT64_DEC_BUFLEN];
				char space_buf[UINT64_DEC_BUFLEN];

				uint64_to_string_buf(con->in.start,
					start_buf, sizeof start_buf);
				uint64_to_string_buf(con->in.start + con->in.space,
					space_buf, sizeof space_buf);

				RUDP_DEBUG(("RUDP: Out of window (%s..%s)",
					start_buf, space_buf));
				return;
			}
		}
  		tm_now(&con->in.last_event);
	} else if (RUDP_OP_SYN != op) {
		RUDP_DEBUG(("RUDP: Unknown connection ID"));
		return;
	}

	switch ((enum rudp_op) op) {
	case RUDP_OP_SYN:
		rudp_handle_syn(con, addr, port, rudp_header);
		break;
	case RUDP_OP_KEEP_ALIVE:
		rudp_handle_keep_alive(con, rudp_header);
		break;
	case RUDP_OP_ACK:
		rudp_handle_ack(con, rudp_header);
		break;
	case RUDP_OP_DATA:
		rudp_handle_data(con, rudp_header);
		break;
	case RUDP_OP_FIN:
		rudp_handle_fin(con, rudp_header);
		break;
	}
}

ssize_t
rudp_write(struct rudp_con *con, const void *data, size_t size)
{
	const char *p;
	
	g_return_val_if_fail(con, -1);
	g_return_val_if_fail(data, -1);
	g_return_val_if_fail(size > 0, -1);

	if (RUDP_ST_ESTABLISHED != con->status) {
		switch (con->status) {
		case RUDP_ST_CLOSED:
			errno = EPIPE;
			return -1;
		case RUDP_ST_SYN_SENT:
			errno = VAL_EAGAIN;
			break;
		case RUDP_ST_ESTABLISHED:
			g_assert_not_reached();
			break;
		case RUDP_ST_ALLOCED:
			break;
		}
		errno = ENOTCONN;
		return -1;
	}

	size = MIN(size, (size_t) INT_MAX);
	p = data;

	while (size > 0) {
		uint n;
		
		n = MIN(512, size);
		if (!rudp_send_data(con, p, n)) {
			rudp_set_writable(con, FALSE);
			break;
		}
		p += n;
		size -= n;
	}

	if (p != data) {
		rudp_list_add(RUDP_LIST_PENDING, con, TRUE);
		return p - (const char *) data;
	} else {
		errno = EAGAIN;
		return -1;
	}
}

ssize_t
rudp_read(struct rudp_con *con, void *data, size_t size)
{
	ssize_t received;
	pmsg_t *mb;
	char *p;
	uint i;
	
	g_return_val_if_fail(con, -1);
	g_return_val_if_fail(data, -1);
	g_return_val_if_fail(size > 0, -1);

	size = MIN(size, (size_t) INT_MAX);
	received = 0;
	p = data;
	i = con->in.rd;
	while (NULL != (mb = con->in.buffers[i])) {
		size_t n;
		
		n = pmsg_read(mb, &p[received], size);
		size -= n;
		received += n;
		if (pmsg_size(mb) > 0) {
			/* Buffer not completely read */
			break;
		}
		pmsg_free(mb);
		con->in.buffers[i] = NULL;
		i = (i + 1) % G_N_ELEMENTS(con->in.buffers);
		con->in.seq_no++;
	}
	con->in.rd = i;

	if (received > 0) {
		return received;
	} else {
		rudp_set_readable(con, FALSE);
		switch (con->status) {
		case RUDP_ST_CLOSED:
			return 0;
		case RUDP_ST_ESTABLISHED:
			errno = EAGAIN;
			break;
		case RUDP_ST_ALLOCED:
		case RUDP_ST_SYN_SENT:
			errno = ENOTCONN;
			return -1;
		}
		return -1;
	}
}

int
rudp_close(struct rudp_con *con)
{
	g_return_val_if_fail(con, -1);

	switch (con->status) {
	case RUDP_ST_ALLOCED:
	case RUDP_ST_CLOSED:
		errno = ENOTCONN;
		return -1;
	case RUDP_ST_ESTABLISHED:
	case RUDP_ST_SYN_SENT:
		break;
	}

	rudp_send_fin(con, con->out.seq_no, RUDP_FIN_CLOSE);
	return 0;
}

host_addr_t
rudp_get_addr(struct rudp_con *con)
{
	g_return_val_if_fail(con, zero_host_addr);
	return con->addr;
}

uint16
rudp_get_port(struct rudp_con *con)
{
	g_return_val_if_fail(con, 0);
	return con->port;
}

void
rudp_set_event_handler(struct rudp_con *con,
	inputevt_cond_t cond, inputevt_handler_t handler, void *data)
{
	g_return_if_fail(con);
	g_return_if_fail(handler);
	g_return_if_fail(INPUT_EVENT_EXCEPTION != cond);
	g_return_if_fail(!(INPUT_EVENT_R & cond) ^ !(INPUT_EVENT_W & cond));

	con->event_cond = cond;
	con->event_handler = handler;
	con->event_data = data;
}

void
rudp_clear_event_handler(struct rudp_con *con)
{
	g_return_if_fail(con);

	con->event_cond = 0;
	con->event_handler = NULL;
	con->event_data = NULL;
}

static void
rudp_foreach_incoming(void *data, void *unused_udata)
{
	struct rudp_con *con = data;
	
	(void) unused_udata;

	rudp_set_incoming(con, FALSE);
	socket_rudp_accept(con);
}

static void
rudp_foreach_writable(void *data, void *unused_udata)
{
	struct rudp_con *con = data;
	
	(void) unused_udata;

	if (con->event_handler && (con->event_cond & INPUT_EVENT_W)) {
		con->event_handler(con->event_data, (-1), INPUT_EVENT_W);
	}
}

static void
rudp_foreach_readable(void *data, void *unused_udata)
{
	struct rudp_con *con = data;

	(void) unused_udata;
	
	if (con->event_handler && (con->event_cond & INPUT_EVENT_R)) {
		con->event_handler(con->event_data, (-1), INPUT_EVENT_R);
	}
}

static void
rudp_foreach_pending(void *data, void *unused_udata)
{
	struct rudp_con *con = data;
	pmsg_t *mb;

	(void) unused_udata;
	
	mb = con->out.buffers[con->out.rd];
	if (mb) {
		tm_t now;
		
		tm_now(&now);

		if (tm_elapsed_ms(&now, &con->out.last_event) > 1000) {
			rudp_send_packet(con, pmsg_read_base(mb), pmsg_size(mb));
		}
	}
}

static void
rudp_foreach_closed(void *data, void *unused_udata)
{
	struct rudp_con *con = data;

	(void) unused_udata;
	(void) con;

	/** TODO:
	 * As soon as there is no more pending data and the connection
	 * is not referenced anymore, free the resources.
	 */
}

/**
 * Hander for queued work e.g., sending queued data, dispatching received
 * messages etc.
 */
void
rudp_timer(time_t unused_now)
{
	int i;
	
	(void) unused_now;

	for (i = 0; i < RUDP_NUM_LISTS; i++) {
		GFunc func = NULL;

		switch ((enum rudp_list) i) {
		case RUDP_LIST_INCOMING: 	func = rudp_foreach_incoming; break;
		case RUDP_LIST_READABLE: 	func = rudp_foreach_readable; break;
		case RUDP_LIST_WRITABLE: 	func = rudp_foreach_writable; break;
		case RUDP_LIST_PENDING:		func = rudp_foreach_pending; break;
		case RUDP_LIST_CLOSED:		func = rudp_foreach_closed; break;
		case RUDP_NUM_LISTS:		g_assert_not_reached();
		}
		hash_list_foreach(rudp_list[i], func, NULL);
	}
}

void
rudp_init(void)
{
	uint i;

	connections = hset_create_any(rudp_con_hash, NULL, rudp_con_eq);
	
	for (i = 0; i < RUDP_NUM_LISTS; i++) {
		rudp_list[i] = hash_list_new(NULL, NULL);
	}
}

void
rudp_shutdown(void)
{
	/** TODO: Free all resources on shutdown. */
}

/* vi: set ts=4 sw=4 cindent: */
