/*
 * Copyright (c) 2012, 2014 Raphael Manfredi
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
 * G2 packet framing.
 *
 * A G2 packet is represented as a tree, much alike an XML tree, hence the
 * "tree" name of its interface.
 *
 * Relevant documentation extracted from the g2.doxu.org website:
 *
 * FRAMING
 *
 * Packets are encoded with a single leading control byte, followed by one
 * or more bytes of packet length, followed by one or more bytes of packet
 * name/ID, followed by zero or more child packets (framed the same way),
 * followed by zero or more bytes of payload:
 *
 *    +---------+--------+---------+-------------------------+
 *    | Control | Length | Name    | children and/or payload |
 *    +---------+--------+---------+-------------------------+
 *
 * All packets can contain a payload only, children and a payload, children
 * only, or nothing at all. The total length of the packet header (control,
 * length and type name) cannot exceed 12 bytes and cannot be less than
 * 2 bytes.
 *
 * The Control Byte
 *
 * The control byte is always non-zero. A zero control byte identifies the
 * end of a stream of packets, and thus has special meaning. It should not
 * be used in root packet streams (which do not end). Control bytes have
 * the following format:
 *
 *    +----+----+----+----+----+----+----+----+
 *    | 7    6  | 5    4    3  | 2  | 1  | 0  | Bit
 *    +----+----+----+----+----+----+----+----+
 *    | Len_Len | Name_Len - 1 | CF | BE | // |
 *    +----+----+----+----+----+----+----+----+
 *
 *  - Len_Len is the number of bytes in the length field of the packet,
 *    which immediately follows the control byte. There are two bits here
 *    which means the length field can be up to 3 bytes long. Len_Len? can
 *    be zero if the packet has zero length (no children and no payload),
 *    in which case there is no need to encode the length.
 *
 *  - Name_Len is the number of bytes in the packet name field MINUS ONE,
 *    which follows the packet length field. There are three bits here which
 *    means that packet names can be 1 to 8 bytes long inclusive. Because a
 *    0 here equates to one byte of name, unnamed packets are not possible.
 *
 * The three least significant bits of the control byte are reserved for
 * flags. They have the following meanings:
 *
 *  - CF is the compound packet flag. If this bit is set, the packet
 *    contains one or more child packets. If not set, the packet does
 *    not contain any child packets. If the packet is of zero length,
 *    this flag is ignored.
 *
 *  - BE is the big-endian packet flag. If set, all multi-byte values
 *    encoded in the packet and its children are encoded in big-endian
 *    byte order - including the length in the packet header.
 *
 * Other bits are reserved. 
 *
 * The Length Field
 *
 * The length field immediately follows the control byte, and can be 0 to
 * 3 bytes long. Length bytes are stored in the byte order of the packet.
 *
 * The length value includes the payload of this packet AND any child
 * packets in their entirety. This is obviously needed so that the entire
 * packet can be detected and acquired from a stream. The length does not
 * include the header (control byte, length, and name). The length field
 * precedes the name field to allow it to be read faster from a stream when
 * acquiring packets.
 *
 * The length field is in the byte order of the root packet.
 *
 * The Type Name Field
 *
 * The type name field immediately follows the length bytes, and can be
 * from 1 to 8 bytes long. Its format is detailed in the previous section
 * entitled "Namespace Considerations".
 *
 * Child Packets
 *
 * Child packets are only present if the "compound packet bit" is set in
 * the control byte. If set, there is one or more child packet immediately
 * following the end of the header. These child packets are included in the
 * total length of their parent (along with the payload, which follows the
 * child packets after a packet stream terminator).
 *
 * Child packets are framed exactly the same way, with a control byte,
 * length, name, children and/or payload. When the compound bit is set
 * and the packet is not of zero length, the first child packet must
 * exist. Subsequent child packets may also exist, and are read in
 * sequentially in the same way that they are read from a root packet
 * stream. The end of the child packet stream is signalled by the presence
 * of a zero control byte, OR the end of the parent packet's length (in
 * which case there is no payload). Including a terminating zero control
 * byte when there is no payload is still valid, but unnecessary.
 *
 * Payload
 *
 * Payload may exist whenever the length field is non-zero. However, if
 * the compound bit is set, one or more child packets must be read before
 * the payload is reached. If there is no packet left after the end of the
 * last child, there is no payload.
 *
 * Notes on the Control Byte
 *
 * Note that there are a number of "marker packet types", which have no
 * children or payload. It is desirable to encode these in as small a
 * space as possible, which means omitting the length field and setting
 * the len_len bits to zero in the control byte. This creates a potential
 * conflict, as the control byte itself may be zero if the type name is one
 * byte long - and as noted above, a zero control byte has special meaning
 * (end of packet stream). This must be avoided; luckily it is perfectly
 * legal to set the compound packet flag (CF) on zero length packets, thus
 * producing a non-zero control byte and the most compact packet possible.
 *
 * The compound packet bit MUST be checked when decoding every packet. It
 * should be done in low-level decoding code to avoid accidental omission.
 * Do not assume that a packet will not have children - it might not now,
 * but no packets are sterile. Anything could be augmented or extended in
 * some unknown way in the future. If you are not interested in children,
 * skip them (which is easy, you don't even need to recurse through their
 * children).
 *
 * IMPORTANT NOTE
 *
 * As discussed with the main implementors of the G2 protocol (Shareaza, Quazaa)
 * the BE field MUST be cleared, i.e. we're only accepting little-endian field
 * encoding in packets.  Packets with big-endian encoding are simply rejected
 * as being invalid.
 *
 * @author Raphael Manfredi
 * @date 2012, 2014
 */

#include "common.h"

#include "frame.h"
#include "tree.h"

#include "lib/endian.h"
#include "lib/halloc.h"
#include "lib/unsigned.h"

#include "lib/override.h"		/* Must be the last header included */

#define G2_BYTELEN(ctrl)		(((ctrl) & 0xc0) >> 6)
#define G2_NAMELEN(ctrl)		((((ctrl) & 0x38) >> 3) + 1)

/**
 * Deserialization context.
 */
struct frame_dctx {
	const void *p;				/* Reading pointer */
	const void *end;			/* End of reading buffer */
	unsigned copy:1;			/* Whether to copy payload data */
};

/**
 * Read a single byte from the deserialization buffer.
 *
 * @param dctx		the deserialization context
 * @param value		where the read byte is stored
 *
 * @return TRUE if OK.
 */
static bool
g2_frame_read_byte(struct frame_dctx *dctx, uint8 *value)
{
	if G_UNLIKELY(dctx->end == dctx->p)
		return FALSE;

	*value = *(uint8 *) dctx->p;
	dctx->p = const_ptr_add_offset(dctx->p, 1);
	return TRUE;
}

/**
 * Decode length from the deserialization buffer, using the specified
 * amount of bytes.
 *
 * Length is expected to be in little-endian format.
 *
 * @param dctx		the deserialization context
 * @param bytes		how many bytes should we read to get the length (3 max)
 * @param length	where the read length is stored
 *
 * @return TRUE if OK.
 */
static bool
g2_frame_read_length(struct frame_dctx *dctx, size_t bytes, size_t *length)
{
	const void *end;
	size_t len, shift;
	const uint8 *p;

	g_assert(size_is_positive(bytes));
	g_assert(bytes <= 3);

	end = const_ptr_add_offset(dctx->p, bytes);

	if G_UNLIKELY(ptr_cmp(dctx->end, end) < 0)
		return FALSE;

	len = 0;
	shift = 0;
	p = dctx->p;

	while (bytes--) {
		len += *p++ << shift;
		shift += 8;
	}

	dctx->p = end;
	*length = len;
	return TRUE;
}

/**
 * Read specified amount of bytes into destination buffer.
 *
 * @param dctx		the deserialization context
 * @param dst		the detination buffer (must be large enough)
 * @param len		how many bytes to read
 *
 * @return TRUE if OK.
 */
static bool
g2_frame_read_data(struct frame_dctx *dctx, void *dst, size_t len)
{
	const void *end;

	end = const_ptr_add_offset(dctx->p, len);

	g_assert(dst != NULL);
	g_assert(size_is_positive(len));

	if G_UNLIKELY(ptr_cmp(dctx->end, end) < 0)
		return FALSE;

	memcpy(dst, dctx->p, len);
	dctx->p = end;
	return TRUE;
}

/**
 * Recursively deserialize the G2 packet.
 *
 * @return NULL if an error occurred, the deserialized tree otherwise.
 */
static g2_tree_t *
g2_frame_recursive_deserialize(struct frame_dctx *dctx)
{
	uint8 control;
	char name[G2_FRAME_NAME_LEN_MAX + 1];
	size_t length, bytelen, namelen, remain, paylen;
	g2_tree_t *node;
	const void *start;

	/*
	 * Decode the header: control byte, length, name.
	 */

	if (!g2_frame_read_byte(dctx, &control))
		return NULL;

	if (control & G2_FRAME_BE)
		return NULL;				/* Only handle little-endian packets */

	if (0 == control)
		return NULL;				/* End of stream */

	bytelen = G2_BYTELEN(control);
	namelen = G2_NAMELEN(control);

	if (0 != bytelen) {
		if (!g2_frame_read_length(dctx, bytelen, &length))
			return NULL;
	} else {
		length = 0;
	}

	if (!g2_frame_read_data(dctx, name, namelen))
		return NULL;

	name[namelen] = '\0';
	start = dctx->p;				/* First byte after header */

	/*
	 * Make sure the whole packet fits into what we were given to deserialize.
	 */

	remain = ptr_diff(dctx->end, dctx->p);
	if (remain < length)
		return NULL;

	/*
	 * OK, create the node.  We don't know whether there will be a payload yet.
	 */

	node = g2_tree_alloc_empty(name);

	/*
	 * If it is a compound packet, deserialize its children.
	 */

	if (length != 0 && (control & G2_FRAME_CF)) {
		struct frame_dctx childctx;
		size_t children = 0;

		childctx.p = dctx->p;
		childctx.end = const_ptr_add_offset(dctx->p, length);
		childctx.copy = dctx->copy;

		while (ptr_cmp(childctx.p, childctx.end) < 0) {
			const uint8 *cptr = childctx.p;		/* Control byte location */
			g2_tree_t *child;

			if (0 == *cptr) {		/* End of child straem */
				childctx.p++;
				break;
			}

			children++;

			child = g2_frame_recursive_deserialize(&childctx);
			if (NULL == child)
				goto failure;

			g2_tree_add_child(node, child);
		}

		if (0 == children)
			goto failure;

		dctx->p = childctx.p;
	}

	/*
	 * Read the payload, if any.
	 */

	paylen = length - ptr_diff(dctx->p, start);

	if (!size_is_non_negative(paylen))
		goto failure;				/* Length was bad, we got garbage */

	g_assert(ptr_cmp(const_ptr_add_offset(dctx->p, paylen), dctx->end) <= 0);

	if (0 != paylen) {
		g2_tree_set_payload(node, dctx->p, paylen, dctx->copy);
		dctx->p = const_ptr_add_offset(dctx->p, paylen);
	}

	g_assert(ptr_cmp(dctx->p, dctx->end) <= 0);

	return node;

failure:
	g2_tree_free_null(&node);
	return NULL;
}

/**
 * Probe the leading of the supplied buffer to know how long the G2 packet
 * is in the serialized form.
 *
 * This can be used to determine whether we got the whole packet: if the
 * returned value is not the amount given in "len", then the message is
 * invalid / truncated.
 *
 * @param buf			start of buffer where packet lies
 * @param len			amount of data held in the buffer
 *
 * @return the total expected length of the message (including header), 0 if
 * the message header cannot be parsed correctly.
 */
size_t
g2_frame_whole_length(const void *buf, size_t len)
{
	struct frame_dctx dctx;
	uint8 control;
	size_t length, bytelen, namelen;

	g_assert(buf != NULL);
	g_assert(size_is_positive(len));

	dctx.p = buf;
	dctx.end = const_ptr_add_offset(buf, len);
	dctx.copy = FALSE;

	/*
	 * Decode the header: control byte, length, name.
	 */

	if (!g2_frame_read_byte(&dctx, &control))
		return 0;

	if (control & G2_FRAME_BE)
		return 0;					/* Only handle little-endian packets */

	if (0 == control)
		return 1;					/* End of stream */

	bytelen = G2_BYTELEN(control);
	namelen = G2_NAMELEN(control);

	if (0 != bytelen) {
		if (!g2_frame_read_length(&dctx, bytelen, &length))
			return 0;
	} else {
		length = 0;
	}

	return 1 + bytelen + namelen + length;	/* Total expected size */
}

/**
 * Get the name of the root packet.
 *
 * @param buf			start of buffer where packet lies
 * @param len			amount of data held in the buffer
 * @param nlen			if non-NULL, where length of name is returned
 *
 * @return the start of the name in the packet (non-NUL terminated string,
 * so use namelen), or NULL if the packet is too short to hold the whole
 * name.
 */
const char *
g2_frame_name(const void *buf, size_t len, size_t *nlen)
{
	struct frame_dctx dctx;
	uint8 control;
	size_t bytelen, namelen;
	const char *name;
	const void *end;

	g_assert(buf != NULL);
	g_assert(size_is_positive(len));

	dctx.p = buf;
	dctx.end = const_ptr_add_offset(buf, len);
	dctx.copy = FALSE;

	/*
	 * Decode the header: control byte, length, name.
	 */

	if (!g2_frame_read_byte(&dctx, &control))
		return NULL;

	if (0 == control)
		return NULL;				/* End of stream */

	bytelen = G2_BYTELEN(control);
	namelen = G2_NAMELEN(control);

	/*
	 * Name is right after the control byte plus the length.
	 */

	name = const_ptr_add_offset(buf, bytelen + 1);
	end = const_ptr_add_offset(name, namelen);

	if (ptr_diff(end, buf) < len)
		return NULL;				/* Packet is too short to hold name */

	if (nlen != NULL)
		*nlen = namelen;

	return name;
}

/**
 * Deserialize the first G2 packet held in the supplied buffer.
 *
 * Payload data is NOT copied but points directly into the input buffer.
 *
 * @param buf			start of buffer where packet lies
 * @param len			amount of data held in the buffer
 * @param packet_len	if non-NULL, set with the amount of data consumed
 * @param copy			if TRUE, payload is copied, otherwise it refers input
 *
 * @return a newly created G2 tree if data was valid, NULL if packet
 * was malformed or incompletely held in the buffer.
 */
g2_tree_t *
g2_frame_deserialize(const void *buf, size_t len, size_t *packet_len, bool copy)
{
	struct frame_dctx dctx;
	g2_tree_t *t;

	g_assert(buf != NULL);
	g_assert(size_is_positive(len));

	dctx.p = buf;
	dctx.end = const_ptr_add_offset(buf, len);
	dctx.copy = booleanize(copy);

	t = g2_frame_recursive_deserialize(&dctx);

	if (packet_len != NULL)
		*packet_len = ptr_diff(dctx.p, buf);

	return t;
}

/**
 * Serialization context.
 */
struct frame_sctx {
	void *p;			/* Pointer to next byte we can write to */
	const void *end;	/* End of buffer (first invalid byte) */
	size_t len;			/* Amount serialized so far */
	unsigned full:1;	/* When set, buffer was too small */
};

/**
 * Write a single byte into the serialization buffer, if there is room for it.
 *
 * @param sctx		the serialization context
 * @param value		the byte to write
 */
static void
g2_frame_write_byte(struct frame_sctx *sctx, uint8 value)
{
	sctx->len++;		/* Regardless of whether byte is written */

	if G_UNLIKELY(sctx->full)
		return;

	if G_UNLIKELY(sctx->end == sctx->p) {
		sctx->full = TRUE;
		return;
	}

	*(uint8 *) sctx->p = value;
	sctx->p = ptr_add_offset(sctx->p, 1);
}

/**
 * Copy data into serialization buffer, if there is room for it.
 *
 * @param sctx		the serialization context
 * @param src		the start of the buffer to copy from
 * @param len		the amount of bytes to copy from buffer
 */
static void
g2_frame_write_data(struct frame_sctx *sctx, const void *src, size_t len)
{
	void *end;

	g_assert(src != NULL);
	g_assert(size_is_non_negative(len));

	sctx->len += len;		/* Regardless of whether there is room for it */

	if G_UNLIKELY(sctx->full)
		return;

	end = ptr_add_offset(sctx->p, len);

	if G_UNLIKELY(ptr_cmp(sctx->end, end) < 0) {
		sctx->full = TRUE;
		return;
	}

	memcpy(sctx->p, src, len);
	sctx->p = end;
}

/**
 * Recursively serialize the tree.
 *
 * @param sctx		the serialization context
 * @param root		the G2 tree to serialize
 */
static void
g2_frame_recursive_serialize(struct frame_sctx *sctx, const g2_tree_t *root)
{
	size_t orig_len = sctx->len;
	void *start = sctx->p;
	const void *payload;
	size_t paylen, namelen;
	const g2_tree_t *child;
	const char *name;
	uint8 control;
	bool is_empty, has_children;

	payload = g2_tree_node_payload(root, &paylen);
	child = g2_tree_first_child(root);
	name = g2_tree_name(root);
	namelen = strlen(name);

	g_assert(size_is_non_negative(namelen));
	g_assert(namelen != 0);
	g_assert_log(namelen <= G2_FRAME_NAME_LEN_MAX,
		"%s(): node name too long (%zu bytes): \"%.*s\"%s",
		G_STRFUNC, namelen, (int) MIN(namelen, 20), name,
		namelen > 20 ? " (truncated)" : "");

	control = (namelen - 1) << 3;
	control |= (child != NULL) ? G2_FRAME_CF : 0;

	/*
	 * If packet has no payload and no children, we don't have to emit any
	 * length but we must set the CF flag in the leading control byte if that
	 * would end-up being zero.
	 *
	 * Otherwise, assume 1 byte will be enough to store the packet length.
	 * If not, we'll go back to the header, fix the control byte and move the
	 * following data around so we can store the actual length.
	 */

	if (0 == paylen && 0 == control) {
		control |= G2_FRAME_CF;
		is_empty = TRUE;
	} else {
		control |= (1 << 6);
		is_empty = FALSE;
	}

	/*
	 * Emit header: the control byte, the length (if not empty), and the name.
	 */

	g2_frame_write_byte(sctx, control);
	if (!is_empty)
		g2_frame_write_byte(sctx, 0);		/* The length, fixed up later */
	g2_frame_write_data(sctx, name, namelen);

	/*
	 * Now recurse to emit all the chidren, if any.
	 */

	has_children = child != NULL;

	while (child != NULL) {
		g2_frame_recursive_serialize(sctx, child);
		child = g2_tree_next_sibling(child);
	}

	if (has_children && paylen != 0)
		g2_frame_write_byte(sctx, 0);		/* End of child stream */

	/*
	 * Emit the payload, if any.
	 */

	if (paylen != 0)
		g2_frame_write_data(sctx, payload, paylen);

	/*
	 * Now fixup the packet length, if necessary.
	 *
	 * Most of the time the length will fit in one byte, and we reserved
	 * one byte above, so we just need to go back and write the length
	 * in the byte following the control byte.
	 *
	 * If it does not fit, we have to compute how many bytes are necessary,
	 * then fix the control byte accordingly and then move the data around
	 * so that we have room to write the correct length.
	 */

	if (!is_empty) {
		size_t length = sctx->len - orig_len;
		uint8 *lptr = ptr_add_offset(start, 1);	/* Follows control byte */

		length -= 2;		/* 2 = control + length byte we reserved */
		length -= namelen;	/* Length does not include the header */

		g_assert(sctx->full || ptr_cmp(lptr, sctx->end) < 0);
		g_assert(size_is_positive(length));		/* Since it's not empty */
		g_assert(length < 256 * 256 * 256);		/* 3 bytes max for length */

		if G_LIKELY(length < 256) {
			if (!sctx->full)
				*lptr = length;			/* Length fits in reserved byte */
		} else {
			uint8 bytlen = (length < 65536) ? 2 : 3;
			char lbuf[4];
			void *end;

			poke_le32(lbuf, length);			/* Encode length */

			/*
			 * Check that we can extend the serialized content by the required
			 * amount of bytes to store the length.  Recall that we already
			 * reserved one byte for it, so we need only "bytlen - 1" extra
			 * bytes in the serialization buffer, and the name of the packet
			 * was written 2 bytes after the start (control byte, length byte).
			 */

			end = ptr_add_offset(sctx->p, bytlen - 1);
			sctx->len += bytlen - 1;

			if (ptr_cmp(end, sctx->end) >= 0) {
				sctx->full = TRUE;
			} else if (!sctx->full) {
				void *namestart = ptr_add_offset(start, 2);
				size_t amount = ptr_diff(sctx->p, namestart);
				void *newname = ptr_add_offset(namestart, bytlen - 1);
				uint8 *cptr = start;

				memmove(newname, namestart, amount);	/* Make room */
				memcpy(lptr, lbuf, bytlen);				/* Actual length */
				*cptr = (*cptr & 0x3f) | (bytlen << 6);	/* Fix control byte */
				sctx->p = end;
			}
		}
	}
}

/**
 * Serialize a G2 packet into the supplied buffer.
 *
 * @param root		the G2 tree to serialize
 * @param dest		destination buffer
 * @param len		length of destination buffer, in bytes
 *
 * @return the amount of bytes occupied by the serialized buffer.
 *
 * @attention
 * The length returned is the total space required to serialize the message.
 * If it is larger than the supplied buffer, then the data were incompletely
 * serialized.  Pre-computing the necessary length can be achieved by passing
 * a NULL destination buffer with a length of zero.
 */
size_t
g2_frame_serialize(const g2_tree_t *root, void *dest, size_t len)
{
	struct frame_sctx sctx;

	g_assert(g2_tree_is_valid(root));
	g_assert(NULL != dest || 0 == len);
	g_assert(size_is_non_negative(len));

	sctx.p = dest;
	sctx.end = ptr_add_offset(dest, len);
	sctx.len = 0;
	sctx.full = booleanize(0 == len);

	g2_frame_recursive_serialize(&sctx, root);

	return sctx.len;
}

/* vi: set ts=4 sw=4 cindent: */
