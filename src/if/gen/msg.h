/*
 * Generated on Sat Apr  5 10:43:36 2014 by enum-msg.pl -- DO NOT EDIT
 *
 * Command: ../../../scripts/enum-msg.pl msg.lst msg.dsc
 */

#ifndef _if_gen_msg_h_
#define _if_gen_msg_h_

/*
 * Enum count: 39
 */
typedef enum {
	MSG_UNKNOWN = 0,
	MSG_INIT,
	MSG_INIT_RESPONSE,
	MSG_BYE,
	MSG_QRP,
	MSG_HSEP,
	MSG_RUDP,
	MSG_VENDOR,
	MSG_STANDARD,
	MSG_PUSH_REQUEST,
	MSG_SEARCH,
	MSG_SEARCH_RESULTS,
	MSG_DHT,
	MSG_DHT_PING,
	MSG_DHT_PONG,
	MSG_DHT_STORE,
	MSG_DHT_STORE_ACK,
	MSG_DHT_FIND_NODE,
	MSG_DHT_FOUND_NODE,
	MSG_DHT_FIND_VALUE,
	MSG_DHT_VALUE,
	MSG_G2_CRAWLR,
	MSG_G2_HAW,
	MSG_G2_KHL,
	MSG_G2_KHLR,
	MSG_G2_KHLA,
	MSG_G2_LNI,
	MSG_G2_PI,
	MSG_G2_PO,
	MSG_G2_PUSH,
	MSG_G2_QKA,
	MSG_G2_QKR,
	MSG_G2_Q2,
	MSG_G2_QA,
	MSG_G2_QH2,
	MSG_G2_QHT,
	MSG_G2_UPROC,
	MSG_G2_UPROD,
	MSG_TOTAL,

	MSG_TYPE_COUNT
} msg_type_t;

const char *gnet_msg_type_description(msg_type_t x);

#endif /* _if_gen_msg_h_ */

/* vi: set ts=4 sw=4 cindent: */
