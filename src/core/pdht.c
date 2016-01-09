/*
 * Copyright (c) 2009, Raphael Manfredi
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
 * Gnutella DHT "publish" interface.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#include "common.h"

#include "pdht.h"
#include "gdht.h"
#include "share.h"
#include "ggep.h"
#include "ggep_type.h"
#include "sockets.h"			/* For socket_listen_port() */
#include "tls_common.h"			/* For tls_enabled() */
#include "nodes.h"				/* For node_push_proxies() */
#include "ipp_cache.h"			/* For tls_cache_lookup() */
#include "settings.h"			/* For listen_addr() */
#include "publisher.h"
#include "gnet_stats.h"

#include "if/dht/kademlia.h"
#include "if/dht/lookup.h"
#include "if/dht/knode.h"
#include "if/dht/value.h"
#include "if/dht/publish.h"
#include "if/dht/stable.h"
#include "if/dht/dht.h"
#include "if/core/fileinfo.h"

#include "if/gnet_property_priv.h"

#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/hikset.h"
#include "lib/misc.h"
#include "lib/nid.h"
#include "lib/plist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define PDHT_ALOC_MAJOR		0	/**< We generate v0.1 "ALOC" values */
#define PDHT_ALOC_MINOR		1

#define PDHT_PROX_MAJOR		0	/**< We generate v0.0 "PROX" values */
#define PDHT_PROX_MINOR		0

#define PDHT_NOPE_MAJOR		0	/**< We generate v0.0 "NOPE" values */
#define PDHT_NOPE_MINOR		0

#define PDHT_BG_PERIOD		60000	/**< 1 minute, in ms */
#define PDHT_BG_MAX_RUNS	3		/**< Max amount of background attempts */
#define PDHT_PROX_DELAY		30		/**< Initial delay before publishing PROX */
#define PDHT_MAX_PROXIES	8		/**< Send out 8 push-proxies at most */
#define PDHT_PROX_RETRY		60		/**< Every minute if we have to */

/**
 * Hash table holding all the pending file publishes by SHA1.
 */
static hikset_t *aloc_publishes;	/* SHA1 -> pdht_publish_t */

/**
 * Hash table holding all the pending push-entry publishing by GUID.
 */
static hikset_t *nope_publishes;	/* GUID -> pdht_publish_t */

typedef enum { PDHT_PUBLISH_MAGIC = 0x680182c5U } pdht_magic_t;

typedef enum {
	PDHT_T_ALOC = 0,			/**< ALOC value: shared files */
	PDHT_T_PROX,				/**< PROX value: push-proxies */
	PDHT_T_NOPE,				/**< NOPE value: node push-entry */

	PDHT_T_MAX					/**< Amount of publishing types */
} pdht_type_t;

/**
 * Background context.
 *
 * Background publishing is created when a STORE request is issued and
 * there are nodes which reported non-specific error conditions that do
 * not enable us to know why the STORE attempt failed.
 */
struct pdht_bg {
	uint16 *status;				/**< Consolidated STORE statuses */
	const lookup_rs_t *rs;		/**< STORE lookup path */
	cevent_t *ev;				/**< Scheduling for background store */
	unsigned published;			/**< Consolidated amount of publishes */
	unsigned candidates;			/**< Initial amount of STORE roots */
	int delay;					/**< Background delay used last iteration */
	int runs;					/**< Completed background runs */
};

/**
 * Publishing context.
 */
typedef struct pdht_publish {
	pdht_magic_t magic;
	pdht_type_t type;
	pdht_cb_t cb;				/**< Callback to invoke when finished */
	void *arg;					/**< Callback argument */
	const kuid_t *id;			/**< Publishing key (atom) */
	publish_t *pb;				/**< The publishing request */
	dht_value_t *value;			/**< The value being published */
	struct pdht_bg *bg;			/**< For backgrounded STORE requests */
	union {
		struct pdht_aloc {			/**< Context for ALOC publishing */
			const sha1_t *sha1;		/**< SHA1 of the file being published */
			shared_file_t *sf;		/**< Published file entry, for logs */
		} aloc;
		struct pdht_nope {			/**< Context for NOPE publishing */
			const guid_t *guid;		/**< GUID of servent */
			struct nid *nid;		/**< ID of node for which we're a proxy */
		} nope;
	} u;
	uint32 flags;				/**< Operating flags */
} pdht_publish_t;

static inline void
pdht_publish_check(const pdht_publish_t *pp)
{
	g_assert(pp != NULL);
	g_assert(PDHT_PUBLISH_MAGIC == pp->magic);
}

/**
 * Operating flags for publishing context.
 */
#define PDHT_F_CANCELLING	(1U << 0)	/**< Explicitly cancelling */
#define PDHT_F_BACKGROUND	(1U << 1)	/**< Background publishing */
#define PDHT_F_DEAD			(1U << 2)	/**< Dead, to be freed ASAP */
#define PDHT_F_LOOKUP_DONE	(1U << 3)	/**< Lookup phase completed */

/**
 * Context for PROX value publishing.
 *
 * Contrary to ALOC publishing, a servent only needs to publish one PROX
 * value only: the one giving its known push-proxies.
 *
 * Whether or not the servent is TCP-firewalled, we do publish push-proxies.
 * When not firewalled, we include the servent itself as its own push-proxy.
 */
static struct {
	gnet_host_t proxies[PDHT_MAX_PROXIES];	/**< Known push proxies */
	size_t proxies_count;		/**< Amount of valid entries in proxies[] */
	pdht_publish_t *pp;			/**< Current running publish, NULL if none */
	cevent_t *publish_ev;		/**< Scheduled (re)publish event */
	time_t last_enqueued;		/**< When republish event was fired */
	time_t last_publish;		/**< Time at which last publish completed */
	time_t last_delayed;		/**< When republish event was set */
	bool backgrounded;			/**< Whether background republish runs */
} pdht_proxy;

static void pdht_bg_publish(cqueue_t *cq, void *obj);

/**
 * English version of the publish type.
 */
static const char *
pdht_type_to_string(pdht_type_t type)
{
	switch (type) {
	case PDHT_T_ALOC:	return "ALOC";
	case PDHT_T_NOPE:	return "NOPE";
	case PDHT_T_PROX:	return "PROX";
	case PDHT_T_MAX:	break;
	}

	return "UNKNOWN";
}

/**
 * Allocate a publishing context.
 */
static pdht_publish_t *
pdht_publish_allocate(pdht_type_t type, pdht_cb_t cb, void *arg)
{
	pdht_publish_t *pp;

	WALLOC0(pp);
	pp->magic = PDHT_PUBLISH_MAGIC;
	pp->type = type;
	pp->cb = cb;
	pp->arg = arg;

	return pp;
}

/**
 * Allocate a background publishing context.
 */
static struct pdht_bg *
pdht_bg_alloc(const lookup_rs_t *rs, const uint16 *status,
	unsigned published, unsigned candidates)
{
	struct pdht_bg *pbg;

	WALLOC0(pbg);
	pbg->rs = lookup_result_refcnt_inc(rs);
	pbg->published = published;
	pbg->candidates = candidates;
	pbg->status = wcopy(status,
		lookup_result_path_length(rs) * sizeof *pbg->status);

	return pbg;
}

/**
 * Free background publishing context and nullify pointer.
 */
static void
pdht_bg_free_null(struct pdht_bg **pbg_ptr)
{
	struct pdht_bg *pbg = *pbg_ptr;

	if (pbg != NULL) {
		cq_cancel(&pbg->ev);
		WFREE_NULL(pbg->status,
			lookup_result_path_length(pbg->rs) * sizeof *pbg->status);
		lookup_result_free(pbg->rs);
		WFREE(pbg);
		*pbg_ptr = NULL;
	}
}

/**
 * Free publishing context.
 */
static void
pdht_free_publish(pdht_publish_t *pp, bool do_remove)
{
	pdht_publish_check(pp);

	if (pp->pb != NULL) {
		publish_cancel(pp->pb, FALSE);
		pp->pb = NULL;
	}

	if (pp->value != NULL) {
		dht_value_free(pp->value, TRUE);
		pp->value = NULL;
	}

	pdht_bg_free_null(&pp->bg);

	switch (pp->type) {
	case PDHT_T_ALOC:
		if (do_remove)
			hikset_remove(aloc_publishes, pp->u.aloc.sha1);
		atom_sha1_free_null(&pp->u.aloc.sha1);
		shared_file_unref(&pp->u.aloc.sf);
		break;
	case PDHT_T_NOPE:
		if (do_remove)
			hikset_remove(nope_publishes, pp->u.nope.guid);
		if (pp->u.nope.nid != NULL) {
			nid_unref(pp->u.nope.nid);
			pp->u.nope.nid = NULL;
		}
		atom_guid_free_null(&pp->u.nope.guid);
		break;
	case PDHT_T_PROX:
		if (do_remove)
			pdht_proxy.pp = NULL;
		break;
	case PDHT_T_MAX:
		g_assert_not_reached();
	}

	/*
	 * Do not free up the object until the lookup has been completed.
	 *
	 * There is no way for us to cancel the enqueued node lookup, so we
	 * need to leave it happen, at which time the callback for the node
	 * lookup will notice the object is dead and will call us back to
	 * finalize the cleanup.
	 *
	 * NB: we always free the object when ``do_remove'' is FALSE because
	 * we are called thusly either at final shutdown time or when the
	 * object was alraedy marked as "dead" and we're called from the node
	 * lookup callbacks.
	 */

	if (!do_remove || (pp->flags & PDHT_F_LOOKUP_DONE)) {
		kuid_atom_free(pp->id);
		pp->magic = 0;
		WFREE(pp);
	} else {
		pp->flags |= PDHT_F_DEAD;		/* For lookup callbacks */
	}
}

static const char *pdht_errstr[] = {
	"OK",									/**< PDHT_E_OK */
	"Value is popular",						/**< PDHT_E_POPULAR */
	"Error during node lookup",				/**< PDHT_E_LOOKUP */
	"Node lookup expired",					/**< PDHT_E_LOOKUP_EXPIRED */
	"SHA1 of shared file not available",	/**< PDHT_E_SHA1 */
	"Value publishing still pending",		/**< PDHT_E_PENDING */
	"File no longer shared",				/**< PDHT_E_NOT_SHARED */
	"Could not build GGEP DHT value",		/**< PDHT_E_GGEP */
	"Got no acknowledgement at all",		/**< PDHT_E_NONE */
	"Cancelled",							/**< PDHT_E_CANCELLED */
	"UDP queue clogged",					/**< PDHT_E_UDP_CLOGGED */
	"Publish expired",						/**< PDHT_E_PUBLISH_EXPIRED */
	"Publish error",						/**< PDHT_E_PUBLISH_ERROR */
};

/**
 * English representation of an error code.
 */
const char *
pdht_strerror(pdht_error_t code)
{
	STATIC_ASSERT(G_N_ELEMENTS(pdht_errstr) == PDHT_E_MAX);

	if (UNSIGNED(code) >= G_N_ELEMENTS(pdht_errstr))
		return "invalid PDHT error code";

	return pdht_errstr[code];
}

/**
 * Report publishing error.
 */
static void
pdht_publish_error(pdht_publish_t *pp, pdht_error_t code)
{
	pdht_info_t pinfo;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT aborting %s publish for %s: %s",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pdht_strerror(code));
	}

	pinfo.roots = 0;
	pinfo.all_roots = 0;
	pinfo.path_len = 0;
	pinfo.can_bg = FALSE;
	pinfo.was_bg = pp->bg != NULL;
	pinfo.presence = 0.0;

	(*pp->cb)(pp->arg, code, &pinfo);
	pdht_free_publish(pp, pp->id != NULL);
}

/**
 * Callback when publish_value() is done.
 */
static void
pdht_publish_done(void *arg,
	publish_error_t code, const publish_info_t *info)
{
	pdht_publish_t *pp = arg;
	pdht_error_t status = PDHT_E_OK;		/* Shut compiler warning up */
	unsigned published = info->published;
	unsigned candidates = info->candidates;
	bool can_bg = TRUE;
	pdht_info_t pinfo;

	pdht_publish_check(pp);

	pp->pb = NULL;

	switch (code) {
	case PUBLISH_E_OK:			status = PDHT_E_OK; break;
	case PUBLISH_E_CANCELLED:	status = PDHT_E_CANCELLED; break;
	case PUBLISH_E_UDP_CLOGGED:	status = PDHT_E_UDP_CLOGGED; break;
	case PUBLISH_E_EXPIRED:		status = PDHT_E_PUBLISH_EXPIRED; break;
	case PUBLISH_E_POPULAR:		status = PDHT_E_POPULAR; break;
	case PUBLISH_E_NONE:		status = PDHT_E_NONE; break;
	case PUBLISH_E_ERROR:
	case PUBLISH_E_MAX:
		status = PDHT_E_PUBLISH_ERROR;
		break;
	}

	/*
	 * If after our max background publishing attempts we did not manage
	 * to store the data to any of the nodes, and provided we had KDA_K
	 * candidates at the beginning and more than KDA_K/2 candidates in our last
	 * run, it is safe to assume that the file is popular enough and that
	 * the real cause for getting generic errors is that the key is full in
	 * all the k-closest nodes.
	 */

	if (
		PUBLISH_E_OK == code &&
		pp->bg != NULL && pp->bg->runs >= PDHT_BG_MAX_RUNS
	) {
		unsigned roots = pp->bg->candidates;	/* Initial amount of roots */
		if (
			KDA_K == roots && info->candidates >= KDA_K/2 &&
			0 == info->published
		) {
			if (GNET_PROPERTY(publisher_debug) > 1) {
				g_debug("PDHT assuming %s %s is a popular key",
					pdht_type_to_string(pp->type), kuid_to_string(pp->id));
			}
			status = PDHT_E_POPULAR;
		}
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT ending %s%s publish for %s (%u publish%s): %s",
			(pp->flags & PDHT_F_BACKGROUND) ? "background " : "",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			info->published, plural_es(info->published),
			publish_strerror(code));
	}

	/*
	 * Consolidate the total amount of nodes to which publishing was done.
	 */

	if (pp->bg != NULL) {
		published += pp->bg->published;
		pp->bg->published = published;
		candidates = pp->bg->candidates;	/* Initial amount of STORE roots */
	}

	/*
	 * If the publishing layer published to all the candidate roots it could
	 * find, then there's no need continuing to background STORES.
	 */

	if (info->published >= info->candidates) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_debug("PDHT no more nodes to background publish %s for %s",
				pdht_type_to_string(pp->type), kuid_to_string(pp->id));
		}
		can_bg = FALSE;		/* Published to all available k-closest roots */
	} else if (pp->bg != NULL && pp->bg->runs >= PDHT_BG_MAX_RUNS) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_debug("PDHT reached max background %s publish attempts for %s",
				pdht_type_to_string(pp->type), kuid_to_string(pp->id));
		}
		can_bg = FALSE;		/* Reached max amount of retries */
	}

	/*
	 * If the upper layer accepts the publishing, then we're done.
	 */

	pinfo.roots = info->published;
	pinfo.all_roots = published;
	pinfo.path_len = candidates;
	pinfo.can_bg = can_bg;
	pinfo.was_bg = pp->bg != NULL;
	pinfo.presence = stable_store_presence(
		DHT_VALUE_REPUBLISH, info->rs, info->status);

	if ((*pp->cb)(pp->arg, status, &pinfo)) {
		if (pp->flags & PDHT_F_CANCELLING)
			return;
		goto terminate;
	}

	/*
	 * Upper layer wants us to continue publishing in the background,
	 * calling back after each subsequent iteration to report on progress.
	 *
	 * The background attempt is delayed for a while, and each time we
	 * actually schedule it in the future, we double the period.
	 */

	if (!can_bg)
		goto terminate;		/* Cannot continue background STORE */

	if (pp->bg != NULL) {
		g_assert(pp->bg->runs < PDHT_BG_MAX_RUNS);	/* Checked above */
		pp->bg->delay *= 2;
		memcpy(pp->bg->status, info->status,
			lookup_result_path_length(info->rs) * sizeof *info->status);
	} else {
		pp->flags |= PDHT_F_BACKGROUND;
		pp->bg = pdht_bg_alloc(info->rs, info->status,
			published, info->candidates);
		pp->bg->delay = PDHT_BG_PERIOD;
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT will start background %s publish for %s in %d secs",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pp->bg->delay / 1000);
	}

	pp->bg->ev = cq_main_insert(pp->bg->delay, pdht_bg_publish, pp);
	return;

terminate:
	pdht_free_publish(pp, TRUE);
}

/**
 * Callout queue callback to launch a background publish.
 */
static void
pdht_bg_publish(cqueue_t *cq, void *obj)
{
	pdht_publish_t *pp = obj;

	pdht_publish_check(pp);
	g_assert(pp->bg != NULL);
	g_assert(NULL == pp->pb);

	cq_zero(cq, &pp->bg->ev);
	pp->bg->runs++;

	/*
	 * If the DHT was disabled dynamically, abort the publishing.
	 */

	if G_UNLIKELY(!dht_enabled()) {
		pdht_free_publish(pp, TRUE);
		return;
	}

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT starting background %s publish for %s (run #%d)",
			pdht_type_to_string(pp->type), kuid_to_string(pp->id),
			pp->bg->runs);
	}

	switch (pp->type) {
	case PDHT_T_ALOC:
	case PDHT_T_NOPE:
	case PDHT_T_PROX:
		pp->pb = publish_value_background(dht_value_clone(pp->value),
			pp->bg->rs, pp->bg->status, pdht_publish_done, pp);
		break;
	case PDHT_T_MAX:
		g_assert_not_reached();
	}
}

/**
 * Generate a DHT "ALOC" value to publish the shared file.
 *
 * @return NULL if problems during GGEP encoding, the DHT value otherwise.
 */
static dht_value_t *
pdht_get_aloc(const shared_file_t *sf, const kuid_t *key)
{
	void *value;
	ggep_stream_t gs;
	int ggep_len;
	bool ok;
	const struct tth *tth;
	dht_value_t *aloc;
	knode_t *our_knode;

	/*
	 * An ALOC value bears the following GGEP keys:
	 *
	 * client-id		the servent's GUID as raw 16 bytes
	 * firewalled		1 byte boolean: whether we are TCP-firewalled
	 * port				the port where file can be requested
	 * length			the length of the file, coded as in "LF"
	 * avail			length available, only set when file is partial
	 * tls				no payload, presence means TLS support
	 * ttroot			the TTH root of the file, as raw data
	 * HNAME			the host's DNS name, if known (as in query hits)
	 *
	 * For LimeWire, the first 4 keys are mandatory for ALOC v0.1.
	 * Stupidly enough for the "firewalled" key, which could have been made
	 * optional like "tls", but this is LimeWire's design choice (interns?).
	 */

	value = walloc(DHT_VALUE_MAX_LEN);
	ggep_stream_init(&gs, value, DHT_VALUE_MAX_LEN);
	
	ok = ggep_stream_pack(&gs, GGEP_NAME(client_id),
		GNET_PROPERTY(servent_guid), GUID_RAW_SIZE, 0);

	{
		uint8 fw = booleanize(GNET_PROPERTY(is_firewalled));
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(firewalled), &fw, 1, 0);
	}

	{
		char buf[sizeof(uint64)];
		int len;

		len = ggept_filesize_encode(shared_file_size(sf), buf, sizeof buf);
		g_assert(len > 0 && UNSIGNED(len) <= sizeof buf);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(length), buf, len, 0);
	}

	if (shared_file_is_partial(sf)) {
		fileinfo_t *fi = shared_file_fileinfo(sf);

		if (shared_file_size(sf) != fi->done) {
			char buf[sizeof(uint64)];
			int len;

			len = ggept_filesize_encode(fi->done, buf, sizeof buf);
			g_assert(len > 0 && UNSIGNED(len) <= sizeof buf);
			ok = ok && ggep_stream_pack(&gs, GGEP_NAME(avail), buf, len, 0);
		}
	}

	{
		char buf[sizeof(uint16)];
		uint16 port = socket_listen_port();

		poke_be16(buf, port);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(port), buf, sizeof buf, 0);
	}

	if (tls_enabled()) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(tls), NULL, 0, 0);
	}

	tth = shared_file_tth(sf);
	if (tth != NULL) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(ttroot),
			tth->data, sizeof tth->data, 0);
	}

	if (
		!GNET_PROPERTY(is_firewalled) &&
		GNET_PROPERTY(give_server_hostname) &&
		!is_null_or_empty(GNET_PROPERTY(server_hostname))
	) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(HNAME),
			GNET_PROPERTY(server_hostname),
			strlen(GNET_PROPERTY(server_hostname)), 0);
	}

	ggep_len = ggep_stream_close(&gs);

	g_assert(ggep_len <= DHT_VALUE_MAX_LEN);

	if (!ok) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_warning("PDHT ALOC cannot construct DHT value for %s \"%s\"",
				shared_file_is_partial(sf) ? "partial" : "shared",
				shared_file_name_nfc(sf));
		}

		wfree(value, DHT_VALUE_MAX_LEN);
		return NULL;
	}

	/*
	 * DHT value becomes the owner of the walloc()-ed GGEP block.
	 */

	g_assert(ggep_len > 0);

	value = wrealloc(value, DHT_VALUE_MAX_LEN, ggep_len);
	our_knode = get_our_knode();
	aloc = dht_value_make(our_knode, key, DHT_VT_ALOC,
		PDHT_ALOC_MAJOR, PDHT_ALOC_MINOR, value, ggep_len);
	knode_refcnt_dec(our_knode);

	return aloc;
}

/**
 * Generate a DHT "PROX" value to publish our push-proxies
 *
 * @return NULL if problems during GGEP encoding, the DHT value otherwise.
 */
static dht_value_t *
pdht_get_prox(const kuid_t *key)
{
	void *value;
	ggep_stream_t gs;
	int ggep_len;
	bool ok;
	dht_value_t *prox;
	knode_t *our_knode;
	uint8 zero = 0;

	/*
	 * A PROX value bears the following GGEP keys:
	 *
	 * client-id		the servent's GUID as raw 16 bytes
	 * features			no idea what it is, use a single "0"
	 * fwt-version		a single "0" for now as we do not support it
	 * port				the servent's listening port for push-proxy messages
	 * tls				bitfield specifying which proxies support TLS
	 * proxies			an array of push-proxy IP:port
	 */

	value = walloc(DHT_VALUE_MAX_LEN);
	ggep_stream_init(&gs, value, DHT_VALUE_MAX_LEN);

	ok = ggep_stream_pack(&gs, GGEP_NAME(client_id),
		GNET_PROPERTY(servent_guid), GUID_RAW_SIZE, 0);

	/* "features" emitted as a little-endian integer with no trailing 0s */
	ok = ok &&
		ggep_stream_pack(&gs, GGEP_NAME(features), &zero, sizeof zero, 0);

	/* "fwt_version" emitted as a little-endian integer with no trailing 0s */
	ok = ok &&
		ggep_stream_pack(&gs, GGEP_NAME(fwt_version), &zero, sizeof zero, 0);

	{
		char buf[sizeof(uint16)];
		uint16 port = socket_listen_port();

		poke_be16(buf, port);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(port), buf, sizeof buf, 0);
	}

	ok = ok && pdht_proxy.proxies_count > 0;

	if (ok) {
		uchar tls_bytes[(PDHT_MAX_PROXIES + 7) / 8];
		uint tls_length;
		size_t i = 0;

		ok = ok && ggep_stream_begin(&gs, GGEP_NAME(proxies), 0);
		ZERO(&tls_bytes);
		tls_length = 0;

		while (ok && i < pdht_proxy.proxies_count) {
			const gnet_host_t *host = &pdht_proxy.proxies[i];
			host_addr_t addr = gnet_host_get_addr(host);
			uint16 port = gnet_host_get_port(host);
			char proxy[18];
			uint8 len;
			bool tls = FALSE;

			switch (host_addr_net(addr)) {
			case NET_TYPE_IPV4:
				len = 6;
				poke_be32(&proxy[0], host_addr_ipv4(addr));
				poke_be16(&proxy[4], port);
				break;
			case NET_TYPE_IPV6:
				len = 18;
				memcpy(&proxy[0], host_addr_ipv6(&addr), 16);
				poke_be16(&proxy[16], port);
				break;
			default:
				continue;
			}

			ok = ok && ggep_stream_write(&gs, &len, sizeof len);
			ok = ok && ggep_stream_write(&gs, proxy, len);

			if (
				tls_cache_lookup(addr, port) ||
				(tls_enabled() && is_my_address_and_port(addr, port))
			) {
				tls_bytes[i >> 3] |= 0x80U >> (i & 7);
				tls_length = (i >> 3) + 1;
				tls = TRUE;
			}
			i++;

			if (GNET_PROPERTY(publisher_debug) > 2) {
				g_debug("PDHT PROX #%u is %s%s", (unsigned) i,
					tls ? "tls:" : "", host_addr_port_to_string(addr, port));
			}
		}

		ok = ok && ggep_stream_end(&gs);

		if (ok && tls_length > 0) {
			ok = ggep_stream_pack(&gs, GGEP_NAME(tls),
					tls_bytes, tls_length, 0);
		}
	}

	ggep_len = ggep_stream_close(&gs);

	g_assert(ggep_len <= DHT_VALUE_MAX_LEN);

	if (!ok) {
		if (GNET_PROPERTY(publisher_debug))
			g_warning("PDHT PROX cannot construct DHT value");

		wfree(value, DHT_VALUE_MAX_LEN);
		return NULL;
	}

	/*
	 * DHT value becomes the owner of the walloc()-ed GGEP block.
	 */

	g_assert(ggep_len > 0);

	value = wrealloc(value, DHT_VALUE_MAX_LEN, ggep_len);
	our_knode = get_our_knode();
	prox = dht_value_make(our_knode, key, DHT_VT_PROX,
		PDHT_PROX_MAJOR, PDHT_PROX_MINOR, value, ggep_len);
	knode_refcnt_dec(our_knode);

	return prox;
}

/**
 * Generate a DHT "NOPE" value to publish we are a push-proxy for a node.
 *
 * @return NULL if problems during GGEP encoding, the DHT value otherwise.
 */
static dht_value_t *
pdht_get_nope(const guid_t *guid, const kuid_t *key)
{
	void *value;
	ggep_stream_t gs;
	int ggep_len;
	bool ok;
	dht_value_t *nope;
	knode_t *our_knode;

	/*
	 * A NOPE value bears the following GGEP keys:
	 *
	 * guid				the servent's GUID as raw 16 bytes
	 * port				our listening port for push-proxy messages
	 * tls				if present, indicates that we support TLS
	 */

	value = walloc(DHT_VALUE_MAX_LEN);
	ggep_stream_init(&gs, value, DHT_VALUE_MAX_LEN);

	ok = ggep_stream_pack(&gs, GGEP_NAME(guid), guid, GUID_RAW_SIZE, 0);

	{
		char buf[sizeof(uint16)];
		uint16 port = socket_listen_port();

		poke_be16(buf, port);
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(port), buf, sizeof buf, 0);
	}

	if (tls_enabled()) {
		ok = ok && ggep_stream_pack(&gs, GGEP_NAME(tls), NULL, 0, 0);
	}

	ggep_len = ggep_stream_close(&gs);

	g_assert(ggep_len <= DHT_VALUE_MAX_LEN);

	if (!ok) {
		if (GNET_PROPERTY(publisher_debug))
			g_warning("PDHT NOPE cannot construct DHT value");

		wfree(value, DHT_VALUE_MAX_LEN);
		return NULL;
	}

	/*
	 * DHT value becomes the owner of the walloc()-ed GGEP block.
	 */

	g_assert(ggep_len > 0);

	value = wrealloc(value, DHT_VALUE_MAX_LEN, ggep_len);
	our_knode = get_our_knode();
	nope = dht_value_make(our_knode, key, DHT_VT_NOPE,
		PDHT_NOPE_MAJOR, PDHT_NOPE_MINOR, value, ggep_len);
	knode_refcnt_dec(our_knode);

	return nope;
}

/**
 * Callback when lookup for STORE roots succeeded.
 */
static void
pdht_roots_found(const kuid_t *kuid, const lookup_rs_t *rs, void *arg)
{
	pdht_publish_t *pp = arg;
	dht_value_t *value = NULL;

	pdht_publish_check(pp);
	g_assert(pp->id == kuid);		/* They are atoms */

	/*
	 * Becase we cannot unqueue lookups once they have been sent to the ULQ
	 * layer, we mark the lookup as completed and check whether the object
	 * was not already marked as dead, the state where it simply waits for
	 * the lookup to be completed.
	 */

	if (pp->flags & PDHT_F_DEAD) {
		pdht_free_publish(pp, FALSE);	/* Already "removed" */
		return;
	}

	pp->flags |= PDHT_F_LOOKUP_DONE;	/* Signals: can free up object now */

	/*
	 * Step #2: generate the DHT value
	 */
	
	switch (pp->type) {
	case PDHT_T_ALOC:
		{
			struct pdht_aloc *paloc = &pp->u.aloc;
			shared_file_t *sf = paloc->sf, *sf1;

			if (GNET_PROPERTY(publisher_debug) > 1) {
				size_t roots = lookup_result_path_length(rs);
				g_debug("PDHT ALOC found %zu publish root%s for %s \"%s\"",
					roots, plural(roots),
					shared_file_is_partial(sf) ? "partial" : "shared",
					shared_file_name_nfc(sf));
			}

			/*
			 * If shared_file_by_sha1() returns SHARE_REBUILDING, we
			 * nonetheless go on with the publishing because chances are the
			 * file will still be shared anyway.  If no longer shared, it will
			 * not be requeued for publishing at the next period.
			 */

			if (NULL == (sf1 = shared_file_by_sha1(paloc->sha1))) {
				if (GNET_PROPERTY(publisher_debug)) {
					g_warning("PDHT ALOC cannot publish %s \"%s\": "
						"no longer shared",
						shared_file_is_partial(sf) ? "partial" : "shared",
						shared_file_name_nfc(sf));
				}

				pdht_publish_error(pp, PDHT_E_NOT_SHARED);
				return;
			}
			shared_file_unref(&sf1);

			value = pdht_get_aloc(sf, pp->id);
		}
		break;
	case PDHT_T_NOPE:
		if (GNET_PROPERTY(publisher_debug) > 1) {
			size_t roots = lookup_result_path_length(rs);
			g_debug("PDHT NOPE found %zu publish root%s for %s",
				roots, plural(roots), guid_hex_str(pp->u.nope.guid));
		}

		value = pdht_get_nope(pp->u.nope.guid, pp->id);
		break;
	case PDHT_T_PROX:
		if (GNET_PROPERTY(publisher_debug) > 1) {
			size_t roots = lookup_result_path_length(rs);
			g_debug("PDHT PROX found %zu publish root%s", roots, plural(roots));
		}

		value = pdht_get_prox(pp->id);
		break;
	case PDHT_T_MAX:
		g_assert_not_reached();
	}

	if (NULL == value) {
		pdht_publish_error(pp, PDHT_E_GGEP);
		return;
	}

	g_assert(kuid_eq(dht_value_key(value), pp->id));

	/*
	 * Step #3: issue the STORE on each of the k identified nodes.
	 */

	pp->value = dht_value_clone(value);
	pp->pb = publish_value(value, rs, pdht_publish_done, pp);
}

/**
 * Callback for errors during root node lookups.
 */
static void
pdht_roots_error(const kuid_t *kuid, lookup_error_t error, void *arg)
{
	pdht_publish_t *pp = arg;
	pdht_error_t status;

	pdht_publish_check(pp);
	g_assert(pp->id == kuid);		/* They are atoms */

	/*
	 * Becase we cannot unqueue lookups once they have been sent to the ULQ
	 * layer, we mark the lookup as completed and check whether the object
	 * was not already marked as dead, the state where it simply waits for
	 * the lookup to be completed.
	 */

	if (pp->flags & PDHT_F_DEAD) {
		pdht_free_publish(pp, FALSE);	/* Already "removed" */
		return;
	}

	pp->flags |= PDHT_F_LOOKUP_DONE;	/* Signals: can free up object now */

	if (GNET_PROPERTY(publisher_debug)) {
		switch (pp->type) {
		case PDHT_T_ALOC:
			{
				struct pdht_aloc *paloc = &pp->u.aloc;

				g_debug("PDHT ALOC publish roots lookup failed "
					"for %s \"%s\": %s",
					shared_file_is_partial(paloc->sf) ? "partial" : "shared",
					shared_file_name_nfc(paloc->sf), lookup_strerror(error));
			}
			break;
		case PDHT_T_NOPE:
			{
				struct pdht_nope *pnope = &pp->u.nope;

				g_debug("PDHT NOPE publish roots lookup failed "
					"for GUID %s: %s",
					guid_hex_str(pnope->guid), lookup_strerror(error));
			}
			break;
		case PDHT_T_PROX:
			g_debug("PDHT PROX publish roots lookup failed: %s",
				lookup_strerror(error));
			break;
		case PDHT_T_MAX:
			g_assert_not_reached();
		}
	}

	switch (error) {
	case LOOKUP_E_UDP_CLOGGED:		status = PDHT_E_UDP_CLOGGED; break;
	case LOOKUP_E_EXPIRED:			status = PDHT_E_PUBLISH_EXPIRED; break;
	default:						status = PDHT_E_LOOKUP; break;
	}

	pdht_publish_error(pp, status);
}

/**
 * Asynchronous error reporting context.
 */
struct pdht_async {
	pdht_publish_t *pp;
	pdht_error_t code;
};

/**
 * Callout queue callback to report error asynchronously.
 */
static void
pdht_report_async_error(struct cqueue *cq, void *udata)
{
	struct pdht_async *pa = udata;

	(void) cq;
	pdht_publish_error(pa->pp, pa->code);
	WFREE(pa);
}

/**
 * Asynchronously report error.
 */
static void
pdht_publish_error_async(pdht_publish_t *pp, pdht_error_t code)
{
	struct pdht_async *pa;

	WALLOC(pa);
	pa->pp = pp;
	pa->code = code;

	cq_main_insert(1, pdht_report_async_error, pa);
}

/**
 * Launch publishing of shared file within the DHT.
 *
 * @param sf		the shared file to publish
 * @param cb		callback to invoke when publish is completed
 * @param arg		argument to supply to callback
 */
void
pdht_publish_file(shared_file_t *sf, pdht_cb_t cb, void *arg)
{
	const char *error = NULL;
	const sha1_t *sha1;
	pdht_publish_t *pp;
	struct pdht_aloc *paloc;
	pdht_error_t code;

	g_assert(sf != NULL);

	pp = pdht_publish_allocate(PDHT_T_ALOC, cb, arg);

	paloc = &pp->u.aloc;
	paloc->sf = shared_file_ref(sf);

	if (!sha1_hash_available(sf) || !sha1_hash_is_uptodate(sf)) {
		error = "no SHA1 available";
		code = PDHT_E_SHA1;
		goto error;
	}

	sha1 = shared_file_sha1(sf);
	g_assert(sha1 != NULL);

	pp->id = gdht_kuid_from_sha1(sha1);
	paloc->sha1 = atom_sha1_get(sha1);

	if (hikset_contains(aloc_publishes, sha1)) {
		error = "previous publish still pending";
		code = PDHT_E_PENDING;
		goto error;
	}

	hikset_insert_key(aloc_publishes, &paloc->sha1);

	/*
	 * Publishing will occur in three steps:
	 *
	 * #1 locate suitable nodes for publishing the ALOC value
	 * #2 if file is still publishable, generate the DHT ALOC value
	 * #3 issue the STORE on each of the k identified nodes.
	 *
	 * Here we launch step #1.
	 */

	ulq_find_store_roots(pp->id, FALSE,
		pdht_roots_found, pdht_roots_error, pp);

	return;

error:
	if (GNET_PROPERTY(publisher_debug)) {
		g_warning("PDHT will not publish ALOC for %s \"%s\": %s",
			shared_file_is_partial(sf) ? "partial" : "shared",
			shared_file_name_nfc(sf), error);
	}

	/*
	 * Report error asynchronously, to return to caller first.
	 */

	pdht_publish_error_async(pp, code);
}

/**
 * Cancel an active publishing.
 *
 * @param pp		the publish object
 * @param callabck	whether callbacks need to be invoked
 */
static void
pdht_cancel(pdht_publish_t *pp, bool callback)
{
	pdht_publish_check(pp);

	/*
	 * By setting PDHT_F_CANCELLING we avoid the publish callback from
	 * freeing the publishing object, since we are going to do that
	 * ourselves once we return from the publish_cancel() call.
	 */

	pp->flags |= PDHT_F_CANCELLING;

	if (pp->pb != NULL) {
		publish_cancel(pp->pb, callback);
		pp->pb = NULL;
	}

	pdht_free_publish(pp, TRUE);
}

/**
 * Cancel a file publishing.
 *
 * @param sha1		the SHA1 of the file
 * @param callabck	whether callbacks need to be invoked
 */
void
pdht_cancel_file(const sha1_t *sha1, bool callback)
{
	pdht_publish_t *pp;

	if (NULL == aloc_publishes)
		return;

	pp = hikset_lookup(aloc_publishes, sha1);

	if (NULL == pp)
		return;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		shared_file_t *sf = pp->u.aloc.sf;
		g_warning("PDHT cancelling ALOC for %s \"%s\" (%s callback): %s",
			shared_file_is_partial(sf) ? "partial" : "shared",
			shared_file_name_nfc(sf),
			callback ? "with" : "no", sha1_to_string(sha1));
	}

	pdht_cancel(pp, callback);
}

/***
 *** Push-proxy publishing.
 ***/

static void pdht_prox_install_republish(time_t t);

/**
 * Cancel current PROX publishing.
 *
 * @param callabck	whether callbacks need to be invoked
 */
static void
pdht_cancel_prox(bool callback)
{
	pdht_publish_t *pp;

	pp = pdht_proxy.pp;

	if (NULL == pp)
		return;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_warning("PDHT cancelling PROX publish (%s callback)",
			callback ? "with" : "no");
	}

	pdht_proxy.backgrounded = FALSE;
	pdht_cancel(pp, callback);
}

/**
 * Publishing callback invoked when asynchronous publication is completed,
 * or ended with an error.
 *
 * @return TRUE if we accept the publishing, FALSE otherwise to get the
 * publishing layer to continue attempts to failed STORE roots and report
 * on progress using the same callback.
 */
static bool
pdht_prox_done(void *u_arg, pdht_error_t code, const pdht_info_t *info)
{
	bool accepted = TRUE;
	int delay = PDHT_PROX_RETRY;

	(void) u_arg;

	/*
	 * The logic here is similar to that of publisher_done(), although we're
	 * dealing with a single value that we want to be widely published and
	 * which cannot be popular, by construction.
	 */

	if (PDHT_E_OK == code) {
		if (pdht_proxy.last_publish && info->roots > 0) {
			time_delta_t elapsed =
				delta_time(tm_time(), pdht_proxy.last_publish);
			if (elapsed > DHT_VALUE_PROX_EXPIRE)
				gnet_stats_inc_general(GNR_DHT_REPUBLISHED_LATE);
		}

		delay = publisher_delay(info, DHT_VALUE_PROX_EXPIRE);
		accepted = publisher_is_acceptable(info);
	}

	/*
	 * For a backgrounded entry publishing, we need to adjust the computed
	 * delay with the time that was elapsed.
	 */

	if (pdht_proxy.backgrounded) {
		time_delta_t elapsed = delta_time(tm_time(), pdht_proxy.last_delayed);
		if (delay > elapsed) {
			delay -= elapsed;
		} else {
			delay = 1;
		}
	}

	cq_cancel(&pdht_proxy.publish_ev);

	/*
	 * Logging.
	 */

	if (GNET_PROPERTY(publisher_debug) > 1) {
		char retry[80];
		char after[80];
		const char *late = "";

		after[0] = '\0';
		if (pdht_proxy.last_publish) {
			time_delta_t elapsed =
				delta_time(tm_time(), pdht_proxy.last_publish);

			if (elapsed > DHT_VALUE_PROX_EXPIRE)
				late = "late, ";
		}

		str_bprintf(retry, sizeof retry, "%s", compact_time(delay));

		g_debug("PDHT PROX %s%spublished to %u node%s%s: %s"
			" (%stook %s, total %u node%s, proba %.3f%%, retry in %s,"
			" %s bg, path %u) [%s]",
			pdht_proxy.backgrounded ? "[bg] " : "",
			pdht_proxy.last_publish ? "re" : "",
			info->roots, 1 == info->roots ? "" : "s",
			after, pdht_strerror(code), late,
			compact_time(delta_time(tm_time(), pdht_proxy.last_enqueued)),
			info->all_roots, plural(info->all_roots),
			info->presence * 100.0, retry,
			info->can_bg ? "can" : "no", info->path_len,
			accepted ? "OK" : "INCOMPLETE");
	}

	/*
	 * Update last publishing time.
	 */

	if (PDHT_E_OK == code && info->roots > 0)
		pdht_proxy.last_publish = tm_time();

	pdht_prox_install_republish(delay);
	pdht_proxy.backgrounded = !accepted;

	return accepted;
}

/**
 * Build list of known push proxies in supplied vector.
 *
 * @return amount of entries filled.
 */
static size_t
pdht_prox_fill_vector(gnet_host_t *vec, size_t vecsize)
{
	sequence_t *seq = NULL;
	plist_t *list = NULL;
	gnet_host_t localhost;
	size_t i = 0;

	if (GNET_PROPERTY(is_firewalled))
		seq = node_push_proxies();

	if (NULL == seq || sequence_is_empty(seq)) {
		host_addr_t addr;
		uint16 port = socket_listen_port();

		sequence_release(&seq);

		/*
		 * List ourselves as the only push-proxy if we have a valid IP:port.
		 */

		addr = listen_addr();
		if (!is_host_addr(addr))
			addr = listen_addr6();

		if (is_host_addr(addr) && port != 0) {
			gnet_host_set(&localhost, addr, socket_listen_port());
			list = plist_prepend(list, &localhost);
			seq = sequence_create_from_plist(list);
		} else {
			return 0;		/* Nothing to fill */
		}
	}

	if (!sequence_is_empty(seq)) {
		gnet_host_t *vp = vec;
		sequence_iter_t *iter;

		/*
		 * We iterate backwards to get the most stable of our push proxies,
		 * namely those to which we've been connected for the longest time.
		 */

		iter = sequence_backward_iterator(seq, TRUE);

		while (i < vecsize && sequence_iter_has_previous(iter)) {
			const gnet_host_t *host = sequence_iter_previous(iter);

			gnet_host_copy(vp++, host);
			i++;
		}

		sequence_iterator_release(&iter);
	}

	sequence_release(&seq);
	plist_free(list);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT PROX using %zu push-prox%s for local node (%sfirewalled)",
			i, plural_y(i), GNET_PROPERTY(is_firewalled) ? "" : "not ");
	}

	return i;
}

/**
 * Update list of known push proxies.
 *
 * @return TRUE if the list changed, FALSE if it is the same as the
 * one we had before.
 */
static bool
pdht_prox_update_list(void)
{
	gnet_host_t proxies[PDHT_MAX_PROXIES];
	size_t n;
	size_t i;

	n = pdht_prox_fill_vector(proxies, G_N_ELEMENTS(proxies));

	g_assert(n <= G_N_ELEMENTS(proxies));

	if (n != pdht_proxy.proxies_count)
		goto new_proxies;

	for (i = 0; i < n; i++) {
		if (!gnet_host_equiv(&proxies[i], &pdht_proxy.proxies[i]))
			goto new_proxies;
	}

	return FALSE;

new_proxies:

	g_assert(G_N_ELEMENTS(proxies) == G_N_ELEMENTS(pdht_proxy.proxies));

	memcpy(pdht_proxy.proxies, proxies, n * sizeof proxies[0]);
	pdht_proxy.proxies_count = n;

	return TRUE;
}

/**
 * Publish our push-proxies to the DHT.
 *
 * When ``force'' is TRUE, we unconditionally publish the list of known
 * push-proxies.  Otherwise, we do so only if the list has changed since
 * the last time we published it.
 */
static void
pdht_prox_publish(bool force)
{
	bool changed;
	bool publishing;
	time_t now;

	changed = pdht_prox_update_list();
	publishing = pdht_proxy.proxies_count > 0 && (changed || force);

	if G_UNLIKELY(!dht_enabled())
		publishing = FALSE;			/* DHT was disabled */

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT PROX list of %u push-prox%s %schanged, %s (%s)",
			(unsigned) pdht_proxy.proxies_count,
			plural_y(pdht_proxy.proxies_count),
			changed ? "" : "un",
			publishing ?  "publishing" : "ignoring",
			force ? "forced" : "on change only");
	}

	if (!publishing)
		return;

	/*
	 * If there is already a request pending, look whether the node lookup
	 * was performed.  If it was not, then we're already enqueued and we
	 * have not generated the DHT PROX value yet, so do nothing.
	 */

	if (pdht_proxy.pp != NULL) {
		if (GNET_PROPERTY(publisher_debug)) {
			g_warning("PDHT PROX publish whilst previous request still active"
				" (node lookup %s)",
				(pdht_proxy.pp->flags & PDHT_F_LOOKUP_DONE) ?
					"completed" : "pending");
		}

		if (!(pdht_proxy.pp->flags & PDHT_F_LOOKUP_DONE))
			return;
		pdht_cancel_prox(TRUE);
	}

	g_assert(NULL == pdht_proxy.pp);

	/*
	 * Ensure that we do not republish PROX values too often, which could be
	 * the case if our set of push-proxies is changing quickly due to
	 * connection problems.
	 *
	 * We check against the last enqueuing of a publish and the last time
	 * we actually completed the publishing.
	 *
	 * Since we're about to either launch the PROX publishing or delay it for
	 * a while, cancel any previously installed timer first.
	 */

	cq_cancel(&pdht_proxy.publish_ev);

	now = tm_time();

	if (
		delta_time(now, pdht_proxy.last_enqueued) < PDHT_PROX_RETRY ||
		delta_time(now, pdht_proxy.last_publish) < PDHT_PROX_RETRY
	) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_debug("PDHT PROX delaying publishing: "
				"last enqueued %s ago, last published %s ago",
				compact_time(delta_time(now, pdht_proxy.last_enqueued)),
				compact_time2(delta_time(now, pdht_proxy.last_publish)));
		}

		pdht_prox_install_republish(PDHT_PROX_DELAY);
		return;
	}

	/*
	 * If the DHT is not bootstrapped yet, delay publishing.
	 */

	if (!dht_bootstrapped()) {
		if (GNET_PROPERTY(publisher_debug) > 1) {
			g_debug("PDHT PROX delaying publishing: "
				"DHT not fully bootstrapped yet");
		}
		pdht_prox_install_republish(PDHT_PROX_DELAY);
		return;
	}

	/*
	 * OK, launch the PROX publishing.
	 */

	pdht_proxy.pp = pdht_publish_allocate(PDHT_T_PROX, pdht_prox_done, NULL);
	pdht_proxy.pp->id =
		gdht_kuid_from_guid((guid_t *) GNET_PROPERTY(servent_guid));

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT PROX initiating publishing for GUID %s (kuid=%s/%s)",
			guid_to_string((guid_t *) GNET_PROPERTY(servent_guid)),
			kuid_to_hex_string(pdht_proxy.pp->id),
			kuid_to_string(pdht_proxy.pp->id));
	}

	/*
	 * Publishing will occur in three steps:
	 *
	 * #1 locate suitable nodes for publishing the PROX value
	 * #2 generate the DHT PROX value
	 * #3 issue the STORE on each of the k identified nodes.
	 *
	 * Here we launch step #1, as a prioritary request to be able to bypass
	 * all other STORE requests, since the push-proxies are transient.
	 */

	ulq_find_store_roots(pdht_proxy.pp->id, TRUE,
		pdht_roots_found, pdht_roots_error, pdht_proxy.pp);

	pdht_proxy.last_enqueued = now;
}

/**
 * Republish push-proxies if list changed.
 */
void
pdht_prox_publish_if_changed(void)
{
	/*
	 * Guard against early calls during the init sequence due to property
	 * value changes.
	 */

	if (NULL == aloc_publishes)
		return;		/* pdht_init() not called yet */

	pdht_prox_publish(FALSE);
}

/**
 * Callout queue callback to initiate a new PROX publish.
 */
static void
pdht_prox_timer(cqueue_t *cq, void *unused_obj)
{
	(void) unused_obj;

	cq_zero(cq, &pdht_proxy.publish_ev);
	pdht_prox_publish(TRUE);
}

/**
 * Install a new callback to republish our push-proxies in t seconds.
 */
static void
pdht_prox_install_republish(time_t t)
{
	g_assert(NULL == pdht_proxy.publish_ev);
	pdht_proxy.publish_ev = cq_main_insert(t * 1000, pdht_prox_timer, NULL);
	pdht_proxy.last_delayed = tm_time();
}

/***
 *** Node push-entry publishing (legacy nodes for which we are a push proxy).
 ***/

/**
 * Cancel a push-entry publishing.
 *
 * @param guid		the GUID of the node
 * @param callabck	whether callbacks need to be invoked
 */
void
pdht_cancel_nope(const struct guid *guid, bool callback)
{
	pdht_publish_t *pp;

	if (NULL == nope_publishes)
		return;

	pp = hikset_lookup(nope_publishes, guid);

	if (NULL == pp)
		return;

	pdht_publish_check(pp);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_warning("PDHT cancelling NOPE (%s callback): %s",
			callback ? "with" : "no", guid_to_string(guid));
	}

	pdht_cancel(pp, callback);
}

/**
 * Publishing callback invoked when asynchronous NOPE publication is completed,
 * or ended with an error.
 *
 * @return TRUE if we accept the publishing, FALSE otherwise to get the
 * publishing layer to continue attempts to failed STORE roots and report
 * on progress using the same callback.
 */
static bool
pdht_nope_done(void *arg, pdht_error_t code, const pdht_info_t *info)
{
	bool accepted = TRUE;
	struct nid *node_id = arg;
	gnutella_node_t *n;

	n = node_by_id(node_id);

	if (NULL == n || NULL == node_guid(n))
		return TRUE;		/* Node is long gone */

	/*
	 * Compute retry delay.
	 */

	if (PDHT_E_OK == code) {
		accepted = publisher_is_acceptable(info);
	}

	/*
	 * Logging.
	 */

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT NOPE %s%s at %s <%s> published to %u node%s: %s"
			" (total %u node%s, proba %.3f%%, "
			" %s bg, path %u) [%s]",
			info->was_bg ? "[bg] " : "",
			guid_hex_str(node_guid(n)), node_addr(n), node_vendor(n),
			info->roots, plural(info->roots),
			pdht_strerror(code),
			info->all_roots, plural(info->all_roots),
			info->presence * 100.0,
			info->can_bg ? "can" : "no", info->path_len,
			accepted ? "OK" : "INCOMPLETE");
	}

	return accepted;
}

/**
 * Publish that we are a push-proxy for a legacy node (not supporting the DHT).
 *
 * @param n		the node for which we are a push-proxy
 */
void
pdht_publish_proxy(const gnutella_node_t *n)
{
	const char *error = NULL;
	pdht_publish_t *pp;
	struct pdht_nope *pnope;
	pdht_error_t code;
	struct nid *nid = node_get_id(n);

	g_return_if_fail(node_guid(n) != NULL);

	pp = pdht_publish_allocate(PDHT_T_NOPE,
		pdht_nope_done, deconstify_pointer(nid));

	pnope = &pp->u.nope;
	pnope->guid = atom_guid_get(node_guid(n));
	pnope->nid = nid_ref(nid);
	pp->id = gdht_kuid_from_guid(pnope->guid);

	if (hikset_contains(nope_publishes, pnope->guid)) {
		error = "previous publish still pending";
		code = PDHT_E_PENDING;
		goto error;
	}

	hikset_insert_key(nope_publishes, &pnope->guid);

	if (GNET_PROPERTY(publisher_debug) > 1) {
		g_debug("PDHT NOPE initiating publishing for GUID %s at %s <%s> "
			"(kuid=%s/%s)",
			guid_to_string(pnope->guid), node_addr(n), node_vendor(n),
			kuid_to_hex_string(pp->id), kuid_to_string(pp->id));
	}

	/*
	 * Publishing will occur in three steps:
	 *
	 * #1 locate suitable nodes for publishing the NOPE value
	 * #2 generate the DHT NOPE value
	 * #3 issue the STORE on each of the k identified nodes.
	 *
	 * Here we launch step #1, as a prioritary request to be able to bypass
	 * all other STORE requests, since the push-proxies are transient.
	 */

	ulq_find_store_roots(pp->id, TRUE,
		pdht_roots_found, pdht_roots_error, pp);

	return;

error:
	if (GNET_PROPERTY(publisher_debug)) {
		g_warning("PDHT will not publish NOPE for GUID %s: %s",
			guid_hex_str(pnope->guid), error);
	}

	/*
	 * Report error asynchronously, to return to caller first.
	 */

	pdht_publish_error_async(pp, code);
}

/***
 *** Initialization / Shutdown
 ***/

/**
 * Initialize the Gnutella DHT layer.
 */
void G_COLD
pdht_init(void)
{
	aloc_publishes = hikset_create(
		offsetof(struct pdht_publish, u.aloc.sha1),
		HASH_KEY_FIXED, SHA1_RAW_SIZE);
	nope_publishes = hikset_create(
		offsetof(struct pdht_publish, u.nope.guid),
		HASH_KEY_FIXED, GUID_RAW_SIZE);
	ZERO(&pdht_proxy);
	pdht_prox_install_republish(PDHT_PROX_DELAY);
}

/**
 * Hash table iterator to free a pdht_publish_t
 */
static void
free_publish_kv(void *val, void *unused_x)
{
	pdht_publish_t *pp = val;

	(void) unused_x;

	pdht_free_publish(pp, FALSE);
}

/**
 * Shutdown the Gnutella DHT layer.
 */
void G_COLD
pdht_close(void)
{
	if (pdht_proxy.pp != NULL) {
		pdht_free_publish(pdht_proxy.pp, TRUE);
	}
	cq_cancel(&pdht_proxy.publish_ev);

	hikset_foreach(aloc_publishes, free_publish_kv, NULL);
	hikset_free_null(&aloc_publishes);

	hikset_foreach(nope_publishes, free_publish_kv, NULL);
	hikset_free_null(&nope_publishes);
}

/* vi: set ts=4 sw=4 cindent: */
