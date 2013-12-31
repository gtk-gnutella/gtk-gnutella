/*
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
 * Copyright (c) 2011, Raphael Manfredi
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
 * Bitzi Core search code.
 *
 * This code makes searches to the Bitzi (bitzi.com) meta-data
 * service. It is independent from any GUI functions and part of the
 * core of GTKG.
 *
 * @author Alex Bennee <alex@bennee.com>
 * @date 2004
 *
 * Removed dependency on libxml2 and switched to a DBMW-based cache with
 * an SDBM back-end to avoid keeping all the known tickets into memory.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "bitzi.h"			/* bitzi metadata */
#include "gnet_stats.h"
#include "http.h"			/* http async stuff */
#include "settings.h"		/* settings_config_dir() */

#include "xml/vxml.h"
#include "xml/xnode.h"
#include "xml/xfmt.h"

#include "if/bridge/c2ui.h"
#include "if/gnet_property_priv.h"

#include "lib/ascii.h"
#include "lib/atoms.h"
#include "lib/cq.h"
#include "lib/dbmw.h"
#include "lib/dbstore.h"
#include "lib/getdate.h"	/* date2time() */
#include "lib/halloc.h"
#include "lib/header.h"
#include "lib/parse.h"
#include "lib/path.h"
#include "lib/slist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/strtok.h"
#include "lib/timestamp.h"
#include "lib/tm.h"
#include "lib/urn.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* This file MUST be the last one included */

#define BITZI_XML_MAXLEN		16384
#define BITZI_DB_CACHE_SIZE		32
#define BITZI_SYNC_PERIOD		(60 * 1000)			/**< ms: 1 minute */
#define BITZI_PRUNE_PERIOD		(24 * 3600 * 1000)	/**< ms: 1 day */
#define BITZI_HEARTBEAT_PERIOD	(5 * 1000)			/**< ms: 5 secs */
#define BITZI_UNKNOWN_TIMEOUT	(60 * 60)			/**< s: 1 hour */

static const char bitzi_url_fmt[] =
	"http://ticket.bitzi.com/rdf/urn:sha1:%s?ref=gtk-gnutella";

static const char BITZI_RDF[]	= "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
static const char BITZI_BZ[]	= "http://bitzi.com/xmlns/2002/01/bz-core#";
static const char BITZI_DC[]	= "http://purl.org/dc/elements/1.1/";
static const char BITZI_MM[]	= "http://musicbrainz.org/mm/mm-2.0#";

/**
 * For XML tree formating, indicate prefixes to use for namespaces we parse.
 */
const struct xfmt_prefix bitzi_prefixes[] = {
	{ BITZI_RDF,	"rdf" },
	{ BITZI_BZ,		"bz" },
	{ BITZI_DC,		"dc" },
	{ BITZI_MM,		"mm" },
};

/**
 * @struct bitzi_request_t
 *
 * The bitzi_request_t structure ties together each Bitzi request
 * which are stored in the request queue.
 *
 */
typedef struct {
	const struct sha1 *sha1;			/**< binary SHA-1, atom */
	filesize_t filesize;
	char bitzi_url[SHA1_BASE32_SIZE + sizeof bitzi_url_fmt]; /**< request URL */
	http_async_t *ha;
} bitzi_request_t;

/**
 * The request queue, the searches to the Bitzi data service are queued
 */
static slist_t *bitzi_rq;

static bitzi_request_t	*current_bitzi_request;
static cperiodic_t *bitzi_heartbeat_ev;
static cperiodic_t *bitzi_sync_ev;
static cperiodic_t *bitzi_prune_ev;

/**
 * DBM wrapper to associate a SHA1 with its Bitzi ticket.
 */
static dbmw_t *db_bzdata;
static char db_bzdata_base[] = "bitzi_tickets";
static char db_bzdata_what[] = "Bitzi tickets";

/**
 * Ticket information stored in the database.
 * The structure is serialized first, not written as-is
 */
struct bzdata {
	const char *mime_type;			/**< MIME type (atom) */
	const char *mime_desc;			/**< MIME details (atom) */
	char *ticket;					/**< Raw XML ticket text */
	filesize_t size;				/**< File size */
	bitzi_fj_t judgment;
	float goodness;
	time_t duration;				/**< Duration (audio/video), in seconds */
	time_t ctime;					/**< Creation time (local insertion) */
	time_t etime;					/**< Expiration date, from ticket */
};

#define BITZI_BZ_VERSION	1		/**< Serialization version number */

/**
 * Serialization flags.
 */
#define BITZI_HAS_MIME_TYPE		(1 << 0)
#define BITZI_HAS_MIME_DESC		(1 << 1)
#define BITZI_HAS_TICKET		(1 << 2)
#define BITZI_HAS_DURATION		(1 << 3)

/*
 * Function declarations
 */

/* cache functions */
static bool bitzi_cache_add(bitzi_data_t * data, const xnode_t *root);

/********************************************************************
 ** Bitzi serialization & deserialization routines for DBMW
 ********************************************************************/

/**
 * Serialization routine for bzdata.
 */
static void
serialize_bzdata(pmsg_t *mb, const void *data)
{
	const struct bzdata *bz = data;
	uint8 flags;

	pmsg_write_u8(mb, BITZI_BZ_VERSION);

	flags = 0;
	if (bz->mime_type != NULL)
		flags |= BITZI_HAS_MIME_TYPE;
	if (bz->mime_desc != NULL)
		flags |= BITZI_HAS_MIME_DESC;
	if (bz->ticket != NULL)
		flags |= BITZI_HAS_TICKET;
	if (bz->duration != 0)
		flags |= BITZI_HAS_DURATION;
	pmsg_write_u8(mb, flags);

	if (bz->mime_type != NULL)
		pmsg_write_string(mb, bz->mime_type, (size_t) -1);
	if (bz->mime_desc != NULL)
		pmsg_write_string(mb, bz->mime_desc, (size_t) -1);
	if (bz->ticket != NULL)
		pmsg_write_string(mb, bz->ticket, (size_t) -1);

	pmsg_write_be64(mb, bz->size);
	pmsg_write_be32(mb, bz->judgment);
	pmsg_write_float_be(mb, bz->goodness);
	pmsg_write_time(mb, bz->ctime);
	pmsg_write_time(mb, bz->etime);

	/* Introduced at version 1 */
	if (bz->duration != 0) {
		pmsg_write_time(mb, bz->duration);
	}
}

/**
 * Deserialization routing for bzdata.
 */
static void
deserialize_bzdata(bstr_t *bs, void *valptr, size_t len)
{
	struct bzdata *bz = valptr;
	uint8 version;
	uint8 flags;
	uint64 val;

	g_assert(sizeof *bz == len);

	bstr_read_u8(bs, &version);
	bstr_read_u8(bs, &flags);

	if (flags & BITZI_HAS_MIME_TYPE) {
		char *string;
		if (bstr_read_string(bs, NULL, &string)) {
			bz->mime_type = atom_str_get(string);
			hfree(string);
		}
	} else {
		bz->mime_type = NULL;
	}

	if (flags & BITZI_HAS_MIME_DESC) {
		char *string;
		if (bstr_read_string(bs, NULL, &string)) {
			bz->mime_desc = atom_str_get(string);
			hfree(string);
		}
	} else {
		bz->mime_desc = NULL;
	}

	if (flags & BITZI_HAS_TICKET) {
		bstr_read_string(bs, NULL, &bz->ticket);
	} else {
		bz->ticket = NULL;
	}

	bz->size = bstr_read_be64(bs, &val) ? val : 0;
	bstr_read_be32(bs, &bz->judgment);
	bstr_read_float_be(bs, &bz->goodness);
	bstr_read_time(bs, &bz->ctime);
	bstr_read_time(bs, &bz->etime);

	/*
	 * Duration was introduced at version 1.
	 */

	if (version < 1) {
		/*
		 * Although we can parse the XML ticket to extract the missing duration,
		 * there's no way currently (2011-06-02) to flag the deserialized
		 * value as dirty, so that we would not lose the result.
		 * That means we would have to reparse the XML ticket each time we
		 * access the value from the database without being able to "upgrade"
		 * the sotred value.
		 *
		 * TODO: This ability to "upgrade" stored data could be useful to add,
		 * but it's tricky as it means changing the contract of all the
		 * deserialization routines to flag the value as dirty for the DBMW
		 * layer.		--RAM, 2011-06-02
		 */

		bz->duration = 0;		/* Sorry */
	} else {
		if (flags & BITZI_HAS_DURATION) {
			bstr_read_time(bs, &bz->duration);
		} else {
			bz->duration = 0;
		}
	}
}

/**
 * Free routine for bzdata, to release internally allocated memory at
 * deserialization time (not the structure itself).
 */
static void
free_bzdata(void *valptr, size_t len)
{
	struct bzdata *bz = valptr;
	
	g_assert(sizeof *bz == len);

	atom_str_free_null(&bz->mime_type);
	atom_str_free_null(&bz->mime_desc);
	HFREE_NULL(bz->ticket);
}

/********************************************************************
 ** Bitzi Create and Destroy data structures
 ********************************************************************/

static bitzi_data_t *
bitzi_create(void)
{
	bitzi_data_t *data;

	/*
	 * defaults
	 */

	WALLOC0(data);
	data->judgment = BITZI_FJ_UNKNOWN;
	data->expiry = (time_t) -1;

	return data;
}

static void
bitzi_destroy(bitzi_data_t *data)
{
	g_assert(data != NULL);

	if (GNET_PROPERTY(bitzi_debug)) {
		g_debug("BITZI %s: ticket for %s",
			G_STRFUNC, sha1_to_string(data->sha1));
	}

	/*
	 * NOTE: data->ticket is NOT freed because it is pointing to the cached
	 * value we insert in the database, to avoid duplicating the string since
	 * the call to notify the GUI is synchronous.
	 */

	atom_sha1_free_null(&data->sha1);
	atom_str_free_null(&data->mime_type);
	atom_str_free_null(&data->mime_desc);
	WFREE(data);
}

static bitzi_request_t *
bitzi_request_create(const sha1_t *sha1, filesize_t filesize)
{
	bitzi_request_t *breq;

	WALLOC0(breq);

	/*
	 * build the bitzi URL
	 */

	breq->sha1 = atom_sha1_get(sha1);
	breq->filesize = filesize;
	str_bprintf(breq->bitzi_url, sizeof breq->bitzi_url,
			bitzi_url_fmt, sha1_base32(sha1));

	return breq;
}

static void
bitzi_request_free(bitzi_request_t *req)
{
	atom_sha1_free_null(&req->sha1);
	http_async_cancel_null(&req->ha);
	WFREE(req);
}

static void
bitzi_request_free_null(bitzi_request_t **ptr)
{
	if (*ptr) {
		bitzi_request_t *req = *ptr;
		bitzi_request_free(req);
		*ptr = NULL;
	}
}

/*********************************************************************
 ** Bitzi Query and Result Parsing
 ********************************************************************/

/*
 * These XML parsing routines are hacked up versions of these from the
 * libxml2 examples.
 */

/**
 * Parse (and eventually fill in) the bitzi specific data.
 *
 * The fields are defined at:
 *	schema: http://bitzi.com/developer/bitzi-ticket.rng
 *	notes: http://bitzi.com/openbits/datadump
 *
 * The ones we have most interest in are:
 *
 * 	bz:fileGoodness="2.1"
 * 	bz:fileJudgement="Complete"
 *
 * Although the other could be used to verify size data and such.
 */

struct efj_t {
	const char *string;
	bitzi_fj_t judgment;
};

static const struct efj_t enum_fj_table[] = {
	{ "Unknown",				BITZI_FJ_UNKNOWN },
	{ "Unrated",				BITZI_FJ_UNRATED },
	{ "Bitzi lookup failure",	BITZI_FJ_FAILURE },
	{ "Filesize mismatch",		BITZI_FJ_WRONG_FILESIZE },
	{ "Dangerous/Misleading",	BITZI_FJ_DANGEROUS_MISLEADING },
	{ "Incomplete/Damaged",		BITZI_FJ_INCOMPLETE_DAMAGED },
	{ "Substandard",			BITZI_FJ_SUBSTANDARD },
	{ "Overrated",				BITZI_FJ_OVERRATED },
	{ "Normal",					BITZI_FJ_NORMAL },
	{ "Underrated",				BITZI_FJ_UNDERRATED },
	{ "Complete",				BITZI_FJ_COMPLETE },
	{ "Recommended",			BITZI_FJ_RECOMMENDED },
	{ "Best Version",			BITZI_FJ_BEST_VERSION }
};

static const char *
bitzi_judgment_to_string(bitzi_fj_t fj)
{
	if (UNSIGNED(fj) < G_N_ELEMENTS(enum_fj_table))
		return enum_fj_table[fj].string;
	else
		return str_smsg("Invalid Judgment %d", fj);
}

/**
 * xnode_prop_foreach() callback to log the attributes of the node.
 */
static void
bitzi_description_attr_log(const char *uri,
	const char *local, const char *value, void *unused_data)
{
	(void) unused_data;

	if (uri != NULL) {
		g_debug("BITZI    %s = \"%s\" [%s]", local, value, uri);
	} else {
		g_debug("BITZI    %s = \"%s\"", local, value);
	}
}

/**
 * Read all the attributes we may want from the rdf ticket, some
 * attributes will not be there in which case xmlGetProp will return a null.
 */
static void
bitzi_process_rdf_description(const xnode_t *xn, bitzi_data_t *data)
{
	const char *value;

	/*
	 * We extract the urn:sha1 from the ticket as we may be processing
	 * cached tickets not associated with any actual request. The
	 * bitprint itself will be at offset 9 into the string.
	 */
	value = xnode_prop_ns_get(xn, BITZI_RDF, "about");
	if (value) {
		sha1_t sha1;

		if (urn_get_sha1(value, &sha1)) {
			data->sha1 = atom_sha1_get(&sha1);
		} else {
			g_warning("%s: bad 'rdf:about' string: \"%s\"", G_STRFUNC, value);
		}
	} else {
		if (GNET_PROPERTY(bitzi_debug)) {
			g_warning("%s: No SHA-1!", G_STRFUNC);
		}
	}

	/*
	 * All tickets have a bz:ticketExpires tag which we need for cache
	 * managment.
	 */
	value = xnode_prop_ns_get(xn, BITZI_BZ, "ticketExpires");
	if (value) {
		data->expiry = date2time(value, tm_time());
		if ((time_t) -1 == data->expiry) {
			if (GNET_PROPERTY(bitzi_debug)) {
				g_warning("%s: Bad expiration date \"%s\"", G_STRFUNC, value);
			}
		}
	} else {
		g_warning("%s: No ticketExpires!", G_STRFUNC);
	}

	/*
	 * fileGoodness amd fileJudgement are the two most immediatly
	 * useful values.
	 */
	value = xnode_prop_ns_get(xn, BITZI_BZ, "fileGoodness");
	if (value) {
		data->goodness = g_strtod(value, NULL);
		if (GNET_PROPERTY(bitzi_debug)) {
			g_debug("BITZI %s: fileGoodness is %s/%g",
				G_STRFUNC, value, data->goodness);
		}
	} else {
		data->goodness = 0.0;
	}

	value = xnode_prop_ns_get(xn, BITZI_BZ, "fileJudgement");
	if (value) {
		size_t i;

		STATIC_ASSERT(NUM_BITZI_FJ == G_N_ELEMENTS(enum_fj_table));

		for (i = 0; i < G_N_ELEMENTS(enum_fj_table); i++) {
			if (0 == strcmp(value, enum_fj_table[i].string)) {
				data->judgment = enum_fj_table[i].judgment;
				break;
			}
		}
	} else {
		data->judgment = BITZI_FJ_UNRATED;
	}

	/*
	 * fileLength, useful for comparing to result
	 */

	value = xnode_prop_ns_get(xn, BITZI_BZ, "fileLength");
	if (value) {
		int error;
		data->size = parse_uint64(value, NULL, 10, &error);
		if (error) {
			if (GNET_PROPERTY(bitzi_debug)) {
				g_warning("%s: fileLength '%s' is invalid: %s",
					G_STRFUNC, value, g_strerror(error));
			}
		}
	}

	/*
	 * The multimedia type, bitrate etc is all built into one
	 * descriptive string. It is dependant on format
	 *
	 * Currently we handle video and audio
	 */

	value = xnode_prop_ns_get(xn, BITZI_DC, "format");
	if (value) {
		/*
		 * copy the mime type
		 */
		atom_str_change(&data->mime_type, value);

		if (is_strcaseprefix(value, "video/")) {
			const char *bitrate =
				xnode_prop_ns_get(xn, BITZI_BZ, "videoBitrate");
			const char *fps = xnode_prop_ns_get(xn, BITZI_BZ, "videoFPS");
			const char *height = xnode_prop_ns_get(xn, BITZI_BZ, "videoHeight");
			const char *width = xnode_prop_ns_get(xn, BITZI_BZ, "videoWidth");
			const char *duration = xnode_prop_ns_get(xn, BITZI_MM, "duration");
			bool has_res = width && height;
			uint32 seconds;
			char desc[256];
			size_t len;

			if (duration != NULL) {
				int error;
				/* Bitzi stores it in ms */
				seconds = parse_uint32(duration, NULL, 10, &error) / 1000;
			} else {
				seconds = 0;
			}

			/*
			 * We don't include the duration in the string because the
			 * output of short_time() is localized and we don't want to
			 * freeze that description in the database.
			 * Keep it separate so that the GUI can format it properly
			 * when the description is displayed, using the right locale.
			 */

			data->duration = seconds;

			/*
			 * format the mime details
			 */

			/**
			 * TRANSLATORS: This describes video parameters;
			 * The first part is used as <width>x<height> (resolution).
			 * fps stands for "frames per second".
			 * kbps stands for "kilobit per second" (metric kilo).
			 */
			len = str_bprintf(desc, sizeof desc, _("%s%s%s%s%s fps, %s kbps"),
					has_res ? width : "",
					has_res ? Q_("times|x") : "",
					has_res ? height : "",
					has_res ? ", " : "",
					(fps != NULL) ? fps : "?",
					(bitrate != NULL) ? bitrate : "?");

			ascii_chomp_trailing_spaces(desc, len);
			atom_str_change(&data->mime_desc, desc);

		} else if (is_strcaseprefix(value, "audio/")) {
			const char *channels =
				xnode_prop_ns_get(xn, BITZI_BZ, "audioChannels");
			const char *kbps = xnode_prop_ns_get(xn, BITZI_BZ, "audioBitrate");
			const char *srate =
				xnode_prop_ns_get(xn, BITZI_BZ, "audioSamplerate");
			const char *duration = xnode_prop_ns_get(xn, BITZI_MM, "duration");
			uint32 seconds;
			char desc[256];
			size_t len;

			if (duration) {
				int error;
				/* Bitzi stores it in ms */
				seconds = parse_uint32(duration, NULL, 10, &error) / 1000;
			} else {
				seconds = 0;
			}

			data->duration = seconds;

			/*
			 * We don't include the duration in the string because the
			 * output of short_time() is localized and we don't want to
			 * freeze that description in the database.  Units like Hz
			 * or acronyms like kbps are OK because they're "international".
			 */

			len = str_bprintf(desc, sizeof desc, "%s%s%s%s%s%s",
				kbps ? kbps : "", kbps ? "kbps " : "",
				srate ? srate : "", srate ? "Hz " : "",
				channels ? channels : "", channels ? "ch" : "");

			ascii_chomp_trailing_spaces(desc, len);
			atom_str_change(&data->mime_desc, desc);
		}
	}

	/*
	 * For debugging/development - dump all the attributes
	 */

	if (GNET_PROPERTY(bitzi_debug) > 3) {
		g_debug("BITZI %s: attributes of %s:", G_STRFUNC, xnode_to_string(xn));
		xnode_prop_foreach(xn, bitzi_description_attr_log, NULL);
	}
}

/**
 * Iterates through the XML/RDF ticket calling various process
 * functions to read the data into the bitzi_data_t.
 *
 * This function is recursive, if the element is not explicity known we
 * just recurse down a level.
 */
static void
bitzi_process_xml(const xnode_t *xn, bitzi_data_t *data)
{
	const xnode_t *xl;

	for (xl = xn; xl != NULL; xl = xnode_next_sibling(xl)) {
		if (!xnode_is_element(xl))
			continue;

		if (GNET_PROPERTY(bitzi_debug) > 3)
			g_debug("BITZI at element %s", xnode_to_string(xl));

		if (xnode_is_element_named(xl, BITZI_RDF, "Description")) {
			bitzi_process_rdf_description(xl, data);
		} else {
			bitzi_process_xml(xnode_first_child(xl), data);
		}
	}
}

/**
 * Report failure to the GUI for a SHA1/filesize request.
 */
static void
bitzi_failure(const struct sha1 *sha1, filesize_t filesize, bitzi_fj_t error)
{
	if (sha1 != NULL) {
		bitzi_data_t dummy;

		ZERO(&dummy);
		dummy.sha1 = sha1;
		dummy.size = filesize;
		dummy.judgment = error;
		gcu_bitzi_result(&dummy);
	}
}

/**
 * Fill data from database entry.
 */
static void
bitzi_fill_data(bitzi_data_t *data,
	const struct sha1 *sha1, const struct bzdata *bz)
{
	ZERO(data);
	data->sha1 = sha1;
	data->mime_type = bz->mime_type;
	data->mime_desc = bz->mime_desc;
	data->ticket = bz->ticket;
	data->size = bz->size;
	data->duration = bz->duration;
	data->judgment = bz->judgment;
	data->goodness = bz->goodness;
	data->expiry = bz->etime;
	data->first_seen = bz->ctime;
}

/**
 * Process the XML ticket and notify GUI.
 */
static void
bitzi_process_ticket(bitzi_request_t *breq, char *ticket, size_t length)
{
	bitzi_data_t *data;
	xnode_t *root;
	vxml_parser_t *vp;
	vxml_error_t e;

	g_assert(breq != NULL);

	if (GNET_PROPERTY(bitzi_debug)) {
		g_debug("BITZI %s: processing ticket data for %s",
			G_STRFUNC, sha1_to_string(breq->sha1));
	}

	/*
	 * Parse the XML ticket.
	 */

	vp = vxml_parser_make("BITZI ticket", VXML_O_STRIP_BLANKS);
	vxml_parser_add_data(vp, ticket, length);
	e = vxml_parse_tree(vp, &root);
	vxml_parser_free(vp);

	if (VXML_E_OK != e) {
		if (GNET_PROPERTY(bitzi_debug)) {
			g_warning("BITZI cannot parse XML ticket: %s", vxml_strerror(e));
			dump_hex(stderr, "BITZI ticket", ticket, length);
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		return;
	}

	/*
	 * Now we can have a look at the data
	 */

   	data = bitzi_create();

	/*
	 * This just dumps the data
	 */

	bitzi_process_xml(root, data);

	if (NULL == data->sha1) {
		if (GNET_PROPERTY(bitzi_debug))  {
			g_warning("process_meta_data: missing SHA-1");
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto finish;
	}

	if (breq->sha1 && !sha1_eq(data->sha1, breq->sha1)) {
		if (GNET_PROPERTY(bitzi_debug))  {
			g_warning("process_meta_data: SHA-1 mismatch");
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto finish;
	}

	/*
	 * If the data has a valid date then we can cache the result.
	 */

	if (
		(time_t) -1 == data->expiry ||
		delta_time(data->expiry, tm_time()) <= 0
	) {
		if (GNET_PROPERTY(bitzi_debug))  {
			g_debug("BITZI %s: stale bitzi data", G_STRFUNC);
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto finish;
	}

	if (!bitzi_cache_add(data, root)) {
		if (GNET_PROPERTY(bitzi_debug))  {
			g_debug("BITZI %s: uncached bitzi data", G_STRFUNC);
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto finish;
	}

	if (breq->filesize && breq->filesize != data->size) {
		if (GNET_PROPERTY(bitzi_debug))  {
			g_debug("BITZI %s: filesize mismatch", G_STRFUNC);
		}
		/* We keep the ticket anyway because there's only one per SHA-1 */
		bitzi_failure(breq->sha1, breq->filesize,
			data->size ? BITZI_FJ_WRONG_FILESIZE : BITZI_FJ_UNKNOWN);
		goto finish;
	}

	gcu_bitzi_result(data);

	/* FALL THROUGH */

finish:
	xnode_tree_free_null(&root);
	bitzi_destroy(data);
}

/**
 * Answer to our ticket request.
 *
 * This is an http_async_wget() completion callback.
 */
static void
bitzi_ticket_requested(char *data, size_t len, int code,
	header_t *header, void *arg)
{
	bitzi_request_t *breq = arg;
	const char *buf;

	breq->ha = NULL;		/* Request ending with this callback */

	if (NULL == data) {
		if (GNET_PROPERTY(bitzi_debug)) {
			g_warning("BITZI requested ticket for %s failed (HTTP %d)",
				sha1_to_string(breq->sha1), code);
		}
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto done;
	}

	if (GNET_PROPERTY(bitzi_debug) > 1) {
		g_debug("BITZI request for %s returned %zu byte%s",
			sha1_to_string(breq->sha1),
			len, 1 == len ? "" : "s");
		if (GNET_PROPERTY(bitzi_debug) > 5) {
			g_debug("BITZI got HTTP %u:", code);
			header_dump(stderr, header, "----");
		}
		if (GNET_PROPERTY(bitzi_debug) > 9) {
			dump_hex(stderr, "BITZI ticket", data, len);
		}
	}

	/*
	 * Make sure we got "text/xml" output.
	 */

	buf = header_get(header, "Content-Type");
	if (NULL == buf || !strtok_case_has(buf, ";", "text/xml")) {
		g_warning("BITZI ticket for %s does not contain any XML",
			sha1_to_string(breq->sha1));
		bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_FAILURE);
		goto done;
	}

	/*
	 * Parse the XML ticket.
	 */

	bitzi_process_ticket(breq, data, len);
	hfree(data);

	/* FALL THROUGH */

done:
	current_bitzi_request = NULL;
	bitzi_request_free(breq);
}

/**
 * Send a meta-data query
 *
 * Called directly when a request launched or via the bitzi_heartbeat tick.
 *
 * @return TRUE if an HTTP request was launched.
 */
static bool
bitzi_launch_query(bitzi_request_t *breq)
{
	if (GNET_PROPERTY(bitzi_debug))
		g_debug("BITZI dequeuing query for %s", sha1_to_string(breq->sha1));

	/*
	 * check we haven't already got a response from a previous query
	 */
	if (bitzi_has_cached_ticket(breq->sha1)) {
		bitzi_data_t data;


		if (bitzi_data_by_sha1(&data, breq->sha1, breq->filesize)) {
			bool ignore = FALSE;

			/*
			 * If the cached entry indicates that the SHA1 was not in the
			 * Bitzi database, re-query Bitzi if the indication was inserted
			 * more than BITZI_UNKNOWN_TIMEOUT seconds ago, thereby ignoring
			 * the default Bitzi expiration time of about 2 weeks.
			 *
			 * The reason for ignoring this timeout is that we're facing an
			 * explicit user request here, not an automatic lookup. Imposing
			 * the BITZI_UNKNOWN_TIMEOUT interval between requests avoids
			 * hammering Bitzi and protects against broad user selections
			 * for updates.
			 *		--RAM, 2011-09-18
			 */

			if (
				BITZI_FJ_UNKNOWN == data.judgment &&
				delta_time(tm_time(), data.first_seen) > BITZI_UNKNOWN_TIMEOUT
			) {
				ignore = TRUE;
			}

			if (GNET_PROPERTY(bitzi_debug)) {
				g_debug("BITZI has cached ticket for %s: \"%s\", inserted %s%s",
					sha1_to_string(breq->sha1),
					bitzi_judgment_to_string(data.judgment),
					timestamp_to_string(data.first_seen),
					ignore ? " (ignoring and re-fetching)" : "");
			}

			if (ignore)
				goto fetch;

			gcu_bitzi_result(&data);
		} else {
			/*
			 * We have a ticket for this SHA1, but no suitable data is filled
			 * which indicates a filesize mismatch.
			 */
			bitzi_failure(breq->sha1, breq->filesize, BITZI_FJ_WRONG_FILESIZE);
		}
		goto failed;
	}

	/*
	 * Launch the HTTP asynchronous request.
	 */

fetch:

	if (GNET_PROPERTY(bitzi_debug))
		g_debug("BITZI launching query for %s", sha1_to_string(breq->sha1));

	breq->ha = http_async_wget(breq->bitzi_url, BITZI_XML_MAXLEN,
		bitzi_ticket_requested, breq);

	if (NULL == breq->ha) {
		g_warning("could not launch a \"GET %s\" request: %s",
			breq->bitzi_url, http_async_strerror(http_async_errno));
		goto failed;
	}

	current_bitzi_request = breq;
	return TRUE;

failed:
	bitzi_request_free(breq);
	return FALSE;
}

/**************************************************************
 ** Bitzi Results Cache
 *************************************************************/

/**
 * Get bzdata from database, returning NULL if not found.
 */
static struct bzdata *
get_bzdata(const sha1_t *sha1)
{
	struct bzdata *bz;

	bz = dbmw_read(db_bzdata, sha1, NULL);

	return bz;
}

/**
 * Add parsed ticket data to the cache.
 *
 * @return TRUE if we added the ticket, FALSE if it was already present (in
 * which case the information is simply updated).
 */
static bool
bitzi_cache_add(bitzi_data_t *data, const xnode_t *root)
{
	struct bzdata bz;
	struct bzdata *bzo;

	g_assert(data != NULL);
	g_assert(data->sha1 != NULL);
	g_assert(NULL == data->ticket);

	bzo = get_bzdata(data->sha1);

	/*
	 * For proper memory management of the pointers allocated at
	 * deserialization time we have two options (when the value was
	 * already present in the database):
	 *
	 * - Either we explicitly manage freeing of previous pointers in the
	 *   supplied value (in effect updating the value that was allocated
	 *   by the DBMW layer.  In that case, we may supply back the same
	 *   value pointer.
	 *
	 * - Or we supply a totally different structure, and the DBMW layer
	 *   will invoke the freeing callback on the previous value.  In that
	 *   case, all the values dynamically allocated in the original must be
	 *   cloned.
	 *
	 * In any case, memory allocation must be consistent with the one
	 * performed at deserialization time since it is the freeing callback
	 * which will ultimately release the memory when the value leaves
	 * the cache.
	 *
	 * We choose option #1: we explicitly manage memory in the cached structure.
	 */

	if (NULL == bzo) {
		bzo = &bz;
		ZERO(&bz);
		bzo->ctime = tm_time();
		gnet_stats_inc_general(GNR_BITZI_TICKETS_HELD);
	} else {
		if (data->expiry < bzo->etime) {
			g_message("%s: entry for %s already present and expires later",
				G_STRFUNC, sha1_to_string(data->sha1));
			return FALSE;
		}

		if (bzo->size != 0 && bzo->size != data->size) {
			g_warning("%s: entry for %s already present with filesize %s but "
				"new entry says %s, keeping old ticket",
				G_STRFUNC, sha1_to_string(data->sha1),
				filesize_to_string(bzo->size),
				filesize_to_string2(data->size));
			return FALSE;
		}
	}

	if (NULL == bzo->mime_type) {
		atom_str_change(&bzo->mime_type, data->mime_type);
	}
	if (NULL == bzo->mime_desc) {
		atom_str_change(&bzo->mime_desc, data->mime_desc);
	} else if (
		data->mime_desc != NULL &&
		strlen(bzo->mime_desc) < strlen(data->mime_desc)
	) {
		/* Keep longest string, assuming it will be more complete */
		atom_str_change(&bzo->mime_desc, data->mime_desc);
	}

	/*
	 * We keep the full XML ticket around, just in case we later wish to
	 * parse more data from the ticket and want to upgrade the database.
	 *
	 * It's not worth compressing the XML data to save space, this will just
	 * slow things down for little space benefits.
	 */

	HFREE_NULL(bzo->ticket);
	if (data->size != 0) {
		bzo->ticket = xfmt_tree_to_string_extended(root, XFMT_O_SINGLE_LINE,
			bitzi_prefixes, G_N_ELEMENTS(bitzi_prefixes), BITZI_RDF);
	}
	bzo->size = data->size;
	bzo->duration = data->duration;
	bzo->judgment = data->judgment;
	bzo->goodness = data->goodness;
	bzo->etime = data->expiry;

	dbmw_write(db_bzdata, data->sha1, bzo, sizeof *bzo);

	if (GNET_PROPERTY(bitzi_debug)) {
		g_debug("BITZI %s: %s %s ticket, filesize=%s, type=%s, desc=\"%s\", "
			"judgment=\"%s\", goodness=%g, duration=%s, expire=%s",
			G_STRFUNC, bzo->ctime == tm_time() ? "added" : "updated",
			sha1_to_string(data->sha1),
			filesize_to_string(bzo->size), bzo->mime_type,
			bzo->mime_desc, bitzi_judgment_to_string(bzo->judgment),
			bzo->goodness, short_time_ascii(bzo->duration),
			timestamp_to_string(bzo->etime));
		if (GNET_PROPERTY(bitzi_debug) > 5 && bzo->ticket != NULL) {
			g_debug("BITZI XML ticket:");
			dump_string(stderr, bzo->ticket, strlen(bzo->ticket), "");
		}
	}

	return TRUE;
}

/**
 * DBMW foreach iterator to remove old entries.
 * @return TRUE if entry must be deleted.
 */
static bool
bitzi_entry_prune(void *key, void *value, size_t u_len, void *u_data)
{
	const sha1_t *sha1 = key;
	const struct bzdata *bz = value;
	bool expired;

	(void) u_len;
	(void) u_data;

	expired = tm_time() >= bz->etime;

	if (GNET_PROPERTY(bitzi_debug) > 4) {
		g_debug("BITZI ticket %s expire=%s%s",
			sha1_to_string(sha1),
			timestamp_to_string(bz->etime), expired ? " [EXPIRED]" : "");
		if (GNET_PROPERTY(bitzi_debug) > 5 && expired && bz->ticket != NULL) {
			g_debug("BITZI Expired XML ticket:");
			dump_string(stderr, bz->ticket, strlen(bz->ticket), "----");
		}
	}

	return expired;
}

/**
 * Prune the database, removing expired entries.
 */
static void
bitzi_prune_old(void)
{
	if (GNET_PROPERTY(bitzi_debug)) {
		g_debug("BITZI pruning expired tickets (%zu)", dbmw_count(db_bzdata));
	}

	dbmw_foreach_remove(db_bzdata, bitzi_entry_prune, NULL);
	gnet_stats_set_general(GNR_BITZI_TICKETS_HELD, dbmw_count(db_bzdata));

	if (GNET_PROPERTY(bitzi_debug)) {
		g_debug("BITZI pruned expired tickets (%zu remaining)",
			dbmw_count(db_bzdata));
	}

	dbstore_compact(db_bzdata);
}

/**
 * Callout queue periodic event to expire old entries.
 */
static bool
bitzi_prune(void *unused_obj)
{
	(void) unused_obj;

	bitzi_prune_old();
	return TRUE;		/* Keep calling */
}

/**
 * Callout queue periodic event to synchronize persistent DB.
 */
static bool
bitzi_sync(void *unused_obj)
{
	(void) unused_obj;

	dbstore_sync_flush(db_bzdata);
	return TRUE;		/* Keep calling */
}

/*************************************************************
 ** Bitzi Heartbeat
 ************************************************************/

/**
 * The heartbeat function is a repeating glib timeout that is used to
 * pace queries to the bitzi metadata service.
 */
static bool
bitzi_heartbeat(void *unused_data)
{
	(void) unused_data;

	/*
	 * launch first pending queries if none is active.
	 */

	while (current_bitzi_request == NULL && slist_length(bitzi_rq) != 0) {
		bitzi_request_t *breq = slist_shift(bitzi_rq);

		if (bitzi_launch_query(breq))
			break;
	}

	return TRUE;		/* Always requeue */
}

/**************************************************************
 ** Bitzi API
 *************************************************************/

/**
 * Query the bitzi cache for this given SHA-1.
 */
bool
bitzi_has_cached_ticket(const struct sha1 *sha1)
{
	return NULL != get_bzdata(sha1);
}

/**
 * A GUI/Bitzi API passes a pointer to the search type (currently only
 * urn:sha1), a pointer to a callback function and a user data
 * pointer.
 *
 * @param sha1 The SHA-1 of the file.
 * @param filesize The expected filesize.
 * @param refresh If TRUE a fresh ticket is requested, otherwise a
 *                cached ticket is used.
 *
 * If no query succeds then the call back is never made, however we
 * should always get some sort of data back from the service.
 */
void
bitzi_query_by_sha1(const struct sha1 *sha1,
	filesize_t filesize, bool refresh)
{
	struct bzdata *bz;

	g_return_if_fail(NULL != sha1);

	bz = get_bzdata(sha1);

	if (bz != NULL) {
		if (GNET_PROPERTY(bitzi_debug)) {
			g_debug("BITZI %s: result for %s already in cache, "
				"size=%s, refresh=%s, expires %s",
				G_STRFUNC, sha1_to_string(sha1), filesize_to_string(bz->size),
				refresh ? "y" : "n",
				timestamp_to_string(bz->etime));
		}
		if (refresh) {
			bz = NULL;
		}
	}

	if (bz != NULL) {
		if (filesize != 0 && bz->size != filesize) {
			bitzi_failure(sha1, filesize,
				bz->size ? BITZI_FJ_WRONG_FILESIZE : BITZI_FJ_UNKNOWN);
			bz = NULL;
		} else {
			bitzi_data_t data;

			bitzi_fill_data(&data, sha1, bz);
			gcu_bitzi_result(&data);
		}
	} else {
		bitzi_request_t	*breq;

		breq = bitzi_request_create(sha1, filesize);

		/*
		 * When no request is running, immediately process the incoming
		 * request if nothing else is pending.
		 */

		if (NULL == current_bitzi_request && 0 == slist_length(bitzi_rq)) {
			bitzi_launch_query(breq);
		} else {
			slist_append(bitzi_rq, breq);

			if (GNET_PROPERTY(bitzi_debug)) {
				g_debug("BITZI %s: queued query for %s at position #%u",
					G_STRFUNC, sha1_base32(sha1), slist_length(bitzi_rq));
			}

			/* The heartbeat will pick up the request */
		}
	}
}

/**
 * Fill supplied data by SHA1.
 *
 * @return TRUE if found, FALSE if ticket does not exist.
 */
bool
bitzi_data_by_sha1(bitzi_data_t *data,
	const struct sha1 *sha1, filesize_t filesize)
{
	struct bzdata *bz;
	
	bz = get_bzdata(sha1);
	if (NULL == bz)
		return FALSE;

	bitzi_fill_data(data, sha1, bz);

	if (0 == bz->size) {
		data->judgment = BITZI_FJ_UNKNOWN;
	} else if (filesize != 0 && bz->size != filesize) {
		data->judgment = BITZI_FJ_WRONG_FILESIZE;
	}

	return TRUE;
}

/**
 * Return XML ticket by SHA1.
 */
const char *
bitzi_ticket_by_sha1(const struct sha1 *sha1, filesize_t filesize)
{
	struct bzdata *bz;
	
	bz = get_bzdata(sha1);

	if (GNET_PROPERTY(bitzi_debug > 9)) {
		if (bz != NULL) {
			bool matches = 0 == filesize || bz->size == filesize;
			g_debug("BITZI %s: %s bz->ticket = %p, filesize %s",
				G_STRFUNC, sha1_to_string(sha1), bz->ticket,
				matches ? "matches": "MISMATCH");
			if (!matches) {
				g_debug("BITZI %s: %s filesize %s, ticket says: %s",
					G_STRFUNC, sha1_to_string(sha1),
					filesize_to_string(filesize),
					filesize_to_string2(bz->size));
			}
		} else {
			g_debug("BITZI %s: %s NOT FOUND", G_STRFUNC, sha1_to_string(sha1));
		}
	}

	return bz != NULL && (0 == filesize || bz->size == filesize) ?
		bz->ticket : NULL;
}

/**
 * Initialise any bitzi specific stuff we want to here.
 */
G_GNUC_COLD void
bitzi_init(void)
{
	dbstore_kv_t kv = { SHA1_RAW_SIZE, NULL, sizeof(struct bzdata),
		sizeof(struct bzdata) + BITZI_XML_MAXLEN + 1024 };
	dbstore_packing_t packing =
		{ serialize_bzdata, deserialize_bzdata, free_bzdata };
	char *oldpath;

	/* Legacy cleanup */
	oldpath = make_pathname(settings_config_dir(), "bitzi.xml");
	(void) unlink(oldpath);
	HFREE_NULL(oldpath);

	db_bzdata = dbstore_open(db_bzdata_what, settings_gnet_db_dir(),
		db_bzdata_base, kv, packing, BITZI_DB_CACHE_SIZE, sha1_hash, sha1_eq,
		FALSE);

	bitzi_rq = slist_new();
	bitzi_prune_old();

	bitzi_sync_ev = cq_periodic_main_add(BITZI_SYNC_PERIOD, bitzi_sync, NULL);
	bitzi_prune_ev = cq_periodic_main_add(BITZI_PRUNE_PERIOD,
		bitzi_prune, NULL);

	/*
	 * Finally start the bitzi heart beat that will send requests when
	 * we set them up.
	 */

	bitzi_heartbeat_ev = cq_periodic_main_add(
		BITZI_HEARTBEAT_PERIOD, bitzi_heartbeat, NULL);
}

G_GNUC_COLD void
bitzi_close(void)
{
	g_return_if_fail(bitzi_rq);

	dbstore_close(db_bzdata, settings_gnet_db_dir(), db_bzdata_base);
	db_bzdata = NULL;
	slist_free_all(&bitzi_rq, cast_to_free_fn(bitzi_request_free));
	bitzi_request_free_null(&current_bitzi_request);
	cq_periodic_remove(&bitzi_heartbeat_ev);
	cq_periodic_remove(&bitzi_sync_ev);
	cq_periodic_remove(&bitzi_prune_ev);
}

/* vi: set ts=4 sw=4 cindent: */
/* -*- mode: cc-mode; tab-width:4; -*- */
