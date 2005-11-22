/*
 * $Id$
 *
 * Copyright (c) 2003, Raphael Manfredi
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
 * Token management.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#include "common.h"

RCSID("$Id$");

#include "token.h"
#include "clock.h"
#include "version.h"

#include "lib/misc.h"
#include "lib/sha1.h"
#include "lib/base64.h"
#include "lib/crc.h"
#include "lib/tm.h"
#include "lib/override.h"	/* Must be the last header included */

#define TOKEN_CLOCK_SKEW	3600		/**< +/- 1 hour */
#define TOKEN_LIFE			60			/**< lifetime of our tokens */
#define TOKEN_BASE64_SIZE	(TOKEN_VERSION_SIZE * 4 / 3)	/**< base64 size */
#define LEVEL_SIZE			(2 * G_N_ELEMENTS(token_keys))	/**< at most */
#define LEVEL_BASE64_SIZE	(LEVEL_SIZE * 4 / 3 + 3)	/**< +2 for == tail */

/*
 * Keys are generated through "od -x /dev/random".
 * There can be up to 2^5 = 32 keys per version.
 */

static const gchar *keys_093_1[] = {
	"8bd8 5c21 1f38 b433 f6bb 8b9c d3ed cbdb",
	"550c 0a1e d6af ba66 11cb 2e38 348a 2cba",
	"793c 2d05 3eae c7fb 75af 8cc8 5952 cf7b",
	"3af4 5190 0c8c efde acdf e12d 3687 4fc4",
	"515d 09ef a9b4 e53e f60f 4a72 6eaa 371a",
	"f947 8d4b ead0 abae 972a 8d73 e521 f914",
	"72c0 809a 66ec 4979 345b a28f ad46 4179",
	"3b43 49d4 5517 38ea 5ab6 b088 1b79 b603",
	"5cd2 69d4 f187 907e 096c c648 adea c40a",
	"9ce0 f178 3238 905d b831 8f9b 031e adb2",
	"6125 2bce 1b0e c97a d5b8 81ac d808 2369",
	"790f 0ca8 91b9 3d94 86f8 6f1e d3d2 198a",
	"e01a 668f 9749 9037 fdf4 a78c 1db8 4381",
	"a019 5ad1 595e 5b72 7fc9 5aea 1799 89ed",
	"db94 b4c2 6c3d a31e d7e4 8731 0784 1fb8",
	"ee48 01f0 40d7 e57b fd0d d3be 84f8 fbe8",
};

static const gchar *keys_095[] = {
	"a4d6 1ffa 2f74 8377 37bc ed80 d041 3976",
	"659f 19f0 7649 6b98 a9b6 d792 34f2 b020",
	"394c 56f2 eff2 ff9b aaae 2b42 9fa6 9b21",
	"3c1a 4be1 fbb3 407f b890 8b48 473a 7efe",
	"0ce6 62c8 064d 9d01 86ae c74d 94fe 8729",
	"245d c44d 485c 955c e5dc c4b4 3377 b51a",
	"a88a 875e f61f 02db bab7 5dab e419 ad96",
	"882c 6d4e f847 11a5 2c60 d949 1ee5 b837",
	"9c22 436c e33b 39bb 4074 b292 4137 b6f0",
	"482f cc27 dc1e d20b 09d1 fab8 7aae 899f",
	"b80d 4624 d321 acb9 6257 ab7e 9a85 b614",
	"3079 31b7 04e3 46fb c417 618a 14b6 812f",
	"512a 3952 b884 fab5 3144 208f 34c7 b666",
	"1b73 dabc 00bf 6b7e 9d83 bf6a b8b0 cadd",
	"a07a fd93 7357 e911 4903 6bac 6401 b593",
	"4372 2239 823d 2f4d 0dd8 cfd2 e755 f870",
	"06b6 9797 e289 6cd2 15d4 3380 428e 4725",
	"a23a 0699 0453 73bd 2e7a 879b 6fec 5151",
	"91c0 086f 1ba3 12b5 9d0a ee3e 0e83 808f",
	"5f9f 1935 9e39 495d 0873 9036 c6ff eaae",
};

static const gchar *keys_096[] = {
	"bea7 69a5 a647 f605 46b0 d155 2ba6 cee7",
	"68b0 2cf3 2c1a 8ae0 a72d f5c0 e77b bba8",
	"856e 4221 1470 a903 193e 2cc9 79a5 5337",
	"59c3 3f96 fbc0 0397 0356 6500 fc72 41b6",
	"e0f3 9f6c 16d7 4231 cd00 e991 b511 db07",
	"e765 cc0e 8672 692c cdc6 3b57 f178 cf59",
	"3120 1d5a ffc2 4ad8 bd4b bb38 bf99 b026",
	"8b39 85dd af31 86a5 2e7e 0b95 f030 482b",
	"5107 a6b7 4013 3439 3dae b5b4 e679 a401",
	"7d65 9e48 ee7e 7078 286b 29e9 e9be 296a",
	"e82d 1335 53d0 28c1 3423 7b30 6358 de81",
	"8b27 3698 03a2 6889 3bdd d095 34b6 0629",
	"b178 7abb 38cd 1084 f861 f1b2 05ab 28bc",
	"1253 e83d 6ee1 739e d7fe cb08 0527 3b3b",
	"13cb 0ec4 7784 2bd3 728a 3cbb 7900 c25c",
	"77da a447 ea85 ca52 4867 abae c992 aca3",
	"232d 40d4 2d6f 473c 411a 2beb bb1c b72c",
	"f62d be65 19a3 63c2 3714 e224 bf31 b565",
	"34b8 c34b aebb 844e 8080 da67 036b 1fbb",
	"e824 cbee 3b74 9c99 e808 ac6c 079b 1d16",
};

/**
 * Describes the keys to use depending on the version.
 */
struct tokkey {
	version_t ver;		/**< Version number */
	const gchar **keys;	/**< Keys to use */
	guint count;		/**< Amount of keys defined */
} token_keys[] = {
	/* Keep this array sorted by increasing timestamp */
	{
		{ 0, 93, 1, '\0', 0, 1072566000 },			/* 28/12/2003 */
		keys_093_1, G_N_ELEMENTS(keys_093_1),
	},
	{
		{ 0, 95, 0, 'u', 0, 1101510000 },			/* 2004-11-27 */
		keys_095, G_N_ELEMENTS(keys_095),
	},
	{
		{ 0, 96, 0, 'b', 0, 1132614000 },			/* 2005-11-22 */
		keys_096, G_N_ELEMENTS(keys_096),
	},
};

/**
 * Token validation errors.
 */

static const gchar *tok_errstr[] = {
	"OK",							/**< TOK_OK */
	"Bad length",					/**< TOK_BAD_LENGTH */
	"Bad timestamp",				/**< TOK_BAD_STAMP */
	"Bad key index",				/**< TOK_BAD_INDEX */
	"Failed checking",				/**< TOK_INVALID */
	"Not base64-encoded",			/**< TOK_BAD_ENCODING */
	"Keys not found",				/**< TOK_BAD_KEYS */
	"Bad version string",			/**< TOK_BAD_VERSION */
	"Version older than expected",	/**< TOK_OLD_VERSION */
	"Level not base64-encoded",		/**< TOK_BAD_LEVEL_ENCODING */
	"Bad level length",				/**< TOK_BAD_LEVEL_LENGTH */
	"Level too short",				/**< TOK_SHORT_LEVEL */
	"Level mismatch",				/**< TOK_INVALID_LEVEL */
	"Missing level",				/**< TOK_MISSING_LEVEL */
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const gchar *tok_strerror(tok_error_t errnum)
{
	if ((gint) errnum < 0 || errnum >= G_N_ELEMENTS(tok_errstr))
		return "Invalid error code";

	return tok_errstr[errnum];
}

/**
 * Based on the timestamp, determine the proper token keys to use.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *find_tokkey(time_t now)
{
	time_t adjusted = now - VERSION_ANCIENT_BAN;
	const struct tokkey *tk;
	guint i;

	for (i = 0; i < G_N_ELEMENTS(token_keys); i++) {
		tk = &token_keys[i];
		if (tk->ver.timestamp > adjusted)
			return tk;
	}

	return NULL;
}

/**
 * Pickup a key randomly.
 *
 * @returns the key string and the index within the key array into `idx'
 * and the token key structure used in `tkused'.
 */
static const gchar *random_key(
	time_t now, guint *idx, const struct tokkey **tkused)
{
	static gboolean warned = FALSE;
	guint random_idx;
	const struct tokkey *tk;

	tk = find_tokkey(now);

	if (tk == NULL) {
		if (!warned) {
			g_warning("did not find any token key, version too ancient");
			warned = TRUE;
		}

		tk = &token_keys[0];	/* They'll have problems with their token */
	}

	random_idx = random_value(tk->count - 1);
	*idx = random_idx;
	*tkused = tk;

	return tk->keys[random_idx];
}

/**
 * Generate new token for given version string.
 */
static gchar *tok_generate(time_t now, const gchar *version)
{
	gchar token[TOKEN_BASE64_SIZE + 1];
	gchar digest[TOKEN_VERSION_SIZE];
	gchar lvldigest[LEVEL_SIZE];
	gchar lvlbase64[LEVEL_BASE64_SIZE + 1];
	const struct tokkey *tk;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
	guint8 seed[3];
	guint32 now32;
	gint lvlsize;
	gint klen;
	gint i;

	/*
	 * Compute token.
	 */

	key = random_key(now, &idx, &tk);
	seed[0] = random_value(0xff);
	seed[1] = random_value(0xff);
	seed[2] = random_value(0xff) & 0xe0;	/* Upper 3 bits only */
	seed[2] |= idx;							/* Has 5 bits for the index */

	now = clock_loc2gmt(now);				/* As close to GMT as possible */

	now32 = (guint32) htonl((guint32) now);
	memcpy(digest, &now32, 4);
	memcpy(digest + 4, &seed, 3);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (guint8 *) key, strlen(key));
	SHA1Input(&ctx, (guint8 *) digest, 7);
	SHA1Input(&ctx, (guint8 *) version, strlen(version));
	SHA1Result(&ctx, (guint8 *) digest + 7);

	/*
	 * Compute level.
	 */

	lvlsize = G_N_ELEMENTS(token_keys) - (tk - token_keys);
	now32 = crc32_update_crc(0, digest, TOKEN_VERSION_SIZE);
	klen = strlen(tk->keys[0]);

	for (i = 0; i < lvlsize; i++, tk++) {
		guint j;
		guint32 crc = now32;
		const guchar *c = (const guchar *) &crc;

		for (j = 0; j < tk->count; j++)
			crc = crc32_update_crc(crc, tk->keys[j], klen);

		crc = htonl(crc);
		lvldigest[i*2] = c[0] ^ c[1];
		lvldigest[i*2+1] = c[2] ^ c[3];
	}

	/*
	 * Encode into base64.
	 */

	base64_encode_into(digest, TOKEN_VERSION_SIZE, token, TOKEN_BASE64_SIZE);
	token[TOKEN_BASE64_SIZE] = '\0';

	memset(lvlbase64, 0, sizeof(lvlbase64));
	base64_encode_into(lvldigest, 2 * lvlsize, lvlbase64, LEVEL_BASE64_SIZE);

	return g_strconcat(token, "; ", lvlbase64, (void *) 0);
}

/**
 * Get a version token, base64-encoded.
 *
 * @returns a pointer to static data.
 *
 * @note
 * Token versions are only used to identify GTKG servents as such with
 * a higher level of confidence than just reading the version string alone.
 * It is not meant to be used for strict authentication management, since
 * the algorithm and the keys are exposed publicly.
 */
gchar *tok_version(void)
{
	static time_t last_generated = 0;
	static gchar *toklevel = NULL;
	time_t now = tm_time();

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (now - last_generated < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	if (toklevel != NULL)
		g_free(toklevel);

	toklevel = tok_generate(now, version_string);

	return toklevel;
}

/**
 * Get a version token for the short version string, base64-encoded.
 *
 * @returns a pointer to static data.
 */
gchar *tok_short_version(void)
{
	static time_t last_generated = 0;
	static gchar *toklevel = NULL;
	time_t now = tm_time();

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (now - last_generated < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	if (toklevel != NULL)
		g_free(toklevel);

	toklevel = tok_generate(now, version_short_string);

	return toklevel;
}

/**
 * Validate a base64-encoded version token `tokenb64' of `len' bytes.
 * The `ip' is given only for clock update operations.
 *
 * @returns error code, or TOK_OK if token is valid.
 */
tok_error_t tok_version_valid(
	const gchar *version, const gchar *tokenb64, gint len, host_addr_t addr)
{
	time_t now = tm_time();
	time_t stamp;
	guint32 stamp32;
	const struct tokkey *tk;
	const struct tokkey *rtk;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
	gchar lvldigest[1024];
	gchar token[TOKEN_VERSION_SIZE];
	gchar digest[SHA1HashSize];
	version_t rver;
	gchar *end;
	gint toklen;
	gint lvllen;
	gint lvlsize;
	gint klen;
	guint i;
	gchar *c = (gchar *) &stamp32;

	end = strchr(tokenb64, ';');		/* After 25/02/2003 */
	toklen = end ? (end - tokenb64) : len;

	/*
	 * Verify token.
	 */

	if (toklen != TOKEN_BASE64_SIZE)
		return TOK_BAD_LENGTH;

	if (!base64_decode_into(tokenb64, toklen, token, TOKEN_VERSION_SIZE))
		return TOK_BAD_ENCODING;

	memcpy(&stamp32, token, 4);
	stamp = (time_t) ntohl(stamp32);

	/*
	 * Use that stamp, whose precision is TOKEN_LIFE, to update our
	 * clock skew if necessary.
	 */

	clock_update(stamp, TOKEN_LIFE, addr);

	if (ABS(stamp - clock_loc2gmt(now)) > TOKEN_CLOCK_SKEW)
		return TOK_BAD_STAMP;

	tk = find_tokkey(stamp);				/* The keys they used */
	if (tk == NULL)
		return TOK_BAD_KEYS;

	idx = (guchar) token[6] & 0x1f;			/* 5 bits for the index */
	if (idx >= tk->count)
		return TOK_BAD_INDEX;

	key = tk->keys[idx];

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (guint8 *) key, strlen(key));
	SHA1Input(&ctx, (guint8 *) token, 7);
	SHA1Input(&ctx, (guint8 *) version, strlen(version));
	SHA1Result(&ctx, (guint8 *) digest);

	if (0 != memcmp(token + 7, digest, SHA1HashSize))
		return TOK_INVALID;

	if (!version_fill(version, &rver))		/* Remote version */
		return TOK_BAD_VERSION;

	if (version_cmp(&rver, &tk->ver) < 0)
		return TOK_OLD_VERSION;

	/*
	 * Verify level.
	 */

	if (end == NULL) {						/* No level */
		if (rver.timestamp >= 1046127600)	/* 25/02/2003 */
			return TOK_MISSING_LEVEL;
		return TOK_OK;
	}

	lvllen = len - toklen - 2;				/* Forget about "; " */
	end += 2;								/* Skip "; " */

	if (lvllen >= (gint) sizeof(lvldigest) || lvllen <= 0)
		return TOK_BAD_LEVEL_LENGTH;

	if (lvllen & 0x3)
		return TOK_BAD_LEVEL_LENGTH;

	lvllen = base64_decode_into(end, lvllen, lvldigest, sizeof(lvldigest));

	if (lvllen == 0 || (lvllen & 0x1))
		return TOK_BAD_LEVEL_ENCODING;

	g_assert(lvllen >= 2);
	g_assert((lvllen & 0x1) == 0);

	/*
	 * Only check the highest keys we can check.
	 */

	lvllen /= 2;							/* # of keys held remotely */
	lvlsize = G_N_ELEMENTS(token_keys) - (tk - token_keys);
	lvlsize = MIN(lvllen, lvlsize);

	g_assert(lvlsize >= 1);

	rtk = tk + (lvlsize - 1);				/* Keys at that level */

	stamp32 = crc32_update_crc(0, token, TOKEN_VERSION_SIZE);
	klen = strlen(rtk->keys[0]);

	for (i = 0; i < rtk->count; i++)
		stamp32 = crc32_update_crc(stamp32, rtk->keys[i], klen);

	stamp32 = htonl(stamp32);

	lvlsize--;								/* Move to 0-based offset */

	if (lvldigest[2*lvlsize] != (c[0] ^ c[1]))
		return TOK_INVALID_LEVEL;

	if (lvldigest[2*lvlsize+1] != (c[2] ^ c[3]))
		return TOK_INVALID_LEVEL;

	for (i = 0; i < G_N_ELEMENTS(token_keys); i++) {
		rtk = &token_keys[i];
		if (rtk->ver.timestamp > rver.timestamp) {
			rtk--;							/* `rtk' could not exist remotely */
			break;
		}
	}

	if (lvlsize < rtk - tk)
		return TOK_SHORT_LEVEL;

	return TOK_OK;
}

/**
 * Check whether the version is too ancient to be able to generate a proper
 * token string identifiable by remote parties.
 */
gboolean tok_is_ancient(time_t now)
{
	return find_tokkey(now) == NULL;
}

/* vi: set ts=4: */
