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

RCSID("$Id$")

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

static const gchar *keys_096b[] = {
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

static const gchar *keys_096[] = {
	"261c 78d6 fcc5 d96e 2649 061a 4534 29b5",
	"2629 7de4 8edd 43eb 6c47 2b01 caf1 5e86",
	"50c2 076a 5a15 5c0c 27fb eda0 381b 2eb7",
	"851c 2fff 0a31 c6ad 2181 4d31 8fea 492c",
	"c8f8 01a8 2975 cc75 417c 63aa 5403 5b41",
	"045b aca8 5227 7d0f 232a 7c6a d713 d5dd",
	"f281 f0c5 23fb cf66 5ca4 6a3d 9df1 dc6a",
	"0fc8 ac1f 76da 5f7e 3459 bd7d 3175 76cf",
	"f981 7fe7 06d1 d3d9 9d69 1e47 b8d0 9adf",
	"7422 4730 d7d0 9293 002c b700 8979 dccf",
	"c328 4be8 9008 8d52 cbd6 2f45 30ba 9467",
	"cdc2 2db6 6bba 312c 10fb 246b b371 be09",
	"017a 3e68 90e0 e0f0 8124 3cc8 fcf8 3bf7",
	"2e56 a817 02b3 0819 d971 a245 c33e 42fc",
	"0ee7 8801 db48 f2d6 64ad 6c42 bac3 f7ee",
	"c758 af82 e6a3 aa5f 1da0 c127 4541 1ce8",
	"2edc 2b16 9e66 a191 9e45 2e66 ea98 0c7b",
	"438a a8ed d27e 711e 631e 2372 a013 d095",
	"45cf 2974 2086 d00e efec 9277 05a3 bff2",
	"bb86 594c 74e2 432d 5444 8a85 82c8 d098",
	"64f4 9829 a541 8625 578c fd90 639c f42b",
	"3084 a2bc f4ed 8b3c 2a2b 1834 cd8e 3f8b",
};

static const gchar *keys_096_1[] = {
	"ac3e f7b1 af37 e22c ce69 f25f 8dd2 8e51",
	"7c66 fddd f8d9 8bde 8c6c 072a 1935 2237",
	"6aab e420 921d b32c 09e9 34b8 e403 525d",
	"3014 53b9 64fd 95a5 e52b e9c9 99f6 323e",
	"dacd 5a3d 34e5 d280 fd58 1af0 6fef ac72",
	"020a 4163 41f6 f089 b285 0321 48df 44fb",
	"8059 f2a1 e91a f319 2ad2 e13d 6634 6eb6",
	"4853 1dba a1bf 9386 8b24 af94 f112 9e5b",
	"e053 3cd9 87ba 9dd7 c4c4 c32e 9bd2 a61a",
	"8625 b5d3 b531 18b9 8716 403d fa26 4a5b",
	"433c 60fb eb1b c33b 139b 1594 9c69 91e4",
	"4a47 e00b 2933 f634 d194 6376 b777 fbb8",
	"70ec 73f6 7ee3 ac83 a899 5e84 1d82 371c",
	"2b53 cad1 b7d6 ad9e f4a1 96bd 8c37 264e",
	"20ed fcbc feb8 f96d e037 af6f 2486 ff84",
	"109c 5d02 d4df 33ac ead3 fe7c 8bc2 e87f",
	"1392 547e 3abe b83c 3e15 8416 0b7b 5d89",
	"a546 f15e 797e 8081 9d88 0c82 5afc 4c2e",
	"fe97 9602 dcd7 efb6 74ee 35ba ea4a 9158",
	"396c 5dcc 43a3 9577 a610 9e89 7079 5862",
	"9e54 e398 f5b0 1e02 272d 87a7 e36e 10a2",
	"9536 535d 0e1b e017 2f73 a0bc c01a dcf9",
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
		{ 0, 96, 0, 'b', 0, 0, 1132614000 },		/* 2005-11-22 */
		keys_096b, G_N_ELEMENTS(keys_096b),
	},
	{
		{ 0, 96, 0, '\0', 0, 0, 1138057200 },		/* 2006-01-24 */
		keys_096, G_N_ELEMENTS(keys_096),
	},
	{
		{ 0, 96, 1, '\0', 0, 0, 1140562800 },		/* 2006-02-22 */
		keys_096_1, G_N_ELEMENTS(keys_096_1),
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
	"Missing build number",			/**< TOK_MISSING_BUILD */
	"Wrong build number",			/**< TOK_WRONG_BUILD */
};

/**
 * @return human-readable error string corresponding to error code `errnum'.
 */
const gchar *tok_strerror(tok_error_t errnum)
{
	STATIC_ASSERT(G_N_ELEMENTS(tok_errstr) == TOK_MAX_ERROR);

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

	if (end == NULL)
		return TOK_MISSING_LEVEL;

	/*
	 * Verify build.
	 */

	if (rver.timestamp >= 1156543200) {		/* 2006-08-26 */
		if (0 == rver.build)
			return TOK_MISSING_BUILD;
		if (rver.build < tk->ver.build)
			return TOK_WRONG_BUILD;
	}

	/*
	 * Verify level.
	 */

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
