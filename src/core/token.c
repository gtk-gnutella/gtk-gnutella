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

static const gchar *keys_096_2[] = {
	"fa04 15ab 5f1d 52cc 5a5d 865b 27b5 c5a5",
	"7f0b 5987 86ec a100 85c5 d0fc f504 b58c",
	"2b06 f3a7 05a8 2769 2679 1ab9 9ba0 2360",
	"4c3f 5636 3ba7 471b 43ea 3350 d71f b0fd",
	"00bf c06b 3703 78e3 87c2 ea7a 3a8c b684",
	"5103 6580 7be1 9cab fecb 3c46 12a9 4287",
	"a5c5 a8f0 d10e 2202 526a f62e d615 afe2",
	"32b8 5d94 5e4b c936 8703 2386 5f67 aa6b",
	"10f8 e454 5d88 ec00 7e44 636f cda5 e45a",
	"0409 a3aa b426 c79a 0d17 8895 f595 d744",
	"9f9f c223 b290 0e7b 0950 d991 1ed9 bae0",
	"a297 f754 a185 81f1 d57d 7b82 fde8 c7d1",
	"d3de 3537 3271 0649 c2e8 de86 842e 1b79",
	"86d1 3b44 b4eb 4842 1736 d42b 8b0b ce30",
	"3b93 8172 1331 99fe 1423 c188 642b c45b",
	"f013 188b 833d de3b 49d9 3709 6067 fd88",
	"42ad 9a84 808e 7638 601a 6d33 9543 0827",
	"ba4e d65e 1768 320d c88f 7b16 3194 0e08",
	"ef2b e292 e29f c2ef 96a2 bc3c fbcb bb96",
	"71a7 a828 ce50 d736 11a5 e687 ad42 ce5c",
	"266b be05 0d52 f825 37e8 ffe3 b4f1 282c",
	"e75d b41f 2332 309d c3ee 4dd7 060d fc08",
};

static const gchar *keys_096_3[] = {
	"ca43 91c3 d080 c596 5ec2 9e17 5011 ebb6",
	"4b53 6e49 a6a8 c045 c0c4 bfc7 8c54 4d9a",
	"411b fc41 6643 ba3a 527a 52c9 4a72 3db0",
	"13aa 0ae0 54f8 c9b3 2af8 3faa c363 cc4b",
	"ebd2 69db d313 b7da 2425 9412 1ce3 16be",
	"faf3 1626 20db 8b5a d448 0887 a22e c156",
	"e925 4acd 65d3 f64d daea 0766 b260 ae03",
	"62ff b5f7 02bf 189c a17f 7fec 3845 2d8e",
	"efe6 4c84 2149 aee7 0e61 9192 b293 8f5d",
	"47ec defc f33c 698e a8d4 eb06 c5bd d062",
	"4aab bc51 4caf f6c2 676d f60c 6e6e 6ad6",
	"afad 3bbc 4981 0a4d a0b9 a247 697f 8052",
	"c244 2aff d148 3a7b 3da0 f837 7207 6795",
	"8b8b 3562 29c5 3d4c 3e9a 46ca 47ff 5e18",
	"4973 9c6e bbb0 6a26 29e9 92d6 300b c4cb",
	"c9fd b78f 37d5 029d 7e99 ce84 d052 7efb",
	"1520 f5bd 1a53 8250 ca3e 8ced 4d1f 1b38",
	"850a 2b7b f978 16fa 3465 a243 c66f 3796",
	"fdf1 fbdf 54bb 32a0 44b1 3892 30b4 ea5c",
	"8a44 58ba ddac b04f 9806 1bce 7a7d 486e",
	"6cc1 768e 0d38 e314 c388 88be 7bf9 2dea",
	"c994 a380 dde0 baff 8900 c9e5 d94c b9ff",
};

static const gchar *keys_096_4[] = {
	"4313 0c48 3747 a2b5 580c f7a5 7adc d83f",
	"94c7 eeca e5c1 c4c4 a09d 243c b846 6917",
	"3188 446a 39da fca8 11ae ef30 8073 f61a",
	"146a 985b 20bc 639e 971e 5fd4 304f f02b",
	"a99f a005 5c50 bf6a 721f 7c88 e4d4 3a1c",
	"e28c 2482 40b0 a41d 4d30 1326 1227 20b1",
	"070a 52ce af8f 2d26 5d01 c5bc 356e 9e3c",
	"f018 d34c 91a6 4653 d397 7bcc 3d64 7b15",
	"bc64 25b4 ac36 0fce 7097 9809 31da 71b6",
	"4e40 d31e d36d 1ade 53ec 0a37 21a0 10fd",
	"1dbb 4288 a191 8016 1bf8 956f 36aa c9c8",
	"45be 9349 07c7 2455 ed07 ab54 f014 fd32",
	"047c 4878 4809 00a2 bc3c 48bf 701c 2123",
	"225d da36 c6ef 96db deb4 ad03 dba6 ce97",
	"c4e9 6cbf 2f1c fd6f 1047 57fc 4c8b 8058",
	"d131 9d1e 161a bbdb d39c 2e0a 1b5e 5546",
	"a0e1 36b2 52d1 efec 6649 608a a3ba 687a",
	"46b7 0f59 b70a 8ce4 147f 18c2 4307 6a30",
	"b8e7 c642 de0c 9498 bdf0 5afe ae6c 8d21",
	"6352 4957 2f40 56f2 0bfe 44c6 173a 9615",
	"4ec5 9106 ab7c 019b 4b87 348a 13eb 82f2",
	"a2d0 b172 becb 8516 8f17 b2f4 80e2 4488",
};

static const gchar *keys_096_5[] = {
	"29af ab9b fc6b 58b7 9031 cf87 f7cc 3c63",
	"5dee 3d3f efb1 ac8d 27f4 2fa9 b1c3 705b",
	"117f 9530 1881 6432 ecf4 780e dbfc 45c9",
	"4b00 06d3 7e49 563b cc0a 3ace bb1d 3f35",
	"6a73 45a2 b30a 2096 c2a4 971c 68a7 5d87",
	"f88e 3f5c d07d e76c 0e1b a94c c93f b40f",
	"40b3 d33c f3c8 06e7 c565 7736 0408 9265",
	"9d43 7091 3bad 0f2d 1554 72d4 c7ec b505",
	"a519 2d25 0f9d 11ca a1cd 3d87 cb5d cb9d",
	"acab b860 7c78 6989 1c9e 2314 c917 dc48",
	"027b 7e7e e566 fb10 d799 e2fd f807 5279",
	"e069 951d 3c2a accf d119 bd4e 0755 e59c",
	"8e4e cd64 d147 597a 32bd d977 6b38 40d3",
	"ee12 9716 e9f7 74f2 bec3 c7fb 915d 11e4",
	"2882 6581 cb85 c261 3c10 af8e 8eec 5761",
	"92ca 01b0 e81c 6ee5 9b8f ae1e 7d57 422b",
	"8eac 6012 99ac 2157 4bf5 df1c 074b 9110",
	"133a 694a b768 3034 693b 57ad 06ab d4e7",
	"477c faed 3a17 d265 7916 79cc 691d c50f",
	"f271 3f09 2b26 095b b4f3 5893 f86d 7814",
	"ecf3 0cb2 261b 3bd1 5f22 c2f5 4e90 d1d6",
	"1f2f 4d01 aee4 8a3b 04c7 b1a7 7557 1d7e",
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
		{ 0, 96, 0, '\0', 0, 0, 1138057200 },		/* 2006-01-24 */
		keys_096, G_N_ELEMENTS(keys_096),
	},
	{
		{ 0, 96, 1, '\0', 0, 0, 1140562800 },		/* 2006-02-22 */
		keys_096_1, G_N_ELEMENTS(keys_096_1),
	},
	{
		{ 0, 96, 2, '\0', 0, 0, 1161025877 },		/* 2006-10-16 */
		keys_096_2, G_N_ELEMENTS(keys_096_2),
	},
	{
		{ 0, 96, 3, '\0', 0, 0, 1163108781 },		/* 2006-11-09 */
		keys_096_3, G_N_ELEMENTS(keys_096_3),
	},
	{
		{ 0, 96, 4, '\0', 0, 0, 1183775000 },		/* 2007-07-07 */
		keys_096_4, G_N_ELEMENTS(keys_096_4),
	},
	{
		{ 0, 96, 5, '\0', 0, 0, 1207083000 },		/* 2008-04-01 */
		keys_096_5, G_N_ELEMENTS(keys_096_5),
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
const gchar *
tok_strerror(tok_error_t errnum)
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
static const struct tokkey *
find_tokkey(time_t now)
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
 * Find latest token structure that is anterior or equal to the remote version.
 */
static const struct tokkey *
find_latest(const version_t *rver)
{
	guint i;
	const struct tokkey *tk;
	const struct tokkey *result = NULL;

	for (i = 0; i < G_N_ELEMENTS(token_keys); i++) {
		tk = &token_keys[i];
		if (version_build_cmp(&tk->ver, rver) > 0)
			break;
		result = tk;
	}

	return result;
}

/**
 * Pickup a key randomly.
 *
 * @returns the key string and the index within the key array into `idx'
 * and the token key structure used in `tkused'.
 */
static const gchar *
random_key(time_t now, guint *idx, const struct tokkey **tkused)
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
static gchar *
tok_generate(time_t now, const gchar *version)
{
	gchar token[TOKEN_BASE64_SIZE + 1];
	gchar digest[TOKEN_VERSION_SIZE];
	gchar lvldigest[LEVEL_SIZE];
	gchar lvlbase64[LEVEL_BASE64_SIZE + 1];
	const struct tokkey *tk;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
    struct sha1 sha1;
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
	memcpy(&digest[0], &now32, 4);
	memcpy(&digest[4], &seed, 3);

	SHA1Reset(&ctx);
	SHA1Input(&ctx, key, strlen(key));
	SHA1Input(&ctx, digest, 7);
	SHA1Input(&ctx, version, strlen(version));
	SHA1Result(&ctx, &sha1);
	memcpy(&digest[7], sha1.data, SHA1_RAW_SIZE);

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
gchar *
tok_version(void)
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
gchar *
tok_short_version(void)
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
tok_error_t
tok_version_valid(
	const gchar *version, const gchar *tokenb64, gint len, host_addr_t addr)
{
	time_t now = tm_time();
	time_t stamp;
	guint32 stamp32;
	const struct tokkey *tk;
	const struct tokkey *rtk;
	const struct tokkey *latest;
	guint idx;
	const gchar *key;
	SHA1Context ctx;
	gchar lvldigest[1024];
	gchar token[TOKEN_VERSION_SIZE];
	struct sha1 digest;
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
	SHA1Input(&ctx, key, strlen(key));
	SHA1Input(&ctx, token, 7);
	SHA1Input(&ctx, version, strlen(version));
	SHA1Result(&ctx, &digest);

	if (0 != memcmp(&token[7], digest.data, SHA1_RAW_SIZE))
		return TOK_INVALID;

	if (!version_fill(version, &rver))		/* Remote version */
		return TOK_BAD_VERSION;

	if (version_build_cmp(&rver, &tk->ver) < 0)
		return TOK_OLD_VERSION;

	if (end == NULL)
		return TOK_MISSING_LEVEL;

	latest = find_latest(&rver);
	if (latest == NULL)						/* Unknown in our key set */
		return TOK_OLD_VERSION;

	/*
	 * Verify build.
	 */

	if (rver.timestamp >= 1156543200) {		/* 2006-08-26 */
		if (0 == rver.build)
			return TOK_MISSING_BUILD;
		if (rver.build < latest->ver.build)
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
gboolean
tok_is_ancient(time_t now)
{
	return find_tokkey(now) == NULL;
}

/* vi: set ts=4: */
