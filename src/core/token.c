/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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

#include "token.h"
#include "clock.h"
#include "version.h"

#include "if/gnet_property_priv.h"

#include "lib/base64.h"
#include "lib/crc.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/misc.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/stacktrace.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"	/* Must be the last header included */

#define TOKEN_CLOCK_SKEW	3600		/**< +/- 1 hour */
#define TOKEN_LIFE			60			/**< lifetime of our tokens */
#define TOKEN_BASE64_SIZE	(TOKEN_VERSION_SIZE * 4 / 3)	/**< base64 size */
#define LEVEL_SIZE			(2 * N_ITEMS(token_keys))	/**< at most */
#define LEVEL_BASE64_SIZE	(LEVEL_SIZE * 4 / 3 + 3)	/**< +2 for == tail */

/*
 * Keys are generated through "od -x /dev/random".
 * There can be up to 2^5 = 32 keys per version.
 */

static const char *keys_103_0[] = {
	"cc9e f37d eb1b 6003 a738 f3f9 404f bf1a",
	"875a b193 6db1 2f1a 9033 fc54 65f1 6504",
	"feb2 3bc7 34c8 0c4b 9bce 1f69 acb5 2bef",
	"3acc 5de7 00f0 87cb a3b7 a1ad eb6a ab29",
	"8c08 314a 7105 c059 b6c9 ec7a dfd2 e088",
	"e6bf f8fe 3edd a59b 489b ea25 564d 6ce3",
	"7143 7867 e24e c0fc 5a21 c4f7 9777 eb0a",
	"f030 abb0 7efc 09a9 fc30 94ed aaf7 037e",
	"39f3 f294 464f 4d5d 3523 c6d5 ac40 6f9e",
	"41b8 a5e2 5d9d 5ad4 663a 30cf 7430 54dc",
	"2f2f 466a 236f df5d e5ce f281 884c c865",
	"6ebb cb32 b6c8 2c0d 2403 50f2 dc9d 5441",
	"7cbc 471c 494b 365b 919e eb69 a45d 83a6",
	"a93e 83c5 abcb 1056 f488 de17 5320 d408",
	"2101 693a 7b7a f19c 131a 9021 b60b 20eb",
	"03f6 8a34 7c38 9663 df91 8675 36b2 5adf",
	"1669 ef3b 1d71 9308 3a4d 54cc 44f5 5eb9",
	"22a4 3721 d33b d16b 96ee d47c 0f26 fe28",
	"fda7 227a 778c 10cb 27c3 efce 00c0 ed72",
	"254b 6219 7944 330a d011 740e c04b bed3",
	"e496 ebb1 617d 9b2b 7642 ef78 691a b146",
	"e179 8365 25cd 5e0c 259a cfbc 9840 9550",
	"3928 130b 4522 b324 114a 7e35 ca32 1ba2",
	"170b 8d0f 7a52 12d7 03bd a6d8 f0c2 e9a2",
	"8bee a5fa 4965 f1d6 e165 ee77 fa07 3144",
	"c387 621e 28c1 17db bad4 761e 37b1 95e4",
	"dcda 416e d217 26f9 5a13 c1e8 6857 f1ab",
	"163a 67db ab6b 5021 19c2 bc4c ac10 af72",
	"97db 106f 9e85 0b52 85fd 79c0 4a42 54cb",
	"a1d0 23e5 edb2 021c fd8a f22b 2cad aeb3",
	"6f6a 5210 1d87 3303 05b3 429b c8d6 15f8",
	"677a 2a7b 1f4d f36b cb9a ca45 2c1e 4cf7",
};

static const char *keys_103_2[] = {
	"5246 1445 5509 2733 8738 c6ed 92bd 6de3",
	"f405 757f 9039 037a 40e9 8823 6a30 5bf4",
	"8045 db85 212f 22eb 0328 dd87 344c a2ed",
	"13db 7f47 8718 da99 1bc6 93f1 98b9 71b2",
	"1c4d b397 377f 954d 20e7 aed4 b46c c64c",
	"bef8 040d 6478 8eda 7986 b59a 0365 3881",
	"35af 4c72 07c1 7685 73f4 a27b 482a 3177",
	"10b3 0680 9d52 99b8 3714 d545 55ed 4ba1",
	"1e58 6ce3 e20a 1a0a a00f b56a e343 b47c",
	"9cd2 df1f f529 ab36 f4cb 01a7 c949 dcf7",
	"be79 4e53 4e03 d3f7 ab6f 935c 1f2a f53e",
	"1958 41b4 878d 2ee4 83bf bfb0 031f caa8",
	"3a28 fa6e 2976 e97f 3b7b b3dd 47aa 289f",
	"c15d b5c9 f7ab 0b98 5a4f f5ee 08bb bba0",
	"7691 e4ca 087f 516b 6b16 785a a071 6758",
	"628b 066d 59da a79f dbc1 7707 b68f 0778",
	"0361 6f01 3a6f 1886 2f02 b5c3 44cf c882",
	"99e1 8789 d7c0 d948 1fcc 3acf fe57 51e8",
	"b79e d24a 7612 03ea 0a31 bdee efee c894",
	"59b7 2607 bf24 c2f0 7036 fade 2a51 45d8",
	"607c 9e04 8dd7 14c6 df0e 99a9 5769 0dfa",
	"14f2 87a3 1943 ba50 091d 3867 2fb9 e939",
	"1610 1d32 780e b2ed ecd0 6c18 b717 6b53",
	"21ec 6545 45f8 5189 cf3e 803d e719 fd76",
	"3f5a 3f36 3ffa 4e90 40ca e1c7 85c3 78ff",
	"7041 a691 527d 11f6 7cae 8018 5bd0 ad42",
	"95a8 fe44 1dd5 e628 aa7b f2be 2a59 d233",
	"62af 0b33 0333 8096 e42b 8472 ab68 c2fd",
};

#define KEYS(x)		keys_ ## x, N_ITEMS(keys_ ## x)

/**
 * Describes the keys to use depending on the version.
 */
struct tokkey {
	version_t ver;		/**< Version number */
	const char **keys;	/**< Keys to use */
	uint count;			/**< Amount of keys defined */
} token_keys[] = {
	/* maj min PL  tag lvl #  timestamp     key array          ISO date   */
	{ { 1, 3,  0, '\0', 0, 0, 1772751600 }, KEYS(103_0) },	/* 2026-03-06 */
	{ { 1, 3,  1, '\0', 0, 0, 1773010800 }, KEYS(103_0) },	/* 2026-03-09 */
	{ { 1, 3,  2, '\0', 0, 0, 1791756000 }, KEYS(103_2) },	/* 2026-10-12 */
};

#undef KEYS

/**
 * Token validation errors.
 */

static const char *tok_errstr[] = {
	"OK",							/**< TOK_OK */
	"Bad length",					/**< TOK_BAD_LENGTH */
	"Bad timestamp",				/**< TOK_BAD_STAMP */
	"Bad key index",				/**< TOK_BAD_INDEX */
	"Failed SHA-1 checking",		/**< TOK_INVALID */
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
const char *
tok_strerror(tok_error_t errnum)
{
	STATIC_ASSERT(N_ITEMS(tok_errstr) == TOK_MAX_ERROR);

	if (UNSIGNED(errnum) >= N_ITEMS(tok_errstr))
		return "Invalid error code";

	return tok_errstr[errnum];
}

/*
 * This is the date when we started to remove banning of old versions.
 *
 * Basically, they no longer expire because the Gnutella protocol is stable.
 * The only reason to upgrade would be bug fixing, not incompatibilities.
 */
#define TOK_POLICY_DATE_NOBAN	1772751600		/* 2026-03-06 */

/**
 * Based on the timestamp, determine the proper token keys to use limiting
 * to the first ``count'' items.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *
find_tokkey_upto(size_t count)
{
	const struct tokkey *tk;

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: count=%zu, from %s()",
			G_STRFUNC, count, stacktrace_caller_name(1));
	}

	g_assert(count <= N_ITEMS(token_keys));

	/*
	 * Since TOK_POLICY_DATE_NOBAN, the remote servent always chooses
	 * the latest it has available.
	 * 		-- RAM, 2026-10-13
	 */

	tk = &token_keys[count - 1];

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: (new) latest=%s, ver.timestamp=%u",
			G_STRFUNC, size_t_to_string(count - 1),
			(unsigned) tk->ver.timestamp);
	}

	if (tk->ver.timestamp >= TOK_POLICY_DATE_NOBAN)
		return tk;

	return NULL; /* Sorry, has expired */
}

/**
 * Based on the timestamp, determine the proper token keys to use limiting
 * to the first ``count'' items.
 *
 * @return the suitable keys, falling back to the last keyset in the table
 * if we can't find any suitable keys.
 */
static const struct tokkey *
find_tokkey_upto_fallback(time_t now, size_t count)
{
	const struct tokkey *tk;

	(void) now;

	tk = find_tokkey_upto(count);

	if (NULL == tk) {
		g_assert(count <= N_ITEMS(token_keys));
		tk = &token_keys[count - 1];

		if (GNET_PROPERTY(version_debug) > 4) {
			g_debug("%s: got NULL, will use index %lu", G_STRFUNC, count - 1UL);
		}
	}

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: returning %p (%u.%u.%u)",
			G_STRFUNC, cast_to_constpointer(tk),
			tk->ver.major, tk->ver.minor, tk->ver.patchlevel);
	}

	g_assert(tk != NULL);

	return tk;
}

/**
 * Based on the timestamp, determine the proper token keys to use.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static inline const struct tokkey *
find_tokkey(time_t now)
{
	/*
	 * Starting with 1.3.0, we no longer say:
	 *
	 * 		return find_tokkey_upto(now, N_ITEMS(token_keys));
	 *
	 * because we no longer wish to expire tokens. There will be no
	 * ancient versions any more, as the Gnutella protocol and
	 * gtk-gnutella are both completely stable and unlikely to evolve.
	 *
	 * Therefore, use the latest keys available, always.
	 * 		--RAM, 2026-03-06
	 */

	(void) now;	/* Parameter no longer used */

	return &token_keys[N_ITEMS(token_keys) - 1];
}

/**
 * Based on the timestamp and their advertised version, find out the
 * token key they used.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *
find_tokkey_version(const version_t *ver, time_t now)
{
	uint i;

	/*
	 * All versions before r16370 used the first key set when they expired.
	 * If we're more recent, we probably have a stripped list of past key
	 * sets, and therefore cannot validate their token.
	 *
	 * All versions after we switched to git can be checked provided we still
	 * have a copy of the keys that they had at the time they were released.
	 * The git switch occurred on 2011-09-11.
	 */

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: looking for proper keyset (theirs is %u.%u.%u)",
			G_STRFUNC, ver->major, ver->minor, ver->patchlevel);
	}

	/*
	 * Expired servents will always use their last key set.  Even if we're
	 * more recent, we can try to validate by mimicing the behaviour of
	 * these servents.
	 *
	 * We determine the index of the last key set that they must know about
	 * and we look for the token up to that index only.
	 */

	for (i = 0; i < N_ITEMS(token_keys); i++) {
		const struct tokkey *tk = &token_keys[i];
		if (version_cmp(ver, &tk->ver) <= 0) {
			if (GNET_PROPERTY(version_debug) > 4) {
				g_debug("%s: matched at %u.%u.%u, index=%u", G_STRFUNC,
					tk->ver.major, tk->ver.minor, tk->ver.patchlevel, i);
			}
			break;
		}
	}

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: fallback max=%u (/%zu)",
			G_STRFUNC, i, N_ITEMS(token_keys));
	}

	i++;								/* We need a count, not an index */
	i = MIN(i, N_ITEMS(token_keys));	/* In case loop did not match */

	return find_tokkey_upto_fallback(now, i);
}

/**
 * Find latest token structure that is anterior or equal to the remote version.
 */
static const struct tokkey *
find_latest(const version_t *rver)
{
	uint i;
	const struct tokkey *tk;
	const struct tokkey *result = NULL;

	for (i = 0; i < N_ITEMS(token_keys); i++) {
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
static const char *
token_random_key(time_t now, uint *idx, const struct tokkey **tkused)
{
	static bool warned = FALSE;
	uint random_idx;
	const struct tokkey *tk;

	tk = find_tokkey(now);

	if (tk == NULL) {
		if (!warned) {
			g_warning("did not find any token key, version too ancient");
			warned = TRUE;
		}

		STATIC_ASSERT(N_ITEMS(token_keys) >= 1);

		/* Pick the latest (most recent) key set from the array */
		tk = &token_keys[N_ITEMS(token_keys) - 1];
	}

	random_idx = random_value(tk->count - 1);
	*idx = random_idx;
	*tkused = tk;

	return tk->keys[random_idx];
}

static uint16
tok_crc(uint32 crc, const struct tokkey *tk)
{
	const char **keys = tk->keys;
	size_t i;

	i = tk->count;
	while (i-- > 0) {
		const char *k = *keys++;
		crc = crc32_update(crc, k, vstrlen(k));
	}
	crc ^= (crc >> 8);
	crc &= 0x00ff00ffU;
	crc |= crc >> 8;
	return crc & 0xffffU;
}

/**
 * Generate new token for given version string.
 */
static char *
tok_generate(time_t now, const char *version)
{
	char token[TOKEN_BASE64_SIZE + 1];
	char digest[TOKEN_VERSION_SIZE];
	char lvldigest[LEVEL_SIZE];
	char lvlbase64[LEVEL_BASE64_SIZE + 1];
	const struct tokkey *tk;
	uint32 crc32;
	uint idx;
	const char *key;
	SHA1_context ctx;
    struct sha1 sha1;
	int lvlsize;
	int i;

	/*
	 * Compute token.
	 */

	key = token_random_key(now, &idx, &tk);
	now = clock_loc2gmt(now);				/* As close to GMT as possible */

	poke_be32(&digest[0], now);
	random_bytes(&digest[4], 3);
	digest[6] &= 0xe0U;			/* Upper 3 bits only */
	digest[6] |= idx & 0xffU;	/* Has 5 bits for the index */

	SHA1_reset(&ctx);
	SHA1_input(&ctx, key, vstrlen(key));
	SHA1_input(&ctx, digest, 7);
	SHA1_input(&ctx, version, vstrlen(version));
	SHA1_result(&ctx, &sha1);
	memcpy(&digest[7], sha1.data, SHA1_RAW_SIZE);

	/*
	 * Compute level.
	 */

	lvlsize = N_ITEMS(token_keys) - (tk - token_keys);
	crc32 = crc32_update(0, VARLEN(digest));

	for (i = 0; i < lvlsize; i++) {
		poke_be16(&lvldigest[i*2], tok_crc(crc32, tk));
		tk++;
	}

	/*
	 * Encode into base64.
	 */

	base64_encode_into(digest, TOKEN_VERSION_SIZE, token, TOKEN_BASE64_SIZE);
	token[TOKEN_BASE64_SIZE] = '\0';

	ZERO(&lvlbase64);
	base64_encode_into(lvldigest, 2 * lvlsize, lvlbase64, LEVEL_BASE64_SIZE);

	return h_strconcat(token, "; ", lvlbase64, NULL_PTR);
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
char *
tok_version(void)
{
	static time_t last_generated = 0;
	static char *toklevel = NULL;
	time_t now = tm_time();

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (delta_time(now, last_generated) < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	HFREE_NULL(toklevel);
	toklevel = tok_generate(now, version_string);

	return NOT_LEAKING(toklevel);
}

/**
 * Get a version token for the short version string, base64-encoded.
 *
 * @returns a pointer to static data.
 */
char *
tok_short_version(void)
{
	static time_t last_generated = 0;
	static char *toklevel = NULL;
	time_t now = tm_time();

	/*
	 * We don't generate a new token each time, but only every TOKEN_LIFE
	 * seconds.  The clock skew threshold must be greater than twice that
	 * amount, of course.
	 */

	g_assert(TOKEN_CLOCK_SKEW > 2 * TOKEN_LIFE);

	if (delta_time(now, last_generated) < TOKEN_LIFE)
		return toklevel;

	last_generated = now;

	HFREE_NULL(toklevel);
	toklevel = tok_generate(now, version_short_string);

	return NOT_LEAKING(toklevel);
}

/**
 * Validate a base64-encoded version token `tokenb64' of `len' bytes.
 * The `ip' is given only for clock update operations.
 *
 * @returns error code, or TOK_OK if token is valid.
 */
tok_error_t
tok_version_valid(const char *version, const char *tokenb64, int len)
{
	time_t now = tm_time();
	time_t stamp;
	uint32 crc;
	const struct tokkey *tk;
	const struct tokkey *rtk;
	const struct tokkey *latest;
	uint idx;
	const char *key;
	SHA1_context ctx;
	char lvldigest[1024];
	char token[TOKEN_VERSION_SIZE];
	struct sha1 digest;
	version_t rver;
	char *end;
	int toklen;
	int lvllen;
	int lvlsize;
	uint i;

	end = vstrchr(tokenb64, ';');		/* After 25/02/2003 */
	toklen = end ? (end - tokenb64) : len;

	/*
	 * Verify token.
	 */

	if (toklen != TOKEN_BASE64_SIZE)
		return TOK_BAD_LENGTH;

	if (!base64_decode_into(tokenb64, toklen, token, TOKEN_VERSION_SIZE))
		return TOK_BAD_ENCODING;

	stamp = (time_t) peek_be32(&token);

	if (ABS(stamp - clock_loc2gmt(now)) > TOKEN_CLOCK_SKEW)
		return TOK_BAD_STAMP;

	if (!version_fill(version, &rver))		/* Remote version */
		return TOK_BAD_VERSION;

	tk = find_tokkey_version(&rver, stamp);	/* The keys they used */
	if (tk == NULL)
		return TOK_BAD_KEYS;

	idx = (uchar) token[6] & 0x1f;			/* 5 bits for the index */
	if (idx >= tk->count)
		return TOK_BAD_INDEX;

	key = tk->keys[idx];

	SHA1_reset(&ctx);
	SHA1_input(&ctx, key, vstrlen(key));
	SHA1_input(&ctx, token, 7);
	SHA1_input(&ctx, version, vstrlen(version));
	SHA1_result(&ctx, &digest);

	if (0 != memcmp(&token[7], digest.data, SHA1_RAW_SIZE))
		return TOK_INVALID;

	if (version_build_cmp(&rver, &tk->ver) < 0)
		return TOK_OLD_VERSION;

	if (end == NULL)
		return TOK_MISSING_LEVEL;

	latest = find_latest(&rver);
	if (latest == NULL)						/* Unknown in our key set */
		return TOK_OLD_VERSION;

	/*
	 * Verify build.
	 *
	 * Build numbers were emitted when we switched to SVN on 2006-08-26
	 * and stopped being a monotonous increasing function when we switched
	 * to git on 2011-09-11.
	 *
	 * We no longer verify them now that we removed all the versions before
	 * the git-switch time.
	 * 		--RAM, 2017-10-22
	 */

	/*
	 * Verify level.
	 */

	lvllen = len - toklen - 2;				/* Forget about "; " */
	end += 2;								/* Skip "; " */

	if (UNSIGNED(lvllen) >= sizeof(lvldigest) || lvllen <= 0)
		return TOK_BAD_LEVEL_LENGTH;

	if (lvllen & 0x3)
		return TOK_BAD_LEVEL_LENGTH;

	lvllen = base64_decode_into(end, lvllen, ARYLEN(lvldigest));

	if (lvllen == 0 || (lvllen & 0x1))
		return TOK_BAD_LEVEL_ENCODING;

	g_assert(lvllen >= 2);
	g_assert((lvllen & 0x1) == 0);

	/*
	 * Only check the highest keys we can check.
	 */

	lvllen /= 2;							/* # of keys held remotely */
	lvlsize = N_ITEMS(token_keys) - (tk - token_keys);
	lvlsize = MIN(lvllen, lvlsize);

	g_assert(lvlsize >= 1);

	rtk = tk + (lvlsize - 1);				/* Keys at that level */

	crc = crc32_update(0, VARLEN(token));
	crc = tok_crc(crc, rtk);

	lvlsize--;								/* Move to 0-based offset */

	if (peek_be16(&lvldigest[2*lvlsize]) != crc)
		return TOK_INVALID_LEVEL;

	for (i = 0; i < N_ITEMS(token_keys); i++) {
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

/* vi: set ts=4 sw=4 cindent: */
