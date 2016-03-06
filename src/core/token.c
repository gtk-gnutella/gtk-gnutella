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

#include "token.h"
#include "clock.h"
#include "version.h"

#include "if/gnet_property_priv.h"

#include "lib/base64.h"
#include "lib/crc.h"
#include "lib/glib-missing.h"
#include "lib/halloc.h"
#include "lib/misc.h"
#include "lib/random.h"
#include "lib/sha1.h"
#include "lib/stacktrace.h"
#include "lib/tm.h"

#include "lib/override.h"	/* Must be the last header included */

#define TOKEN_CLOCK_SKEW	3600		/**< +/- 1 hour */
#define TOKEN_LIFE			60			/**< lifetime of our tokens */
#define TOKEN_BASE64_SIZE	(TOKEN_VERSION_SIZE * 4 / 3)	/**< base64 size */
#define LEVEL_SIZE			(2 * N_ITEMS(token_keys))	/**< at most */
#define LEVEL_BASE64_SIZE	(LEVEL_SIZE * 4 / 3 + 3)	/**< +2 for == tail */

#define GIT_SWITCH			1315692000		/* 2011-09-11 */

/*
 * Keys are generated through "od -x /dev/random".
 * There can be up to 2^5 = 32 keys per version.
 */

static const char *keys_097_0[] = {
	"1cf5 88ac a6a8 f440 8278 842c 6952 931b",
	"04cc 6a81 9bbb fadd 396a d06c 148e 6b64",
	"0434 c7cb 3226 cd37 8448 59f4 6b9b 5f33",
	"acf0 3d65 c8a1 ebe7 99cf 34e8 1fc6 c655",
	"51aa e878 b6e4 7d39 4a43 94e6 3106 98b7",
	"fbbb b0ce 9b4a ec5b 3ce6 dbac 0fbe 062d",
	"b2a9 080d 3614 8f20 7e41 ed84 008e 843a",
	"c997 42a0 cd6c 0d8b 0fe7 c5e4 0586 d889",
	"d2c5 4ae3 da17 6985 e85e 9ea7 981e 3bd2",
	"187b dbb8 5bf3 02d5 84ef ac8d e01c c2bf",
	"47a9 8c5f 8c66 dc20 75a2 093b a881 ca9b",
	"0034 f0bc 40d7 32ce af60 9b36 2452 0f74",
	"aed7 7fe3 bf75 2fd8 1189 64ae a026 3f05",
	"4ffc 76a4 a156 8b51 6cdc 2119 3c02 f54a",
	"4aa4 9560 df85 56e3 30ae dcd6 4f86 c99d",
	"4c59 1b09 d09c 5d16 f674 8392 f9fc 2716",
	"f36b facc 967a 8311 c75e d10b 9b31 dc9d",
	"ea54 9826 9661 1f6b 8cad b908 5126 d48a",
	"5c3c 3efe 9272 a595 86d1 8e3c f439 f5b3",
	"cc03 d92d 4ef5 f0b0 832f 8258 9277 ad5a",
	"be83 63e1 0bdd e26d f259 b49a 21b3 2146",
	"d5d4 ddce f41c c18b 0a5c 8cbf 1788 eb1a",
	"0238 c884 51ba cd79 3ddb d27b d1ae 07e4",
	"e331 b1c3 3642 2b82 e196 97d9 d49a 9a86",
	"20ce c244 4cc7 b0b3 f009 174e a3e8 031c",
	"d219 b497 1b0e 250a ac1b 8b66 e39f efee",
	"b2ff 7959 f55c b48d d5cb e075 df1d a83e",
	"923d 4db5 5294 7c22 e6df f040 482d e7fd",
};

static const char *keys_097_1[] = {
	"39c5 71be a79f 3c39 2f30 7ae6 1eed c59d",
	"f0f5 8eed c463 e3a0 58ea 7c8b 8624 b872",
	"cfcd 4453 0a76 a4cf b31f 33ca b6fd c21a",
	"445e d272 97af cf1a 0a24 0ed1 9b0f 2698",
	"3dde 9e5c 1309 e6ea 6f7e 0663 7455 f809",
	"1198 719c 180b 1b24 40ea b08f c87b 9130",
	"91c5 675a 2308 bf82 8fc0 26cd 17b1 ae5f",
	"c5b8 7e17 cfc5 fdf4 1b17 c71e 44ce 6cdf",
	"b235 71f4 b93a f624 aee2 f369 dabd 333e",
	"cfad b4c6 3cf1 e260 5e94 b745 a847 5b6f",
	"9962 17de eb49 5d2f b6c8 b1d7 cd7c e709",
	"d6db 29ea e272 2c88 c9aa 4ddf 7894 7450",
	"df89 9db3 f8af 728a cd68 3ac1 1dc5 8954",
	"b575 1dc5 0b95 db1a 121f b80a 6ab7 b274",
	"d9ad 1f64 3705 a900 0d23 1314 51b8 c8a8",
	"1f2c 6150 3d53 499f 8277 be84 6e88 de48",
	"8e5f 13bb 66ce 575b f494 a7d4 35dd 7284",
	"bbfd fdc9 ac8b 507f 190b 2b2a 33f9 ae99",
	"dbdc 1eb8 e82a 18d1 7157 8531 587f 0132",
	"ad13 6076 a759 b5da 0527 96cd 70c3 d893",
	"78f2 bb4c ae51 e468 21d7 6f10 ad52 848c",
	"50c3 abb7 60a3 658c 8352 26e2 de16 ee43",
	"9910 aa85 e2c5 0d7e c587 86eb 6474 9a8c",
	"7d6d 5c4b fd2f 509a af2b c7ee f060 0ed2",
	"ed5e 6a5e 6574 bda8 246b 670b 7a0e bb81",
	"45b2 3377 0a88 c54a d911 2d5e e4ba d513",
	"89e6 b32f e2b6 0e65 3453 bbc7 fb5b b1e4",
	"0c93 3ee1 f48f 3653 7a9c f338 8d2e 8868",
};

static const char *keys_098_0[] = {
	"3248 b31b 8cf3 763c 552a d42c d833 1d79",
	"9dbb 43d8 c217 0ecf 743d 4ac4 02ec 9aed",
	"4165 dbb9 2afb 61d9 9a7e d13c b65a 05e2",
	"4971 e904 c448 9802 2eb6 b9e4 d177 83c2",
	"0bbe a4cb 17be 4427 cad0 2d48 c39f 5464",
	"110b 8553 bd5d a1da ae75 d863 c652 3d37",
	"7c19 9b64 b003 55c9 391e 8740 5697 035b",
	"3e5d f6de fb0e 72aa c25b a9f4 5295 78e8",
	"e681 10b1 8958 7b54 428b 8c50 1c5b 7c5c",
	"7f74 ee30 0392 a474 3cdb 7d23 47dd 9956",
	"6751 4a3c 3a4d 2889 edb2 23fb 14c4 6b8d",
	"3efa ba6b 0d92 a890 0ee4 676d 0ec6 8884",
	"6a4b 0ed9 6ca4 771e 2fd9 c14b ea65 f661",
	"aa57 742b 6ea7 843b 08a4 8228 fcc1 ff1f",
	"4e42 81bf 8e15 54f5 62bc d970 e456 2345",
	"194d 052b 25b5 0731 14e8 372a 952a 8535",
	"1af5 7651 8c7b 8aed ee9d a752 167e d735",
	"40a8 a0f0 8432 30ba d2ba d297 9b81 6542",
	"c761 e6cd 1829 8056 7bb0 ffab 6fee 4867",
	"a498 e32b d8ff 954d f68c 1bfd 6d65 9ff2",
	"ffb0 3a61 6795 6b47 f7ef 7c9c d08b 913c",
	"8f62 d747 2f8c 9a2f 019e 3bc0 9c62 7374",
	"fd79 60f5 9ac7 f1e9 3cde c3c8 8cad bd36",
	"01a9 c262 e5e5 0c10 fabb d81c 54b9 e9f0",
	"764c 89cb 4a1b 978f 2217 ec5d 38d7 33f7",
	"e3b6 8589 dfd1 829a 41f3 b371 0555 80bb",
	"5376 c257 21cb 0f2b 2f56 f1f3 a772 afd0",
};

static const char *keys_098_1[] = {
	"64e2 7991 d384 b6bf 2bbe 7741 152c 8b93",
	"0ba4 8379 63d4 e789 575c 9035 e3a4 93be",
	"dfb4 08fe ec3a 2aa3 6018 37be 2a68 06d0",
	"3e31 23c5 526f 564b 8da9 5315 687e d437",
	"0728 cfa5 43af e2ae 46ed d9b0 af49 a64a",
	"2fa9 fff7 57d9 5b5a 46af b557 e388 7826",
	"b8a5 0059 6464 87a5 dba1 79d1 373f 5966",
	"150e 70ac 19c8 1040 912e 5cc4 7d37 db12",
	"3ab0 72d9 9436 4be3 3bea 77fe 409f 3e37",
	"f5ed 6af6 9fa1 c9af 3ea0 d652 2ac0 5d75",
	"6a9a 0d02 2abc a36d 0cc8 ae53 8292 c608",
	"4284 5952 4a2c 8399 cbaa ade3 e320 0712",
	"9aec 465a f6ec 175a e384 1d22 8570 56be",
	"234f f3cc c451 cead 33df 5e5d dce7 e492",
	"8b42 74bc 7703 492c 5ba2 83f5 65eb 4ed3",
	"9991 5c43 5400 48d4 fab3 65a1 33e0 c102",
	"e280 ca7d 0143 f98a 3131 4031 a147 b16c",
	"0211 f8b4 aa81 e9c6 5d93 f9e1 e853 7ca7",
	"eaf5 5569 653a a80d a730 d528 7512 7bff",
	"540e b603 96b8 db6b 0a71 2d80 b44f 524f",
	"98c8 6092 0929 30fb 63bb 177f ebf4 9db9",
	"cf06 0c7a a6ac 0ed9 9c4c bae3 3a63 3075",
	"5743 93c2 b5d2 9be4 7fa0 62e2 c3e9 6f22",
	"d6eb 0f97 2792 e548 aac0 34d5 26e2 4cb2",
	"b8e6 d222 2e81 e91a ec37 63d0 471e 17b4",
	"e1ed 3bb0 0efc a215 b3af 560f cd50 fcdf",
	"7827 f3ef ac6d 92cb aa1e 5696 33a1 2c66",
	"8091 baf1 4b68 dd57 244b 644b 6639 5ede",
	"e3bd 34aa b8aa 4bf8 2aa3 0886 f8a7 f645",
	"e6c7 79b9 a976 7d3b a542 f538 a35f afd7",
	"8dd7 e6f4 a16a 6287 ccff 1aa8 8a4c 61aa",
	"d3c8 ed48 c580 8e04 cf55 14f0 a97a d084",
};

static const char *keys_098_2[] = {
	"9e02 8332 b67c 3ed0 3e98 d0e4 b115 7a1f",
	"3196 2dac b607 5b85 f1cf dcf9 7581 801c",
	"2e1e 25ca 3b59 8673 c6ac 669b 08c9 51a6",
	"7ffc e673 6996 74d7 9260 f164 d1e1 93fe",
	"f0d1 30f5 e6d4 b20b d9f9 e927 3f84 8303",
	"5a63 469e 0241 baa8 ce28 cdfb c341 9065",
	"dc46 bdd4 edc8 b8ea fb84 f68a a1c5 236b",
	"604f 1341 4c08 aa1f 38aa 8349 835f 636f",
	"30b6 e183 a5f8 b91a 0e42 af9c 123c ce09",
	"66fd 02eb 6daf ff35 f567 6516 4dea fabb",
	"5c4f a301 0400 15ba 3d00 9aaf 42a9 76d0",
	"640e c7f1 dde0 fd4b a4b7 f7ff 2a07 17c7",
	"0a0d ac20 3049 24e9 6d73 710f adad 6029",
	"2e83 a8dc 5ac0 8835 86c6 f311 add3 c6f3",
	"5013 a492 e7c1 65a0 2ba2 0941 8659 c3db",
	"a0eb a55c 3da6 d0a9 7d46 9a6b 4fe9 04a7",
	"f30e 5f3e 59c3 153e 25bd 159d c61a 126d",
	"a200 bdf3 37c9 24e9 4029 51be 7551 75f4",
	"c980 1460 a6f5 6d13 2ef1 d906 5dfb 4082",
	"c948 a66c 0c0e e137 8328 61a0 74a8 f745",
	"6896 50f8 4578 29c3 ba5c 2c7b dc94 5819",
	"c198 8eec 5094 37f3 e8c4 bff3 7c6e 57c8",
	"bf63 5675 31f9 b69e 64ab 365a bc08 644d",
	"6048 4267 a56b 5dd6 9ed7 f98b acca 298d",
	"5d27 b6f3 4bec 2111 f080 0c52 35a4 d3ae",
	"1bb0 4177 686f 07bb cba0 1655 cb15 a475",
	"b476 61c3 1e97 0ad3 bbbd d201 57fb 94fc",
	"4719 d106 18ba e037 3040 f1fa f19d fea9",
};

static const char *keys_098_3[] = {
	"04b5 8d0a b3b9 59b9 8113 5dab 53ab 6c7d",
	"522a 3d32 f9ef be3d 20fc a797 6834 85ed",
	"878d 2e7a f1bc ebfc b60e 99d8 df3f 983a",
	"876c 71b5 07b6 55bb 0453 2f89 d59f 8803",
	"fa44 34aa a0f3 6763 9845 afed c961 5034",
	"c3c7 bbb9 fc77 858a b175 e257 b437 e6f6",
	"58dd 513d 0aa1 3e04 7638 9803 acfb 869a",
	"d93a 806a 9740 a162 7ac5 25d2 e20c 03bf",
	"0c58 bbd7 e60f ca7b fc0a 814c 6628 0db2",
	"4ec7 4839 75d8 4657 9b9c ee47 eab0 22d4",
	"a253 8772 8555 7134 7df5 e353 1567 9f92",
	"7a00 7d25 1936 95f3 f01a 47f3 1c3b 4c6c",
	"66a9 9fcc 5fbb 100b d397 79a9 6b82 70a6",
	"37bc 0e47 5838 a33c d91e 88e5 322e 7ab8",
	"b930 87df 027e 8971 9a8e 1bee 4034 59cf",
	"5b75 cf63 b8c4 7c40 e7f3 cd0b 8900 092b",
	"82ba 6d10 61a9 fb9b b53a 0a8d eca2 c42a",
	"9282 b83b c214 2648 1fd6 e4ed 3a99 f896",
	"5590 b2a2 f8a2 2235 6cef 7073 1841 eb4b",
	"5470 bd80 3d7a 33c2 b490 3caf e9d0 dbd2",
	"1dc8 334e 10ad c0c3 3639 7b8b 4eb5 ad09",
	"3280 5c30 acf4 239a cee3 cd5c 4fe8 6155",
	"d78b 9d1d 6da2 9f2d bf9f 4fdc 317f 4ae2",
	"d442 08fb e0e5 f419 498f 0055 5878 5c32",
	"d92d 62d9 303e 3180 bf4f 2a82 f1c1 09ec",
	"60d3 a2b2 f713 8859 8232 b163 e808 8de6",
	"6cc1 f2d0 b9c6 25be e62c a64b 2c1e 8b5c",
	"0cb7 2795 f88d 77d3 0dd5 d978 a818 1253",
};

static const char *keys_098_4[] = {
	"1a94 ebfa bce6 1878 3dfe d484 62ab 20ef",
	"f1f6 8df3 fa99 8805 c248 c008 e793 11eb",
	"c785 e618 7a5f e3d1 1a02 483a d334 e706",
	"8213 787a 5ce4 a016 84aa 8147 c3c0 10a8",
	"0916 b1d0 6e33 6746 dda7 4980 50f3 4786",
	"0699 29ec 7855 0952 0301 4676 4db3 0efe",
	"0c9f 34f2 bb70 73b7 6115 777e 3339 ede0",
	"fa09 d4b4 19d5 f151 6057 8da5 a18f c38a",
	"4e7e 84c1 4b72 cdbf 1b20 4267 a877 4262",
	"ea85 070f d6c6 4c52 aaad f375 6b68 59f7",
	"06c5 ac96 f7c9 2de3 3c16 9b6e 5e04 2c82",
	"f8d6 981f 83b8 9fde fc4d 1d5b 2e52 2186",
	"9b38 2bec 6740 009a 8a4b 143f d786 c6f9",
	"3617 bff5 b5b6 86e6 bf0c 0560 3372 577b",
	"088f fd18 1a6f b22f 9db3 3419 196d 4544",
	"f3aa 2b69 0567 6193 0c14 a331 82dc be14",
	"0d66 0ab5 bd7d 9174 ede8 2b53 31f5 74b8",
	"a66f 698a 6514 760f 6e37 6de3 237a 40a1",
	"24de 4a61 90f4 eba3 ba42 7a09 1fa4 69db",
	"3996 3984 cca8 cfab 28df 5af0 5576 3bf7",
	"8a8a a3fe 0950 3346 848d 388a aaf5 5b0a",
	"82ca de6a 9485 2655 3b0a c67a f02e 0543",
	"8ddf 1a8c 5b96 d7e0 e43e 63cb 04c3 dc8d",
	"d4bf dd41 c177 6ae1 fc7f dbf4 4d16 d93d",
	"34e8 5a53 e51e b7dd e3d8 8965 6888 6998",
	"4566 2c9b c0ff 06ee 2d65 8037 8ad6 d0d2",
	"eb20 c9dc 68fa 1176 a138 20d6 befa fec5",
	"aeed 4f98 40ca 8dfa 3488 d8c4 6b70 92c7",
};

static const char *keys_100_0[] = {
	"b6e8 a799 db61 cbe8 ce60 1438 a3c0 31ab",
	"6f8c 91be f9df b352 cce4 a837 ce3b 73a2",
	"2c61 cb7b e7c7 613f b020 17ac cad1 899f",
	"bda1 e42e 8d26 f98a bb37 8b3a fe33 9de2",
	"612a 8eea af18 3792 aec1 42dd d242 53c7",
	"7ebf 027a c5a3 8cf2 19d7 17ae 1ac3 4d48",
	"de52 5dc9 1130 059e a7e3 5994 bd17 99a4",
	"f27e 75d7 b23f 20b7 ba72 bde7 6b05 6513",
	"377f 9f2a 049e 8410 57fb edf9 e67e 80e0",
	"48cc 202c eaf1 a7eb 0ae9 d2b1 1f40 a333",
	"05b4 e02f 8369 8712 e31a 3a2f 8f9b 8a65",
	"0290 e4a5 bcb8 795e 31e7 5cd3 e73a 3a0b",
	"7781 c375 0d49 d4d5 175a 7c69 fcf6 d345",
	"c2be 1fb2 1056 6ea7 0299 d8f7 8cfa bdd8",
	"91b1 e043 eb64 4ed4 b195 0967 623c 5532",
	"cf11 65f8 2688 9e26 b0b4 c75a 2eec 4ca9",
	"e9a3 ec87 e160 2783 0de9 df46 b1b5 952f",
	"ce27 deba 3d8b a62f 1940 77b7 4a54 e281",
	"30ac 305f 1ec6 cf78 8e76 d47b 4a1b d291",
	"4b4e 899d c18c 4b71 c621 a6e3 6740 4993",
	"0094 fcab 5cd6 5b5f 91e9 9829 5fdd 930b",
	"3d6f 2ec5 f111 f18b fe59 1aa8 7cd6 b444",
	"b88f 9d67 d687 3355 0ada 0631 3b6d 6a3d",
	"41f2 d33f d88a f371 6c11 feaa 83c2 f964",
	"a525 93a8 ade7 49fa 3e76 bcf2 ccc8 f043",
	"df6d b945 a6ff 14f6 2963 1795 ea92 266d",
	"7271 5313 f59d f0da 343d b348 2089 c717",
	"0ce6 7dd0 5a41 7f37 a7fd 1a81 c77e 2f89",
	"c14b 2928 a554 d0db d921 45ce 91b7 7dd8",
};

static const char *keys_100_1[] = {
	"d8d4 9d20 bfdb b0c4 16a0 5295 be08 1b85",
	"0644 874b 1c69 38e6 4d9a aef7 6290 ca51",
	"32ca 7a16 e87c ae50 43cd b55f e8df 55de",
	"769e 0046 b99a 1377 b955 8969 f643 9169",
	"6f17 f2fa cec5 8276 9ac0 04bc c834 d339",
	"4e81 3e42 ff1f 9d55 b201 a3eb a521 3ea9",
	"319f c22f 1a55 9e8c 646c 6275 0beb 166b",
	"2907 4301 9ea6 bb77 ad8e 1772 e0e0 67b7",
	"0a65 44ed 2016 5889 39d1 93f7 c998 fdf8",
	"291f f564 1853 eb1d c242 6918 361d 56c1",
	"69fe 41b6 cf04 0e28 2d7e 1d1b be21 a88e",
	"0819 a7e0 f5c6 c596 0524 d826 3e39 8e12",
	"bd56 2ece ca17 966f 4bcc 34c9 770d 0227",
	"44b8 2e27 fba9 88c5 a693 1f6d 7219 7dd4",
	"5ab2 1203 ac8e a0e8 d493 27c1 9da8 f6ff",
	"1aab 5cdb a0ea 3a04 9c7a c72b 00c8 0ba9",
	"9fc8 0038 a170 b822 3e9c a53f 1eb2 4f44",
	"bd8c 2065 f363 ccdb 5976 36b5 0066 e02c",
	"07df 6ea9 4b11 3fe2 138a 89d7 6439 457d",
	"363c 5617 e66b 2a99 a33e f868 e694 9bd3",
	"8cb4 7d83 8e67 55f8 8890 2762 f374 951d",
	"99d6 00ef ec4d 8f80 5fb0 71c3 8967 c64e",
	"26f0 b2cc bff1 8ea8 f39d 5cd8 4873 adce",
	"953c 3fb1 4f9c 6390 9657 1596 2a31 e287",
	"c596 de71 7e6e a5a6 7727 6db4 90f8 338f",
	"8d33 5aa8 36ec 8117 e0fb c02e 296b a65a",
	"c40a 619a b29d d17e 6100 e982 4dca 364e",
	"75e4 4d2d 3533 d462 6846 52be d9d7 c12d",
	"c831 6dc0 2434 f793 4ae2 ba68 37c6 ae9c",
};

static const char *keys_101_0[] = {
	"0e52 1f9e 9175 3956 c50c ea12 2c04 8571",
	"6935 29db 10f5 2457 9f50 7db6 5835 6706",
	"c584 2380 e246 5ab5 5869 5cad 717d 1b66",
	"2f6f 8f86 35a5 3b45 a082 c980 bbd3 b11b",
	"e19f 2759 ce8a 20db 5d63 6144 8b3d 9ca3",
	"8768 9271 bd23 80be ff99 036a b29c fc0b",
	"b907 d822 b334 6d60 6abf aba1 d27a d813",
	"88d9 096a 5caf b555 08b6 d0aa 8bca ca3d",
	"f385 2ffb 2e4c 3c67 5c4c 654f 5566 bb3a",
	"c5cf 6783 e701 5c8f ea15 d6d4 6bd9 aba9",
	"e761 a010 c248 1d55 baeb a273 a745 e8f8",
	"c427 5bd7 a45d a5e6 79b9 d454 5ad4 51ad",
	"665a 811f 57d6 fbf4 0d6c e5f8 278d 1e52",
	"a31b 4b67 741f f021 cf3f 9c8c d001 7128",
	"5758 7c97 7b7d f10d c985 af97 477f 44b6",
	"a319 d8ad 5e65 6920 e548 05c8 715c 3fe5",
	"7683 61c1 1b54 581d 185e 6675 d325 fa72",
	"7136 394a b039 c5ee a361 28df 157d 6d39",
	"321a 6d8a 7d4f deb0 e41c 67df 2d46 616e",
	"f55e a8be ae4a 8f43 20de 89bf e39f 7b90",
	"76e0 bd5e f08f 5ee1 9d45 aa9f 4c25 c9fb",
	"fdf7 8827 d862 284a e929 194f 8e40 292e",
	"a85b e9bd 8de0 c4ee 3397 cc7b cf9b a2e0",
	"48b2 22d5 993a 53f5 1c41 2211 f8ab 8aeb",
	"9b16 317b 42d1 a718 f330 a0d8 7a4e 2df1",
	"8fd2 ac5e 7e4a 3451 d101 43d3 d2bf c943",
	"a708 ad13 754d 6735 b9f3 137f a7e4 63d1",
	"21d8 66c6 dbc3 49e7 3141 e11b f869 95bf",
};

static const char *keys_101_1[] = {
	"b5c5 bd25 df65 7faa 1216 956c 2558 c058",
	"3530 cf03 72fa 7ccc 7eda aaa5 7e78 1da3",
	"5a7d 2588 20d9 cfc4 c9ff b40c 237a a652",
	"f8cb 44b2 cd14 725b 9a95 ac71 62a2 45e6",
	"a5d5 2775 6bbb 0ccc 0d80 9ecd 0e7e 100a",
	"916a d1d1 1b04 2696 8ce8 dd7e 6322 f423",
	"01e9 13df 3323 dace 35ca a05b 84fd 1be6",
	"1ce5 854f ef94 a460 de7d cc0b 0a80 37de",
	"bee6 411d 02dc 2419 554c 2076 bd62 668f",
	"fcdf f558 3924 a001 d92b 5619 6ec7 9995",
	"fa96 d817 60e0 7a99 7161 085d 182b 1085",
	"e3cd 6301 5750 f263 c260 6ce3 6c2a 6634",
	"8298 0b87 8215 6f6f d270 d811 8d75 21eb",
	"2675 df59 4f9b 8680 efdd a2dc 605f 3b60",
	"d45e 32d4 d5a8 248d ae95 9df9 87c2 213c",
	"5562 ebb4 2c0e 8ee1 990e 16c1 e856 be61",
	"10f7 cc2a 1e9a 82b0 508b 8658 a687 2b5d",
	"b562 070c 4abf d10e ed89 68f2 f924 e9c7",
	"581b f25a 67f1 e35d 1bf3 aec7 de88 48c1",
	"8b7a e5fa 4221 528b ebb3 d25f d5ae 17d8",
	"514c ec66 e6b3 9b32 3a93 d336 6711 96a0",
	"bf33 db03 5267 e9b8 2736 e1d2 95d7 14aa",
	"d5f2 035a ed75 6698 43f0 330a 8d5d 5771",
	"9c6c 232a 8b37 3b45 d192 aa19 2f0a 5855",
	"dd5c e4ec 4b5e 63c2 48eb 5a50 d622 0e82",
	"ad1e ecbe eb9b 3762 d1b7 ba31 27cf e585",
	"b3ce b544 82a7 711b d8e9 36c4 2152 269d",
	"2547 4731 9fbd 4c83 e58a aa5b f401 c0e8",
};

static const char *keys_101_2[] = {
	"5475 43e8 a2ca 1404 f2d9 df56 2feb 70eb",
	"53ab ae62 458a e08a c3fc 49e0 f94e 7aff",
	"6493 d9ac 61e7 9a3a e1ab abc7 95f6 2072",
	"6f79 2aac e10c ebdb 1e9f e9c3 0df9 4b2b",
	"78db 1395 8bea 63a3 933f 1760 7860 d480",
	"e4d2 40a9 a4a3 fc73 5dfa 3f56 15f7 254a",
	"70f6 3795 1a4e 7e32 74bc bfc6 366c b889",
	"fc10 b6c8 1f52 3134 531b 62e0 150b 6101",
	"02ab c0b8 1bd2 6cea 3fd0 c191 ecc4 0262",
	"e41b 3732 d070 ae4b ac4b c36b 176f 0a03",
	"0de1 e1bb 4dd0 81a1 5365 cf5c d358 d7ba",
	"c0bc b0fd 762b 773a a85b 21c8 2af0 f797",
	"405d 4997 01db e436 ba6e 2222 cc28 9b6d",
	"2ab5 245e aaee d65d 92f0 c65a b08c d636",
	"ff11 3970 246c ee6e a00d 4ebd 54c0 ca31",
	"c5a9 63a7 28da b2d2 8d3b a63e 0957 cf7a",
	"d4f0 a55a 0ea6 100c 7062 cd93 a886 e802",
	"49c9 76e6 f907 5b02 46de 70f9 236e 828d",
	"d1f6 91e2 7f5a e8d8 2ebe 754e 2041 31cc",
	"4467 80bb 0874 6e60 d3a2 d12f 37cd eb8b",
	"9a5a 6ddb 440b f584 8a7d fdd0 a026 8c05",
	"635d 9f51 d228 70bf bdba 995f f360 4171",
	"e7a7 b9d3 a02c b0e6 a66d 9aef aeb4 187d",
	"989c 1c07 ebc0 a635 4a4f 2bf5 305c cb0f",
	"790d 7a2c c570 3856 8d79 6909 3479 85de",
	"373b 7f3e c464 de1e a6c9 a0b0 c810 20b0",
	"de00 19a9 8674 2c20 789f f688 d721 2a23",
	"e351 701b 3cac f6d3 37b3 7052 2b64 f64c",
};

static const char *keys_101_3[] = {
	"be45 6d2e b759 55b8 0616 85b4 6efe 829e",
	"4003 5f01 b4a2 3026 23ef 6bbf d221 955c",
	"8e58 304c 6aa7 7ffb 0a5a 89f7 3384 3735",
	"1176 4ef2 e01d 5256 0d98 92e4 3bdd 6d59",
	"d2e3 d4db 4752 263f bfc5 ecc5 2268 ee26",
	"b349 5c28 6217 57da 0c18 6372 fa89 99f7",
	"7f87 fce2 7d76 5b5b 863a 2bbd 1db9 b3bf",
	"b161 dca9 e137 c304 fbae 867e b816 68b3",
	"d8ac b802 e14d ad55 14fa 2c91 6b01 fd40",
	"a10e c052 1e95 627c 70b9 0975 38d9 82c5",
	"338e 9ad5 4949 c9ca a87b 7ee1 abe9 780b",
	"9179 88e8 82ed e94e 2bc9 dd04 a6ca fae7",
	"856b b3a8 2f28 9b4d 7e96 4675 4d42 2096",
	"8b1f eac3 1c28 023c 757d 539c 493c 7935",
	"b222 4f2b 6d93 a501 0f8c 3e95 614d 84cf",
	"b7de 80b5 a08d d9e5 c9fa 530a 96ee c1cb",
	"7c52 4279 bcfb c2fb 65eb 7a75 13c3 0b7a",
	"c6b9 14cc 0738 b907 372b 5f16 e6c6 46d6",
	"a392 0388 295a 0eba 3546 2c0d 3fdf 8fb8",
	"9d2a 0362 60fb 3881 ef6e 3261 094f 2cdd",
	"f1ea 482e 8b57 d3b6 8d71 15fb 9e2b 4d93",
	"cf84 15c5 00c8 7232 e35b 707c e21e be62",
	"a79f 219f adda bf80 e00b cef9 5991 6674",
	"cdf9 0894 103e 9f32 fe12 3779 671b c4ee",
	"3553 c1f0 2c52 ed5d 8933 28b2 2e82 5bdf",
	"16ef 4da0 76b0 10eb cb8e 4c73 dead a6c6",
	"c4c9 c157 2f92 8df7 bf67 70cb e8a8 1e41",
	"ec54 de4b 6290 152e 3e4f 3a7e 225b d9bf",
};

static const char *keys_101_4[] = {
	"58fc e374 b0bb 6513 e300 bbc2 d6fe c15d",
	"aa0c 2ec1 4704 284e 6342 12cc 05aa 678f",
	"ec54 b643 d0d7 631e b76c 0d71 4c5b 7476",
	"766e 1c8f a71c 03d6 c611 6e29 b0e5 97fe",
	"e4b0 0719 1e4a b4d4 5f91 fa95 91c4 a9e2",
	"ad25 ef5e d04a bb02 5c9d dfeb 3d0b a088",
	"7058 eea1 6f08 e792 b904 87ed 6702 968d",
	"b1a7 1ba5 0eee da59 c434 36a7 904c d43f",
	"c44f 63dd e8eb d380 2859 f4d0 2a5e 5500",
	"e2e2 4b89 1a6b c2d2 9e1b 22eb de4e 41a4",
	"0fd1 6eb7 fd7c 6b4b c021 b5b5 c913 0553",
	"a41a e6ef 8da3 d109 f253 1a10 139d 39ce",
	"721e da21 b10c 43a6 ecce ab57 6b73 e231",
	"14a3 0b58 ca81 053a 8fe0 cce4 c8c6 7f1b",
	"2be9 a5e3 a3ad 1990 058f d116 d3eb 9f5c",
	"622b c7d9 247d f8a8 fb4d 963a 8797 ee18",
	"b12d 9e6a eb8e 5df8 0b3c 57f6 52c6 5b43",
	"6233 2f0a 8e46 c3a9 526b 6b56 92e3 3c12",
	"8db5 5af8 9527 ea2b 1f22 8a70 bcc8 621a",
	"e55a 223d 23f7 ed62 c381 3f7c b151 9d28",
	"92b5 626f d69f c011 ade4 ac57 d8ea 2e37",
	"7881 c4b7 cf45 8484 e735 f6f0 71a8 1ffe",
	"7788 755d aeb5 f875 be16 6587 1dd0 3e01",
	"fe56 c9c3 b194 da09 bbf8 25be 5f2b e2da",
	"c2f3 f1ff 580b efa4 1e0c 30dd 7478 fc20",
	"73b1 97b0 dc00 f43d 8327 9c56 0369 51a8",
	"60a0 3f09 e110 1812 3dde 75e8 6402 f5f0",
	"c0c9 b75a df8f 784b 2ff3 7a25 f175 03f5",
};

static const char *keys_101_5[] = {
	"2b70 9d92 a693 86c1 a5b3 a55b c55e 48a9",
	"e118 e30a f9ef 1a31 5e22 c8cb 9cc4 d3f8",
	"75af 1193 e9b3 64d7 6150 2531 6f07 e23a",
	"2920 8768 b211 a247 2f78 7456 dd24 9849",
	"25fc a295 fcb2 3147 13d4 4210 ee2b 45f5",
	"e76d 1a8a 929c 4382 8aee 4e56 fe65 d9dc",
	"d4a8 405c 9f07 09f8 ae6b e8e4 783e 0328",
	"6b3a fdbd 50ec f9f4 1ee1 7e49 df0b 49e0",
	"d11a a613 be62 2a55 ed82 5a28 d4e9 0763",
	"45f8 cb52 ddad 22e7 f9b7 0124 d0e8 bbe3",
	"0ed3 8f13 62e1 b68c 83ea 9824 d919 8776",
	"f331 1edb c576 dd92 b12d 7b6f 2064 6b36",
	"5db1 a911 77b0 9c20 3350 5001 8856 0b9c",
	"08d6 b62b 8c35 a7d4 dfba a18e faee efee",
	"d7f4 4df4 dfdb 7ef3 2dff bc45 614c 527e",
	"66dd 661d eef6 3c4d cc36 464e 9c13 a847",
	"c2b6 2207 773a 6d01 8d84 ad4c 5ae0 07c4",
	"4b58 8da5 3fa5 128f 5d73 b019 cb0b 46ca",
	"6aab 3555 605b 5b93 e093 3db9 bc1e 631a",
	"9b10 ec1d ac5b 5e39 6e97 33e3 3a02 1c04",
	"95b5 b829 3533 4897 c2b3 24a3 0c31 3354",
	"7310 5672 717c 10f1 6dd1 90e5 c533 4b80",
	"b0a7 5c33 01dc 042e fd9e 4f00 ca27 4426",
	"b450 430b 9e63 a101 e05f dfb6 7e45 10cf",
	"ab14 6c74 2781 1e6f b558 0970 c7ed 50dc",
	"fe89 9f1d 8a2e 10d6 1cc1 1094 8177 c3fc",
	"b1c3 3046 2613 c585 a1fa 8701 6573 a37a",
	"ca0e 8b49 2c8b 961a 9244 bcff 122d be09",
};

static const char *keys_101_6[] = {
	"cf46 9775 89cb 1e4c 0759 782a 9e10 e247",
	"284d 5536 1f38 6c13 2126 edea 88b5 bda2",
	"557e 0a96 fcc8 9a9a 13d8 318c 9e70 1146",
	"8ff9 f0b7 54c2 8778 518d b63a 5439 1871",
	"7403 cf6d c8a2 3450 9907 a6da bcca e8b5",
	"678e 0731 3b49 ae9d 391b b08b 44c7 2017",
	"a6bd 0a6a 6810 ab1d dc8b 8c16 a569 7382",
	"c6d9 e370 2c69 3d37 4c23 fe8c 75b2 7be8",
	"4037 846c 1285 9b6c 3bdd e181 03ba eee6",
	"2314 bc87 25fb 9c7e d157 97c2 2162 3142",
	"1942 d882 5b81 912d 62a3 4911 85db 4f3f",
	"5790 62e5 8d93 6356 0834 6702 f2fe 6526",
	"d0fe fc39 a6bd 568f 654c a1a5 780e 974b",
	"dd10 e11c 5e63 ec6b 06b3 9fe1 173f c04f",
	"b7b7 a969 e4e2 e900 3276 7478 a145 ebd6",
	"9f91 382e cd2f 367c 28f6 dd41 d95a c089",
	"5a96 a120 c008 702a 5657 8e13 af17 ba3b",
	"c585 944d 96e5 e85c ff21 7fb7 855d 7902",
	"5b8b 4752 7b9a 4280 cbf8 5561 5900 58a9",
	"8a89 db36 0c73 ff68 38d0 3d9b a3da 37d4",
	"3278 6ce0 e520 badb adc8 4f7e 39af 382e",
	"8dfe aea3 1438 88c6 1033 1a7b c8b1 4733",
	"21c1 a537 3b0c ed60 f4a0 71b4 760d 26ac",
	"be79 dca9 0dfc 6ba7 3eb6 9fdc 0072 eb87",
	"fc72 ae20 cb31 8ba1 5c91 5666 3623 16d4",
	"a7b2 db48 42ae b6ea 2ad9 45a8 2da8 99ed",
	"4274 7dc8 3b36 67c0 4b98 07e7 161f dc2e",
	"e113 e05c f75d b6f8 61f8 62d6 be68 c138",
};

static const char *keys_101_7[] = {
	"0d3c 02a2 5e56 5f39 609b 7c85 e272 1946",
	"f854 c268 4afb 5c4b dacc 15ba 28af f140",
	"db35 3ea8 0ee9 e3de 54ab 7cd5 3aee 1678",
	"a5ee c97c a65c 80ed eab0 5016 259d 7d0b",
	"1924 abc5 eeba 420b 8519 e792 1f0d b066",
	"104c 2d53 18cb 479b 32ff a21d 8b8e 932c",
	"bb49 419c efac 3a45 e9b5 ca2a ccd1 11a6",
	"4d54 3aa7 c2f8 2c05 655a 8dff 82c2 a413",
	"a845 4771 9c15 b101 b4fb c8a9 cff1 9f5a",
	"7fb8 1f13 f6dc b1bd a78f f97e 0280 21d8",
	"7ac2 b366 c007 0f08 c767 f33e e820 a60e",
	"2aba 8da6 35da 0e57 d63e f082 adb4 bcf6",
	"50bb 9dd2 b9d3 9643 836f b825 d91c c8b1",
	"1d74 f303 a08c 2c0e bbdb 787b 82d1 1ec8",
	"0518 0d55 4bd9 c226 6126 bde8 ddd5 49c6",
	"17fa 7242 7d8b a5e2 ef7f fc53 471e c6a8",
	"f661 ddd6 9cad ea22 0ce2 7365 6a8e f0b3",
	"6947 1c7b eaf4 c15b 1ca4 2d7f 3432 6a00",
	"da13 d844 2f5f 1da8 36e1 7a30 6e5f 2153",
	"cc7f bf19 58ca 9a9f d83c b7c5 83de a1d2",
	"c53d cfcd 5c3c 9aac d956 fd41 f355 a401",
	"bf8c db79 352c 7d2b 4070 c82f 5fe3 aeed",
	"a9db 8e75 c3c7 ba9d 8d57 56cc f933 80d0",
	"f7a2 0627 6d71 5e34 b4c0 3430 73c6 061f",
	"607a 89c4 9f7d 306c a42a 268a 0cab d32d",
	"8254 5734 1ba1 da50 07d6 0a99 2219 8a2a",
	"ebbc 6e73 663c 18ef f93e c9a0 e420 6231",
	"ed20 5683 365b 1481 f1be ad4c 5e5f 3a76",
};

static const char *keys_101_8[] = {
	"b841 e964 b9bb d36a cfed 48fa 82d8 8b39",
	"c4ec 3dfc 8d64 14d0 e2b2 631d b00e 2822",
	"cc4b f15f ad23 d370 ad7f b35c 655b d997",
	"8ac3 199e e48d 18bc 1031 3a82 5cff 2e95",
	"9772 121f 5d38 673f e217 401e f5dd 778d",
	"3e79 2f5f e996 c44d 7c70 1531 f2be 42ce",
	"3700 dc67 4644 7fb1 c673 2e06 e1ad 4715",
	"a933 22f5 3f8f db8c d51c ff14 bd5e 211b",
	"326f 5d87 185e 9e57 5808 1465 cd22 785a",
	"290d 2617 d178 710d 4a32 3893 6720 d1c7",
	"93a4 f75b d71c 633e bd54 85eb b5f5 dc5c",
	"7683 9fce 1b67 9b00 53b0 6967 2e81 de72",
	"01ab db4f 7835 fb94 f266 2a67 6565 086f",
	"b139 e53b 2f1f c8a4 0f39 3a22 1961 674d",
	"97e3 2231 1063 f2fc 299f e743 4b6f 5c50",
	"e44a 5024 28c6 55e1 8110 51be 7e76 9cb4",
	"a116 536a 739c d813 f87c 9986 33da 37b1",
	"7add de37 e523 e423 3e71 25b6 e69f 62e7",
	"f7c0 fa9e b05b a953 4a65 9e41 d576 1929",
	"5f31 dec1 254a 57d0 74ab 96d1 6ff5 28f3",
	"dd3a 6f81 7e55 536e dbc8 7561 a4e4 11f2",
	"e3fc e69b 96bc 706a b35f fa5a 2ee9 6681",
	"5f69 115a e6cf 05ba ef32 17ad 03e2 9545",
	"317a 300c ccad 524e b740 9103 77a6 98ae",
	"d475 28e5 9fc0 4cd4 7865 b72a 12c9 d0d0",
	"96e6 b914 cf60 2826 8d0b f074 29af 7d41",
	"d733 1588 0df3 7421 e961 28d1 024a 166c",
	"645a f525 9f98 7838 5beb eb45 06b4 dd52",
};

static const char *keys_101_9[] = {
	"0e6f 2f6d 8da7 cb51 2a7d eb89 0922 9cd6",
	"403c 3714 199e 8813 e207 d01b 940d e437",
	"625a e6c5 5d1f e26b d419 f5e9 05bf f9b9",
	"041a 27b8 3d17 b670 a9af 4777 6bbc be00",
	"f7f3 bb5f efb5 c3ae ec4f 5c69 1cdf df27",
	"2e94 be67 f27f d02d 7eb2 6652 84c3 a341",
	"d912 c05c 4d11 d5da 5c2a 25d0 80c3 74f3",
	"0033 a4e7 b00b 1c54 87c0 3e6f a319 709c",
	"e12d 8b7c 5b39 81e9 6159 8d7a 114a 91fe",
	"1575 36a3 4232 66b4 4a06 bd7c 4cc5 e479",
	"83dc 334c 3231 2cf9 9d0c 8f8e 84c7 2f48",
	"8c27 8287 aeb0 1ce7 39bb 9494 8c1f b58e",
	"4f21 faf4 fb61 8b6c 7596 df7f 07e2 30d3",
	"fd8e 3a57 9526 1665 6f8b 0355 f0b7 0a9d",
	"06b3 ecdd a6f9 9041 b237 de69 096c b912",
	"b0aa 033d b7a4 3f5b 5eda d3b8 f07b 0520",
	"8ee5 423e 6c67 465c 3cb7 a165 ec64 e4aa",
	"a838 a2f8 3129 2ddb 3045 72c0 b859 dd8f",
	"902c 4a02 d79b fbfa b98f d88e e52b 8772",
	"2c3a dc95 58b3 51e9 5d83 6644 0cc5 f669",
	"8f08 629d 0145 183f 9435 267b fbe7 773e",
	"aa91 2e8b 10a4 9f1c 051d 801b 8f61 19f5",
	"009d 7610 f444 fec6 6dcf db47 74bf 0e52",
	"2214 b567 0734 8577 003b 7cea d5b2 9371",
	"7758 074e b632 d84a e463 2cda bda2 2cd6",
	"4609 1c68 dfd8 8eb7 a551 103f 5bb9 93ff",
	"cf8b 4db0 af43 c5ae 5053 a833 7926 9f21",
	"86e1 e20b 5edd 3261 10d1 7912 6686 ba90",
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
	{ { 0, 97, 0, '\0', 0, 0, 1310940000 }, KEYS(097_0)	},	/* 2011-07-18 */
	{ { 0, 97, 1, '\0', 0, 0, GIT_SWITCH }, KEYS(097_1)	},	/* 2011-09-11 */
	{ { 0, 98, 0, '\0', 0, 0, 1323558000 }, KEYS(098_0)	},	/* 2011-12-11 */
	{ { 0, 98, 1, '\0', 0, 0, 1323990000 }, KEYS(098_1)	},	/* 2011-12-16 */
	{ { 0, 98, 2, '\0', 0, 0, 1325199600 }, KEYS(098_2) },	/* 2011-12-30 */
	{ { 0, 98, 3, '\0', 0, 0, 1338760800 },	KEYS(098_3) },	/* 2012-06-04 */
	{ { 0, 98, 4, '\0', 0, 0, 1352588400 },	KEYS(098_4) },	/* 2012-11-11 */
	{ { 1, 0,  0, '\0', 0, 0, 1377986400 }, KEYS(100_0) },	/* 2013-09-01 */
	{ { 1, 0,  1, '\0', 0, 0, 1388444400 }, KEYS(100_1) },	/* 2013-12-31 */
	{ { 1, 1,  0, '\0', 0, 0, 1404252000 }, KEYS(101_0) },	/* 2014-07-02 */
	{ { 1, 1,  1, '\0', 0, 0, 1409608800 }, KEYS(101_1) },	/* 2014-09-02 */
	{ { 1, 1,  2, '\0', 0, 0, 1426892400 }, KEYS(101_2) },	/* 2015-03-21 */
	{ { 1, 1,  3, '\0', 0, 0, 1428444000 }, KEYS(101_3) },	/* 2015-04-08 */
	{ { 1, 1,  4, '\0', 0, 0, 1441749600 }, KEYS(101_4) },	/* 2015-09-09 */
	{ { 1, 1,  5, '\0', 0, 0, 1444255200 }, KEYS(101_5) },	/* 2015-10-08 */
	{ { 1, 1,  6, '\0', 0, 0, 1446937200 }, KEYS(101_6) },	/* 2015-11-08 */
	{ { 1, 1,  7, '\0', 0, 0, 1449961200 }, KEYS(101_7) },	/* 2015-12-13 */
	{ { 1, 1,  8, '\0', 0, 0, 1450393200 }, KEYS(101_8) },	/* 2015-12-18 */
	{ { 1, 1,  9, '\0', 0, 0, 1457218800 }, KEYS(101_9) },	/* 2016-03-06 */
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
	"Missing build number",			/**< TOK_MISSING_BUILD */
	"Wrong build number",			/**< TOK_WRONG_BUILD */
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

/**
 * Based on the timestamp, determine the proper token keys to use limiting
 * to the first ``count'' items.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *
find_tokkey_upto(time_t now, size_t count)
{
	time_t adjusted = now - VERSION_ANCIENT_BAN;
	uint i;

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: count=%zu, from %s()",
			G_STRFUNC, count, stacktrace_caller_name(1));
	}

	g_assert(count <= N_ITEMS(token_keys));

	for (i = 0; i < count; i++) {
		const struct tokkey *tk = &token_keys[i];

		if (GNET_PROPERTY(version_debug) > 4) {
			g_debug("%s: index=%u, ver.timestamp=%u, adjusted=%u (%s)",
				G_STRFUNC, i, (unsigned) tk->ver.timestamp, (unsigned) adjusted,
				tk->ver.timestamp > adjusted ? "OK" :
					i + 1 == count ? "FAILED" : "no");
		}

		if (tk->ver.timestamp > adjusted)
			return tk;
	}

	return NULL;
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

	tk = find_tokkey_upto(now, count);


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
	return find_tokkey_upto(now, N_ITEMS(token_keys));
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
	 */

	if (
		ver->timestamp < GIT_SWITCH &&			/* Before we switched to git */
		ver->build != 0 && ver->build < 16370
	)
		return find_tokkey(now);

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

	i++;									/* We need a count, not an index */
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
		crc = crc32_update(crc, k, strlen(k));
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
	SHA1_input(&ctx, key, strlen(key));
	SHA1_input(&ctx, digest, 7);
	SHA1_input(&ctx, version, strlen(version));
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
tok_version_valid(
	const char *version, const char *tokenb64, int len, host_addr_t addr)
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

	end = strchr(tokenb64, ';');		/* After 25/02/2003 */
	toklen = end ? (end - tokenb64) : len;

	/*
	 * Verify token.
	 */

	if (toklen != TOKEN_BASE64_SIZE)
		return TOK_BAD_LENGTH;

	if (!base64_decode_into(tokenb64, toklen, token, TOKEN_VERSION_SIZE))
		return TOK_BAD_ENCODING;

	stamp = (time_t) peek_be32(&token);

	/*
	 * Use that stamp, whose precision is TOKEN_LIFE, to update our
	 * clock skew if necessary.
	 */

	clock_update(stamp, TOKEN_LIFE, addr);

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
	SHA1_input(&ctx, key, strlen(key));
	SHA1_input(&ctx, token, 7);
	SHA1_input(&ctx, version, strlen(version));
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
	 */

	if (
		rver.timestamp >= 1156543200 &&		/* 2006-08-26 */
		rver.timestamp < GIT_SWITCH			/* 2011-09-11 */
	) {
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

	if (UNSIGNED(lvllen) >= sizeof(lvldigest) || lvllen <= 0)
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

/**
 * Check whether the version is too ancient to be able to generate a proper
 * token string identifiable by remote parties.
 */
bool
tok_is_ancient(time_t now)
{
	return find_tokkey(now) == NULL;
}

/* vi: set ts=4: */
