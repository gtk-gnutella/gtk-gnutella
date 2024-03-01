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

static const char *keys_101_10[] = {
	"f784 cfc0 85e7 fbf7 b711 d98b 3053 ca33",
	"5947 aef7 7ffd 795a a756 1af9 8d95 0126",
	"2c0d c50a 27be 2181 364e b0dd b50c f904",
	"8235 815e 6e1f 0cb4 b129 b69f a1bb 1673",
	"d257 ea61 3a80 3f33 a780 db47 6c41 d3fd",
	"0958 98cb 5ac3 56c9 2af5 d35f 5c96 0fad",
	"274a 4e0f eb0b 3b69 2f9e 90ab 630f 4285",
	"1ae9 8e14 e441 7bde c067 d851 97b1 3a0c",
	"d138 0cb6 8d15 8f73 0985 ff8d d936 9c10",
	"306e 0e53 82c0 7d79 de56 db70 0427 6282",
	"0b7b 01ac ece5 42ff 9a93 064b a732 8262",
	"f966 bf9e e10a 2cba 41b2 41db de0b d3ff",
	"9b72 d9c3 3c6c 22c1 43b8 dbaa 3c1f a8a4",
	"34ee 4015 3cf2 166b 45cb 66ac 2e9b c160",
	"ca5b 0a4e e427 465d 52f2 da38 fbd2 fef5",
	"a546 a304 1582 1220 8a84 4a2b c909 846d",
	"81a7 cbe3 97d6 2197 a8a8 fad7 4029 c93b",
	"d102 304c df28 7698 5279 b553 02b3 b776",
	"1a62 a026 71ba b615 3105 2244 51f5 22b9",
	"cf94 3aba 9d4f 5565 4364 b68a 5248 4012",
	"7bab 13f4 6da9 0be8 86da cee8 be2e 71ba",
	"1178 214a e278 2f9f e8a7 5fe5 89e8 b298",
	"64f2 d43e e6d9 7eb3 27db 3221 04eb 38eb",
	"942f 77ba 12e0 f78a e535 ada4 51b3 d053",
	"c78c 142e d623 8bcd 7b23 8b25 1981 faa1",
	"9513 c2d8 df36 2cad e0e1 2699 6a2f 9b52",
	"8db4 ad3c 0109 3bb0 3c38 4c0b b04b 0e87",
	"4c5d ecb4 56ce f1e0 1c01 2e3c a5d8 a5e7",
};

static const char *keys_101_11[] = {
	"e801 7c71 ad33 d9ae 9ace 8b08 bd47 3938",
	"7cba 53dc 50bb 05a6 ef64 debb d345 b7d0",
	"f806 6df3 23db e809 317a 4f2c c526 64c5",
	"f981 18cf b42f e681 7f4e 7d4c 82df 78f9",
	"5e71 0d77 1021 dfe1 1dcc 8bfc 6f18 d698",
	"0f4c af05 ef52 eafb 6511 b662 e830 7c46",
	"0cb3 d221 2a5f 93fe 8e53 b547 949d 0a54",
	"7745 5be9 c91b c09f 9a9d bf8d f15c 46ea",
	"323e 8bf3 289f be0b 53e3 3e20 a7f7 3f75",
	"5fa1 5cc4 4ab9 36c0 49c7 e4ec 9d1e 7f58",
	"c45f 6d3c b11d 9a39 86bb 2bc2 8564 b4c1",
	"263e 7c32 f25a 9332 c922 0834 30e0 782a",
	"e8ae 3576 9dfd 61b3 e76e 4d97 4713 6d55",
	"1dff c81e 91b6 b0e2 4e03 fe8d ecf0 9fb7",
	"19f2 c53b 6a4c 0732 9036 50c5 dce0 1259",
	"d4d5 a903 629c 67c9 6355 5cbf 6acf bef8",
	"fd2d d13d e6ad ff5f b655 03c9 d1a4 4ea2",
	"ff45 83c2 d761 4157 e1ff 5170 dbcd 1123",
	"ebea 5c43 66f6 9cca b4d0 59a2 dd73 5cd7",
	"c8d2 0d57 3600 7530 a582 a860 db84 b856",
	"fee2 6a4d 557f b49c 965a 5dd6 06ac 6507",
	"b7ed 119a c033 4fdb 85bc b24a 41bd 681d",
	"977b a331 72fa 9974 4c7c 366a 8724 6fa7",
	"ed54 44b3 d4f6 5052 1ca0 bf5a 11a9 f3ae",
	"4d23 3426 5be8 3120 9c22 a315 ec77 1cb8",
	"30cf 1e01 b306 f88c 3955 e47f 991c c239",
	"bbb5 d254 e397 4372 d182 1bf3 1f1e 9b83",
	"d85c 414f 6920 ee83 982d 14a0 4417 c5fb",
};

static const char *keys_101_12[] = {
	"1879 3fd7 37aa d5c8 0099 f573 513f 53f4",
	"548b 446c 0d8a 7a78 13ad 3eca 1f74 136f",
	"43e7 a999 e947 4dbf a417 9f8b ce22 02c4",
	"18de d20d 5ee7 1264 359c f749 0e32 b85b",
	"34b0 96fd 340a d807 3d14 48f9 9f2a 4bb2",
	"c6f7 d19b 4ec1 e25d 65b1 0da4 f64b 7cb4",
	"e3df 4de0 fc51 46f6 d82e 328f 6de2 7f3e",
	"5158 1db9 f15c 6499 9b09 f218 1c9f 502f",
	"d608 b8f9 f7fa 4f18 4233 9faf c76c 1722",
	"f917 8c52 5d7c 1981 7151 f951 1ebc fbe0",
	"1b15 69a9 37ec e7e4 9caf 659d b379 d142",
	"bc28 32b9 b491 8325 f3bc 2abf 9ec7 5a84",
	"319f d7fd 122d 5cf7 2b35 d93a 9ed7 1ba8",
	"cc20 f651 4f5a 97ec 938c d461 3b1c 224f",
	"68dd dbcc 2343 738e 6399 6405 9cb8 5bca",
	"ecc2 0294 6338 e128 66d1 0852 7008 d135",
	"ac62 37b7 9c8f e0f5 60ee b86c 7d87 af07",
	"1e5e e4bd cbe5 2113 3bb1 0b06 1d8c 9aa9",
	"ae91 1287 b3e4 2b95 89be 4832 ff50 fd7f",
	"27fd 5488 d3df 45a0 99ed 3bd5 5979 6bfd",
	"b4ae a266 ec5b 9ab1 494e d46c d02d 5b89",
	"6714 f180 08a4 92ef cfc1 e788 6547 2d35",
	"2854 7e6f bfad 584e 0e88 b8e5 ab78 6958",
	"4876 3e55 2ae4 03cb 6af2 91d2 a5ce 81d4",
	"d577 56fc 8854 c701 5ecc f532 c778 77bf",
	"6433 7cfb e732 3f3b 0fb6 5e85 c619 c007",
	"bed5 dd56 c618 dcf4 dec2 5952 01b5 9cd7",
	"68ae daa6 2f00 03e0 2282 f794 c143 800b",
};

static const char *keys_101_13[] = {
	"ca05 6ac9 697a 6226 059a a3f6 16d8 da68",
	"7138 c56c ed60 f9dd 1521 8a74 4a4e 2624",
	"50c7 5489 8abb 5e81 d65d 5547 7759 6f42",
	"ee38 d4d3 9b15 2efd 3653 2a0b 704d d890",
	"b32f e588 fc45 7dda 2595 a762 1cb8 c825",
	"b681 d967 dbf5 07cf 48bd 1a19 94f1 7872",
	"8904 f24c 1165 4322 dc68 0837 420c 3bef",
	"a114 d699 a869 6985 dbad 3067 52e0 c055",
	"be76 b6fc e327 8add 7096 a813 00fc 3338",
	"3388 220b 2f25 220c f70e 7279 626b 60b1",
	"af33 c164 5a80 b8b0 a343 2311 bacf 92da",
	"dee0 e9db 173a 45dd 5902 5c9c bc08 7632",
	"5c6f 8c90 14dd 2184 9cbf c963 abb6 3367",
	"db09 0d2d 90e1 69b1 118a 9312 24d8 7b0d",
	"4551 8973 97e4 0395 7367 53f6 0f9f 7f4f",
	"a1d5 f4f0 91e5 ef92 fd90 790e 57ad 9380",
	"6fe8 98b0 9088 21c2 b6ff 1136 343f 0341",
	"d61d 6023 48c8 50c0 1fa2 4dd9 2287 a3cd",
	"ee3e d463 3cb8 8309 6e30 e630 2b81 cf1f",
	"d462 2b30 b15b 40db e21d 2629 e45e 1bf7",
	"9a1d 24f3 b4c5 32b7 38dd 3cdb 91d0 b0dc",
	"fd84 4bff 5c6d e6b7 dcfe 3963 6c4b ff05",
	"3a2f 408e 1af4 1652 aba5 df9b ce64 5622",
	"4867 b2ce 300f 405d 583d 5383 5ab7 9ebb",
	"93d7 29df 474b b2c9 8e8c 9439 c3c1 2e97",
	"aada 550b 190d 3aec 19b4 0905 b4a2 89fc",
	"1f70 e468 92f3 dd39 c62a 893a a878 9510",
	"ce5b 42fc fddf 4180 71d1 f11b e4b2 2402",
	"ae9f 9232 8033 0e18 a9b0 aec3 43e5 d9bd",
	"8b47 06db fb68 bd69 e6aa bf2a 3b08 53f8",
};

static const char *keys_101_14[] = {
	"a829 6896 2486 73d2 9a49 3164 7ab1 1602",
	"24ba cfd2 e760 cd2c 33da fd58 4ee1 db19",
	"5c0c 0e50 880c c875 0645 783f 79d5 b95c",
	"f7f3 2e97 4564 cb83 eea3 882d 10b2 96a4",
	"5169 a7a3 2fef 6c53 81d1 f178 d3bf b85c",
	"2276 cb69 b0d8 1aa3 b3a5 47e5 bc16 24d0",
	"19a9 1c7c 6d38 918e 754f 7915 53dc d724",
	"49cb ac41 73c4 3a46 e70f 5699 db70 f716",
	"e984 cece 3f1d 772c eb11 de11 7451 8ab5",
	"f0b3 2394 fc86 e998 eab4 39e0 2810 1f79",
	"b0ac 20ed cce1 407b c5f3 86f5 2c15 592c",
	"5bbd 6363 88dc 4bf2 94ac 33fb 275d ae5b",
	"2cb9 a1f2 b660 3eb9 be0e d6e0 dfe3 fc4d",
	"164e 1d7c c6cb fa5f a071 3d38 e0f2 3bbe",
	"662b fe05 6a30 d7c9 168a 32c9 040c 8819",
	"2614 0b11 d5c1 e4e8 8ffd 7f60 7e56 bffc",
	"a756 1fd6 dae3 4747 25c3 ae27 1bea 935c",
	"5b7e 8012 5db3 f6e1 4a88 c1b0 781e 30e2",
	"b235 f537 88b1 10d2 555f ec00 f206 ba47",
	"6b5a 5b01 cf75 df2d 9df4 9e3c 5cf5 2ebe",
	"3ec0 4323 e4b2 c412 b3af 7da9 bdf1 5331",
	"e8ac c21c 27da 405f 025c 666a ffaf 65f4",
	"f6d9 b8bf efa7 bbb6 b5e8 e308 662e 6f30",
	"c751 4375 9679 0efd 8774 e99a 8ceb 0e89",
	"832d 480e 2c26 8806 f225 84e0 3542 6080",
	"5218 ba99 dcdd 8554 c965 6a66 6503 71bd",
	"152d b4d6 3f2b ae0c 109e e16f adfc 3aa1",
	"d99e 7ef6 58c7 8c3c b534 8a48 0ecc 3c9a",
	"0daa e186 62c1 7904 c035 4283 da1d c5f8",
};

static const char *keys_101_15[] = {
	"5942 7363 7cde 78bd 2e0e b186 0517 4e4a",
	"d046 ef18 ad73 70c5 9a53 0c0e da88 705e",
	"d9cf cb69 4ddc 4bae 3165 31ea 1a3e 1295",
	"0126 9d38 2d3f 1a49 7cda ab6c 96a3 3206",
	"4e8e bd4e 5af3 731f 6c60 0322 cdfe 4e86",
	"5b82 c5d8 2eb1 0409 7a48 3d57 6ca3 f018",
	"ca29 a64d be93 ef88 e689 6e22 50e8 1d29",
	"acfd 1141 0920 7f68 2269 39f2 cbce fbcf",
	"ea02 6e0b 2de0 90e0 31ec 854e 385c aca5",
	"1dab 733a fd8e 1425 d4b4 cf46 7788 956c",
	"7090 af27 156a 8604 61bd 19fb 507a 98e3",
	"1268 cc4d 52c3 1982 97a6 4272 4855 f13f",
	"599c b477 a541 a181 6f0f 654e 7ef8 9ee2",
	"183e 70f2 e9c1 f7ff dd26 65b7 d5fe 6b98",
	"e77f c562 6857 ca9d cf38 5bcf d1e7 0a6e",
	"90ba e3bf fc1e 9f70 9d05 4adf 2fca 5dfb",
	"31ac cb84 d399 69fc c7d4 d315 dc35 2b6c",
	"11a1 3c11 4e05 0a46 d7b1 7c9a 4bbf 65e1",
	"2ccf 89a6 d33c df6d b032 a395 7827 8859",
	"fd6b 64c7 a636 77d7 892c 4729 c884 4b95",
	"8932 b125 88c9 86ee 996a bbf0 19b2 ccba",
	"0de0 297c 5670 95bf 298a bd3b b970 f38d",
	"afbf 6481 dffd 9329 2e51 2137 d33c 7e94",
	"1d51 28c3 dcb6 6ac1 ad36 b7da 3527 aec2",
	"e745 e8ba 4c0b bd7e f5f5 9b68 5c02 b238",
	"14f2 0ffd 1b3d 7d85 ede4 f509 e843 7107",
	"ca3e d81c 5e5b 73d5 859b 658c c6dc 1021",
	"87eb 2420 15fa f960 4981 391e 3b57 2bbc",
	"005b 406f af8a 9f98 4eec b4ff 6e13 65fe",
	"d524 983c 9f60 1ce8 804c 88b3 d902 0dfe",
};

static const char *keys_102_0[] = {
	"dc29 762a 977d b0d4 3cb7 71ea f633 0a29",
	"b7dd aef2 d529 3a75 fb9e 8c7b c9e1 7f6a",
	"a66d 0b92 db02 45fd 1cf2 b007 6cd4 ec9f",
	"0021 3e20 4a0b b354 8f72 9178 9791 b695",
	"72f6 eb92 cd15 2da9 a668 19f2 6d1c 629b",
	"bd8e a0cc 2774 b95b 5cbf 8d83 d706 e838",
	"7dfd bb93 702b 0994 acdc b90e ac93 31ef",
	"35b5 b048 633e 2b18 1021 ef92 39a2 8f6a",
	"e46b be05 3824 85f9 8170 49a4 895b c04a",
	"a19d d800 7a1a 34fc 8234 b459 adff a328",
	"4930 f2bd e472 4b50 f4b5 a898 484b 5d69",
	"a6b4 558e 685c a7ef bad4 ceed f978 21cb",
	"1864 c9bd 4323 a8bd 4416 e990 5b40 4ccf",
	"f223 5c7c 8d2a 9fd6 fa44 3cde 2e2e 9abe",
	"b90d 7d30 b2ae 432f dba2 0c12 5514 502c",
	"dec0 5b46 35e6 23e4 4026 93fb 3581 0f62",
	"f600 501f 516d e575 1b60 ab2d 404b 0ce9",
	"45c4 7333 f5e4 1853 0668 c6da ff04 db74",
	"934d 638d edd5 deed 4850 1825 369c 3e9d",
	"da16 280b 3093 0a67 aae7 fe12 0b27 dd86",
	"68cc 42a9 126e fe35 b85e a08d 8b0f 2f9c",
	"db65 38ba 29dc d2d4 be2a 3d0f 1aff d0a8",
	"27ee 6ce1 235b 42bd 7a2e fd88 9237 9b00",
	"4799 11ba 373f effa 6b6b ceb0 6da9 b551",
	"5dd3 104c a1d0 7b4d 84d6 61a2 9cbd ac39",
	"fe0e b10d f9c8 fbcb e27b 5542 d89e 9d98",
	"bfde 09f2 e83a 9eb5 9e15 6978 207d e69e",
	"a412 e334 288c 1f0f 52cb 0aad b816 2972",
	"5be0 7069 6266 7905 5bba 101c e96a d403",
};

static const char *keys_102_1[] = {
	"aab6 db11 2962 546e 4006 67e6 b632 d8a7",
	"3139 b84c 09a5 d1e6 17d2 a5f6 9539 0252",
	"5cea 6c17 7a01 362a e231 1e93 8987 bcaa",
	"da5e 7d35 e31c 4f0d 46eb c304 d4af f780",
	"69e5 f538 4446 6f0d 1147 4ff8 b777 578e",
	"823e 092a 8ee6 c941 4524 0ffb 0968 7214",
	"14e1 1c4e ae27 b982 7f31 a6e0 5bbe 231a",
	"c7e6 b459 5f94 02c1 813b 435e 421e 6af2",
	"434a b148 ce58 6701 dcdb 19d1 0a01 77ec",
	"f52c defe d842 c595 833e 84bd eba3 daee",
	"e31f 5eb3 2523 18a4 7f6f e66f eefc 951d",
	"aa8d d888 a1fc 5be7 5aba 248b 4642 0cac",
	"ccce 691a 410d 976d 039c 2a4d 0fb7 7062",
	"510e 7ab0 7aee 04c2 7434 8487 336b 5759",
	"2113 6a45 0027 7c2f 4089 44ba db8f d405",
	"9cb2 b49f 2e51 3a9b 9872 3324 dc89 a6e3",
	"819d e491 2cc9 6e02 2ae9 d982 5f38 1035",
	"da47 fb3c 1d42 6eba fa21 1cf2 8236 e599",
	"ee31 d958 55f6 a06e 2776 1177 0f98 fd89",
	"4fa0 05bc c000 89a1 15ea 2e42 1b1d e18a",
	"930b 541e 0037 cd15 b132 3640 4008 240c",
	"cf5c 10a0 57f4 8ba3 7189 e6bd ee64 2ce4",
	"5062 62d1 a70d 3100 a673 9bee 50eb 3cb6",
	"2ec9 0ed9 c720 6f4c 7abb 4275 6e6f d369",
	"8ed9 c6a7 1bac 9ab8 56c3 0503 3bbf c6cf",
	"1295 66fc 4c33 c341 c479 1c0f ba90 91be",
	"d1df b008 e63b 0f46 3e87 5189 6abd cadb",
	"ce78 1809 89c0 3c80 e9dc ca22 0bef 71d0",
};

static const char *keys_102_2[] = {
	"4b40 70f5 93fc 6998 e092 3ba5 6c6c b32b",
	"d26e 1468 44de 417e c596 0397 389d 85b2",
	"5105 6295 649d 6769 b1cf 8b95 c57d bdb7",
	"6844 b056 c078 8a87 996b 495b fddc 174e",
	"641e 9b8c ed8c f280 486f 4e12 ddba 8012",
	"db43 c956 3f6e 5c1a a053 5b81 2067 e1b6",
	"267b 8663 4dac 2ae1 72b2 2db2 5bd7 7db5",
	"5ee2 7852 d7d4 ae52 e41e 4347 58d5 8429",
	"351d 7969 ba9f e266 7a27 20a8 1f72 24f3",
	"2d5e 1d43 5d61 7b5c 01f6 67c5 00f4 04e8",
	"21f7 b850 7316 71ae 7558 aed8 f748 b419",
	"a156 0466 f350 a8cf 6d94 b7c1 9d39 2142",
	"4d46 e2ae 7709 c3e8 4237 d47f 0a85 a938",
	"87e5 dcbb 63af 251e 3b07 b280 9389 bfaa",
	"685a 2b0f 5001 65dc e04d d20b fc87 1617",
	"70d3 56ee 5ac1 fa6c 7d21 e69f 5282 9bd1",
	"64d3 4219 0a3b 233b 6845 00d0 38d2 171d",
	"b3d9 73d4 3c51 1e4f 62fe 3a27 78b5 9de5",
	"c4d1 8159 b2fc 6e4c 0b08 cf70 17f5 3419",
	"af78 ec18 a7b6 c564 e97b 12ab 2ea2 a76f",
	"55d2 e105 a20e cca6 4dfe cba1 9f45 bac0",
	"2ce8 661c 251a 2e03 40dc 8f17 b496 5fca",
	"3b72 0fa5 a31a d70f 0ae4 1fdb 8a2d 86b4",
	"76a0 f3ea 702e b870 9bae 9ba5 d9bd a13f",
	"e975 96bd 8627 23cb 7fb7 415f 41b5 8851",
	"0c6f c649 f90b 47d4 3d98 24ac e8bb 3e6b",
	"c19b 5529 0904 2f10 ede4 b0d6 c994 f31b",
	"275a ca3e fee6 0882 401a 19b6 8014 cdfc",
};

static const char *keys_102_3[] = {
	"8ccf 7ff6 c3ea 1c89 b1aa 81ef f846 370d",
	"83b2 3866 3581 7312 910b 8c35 b62b 04b0",
	"5d8f c244 8639 71f0 f50c 6857 8946 825f",
	"b7f9 b4c1 8f17 78a9 a6e7 6d07 0d83 d968",
	"52bf ee17 1ce4 29c7 72a2 ec96 ec7d 1b9a",
	"95a7 2817 9f2b a392 e361 62a2 4bba 020a",
	"f1ea d59e 0580 2e19 2a2f ed9c 28a9 48ea",
	"2edc ffa1 8515 0ddc 3b1c 1f22 bee6 4b84",
	"974d 67f0 92d8 7c05 b524 b38d 501b 8e4c",
	"90e0 c9e1 dad7 da75 5b9e 0a35 7587 43c5",
	"7fd9 9d47 b0de 51c9 d59c 64ef b5c4 64c3",
	"43e4 c529 653d df53 20ae ca8e e5b3 cefe",
	"15b9 ada7 42a9 7039 7a98 a884 bb93 8f6b",
	"cdd5 3bb4 7ae9 40be 0f28 6bcd df20 951e",
	"52db 24c8 a4ce 28af e458 8619 c3c1 f0a3",
	"9193 60c1 b059 c094 5b70 d088 bce1 b528",
	"7117 628f e3f3 d6c3 dc1f bd27 398e b289",
	"3a01 6a75 b919 e271 ab27 a758 35ea 9680",
	"5bf1 5af2 4404 d9fd 76ad d943 7faf bb55",
	"aa0b 4320 5d45 c778 c92e c9a4 0cc7 8f16",
	"c9c0 90f2 2f8f 1a4c f16b 0882 6e1d 49cc",
	"e10e 112b 1428 2f8c e81a 552d 33b2 ecc1",
	"6e86 b1e4 faab 7022 062f aed4 b0a8 0377",
	"3e6c b36c 19f6 e54f 162f 1218 dce6 8460",
	"bf98 1271 ad21 e606 6895 b0c7 0c74 0955",
	"ac35 f19d 6dad 8e29 66ed 2bfd b55b cefb",
	"56ef 56d7 6429 910d 2a2a 398a 0ec3 21bf",
	"d7a7 704a 0582 8faa 266f 5930 d243 ded4",
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
	{ { 1, 1,  9, '\0', 0, 0, 1457218800 }, KEYS(101_9) },	/* 2016-03-06 */
	{ { 1, 1, 10, '\0', 0, 0, 1472680800 }, KEYS(101_10) },	/* 2016-09-01 */
	{ { 1, 1, 11, '\0', 0, 0, 1478818800 }, KEYS(101_11) },	/* 2016-11-11 */
	{ { 1, 1, 12, '\0', 0, 0, 1505858400 }, KEYS(101_12) },	/* 2017-09-20 */
	{ { 1, 1, 13, '\0', 0, 0, 1508623200 }, KEYS(101_13) },	/* 2017-10-22 */
	{ { 1, 1, 14, '\0', 0, 0, 1538604000 }, KEYS(101_14) },	/* 2018-10-04 */
	{ { 1, 1, 15, '\0', 0, 0, 1563055200 }, KEYS(101_15) },	/* 2019-07-14 */
	{ { 1, 2,  0, '\0', 0, 0, 1594245600 }, KEYS(102_0) },	/* 2020-07-09 */
	{ { 1, 2,  1, '\0', 0, 0, 1626040800 }, KEYS(102_1) },	/* 2021-07-12 */
	{ { 1, 2,  2, '\0', 0, 0, 1645743600 }, KEYS(102_2) },	/* 2022-02-25 */
	{ { 1, 2,  3, '\0', 0, 0, 1709251200 }, KEYS(102_3) },	/* 2024-03-01 */
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
 * This is the date when the banning time was changed for gtk-gnutella,
 * moving from 1 year to a little bit more than 2 years.
 */
#define TOK_POLICY_DATE_CHANGE	1625954400		/* 2021-07-11 */
#define TOK_POLICY_OLD_BAN		(86400 * 365)	/* 1-year */

/**
 * Based on the timestamp, determine the proper token keys to use limiting
 * to the first ``count'' items.
 *
 * @return NULL if we cannot locate any suitable keys.
 */
static const struct tokkey *
find_tokkey_upto(time_t now, size_t count)
{
	uint i;

	if (GNET_PROPERTY(version_debug) > 4) {
		g_debug("%s: count=%zu, from %s()",
			G_STRFUNC, count, stacktrace_caller_name(1));
	}

	g_assert(count <= N_ITEMS(token_keys));

	for (i = 0; i < count; i++) {
		const struct tokkey *tk = &token_keys[i];

		/*
		 * Prior to TOK_POLICY_DATE_CHANGE, tokens were selected based on
		 * an expiration time of TOK_POLICY_OLD_BAN seconds.  To remain
		 * compatible with all the other gtk-gnutella out there, we need
		 * to continue this selection as long as the token's timestamp
		 * pre-dates the policy change.
		 * 		--RAM, 2021-07-11
		 */

		if (tk->ver.timestamp < TOK_POLICY_DATE_CHANGE) {
			/* Older policy */
			time_t old_adjusted = now - TOK_POLICY_OLD_BAN;

			if (GNET_PROPERTY(version_debug) > 4) {
				g_debug("%s: (old) index=%u, ver.timestamp=%u, adjusted=%u (%s)",
					G_STRFUNC, i, (unsigned) tk->ver.timestamp,
					(unsigned) old_adjusted,
					tk->ver.timestamp > old_adjusted ? "OK" :
						i + 1 == count ? "FAILED" : "no");
			}
			if (tk->ver.timestamp > old_adjusted)
				return tk;
		} else {
			/* New policy */
			time_t adjusted = now - VERSION_ANCIENT_BAN;

			if (GNET_PROPERTY(version_debug) > 4) {
				g_debug("%s: (new) index=%u, ver.timestamp=%u, adjusted=%u (%s)",
					G_STRFUNC, i, (unsigned) tk->ver.timestamp,
					(unsigned) adjusted,
					tk->ver.timestamp > adjusted ? "OK" :
						i + 1 == count ? "FAILED" : "no");
			}

			if (tk->ver.timestamp > adjusted)
				return tk;
		}
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

/**
 * Check whether the version is too ancient to be able to generate a proper
 * token string identifiable by remote parties.
 */
bool
tok_is_ancient(time_t now)
{
	return find_tokkey(now) == NULL;
}

/* vi: set ts=4 sw=4 cindent: */
