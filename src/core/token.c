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

static const char *keys_120_0[] = {
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
	{ { 1, 1, 10, '\0', 0, 0, 1472680800 }, KEYS(101_10) },	/* 2016-09-01 */
	{ { 1, 1, 11, '\0', 0, 0, 1478818800 }, KEYS(101_11) },	/* 2016-11-11 */
	{ { 1, 1, 12, '\0', 0, 0, 1505858400 }, KEYS(101_12) },	/* 2017-09-20 */
	{ { 1, 1, 13, '\0', 0, 0, 1508623200 }, KEYS(101_13) },	/* 2017-10-22 */
	{ { 1, 1, 14, '\0', 0, 0, 1538604000 }, KEYS(101_14) },	/* 2018-10-04 */
	{ { 1, 1, 15, '\0', 0, 0, 1563055200 }, KEYS(101_15) },	/* 2019-07-14 */
	{ { 1, 2,  0, '\0', 0, 0, 1594245600 }, KEYS(120_0) },	/* 2020-07-09 */
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
