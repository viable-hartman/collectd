/**
 * Copyright 2017 Florian Forster
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 **/

#include "collectd/lcc_features.h"

#include "collectd/network_buffer.h" /* for LCC_NETWORK_BUFFER_SIZE_DEFAULT */

#include <assert.h>

#include "network_parse.c" /* sic */

char *raw_packet_data[] = {
    "0000000e6c6f63616c686f7374000008000c1513676ac3a6e0970009000c00000002800000"
    "000002000973776170000004000973776170000005000966726565000006000f0001010000"
    "0080ff610f420008000c1513676ac3a8fc120004000c737761705f696f0000050007696e00"
    "0006000f00010200000000000000000008000c1513676ac3a9077d000500086f7574000006"
    "000f00010200000000000000000008000c1513676ac3bd2a8c0002000e696e746572666163"
    "65000003000965746830000004000e69665f6f637465747300000500050000060018000202"
    "02000000000000000000000000000000000008000c1513676ac3bd5a970004000e69665f65"
    "72726f7273000006001800020202000000000000000000000000000000000008000c151367"
    "6ac3bd7fea000300076c6f000004000e69665f6f6374657473000006001800020202000000"
    "000009e79c000000000009e79c0008000c1513676ac3bdaae60003000a776c616e30000006"
    "001800020202000000001009fa5400000000011cf6670008000c1513676ac3bdb0e0000400"
    "0e69665f6572726f7273000006001800020202000000000000000000000000000000000008"
    "000c1513676ac3bd3d6d0003000965746830000004000f69665f7061636b65747300000600"
    "1800020202000000000000000000000000000000000008000c1513676ac3bdae290003000a"
    "776c616e300000060018000202020000000000032f8f00000000000205e50008000c151367"
    "6ac3bdbb7b0003000c646f636b657230000006001800020202000000000000000000000000"
    "000000000008000c1513676ac3bda0db000300076c6f000004000e69665f6572726f727300"
    "0006001800020202000000000000000000000000000000000008000c1513676ac3bdbde800"
    "03000c646f636b657230000006001800020202000000000000000000000000000000000008"
    "000c1513676ac3bd8d8e000300076c6f000004000f69665f7061636b657473000006001800"
    "0202020000000000000c9c0000000000000c9c0008000c1513676ac3bdb90b0003000c646f"
    "636b657230000004000e69665f6f6374657473000006001800020202000000000000000000"
    "000000000000000008000c1513676ac469b10f0002000e70726f6365737365730000030005"
    "000004000d70735f7374617465000005000c7a6f6d62696573000006000f00010100000000"
    "000000000008000c1513676ac469a4a30005000d736c656570696e67000006000f00010100"
    "00000000006e400008000c1513676ac469c6320005000b706167696e67000006000f000101"
    "00000000000000000008000c1513676ac469f06e0005000c626c6f636b6564000006000f00"
    "010100000000000000000008000c1513676ac4698af40005000c72756e6e696e6700000600"
    "0f00010100000000000000000008000c1513676ac469bbe10005000c73746f707065640000"
    "06000f00010100000000000000000008000c1513676ac46b8e710004000e666f726b5f7261"
    "74650000050005000006000f0001020000000000001bcf0008000c1513676d437f12960002"
    "00086370750000030006300000040008637075000005000b73797374656d000006000f0001"
    "0200000000000021870008000c1513676d437f36020005000969646c65000006000f000102"
    "000000000005847a0008000c1513676d437f979b0005000977616974000006000f00010200"
    "000000000005210008000c1513676d43802ff60005000c736f6674697271000006000f0001"
    "02000000000000001f0008000c1513676d43803b3a0005000a737465616c000006000f0001"
    "020000000000000000",
    "0000000e6c6f63616c686f7374000008000c1513676d4380551f0009000c00000002800000"
    "00000200086370750000030006310000040008637075000005000975736572000006000f00"
    "01020000000000007cad0008000c1513676d43805dbe000500096e696365000006000f0001"
    "0200000000000001de0008000c1513676d4380697d0005000b73797374656d000006000f00"
    "01020000000000001ce80008000c1513676d438072bd0005000969646c65000006000f0001"
    "02000000000005931c0008000c1513676d43807c430005000977616974000006000f000102"
    "000000000000094b0008000c1513676d43808cee0005000c736f6674697271000006000f00"
    "010200000000000000120008000c1513676d4380843a0005000e696e746572727570740000"
    "06000f00010200000000000000000008000c1513676d438096230005000a737465616c0000"
    "06000f00010200000000000000000008000c1513676d4380aa9c0003000632000005000975"
    "736572000006000f00010200000000000089580008000c1513676d4380b29f000500096e69"
    "6365000006000f00010200000000000003610008000c1513676d4380c44c0005000969646c"
    "65000006000f000102000000000005873d0008000c1513676d4380bc0f0005000b73797374"
    "656d000006000f000102000000000000201d0008000c1513676d4380cea400050009776169"
    "74000006000f00010200000000000005810008000c1513676d4380d7370005000e696e7465"
    "7272757074000006000f00010200000000000000000008000c1513676d4380ea830005000a"
    "737465616c000006000f00010200000000000000000008000c1513676d437eef6200030006"
    "3000000500096e696365000006000f00010200000000000003920008000c1513676d4380e0"
    "260003000632000005000c736f6674697271000006000f0001020000000000000016000800"
    "0c1513676d438101410003000633000005000975736572000006000f000102000000000000"
    "7d8a0008000c1513676d438109f5000500096e696365000006000f00010200000000000004"
    "350008000c1513676d4380244b0003000630000005000e696e74657272757074000006000f"
    "00010200000000000000000008000c1513676d438122070003000633000005000969646c65"
    "000006000f0001020000000000058eb60008000c1513676d43812e83000500097761697400"
    "0006000f0001020000000000000ca80008000c1513676d438141480005000c736f66746972"
    "71000006000f000102000000000000001e0008000c1513676d43814a5d0005000a73746561"
    "6c000006000f00010200000000000000000008000c1513676d4381149e0005000b73797374"
    "656d000006000f0001020000000000001b9a0008000c1513676d437ea86000030006300000"
    "05000975736572000006000f00010200000000000089a80008000c1513676d438138190003"
    "000633000005000e696e74657272757074000006000f00010200000000000000000008000c"
    "1513676d438a9ca00002000e696e74657266616365000003000965746830000004000e6966"
    "5f6f6374657473000005000500000600180002020200000000000000000000000000000000"
    "0008000c1513676d438aea760004000f69665f7061636b6574730000060018000202020000"
    "00000000000000000000000000000008000c1513676d438b214d0004000e69665f6572726f"
    "727300000600180002020200000000000000000000000000000000",
    "0000000e6c6f63616c686f7374000008000c1513676d438aac590009000c00000002800000"
    "000002000764660000030009726f6f74000004000f64665f636f6d706c6578000005000966"
    "726565000006000f0001010000004c077e57420008000c1513676d438b6ada0005000d7265"
    "736572766564000006000f00010100000000338116420008000c1513676d438b7a17000200"
    "0e696e7465726661636500000300076c6f000004000e69665f6f6374657473000005000500"
    "0006001800020202000000000009ecf5000000000009ecf50008000c1513676d438b757800"
    "02000764660000030009726f6f74000004000f64665f636f6d706c65780000050009757365"
    "64000006000f000101000000e0a41b26420008000c1513676d438b8ed20002000e696e7465"
    "726661636500000300076c6f000004000e69665f6572726f72730000050005000006001800"
    "020202000000000000000000000000000000000008000c1513676d438b86bf0004000f6966"
    "5f7061636b6574730000060018000202020000000000000c9d0000000000000c9d0008000c"
    "1513676d438bb3e60003000a776c616e300000060018000202020000000000032fab000000"
    "00000205ed0008000c1513676d438bd62e0003000c646f636b657230000004000e69665f6f"
    "6374657473000006001800020202000000000000000000000000000000000008000c151367"
    "6d438bbc8f0003000a776c616e30000004000e69665f6572726f7273000006001800020202"
    "000000000000000000000000000000000008000c1513676d438bdf030003000c646f636b65"
    "7230000004000f69665f7061636b6574730000060018000202020000000000000000000000"
    "00000000000008000c1513676d438baaf10003000a776c616e30000004000e69665f6f6374"
    "65747300000600180002020200000000100a042300000000011cfa460008000c1513676d43"
    "8c5f100002000764660000030009626f6f74000004000f64665f636f6d706c657800000500"
    "0966726565000006000f0001010000000010e198410008000c1513676d438c689c0005000d"
    "7265736572766564000006000f00010100000000804c68410008000c1513676d438c70ce00"
    "05000975736564000006000f0001010000000020ea9e410008000c1513676d438be7bc0002"
    "000e696e74657266616365000003000c646f636b657230000004000e69665f6572726f7273"
    "0000050005000006001800020202000000000000000000000000000000000008000c151367"
    "6d43beca8c0002000c656e74726f70790000030005000004000c656e74726f707900000600"
    "0f0001010000000000088f400008000c1513676d43bf1d13000200096c6f61640000040009"
    "6c6f6164000006002100030101019a9999999999a93f666666666666d63f5c8fc2f5285cdf"
    "3f0008000c1513676d43c02b85000200096469736b00000300087364610000040010646973"
    "6b5f6f63746574730000060018000202020000000075887800000000005b6f3c000008000c"
    "1513676d43c06d1f0004000d6469736b5f6f7073000006001800020202000000000003cbbd"
    "000000000001c0510008000c1513676d43c08b6a0004000e6469736b5f74696d6500000600"
    "1800020202000000000000003f00000000000001720008000c1513676d43c0a5fb00040010"
    "6469736b5f6d65726765640000060018000202020000000000001285000000000000f80100"
    "08000c1513676d43c0c8b4000300097364613100000400106469736b5f6f63746574730000"
    "060018000202020000000001107c000000000000003c00",
    "0000000e6c6f63616c686f7374000008000c1513676d43c0d00a0009000c00000002800000"
    "00000200096469736b000003000973646131000004000d6469736b5f6f7073000006001800"
    "020202000000000000029b00000000000000080008000c1513676d43c0d7b20004000e6469"
    "736b5f74696d650000060018000202020000000000000004000000000000000f0008000c15"
    "13676d43c0df73000400106469736b5f6d6572676564000006001800020202000000000000"
    "0fb400000000000000010008000c1513676d43c0f87c000300097364613200000400106469"
    "736b5f6f637465747300000600180002020200000000000008000000000000000000000800"
    "0c1513676d43c1003e0004000d6469736b5f6f707300000600180002020200000000000000"
    "0200000000000000000008000c1513676d43c107bf000400106469736b5f6d657267656400"
    "0006001800020202000000000000000000000000000000000008000c1513676d43c12fa400"
    "03000973646135000004000d6469736b5f6f7073000006001800020202000000000003c867"
    "000000000001aef20008000c1513676d43c13d5e000400106469736b5f6d65726765640000"
    "0600180002020200000000000002d1000000000000f8000008000c1513676d43c136a90004"
    "000e6469736b5f74696d65000006001800020202000000000000003f000000000000011c00"
    "08000c1513676d43c1740500030009646d2d3000000400106469736b5f6f63746574730000"
    "060018000202020000000074596400000000005b6f00000008000c1513676d43c179c70004"
    "000d6469736b5f6f7073000006001800020202000000000003cae4000000000002b0f30008"
    "000c1513676d43c18abe000400106469736b5f6d6572676564000006001800020202000000"
    "000000000000000000000000000008000c1513676d43c181b90004000e6469736b5f74696d"
    "650000060018000202020000000000000040000000000000013e0008000c1513676d43c1a9"
    "5e00030009646d2d3100000400106469736b5f6f6374657473000006001800020202000000"
    "00000e000000000000000000000008000c1513676d43c1b7ea0004000e6469736b5f74696d"
    "65000006001800020202000000000000000200000000000000000008000c1513676d43c1b0"
    "3e0004000d6469736b5f6f707300000600180002020200000000000000e000000000000000"
    "000008000c1513676d43c1c00d000400106469736b5f6d6572676564000006001800020202"
    "000000000000000000000000000000000008000c1513676d43c12818000300097364613500"
    "000400106469736b5f6f637465747300000600180002020200000000746c6400000000005b"
    "6f00000008000c1513676d43d320a80002000c62617474657279000003000630000004000b"
    "636861726765000006000f0001018fc2f5285c2f58400008000c1513676d43d36fd6000400"
    "0c63757272656e74000006000f00010100000000000000800008000c1513676d43d3cdb600"
    "04000c766f6c74616765000006000f000101736891ed7cbf28400008000c1513676d43d59d"
    "d60002000869727100000300050000040008697271000005000630000006000f0001020000"
    "0000000000110008000c1513676d43d5d2cf0005000631000006000f000102000000000000"
    "00100008000c1513676d43d5fe820005000638000006000f00010200000000000000010008"
    "000c1513676d43d635440005000639000006000f00010200000000000035210008000c1513"
    "676d43d66265000500073132000006000f0001020000000000000790",
    "0000000e6c6f63616c686f7374000008000c1513676d43d68e940009000c00000002800000"
    "0000020008697271000004000869727100000500073136000006000f000102000000000000"
    "00210008000c1513676d43d69be20002000a7573657273000004000a757365727300000500"
    "05000006000f00010100000000000010400008000c1513676d43d6aa5d0002000869727100"
    "0004000869727100000500073233000006000f00010200000000000000250008000c151367"
    "6d43d6c7dc000500073431000006000f000102000000000000ff7d0008000c1513676d43d6"
    "e23d000500073432000006000f00010200000000000008070008000c1513676d43d9aa3a00"
    "0500073437000006000f0001020000000000079a260008000c1513676d43d9cca900050007"
    "3438000006000f00010200000000000000c70008000c1513676d43d9ea5d00050007343900"
    "0006000f00010200000000000004c20008000c1513676d43da050e00050007353000000600"
    "0f000102000000000000001c0008000c1513676d43da1efa000500084e4d49000006000f00"
    "010200000000000000000008000c1513676d43da3c82000500084c4f43000006000f000102"
    "000000000018d3080008000c1513676d43da544e00050008535055000006000f0001020000"
    "0000000000000008000c1513676d43da6cca00050008504d49000006000f00010200000000"
    "000000000008000c1513676d43da885400050008495749000006000f000102000000000000"
    "a9da0008000c1513676d43daa23a00050008525452000006000f0001020000000000000003"
    "0008000c1513676d43dabaed00050008524553000006000f00010200000000000ac8360008"
    "000c1513676d43dad4150005000843414c000006000f000102000000000000191f0008000c"
    "1513676d43daeef300050008544c42000006000f000102000000000003dbdc0008000c1513"
    "676d43db11410005000854524d000006000f00010200000000000000000008000c1513676d"
    "43db292c00050008544852000006000f00010200000000000000000008000c1513676d43db"
    "411d000500084d4345000006000f00010200000000000000000008000c1513676d43db5b59"
    "000500084d4350000006000f000102000000000000003c0008000c1513676d43db68010005"
    "0008455252000006000f00010200000000000000000008000c1513676d43db758a00050008"
    "4d4953000006000f00010200000000000000000008000c1513676d43dd2e800002000b6d65"
    "6d6f7279000004000b6d656d6f7279000005000975736564000006000f00010100000000fe"
    "bbe0410008000c1513676d43dd3f4b0005000d6275666665726564000006000f0001010000"
    "000070fbc8410008000c1513676d43dd48700005000b636163686564000006000f00010100"
    "000000c008df410008000c1513676d43dd51c60005000966726565000006000f0001010000"
    "0080481d05420008000c1513676d43dec7e300020009737761700000040009737761700000"
    "05000975736564000006000f00010100000000000000000008000c1513676d43ded4490005"
    "000966726565000006000f00010100000080ff610f420008000c1513676d43dedcfd000500"
    "0b636163686564000006000f00010100000000000000000008000c1513676d43d715e30002"
    "0008697271000004000869727100000500073434000006000f0001020000000000031b6100"
    "08000c1513676d43d73116000500073435000006000f00010200000000000000180008000c"
    "1513676d43ee00150002000973776170000004000c737761705f696f0000050007696e0000"
    "06000f0001020000000000000000",
};

static int decode_string(char const *in, uint8_t *out, size_t *out_size) {
  size_t in_size = strlen(in);
  if (*out_size < (in_size / 2))
    return -1;
  *out_size = in_size / 2;

  for (size_t i = 0; i < *out_size; i++) {
    char tmp[] = {in[2 * i], in[2 * i + 1], 0};
    out[i] = (uint8_t)strtoul(tmp, NULL, 16);
  }

  return 0;
}

static int nop_writer(lcc_value_list_t const *vl) {
  if (!strlen(vl->identifier.host) || !strlen(vl->identifier.plugin) ||
      !strlen(vl->identifier.type)) {
    return EINVAL;
  }
  return 0;
}

static int test_network_parse() {
  int ret = 0;

  for (size_t i = 0; i < sizeof(raw_packet_data) / sizeof(raw_packet_data[0]);
       i++) {
    uint8_t buffer[LCC_NETWORK_BUFFER_SIZE_DEFAULT];
    size_t buffer_size = sizeof(buffer);
    if (decode_string(raw_packet_data[i], buffer, &buffer_size)) {
      fprintf(stderr, "lcc_network_parse(raw_packet_data[%" PRIsz "]):"
                      " decoding string failed\n",
              i);
      return -1;
    }

    int status =
        lcc_network_parse(buffer, buffer_size, (lcc_network_parse_options_t){
                                                   .writer = nop_writer,
                                               });
    if (status != 0) {
      fprintf(stderr,
              "lcc_network_parse(raw_packet_data[%" PRIsz "]) = %d, want 0\n",
              i, status);
      ret = status;
    }

    printf("ok - lcc_network_parse(raw_packet_data[%" PRIsz "])\n", i);
  }

  return ret;
}

static int test_parse_time() {
  int ret = 0;

  struct {
    uint64_t in;
    double want;
  } cases[] = {
      {1439980823, 1439980823.0},
      {1439981005, 1439981005.0},
      {1439981150, 1439981150.0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    lcc_value_list_t vl = LCC_VALUE_LIST_INIT;

    uint64_t be = htobe64(cases[i].in);
    int status = parse_time(TYPE_TIME, &be, sizeof(be), &vl);
    if ((status != 0) || (vl.time != cases[i].want)) {
      fprintf(stderr, "parse_time(%" PRIu64 ") = (%.0f, %d), want (%.0f, 0)\n",
              cases[i].in, vl.time, status, cases[i].want);
      ret = -1;
    }
  }

  struct {
    uint64_t in;
    double want;
  } cases_hr[] = {
      {1546167635576736987, 1439980823.152453627},
      {1546167831554815222, 1439981005.671262017},
      {1546167986577716567, 1439981150.047589622},
  };

  for (size_t i = 0; i < sizeof(cases_hr) / sizeof(cases_hr[0]); i++) {
    lcc_value_list_t vl = LCC_VALUE_LIST_INIT;

    uint64_t be = htobe64(cases_hr[i].in);
    int status = parse_time(TYPE_TIME_HR, &be, sizeof(be), &vl);
    if ((status != 0) || (vl.time != cases_hr[i].want)) {
      fprintf(stderr, "parse_time(%" PRIu64 ") = (%.9f, %d), want (%.9f, 0)\n",
              cases_hr[i].in, vl.time, status, cases_hr[i].want);
      ret = -1;
    }
  }

  return ret;
}

static int test_parse_string() {
  int ret = 0;

  struct {
    uint8_t *in;
    size_t in_len;
    char *want;
  } cases[] = {
      {(uint8_t[]){0}, 1, ""},
      {(uint8_t[]){'t', 'e', 's', 't', 0}, 5, "test"},
      {(uint8_t[]){'t', 'e', 's', 't'}, 4, NULL}, // null byte missing
      {(uint8_t[]){'t', 'e', 's', 't', 'x', 0}, 6,
       NULL}, // output buffer too small
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char got[5] = {0};

    int status = parse_string(cases[i].in, cases[i].in_len, got, sizeof(got));
    if (cases[i].want == NULL) {
      if (status == 0) {
        fprintf(stderr, "parse_string() = (\"%s\", 0), want error\n", got);
        ret = -1;
      }
    } else /* if cases[i].want != NULL */ {
      if (status != 0) {
        fprintf(stderr, "parse_string() = %d, want 0\n", status);
        ret = -1;
      } else if (strcmp(got, cases[i].want) != 0) {
        fprintf(stderr, "parse_string() = (\"%s\", 0), want (\"%s\", 0)\n", got,
                cases[i].want);
        ret = -1;
      }
    }
  }

  return ret;
}

static int test_parse_values() {
  int ret = 0;

  uint8_t testcase[] = {
      // 0, 6,                          // pkg type
      // 0, 33,                         // pkg len
      0, 3,                         // num values
      1, 2, 1,                      // gauge, derive, gauge
      0, 0, 0, 0, 0, 0, 0x45, 0x40, // 42.0
      0, 0, 0, 0, 0, 0, 0x7a, 0x69, // 31337
      0, 0, 0, 0, 0, 0, 0xf8, 0x7f, // NaN
  };

  lcc_value_list_t vl = LCC_VALUE_LIST_INIT;
  int status = parse_values(testcase, sizeof(testcase), &vl);
  if (status != 0) {
    fprintf(stderr, "parse_values() = %d, want 0\n", status);
    return -1;
  }

  if (vl.values_len != 3) {
    fprintf(stderr, "parse_values(): vl.values_len = %" PRIsz ", want 3\n",
            vl.values_len);
    return -1;
  }

  int want_types[] = {LCC_TYPE_GAUGE, LCC_TYPE_DERIVE, LCC_TYPE_GAUGE};
  for (size_t i = 0; i < sizeof(want_types) / sizeof(want_types[0]); i++) {
    if (vl.values_types[i] != want_types[i]) {
      fprintf(stderr,
              "parse_values(): vl.values_types[%" PRIsz "] = %d, want %d\n", i,
              vl.values_types[i], want_types[i]);
      ret = -1;
    }
  }

  if (vl.values[0].gauge != 42.0) {
    fprintf(stderr, "parse_values(): vl.values[0] = %g, want 42\n",
            vl.values[0].gauge);
    ret = -1;
  }
  if (vl.values[1].derive != 31337) {
    fprintf(stderr, "parse_values(): vl.values[1] = %" PRIu64 ", want 31337\n",
            vl.values[1].derive);
    ret = -1;
  }
  if (!isnan(vl.values[2].gauge)) {
    fprintf(stderr, "parse_values(): vl.values[2] = %g, want NaN\n",
            vl.values[2].gauge);
    ret = -1;
  }

  free(vl.values);
  free(vl.values_types);

  return ret;
}

#if HAVE_GCRYPT_H
static int test_verify_sha256() {
  int ret = 0;

  int status = verify_sha256(
      (char[]){'c', 'o', 'l', 'l', 'e', 'c', 't', 'd'}, 8, "admin", "admin",
      (uint8_t[]){
          0xcd, 0xa5, 0x9a, 0x37, 0xb0, 0x81, 0xc2, 0x31, 0x24, 0x2a, 0x6d,
          0xbd, 0xfb, 0x44, 0xdb, 0xd7, 0x41, 0x2a, 0xf4, 0x29, 0x83, 0xde,
          0xa5, 0x11, 0x96, 0xd2, 0xe9, 0x30, 0x21, 0xae, 0xc5, 0x45,
      });
  if (status != 0) {
    fprintf(stderr, "verify_sha256() = %d, want 0\n", status);
    ret = -1;
  }

  status = verify_sha256(
      (char[]){'c', 'o', 'l', 'l', 'E', 'c', 't', 'd'}, 8, "admin", "admin",
      (uint8_t[]){
          0xcd, 0xa5, 0x9a, 0x37, 0xb0, 0x81, 0xc2, 0x31, 0x24, 0x2a, 0x6d,
          0xbd, 0xfb, 0x44, 0xdb, 0xd7, 0x41, 0x2a, 0xf4, 0x29, 0x83, 0xde,
          0xa5, 0x11, 0x96, 0xd2, 0xe9, 0x30, 0x21, 0xae, 0xc5, 0x45,
      });
  if (status != 1) {
    fprintf(stderr, "verify_sha256() = %d, want 1\n", status);
    ret = -1;
  }

  return ret;
}
#endif

#if HAVE_GCRYPT_H
static int test_decrypt_aes256() {
  char const *iv_str = "4cbe2a747c9f9dcfa0e66f0c2fa74875";
  uint8_t iv[16] = {0};
  size_t iv_len = sizeof(iv);

  char const *ciphertext_str =
      "8f023b0b15178f8428da1221a5f653e840f065db4aff032c22e5a3df";
  uint8_t ciphertext[28] = {0};
  size_t ciphertext_len = sizeof(ciphertext);

  if (decode_string(iv_str, iv, &iv_len) ||
      decode_string(ciphertext_str, ciphertext, &ciphertext_len)) {
    fprintf(stderr, "test_decrypt_aes256: decode_string failed.\n");
    return -1;
  }
  assert(iv_len == sizeof(iv));
  assert(ciphertext_len == sizeof(ciphertext));

  int status = decrypt_aes256(
      &(buffer_t){
          .data = ciphertext, .len = ciphertext_len,
      },
      iv, iv_len, "admin");
  if (status != 0) {
    fprintf(stderr, "decrypt_aes256() = %d, want 0\n", status);
    return -1;
  }

  char const *want = "collectd";
  char got[9] = {0};
  memmove(got, &ciphertext[20], sizeof(got) - 1);
  if (strcmp(got, want) != 0) {
    fprintf(stderr, "decrypt_aes256() = \"%s\", want \"%s\"\n", got, want);
    return -1;
  }

  return 0;
}
#endif

int main(void) {
  int ret = 0;

  int status;
  if ((status = test_network_parse())) {
    ret = status;
  }
  if ((status = test_parse_time())) {
    ret = status;
  }
  if ((status = test_parse_string())) {
    ret = status;
  }
  if ((status = test_parse_values())) {
    ret = status;
  }

#if HAVE_GCRYPT_H
  if ((status = test_verify_sha256())) {
    ret = status;
  }
  if ((status = test_decrypt_aes256())) {
    ret = status;
  }
#endif

  return ret;
}