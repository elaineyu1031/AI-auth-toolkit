/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "demo/SimpleAnonCredUtils.h"
#include <sodium.h>
#include "gen-cpp/service_types.h"

namespace anon_cred {
namespace util {
std::string binToHex(const std::vector<unsigned char>& bin) {
  char buf[bin.size() * 2 + 1];
  sodium_bin2hex(buf, bin.size() * 2 + 1, bin.data(), bin.size());
  return std::string(buf);
}

std::vector<unsigned char> hexToBin(
    const std::string& hex,
    size_t desiredBinSize) {
  std::vector<unsigned char> bin(
      desiredBinSize == 0 ? hex.size() : desiredBinSize);
  size_t length;
  if (sodium_hex2bin(
          bin.data(),
          bin.size(),
          hex.data(),
          hex.size(),
          nullptr,
          &length,
          nullptr) != 0 ||
      (desiredBinSize != 0 && desiredBinSize != length)) {
    thrift::TokenEncodingException exception;
    exception.message = "Failed to convert token " + hex + " to binary";
    throw exception;
  }
  bin.resize(length);
  return bin;
}
} // namespace util
} // namespace anon_cred
