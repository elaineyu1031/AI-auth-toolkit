/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <vector>

namespace anon_cred {
namespace util {
std::string binToHex(const std::vector<unsigned char>& bin);
std::vector<unsigned char> hexToBin(
    const std::string& hex,
    size_t desiredBinSize = 0);
} // namespace util
} // namespace anon_cred
