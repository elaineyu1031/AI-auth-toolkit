/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/kdf/kdf.h"

/**
 * Implementation for KDF default.
 * Note: This KDF does NOT support public key proof.
 *
 * . primary key: random generated
 * . private key: sk = hash(primary_key, attr[0], attr[1], ...)
 * . public key: pk = g^sk, where g is the generator of the curve
 */

void kdf_default_init(kdf_t* /* kdf */, curve_t* /* curve */);
