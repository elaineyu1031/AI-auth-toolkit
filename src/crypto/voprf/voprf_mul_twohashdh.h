/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "src/crypto/voprf/voprf.h"

/**
 * (Double) Hashed Diffie-Hellman (two hash DH) implementations with
 * multiplactive blinding.
 * . (client) blind:
 * .   pick random scalar r
 * .   blinded_element = hash_1(input) * g^r
 * . (server) evaluate:
 * .   evaluated_element = blinded_element ^ sk
 * . (client) unblind:
 * .   unblinded_element = evaluated_element * pk^(-r)
 * .                     = hash_1(input) ^ sk
 * . (client) client_finalize:
 * .   client_final_evaluation = hash_2(input, unblinded_element)
 * . (server) server_finalize:
 * .   server_final_evaluation = hash_2(input, hash_1(input) ^ sk)
 * . client_final_evaluation and server_final_evaluation should match
 *
 * Example with curve ed25519:
 *   curve_t c;
 *   voprf_t v;
 *   curve_ed25519_init(&c);
 *   voprf_mul_twohashdh_init(&v, &c);
 *   v.blind(&v, ...);
 */

void voprf_mul_twohashdh_init(voprf_t* /* voprf */, curve_t* /* curve */);
