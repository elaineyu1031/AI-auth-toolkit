/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "src/crypto/voprf/voprf.h"

/*
  This is a header for helper functions used in voprf_exp_twohashdh and
  voprf_mul_twohashdh. Do not use this as an implementation directly
*/

enum voprf_error setup(
    voprf_t* voprf,
    unsigned char* sk,
    size_t sk_len,
    unsigned char* pk,
    size_t pk_len);

enum voprf_error evaluate(
    voprf_t* voprf,
    unsigned char* evaluated_element,
    size_t evaluated_element_len,
    unsigned char* proof_c,
    size_t proof_c_len,
    unsigned char* proof_s,
    size_t proof_s_len,
    const unsigned char* sk,
    size_t sk_len,
    const unsigned char* blinded_element,
    size_t blinded_element_len,
    int flag_proof_generate);

enum voprf_error client_finalize(
    voprf_t* voprf,
    unsigned char* final_evaluation,
    size_t final_evaluation_len,
    const unsigned char* input,
    size_t input_len,
    const unsigned char* unblinded_element,
    size_t unblinded_element_len);

enum voprf_error server_finalize(
    voprf_t* voprf,
    unsigned char* final_evaluation,
    size_t final_evaluation_len,
    const unsigned char* input,
    size_t input_len,
    const unsigned char* sk,
    size_t sk_len);
