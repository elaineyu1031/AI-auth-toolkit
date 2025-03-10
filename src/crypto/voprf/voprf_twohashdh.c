/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/dleqproof/dleqproof.h"
#include "src/crypto/voprf/voprf.h"
#include "src/crypto/voprf/voprf_twohashdh.h"

#define CURVE_SUCCESS_CHECK(EXP)        \
  if (EXP != CURVE_SUCCESS) {           \
    return VOPRF_CURVE_OPERATION_ERROR; \
  }

enum voprf_error setup(
    voprf_t* voprf,
    unsigned char* sk,
    size_t sk_len,
    unsigned char* pk,
    size_t pk_len) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t scalar_bytes = voprf->curve->scalar_bytes;
  if (sk_len != scalar_bytes || pk_len != element_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }
  CURVE_SUCCESS_CHECK(voprf->curve->scalar_random(sk, sk_len));
  CURVE_SUCCESS_CHECK(
      voprf->curve->group_exp_generator(pk, pk_len, sk, sk_len));
  return VOPRF_SUCCESS;
}

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
    int flag_proof_generate) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t scalar_bytes = voprf->curve->scalar_bytes;
  if (evaluated_element_len != element_bytes || sk_len != scalar_bytes ||
      blinded_element_len != element_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }
  CURVE_SUCCESS_CHECK(
      voprf->curve->check_on_curve(blinded_element, blinded_element_len));
  // Perform evaluation
  CURVE_SUCCESS_CHECK(voprf->curve->group_exp(
      evaluated_element,
      evaluated_element_len,
      sk,
      sk_len,
      blinded_element,
      blinded_element_len));
  if (flag_proof_generate) {
    if (proof_c == NULL || proof_s == NULL) {
      return VOPRF_PROOF_ERROR;
    }
    if (proof_c_len != scalar_bytes || proof_s_len != scalar_bytes) {
      return VOPRF_BUFFER_LENGTH_ERROR;
    }
    size_t generator_len = element_bytes;
    unsigned char generator[generator_len];
    CURVE_SUCCESS_CHECK(voprf->curve->get_generator(generator, element_bytes));
    size_t pk_len = element_bytes;
    unsigned char pk[pk_len];
    CURVE_SUCCESS_CHECK(
        voprf->curve->group_exp_generator(pk, element_bytes, sk, scalar_bytes));
    dleqproof_protocol_t dleqproof;
    dleqproof_init(&dleqproof, voprf->curve);
    if (dleqproof.prove(
            &dleqproof,
            proof_c,
            proof_c_len,
            proof_s,
            proof_s_len,
            generator,
            generator_len,
            blinded_element,
            blinded_element_len,
            pk,
            pk_len,
            evaluated_element,
            evaluated_element_len,
            sk,
            sk_len) != CURVE_SUCCESS) {
      return VOPRF_PROOF_ERROR;
    }
  }

  return VOPRF_SUCCESS;
}

static enum voprf_error hash_final_evaluation(
    struct voprf* voprf,
    unsigned char* final_evaluation,
    const unsigned char* input,
    size_t input_len,
    const unsigned char* evaluation_element) {
  // TODO: Use indifferentiable hash function
  size_t element_len = voprf->curve->element_bytes;

  crypto_hash_sha512_state state;
  if (crypto_hash_sha512_init(&state) != CURVE_SUCCESS) {
    return VOPRF_HASH_OPERATION_ERROR;
  }
  if (crypto_hash_sha512_update(&state, input, input_len) != CURVE_SUCCESS) {
    return VOPRF_HASH_OPERATION_ERROR;
  }
  if (crypto_hash_sha512_update(&state, evaluation_element, element_len) !=
      CURVE_SUCCESS) {
    return VOPRF_HASH_OPERATION_ERROR;
  }
  if (crypto_hash_sha512_final(&state, final_evaluation) != CURVE_SUCCESS) {
    return VOPRF_HASH_OPERATION_ERROR;
  }

  return VOPRF_SUCCESS;
}

enum voprf_error client_finalize(
    voprf_t* voprf,
    unsigned char* final_evaluation,
    size_t final_evaluation_len,
    const unsigned char* input,
    size_t input_len,
    const unsigned char* unblinded_element,
    size_t unblinded_element_len) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t final_evaluation_bytes = voprf->final_evaluation_bytes;
  if (final_evaluation_len != final_evaluation_bytes ||
      unblinded_element_len != element_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }
  return hash_final_evaluation(
      voprf, final_evaluation, input, input_len, unblinded_element);
}

enum voprf_error server_finalize(
    voprf_t* voprf,
    unsigned char* final_evaluation,
    size_t final_evaluation_len,
    const unsigned char* input,
    size_t input_len,
    const unsigned char* sk,
    size_t sk_len) {
  size_t element_bytes = voprf->curve->element_bytes;
  size_t scalar_bytes = voprf->curve->scalar_bytes;
  size_t final_evaluation_bytes = voprf->final_evaluation_bytes;
  if (final_evaluation_len != final_evaluation_bytes ||
      sk_len != scalar_bytes) {
    return VOPRF_BUFFER_LENGTH_ERROR;
  }
  unsigned char hashed_message[element_bytes];
  unsigned char evaluation_element[element_bytes];
  CURVE_SUCCESS_CHECK(voprf->curve->hash_to_curve(
      hashed_message,
      (const unsigned char*[]){input},
      (const size_t[]){input_len},
      1));
  CURVE_SUCCESS_CHECK(voprf->curve->group_exp(
      evaluation_element,
      element_bytes,
      sk,
      sk_len,
      hashed_message,
      element_bytes));
  return hash_final_evaluation(
      voprf, final_evaluation, input, input_len, evaluation_element);
}
