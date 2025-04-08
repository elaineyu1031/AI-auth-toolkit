/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <sodium.h>
#include <string.h>

#include "src/crypto/curve/curve.h"
#include "src/crypto/dleqproof/dleqproof.h"
#include "src/crypto/kdf/kdf.h"
#include "src/crypto/kdf/kdf_sdhi.h"

#define CURVE_SUCCESS_CHECK(EXP)      \
  if (EXP != CURVE_SUCCESS) {         \
    return KDF_CURVE_OPERATION_ERROR; \
  }

static enum kdf_error generate_primary_key(
    kdf_t* kdf,
    unsigned char* primary_key,
    size_t primary_key_len) {
  size_t element_bytes = kdf->curve->element_bytes;
  size_t scalar_bytes = kdf->curve->scalar_bytes;
  if (primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  CURVE_SUCCESS_CHECK(kdf->curve->scalar_random(primary_key, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(
      primary_key + kdf->primary_private_key_bytes,
      element_bytes,
      primary_key,
      scalar_bytes));
  return KDF_SUCCESS;
}

static enum kdf_error derive_key_pair(
    kdf_t* kdf,
    unsigned char* sk,
    size_t sk_len,
    unsigned char* pk,
    size_t pk_len,
    unsigned char* pk_proof,
    size_t pk_proof_len,
    const unsigned char* primary_key,
    size_t primary_key_len,
    int n_attributes,
    const unsigned char** attribute_arr,
    const size_t* attribute_len_arr,
    int flag_pk_proof_generate) {
  const size_t scalar_bytes = kdf->curve->scalar_bytes;
  const size_t element_bytes = kdf->curve->element_bytes;

  if (sk_len != scalar_bytes || pk_len != element_bytes ||
      primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }

  const unsigned char* primary_private_key_ptr = primary_key;

  // Hash attribute to scalar
  unsigned char attr_hash[scalar_bytes];
  CURVE_SUCCESS_CHECK(kdf->curve->hash_to_scalar(
      attr_hash, attribute_arr, attribute_len_arr, n_attributes));

  unsigned char tmp_inverse[scalar_bytes];
  CURVE_SUCCESS_CHECK(kdf->curve->scalar_add(
      tmp_inverse,
      scalar_bytes,
      primary_private_key_ptr,
      kdf->primary_private_key_bytes,
      attr_hash,
      scalar_bytes));
  CURVE_SUCCESS_CHECK(
      kdf->curve->scalar_inv(sk, scalar_bytes, tmp_inverse, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(pk, pk_len, sk, sk_len));

  if (flag_pk_proof_generate) {
    if (pk_proof == NULL) {
      return KDF_PK_PROOF_ERROR;
    }
    if (pk_proof_len != kdf->public_key_proof_bytes) {
      return KDF_BUFFER_LENGTH_ERROR;
    }
    unsigned char generator[element_bytes];
    CURVE_SUCCESS_CHECK(kdf->curve->get_generator(generator, element_bytes));

    unsigned char tmp_inverse_element[element_bytes];
    CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(
        tmp_inverse_element, element_bytes, tmp_inverse, scalar_bytes));
    dleqproof_protocol_t dleqproof;
    dleqproof_init(&dleqproof, kdf->curve);
    if (dleqproof.prove(
            &dleqproof /* protocol */,
            pk_proof /* proof_c */,
            scalar_bytes,
            pk_proof + scalar_bytes /* proof_s */,
            scalar_bytes,
            generator /* base1 */,
            element_bytes,
            pk /* base2 */,
            pk_len,
            tmp_inverse_element /* element1 */,
            element_bytes,
            generator /* element2 */,
            element_bytes,
            tmp_inverse /* discrete_log */,
            scalar_bytes) != DLEQPROOF_SUCCESS) {
      return KDF_PK_PROOF_ERROR;
    }
  }
  sodium_memzero(tmp_inverse, scalar_bytes);
  return KDF_SUCCESS;
}

static enum kdf_error verify_public_key(
    kdf_t* kdf,
    const unsigned char* pk,
    size_t pk_len,
    const unsigned char* pk_proof,
    size_t pk_proof_len,
    const unsigned char* ppk,
    size_t ppk_len,
    int n_attributes,
    const unsigned char** attribute_arr,
    const size_t* attribute_len_arr) {
  size_t scalar_bytes = kdf->curve->scalar_bytes;
  size_t element_bytes = kdf->curve->element_bytes;
  if (pk_len != element_bytes || pk_proof_len != kdf->public_key_proof_bytes ||
      ppk_len != kdf->primary_private_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  // Hash attribute to scalar
  unsigned char attr_hash[scalar_bytes];
  CURVE_SUCCESS_CHECK(kdf->curve->hash_to_scalar(
      attr_hash, attribute_arr, attribute_len_arr, n_attributes));

  unsigned char generator[element_bytes];
  unsigned char tmp_attr_element[element_bytes];
  unsigned char tmp_inverse_element[element_bytes];
  CURVE_SUCCESS_CHECK(kdf->curve->get_generator(generator, element_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(
      tmp_attr_element, element_bytes, attr_hash, scalar_bytes));
  CURVE_SUCCESS_CHECK(kdf->curve->group_op(
      tmp_inverse_element,
      element_bytes,
      ppk,
      ppk_len,
      tmp_attr_element,
      element_bytes));

  dleqproof_protocol_t dleqproof;
  dleqproof_init(&dleqproof, kdf->curve);
  return dleqproof.verify(
             &dleqproof /* protocol */,
             pk_proof /* proof_c */,
             scalar_bytes,
             pk_proof + scalar_bytes /* proof_s */,
             scalar_bytes,
             generator /* base1 */,
             element_bytes,
             pk /* base2 */,
             pk_len,
             tmp_inverse_element /* element1 */,
             element_bytes,
             generator /* element2 */,
             element_bytes) == DLEQPROOF_SUCCESS
      ? KDF_SUCCESS
      : KDF_PK_PROOF_ERROR;
}

static enum kdf_error derive_primary_public_key(
    kdf_t* kdf,
    unsigned char* ppk,
    size_t ppk_len,
    const unsigned char* primary_key,
    size_t primary_key_len) {
  if (ppk_len != kdf->primary_private_key_bytes ||
      primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  memcpy(
      ppk,
      primary_key + kdf->primary_private_key_bytes,
      kdf->primary_public_key_bytes);
  return KDF_SUCCESS;
}

void kdf_sdhi_init(kdf_t* kdf, curve_t* curve) {
  kdf->curve = curve;
  kdf->primary_private_key_bytes = curve->scalar_bytes;
  kdf->primary_public_key_bytes = curve->element_bytes;
  kdf->primary_key_bytes = curve->scalar_bytes + curve->element_bytes;
  kdf->public_key_proof_bytes = 2 * curve->scalar_bytes;
  kdf->generate_primary_key = generate_primary_key;
  kdf->derive_key_pair = derive_key_pair;
  kdf->verify_public_key = verify_public_key;
  kdf->derive_primary_public_key = derive_primary_public_key;
}
