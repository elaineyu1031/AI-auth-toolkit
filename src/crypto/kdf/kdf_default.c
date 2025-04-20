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
#include "src/crypto/kdf/kdf_default.h"

#define CURVE_SUCCESS_CHECK(EXP)      \
  if (EXP != CURVE_SUCCESS) {         \
    return KDF_CURVE_OPERATION_ERROR; \
  }

static enum kdf_error generate_primary_key(
    kdf_t* kdf,
    unsigned char* primary_key,
    size_t primary_key_len) {
  if (primary_key_len != kdf->primary_key_bytes) {
    return KDF_BUFFER_LENGTH_ERROR;
  }
  randombytes_buf((void*)primary_key, primary_key_len);
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
  // Hash attribute to attribute secret key scalar
  unsigned char round_hmac_key[crypto_auth_hmacsha256_KEYBYTES];
  unsigned char out[crypto_auth_hmacsha256_BYTES];

  memcpy(round_hmac_key, primary_key, crypto_auth_hmacsha256_KEYBYTES);
  for (int i = 0; i < n_attributes; ++i) {
    crypto_auth_hmacsha256(
        out, attribute_arr[i], attribute_len_arr[i], round_hmac_key);
    memcpy(round_hmac_key, out, crypto_auth_hmacsha256_KEYBYTES);
  }

  CURVE_SUCCESS_CHECK(kdf->curve->hash_to_scalar(
      sk,
      (const unsigned char*[]){out},
      (const size_t[]){crypto_auth_hmacsha256_BYTES},
      1));
  CURVE_SUCCESS_CHECK(kdf->curve->group_exp_generator(pk, pk_len, sk, sk_len));

  sodium_memzero(round_hmac_key, crypto_auth_hmacsha256_KEYBYTES);
  sodium_memzero(out, crypto_auth_hmacsha256_BYTES);

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
  return KDF_SUCCESS;
}

static enum kdf_error derive_primary_public_key(
    kdf_t* kdf,
    unsigned char* ppk,
    size_t ppk_len,
    const unsigned char* primary_key,
    size_t primary_key_len) {
  return KDF_SUCCESS;
}

void kdf_default_init(kdf_t* kdf, curve_t* curve) {
  kdf->curve = curve;
  kdf->primary_private_key_bytes = crypto_auth_hmacsha256_KEYBYTES;
  kdf->primary_public_key_bytes = 0;
  kdf->primary_key_bytes = crypto_auth_hmacsha256_KEYBYTES;
  kdf->public_key_proof_bytes = 0;
  kdf->generate_primary_key = generate_primary_key;
  kdf->derive_key_pair = derive_key_pair;
  kdf->verify_public_key = verify_public_key;
  kdf->derive_primary_public_key = derive_primary_public_key;
}
