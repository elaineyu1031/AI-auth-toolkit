/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <stddef.h>

#include "src/crypto/curve/curve.h"

enum kdf_error {
  KDF_SUCCESS = 0,
  KDF_UNKNOWN_ERROR = -1,
  KDF_BUFFER_LENGTH_ERROR = 1,
  KDF_CURVE_OPERATION_ERROR = 2,
  KDF_PK_PROOF_ERROR = 3,
};

/**
 * Key derivation function (KDF) is used to derive general private and public
 * key pairs for VOPRF evaluate (sign) and finalize (redeem). For some KDFs, an
 * optional “public key proof” (pk_proof) can be generated. The proof can be
 * verified (by verify_attr_public_key) by the client to improve key
 * transparency.
 */

typedef struct kdf kdf_t;

struct kdf {
  /**
   * The size of the primary key.
   */
  size_t primary_key_bytes;

  /**
   * The size of the primary public key. (0 if the KDF does not support public
   * key proof)
   */
  size_t primary_public_key_bytes;

  /**
   * The size of the primary private key.
   */
  size_t primary_private_key_bytes;

  /**
   * The size of the public key proof. (0 if the KDF does not support public
   * key proof)
   */
  size_t public_key_proof_bytes;

  /**
   * The elliptic curve used in this KDF.
   */
  curve_t* curve;

  /**
   * Generated a random primary key. Some KDFs’ primary keys contain “private”
   * and “public” part, i.e. primary private key and primary public key. Some
   * KDFs’ primary keys only contain a single secret.
   *
   * @param kdf A pointer to kdf struct.
   * @param primary_key Mutable unsigned char buffers for output.
   * @param primary_key_len The size of this buffer should be primary_key_bytes
   * of the kdf.
   */
  enum kdf_error (*generate_primary_key)(
      kdf_t* /* kdf */,
      unsigned char* /* primary_key */,
      size_t /* primary_key_len */);

  /**
   * Derive primary public key from primary key.
   * Client can use this primary public key to verify the public key generated
   * from derive_primary_public_key().
   * Note: some KDFs may not support public key verification. For those KDFs,
   * this method will do nothing and return KDF_SUCCESS directly.
   *
   * @param kdf A pointer to kdf struct.
   * @param ppk Mutable unsigned char buffers for primary public key.
   * @param ppk_len The size of this buffer should be primary_public_key_bytes
   * of the KDF.
   * @param primary_key Immutable unsigned char buffers for primary key.
   * @param primary_key_len The size of these buffers should be
   * primary_key_bytes of the curve.
   */
  enum kdf_error (*derive_primary_public_key)(
      kdf_t* /* kdf */,
      unsigned char* /* ppk */,
      size_t /* ppk_len */,
      const unsigned char* /* primary_key */,
      size_t /* primary_key_len */
  );

  /**
   * Derive private key and public key from primary key and some attribute
   * strings. This private and public key pair can be used for VOPRF operations.
   * Optionally, generate a public key proof for clients to verify the public
   * key (with primary public key and attribute strings).
   * Note: some KDFs may not support public key verification. For those KDFs,
   * this method will ignore the parameter pk_proof and flag_pk_proof_generate.
   *
   * @param kdf A pointer to kdf struct.
   * @param sk Mutable unsigned char buffer for private key.
   * @param sk_len The size of this buffer should be scalar_bytes of the curve.
   * @param pk Mutable unsigned char buffer for public key.
   * @param pk_len The size of this buffer should be element_bytes of the curve.
   * @param pk_proof Mutable unsigned char buffer for public key proof. This is
   * optional if flag_pk_proof_generate = 0.
   * @param pk_proof_len The size of this buffer should be
   * public_key_proof_bytes of the kdf. This is optional if
   * flag_pk_proof_generate = 0.
   * @param primary_key Unsigned char buffer for primary key.
   * @param primary_key_len The size of this buffer should be primary_key_bytes
   * of the curve.
   * @param n_attributes Number of elements in attribute array
   * @param attribute_arr A pointer to an array, storing pointers to unsigned
   * char buffers. The size of the array should be n_attributes.
   * @param attribute_len_array A pointer to an array, storing the length of the
   * unsigned char buffer corresponding to the same index of attribute_arr.The
   * size of the array should be n_attributes.
   * @param flag_pk_proof_generate Use flag_pk_proof_generate = 1 if pk_proof is
   * needed, 0 otherwise.
   */
  enum kdf_error (*derive_key_pair)(
      kdf_t* /* kdf */,
      unsigned char* /* sk */,
      size_t /* sk_len */,
      unsigned char* /* pk */,
      size_t /* pk_len */,
      unsigned char* /* pk_proof */,
      size_t /* pk_proof_len */,
      const unsigned char* /* primary_key */,
      size_t /* primary_key_len */,
      int /* n_attributes */,
      const unsigned char** /* attribute_arr */,
      const size_t* /* attribute_len_arr */,
      int /* flag_pk_proof_generate */);

  /**
   * (Client side) Verify the public key received with public key proof and
   * primary public key.
   * Note: some KDFs may not support public key verification. For those KDFs,
   * this method will do nothing and return KDF_SUCCESS directly.
   *
   * @param kdf A pointer to kdf struct.
   * @param pk Unsigned char buffer for public key.
   * @param pk_len The size of this buffer should be element_bytes of the curve.
   * @param pk_proof Unsigned char buffer for public key proof.
   * @param pk_proof_len The size of this buffer should be
   * public_key_proof_bytes of the kdf.
   * @param ppk Unsigned char buffer for primary public key.
   * @param ppk_len The size of this buffer should be primary_public_key_bytes
   * of the curve.
   * @param n_attributes Number of elements in attribute array
   * @param attribute_arr A pointer to an array, storing pointers to unsigned
   * char buffers. The size of the array should be n_attributes.
   * @param attribute_len_array A pointer to an array, storing the length of the
   * unsigned char buffer corresponding to the same index of attribute_arr.The
   * size of the array should be n_attributes.
   */
  enum kdf_error (*verify_public_key)(
      kdf_t* /* kdf */,
      const unsigned char* /* pk */,
      size_t /* pk_len */,
      const unsigned char* /* pk_proof */,
      size_t /* pk_proof_len */,
      const unsigned char* /* ppk */,
      size_t /* ppk_len */,
      int /* n_attributes */,
      const unsigned char** /* attribute_arr */,
      const size_t* /* attribute_len_arr */);
};
