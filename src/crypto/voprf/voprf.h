/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <stddef.h>

#include "src/crypto/curve/curve.h"

enum voprf_error {
  VOPRF_SUCCESS = 0,
  VOPRF_UNKNOWN_ERROR = -1,
  VOPRF_BUFFER_LENGTH_ERROR = 1,
  VOPRF_CURVE_OPERATION_ERROR = 2,
  VOPRF_HASH_OPERATION_ERROR = 3,
  VOPRF_PROOF_ERROR = 4,
};

/**
 * User interface for VOPRF library. See demo.c for examples.
 *
 * (Double) Hashed Diffie-Hellman (two hash DH) implementations with exponential
 * blinding and multiplactive blinding are provided.
 */

typedef struct voprf voprf_t;

struct voprf {
  /**
   * The length of final evaluation used in this VOPRF protocol.
   */
  size_t final_evaluation_bytes;

  /**
   * The elliptic curve used in this VOPRF protocol.
   */
  curve_t* curve;

  /**
   * Computes a (sk, pk) pair.
   * This method is designed for demo. In real applications consider using key
   * pairs generated from KDF.
   *
   * @param voprf A pointer to voprf struct.
   * @param sk Mutable unsigned char buffer for secret key.
   * @param sk_len The size of this buffer should be scalar_bytes of the curve.
   * @param pk Mutable unsigned char buffer for public key.
   * @param pk_len The size of this buffer should be element_bytes of the curve.
   */
  enum voprf_error (*setup)(
      voprf_t* /* voprf */,
      unsigned char* /* sk */,
      size_t /* sk_len */,
      unsigned char* /* pk */,
      size_t /* pk_len */);

  /**
   * (Client side) Blind a token, generate a blinded_element and a
   * blinding_factor. blinded_element is supposed to be sent to server for
   * evaluation. blinding_factor is random generated and should be stored on
   * client for unblinding.
   *
   * @param voprf A pointer to voprf struct.
   * @param blinded_element Mutable unsigned char buffer for blinded_element.
   * @param blinded_element_len The size of this buffer should be element_bytes
   * of the curve.
   * @param blinding_factor Mutable unsigned char buffer for blinding_factor.
   * @param blinding_factor_len The size of this buffer should be scalar_bytes
   * of the curve.
   * @param input Unsigned char buffer for input token. We recommend using
   * random generated tokens.
   * @param input_len The size of input buffer.
   */
  enum voprf_error (*blind)(
      voprf_t* /* voprf */,
      unsigned char* /* blinded_element */,
      size_t /* blinded_element_len */,
      unsigned char* /* blinding_factor */,
      size_t /* blinding_factor_len */,
      const unsigned char* /* input */,
      const size_t /* input_len */);

  /**
   * (Server side) Evalutate a blinded_element from client, and optionally
   * generate a DLEQPROOF
   *
   * @param voprf A pointer to voprf struct.
   * @param evaluated_element Mutable unsigned char buffer for
   * evaluated_element.
   * @param evaluated_element_len The size of this buffer should be
   * element_bytes of the curve.
   * @param proof_c Mutable unsigned char buffers for proof_c. This is optional
   * if flag_proof_generate = 0.
   * @param proof_c_len The size of this buffer should be scalar_bytes of the
   * curve. This is optional if flag_proof_generate = 0
   * @param proof_s Mutable unsigned char buffers for proof_s. This is optional
   * if flag_proof_generate = 0.
   * @param proof_s_len The size of this buffer should be scalar_bytes of the
   * curve. This is optional if flag_proof_generate = 0
   * @param sk Unsigned char buffer for secret key.
   * @param sk_len The size of this buffer should be scalar_bytes of the curve.
   * @param blinded_element Unsigned char buffer for blinded_element to be
   * evaluated.
   * @param blinded_element_len The size of this buffer should be element_bytes
   * of the curve.
   * @param flag_proof_generate Use flag_proof_generate = 1 if DLEQPROOF is
   * needed, 0 otherwise.
   */
  enum voprf_error (*evaluate)(
      voprf_t* /* voprf */,
      unsigned char* /* evaluated_element */,
      size_t /* evaluated_element_len */,
      unsigned char* /* proof_c */,
      size_t /* proof_c_len */,
      unsigned char* /* proof_s */,
      size_t /* proof_s_len */,
      const unsigned char* /* sk */,
      size_t /* sk_len */,
      const unsigned char* /* blinded_element */,
      size_t /* blinded_element_len */,
      int /* flag_proof_generate */);

  /**
   * (Client side) Unblind token, and optionally check DLEQPROOF from server.
   *
   * @param voprf A pointer to voprf struct.
   * @param unblinded_element Mutable unsigned char buffer for
   * unblinded_element.
   * @param unblinded_element_len The size of this buffer should be
   * element_bytes of the curve.
   * @param proof_c Unsigned char buffers for proof_c. This is optional if
   * flag_proof_generate = 0.
   * @param proof_c_len The size of this buffer should be scalar_bytes of the
   * curve. This is optional if flag_proof_generate = 0
   * @param proof_s unsigned char buffers for proof_s. This is optional if
   * flag_proof_generate = 0.
   * @param proof_s_len The size of this buffer should be scalar_bytes of the
   * curve. This is optional if flag_proof_generate = 0
   * @param blinding_factor Unsigned char buffer for blinding_factor generated
   * from blind().
   * @param blinding_factor_len The size of this buffer should be scalar_bytes
   * of the curve.
   * @param evaluated_element Unsigned char buffer for evaluated_element from
   * server.
   * @param evaluated_element_len The size of this buffer should be
   * element_bytes of the curve.
   * @param blinded_element Unsigned char buffer for blinded_element generated
   * from blind().
   * @param blinded_element_len The size of this buffer should be element_bytes
   * of the curve.
   * @param pk Unsigned char buffer for private key.
   * @param pk_len The size of this buffer should be element_bytes of the curve.
   * @param flag_proof_generate Use flag_proof_generate = 1 if DLEQPROOF is
   * needed, 0 otherwise.
   */
  enum voprf_error (*verifiable_unblind)(
      voprf_t* /* voprf */,
      unsigned char* /* unblinded_element */,
      size_t /* unblinded_element_len */,
      const unsigned char* /* proof_c */,
      size_t /* proof_c_len */,
      const unsigned char* /* proof_s */,
      size_t /* proof_s_len */,
      const unsigned char* /* blinding_factor */,
      size_t /* blinding_factor_len */,
      const unsigned char* /* evaluated_element */,
      size_t /* evaluated_element_len */,
      const unsigned char* /* blinded_element */,
      size_t /* blinded_element_len */,
      const unsigned char* /* pk */,
      size_t /* pk_len */,
      int /* flag_proof_verify */);

  /**
   * (Client side) Generate a shared secret for redemption.
   *
   * @param voprf A pointer to voprf struct.
   * @param final_evaluation Mutable unsigned char buffer for shared secret
   * (output).
   * @param final_evaluation_len The size of this buffer should be
   * final_evaluation_bytes.
   * @param input unsigned char buffer for input token used in blind().
   * @param input_size The size of input buffer.
   * @param unblinded_element unsigned char buffer for unblinded_element
   * generated from element_bytes().
   * @param unblinded_element_len The size of this buffer should be
   * element_bytes of the curve.
   */
  enum voprf_error (*client_finalize)(
      voprf_t* /* voprf */,
      unsigned char* /* final_evaluation */,
      size_t /* final_evaluation_len */,
      const unsigned char* /* input */,
      size_t /* input_len */,
      const unsigned char* /* unblinded_element */,
      size_t /* unblinded_element_len */
  );

  /**
   * (Server side) Generate a shared secret for redemption.
   *
   * @param voprf A pointer to voprf struct.
   * @param final_evaluation Mutable unsigned char buffer for shared secret
   * (output).
   * @param final_evaluation_len The size of this buffer should be
   * final_evaluation_bytes.
   * @param input unsigned char buffer for input token used in blind().
   * @param input_size The size of input buffer.
   * @param sk Unsigned char buffer for secret key.
   * @param sk_len The size of this buffer should be scalar_bytes of the curve.
   */
  enum voprf_error (*server_finalize)(
      voprf_t* /* voprf */,
      unsigned char* /* final_evaluation */,
      size_t /* final_evaluation_len */,
      const unsigned char* /* input */,
      size_t /* input_len */,
      const unsigned char* /* sk */,
      size_t /* sk_len */
  );
};
