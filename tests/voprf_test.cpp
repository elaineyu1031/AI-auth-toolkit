/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sodium/utils.h"

extern "C" {
#include "src/crypto/curve/curve.h"
#include "src/crypto/curve/curve_ed25519.h"
#include "src/crypto/curve/curve_ristretto.h"
#include "src/crypto/dleqproof/dleqproof.h"
#include "src/crypto/voprf/voprf.h"
#include "src/crypto/voprf/voprf_exp_twohashdh.h"
#include "src/crypto/voprf/voprf_mul_twohashdh.h"
}

namespace facebook {
namespace privacy_infra {
namespace anon_cred {
namespace {

enum class CryptoCurve {
  CURVE_ED25519,
  CURVE_RISTRETTO,
};

enum class Blinding {
  MULTIPLICATIVE,
  EXPONENTIAL,
};

struct VoprfTest
    : public testing::TestWithParam<std::tuple<CryptoCurve, Blinding>> {
  void SetUp() override {
    auto testParam = GetParam();
    switch (std::get<0>(testParam)) {
      case CryptoCurve::CURVE_ED25519:
        curve_ed25519_init(&curve_);
        break;
      case CryptoCurve::CURVE_RISTRETTO:
        curve_ristretto_init(&curve_);
        break;
    }
    switch (std::get<1>(testParam)) {
      case Blinding::MULTIPLICATIVE:
        voprf_mul_twohashdh_init(&voprf_, &curve_);
        break;
      case Blinding::EXPONENTIAL:
        voprf_exp_twohashdh_init(&voprf_, &curve_);
        break;
    }

    pk_ = (unsigned char*)malloc(curve_.scalar_bytes * sizeof(unsigned char));
    sk_ = (unsigned char*)malloc(curve_.element_bytes * sizeof(unsigned char));

    EXPECT_EQ(
        voprf_.setup(
            &voprf_, sk_, curve_.scalar_bytes, pk_, curve_.element_bytes),
        VOPRF_SUCCESS);
  }

  void TearDown() override {
    free(pk_);
    free(sk_);
  }

  curve_t curve_;
  voprf_t voprf_;
  unsigned char* pk_;
  unsigned char* sk_;
};

TEST_P(VoprfTest, NotOnCurveTest) {
  unsigned char output_buffer[curve_.element_bytes];
  unsigned char not_on_curve_element[curve_.element_bytes];
  unsigned char on_curve_element[curve_.element_bytes];
  unsigned char blinding_factor[curve_.scalar_bytes];
  char h[] = "cd10942ca1885798e1987b43b068f9b8f344576b44f570a5debf734949210960";
  sodium_hex2bin(
      not_on_curve_element,
      curve_.element_bytes,
      h,
      strlen(h),
      NULL,
      NULL,
      NULL);
  curve_.scalar_random(blinding_factor, curve_.element_bytes);
  curve_.hash_to_curve(
      on_curve_element,
      (const unsigned char*[]){blinding_factor},
      (const size_t[]){curve_.scalar_bytes},
      1);
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          output_buffer,
          curve_.element_bytes,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          blinding_factor,
          curve_.scalar_bytes,
          on_curve_element,
          curve_.element_bytes,
          not_on_curve_element,
          curve_.element_bytes,
          pk_,
          curve_.element_bytes,
          0 /* flag_proof_generate */),
      VOPRF_CURVE_OPERATION_ERROR);
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          output_buffer,
          curve_.element_bytes,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          blinding_factor,
          curve_.scalar_bytes,
          not_on_curve_element,
          curve_.element_bytes,
          on_curve_element,
          curve_.element_bytes,
          pk_,
          curve_.element_bytes,
          0 /* flag_proof_generate */),
      VOPRF_CURVE_OPERATION_ERROR);
  EXPECT_EQ(
      voprf_.evaluate(
          &voprf_,
          output_buffer,
          curve_.element_bytes,
          NULL,
          0,
          NULL,
          0,
          sk_,
          curve_.scalar_bytes,
          not_on_curve_element,
          curve_.element_bytes,
          0),
      VOPRF_CURVE_OPERATION_ERROR);
}

TEST_P(VoprfTest, BlindingTest) {
  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;

  // blind
  const size_t blinded_element_len = curve_.element_bytes;
  const size_t blinding_factor_len = curve_.scalar_bytes;
  unsigned char blinded_element[blinded_element_len];
  unsigned char blinding_factor[blinding_factor_len];
  EXPECT_EQ(
      voprf_.blind(
          &voprf_,
          blinded_element,
          blinded_element_len,
          blinding_factor,
          blinding_factor_len,
          token,
          token_len),
      VOPRF_SUCCESS);

  // evaluate
  const size_t evaluated_element_len = curve_.element_bytes;
  unsigned char evaluated_element[evaluated_element_len];
  EXPECT_EQ(
      voprf_.evaluate(
          &voprf_,
          evaluated_element,
          evaluated_element_len,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          sk_,
          curve_.scalar_bytes,
          blinded_element,
          blinded_element_len,
          0 /* flag_proof_generate */),
      VOPRF_SUCCESS);

  // unblind
  const size_t unblinded_element_len = curve_.element_bytes;
  unsigned char unblinded_element[unblinded_element_len];
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          unblinded_element,
          unblinded_element_len,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          blinding_factor,
          curve_.scalar_bytes,
          evaluated_element,
          evaluated_element_len,
          blinded_element,
          blinded_element_len,
          pk_,
          curve_.element_bytes,
          0 /* flag_proof_verify */),
      VOPRF_SUCCESS);

  // unblinded_element should be equal to H(token) ^ sk_
  unsigned char hashed_message_point[curve_.element_bytes];
  voprf_.curve->hash_to_curve(
      hashed_message_point,
      (const unsigned char*[]){token},
      (const size_t[]){token_len},
      1);
  unsigned char hashed_message_signed[curve_.element_bytes];
  voprf_.curve->group_exp(
      hashed_message_signed,
      curve_.element_bytes,
      sk_,
      curve_.scalar_bytes,
      hashed_message_point,
      curve_.element_bytes);
  EXPECT_EQ(
      sodium_memcmp(
          hashed_message_signed,
          unblinded_element,
          voprf_.curve->element_bytes),
      0);
}

TEST_P(VoprfTest, RedemptionTest) {
  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;

  unsigned char hashed_message_point[voprf_.curve->element_bytes];
  voprf_.curve->hash_to_curve(
      hashed_message_point,
      (const unsigned char*[]){token},
      (const size_t[]){token_len},
      1);
  unsigned char unblinded_element[voprf_.curve->element_bytes];
  voprf_.curve->group_exp(
      unblinded_element,
      curve_.element_bytes,
      sk_,
      curve_.scalar_bytes,
      hashed_message_point,
      curve_.element_bytes);
  // client finalize
  const size_t client_secret_len = voprf_.final_evaluation_bytes;
  unsigned char client_secret[client_secret_len];
  EXPECT_EQ(
      voprf_.client_finalize(
          &voprf_,
          client_secret,
          client_secret_len,
          token,
          token_len,
          unblinded_element,
          curve_.element_bytes),
      VOPRF_SUCCESS);

  // server finalize
  const size_t server_secret_len = voprf_.final_evaluation_bytes;
  unsigned char server_secret[server_secret_len];
  EXPECT_EQ(
      voprf_.server_finalize(
          &voprf_,
          server_secret,
          server_secret_len,
          token,
          token_len,
          sk_,
          curve_.scalar_bytes),
      VOPRF_SUCCESS);

  EXPECT_EQ(
      sodium_memcmp(
          client_secret, server_secret, voprf_.final_evaluation_bytes),
      0);
}

TEST_P(VoprfTest, WorkflowWithoutDLEQProofTest) {
  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;

  // blind
  const size_t blinded_element_len = curve_.element_bytes;
  const size_t blinding_factor_len = curve_.scalar_bytes;
  unsigned char blinded_element[blinded_element_len];
  unsigned char blinding_factor[blinding_factor_len];
  EXPECT_EQ(
      voprf_.blind(
          &voprf_,
          blinded_element,
          blinded_element_len,
          blinding_factor,
          blinding_factor_len,
          token,
          token_len),
      VOPRF_SUCCESS);

  // evaluate
  const size_t evaluated_element_len = curve_.element_bytes;
  unsigned char evaluated_element[evaluated_element_len];
  EXPECT_EQ(
      voprf_.evaluate(
          &voprf_,
          evaluated_element,
          evaluated_element_len,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          sk_,
          curve_.scalar_bytes,
          blinded_element,
          blinded_element_len,
          0 /* flag_proof_generate */),
      VOPRF_SUCCESS);

  // unblind
  const size_t unblinded_element_len = curve_.element_bytes;
  unsigned char unblinded_element[unblinded_element_len];
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          unblinded_element,
          unblinded_element_len,
          NULL /* proof_c */,
          0,
          NULL /* proof_s */,
          0,
          blinding_factor,
          blinding_factor_len,
          evaluated_element,
          evaluated_element_len,
          blinded_element,
          blinded_element_len,
          pk_,
          curve_.element_bytes,
          0 /* flag_proof_verify */),
      VOPRF_SUCCESS);

  // client finalize
  const size_t client_secret_len = voprf_.final_evaluation_bytes;
  unsigned char client_secret[client_secret_len];
  EXPECT_EQ(
      voprf_.client_finalize(
          &voprf_,
          client_secret,
          client_secret_len,
          token,
          token_len,
          unblinded_element,
          unblinded_element_len),
      VOPRF_SUCCESS);

  // server finalize
  const size_t server_secret_len = voprf_.final_evaluation_bytes;
  unsigned char server_secret[server_secret_len];
  EXPECT_EQ(
      voprf_.server_finalize(
          &voprf_,
          server_secret,
          server_secret_len,
          token,
          token_len,
          sk_,
          curve_.scalar_bytes),
      VOPRF_SUCCESS);

  EXPECT_EQ(
      sodium_memcmp(
          client_secret, server_secret, voprf_.final_evaluation_bytes),
      0);
}

TEST_P(VoprfTest, WorkflowTest) {
  unsigned char* token = (unsigned char*)"test";
  const size_t token_len = 4;

  // blind
  const size_t blinded_element_len = curve_.element_bytes;
  const size_t blinding_factor_len = curve_.scalar_bytes;
  unsigned char blinded_element[blinded_element_len];
  unsigned char blinding_factor[blinding_factor_len];
  EXPECT_EQ(
      voprf_.blind(
          &voprf_,
          blinded_element,
          blinded_element_len,
          blinding_factor,
          blinding_factor_len,
          token,
          token_len),
      VOPRF_SUCCESS);

  // evaluate
  const size_t evaluated_element_len = curve_.element_bytes;
  unsigned char evaluated_element[evaluated_element_len];
  const size_t proof_c_len = curve_.scalar_bytes;
  unsigned char proof_c[proof_c_len];
  const size_t proof_s_len = curve_.scalar_bytes;
  unsigned char proof_s[proof_s_len];
  EXPECT_EQ(
      voprf_.evaluate(
          &voprf_,
          evaluated_element,
          evaluated_element_len,
          proof_c,
          proof_c_len,
          proof_s,
          proof_s_len,
          sk_,
          curve_.scalar_bytes,
          blinded_element,
          blinded_element_len,
          1 /* flag_proof_generate */),
      VOPRF_SUCCESS);

  // unblind
  const size_t unblinded_element_len = curve_.element_bytes;
  unsigned char unblinded_element[unblinded_element_len];
  EXPECT_EQ(
      voprf_.verifiable_unblind(
          &voprf_,
          unblinded_element,
          unblinded_element_len,
          proof_c,
          proof_c_len,
          proof_s,
          proof_s_len,
          blinding_factor,
          blinding_factor_len,
          evaluated_element,
          evaluated_element_len,
          blinded_element,
          blinded_element_len,
          pk_,
          curve_.element_bytes,
          1 /* flag_proof_verify */),
      VOPRF_SUCCESS);

  // client finalize
  const size_t client_secret_len = voprf_.final_evaluation_bytes;
  unsigned char client_secret[client_secret_len];
  EXPECT_EQ(
      voprf_.client_finalize(
          &voprf_,
          client_secret,
          client_secret_len,
          token,
          token_len,
          unblinded_element,
          unblinded_element_len),
      VOPRF_SUCCESS);

  // server finalize
  const size_t server_secret_len = voprf_.final_evaluation_bytes;
  unsigned char server_secret[server_secret_len];
  EXPECT_EQ(
      voprf_.server_finalize(
          &voprf_,
          server_secret,
          server_secret_len,
          token,
          token_len,
          sk_,
          curve_.scalar_bytes),
      VOPRF_SUCCESS);

  EXPECT_EQ(
      sodium_memcmp(
          client_secret, server_secret, voprf_.final_evaluation_bytes),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    VOPRFLib,
    VoprfTest,
    testing::Combine(
        testing::Values(
            CryptoCurve::CURVE_ED25519,
            CryptoCurve::CURVE_RISTRETTO),
        testing::Values(Blinding::EXPONENTIAL, Blinding::MULTIPLICATIVE)));

} // namespace
} // namespace anon_cred
} // namespace privacy_infra
} // namespace facebook
