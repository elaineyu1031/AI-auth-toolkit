/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "demo/SimpleAnonCredClient.h"
#include "demo/SimpleAnonCredUtils.h"

namespace anon_cred {

SimpleAnonCredClient::SimpleAnonCredClient(
    std::shared_ptr<::apache::thrift::protocol::TProtocol> prot)
    : thriftClient_(prot) {
  if (sodium_init() == -1) {
    throw std::runtime_error("sodium_init failed");
  }
  curve_ristretto_init(&curve_);
  voprf_mul_twohashdh_init(&voprf_, &curve_);
  kdf_sdhi_init(&kdf_, &curve_);
  primaryPublicKey.resize(kdf_.primary_public_key_bytes);
  publicKey.resize(curve_.element_bytes);
  unBlindedElement.resize(curve_.element_bytes);
}

void SimpleAnonCredClient::getPrimaryPublicKey() {
  thrift::GetPrimaryPublicKeyResponse getPrimaryPublicKeyResp;
  thriftClient_.getPrimaryPublicKey(getPrimaryPublicKeyResp);
  std::cout << "Returned primary public key: "
            << getPrimaryPublicKeyResp.primay_public_key << std::endl;
  primaryPublicKey = util::hexToBin(
      getPrimaryPublicKeyResp.primay_public_key, kdf_.primary_public_key_bytes);
}

void SimpleAnonCredClient::getPublicKey(
    const std::vector<std::string>& attributes) {
  auto attributeArrSize = attributes.size();
  std::vector<const unsigned char*> attributeArr;
  std::vector<size_t> attributeLenArr;
  for (const std::string& s : attributes) {
    attributeLenArr.push_back(s.size());
    attributeArr.push_back((const unsigned char*)s.data());
  }

  thrift::GetPublicKeyRequest getPublicKeyReq;
  getPublicKeyReq.attributes = attributes;
  thrift::GetPublicKeyResponse getPublicKeyResp;
  thriftClient_.getPublicKeyAndProof(getPublicKeyResp, getPublicKeyReq);
  std::cout << "Returned public key: " << getPublicKeyResp.public_key
            << std::endl;
  std::cout << "Returned public key proof: "
            << getPublicKeyResp.public_key_proof << std::endl;
  publicKey = util::hexToBin(getPublicKeyResp.public_key, curve_.element_bytes);
  auto pkProof = util::hexToBin(
      getPublicKeyResp.public_key_proof, kdf_.public_key_proof_bytes);
  auto pkVerifyResult = kdf_.verify_public_key(
      &kdf_,
      publicKey.data(),
      publicKey.size(),
      pkProof.data(),
      pkProof.size(),
      primaryPublicKey.data(),
      primaryPublicKey.size(),
      attributeArrSize,
      attributeArr.data(),
      attributeLenArr.data());

  if (pkVerifyResult == KDF_SUCCESS) {
    std::cout << "Public key proof validation success" << std::endl;
  } else {
    throw std::runtime_error("Public key proof validation failed");
  }
}

void SimpleAnonCredClient::getCredential(
    const std::string& cred,
    const std::vector<std::string>& attributes) {
  auto attributeArrSize = attributes.size();
  std::vector<const unsigned char*> attributeArr;
  std::vector<size_t> attributeLenArr;
  for (const std::string& s : attributes) {
    attributeLenArr.push_back(s.size());
    attributeArr.push_back((const unsigned char*)s.data());
  }
  auto elementBytes = curve_.element_bytes;
  auto scalarBytes = curve_.scalar_bytes;

  // blind
  std::vector<unsigned char> blindedElement(elementBytes);
  std::vector<unsigned char> blindingFactor(scalarBytes);
  voprf_.blind(
      &voprf_,
      blindedElement.data(),
      blindedElement.size(),
      blindingFactor.data(),
      blindingFactor.size(),
      (const unsigned char*)cred.data(),
      cred.size());
  auto blindedElementHex = util::binToHex(blindedElement);
  std::cout << "Blinded token: " << blindedElementHex << std::endl;

  // evaluate (sign, send to server)
  thrift::SignCredentialRequest signReq;
  thrift::SignCredentialResponse signResp;
  signReq.blinded_token = blindedElementHex;
  signReq.attributes = attributes;
  thriftClient_.signCredential(signResp, signReq);
  std::cout << "Returned evaluated token: " << signResp.evaluated_token
            << std::endl;
  auto blindedSignature =
      util::hexToBin(signResp.evaluated_token, elementBytes);
  auto proofC = util::hexToBin(signResp.proof_c, scalarBytes);
  auto proofS = util::hexToBin(signResp.proof_s, scalarBytes);

  // unblind and verify proof
  auto signatureVerifyResult = voprf_.verifiable_unblind(
      &voprf_,
      unBlindedElement.data(),
      unBlindedElement.size(),
      proofC.data(),
      proofC.size(),
      proofS.data(),
      proofS.size(),
      blindingFactor.data(),
      blindingFactor.size(),
      blindedSignature.data(),
      blindedSignature.size(),
      blindedElement.data(),
      blindedElement.size(),
      publicKey.data(),
      publicKey.size(),
      1);
  if (signatureVerifyResult == VOPRF_SUCCESS) {
    std::cout << "Sign token proof verification success" << std::endl;
  } else {
    throw std::runtime_error("Sign token proof verification failed");
  }
  std::cout << "Unblinded token: " << util::binToHex(unBlindedElement)
            << std::endl;
}

void SimpleAnonCredClient::redeemCredential(
    const std::string& cred,
    const std::vector<std::string>& attributes) {
  auto attributeArrSize = attributes.size();
  std::vector<const unsigned char*> attributeArr;
  std::vector<size_t> attributeLenArr;
  for (const std::string& s : attributes) {
    attributeLenArr.push_back(s.size());
    attributeArr.push_back((const unsigned char*)s.data());
  }
  auto elementBytes = curve_.element_bytes;
  auto scalarBytes = curve_.scalar_bytes;
  auto finalEvaluationBytes = voprf_.final_evaluation_bytes;
  std::vector<unsigned char> clientSecret(finalEvaluationBytes);
  voprf_.client_finalize(
      &voprf_,
      clientSecret.data(),
      clientSecret.size(),
      (const unsigned char*)cred.data(),
      cred.size(),
      unBlindedElement.data(),
      unBlindedElement.size());
  std::cout << "Client secret: " << util::binToHex(clientSecret) << std::endl;

  // redeem (server finalize, send to server)
  thrift::RedeemCredentialRequest redeemReq;
  redeemReq.token = cred;
  redeemReq.attributes = attributes;
  redeemReq.shared_secret = util::binToHex(clientSecret);
  try {
    thriftClient_.redeemCredential(redeemReq);
    std::cout << "Redeem credential success!" << std::endl;
  } catch (thrift::TokenEncodingException& e) {
    std::cout << "redeemCredential throws TokenEncodingException" << std::endl;
  } catch (thrift::VoprfErrorException& e) {
    std::cout << "redeemCredential throws VoprfErrorException with ErrorCode "
              << e.errorcode << std::endl;
  } catch (thrift::CredentialMismatchException& e) {
    std::cout << "redeemCredential failed. Credential mismatch!" << std::endl;
  }
}

} // namespace anon_cred
