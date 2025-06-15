/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include "demo/SimpleAnonCredClient.h"

int main() {
  std::shared_ptr<apache::thrift::transport::TTransport> socket(
      new apache::thrift::transport::TSocket("127.0.0.1", 9090));
  std::shared_ptr<apache::thrift::transport::TTransport> transport(
      new apache::thrift::transport::TBufferedTransport(socket));
  std::shared_ptr<apache::thrift::protocol::TProtocol> protocol(
      new apache::thrift::protocol::TBinaryProtocol(transport));
  anon_cred::SimpleAnonCredClient client(protocol);
  transport->open();

  std::string token = "test_credential";
  std::vector<std::string> attributes = {"some", "random", "attributes"};

  client.getPrimaryPublicKey();
  client.getPublicKey(attributes);
  client.getCredential(token, attributes);
  client.redeemCredential(token, attributes);
  return 0;
}
