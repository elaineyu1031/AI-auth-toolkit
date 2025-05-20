/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TServerSocket.h>
#include "demo/SimpleAnonCredServiceHandler.h"
#include "gen-cpp/SimpleAnonCredService.h"

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;
using namespace ::anon_cred;

int main(int argc, char** argv) {
  int port = 9090;
  ::std::shared_ptr<SimpleAnonCredServiceHandler> handler(
      new SimpleAnonCredServiceHandler());
  ::std::shared_ptr<TProcessor> processor(
      new SimpleAnonCredServiceProcessor(handler));
  ::std::shared_ptr<TServerTransport> serverTransport(new TServerSocket(port));
  ::std::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  ::std::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  TSimpleServer server(
      processor, serverTransport, transportFactory, protocolFactory);
  server.serve();
  return 0;
}
