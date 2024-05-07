









namespace Envoy {
namespace {


class ConnectTerminationIntegrationTest : public HttpProtocolIntegrationTest {
public:
  ConnectTerminationIntegrationTest() { enableHalfClose(true); }

  void initialize() override {
    config_helper_.addConfigModifier( [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {

          ConfigHelper::setConnectConfig(hcm, true, allow_post_, downstream_protocol_ == Http::CodecType::HTTP3);

          if (enable_timeout_) {
            hcm.mutable_stream_idle_timeout()->set_seconds(0);
            hcm.mutable_stream_idle_timeout()->set_nanos(200 * 1000 * 1000);
          }
          if (exact_match_) {
            auto* route_config = hcm.mutable_route_config();
            ASSERT_EQ(1, route_config->virtual_hosts_size());
            route_config->mutable_virtual_hosts(0)->clear_domains();
            route_config->mutable_virtual_hosts(0)->add_domains("host:80");
          }
        });
    HttpIntegrationTest::initialize();
  }

  void setUpConnection() {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto encoder_decoder = codec_client_->startRequest(connect_headers_);
    request_encoder_ = &encoder_decoder.first;
    response_ = std::move(encoder_decoder.second);
    ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_raw_upstream_connection_));
    response_->waitForHeaders();
  }

  void sendBidirectionalData(const char* downstream_send_data = "hello", const char* upstream_received_data = "hello", const char* upstream_send_data = "there!", const char* downstream_received_data = "there!") {


    
    codec_client_->sendData(*request_encoder_, downstream_send_data, false);
    ASSERT_TRUE(fake_raw_upstream_connection_->waitForData( FakeRawConnection::waitForInexactMatch(upstream_received_data)));

    
    ASSERT_TRUE(fake_raw_upstream_connection_->write(upstream_send_data));
    response_->waitForBodyData(strlen(downstream_received_data));
    EXPECT_EQ(downstream_received_data, response_->body());
  }

  Http::TestRequestHeaderMapImpl connect_headers_{{":method", "CONNECT", {":path", "/", {":protocol", "bytestream", {":scheme", "https", {":authority", "host:80";



  void clearExtendedConnectHeaders() {
    connect_headers_.removeProtocol();
    connect_headers_.removePath();
  }

  void sendBidirectionalDataAndCleanShutdown() {
    sendBidirectionalData("hello", "hello", "there!", "there!");
    
    sendBidirectionalData(",bye", "hello,bye", "ack", "there!ack");

    
    codec_client_->sendData(*request_encoder_, "", true);
    ASSERT_TRUE(fake_raw_upstream_connection_->waitForHalfClose());

    
    ASSERT_TRUE(fake_raw_upstream_connection_->close());
    if (downstream_protocol_ == Http::CodecType::HTTP1) {
      ASSERT_TRUE(codec_client_->waitForDisconnect());
    } else {
      ASSERT_TRUE(response_->waitForEndStream());
      ASSERT_FALSE(response_->reset());
    }
  }

  FakeRawConnectionPtr fake_raw_upstream_connection_;
  IntegrationStreamDecoderPtr response_;
  bool enable_timeout_{};
  bool exact_match_{};
  bool allow_post_{};
};

TEST_P(ConnectTerminationIntegrationTest, OriginalStyle) {
  initialize();
  clearExtendedConnectHeaders();

  setUpConnection();
  sendBidirectionalDataAndCleanShutdown();
}

TEST_P(ConnectTerminationIntegrationTest, Basic) {
  initialize();

  setUpConnection();
  sendBidirectionalDataAndCleanShutdown();
}

TEST_P(ConnectTerminationIntegrationTest, BasicAllowPost) {
  allow_post_ = true;
  initialize();

  
  connect_headers_.setMethod("POST");
  connect_headers_.removeProtocol();

  setUpConnection();
  sendBidirectionalDataAndCleanShutdown();
}

TEST_P(ConnectTerminationIntegrationTest, UsingHostMatch) {
  exact_match_ = true;
  initialize();

  connect_headers_.removePath();
  connect_headers_.removeProtocol();

  setUpConnection();
  sendBidirectionalDataAndCleanShutdown();
}

TEST_P(ConnectTerminationIntegrationTest, DownstreamClose) {
  initialize();

  setUpConnection();
  sendBidirectionalData();

  
  codec_client_->close();
  ASSERT_TRUE(fake_raw_upstream_connection_->waitForHalfClose());
}

TEST_P(ConnectTerminationIntegrationTest, DownstreamReset) {
  if (downstream_protocol_ == Http::CodecType::HTTP1) {
    
    return;
  }
  initialize();

  setUpConnection();
  sendBidirectionalData();

  
  codec_client_->sendReset(*request_encoder_);
  ASSERT_TRUE(fake_raw_upstream_connection_->waitForHalfClose());
}

TEST_P(ConnectTerminationIntegrationTest, UpstreamClose) {
  initialize();

  setUpConnection();
  sendBidirectionalData();

  
  ASSERT_TRUE(fake_raw_upstream_connection_->close());
  if (downstream_protocol_ == Http::CodecType::HTTP3) {
    
    
    ASSERT_TRUE(response_->waitForEndStream());
  } else {
    ASSERT_TRUE(response_->waitForReset());
  }
}

TEST_P(ConnectTerminationIntegrationTest, TestTimeout) {
  enable_timeout_ = true;
  initialize();

  setUpConnection();

  
  ASSERT_TRUE(response_->waitForReset());
  ASSERT_TRUE(fake_raw_upstream_connection_->waitForHalfClose());
}

TEST_P(ConnectTerminationIntegrationTest, BuggyHeaders) {
  if (downstream_protocol_ == Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  
  
  codec_client_ = makeHttpConnection(lookupPort("http"));
  response_ = codec_client_->makeHeaderOnlyRequest( Http::TestRequestHeaderMapImpl{{":method", "CONNECT", {":path", "/", {":protocol", "bytestream", {":scheme", "https", {":authority", "host:80");




  
  
  if (fake_upstreams_[0]->waitForRawConnection(fake_raw_upstream_connection_) && fake_raw_upstream_connection_->connected()) {
    ASSERT_TRUE(fake_raw_upstream_connection_->waitForHalfClose());
    ASSERT_TRUE(fake_raw_upstream_connection_->close());
  }

  
  
  ASSERT_TRUE(response_->waitForEndStream());
  ASSERT_FALSE(response_->reset());
}

TEST_P(ConnectTerminationIntegrationTest, BasicMaxStreamDuration) {
  setUpstreamProtocol(upstreamProtocol());
  config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
    ConfigHelper::HttpProtocolOptions protocol_options;
    protocol_options.mutable_common_http_protocol_options()
        ->mutable_max_stream_duration()
        ->MergeFrom(ProtobufUtil::TimeUtil::MillisecondsToDuration(1000));
    ConfigHelper::setProtocolOptions(*bootstrap.mutable_static_resources()->mutable_clusters(0), protocol_options);
  });

  initialize();
  setUpConnection();
  sendBidirectionalData();

  test_server_->waitForCounterGe("cluster.cluster_0.upstream_rq_max_duration_reached", 1);

  if (downstream_protocol_ == Http::CodecType::HTTP1) {
    ASSERT_TRUE(codec_client_->waitForDisconnect());
  } else {
    ASSERT_TRUE(response_->waitForReset());
    codec_client_->close();
  }
}


TEST_P(ConnectTerminationIntegrationTest, IgnoreH11HostField) {
  
  if (downstream_protocol_ != Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  std::string response;
  const std::string full_request = "CONNECT www.foo.com:443 HTTP/1.1\r\n" "Host: www.bar.com:443\r\n\r\n";
  EXPECT_LOG_CONTAINS( "", "':authority', 'www.foo.com:443'\n" "':method', 'CONNECT'", sendRawHttpAndWaitForResponse(lookupPort("http"), full_request.c_str(), &response, false););



}


class ProxyingConnectIntegrationTest : public HttpProtocolIntegrationTest {
public:
  void initialize() override {
    config_helper_.addConfigModifier( [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) -> void {

          ConfigHelper::setConnectConfig(hcm, false, false, downstream_protocol_ == Http::CodecType::HTTP3);
        });

    HttpProtocolIntegrationTest::initialize();
  }

  Http::TestRequestHeaderMapImpl connect_headers_{{":method", "CONNECT", {":path", "/", {":protocol", "bytestream", {":scheme", "https", {":authority", "host:80";



  IntegrationStreamDecoderPtr response_;
};

INSTANTIATE_TEST_SUITE_P(Protocols, ProxyingConnectIntegrationTest, testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams( {Http::CodecType::HTTP1, Http::CodecType::HTTP2, Http::CodecType::HTTP3}, {Http::CodecType::HTTP1})), HttpProtocolIntegrationTest::protocolTestParamsToString);





TEST_P(ProxyingConnectIntegrationTest, ProxyConnect) {
  initialize();

  
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder = codec_client_->startRequest(connect_headers_);
  request_encoder_ = &encoder_decoder.first;
  response_ = std::move(encoder_decoder.second);

  
  AssertionResult result = fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_);
  RELEASE_ASSERT(result, result.message());
  result = fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_);
  RELEASE_ASSERT(result, result.message());
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().get(Http::Headers::get().Method)[0]->value(), "CONNECT");
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    EXPECT_TRUE(upstream_request_->headers().get(Http::Headers::get().Protocol).empty());
  } else {
    EXPECT_EQ(upstream_request_->headers().get(Http::Headers::get().Protocol)[0]->value(), "bytestream");
  }

  
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  response_->waitForHeaders();
  EXPECT_EQ("200", response_->headers().getStatusValue());

  
  codec_client_->sendData(*request_encoder_, "hello", false);
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

  
  upstream_request_->encodeData(12, false);
  response_->waitForBodyData(12);

  cleanupUpstreamAndDownstream();
}

TEST_P(ProxyingConnectIntegrationTest, ProxyConnectWithPortStripping) {
  config_helper_.addConfigModifier( [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) {

        hcm.set_strip_any_host_port(true);
        auto* route_config = hcm.mutable_route_config();
        auto* header_value_option = route_config->mutable_request_headers_to_add()->Add();
        auto* mutable_header = header_value_option->mutable_header();
        mutable_header->set_key("Host-In-Envoy");
        mutable_header->set_value("%REQ(:AUTHORITY)%");
      });

  initialize();

  
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder = codec_client_->startRequest(connect_headers_);
  request_encoder_ = &encoder_decoder.first;
  response_ = std::move(encoder_decoder.second);

  
  AssertionResult result = fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_);
  RELEASE_ASSERT(result, result.message());
  result = fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_);
  RELEASE_ASSERT(result, result.message());
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().getMethodValue(), "CONNECT");
  EXPECT_EQ(upstream_request_->headers().getHostValue(), "host:80");
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    EXPECT_TRUE(upstream_request_->headers().getProtocolValue().empty());
  } else {
    EXPECT_EQ(upstream_request_->headers().getProtocolValue(), "bytestream");
  }
  auto stripped_host = upstream_request_->headers().get(Http::LowerCaseString("host-in-envoy"));
  ASSERT_EQ(stripped_host.size(), 1);
  EXPECT_EQ(stripped_host[0]->value(), "host");

  
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  response_->waitForHeaders();
  EXPECT_EQ("200", response_->headers().getStatusValue());

  
  codec_client_->sendData(*request_encoder_, "hello", false);
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

  
  upstream_request_->encodeData(12, false);
  response_->waitForBodyData(12);

  cleanupUpstreamAndDownstream();
}

TEST_P(ProxyingConnectIntegrationTest, ProxyConnectWithIP) {
  initialize();

  
  codec_client_ = makeHttpConnection(lookupPort("http"));
  connect_headers_.setHost("1.2.3.4:80");
  auto encoder_decoder = codec_client_->startRequest(connect_headers_);
  request_encoder_ = &encoder_decoder.first;
  response_ = std::move(encoder_decoder.second);

  
  AssertionResult result = fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_);
  RELEASE_ASSERT(result, result.message());
  result = fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_);
  RELEASE_ASSERT(result, result.message());
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().get(Http::Headers::get().Method)[0]->value(), "CONNECT");
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    EXPECT_TRUE(upstream_request_->headers().get(Http::Headers::get().Protocol).empty());
  } else {
    EXPECT_EQ(upstream_request_->headers().get(Http::Headers::get().Protocol)[0]->value(), "bytestream");
  }

  
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  response_->waitForHeaders();
  EXPECT_EQ("200", response_->headers().getStatusValue());

  cleanupUpstreamAndDownstream();
}

INSTANTIATE_TEST_SUITE_P(HttpAndIpVersions, ConnectTerminationIntegrationTest, testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams( {Http::CodecType::HTTP1, Http::CodecType::HTTP2, Http::CodecType::HTTP3}, {Http::CodecType::HTTP1})), HttpProtocolIntegrationTest::protocolTestParamsToString);





using Params = std::tuple<Network::Address::IpVersion, Http::CodecType>;


class TcpTunnelingIntegrationTest : public HttpProtocolIntegrationTest {
public:
  void SetUp() override {
    enableHalfClose(true);

    config_helper_.addConfigModifier( [&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
          envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy proxy_config;
          proxy_config.set_stat_prefix("tcp_stats");
          proxy_config.set_cluster("cluster_0");
          proxy_config.mutable_tunneling_config()->set_hostname("host.com:80");

          auto* listener = bootstrap.mutable_static_resources()->add_listeners();
          listener->set_name("tcp_proxy");
          auto* socket_address = listener->mutable_address()->mutable_socket_address();
          socket_address->set_address(Network::Test::getLoopbackAddressString(version_));
          socket_address->set_port_value(0);

          auto* filter_chain = listener->add_filter_chains();
          auto* filter = filter_chain->add_filters();
          filter->mutable_typed_config()->PackFrom(proxy_config);
          filter->set_name("envoy.filters.network.tcp_proxy");
        });
    HttpProtocolIntegrationTest::SetUp();
  }

  void setUpConnection(FakeHttpConnectionPtr& fake_upstream_connection) {
    
    tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
    if (!fake_upstream_connection) {
      ASSERT_TRUE( fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    }
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request_));
    ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

    
    upstream_request_->encodeHeaders(default_response_headers_, false);
  }

  void sendBidiData(FakeHttpConnectionPtr& fake_upstream_connection, bool send_goaway = false) {
    
    ASSERT_TRUE(tcp_client_->write("hello", false));
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

    if (send_goaway) {
      fake_upstream_connection->encodeGoAway();
    }
    
    upstream_request_->encodeData(12, false);
    ASSERT_TRUE(tcp_client_->waitForData(12));
  }

  void closeConnection(FakeHttpConnectionPtr& fake_upstream_connection) {
    
    
    ASSERT_TRUE(tcp_client_->write("hello", false));
    tcp_client_->close();
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));
    if (upstreamProtocol() == Http::CodecType::HTTP1) {
      ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
    } else {
      ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
      
      upstream_request_->encodeData(0, true);
    }
  }

  IntegrationTcpClientPtr tcp_client_;
};

TEST_P(TcpTunnelingIntegrationTest, Basic) {
  initialize();

  setUpConnection(fake_upstream_connection_);
  sendBidiData(fake_upstream_connection_);
  closeConnection(fake_upstream_connection_);
}

TEST_P(TcpTunnelingIntegrationTest, SendDataUpstreamAfterUpstreamClose) {
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    
    return;
  }
  initialize();

  setUpConnection(fake_upstream_connection_);
  sendBidiData(fake_upstream_connection_);
  
  upstream_request_->encodeData(2, true);
  tcp_client_->waitForHalfClose();

  
  ASSERT_TRUE(tcp_client_->write("hello", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

  
  tcp_client_->close();
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  }
}

TEST_P(TcpTunnelingIntegrationTest, BasicUsePost) {
  
  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy proxy_config;
    proxy_config.set_stat_prefix("tcp_stats");
    proxy_config.set_cluster("cluster_0");
    proxy_config.mutable_tunneling_config()->set_hostname("host.com:80");
    proxy_config.mutable_tunneling_config()->set_use_post(true);

    auto* listeners = bootstrap.mutable_static_resources()->mutable_listeners();
    for (auto& listener : *listeners) {
      if (listener.name() != "tcp_proxy") {
        continue;
      }
      auto* filter_chain = listener.mutable_filter_chains(0);
      auto* filter = filter_chain->mutable_filters(0);
      filter->mutable_typed_config()->PackFrom(proxy_config);
      break;
    }
  });

  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().get(Http::Headers::get().Method)[0]->value(), "POST");

  
  upstream_request_->encodeHeaders(default_response_headers_, false);

  sendBidiData(fake_upstream_connection_);
  closeConnection(fake_upstream_connection_);
}

TEST_P(TcpTunnelingIntegrationTest, BasicHeaderEvaluationTunnelingConfig) {
  
  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy proxy_config;
    proxy_config.set_stat_prefix("tcp_stats");
    proxy_config.set_cluster("cluster_0");
    proxy_config.mutable_tunneling_config()->set_hostname("host.com:80");
    auto new_header = proxy_config.mutable_tunneling_config()->mutable_headers_to_add()->Add();
    new_header->mutable_header()->set_key("downstream-local-ip");
    new_header->mutable_header()->set_value("%DOWNSTREAM_LOCAL_ADDRESS_WITHOUT_PORT%");

    auto* listeners = bootstrap.mutable_static_resources()->mutable_listeners();
    for (auto& listener : *listeners) {
      if (listener.name() != "tcp_proxy") {
        continue;
      }
      auto* filter_chain = listener.mutable_filter_chains(0);
      auto* filter = filter_chain->mutable_filters(0);
      filter->mutable_typed_config()->PackFrom(proxy_config);
      break;
    }
  });

  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().getMethodValue(), "CONNECT");

  
  
  EXPECT_EQ( upstream_request_->headers().get(Envoy::Http::LowerCaseString("downstream-local-ip")).size(), 1);

  EXPECT_EQ(upstream_request_->headers()
                .get(Envoy::Http::LowerCaseString("downstream-local-ip"))[0] ->value()
                .getStringView(), Network::Test::getLoopbackAddressString(version_));

  
  upstream_request_->encodeHeaders(default_response_headers_, false);
  sendBidiData(fake_upstream_connection_);
  closeConnection(fake_upstream_connection_);
}


TEST_P(TcpTunnelingIntegrationTest, HeaderEvaluatorConfigUpdate) {
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    return;
  }
  envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy proxy_config;
  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    proxy_config.set_stat_prefix("tcp_stats");
    proxy_config.set_cluster("cluster_0");
    proxy_config.mutable_tunneling_config()->set_hostname("host.com:80");
    auto address_header = proxy_config.mutable_tunneling_config()->mutable_headers_to_add()->Add();
    address_header->mutable_header()->set_key("config-version");
    address_header->mutable_header()->set_value("1");

    auto* listeners = bootstrap.mutable_static_resources()->mutable_listeners();
    for (auto& listener : *listeners) {
      if (listener.name() != "tcp_proxy") {
        continue;
      }
      auto* filter_chain = listener.mutable_filter_chains(0);
      auto* filter = filter_chain->mutable_filters(0);
      filter->mutable_typed_config()->PackFrom(proxy_config);
      break;
    }
  });

  initialize();
  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  EXPECT_EQ(upstream_request_->headers().getMethodValue(), "CONNECT");

  EXPECT_EQ(upstream_request_->headers()
                .get(Envoy::Http::LowerCaseString("config-version"))[0] ->value()
                .getStringView(), "1");

  
  upstream_request_->encodeHeaders(default_response_headers_, false);
  ASSERT_TRUE(tcp_client_->write("hello", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

  ConfigHelper new_config_helper( version_, *api_, MessageUtil::getJsonStringFromMessageOrDie(config_helper_.bootstrap()));
  new_config_helper.addConfigModifier( [&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
        auto* header = proxy_config.mutable_tunneling_config()->mutable_headers_to_add()->Mutable(0);
        header->mutable_header()->set_value("2");

        auto* listeners = bootstrap.mutable_static_resources()->mutable_listeners();
        for (auto& listener : *listeners) {
          if (listener.name() != "tcp_proxy") {
            continue;
          }
          
          (*(*listener.mutable_metadata()->mutable_filter_metadata())["random_filter_name"] .mutable_fields())["random_key"] .set_number_value(2);

          auto* filter_chain = listener.mutable_filter_chains(0);
          auto* filter = filter_chain->mutable_filters(0);
          filter->mutable_typed_config()->PackFrom(proxy_config);
          break;
        }
      });
  new_config_helper.setLds("1");

  test_server_->waitForCounterEq("listener_manager.listener_modified", 1);
  test_server_->waitForGaugeEq("listener_manager.total_listeners_draining", 0);

  
  auto tcp_client_2 = makeTcpConnection(lookupPort("tcp_proxy"));

  
  ASSERT_TRUE(fake_upstream_connection_ != nullptr);

  FakeStreamPtr upstream_request_2;
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_2));
  ASSERT_TRUE(upstream_request_2->waitForHeadersComplete());
  
  EXPECT_EQ(upstream_request_2->headers()
                .get(Envoy::Http::LowerCaseString("config-version"))[0] ->value()
                .getStringView(), "2");
  upstream_request_2->encodeHeaders(default_response_headers_, false);

  tcp_client_->close();
  tcp_client_2->close();

  ASSERT_TRUE(upstream_request_2->waitForEndStream(*dispatcher_));
  
  upstream_request_2->encodeData(0, true);
  ASSERT_TRUE(fake_upstream_connection_->waitForNoPost());
}

TEST_P(TcpTunnelingIntegrationTest, Goaway) {
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  
  
  setUpConnection(fake_upstream_connection_);
  sendBidiData(fake_upstream_connection_, true);
  closeConnection(fake_upstream_connection_);
  test_server_->waitForCounterGe("cluster.cluster_0.upstream_cx_destroy", 1);

  
  FakeHttpConnectionPtr fake_upstream_connection;
  setUpConnection(fake_upstream_connection);
  sendBidiData(fake_upstream_connection);
  closeConnection(fake_upstream_connection_);

  
  fake_upstream_connection->encodeGoAway();
  test_server_->waitForCounterGe("cluster.cluster_0.upstream_cx_destroy", 2);
}

TEST_P(TcpTunnelingIntegrationTest, InvalidResponseHeaders) {
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  
  
  default_response_headers_.setStatus(enumToInt(Http::Code::ServiceUnavailable));
  upstream_request_->encodeHeaders(default_response_headers_, false);
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    ASSERT_TRUE(upstream_request_->waitForReset());
  }

  
  
  tcp_client_->waitForHalfClose();
  tcp_client_->close();
}

TEST_P(TcpTunnelingIntegrationTest, CloseUpstreamFirst) {
  initialize();

  setUpConnection(fake_upstream_connection_);
  sendBidiData(fake_upstream_connection_);

  
  
  upstream_request_->encodeData(12, true);
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->close());
  }
  ASSERT_TRUE(tcp_client_->waitForData(12));
  tcp_client_->waitForHalfClose();

  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
    tcp_client_->close();
  } else {
    
    
    ASSERT_TRUE(tcp_client_->write("hello", false));
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

    ASSERT_TRUE(tcp_client_->write("hello", true));
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  }
}

TEST_P(TcpTunnelingIntegrationTest, ResetStreamTest) {
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    return;
  }
  enableHalfClose(false);
  initialize();

  setUpConnection(fake_upstream_connection_);

  
  upstream_request_->encodeResetStream();
  tcp_client_->waitForDisconnect();
}

TEST_P(TcpTunnelingIntegrationTest, TestIdletimeoutWithLargeOutstandingData) {
  enableHalfClose(false);
  config_helper_.setBufferLimits(1024, 1024);
  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    auto* listener = bootstrap.mutable_static_resources()->mutable_listeners(1);
    auto* filter_chain = listener->mutable_filter_chains(0);
    auto* config_blob = filter_chain->mutable_filters(0)->mutable_typed_config();

    ASSERT_TRUE(config_blob->Is<envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy>());
    auto tcp_proxy_config = MessageUtil::anyConvert<envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy>( *config_blob);

    tcp_proxy_config.mutable_idle_timeout()->set_nanos( std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::milliseconds(500))
            .count());
    config_blob->PackFrom(tcp_proxy_config);
  });

  initialize();

  setUpConnection(fake_upstream_connection_);

  std::string data(1024 * 16, 'a');
  ASSERT_TRUE(tcp_client_->write(data));
  upstream_request_->encodeData(data, false);

  tcp_client_->waitForDisconnect();
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
    tcp_client_->close();
  } else {
    ASSERT_TRUE(upstream_request_->waitForReset());
  }
}


TEST_P(TcpTunnelingIntegrationTest, TcpProxyDownstreamFlush) {
  
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size / 4, size / 4);
  initialize();

  setUpConnection(fake_upstream_connection_);

  tcp_client_->readDisable(true);
  std::string data(size, 'a');
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(tcp_client_->write("hello", false));
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

    upstream_request_->encodeData(data, true);
    ASSERT_TRUE(fake_upstream_connection_->close());
  } else {
    ASSERT_TRUE(tcp_client_->write("", true));

    
    
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

    upstream_request_->encodeData(data, true);
  }

  test_server_->waitForCounterGe("cluster.cluster_0.upstream_flow_control_paused_reading_total", 1);
  tcp_client_->readDisable(false);
  tcp_client_->waitForData(data);
  tcp_client_->waitForHalfClose();
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    tcp_client_->close();
  }
}


TEST_P(TcpTunnelingIntegrationTest, TcpProxyUpstreamFlush) {
  if (upstreamProtocol() == Http::CodecType::HTTP3) {
    
    
    
    
    return;
  }
  
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  setUpConnection(fake_upstream_connection_);

  upstream_request_->readDisable(true);
  upstream_request_->encodeData("hello", false);

  
  
  ASSERT_TRUE(tcp_client_->waitForData(5));

  std::string data(size, 'a');
  ASSERT_TRUE(tcp_client_->write(data, true));
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    tcp_client_->close();

    upstream_request_->readDisable(false);
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, size));
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    
    
    
    upstream_request_->readDisable(false);
    ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, size));
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
    upstream_request_->encodeData("world", true);
    tcp_client_->waitForHalfClose();
  }
}


TEST_P(TcpTunnelingIntegrationTest, ConnectionReuse) {
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  setUpConnection(fake_upstream_connection_);

  
  ASSERT_TRUE(tcp_client_->write("hello1", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello1"));

  
  
  upstream_request_->encodeData("world1", true);
  tcp_client_->waitForData("world1");
  tcp_client_->waitForHalfClose();
  tcp_client_->close();
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  
  IntegrationTcpClientPtr tcp_client_2 = makeTcpConnection(lookupPort("tcp_proxy"));

  
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  upstream_request_->encodeHeaders(default_response_headers_, false);

  ASSERT_TRUE(tcp_client_2->write("hello2", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello2"));

  
  
  upstream_request_->encodeData("world2", true);
  tcp_client_2->waitForData("world2");
  tcp_client_2->waitForHalfClose();
  tcp_client_2->close();
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
}


TEST_P(TcpTunnelingIntegrationTest, H1NoConnectionReuse) {
  if (upstreamProtocol() != Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  setUpConnection(fake_upstream_connection_);

  
  ASSERT_TRUE(tcp_client_->write("hello1", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello1"));

  
  
  upstream_request_->encodeData("world1", false);
  tcp_client_->waitForData("world1");
  tcp_client_->close();

  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());

  
  IntegrationTcpClientPtr tcp_client_2 = makeTcpConnection(lookupPort("tcp_proxy"));
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  upstream_request_->encodeHeaders(default_response_headers_, false);

  ASSERT_TRUE(tcp_client_2->write("hello1", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello1"));
  tcp_client_2->close();

  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
}


TEST_P(TcpTunnelingIntegrationTest, H1UpstreamCloseNoConnectionReuse) {
  if (upstreamProtocol() == Http::CodecType::HTTP2) {
    return;
  }
  initialize();

  
  IntegrationTcpClientPtr tcp_client_1 = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  ASSERT_TRUE(tcp_client_1->write("hello1", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello1"));

  
  
  upstream_request_->encodeData("world1", false);
  tcp_client_1->waitForData("world1");
  ASSERT_TRUE(fake_upstream_connection_->close());

  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  tcp_client_1->waitForHalfClose();
  tcp_client_1->close();

  
  IntegrationTcpClientPtr tcp_client_2 = makeTcpConnection(lookupPort("tcp_proxy"));
  
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());
  upstream_request_->encodeHeaders(default_response_headers_, false);

  ASSERT_TRUE(tcp_client_2->write("hello2", false));
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, "hello2"));
  ASSERT_TRUE(fake_upstream_connection_->close());

  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  tcp_client_2->waitForHalfClose();
  tcp_client_2->close();
}

TEST_P(TcpTunnelingIntegrationTest, 2xxStatusCodeValidHttp1) {
  if (upstreamProtocol() != Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  
  
  default_response_headers_.setStatus(enumToInt(Http::Code::Accepted));
  upstream_request_->encodeHeaders(default_response_headers_, false);

  sendBidiData(fake_upstream_connection_);

  
  tcp_client_->close();
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
}

TEST_P(TcpTunnelingIntegrationTest, ContentLengthHeaderIgnoredHttp1) {
  if (upstreamProtocol() != Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  
  
  default_response_headers_.setStatus(enumToInt(Http::Code::IMUsed));
  default_response_headers_.setContentLength(10);
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  upstream_request_->encodeData(12, false);
  ASSERT_TRUE(tcp_client_->waitForData(12));

  
  ASSERT_TRUE(tcp_client_->write("hello", false));
  tcp_client_->close();
  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));
  ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
}

TEST_P(TcpTunnelingIntegrationTest, TransferEncodingHeaderIgnoredHttp1) {
  if (upstreamProtocol() != Http::CodecType::HTTP1) {
    return;
  }
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));
  
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData( FakeRawConnection::waitForInexactMatch("\r\n\r\n"), &data));
  ASSERT_THAT(data, testing::HasSubstr("CONNECT host.com:80 HTTP/1.1"));

  
  ASSERT_TRUE( fake_upstream_connection->write("HTTP/1.1 200 OK\r\nTransfer-encoding: chunked\r\n\r\n"));

  
  ASSERT_TRUE(tcp_client_->write("hello"));
  ASSERT_TRUE( fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("hello")));

  
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client_->close();
}

TEST_P(TcpTunnelingIntegrationTest, DeferTransmitDataUntilSuccessConnectResponseIsReceived) {
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));

  
  ASSERT_TRUE(tcp_client_->write("hello", false));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  
  ASSERT_FALSE(upstream_request_->waitForData(*dispatcher_, 1, std::chrono::milliseconds(100)));

  upstream_request_->encodeHeaders(default_response_headers_, false);

  ASSERT_TRUE(upstream_request_->waitForData(*dispatcher_, 5));

  tcp_client_->close();
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
    
    upstream_request_->encodeData(0, true);
  }
}

TEST_P(TcpTunnelingIntegrationTest, NoDataTransmittedIfConnectFailureResponseIsReceived) {
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));

  
  ASSERT_TRUE(tcp_client_->write("hello", false));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  default_response_headers_.setStatus(enumToInt(Http::Code::ServiceUnavailable));
  upstream_request_->encodeHeaders(default_response_headers_, false);

  
  ASSERT_FALSE(upstream_request_->waitForData(*dispatcher_, 1, std::chrono::milliseconds(100)));

  tcp_client_->close();
  if (upstreamProtocol() == Http::CodecType::HTTP1) {
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
  } else {
    ASSERT_TRUE(upstream_request_->waitForReset());
  }
}

TEST_P(TcpTunnelingIntegrationTest, UpstreamDisconnectBeforeResponseReceived) {
  initialize();

  
  tcp_client_ = makeTcpConnection(lookupPort("tcp_proxy"));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForHeadersComplete());

  ASSERT_TRUE(fake_upstream_connection_->close());
  tcp_client_->waitForHalfClose();
  tcp_client_->close();
}

INSTANTIATE_TEST_SUITE_P(IpAndHttpVersions, TcpTunnelingIntegrationTest, testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams( {Http::CodecType::HTTP1}, {Http::CodecType::HTTP1, Http::CodecType::HTTP2, Http::CodecType::HTTP3})), HttpProtocolIntegrationTest::protocolTestParamsToString);




} 
} 
