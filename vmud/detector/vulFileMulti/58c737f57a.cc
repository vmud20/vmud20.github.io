




















using testing::AssertionResult;

namespace Envoy {
namespace {

const char ClusterName1[] = "cluster_1";
const char ClusterName2[] = "cluster_2";
const int UpstreamIndex1 = 1;
const int UpstreamIndex2 = 2;

class CdsIntegrationTest : public Grpc::DeltaSotwIntegrationParamTest, public HttpIntegrationTest {
public:
  CdsIntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP2, ipVersion(), ConfigHelper::discoveredClustersBootstrap( sotwOrDelta() == Grpc::SotwOrDelta::Sotw || sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw ? "GRPC" : "DELTA_GRPC")), cluster_creator_(&ConfigHelper::buildStaticCluster) {





    if (sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw || sotwOrDelta() == Grpc::SotwOrDelta::UnifiedDelta) {
      config_helper_.addRuntimeOverride("envoy.reloadable_features.unified_mux", "true");
    }
    use_lds_ = false;
    sotw_or_delta_ = sotwOrDelta();
  }

  void TearDown() override {
    if (!test_skipped_) {
      cleanUpXdsConnection();
    }
  }

  
  
  void initialize() override {
    use_lds_ = false;
    test_skipped_ = false;
    
    
    
    
    setUpstreamCount(1);                         
    setUpstreamProtocol(Http::CodecType::HTTP2); 

    
    
    
    
    
    
    
    
    
    defer_listener_finalization_ = true;
    HttpIntegrationTest::initialize();

    
    
    
    addFakeUpstream(upstream_codec_type_);
    addFakeUpstream(upstream_codec_type_);
    cluster1_ = cluster_creator_( ClusterName1, fake_upstreams_[UpstreamIndex1]->localAddress()->ip()->port(), Network::Test::getLoopbackAddressString(ipVersion()), "ROUND_ROBIN");

    cluster2_ = cluster_creator_( ClusterName2, fake_upstreams_[UpstreamIndex2]->localAddress()->ip()->port(), Network::Test::getLoopbackAddressString(ipVersion()), "ROUND_ROBIN");


    
    acceptXdsConnection();

    
    EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "", {}, {}, {}, true));
    sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {cluster1_}, {cluster1_}, {}, "55");

    
    
    
    test_server_->waitForGaugeGe("cluster_manager.active_clusters", 2);

    
    
    test_server_->waitUntilListenersReady();
    registerTestServerPorts({"http");
  }

  
  
  void verifyGrpcServiceMethod() {
    EXPECT_TRUE(xds_stream_->waitForHeadersComplete());
    Envoy::Http::LowerCaseString path_string(":path");
    std::string expected_method( sotwOrDelta() == Grpc::SotwOrDelta::Sotw || sotwOrDelta() == Grpc::SotwOrDelta::UnifiedSotw ? "/envoy.service.cluster.v3.ClusterDiscoveryService/StreamClusters" : "/envoy.service.cluster.v3.ClusterDiscoveryService/DeltaClusters");


    EXPECT_EQ(xds_stream_->headers().get(path_string)[0]->value(), expected_method);
  }

  void acceptXdsConnection() {
    AssertionResult result =  fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, xds_connection_);
    RELEASE_ASSERT(result, result.message());
    result = xds_connection_->waitForNewStream(*dispatcher_, xds_stream_);
    RELEASE_ASSERT(result, result.message());
    xds_stream_->startGrpcStream();
    verifyGrpcServiceMethod();
  }

  envoy::config::cluster::v3::Cluster cluster1_;
  envoy::config::cluster::v3::Cluster cluster2_;
  
  bool test_skipped_{true};
  Http::CodecType upstream_codec_type_{Http::CodecType::HTTP2};
  std::function<envoy::config::cluster::v3::Cluster(const std::string&, int, const std::string&, const std::string&)> cluster_creator_;

};

INSTANTIATE_TEST_SUITE_P(IpVersionsClientTypeDelta, CdsIntegrationTest, DELTA_SOTW_GRPC_CLIENT_INTEGRATION_PARAMS);








TEST_P(CdsIntegrationTest, CdsClusterUpDownUp) {
  
  config_helper_.addConfigModifier(configureProxyStatus());
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");
  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, "42");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  
  BufferingStreamDecoderPtr response = IntegrationUtil::makeSingleRequest( lookupPort("http"), "GET", "/cluster1", "", downstream_protocol_, version_, "foo.com");
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("503", response->headers().getStatusValue());
  EXPECT_EQ(response->headers().getProxyStatusValue(), "envoy; error=destination_unavailable; details=\"cluster_not_found; NC\"");

  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "42", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {cluster1_}, {cluster1_}, {}, "413");

  
  
  test_server_->waitForGaugeGe("cluster_manager.active_clusters", 2);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");

  cleanupUpstreamAndDownstream();
}


TEST_P(CdsIntegrationTest, CdsClusterTeardownWhileConnecting) {
  initialize();
  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);
  test_server_->waitForCounterExists("cluster.cluster_1.upstream_cx_total");
  Stats::CounterSharedPtr cx_counter = test_server_->counter("cluster.cluster_1.upstream_cx_total");
  
  EXPECT_EQ(0, cx_counter->value());

  
  
  fake_upstreams_[1]->dispatcher()->exit();
  fake_upstreams_[2]->dispatcher()->exit();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder = codec_client_->startRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET", {":path", "/cluster1", {":scheme", "http", {":authority", "host");

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, "42");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);
  codec_client_->sendReset(encoder_decoder.first);
  cleanupUpstreamAndDownstream();

  
  EXPECT_LE(cx_counter->value(), 1);
}


TEST_P(CdsIntegrationTest, CdsClusterWithThreadAwareLbCycleUpDownUp) {
  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");
  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, "42");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  
  cluster1_ = ConfigHelper::buildStaticCluster( ClusterName1, fake_upstreams_[UpstreamIndex1]->localAddress()->ip()->port(), Network::Test::getLoopbackAddressString(ipVersion()), "MAGLEV");


  
  for (int i = 42; i < 142; i += 2) {
    EXPECT_TRUE( compareDiscoveryRequest(Config::TypeUrl::get().Cluster, absl::StrCat(i), {}, {}, {}));
    sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>( Config::TypeUrl::get().Cluster, {cluster1_}, {cluster1_}, {}, absl::StrCat(i + 1));
    EXPECT_TRUE( compareDiscoveryRequest(Config::TypeUrl::get().Cluster, absl::StrCat(i + 1), {}, {}, {}));
    sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>( Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, absl::StrCat(i + 2));
  }

  cleanupUpstreamAndDownstream();
}


TEST_P(CdsIntegrationTest, TwoClusters) {
  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");

  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>( Config::TypeUrl::get().Cluster, {cluster1_, cluster2_}, {cluster2_}, {}, "42");
  
  test_server_->waitForGaugeGe("cluster_manager.active_clusters", 3);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex2, "/cluster2");
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "42", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {cluster2_}, {}, {ClusterName1}, "43");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex2, "/cluster2");
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "43", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>( Config::TypeUrl::get().Cluster, {cluster1_, cluster2_}, {cluster1_}, {}, "413");

  
  
  test_server_->waitForGaugeGe("cluster_manager.active_clusters", 3);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");

  cleanupUpstreamAndDownstream();
}



TEST_P(CdsIntegrationTest, VersionsRememberedAfterReconnect) {
  SKIP_IF_XDS_IS(Grpc::SotwOrDelta::Sotw);
  SKIP_IF_XDS_IS(Grpc::SotwOrDelta::UnifiedSotw);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  
  AssertionResult result = xds_connection_->close();
  RELEASE_ASSERT(result, result.message());
  result = xds_connection_->waitForDisconnect();
  RELEASE_ASSERT(result, result.message());
  xds_connection_.reset();
  
  acceptXdsConnection();

  
  envoy::service::discovery::v3::DeltaDiscoveryRequest request;
  result = xds_stream_->waitForGrpcMessage(*dispatcher_, request);
  RELEASE_ASSERT(result, result.message());
  const auto& initial_resource_versions = request.initial_resource_versions();
  EXPECT_EQ("55", initial_resource_versions.at(std::string(ClusterName1)));
  EXPECT_EQ(1, initial_resource_versions.size());

  
  
  sendDeltaDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {cluster2_}, {}, "42");
  
  test_server_->waitForGaugeGe("cluster_manager.active_clusters", 3);

  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex1, "/cluster1");
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());
  
  testRouterHeaderOnlyRequestAndResponse(nullptr, UpstreamIndex2, "/cluster2");
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());
}




TEST_P(CdsIntegrationTest, CdsClusterDownWithLotsOfIdleConnections) {
  constexpr int num_requests = 2000;
  
  upstream_codec_type_ = Http::CodecType::HTTP1;
  
  
  cluster_creator_ = &ConfigHelper::buildH1ClusterWithHighCircuitBreakersLimits;
  config_helper_.addConfigModifier( [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) -> void {

        hcm.mutable_route_config()
            ->mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_route()
            ->mutable_timeout()
            ->set_seconds(600);
        hcm.mutable_route_config()
            ->mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_route()
            ->mutable_idle_timeout()
            ->set_seconds(600);
      });
  initialize();
  std::vector<IntegrationStreamDecoderPtr> responses;
  std::vector<FakeHttpConnectionPtr> upstream_connections;
  std::vector<FakeStreamPtr> upstream_requests;
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  
  for (int i = 0; i < num_requests; ++i) {
    Http::TestRequestHeaderMapImpl request_headers{{":method", "GET", {":path", "/cluster1", {":scheme", "http", {":authority", "host", {"x-lyft-user-id", absl::StrCat(i)}};




    auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
    responses.push_back(std::move(response));

    FakeHttpConnectionPtr fake_upstream_connection;
    waitForNextUpstreamConnection({UpstreamIndex1}, TestUtility::DefaultTimeout, fake_upstream_connection);
    
    FakeStreamPtr upstream_request;
    AssertionResult result = fake_upstream_connection->waitForNewStream(*dispatcher_, upstream_request);
    RELEASE_ASSERT(result, result.message());
    
    result = upstream_request->waitForEndStream(*dispatcher_);
    RELEASE_ASSERT(result, result.message());
    upstream_connections.push_back(std::move(fake_upstream_connection));
    upstream_requests.push_back(std::move(upstream_request));
  }

  
  for (int i = 0; i < num_requests; ++i) {
    
    upstream_requests[i]->encodeHeaders(default_response_headers_, true);
    
    RELEASE_ASSERT(responses[i]->waitForEndStream(), "unexpected timeout");
    ASSERT_TRUE(responses[i]->complete());
    EXPECT_EQ("200", responses[i]->headers().getStatusValue());
  }

  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, "42");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  
  for (int i = 0; i < num_requests; ++i) {
    AssertionResult result = upstream_connections[i]->close();
    RELEASE_ASSERT(result, result.message());
    result = upstream_connections[i]->waitForDisconnect();
    RELEASE_ASSERT(result, result.message());
  }
  upstream_connections.clear();
  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());
}







TEST_P(CdsIntegrationTest, DISABLED_CdsClusterDownWithLotsOfConnectingConnections) {
  
  
  
  constexpr int num_requests = 64;
  
  upstream_codec_type_ = Http::CodecType::HTTP1;
  cluster_creator_ = &ConfigHelper::buildH1ClusterWithHighCircuitBreakersLimits;
  config_helper_.addConfigModifier( [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm) -> void {

        hcm.mutable_route_config()
            ->mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_route()
            ->mutable_timeout()
            ->set_seconds(600);
        hcm.mutable_route_config()
            ->mutable_virtual_hosts(0)
            ->mutable_routes(0)
            ->mutable_route()
            ->mutable_idle_timeout()
            ->set_seconds(600);
      });
  initialize();
  test_server_->waitForCounterGe("cluster_manager.cluster_added", 1);
  std::vector<IntegrationStreamDecoderPtr> responses;
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  
  
  fake_upstreams_[UpstreamIndex1]->dispatcher()->exit();
  for (int i = 0; i < num_requests; ++i) {
    Http::TestRequestHeaderMapImpl request_headers{{":method", "GET", {":path", "/cluster1", {":scheme", "http", {":authority", "host", {"x-lyft-user-id", absl::StrCat(i)}};




    auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
    responses.push_back(std::move(response));
  }

  
  test_server_->waitForCounterEq("cluster.cluster_1.upstream_cx_total", num_requests);

  
  EXPECT_TRUE(compareDiscoveryRequest(Config::TypeUrl::get().Cluster, "55", {}, {}, {}));
  sendDiscoveryResponse<envoy::config::cluster::v3::Cluster>(Config::TypeUrl::get().Cluster, {}, {}, {ClusterName1}, "42");
  
  
  test_server_->waitForCounterGe("cluster_manager.cluster_removed", 1);

  cleanupUpstreamAndDownstream();
  ASSERT_TRUE(codec_client_->waitForDisconnect());
  
  
  
}

} 
} 
