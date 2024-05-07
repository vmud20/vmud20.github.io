






















namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oauth2 {

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

static const std::string TEST_CALLBACK = "/_oauth";
static const std::string TEST_CLIENT_ID = "1";
static const std::string TEST_CLIENT_SECRET_ID = "MyClientSecretKnoxID";
static const std::string TEST_TOKEN_SECRET_ID = "MyTokenSecretKnoxID";
static const std::string TEST_DEFAULT_SCOPE = "user";
static const std::string TEST_ENCODED_AUTH_SCOPES = "user%20openid%20email";

namespace {
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders> authorization_handle(Http::CustomHeaders::get().Authorization);
}

class MockSecretReader : public SecretReader {
public:
  const std::string& clientSecret() const override {
    CONSTRUCT_ON_FIRST_USE(std::string, "asdf_client_secret_fdsa");
  }
  const std::string& tokenSecret() const override {
    CONSTRUCT_ON_FIRST_USE(std::string, "asdf_token_secret_fdsa");
  }
};

class MockOAuth2CookieValidator : public CookieValidator {
public:
  MOCK_METHOD(std::string&, username, (), (const));
  MOCK_METHOD(std::string&, token, (), (const));
  MOCK_METHOD(bool, isValid, (), (const));
  MOCK_METHOD(void, setParams, (const Http::RequestHeaderMap& headers, const std::string& secret));
};

class MockOAuth2Client : public OAuth2Client {
public:
  void onSuccess(const Http::AsyncClient::Request&, Http::ResponseMessagePtr&&) override {}
  void onFailure(const Http::AsyncClient::Request&, Http::AsyncClient::FailureReason) override {}
  void setCallbacks(FilterCallbacks&) override {}
  void onBeforeFinalizeUpstreamSpan(Envoy::Tracing::Span&, const Http::ResponseHeaderMap*) override {}

  MOCK_METHOD(void, asyncGetAccessToken, (const std::string&, const std::string&, const std::string&, const std::string&));
};

class OAuth2Test : public testing::Test {
public:
  OAuth2Test() : request_(&cm_.thread_local_cluster_.async_client_) {
    factory_context_.cluster_manager_.initializeClusters({"auth.example.com", {});
    init();
  }

  void init() { init(getConfig()); }

  void init(FilterConfigSharedPtr config) {
    
    oauth_client_ = new MockOAuth2Client();
    std::unique_ptr<OAuth2Client> oauth_client_ptr{oauth_client_};

    config_ = config;
    filter_ = std::make_shared<OAuth2Filter>(config_, std::move(oauth_client_ptr), test_time_);
    filter_->setDecoderFilterCallbacks(decoder_callbacks_);
    validator_ = std::make_shared<MockOAuth2CookieValidator>();
    filter_->validator_ = validator_;
  }

  
  FilterConfigSharedPtr getConfig() {
    envoy::extensions::filters::http::oauth2::v3::OAuth2Config p;
    auto* endpoint = p.mutable_token_endpoint();
    endpoint->set_cluster("auth.example.com");
    endpoint->set_uri("auth.example.com/_oauth");
    endpoint->mutable_timeout()->set_seconds(1);
    p.set_redirect_uri("%REQ(:scheme)%://%REQ(:authority)%" + TEST_CALLBACK);
    p.mutable_redirect_path_matcher()->mutable_path()->set_exact(TEST_CALLBACK);
    p.set_authorization_endpoint("https://auth.example.com/oauth/authorize/");
    p.mutable_signout_path()->mutable_path()->set_exact("/_signout");
    p.set_forward_bearer_token(true);
    p.add_auth_scopes("user");
    p.add_auth_scopes("openid");
    p.add_auth_scopes("email");
    p.add_resources("oauth2-resource");
    p.add_resources("http://example.com");
    p.add_resources("https://example.com");
    auto* matcher = p.add_pass_through_matcher();
    matcher->set_name(":method");
    matcher->mutable_string_match()->set_exact("OPTIONS");
    auto credentials = p.mutable_credentials();
    credentials->set_client_id(TEST_CLIENT_ID);
    credentials->mutable_token_secret()->set_name("secret");
    credentials->mutable_hmac_secret()->set_name("hmac");
    
    

    MessageUtil::validate(p, ProtobufMessage::getStrictValidationVisitor());

    
    auto secret_reader = std::make_shared<MockSecretReader>();
    FilterConfigSharedPtr c = std::make_shared<FilterConfig>(p, factory_context_.cluster_manager_, secret_reader, scope_, "test.");

    return c;
  }

  Http::AsyncClient::Callbacks* popPendingCallback() {
    if (callbacks_.empty()) {
      
      throw std::underflow_error("empty deque");
    }

    auto callbacks = callbacks_.front();
    callbacks_.pop_front();
    return callbacks;
  }

  
  void expectValidCookies(const CookieNames& cookie_names) {
    
    test_time_.setSystemTime(SystemTime(std::chrono::seconds(0)));

    const auto expires_at_s = DateUtil::nowToSeconds(test_time_.timeSystem()) + 10;

    Http::TestRequestHeaderMapImpl request_headers{
        {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Path.get(), "/anypath", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Cookie.get(), fmt::format("{}={};version=test", cookie_names.oauth_expires_, expires_at_s)}, {Http::Headers::get().Cookie.get(), absl::StrCat(cookie_names.bearer_token_, "=xyztoken;version=test")}, {Http::Headers::get().Cookie.get(), absl::StrCat(cookie_names.oauth_hmac_, "=" "NGQ3MzVjZGExNGM5NTFiZGJjODBkMjBmYjAyYjNiOTFjMmNjYj" "IxMTUzNmNiNWU0NjQzMmMxMWUzZmE2ZWJjYg==" ";version=test")}, };












    auto cookie_validator = std::make_shared<OAuth2CookieValidator>(test_time_, cookie_names);
    EXPECT_EQ(cookie_validator->token(), "");
    cookie_validator->setParams(request_headers, "mock-secret");

    EXPECT_TRUE(cookie_validator->hmacIsValid());
    EXPECT_TRUE(cookie_validator->timestampIsValid());
    EXPECT_TRUE(cookie_validator->isValid());

    
    test_time_.advanceTimeWait(std::chrono::seconds(11));

    EXPECT_FALSE(cookie_validator->timestampIsValid());
    EXPECT_FALSE(cookie_validator->isValid());
  }

  NiceMock<Event::MockTimer>* attachmentTimeout_timer_{};
  NiceMock<Server::Configuration::MockFactoryContext> factory_context_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Upstream::MockClusterManager> cm_;
  std::shared_ptr<MockOAuth2CookieValidator> validator_;
  std::shared_ptr<OAuth2Filter> filter_;
  MockOAuth2Client* oauth_client_;
  FilterConfigSharedPtr config_;
  Http::MockAsyncClientRequest request_;
  std::deque<Http::AsyncClient::Callbacks*> callbacks_;
  Stats::IsolatedStoreImpl scope_;
  Event::SimulatedTimeSystem test_time_;
};


TEST_F(OAuth2Test, SdsDynamicGenericSecret) {
  NiceMock<Server::MockConfigTracker> config_tracker;
  Secret::SecretManagerImpl secret_manager{config_tracker};
  envoy::config::core::v3::ConfigSource config_source;

  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> secret_context;
  NiceMock<LocalInfo::MockLocalInfo> local_info;
  Api::ApiPtr api = Api::createApiForTest();
  Stats::IsolatedStoreImpl stats;
  NiceMock<Init::MockManager> init_manager;
  Init::TargetHandlePtr init_handle;
  NiceMock<Event::MockDispatcher> dispatcher;
  EXPECT_CALL(secret_context, localInfo()).WillRepeatedly(ReturnRef(local_info));
  EXPECT_CALL(secret_context, api()).WillRepeatedly(ReturnRef(*api));
  EXPECT_CALL(secret_context, mainThreadDispatcher()).WillRepeatedly(ReturnRef(dispatcher));
  EXPECT_CALL(secret_context, stats()).WillRepeatedly(ReturnRef(stats));
  EXPECT_CALL(secret_context, initManager()).WillRepeatedly(ReturnRef(init_manager));
  EXPECT_CALL(init_manager, add(_))
      .WillRepeatedly(Invoke([&init_handle](const Init::Target& target) {
        init_handle = target.createHandle("test");
      }));

  auto client_secret_provider = secret_manager.findOrCreateGenericSecretProvider(config_source, "client", secret_context);
  auto client_callback = secret_context.cluster_manager_.subscription_factory_.callbacks_;
  auto token_secret_provider = secret_manager.findOrCreateGenericSecretProvider(config_source, "token", secret_context);
  auto token_callback = secret_context.cluster_manager_.subscription_factory_.callbacks_;

  SDSSecretReader secret_reader(client_secret_provider, token_secret_provider, *api);
  EXPECT_TRUE(secret_reader.clientSecret().empty());
  EXPECT_TRUE(secret_reader.tokenSecret().empty());

  const std::string yaml_client = R"EOF( name: client generic_secret:

  secret:
    inline_string: "client_test" )EOF";

  envoy::extensions::transport_sockets::tls::v3::Secret typed_secret;
  TestUtility::loadFromYaml(yaml_client, typed_secret);
  const auto decoded_resources_client = TestUtility::decodeResources({typed_secret});

  client_callback->onConfigUpdate(decoded_resources_client.refvec_, "");
  EXPECT_EQ(secret_reader.clientSecret(), "client_test");
  EXPECT_EQ(secret_reader.tokenSecret(), "");

  const std::string yaml_token = R"EOF( name: token generic_secret:

  secret:
    inline_string: "token_test" )EOF";
  TestUtility::loadFromYaml(yaml_token, typed_secret);
  const auto decoded_resources_token = TestUtility::decodeResources({typed_secret});

  token_callback->onConfigUpdate(decoded_resources_token.refvec_, "");
  EXPECT_EQ(secret_reader.clientSecret(), "client_test");
  EXPECT_EQ(secret_reader.tokenSecret(), "token_test");

  const std::string yaml_client_recheck = R"EOF( name: client generic_secret:

  secret:
    inline_string: "client_test_recheck" )EOF";
  TestUtility::loadFromYaml(yaml_client_recheck, typed_secret);
  const auto decoded_resources_client_recheck = TestUtility::decodeResources({typed_secret});

  client_callback->onConfigUpdate(decoded_resources_client_recheck.refvec_, "");
  EXPECT_EQ(secret_reader.clientSecret(), "client_test_recheck");
  EXPECT_EQ(secret_reader.tokenSecret(), "token_test");
}

TEST_F(OAuth2Test, InvalidCluster) {
  ON_CALL(factory_context_.cluster_manager_, clusters())
      .WillByDefault(Return(Upstream::ClusterManager::ClusterInfoMaps()));

  EXPECT_THROW_WITH_MESSAGE(init(), EnvoyException, "OAuth2 filter: unknown cluster 'auth.example.com' in config. Please " "specify which cluster to direct OAuth requests to.");

}



TEST_F(OAuth2Test, DefaultAuthScope) {

  
  envoy::extensions::filters::http::oauth2::v3::OAuth2Config p;
  auto* endpoint = p.mutable_token_endpoint();
  endpoint->set_cluster("auth.example.com");
  endpoint->set_uri("auth.example.com/_oauth");
  endpoint->mutable_timeout()->set_seconds(1);
  p.set_redirect_uri("%REQ(:scheme)%://%REQ(:authority)%" + TEST_CALLBACK);
  p.mutable_redirect_path_matcher()->mutable_path()->set_exact(TEST_CALLBACK);
  p.set_authorization_endpoint("https://auth.example.com/oauth/authorize/");
  p.mutable_signout_path()->mutable_path()->set_exact("/_signout");
  p.set_forward_bearer_token(true);
  auto* matcher = p.add_pass_through_matcher();
  matcher->set_name(":method");
  matcher->mutable_string_match()->set_exact("OPTIONS");

  auto credentials = p.mutable_credentials();
  credentials->set_client_id(TEST_CLIENT_ID);
  credentials->mutable_token_secret()->set_name("secret");
  credentials->mutable_hmac_secret()->set_name("hmac");

  MessageUtil::validate(p, ProtobufMessage::getStrictValidationVisitor());

  
  auto secret_reader = std::make_shared<MockSecretReader>();
  FilterConfigSharedPtr test_config_;
  test_config_ = std::make_shared<FilterConfig>(p, factory_context_.cluster_manager_, secret_reader, scope_, "test.");

  
  EXPECT_EQ(test_config_->encodedAuthScopes(), TEST_DEFAULT_SCOPE);

  
  EXPECT_EQ(test_config_->encodedResourceQueryParams(), "");

  
  
  init(test_config_);
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Path.get(), "/not/_oauth", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "http", };




  Http::TestResponseHeaderMapImpl response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().Location.get(), "https://auth.example.com/oauth/" "authorize/?client_id=" + TEST_CLIENT_ID + "&scope=" + TEST_DEFAULT_SCOPE + "&response_type=code&" "redirect_uri=http%3A%2F%2Ftraffic.example.com%2F" "_oauth&state=http%3A%2F%2Ftraffic.example.com%2Fnot%2F_oauth", };








  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&response_headers), true));

  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, RequestSignout) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Path.get(), "/_signout", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", };




  Http::TestResponseHeaderMapImpl response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().SetCookie.get(), "OauthHMAC=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", {Http::Headers::get().SetCookie.get(), "BearerToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", {Http::Headers::get().SetCookie.get(), "IdToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", {Http::Headers::get().SetCookie.get(), "RefreshToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT", {Http::Headers::get().Location.get(), "https://traffic.example.com/", };









  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&response_headers), true));

  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, OAuthOkPass) {
  Http::TestRequestHeaderMapImpl mock_request_headers{
      {Http::Headers::get().Path.get(), "/anypath", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", {Http::CustomHeaders::get().Authorization.get(), "Bearer injected_malice!", };





  Http::TestRequestHeaderMapImpl expected_headers{
      {Http::Headers::get().Path.get(), "/anypath", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", {Http::CustomHeaders::get().Authorization.get(), "Bearer legit_token", };





  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(true));

  
  std::string legit_token{"legit_token";
  EXPECT_CALL(*validator_, token()).WillRepeatedly(ReturnRef(legit_token));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(mock_request_headers, false));

  
  EXPECT_EQ(mock_request_headers, expected_headers);

  EXPECT_EQ(scope_.counterFromString("test.oauth_failure").value(), 0);
  EXPECT_EQ(scope_.counterFromString("test.oauth_success").value(), 1);
}


TEST_F(OAuth2Test, OAuthErrorNonOAuthHttpCallback) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Path.get(), "/not/_oauth", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "http", };




  Http::TestResponseHeaderMapImpl response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().Location.get(), "https://auth.example.com/oauth/" "authorize/?client_id=" + TEST_CLIENT_ID + "&scope=" + TEST_ENCODED_AUTH_SCOPES + "&response_type=code&" "redirect_uri=http%3A%2F%2Ftraffic.example.com%2F" "_oauth&state=http%3A%2F%2Ftraffic.example.com%2Fnot%2F_oauth" "&resource=oauth2-resource&resource=http%3A%2F%2Fexample.com" "&resource=https%3A%2F%2Fexample.com", };










  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&response_headers), true));

  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, OAuthErrorQueryString) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Path.get(), "/_oauth?error=someerrorcode", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, };



  Http::TestResponseHeaderMapImpl response_headers{
      {Http::Headers::get().Status.get(), "401", {Http::Headers::get().ContentLength.get(), "18", {Http::Headers::get().ContentType.get(), "text/plain", };



  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&response_headers), false));
  EXPECT_CALL(decoder_callbacks_, encodeData(_, true));

  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));

  EXPECT_EQ(scope_.counterFromString("test.oauth_failure").value(), 1);
  EXPECT_EQ(scope_.counterFromString("test.oauth_success").value(), 0);
}


TEST_F(OAuth2Test, OAuthCallbackStartsAuthentication) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Path.get(), "/_oauth?code=123&state=https://asdf&method=GET", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Scheme.get(), "https", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, };




  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_CALL(*oauth_client_, asyncGetAccessToken("123", TEST_CLIENT_ID, "asdf_client_secret_fdsa", "https://traffic.example.com" + TEST_CALLBACK));

  EXPECT_EQ(Http::FilterHeadersStatus::StopAllIterationAndBuffer, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, OAuthOptionsRequestAndContinue) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Path.get(), "/anypath", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Options}, };



  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, CookieValidator) {
  expectValidCookies(CookieNames{"BearerToken", "OauthHMAC", "OauthExpires");
}


TEST_F(OAuth2Test, CookieValidatorWithCustomNames) {
  expectValidCookies(CookieNames{"CustomBearerToken", "CustomOauthHMAC", "CustomOauthExpires");
}


TEST_F(OAuth2Test, CookieValidatorInvalidExpiresAt) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Path.get(), "/anypath", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Cookie.get(), "OauthExpires=notanumber;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=xyztoken;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "M2NjZmIxYWE0NzQzOGZlZTJjMjQwMzBiZTU5OTdkN2Y0NDRhZjE5MjZiOWNhY2YzNjM0MWRmMTNkMDVmZWFlOQ==" ";version=test", };









  auto cookie_validator = std::make_shared<OAuth2CookieValidator>( test_time_, CookieNames{"BearerToken", "OauthHMAC", "OauthExpires");
  cookie_validator->setParams(request_headers, "mock-secret");

  EXPECT_TRUE(cookie_validator->hmacIsValid());
  EXPECT_FALSE(cookie_validator->timestampIsValid());
  EXPECT_FALSE(cookie_validator->isValid());
}


TEST_F(OAuth2Test, OAuthTestInvalidUrlInStateQueryParam) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Path.get(), "/_oauth?code=abcdefxyz123&scope=" + TEST_ENCODED_AUTH_SCOPES + "&state=blah", {Http::Headers::get().Cookie.get(), "OauthExpires=123;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=legit_token;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "ZTRlMzU5N2Q4ZDIwZWE5ZTU5NTg3YTU3YTcxZTU0NDFkMzY1ZTc1NjMyODYyMj" "RlNjMxZTJmNTZkYzRmZTM0ZQ====;version=test", };










  Http::TestRequestHeaderMapImpl expected_headers{
      {Http::Headers::get().Status.get(), "401", {Http::Headers::get().ContentLength.get(), "18", {Http::Headers::get().ContentType.get(), "text/plain",  };




  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(true));

  std::string legit_token{"legit_token";
  EXPECT_CALL(*validator_, token()).WillRepeatedly(ReturnRef(legit_token));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&expected_headers), false));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));
}


TEST_F(OAuth2Test, OAuthTestCallbackUrlInStateQueryParam) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Path.get(), "/_oauth?code=abcdefxyz123&scope=" + TEST_ENCODED_AUTH_SCOPES + "&state=https%3A%2F%2Ftraffic.example.com%2F_oauth",  {Http::Headers::get().Cookie.get(), "OauthExpires=123;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=legit_token;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "ZTRlMzU5N2Q4ZDIwZWE5ZTU5NTg3YTU3YTcxZTU0NDFkMzY1ZTc1NjMyODYyMj" "RlNjMxZTJmNTZkYzRmZTM0ZQ====;version=test", };












  Http::TestRequestHeaderMapImpl expected_response_headers{
      {Http::Headers::get().Status.get(), "401", {Http::Headers::get().ContentLength.get(), "18", {Http::Headers::get().ContentType.get(), "text/plain", };



  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(true));

  std::string legit_token{"legit_token";
  EXPECT_CALL(*validator_, token()).WillRepeatedly(ReturnRef(legit_token));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&expected_response_headers), false));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(request_headers, false));

  Http::TestRequestHeaderMapImpl final_request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Path.get(), "/_oauth?code=abcdefxyz123&scope=" + TEST_ENCODED_AUTH_SCOPES + "&state=https%3A%2F%2Ftraffic.example.com%2F_oauth", {Http::Headers::get().Cookie.get(), "OauthExpires=123;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=legit_token;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "ZTRlMzU5N2Q4ZDIwZWE5ZTU5NTg3YTU3YTcxZTU0NDFkMzY1ZTc1NjMyODYyMj" "RlNjMxZTJmNTZkYzRmZTM0ZQ====;version=test", {Http::CustomHeaders::get().Authorization.get(), "Bearer legit_token", };












  EXPECT_EQ(request_headers, final_request_headers);
}


TEST_F(OAuth2Test, OAuthTestUpdatePathAfterSuccess) {
  Http::TestRequestHeaderMapImpl request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Path.get(), "/_oauth?code=abcdefxyz123&scope=" + TEST_ENCODED_AUTH_SCOPES + "&state=https%3A%2F%2Ftraffic.example.com%2Foriginal_path", {Http::Headers::get().Cookie.get(), "OauthExpires=123;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=legit_token;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "ZTRlMzU5N2Q4ZDIwZWE5ZTU5NTg3YTU3YTcxZTU0NDFkMzY1ZTc1NjMyODYyMj" "RlNjMxZTJmNTZkYzRmZTM0ZQ====;version=test", };











  Http::TestRequestHeaderMapImpl expected_response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().Location.get(), "https://traffic.example.com/original_path", };


  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(true));

  std::string legit_token{"legit_token";
  EXPECT_CALL(*validator_, token()).WillRepeatedly(ReturnRef(legit_token));

  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&expected_response_headers), true));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers, false));

  Http::TestRequestHeaderMapImpl final_request_headers{
      {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Path.get(), "/_oauth?code=abcdefxyz123&scope=" + TEST_ENCODED_AUTH_SCOPES + "&state=https%3A%2F%2Ftraffic.example.com%2Foriginal_path", {Http::Headers::get().Cookie.get(), "OauthExpires=123;version=test", {Http::Headers::get().Cookie.get(), "BearerToken=legit_token;version=test", {Http::Headers::get().Cookie.get(), "OauthHMAC=" "ZTRlMzU5N2Q4ZDIwZWE5ZTU5NTg3YTU3YTcxZTU0NDFkMzY1ZTc1NjMyODYyMj" "RlNjMxZTJmNTZkYzRmZTM0ZQ====;version=test", {Http::CustomHeaders::get().Authorization.get(), "Bearer legit_token", };












  EXPECT_EQ(request_headers, final_request_headers);
}


TEST_F(OAuth2Test, OAuthTestFullFlowPostWithParameters) {
  
  Http::TestRequestHeaderMapImpl first_request_headers{
      {Http::Headers::get().Path.get(), "/test?name=admin&level=trace", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Post}, {Http::Headers::get().Scheme.get(), "https", };




  
  Http::TestResponseHeaderMapImpl first_response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().Location.get(), "https://auth.example.com/oauth/" "authorize/?client_id=" + TEST_CLIENT_ID + "&scope=" + TEST_ENCODED_AUTH_SCOPES + "&response_type=code&" "redirect_uri=https%3A%2F%2Ftraffic.example.com%2F" "_oauth&state=https%3A%2F%2Ftraffic.example.com%2Ftest%" "3Fname%3Dadmin%26level%3Dtrace" "&resource=oauth2-resource&resource=http%3A%2F%2Fexample.com" "&resource=https%3A%2F%2Fexample.com", };











  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  
  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&first_response_headers), true));

  
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(first_request_headers, false));

  
  Http::TestRequestHeaderMapImpl second_request_headers{
      {Http::Headers::get().Path.get(), "/_oauth?code=123&state=https%3A%2F%2Ftraffic.example.com%" "2Ftest%3Fname%3Dadmin%26level%3Dtrace", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", };





  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_CALL(*oauth_client_, asyncGetAccessToken("123", TEST_CLIENT_ID, "asdf_client_secret_fdsa", "https://traffic.example.com" + TEST_CALLBACK));

  
  EXPECT_EQ(Http::FilterHeadersStatus::StopAllIterationAndBuffer, filter_->decodeHeaders(second_request_headers, false));

  EXPECT_EQ(1, config_->stats().oauth_unauthorized_rq_.value());
  EXPECT_EQ(config_->clusterName(), "auth.example.com");

  
  
  Http::TestRequestHeaderMapImpl second_response_headers{
      {Http::Headers::get().Status.get(), "302", {Http::Headers::get().SetCookie.get(), "OauthHMAC=" "NWUzNzE5MWQwYTg0ZjA2NjIyMjVjMzk3MzY3MzMyZmE0NjZmMWI2MjI1NWFhNDhkYjQ4NDFlZmRiMTVmMTk0MQ==;" "version=1;path=/;Max-Age=;secure;HttpOnly", {Http::Headers::get().SetCookie.get(), "OauthExpires=;version=1;path=/;Max-Age=;secure;HttpOnly", {Http::Headers::get().SetCookie.get(), "BearerToken=;version=1;path=/;Max-Age=;secure", {Http::Headers::get().Location.get(), "https://traffic.example.com/test?name=admin&level=trace", };










  EXPECT_CALL(decoder_callbacks_, encodeHeaders_(HeaderMapEqualRef(&second_response_headers), true));
  EXPECT_CALL(decoder_callbacks_, continueDecoding());

  filter_->finishFlow();
}

TEST_F(OAuth2Test, OAuthBearerTokenFlowFromHeader) {
  Http::TestRequestHeaderMapImpl request_headers_before{
      {Http::Headers::get().Path.get(), "/test?role=bearer", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", {Http::CustomHeaders::get().Authorization.get(), "Bearer xyz-header-token", };




  
  Http::TestRequestHeaderMapImpl request_headers_after{
      {Http::Headers::get().Path.get(), "/test?role=bearer", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", {Http::CustomHeaders::get().Authorization.get(), "Bearer xyz-header-token", };





  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers_before, false));

  
  EXPECT_EQ(request_headers_before, request_headers_after);
}

TEST_F(OAuth2Test, OAuthBearerTokenFlowFromQueryParameters) {
  Http::TestRequestHeaderMapImpl request_headers_before{
      {Http::Headers::get().Path.get(), "/test?role=bearer&token=xyz-queryparam-token", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", };



  Http::TestRequestHeaderMapImpl request_headers_after{
      {Http::Headers::get().Path.get(), "/test?role=bearer&token=xyz-queryparam-token", {Http::Headers::get().Host.get(), "traffic.example.com", {Http::Headers::get().Method.get(), Http::Headers::get().MethodValues.Get}, {Http::Headers::get().Scheme.get(), "https", {Http::CustomHeaders::get().Authorization.get(), "Bearer xyz-queryparam-token", };





  
  EXPECT_CALL(*validator_, setParams(_, _));
  EXPECT_CALL(*validator_, isValid()).WillOnce(Return(false));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(request_headers_before, false));

  
  EXPECT_EQ(request_headers_before, request_headers_after);
}

} 
} 
} 
} 
