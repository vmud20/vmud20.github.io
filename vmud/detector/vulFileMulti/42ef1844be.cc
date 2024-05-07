































namespace Envoy {
namespace TcpProxy {

const std::string& PerConnectionCluster::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.tcp_proxy.cluster");
}

Config::SimpleRouteImpl::SimpleRouteImpl(const Config& parent, absl::string_view cluster_name)
    : parent_(parent), cluster_name_(cluster_name) {}

Config::WeightedClusterEntry::WeightedClusterEntry( const Config& parent, const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::
                              WeightedCluster::ClusterWeight& config)
    : parent_(parent), cluster_name_(config.name()), cluster_weight_(config.weight()) {
  if (config.has_metadata_match()) {
    const auto filter_it = config.metadata_match().filter_metadata().find( Envoy::Config::MetadataFilters::get().ENVOY_LB);
    if (filter_it != config.metadata_match().filter_metadata().end()) {
      if (parent.cluster_metadata_match_criteria_) {
        metadata_match_criteria_ = parent.cluster_metadata_match_criteria_->mergeMatchCriteria(filter_it->second);
      } else {
        metadata_match_criteria_ = std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
      }
    }
  }
}

Config::SharedConfig::SharedConfig( const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config, Server::Configuration::FactoryContext& context)

    : stats_scope_(context.scope().createScope(fmt::format("tcp.{}", config.stat_prefix()))), stats_(generateStats(*stats_scope_)) {
  if (config.has_idle_timeout()) {
    const uint64_t timeout = DurationUtil::durationToMilliseconds(config.idle_timeout());
    if (timeout > 0) {
      idle_timeout_ = std::chrono::milliseconds(timeout);
    }
  } else {
    idle_timeout_ = std::chrono::hours(1);
  }
  if (config.has_tunneling_config()) {
    tunneling_config_helper_ = std::make_unique<TunnelingConfigHelperImpl>(config.tunneling_config());
  }
  if (config.has_max_downstream_connection_duration()) {
    const uint64_t connection_duration = DurationUtil::durationToMilliseconds(config.max_downstream_connection_duration());
    max_downstream_connection_duration_ = std::chrono::milliseconds(connection_duration);
  }
}

Config::Config(const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy& config, Server::Configuration::FactoryContext& context)
    : max_connect_attempts_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, max_connect_attempts, 1)), upstream_drain_manager_slot_(context.threadLocal().allocateSlot()), shared_config_(std::make_shared<SharedConfig>(config, context)), random_generator_(context.api().randomGenerator()) {


  upstream_drain_manager_slot_->set([](Event::Dispatcher&) {
    ThreadLocal::ThreadLocalObjectSharedPtr drain_manager = std::make_shared<UpstreamDrainManager>();
    return drain_manager;
  });

  if (!config.cluster().empty()) {
    default_route_ = std::make_shared<const SimpleRouteImpl>(*this, config.cluster());
  }

  if (config.has_metadata_match()) {
    const auto& filter_metadata = config.metadata_match().filter_metadata();

    const auto filter_it = filter_metadata.find(Envoy::Config::MetadataFilters::get().ENVOY_LB);

    if (filter_it != filter_metadata.end()) {
      cluster_metadata_match_criteria_ = std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
    }
  }

  
  if (default_route_ == nullptr && config.has_weighted_clusters()) {
    total_cluster_weight_ = 0;
    for (const envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy::WeightedCluster::
             ClusterWeight& cluster_desc : config.weighted_clusters().clusters()) {
      WeightedClusterEntryConstSharedPtr cluster_entry( std::make_shared<const WeightedClusterEntry>(*this, cluster_desc));
      weighted_clusters_.emplace_back(std::move(cluster_entry));
      total_cluster_weight_ += weighted_clusters_.back()->clusterWeight();
    }
  }

  for (const envoy::config::accesslog::v3::AccessLog& log_config : config.access_log()) {
    access_logs_.emplace_back(AccessLog::AccessLogFactory::fromProto(log_config, context));
  }

  if (!config.hash_policy().empty()) {
    hash_policy_ = std::make_unique<Network::HashPolicyImpl>(config.hash_policy());
  }
}

RouteConstSharedPtr Config::getRegularRouteFromEntries(Network::Connection& connection) {
  
  if (const auto* per_connection_cluster = connection.streamInfo().filterState()->getDataReadOnly<PerConnectionCluster>( PerConnectionCluster::key());

      per_connection_cluster != nullptr) {
    return std::make_shared<const SimpleRouteImpl>(*this, per_connection_cluster->value());
  }

  if (default_route_ != nullptr) {
    return default_route_;
  }

  
  return nullptr;
}

RouteConstSharedPtr Config::getRouteFromEntries(Network::Connection& connection) {
  if (weighted_clusters_.empty()) {
    return getRegularRouteFromEntries(connection);
  }
  return WeightedClusterUtil::pickCluster(weighted_clusters_, total_cluster_weight_, random_generator_.random(), false);
}

UpstreamDrainManager& Config::drainManager() {
  return upstream_drain_manager_slot_->getTyped<UpstreamDrainManager>();
}

Filter::Filter(ConfigSharedPtr config, Upstream::ClusterManager& cluster_manager)
    : config_(config), cluster_manager_(cluster_manager), downstream_callbacks_(*this), upstream_callbacks_(new UpstreamCallbacks(this)) {
  ASSERT(config != nullptr);
}

Filter::~Filter() {
  for (const auto& access_log : config_->accessLogs()) {
    access_log->log(nullptr, nullptr, nullptr, getStreamInfo());
  }

  ASSERT(generic_conn_pool_ == nullptr);
  ASSERT(upstream_ == nullptr);
}

TcpProxyStats Config::SharedConfig::generateStats(Stats::Scope& scope) {
  return {ALL_TCP_PROXY_STATS(POOL_COUNTER(scope), POOL_GAUGE(scope))};
}

void Filter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  initialize(callbacks, true);
}

void Filter::initialize(Network::ReadFilterCallbacks& callbacks, bool set_connection_stats) {
  read_callbacks_ = &callbacks;
  ENVOY_CONN_LOG(debug, "new tcp proxy session", read_callbacks_->connection());

  read_callbacks_->connection().addConnectionCallbacks(downstream_callbacks_);
  read_callbacks_->connection().enableHalfClose(true);

  
  
  
  read_callbacks_->connection().readDisable(true);
  getStreamInfo().setUpstreamInfo(std::make_shared<StreamInfo::UpstreamInfoImpl>());
  config_->stats().downstream_cx_total_.inc();
  if (set_connection_stats) {
    read_callbacks_->connection().setConnectionStats( {config_->stats().downstream_cx_rx_bytes_total_, config_->stats().downstream_cx_rx_bytes_buffered_, config_->stats().downstream_cx_tx_bytes_total_, config_->stats().downstream_cx_tx_bytes_buffered_, nullptr, nullptr});



  }
}

void Filter::readDisableUpstream(bool disable) {
  bool success = false;
  if (upstream_) {
    success = upstream_->readDisable(disable);
  }
  if (!success) {
    return;
  }
  if (disable) {
    read_callbacks_->upstreamHost()
        ->cluster()
        .stats()
        .upstream_flow_control_paused_reading_total_.inc();
  } else {
    read_callbacks_->upstreamHost()
        ->cluster()
        .stats()
        .upstream_flow_control_resumed_reading_total_.inc();
  }
}

void Filter::readDisableDownstream(bool disable) {
  if (read_callbacks_->connection().state() != Network::Connection::State::Open) {
    
    
    
    return;
  }
  read_callbacks_->connection().readDisable(disable);

  if (disable) {
    config_->stats().downstream_flow_control_paused_reading_total_.inc();
  } else {
    config_->stats().downstream_flow_control_resumed_reading_total_.inc();
  }
}

StreamInfo::StreamInfo& Filter::getStreamInfo() {
  return read_callbacks_->connection().streamInfo();
}

void Filter::DownstreamCallbacks::onAboveWriteBufferHighWatermark() {
  ASSERT(!on_high_watermark_called_);
  on_high_watermark_called_ = true;
  
  parent_.readDisableUpstream(true);
}

void Filter::DownstreamCallbacks::onBelowWriteBufferLowWatermark() {
  ASSERT(on_high_watermark_called_);
  on_high_watermark_called_ = false;
  
  parent_.readDisableUpstream(false);
}

void Filter::UpstreamCallbacks::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::Connected) {
    return;
  }
  if (drainer_ == nullptr) {
    parent_->onUpstreamEvent(event);
  } else {
    drainer_->onEvent(event);
  }
}

void Filter::UpstreamCallbacks::onAboveWriteBufferHighWatermark() {
  ASSERT(!on_high_watermark_called_);
  on_high_watermark_called_ = true;

  if (parent_ != nullptr) {
    
    parent_->readDisableDownstream(true);
  }
}

void Filter::UpstreamCallbacks::onBelowWriteBufferLowWatermark() {
  ASSERT(on_high_watermark_called_);
  on_high_watermark_called_ = false;

  if (parent_ != nullptr) {
    
    parent_->readDisableDownstream(false);
  }
}

void Filter::UpstreamCallbacks::onUpstreamData(Buffer::Instance& data, bool end_stream) {
  if (parent_) {
    parent_->onUpstreamData(data, end_stream);
  } else {
    drainer_->onData(data, end_stream);
  }
}

void Filter::UpstreamCallbacks::onBytesSent() {
  if (drainer_ == nullptr) {
    parent_->resetIdleTimer();
  } else {
    drainer_->onBytesSent();
  }
}

void Filter::UpstreamCallbacks::onIdleTimeout() {
  if (drainer_ == nullptr) {
    parent_->onIdleTimeout();
  } else {
    drainer_->onIdleTimeout();
  }
}

void Filter::UpstreamCallbacks::drain(Drainer& drainer) {
  ASSERT(drainer_ == nullptr); 
  drainer_ = &drainer;
  parent_ = nullptr;
}

Network::FilterStatus Filter::initializeUpstreamConnection() {
  ASSERT(upstream_ == nullptr);

  route_ = pickRoute();

  const std::string& cluster_name = route_ ? route_->clusterName() : EMPTY_STRING;

  Upstream::ThreadLocalCluster* thread_local_cluster = cluster_manager_.getThreadLocalCluster(cluster_name);

  if (thread_local_cluster) {
    ENVOY_CONN_LOG(debug, "Creating connection to cluster {}", read_callbacks_->connection(), cluster_name);
  } else {
    ENVOY_CONN_LOG(debug, "Cluster not found {}", read_callbacks_->connection(), cluster_name);
    config_->stats().downstream_cx_no_route_.inc();
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::NoClusterFound);
    onInitFailure(UpstreamFailureReason::NoRoute);
    return Network::FilterStatus::StopIteration;
  }

  Upstream::ClusterInfoConstSharedPtr cluster = thread_local_cluster->info();
  getStreamInfo().setUpstreamClusterInfo(cluster);

  
  
  if (!cluster->resourceManager(Upstream::ResourcePriority::Default).connections().canCreate()) {
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamOverflow);
    cluster->stats().upstream_cx_overflow_.inc();
    onInitFailure(UpstreamFailureReason::ResourceLimitExceeded);
    return Network::FilterStatus::StopIteration;
  }

  const uint32_t max_connect_attempts = config_->maxConnectAttempts();
  if (connect_attempts_ >= max_connect_attempts) {
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamRetryLimitExceeded);
    cluster->stats().upstream_cx_connect_attempts_exceeded_.inc();
    onInitFailure(UpstreamFailureReason::ConnectFailed);
    return Network::FilterStatus::StopIteration;
  }

  if (auto downstream_connection = downstreamConnection(); downstream_connection != nullptr) {
    if (!read_callbacks_->connection()
             .streamInfo()
             .filterState()
             ->hasData<Network::ProxyProtocolFilterState>( Network::ProxyProtocolFilterState::key())) {
      read_callbacks_->connection().streamInfo().filterState()->setData( Network::ProxyProtocolFilterState::key(), std::make_shared<Network::ProxyProtocolFilterState>(Network::ProxyProtocolData{

              downstream_connection->connectionInfoProvider().remoteAddress(), downstream_connection->connectionInfoProvider().localAddress()}), StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);


    }
    transport_socket_options_ = Network::TransportSocketOptionsUtility::fromFilterState( downstream_connection->streamInfo().filterState());

    if (auto typed_state = downstream_connection->streamInfo()
                               .filterState()
                               .getDataReadOnly<Network::UpstreamSocketOptionsFilterState>( Network::UpstreamSocketOptionsFilterState::key());
        typed_state != nullptr) {
      auto downstream_options = typed_state->value();
      if (!upstream_options_) {
        upstream_options_ = std::make_shared<Network::Socket::Options>();
      }
      Network::Socket::appendOptions(upstream_options_, downstream_options);
    }
  }

  if (!maybeTunnel(*thread_local_cluster)) {
    
    
    getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::NoHealthyUpstream);
    onInitFailure(UpstreamFailureReason::NoHealthyUpstream);
  }
  return Network::FilterStatus::StopIteration;
}

bool Filter::maybeTunnel(Upstream::ThreadLocalCluster& cluster) {
  GenericConnPoolFactory* factory = nullptr;
  if (cluster.info()->upstreamConfig().has_value()) {
    factory = Envoy::Config::Utility::getFactory<GenericConnPoolFactory>( cluster.info()->upstreamConfig().value());
  } else {
    factory = Envoy::Config::Utility::getFactoryByName<GenericConnPoolFactory>( "envoy.filters.connection_pools.tcp.generic");
  }
  if (!factory) {
    return false;
  }

  generic_conn_pool_ = factory->createGenericConnPool(cluster, config_->tunnelingConfigHelper(), this, *upstream_callbacks_);
  if (generic_conn_pool_) {
    connecting_ = true;
    connect_attempts_++;
    getStreamInfo().setAttemptCount(connect_attempts_);
    generic_conn_pool_->newStream(*this);
    
    
    return true;
  }
  return false;
}

void Filter::onGenericPoolFailure(ConnectionPool::PoolFailureReason reason, Upstream::HostDescriptionConstSharedPtr host) {
  generic_conn_pool_.reset();
  read_callbacks_->upstreamHost(host);
  getStreamInfo().upstreamInfo()->setUpstreamHost(host);

  switch (reason) {
  case ConnectionPool::PoolFailureReason::Overflow:
  case ConnectionPool::PoolFailureReason::LocalConnectionFailure:
    upstream_callbacks_->onEvent(Network::ConnectionEvent::LocalClose);
    break;
  case ConnectionPool::PoolFailureReason::RemoteConnectionFailure:
    upstream_callbacks_->onEvent(Network::ConnectionEvent::RemoteClose);
    break;
  case ConnectionPool::PoolFailureReason::Timeout:
    onConnectTimeout();
    break;
  }
}

void Filter::onGenericPoolReady(StreamInfo::StreamInfo* info, std::unique_ptr<GenericUpstream>&& upstream, Upstream::HostDescriptionConstSharedPtr& host, const Network::Address::InstanceConstSharedPtr& local_address, Ssl::ConnectionInfoConstSharedPtr ssl_info) {



  upstream_ = std::move(upstream);
  generic_conn_pool_.reset();
  read_callbacks_->upstreamHost(host);
  StreamInfo::UpstreamInfo& upstream_info = *getStreamInfo().upstreamInfo();
  upstream_info.setUpstreamHost(host);
  upstream_info.setUpstreamLocalAddress(local_address);
  upstream_info.setUpstreamSslConnection(ssl_info);
  onUpstreamConnection();
  read_callbacks_->continueReading();
  if (info) {
    upstream_info.setUpstreamFilterState(info->filterState());
  }
}

const Router::MetadataMatchCriteria* Filter::metadataMatchCriteria() {
  const Router::MetadataMatchCriteria* route_criteria = (route_ != nullptr) ? route_->metadataMatchCriteria() : nullptr;

  const auto& request_metadata = getStreamInfo().dynamicMetadata().filter_metadata();
  const auto filter_it = request_metadata.find(Envoy::Config::MetadataFilters::get().ENVOY_LB);

  if (filter_it != request_metadata.end() && route_criteria != nullptr) {
    metadata_match_criteria_ = route_criteria->mergeMatchCriteria(filter_it->second);
    return metadata_match_criteria_.get();
  } else if (filter_it != request_metadata.end()) {
    metadata_match_criteria_ = std::make_unique<Router::MetadataMatchCriteriaImpl>(filter_it->second);
    return metadata_match_criteria_.get();
  } else {
    return route_criteria;
  }
}

void Filter::onConnectTimeout() {
  ENVOY_CONN_LOG(debug, "connect timeout", read_callbacks_->connection());
  read_callbacks_->upstreamHost()->outlierDetector().putResult( Upstream::Outlier::Result::LocalOriginTimeout);
  getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);

  
  upstream_callbacks_->onEvent(Network::ConnectionEvent::LocalClose);
}

Network::FilterStatus Filter::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "downstream connection received {} bytes, end_stream={}", read_callbacks_->connection(), data.length(), end_stream);
  if (upstream_) {
    upstream_->encodeData(data, end_stream);
  }
  
  
  
  ASSERT(0 == data.length());
  resetIdleTimer(); 
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Filter::onNewConnection() {
  if (config_->maxDownstreamConnectionDuration()) {
    connection_duration_timer_ = read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onMaxDownstreamConnectionDuration(); });
    connection_duration_timer_->enableTimer(config_->maxDownstreamConnectionDuration().value());
  }
  return initializeUpstreamConnection();
}

void Filter::onDownstreamEvent(Network::ConnectionEvent event) {
  ENVOY_CONN_LOG(trace, "on downstream event {}, has upstream = {}", read_callbacks_->connection(), static_cast<int>(event), upstream_ == nullptr);
  if (upstream_) {
    Tcp::ConnectionPool::ConnectionDataPtr conn_data(upstream_->onDownstreamEvent(event));
    if (conn_data != nullptr && conn_data->connection().state() != Network::Connection::State::Closed) {
      config_->drainManager().add(config_->sharedConfig(), std::move(conn_data), std::move(upstream_callbacks_), std::move(idle_timer_), read_callbacks_->upstreamHost());

    }
    if (event != Network::ConnectionEvent::Connected) {
      upstream_.reset();
      disableIdleTimer();
    }
  }
  if (generic_conn_pool_) {
    if (event == Network::ConnectionEvent::LocalClose || event == Network::ConnectionEvent::RemoteClose) {
      
      generic_conn_pool_.reset();
    }
  }
}

void Filter::onUpstreamData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "upstream connection received {} bytes, end_stream={}", read_callbacks_->connection(), data.length(), end_stream);
  read_callbacks_->connection().write(data, end_stream);
  ASSERT(0 == data.length());
  resetIdleTimer(); 
}

void Filter::onUpstreamEvent(Network::ConnectionEvent event) {
  
  
  bool connecting = connecting_;
  connecting_ = false;

  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    upstream_.reset();
    disableIdleTimer();

    if (connecting) {
      if (event == Network::ConnectionEvent::RemoteClose) {
        getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::UpstreamConnectionFailure);
        read_callbacks_->upstreamHost()->outlierDetector().putResult( Upstream::Outlier::Result::LocalOriginConnectFailed);
      }

      initializeUpstreamConnection();
    } else {
      if (read_callbacks_->connection().state() == Network::Connection::State::Open) {
        read_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
      }
    }
  }
}

void Filter::onUpstreamConnection() {
  connecting_ = false;
  
  
  read_callbacks_->connection().readDisable(false);

  read_callbacks_->upstreamHost()->outlierDetector().putResult( Upstream::Outlier::Result::LocalOriginConnectSuccessFinal);

  ENVOY_CONN_LOG(debug, "TCP:onUpstreamEvent(), requestedServerName: {}", read_callbacks_->connection(), getStreamInfo().downstreamAddressProvider().requestedServerName());


  if (config_->idleTimeout()) {
    
    
    
    idle_timer_ = read_callbacks_->connection().dispatcher().createTimer( [upstream_callbacks = upstream_callbacks_]() { upstream_callbacks->onIdleTimeout(); });
    resetIdleTimer();
    read_callbacks_->connection().addBytesSentCallback([this](uint64_t) {
      resetIdleTimer();
      return true;
    });
    if (upstream_) {
      upstream_->addBytesSentCallback([upstream_callbacks = upstream_callbacks_](uint64_t) -> bool {
        upstream_callbacks->onBytesSent();
        return true;
      });
    }
  }
}

void Filter::onIdleTimeout() {
  ENVOY_CONN_LOG(debug, "Session timed out", read_callbacks_->connection());
  config_->stats().idle_timeout_.inc();

  
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
}

void Filter::onMaxDownstreamConnectionDuration() {
  ENVOY_CONN_LOG(debug, "max connection duration reached", read_callbacks_->connection());
  getStreamInfo().setResponseFlag(StreamInfo::ResponseFlag::DurationTimeout);
  config_->stats().max_downstream_connection_duration_.inc();
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
}

void Filter::resetIdleTimer() {
  if (idle_timer_ != nullptr) {
    ASSERT(config_->idleTimeout());
    idle_timer_->enableTimer(config_->idleTimeout().value());
  }
}

void Filter::disableIdleTimer() {
  if (idle_timer_ != nullptr) {
    idle_timer_->disableTimer();
    idle_timer_.reset();
  }
}

UpstreamDrainManager::~UpstreamDrainManager() {
  
  
  if (!drainers_.empty()) {
    auto& dispatcher = drainers_.begin()->second->dispatcher();
    while (!drainers_.empty()) {
      auto begin = drainers_.begin();
      Drainer* key = begin->first;
      begin->second->cancelDrain();

      
      
      ASSERT(drainers_.find(key) == drainers_.end());
    }

    
    
    
    dispatcher.clearDeferredDeleteList();
  }
}

void UpstreamDrainManager::add(const Config::SharedConfigSharedPtr& config, Tcp::ConnectionPool::ConnectionDataPtr&& upstream_conn_data, const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks, Event::TimerPtr&& idle_timer, const Upstream::HostDescriptionConstSharedPtr& upstream_host) {



  DrainerPtr drainer(new Drainer(*this, config, callbacks, std::move(upstream_conn_data), std::move(idle_timer), upstream_host));
  callbacks->drain(*drainer);

  
  Drainer* ptr = drainer.get();
  drainers_[ptr] = std::move(drainer);
}

void UpstreamDrainManager::remove(Drainer& drainer, Event::Dispatcher& dispatcher) {
  auto it = drainers_.find(&drainer);
  ASSERT(it != drainers_.end());
  dispatcher.deferredDelete(std::move(it->second));
  drainers_.erase(it);
}

Drainer::Drainer(UpstreamDrainManager& parent, const Config::SharedConfigSharedPtr& config, const std::shared_ptr<Filter::UpstreamCallbacks>& callbacks, Tcp::ConnectionPool::ConnectionDataPtr&& conn_data, Event::TimerPtr&& idle_timer, const Upstream::HostDescriptionConstSharedPtr& upstream_host)


    : parent_(parent), callbacks_(callbacks), upstream_conn_data_(std::move(conn_data)), timer_(std::move(idle_timer)), upstream_host_(upstream_host), config_(config) {
  ENVOY_CONN_LOG(trace, "draining the upstream connection", upstream_conn_data_->connection());
  config_->stats().upstream_flush_total_.inc();
  config_->stats().upstream_flush_active_.inc();
}

void Drainer::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    if (timer_ != nullptr) {
      timer_->disableTimer();
    }
    config_->stats().upstream_flush_active_.dec();
    parent_.remove(*this, upstream_conn_data_->connection().dispatcher());
  }
}

void Drainer::onData(Buffer::Instance& data, bool) {
  if (data.length() > 0) {
    
    
    
    
    cancelDrain();
  }
}

void Drainer::onIdleTimeout() {
  config_->stats().idle_timeout_.inc();
  cancelDrain();
}

void Drainer::onBytesSent() {
  if (timer_ != nullptr) {
    timer_->enableTimer(config_->idleTimeout().value());
  }
}

void Drainer::cancelDrain() {
  
  upstream_conn_data_->connection().close(Network::ConnectionCloseType::NoFlush);
}

Event::Dispatcher& Drainer::dispatcher() { return upstream_conn_data_->connection().dispatcher(); }

} 
} 
