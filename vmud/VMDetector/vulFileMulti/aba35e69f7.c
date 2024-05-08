

































static smartlist_t *guard_contexts = NULL;

static guard_selection_t *curr_guard_context = NULL;


static int entry_guards_dirty = 0;

static void entry_guard_set_filtered_flags(const or_options_t *options, guard_selection_t *gs, entry_guard_t *guard);

static void pathbias_check_use_success_count(entry_guard_t *guard);
static void pathbias_check_close_success_count(entry_guard_t *guard);
static int node_is_possible_guard(const node_t *node);
static int node_passes_guard_filter(const or_options_t *options, const node_t *node);
static entry_guard_t *entry_guard_add_to_sample_impl(guard_selection_t *gs, const uint8_t *rsa_id_digest, const char *nickname, const tor_addr_port_t *bridge_addrport);


static entry_guard_t *get_sampled_guard_by_bridge_addr(guard_selection_t *gs, const tor_addr_port_t *addrport);
static int entry_guard_obeys_restriction(const entry_guard_t *guard, const entry_guard_restriction_t *rst);


int should_apply_guardfraction(const networkstatus_t *ns)
{
  
  const or_options_t *options = get_options();

  
  if (options->UseGuardFraction == -1) {
    return networkstatus_get_param(ns, "UseGuardFraction", 0, 0, 1);

  }

  return options->UseGuardFraction;
}


static int guard_has_descriptor(const entry_guard_t *guard)
{
  const node_t *node = node_get_by_id(guard->identity);
  if (!node)
    return 0;
  return node_has_descriptor(node);
}


STATIC guard_selection_type_t guard_selection_infer_type(guard_selection_type_t type, const char *name)

{
  if (type == GS_TYPE_INFER) {
    if (!strcmp(name, "bridges"))
      type = GS_TYPE_BRIDGE;
    else if (!strcmp(name, "restricted"))
      type = GS_TYPE_RESTRICTED;
    else type = GS_TYPE_NORMAL;
  }
  return type;
}


STATIC guard_selection_t * guard_selection_new(const char *name, guard_selection_type_t type)

{
  guard_selection_t *gs;

  type = guard_selection_infer_type(type, name);

  gs = tor_malloc_zero(sizeof(*gs));
  gs->name = tor_strdup(name);
  gs->type = type;
  gs->sampled_entry_guards = smartlist_new();
  gs->confirmed_entry_guards = smartlist_new();
  gs->primary_entry_guards = smartlist_new();

  return gs;
}


STATIC guard_selection_t * get_guard_selection_by_name(const char *name, guard_selection_type_t type, int create_if_absent)


{
  if (!guard_contexts) {
    guard_contexts = smartlist_new();
  }
  SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
    if (!strcmp(gs->name, name))
      return gs;
  } SMARTLIST_FOREACH_END(gs);

  if (! create_if_absent)
    return NULL;

  log_debug(LD_GUARD, "Creating a guard selection called %s", name);
  guard_selection_t *new_selection = guard_selection_new(name, type);
  smartlist_add(guard_contexts, new_selection);

  return new_selection;
}


static void create_initial_guard_context(void)
{
  tor_assert(! curr_guard_context);
  if (!guard_contexts) {
    guard_contexts = smartlist_new();
  }
  guard_selection_type_t type = GS_TYPE_INFER;
  const char *name = choose_guard_selection( get_options(), networkstatus_get_live_consensus(approx_time()), NULL, &type);



  tor_assert(name); 
  tor_assert(type != GS_TYPE_INFER);
  log_notice(LD_GUARD, "Starting with guard context \"%s\"", name);
  curr_guard_context = get_guard_selection_by_name(name, type, 1);
}


guard_selection_t * get_guard_selection_info(void)
{
  if (!curr_guard_context) {
    create_initial_guard_context();
  }

  return curr_guard_context;
}


const char * entry_guard_describe(const entry_guard_t *guard)
{
  static char buf[256];
  tor_snprintf(buf, sizeof(buf), "%s ($%s)", strlen(guard->nickname) ? guard->nickname : "[bridge]", hex_str(guard->identity, DIGEST_LEN));


  return buf;
}


const char * entry_guard_get_rsa_id_digest(const entry_guard_t *guard)
{
  return guard->identity;
}


guard_pathbias_t * entry_guard_get_pathbias_state(entry_guard_t *guard)
{
  return &guard->pb;
}

HANDLE_IMPL(entry_guard, entry_guard_t, ATTR_UNUSED STATIC)


MOCK_IMPL(STATIC time_t, randomize_time,(time_t now, time_t max_backdate))
{
  tor_assert(max_backdate > 0);

  time_t earliest = now - max_backdate;
  time_t latest = now;
  if (earliest <= 0)
    earliest = 1;
  if (latest <= earliest)
    latest = earliest + 1;

  return crypto_rand_time_range(earliest, latest);
}




STATIC double get_max_sample_threshold(void)
{
  int32_t pct = networkstatus_get_param(NULL, "guard-max-sample-threshold-percent", DFLT_MAX_SAMPLE_THRESHOLD_PERCENT, 1, 100);


  return pct / 100.0;
}

STATIC int get_max_sample_size_absolute(void)
{
  return (int) networkstatus_get_param(NULL, "guard-max-sample-size", DFLT_MAX_SAMPLE_SIZE, 1, INT32_MAX);

}

STATIC int get_min_filtered_sample_size(void)
{
  return networkstatus_get_param(NULL, "guard-min-filtered-sample-size", DFLT_MIN_FILTERED_SAMPLE_SIZE, 1, INT32_MAX);

}

STATIC int get_remove_unlisted_guards_after_days(void)
{
  return networkstatus_get_param(NULL, "guard-remove-unlisted-guards-after-days", DFLT_REMOVE_UNLISTED_GUARDS_AFTER_DAYS, 1, 365*10);


}

STATIC int get_guard_lifetime(void)
{
  if (get_options()->GuardLifetime >= 86400)
    return get_options()->GuardLifetime;
  int32_t days;
  days = networkstatus_get_param(NULL, "guard-lifetime-days", DFLT_GUARD_LIFETIME_DAYS, 1, 365*10);

  return days * 86400;
}

STATIC int get_guard_confirmed_min_lifetime(void)
{
  if (get_options()->GuardLifetime >= 86400)
    return get_options()->GuardLifetime;
  int32_t days;
  days = networkstatus_get_param(NULL, "guard-confirmed-min-lifetime-days", DFLT_GUARD_CONFIRMED_MIN_LIFETIME_DAYS, 1, 365*10);

  return days * 86400;
}

STATIC int get_n_primary_guards(void)
{
  const int n = get_options()->NumEntryGuards;
  const int n_dir = get_options()->NumDirectoryGuards;
  if (n > 5) {
    return MAX(n_dir, n + n / 2);
  } else if (n >= 1) {
    return MAX(n_dir, n * 2);
  }

  return networkstatus_get_param(NULL, "guard-n-primary-guards", DFLT_N_PRIMARY_GUARDS, 1, INT32_MAX);

}

STATIC int get_n_primary_guards_to_use(guard_usage_t usage)
{
  int configured;
  const char *param_name;
  int param_default;
  if (usage == GUARD_USAGE_DIRGUARD) {
    configured = get_options()->NumDirectoryGuards;
    param_name = "guard-n-primary-dir-guards-to-use";
    param_default = DFLT_N_PRIMARY_DIR_GUARDS_TO_USE;
  } else {
    configured = get_options()->NumEntryGuards;
    param_name = "guard-n-primary-guards-to-use";
    param_default = DFLT_N_PRIMARY_GUARDS_TO_USE;
  }
  if (configured >= 1) {
    return configured;
  }
  return networkstatus_get_param(NULL, param_name, param_default, 1, INT32_MAX);
}

STATIC int get_internet_likely_down_interval(void)
{
  return networkstatus_get_param(NULL, "guard-internet-likely-down-interval", DFLT_INTERNET_LIKELY_DOWN_INTERVAL, 1, INT32_MAX);

}

STATIC int get_nonprimary_guard_connect_timeout(void)
{
  return networkstatus_get_param(NULL, "guard-nonprimary-guard-connect-timeout", DFLT_NONPRIMARY_GUARD_CONNECT_TIMEOUT, 1, INT32_MAX);


}

STATIC int get_nonprimary_guard_idle_timeout(void)
{
  return networkstatus_get_param(NULL, "guard-nonprimary-guard-idle-timeout", DFLT_NONPRIMARY_GUARD_IDLE_TIMEOUT, 1, INT32_MAX);


}

STATIC double get_meaningful_restriction_threshold(void)
{
  int32_t pct = networkstatus_get_param(NULL, "guard-meaningful-restriction-percent", DFLT_MEANINGFUL_RESTRICTION_PERCENT, 1, INT32_MAX);


  return pct / 100.0;
}

STATIC double get_extreme_restriction_threshold(void)
{
  int32_t pct = networkstatus_get_param(NULL, "guard-extreme-restriction-percent", DFLT_EXTREME_RESTRICTION_PERCENT, 1, INT32_MAX);


  return pct / 100.0;
}


static void mark_guard_maybe_reachable(entry_guard_t *guard)
{
  if (guard->is_reachable != GUARD_REACHABLE_NO) {
    return;
  }

  
  guard->is_reachable = GUARD_REACHABLE_MAYBE;
  if (guard->is_filtered_guard)
    guard->is_usable_filtered_guard = 1;
}


STATIC void mark_primary_guards_maybe_reachable(guard_selection_t *gs)
{
  tor_assert(gs);

  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);

  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    mark_guard_maybe_reachable(guard);
  } SMARTLIST_FOREACH_END(guard);
}


static void mark_all_guards_maybe_reachable(guard_selection_t *gs)
{
  tor_assert(gs);

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    mark_guard_maybe_reachable(guard);
  } SMARTLIST_FOREACH_END(guard);
}




STATIC const char * choose_guard_selection(const or_options_t *options, const networkstatus_t *live_ns, const guard_selection_t *old_selection, guard_selection_type_t *type_out)



{
  tor_assert(options);
  tor_assert(type_out);

  if (options->UseBridges) {
    *type_out = GS_TYPE_BRIDGE;
    return "bridges";
  }

  if (! live_ns) {
    
    *type_out = GS_TYPE_NORMAL;
    return "default";
  }

  const smartlist_t *nodes = nodelist_get_list();
  int n_guards = 0, n_passing_filter = 0;
  SMARTLIST_FOREACH_BEGIN(nodes, const node_t *, node) {
    if (node_is_possible_guard(node)) {
      ++n_guards;
      if (node_passes_guard_filter(options, node)) {
        ++n_passing_filter;
      }
    }
  } SMARTLIST_FOREACH_END(node);

  
  const int meaningful_threshold_high = (int)(n_guards * get_meaningful_restriction_threshold() * 1.05);
  const int meaningful_threshold_mid = (int)(n_guards * get_meaningful_restriction_threshold());
  const int meaningful_threshold_low = (int)(n_guards * get_meaningful_restriction_threshold() * .95);
  const int extreme_threshold = (int)(n_guards * get_extreme_restriction_threshold());

  

  static int have_warned_extreme_threshold = 0;
  if (n_guards && n_passing_filter < extreme_threshold && ! have_warned_extreme_threshold) {

    have_warned_extreme_threshold = 1;
    const double exclude_frac = (n_guards - n_passing_filter) / (double)n_guards;
    log_warn(LD_GUARD, "Your configuration excludes %d%% of all possible " "guards. That's likely to make you stand out from the " "rest of the world.", (int)(exclude_frac * 100));

  }

  
  if (old_selection == NULL) {
    if (n_passing_filter >= meaningful_threshold_mid) {
      *type_out = GS_TYPE_NORMAL;
      return "default";
    } else {
      *type_out = GS_TYPE_RESTRICTED;
      return "restricted";
    }
  }

  
  tor_assert(old_selection);

  
  if (n_passing_filter >= meaningful_threshold_high) {
    *type_out = GS_TYPE_NORMAL;
    return "default";
  } else if (n_passing_filter < meaningful_threshold_low) {
    *type_out = GS_TYPE_RESTRICTED;
    return "restricted";
  } else {
    
    *type_out = old_selection->type;
    return old_selection->name;
  }
}


int update_guard_selection_choice(const or_options_t *options)
{
  if (!curr_guard_context) {
    create_initial_guard_context();
    return 1;
  }

  guard_selection_type_t type = GS_TYPE_INFER;
  const char *new_name = choose_guard_selection( options, networkstatus_get_live_consensus(approx_time()), curr_guard_context, &type);



  tor_assert(new_name);
  tor_assert(type != GS_TYPE_INFER);

  const char *cur_name = curr_guard_context->name;
  if (! strcmp(cur_name, new_name)) {
    log_debug(LD_GUARD, "Staying with guard context \"%s\" (no change)", new_name);
    return 0; 
  }

  log_notice(LD_GUARD, "Switching to guard context \"%s\" (was using \"%s\")", new_name, cur_name);
  guard_selection_t *new_guard_context;
  new_guard_context = get_guard_selection_by_name(new_name, type, 1);
  tor_assert(new_guard_context);
  tor_assert(new_guard_context != curr_guard_context);
  curr_guard_context = new_guard_context;

  return 1;
}


static int node_is_possible_guard(const node_t *node)
{
  

  tor_assert(node);
  return (node->is_possible_guard && node->is_stable && node->is_fast && node->is_valid && node_is_dir(node));



}


STATIC entry_guard_t * get_sampled_guard_with_id(guard_selection_t *gs, const uint8_t *rsa_id)

{
  tor_assert(gs);
  tor_assert(rsa_id);
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    if (tor_memeq(guard->identity, rsa_id, DIGEST_LEN))
      return guard;
  } SMARTLIST_FOREACH_END(guard);
  return NULL;
}


static entry_guard_t * get_sampled_guard_for_bridge(guard_selection_t *gs, const bridge_info_t *bridge)

{
  const uint8_t *id = bridge_get_rsa_id_digest(bridge);
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);
  entry_guard_t *guard;
  if (BUG(!addrport))
    return NULL; 
  guard = get_sampled_guard_by_bridge_addr(gs, addrport);
  if (! guard || (id && tor_memneq(id, guard->identity, DIGEST_LEN)))
    return NULL;
  else return guard;
}


static bridge_info_t * get_bridge_info_for_guard(const entry_guard_t *guard)
{
  const uint8_t *identity = NULL;
  if (! tor_digest_is_zero(guard->identity)) {
    identity = (const uint8_t *)guard->identity;
  }
  if (BUG(guard->bridge_addr == NULL))
    return NULL;

  return get_configured_bridge_by_exact_addr_port_digest( &guard->bridge_addr->addr, guard->bridge_addr->port, (const char*)identity);


}


static inline int have_sampled_guard_with_id(guard_selection_t *gs, const uint8_t *rsa_id)
{
  return get_sampled_guard_with_id(gs, rsa_id) != NULL;
}


STATIC entry_guard_t * entry_guard_add_to_sample(guard_selection_t *gs, const node_t *node)

{
  log_info(LD_GUARD, "Adding %s as to the entry guard sample set.", node_describe(node));

  
  if (BUG(have_sampled_guard_with_id(gs, (const uint8_t*)node->identity)))
    return NULL; 

  return entry_guard_add_to_sample_impl(gs, (const uint8_t*)node->identity, node_get_nickname(node), NULL);


}


static entry_guard_t * entry_guard_add_to_sample_impl(guard_selection_t *gs, const uint8_t *rsa_id_digest, const char *nickname, const tor_addr_port_t *bridge_addrport)



{
  const int GUARD_LIFETIME = get_guard_lifetime();
  tor_assert(gs);

  

  
  if (BUG(!rsa_id_digest && !bridge_addrport))
    return NULL; 

  entry_guard_t *guard = tor_malloc_zero(sizeof(entry_guard_t));

  
  guard->is_persistent = (rsa_id_digest != NULL);
  guard->selection_name = tor_strdup(gs->name);
  if (rsa_id_digest)
    memcpy(guard->identity, rsa_id_digest, DIGEST_LEN);
  if (nickname)
    strlcpy(guard->nickname, nickname, sizeof(guard->nickname));
  guard->sampled_on_date = randomize_time(approx_time(), GUARD_LIFETIME/10);
  tor_free(guard->sampled_by_version);
  guard->sampled_by_version = tor_strdup(VERSION);
  guard->currently_listed = 1;
  guard->confirmed_idx = -1;

  
  guard->is_reachable = GUARD_REACHABLE_MAYBE;
  if (bridge_addrport)
    guard->bridge_addr = tor_memdup(bridge_addrport, sizeof(*bridge_addrport));

  smartlist_add(gs->sampled_entry_guards, guard);
  guard->in_selection = gs;
  entry_guard_set_filtered_flags(get_options(), gs, guard);
  entry_guards_changed_for_guard_selection(gs);
  return guard;
}


static entry_guard_t * entry_guard_add_bridge_to_sample(guard_selection_t *gs, const bridge_info_t *bridge)

{
  const uint8_t *id_digest = bridge_get_rsa_id_digest(bridge);
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);

  tor_assert(addrport);

  
  if (BUG(get_sampled_guard_for_bridge(gs, bridge)))
    return NULL; 

  return entry_guard_add_to_sample_impl(gs, id_digest, NULL, addrport);
}


static entry_guard_t * get_sampled_guard_by_bridge_addr(guard_selection_t *gs, const tor_addr_port_t *addrport)

{
  if (! gs)
    return NULL;
  if (BUG(!addrport))
    return NULL;
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, g) {
    if (g->bridge_addr && tor_addr_port_eq(addrport, g->bridge_addr))
      return g;
  } SMARTLIST_FOREACH_END(g);
  return NULL;
}


void entry_guard_learned_bridge_identity(const tor_addr_port_t *addrport, const uint8_t *rsa_id_digest)

{
  guard_selection_t *gs = get_guard_selection_by_name("bridges", GS_TYPE_BRIDGE, 0);

  if (!gs)
    return;

  entry_guard_t *g = get_sampled_guard_by_bridge_addr(gs, addrport);
  if (!g)
    return;

  int make_persistent = 0;

  if (tor_digest_is_zero(g->identity)) {
    memcpy(g->identity, rsa_id_digest, DIGEST_LEN);
    make_persistent = 1;
  } else if (tor_memeq(g->identity, rsa_id_digest, DIGEST_LEN)) {
    
    if (BUG(! g->is_persistent))
      make_persistent = 1;
  } else {
    char old_id[HEX_DIGEST_LEN+1];
    base16_encode(old_id, sizeof(old_id), g->identity, sizeof(g->identity));
    log_warn(LD_BUG, "We 'learned' an identity %s for a bridge at %s:%d, but " "we already knew a different one (%s). Ignoring the new info as " "possibly bogus.", hex_str((const char *)rsa_id_digest, DIGEST_LEN), fmt_and_decorate_addr(&addrport->addr), addrport->port, old_id);




    return; 
  }

  if (make_persistent) {
    g->is_persistent = 1;
    entry_guards_changed_for_guard_selection(gs);
  }
}


STATIC int num_reachable_filtered_guards(guard_selection_t *gs, const entry_guard_restriction_t *rst)

{
  int n_reachable_filtered_guards = 0;
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (guard->is_usable_filtered_guard)
      ++n_reachable_filtered_guards;
  } SMARTLIST_FOREACH_END(guard);
  return n_reachable_filtered_guards;
}


static int get_max_sample_size(guard_selection_t *gs, int n_guards)

{
  const int using_bridges = (gs->type == GS_TYPE_BRIDGE);
  const int min_sample = get_min_filtered_sample_size();

  
  if (using_bridges)
    return INT_MAX;

  const int max_sample_by_pct = (int)(n_guards * get_max_sample_threshold());
  const int max_sample_absolute = get_max_sample_size_absolute();
  const int max_sample = MIN(max_sample_by_pct, max_sample_absolute);
  if (max_sample < min_sample)
    return min_sample;
  else return max_sample;
}


static smartlist_t * get_eligible_guards(const or_options_t *options, guard_selection_t *gs, int *n_guards_out)


{
  
  smartlist_t *eligible_guards = smartlist_new();
  int n_guards = 0; 

  if (gs->type == GS_TYPE_BRIDGE) {
    const smartlist_t *bridges = bridge_list_get();
    SMARTLIST_FOREACH_BEGIN(bridges, bridge_info_t *, bridge) {
      ++n_guards;
      if (NULL != get_sampled_guard_for_bridge(gs, bridge)) {
        continue;
      }
      smartlist_add(eligible_guards, bridge);
    } SMARTLIST_FOREACH_END(bridge);
  } else {
    const smartlist_t *nodes = nodelist_get_list();
    const int n_sampled = smartlist_len(gs->sampled_entry_guards);

    
    digestset_t *sampled_guard_ids = digestset_new(n_sampled);
    SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, const entry_guard_t *, guard) {
      digestset_add(sampled_guard_ids, guard->identity);
    } SMARTLIST_FOREACH_END(guard);

    SMARTLIST_FOREACH_BEGIN(nodes, const node_t *, node) {
      if (! node_is_possible_guard(node))
        continue;
      if (gs->type == GS_TYPE_RESTRICTED) {
        
        if (! node_passes_guard_filter(options, node))
          continue;
      }
      ++n_guards;
      if (digestset_contains(sampled_guard_ids, node->identity))
        continue;
      smartlist_add(eligible_guards, (node_t*)node);
    } SMARTLIST_FOREACH_END(node);

    
    digestset_free(sampled_guard_ids);
  }

  *n_guards_out = n_guards;
  return eligible_guards;
}


static entry_guard_t * select_and_add_guard_item_for_sample(guard_selection_t *gs, smartlist_t *eligible_guards)

{
  entry_guard_t *added_guard;
  if (gs->type == GS_TYPE_BRIDGE) {
    const bridge_info_t *bridge = smartlist_choose(eligible_guards);
    if (BUG(!bridge))
      return NULL; 
    smartlist_remove(eligible_guards, bridge);
    added_guard = entry_guard_add_bridge_to_sample(gs, bridge);
  } else {
    const node_t *node = node_sl_choose_by_bandwidth(eligible_guards, WEIGHT_FOR_GUARD);
    if (BUG(!node))
      return NULL; 
    smartlist_remove(eligible_guards, node);
    added_guard = entry_guard_add_to_sample(gs, node);
  }

  return added_guard;
}


static int live_consensus_is_missing(const guard_selection_t *gs)
{
  tor_assert(gs);
  if (gs->type == GS_TYPE_BRIDGE) {
    
    return 0;
  }
  return networkstatus_get_live_consensus(approx_time()) == NULL;
}


STATIC entry_guard_t * entry_guards_expand_sample(guard_selection_t *gs)
{
  tor_assert(gs);
  const or_options_t *options = get_options();

  if (live_consensus_is_missing(gs)) {
    log_info(LD_GUARD, "Not expanding the sample guard set; we have " "no live consensus.");
    return NULL;
  }

  int n_sampled = smartlist_len(gs->sampled_entry_guards);
  entry_guard_t *added_guard = NULL;
  int n_usable_filtered_guards = num_reachable_filtered_guards(gs, NULL);
  int n_guards = 0;
  smartlist_t *eligible_guards = get_eligible_guards(options, gs, &n_guards);

  const int max_sample = get_max_sample_size(gs, n_guards);
  const int min_filtered_sample = get_min_filtered_sample_size();

  log_info(LD_GUARD, "Expanding the sample guard set. We have %d guards " "in the sample, and %d eligible guards to extend it with.", n_sampled, smartlist_len(eligible_guards));


  while (n_usable_filtered_guards < min_filtered_sample) {
    
    if (n_sampled >= max_sample) {
      log_info(LD_GUARD, "Not expanding the guard sample any further; " "just hit the maximum sample threshold of %d", max_sample);

      goto done;
    }

    
    if (smartlist_len(eligible_guards) == 0) {
      
      log_info(LD_GUARD, "Not expanding the guard sample any further; " "just ran out of eligible guards");
      goto done;
      
    }

    
    added_guard = select_and_add_guard_item_for_sample(gs, eligible_guards);
    if (!added_guard)
      goto done; 

    ++n_sampled;

    if (added_guard->is_usable_filtered_guard)
      ++n_usable_filtered_guards;
  }

 done:
  smartlist_free(eligible_guards);
  return added_guard;
}


static void remove_guard_from_confirmed_and_primary_lists(guard_selection_t *gs, entry_guard_t *guard)

{
  if (guard->is_primary) {
    guard->is_primary = 0;
    smartlist_remove_keeporder(gs->primary_entry_guards, guard);
  } else {
    if (BUG(smartlist_contains(gs->primary_entry_guards, guard))) {
      smartlist_remove_keeporder(gs->primary_entry_guards, guard);
    }
  }

  if (guard->confirmed_idx >= 0) {
    smartlist_remove_keeporder(gs->confirmed_entry_guards, guard);
    guard->confirmed_idx = -1;
    guard->confirmed_on_date = 0;
  } else {
    if (BUG(smartlist_contains(gs->confirmed_entry_guards, guard))) {
      
      smartlist_remove_keeporder(gs->confirmed_entry_guards, guard);
      
    }
  }
}


MOCK_IMPL(STATIC int, entry_guard_is_listed,(guard_selection_t *gs, const entry_guard_t *guard))
{
  if (gs->type == GS_TYPE_BRIDGE) {
    return NULL != get_bridge_info_for_guard(guard);
  } else {
    const node_t *node = node_get_by_id(guard->identity);

    return node && node_is_possible_guard(node);
  }
}


STATIC void sampled_guards_update_from_consensus(guard_selection_t *gs)
{
  tor_assert(gs);
  const int REMOVE_UNLISTED_GUARDS_AFTER = (get_remove_unlisted_guards_after_days() * 86400);
  const int unlisted_since_slop = REMOVE_UNLISTED_GUARDS_AFTER / 5;

  
  
  if (live_consensus_is_missing(gs)) {
    log_info(LD_GUARD, "Not updating the sample guard set; we have " "no live consensus.");
    return;
  }
  log_info(LD_GUARD, "Updating sampled guard status based on received " "consensus.");

  int n_changes = 0;

  
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    
    const int is_listed = entry_guard_is_listed(gs, guard);

    if (is_listed && ! guard->currently_listed) {
      ++n_changes;
      guard->currently_listed = 1;
      guard->unlisted_since_date = 0;
      log_info(LD_GUARD, "Sampled guard %s is now listed again.", entry_guard_describe(guard));
    } else if (!is_listed && guard->currently_listed) {
      ++n_changes;
      guard->currently_listed = 0;
      guard->unlisted_since_date = randomize_time(approx_time(), unlisted_since_slop);
      log_info(LD_GUARD, "Sampled guard %s is now unlisted.", entry_guard_describe(guard));
    } else if (is_listed && guard->currently_listed) {
      log_debug(LD_GUARD, "Sampled guard %s is still listed.", entry_guard_describe(guard));
    } else {
      tor_assert(! is_listed && ! guard->currently_listed);
      log_debug(LD_GUARD, "Sampled guard %s is still unlisted.", entry_guard_describe(guard));
    }

    
    if (guard->currently_listed && guard->unlisted_since_date) {
      ++n_changes;
      guard->unlisted_since_date = 0;
      log_warn(LD_BUG, "Sampled guard %s was listed, but with " "unlisted_since_date set. Fixing.", entry_guard_describe(guard));

    } else if (!guard->currently_listed && ! guard->unlisted_since_date) {
      ++n_changes;
      guard->unlisted_since_date = randomize_time(approx_time(), unlisted_since_slop);
      log_warn(LD_BUG, "Sampled guard %s was unlisted, but with " "unlisted_since_date unset. Fixing.", entry_guard_describe(guard));

    }
  } SMARTLIST_FOREACH_END(guard);

  const time_t remove_if_unlisted_since = approx_time() - REMOVE_UNLISTED_GUARDS_AFTER;
  const time_t maybe_remove_if_sampled_before = approx_time() - get_guard_lifetime();
  const time_t remove_if_confirmed_before = approx_time() - get_guard_confirmed_min_lifetime();

  
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    int rmv = 0;

    if (guard->currently_listed == 0 && guard->unlisted_since_date < remove_if_unlisted_since) {
      
      log_info(LD_GUARD, "Removing sampled guard %s: it has been unlisted " "for over %d days", entry_guard_describe(guard), get_remove_unlisted_guards_after_days());

      rmv = 1;
    } else if (guard->sampled_on_date < maybe_remove_if_sampled_before) {
      
      if (guard->confirmed_on_date == 0) {
        rmv = 1;
        log_info(LD_GUARD, "Removing sampled guard %s: it was sampled " "over %d days ago, but never confirmed.", entry_guard_describe(guard), get_guard_lifetime() / 86400);


      } else if (guard->confirmed_on_date < remove_if_confirmed_before) {
        rmv = 1;
        log_info(LD_GUARD, "Removing sampled guard %s: it was sampled " "over %d days ago, and confirmed over %d days ago.", entry_guard_describe(guard), get_guard_lifetime() / 86400, get_guard_confirmed_min_lifetime() / 86400);



      }
    }

    if (rmv) {
      ++n_changes;
      SMARTLIST_DEL_CURRENT(gs->sampled_entry_guards, guard);
      remove_guard_from_confirmed_and_primary_lists(gs, guard);
      entry_guard_free(guard);
    }
  } SMARTLIST_FOREACH_END(guard);

  if (n_changes) {
    gs->primary_guards_up_to_date = 0;
    entry_guards_update_filtered_sets(gs);
    
    entry_guards_changed_for_guard_selection(gs);
  }
}


static int node_passes_guard_filter(const or_options_t *options, const node_t *node)

{
  
  if (routerset_contains_node(options->ExcludeNodes, node))
    return 0;

  if (options->EntryNodes && !routerset_contains_node(options->EntryNodes, node))
    return 0;

  if (!fascist_firewall_allows_node(node, FIREWALL_OR_CONNECTION, 0))
    return 0;

  if (node_is_a_configured_bridge(node))
    return 0;

  return 1;
}


static int bridge_passes_guard_filter(const or_options_t *options, const bridge_info_t *bridge)

{
  tor_assert(bridge);
  if (!bridge)
    return 0;

  if (routerset_contains_bridge(options->ExcludeNodes, bridge))
    return 0;

  
  const tor_addr_port_t *addrport = bridge_get_addr_port(bridge);

  if (!fascist_firewall_allows_address_addr(&addrport->addr, addrport->port, FIREWALL_OR_CONNECTION, 0, 0))


    return 0;

  return 1;
}


static int entry_guard_passes_filter(const or_options_t *options, guard_selection_t *gs, entry_guard_t *guard)

{
  if (guard->currently_listed == 0)
    return 0;
  if (guard->pb.path_bias_disabled)
    return 0;

  if (gs->type == GS_TYPE_BRIDGE) {
    const bridge_info_t *bridge = get_bridge_info_for_guard(guard);
    if (bridge == NULL)
      return 0;
    return bridge_passes_guard_filter(options, bridge);
  } else {
    const node_t *node = node_get_by_id(guard->identity);
    if (node == NULL) {
      
      
      return 0;
    }

    return node_passes_guard_filter(options, node);
  }
}


static int entry_guard_obeys_restriction(const entry_guard_t *guard, const entry_guard_restriction_t *rst)

{
  tor_assert(guard);
  if (! rst)
    return 1; 

  
  return tor_memneq(guard->identity, rst->exclude_id, DIGEST_LEN);
}


void entry_guard_set_filtered_flags(const or_options_t *options, guard_selection_t *gs, entry_guard_t *guard)


{
  unsigned was_filtered = guard->is_filtered_guard;
  guard->is_filtered_guard = 0;
  guard->is_usable_filtered_guard = 0;

  if (entry_guard_passes_filter(options, gs, guard)) {
    guard->is_filtered_guard = 1;

    if (guard->is_reachable != GUARD_REACHABLE_NO)
      guard->is_usable_filtered_guard = 1;

    entry_guard_consider_retry(guard);
  }
  log_debug(LD_GUARD, "Updated sampled guard %s: filtered=%d; " "reachable_filtered=%d.", entry_guard_describe(guard), guard->is_filtered_guard, guard->is_usable_filtered_guard);


  if (!bool_eq(was_filtered, guard->is_filtered_guard)) {
    
    gs->primary_guards_up_to_date = 0;
  }
}


STATIC void entry_guards_update_filtered_sets(guard_selection_t *gs)
{
  const or_options_t *options = get_options();

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_set_filtered_flags(options, gs, guard);
  } SMARTLIST_FOREACH_END(guard);
}


STATIC entry_guard_t * sample_reachable_filtered_entry_guards(guard_selection_t *gs, const entry_guard_restriction_t *rst, unsigned flags)


{
  tor_assert(gs);
  entry_guard_t *result = NULL;
  const unsigned exclude_confirmed = flags & SAMPLE_EXCLUDE_CONFIRMED;
  const unsigned exclude_primary = flags & SAMPLE_EXCLUDE_PRIMARY;
  const unsigned exclude_pending = flags & SAMPLE_EXCLUDE_PENDING;
  const unsigned no_update_primary = flags & SAMPLE_NO_UPDATE_PRIMARY;
  const unsigned need_descriptor = flags & SAMPLE_EXCLUDE_NO_DESCRIPTOR;

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
  } SMARTLIST_FOREACH_END(guard);

  const int n_reachable_filtered = num_reachable_filtered_guards(gs, rst);

  log_info(LD_GUARD, "Trying to sample a reachable guard: We know of %d " "in the USABLE_FILTERED set.", n_reachable_filtered);

  const int min_filtered_sample = get_min_filtered_sample_size();
  if (n_reachable_filtered < min_filtered_sample) {
    log_info(LD_GUARD, "  (That isn't enough. Trying to expand the sample.)");
    entry_guards_expand_sample(gs);
  }

  if (exclude_primary && !gs->primary_guards_up_to_date && !no_update_primary)
    entry_guards_update_primary(gs);

  
  smartlist_t *reachable_filtered_sample = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (! guard->is_usable_filtered_guard)
      continue;
    if (exclude_confirmed && guard->confirmed_idx >= 0)
      continue;
    if (exclude_primary && guard->is_primary)
      continue;
    if (exclude_pending && guard->is_pending)
      continue;
    if (need_descriptor && !guard_has_descriptor(guard))
      continue;
    smartlist_add(reachable_filtered_sample, guard);
  } SMARTLIST_FOREACH_END(guard);

  log_info(LD_GUARD, "  (After filters [%x], we have %d guards to consider.)", flags, smartlist_len(reachable_filtered_sample));

  if (smartlist_len(reachable_filtered_sample)) {
    result = smartlist_choose(reachable_filtered_sample);
    log_info(LD_GUARD, "  (Selected %s.)", result ? entry_guard_describe(result) : "<null>");
  }
  smartlist_free(reachable_filtered_sample);

  return result;
}


static int compare_guards_by_confirmed_idx(const void **a_, const void **b_)
{
  const entry_guard_t *a = *a_, *b = *b_;
  if (a->confirmed_idx < b->confirmed_idx)
    return -1;
  else if (a->confirmed_idx > b->confirmed_idx)
    return 1;
  else return 0;
}


STATIC void entry_guards_update_confirmed(guard_selection_t *gs)
{
  smartlist_clear(gs->confirmed_entry_guards);
  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    if (guard->confirmed_idx >= 0)
      smartlist_add(gs->confirmed_entry_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  smartlist_sort(gs->confirmed_entry_guards, compare_guards_by_confirmed_idx);

  int any_changed = 0;
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (guard->confirmed_idx != guard_sl_idx) {
      any_changed = 1;
      guard->confirmed_idx = guard_sl_idx;
    }
  } SMARTLIST_FOREACH_END(guard);

  gs->next_confirmed_idx = smartlist_len(gs->confirmed_entry_guards);

  if (any_changed) {
    entry_guards_changed_for_guard_selection(gs);
  }
}


STATIC void make_guard_confirmed(guard_selection_t *gs, entry_guard_t *guard)
{
  if (BUG(guard->confirmed_on_date && guard->confirmed_idx >= 0))
    return; 

  if (BUG(smartlist_contains(gs->confirmed_entry_guards, guard)))
    return; 

  const int GUARD_LIFETIME = get_guard_lifetime();
  guard->confirmed_on_date = randomize_time(approx_time(), GUARD_LIFETIME/10);

  log_info(LD_GUARD, "Marking %s as a confirmed guard (index %d)", entry_guard_describe(guard), gs->next_confirmed_idx);


  guard->confirmed_idx = gs->next_confirmed_idx++;
  smartlist_add(gs->confirmed_entry_guards, guard);

  
  
  gs->primary_guards_up_to_date = 0;

  entry_guards_changed_for_guard_selection(gs);
}


STATIC void entry_guards_update_primary(guard_selection_t *gs)
{
  tor_assert(gs);

  
  static int running = 0;
  tor_assert(!running);
  running = 1;

  const int N_PRIMARY_GUARDS = get_n_primary_guards();

  smartlist_t *new_primary_guards = smartlist_new();
  smartlist_t *old_primary_guards = smartlist_new();
  smartlist_add_all(old_primary_guards, gs->primary_entry_guards);

  
  gs->primary_guards_up_to_date = 1;

  
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (smartlist_len(new_primary_guards) >= N_PRIMARY_GUARDS)
      break;
    if (! guard->is_filtered_guard)
      continue;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    if (smartlist_contains(new_primary_guards, guard)) {
      SMARTLIST_DEL_CURRENT_KEEPORDER(old_primary_guards, guard);
    }
  } SMARTLIST_FOREACH_END(guard);

  
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    if (smartlist_len(new_primary_guards) >= N_PRIMARY_GUARDS)
      break;
    if (! guard->is_filtered_guard)
      continue;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
    SMARTLIST_DEL_CURRENT_KEEPORDER(old_primary_guards, guard);
  } SMARTLIST_FOREACH_END(guard);

  
  SMARTLIST_FOREACH_BEGIN(old_primary_guards, entry_guard_t *, guard) {
    guard->is_primary = 0;
  } SMARTLIST_FOREACH_END(guard);

  
  while (smartlist_len(new_primary_guards) < N_PRIMARY_GUARDS) {
    entry_guard_t *guard = sample_reachable_filtered_entry_guards(gs, NULL, SAMPLE_EXCLUDE_CONFIRMED| SAMPLE_EXCLUDE_PRIMARY| SAMPLE_NO_UPDATE_PRIMARY);


    if (!guard)
      break;
    guard->is_primary = 1;
    smartlist_add(new_primary_guards, guard);
  }


  
  SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, guard, {
    tor_assert_nonfatal( bool_eq(guard->is_primary, smartlist_contains(new_primary_guards, guard)));

  });


  int any_change = 0;
  if (smartlist_len(gs->primary_entry_guards) != smartlist_len(new_primary_guards)) {
    any_change = 1;
  } else {
    SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, g) {
      if (g != smartlist_get(new_primary_guards, g_sl_idx)) {
        any_change = 1;
      }
    } SMARTLIST_FOREACH_END(g);
  }

  if (any_change) {
    log_info(LD_GUARD, "Primary entry guards have changed. " "New primary guard list is: ");
    int n = smartlist_len(new_primary_guards);
    SMARTLIST_FOREACH_BEGIN(new_primary_guards, entry_guard_t *, g) {
      log_info(LD_GUARD, "  %d/%d: %s%s%s", g_sl_idx+1, n, entry_guard_describe(g), g->confirmed_idx >= 0 ? " (confirmed)" : "", g->is_filtered_guard ? "" : " (excluded by filter)");


    } SMARTLIST_FOREACH_END(g);
  }

  smartlist_free(old_primary_guards);
  smartlist_free(gs->primary_entry_guards);
  gs->primary_entry_guards = new_primary_guards;
  gs->primary_guards_up_to_date = 1;
  running = 0;
}


static int get_retry_schedule(time_t failing_since, time_t now, int is_primary)

{
  const unsigned SIX_HOURS = 6 * 3600;
  const unsigned FOUR_DAYS = 4 * 86400;
  const unsigned SEVEN_DAYS = 7 * 86400;

  time_t tdiff;
  if (now > failing_since) {
    tdiff = now - failing_since;
  } else {
    tdiff = 0;
  }

  const struct {
    time_t maximum; int primary_delay; int nonprimary_delay;
  } delays[] = {
    { SIX_HOURS,    10*60,  1*60*60 }, { FOUR_DAYS,    90*60,  4*60*60 }, { SEVEN_DAYS, 4*60*60, 18*60*60 }, { TIME_MAX,   9*60*60, 36*60*60 }


  };

  unsigned i;
  for (i = 0; i < ARRAY_LENGTH(delays); ++i) {
    if (tdiff <= delays[i].maximum) {
      return is_primary ? delays[i].primary_delay : delays[i].nonprimary_delay;
    }
  }
  
  tor_assert_nonfatal_unreached();
  return 36*60*60;
  
}


STATIC void entry_guard_consider_retry(entry_guard_t *guard)
{
  if (guard->is_reachable != GUARD_REACHABLE_NO)
    return; 

  const time_t now = approx_time();
  const int delay = get_retry_schedule(guard->failing_since, now, guard->is_primary);
  const time_t last_attempt = guard->last_tried_to_connect;

  if (BUG(last_attempt == 0) || now >= last_attempt + delay) {
    
    char tbuf[ISO_TIME_LEN+1];
    format_local_iso_time(tbuf, last_attempt);
    log_info(LD_GUARD, "Marked %s%sguard %s for possible retry, since we " "haven't tried to use it since %s.", guard->is_primary?"primary ":"", guard->confirmed_idx>=0?"confirmed ":"", entry_guard_describe(guard), tbuf);





    guard->is_reachable = GUARD_REACHABLE_MAYBE;
    if (guard->is_filtered_guard)
      guard->is_usable_filtered_guard = 1;
  }
}


void entry_guards_note_internet_connectivity(guard_selection_t *gs)
{
  gs->last_time_on_internet = approx_time();
}


STATIC entry_guard_t * select_entry_guard_for_circuit(guard_selection_t *gs, guard_usage_t usage, const entry_guard_restriction_t *rst, unsigned *state_out)



{
  const int need_descriptor = (usage == GUARD_USAGE_TRAFFIC);
  tor_assert(gs);
  tor_assert(state_out);

  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);

  int num_entry_guards = get_n_primary_guards_to_use(usage);
  smartlist_t *usable_primary_guards = smartlist_new();

  
  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    if (guard->is_reachable != GUARD_REACHABLE_NO) {
      if (need_descriptor && !guard_has_descriptor(guard)) {
        continue;
      }
      *state_out = GUARD_CIRC_STATE_USABLE_ON_COMPLETION;
      guard->last_tried_to_connect = approx_time();
      smartlist_add(usable_primary_guards, guard);
      if (smartlist_len(usable_primary_guards) >= num_entry_guards)
        break;
    }
  } SMARTLIST_FOREACH_END(guard);

  if (smartlist_len(usable_primary_guards)) {
    entry_guard_t *guard = smartlist_choose(usable_primary_guards);
    smartlist_free(usable_primary_guards);
    log_info(LD_GUARD, "Selected primary guard %s for circuit.", entry_guard_describe(guard));
    return guard;
  }
  smartlist_free(usable_primary_guards);

  
  SMARTLIST_FOREACH_BEGIN(gs->confirmed_entry_guards, entry_guard_t *, guard) {
    if (guard->is_primary)
      continue; 
    if (! entry_guard_obeys_restriction(guard, rst))
      continue;
    entry_guard_consider_retry(guard);
    if (guard->is_usable_filtered_guard && ! guard->is_pending) {
      if (need_descriptor && !guard_has_descriptor(guard))
        continue; 
      guard->is_pending = 1;
      guard->last_tried_to_connect = approx_time();
      *state_out = GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD;
      log_info(LD_GUARD, "No primary guards available. Selected confirmed " "guard %s for circuit. Will try other guards before using " "this circuit.", entry_guard_describe(guard));


      return guard;
    }
  } SMARTLIST_FOREACH_END(guard);

  
  {
    entry_guard_t *guard;
    unsigned flags = 0;
    if (need_descriptor)
      flags |= SAMPLE_EXCLUDE_NO_DESCRIPTOR;
    guard = sample_reachable_filtered_entry_guards(gs, rst, SAMPLE_EXCLUDE_CONFIRMED | SAMPLE_EXCLUDE_PRIMARY | SAMPLE_EXCLUDE_PENDING | flags);




    if (guard == NULL) {
      log_info(LD_GUARD, "Absolutely no sampled guards were available. " "Marking all guards for retry and starting from top again.");
      mark_all_guards_maybe_reachable(gs);
      return NULL;
    }
    guard->is_pending = 1;
    guard->last_tried_to_connect = approx_time();
    *state_out = GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD;
    log_info(LD_GUARD, "No primary or confirmed guards available. Selected " "random guard %s for circuit. Will try other guards before " "using this circuit.", entry_guard_describe(guard));


    return guard;
  }
}


STATIC void entry_guards_note_guard_failure(guard_selection_t *gs, entry_guard_t *guard)

{
  tor_assert(gs);

  guard->is_reachable = GUARD_REACHABLE_NO;
  guard->is_usable_filtered_guard = 0;

  guard->is_pending = 0;
  if (guard->failing_since == 0)
    guard->failing_since = approx_time();

  log_info(LD_GUARD, "Recorded failure for %s%sguard %s", guard->is_primary?"primary ":"", guard->confirmed_idx>=0?"confirmed ":"", entry_guard_describe(guard));


}


STATIC unsigned entry_guards_note_guard_success(guard_selection_t *gs, entry_guard_t *guard, unsigned old_state)


{
  tor_assert(gs);

  
  const time_t last_time_on_internet = gs->last_time_on_internet;
  gs->last_time_on_internet = approx_time();

  guard->is_reachable = GUARD_REACHABLE_YES;
  guard->failing_since = 0;
  guard->is_pending = 0;
  if (guard->is_filtered_guard)
    guard->is_usable_filtered_guard = 1;

  if (guard->confirmed_idx < 0) {
    make_guard_confirmed(gs, guard);
    if (!gs->primary_guards_up_to_date)
      entry_guards_update_primary(gs);
  }

  unsigned new_state;
  switch (old_state) {
    case GUARD_CIRC_STATE_COMPLETE:
    case GUARD_CIRC_STATE_USABLE_ON_COMPLETION:
      new_state = GUARD_CIRC_STATE_COMPLETE;
      break;
    default:
      tor_assert_nonfatal_unreached();
      
    case GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD:
      if (guard->is_primary) {
        
        
        new_state = GUARD_CIRC_STATE_COMPLETE;
      } else {
        new_state = GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD;
      }
      break;
  }

  if (! guard->is_primary) {
    if (last_time_on_internet + get_internet_likely_down_interval()
        < approx_time()) {
      mark_primary_guards_maybe_reachable(gs);
    }
  }

  log_info(LD_GUARD, "Recorded success for %s%sguard %s", guard->is_primary?"primary ":"", guard->confirmed_idx>=0?"confirmed ":"", entry_guard_describe(guard));



  return new_state;
}


STATIC int entry_guard_has_higher_priority(entry_guard_t *a, entry_guard_t *b)
{
  tor_assert(a && b);
  if (a == b)
    return 0;

  
  if (a->confirmed_idx < 0) {
    if (b->confirmed_idx >= 0)
      return 0;
  } else {
    if (b->confirmed_idx < 0)
      return 1;

    
    return (a->confirmed_idx < b->confirmed_idx);
  }

  
  if (a->is_pending) {
    if (! b->is_pending)
      return 1;

    
    return a->last_tried_to_connect < b->last_tried_to_connect;
  } else {
    if (b->is_pending)
      return 0;

    
    return 0;
  }
}


static void entry_guard_restriction_free(entry_guard_restriction_t *rst)
{
  tor_free(rst);
}


void circuit_guard_state_free(circuit_guard_state_t *state)
{
  if (!state)
    return;
  entry_guard_restriction_free(state->restrictions);
  entry_guard_handle_free(state->guard);
  tor_free(state);
}


int entry_guard_pick_for_circuit(guard_selection_t *gs, guard_usage_t usage, entry_guard_restriction_t *rst, const node_t **chosen_node_out, circuit_guard_state_t **guard_state_out)




{
  tor_assert(gs);
  tor_assert(chosen_node_out);
  tor_assert(guard_state_out);
  *chosen_node_out = NULL;
  *guard_state_out = NULL;

  unsigned state = 0;
  entry_guard_t *guard = select_entry_guard_for_circuit(gs, usage, rst, &state);
  if (! guard)
    goto fail;
  if (BUG(state == 0))
    goto fail;
  const node_t *node = node_get_by_id(guard->identity);
  
  if (! node)
    goto fail;
  if (BUG(usage != GUARD_USAGE_DIRGUARD && !node_has_descriptor(node)))
    goto fail;

  *chosen_node_out = node;
  *guard_state_out = tor_malloc_zero(sizeof(circuit_guard_state_t));
  (*guard_state_out)->guard = entry_guard_handle_new(guard);
  (*guard_state_out)->state = state;
  (*guard_state_out)->state_set_at = approx_time();
  (*guard_state_out)->restrictions = rst;

  return 0;
 fail:
  entry_guard_restriction_free(rst);
  return -1;
}


guard_usable_t entry_guard_succeeded(circuit_guard_state_t **guard_state_p)
{
  if (BUG(*guard_state_p == NULL))
    return GUARD_USABLE_NEVER;

  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard || BUG(guard->in_selection == NULL))
    return GUARD_USABLE_NEVER;

  unsigned newstate = entry_guards_note_guard_success(guard->in_selection, guard, (*guard_state_p)->state);


  (*guard_state_p)->state = newstate;
  (*guard_state_p)->state_set_at = approx_time();

  if (newstate == GUARD_CIRC_STATE_COMPLETE) {
    return GUARD_USABLE_NOW;
  } else {
    return GUARD_MAYBE_USABLE_LATER;
  }
}


void entry_guard_cancel(circuit_guard_state_t **guard_state_p)
{
  if (BUG(*guard_state_p == NULL))
    return;
  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard)
    return;

  
  guard->is_pending = 0;
  circuit_guard_state_free(*guard_state_p);
  *guard_state_p = NULL;
}


void entry_guard_failed(circuit_guard_state_t **guard_state_p)
{
  if (BUG(*guard_state_p == NULL))
    return;

  entry_guard_t *guard = entry_guard_handle_get((*guard_state_p)->guard);
  if (! guard || BUG(guard->in_selection == NULL))
    return;

  entry_guards_note_guard_failure(guard->in_selection, guard);

  (*guard_state_p)->state = GUARD_CIRC_STATE_DEAD;
  (*guard_state_p)->state_set_at = approx_time();
}


void entry_guard_chan_failed(channel_t *chan)
{
  if (!chan)
    return;

  smartlist_t *pending = smartlist_new();
  circuit_get_all_pending_on_channel(pending, chan);
  SMARTLIST_FOREACH_BEGIN(pending, circuit_t *, circ) {
    if (!CIRCUIT_IS_ORIGIN(circ))
      continue;

    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    if (origin_circ->guard_state) {
      
      entry_guard_failed(&origin_circ->guard_state);
    }
  } SMARTLIST_FOREACH_END(circ);
  smartlist_free(pending);
}


STATIC int entry_guards_all_primary_guards_are_down(guard_selection_t *gs)
{
  tor_assert(gs);
  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);
  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (guard->is_reachable != GUARD_REACHABLE_NO)
      return 0;
  } SMARTLIST_FOREACH_END(guard);
  return 1;
}


static int circ_state_has_higher_priority(origin_circuit_t *a, const entry_guard_restriction_t *rst, origin_circuit_t *b)


{
  circuit_guard_state_t *state_a = origin_circuit_get_guard_state(a);
  circuit_guard_state_t *state_b = origin_circuit_get_guard_state(b);

  tor_assert(state_a);
  tor_assert(state_b);

  entry_guard_t *guard_a = entry_guard_handle_get(state_a->guard);
  entry_guard_t *guard_b = entry_guard_handle_get(state_b->guard);

  if (! guard_a) {
    
    return 0;
  } else if (! guard_b) {
    
    return 1;
  } else  if (! entry_guard_obeys_restriction(guard_a, rst)) {
    
    return 0;
  } else {
    
    return entry_guard_has_higher_priority(guard_a, guard_b);
  }
}


int entry_guards_upgrade_waiting_circuits(guard_selection_t *gs, const smartlist_t *all_circuits_in, smartlist_t *newly_complete_out)


{
  tor_assert(gs);
  tor_assert(all_circuits_in);
  tor_assert(newly_complete_out);

  if (! entry_guards_all_primary_guards_are_down(gs)) {
    
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits, " "but not all primary guards were definitely down.");
    return 0;
  }

  int n_waiting = 0;
  int n_complete = 0;
  int n_complete_blocking = 0;
  origin_circuit_t *best_waiting_circuit = NULL;
  smartlist_t *all_circuits = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(all_circuits_in, origin_circuit_t *, circ) {
    
    
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (state == NULL)
      continue;
    entry_guard_t *guard = entry_guard_handle_get(state->guard);
    if (!guard || guard->in_selection != gs)
      continue;

    smartlist_add(all_circuits, circ);
  } SMARTLIST_FOREACH_END(circ);

  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if BUG((state == NULL))
      continue;

    if (state->state == GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD) {
      ++n_waiting;
      if (! best_waiting_circuit || circ_state_has_higher_priority(circ, NULL, best_waiting_circuit)) {
        best_waiting_circuit = circ;
      }
    }
  } SMARTLIST_FOREACH_END(circ);

  if (! best_waiting_circuit) {
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits, " "but didn't find any.");
    goto no_change;
  }

  
  const entry_guard_restriction_t *rst_on_best_waiting = origin_circuit_get_guard_state(best_waiting_circuit)->restrictions;

  
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if BUG((state == NULL))
      continue;
    if (state->state != GUARD_CIRC_STATE_COMPLETE)
      continue;
    ++n_complete;
    if (circ_state_has_higher_priority(circ, rst_on_best_waiting, best_waiting_circuit))
      ++n_complete_blocking;
  } SMARTLIST_FOREACH_END(circ);

  if (n_complete_blocking) {
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits: found " "%d complete and %d guard-stalled. At least one complete " "circuit had higher priority, so not upgrading.", n_complete, n_waiting);


    goto no_change;
  }

  
  int n_blockers_found = 0;
  const time_t state_set_at_cutoff = approx_time() - get_nonprimary_guard_connect_timeout();
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (BUG(state == NULL))
      continue;
    if (state->state != GUARD_CIRC_STATE_USABLE_IF_NO_BETTER_GUARD)
      continue;
    if (state->state_set_at <= state_set_at_cutoff)
      continue;
    if (circ_state_has_higher_priority(circ, rst_on_best_waiting, best_waiting_circuit))
      ++n_blockers_found;
  } SMARTLIST_FOREACH_END(circ);

  if (n_blockers_found) {
    log_debug(LD_GUARD, "Considered upgrading guard-stalled circuits: found " "%d guard-stalled, but %d pending circuit(s) had higher " "guard priority, so not upgrading.", n_waiting, n_blockers_found);


    goto no_change;
  }

  
  int n_succeeded = 0;
  SMARTLIST_FOREACH_BEGIN(all_circuits, origin_circuit_t *, circ) {
    circuit_guard_state_t *state = origin_circuit_get_guard_state(circ);
    if (BUG(state == NULL))
      continue;
    if (circ != best_waiting_circuit && rst_on_best_waiting) {
      
      continue;
    }
    if (state->state != GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD)
      continue;
    if (circ_state_has_higher_priority(best_waiting_circuit, NULL, circ))
      continue;

    state->state = GUARD_CIRC_STATE_COMPLETE;
    state->state_set_at = approx_time();
    smartlist_add(newly_complete_out, circ);
    ++n_succeeded;
  } SMARTLIST_FOREACH_END(circ);

  log_info(LD_GUARD, "Considered upgrading guard-stalled circuits: found " "%d guard-stalled, %d complete. %d of the guard-stalled " "circuit(s) had high enough priority to upgrade.", n_waiting, n_complete, n_succeeded);



  tor_assert_nonfatal(n_succeeded >= 1);
  smartlist_free(all_circuits);
  return 1;

 no_change:
  smartlist_free(all_circuits);
  return 0;
}


int entry_guard_state_should_expire(circuit_guard_state_t *guard_state)
{
  if (guard_state == NULL)
    return 0;
  const time_t expire_if_waiting_since = approx_time() - get_nonprimary_guard_idle_timeout();
  return (guard_state->state == GUARD_CIRC_STATE_WAITING_FOR_BETTER_GUARD && guard_state->state_set_at < expire_if_waiting_since);
}


int entry_guards_update_all(guard_selection_t *gs)
{
  sampled_guards_update_from_consensus(gs);
  entry_guards_update_filtered_sets(gs);
  entry_guards_update_confirmed(gs);
  entry_guards_update_primary(gs);
  return 0;
}


STATIC char * entry_guard_encode_for_state(entry_guard_t *guard)
{
  

  smartlist_t *result = smartlist_new();
  char tbuf[ISO_TIME_LEN+1];

  tor_assert(guard);

  smartlist_add_asprintf(result, "in=%s", guard->selection_name);
  smartlist_add_asprintf(result, "rsa_id=%s", hex_str(guard->identity, DIGEST_LEN));
  if (guard->bridge_addr) {
    smartlist_add_asprintf(result, "bridge_addr=%s:%d", fmt_and_decorate_addr(&guard->bridge_addr->addr), guard->bridge_addr->port);

  }
  if (strlen(guard->nickname) && is_legal_nickname(guard->nickname)) {
    smartlist_add_asprintf(result, "nickname=%s", guard->nickname);
  }

  format_iso_time_nospace(tbuf, guard->sampled_on_date);
  smartlist_add_asprintf(result, "sampled_on=%s", tbuf);

  if (guard->sampled_by_version) {
    smartlist_add_asprintf(result, "sampled_by=%s", guard->sampled_by_version);
  }

  if (guard->unlisted_since_date > 0) {
    format_iso_time_nospace(tbuf, guard->unlisted_since_date);
    smartlist_add_asprintf(result, "unlisted_since=%s", tbuf);
  }

  smartlist_add_asprintf(result, "listed=%d", (int)guard->currently_listed);

  if (guard->confirmed_idx >= 0) {
    format_iso_time_nospace(tbuf, guard->confirmed_on_date);
    smartlist_add_asprintf(result, "confirmed_on=%s", tbuf);

    smartlist_add_asprintf(result, "confirmed_idx=%d", guard->confirmed_idx);
  }

  const double EPSILON = 1.0e-6;

  
  guard_pathbias_t *pb = tor_memdup(&guard->pb, sizeof(*pb));
  pb->use_successes = pathbias_get_use_success_count(guard);
  pb->successful_circuits_closed = pathbias_get_close_success_count(guard);

  #define PB_FIELD(field) do {                                           if (pb->field >= EPSILON) { smartlist_add_asprintf(result, "pb_" #field "=%f", pb->field); } } while (0



  PB_FIELD(use_attempts);
  PB_FIELD(use_successes);
  PB_FIELD(circ_attempts);
  PB_FIELD(circ_successes);
  PB_FIELD(successful_circuits_closed);
  PB_FIELD(collapsed_circuits);
  PB_FIELD(unusable_circuits);
  PB_FIELD(timeouts);
  tor_free(pb);


  if (guard->extra_state_fields)
    smartlist_add_strdup(result, guard->extra_state_fields);

  char *joined = smartlist_join_strings(result, " ", 0, NULL);
  SMARTLIST_FOREACH(result, char *, cp, tor_free(cp));
  smartlist_free(result);

  return joined;
}


STATIC entry_guard_t * entry_guard_parse_from_state(const char *s)
{
  
  smartlist_t *extra = smartlist_new();

  
  char *in = NULL;
  char *rsa_id = NULL;
  char *nickname = NULL;
  char *sampled_on = NULL;
  char *sampled_by = NULL;
  char *unlisted_since = NULL;
  char *listed  = NULL;
  char *confirmed_on = NULL;
  char *confirmed_idx = NULL;
  char *bridge_addr = NULL;

  
  char *pb_use_attempts = NULL;
  char *pb_use_successes = NULL;
  char *pb_circ_attempts = NULL;
  char *pb_circ_successes = NULL;
  char *pb_successful_circuits_closed = NULL;
  char *pb_collapsed_circuits = NULL;
  char *pb_unusable_circuits = NULL;
  char *pb_timeouts = NULL;

  
  {
    smartlist_t *entries = smartlist_new();

    strmap_t *vals = strmap_new(); 

    FIELD(in);
    FIELD(rsa_id);
    FIELD(nickname);
    FIELD(sampled_on);
    FIELD(sampled_by);
    FIELD(unlisted_since);
    FIELD(listed);
    FIELD(confirmed_on);
    FIELD(confirmed_idx);
    FIELD(bridge_addr);
    FIELD(pb_use_attempts);
    FIELD(pb_use_successes);
    FIELD(pb_circ_attempts);
    FIELD(pb_circ_successes);
    FIELD(pb_successful_circuits_closed);
    FIELD(pb_collapsed_circuits);
    FIELD(pb_unusable_circuits);
    FIELD(pb_timeouts);


    smartlist_split_string(entries, s, " ", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);

    SMARTLIST_FOREACH_BEGIN(entries, char *, entry) {
      const char *eq = strchr(entry, '=');
      if (!eq) {
        smartlist_add(extra, entry);
        continue;
      }
      char *key = tor_strndup(entry, eq-entry);
      char **target = strmap_get(vals, key);
      if (target == NULL || *target != NULL) {
        
        smartlist_add(extra, entry);
        tor_free(key);
        continue;
      }

      *target = tor_strdup(eq+1);
      tor_free(key);
      tor_free(entry);
    } SMARTLIST_FOREACH_END(entry);

    smartlist_free(entries);
    strmap_free(vals, NULL);
  }

  entry_guard_t *guard = tor_malloc_zero(sizeof(entry_guard_t));
  guard->is_persistent = 1;

  if (in == NULL) {
    log_warn(LD_CIRC, "Guard missing 'in' field");
    goto err;
  }

  guard->selection_name = in;
  in = NULL;

  if (rsa_id == NULL) {
    log_warn(LD_CIRC, "Guard missing RSA ID field");
    goto err;
  }

  
  if (base16_decode(guard->identity, sizeof(guard->identity), rsa_id, strlen(rsa_id)) != DIGEST_LEN) {
    log_warn(LD_CIRC, "Unable to decode guard identity %s", escaped(rsa_id));
    goto err;
  }

  if (nickname) {
    strlcpy(guard->nickname, nickname, sizeof(guard->nickname));
  } else {
    guard->nickname[0]='$';
    base16_encode(guard->nickname+1, sizeof(guard->nickname)-1, guard->identity, DIGEST_LEN);
  }

  if (bridge_addr) {
    tor_addr_port_t res;
    memset(&res, 0, sizeof(res));
    int r = tor_addr_port_parse(LOG_WARN, bridge_addr, &res.addr, &res.port, -1);
    if (r == 0)
      guard->bridge_addr = tor_memdup(&res, sizeof(res));
    
  }

  











  time_t sampled_on_time = 0;
  time_t unlisted_since_time = 0;
  time_t confirmed_on_time = 0;

  HANDLE_TIME(sampled_on);
  HANDLE_TIME(unlisted_since);
  HANDLE_TIME(confirmed_on);

  if (sampled_on_time <= 0)
    sampled_on_time = approx_time();
  if (unlisted_since_time < 0)
    unlisted_since_time = 0;
  if (confirmed_on_time < 0)
    confirmed_on_time = 0;

  #undef HANDLE_TIME

  guard->sampled_on_date = sampled_on_time;
  guard->unlisted_since_date = unlisted_since_time;
  guard->confirmed_on_date = confirmed_on_time;

  
  guard->sampled_by_version = sampled_by;
  sampled_by = NULL; 

  
  if (listed && strcmp(listed, "0"))
    guard->currently_listed = 1;

  
  guard->confirmed_idx = -1;
  if (confirmed_idx) {
    int ok=1;
    long idx = tor_parse_long(confirmed_idx, 10, 0, INT_MAX, &ok, NULL);
    if (! ok) {
      log_warn(LD_GUARD, "Guard has invalid confirmed_idx %s", escaped(confirmed_idx));
    } else {
      guard->confirmed_idx = (int)idx;
    }
  }

  
  if (smartlist_len(extra) > 0) {
    guard->extra_state_fields = smartlist_join_strings(extra, " ", 0, NULL);
  }

  
  guard->is_reachable = GUARD_REACHABLE_MAYBE;













  PB_FIELD(use_attempts);
  PB_FIELD(use_successes);
  PB_FIELD(circ_attempts);
  PB_FIELD(circ_successes);
  PB_FIELD(successful_circuits_closed);
  PB_FIELD(collapsed_circuits);
  PB_FIELD(unusable_circuits);
  PB_FIELD(timeouts);


  pathbias_check_use_success_count(guard);
  pathbias_check_close_success_count(guard);

  

  goto done;

 err:
  
  entry_guard_free(guard);
  guard = NULL;

 done:
  tor_free(in);
  tor_free(rsa_id);
  tor_free(nickname);
  tor_free(sampled_on);
  tor_free(sampled_by);
  tor_free(unlisted_since);
  tor_free(listed);
  tor_free(confirmed_on);
  tor_free(confirmed_idx);
  tor_free(bridge_addr);
  tor_free(pb_use_attempts);
  tor_free(pb_use_successes);
  tor_free(pb_circ_attempts);
  tor_free(pb_circ_successes);
  tor_free(pb_successful_circuits_closed);
  tor_free(pb_collapsed_circuits);
  tor_free(pb_unusable_circuits);
  tor_free(pb_timeouts);

  SMARTLIST_FOREACH(extra, char *, cp, tor_free(cp));
  smartlist_free(extra);

  return guard;
}


static void entry_guards_update_guards_in_state(or_state_t *state)
{
  if (!guard_contexts)
    return;
  config_line_t *lines = NULL;
  config_line_t **nextline = &lines;

  SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
    SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
      if (guard->is_persistent == 0)
        continue;
      *nextline = tor_malloc_zero(sizeof(config_line_t));
      (*nextline)->key = tor_strdup("Guard");
      (*nextline)->value = entry_guard_encode_for_state(guard);
      nextline = &(*nextline)->next;
    } SMARTLIST_FOREACH_END(guard);
  } SMARTLIST_FOREACH_END(gs);

  config_free_lines(state->Guard);
  state->Guard = lines;
}


static int entry_guards_load_guards_from_state(or_state_t *state, int set)
{
  const config_line_t *line = state->Guard;
  int n_errors = 0;

  if (!guard_contexts)
    guard_contexts = smartlist_new();

  
  if (set) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      guard_selection_free(gs);
      if (curr_guard_context == gs)
        curr_guard_context = NULL;
      SMARTLIST_DEL_CURRENT(guard_contexts, gs);
    } SMARTLIST_FOREACH_END(gs);
  }

  for ( ; line != NULL; line = line->next) {
    entry_guard_t *guard = entry_guard_parse_from_state(line->value);
    if (guard == NULL) {
      ++n_errors;
      continue;
    }
    tor_assert(guard->selection_name);
    if (!strcmp(guard->selection_name, "legacy")) {
      ++n_errors;
      entry_guard_free(guard);
      continue;
    }

    if (set) {
      guard_selection_t *gs;
      gs = get_guard_selection_by_name(guard->selection_name, GS_TYPE_INFER, 1);
      tor_assert(gs);
      smartlist_add(gs->sampled_entry_guards, guard);
      guard->in_selection = gs;
    } else {
      entry_guard_free(guard);
    }
  }

  if (set) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      entry_guards_update_all(gs);
    } SMARTLIST_FOREACH_END(gs);
  }
  return n_errors ? -1 : 0;
}


entry_guard_t * entry_guard_get_by_id_digest_for_guard_selection(guard_selection_t *gs, const char *digest)

{
  return get_sampled_guard_with_id(gs, (const uint8_t*)digest);
}


const node_t * entry_guard_find_node(const entry_guard_t *guard)
{
  tor_assert(guard);
  return node_get_by_id(guard->identity);
}


entry_guard_t * entry_guard_get_by_id_digest(const char *digest)
{
  return entry_guard_get_by_id_digest_for_guard_selection( get_guard_selection_info(), digest);
}


STATIC void entry_guard_free(entry_guard_t *e)
{
  if (!e)
    return;
  entry_guard_handles_clear(e);
  tor_free(e->sampled_by_version);
  tor_free(e->extra_state_fields);
  tor_free(e->selection_name);
  tor_free(e->bridge_addr);
  tor_free(e);
}


int entry_list_is_constrained(const or_options_t *options)
{
  
  if (options->EntryNodes)
    return 1;
  if (options->UseBridges)
    return 1;
  return 0;
}


int num_bridges_usable(void)
{
  int n_options = 0;

  tor_assert(get_options()->UseBridges);
  guard_selection_t *gs  = get_guard_selection_info();
  tor_assert(gs->type == GS_TYPE_BRIDGE);

  SMARTLIST_FOREACH_BEGIN(gs->sampled_entry_guards, entry_guard_t *, guard) {
    if (guard->is_reachable == GUARD_REACHABLE_NO)
      continue;
    if (tor_digest_is_zero(guard->identity))
      continue;
    const node_t *node = node_get_by_id(guard->identity);
    if (node && node->ri)
      ++n_options;
  } SMARTLIST_FOREACH_END(guard);

  return n_options;
}


static void pathbias_check_use_success_count(entry_guard_t *node)
{
  const or_options_t *options = get_options();
  const double EPSILON = 1.0e-9;

  
  if (node->pb.use_attempts > EPSILON && pathbias_get_use_success_count(node)/node->pb.use_attempts < pathbias_get_extreme_use_rate(options) && pathbias_get_dropguards(options)) {


    node->pb.path_bias_disabled = 1;
    log_info(LD_GENERAL, "Path use bias is too high (%f/%f); disabling node %s", node->pb.circ_successes, node->pb.circ_attempts, node->nickname);


  }
}


static void pathbias_check_close_success_count(entry_guard_t *node)
{
  const or_options_t *options = get_options();
  const double EPSILON = 1.0e-9;

  
  if (node->pb.circ_attempts > EPSILON && pathbias_get_close_success_count(node)/node->pb.circ_attempts < pathbias_get_extreme_rate(options) && pathbias_get_dropguards(options)) {


    node->pb.path_bias_disabled = 1;
    log_info(LD_GENERAL, "Path bias is too high (%f/%f); disabling node %s", node->pb.circ_successes, node->pb.circ_attempts, node->nickname);


  }
}


int entry_guards_parse_state(or_state_t *state, int set, char **msg)
{
  entry_guards_dirty = 0;
  int r1 = entry_guards_load_guards_from_state(state, set);
  entry_guards_dirty = 0;

  if (r1 < 0) {
    if (msg && *msg == NULL) {
      *msg = tor_strdup("parsing error");
    }
    return -1;
  }
  return 0;
}







void entry_guards_changed_for_guard_selection(guard_selection_t *gs)
{
  time_t when;

  tor_assert(gs != NULL);

  entry_guards_dirty = 1;

  if (get_options()->AvoidDiskWrites)
    when = time(NULL) + SLOW_GUARD_STATE_FLUSH_TIME;
  else when = time(NULL) + FAST_GUARD_STATE_FLUSH_TIME;

  
  or_state_mark_dirty(get_or_state(), when);
}


void entry_guards_changed(void)
{
  entry_guards_changed_for_guard_selection(get_guard_selection_info());
}


void entry_guards_update_state(or_state_t *state)
{
  entry_guards_dirty = 0;

  
  entry_guards_update_guards_in_state(state);

  entry_guards_dirty = 0;

  if (!get_options()->AvoidDiskWrites)
    or_state_mark_dirty(get_or_state(), 0);
  entry_guards_dirty = 0;
}


STATIC char * getinfo_helper_format_single_entry_guard(const entry_guard_t *e)
{
  const char *status = NULL;
  time_t when = 0;
  const node_t *node;
  char tbuf[ISO_TIME_LEN+1];
  char nbuf[MAX_VERBOSE_NICKNAME_LEN+1];

  
  if (e->confirmed_idx < 0) {
    status = "never-connected";
  } else if (! e->currently_listed) {
    when = e->unlisted_since_date;
    status = "unusable";
  } else if (! e->is_filtered_guard) {
    status = "unusable";
  } else if (e->is_reachable == GUARD_REACHABLE_NO) {
    when = e->failing_since;
    status = "down";
  } else {
    status = "up";
  }

  node = entry_guard_find_node(e);
  if (node) {
    node_get_verbose_nickname(node, nbuf);
  } else {
    nbuf[0] = '$';
    base16_encode(nbuf+1, sizeof(nbuf)-1, e->identity, DIGEST_LEN);
    
  }

  char *result = NULL;
  if (when) {
    format_iso_time(tbuf, when);
    tor_asprintf(&result, "%s %s %s\n", nbuf, status, tbuf);
  } else {
    tor_asprintf(&result, "%s %s\n", nbuf, status);
  }
  return result;
}


int getinfo_helper_entry_guards(control_connection_t *conn, const char *question, char **answer, const char **errmsg)


{
  guard_selection_t *gs = get_guard_selection_info();

  tor_assert(gs != NULL);

  (void) conn;
  (void) errmsg;

  if (!strcmp(question,"entry-guards") || !strcmp(question,"helper-nodes")) {
    const smartlist_t *guards;
    guards = gs->sampled_entry_guards;

    smartlist_t *sl = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(guards, const entry_guard_t *, e) {
      char *cp = getinfo_helper_format_single_entry_guard(e);
      smartlist_add(sl, cp);
    } SMARTLIST_FOREACH_END(e);
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
  return 0;
}


void guard_get_guardfraction_bandwidth(guardfraction_bandwidth_t *guardfraction_bw, int orig_bandwidth, uint32_t guardfraction_percentage)


{
  double guardfraction_fraction;

  
  tor_assert(guardfraction_percentage <= 100);
  guardfraction_fraction = guardfraction_percentage / 100.0;

  long guard_bw = tor_lround(guardfraction_fraction * orig_bandwidth);
  tor_assert(guard_bw <= INT_MAX);

  guardfraction_bw->guard_bw = (int) guard_bw;

  guardfraction_bw->non_guard_bw = orig_bandwidth - (int) guard_bw;
}


int guards_update_all(void)
{
  int mark_circuits = 0;
  if (update_guard_selection_choice(get_options()))
    mark_circuits = 1;

  tor_assert(curr_guard_context);

  if (entry_guards_update_all(curr_guard_context))
    mark_circuits = 1;

  return mark_circuits;
}


const node_t * guards_choose_guard(cpath_build_state_t *state, circuit_guard_state_t **guard_state_out)

{
  const node_t *r = NULL;
  const uint8_t *exit_id = NULL;
  entry_guard_restriction_t *rst = NULL;
  if (state && (exit_id = build_state_get_exit_rsa_id(state))) {
    
    rst = tor_malloc_zero(sizeof(entry_guard_restriction_t));
    memcpy(rst->exclude_id, exit_id, DIGEST_LEN);
  }
  if (entry_guard_pick_for_circuit(get_guard_selection_info(), GUARD_USAGE_TRAFFIC, rst, &r, guard_state_out) < 0) {



    tor_assert(r == NULL);
  }
  return r;
}


void remove_all_entry_guards_for_guard_selection(guard_selection_t *gs)
{
  
  tor_assert(gs != NULL);
  char *old_name = tor_strdup(gs->name);
  guard_selection_type_t old_type = gs->type;

  SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, entry, {
    control_event_guard(entry->nickname, entry->identity, "DROPPED");
  });

  if (gs == curr_guard_context) {
    curr_guard_context = NULL;
  }

  smartlist_remove(guard_contexts, gs);
  guard_selection_free(gs);

  gs = get_guard_selection_by_name(old_name, old_type, 1);
  entry_guards_changed_for_guard_selection(gs);
  tor_free(old_name);
}


void remove_all_entry_guards(void)
{
  remove_all_entry_guards_for_guard_selection(get_guard_selection_info());
}


const node_t * guards_choose_dirguard(circuit_guard_state_t **guard_state_out)
{
  const node_t *r = NULL;
  if (entry_guard_pick_for_circuit(get_guard_selection_info(), GUARD_USAGE_DIRGUARD, NULL, &r, guard_state_out) < 0) {



    tor_assert(r == NULL);
  }
  return r;
}


int guards_retry_optimistic(const or_options_t *options)
{
  if (! entry_list_is_constrained(options))
    return 0;

  mark_primary_guards_maybe_reachable(get_guard_selection_info());

  return 1;
}


int guard_selection_have_enough_dir_info_to_build_circuits(guard_selection_t *gs)
{
  if (!gs->primary_guards_up_to_date)
    entry_guards_update_primary(gs);

  int n_missing_descriptors = 0;
  int n_considered = 0;
  int num_primary_to_check;

  
  num_primary_to_check = get_n_primary_guards_to_use(GUARD_USAGE_TRAFFIC);
  num_primary_to_check++;

  SMARTLIST_FOREACH_BEGIN(gs->primary_entry_guards, entry_guard_t *, guard) {
    entry_guard_consider_retry(guard);
    if (guard->is_reachable == GUARD_REACHABLE_NO)
      continue;
    n_considered++;
    if (!guard_has_descriptor(guard))
      n_missing_descriptors++;
    if (n_considered >= num_primary_to_check)
      break;
  } SMARTLIST_FOREACH_END(guard);

  return n_missing_descriptors == 0;
}


int entry_guards_have_enough_dir_info_to_build_circuits(void)
{
  return guard_selection_have_enough_dir_info_to_build_circuits( get_guard_selection_info());
}


STATIC void guard_selection_free(guard_selection_t *gs)
{
  if (!gs) return;

  tor_free(gs->name);

  if (gs->sampled_entry_guards) {
    SMARTLIST_FOREACH(gs->sampled_entry_guards, entry_guard_t *, e, entry_guard_free(e));
    smartlist_free(gs->sampled_entry_guards);
    gs->sampled_entry_guards = NULL;
  }

  smartlist_free(gs->confirmed_entry_guards);
  smartlist_free(gs->primary_entry_guards);

  tor_free(gs);
}


void entry_guards_free_all(void)
{
  
  curr_guard_context = NULL;
  
  if (guard_contexts != NULL) {
    SMARTLIST_FOREACH_BEGIN(guard_contexts, guard_selection_t *, gs) {
      guard_selection_free(gs);
    } SMARTLIST_FOREACH_END(gs);
    smartlist_free(guard_contexts);
    guard_contexts = NULL;
  }
  circuit_build_times_free_timeouts(get_circuit_build_times_mutable());
}

