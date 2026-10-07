use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::proxy::{
    CreateSubscriptionReq, LeakGuardReport, ProxyGroupItem, ProxyNodeItem, ProxyPluginConfig,
    ProxyRuntimeInfo, ProxySubscription, SelectGroupProxyReq, TestDelayReq, ToggleProxyReq,
    TproxyDeliveryStatus,
};
use landscape_common::service::ServiceStatus;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::LandscapeApp;
use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::{LandscapeApiError, LandscapeApiResult};

/// Request body for changing the DNS leak guard.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct SetDnsGuardReq {
    /// Whether to block the DNS paths that bypass the managed resolver.
    pub enable: bool,
    /// Interface whose clients are guarded. Defaults to the configured value.
    #[serde(default)]
    pub lan_iface: Option<String>,
    /// Known DoH endpoints to refuse. Ordinary HTTPS, so only an address works.
    #[serde(default)]
    pub doh_block_ips: Option<Vec<String>>,
    /// Trusted hosts and the one service each may keep using. Replaces the whole
    /// list when present.
    #[serde(default)]
    pub exempt: Option<Vec<landscape_common::proxy::DnsGuardExempt>>,
    /// Refuse fragments that cannot be classified.
    #[serde(default)]
    pub drop_fragments: Option<bool>,
    /// Refuse packets whose header chain cannot be parsed.
    #[serde(default)]
    pub drop_unclassified: Option<bool>,
    /// Hijack plaintext DNS over TCP as well as UDP. Only after the managed
    /// resolver has been checked to serve TCP.
    #[serde(default)]
    pub plaintext_tcp: Option<bool>,
}

/// Set the policy for a destination nothing classified.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct SetUnclassifiedReq {
    /// `{"mode":"passthrough"}`, `{"mode":"drop"}`, or
    /// `{"mode":"proxy_tier","flow_id":14}`.
    pub policy: landscape_common::flow::dataplane::UnclassifiedPolicy,
}

pub fn build_proxy_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_proxy_status))
        .routes(routes!(get_tproxy_status))
        .routes(routes!(get_leak_report))
        .routes(routes!(get_dns_guard, set_dns_guard))
        .routes(routes!(get_unclassified, set_unclassified))
        .routes(routes!(get_proxy_config, update_proxy_config))
        .routes(routes!(toggle_proxy))
        .routes(routes!(restart_proxy))
        .routes(routes!(get_subscriptions, create_subscription))
        .routes(routes!(delete_subscription, refresh_subscription))
        .routes(routes!(get_nodes, test_node_delay))
        .routes(routes!(get_groups, select_group_node))
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_status",
    responses((status = 200, description = "Success", body = CommonApiResp<ProxyRuntimeInfo>))
)]
async fn get_proxy_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ProxyRuntimeInfo> {
    let status = state.proxy_service.status().await;
    LandscapeApiResp::success(status)
}

#[utoipa::path(
    get,
    path = "/tproxy",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_tproxy_status",
    responses((status = 200, description = "Kernel state of the local TProxy delivery fabric", body = CommonApiResp<TproxyDeliveryStatus>))
)]
async fn get_tproxy_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<TproxyDeliveryStatus> {
    let status = state.proxy_service.tproxy_status().await;
    LandscapeApiResp::success(status)
}

#[utoipa::path(
    get,
    path = "/leak_report",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_leak_report",
    responses((
        status = 200,
        description = "Whether each of the four leak classes is covered, and what each cell of \
                       the delivery matrix does",
        body = CommonApiResp<LeakGuardReport>
    ))
)]
async fn get_leak_report(State(state): State<LandscapeApp>) -> LandscapeApiResult<LeakGuardReport> {
    use landscape::proxy::leak_guard::{
        BootstrapResolution, LeakGuardInput, RoutingDefault, RoutingRule, dns_hijack_rules,
        evaluate, wan_has_global_ipv6,
    };
    use landscape_common::flow::config::FlowTarget;
    use landscape_common::service::controller::ConfigStoreController;

    let tproxy = state.proxy_service.tproxy_status().await;
    let config = state.proxy_service.get_config().await;
    let engine_running = state.proxy_service.is_running().await;

    // The flows the configuration classifies as proxied. A read failure leaves
    // this empty, which the report treats as "classification unavailable" — the
    // delivery check is skipped rather than claiming coverage it did not verify.
    let flow_rules = state.flow_rule_service.list().await;
    let proxied_flows = match &flow_rules {
        Ok(rules) => rules
            .iter()
            .filter(|rule| rule.enable)
            .filter(|rule| {
                rule.flow_targets
                    .iter()
                    .any(|target| matches!(target.target, FlowTarget::LocalTproxy { .. }))
            })
            .map(|rule| rule.flow_id as u8)
            .collect::<Vec<u8>>(),
        Err(e) => {
            tracing::warn!("cannot read flow rules for the leak report: {e}");
            Vec::new()
        }
    };

    // What the DNS rules do with a destination nothing more specific matched.
    //
    // Read from the rule set because the states that matter are invisible in any
    // single rule: a rule can be written as a redirect and still resolve to a
    // direct path. A read failure leaves it empty, which the report states rather
    // than turning into "no finding".
    let routing_default = match state.dns_rule_service.list().await {
        Ok(rules) => RoutingDefault::from_rules(rules.into_iter().map(|rule| {
            let matches = if rule.source.is_empty() {
                String::new()
            } else {
                rule.source
                    .iter()
                    .map(|source| format!("{source:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let one_line: String = matches
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(160)
                .collect();
            RoutingRule::new(
                rule.index,
                rule.name.clone(),
                rule.enable,
                rule.mark,
                rule.source.is_empty(),
                one_line,
            )
        })),
        Err(e) => {
            tracing::warn!("cannot read DNS rules for the leak report: {e}");
            RoutingDefault::default()
        }
    };

    // Whether the engine can resolve what it needs to start. Each hostname is put
    // through the same classification the resolver uses (`/dns/service/check`), and
    // the rule that answers it is looked up to read its mark - so the verdict comes
    // from the engine's own decision path rather than from a reimplementation of it.
    // The resolver reports which rule answered; the rule's own list supplies what
    // a reader needs to act on that (its index and name) and the mark that decides
    // where the answer's traffic goes.
    let rules_by_id: std::collections::HashMap<
        uuid::Uuid,
        (u32, String, landscape_common::flow::mark::FlowMark),
    > = state
        .dns_rule_service
        .list()
        .await
        .map(|rules| {
            rules
                .into_iter()
                .map(|rule| (rule.id, (rule.index, rule.name.clone(), rule.mark)))
                .collect()
        })
        .unwrap_or_default();
    let mut bootstrap = Vec::new();
    for requirement in state.proxy_service.engine_hostnames().await {
        let checked = state
            .dns_service
            .check_domain(landscape_common::dns::check::CheckDnsReq {
                flow_id: 0,
                domain: requirement.hostname.clone(),
                record_type: landscape_common::dns::rule::LandscapeDnsRecordType::A,
                apply_filter: false,
            })
            .await;
        let matched = checked.rule_id.and_then(|id| rules_by_id.get(&id));
        bootstrap.push(BootstrapResolution {
            // Either list counts: a cached answer is an answer.
            resolved: checked.records.as_ref().is_some_and(|list| !list.is_empty())
                || checked.cache_records.as_ref().is_some_and(|list| !list.is_empty()),
            hostname: requirement.hostname,
            source: requirement.source,
            rule: matched.map(|(index, name, _)| (*index, name.clone())),
            action: matched.map(|(_, _, mark)| mark.action()),
            flow_id: matched.map(|(_, _, mark)| mark.flow_id()),
        });
    }

    let report = evaluate(LeakGuardInput {
        tproxy: &tproxy,
        engine_running,
        missing_listener_policy: config.tproxy_missing_listener,
        wan_has_ipv6: wan_has_global_ipv6(),
        dns_hijack_rules: dns_hijack_rules().await,
        dns_guard: state.proxy_service.dns_guard_status().await,
        proxied_flows,
        routing_default,
        unclassified: config.unclassified,
        unclassified_stats: state.proxy_service.unclassified_stats().unwrap_or_else(|e| {
            // Not swallowed: the finding that reads these counters says they were
            // unavailable, rather than showing zeros that look like "nothing
            // happened".
            tracing::warn!("cannot read the unclassified-destination counters: {e}");
            Default::default()
        }),
        bootstrap,
        mtu: state.proxy_service.mtu_stats().unwrap_or_else(|e| {
            tracing::warn!("cannot read the WAN oversize counters: {e}");
            Default::default()
        }),
    });
    LandscapeApiResp::success(report)
}

#[utoipa::path(
    get,
    path = "/dns_guard",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_dns_guard",
    responses((
        status = 200,
        description = "The DNS leak guard's kernel state: which rules are installed, and the \
                       last error when it could not be applied",
        body = CommonApiResp<landscape_common::proxy::DnsGuardStatus>
    ))
)]
async fn get_dns_guard(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<landscape_common::proxy::DnsGuardStatus> {
    LandscapeApiResp::success(state.proxy_service.dns_guard_status().await)
}

#[utoipa::path(
    post,
    path = "/dns_guard",
    tag = "Proxy Plugin",
    operation_id = "set_proxy_dns_guard",
    request_body = SetDnsGuardReq,
    responses((
        status = 200,
        description = "The guard was applied and its kernel state is returned",
        body = CommonApiResp<landscape_common::proxy::DnsGuardStatus>
    ))
)]
async fn set_dns_guard(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<SetDnsGuardReq>,
) -> LandscapeApiResult<landscape_common::proxy::DnsGuardStatus> {
    // Parsed here rather than in the body type so a typo is a clear 400 instead of
    // a silent omission from the block list.
    let parse =
        |values: &Option<Vec<String>>, what: &str| -> Result<Vec<std::net::IpAddr>, String> {
            values
                .as_ref()
                .map(|list| {
                    list.iter()
                        .map(|value| {
                            value
                                .parse::<std::net::IpAddr>()
                                .map_err(|e| format!("invalid IP in {what}: {value}: {e}"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap_or_else(|| Ok(Vec::new()))
        };
    let blocked = parse(&req.doh_block_ips, "doh_block_ips").map_err(LandscapeApiError::Proxy)?;

    state
        .proxy_service
        .update_config(|config| {
            config.dns_guard.enable = req.enable;
            if let Some(iface) = &req.lan_iface {
                config.dns_guard.lan_iface = iface.clone();
            }
            config.dns_guard.doh_block_ips = blocked.clone();
            if let Some(drop_fragments) = req.drop_fragments {
                config.dns_guard.drop_fragments = drop_fragments;
            }
            if let Some(drop_unclassified) = req.drop_unclassified {
                config.dns_guard.drop_unclassified = drop_unclassified;
            }
            if let Some(plaintext_tcp) = req.plaintext_tcp {
                config.dns_guard.plaintext_tcp = plaintext_tcp;
            }
            if let Some(exempt) = &req.exempt {
                config.dns_guard.exempt = exempt.clone();
            }
        })
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(state.proxy_service.dns_guard_status().await)
}

#[utoipa::path(
    get,
    path = "/unclassified",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_unclassified",
    responses((
        status = 200,
        description = "The datapath policy for a destination nothing classified",
        body = CommonApiResp<landscape_common::flow::dataplane::UnclassifiedPolicy>
    ))
)]
async fn get_unclassified(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<landscape_common::flow::dataplane::UnclassifiedPolicy> {
    LandscapeApiResp::success(state.proxy_service.get_config().await.unclassified)
}

#[utoipa::path(
    post,
    path = "/unclassified",
    tag = "Proxy Plugin",
    operation_id = "set_proxy_unclassified",
    request_body = SetUnclassifiedReq,
    responses((
        status = 200,
        description = "The policy was written to the datapath and the LAN verdict cache was \
                       invalidated, so it is in effect rather than merely recorded",
        body = CommonApiResp<landscape_common::flow::dataplane::UnclassifiedPolicy>
    ))
)]
async fn set_unclassified(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<SetUnclassifiedReq>,
) -> LandscapeApiResult<landscape_common::flow::dataplane::UnclassifiedPolicy> {
    let policy = req.policy;
    state
        .proxy_service
        .update_config(|config| config.unclassified = policy)
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(policy)
}

#[utoipa::path(
    get,
    path = "/config",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_config",
    responses((status = 200, description = "Success", body = CommonApiResp<ProxyPluginConfig>))
)]
async fn get_proxy_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ProxyPluginConfig> {
    let cfg = state.proxy_service.get_config().await;
    LandscapeApiResp::success(cfg)
}

#[utoipa::path(
    put,
    path = "/config",
    tag = "Proxy Plugin",
    operation_id = "update_proxy_config",
    request_body = ProxyPluginConfig,
    responses((status = 200, description = "Success"))
)]
async fn update_proxy_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<ProxyPluginConfig>,
) -> LandscapeApiResult<()> {
    state.proxy_service.save_config(config).await.map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/toggle",
    tag = "Proxy Plugin",
    operation_id = "toggle_proxy",
    request_body = ToggleProxyReq,
    responses((status = 200, description = "Success", body = CommonApiResp<ServiceStatus>))
)]
async fn toggle_proxy(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<ToggleProxyReq>,
) -> LandscapeApiResult<ServiceStatus> {
    let status = state.proxy_service.toggle(req.enable).await.map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(status)
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Proxy Plugin",
    operation_id = "restart_proxy",
    responses((status = 200, description = "Success"))
)]
async fn restart_proxy(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.proxy_service.restart().await.map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/subscriptions",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_subscriptions",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ProxySubscription>>))
)]
async fn get_subscriptions(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ProxySubscription>> {
    let cfg = state.proxy_service.get_config().await;
    LandscapeApiResp::success(cfg.subscriptions)
}

#[utoipa::path(
    post,
    path = "/subscriptions",
    tag = "Proxy Plugin",
    operation_id = "create_proxy_subscription",
    request_body = CreateSubscriptionReq,
    responses((status = 200, description = "Success", body = CommonApiResp<ProxySubscription>))
)]
async fn create_subscription(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<CreateSubscriptionReq>,
) -> LandscapeApiResult<ProxySubscription> {
    let sub = state
        .proxy_service
        .add_subscription(req.name, req.url)
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(sub)
}

#[utoipa::path(
    delete,
    path = "/subscriptions/{id}",
    tag = "Proxy Plugin",
    operation_id = "delete_proxy_subscription",
    params(("id" = Uuid, Path, description = "Subscription ID")),
    responses((status = 200, description = "Success"))
)]
async fn delete_subscription(
    State(state): State<LandscapeApp>,
    Path(id): Path<Uuid>,
) -> LandscapeApiResult<()> {
    state.proxy_service.delete_subscription(id).await.map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/subscriptions/{id}/refresh",
    tag = "Proxy Plugin",
    operation_id = "refresh_proxy_subscription",
    params(("id" = Uuid, Path, description = "Subscription ID")),
    responses((status = 200, description = "Success", body = CommonApiResp<usize>))
)]
async fn refresh_subscription(
    State(state): State<LandscapeApp>,
    Path(id): Path<Uuid>,
) -> LandscapeApiResult<usize> {
    let count =
        state.proxy_service.refresh_subscription(id).await.map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(count)
}

#[utoipa::path(
    get,
    path = "/nodes",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_nodes",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ProxyNodeItem>>))
)]
async fn get_nodes(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<ProxyNodeItem>> {
    let raw = match state.proxy_service.get_proxies_from_controller().await {
        Ok(v) => v,
        Err(_) => return LandscapeApiResp::success(Vec::new()),
    };

    let mut items = Vec::new();
    if let Some(proxies_map) = raw.get("proxies").and_then(|v| v.as_object()) {
        for (name, obj) in proxies_map {
            let node_type =
                obj.get("type").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
            // Filter out internal groups and pseudonodes
            if [
                "Selector",
                "URLTest",
                "Fallback",
                "Direct",
                "Reject",
                "Compatible",
                "Pass",
                "PassRule",
                "RejectDrop",
                "Relay",
            ]
            .contains(&node_type.as_str())
                || ["PASS", "PASS-RULE", "REJECT-DROP", "DIRECT", "REJECT", "GLOBAL", "COMPATIBLE"]
                    .contains(&name.as_str())
            {
                continue;
            }

            let mut history_list = Vec::new();
            let mut latest_delay = None;
            if let Some(hist) = obj.get("history").and_then(|v| v.as_array()) {
                for h in hist {
                    let delay = h.get("delay").and_then(|v| v.as_u64()).unwrap_or(0);
                    let time = h.get("time").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if delay > 0 {
                        latest_delay = Some(delay);
                    }
                    history_list.push(landscape_common::proxy::ProxyDelayHistory { time, delay });
                }
            }

            items.push(ProxyNodeItem {
                name: name.clone(),
                node_type,
                delay: latest_delay,
                history: history_list,
            });
        }
    }

    LandscapeApiResp::success(items)
}

#[utoipa::path(
    post,
    path = "/nodes/delay",
    tag = "Proxy Plugin",
    operation_id = "test_proxy_node_delay",
    request_body = TestDelayReq,
    responses((status = 200, description = "Success", body = CommonApiResp<u64>))
)]
async fn test_node_delay(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<TestDelayReq>,
) -> LandscapeApiResult<u64> {
    let delay = state
        .proxy_service
        .test_node_delay(&req.proxy_name, req.url.as_deref())
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(delay)
}

#[utoipa::path(
    get,
    path = "/groups",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_groups",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ProxyGroupItem>>))
)]
async fn get_groups(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<ProxyGroupItem>> {
    let raw = match state.proxy_service.get_proxies_from_controller().await {
        Ok(v) => v,
        Err(_) => return LandscapeApiResp::success(Vec::new()),
    };

    let mut groups = Vec::new();
    if let Some(proxies_map) = raw.get("proxies").and_then(|v| v.as_object()) {
        for (name, obj) in proxies_map {
            let group_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if !["Selector", "URLTest", "Fallback"].contains(&group_type) {
                continue;
            }

            let now = obj.get("now").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let all = obj
                .get("all")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| !["PASS", "PASS-RULE", "REJECT-DROP"].contains(s))
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();

            groups.push(ProxyGroupItem {
                name: name.clone(),
                group_type: group_type.to_string(),
                now,
                all,
            });
        }
    }

    LandscapeApiResp::success(groups)
}

#[utoipa::path(
    post,
    path = "/groups/select",
    tag = "Proxy Plugin",
    operation_id = "select_proxy_group_node",
    request_body = SelectGroupProxyReq,
    responses((status = 200, description = "Success"))
)]
async fn select_group_node(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<SelectGroupProxyReq>,
) -> LandscapeApiResult<()> {
    state
        .proxy_service
        .select_group_node(&req.group_name, &req.proxy_name)
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(())
}
