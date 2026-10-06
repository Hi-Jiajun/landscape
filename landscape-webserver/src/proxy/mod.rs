use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::proxy::{
    CreateSubscriptionReq, ProxyGroupItem, ProxyNodeItem, ProxyPluginConfig, ProxyRuntimeInfo,
    ProxySubscription, SelectGroupProxyReq, TestDelayReq, ToggleProxyReq,
};
use landscape_common::service::ServiceStatus;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::LandscapeApp;
use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::{LandscapeApiError, LandscapeApiResult};

pub fn build_proxy_openapi_router() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_proxy_status))
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
    state
        .proxy_service
        .save_config(config)
        .await
        .map_err(LandscapeApiError::Proxy)?;
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
    let status = state
        .proxy_service
        .toggle(req.enable)
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(status)
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Proxy Plugin",
    operation_id = "restart_proxy",
    responses((status = 200, description = "Success"))
)]
async fn restart_proxy(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<()> {
    state
        .proxy_service
        .restart()
        .await
        .map_err(LandscapeApiError::Proxy)?;
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
    state
        .proxy_service
        .delete_subscription(id)
        .await
        .map_err(LandscapeApiError::Proxy)?;
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
    let count = state
        .proxy_service
        .refresh_subscription(id)
        .await
        .map_err(LandscapeApiError::Proxy)?;
    LandscapeApiResp::success(count)
}

#[utoipa::path(
    get,
    path = "/nodes",
    tag = "Proxy Plugin",
    operation_id = "get_proxy_nodes",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ProxyNodeItem>>))
)]
async fn get_nodes(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ProxyNodeItem>> {
    let raw = match state.proxy_service.get_proxies_from_controller().await {
        Ok(v) => v,
        Err(_) => return LandscapeApiResp::success(Vec::new()),
    };

    let mut items = Vec::new();
    if let Some(proxies_map) = raw.get("proxies").and_then(|v| v.as_object()) {
        for (name, obj) in proxies_map {
            let node_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
            // Filter out internal groups and pseudonodes
            if ["Selector", "URLTest", "Fallback", "Direct", "Reject", "Compatible", "Pass", "PassRule", "RejectDrop", "Relay"].contains(&node_type.as_str())
                || ["PASS", "PASS-RULE", "REJECT-DROP", "DIRECT", "REJECT", "GLOBAL", "COMPATIBLE"].contains(&name.as_str()) {
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
async fn get_groups(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ProxyGroupItem>> {
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
