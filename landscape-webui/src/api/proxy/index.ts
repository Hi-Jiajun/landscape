import {
  getProxyStatus,
  getProxyConfig,
  updateProxyConfig,
  toggleProxy,
  restartProxy,
  getProxySubscriptions,
  createProxySubscription,
  deleteProxySubscription,
  refreshProxySubscription,
  getProxyNodes,
  testProxyNodeDelay,
  getProxyGroups,
  selectProxyGroupNode,
} from "@landscape-router/types/api/proxy-plugin/proxy-plugin";
import type {
  ProxyRuntimeInfo,
  ProxyPluginConfig,
  ProxySubscription,
  ProxyNodeItem,
  ProxyGroupItem,
  ServiceStatus,
} from "@landscape-router/types/api/schemas";

export type {
  ProxyRuntimeInfo,
  ProxyPluginConfig,
  ProxySubscription,
  ProxyNodeItem,
  ProxyGroupItem,
  ServiceStatus,
};

export async function get_proxy_status(): Promise<ProxyRuntimeInfo> {
  return getProxyStatus();
}

export async function get_proxy_config(): Promise<ProxyPluginConfig> {
  return getProxyConfig();
}

export async function update_proxy_config(
  config: ProxyPluginConfig,
): Promise<void> {
  return updateProxyConfig(config);
}

export async function toggle_proxy_service(
  enable: boolean,
): Promise<ServiceStatus> {
  return toggleProxy({ enable });
}

export async function restart_proxy_service(): Promise<void> {
  return restartProxy();
}

export async function get_proxy_subscriptions(): Promise<ProxySubscription[]> {
  return getProxySubscriptions();
}

export async function create_proxy_subscription(
  name: string,
  url: string,
): Promise<ProxySubscription> {
  return createProxySubscription({ name, url });
}

export async function delete_proxy_subscription(id: string): Promise<void> {
  return deleteProxySubscription(id);
}

export async function refresh_proxy_subscription(id: string): Promise<number> {
  return refreshProxySubscription(id);
}

export async function get_proxy_nodes(): Promise<ProxyNodeItem[]> {
  return getProxyNodes();
}

export async function test_node_delay(
  proxy_name: string,
  url?: string,
): Promise<number> {
  return testProxyNodeDelay({ proxy_name, url });
}

export async function get_proxy_groups(): Promise<ProxyGroupItem[]> {
  return getProxyGroups();
}

export async function select_group_node(
  group_name: string,
  proxy_name: string,
): Promise<void> {
  return selectProxyGroupNode({ group_name, proxy_name });
}
