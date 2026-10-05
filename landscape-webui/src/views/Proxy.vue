<script lang="ts" setup>
import {
  get_proxy_status,
  get_proxy_config,
  update_proxy_config,
  toggle_proxy_service,
  restart_proxy_service,
  get_proxy_subscriptions,
  create_proxy_subscription,
  delete_proxy_subscription,
  refresh_proxy_subscription,
  get_proxy_nodes,
  test_node_delay,
  get_proxy_groups,
  select_group_node,
  type ProxyRuntimeInfo,
  type ProxyPluginConfig,
  type ProxySubscription,
  type ProxyNodeItem,
  type ProxyGroupItem,
} from "@/api/proxy";
import {
  Rocket,
  Renew,
  Flash,
  Add,
  TrashCan,
  Settings,
  CloudDownload,
  CheckmarkOutline,
} from "@vicons/carbon";
import { useMessage } from "naive-ui";
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useI18n } from "vue-i18n";

const { t } = useI18n();
const message = useMessage();

const loading = ref(false);
const status = ref<ProxyRuntimeInfo>();
const config = ref<ProxyPluginConfig>();
const subscriptions = ref<ProxySubscription[]>([]);
const groups = ref<ProxyGroupItem[]>([]);
const nodes = ref<ProxyNodeItem[]>([]);
const activeTab = ref("groups");
const nodeSearch = ref("");
const testingAll = ref(false);
const testingNode = ref<Record<string, boolean>>({});

// Add subscription modal
const showAddModal = ref(false);
const newSubName = ref("");
const newSubUrl = ref("");
const addingSub = ref(false);

// Refresh polling
let pollTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  await refreshAll();
  pollTimer = setInterval(async () => {
    if (status.value?.status.t === "running" || status.value?.status.t === "staring") {
      await refreshStatusOnly();
    }
  }, 3000);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});

async function refreshAll() {
  loading.value = true;
  try {
    const [st, cfg, subs, grps, nds] = await Promise.all([
      get_proxy_status(),
      get_proxy_config(),
      get_proxy_subscriptions(),
      get_proxy_groups(),
      get_proxy_nodes(),
    ]);
    status.value = st;
    config.value = cfg;
    subscriptions.value = subs;
    groups.value = grps;
    nodes.value = nds;
  } catch (err: any) {
    console.error("Failed to load proxy state", err);
  } finally {
    loading.value = false;
  }
}

async function refreshStatusOnly() {
  try {
    status.value = await get_proxy_status();
    if (status.value?.status.t === "running") {
      groups.value = await get_proxy_groups();
      nodes.value = await get_proxy_nodes();
    }
  } catch (e) {
    // ignore
  }
}

const isRunning = computed(() => status.value?.status.t === "running");

async function handleToggle(enable: boolean) {
  try {
    loading.value = true;
    const res = await toggle_proxy_service(enable);
    message.success(enable ? "代理服务启动中..." : "代理服务已停止，已释放全部内存");
    await refreshAll();
  } catch (err: any) {
    message.error("切换代理服务状态失败: " + (err.message || err));
  } finally {
    loading.value = false;
  }
}

async function handleRestart() {
  try {
    loading.value = true;
    await restart_proxy_service();
    message.success("代理服务已重启");
    await refreshAll();
  } catch (err: any) {
    message.error("重启失败: " + (err.message || err));
  } finally {
    loading.value = false;
  }
}

async function handleSaveConfig() {
  if (!config.value) return;
  try {
    loading.value = true;
    await update_proxy_config(config.value);
    message.success("代理配置已保存并应用");
    await refreshAll();
  } catch (err: any) {
    message.error("保存配置失败: " + (err.message || err));
  } finally {
    loading.value = false;
  }
}

async function handleAddSubscription() {
  if (!newSubName.value.trim() || !newSubUrl.value.trim()) {
    message.warning("请完整填写订阅名称和 URL 链接");
    return;
  }
  addingSub.value = true;
  try {
    await create_proxy_subscription(newSubName.value.trim(), newSubUrl.value.trim());
    message.success("订阅添加成功，后台正在拉取节点...");
    showAddModal.value = false;
    newSubName.value = "";
    newSubUrl.value = "";
    await refreshAll();
  } catch (err: any) {
    message.error("添加订阅失败: " + (err.message || err));
  } finally {
    addingSub.value = false;
  }
}

async function handleDeleteSub(id: string) {
  try {
    await delete_proxy_subscription(id);
    message.success("订阅已删除");
    await refreshAll();
  } catch (err: any) {
    message.error("删除订阅失败: " + (err.message || err));
  }
}

async function handleRefreshSub(id: string) {
  try {
    message.loading("正在拉取最新订阅节点...");
    const count = await refresh_proxy_subscription(id);
    message.success(`订阅已更新，成功解析 ${count} 个节点`);
    await refreshAll();
  } catch (err: any) {
    message.error("更新订阅失败: " + (err.message || err));
  }
}

async function handleTestDelay(proxyName: string) {
  testingNode.value[proxyName] = true;
  try {
    const delay = await test_node_delay(proxyName);
    const target = nodes.value.find((n) => n.name === proxyName);
    if (target) {
      target.delay = delay;
    }
  } catch (err: any) {
    message.warning(`节点 [${proxyName}] 测速超时或失败`);
    const target = nodes.value.find((n) => n.name === proxyName);
    if (target) {
      target.delay = 0;
    }
  } finally {
    testingNode.value[proxyName] = false;
  }
}

async function handleTestAllDelays() {
  testingAll.value = true;
  try {
    const candidates = nodes.value.filter(
      (n) => !["DIRECT", "REJECT", "GLOBAL"].includes(n.name),
    );
    message.info(`正在并发测速 ${candidates.length} 个节点...`);
    await Promise.all(
      candidates.map((n) =>
        test_node_delay(n.name)
          .then((delay) => {
            n.delay = delay;
          })
          .catch(() => {
            n.delay = 0;
          }),
      ),
    );
    message.success("全量节点延迟测试已完成");
  } catch (err: any) {
    message.error("测速过程出现异常: " + (err.message || err));
  } finally {
    testingAll.value = false;
  }
}

async function handleSelectNode(groupName: string, proxyName: string) {
  try {
    await select_group_node(groupName, proxyName);
    message.success(`已切换 [${groupName}] -> ${proxyName}`);
    const grp = groups.value.find((g) => g.name === groupName);
    if (grp) {
      grp.now = proxyName;
    }
  } catch (err: any) {
    message.error("切换节点失败: " + (err.message || err));
  }
}

const filteredNodes = computed(() => {
  if (!nodeSearch.value.trim()) return nodes.value;
  const q = nodeSearch.value.toLowerCase();
  return nodes.value.filter(
    (n) => n.name.toLowerCase().includes(q) || n.node_type.toLowerCase().includes(q),
  );
});

function getDelayType(delay?: number | null) {
  if (!delay || delay === 0) return "error";
  if (delay <= 250) return "success";
  if (delay <= 600) return "info";
  if (delay <= 1000) return "warning";
  return "error";
}

function formatMemory(bytes?: number) {
  if (!bytes || bytes === 0) return "0 MB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

function formatUptime(seconds?: number) {
  if (!seconds || seconds === 0) return "--";
  const m = Math.floor(seconds / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}小时 ${m % 60}分`;
  return `${m}分 ${seconds % 60}秒`;
}

const zashboardUrl = computed(() => {
  const host = typeof window !== "undefined" ? window.location.hostname : "192.168.1.1";
  const port = config.value?.api_port || 9090;
  return `http://${host}:${port}/ui`;
});

function getGroupIcon(name: string) {
  if (name.includes("AI")) return "🤖";
  if (name.includes("流媒体") || name.includes("Media")) return "🎥";
  if (name.includes("游戏") || name.includes("Game") || name.includes("Steam")) return "🎮";
  if (name.includes("通讯") || name.includes("IM")) return "💬";
  if (name.includes("漏网之鱼") || name.includes("Final")) return "🐟";
  if (name.includes("节点选择") || name.includes("Proxy")) return "🚀";
  if (name.includes("直连") || name.includes("DIRECT")) return "🎯";
  if (name.includes("拦截") || name.includes("REJECT")) return "🛑";
  if (name.includes("香港") || name.includes("HK")) return "🇭🇰";
  if (name.includes("台湾") || name.includes("TW")) return "🇹🇼";
  if (name.includes("日本") || name.includes("JP")) return "🇯🇵";
  if (name.includes("美国") || name.includes("US")) return "🇺🇸";
  if (name.includes("新加坡") || name.includes("SG")) return "🇸🇬";
  return "⚡";
}

function getNodeIcon(name: string) {
  if (name.includes("香港") || name.includes("HK")) return "🇭🇰";
  if (name.includes("台湾") || name.includes("TW")) return "🇹🇼";
  if (name.includes("日本") || name.includes("JP")) return "🇯🇵";
  if (name.includes("美国") || name.includes("US")) return "🇺🇸";
  if (name.includes("新加坡") || name.includes("SG")) return "🇸🇬";
  if (name.includes("直连") || name.includes("DIRECT")) return "🎯";
  return "🌐";
}
</script>

<template>
  <div class="proxy-page-container">
    <!-- Top Hero Header Card -->
    <div class="proxy-hero-card">
      <div class="hero-content">
        <div class="hero-left">
          <div class="hero-title-row">
            <span class="hero-logo-icon">🚀</span>
            <h2 class="hero-title">出站代理插件</h2>
            <n-tag
              :type="isRunning ? 'success' : status?.status.t === 'staring' ? 'warning' : 'default'"
              round
              size="small"
              class="status-tag"
            >
              {{ isRunning ? "运行中" : status?.status.t === "staring" ? "启动中" : "已停止 (零资源消耗)" }}
            </n-tag>
          </div>
          <p class="hero-subtitle">
            原生 Linux 守护进程，免 Docker 零虚拟化损耗。直接对接 Landscape eBPF Flow 智能流表与内核分流策略。
          </p>
        </div>

        <div class="hero-right">
          <n-flex align="center" :size="12">
            <div class="switch-box">
              <span class="switch-label">代理主控</span>
              <n-switch
                size="large"
                :value="config?.enable ?? false"
                @update:value="handleToggle"
                :loading="loading"
              />
            </div>
            <n-button
              quaternary
              circle
              size="medium"
              @click="handleRestart"
              :disabled="!isRunning"
              title="重启核心引擎"
            >
              <template #icon>
                <n-icon><Renew /></n-icon>
              </template>
            </n-button>
            <n-button
              type="primary"
              secondary
              size="small"
              tag="a"
              :href="zashboardUrl"
              target="_blank"
              :disabled="!isRunning"
              class="zashboard-btn"
            >
              打开 Zashboard 面板 ↗
            </n-button>
          </n-flex>
        </div>
      </div>

      <!-- Quick Metrics Grid -->
      <div class="metrics-row">
        <div class="metric-chip">
          <span class="chip-label">内核状态 / PID</span>
          <span class="chip-value">
            <span class="status-indicator-dot" :class="{ running: isRunning }"></span>
            {{ isRunning ? (status?.pid ? `PID ${status.pid}` : 'Running') : '已释放' }}
          </span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">核心内存占用</span>
          <span class="chip-value" :class="{ 'zero-cost': !isRunning }">
            {{ formatMemory(status?.memory_bytes) }}
          </span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">分流 / 混合 / API 端口</span>
          <span class="chip-value port-value">
            {{ status?.tproxy_port ?? 17890 }} / {{ status?.mixed_port ?? 7890 }} / {{ status?.api_port ?? 9090 }}
          </span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">已就绪代理节点</span>
          <span class="chip-value">{{ nodes.length }} 节点</span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">持续在线时长</span>
          <span class="chip-value">{{ formatUptime(status?.uptime_seconds) }}</span>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <n-tabs v-model:value="activeTab" type="line" size="large" class="proxy-tabs">
      <!-- Tab 1: Groups & Proxies -->
      <n-tab-pane name="groups" tab="策略组与节点池">
        <div v-if="!isRunning" class="empty-placeholder">
          <n-empty description="代理引擎当前处于停止状态（0 进程、0 内存）。开启右上角主控开关即可极速拉起。">
            <template #extra>
              <n-button type="primary" size="medium" @click="handleToggle(true)">
                一键启动代理服务
              </n-button>
            </template>
          </n-empty>
        </div>

        <div v-else class="groups-pane-content">
          <!-- Proxy Groups Grid -->
          <div class="section-heading">
            <div class="heading-left">
              <span class="heading-title">出站策略组 (Proxy Groups)</span>
              <span class="heading-desc">对应 eBPF 分流目标，点击可直接切换策略出口节点</span>
            </div>
            <div class="heading-badge">
              <n-tag size="small" round :bordered="false">{{ groups.length }} 个策略组</n-tag>
            </div>
          </div>

          <n-grid cols="1 650:2 1050:3 1450:4 1850:5" :x-gap="14" :y-gap="14" class="groups-grid">
            <n-grid-item v-for="grp in groups" :key="grp.name">
              <div class="group-card">
                <div class="group-card-header">
                  <div class="group-header-left">
                    <span class="group-icon">{{ getGroupIcon(grp.name) }}</span>
                    <span class="group-name" :title="grp.name">{{ grp.name }}</span>
                  </div>
                  <n-tag
                    size="tiny"
                    round
                    :bordered="false"
                    :type="grp.group_type === 'URLTest' ? 'info' : 'default'"
                    class="group-type-badge"
                  >
                    {{ grp.group_type === 'URLTest' ? '⚡ 自动选优' : '🎯 手动选择' }}
                  </n-tag>
                </div>

                <div class="group-card-current">
                  <span class="now-label">当前出口：</span>
                  <div class="now-pill" :title="grp.now">
                    <span class="active-node-dot"></span>
                    <span class="now-value">{{ grp.now || '未指定' }}</span>
                  </div>
                </div>

                <div class="group-card-select">
                  <n-select
                    size="small"
                    :value="grp.now"
                    :options="grp.all.map((item) => ({ label: item, value: item }))"
                    @update:value="handleSelectNode(grp.name, $event)"
                    placeholder="切换当前出口节点"
                    class="node-selector"
                  />
                </div>
              </div>
            </n-grid-item>
          </n-grid>

          <!-- Nodes Section -->
          <div class="section-heading nodes-section-header">
            <div class="heading-left">
              <span class="heading-title">可用节点池 (Nodes Pool)</span>
              <span class="heading-desc">共加载 {{ nodes.length }} 个代理出站节点，支持低延迟实时检测</span>
            </div>
            <div class="heading-actions">
              <n-input
                v-model:value="nodeSearch"
                placeholder="搜索节点名称、地区或协议..."
                clearable
                size="small"
                class="node-search-input"
              >
                <template #prefix>
                  <n-icon><Search /></n-icon>
                </template>
              </n-input>
              <n-button
                type="primary"
                secondary
                size="small"
                :loading="testingAll"
                @click="handleTestAllDelays"
                class="test-all-btn"
              >
                <template #icon>
                  <n-icon><Flash /></n-icon>
                </template>
                ⚡ 全部测速
              </n-button>
            </div>
          </div>

          <!-- Nodes Cards Grid -->
          <n-grid cols="1 500:2 800:3 1150:4 1500:5 1900:6" :x-gap="12" :y-gap="12" class="nodes-grid">
            <n-grid-item v-for="node in filteredNodes" :key="node.name">
              <div class="node-card">
                <div class="node-top-row">
                  <span class="node-flag">{{ getNodeIcon(node.name) }}</span>
                  <span class="node-name" :title="node.name">{{ node.name }}</span>
                </div>
                <div class="node-bottom-row">
                  <span class="node-proto-tag">{{ node.node_type.toUpperCase() }}</span>
                  <div class="node-delay-wrapper">
                    <n-tag
                      size="tiny"
                      round
                      :type="getDelayType(node.delay)"
                      class="node-delay-tag"
                    >
                      {{ node.delay && node.delay > 0 ? node.delay + ' ms' : '超时 / 未测' }}
                    </n-tag>
                    <n-button
                      quaternary
                      circle
                      size="tiny"
                      class="test-single-btn"
                      :loading="testingNode[node.name]"
                      @click="handleTestDelay(node.name)"
                      title="单独测速"
                    >
                      <template #icon>
                        <n-icon><Flash /></n-icon>
                      </template>
                    </n-button>
                  </div>
                </div>
              </div>
            </n-grid-item>
          </n-grid>
        </div>
      </n-tab-pane>

      <!-- Tab 2: Subscriptions -->
      <n-tab-pane name="subscriptions" tab="订阅与机场管理">
        <div class="subscriptions-pane">
          <div class="table-toolbar">
            <div class="heading-left">
              <span class="toolbar-title">受管订阅列表 ({{ subscriptions.length }})</span>
              <span class="heading-desc">订阅更新时内核自动平滑重载节点，不中断已有连接</span>
            </div>
            <n-button type="primary" size="small" @click="showAddModal = true">
              <template #icon>
                <n-icon><Add /></n-icon>
              </template>
              添加新订阅
            </n-button>
          </div>

          <n-table :bordered="true" :single-line="false" size="small" class="subs-table">
            <thead>
              <tr>
                <th style="width: 25%;">订阅名称</th>
                <th style="width: 40%;">订阅链接 (URL)</th>
                <th style="width: 10%;">节点数</th>
                <th style="width: 12%;">状态</th>
                <th style="width: 13%;">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="subscriptions.length === 0">
                <td colspan="5" class="empty-subs-cell">
                  暂无订阅配置，点击上方「添加新订阅」导入机场订阅链接
                </td>
              </tr>
              <tr v-for="sub in subscriptions" :key="sub.id">
                <td style="font-weight: 600;">{{ sub.name }}</td>
                <td style="font-family: monospace; font-size: 12px; word-break: break-all;">
                  {{ sub.url }}
                </td>
                <td>
                  <n-tag size="small" round type="info">{{ sub.node_count }} 节点</n-tag>
                </td>
                <td>
                  <n-tag size="small" :type="sub.enabled ? 'success' : 'default'">
                    {{ sub.enabled ? '已启用' : '已停用' }}
                  </n-tag>
                </td>
                <td>
                  <n-space size="small">
                    <n-button
                      size="tiny"
                      type="primary"
                      secondary
                      @click="handleRefreshSub(sub.id)"
                      title="立即更新"
                    >
                      <template #icon><n-icon><CloudDownload /></n-icon></template>
                    </n-button>
                    <n-popconfirm @positive-click="handleDeleteSub(sub.id)">
                      <template #trigger>
                        <n-button size="tiny" type="error" secondary title="删除订阅">
                          <template #icon><n-icon><TrashCan /></n-icon></template>
                        </n-button>
                      </template>
                      确定要删除该订阅吗？
                    </n-popconfirm>
                  </n-space>
                </td>
              </tr>
            </tbody>
          </n-table>
        </div>
      </n-tab-pane>

      <!-- Tab 3: Settings -->
      <n-tab-pane name="settings" tab="核心与网络设置">
        <div v-if="config" class="settings-pane">
          <n-card :bordered="false" class="settings-card">
            <template #header>
              <span class="settings-card-title">⚙️ 底层网络与 API 参数配置</span>
            </template>
            <n-form label-placement="left" label-width="180" size="medium">
              <n-form-item label="透明代理 (TProxy) 端口">
                <n-input-number
                  v-model:value="config.tproxy_port"
                  :min="1"
                  :max="65535"
                  placeholder="默认 17890"
                  style="width: 100%;"
                />
              </n-form-item>
              <n-form-item label="混合代理 (Mixed) 端口">
                <n-input-number
                  v-model:value="config.mixed_port"
                  :min="1"
                  :max="65535"
                  placeholder="默认 7890"
                  style="width: 100%;"
                />
              </n-form-item>
              <n-form-item label="Clash Controller 端口">
                <n-input-number
                  v-model:value="config.api_port"
                  :min="1"
                  :max="65535"
                  placeholder="默认 9090"
                  style="width: 100%;"
                />
              </n-form-item>
              <n-form-item label="分流运行模式">
                <n-select
                  v-model:value="config.mode"
                  :options="[
                    { label: '规则分流 (Rule)', value: 'rule' },
                    { label: '全局代理 (Global)', value: 'global' },
                    { label: '全局直连 (Direct)', value: 'direct' },
                  ]"
                />
              </n-form-item>
              <n-form-item label="日志输出级别">
                <n-select
                  v-model:value="config.log_level"
                  :options="[
                    { label: 'Silent (静默)', value: 'silent' },
                    { label: 'Error (仅错误)', value: 'error' },
                    { label: 'Warning (告警)', value: 'warn' },
                    { label: 'Info (信息)', value: 'info' },
                    { label: 'Debug (调试)', value: 'debug' },
                  ]"
                />
              </n-form-item>
              <n-form-item label="底层核心程序路径">
                <n-input
                  v-model:value="config.engine_path"
                  placeholder="留空自动检测 (/usr/local/bin/mihomo)"
                />
              </n-form-item>

              <div style="margin-top: 24px; text-align: right;">
                <n-button type="primary" size="medium" :loading="loading" @click="handleSaveConfig">
                  保存并生效配置
                </n-button>
              </div>
            </n-form>
          </n-card>
        </div>
      </n-tab-pane>
    </n-tabs>

    <!-- Modal: Add Subscription -->
    <n-modal
      v-model:show="showAddModal"
      preset="card"
      title="添加订阅"
      style="width: 520px;"
      :bordered="false"
    >
      <n-form label-placement="top" size="medium">
        <n-form-item label="订阅名称">
          <n-input v-model:value="newSubName" placeholder="例如：拼车机场 / 专用中继节点" />
        </n-form-item>
        <n-form-item label="订阅链接 (URL)">
          <n-input
            v-model:value="newSubUrl"
            type="textarea"
            :rows="3"
            placeholder="https://... 支持 Clash/Meta 格式订阅链接"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-flex justify="end">
          <n-button @click="showAddModal = false">取消</n-button>
          <n-button type="primary" :loading="addingSub" @click="handleAddSubscription">
            确认添加
          </n-button>
        </n-flex>
      </template>
    </n-modal>
  </div>
</template>

<style scoped>
.proxy-page-container {
  display: flex;
  flex-direction: column;
  flex: 1;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  padding: 18px 24px 32px 24px;
}

.proxy-hero-card {
  width: 100%;
  box-sizing: border-box;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
  border: 1px solid rgba(255, 255, 255, 0.09);
  border-radius: 14px;
  padding: 20px 24px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.18);
  backdrop-filter: blur(10px);
}

.hero-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}

.hero-title-row {
  display: flex;
  align-items: center;
}

.hero-logo-icon {
  font-size: 24px;
  margin-right: 10px;
}

.hero-title {
  margin: 0;
  font-size: 21px;
  font-weight: 700;
  letter-spacing: -0.5px;
}

.status-tag {
  margin-left: 12px;
  font-weight: 600;
}

.hero-subtitle {
  margin: 8px 0 0 0;
  font-size: 13px;
  color: var(--n-text-color-3);
  max-width: 800px;
}

.switch-box {
  display: flex;
  align-items: center;
  background: rgba(255, 255, 255, 0.04);
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.switch-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--n-text-color-2);
  margin-right: 8px;
}

.zashboard-btn {
  font-weight: 600;
}

.metrics-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}

.metric-chip {
  display: flex;
  flex-direction: column;
  padding: 10px 16px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 10px;
  min-width: 130px;
  flex: 1;
}

.chip-label {
  font-size: 11px;
  color: var(--n-text-color-3);
  margin-bottom: 4px;
}

.chip-value {
  display: flex;
  align-items: center;
  font-size: 15px;
  font-weight: 700;
  color: var(--n-text-color-1);
}

.port-value {
  font-family: monospace;
  font-size: 13px;
}

.chip-value.zero-cost {
  color: #10b981;
}

.status-indicator-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #64748b;
  margin-right: 6px;
}

.status-indicator-dot.running {
  background: #10b981;
  box-shadow: 0 0 8px #10b981;
}

.proxy-tabs {
  margin-top: 20px;
  width: 100%;
}

.section-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
}

.nodes-section-header {
  margin-top: 28px;
  padding-top: 18px;
  border-top: 1px dashed rgba(255, 255, 255, 0.08);
}

.heading-left {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
}

.heading-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--n-text-color-1);
}

.heading-desc {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-left: 10px;
}

.heading-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.node-search-input {
  width: 220px;
}

.test-all-btn {
  font-weight: 600;
}

/* Proxy Group Cards */
.groups-grid {
  width: 100%;
}

.group-card {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 14px 16px;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.group-card:hover {
  background: rgba(255, 255, 255, 0.05);
  border-color: rgba(255, 255, 255, 0.16);
  transform: translateY(-2px);
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
}

.group-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.group-header-left {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  flex: 1;
}

.group-icon {
  font-size: 16px;
}

.group-name {
  font-weight: 700;
  font-size: 14px;
  color: var(--n-text-color-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.group-type-badge {
  font-size: 11px;
}

.group-card-current {
  display: flex;
  align-items: center;
  font-size: 12px;
}

.now-label {
  color: var(--n-text-color-3);
  margin-right: 6px;
  flex-shrink: 0;
}

.now-pill {
  display: inline-flex;
  align-items: center;
  background: rgba(16, 185, 129, 0.08);
  border: 1px solid rgba(16, 185, 129, 0.2);
  border-radius: 6px;
  padding: 2px 8px;
  min-width: 0;
  max-width: 100%;
}

.active-node-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #10b981;
  margin-right: 6px;
  flex-shrink: 0;
}

.now-value {
  font-weight: 600;
  color: #10b981;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-selector {
  width: 100%;
}

/* Node Pool Cards */
.nodes-grid {
  width: 100%;
}

.node-card {
  background: rgba(255, 255, 255, 0.025);
  border: 1px solid rgba(255, 255, 255, 0.07);
  border-radius: 10px;
  padding: 12px 14px;
  transition: all 0.15s ease;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.node-card:hover {
  background: rgba(255, 255, 255, 0.055);
  border-color: rgba(255, 255, 255, 0.15);
  transform: translateY(-1px);
}

.node-top-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.node-flag {
  font-size: 15px;
  flex-shrink: 0;
}

.node-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color-1);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-bottom-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.node-proto-tag {
  font-family: monospace;
  font-size: 10px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  background: rgba(255, 255, 255, 0.06);
  color: var(--n-text-color-2);
}

.node-delay-wrapper {
  display: flex;
  align-items: center;
  gap: 4px;
}

.node-delay-tag {
  font-weight: 700;
  font-size: 11px;
}

.test-single-btn {
  color: var(--n-text-color-3);
}

.test-single-btn:hover {
  color: var(--primary-color);
}

/* Subscriptions & Settings */
.subscriptions-pane {
  padding-top: 6px;
}

.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.toolbar-title {
  font-size: 16px;
  font-weight: 700;
}

.subs-table {
  border-radius: 10px;
  overflow: hidden;
}

.empty-subs-cell {
  text-align: center;
  color: var(--n-text-color-3);
  padding: 32px;
}

.settings-pane {
  max-width: 720px;
  margin-top: 8px;
}

.settings-card {
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
}

.settings-card-title {
  font-weight: 700;
  font-size: 15px;
}

.empty-placeholder {
  padding: 80px 0;
  text-align: center;
}
</style>
