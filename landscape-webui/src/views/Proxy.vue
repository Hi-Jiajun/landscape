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
</script>

<template>
  <div class="proxy-page-container">
    <!-- Top Hero Header Card -->
    <n-card class="proxy-hero-card" :bordered="false">
      <div class="hero-content">
        <div class="hero-left">
          <div class="hero-title-row">
            <n-icon size="28" color="var(--primary-color)" style="margin-right: 10px;">
              <Rocket />
            </n-icon>
            <h2 class="hero-title">出站代理插件</h2>
            <n-tag
              :type="isRunning ? 'success' : status?.status.t === 'staring' ? 'warning' : 'default'"
              round
              size="small"
              style="margin-left: 12px; font-weight: 600;"
            >
              {{ isRunning ? "运行中" : status?.status.t === "staring" ? "启动中" : "已停止 (零资源占用)" }}
            </n-tag>
          </div>
          <p class="hero-subtitle">
            基于原生内核守护的零虚拟化透明代理与协议出站系统，支持 eBPF Flow 智能分流与按需冷启动。
          </p>
        </div>

        <div class="hero-right">
          <n-flex align="center">
            <span style="font-size: 13px; font-weight: 600; color: var(--n-text-color-2); margin-right: 4px;">
              插件总开关
            </span>
            <n-switch
              size="large"
              :value="config?.enable ?? false"
              @update:value="handleToggle"
              :loading="loading"
            />
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
          </n-flex>
        </div>
      </div>

      <!-- Quick Metrics Grid -->
      <div class="metrics-row">
        <div class="metric-chip">
          <span class="chip-label">核心内存占用</span>
          <span class="chip-value" :class="{ 'zero-cost': !isRunning }">
            {{ formatMemory(status?.memory_bytes) }}
          </span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">受管 PID</span>
          <span class="chip-value">{{ status?.pid ?? '--' }}</span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">TProxy / Mixed 端口</span>
          <span class="chip-value">{{ status?.tproxy_port ?? 17890 }} / {{ status?.mixed_port ?? 7890 }}</span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">可用节点数</span>
          <span class="chip-value">{{ nodes.length }} 节点</span>
        </div>
        <div class="metric-chip">
          <span class="chip-label">持续运行</span>
          <span class="chip-value">{{ formatUptime(status?.uptime_seconds) }}</span>
        </div>
      </div>
    </n-card>

    <!-- Navigation Tabs -->
    <n-tabs v-model:value="activeTab" type="line" size="large" style="margin-top: 16px;">
      <!-- Tab 1: Groups & Proxies -->
      <n-tab-pane name="groups" tab="策略组与节点">
        <div v-if="!isRunning" class="empty-placeholder">
          <n-empty description="代理服务当前处于停止状态（0 进程、0 内存）。开启总开关后即可拉起核心引擎。">
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
            <span class="heading-title">出站策略组 (Proxy Groups)</span>
            <span class="heading-desc">点击可在对应分组下即时切换当前出口节点</span>
          </div>

          <n-grid cols="1 s:2 m:3 l:4" :x-gap="12" :y-gap="12" style="margin-bottom: 24px;">
            <n-grid-item v-for="grp in groups" :key="grp.name">
              <n-card size="small" class="group-card" :bordered="true">
                <div class="group-header">
                  <span class="group-name">{{ grp.name }}</span>
                  <n-tag size="tiny" round :bordered="false">{{ grp.group_type }}</n-tag>
                </div>
                <div class="group-current-row">
                  <span class="now-label">当前出口:</span>
                  <span class="now-value">{{ grp.now || '--' }}</span>
                </div>
                <div class="group-options-select">
                  <n-select
                    size="small"
                    :value="grp.now"
                    :options="grp.all.map((item) => ({ label: item, value: item }))"
                    @update:value="handleSelectNode(grp.name, $event)"
                    placeholder="选择出口节点"
                  />
                </div>
              </n-card>
            </n-grid-item>
          </n-grid>

          <!-- Nodes Section -->
          <div class="section-heading" style="margin-top: 16px;">
            <div class="heading-left">
              <span class="heading-title">节点池与实时测速</span>
              <span class="heading-desc">共加载 {{ nodes.length }} 个节点</span>
            </div>
            <div class="heading-actions">
              <n-input
                v-model:value="nodeSearch"
                placeholder="搜索节点或协议..."
                clearable
                size="small"
                style="width: 200px; margin-right: 10px;"
              />
              <n-button
                type="primary"
                secondary
                size="small"
                :loading="testingAll"
                @click="handleTestAllDelays"
              >
                <template #icon>
                  <n-icon><Flash /></n-icon>
                </template>
                ⚡ 全部测速
              </n-button>
            </div>
          </div>

          <!-- Nodes Cards Grid -->
          <n-grid cols="1 s:2 m:3 l:4 xl:5" :x-gap="10" :y-gap="10" style="margin-top: 10px;">
            <n-grid-item v-for="node in filteredNodes" :key="node.name">
              <n-card size="small" class="node-card" :bordered="true">
                <div class="node-top-row">
                  <span class="node-name" :title="node.name">{{ node.name }}</span>
                </div>
                <div class="node-bottom-row">
                  <n-tag size="tiny" :bordered="false" class="type-tag">{{ node.node_type }}</n-tag>
                  <div class="node-delay-action">
                    <n-tag
                      size="tiny"
                      round
                      :type="getDelayType(node.delay)"
                      style="font-weight: 600;"
                    >
                      {{ node.delay && node.delay > 0 ? node.delay + ' ms' : '超时 / 未测' }}
                    </n-tag>
                    <n-button
                      quaternary
                      circle
                      size="tiny"
                      style="margin-left: 6px;"
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
              </n-card>
            </n-grid-item>
          </n-grid>
        </div>
      </n-tab-pane>

      <!-- Tab 2: Subscriptions -->
      <n-tab-pane name="subscriptions" tab="订阅管理">
        <div class="subscriptions-pane">
          <div class="table-toolbar">
            <span class="toolbar-title">受管订阅列表 ({{ subscriptions.length }})</span>
            <n-button type="primary" size="small" @click="showAddModal = true">
              <template #icon>
                <n-icon><Add /></n-icon>
              </template>
              添加新订阅
            </n-button>
          </div>

          <n-table :bordered="true" :single-line="false" size="small" style="margin-top: 12px;">
            <thead>
              <tr>
                <th style="width: 25%;">订阅名称</th>
                <th style="width: 40%;">订阅链接 (URL)</th>
                <th style="width: 10%;">节点数</th>
                <th style="width: 15%;">状态</th>
                <th style="width: 10%;">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="subscriptions.length === 0">
                <td colspan="5" style="text-align: center; color: var(--n-text-color-3); padding: 24px;">
                  暂无订阅配置，点击上方「添加新订阅」快速导入机场订阅链接
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
        <div v-if="config" class="settings-pane" style="max-width: 680px; margin-top: 10px;">
          <n-form label-placement="left" label-width="160" size="medium">
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
            <n-form-item label="Controller API 端口">
              <n-input-number
                v-model:value="config.api_port"
                :min="1"
                :max="65535"
                placeholder="默认 19091"
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

            <div style="margin-top: 20px;">
              <n-button type="primary" size="medium" :loading="loading" @click="handleSaveConfig">
                保存并生效配置
              </n-button>
            </div>
          </n-form>
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
  padding: 16px 20px;
}

.proxy-hero-card {
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0.02) 100%);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
}

.hero-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.hero-title-row {
  display: flex;
  align-items: center;
}

.hero-title {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.5px;
}

.hero-subtitle {
  margin: 6px 0 0 0;
  font-size: 13px;
  color: var(--n-text-color-3);
}

.metrics-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 18px;
  padding-top: 14px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}

.metric-chip {
  display: flex;
  flex-direction: column;
  padding: 8px 14px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 8px;
  min-width: 110px;
}

.chip-label {
  font-size: 11px;
  color: var(--n-text-color-3);
  margin-bottom: 2px;
}

.chip-value {
  font-size: 14px;
  font-weight: 700;
  color: var(--n-text-color-1);
}

.chip-value.zero-cost {
  color: #10b981;
}

.section-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.heading-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--n-text-color-1);
}

.heading-desc {
  font-size: 12px;
  color: var(--n-text-color-3);
  margin-left: 10px;
}

.group-card {
  border-radius: 10px;
  transition: all 0.2s ease;
}

.group-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.group-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.group-name {
  font-weight: 700;
  font-size: 14px;
}

.group-current-row {
  display: flex;
  font-size: 12px;
  margin-bottom: 8px;
  color: var(--n-text-color-2);
}

.now-label {
  color: var(--n-text-color-3);
  margin-right: 6px;
}

.now-value {
  font-weight: 600;
  color: var(--primary-color);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.node-card {
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.02);
  transition: all 0.15s ease;
}

.node-card:hover {
  background: rgba(255, 255, 255, 0.05);
}

.node-top-row {
  margin-bottom: 6px;
}

.node-name {
  font-size: 13px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: block;
}

.node-bottom-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.type-tag {
  font-family: monospace;
  font-size: 10px;
}

.node-delay-action {
  display: flex;
  align-items: center;
}

.table-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.toolbar-title {
  font-size: 15px;
  font-weight: 700;
}

.empty-placeholder {
  padding: 60px 0;
  text-align: center;
}
</style>
