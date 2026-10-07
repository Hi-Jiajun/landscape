<script lang="ts" setup>
import { getFlowRuleByFlowId } from "@landscape-router/types/api/flow-rules/flow-rules";
import type { FlowConfig } from "@landscape-router/types/api/schemas";
import { onMounted, ref, watch, watchEffect } from "vue";
import { Docker, NetworkWired } from "@vicons/fa";
import { useFrontEndStore } from "@/stores/front_end_config";
import { useI18n } from "vue-i18n";

const frontEndStore = useFrontEndStore();
const { t } = useI18n();
type Props = {
  flow_id: number;
};

const props = defineProps<Props>();

onMounted(async () => {
  await refresh();
});

watch(
  () => props.flow_id,
  async () => {
    await refresh();
  },
);

const config = ref<FlowConfig>();
async function refresh() {
  config.value = await getFlowRuleByFlowId(props.flow_id);
}
</script>
<template>
  <n-popover v-if="config" trigger="hover">
    <template #trigger>
      <n-flex align="center">
        {{
          config.remark
            ? frontEndStore.MASK_INFO(config.remark)
            : t("common.unnamed")
        }}
        <n-tag
          size="small"
          v-for="each in config.flow_targets"
          :bordered="false"
        >
          {{
            each.target.t === "netns"
              ? frontEndStore.MASK_INFO(each.target.container_name)
              : each.target.t === "local_tproxy"
                ? `TProxy :${each.target.port}`
                : frontEndStore.MASK_INFO(each.target.name)
          }}
          <span v-if="(each.weight ?? 1) !== 1"> ×{{ each.weight ?? 1 }}</span>
          <template #icon>
            <n-icon
              :component="each.target.t === 'netns' ? Docker : NetworkWired"
            />
          </template>
        </n-tag>
      </n-flex>
    </template>
    <FlowConfigCard :show_action="false" :config="config"></FlowConfigCard>
    <!-- <span>{{ config }}</span> -->
  </n-popover>
  <n-flex v-else> {{ t("flow.exhibit.flow_not_found", { flow_id }) }}</n-flex>
</template>
