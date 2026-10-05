<script setup lang="ts">
import { computed, h } from "vue";
import { NButton, NDropdown, NIcon } from "naive-ui";
import { ColorPaletteOutline, CheckmarkOutline } from "@vicons/ionicons5";
import { useThemePluginStore, type ThemeStyle } from "@/stores/theme_plugin";

const themePlugin = useThemePluginStore();

const options = computed(() => [
  {
    label: "Beam (现代流光布局)",
    key: "beam",
    icon: themePlugin.currentStyle === "beam" ? () => h(NIcon, null, { default: () => h(CheckmarkOutline) }) : undefined,
  },
  {
    label: "Landscape 原生经典",
    key: "default",
    icon: themePlugin.currentStyle === "default" ? () => h(NIcon, null, { default: () => h(CheckmarkOutline) }) : undefined,
  },
]);

function handleSelect(key: string) {
  themePlugin.setStyle(key as ThemeStyle);
}
</script>

<template>
  <n-dropdown :options="options" @select="handleSelect" trigger="click">
    <n-button quaternary circle size="small" title="主题与布局切换">
      <template #icon>
        <n-icon :size="16">
          <ColorPaletteOutline />
        </n-icon>
      </template>
    </n-button>
  </n-dropdown>
</template>
