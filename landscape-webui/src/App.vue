<script setup lang="ts">
import { darkTheme, enUS, zhCN, dateZhCN, dateEnUS } from "naive-ui";
import { computed, onMounted } from "vue";
import { usePreferenceStore } from "@/stores/preference";
import { useThemePluginStore } from "@/stores/theme_plugin";
import "@/styles/beam.css";
import Env from "@/components/Env.vue";

const prefStore = usePreferenceStore();
const themePlugin = useThemePluginStore();

onMounted(() => {
  prefStore.loadPreference();
  themePlugin.applyBodyClass();
});

const currentLocale = computed(() => {
  return prefStore.language?.startsWith("en") ? enUS : zhCN;
});

const currentDateLocale = computed(() => {
  return prefStore.language?.startsWith("en") ? dateEnUS : dateZhCN;
});

const currentTheme = computed(() => {
  return prefStore.theme === "light" ? null : darkTheme;
});
</script>

<template>
  <n-config-provider
    :locale="currentLocale"
    :date-locale="currentDateLocale"
    :theme="currentTheme"
    style="display: flex; flex: 1"
    :theme-overrides="themePlugin.activeThemeOverrides"
  >
    <n-message-provider>
      <n-notification-provider>
        <n-dialog-provider>
          <Env></Env>
          <RouterView />
        </n-dialog-provider>
      </n-notification-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<style>
/* .main-body {
  align-items: center;
  width: 100%;
  display: flex;
  justify-items: center;
} */
</style>
