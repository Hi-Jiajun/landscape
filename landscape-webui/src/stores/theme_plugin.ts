import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { GlobalThemeOverrides } from "naive-ui";

export type ThemeStyle = "default" | "unifi-argon";

const UNIFI_BLUE = "#0066FF";
const UNIFI_BLUE_HOVER = "#2563EB";
const UNIFI_BLUE_PRESSED = "#1D4ED8";
const UNIFI_BG = "#0A0D14";
const UNIFI_CARD_BG = "#101622";
const UNIFI_SIDER_BG = "#0D111A";
const UNIFI_HEADER_BG = "#0D111ACC";
const UNIFI_BORDER = "rgba(255, 255, 255, 0.08)";

export const unifiArgonThemeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: UNIFI_BLUE,
    primaryColorHover: UNIFI_BLUE_HOVER,
    primaryColorPressed: UNIFI_BLUE_PRESSED,
    primaryColorSuppl: UNIFI_BLUE,
    bodyColor: UNIFI_BG,
    cardColor: UNIFI_CARD_BG,
    modalColor: UNIFI_CARD_BG,
    popoverColor: "#141B2D",
    tableColor: UNIFI_CARD_BG,
    borderColor: UNIFI_BORDER,
    borderRadius: "10px",
    borderRadiusSmall: "6px",
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    fontWeightStrong: "600",
  },
  Layout: {
    color: UNIFI_BG,
    siderColor: UNIFI_SIDER_BG,
    headerColor: UNIFI_HEADER_BG,
  },
  Card: {
    color: UNIFI_CARD_BG,
    borderColor: UNIFI_BORDER,
    borderRadius: "10px",
  },
  Menu: {
    itemColorActive: "rgba(0, 102, 255, 0.12)",
    itemColorHover: "rgba(255, 255, 255, 0.04)",
    itemTextColorActive: UNIFI_BLUE,
    borderRadius: "8px",
  },
  Tag: {
    borderRadius: "6px",
  },
  Button: {
    borderRadiusMedium: "8px",
    borderRadiusSmall: "6px",
  },
};

export const useThemePluginStore = defineStore("theme_plugin", () => {
  const currentStyle = ref<ThemeStyle>(
    (localStorage.getItem("landscape_theme_style") as ThemeStyle) || "unifi-argon",
  );

  function setStyle(style: ThemeStyle) {
    currentStyle.value = style;
    localStorage.setItem("landscape_theme_style", style);
    applyBodyClass();
  }

  function applyBodyClass() {
    if (currentStyle.value === "unifi-argon") {
      document.documentElement.classList.add("theme-unifi-argon");
    } else {
      document.documentElement.classList.remove("theme-unifi-argon");
    }
  }

  const activeThemeOverrides = computed<GlobalThemeOverrides>(() => {
    if (currentStyle.value === "unifi-argon") {
      return unifiArgonThemeOverrides;
    }
    return { common: { fontWeightStrong: "600" } };
  });

  return {
    currentStyle,
    setStyle,
    applyBodyClass,
    activeThemeOverrides,
  };
});
