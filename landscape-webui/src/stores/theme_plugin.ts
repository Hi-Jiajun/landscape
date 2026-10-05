import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { GlobalThemeOverrides } from "naive-ui";

export type ThemeStyle = "default" | "beam";

// Beam Cyber Azure & Indigo Color Palette
const BEAM_PRIMARY = "#0EA5E9"; // Cyan 500
const BEAM_PRIMARY_HOVER = "#38BDF8"; // Cyan 400
const BEAM_PRIMARY_PRESSED = "#0284C7"; // Cyan 600
const BEAM_BG = "#07090E";
const BEAM_CARD_BG = "#0F172A";
const BEAM_SIDER_BG = "#0A0E17";
const BEAM_HEADER_BG = "#0A0E17CC";
const BEAM_BORDER = "rgba(255, 255, 255, 0.08)";

export const beamThemeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: BEAM_PRIMARY,
    primaryColorHover: BEAM_PRIMARY_HOVER,
    primaryColorPressed: BEAM_PRIMARY_PRESSED,
    primaryColorSuppl: BEAM_PRIMARY,
    bodyColor: BEAM_BG,
    cardColor: BEAM_CARD_BG,
    modalColor: BEAM_CARD_BG,
    popoverColor: "#131C31",
    tableColor: BEAM_CARD_BG,
    borderColor: BEAM_BORDER,
    borderRadius: "12px",
    borderRadiusSmall: "8px",
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    fontWeightStrong: "600",
  },
  Layout: {
    color: BEAM_BG,
    siderColor: BEAM_SIDER_BG,
    headerColor: BEAM_HEADER_BG,
  },
  Card: {
    color: BEAM_CARD_BG,
    borderColor: BEAM_BORDER,
    borderRadius: "14px",
  },
  Menu: {
    itemColorActive: "rgba(14, 165, 233, 0.15)",
    itemColorHover: "rgba(255, 255, 255, 0.04)",
    itemTextColorActive: BEAM_PRIMARY,
    borderRadius: "10px",
  },
  Tag: {
    borderRadius: "8px",
  },
  Button: {
    borderRadiusMedium: "9px",
    borderRadiusSmall: "7px",
  },
};

export const useThemePluginStore = defineStore("theme_plugin", () => {
  const currentStyle = ref<ThemeStyle>(
    (localStorage.getItem("landscape_theme_style_v2") as ThemeStyle) || "default",
  );

  function setStyle(style: ThemeStyle) {
    currentStyle.value = style;
    localStorage.setItem("landscape_theme_style_v2", style);
    applyBodyClass();
  }

  function applyBodyClass() {
    if (currentStyle.value === "beam") {
      document.documentElement.classList.add("theme-beam");
    } else {
      document.documentElement.classList.remove("theme-beam");
    }
  }

  const activeThemeOverrides = computed<GlobalThemeOverrides>(() => {
    if (currentStyle.value === "beam") {
      return beamThemeOverrides;
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
