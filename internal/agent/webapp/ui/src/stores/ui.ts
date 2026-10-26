import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Language = "fa" | "en";
export type Theme = "light" | "dark";

interface UiState {
  language: Language;
  theme: Theme;
  setLanguage: (language: Language) => void;
  toggleLanguage: () => void;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
}

function systemTheme(): Theme {
  if (typeof window === "undefined") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyAppearance(language: Language, theme: Theme): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.lang = language;
  root.dir = language === "fa" ? "rtl" : "ltr";
  root.classList.toggle("dark", theme === "dark");
}

export const useUi = create<UiState>()(
  persist(
    (set) => ({
      language: "fa",
      theme: systemTheme(),
      setLanguage: (language) => {
        set({ language });
        applyAppearance(language, useUi.getState().theme);
      },
      toggleLanguage: () => {
        const language: Language = useUi.getState().language === "fa" ? "en" : "fa";
        set({ language });
        applyAppearance(language, useUi.getState().theme);
      },
      setTheme: (theme) => {
        set({ theme });
        applyAppearance(useUi.getState().language, theme);
      },
      toggleTheme: () => {
        const theme: Theme = useUi.getState().theme === "dark" ? "light" : "dark";
        set({ theme });
        applyAppearance(useUi.getState().language, theme);
      },
    }),
    {
      name: "hooshix-agent-ui",
      partialize: (state) => ({ language: state.language, theme: state.theme }),
    },
  ),
);
