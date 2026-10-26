import type { Language } from "@/stores/ui";

export function formatDateTime(value: string | undefined, language: Language): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(language === "fa" ? "fa-IR" : "en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatNumber(value: number, language: Language): string {
  return new Intl.NumberFormat(language === "fa" ? "fa-IR" : "en-US").format(value);
}

export function formatRemaining(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.ceil(milliseconds / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}
