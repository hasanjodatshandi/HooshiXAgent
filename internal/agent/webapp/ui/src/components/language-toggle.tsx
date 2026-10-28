import { Languages } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useMessages } from "@/lib/i18n";
import { useUi } from "@/stores/ui";

export function LanguageToggle() {
  const messages = useMessages();
  const language = useUi((state) => state.language);
  const toggleLanguage = useUi((state) => state.toggleLanguage);
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      onClick={toggleLanguage}
      aria-label={messages.common.language}
      title={messages.common.language}
      className="gap-1.5 px-2.5"
    >
      <Languages aria-hidden />
      <span className="text-xs font-semibold">{language === "fa" ? "EN" : "فا"}</span>
    </Button>
  );
}
