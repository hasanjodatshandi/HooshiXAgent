import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useMessages } from "@/lib/i18n";
import { useUi } from "@/stores/ui";

export function ThemeToggle() {
  const messages = useMessages();
  const theme = useUi((state) => state.theme);
  const toggleTheme = useUi((state) => state.toggleTheme);
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={toggleTheme}
      aria-label={messages.common.theme}
      title={`${messages.common.theme}: ${theme === "dark" ? messages.common.dark : messages.common.light}`}
    >
      {theme === "dark" ? <Sun aria-hidden /> : <Moon aria-hidden />}
    </Button>
  );
}
