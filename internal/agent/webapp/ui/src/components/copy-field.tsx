import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/clipboard";
import { useMessages } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function CopyField({ value, className }: { value: string; className?: string }) {
  const messages = useMessages();
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    const ok = await copyText(value);
    if (!ok) return;
    setCopied(true);
    toast.success(messages.common.copied);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className={cn("flex items-start gap-2", className)}>
      <code className="mono-value min-w-0 flex-1">{value}</code>
      <Button
        type="button"
        variant="outline"
        size="icon"
        className="size-9 shrink-0"
        onClick={() => void onCopy()}
        aria-label={messages.common.copy}
        title={messages.common.copy}
      >
        {copied ? <Check className="text-success" aria-hidden /> : <Copy aria-hidden />}
      </Button>
    </div>
  );
}
