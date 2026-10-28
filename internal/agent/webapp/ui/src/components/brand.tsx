import { ShieldCheck } from "lucide-react";
import { useMessages } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function Brand({ compact = false, className }: { compact?: boolean; className?: string }) {
  const messages = useMessages();
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="brand-gradient grid size-10 shrink-0 place-items-center rounded-xl text-white shadow-glow">
        <ShieldCheck className="size-5" aria-hidden />
      </div>
      <div className="min-w-0 leading-tight">
        <div className="flex items-baseline gap-1.5">
          <span className="text-base font-bold tracking-tight">{messages.brand.name}</span>
          {!compact ? (
            <span className="truncate text-xs font-medium text-muted-foreground">
              {messages.brand.product}
            </span>
          ) : null}
        </div>
        {!compact ? (
          <p className="truncate text-[11px] text-muted-foreground">{messages.brand.tagline}</p>
        ) : null}
      </div>
    </div>
  );
}
