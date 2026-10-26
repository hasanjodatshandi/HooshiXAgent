import type * as React from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { StatusTone } from "@/lib/status";

const dotTone: Record<StatusTone, string> = {
  default: "bg-primary",
  success: "bg-success",
  warning: "bg-warning",
  destructive: "bg-destructive",
  outline: "bg-muted-foreground/60",
};

const badgeTone: Record<StatusTone, "default" | "success" | "warning" | "destructive" | "outline"> = {
  default: "default",
  success: "success",
  warning: "warning",
  destructive: "destructive",
  outline: "outline",
};

export function StatusBadge({
  tone,
  children,
  pulse = false,
  className,
}: {
  tone: StatusTone;
  children: React.ReactNode;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <Badge variant={badgeTone[tone]} className={cn("gap-1.5 whitespace-nowrap", className)}>
      <span
        aria-hidden
        className={cn("size-1.5 rounded-full", dotTone[tone], pulse && "animate-pulse")}
      />
      {children}
    </Badge>
  );
}
