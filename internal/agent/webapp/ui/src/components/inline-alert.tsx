import type * as React from "react";
import { AlertTriangle, CheckCircle2, CircleAlert, Info } from "lucide-react";
import { cn } from "@/lib/utils";

type AlertVariant = "info" | "success" | "warning" | "destructive";

const styles: Record<AlertVariant, { box: string; icon: React.ReactNode }> = {
  info: {
    box: "border-primary/25 bg-primary/5 text-foreground",
    icon: <Info className="size-4 text-primary" aria-hidden />,
  },
  success: {
    box: "border-success/30 bg-success/5 text-foreground",
    icon: <CheckCircle2 className="size-4 text-success" aria-hidden />,
  },
  warning: {
    box: "border-warning/35 bg-warning/10 text-foreground",
    icon: <AlertTriangle className="size-4 text-warning-foreground dark:text-warning" aria-hidden />,
  },
  destructive: {
    box: "border-destructive/30 bg-destructive/5 text-foreground",
    icon: <CircleAlert className="size-4 text-destructive" aria-hidden />,
  },
};

export function InlineAlert({
  variant = "info",
  title,
  children,
  className,
}: {
  variant?: AlertVariant;
  title?: string;
  children?: React.ReactNode;
  className?: string;
}) {
  const style = styles[variant];
  return (
    <div
      role={variant === "destructive" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-xl border px-4 py-3 text-sm", style.box, className)}
    >
      <span className="mt-0.5 shrink-0">{style.icon}</span>
      <div className="min-w-0 space-y-1">
        {title ? <p className="font-semibold leading-5">{title}</p> : null}
        {children ? <div className="text-sm leading-6 text-muted-foreground">{children}</div> : null}
      </div>
    </div>
  );
}
