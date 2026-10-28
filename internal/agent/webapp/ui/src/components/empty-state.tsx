import type * as React from "react";
import { cn } from "@/lib/utils";

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/80 bg-muted/20 px-6 py-10 text-center",
        className,
      )}
    >
      <span className="grid size-12 place-items-center rounded-2xl bg-muted text-muted-foreground">
        {icon}
      </span>
      <div className="space-y-1">
        <p className="font-semibold">{title}</p>
        {description ? (
          <p className="max-w-sm text-sm leading-6 text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}
