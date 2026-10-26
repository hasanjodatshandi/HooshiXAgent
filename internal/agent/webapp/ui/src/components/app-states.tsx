import { Loader2, Lock, RefreshCw } from "lucide-react";
import { Brand } from "@/components/brand";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useMessages } from "@/lib/i18n";

export function AppLoading() {
  const messages = useMessages();
  return (
    <div className="grid min-h-dvh place-items-center px-4">
      <div className="flex flex-col items-center gap-4">
        <Brand />
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {messages.common.loading}
        </div>
      </div>
    </div>
  );
}

export function UnauthorizedScreen() {
  const messages = useMessages();
  return (
    <div className="relative grid min-h-dvh place-items-center overflow-hidden px-4 py-10">
      <div aria-hidden className="page-grid pointer-events-none absolute inset-0 opacity-50" />
      <Card className="relative w-full max-w-md">
        <CardContent className="flex flex-col items-center gap-4 p-8 text-center">
          <span className="grid size-14 place-items-center rounded-2xl bg-destructive/10 text-destructive">
            <Lock className="size-7" aria-hidden />
          </span>
          <div className="space-y-2">
            <h1 className="text-xl font-bold tracking-tight">{messages.errors.unauthorizedTitle}</h1>
            <p className="text-sm leading-6 text-muted-foreground">
              {messages.errors.unauthorizedBody}
            </p>
          </div>
          <Button onClick={() => window.location.reload()}>
            <RefreshCw aria-hidden />
            {messages.errors.reload}
          </Button>
          <p className="text-xs text-muted-foreground">{messages.brand.localOnly}</p>
        </CardContent>
      </Card>
    </div>
  );
}

export function LoadErrorScreen({ onRetry }: { onRetry: () => void }) {
  const messages = useMessages();
  return (
    <div className="grid min-h-dvh place-items-center px-4 py-10">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center gap-4 p-8 text-center">
          <Brand />
          <p className="text-sm text-muted-foreground">{messages.errors.loadFailed}</p>
          <Button variant="outline" onClick={onRetry}>
            <RefreshCw aria-hidden />
            {messages.common.retry}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
