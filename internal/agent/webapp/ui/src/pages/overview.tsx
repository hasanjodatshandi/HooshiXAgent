import type { ReactNode } from "react";
import { Activity, Clock, Lock, PlugZap, RefreshCw, Server, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState } from "@/components/empty-state";
import { InlineAlert } from "@/components/inline-alert";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useMessages } from "@/lib/i18n";
import { formatDateTime, formatNumber } from "@/lib/format";
import { connectionView, type StatusTone } from "@/lib/status";
import { useAgentData } from "@/stores/agent";
import { useUi } from "@/stores/ui";

function statTone(tone: StatusTone): "primary" | "success" | "warning" | "destructive" | "muted" {
  switch (tone) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "destructive":
      return "destructive";
    case "outline":
      return "muted";
    default:
      return "primary";
  }
}

function SummaryRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 sm:max-w-[70%]">{children}</dd>
    </div>
  );
}

export function OverviewPage() {
  const data = useAgentData();
  const messages = useMessages();
  const language = useUi((state) => state.language);

  const endpoints = data.config.endpoints ?? [];
  const connection = connectionView(
    { paired: data.paired, pending: Boolean(data.pending), tunnel: data.tunnel },
    messages,
  );
  const caFile = data.config.ca_file?.trim() ?? "";
  const trustLabel = caFile ? messages.overview.configuredCA : messages.overview.systemTrust;
  const trustShort = caFile
    ? messages.overview.configuredCAShort
    : messages.overview.systemTrustShort;
  const pending = Boolean(data.pending);

  return (
    <div className="space-y-6">
      <PageHeader title={messages.overview.title} description={messages.overview.description} />

      <Card className="relative overflow-hidden">
        <div aria-hidden className="page-grid pointer-events-none absolute inset-0 opacity-60" />
        <CardContent className="relative flex flex-col gap-6 p-6 sm:p-8 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-start gap-4">
            <span className="brand-gradient grid size-14 shrink-0 place-items-center rounded-2xl text-white shadow-glow">
              {data.paired ? (
                <ShieldCheck className="size-7" aria-hidden />
              ) : pending ? (
                <Clock className="size-7" aria-hidden />
              ) : (
                <PlugZap className="size-7" aria-hidden />
              )}
            </span>
            <div className="min-w-0 space-y-2">
              <StatusBadge tone={connection.tone} pulse={connection.tone === "success"}>
                {connection.label}
              </StatusBadge>
              <h2 className="text-xl font-bold tracking-tight sm:text-2xl">
                {data.paired
                  ? messages.overview.heroPairedTitle
                  : pending
                    ? messages.overview.heroPendingTitle
                    : messages.overview.heroUnpairedTitle}
              </h2>
              <p className="max-w-xl text-sm leading-6 text-muted-foreground">
                {data.paired
                  ? messages.overview.heroPairedBody
                  : pending
                    ? messages.overview.heroPendingBody
                    : messages.overview.heroUnpairedBody}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {data.paired ? (
              <>
                <Button asChild>
                  <Link to="/services">{messages.overview.manageServices}</Link>
                </Button>
                <Button variant="outline" asChild>
                  <Link to="/device">{messages.overview.deviceSettings}</Link>
                </Button>
              </>
            ) : (
              <Button asChild>
                <Link to="/connect">
                  {pending ? messages.overview.viewCode : messages.overview.connectNow}
                </Link>
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<Activity className="size-5" aria-hidden />}
          label={messages.overview.statsTunnel}
          value={connection.label}
          hint={data.paired && data.tunnel.phase !== "unknown" ? data.tunnel.phase : undefined}
          tone={statTone(connection.tone)}
        />
        <StatCard
          icon={<RefreshCw className="size-5" aria-hidden />}
          label={messages.overview.statsReconnects}
          value={formatNumber(data.tunnel.reconnects, language)}
          hint={messages.overview.tunnelTitle}
          tone="primary"
        />
        <StatCard
          icon={<Server className="size-5" aria-hidden />}
          label={messages.overview.statsServices}
          value={formatNumber(endpoints.length, language)}
          hint={messages.services.listTitle}
          tone={endpoints.length > 0 ? "success" : "muted"}
        />
        <StatCard
          icon={<Lock className="size-5" aria-hidden />}
          label={messages.overview.statsTrust}
          value={trustShort}
          hint={caFile || data.config.gateway_url || undefined}
          tone="muted"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="size-4 text-primary" aria-hidden />
              {messages.overview.tunnelTitle}
            </CardTitle>
            <CardDescription>{messages.overview.tunnelDesc}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-sm text-muted-foreground">{messages.common.status}</span>
              <StatusBadge tone={connection.tone} pulse={connection.tone === "success"}>
                {connection.label}
              </StatusBadge>
            </div>
            <Separator />
            <SummaryRow label={messages.overview.lastUpdate}>
              <span className="text-sm font-medium">
                {formatDateTime(data.tunnel.last_update_at, language)}
              </span>
            </SummaryRow>
            <SummaryRow label={messages.overview.statsReconnects}>
              <span className="text-sm font-medium">
                {formatNumber(data.tunnel.reconnects, language)}
              </span>
            </SummaryRow>
            {data.tunnel.last_error ? (
              <InlineAlert variant="destructive" title={messages.overview.lastError}>
                <p className="mono-value mt-1" dir="ltr">
                  {data.tunnel.last_error}
                </p>
              </InlineAlert>
            ) : (
              <p className="text-sm text-muted-foreground">{messages.overview.noError}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-primary" aria-hidden />
              {messages.overview.deviceTitle}
            </CardTitle>
            <CardDescription>{messages.overview.deviceDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-4">
              <SummaryRow label={messages.overview.gateway}>
                {data.config.gateway_url ? (
                  <span className="mono-value inline-block">{data.config.gateway_url}</span>
                ) : (
                  <span className="text-sm text-muted-foreground">{messages.overview.notPaired}</span>
                )}
              </SummaryRow>
              <SummaryRow label={messages.overview.deviceId}>
                {data.config.device_id ? (
                  <span className="mono-value inline-block">{data.config.device_id}</span>
                ) : (
                  <span className="text-sm text-muted-foreground">{messages.overview.notPaired}</span>
                )}
              </SummaryRow>
              <SummaryRow label={messages.overview.trustAnchor}>
                <span className="text-sm font-medium">{trustLabel}</span>
                {caFile ? <p className="mono-value mt-1">{caFile}</p> : null}
              </SummaryRow>
            </dl>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Server className="size-4 text-primary" aria-hidden />
              {messages.overview.servicesTitle}
            </CardTitle>
            <CardDescription>{messages.overview.servicesDesc}</CardDescription>
          </div>
          <Link
            to="/services"
            className="shrink-0 text-sm font-medium text-primary underline-offset-4 hover:underline"
          >
            {messages.overview.openServices}
          </Link>
        </CardHeader>
        <CardContent>
          {endpoints.length === 0 ? (
            <EmptyState
              icon={<Server className="size-5" aria-hidden />}
              title={messages.overview.noServices}
              description={messages.services.emptyDesc}
            />
          ) : (
            <div className="divide-y divide-border/70">
              {endpoints.map((endpoint) => (
                <div
                  key={endpoint.id}
                  className="flex flex-col gap-1.5 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold">{endpoint.id}</span>
                    <StatusBadge tone="outline">
                      {(endpoint.protocol || "tcp").toUpperCase()}
                    </StatusBadge>
                  </div>
                  <span className="mono-value inline-block text-xs">{endpoint.target}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
        {endpoints.length > 0 ? (
          <CardFooter className="pt-0">
            <Button variant="outline" size="sm" asChild>
              <Link to="/services">{messages.overview.manageServices}</Link>
            </Button>
          </CardFooter>
        ) : null}
      </Card>
    </div>
  );
}
