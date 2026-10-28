import { useEffect, useState, type FormEvent } from "react";
import {
  Check,
  Copy,
  ExternalLink,
  Loader2,
  PlugZap,
  RefreshCw,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { InlineAlert } from "@/components/inline-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import {
  ApiError,
  claimEnrollment,
  replaceCapability,
  startEnrollment,
  type PendingEnrollment,
} from "@/lib/api";
import { copyText } from "@/lib/clipboard";
import { apiErrorMessage } from "@/lib/errors";
import { formatDateTime, formatRemaining } from "@/lib/format";
import { useMessages } from "@/lib/i18n";
import { useAgent, useAgentData } from "@/stores/agent";
import { useUi } from "@/stores/ui";

function safeHttpUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function Summary({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="mono-value inline-block max-w-full text-xs">{value}</span>
    </div>
  );
}

function PairedCard() {
  const data = useAgentData();
  const messages = useMessages();
  const language = useUi((state) => state.language);
  const trust = data.config.ca_file?.trim()
    ? messages.overview.configuredCA
    : messages.overview.systemTrust;

  return (
    <Card className="mx-auto w-full max-w-2xl">
      <CardHeader className="items-start gap-3">
        <span className="grid size-12 place-items-center rounded-2xl bg-success/10 text-success">
          <ShieldCheck className="size-6" aria-hidden />
        </span>
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle>{messages.connect.pairedTitle}</CardTitle>
            <StatusBadge tone="success" pulse>
              {messages.status.paired}
            </StatusBadge>
          </div>
          <CardDescription>{messages.connect.pairedDesc}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="surface-muted space-y-3 p-4">
          <Summary label={messages.connect.gateway} value={data.config.gateway_url || "—"} />
          <Separator />
          <Summary label={messages.connect.deviceId} value={data.config.device_id || "—"} />
          <Separator />
          <Summary label={messages.connect.trustAnchor} value={trust} />
          <Separator />
          <Summary
            label={messages.overview.lastUpdate}
            value={formatDateTime(data.tunnel.last_update_at, language)}
          />
        </div>
        <InlineAlert variant="success">{messages.connect.serviceAutoConnect}</InlineAlert>
        <p className="text-sm text-muted-foreground">{messages.connect.closeNote}</p>
        <Button variant="outline" asChild>
          <Link to="/">{messages.connect.goOverview}</Link>
        </Button>
      </CardContent>
    </Card>
  );
}

function EnrollmentForm() {
  const data = useAgentData();
  const messages = useMessages();
  const refresh = useAgent((state) => state.refresh);
  const [serverUrl, setServerUrl] = useState(() => data.default_panel_url);
  const [deviceName, setDeviceName] = useState(() => data.hostname);
  const [caFile, setCaFile] = useState(() => data.config.ca_file ?? "");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError("");
    try {
      await startEnrollment(
        {
          server_url: serverUrl.trim(),
          device_name: deviceName.trim(),
          ca_file: caFile.trim(),
        },
        data.csrf,
      );
      await refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 409) {
        toast.info(messages.connect.pendingDesc);
        await refresh();
      } else {
        const message = apiErrorMessage(caught, messages);
        setError(message);
        toast.error(message);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="mx-auto w-full max-w-2xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <PlugZap className="size-4 text-primary" aria-hidden />
          {messages.connect.formTitle}
        </CardTitle>
        <CardDescription>{messages.connect.formDesc}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-5" onSubmit={(event) => void onSubmit(event)}>
          <div className="space-y-2">
            <Label htmlFor="server-url">{messages.connect.panelUrl}</Label>
            <Input
              id="server-url"
              name="server_url"
              type="url"
              dir="ltr"
              className="text-start font-mono text-xs"
              value={serverUrl}
              onChange={(event) => setServerUrl(event.target.value)}
              placeholder="https://panel.example.com"
              autoComplete="off"
              spellCheck={false}
              required
            />
            <p className="text-xs leading-5 text-muted-foreground">{messages.connect.panelUrlHint}</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="device-name">{messages.connect.deviceName}</Label>
            <Input
              id="device-name"
              name="device_name"
              value={deviceName}
              onChange={(event) => setDeviceName(event.target.value)}
              autoComplete="off"
              required
            />
            <p className="text-xs leading-5 text-muted-foreground">{messages.connect.deviceNameHint}</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="ca-file">
              {messages.connect.caFile}{" "}
              <span className="font-normal text-muted-foreground">({messages.common.optional})</span>
            </Label>
            <Input
              id="ca-file"
              name="ca_file"
              dir="ltr"
              className="text-start font-mono text-xs"
              value={caFile}
              onChange={(event) => setCaFile(event.target.value)}
              placeholder={messages.connect.caFilePlaceholder}
              autoComplete="off"
              spellCheck={false}
            />
            <p className="text-xs leading-5 text-muted-foreground">{messages.connect.caFileHint}</p>
          </div>
          {error ? <InlineAlert variant="destructive">{error}</InlineAlert> : null}
          <Button type="submit" disabled={submitting} className="w-full sm:w-auto">
            {submitting ? <Loader2 className="animate-spin" aria-hidden /> : null}
            {submitting ? messages.connect.starting : messages.connect.submit}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function PendingCard({ pending, csrf }: { pending: PendingEnrollment; csrf: string }) {
  const messages = useMessages();
  const refresh = useAgent((state) => state.refresh);
  const navigate = useNavigate();
  const [now, setNow] = useState(() => Date.now());
  const [expired, setExpired] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [copied, setCopied] = useState(false);

  const deadline = Date.parse(pending.expires_at);
  const remaining = Number.isNaN(deadline) ? Number.NaN : deadline - now;
  const verificationUrl = safeHttpUrl(pending.verification_uri);

  useEffect(() => {
    if (Number.isNaN(deadline)) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [deadline]);

  useEffect(() => {
    if (expired || Number.isNaN(deadline) || now < deadline) return;
    setExpired(true);
    void refresh();
  }, [deadline, expired, now, refresh]);

  useEffect(() => {
    let cancelled = false;
    let delay = 2000;
    let timer: number | undefined;

    async function poll() {
      if (cancelled) return;
      if (!Number.isNaN(deadline) && Date.now() >= deadline) {
        setExpired(true);
        return;
      }
      try {
        const result = await claimEnrollment(csrf);
        if (cancelled) return;
        if (result.state === "claimed") {
          replaceCapability(result.capability);
          toast.success(messages.connect.claimed);
          const updated = await refresh();
          if (cancelled) return;
          navigate("/", { replace: true });
          if (!updated) toast.error(messages.errors.loadFailed);
          return;
        }
        setRetrying(false);
        delay = 2000;
      } catch (error) {
        if (cancelled) return;
        const status = error instanceof ApiError ? error.status : 0;
        if (status === 404) {
          setExpired(true);
          void refresh();
          return;
        }
        if (status >= 500 || status === 0) {
          setRetrying(true);
          delay = Math.min(delay * 2, 16000);
        } else {
          toast.error(apiErrorMessage(error, messages));
          void refresh();
          return;
        }
      }
      timer = window.setTimeout(() => void poll(), delay);
    }

    timer = window.setTimeout(() => void poll(), 1500);
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [csrf, deadline, messages, navigate, refresh]);

  async function onCopy() {
    if (!(await copyText(pending.user_code))) return;
    setCopied(true);
    toast.success(messages.common.copied);
    window.setTimeout(() => setCopied(false), 1600);
  }

  if (expired) {
    return (
      <Card className="mx-auto w-full max-w-2xl">
        <CardHeader className="items-start gap-3">
          <span className="grid size-12 place-items-center rounded-2xl bg-warning/10 text-warning-foreground dark:text-warning">
            <Timer className="size-6" aria-hidden />
          </span>
          <div className="space-y-1.5">
            <CardTitle>{messages.connect.expiredTitle}</CardTitle>
            <CardDescription>{messages.connect.expiredBody}</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Button onClick={() => void refresh()}>
            <RefreshCw aria-hidden />
            {messages.common.refresh}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="mx-auto w-full max-w-2xl overflow-hidden">
      <CardHeader className="items-start gap-3">
        <span className="grid size-12 place-items-center rounded-2xl bg-primary/10 text-primary">
          <Timer className="size-6" aria-hidden />
        </span>
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle>{messages.connect.pendingTitle}</CardTitle>
            <StatusBadge tone="warning" pulse>
              {messages.status.pending}
            </StatusBadge>
          </div>
          <CardDescription>{messages.connect.pendingDesc}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="surface-muted flex flex-col items-center gap-3 p-5 sm:flex-row sm:justify-between">
          <div className="space-y-2 text-center sm:text-start">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {messages.connect.codeLabel}
            </p>
            <p className="font-mono text-3xl font-bold tracking-[0.25em]" dir="ltr">
              {pending.user_code}
            </p>
          </div>
          <Button
            type="button"
            variant="outline"
            onClick={() => void onCopy()}
            className="shrink-0"
          >
            {copied ? <Check className="text-success" aria-hidden /> : <Copy aria-hidden />}
            {copied ? messages.common.copied : messages.common.copy}
          </Button>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <span className="text-muted-foreground">{messages.connect.expiresIn}</span>
          <span className="font-mono text-base font-semibold" dir="ltr">
            {Number.isNaN(remaining) ? "—" : formatRemaining(remaining)}
          </span>
        </div>

        {retrying ? (
          <InlineAlert variant="warning">{messages.connect.claimRetry}</InlineAlert>
        ) : (
          <InlineAlert variant="info">{messages.connect.waitingApproval}</InlineAlert>
        )}

        {verificationUrl ? (
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <a
              href={verificationUrl}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-2 break-all text-sm font-medium text-primary underline-offset-4 hover:underline"
            >
              <ExternalLink className="size-4 shrink-0" aria-hidden />
              {pending.verification_uri}
            </a>
            <Button asChild variant="outline" size="sm">
              <a href={verificationUrl} target="_blank" rel="noreferrer noopener">
                {messages.connect.openPanel}
              </a>
            </Button>
          </div>
        ) : (
          <p className="mono-value">{pending.verification_uri}</p>
        )}
      </CardContent>
    </Card>
  );
}

export function ConnectPage() {
  const data = useAgentData();
  const messages = useMessages();
  const csrf = data.csrf;

  return (
    <div className="space-y-6">
      <PageHeader title={messages.connect.title} description={messages.connect.description} />
      {data.pending ? (
        <PendingCard key={data.pending.user_code} pending={data.pending} csrf={csrf} />
      ) : data.paired ? (
        <PairedCard />
      ) : (
        <EnrollmentForm />
      )}
    </div>
  );
}
