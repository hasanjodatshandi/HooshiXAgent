import { useState, type FormEvent } from "react";
import { Loader2, Monitor, Plus, Server, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { EmptyState } from "@/components/empty-state";
import { InlineAlert } from "@/components/inline-alert";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { Select } from "@/components/ui/select";
import { addEndpoint, removeEndpoint, type Endpoint } from "@/lib/api";
import { apiErrorMessage } from "@/lib/errors";
import { formatNumber } from "@/lib/format";
import { useMessages } from "@/lib/i18n";
import { useAgent, useAgentData } from "@/stores/agent";
import { useUi } from "@/stores/ui";

const endpointIdPattern = "[A-Za-z0-9][A-Za-z0-9._:-]{0,63}";

export function ServicesPage() {
  const data = useAgentData();
  const messages = useMessages();
  const language = useUi((state) => state.language);
  const refresh = useAgent((state) => state.refresh);
  const endpoints = data.config.endpoints ?? [];

  const [id, setId] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [target, setTarget] = useState("");
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");
  const [restartNeeded, setRestartNeeded] = useState(false);
  const [showRdpHint, setShowRdpHint] = useState(false);
  const [pendingRemove, setPendingRemove] = useState<Endpoint | null>(null);

  async function onAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (adding || !data.paired) return;
    setAdding(true);
    setError("");
    try {
      await addEndpoint({ id: id.trim(), target: target.trim(), protocol }, data.csrf);
      toast.success(messages.services.added, { description: messages.services.restartNote });
      setId("");
      setTarget("");
      setRestartNeeded(true);
      await refresh();
    } catch (caught) {
      const message = apiErrorMessage(caught, messages);
      setError(message);
      toast.error(messages.services.addError, { description: message });
    } finally {
      setAdding(false);
    }
  }

  async function onRemove(endpoint: Endpoint) {
    if (!data.paired) return;
    try {
      await removeEndpoint(endpoint.id, data.csrf);
      toast.success(messages.services.removed, {
        description: messages.services.restartNote,
      });
      setRestartNeeded(true);
      setPendingRemove(null);
      await refresh();
    } catch (caught) {
      toast.error(apiErrorMessage(caught, messages));
    }
  }

  function applyRdpPreset() {
    setId("rdp-001");
    setProtocol("tcp");
    setTarget("127.0.0.1:3389");
    setShowRdpHint(true);
  }

  return (
    <div className="space-y-6">
      <PageHeader title={messages.services.title} description={messages.services.description} />

      {!data.paired ? <InlineAlert variant="info">{messages.services.pairRequired}</InlineAlert> : null}

      <div className="grid items-start gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Plus className="size-4 text-primary" aria-hidden />
              {messages.services.addTitle}
            </CardTitle>
            <CardDescription>{messages.services.addDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={(event) => void onAdd(event)}>
              <div className="space-y-2">
                <Label htmlFor="endpoint-id">{messages.services.id}</Label>
                <Input
                  id="endpoint-id"
                  name="id"
                  value={id}
                  onChange={(event) => setId(event.target.value)}
                  placeholder={messages.services.idPlaceholder}
                  pattern={endpointIdPattern}
                  title={messages.services.idHint}
                  dir="ltr"
                  className="text-start font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
                <p className="text-xs leading-5 text-muted-foreground">{messages.services.idHint}</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="endpoint-protocol">{messages.services.protocol}</Label>
                <Select
                  id="endpoint-protocol"
                  name="protocol"
                  value={protocol}
                  onChange={(event) => setProtocol(event.target.value)}
                >
                  <option value="tcp">{messages.services.tcp}</option>
                  <option value="udp">{messages.services.udp}</option>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="endpoint-target">{messages.services.target}</Label>
                <Input
                  id="endpoint-target"
                  name="target"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={messages.services.targetPlaceholder}
                  dir="ltr"
                  className="text-start font-mono text-xs"
                  autoComplete="off"
                  spellCheck={false}
                  required
                />
              </div>
              {error ? <InlineAlert variant="destructive">{error}</InlineAlert> : null}
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={adding || !data.paired}>
                  {adding ? <Loader2 className="animate-spin" aria-hidden /> : <Plus aria-hidden />}
                  {adding ? messages.services.adding : messages.services.add}
                </Button>
                <Button type="button" variant="outline" onClick={applyRdpPreset}>
                  <Monitor aria-hidden />
                  {messages.services.rdpPreset}
                </Button>
              </div>
            </form>
            {showRdpHint ? (
              <InlineAlert variant="info" className="mt-4">
                {messages.services.rdpHint}
              </InlineAlert>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-start justify-between gap-3">
            <div className="space-y-1.5">
              <CardTitle className="flex items-center gap-2">
                <Server className="size-4 text-primary" aria-hidden />
                {messages.services.listTitle}
              </CardTitle>
              <CardDescription>{messages.services.listDesc}</CardDescription>
            </div>
            <StatusBadge tone="outline">
              {formatNumber(endpoints.length, language)}
            </StatusBadge>
          </CardHeader>
          <CardContent className="space-y-4">
            {restartNeeded ? (
              <InlineAlert variant="warning">{messages.services.restartNote}</InlineAlert>
            ) : null}
            {endpoints.length === 0 ? (
              <EmptyState
                icon={<Server className="size-5" aria-hidden />}
                title={messages.services.emptyTitle}
                description={messages.services.emptyDesc}
              />
            ) : (
              <div className="divide-y divide-border/70">
                {endpoints.map((endpoint) => (
                  <div
                    key={endpoint.id}
                    className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold">{endpoint.id}</span>
                        <StatusBadge tone="outline">
                          {(endpoint.protocol || "tcp").toUpperCase()}
                        </StatusBadge>
                      </div>
                      <p className="mono-value inline-block text-xs">{endpoint.target}</p>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={!data.paired}
                      className="self-start text-destructive hover:bg-destructive/10 hover:text-destructive sm:self-auto"
                      onClick={() => setPendingRemove(endpoint)}
                    >
                      <Trash2 aria-hidden />
                      {messages.common.remove}
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <AlertDialog
        open={pendingRemove !== null}
        onOpenChange={(open) => {
          if (!open) setPendingRemove(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{messages.services.removeTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {messages.services.removeBody.replace("{id}", pendingRemove?.id ?? "")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{messages.common.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (pendingRemove) void onRemove(pendingRemove);
              }}
            >
              {messages.common.remove}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
