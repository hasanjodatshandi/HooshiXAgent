import { useState, type ReactNode } from "react";
import {
  AlertTriangle,
  KeyRound,
  Loader2,
  Lock,
  Monitor,
  RotateCcw,
  Unplug,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { CopyField } from "@/components/copy-field";
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
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { apiErrorMessage } from "@/lib/errors";
import { useMessages } from "@/lib/i18n";
import { replaceCapability, rotateCapability, unpair } from "@/lib/api";
import { useAgent, useAgentData } from "@/stores/agent";

function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="min-w-0 text-sm font-medium sm:text-end">{children}</span>
    </div>
  );
}

export function DevicePage() {
  const data = useAgentData();
  const messages = useMessages();
  const refresh = useAgent((state) => state.refresh);
  const navigate = useNavigate();

  const [rotating, setRotating] = useState(false);
  const [unpairing, setUnpairing] = useState(false);
  const [resetIdentity, setResetIdentity] = useState(false);

  async function onRotate() {
    if (rotating) return;
    setRotating(true);
    try {
      const result = await rotateCapability(data.csrf);
      replaceCapability(result.capability);
      toast.success(messages.device.rotated);
      await refresh();
    } catch (caught) {
      toast.error(messages.device.rotateError, { description: apiErrorMessage(caught, messages) });
    } finally {
      setRotating(false);
    }
  }

  async function onUnpair() {
    if (unpairing) return;
    setUnpairing(true);
    try {
      const result = await unpair(resetIdentity, data.csrf);
      if (result.already_unpaired) {
        toast.info(messages.device.alreadyUnpaired);
      } else if (result.identity_preserved) {
        toast.success(messages.device.unpairDone);
      } else {
        toast.success(messages.device.unpairReset);
      }
      setResetIdentity(false);
      await refresh();
      navigate("/connect", { replace: true });
    } catch (caught) {
      toast.error(messages.device.unpairError, {
        description: apiErrorMessage(caught, messages),
      });
    } finally {
      setUnpairing(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title={messages.device.title} description={messages.device.description} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="size-4 text-primary" aria-hidden />
            {messages.device.identityTitle}
          </CardTitle>
          <CardDescription>{messages.device.identityDesc}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {data.public_key ? (
            <CopyField value={data.public_key} />
          ) : (
            <InlineAlert variant="warning" title={messages.device.keyUnavailable}>
              {data.public_key_error ? (
                <p className="mono-value mt-1" dir="ltr">
                  {data.public_key_error}
                </p>
              ) : null}
            </InlineAlert>
          )}
          <p className="text-xs leading-5 text-muted-foreground">{messages.device.publicKeyHint}</p>
        </CardContent>
      </Card>

      <div className="grid items-start gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <RotateCcw className="size-4 text-primary" aria-hidden />
              {messages.device.rotateTitle}
            </CardTitle>
            <CardDescription>{messages.device.rotateDesc}</CardDescription>
          </CardHeader>
          <CardContent>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" disabled={rotating}>
                  {rotating ? <Loader2 className="animate-spin" aria-hidden /> : <RotateCcw aria-hidden />}
                  {rotating ? messages.device.rotating : messages.device.rotate}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>{messages.device.rotateConfirmTitle}</AlertDialogTitle>
                  <AlertDialogDescription>{messages.device.rotateConfirmBody}</AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{messages.common.cancel}</AlertDialogCancel>
                  <AlertDialogAction onClick={() => void onRotate()}>
                    {messages.device.rotate}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Monitor className="size-4 text-primary" aria-hidden />
              {messages.device.metadataTitle}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <MetaRow label={messages.device.hostname}>
              <span className="font-mono text-xs">{data.hostname}</span>
            </MetaRow>
            <Separator />
            <MetaRow label={messages.device.version}>
              <span className="font-mono text-xs">{data.version}</span>
            </MetaRow>
            <Separator />
            <MetaRow label={messages.common.status}>
              <StatusBadge tone={data.paired ? "success" : "outline"}>
                {data.paired ? messages.status.paired : messages.status.unpaired}
              </StatusBadge>
            </MetaRow>
            <Separator />
            <p className="flex items-center gap-2 text-xs text-muted-foreground">
              <Lock className="size-3.5" aria-hidden />
              {messages.device.localOnly}
            </p>
            <p className="text-xs leading-5 text-muted-foreground">{messages.device.secretNote}</p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-destructive/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="size-4" aria-hidden />
            {messages.device.unpairTitle}
          </CardTitle>
          <CardDescription>{messages.device.unpairDesc}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start gap-3 rounded-xl border border-border/70 bg-muted/30 p-3">
            <input
              id="reset-identity"
              type="checkbox"
              checked={resetIdentity}
              onChange={(event) => setResetIdentity(event.target.checked)}
              className="mt-0.5 size-4 shrink-0 rounded border-input accent-destructive"
            />
            <div className="space-y-1">
              <label htmlFor="reset-identity" className="text-sm font-medium">
                {messages.device.resetIdentity}
              </label>
              <p className="text-xs leading-5 text-muted-foreground">
                {messages.device.resetIdentityHint}
              </p>
            </div>
          </div>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" disabled={unpairing}>
                {unpairing ? <Loader2 className="animate-spin" aria-hidden /> : <Unplug aria-hidden />}
                {unpairing ? messages.device.unpairing : messages.device.unpair}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{messages.device.unpairConfirmTitle}</AlertDialogTitle>
                <AlertDialogDescription>{messages.device.unpairConfirmBody}</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{messages.common.cancel}</AlertDialogCancel>
                <AlertDialogAction variant="destructive" onClick={() => void onUnpair()}>
                  {messages.device.unpair}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardContent>
      </Card>
    </div>
  );
}
