import type { TunnelHealth } from "@/lib/api";
import type { Messages } from "@/lib/i18n";

export type StatusTone = "default" | "success" | "warning" | "destructive" | "outline";

export interface ConnectionView {
  label: string;
  tone: StatusTone;
  detail: string;
}

export function connectionView(
  input: { paired: boolean; pending: boolean; tunnel: TunnelHealth },
  messages: Messages,
): ConnectionView {
  const { tunnel } = input;
  if (input.pending) {
    return { label: messages.status.pending, tone: "warning", detail: messages.status.pending };
  }
  if (!input.paired) {
    return {
      label: messages.status.waitingForPairing,
      tone: "outline",
      detail: messages.status.waitingForPairing,
    };
  }
  const state = (tunnel.state || "").toLowerCase();
  switch (tunnel.phase) {
    case "running":
      if (state === "connected") {
        return { label: messages.status.connected, tone: "success", detail: messages.status.connected };
      }
      if (state === "connecting" || state === "initializing") {
        return {
          label: messages.status.connecting,
          tone: "warning",
          detail: messages.status.connecting,
        };
      }
      return {
        label: messages.status.unknown,
        tone: "warning",
        detail: state || messages.status.unknown,
      };
    case "reconnecting":
      return { label: messages.status.reconnecting, tone: "warning", detail: messages.status.reconnecting };
    case "recovering":
      return { label: messages.status.recovering, tone: "warning", detail: messages.status.recovering };
    case "pending_config":
      return {
        label: messages.status.waitingForPairing,
        tone: "outline",
        detail: messages.status.waitingForPairing,
      };
    case "stopped":
      return { label: messages.status.stopped, tone: "outline", detail: messages.status.stopped };
    case "terminal":
      return { label: messages.status.error, tone: "destructive", detail: messages.status.error };
    default:
      return {
        label: messages.status.unavailable,
        tone: "outline",
        detail: messages.status.unavailable,
      };
  }
}
