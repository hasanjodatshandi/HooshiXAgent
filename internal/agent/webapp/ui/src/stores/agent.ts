import { create } from "zustand";
import { ApiError, getState, type AgentState } from "@/lib/api";

type LoadStatus = "loading" | "ready" | "error";

interface AgentStore {
  data: AgentState | null;
  status: LoadStatus;
  error: string;
  fatal: boolean;
  refreshing: boolean;
  refresh: () => Promise<AgentState | null>;
}

let inFlight: Promise<AgentState | null> | null = null;

export const useAgent = create<AgentStore>((set, get) => ({
  data: null,
  status: "loading",
  error: "",
  fatal: false,
  refreshing: false,
  refresh: () => {
    if (inFlight) return inFlight;
    set({ refreshing: true });
    inFlight = (async () => {
      try {
        const data = await getState();
        set({ data, status: "ready", error: "", fatal: false, refreshing: false });
        return data;
      } catch (error) {
        const status = error instanceof ApiError ? error.status : 0;
        const message = error instanceof Error ? error.message : "unknown error";
        set({
          status: get().data ? "ready" : "error",
          error: message,
          fatal: status === 401 || status === 403,
          refreshing: false,
        });
        return null;
      } finally {
        inFlight = null;
      }
    })();
    return inFlight;
  },
}));

export function useAgentData(): AgentState {
  const data = useAgent((state) => state.data);
  if (!data) throw new Error("agent state is not loaded");
  return data;
}

