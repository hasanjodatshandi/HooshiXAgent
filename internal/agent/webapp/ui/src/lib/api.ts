const CAPABILITY_KEY = "hooshix-agent-capability";

let capability = "";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface Endpoint {
  id: string;
  target: string;
  protocol?: string;
}

export interface PendingEnrollment {
  user_code: string;
  verification_uri: string;
  expires_at: string;
}

export interface TunnelHealth {
  phase: string;
  state: string;
  reconnects: number;
  last_error?: string;
  last_update_at: string;
}

export interface AgentState {
  paired: boolean;
  config: {
    gateway_url?: string;
    ca_file?: string;
    device_id?: string;
    endpoints?: Endpoint[];
  };
  public_key?: string;
  public_key_error?: string;
  pending?: PendingEnrollment | null;
  tunnel: TunnelHealth;
  notice?: string;
  notice_at?: string;
  csrf: string;
  hostname: string;
  default_panel_url: string;
  version: string;
}

interface RequestOptions {
  method?: "GET" | "POST";
  json?: unknown;
  form?: Record<string, string>;
  csrf?: string;
}

function rememberCapability(value: string): void {
  capability = value;
  try {
    if (value) sessionStorage.setItem(CAPABILITY_KEY, value);
    else sessionStorage.removeItem(CAPABILITY_KEY);
  } catch {
    // Storage can be disabled; the URL still carries the capability.
  }
}

export function readInitialCapability(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("cap") ?? "";
  if (fromQuery) {
    rememberCapability(fromQuery);
    return fromQuery;
  }
  try {
    capability = sessionStorage.getItem(CAPABILITY_KEY) ?? "";
  } catch {
    capability = "";
  }
  return capability;
}

export function currentCapability(): string {
  return capability;
}

export function replaceCapability(value: string): void {
  rememberCapability(value);
  const url = new URL(window.location.href);
  if (value) url.searchParams.set("cap", value);
  else url.searchParams.delete("cap");
  window.history.replaceState(null, "", url.pathname + url.search + url.hash);
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  if (!capability) throw new ApiError(401, "pairing authorization required");
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-HooshiX-Pairing-Capability": capability,
  };
  if (options.csrf) headers["X-HooshiX-CSRF"] = options.csrf;
  let body: string | undefined;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  } else if (options.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(options.form).toString();
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? (body === undefined ? "GET" : "POST"),
      headers,
      body,
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch (error) {
    throw new ApiError(0, error instanceof Error ? error.message : "network request failed");
  }
  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }
  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : typeof payload === "string" && payload.trim()
          ? payload.trim()
          : `HTTP ${response.status}`;
    throw new ApiError(response.status, detail);
  }
  return payload as T;
}

export function getState(): Promise<AgentState> {
  return request<AgentState>("/api/state");
}

export interface EnrollmentStartResult {
  state: string;
  user_code: string;
  verification_uri: string;
  expires_at: string;
}

export function startEnrollment(
  input: { server_url: string; device_name: string; ca_file: string },
  csrf: string,
): Promise<EnrollmentStartResult> {
  return request<EnrollmentStartResult>("/enrollment/start", { method: "POST", json: input, csrf });
}

export type ClaimResult =
  | { state: "pending" }
  | { state: "claimed"; device_id: string; capability: string };

export function claimEnrollment(csrf: string): Promise<ClaimResult> {
  return request<ClaimResult>("/enrollment/claim", { method: "POST", csrf });
}

export interface EndpointMutationResult {
  endpoints: Endpoint[];
  notice?: string;
}

export function addEndpoint(
  input: { id: string; target: string; protocol: string },
  csrf: string,
): Promise<EndpointMutationResult> {
  return request<EndpointMutationResult>("/expose/add", { method: "POST", form: input, csrf });
}

export function removeEndpoint(id: string, csrf: string): Promise<EndpointMutationResult> {
  return request<EndpointMutationResult>("/expose/remove", { method: "POST", form: { id }, csrf });
}

export interface RotateResult {
  capability: string;
  notice?: string;
}

export function rotateCapability(csrf: string): Promise<RotateResult> {
  return request<RotateResult>("/pairing/rotate", { method: "POST", csrf });
}

export interface UnpairResult {
  device_id: string;
  identity_preserved: boolean;
  already_unpaired: boolean;
  public_key: string;
}

export function unpair(resetIdentity: boolean, csrf: string): Promise<UnpairResult> {
  return request<UnpairResult>("/unpair", {
    method: "POST",
    form: resetIdentity ? { reset_identity: "true" } : {},
    csrf,
  });
}
