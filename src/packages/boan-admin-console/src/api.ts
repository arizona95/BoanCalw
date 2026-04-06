const POLICY_BASE = "/api/policy";
const REGISTRY_BASE = "/api/registry";
const AUDIT_BASE = "/api/audit";
const CREDENTIAL_BASE = "/api/credential";
const APPROVAL_BASE = "/api/approvals";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export interface OrgPolicy {
  version: number;
  org_id: string;
  updated_at: string;
  rules: Record<string, unknown>;
  network_whitelist?: NetworkEndpoint[];
  dlp_rules?: unknown[];
  rbac?: unknown;
  allow_models?: string[];
  features?: Record<string, boolean>;
  version_policy?: VersionPolicy;
  org_settings?: OrgPolicySettings;
  guardrail?: GuardrailConfig;
}

export interface NetworkEndpoint {
  host: string;
  ports?: number[];
  methods?: string[];
}

export interface VersionPolicy {
  min_version?: string;
  blocked_versions?: string[];
  update_channel?: string;
}

export interface OrgPolicySettings {
  org_name?: string;
  admin_emails?: string[];
  seat_limit?: number;
  gcp_org_id?: string;
  workspace_url?: string;
  mount_root?: string;
}

export interface GuardrailConfig {
  constitution?: string;
  auto_approve_mode?: boolean;
}

export interface LLMEntry {
  name: string;
  endpoint: string;
  type: "llm" | "image";
  scope?: string;
  curl_template?: string;
  image_curl_template?: string;
  is_security_llm?: boolean;
  is_security_lmm?: boolean;
  healthy?: boolean;
  last_checked?: string;
  registered_at?: string;
}

export interface LLMRegistrationHistory {
  name: string;
  endpoint: string;
  type: "llm" | "image";
  curl_template?: string;
  image_curl_template?: string;
  registered_at: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  s_level: string;
  host: string;
  user: string;
  timestamp: string;
  details: string;
}

export interface Credential {
  role: string;
  org_id: string;
  status: "ok" | "expired" | "missing";
  expires_at: string;
}

export interface CredentialPassthrough {
  name: string;
  value: string;
}

export interface DashboardStats {
  llm_count: number;
  active_sessions: number;
  dlp_block_count: number;
  policy_version: number;
}

function normalizePolicy(raw: Record<string, unknown>): OrgPolicy {
  const { version, org_id, updated_at, signature, ...rest } = raw as Record<string, unknown>;
  void signature;
  return {
    version: version as number,
    org_id: org_id as string,
    updated_at: updated_at as string,
    rules: rest,
    ...rest,
  };
}

export const policyApi = {
  get: () =>
    request<Record<string, unknown>>(`${POLICY_BASE}/v1/policy`).then(
      normalizePolicy
    ),
  update: (rules: Record<string, unknown>) =>
    request<Record<string, unknown>>(`${POLICY_BASE}/v1/policy`, {
      method: "PUT",
      body: JSON.stringify(rules),
    }).then(normalizePolicy),
  rollback: () =>
    request<Record<string, unknown>>(`${POLICY_BASE}/v1/policy/rollback`, {
      method: "POST",
    }).then(normalizePolicy),
};

export interface RegisterLLMPayload {
  name: string;
  type: "llm" | "image";
  curl_template?: string;
  image_curl_template?: string;
  endpoint?: string;
  store_detected_credentials?: boolean;
}

export const registryApi = {
  list: () => request<LLMEntry[]>(`${REGISTRY_BASE}/v1/llms`),
  history: () => request<LLMRegistrationHistory[]>(`${REGISTRY_BASE}/v1/llms/history`),
  register: (payload: RegisterLLMPayload) =>
    request<LLMEntry>(`${REGISTRY_BASE}/v1/llms`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  bindSecurity: (name: string) =>
    request<LLMEntry>(`${REGISTRY_BASE}/v1/llms/${name}/bind-security`, {
      method: "POST",
    }),
  bindSecurityLMM: (name: string) =>
    request<LLMEntry>(`${REGISTRY_BASE}/v1/llms/${name}/bind-security-lmm`, {
      method: "POST",
    }),
  remove: (name: string) =>
    request<void>(`${REGISTRY_BASE}/v1/llms/${name}`, { method: "DELETE" }),
  clearHistory: () =>
    request<void>(`${REGISTRY_BASE}/v1/llms/history`, { method: "DELETE" }),
  deleteHistoryItem: (name: string, registeredAt: string) =>
    request<void>(`${REGISTRY_BASE}/v1/llms/history/${encodeURIComponent(name)}/${encodeURIComponent(registeredAt)}`, { method: "DELETE" }),
};

export const auditApi = {
  list: (limit = 50) =>
    request<AuditEvent[]>(`${AUDIT_BASE}/v1/events?limit=${limit}`),
};

export const credentialApi = {
  list: () => request<Credential[]>(`${CREDENTIAL_BASE}/v1/credentials`),
  add: (name: string, key: string, ttlHours = 8760) =>
    request<{ status: string; role: string }>(`${CREDENTIAL_BASE}/v1/credentials`, {
      method: "POST",
      body: JSON.stringify({ name, key, ttl_hours: ttlHours }),
    }),
  revoke: (role: string) =>
    request<void>(`${CREDENTIAL_BASE}/v1/credentials/${role}`, {
      method: "DELETE",
    }),
  storeForLLM: (role: string, key: string) =>
    request<{ status: string; role: string }>(`${CREDENTIAL_BASE}/v1/store`, {
      method: "POST",
      body: JSON.stringify({ role, key, ttl_hours: 8760 }),
    }),
  listPassthrough: () => request<CredentialPassthrough[]>(`${CREDENTIAL_BASE}/v1/passthrough`),
  addPassthrough: (name: string, value: string) =>
    request<{ status: string; name: string }>(`${CREDENTIAL_BASE}/v1/passthrough`, {
      method: "POST",
      body: JSON.stringify({ name, value }),
    }),
  removePassthrough: (name: string) =>
    request<void>(`${CREDENTIAL_BASE}/v1/passthrough/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),
};

export interface ApprovalRequest {
  id: string;
  sessionId: string;
  command: string;
  args: string[];
  requester: string;
  requestedAt: string;
  status: "pending" | "approved" | "rejected";
  decidedBy?: string;
  decidedAt?: string;
}

export const approvalApi = {
  list: () => request<ApprovalRequest[]>(APPROVAL_BASE),
  get: (id: string) => request<ApprovalRequest>(`${APPROVAL_BASE}/${id}`),
  approve: (id: string) =>
    request<void>(`${APPROVAL_BASE}/${id}/approve`, { method: "POST" }),
  reject: (id: string) =>
    request<void>(`${APPROVAL_BASE}/${id}/reject`, { method: "POST" }),
};

export interface GCPOrg {
  name: string;
  displayName?: string;
  state?: string;
  createTime?: string;
  [key: string]: unknown;
}

export interface OrgSettingsRecord {
  org_id: string;
  display_name?: string;
  settings: Record<string, unknown>;
  updated_at: string;
}

export interface PersonalWorkstation {
  email: string;
  org_id: string;
  provider: string;
  platform: string;
  status: string;
  display_name: string;
  instance_id: string;
  region?: string;
  console_url?: string;
  web_desktop_url?: string;
  assigned_at: string;
}

export interface OpenClawDashboard {
  url: string;
}

export interface InputGateRequest {
  mode: "text" | "key" | "paste" | "chord" | "clipboard_sync";
  text?: string;
  key?: string;
  src_level?: number;
  dest_level?: number;
  flow?: string;
}

export interface InputGateResponse {
  allowed: boolean;
  action: string;
  reason?: string;
  normalized_text?: string;
  key?: string;
  approval_id?: string;
}

export const orgSettingsApi = {
  get: () =>
    fetch("/api/admin/org-settings", { credentials: "include" }).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.json() as Promise<OrgSettingsRecord>;
    }),
  patch: (body: { display_name?: string; settings?: Record<string, unknown> }) =>
    fetch("/api/admin/org-settings", {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.json() as Promise<OrgSettingsRecord>;
    }),
};

export const gcpApi = {
  fetchOrg: (accessToken: string, orgId?: string) =>
    request<GCPOrg>("/api/gcp/org", {
      method: "POST",
      body: JSON.stringify({ access_token: accessToken, org_id: orgId }),
    }),
  sync: (accessToken: string, orgId: string, orgName: string, allowDomains: string[]) =>
    request<{ status: string; org_id: string; domains: number }>("/api/gcp/sync", {
      method: "POST",
      body: JSON.stringify({
        access_token: accessToken,
        org_id: orgId,
        org_name: orgName,
        allow_domains: allowDomains,
      }),
    }),
};

export const openclawApi = {
  dashboard: () =>
    request<OpenClawDashboard>("/api/openclaw/dashboard", {
      credentials: "include",
    }),
};

export const workstationApi = {
  me: () =>
    fetch("/api/workstation/me", { credentials: "include" }).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.json() as Promise<PersonalWorkstation>;
    }),
};

export const inputGateApi = {
  evaluate: (payload: InputGateRequest) =>
    fetch("/api/input-gate/evaluate", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.json() as Promise<InputGateResponse>;
    }),
};

export const chatApi = {
  forward: (message: string) =>
    request<{ ok: boolean; runId?: string; error?: string }>("/api/chat/forward", {
      method: "POST",
      body: JSON.stringify({ message }),
    }),
};

export const computerUseApi = {
  type: (text: string) =>
    request<{ ok: boolean; result: string }>("/api/computer-use/type", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  key: (name: string) =>
    request<{ ok: boolean; result: string }>("/api/computer-use/key", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
};

export const dashboardApi = {
  stats: async (): Promise<DashboardStats> => {
    try {
      const [llms, policy] = await Promise.all([
        registryApi.list().catch(() => []),
        policyApi.get().catch(() => ({ version: 0 })),
      ]);
      return {
        llm_count: llms.length,
        active_sessions: 0,
        dlp_block_count: 0,
        policy_version: policy.version,
      };
    } catch {
      return {
        llm_count: 0,
        active_sessions: 0,
        dlp_block_count: 0,
        policy_version: 0,
      };
    }
  },
};
