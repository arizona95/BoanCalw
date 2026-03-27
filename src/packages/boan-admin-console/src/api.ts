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
  return res.json();
}

export interface OrgPolicy {
  version: number;
  org_id: string;
  rules: Record<string, unknown>;
  updated_at: string;
}

export interface LLMEntry {
  id: string;
  name: string;
  endpoint: string;
  is_security_llm: boolean;
  created_at: string;
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
  id: string;
  name: string;
  status: "ok" | "expired" | "missing";
  provider: string;
  expires_at: string;
}

export interface DashboardStats {
  llm_count: number;
  active_sessions: number;
  dlp_block_count: number;
  policy_version: number;
}

export const policyApi = {
  get: () => request<OrgPolicy>(`${POLICY_BASE}/v1/policy`),
  update: (rules: Record<string, unknown>) =>
    request<OrgPolicy>(`${POLICY_BASE}/v1/policy`, {
      method: "PUT",
      body: JSON.stringify({ rules }),
    }),
  rollback: () =>
    request<OrgPolicy>(`${POLICY_BASE}/v1/policy/rollback`, {
      method: "POST",
    }),
};

export const registryApi = {
  list: () => request<LLMEntry[]>(`${REGISTRY_BASE}/v1/llms`),
  register: (name: string, endpoint: string) =>
    request<LLMEntry>(`${REGISTRY_BASE}/v1/llms`, {
      method: "POST",
      body: JSON.stringify({ name, endpoint }),
    }),
  bindSecurity: (id: string) =>
    request<LLMEntry>(`${REGISTRY_BASE}/v1/llms/${id}/bind-security`, {
      method: "POST",
    }),
  remove: (id: string) =>
    request<void>(`${REGISTRY_BASE}/v1/llms/${id}`, { method: "DELETE" }),
};

export const auditApi = {
  list: (limit = 50) =>
    request<AuditEvent[]>(`${AUDIT_BASE}/v1/events?limit=${limit}`),
};

export const credentialApi = {
  list: () => request<Credential[]>(`${CREDENTIAL_BASE}/v1/credentials`),
  add: (name: string, provider: string) =>
    request<Credential>(`${CREDENTIAL_BASE}/v1/credentials`, {
      method: "POST",
      body: JSON.stringify({ name, provider }),
    }),
  revoke: (id: string) =>
    request<void>(`${CREDENTIAL_BASE}/v1/credentials/${id}`, {
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
  approve: (id: string) =>
    request<void>(`${APPROVAL_BASE}/${id}/approve`, { method: "POST" }),
  reject: (id: string) =>
    request<void>(`${APPROVAL_BASE}/${id}/reject`, { method: "POST" }),
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
