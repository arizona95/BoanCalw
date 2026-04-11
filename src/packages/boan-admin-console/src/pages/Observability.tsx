import { useEffect, useState, useCallback } from "react";
import { auditApi, type AuditEvent } from "../api";

interface TraceEntry {
  id: string;
  timestamp: string;
  type: string;
  direction: string;
  source: string;
  target: string;
  summary: string;
  decision: string;
  gate: string;
  duration_ms: number;
  meta?: Record<string, unknown>;
}

const LEVEL_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-green-100 text-green-800",
  info: "bg-gray-100 text-gray-600",
};

interface TracesResponse {
  total: number;
  offset: number;
  limit: number;
  traces: TraceEntry[];
}

const TYPE_STYLE: Record<string, string> = {
  chat: "bg-blue-100 text-blue-700",
  guardrail: "bg-yellow-100 text-yellow-700",
  network: "bg-purple-100 text-purple-700",
  credential: "bg-red-100 text-red-700",
  file: "bg-green-100 text-green-700",
  system: "bg-gray-100 text-gray-600",
};

const DECISION_STYLE: Record<string, string> = {
  allow: "text-green-600",
  block: "text-red-600",
  ask: "text-yellow-600",
  "hitl_required": "text-orange-600",
  "credential_required": "text-red-500",
  "n/a": "text-gray-400",
};

const TIER_STYLE: Record<string, string> = {
  G1: "bg-blue-50 text-blue-700 border-blue-200",
  G2: "bg-purple-50 text-purple-700 border-purple-200",
  G3: "bg-indigo-50 text-indigo-700 border-indigo-200",
  DLP: "bg-emerald-50 text-emerald-700 border-emerald-200",
  access: "bg-red-50 text-red-700 border-red-300",
  "G1+credential": "bg-amber-50 text-amber-700 border-amber-200",
  key: "bg-gray-50 text-gray-600 border-gray-200",
  chord: "bg-gray-50 text-gray-600 border-gray-200",
  clipboard: "bg-gray-50 text-gray-600 border-gray-200",
  mode: "bg-gray-50 text-gray-600 border-gray-200",
};

type Tab = "traces" | "metrics" | "logs" | "audit";
const PAGE_SIZE = 50;

export default function Observability() {
  const [tab, setTab] = useState<Tab>("traces");
  const [data, setData] = useState<TracesResponse>({ total: 0, offset: 0, limit: PAGE_SIZE, traces: [] });
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  // Audit tab state
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  const load = useCallback(() => {
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) });
    if (typeFilter) params.set("type", typeFilter);
    if (query) params.set("q", query);
    fetch(`/api/observability/traces?${params}`, { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setData(d))
      .catch(() => setData({ total: 0, offset: 0, limit: PAGE_SIZE, traces: [] }))
      .finally(() => setLoading(false));
  }, [typeFilter, query, page]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (autoRefresh && page === 0) {
      const interval = setInterval(load, 3000);
      return () => clearInterval(interval);
    }
  }, [load, autoRefresh, page]);

  const loadAudit = useCallback(() => {
    setAuditLoading(true);
    setAuditError(null);
    auditApi
      .list(100)
      .then(setAuditEvents)
      .catch((e) => setAuditError(e instanceof Error ? e.message : String(e)))
      .finally(() => setAuditLoading(false));
  }, []);

  useEffect(() => {
    if (tab === "audit") loadAudit();
  }, [tab, loadAudit]);

  const clearLogs = async () => {
    if (!confirm("모든 로그를 삭제하시겠습니까?")) return;
    await fetch("/api/observability/traces", { method: "DELETE", credentials: "include" });
    load();
  };

  const totalPages = Math.ceil(data.total / PAGE_SIZE);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Observability</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">Total: {data.total}</span>
          <label className="flex items-center gap-1 text-xs text-gray-500">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Auto (3s)
          </label>
          <button onClick={load} className="text-xs text-boan-600 hover:underline">Refresh</button>
          <button onClick={clearLogs} className="text-xs text-red-500 hover:underline">Clear All</button>
        </div>
      </div>

      <div className="flex border-b border-gray-200 mb-4">
        {(["traces", "metrics", "logs", "audit"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors capitalize ${tab === t ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"}`}>{t}</button>
        ))}
      </div>

      {tab === "traces" && (
        <div>
          {/* 필터 + 검색 */}
          <div className="flex gap-2 mb-3 items-center">
            {["", "chat", "guardrail", "network", "credential", "file"].map((f) => (
              <button key={f} onClick={() => { setTypeFilter(f); setPage(0); }} className={`px-2 py-1 text-xs rounded-full ${typeFilter === f ? "bg-boan-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
                {f || "All"}
              </button>
            ))}
            <input
              value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }}
              placeholder="Search..."
              className="ml-auto px-3 py-1 border border-gray-300 rounded-lg text-xs w-48"
            />
          </div>

          {loading && data.traces.length === 0 ? (
            <p className="text-gray-400 text-sm">Loading...</p>
          ) : data.traces.length === 0 ? (
            <p className="text-gray-400 text-sm text-center py-8">No traces</p>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-gray-50 border-b text-gray-500">
                  <tr>
                    <th className="px-3 py-2 text-left">Time</th>
                    <th className="px-3 py-2 text-left">Type</th>
                    <th className="px-3 py-2 text-left">Sender</th>
                    <th className="px-3 py-2 text-left">→ Target</th>
                    <th className="px-3 py-2 text-left">Summary</th>
                    <th className="px-3 py-2 text-left">Decision</th>
                    <th className="px-3 py-2 text-left">Tier</th>
                    <th className="px-3 py-2 text-left">Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {data.traces.map((t) => {
                    const tier = (t.meta?.tier as string) || t.gate || "";
                    const reason = (t.meta?.reason as string) || "";
                    const accessLevel = (t.meta?.access_level as string) || "";
                    return (
                      <tr key={t.id} className="hover:bg-gray-50 align-top">
                        <td className="px-3 py-2 text-gray-400 whitespace-nowrap font-mono">
                          {new Date(t.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                        </td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${TYPE_STYLE[t.type] ?? "bg-gray-100"}`}>{t.type}</span>
                        </td>
                        <td className="px-3 py-2 font-mono text-gray-600 truncate max-w-[140px]" title={t.source}>
                          {t.source}
                          {accessLevel && <div className="text-[10px] text-gray-400 font-normal">al={accessLevel}</div>}
                        </td>
                        <td className="px-3 py-2 font-mono text-gray-500 truncate max-w-[80px]">{t.target}</td>
                        <td className="px-3 py-2 text-gray-700 truncate max-w-[260px]" title={t.summary}>{t.summary}</td>
                        <td className="px-3 py-2">
                          <span className={`font-medium ${DECISION_STYLE[t.decision] ?? "text-gray-400"}`}>{t.decision}</span>
                        </td>
                        <td className="px-3 py-2">
                          {tier ? (
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono font-medium ${TIER_STYLE[tier] ?? "bg-gray-50 text-gray-600 border-gray-200"}`}>
                              {tier}
                            </span>
                          ) : (
                            <span className="text-gray-300">-</span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-gray-500 max-w-[280px] truncate" title={reason}>
                          {reason || <span className="text-gray-300">-</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {/* 페이지네이션 */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-2 border-t bg-gray-50">
                  <span className="text-xs text-gray-500">{data.total}건 중 {page * PAGE_SIZE + 1}~{Math.min((page + 1) * PAGE_SIZE, data.total)}</span>
                  <div className="flex gap-1">
                    <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0} className="px-2 py-1 text-xs rounded border disabled:opacity-30">Prev</button>
                    <span className="px-2 py-1 text-xs text-gray-500">{page + 1}/{totalPages}</span>
                    <button onClick={() => setPage(Math.min(totalPages - 1, page + 1))} disabled={page >= totalPages - 1} className="px-2 py-1 text-xs rounded border disabled:opacity-30">Next</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {tab === "metrics" && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-sm font-semibold mb-4">System Metrics</h2>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="p-4 rounded-lg bg-blue-50 border border-blue-200">
              <p className="text-2xl font-bold text-blue-700">{data.traces.filter((t) => t.type === "chat").length}</p>
              <p className="text-xs text-blue-600">Chat Messages</p>
            </div>
            <div className="p-4 rounded-lg bg-yellow-50 border border-yellow-200">
              <p className="text-2xl font-bold text-yellow-700">{data.traces.filter((t) => t.type === "guardrail").length}</p>
              <p className="text-xs text-yellow-600">Guardrail Evaluations</p>
            </div>
            <div className="p-4 rounded-lg bg-green-50 border border-green-200">
              <p className="text-2xl font-bold text-green-700">{data.traces.filter((t) => t.decision === "allow").length}</p>
              <p className="text-xs text-green-600">Allowed</p>
            </div>
            <div className="p-4 rounded-lg bg-red-50 border border-red-200">
              <p className="text-2xl font-bold text-red-700">{data.traces.filter((t) => t.decision === "block").length}</p>
              <p className="text-xs text-red-600">Blocked</p>
            </div>
          </div>
          <p className="mt-4 text-xs text-gray-400">1년 경과 로그는 자동 삭제됩니다.</p>
        </div>
      )}

      {tab === "logs" && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <div className="border-b bg-gray-50 px-4 py-2 flex items-center justify-between">
            <span className="text-xs text-gray-500">Raw JSON log (newest first) — Fluent Bit 연동 가능</span>
            <button onClick={clearLogs} className="text-xs text-red-500 hover:underline">Clear All</button>
          </div>
          <pre className="p-4 text-xs font-mono text-gray-600 overflow-x-auto max-h-[600px] overflow-y-auto">
            {data.traces.map((t) => JSON.stringify(t)).join("\n")}
          </pre>
        </div>
      )}

      {tab === "audit" && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-gray-500">{auditEvents.length} events</span>
            <button onClick={loadAudit} className="text-xs text-boan-600 hover:underline">Refresh</button>
          </div>
          {auditError && (
            <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{auditError}</div>
          )}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
            {auditLoading ? (
              <p className="p-6 text-gray-500 text-sm">Loading...</p>
            ) : auditEvents.length === 0 ? (
              <p className="p-6 text-gray-500 text-sm">No audit events.</p>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="text-left px-6 py-3 font-medium text-gray-500">Action</th>
                    <th className="text-left px-6 py-3 font-medium text-gray-500">S-Level</th>
                    <th className="text-left px-6 py-3 font-medium text-gray-500">Host</th>
                    <th className="text-left px-6 py-3 font-medium text-gray-500">User</th>
                    <th className="text-left px-6 py-3 font-medium text-gray-500">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {auditEvents.map((ev) => (
                    <tr key={ev.id} className="hover:bg-gray-50">
                      <td className="px-6 py-3 font-mono">{ev.action}</td>
                      <td className="px-6 py-3">
                        <span className={`text-xs px-2 py-1 rounded-full ${LEVEL_COLORS[ev.s_level] || LEVEL_COLORS.info}`}>
                          {ev.s_level}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-gray-600">{ev.host}</td>
                      <td className="px-6 py-3 text-gray-600">{ev.user}</td>
                      <td className="px-6 py-3 text-gray-500">{ev.timestamp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
