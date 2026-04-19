import { useEffect, useMemo, useState } from "react";

// KillChain — EDR (Wazuh / custom webhook) 가 금지 프로세스를 감지하면
// 네트워크 격리 → forensic disk snapshot → VM STOP → DELETE 순서로 대응.
// v1 scope: manual trigger + Wazuh auto mode 토글. RAM dump 는 skipped.

type Rule = {
  id: string;
  name: string;
  process_name?: string;
  auto: boolean;
  description?: string;
  created_at: string;
};

type IncidentStep = {
  name: string;
  started_at: string;
  finished_at?: string;
  status: string;
  detail?: string;
  artifact?: string;
};

type Incident = {
  id: string;
  created_at: string;
  trigger: string;
  rule_id?: string;
  rule_name?: string;
  target_email: string;
  target_vm?: string;
  matched_event?: Record<string, unknown>;
  steps?: IncidentStep[];
  status: string;
  requester?: string;
};

type User = { email: string; role?: string; workstation?: { instance_id?: string } };

export default function KillChain() {
  const [tab, setTab] = useState<"rules" | "incidents">("incidents");
  const [rules, setRules] = useState<Rule[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setErr(null);
    try {
      const [r1, r2, r3] = await Promise.all([
        fetch("/api/kill-chain/rules").then((r) => r.json()),
        fetch("/api/kill-chain/incidents?limit=200").then((r) => r.json()),
        fetch("/api/admin/users").then((r) => r.json()).catch(() => []),
      ]);
      setRules(Array.isArray(r1) ? r1 : []);
      setIncidents(Array.isArray(r2) ? r2 : []);
      setUsers(Array.isArray(r3) ? r3 : []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    refresh();
    const t = window.setInterval(refresh, 5000);
    return () => window.clearInterval(t);
  }, []);

  return (
    <div className="mx-auto w-full max-w-6xl p-4 space-y-4">
      <div className="flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900">☠️ Kill Chain</h1>
          <p className="text-sm text-slate-500">
            Wazuh / EDR 이벤트에 자동 대응 — 네트워크 격리 → disk 스냅샷 → VM 할당해제.
          </p>
        </div>
        <button
          onClick={refresh}
          className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-200"
        >
          새로고침
        </button>
      </div>

      {err && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700">{err}</div>
      )}

      <div className="flex gap-2 border-b border-slate-200">
        {(["incidents", "rules"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === t
                ? "border-b-2 border-red-500 text-red-600"
                : "text-slate-500 hover:text-slate-700"
            }`}
          >
            {t === "incidents" ? `Incidents (${incidents.length})` : `Rules (${rules.length})`}
          </button>
        ))}
      </div>

      {tab === "rules" && (
        <RulesTab rules={rules} onChange={refresh} onError={setErr} />
      )}
      {tab === "incidents" && (
        <IncidentsTab
          incidents={incidents}
          users={users}
          loading={loading}
          setLoading={setLoading}
          onChange={refresh}
          onError={setErr}
        />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
//                               Rules
// ═══════════════════════════════════════════════════════════════════════

function RulesTab({
  rules,
  onChange,
  onError,
}: {
  rules: Rule[];
  onChange: () => void;
  onError: (e: string | null) => void;
}) {
  const [name, setName] = useState("");
  const [processName, setProcessName] = useState("");
  const [desc, setDesc] = useState("");
  const [auto, setAuto] = useState(false);

  const add = async () => {
    onError(null);
    try {
      const resp = await fetch("/api/kill-chain/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, process_name: processName, auto, description: desc }),
      });
      if (!resp.ok) {
        const t = await resp.text();
        onError(t);
        return;
      }
      setName("");
      setProcessName("");
      setDesc("");
      setAuto(false);
      onChange();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  const remove = async (id: string) => {
    if (!confirm("정말 룰을 삭제하시겠습니까?")) return;
    await fetch(`/api/kill-chain/rules/${id}`, { method: "DELETE" });
    onChange();
  };

  const toggleAuto = async (id: string, next: boolean) => {
    await fetch(`/api/kill-chain/rules/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto: next }),
    });
    onChange();
  };

  return (
    <div className="space-y-4">
      {/* Add rule form */}
      <div className="rounded-lg border border-slate-200 bg-white p-4">
        <h3 className="mb-3 text-sm font-semibold text-slate-700">새 룰 추가</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="text-xs text-slate-500">
            <span className="mb-1 block">룰 이름</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Block Claude CLI"
              className="w-full rounded border border-slate-300 px-2 py-1.5 text-sm"
            />
          </label>
          <label className="text-xs text-slate-500">
            <span className="mb-1 block">프로세스명 (substring, case-insensitive)</span>
            <input
              value={processName}
              onChange={(e) => setProcessName(e.target.value)}
              placeholder="claude"
              className="w-full rounded border border-slate-300 px-2 py-1.5 text-sm font-mono"
            />
          </label>
          <label className="text-xs text-slate-500 md:col-span-2">
            <span className="mb-1 block">설명</span>
            <textarea
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              rows={2}
              className="w-full rounded border border-slate-300 px-2 py-1.5 text-sm"
            />
          </label>
          <label className="flex items-center gap-2 text-xs text-slate-600">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            <span>
              <b>Auto</b> — 이벤트 수신 즉시 kill chain 자동 실행 (위험: 오탐 시에도 VM 삭제됨)
            </span>
          </label>
          <div className="flex justify-end md:col-span-2">
            <button
              onClick={add}
              disabled={!name.trim() || !processName.trim()}
              className="rounded-lg bg-red-600 px-4 py-1.5 text-xs font-medium text-white disabled:bg-slate-300"
            >
              추가
            </button>
          </div>
        </div>
      </div>

      {/* Rules list */}
      <div className="rounded-lg border border-slate-200 bg-white">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-3 py-2 text-left">Name</th>
              <th className="px-3 py-2 text-left">Process</th>
              <th className="px-3 py-2">Auto</th>
              <th className="px-3 py-2 text-left">Description</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rules.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-xs text-slate-400">
                  룰 없음 — 위에서 추가하세요
                </td>
              </tr>
            ) : (
              rules.map((r) => (
                <tr key={r.id}>
                  <td className="px-3 py-2 font-medium">{r.name}</td>
                  <td className="px-3 py-2 font-mono text-xs">{r.process_name || "—"}</td>
                  <td className="px-3 py-2 text-center">
                    <label className="inline-flex items-center gap-1">
                      <input
                        type="checkbox"
                        checked={r.auto}
                        onChange={(e) => toggleAuto(r.id, e.target.checked)}
                      />
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                          r.auto ? "bg-red-100 text-red-700" : "bg-slate-100 text-slate-500"
                        }`}
                      >
                        {r.auto ? "AUTO" : "MANUAL"}
                      </span>
                    </label>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{r.description || "—"}</td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => remove(r.id)}
                      className="text-xs text-red-600 hover:underline"
                    >
                      삭제
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
//                             Incidents
// ═══════════════════════════════════════════════════════════════════════

function IncidentsTab({
  incidents,
  users,
  loading,
  setLoading,
  onChange,
  onError,
}: {
  incidents: Incident[];
  users: User[];
  loading: boolean;
  setLoading: (v: boolean) => void;
  onChange: () => void;
  onError: (e: string | null) => void;
}) {
  const [targetEmail, setTargetEmail] = useState("");
  const [reason, setReason] = useState("");

  const eligible = useMemo(
    () => users.filter((u) => u.workstation && u.workstation.instance_id),
    [users],
  );

  const manualTrigger = async () => {
    if (!targetEmail) return;
    if (
      !confirm(
        `${targetEmail} 의 VM 을 격리+이미징+삭제합니다. 되돌릴 수 없습니다. 계속하시겠습니까?`,
      )
    )
      return;
    onError(null);
    setLoading(true);
    try {
      const resp = await fetch("/api/kill-chain/incidents/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_email: targetEmail, reason }),
      });
      if (!resp.ok) {
        const t = await resp.text();
        onError(t);
        return;
      }
      setTargetEmail("");
      setReason("");
      onChange();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Manual trigger */}
      <div className="rounded-lg border border-red-200 bg-red-50 p-4">
        <h3 className="mb-2 text-sm font-semibold text-red-700">⚠️ Manual Trigger</h3>
        <p className="mb-3 text-xs text-red-600">
          선택한 사용자의 VM 을 즉시 격리 → 포렌식 스냅샷 → STOP → DELETE. 되돌릴 수 없습니다.
        </p>
        <div className="grid gap-3 md:grid-cols-[1fr,2fr,auto]">
          <select
            value={targetEmail}
            onChange={(e) => setTargetEmail(e.target.value)}
            className="rounded border border-red-300 bg-white px-2 py-1.5 text-sm"
          >
            <option value="">— 대상 VM 선택 —</option>
            {eligible.map((u) => (
              <option key={u.email} value={u.email}>
                {u.email} {u.workstation?.instance_id ? `(${u.workstation.instance_id})` : ""}
              </option>
            ))}
          </select>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="사유 (선택) — incident 기록에 남음"
            className="rounded border border-red-300 bg-white px-2 py-1.5 text-sm"
          />
          <button
            onClick={manualTrigger}
            disabled={!targetEmail || loading}
            className="rounded-lg bg-red-600 px-4 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:bg-slate-300"
          >
            {loading ? "..." : "KILL"}
          </button>
        </div>
      </div>

      {/* Incident list */}
      <div className="rounded-lg border border-slate-200 bg-white">
        {incidents.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-400">
            incident 없음. 자동 트리거 또는 수동 실행 시 여기에 기록됩니다.
          </div>
        ) : (
          <ul className="divide-y divide-slate-100">
            {incidents.map((inc) => (
              <IncidentRow key={inc.id} incident={inc} />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function IncidentRow({ incident }: { incident: Incident }) {
  const [open, setOpen] = useState(false);
  const statusColor =
    incident.status === "success"
      ? "bg-green-100 text-green-700"
      : incident.status === "failed"
        ? "bg-red-100 text-red-700"
        : incident.status === "running"
          ? "bg-amber-100 text-amber-700"
          : incident.status === "partial"
            ? "bg-orange-100 text-orange-700"
            : "bg-slate-100 text-slate-600";

  return (
    <li>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-slate-50"
      >
        <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${statusColor}`}>
          {incident.status}
        </span>
        <span className="font-mono text-xs text-slate-500">{incident.id.slice(-12)}</span>
        <span className="flex-1 text-sm">
          <b>{incident.target_email}</b>
          {incident.target_vm && <span className="ml-2 text-xs text-slate-500">VM: {incident.target_vm}</span>}
          {incident.rule_name && <span className="ml-2 text-xs text-slate-500">룰: {incident.rule_name}</span>}
        </span>
        <span className="text-xs text-slate-400">{new Date(incident.created_at).toLocaleString()}</span>
        <span className="text-xs">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="bg-slate-50 px-4 py-3 text-xs">
          <div className="mb-2 grid grid-cols-2 gap-2">
            <div>
              <span className="text-slate-500">Trigger:</span> {incident.trigger}
            </div>
            <div>
              <span className="text-slate-500">Requester:</span> {incident.requester || "—"}
            </div>
          </div>
          <div className="rounded border border-slate-200 bg-white">
            <table className="w-full">
              <thead className="bg-slate-100 text-[10px] uppercase text-slate-500">
                <tr>
                  <th className="px-2 py-1 text-left">Step</th>
                  <th className="px-2 py-1">Status</th>
                  <th className="px-2 py-1 text-left">Detail</th>
                  <th className="px-2 py-1 text-left">Artifact</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {(incident.steps ?? []).map((s, i) => (
                  <tr key={i}>
                    <td className="px-2 py-1 font-mono">{s.name}</td>
                    <td className="px-2 py-1 text-center">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                          s.status === "success"
                            ? "bg-green-100 text-green-700"
                            : s.status === "failed"
                              ? "bg-red-100 text-red-700"
                              : s.status === "running"
                                ? "bg-amber-100 text-amber-700"
                                : "bg-slate-100 text-slate-500"
                        }`}
                      >
                        {s.status}
                      </span>
                    </td>
                    <td className="px-2 py-1 text-slate-600">{s.detail || "—"}</td>
                    <td className="px-2 py-1 font-mono text-[10px] text-slate-500">
                      {s.artifact || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {incident.matched_event && (
            <details className="mt-2">
              <summary className="cursor-pointer text-slate-500">matched event</summary>
              <pre className="mt-1 overflow-x-auto rounded bg-slate-900 p-2 text-[10px] text-slate-100">
                {JSON.stringify(incident.matched_event, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </li>
  );
}
