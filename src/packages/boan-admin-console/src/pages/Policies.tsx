import { useEffect, useMemo, useState } from "react";
import { policyApi, type NetworkEndpoint, type OrgPolicy } from "../api";

// ── 공통 유틸 ─────────────────────────────────────────────────────────────
type EndpointRow = { id: string; host: string; ports: string; methods: string };

function makeRow(seed?: Partial<EndpointRow>): EndpointRow {
  return { id: Math.random().toString(36).slice(2, 10), host: seed?.host ?? "", ports: seed?.ports ?? "443", methods: seed?.methods ?? "POST" };
}
function endpointToRow(ep: NetworkEndpoint): EndpointRow {
  return makeRow({ host: ep.host ?? "", ports: (ep.ports ?? []).join(",") || "443", methods: (ep.methods ?? []).join(",") || "POST" });
}
function parseCsv(v: string): string[] { return v.split(",").map((s) => s.trim()).filter(Boolean); }
function parsePorts(v: string): number[] { return parseCsv(v).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535); }
function buildWhitelist(rows: EndpointRow[]): NetworkEndpoint[] {
  return rows.map((r) => ({ host: r.host.trim(), ports: parsePorts(r.ports), methods: parseCsv(r.methods).map((m) => m.toUpperCase()) }))
    .filter((r) => r.host)
    .map((r) => ({ host: r.host, ports: r.ports.length ? r.ports : [443], methods: r.methods.length ? r.methods : ["POST"] }));
}

const TABS = ["Network", "Mount", "Guardrail", "SSO"] as const;
type Tab = (typeof TABS)[number];

export default function Policies() {
  const [tab, setTab] = useState<Tab>("Network");
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  // Network
  const [rows, setRows] = useState<EndpointRow[]>([makeRow()]);
  // Mount
  const [mountRoot, setMountRoot] = useState("/workspace/boanclaw");
  const [allowedModels, setAllowedModels] = useState("security");
  const [featureRemoteControl, setFeatureRemoteControl] = useState(false);
  const [featureWebAccess, setFeatureWebAccess] = useState(false);
  const [featureScheduledTasks, setFeatureScheduledTasks] = useState(true);
  // Guardrail
  const [constitution, setConstitution] = useState("");
  const [autoApprove, setAutoApprove] = useState(false);
  // SSO
  const [allowedDomains, setAllowedDomains] = useState("samsung.com");

  const whitelistPreview = useMemo(() => buildWhitelist(rows), [rows]);

  const load = () => {
    setLoading(true);
    policyApi.get().then((p) => {
      setPolicy(p);
      const nr = (p.network_whitelist ?? []).map(endpointToRow);
      setRows(nr.length > 0 ? nr : [makeRow()]);
      setAllowedModels((p.allow_models ?? ["security"]).join(", "));
      setMountRoot(p.org_settings?.mount_root ?? "/workspace/boanclaw");
      setFeatureRemoteControl(Boolean(p.features?.remote_control));
      setFeatureWebAccess(Boolean(p.features?.web_access));
      setFeatureScheduledTasks(p.features?.scheduled_tasks === undefined ? true : Boolean(p.features?.scheduled_tasks));
      setConstitution(p.guardrail?.constitution ?? "");
      setAutoApprove(Boolean(p.guardrail?.auto_approve_mode));
      setAllowedDomains((p.org_settings?.allowed_domains ?? ["samsung.com"]).join(", "));
    }).catch((e) => setMsg({ type: "err", text: e.message })).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const save = async () => {
    setMsg(null); setSaving(true);
    try {
      const updated = await policyApi.update({
        network_whitelist: whitelistPreview,
        allow_models: parseCsv(allowedModels),
        features: { remote_control: featureRemoteControl, web_access: featureWebAccess, scheduled_tasks: featureScheduledTasks },
        version_policy: { min_version: "0.1.0", blocked_versions: [], update_channel: "stable" },
        org_settings: { mount_root: mountRoot.trim(), allowed_domains: parseCsv(allowedDomains) },
        guardrail: { constitution: constitution.trim(), auto_approve_mode: autoApprove },
      });
      setPolicy(updated);
      setMsg({ type: "ok", text: "저장됨" });
    } catch (e: unknown) { setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" }); }
    finally { setSaving(false); }
  };

  const rollback = async () => {
    setMsg(null); setSaving(true);
    try { await policyApi.rollback(); load(); setMsg({ type: "ok", text: "롤백 완료" }); }
    catch (e: unknown) { setMsg({ type: "err", text: e instanceof Error ? e.message : "롤백 실패" }); }
    finally { setSaving(false); }
  };

  const updateRow = (id: string, patch: Partial<EndpointRow>) => setRows((c) => c.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">Gateway Policies</h1>
          {policy && <p className="text-xs text-gray-500 mt-1">v{policy.version} · {policy.org_id} · {policy.updated_at}</p>}
        </div>
        <div className="flex gap-2">
          <button onClick={rollback} disabled={saving} className="px-3 py-1.5 text-xs rounded-lg border border-gray-300 hover:bg-gray-100 disabled:opacity-50">Rollback</button>
          <button onClick={save} disabled={saving} className="px-3 py-1.5 text-xs rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50">{saving ? "..." : "Save"}</button>
        </div>
      </div>

      {msg && <div className={`mb-3 p-2 rounded-lg text-xs ${msg.type === "ok" ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700"}`}>{msg.text}</div>}

      {/* 탭 */}
      <div className="flex border-b border-gray-200 mb-4">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === t ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"}`}>{t}</button>
        ))}
      </div>

      {/* ── Network ── */}
      {tab === "Network" && (
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
          <h2 className="text-sm font-semibold mb-1">Egress Allowlist</h2>
          <p className="text-xs text-gray-500 mb-4">기본 전부 차단. 등록된 host/port/method만 허용.</p>

          <div className="space-y-2">
            <div className="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto] text-xs text-gray-500 font-medium px-1">
              <span>Host</span><span>Ports</span><span>Methods</span><span></span>
            </div>
            {rows.map((row, i) => (
              <div key={row.id} className="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto]">
                <input value={row.host} onChange={(e) => updateRow(row.id, { host: e.target.value })} placeholder="api.example.com" className="px-3 py-2 border border-gray-300 rounded-lg text-sm" />
                <input value={row.ports} onChange={(e) => updateRow(row.id, { ports: e.target.value })} placeholder="443" className="px-3 py-2 border border-gray-300 rounded-lg text-sm" />
                <input value={row.methods} onChange={(e) => updateRow(row.id, { methods: e.target.value })} placeholder="POST,GET" className="px-3 py-2 border border-gray-300 rounded-lg text-sm" />
                <div className="flex gap-1">
                  <button onClick={() => setRows((c) => c.filter((r) => r.id !== row.id))} disabled={rows.length === 1} className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 hover:bg-red-50 hover:text-red-600 disabled:opacity-30">−</button>
                  {i === rows.length - 1 && <button onClick={() => setRows((c) => [...c, makeRow()])} className="px-2.5 py-2 text-sm rounded-lg bg-gray-900 text-white hover:bg-black">+</button>}
                </div>
              </div>
            ))}
          </div>

          <details className="mt-4">
            <summary className="text-xs text-gray-500 cursor-pointer">JSON 미리보기</summary>
            <pre className="mt-2 text-xs text-gray-600 bg-gray-50 p-3 rounded-lg overflow-x-auto">{JSON.stringify(whitelistPreview, null, 2)}</pre>
          </details>
        </section>
      )}

      {/* ── Mount ── */}
      {tab === "Mount" && (
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold mb-1">Mount & Access Rules</h2>
            <p className="text-xs text-gray-500">S3→S2 마운트 경로 및 기능 플래그 설정.</p>
          </div>
          <label className="block">
            <span className="text-sm font-medium text-gray-700">Mount Root</span>
            <input value={mountRoot} onChange={(e) => setMountRoot(e.target.value)} className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" />
          </label>
          <label className="block">
            <span className="text-sm font-medium text-gray-700">허용 모델</span>
            <input value={allowedModels} onChange={(e) => setAllowedModels(e.target.value)} placeholder="security, minimax" className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm" />
          </label>
          <div className="grid gap-3 md:grid-cols-3 pt-2">
            {[
              { label: "scheduled_tasks", val: featureScheduledTasks, set: setFeatureScheduledTasks },
              { label: "remote_control", val: featureRemoteControl, set: setFeatureRemoteControl },
              { label: "web_access", val: featureWebAccess, set: setFeatureWebAccess },
            ].map((f) => (
              <label key={f.label} className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={f.val} onChange={(e) => f.set(e.target.checked)} />
                {f.label}
              </label>
            ))}
          </div>
        </section>
      )}

      {/* ── Guardrail ── */}
      {tab === "Guardrail" && (
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold mb-1">Guardrail Constitution</h2>
            <p className="text-xs text-gray-500">Tier 1 헌법 가드레일 기준. LLM이 이 헌법으로 allow/ask/block 판정.</p>
          </div>
          <textarea value={constitution} onChange={(e) => setConstitution(e.target.value)} rows={8} placeholder="가드레일 헌법을 작성하세요..." className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm" />

          <div className="p-4 rounded-xl border border-gray-200 bg-gray-50">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-gray-800">HITL 모드</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  <b>수동</b>: ask 판정시 소유자 승인 &nbsp;|&nbsp; <b>자동</b>: LLM이 즉시 판단
                </p>
              </div>
              <button type="button" onClick={() => setAutoApprove((v) => !v)} className={`relative inline-flex h-7 w-14 items-center rounded-full transition-colors ${autoApprove ? "bg-boan-600" : "bg-gray-300"}`}>
                <span className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${autoApprove ? "translate-x-8" : "translate-x-1"}`} />
              </button>
            </div>
            <p className="mt-2 text-xs font-medium text-center">
              {autoApprove ? <span className="text-boan-700">자동 모드 ON</span> : <span className="text-gray-500">수동 모드</span>}
            </p>
          </div>
        </section>
      )}

      {/* ── SSO ── */}
      {tab === "SSO" && (
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
          <div>
            <h2 className="text-sm font-semibold mb-1">SSO Allowed Domains</h2>
            <p className="text-xs text-gray-500">이 도메인의 이메일만 로그인/가입 가능합니다. 콤마로 구분.</p>
          </div>
          <input
            value={allowedDomains}
            onChange={(e) => setAllowedDomains(e.target.value)}
            placeholder="samsung.com, samsungsds.com"
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono"
          />
          <div className="flex flex-wrap gap-2">
            {parseCsv(allowedDomains).map((d) => (
              <span key={d} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 text-blue-700 rounded-full text-xs font-medium">
                @{d}
                <button onClick={() => setAllowedDomains(parseCsv(allowedDomains).filter((x) => x !== d).join(", "))} className="text-blue-400 hover:text-red-500">&times;</button>
              </span>
            ))}
          </div>
          <p className="text-xs text-gray-400">저장(Save) 버튼을 누르면 즉시 반영됩니다.</p>
        </section>
      )}
    </div>
  );
}
