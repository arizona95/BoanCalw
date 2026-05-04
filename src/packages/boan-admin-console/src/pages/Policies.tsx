import { useEffect, useMemo, useState } from "react";
import {
  mountApi,
  policyApi,
  type MountConfig,
  type MountRule,
  type NetworkEndpoint,
  type OrgPolicy,
} from "../api";

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

// Guardrail 섹션은 별도 Guardrail 페이지 (/guardrail) 로 분리됨 — 보안 코어라
// 사이드바 상위 항목. 이 페이지는 Network 화이트리스트 + Mount 규칙만.
const TABS = ["Network", "Mount"] as const;
type Tab = (typeof TABS)[number];

type MountRuleRow = { id: string; pattern: string; mode: "deny" | "ask" };

function makeMountRow(seed?: Partial<MountRuleRow>): MountRuleRow {
  return {
    id: Math.random().toString(36).slice(2, 10),
    pattern: seed?.pattern ?? "",
    mode: (seed?.mode === "ask" ? "ask" : "deny"),
  };
}

export default function Policies() {
  // URL query (?tab=...) 로 초기 탭 결정.
  const initialTab = ((): Tab => {
    if (typeof window === "undefined") return "Network";
    const q = new URLSearchParams(window.location.search).get("tab");
    if (q === "Network" || q === "Mount") return q as Tab;
    return "Network";
  })();
  const [tab, setTab] = useState<Tab>(initialTab);
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  // Network
  const [rows, setRows] = useState<EndpointRow[]>([makeRow()]);
  // Mount — host/sandbox/s1 경로는 env var 에서 read-only. 규칙은 정책에 저장.
  const [mountCfg, setMountCfg] = useState<MountConfig | null>(null);
  const [mountRules, setMountRules] = useState<MountRuleRow[]>([]);

  const whitelistPreview = useMemo(() => buildWhitelist(rows), [rows]);

  const load = () => {
    setLoading(true);
    Promise.all([
      policyApi.get(),
      mountApi.config().catch(() => null),
    ])
      .then(([p, m]) => {
        setPolicy(p);
        const nr = (p.network_whitelist ?? []).map(endpointToRow);
        setRows(nr.length > 0 ? nr : [makeRow()]);
        setMountCfg(m);
        const mr = (p.org_settings?.mount_rules ?? []).map((r) => makeMountRow({ pattern: r.pattern, mode: r.mode }));
        setMountRules(mr);
      })
      .catch((e) => setMsg({ type: "err", text: e.message }))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const cleanedMountRules: MountRule[] = useMemo(
    () =>
      mountRules
        .map((r) => ({ pattern: r.pattern.trim(), mode: r.mode }))
        .filter((r) => r.pattern.length > 0),
    [mountRules]
  );

  const save = async () => {
    setMsg(null); setSaving(true);
    // Mount 규칙 정규식 검증
    for (const r of cleanedMountRules) {
      try { new RegExp(r.pattern); }
      catch (e) {
        setMsg({ type: "err", text: `Mount 규칙 정규식 오류: ${r.pattern} — ${e instanceof Error ? e.message : ""}` });
        setSaving(false);
        return;
      }
    }
    try {
      // guardrail 관련 필드는 /guardrail 페이지가 관리. 여기는 network + mount 만.
      const updated = await policyApi.update({
        network_whitelist: whitelistPreview,
        version_policy: { min_version: "0.1.0", blocked_versions: [], update_channel: "stable" },
        org_settings: { mount_rules: cleanedMountRules },
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
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-5">
          <div>
            <h2 className="text-sm font-semibold mb-1">Mount & Access Rules</h2>
            <p className="text-xs text-gray-500">
              기본은 마운트 경로 하위 <b>전체 read+write 허용</b>. 아래 정규식 규칙으로 특정 파일/폴더에만 제한을 건다.
              위→아래 순서로 첫 매칭이 적용됨.
            </p>
          </div>

          <div>
            <span className="text-xs font-medium text-gray-500">마운트 경로 (환경변수 기반 read-only)</span>
            <div className="mt-2 space-y-2">
              {([
                ["S3 (Host PC)", mountCfg?.paths.host_s3],
                ["S2 (Sandbox)", mountCfg?.paths.sandbox_s2],
                ["S1 (GCP stage)", mountCfg?.paths.s1_stage],
              ] as const).map(([label, p]) => (
                <div key={label} className="grid grid-cols-[110px_200px_1fr] gap-3 items-center">
                  <span className="text-xs font-medium text-gray-600">{label}</span>
                  <code className="text-xs px-2 py-1 bg-blue-50 text-blue-700 rounded border border-blue-100 font-mono">
                    ${p?.env_var ?? "?"}
                  </code>
                  <code className="text-xs px-3 py-1 bg-gray-50 border border-gray-200 rounded font-mono text-gray-700">
                    {p?.value || <span className="text-gray-400">(unset)</span>}
                  </code>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="grid gap-2 md:grid-cols-[3fr_1fr_auto] text-xs text-gray-500 font-medium px-1 mb-1">
              <span>패턴 (정규식)</span>
              <span>모드</span>
              <span></span>
            </div>
            <div className="space-y-2">
              {mountRules.map((row, i) => (
                <div key={row.id} className="grid gap-2 md:grid-cols-[3fr_1fr_auto]">
                  <input
                    value={row.pattern}
                    onChange={(e) =>
                      setMountRules((c) => c.map((r) => (r.id === row.id ? { ...r, pattern: e.target.value } : r)))
                    }
                    placeholder=".*\.env$  또는  ^secrets/.*"
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono"
                  />
                  <select
                    value={row.mode}
                    onChange={(e) =>
                      setMountRules((c) =>
                        c.map((r) => (r.id === row.id ? { ...r, mode: e.target.value as "deny" | "ask" } : r))
                      )
                    }
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  >
                    <option value="deny">deny (읽기만 가능)</option>
                    <option value="ask">ask (사용자 본인 HITL 확인)</option>
                  </select>
                  <div className="flex gap-1">
                    <button
                      type="button"
                      onClick={() => setMountRules((c) => c.filter((r) => r.id !== row.id))}
                      className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 hover:bg-red-50 hover:text-red-600"
                    >
                      −
                    </button>
                    {i === mountRules.length - 1 && (
                      <button
                        type="button"
                        onClick={() => setMountRules((c) => [...c, makeMountRow()])}
                        className="px-2.5 py-2 text-sm rounded-lg bg-gray-900 text-white hover:bg-black"
                      >
                        +
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {mountRules.length === 0 && (
                <button
                  type="button"
                  onClick={() => setMountRules([makeMountRow()])}
                  className="w-full py-2 text-xs rounded-lg border border-dashed border-gray-300 text-gray-500 hover:bg-gray-50"
                >
                  + 첫 규칙 추가
                </button>
              )}
            </div>
            <p className="mt-2 text-xs text-gray-500">
              예: <code className="px-1 bg-gray-100 rounded">.*\.env$</code> + <b>deny</b> → <code>.env</code> 파일은 읽기만 가능 (수정 차단).
              <code className="px-1 bg-gray-100 rounded ml-2">^secrets/.*</code> + <b>ask</b> → <code>secrets/</code> 하위 접근 시 사용자 본인에게 HITL 확인 팝업.
            </p>
          </div>
        </section>
      )}

    </div>
  );
}
