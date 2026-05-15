import { useCallback, useEffect, useMemo, useState } from "react";
import {
  mountApi,
  policyApi,
  type MountConfig,
  type MountRule,
  type NetworkEndpoint,
  type OrgPolicy,
} from "../api";
import { usePolicyLiveSync } from "../lib/usePolicyLiveSync";

// ── 공통 유틸 ─────────────────────────────────────────────────────────────
type EndpointRow = { id: string; host: string; ports: string; methods: string; system?: boolean };

function makeRow(seed?: Partial<EndpointRow>): EndpointRow {
  return { id: Math.random().toString(36).slice(2, 10), host: seed?.host ?? "", ports: seed?.ports ?? "443", methods: seed?.methods ?? "POST", system: seed?.system };
}
function endpointToRow(ep: NetworkEndpoint): EndpointRow {
  return makeRow({ host: ep.host ?? "", ports: (ep.ports ?? []).join(",") || "443", methods: (ep.methods ?? []).join(",") || "POST", system: ep.system === true });
}
function parseCsv(v: string): string[] { return v.split(",").map((s) => s.trim()).filter(Boolean); }

// portError — empty string ("") = ok, non-empty = human-readable error.
// Each token in the CSV must be an integer 1..65535. We surface the error
// inline so users can see invalid input instead of silently rewriting it
// to 443 on save (that previous silent-fallback masked typos).
function portError(v: string): string {
  const tokens = parseCsv(v);
  if (tokens.length === 0) return "포트를 하나 이상 입력하세요";
  for (const t of tokens) {
    if (!/^\d+$/.test(t)) return `포트는 숫자만: ${t}`;
    const n = Number(t);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return `포트 범위 1–65535: ${t}`;
  }
  return "";
}
function parsePorts(v: string): number[] { return parseCsv(v).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535); }
function buildWhitelist(rows: EndpointRow[]): NetworkEndpoint[] {
  // Skip rows with empty host OR invalid ports — frontend never silently
  // rewrites bad input. Caller (autoSave) shows an inline error per row.
  // System rows are *not* sent on save: the server re-prepends them on
  // every read, so including them would round-trip noise and (if it ever
  // missed strip-on-write) risk persisting them as user entries.
  return rows
    .filter((r) => !r.system && r.host.trim() !== "" && portError(r.ports) === "")
    .map((r) => ({
      host: r.host.trim(),
      ports: parsePorts(r.ports),
      methods: parseCsv(r.methods).map((m) => m.toUpperCase()),
    }))
    .map((r) => ({ host: r.host, ports: r.ports, methods: r.methods.length ? r.methods : ["POST"] }));
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
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
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

  // flush — push the current Network + Mount state to the cloud policy
  // server immediately. Replaces the old "Save" button: every edit / "−"
  // delete calls this. Skipping the Save click means users can't accidentally
  // leave a stale row in their browser unsynced.
  const flush = async (next: { rows?: EndpointRow[]; mount?: MountRule[] } = {}) => {
    const rowsToSave = next.rows ?? rows;
    const mountToSave = next.mount ?? cleanedMountRules;
    // Validate mount regex client-side; abort if any rule is malformed.
    for (const r of mountToSave) {
      try { new RegExp(r.pattern); }
      catch (e) {
        setMsg({ type: "err", text: `Mount 규칙 정규식 오류: ${r.pattern} — ${e instanceof Error ? e.message : ""}` });
        setSaveState("error");
        return;
      }
    }
    setMsg(null);
    setSaveState("saving");
    try {
      const updated = await policyApi.update({
        network_whitelist: buildWhitelist(rowsToSave),
        version_policy: { min_version: "0.1.0", blocked_versions: [], update_channel: "stable" },
        org_settings: { mount_rules: mountToSave },
      });
      setPolicy(updated);
      setSaveState("saved");
      window.setTimeout(() => setSaveState((s) => (s === "saved" ? "idle" : s)), 1500);
    } catch (e: unknown) {
      setSaveState("error");
      setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" });
    }
  };

  // Live policy sync — SSE + polling are encapsulated in the shared hook so
  // this page (and any future policy page) doesn't reimplement EventSource /
  // setInterval / race-suppress flags. The hook calls `pullFresh` whenever a
  // remote change lands; `markLocalEdit()` is invoked right before our own
  // writes so the resulting SSE echo doesn't clobber inputs the user is
  // still editing.
  const pullFresh = useCallback(() => {
    policyApi.get().then((p) => {
      setPolicy(p);
      const nr = (p.network_whitelist ?? []).map(endpointToRow);
      setRows(nr.length > 0 ? nr : [makeRow()]);
      const mr = (p.org_settings?.mount_rules ?? []).map((r) => makeMountRow({ pattern: r.pattern, mode: r.mode }));
      setMountRules(mr);
    }).catch(() => undefined);
  }, []);
  const { markLocalEdit } = usePolicyLiveSync(pullFresh);

  const updateRow = (id: string, patch: Partial<EndpointRow>) => setRows((c) => c.map((r) => (r.id === id ? { ...r, ...patch } : r)));

  const commitRowEdit = (id: string) => {
    const row = rows.find((r) => r.id === id);
    if (!row) return;
    if (!row.host.trim()) return;
    if (portError(row.ports) !== "") return;
    markLocalEdit();
    flush();
  };

  const deleteRow = (id: string) => {
    const next = rows.filter((r) => r.id !== id);
    setRows(next.length > 0 ? next : [makeRow()]);
    markLocalEdit();
    flush({ rows: next });
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      {/* 헤더 */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">Gateway Policies</h1>
          {policy && <p className="text-xs text-gray-500 mt-1">v{policy.version} · {policy.org_id} · {policy.updated_at}</p>}
        </div>
        <div className="text-xs">
          {saveState === "saving" && <span className="text-gray-500">저장 중…</span>}
          {saveState === "saved" && <span className="text-green-600">✓ 즉시 반영됨</span>}
          {saveState === "error" && <span className="text-red-600">저장 실패</span>}
          {saveState === "idle" && <span className="text-gray-400">실시간 동기화</span>}
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
            {rows.map((row, i) => {
              const pErr = row.system ? "" : portError(row.ports);
              const sys = row.system === true;
              // `w-full min-w-0` 가 핵심 — grid track 안에서 input intrinsic
              // width 가 content (긴 host) 에 의해 늘어나지 않게. 빠지면 sys
              // 의 긴 cloud-run hostname 이 호스트 컬럼을 잡아당겨 보기 흉함.
              const inputBase = sys
                ? "w-full min-w-0 px-3 py-2 border rounded-lg text-sm bg-gray-100 text-gray-500 cursor-not-allowed border-gray-200"
                : "w-full min-w-0 px-3 py-2 border border-gray-300 rounded-lg text-sm";
              return (
                <div key={row.id}>
                  <div className="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto]">
                    <div className="relative min-w-0">
                      <input
                        value={row.host}
                        onChange={(e) => !sys && updateRow(row.id, { host: e.target.value })}
                        onBlur={() => !sys && commitRowEdit(row.id)}
                        placeholder="api.example.com"
                        readOnly={sys}
                        title={sys ? row.host : undefined}
                        className={inputBase + (sys ? " pl-7" : "")}
                      />
                      {sys && (
                        <span className="absolute left-2 top-1/2 -translate-y-1/2 text-xs" title="시스템 필수 endpoint — 관리자도 지울 수 없음 (정책 / LLM proxy 통신 보장)">🔒</span>
                      )}
                    </div>
                    <input
                      value={row.ports}
                      onChange={(e) => !sys && updateRow(row.id, { ports: e.target.value })}
                      onBlur={() => !sys && commitRowEdit(row.id)}
                      placeholder="443"
                      readOnly={sys}
                      className={sys ? inputBase : `w-full min-w-0 px-3 py-2 border rounded-lg text-sm ${pErr ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                    />
                    <input
                      value={row.methods}
                      onChange={(e) => !sys && updateRow(row.id, { methods: e.target.value })}
                      onBlur={() => !sys && commitRowEdit(row.id)}
                      placeholder="POST,GET"
                      readOnly={sys}
                      className={inputBase}
                    />
                    <div className="flex gap-1">
                      <button
                        onClick={() => !sys && deleteRow(row.id)}
                        disabled={sys || rows.length === 1}
                        className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 hover:bg-red-50 hover:text-red-600 disabled:opacity-30 disabled:cursor-not-allowed"
                        title={sys ? "시스템 필수 — 지울 수 없음" : "즉시 정책에서 삭제"}
                      >−</button>
                      {/* + 자리는 모든 row 에서 동일 너비로 유지 — 마지막 row 외에는
                          invisible placeholder (같은 px/border/text size) 로 두어
                          − 버튼이 row 마다 동일 위치에 정렬되게 한다. */}
                      {!sys && i === rows.length - 1 ? (
                        <button
                          onClick={() => setRows((c) => [...c, makeRow()])}
                          className="px-2.5 py-2 text-sm rounded-lg bg-gray-900 text-white hover:bg-black"
                          title="새 row 추가 (host 입력 후 Tab 으로 저장)"
                        >+</button>
                      ) : (
                        <span
                          aria-hidden="true"
                          className="px-2.5 py-2 text-sm rounded-lg border border-transparent invisible"
                        >+</span>
                      )}
                    </div>
                  </div>
                  {pErr && (
                    <p className="text-xs text-red-600 mt-1 ml-1">{pErr}</p>
                  )}
                </div>
              );
            })}
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
                    onBlur={() => {
                      if (row.pattern.trim() === "") return;
                      markLocalEdit();
                      flush();
                    }}
                    placeholder=".*\.env$  또는  ^secrets/.*"
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono"
                  />
                  <select
                    value={row.mode}
                    onChange={(e) => {
                      const next = mountRules.map((r) => (r.id === row.id ? { ...r, mode: e.target.value as "deny" | "ask" } : r));
                      setMountRules(next);
                      markLocalEdit();
                      flush({ mount: next.filter((r) => r.pattern.trim() !== "").map((r) => ({ pattern: r.pattern.trim(), mode: r.mode })) });
                    }}
                    className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
                  >
                    <option value="deny">deny (읽기만 가능)</option>
                    <option value="ask">ask (사용자 본인 HITL 확인)</option>
                  </select>
                  <div className="flex gap-1">
                    <button
                      type="button"
                      onClick={() => {
                        const next = mountRules.filter((r) => r.id !== row.id);
                        setMountRules(next);
                        markLocalEdit();
                        flush({ mount: next.filter((r) => r.pattern.trim() !== "").map((r) => ({ pattern: r.pattern.trim(), mode: r.mode })) });
                      }}
                      className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 hover:bg-red-50 hover:text-red-600"
                      title="즉시 정책에서 삭제"
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
