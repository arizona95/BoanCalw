import { useEffect, useMemo, useState } from "react";
import {
  guardrailApi,
  mountApi,
  policyApi,
  type G1CustomPattern,
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

const TABS = ["Network", "Mount", "Guardrail"] as const;
type Tab = (typeof TABS)[number];
type GuardrailSubTab = "G1" | "G2" | "G3";

type MountRuleRow = { id: string; pattern: string; mode: "deny" | "ask" };

function makeMountRow(seed?: Partial<MountRuleRow>): MountRuleRow {
  return {
    id: Math.random().toString(36).slice(2, 10),
    pattern: seed?.pattern ?? "",
    mode: (seed?.mode === "ask" ? "ask" : "deny"),
  };
}

// G1 custom pattern row — pattern + description + mode
type G1Mode = "credential" | "block";
type G1PatternRow = { id: string; pattern: string; description: string; mode: G1Mode };

function makeG1Row(seed?: Partial<G1PatternRow>): G1PatternRow {
  return {
    id: Math.random().toString(36).slice(2, 10),
    pattern: seed?.pattern ?? "",
    description: seed?.description ?? "",
    mode: seed?.mode === "credential" ? "credential" : "block",
  };
}

export default function Policies() {
  const [tab, setTab] = useState<Tab>("Network");
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  // Network
  const [rows, setRows] = useState<EndpointRow[]>([makeRow()]);
  // Mount — host/sandbox/s1 경로는 env var 에서 read-only. 규칙은 정책에 저장
  const [mountCfg, setMountCfg] = useState<MountConfig | null>(null);
  const [mountRules, setMountRules] = useState<MountRuleRow[]>([]);
  // Guardrail — G1 / G2 / G3 각각의 설정
  const [guardrailSubTab, setGuardrailSubTab] = useState<GuardrailSubTab>("G1");
  const [g1DefaultPatterns, setG1DefaultPatterns] = useState<string[]>([]);
  const [g1Rows, setG1Rows] = useState<G1PatternRow[]>([]);
  const [constitution, setConstitution] = useState("");
  const [g3WikiHint, setG3WikiHint] = useState("");

  const whitelistPreview = useMemo(() => buildWhitelist(rows), [rows]);

  const load = () => {
    setLoading(true);
    Promise.all([
      policyApi.get(),
      mountApi.config().catch(() => null),
      guardrailApi.g1Defaults().catch(() => ({ patterns: [] })),
    ])
      .then(([p, m, g1]) => {
        setPolicy(p);
        const nr = (p.network_whitelist ?? []).map(endpointToRow);
        setRows(nr.length > 0 ? nr : [makeRow()]);
        setMountCfg(m);
        const mr = (p.org_settings?.mount_rules ?? []).map((r) => makeMountRow({ pattern: r.pattern, mode: r.mode }));
        setMountRules(mr);
        setG1DefaultPatterns(g1.patterns ?? []);
        const storedG1 = p.guardrail?.g1_custom_patterns ?? [];
        if (storedG1.length > 0) {
          setG1Rows(storedG1.map((g) => makeG1Row({ pattern: g.pattern, description: g.description ?? "", mode: g.mode })));
        } else {
          // 최초 로드 — 정책에 아무것도 없으면 기본 5줄을 편집 가능한 행으로 seed.
          // 사용자는 이 값을 수정/삭제/추가할 수 있음. save 시 현재 상태 그대로 저장.
          const defaultDescs: Record<string, string> = {
            "(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----": "PEM 형식 private key 헤더",
            "(?i)\\b(?:ghp|github_pat|sk-[a-z0-9]|AKIA|AIza)[A-Za-z0-9_\\-]{8,}\\b": "GitHub/OpenAI/AWS/Google API 키 prefix",
            "(?i)\\beyJ[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\b": "JWT 토큰 (base64 헤더.payload.signature)",
            "(?i)\\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\\s*[:=]\\s*\\S+": "password/secret/token 변수 할당 표현",
            "(?i)\\b(?:setx?|export)\\s+[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\\s*[= ]\\s*\\S+": "환경변수 export TOKEN=... 패턴",
          };
          setG1Rows(
            (g1.patterns ?? []).map((pat) =>
              makeG1Row({ pattern: pat, description: defaultDescs[pat] ?? "", mode: "credential" })
            )
          );
        }
        setConstitution(p.guardrail?.constitution ?? "");
        setG3WikiHint(p.guardrail?.g3_wiki_hint ?? "");
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

  const cleanedG1Custom: G1CustomPattern[] = useMemo(
    () =>
      g1Rows
        .map((r) => ({ pattern: r.pattern.trim(), description: r.description.trim(), mode: r.mode }))
        .filter((r) => r.pattern.length > 0),
    [g1Rows]
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
    // G1 정규식은 Go 서버에서 실행 — JS 검증 생략 ((?i) 등 Go 전용 문법 지원)
    try {
      const updated = await policyApi.update({
        network_whitelist: whitelistPreview,
        version_policy: { min_version: "0.1.0", blocked_versions: [], update_channel: "stable" },
        org_settings: { mount_rules: cleanedMountRules },
        guardrail: {
          g1_custom_patterns: cleanedG1Custom,
          constitution: constitution.trim(),
          g3_wiki_hint: g3WikiHint.trim(),
        },
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

      {/* ── Guardrail ── */}
      {tab === "Guardrail" && (
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
          {/* 내부 sub-tab */}
          <div className="flex border-b border-gray-200 -mx-5 px-5">
            {([
              ["G1", "border-blue-500 text-blue-700"],
              ["G2", "border-purple-500 text-purple-700"],
              ["G3", "border-indigo-500 text-indigo-700"],
            ] as const).map(([g, activeCls]) => {
              const active = guardrailSubTab === g;
              return (
                <button
                  key={g}
                  onClick={() => setGuardrailSubTab(g)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors font-mono ${
                    active ? activeCls : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {g}
                </button>
              );
            })}
          </div>

          {/* G1 */}
          {guardrailSubTab === "G1" && (
            <div className="space-y-4">
              <div>
                <h2 className="text-sm font-semibold mb-1">G1 · 정규식 가드레일</h2>
                <p className="text-xs text-gray-500">
                  모든 사용자(allow 포함) 무조건 적용. credential 패턴 및 위험 키워드 감지. 매칭되면 <b>block</b>.
                  기본 5개 패턴은 최초 로드 시 seed 되며, 자유롭게 수정/삭제/추가 가능. LLM 이 제안하는 G1 변경은 Approvals → Guardrail Diff 탭에서 승인.
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-gray-600">G1 정규식 ({g1Rows.length})</span>
                  <button
                    type="button"
                    onClick={() => setG1Rows((rows) => [...rows, makeG1Row()])}
                    className="px-2.5 py-1 text-xs rounded-lg bg-gray-900 text-white hover:bg-black"
                  >
                    + 추가
                  </button>
                </div>
                <div className="space-y-3">
                  {g1Rows.length === 0 && (
                    <button
                      type="button"
                      onClick={() => setG1Rows([makeG1Row()])}
                      className="w-full py-2 text-xs rounded-lg border border-dashed border-gray-300 text-gray-500 hover:bg-gray-50"
                    >
                      + 첫 패턴 추가
                    </button>
                  )}
                  {g1Rows.map((row) => (
                    <div key={row.id} className="rounded-lg border border-gray-200 bg-gray-50 p-3 space-y-1.5">
                      <div className="flex gap-2 items-center">
                        <input
                          value={row.pattern}
                          onChange={(e) =>
                            setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, pattern: e.target.value } : r)))
                          }
                          placeholder="(?i)\bproject-alpha\b"
                          className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono bg-white"
                        />
                        <select
                          value={row.mode}
                          onChange={(e) =>
                            setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, mode: e.target.value as G1Mode } : r)))
                          }
                          className="px-2 py-2 border border-gray-300 rounded-lg text-xs bg-white"
                          title="credential: 매칭값을 credential 치환 플로우로 / block: 즉시 차단"
                        >
                          <option value="credential">credential</option>
                          <option value="block">block</option>
                        </select>
                        <button
                          type="button"
                          onClick={() => setG1Rows((rows) => rows.filter((r) => r.id !== row.id))}
                          className="px-2.5 py-2 text-sm rounded-lg border border-gray-300 hover:bg-red-50 hover:text-red-600 bg-white"
                        >
                          −
                        </button>
                      </div>
                      <input
                        value={row.description}
                        onChange={(e) =>
                          setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, description: e.target.value } : r)))
                        }
                        placeholder="설명 (선택) — 이 패턴이 왜 필요한지"
                        className="w-full px-3 py-1 border border-transparent rounded text-[11px] text-gray-500 bg-transparent focus:bg-white focus:border-gray-300"
                      />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* G2 */}
          {guardrailSubTab === "G2" && (
            <div className="space-y-3">
              <div>
                <h2 className="text-sm font-semibold mb-1">G2 · 헌법 + LLM 가드레일</h2>
                <p className="text-xs text-gray-500">
                  ask 사용자 대상. 아래 헌법이 G2 LLM 시스템 프롬프트로 들어가서 allow/ask/block 판정.
                  LLM 은 <b>LLM Registry</b> 탭에서 <code>g2</code> 역할 바인딩한 모델 사용.
                </p>
              </div>
              <textarea
                value={constitution}
                onChange={(e) => setConstitution(e.target.value)}
                rows={10}
                placeholder="가드레일 헌법을 작성하세요..."
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
              />
            </div>
          )}

          {/* G3 */}
          {guardrailSubTab === "G3" && (
            <div className="space-y-3">
              <div>
                <h2 className="text-sm font-semibold mb-1">G3 · Wiki 적응형 가드레일</h2>
                <p className="text-xs text-gray-500">
                  G2 가 ask 로 애매한 경우 호출. 과거 HITL 결정(training log) 을 few-shot context 로 쓰는 자기진화 LLM.
                  ask 사용자 대상. G3 도 ask 면 사용자 본인 HITL 확인. LLM 은 <b>LLM Registry</b> 탭에서 <code>g3</code> 역할 바인딩한 모델 사용.
                </p>
              </div>
              <label className="block text-xs font-medium text-gray-600">추가 힌트 (G3 LLM 에 전달될 운영자 메모)</label>
              <textarea
                value={g3WikiHint}
                onChange={(e) => setG3WikiHint(e.target.value)}
                rows={10}
                placeholder={`예시:\n- 사내 code review 텍스트는 외부 전송 금지\n- project-alpha 관련 문서는 모두 ask`}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
              />
            </div>
          )}

          {/* 공통 하단 설명 */}
          <div className="p-3 rounded-lg bg-blue-50 border border-blue-200">
            <p className="text-xs text-blue-800">
              <b>흐름:</b> G1 통과 → G2 (ask 사용자만) → allow/ask/block. G2 가 ask 면 G3 호출 → allow/ask/block. G3 가 ask 면 사용자 본인 HITL 확인. 어느 단계든 LLM 미등록/연결실패 시 <b>fail-closed (차단)</b>. deny 사용자는 하향 전송 전면 금지.
            </p>
          </div>
        </section>
      )}

    </div>
  );
}
