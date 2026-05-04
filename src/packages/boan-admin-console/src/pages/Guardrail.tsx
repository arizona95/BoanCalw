import { useEffect, useMemo, useState } from "react";
import { guardrailApi, policyApi, type G1CustomPattern } from "../api";
import WikiGraph from "./WikiGraph";
import { ApprovalQueue } from "../components/ApprovalQueue";

// Guardrail — G1 (정규식) / G2 (헌법) / G3 (Folder Wiki) / HITL (가드레일 승인 큐) 4 탭.
// 예전엔 Gateway Policies 의 sub-tab 이었지만 보안 코어라 상위 사이드바로 분리.
// 저장은 partial policy PUT — network_whitelist / mount 규칙은 건드리지 않음.
// HITL 탭은 가드레일이 자동 제안한 G1/G2 amendment + critical input-gate 차단 검토만.
// 사용자 가입/credential 등록 등 비-가드레일 승인은 /approvals 페이지에서 따로 본다.

type SubTab = "G1" | "G2" | "G3" | "HITL";
type G1Mode = "redact" | "credential" | "block";
type G1PatternRow = {
  id: string;
  pattern: string;
  description: string;
  replacement: string;
  mode: G1Mode;
};

function makeG1Row(seed?: Partial<G1PatternRow>): G1PatternRow {
  const mode: G1Mode =
    seed?.mode === "credential" || seed?.mode === "block" || seed?.mode === "redact"
      ? seed.mode
      : "redact";
  return {
    id: Math.random().toString(36).slice(2, 10),
    pattern: seed?.pattern ?? "",
    description: seed?.description ?? "",
    replacement: seed?.replacement ?? "",
    mode,
  };
}

export default function Guardrail() {
  // 초기 sub-tab — `?sub=G3` 딥링크 지원 (예: /wiki-graph 리다이렉트).
  const initialSub = ((): SubTab => {
    if (typeof window === "undefined") return "G1";
    const s = new URLSearchParams(window.location.search).get("sub");
    if (s === "G1" || s === "G2" || s === "G3" || s === "HITL") return s;
    return "G1";
  })();
  const [sub, setSub] = useState<SubTab>(initialSub);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const [g1Rows, setG1Rows] = useState<G1PatternRow[]>([]);
  const [constitution, setConstitution] = useState("");
  const [g3WikiHint, setG3WikiHint] = useState("");
  const [policyVersion, setPolicyVersion] = useState<number>(0);

  const load = () => {
    setLoading(true);
    Promise.all([
      policyApi.get(),
      guardrailApi.g1Defaults().catch(() => ({ patterns: [] })),
    ])
      .then(([p, g1Defaults]) => {
        setPolicyVersion(p.version ?? 0);
        const storedG1 = p.guardrail?.g1_custom_patterns ?? [];
        if (storedG1.length > 0) {
          setG1Rows(
            storedG1.map((g) =>
              makeG1Row({
                pattern: g.pattern,
                description: g.description ?? "",
                replacement: g.replacement ?? "",
                mode: g.mode as G1Mode,
              })
            )
          );
        } else {
          // 정책에 custom 이 없으면 서버에서 받은 기본 시드로 편집 가능한 행을 채움.
          setG1Rows(
            (g1Defaults.patterns ?? []).map((d) =>
              makeG1Row({
                pattern: d.pattern,
                description: d.description,
                replacement: d.replacement,
                mode:
                  d.mode === "redact" || d.mode === "credential" || d.mode === "block"
                    ? (d.mode as G1Mode)
                    : "redact",
              })
            )
          );
        }
        setConstitution(p.guardrail?.constitution ?? "");
        setG3WikiHint(p.guardrail?.g3_wiki_hint ?? "");
      })
      .catch((e) => setMsg({ type: "err", text: e instanceof Error ? e.message : String(e) }))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const cleanedG1: G1CustomPattern[] = useMemo(
    () =>
      g1Rows
        .map((r) => ({
          pattern: r.pattern.trim(),
          description: r.description.trim(),
          replacement: r.replacement.trim(),
          mode: r.mode,
        }))
        .filter((r) => r.pattern.length > 0),
    [g1Rows]
  );

  const save = async () => {
    setMsg(null);
    setSaving(true);
    try {
      // guardrail 만 부분 업데이트 — network_whitelist / org_settings 은 건드리지 않음.
      const updated = await policyApi.update({
        guardrail: {
          g1_custom_patterns: cleanedG1,
          constitution: constitution.trim(),
          g3_wiki_hint: g3WikiHint.trim(),
        },
      });
      setPolicyVersion(updated.version ?? policyVersion + 1);
      setMsg({ type: "ok", text: "저장됨" });
    } catch (e) {
      setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" });
    } finally {
      setSaving(false);
    }
  };

  const rollback = async () => {
    setMsg(null);
    setSaving(true);
    try {
      await policyApi.rollback();
      load();
      setMsg({ type: "ok", text: "롤백 완료" });
    } catch (e) {
      setMsg({ type: "err", text: e instanceof Error ? e.message : "롤백 실패" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6 max-w-6xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Guardrail</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            G1 (정규식) → G2 (헌법 + LLM) → G3 (Folder Wiki 자기진화) 3 단계 가드레일.
            {loading ? " 불러오는 중…" : ` · policy v${policyVersion}`}
          </p>
        </div>
        {sub !== "HITL" && (
          <div className="flex gap-2">
            <button
              onClick={rollback}
              disabled={saving || loading}
              className="px-3 py-1.5 text-xs rounded-lg border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-50"
            >
              Rollback
            </button>
            <button
              onClick={save}
              disabled={saving || loading}
              className="px-4 py-1.5 text-xs rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50 font-medium"
            >
              {saving ? "저장 중…" : "Save"}
            </button>
          </div>
        )}
      </div>

      {msg && (
        <div
          className={`mb-3 px-3 py-2 rounded-lg text-xs ${
            msg.type === "ok" ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"
          }`}
        >
          {msg.text}
        </div>
      )}

      <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
        {/* Sub-tab */}
        <div className="flex border-b border-gray-200 -mx-5 px-5">
          {([
            ["G1", "border-blue-500 text-blue-700"],
            ["G2", "border-purple-500 text-purple-700"],
            ["G3", "border-indigo-500 text-indigo-700"],
            ["HITL", "border-orange-500 text-orange-700"],
          ] as const).map(([g, activeCls]) => {
            const active = sub === g;
            return (
              <button
                key={g}
                onClick={() => setSub(g)}
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
        {sub === "G1" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold mb-1">G1 · 정규식 가드레일</h2>
              <p className="text-xs text-gray-500">
                모든 사용자(allow 포함) 무조건 적용. 매칭되면 동작 분기:
                {" "}<b>redact</b>(매칭 부분을 치환값으로 교체 후 통과) /
                {" "}<b>credential</b>(자격증명 플로우, legacy) /
                {" "}<b>block</b>(즉시 차단).<br />
                예: <code className="font-mono text-[11px]">폰번호 → <span className="text-blue-600">{"{{G1::phone_number}}"}</span></code>.
                {" "}한 줄 = 한 가지 감지 대상.
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
                        placeholder="(?i)\b01[016-9][-.\s]?\d{3,4}[-.\s]?\d{4}\b"
                        className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono bg-white"
                        title="정규식 (Go syntax, (?i) 등 지원)"
                      />
                      <span className="text-xs text-gray-400 select-none">→</span>
                      <input
                        value={row.replacement}
                        onChange={(e) =>
                          setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, replacement: e.target.value } : r)))
                        }
                        placeholder="{{G1::phone_number}}"
                        className="w-56 px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono bg-white"
                        title="매칭된 텍스트를 이 값으로 치환. 비우고 모드를 block 으로 하면 차단."
                      />
                      <select
                        value={row.mode}
                        onChange={(e) =>
                          setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, mode: e.target.value as G1Mode } : r)))
                        }
                        className="px-2 py-2 border border-gray-300 rounded-lg text-xs bg-white"
                        title="redact: 치환해서 통과 / credential: 자격증명 플로우 / block: 즉시 차단"
                      >
                        <option value="redact">redact</option>
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
        {sub === "G2" && (
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

        {/* G3 — Folder Wiki embed */}
        {sub === "G3" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold mb-1">G3 · Folder Wiki (자기진화 가드레일)</h2>
              <p className="text-xs text-gray-500">
                G2 가 ask 로 애매한 경우 호출. 과거 HITL 결정 + Folder Wiki 를 few-shot context 로 쓰는 자기진화 LLM.
                아래는 Wiki 본체 — LLM 이 agentic loop 로 스스로 편집하는 skill tree + 대화 기록 + HITL 라벨 fix.
                LLM 은 <b>LLM Registry</b> 탭에서 <code>g3</code> / <code>agentic_iterate</code> 역할 바인딩.
              </p>
            </div>
            <div className="h-[calc(100vh-280px)] min-h-[520px] -mx-6 border-y border-gray-200 bg-gray-50 flex">
              <WikiGraph />
            </div>
            <details className="text-xs">
              <summary className="cursor-pointer text-gray-500 hover:text-gray-700 py-1">
                ▸ G3 LLM 에 전달될 운영자 메모 (Advanced)
              </summary>
              <textarea
                value={g3WikiHint}
                onChange={(e) => setG3WikiHint(e.target.value)}
                rows={6}
                placeholder={`예시:\n- 사내 code review 텍스트는 외부 전송 금지\n- project-alpha 관련 문서는 모두 ask`}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm mt-2"
              />
            </details>
          </div>
        )}

        {/* HITL — 가드레일이 자동 제안한 G1/G2 amendment + critical input-gate 차단 검토 */}
        {sub === "HITL" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold mb-1">HITL · 가드레일 승인 큐</h2>
              <p className="text-xs text-gray-500">
                G3 wiki LLM 이 자동 제안한 G1 정규식 / G2 헌법 변경안 + 크리티컬 input-gate 차단 검토.
                Approve 시 정책에 즉시 반영. 사용자 가입 같은 일반 승인은 <a href="/approvals" className="text-blue-600 underline">User Actions</a> 페이지에서.
              </p>
            </div>
            <ApprovalQueue category="guardrail" emptyText="대기 중인 가드레일 승인이 없습니다." />
          </div>
        )}

        <div className="p-3 rounded-lg bg-blue-50 border border-blue-200">
          <p className="text-xs text-blue-800">
            <b>흐름:</b> G1 통과 → G2 (ask 사용자만) → allow/ask/block. G2 가 ask 면 G3 호출 → allow/ask/block. G3 가 ask 면 사용자 본인 HITL 확인.
            어느 단계든 LLM 미등록/연결실패 시 <b>fail-closed (차단)</b>. deny 사용자는 하향 전송 전면 금지.
          </p>
        </div>
      </section>
    </div>
  );
}
