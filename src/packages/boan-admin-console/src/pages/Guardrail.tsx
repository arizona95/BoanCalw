import { useCallback, useEffect, useMemo, useState } from "react";
import { guardrailApi, policyApi, type G1CustomPattern, type GI1ForbiddenImage, type GI2Description } from "../api";
import WikiGraph from "./WikiGraph";
import { ApprovalQueue } from "../components/ApprovalQueue";
import { usePolicyLiveSync } from "../lib/usePolicyLiveSync";

// Guardrail — 2-level 메뉴 구조:
//   text  → G1(정규식) · G2(헌법) · G3(Wiki) · HITL
//   image → G1(pHash) · G2(Vision-LLM)
// 내부적으로는 여전히 GT1/GI1 등으로 매핑되지만 UI 표면은 단순화.
// 저장은 partial policy PUT — network_whitelist / mount 규칙은 건드리지 않음.

type Category = "text" | "image";
type TextSub = "G1" | "G2" | "G3" | "HITL";
type ImageSub = "G1" | "G2";
// G1 모드:
//   block = 즉시 차단 (treatment 없음)
//   mask  = placeholder 로 치환 (예: {{phone-number}})
//   fake  = 형식 보존 가짜값 (예: 000-0000-0000)
type G1Mode = "block" | "mask" | "fake";
type G1PatternRow = {
  id: string;
  pattern: string;
  description: string;
  replacement: string;
  mode: G1Mode;
};

function normalizeMode(raw: string | undefined): G1Mode {
  // 레거시 'redact' / 'credential' → 'mask' 자동 매핑.
  if (raw === "block" || raw === "mask" || raw === "fake") return raw;
  return "mask";
}

function makeG1Row(seed?: Partial<G1PatternRow>): G1PatternRow {
  const mode: G1Mode = normalizeMode(seed?.mode as string | undefined);
  return {
    id: Math.random().toString(36).slice(2, 10),
    pattern: seed?.pattern ?? "",
    description: seed?.description ?? "",
    replacement: seed?.replacement ?? "",
    mode,
  };
}

export default function Guardrail() {
  // 초기 카테고리 + 서브탭 — `?cat=text&sub=G3` 또는 `?sub=GT3` (레거시) 지원.
  const { initialCategory, initialTextSub, initialImageSub } = ((): {
    initialCategory: Category;
    initialTextSub: TextSub;
    initialImageSub: ImageSub;
  } => {
    if (typeof window === "undefined")
      return { initialCategory: "text", initialTextSub: "G1", initialImageSub: "G1" };
    const params = new URLSearchParams(window.location.search);
    const cat = params.get("cat");
    const sub = params.get("sub");
    // 레거시 ?sub=GT1|GT2|GT3|GI1|GI2|G1|G2|G3|HITL → 새 cat+sub 매핑.
    const legacy: Record<string, { cat: Category; sub: string }> = {
      GT1: { cat: "text", sub: "G1" },
      GT2: { cat: "text", sub: "G2" },
      GT3: { cat: "text", sub: "G3" },
      GI1: { cat: "image", sub: "G1" },
      GI2: { cat: "image", sub: "G2" },
      G1: { cat: "text", sub: "G1" },
      G2: { cat: "text", sub: "G2" },
      G3: { cat: "text", sub: "G3" },
      HITL: { cat: "text", sub: "HITL" },
    };
    if (sub && legacy[sub]) {
      return {
        initialCategory: legacy[sub].cat,
        initialTextSub: (legacy[sub].cat === "text" ? legacy[sub].sub : "G1") as TextSub,
        initialImageSub: (legacy[sub].cat === "image" ? legacy[sub].sub : "G1") as ImageSub,
      };
    }
    const c: Category = cat === "image" ? "image" : "text";
    if (c === "text") {
      const ts: TextSub = sub === "G2" || sub === "G3" || sub === "HITL" ? sub : "G1";
      return { initialCategory: "text", initialTextSub: ts, initialImageSub: "G1" };
    }
    const is: ImageSub = sub === "G2" ? "G2" : "G1";
    return { initialCategory: "image", initialTextSub: "G1", initialImageSub: is };
  })();
  const [category, setCategory] = useState<Category>(initialCategory);
  const [textSub, setTextSub] = useState<TextSub>(initialTextSub);
  const [imageSub, setImageSub] = useState<ImageSub>(initialImageSub);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const [g1Rows, setG1Rows] = useState<G1PatternRow[]>([]);
  const [constitution, setConstitution] = useState("");
  const [g3WikiHint, setG3WikiHint] = useState("");
  const [gi1Forbidden, setGi1Forbidden] = useState<GI1ForbiddenImage[]>([]);
  const [gi1Threshold, setGi1Threshold] = useState<number>(10);
  const [gi1Uploading, setGi1Uploading] = useState(false);
  const [gi1Description, setGi1Description] = useState("");
  const [gi2Descriptions, setGi2Descriptions] = useState<GI2Description[]>([]);
  const [gi2Saving, setGi2Saving] = useState(false);
  const [policyVersion, setPolicyVersion] = useState<number>(0);

  // pullFresh — usePolicyLiveSync 가 SSE / 30s polling 이벤트마다 호출. 다른
  // admin 이 헌법 / G1 패턴 등을 바꾸면 이 페이지에 즉시 반영. markLocalEdit 는
  // save() 가 자기 자신의 echo 를 무시할 수 있게 해줌.
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
                mode: normalizeMode(g.mode as string | undefined),
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
                mode: normalizeMode(d.mode as string | undefined),
              })
            )
          );
        }
        setConstitution(p.guardrail?.constitution ?? "");
        setG3WikiHint(p.guardrail?.g3_wiki_hint ?? "");
        setGi1Forbidden(p.guardrail?.gi1_forbidden ?? []);
        setGi1Threshold(p.guardrail?.gi1_hamming_threshold ?? 10);
        setGi2Descriptions(p.guardrail?.gi2_descriptions ?? []);
      })
      .catch((e) => setMsg({ type: "err", text: e instanceof Error ? e.message : String(e) }))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);
  const pullFresh = useCallback(() => { load(); }, []);
  const { markLocalEdit } = usePolicyLiveSync(pullFresh);

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
    markLocalEdit();
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
            {category === "text"
              ? "텍스트: G1 (정규식) → G2 (헌법 + LLM) → G3 (Folder Wiki) → HITL"
              : "이미지: G1 (pHash) → G2 (Vision-LLM) → HITL (ask 시 텍스트 HITL 큐 공유)"}
            {loading ? " · 불러오는 중…" : ` · policy v${policyVersion}`}
          </p>
        </div>
        {category === "text" && textSub !== "HITL" && (
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
        {/* Level-1: 텍스트 / 이미지 카테고리 */}
        <div className="flex gap-1 -mx-5 px-5 pb-3">
          {([
            ["text", "텍스트"],
            ["image", "이미지"],
          ] as const).map(([c, label]) => {
            const active = category === c;
            return (
              <button
                key={c}
                onClick={() => setCategory(c)}
                className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                  active ? "bg-boan-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Level-2: 카테고리별 sub-tab */}
        <div className="flex border-b border-gray-200 -mx-5 px-5 overflow-x-auto">
          {category === "text" &&
            (
              [
                ["G1", "border-blue-500 text-blue-700"],
                ["G2", "border-purple-500 text-purple-700"],
                ["G3", "border-indigo-500 text-indigo-700"],
                ["HITL", "border-orange-500 text-orange-700"],
              ] as const
            ).map(([g, activeCls]) => {
              const active = textSub === g;
              return (
                <button
                  key={g}
                  onClick={() => setTextSub(g)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors font-mono ${
                    active ? activeCls : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {g}
                </button>
              );
            })}
          {category === "image" &&
            (
              [
                ["G1", "border-teal-500 text-teal-700"],
                ["G2", "border-emerald-500 text-emerald-700"],
              ] as const
            ).map(([g, activeCls]) => {
              const active = imageSub === g;
              return (
                <button
                  key={g}
                  onClick={() => setImageSub(g)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors font-mono ${
                    active ? activeCls : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {g}
                </button>
              );
            })}
        </div>

        {/* 텍스트 · G1 (정규식) */}
        {category === "text" && textSub === "G1" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold mb-1">GT1 · 텍스트 정규식 가드레일</h2>
              <p className="text-xs text-gray-500">
                모든 사용자(allow 포함) 무조건 적용. 매칭되면 동작 분기:
                {" "}<b>block</b>(즉시 차단) /
                {" "}<b>mask</b>(placeholder 로 치환 — <code>{"{{phone-number}}"}</code>) /
                {" "}<b>fake</b>(형식 보존 가짜값 — <code>000-0000-0000</code>).<br />
                예: <code className="font-mono text-[11px]">폰번호 → <span className="text-blue-600">{"{{GT1::phone_number}}"}</span></code>.
                {" "}한 줄 = 한 가지 감지 대상.
              </p>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-gray-600">GT1 정규식 ({g1Rows.length})</span>
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
                        value={row.mode === "block" ? "" : row.replacement}
                        onChange={(e) =>
                          setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, replacement: e.target.value } : r)))
                        }
                        placeholder={
                          row.mode === "block"
                            ? "block 모드 — 치환값 사용 안 함"
                            : row.mode === "fake"
                              ? "000-0000-0000"
                              : "{{phone-number}}"
                        }
                        disabled={row.mode === "block"}
                        className="w-56 px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono bg-white disabled:bg-gray-100 disabled:text-gray-400"
                        title={
                          row.mode === "block"
                            ? "block: 매칭되면 즉시 차단. 치환값 사용 안 함."
                            : row.mode === "fake"
                              ? "fake: 매칭 부분을 형식 보존한 가짜값으로 치환 (예: 000-0000-0000)"
                              : "mask: 매칭 부분을 placeholder 로 치환 (의미 가림)"
                        }
                      />
                      <select
                        value={row.mode}
                        onChange={(e) =>
                          setG1Rows((rows) => rows.map((r) => (r.id === row.id ? { ...r, mode: e.target.value as G1Mode } : r)))
                        }
                        className="px-2 py-2 border border-gray-300 rounded-lg text-xs bg-white"
                        title="block: 즉시 차단 / mask: placeholder 치환 / fake: 형식 보존 가짜값"
                      >
                        <option value="block">block</option>
                        <option value="mask">mask</option>
                        <option value="fake">fake</option>
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

        {/* 텍스트 · G2 (헌법 + LLM) */}
        {category === "text" && textSub === "G2" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold mb-1">GT2 · 텍스트 헌법 + LLM 가드레일</h2>
              <p className="text-xs text-gray-500">
                ask 사용자 대상. 아래 헌법이 GT2 LLM 시스템 프롬프트로 들어가서 allow/ask/block 판정.
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

        {/* 텍스트 · G3 (Folder Wiki) */}
        {category === "text" && textSub === "G3" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold mb-1">GT3 · 텍스트 Folder Wiki (자기진화 가드레일)</h2>
              <p className="text-xs text-gray-500">
                GT2 가 ask 로 애매한 경우 호출. 과거 HITL 결정 + Folder Wiki 를 few-shot context 로 쓰는 자기진화 LLM.
                아래는 Wiki 본체 — LLM 이 agentic loop 로 스스로 편집하는 skill tree + 대화 기록 + HITL 라벨 fix.
                LLM 은 <b>LLM Registry</b> 탭에서 <code>g3</code> / <code>agentic_iterate</code> 역할 바인딩.
              </p>
            </div>
            <div className="h-[calc(100vh-280px)] min-h-[520px] -mx-6 border-y border-gray-200 bg-gray-50 flex">
              <WikiGraph />
            </div>
            <details className="text-xs">
              <summary className="cursor-pointer text-gray-500 hover:text-gray-700 py-1">
                ▸ GT3 LLM 에 전달될 운영자 메모 (Advanced)
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

        {/* 이미지 · G1 (pHash 차단 리스트) */}
        {category === "image" && imageSub === "G1" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold mb-1">GI1 · 이미지 perceptual-hash 차단 리스트</h2>
              <p className="text-xs text-gray-500">
                통과되면 안 되는 이미지(예: 사내 회로도, 도면)를 업로드하면 device 에서 64-bit pHash 를 추출해 정책에 저장.
                들어오는 이미지의 pHash 와 Hamming distance ≤ 임계값이면 차단/치환.
                <b className="text-teal-700"> 이미지 바이트는 cloud 로 전송되지 않음</b> — pHash 16-hex 만 올라감.
                모든 사용자(allow 포함) 무조건 적용.
              </p>
            </div>

            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 space-y-2">
              <div className="text-xs font-medium text-gray-700">Hamming distance 임계값</div>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={0}
                  max={32}
                  value={gi1Threshold}
                  onChange={(e) => setGi1Threshold(Number(e.target.value))}
                  className="flex-1"
                />
                <span className="text-xs font-mono w-12 text-right">{gi1Threshold} bits</span>
                <button
                  type="button"
                  onClick={async () => {
                    markLocalEdit();
                    try {
                      await guardrailApi.gi1SetThreshold(gi1Threshold);
                      setMsg({ type: "ok", text: "임계값 저장됨" });
                    } catch (e) {
                      setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" });
                    }
                  }}
                  className="px-3 py-1 text-xs rounded-lg bg-gray-900 text-white hover:bg-black"
                >
                  적용
                </button>
              </div>
              <p className="text-[11px] text-gray-500">
                0 = 완전 일치만 차단 / 10 = 약간 변형(리사이즈/색조 보정)까지 / 20 이상 = 오탐 위험.
              </p>
            </div>

            <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 space-y-2">
              <div className="text-xs font-medium text-gray-700">새 차단 이미지 업로드</div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={gi1Description}
                  onChange={(e) => setGi1Description(e.target.value)}
                  placeholder="설명 (예: 사내 회로도 — Q3 신제품)"
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-xs bg-white"
                />
                <label className="px-3 py-2 text-xs rounded-lg bg-teal-600 text-white hover:bg-teal-700 cursor-pointer">
                  {gi1Uploading ? "업로드 중…" : "📁 파일 선택"}
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/gif"
                    className="hidden"
                    disabled={gi1Uploading}
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      setGi1Uploading(true);
                      markLocalEdit();
                      try {
                        const res = await guardrailApi.gi1Upload(file, gi1Description, "");
                        if (res.duplicate) {
                          setMsg({ type: "ok", text: `이미 등록된 해시: ${res.hash}` });
                        } else {
                          setMsg({ type: "ok", text: `해시 ${res.hash} 추가됨` });
                        }
                        setGi1Description("");
                        load();
                      } catch (err) {
                        setMsg({ type: "err", text: err instanceof Error ? err.message : "업로드 실패" });
                      } finally {
                        setGi1Uploading(false);
                        e.target.value = "";
                      }
                    }}
                  />
                </label>
              </div>
            </div>

            <div>
              <div className="text-xs font-medium text-gray-600 mb-2">
                차단 리스트 ({gi1Forbidden.length})
              </div>
              {gi1Forbidden.length === 0 ? (
                <div className="text-xs text-gray-400 italic px-3 py-6 text-center border border-dashed border-gray-200 rounded-lg">
                  아직 등록된 차단 이미지가 없습니다.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {gi1Forbidden.map((img) => (
                    <div key={img.hash} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-white border border-gray-200">
                      <code className="text-[11px] font-mono text-gray-600 w-40">{img.hash}</code>
                      <span className="flex-1 text-xs text-gray-800 truncate">
                        {img.description || <span className="italic text-gray-400">설명 없음</span>}
                      </span>
                      {img.uploaded_at && (
                        <span className="text-[10px] text-gray-400">
                          {new Date(img.uploaded_at).toLocaleDateString()}
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={async () => {
                          markLocalEdit();
                          try {
                            await guardrailApi.gi1Delete(img.hash);
                            setMsg({ type: "ok", text: `해시 ${img.hash} 삭제됨` });
                            load();
                          } catch (err) {
                            setMsg({ type: "err", text: err instanceof Error ? err.message : "삭제 실패" });
                          }
                        }}
                        className="px-2 py-1 text-[11px] rounded border border-gray-300 hover:bg-red-50 hover:text-red-600 hover:border-red-200"
                      >
                        삭제
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 이미지 · G2 (Vision-LLM 설명 매칭) */}
        {category === "image" && imageSub === "G2" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-sm font-semibold mb-1">GI2 · Vision-LLM 이미지 설명 매칭</h2>
              <p className="text-xs text-gray-500">
                GI1 을 통과한 이미지에 대해 Vision-LLM 이 자연어 설명과 비교. 매칭되면 action 에 따라
                <b>ask</b>(사용자 approval 큐로) 또는 <b>block</b>(즉시 차단).
                LLM 은 <b>LLM Registry</b> 탭에서 <code>vision</code> 역할 바인딩한 모델 사용 — 미바인딩 시 GI2 가 fail-open (통과).
              </p>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-gray-600">차단 설명 ({gi2Descriptions.length})</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setGi2Descriptions((arr) => [...arr, { description: "", action: "ask" }])}
                    className="px-2.5 py-1 text-xs rounded-lg bg-gray-900 text-white hover:bg-black"
                  >
                    + 추가
                  </button>
                  <button
                    type="button"
                    disabled={gi2Saving}
                    onClick={async () => {
                      setGi2Saving(true);
                      markLocalEdit();
                      try {
                        const cleaned = gi2Descriptions
                          .map((d) => ({ description: d.description.trim(), action: d.action || "ask" }))
                          .filter((d) => d.description.length > 0);
                        await guardrailApi.gi2SetDescriptions(cleaned);
                        setGi2Descriptions(cleaned);
                        setMsg({ type: "ok", text: `GI2 설명 ${cleaned.length}개 저장됨` });
                      } catch (e) {
                        setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" });
                      } finally {
                        setGi2Saving(false);
                      }
                    }}
                    className="px-3 py-1 text-xs rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-50"
                  >
                    {gi2Saving ? "저장 중…" : "💾 GI2 저장"}
                  </button>
                </div>
              </div>
              {gi2Descriptions.length === 0 ? (
                <div className="text-xs text-gray-400 italic px-3 py-6 text-center border border-dashed border-gray-200 rounded-lg">
                  등록된 차단 설명이 없습니다. "+ 추가" 로 새 설명을 만드세요.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {gi2Descriptions.map((d, idx) => (
                    <div key={idx} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white border border-gray-200">
                      <input
                        value={d.description}
                        onChange={(e) =>
                          setGi2Descriptions((arr) => arr.map((x, i) => (i === idx ? { ...x, description: e.target.value } : x)))
                        }
                        placeholder="예: 회로도, 도면, 스키매틱"
                        className="flex-1 px-3 py-1.5 border border-gray-300 rounded-lg text-xs bg-white"
                      />
                      <select
                        value={d.action || "ask"}
                        onChange={(e) =>
                          setGi2Descriptions((arr) => arr.map((x, i) => (i === idx ? { ...x, action: e.target.value as "ask" | "block" } : x)))
                        }
                        className="px-2 py-1.5 border border-gray-300 rounded-lg text-xs bg-white"
                        title="ask: HITL 큐로 라우팅 / block: 즉시 차단"
                      >
                        <option value="ask">ask</option>
                        <option value="block">block</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => setGi2Descriptions((arr) => arr.filter((_, i) => i !== idx))}
                        className="px-2 py-1 text-[11px] rounded border border-gray-300 hover:bg-red-50 hover:text-red-600 hover:border-red-200"
                      >
                        삭제
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 텍스트 · HITL — GT/GI 양쪽 ask + 가드레일 amendment 큐 */}
        {category === "text" && textSub === "HITL" && (
          <div className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold mb-1">HITL · 가드레일 승인 큐</h2>
              <p className="text-xs text-gray-500">
                GT3 wiki LLM 이 자동 제안한 GT1 정규식 / GT2 헌법 변경안 + 크리티컬 input-gate 차단 검토 + GI2 ask 결정.
                Approve 시 정책에 즉시 반영. 사용자 가입 같은 일반 승인은 <a href="/approvals" className="text-blue-600 underline">User Actions</a> 페이지에서.
              </p>
            </div>
            <ApprovalQueue category="guardrail" emptyText="대기 중인 가드레일 승인이 없습니다." />
          </div>
        )}

        <div className="p-3 rounded-lg bg-blue-50 border border-blue-200">
          {category === "text" ? (
            <p className="text-xs text-blue-800">
              <b>흐름:</b> G1(정규식) 통과 → G2(헌법 + LLM, ask 사용자만) → allow/ask/block.
              G2 가 ask 면 G3(Folder Wiki) 호출 → allow/ask/block. G3 가 ask 면 사용자 HITL.
              어느 단계든 LLM 미등록/연결실패 시 <b>fail-closed (차단)</b>. deny 사용자는 하향 전송 전면 금지.
            </p>
          ) : (
            <p className="text-xs text-blue-800">
              <b>흐름:</b> G1(pHash 차단 리스트) 통과 → G2(Vision-LLM 설명 매칭) → 매칭되면 ask/block.
              ask 는 텍스트 카테고리의 HITL 큐로 라우팅. vision LLM 미바인딩 시 <b>G2 는 fail-open (통과)</b>.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
