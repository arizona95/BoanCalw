import { useEffect, useState, useCallback, Fragment } from "react";

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
  // 텍스트 게이트
  G1_txt: "bg-blue-50 text-blue-700 border-blue-200",
  G2_txt: "bg-purple-50 text-purple-700 border-purple-200",
  G3_txt: "bg-indigo-50 text-indigo-700 border-indigo-200",
  // 이미지 게이트
  G1_img: "bg-teal-50 text-teal-700 border-teal-200",
  G2_img: "bg-emerald-50 text-emerald-700 border-emerald-200",
  // 파일 분류 (text/image 외 drop)
  classify: "bg-gray-100 text-gray-700 border-gray-300",
  // 레거시 (혹시 잔존 trace)
  G1: "bg-blue-50 text-blue-700 border-blue-200",
  G2: "bg-purple-50 text-purple-700 border-purple-200",
  G3: "bg-indigo-50 text-indigo-700 border-indigo-200",
  GI1: "bg-teal-50 text-teal-700 border-teal-200",
  GI2: "bg-emerald-50 text-emerald-700 border-emerald-200",
  // 기타
  DLP: "bg-emerald-50 text-emerald-700 border-emerald-200",
  access: "bg-red-50 text-red-700 border-red-300",
  "G1+credential": "bg-amber-50 text-amber-700 border-amber-200",
  key: "bg-gray-50 text-gray-600 border-gray-200",
  chord: "bg-gray-50 text-gray-600 border-gray-200",
  clipboard: "bg-gray-50 text-gray-600 border-gray-200",
  mode: "bg-gray-50 text-gray-600 border-gray-200",
};

// Top-level 카테고리:
//   file-manager : S2↔S1 파일 전송 (방향 sub-tab: S2→S1 outbound / S1→S2 inbound)
//   boanclaw     : LLM 채팅 (type=chat)
//   guardrail    : 가드레일 차단/평가 이벤트 (type=guardrail)
type Category = "file-manager" | "boanclaw" | "guardrail";
type Direction = "outbound" | "inbound";
const PAGE_SIZE = 50;

export default function Observability() {
  const [category, setCategory] = useState<Category>("file-manager");
  const [direction, setDirection] = useState<Direction>("outbound");
  const [data, setData] = useState<TracesResponse>({ total: 0, offset: 0, limit: PAGE_SIZE, traces: [] });
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  // 행 펼치기 — id 별로 토글. 처음엔 다 접힌 상태.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const load = useCallback(() => {
    // category/direction 은 client-side 필터 (backend 미지원).
    // limit 을 PAGE_SIZE 의 4 배로 가져와서 카테고리 필터 후에도 한 페이지 채우게.
    const params = new URLSearchParams({ limit: String(PAGE_SIZE * 4), offset: String(page * PAGE_SIZE) });
    if (query) params.set("q", query);
    fetch(`/api/observability/traces?${params}`, { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setData(d))
      .catch(() => setData({ total: 0, offset: 0, limit: PAGE_SIZE, traces: [] }))
      .finally(() => setLoading(false));
  }, [query, page]);

  // 카테고리로 필터링한 trace 목록. file-manager 는 추가로 direction 으로 한번 더 필터.
  const filteredTraces = data.traces.filter((t) => {
    if (category === "file-manager") return t.type === "file" && t.direction === direction;
    if (category === "boanclaw") return t.type === "chat";
    if (category === "guardrail") return t.type === "guardrail";
    return true;
  });

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (autoRefresh && page === 0) {
      const interval = setInterval(load, 3000);
      return () => clearInterval(interval);
    }
  }, [load, autoRefresh, page]);

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
          <span className="text-xs text-gray-400">
            {category === "file-manager"
              ? `${direction === "outbound" ? "S2→S1" : "S1→S2"}`
              : category === "boanclaw"
                ? "BoanClaw"
                : "Guardrail"}{" "}
            {filteredTraces.length} / 전체 {data.total}
          </span>
          <label className="flex items-center gap-1 text-xs text-gray-500">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Auto (3s)
          </label>
          <button onClick={load} className="text-xs text-boan-600 hover:underline">Refresh</button>
          <button onClick={clearLogs} className="text-xs text-red-500 hover:underline">Clear All</button>
        </div>
      </div>

      {/* Level 1: 카테고리 (File Manager / BoanClaw / Guardrail) */}
      <div className="flex gap-1 mb-3">
        {(
          [
            ["file-manager", "📁 File Manager"],
            ["boanclaw", "💬 BoanClaw"],
            ["guardrail", "🛡 Guardrail"],
          ] as const
        ).map(([c, label]) => (
          <button
            key={c}
            onClick={() => setCategory(c)}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              category === c ? "bg-boan-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Level 2: 방향 (File Manager 일 때만) */}
      {category === "file-manager" && (
        <div className="flex border-b border-gray-200 mb-4">
          {(
            [
              ["outbound", "S2 → S1"],
              ["inbound", "S1 → S2"],
            ] as const
          ).map(([d, label]) => (
            <button
              key={d}
              onClick={() => setDirection(d)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                direction === d ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      <div>
          <div className="flex gap-2 mb-3 items-center">
            <input
              value={query} onChange={(e) => { setQuery(e.target.value); setPage(0); }}
              placeholder="Search..."
              className="ml-auto px-3 py-1 border border-gray-300 rounded-lg text-xs w-48"
            />
          </div>

          {loading && filteredTraces.length === 0 ? (
            <p className="text-gray-400 text-sm">Loading...</p>
          ) : filteredTraces.length === 0 ? (
            <p className="text-gray-400 text-sm text-center py-8">
              {category === "file-manager"
                ? direction === "outbound" ? "S2→S1 traces 없음" : "S1→S2 traces 없음"
                : category === "boanclaw" ? "BoanClaw chat traces 없음"
                : "Guardrail events 없음"}
            </p>
          ) : (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-gray-50 border-b text-gray-500">
                  <tr>
                    <th className="w-6 px-2 py-2 text-left"></th>
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
                  {filteredTraces.map((t) => {
                    const tier = (t.meta?.tier as string) || t.gate || "";
                    const reason = (t.meta?.reason as string) || "";
                    const accessLevel = (t.meta?.access_level as string) || "";
                    const isOpen = !!expanded[t.id];
                    const toggle = () => setExpanded((prev) => ({ ...prev, [t.id]: !prev[t.id] }));
                    return (
                      <Fragment key={t.id}>
                        <tr className="hover:bg-gray-50 align-top">
                          <td className="px-2 py-2 align-top">
                            <button
                              type="button"
                              onClick={toggle}
                              className="text-gray-400 hover:text-gray-700 font-mono text-xs select-none w-4 text-center"
                              title={isOpen ? "접기" : "펼치기"}
                            >
                              {isOpen ? "▼" : "▶"}
                            </button>
                          </td>
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
                        {isOpen && (
                          <tr className="bg-gray-50">
                            <td></td>
                            <td colSpan={8} className="px-4 py-3 text-xs text-gray-700">
                              <div className="mb-2">
                                <div className="text-[11px] text-gray-400 font-semibold mb-1">Summary (full)</div>
                                <pre className="whitespace-pre-wrap break-words font-mono text-[11px] bg-white border border-gray-200 rounded p-2 max-h-80 overflow-y-auto">{t.summary || "—"}</pre>
                              </div>
                              {reason && (
                                <div className="mb-2">
                                  <div className="text-[11px] text-gray-400 font-semibold mb-1">Reason</div>
                                  <div className="text-[11px] text-gray-600">{reason}</div>
                                </div>
                              )}
                              {t.meta && Object.keys(t.meta).length > 0 && (
                                <div>
                                  <div className="text-[11px] text-gray-400 font-semibold mb-1">Meta</div>
                                  <pre className="text-[10px] font-mono bg-white border border-gray-200 rounded p-2 overflow-x-auto">{JSON.stringify(t.meta, null, 2)}</pre>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </Fragment>
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
    </div>
  );
}
