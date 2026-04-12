import { useEffect, useState } from "react";

interface WikiEntry {
  timestamp: string;
  text: string;
  mode: string;
  flagged_reason: string;
  decision: string;
  reasoning: string;
  confidence: number;
  source: string;
}

interface WikiPage {
  path: string;
  title: string;
  updated_at: string;
  size: number;
  content: string;
}

interface WikiData {
  entries: WikiEntry[];
  stats: {
    total: number;
    human: number;
    auto: number;
    approve: number;
    reject: number;
  };
  wiki_pages: WikiPage[];
  wiki_index: {
    index?: string;
    pages?: { path: string; title: string; updated_at: string; size: number }[];
  } | null;
}

type TabType = "raw" | "wiki";

export default function Wiki() {
  const [data, setData] = useState<WikiData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabType>("wiki");
  const [selectedPage, setSelectedPage] = useState<string | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [compileMsg, setCompileMsg] = useState("");

  const fetchData = () => {
    setLoading(true);
    fetch("/api/admin/wiki", { credentials: "include" })
      .then((r) => r.json())
      .then((d) => {
        setData(d);
        // Auto-select first wiki page if none selected
        if (!selectedPage && d.wiki_pages && d.wiki_pages.length > 0) {
          const indexPage = d.wiki_pages.find((p: WikiPage) => p.path === "index.md");
          setSelectedPage(indexPage ? "index.md" : d.wiki_pages[0].path);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCompile = async () => {
    setCompiling(true);
    setCompileMsg("");
    try {
      const r = await fetch("/api/admin/wiki/compile", {
        method: "POST",
        credentials: "include",
      });
      const result = await r.json();
      if (result.error) {
        setCompileMsg("Compile failed: " + result.error);
      } else {
        setCompileMsg("Compilation complete");
        fetchData();
      }
    } catch (e) {
      setCompileMsg("Compile error: " + String(e));
    } finally {
      setCompiling(false);
    }
  };

  if (loading) return <p className="text-gray-400 p-6">Loading...</p>;
  if (!data) return <p className="text-red-400 p-6">Wiki data not available</p>;

  const { entries, stats, wiki_pages, wiki_index } = data;
  const selectedContent = wiki_pages?.find((p) => p.path === selectedPage);

  // Extract last compiled time from wiki_index
  const lastCompiled = wiki_index?.index
    ? (() => {
        const match = wiki_index.index.match(/Last compiled: (.+)/);
        return match ? match[1] : null;
      })()
    : null;

  // Organize pages into groups
  const groupPages = (pages: WikiPage[]) => {
    const root: WikiPage[] = [];
    const patterns: WikiPage[] = [];
    const proposals: WikiPage[] = [];
    for (const p of pages || []) {
      if (p.path.startsWith("patterns/")) patterns.push(p);
      else if (p.path.startsWith("proposals/")) proposals.push(p);
      else root.push(p);
    }
    return { root, patterns, proposals };
  };

  const groups = groupPages(wiki_pages || []);

  return (
    <div className="p-6 max-w-6xl">
      <h1 className="text-xl font-bold text-gray-800 mb-2">G3 Wiki</h1>
      <p className="text-sm text-gray-500 mb-4">
        G3 wiki 가 학습한 HITL 결정 로그. 이 데이터가 가드레일 자동 판단과 헌법 개정 제안의 근거가 됩니다.
      </p>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3 mb-4">
        <StatCard label="전체" value={stats.total} color="text-gray-700" />
        <StatCard label="사람 결정" value={stats.human} color="text-blue-600" />
        <StatCard label="자동 판단" value={stats.auto} color="text-purple-600" />
        <StatCard label="승인" value={stats.approve} color="text-green-600" />
        <StatCard label="거부" value={stats.reject} color="text-red-600" />
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 mb-4">
        <button
          className={`px-4 py-2 text-sm font-medium border-b-2 ${
            activeTab === "wiki"
              ? "border-blue-500 text-blue-600"
              : "border-transparent text-gray-500 hover:text-gray-700"
          }`}
          onClick={() => setActiveTab("wiki")}
        >
          Wiki
        </button>
        <button
          className={`px-4 py-2 text-sm font-medium border-b-2 ${
            activeTab === "raw"
              ? "border-blue-500 text-blue-600"
              : "border-transparent text-gray-500 hover:text-gray-700"
          }`}
          onClick={() => setActiveTab("raw")}
        >
          Raw Data
        </button>
      </div>

      {activeTab === "wiki" && (
        <div>
          {/* Compile button + status */}
          <div className="flex items-center gap-3 mb-4">
            <button
              onClick={handleCompile}
              disabled={compiling}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {compiling ? "Compiling..." : "Compile Wiki"}
            </button>
            {lastCompiled && (
              <span className="text-xs text-gray-400">
                Last compiled: {new Date(lastCompiled).toLocaleString("ko-KR")}
              </span>
            )}
            {compileMsg && (
              <span
                className={`text-xs ${
                  compileMsg.includes("error") || compileMsg.includes("failed")
                    ? "text-red-500"
                    : "text-green-600"
                }`}
              >
                {compileMsg}
              </span>
            )}
          </div>

          {wiki_pages && wiki_pages.length > 0 ? (
            <div className="flex gap-4">
              {/* Sidebar */}
              <div className="w-56 flex-shrink-0">
                <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                  <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 text-xs font-semibold text-gray-500 uppercase">
                    Pages
                  </div>
                  <div className="divide-y divide-gray-100">
                    {groups.root.map((p) => (
                      <SidebarItem
                        key={p.path}
                        page={p}
                        selected={selectedPage === p.path}
                        onClick={() => setSelectedPage(p.path)}
                      />
                    ))}
                    {groups.patterns.length > 0 && (
                      <>
                        <div className="px-3 py-1.5 bg-gray-50 text-[10px] font-semibold text-gray-400 uppercase">
                          Patterns
                        </div>
                        {groups.patterns.map((p) => (
                          <SidebarItem
                            key={p.path}
                            page={p}
                            selected={selectedPage === p.path}
                            onClick={() => setSelectedPage(p.path)}
                          />
                        ))}
                      </>
                    )}
                    {groups.proposals.length > 0 && (
                      <>
                        <div className="px-3 py-1.5 bg-gray-50 text-[10px] font-semibold text-gray-400 uppercase">
                          Proposals
                        </div>
                        {groups.proposals.map((p) => (
                          <SidebarItem
                            key={p.path}
                            page={p}
                            selected={selectedPage === p.path}
                            onClick={() => setSelectedPage(p.path)}
                          />
                        ))}
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="bg-white border border-gray-200 rounded-xl p-5">
                  {selectedContent ? (
                    <>
                      <div className="flex items-center justify-between mb-3">
                        <h2 className="text-sm font-bold text-gray-700">
                          {selectedContent.path}
                        </h2>
                        <span className="text-[10px] text-gray-400">
                          {selectedContent.updated_at
                            ? new Date(selectedContent.updated_at).toLocaleString("ko-KR")
                            : ""}
                        </span>
                      </div>
                      <div className="prose prose-sm max-w-none text-gray-700 whitespace-pre-wrap text-xs leading-relaxed font-mono">
                        {selectedContent.content || "(empty)"}
                      </div>
                    </>
                  ) : (
                    <p className="text-gray-400 text-sm">Select a page from the sidebar</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white border border-gray-200 rounded-xl p-8 text-center">
              <p className="text-gray-400 text-sm mb-3">
                Wiki has not been compiled yet. Click "Compile Wiki" to generate pages from HITL training data.
              </p>
            </div>
          )}
        </div>
      )}

      {activeTab === "raw" && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">시각</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">출처</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">결정</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">사유</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">입력 (미리보기)</th>
                <th className="text-left px-3 py-2 font-semibold text-gray-500">판단 근거</th>
                <th className="text-right px-3 py-2 font-semibold text-gray-500">신뢰도</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-3 py-8 text-center text-gray-400">
                    아직 학습 데이터가 없습니다. 가드레일이 입력을 차단하고 소유자가 승인/거부하면 여기에 기록됩니다.
                  </td>
                </tr>
              ) : (
                [...entries].reverse().map((e, i) => (
                  <tr key={i} className={e.source === "human" ? "bg-blue-50/30" : ""}>
                    <td className="px-3 py-2 text-gray-400 whitespace-nowrap font-mono">
                      {e.timestamp
                        ? new Date(e.timestamp).toLocaleString("ko-KR", {
                            month: "numeric",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })
                        : "-"}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          e.source === "human"
                            ? "bg-blue-100 text-blue-700"
                            : "bg-purple-100 text-purple-700"
                        }`}
                      >
                        {e.source === "human" ? "HITL" : "auto"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          e.decision === "approve"
                            ? "bg-green-100 text-green-700"
                            : "bg-red-100 text-red-700"
                        }`}
                      >
                        {e.decision === "approve" ? "approve" : "reject"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-gray-600 max-w-[150px] truncate">
                      {e.flagged_reason || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-700 max-w-[200px] truncate font-mono">
                      {e.text || "-"}
                    </td>
                    <td className="px-3 py-2 text-gray-500 max-w-[200px] truncate">
                      {e.reasoning || "-"}
                    </td>
                    <td className="px-3 py-2 text-right text-gray-400">
                      {e.confidence != null ? `${(e.confidence * 100).toFixed(0)}%` : "-"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-3 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  );
}

function SidebarItem({
  page,
  selected,
  onClick,
}: {
  page: WikiPage;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-2 text-xs transition-colors ${
        selected
          ? "bg-blue-50 text-blue-700 font-medium"
          : "text-gray-600 hover:bg-gray-50"
      }`}
    >
      <div className="truncate">{page.title}</div>
      <div className="text-[10px] text-gray-400 truncate">{page.path}</div>
    </button>
  );
}
