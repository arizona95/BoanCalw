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

interface WikiData {
  entries: WikiEntry[];
  stats: {
    total: number;
    human: number;
    auto: number;
    approve: number;
    reject: number;
  };
}

export default function Wiki() {
  const [data, setData] = useState<WikiData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/admin/wiki", { credentials: "include" })
      .then((r) => r.json())
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-gray-400 p-6">Loading...</p>;
  if (!data) return <p className="text-red-400 p-6">Wiki data not available</p>;

  const { entries, stats } = data;

  return (
    <div className="p-6 max-w-6xl">
      <h1 className="text-xl font-bold text-gray-800 mb-2">G3 Wiki</h1>
      <p className="text-sm text-gray-500 mb-6">
        G3 wiki 가 학습한 HITL 결정 로그. 이 데이터가 가드레일 자동 판단과 헌법 개정 제안의 근거가 됩니다.
      </p>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3 mb-6">
        <StatCard label="전체" value={stats.total} color="text-gray-700" />
        <StatCard label="사람 결정" value={stats.human} color="text-blue-600" />
        <StatCard label="자동 판단" value={stats.auto} color="text-purple-600" />
        <StatCard label="승인" value={stats.approve} color="text-green-600" />
        <StatCard label="거부" value={stats.reject} color="text-red-600" />
      </div>

      {/* Entries table */}
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
                    {e.timestamp ? new Date(e.timestamp).toLocaleString("ko-KR", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "-"}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${e.source === "human" ? "bg-blue-100 text-blue-700" : "bg-purple-100 text-purple-700"}`}>
                      {e.source === "human" ? "HITL" : "auto"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${e.decision === "approve" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                      {e.decision === "approve" ? "approve" : "reject"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-gray-600 max-w-[150px] truncate">{e.flagged_reason || "-"}</td>
                  <td className="px-3 py-2 text-gray-700 max-w-[200px] truncate font-mono">{e.text || "-"}</td>
                  <td className="px-3 py-2 text-gray-500 max-w-[200px] truncate">{e.reasoning || "-"}</td>
                  <td className="px-3 py-2 text-right text-gray-400">
                    {e.confidence != null ? `${(e.confidence * 100).toFixed(0)}%` : "-"}
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

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-3 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  );
}
