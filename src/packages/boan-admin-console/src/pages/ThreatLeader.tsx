import { useEffect, useState, useCallback } from "react";

// ThreatLeader v2 — OSV.dev 데일리 dump 에서 자동 fetch 한 5 개 추천.
// Accept = KillChain rule 추가 (auto=true) → 매칭 process 발견 시 즉시 격리 →
// 포렌식 disk snapshot → STOP → DELETE.
// Reject = ignored 마킹 (다음 라운드 추천 안 함).

type Severity = "low" | "medium" | "high" | "critical";

type Proposal = {
  id: string;
  cve_id?: string;
  ecosystem: string;
  package_name: string;
  versions_affected: string;
  summary: string;
  description: string;
  published_at: string;
  modified_at: string;
  severity: Severity;
  cvss_score?: number;
  suggested_process: string;
  suggested_rule_name: string;
  reference_url?: string;
};

type ProposalList = {
  last_fetch_at: string;
  proposals: Proposal[];
};

const SEVERITY_BG: Record<Severity, string> = {
  low: "bg-gray-100 text-gray-700",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export default function ThreatLeader() {
  const [data, setData] = useState<ProposalList | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = useCallback(() => {
    fetch("/api/threat-leader/proposals", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: ProposalList) => setData(d))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    // 30 초 주기 polling — 백엔드 cron 또는 수동 ↻ 결과 반영.
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  const triggerRefresh = async () => {
    setRefreshing(true);
    setError(null);
    setSuccess(null);
    try {
      const r = await fetch("/api/threat-leader/refresh", {
        method: "POST",
        credentials: "include",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
      setSuccess("OSV fetch 트리거됨. 30 초~몇 분 후 새 추천이 나타납니다 (자동 polling).");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRefreshing(false);
    }
  };

  const accept = async (id: string) => {
    setBusy(id);
    setError(null);
    setSuccess(null);
    try {
      const r = await fetch(`/api/threat-leader/proposals/${encodeURIComponent(id)}/accept`, {
        method: "POST",
        credentials: "include",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
      const j = await r.json();
      setSuccess(j.message ?? `Kill Chain rule 등록 완료 (auto=true).`);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const reject = async (id: string) => {
    setBusy(id);
    setError(null);
    try {
      const r = await fetch(`/api/threat-leader/proposals/${encodeURIComponent(id)}/reject`, {
        method: "POST",
        credentials: "include",
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const lastFetch = data?.last_fetch_at && new Date(data.last_fetch_at).getTime() > 0
    ? new Date(data.last_fetch_at).toLocaleString("ko-KR")
    : "(아직 fetch 안 됨)";

  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2 mb-1">
          <span>🐲 Threat Leader</span>
          <span className="text-xs px-2 py-0.5 rounded bg-purple-100 text-purple-700 font-normal">
            OSV.dev v2
          </span>
        </h1>
        <p className="text-xs text-gray-500">
          외부 공급망 공격 / CVE 피드 (OSV.dev 데일리 dump). 24h 마다 자동 fetch + 최근 7 일 + severity HIGH/CRITICAL 우선 top 5 추천.
          Accept = <a href="/kill-chain" className="text-red-600 underline">Kill Chain Rule</a> 즉시 등록 (auto=true) → 매칭 process 발견 시 자동 격리 → 포렌식 disk snapshot → STOP → DELETE.
        </p>
        <div className="mt-3 flex items-center gap-3 text-xs">
          <span className="text-gray-500">마지막 fetch: <code className="bg-gray-50 px-1.5 py-0.5 rounded">{lastFetch}</code></span>
          <button
            onClick={triggerRefresh}
            disabled={refreshing}
            className="px-3 py-1 rounded-lg bg-purple-600 text-white text-xs font-medium hover:bg-purple-700 disabled:opacity-50"
          >
            {refreshing ? "트리거 중..." : "↻ 즉시 탐색"}
          </button>
        </div>
      </div>

      {error && <div className="mb-3 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>}
      {success && <div className="mb-3 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{success}</div>}

      {loading ? (
        <p className="text-gray-500 text-sm">로딩 중...</p>
      ) : !data?.proposals?.length ? (
        <div className="text-center py-12 bg-white rounded-xl border border-dashed border-gray-300 text-gray-400 text-sm">
          현재 추천 항목이 없습니다.<br />
          <span className="text-[11px]">백엔드 cron 이 부팅 후 5 분 이내 첫 fetch 시작. 즉시 보려면 위 ↻ 버튼.</span>
        </div>
      ) : (
        <div className="space-y-3">
          {data.proposals.map((entry) => (
            <div key={entry.id} className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-[10px] px-2 py-0.5 rounded font-semibold uppercase ${SEVERITY_BG[entry.severity]}`}>
                    {entry.severity}
                    {entry.cvss_score ? ` · CVSS ${entry.cvss_score.toFixed(1)}` : ""}
                  </span>
                  {entry.cve_id && (
                    <code className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-700">{entry.cve_id}</code>
                  )}
                  <code className="text-[11px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-700">{entry.id}</code>
                  <code className="text-[11px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-700">
                    {entry.ecosystem}:{entry.package_name} {entry.versions_affected}
                  </code>
                  {entry.published_at && (
                    <span className="text-[10px] text-gray-400">
                      {new Date(entry.published_at).toLocaleDateString("ko-KR")}
                    </span>
                  )}
                </div>
                <div className="shrink-0 flex gap-2">
                  <button
                    onClick={() => accept(entry.id)}
                    disabled={busy !== null}
                    className="px-3 py-1.5 rounded-lg bg-red-600 text-white text-xs font-medium hover:bg-red-700 disabled:opacity-50"
                    title="Kill Chain rule 즉시 등록 (auto=true)"
                  >
                    {busy === entry.id ? "..." : "✓ Accept (rule 등록)"}
                  </button>
                  <button
                    onClick={() => reject(entry.id)}
                    disabled={busy !== null}
                    className="px-3 py-1.5 rounded-lg border border-gray-300 bg-white text-gray-700 text-xs hover:bg-gray-50 disabled:opacity-50"
                  >
                    Reject
                  </button>
                </div>
              </div>
              <h3 className="text-sm font-semibold text-gray-900 mb-1">{entry.summary || entry.suggested_rule_name}</h3>
              {entry.description && (
                <p className="text-xs text-gray-600 leading-relaxed mb-2 whitespace-pre-wrap">{entry.description}</p>
              )}
              <div className="text-[11px] text-gray-500 flex items-center gap-3 flex-wrap">
                <span>제안 rule: <code className="bg-gray-50 px-1.5 py-0.5 rounded">{entry.suggested_rule_name}</code></span>
                <span>매칭 process: <code className="bg-red-50 text-red-700 px-1.5 py-0.5 rounded">{entry.suggested_process}</code></span>
                {entry.reference_url && (
                  <a href={entry.reference_url} target="_blank" rel="noreferrer" className="text-blue-600 underline">
                    원본 advisory ↗
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
