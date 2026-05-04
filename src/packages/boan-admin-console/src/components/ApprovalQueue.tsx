import { useEffect, useState, useCallback } from "react";
import { approvalApi, type ApprovalCategory, type ApprovalRequest } from "../api";

// ApprovalQueue — 카테고리별 (user/guardrail/killchain) 승인 큐 UI 공용 컴포넌트.
// 페이지 (Approvals / Guardrail / KillChain) 가 같은 backend 의 approvalsStore 를 다른
// category 필터로 본다. category 는 backend 가 command prefix 로 자동 도출.
//
// 사용 예:
//   <ApprovalQueue category="guardrail" title="가드레일 HITL" />
//   <ApprovalQueue category="killchain" title="Kill Chain HITL" />

function formatCommand(command: string): string {
  switch (command) {
    case "critical-guardrail:review":
    case "guardrail:review":
      return "Critical Guardrail Review";
    case "constitution-amendment:review":
      return "G2 Amendment";
    case "g1-amendment:review":
      return "G1 Amendment";
    case "kill-chain:trigger":
      return "Kill Chain Trigger";
    case "threat-leader:rule-add":
      return "Threat Leader → Rule";
    default:
      return command;
  }
}

function renderDiffArgs(req: ApprovalRequest) {
  const diff = req.args.find((a) => a.startsWith("diff="))?.slice(5) ?? "";
  const reasoning = req.args.find((a) => a.startsWith("reasoning="))?.slice(10) ?? "";
  return (
    <div className="max-w-lg">
      {reasoning && <p className="text-xs text-gray-600 mb-2">{reasoning}</p>}
      <pre className="text-xs bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
        {diff.split("\n").map((line, i) => (
          <span
            key={i}
            className={
              line.startsWith("+")
                ? "text-green-400"
                : line.startsWith("-")
                  ? "text-red-400"
                  : ""
            }
          >
            {line}
            {"\n"}
          </span>
        ))}
      </pre>
    </div>
  );
}

function renderArgs(req: ApprovalRequest) {
  if (req.command === "constitution-amendment:review" || req.command === "g1-amendment:review") {
    return renderDiffArgs(req);
  }
  return <span className="font-mono text-gray-600 max-w-xs truncate">{req.args.join(" ")}</span>;
}

export interface ApprovalQueueProps {
  category: ApprovalCategory;
  title?: string;
  emptyText?: string;
  pollIntervalMs?: number;
}

export function ApprovalQueue({
  category,
  title,
  emptyText = "승인 요청이 없습니다.",
  pollIntervalMs = 5000,
}: ApprovalQueueProps) {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(() => {
    approvalApi
      .list(category)
      .then(setApprovals)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [category]);

  useEffect(() => {
    load();
    if (pollIntervalMs > 0) {
      const id = setInterval(load, pollIntervalMs);
      return () => clearInterval(id);
    }
  }, [load, pollIntervalMs]);

  const handleDecision = async (id: string, action: "approve" | "reject") => {
    setActing(id);
    try {
      if (action === "approve") await approvalApi.approve(id);
      else await approvalApi.reject(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(null);
    }
  };

  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending");

  return (
    <div>
      {title && (
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">{title}</h2>
          <span className="text-sm text-gray-500">{pending.length} pending</span>
        </div>
      )}

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>
      )}

      {loading && approvals.length === 0 ? (
        <p className="text-gray-500">Loading...</p>
      ) : (
        <>
          {pending.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Pending</h3>
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-100 text-left text-gray-500 text-xs uppercase tracking-wide">
                      <th className="px-4 py-3">Command</th>
                      <th className="px-4 py-3">Args</th>
                      <th className="px-4 py-3">Requester</th>
                      <th className="px-4 py-3">Requested At</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {pending.map((req) => (
                      <tr key={req.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-mono font-medium text-gray-900">
                          {formatCommand(req.command)}
                        </td>
                        <td className="px-4 py-3">{renderArgs(req)}</td>
                        <td className="px-4 py-3 text-gray-700">{req.requester}</td>
                        <td className="px-4 py-3 text-gray-500">
                          {new Date(req.requestedAt).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-right space-x-2">
                          <button
                            disabled={acting === req.id}
                            onClick={() => handleDecision(req.id, "approve")}
                            className="inline-flex items-center px-3 py-1 rounded-md text-xs font-medium bg-green-100 text-green-800 hover:bg-green-200 disabled:opacity-50"
                          >
                            Approve
                          </button>
                          <button
                            disabled={acting === req.id}
                            onClick={() => handleDecision(req.id, "reject")}
                            className="inline-flex items-center px-3 py-1 rounded-md text-xs font-medium bg-red-100 text-red-800 hover:bg-red-200 disabled:opacity-50"
                          >
                            Reject
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {decided.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-2">Recent Decisions</h3>
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-100 text-left text-gray-500 text-xs uppercase tracking-wide">
                      <th className="px-4 py-3">Command</th>
                      <th className="px-4 py-3">Args</th>
                      <th className="px-4 py-3">Requester</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Decided At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {decided.slice(0, 30).map((req) => (
                      <tr key={req.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-mono font-medium text-gray-900">
                          {formatCommand(req.command)}
                        </td>
                        <td className="px-4 py-3">{renderArgs(req)}</td>
                        <td className="px-4 py-3 text-gray-700">{req.requester}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                              req.status === "approved"
                                ? "bg-green-100 text-green-800"
                                : "bg-red-100 text-red-800"
                            }`}
                          >
                            {req.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-500">
                          {req.decidedAt ? new Date(req.decidedAt).toLocaleString() : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {approvals.length === 0 && (
            <div className="text-center py-12 text-gray-400 text-sm">{emptyText}</div>
          )}
        </>
      )}
    </div>
  );
}
