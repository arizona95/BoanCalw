import { useEffect, useState, useCallback } from "react";
import { approvalApi, type ApprovalRequest } from "../api";

function formatApprovalCommand(command: string): string {
  switch (command) {
    case "critical-guardrail:review":
    case "guardrail:review":
      return "Critical Guardrail Review";
    case "constitution-amendment:review":
      return "G2 Amendment";
    case "g1-amendment:review":
      return "G1 Amendment";
    default:
      return command;
  }
}

function renderDiffArgs(req: ApprovalRequest): JSX.Element {
  const diff = req.args.find((a) => a.startsWith("diff="))?.slice(5) ?? "";
  const reasoning = req.args.find((a) => a.startsWith("reasoning="))?.slice(10) ?? "";
  return (
    <div className="max-w-lg">
      {reasoning && <p className="text-xs text-gray-600 mb-2">{reasoning}</p>}
      <pre className="text-xs bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
        {diff.split("\n").map((line, i) => (
          <span key={i} className={line.startsWith("+") ? "text-green-400" : line.startsWith("-") ? "text-red-400" : ""}>
            {line}{"\n"}
          </span>
        ))}
      </pre>
    </div>
  );
}

function renderArgs(req: ApprovalRequest): JSX.Element {
  if (req.command === "constitution-amendment:review" || req.command === "g1-amendment:review") {
    return renderDiffArgs(req);
  }
  return <span className="font-mono text-gray-600 max-w-xs truncate">{req.args.join(" ")}</span>;
}

type ApprovalTab = "actions" | "guardrail";
type GuardrailDiffSub = "G1" | "G2";

export default function Approvals() {
  const [tab, setTab] = useState<ApprovalTab>("actions");
  const [guardrailSub, setGuardrailSub] = useState<GuardrailDiffSub>("G1");
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(() => {
    approvalApi
      .list()
      .then(setApprovals)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);

  const handleDecision = async (id: string, action: "approve" | "reject") => {
    setActing(id);
    try {
      if (action === "approve") {
        await approvalApi.approve(id);
      } else {
        await approvalApi.reject(id);
      }
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActing(null);
    }
  };

  const isG1Amendment = (a: ApprovalRequest) => a.command === "g1-amendment:review";
  const isG2Amendment = (a: ApprovalRequest) => a.command === "constitution-amendment:review";
  const isGuardrailDiff = (a: ApprovalRequest) => isG1Amendment(a) || isG2Amendment(a);

  const filtered = approvals.filter((a) => {
    if (tab === "guardrail") {
      if (!isGuardrailDiff(a)) return false;
      return guardrailSub === "G1" ? isG1Amendment(a) : isG2Amendment(a);
    }
    return !isGuardrailDiff(a);
  });
  const pending = filtered.filter((a) => a.status === "pending");
  const decided = filtered.filter((a) => a.status !== "pending");
  const guardrailG1Count = approvals.filter((a) => isG1Amendment(a) && a.status === "pending").length;
  const guardrailG2Count = approvals.filter((a) => isG2Amendment(a) && a.status === "pending").length;

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Approvals</h1>
        <span className="text-sm text-gray-500">
          {pending.length} pending
        </span>
      </div>

      <div className="flex border-b border-gray-200 mb-4">
        {([["actions", "User Actions"], ["guardrail", "Guardrail Diff"]] as const).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === k ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"}`}>
            {label}
            {k === "guardrail" && (guardrailG1Count + guardrailG2Count) > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 text-[10px] rounded-full bg-orange-100 text-orange-700 font-semibold">
                {guardrailG1Count + guardrailG2Count}
              </span>
            )}
          </button>
        ))}
      </div>

      {tab === "guardrail" && (
        <div className="mb-4">
          <p className="text-xs text-gray-500 mb-2">
            LLM(G3 wiki) 이 제안하는 G1 정규식 / G2 헌법 변경안 승인 큐. diff 확인 후 approve 하면 정책에 즉시 반영.
          </p>
          <div className="flex gap-1 bg-gray-100 rounded-lg p-1 w-fit">
            {(["G1", "G2"] as const).map((g) => {
              const count = g === "G1" ? guardrailG1Count : guardrailG2Count;
              const active = guardrailSub === g;
              return (
                <button
                  key={g}
                  onClick={() => setGuardrailSub(g)}
                  className={`px-3 py-1 rounded-md text-xs font-mono font-medium transition-colors ${
                    active ? "bg-white shadow text-gray-900" : "text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {g}
                  {count > 0 && (
                    <span className="ml-1 px-1 rounded bg-orange-100 text-orange-700 text-[10px]">{count}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}

      {loading && approvals.length === 0 ? (
        <p className="text-gray-500">Loading...</p>
      ) : (
        <>
          {pending.length > 0 && (
            <div className="mb-8">
              <h2 className="text-base font-semibold text-gray-700 mb-3">
                Pending
              </h2>
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
                          {formatApprovalCommand(req.command)}
                        </td>
                        <td className="px-4 py-3">
                          {renderArgs(req)}
                        </td>
                        <td className="px-4 py-3 text-gray-700">
                          {req.requester}
                        </td>
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
              <h2 className="text-base font-semibold text-gray-700 mb-3">
                Recent Decisions
              </h2>
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 border-b border-gray-100 text-left text-gray-500 text-xs uppercase tracking-wide">
                      <th className="px-4 py-3">Command</th>
                      <th className="px-4 py-3">Args</th>
                      <th className="px-4 py-3">Requester</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Decided By</th>
                      <th className="px-4 py-3">Decided At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {decided.map((req) => (
                      <tr key={req.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-mono font-medium text-gray-900">
                          {formatApprovalCommand(req.command)}
                        </td>
                        <td className="px-4 py-3">
                          {renderArgs(req)}
                        </td>
                        <td className="px-4 py-3 text-gray-700">
                          {req.requester}
                        </td>
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
                          {req.decidedBy ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-gray-500">
                          {req.decidedAt
                            ? new Date(req.decidedAt).toLocaleString()
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {approvals.length === 0 && (
            <div className="text-center py-16 text-gray-400">
              No approval requests yet.
            </div>
          )}
        </>
      )}
    </div>
  );
}
