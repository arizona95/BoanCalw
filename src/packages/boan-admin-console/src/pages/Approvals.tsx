import { useEffect, useState, useCallback } from "react";
import { approvalApi, type ApprovalRequest } from "../api";

function formatApprovalCommand(command: string): string {
  switch (command) {
    case "critical-guardrail:review":
    case "guardrail:review":
      return "Critical Guardrail Review";
    case "constitution-amendment:review":
      return "Constitution Amendment";
    default:
      return command;
  }
}

function renderArgs(req: ApprovalRequest): JSX.Element {
  if (req.command === "constitution-amendment:review") {
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
  return <span className="font-mono text-gray-600 max-w-xs truncate">{req.args.join(" ")}</span>;
}

type ApprovalTab = "actions" | "amendments";

export default function Approvals() {
  const [tab, setTab] = useState<ApprovalTab>("actions");
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

  const isAmendment = (a: ApprovalRequest) => a.command === "constitution-amendment:review";
  const filtered = approvals.filter((a) => tab === "amendments" ? isAmendment(a) : !isAmendment(a));
  const pending = filtered.filter((a) => a.status === "pending");
  const decided = filtered.filter((a) => a.status !== "pending");

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Approvals</h1>
        <span className="text-sm text-gray-500">
          {pending.length} pending
        </span>
      </div>

      <div className="flex border-b border-gray-200 mb-4">
        {([["actions", "User Actions"], ["amendments", "Constitution Diff"]] as const).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === k ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"}`}>{label}</button>
        ))}
      </div>

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
