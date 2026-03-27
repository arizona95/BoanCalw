import { useEffect, useState, useCallback } from "react";
import { approvalApi, type ApprovalRequest } from "../api";

export default function Approvals() {
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

  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending");

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Exec Approvals</h1>
        <span className="text-sm text-gray-500">
          {pending.length} pending
        </span>
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
                          {req.command}
                        </td>
                        <td className="px-4 py-3 font-mono text-gray-600 max-w-xs truncate">
                          {req.args.join(" ")}
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
                          {req.command}
                        </td>
                        <td className="px-4 py-3 font-mono text-gray-600 max-w-xs truncate">
                          {req.args.join(" ")}
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
