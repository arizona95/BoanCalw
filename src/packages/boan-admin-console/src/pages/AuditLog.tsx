import { useEffect, useState } from "react";
import { auditApi, type AuditEvent } from "../api";

const LEVEL_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-green-100 text-green-800",
  info: "bg-gray-100 text-gray-600",
};

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    auditApi
      .list(100)
      .then(setEvents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <span className="text-sm text-gray-500">{events.length} events</span>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">
          {error}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <p className="p-6 text-gray-500">Loading...</p>
        ) : events.length === 0 ? (
          <p className="p-6 text-gray-500">No audit events.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Action</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">S-Level</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Host</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">User</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {events.map((ev) => (
                <tr key={ev.id} className="hover:bg-gray-50">
                  <td className="px-6 py-3 font-mono">{ev.action}</td>
                  <td className="px-6 py-3">
                    <span
                      className={`text-xs px-2 py-1 rounded-full ${
                        LEVEL_COLORS[ev.s_level] || LEVEL_COLORS.info
                      }`}
                    >
                      {ev.s_level}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-gray-600">{ev.host}</td>
                  <td className="px-6 py-3 text-gray-600">{ev.user}</td>
                  <td className="px-6 py-3 text-gray-500">{ev.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
