import { useEffect, useState } from "react";
import { dashboardApi, type DashboardStats } from "../api";

const EMPTY: DashboardStats = {
  llm_count: 0,
  active_sessions: 0,
  dlp_block_count: 0,
  policy_version: 0,
};

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(EMPTY);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    dashboardApi
      .stats()
      .then(setStats)
      .finally(() => setLoading(false));
  }, []);

  const cards = [
    {
      label: "Registered LLMs",
      value: stats.llm_count,
      color: "bg-blue-500",
    },
    {
      label: "Active Sessions",
      value: stats.active_sessions,
      color: "bg-green-500",
    },
    {
      label: "DLP Blocks",
      value: stats.dlp_block_count,
      color: "bg-red-500",
    },
    {
      label: "Policy Version",
      value: `v${stats.policy_version}`,
      color: "bg-purple-500",
    },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      {loading ? (
        <p className="text-gray-500">Loading...</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {cards.map((card) => (
            <div
              key={card.label}
              className="bg-white rounded-xl shadow-sm border border-gray-200 p-6"
            >
              <div className="flex items-center gap-3 mb-3">
                <div className={`w-3 h-3 rounded-full ${card.color}`} />
                <span className="text-sm text-gray-500">{card.label}</span>
              </div>
              <p className="text-3xl font-bold">{card.value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold mb-4">System Status</h2>
        <div className="space-y-3">
          {[
            "boan-proxy",
            "boan-policy-server",
            "boan-credential-filter",
            "boan-audit-agent",
            "boan-llm-registry",
            "boan-whitelist-proxy",
          ].map((svc) => (
            <div key={svc} className="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
              <span className="text-sm font-mono">{svc}</span>
              <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-green-50 text-green-700">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                healthy
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
