import { useState } from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Policies from "./pages/Policies";
import LLMRegistry from "./pages/LLMRegistry";
import AuditLog from "./pages/AuditLog";
import Credentials from "./pages/Credentials";
import Approvals from "./pages/Approvals";

const NAV_ITEMS = [
  { path: "/", label: "Dashboard", icon: "📊" },
  { path: "/policies", label: "Policies", icon: "📋" },
  { path: "/llm-registry", label: "LLM Registry", icon: "🤖" },
  { path: "/audit", label: "Audit Log", icon: "📝" },
  { path: "/credentials", label: "Credentials", icon: "🔑" },
  { path: "/approvals", label: "Approvals", icon: "✅" },
];

export default function App() {
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen overflow-hidden">
      <aside
        className={`${
          sidebarOpen ? "w-64" : "w-16"
        } flex flex-col bg-boan-900 text-white transition-all duration-200`}
      >
        <div className="flex items-center gap-2 px-4 py-5 border-b border-white/10">
          <span className="text-xl font-bold tracking-tight">
            {sidebarOpen ? "BoanClaw" : "B"}
          </span>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="ml-auto text-white/60 hover:text-white"
          >
            {sidebarOpen ? "◀" : "▶"}
          </button>
        </div>
        <nav className="flex-1 py-4 space-y-1">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                  isActive
                    ? "bg-white/10 text-white font-medium"
                    : "text-white/60 hover:bg-white/5 hover:text-white"
                }`
              }
            >
              <span>{item.icon}</span>
              {sidebarOpen && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-white/10 text-xs text-white/40">
          {sidebarOpen && "Samsung SDS BoanClaw v1.0"}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto bg-gray-50">
        <div className="p-8 max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/llm-registry" element={<LLMRegistry />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/credentials" element={<Credentials />} />
            <Route path="/approvals" element={<Approvals />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
