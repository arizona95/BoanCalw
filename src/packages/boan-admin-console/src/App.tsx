import { useState } from "react";
import { Routes, Route, NavLink, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Login from "./pages/Login";
import Register from "./pages/Register";
import SelectOrg from "./pages/SelectOrg";
import Dashboard from "./pages/Dashboard";
import OrgSettings from "./pages/OrgSettings";
import Policies from "./pages/Policies";
import LLMRegistry from "./pages/LLMRegistry";
import AuditLog from "./pages/AuditLog";
import Credentials from "./pages/Credentials";
import Approvals from "./pages/Approvals";
import Users from "./pages/Users";

const ROLE_COLOR: Record<string, string> = {
  owner: "bg-blue-100 text-blue-800",
  user: "bg-gray-100 text-gray-600",
};

function Shell() {
  const { user, loading, logout } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-gray-400 text-sm">로딩 중...</div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const canEdit = user.can_edit;

  const NAV_ITEMS = [
    { path: "/", label: "Dashboard", icon: "📊", always: true },
    { path: "/org", label: "Org Settings", icon: "🏢", always: false },
    { path: "/policies", label: "Policies", icon: "📋", always: false },
    { path: "/llm-registry", label: "LLM Registry", icon: "🤖", always: true },
    { path: "/audit", label: "Audit Log", icon: "📝", always: true },
    { path: "/credentials", label: "Credentials", icon: "🔑", always: false },
    { path: "/approvals", label: "Approvals", icon: "✅", always: false },
    { path: "/users", label: "Users", icon: "👥", always: false },
  ].filter((item) => item.always || canEdit);

  return (
    <div className="flex h-screen overflow-hidden">
      <aside
        className={`${sidebarOpen ? "w-64" : "w-16"} flex flex-col bg-boan-900 text-white transition-all duration-200`}
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

        {sidebarOpen && user && (
          <div className="px-4 py-3 border-t border-white/10 space-y-2">
            {user.org_id && (
              <div className="flex items-center gap-1.5 px-2 py-1 bg-white/5 rounded-lg">
                <span className="text-white/40 text-xs">🏢</span>
                <span className="text-xs text-white/60 font-mono truncate">{user.org_id}</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-boan-600 flex items-center justify-center text-xs font-bold flex-shrink-0">
                {(user.name ?? user.email ?? "?")[0].toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs text-white truncate">{user.name ?? user.email}</p>
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-medium ${ROLE_COLOR[user.role] ?? ROLE_COLOR.user}`}>
                  {user.role_label}
                </span>
              </div>
            </div>
            {user.enabled && (
              <button
                onClick={logout}
                className="w-full text-xs text-white/40 hover:text-white/80 text-left"
              >
                로그아웃
              </button>
            )}
          </div>
        )}
      </aside>

      <main className="flex-1 overflow-y-auto bg-gray-50">
        {!canEdit && (
          <div className="bg-yellow-50 border-b border-yellow-200 px-6 py-2 text-xs text-yellow-800 flex items-center gap-2">
            <span>👁️</span>
            <span>읽기 전용 모드입니다. 설정을 변경하려면 소유자 권한이 필요합니다.</span>
          </div>
        )}
        <div className="p-8 max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/org" element={canEdit ? <OrgSettings /> : <ReadOnly />} />
            <Route path="/policies" element={canEdit ? <Policies /> : <ReadOnly />} />
            <Route path="/llm-registry" element={<LLMRegistry />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/credentials" element={canEdit ? <Credentials /> : <ReadOnly />} />
            <Route path="/approvals" element={canEdit ? <Approvals /> : <ReadOnly />} />
            <Route path="/users" element={canEdit ? <Users /> : <ReadOnly />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}

function ReadOnly() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="text-5xl mb-4">🔒</div>
      <h2 className="text-xl font-semibold text-gray-700 mb-2">접근 권한 없음</h2>
      <p className="text-sm text-gray-500">이 페이지는 소유자만 볼 수 있습니다.</p>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginGuard />} />
        <Route path="/register" element={<RegisterGuard />} />
        <Route path="/select-org" element={<SelectOrg />} />
        <Route path="/*" element={<Shell />} />
      </Routes>
    </AuthProvider>
  );
}

function LoginGuard() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/" replace />;
  return <Login />;
}

function RegisterGuard() {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (user) return <Navigate to="/" replace />;
  return <Register />;
}
