import { useState, useEffect, useCallback } from "react";
import { Routes, Route, NavLink, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Login from "./pages/Login";
import Register from "./pages/Register";
import SelectOrg from "./pages/SelectOrg";
import OrgSettings from "./pages/OrgSettings";
import OrgOverview from "./pages/OrgOverview";
import Policies from "./pages/Policies";
import LLMRegistry from "./pages/LLMRegistry";
import Credentials from "./pages/Credentials";
import Approvals from "./pages/Approvals";
import Authorization from "./pages/Authorization";
import FileManager from "./pages/FileManager";
import Observability from "./pages/Observability";
import MyBoanClaw from "./pages/MyBoanClaw";
import MyGCP from "./pages/MyGCP";
import WikiGraph from "./pages/WikiGraph";

const ROLE_COLOR: Record<string, string> = {
  owner: "bg-blue-100 text-blue-800",
  user: "bg-gray-100 text-gray-600",
};

function useVersion(enabled: boolean) {
  const [version, setVersion] = useState<{
    current: string; latest: string; update_available: boolean;
  } | null>(null);
  const [updating, setUpdating] = useState(false);

  const check = useCallback(() => {
    if (!enabled) return;
    fetch("/api/admin/version", { credentials: "include" })
      .then((r) => r.json())
      .then(setVersion)
      .catch(() => {});
  }, [enabled]);

  useEffect(() => {
    check();
    const id = setInterval(check, 5 * 60 * 1000);
    return () => clearInterval(id);
  }, [check]);

  const triggerUpdate = async () => {
    setUpdating(true);
    const startVersion = version?.current;
    try {
      await fetch("/api/admin/update", { method: "POST", credentials: "include" });
    } catch { /* noop */ }

    // Poll until version changes OR timeout (15 min max)
    const startTime = Date.now();
    const MAX_WAIT = 15 * 60 * 1000; // 15 min
    const pollVersion = async () => {
      if (Date.now() - startTime > MAX_WAIT) {
        setUpdating(false);
        return;
      }
      try {
        const r = await fetch("/api/admin/version", { credentials: "include" });
        const v = await r.json();
        if (v.current && v.current !== startVersion && !v.update_available) {
          // Version changed AND no longer pending update — rebuild complete
          window.location.reload();
          return;
        }
      } catch { /* server may be down during restart, keep polling */ }
      setTimeout(pollVersion, 5000); // poll every 5s
    };
    setTimeout(pollVersion, 30_000); // wait 30s before first poll (rebuild just started)
  };

  return { version, updating, triggerUpdate };
}

type Mode = "default" | "usage";

function Shell() {
  const { user, loading, logout } = useAuth();
  const [mode, setMode] = useState<Mode>(() => {
    const stored = localStorage.getItem("boan_mode");
    return stored === "usage" ? "usage" : "default";
  });
  const location = useLocation();
  const { version, updating, triggerUpdate } = useVersion(!!user?.can_edit);

  const toggleMode = useCallback(() => {
    setMode((prev) => {
      const next = prev === "default" ? "usage" : "default";
      localStorage.setItem("boan_mode", next);
      return next;
    });
  }, []);

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

  type NavItem = { path: string; label: string; icon: string; separator?: boolean };
  const NAV_ITEMS: NavItem[] = canEdit
    ? [
        { path: "/authorization", label: "Authorization", icon: "🔐" },
        { path: "/llm-registry", label: "LLM Registry", icon: "🤖" },
        { path: "/gateway", label: "Gateway Policies", icon: "🛡️" },
        { path: "/credentials", label: "Credentials", icon: "🔑" },
        { path: "/approvals", label: "Approvals", icon: "✅" },
        { path: "/observability", label: "Observability", icon: "🔭" },
        { path: "/wiki-graph", label: "G3 Folder Wiki", icon: "📂" },
        { path: "/my-boanclaw", label: "BoanClaw", icon: "🦞", separator: true },
        { path: "/files", label: "File Manager", icon: "📂" },
        { path: "/my-gcp", label: "Personal Computer", icon: "🖥️" },
      ]
    : [
        { path: "/org-overview", label: "조직 설정 확인", icon: "🏢" },
        { path: "/credentials", label: "Credentials", icon: "🔑" },
        { path: "/my-boanclaw", label: "BoanClaw", icon: "🦞", separator: true },
        { path: "/files", label: "File Manager", icon: "📂" },
        { path: "/my-gcp", label: "Personal Computer", icon: "🖥️" },
      ];

  const fullBleed = location.pathname === "/my-boanclaw" || location.pathname === "/my-gcp" || location.pathname === "/wiki-graph";
  // FileManager needs a wider content area — ~1.3x default max-w-7xl
  const wideContent = location.pathname === "/files";
  const showMyBoanClaw = location.pathname === "/my-boanclaw";
  const showMyGCP = location.pathname === "/my-gcp";
  const showPersistentSurface = showMyBoanClaw || showMyGCP;

  // 사용모드(Usage mode): 왼쪽 메뉴판 자리에 BoanClaw 채팅이 영구 표시,
  // 오른쪽에 Personal Computer(또는 다른 라우트) 가 나란히 보인다.
  if (mode === "usage") {
    return (
      <UsageShell
        mode={mode}
        toggleMode={toggleMode}
        user={user}
        logout={logout}
        version={version}
        updating={updating}
        triggerUpdate={triggerUpdate}
      />
    );
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="w-64 flex flex-col bg-boan-900 text-white">
        <div className="flex items-center gap-2 px-4 py-5 border-b border-white/10">
          <span className="text-xl font-bold tracking-tight">BoanClaw v0.4</span>
          {version?.current && (
            <span className="text-[10px] text-white/30 font-mono">{version.current}</span>
          )}
          <button
            onClick={toggleMode}
            title="사용 모드로 전환 — BoanClaw 채팅 + Personal Computer 를 함께 쓰세요"
            className="ml-auto px-2 py-0.5 text-[10px] bg-white/10 hover:bg-white/20 rounded border border-white/20 text-white/80 hover:text-white font-medium"
          >
            사용 모드 →
          </button>
        </div>

        <nav className="flex-1 py-4 space-y-1">
          {NAV_ITEMS.map((item) => (
            <div key={item.path}>
              {item.separator && <div className="mx-4 my-2 border-t border-white/10" />}
              <NavLink
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
                <span>{item.label}</span>
              </NavLink>
            </div>
          ))}
        </nav>

        {user && (
          <div className="px-4 py-3 border-t border-white/10 space-y-2">
            {version?.update_available && !updating && (
              <button
                onClick={triggerUpdate}
                className="w-full px-2 py-1.5 bg-emerald-500/20 border border-emerald-400/30 rounded-lg text-xs text-emerald-300 hover:bg-emerald-500/30 transition-colors text-left"
              >
                <span className="font-medium">NEW {version.latest}</span>
                <span className="block text-emerald-400/60 text-[10px] mt-0.5">
                  업데이트 하시겠습니까?
                </span>
              </button>
            )}
            {updating && (
              <div className="px-2 py-1.5 bg-yellow-500/20 border border-yellow-400/30 rounded-lg text-xs text-yellow-300 animate-pulse">
                업데이트 중... 잠시 후 새로고침됩니다
              </div>
            )}
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
                <div className="flex items-center gap-1.5">
                  <span className={`text-xs px-1.5 py-0.5 rounded-full font-medium ${ROLE_COLOR[user.role] ?? ROLE_COLOR.user}`}>
                    {user.role_label}
                  </span>
                  <button
                    onClick={logout}
                    title="로그아웃"
                    className="text-xs text-white/40 hover:text-white/80 px-1.5 py-0.5 rounded hover:bg-white/10"
                  >
                    ↗ 로그아웃
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </aside>

      <main className={`flex-1 bg-gradient-to-br from-boan-200 via-boan-100 to-white ${fullBleed ? "overflow-hidden flex flex-col" : "overflow-y-auto"}`}>
        {!canEdit && !fullBleed && (
          <div className="bg-yellow-50 border-b border-yellow-200 px-6 py-2 text-xs text-yellow-800 flex items-center gap-2">
            <span>👁️</span>
            <span>읽기 전용 모드입니다. 설정을 변경하려면 소유자 권한이 필요합니다.</span>
          </div>
        )}
        <div className={fullBleed ? "flex-1 flex min-h-0" : wideContent ? "p-8 w-full max-w-[104rem] mx-auto" : "p-8 max-w-7xl mx-auto"}>
          {/* 일반 라우트 */}
          <div className={showPersistentSurface ? "hidden" : fullBleed ? "h-full flex-1 flex min-w-0" : "h-full"}>
            <Routes>
              {/* default landing — owner: LLM Registry, viewer: org-overview */}
              <Route path="/" element={canEdit ? <Navigate to="/llm-registry" replace /> : <Navigate to="/org-overview" replace />} />
              {/* legacy /dashboard URL */}
              <Route path="/dashboard" element={<Navigate to="/llm-registry" replace />} />
              <Route path="/org" element={canEdit ? <OrgSettings /> : <ReadOnly />} />
              <Route path="/org-overview" element={<OrgOverview />} />
              <Route path="/gateway" element={canEdit ? <Policies /> : <ReadOnly />} />
              <Route path="/policies" element={<Navigate to="/gateway" replace />} />
              <Route path="/llm-registry" element={<LLMRegistry />} />
              <Route path="/audit" element={<Navigate to="/observability" replace />} />
              {/* Credentials — 모든 사용자가 본인 자격증명을 등록/관리할 수 있어야 함 */}
              <Route path="/credentials" element={<Credentials />} />
              <Route path="/approvals" element={canEdit ? <Approvals /> : <ReadOnly />} />
              <Route path="/observability" element={canEdit ? <Observability /> : <ReadOnly />} />
              <Route path="/wiki" element={<Navigate to="/wiki-graph" replace />} />
              <Route path="/wiki-graph" element={canEdit ? <WikiGraph /> : <ReadOnly />} />
              {/* Authorization = Users + SSO 통합 */}
              <Route path="/authorization" element={canEdit ? <Authorization /> : <ReadOnly />} />
              {/* legacy redirects so 직접 URL bookmark 도 동작 */}
              <Route path="/users" element={<Navigate to="/authorization?tab=users" replace />} />
              <Route path="/sso" element={<Navigate to="/authorization?tab=sso" replace />} />
              <Route path="/files" element={<FileManager />} />
              <Route path="/my-boanclaw" element={null} />
              <Route path="/my-gcp" element={null} />
            </Routes>
          </div>

          {/* 내 BoanClaw - 항상 마운트, 탭 전환시 hide/show */}
          <div
            aria-hidden={!showMyBoanClaw}
            className={`flex-1 h-full relative ${showMyBoanClaw ? "flex" : "hidden"}`}
          >
            <MyBoanClaw />
          </div>

          {/* 내 작업 컴퓨터 - 항상 마운트, 탭 전환시 hide/show → RDP 세션 유지 */}
          <div
            aria-hidden={!showMyGCP}
            className={`flex-1 h-full relative ${showMyGCP ? "flex" : "hidden"}`}
          >
            <MyGCP />
          </div>
        </div>
      </main>
    </div>
  );
}

type UsageShellProps = {
  mode: Mode;
  toggleMode: () => void;
  user: ReturnType<typeof useAuth>["user"];
  logout: ReturnType<typeof useAuth>["logout"];
  version: { current: string; latest: string; update_available: boolean } | null;
  updating: boolean;
  triggerUpdate: () => void;
};

// UsageShell — 사용모드 전용 레이아웃.
//
// 구조:  [채팅 사이드바 (왼쪽, 고정 폭) ] | [ Personal Computer 메인 영역 (오른쪽) ]
//
// 의도: 운영자가 BoanClaw 채팅을 보면서 동시에 원격 PC 를 조작할 수 있게
// 두 surface 를 항상 나란히 띄운다. 탭 전환 없음.
function UsageShell({ toggleMode, user, logout, version, updating, triggerUpdate }: UsageShellProps) {
  return (
    <div className="flex h-screen overflow-hidden">
      {/* 채팅 사이드바 — 왼쪽 */}
      <aside className="w-[420px] min-w-[360px] flex flex-col bg-boan-900 text-white border-r border-white/10">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10 flex-shrink-0">
          <span className="text-sm font-bold tracking-tight">BoanClaw</span>
          {version?.current && (
            <span className="text-[10px] text-white/30 font-mono">{version.current}</span>
          )}
          <button
            onClick={toggleMode}
            title="기본 모드로 전환 — 전체 메뉴 다시 보기"
            className="ml-auto px-2 py-0.5 text-[10px] bg-white/10 hover:bg-white/20 rounded border border-white/20 text-white/80 hover:text-white font-medium"
          >
            ← 기본 모드
          </button>
        </div>

        {/* 채팅창 (영구 마운트) — embedded 플래그로 iframe auto-focus 비활성 */}
        <div className="flex-1 min-h-0 bg-white text-gray-900">
          <MyBoanClaw embedded />
        </div>

        {/* 하단 사용자 정보 */}
        {user && (
          <div className="px-3 py-2 border-t border-white/10 flex items-center gap-2 flex-shrink-0">
            {version?.update_available && !updating && (
              <button
                onClick={triggerUpdate}
                className="px-2 py-1 bg-emerald-500/20 border border-emerald-400/30 rounded text-[10px] text-emerald-300 hover:bg-emerald-500/30"
                title={`NEW ${version.latest} — 업데이트`}
              >
                NEW
              </button>
            )}
            {updating && (
              <span className="text-[10px] text-yellow-300 animate-pulse">업데이트 중...</span>
            )}
            {user.org_id && (
              <span className="text-[10px] text-white/50 font-mono truncate">🏢 {user.org_id}</span>
            )}
            <div className="flex-1 min-w-0 flex items-center gap-2 ml-auto justify-end">
              <span className="text-xs text-white/70 truncate">{user.name ?? user.email}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${ROLE_COLOR[user.role] ?? ROLE_COLOR.user}`}>
                {user.role_label}
              </span>
              <button
                onClick={logout}
                title="로그아웃"
                className="text-[10px] text-white/40 hover:text-white/80 px-1.5 py-0.5 rounded hover:bg-white/10"
              >
                ↗
              </button>
            </div>
          </div>
        )}
      </aside>

      {/* Personal Computer (영구 마운트 → RDP 세션 유지) */}
      <main className="flex-1 flex flex-col bg-gradient-to-br from-boan-200 via-boan-100 to-white overflow-hidden">
        <MyGCP alwaysActive />
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
