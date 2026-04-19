import { useState, useEffect, useCallback } from "react";
import { Routes, Route, NavLink, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { FocusProvider } from "./focusContext";
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
import KillChain from "./pages/KillChain";

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
        { path: "/kill-chain", label: "Kill Chain", icon: "☠️" },
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
  const isUsage = mode === "usage";
  // 사용모드에서는 두 surface 가 항상 보임. 기본모드에서는 라우트 매칭.
  const showMyBoanClaw = isUsage || location.pathname === "/my-boanclaw";
  const showMyGCP = isUsage || location.pathname === "/my-gcp";
  const showPersistentSurface = showMyBoanClaw || showMyGCP;

  return (
    <div className="flex h-screen overflow-hidden">
      {/* 좌측 사이드바 — 모드에 따라 폭/콘텐츠 달라지지만 **DOM 트리는 동일** */}
      <aside
        className={`flex flex-col bg-boan-900 text-white border-r border-white/10 transition-[width] duration-150 ${
          isUsage ? "w-[420px] min-w-[360px]" : "w-64"
        }`}
      >
        <div className={`flex items-center gap-2 border-b border-white/10 flex-shrink-0 ${isUsage ? "px-4 py-3" : "px-4 py-5"}`}>
          <span className={isUsage ? "text-sm font-bold tracking-tight" : "text-xl font-bold tracking-tight"}>
            {isUsage ? "BoanClaw" : "BoanClaw v0.4"}
          </span>
          {version?.current && (
            <span className="text-[10px] text-white/30 font-mono">{version.current}</span>
          )}
          <button
            onClick={toggleMode}
            title={isUsage ? "기본 모드로 전환 — 전체 메뉴 다시 보기" : "사용 모드로 전환 — BoanClaw 채팅 + Personal Computer 를 함께 쓰세요"}
            className="ml-auto px-2 py-0.5 text-[10px] bg-white/10 hover:bg-white/20 rounded border border-white/20 text-white/80 hover:text-white font-medium"
          >
            {isUsage ? "← 기본 모드" : "사용 모드 →"}
          </button>
        </div>

        {/* 기본모드: 내비게이션 / 사용모드: 채팅 자리 (실제 MyBoanClaw 는 아래 공통 영역에서 렌더됨) */}
        <nav className={`flex-1 py-4 space-y-1 ${isUsage ? "hidden" : "block"}`}>
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

        {/* 사용모드: 채팅이 들어갈 빈 슬롯 (MyBoanClaw 는 아래 portal 위치에서 렌더해서
            position 고정) — 여기서는 공간만 잡아주고 chat iframe 이 flex-1 로 채움 */}
        <div
          id="boan-chat-slot"
          className={`flex-1 min-h-0 bg-white text-gray-900 ${isUsage ? "block" : "hidden"}`}
        />

        {user && (
          <div className={`border-t border-white/10 flex-shrink-0 ${isUsage ? "px-3 py-2 flex items-center gap-2" : "px-4 py-3 space-y-2"}`}>
            {version?.update_available && !updating && (
              <button
                onClick={triggerUpdate}
                className={isUsage
                  ? "px-2 py-1 bg-emerald-500/20 border border-emerald-400/30 rounded text-[10px] text-emerald-300 hover:bg-emerald-500/30"
                  : "w-full px-2 py-1.5 bg-emerald-500/20 border border-emerald-400/30 rounded-lg text-xs text-emerald-300 hover:bg-emerald-500/30 transition-colors text-left"}
                title={isUsage ? `NEW ${version.latest} — 업데이트` : undefined}
              >
                {isUsage ? "NEW" : (
                  <>
                    <span className="font-medium">NEW {version.latest}</span>
                    <span className="block text-emerald-400/60 text-[10px] mt-0.5">업데이트 하시겠습니까?</span>
                  </>
                )}
              </button>
            )}
            {updating && (
              isUsage
                ? <span className="text-[10px] text-yellow-300 animate-pulse">업데이트 중...</span>
                : <div className="px-2 py-1.5 bg-yellow-500/20 border border-yellow-400/30 rounded-lg text-xs text-yellow-300 animate-pulse">업데이트 중... 잠시 후 새로고침됩니다</div>
            )}
            {user.org_id && (
              isUsage
                ? <span className="text-[10px] text-white/50 font-mono truncate">🏢 {user.org_id}</span>
                : (
                  <div className="flex items-center gap-1.5 px-2 py-1 bg-white/5 rounded-lg">
                    <span className="text-white/40 text-xs">🏢</span>
                    <span className="text-xs text-white/60 font-mono truncate">{user.org_id}</span>
                  </div>
                )
            )}
            {isUsage ? (
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
            ) : (
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
            )}
          </div>
        )}
      </aside>

      <main className={`flex-1 bg-gradient-to-br from-boan-200 via-boan-100 to-white ${fullBleed || isUsage ? "overflow-hidden flex flex-col" : "overflow-y-auto"}`}>
        {!canEdit && !fullBleed && !isUsage && (
          <div className="bg-yellow-50 border-b border-yellow-200 px-6 py-2 text-xs text-yellow-800 flex items-center gap-2">
            <span>👁️</span>
            <span>읽기 전용 모드입니다. 설정을 변경하려면 소유자 권한이 필요합니다.</span>
          </div>
        )}
        <div className={isUsage ? "flex-1 flex min-h-0" : fullBleed ? "flex-1 flex min-h-0" : wideContent ? "p-8 w-full max-w-[104rem] mx-auto" : "p-8 max-w-7xl mx-auto"}>
          {/* 일반 라우트 — 사용모드이거나 my-boanclaw/my-gcp 일 땐 숨김 */}
          <div className={isUsage || showPersistentSurface ? "hidden" : fullBleed ? "h-full flex-1 flex min-w-0" : "h-full"}>
            <Routes>
              <Route path="/" element={canEdit ? <Navigate to="/llm-registry" replace /> : <Navigate to="/org-overview" replace />} />
              <Route path="/dashboard" element={<Navigate to="/llm-registry" replace />} />
              <Route path="/org" element={canEdit ? <OrgSettings /> : <ReadOnly />} />
              <Route path="/org-overview" element={<OrgOverview />} />
              <Route path="/gateway" element={canEdit ? <Policies /> : <ReadOnly />} />
              <Route path="/policies" element={<Navigate to="/gateway" replace />} />
              <Route path="/llm-registry" element={<LLMRegistry />} />
              <Route path="/audit" element={<Navigate to="/observability" replace />} />
              <Route path="/credentials" element={<Credentials />} />
              <Route path="/approvals" element={canEdit ? <Approvals /> : <ReadOnly />} />
              <Route path="/observability" element={canEdit ? <Observability /> : <ReadOnly />} />
              <Route path="/kill-chain" element={canEdit ? <KillChain /> : <ReadOnly />} />
              <Route path="/wiki" element={<Navigate to="/wiki-graph" replace />} />
              <Route path="/wiki-graph" element={canEdit ? <WikiGraph /> : <ReadOnly />} />
              <Route path="/authorization" element={canEdit ? <Authorization /> : <ReadOnly />} />
              <Route path="/users" element={<Navigate to="/authorization?tab=users" replace />} />
              <Route path="/sso" element={<Navigate to="/authorization?tab=sso" replace />} />
              <Route path="/files" element={<FileManager />} />
              <Route path="/my-boanclaw" element={null} />
              <Route path="/my-gcp" element={null} />
            </Routes>
          </div>

          {/* 내 작업 컴퓨터 — 항상 동일 DOM 위치에 마운트. 사용모드/라우트 전환은
              className 변경만 → RDP + Guacamole 세션 유지. 재연결 없음. */}
          <div
            aria-hidden={!showMyGCP}
            className={`flex-1 h-full relative ${showMyGCP ? "flex" : "hidden"}`}
          >
            <MyGCP alwaysActive />
          </div>
        </div>
      </main>

      {/*
        MyBoanClaw — 앱 전체에서 유일한 인스턴스. 위치는 mode 에 따라 CSS 로만
        바뀐다. DOM 트리의 position 은 고정 → iframe 이 unmount 안 되므로
        세션 재연결 없음.

        기본모드 + /my-boanclaw 라우트:
          사이드바 오른쪽 전체 영역에 오버레이
        사용모드:
          왼쪽 사이드바 내부의 chat-slot 위치에 오버레이 (top/bottom offset 으로
          사이드바 헤더 + 푸터 피함)
        그 외: hidden
      */}
      <div
        aria-hidden={!showMyBoanClaw}
        className={(() => {
          if (isUsage) {
            // 사이드바 폭 420 + 헤더 ~48 + 푸터 ~40 offset
            return "fixed z-10 left-0 top-[48px] bottom-[40px] w-[420px] min-w-[360px]";
          }
          if (location.pathname === "/my-boanclaw") {
            // 사이드바 오른쪽 전체
            return "fixed z-10 left-64 right-0 top-0 bottom-0";
          }
          return "hidden";
        })()}
      >
        <MyBoanClaw embedded={isUsage} />
      </div>
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
      <FocusProvider>
        <Routes>
          <Route path="/login" element={<LoginGuard />} />
          <Route path="/register" element={<RegisterGuard />} />
          <Route path="/select-org" element={<SelectOrg />} />
          <Route path="/*" element={<Shell />} />
        </Routes>
      </FocusProvider>
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
