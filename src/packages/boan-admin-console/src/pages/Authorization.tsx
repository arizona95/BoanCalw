import { useState, useEffect } from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import Users from "./Users";
import SSOSettings from "./SSOSettings";

// Authorization — Users + SSO 통합 화면.
// 옛 "🏢 조직" 탭은 사이드바의 "Organization" 메뉴로 분리됨 (호스트 ↔ 조직서버
// 연결은 user/SSO 관리와 다른 layer 라서). tab=orgs 로 들어오면 redirect.
type Tab = "users" | "sso";

export default function Authorization() {
  const location = useLocation();
  const navigate = useNavigate();
  const params = new URLSearchParams(location.search);
  const requested = params.get("tab") ?? "";
  const initialTab: Tab = requested === "sso" ? "sso" : "users";
  const [tab, setTab] = useState<Tab>(initialTab);

  useEffect(() => {
    const t = new URLSearchParams(location.search).get("tab");
    if (t === "sso" || t === "users") setTab(t);
  }, [location.search]);

  // 옛 deep-link 호환: /authorization?tab=orgs → /organization
  if (requested === "orgs") {
    return <Navigate to="/organization" replace />;
  }

  const switchTab = (next: Tab) => {
    setTab(next);
    navigate(`/authorization?tab=${next}`, { replace: true });
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Authorization</h1>
      <p className="text-sm text-gray-500 mb-6">
        사용자 계정과 SSO 인증 공급자를 통합 관리합니다.
      </p>

      <div className="flex gap-2 mb-5 border-b border-gray-200">
        {([
          { id: "users", label: "👥 Users", desc: "조직 멤버 + 권한" },
          { id: "sso", label: "🔐 SSO", desc: "OTP / OAuth 등 인증 공급자" },
        ] as const).map((t) => (
          <button
            key={t.id}
            onClick={() => switchTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? "border-boan-600 text-boan-600"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
            title={t.desc}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "users" ? <Users /> : <SSOSettings />}
    </div>
  );
}
