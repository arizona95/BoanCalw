import { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import Users from "./Users";
import SSOSettings from "./SSOSettings";
import OrgRegistry from "./OrgRegistry";

// Authorization — Users, SSO, Orgs 통합 화면.
// URL pattern: /authorization?tab=users (default) | tab=sso | tab=orgs
type Tab = "users" | "sso" | "orgs";

export default function Authorization() {
  const location = useLocation();
  const navigate = useNavigate();
  const params = new URLSearchParams(location.search);
  const initialTab: Tab = ["sso", "orgs"].includes(params.get("tab") ?? "")
    ? (params.get("tab") as Tab)
    : "users";
  const [tab, setTab] = useState<Tab>(initialTab);

  useEffect(() => {
    const t = new URLSearchParams(location.search).get("tab");
    if (t === "sso" || t === "users" || t === "orgs") setTab(t);
  }, [location.search]);

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
          { id: "orgs", label: "🏢 조직", desc: "연결된 조직서버 (URL + 토큰)" },
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

      {tab === "users" ? <Users /> : tab === "sso" ? <SSOSettings /> : <OrgRegistry />}
    </div>
  );
}
