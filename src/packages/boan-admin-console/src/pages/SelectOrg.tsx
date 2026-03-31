import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

interface OrgOption {
  name: string;
  displayName: string;
  state: string;
  OrgID: string;
}

interface PendingData {
  orgs: OrgOption[];
  access_token: string;
  user_info: { sub: string; email: string; name: string };
}

export default function SelectOrg() {
  const navigate = useNavigate();
  const [data, setData] = useState<PendingData | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const encoded = params.get("data");
    if (!encoded) { navigate("/login"); return; }
    try {
      const decoded = JSON.parse(atob(encoded)) as PendingData;
      setData(decoded);
      if (decoded.orgs.length > 0) setSelected(decoded.orgs[0].OrgID);
    } catch {
      navigate("/login");
    }
  }, [navigate]);

  const handleSelect = async () => {
    if (!data || !selected) return;
    setLoading(true);
    setError(null);
    try {
      const org = data.orgs.find((o) => o.OrgID === selected);
      const res = await fetch("/api/auth/select-org", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          access_token: data.access_token,
          org_id: selected,
          email: data.user_info.email,
          name: data.user_info.name,
          sub: data.user_info.sub,
        }),
      });
      if (!res.ok) throw new Error(`${res.status}`);
      navigate("/?login=ok");
      void org;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "선택 실패");
    } finally {
      setLoading(false);
    }
  };

  if (!data) return null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-boan-900 to-boan-700 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl p-8">
        <div className="text-center mb-6">
          <div className="text-3xl mb-2">🏢</div>
          <h2 className="text-xl font-bold text-gray-800">조직 선택</h2>
          <p className="text-sm text-gray-500 mt-1">
            <span className="font-medium">{data.user_info.email}</span> 계정이
            여러 GCP 조직에 속해 있습니다.
          </p>
        </div>

        <div className="space-y-2 mb-6">
          {data.orgs.map((org) => (
            <label
              key={org.OrgID}
              className={`flex items-center gap-4 p-4 border-2 rounded-xl cursor-pointer transition-colors ${
                selected === org.OrgID
                  ? "border-boan-500 bg-boan-50"
                  : "border-gray-200 hover:border-gray-300"
              }`}
            >
              <input
                type="radio"
                name="org"
                value={org.OrgID}
                checked={selected === org.OrgID}
                onChange={() => setSelected(org.OrgID)}
                className="accent-boan-600"
              />
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-gray-800 truncate">
                  {org.displayName || org.name}
                </div>
                <div className="text-xs text-gray-400 font-mono">ID: {org.OrgID}</div>
                <div className={`text-xs mt-0.5 ${org.state === "ACTIVE" ? "text-green-600" : "text-gray-400"}`}>
                  {org.state}
                </div>
              </div>
            </label>
          ))}
        </div>

        {error && <p className="text-xs text-red-600 mb-3">{error}</p>}

        <button
          onClick={handleSelect}
          disabled={loading || !selected}
          className="w-full py-3 rounded-xl bg-boan-600 text-white font-medium hover:bg-boan-700 disabled:opacity-50"
        >
          {loading ? "연결 중..." : "이 조직으로 입장"}
        </button>

        <p className="text-xs text-gray-400 text-center mt-3">
          선택한 조직의 정책, 크레덴셜, LLM 레지스트리는 다른 조직과 완전히 분리됩니다.
        </p>
      </div>
    </div>
  );
}
