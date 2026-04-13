import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

// Register — 사용자 가입 UX (한 줄 설치 후 처음 보는 화면).
// 입력: 조직 ID (소유자가 알려준) + 이메일 (SSO 용).
// 비밀번호 / URL / 토큰 등은 사용자가 건드리지 않음.
// 뒤에서 proxy 가 org_id → URL 을 pattern 으로 resolve 하고, 공개 register 엔드포인트 호출.
export default function Register() {
  const navigate = useNavigate();
  const [orgID, setOrgID] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/auth/join-org", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, org_id: orgID }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "가입 신청 실패");
        return;
      }
      setDone(true);
    } catch {
      setError("서버 연결 실패");
    } finally {
      setLoading(false);
    }
  };

  if (done) {
    return (
      <div className="min-h-screen bg-boan-900 flex items-center justify-center p-4">
        <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-sm text-center space-y-4">
          <div className="text-5xl">✅</div>
          <h2 className="text-xl font-bold text-gray-800">사용 요청 완료</h2>
          <p className="text-sm text-gray-500">
            조직 <b className="font-mono">{orgID}</b> 의 소유자에게 사용 요청이 전달되었습니다.<br />
            승인 후 이 화면에서 로그인할 수 있습니다.
          </p>
          <button
            onClick={() => navigate("/login")}
            className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700"
          >
            로그인 화면으로
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-boan-900 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <span className="text-4xl">🛡️</span>
          <h1 className="text-2xl font-bold text-white mt-2">BoanClaw</h1>
          <p className="text-boan-300 text-xs mt-1">조직 가입 요청</p>
        </div>

        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <p className="text-center text-xs text-gray-500 mb-5">
            조직 소유자에게 받은 조직 ID 와<br />본인 회사 이메일을 입력하세요.
          </p>
          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <label className="text-[11px] font-medium text-gray-500 ml-1">조직 ID</label>
              <input
                type="text"
                placeholder="예: sds-corp"
                value={orgID}
                onChange={(e) => setOrgID(e.target.value)}
                required
                autoCapitalize="none"
                autoComplete="off"
                className="w-full mt-1 px-4 py-3 border border-gray-200 rounded-xl text-sm font-mono focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>
            <div>
              <label className="text-[11px] font-medium text-gray-500 ml-1">회사 이메일</label>
              <input
                type="email"
                placeholder="user@samsung.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full mt-1 px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>
            {error && <p className="text-xs text-red-500 text-center">{error}</p>}

            <button
              type="submit"
              disabled={loading || !orgID || !email}
              className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40 transition-colors"
            >
              {loading ? "요청 중..." : "사용 요청"}
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-gray-400">
            이미 가입된 상태인가요?{" "}
            <Link to="/login" className="text-boan-600 hover:underline font-medium">
              로그인
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
