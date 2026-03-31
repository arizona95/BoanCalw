import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

export default function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [orgId, setOrgId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [isOwner, setIsOwner] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError("비밀번호가 일치하지 않습니다.");
      return;
    }
    if (password.length < 8) {
      setError("비밀번호는 8자 이상이어야 합니다.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, org_id: orgId }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "회원가입 실패");
        return;
      }
      setIsOwner(data.role === "owner");
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
          <div className="text-5xl">{isOwner ? "🎉" : "✅"}</div>
          <h2 className="text-xl font-bold text-gray-800">
            {isOwner ? "소유자 계정 생성 완료" : "가입 신청 완료"}
          </h2>
          <p className="text-sm text-gray-500">
            {isOwner
              ? "고정 소유자 계정으로 등록되었습니다. 바로 로그인할 수 있습니다."
              : "관리자 승인 후 로그인할 수 있습니다."}
          </p>
          <button
            onClick={() => navigate("/login")}
            className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700"
          >
            로그인으로
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
          <p className="text-boan-300 text-xs mt-1">계정 만들기</p>
        </div>

        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <form onSubmit={handleSubmit} className="space-y-3">
            <div>
              <input
                type="email"
                placeholder="이메일"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>
            <div>
              <input
                type="password"
                placeholder="비밀번호 (8자 이상)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="new-password"
                className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>
            <div>
              <input
                type="password"
                placeholder="비밀번호 확인"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                autoComplete="new-password"
                className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>
            <div>
              <input
                type="text"
                placeholder="조직 ID (선택, 미입력시 이메일 도메인)"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
            </div>

            {error && <p className="text-xs text-red-500 text-center">{error}</p>}

            <button
              type="submit"
              disabled={loading || !email || !password || !confirm}
              className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40 transition-colors"
            >
              {loading ? "처리 중..." : "가입하기"}
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-gray-400">
            이미 계정이 있으신가요?{" "}
            <Link to="/login" className="text-boan-600 hover:underline font-medium">
              로그인
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
