import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth";

interface SSOProvider {
  id: string;
  label: string;
  url: string;
  configured: boolean;
  setup_url: string;
  redirect_uri: string;
}

function GoogleIcon() {
  return (
    <svg className="w-4 h-4 flex-shrink-0" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.47 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  );
}

function SetupGuide({ provider, onClose }: { provider: SSOProvider; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold text-gray-800 flex items-center gap-2">
            <GoogleIcon /> Google SSO 설정
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl">×</button>
        </div>
        <ol className="text-sm text-gray-600 space-y-3">
          <li className="flex gap-3"><span className="font-bold text-boan-600 w-4">1.</span>
            <span><a href={provider.setup_url} target="_blank" rel="noreferrer" className="text-blue-600 underline">GCP Console → Credentials</a>에서 OAuth 2.0 클라이언트 ID 생성</span></li>
          <li className="flex gap-3"><span className="font-bold text-boan-600 w-4">2.</span>
            <span>Authorized redirect URI 추가:</span></li>
        </ol>
        <div className="my-3 px-3 py-2 bg-gray-50 rounded-lg font-mono text-xs text-gray-700 select-all break-all">{provider.redirect_uri}</div>
        <ol className="text-sm text-gray-600 space-y-3" start={3}>
          <li className="flex gap-3"><span className="font-bold text-boan-600 w-4">3.</span>
            <span>docker-compose 환경변수 설정 후 재시작:</span></li>
        </ol>
        <div className="my-3 px-3 py-2 bg-gray-900 rounded-lg font-mono text-xs text-green-400 space-y-1">
          <div>BOAN_OAUTH_CLIENT_ID=<span className="text-yellow-300">your-client-id</span></div>
          <div>BOAN_OAUTH_CLIENT_SECRET=<span className="text-yellow-300">your-secret</span></div>
        </div>
        <button onClick={onClose} className="mt-4 w-full py-2.5 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700">확인</button>
      </div>
    </div>
  );
}

export default function Login() {
  const { login } = useAuth();
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [setupModal, setSetupModal] = useState<SSOProvider | null>(null);

  const [step, setStep] = useState<"email" | "otp">("email");
  const [email, setEmail] = useState("");
  const [hint, setHint] = useState("");
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const otpRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    fetch("/api/auth/config")
      .then((r) => r.json())
      .then((cfg) => setProviders(cfg.sso_providers ?? []))
      .catch(() => {});
  }, []);

  const handleSendOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/auth/send-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "실패"); return; }
      setHint(data.hint ?? "");
      setStep("otp");
      setTimeout(() => otpRefs.current[0]?.focus(), 100);
    } catch { setError("서버 연결 실패"); }
    finally { setLoading(false); }
  };

  const handleOTPChange = (idx: number, val: string) => {
    if (!/^\d*$/.test(val)) return;
    const next = [...otp];
    next[idx] = val.slice(-1);
    setOtp(next);
    if (val && idx < 5) otpRefs.current[idx + 1]?.focus();
    if (next.every((c) => c !== "") && next.join("").length === 6) {
      verifyOTP(next.join(""));
    }
  };

  const handleOTPKeyDown = (idx: number, e: React.KeyboardEvent) => {
    if (e.key === "Backspace" && !otp[idx] && idx > 0) {
      otpRefs.current[idx - 1]?.focus();
    }
  };

  const verifyOTP = async (code: string) => {
    setError(null);
    setLoading(true);
    try {
      await login(email, code);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "코드가 올바르지 않습니다.");
      setOtp(["", "", "", "", "", ""]);
      setTimeout(() => otpRefs.current[0]?.focus(), 100);
    } finally { setLoading(false); }
  };

  const handleOTPSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    verifyOTP(otp.join(""));
  };

  const handleSSO = (p: SSOProvider) => {
    if (!p.configured) { setSetupModal(p); return; }
    window.location.href = p.url;
  };

  return (
    <div className="min-h-screen bg-boan-900 flex items-center justify-center p-4">
      {setupModal && <SetupGuide provider={setupModal} onClose={() => setSetupModal(null)} />}

      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <span className="text-4xl">🛡️</span>
          <h1 className="text-2xl font-bold text-white mt-2">BoanClaw</h1>
          <p className="text-boan-300 text-xs mt-1">Samsung SDS</p>
        </div>

        <div className="bg-white rounded-2xl shadow-2xl p-8">
          {step === "email" ? (
            <>
              {providers.map((p) => (
                <button key={p.id} onClick={() => handleSSO(p)}
                  className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-medium border-2 transition-all mb-4 ${
                    p.configured
                      ? "border-gray-200 text-gray-700 hover:border-blue-400 hover:bg-blue-50"
                      : "border-dashed border-gray-200 text-gray-400 hover:border-gray-300"
                  }`}>
                  <GoogleIcon />
                  <span>Google 계정으로 로그인</span>
                  {!p.configured && <span className="ml-1 text-xs bg-gray-100 text-gray-400 px-1.5 py-0.5 rounded">미설정</span>}
                </button>
              ))}

              <div className="flex items-center gap-3 mb-4">
                <div className="flex-1 h-px bg-gray-100" />
                <span className="text-xs text-gray-400">이메일로 로그인</span>
                <div className="flex-1 h-px bg-gray-100" />
              </div>

              <form onSubmit={handleSendOTP} className="space-y-3">
                <input
                  type="email" placeholder="회사 이메일" value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email" required
                  className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
                />
                {error && <p className="text-xs text-red-500 text-center">{error}</p>}
                <button type="submit" disabled={loading || !email}
                  className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40">
                  {loading ? "전송 중..." : "코드 받기"}
                </button>
              </form>

              <p className="mt-4 text-center text-xs text-gray-400">
                계정이 없으신가요?{" "}
                <Link to="/register" className="text-boan-600 hover:underline font-medium">회원가입</Link>
              </p>
            </>
          ) : (
            <>
              <button onClick={() => { setStep("email"); setOtp(["","","","","",""]); setError(null); }}
                className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 mb-5">
                ← 이메일 변경
              </button>

              <div className="text-center mb-6">
                <p className="text-sm font-medium text-gray-800">코드를 입력하세요</p>
                <p className="text-xs text-gray-500 mt-1">{email}</p>
                <p className="text-xs text-gray-400 mt-1">{hint}</p>
              </div>

              <form onSubmit={handleOTPSubmit} className="space-y-4">
                <div className="flex justify-center gap-2">
                  {otp.map((digit, idx) => (
                    <input
                      key={idx}
                      ref={(el) => { otpRefs.current[idx] = el; }}
                      type="text" inputMode="numeric" maxLength={1}
                      value={digit}
                      onChange={(e) => handleOTPChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOTPKeyDown(idx, e)}
                      className="w-11 h-14 text-center text-2xl font-bold border-2 border-gray-200 rounded-xl focus:outline-none focus:border-boan-500 focus:ring-2 focus:ring-boan-100"
                    />
                  ))}
                </div>

                {error && <p className="text-xs text-red-500 text-center">{error}</p>}

                <button type="submit" disabled={loading || otp.some((c) => !c)}
                  className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40">
                  {loading ? "확인 중..." : "로그인"}
                </button>

                <button type="button" onClick={() => { setStep("email"); setOtp(["","","","","",""]); }}
                  className="w-full py-2 text-xs text-gray-400 hover:text-gray-600">
                  코드 재전송
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
