import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth";

const LAST_LOGIN_EMAIL_KEY = "boanclaw:last-login-email";

export default function Login() {
  const { login } = useAuth();

  const [step, setStep] = useState<"email" | "otp">("email");
  const [email, setEmail] = useState(() => {
    if (typeof window === "undefined") {
      return "";
    }
    return window.localStorage.getItem(LAST_LOGIN_EMAIL_KEY) ?? "";
  });
  const [hint, setHint] = useState("");
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [testMode, setTestMode] = useState(false);
  const [ownerEmail, setOwnerEmail] = useState("");
  const otpRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const normalized = email.trim();
    if (normalized) {
      window.localStorage.setItem(LAST_LOGIN_EMAIL_KEY, normalized);
    } else {
      window.localStorage.removeItem(LAST_LOGIN_EMAIL_KEY);
    }
  }, [email]);

  useEffect(() => {
    let cancelled = false;
    const loadConfig = async () => {
      try {
        const res = await fetch("/api/auth/config");
        const data = await res.json();
        if (cancelled) {
          return;
        }
        setTestMode(Boolean(data.test_mode));
        setOwnerEmail(typeof data.owner_email === "string" ? data.owner_email : "");
      } catch {
        if (!cancelled) {
          setTestMode(false);
          setOwnerEmail("");
        }
      }
    };
    loadConfig();
    return () => {
      cancelled = true;
    };
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
      if (!res.ok) {
        setError(data.error ?? "실패");
        return;
      }
      if (typeof window !== "undefined") {
        window.localStorage.setItem(LAST_LOGIN_EMAIL_KEY, email.trim());
      }
      if (data.status === "ok" && data.bypass_otp) {
        window.location.assign("/");
        return;
      }
      setHint(data.hint ?? "");
      setStep("otp");
      setTimeout(() => otpRefs.current[0]?.focus(), 100);
    } catch {
      setError("서버 연결 실패");
    } finally {
      setLoading(false);
    }
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
      if (typeof window !== "undefined") {
        window.localStorage.setItem(LAST_LOGIN_EMAIL_KEY, email.trim());
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "코드가 올바르지 않습니다.");
      setOtp(["", "", "", "", "", ""]);
      setTimeout(() => otpRefs.current[0]?.focus(), 100);
    } finally {
      setLoading(false);
    }
  };

  const handleOTPSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    verifyOTP(otp.join(""));
  };

  return (
    <div className="min-h-screen bg-boan-900 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <span className="text-4xl">🛡️</span>
          <h1 className="text-2xl font-bold text-white mt-2">BoanClaw</h1>
          <p className="text-boan-300 text-xs mt-1">Samsung SDS</p>
        </div>

        <div className="bg-white rounded-2xl shadow-2xl p-8">
          {testMode ? (
            <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-left">
              <p className="text-xs font-semibold text-amber-800">TEST MODE</p>
              <p className="mt-1 text-xs text-amber-700">
                테스트 환경입니다. 소유자 계정은 OTP 없이 바로 로그인됩니다.
              </p>
              {ownerEmail ? (
                <p className="mt-1 text-[11px] text-amber-700">소유자 계정: {ownerEmail}</p>
              ) : null}
            </div>
          ) : null}
          {step === "email" ? (
            <>
              <div className="mb-5 text-center">
                <p className="text-sm font-semibold text-gray-800">회사 이메일로 로그인</p>
                <p className="mt-1 text-xs text-gray-400">허용된 회사 이메일로 6자리 인증 코드를 전송합니다.</p>
              </div>

              <form onSubmit={handleSendOTP} className="space-y-3">
                <input
                  type="email"
                  placeholder="회사 이메일"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  required
                  className="w-full px-4 py-3 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
                />
                {error && <p className="text-xs text-red-500 text-center">{error}</p>}
                <button
                  type="submit"
                  disabled={loading || !email}
                  className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40"
                >
                  {loading
                    ? "전송 중..."
                    : testMode && ownerEmail && email.trim().toLowerCase() === ownerEmail.trim().toLowerCase()
                      ? "테스트 로그인"
                      : "코드 받기"}
                </button>
              </form>

              <p className="mt-4 text-center text-xs text-gray-400">
                계정이 없으신가요?{" "}
                <Link to="/register" className="text-boan-600 hover:underline font-medium">
                  회원가입
                </Link>
              </p>
            </>
          ) : (
            <>
              <button
                onClick={() => {
                  setStep("email");
                  setOtp(["", "", "", "", "", ""]);
                  setError(null);
                }}
                className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600 mb-5"
              >
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
                      ref={(el) => {
                        otpRefs.current[idx] = el;
                      }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={digit}
                      onChange={(e) => handleOTPChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOTPKeyDown(idx, e)}
                      className="w-11 h-14 text-center text-2xl font-bold border-2 border-gray-200 rounded-xl focus:outline-none focus:border-boan-500 focus:ring-2 focus:ring-boan-100"
                    />
                  ))}
                </div>

                {error && <p className="text-xs text-red-500 text-center">{error}</p>}

                <button
                  type="submit"
                  disabled={loading || otp.some((c) => !c)}
                  className="w-full py-3 bg-boan-600 text-white rounded-xl text-sm font-medium hover:bg-boan-700 disabled:opacity-40"
                >
                  {loading ? "확인 중..." : "로그인"}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setStep("email");
                    setOtp(["", "", "", "", "", ""]);
                  }}
                  className="w-full py-2 text-xs text-gray-400 hover:text-gray-600"
                >
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
