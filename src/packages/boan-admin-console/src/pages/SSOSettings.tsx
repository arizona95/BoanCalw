import { useEffect, useState } from "react";
import { policyApi } from "../api";
import { useAuth } from "../auth";

function parseCsv(v: string): string[] {
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

export default function SSOSettings() {
  const { user } = useAuth();
  const [allowedDomains, setAllowedDomains] = useState("samsung.com");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [orgIdCopied, setOrgIdCopied] = useState(false);

  const orgId = user?.org_id ?? "";
  const copyOrgId = async () => {
    if (!orgId) return;
    try {
      await navigator.clipboard.writeText(orgId);
      setOrgIdCopied(true);
      window.setTimeout(() => setOrgIdCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    policyApi.get().then((p) => {
      setAllowedDomains((p.org_settings?.allowed_domains ?? ["samsung.com"]).join(", "));
    }).catch((e) => setMsg({ type: "err", text: e.message })).finally(() => setLoading(false));
  }, []);

  const save = async () => {
    setMsg(null); setSaving(true);
    try {
      await policyApi.update({ org_settings: { allowed_domains: parseCsv(allowedDomains) } });
      setMsg({ type: "ok", text: "저장됨" });
    } catch (e: unknown) {
      setMsg({ type: "err", text: e instanceof Error ? e.message : "저장 실패" });
    } finally { setSaving(false); }
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      {/* 🏢 조직 가입 ID — 새 사용자가 이 값으로 가입 신청 */}
      {orgId && (
        <div className="mb-5 rounded-xl border border-boan-200 bg-boan-50/50 p-4">
          <div className="flex items-start gap-3">
            <span className="text-2xl">🏢</span>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-gray-800">조직 가입 ID</p>
              <p className="mt-0.5 text-xs text-gray-500">
                새 사용자가 회원가입 시 이 ID 를 입력해야 본 조직으로 가입 신청이 들어옵니다.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <code className="font-mono text-base font-bold text-boan-700 bg-white border border-boan-200 px-3 py-1.5 rounded-lg select-all">
                  {orgId}
                </code>
                <button
                  onClick={copyOrgId}
                  className="text-xs px-3 py-1.5 rounded-lg bg-boan-600 text-white hover:bg-boan-700 transition-colors"
                >
                  {orgIdCopied ? "✓ 복사됨" : "📋 복사"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">SSO Settings</h1>
        <button onClick={save} disabled={saving} className="px-3 py-1.5 text-xs rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50">{saving ? "..." : "Save"}</button>
      </div>

      {msg && <div className={`mb-3 p-2 rounded-lg text-xs ${msg.type === "ok" ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700"}`}>{msg.text}</div>}

      <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold mb-1">Allowed Email Domains</h2>
          <p className="text-xs text-gray-500">이 도메인의 이메일만 로그인/가입 가능합니다. 콤마로 구분.</p>
        </div>
        <input
          value={allowedDomains}
          onChange={(e) => setAllowedDomains(e.target.value)}
          placeholder="samsung.com, samsungsds.com"
          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono"
        />
        <div className="flex flex-wrap gap-2">
          {parseCsv(allowedDomains).map((d) => (
            <span key={d} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 text-blue-700 rounded-full text-xs font-medium">
              @{d}
              <button onClick={() => setAllowedDomains(parseCsv(allowedDomains).filter((x) => x !== d).join(", "))} className="text-blue-400 hover:text-red-500">&times;</button>
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}
