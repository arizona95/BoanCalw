import { useEffect, useState } from "react";
import { orgSettingsApi, policyApi, type OrgPolicy, type OrgSettingsRecord } from "../api";

export default function OrgOverview() {
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [settings, setSettings] = useState<OrgSettingsRecord | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([policyApi.get().catch(() => null), orgSettingsApi.get().catch(() => null)])
      .then(([policyData, settingsData]) => {
        setPolicy(policyData);
        setSettings(settingsData);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="text-sm text-gray-400">조직 설정을 불러오는 중...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-800">조직 설정 확인</h1>
        <p className="mt-1 text-sm text-gray-500">
          현재 내가 속한 조직의 기본 설정과 정책 요약입니다.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card title="조직 ID" value={policy?.org_id ?? settings?.org_id ?? "-"} />
        <Card title="정책 버전" value={policy ? `v${policy.version}` : "-"} />
        <Card title="표시 이름" value={settings?.display_name ?? "-"} />
      </div>

      <section className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-base font-semibold text-gray-800 mb-3">네트워크 화이트리스트</h2>
        <div className="flex flex-wrap gap-2">
          {(policy?.network_whitelist ?? []).length > 0 ? (
            (policy?.network_whitelist ?? []).map((entry) => {
              const host = typeof entry === "string" ? entry : String((entry as { host?: string }).host ?? "-");
              return (
                <span key={host} className="px-2 py-1 rounded-full bg-emerald-50 text-emerald-700 text-xs font-medium">
                  {host}
                </span>
              );
            })
          ) : (
            <span className="text-sm text-gray-400">등록된 네트워크 항목이 없습니다.</span>
          )}
        </div>
      </section>

      <section className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-base font-semibold text-gray-800 mb-1">조직 메모</h2>
        <p className="text-xs text-gray-500 mb-4">현재 조직에 적용된 정책 항목 목록입니다.</p>
        <OrgSettingsView settings={settings?.settings ?? {}} />
      </section>
    </div>
  );
}

function Card({ title, value }: { title: string; value: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <p className="text-xs font-medium text-gray-500 mb-2">{title}</p>
      <p className="text-lg font-semibold text-gray-800 break-all">{value}</p>
    </div>
  );
}

// OrgSettingsView — settings JSON 을 사람이 읽기 쉬운 체크리스트로 표시.
// 알려진 키는 한국어 라벨 + 설명, 미지의 키는 raw key/value 로 fallback.
function OrgSettingsView({ settings }: { settings: Record<string, unknown> }) {
  const knownKeys = new Set(["credential_passthrough"]);
  const unknown = Object.entries(settings).filter(([k]) => !knownKeys.has(k));

  const credPass = settings.credential_passthrough;
  const credList: Array<{ name: string; value?: string }> = Array.isArray(credPass)
    ? credPass.map((c) => {
        if (typeof c === "string") return { name: c };
        if (c && typeof c === "object") {
          const obj = c as { name?: unknown; value?: unknown };
          return {
            name: typeof obj.name === "string" ? obj.name : String(obj.name ?? "?"),
            value: typeof obj.value === "string" ? obj.value : undefined,
          };
        }
        return { name: String(c) };
      })
    : [];

  if (Object.keys(settings).length === 0) {
    return <p className="text-sm text-gray-400">등록된 조직 메모가 없습니다.</p>;
  }

  return (
    <div className="space-y-5">
      {/* credential_passthrough */}
      <div className="border border-gray-100 rounded-lg p-4 bg-gray-50/50">
        <div className="flex items-start gap-2 mb-2">
          <span className="text-emerald-600">🔑</span>
          <div>
            <h3 className="text-sm font-semibold text-gray-800">직접 사용 허용 자격증명</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              아래 자격증명은 <span className="font-medium">credential filter 를 우회</span>하여 사용자의 코드/요청에서
              직접 그 값으로 치환됩니다 (예: API key 노출 허용).
            </p>
          </div>
        </div>
        {credList.length === 0 ? (
          <p className="ml-6 text-xs text-gray-400">등록된 항목 없음 — 모든 자격증명은 보안 필터를 통해 접근됩니다.</p>
        ) : (
          <ul className="ml-6 mt-2 space-y-1.5">
            {credList.map((c) => (
              <li key={c.name} className="flex items-center gap-2 text-sm">
                <span className="text-emerald-500 text-xs">✓</span>
                <span className="font-mono text-gray-800">{c.name}</span>
                {c.value && (
                  <span className="font-mono text-xs text-gray-400 truncate" title={c.value}>
                    ({maskSecret(c.value)})
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* unknown keys fallback */}
      {unknown.length > 0 && (
        <div className="border border-gray-100 rounded-lg p-4 bg-gray-50/50">
          <h3 className="text-sm font-semibold text-gray-800 mb-2">기타 설정</h3>
          <ul className="ml-2 space-y-1">
            {unknown.map(([k, v]) => (
              <li key={k} className="text-xs text-gray-700">
                <span className="font-mono text-gray-800">{k}:</span>{" "}
                <span className="font-mono text-gray-600">
                  {typeof v === "string" || typeof v === "number" || typeof v === "boolean"
                    ? String(v)
                    : JSON.stringify(v)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// maskSecret — sk-ant-api03-XXXX...YYYY 형태로 일부만 표시
function maskSecret(s: string): string {
  if (s.length <= 12) return "****";
  return s.slice(0, 8) + "…" + s.slice(-4);
}
