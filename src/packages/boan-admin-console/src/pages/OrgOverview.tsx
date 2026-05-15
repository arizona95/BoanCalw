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
  const entries = Object.entries(settings);

  if (entries.length === 0) {
    return <p className="text-sm text-gray-400">등록된 조직 메모가 없습니다.</p>;
  }

  return (
    <div className="space-y-5">
      <div className="border border-gray-100 rounded-lg p-4 bg-gray-50/50">
        <h3 className="text-sm font-semibold text-gray-800 mb-2">조직 설정</h3>
        <ul className="ml-2 space-y-1">
          {entries.map(([k, v]) => (
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
    </div>
  );
}

