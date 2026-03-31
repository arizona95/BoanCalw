import { useState, useEffect } from "react";
import { gcpApi, orgSettingsApi, policyApi, type GCPOrg, type OrgPolicy, type OrgSettingsRecord } from "../api";

function Tag({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="flex items-center gap-1 px-2 py-1 bg-blue-50 border border-blue-200 rounded text-xs text-blue-800 font-mono">
      {label}
      <button onClick={onRemove} className="ml-1 text-blue-400 hover:text-red-500">×</button>
    </span>
  );
}

export default function OrgSettings() {
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [tab, setTab] = useState<"org" | "gcp" | "store">("org");
  const [orgStore, setOrgStore] = useState<OrgSettingsRecord | null>(null);
  const [storeJson, setStoreJson] = useState("");
  const [storeLoading, setStoreLoading] = useState(false);

  const [accessToken, setAccessToken] = useState("");
  const [gcpOrgId, setGcpOrgId] = useState("");
  const [gcpOrg, setGcpOrg] = useState<GCPOrg | null>(null);
  const [allowDomains, setAllowDomains] = useState<string[]>([]);
  const [domainInput, setDomainInput] = useState("");
  const [fetching, setFetching] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    policyApi.get()
      .then((p) => {
        setPolicy(p);
        const gcp = p.rules;
        if (gcp?.gcp_org_id) setGcpOrgId(gcp.gcp_org_id as string);
        const net = p.network_whitelist as Array<{ host: string }> | undefined;
        if (net) setAllowDomains(net.map((n) => n.host));
      })
      .catch(() => null);
  }, []);

  useEffect(() => {
    orgSettingsApi
      .get()
      .then((rec) => {
        setOrgStore(rec);
        setStoreJson(JSON.stringify(rec.settings ?? {}, null, 2));
      })
      .catch(() => null);
  }, []);

  const handleFetchOrg = async () => {
    if (!accessToken) { setError("Access Token을 입력하세요."); return; }
    setError(null);
    setFetching(true);
    try {
      const org = await gcpApi.fetchOrg(accessToken, gcpOrgId || undefined);
      setGcpOrg(org);
      if (org.name) {
        setGcpOrgId(org.name.replace("organizations/", ""));
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "GCP API 오류");
    } finally {
      setFetching(false);
    }
  };

  const handleSync = async () => {
    if (!gcpOrgId) { setError("GCP Org ID를 입력하세요."); return; }
    setError(null);
    setSyncing(true);
    try {
      const res = await gcpApi.sync(
        accessToken,
        gcpOrgId,
        gcpOrg?.displayName ?? gcpOrgId,
        allowDomains,
      );
      setSuccess(`GCP 조직 ${res.org_id} 동기화 완료 — 도메인 ${res.domains}개 적용됨`);
      const updated = await policyApi.get();
      setPolicy(updated);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "동기화 실패");
    } finally {
      setSyncing(false);
    }
  };

  const addDomain = () => {
    const d = domainInput.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
    if (d && !allowDomains.includes(d)) {
      setAllowDomains([...allowDomains, d]);
    }
    setDomainInput("");
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Org Settings</h1>
      <p className="text-sm text-gray-500 mb-6">
        조직 정책 서버 설정. GCP Organization과 연계하여 네트워크 화이트리스트를 자동 동기화합니다.
      </p>

      {error && <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>}
      {success && <div className="mb-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{success}</div>}

      {policy && (
        <div className="mb-4 flex items-center gap-3 p-3 bg-white rounded-lg border border-gray-200 text-sm">
          <span className="text-gray-500">현재 Org ID:</span>
          <span className="font-mono font-medium">{policy.org_id || "—"}</span>
          <span className="text-gray-400">|</span>
          <span className="text-gray-500">Policy 버전:</span>
          <span className="font-mono font-medium">v{policy.version}</span>
          {policy.rules?.gcp_org_id ? (
            <>
              <span className="text-gray-400">|</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-blue-50 text-blue-700">
                ☁️ GCP 연결됨: {String(policy.rules.gcp_org_id)}
              </span>
            </>
          ) : null}
        </div>
      )}

      <div className="flex gap-2 mb-5 border-b border-gray-200 flex-wrap">
        {(["org", "gcp", "store"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
              tab === t
                ? "border-boan-600 text-boan-600"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {t === "org" ? "📋 조직 기본 설정" : t === "gcp" ? "☁️ GCP 연동" : "🗄️ 조직설정 서버"}
          </button>
        ))}
      </div>

      {tab === "org" && (
        <div className="space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-base font-semibold mb-4">네트워크 화이트리스트</h2>
            <p className="text-xs text-gray-500 mb-3">
              boan-proxy가 허용하는 외부 도메인 목록입니다. GCP 연동 탭에서 자동 동기화할 수 있습니다.
            </p>
            <div className="flex gap-2 mb-3">
              <input
                type="text"
                placeholder="도메인 추가 (예: api.anthropic.com)"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addDomain()}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
              <button
                onClick={addDomain}
                className="px-3 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700"
              >
                추가
              </button>
            </div>
            <div className="flex flex-wrap gap-2 min-h-[36px]">
              {allowDomains.length === 0 ? (
                <span className="text-sm text-gray-400">등록된 도메인 없음</span>
              ) : (
                allowDomains.map((d) => (
                  <Tag
                    key={d}
                    label={d}
                    onRemove={() => setAllowDomains(allowDomains.filter((x) => x !== d))}
                  />
                ))
              )}
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-base font-semibold mb-2">배포 모드 안내</h2>
            <div className="text-sm text-gray-600 space-y-2">
              <div className="flex items-start gap-2">
                <span className="mt-0.5 text-green-600">✓</span>
                <span><b>중앙 배포</b>: boan-policy-server를 사내 서버에 단독 배포 → 모든 클라이언트가 같은 정책을 조회합니다.</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="mt-0.5 text-yellow-600">!</span>
                <span><b>로컬 배포</b>: 각 PC에 docker-compose → 설정이 PC마다 독립적으로 분리됩니다.</span>
              </div>
              <div className="mt-3 p-3 bg-blue-50 rounded-lg text-xs text-blue-800">
                <b>현재 상태</b>: 정책은 Docker 볼륨(<code>boan-policy-data</code>)에 영속 저장됩니다.
                중앙 배포 시 에이전트의 <code>BOAN_POLICY_URL</code>을 중앙 서버 주소로 설정하세요.
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "store" && (
        <div className="space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-base font-semibold mb-1">조직설정 서버 (boan-proxy)</h2>
            <p className="text-xs text-gray-500 mb-4">
              소유자·사용자 멤버십은 사용자 관리에 저장되고, 조직 단위 키·값 설정은 여기(org_settings.json)가 정본입니다.
            </p>
            {orgStore && (
              <div className="text-xs text-gray-600 mb-3 space-y-1">
                <div>
                  <span className="text-gray-500">org_id:</span>{" "}
                  <span className="font-mono">{orgStore.org_id}</span>
                </div>
                <div>
                  <span className="text-gray-500">updated_at:</span>{" "}
                  <span className="font-mono">{orgStore.updated_at}</span>
                </div>
              </div>
            )}
            <label className="block text-sm font-medium text-gray-700 mb-1">settings (JSON)</label>
            <textarea
              value={storeJson}
              onChange={(e) => setStoreJson(e.target.value)}
              rows={12}
              className="w-full font-mono text-xs p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-boan-500"
            />
            <button
              type="button"
              disabled={storeLoading}
              onClick={async () => {
                setStoreLoading(true);
                setError(null);
                setSuccess(null);
                try {
                  const parsed = JSON.parse(storeJson) as Record<string, unknown>;
                  const rec = await orgSettingsApi.patch({ settings: parsed });
                  setOrgStore(rec);
                  setSuccess("조직설정 서버에 저장했습니다.");
                } catch (e: unknown) {
                  setError(e instanceof Error ? e.message : "저장 실패");
                } finally {
                  setStoreLoading(false);
                }
              }}
              className="mt-3 px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
            >
              {storeLoading ? "저장 중…" : "설정 저장"}
            </button>
          </div>
        </div>
      )}

      {tab === "gcp" && (
        <div className="space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-base font-semibold mb-1">GCP Organization 연동</h2>
            <p className="text-xs text-gray-500 mb-4">
              GCP Access Token으로 조직 정보를 가져와 네트워크 화이트리스트에 적용합니다.
              <br />
              토큰 발급: <code className="bg-gray-100 px-1 rounded">gcloud auth print-access-token</code>
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">GCP Access Token</label>
                <textarea
                  rows={3}
                  placeholder="ya29.a0..."
                  value={accessToken}
                  onChange={(e) => setAccessToken(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-xs font-mono focus:outline-none focus:ring-2 focus:ring-boan-500 bg-gray-50"
                />
                <p className="text-xs text-gray-400 mt-1">
                  필요 권한: <code>resourcemanager.organizations.get</code>
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  GCP Org ID <span className="text-gray-400 font-normal">(선택 — 비우면 자동 검색)</span>
                </label>
                <input
                  type="text"
                  placeholder="예: 123456789012"
                  value={gcpOrgId}
                  onChange={(e) => setGcpOrgId(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-boan-500"
                />
              </div>

              <button
                onClick={handleFetchOrg}
                disabled={fetching}
                className="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {fetching ? "조회 중..." : "☁️ GCP 조직 정보 가져오기"}
              </button>
            </div>

            {gcpOrg && (
              <div className="mt-4 p-4 rounded-lg border border-green-200 bg-green-50 text-sm">
                <p className="font-semibold text-green-800 mb-2">✓ GCP 조직 확인됨</p>
                <div className="space-y-1 text-green-700 font-mono text-xs">
                  <div>name: {gcpOrg.name}</div>
                  {gcpOrg.displayName && <div>displayName: {gcpOrg.displayName}</div>}
                  {gcpOrg.state && <div>state: {gcpOrg.state}</div>}
                </div>
              </div>
            )}
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-base font-semibold mb-1">정책 동기화</h2>
            <p className="text-xs text-gray-500 mb-4">
              아래 도메인 목록을 boan-policy-server의 네트워크 화이트리스트로 적용합니다.
            </p>
            <div className="flex gap-2 mb-3">
              <input
                type="text"
                placeholder="허용 도메인 추가 (예: *.googleapis.com)"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addDomain()}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
              <button onClick={addDomain} className="px-3 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700">
                추가
              </button>
            </div>
            <div className="flex flex-wrap gap-2 min-h-[36px] mb-4">
              {allowDomains.length === 0 ? (
                <span className="text-sm text-gray-400">도메인 없음</span>
              ) : (
                allowDomains.map((d) => (
                  <Tag key={d} label={d} onRemove={() => setAllowDomains(allowDomains.filter((x) => x !== d))} />
                ))
              )}
            </div>
            <button
              onClick={handleSync}
              disabled={syncing || !gcpOrgId}
              className="px-5 py-2 text-sm rounded-lg bg-green-600 text-white hover:bg-green-700 disabled:opacity-50"
            >
              {syncing ? "동기화 중..." : "🔄 정책 서버에 적용"}
            </button>
            <p className="text-xs text-gray-400 mt-2">
              GCP Org ID 없이도 도메인 목록만 직접 입력해서 적용 가능합니다.
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 text-sm text-gray-600">
            <h2 className="text-base font-semibold mb-3 text-gray-800">GCP 연동 구조</h2>
            <div className="space-y-2">
              <div className="flex items-start gap-2">
                <span className="text-blue-500 mt-0.5">→</span>
                <span><b>GCP Resource Manager API</b>: 조직 ID/이름 조회 (<code className="bg-gray-100 px-1 rounded text-xs">resourcemanager.googleapis.com/v3/organizations</code>)</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-blue-500 mt-0.5">→</span>
                <span><b>정책 서버 동기화</b>: 가져온 조직 정보 + 도메인 목록 → <code className="bg-gray-100 px-1 rounded text-xs">boan-policy-server</code> PUT</span>
              </div>
              <div className="flex items-start gap-2">
                <span className="text-blue-500 mt-0.5">→</span>
                <span><b>모든 에이전트 즉시 반영</b>: 정책 서버가 중앙 배포 시 전체 클라이언트가 동일 정책 적용</span>
              </div>
              <div className="mt-3 p-3 bg-yellow-50 rounded-lg text-xs text-yellow-800">
                <b>TODO (추가 구현 가능)</b>: GCP Org Policy API 연동 (constraint 가져오기), Cloud Identity 그룹 기반 RBAC, Workload Identity Federation 인증
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
