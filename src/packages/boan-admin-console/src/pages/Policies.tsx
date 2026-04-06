import { useEffect, useMemo, useState } from "react";
import {
  policyApi,
  type NetworkEndpoint,
  type OrgPolicy,
} from "../api";

type EndpointRow = {
  id: string;
  host: string;
  ports: string;
  methods: string;
};

function makeRow(seed?: Partial<EndpointRow>): EndpointRow {
  return {
    id: Math.random().toString(36).slice(2, 10),
    host: seed?.host ?? "",
    ports: seed?.ports ?? "443",
    methods: seed?.methods ?? "POST",
  };
}

function endpointToRow(endpoint: NetworkEndpoint): EndpointRow {
  return makeRow({
    host: endpoint.host ?? "",
    ports: (endpoint.ports ?? []).join(",") || "443",
    methods: (endpoint.methods ?? []).join(",") || "POST",
  });
}

function parseCsv(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function parsePorts(value: string): number[] {
  return parseCsv(value)
    .map((part) => Number(part))
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
}

function buildNetworkWhitelist(rows: EndpointRow[]): NetworkEndpoint[] {
  return rows
    .map((row) => ({
      host: row.host.trim(),
      ports: parsePorts(row.ports),
      methods: parseCsv(row.methods).map((method) => method.toUpperCase()),
    }))
    .filter((row) => row.host)
    .map((row) => ({
      host: row.host,
      ports: row.ports.length > 0 ? row.ports : [443],
      methods: row.methods.length > 0 ? row.methods : ["POST"],
    }));
}

function validateRows(rows: EndpointRow[]): string | null {
  for (const row of rows) {
    if (!row.host.trim()) {
      continue;
    }
    if (parsePorts(row.ports).length === 0) {
      return `포트 형식이 잘못되었습니다: ${row.host}`;
    }
    if (parseCsv(row.methods).length === 0) {
      return `메서드 형식이 잘못되었습니다: ${row.host}`;
    }
  }
  return null;
}

export default function Policies() {
  const [policy, setPolicy] = useState<OrgPolicy | null>(null);
  const [rows, setRows] = useState<EndpointRow[]>([makeRow()]);
  const [allowedModels, setAllowedModels] = useState("security");
  const [minVersion, setMinVersion] = useState("0.1.0");
  const [blockedVersions, setBlockedVersions] = useState("");
  const [featureRemoteControl, setFeatureRemoteControl] = useState(false);
  const [featureWebAccess, setFeatureWebAccess] = useState(false);
  const [featureScheduledTasks, setFeatureScheduledTasks] = useState(true);
  const [mountRoot, setMountRoot] = useState("/workspace/boanclaw");
  const [guardrailConstitution, setGuardrailConstitution] = useState("");
  const [autoApproveMode, setAutoApproveMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const whitelistPreview = useMemo(() => buildNetworkWhitelist(rows), [rows]);

  const load = () => {
    setLoading(true);
    policyApi
      .get()
      .then((p) => {
        setPolicy(p);
        const networkRows = (p.network_whitelist ?? []).map(endpointToRow);
        setRows(networkRows.length > 0 ? networkRows : [makeRow()]);
        setAllowedModels((p.allow_models ?? ["security"]).join(", "));
        setMinVersion(p.version_policy?.min_version ?? "0.1.0");
        setBlockedVersions((p.version_policy?.blocked_versions ?? []).join(", "));
        setFeatureRemoteControl(Boolean(p.features?.remote_control));
        setFeatureWebAccess(Boolean(p.features?.web_access));
        setFeatureScheduledTasks(
          p.features?.scheduled_tasks === undefined ? true : Boolean(p.features?.scheduled_tasks),
        );
        setMountRoot(p.org_settings?.mount_root ?? "/workspace/boanclaw");
        setGuardrailConstitution(
          p.guardrail?.constitution ??
            "가드레일 헌법: 자격증명, 비밀번호, 토큰, 개인정보, 사내 비밀, 고객 데이터, 민감한 운영 명령은 외부로 그대로 내보내지 않는다. 완전 무해한 일반 텍스트만 허용한다. 애매하면 ask 로 분류하고 사람 확인을 거친다.",
        );
        setAutoApproveMode(Boolean(p.guardrail?.auto_approve_mode));
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const updateRow = (id: string, patch: Partial<EndpointRow>) => {
    setRows((current) => current.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  };

  const handleSave = async () => {
    setError(null);
    setSuccess(null);
    const validationError = validateRows(rows);
    if (validationError) {
      setError(validationError);
      return;
    }
    try {
      setSaving(true);
      const payload = {
        network_whitelist: whitelistPreview,
        allow_models: parseCsv(allowedModels),
        features: {
          remote_control: featureRemoteControl,
          web_access: featureWebAccess,
          scheduled_tasks: featureScheduledTasks,
        },
        version_policy: {
          min_version: minVersion.trim(),
          blocked_versions: parseCsv(blockedVersions),
          update_channel: "stable",
        },
        org_settings: {
          mount_root: mountRoot.trim(),
        },
        guardrail: {
          constitution: guardrailConstitution.trim(),
          auto_approve_mode: autoApproveMode,
        },
      };
      const updated = await policyApi.update(payload);
      setPolicy(updated);
      setSuccess("화이트리스트 정책을 저장했습니다.");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "정책 저장 실패");
    } finally {
      setSaving(false);
    }
  };

  const handleRollback = async () => {
    setError(null);
    setSuccess(null);
    try {
      setSaving(true);
      await policyApi.rollback();
      load();
      setSuccess("정책 롤백을 요청했습니다.");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Rollback failed");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Network Policy</h1>
          {policy && (
            <p className="text-sm text-gray-500 mt-1">
              Version {policy.version} · Org: {policy.org_id} · Updated: {policy.updated_at}
            </p>
          )}
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleRollback}
            disabled={saving}
            className="px-4 py-2 text-sm rounded-lg border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
          >
            Rollback
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Policy"}
          </button>
        </div>
      </div>

      {error && <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>}
      {success && <div className="mb-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{success}</div>}

      <div className="grid gap-5">
        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="mb-4">
            <h2 className="text-base font-semibold">Fail-Closed Egress Allowlist</h2>
            <p className="text-xs text-gray-500 mt-1">
              기본은 전부 차단입니다. 여기에 등록한 host/port/method만 S2에서 외부로 나갈 수 있습니다.
            </p>
          </div>

          <div className="space-y-3">
            {rows.map((row, index) => (
              <div key={row.id} className="grid gap-2 md:grid-cols-[2fr_1fr_1fr_auto]">
                <input
                  type="text"
                  value={row.host}
                  onChange={(e) => updateRow(row.id, { host: e.target.value })}
                  placeholder="api.example.com"
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
                />
                <input
                  type="text"
                  value={row.ports}
                  onChange={(e) => updateRow(row.id, { ports: e.target.value })}
                  placeholder="443"
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
                />
                <input
                  type="text"
                  value={row.methods}
                  onChange={(e) => updateRow(row.id, { methods: e.target.value })}
                  placeholder="POST,GET"
                  className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
                />
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setRows((current) => current.filter((item) => item.id !== row.id))}
                    disabled={rows.length === 1}
                    className="px-3 py-2 text-sm rounded-lg border border-gray-300 hover:bg-gray-100 disabled:opacity-50"
                    aria-label={`remove-endpoint-${index}`}
                  >
                    −
                  </button>
                  {index === rows.length - 1 && (
                    <button
                      type="button"
                      onClick={() => setRows((current) => [...current, makeRow()])}
                      className="px-3 py-2 text-sm rounded-lg bg-gray-900 text-white hover:bg-black"
                      aria-label="add-endpoint"
                    >
                      +
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 p-3 rounded-lg bg-gray-50 border border-gray-200">
            <p className="text-xs font-medium text-gray-700 mb-2">저장될 allowlist 미리보기</p>
            <pre className="text-xs text-gray-600 whitespace-pre-wrap">
              {JSON.stringify(whitelistPreview, null, 2)}
            </pre>
          </div>
        </section>

        <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-base font-semibold mb-4">Security Defaults</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="block">
              <span className="text-sm font-medium text-gray-700">허용 모델 목록</span>
              <input
                type="text"
                value={allowedModels}
                onChange={(e) => setAllowedModels(e.target.value)}
                placeholder="security, minimax-m2.7-cloud"
                className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-gray-700">최소 클라이언트 버전</span>
              <input
                type="text"
                value={minVersion}
                onChange={(e) => setMinVersion(e.target.value)}
                className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </label>
            <label className="block md:col-span-2">
              <span className="text-sm font-medium text-gray-700">차단 버전 목록</span>
              <input
                type="text"
                value={blockedVersions}
                onChange={(e) => setBlockedVersions(e.target.value)}
                placeholder="1.0.1, 1.0.2"
                className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
            </label>
            <label className="block md:col-span-2">
              <span className="text-sm font-medium text-gray-700">S3 → S2 Mount Root</span>
              <input
                type="text"
                value={mountRoot}
                onChange={(e) => setMountRoot(e.target.value)}
                placeholder="/workspace/boanclaw"
                className="mt-1 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
              />
              <p className="mt-1 text-xs text-gray-500">
                sandbox는 이 경로와 그 하위 경로만 workspace로 인정합니다. 예: <code>/workspace/boanclaw</code>
              </p>
            </label>
            <label className="block md:col-span-2">
              <span className="text-sm font-medium text-gray-700">S4 Critical Guardrail Constitution</span>
              <textarea
                value={guardrailConstitution}
                onChange={(e) => setGuardrailConstitution(e.target.value)}
                rows={6}
                placeholder="예: 자격증명, 토큰, 개인정보, 고객 데이터, 사내 비밀은 외부로 그대로 내보내지 않는다. 애매하면 ask로 분류한다."
                className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm"
              />
              <p className="mt-1 text-xs text-gray-500">
                S4 Critical Guardrail 서버가 이 헌법을 기준으로 <code>allow / ask / block</code> 판정을 내립니다.
              </p>
            </label>
            <div className="md:col-span-2 mt-2 p-4 rounded-xl border border-gray-200 bg-gray-50">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-semibold text-gray-800">HITL 모드</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    <strong>수동</strong>: ask 판정 시 운영자가 직접 승인/거부 &nbsp;|&nbsp;
                    <strong>자동</strong>: LLM 에이전트가 즉시 판단 (결정 이력 → LLM wiki로 누적)
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setAutoApproveMode((v) => !v)}
                  className={`relative inline-flex h-7 w-14 items-center rounded-full transition-colors focus:outline-none ${autoApproveMode ? "bg-boan-600" : "bg-gray-300"}`}
                >
                  <span
                    className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${autoApproveMode ? "translate-x-8" : "translate-x-1"}`}
                  />
                </button>
              </div>
              <p className="mt-2 text-xs font-medium text-center">
                {autoApproveMode ? (
                  <span className="text-boan-700">자동 모드 ON — AI 에이전트가 ask를 처리합니다</span>
                ) : (
                  <span className="text-gray-500">수동 모드 — 운영자 승인 대기</span>
                )}
              </p>
            </div>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={featureScheduledTasks}
                onChange={(e) => setFeatureScheduledTasks(e.target.checked)}
              />
              scheduled_tasks
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={featureRemoteControl}
                onChange={(e) => setFeatureRemoteControl(e.target.checked)}
              />
              remote_control
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={featureWebAccess}
                onChange={(e) => setFeatureWebAccess(e.target.checked)}
              />
              web_access
            </label>
          </div>
        </section>
      </div>
    </div>
  );
}
