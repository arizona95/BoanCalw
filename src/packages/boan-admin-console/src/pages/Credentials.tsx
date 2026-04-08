import { useEffect, useState } from "react";
import {
  credentialApi,
  type Credential,
  type CredentialPassthrough,
} from "../api";

const STATUS_STYLE: Record<string, string> = {
  ok: "bg-green-50 text-green-700",
  expired: "bg-red-50 text-red-700",
  missing: "bg-yellow-50 text-yellow-700",
};

type TabKey = "org" | "personal" | "passthrough";

function maskKey(k: string) {
  if (!k) return "";
  if (k.length <= 8) return "****";
  return k.slice(0, 6) + "..." + k.slice(-4);
}

export default function Credentials() {
  const [tab, setTab] = useState<TabKey>("org");
  const [creds, setCreds] = useState<Credential[]>([]);
  const [passthrough, setPassthrough] = useState<CredentialPassthrough[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [passthroughName, setPassthroughName] = useState("");
  const [passthroughValue, setPassthroughValue] = useState("");
  const [adding, setAdding] = useState(false);
  const [addingPassthrough, setAddingPassthrough] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    Promise.all([credentialApi.list(), credentialApi.listPassthrough()])
      .then(([credentialItems, passthroughItems]) => {
        setCreds(credentialItems);
        setPassthrough(passthroughItems);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleAdd = async () => {
    if (!name.trim()) {
      setError("Credential 이름을 입력하세요.");
      return;
    }
    if (!key.trim()) {
      setError("API 키를 입력하세요.");
      return;
    }
    setError(null);
    setSuccess(null);
    setAdding(true);
    try {
      await credentialApi.add(name.trim(), key.trim());
      setName("");
      setKey("");
      setSuccess(`"${name}" 이(가) credential-filter에 암호화 저장되었습니다.`);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "추가 실패");
    } finally {
      setAdding(false);
    }
  };

  const handleAddPassthrough = async () => {
    if (!passthroughName.trim()) {
      setError("예외 키 이름을 입력하세요.");
      return;
    }
    if (!passthroughValue.trim()) {
      setError("안 바꾸는 값을 입력하세요.");
      return;
    }
    setError(null);
    setSuccess(null);
    setAddingPassthrough(true);
    try {
      await credentialApi.addPassthrough(
        passthroughName.trim(),
        passthroughValue.trim()
      );
      setPassthroughName("");
      setPassthroughValue("");
      setSuccess(
        `"${passthroughName}" 이(가) HITL/마스킹 예외 값으로 등록되었습니다.`
      );
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "예외 키 추가 실패");
    } finally {
      setAddingPassthrough(false);
    }
  };

  const handleRevoke = async (role: string) => {
    setError(null);
    try {
      await credentialApi.revoke(role);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "삭제 실패");
    }
  };

  const handleRemovePassthrough = async (nameToRemove: string) => {
    setError(null);
    try {
      await credentialApi.removePassthrough(nameToRemove);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "예외 키 삭제 실패");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Credentials</h1>
      <p className="text-sm text-gray-500 mb-6">
        API 키는{" "}
        <span className="font-medium text-boan-700">
          boan-credential-filter
        </span>
        에 AES 암호화 저장됩니다. LLM 등록 시 curl에서 키가 감지되면 자동으로
        여기에 저장됩니다.
      </p>

      {error && (
        <div className="mb-4 rounded-lg bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-lg bg-green-50 p-3 text-sm text-green-700">
          {success}
        </div>
      )}

      <div className="flex border-b border-gray-200 mb-4">
        {([["org", "Organization"], ["personal", "Personal"], ["passthrough", "Passthrough"]] as const).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)} className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === k ? "border-boan-600 text-boan-700" : "border-transparent text-gray-500 hover:text-gray-700"}`}>{label}</button>
        ))}
      </div>

      {tab === "org" ? (
        <>
          <div className="mb-6 rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
            <h2 className="mb-1 text-lg font-semibold">Credential 추가</h2>
            <p className="mb-4 text-xs text-gray-500">
              Role 이름은 LLM 등록 시{" "}
              <code className="rounded bg-gray-100 px-1">{"{{CREDENTIAL:이름}}"}</code>
              에서 참조합니다.
            </p>
            <div className="flex flex-col gap-3">
              <input
                type="text"
                placeholder="Role 이름 (예: claude-3-5-sonnet-apikey)"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
              />
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <input
                    type={showKey ? "text" : "password"}
                    placeholder="API 키 (예: sk-ant-api03-...)"
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 pr-16 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-boan-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-gray-600"
                  >
                    {showKey ? "숨기기" : "표시"}
                  </button>
                </div>
                <button
                  onClick={handleAdd}
                  disabled={adding}
                  className="rounded-lg bg-boan-600 px-4 py-2 text-sm text-white hover:bg-boan-700 disabled:opacity-50"
                >
                  {adding ? "저장 중..." : "🔐 저장"}
                </button>
              </div>
              {key && (
                <p className="font-mono text-xs text-gray-400">
                  미리보기: {maskKey(key)}
                </p>
              )}
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 px-6 py-3">
              <h3 className="text-sm font-semibold text-gray-700">
                저장된 Credentials
              </h3>
              <button
                onClick={load}
                className="text-xs text-boan-600 hover:underline"
              >
                새로고침
              </button>
            </div>
            {loading ? (
              <p className="p-6 text-sm text-gray-500">로딩 중...</p>
            ) : creds.length === 0 ? (
              <p className="p-6 text-sm text-gray-400">
                등록된 Credential이 없습니다.
              </p>
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-gray-200 bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      Role (참조 이름)
                    </th>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      Org
                    </th>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      상태
                    </th>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      만료
                    </th>
                    <th className="px-6 py-3 text-right font-medium text-gray-500">
                      액션
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {creds.map((c) => (
                    <tr key={c.role} className="hover:bg-gray-50">
                      <td className="px-6 py-3 font-mono font-medium">
                        {c.role}
                      </td>
                      <td className="px-6 py-3 text-gray-500">{c.org_id}</td>
                      <td className="px-6 py-3">
                        <span
                          className={`rounded-full px-2 py-1 text-xs ${
                            STATUS_STYLE[c.status] ?? STATUS_STYLE.ok
                          }`}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-xs text-gray-500">
                        {c.expires_at
                          ? new Date(c.expires_at).toLocaleString("ko-KR")
                          : "—"}
                      </td>
                      <td className="px-6 py-3 text-right">
                        <button
                          onClick={() => handleRevoke(c.role)}
                          className="text-xs text-red-600 hover:underline"
                        >
                          revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      ) : tab === "personal" ? (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-1">Personal Credentials</h2>
          <p className="text-xs text-gray-500 mb-4">각 사용자가 개인적으로 등록한 API 키. 소유자는 여기서 전체 조회 가능.</p>
          {loading ? (
            <p className="text-sm text-gray-500">로딩 중...</p>
          ) : creds.filter((c) => c.role.includes("personal")).length === 0 ? (
            <p className="text-sm text-gray-400 py-8 text-center">개인 credential이 없습니다.</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-gray-200 bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left font-medium text-gray-500">Role</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500">Org</th>
                  <th className="px-4 py-3 text-left font-medium text-gray-500">상태</th>
                  <th className="px-4 py-3 text-right font-medium text-gray-500">액션</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {creds.filter((c) => c.role.includes("personal")).map((c) => (
                  <tr key={c.role} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-mono text-xs">{c.role}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">{c.org_id || "-"}</td>
                    <td className="px-4 py-3"><span className={`rounded-full px-2 py-1 text-xs ${STATUS_STYLE[c.status] ?? STATUS_STYLE.ok}`}>{c.status}</span></td>
                    <td className="px-4 py-3 text-right"><button onClick={() => handleRevoke(c.role)} className="text-xs text-red-600 hover:underline">revoke</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ) : (
        <>
          <div className="mb-6 rounded-xl border border-amber-200 bg-white p-6 shadow-sm">
            <h2 className="mb-1 text-lg font-semibold">안 바꾸는 키 등록</h2>
            <p className="mb-4 text-xs text-gray-500">
              여기 등록한 값은 Credential HITL이나 `[REDACTED]`로 바꾸지 않습니다.
              테스트 키, 가짜 키, 샘플 키 같은 값만 넣는 용도입니다.
            </p>
            <div className="flex flex-col gap-3">
              <input
                type="text"
                placeholder="이름 (예: anthropic-fake-key)"
                value={passthroughName}
                onChange={(e) => setPassthroughName(e.target.value)}
                className="rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-amber-400"
              />
              <div className="flex gap-3">
                <input
                  type="text"
                  placeholder="안 바꾸는 값 (예: sk-ant-api03-fakekey...)"
                  value={passthroughValue}
                  onChange={(e) => setPassthroughValue(e.target.value)}
                  className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-amber-400"
                />
                <button
                  onClick={handleAddPassthrough}
                  disabled={addingPassthrough}
                  className="rounded-lg bg-amber-500 px-4 py-2 text-sm text-white hover:bg-amber-600 disabled:opacity-50"
                >
                  {addingPassthrough ? "저장 중..." : "등록"}
                </button>
              </div>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-gray-200 bg-gray-50 px-6 py-3">
              <h3 className="text-sm font-semibold text-gray-700">안 바꾸는 키 목록</h3>
              <button
                onClick={load}
                className="text-xs text-boan-600 hover:underline"
              >
                새로고침
              </button>
            </div>
            {loading ? (
              <p className="p-6 text-sm text-gray-500">로딩 중...</p>
            ) : passthrough.length === 0 ? (
              <p className="p-6 text-sm text-gray-400">
                등록된 예외 키가 없습니다.
              </p>
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-gray-200 bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      이름
                    </th>
                    <th className="px-6 py-3 text-left font-medium text-gray-500">
                      값
                    </th>
                    <th className="px-6 py-3 text-right font-medium text-gray-500">
                      액션
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {passthrough.map((item) => (
                    <tr key={item.name} className="hover:bg-gray-50">
                      <td className="px-6 py-3 font-mono font-medium">
                        {item.name}
                      </td>
                      <td className="px-6 py-3 font-mono text-xs text-gray-500">
                        {item.value}
                      </td>
                      <td className="px-6 py-3 text-right">
                        <button
                          onClick={() => handleRemovePassthrough(item.name)}
                          className="text-xs text-red-600 hover:underline"
                        >
                          revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
