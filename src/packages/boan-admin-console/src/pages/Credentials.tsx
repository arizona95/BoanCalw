import { useEffect, useState } from "react";
import { credentialApi, type Credential } from "../api";

const STATUS_STYLE: Record<string, string> = {
  ok: "bg-green-50 text-green-700",
  expired: "bg-red-50 text-red-700",
  missing: "bg-yellow-50 text-yellow-700",
};

function maskKey(k: string) {
  if (!k) return "";
  if (k.length <= 8) return "****";
  return k.slice(0, 6) + "..." + k.slice(-4);
}

export default function Credentials() {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    credentialApi
      .list()
      .then(setCreds)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async () => {
    if (!name.trim()) { setError("Credential 이름을 입력하세요."); return; }
    if (!key.trim()) { setError("API 키를 입력하세요."); return; }
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

  const handleRevoke = async (role: string) => {
    setError(null);
    try {
      await credentialApi.revoke(role);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "삭제 실패");
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Credentials</h1>
      <p className="text-sm text-gray-500 mb-6">
        API 키는 <span className="font-medium text-boan-700">boan-credential-filter</span>에 AES 암호화 저장됩니다.
        LLM 등록 시 curl에서 키가 감지되면 자동으로 여기에 저장됩니다.
      </p>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-50 text-red-700 text-sm">{error}</div>
      )}
      {success && (
        <div className="mb-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{success}</div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
        <h2 className="text-lg font-semibold mb-1">Credential 추가</h2>
        <p className="text-xs text-gray-500 mb-4">
          Role 이름은 LLM 등록 시 <code className="bg-gray-100 px-1 rounded">{"{{CREDENTIAL:이름}}"}</code>에서 참조합니다.
        </p>
        <div className="flex flex-col gap-3">
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="Role 이름 (예: claude-3-5-sonnet-apikey)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-boan-500"
            />
          </div>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <input
                type={showKey ? "text" : "password"}
                placeholder="API 키 (예: sk-ant-api03-...)"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full px-3 py-2 pr-16 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-boan-500"
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
              className="px-4 py-2 text-sm rounded-lg bg-boan-600 text-white hover:bg-boan-700 disabled:opacity-50"
            >
              {adding ? "저장 중..." : "🔐 저장"}
            </button>
          </div>
          {key && (
            <p className="text-xs text-gray-400 font-mono">
              미리보기: {maskKey(key)}
            </p>
          )}
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-gray-700">저장된 Credentials</h3>
          <button onClick={load} className="text-xs text-boan-600 hover:underline">새로고침</button>
        </div>
        {loading ? (
          <p className="p-6 text-gray-500 text-sm">로딩 중...</p>
        ) : creds.length === 0 ? (
          <p className="p-6 text-gray-400 text-sm">등록된 Credential이 없습니다.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Role (참조 이름)</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">Org</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">상태</th>
                <th className="text-left px-6 py-3 font-medium text-gray-500">만료</th>
                <th className="text-right px-6 py-3 font-medium text-gray-500">액션</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {creds.map((c) => (
                <tr key={c.role} className="hover:bg-gray-50">
                  <td className="px-6 py-3 font-mono font-medium">{c.role}</td>
                  <td className="px-6 py-3 text-gray-500">{c.org_id}</td>
                  <td className="px-6 py-3">
                    <span className={`text-xs px-2 py-1 rounded-full ${STATUS_STYLE[c.status] ?? STATUS_STYLE.ok}`}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-gray-500 text-xs">
                    {c.expires_at ? new Date(c.expires_at).toLocaleString("ko-KR") : "—"}
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
    </div>
  );
}
