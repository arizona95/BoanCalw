import { useEffect, useState } from "react";

interface OrgEntry {
  org_id: string;
  url: string;
  label?: string;
}

interface OrgsResp {
  active: string;
  orgs: OrgEntry[];
}

// OrgRegistry — 이 호스트가 연결된 조직 목록.
// 로그인 화면 드롭다운에 표시되며, "조직 추가" 는 공개 가입 요청 flow 로 처리.
export default function OrgRegistry() {
  const [data, setData] = useState<OrgsResp>({ active: "", orgs: [] });
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const [form, setForm] = useState<{ url: string; email: string }>({ url: "", email: "" });
  const [showAdd, setShowAdd] = useState(false);

  const load = () => {
    setLoading(true);
    fetch("/api/admin/orgs", { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setData(d))
      .catch(() => setErr("조직 목록을 불러오지 못했습니다."))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const submitAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setMsg(null);
    const res = await fetch("/api/auth/join-org", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: form.url, email: form.email }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) {
      setErr(d.error ?? "사용 요청 실패");
      return;
    }
    setMsg(`${d.org_id ?? ""} 사용 요청 전송됨 — 조직 소유자 승인 대기`);
    setForm({ url: "", email: "" });
    setShowAdd(false);
    load();
  };

  const remove = async (orgID: string) => {
    if (!confirm(`${orgID} 조직 연결을 해제합니까?`)) return;
    const res = await fetch("/api/admin/orgs", {
      method: "DELETE",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ org_id: orgID }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      setErr(d.error ?? "삭제 실패");
      return;
    }
    load();
  };


  return (
    <div className="max-w-4xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-800">연결된 조직</h2>
          <p className="text-xs text-gray-500 mt-1">
            이 호스트가 로그인 가능한 조직서버 목록. 로그인 화면 드롭다운에 표시됩니다.
          </p>
        </div>
        <button
          onClick={() => setShowAdd(!showAdd)}
          className="text-sm bg-boan-600 text-white px-4 py-2 rounded-lg hover:bg-boan-700"
        >
          {showAdd ? "취소" : "+ 조직 추가"}
        </button>
      </div>

      {msg && <div className="mb-3 text-xs text-green-600 bg-green-50 border border-green-200 rounded-lg px-3 py-2">{msg}</div>}
      {err && <div className="mb-3 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{err}</div>}

      {showAdd && (
        <form onSubmit={submitAdd} className="mb-5 bg-white border border-gray-200 rounded-xl p-5 space-y-3">
          <div>
            <label className="text-xs font-medium text-gray-600">조직서버 URL</label>
            <input
              type="url"
              placeholder="https://boan-policy-server-{org}-*.run.app"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              required
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
            />
            <p className="text-[11px] text-gray-400 mt-1">
              조직 ID 는 URL 에서 자동 파싱됩니다. 조직 소유자에게 URL 을 받아 붙여넣으세요.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600">본인 이메일</label>
            <input
              type="email"
              placeholder="user@samsung.com"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              required
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
            <p className="text-[11px] text-gray-400 mt-1">
              해당 조직에 가입 요청할 이메일 (가입 승인 후 로그인 가능).
            </p>
          </div>
          <button
            type="submit"
            className="w-full py-2 bg-boan-600 text-white rounded-lg text-sm font-medium hover:bg-boan-700"
          >
            사용 요청 전송
          </button>
        </form>
      )}

      {loading ? (
        <div className="text-sm text-gray-400 py-8 text-center">로딩 중...</div>
      ) : data.orgs.length === 0 ? (
        <div className="text-sm text-gray-400 py-8 text-center">연결된 조직이 없습니다.</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">조직 ID</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">표시명</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">URL</th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-gray-500">관리</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.orgs.map((o) => (
                <tr key={o.org_id}>
                  <td className="px-4 py-3 font-mono text-xs text-gray-700">{o.org_id}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{o.label || "-"}</td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-500 truncate max-w-xs">{o.url}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => remove(o.org_id)}
                      className="text-xs text-red-400 hover:text-red-600"
                    >
                      삭제
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-4 text-xs text-gray-400">
        * 조직 가입은 "사용 요청" 으로 전송 → 조직 소유자 승인 후 로그인 가능합니다.
      </p>
    </div>
  );
}
