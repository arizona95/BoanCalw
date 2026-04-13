import { useEffect, useState } from "react";

interface OrgEntry {
  org_id: string;
  url: string;
  token: string;
  label?: string;
}

interface OrgsResp {
  active: string;
  orgs: OrgEntry[];
}

// OrgRegistry — 소유자만 볼 수 있는 "연결된 조직" 관리 화면.
// 여러 조직서버 (GCP Cloud Run 인스턴스) 의 URL + Bearer 토큰을 저장.
// 로그인 화면의 조직 드롭다운이 이 목록을 읽어서 표시.
export default function OrgRegistry() {
  const [data, setData] = useState<OrgsResp>({ active: "", orgs: [] });
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const [form, setForm] = useState<OrgEntry>({ org_id: "", url: "", token: "", label: "" });
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
    const res = await fetch("/api/admin/orgs", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      setErr(d.error ?? "등록 실패");
      return;
    }
    setMsg(`${form.org_id} 추가됨`);
    setForm({ org_id: "", url: "", token: "", label: "" });
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

  const setActive = async (orgID: string) => {
    const res = await fetch("/api/admin/orgs", {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ org_id: orgID, active: true }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      setErr(d.error ?? "기본 조직 설정 실패");
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
            <label className="text-xs font-medium text-gray-600">조직 ID</label>
            <input
              type="text"
              placeholder="sds2-corp"
              value={form.org_id}
              onChange={(e) => setForm({ ...form, org_id: e.target.value })}
              required
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600">조직서버 URL</label>
            <input
              type="url"
              placeholder="https://boan-policy-server-sds2-corp-*.run.app"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              required
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600">Bearer 토큰</label>
            <input
              type="text"
              placeholder="64자 hex"
              value={form.token}
              onChange={(e) => setForm({ ...form, token: e.target.value })}
              required
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm font-mono"
            />
            <p className="text-[11px] text-gray-400 mt-1">
              조직 소유자가 deploy 시 생성한 토큰. 없으면 조직 소유자에게 요청하세요.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600">표시명 (선택)</label>
            <input
              type="text"
              placeholder="삼성 SDS Corp"
              value={form.label ?? ""}
              onChange={(e) => setForm({ ...form, label: e.target.value })}
              className="w-full mt-1 px-3 py-2 border border-gray-200 rounded-lg text-sm"
            />
          </div>
          <button
            type="submit"
            className="w-full py-2 bg-boan-600 text-white rounded-lg text-sm font-medium hover:bg-boan-700"
          >
            조직서버 연결 테스트 + 저장
          </button>
          <p className="text-[11px] text-gray-400 text-center">
            저장 버튼을 누르면 URL + 토큰으로 실제 조직서버에 접속해 검증합니다. 실패 시 저장되지 않습니다.
          </p>
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
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">토큰</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">기본</th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-gray-500">관리</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.orgs.map((o) => (
                <tr key={o.org_id}>
                  <td className="px-4 py-3 font-mono text-xs text-gray-700">{o.org_id}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{o.label || "-"}</td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-500 truncate max-w-xs">{o.url}</td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-400">{o.token.slice(0, 8)}…{o.token.slice(-4)}</td>
                  <td className="px-4 py-3">
                    {data.active === o.org_id ? (
                      <span className="text-xs bg-boan-100 text-boan-700 px-2 py-1 rounded-full font-medium">기본</span>
                    ) : (
                      <button
                        onClick={() => setActive(o.org_id)}
                        className="text-xs text-gray-500 hover:text-boan-600"
                      >
                        기본 설정
                      </button>
                    )}
                  </td>
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
        * URL 을 바꿔도 해당 조직의 토큰이 없으면 접근할 수 없습니다 (401).
        <br />* 기본 조직은 로그인 화면 드롭다운의 기본 선택값으로 쓰입니다.
      </p>
    </div>
  );
}
