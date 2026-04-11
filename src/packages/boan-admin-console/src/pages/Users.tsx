import { useEffect, useState } from "react";

interface UserRow {
  email: string;
  role: string;
  org_id: string;
  status: string;
  access_level: string;
  created_at: string;
}

const ROLE_BADGE: Record<string, string> = {
  owner: "bg-blue-100 text-blue-700",
  user: "bg-gray-100 text-gray-600",
};

const ACCESS_LEVEL_STYLE: Record<string, { label: string; bg: string }> = {
  allow: { label: "Allow", bg: "bg-green-100 text-green-700 border-green-300" },
  ask:   { label: "Ask",   bg: "bg-yellow-100 text-yellow-700 border-yellow-300" },
  deny:  { label: "Deny",  bg: "bg-red-100 text-red-700 border-red-300" },
};

export default function Users() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    fetch("/api/admin/users", { credentials: "include" })
      .then((r) => r.json())
      .then((data) => setUsers(Array.isArray(data) ? data : []))
      .catch(() => setUsers([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const patch = async (email: string, payload: object) => {
    setMsg(null);
    const res = await fetch("/api/admin/users", {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, ...payload }),
    });
    if (res.ok) { setMsg("저장됨"); load(); }
    else { const d = await res.json(); setMsg(d.error ?? "오류"); }
  };

  const remove = async (email: string) => {
    if (!confirm(`${email} 계정을 삭제하시겠습니까?`)) return;
    const res = await fetch("/api/admin/users", {
      method: "DELETE",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (res.ok) { setMsg("삭제됨"); load(); }
    else { const d = await res.json(); setMsg(d.error ?? "오류"); }
  };

  const pendingCount = users.filter((u) => u.status === "pending").length;

  return (
    <div className="p-6 max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold text-gray-800">
          사용자 관리
          {pendingCount > 0 && (
            <span className="ml-2 text-xs bg-yellow-100 text-yellow-700 px-2 py-0.5 rounded-full">
              승인 대기 {pendingCount}
            </span>
          )}
        </h1>
        {msg && <span className="text-xs text-green-600">{msg}</span>}
      </div>

      {loading ? (
        <div className="text-sm text-gray-400">로딩 중...</div>
      ) : users.length === 0 ? (
        <div className="text-sm text-gray-400 py-8 text-center">등록된 사용자가 없습니다.</div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">이메일</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">역할</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">권한</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">조직</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">상태</th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">가입일</th>
                <th className="text-right px-4 py-3 text-xs font-semibold text-gray-500">관리</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map((u) => (
                <tr key={u.email} className={u.status === "pending" ? "bg-yellow-50" : ""}>
                  <td className="px-4 py-3 font-mono text-xs text-gray-700">{u.email}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-1 rounded-full ${ROLE_BADGE[u.role] ?? "bg-gray-100 text-gray-600"}`}>
                      {u.role === "owner" ? "소유자" : "사용자"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                      <select
                        value={u.access_level || "ask"}
                        onChange={(e) => patch(u.email, { access_level: e.target.value })}
                        className={`text-xs font-medium px-2 py-1 rounded border cursor-pointer ${ACCESS_LEVEL_STYLE[u.access_level || "ask"]?.bg ?? "bg-gray-100"}`}
                      >
                        <option value="allow">Allow</option>
                        <option value="ask">Ask</option>
                        <option value="deny">Deny</option>
                      </select>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 font-mono">{u.org_id || "-"}</td>
                  <td className="px-4 py-3">
                    {u.status === "pending" ? (
                      <button
                        onClick={() => patch(u.email, { action: "approve" })}
                        className="text-xs bg-yellow-100 text-yellow-700 px-2 py-1 rounded-full hover:bg-yellow-200"
                      >
                        승인하기
                      </button>
                    ) : (
                      <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded-full">
                        활성
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">{u.created_at}</td>
                  <td className="px-4 py-3 text-right">
                    {u.role === "owner" ? (
                      <span className="text-xs text-gray-300">고정</span>
                    ) : (
                      <button
                        onClick={() => remove(u.email)}
                        className="text-xs text-red-400 hover:text-red-600"
                      >
                        삭제
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 space-y-1">
        <p className="text-xs text-gray-400">
          * 소유자는 모든 권한을 가지며 권한 설정 대상이 아닙니다.
        </p>
        <p className="text-xs text-gray-400">
          * <b>Allow</b>: 정보의 낮은 흐름 허용 (모니터링만) &nbsp;|&nbsp;
          <b>Ask</b>: 가드레일 적용 (사전차단 + 모니터링) &nbsp;|&nbsp;
          <b>Deny</b>: 낮은 흐름 차단 (같은/높은 레벨만)
        </p>
      </div>
    </div>
  );
}
