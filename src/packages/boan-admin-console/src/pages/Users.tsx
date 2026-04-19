import { useEffect, useState } from "react";
import { orgSettingsApi, workstationApi } from "../api";

// GoldenImagePanel — owner 전용. 현재 등록된 골든 이미지 URI 표시 + "내 VM 을
// 골든 이미지로 굽기" 버튼. 버튼 누르면 /api/admin/workstation/image 호출 →
// 백엔드가 VM 정지 → Custom Image 생성 → VM 재시작 (약 10-20분 소요).
// 이후 신규 사용자 VM 은 이 이미지로 프로비저닝되어 관리자가 설치해둔
// 파일 / 폴더 / endpoint agent 가 그대로 들어있음.
function GoldenImagePanel() {
  const [uri, setUri] = useState<string>("");
  const [capturedAt, setCapturedAt] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>("");

  const refresh = () => {
    orgSettingsApi.get()
      .then((rec) => {
        const s = (rec?.settings ?? {}) as Record<string, unknown>;
        setUri(typeof s.golden_image_uri === "string" ? s.golden_image_uri : "");
        setCapturedAt(typeof s.golden_image_captured_at === "string" ? s.golden_image_captured_at : "");
        setSource(typeof s.golden_image_source_instance === "string" ? s.golden_image_source_instance : "");
      })
      .catch(() => undefined);
  };
  useEffect(() => { refresh(); const t = setInterval(refresh, 15_000); return () => clearInterval(t); }, []);

  const capture = async () => {
    if (!confirm("현재 본인(소유자) VM 을 Custom Image 로 스냅샷합니다.\nVM 이 10-20분간 재부팅되며 그 동안 Personal Computer 를 쓸 수 없습니다. 계속할까요?")) return;
    setBusy(true); setMsg("");
    try {
      const r = await workstationApi.captureGoldenImage();
      setMsg(`✓ 시작됨 (job=${r.job_id}) — ${r.hint}`);
      // 15초 뒤 자동 refresh
      setTimeout(refresh, 15_000);
    } catch (e) {
      setMsg(`✗ 실패: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mb-6 rounded-xl border border-indigo-200 bg-indigo-50 p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <h2 className="text-sm font-semibold text-indigo-900">🧊 골든 이미지 (신규 사용자 VM 템플릿)</h2>
          {uri ? (
            <div className="mt-2 text-xs text-indigo-800 space-y-0.5">
              <div><span className="text-indigo-500">이미지:</span> <code className="bg-white px-1 rounded">{uri}</code></div>
              {capturedAt && <div><span className="text-indigo-500">생성:</span> {new Date(capturedAt).toLocaleString("ko-KR")}</div>}
              {source && <div><span className="text-indigo-500">원본:</span> <code className="bg-white px-1 rounded">{source}</code></div>}
              <div className="mt-1 text-[11px] text-indigo-600">신규 사용자 VM 은 이 이미지로 프로비저닝됩니다.</div>
            </div>
          ) : (
            <p className="mt-2 text-xs text-indigo-700">
              아직 등록된 골든 이미지가 없습니다. 본인 VM 에 기본 파일 / 폴더 / endpoint agent 를 세팅한 뒤 "굽기" 버튼을 누르면 그 상태로 스냅샷됩니다.
            </p>
          )}
        </div>
        <button
          onClick={capture}
          disabled={busy}
          className="shrink-0 px-3 py-2 rounded-lg bg-indigo-600 text-white text-xs font-medium hover:bg-indigo-700 disabled:opacity-50"
          title="내 VM 을 GCP Custom Image 로 스냅샷 (약 10-20분)"
        >
          {busy ? "요청 중..." : uri ? "🔁 다시 굽기" : "🧊 내 VM 굽기"}
        </button>
      </div>
      {msg && <div className="mt-2 text-xs text-indigo-900 bg-white border border-indigo-200 rounded px-2 py-1">{msg}</div>}
    </div>
  );
}

interface UserRow {
  email: string;
  role: string;
  org_id: string;
  status: string;
  access_level: string;
  created_at: string;
  registered_ip?: string;
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
      <GoldenImagePanel />
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
                <th className="text-left px-4 py-3 text-xs font-semibold text-gray-500">바인딩 PC</th>
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
                        className="text-xs bg-emerald-600 text-white px-3 py-1.5 rounded-full hover:bg-emerald-700 font-medium"
                        title="수락하면 즉시 GCP 워크스테이션이 생성됩니다"
                      >
                        ✓ 수락
                      </button>
                    ) : (
                      <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded-full">
                        활성
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-500" title={u.registered_ip ?? ""}>
                    {u.registered_ip
                      ? u.registered_ip.length > 16
                        ? `${u.registered_ip.slice(0, 8)}…${u.registered_ip.slice(-4)}`
                        : u.registered_ip
                      : <span className="text-gray-300">-</span>}
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
