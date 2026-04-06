import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { approvalApi, openclawApi, type ApprovalRequest } from "../api";

function extractRoles(args: string[]) {
  return args
    .filter((arg) => arg.startsWith("role="))
    .map((arg) => arg.slice("role=".length))
    .filter(Boolean);
}

type MyBoanClawProps = {
  embedded?: boolean;
};

export default function MyBoanClaw({ embedded = false }: MyBoanClawProps) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [dismissedApprovalId, setDismissedApprovalId] = useState("");
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const navigate = useNavigate();

  const focusOpenClaw = () => {
    iframeRef.current?.focus();
  };

  const announceEmbeddedIntent = () => {
    if (!embedded) return;
    window.dispatchEvent(new CustomEvent("boan:allow-openclaw-focus"));
  };

  useEffect(() => {
    let active = true;
    openclawApi
      .dashboard()
      .then((data) => {
        if (!active) return;
        setUrl(data.url);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "OpenClaw 연결 실패");
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (embedded) return;
    if (!url) return;
    const timer = window.setTimeout(focusOpenClaw, 150);
    return () => window.clearTimeout(timer);
  }, [embedded, url]);

  useEffect(() => {
    let active = true;
    const load = () => {
      approvalApi
        .list()
        .then((items) => {
          if (!active) return;
          setApprovals(items);
        })
        .catch(() => {
          if (!active) return;
          setApprovals([]);
        });
    };
    load();
    const interval = window.setInterval(load, 3000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const pendingCredentialApproval = useMemo(() => {
    const pending = approvals
      .filter(
        (item) =>
          item.status === "pending" && item.command === "credential-gate:register"
      )
      .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
    return pending[0];
  }, [approvals]);

  useEffect(() => {
    if (!pendingCredentialApproval) return;
    if (pendingCredentialApproval.id !== dismissedApprovalId) {
      setDismissedApprovalId("");
    }
  }, [pendingCredentialApproval, dismissedApprovalId]);

  const showPopup =
    pendingCredentialApproval && pendingCredentialApproval.id !== dismissedApprovalId;
  const popupRoles = pendingCredentialApproval
    ? extractRoles(pendingCredentialApproval.args)
    : [];

  if (error) {
    return (
      <div className="h-full w-full bg-gradient-to-br from-boan-200 via-boan-100 to-white flex items-center justify-center text-sm text-boan-800">
        {error}
      </div>
    );
  }

  if (!url) {
    return (
      <div className="h-full w-full bg-gradient-to-br from-boan-200 via-boan-100 to-white flex items-center justify-center text-sm text-boan-800">
        OpenClaw 작업 화면을 준비하는 중입니다.
      </div>
    );
  }

  return (
    <div
      className="relative h-full w-full bg-gradient-to-br from-boan-200 via-boan-100 to-white"
      onPointerDown={embedded ? announceEmbeddedIntent : focusOpenClaw}
      onMouseEnter={embedded ? undefined : focusOpenClaw}
    >
      <iframe
        ref={iframeRef}
        title="OpenClaw"
        src={url}
        tabIndex={embedded ? -1 : 0}
        onLoad={embedded ? undefined : focusOpenClaw}
        className="h-full w-full border-0 bg-white"
      />
      {showPopup && pendingCredentialApproval && (
        <div className="absolute right-5 top-5 z-30 w-[360px] rounded-2xl border border-boan-300 bg-white/92 p-4 shadow-2xl backdrop-blur">
          <div className="mb-2 flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-boan-700">
                Credential HITL
              </p>
              <h2 className="mt-1 text-sm font-semibold text-gray-900">
                등록 대기 중인 credential이 있습니다
              </h2>
            </div>
            <button
              type="button"
              onClick={() => setDismissedApprovalId(pendingCredentialApproval.id)}
              className="rounded-md px-2 py-1 text-xs text-gray-400 hover:bg-gray-100 hover:text-gray-600"
            >
              닫기
            </button>
          </div>
          <p className="text-xs text-gray-600">
            OpenClaw 대화 중 감지된 미등록 credential입니다. 승인하면
            `Credentials`에 저장됩니다.
          </p>
          {popupRoles.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {popupRoles.map((role) => (
                <span
                  key={role}
                  className="rounded-full bg-boan-50 px-2.5 py-1 font-mono text-[11px] text-boan-800"
                >
                  {role}
                </span>
              ))}
            </div>
          )}
          <div className="mt-4 flex items-center justify-between">
            <span className="text-[11px] text-gray-400">
              요청 시각 {new Date(pendingCredentialApproval.requestedAt).toLocaleTimeString("ko-KR")}
            </span>
            <button
              type="button"
              onClick={() => navigate("/approvals")}
              className="rounded-lg bg-boan-600 px-3 py-2 text-xs font-medium text-white hover:bg-boan-700"
            >
              Approvals 열기
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
