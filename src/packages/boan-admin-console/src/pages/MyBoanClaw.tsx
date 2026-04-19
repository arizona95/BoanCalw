import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { approvalApi, openclawApi, type ApprovalRequest } from "../api";
import { useFocusTarget } from "../focusContext";

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
  const { focusTarget, focusTargetRef, setFocusTarget } = useFocusTarget();

  const focusOpenClaw = () => {
    iframeRef.current?.focus();
  };

  const claimEmbeddedFocus = () => {
    if (!embedded) return;
    // 사용모드에서 chat 을 클릭하면 focus 주인을 "boanclaw" 로 전환.
    setFocusTarget("boanclaw");
    const frame = iframeRef.current;
    if (!frame) return;
    frame.focus();
    // 리렌더 이후 MyGCP 의 잔여 blur 처리가 끝난 뒤 한 번 더 밀어준다.
    window.requestAnimationFrame(() => frame.focus());
  };

  // focusTarget === "boanclaw" 로 바뀌면 iframe 실제 포커스.
  useEffect(() => {
    if (!embedded) return;
    if (focusTarget !== "boanclaw") return;
    const frame = iframeRef.current;
    if (!frame) return;
    const id = window.requestAnimationFrame(() => frame.focus());
    return () => window.cancelAnimationFrame(id);
  }, [embedded, focusTarget]);

  // 같은 origin 인 OpenClaw iframe 이라도 내부에서 발생한 pointerdown / focusin
  // 이벤트는 부모 document 로 버블되지 않고, 내부 textarea 가 focus 되어도
  // 부모의 document.activeElement 가 반드시 iframe 요소가 되지도 않는다.
  // 그래서 "iframe 안 어디든 클릭되면 boanclaw 가 focus 주인" 신호를
  // 부모에 전달하려면, iframe.contentDocument 에 직접 리스너를 붙여야 한다.
  useEffect(() => {
    if (!embedded) return;
    const frame = iframeRef.current;
    if (!frame) return;
    const claim = () => setFocusTarget("boanclaw");
    let attachedDoc: Document | null = null;
    const attach = () => {
      const doc = frame.contentDocument;
      if (!doc || doc === attachedDoc) return false;
      attachedDoc = doc;
      doc.addEventListener("pointerdown", claim, true);
      doc.addEventListener("focusin", claim, true);
      return true;
    };
    const detach = () => {
      if (!attachedDoc) return;
      attachedDoc.removeEventListener("pointerdown", claim, true);
      attachedDoc.removeEventListener("focusin", claim, true);
      attachedDoc = null;
    };
    attach();
    const onLoad = () => {
      detach();
      attach();
    };
    frame.addEventListener("load", onLoad);
    // iframe src 가 fetch 기반으로 늦게 설정되는 구조라 load 이벤트가 이미
    // 지나간 경우가 있다. 안전하게 짧은 주기로 contentDocument 를 polling
    // 하면서 새 doc 가 보이면 재부착한다. 4초 후 중지.
    const pollTimer = window.setInterval(() => {
      attach();
    }, 200);
    window.setTimeout(() => window.clearInterval(pollTimer), 4000);
    // 부모 document 레벨에서도 iframe 요소 자체가 focus 되는 경우(외부 .focus()
    // 호출)를 캐치.
    const onParentFocusIn = () => {
      if (document.activeElement === frame) setFocusTarget("boanclaw");
    };
    document.addEventListener("focusin", onParentFocusIn, true);
    return () => {
      window.clearInterval(pollTimer);
      detach();
      frame.removeEventListener("load", onLoad);
      document.removeEventListener("focusin", onParentFocusIn, true);
    };
    // url 이 비어있는 동안에는 iframe 이 렌더되지 않아 ref 가 null.
    // url 이 채워지면 iframe 이 실제 마운트되므로 effect 를 재실행해서
    // contentDocument 에 listener 를 부착한다.
  }, [embedded, setFocusTarget, url]);
  // focusTargetRef 는 focusContext 내부에서 setFocusTarget 호출 시 동기
  // 업데이트되므로 여기서 별도 로직 없이 읽기만 해도 최신이다.
  void focusTargetRef;

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
      onPointerDown={embedded ? claimEmbeddedFocus : focusOpenClaw}
      onMouseEnter={embedded ? undefined : focusOpenClaw}
    >
      <iframe
        ref={iframeRef}
        title="OpenClaw"
        src={url}
        /* embedded 모드에서도 tabIndex=0 로 두어야 마우스 클릭이 iframe
           요소로 정상 포커스된다. -1 이면 일부 브라우저에서 click-focus 가
           전달되지 않아 textarea 가 눌리지 않는 증상이 난다. */
        tabIndex={0}
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
