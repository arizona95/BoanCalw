import { useEffect, useMemo, useRef, useState, type ChangeEvent, type ClipboardEvent, type FocusEvent, type KeyboardEvent } from "react";
import { useLocation } from "react-router-dom";

import {
  approvalApi,
  chatApi,
  inputGateApi,
  openclawApi,
  workstationApi,
  type PersonalWorkstation,
} from "../api";
import { useAuth } from "../auth";
import { useFocusTarget } from "../focusContext";

const IMMEDIATE_KEYS = new Set([
  "Tab",
  "Escape",
  "ArrowUp",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "Home",
  "End",
  "PageUp",
  "PageDown",
  "Insert",
  "F1",
  "F2",
  "F3",
  "F4",
  "F5",
  "F6",
  "F7",
  "F8",
  "F9",
  "F10",
  "F11",
  "F12",
]);

type MyGCPProps = {
  // 사용모드처럼 경로와 무관하게 항상 활성화해야 할 때 true.
  // 기본은 path === "/my-gcp" 일 때만 활성화.
  alwaysActive?: boolean;
};

export default function MyGCP({ alwaysActive = false }: MyGCPProps = {}) {
  const location = useLocation();
  const { user } = useAuth();
  const { focusTarget, focusTargetRef, setFocusTarget } = useFocusTarget();
  const isActive = alwaysActive || location.pathname === "/my-gcp";
  // 기본(non-usage) 모드에서는 focus 주인이 항상 "gcp".
  // 사용모드에서는 focusTargetRef 를 동기적으로 읽어 판단 — React 리렌더보다
  // 먼저 blur / RAF 가 실행되는 race 를 피하기 위함.
  const ownsFocusNow = () => (alwaysActive ? focusTargetRef.current === "gcp" : true);
  const ownsFocus = alwaysActive ? focusTarget === "gcp" : true;
  const [workstation, setWorkstation] = useState<PersonalWorkstation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [buffer, setBuffer] = useState("");
  const [gateBusy, setGateBusy] = useState(false);
  const [gateStatus, setGateStatus] = useState<string>("키보드는 보안 입력 바를 통해서만 전달됩니다.");
  const [capturedRemoteClipboard, setCapturedRemoteClipboard] = useState<string>("");
  const [openclawUrl, setOpenclawUrl] = useState<string>("");
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const openclawFrameRef = useRef<HTMLIFrameElement | null>(null);
  const gateInputRef = useRef<HTMLTextAreaElement | null>(null);
  const remoteClipboardCleanupRef = useRef<(() => void) | null>(null);
  const capturedRemoteClipboardRef = useRef("");
  const bridgeRetryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isSubmittingRef = useRef(false);
  const ignoreNextChangeRef = useRef(false);

  const remoteReady = Boolean(workstation?.web_desktop_url);
  const screenTitle = useMemo(() => stateTitle(workstation?.status ?? ""), [workstation?.status]);

  const focusGateInput = () => {
    // ref 로 실시간 체크 — closure 의 stale ownsFocus 가 아니라 RAF/timeout
    // 이 실제로 실행되는 시점의 focusTarget 을 본다.
    if (!ownsFocusNow()) return;
    gateInputRef.current?.focus({ preventScroll: true });
  };

  const focusGateInputDeferred = () => {
    if (!ownsFocusNow()) return;
    window.requestAnimationFrame(() => focusGateInput());
  };

  const getRemoteClipboardService = () => {
    const win = remoteWindow() as
      | (Window & {
          angular?: {
            element: (node: unknown) => { injector?: () => { get: (name: string) => unknown } };
          };
        })
      | null;
    if (!win?.angular) return null;

    try {
      const root = win.document.body ?? win.document.documentElement;
      const injector = win.angular.element(root).injector?.();
      if (!injector) return null;
      return injector.get("clipboardService") as
        | {
            getClipboard: () => PromiseLike<{ type?: string; data?: unknown }>;
          }
        | null;
    } catch {
      return null;
    }
  };

  const getManagedClient = () => {
    const win = remoteWindow() as
      | (Window & {
          angular?: {
            element: (node: unknown) => { injector?: () => { get: (name: string) => unknown } };
          };
        })
      | null;
    if (!win?.angular) return null;

    try {
      const root = win.document.body ?? win.document.documentElement;
      const injector = win.angular.element(root).injector?.();
      if (!injector) return null;
      const clientManager = injector.get("guacClientManager") as
        | {
            getManagedClients: () => Record<string, { client?: { sendKeyEvent: (pressed: number, keysym: number) => void } }>;
          }
        | null;
      if (!clientManager) return null;
      const managedClients = clientManager.getManagedClients?.() ?? {};
      const firstManagedClient = Object.values(managedClients)[0];
      return firstManagedClient?.client ?? null;
    } catch {
      return null;
    }
  };

  const writeLocalClipboard = async (text: string) => {
    if (!text) return false;
    console.log("[BoanClaw] writeLocalClipboard, length=", text.length);
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        console.log("[BoanClaw] navigator.clipboard.writeText SUCCESS");
        return true;
      }
    } catch (e) {
      console.warn("[BoanClaw] navigator.clipboard.writeText FAILED", e);
      // Fall through to legacy copy path.
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";
    document.body.appendChild(textarea);
    textarea.select();
    try {
      return document.execCommand("copy");
    } finally {
      document.body.removeChild(textarea);
    }
  };

  const handleCapturedRemoteClipboard = async (text: string) => {
    if (!text) return;
    capturedRemoteClipboardRef.current = text;
    setCapturedRemoteClipboard(text);
    void inputGateApi
      .evaluate({
        mode: "clipboard_sync",
        text,
        src_level: 1,
        dest_level: 3,
        flow: "remote-workstation-clipboard-to-local-clipboard",
      })
      .catch(() => undefined);
    const copied = await writeLocalClipboard(text);
    setGateStatus(
      copied
        ? "원격 클립보드를 로컬 클립보드로 동기화했습니다."
        : "원격 클립보드는 잡았지만 브라우저가 시스템 클립보드 자동 복사를 막았습니다.",
    );
  };

  const installRemoteClipboardBridge = () => {
    remoteClipboardCleanupRef.current?.();
    remoteClipboardCleanupRef.current = null;

    const win = remoteWindow() as
      | (Window & {
          angular?: {
            element: (node: unknown) => { injector?: () => { get: (name: string) => unknown } };
          };
        })
      | null;
    if (!win?.angular) return;

    try {
      const root = win.document.body ?? win.document.documentElement;
      const injector = win.angular.element(root).injector?.();
      if (!injector) return;
      const clipboardService = injector.get("clipboardService") as
        | {
            getClipboard?: () => Promise<{ type?: string; data?: unknown }>;
            resyncClipboard?: () => Promise<unknown> | unknown;
            setClipboard?: (data: { type?: string; data?: unknown }) => Promise<unknown> | unknown;
            __boanOriginalGetClipboard__?: () => Promise<{ type?: string; data?: unknown }>;
            __boanOriginalResyncClipboard__?: () => Promise<unknown> | unknown;
            __boanOriginalSetClipboard__?: (data: { type?: string; data?: unknown }) => Promise<unknown> | unknown;
          }
        | null;
      const rootScope = injector.get("$rootScope") as {
        $on: (
          name: string,
          listener: (_event: unknown, payload?: { type?: string; data?: unknown }) => void,
        ) => () => void;
      };

      if (clipboardService?.setClipboard && !clipboardService.__boanOriginalSetClipboard__) {
        clipboardService.__boanOriginalSetClipboard__ = clipboardService.setClipboard.bind(clipboardService);
        clipboardService.setClipboard = (data) => {
          const result = clipboardService.__boanOriginalSetClipboard__?.(data);
          return Promise.resolve(result).finally(() => {
            if (data?.type !== "text/plain" || typeof data.data !== "string" || !data.data) return;
            const text = data.data;
            // Schedule in parent-frame task queue so navigator.clipboard runs with
            // parent-frame user activation (not inside the iframe's Angular digest).
            window.setTimeout(() => void handleCapturedRemoteClipboard(text), 0);
          });
        };
      }

      if (clipboardService?.getClipboard && !clipboardService.__boanOriginalGetClipboard__) {
        clipboardService.__boanOriginalGetClipboard__ = clipboardService.getClipboard.bind(clipboardService);
        clipboardService.getClipboard = () => {
          const text = capturedRemoteClipboardRef.current;
          if (text) {
            return Promise.resolve({ type: "text/plain", data: text });
          }
          return clipboardService.__boanOriginalGetClipboard__!();
        };
      }

      if (clipboardService?.resyncClipboard && !clipboardService.__boanOriginalResyncClipboard__) {
        clipboardService.__boanOriginalResyncClipboard__ = clipboardService.resyncClipboard.bind(clipboardService);
        clipboardService.resyncClipboard = () => Promise.resolve();
        try {
          win.removeEventListener("copy", clipboardService.__boanOriginalResyncClipboard__ as EventListener);
          win.removeEventListener("cut", clipboardService.__boanOriginalResyncClipboard__ as EventListener);
          win.removeEventListener("load", clipboardService.__boanOriginalResyncClipboard__ as EventListener, true);
        } catch {
          // Ignore listener removal failures within the embedded Guacamole runtime.
        }
      }

      console.log("[BoanClaw] bridge installed, subscribing to guacClipboard");
      const unsubscribe = rootScope.$on("guacClipboard", (_event, payload) => {
        console.log("[BoanClaw] guacClipboard event fired", payload);
        if (payload?.type !== "text/plain" || typeof payload.data !== "string" || !payload.data) return;
        const text = payload.data;
        // Same as setClipboard path: run in parent-frame task queue.
        window.setTimeout(() => void handleCapturedRemoteClipboard(text), 0);
      });

      remoteClipboardCleanupRef.current = () => {
        if (clipboardService?.__boanOriginalSetClipboard__) {
          clipboardService.setClipboard = clipboardService.__boanOriginalSetClipboard__;
          delete clipboardService.__boanOriginalSetClipboard__;
        }
        if (clipboardService?.__boanOriginalGetClipboard__) {
          clipboardService.getClipboard = clipboardService.__boanOriginalGetClipboard__;
          delete clipboardService.__boanOriginalGetClipboard__;
        }
        if (clipboardService?.__boanOriginalResyncClipboard__) {
          clipboardService.resyncClipboard = clipboardService.__boanOriginalResyncClipboard__;
          delete clipboardService.__boanOriginalResyncClipboard__;
        }
        unsubscribe();
      };
    } catch {
      remoteClipboardCleanupRef.current = null;
    }
  };

  const syncRemoteClipboardToLocal = async () => {
    const service = getRemoteClipboardService();
    if (!service) return;

    try {
      const data = await service.getClipboard();
      if (data?.type !== "text/plain" || typeof data.data !== "string" || !data.data) return;
      await handleCapturedRemoteClipboard(data.data);
    } catch {
      // Ignore best-effort clipboard sync failures.
    } finally {
      focusGateInput();
    }
  };

  const tryInstallBridgeWithRetry = (attemptsLeft = 25) => {
    if (bridgeRetryTimerRef.current !== null) {
      clearTimeout(bridgeRetryTimerRef.current);
      bridgeRetryTimerRef.current = null;
    }
    const win = remoteWindow() as (Window & { angular?: unknown }) | null;
    console.log("[BoanClaw] tryInstallBridge attempt, attemptsLeft=", attemptsLeft, "angular=", !!win?.angular);
    if (win?.angular) {
      installRemoteClipboardBridge();
      return;
    }
    if (attemptsLeft > 0) {
      bridgeRetryTimerRef.current = setTimeout(() => tryInstallBridgeWithRetry(attemptsLeft - 1), 250);
    }
  };

  useEffect(() => {
    if (!isActive || !user) return;
    if (!workstation) {
      setLoading(true);
    }
    workstationApi
      .me()
      .then((data) => {
        setWorkstation(data);
        setError(null);
      })
      .catch((e) => {
        setError(e instanceof Error ? e.message : "작업 컴퓨터 정보를 불러오지 못했습니다.");
        setWorkstation(null);
      })
      .finally(() => setLoading(false));
  }, [isActive, user]);

  // OpenClaw URL 로드 (숨겨진 iframe용 — AI 백그라운드 실행)
  useEffect(() => {
    if (!isActive) return;
    openclawApi.dashboard().then((d) => setOpenclawUrl(d.url)).catch(() => undefined);
  }, [isActive]);

  useEffect(() => {
    if (!isActive || !remoteReady) return;
    const frame = window.requestAnimationFrame(() => focusGateInput());
    return () => window.cancelAnimationFrame(frame);
  }, [isActive, remoteReady]);

  useEffect(() => {
    if (!isActive || !remoteReady) return;
    if (!ownsFocus) return;

    // focusTarget === "gcp" 일 때만 창 복귀 시 gate input 복구.
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") focusGateInputDeferred();
    };
    const handleWindowFocus = () => focusGateInputDeferred();

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleWindowFocus);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("focus", handleWindowFocus);
    };
  }, [isActive, remoteReady, ownsFocus]);

  // focusTarget 이 "gcp" 로 돌아오면 즉시 gate input 복구.
  useEffect(() => {
    if (ownsFocus && isActive && remoteReady) focusGateInputDeferred();
  }, [ownsFocus, isActive, remoteReady]);

  useEffect(() => {
    return () => {
      if (bridgeRetryTimerRef.current !== null) {
        clearTimeout(bridgeRetryTimerRef.current);
        bridgeRetryTimerRef.current = null;
      }
      remoteClipboardCleanupRef.current?.();
      remoteClipboardCleanupRef.current = null;
    };
  }, []);

  const evaluateClipboardInput = async (text: string) => {
    if (!text.trim()) {
      setGateStatus("클립보드가 비어 있어 전달할 내용이 없습니다.");
      return;
    }

    setGateBusy(true);
    let pollOwned = false;
    try {
      const result = await inputGateApi.evaluate({
        mode: "paste",
        text,
        src_level: 3,
        dest_level: 1,
        flow: "local-clipboard-to-remote-workstation",
      });

      if (result.action === "hitl_required" && result.approval_id) {
        pollOwned = true; // poll() will call setGateBusy(false)
        const approvalId = result.approval_id;
        setGateStatus(`관리자 승인 대기 중... (${result.reason ?? "human review required"})`);

        const deadline = Date.now() + 5 * 60 * 1000;
        const poll = async (): Promise<void> => {
          if (Date.now() > deadline) {
            setGateStatus("승인 대기 시간이 초과되었습니다.");
            setGateBusy(false);
            return;
          }
          try {
            const approval = await approvalApi.get(approvalId);
            if (approval.status === "approved") {
              injectTextToRemote(text);
              setGateStatus("관리자 승인 완료. 원격 화면에 전달되었습니다.");
              focusGateInputDeferred();
              setGateBusy(false);
            } else if (approval.status === "rejected") {
              setGateStatus("관리자가 입력을 거부했습니다.");
              setGateBusy(false);
            } else {
              window.setTimeout(() => void poll(), 2000);
            }
          } catch {
            window.setTimeout(() => void poll(), 2000);
          }
        };
        void poll();
        return;
      }

      if (!result.allowed) {
        setGateStatus(result.reason ?? "클립보드 내용이 차단되었습니다.");
        return;
      }

      const payload = result.normalized_text || text;
      injectTextToRemote(payload);
      const credSubstituted = result.reason?.includes("credential");
      setGateStatus(
        credSubstituted
          ? "크리덴셜이 {{CREDENTIAL:name}} 으로 치환되어 전달되었습니다."
          : "클립보드 내용이 검사를 통과했고 원격 화면에 바로 전달되었습니다."
      );
      focusGateInputDeferred();
    } catch (e) {
      setGateStatus(e instanceof Error ? e.message : "클립보드 검사에 실패했습니다.");
    } finally {
      if (!pollOwned) setGateBusy(false);
    }
  };

  const submitBufferedInput = async () => {
    const text = buffer;
    if (!text.trim()) {
      setGateStatus("보낼 입력이 없습니다.");
      return;
    }

    setGateBusy(true);
    try {
      const result = await inputGateApi.evaluate({
        mode: "text",
        text,
        src_level: 3,
        dest_level: 1,
        flow: "local-input-buffer-to-remote-workstation",
      });
      const botMsg = result.allowed
        ? `[gcp_send] ${text} : 입력이 검사를 통과했고 원격 화면에 전달되었습니다.`
        : `[gcp_send] ${text} : 가드레일에 통과되지 못하였습니다 — ${result.reason ?? "차단됨"}`;

      chatApi.inject("assistant", botMsg).catch(() => {});

      if (!result.allowed) {
        setGateStatus(result.reason ?? "입력이 차단되었습니다.");
        return;
      }
      injectTextToRemote(result.normalized_text || text);
      // 버퍼 전송 끝에 Enter 자동 부여 — 여러 줄 입력 (Alt+Enter 로 \n 끼운 경우)
      // 이든 한 줄이든 동일하게, 원격 쪽에서 "input submit" 이 되도록.
      // injectTextToRemote 자체는 Enter 를 자동 안 붙임 (clipboard paste 등 다른
      // 호출자는 Enter 없이 단순 type 만 해야 함).
      injectImmediateKeyToRemote("Enter");
      setBuffer("");
      setGateStatus("입력이 검사를 통과했고 원격 화면에 전달되었습니다.");
      focusGateInputDeferred();
    } catch (e) {
      setGateStatus(e instanceof Error ? e.message : "입력 게이트 검사에 실패했습니다.");
    } finally {
      setGateBusy(false);
    }
  };

  // ── 스크린샷: 현재 세션 iframe canvas 캡처 ───────────────────────────────
  // 실패 시 풍부한 진단정보를 반환 (서버 로그로 전송돼서 디버깅 가능).
  // 성공: { image, width, height }
  // 실패: { error, debug: { ... } }
  type CaptureResult =
    | { image: string; width: number; height: number; debug?: Record<string, unknown> }
    | { error: string; debug: Record<string, unknown> };

  const captureCanvas = (): CaptureResult => {
    const ts = new Date().toISOString();
    const iframeExists = !!iframeRef.current;
    const ifSrc = iframeRef.current?.src ?? null;
    const win = iframeRef.current?.contentWindow ?? null;
    if (!win) {
      return {
        error: "canvas not found or empty",
        debug: {
          ts,
          reason: "remoteWindow_null",
          iframeExists,
          iframeSrc: ifSrc,
        },
      };
    }
    let doc: Document | null = null;
    try {
      doc = win.document;
    } catch (e) {
      return {
        error: "canvas not found or empty",
        debug: {
          ts,
          reason: "doc_access_threw",
          iframeExists,
          iframeSrc: ifSrc,
          message: e instanceof Error ? e.message : String(e),
        },
      };
    }
    if (!doc) {
      return {
        error: "canvas not found or empty",
        debug: { ts, reason: "doc_null", iframeExists, iframeSrc: ifSrc },
      };
    }
    try {
      const displayEl = doc.querySelector("#display, .display");
      const canvasesInDisplay = displayEl
        ? (Array.from(displayEl.querySelectorAll("canvas")) as HTMLCanvasElement[])
        : [];
      const allCanvases = Array.from(doc.querySelectorAll("canvas")) as HTMLCanvasElement[];
      const canvases = displayEl ? canvasesInDisplay : allCanvases;

      // 항상 함께 첨부할 진단 컨텍스트
      const baseDebug: Record<string, unknown> = {
        ts,
        iframeExists,
        iframeSrc: ifSrc,
        docReadyState: doc.readyState,
        docUrl: (doc.location && doc.location.href) || "(unknown)",
        docTitle: doc.title,
        bodyChildren: doc.body?.children.length ?? 0,
        iframesInDoc: doc.querySelectorAll("iframe").length,
        displayElFound: !!displayEl,
        canvasesInDisplay: canvasesInDisplay.length,
        canvasesAnywhere: allCanvases.length,
        activeElement: doc.activeElement?.tagName ?? null,
        // forensics: 어떤 페이지가 떠 있는지 확인용 (HTML 앞 400자)
        bodyHtmlPreview: (doc.body?.innerHTML ?? "(no body)").slice(0, 400),
      };

      if (canvases.length === 0) {
        return {
          error: "canvas not found or empty",
          debug: { ...baseDebug, reason: "no_canvases" },
        };
      }
      const sizes = canvases.map((c) => `${c.width}x${c.height}`);
      const mainCanvas = canvases[0];
      const w = mainCanvas.width;
      const h = mainCanvas.height;
      if (w === 0 || h === 0) {
        return {
          error: "canvas not found or empty",
          debug: { ...baseDebug, reason: "main_canvas_zero", canvasSizes: sizes },
        };
      }
      const offscreen = document.createElement("canvas");
      offscreen.width = w;
      offscreen.height = h;
      const ctx = offscreen.getContext("2d");
      if (!ctx) {
        return {
          error: "canvas not found or empty",
          debug: { ...baseDebug, reason: "offscreen_2d_ctx_null", canvasSizes: sizes },
        };
      }
      let drawnLayers = 0;
      const drawErrors: string[] = [];
      for (const c of canvases) {
        if (c.width > 0 && c.height > 0) {
          try {
            ctx.drawImage(c, 0, 0, w, h);
            drawnLayers++;
          } catch (e) {
            drawErrors.push(e instanceof Error ? e.message : String(e));
          }
        }
      }
      if (drawnLayers === 0) {
        return {
          error: "canvas not found or empty",
          debug: { ...baseDebug, reason: "no_layers_drawn", canvasSizes: sizes, drawErrors },
        };
      }
      let dataUrl: string;
      try {
        dataUrl = offscreen.toDataURL("image/png");
      } catch (e) {
        return {
          error: "canvas not found or empty",
          debug: {
            ...baseDebug,
            reason: "toDataURL_threw",
            canvasSizes: sizes,
            message: e instanceof Error ? e.message : String(e),
          },
        };
      }
      return { image: dataUrl.split(",")[1], width: w, height: h };
    } catch (e) {
      console.warn("[BoanClaw] captureCanvas unexpected error", e);
      return {
        error: "canvas not found or empty",
        debug: {
          ts,
          reason: "outer_catch",
          iframeExists,
          iframeSrc: ifSrc,
          message: e instanceof Error ? e.message : String(e),
          stack: e instanceof Error ? e.stack?.slice(0, 500) : null,
        },
      };
    }
  };

  // ── 마우스 입력: Guacamole client API 직접 호출
  //
  // 이전 구현은 .display div 에 합성 DOM MouseEvent 를 dispatch 했는데, Guacamole.Mouse
  // 가 그걸 전혀 받지 못해서 (synthetic / wrong target / isTrusted 문제) 모든 클릭이
  // 무시되고 있었다. Vision LLM 은 좌표를 잘 보내고 있었지만 RDP 측에 도달 자체를 안 함.
  //
  // 키보드 (injectKeyName) 가 이미 client.sendKeyEvent 직접 호출로 잘 동작하는 것과
  // 동일하게, 마우스도 client.sendMouseState 를 직접 부른다. 이게 Guacamole.Mouse 가
  // 내부적으로 RDP 서버로 보내는 그 메서드 — DOM 이벤트 우회.
  //
  // 좌표계: vision LLM 이 보는 screenshot 의 픽셀 == canvas native pixel == RDP 서버
  // 화면 픽셀 (Guacamole canvas 의 internal 해상도가 곧 remote screen resolution).
  // 따라서 vision 좌표를 그대로 sendMouseState 에 넘기면 됨 — CSS 변환 일절 불필요.
  type GuacClient = {
    sendMouseState?: (state: {
      x: number; y: number;
      left?: boolean; middle?: boolean; right?: boolean;
      up?: boolean; down?: boolean;
    }) => void;
    sendKeyEvent?: (pressed: number, keysym: number) => void;
  };

  const buttonState = (button: string, pressed: boolean) => {
    const s = { left: false, middle: false, right: false, up: false, down: false };
    if (!pressed) return s;
    if (button === "right") s.right = true;
    else if (button === "middle") s.middle = true;
    else s.left = true;
    return s;
  };

  const injectMouseClick = (x: number, y: number, button: string = "left", double: boolean = false): Promise<void> => {
    return new Promise<void>((resolve) => {
      const client = getManagedClient() as GuacClient | null;
      if (!client?.sendMouseState) {
        console.warn("[BoanClaw] injectMouseClick: guacamole client not available");
        resolve();
        return;
      }
      const press = () => client.sendMouseState!({ x, y, ...buttonState(button, true) });
      const release = () => client.sendMouseState!({ x, y, ...buttonState(button, false) });

      // 1) move (no buttons) → 2) press → 3) release. 더블클릭이면 한 번 더.
      client.sendMouseState({ x, y, left: false, middle: false, right: false, up: false, down: false });
      press();
      setTimeout(() => {
        release();
        if (!double) { resolve(); return; }
        setTimeout(() => {
          press();
          setTimeout(() => { release(); resolve(); }, 30);
        }, 50);
      }, 50);
    });
  };

  const injectMouseMove = (x: number, y: number) => {
    const client = getManagedClient() as GuacClient | null;
    if (!client?.sendMouseState) return;
    client.sendMouseState({ x, y, left: false, middle: false, right: false, up: false, down: false });
  };

  const injectWheelScroll = (x: number, y: number, direction: string, amount: number) => {
    const client = getManagedClient() as GuacClient | null;
    if (!client?.sendMouseState) return;
    // Guacamole 의 wheel: up = scroll up, down = scroll down. 한 단위가 wheel notch 1.
    // amount 만큼 반복해서 click → release.
    const dir = direction === "up" ? "up" : "down";
    const ticks = Math.max(1, Math.min(amount | 0, 20));
    const tick = (i: number) => {
      if (i >= ticks) return;
      client.sendMouseState!({ x, y, [dir]: true } as { x: number; y: number; up?: boolean; down?: boolean });
      setTimeout(() => {
        client.sendMouseState!({ x, y, [dir]: false } as { x: number; y: number; up?: boolean; down?: boolean });
        setTimeout(() => tick(i + 1), 20);
      }, 20);
    };
    tick(0);
  };

  const injectKeyName = (name: string) => {
    const win = remoteWindow();
    const target = remoteTarget();
    if (!win || !target) return;

    // LLM이 ctrl+s, alt+F4, ctrl+shift+t 형태로 보낼 수 있으므로 + 구분자 처리
    if (name.includes("+")) {
      const parts = name.toLowerCase().split("+");
      const key = parts[parts.length - 1];
      const hasCtrl = parts.includes("ctrl") || parts.includes("control");
      const hasAlt = parts.includes("alt");
      const hasShift = parts.includes("shift");
      const client = getManagedClient() as { sendKeyEvent?: (p: number, k: number) => void } | null;
      if (client?.sendKeyEvent) {
        const ksym = toKeysym(key);
        if (ksym != null) {
          if (hasCtrl) client.sendKeyEvent(1, 0xffe3);
          if (hasAlt) client.sendKeyEvent(1, 0xffe9);
          if (hasShift) client.sendKeyEvent(1, 0xffe1);
          client.sendKeyEvent(1, ksym);
          client.sendKeyEvent(0, ksym);
          if (hasShift) client.sendKeyEvent(0, 0xffe1);
          if (hasAlt) client.sendKeyEvent(0, 0xffe9);
          if (hasCtrl) client.sendKeyEvent(0, 0xffe3);
          return;
        }
      }
      // Fallback: Ctrl-key 형식으로 재귀
      if (hasCtrl) { injectKeyName(`Ctrl-${key}`); return; }
      if (hasAlt) {
        dispatchKeyEvent(win, target, "keydown", key, { altKey: true });
        dispatchKeyEvent(win, target, "keyup", key, { altKey: true });
        return;
      }
    }

    // Handle Ctl- chord keys via managed Guacamole client
    if (name.startsWith("Ctl-") || name.startsWith("Ctrl-")) {
      const key = name.replace(/^Ct(?:r?)l-/, "").toLowerCase();
      const client = getManagedClient() as { sendKeyEvent?: (p: number, k: number) => void } | null;
      if (client?.sendKeyEvent) {
        const ksym = toKeysym(key);
        if (ksym != null) {
          client.sendKeyEvent(1, 0xffe3); // Ctrl press
          client.sendKeyEvent(1, ksym);
          client.sendKeyEvent(0, ksym);
          client.sendKeyEvent(0, 0xffe3); // Ctrl release
          return;
        }
      }
      dispatchKeyEvent(win, target, "keydown", key, { ctrlKey: true });
      dispatchKeyEvent(win, target, "keyup", key, { ctrlKey: true });
      return;
    }
    const keyMap: Record<string, string> = {
      Return: "Enter", BackSpace: "Backspace", Prior: "PageUp", Next: "PageDown",
      Up: "ArrowUp", Down: "ArrowDown", Left: "ArrowLeft", Right: "ArrowRight",
      Win: "Meta", Ctl_L: "Control", Ctl_R: "Control",
      Escape: "Escape", Tab: "Tab", Delete: "Delete",
    };
    injectImmediateKeyToRemote(keyMap[name] ?? name);
  };

  const sendImmediateKey = async (key: string) => {
    setGateBusy(true);
    try {
      const result = await inputGateApi.evaluate({
        mode: "key",
        key,
        src_level: 3,
        dest_level: 1,
        flow: "local-special-key-to-remote-workstation",
      });
      if (!result.allowed) {
        setGateStatus(result.reason ?? "이 키는 현재 차단되었습니다.");
        return;
      }
      injectImmediateKeyToRemote(result.key || key);
      setGateStatus(`보안 게이트를 통과한 키 ${key}를 원격 화면으로 전달했습니다.`);
    } catch (e) {
      setGateStatus(e instanceof Error ? e.message : "키 게이트 검사에 실패했습니다.");
    } finally {
      setGateBusy(false);
      focusGateInputDeferred();
    }
  };

  const toKeysym = (key: string) => {
    if (!key) return null;
    const named: Record<string, number> = {
      Control: 0xffe3,
      Meta: 0xffe7,
      Alt: 0xffe9,
      Enter: 0xff0d,
      Tab: 0xff09,
      Escape: 0xff1b,
      Backspace: 0xff08,
      Delete: 0xffff,
      Home: 0xff50,
      End: 0xff57,
      PageUp: 0xff55,
      PageDown: 0xff56,
      ArrowLeft: 0xff51,
      ArrowUp: 0xff52,
      ArrowRight: 0xff53,
      ArrowDown: 0xff54,
      Insert: 0xff63,
      F1: 0xffbe,
      F2: 0xffbf,
      F3: 0xffc0,
      F4: 0xffc1,
      F5: 0xffc2,
      F6: 0xffc3,
      F7: 0xffc4,
      F8: 0xffc5,
      F9: 0xffc6,
      F10: 0xffc7,
      F11: 0xffc8,
      F12: 0xffc9,
      " ": 0x20,
    };
    if (named[key]) return named[key];
    // case-insensitive lookup: "f4" → "F4", "escape" → "Escape" 등
    const ciMatch = Object.keys(named).find((k) => k.toLowerCase() === key.toLowerCase());
    if (ciMatch) return named[ciMatch];
    if (key.length === 1) return key.codePointAt(0) ?? null;
    return null;
  };

  const sendManagedClientKey = (pressed: 0 | 1, key: string) => {
    const client = getManagedClient();
    const keysym = toKeysym(key);
    if (!client || keysym == null) return false;
    client.sendKeyEvent(pressed, keysym);
    return true;
  };

  const sendDirectChordToRemote = (key: string, modifier: "ctrl" | "meta") => {
    const modifierKey = modifier === "ctrl" ? "Control" : "Meta";
    if (!sendManagedClientKey(1, modifierKey)) return;
    sendManagedClientKey(1, key);
    sendManagedClientKey(0, key);
    sendManagedClientKey(0, modifierKey);
  };

  const remoteWindow = () => iframeRef.current?.contentWindow ?? null;

  const remoteTarget = (): EventTarget | null => {
    const win = remoteWindow();
    if (!win) return null;
    try {
      const doc = win.document;
      return (
        doc.activeElement ||
        doc.querySelector("#display, .display, canvas, input, textarea") ||
        doc.body ||
        win
      );
    } catch {
      return null;
    }
  };

  const forwardPointerEvent = (event: React.PointerEvent<HTMLDivElement>) => {
    const win = remoteWindow();
    if (!win) return;
    try {
      const iframe = iframeRef.current;
      if (!iframe) return;
      const rect = event.currentTarget.getBoundingClientRect();
      const clientX = event.clientX - rect.left;
      const clientY = event.clientY - rect.top;
      const doc = win.document;
      const target =
        doc.elementFromPoint(clientX, clientY) ||
        doc.querySelector("#display, .display, canvas") ||
        doc.body;
      if (!target) return;
      const forwardedType =
        event.type === "pointerdown"
          ? "mousedown"
          : event.type === "pointerup"
            ? "mouseup"
            : event.type === "pointermove"
              ? "mousemove"
              : event.type;
      const MouseCtor = (doc.defaultView?.MouseEvent ?? globalThis.MouseEvent) as typeof MouseEvent;
      const forwarded = new MouseCtor(forwardedType, {
        bubbles: true,
        cancelable: true,
        clientX,
        clientY,
        button: event.button,
        buttons: event.buttons,
        ctrlKey: event.ctrlKey,
        shiftKey: event.shiftKey,
        altKey: event.altKey,
        metaKey: event.metaKey,
      });
      target.dispatchEvent(forwarded);
    } catch {
      // Ignore best-effort pointer forwarding failures.
    } finally {
      // Mouse interaction must not change keyboard ownership.
    }
  };

  const forwardWheelEvent = (event: React.WheelEvent<HTMLDivElement>) => {
    const win = remoteWindow();
    if (!win) return;
    try {
      const rect = event.currentTarget.getBoundingClientRect();
      const clientX = event.clientX - rect.left;
      const clientY = event.clientY - rect.top;
      const doc = win.document;
      const target =
        doc.elementFromPoint(clientX, clientY) ||
        doc.querySelector("#display, .display, canvas") ||
        doc.body;
      if (!target) return;
      const WheelCtor = (doc.defaultView?.WheelEvent ?? globalThis.WheelEvent) as typeof WheelEvent;
      const forwarded = new WheelCtor("wheel", {
        bubbles: true,
        cancelable: true,
        clientX,
        clientY,
        deltaX: event.deltaX,
        deltaY: event.deltaY,
        deltaZ: event.deltaZ,
        deltaMode: event.deltaMode,
      });
      target.dispatchEvent(forwarded);
    } catch {
      // Ignore best-effort wheel forwarding failures.
    } finally {
      // Mouse interaction must not change keyboard ownership.
    }
  };

  const injectImmediateKeyToRemote = (key: string) => {
    const win = remoteWindow();
    const target = remoteTarget();
    if (!win || !target) return;
    dispatchKeyEvent(win, target, "keydown", key);
    if (key.length === 1) {
      dispatchKeyEvent(win, target, "keypress", key);
    }
    dispatchKeyEvent(win, target, "keyup", key);
  };

  const injectTextToRemote = (text: string) => {
    const win = remoteWindow();
    const target = remoteTarget();
    if (!win || !target) return;
    for (const char of text) {
      // \n / \r → Enter 키 이벤트로 변환. 안 그러면 keyCode 10/13 의 generic
      // KeyboardEvent 가 되어 Guacamole client 가 keysym 매핑 못 하고 무시.
      if (char === "\n" || char === "\r") {
        dispatchKeyEvent(win, target, "keydown", "Enter");
        dispatchKeyEvent(win, target, "keyup", "Enter");
        continue;
      }
      dispatchKeyEvent(win, target, "keydown", char);
      dispatchKeyEvent(win, target, "keyup", char);
    }
  };

  const handleTextareaKeyDown = async (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (!remoteReady || !isActive) return;

    if ((event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === "v") {
      event.preventDefault();
      try {
        const text = await navigator.clipboard.readText();
        const lastGcpCopy = capturedRemoteClipboardRef.current;
        console.log("[BoanClaw] Ctrl+V: systemClipboard=", text?.slice(0, 30), "lastGcpCopy=", lastGcpCopy?.slice(0, 30));
        if (lastGcpCopy && text === lastGcpCopy) {
          // S1→S1: 시스템 클립보드가 마지막 GCP 복사 내용과 같음 → 게이트 없이 주입
          injectTextToRemote(text);
          setGateStatus("원격 클립보드 내용을 게이트 없이 원격 화면에 전달했습니다.");
        } else {
          // S3→S1: 외부에서 복사한 내용 → 게이트 통과
          await evaluateClipboardInput(text);
        }
      } catch {
        setGateStatus("클립보드를 읽지 못했습니다. 브라우저 권한을 확인하거나 다시 시도하세요.");
      }
      focusGateInputDeferred();
      return;
    }

    if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "c") {
      event.preventDefault();
      const modifier = event.ctrlKey ? "ctrl" : "meta";
      const chord = `${modifier === "ctrl" ? "Ctrl" : "Meta"}+${event.key.toUpperCase()}`;
      try {
        const result = await inputGateApi.evaluate({
          mode: "chord",
          key: chord,
          src_level: 3,
          dest_level: 1,
          flow: "local-copy-command-to-remote-workstation",
        });
        if (!result.allowed) {
          setGateStatus(result.reason ?? "복사 명령이 차단되었습니다.");
          focusGateInputDeferred();
          return;
        }
      } catch (e) {
        setGateStatus(e instanceof Error ? e.message : "복사 명령 검사에 실패했습니다.");
        focusGateInputDeferred();
        return;
      }
      sendDirectChordToRemote(event.key, modifier);
      setGateStatus("원격 Ctrl+C 전송 중... 클립보드 동기화 대기 중");
      focusGateInputDeferred();

      // Poll Guacamole's clipboard until the remote clipboard changes.
      // clipboardSyncPromiseRef lets Ctrl+V await this completion deterministically.
      const before = capturedRemoteClipboardRef.current;
      // Poll Guacamole's original getClipboard until clipboard changes (max 20 attempts).
      const pollGuacClipboard = async (attemptsLeft = 20) => {
        console.log("[BoanClaw] pollGuacClipboard attemptsLeft=", attemptsLeft, "before=", before?.slice(0, 20));
        const win = remoteWindow() as
          | (Window & { angular?: { element: (n: unknown) => { injector?: () => { get: (s: string) => unknown } } } })
          | null;
        if (!win?.angular) return;
        try {
          const root = win.document.body ?? win.document.documentElement;
          const injector = win.angular.element(root).injector?.();
          if (!injector) return;
          const svc = injector.get("clipboardService") as {
            getClipboard?: () => PromiseLike<{ type?: string; data?: unknown }>;
            __boanOriginalGetClipboard__?: () => PromiseLike<{ type?: string; data?: unknown }>;
          } | null;
          const getter = svc?.__boanOriginalGetClipboard__ ?? svc?.getClipboard;
          if (!getter || !svc) return;
          const data = await Promise.resolve(getter.call(svc));
          console.log("[BoanClaw] pollGuacClipboard got", data?.type, typeof data?.data === "string" ? (data.data as string).slice(0, 30) : data?.data);
          if (data?.type === "text/plain" && typeof data.data === "string" && data.data && data.data !== before) {
            capturedRemoteClipboardRef.current = data.data;
            setCapturedRemoteClipboard(data.data);
            try {
              await navigator.clipboard.writeText(data.data);
              setGateStatus("원격 클립보드를 로컬 클립보드로 동기화했습니다.");
            } catch {
              setGateStatus("원격 클립보드 캡처 완료. '원격 복사 가져오기' 버튼으로 복사하세요.");
            }
            return;
          }
        } catch (e) {
          console.log("[BoanClaw] pollGuacClipboard error:", e);
        }
        if (attemptsLeft > 0) window.setTimeout(() => void pollGuacClipboard(attemptsLeft - 1), 200);
      };
      window.setTimeout(() => void pollGuacClipboard(), 150);
      return;
    }

    // event.code로 Enter 판별 — 한글 IME 활성 시 event.key가 "Process"로 오는 버그 대응
    const isEnterCode = event.code === "Enter" || event.code === "NumpadEnter";
    if (event.key === "Enter" || (event.key === "Process" && isEnterCode)) {
      // Alt+Enter — 줄바꿈 삽입. 옛 "실행" 단축키였는데 computer-use 삭제 후
      // 명시적 줄바꿈으로 재배정. textarea 는 Alt+Enter 에 기본 newline 동작이
      // 없어서 직접 cursor 위치에 \n 끼워넣고 selectionStart 갱신.
      if (event.altKey) {
        event.preventDefault();
        const ta = event.currentTarget as HTMLTextAreaElement;
        const start = ta.selectionStart ?? buffer.length;
        const end = ta.selectionEnd ?? buffer.length;
        const next = buffer.slice(0, start) + "\n" + buffer.slice(end);
        setBuffer(next);
        // React 렌더 후에 cursor 를 \n 다음으로 이동.
        window.requestAnimationFrame(() => {
          if (gateInputRef.current) {
            gateInputRef.current.value = next;
            gateInputRef.current.selectionStart = start + 1;
            gateInputRef.current.selectionEnd = start + 1;
          }
        });
        return;
      }
      event.preventDefault();
      if (event.key === "Process") return; // IME 조합 중 Enter는 무시
      if (buffer.trim()) {
        await submitBufferedInput();
      } else {
        injectImmediateKeyToRemote("Enter");
        setGateStatus("Enter 키를 원격 화면으로 바로 전달했습니다.");
        focusGateInput();
      }
      return;
    }

    if (event.metaKey || event.ctrlKey || event.altKey) {
      // Skip if the key itself is a modifier — pressing Ctrl alone is not a chord
      if (["Control", "Meta", "Alt", "Shift", "Process"].includes(event.key)) return;
      event.preventDefault();
      const modifier = event.ctrlKey ? "ctrl" : "meta";
      const chord = `${modifier === "ctrl" ? "Ctrl" : modifier === "meta" ? "Meta" : "Alt"}+${event.key.toUpperCase()}`;
      try {
        const result = await inputGateApi.evaluate({
          mode: "chord",
          key: chord,
          src_level: 3,
          dest_level: 1,
          flow: "local-chord-to-remote-workstation",
        });
        if (!result.allowed) {
          setGateStatus(result.reason ?? "조합키가 차단되었습니다.");
          focusGateInputDeferred();
          return;
        }
      } catch (e) {
        setGateStatus(e instanceof Error ? e.message : "조합키 검사에 실패했습니다.");
        focusGateInputDeferred();
        return;
      }
      sendDirectChordToRemote(event.key, modifier);
      setGateStatus(`조합키 ${event.key}는 Input Gate를 통과해 원격 화면으로 전달됩니다.`);
      focusGateInputDeferred();
      return;
    }

    if (IMMEDIATE_KEYS.has(event.key)) {
      event.preventDefault();
      await sendImmediateKey(event.key);
      return;
    }

    if (event.key === "Backspace" && buffer.length === 0) {
      event.preventDefault();
      await sendImmediateKey("Backspace");
      return;
    }

    if (event.key === "Delete" && buffer.length === 0) {
      event.preventDefault();
      await sendImmediateKey("Delete");
    }
  };

  const handleTextareaPaste = async (event: ClipboardEvent<HTMLTextAreaElement>) => {
    event.preventDefault();
    const text = event.clipboardData.getData("text");
    const lastGcpCopy = capturedRemoteClipboardRef.current;
    console.log("[BoanClaw] onPaste: text=", text?.slice(0, 30), "lastGcpCopy=", lastGcpCopy?.slice(0, 30));
    if (lastGcpCopy && text === lastGcpCopy) {
      injectTextToRemote(text);
      setGateStatus("원격 클립보드 내용을 게이트 없이 원격 화면에 전달했습니다.");
    } else {
      await evaluateClipboardInput(text);
    }
  };

  const handleTextareaChange = (event: ChangeEvent<HTMLTextAreaElement>) => {
    if (ignoreNextChangeRef.current) {
      ignoreNextChangeRef.current = false;
      // DOM 값도 강제로 비워 IME commit 재삽입 방지
      if (gateInputRef.current) gateInputRef.current.value = "";
      return;
    }
    setBuffer(event.target.value);
    setGateStatus("입력이 Secure Input 바에 쌓였습니다. 전송 버튼을 누르면 검사 후 원격 화면으로 보냅니다.");
  };

  const handleTextareaBlur = (_event: FocusEvent<HTMLTextAreaElement>) => {
    if (!isActive || !remoteReady) return;
    // blur 가 먼저 터지고 focusin(IFRAME) 이 직후에 발생해 focusTarget="boanclaw"
    // 로 바뀌는 타이밍이 있다. focusGateInputDeferred 내부에서 ref 기반으로
    // 재확인하므로, RAF 가 실제로 실행되는 시점에는 이미 "boanclaw" 로 바뀌어
    // 있어 early return 된다.
    focusGateInputDeferred();
  };

  return (
    <div className="h-full w-full bg-gray-100">
      {/* 숨겨진 OpenClaw iframe — AI 백그라운드 실행용 (화면에 표시 안됨) */}
      {openclawUrl && (
        <iframe
          ref={openclawFrameRef}
          title="OpenClaw"
          src={openclawUrl}
          style={{ position: "fixed", width: 0, height: 0, border: 0, opacity: 0, pointerEvents: "none", top: "-9999px", left: "-9999px" }}
          aria-hidden="true"
          tabIndex={-1}
        />
      )}
      {workstation?.web_desktop_url ? (
        <div className="relative h-full bg-black">
            <iframe
              ref={iframeRef}
              title="Personal Windows Workstation"
              src={workstation.web_desktop_url}
              allow="clipboard-read; clipboard-write"
              onLoad={() => {
                focusGateInput();
                tryInstallBridgeWithRetry();
              }}
              tabIndex={-1}
              className="pointer-events-none h-full w-full border-0 bg-white"
            />
            <div
              className="absolute inset-0 z-20 cursor-default bg-transparent"
              onPointerDown={(event) => {
                event.preventDefault();
                forwardPointerEvent(event);
                // GCP 쪽을 누르면 focus 주인을 "gcp" 로 선언.
                setFocusTarget("gcp");
                window.setTimeout(focusGateInput, 0);
              }}
              onPointerUp={(event) => {
                event.preventDefault();
                forwardPointerEvent(event);
              }}
              onPointerMove={(event) => {
                event.preventDefault();
                forwardPointerEvent(event);
              }}
              onClick={(event) => {
                event.preventDefault();
                forwardPointerEvent(event as unknown as React.PointerEvent<HTMLDivElement>);
              }}
              onDoubleClick={(event) => {
                event.preventDefault();
                forwardPointerEvent(event as unknown as React.PointerEvent<HTMLDivElement>);
              }}
              onContextMenu={(e) => {
                e.preventDefault();
              }}
              onWheel={(event) => {
                event.preventDefault();
                forwardWheelEvent(event);
              }}
            />
          <div className="pointer-events-none absolute inset-x-0 bottom-0 z-30 flex justify-center px-4 pb-4">
            <div
              className="pointer-events-auto w-full max-w-3xl overflow-hidden rounded-2xl border border-cyan-400/20 bg-slate-950/92 shadow-2xl backdrop-blur outline-none focus:border-cyan-300 focus:ring-2 focus:ring-cyan-400/30"
            >
              <div className="flex items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1 rounded-xl border border-cyan-400/15 bg-slate-900/80 px-4 py-3">
                  <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-[0.2em]">
                    <span className="text-cyan-300/60">BoanClaw Input</span>
                    {gateStatus && <span className="normal-case tracking-normal text-white truncate">{gateStatus}</span>}
                  </div>
                  <textarea
                    ref={gateInputRef}
                    value={buffer}
                    onChange={handleTextareaChange}
                    onKeyDown={(event) => void handleTextareaKeyDown(event)}
                    onPaste={(event) => void handleTextareaPaste(event)}
                    onBlur={handleTextareaBlur}
                    rows={2}
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    className="min-h-8 w-full resize-none bg-transparent text-sm leading-6 text-cyan-50 outline-none placeholder:text-cyan-300/40"
                    placeholder="Type with keyboard, then press Enter to send"
                  />
                </div>
                <div className="flex shrink-0 flex-col gap-2">
                  <button
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => void submitBufferedInput()}
                    disabled={gateBusy || !buffer.trim()}
                    className="inline-flex h-10 items-center justify-center rounded-xl bg-cyan-400 px-4 text-xs font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
                  >
                    {gateBusy ? "검사 중..." : "전송"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : loading ? (
        <StateScreen title="작업 컴퓨터를 불러오는 중" subtitle="잠시만 기다리세요." />
      ) : error || !workstation ? (
        <StateScreen
          title="작업 컴퓨터가 준비되지 않았습니다"
          subtitle={error ?? "소유자 승인 후 개인 작업 컴퓨터가 생성됩니다."}
        />
      ) : (
        <StateScreen
          title={screenTitle}
          subtitle={stateSubtitle(workstation)}
          actionHref={workstation.console_url}
          actionLabel={workstation.console_url ? "콘솔 열기" : undefined}
        />
      )}
    </div>
  );
}

function keyDetails(key: string) {
  const special: Record<string, { code: string; keyCode: number }> = {
    Enter: { code: "Enter", keyCode: 13 },
    Tab: { code: "Tab", keyCode: 9 },
    Backspace: { code: "Backspace", keyCode: 8 },
    Delete: { code: "Delete", keyCode: 46 },
    Escape: { code: "Escape", keyCode: 27 },
    ArrowUp: { code: "ArrowUp", keyCode: 38 },
    ArrowDown: { code: "ArrowDown", keyCode: 40 },
    ArrowLeft: { code: "ArrowLeft", keyCode: 37 },
    ArrowRight: { code: "ArrowRight", keyCode: 39 },
    Home: { code: "Home", keyCode: 36 },
    End: { code: "End", keyCode: 35 },
    PageUp: { code: "PageUp", keyCode: 33 },
    PageDown: { code: "PageDown", keyCode: 34 },
    Insert: { code: "Insert", keyCode: 45 },
  };

  if (special[key]) return special[key];
  if (/^F\d{1,2}$/.test(key)) {
    return { code: key, keyCode: 111 + Number.parseInt(key.slice(1), 10) };
  }
  if (key.length === 1) {
    const upper = key.toUpperCase();
    if (/[A-Z]/.test(upper)) {
      return { code: `Key${upper}`, keyCode: upper.charCodeAt(0) };
    }
    if (/[0-9]/.test(key)) {
      return { code: `Digit${key}`, keyCode: key.charCodeAt(0) };
    }
    if (key === " ") {
      return { code: "Space", keyCode: 32 };
    }
    return { code: `Key${upper}`, keyCode: key.charCodeAt(0) };
  }
  return { code: key, keyCode: 0 };
}

function dispatchKeyEvent(
  win: Window,
  target: EventTarget,
  type: string,
  key: string,
  modifiers?: { ctrlKey?: boolean; metaKey?: boolean; altKey?: boolean; shiftKey?: boolean },
) {
  const { code, keyCode } = keyDetails(key);
  const value = key.length === 1 ? key.charCodeAt(0) : keyCode;
  const KeyboardCtor = ((win.document.defaultView?.KeyboardEvent ?? globalThis.KeyboardEvent) as typeof KeyboardEvent);
  const dispatchTo = (nextTarget: EventTarget) => {
    const event = new KeyboardCtor(type, {
      key,
      code,
      bubbles: true,
      cancelable: true,
      ctrlKey: modifiers?.ctrlKey ?? false,
      metaKey: modifiers?.metaKey ?? false,
      altKey: modifiers?.altKey ?? false,
      shiftKey: modifiers?.shiftKey ?? false,
    });
    for (const [name, current] of [
      ["keyCode", keyCode],
      ["which", keyCode],
      ["charCode", type === "keypress" ? value : 0],
    ] as const) {
      Object.defineProperty(event, name, {
        configurable: true,
        get: () => current,
      });
    }
    nextTarget.dispatchEvent(event);
  };

  dispatchTo(target);
  if (target !== win.document) {
    dispatchTo(win.document);
  }
  dispatchTo(win);
}

function stateTitle(status: string) {
  if (status === "provisioning") return "작업 컴퓨터를 생성하는 중입니다";
  if (status === "running") return "웹 제어 화면을 준비하는 중입니다";
  if (status === "stopped") return "작업 컴퓨터가 중지되어 있습니다";
  if (status === "stopping") return "작업 컴퓨터를 중지하는 중입니다";
  return "작업 컴퓨터가 아직 생성되지 않았습니다";
}

function stateSubtitle(workstation: PersonalWorkstation) {
  if (workstation.status === "provisioning") {
    return "몇 분 뒤 새로고침하면 화면이 연결됩니다.";
  }
  if (workstation.status === "running") {
    return "원격 제어 게이트웨이 연결이 완료되면 이 화면 전체에 바로 표시됩니다.";
  }
  if (workstation.status === "stopped") {
    return "다시 접속하면 자동으로 시작되며, 준비가 끝나면 이 화면에 바로 표시됩니다.";
  }
  if (workstation.status === "stopping") {
    return "중지 작업이 끝난 뒤 다시 접속하면 자동으로 시작됩니다.";
  }
  return "소유자 승인 후 개인 작업 컴퓨터가 생성되며, 준비가 끝나면 이 화면 전체에 바로 표시됩니다.";
}

function StateScreen({
  title,
  subtitle,
  actionHref,
  actionLabel,
}: {
  title: string;
  subtitle: string;
  actionHref?: string;
  actionLabel?: string;
}) {
  return (
    <div className="flex h-full items-center justify-center bg-[radial-gradient(circle_at_top,_#ffffff,_#eef2f7_55%,_#e5e7eb)] px-8">
      <div className="w-full max-w-3xl rounded-3xl border border-white/70 bg-white/80 p-12 text-center shadow-[0_30px_80px_rgba(15,23,42,0.08)] backdrop-blur">
        <div className="text-lg font-semibold text-gray-900">{title}</div>
        <div className="mt-3 text-sm text-gray-500">{subtitle}</div>
        {actionHref && actionLabel && (
          <a
            href={actionHref}
            target="_blank"
            rel="noreferrer"
            className="mt-6 inline-flex rounded-xl border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            {actionLabel}
          </a>
        )}
      </div>
    </div>
  );
}
