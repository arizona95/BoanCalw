import { createContext, useCallback, useContext, useRef, useState, type MutableRefObject, type ReactNode } from "react";

// 사용모드에서 왼쪽 BoanClaw chat iframe 과 오른쪽 GCP 리모트 화면이 동시에
// 보이는데, 키 입력은 한쪽에만 들어가야 한다. 각 컴포넌트가 자기 마음대로
// focus 를 잡으면 무한 focus 전쟁이 일어나므로, 앱 레벨에서 누가 주인인지
// 단일 state 로 관리한다.
//
// state 는 React 렌더용이고, ref 는 blur / RAF 핸들러에서 "지금 당장" 의
// 값을 읽기 위해 동기 업데이트된다. setFocusTarget 호출 시점과 React 리렌더
// 사이의 race 를 없애는 것이 목적.
export type FocusTarget = "gcp" | "boanclaw";

type FocusContextValue = {
  focusTarget: FocusTarget;
  focusTargetRef: MutableRefObject<FocusTarget>;
  setFocusTarget: (t: FocusTarget) => void;
};

const FocusContext = createContext<FocusContextValue | null>(null);

export function FocusProvider({ children }: { children: ReactNode }) {
  const [focusTarget, setFocusTargetState] = useState<FocusTarget>("gcp");
  const focusTargetRef = useRef<FocusTarget>("gcp");
  const setFocusTarget = useCallback((t: FocusTarget) => {
    focusTargetRef.current = t;
    setFocusTargetState((prev) => (prev === t ? prev : t));
  }, []);
  return (
    <FocusContext.Provider value={{ focusTarget, focusTargetRef, setFocusTarget }}>
      {children}
    </FocusContext.Provider>
  );
}

export function useFocusTarget(): FocusContextValue {
  const ctx = useContext(FocusContext);
  if (!ctx) {
    // Provider 밖에서 호출되는 경우(예: 라우팅 밖) — no-op 기본값.
    const dummy = { current: "gcp" as FocusTarget };
    return { focusTarget: "gcp", focusTargetRef: dummy, setFocusTarget: () => undefined };
  }
  return ctx;
}
