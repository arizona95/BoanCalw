import { ApprovalQueue } from "../components/ApprovalQueue";

// Approvals — User Actions 전용 큐. 가드레일 amendment 는 /guardrail 의 HITL 탭,
// kill chain trigger / threat leader 제안은 /kill-chain 의 HITL 탭에서 처리.
// (이전엔 한 페이지에 모든 승인이 모여서 승인 대상을 분간하기 어려웠음.)
export default function Approvals() {
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-2xl font-bold">User Actions</h1>
        <p className="text-xs text-gray-500 mt-1">
          사용자 가입 / credential 등록 / agent 동작 등 일반 승인 큐. 가드레일 변경안과 Kill Chain HITL 은 각 페이지에서 분리 관리.
        </p>
      </div>
      <ApprovalQueue category="user" emptyText="대기 중인 사용자 행동 승인이 없습니다." />
    </div>
  );
}
