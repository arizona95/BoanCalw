import OrgRegistry from "./OrgRegistry";

// Organization — 호스트가 연결된 조직 + 조직 레벨 설정 (golden image 등) 통합.
// Authorization 탭의 "🏢 조직" 서브탭에서 분리 — 의미상 user/SSO 관리와는
// 다른 layer (호스트 머신 ↔ 조직서버 연결).
//
// 사이드바 위치: BoanClaw 위, 별도 섹션. user/admin 모두 여기서 본인이
// 어느 조직에 붙어있는지 확인 + (필요 시) 추가 가입 요청.
export default function Organization() {
  return (
    <div className="p-6 max-w-5xl">
      <h1 className="text-2xl font-bold text-gray-800">🏢 Organization</h1>
      <p className="mt-1 text-sm text-gray-500">
        이 BoanClaw 가 통신하는 조직 서버 목록. 사용자가 Register 페이지에서 URL 을 입력하면
        자동으로 추가됩니다.
      </p>
      <div className="mt-6">
        <OrgRegistry />
      </div>
    </div>
  );
}
