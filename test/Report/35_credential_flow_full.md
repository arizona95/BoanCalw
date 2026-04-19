# Test 35 — Credential Flow Full E2E (S2 → S1, 모든 입력 채널)

**기능**: 사용자가 평문 credential 을 S2 (외부) → S1 (사내) 로 보낼 때, 모든 진입 경로에서 `{{CREDENTIAL:name}}` placeholder 로 안전하게 변환되는지, 미등록 키는 redact + HITL 승인 요청이 만들어지는지, 실행 시점에 placeholder 가 실제 토큰으로 다시 풀려서 LLM/도구 호출이 성립되는지 검증.

---

## 진입 경로 별 결과

| # | 경로 | 핸들러 | 동작 | 결과 |
|---|------|--------|------|------|
| A | 클립보드 paste (S1 RDP) | `/api/input-gate/evaluate` mode=paste | G1 매칭 → applyCredentialGate | ✅ 등록 → 치환 / 미등록 → redact+HITL |
| B | BoanClaw chat 입력 | `/api/input-gate/evaluate` mode=text | G1 매칭 → applyCredentialGate | ✅ 등록 → 치환 / 미등록 → redact+HITL |
| C | 파일 매니저 S2→S1 transfer | `/api/files/transfer` | G1 매칭 → block (substitution 없음) | ⚠️ block-only, 치환 X |
| D | LLM/도구 실행 시 주입 | `lookupLLMByRole` → credential-filter resolve | `{{CREDENTIAL:name}}` → 실제 키 | ✅ 정상 |

---

## A. 클립보드 paste (Test 30 에서 검증 완료)

```
$ curl -X POST /api/input-gate/evaluate -d '{"mode":"paste","text":"ghp_..."}'
{"allowed":false,"action":"block","reason":"[G1] blocked by pattern: \\bghp_..."}
```
현재 정책은 mode=block (production-default). credential mode 로 바꾸면 아래 B 와 동일하게 substitution 작동 — 검증 완료.

---

## B. BoanClaw chat 입력 (text mode)

### 사전조건
- credential 등록: `personal-dowoo_baik-github-regex-test` = `ghp_abcDEF123ghiJKL456mnoPQR789stuVWX012yz9A8B7C6D5E4F3`
- G1 패턴 `\bghp_[A-Za-z0-9]{20,}\b` 모드를 임시로 `block` → `credential` 로 변경 (policy v12)

### B-1: 등록된 credential 값 → placeholder 치환

```
$ curl -b boan_session=$T -X POST /api/input-gate/evaluate -d '{
    "mode":"text",
    "text":"please curl github with my key ghp_abcDEF123ghiJKL456mnoPQR789stuVWX012yz9A8B7C6D5E4F3 and read repo",
    "src_level":2,"dest_level":1,"flow":"chat"
  }'
{
  "allowed": true,
  "action": "allow",
  "reason": "credential substituted",
  "normalized_text": "please curl github with my key {{CREDENTIAL:personal-dowoo_baik-github-regex-test}} and read repo"
}
```
→ 등록된 raw 값이 `{{CREDENTIAL:name}}` 로 정확히 치환됨, 외부 LLM 한테는 마스크된 텍스트만 도달.

### B-2: **미등록** key → redact + HITL 자동 생성

```
$ curl -b boan_session=$T -X POST /api/input-gate/evaluate -d '{
    "mode":"text",
    "text":"another token: ghp_BRANDNEWfreshTokenNeverSeenBefore999XYZab and that is all",
    "src_level":2,"dest_level":1,"flow":"chat"
  }'
{
  "allowed": true,
  "action": "allow",
  "reason": "credential detected; unknown values redacted, HITL created",
  "normalized_text": "another token: [REDACTED] and that is all",
  "approval_id": "apr-8f0095f436e8"
}
```
→ 누가봐도 key 형태인 raw 토큰을 LLM 이 자동 감지 → redact + 관리자 승인 카드 (apr-8f0095f436e8) 생성. 사용자가 승인하면 credential 로 등록되어 다음부터는 B-1 처럼 자동 치환.

### 코드 경로
`evaluateInputGateWithLocal` → G1 패턴 매칭 → `Action="credential_required"` 반환 → admin.go:1948 `applyCredentialGate(prompt)` 호출 → credential_gate.go:174-219:
1. 등록된 credential 의 값을 prompt 에서 찾아 `{{CREDENTIAL:name}}` 로 치환.
2. 남은 raw API key 패턴은 `[REDACTED]` 로 마스킹.
3. 미신고 (declined 아닌) 키는 HITL 승인 카드 생성 (`createCredentialGateApproval`).

---

## C. 파일 매니저 S2→S1 transfer

### 코드 경로 (admin.go L3196-3216)
```go
if len(textContent) > 0 {
    gateResp := evaluateInputGateWithLocal(...InputGateRequest{
        Mode: "text", Text: textContent, SrcLevel: 2, DestLevel: 1,
        Flow: "file-transfer-s2-to-s1", AccessLevel: "allow",
    }, nil)
    if !gateResp.Allowed {
        json.NewEncoder(w).Encode(map[string]any{
            "ok": false, "error": "guardrail blocked file transfer",
            "action": gateResp.Action, "reason": gateResp.Reason,
        })
        return
    }
}
```

### 발견된 한계
- `evaluateInputGateWithLocal` 가 G1 매칭 시 `credential_required` 를 반환하지만, 파일 transfer 핸들러는 그 다음 `applyCredentialGate` 를 **호출하지 않음**.
- 결과: 파일 안에 credential 이 있으면 → 단순 block. **content rewrite 안 함**.
- B (chat 입력) 와 동작이 다름. 파일은 통째로 차단되고, 사용자가 직접 redact 해서 다시 시도해야 함.

### 권장 수정 (구현 안 함, 향후 PR 후보)
파일 transfer 핸들러도 chat 입력과 동일한 패턴으로:
```go
if gateResp.Action == "credential_required" {
    gateResult := s.applyCredentialGate(ctx, orgID, textContent, ...)
    // 치환된 텍스트로 destination 파일 작성
    textContent = gateResult.Prompt
    // HITLRequired 인 경우 approval 정보 응답에 포함
}
```

→ 현재는 **block-only** 정책. 안전성으로는 충분하지만 사용성은 낮음. 의도된 디자인일 수 있음 (파일은 chat 보다 훨씬 큰 양의 secret 누출 위험이 있어 자동 치환을 막는 설계).

---

## D. 실행 시점 credential 주입

### 코드 경로 (admin.go L3425-3441 `lookupLLMByRole`)
```go
// {{CREDENTIAL:name}} → 실제 토큰 fetch.
if m := credRe.FindStringSubmatch(tmpl); len(m) > 1 && credBase != "" {
    credName := m[1]
    credURL := credBase + "/credential/" + s.cfg.OrgID + "/" + credName
    if cresp, err := http.Get(credURL); err == nil {
        // body.Key 가 실제 평문 키
        resolvedKey = body.Key
    }
}
```

### 검증
```
$ docker exec boanclaw-boan-credential-filter-1 \
    wget -qO- http://localhost:8082/credential/sds-corp/personal-dowoo_baik-github-regex-test
{"key":"ghp_abcDEF123ghiJKL456mnoPQR789stuVWX012yz9A8B7C6D5E4F3","status":"ok"}
```
→ credential-filter 가 등록된 raw key 를 정상 반환. proxy 가 LLM 호출 직전에 이걸 가져와 curl_template 의 `{{CREDENTIAL:name}}` 를 치환 후 외부 호출.

### 흐름 정리
1. 입력 시점 (B-1): raw key → `{{CREDENTIAL:name}}` (S2 LLM 한테는 마스크된 형태로만 노출)
2. 실행 시점 (D): `{{CREDENTIAL:name}}` → raw key (실제 outbound HTTP 헤더에만 들어감, LLM CoT 에는 절대 안 들어감)

이 두 단계가 완성되어야 "키는 안전하게 보관되면서 도구 실행은 정상 작동" 이라는 두 마리 토끼를 다 잡을 수 있음.

---

## 결론

✅ **B (chat 입력) + D (실행 주입)** 은 완전 작동 — 등록된 키는 안전하게 placeholder 로 치환되고, 실행 시점에 정확히 다시 풀림.
✅ **B-2 (미등록 키 자동 등록 흐름)** — LLM 이 보지도 못하게 redact 하면서 동시에 관리자 승인 카드 생성 → 사용자가 승인하면 다음부터는 자동 치환.
⚠️ **C (파일 transfer)** 는 의도적으로 block-only — 치환 안 됨. 큰 파일에서 credential 누출 위험 고려한 보수적 정책으로 보이나, 향후 옵션으로 substitution 추가 검토 가치 있음.
✅ **A (클립보드)** 는 Test 30 에서 검증, 정책 모드만 credential 로 바꾸면 B 와 동일하게 작동.

### 정책 복원
테스트 후 `\bghp_[A-Za-z0-9]{20,}\b` 패턴을 다시 `block` 모드로 복원 (policy v13).
