# BoanClaw LLM 가드레일 (G1/G2/G3)

## 구조

```
G1 (정규식)      모든 사용자 무조건. credential/위험 패턴 정규식
G2 (헌법+LLM)   ask/deny만. 보안 LLM이 헌법 기준 판정. (위험도, 답변) 한번에 리턴
G3 (wiki 적응형) ask/deny만. 과거 결정 학습. G1/G2 자동 개정 제안
```

## G1: 정규식 가드레일

- **적용**: 전원 (allow 포함)
- **위치**: input_gate.go `credentialLikePatterns`
- **패턴**: private key, API token (sk-*, ghp_*, AKIA*), JWT, password=, export SECRET=
- **판정**: credential_required (즉시 차단)
- **G3에 의한 개정**: G3이 새 정규식 패턴을 제안 → 소유자 수락 시 G1 규칙 추가

## G2: 헌법 + LLM 가드레일

- **적용**: ask/deny 사용자만 (allow는 건너뜀)
- **평가자**: LLM Registry의 Security binding 모델
- **입력**: 헌법 + 사용자 질문을 한번에 전달 (분리 호출 아님)
- **출력**: `{decision: allow|ask|block, reason, confidence, response}`
- **LLM 경유**: boan-org-llm-proxy (Cloud Run, `POST /v1/forward`) — 로컬 호스트에서 직접 LLM 에 요청하지 않는다. `{{CREDENTIAL:role}}` placeholder 가 치환되는 것도 여기서.
- **Fail-Closed**: LLM 설정 + 연결 실패 → block. Cloud Run 미응답 / 401 / 403 도 block.

### 헌법 형식
```
가드레일 헌법: 자격증명, 비밀번호, 토큰, 개인정보, 사내 비밀, 고객 데이터,
민감한 운영 명령은 외부로 그대로 내보내지 않는다. 완전 무해한 일반 텍스트만 허용한다.
애매하면 ask로 분류하고 사람 확인을 거친다.
```

## G3: Wiki 적응형 가드레일

- **적용**: G2가 ask일 때만
- **평가자**: Wiki LLM (별도 모델 가능)
- **입력**: 헌법 + training log 50건 (few-shot) + 사용자 질문
- **학습 데이터**: HITL training log (JSONL, append-only)
- **자기진화**: 인간 결정(approve/reject)이 누적 → 판단 정확도 향상

### G3의 G1/G2 자동 개정

```
Training Log 누적 (인간 결정)
    ↓
G3 Wiki LLM: 패턴 분석 → G2 헌법 개정안 (diff) 생성
    ↓                  → G1 정규식 추가 제안
    ↓
Approvals > Constitution Diff 탭
    ↓
소유자: diff 확인 → 수락/거절/피드백
    ↓
수락 시: G2 헌법 업데이트 (정책 버전 증가, 롤백 가능)
         G1 정규식 추가 (패턴 등록)
```

## 엔드포인트

| 엔드포인트 | 가드레일 | 용도 |
|-----------|---------|------|
| `POST /org/{id}/v1/guardrail/evaluate` | G2 | 헌법+LLM 평가 |
| `POST /org/{id}/v1/guardrail/wiki-evaluate` | G3 | wiki 적응형 평가 |
| `POST /org/{id}/v1/guardrail/auto-judge` | G3 | 자동 HITL 판정 |
| `GET /org/{id}/v1/guardrail/training-log` | G3 | 학습 로그 조회 |
| `POST /org/{id}/v1/guardrail/training-log` | G3 | 인간 결정 피드백 |
| `POST /org/{id}/v1/guardrail/propose-amendment` | G3→G2 | 헌법 개정 제안 |

## LLM 선택 우선순위

```
1. proxy가 LLM Registry에서 Security binding 모델 정보를 전달
2. 정책의 guardrail.llm_url/llm_model (UI에서 직접 설정)
3. env 변수 BOAN_GUARDRAIL_LLM_URL/MODEL (fallback)

모든 외부 LLM 호출은 boan-org-llm-proxy (Cloud Run, BOAN_ORG_LLM_PROXY_URL) 경유.
로컬 서비스 (boan-grounding 등) 는 BOAN_ORG_LLM_PROXY_BYPASS_HOSTS 에 등록되어 직접 호출.
```

## Credential 주입 흐름 (P1-P4 통합)

```
guardrail 호출 (G2) → boan-proxy.callRegistryLLM
  → curl_template headers/body 에 {{CREDENTIAL:role}} placeholder 유지
  → dispatchLLMRequest(endpoint, headers, body)
  → forwardViaOrgProxy: envelope 에 org_id + device JWT 포함
  → POST https://boan-org-llm-proxy-{org}-*.a.run.app/v1/forward
      ├─ bearer 인증 + JWT 검증 + rate limit
      ├─ credresolver.ResolveAll: placeholder → credential-gate /v1/resolve → 평문
      ├─ http.Do(upstream)  ← Cloud Run 이 유일한 egress
      └─ credresolver.ScrubEchoes: response body 에서 credential 문자열 [REDACTED]
  → 응답 반환
```

로컬 boan-proxy 는 **단 한 번도 평문 credential 을 메모리에 담지 않는다**. 헤더 문자열 `"Authorization": "Bearer {{CREDENTIAL:ollama-cloud-key}}"` 그대로 Cloud Run 에 전송 → Cloud Run 에서 치환 → upstream.
