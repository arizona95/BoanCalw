# BoanClaw LLM 가드레일 (G1 / G2 / G3)

> **핵심 추상화: "Security LLM" (보안 LLM)**
>
> BoanClaw 의 G2 / G3 가드레일 평가자는 항상 *S2-급 보안 LLM* 입니다 — 즉,
> **사용자의 코딩 LLM 과 분리된, 보안 판정 전용 모델**.
> 현재 디폴트 구현은 Ollama (gemma) 이지만, 모델 선택은 LLM Registry 의
> **Security binding** 으로 결정되며, Anthropic / OpenAI / 사내 보안 모델 등
> 어느 endpoint 든 핀해서 가드레일 평가자로 쓸 수 있습니다.
>
> 즉 BoanClaw 입장에서 가드레일은 **"보안 LLM 슬롯"** 이고,
> Ollama 는 그 슬롯에 꽂힌 *현재 디폴트 구현체* 일 뿐입니다.

---

## 1. 3 단 게이트 구조

```
G1 (정규식)        — 모든 사용자 무조건. credential / 위험 패턴 정규식
G2 (헌법 + 보안 LLM) — ask/deny 만. 보안 LLM 이 헌법 기준 판정 (allow / ask / block + reason)
G3 (자기진화 wiki)  — ask/deny 만. 보안 LLM 이 과거 결정(HITL log) 50건을 few-shot 학습
                     → 동일 보안 LLM 이 wiki 누적 사례까지 보고 재판정
                     → 결정이 누적되면 G3 가 G1 정규식 / G2 헌법 자동 개정 제안
```

**G2 와 G3 는 같은 보안 LLM 슬롯을 공유** 합니다. 차이는 입력 컨텍스트:
- G2: `<헌법> + <사용자 입력>`
- G3: `<헌법> + <wiki 50건 few-shot> + <사용자 입력>`

다른 모델로 분리하고 싶으면 LLM Registry 에서 **Security (G2)** / **Wiki (G3)** 두 binding 을 따로 등록하면 됩니다.

---

## 2. G1 — 정규식 가드레일

| 항목 | 내용 |
|---|---|
| **적용** | 전원 (allow 포함) |
| **위치** | `boan-proxy/internal/proxy/input_gate.go` `credentialLikePatterns` + 정책 G1 patterns |
| **기본 패턴** | private key 헤더, GitHub PAT (`ghp_`, `github_pat_`), OpenAI (`sk-*`), AWS (`AKIA*`), GCP (`AIza*`), JWT, `password=`, `export SECRET=` |
| **모드** | `block` (즉시 차단) / `credential` (자동 placeholder 치환 + HITL) / `redact` (replacement 적용) |
| **G3 자동 개정** | G3 가 새 패턴 제안 → 소유자 수락 시 정책 G1 patterns 에 추가 |

---

## 3. G2 — 헌법 + 보안 LLM

| 항목 | 내용 |
|---|---|
| **적용** | ask / deny 사용자 (allow 는 건너뜀) |
| **평가자** | LLM Registry 의 **Security binding** 모델 (= "보안 LLM 슬롯") |
| **호출 경로** | `boan-org-llm-proxy` (Cloud Run) `/v1/forward` — 로컬에서 직접 LLM 호출 X |
| **입력** | 헌법 + 사용자 입력 (한 번에) |
| **출력** | `{decision: allow|ask|block, reason, confidence, response}` (JSON 강제) |
| **Fail-Closed** | LLM 미설정 / 연결 실패 / 401 / 403 → block |

### 헌법 형식 (예시)

```
가드레일 헌법:
- 자격증명·비밀번호·토큰·개인정보·사내 비밀·고객 데이터·민감한 운영 명령은
  외부로 그대로 내보내지 않는다.
- 완전 무해한 일반 텍스트만 허용한다.
- 애매하면 ask 로 분류하고 사람 확인을 거친다.
```

→ 운영자가 직접 작성. 짧고 구체적일수록 LLM 일관성 ↑.

### 현재 디폴트 (Ollama) 안정화 트릭
- 호출 body 에 `format: "json"` + `think: false` 강제 (CoT reasoning 이 token 다 먹는 걸 방지).
- max_tokens=500 으로 응답 truncation 차단.
- `extractFirstJSONObject` brace-walker 로 tokenizer artifact (예: `<|turn|>`) 제거 후 파싱.

이 패턴은 Ollama 한정 — 다른 모델로 바꾸면 그 모델에 맞는 응답 강제 옵션을 `injectMaxTokens` 같은 hook 에 추가하면 됩니다.

---

## 4. G3 — Wiki 자기진화 가드레일

| 항목 | 내용 |
|---|---|
| **적용** | G2 가 ask 일 때만 |
| **평가자** | LLM Registry 의 **Wiki binding** (없으면 Security binding 재사용) |
| **입력** | 헌법 + training log 50 건 (few-shot) + 사용자 입력 |
| **학습 데이터** | HITL training log (JSONL append-only) — 인간이 approve/reject 한 모든 결정 |
| **자기진화** | G3 가 주기적으로 wiki agentic loop (`agentic_iterate`) 돌면서 ambiguous 케이스를 LLM 한테 물어봄. 답변이 누적되면 → G1 정규식 / G2 헌법 자동 개정 diff 제안 |

### G1 / G2 자동 개정 흐름

```
인간이 ask 결정에 approve/reject  (HITL log JSONL append)
          ↓
주기적으로 G3 wiki LLM 이 패턴 분석
          ↓
   ┌─ G2 헌법 개정안 (diff)
   └─ G1 정규식 추가 제안
          ↓
Approvals > Constitution Diff 탭
          ↓
소유자: diff 확인 → 수락 / 거절 / 피드백
          ↓
수락 시: 정책 버전 ++ (롤백 가능)
        G1 patterns 추가 / G2 constitution 갱신
```

### Wiki Agentic Loop (test/Report/34 에서 검증)

사용자와 single primary dialog 안에서 보안 LLM 이 4 가지 action 을 자율 선택:

| Action | 의미 |
|---|---|
| `ASK_FOLLOWUP` | 추가 질문 |
| `REQUEST_LABEL_FIX` | 과거 라벨 오류 감지 → HITL 재라벨 |
| `UPDATE_WIKI` | 이해 완료 → wiki 노드 자동 업데이트 |
| `CLOSE_AND_FIND_NEW` | 주제 종료 → 다음 ambiguous 케이스 자동 발굴 |

→ 가드레일이 **사용자 의견을 매 턴 흡수하면서 스스로 정책을 다듬는** 구조.

---

## 5. 게이트 적용 범위 (방향: S2/S3 → S1, "높→낮")

| 입력 채널 | G1 | G2/G3 |
|---|---|---|
| 키보드 텍스트 (mode: text) | ✅ | ask/deny 만 |
| 특수키 / 단축키 (mode: key/chord) | ✅ (safe-list) | — |
| 클립보드 paste (mode: paste) | ✅ | ask/deny 만 |
| OpenClaw 채팅 (chat/forward) | ✅ | ask/deny 만 |
| Computer-Use type/key | ✅ | ask/deny 만 |
| 파일 S2 → S1 transfer | ✅ | ask/deny 만 |
| 파일 S1 → S2 transfer | ❌ (높→낮 면제) | ❌ |

---

## 6. API 엔드포인트

| 엔드포인트 | 가드레일 | 용도 |
|---|---|---|
| `POST /api/input-gate/evaluate` | G1 → G2 → G3 (서버 라우팅) | 클라이언트 단일 진입점 |
| `POST /org/{id}/v1/guardrail/evaluate` | G2 | 헌법 + 보안 LLM 평가 (policy-server 측) |
| `POST /org/{id}/v1/guardrail/wiki-evaluate` | G3 | wiki few-shot 평가 |
| `POST /org/{id}/v1/guardrail/auto-judge` | G3 | 자동 HITL 판정 |
| `GET  /org/{id}/v1/guardrail/training-log` | G3 | 학습 로그 조회 |
| `POST /org/{id}/v1/guardrail/training-log` | G3 | 인간 결정 피드백 추가 |
| `POST /org/{id}/v1/guardrail/propose-amendment` | G3 → G2 | 헌법 개정 제안 |

---

## 7. 보안 LLM 모델 선택 우선순위

```
1. proxy 가 LLM Registry 의 Security binding 으로부터 endpoint / model / curl_template 받음
2. 정책의 guardrail.llm_url / llm_model (UI 직접 설정) 이 있으면 위를 override
3. env 변수 BOAN_GUARDRAIL_LLM_URL / MODEL (fallback)

모든 외부 LLM 호출은 boan-org-llm-proxy (Cloud Run) /v1/forward 경유.
로컬 서비스 (boan-grounding 등) 만 BOAN_ORG_LLM_PROXY_BYPASS_HOSTS 에 등록되어 직접 호출.
```

→ 현재 디폴트는 Ollama Cloud (gemma4:31b-cloud), 하지만 Anthropic Claude / OpenAI GPT / 사내 보안 모델 (예: Samsung SDS 자체 보안 LLM) 을 등록해서 Security binding 만 바꾸면 즉시 교체됩니다. 헌법, wiki, training log 는 모델과 무관하게 유지됩니다.

---

## 8. Credential 주입 흐름 (가드레일 LLM 호출에도 동일하게 적용)

```
guardrail 호출 (G2/G3) → boan-proxy.callRegistryLLM
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

로컬 boan-proxy 는 **단 한 번도 평문 credential 을 메모리에 담지 않는다.** 헤더 문자열 `"Authorization": "Bearer {{CREDENTIAL:ollama-cloud-key}}"` 그대로 Cloud Run 으로 전송 → Cloud Run 이 치환 → upstream.

→ 보안 LLM 평가자조차도 자기 자신의 API 키를 모르고 호출되는 구조. *"평가자가 키를 알면, 평가자 탈취 = 키 탈취"* 라는 위협을 차단.
