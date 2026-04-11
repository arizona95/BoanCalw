# Computer Use 실행 흐름

이 문서는 현재 코드 기준으로 `computer-use` 관련 실행 흐름만 따로 정리한 것이다.

범위는 두 가지다.

1. 사용자가 `내 작업 컴퓨터(MyGCP)` 화면에서 직접 GCP Windows를 조작하는 흐름
2. 에이전트가 `computer-use` 툴을 통해 GCP Windows를 자동 조작하는 흐름

---

## 1. 관련 컴포넌트

### S3 UI / Control Surface

- `boan-admin-console`
  - [`MyGCP.tsx`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-admin-console/src/pages/MyGCP.tsx)
  - [`MyBoanClaw.tsx`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-admin-console/src/pages/MyBoanClaw.tsx)

### S2 Enforcement / Proxy

- `boan-proxy`
  - [`admin.go`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-proxy/internal/proxy/admin.go)
  - [`input_gate.go`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-proxy/internal/proxy/input_gate.go)
  - [`guac/client.go`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-proxy/internal/guac/client.go)

### S2 Computer Use Runtime

- `boan-agent computer-use tool`
  - [`computer-use.ts`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-agent/src/commands/computer-use.ts)
- `boan-computer-use`
  - [`main.py`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-computer-use/main.py)
  - `guac_agent.py`

### S1 Target

- GCP Windows Workstation
- Guacamole를 통해 접속되는 원격 Windows 세션

---

## 2. 큰 구조

```text
사용자 / 에이전트
  -> boan-admin-console 또는 boan-agent
  -> boan-proxy (/api/workstation/*, /api/input-gate/*, /api/computer-use/*)
  -> boan-guacamole / guacd
  -> GCP Windows Workstation
```

단, 실제 경로는 둘로 갈라진다.

1. 수동 조작 경로
   - `MyGCP` 화면
   - 키보드/클립보드/마우스 분기 존재
   - `Input Gate`가 붙는 경로가 있음

2. 자동 조작 경로
   - `boan-agent`의 `computer-use` 툴
   - `boan-proxy /api/computer-use/*`
   - `boan-computer-use`
   - Playwright + Guacamole로 원격 조작

---

## 3. 수동 조작 흐름: `MyGCP`

### 3-1. 작업 컴퓨터 세션 열기

1. 사용자가 `/my-gcp` 진입
2. [`MyGCP.tsx`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-admin-console/src/pages/MyGCP.tsx) 에서 `workstationApi.me()` 호출
3. `boan-proxy`의 `/api/workstation/me` 처리
4. `userstore`에서 사용자 workstation 조회
5. 필요 시 `EnsureWorkstation(...)` 수행
6. `guac.Client.EnsureSessionURL(...)`로 Guacamole 세션 URL 생성
7. 응답에 `web_desktop_url` 포함
8. `MyGCP`가 해당 URL을 iframe으로 로드

이 단계에서 원격 Windows 화면은 Guacamole iframe으로 보인다.

### 3-2. 마우스 경로

마우스는 현재 `Input Gate`를 타지 않는다.

흐름:

1. 사용자가 `MyGCP` 원격 화면 위 오버레이에서 마우스 이동/클릭/휠
2. `MyGCP.tsx`의 overlay가 pointer/wheel 이벤트를 받음
3. 이벤트를 iframe 내부 Guacamole DOM으로 best-effort forwarding
4. Guacamole가 원격 Windows에 전달

즉 마우스는 현재:

```text
S3 mouse event -> S3 UI overlay -> Guacamole DOM -> S1 Windows
```

현재 구현상 마우스는 `Input Gate` 평가를 받지 않는다.

### 3-3. 키보드 경로

키보드는 현재 `MyGCP` 하단 `BoanClaw Input` textarea만 입력 지점이다.

흐름:

1. 사용자가 하단 textarea에 입력
2. 입력은 모드별로 분기
3. `inputGateApi.evaluate()` 호출
4. 허용 시 원격에 synthetic key/text로 주입

모드별 분기:

- `text`
  - 일반 문자열
  - `src_level=3`, `dest_level=1`
  - `Input Gate` + 필요 시 `Critical Guardrail`
- `paste`
  - 브라우저 클립보드에서 붙여넣기
  - `src_level=3`, `dest_level=1`
  - `Input Gate` + 필요 시 `Critical Guardrail`
- `key`
  - 특수키
  - `Tab`, `Enter`, 방향키, `F1~F12` 등 일부만 허용
- `chord`
  - `Ctrl+A`, `Ctrl+C` 같은 조합키
  - 일부 안전 조합만 허용
- `clipboard_sync`
  - 원격 클립보드가 로컬 브라우저 클립보드로 올라오는 관찰 경로
  - 현재는 `allow` + observe only

### 3-4. `Input Gate` 내부 판단

[`input_gate.go`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-proxy/internal/proxy/input_gate.go) 기준 순서는 다음과 같다.

#### `text` / `paste`

1. 빈 값 차단
2. credential-like 패턴 검사
   - `password=...`
   - `token=...`
   - `export SECRET=...`
   - JWT, private key 등
3. `dest_level < src_level`이면 `Critical Guardrail` 평가
4. 그 뒤 DLP 검사
5. 결과:
   - `allow`
   - `hitl_required`
   - `credential_required`
   - `redact_required`
   - `block`

즉 현재 수동 입력의 핵심 흐름은:

```text
S3 입력
  -> Input Gate
  -> credential-like 검사
  -> Critical Guardrail (3 -> 1 하향 흐름일 때)
  -> DLP
  -> 허용 시 원격 주입
```

#### `key`

- 허용된 immediate key만 통과
- 나머지는 block

#### `chord`

- 허용된 safe chord만 통과
- 현재 기본 허용:
  - `Ctrl+A`
  - `Ctrl+C`
  - `Ctrl+X`
  - `Ctrl+Z`
  - `Ctrl+Y`
  - `Meta+A/C/X/Z/Y`

#### `clipboard_sync`

- 현재는 차단 목적이 아니라 관찰 목적
- `S1 -> S3` 상향 흐름으로 보고 통과

---

## 4. 클립보드 흐름

현재 코드는 클립보드를 두 종류로 본다.

1. `S1 GCP clipboard`
2. `S3 browser clipboard`

### 4-1. GCP 내부 복사: `S1 -> S3`

흐름:

1. 원격 화면에서 `Ctrl+C`
2. `MyGCP`가 원격에 `Ctrl+C` chord 전달
3. Guacamole `clipboardService` / `guacClipboard` 이벤트로 원격 clipboard 감지
4. `handleCapturedRemoteClipboard(...)`
5. `/api/input-gate/evaluate`를 `mode=clipboard_sync`, `src=1`, `dest=3`로 호출
6. `clipboard_sync observed`로 allow
7. 로컬 브라우저 clipboard 쓰기 시도

즉 현재 설계상:

```text
S1 clipboard -> S3 browser clipboard
```

이 흐름은 감시 대상일 수는 있지만, 현재는 차단하지 않는다.

### 4-2. 브라우저 붙여넣기: `S3 -> S1`

흐름:

1. 사용자가 `Ctrl+V` 또는 paste
2. `navigator.clipboard.readText()` 또는 paste event에서 로컬 clipboard 읽기
3. `Input Gate`에 `mode=paste`, `src=3`, `dest=1`로 전달
4. 허용 시 원격 주입

즉:

```text
S3 browser clipboard -> Input Gate -> S1 Windows
```

### 4-3. 최근 GCP 복사본 재붙여넣기: `S1 -> S1`

현재 `MyGCP.tsx`는 특수 케이스를 둔다.

- 최근 원격 복사본(`capturedRemoteClipboard`)과
- 현재 브라우저 clipboard 값이 같으면

이를 `S1 -> S1` 재붙여넣기로 간주하고 게이트 없이 원격에 주입한다.

즉 현재 구현은:

```text
if systemClipboard == lastCapturedRemoteClipboard:
    gate bypass
else:
    Input Gate
```

이 분기 덕분에:

- `GCP에서 Ctrl+C`
- 곧바로 `GCP에 Ctrl+V`

같은 동작은 게이트를 다시 타지 않도록 의도되어 있다.

---

## 5. 자동 조작 흐름: `computer-use`

이 경로는 `MyGCP` 수동 입력 경로와 별개다.

### 5-1. OpenClaw / Agent 툴에서 호출

[`computer-use.ts`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-agent/src/commands/computer-use.ts) 에서 다음 툴을 제공한다.

- `computerScreenshotTool`
- `computerClickTool`
- `computerDoubleClickTool`
- `computerRightClickTool`
- `computerScrollTool`
- `computerTypeTool`
- `computerKeyTool`
- `computerMoveTool`
- `computerClickQueryTool`

이 툴들은 모두:

```text
POST /api/computer-use/{action}
```

으로 간다.

### 5-2. boan-proxy `/api/computer-use/*`

[`admin.go`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-proxy/internal/proxy/admin.go) 의 `/api/computer-use/*`는 단순 프록시다.

동작:

1. action 추출
2. body JSON 읽기
3. `web_desktop_url`이 없으면 사용자 workstation에서 자동 주입
4. 상대 경로 `/remote/...`이면 내부 Guacamole URL로 변환
5. `boan-computer-use` 서비스로 그대로 POST

즉 현재 구조는:

```text
Agent tool
  -> boan-proxy /api/computer-use/*
  -> boan-computer-use
  -> Guacamole session
  -> Windows
```

### 5-3. boan-computer-use

[`main.py`](/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw/src/packages/boan-computer-use/main.py) 는 FastAPI 서비스다.

주요 엔드포인트:

- `POST /screenshot`
- `POST /click`
- `POST /double_click`
- `POST /right_click`
- `POST /move`
- `POST /scroll`
- `POST /type`
- `POST /key`
- `POST /click_query`

이 서비스는 내부적으로 `guac_agent.py`를 호출해 Playwright로 Guacamole 화면을 자동 조작한다.

즉:

```text
boan-computer-use
  -> Playwright
  -> Guacamole Web UI
  -> RDP 세션
  -> Windows
```

---

## 6. 현재 기준으로 게이트가 붙는 곳 / 안 붙는 곳

### 붙는 곳

- `MyGCP` 하단 textarea의 일반 텍스트 입력
- `MyGCP` 로컬 clipboard 붙여넣기
- `MyGCP` 특수키 / 조합키 일부
- `Critical Guardrail`
  - `src > dest`인 수동 입력/붙여넣기 경로

### 안 붙는 곳

- `MyGCP` 마우스 이동/클릭/휠
- `MyGCP`의 최근 원격 복사본 재붙여넣기(`S1 -> S1`)
- `computer-use` 자동조작 API 전체
  - `/api/computer-use/click`
  - `/api/computer-use/type`
  - `/api/computer-use/key`
  - 등

즉 현재 `computer-use` 자동조작 경로는:

```text
Agent -> boan-proxy -> boan-computer-use -> Windows
```

로 지나가며, `Input Gate`를 타지 않는다.

---

## 7. 현재 구현 기준 해석

### 수동 경로

수동 경로는 다음 철학에 가깝다.

- 키보드/붙여넣기 같은 `S3 -> S1` 흐름은 감시
- `Input Gate` + `Critical Guardrail` 적용
- 원격 clipboard 동기화 `S1 -> S3`는 현재 관찰 중심

### 자동 `computer-use` 경로

자동 경로는 아직 다음 특징을 가진다.

- `boan-proxy`가 단순 reverse proxy 역할
- `boan-computer-use`가 실제 조작을 수행
- 별도의 `Input Gate`, `Critical Guardrail`, `Credential Gate` 분기 없음

즉 현재 자동조작 경로는 기능적으로는 완성되어 있지만, 보안 게이트 관점에서는 수동 경로보다 약하다.

---

## 8. 앞으로 맞춰야 할 목표 흐름

현재 철학에 맞는 최종 목표는 이렇다.

### 수동 조작

```text
사람 입력(S3)
  -> Input Gate
  -> 필요 시 Critical Guardrail
  -> 허용 시 Windows(S1)
```

### 자동 computer-use

```text
Agent action(S2)
  -> computer-use action gate
  -> 필요 시 Critical Guardrail
  -> 허용 시 boan-computer-use
  -> Guacamole
  -> Windows(S1)
```

즉 장기적으로는 `computer-use` 자동조작도 수동 입력처럼 별도 gate를 하나 더 타는 구조가 되어야 한다.

---

## 9. 한 줄 요약

현재 `computer-use` 실행 흐름은 두 갈래다.

- 수동 `MyGCP` 조작은 `Input Gate` 중심으로 감시된다.
- 자동 `computer-use` 조작은 `boan-proxy -> boan-computer-use` 프록시 경로로 바로 가며, 아직 같은 수준의 게이트를 타지 않는다.
