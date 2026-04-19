# Test 23 — Admin Computer-Use Agent (Agentic Loop "실행")

**기능**: Secure Input 의 "실행" 버튼. 자연어 명령을 computer-use agent 가 Plan → Execute → Verify → Replan 루프로 수행.

---

## 시나리오
1. "크롬 브라우저 다운로드해줘" 를 실행.
2. Backend `/api/computer-use/agent` 가 NDJSON 스트림 반환:
   - `plan` (sub-goal 5개)
   - step 별 screenshot + thinking + subgoal_done / action / replan / done
3. Planner LLM 이 목표 분해 → Vision LMM 이 다음 action 결정 → Grounding LMM 이 click 좌표 → action 실행 → 화면 변화 검증.

---

## 증거 (NDJSON 이벤트 캡처)

### 1) Planner 결과
```
{"type":"plan","subgoals":[
  "Edge 브라우저가 실행됨",
  "주소창에 구글 크롬 다운로드 페이지 URL이 입력됨",
  "Chrome 다운로드 버튼이 클릭됨",
  "ChromeSetup.exe 설치 파일이 다운로드됨",
  "ChromeSetup.exe 파일이 실행되어 설치가 시작됨"
]}
```

### 2) Sub-goal 1 완료 (Edge 실제 실행)
```
Vision thought:
  OBSERVATION: Microsoft Edge is open and active with a welcome dialog
  SUBGOAL_STATUS: DONE
  
{"type":"subgoal_done","text":"Edge 브라우저가 실행됨"}
```

### 3) Grounding LMM 좌표 변환
```
{"type":"status","text":"🎯 grounding LMM 에 좌표 요청: \"the address bar...\""}
{"type":"status","text":"✓ grounding 결과: ... → (302, 58)"}
{"type":"action","action":{"action":"click","x":302,"y":58}}
```
→ Vision 이 `click_element:DESCRIPTION` 출력 → Grounding 이 실제 픽셀 좌표로 변환.

### 4) STUCK 감지 → Replan
```
Vision: SUBGOAL_STATUS: STUCK
{"type":"status","text":"🔄 재계획 (1/2)..."}
{"type":"plan","subgoals":[... 다른 접근법 ...]}
```
Welcome dialog 때문에 막히자 자동 replan. 새 plan 은 "Start without your data 클릭" 같은 dialog dismiss 단계 포함.

### 5) Fuzzy dedup 정확 동작
같은 영역에 다른 버튼 생기면 dedup 안 함:
- 이전: "Start without your data" @ (385, 727)
- 다음: "Confirm and continue" @ (391, 721) → **화면 변했으니 허용** (fuzzy dedup bypass).

### 6) Chat log (실행 기록)
```
[gcp_exec] 크롬 브라우저 다운로드해줘 : 📋 실행 계획 (5 단계)
  1. Edge 브라우저가 실행됨
  ...
[gcp_exec] 크롬 브라우저 다운로드해줘 : [1] double_click (38, 362)
[gcp_exec] 크롬 브라우저 다운로드해줘 : ✓ [1/5] Edge 브라우저가 실행됨
[gcp_exec] 크롬 브라우저 다운로드해줘 : [2] click (641, 286)
...
```

---

## 관련 구현 + 버그 fix
- **Agentic loop 재구조화** (`admin.go` L4739+): plan[] + subgoalIdx state machine.
- **Planner LLM**: G2 entry (`gemma4:31b-cloud`) 재사용, JSON plan 출력.
- **`click_element` 강제**: grounding 바인딩 시 vision 이 raw `click:X,Y` 출력하면 server-side reject.
- **Desktop icon double-click rule**: vision prompt 에 명시 → Edge 아이콘 정상 실행됨.
- **`looksBroken()` false positive 제거**: "sign in" 같은 generic 단어 삭제, `ctrl+alt+del` 같은 Windows lock 특유 표현만.
- **Fuzzy dedup + screenChanged**: 화면이 변했으면 같은 좌표라도 dedup 건너뜀.

---

## 결론
✅ Agentic loop 구조 완전 동작 (Plan → Execute → Verify → Replan → Give-up).
✅ Vision + Grounding + Planner 3-LLM 협력 확인.
✅ Edge 브라우저 실제 실행, welcome dialog 순차 dismiss 까지 진행 (Chrome 설치까지 끝은 못 갔지만 루프 구조 자체는 정상).
