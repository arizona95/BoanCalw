# Test 18 — Admin Wiki Graph (G3 Folder Wiki)

**기능**: 조직의 G3 wiki (과거 decision history + 분류 규칙) 를 노드 그래프로 시각화.

## 증거
### 1) `/api/wiki-graph/nodes` — 노드 목록
```
$ curl /api/wiki-graph/nodes
[{
  "id": "n_1776086350063069104",
  "path": "/security/pii",
  "definition": "위험: 내부/대외비 정보",
  "content": "IDS 시그니처 자체 개발 160종\n- 추가 예시 ..."
}, ...]
```

### 2) `/api/admin/wiki` — 학습 레코드 (entries)
```
$ curl /api/admin/wiki
{
  "entries": [
    {"decision":"reject","flagged_reason":"G1 credential","text":"sk-ant-api03-FAKEKEY1","reasoning":"API key must be redacted","source":"human",...},
    ...
  ]
}
```

## 구조
- **Nodes**: 조직이 정의한 분류 (예: `/security/pii`) + 예시 content.
- **Entries**: 과거 human/LLM decision 누적 → G3 WikiEvaluate 가 참고.
- **Compile** (`/api/admin/wiki/compile`): entries 를 nodes 로 승격 / 헌법 개정 제안.

## 결론
✅ Wiki graph + entries 저장 + API 정상 응답. UI 는 이 데이터로 그래프 렌더링.
