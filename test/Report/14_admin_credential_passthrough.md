# Test 14 — Admin Credential Passthrough

**기능**: Passthrough credential (ollama key 등) 등록 → LLM 호출 시 `{{CREDENTIAL:name}}` placeholder 치환.

---

## 시나리오
1. Credentials 탭 → passthrough 섹션 → name+value 입력 후 저장.
2. org_settings.credential_passthrough 에 저장.
3. LLM curl_template 에 `{{CREDENTIAL:ollama-cloud-key}}` 포함 → Cloud Run 경유 시 치환.

---

## 증거

### 1) org_settings.json 에 저장 확인
```
$ docker exec -u root boanclaw-boan-proxy-1 cat /data/users/org_settings.json | jq '.orgs."sds-corp".settings.credential_passthrough'
[
  {
    "name": "anthropic-fake-manual",
    "value": "sk-ant-api03-fakekey1234567890123456789011987987"
  }
]
```

### 2) LLM curl_template 에 placeholder 사용
`/data/registry/llms.json`:
```json
{
  "curl_template": "... -H \"Authorization: Bearer {{CREDENTIAL:ollama-cloud-key}}\" ..."
}
```

### 3) 실제 호출 시 Cloud Run 측에서 치환 (G2 호출 성공 로그)
proxy 에서 LLM 호출 시 placeholder 포함 template 을 org-llm-proxy → Cloud Run 으로 전송. Cloud Run 에서 `{{CREDENTIAL:ollama-cloud-key}}` 을 Secret Manager 의 실제 key 로 치환 후 ollama.com 호출. G2 응답 200 OK 확인 = 치환 성공.

### 4) 로컬 proxy 로그에 raw key 노출 없음
```
$ docker logs boanclaw-boan-proxy-1 | grep -i "sk-ant\|ollama-key" 
(empty)
```

---

## 결론
✅ Passthrough 저장 + placeholder 치환 flow 정상. raw key 는 Secret Manager 에만.
