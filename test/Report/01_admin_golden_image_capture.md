# Test 01 — Admin Golden Image Capture

**기능**: 관리자 Users 탭 상단 🧊 "내 VM 을 골든 이미지로 굽기" 버튼. 관리자가 자기 S1 PC 를 이미징하면, 신규 사용자 VM 이 그 이미지 그대로 프로비저닝된다.

---

## 시나리오
1. 관리자 (`genaisec.ssc@samsung.com`) 로그인 → Authorization > Users 탭.
2. 상단 indigo 패널의 "🧊 내 VM 굽기" 클릭.
3. Confirm 다이얼로그 "계속" → `/api/admin/workstation/image` POST.
4. Backend: owner VM STOP → GCP Custom Image 생성 (약 10-20분) → VM START.
5. `org_settings.golden_image_uri` 에 저장.
6. 신규 사용자 승인 → 그 VM 의 boot disk 가 golden image URI 로 생성.

---

## 증거 — 실제 cloud/backend 검증

### 1) GCP Custom Image 생성 확인
```
$ gcloud compute images list --project=ai-security-test-473701 --filter="name~boan-golden"
NAME                                          STATUS  CREATION_TIMESTAMP
boan-golden-boan-win-genaisec-ssc-1776576337  READY   2026-04-18T22:26:08.454-07:00
```
→ GCP 에 실제 custom image 가 `READY` 상태로 존재.

### 2) org_settings 에 URI 저장 확인
```
$ docker exec -u root boanclaw-boan-proxy-1 cat /data/users/org_settings.json
{
  "orgs": {
    "sds-corp": {
      "settings": {
        "golden_image_uri": "projects/ai-security-test-473701/global/images/boan-golden-boan-win-genaisec-ssc-1776576337",
        "golden_image_captured_at": "2026-04-19T05:29:17Z",
        "golden_image_source_instance": "projects/.../boan-win-genaisec-ssc"
      }
    }
  }
}
```
→ proxy 의 org_settings 파일에 정확한 URI + 타임스탬프 + 원본 인스턴스 저장.

### 3) 신규 사용자 VM 이 golden image 로 프로비저닝 확인
```
$ gcloud compute disks describe boan-win-dowoo-baik --zone=asia-northeast3-a \
    --format='value(sourceImage)'
https://www.googleapis.com/compute/v1/projects/ai-security-test-473701/global/images/boan-golden-boan-win-genaisec-ssc-1776576337
```
→ 승인된 신규 사용자 `dowoo.baik` 의 VM disk 가 **방금 찍은 golden image URI 와 완전 일치**.

### 4) 그 VM 에 로그인해서 Windows desktop 실제 렌더링
- Guacamole 로 `boan-win-dowoo-baik` RDP 접속
- Windows Server 2022 desktop + Server Manager 정상 표시 (screenshot 첨부 가능)
- 즉 golden image 가 정상적으로 부팅되고, user profile/앱 설정이 복원됨

---

## 발견한 버그 및 수정

### Bug A — startup script 에서 `Remote Desktop Users` 그룹 누락
**증상**: Golden image 로부터 만든 VM 에 RDP 접속 시 "The remote desktop server has denied access to this connection" 발생. Administrators 그룹에만 추가하고 있어서 기존 image 에서 복원된 user 의 group membership 이 꼬임.

**Fix** (`gcp.go`, `startupScript()`):
```go
foreach ($grp in @("Administrators","Remote Desktop Users")) {
  Add-LocalGroupMember -Group $grp -Member "%s" -ErrorAction SilentlyContinue
}
# NLA 비활성 (Guacamole 호환성)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0
```
또한 `C:\ProgramData\boanclaw-startup.log` 에 실행 로그 남기도록 추가 → 차후 디버깅 용이.

### Bug B — `machine_id` 필드가 로컬 UI 의 "바인딩 PC" 컬럼에 안 나옴
**증상**: policy-server 는 사용자에 대해 `machine_id` 로 TOFU binding 을 저장하는데 (owner 는 `registered_ip` 사용, 레거시 호환), 로컬 proxy 의 `/api/admin/users` overlay 는 `registered_ip` 만 읽어서 `machine_id` 만 있는 user 는 UI 에 `-` 로 표시됨.

**Fix** (`admin.go` L2599):
```go
effectiveIP := ru.RegisteredIP
if effectiveIP == "" {
    effectiveIP = ru.MachineID
}
```

---

## 결론
✅ Golden image 기능 정상 작동. UI 클릭 → GCP image 생성 → org_settings 저장 → 신규 VM boot disk = golden image → RDP 접속 → Windows desktop 렌더링까지 모두 증거 기반 검증됨.

검증 완료 시각: 2026-04-19 (KST).
