# BoanClaw Grounding Server (GCP)

S1 가드레일 외부에 떠 있는 **GUI element grounding 전용 서버**.
자연어 (예: `"the X close button on Notepad"`) → 픽셀 좌표 `(x, y)` 변환만 담당.

BoanClaw 본체와는 **OpenAI-호환 vision endpoint** 로만 통신하며, LLM Registry 의
**GUI** 역할 슬롯에 등록해서 언제든 다른 grounding 모델로 교체할 수 있다.

## 아키텍처

```
[boan-proxy /api/computer-use/agent]
    │   click_element:DESCRIPTION
    ▼
[forwardGroundingLLM]
    │   OpenAI vision call (image + prompt)
    ▼
[GCP VM: this server]
    │   vLLM (OpenAI-compatible /v1/chat/completions)
    ▼
[MAI-UI-8B] ── 또는 다른 grounding 모델 ──
```

LLM Registry 화면에서 이 서버 endpoint 를 등록하고 **GUI** 역할 체크박스만 켜면 끝.
다른 모델 (UGround-V1-2B, OS-Atlas-Base-7B, Phi-Ground 등) 으로 교체하려면 vLLM 의
`--model` 만 바꿔서 재시작하면 됨 — 본체 코드 수정 불필요.

## 권장 인스턴스 (C안 — L4 GPU spot)

| 항목 | 값 |
|---|---|
| Machine type | `g2-standard-4` |
| GPU | NVIDIA L4 (24 GB VRAM) |
| Region | `us-central1` (또는 `asia-northeast3` for KR latency) |
| Pricing (spot) | ~$0.21/hr (~$155/month always-on) |
| Pricing (on-demand) | ~$0.71/hr (~$515/month always-on) |
| Disk | 100 GB pd-balanced |
| Image | Deep Learning VM (Debian 11, CUDA 12.x) |

L4 24GB 면 MAI-UI-8B BF16 도 충분히 들어감 (~16GB) + KV cache 여유.
2B 모델은 INT4 로 ~2GB → 동시 호출도 가능.

## 부트스트랩 (한 줄)

GCP VM (Deep Learning Image, CUDA 사전 설치) 안에서:

```bash
sudo bash bootstrap.sh
```

이 스크립트가 하는 일:
1. Docker + NVIDIA Container Toolkit 확인 (없으면 설치)
2. `MODEL` 환경변수의 모델을 vLLM 으로 띄움 (기본: `Tongyi-MAI/MAI-UI-8B`)
3. 포트 8000 에 OpenAI-호환 API 노출
4. systemd 유닛 등록 (재부팅 자동 복구)

## 모델 교체

다른 grounding 모델로 바꾸려면:

```bash
sudo MODEL=osunlp/UGround-V1-2B bash bootstrap.sh    # 더 가벼움 (2B)
sudo MODEL=tencent/POINTS-GUI-G  bash bootstrap.sh    # 다른 SOTA 후보
sudo MODEL=OS-Copilot/OS-Atlas-Base-7B bash bootstrap.sh
```

스크립트가 컨테이너만 재시작 — endpoint URL/포트는 그대로라 본체 LLM Registry
쪽 수정 불필요.

## BoanClaw LLM Registry 등록

1. Admin Console → **LLM Registry** 탭 → **모델 등록**
2. **이미지 모델** 모드 선택
3. curl 예시:

```bash
curl -X POST https://YOUR-GCP-IP:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "MAI-UI-8B",
    "max_tokens": 64,
    "messages": [{
      "role": "user",
      "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,{{IMAGE_BASE64}}"}},
        {"type": "text", "text": "{{MESSAGE}}"}
      ]
    }]
  }'
```

4. 등록 후 **역할 설정** 탭 → 등록된 모델의 **GUI** 컬럼 + 버튼 클릭
5. 끝. 다음 `/gcp_exec` 부터 자동으로 grounding LMM 사용

## 보안

- VM 의 외부 IP 는 BoanClaw 본체 (S2) 의 IP 만 화이트리스트
- 또는 IAP TCP forwarding / VPC peering 으로 외부 노출 없이 연결
- vLLM 에 API key 헤더 추가하려면 `--api-key sk-xxx` 옵션 사용
  → BoanClaw credential filter 가 자동으로 토큰을 감춤

## 제거

```bash
sudo systemctl stop boan-grounding
sudo systemctl disable boan-grounding
sudo rm /etc/systemd/system/boan-grounding.service
docker rm -f boan-grounding 2>/dev/null
```
