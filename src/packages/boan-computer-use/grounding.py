"""
OCR / Grounding — open-computer-use 의 grounding.py 를 참고해 Guacamole 용으로 작성.
스크린샷 + 자연어 쿼리 → (x, y) 픽셀 좌표 반환.
OS-Atlas (HuggingFace Gradio) 또는 단순 fallback 제공.
"""
from __future__ import annotations

import re
from PIL import ImageDraw


def draw_big_dot(image, coordinates, color="red", radius=12):
    """open-computer-use 의 grounding.py 와 동일 — 빨간 점으로 클릭 위치 표시."""
    draw = ImageDraw.Draw(image)
    x, y = coordinates
    bbox = [x - radius, y - radius, x + radius, y + radius]
    draw.ellipse(bbox, fill=color, outline=color)
    return image


def extract_bbox_midpoint(bbox_response: str):
    """
    OS-Atlas 응답에서 <|box_start|>...<|box_end|> 포맷 좌표를 추출.
    open-computer-use 의 grounding.py::extract_bbox_midpoint 와 동일 로직.
    """
    match = re.search(r"<\|box_start\|>(.*?)<\|box_end\|>", bbox_response)
    inner = match.group(1) if match else bbox_response
    numbers = [float(n) for n in re.findall(r"\d+\.\d+|\d+", inner)]
    if len(numbers) == 2:
        return int(numbers[0]), int(numbers[1])
    elif len(numbers) >= 4:
        return int((numbers[0] + numbers[2]) / 2), int((numbers[1] + numbers[3]) / 2)
    return None


async def ground_query(screenshot_bytes: bytes, query: str, image_width: int, image_height: int):
    """
    자연어 쿼리로 스크린샷에서 좌표 추출.
    OS-Atlas Gradio API 호출 (HuggingFace Space).
    실패 시 None 반환 — 호출측에서 직접 좌표 지정으로 fallback.
    """
    try:
        import httpx, base64

        encoded = base64.b64encode(screenshot_bytes).decode()
        async with httpx.AsyncClient(timeout=30.0) as client:
            # OS-Atlas HuggingFace Space API
            resp = await client.post(
                "https://maxiw-os-atlas.hf.space/gradio_api/call/run",
                json={
                    "data": [
                        {"image": f"data:image/png;base64,{encoded}", "type": "base64"},
                        f"In the screenshot, find and click: {query}",
                    ]
                },
            )
            if resp.status_code != 200:
                return None
            event_id = resp.json().get("event_id")
            if not event_id:
                return None

            result_resp = await client.get(
                f"https://maxiw-os-atlas.hf.space/gradio_api/call/run/{event_id}",
                timeout=30.0,
            )
            text = result_resp.text
            # Parse SSE: find data: line
            for line in text.splitlines():
                if line.startswith("data:"):
                    import json
                    data = json.loads(line[5:].strip())
                    if isinstance(data, list) and data:
                        coords = extract_bbox_midpoint(str(data[0]))
                        if coords:
                            # OS-Atlas returns normalized 0-1000 coords
                            x = int(coords[0] / 1000 * image_width)
                            y = int(coords[1] / 1000 * image_height)
                            return x, y
    except Exception:
        pass
    return None
