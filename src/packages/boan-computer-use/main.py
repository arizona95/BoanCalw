"""
boan-computer-use FastAPI 서비스.
open-computer-use 의 SandboxAgent 툴셋을 Guacamole/Playwright 로 구현.

엔드포인트:
  POST /screenshot      → base64 PNG + 해상도
  POST /click           → 좌표 클릭
  POST /double_click    → 좌표 더블클릭
  POST /right_click     → 좌표 우클릭
  POST /move            → 마우스 이동
  POST /scroll          → 스크롤
  POST /type            → 텍스트 입력
  POST /key             → 특수키/단축키
  POST /click_query     → 자연어로 요소 찾아 클릭 (OS-Atlas OCR)
  GET  /healthz         → 헬스체크
"""
from __future__ import annotations

import base64
import logging
from contextlib import asynccontextmanager
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, HTTPException
from PIL import Image
from pydantic import BaseModel

import guac_agent

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("boan-computer-use starting (Playwright-based Guacamole controller)")
    yield
    logger.info("boan-computer-use shutting down")


app = FastAPI(title="boan-computer-use", version="1.0.0", lifespan=lifespan)


# ── 공통 요청 베이스 ────────────────────────────────────────────────────────
class BaseRequest(BaseModel):
    web_desktop_url: str  # Guacamole 세션 URL (내부 Docker 네트워크 URL)


# ── 스크린샷 ────────────────────────────────────────────────────────────────
class ScreenshotResponse(BaseModel):
    image: str          # base64 PNG
    width: int
    height: int
    media_type: str = "image/png"


@app.post("/screenshot", response_model=ScreenshotResponse)
async def screenshot(req: BaseRequest):
    """
    GCP 작업화면 스크린샷.
    open-computer-use SandboxAgent.screenshot() 에 해당.
    """
    try:
        raw = await guac_agent.screenshot(req.web_desktop_url)
        img = Image.open(BytesIO(raw))
        w, h = img.size
        return ScreenshotResponse(
            image=base64.b64encode(raw).decode(),
            width=w,
            height=h,
        )
    except Exception as e:
        logger.exception("screenshot failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── 마우스 클릭 ─────────────────────────────────────────────────────────────
class ClickRequest(BaseRequest):
    x: int
    y: int
    button: str = "left"  # left | right | middle


@app.post("/click")
async def click(req: ClickRequest):
    """좌표 단일 클릭. open-computer-use sandbox.left_click() 에 해당."""
    try:
        result = await guac_agent.click(req.web_desktop_url, req.x, req.y, req.button)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("click failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/double_click")
async def double_click(req: ClickRequest):
    """더블클릭. open-computer-use sandbox.double_click() 에 해당."""
    try:
        result = await guac_agent.double_click(req.web_desktop_url, req.x, req.y)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("double_click failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/right_click")
async def right_click(req: ClickRequest):
    """우클릭. open-computer-use sandbox.right_click() 에 해당."""
    try:
        result = await guac_agent.right_click(req.web_desktop_url, req.x, req.y)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("right_click failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── 마우스 이동/스크롤 ──────────────────────────────────────────────────────
class MoveRequest(BaseRequest):
    x: int
    y: int


@app.post("/move")
async def move_mouse(req: MoveRequest):
    """마우스 이동."""
    try:
        result = await guac_agent.move_mouse(req.web_desktop_url, req.x, req.y)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("move failed")
        raise HTTPException(status_code=500, detail=str(e))


class ScrollRequest(BaseRequest):
    x: int
    y: int
    direction: str = "down"  # up | down
    amount: int = 3


@app.post("/scroll")
async def scroll(req: ScrollRequest):
    """스크롤."""
    try:
        result = await guac_agent.scroll(req.web_desktop_url, req.x, req.y, req.direction, req.amount)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("scroll failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── 키보드 ──────────────────────────────────────────────────────────────────
class TypeRequest(BaseRequest):
    text: str
    chunk_size: int = 50   # open-computer-use TYPING_GROUP_SIZE 와 동일
    delay_ms: int = 12     # open-computer-use TYPING_DELAY_MS 와 동일


@app.post("/type")
async def type_text(req: TypeRequest):
    """텍스트 입력. open-computer-use sandbox.write() 에 해당."""
    try:
        result = await guac_agent.type_text(
            req.web_desktop_url, req.text, req.chunk_size, req.delay_ms
        )
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("type failed")
        raise HTTPException(status_code=500, detail=str(e))


class KeyRequest(BaseRequest):
    name: str  # e.g. 'Return', 'Ctl-C', 'F5', 'Tab'


@app.post("/key")
async def send_key(req: KeyRequest):
    """특수키/단축키. open-computer-use sandbox.press() 에 해당."""
    try:
        result = await guac_agent.send_key(req.web_desktop_url, req.name)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("key failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── OCR 기반 클릭 ───────────────────────────────────────────────────────────
class QueryClickRequest(BaseRequest):
    query: str   # 자연어 설명, e.g. "test-text.txt 파일 아이콘"
    double: bool = False


@app.post("/click_query")
async def click_by_query(req: QueryClickRequest):
    """
    자연어로 UI 요소 찾아 클릭.
    open-computer-use SandboxAgent.click_element() + OS-Atlas grounding 에 해당.
    """
    try:
        result = await guac_agent.click_by_query(req.web_desktop_url, req.query, req.double)
        return {"ok": True, "result": result}
    except Exception as e:
        logger.exception("click_query failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── 헬스체크 ────────────────────────────────────────────────────────────────
@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "boan-computer-use"}
