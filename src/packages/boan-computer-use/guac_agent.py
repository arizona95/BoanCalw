"""
GuacAgent — open-computer-use 의 SandboxAgent 를 Guacamole/Playwright 용으로 재작성.
- sandbox.screenshot()  → Playwright 로 Guacamole 캔버스 캡처
- sandbox.left_click()  → Playwright mouse.click
- sandbox.write()       → Playwright keyboard.type
등을 Guacamole iframe 환경에서 동작하도록 구현.
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
from dataclasses import dataclass, field
from typing import Optional

from PIL import Image
from playwright.async_api import async_playwright, Browser, Page, BrowserContext

logger = logging.getLogger("guac_agent")


@dataclass
class GuacSession:
    url: str
    browser: Browser
    context: BrowserContext
    page: Page
    canvas_width: int = 1280
    canvas_height: int = 800


_sessions: dict[str, GuacSession] = {}
_lock = asyncio.Lock()
_pw = None
_browser: Optional[Browser] = None


async def _ensure_playwright():
    global _pw, _browser
    if _browser is None or not _browser.is_connected():
        _pw = await async_playwright().start()
        _browser = await _pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",
                "--allow-running-insecure-content",
            ],
        )
    return _browser


async def get_or_create_session(web_desktop_url: str) -> GuacSession:
    """
    세션 캐시 관리 — 동일 URL 의 경우 기존 페이지 재사용.
    Guacamole 연결이 끊어진 경우 재연결.
    """
    async with _lock:
        sess = _sessions.get(web_desktop_url)
        if sess:
            try:
                # 페이지가 살아있는지 확인
                await sess.page.title()
                return sess
            except Exception:
                logger.warning("Session stale, recreating: %s", web_desktop_url[:80])
                try:
                    await sess.context.close()
                except Exception:
                    pass
                del _sessions[web_desktop_url]

        browser = await _ensure_playwright()
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        logger.info("Navigating to Guacamole: %s", web_desktop_url[:80])
        try:
            await page.goto(web_desktop_url, wait_until="domcontentloaded", timeout=20000)
        except Exception as e:
            logger.warning("goto error (continuing): %s", e)

        # Guacamole 캔버스가 나타날 때까지 대기 (최대 15초)
        try:
            await page.wait_for_selector("canvas", timeout=15000)
            logger.info("Guacamole canvas appeared")
        except Exception:
            logger.warning("Canvas not found within timeout, proceeding anyway")

        # 초기 렌더링 대기
        await asyncio.sleep(3)

        sess = GuacSession(
            url=web_desktop_url,
            browser=browser,
            context=context,
            page=page,
        )
        _sessions[web_desktop_url] = sess
        return sess


async def _get_canvas_bbox(page: Page):
    """Guacamole 메인 display canvas 의 bounding box 반환."""
    # Guacamole renders multiple canvas layers; the display div wraps them all
    for selector in ["#display", ".display", "canvas"]:
        el = await page.query_selector(selector)
        if el:
            bbox = await el.bounding_box()
            if bbox and bbox["width"] > 100:
                return bbox
    return None


async def screenshot(web_desktop_url: str) -> bytes:
    """
    open-computer-use SandboxAgent.screenshot() 과 동일 역할.
    Guacamole 캔버스를 PNG bytes 로 반환.
    """
    sess = await get_or_create_session(web_desktop_url)
    page = sess.page

    try:
        # 캔버스 영역만 캡처 시도
        bbox = await _get_canvas_bbox(page)
        if bbox:
            raw = await page.screenshot(
                clip={
                    "x": bbox["x"],
                    "y": bbox["y"],
                    "width": bbox["width"],
                    "height": bbox["height"],
                },
                type="png",
            )
            sess.canvas_width = int(bbox["width"])
            sess.canvas_height = int(bbox["height"])
            return raw
    except Exception as e:
        logger.warning("Canvas screenshot failed, falling back to full page: %s", e)

    return await page.screenshot(type="png", full_page=False)


async def _canvas_coords(page: Page, x: int, y: int):
    """
    canvas-relative 좌표 → page 좌표 변환.
    AI 가 screenshot(캔버스 영역) 에서 얻은 좌표를 페이지 절대 좌표로 변환.
    """
    bbox = await _get_canvas_bbox(page)
    if bbox:
        return bbox["x"] + x, bbox["y"] + y
    return float(x), float(y)


async def click(web_desktop_url: str, x: int, y: int, button: str = "left") -> str:
    """단일 클릭 — open-computer-use sandbox.left_click() / right_click() 에 해당."""
    sess = await get_or_create_session(web_desktop_url)
    px, py = await _canvas_coords(sess.page, x, y)
    btn = "right" if button == "right" else "middle" if button == "middle" else "left"
    await sess.page.mouse.click(px, py, button=btn)
    logger.info("click(%s, %s, %s) page=(%.0f, %.0f)", x, y, btn, px, py)
    return f"clicked ({x}, {y}) button={btn}"


async def double_click(web_desktop_url: str, x: int, y: int) -> str:
    """더블클릭 — open-computer-use sandbox.double_click() 에 해당."""
    sess = await get_or_create_session(web_desktop_url)
    px, py = await _canvas_coords(sess.page, x, y)
    await sess.page.mouse.dblclick(px, py)
    logger.info("double_click(%s, %s) page=(%.0f, %.0f)", x, y, px, py)
    return f"double-clicked ({x}, {y})"


async def right_click(web_desktop_url: str, x: int, y: int) -> str:
    """우클릭."""
    return await click(web_desktop_url, x, y, button="right")


async def move_mouse(web_desktop_url: str, x: int, y: int) -> str:
    """마우스 이동 — open-computer-use sandbox.move_mouse() 에 해당."""
    sess = await get_or_create_session(web_desktop_url)
    px, py = await _canvas_coords(sess.page, x, y)
    await sess.page.mouse.move(px, py)
    return f"moved to ({x}, {y})"


async def scroll(web_desktop_url: str, x: int, y: int, direction: str, amount: int = 3) -> str:
    """스크롤."""
    sess = await get_or_create_session(web_desktop_url)
    px, py = await _canvas_coords(sess.page, x, y)
    await sess.page.mouse.move(px, py)
    delta = -amount * 100 if direction == "up" else amount * 100
    await sess.page.mouse.wheel(0, delta)
    return f"scrolled {direction} x{amount} at ({x}, {y})"


# Windows 특수키 → Playwright key 이름 매핑
# open-computer-use 의 send_key 명세 참고
_KEY_MAP: dict[str, str] = {
    "Return": "Enter",
    "Ctl-C": "Control+c",
    "Ctl-V": "Control+v",
    "Ctl-X": "Control+x",
    "Ctl-Z": "Control+z",
    "Ctl-A": "Control+a",
    "Ctl-S": "Control+s",
    "Ctl-Alt-Del": "Control+Alt+Delete",
    "Win": "Meta",
    "Tab": "Tab",
    "Escape": "Escape",
    "BackSpace": "Backspace",
    "Delete": "Delete",
    "Home": "Home",
    "End": "End",
    "Prior": "PageUp",
    "Next": "PageDown",
    "Up": "ArrowUp",
    "Down": "ArrowDown",
    "Left": "ArrowLeft",
    "Right": "ArrowRight",
    "F1": "F1", "F2": "F2", "F3": "F3", "F4": "F4",
    "F5": "F5", "F6": "F6", "F7": "F7", "F8": "F8",
    "F9": "F9", "F10": "F10", "F11": "F11", "F12": "F12",
}


async def send_key(web_desktop_url: str, name: str) -> str:
    """
    특수키/단축키 전송 — open-computer-use sandbox.press() 에 해당.
    e.g. 'Return', 'Ctl-C', 'F5', 'Tab'
    """
    sess = await get_or_create_session(web_desktop_url)
    playwright_key = _KEY_MAP.get(name, name)
    await sess.page.keyboard.press(playwright_key)
    logger.info("send_key: %s → %s", name, playwright_key)
    return f"pressed key: {name}"


async def type_text(
    web_desktop_url: str,
    text: str,
    chunk_size: int = 50,
    delay_ms: int = 12,
) -> str:
    """
    텍스트 입력 — open-computer-use sandbox.write() 에 해당.
    chunk_size / delay_ms 기본값도 open-computer-use 와 동일.
    """
    sess = await get_or_create_session(web_desktop_url)
    # Guacamole canvas 에 포커스 확보
    bbox = await _get_canvas_bbox(sess.page)
    if bbox:
        cx = bbox["x"] + bbox["width"] / 2
        cy = bbox["y"] + bbox["height"] / 2
        await sess.page.mouse.click(cx, cy)

    delay_s = delay_ms / 1000
    for i in range(0, len(text), chunk_size):
        chunk = text[i : i + chunk_size]
        await sess.page.keyboard.type(chunk, delay=delay_s * 1000)
        if i + chunk_size < len(text):
            await asyncio.sleep(delay_s)

    logger.info("type_text: %d chars", len(text))
    return f"typed {len(text)} characters"


async def click_by_query(web_desktop_url: str, query: str, double: bool = False) -> str:
    """
    자연어 쿼리로 요소 찾아 클릭 — open-computer-use click_element() 에 해당.
    OS-Atlas grounding 으로 좌표 추출 후 클릭.
    """
    from grounding import ground_query

    img_bytes = await screenshot(web_desktop_url)
    img = Image.open(io.BytesIO(img_bytes))
    w, h = img.size

    coords = await ground_query(img_bytes, query, w, h)
    if coords is None:
        return f"grounding failed for query: {query!r} — use coordinate-based click instead"

    x, y = coords
    if double:
        return await double_click(web_desktop_url, x, y)
    return await click(web_desktop_url, x, y)
