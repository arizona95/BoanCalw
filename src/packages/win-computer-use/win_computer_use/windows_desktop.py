"""
windows_desktop.py — replaces open-computer-use's streaming.py (E2B Sandbox).

Provides the same interface that SandboxAgent expects, but drives the local
Windows desktop with pyautogui + mss instead of an E2B cloud sandbox.
"""

import io
import subprocess
import threading
import time

import mss
import pyautogui
import pyperclip
from PIL import Image

# Disable pyautogui's fail-safe pause (we handle timing ourselves)
pyautogui.PAUSE = 0.05
pyautogui.FAILSAFE = True  # Move mouse to top-left corner to abort

# ── Key-name translation ──────────────────────────────────────────────────────
# E2B / X11 key names  →  pyautogui key names
_KEY_MAP: dict[str, str] = {
    "Return": "enter",
    "BackSpace": "backspace",
    "Delete": "delete",
    "Escape": "escape",
    "Tab": "tab",
    "space": "space",
    "super": "win",
    "Super_L": "win",
    "Super_R": "win",
    "Up": "up",
    "Down": "down",
    "Left": "left",
    "Right": "right",
    "Home": "home",
    "End": "end",
    "Page_Up": "pageup",
    "Page_Down": "pagedown",
    "Insert": "insert",
    "Print": "printscreen",
    "F1": "f1", "F2": "f2", "F3": "f3", "F4": "f4",
    "F5": "f5", "F6": "f6", "F7": "f7", "F8": "f8",
    "F9": "f9", "F10": "f10", "F11": "f11", "F12": "f12",
}

# Modifier aliases used in combo strings like "Ctrl-C", "Alt-F4"
_MOD_MAP: dict[str, str] = {
    "Ctrl":  "ctrl",
    "ctrl":  "ctrl",
    "Alt":   "alt",
    "alt":   "alt",
    "Shift": "shift",
    "shift": "shift",
    "Win":   "win",
    "win":   "win",
    "Super": "win",
}


def _translate_key(name: str) -> str:
    """Map an X11/E2B key name to the pyautogui equivalent."""
    return _KEY_MAP.get(name, name.lower())


def _parse_combo(combo: str) -> list[str]:
    """
    Parse a key-combo string such as 'Ctrl-C' or 'Alt-F4' or 'Shift-Return'
    into a list of pyautogui key names.
    """
    parts = combo.replace("+", "-").split("-")
    keys = []
    for part in parts:
        if part in _MOD_MAP:
            keys.append(_MOD_MAP[part])
        else:
            keys.append(_translate_key(part))
    return keys


# ── Command runner helper ─────────────────────────────────────────────────────

class _CommandResult:
    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr


class _Commands:
    """Mimics e2b_desktop Sandbox.commands interface."""

    @staticmethod
    def run(command: str, timeout: int = 5, background: bool = False) -> _CommandResult:
        if background:
            subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            return _CommandResult()
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            return _CommandResult(result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return _CommandResult(stderr=f"Command timed out after {timeout}s")
        except Exception as e:
            return _CommandResult(stderr=str(e))


# ── Main sandbox class ────────────────────────────────────────────────────────

class WindowsDesktop:
    """
    Drop-in replacement for the E2B Sandbox used in open-computer-use.

    SandboxAgent calls these methods:
        screenshot()            → bytes (PNG)
        move_mouse(x, y)
        left_click()
        double_click()
        right_click()
        press(key_name)         → single key or combo like "Ctrl-C"
        write(text, chunk_size, delay_in_ms)
        commands.run(cmd, timeout, background)
        set_timeout(seconds)    → no-op
        kill()                  → no-op
    """

    def __init__(self, monitor_index: int = 1):
        """
        monitor_index: 1 = primary monitor (mss index), 2 = secondary, etc.
        Set to 0 to capture all monitors combined.
        """
        self._monitor_index = monitor_index
        self.commands = _Commands()
        self._lock = threading.Lock()  # Serialise mouse/keyboard ops

    # ── Screen capture ──────────────────────────────────────────────────────

    def screenshot(self) -> bytes:
        with mss.mss() as sct:
            monitor = sct.monitors[self._monitor_index]
            raw = sct.grab(monitor)
            # mss returns BGRA; convert to RGB PNG
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()

    # ── Mouse ───────────────────────────────────────────────────────────────

    def move_mouse(self, x: int, y: int) -> None:
        with self._lock:
            pyautogui.moveTo(x, y, duration=0.15)

    def left_click(self) -> None:
        with self._lock:
            pyautogui.click()

    def double_click(self) -> None:
        with self._lock:
            pyautogui.doubleClick()

    def right_click(self) -> None:
        with self._lock:
            pyautogui.rightClick()

    # ── Keyboard ────────────────────────────────────────────────────────────

    def press(self, name: str) -> None:
        """
        Press a key or key combination.
        Supports X11/E2B style names: 'Return', 'Ctrl-C', 'Alt-F4', etc.
        """
        with self._lock:
            keys = _parse_combo(name)
            if len(keys) == 1:
                pyautogui.press(keys[0])
            else:
                pyautogui.hotkey(*keys)

    def write(self, text: str, chunk_size: int = 50, delay_in_ms: int = 12) -> None:
        """
        Type text into the focused window.

        Strategy:
        - Pure ASCII → pyautogui.typewrite() (simulates actual keystrokes)
        - Any non-ASCII (e.g. Korean, CJK, symbols) → clipboard paste,
          which works reliably on Windows for all Unicode text.
        """
        with self._lock:
            if text.isascii():
                # Chunk to stay close to the original implementation
                for i in range(0, len(text), chunk_size):
                    chunk = text[i:i + chunk_size]
                    pyautogui.typewrite(chunk, interval=delay_in_ms / 1000)
            else:
                # Unicode-safe path: copy → Ctrl+V
                original = _safe_clipboard_get()
                pyperclip.copy(text)
                time.sleep(0.05)
                pyautogui.hotkey("ctrl", "v")
                time.sleep(0.1)
                # Restore clipboard (best-effort)
                if original is not None:
                    pyperclip.copy(original)

    # ── Lifecycle (no-ops for local desktop) ────────────────────────────────

    def set_timeout(self, seconds: int) -> None:  # noqa: ARG002
        """No-op: local desktop doesn't time out."""

    def kill(self) -> None:
        """No-op: we don't own the desktop process."""


# ── Clipboard helpers ────────────────────────────────────────────────────────

def _safe_clipboard_get() -> str | None:
    try:
        return pyperclip.paste()
    except Exception:
        return None
