"""
agent.py — Windows computer-use agent.

Structurally identical to open-computer-use's sandbox_agent.py,
but runs against WindowsDesktop instead of an E2B sandbox.
Shell commands go to PowerShell (with cmd fallback).
"""

import json
import os
import tempfile

from PIL import Image

from win_computer_use.config import action_model, grounding_model, vision_model
from win_computer_use.grounding import draw_big_dot
from win_computer_use.llm_provider import Message
from win_computer_use.logging import logger

TYPING_DELAY_MS = 12
TYPING_GROUP_SIZE = 50

tools: dict = {
    "stop": {
        "description": "Indicate that the task has been completed.",
        "params": {},
    }
}


class WindowsAgent:
    """
    Agent that controls a local Windows desktop.
    API-compatible with open-computer-use's SandboxAgent.
    """

    def __init__(self, desktop, output_dir: str = ".", save_logs: bool = True):
        self.messages: list = []
        self.desktop = desktop
        self.latest_screenshot: str | None = None
        self.image_counter = 0
        self.tmp_dir = tempfile.mkdtemp()

        if save_logs:
            logger.log_file = f"{output_dir}/log.html"

        print("Windows agent ready. Available actions:")
        for action, details in tools.items():
            param_str = ", ".join(details.get("params", {}).keys())
            print(f"  {action}({param_str})")

    # ── Tool registration decorator (identical to original) ─────────────────

    def tool(description, params):  # noqa: N805 (intentional classmethod-like decorator)
        def decorator(func):
            tools[func.__name__] = {"description": description, "params": params}
            return func
        return decorator

    # ── Dispatch ────────────────────────────────────────────────────────────

    def call_function(self, name: str, arguments: dict):
        func = getattr(self, name.lower(), None) if name.lower() in tools else None
        if func:
            try:
                return func(**arguments) if arguments else func()
            except Exception as e:
                return f"Error executing {name}: {e}"
        return "Function not implemented."

    # ── Image helpers ────────────────────────────────────────────────────────

    def save_image(self, image, prefix: str = "image") -> str:
        self.image_counter += 1
        filepath = os.path.join(self.tmp_dir, f"{prefix}_{self.image_counter}.png")
        if isinstance(image, Image.Image):
            image.save(filepath)
        else:
            with open(filepath, "wb") as f:
                f.write(image)
        return filepath

    def screenshot(self) -> bytes:
        raw = self.desktop.screenshot()
        filepath = self.save_image(raw, "screenshot")
        logger.log(f"screenshot {filepath}", "gray")
        self.latest_screenshot = filepath
        with open(filepath, "rb") as f:
            return f.read()

    # ── Tools ────────────────────────────────────────────────────────────────

    @tool(
        description="Run a PowerShell command and return the output.",
        params={"command": "PowerShell command to run synchronously"},
    )
    def run_command(self, command: str) -> str:
        # Prefer PowerShell; fall back to cmd on error
        ps_cmd = f'powershell -NoProfile -NonInteractive -Command "{command}"'
        result = self.desktop.commands.run(ps_cmd, timeout=10)
        output = (result.stdout or "") + (result.stderr or "")
        return output.strip() if output.strip() else "The command finished with no output."

    @tool(
        description="Run a PowerShell command in the background (fire-and-forget).",
        params={"command": "PowerShell command to run asynchronously"},
    )
    def run_background_command(self, command: str) -> str:
        ps_cmd = f'powershell -NoProfile -NonInteractive -Command "{command}"'
        self.desktop.commands.run(ps_cmd, background=True)
        return "The command has been started in the background."

    @tool(
        description="Send a key or key combination to the active window.",
        params={"name": "Key name or combo, e.g. 'Return', 'Ctrl-C', 'Alt-F4'"},
    )
    def send_key(self, name: str) -> str:
        self.desktop.press(name)
        return f"Pressed: {name}"

    @tool(
        description="Type text into the active window. Supports Unicode (including Korean).",
        params={"text": "Text to type"},
    )
    def type_text(self, text: str) -> str:
        self.desktop.write(text, chunk_size=TYPING_GROUP_SIZE, delay_in_ms=TYPING_DELAY_MS)
        return "Text typed."

    @tool(
        description="Scroll the mouse wheel.",
        params={
            "direction": "'up' or 'down'",
            "clicks": "Number of scroll steps (default 3)",
        },
    )
    def scroll(self, direction: str = "down", clicks: str = "3") -> str:
        import pyautogui
        amount = int(clicks) if str(clicks).isdigit() else 3
        pyautogui.scroll(amount if direction == "up" else -amount)
        return f"Scrolled {direction} {amount} steps."

    def _click_element(self, query: str, click_fn, action_name: str = "click") -> str:
        self.screenshot()
        position = grounding_model.call(query, self.latest_screenshot)
        if position is None:
            return f"Could not locate '{query}' on screen."
        dot_img = draw_big_dot(Image.open(self.latest_screenshot), position)
        filepath = self.save_image(dot_img, "location")
        logger.log(f"{action_name} → {filepath}", "gray")
        x, y = position
        self.desktop.move_mouse(x, y)
        click_fn()
        return f"{action_name.capitalize()} performed."

    @tool(
        description="Click on a UI element described in natural language.",
        params={"query": "Description of the element to click, e.g. 'OK button'"},
    )
    def click(self, query: str) -> str:
        return self._click_element(query, self.desktop.left_click)

    @tool(
        description="Double-click on a UI element.",
        params={"query": "Description of the element to double-click"},
    )
    def double_click(self, query: str) -> str:
        return self._click_element(query, self.desktop.double_click, "double click")

    @tool(
        description="Right-click on a UI element.",
        params={"query": "Description of the element to right-click"},
    )
    def right_click(self, query: str) -> str:
        return self._click_element(query, self.desktop.right_click, "right click")

    # ── Vision + agent loop ──────────────────────────────────────────────────

    def _vision_prompt(self) -> str:
        return vision_model.call(
            [
                *self.messages,
                Message(
                    [
                        self.screenshot(),
                        "This image shows the current Windows desktop. Please respond in the following format:\n"
                        "The objective is: [put the objective here]\n"
                        "On the screen, I see: [an extensive list of everything relevant: windows, taskbar, icons, menus, dialogs, text fields, buttons]\n"
                        "This means the objective is: [complete|not complete]\n\n"
                        "(Only continue if the objective is not complete.)\n"
                        "The next step is to [click|type|run the PowerShell command|press key] "
                        "[put the next single step here] in order to [put what you expect to happen].",
                    ],
                    role="user",
                ),
            ]
        )

    def run(self, instruction: str) -> None:
        self.messages.append(Message(f"OBJECTIVE: {instruction}"))
        logger.log(f"USER: {instruction}", print=False)

        should_continue = True
        while should_continue:
            # Local desktop never times out, but we honour the interface.
            self.desktop.set_timeout(60)

            vision_analysis = self._vision_prompt()

            content, tool_calls = action_model.call(
                [
                    Message(
                        "You are an AI assistant that controls a Windows desktop. "
                        "Use PowerShell for shell commands. Prefer GUI interactions over CLI when possible.",
                        role="system",
                    ),
                    *self.messages,
                    Message(logger.log(f"THOUGHT: {vision_analysis}", "green")),
                    Message(
                        "I will now use tool calls to take the next action, "
                        "or call stop if the objective is complete."
                    ),
                ],
                tools,
            )

            if content:
                self.messages.append(Message(logger.log(f"THOUGHT: {content}", "blue")))

            should_continue = False
            for tool_call in tool_calls:
                name = tool_call.get("name")
                parameters = tool_call.get("parameters", {})
                should_continue = name != "stop"
                if not should_continue:
                    break
                logger.log(f"ACTION: {name} {parameters}", "red")
                self.messages.append(Message(json.dumps(tool_call)))
                result = self.call_function(name, parameters)
                self.messages.append(
                    Message(logger.log(f"OBSERVATION: {result}", "yellow"))
                )
