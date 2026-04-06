# config.py — select which models to use for each role.
# Edit this file to switch providers without touching agent code.

from win_computer_use import providers

# ── Grounding model: locates UI elements by natural-language query → (x, y) ──
grounding_model = providers.OSAtlasProvider()
# grounding_model = providers.ShowUIProvider()

# ── Vision model: analyzes screenshots, describes what is on screen ───────────
# vision_model = providers.AnthropicProvider("claude-3.5-sonnet")
# vision_model = providers.OpenAIProvider("gpt-4o")
# vision_model = providers.GroqProvider("llama-3.2")
vision_model = providers.OpenRouterProvider("qwen-2.5-vl")

# ── Action model: decides tool calls (click / type / run_command / stop) ──────
# action_model = providers.AnthropicProvider("claude-3.5-haiku")
# action_model = providers.OpenAIProvider("gpt-4o")
# action_model = providers.FireworksProvider("llama-3.3")
action_model = providers.GroqProvider("llama-3.3")
