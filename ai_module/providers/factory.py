from ai_module.config import AIAgentSettings
from ai_module.providers.base import AIProvider
from ai_module.providers.gemini import GeminiProvider


def get_provider(settings: AIAgentSettings) -> AIProvider:
    provider = settings.provider.strip().lower()
    if provider == "gemini":
        return GeminiProvider(settings)
    # Placeholder fallback to Gemini while keeping provider-agnostic shape.
    return GeminiProvider(settings)
