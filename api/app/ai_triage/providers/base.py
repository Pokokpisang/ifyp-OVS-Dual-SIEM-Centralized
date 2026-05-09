from abc import ABC, abstractmethod
from ..schemas import AITriageResult


class BaseTriageProvider(ABC):
    @abstractmethod
    async def run_triage(self, prompt: str) -> tuple[AITriageResult, str]:
        """Call the AI API. Returns (validated_result, raw_json_string). Raises on error."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @property
    @abstractmethod
    def model_name(self) -> str: ...
