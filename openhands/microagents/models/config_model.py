from dataclasses import dataclass
from typing import Optional, List

@dataclass
class MicroagentConfig:
    version: str = "2.0"
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    max_context_tokens: int = 50000
    enabled_workflows: Optional[List[str]] = None
    disabled_contexts: Optional[List[str]] = None
    strict_mode: bool = True  # Enforce all validations
