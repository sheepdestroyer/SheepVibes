from dataclasses import dataclass
from typing import Optional, List

@dataclass
class MicroagentConfig:
    """Represents the configuration for the microagent system.

    Attributes:
        version: The version of the microagent configuration.
        enable_caching: Whether to enable caching of microagents.
        cache_ttl_seconds: The time-to-live for the cache in seconds.
        max_context_tokens: The maximum number of tokens to use for context.
        enabled_workflows: A list of workflow names to enable. If None, all
            discovered workflows are enabled. If an empty list, no workflows
            are enabled.
        disabled_contexts: A list of context provider names to disable.
        strict_mode: Whether to enforce all validations.
    """
    version: str = "2.0"
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    max_context_tokens: int = 50000
    enabled_workflows: Optional[List[str]] = None
    disabled_contexts: Optional[List[str]] = None
    strict_mode: bool = True  # Enforce all validations
