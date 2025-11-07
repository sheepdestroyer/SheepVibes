from dataclasses import dataclass
from typing import Optional
from pathlib import Path

@dataclass(frozen=True)
class ContextProvider:
    """Immutable context provider model"""
    name: str
    domain: str
    content: str
    filepath: Path
    checksum: str  # For cache validation
    priority: int = 100  # Higher = loaded first

    def __post_init__(self):
        # Validation logic can be added here
        pass
