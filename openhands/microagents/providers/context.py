from typing import List, Optional
from openhands.microagents.core.registry import MicroagentRegistry
from openhands.microagents.models.context_model import ContextProvider

class ContextProviderService:
    """Service for accessing context providers"""

    def __init__(self):
        self.registry = MicroagentRegistry()

    def get_all_contexts(self) -> str:
        """Get all contexts as formatted string"""
        contexts = self.registry.list_contexts()
        return self._format_contexts(contexts)

    def get_context_by_domain(self, domain: str) -> Optional[str]:
        """Get specific context by domain"""
        context = self.registry.get_context(domain)
        return context.content if context else None

    def get_contexts_for_prompt(
        self,
        max_tokens: int = 50000
    ) -> str:
        """Get contexts optimized for LLM prompt"""
        contexts = self.registry.list_contexts()

        result = []
        token_count = 0

        for context in contexts:
            # Rough token estimation (1 token ≈ 4 chars)
            estimated_tokens = len(context.content) // 4

            if token_count + estimated_tokens > max_tokens:
                break

            result.append(context.content)
            token_count += estimated_tokens

        return "\n\n---\n\n".join(result)

    def _format_contexts(self, contexts: List[ContextProvider]) -> str:
        """Format contexts for display"""
        sections = []
        for ctx in contexts:
            sections.append(
                f"# {ctx.domain.upper()} Context\n\n{ctx.content}"
            )
        return "\n\n".join(sections)
