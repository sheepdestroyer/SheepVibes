from typing import Dict, List, Optional
from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController
import threading

class MicroagentRegistry:
    """Thread-safe singleton registry for all microagents"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self._contexts: Dict[str, ContextProvider] = {}
        self._workflows: Dict[str, WorkflowController] = {}
        self._loaded = False

    def register_context(self, context: ContextProvider) -> None:
        """Register a context provider (idempotent)"""
        if context.name in self._contexts:
            # Check if content changed via checksum
            existing = self._contexts[context.name]
            if existing.checksum != context.checksum:
                self._contexts[context.name] = context
        else:
            self._contexts[context.name] = context

    def register_workflow(self, workflow: WorkflowController) -> None:
        """Register a workflow controller (idempotent)"""
        self._workflows[workflow.name] = workflow

    def get_context(self, name: str) -> Optional[ContextProvider]:
        return self._contexts.get(name)

    def get_workflow(self, name: str) -> Optional[WorkflowController]:
        return self._workflows.get(name)

    def list_contexts(self) -> List[ContextProvider]:
        return sorted(
            self._contexts.values(),
            key=lambda c: c.priority,
            reverse=True
        )

    def list_workflows(self) -> List[WorkflowController]:
        return list(self._workflows.values())

    def clear(self) -> None:
        """Clear all registrations (for testing)"""
        self._contexts.clear()
        self._workflows.clear()
        self._loaded = False
