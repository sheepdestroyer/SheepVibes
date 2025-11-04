from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml
from openhands.microagents.core.registry import MicroagentRegistry
from openhands.microagents.core.cache import MicroagentCache
from openhands.microagents.core.validator import MicroagentValidator
from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep, StepType
import hashlib

class MicroagentLoader:
    """Single source of truth for loading microagents"""

    def __init__(
        self,
        repo_root: Path,
        cache_dir: Optional[Path] = None,
        enable_cache: bool = True
    ):
        self.repo_root = repo_root
        self.openhands_dir = repo_root / ".openhands"
        self.registry = MicroagentRegistry()
        self.validator = MicroagentValidator()

        if enable_cache:
            cache_path = cache_dir or (self.openhands_dir / ".microagent-cache")
            self.cache = MicroagentCache(cache_path)
        else:
            self.cache = None

    def load_all(self) -> None:
        """Load all microagents (contexts + workflows)"""
        self.load_contexts()
        self.load_workflows()

    def load_contexts(self) -> None:
        """Load all context providers from .openhands/context/"""
        context_dir = self.openhands_dir / "context"
        if not context_dir.exists():
            return

        for md_file in sorted(context_dir.glob("*.md")):
            self._load_context_file(md_file)

    def load_workflows(self) -> None:
        """Load all workflow controllers from .openhands/workflows/"""
        workflow_dir = self.openhands_dir / "workflows"
        if not workflow_dir.exists():
            return

        for yml_file in sorted(workflow_dir.glob("*.yml")):
            self._load_workflow_file(yml_file)

    def _load_context_file(self, filepath: Path) -> None:
        """Load single context provider"""
        content = filepath.read_text()

        # Create context provider
        context = ContextProvider(
            name=filepath.stem,
            domain=filepath.stem,
            content=content,
            filepath=filepath,
            checksum=hashlib.sha256(content.encode()).hexdigest()
        )

        # Validate
        self.validator.validate_context(context)

        # Register
        self.registry.register_context(context)

    def _load_workflow_file(self, filepath: Path) -> None:
        """Load single workflow controller"""
        content = filepath.read_text()

        # Parse YAML
        data = yaml.safe_load(content)

        # Create workflow controller
        workflow = WorkflowController(
            name=data['name'],
            version=str(data['version']),
            description=data['description'],
            steps=[self._parse_step(s) for s in data.get('steps', [])],
            config=data.get('config', {}),
            error_handling=data.get('error_handling', {}),
            exit_criteria=data.get('exit_criteria', {})
        )

        # Validate
        self.validator.validate_workflow(workflow)

        # Register
        self.registry.register_workflow(workflow)

    def _parse_step(self, step_data: Dict[str, Any]) -> WorkflowStep:
        """Parse workflow step from YAML"""
        return WorkflowStep(
            id=step_data['id'],
            name=step_data['name'],
            type=StepType(step_data['type']),
            required=step_data.get('required', False),
            actions=step_data.get('actions', []),
            gates=step_data.get('gates'),
            on_success=step_data.get('on_success'),
            on_failure=step_data.get('on_failure')
        )
