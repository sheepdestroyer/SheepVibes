from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml
from openhands.microagents.core.registry import MicroagentRegistry
from openhands.microagents.core.cache import MicroagentCache
from openhands.microagents.core.validator import MicroagentValidator
from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep, StepType
import hashlib
from dataclasses import asdict

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

        if self.cache:
            cached = self.cache.get(content)
            if cached:
                context = self._deserialize_context(cached)
                self.registry.register_context(context)
                return

        context = ContextProvider(
            name=filepath.stem,
            domain=filepath.stem,
            content=content,
            filepath=filepath,
            checksum=hashlib.sha256(content.encode()).hexdigest()
        )

        self.validator.validate_context(context)
        self.registry.register_context(context)

        if self.cache:
            self.cache.set(content, self._serialize_context(context))

    def _load_workflow_file(self, filepath: Path) -> None:
        """Load single workflow controller"""
        content = filepath.read_text()

        if self.cache:
            cached = self.cache.get(content)
            if cached:
                workflow = self._deserialize_workflow(cached)
                self.registry.register_workflow(workflow)
                return

        data = yaml.safe_load(content)
        workflow = self._parse_workflow(data)

        self.validator.validate_workflow(workflow)
        self.registry.register_workflow(workflow)

        if self.cache:
            self.cache.set(content, self._serialize_workflow(workflow))

    def _parse_workflow(self, data: Dict[str, Any]) -> WorkflowController:
        """Parse workflow from YAML"""
        return WorkflowController(
            name=data['name'],
            version=str(data['version']),
            description=data['description'],
            steps=[self._parse_step(s) for s in data.get('steps', [])],
            config=data.get('config', {}),
            error_handling=data.get('error_handling', {}),
            exit_criteria=data.get('exit_criteria', {})
        )

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

    def _serialize_context(self, context: ContextProvider) -> Dict[str, Any]:
        """Serialize ContextProvider to a dict"""
        data = asdict(context)
        data['filepath'] = str(data['filepath'])
        return data

    def _deserialize_context(self, data: Dict[str, Any]) -> ContextProvider:
        """Deserialize a dict to a ContextProvider"""
        data['filepath'] = Path(data['filepath'])
        return ContextProvider(**data)

    def _serialize_workflow(self, workflow: WorkflowController) -> Dict[str, Any]:
        """Serialize WorkflowController to a dict"""
        data = asdict(workflow)
        for step in data['steps']:
            step['type'] = step['type'].value
        return data

    def _deserialize_workflow(self, data: Dict[str, Any]) -> WorkflowController:
        """Deserialize a dict to a WorkflowController"""
        data['steps'] = [self._parse_step(step) for step in data.get('steps', [])]
        return WorkflowController(**data)
