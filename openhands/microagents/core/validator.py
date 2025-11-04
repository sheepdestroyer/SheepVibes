from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep
from typing import List
import re

class ValidationError(Exception):
    pass

class MicroagentValidator:
    """Validates microagent definitions"""

    def validate_context(self, context: ContextProvider) -> None:
        """Validate context provider"""
        errors = []

        # Name validation
        if not re.match(r'^[a-z0-9-]+$', context.name):
            errors.append(f"Invalid name: {context.name}")

        # Content validation
        if not context.content.strip():
            errors.append("Context content is empty")

        if len(context.content) > 100000:  # 100KB limit
            errors.append("Context content exceeds size limit")

        # Filepath validation
        if not context.filepath.exists():
            errors.append(f"Context file not found: {context.filepath}")

        if errors:
            raise ValidationError("; ".join(errors))

    def validate_workflow(self, workflow: WorkflowController) -> None:
        """Validate workflow controller"""
        errors = []

        # Version validation
        if not isinstance(workflow.version, str) or not re.match(r'^\d+\.\d+(\.\d+)?$', workflow.version):
            errors.append(f"Invalid version: {workflow.version}")

        # Steps validation
        if not workflow.steps:
            errors.append("Workflow has no steps")

        step_ids = [s.id for s in workflow.steps]
        if len(step_ids) != len(set(step_ids)):
            errors.append("Duplicate step IDs found")

        # Validate step references
        for step in workflow.steps:
            if step.on_success and step.on_success not in step_ids and step.on_success != "workflow_complete":
                errors.append(f"Invalid on_success reference in step '{step.id}': {step.on_success}")
            if step.on_failure and step.on_failure not in step_ids:
                errors.append(f"Invalid on_failure reference in step '{step.id}': {step.on_failure}")

        # Validate required steps form a valid path
        required_steps = [s for s in workflow.steps if s.required]
        if required_steps and not self._forms_valid_path(required_steps):
            errors.append("Required steps do not form a valid execution path")
        if errors:
            raise ValidationError("; ".join(errors))

    def _forms_valid_path(self, steps: List[WorkflowStep]) -> bool:
        """Check if required steps form a valid path using BFS and ensuring a single starting point."""
        if not steps:
            return True

        steps_map = {step.id: step for step in steps}
        step_ids = set(steps_map.keys())

        # Identify potential targets of transitions
        targets = set()
        for step in steps:
            if step.on_success and step.on_success in step_ids:
                targets.add(step.on_success)
            if step.on_failure and step.on_failure in step_ids:
                targets.add(step.on_failure)

        # A valid workflow should have exactly one step that is not a target of any other step
        start_nodes = step_ids - targets
        if len(start_nodes) != 1:
            return False  # No single, clear starting point

        start_node = start_nodes.pop()

        # Perform BFS from the identified start node
        q = [start_node]
        visited = set()

        while q:
            step_id = q.pop(0)
            if step_id in visited:
                continue # Already visited, but not a cycle in this context

            visited.add(step_id)
            step = steps_map.get(step_id)

            if step.on_success and step.on_success in step_ids:
                q.append(step.on_success)
            if step.on_failure and step.on_failure in step_ids:
                q.append(step.on_failure)

        # Check if all required steps are reachable from the start node
        return visited == step_ids
