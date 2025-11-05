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
        """Check if required steps form a valid path using DFS for cycle detection."""
        if not steps:
            return True

        steps_map = {step.id: step for step in steps}
        step_ids = set(steps_map.keys())

        # Find start nodes (nodes with no incoming edges)
        targets = {s.on_success for s in steps if s.on_success in step_ids}
        targets.update({s.on_failure for s in steps if s.on_failure in step_ids})
        start_nodes = step_ids - targets

        if not start_nodes:
            return False  # No start node, likely a cycle

        # DFS for cycle detection
        visiting = set()
        visited = set()

        def has_cycle(step_id):
            visiting.add(step_id)
            step = steps_map.get(step_id)

            for next_step_id in [step.on_success, step.on_failure]:
                if next_step_id in visiting:
                    return True  # Cycle detected
                if next_step_id in step_ids and next_step_id not in visited:
                    if has_cycle(next_step_id):
                        return True

            visiting.remove(step_id)
            visited.add(step_id)
            return False

        for start_node in start_nodes:
            if start_node not in visited:
                if has_cycle(start_node):
                    return False

        # Check for reachability
        return len(visited) == len(step_ids)
