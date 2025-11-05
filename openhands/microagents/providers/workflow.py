from typing import Dict, Any, Optional, List
from enum import Enum
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep
from openhands.microagents.core.registry import MicroagentRegistry
from datetime import datetime
import asyncio

class WorkflowState(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

class WorkflowExecutor:
    """Executes workflow controllers"""

    def __init__(self, workflow_name: str):
        self.registry = MicroagentRegistry()
        workflow = self.registry.get_workflow(workflow_name)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_name}")

        self.workflow = workflow
        self.state = WorkflowState.NOT_STARTED
        self.current_step_id: Optional[str] = None
        self.step_results: Dict[str, Any] = {}
        self.execution_log: List[Dict[str, Any]] = []
        self.action_handlers = {}

    async def execute(self) -> Dict[str, Any]:
        """Execute entire workflow"""
        self.state = WorkflowState.IN_PROGRESS
        self._log_event('workflow_start', {'workflow_name': self.workflow.name})

        try:
            current_step = self.workflow.steps[0] if self.workflow.steps else None

            while current_step:
                result = await self._execute_step(current_step)
                self.step_results[current_step.id] = result

                next_id = None
                if result.get('success'):
                    if current_step.on_success == "workflow_complete":
                        break
                    next_id = current_step.on_success
                else:
                    next_id = current_step.on_failure

                if not next_id:
                    break

                current_step = self._get_step_by_id(next_id)

            self.state = WorkflowState.COMPLETED
            self._log_event('workflow_complete', {'final_state': 'completed'})
            return {
                'success': True,
                'results': self.step_results,
                'log': self.execution_log
            }

        except Exception as e:
            self.state = WorkflowState.FAILED
            self._log_event('workflow_error', {'error': str(e)})
            return {
                'success': False,
                'error': str(e),
                'log': self.execution_log
            }

    async def _execute_step(self, step: WorkflowStep) -> Dict[str, Any]:
        """Execute single workflow step"""
        self.current_step_id = step.id
        self._log_event('step_start', {'step_id': step.id, 'step_name': step.name})

        action_results = {}
        step_success = True
        for action in step.actions:
            action_id = action.get('id')
            if not action_id:
                self._log_event('action_error', {'error': 'Action missing id'})
                step_success = False
                continue

            result = await self._execute_action(action)
            action_results[action_id] = result
            if not result.get('success', True):
                step_success = False

        gates_passed = self._check_gates(step.gates, action_results) if step.gates else True

        final_success = step_success and gates_passed
        self._log_event('step_complete', {
            'step_id': step.id,
            'success': final_success,
            'gates_passed': gates_passed
        })

        return {
            'success': final_success,
            'actions': action_results
        }

    async def _execute_action(self, action: Dict[str, Any]) -> Any:
        """Execute single action"""
        action_type = action['type']
        handler = self.action_handlers.get(action_type)
        if not handler:
            return {'success': False, 'error': f'No handler for action type: {action_type}'}
        try:
            return await handler(action.get('params', {}))
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _check_gates(self, gates: List[Dict[str, Any]], results: Dict[str, Any]) -> bool:
        """Check if all gates pass"""
        for gate in gates:
            if not self._evaluate_gate(gate, results):
                self._log_event('gate_failed', {'gate': gate['check']})
                return False
        return True

    def _evaluate_gate(self, gate: Dict[str, Any], results: Dict[str, Any]) -> bool:
        """Evaluate single gate condition against a specific action's result."""
        check = gate.get("check")
        action_id = gate.get("action_id")
        expected_value = gate.get("value", True)
        operator = gate.get("operator", "equals")

        if not action_id:
            self._log_event('gate_error', {'error': 'Gate missing action_id'})
            return False

        action_result = results.get(action_id)
        if not action_result or not isinstance(action_result, dict) or check not in action_result:
            return False

        actual_value = action_result[check]

        if operator == "equals":
            return actual_value == expected_value
        elif operator == "not_equals":
            return actual_value != expected_value
        elif operator == "contains":
            return expected_value in actual_value
        elif operator == "not_contains":
            return expected_value not in actual_value
        elif operator == "greater_than":
            return actual_value > expected_value
        elif operator == "less_than":
            return actual_value < expected_value
        else:
            self._log_event('gate_error', {'error': f'Unsupported operator: {operator}'})
            return False

    def _get_step_by_id(self, step_id: str) -> Optional[WorkflowStep]:
        for step in self.workflow.steps:
            if step.id == step_id:
                return step
        return None

    def _log_event(self, event_type: str, data: Dict[str, Any]) -> None:
        self.execution_log.append({
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': data
        })

    def register_action_handler(self, action_type: str, handler):
        self.action_handlers[action_type] = handler
