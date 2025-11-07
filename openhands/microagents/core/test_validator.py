import pytest
from pathlib import Path
from openhands.microagents.core.validator import MicroagentValidator, ValidationError
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep, StepType

@pytest.fixture
def validator():
    return MicroagentValidator()

@pytest.fixture
def valid_step():
    return WorkflowStep(id="step1", name="Step 1", type=StepType.ACTION, required=True, actions=[])

def test_valid_path_with_cycle(validator, valid_step):
    steps = [
        valid_step,
        WorkflowStep(id="step2", name="Step 2", type=StepType.ACTION, required=True, actions=[], on_success="step3"),
        WorkflowStep(id="step3", name="Step 3", type=StepType.ACTION, required=True, actions=[], on_success="step2"),
    ]
    assert not validator._forms_valid_path(steps)

def test_valid_path_no_cycle(validator, valid_step):
    steps = [
        valid_step,
        WorkflowStep(id="step2", name="Step 2", type=StepType.ACTION, required=True, actions=[], on_success="step3"),
        WorkflowStep(id="step3", name="Step 3", type=StepType.ACTION, required=True, actions=[]),
    ]
    assert validator._forms_valid_path(steps)
