from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum

class StepType(Enum):
    VALIDATION = "validation"
    ANALYSIS = "analysis"
    SECURITY = "security"
    ACTION = "action"
    REPORT = "report"
    COMPLETION = "completion"

@dataclass
class WorkflowStep:
    id: str
    name: str
    type: StepType
    required: bool
    actions: List[Dict[str, Any]]
    gates: Optional[List[Dict[str, Any]]] = None
    on_success: Optional[str] = None
    on_failure: Optional[str] = None

@dataclass
class WorkflowController:
    name: str
    version: str
    description: str
    steps: List[WorkflowStep]
    config: Dict[str, Any]
    error_handling: Dict[str, Any]
    exit_criteria: Dict[str, Any]
