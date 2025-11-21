import unittest
from pathlib import Path
from openhands.microagents.core.registry import MicroagentRegistry
from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep, StepType

class TestRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = MicroagentRegistry()
        self.registry.clear()

    def test_singleton(self):
        registry2 = MicroagentRegistry()
        self.assertIs(self.registry, registry2)

    def test_register_context(self):
        cp = ContextProvider(
            name="test-context",
            domain="test",
            content="This is a test.",
            filepath=Path("/tmp/test.md"),
            checksum="12345"
        )
        self.registry.register_context(cp)
        self.assertEqual(len(self.registry.list_contexts()), 1)
        self.assertEqual(self.registry.get_context("test-context"), cp)

    def test_register_workflow(self):
        step = WorkflowStep(
            id="test-step",
            name="Test Step",
            type=StepType.VALIDATION,
            required=True,
            actions=[]
        )
        wc = WorkflowController(
            name="Test Workflow",
            version="1.0",
            description="A test workflow.",
            steps=[step],
            config={},
            error_handling={},
            exit_criteria={}
        )
        self.registry.register_workflow(wc)
        self.assertEqual(len(self.registry.list_workflows()), 1)
        self.assertEqual(self.registry.get_workflow("Test Workflow"), wc)

if __name__ == '__main__':
    unittest.main()
