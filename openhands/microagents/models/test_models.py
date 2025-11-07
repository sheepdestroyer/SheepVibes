import unittest
from pathlib import Path
from openhands.microagents.models.context_model import ContextProvider
from openhands.microagents.models.workflow_model import WorkflowController, WorkflowStep, StepType
from openhands.microagents.models.config_model import MicroagentConfig

class TestModels(unittest.TestCase):

    def test_context_provider(self):
        cp = ContextProvider(
            name="test-context",
            domain="test",
            content="This is a test.",
            filepath=Path("/tmp/test.md"),
            checksum="12345"
        )
        self.assertEqual(cp.name, "test-context")
        self.assertEqual(cp.priority, 100)

    def test_workflow_controller(self):
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
        self.assertEqual(wc.name, "Test Workflow")
        self.assertEqual(len(wc.steps), 1)

    def test_microagent_config(self):
        mc = MicroagentConfig()
        self.assertEqual(mc.version, "2.0")
        self.assertTrue(mc.enable_caching)

if __name__ == '__main__':
    unittest.main()
