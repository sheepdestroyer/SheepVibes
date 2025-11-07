from typing import Dict, Any, List
from openhands.microagents.providers.workflow import WorkflowExecutor
from openhands.microagents.integrations.github import GitHubClient
import subprocess
import git
import asyncio
import ast
import glob

class PRReviewWorkflow:
    """PR Review workflow implementation"""

    def __init__(
        self,
        repo: str,
        pr_number: int,
        github_token: str
    ):
        self.repo = repo
        self.pr_number = pr_number
        self.github = GitHubClient(github_token)
        self.executor = WorkflowExecutor("PR Review Workflow")
        self._register_action_handlers()
        self.git_repo = git.Repo('.')

    async def run(self) -> Dict[str, Any]:
        """Run complete PR review workflow"""
        pr_data = self.github.get_pr(self.repo, self.pr_number)

        self.executor.step_results['pr_data'] = pr_data

        result = await self.executor.execute()

        if result['success']:
            await self._post_review(result)

        return result

    async def _post_review(self, result: Dict[str, Any]) -> None:
        """Post review results to GitHub"""
        summary_step_result = result.get('results', {}).get('generate_review_summary', {})
        review_summary = summary_step_result.get('actions', {}).get('generate_markdown_report', {}).get('report', 'No summary generated.')

        self.github.post_pr_comment(
            self.repo,
            self.pr_number,
            review_summary
        )

        labels = self._determine_labels(result)
        if labels:
            self.github.add_labels(self.repo, self.pr_number, labels)

        recommendation = summary_step_result.get('actions', [{}])[0].get('recommendation')
        if recommendation == 'approve':
            self.github.approve_pr(self.repo, self.pr_number)
        elif recommendation == 'request_changes':
            self.github.request_changes(self.repo, self.pr_number, "Changes requested based on automated review.")

    def _determine_labels(self, result: Dict[str, Any]) -> List[str]:
        """Determine labels based on workflow result"""
        labels = ["reviewed"]
        analyze_step_result = result.get('results', {}).get('analyze_changes', {})
        change_category = analyze_step_result.get('actions', {}).get('categorize_changes', {}).get('category')
        if change_category:
            labels.append(change_category)
        return labels

    def _register_action_handlers(self):
        """Register all action handlers for the PR review workflow"""
        handlers = {
            "read_pr_metadata": self.read_pr_metadata,
            "read_pr_description": self.read_pr_description,
            "check_merge_status": self.check_merge_status,
            "fetch_diff": self.fetch_diff,
            "identify_changed_files": self.identify_changed_files,
            "categorize_changes": self.categorize_changes,
            "calculate_complexity": self.calculate_complexity,
            "run_linters": self.run_linters,
            "check_test_coverage": self.check_test_coverage,
            "detect_code_smells": self.detect_code_smells,
            "check_naming_conventions": self.check_naming_conventions,
            "verify_documentation": self.verify_documentation,
            "scan_dependencies": self.scan_dependencies,
            "detect_secrets": self.detect_secrets,
            "check_sql_injection": self.check_sql_injection,
            "check_xss_vulnerabilities": self.check_xss_vulnerabilities,
            "validate_input_sanitization": self.validate_input_sanitization,
            "check_design_patterns": self.check_design_patterns,
            "validate_separation_of_concerns": self.validate_separation_of_concerns,
            "review_api_design": self.review_api_design,
            "check_dependency_direction": self.check_dependency_direction,
            "validate_error_handling": self.validate_error_handling,
            "review_performance_implications": self.review_performance_implications,
            "analyze_logic": self.analyze_logic,
            "check_edge_cases": self.check_edge_cases,
            "validate_error_scenarios": self.validate_error_scenarios,
            "review_test_cases": self.review_test_cases,
            "check_business_logic": self.check_business_logic,
            "check_breaking_changes": self.check_breaking_changes,
            "validate_api_versioning": self.validate_api_versioning,
            "check_migration_path": self.check_migration_path,
            "verify_deprecation_notices": self.verify_deprecation_notices,
            "check_code_comments": self.check_code_comments,
            "validate_readme_updates": self.validate_readme_updates,
            "check_changelog_entry": self.check_changelog_entry,
            "verify_api_docs": self.verify_api_docs,
            "validate_migration_guides": self.validate_migration_guides,
            "aggregate_findings": self.aggregate_findings,
            "generate_markdown_report": self.generate_markdown_report,
            "calculate_review_score": self.calculate_review_score,
            "post_github_comment": self.post_github_comment,
            "add_inline_comments": self.add_inline_comments,
            "set_pr_labels": self.set_pr_labels,
            "request_changes_if_needed": self.request_changes_if_needed,
            "approve_if_passing": self.approve_if_passing,
            "update_workflow_state": self.update_workflow_state,
            "send_notification": self.send_notification,
            "log_metrics": self.log_metrics,
        }
        for action_type, handler in handlers.items():
            self.executor.register_action_handler(action_type, handler)

    async def fetch_diff(self, params):
        """Fetches the diff of the pull request."""
        pr_data = self.executor.step_results.get('pr_data')
        if not pr_data:
            return {"success": False, "error": "PR data not found"}

        base_ref = pr_data.get('base', {}).get('ref')
        head_sha = pr_data.get('head', {}).get('sha')

        if not (base_ref and head_sha):
            return {"success": False, "error": "Base or head ref not found in PR data"}

        if self.github.dummy_mode:
            head_sha = self.git_repo.head.commit.hexsha
            base_ref = 'main'  # Assume 'main' for local simulation

        try:
            # Ensure remotes are up-to-date
            if not self.github.dummy_mode:
                self.git_repo.remotes.origin.fetch()
                merge_base = self.git_repo.merge_base(f'origin/{base_ref}', head_sha)
            else:
                merge_base = [self.git_repo.commit(base_ref)]

            if not merge_base:
                return {"success": False, "error": "Could not find merge base"}

            diff = self.git_repo.git.diff(merge_base[0].hexsha, head_sha)
            return {"success": True, "diff": diff}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_linters(self, params):
        """Runs linters asynchronously."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ruff", "check", "openhands",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                return {"success": False, "lint_passed": False, "error": stderr.decode()}
            return {"success": True, "lint_passed": True}
        except FileNotFoundError as e:
            return {"success": False, "lint_passed": False, "error": str(e)}

    async def scan_dependencies(self, params):
        """Scans dependencies for vulnerabilities asynchronously."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "safety", "check",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                return {"success": False, "vulnerabilities": [], "error": stderr.decode()}
            return {"success": True, "vulnerabilities": []}
        except FileNotFoundError as e:
            return {"success": False, "vulnerabilities": [], "error": str(e)}

    async def detect_code_smells(self, params):
        """Detects code smells asynchronously."""
        try:
            # Check for long lines, TODOs, and FIXMEs using ruff
            proc = await asyncio.create_subprocess_exec(
                "ruff", "check", "openhands", "--select", "E501,T101",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0 and stdout:
                smells = stdout.decode().strip().split('\n')
                return {"success": True, "smells": smells}
            elif proc.returncode != 0:
                return {"success": False, "error": stderr.decode()}
            return {"success": True, "smells": []}
        except FileNotFoundError as e:
            return {"success": False, "error": str(e)}

    async def analyze_logic(self, params):
        """Analyzes logic asynchronously."""
        logic_issues = []

        class LogicAnalyzer(ast.NodeVisitor):
            def visit_If(self, node):
                if isinstance(node.test, ast.BoolOp):
                    logic_issues.append(f"Complex boolean expression at line {node.lineno}")
                self.generic_visit(node)

        try:
            for filepath in glob.glob("openhands/**/*.py", recursive=True):
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    tree = ast.parse(content)
                    analyzer = LogicAnalyzer()
                    analyzer.visit(tree)
            return {"success": True, "logic_issues": logic_issues}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # Placeholder Action Handlers
    async def read_pr_metadata(self, params): return {"success": True, "metadata": "..."}
    async def read_pr_description(self, params): return {"success": True, "description": "..."}
    async def check_merge_status(self, params): return {"success": True, "mergeable": True}
    async def identify_changed_files(self, params): return {"success": True, "files": []}
    async def categorize_changes(self, params): return {"success": True, "category": "feature"}
    async def calculate_complexity(self, params): return {"success": True, "score": 10}
    async def check_test_coverage(self, params): return {"success": True, "coverage": 90}
    async def check_naming_conventions(self, params): return {"success": True, "conventions_ok": True}
    async def verify_documentation(self, params): return {"success": True, "docs_ok": True}
    async def detect_secrets(self, params): return {"success": True, "secrets": []}
    async def check_sql_injection(self, params): return {"success": True, "sql_injection_ok": True}
    async def check_xss_vulnerabilities(self, params): return {"success": True, "xss_ok": True}
    async def validate_input_sanitization(self, params): return {"success": True, "sanitization_ok": True}
    async def check_design_patterns(self, params): return {"success": True, "patterns_ok": True}
    async def validate_separation_of_concerns(self, params): return {"success": True, "soc_ok": True}
    async def review_api_design(self, params): return {"success": True, "api_design_ok": True}
    async def check_dependency_direction(self, params): return {"success": True, "dep_direction_ok": True}
    async def validate_error_handling(self, params): return {"success": True, "error_handling_ok": True}
    async def review_performance_implications(self, params): return {"success": True, "perf_ok": True}
    async def check_edge_cases(self, params): return {"success": True, "edge_cases_ok": True}
    async def validate_error_scenarios(self, params): return {"success": True, "error_scenarios_ok": True}
    async def review_test_cases(self, params): return {"success": True, "tests_ok": True}
    async def check_business_logic(self, params): return {"success": True, "business_logic_ok": True}
    async def check_breaking_changes(self, params): return {"success": True, "breaking_changes": []}
    async def validate_api_versioning(self, params): return {"success": True, "versioning_ok": True}
    async def check_migration_path(self, params): return {"success": True, "migration_path_ok": True}
    async def verify_deprecation_notices(self, params): return {"success": True, "deprecation_ok": True}
    async def check_code_comments(self, params): return {"success": True, "comments_ok": True}
    async def validate_readme_updates(self, params): return {"success": True, "readme_ok": True}
    async def check_changelog_entry(self, params): return {"success": True, "changelog_ok": True}
    async def verify_api_docs(self, params): return {"success": True, "api_docs_ok": True}
    async def validate_migration_guides(self, params): return {"success": True, "migration_guides_ok": True}
    async def aggregate_findings(self, params): return {"success": True, "findings": "..."}
    async def generate_markdown_report(self, params): return {"success": True, "report": "..."}
    async def calculate_review_score(self, params): return {"success": True, "score": 95, "recommendation": "approve"}
    async def post_github_comment(self, params): return {"success": True}
    async def add_inline_comments(self, params): return {"success": True}
    async def set_pr_labels(self, params): return {"success": True}
    async def request_changes_if_needed(self, params): return {"success": True}
    async def approve_if_passing(self, params): return {"success": True}
    async def update_workflow_state(self, params): return {"success": True}
    async def send_notification(self, params): return {"success": True}
    async def log_metrics(self, params): return {"success": True}
