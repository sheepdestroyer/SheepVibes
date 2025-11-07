# OpenHands Microagent System - Complete Rewrite Plan

## Executive Summary

This document outlines a comprehensive rewrite of the OpenHands microagent system to address: complexity, inconsistency, duplication, unclear organization, and lack of strict PR review workflow enforcement.

**Goals:**
1. **Simplification**: Reduce cognitive load and make the system intuitive
2. **Consistency**: Unified patterns across all microagent types
3. **Deduplication**: Single source of truth for all functionality
4. **Clear Organization**: Logical module hierarchy with clear responsibilities
5. **PR Review Compliance**: Enforced step-by-step workflow cycle

---

## Current State Analysis

### Critical Issues Identified

1. **Excessive Complexity**
   - Multiple trigger mechanisms (always, keyword, manual) with inconsistent loading
   - Confusion between `.openhands/microagents/` and `OpenHands/microagents/`
   - Legacy `.openhands_instructions` coexisting with new system
   - Markdown + YAML frontmatter adds unnecessary parsing complexity

2. **Duplication Problems**
   - Same microagent can be triggered multiple times (user + agent messages)
   - No deduplication mechanism for repeated triggers
   - RecallAction creates duplicate observations
   - Multiple loading points in codebase (runtime, resolver, controller)

3. **Organizational Issues**
   - No clear separation between repository vs. organizational vs. public microagents
   - `knowledge/` and `tasks/` distinction is unclear
   - Microagent hub management is scattered
   - No versioning or dependency management

4. **PR Review Workflow Gap**
   - No enforced step-by-step review cycle
   - PR review microagent exists but isn't mandatory
   - No validation gates for review completion
   - Missing integration with GitHub Actions workflow

---

## Proposed Architecture

### 1. Simplified Type System

**BEFORE** (3 types with complex triggers):
- `always` - repository guidelines
- `keyword` - triggered by keywords  
- `manual` - user-activated workflows

**AFTER** (2 types with clear purposes):

#### Type A: Context Providers
- **Purpose**: Provide static knowledge/guidelines
- **Loading**: Loaded once at session start
- **Format**: Simple markdown (no frontmatter needed)
- **Location**: `.openhands/context/<domain>.md`
- **Examples**: `repo.md`, `style-guide.md`, `architecture.md`

#### Type B: Workflow Controllers
- **Purpose**: Multi-step interactive processes
- **Loading**: Explicitly invoked by user or automation
- **Format**: YAML workflow definition + markdown content
- **Location**: `.openhands/workflows/<workflow-name>.yml`
- **Examples**: `pr-review.yml`, `bug-fix.yml`, `feature-implementation.yml`

### 2. Unified Directory Structure

```
.openhands/
├── context/                    # Context Providers (Type A)
│   ├── repo.md                # General repository info (always loaded)
│   ├── coding-standards.md    # Code style guidelines
│   ├── architecture.md        # System architecture
│   └── dependencies.md        # Dependency management rules
│
├── workflows/                  # Workflow Controllers (Type B)
│   ├── pr-review.yml          # PR review process
│   ├── pr-review.md           # PR review instructions
│   ├── bug-fix.yml            # Bug fixing workflow
│   ├── bug-fix.md             # Bug fixing instructions
│   ├── feature.yml            # Feature implementation
│   └── feature.md             # Feature instructions
│
├── config.yml                  # Microagent system configuration
└── .microagent-cache/          # Runtime cache (gitignored)
    ├── loaded-contexts.json
    └── workflow-states.json
```

### 3. Core Module Reorganization

```
openhands/
├── microagents/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── loader.py           # Single loading entry point
│   │   ├── registry.py         # Central microagent registry
│   │   ├── cache.py            # Deduplication & caching
│   │   └── validator.py        # Schema validation
│   │
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── context.py          # Context provider implementation
│   │   └── workflow.py         # Workflow controller implementation
│   │
│   ├── workflows/
│   │   ├── __init__.py
│   │   ├── base.py             # Base workflow class
│   │   ├── pr_review.py        # PR review workflow
│   │   ├── bug_fix.py          # Bug fix workflow
│   │   └── feature.py          # Feature workflow
│   │
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── github.py           # GitHub integration
│   │   ├── gitlab.py           # GitLab integration
│   │   └── runtime.py          # Runtime integration
│   │
│   └── models/
│       ├── __init__.py
│       ├── context_model.py    # Context provider model
│       ├── workflow_model.py   # Workflow controller model
│       └── config_model.py     # Configuration model
│
└── ...existing openhands structure...
```

---

## PR Review Workflow - Detailed Specification

### Mandatory PR Review Cycle

The PR review workflow is a **strict, sequential, gate-enforced process** that must complete all steps:

```yaml
# .openhands/workflows/pr-review.yml
version: "2.0"
name: "PR Review Workflow"
description: "Comprehensive PR review with mandatory gates"
type: "workflow"

trigger:
  events:
    - pull_request.opened
    - pull_request.synchronize
    - manual_invoke

config:
  enforce_gates: true          # Prevent skipping steps
  require_completion: true     # Must complete all steps
  allow_parallel: false        # Sequential execution only
  timeout_minutes: 60          # Max workflow duration
  auto_comment: true           # Post review comments

steps:
  # Step 1: Pre-Flight Checks
  - id: "preflight"
    name: "Pre-Flight Validation"
    type: "validation"
    required: true
    gates:
      - check: "pr_description_exists"
        message: "PR must have a description"
      - check: "no_merge_conflicts"
        message: "PR has unresolved merge conflicts"
      - check: "base_branch_valid"
        message: "PR base branch must be main/master/develop"
    actions:
      - type: "read_pr_metadata"
      - type: "read_pr_description"
      - type: "check_merge_status"
    on_failure:
      action: "block"
      message: "Pre-flight checks failed. Cannot proceed with review."
    on_success: "analyze_changes"

  # Step 2: Change Analysis
  - id: "analyze_changes"
    name: "Analyze PR Changes"
    type: "analysis"
    required: true
    actions:
      - type: "fetch_diff"
        params:
          include_context: 3
      - type: "identify_changed_files"
      - type: "categorize_changes"
        categories:
          - "feature"
          - "bugfix"
          - "refactor"
          - "docs"
          - "tests"
          - "config"
      - type: "calculate_complexity"
        metrics:
          - "lines_changed"
          - "files_modified"
          - "cyclomatic_complexity"
    outputs:
      - "diff_content"
      - "changed_files"
      - "change_category"
      - "complexity_score"
    on_success:
      next_step: "code_quality"

  # Step 3: Code Quality Check
  - id: "code_quality"
    name: "Code Quality Analysis"
    type: "analysis"
    required: true
    actions:
      - type: "run_linters"
        tools:
          - "ruff"
          - "mypy"
          - "eslint"
          - "prettier"
      - type: "check_test_coverage"
        minimum_coverage: 80
      - type: "detect_code_smells"
        checks:
          - "long_functions"
          - "duplicate_code"
          - "complex_conditionals"
          - "magic_numbers"
      - type: "check_naming_conventions"
      - type: "verify_documentation"
    gates:
      - check: "linters_pass"
        severity: "error"
      - check: "coverage_threshold"
        severity: "warning"
      - check: "no_critical_smells"
        severity: "error"
    on_failure:
      action: "request_changes"
      next_step: "report_findings"
    on_success:
      next_step: "security_scan"

  # Step 4: Security Scan
  - id: "security_scan"
    name: "Security Vulnerability Scan"
    type: "security"
    required: true
    actions:
      - type: "scan_dependencies"
        tools:
          - "safety"
          - "npm-audit"
      - type: "detect_secrets"
        patterns:
          - "api_keys"
          - "passwords"
          - "tokens"
          - "private_keys"
      - type: "check_sql_injection"
      - type: "check_xss_vulnerabilities"
      - type: "validate_input_sanitization"
    gates:
      - check: "no_high_severity_vulns"
        severity: "error"
      - check: "no_hardcoded_secrets"
        severity: "error"
    on_failure:
      action: "block"
      message: "Security vulnerabilities detected. Review cannot proceed."
      next_step: "report_findings"
    on_success:
      next_step: "architectural_review"

  # Step 5: Architectural Review
  - id: "architectural_review"
    name: "Architecture & Design Review"
    type: "analysis"
    required: true
    actions:
      - type: "check_design_patterns"
      - type: "validate_separation_of_concerns"
      - type: "review_api_design"
      - type: "check_dependency_direction"
      - type: "validate_error_handling"
      - type: "review_performance_implications"
    context_files:
      - ".openhands/context/architecture.md"
      - ".openhands/context/design-principles.md"
    gates:
      - check: "follows_architecture_guidelines"
        severity: "warning"
      - check: "maintains_clean_architecture"
        severity: "warning"
    on_success:
      next_step: "functional_review"

  # Step 6: Functional Review
  - id: "functional_review"
    name: "Functional Correctness Review"
    type: "analysis"
    required: true
    actions:
      - type: "analyze_logic"
      - type: "check_edge_cases"
      - type: "validate_error_scenarios"
      - type: "review_test_cases"
        requirements:
          - "happy_path_covered"
          - "edge_cases_covered"
          - "error_cases_covered"
      - type: "check_business_logic"
    gates:
      - check: "logic_is_sound"
        severity: "error"
      - check: "adequate_test_coverage"
        severity: "error"
    on_success:
      next_step: "compatibility_check"

  # Step 7: Compatibility Check
  - id: "compatibility_check"
    name: "Backwards Compatibility Check"
    type: "validation"
    required: true
    actions:
      - type: "check_breaking_changes"
      - type: "validate_api_versioning"
      - type: "check_migration_path"
      - type: "verify_deprecation_notices"
    gates:
      - check: "no_unhandled_breaking_changes"
        severity: "error"
    on_success:
      next_step: "documentation_review"

  # Step 8: Documentation Review
  - id: "documentation_review"
    name: "Documentation Review"
    type: "analysis"
    required: true
    actions:
      - type: "check_code_comments"
        requirements:
          - "complex_logic_commented"
          - "public_apis_documented"
      - type: "validate_readme_updates"
      - type: "check_changelog_entry"
      - type: "verify_api_docs"
      - type: "validate_migration_guides"
    gates:
      - check: "documentation_complete"
        severity: "warning"
    on_success:
      next_step: "generate_review_summary"

  # Step 9: Generate Review Summary
  - id: "generate_review_summary"
    name: "Generate Review Summary"
    type: "report"
    required: true
    actions:
      - type: "aggregate_findings"
        inputs:
          - "preflight"
          - "analyze_changes"
          - "code_quality"
          - "security_scan"
          - "architectural_review"
          - "functional_review"
          - "compatibility_check"
          - "documentation_review"
      - type: "generate_markdown_report"
        template: ".openhands/workflows/pr-review-report.md"
      - type: "calculate_review_score"
        weights:
          code_quality: 0.25
          security: 0.25
          architecture: 0.20
          functionality: 0.20
          documentation: 0.10
    outputs:
      - "review_summary"
      - "overall_score"
      - "recommendation"
    on_success:
      next_step: "post_review"

  # Step 10: Post Review
  - id: "post_review"
    name: "Post Review Results"
    type: "action"
    required: true
    actions:
      - type: "post_github_comment"
        content: "${review_summary}"
      - type: "add_inline_comments"
        findings: "${all_findings}"
      - type: "set_pr_labels"
        labels:
          - "reviewed"
          - "${change_category}"
      - type: "request_changes_if_needed"
        condition: "${overall_score < 70}"
      - type: "approve_if_passing"
        condition: "${overall_score >= 80}"
    on_complete:
      next_step: "workflow_complete"

  # Step 11: Workflow Complete
  - id: "workflow_complete"
    name: "Review Workflow Complete"
    type: "completion"
    required: true
    actions:
      - type: "update_workflow_state"
        state: "completed"
      - type: "send_notification"
        recipients:
          - "pr_author"
          - "code_reviewers"
      - type: "log_metrics"
        metrics:
          - "total_duration"
          - "steps_completed"
          - "issues_found"
          - "final_score"

# Error handling for entire workflow
error_handling:
  on_step_failure:
    action: "pause"
    notification: true
    retry_policy:
      max_attempts: 3
      backoff: "exponential"
  
  on_timeout:
    action: "abort"
    message: "Workflow exceeded timeout limit"
    
  on_critical_error:
    action: "abort"
    notification: true
    rollback: true

# Workflow exit criteria
exit_criteria:
  auto_approve:
    conditions:
      - "overall_score >= 95"
      - "no_security_issues"
      - "all_tests_pass"
    
  request_changes:
    conditions:
      - "overall_score < 70"
      - "security_issues_found"
      - "critical_quality_issues"
  
  comment_only:
    conditions:
      - "overall_score >= 70 AND overall_score < 95"
      - "only_warning_level_issues"
```

---

## Step-by-Step Implementation Plan

### Phase 1: Foundation & Core Infrastructure (Week 1-2)

#### Task 1.1: Create New Module Structure
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Estimated Duration**: 2 days

**Detailed Steps**:
1. Create new directory structure:
   ```bash
   mkdir -p openhands/microagents/{core,providers,workflows,integrations,models}
   touch openhands/microagents/__init__.py
   touch openhands/microagents/core/{__init__.py,loader.py,registry.py,cache.py,validator.py}
   touch openhands/microagents/providers/{__init__.py,context.py,workflow.py}
   touch openhands/microagents/workflows/{__init__.py,base.py,pr_review.py}
   touch openhands/microagents/integrations/{__init__.py,github.py,runtime.py}
   touch openhands/microagents/models/{__init__.py,context_model.py,workflow_model.py,config_model.py}
   ```

2. Initialize each `__init__.py` with proper exports

3. Add module docstrings to every file explaining purpose

4. Create `openhands/microagents/README.md` with architecture overview

5. Add type stubs: `touch openhands/microagents/py.typed`

**Acceptance Criteria**:
- [ ] All directories created
- [ ] All `__init__.py` files initialized
- [ ] Module imports work correctly
- [ ] No circular dependencies
- [ ] Type checking passes with mypy

**Validation Command**:
```bash
python -c "from openhands.microagents import core, providers, workflows, integrations, models; print('✓ All modules importable')"
mypy openhands/microagents --strict
```

---

#### Task 1.2: Implement Data Models
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Dependencies**: Task 1.1  
**Estimated Duration**: 3 days

**Detailed Steps**:

1. **Implement `context_model.py`**:
   ```python
   # openhands/microagents/models/context_model.py
   from dataclasses import dataclass
   from typing import Optional
   from pathlib import Path
   
   @dataclass(frozen=True)
   class ContextProvider:
       """Immutable context provider model"""
       name: str
       domain: str
       content: str
       filepath: Path
       checksum: str  # For cache validation
       priority: int = 100  # Higher = loaded first
       
       def __post_init__(self):
           # Validation logic
           pass
   ```

2. **Implement `workflow_model.py`**:
   ```python
   # openhands/microagents/models/workflow_model.py
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
   ```

3. **Implement `config_model.py`**:
   ```python
   # openhands/microagents/models/config_model.py
   from dataclasses import dataclass
   from typing import Optional, List
   
   @dataclass
   class MicroagentConfig:
       version: str = "2.0"
       enable_caching: bool = True
       cache_ttl_seconds: int = 3600
       max_context_tokens: int = 50000
       enabled_workflows: List[str] = None
       disabled_contexts: List[str] = None
       strict_mode: bool = True  # Enforce all validations
   ```

4. Add comprehensive unit tests for all models

5. Add JSON schema generation for validation

**Acceptance Criteria**:
- [ ] All models implemented with type hints
- [ ] Immutability enforced where appropriate
- [ ] Validation logic implemented
- [ ] Unit tests achieve >95% coverage
- [ ] Models are serializable to JSON/YAML
- [ ] Documentation strings complete

**Validation Command**:
```bash
pytest tests/unit/microagents/models/ -v --cov=openhands/microagents/models --cov-report=term-missing
```

---

#### Task 1.3: Build Central Registry
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Dependencies**: Task 1.2  
**Estimated Duration**: 2 days

**Detailed Steps**:

1. **Implement `registry.py`**:
   ```python
   # openhands/microagents/core/registry.py
   from typing import Dict, List, Optional
   from openhands.microagents.models import ContextProvider, WorkflowController
   import threading
   
   class MicroagentRegistry:
       """Thread-safe singleton registry for all microagents"""
       _instance = None
       _lock = threading.Lock()
       
       def __new__(cls):
           if cls._instance is None:
               with cls._lock:
                   if cls._instance is None:
                       cls._instance = super().__new__(cls)
                       cls._instance._initialize()
           return cls._instance
       
       def _initialize(self):
           self._contexts: Dict[str, ContextProvider] = {}
           self._workflows: Dict[str, WorkflowController] = {}
           self._loaded = False
       
       def register_context(self, context: ContextProvider) -> None:
           """Register a context provider (idempotent)"""
           if context.name in self._contexts:
               # Check if content changed via checksum
               existing = self._contexts[context.name]
               if existing.checksum != context.checksum:
                   self._contexts[context.name] = context
           else:
               self._contexts[context.name] = context
       
       def register_workflow(self, workflow: WorkflowController) -> None:
           """Register a workflow controller (idempotent)"""
           self._workflows[workflow.name] = workflow
       
       def get_context(self, name: str) -> Optional[ContextProvider]:
           return self._contexts.get(name)
       
       def get_workflow(self, name: str) -> Optional[WorkflowController]:
           return self._workflows.get(name)
       
       def list_contexts(self) -> List[ContextProvider]:
           return sorted(
               self._contexts.values(),
               key=lambda c: c.priority,
               reverse=True
           )
       
       def list_workflows(self) -> List[WorkflowController]:
           return list(self._workflows.values())
       
       def clear(self) -> None:
           """Clear all registrations (for testing)"""
           self._contexts.clear()
           self._workflows.clear()
           self._loaded = False
   ```

2. Add thread-safety tests

3. Add registration deduplication tests

4. Document singleton pattern usage

**Acceptance Criteria**:
- [ ] Registry is truly singleton
- [ ] Thread-safe registration
- [ ] Deduplication works correctly
- [ ] Clear method works for testing
- [ ] All methods documented

---

#### Task 1.4: Implement Caching & Deduplication
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Dependencies**: Task 1.3  
**Estimated Duration**: 3 days

**Detailed Steps**:

1. **Implement `cache.py`**:
   ```python
   # openhands/microagents/core/cache.py
   import hashlib
   import json
   from pathlib import Path
   from typing import Optional, Any, Dict
   from datetime import datetime, timedelta
   
   class MicroagentCache:
       """File-based cache with TTL and deduplication"""
       
       def __init__(self, cache_dir: Path, ttl_seconds: int = 3600):
           self.cache_dir = cache_dir
           self.cache_dir.mkdir(parents=True, exist_ok=True)
           self.ttl = timedelta(seconds=ttl_seconds)
           self._memory_cache: Dict[str, Any] = {}
       
       def _get_cache_key(self, content: str) -> str:
           """Generate deterministic cache key"""
           return hashlib.sha256(content.encode()).hexdigest()
       
       def _get_cache_path(self, cache_key: str) -> Path:
           return self.cache_dir / f"{cache_key}.json"
       
       def get(self, content: str) -> Optional[Any]:
           """Get cached value if valid"""
           cache_key = self._get_cache_key(content)
           
           # Check memory cache first
           if cache_key in self._memory_cache:
               return self._memory_cache[cache_key]
           
           # Check file cache
           cache_path = self._get_cache_path(cache_key)
           if not cache_path.exists():
               return None
           
           try:
               with open(cache_path) as f:
                   cached = json.load(f)
               
               # Check TTL
               cached_time = datetime.fromisoformat(cached['timestamp'])
               if datetime.now() - cached_time > self.ttl:
                   cache_path.unlink()  # Expired
                   return None
               
               # Populate memory cache
               value = cached['value']
               self._memory_cache[cache_key] = value
               return value
           except Exception:
               return None
       
       def set(self, content: str, value: Any) -> None:
           """Cache value with timestamp"""
           cache_key = self._get_cache_key(content)
           cache_path = self._get_cache_path(cache_key)
           
           # Update memory cache
           self._memory_cache[cache_key] = value
           
           # Update file cache
           with open(cache_path, 'w') as f:
               json.dump({
                   'timestamp': datetime.now().isoformat(),
                   'value': value
               }, f)
       
       def invalidate(self, content: str) -> None:
           """Invalidate specific cache entry"""
           cache_key = self._get_cache_key(content)
           self._memory_cache.pop(cache_key, None)
           cache_path = self._get_cache_path(cache_key)
           if cache_path.exists():
               cache_path.unlink()
       
       def clear_all(self) -> None:
           """Clear entire cache"""
           self._memory_cache.clear()
           for cache_file in self.cache_dir.glob("*.json"):
               cache_file.unlink()
   ```

2. Implement deduplication logic for trigger events

3. Add cache warming for frequently used contexts

4. Add cache eviction policies (LRU)

5. Add comprehensive tests

**Acceptance Criteria**:
- [ ] Cache prevents redundant processing
- [ ] TTL works correctly
- [ ] Memory + file caching functional
- [ ] Deduplication prevents duplicate triggers
- [ ] Cache survives process restarts
- [ ] Tests cover edge cases

---

### Phase 2: Loader & Validator Implementation (Week 3)

#### Task 2.1: Build Universal Loader
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Dependencies**: Task 1.4  
**Estimated Duration**: 3 days

**Detailed Steps**:

1. **Implement `loader.py`** - Single entry point for all loading:
   ```python
   # openhands/microagents/core/loader.py
   from pathlib import Path
   from typing import List, Optional
   import yaml
   from openhands.microagents.core.registry import MicroagentRegistry
   from openhands.microagents.core.cache import MicroagentCache
   from openhands.microagents.core.validator import MicroagentValidator
   from openhands.microagents.models import ContextProvider, WorkflowController
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
           
           # Check cache
           if self.cache:
               cached = self.cache.get(content)
               if cached:
                   self.registry.register_context(cached)
                   return
           
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
           
           # Cache
           if self.cache:
               self.cache.set(content, context)
       
       def _load_workflow_file(self, filepath: Path) -> None:
           """Load single workflow controller"""
           content = filepath.read_text()
           
           # Check cache
           if self.cache:
               cached = self.cache.get(content)
               if cached:
                   self.registry.register_workflow(cached)
                   return
           
           # Parse YAML
           data = yaml.safe_load(content)
           
           # Create workflow controller
           workflow = WorkflowController(
               name=data['name'],
               version=data['version'],
               description=data['description'],
               steps=[self._parse_step(s) for s in data['steps']],
               config=data.get('config', {}),
               error_handling=data.get('error_handling', {}),
               exit_criteria=data.get('exit_criteria', {})
           )
           
           # Validate
           self.validator.validate_workflow(workflow)
           
           # Register
           self.registry.register_workflow(workflow)
           
           # Cache
           if self.cache:
               self.cache.set(content, workflow)
       
       def _parse_step(self, step_data: dict) -> 'WorkflowStep':
           """Parse workflow step from YAML"""
           # Implementation...
           pass
   ```

2. Remove ALL existing loading points in codebase:
   - Remove from `openhands/runtime/base.py`
   - Remove from `openhands/resolver/`
   - Remove from `openhands/controller/agent_controller.py`

3. Add single integration point in runtime initialization

4. Add comprehensive tests

**Acceptance Criteria**:
- [ ] Single loader instance per session
- [ ] All microagents loaded through loader
- [ ] Old loading code removed
- [ ] No duplicate loading
- [ ] Caching works correctly
- [ ] Error handling comprehensive

---

#### Task 2.2: Implement Validation System
**Owner**: OpenHands Agent  
**Priority**: P0 (Blocking)  
**Dependencies**: Task 2.1  
**Estimated Duration**: 2 days

**Detailed Steps**:

1. **Implement `validator.py`**:
   ```python
   # openhands/microagents/core/validator.py
   from openhands.microagents.models import ContextProvider, WorkflowController
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
           if not re.match(r'^\d+\.\d+(\.\d+)?$', workflow.version):
               errors.append(f"Invalid version: {workflow.version}")
           
           # Steps validation
           if not workflow.steps:
               errors.append("Workflow has no steps")
           
           step_ids = [s.id for s in workflow.steps]
           if len(step_ids) != len(set(step_ids)):
               errors.append("Duplicate step IDs found")
           
           # Validate step references
           for step in workflow.steps:
               if step.on_success and step.on_success not in step_ids:
                   errors.append(f"Invalid on_success reference: {step.on_success}")
               if step.on_failure and step.on_failure not in step_ids:
                   errors.append(f"Invalid on_failure reference: {step.on_failure}")
           
           # Validate required steps form a path
           required_steps = [s for s in workflow.steps if s.required]
           if not self._forms_valid_path(required_steps):
               errors.append("Required steps do not form a valid execution path")
           
           if errors:
               raise ValidationError("; ".join(errors))
       
       def _forms_valid_path(self, steps: List['WorkflowStep']) -> bool:
           """Check if required steps form a valid path"""
           # Graph validation logic
           pass
   ```

2. Add JSON schema validators

3. Add workflow graph validation (no cycles, all paths terminate)

4. Add comprehensive tests

**Acceptance Criteria**:
- [ ] All validation rules implemented
- [ ] Clear error messages
- [ ] Invalid configs rejected
- [ ] Graph validation works
- [ ] Tests cover all edge cases

---

### Phase 3: Provider Implementations (Week 4)

#### Task 3.1: Implement Context Provider
**Owner**: OpenHands Agent  
**Priority**: P1 (High)  
**Dependencies**: Task 2.2  
**Estimated Duration**: 2 days

**Detailed Steps**:

1. **Implement `context.py`**:
   ```python
   # openhands/microagents/providers/context.py
   from typing import List, Optional
   from openhands.microagents.core.registry import MicroagentRegistry
   from openhands.microagents.models import ContextProvider
   
   class ContextProviderService:
       """Service for accessing context providers"""
       
       def __init__(self):
           self.registry = MicroagentRegistry()
       
       def get_all_contexts(self) -> str:
           """Get all contexts as formatted string"""
           contexts = self.registry.list_contexts()
           return self._format_contexts(contexts)
       
       def get_context_by_domain(self, domain: str) -> Optional[str]:
           """Get specific context by domain"""
           context = self.registry.get_context(domain)
           return context.content if context else None
       
       def get_contexts_for_prompt(
           self,
           max_tokens: int = 50000
       ) -> str:
           """Get contexts optimized for LLM prompt"""
           contexts = self.registry.list_contexts()
           
           result = []
           token_count = 0
           
           for context in contexts:
               # Rough token estimation (1 token ≈ 4 chars)
               estimated_tokens = len(context.content) // 4
               
               if token_count + estimated_tokens > max_tokens:
                   break
               
               result.append(context.content)
               token_count += estimated_tokens
           
           return "\n\n---\n\n".join(result)
       
       def _format_contexts(self, contexts: List[ContextProvider]) -> str:
           """Format contexts for display"""
           sections = []
           for ctx in contexts:
               sections.append(
                   f"# {ctx.domain.upper()} Context\n\n{ctx.content}"
               )
           return "\n\n".join(sections)
   ```

2. Add context aggregation logic

3. Add token counting utilities

4. Add tests

**Acceptance Criteria**:
- [ ] Context retrieval works
- [ ] Token limits respected
- [ ] Formatting correct
- [ ] Tests complete

---

#### Task 3.2: Implement Workflow Controller
**Owner**: OpenHands Agent  
**Priority**: P1 (High)  
**Dependencies**: Task 3.1  
**Estimated Duration**: 4 days

**Detailed Steps**:

1. **Implement `workflow.py`**:
   ```python
   # openhands/microagents/providers/workflow.py
   from typing import Dict, Any, Optional
   from enum import Enum
   from openhands.microagents.models import WorkflowController, WorkflowStep
   from openhands.microagents.core.registry import MicroagentRegistry
   
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
       
       async def execute(self) -> Dict[str, Any]:
           """Execute entire workflow"""
           self.state = WorkflowState.IN_PROGRESS
           
           try:
               # Start from first step
               current_step = self.workflow.steps[0]
               
               while current_step:
                   result = await self._execute_step(current_step)
                   self.step_results[current_step.id] = result
                   
                   # Determine next step
                   if result['success']:
                       next_id = current_step.on_success
                   else:
                       next_id = current_step.on_failure
                   
                   if not next_id:
                       break
                   
                   current_step = self._get_step_by_id(next_id)
               
               self.state = WorkflowState.COMPLETED
               return {
                   'success': True,
                   'results': self.step_results,
                   'log': self.execution_log
               }
           
           except Exception as e:
               self.state = WorkflowState.FAILED
               return {
                   'success': False,
                   'error': str(e),
                   'log': self.execution_log
               }
       
       async def _execute_step(self, step: WorkflowStep) -> Dict[str, Any]:
           """Execute single workflow step"""
           self.current_step_id = step.id
           
           # Log step start
           self._log_event('step_start', {'step_id': step.id})
           
           # Execute actions
           action_results = []
           for action in step.actions:
               result = await self._execute_action(action)
               action_results.append(result)
           
           # Check gates
           gates_passed = True
           if step.gates:
               gates_passed = self._check_gates(step.gates, action_results)
           
           # Log step completion
           self._log_event('step_complete', {
               'step_id': step.id,
               'gates_passed': gates_passed
           })
           
           return {
               'success': gates_passed,
               'actions': action_results
           }
       
       async def _execute_action(self, action: Dict[str, Any]) -> Any:
           """Execute single action"""
           action_type = action['type']
           handler = self._get_action_handler(action_type)
           return await handler(action)
       
       def _check_gates(
           self,
           gates: List[Dict[str, Any]],
           results: List[Any]
       ) -> bool:
           """Check if all gates pass"""
           for gate in gates:
               if not self._evaluate_gate(gate, results):
                   return False
           return True
       
       def _evaluate_gate(self, gate: Dict[str, Any], results: List[Any]) -> bool:
           """Evaluate single gate condition"""
           # Gate evaluation logic
           pass
       
       def _get_action_handler(self, action_type: str):
           """Get handler for action type"""
           # Return appropriate handler function
           pass
       
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
   ```

2. Implement action handlers for all action types

3. Add gate evaluation logic

4. Add workflow state persistence

5. Add comprehensive tests

**Acceptance Criteria**:
- [ ] Workflow execution works end-to-end
- [ ] All gates evaluated correctly
- [ ] State management works
- [ ] Error handling robust
- [ ] Tests cover all paths

---

### Phase 4: PR Review Workflow Implementation (Week 5-6)

#### Task 4.1: Implement PR Review Workflow
**Owner**: OpenHands Agent  
**Priority**: P0 (Critical)  
**Dependencies**: Task 3.2  
**Estimated Duration**: 5 days

**Detailed Steps**:

1. **Implement `pr_review.py`**:
   ```python
   # openhands/microagents/workflows/pr_review.py
   from typing import Dict, Any, List
   from openhands.microagents.providers.workflow import WorkflowExecutor
   from openhands.integrations.github import GitHubClient
   
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
           self.executor = WorkflowExecutor("pr-review")
       
       async def run(self) -> Dict[str, Any]:
           """Run complete PR review workflow"""
           # Fetch PR data
           pr_data = await self.github.get_pr(self.repo, self.pr_number)
           
           # Execute workflow
           result = await self.executor.execute()
           
           # Post results
           if result['success']:
               await self._post_review(result)
           
           return result
       
       async def _post_review(self, result: Dict[str, Any]) -> None:
           """Post review results to GitHub"""
           # Generate review comment
           comment = self._generate_review_comment(result)
           
           # Post comment
           await self.github.post_pr_comment(
               self.repo,
               self.pr_number,
               comment
           )
           
           # Add labels
           labels = self._determine_labels(result)
           await self.github.add_labels(self.repo, self.pr_number, labels)
           
           # Approve or request changes
           score = result['results']['generate_review_summary']['overall_score']
           if score >= 80:
               await self.github.approve_pr(self.repo, self.pr_number)
           elif score < 70:
               await self.github.request_changes(self.repo, self.pr_number)
       
       def _generate_review_comment(self, result: Dict[str, Any]) -> str:
           """Generate markdown review comment"""
           # Template rendering logic
           pass
   ```

2. Create review comment template

3. Implement all action handlers specific to PR review

4. Add GitHub API integration

5. Add comprehensive tests including mock PR reviews

**Acceptance Criteria**:
- [ ] Complete PR review works end-to-end
- [ ] All 11 steps execute correctly
- [ ] Review comments posted correctly
- [ ] Labels and approvals work
- [ ] Tests include full mock workflow

---

#### Task 4.2: Create PR Review Report Template
**Owner**: OpenHands Agent  
**Priority**: P1 (High)  
**Dependencies**: Task 4.1  
**Estimated Duration**: 1 day

**Detailed Steps**:

1. Create `.openhands/workflows/pr-review-report.md`:
   ```markdown
   # PR Review Report
   
   **PR**: #{pr_number}  
   **Repository**: {repository}  
   **Author**: @{author}  
   **Review Date**: {review_date}  
   **Overall Score**: {overall_score}/100  
   **Recommendation**: {recommendation}
   
   ---
   
   ## Summary
   
   {summary_paragraph}
   
   ## Review Details
   
   ### ✅ Passed Checks ({passed_count})
   
   {passed_checks_list}
   
   ### ⚠️ Warnings ({warning_count})
   
   {warnings_list}
   
   ### ❌ Failed Checks ({failed_count})
   
   {failed_checks_list}
   
   ## Step-by-Step Results
   
   {step_results}
   
   ## Recommendations
   
   {recommendations_list}
   
   ---
   
   *This review was generated by OpenHands PR Review Workflow v{version}*
   ```

2. Add template variable substitution logic

3. Add markdown formatting utilities

4. Add tests

**Acceptance Criteria**:
- [ ] Template renders correctly
- [ ] All variables substituted
- [ ] Markdown valid
- [ ] Looks professional

---

#### Task 4.3: GitHub Actions Integration
**Owner**: OpenHands Agent  
**Priority**: P1 (High)  
**Dependencies**: Task 4.2  
**Estimated Duration**: 2 days

**Detailed Steps**:

1. Create `.github/workflows/openhands-pr-review.yml`:
   ```yaml
   name: OpenHands PR Review
   
   on:
     pull_request:
       types: [opened, synchronize, reopened]
   
   permissions:
     contents: read
     pull-requests: write
   
   jobs:
     review:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         
         - name: Run OpenHands PR Review
           uses: openhands-ai/pr-review-action@v2
           with:
             github-token: ${{ secrets.GITHUB_TOKEN }}
             llm-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
             workflow-config: .openhands/workflows/pr-review.yml
             enforce-gates: true
             auto-approve: false  # Manual approval required
   ```

2. Create GitHub Action wrapper

3. Add action.yml metadata

4. Document setup instructions

5. Add tests

**Acceptance Criteria**:
- [ ] Action triggers on PR events
- [ ] Workflow executes correctly
