---
name: SheepVibes Rules
type: knowledge
version: 1.0.0
agent: CodeActAgent
triggers: []
---

# SheepVibes Repository Rules and Guidelines

This microagent provides comprehensive knowledge about the SheepVibes RSS/Atom feed aggregator repository, including development workflows, testing requirements, and deployment procedures.

## Core Rules for AI Agents

### Mandatory Workflow Steps
1. **Read all `.md` files** from the repository before starting any task
2. **Read both backend & frontend code files** to understand the application's logic
3. **For each individual step** during a task:
   - Add new relevant tests to the test suite
   - Verify pre-existing tests are still valid, correct if necessary
4. **Execute full CI workflow** as described in `.github/workflows/run-tests.yml`
5. **Before task completion**:
   - Run final full validation of all tests
   - Update relevant `.md` files (especially `TODO.md` and `CHANGELOG.md`)

### Testing Requirements
- **Backend tests** require a running Redis service container
- **Dynamic port handling** - Redis port is dynamically mapped in CI environments
- **Environment variable**: Tests look for `CACHE_REDIS_PORT` to override default Redis port
- **Full test suite execution** is mandatory before proceeding to next steps

## Application Architecture

### Backend (Python/Flask)
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite with migrations
- **Caching**: Redis for performance optimization
- **Background tasks**: APScheduler for automatic feed updates
- **API**: RESTful endpoints for tabs, feeds, and feed items

### Frontend (Vanilla JavaScript)
- **No frameworks** - pure JavaScript, HTML, CSS
- **Real-time updates**: Server-Sent Events (SSE) for live feed updates
- **UI**: Netvibes/iGoogle-inspired grid layout

## Development Environment Setup

### Production Deployment (Podman Pod with systemd/Quadlet)
- Use `scripts/deploy_pod.sh` for stable deployment
- Pod includes: app container, Redis container, persistent volumes
- Auto-start configured via systemd user services

### Local Development Options
1. **Podman containers** with development network
2. **Direct backend/frontend** development with virtual environment

## Key Configuration Variables
- `DATABASE_PATH`: SQLite database file location
- `UPDATE_INTERVAL_MINUTES`: Feed update frequency (default: 15)
- `CACHE_REDIS_URL`: Redis connection URL

## Testing Procedures

### Backend Testing
1. Start Redis container: `podman run -d --rm --name sheepvibes-test-redis -p 6379:6379 redis:alpine`
- Install dependencies: `cd backend && pip install -r requirements.txt -r requirements-dev.txt`
- Run tests: `python -m pytest -v`

### CI/CD Reference
- **Definitive guide**: `.github/workflows/run-tests.yml`
- **Service containerization**: Redis service with dynamic port mapping
- **Environment setup**: Set `CACHE_REDIS_PORT` for dynamic environments

## Error Handling and Limitations
- **Feed parsing**: Handle timeouts, invalid URLs, bad feed formats
- **Database constraints**: Use entry link as GUID to prevent UNIQUE constraint errors

## Usage Examples
When working on this repository, agents must:
- Always start by reading all markdown files
- Follow the step-by-step validation workflow
- Replicate CI environment setup for testing
- Update documentation files upon task completion

## Important Notes
- The repository follows a strict validation-first approach
- All changes must be tested and validated before proceeding
- Documentation updates are part of the completion criteria
