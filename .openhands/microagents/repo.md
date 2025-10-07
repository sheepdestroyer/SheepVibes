# SheepVibes Repository Summary

## 1. Purpose
SheepVibes is a self-hosted RSS/Atom feed aggregator inspired by Netvibes and iGoogle. It allows users to organize feeds into customizable tabs in a grid layout, with real-time updates via Server-Sent Events (SSE).

## 2. General Setup
- **Backend**: Python Flask application with SQLAlchemy ORM, Redis caching, and APScheduler for background feed updates
- **Frontend**: Vanilla JavaScript (no frameworks) with HTML/CSS
- **Database**: SQLite with Flask-Migrate for database migrations
- **Deployment**: Designed for Podman Pod with systemd/Quadlet management

## 3. Repository Structure
```
SheepVibes/
├── backend/                 # Python Flask application
│   ├── app.py               # Main Flask application with API endpoints
│   ├── feed_service.py      # Feed parsing and update logic
│   ├── models.py            # SQLAlchemy database models
│   ├── migrations/          # Database migration files
│   ├── test_app.py          # API endpoint tests
│   ├── test_feed.py         # Feed service tests
│   ├── requirements.txt     # Production dependencies
│   └── requirements-dev.txt # Development dependencies
├── frontend/                 # Vanilla JavaScript UI
│   ├── index.html           # Main HTML file
│   ├── script.js            # Frontend JavaScript logic
│   └── style.css            # CSS styling
├── pod/                     # Podman deployment configuration
│   └── quadlet/             # Systemd Quadlet unit files
├── scripts/                  # Deployment and management scripts
│   ├── deploy_pod.sh         # Production deployment script
│   ├── run_dev.sh            # Local development script
├── .github/workflows/        # CI/CD pipelines
│   ├── run-tests.yml        # Main test workflow
│   └── release.yml          # Container image publishing
└── docs/                     # Documentation files
    ├── README.md              # Main documentation
    ├── AGENTS.md              # AI agent guidelines
    ├── TESTING.md             # Testing procedures
    ├── TODO.md                # Development roadmap
    └── CHANGELOG.md           # Project history
```

## 4. CI/CD Workflows

### Main Test Workflow (.github/workflows/run-tests.yml)
- **Trigger**: On every push and pull request
- **Services**: Redis container for caching (dynamic port mapping)
- **Key Environment Variable**: `CACHE_REDIS_PORT` - dynamically assigned Redis port
- **Setup**: Python 3.13 with pip caching
- **Test Execution**: 
  - Install dependencies from backend/requirements*.txt
  - Run pytest with `python -m pytest -v` from backend directory
- **Redis Health Check**: Configured with ping commands

### Release Workflow (.github/workflows/release.yml)
- **Trigger**: On version tags (v*) or manual dispatch
- **Actions**: Build and publish container image to GitHub Container Registry

### Dependabot Configuration
- **Pip**: Daily updates for backend dependencies
- **GitHub Actions**: Daily updates for workflow files

## 5. Key Features
- Grid-based feed organization in customizable tabs
- OPML import/export functionality
- Real-time UI updates via Server-Sent Events
- Background feed updates every 15 minutes (configurable)
- Unread count tracking per feed and tab
- Feed management (add/delete feeds, create/rename/delete tabs)
- Persistent data storage with SQLite
- Redis caching for performance optimization

## 6. Development Requirements
- **Testing**: Requires running Redis service container
- **Dynamic Port Handling**: Tests use `CACHE_REDIS_PORT` environment variable
- Backend tests require Redis for caching functionality

## 7. Deployment Options
1. **Production**: Podman Pod with systemd/Quadlet (recommended)
2. **Local Development**: Direct backend/frontend development
3. **Container Development**: Podman containers with development network

## 8. Configuration Variables
- `DATABASE_PATH`: SQLite database file location
- `UPDATE_INTERVAL_MINUTES`: Feed update frequency (default: 15)
- `CACHE_REDIS_URL`: Redis connection URL
- `FLASK_APP`: Path to Flask application (default: backend.app)
- `FLASK_RUN_HOST`: Flask server host (default: 0.0.0.0)
- `PYTHONPATH`: Module search path (default: /app in container)
