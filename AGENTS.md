AGENTS.md

Automated environments, such as those used by Google's Jules, often operate in restricted or virtualized settings where service ports may be mapped dynamically. The project's test suite is designed to handle this.

The key to running tests successfully in such an environment is to provide a Redis instance and inform the test suite how to connect to it.

The most reliable reference is the project's own CI workflow, located at .github/workflows/run-tests.yml. This file demonstrates exactly how to set up the environment.

Key Configuration Points for Automated Agents:
Redis Service: The tests require a running Redis service for caching checks. In the GitHub Actions workflow, this is accomplished using the services block to start a redis:alpine container. Your environment will need to do the same.

Dynamic Port Handling: In many CI systems, you cannot assume Redis will be available on localhost:6379. The service container's port 6379 will be mapped to a dynamic port on the host runner. The GitHub Actions workflow retrieves this port using ${{ job.services.redis.ports['6379'] }}.

Environment Variable: The test suite (backend/test_app.py) is explicitly configured to look for the CACHE_REDIS_PORT environment variable. If this variable is set, it will override the default Redis port and allow the tests to connect to the dynamically mapped port of the Redis service container.

Actionable Steps for CI/CD Tools:
To successfully run the backend tests, please follow this procedure:

Start a Redis container within your environment.
Identify the host port that has been dynamically mapped to the container's internal port 6379.
Set the CACHE_REDIS_PORT environment variable to this dynamically assigned port number.
Navigate to the backend directory.
Install dependencies: pip install -r requirements.txt -r requirements-dev.txt.
Run the tests using the command: python -m pytest -v.

By following these instructions, which mirror the setup in our own CI workflow, your automated tool should be able to execute the test suite correctly ; Always make sure it suceeds.
