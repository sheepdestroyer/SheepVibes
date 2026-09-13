import pathlib


def test_quadlet_valkey_configuration():
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    valkey_container = repo_root / "pod" / "sheepvibes-valkey.container"

    assert valkey_container.exists(), "sheepvibes-valkey.container must exist"
    content = valkey_container.read_text(encoding="utf-8")

    assert "Image=docker.io/valkey/valkey:9.1-alpine" in content
    assert "AutoUpdate=registry" in content
    assert "Label=wud.watch.digest=true" in content
    assert 'Label="wud.tag.include=^[0-9]+[.][0-9]+-alpine$"' in content
    assert 'Label="wud.tag.exclude=.*(trixie|bookworm|bullseye).*"' in content


def test_quadlet_rssbridge_configuration():
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    rssbridge_container = repo_root / "pod" / "sheepvibes-rssbridge.container"

    assert rssbridge_container.exists(), "sheepvibes-rssbridge.container must exist"
    content = rssbridge_container.read_text(encoding="utf-8")

    assert "Image=docker.io/rssbridge/rss-bridge:latest" in content
    assert "AutoUpdate=registry" in content
    assert "Label=wud.watch.digest=true" in content
    assert "Environment=RSSBRIDGE_ERROR_OUTPUT=http" in content


def test_ci_workflow_valkey_image():
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    workflow = repo_root / ".github" / "workflows" / "run-tests.yml"

    assert workflow.exists(), "run-tests.yml workflow must exist"
    content = workflow.read_text(encoding="utf-8")

    assert "image: docker.io/valkey/valkey:9.1-alpine" in content


def test_dev_scripts_valkey_image():
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    dev_manager = repo_root / "scripts" / "dev_manager.sh"
    deploy_pod = repo_root / "scripts" / "deploy_pod.sh"
    run_dev = repo_root / "scripts" / "run_dev.sh"

    assert "docker.io/valkey/valkey:9.1-alpine" in dev_manager.read_text(encoding="utf-8")
    assert "docker.io/valkey/valkey:9.1-alpine" in deploy_pod.read_text(encoding="utf-8")
    assert "docker.io/valkey/valkey:9.1-alpine" in run_dev.read_text(encoding="utf-8")
