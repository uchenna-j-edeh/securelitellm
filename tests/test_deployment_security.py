"""Regression tests for the safe, reproducible local deployment defaults."""

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def load_yaml(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text())


def test_compose_uses_pinned_litellm_image():
    compose = load_yaml("deploy/docker-compose.yml")
    image = compose["services"]["litellm"]["image"]
    assert image.startswith("ghcr.io/berriai/litellm@sha256:")


def test_mock_model_uses_pinned_python_image():
    dockerfile = (ROOT / "deploy/mock_model/Dockerfile").read_text()
    assert dockerfile.startswith("FROM python:3.11-slim@sha256:")


def test_compose_binds_host_ports_to_loopback_only():
    compose = load_yaml("deploy/docker-compose.yml")
    services = compose["services"]
    assert services["litellm"]["ports"] == ["127.0.0.1:4000:4000"]
    assert services["mock-model"]["ports"] == ["127.0.0.1:8001:8001"]


def test_compose_does_not_enable_detailed_debug():
    compose = load_yaml("deploy/docker-compose.yml")
    assert "--detailed_debug" not in compose["services"]["litellm"]["command"]


def test_master_key_comes_from_environment():
    compose = load_yaml("deploy/docker-compose.yml")
    environment = compose["services"]["litellm"]["environment"]
    assert any(item.startswith("LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY:?") for item in environment)

    config = load_yaml("deploy/litellm_config.yaml")
    assert config["general_settings"]["master_key"] == "os.environ/LITELLM_MASTER_KEY"


def test_uv_lock_is_committed_as_project_input():
    assert (ROOT / "uv.lock").is_file()
    assert "uv.lock" not in (ROOT / ".gitignore").read_text().splitlines()


def test_production_router_dependencies_are_exactly_pinned():
    dockerfile = (ROOT / "deploy/Dockerfile").read_text()
    assert "pyyaml==6.0.3" in dockerfile
    assert "aiohttp==3.14.3" in dockerfile
    assert "pyyaml>=" not in dockerfile
    assert "aiohttp>=" not in dockerfile


def test_compose_enforces_session_l3_by_default():
    compose = load_yaml("deploy/docker-compose.yml")
    environment = compose["services"]["litellm"]["environment"]
    assert "ROUTER_MODE=${ROUTER_MODE:-session}" in environment
    assert "ROUTER_LEVEL=${ROUTER_LEVEL:-L3}" in environment
    assert "ROUTER_ENFORCE=${ROUTER_ENFORCE:-true}" in environment


def test_aws_load_balancer_redirects_http_to_https():
    alb = (ROOT / "infra/alb.tf").read_text()
    outputs = (ROOT / "infra/outputs.tf").read_text()
    assert 'protocol          = "HTTPS"' in alb
    assert "certificate_arn   = var.acm_certificate_arn" in alb
    assert 'type = "redirect"' in alb
    assert 'protocol    = "HTTPS"' in alb
    assert 'value       = "https://${var.proxy_domain_name}"' in outputs


def test_aws_deploy_requires_explicit_enablement_and_configuration():
    workflow = (ROOT / ".github/workflows/deploy.yml").read_text()
    assert "vars.AWS_DEPLOY_ENABLED == 'true'" in workflow
    for required in (
        "AWS_ROLE_ARN",
        "AWS_REGION",
        "ECR_REPOSITORY_NAME",
        "ECS_CLUSTER",
        "ECS_SERVICE",
    ):
        assert required in workflow
