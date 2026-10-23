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


def test_deployments_point_the_router_at_their_litellm_config():
    for path in ("deploy/docker-compose.yml", "deploy/docker-compose.demo-dual.yml"):
        compose = load_yaml(path)
        for name, service in compose["services"].items():
            environment = service.get("environment") or []
            if not any(item.startswith("POLICY_PATH=") for item in environment):
                continue  # not a router service
            assert "ROUTER_LITELLM_CONFIG=/app/config.yaml" in environment, (path, name)
            assert not any(item.startswith("ROUTER_HARDENED_MODEL") for item in environment)
    assert "ENV ROUTER_LITELLM_CONFIG=/app/config.yaml" in (ROOT / "deploy/Dockerfile").read_text()


def test_demo_serves_quarantine_from_the_pulled_local_model():
    compose = load_yaml("deploy/docker-compose.demo-dual.yml")
    services = compose["services"]
    for name in ("ollama", "ollama-pull"):
        assert services[name]["image"].startswith("ollama/ollama@sha256:"), name
        assert "ports" not in services[name], name  # reachable only on the compose network
    for name in ("litellm", "litellm-stateless"):
        assert "./litellm_config.demo.yaml:/app/config.yaml:ro" in services[name]["volumes"]
        assert services[name]["depends_on"]["ollama-pull"] == {
            "condition": "service_completed_successfully"
        }
    pulled = services["ollama-pull"]["entrypoint"][-1]
    demo = load_yaml("deploy/litellm_config.demo.yaml")
    quarantine = next(m for m in demo["model_list"] if m["model_name"] == "quarantine")
    assert quarantine["litellm_params"]["model"] == f"ollama_chat/{pulled}"


def test_route_header_is_enabled_only_for_the_demo():
    """The route header lets a caller probe the classifier; ROUTER_LOCK rejects it."""
    base = load_yaml("deploy/docker-compose.yml")["services"]["litellm"]["environment"]
    assert not any(item.startswith("ROUTER_ROUTE_HEADER") for item in base)
    assert "ROUTER_ROUTE_HEADER" not in (ROOT / "deploy/Dockerfile").read_text()
    demo = load_yaml("deploy/docker-compose.demo-dual.yml")["services"]
    for name in ("litellm", "litellm-stateless"):
        assert "ROUTER_ROUTE_HEADER=true" in demo[name]["environment"], name


def _ollama_container(ecs: str) -> str:
    start = ecs.index('name       = "ollama"')
    return ecs[start : ecs.index('name      = "litellm"', start)]


def test_production_serves_sensitive_data_from_a_local_sidecar():
    """#181: the sensitive model group runs inside the ECS task, on its localhost only."""
    ecs = (ROOT / "infra/ecs.tf").read_text()
    variables = (ROOT / "infra/variables.tf").read_text()
    sidecar = _ollama_container(ecs)
    assert "portMappings" not in sidecar  # not exposed to the load balancer or the VPC
    assert '{ name = "OLLAMA_HOST", value = "127.0.0.1:11434" }' in sidecar
    assert "ollama pull ${var.sensitive_model} && wait" in sidecar  # failed pull stops the task
    assert '{ containerName = "ollama", condition = "HEALTHY" }' in ecs
    assert 'default     = "ollama/ollama@sha256:' in variables

    model = variables.split('variable "sensitive_model"')[1].split('default     = "')[1]
    model = model.split('"')[0]
    prod = load_yaml("deploy/litellm_config_prod.yaml")["model_list"]
    sensitive = next(m for m in prod if m["model_name"] == "sensitive")["litellm_params"]
    assert sensitive == {"model": f"ollama_chat/{model}", "api_base": "http://localhost:11434"}
    demo_pull = load_yaml("deploy/docker-compose.demo-dual.yml")["services"]["ollama-pull"]
    assert demo_pull["entrypoint"][-1] == model  # demo and production run the same model
