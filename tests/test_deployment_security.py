"""Regression tests for the safe, reproducible local deployment defaults."""

import json
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
        "ECR_CLASSIFIER_REPOSITORY_NAME",
        "ECS_DB_SETUP_TASK_FAMILY",
    ):
        assert required in workflow
    # The database is prepared, and must succeed, before the service is updated.
    assert workflow.index("Prepare the database") < workflow.index("Roll the proxy service")
    assert "BAKE_MODEL=true" in workflow


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


def _tf(name: str) -> str:
    return (ROOT / "infra" / name).read_text()


def _container(ecs: str, name: str) -> str:
    """The text of one container definition in infra/ecs.tf."""
    start = ecs.index(f'name      = "{name}"')
    end = ecs.find("\n    },\n", start)
    return ecs[start:end]


def test_production_serves_every_route_from_bedrock_in_this_account():
    """Decision 3 (infra/DESIGN.md): no local model; sensitive data goes to Bedrock too."""
    prod = load_yaml("deploy/litellm_config_prod.yaml")
    groups = {m["model_name"]: m for m in prod["model_list"]}
    assert {"llm", "hardened", "quarantine", "sensitive"} <= set(groups)
    models = {m["litellm_params"]["model"] for m in prod["model_list"]}
    assert all(model.startswith("bedrock/") for model in models)
    assert groups["sensitive"]["model_info"]["cleared_for"] == ["sensitive"]
    assert all("api_key" not in m["litellm_params"] for m in prod["model_list"])  # task role
    # The task role may invoke exactly the models the config names.
    variables = _tf("variables.tf")
    default = variables.split('variable "bedrock_model_ids"')[1].split("default     = ")[1]
    allowed = set(json.loads(default.split("\n")[0]))
    assert {model.split("/")[-1] for model in models} == allowed
    assert "ollama" not in _tf("ecs.tf").lower()
    assert "GROQ" not in _tf("ecs.tf") + _tf("secrets.tf")


def test_production_key_cache_is_short_so_revoking_an_agent_takes_effect_quickly():
    settings = load_yaml("deploy/litellm_config_prod.yaml")["general_settings"]
    assert settings["user_api_key_cache_ttl"] <= 10


def test_production_task_runs_with_every_safety_switch_on():
    proxy = _container(_tf("ecs.tf"), "proxy")
    for setting in (
        '{ name = "ROUTER_MODE", value = "session" }',
        '{ name = "ROUTER_LEVEL", value = "L3" }',
        '{ name = "ROUTER_ENFORCE", value = "true" }',
        '{ name = "ROUTER_LOCK", value = "true" }',
        '{ name = "ROUTER_REQUIRE_AGENT_KEY", value = "true" }',
        '{ name = "CLASSIFIER_BACKEND", value = "local" }',
        '{ name = "SESSION_STORE", value = "postgres" }',
    ):
        assert setting in proxy, setting
    assert "ROUTER_ROUTE_HEADER" not in proxy
    assert "SESSION_DB_ALLOW_PLAINTEXT" not in _tf("ecs.tf")
    assert '{ containerName = "classifier", condition = "HEALTHY" }' in proxy
    classifier = _container(_tf("ecs.tf"), "classifier")
    assert "portMappings" not in classifier  # reached on the task's localhost only
    assert '{ name = "HF_HUB_OFFLINE", value = "1" }' in classifier


def test_production_tasks_have_no_path_to_the_internet():
    """Decision 2: VPC endpoints only. No NAT, no public IP, no default route from private subnets."""
    infra = "".join(_tf(p.name) for p in (ROOT / "infra").glob("*.tf"))
    assert "aws_nat_gateway" not in infra
    assert "assign_public_ip = false" in _tf("ecs.tf")
    assert "map_public_ip_on_launch = true" not in infra
    network = _tf("network.tf")
    private = network.split('resource "aws_route_table" "private"')[1].split("resource ")[0]
    assert "0.0.0.0/0" not in private and "route {" not in private
    # The only default route is the public one, used by the load balancer.
    assert network.count('destination_cidr_block = "0.0.0.0/0"') == 1
    assert "route_table_id         = aws_route_table.public.id" in network
    # Task egress goes only to the database, the endpoints and the S3 gateway.
    egress = [block for block in network.split("resource ") if '"tasks_to_' in block]
    assert len(egress) == 3
    assert not any("cidr_ipv4" in block for block in egress)
    # The S3 gateway endpoint reads ECR image layers and nothing else.
    endpoints = _tf("endpoints.tf")
    s3 = endpoints.split('data "aws_iam_policy_document" "s3_endpoint"')[1].split("resource ")[0]
    assert 'actions   = ["s3:GetObject"]' in s3 and "starport-layer-bucket" in s3


def test_production_load_balancer_is_reachable_only_from_chosen_ranges():
    variables = _tf("variables.tf")
    allowed = variables.split('variable "allowed_cidrs"')[1].split("\nvariable ")[0]
    assert "default" not in allowed  # must be chosen; never open by accident
    alb_rules = [b for b in _tf("network.tf").split("resource ") if '"alb_http' in b]
    assert alb_rules and all("cidr_ipv4         = each.value" in b for b in alb_rules)
    alb = _tf("alb.tf")
    assert "drop_invalid_header_fields = true" in alb


def test_production_database_is_private_encrypted_and_tls_only():
    rds = _tf("rds.tf")
    for setting in (
        "publicly_accessible    = false",
        "storage_encrypted     = true",
        "manage_master_user_password = true",
        'name  = "rds.force_ssl"',
        "deletion_protection        = var.db_deletion_protection",
    ):
        assert setting in rds, setting
    secrets = _tf("secrets.tf")
    assert "sslmode=verify-full&sslrootcert=/etc/ssl/rds/global-bundle.pem" in secrets
    dockerfile = (ROOT / "deploy/Dockerfile").read_text()
    assert "/etc/ssl/rds/global-bundle.pem" in dockerfile and "--checksum=sha256:" in dockerfile
    # Only the db-setup task can read the RDS admin password.
    iam = _tf("iam.tf")
    assert iam.count("master_user_secret[0].secret_arn") == 1
    assert (
        "master_user_secret" in iam.split('"db_setup_execution_secrets"')[1].split("resource ")[0]
    )


def test_db_setup_task_runs_the_script_the_image_ships():
    dockerfile = (ROOT / "deploy/Dockerfile").read_text()
    assert "COPY deploy/db_setup.py /workspace/deploy/db_setup.py" in dockerfile
    assert 'entryPoint = ["/app/.venv/bin/python", "/workspace/deploy/db_setup.py"]' in _tf(
        "ecs.tf"
    )


def test_production_image_builds_without_pip():
    """The pinned LiteLLM base image has no pip; installing broke the production build."""
    dockerfile = (ROOT / "deploy/Dockerfile").read_text()
    assert "pip install" not in dockerfile
    assert "/app/.venv/bin/python -c" in dockerfile


def test_demo_proxies_require_agent_keys_and_share_a_private_key_database():
    """Agent identity (#148): virtual keys live in Postgres, reachable only by the proxies."""
    services = load_yaml("deploy/docker-compose.demo-dual.yml")["services"]
    db = services["agents-db"]
    assert db["image"].startswith("postgres@sha256:")
    assert "ports" not in db  # never published on the host
    assert not any("POSTGRES_PASSWORD=" in item and "${" not in item for item in db["environment"])
    for name in ("litellm", "litellm-stateless"):
        environment = services[name]["environment"]
        assert "ROUTER_REQUIRE_AGENT_KEY=true" in environment, name
        assert any(
            item.startswith("DATABASE_URL=") and "@agents-db:" in item for item in environment
        )
    # The session proxy migrates the database before the stateless one starts.
    assert services["litellm-stateless"]["depends_on"]["litellm"] == {
        "condition": "service_healthy"
    }
    # The base stack (eval, e2e) has no database and keeps the master key usable.
    base = load_yaml("deploy/docker-compose.yml")["services"]["litellm"]["environment"]
    assert not any(item.startswith(("DATABASE_URL", "ROUTER_REQUIRE_AGENT_KEY")) for item in base)


def test_demo_key_cache_is_short_so_revoking_an_agent_takes_effect_quickly():
    """LiteLLM caches key lookups per proxy for 60 s by default; a blocked key outlives that long."""
    for config in ("deploy/litellm_config.demo.yaml", "deploy/litellm_config.bedrock.yaml"):
        settings = load_yaml(config)["general_settings"]
        assert settings["user_api_key_cache_ttl"] <= 10, config
