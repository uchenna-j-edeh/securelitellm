# The proxy: one Fargate service (decision 4: one task, one AZ).
# A task = the proxy container plus the DeBERTa classifier container, started
# together with one private IP in the app subnet. The classifier is reached on
# the task's localhost only and is never exposed to the network.

resource "aws_cloudwatch_log_group" "proxy" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_ecs_cluster" "main" {
  name = local.name
}

locals {
  proxy_image      = "${aws_ecr_repository.app["proxy"].repository_url}:${var.image_tag}"
  classifier_image = "${aws_ecr_repository.app["classifier"].repository_url}:${var.image_tag}"
  log_options = {
    "awslogs-group"  = aws_cloudwatch_log_group.proxy.name
    "awslogs-region" = var.aws_region
  }
}

resource "aws_ecs_task_definition" "proxy" {
  family                   = "${local.name}-proxy"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.proxy_execution.arn
  task_role_arn            = aws_iam_role.proxy_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "classifier"
      image     = local.classifier_image
      essential = true
      environment = [
        # The model is in the image (BAKE_MODEL=true); the task has no internet.
        { name = "TRANSFORMERS_CACHE", value = "/opt/model" },
        { name = "HF_HUB_OFFLINE", value = "1" },
        { name = "TRANSFORMERS_OFFLINE", value = "1" },
        { name = "CLASSIFIER_MAX_LENGTH", value = "512" },
      ]
      healthCheck = {
        command     = ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
        interval    = 15
        timeout     = 5
        retries     = 5
        startPeriod = 120
      }
      logConfiguration = {
        logDriver = "awslogs"
        options   = merge(local.log_options, { "awslogs-stream-prefix" = "classifier" })
      }
    },
    {
      name      = "proxy"
      image     = local.proxy_image
      essential = true
      portMappings = [
        { containerPort = 4000, protocol = "tcp" }
      ]
      dependsOn = [
        { containerName = "classifier", condition = "HEALTHY" }
      ]
      environment = [
        { name = "ROUTER_MODE", value = "session" },
        { name = "ROUTER_LEVEL", value = "L3" },
        { name = "ROUTER_ENFORCE", value = "true" },
        { name = "ROUTER_LOCK", value = "true" },
        { name = "ROUTER_REQUIRE_AGENT_KEY", value = "true" },
        { name = "CLASSIFIER_BACKEND", value = "local" },
        { name = "LOCAL_CLASSIFIER_URL", value = "http://127.0.0.1:8080" },
        { name = "SESSION_STORE", value = "postgres" },
        { name = "POLICY_PATH", value = "/workspace/deploy/${var.policy_file}" },
        { name = "ROUTER_LOG_PATH", value = "-" }, # stdout -> CloudWatch
        { name = "AWS_REGION_NAME", value = var.aws_region },
        # Use the price list in the image: the task can't reach GitHub.
        { name = "LITELLM_LOCAL_MODEL_COST_MAP", value = "True" },
      ]
      secrets = [
        { name = "LITELLM_MASTER_KEY", valueFrom = aws_secretsmanager_secret.app["master_key"].arn },
        { name = "LITELLM_SALT_KEY", valueFrom = aws_secretsmanager_secret.app["salt_key"].arn },
        { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.app["database_url"].arn },
        { name = "SESSION_DB_URL", valueFrom = aws_secretsmanager_secret.app["session_db_url"].arn },
        { name = "SESSION_HMAC_KEY", valueFrom = aws_secretsmanager_secret.app["session_hmac_key"].arn },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options   = merge(local.log_options, { "awslogs-stream-prefix" = "proxy" })
      }
    }
  ])
}

# Prepares the database (deploy/db_setup.py). The deploy workflow runs it, and
# waits for it to succeed, before updating the service.
resource "aws_ecs_task_definition" "db_setup" {
  family                   = "${local.name}-db-setup"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.db_setup_execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name       = "db-setup"
      image      = local.proxy_image
      essential  = true
      entryPoint = ["/app/.venv/bin/python", "/workspace/deploy/db_setup.py"]
      environment = [
        { name = "DB_HOST", value = aws_db_instance.main.address },
        { name = "DB_PORT", value = tostring(aws_db_instance.main.port) },
      ]
      secrets = [
        # The whole RDS-managed secret: JSON with username and password.
        { name = "DB_ADMIN_SECRET", valueFrom = aws_db_instance.main.master_user_secret[0].secret_arn },
        { name = "LITELLM_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.app["litellm_db_password"].arn },
        { name = "SESSION_DB_PROXY_PASSWORD", valueFrom = aws_secretsmanager_secret.app["session_db_proxy_password"].arn },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options   = merge(local.log_options, { "awslogs-stream-prefix" = "db-setup" })
      }
    }
  ])
}

resource "aws_ecs_service" "proxy" {
  name            = "${local.name}-proxy"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.proxy.arn
  launch_type     = "FARGATE"
  desired_count   = var.desired_count

  # Start the new task and wait until it is healthy before stopping the old
  # one, so a deploy doesn't interrupt users; roll back if it never gets there.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  health_check_grace_period_seconds = 180

  network_configuration {
    subnets          = [aws_subnet.app.id]
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.proxy.arn
    container_name   = "proxy"
    container_port   = 4000
  }

  # Everything a task needs before it can start. Without the secret values,
  # the first apply created the service minutes before the secrets had values
  # (they wait for the database address), and its tasks failed with
  # ResourceNotFoundException (found in the 2026-11-17 dry run).
  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy_attachment.proxy_execution_managed,
    aws_iam_role_policy.proxy_execution_secrets,
    aws_secretsmanager_secret_version.app,
    aws_vpc_endpoint.interface,
    aws_vpc_endpoint.s3,
  ]

  # The deploy workflow registers a new revision per release (new image tags).
  # Terraform changes to the task definition reach the service through the
  # next deploy, which starts from the latest registered revision.
  lifecycle {
    ignore_changes = [task_definition]
  }
}
