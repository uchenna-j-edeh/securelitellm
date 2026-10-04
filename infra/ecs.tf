# ---------------------------------------------------------------------------
# CloudWatch log group — ECS ships container stdout here
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "litellm" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30
}

# ---------------------------------------------------------------------------
# IAM roles
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Execution role — ECS control plane uses this to pull the image and inject secrets
resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name}-ecs-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.litellm_master_key.arn,
      aws_secretsmanager_secret.groq_api_key.arn,
    ]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "read-secrets"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

# Task role — the running container assumes this (S3 write for decision logs)
resource "aws_iam_role" "ecs_task" {
  name               = "${local.name}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "ecs_task_s3" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.decision_logs.arn}/decisions/*"]
  }
}

resource "aws_iam_role_policy" "ecs_task_s3" {
  name   = "decision-logs-s3"
  role   = aws_iam_role.ecs_task.id
  policy = data.aws_iam_policy_document.ecs_task_s3.json
}

# ---------------------------------------------------------------------------
# ECS cluster + Fargate task + service
# ---------------------------------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = local.name
}

resource "aws_ecs_task_definition" "litellm" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "litellm"
      image     = "${aws_ecr_repository.app.repository_url}:latest"
      essential = true

      portMappings = [
        { containerPort = 4000, protocol = "tcp" }
      ]

      # Non-secret config — safe to store in plain env vars
      environment = [
        { name = "ROUTER_MODE",           value = var.router_mode },
        { name = "ROUTER_LEVEL",          value = var.router_level },
        { name = "ROUTER_ENFORCE",        value = var.router_enforce },
        { name = "CLASSIFIER_BACKEND",    value = var.classifier_backend },
        { name = "PROMPTGUARD_THRESHOLD", value = var.promptguard_threshold },
        { name = "POLICY_PATH",           value = "/workspace/deploy/policy.yaml" },
        { name = "ROUTER_LOG_PATH",       value = "-" },   # stdout → CloudWatch
        { name = "PYTHONPATH",            value = "/workspace" },
      ]

      # Secrets pulled from Secrets Manager at task start — never visible in task def
      secrets = [
        {
          name      = "LITELLM_MASTER_KEY"
          valueFrom = aws_secretsmanager_secret.litellm_master_key.arn
        },
        {
          name      = "GROQ_API_KEY"
          valueFrom = aws_secretsmanager_secret.groq_api_key.arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.litellm.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "litellm"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "litellm" {
  name            = local.name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.litellm.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.litellm.arn
    container_name   = "litellm"
    container_port   = 4000
  }

  depends_on = [
    aws_lb_listener.https,
    aws_iam_role_policy_attachment.ecs_execution_managed,
  ]

  # Prevent Terraform from reverting manual image tag changes done by the deploy workflow
  lifecycle {
    ignore_changes = [task_definition]
  }
}
