data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# -- the proxy service -------------------------------------------------------------

# Used by ECS itself (not the app) to pull images, write logs and inject secrets.
resource "aws_iam_role" "proxy_execution" {
  name               = "${local.name}-proxy-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "proxy_execution_managed" {
  role       = aws_iam_role.proxy_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "proxy_execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      for name in ["master_key", "salt_key", "session_hmac_key", "database_url", "session_db_url"] :
      aws_secretsmanager_secret.app[name].arn
    ]
  }
}

resource "aws_iam_role_policy" "proxy_execution_secrets" {
  name   = "read-proxy-secrets"
  role   = aws_iam_role.proxy_execution.id
  policy = data.aws_iam_policy_document.proxy_execution_secrets.json
}

# Used by the app: call the configured Bedrock models, nothing else.
resource "aws_iam_role" "proxy_task" {
  name               = "${local.name}-proxy-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "proxy_task" {
  statement {
    sid       = "InvokeConfiguredModels"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = local.bedrock_model_arns
  }
}

resource "aws_iam_role_policy" "proxy_task" {
  name   = "bedrock-invoke"
  role   = aws_iam_role.proxy_task.id
  policy = data.aws_iam_policy_document.proxy_task.json
}

# -- the db-setup task (deploy/db_setup.py) --------------------------------------
# The only role that can read the RDS admin password. It has no task role:
# the script makes no AWS calls.

resource "aws_iam_role" "db_setup_execution" {
  name               = "${local.name}-db-setup-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "db_setup_execution_managed" {
  role       = aws_iam_role.db_setup_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "db_setup_execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_db_instance.main.master_user_secret[0].secret_arn,
      aws_secretsmanager_secret.app["litellm_db_password"].arn,
      aws_secretsmanager_secret.app["session_db_proxy_password"].arn,
    ]
  }
}

resource "aws_iam_role_policy" "db_setup_execution_secrets" {
  name   = "read-db-setup-secrets"
  role   = aws_iam_role.db_setup_execution.id
  policy = data.aws_iam_policy_document.db_setup_execution_secrets.json
}

# -- GitHub Actions deploy (OIDC) ----------------------------------------------------

data "aws_iam_openid_connect_provider" "github" {
  count = var.enable_github_deploy ? 1 : 0
  url   = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_assume" {
  count = var.enable_github_deploy ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only jobs in the repository's "production" environment (the deploy job,
    # .github/workflows/deploy.yml). It used to be any job in the repository.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:environment:production"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  count              = var.enable_github_deploy ? 1 : 0
  name               = "${local.name}-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume[0].json
}

data "aws_iam_policy_document" "github_actions_deploy" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
    resources = [for repo in aws_ecr_repository.app : repo.arn]
  }
  statement {
    sid = "RegisterRevisions"
    # These two actions can't be limited to a resource.
    actions   = ["ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition"]
    resources = ["*"]
  }
  statement {
    sid       = "RunDbSetup"
    actions   = ["ecs:RunTask"]
    resources = ["arn:aws:ecs:${var.aws_region}:${local.account_id}:task-definition/${local.name}-db-setup:*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.main.arn]
    }
  }
  statement {
    sid       = "WatchTasks"
    actions   = ["ecs:DescribeTasks"]
    resources = ["arn:aws:ecs:${var.aws_region}:${local.account_id}:task/${aws_ecs_cluster.main.name}/*"]
  }
  statement {
    sid       = "UpdateService"
    actions   = ["ecs:DescribeServices", "ecs:UpdateService"]
    resources = [aws_ecs_service.proxy.id]
  }
  statement {
    sid     = "PassTaskRoles"
    actions = ["iam:PassRole"]
    resources = [
      aws_iam_role.proxy_execution.arn,
      aws_iam_role.proxy_task.arn,
      aws_iam_role.db_setup_execution.arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
  statement {
    sid       = "ReadDbSetupLogs"
    actions   = ["logs:GetLogEvents"]
    resources = ["${aws_cloudwatch_log_group.proxy.arn}:log-stream:db-setup/*"]
  }
}

resource "aws_iam_role_policy" "github_actions_deploy" {
  count  = var.enable_github_deploy ? 1 : 0
  name   = "deploy"
  role   = aws_iam_role.github_actions[0].id
  policy = data.aws_iam_policy_document.github_actions_deploy.json
}
