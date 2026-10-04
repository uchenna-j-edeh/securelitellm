# ---------------------------------------------------------------------------
# Secrets Manager — create empty placeholders.
# Populate values out-of-band before the first deploy:
#
#   aws secretsmanager put-secret-value \
#     --secret-id securelitellm-dev/litellm-master-key \
#     --secret-string 'sk-your-key-here'
#
#   aws secretsmanager put-secret-value \
#     --secret-id securelitellm-dev/groq-api-key \
#     --secret-string 'gsk_your-key-here'
# ---------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "litellm_master_key" {
  name                    = "${local.name}/litellm-master-key"
  description             = "LiteLLM proxy master key"
  recovery_window_in_days = 0  # instant delete; fine for dev
}

resource "aws_secretsmanager_secret" "groq_api_key" {
  name                    = "${local.name}/groq-api-key"
  description             = "Groq API key for the LLM backend"
  recovery_window_in_days = 0
}

# ---------------------------------------------------------------------------
# GitHub Actions OIDC — lets Actions assume an IAM role without long-lived keys
# ---------------------------------------------------------------------------

data "aws_iam_openid_connect_provider" "github" {
  # Use the account's existing OIDC provider if one was already registered;
  # create it once manually or via the bootstrap script if not:
  #   aws iam create-open-id-connect-provider \
  #     --url https://token.actions.githubusercontent.com \
  #     --client-id-list sts.amazonaws.com \
  #     --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "github_actions_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "${local.name}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume.json
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "github_actions_deploy" {
  # ECR: push images
  statement {
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]
    resources = ["*"]
  }

  # ECS: force a new deployment
  statement {
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/${local.name}/${local.name}"]
  }

  # IAM: pass the task roles to ECS (required by update-service)
  statement {
    actions   = ["iam:PassRole"]
    resources = [
      aws_iam_role.ecs_execution.arn,
      aws_iam_role.ecs_task.arn,
    ]
  }
}

resource "aws_iam_role_policy" "github_actions_deploy" {
  name   = "deploy"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.github_actions_deploy.json
}
