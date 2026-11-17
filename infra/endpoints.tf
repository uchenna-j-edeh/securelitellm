# VPC endpoints: the tasks' only way out (decision 2, no NAT gateway).
#
# Each endpoint has a policy, so it isn't a general path out of the VPC:
#   - S3 (gateway): read the ECR image-layer bucket and nothing else. A
#     default policy would let a compromised task write to any bucket in the
#     region, including an attacker's.
#   - Bedrock runtime: invoke the configured models only.
#   - Secrets Manager, CloudWatch Logs: only principals and resources of this
#     account.
#   - ECR: only principals of this account.
# These policies are written from AWS documentation and have not been
# exercised against a real deployment yet (infra/README.md, "First apply").

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  interface_endpoints = {
    bedrock_runtime = "bedrock-runtime"
    ecr_api         = "ecr.api"
    ecr_dkr         = "ecr.dkr"
    logs            = "logs"
    secretsmanager  = "secretsmanager"
  }
  bedrock_model_arns = [
    for id in var.bedrock_model_ids : "arn:aws:bedrock:${var.aws_region}::foundation-model/${id}"
  ]
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json
  tags              = { Name = "${local.name}-s3" }
}

data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid       = "EcrImageLayersOnly"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.app.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.endpoint[each.key].json
  tags                = { Name = "${local.name}-${each.value}" }
}

data "aws_iam_policy_document" "endpoint" {
  for_each = local.interface_endpoints

  statement {
    sid = "ThisAccountOnly"
    actions = each.key == "bedrock_runtime" ? [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ] : ["*"]
    resources = each.key == "bedrock_runtime" ? local.bedrock_model_arns : ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [local.account_id]
    }
    dynamic "condition" {
      for_each = contains(["logs", "secretsmanager"], each.key) ? [1] : []
      content {
        test     = "StringEquals"
        variable = "aws:ResourceAccount"
        values   = [local.account_id]
      }
    }
  }
}
