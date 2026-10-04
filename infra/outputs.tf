output "proxy_url" {
  description = "Public URL of the LiteLLM proxy — use as OPENAI_API_BASE in clients"
  value       = "https://${var.proxy_domain_name}"
}

output "alb_dns_name" {
  description = "ALB target for the proxy_domain_name DNS record"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "Full ECR repository URL"
  value       = aws_ecr_repository.app.repository_url
}

output "ecr_repository_name" {
  description = "ECR repository name — set as ECR_REPOSITORY_NAME in GitHub Actions secrets"
  value       = aws_ecr_repository.app.name
}

output "ecs_cluster_name" {
  description = "ECS cluster name — set as ECS_CLUSTER in GitHub Actions secrets"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name — set as ECS_SERVICE in GitHub Actions secrets"
  value       = aws_ecs_service.litellm.name
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC — set as AWS_ROLE_ARN in GitHub Actions secrets"
  value       = aws_iam_role.github_actions.arn
}

output "decision_logs_bucket" {
  description = "S3 bucket for JSONL decision records"
  value       = aws_s3_bucket.decision_logs.bucket
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for container stdout (JSONL decision records)"
  value       = aws_cloudwatch_log_group.litellm.name
}
