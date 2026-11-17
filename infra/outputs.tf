output "proxy_url" {
  description = "HTTPS endpoint (point proxy_domain_name's DNS at alb_dns_name)"
  value       = "https://${var.proxy_domain_name}"
}

output "alb_dns_name" {
  description = "Create a CNAME (or alias) from proxy_domain_name to this"
  value       = aws_lb.main.dns_name
}

output "ecr_proxy_repository" {
  description = "GitHub secret ECR_REPOSITORY_NAME"
  value       = aws_ecr_repository.app["proxy"].name
}

output "ecr_classifier_repository" {
  description = "GitHub secret ECR_CLASSIFIER_REPOSITORY_NAME"
  value       = aws_ecr_repository.app["classifier"].name
}

output "ecs_cluster_name" {
  description = "GitHub secret ECS_CLUSTER"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "GitHub secret ECS_SERVICE"
  value       = aws_ecs_service.proxy.name
}

output "db_setup_task_family" {
  description = "GitHub secret ECS_DB_SETUP_TASK_FAMILY"
  value       = aws_ecs_task_definition.db_setup.family
}

output "github_actions_role_arn" {
  description = "GitHub secret AWS_ROLE_ARN"
  value       = var.enable_github_deploy ? aws_iam_role.github_actions[0].arn : null
}

output "master_key_secret" {
  description = "Secrets Manager secret holding the LiteLLM master key (to create agent keys)"
  value       = aws_secretsmanager_secret.app["master_key"].name
}

output "cloudwatch_log_group" {
  description = "Proxy, classifier and db-setup logs, including the decision records"
  value       = aws_cloudwatch_log_group.proxy.name
}

output "db_endpoint" {
  description = "RDS endpoint (reachable only from the proxy tasks)"
  value       = aws_db_instance.main.address
}
