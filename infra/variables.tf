variable "aws_region" {
  description = "AWS region for every resource"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for resource names"
  type        = string
  default     = "securelitellm"
}

variable "environment" {
  description = "Environment name (dev, prod)"
  type        = string
  default     = "dev"
}

variable "github_repo" {
  description = "GitHub repository allowed to deploy, as owner/name"
  type        = string
  default     = "uchenna-j-edeh/securelitellm"
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for proxy_domain_name, in aws_region"
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-zA-Z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/.+$", var.acm_certificate_arn))
    error_message = "acm_certificate_arn must be an ACM certificate ARN."
  }
}

variable "proxy_domain_name" {
  description = "Public hostname that points to the ALB"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.proxy_domain_name))
    error_message = "proxy_domain_name must be a lowercase DNS name without scheme or path."
  }
}

# No default on purpose: the load balancer is internet-facing (infra/DESIGN.md,
# decision 1), so who may reach it must be chosen. ["0.0.0.0/0"] is accepted
# if that is really meant; agent keys are still required for every request.
variable "allowed_cidrs" {
  description = "IPv4 CIDR blocks allowed to reach the load balancer"
  type        = list(string)

  validation {
    condition     = length(var.allowed_cidrs) > 0 && alltrue([for cidr in var.allowed_cidrs : can(cidrnetmask(cidr))])
    error_message = "allowed_cidrs must list at least one IPv4 CIDR block, such as \"203.0.113.0/24\"."
  }
}

variable "vpc_cidr" {
  description = "VPC address range"
  type        = string
  default     = "10.20.0.0/16"
}

variable "image_tag" {
  description = "Image tag Terraform's task definitions point at. The deploy workflow registers new revisions with sha-<commit> tags; this only matters before the first deploy."
  type        = string
  default     = "initial"
}

variable "task_cpu" {
  description = "Fargate task CPU units (proxy + classifier sidecar)"
  type        = number
  default     = 2048
}

variable "task_memory" {
  description = "Fargate task memory in MiB (proxy + classifier sidecar)"
  type        = number
  default     = 4096
}

variable "desired_count" {
  description = "Proxy tasks to run. All in one AZ (decision 4); 2 removes the restart gap after a crash."
  type        = number
  default     = 1
}

variable "bedrock_model_ids" {
  description = "Bedrock foundation model IDs the proxy may invoke. Must cover every bedrock/ model in deploy/litellm_config_prod.yaml."
  type        = list(string)
  default     = ["openai.gpt-oss-120b-1:0"]
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS storage in GiB"
  type        = number
  default     = 20
}

variable "db_deletion_protection" {
  description = "Block deleting the database. Turn off only to tear the environment down."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch retention for proxy logs, which include the decision records"
  type        = number
  default     = 90
}

variable "alarm_email" {
  description = "Email address subscribed to alarms (confirm the subscription by email). Null for none."
  type        = string
  default     = null
}

variable "enable_github_deploy" {
  description = "Create the GitHub Actions deploy role. Needs the GitHub OIDC provider registered in the account; set false for a dry run deployed from a workstation."
  type        = bool
  default     = true
}

variable "policy_file" {
  description = "Router policy baked into the proxy image (deploy/<file>). policy.demo.yaml is generated locally and only present in images built on that machine (dry runs)."
  type        = string
  default     = "policy.yaml"

  validation {
    condition     = contains(["policy.yaml", "policy.demo.yaml"], var.policy_file)
    error_message = "policy_file must be policy.yaml or policy.demo.yaml."
  }
}

variable "ephemeral" {
  description = "Short-lived environment (dry runs): destroy removes everything at once. Skips the final database snapshot, empties the image repositories and log bucket, and deletes secrets without the 7-day recovery window. Never set it for an environment with data to keep."
  type        = bool
  default     = false
}
