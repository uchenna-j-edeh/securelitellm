variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used as a prefix for all AWS resources"
  type        = string
  default     = "securelitellm"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "github_repo" {
  description = "GitHub repo slug (owner/name) used in the OIDC trust policy for Actions"
  type        = string
  default     = "uchenna-j-edeh/securelitellm"
}

variable "task_cpu" {
  description = "ECS task CPU units (256 | 512 | 1024 | 2048)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "ECS task memory in MiB"
  type        = number
  default     = 1024
}

# --- Router env vars (non-secret) ---

variable "router_mode" {
  description = "ROUTER_MODE (stateless | session)"
  type        = string
  default     = "session"
}

variable "router_level" {
  description = "ROUTER_LEVEL (L0 | L1 | L2 | L3)"
  type        = string
  default     = "L3"
}

variable "router_enforce" {
  description = "ROUTER_ENFORCE — 'true' blocks requests; 'false' logs only (audit mode)"
  type        = string
  default     = "false"
}

variable "classifier_backend" {
  description = "CLASSIFIER_BACKEND (none | promptguard | llmguard)"
  type        = string
  default     = "promptguard"
}

variable "promptguard_threshold" {
  description = "PROMPTGUARD_THRESHOLD — injection score threshold (0–1)"
  type        = string
  default     = "0.5"
}
