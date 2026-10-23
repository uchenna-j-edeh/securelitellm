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

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate for the public HTTPS listener"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:acm:", var.acm_certificate_arn))
    error_message = "acm_certificate_arn must be a valid AWS ACM certificate ARN."
  }
}

variable "proxy_domain_name" {
  description = "DNS hostname covered by the ACM certificate and pointed at the ALB"
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9.-]+$", var.proxy_domain_name))
    error_message = "proxy_domain_name must be a valid DNS hostname."
  }
}

# The task runs litellm plus the Ollama sidecar for sensitive data (#181);
# CPU inference of the sensitive model needs about 2 vCPU and 3 GiB.
variable "task_cpu" {
  description = "ECS task CPU units (Fargate: 1024 | 2048 | 4096 ...)"
  type        = number
  default     = 2048
}

variable "task_memory" {
  description = "ECS task memory in MiB"
  type        = number
  default     = 4096
}

# --- Sensitive-data model (#181) ---

variable "ollama_image" {
  description = "Ollama sidecar image, pinned by digest"
  type        = string
  default     = "ollama/ollama@sha256:1bef639749741b375e9a1eb2c1346fb57ce52f5432de1f74846e44ccc18e1687" # 0.40.0
}

variable "sensitive_model" {
  description = "Ollama model for the sensitive model group; must match litellm_config_prod.yaml"
  type        = string
  default     = "qwen2.5:1.5b"
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
  default     = "true"
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
