terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state in S3 with a DynamoDB lock table, both created by bootstrap/.
  # Settings come from a file at init time:
  #   terraform init -backend-config=backend.hcl   (see backend.hcl.example)
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
  default_tags { tags = local.tags }
}

locals {
  name = "${var.project_name}-${var.environment}"
  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}
