# AWS deployment setup

The Terraform configuration deploys the proxy behind an Application Load
Balancer. Port 80 only redirects to port 443; the public service is HTTPS.
GitHub deployment stays disabled until its required AWS settings exist.

## Prerequisites

1. An AWS account with the GitHub Actions OIDC provider registered for
   `https://token.actions.githubusercontent.com`.
2. An ACM certificate in the deployment region for a hostname you control,
   such as `securelitellm.example.com`.
3. Terraform 1.5 or newer and authenticated AWS credentials for initial setup.

## Provision infrastructure

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# Set acm_certificate_arn and proxy_domain_name to real matching values.
terraform init
terraform plan
terraform apply
```

Create an A/AAAA alias (Route 53) or appropriate DNS record for
`proxy_domain_name` that targets the `alb_dns_name` Terraform output. Do not use
the raw ALB hostname as the client URL because it is not covered by your ACM
certificate.

Terraform creates secret placeholders but does not put credentials into them.
Before starting ECS, set the real LiteLLM master key and provider API key in the
two Secrets Manager entries shown by the Terraform resource names.

## Configure GitHub Actions

In the repository's `production` environment, add these Actions secrets from
the Terraform outputs and deployment settings:

- `AWS_ROLE_ARN` — `github_actions_role_arn`
- `AWS_REGION` — the Terraform `aws_region`
- `ECR_REPOSITORY_NAME` — `ecr_repository_name`
- `ECS_CLUSTER` — `ecs_cluster_name`
- `ECS_SERVICE` — `ecs_service_name`

Only after the infrastructure, DNS, secrets, and OIDC role are ready, create the
repository variable `AWS_DEPLOY_ENABLED=true`. Until then, pushes to `main` skip
the deployment job instead of failing during AWS authentication.

The deployed proxy URL is the Terraform `proxy_url` output. Keep
`ROUTER_ENFORCE=true` for real deployments; turn it off only for an explicitly
audit-only experiment.
