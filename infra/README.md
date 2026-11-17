# AWS deployment

Terraform for running SecureLiteLLM on AWS: an internet-facing load balancer
(reachable only from `allowed_cidrs`), one Fargate task (proxy + DeBERTa
classifier) in a private subnet with no internet path, RDS Postgres, and
Bedrock for every model. Why it looks like this, and what it costs: see
[DESIGN.md](DESIGN.md).

A short-lived copy has been applied and destroyed in a dry run (see "What
has been tested"); there is no long-running deployment yet.

## Prerequisites

- An AWS account and an identity that can create VPC, ECS, RDS, IAM,
  Secrets Manager, ECR, S3, DynamoDB, CloudWatch and SNS resources. (The
  `securelitellm` profile used for the demo can only call Bedrock; it can't
  apply this.)
- Bedrock model access granted in the account for every model in
  `bedrock_model_ids` (default `openai.gpt-oss-120b-1:0`, us-east-1).
- An ACM certificate in the region for a hostname you control.
- The GitHub OIDC provider registered in IAM for
  `https://token.actions.githubusercontent.com`.
- Terraform 1.5 or newer (CI uses 1.6.6).

## First apply

```bash
# 1. Remote state (once)
cd infra/bootstrap
terraform init && terraform apply
cd ..
cp backend.hcl.example backend.hcl            # fill in the two names bootstrap printed

# 2. Settings
cp terraform.tfvars.example terraform.tfvars  # certificate, domain, allowed_cidrs (required)

# 3. Infrastructure
terraform init -backend-config=backend.hcl
terraform plan -out=plan.tfplan
terraform apply plan.tfplan
```

The service is created pointing at images tagged `initial`, which don't exist
yet, so it can't start until the first deploy. Until then ECS shows stopped
tasks ("CannotPullContainerError") and a failed rollout; that is expected:

4. Point the domain at the load balancer: a CNAME (or Route 53 alias) from
   `proxy_domain_name` to the `alb_dns_name` output.
5. In GitHub, create the `production` environment, set the repository
   variable `AWS_DEPLOY_ENABLED=true`, and add these secrets from the
   Terraform outputs:

   | Secret | Output |
   |---|---|
   | `AWS_ROLE_ARN` | `github_actions_role_arn` |
   | `AWS_REGION` | your region |
   | `ECR_REPOSITORY_NAME` | `ecr_proxy_repository` |
   | `ECR_CLASSIFIER_REPOSITORY_NAME` | `ecr_classifier_repository` |
   | `ECS_CLUSTER` | `ecs_cluster_name` |
   | `ECS_SERVICE` | `ecs_service_name` |
   | `ECS_DB_SETUP_TASK_FAMILY` | `db_setup_task_family` |

6. Run the **Deploy to AWS** workflow (or push to `main`). It builds both
   images, runs the db-setup task, and rolls the service.
7. Create an agent key with the master key (`master_key_secret` output):

   ```bash
   MASTER=$(aws secretsmanager get-secret-value --secret-id <master_key_secret> \
            --query SecretString --output text)
   curl -s https://<proxy_domain_name>/user/new -H "Authorization: Bearer $MASTER" \
        -H 'Content-Type: application/json' -d '{"user_id": "agent-1"}'
   curl -s https://<proxy_domain_name>/key/generate -H "Authorization: Bearer $MASTER" \
        -H 'Content-Type: application/json' -d '{"user_id": "agent-1", "models": ["llm"]}'
   ```

   Agents send requests with that key and `"model": "llm"`. The master key
   is refused for model requests (`ROUTER_REQUIRE_AGENT_KEY=true`).

## Each release

The deploy workflow (`.github/workflows/deploy.yml`):

1. builds the proxy image and the classifier image (model baked in), tagged
   `sha-<commit>`; tags are immutable;
2. registers new task definition revisions naming exactly those images,
   starting from the latest revision, so settings Terraform changed are kept;
3. runs the db-setup task (`deploy/db_setup.py`) and stops if it fails;
4. updates the service and waits until the new task is healthy. The old task
   keeps serving until then, and ECS rolls back if the new one never gets
   healthy.

To roll back by hand, point the service at the previous revision:
`aws ecs update-service --cluster C --service S --task-definition FAMILY:N`.

A Terraform change to the task definition (an environment variable, say)
takes effect at the next deploy, not at `terraform apply`: the service
follows the workflow's revisions.

## What has been tested, and what hasn't

Tested locally:

- `terraform validate` and `terraform fmt` for this directory and
  `bootstrap/` (also in CI).
- `tests/test_deployment_security.py` pins the safety properties: no NAT
  gateway, no public IP, no default route from private subnets, task egress
  only to the database, endpoints and S3 gateway, an S3 endpoint limited to
  ECR image layers, no allow-list default, a private encrypted TLS-only
  database, every safety switch on, every model on Bedrock and the task role
  limited to those models. Breaking each of these on purpose fails a test.
- The production images on a Docker network with no internet: the db-setup
  script against a Postgres whose admin is not a superuser (as on RDS); the
  classifier starting from its baked-in model; the proxy starting with the
  production settings, issuing a session stored in Postgres, refusing the
  master key for model requests, and having no route to Bedrock, GitHub or
  Hugging Face.

Tested in AWS, in a dry run on 2026-11-17 (`scripts/aws_dryrun.sh`): the
whole configuration applied on the first try (94 resources) in us-east-1 with
a self-signed certificate and an allow-list of one IP, ran for a few hours,
and was destroyed. Confirmed there:

- image pulls, secrets and logs through the VPC endpoints and their policies;
- TLS to RDS with `verify-full` and the baked CA bundle (the db-setup task
  and the proxy's session store);
- Bedrock through its endpoint with the task role, and no internet path;
- the classifier starting offline from its baked-in model;
- the release steps (the same ones `.github/workflows/deploy.yml` runs, from
  a workstation): build and push, new revisions, db-setup, rolling the service;
- every demo beat, driven by the local UI against the AWS proxy in session
  mode, deciding as it does locally (decisions read in CloudWatch), including
  held-for-approval approve and deny with approvals in Postgres;
- all alarms created and in OK.

Found and fixed: the first apply created the service before its secrets had
values (the tasks failed with `ResourceNotFoundException`); the service now
depends on the secret values.

Not tested yet: the GitHub deploy workflow itself (the account has no GitHub
OIDC provider; the dry run used `enable_github_deploy = false`), and an alarm
actually firing.

## Dry run

`scripts/aws_dryrun.sh` builds a short-lived copy (`environment = "dryrun"`,
`ephemeral = true`) from a workstation, so the local demo UI can be driven
against it. It needs an AWS profile that can create the infrastructure, given
as `DRYRUN_AWS_PROFILE`:

```bash
DRYRUN_AWS_PROFILE=<profile> scripts/aws_dryrun.sh up        # about 10 minutes
DRYRUN_AWS_PROFILE=<profile> scripts/aws_dryrun.sh release   # images, db-setup, service
DRYRUN_AWS_PROFILE=<profile> scripts/aws_dryrun.sh agent     # agent key + infra/.dryrun/demo.env
set -a; . deploy/.env; . infra/.dryrun/demo.env; set +a; .venv/bin/python demo/server.py   # UI on :8013
DRYRUN_AWS_PROFILE=<profile> scripts/aws_dryrun.sh down      # removes everything, state included
```

The load balancer admits only this machine's public IP at the time of `up`
(`DRYRUN_ALLOWED_CIDR` to override); re-run `up` if the IP changes. Only
session mode exists in AWS, and the UI's decision panel stays empty: read the
decisions in CloudWatch Logs Insights (log group `/ecs/securelitellm-dryrun`).

## Tearing down

Set `db_deletion_protection = false`, apply, then `terraform destroy`. RDS
keeps a final snapshot (`<name>-final`); delete it separately if it isn't
needed. Secrets are recoverable for 7 days.
