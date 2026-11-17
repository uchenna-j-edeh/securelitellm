# Production infrastructure design (AWS)

Status: design agreed and Terraform written 2026-11-16; applied, exercised
and destroyed in a dry run 2026-11-17 (see [README.md](README.md)). It replaces the
single-tier layout in this directory, which predates Bedrock (#234), agent
keys (#148), approvals (#174) and the Postgres store (#169).

## What it is for

An internal company tool: employees' agents call one HTTPS endpoint. Not a
high-volume, internet-facing service. One region (`us-east-1`), one
environment per Terraform workspace.

## What exists today, and what is wrong with it

| Today | Problem |
|---|---|
| Tasks in public subnets with public IPs, open egress | The proxy's whole job is controlling what leaves; its own host can reach anywhere |
| ALB open to `0.0.0.0/0` | Anyone on the internet can reach it |
| No database | Agent keys (#148) and the session/approval store (#169) need Postgres |
| Groq key + Ollama sidecar | Models moved to Bedrock; the sidecar costs 2 vCPU for one route |
| `classifier_backend = promptguard` | DeBERTa was chosen for production; there is no classifier container |
| No `ROUTER_LOCK`, `ROUTER_REQUIRE_AGENT_KEY`, `SESSION_STORE` | The safety switches added since are off |
| One task, image tag `latest`, mutable | No rollback point; one task is a restart outage |
| Task role can write S3; nothing writes there | Unused permission; logs go to CloudWatch only |
| ALB idle timeout 60 s (default) | Long model calls are cut off |
| State file local, backend commented out | No locking, no shared state |

## Target layout

```
                 company network / allowed CIDRs
                              |  HTTPS 443
                    +---------v----------+   public subnets (2 AZs: AWS
                    |        ALB         |   requires 2 for an ALB); only
                    +---------+----------+   the load balancer lives here
                              | 4000
        +---------------------v----------------------+   private app subnets
        |  ECS Fargate service "proxy" (1 task)      |   one AZ, no public IP, no NAT
        |   - litellm + router hook   :4000          |
        |   - classifier (DeBERTa)    :8080 (local)  |
        +------+--------------------+----------------+
               | 5432 (TLS)         | 443, AWS-private
        +------v--------+    +------v---------------------------+
        | RDS Postgres  |    | VPC endpoints: Bedrock runtime,  |
        | private data  |    | ECR (api, dkr), CloudWatch Logs, |
        | subnets       |    | Secrets Manager, S3 (gateway)    |
        +---------------+    +----------------------------------+
```

### Network
- One VPC, **single AZ** for everything that runs or stores data: one
  private app subnet (tasks) and one private data subnet (RDS).
- Public subnets in two AZs, because AWS requires an ALB to span at least
  two. They hold only the load balancer's own interfaces and cost nothing.
- RDS also requires a subnet group naming two AZs, even for a single-AZ
  instance. The second data subnet stays empty; the instance is pinned to the
  first AZ.
- What single AZ means: if that AZ has an outage, the tool is down until it
  recovers. Accepted for an internal tool. Moving to two AZs later is a
  variable change (subnets, task count, RDS Multi-AZ), not a redesign.
- **No NAT gateway and no internet route for tasks.** Everything a task needs
  is an AWS API, reached through VPC endpoints. A compromised proxy has no
  path to the internet. This needs the classifier model baked into its image
  (today it downloads from Hugging Face at start).
- Security groups, each allowing only its neighbour: ALB <- allowed CIDRs:443;
  tasks <- ALB:4000; RDS <- tasks:5432; endpoints <- tasks:443. Task egress
  is limited to the RDS and endpoint security groups and the S3 prefix list.

### Entry
- ALB with TLS 1.3 policy (as today), `drop_invalid_header_fields`, idle
  timeout 300 s, access logs to S3.
- Internet-facing, reachable only from `allowed_cidrs`, which has no
  default: Terraform refuses to plan without it, so "open to everyone" is
  never an accident. (`["0.0.0.0/0"]` is accepted if set on purpose.)

### Compute
- A **task** is one running copy of the app: the containers below, started
  together on Fargate (AWS supplies the CPU and memory; there is no server to
  manage) with a private IP in the app subnet. The **service** keeps the
  chosen number of tasks running and replaces one that dies.
- One task, one worker. A deploy starts the new task and waits for it to be
  healthy before stopping the old one, so deploys don't interrupt users. A
  crash does: about a minute until the replacement is healthy. A second task
  in the same AZ (about $72 a month) removes that gap; it's one variable, and
  safe now that sessions and approvals are in Postgres.
- Task = `litellm` (the router image) + `classifier` sidecar on localhost.
  They scale together and the classifier is never exposed on the network.
- Ollama sidecar removed. Every route, including `sensitive`, is served by
  Bedrock in this account (see open decision 3).
- Images are tagged with the commit SHA; ECR tags are immutable. The deploy
  job registers a new task definition revision per image, so a rollback is
  "point the service at the previous revision".
- Environment: `ROUTER_MODE=session`, `ROUTER_LEVEL=L3`, `ROUTER_ENFORCE=true`,
  `ROUTER_LOCK=true`, `ROUTER_REQUIRE_AGENT_KEY=true`,
  `CLASSIFIER_BACKEND=local`, `SESSION_STORE=postgres`.

### Data
- One RDS Postgres 16 instance, single-AZ, encrypted, in the data subnet, TLS forced
  (`rds.force_ssl`), 7-day backups, deletion protection, master password
  managed by RDS in Secrets Manager.
- Two databases on it, kept apart by login:
  - `litellm`: LiteLLM's virtual keys and usage (#148).
  - `sessions`: SecureLiteLLM's sessions and approvals (#169). The proxy's
    login there (`securelitellm_proxy`) can read and write those two tables
    and nothing else.
- The proxy connects with `sslmode=verify-full` against the RDS CA bundle
  baked into the image.
- Schema setup is a one-off ECS task run by the deploy job before the service
  is updated: create the databases if missing, then
  `python -m router.pg_session migrate --grant-to securelitellm_proxy`.
- No Redis (decided 2026-11; see README "Persistent session store").

### Secrets and permissions
- Secrets Manager: `LITELLM_MASTER_KEY`, LiteLLM salt key, `DATABASE_URL`,
  `SESSION_DB_URL`, `SESSION_HMAC_KEY`. The Groq secret is removed.
- Task role: `bedrock:InvokeModel` and `InvokeModelWithResponseStream` on the
  configured model ARNs only. Nothing else.
- Execution role: pull the image, write logs, read exactly those secrets.
- GitHub deploy role (OIDC, as today) gains only: register task definitions,
  run the migration task, pass the two task roles.

### Logs and alarms
- Decision records go to stdout and CloudWatch Logs, as today; retention is a
  variable (default 90 days). The unused S3 write permission is removed; the
  bucket stays for ALB access logs.
- Alarms to one SNS topic: ALB 5xx rate, unhealthy targets, RDS CPU, free
  storage and connections, and log metric filters on
  `session_store_unavailable` and `session_tampered` records.

### Terraform housekeeping
- Remote state in S3 with a DynamoDB lock table, created by a small
  `bootstrap/` configuration.
- Files split by concern: `network.tf`, `alb.tf`, `ecs.tf`, `rds.tf`,
  `endpoints.tf`, `secrets.tf`, `iam.tf`, `observability.tf`.
- `terraform validate` and `terraform fmt -check` added to CI.

## Rough monthly cost (us-east-1, on-demand; estimates to confirm against current pricing)

| Item | Single AZ (chosen) |
|---|---|
| Fargate, 1 task (2 vCPU, 4 GB) | about $72 |
| ALB | about $18 |
| RDS `db.t4g.micro`, single-AZ, 20 GB | about $15 |
| VPC interface endpoints (5, one AZ) | about $37 |
| Secrets, logs, state | about $5 |
| **Total before Bedrock usage** | **about $145** |

A second task adds about $72; two AZs throughout (two tasks, Multi-AZ RDS,
endpoints in both AZs) comes to about $270.

A NAT gateway instead of endpoints is about $33 per month plus data, but
gives tasks open internet egress.

## Decisions (2026-11-16)

1. **Internet-facing ALB** with an IP allow-list (`allowed_cidrs`). This is a
   school (capstone) project with no company network to sit behind. Agent
   keys are still required for every model request.
2. **VPC endpoints only, no NAT gateway.** Tasks have no path to the internet.
3. **Every route on Bedrock**, including `sensitive`. No local model.
4. **Single AZ, one task.**

## Found while building it

- **The production image did not build.** `deploy/Dockerfile` ran
  `pip install`, but the pinned LiteLLM base image has no pip (exit 127).
  The base image already ships the pinned versions, so the build now checks
  them instead of installing.
- **LiteLLM starts with no internet.** Tested on an isolated Docker network:
  it applied its database migrations and came up. It tries to download its
  model price list from GitHub first (about 7 s of retries), so the task sets
  `LITELLM_LOCAL_MODEL_COST_MAP=True`.
- **The classifier downloaded its model at start.** Its image now bakes the
  model in (`BAKE_MODEL=true`); offline it starts in about 9 s.
- **On RDS the admin is not a superuser,** and a non-superuser may not even
  say `NOSUPERUSER`. The db-setup script was tested against such an admin.
- **LiteLLM's database connection can't verify the server certificate.**
  It goes through Prisma, which takes `sslmode=require` (encrypted, server
  not verified). The router's own connection uses `verify-full`. RDS refuses
  unencrypted connections either way.
- **The old GitHub deploy role trusted any job in the repository.** It now
  trusts only jobs in the `production` environment.
- **Generated secrets are in the Terraform state.** The state bucket is
  private, encrypted and versioned; access to it is access to the secrets.

## Order of work

1. State bootstrap, network tiers, security groups, endpoints.
2. RDS, secrets, IAM.
3. Classifier image with the model baked in; task definition; service.
4. Production LiteLLM config on Bedrock; deploy workflow (SHA tags,
   migration task).
5. Alarms; CI validate; README for this directory.

Each step can be planned and validated without applying. Applying needs an
AWS identity with rights the current Bedrock-only user does not have.
