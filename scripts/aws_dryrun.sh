#!/usr/bin/env bash
# Dry run of the AWS deployment (infra/) from this workstation, then drive the
# local demo UI and agent against it.
#
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh up       # infra
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh release  # images, db-setup, service
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh agent    # agent key + demo env
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh allow <ip>...        # admit more IPs
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh participant <name>   # keys + env for a laptop
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh watch    # decisions from CloudWatch
#   DRYRUN_AWS_PROFILE=<admin profile> scripts/aws_dryrun.sh down     # destroy everything
#
# Differences from a real deployment, all on purpose:
#   - environment "dryrun", ephemeral = true (destroy removes everything at once)
#   - no domain: a self-signed certificate for *.<region>.elb.amazonaws.com is
#     imported into ACM, and the demo trusts it through SSL_CERT_FILE
#   - the load balancer admits only this machine's public IP (DRYRUN_ALLOWED_CIDR
#     to override)
#   - the proxy runs the demo policy (deploy/policy.demo.yaml, generated from
#     deploy/.env) so the beats behave as in the local demo
#   - no GitHub deploy role; images are built and pushed from here
#
# Local files (git-ignored) go to infra/.dryrun/, including the master key.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/infra/.dryrun"
REGION="${DRYRUN_AWS_REGION:-us-east-1}"
PYTHON="$ROOT/.venv/bin/python"

: "${DRYRUN_AWS_PROFILE:?set DRYRUN_AWS_PROFILE to a profile that can create the infrastructure}"
export AWS_PROFILE="$DRYRUN_AWS_PROFILE" AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
export TF_IN_AUTOMATION=1

tf() { terraform -chdir="$ROOT/infra" "$@"; }
tfb() { terraform -chdir="$ROOT/infra/bootstrap" "$@"; }
out() { tf output -raw "$1"; }
log() { printf '\n== %s\n' "$*"; }

preflight() {
  mkdir -p "$STATE" && chmod 700 "$STATE"
  local who
  who=$(aws sts get-caller-identity --query Arn --output text)
  echo "AWS identity: ${who/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]/<account>}"
}

cmd_up() {
  preflight
  log "remote state (infra/bootstrap)"
  tfb init -input=false >/dev/null
  tfb apply -auto-approve -input=false -var "aws_region=$REGION"
  cat > "$STATE/backend.hcl" <<EOF
bucket         = "$(tfb output -raw state_bucket)"
key            = "securelitellm/dryrun/terraform.tfstate"
region         = "$REGION"
dynamodb_table = "$(tfb output -raw lock_table)"
encrypt        = true
EOF

  log "self-signed certificate for the load balancer"
  if [ ! -s "$STATE/cert_arn" ]; then
    local name="*.${REGION}.elb.amazonaws.com"
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=${name}" \
      -addext "subjectAltName=DNS:${name}" \
      -keyout "$STATE/key.pem" -out "$STATE/cert.pem" 2>/dev/null
    chmod 600 "$STATE/key.pem"
    aws acm import-certificate --certificate "fileb://$STATE/cert.pem" \
      --private-key "fileb://$STATE/key.pem" \
      --tags Key=Project,Value=securelitellm Key=Environment,Value=dryrun \
      --query CertificateArn --output text > "$STATE/cert_arn"
  fi
  echo "certificate: $(cat "$STATE/cert_arn" | sed 's/[0-9]\{12\}/<account>/')"

  write_tfvars
  log "infrastructure (infra/)"
  tf init -input=false -reconfigure -backend-config="$STATE/backend.hcl" >/dev/null
  tf apply -auto-approve -input=false -var-file="$STATE/dryrun.tfvars"
}

# The load balancer admits this machine's current public IP (or
# DRYRUN_ALLOWED_CIDR) plus every CIDR added with `allow`, kept in
# infra/.dryrun/allowed_cidrs, one per line.
write_tfvars() {
  local own cidrs list
  own="${DRYRUN_ALLOWED_CIDR:-$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')/32}"
  touch "$STATE/allowed_cidrs"
  cidrs=$( { echo "$own"; cat "$STATE/allowed_cidrs"; } | sed '/^$/d' | sort -u)
  echo "load balancer admits:"; echo "$cidrs" | sed 's/^/  /'
  list=$(echo "$cidrs" | sed 's/.*/"&"/' | paste -sd, -)
  cat > "$STATE/dryrun.tfvars" <<EOF
aws_region             = "$REGION"
environment            = "dryrun"
acm_certificate_arn    = "$(cat "$STATE/cert_arn")"
proxy_domain_name      = "securelitellm-dryrun.invalid"
allowed_cidrs          = [$list]
enable_github_deploy   = false
policy_file            = "policy.demo.yaml"
db_deletion_protection = false
ephemeral              = true
EOF
}

cmd_allow() {  # allow <ip or cidr>... : add to the allow-list and apply
  preflight
  [ -s "$STATE/backend.hcl" ] || { echo "run 'up' first" >&2; exit 1; }
  [ $# -gt 0 ] || { echo "usage: $0 allow <ip or cidr>..." >&2; exit 2; }
  local entry cidrs=""
  for entry in "$@"; do
    # Normalised by Python: a bare IP becomes /32; anything else is refused,
    # and nothing is added unless every entry is valid.
    if ! cidrs+=$("$PYTHON" -c 'import ipaddress, sys; print(ipaddress.IPv4Network(sys.argv[1]))' \
        "$entry" 2>/dev/null)$'\n'; then
      echo "not an IPv4 address or CIDR: $entry" >&2; exit 2
    fi
  done
  printf '%s' "$cidrs" >> "$STATE/allowed_cidrs"
  write_tfvars
  log "update the load balancer allow-list"
  tf init -input=false -reconfigure -backend-config="$STATE/backend.hcl" >/dev/null
  tf apply -auto-approve -input=false -var-file="$STATE/dryrun.tfvars"
}

register_revision() {  # family, jq filter -> new revision ARN
  aws ecs describe-task-definition --task-definition "$1" --query taskDefinition --output json \
    | jq "$2 | {family, taskRoleArn, executionRoleArn, networkMode, containerDefinitions,
                volumes, requiresCompatibilities, cpu, memory, runtimePlatform}
           | with_entries(select(.value != null))" > "$STATE/$1.json"
  aws ecs register-task-definition --cli-input-json "file://$STATE/$1.json" \
    --query taskDefinition.taskDefinitionArn --output text
}

cmd_release() {
  preflight
  local cluster service setup_family registry proxy_repo classifier_repo tag
  cluster=$(out ecs_cluster_name); service=$(out ecs_service_name)
  setup_family=$(out db_setup_task_family)
  proxy_repo=$(out ecr_proxy_repository); classifier_repo=$(out ecr_classifier_repository)
  registry="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.${REGION}.amazonaws.com"
  tag="dryrun-$(git -C "$ROOT" rev-parse --short HEAD)-$(date +%s)"

  log "demo policy (deploy/policy.demo.yaml from deploy/.env)"
  (cd "$ROOT" && set -a && . ./deploy/.env && set +a && "$PYTHON" scripts/demo_policy.py)

  log "build and push images ($tag)"
  aws ecr get-login-password | docker login --username AWS --password-stdin "$registry" >/dev/null
  export PROXY_IMAGE="$registry/$proxy_repo:$tag" CLASSIFIER_IMAGE="$registry/$classifier_repo:$tag"
  docker build -q -f "$ROOT/deploy/Dockerfile" -t "$PROXY_IMAGE" "$ROOT"
  docker build -q --build-arg BAKE_MODEL=true -t "$CLASSIFIER_IMAGE" "$ROOT/deploy/classifier"
  docker push -q "$PROXY_IMAGE"
  docker push -q "$CLASSIFIER_IMAGE"

  log "task definition revisions"
  local family proxy_arn setup_arn
  family=$(aws ecs describe-services --cluster "$cluster" --services "$service" \
    --query 'services[0].taskDefinition' --output text | sed 's#.*/##; s#:[0-9]*$##')
  proxy_arn=$(register_revision "$family" '.containerDefinitions |= map(
    if .name == "proxy" then .image = env.PROXY_IMAGE
    elif .name == "classifier" then .image = env.CLASSIFIER_IMAGE else . end)')
  setup_arn=$(register_revision "$setup_family" '.containerDefinitions |= map(.image = env.PROXY_IMAGE)')
  echo "proxy: ${proxy_arn##*/}  db-setup: ${setup_arn##*/}"

  log "db-setup task"
  local network task code
  network=$(aws ecs describe-services --cluster "$cluster" --services "$service" \
    --query 'services[0].networkConfiguration' --output json)
  task=$(aws ecs run-task --cluster "$cluster" --launch-type FARGATE --task-definition "$setup_arn" \
    --network-configuration "$network" --query 'tasks[0].taskArn' --output text)
  aws ecs wait tasks-stopped --cluster "$cluster" --tasks "$task"
  code=$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" \
    --query 'tasks[0].containers[0].exitCode' --output text)
  if [ "$code" != "0" ]; then
    echo "db-setup failed (exit $code): $(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" \
      --query 'tasks[0].stoppedReason' --output text)"
    aws logs tail "$(out cloudwatch_log_group)" --log-stream-name-prefix db-setup --since 30m | tail -30
    exit 1
  fi
  echo "db-setup succeeded"

  log "roll the service (waits for a healthy task)"
  aws ecs update-service --cluster "$cluster" --service "$service" --task-definition "$proxy_arn" >/dev/null
  if ! aws ecs wait services-stable --cluster "$cluster" --services "$service"; then
    echo "service did not become stable; recent events:"
    aws ecs describe-services --cluster "$cluster" --services "$service" \
      --query 'services[0].events[:8].message' --output text
    exit 1
  fi
  echo "service is stable on ${proxy_arn##*/}"
}

cmd_agent() {
  preflight
  local url master key
  url="https://$(out alb_dns_name)"
  master=$(aws secretsmanager get-secret-value --secret-id "$(out master_key_secret)" \
    --query SecretString --output text)
  log "proxy health at $url"
  curl -fsS --cacert "$STATE/cert.pem" "$url/health/liveliness" && echo

  log "agent key"
  curl -sS --cacert "$STATE/cert.pem" "$url/user/new" -H "Authorization: Bearer $master" \
    -H 'Content-Type: application/json' -d '{"user_id": "dryrun-agent"}' >/dev/null
  key=$(curl -fsS --cacert "$STATE/cert.pem" "$url/key/generate" -H "Authorization: Bearer $master" \
    -H 'Content-Type: application/json' -d '{"user_id": "dryrun-agent", "models": ["llm"]}' | jq -r .key)

  umask 077
  cat > "$STATE/demo.env" <<EOF
# Source after deploy/.env to run the demo UI against the dry run.
PROXY_URL_SESSION=$url
# Only session mode exists in AWS; stateless beats fail fast instead of
# quietly reaching the local demo proxy.
PROXY_URL_STATELESS=http://127.0.0.1:9
# The UI reads decision records from a local container's logs; there is none
# here, so it shows none (read them from CloudWatch instead).
CONTAINER_SESSION=no-local-container-dryrun
DEMO_MODEL=llm
DEMO_AGENT_ID=dryrun-agent
DEMO_AGENT_KEY=$key
LITELLM_MASTER_KEY=$master
SSL_CERT_FILE=$STATE/cert.pem
DEMO_PORT=8013
EOF
  echo "wrote $STATE/demo.env; start the UI with:"
  echo "  set -a; . deploy/.env; . infra/.dryrun/demo.env; set +a; .venv/bin/python demo/server.py"
}

# A participant runs the UI on their own laptop (scripts/demo_remote.py). They
# get two keys, never the master key:
#   - an agent key for demo-<name> (model requests; the identity in CloudWatch)
#   - an approver key for demo-<name>-approver, a proxy_admin user, used only
#     by the UI's approve/deny buttons (an admin's key can't send model calls)
# Their env file carries no Jira, Gmail or SMTP secrets: email stays in log
# mode and only the public GitHub beats are offered besides the core beats.
cmd_participant() {
  preflight
  local name="${1:-}"
  if ! [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; then
    echo "usage: $0 participant <name>  (lowercase letters, digits, dashes)" >&2; exit 2
  fi
  local url master agent approver agent_key approver_key dir
  url="https://$(out alb_dns_name)"
  master=$(aws secretsmanager get-secret-value --secret-id "$(out master_key_secret)" \
    --query SecretString --output text)
  agent="demo-$name"; approver="demo-$name-approver"
  api() {  # path, json -> response body (fails on HTTP errors)
    curl -fsS --cacert "$STATE/cert.pem" "$url$1" -H "Authorization: Bearer $master" \
      -H 'Content-Type: application/json' -d "$2"
  }
  log "LiteLLM users and keys for $name"
  # /user/new fails if the user exists (a re-run); the new key is what matters.
  api /user/new "{\"user_id\": \"$agent\"}" >/dev/null 2>&1 || true
  api /user/new "{\"user_id\": \"$approver\", \"user_role\": \"proxy_admin\"}" >/dev/null 2>&1 || true
  agent_key=$(api /key/generate "{\"user_id\": \"$agent\", \"models\": [\"llm\"], \"key_alias\": \"$agent\"}" | jq -r .key)
  approver_key=$(api /key/generate "{\"user_id\": \"$approver\", \"key_alias\": \"$approver\"}" | jq -r .key)
  [ -n "$agent_key" ] && [ "$agent_key" != null ] && [ -n "$approver_key" ] && [ "$approver_key" != null ] \
    || { echo "key generation failed" >&2; exit 1; }

  dir="$STATE/participants/$name"
  mkdir -p "$dir"
  cp "$STATE/cert.pem" "$dir/cert.pem"
  (
    umask 077
    set -a; . "$ROOT/deploy/.env"; set +a
    cat > "$dir/securelitellm-demo.env" <<EOF
# SecureLiteLLM demo for $name. Run: uv run python scripts/demo_remote.py <this file>
# Keep it private: it holds your agent and approver keys. Valid until the
# deployment is torn down.
PROXY_URL_SESSION=$url
PROXY_URL_STATELESS=http://127.0.0.1:9
CONTAINER_SESSION=no-local-container
DEMO_MODEL=llm
DEMO_AGENT_ID=$agent
DEMO_AGENT_KEY=$agent_key
DEMO_APPROVER_KEY=$approver_key
SSL_CERT_FILE=cert.pem
DEMO_PORT=8003
DEMO_EMAIL_MODE=log
DEMO_RECIPIENT=${DEMO_RECIPIENT:-demo-recipient@example.test}
DEMO_EMAIL_ALLOWLIST=${DEMO_EMAIL_ALLOWLIST:-${DEMO_RECIPIENT:-demo-recipient@example.test}}
GITHUB_ISSUES_REPO=${GITHUB_ISSUES_REPO:-}
GITHUB_ISSUES_CONTROL_NUMBER=${GITHUB_ISSUES_CONTROL_NUMBER:-}
GITHUB_ISSUES_ATTACK_NUMBER=${GITHUB_ISSUES_ATTACK_NUMBER:-}
EOF
  )
  (cd "$STATE/participants" && rm -f "$name.zip" && zip -qr "$name.zip" "$name")
  echo "send $STATE/participants/$name.zip to $name privately"
  echo "(agent $agent; decisions show \"agent\": \"$agent\" in CloudWatch)"
}

# Stream decision records from CloudWatch, one line each:
#   time  agent  phase  action  risk  rules
cmd_watch() {
  preflight
  local group
  group=$(out cloudwatch_log_group)
  echo "following $group (Ctrl-C to stop)"
  aws logs tail "$group" --follow --format short --since "${DRYRUN_WATCH_SINCE:-5m}" \
    --log-stream-name-prefix proxy | format_decisions
}

format_decisions() {  # "<timestamp> <json>" lines -> decision summary lines
  local line
  while IFS= read -r line; do
    case "$line" in *'"action"'*) ;; *) continue ;; esac
    printf '%s\n' "${line#* }" | jq -r --arg t "${line%% *}" \
      'select(.phase and .action) | [($t | .[11:19]), (.agent // "-"), .phase, .action,
        (.risk_score // "" | tostring), ((.matched_rules // []) | map(tostring) | join(","))] | @tsv' \
      2>/dev/null || true
  done
}

cmd_down() {
  preflight
  if [ -s "$STATE/backend.hcl" ]; then
    log "destroy infrastructure"
    tf init -input=false -reconfigure -backend-config="$STATE/backend.hcl" >/dev/null
    tf destroy -auto-approve -input=false -var-file="$STATE/dryrun.tfvars"
  fi
  # `release` registers task definition revisions outside Terraform, so
  # destroy leaves them ACTIVE (found in the 2026-11-17 dry run). Remove every
  # revision of the dry run's families.
  log "delete task definition revisions"
  local family revisions
  for family in securelitellm-dryrun-proxy securelitellm-dryrun-db-setup; do
    for status in ACTIVE INACTIVE; do
      revisions=$(aws ecs list-task-definitions --family-prefix "$family" --status "$status" \
        --query 'taskDefinitionArns' --output text)
      for revision in $revisions; do
        [ "$status" = ACTIVE ] && aws ecs deregister-task-definition --task-definition "$revision" >/dev/null
        aws ecs delete-task-definitions --task-definitions "$revision" >/dev/null
      done
    done
  done
  if [ -s "$STATE/cert_arn" ]; then
    log "delete certificate"
    aws acm delete-certificate --certificate-arn "$(cat "$STATE/cert_arn")"
  fi
  log "destroy remote state"
  local bucket
  bucket=$(tfb output -raw state_bucket 2>/dev/null || true)
  if [ -n "$bucket" ]; then
    # Versioned: every version and delete marker has to go before the bucket can.
    aws s3api list-object-versions --bucket "$bucket" --output json \
      --query '{Objects: [Versions, DeleteMarkers][][].{Key: Key, VersionId: VersionId}}' \
      > "$STATE/versions.json"
    if [ "$(jq '.Objects | length' "$STATE/versions.json")" -gt 0 ]; then
      aws s3api delete-objects --bucket "$bucket" --delete "file://$STATE/versions.json" >/dev/null
    fi
  fi
  tfb destroy -auto-approve -input=false -var "aws_region=$REGION"
  rm -rf "$STATE" "$ROOT/infra/.terraform" "$ROOT/infra/bootstrap/.terraform"
  rm -f "$ROOT/infra/bootstrap/terraform.tfstate" "$ROOT/infra/bootstrap/terraform.tfstate.backup"
  echo "everything is gone"
}

case "${1:-}" in
  up) cmd_up ;;
  release) cmd_release ;;
  agent) cmd_agent ;;
  allow) shift; cmd_allow "$@" ;;
  participant) shift; cmd_participant "$@" ;;
  watch) cmd_watch ;;
  down) cmd_down ;;
  *) echo "usage: DRYRUN_AWS_PROFILE=<profile> $0 up|release|agent|allow <ip>...|participant <name>|watch|down" >&2; exit 2 ;;
esac
