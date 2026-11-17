# Secrets the proxy reads at start (ECS injects them as environment variables).
#
# The values are generated here, so they are also in the Terraform state. The
# state bucket (bootstrap/) is encrypted, versioned and private; treat access
# to it as access to these secrets.

resource "random_password" "master_key" {
  length  = 48
  special = false
}

resource "random_password" "salt_key" {
  length  = 48
  special = false
}

resource "random_password" "session_hmac_key" {
  length  = 64
  special = false
}

resource "random_password" "litellm_db" {
  length  = 40
  special = false # used inside connection URLs
}

resource "random_password" "session_db_proxy" {
  length  = 40
  special = false
}

locals {
  db_host = aws_db_instance.main.address
  db_port = aws_db_instance.main.port
  secrets = {
    # Admin key for LiteLLM's key management. Can't send model requests
    # (ROUTER_REQUIRE_AGENT_KEY=true).
    master_key = "sk-${random_password.master_key.result}"
    # Encrypts credentials LiteLLM stores in its database. Never change it
    # once keys exist.
    salt_key                  = random_password.salt_key.result
    session_hmac_key          = random_password.session_hmac_key.result
    litellm_db_password       = random_password.litellm_db.result
    session_db_proxy_password = random_password.session_db_proxy.result
    # LiteLLM connects through Prisma, which takes sslmode=require (TLS,
    # without checking the server's certificate). rds.force_ssl refuses
    # anything unencrypted either way.
    database_url = "postgresql://litellm:${random_password.litellm_db.result}@${local.db_host}:${local.db_port}/litellm?sslmode=require"
    # The router's own connection verifies the server against the RDS CA
    # bundle baked into the image (deploy/Dockerfile).
    session_db_url = "postgresql://securelitellm_proxy:${random_password.session_db_proxy.result}@${local.db_host}:${local.db_port}/sessions?sslmode=verify-full&sslrootcert=/etc/ssl/rds/global-bundle.pem"
  }
}

locals {
  # for_each needs keys Terraform doesn't treat as sensitive.
  secret_names = toset([
    "master_key", "salt_key", "session_hmac_key", "litellm_db_password",
    "session_db_proxy_password", "database_url", "session_db_url",
  ])
}

resource "aws_secretsmanager_secret" "app" {
  for_each                = local.secret_names
  name                    = "${local.name}/${replace(each.key, "_", "-")}"
  recovery_window_in_days = var.ephemeral ? 0 : 7
}

resource "aws_secretsmanager_secret_version" "app" {
  for_each      = local.secret_names
  secret_id     = aws_secretsmanager_secret.app[each.key].id
  secret_string = local.secrets[each.key]
}
