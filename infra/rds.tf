# Postgres (infra/DESIGN.md, "Data"). One single-AZ instance holding two
# databases, each with its own login, created by the db-setup task
# (deploy/db_setup.py) that the deploy workflow runs before each release:
#   litellm   LiteLLM's virtual keys and usage (#148)
#   sessions  SecureLiteLLM's sessions and approvals (#169)
# The admin password is generated and kept by RDS in Secrets Manager; only the
# db-setup task can read it.

resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = aws_subnet.data[*].id # two AZs required; the instance uses the first
}

resource "aws_db_parameter_group" "main" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "main" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"

  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 2
  storage_type          = "gp3"
  storage_encrypted     = true

  username                    = "dbadmin"
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  availability_zone      = local.main_az
  multi_az               = false
  publicly_accessible    = false

  backup_retention_period    = 7
  copy_tags_to_snapshot      = true
  deletion_protection        = var.db_deletion_protection
  skip_final_snapshot        = var.ephemeral
  final_snapshot_identifier  = var.ephemeral ? null : "${local.name}-final"
  auto_minor_version_upgrade = true
  apply_immediately          = false
}
