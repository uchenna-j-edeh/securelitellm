# Decision log bucket — stores JSONL records for offline analysis.
# Today the container writes to stdout (CloudWatch); this bucket is wired into
# the task role so a future router/logger.py update can ship directly to S3
# without any infra change.

resource "aws_s3_bucket" "decision_logs" {
  bucket = "${local.name}-decision-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "decision_logs" {
  bucket = aws_s3_bucket.decision_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "decision_logs" {
  bucket = aws_s3_bucket.decision_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "decision_logs" {
  bucket                  = aws_s3_bucket.decision_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "decision_logs" {
  bucket = aws_s3_bucket.decision_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter { prefix = "" }
    expiration { days = 90 }
  }
}
