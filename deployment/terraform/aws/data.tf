data "aws_iam_policy_document" "kms_data" {
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

  }

  statement {
    sid    = "ApprovedAWSServiceUse"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    principals {
      type = "Service"
      identifiers = [
        "autoscaling.amazonaws.com",
        "ec2.amazonaws.com",
        "ecr.amazonaws.com",
        "eks.amazonaws.com",
        "rds.amazonaws.com",
        "s3.amazonaws.com",
        "secretsmanager.amazonaws.com",
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

}

data "aws_iam_policy_document" "kms_telemetry" {
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

data "aws_iam_policy_document" "kms_backup" {
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "BackupService"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    principals {
      type = "Service"
      identifiers = [
        "backup.amazonaws.com",
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "ApprovedCrossAccountBackup"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.backup_account_id}:root"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["backup.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${var.name} application data"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.kms_data.json
}

resource "aws_kms_key" "backup" {
  description             = "${var.name} backup data"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true
  policy                  = data.aws_iam_policy_document.kms_backup.json
}

resource "aws_kms_key" "telemetry" {
  description             = "${var.name} bounded telemetry"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.kms_telemetry.json
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = values(aws_subnet.data)[*].id
}

resource "aws_security_group" "postgres" {
  name_prefix = "${var.name}-postgres-"
  description = "PostgreSQL only from EKS workload nodes"
  vpc_id      = aws_vpc.this.id

  ingress {
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = [aws_security_group.workloads.id]
  }
}

resource "aws_db_parameter_group" "postgres" {
  name_prefix = "${var.name}-pg17-"
  family      = "postgres17"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_db_instance" "postgres" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = var.postgres_engine_version
  instance_class = var.postgres_instance_class

  allocated_storage     = 500
  max_allocated_storage = 4000
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.data.arn

  db_name                       = "aegis"
  username                      = "aegis_admin"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.data.arn

  multi_az               = true
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.postgres.id]
  parameter_group_name   = aws_db_parameter_group.postgres.name

  backup_retention_period   = 35
  backup_window             = "02:00-03:00"
  maintenance_window        = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final"

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  auto_minor_version_upgrade      = false
  allow_major_version_upgrade     = false
  apply_immediately               = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecr_repository" "application" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }

  image_scanning_configuration { scan_on_push = true }
}

resource "aws_ecr_lifecycle_policy" "application" {
  repository = aws_ecr_repository.application.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the newest 200 immutable releases"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 200
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_s3_bucket" "artifact" {
  for_each = local.artifact_buckets

  bucket              = "${var.name}-${each.key}-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = each.key == "ledger-archive"

  lifecycle { prevent_destroy = true }
}

resource "aws_s3_bucket_versioning" "artifact" {
  for_each = aws_s3_bucket.artifact
  bucket   = each.value.id

  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifact" {
  for_each = aws_s3_bucket.artifact
  bucket   = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifact" {
  for_each = aws_s3_bucket.artifact
  bucket   = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "ledger" {
  bucket = aws_s3_bucket.artifact["ledger-archive"].id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 35
    }
  }
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each = toset([
    "cursor-signing-key",
    "oidc-client",
    "reference-encryption-key",
    "temporal-api-key",
    "temporal-client-certificate",
    "temporal-client-key",
    "temporal-payload-codec-key",
  ])

  name                    = "${var.name}/${each.value}"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}
