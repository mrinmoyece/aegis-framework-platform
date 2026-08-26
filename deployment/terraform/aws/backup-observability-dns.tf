resource "aws_backup_vault" "this" {
  name        = var.name
  kms_key_arn = aws_kms_key.backup.arn
}

resource "aws_backup_vault_lock_configuration" "this" {
  backup_vault_name   = aws_backup_vault.this.name
  changeable_for_days = 7
  min_retention_days  = 35
  max_retention_days  = 365
}

resource "aws_backup_vault_policy" "cross_account_copy" {
  backup_vault_name = aws_backup_vault.this.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowApprovedBackupAccountCopy"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.backup_account_id}:root" }
      Action    = "backup:CopyIntoBackupVault"
      Resource  = aws_backup_vault.this.arn
    }]
  })
}

resource "aws_backup_plan" "this" {
  name = var.name

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 3 * * ? *)"
    start_window      = 60
    completion_window = 360

    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }
  }
}

resource "aws_iam_role" "backup" {
  name                 = "${var.name}-backup"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_s3" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup",
    "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore",
  ])

  role       = aws_iam_role.backup.name
  policy_arn = each.value
}

resource "aws_backup_selection" "this" {
  name         = var.name
  plan_id      = aws_backup_plan.this.id
  iam_role_arn = aws_iam_role.backup.arn
  resources = concat(
    [aws_db_instance.postgres.arn],
    [for bucket in aws_s3_bucket.artifact : bucket.arn],
  )
}

resource "aws_prometheus_workspace" "this" {
  alias = var.name

  logging_configuration {
    log_group_arn = "${aws_cloudwatch_log_group.prometheus.arn}:*"
  }
}

resource "aws_cloudwatch_log_group" "prometheus" {
  name              = "/aws/prometheus/${var.name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_cloudwatch_log_group" "application" {
  name              = "/aegis/${var.name}/application"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.telemetry.arn
}

resource "aws_acm_certificate" "application" {
  domain_name       = var.application_domain
  validation_method = "DNS"

  lifecycle { create_before_destroy = true }
}

resource "aws_route53_record" "certificate" {
  zone_id = var.route53_zone_id
  name    = tolist(aws_acm_certificate.application.domain_validation_options)[0].resource_record_name
  type    = tolist(aws_acm_certificate.application.domain_validation_options)[0].resource_record_type
  ttl     = 300
  records = [
    tolist(aws_acm_certificate.application.domain_validation_options)[0].resource_record_value
  ]
}

resource "aws_acm_certificate_validation" "application" {
  certificate_arn         = aws_acm_certificate.application.arn
  validation_record_fqdns = [aws_route53_record.certificate.fqdn]
}
