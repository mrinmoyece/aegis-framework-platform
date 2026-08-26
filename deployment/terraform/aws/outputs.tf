output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_private_endpoint" {
  value     = aws_eks_cluster.this.endpoint
  sensitive = true
}

output "postgres_endpoint" {
  value     = aws_db_instance.postgres.endpoint
  sensitive = true
}

output "registry_url" {
  value = aws_ecr_repository.application.repository_url
}

output "artifact_bucket_arns" {
  value = { for key, bucket in aws_s3_bucket.artifact : key => bucket.arn }
}

output "temporal_vpc_endpoint_id" {
  value = aws_vpc_endpoint.temporal.id
}

output "temporal_server_name" {
  value = var.temporal_server_name
}

output "workload_role_arns" {
  value = { for key, role in aws_iam_role.workload : key => role.arn }
}

output "backup_vault_arn" {
  value = aws_backup_vault.this.arn
}

output "prometheus_workspace_id" {
  value = aws_prometheus_workspace.this.id
}

output "certificate_arn" {
  value = aws_acm_certificate_validation.application.certificate_arn
}

