variable "region" {
  description = "Single application-ledger home region for this stack."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.region))
    error_message = "Region must be an AWS region identifier."
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "Environment must be staging or production."
  }
}

variable "name" {
  description = "Short globally unique deployment name."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "Name must be a short lowercase DNS label."
  }
}

variable "vpc_cidr" {
  description = "Private VPC CIDR."
  type        = string
  default     = "10.64.0.0/16"
}

variable "kubernetes_version" {
  description = "Qualified EKS version; upgrade only after replay and admission tests."
  type        = string
  default     = "1.32"
}

variable "coredns_addon_version" {
  description = "Pinned CoreDNS version qualified with EKS."
  type        = string
  default     = "v1.11.4-eksbuild.2"
}

variable "kube_proxy_addon_version" {
  description = "Pinned kube-proxy version qualified with EKS."
  type        = string
  default     = "v1.32.0-eksbuild.2"
}

variable "pod_identity_addon_version" {
  description = "Pinned EKS Pod Identity Agent version."
  type        = string
  default     = "v1.3.4-eksbuild.1"
}

variable "vpc_cni_addon_version" {
  description = "Pinned VPC CNI version with NetworkPolicy enforcement."
  type        = string
  default     = "v1.19.2-eksbuild.1"
}

variable "sandbox_ami_id" {
  description = "Organization-qualified EKS AL2023 AMI with the pinned Kata handler."
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.sandbox_ami_id))
    error_message = "Sandbox AMI ID must be an explicit qualified AMI ID."
  }
}

variable "postgres_engine_version" {
  description = "Qualified RDS PostgreSQL major/minor version."
  type        = string
  default     = "17.6"
}

variable "postgres_instance_class" {
  description = "Measured RDS capacity selection."
  type        = string
  default     = "db.r7g.xlarge"
}

variable "route53_zone_id" {
  description = "Existing private/public zone selected by platform policy."
  type        = string
}

variable "application_domain" {
  description = "Operator/API DNS name."
  type        = string
}

variable "temporal_private_service_name" {
  description = "Temporal Cloud AWS PrivateLink service name supplied by the tenant account."
  type        = string
}

variable "temporal_server_name" {
  description = "Pinned Temporal Cloud TLS server name."
  type        = string
}

variable "temporal_private_zone_name" {
  description = "Private DNS zone containing the Temporal TLS server name."
  type        = string
}

variable "backup_account_id" {
  description = "Separate AWS account allowed to copy immutable backups."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.backup_account_id))
    error_message = "Backup account ID must be a 12 digit AWS account ID."
  }
}

variable "permissions_boundary_arn" {
  description = "Organization-owned IAM permissions boundary for workload roles."
  type        = string
}

variable "eks_admin_principal_arn" {
  description = "Reviewed break-glass/platform role granted explicit EKS administration."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.eks_admin_principal_arn))
    error_message = "EKS admin principal ARN must be an IAM role ARN."
  }
}
