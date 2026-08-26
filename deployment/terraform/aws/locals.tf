data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnet_cidrs = {
    for index, zone in local.availability_zones :
    zone => cidrsubnet(var.vpc_cidr, 4, index)
  }
  data_subnet_cidrs = {
    for index, zone in local.availability_zones :
    zone => cidrsubnet(var.vpc_cidr, 4, index + 4)
  }
  public_subnet_cidrs = {
    for index, zone in local.availability_zones :
    zone => cidrsubnet(var.vpc_cidr, 4, index + 8)
  }
  artifact_buckets = toset([
    "ledger-archive",
    "evidence-blobs",
    "trust-backup",
  ])
  workload_service_accounts = {
    api       = "aegis-api"
    operator  = "aegis-operator"
    workers   = "aegis-investigation-worker"
    sandbox   = "aegis-sandbox-controller"
    migration = "aegis-migration"
    telemetry = "aegis-otel"
  }
}

