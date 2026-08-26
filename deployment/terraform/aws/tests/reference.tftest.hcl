mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "000000000000"
      arn        = "arn:aws:iam::000000000000:root"
      id         = "000000000000"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_vpc_endpoint" {
    defaults = {
      dns_entry = [{
        dns_name       = "vpce-00000000000000000.example.invalid"
        hosted_zone_id = "Z0000000000000000000"
      }]
    }
  }
}

run "guarded_reference_plan" {
  command = plan

  variables {
    region                        = "eu-west-1"
    environment                   = "production"
    name                          = "aegis-prod"
    route53_zone_id               = "Z0000000000000000000"
    application_domain            = "aegis.example.invalid"
    temporal_private_service_name = "com.amazonaws.vpce.eu-west-1.vpce-svc-00000000000000000"
    temporal_server_name          = "private.a1b2c.tmprl.cloud"
    temporal_private_zone_name    = "a1b2c.tmprl.cloud"
    backup_account_id             = "000000000000"
    permissions_boundary_arn      = "arn:aws:iam::000000000000:policy/aegis-boundary"
    sandbox_ami_id                = "ami-00000000000000000"
    eks_admin_principal_arn       = "arn:aws:iam::000000000000:role/aegis-platform-admin"
  }

  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].endpoint_public_access == false
    error_message = "EKS must not expose a public control-plane endpoint."
  }

  assert {
    condition     = aws_db_instance.postgres.multi_az && aws_db_instance.postgres.deletion_protection
    error_message = "Production PostgreSQL must be Multi-AZ and deletion-protected."
  }

  assert {
    condition     = aws_ecr_repository.application.image_tag_mutability == "IMMUTABLE"
    error_message = "Registry tags must be immutable."
  }

  assert {
    condition     = aws_db_instance.postgres.backup_retention_period >= 35
    error_message = "Database backup retention must meet the objective."
  }
}
