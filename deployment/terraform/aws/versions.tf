terraform {
  required_version = "= 1.13.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.10.0"
    }
  }

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Application        = "aegis-framework-platform"
      Environment        = var.environment
      ManagedBy          = "terraform"
      DataClassification = "confidential"
    }
  }
}

