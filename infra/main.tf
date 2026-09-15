terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # ponytail: local state for now. Add an S3+DynamoDB backend when a second
  # operator/CI needs to apply this — a single-maintainer static site doesn't yet.
}

# CloudFront + (later) ACM certs must live in us-east-1; keep the whole stack there
# so the deferred custom-domain cert (U6) needs no second provider alias.
provider "aws" {
  region = var.aws_region
}
