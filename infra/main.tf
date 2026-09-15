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

# Stack region = us-east-2 (account default). CloudFront is global, so the distribution
# is region-agnostic; only the S3 bucket is regional. The deferred custom-domain ACM cert
# (U6) must be us-east-1 for CloudFront — add a `provider "aws" { alias = "us_east_1" }`
# just for that cert when cernity.io is wired up.
provider "aws" {
  region = var.aws_region
}
