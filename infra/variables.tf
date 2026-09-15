variable "aws_region" {
  description = "Region for the stack. Keep us-east-1 so the deferred ACM cert (U6) needs no provider alias."
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Globally-unique S3 bucket name for the built site (private; served only via CloudFront OAC)."
  type        = string
  default     = "cernity-website"
}

variable "github_repo" {
  description = "owner/repo allowed to assume the deploy role via GitHub OIDC. Trust is pinned to this repo's main branch."
  type        = string
  default     = "cernity/cernityweb"
}
