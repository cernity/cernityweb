variable "aws_region" {
  description = "Region for the stack (S3 bucket). us-east-2 matches the account default. The deferred CloudFront ACM cert (U6) still must be us-east-1 — add a us-east-1 provider alias just for the cert then."
  type        = string
  default     = "us-east-2"
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

variable "site_aliases" {
  description = "Custom domains served by CloudFront (empty = default *.cloudfront.net only)."
  type        = list(string)
  default     = ["cernity.io", "www.cernity.io"]
}

variable "acm_certificate_arn" {
  description = "us-east-1 ACM cert ARN for site_aliases. Empty = use the default CloudFront cert."
  type        = string
  default     = ""
}

variable "oidc_subject" {
  description = "GitHub OIDC token sub to trust. The cernity org uses immutable subject claims (org/repo numeric IDs appended), so this pins repo:cernity@<org_id>/cernityweb@*:ref:refs/heads/main."
  type        = string
  default     = "repo:cernity@326747386/cernityweb@*:ref:refs/heads/main"
}
