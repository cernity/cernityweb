output "bucket_name" {
  description = "S3 bucket the deploy workflow syncs dist/ into."
  value       = aws_s3_bucket.site.bucket
}

output "distribution_id" {
  description = "CloudFront distribution id (for cache invalidation)."
  value       = aws_cloudfront_distribution.site.id
}

output "distribution_domain_name" {
  description = "Live HTTPS URL of the site until cernity.io is wired up."
  value       = aws_cloudfront_distribution.site.domain_name
}

output "deploy_role_arn" {
  description = "IAM role ARN GitHub Actions assumes via OIDC (set as the AWS_DEPLOY_ROLE repo variable)."
  value       = aws_iam_role.deploy.arn
}
