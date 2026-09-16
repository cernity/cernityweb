# GitHub Actions OIDC identity provider. One per account per URL — if the account
# already has it, `terraform import` this resource instead of creating a duplicate
# (see infra/README.md).
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's OIDC cert against its own trusted CA store and ignores
  # this value for this provider, but the argument is still required.
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Pinned to this repo's main branch only — no other repo/branch/PR can assume it.
    # The cernity org enables GitHub's immutable OIDC subject claims, so the token sub is
    # "repo:cernity@<org_id>/cernityweb@<repo_id>:ref:refs/heads/main" (numeric IDs appended),
    # not the plain "repo:cernity/cernityweb:...". StringLike pins the org (name+id) and repo
    # name + branch while tolerating a repo-id change (e.g. repo recreation).
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [var.oidc_subject]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "cernity-website-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_trust.json
}

# Least privilege: sync the site bucket + invalidate this one distribution.
data "aws_iam_policy_document" "deploy_perms" {
  statement {
    sid       = "SyncSiteBucket"
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetObject"]
    resources = [aws_s3_bucket.site.arn, "${aws_s3_bucket.site.arn}/*"]
  }
  statement {
    sid       = "InvalidateDistribution"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.site.arn]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "cernity-website-deploy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_perms.json
}
