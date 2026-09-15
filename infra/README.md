# infra — Cernity website hosting (Terraform)

Private S3 bucket → CloudFront (OAC, default HTTPS cert) → GitHub OIDC deploy role.
No custom domain yet: the site serves on the CloudFront `*.cloudfront.net` URL until
`cernity.io` is purchased (the ACM cert + `aliases` swap is the deferred follow-up).

## Apply

```bash
cd infra
terraform init
terraform apply            # bucket_name/github_repo have defaults; override with -var if needed
```

Then wire the three GitHub **repository variables** the deploy workflow reads (from the
`terraform output` values — they are IDs/ARNs, not secrets):

| Repo variable          | From output                |
|------------------------|----------------------------|
| `AWS_DEPLOY_ROLE`      | `deploy_role_arn`          |
| `AWS_BUCKET`           | `bucket_name`              |
| `AWS_DISTRIBUTION_ID`  | `distribution_id`          |

Visit `distribution_domain_name` to see the live site.

## Notes

- **OIDC provider already exists?** An account can hold only one provider per URL. If
  `token.actions.githubusercontent.com` is already present, import it instead of applying:
  `terraform import aws_iam_openid_connect_provider.github <provider-arn>`.
- **Trust is pinned** to `repo:cernity/cernityweb:ref:refs/heads/main` — no other repo,
  branch, or PR can assume the deploy role.
- State is local for now; add a remote backend in `main.tf` when a second operator applies.
