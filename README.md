Creates a standalone secretsmanager secret, encrypted with a kms key.

# terraform-kms-secret

```hcl
module "your_secret"{
  source = "github.com/turnerlabs/terraform-kms-secret?ref=v1.1"
  region = var.region
  secret_id = "your-secret-id"
  secrets_saml_users = ["peoplein@org.com", "yourcompany@org.com"]
  saml_role = var.saml_role
  tags = var.tags
  additional_roles = [
    data.aws_iam_role.ecsTaskExecutionRole.name
  ]
}

```

Big thanks to [John](https://github.com/jritsema) for creating the original code, which I refactored into this standalone module.
