<hr/>
<p align="center">
  <sub><img src="https://1password.com/img/logo-v1.svg" alt="1Password" width="20" /></sub> <b>SecretHub has joined 1Password!</b> Find out more on the <a href="https://secrethub.io/blog/secrethub-joins-1password/">SecretHub blog</a>. 🎉
</p>
<hr/>

<p align="center">
  <img src="https://secrethub.io/img/integrations/terraform/github-banner.png?v2" alt="Terraform + SecretHub" width="390">
</p>
<br/>

<p align="center">
  <a href="https://secrethub.io/blog/secret-management-for-terraform/"><img alt="Read blog post" src="https://secrethub.io/img/buttons/github/read-blog-post.png?v1" height="28" /></a>
  <a href="https://secrethub.io/docs/guides/terraform/"><img alt="View docs" src="https://secrethub.io/img/buttons/github/view-docs.png?v2" height="28" /></a>
</p>
<br/>

# Terraform Provider

[![](https://godoc.org/github.com/secrethub/terraform-provider-secrethub?status.svg)][godoc]
[![](https://circleci.com/gh/secrethub/terraform-provider-secrethub.svg?style=shield)][circleci]
[![](https://goreportcard.com/badge/github.com/secrethub/terraform-provider-secrethub)][goreportcard]
[![]( https://img.shields.io/github/release/secrethub/terraform-provider-secrethub.svg)][latest-version]
[![](https://img.shields.io/badge/chat-on%20discord-7289da.svg?logo=discord)][discord]
[![](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/shuaibiyy/awesome-terraform)

> [SecretHub][secrethub] is a secrets management tool that works for every engineer. Securely provision passwords and keys throughout your entire stack with just a few lines of code.

The SecretHub Terraform Provider lets you manage your secrets using Terraform.
It is officially supported and actively maintained by SecretHub, but community contributions are very welcome.

## Usage

### Terraform v0.13
```hcl
terraform {
  required_providers {
    secrethub = {
      source = "secrethub/secrethub"
      version = ">= 1.2.0"
    }
  }
}

resource "secrethub_secret" "db_password" {
  path = "my-org/my-repo/db/password"

  generate {
    length   = 22
    charsets = ["alphanumeric"]
  }
}

resource "secrethub_secret" "db_username" {
  path  = "my-org/my-repo/db/username"
  value = "db-user"
}

resource "aws_db_instance" "default" {
  allocated_storage    = 10
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = secrethub_secret.db_username.value
  password             = secrethub_secret.db_password.value
  parameter_group_name = "default.mysql5.7"
}
```

Have a look at the [reference docs](https://registry.terraform.io/providers/secrethub/secrethub/latest/docs) for more information on the supported resources and data sources.

### Terraform v0.12 and below
Manually install the secrethub provider by downloading the binary for your platform and moving it to `~/.terraform/plugins` or `%APPDATA%\terraform.d\plugins` on Windows.

Afterwards you can run the following example with Terraform.
```hcl
provider "secrethub" {}

resource "secrethub_secret" "db_password" {
  path = "my-org/my-repo/db/password"

  generate {
    length   = 22
    charsets = ["alphanumeric"]
  }
}

resource "secrethub_secret" "db_username" {
  path  = "my-org/my-repo/db/username"
  value = "db-user"
}

resource "aws_db_instance" "default" {
  allocated_storage    = 10
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = secrethub_secret.db_username.value
  password             = secrethub_secret.db_password.value
  parameter_group_name = "default.mysql5.7"
}
```

Have a look at the [reference docs](https://registry.terraform.io/providers/secrethub/secrethub/latest/docs) for more information on the supported resources and data sources.

## [Get Started]((https://secrethub.io/docs/terraform/))

Check out the [step-by-step integration guide](https://secrethub.io/docs/terraform/) to get started.

A detailed use case is described in the [original announcement](https://secrethub.io/blog/secret-management-for-terraform/).
There are also some [examples](/examples) in this repo.

## Support

If you need help, send us a message on the `#terraform` channel on [<img src="https://discordapp.com/assets/2c21aeda16de354ba5334551a883b481.png" alt="Discord" width="20px"> Discord](https://discord.gg/wcxV5RD) or send an email to [terraform@secrethub.io](mailto:terraform@secrethub.io)

## Development

### Building

Get the source code:

```
git clone https://github.com/secrethub/terraform-provider-secrethub
```

Build it using:

```
make build
```

### Testing

To run the [acceptance tests](https://www.terraform.io/docs/extend/testing/acceptance-tests/index.html), the following environment variables need to be set up.

* `SECRETHUB_CREDENTIAL` - a SecretHub credential.
* `SECRETHUB_TF_ACC_NAMESPACE` - a namespace registered on SecretHub. Make sure `SECRETHUB_CREDENTIAL` has admin access.
* `SECRETHUB_TF_ACC_REPOSITORY` - a repository within `SECRETHUB_TF_ACC_NAMESPACE` to be used in the acceptance tests. Make sure `SECRETHUB_CREDENTIAL` has admin access.
* `SECRETHUB_TF_ACC_SECOND_ACCOUNT_NAME` - an account other than the authenticated account, that is a member of the repository. It will be used to test access rules.

Only for the AWS acceptance tests:

* `SECRETHUB_TF_ACC_AWS_ROLE` - an AWS IAM role to use for testing AWS service accounts. The role should have decrypt permission on the key in `SECRETHUB_TF_ACC_AWS_KMS_KEY`.
* `SECRETHUB_TF_ACC_AWS_KMS_KEY` - an AWS KMS key to use for testing AWS service accounts. The authenticated AWS user or role should have encrypt permission on this key and the `SECRETHUB_TF_ACC_AWS_ROLE` should have decrypt permission.

Only for the GCP acceptance tests:

* `SECRETHUB_TF_ACC_GCP_SERVICE_ACCOUNT` - a GCP service account email to use for testing SecretHub GCP service accounts. It should have decrypt permission on the key in `SECRETHUB_TF_ACC_GCP_KMS_KEY`.
* `SECRETHUB_TF_ACC_GCP_KMS_KEY` - an GCP KMS key to use for testing GCP service accounts. The authenticated GCP user or role should have encrypt permission on this key and the `SECRETHUB_TF_ACC_GCP_SERVICE_ACCOUNT` should have decrypt permission.

With the environment variables properly set up, run:

```
make testacc
```
[secrethub]: https://secrethub.io
[godoc]: https://godoc.org/github.com/secrethub/terraform-provider-secrethub
[circleci]: https://circleci.com/gh/secrethub/terraform-provider-secrethub
[discord]: https://discord.gg/wcxV5RD
[latest-version]: https://github.com/secrethub/terraform-provider-secrethub/releases/latest
[goreportcard]: https://goreportcard.com/report/github.com/secrethub/terraform-provider-secrethub
# secretone
