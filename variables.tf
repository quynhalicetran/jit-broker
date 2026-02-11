variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type = string
}

# Okta JWT authorizer settings
variable "okta_issuer" {
  type = string
  # ex: https://integrator-7033282.okta.com/oauth2/default
}

variable "okta_audience" {
  type = string
  # IMPORTANT:
  # If validating access tokens from Okta default AS, your audience is often "api://default"
  # If validating ID tokens, audience is usually the OIDC client_id.
}

# Broker config
variable "default_duration" {
  type    = number
  default = 3600
}

variable "default_role_group" {
  type    = string
  default = "JIT-AWS-Prod-ReadOnly"
}
variable "role_map_json" {
  type        = string
  description = "JSON string mapping Okta group -> role ARN (used as Lambda env var ROLE_MAP)"
}
