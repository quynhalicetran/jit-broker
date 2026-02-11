locals {
  jit_readonly_role_name = "JIT-Prod-ReadOnly"
  jit_admin_role_name    = "JIT-Prod-Admin"
  broker_role_name       = "OktaJitBrokerRole"

  role_map = {
    "JIT-AWS-Prod-ReadOnly" = "arn:aws:iam::${var.account_id}:role/${local.jit_readonly_role_name}"
    "JIT-AWS-Prod-Admin"    = "arn:aws:iam::${var.account_id}:role/${local.jit_admin_role_name}"
  }
}

# ---------- Target role: ReadOnly ----------
resource "aws_iam_role" "jit_prod_readonly" {
  name = local.jit_readonly_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustBroker"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:role/${local.broker_role_name}"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        # Require tags (adjust to match what your Lambda sends)
        Condition = {
          Null = {
            "aws:RequestTag/okta_user" = "false",
            "aws:RequestTag/okta_sub"  = "false",
            "aws:RequestTag/reason"    = "false"
          }
        }
      }
    ]
  })

  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "jit_readonly_attach" {
  role       = aws_iam_role.jit_prod_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ---------- Target role: Admin (demo scoped) ----------
resource "aws_iam_role" "jit_prod_admin" {
  name = local.jit_admin_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TrustBroker"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:role/${local.broker_role_name}"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
        Condition = {
          Null = {
            "aws:RequestTag/okta_user" = "false",
            "aws:RequestTag/okta_sub"  = "false",
            "aws:RequestTag/reason"    = "false"
          }
        }
      }
    ]
  })

  max_session_duration = 3600
}

# Example "Admin-ish but safe" policy (replace with your preferred scope)
resource "aws_iam_policy" "jit_admin_scoped" {
  name        = "JIT-Admin-Scoped"
  description = "Scoped admin-like permissions for demo"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:List*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "iam:List*",
          "iam:Get*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "jit_admin_attach" {
  role       = aws_iam_role.jit_prod_admin.name
  policy_arn = aws_iam_policy.jit_admin_scoped.arn
}

# ---------- Broker execution role for Lambda ----------
resource "aws_iam_role" "okta_jit_broker_role" {
  name = local.broker_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaAssume"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Allow Lambda logs
resource "aws_iam_role_policy_attachment" "lambda_basic_logs" {
  role       = aws_iam_role.okta_jit_broker_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Broker role permissions: AssumeRole tightly, TagSession with tag-keys guardrail
resource "aws_iam_policy" "broker_assume_tag" {
  name        = "OktaJitBrokerAssumeTag"
  description = "Allow broker to assume JIT roles and tag sessions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeOnlyJitRoles"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = [
          aws_iam_role.jit_prod_readonly.arn,
          aws_iam_role.jit_prod_admin.arn
        ]
      },
      {
        Sid      = "TagSessionOnlyAllowedKeys"
        Effect   = "Allow"
        Action   = "sts:TagSession"
        Resource = "*"
        Condition = {
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = [
              "okta_user",
              "okta_sub",
              "reason",
              "requested_group"
            ]
          }
        }
      },
      {
        Sid      = "DebugIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "broker_assume_tag_attach" {
  role       = aws_iam_role.okta_jit_broker_role.name
  policy_arn = aws_iam_policy.broker_assume_tag.arn
}
