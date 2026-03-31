variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "ai-security-test-473701"
}

variable "project_name" {
  description = "GCP project display name"
  type        = string
  default     = "ai-security-test"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "asia-northeast3"
}

variable "org_id" {
  description = "BoanClaw organization ID"
  type        = string
}

variable "policy_server_image" {
  description = "Container image for boan-policy-server"
  type        = string
  default     = "gcr.io/ai-security-test-473701/boan-policy-server:latest"
}

variable "admin_api_image" {
  description = "Container image for boan-admin-api"
  type        = string
  default     = "gcr.io/ai-security-test-473701/boan-proxy:latest"
}

variable "enable_firebase_hosting" {
  description = "Enable Firebase Hosting resources for admin console"
  type        = bool
  default     = false
}

variable "oauth_client_id" {
  description = "Google OAuth client ID"
  type        = string
  default     = ""
}

variable "oauth_client_secret" {
  description = "Google OAuth client secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oauth_redirect_url" {
  description = "OAuth redirect URL for admin login"
  type        = string
  default     = ""
}

variable "app_base_url" {
  description = "Base URL of the admin app"
  type        = string
  default     = ""
}

variable "allowed_email_domains" {
  description = "Comma separated company email domains allowed for SSO"
  type        = string
  default     = ""
}

variable "owner_email" {
  description = "Fixed owner email"
  type        = string
  default     = "genaisec.ssc@samsung.com"
}

variable "jwt_secret" {
  description = "JWT signing secret for boan admin auth"
  type        = string
  default     = ""
  sensitive   = true
}

variable "gcp_org_id" {
  description = "GCP organization ID for org sync"
  type        = string
  default     = ""
}

variable "admin_emails" {
  description = "Comma separated admin email list"
  type        = string
  default     = ""
}

variable "allowed_sso" {
  description = "Comma separated enabled SSO providers"
  type        = string
  default     = ""
}

variable "smtp_host" {
  description = "SMTP host for OTP delivery"
  type        = string
  default     = ""
}

variable "smtp_port" {
  description = "SMTP port for OTP delivery"
  type        = string
  default     = "587"
}

variable "smtp_user" {
  description = "SMTP username"
  type        = string
  default     = ""
}

variable "smtp_password" {
  description = "SMTP password or app password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "smtp_from" {
  description = "From address for OTP emails"
  type        = string
  default     = ""
}
