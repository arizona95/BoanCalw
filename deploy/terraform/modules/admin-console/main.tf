variable "project_id" {}
variable "region" { default = "asia-northeast3" }
variable "org_id" {}
variable "policy_server_url" {}
variable "admin_api_image" {}
variable "enable_firebase_hosting" { default = false }
variable "oauth_client_id" { default = "" }
variable "oauth_client_secret" { default = "" }
variable "oauth_redirect_url" { default = "" }
variable "app_base_url" { default = "" }
variable "allowed_email_domains" { default = "" }
variable "owner_email" { default = "" }
variable "jwt_secret" { default = "" }
variable "gcp_org_id" { default = "" }
variable "admin_emails" { default = "" }
variable "allowed_sso" { default = "" }
variable "smtp_host" { default = "" }
variable "smtp_port" { default = "587" }
variable "smtp_user" { default = "" }
variable "smtp_password" { default = "" }
variable "smtp_from" { default = "" }

resource "google_firebase_hosting_site" "admin" {
  count    = var.enable_firebase_hosting ? 1 : 0
  provider = google-beta
  project  = var.project_id
  site_id  = "boanclaw-admin-${var.org_id}"
}

resource "google_firebase_hosting_channel" "production" {
  count      = var.enable_firebase_hosting ? 1 : 0
  provider   = google-beta
  site_id    = google_firebase_hosting_site.admin[0].site_id
  channel_id = "live"
}

# Cloud Run for SSO callback + API proxy
resource "google_cloud_run_v2_service" "admin_api" {
  name     = "boan-admin-api"
  location = var.region
  project  = var.project_id

  template {
    containers {
      image = var.admin_api_image
      ports {
        container_port = 18081
      }
      env {
        name  = "BOAN_POLICY_URL"
        value = var.policy_server_url
      }
      env {
        name  = "BOAN_ORG_ID"
        value = var.org_id
      }
      env {
        name  = "BOAN_ADMIN_LISTEN"
        value = ":18081"
      }
      env {
        name  = "BOAN_OAUTH_CLIENT_ID"
        value = var.oauth_client_id
      }
      env {
        name  = "BOAN_OAUTH_CLIENT_SECRET"
        value = var.oauth_client_secret
      }
      env {
        name  = "BOAN_OAUTH_REDIRECT_URL"
        value = var.oauth_redirect_url
      }
      env {
        name  = "BOAN_APP_BASE_URL"
        value = var.app_base_url
      }
      env {
        name  = "BOAN_ALLOWED_EMAIL_DOMAINS"
        value = var.allowed_email_domains
      }
      env {
        name  = "BOAN_OWNER_EMAIL"
        value = var.owner_email
      }
      env {
        name  = "BOAN_JWT_SECRET"
        value = var.jwt_secret
      }
      env {
        name  = "BOAN_GCP_ORG_ID"
        value = var.gcp_org_id
      }
      env {
        name  = "BOAN_ADMIN_EMAILS"
        value = var.admin_emails
      }
      env {
        name  = "BOAN_ALLOWED_SSO"
        value = var.allowed_sso
      }
      env {
        name  = "BOAN_SMTP_HOST"
        value = var.smtp_host
      }
      env {
        name  = "BOAN_SMTP_PORT"
        value = var.smtp_port
      }
      env {
        name  = "BOAN_SMTP_USER"
        value = var.smtp_user
      }
      env {
        name  = "BOAN_SMTP_PASSWORD"
        value = var.smtp_password
      }
      env {
        name  = "BOAN_SMTP_FROM"
        value = var.smtp_from
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public_admin_api" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_v2_service.admin_api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "hosting_url" {
  value = var.enable_firebase_hosting ? "https://${google_firebase_hosting_site.admin[0].site_id}.web.app" : ""
}
output "admin_api_url" { value = google_cloud_run_v2_service.admin_api.uri }
