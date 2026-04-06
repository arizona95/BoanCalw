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
variable "workstation_provider" { default = "gcp-compute" }
variable "workstation_platform" { default = "windows" }
variable "workstation_region" { default = "asia-northeast3" }
variable "workstation_machine_type" { default = "e2-standard-2" }
variable "workstation_project_id" { default = "" }
variable "workstation_zone" { default = "asia-northeast3-a" }
variable "workstation_image_project" { default = "windows-cloud" }
variable "workstation_image_family" { default = "windows-2022" }
variable "workstation_subnetwork" { default = "" }
variable "workstation_network_tags" { default = "" }
variable "workstation_service_account" { default = "" }
variable "workstation_root_volume_gib" { default = "100" }
variable "workstation_console_base_url" { default = "" }
variable "workstation_web_base_url" { default = "" }

locals {
  admin_api_service_account_id     = "boan-admin-api"
  workstation_service_account_id   = "boan-workstation-vm"
  effective_workstation_sa_email   = var.workstation_service_account != "" ? var.workstation_service_account : google_service_account.workstation_vm.email
}

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

resource "google_service_account" "admin_api" {
  project      = var.project_id
  account_id   = local.admin_api_service_account_id
  display_name = "BoanClaw Admin API"
}

resource "google_service_account" "workstation_vm" {
  project      = var.project_id
  account_id   = local.workstation_service_account_id
  display_name = "BoanClaw Workstation VM"
}

resource "google_project_iam_member" "admin_api_compute_instance_admin" {
  project = var.project_id
  role    = "roles/compute.instanceAdmin.v1"
  member  = "serviceAccount:${google_service_account.admin_api.email}"
}

resource "google_project_iam_member" "admin_api_compute_network_user" {
  project = var.project_id
  role    = "roles/compute.networkUser"
  member  = "serviceAccount:${google_service_account.admin_api.email}"
}

resource "google_project_iam_member" "admin_api_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.admin_api.email}"
}

resource "google_service_account_iam_member" "admin_api_service_account_user" {
  service_account_id = google_service_account.workstation_vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.admin_api.email}"
}

# Cloud Run for SSO callback + API proxy
resource "google_cloud_run_v2_service" "admin_api" {
  name     = "boan-admin-api"
  location = var.region
  project  = var.project_id

  template {
    service_account = google_service_account.admin_api.email

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
      env {
        name  = "BOAN_WORKSTATION_PROVIDER"
        value = var.workstation_provider
      }
      env {
        name  = "BOAN_WORKSTATION_PLATFORM"
        value = var.workstation_platform
      }
      env {
        name  = "BOAN_WORKSTATION_REGION"
        value = var.workstation_region
      }
      env {
        name  = "BOAN_WORKSTATION_MACHINE_TYPE"
        value = var.workstation_machine_type
      }
      env {
        name  = "BOAN_WORKSTATION_PROJECT_ID"
        value = var.workstation_project_id
      }
      env {
        name  = "BOAN_WORKSTATION_ZONE"
        value = var.workstation_zone
      }
      env {
        name  = "BOAN_WORKSTATION_IMAGE_PROJECT"
        value = var.workstation_image_project
      }
      env {
        name  = "BOAN_WORKSTATION_IMAGE_FAMILY"
        value = var.workstation_image_family
      }
      env {
        name  = "BOAN_WORKSTATION_SUBNETWORK"
        value = var.workstation_subnetwork
      }
      env {
        name  = "BOAN_WORKSTATION_NETWORK_TAGS"
        value = var.workstation_network_tags
      }
      env {
        name  = "BOAN_WORKSTATION_SERVICE_ACCOUNT"
        value = local.effective_workstation_sa_email
      }
      env {
        name  = "BOAN_WORKSTATION_ROOT_VOLUME_GIB"
        value = var.workstation_root_volume_gib
      }
      env {
        name  = "BOAN_WORKSTATION_CONSOLE_BASE_URL"
        value = var.workstation_console_base_url
      }
      env {
        name  = "BOAN_WORKSTATION_WEB_BASE_URL"
        value = var.workstation_web_base_url
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
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
output "admin_api_service_account" { value = google_service_account.admin_api.email }
output "workstation_service_account" { value = local.effective_workstation_sa_email }
