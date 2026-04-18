terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

module "network" {
  source                        = "../../modules/network"
  project_id                    = var.project_id
  region                        = var.region
  org_id                        = var.org_id
  workstation_rdp_source_ranges = var.workstation_rdp_source_ranges
}

module "kms" {
  source     = "../../modules/kms"
  project_id = var.project_id
  region     = var.region
  org_id     = var.org_id
}

module "logging" {
  source     = "../../modules/logging"
  project_id = var.project_id
  region     = var.region
  org_id     = var.org_id
}

module "policy_server" {
  source     = "../../modules/policy-server"
  project_id = var.project_id
  region     = var.region
  org_id     = var.org_id
  image      = var.policy_server_image
}

module "org_llm_proxy" {
  source                     = "../../modules/boan-org-llm-proxy"
  project_id                 = var.project_id
  region                     = var.region
  org_id                     = var.org_id
  image                      = var.org_llm_proxy_image
  auth_token                 = var.org_llm_proxy_auth_token
  allowed_hosts              = var.org_llm_proxy_allowed_hosts
  credential_gate_url        = module.credential_gate.credential_gate_url
  credential_gate_auth_token = var.credential_gate_auth_token
  device_pubkeys             = var.device_pubkeys
  revoked_devices            = var.revoked_devices
  rate_limit_rpm             = var.org_llm_proxy_rpm
}

module "credential_gate" {
  source          = "../../modules/boan-org-credential-gate"
  project_id      = var.project_id
  region          = var.region
  org_id          = var.org_id
  image           = var.credential_gate_image
  auth_token      = var.credential_gate_auth_token
  device_pubkeys  = ""
  revoked_devices = var.revoked_devices
}

module "admin_console" {
  source                       = "../../modules/admin-console"
  project_id                   = var.project_id
  region                       = var.region
  org_id                       = var.org_id
  policy_server_url            = module.policy_server.policy_server_url
  admin_api_image              = var.admin_api_image
  enable_firebase_hosting      = var.enable_firebase_hosting
  oauth_client_id              = var.oauth_client_id
  oauth_client_secret          = var.oauth_client_secret
  oauth_redirect_url           = var.oauth_redirect_url
  app_base_url                 = var.app_base_url
  allowed_email_domains        = var.allowed_email_domains
  owner_email                  = var.owner_email
  jwt_secret                   = var.jwt_secret
  gcp_org_id                   = var.gcp_org_id
  admin_emails                 = var.admin_emails
  allowed_sso                  = var.allowed_sso
  smtp_host                    = var.smtp_host
  smtp_port                    = var.smtp_port
  smtp_user                    = var.smtp_user
  smtp_password                = var.smtp_password
  smtp_from                    = var.smtp_from
  workstation_provider         = var.workstation_provider
  workstation_platform         = var.workstation_platform
  workstation_region           = var.workstation_region
  workstation_machine_type     = var.workstation_machine_type
  workstation_project_id       = var.workstation_project_id
  workstation_zone             = var.workstation_zone
  workstation_image_project    = var.workstation_image_project
  workstation_image_family     = var.workstation_image_family
  workstation_subnetwork       = var.workstation_subnetwork
  workstation_network_tags     = var.workstation_network_tags
  workstation_service_account  = var.workstation_service_account
  workstation_root_volume_gib  = var.workstation_root_volume_gib
  workstation_console_base_url = var.workstation_console_base_url
  workstation_web_base_url     = var.workstation_web_base_url
}

output "vpc_id" { value = module.network.vpc_id }
output "project_id" { value = var.project_id }
output "project_name" { value = var.project_name }
output "policy_server_url" { value = module.policy_server.policy_server_url }
output "admin_console_url" { value = module.admin_console.hosting_url }
output "admin_api_service_account" { value = module.admin_console.admin_api_service_account }
output "workstation_service_account" { value = module.admin_console.workstation_service_account }
output "audit_bucket" { value = module.logging.bucket_name }
output "kms_keyring" { value = module.kms.keyring_id }
