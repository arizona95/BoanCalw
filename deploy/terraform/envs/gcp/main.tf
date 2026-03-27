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
  backend "gcs" {
    bucket = "boanclaw-tfstate"
    prefix = "boanclaw/gcp"
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
  source     = "../../modules/network"
  project_id = var.project_id
  region     = var.region
  org_id     = var.org_id
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
}

module "admin_console" {
  source             = "../../modules/admin-console"
  project_id         = var.project_id
  region             = var.region
  org_id             = var.org_id
  policy_server_url  = module.policy_server.policy_server_url
}

output "vpc_id"             { value = module.network.vpc_id }
output "policy_server_url"  { value = module.policy_server.policy_server_url }
output "admin_console_url"  { value = module.admin_console.hosting_url }
output "audit_bucket"       { value = module.logging.bucket_name }
output "kms_keyring"        { value = module.kms.keyring_id }
