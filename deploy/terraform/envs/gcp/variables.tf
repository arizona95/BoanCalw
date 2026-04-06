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

variable "workstation_provider" {
  description = "Personal workstation provider"
  type        = string
  default     = "gcp-compute"
}

variable "workstation_platform" {
  description = "Personal workstation platform"
  type        = string
  default     = "windows"
}

variable "workstation_region" {
  description = "Personal workstation cloud region"
  type        = string
  default     = "asia-northeast3"
}

variable "workstation_machine_type" {
  description = "GCE machine type for personal workstation"
  type        = string
  default     = "e2-standard-2"
}

variable "workstation_project_id" {
  description = "GCP project ID used for personal workstation VM"
  type        = string
  default     = "ai-security-test-473701"
}

variable "workstation_zone" {
  description = "GCE zone for personal workstation"
  type        = string
  default     = "asia-northeast3-a"
}

variable "workstation_image_project" {
  description = "Windows image project"
  type        = string
  default     = "windows-cloud"
}

variable "workstation_image_family" {
  description = "Windows image family"
  type        = string
  default     = "windows-2022"
}

variable "workstation_subnetwork" {
  description = "Required GCE subnetwork name or self link. BoanClaw must not fall back to the default network."
  type        = string
  validation {
    condition     = trimspace(var.workstation_subnetwork) != ""
    error_message = "workstation_subnetwork must be set. BoanClaw must not create instances on the default network or rely on default-allow-* firewall rules."
  }
}

variable "workstation_network_tags" {
  description = "Comma separated network tags for workstation GCE"
  type        = string
  default     = ""
}

variable "workstation_rdp_source_ranges" {
  description = "CIDR ranges allowed to reach Windows workstations over RDP."
  type        = list(string)
  default     = []
}

variable "workstation_service_account" {
  description = "Optional service account email for workstation GCE"
  type        = string
  default     = ""
}

variable "workstation_root_volume_gib" {
  description = "Root volume size for workstation GCE"
  type        = string
  default     = "100"
}

variable "workstation_console_base_url" {
  description = "Console URL template"
  type        = string
  default     = "https://console.cloud.google.com/compute/instancesDetail/zones/{zone}/instances/{instance_name}?project={project}"
}

variable "workstation_web_base_url" {
  description = "Web desktop gateway URL template"
  type        = string
  default     = ""
}
