variable "project_id" {}
variable "region" { default = "asia-northeast3" }
variable "org_id" {}
variable "image" { default = "boanclaw/boan-policy-server:latest" }

resource "google_service_account" "policy_server" {
  account_id   = "boan-policy-server"
  display_name = "BoanClaw Policy Server"
  project      = var.project_id
}

resource "google_storage_bucket" "policy_data" {
  name                        = "boanclaw-policy-${var.org_id}-${var.project_id}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
}

resource "google_storage_bucket" "policy_keys" {
  name                        = "boanclaw-policy-keys-${var.org_id}-${var.project_id}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "policy_data_admin" {
  bucket = google_storage_bucket.policy_data.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.policy_server.email}"
}

resource "google_storage_bucket_iam_member" "policy_keys_admin" {
  bucket = google_storage_bucket.policy_keys.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.policy_server.email}"
}

resource "google_cloud_run_v2_service" "policy_server" {
  name     = "boan-policy-server-${var.org_id}"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.policy_server.email
    scaling {
      min_instance_count = 1
      max_instance_count = 3
    }
    containers {
      image = var.image
      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
      env {
        name  = "BOAN_ORG_ID"
        value = var.org_id
      }
      env {
        name  = "BOAN_DATA_DIR"
        value = "/data/policies"
      }
      env {
        name  = "BOAN_KEY_DIR"
        value = "/etc/boan-policy"
      }
      volume_mounts {
        name       = "policy-data"
        mount_path = "/data/policies"
      }
      volume_mounts {
        name       = "policy-keys"
        mount_path = "/etc/boan-policy"
      }
    }
    volumes {
      name = "policy-data"
      gcs {
        bucket    = google_storage_bucket.policy_data.name
        read_only = false
      }
    }
    volumes {
      name = "policy-keys"
      gcs {
        bucket    = google_storage_bucket.policy_keys.name
        read_only = false
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_v2_service.policy_server.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "policy_server_url" { value = google_cloud_run_v2_service.policy_server.uri }
