variable "project_id"   {}
variable "region"       { default = "asia-northeast3" }
variable "org_id"       {}
variable "image"        { default = "boanclaw/boan-policy-server:latest" }

resource "google_cloud_run_v2_service" "policy_server" {
  name     = "boan-policy-server"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
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
      volume_mounts {
        name       = "policy-data"
        mount_path = "/data/policies"
      }
    }
    volumes {
      name = "policy-data"
      gcs {
        bucket    = google_storage_bucket.policy_data.name
        read_only = false
      }
    }
  }
}

resource "google_storage_bucket" "policy_data" {
  name                        = "boanclaw-policy-${var.org_id}-${var.project_id}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
}

output "policy_server_url" { value = google_cloud_run_v2_service.policy_server.uri }
