variable "project_id" {}
variable "region"     { default = "asia-northeast3" }
variable "org_id"     {}

resource "google_storage_bucket" "audit_logs" {
  name                        = "boanclaw-audit-${var.org_id}-${var.project_id}"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = false

  retention_policy {
    is_locked        = true
    retention_period = 31536000 # 1 year
  }

  lifecycle_rule {
    condition { age = 365 }
    action    { type = "Delete" }
  }
}

resource "google_logging_project_sink" "boan_audit" {
  name        = "boanclaw-audit-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = "resource.labels.service_name=\"boan-proxy\""

  unique_writer_identity = true
}

resource "google_storage_bucket_iam_member" "sink_writer" {
  bucket = google_storage_bucket.audit_logs.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.boan_audit.writer_identity
}

output "bucket_name"     { value = google_storage_bucket.audit_logs.name }
output "sink_name"       { value = google_logging_project_sink.boan_audit.name }
