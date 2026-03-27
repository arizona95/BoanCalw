variable "project_id" {}
variable "region"     { default = "asia-northeast3" }
variable "org_id"     {}

resource "google_kms_key_ring" "boan" {
  name     = "boanclaw-${var.org_id}"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "policy" {
  name            = "policy-signing"
  key_ring        = google_kms_key_ring.boan.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "credential" {
  name            = "credential-encryption"
  key_ring        = google_kms_key_ring.boan.id
  rotation_period = "2592000s" # 30 days

  lifecycle {
    prevent_destroy = true
  }
}

output "keyring_id"         { value = google_kms_key_ring.boan.id }
output "policy_key_id"      { value = google_kms_crypto_key.policy.id }
output "credential_key_id"  { value = google_kms_crypto_key.credential.id }
