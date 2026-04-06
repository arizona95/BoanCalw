variable "project_id" {}
variable "region" { default = "asia-northeast3" }
variable "org_id" {}
variable "workstation_rdp_source_ranges" {
  type    = list(string)
  default = []
}

resource "google_compute_network" "boan_vpc" {
  name                    = "boanclaw-vpc-${var.org_id}"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "boan_subnet" {
  name          = "boanclaw-subnet-${var.org_id}"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.boan_vpc.id
  ip_cidr_range = "10.100.0.0/24"

  private_ip_google_access = true
}

resource "google_compute_firewall" "allow_internal" {
  name    = "boanclaw-allow-internal"
  project = var.project_id
  network = google_compute_network.boan_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["8080", "8090", "18080", "18081"]
  }

  source_ranges = ["10.100.0.0/24"]
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = "boanclaw-deny-egress"
  project   = var.project_id
  network   = google_compute_network.boan_vpc.id
  direction = "EGRESS"
  priority  = 65534

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_proxy_egress" {
  name      = "boanclaw-allow-proxy-egress"
  project   = var.project_id
  network   = google_compute_network.boan_vpc.id
  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["443", "80"]
  }

  target_tags        = ["boan-proxy"]
  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_workstation_egress" {
  name      = "boanclaw-allow-workstation-egress"
  project   = var.project_id
  network   = google_compute_network.boan_vpc.id
  direction = "EGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["53", "80", "443"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "123", "443"]
  }

  target_tags        = ["boan-workstation"]
  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_admin_ingress" {
  name    = "boanclaw-allow-admin"
  project = var.project_id
  network = google_compute_network.boan_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  target_tags   = ["boan-admin"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_workstation_rdp" {
  name    = "boanclaw-allow-workstation-rdp"
  project = var.project_id
  network = google_compute_network.boan_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  target_tags   = ["boan-workstation"]
  source_ranges = var.workstation_rdp_source_ranges
}

output "vpc_id" { value = google_compute_network.boan_vpc.id }
output "subnet_id" { value = google_compute_subnetwork.boan_subnet.id }
output "vpc_self_link" { value = google_compute_network.boan_vpc.self_link }
