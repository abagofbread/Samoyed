resource "google_compute_network" "dmz" { name = "dmz"; project = var.project_dmz; auto_create_subnetworks = false }
resource "google_compute_network" "app" { name = "app"; project = var.project_app; auto_create_subnetworks = false }
resource "google_compute_network" "pci" { name = "pci"; project = var.project_pci; auto_create_subnetworks = false }
resource "google_compute_network" "shared" { name = "shared"; project = var.project_shared; auto_create_subnetworks = false }
resource "google_compute_network" "staging" { name = "staging"; project = var.project_staging; auto_create_subnetworks = false }

resource "google_compute_network_peering" "dmz_app" {
  name = "dmz-app"; network = google_compute_network.dmz.self_link; peer_network = google_compute_network.app.self_link
}
resource "google_compute_network_peering" "app_pci" {
  name = "app-pci"; network = google_compute_network.app.self_link; peer_network = google_compute_network.pci.self_link
}
resource "google_compute_firewall" "bastion_ssh" {
  name = "bastion-ssh"; network = google_compute_network.dmz.name; source_ranges = ["0.0.0.0/0"]
  allow { protocol = "tcp"; ports = ["22"] }
}
