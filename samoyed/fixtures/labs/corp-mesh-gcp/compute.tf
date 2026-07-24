resource "google_compute_instance" "bastion" {
  project = var.project_dmz
  name = "bastion-01"
  zone = "us-central1-a"
  machine_type = "e2-micro"
  boot_disk { initialize_params { image = "debian-cloud/debian-12" } }
  network_interface { network = google_compute_network.dmz.name; access_config {} }
  service_account { email = google_service_account.bastion.email; scopes = ["cloud-platform"] }
}
resource "google_cloud_run_v2_service" "app_api" {
  project = var.project_app
  name = "app-api"
  location = var.region
  template { service_account = google_service_account.cloudbuild.email; containers { image = "us-docker.pkg.dev/cloudrun/container/hello" } }
}
resource "google_storage_bucket" "pci_crown_jewel" {
  project = var.project_pci
  name = "corp-pci-crown-jewel"
  location = "US"
}
resource "google_secret_manager_secret" "prod_db" {
  project = var.project_pci
  secret_id = "prod-db-password"
  replication { auto {} }
}
