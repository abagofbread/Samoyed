resource "google_service_account" "bastion" {
  project = var.project_dmz
  account_id = "bastion"
}
resource "google_service_account" "cloudbuild" {
  project = var.project_shared
  account_id = "cloudbuild"
}
resource "google_service_account" "pci_reader" {
  project = var.project_pci
  account_id = "pci-reader"
}
resource "google_service_account_iam_member" "build_impersonates_pci" {
  service_account_id = google_service_account.pci_reader.name
  role = "roles/iam.serviceAccountTokenCreator"
  member = "serviceAccount:${google_service_account.cloudbuild.email}"
}
resource "google_iam_workload_identity_pool" "github" {
  project = var.project_shared
  workload_identity_pool_id = "github"
}
resource "google_iam_workload_identity_pool_provider" "github_oidc" {
  project = var.project_shared
  workload_identity_pool_id = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}
