# Illustrative only — grand tri-cloud GCP IAM (app-deploy patient pivot).

resource "google_service_account" "app_deploy" {
  project    = "proj-app"
  account_id = "app-deploy"
}

resource "google_service_account_iam_member" "app_deploy_impersonates_build" {
  service_account_id = "cloudbuild@proj-shared.iam.gserviceaccount.com"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:app-deploy@proj-app.iam.gserviceaccount.com"
}

resource "google_service_account" "decoy_metrics" {
  project    = "proj-staging"
  account_id = "decoy-metrics"
}

resource "google_storage_bucket_iam_member" "pci_reader_crown" {
  bucket = "corp-pci-crown-jewel"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:pci-reader@proj-pci.iam.gserviceaccount.com"
}
