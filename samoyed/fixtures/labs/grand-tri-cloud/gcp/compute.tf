resource "google_compute_instance" "app_worker" {
  name    = "app-worker-1"
  project = "proj-app"
  # network: projects/proj-app/global/networks/app
}
