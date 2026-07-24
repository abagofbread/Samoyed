# GCP corporate mesh fixture

Synthetic Terraform state for five GCP projects. `proj-dmz` contains an internet-facing bastion, peered through `proj-app` to the PCI project. Cloud Build in `proj-shared` can impersonate the PCI reader service account, which reaches the GCS crown jewel and production secret.
