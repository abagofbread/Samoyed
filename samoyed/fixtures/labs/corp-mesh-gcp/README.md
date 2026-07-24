# Corp mesh GCP lab

This illustrative, multi-project topology has DMZ, application, PCI, shared, and staging VPCs. An internet-facing bastion in `proj-dmz` peers through `proj-app` toward `proj-pci`; Cloud Build in `proj-shared` can impersonate a PCI reader service account.

The WIF pool is a GitHub OIDC stub. A real GKE workload-identity deployment would annotate its Kubernetes service account with `iam.gke.io/gcp-service-account=<service-account-email>`; that Kubernetes object is intentionally outside this Terraform-only lab.

Use `corp_mesh_gcp.tfstate` for a self-contained, synthetic importer demo. This directory is valid-looking reference infrastructure and should not be applied as production configuration.
