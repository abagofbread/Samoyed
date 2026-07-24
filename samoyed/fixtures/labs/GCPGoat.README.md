# GCPGoat starter target

Use [ine-labs/GCPGoat](https://github.com/ine-labs/GCPGoat) the same way AWSGoat lives under `.samoyed/AWSGoat`.

```bash
git clone https://github.com/ine-labs/GCPGoat.git .samoyed/GCPGoat
# optional live deploy (needs billing + ADC):
# gcloud auth application-default login
# terraform -chdir=.samoyed/GCPGoat apply

# Offline / post-apply import into Samoyed:
samoyed import-path .samoyed/GCPGoat
# or:
samoyed import-path .samoyed/GCPGoat/terraform.tfstate
```

With GCP application-default credentials configured, plain live enum works without `--provider`:

```bash
samoyed enum
samoyed scenario leaked-credential --session-id <id>
```

Module 1 surfaces Cloud Functions (incl. SSRF→metadata paths), GCS misconfigurations, IAM privilege escalations, and Compute Engine. Attack manuals live upstream under `attack-manuals/`.

`.samoyed/` is gitignored — do not commit the clone.
