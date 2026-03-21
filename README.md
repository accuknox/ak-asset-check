# AccuKnox Asset Check

Scan AWS, Azure, GCP, and Oracle Cloud for billable or all resources from a single browser-based UI. Ships as a self-contained binary — no runtime, no dependencies.

---

## Install

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/accuknox/ak-asset-check/main/install.sh | sh
```

The script auto-detects your OS and architecture (amd64 / arm64) and installs to `/usr/local/bin`. To install to a different directory:

```bash
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/accuknox/ak-asset-check/main/install.sh | sh
```

To pin a specific version:

```bash
VERSION=v1.2.0 curl -fsSL https://raw.githubusercontent.com/accuknox/ak-asset-check/main/install.sh | sh
```

### Windows (PowerShell)

```powershell
iwr -useb https://raw.githubusercontent.com/accuknox/ak-asset-check/main/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\ak-asset-check` and adds it to your user `PATH`.

---

## Configure credentials

The tool reads credentials from the standard locations for each cloud — no extra configuration needed.

| Cloud | Credential source |
|-------|-------------------|
| <img src="static/logo-aws.svg" height="16" alt="AWS"> **AWS** | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, `~/.aws/credentials`, or instance/task role |
| <img src="static/logo-azure.svg" height="16" alt="Azure"> **Azure** | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` env vars, or Azure CLI (`az login`) |
| <img src="static/logo-gcp.svg" height="16" alt="GCP"> **GCP** | `GOOGLE_APPLICATION_CREDENTIALS` env var pointing to a service-account JSON, or `gcloud auth application-default login` |
| <img src="static/logo-oracle.svg" height="16" alt="Oracle"> **Oracle** | `~/.oci/config` (populated by `oci setup config`) |

Only the clouds with valid credentials will appear in the UI.

---

## Run

```bash
ak-asset-check
# AccuKnox Asset Check — http://0.0.0.0:8000
```

Open **http://localhost:8000** in a browser.

To use a different port:

```bash
PORT=9090 ak-asset-check
```

---

## Usage

1. The UI shows a pill for each detected cloud account.
2. Choose **Billable scan** (faster, key resources only) or **Full scan** (all resources).
3. Click **Start Scan** — results stream in real time.
4. Use **Export CSV** or **Export JSON** to download the inventory.

---

## Build from source

```bash
git clone https://github.com/accuknox/ak-asset-check.git
cd ak-asset-check
make build          # native binary → dist/ak-asset-check
make build-all      # all platforms → dist/
```

Requires Go 1.23+.
