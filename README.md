# AccuKnox Asset Check

Scan AWS, Azure, GCP, and Oracle Cloud for billable or all resources from a single browser-based UI. Ships as a self-contained binary — no runtime, no dependencies.

---

## Install

### macOS

```bash
# Apple Silicon
curl -Lo ak-asset-check https://github.com/accuknox/ak-asset-check/releases/latest/download/ak-asset-check-darwin-arm64.tar.gz \
  | tar -xz && chmod +x ak-asset-check && sudo mv ak-asset-check /usr/local/bin/

# Intel
curl -Lo ak-asset-check https://github.com/accuknox/ak-asset-check/releases/latest/download/ak-asset-check-darwin-amd64.tar.gz \
  | tar -xz && chmod +x ak-asset-check && sudo mv ak-asset-check /usr/local/bin/
```

### Linux

```bash
# tar.gz
curl -Lo ak-asset-check https://github.com/accuknox/ak-asset-check/releases/latest/download/ak-asset-check-linux-amd64.tar.gz \
  | tar -xz && chmod +x ak-asset-check && sudo mv ak-asset-check /usr/local/bin/

# Debian / Ubuntu (.deb)
curl -LO https://github.com/accuknox/ak-asset-check/releases/latest/download/ak-asset-check_linux_amd64.deb
sudo dpkg -i ak-asset-check_linux_amd64.deb

# RHEL / Fedora (.rpm)
sudo rpm -i https://github.com/accuknox/ak-asset-check/releases/latest/download/ak-asset-check_linux_amd64.rpm
```

### Windows

Download `ak-asset-check-windows-amd64.zip` from the [latest release](https://github.com/accuknox/ak-asset-check/releases/latest), extract, and place `ak-asset-check.exe` anywhere on your `PATH`.

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
