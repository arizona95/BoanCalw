# BoanClaw

> Security isolation + information-flow control + built-in guardrails — a wrapper around OpenClaw.
> Structurally prevents credentials, source code, and customer data from leaking outside while you run a coding agent.

---

## 1. One-line install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/arizona95/BoanCalw/main/install.sh)
```

Once it finishes, open your browser at **<http://localhost:19080>**.

---

## 2. Joining an organization

In the browser → click **"Request to join"** → fill in two fields:

- **Org-server URL** — given to you by the organization owner (e.g. `https://boan-policy-server-sds-corp-xxxxx.run.app`)
- **Company email**

Submit; the owner receives a join request and, once approved, you can sign in via email SSO. *No token / org ID needed — a single URL is enough.*

> **Org owners (admins)** must deploy the GCP infrastructure first → see [`docs/00_admin_install.md`](docs/00_관리자_설치.md).

---

## 3. Per-environment install guide

### Case 1 — Linux / WSL2 (Docker already installed)
Just run the one-line install above. Done.

### Case 2 — Windows (no WSL yet)
In PowerShell (Admin):
```powershell
wsl --install
```
Reboot → open the WSL Ubuntu terminal → install Docker:
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
Then run the one-line install. Windows automatically forwards `http://localhost:19080` to your browser.

### Case 3 — Linux without Docker
**Ubuntu / Debian**
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
**CentOS / RHEL / Fedora**
```bash
sudo dnf install -y docker docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
Then run the one-line install.

### Case 4 — macOS
Install Docker Desktop (<https://docs.docker.com/desktop/install/mac-install/>) → launch it → run the one-line install.

### Case 5 — `docker-credential-desktop.exe: not found`
Happens on environments where Docker Desktop was installed and then removed.
```bash
python3 -c "
import json
with open('$HOME/.docker/config.json') as f: c = json.load(f)
c.pop('credsStore', None)
with open('$HOME/.docker/config.json', 'w') as f: json.dump(c, f, indent=2)
"
```

### Update
```bash
cd ~/boanclaw && bash install.sh
```

---

## 🧱 What BoanClaw does

Coding agents like OpenClaw are powerful, but running them as-is easily leaks **credentials, source code, and customer data** to external LLMs. BoanClaw leaves OpenClaw untouched and wraps it in five structural layers:

1. **S1–S5 zone separation** — five trust zones (data / execution / policy / external / cloud). Every cross-zone hop traverses a gate.
2. **G1 / G2 / G3 guardrails** — three-stage inspection: regex → **security LLM (constitution)** → **security LLM (self-evolving wiki)**. *The reference implementation uses Ollama (gemma), but the design assumes "any security model can be plugged in" — the Security LLM Registry decides the actual model.*
3. **Cloud Credential Vault** — credential plaintext lives only in GCP Secret Manager (Cloud Run `boan-org-credential-gate`). The local host holds only `{{CREDENTIAL:role}}` placeholders.
4. **Single egress (org-llm-proxy)** — every external LLM call goes through Cloud Run `boan-org-llm-proxy`. Local hosts never egress to ollama / anthropic / openai directly. Right before the LLM call, the cloud substitutes the credential and scrubs any echoed credentials from the response.
5. **OpenClaw integrity verification** — blocks supply-chain attacks. Pinned version + binary sha256 is verified at every container start.

For the full architecture see [`docs/02_architecture.md`](docs/02_구성도.md); for the role of the security LLM see [`docs/04_LLM_guardrail.md`](docs/04_LLM가드레일.md).

---

## 📚 Document index

| File | Contents |
|---|---|
| [`docs/00_admin_install.md`](docs/00_관리자_설치.md) | **GCP deployment guide for org owners (admins)** |
| [`docs/01_security_philosophy.md`](docs/01_보안철학.md) | S1–S5, fail-closed, information-flow principles |
| [`docs/02_architecture.md`](docs/02_구성도.md) | Full architecture, containers, mounts, info-flow edges |
| [`docs/03_security_gateway.md`](docs/03_보안게이트웨이.md) | Input / Credential / Network gate behavior |
| [`docs/04_LLM_guardrail.md`](docs/04_LLM가드레일.md) | G1 / G2 / G3 evaluation algorithm + **security-LLM abstraction** |
| [`docs/05_credential_vault.md`](docs/05_Credential_Vault.md) | S5 vault, Secret Manager, P3 device JWT, P4 revoke / rate-limit |
| [`docs/06_EDR_wazuh.md`](docs/06_EDR_Wazuh.md) | Wazuh-based endpoint detection + Fluent Bit log integration |
| [`docs/07_other_claw_comparison.md`](docs/07_타Claw보안비교.md) | Security comparison with OpenClaw / open-computer-use |
| [`docs/08_agent_security.md`](docs/08_에이전트보안고려사항.md) | Mapping to Anthropic agent guidelines |
| [`docs/09_integration_tests.md`](docs/09_통합테스트.md) | API E2E test spec (`/api/test/*`) |
| [`test/Report/`](test/Report/) | Per-feature validation reports (with real cloud / backend evidence) |

---

## 🚀 Daily usage

```bash
# Start / stop
cd ~/boanclaw
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml down

# After code changes (rebuilds proxy / sandbox / console together)
./scripts/rebuild.sh
```

| Port | Service |
|---|---|
| `19080` | Admin console (admin-console) |
| `18080` | boan-proxy MITM (for HTTP_PROXY) |
| `18081` | boan-proxy admin API |
| `8082` | credential-filter (S4 thin forwarder, no plaintext storage) |
| `8084` | audit-agent |
| `8086` | llm-registry |
| `8090` | computer-use |
| `8091` | boan-org-llm-proxy *(local dev; production runs on Cloud Run)* |
| `8092` | boan-org-credential-gate *(local dev; production runs on Cloud Run)* |

---

## 🧪 Development / contributing

```bash
# Go unit tests (proxy)
cd src/packages/boan-proxy && go test ./... -count=1

# TypeScript unit tests (admin-console)
cd src/packages/boan-admin-console && npm test

# Full integration suite
./scripts/test.sh
```

Rule of thumb when editing code: **always rebuild proxy / sandbox / console together** — `scripts/rebuild.sh` bundles all three automatically (sandbox embeds the boan-proxy binary at build time).
