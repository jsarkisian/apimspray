 <p align="center">
 <img src="Logo.png" width="1000px" alt="Apimspray" />
</p>

<p align="center">
  <a href="https://github.com/crtvrffnrt/apimspray">
    <img src="https://img.shields.io/badge/GitHub-Repository-black?style=for-the-badge&logo=github">
  </a>
  <a href="https://shell.azure.com/bash">
    <img src="https://img.shields.io/badge/Azure-Cloud%20Shell-0078D4?style=for-the-badge&logo=microsoftazure">
  </a>
  <a href="https://learn.microsoft.com/entra/identity/">
    <img src="https://img.shields.io/badge/Microsoft-Entra%20ID-6264A7?style=for-the-badge&logo=microsoft">
  </a>
</p>

## apimspray

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Azure](https://img.shields.io/badge/Azure-APIM-blue?logo=microsoftazure)
![License](https://img.shields.io/badge/License-Research--Only-lightgrey)
![Status](https://img.shields.io/badge/Status-Active%20Development-green)

apimspray is a specialized **Entra ID Passwordspraying Toolkit** designed for authorized security research and Red Teaming. It utilizes Azure API Management (APIM) gateways as a distributed, rotating proxy layer for IP Rotating.

## Prerequisites

- **Azure CLI (`az`)**: Required for the rotator script to deploy resources. (Execute script from cli session already authenticated to az cli or use Azure Cloud Shell)
- **Active Azure Subscription**: To deploy APIM Consumption tier resources (Cost is negligible, typically <$0.01 for short assessments).

### Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure you are logged into Azure CLI:
   ```bash
   az login
   ```
   _Note: The rotator script relies on an active background Azure CLI session to deploy resources._

## Setup

### Quick Start (Azure Cloud Shell)

Run apimspray directly from an authenticated Azure environment.

<a href="https://shell.azure.com/bash">
  <img src="https://az-icons.com/api/icon/azure-cloud-shell/download?format=png"
       alt="Open in Azure Cloud Shell"
       width="180" />
</a>

```bash
git clone https://github.com/crtvrffnrt/apimspray.git
cd apimspray
python3 apimspray.py --help
```

### 1. Deploy Gateways

Deploys all APIM instances in a single Bicep deployment for maximum speed.

```bash
# Deploy 33 login gateways
python3 apimcreate.py --type login --count 33 --outfile urls.txt

# Deploy 10 Teams gateways
python3 apimcreate.py --type teams --count 10 --outfile teams_urls.txt

# Deploy both login and Teams gateways in one deployment
python3 apimcreate.py --type both --count 33 --outfile urls.txt --teams-outfile teams_urls.txt

# Deploy into specific regions
python3 apimcreate.py --type login --location germanywestcentral,westeurope --count 33 --outfile urls.txt

# Clean up old deployments
python3 apimcreate.py --type login --delete-only
```

**apimcreate CLI reference:**

```text
usage: apimcreate.py [-h] --type {login,teams,both} [--count COUNT] [--outfile OUTFILE]
                     [--teams-outfile TEAMS_OUTFILE] [--location LOCATION] [--prefix PREFIX]
                     [--delete-old] [--delete-only]

apimcreate - Unified Azure APIM Deployer (Bicep)

options:
  -h, --help            show this help message and exit
  --type {login,teams,both}
                        Type of APIM gateways to deploy
  --count COUNT         Number of instances per type
  --outfile OUTFILE     Output file for login gateway URLs
  --teams-outfile TEAMS_OUTFILE
                        Output file for Teams gateway URLs (required with --type both)
  --location LOCATION   Comma-separated APIM location(s)
  --prefix PREFIX       API URL prefix (default: oauth for login, teamsmt for teams)
  --delete-old          Delete old resource groups before deploying
  --delete-only         Only delete old resource groups
```

**Important:** For all methods, you must have an active `az` session in the background (`az login`).

### 2. Prepare Wordlists

Ensure you have your target lists ready:

- `users.txt`: List of UserPrincipalNames (e.g., `user@domain.com`).
- `passwords.txt`: List of passwords to spray.

### 3. Reconnaissance / UPN Generation (Optional)

If you do not have a user list, you can use the helper script `generate_upns.py`. This tool:

1. Queries the target Azure tenant to discover all connected and verified domains.
2. Downloads a list of statistically likely service account usernames from GitHub.
3. Generates a permutation list of UPNs (UserPrincipalNames) and saves them to `users.txt`.

**Usage:**

```bash
# Generate users.txt for a specific domain or tenant ID
python3 generate_upns.py --target example.com
# OR using Tenantid
python3 generate_upns.py --target 00000000-0000-0000-0000-000000000000
```

**generate_upns CLI reference:**

```text
usage: generate_upns.py [-h] --target TARGET

Generate UPNs from connected Azure Tenants and Service Accounts.

options:
  -h, --help       show this help message and exit
  --target TARGET  Target Domain (e.g., example.com) or Tenant UUID
```

## Usage

```text
usage: apimspray.py [-h] [--urls URLS] [--teams-urls TEAMS_URLS] [--users USERS]
                    [--passwords PASSWORDS] [--output OUTPUT] [--tenant TENANT]
                    [--domain DOMAIN] --mode {spray,validate,enumerate}
                    [--pace {stealth,low,mid,medium,high}] [--continue-on-success]
                    [--randomize-users] [--verbose] [--sac-user SAC_USER]
                    [--sac-pass SAC_PASS] [--sac-accounts SAC_ACCOUNTS]
                    [--teams-region {amer,emea,apac}] [--no-presence] [--skip-sanity]

apimspray - Entra ID Assessment Tool (with Teams Enumeration)

options:
  -h, --help            show this help message and exit
  --urls URLS           Path to APIM URLs file (login gateways, from apimcreate.py)
  --teams-urls TEAMS_URLS
                        Path to Teams APIM URLs file (from apimcreate.py --type teams)
  --users USERS         Path to users file
  --passwords PASSWORDS
                        Path to passwords file
  --output OUTPUT       Output directory
  --tenant TENANT       Tenant ID or Domain
  --domain DOMAIN       Append domain to users if missing
  --mode {spray,validate,enumerate}
                        Operation mode:
                         - spray:      Test all passwords against all users (1:N) via APIM.
                         - validate:   Perform 1:1 credential pair testing via APIM.
                         - enumerate:  Enumerate valid users via Microsoft Teams external search.
  --pace {stealth,low,mid,medium,high}
                        Pacing profile for requests and lockout management.
  --continue-on-success
                        Continue the assessment even after finding valid credentials.
  --randomize-users     Randomize user order before each round.
  --sac-user SAC_USER   Sacrificial O365 username for Teams enumeration
  --sac-pass SAC_PASS   Sacrificial O365 password for Teams enumeration
  --sac-accounts SAC_ACCOUNTS
                        Path to file with additional sacrificial accounts (user:pass per line).
                        Each account adds ~45 req/s to the enumeration pool.
  --teams-region {amer,emea,apac}
                        Teams API region hint (default: amer).
  --no-presence         Skip presence/out-of-office fetching during enumeration.
  --skip-sanity         Skip the pre-enumeration sanity check.
```

### Modes

- **validate**: Checks a list of `user:password` pairs. Requires equal length lists.

  ```bash
  python3 apimspray.py --urls urls.txt --mode validate --users u.txt --passwords p.txt
  ```

- **spray**: Attempts one password against all users, then waits (if configured), then moves to the next password.
  ```bash
  python3 apimspray.py --urls urls.txt --mode spray --users users.txt --passwords common_passwords.txt --pace medium
  ```

### Pacing Profiles

The `--pace` argument controls the aggressiveness of the spray. Values are hardcoded to ensure stability and safety.

| Profile   | Workers | Delay | Count (Chunk) | Lockout Wait | Safe Threshold | Jitter |
| :-------- | :-----: | :---: | :-----------: | :----------: | :------------: | :----: |
| `high`    |   15    | 0.1s  |      10       |      5m      |   20 locked    |   0%   |
| `medium`  |    5    | 1.0s  |       5       |     10m      |   10 locked    |  10%   |
| `low`     |    2    | 5.0s  |       2       |     15m      |    5 locked    |  20%   |
| `stealth` |    1    | 30.0s |       1       |     20m      |    1 locked    |  40%   |

- **Count**: Number of passwords to try per user before pausing to let lockout timers reset.
- **Lockout Wait**: Time to sleep between password chunks.
- **Safe Threshold**: If this many accounts get locked (`AADSTS50053`), the tool aborts immediately.
- **Jitter**: Randomizes the delay to evade static timing analysis.

## Output

Results are stored in the `results/<timestamp>/` directory:

- `valid_*.txt`: Successful authentications (MFA Required or Token received).
- `blocked_*.txt`: Locked or conditionally blocked accounts.
- `failed_*.txt`: Invalid credentials or user not found.

## Credits & References

- **o365spray**: Logic inspiration for ROPC flow.
- **TeamFiltration**: Design inspiration for tool structure.
- **FireProx**: The grandfather of cloud gateway rotation techniques.
