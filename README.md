
 <p align="center">
 <img src="Logo.png" width="500px" alt="Apimspray" />
</p>

## apimspray

apimspray is a specialized **Entra ID Authentication Assessment Toolkit** designed for authorized security research and Red Teaming. It utilizes Azure API Management (APIM) gateways as a distributed, rotating proxy layer to analyze authentication behavior and simulate distributed traffic patterns.

> **⚠️ AUTHORIZED USE ONLY**  
> This tool is intended for use by authorized security professionals to validate detection capabilities and authentication protections.  
> Unimplemented or malicious use against targets without permission is illegal.

## Features

- **Distributed Egress**: Routes each request through a rotating pool of Azure APIM gateways (Round-Robin).
- **Smart Lockout Handling**: Detects `AADSTS50053` and implements compliant back-off (65s) to avoid permanent lockout during testing.
- **Pacing Control**: Pre-defined profiles (`stealth`, `low`, `medium`, `high`) incorporating worker counts, delays, jitter, and safety thresholds.
- **Client Emulation**: Rotates valid Microsoft Client IDs (Teams, Office, PowerShell) and User-Agents (Windows 11).
- **Modes**:
  - `validate`: Single pass credential validation (1:1).
  - `spray`: Password spraying (1 password -> N users).

## Prerequisites

- **Python 3.10+**
- **Azure CLI (`az`)**: Required for the rotator script to deploy resources.
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
   *Note: The rotator script relies on an active background Azure CLI session to deploy resources.*

## Setup

### 1. Deploy Gateways
You can deploy gateways manually or let `apimspray.py` handle it automatically.

#### Option A: Automatic Deployment
Simply run `apimspray.py` without the `--urls` argument. The tool will detect missing resources and prompt you to deploy them automatically (defaults to 33 instances).

```bash
python3 apimspray.py --mode spray --users users.txt --passwords passwords.txt
```

#### Option B: Manual Deployment (Python)
Use the included Python script for more control:

```bash
# Deploys 5 APIM instances and saves to urls.txt
python3 apimspraycreate.py --count 5 --outfile urls.txt
```

#### Option C: Manual Deployment (Bash)
Legacy bash script is also available:

```bash
./apimsprayrotator.sh --count 5 --outfile urls.txt
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
# OR
python3 generate_upns.py --target 00000000-0000-0000-0000-000000000000
```

## Usage

```text
usage: apimspray.py [-h] --urls URLS [--users USERS] [--passwords PASSWORDS] 
                    [--output OUTPUT] [--tenant TENANT] [--domain DOMAIN] 
                    --mode {spray,validate}
                    [--pace {stealth,low,mid,medium,high}] [--continue-on-success]
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

| Profile | Workers | Delay | Count (Chunk) | Lockout Wait | Safe Threshold | Jitter |
|:--------|:-------:|:-----:|:-------------:|:------------:|:--------------:|:------:|
| `high` | 15 | 0.1s | 10 | 5m | 20 locked | 0% |
| `medium` | 5 | 1.0s | 5 | 10m | 10 locked | 10% |
| `low` | 2 | 5.0s | 2 | 15m | 5 locked | 20% |
| `stealth` | 1 | 30.0s | 1 | 20m | 1 locked | 40% |

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
