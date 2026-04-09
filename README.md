# Entra ID Stale Account Hunter

Scans your Microsoft Entra ID (Azure AD) tenant for inactive, over-privileged, and at-risk accounts. Calculates a risk score for each account and exports a detailed CSV report.

Zero dependencies beyond Python 3.8+ and OpenSSL.

## What It Detects

- Accounts with no sign-in for 90+ days
- Accounts that were created but never signed in
- Passwords unchanged for 180+ days
- Passwords set to never expire
- Privileged role assignments (Global Admin, Security Admin, etc.)
- Stale accounts that also hold privileged roles (critical combination)
- Guest accounts that are inactive
- Licensed accounts that never signed in (wasted licenses)

## Risk Scoring

Each account is scored based on the flags it triggers:

| Risk Level | Score | Meaning |
|------------|-------|---------|
| CRITICAL   | 50+   | Immediate action required |
| HIGH       | 30+   | Review within 7 days |
| MEDIUM     | 15+   | Review within 30 days |
| LOW        | 1-14  | Best practice cleanup |

## Prerequisites

### 1. Entra ID App Registration

You need an app registration in your Entra ID tenant with:

- **Application (client) permissions** (not delegated):
  - `User.Read.All`
  - `Directory.Read.All`
  - `AuditLog.Read.All` (required for `signInActivity`)
- **Admin consent** granted for all permissions
- **Certificate-based authentication** (no client secrets)

### 2. Certificate

Generate a self-signed certificate or use an existing one:

```bash
# Generate a self-signed cert (valid 2 years)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 730 -nodes -subj "/CN=EntraAudit"

# Combine into PFX (upload cert.pem to your app registration in Entra ID)
openssl pkcs12 -export -out auth.pfx -inkey key.pem -in cert.pem -passout pass:
```

Upload `cert.pem` to your app registration under **Certificates & secrets > Certificates**.

### 3. Tools

- Python 3.8+
- OpenSSL (pre-installed on macOS and most Linux)

No pip packages required. The script uses only Python standard library and OpenSSL CLI.

## Configuration

Edit the top of `entra_stale_account_hunter.py`:

```python
TENANT_ID  = "your-tenant-id"          # From Entra ID > Overview
CLIENT_ID  = "your-app-client-id"      # From your app registration
CERT_PATH  = "/path/to/your/auth.pfx"  # Path to PFX certificate
```

Or set `CERT_PATH` as an environment variable:

```bash
export CERT_PATH="/path/to/your/auth.pfx"
```

### Tunable Thresholds

```python
DAYS_INACTIVE     = 90   # Flag accounts with no sign-in for X+ days
DAYS_PASSWORD_OLD = 180  # Flag passwords not changed in X+ days
DAYS_NEVER_USED   = 30   # Flag accounts created X+ days ago that never signed in
```

## Usage

```bash
python3 entra_stale_account_hunter.py
```

Output:

```
Authenticating with Graph API...
Fetching all users (with sign-in activity)...
  Found 346 user accounts
Fetching privileged role assignments...
  Found 9 privileged role assignments
Fetching guest accounts...
  Found 12 guest accounts
Analyzing accounts and calculating risk scores...
Report saved: reports/entra_stale_accounts_20260409_042942.csv

============================================================
  ENTRA ID STALE ACCOUNT HUNTER - SUMMARY
============================================================
  Total accounts flagged:  185
  CRITICAL:                5
  HIGH:                    51
  MEDIUM:                  129
  LOW:                     0
============================================================
```

The CSV report is saved to `reports/` with a timestamp in the filename.

## CSV Report Columns

| Column | Description |
|--------|-------------|
| DisplayName | Account display name |
| UPN | User principal name (email) |
| Enabled | Whether the account is active |
| UserType | Member or Guest |
| Department | Department from Entra ID |
| JobTitle | Job title from Entra ID |
| Created | Account creation date |
| LastSignIn | Last interactive or non-interactive sign-in |
| LastPasswordChange | When the password was last changed |
| PasswordNeverExpires | Whether password expiration is disabled |
| PrivilegedRoles | Comma-separated list of admin roles held |
| LicenseCount | Number of M365 licenses assigned |
| RiskScore | Calculated risk score |
| RiskLevel | CRITICAL / HIGH / MEDIUM / LOW |
| Flags | All risk flags triggered for this account |

## Recommended Actions

After reviewing the report:

1. **CRITICAL accounts** - Disable immediately, investigate if compromised
2. **HIGH accounts** - Review within 7 days, disable or rotate credentials
3. **Stale + Privileged** - Remove admin roles first, then disable
4. **Never signed in + Licensed** - Reclaim the license
5. **Guest accounts inactive 90+ days** - Remove from tenant

## Automation

Run on a schedule (cron, Jenkins, GitHub Actions) and email the report:

```bash
# Example: weekly scan via cron
0 8 * * 1 python3 /path/to/entra_stale_account_hunter.py
```

## License

MIT
