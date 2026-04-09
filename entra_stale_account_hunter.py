#!/usr/bin/env python3
"""
Entra ID Stale Account Hunter
Scans Entra ID for inactive, over-privileged, and at-risk accounts.
Calculates risk scores and exports a detailed CSV report.

Uses certificate-based auth via Graph API (no PowerShell required).

Required env vars:
    CERT_PATH   - Path to exchange-auth.pfx (optional, defaults to knowledge base cert)

Hardcoded config:
    TENANT_ID, CLIENT_ID — IT-Onboarding-Automation app registration
"""

import base64
import csv
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

TENANT_ID  = "9903f1b8-f66c-46ed-824d-ef6aaefa54b9"
CLIENT_ID  = "9b998d6f-8493-4e9a-bc14-91e14e73794a"
CERT_PATH  = os.environ.get("CERT_PATH", os.path.expanduser(
                 "~/ai-knowledge-base/infrastructure/certs/exchange-auth.pfx"))

DAYS_INACTIVE       = 90   # accounts with no sign-in for this many days
DAYS_PASSWORD_OLD   = 180  # passwords not changed in this many days
DAYS_NEVER_USED     = 30   # created X+ days ago but never signed in

# Privileged roles to flag
PRIVILEGED_ROLES = [
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Exchange Administrator",
    "Security Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Conditional Access Administrator",
    "Intune Administrator",
]

OUTPUT_DIR = os.path.expanduser("~/Code/security-monitoring/reports")

# ── Helpers ────────────────────────────────────────────────────────────────────

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def graph_get(url, token, results=None):
    """GET with automatic pagination."""
    if results is None:
        results = []
    headers = {"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode())
    results.extend(data.get("value", []))
    next_link = data.get("@odata.nextLink")
    if next_link:
        return graph_get(next_link, token, results)
    return results


# ── Auth ───────────────────────────────────────────────────────────────────────

def get_graph_token():
    cert_path = os.path.expanduser(CERT_PATH)

    cert_pem = subprocess.check_output(
        ["openssl", "pkcs12", "-in", cert_path, "-clcerts", "-nokeys", "-passin", "pass:"],
        stderr=subprocess.DEVNULL
    )
    der = subprocess.check_output(
        ["openssl", "x509", "-outform", "DER"],
        input=cert_pem, stderr=subprocess.DEVNULL
    )
    thumbprint = b64url(hashlib.sha1(der).digest())

    raw_key = subprocess.check_output(
        ["openssl", "pkcs12", "-in", cert_path, "-nocerts", "-nodes", "-passin", "pass:"],
        stderr=subprocess.DEVNULL
    )
    privkey = subprocess.check_output(
        ["openssl", "rsa"], input=raw_key, stderr=subprocess.DEVNULL
    )

    now = int(datetime.now(timezone.utc).timestamp())
    header  = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "x5t": thumbprint}).encode())
    payload = b64url(json.dumps({
        "aud": f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        "iss": CLIENT_ID, "sub": CLIENT_ID,
        "jti": str(uuid.uuid4()), "nbf": now, "exp": now + 3600,
    }).encode())
    signing_input = f"{header}.{payload}"

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(privkey)
        keyfile = kf.name

    try:
        sig_bytes = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", keyfile],
            input=signing_input.encode(), stderr=subprocess.DEVNULL
        )
    finally:
        os.unlink(keyfile)

    jwt_assertion = f"{signing_input}.{b64url(sig_bytes)}"

    data = "&".join([
        f"client_id={CLIENT_ID}",
        "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        f"client_assertion={jwt_assertion}",
        "grant_type=client_credentials",
        "scope=https://graph.microsoft.com/.default",
    ])
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data=data.encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())["access_token"]


# ── Data Collection ────────────────────────────────────────────────────────────

def get_all_users(token):
    """Fetch all users with sign-in activity, password info, and account status."""
    url = (
        "https://graph.microsoft.com/v1.0/users"
        "?$select=id,displayName,userPrincipalName,accountEnabled,userType,"
        "createdDateTime,lastPasswordChangeDateTime,passwordPolicies,"
        "signInActivity,department,jobTitle,assignedLicenses"
        "&$top=999"
    )
    return graph_get(url, token)


def get_directory_roles(token):
    """Fetch all activated directory roles and their members."""
    roles = graph_get("https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName", token)
    role_members = {}
    for role in roles:
        if role.get("displayName") in PRIVILEGED_ROLES:
            members_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role['id']}/members?$select=id,userPrincipalName"
            members = graph_get(members_url, token)
            for m in members:
                uid = m.get("id", "")
                if uid not in role_members:
                    role_members[uid] = []
                role_members[uid].append(role["displayName"])
    return role_members


def get_guest_users(token):
    """Fetch all guest accounts."""
    url = (
        "https://graph.microsoft.com/v1.0/users"
        "?$filter=userType%20eq%20'Guest'"
        "&$select=id,displayName,userPrincipalName,createdDateTime,signInActivity,accountEnabled"
        "&$top=999"
    )
    return graph_get(url, token)


# ── Risk Scoring ───────────────────────────────────────────────────────────────

def calculate_risk(user, role_members, now):
    """Calculate risk score for a user account. Returns (score, flags)."""
    score = 0
    flags = []
    uid = user.get("id", "")
    upn = user.get("userPrincipalName") or ""
    enabled = user.get("accountEnabled", False)
    user_type = user.get("userType") or "Member"

    # Skip disabled accounts (low priority)
    if not enabled:
        return 0, ["Account disabled"]

    # ── Sign-in activity ───────────────────────────────────────────────────
    sign_in = user.get("signInActivity") or {}
    last_sign_in_str = sign_in.get("lastSignInDateTime") or sign_in.get("lastNonInteractiveSignInDateTime")
    created_str = user.get("createdDateTime") or ""

    last_sign_in = None
    if last_sign_in_str:
        try:
            last_sign_in = datetime.fromisoformat(last_sign_in_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    created = None
    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    days_since_login = None
    if last_sign_in:
        days_since_login = (now - last_sign_in).days

    # Stale account (no login in 90+ days)
    if days_since_login is not None and days_since_login >= DAYS_INACTIVE:
        score += 20
        flags.append(f"No sign-in for {days_since_login} days")

    # Never logged in but account created 30+ days ago
    if last_sign_in is None and created:
        days_since_created = (now - created).days
        if days_since_created >= DAYS_NEVER_USED:
            score += 25
            flags.append(f"Never signed in (created {days_since_created} days ago)")

    # ── Password checks ────────────────────────────────────────────────────
    last_pw_change_str = user.get("lastPasswordChangeDateTime")
    pw_policies = user.get("passwordPolicies") or ""

    if last_pw_change_str:
        try:
            last_pw_change = datetime.fromisoformat(last_pw_change_str.replace("Z", "+00:00"))
            pw_age = (now - last_pw_change).days
            if pw_age >= DAYS_PASSWORD_OLD:
                score += 15
                flags.append(f"Password unchanged for {pw_age} days")
        except (ValueError, TypeError):
            pass

    if "DisablePasswordExpiration" in pw_policies:
        score += 10
        flags.append("Password set to never expire")

    # ── Privileged roles ───────────────────────────────────────────────────
    if uid in role_members:
        roles = role_members[uid]
        role_names = ", ".join(roles)

        if "Global Administrator" in roles:
            score += 30
            flags.append(f"Global Administrator")
        elif "Privileged Role Administrator" in roles:
            score += 25
            flags.append(f"Privileged Role Administrator")
        else:
            score += 15
            flags.append(f"Privileged role(s): {role_names}")

        # Stale + privileged = extra dangerous
        if days_since_login is not None and days_since_login >= DAYS_INACTIVE:
            score += 20
            flags.append("STALE + PRIVILEGED (critical combination)")

    # ── Guest account checks ───────────────────────────────────────────────
    if user_type == "Guest":
        score += 5
        flags.append("External guest account")
        if days_since_login is not None and days_since_login >= DAYS_INACTIVE:
            score += 10
            flags.append("Stale guest account")

    # ── License but no login ───────────────────────────────────────────────
    licenses = user.get("assignedLicenses") or []
    if licenses and last_sign_in is None:
        score += 10
        flags.append(f"Has {len(licenses)} license(s) assigned but never signed in")

    return score, flags


def risk_level(score):
    if score >= 50:
        return "CRITICAL"
    elif score >= 30:
        return "HIGH"
    elif score >= 15:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


# ── Report Generation ──────────────────────────────────────────────────────────

def generate_report(users, role_members, guests, now):
    """Analyze all accounts and return sorted findings."""
    findings = []

    for user in users:
        score, flags = calculate_risk(user, role_members, now)
        if score == 0:
            continue

        sign_in = user.get("signInActivity") or {}
        last_sign_in = sign_in.get("lastSignInDateTime") or sign_in.get("lastNonInteractiveSignInDateTime") or "Never"
        uid = user.get("id", "")
        roles = ", ".join(role_members.get(uid, [])) or "None"

        findings.append({
            "DisplayName": user.get("displayName") or "",
            "UPN": user.get("userPrincipalName") or "",
            "Enabled": user.get("accountEnabled", False),
            "UserType": user.get("userType") or "Member",
            "Department": user.get("department") or "",
            "JobTitle": user.get("jobTitle") or "",
            "Created": (user.get("createdDateTime") or "")[:10],
            "LastSignIn": last_sign_in[:10] if last_sign_in != "Never" else "Never",
            "LastPasswordChange": (user.get("lastPasswordChangeDateTime") or "Unknown")[:10],
            "PasswordNeverExpires": "DisablePasswordExpiration" in (user.get("passwordPolicies") or ""),
            "PrivilegedRoles": roles,
            "LicenseCount": len(user.get("assignedLicenses") or []),
            "RiskScore": score,
            "RiskLevel": risk_level(score),
            "Flags": " | ".join(flags),
        })

    findings.sort(key=lambda x: x["RiskScore"], reverse=True)
    return findings


def write_csv(findings, output_path):
    if not findings:
        print("No findings to write.")
        return

    fieldnames = list(findings[0].keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    print(f"Report saved: {output_path}")


def print_summary(findings):
    total = len(findings)
    critical = sum(1 for f in findings if f["RiskLevel"] == "CRITICAL")
    high = sum(1 for f in findings if f["RiskLevel"] == "HIGH")
    medium = sum(1 for f in findings if f["RiskLevel"] == "MEDIUM")
    low = sum(1 for f in findings if f["RiskLevel"] == "LOW")

    print("\n" + "=" * 60)
    print("  ENTRA ID STALE ACCOUNT HUNTER — SUMMARY")
    print("=" * 60)
    print(f"  Total accounts flagged:  {total}")
    print(f"  CRITICAL:                {critical}")
    print(f"  HIGH:                    {high}")
    print(f"  MEDIUM:                  {medium}")
    print(f"  LOW:                     {low}")
    print("=" * 60)

    if critical > 0 or high > 0:
        print("\n  TOP CRITICAL/HIGH FINDINGS:")
        print("-" * 60)
        for f in findings:
            if f["RiskLevel"] in ("CRITICAL", "HIGH"):
                print(f"  [{f['RiskLevel']}] {f['DisplayName']} ({f['UPN']})")
                print(f"         Score: {f['RiskScore']} | Last login: {f['LastSignIn']}")
                print(f"         Roles: {f['PrivilegedRoles']}")
                print(f"         Flags: {f['Flags']}")
                print()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Authenticating with Graph API...")
    token = get_graph_token()

    print("Fetching all users (with sign-in activity)...")
    users = get_all_users(token)
    print(f"  Found {len(users)} user accounts")

    print("Fetching privileged role assignments...")
    role_members = get_directory_roles(token)
    priv_count = sum(len(v) for v in role_members.values())
    print(f"  Found {priv_count} privileged role assignments")

    print("Fetching guest accounts...")
    guests = get_guest_users(token)
    print(f"  Found {len(guests)} guest accounts")

    print("Analyzing accounts and calculating risk scores...")
    findings = generate_report(users, role_members, guests, now)

    # Write report
    report_path = os.path.join(OUTPUT_DIR, f"entra_stale_accounts_{timestamp}.csv")
    write_csv(findings, report_path)

    # Print summary
    print_summary(findings)

    # Print recommendation
    print("\nRECOMMENDED ACTIONS:")
    print("  1. Disable all CRITICAL accounts immediately")
    print("  2. Review HIGH accounts within 7 days")
    print("  3. Enforce password rotation for accounts with passwords 180+ days old")
    print("  4. Remove unused guest accounts")
    print("  5. Review privileged role assignments quarterly")
    print(f"\n  Full report: {report_path}")


if __name__ == "__main__":
    main()
