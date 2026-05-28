#!/usr/bin/env python3
"""
orchard-sign diagnostics — Parse and diagnose Apple code signing errors.

Covers the most common signing failures:
  - Certificate expired/missing/revoked
  - Provisioning profile invalid/expired/missing entitlements
  - Team ID mismatch
  - Bundle ID mismatch
  - Entitlements conflicts
  - Keychain access failures
  - Automatic signing destructive conflicts
"""

import re
import subprocess
import json
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


@dataclass
class SigningIssue:
    category: str  # certificate, profile, entitlement, keychain, config
    severity: str  # error, warning, info
    title: str
    message: str
    fix: str
    commands: list[str] = field(default_factory=list)
    apple_doc: str = ""


# ═══════════════════════════════════════════
# ERROR PATTERN DATABASE
# ═══════════════════════════════════════════

ERROR_PATTERNS = [
    # Certificate errors
    {
        "pattern": r"(?:No signing certificate|no valid code signing identity|Code Sign error:.*no signing certificate)",
        "category": "certificate",
        "severity": "error",
        "title": "No signing certificate found",
        "fix": "Install a valid Apple Development or Distribution certificate.",
        "commands": [
            "security find-identity -v -p codesigning",
            "# If empty, create a new certificate in Xcode > Settings > Accounts > Manage Certificates"
        ],
        "apple_doc": "https://developer.apple.com/documentation/technotes/tn3161-inside-code-signing-certificates"
    },
    {
        "pattern": r"(?:certificate has expired|CSSMERR_TP_CERT_EXPIRED|expired certificate)",
        "category": "certificate",
        "severity": "error",
        "title": "Signing certificate expired",
        "fix": "Your signing certificate has expired. Revoke it and create a new one.",
        "commands": [
            "security find-identity -v -p codesigning | grep EXPIRED",
            "# Revoke in Apple Developer Portal > Certificates, then create new in Xcode"
        ],
        "apple_doc": "https://developer.apple.com/account/resources/certificates"
    },
    {
        "pattern": r"(?:certificate.*revoked|CSSMERR_TP_CERT_REVOKED)",
        "category": "certificate",
        "severity": "error",
        "title": "Signing certificate revoked",
        "fix": "Certificate was revoked (possibly by automatic signing on another machine). Create a new one.",
        "commands": [
            "security delete-certificate -c 'YOUR_CERT_NAME'",
            "# Then: Xcode > Settings > Accounts > Manage Certificates > +"
        ]
    },
    # Profile errors
    {
        "pattern": r"(?:no provisioning profile|Provisioning profile.*doesn't include|No provisioning profiles with a valid signing identity)",
        "category": "profile",
        "severity": "error",
        "title": "No valid provisioning profile",
        "fix": "No provisioning profile matches your app's bundle ID and signing certificate.",
        "commands": [
            "# List installed profiles:",
            "ls ~/Library/MobileDevice/Provisioning\\ Profiles/",
            "# Decode a profile:",
            "security cms -D -i ~/Library/MobileDevice/Provisioning\\ Profiles/PROFILE.mobileprovision",
            "# Or enable Automatic Signing in Xcode project settings"
        ],
        "apple_doc": "https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles"
    },
    {
        "pattern": r"(?:Provisioning profile.*expired|expired provisioning profile)",
        "category": "profile",
        "severity": "error",
        "title": "Provisioning profile expired",
        "fix": "Your provisioning profile has expired. Regenerate it.",
        "commands": [
            "# Check expiry:",
            "security cms -D -i PROFILE.mobileprovision | grep -A1 ExpirationDate",
            "# Regenerate in Apple Developer Portal > Profiles"
        ]
    },
    {
        "pattern": r"(?:doesn't match.*bundle identifier|bundle identifier.*mismatch)",
        "category": "profile",
        "severity": "error",
        "title": "Bundle ID mismatch",
        "fix": "Your profile's bundle ID doesn't match your project's PRODUCT_BUNDLE_IDENTIFIER.",
        "commands": [
            "# Check your project's bundle ID:",
            "xcodebuild -showBuildSettings | grep PRODUCT_BUNDLE_IDENTIFIER",
            "# Update in Xcode > Target > General > Bundle Identifier"
        ]
    },
    {
        "pattern": r"(?:doesn't include.*entitlement|missing entitlement|entitlement.*not present)",
        "category": "entitlement",
        "severity": "error",
        "title": "Missing entitlement in provisioning profile",
        "fix": "Your app uses an entitlement not included in the provisioning profile.",
        "commands": [
            "# Compare app entitlements vs profile:",
            "codesign -d --entitlements :- YourApp.app",
            "# Add the capability in Apple Developer Portal > Identifiers > Your App"
        ]
    },
    # Keychain errors
    {
        "pattern": r"(?:errSecInternalComponent|User interaction is not allowed|unable to access keychain)",
        "category": "keychain",
        "severity": "error",
        "title": "Keychain access failure",
        "fix": "The build process cannot access the signing keychain. Common in CI/CD.",
        "commands": [
            "# Unlock the keychain:",
            "security unlock-keychain -p PASSWORD ~/Library/Keychains/login.keychain-db",
            "# Set keychain partition list (CI):",
            "security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k PASSWORD ~/Library/Keychains/login.keychain-db"
        ]
    },
    # Team errors
    {
        "pattern": r"(?:multiple teams|ambiguous.*team|team.*mismatch)",
        "category": "config",
        "severity": "warning",
        "title": "Team ID ambiguity",
        "fix": "Multiple development teams found. Specify DEVELOPMENT_TEAM in build settings.",
        "commands": [
            "# Set team explicitly:",
            "xcodebuild -project YourApp.xcodeproj -scheme YourScheme DEVELOPMENT_TEAM=YOUR_TEAM_ID",
            "# Find your team ID:",
            "security find-identity -v -p codesigning | grep 'Developer'"
        ]
    },
    # Automatic signing conflicts
    {
        "pattern": r"(?:Automatic signing is unable|automatic code signing|Xcode could not.*provisioning profile|conflicting provisioning settings)",
        "category": "config",
        "severity": "warning",
        "title": "Automatic signing conflict",
        "fix": "Automatic signing is failing, often because it revoked a certificate another team member needs.",
        "commands": [
            "# Switch to manual signing for teams:",
            "# In Xcode: Target > Signing & Capabilities > uncheck 'Automatically manage signing'",
            "# Or specify in xcodebuild:",
            "xcodebuild CODE_SIGN_STYLE=Manual PROVISIONING_PROFILE_SPECIFIER='YourProfile'"
        ]
    },
]


def diagnose_error(error_text: str) -> list[SigningIssue]:
    """Diagnose code signing errors from xcodebuild output or error messages."""
    issues = []
    error_lower = error_text.lower()

    for pat in ERROR_PATTERNS:
        if re.search(pat["pattern"], error_text, re.IGNORECASE):
            issues.append(SigningIssue(
                category=pat["category"],
                severity=pat["severity"],
                title=pat["title"],
                message=pat.get("message", pat["fix"]),
                fix=pat["fix"],
                commands=pat.get("commands", []),
                apple_doc=pat.get("apple_doc", "")
            ))

    if not issues and ("sign" in error_lower or "provision" in error_lower or "certificate" in error_lower):
        issues.append(SigningIssue(
            category="unknown",
            severity="info",
            title="Unrecognized signing error",
            message=f"Could not auto-diagnose: {error_text[:200]}",
            fix="Check the full xcodebuild log. Common fixes: clean build folder, restart Xcode, re-download profiles.",
            commands=["xcodebuild clean", "rm -rf ~/Library/Developer/Xcode/DerivedData"]
        ))

    return issues


def list_signing_identities() -> dict:
    """List all code signing identities on this machine."""
    try:
        result = subprocess.run(
            ["security", "find-identity", "-v", "-p", "codesigning"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
        identities = []
        for line in lines:
            match = re.match(r'\s*\d+\)\s+([A-F0-9]+)\s+"(.+)"', line)
            if match:
                sha = match.group(1)
                name = match.group(2)
                expired = "EXPIRED" in line
                identities.append({"sha1": sha, "name": name, "expired": expired})
        valid = [i for i in identities if not i["expired"]]
        return {"identities": identities, "valid": len(valid), "expired": len(identities) - len(valid)}
    except Exception as e:
        return {"error": str(e)}


def list_provisioning_profiles() -> dict:
    """List installed provisioning profiles with key details."""
    profiles_dir = Path.home() / "Library" / "MobileDevice" / "Provisioning Profiles"
    if not profiles_dir.exists():
        return {"profiles": [], "error": "No provisioning profiles directory found"}

    profiles = []
    for fp in profiles_dir.glob("*.mobileprovision"):
        try:
            result = subprocess.run(
                ["security", "cms", "-D", "-i", str(fp)],
                capture_output=True, text=True, timeout=10
            )
            plist_text = result.stdout

            name = _extract_plist_value(plist_text, "Name")
            team = _extract_plist_value(plist_text, "TeamName")
            app_id = _extract_plist_value(plist_text, "application-identifier") or _extract_plist_value(plist_text, "AppIDName")
            expiry = _extract_plist_value(plist_text, "ExpirationDate")

            expired = False
            if expiry:
                try:
                    exp_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    expired = exp_date < datetime.now(exp_date.tzinfo)
                except Exception:
                    pass

            profiles.append({
                "file": fp.name,
                "name": name or "Unknown",
                "team": team or "Unknown",
                "app_id": app_id or "Unknown",
                "expired": expired,
                "expiry": expiry or "Unknown"
            })
        except Exception:
            profiles.append({"file": fp.name, "name": "Error reading", "expired": None})

    valid = [p for p in profiles if p.get("expired") is False]
    return {"profiles": profiles, "total": len(profiles), "valid": len(valid)}


def check_signing_health() -> dict:
    """Full signing health check: certificates, profiles, Xcode config."""
    health = {"status": "unknown", "issues": []}

    # Check certificates
    certs = list_signing_identities()
    if certs.get("error"):
        health["issues"].append(f"Certificate check failed: {certs['error']}")
    elif certs["valid"] == 0:
        health["issues"].append("No valid signing certificates found")
        health["status"] = "error"
    else:
        health["certificates"] = f"{certs['valid']} valid, {certs['expired']} expired"

    # Check profiles
    profiles = list_provisioning_profiles()
    if profiles.get("error"):
        health["issues"].append(f"Profile check failed: {profiles['error']}")
    else:
        health["profiles"] = f"{profiles['valid']} valid of {profiles['total']} total"
        expired = [p for p in profiles["profiles"] if p.get("expired")]
        if expired:
            health["issues"].append(f"{len(expired)} expired provisioning profile(s)")

    # Check Xcode
    try:
        result = subprocess.run(["xcode-select", "-p"], capture_output=True, text=True, timeout=5)
        health["xcode_path"] = result.stdout.strip()
    except Exception:
        health["issues"].append("xcode-select not available")

    if not health["issues"]:
        health["status"] = "healthy"
    elif health.get("status") != "error":
        health["status"] = "warning"

    return health


def _extract_plist_value(plist_text: str, key: str) -> str:
    """Extract a value from plist XML text."""
    pattern = rf"<key>{re.escape(key)}</key>\s*<(?:string|date)>([^<]+)</"
    match = re.search(pattern, plist_text)
    return match.group(1) if match else ""


def format_diagnosis(issues: list[SigningIssue]) -> str:
    """Format diagnosis into readable report."""
    if not issues:
        return "No signing issues detected."

    lines = [f"Code Signing Diagnosis: {len(issues)} issue(s)\n"]
    icons = {"error": "ERROR", "warning": "WARN", "info": "INFO"}

    for issue in issues:
        lines.append(f"  [{icons[issue.severity]}] {issue.title}")
        lines.append(f"    Category: {issue.category}")
        lines.append(f"    {issue.fix}")
        if issue.commands:
            lines.append("    Commands:")
            for cmd in issue.commands:
                lines.append(f"      {cmd}")
        if issue.apple_doc:
            lines.append(f"    Docs: {issue.apple_doc}")
        lines.append("")

    return "\n".join(lines)
