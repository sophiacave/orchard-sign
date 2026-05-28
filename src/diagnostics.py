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
    # Notarization errors
    {
        "pattern": r"(?:notarization|notarize|notary).*(?:failed|error|rejected|invalid)",
        "category": "notarization",
        "severity": "error",
        "title": "Notarization failed",
        "fix": "App notarization was rejected by Apple. Check the notarization log for specific issues.",
        "commands": [
            "# Submit for notarization:",
            "xcrun notarytool submit YourApp.zip --apple-id YOUR_APPLE_ID --password YOUR_APP_PASSWORD --team-id YOUR_TEAM_ID --wait",
            "# Check notarization log:",
            "xcrun notarytool log SUBMISSION_ID --apple-id YOUR_APPLE_ID --password YOUR_APP_PASSWORD"
        ],
        "apple_doc": "https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution"
    },
    {
        "pattern": r"(?:hardened runtime|com\.apple\.security\.cs\.allow-unsigned-executable-memory|runtime hardening)",
        "category": "notarization",
        "severity": "error",
        "title": "Hardened Runtime issue",
        "fix": "Hardened Runtime is required for notarization. Enable it or check entitlements.",
        "commands": [
            "# Enable Hardened Runtime in Xcode:",
            "# Target > Signing & Capabilities > + Capability > Hardened Runtime",
            "# Or via command line:",
            "codesign --force --options runtime --sign 'Developer ID Application: YOUR_NAME' YourApp.app"
        ],
        "apple_doc": "https://developer.apple.com/documentation/security/hardened-runtime"
    },
    # Gatekeeper errors
    {
        "pattern": r"(?:Gatekeeper|GKE|translocated|quarantine|cannot be opened because.*unidentified|damaged.*move.*trash)",
        "category": "gatekeeper",
        "severity": "error",
        "title": "Gatekeeper rejection",
        "fix": "macOS Gatekeeper is blocking the app. Usually a signing or notarization issue.",
        "commands": [
            "# Check Gatekeeper assessment:",
            "spctl --assess -vv YourApp.app",
            "# Check code signature:",
            "codesign -dvv YourApp.app",
            "# Check notarization staple:",
            "stapler validate YourApp.app"
        ],
        "apple_doc": "https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df"
    },
    # Code signature corruption
    {
        "pattern": r"(?:invalid signature|code signature invalid|signature not valid|CSSMERR_TP_NOT_TRUSTED|a sealed resource is missing or invalid|resource.*modified)",
        "category": "certificate",
        "severity": "error",
        "title": "Code signature invalid or corrupted",
        "fix": "The code signature is invalid. The binary may have been modified after signing, or the signature is malformed.",
        "commands": [
            "# Verify signature:",
            "codesign --verify --deep --strict YourApp.app",
            "# Re-sign the app:",
            "codesign --force --deep --sign 'YOUR_SIGNING_IDENTITY' YourApp.app"
        ]
    },
    # Resource seal broken
    {
        "pattern": r"(?:resource fork|resource envelope|seal.*broken|resource.*modified after signing)",
        "category": "certificate",
        "severity": "error",
        "title": "Resource seal broken",
        "fix": "A resource was modified after the app was signed. Re-sign after all modifications are complete.",
        "commands": [
            "# Find modified resources:",
            "codesign --verify --deep --strict --verbose=4 YourApp.app 2>&1 | grep 'modified'",
            "# Strip resource forks before signing:",
            "xattr -cr YourApp.app",
            "# Then re-sign:",
            "codesign --force --deep --sign 'YOUR_SIGNING_IDENTITY' YourApp.app"
        ]
    },
    # Embedded binary signing
    {
        "pattern": r"(?:embedded binary.*not signed|nested.*not signed|framework.*not signed|dylib.*not signed|helper.*not signed)",
        "category": "certificate",
        "severity": "error",
        "title": "Embedded binary not signed",
        "fix": "An embedded framework, dylib, or helper tool is not code signed.",
        "commands": [
            "# Find unsigned embedded binaries:",
            "codesign --verify --deep --strict YourApp.app 2>&1",
            "# Sign embedded frameworks:",
            "codesign --force --sign 'YOUR_SIGNING_IDENTITY' YourApp.app/Contents/Frameworks/*.framework",
            "# Then re-sign the main app:",
            "codesign --force --deep --sign 'YOUR_SIGNING_IDENTITY' YourApp.app"
        ]
    },
    # Timestamp server
    {
        "pattern": r"(?:timestamp.*(?:fail|error|unavailable)|secure timestamp|TSA)",
        "category": "certificate",
        "severity": "warning",
        "title": "Timestamp server failure",
        "fix": "Code signing timestamp server is unavailable. Signatures without timestamps expire with the certificate.",
        "commands": [
            "# Sign with timestamp (default, requires internet):",
            "codesign --force --timestamp --sign 'YOUR_SIGNING_IDENTITY' YourApp.app",
            "# Sign without timestamp (NOT recommended for distribution):",
            "codesign --force --timestamp=none --sign 'YOUR_SIGNING_IDENTITY' YourApp.app"
        ]
    },
    # App Sandbox
    {
        "pattern": r"(?:sandbox.*(?:deny|violation|error)|SANDBOX_CHECK|deny.*file-read|deny.*file-write|deny.*network)",
        "category": "entitlement",
        "severity": "error",
        "title": "App Sandbox violation",
        "fix": "The app tried to access a resource blocked by App Sandbox. Add the required entitlement.",
        "commands": [
            "# Check current entitlements:",
            "codesign -d --entitlements :- YourApp.app",
            "# Common sandbox entitlements:",
            "# com.apple.security.network.client (outgoing connections)",
            "# com.apple.security.files.user-selected.read-write (file access)",
            "# com.apple.security.files.downloads.read-write (Downloads folder)"
        ],
        "apple_doc": "https://developer.apple.com/documentation/security/app-sandbox"
    },
    # Entitlement conflicts
    {
        "pattern": r"(?:entitlement.*conflict|conflicting entitlements|entitlements.*(?:don't match|do not match|mismatch))",
        "category": "entitlement",
        "severity": "error",
        "title": "Entitlement conflict between targets",
        "fix": "Entitlements in embedded binaries conflict with the parent app's entitlements.",
        "commands": [
            "# Compare entitlements between app and extensions:",
            "codesign -d --entitlements :- YourApp.app",
            "codesign -d --entitlements :- YourApp.app/Contents/PlugIns/YourExtension.appex",
            "# Embedded binaries must have a subset of the parent's entitlements"
        ]
    },
    # Architecture mismatch
    {
        "pattern": r"(?:(?:unsupported|missing|incompatible).*(?:architecture|arch)|arm64.*x86_64|no matching architecture|Bad CPU type)",
        "category": "config",
        "severity": "error",
        "title": "Architecture mismatch",
        "fix": "Binary does not contain the required architecture for the target device.",
        "commands": [
            "# Check architectures in binary:",
            "lipo -info YourApp.app/Contents/MacOS/YourApp",
            "# Build universal binary:",
            "xcodebuild -target YourApp -arch arm64 -arch x86_64",
            "# Or create universal manually:",
            "lipo -create YourApp_arm64 YourApp_x86_64 -output YourApp_universal"
        ]
    },
    # Export compliance
    {
        "pattern": r"(?:export compliance|ITSAppUsesNonExemptEncryption|encryption.*export|ECCN)",
        "category": "config",
        "severity": "info",
        "title": "Export compliance flag",
        "fix": "App may need export compliance documentation if it uses non-exempt encryption.",
        "commands": [
            "# Add to Info.plist if using only HTTPS (exempt):",
            "# <key>ITSAppUsesNonExemptEncryption</key>",
            "# <false/>",
            "# If using custom encryption, file for ECCN classification"
        ],
        "apple_doc": "https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations"
    },
    # Provisioning profile device
    {
        "pattern": r"(?:device.*not included|UDID.*not.*(?:found|included|registered)|not include.*device)",
        "category": "profile",
        "severity": "error",
        "title": "Device not in provisioning profile",
        "fix": "The target device's UDID is not registered in the provisioning profile.",
        "commands": [
            "# Get device UDID:",
            "xcrun xctrace list devices",
            "# Register device in Apple Developer Portal > Devices",
            "# Then regenerate your provisioning profile to include it"
        ],
        "apple_doc": "https://developer.apple.com/account/resources/devices"
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
