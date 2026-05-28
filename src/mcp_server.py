#!/usr/bin/env python3
"""
orchard-sign MCP server — Code signing automation for Apple developers.

Tools:
  sign_diagnose     — Diagnose code signing errors from xcodebuild output
  sign_health       — Full signing health check (certs, profiles, Xcode)
  sign_identities   — List all code signing identities
  sign_profiles     — List all provisioning profiles with expiry status
  sign_fix          — Get step-by-step fix for a specific signing problem
"""

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from diagnostics import (
    diagnose_error, list_signing_identities, list_provisioning_profiles,
    check_signing_health, format_diagnosis, SigningIssue
)

FIX_GUIDES = {
    "no-certificate": {
        "problem": "No signing certificate on this machine",
        "steps": [
            "1. Open Xcode > Settings (Cmd+,) > Accounts",
            "2. Select your Apple ID / Team",
            "3. Click 'Manage Certificates'",
            "4. Click '+' > 'Apple Development' (for dev) or 'Apple Distribution' (for release)",
            "5. Xcode will create and install the certificate",
            "Alternative (CLI): Use `security` commands to import a .p12 file"
        ]
    },
    "expired-profile": {
        "problem": "Provisioning profile expired",
        "steps": [
            "1. Go to Apple Developer Portal > Certificates, Identifiers & Profiles > Profiles",
            "2. Find the expired profile and click 'Edit'",
            "3. Regenerate with a valid certificate",
            "4. Download and double-click to install",
            "5. Or in Xcode: Product > Clean Build Folder, then build (auto-signing refreshes)"
        ]
    },
    "keychain-ci": {
        "problem": "Keychain access in CI/CD (headless builds)",
        "steps": [
            "1. Create a dedicated keychain for CI:",
            "   security create-keychain -p $KEYCHAIN_PASSWORD build.keychain",
            "2. Import your .p12 certificate:",
            "   security import cert.p12 -k build.keychain -P $CERT_PASSWORD -T /usr/bin/codesign",
            "3. Set partition list (critical for macOS 12+):",
            "   security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k $KEYCHAIN_PASSWORD build.keychain",
            "4. Add to search list:",
            "   security list-keychains -s build.keychain login.keychain-db",
            "5. Unlock before build:",
            "   security unlock-keychain -p $KEYCHAIN_PASSWORD build.keychain"
        ]
    },
    "team-conflict": {
        "problem": "Multiple teams / automatic signing conflicts",
        "steps": [
            "1. Switch to manual signing for team projects:",
            "   Xcode > Target > Signing & Capabilities > uncheck 'Automatically manage signing'",
            "2. Specify team and profile in xcodebuild:",
            "   xcodebuild DEVELOPMENT_TEAM=ABCDE12345 CODE_SIGN_STYLE=Manual PROVISIONING_PROFILE_SPECIFIER='MyProfile'",
            "3. Store profiles in git (encrypted) for team consistency:",
            "   Use fastlane match or manual profile distribution",
            "4. Designate one person as 'certificate manager' to prevent revocation"
        ]
    },
    "entitlements": {
        "problem": "Entitlement mismatch between app and profile",
        "steps": [
            "1. Check your app's entitlements:",
            "   codesign -d --entitlements :- YourApp.app",
            "2. Compare with profile entitlements:",
            "   security cms -D -i profile.mobileprovision | grep -A20 Entitlements",
            "3. Enable missing capabilities in Apple Developer Portal:",
            "   Certificates, Identifiers & Profiles > Identifiers > Your App > Capabilities",
            "4. Regenerate the provisioning profile after adding capabilities",
            "5. Download and install the new profile"
        ]
    },
}


def handle_request(request):
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "orchard-sign", "version": "0.1.0"}
        }

    if method == "tools/list":
        return {"tools": [
            {
                "name": "sign_diagnose",
                "description": "Diagnose Apple code signing errors. Paste xcodebuild error output and get specific diagnosis with fix commands.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "error_text": {"type": "string", "description": "The error message or xcodebuild output containing signing errors"}
                    },
                    "required": ["error_text"]
                }
            },
            {
                "name": "sign_health",
                "description": "Full code signing health check. Verifies certificates, provisioning profiles, and Xcode configuration.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "sign_identities",
                "description": "List all code signing identities (certificates) on this machine with validity status.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "sign_profiles",
                "description": "List all installed provisioning profiles with team, app ID, and expiry status.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "sign_fix",
                "description": "Get a step-by-step fix guide for a specific signing problem. Topics: no-certificate, expired-profile, keychain-ci, team-conflict, entitlements.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "topic": {"type": "string", "description": "Fix topic: no-certificate, expired-profile, keychain-ci, team-conflict, entitlements"}
                    },
                    "required": ["topic"]
                }
            },
        ]}

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "sign_diagnose":
            issues = diagnose_error(args["error_text"])
            result = format_diagnosis(issues)
        elif tool_name == "sign_health":
            health = check_signing_health()
            result = json.dumps(health, indent=2)
        elif tool_name == "sign_identities":
            certs = list_signing_identities()
            result = json.dumps(certs, indent=2)
        elif tool_name == "sign_profiles":
            profiles = list_provisioning_profiles()
            result = json.dumps(profiles, indent=2, default=str)
        elif tool_name == "sign_fix":
            topic = args.get("topic", "")
            if topic in FIX_GUIDES:
                guide = FIX_GUIDES[topic]
                result = f"Fix: {guide['problem']}\n\n" + "\n".join(guide["steps"])
            else:
                result = f"Unknown topic: {topic}. Available: {', '.join(FIX_GUIDES.keys())}"
        else:
            result = f"Unknown tool: {tool_name}"

        return {"content": [{"type": "text", "text": result}]}

    return {"error": f"Unknown method: {method}"}


def main():
    input_stream = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8")
    for line in input_stream:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            result = handle_request(request)
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32603, "message": str(e)}
            }) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
