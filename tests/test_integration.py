#!/usr/bin/env python3
"""Integration tests for orchard-sign MCP server."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from diagnostics import diagnose_error, format_diagnosis, ERROR_PATTERNS, SigningIssue
from mcp_server import handle_request, FIX_GUIDES

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


def test_pattern_coverage():
    """All 22 error patterns exist."""
    print("\n--- Pattern Coverage ---")
    check("22+ error patterns defined", len(ERROR_PATTERNS) >= 22)

    categories = set(p["category"] for p in ERROR_PATTERNS)
    expected_categories = {"certificate", "profile", "entitlement", "keychain", "config", "notarization", "gatekeeper"}
    for cat in expected_categories:
        check(f"Category '{cat}' exists", cat in categories)


def test_certificate_errors():
    """Certificate error patterns match correctly."""
    print("\n--- Certificate Errors ---")

    issues = diagnose_error("No signing certificate found for team ABC")
    check("Matches 'no signing certificate'", any(i.title == "No signing certificate found" for i in issues))

    issues = diagnose_error("certificate has expired on 2025-01-01")
    check("Matches expired certificate", any(i.title == "Signing certificate expired" for i in issues))

    issues = diagnose_error("certificate was revoked by the issuer")
    check("Matches revoked certificate", any(i.title == "Signing certificate revoked" for i in issues))


def test_profile_errors():
    """Provisioning profile error patterns match."""
    print("\n--- Profile Errors ---")

    issues = diagnose_error("no provisioning profile found matching bundle ID com.example.app")
    check("Matches no provisioning profile", any(i.title == "No valid provisioning profile" for i in issues))

    issues = diagnose_error("Provisioning profile has expired")
    check("Matches expired profile", any(i.title == "Provisioning profile expired" for i in issues))

    issues = diagnose_error("doesn't match the bundle identifier com.example.app")
    check("Matches bundle ID mismatch", any(i.title == "Bundle ID mismatch" for i in issues))

    issues = diagnose_error("device UDID not included in provisioning profile")
    check("Matches device not in profile", any(i.title == "Device not in provisioning profile" for i in issues))


def test_notarization_errors():
    """Notarization-related patterns match."""
    print("\n--- Notarization Errors ---")

    issues = diagnose_error("notarization failed: invalid binary")
    check("Matches notarization failed", any(i.title == "Notarization failed" for i in issues))

    issues = diagnose_error("hardened runtime is required for notarization")
    check("Matches hardened runtime", any(i.title == "Hardened Runtime issue" for i in issues))


def test_gatekeeper_errors():
    """Gatekeeper patterns match."""
    print("\n--- Gatekeeper Errors ---")

    issues = diagnose_error("Gatekeeper has blocked this application")
    check("Matches Gatekeeper rejection", any(i.title == "Gatekeeper rejection" for i in issues))

    issues = diagnose_error("app is damaged and can't be opened. You should move it to the Trash.")
    check("Matches damaged app message", any(i.title == "Gatekeeper rejection" for i in issues))


def test_signature_errors():
    """Code signature patterns match."""
    print("\n--- Signature Errors ---")

    issues = diagnose_error("code signature invalid for binary")
    check("Matches invalid signature", any(i.title == "Code signature invalid or corrupted" for i in issues))

    issues = diagnose_error("a sealed resource is missing or invalid in the app bundle")
    check("Matches sealed resource issue", any("signature" in i.title.lower() or "seal" in i.title.lower() for i in issues))


def test_sandbox_errors():
    """Sandbox patterns match."""
    print("\n--- Sandbox Errors ---")

    issues = diagnose_error("sandbox deny file-read-data /usr/local/bin/tool")
    check("Matches sandbox deny", any(i.title == "App Sandbox violation" for i in issues))


def test_architecture_errors():
    """Architecture mismatch patterns match."""
    print("\n--- Architecture Errors ---")

    issues = diagnose_error("unsupported architecture arm64")
    check("Matches arch mismatch", any(i.title == "Architecture mismatch" for i in issues))

    issues = diagnose_error("Bad CPU type in executable")
    check("Matches Bad CPU type", any(i.title == "Architecture mismatch" for i in issues))


def test_fallback_diagnosis():
    """Unknown signing errors produce a fallback."""
    print("\n--- Fallback ---")

    issues = diagnose_error("weird signing error nobody has seen before")
    check("Fallback produces info issue", len(issues) > 0 and issues[0].severity == "info")

    issues = diagnose_error("completely unrelated error")
    check("Non-signing error produces no issues", len(issues) == 0)


def test_format_diagnosis():
    """Diagnosis formatting works."""
    print("\n--- Formatting ---")

    issues = [SigningIssue("certificate", "error", "Test error", "msg", "fix", ["cmd1"])]
    report = format_diagnosis(issues)
    check("Report contains issue count", "1 issue" in report)
    check("Report contains ERROR tag", "ERROR" in report)

    empty = format_diagnosis([])
    check("Empty report says no issues", "No signing issues" in empty)


def test_mcp_protocol():
    """MCP protocol handlers work."""
    print("\n--- MCP Protocol ---")

    resp = handle_request({"method": "initialize", "id": 1})
    check("initialize returns serverInfo", "serverInfo" in resp)
    check("server name is orchard-sign", resp["serverInfo"]["name"] == "orchard-sign")

    resp = handle_request({"method": "tools/list", "id": 2})
    tools = resp["tools"]
    tool_names = [t["name"] for t in tools]
    check("5 tools listed", len(tools) == 5)
    check("sign_diagnose exists", "sign_diagnose" in tool_names)
    check("sign_health exists", "sign_health" in tool_names)
    check("sign_fix exists", "sign_fix" in tool_names)

    # sign_diagnose
    resp = handle_request({
        "method": "tools/call",
        "params": {"name": "sign_diagnose", "arguments": {"error_text": "certificate has expired"}},
        "id": 3
    })
    text = resp["content"][0]["text"]
    check("sign_diagnose returns diagnosis text", "expired" in text.lower())

    # sign_fix
    resp = handle_request({
        "method": "tools/call",
        "params": {"name": "sign_fix", "arguments": {"topic": "no-certificate"}},
        "id": 4
    })
    text = resp["content"][0]["text"]
    check("sign_fix returns steps", "Xcode" in text)

    # sign_fix unknown topic
    resp = handle_request({
        "method": "tools/call",
        "params": {"name": "sign_fix", "arguments": {"topic": "nonexistent"}},
        "id": 5
    })
    text = resp["content"][0]["text"]
    check("sign_fix unknown returns available topics", "Available" in text or "Unknown" in text)


def test_fix_guides():
    """All fix guides are complete."""
    print("\n--- Fix Guides ---")
    check("5 fix guides defined", len(FIX_GUIDES) >= 5)
    for topic, guide in FIX_GUIDES.items():
        check(f"Guide '{topic}' has steps", len(guide["steps"]) > 0)


if __name__ == "__main__":
    test_pattern_coverage()
    test_certificate_errors()
    test_profile_errors()
    test_notarization_errors()
    test_gatekeeper_errors()
    test_signature_errors()
    test_sandbox_errors()
    test_architecture_errors()
    test_fallback_diagnosis()
    test_format_diagnosis()
    test_mcp_protocol()
    test_fix_guides()
    print(f"\n{'='*40}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL > 0 else 0)
