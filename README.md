# Orchard Sign

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Tests: 44 passing](https://img.shields.io/badge/Tests-44%20passing-green.svg)](tests/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io)

**Apple code signing automation for Claude Code.** Diagnose errors, check health, list certificates and profiles, get fix guides. Zero competitors.

Code signing is the #1 pain point for Apple developers. Every AI coding tool fails at it. orchard-sign fixes that.

## Quick Start

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "orchard-sign": {
      "command": "python3",
      "args": ["/path/to/orchard-sign/src/mcp_server.py"]
    }
  }
}
```

## Tools

| Tool | What It Does |
|------|-------------|
| `sign_diagnose` | Paste xcodebuild errors → get specific diagnosis + fix commands |
| `sign_health` | Full health check: certificates, profiles, Xcode config |
| `sign_identities` | List all signing certificates with validity status |
| `sign_profiles` | List all provisioning profiles with expiry dates |
| `sign_fix` | Step-by-step fix guides for common signing problems |

## Error Patterns Detected (22)

**Certificates:** No certificate found, expired, revoked, invalid/corrupted signature, resource seal broken, embedded binary not signed, timestamp server failure

**Profiles:** No valid profile, expired, bundle ID mismatch, missing entitlements, device not registered

**Notarization:** Notarization failed, Hardened Runtime issues

**Gatekeeper:** App blocked/damaged messages

**Entitlements:** Missing entitlements, entitlement conflicts between targets, App Sandbox violations

**Config:** Team ID ambiguity, automatic signing conflicts, architecture mismatch, export compliance

## Testing

```bash
python3 tests/test_integration.py
# 44 tests, 0 failures
```

## Fix Guides

| Topic | Problem |
|-------|---------|
| `no-certificate` | No signing cert on machine |
| `expired-profile` | Profile needs regeneration |
| `keychain-ci` | Headless CI/CD keychain setup |
| `team-conflict` | Multiple devs breaking each other's signing |
| `entitlements` | App uses capabilities not in profile |

## Example

```
> sign_diagnose "Code Sign error: No signing certificate 'iOS Distribution' found"

Code Signing Diagnosis: 1 issue(s)

  [ERROR] No signing certificate found
    Category: certificate
    Install a valid Apple Development or Distribution certificate.
    Commands:
      security find-identity -v -p codesigning
      # If empty: Xcode > Settings > Accounts > Manage Certificates > +
    Docs: https://developer.apple.com/documentation/technotes/tn3161
```

## Part of Orchard

orchard-sign is part of the Orchard suite — Apple developer MCP tools by [Like One](https://likeone.ai).

- **orchard-sign** — Code signing automation (this repo)
- **[orchard-hig](https://github.com/sophiacave/orchard-hig)** — Apple HIG compliance checker

## License

MIT
