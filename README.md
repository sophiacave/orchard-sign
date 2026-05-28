# orchard-sign

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

## Error Patterns Detected

- No signing certificate / expired / revoked
- Provisioning profile invalid / expired / missing entitlements
- Bundle ID mismatch
- Keychain access failures (CI/CD)
- Team ID ambiguity
- Automatic signing conflicts

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
