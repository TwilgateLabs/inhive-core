# Security Policy — inhive-core (Go)

## Reporting a Vulnerability

If you've discovered a security vulnerability in `inhive-core` (Go DLL/AAR/iOS
framework, a fork of `hiddify-core` / `sing-box`) or related InHive
infrastructure, **please report it privately** — not through public channels.

### Preferred reporting channels (in order)

1. **GitHub Security Advisory** (private to maintainers):
   <https://github.com/TwilgateLabs/inhive-core/security/advisories/new>

2. **Email:** `security@inhive.ru`
   *(secured mailbox, monitored by core team)*

3. **Telegram** (direct message): `@InHive_bot` with `/start security <details>`

### Do NOT report via

- Public GitHub Issues
- Public Telegram channels (`@InHive_club` or similar)
- Social media, forums, blog posts before coordinated disclosure
- Pull requests with security-fix code (we'll review privately and credit you)

### Upstream vs InHive-specific

`inhive-core` is a fork of upstream sing-box. Please check whether the issue
applies to upstream:

- **Upstream sing-box** vulnerabilities → report to <https://github.com/SagerNet/sing-box/security/advisories/new>
- **Patches we maintain** (UTProto, naive outbound, system proxy via
  Advapi32, gRPC control plane) → report to this repo
- **`hiddify-core` patches** that we inherited (most of the gRPC layer) →
  report both to this repo and upstream `hiddify-next/hiddify-core`

When in doubt, report to us first — we'll coordinate upstream disclosure.

## Supported versions

Per [ADR-006 (6-month backwards compatibility grace)](https://github.com/twilgate/inhive-memory/blob/main/docs/adr/006-backwards-compat-6-months.md):

| Version | Status | Security fixes |
|---------|--------|----------------|
| latest DLL/AAR/Framework shipped in `inhive-app` | ✅ | yes |
| within 6 months of release | ✅ | yes |
| older | ❌ | upgrade required (via app update) |

`inhive-core` is rebuilt and vendored into the Flutter app on each app release.
There's no version branching — `main` is canonical, releases are tags.

## Disclosure policy

Per [ADR-009 (Stealth security releases)](https://github.com/twilgate/inhive-memory/blob/main/docs/adr/009-stealth-security-releases.md):

- **Tier 1: Critical** (RCE, auth-bypass, traffic injection into the tunnel,
  TLS validation bypass) — silent fix shipped first, public disclosure delayed
  90+ days (or immediately if exploited in the wild). Internal incident log in
  private memory.
- **Tier 2: Non-critical** (DoS, info-disclosure, log injection) — standard
  disclosure in release notes / `inhive.ru/news`.

We do **not** operate a bug bounty programme (small project, solo dev).
However, we will publicly credit researchers who follow coordinated
disclosure, in agreement with the researcher.

## Response time SLA

- **Initial acknowledgement:** within 72 hours (best-effort)
- **Triage decision:** within 7 days
- **Patch shipped:** depends on severity (Tier 1 ≤ 7 days, Tier 2 ≤ 30 days)

For coordination with upstream sing-box releases, response time may extend if
we need upstream input before public disclosure.

## Scope

In-scope:
- `inhive-core` source (this repo, including our patches)
- gRPC control-plane API (`SetupMode=4`, port 18078)
- Build artefacts shipped in `inhive-app` (DLL, AAR, iOS framework)
- UTProto protocol implementation (our fork of MTProto FakeTLS)
- Reality / VLESS / Trojan / NaiveProxy outbound implementations
- TUN driver code (Windows: Wintun; Android: VPNService; iOS: NetworkExtension)
- System proxy injection (Windows Advapi32 / Wininet registry)

Out-of-scope:
- Third-party VPN protocols (WireGuard, OpenVPN — upstream)
- DDoS / volumetric attacks (operational concern, not a vulnerability)
- Pure upstream sing-box / hiddify-core issues (report there, see above)

## Acknowledgements

This security policy itself is published per recommendations of
[OpenSSF Best Practices Guide](https://www.bestpractices.dev/) and
[GitHub Security Lab](https://securitylab.github.com/).
