# 🛡️ SecForge MCP

**Autonomous Application Security, Threat Modeling, OWASP Hardening, Secrets Management & Incident Response Engine MCP**

[![MCP](https://img.shields.io/badge/MCP-Server-blueviolet)](https://modelcontextprotocol.io)
[![Smithery](https://img.shields.io/badge/Smithery-SecForge-green)](https://smithery.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Studies keep finding that a huge share of AI-generated code ships with security flaws — CRUD handlers that check login but never ownership, raw SQL with string interpolation, wildcard CORS "fixes", hardcoded secrets. SecForge turns your AI agent (Cursor, Claude Code, any MCP client) into a **senior application security engineer** that threat-models, hardens, and audits your code — end to end.

## 🚀 Live Endpoint

```
https://secforge-api.agentweb-hub.workers.dev/mcp
```

Streamable HTTP MCP — works with Cursor, Claude Code, Claude Desktop, Windsurf, and any MCP client.

## 🛠️ Tools (5)

| Tool | What it does |
|------|-------------|
| `sec.architect` | Full security blueprint in one call: lightweight threat model (assets, attackers, surfaces, abuse cases), trust-boundary architecture by stack, OWASP-prioritized risk map tuned to data sensitivity, quick wins this week, maturity-based roadmap |
| `sec.harden_owasp` | OWASP Top 10 with vulnerable-vs-fixed code pairs: IDOR & broken access control, injection & XSS escape hatches, SSRF guards with redirect re-validation, auth/session failures (argon2id, refresh rotation with reuse detection), misconfiguration CI gates — plus the AI-codegen warning list |
| `sec.secrets_supply_chain` | Secrets architecture per environment, the leaked-secret emergency runbook (rotate-first discipline), supply chain defenses (lockfiles, install-script caution, typosquat/slopsquat hygiene, update cooldowns), hardened CI config with OIDC + SHA-pinned actions |
| `sec.headers_csp` | Copy-paste security header sets, strict nonce-based CSP with `strict-dynamic`, report-only rollout strategy, cookie hardening (`__Host-` prefix, SameSite), CORS done correctly, staged zero-breakage deployment plan |
| `sec.incident_response` | SOC 2 Type II prep, pentest preparation that halves the bill, active-incident triage with roles and legal clocks, bug bounty launch sequencing, logging/detection baseline, responsible disclosure policy |

## ⚡ Quick Start (Cursor / Claude Code)

```json
{
  "mcpServers": {
    "secforge": {
      "url": "https://secforge-api.agentweb-hub.workers.dev/mcp"
    }
  }
}
```

## 🔴 NEW in v1.1 — Live Security Headers Audit

`sec.audit_headers_live` fetches **your real HTTP response in real time** and grades the actual security posture: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags, CORS exposure and info-leak headers — with a letter grade and prioritized hardening list computed from what your server actually sends.

## 💰 Pricing

**Start free — 10 requests/day, no signup, no card.** Upgrade only if it earns a place in your workflow.

| Plan | Price | Pay with |
|------|-------|----------|
| **Free** | $0 | 10 requests/day — no signup needed |
| **Pro** (SecForge only) | **$7.99** lifetime | 💳 Gumroad **or** 🪙 Solana USDC |
| **All-Access Suite** (all 45+ servers) | **$14.99** lifetime | 💳 Gumroad **or** 🪙 Solana USDC |

### 💳 Option 1 — Gumroad (PayPal & Credit Cards)

👉 **[amygraphics.gumroad.com/l/mcp-pro](https://amygraphics.gumroad.com/l/mcp-pro)** — select *Single MCP Server* ($7.99) or *All-Access Lifetime Suite* ($14.99). Instant license key delivery.

### 🪙 Option 2 — Solana USDC (instant, no account needed)

Send **$7.99 USDC** (single) or **$14.99 USDC** (all-access) to:

```
8sDLX3okSV974wdjdeKhN9uWLZDr45DeGCJ28zgTLEdJ
```

Then POST your transaction signature to the `/verify-solana` endpoint to activate your lifetime license instantly.

## 🌐 More Servers

Browse all 45 autonomous MCP servers: [MCP Hub](https://mcp-hub.agentweb-hub.workers.dev)

## 📄 License

MIT © AmyGraphics
