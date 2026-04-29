# GitHub Copilot Custom Agents — Application Security Review

A two-step security-review pipeline (Reconnaissance → Vulnerability Detection) built as GitHub Copilot **custom agents** + **custom instructions** for Java, .NET, and Node.js codebases.

Verified to work with:
- Visual Studio Code **1.106**
- GitHub Copilot Chat for VS Code **0.33.3**
- GitHub Copilot for VS Code **1.388**

## What you get

- **1 orchestrator** custom agent that coordinates the whole review.
- **4 specialist subagents:**
  - `security-recon` — maps the attack surface (tech stack, endpoints with sample req/resp, data flow with sink categories, datastores, external services).
  - `security-vuln-injection` — deep-dive on Command Injection (14 subtypes), Path Traversal (20 subtypes including session-stored second-order), SQL Injection (29 subtypes across in-band / inferential / out-of-band channels and ORM escape hatches), and NoSQL Injection.
  - `security-vuln-common` — normal-depth analysis on XXE, XSS, SSRF, security misconfiguration.
  - `security-vuln-sca` — Software Component Analysis via OSV.dev advisory queries (proxy-aware), with optional package-manager cross-check and manifest-only fallback.
- **3 language-specific custom-instruction files** that auto-attach based on file globs (Java, .NET, Node.js).
- **1 project-wide** `copilot-instructions.md`.

The orchestrator delegates to subagents via VS Code 1.106's **subagent auto-delegation** (based on the `description:` frontmatter). Subagents run with their own context windows, so the main chat never carries the full codebase across steps. All inter-step communication happens through structured markdown artifacts written to a `.security-review/` folder at the repo root — that's why later steps don't need to re-read the whole codebase.

Each subagent has a **Step 0** that explicitly loads the relevant language instruction file (with a tolerant fallback) — `applyTo` auto-attach is observed to be unreliable inside subagent contexts in 1.106, so the agents read the instruction files themselves to guarantee language-specific detection rules apply.

## Files in this bundle

```
.github/
├── copilot-instructions.md                               # always-on minimal rules
├── agents/
│   ├── security-review.agent.md                          # ORCHESTRATOR
│   ├── security-recon.agent.md                           # Step 1: Reconnaissance
│   ├── security-vuln-injection.agent.md                  # Step 2a: deep-dive (cmd/path/SQL/NoSQL)
│   ├── security-vuln-common.agent.md                     # Step 2b: XXE/XSS/SSRF/misconfig
│   └── security-vuln-sca.agent.md                        # Step 2c: Software Component Analysis
└── instructions/
    ├── security-review-java.instructions.md              # Java + Kotlin + Maven/Gradle
    ├── security-review-dotnet.instructions.md            # C#/F#/VB + ASP.NET Core + WCF
    └── security-review-nodejs.instructions.md            # JS/TS + Express/Fastify/Nest/Next/Lambda
```

## Install

Copy the `.github/` directory from this bundle into the root of the repository you want to review. That's it — VS Code 1.106 auto-discovers:

- `.github/agents/*.agent.md` as **custom agents** (formerly "custom chat modes")
- `.github/instructions/*.instructions.md` as **path-scoped instructions** (merged based on the `applyTo` glob)
- `.github/copilot-instructions.md` as **always-on instructions**

Confirm discovery: in the Copilot Chat view, open the agent picker — you should see **Security Review Orchestrator** and the four **security-*** subagents listed alongside the built-ins (Ask / Edit / Agent / Plan / Explore).

> If your org has not enabled custom agents in the org policy, contact an admin — the feature is gated by the `Editor preview features` policy in GitHub Copilot Business/Enterprise.

### One-time setup for SCA behind a corporate proxy

If you're behind a corporate proxy and PowerShell is the shell Copilot uses (Windows default), set a user-level environment variable so the SCA agent can reach `api.osv.dev` for advisory queries. **No admin needed.**

1. Open **System Properties → Environment Variables**.
2. Under **User variables**, click **New**.
3. Name: `HTTP_PROXY`. Value: your corporate proxy URL, e.g. `http://192.0.2.10:8080`.
4. Click OK and restart VS Code.

The SCA agent reads `$env:HTTP_PROXY` at runtime and emits a per-call PowerShell preamble that constructs `[System.Net.WebRequest]::DefaultWebProxy` from it. This is the fully-tolerated workaround for Windows PowerShell 5.1 not honoring `HTTP_PROXY` automatically for `Invoke-RestMethod`. If `HTTP_PROXY` is not set, the SCA agent stops with a clear message instead of producing silent empty results. See Troubleshooting for details.

## Run

In Copilot Chat, switch to the **Security Review Orchestrator** agent (agent dropdown → pick it), then type:

```
Run a full security review on this repository.
```

The orchestrator will:

1. Bootstrap `.security-review/` folder structure.
2. Auto-delegate to `security-recon` → writes `01-reconnaissance/*.md` incrementally (scope.md → tech-stack.md → endpoints.md (table first, detail blocks streamed) → data-flow.md → datastores.md → external-services.md → INDEX.md).
3. Auto-delegate to `security-vuln-injection` → writes `02-vulnerabilities/deep-dive/*.md`.
4. Auto-delegate to `security-vuln-common` → writes `02-vulnerabilities/common/*.md`.
5. Auto-delegate to `security-vuln-sca` → writes `02-vulnerabilities/sca/components.md`.
6. Stitch `final-report.md` from the artifacts.

Between steps, only short status summaries appear in chat — every finding lives on disk. Each subagent echoes a `Language instructions: java=<loaded|missing|n/a>, dotnet=<...>, nodejs=<...>` line so you can see whether language-specific detection rules were applied; the orchestrator re-delegates once if a subagent skipped Step 0 or shows `missing` for an in-scope language.

The orchestrator uses **tiered verification** between steps. If a subagent produces a minimum-viable artifact set with `## Coverage gaps` notes (because it ran out of budget on a large repo), the pipeline continues rather than aborting. Run the full pipeline a second time to fill in any pending items.

### Direct subagent invocation

You can also call a single step directly if recon already exists:

```
Use the security-vuln-injection subagent to rerun deep-dive injection on the already-generated reconnaissance artifacts.
```

### Handoff fallback

If your Copilot edition doesn't support automatic subagent invocation (unlikely on the versions above, but possible in restricted enterprise configs), the orchestrator will tell you to switch custom agents manually. The `.security-review/` folder is the continuity layer — the pipeline survives any agent switch.

## Output directory layout

```
.security-review/
├── 00-meta/
│   ├── scope.md
│   └── run-log.md
├── 01-reconnaissance/
│   ├── tech-stack.md
│   ├── endpoints.md
│   ├── data-flow.md
│   ├── datastores.md
│   ├── external-services.md
│   └── INDEX.md              <-- the handoff document Step 2 reads
├── 02-vulnerabilities/
│   ├── deep-dive/
│   │   ├── command-injection.md
│   │   ├── path-traversal.md
│   │   ├── sql-injection.md
│   │   └── nosql-injection.md
│   ├── common/
│   │   ├── xxe.md
│   │   ├── xss.md
│   │   ├── ssrf.md
│   │   └── security-misconfiguration.md
│   └── sca/
│       └── components.md
└── final-report.md
```

Each finding file uses a consistent schema. Mandatory fields:

- **Severity** (Critical / High / Medium / Low / Info) and **Class** (OWASP / CWE).
- **Confidence** + **Confidence rationale** — calibrated against proof cleanliness, with a one-line justification.
- **Endpoint** — links the finding back to the recon endpoint ID + METHOD + route.
- **Location** (`file:line-range`) and **Classes involved** — every class touched on the chain.
- **Source → Sink** — tainted input → dangerous API.
- **Evidence** — code excerpt covering source, sink, and any validator. Required.
- **Root Cause** — one-line label of the underlying defect class (e.g. "regex anchored only at start", "trust boundary violation — second-order persisted XSS").
- **Validation & Bypass** — every validator found in the chain (file:line, type, verdict), whether a bypass was attempted, the bypass technique, and a concrete bypass payload. If a sufficient validator exists and no bypass works, the finding is **dismissed** under the file's "Dismissed" section instead of raised — this is how false positives are kept low.
- **Reasoning** — 2–5 sentences explaining the defect, integrating the validation analysis.
- **Exploit Payload** — concrete, fenced payload that matches the endpoint's actual request contract from `endpoints.md`. For non-HTTP findings (MQ, CLI, deserialization), the equivalent.
- **Second-Order Pattern** — explicit yes/no, with write endpoint + read endpoint + persistence medium when yes. Persistence media include database, filesystem, cache, **server-side session**, cookies, message queues, headers/context, and config stores. Mandatory check on every persistence-touching endpoint.
- **Exploitability** — pre-conditions, auth, reachability.
- **Fix** — before/after code snippet. The "after" must show the right control (canonicalize-then-prefix-check for path traversal, parameterized query for SQLi, allowlist of operator keys for NoSQLi, etc.).
- **References** — links, CVEs, framework docs.

Add `.security-review/` to `.gitignore` unless you want to commit the review as an artifact.

## What the agents actually check for

### Reconnaissance (`security-recon`)

Produces six artifacts. The recon agent writes incrementally — each file is saved as soon as a usable draft is ready, so a budget-limited run still leaves you with usable partial output:

- **`tech-stack.md`** — full **dependency inventory** per module: every library with exact resolved version, direct vs transitive, ecosystem, source manifest reference. Plus framework, build tool, runtime target, lockfile presence.
- **`endpoints.md`** — every HTTP/WebSocket/gRPC/SOAP/MQ/scheduled/CLI/serverless endpoint as a summary row PLUS a **detail block per endpoint**: parameter schema table, **complete sample HTTP request** (method, headers, full body), **complete sample HTTP response** (status, headers, full body). Bodies are walked from the actual DTO classes — Jackson / `System.Text.Json` / `class-transformer` serialization transforms applied. Self-check footer logs any gaps.
- **`data-flow.md`** — per non-trivial endpoint, a block headed by ENDPOINT / METHOD / PATH / HANDLER / CLASSES INVOLVED, then SOURCE → validator → SINK. Sink classification covers 12 categories beyond just databases: persistence, local filesystem (incl. archive-extract), external HTTP/SOAP/gRPC/SDK/LDAP/JNDI, messaging producers/consumers, process-exec, templating, XML/XPath/XSL, mail/SMS/push, crypto/RNG/serialization, web sinks (cookies/redirects/CORS/headers), cache writes, reflection/eval. Every validator on the chain is classified and verdicted.
- **`datastores.md`** — every DB / cache / object store / file store, connection-string shapes (redacted), how credentials are loaded, **flagged hardcoded secrets** with file:line.
- **`external-services.md`** — every outbound REST/SOAP/gRPC client, message broker, FTP/SFTP/email/LDAP, cloud SDK call, third-party SaaS — with auth scheme and call site.
- **`INDEX.md`** — the one-page handoff doc for vuln steps. Lists candidate hot-spots per vulnerability class, plus `## Coverage gaps` for anything pending.

### Deep-dive injection (`security-vuln-injection`)

Covers all subtypes per class:

- **Command injection (14 subtypes)**: direct shell concat; indirect via array-spawn-with-shell-interpreting-binary (`git`, `ssh`, `bash -c`, `find -exec`, `tar --to-command`, `mysql -e`, `awk -e`, `xargs`, `rsync -e`, `wget`, `curl --config`); argument injection (missing `--`); PATH/executable-name hijack; environment-variable injection (`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`, `PERL5LIB`, `IFS`, ...); wildcard/glob; CRLF-into-config-files; SSTI → RCE across all major engines; `eval` / `Function(...)` / `vm.run*` / `ScriptEngine` / Roslyn; deserialization-driven RCE (call-out); JNI/native bridge; mass-assignment-driven argument injection; container/orchestrator command sinks; background-job task arguments.
- **Path traversal (20 subtypes)**: classic dot-dot; URL-encoded; double-encoded; Unicode/overlong-UTF-8; null-byte truncation; absolute-path injection; UNC/SMB; symlink/junction (with `toRealPath` vs `toAbsolutePath`); Windows ADS; reserved names; extension confusion / RTL override / trailing dot/space; zip-slip / tar-slip / archive-prefix-confusion; symlink-within-archive; case-insensitive filesystem; NFC/NFD; backslash-on-Linux; `path.normalize` non-protection; **second-order** (incl. session-stored filenames); SSRF via `file://`; template-include traversal.
- **SQL injection (29 subtypes)** by exploitation channel (in-band error-based, union, stacked queries with driver defaults, boolean-blind, time-blind, OOB DNS/HTTP, second-order); by query context where parameterization is skipped (`ORDER BY`, `LIMIT`/`OFFSET`, identifier injection, `IN(...)` array splat, `LIKE`, `COLLATE`, numeric-cast confusion); by framework escape hatch (Spring `nativeQuery=true`, `JdbcTemplate.query(String)`, MyBatis `${...}`, Hibernate HQL, jOOQ `DSL.sql`, EF Core `FromSqlRaw`, Dapper concat, Sequelize raw, Knex `.raw`/`.whereRaw`, TypeORM raw, Prisma `$queryRaw` non-tagged); plus stored-procedure body, HQL/JPQL, GraphQL → SQL boundary.
- **NoSQL injection**: MongoDB operator injection (`$ne` login bypass), `$where` server-side JS, query-shape injection from raw `req.body`.

For **every** finding, the agent runs validation analysis — classifies each validator on the chain (allowlist / regex / blocklist / type-check / length / encoding / framework-level), attempts a concrete bypass, and **dismisses** the finding if the validator is genuinely sufficient. This is the main false-positive control. Dismissals are recorded under each file's "Dismissed" section with the validator's code reference.

Every persistence-touching endpoint also gets a **second-order check**, with multiple cross-endpoint shapes documented for each class (session-stored filenames, DB-stored filenames, cache-stored avatar paths, cookie-stored locale paths, header-propagated paths, archive-entry names, etc.).

### Common web vulnerabilities (`security-vuln-common`)

XXE, XSS, SSRF, security misconfiguration. Same validation-aware methodology and second-order check (stored XSS handoff). Class-specific bypass patterns documented: SSRF (DNS rebinding, IPv6 alternate forms, decimal/octal IP, URL-parser confusion, redirect chains), XSS (cross-context encoder misuse, alternative quote injection, `javascript:` vs `data:` URIs), XXE (parser-flag combinations and partial coverage), misconfig (JWT `alg=none`, CORS reflected-Origin, CSP unsafe-inline).

### Software Component Analysis (`security-vuln-sca`)

Three-path methodology, ecosystem-scoped throughout (only audits ecosystems that appear in `tech-stack.md`):

- **Path B (PRIMARY)** — OSV.dev `Invoke-RestMethod` queries against the inventory in `tech-stack.md`. Batched up to 1000 per call against `api.osv.dev/v1/querybatch`. Every `runCommands` invocation that touches network starts with a proxy preamble that reads `$env:HTTP_PROXY` (set once at user level — see Install). No `fetch` tool dependency.
- **Path A (opportunistic cross-check)** — local package-manager audits (`npm audit`, `pnpm audit`, `yarn npm audit`, `dotnet list package --vulnerable`) when the binary is on PATH. Maven/Gradle audit plugins are skipped here (Path B already covers them). Findings from A and B merge and dedupe by `(package, version, advisory-id)`.
- **Path C (final fallback)** — manifest-only pattern matching against a curated set of high-impact CVEs (Log4Shell, Spring4Shell, Newtonsoft.Json deserialization, lodash <4.17.21, node-ipc protestware, event-stream, colors sabotage, ua-parser-js compromised, etc.). Confidence: Low.

Optional GHSA enrichment for Critical/High findings via the GitHub GraphQL API with the same proxy preamble.

Plus license audit (GPL/AGPL/SSPL flagging, missing-license, copyleft transitives), runtime EOL audit (JDK / .NET TFM / Node), lockfile-presence checks, and reachability annotation when the recon artifacts cite the vulnerable library's API at a specific call site.

## Version notes and feature caveats

| Feature | VS Code 1.106 / Copilot Chat 0.33.3 | Notes |
|---|---|---|
| Custom agents (`*.agent.md` in `.github/agents/`) | ✅ | This bundle targets this format. |
| Legacy `*.chatmode.md` in `.github/chatmodes/` | ✅ (still works) | Renaming is optional. |
| Subagents with isolated context | ✅ | Introduced in VS Code 1.106 (Oct 2025). |
| Auto-delegation from a parent agent | ✅ | Driven by the subagent's `description:` field. |
| **Subagent invoking another subagent** | ❌ | Only in VS Code 1.110+ (March 2026). That's why this bundle puts all 4 step agents at the same level under a single orchestrator — the orchestrator is the only one that fans out. |
| Parallel subagents from one orchestrator | ❌ | 1.107 added multi-agent orchestration; 1.106 runs sequentially. The orchestrator is designed for sequential delegation, which matches the user's requirement exactly. |
| `target:` frontmatter property on `.agent.md` | ✅ (optional) | Not used here; agents run locally in the IDE. |
| `applyTo` globs on instruction files | ✅ | Used to auto-scope language guidance. |

## Known quirks in your version

- **Instruction files MUST be named `*.instructions.md`** (plural). A singular `*.instruction.md` is silently ignored by Copilot's instruction-file scanner, which means `applyTo` never fires and the file is invisible to agents. If a language's detection rules don't seem to be applied during a review, check the filename first.
- **`applyTo` with comma-separated globs is flaky** in the 1.106 generation of Copilot Chat (see `vscode-copilot-release#9476`, closed as "not planned"). This bundle uses **single-glob-with-brace-expansion** syntax (`**/{*.java,pom.xml,...}`) instead, which is parsed by minimatch reliably. If you add more file types, keep them inside the same `{...}` group rather than comma-joining multiple globs.
- **Subagents can't invoke other subagents** until VS Code 1.110. That's why all four step agents live at the same level under a single orchestrator.
- **Parallel subagents** aren't available until 1.107. The orchestrator deliberately runs steps sequentially, which matches your stated requirement anyway.

## Troubleshooting

### SCA agent fails with "HTTP_PROXY user-level env var is not set"

The Software Component Analysis agent queries OSV.dev for advisories via PowerShell `Invoke-RestMethod`. On Windows PowerShell 5.1 behind a corporate proxy, the call needs an explicit proxy preamble — the agent reads the proxy URL from a user-level environment variable.

One-time setup (no admin needed):

1. Open **System Properties → Environment Variables**.
2. Under **User variables**, click **New**.
3. Name: `HTTP_PROXY`. Value: your corporate proxy URL, e.g. `http://192.0.2.10:8080`.
4. Click OK. Restart VS Code so Copilot Chat's PowerShell sessions inherit the new variable.

Why it's needed: PowerShell 5.1 doesn't honor `HTTP_PROXY` for `Invoke-RestMethod` automatically, but the SCA agent reads the variable's value and constructs `[System.Net.WebRequest]::DefaultWebProxy` from it. PowerShell 7+ users get the same setup, just with a different consumption path inside the agent. This avoids needing admin to run `netsh winhttp set proxy`.

### Language-specific instructions are not being applied during a review

Most often a filename problem. The file must be named `security-review-<lang>.instructions.md` — **plural `instructions`**. A singular `*.instruction.md` is silently ignored by Copilot's instruction-file scanner, so `applyTo` never fires and the agent appears to have no language-specific rules. Rename the file and reload the window.

If the filename is correct and the rules still don't seem applied, check that:
- VS Code is opened at the **repo root**, not a subfolder.
- `.github/**` is not in `search.exclude` or `files.exclude` in your `settings.json`.
- After copying the bundle in, run `Ctrl+Shift+P → Developer: Reload Window` so Copilot rebuilds its workspace index.

### Agent frontmatter shows tool warnings (`codebase has been renamed`, `editFiles has been renamed`, `unknown tool 'think'`)

Tool IDs in Copilot Chat 0.33.3 use namespaced names. The bundle uses the corrected forms:
- `search/codebase` (was `codebase`)
- `edit/editFiles` (was `editFiles`)
- `think` was removed entirely

If you see these warnings on a forked agent file, update its `tools:` line accordingly.

### Endpoints have summary rows but no detail blocks, or sample request/response is missing

Hard Rule #1 of the recon agent requires 1:1 mapping (every summary row → one detail block) and Hard Rule #2 requires every detail block to contain both a sample request and a sample response. The recon file ends with a self-check footer that flags any missing block. If you're seeing summary-only output, your `security-recon.agent.md` is stale — re-copy from the bundle.

## Customizing

- **Change output directory**: edit `security-review.agent.md` — the path `.security-review/` is referenced in one block near the top and echoed in every subagent file. Search-and-replace.
- **Add a language** (e.g. Python, Go): create a new `.github/instructions/security-review-<lang>.instructions.md` with an appropriate `applyTo` glob. Each subagent's Step 0 also needs a one-line entry to attempt loading the new file (since `applyTo` is unreliable in subagent contexts and the agents read instruction files explicitly).
- **Remove a vulnerability class**: delete the relevant subagent file, and remove the corresponding step from the orchestrator's "Pipeline" section.
- **Tighten severity**: each subagent has a severity guidance block; adjust thresholds (e.g. unauthenticated reachable → Critical) to match your team's risk appetite.
- **Adjust SCA paths**: in `security-vuln-sca.agent.md`, you can disable Path A (local package-manager audit) by removing `runCommands` from the `tools:` list — Path B (OSV) is sufficient on its own for most repos. Or skip the GHSA enrichment entirely if you don't have a `GITHUB_TOKEN`.
- **Different proxy URL across machines**: the SCA agent reads `$env:HTTP_PROXY` per session, so each developer can set their own value at the user-environment level. No agent-file edits needed.
- **Force a re-run of just one step**: directly invoke a subagent (`Use the security-vuln-injection subagent to ...`). The artifact directory is the continuity layer, so it picks up where recon left off without re-scanning.

## Design principles

1. **Orchestrator never analyzes.** It only coordinates.
2. **Artifacts are the contract.** Every step writes to named files; every step reads named files. No chat-history dependence. Subagents tolerate partial recon (`## Coverage gaps` notes) rather than aborting on incomplete input.
3. **Minimize re-reading the codebase.** Step 2 uses Step 1's `INDEX.md` to nominate candidate hotspots, then opens only those source files. The recon agent's exhaustive `tech-stack.md` is the SCA agent's inventory — no re-derivation from manifests.
4. **One agent per vulnerability-class group, not per language.** Language specificity is injected via instruction files. Each subagent has a Step 0 that loads them explicitly (with tolerant fallback) since `applyTo` doesn't fire reliably inside subagent contexts in 1.106.
5. **Every finding is falsifiable.** Schema requires `file:line`, source-to-sink trace, code Evidence, validation analysis with bypass attempt (or dismissal under "Dismissed"), Root Cause label, second-order check on persistence-touching endpoints, concrete Exploit Payload, and before/after Fix snippet. Confidence ratings are calibrated against proof cleanliness, paired with a one-line Confidence rationale.
6. **Validators dismiss findings, not the other way around.** If a validator on the chain is sufficient and no concrete bypass works against it, the finding is dismissed under the file's "Dismissed" section with the validator's code reference. This is the main false-positive control.
7. **Incremental writes.** Recon and vuln subagents save artifacts as they're drafted, not at the end. Budget-limited runs leave usable partial output rather than nothing.
