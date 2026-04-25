# GitHub Copilot Custom Agents — Application Security Review

A two-step security-review pipeline built as GitHub Copilot **custom agents** + **custom instructions** for Java, .NET, and Node.js codebases.

Verified to work with:
- Visual Studio Code **1.106**
- GitHub Copilot Chat for VS Code **0.33.3**
- GitHub Copilot for VS Code **1.388**

## What you get

- 1 orchestrator custom agent that coordinates the whole review
- 4 specialist subagents (one for reconnaissance, three for vulnerability detection)
- 3 language-specific custom-instruction files that auto-attach based on file globs
- 1 project-wide `copilot-instructions.md`

The orchestrator delegates to subagents via VS Code 1.106's **subagent auto-delegation** (based on the `description:` frontmatter). Subagents run with their own context windows, so the main chat never carries the full codebase across steps. All inter-step communication happens through structured markdown artifacts written to a `.security-review/` folder at the repo root — that's why later steps don't need to re-read the whole codebase.

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

## Run

In Copilot Chat, switch to the **Security Review Orchestrator** agent (agent dropdown → pick it), then type:

```
Run a full security review on this repository.
```

The orchestrator will:

1. Bootstrap `.security-review/` folder structure.
2. Auto-delegate to `security-recon` → writes `01-reconnaissance/*.md`.
3. Auto-delegate to `security-vuln-injection` → writes `02-vulnerabilities/deep-dive/*.md`.
4. Auto-delegate to `security-vuln-common` → writes `02-vulnerabilities/common/*.md`.
5. Auto-delegate to `security-vuln-sca` → writes `02-vulnerabilities/sca/components.md`.
6. Stitch `final-report.md` from the artifacts.

Between steps, only short status summaries appear in chat — every finding lives on disk.

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

Each finding file uses a consistent schema (Severity, Class/CWE, Confidence, Location, Source→Sink, Evidence code block, Exploitability, Fix with before/after, References).

Add `.security-review/` to `.gitignore` unless you want to commit the review as an artifact.

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
- **Add a language** (e.g. Python, Go): create a new `.github/instructions/security-review-<lang>.instructions.md` with an appropriate `applyTo` glob. No changes to the agents needed — they are language-agnostic and inherit detection rules via the instructions layer.
- **Remove a vulnerability class**: delete the relevant subagent file, and remove the corresponding step from the orchestrator's "Pipeline" section.
- **Deeper SCA**: in `security-vuln-sca.agent.md`, enable the `runCommands` tool (already listed in frontmatter) and let it shell out to `npm audit` / `dotnet list package --vulnerable` / `osv-scanner`.
- **Tighten severity**: each subagent has a severity guidance block; adjust thresholds (e.g. unauthenticated reachable → Critical) to match your team's risk appetite.

## Design principles

1. **Orchestrator never analyzes.** It only coordinates.
2. **Artifacts are the contract.** Every step writes to named files; every step reads named files. No chat-history dependence.
3. **Minimize re-reading the codebase.** Step 2 uses Step 1's `INDEX.md` to nominate candidate hotspots, then opens only those source files.
4. **One agent per vulnerability-class group, not per language.** Language specificity is injected via `applyTo`-scoped instructions.
5. **Every finding is falsifiable.** Schema requires `file:line`, source-to-sink trace, and a before/after fix snippet. "Heuristic match" findings are marked Confidence: Low.
