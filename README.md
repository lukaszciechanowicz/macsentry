# MacSentry

An AI-agent skill for checking known vulnerabilities in Mac apps and Homebrew packages.

## Install (Codex)

```sh
git clone https://github.com/lukaszciechanowicz/macsentry.git
bash macsentry/install.sh codex
```

Start a Codex session and invoke `$macsentry`.

For omp: `bash install.sh omp`, then `/skill:macsentry`.

Requires macOS, Python 3, and an agent with web access. Homebrew scanning requires `brew vulns`.

Read-only. Inventories App Store/direct apps and package receipts; the agent checks advisories. Reports uncertainty, not a guarantee of safety. Product/version lookups contact public services.

Installation links this checkout into `~/.agents/skills` (Codex) or `~/.omp/agent/skills` (omp); keep it in place.
