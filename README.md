# MacSentry

An AI-agent skill for checking known vulnerabilities in Mac apps and Homebrew packages.

## Install (omp)

```sh
bash install.sh
```

Start a new omp session, then run `/skill:macsentry`.

Requires macOS, Python 3, and an agent with web access. Homebrew scanning requires `brew vulns`.

Read-only. Inventories App Store/direct apps and package receipts; the agent checks advisories. Reports uncertainty, not a guarantee of safety. Product/version lookups contact public services.

Installation links this checkout into `~/.omp/agent/skills`; keep it in place.
