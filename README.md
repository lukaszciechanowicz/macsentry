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

## Vulnerability sources

The collector gathers local inventory and Homebrew vulnerability results; the agent uses web/API lookups for the other sources.

| Source | Used for |
| --- | --- |
| Homebrew (`brew vulns --json`) | Vulnerability results for installed formulae, with coverage gaps reported separately. |
| [OSV](https://google.github.io/osv.dev/api/) | Open-source products not covered by Homebrew results, using verified upstream package identities and versions or commits. |
| Vendor security advisories | Affected and fixed versions for App Store apps, directly installed apps, casks, and verified installer-package payloads. |
| [National Vulnerability Database (NVD)](https://nvd.nist.gov/developers/vulnerabilities) | CVE candidates for those apps and package payloads, verified against product, version, and platform evidence. |
| [Apple security releases](https://support.apple.com/100100) | Apple-managed components, matched against the installed macOS version and build. |
| [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Cross-checking confirmed CVEs for known exploitation; absence from KEV does not mean unexploited. |
