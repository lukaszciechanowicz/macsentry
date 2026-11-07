# MacSentry

An AI-agent skill for checking known vulnerabilities in Mac apps and Homebrew
packages, with an optional script for configuring selected telemetry settings.

## Install (Codex)

```sh
git clone https://github.com/lukaszciechanowicz/macsentry.git
bash macsentry/install.sh codex
```

Start a Codex session and invoke `$macsentry`.

For omp: `bash install.sh omp`, then `/skill:macsentry`.

Requires macOS, Python 3, and an agent with web access. Homebrew scanning requires `brew vulns`.

The vulnerability scan is read-only. It inventories App Store/direct apps and
package receipts; the agent checks advisories. Reports uncertainty, not a
guarantee of safety. Product/version lookups contact public services.

Installation links this checkout into `~/.agents/skills` (Codex) or `~/.omp/agent/skills` (omp); keep it in place.

## Privacy controls

`privacy.json` configures Homebrew analytics, VS Code telemetry, Firefox
telemetry, and a recommended Chrome usage/crash reporting policy. The supplied
defaults set each to `false`. `true` requests enabling the setting, not
restoration of a previous custom value. Edit the file, then apply it:

```json
{
  "homebrew_analytics": false,
  "vscode_telemetry": false,
  "firefox_telemetry": false,
  "chrome_telemetry": false
}
```

```sh
python3 scripts/privacy.py
# Or keep it running to apply config edits automatically:
python3 scripts/privacy.py --watch
# Use a separate config file instead:
python3 scripts/privacy.py --config /path/to/privacy.json
```

The watcher applies immediately, checks for changes every two seconds, and runs
only while the command is running. Invalid config is rejected; in watch mode it
is retried until corrected. All four keys are required JSON booleans; add the
browser keys to any older custom config. Absent applications or profile
directories are skipped. No software is installed and sudo is not used.

- Homebrew uses `brew analytics on/off`; environment variables may override it.
- VS Code uses `telemetry.telemetryLevel` (`off` or `all`); the script preserves
  other settings and JSON comments. Extensions can have separate telemetry.
- Firefox updates `user.js` in each profile registered in `profiles.ini`, using
  the preferences affected by Mozilla's DisableTelemetry policy. Restart
  Firefox to apply. Existing and newly created profiles must be present when the
  script runs; rerun after creating a profile. Its policy or other application
  settings may override these preferences. Crash reports and extensions have
  separate controls.
- Chrome uses `defaults write` for `MetricsReportingEnabled`. On macOS this is
  a **recommended**, not mandatory, policy: a user choice or managed policy can
  override it. Restart Chrome and inspect `chrome://policy` and Chrome's usage
  reporting setting; writing a recommendation does not prove reporting stopped.
  Managed preferences are required to enforce the policy.

VS Code workspace or managed policies may override user settings. Close and
reopen VS Code if necessary.

These controls do **not** disable all macOS or application telemetry, prevent
network access, or make a Mac private. Apple does not document a supported
command-line switch for its analytics settings: use System Settings → Privacy
& Security → Analytics & Improvements to turn off **Share Mac Analytics** and
**Share with app developers**. Safari has no separate documented CLI telemetry
switch; review its privacy settings and Apple's analytics controls manually.
These browser controls do not disable browsing, search, extension, sync, or
website traffic. See [Apple's instructions](https://support.apple.com/guide/mac-help/share-analytics-information-mac-apple-mh27990/mac),
[Homebrew analytics](https://docs.brew.sh/Analytics),
[VS Code telemetry](https://code.visualstudio.com/docs/configure/telemetry),
[Firefox telemetry policy](https://firefox-admin-docs.mozilla.org/reference/policies/disabletelemetry/),
and [Chrome's macOS policy guidance](https://www.chromium.org/administrators/mac-quick-start/).

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
