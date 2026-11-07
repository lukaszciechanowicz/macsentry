"""Render the collector's local evidence without making security claims."""
from html import escape
import re


def text(value):
    return escape(str(value if value is not None else "Unknown"), quote=True)


def count_records(record):
    data = record.get("data")
    return len(data) if isinstance(data, list) else "Unknown"


def advisory_id(identifier):
    label = text(identifier)
    if isinstance(identifier, str) and re.fullmatch(r"(?:CVE|OSV)-\d{4}-\d+", identifier):
        return f'<a href="https://osv.dev/vulnerability/{identifier}">{label}</a>'
    return label


def finding_rows(findings, key):
    rows = []
    for package in findings:
        for advisory in package.get(key, []):
            fixed = advisory.get("fixed_versions") or []
            rows.append("<tr>"
                        f"<td><strong>{text(package.get('formula'))}</strong><br>"
                        f"<span class=\"muted\">{text(package.get('version'))}</span></td>"
                        f"<td>{advisory_id(advisory.get('id'))}<br>"
                        f"<span class=\"muted\">{text(advisory.get('summary'))}</span></td>"
                        f"<td>{text(advisory.get('severity'))}</td>"
                        f"<td>{text(', '.join(map(str, fixed)) if fixed else 'Not reported')}</td>"
                        "</tr>")
    return rows


def extension_rows(results):
    rows = []
    for item in results:
        status = item.get("status", "not assessed")
        details = text(item.get("reason") or item.get("version_warning") or "")
        candidates = item.get("candidates", [])
        if candidates:
            entries = "".join(
                f"<li>{advisory_id(candidate.get('id'))} — {text(candidate.get('severity'))}<br>"
                f"{text(candidate.get('description'))}<br>"
                f"<span class=\"muted\">CPE version comparison: {text(candidate.get('version_range'))}</span></li>"
                for candidate in candidates
            )
            details += f"<details><summary>{len(candidates)} candidate records</summary><ul>{entries}</ul></details>"
        if item.get("truncated"):
            details += "<p>Results truncated; further candidates were not retrieved.</p>"
        rows.append("<tr>"
                    f"<td>{text(item.get('browser'))}<br><span class=\"muted\">{text(item.get('profile'))}</span></td>"
                    f"<td><strong>{text(item.get('name') or item.get('id'))}</strong><br>"
                    f"<span class=\"muted\">{text(item.get('version'))}</span></td>"
                    f"<td>{text(status)}<br>{details}</td></tr>")
    if not rows:
        return '<p class=\"muted\">No extension advisory results available.</p>'
    return ('<div class="table-wrap"><table class="extensions"><thead><tr><th>Browser / profile</th>'
            '<th>Extension / version</th><th>Advisory search</th></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div>')


def render(data):
    apps = data.get("applications", {})
    receipts = data.get("package_receipts", {})
    brew = data.get("homebrew_vulnerabilities", {})
    brew_data = brew.get("data") if isinstance(brew.get("data"), dict) else None
    inventory = data.get("homebrew_inventory", {}).get("data")
    inventory = inventory if isinstance(inventory, dict) else {}
    findings = brew_data.get("findings", []) if brew_data is not None else []
    open_rows = finding_rows(findings, "vulnerabilities")
    patched_rows = finding_rows(findings, "patched")
    flagged = sum(bool(package.get("vulnerabilities")) for package in findings)
    browsers = data.get("browser_extensions", {})
    extension_count = sum(len(profile.get("extensions", []))
                          for result in browsers.values() for profile in result.get("profiles", []))
    formulae = inventory.get("formulae")
    casks = inventory.get("casks")
    stats = [
        ("Applications", count_records(apps), "inventory records"),
        ("Package receipts", count_records(receipts), "installation history"),
        ("Browser extensions", extension_count if browsers else "Unknown", "profile records"),
        ("Homebrew formulae", len(formulae) if isinstance(formulae, list) else "Unknown", "installed records"),
        ("Homebrew casks", len(casks) if isinstance(casks, list) else "Unknown", "installed records"),
        ("Flagged formulae", flagged if brew_data is not None else "Unknown", "Homebrew open findings"),
    ]
    cards = "".join(f'<div class="card"><div class="label">{text(label)}</div>'
                    f'<div class="number">{text(value)}</div><div class="muted">{text(detail)}</div></div>'
                    for label, value, detail in stats)
    gaps = []
    for key, label in (("macos", "macOS"), ("applications", "Applications"),
                       ("package_receipts", "Package receipts"), ("homebrew_inventory", "Homebrew inventory"),
                       ("homebrew_vulnerabilities", "Homebrew vulnerabilities")):
        record = data.get(key, {})
        if record.get("error"):
            gaps.append(f"{label}: {record['error']}")
        if record.get("stderr"):
            gaps.append(f"{label} stderr: {record['stderr']}")
        if record.get("exit_code") not in (None, 0):
            gaps.append(f"{label}: command exited {record['exit_code']}; inspect JSON for details")
    for label, record in (("Applications", apps), ("Package receipts", receipts)):
        entries = record.get("data")
        if isinstance(entries, list):
            errors = sum(bool(item.get("error") or
                              (label == "Package receipts" and item.get("exit_code") != 0)) for item in entries)
            if errors:
                gaps.append(f"{label}: {errors} records could not be fully read; inspect JSON")
    for browser, result in browsers.items():
        gaps.extend(f"{browser}: {error}" for error in result.get("errors", []))
        if result.get("status"):
            gaps.append(f"{browser}: {result['status']}")
        for profile in result.get("profiles", []):
            gaps.extend(f"{browser}: {error}" for error in profile.get("errors", []))
    if brew_data is None:
        coverage = "Not assessed"
    else:
        coverage = "Complete" if brew_data.get("complete") is True else "Incomplete or unknown"
        for key, label in (("skipped_formulae", "Skipped formulae"),
                           ("outdated_without_sbom", "Outdated without SBOM"),
                           ("unscanned_formulae", "Unscanned formulae")):
            values = brew_data.get(key)
            if values:
                gaps.append(f"{label}: {values}")
    gaps_html = "".join(f"<li>{text(item)}</li>" for item in gaps) or "<li>No collection errors recorded; this is not a complete security assessment.</li>"
    headers = "<thead><tr><th>Formula / version</th><th>Advisory</th><th>Severity</th><th>Fixed versions / commits</th></tr></thead>"
    def table(rows, empty):
        if not rows:
            return f'<p class="muted">{text(empty)}</p>'
        return f'<div class="table-wrap"><table class="homebrew">{headers}<tbody>{"".join(rows)}</tbody></table></div>'
    open_empty = ("No open Homebrew advisory records returned. Coverage may be incomplete."
                  if brew_data is not None else "Homebrew advisory results were not available.")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MacSentry scan report</title><style>
:root {{ color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }}
body {{ max-width: 1120px; margin: 0 auto; padding: 2rem 1.25rem 4rem; line-height: 1.5; }}
h1 {{ margin-bottom: .25rem; }} h2 {{ margin-top: 2rem; }}
.muted, .label {{ color: light-dark(#525b66, #b8c2cd); }} .label {{ font-weight: 600; }}
.banner {{ padding: 1rem; border: 1px solid light-dark(#d39b2d, #ba8b32); border-radius: .5rem; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(155px, 1fr)); gap: .75rem; }}
.card {{ border: 1px solid light-dark(#d3d9e0, #505b69); border-radius: .5rem; padding: .9rem; }}
.number {{ font-size: 1.8rem; font-weight: 700; }} .table-wrap {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; min-width: 700px; table-layout: fixed; text-align: left; }} th, td {{ padding: .75rem; border-bottom: 1px solid light-dark(#d3d9e0, #505b69); vertical-align: top; overflow-wrap: anywhere; }}
.extensions th:nth-child(1) {{ width: 23%; }} .extensions th:nth-child(2) {{ width: 25%; }}
.homebrew th:nth-child(1) {{ width: 18%; }} .homebrew th:nth-child(2) {{ width: 42%; }} .homebrew th:nth-child(3) {{ width: 15%; }}
a {{ color: light-dark(#0759aa, #8bc4ff); }}
</style></head><body><main>
<h1>MacSentry scan report</h1><p class="muted">Collected {text(data.get('collected_at'))}</p>
<p class=\"banner\"><strong>Limited automated assessment.</strong> Extension results are unverified NVD keyword candidates, not confirmed vulnerabilities; application advisories require the agent skill. A successful scan does not establish safety.</p>
<h2>Inventory overview</h2><div class="cards">{cards}</div>
<h2>Open Homebrew advisory records</h2><p>Coverage: <strong>{text(coverage)}</strong>. Findings are reported by Homebrew and require advisory verification; severity and fixes may be unknown.</p>
{table(open_rows, open_empty)}
<h2>Patched or resolved Homebrew records</h2><p class="muted">Listed separately from open findings, as reported by Homebrew.</p>
{table(patched_rows, 'No patched or resolved records returned.' if brew_data is not None else 'Homebrew advisory results were not available.')}
<h2>Browser extension advisory search</h2><p>Each row represents a browser profile record, which may be stale. NVD keyword hits may be unrelated and require publisher, version and platform verification. No keyword match does not mean safe. Browser components require separate browser advisory assessment.</p>
{extension_rows(data.get('extension_advisories', {}).get('results', []))}
<h2>Coverage and collection notes</h2><ul>{gaps_html}</ul>
<p class="muted">This report contains local inventory details. Keep it private. Open advisory links contact OSV.</p>
</main></body></html>'''
