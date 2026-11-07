"""Search NVD for extension advisory candidates; identity matches need review."""
import json
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_name(extension):
    name = extension.get("name")
    if isinstance(name, str) and not name.startswith("__MSG_"):
        # Store display names often append marketing text not present in CVEs.
        name = re.split(r"\s+[–—|]\s+", name, maxsplit=1)[0].strip()
        if 2 <= len(name) <= 100 and not any(c in name for c in "/\\@\r\n"):
            return name
    identifier = extension.get("id")
    if isinstance(identifier, str) and re.fullmatch(r"[a-p]{32}", identifier):
        return identifier
    return None


def request_nvd(query):
    url = NVD_URL + "?" + urlencode({"keywordSearch": query, "resultsPerPage": 100})
    with urlopen(Request(url, headers={"User-Agent": "MacSentry/1.0"}), timeout=25) as response:
        data = json.load(response)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list) or not isinstance(data.get("totalResults"), int):
        raise ValueError("Invalid NVD response")
    candidates = []
    for item in data["vulnerabilities"]:
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        metrics = cve.get("metrics", {})
        severity = None
        for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version, [])
            if entries:
                severity = entries[0].get("cvssData", {}).get("baseSeverity") or entries[0].get("baseSeverity")
                if severity:
                    break
        candidates.append({"id": cve.get("id"), "description": english,
                           "severity": severity, "configurations": cve.get("configurations", []),
                           "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]})
    return {"total_results": data["totalResults"], "candidates": candidates,
            "truncated": data["totalResults"] > len(candidates)}


def numeric_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    parts = tuple(int(part) for part in value.split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def cpe_version_range(candidate, query, installed):
    """Compare simple numeric ranges for same-named CPEs, not overall applicability."""
    version = numeric_version(installed)
    if version is None:
        return "unknown"
    product = re.sub(r"[^a-z0-9]", "", query.lower())
    ranges = []
    unknown = False

    def visit(value):
        nonlocal unknown
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            if value.get("vulnerable") is True:
                cpe = value.get("criteria", "").split(":")
                if len(cpe) >= 6 and re.sub(r"[^a-z0-9]", "", cpe[4].lower()) == product:
                    constraints = [("versionStartIncluding", lambda a, b: a >= b),
                                   ("versionStartExcluding", lambda a, b: a > b),
                                   ("versionEndIncluding", lambda a, b: a <= b),
                                   ("versionEndExcluding", lambda a, b: a < b)]
                    checks = [(value[key], compare) for key, compare in constraints if key in value]
                    if cpe[5] not in ("*", "-"):
                        checks.append((cpe[5], lambda a, b: a == b))
                    if not checks:
                        unknown = True
                    else:
                        parsed = [(numeric_version(bound), compare) for bound, compare in checks]
                        if any(bound is None for bound, _ in parsed):
                            unknown = True
                        else:
                            ranges.append(all(compare(version, bound) for bound, compare in parsed))
            for child in value.values():
                if isinstance(child, (dict, list)):
                    visit(child)

    visit(candidate.get("configurations", []))
    if any(ranges):
        return "within same-named CPE version range; applicability unverified"
    if ranges and not unknown:
        return "outside same-named CPE version ranges; applicability unverified"
    return "unknown"


def assess(inventory, progress=lambda *_: None):
    cache = {}
    last_request = None
    output = []
    for browser, result in inventory.items():
        for profile in result.get("profiles", []):
            for extension in profile.get("extensions", []):
                name, version, identifier = extension.get("name"), extension.get("version"), extension.get("id")
                item = {"browser": browser, "profile": profile.get("profile"), "id": identifier,
                        "name": name, "version": version}
                if (browser == "chrome" and extension.get("location") == 5 or
                        browser == "firefox" and isinstance(identifier, str) and
                        identifier.endswith(("@mozilla.org", "@mozilla.com"))):
                    item.update(status="not assessed", reason="Browser-managed component; assess with the browser version")
                else:
                    query = query_name(extension)
                    if not query:
                        item.update(status="not assessed", reason="No usable extension name or Chrome store ID")
                    else:
                        key = query.casefold()
                        if key not in cache:
                            progress("Extension advisory search", f"{query} — querying NVD")
                            if last_request is not None:
                                time.sleep(max(0, 6.1 - (time.monotonic() - last_request)))
                            last_request = time.monotonic()
                            try:
                                cache[key] = request_nvd(query)
                            except (OSError, ValueError, TypeError, KeyError) as error:
                                cache[key] = {"error": f"{type(error).__name__}: {error}"}
                        result = cache[key]
                        item["query"] = query
                        if "error" in result:
                            item.update(status="not assessed", reason=result["error"])
                        else:
                            candidates = [{**candidate, "version_range": cpe_version_range(candidate, query, version)}
                                          for candidate in result["candidates"]]
                            item.update(status="potential matches" if candidates else "no keyword matches",
                                        total_results=result["total_results"], truncated=result["truncated"],
                                        candidates=candidates)
                            if not version:
                                item["version_warning"] = "Installed version unknown; applicability cannot be assessed"
                                item["status"] = "not assessed"
                progress("Extension advisory result", f'{name or identifier or "unknown"} — {item["status"]}')
                output.append(item)
    return {"source": "NVD CVE API keyword search", "results": output,
            "limitations": "Keyword hits are unverified candidates, not confirmed affected versions. No keyword matches does not establish safety; identities, versions and applicability require advisory review."}
